using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WithSecrets.Tests;

/// <summary>
/// Writes signed manifests for tests, the way the pages do: an admin key of the stored manifest (the new key itself on the
/// first write) signs SHA-256(bind || SHA-256(manifest)). Keys must come from a <see cref="TestAuthenticator" /> so an
/// admin can sign.
/// </summary>
internal static class TestState
{
    public const string Origin = "http://localhost:1";

    private static int _signs = 1_000_000;

    /// <summary>An enrollment where the approval and the change happen at the same place.</summary>
    public static Enrollment Enrollment(IProofMethod method, WebApprover approver, Action<string> announce, AdminAudit? audit = null)
    {
        return new Enrollment(EnrollmentTarget.For(method, approver), EnrollmentTarget.For(method, approver), announce, audit);
    }

    /// <summary>A sign count higher than any before in this process.</summary>
    public static uint NextCount() => (uint)Interlocked.Increment(ref _signs);

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, JsonElement> Registrations = new(StringComparer.Ordinal);

    /// <summary>Remembers the options of a registration page by challenge, so that <see cref="Register" /> can send its PRF part.</summary>
    public static void Note(JsonElement options)
    {
        if (options.ValueKind == JsonValueKind.Object && options.TryGetProperty("challenge", out JsonElement challenge) && challenge.ValueKind == JsonValueKind.String)
        {
            Registrations[challenge.GetString()!] = options.Clone();
        }
    }

    /// <summary>
    /// A registration body as the page posts it: the attestation and, when the page asked for it (its options have prf) and
    /// the authenticator has PRF, the PRF output for the page's slot salt sealed to the page's key (prfEpk, prfIv, prfCt).
    /// </summary>
    public static string Register(TestAuthenticator who, byte[] challenge, string origin, string rpId, string name, PrfMode prf = PrfMode.Normal)
    {
        string json = who.Attest(challenge, origin, rpId, name);

        return Registrations.TryGetValue(Base64Url.EncodeToString(challenge), out JsonElement options) ? WithPrf(json, options, who, prf) : json;
    }

    /// <summary>Adds the sealed PRF output to a registration body (see <see cref="Register" />).</summary>
    public static string WithPrf(string json, JsonElement options, TestAuthenticator who, PrfMode mode = PrfMode.Normal, TestAuthenticator? other = null)
    {
        if (mode == PrfMode.Missing || !options.TryGetProperty("prf", out JsonElement prf))
        {
            return json;
        }

        byte[] bind = Base64Url.DecodeFromChars(options.GetProperty("challenge").GetString()!);
        byte[]? output = (mode == PrfMode.OtherCredential ? other! : who).Prf(Base64Url.DecodeFromChars(prf.GetProperty("salt").GetString()!));
        if (output is null)
        {
            return json;
        }

        if (mode == PrfMode.ShortOutput)
        {
            output = output[..16];
        }

        (string epk, string iv, string ct) = PrfBrowser.Seal(prf.GetProperty("serverKey").GetString()!, mode == PrfMode.WrongBind ? SHA256.HashData(bind) : bind, output);
        if (mode == PrfMode.Garbled)
        {
            byte[] bytes = Base64Url.DecodeFromChars(ct);
            bytes[0] ^= 1;
            ct = Base64Url.EncodeToString(bytes);
        }

        return json[..^1] + ",\"prfEpk\":\"" + epk + "\",\"prfIv\":\"" + iv + "\",\"prfCt\":\"" + ct + "\"}";
    }

    /// <summary>
    /// Plays the registration page's second prompt: when <paramref name="reply" /> (from /create) asks for the admin's
    /// assertion over the new manifest, the key it names signs it (or <paramref name="signer" />), and the assertion is posted
    /// to /sign. Returns the reply that has the code (or the first reply when there is no sign step).
    /// </summary>
    public static string SignStep(HttpClient client, string pageUrl, string origin, string reply, TestAuthenticator? signer = null, Func<byte[], string, byte[]>? challenge = null)
    {
        JsonElement sign;
        try
        {
            using JsonDocument document = JsonDocument.Parse(reply);
            if (!document.RootElement.TryGetProperty("sign", out JsonElement found))
            {
                return reply;
            }

            sign = found.Clone();
        }
        catch (JsonException)
        {
            return reply;
        }

        string manifest = sign.GetProperty("manifest").GetString()!;
        byte[] bind = Base64Url.DecodeFromChars(sign.GetProperty("bind").GetString()!);
        string rpId = sign.GetProperty("rpId").GetString()!;
        // The page no longer names the keys (the authenticator chooses among its passkeys), so the oldest admin key of the manifest signs.
        Manifest? offered = Manifest.Parse(manifest, out _);
        TestAuthenticator? who = signer ?? offered?.Admins.Select(item => TestAuthenticator.ById(item.Id)).OfType<TestAuthenticator>().OrderBy(item => item.Sequence).FirstOrDefault();
        if (who is null)
        {
            return "";
        }

        string body = who.Assert((challenge ?? Manifest.Challenge)(bind, manifest), origin, rpId, NextCount());

        return Post(client, pageUrl + "/sign", body).Body;
    }

    /// <summary>
    /// Plays the approval page: reads its data block and posts a proof by <paramref name="signer" />, over the manifest
    /// challenge when the page signs a new state, else over "approve once". When the page asks for the PRF output (it has a
    /// prfKey) the proof carries it sealed to the page's key, as the page script does, except as <paramref name="prf" /> says.
    /// </summary>
    public static (int Status, string Body) Approve(HttpClient client, string pageUrl, string origin, string rpId, TestAuthenticator signer, PrfMode prf = PrfMode.Normal, TestAuthenticator? other = null, bool userVerified = true, Func<byte[], byte[]>? changeChallenge = null)
    {
        (_, string page) = Get(client, pageUrl);
        const string open = "<script type=\"application/json\" id=\"start\">";
        int from = page.IndexOf(open, StringComparison.Ordinal);
        if (from < 0)
        {
            return (0, "");
        }

        from += open.Length;
        using JsonDocument start = JsonDocument.Parse(page[from..page.IndexOf("</script>", from, StringComparison.Ordinal)]);
        byte[] bind = Base64Url.DecodeFromChars(start.RootElement.GetProperty("bind").GetString()!);
        byte[] challenge = start.RootElement.TryGetProperty("manifest", out JsonElement manifest)
            ? Manifest.Challenge(bind, manifest.GetString()!)
            : ReuseBinding.Challenge(bind, 0);
        if (changeChallenge is not null)
        {
            challenge = changeChallenge(challenge);
        }

        string body = ReuseTests.Body(0, signer.Assert(challenge, origin, rpId, NextCount(), userVerified));
        if (start.RootElement.TryGetProperty("prfKey", out JsonElement prfKey) && prf != PrfMode.Missing)
        {
            body = body[..^1] + ",\"prf\":" + PrfMember(start.RootElement, prfKey.GetString()!, bind, signer, prf, other) + "}";
        }

        LastProofBody = body;

        return Post(client, pageUrl + "/proof", body);
    }

    /// <summary>The body of the last proof <see cref="Approve" /> sent, so a test can send it again as a page resend would.</summary>
    public static string LastProofBody { get; private set; } = "";

    /// <summary>What the page sends as "prf": the output for the key's slot salt sealed to the page's key, or as a twist says.</summary>
    private static string PrfMember(JsonElement start, string serverKey, byte[] bind, TestAuthenticator signer, PrfMode mode, TestAuthenticator? other)
    {
        using JsonDocument payload = JsonDocument.Parse(start.GetProperty("payload").GetString()!);
        TestAuthenticator releasing = mode is PrfMode.OtherCredential or PrfMode.OtherOwnSalt ? other! : signer;
        byte[] salt = payload.RootElement.TryGetProperty("salt", out JsonElement found) && found.ValueKind == JsonValueKind.String ? Base64Url.DecodeFromChars(found.GetString()!) : new byte[32];
        byte[] output = releasing.Prf(salt) ?? new byte[32];
        if (mode == PrfMode.ShortOutput)
        {
            output = output[..16];
        }

        (string epk, string iv, string ct) = PrfBrowser.Seal(serverKey, mode == PrfMode.WrongBind ? SHA256.HashData(bind) : bind, output);
        if (mode == PrfMode.Garbled)
        {
            byte[] bytes = Base64Url.DecodeFromChars(ct);
            bytes[0] ^= 1;
            ct = Base64Url.EncodeToString(bytes);
        }

        return JsonSerializer.Serialize(new Dictionary<string, string> { ["epk"] = epk, ["iv"] = iv, ["ct"] = ct });
    }

    public static (int Status, string Body) Get(HttpClient client, string url)
    {
        try
        {
            using HttpResponseMessage response = client.Send(new HttpRequestMessage(HttpMethod.Get, url));

            return ((int)response.StatusCode, response.Content.ReadAsStringAsync().GetAwaiter().GetResult());
        }
        catch (HttpRequestException)
        {
            return (0, "");
        }
    }

    public static (int Status, string Body) Post(HttpClient client, string url, string body)
    {
        try
        {
            using HttpRequestMessage message = new(HttpMethod.Post, url) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            using HttpResponseMessage response = client.Send(message);

            return ((int)response.StatusCode, response.Content.ReadAsStringAsync().GetAwaiter().GetResult());
        }
        catch (HttpRequestException)
        {
            return (0, "");
        }
    }

    /// <summary>A manifest signed by <paramref name="signer" /> over a fresh bind.</summary>
    public static SignedManifest Sign(TestAuthenticator signer, string text, string rpId = "localhost")
    {
        byte[] bind = RandomNumberGenerator.GetBytes(32);

        return new SignedManifest(text, bind, signer.Assert(Manifest.Challenge(bind, text), Origin, rpId, 0));
    }

    /// <summary>The verified manifest, null when there is none. Throws when the state fails verification.</summary>
    public static Manifest? Current(StateDatabase db)
    {
        return db.TryManifest(out Manifest? manifest, out string? error) ? manifest : throw new InvalidOperationException(error);
    }

    /// <summary>
    /// Signs <paramref name="next" /> and stores it in place of version - 1. False when refused. The signer is
    /// <paramref name="by" />, else the first admin of the stored manifest that is still an admin in <paramref name="next" />
    /// (on the first write, the first admin of <paramref name="next" />).
    /// </summary>
    public static bool Write(StateDatabase db, Manifest next, TestAuthenticator? by = null)
    {
        Manifest? current;
        try
        {
            current = next.Version > 1 ? Current(db) : null;
        }
        catch (InvalidOperationException)
        {
            return false;
        }

        IEnumerable<ManifestKey> candidates = current is null ? next.Admins : current.Admins.Where(key => next.Admins.Any(item => item.Id == key.Id));
        ManifestKey? admin = by is null ? candidates.FirstOrDefault(key => TestAuthenticator.ById(key.Id) is not null)
            : next.Keys.Concat(current?.Keys ?? []).FirstOrDefault(key => key.Id == TestAuthenticator.Encode(by.CredentialId));
        TestAuthenticator? signer = by ?? (admin is null ? null : TestAuthenticator.ById(admin.Id));
        if (signer is null)
        {
            return false;
        }

        SignedManifest signed = Sign(signer, next.Canonical(), admin?.RpId ?? "localhost");
        try
        {
            return db.Write((connection, transaction) => db.TryReplace(connection, transaction, next.Version - 1, signed) is null);
        }
        catch (StateDatabaseException)
        {
            return false;
        }
    }

    /// <summary>
    /// Adds a key: the first one is an admin (with <paramref name="settings" />); the rest are signed by an admin and are
    /// admins too when <paramref name="admin" /> says so.
    /// </summary>
    public static bool Add(StateDatabase db, PasskeyRecord record, ToolSettings? settings = null, bool admin = false, bool withStore = false)
    {
        Manifest? current;
        try
        {
            current = Current(db);
        }
        catch (InvalidOperationException)
        {
            return false;
        }

        if (current is not null && current.Keys.Any(key => key.Id == record.Id))
        {
            return false;
        }

        // Every key of one test state wraps the same master key, so a vault made for the state opens with any of them.
        record = TestVault.Reslot(db, record);

        Manifest first = Manifest.First(record, settings ?? ToolSettings.Defaults);
        if (withStore && current is null)
        {
            // Like a first setup: the store public key and its vault are in the first manifest.
            (string publicKey, string privateKey) = DotenvxCipher.Instance.NewKeyPair();
            first = first with { Store = publicKey, Vault = TestVault.Vault(db, privateKey, publicKey), Review = KeyVault.NewReviewKey(TestVault.Master(db)) };
        }

        return Write(db, current is null ? first : current.WithKey(record, admin));
    }

    /// <summary>A state at <paramref name="path" /> with one admin key (localhost) and these settings, for tests that need a manifest.</summary>
    public static StateDatabase Seeded(string path, ToolSettings? settings = null)
    {
        StateDatabase db = new(path);
        if (!Add(db, TestAuthenticator.ES256().Record("localhost", "seed-admin"), settings))
        {
            throw new InvalidOperationException("the test state could not be seeded");
        }

        return db;
    }

    /// <summary>Replaces the settings (signed by the admin). False when there is no manifest.</summary>
    public static bool Settings(StateDatabase db, ToolSettings settings)
    {
        Manifest? current = Current(db);

        return current is not null && Write(db, current.WithSettings(settings));
    }

    /// <summary>Changes one setting by name, from its text, as the old tests wrote rows.</summary>
    public static bool Setting(StateDatabase db, string name, string value)
    {
        Manifest? current = Current(db);
        if (current is null)
        {
            return false;
        }

        ToolSettings s = current.Settings;
        int Number() => int.Parse(value, System.Globalization.CultureInfo.InvariantCulture);
        ToolSettings next = name switch
        {
            "reuseMaxMinutes" => s with { ReuseMaxMinutes = Number() },
            "baseUrl" => s with { BaseUrl = value },
            "port" => s with { Port = Number() },
            "timeoutMinutes" => s with { TimeoutMinutes = Number() },
            _ => throw new ArgumentOutOfRangeException(nameof(name)),
        };

        return Write(db, current.WithSettings(next));
    }
}

/// <summary>
/// The master key of a test state and what opens it. <see cref="TestState.Add" /> gives every key of a state a slot of the same
/// master key; a test that needs the secret store's vault makes it with <see cref="Master" />, and plays a passkey's PRF
/// release with <see cref="Unlock" />.
/// </summary>
internal static class TestVault
{
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, byte[]> Masters = new(StringComparer.Ordinal);

    /// <summary>The master key of the state at this database (made on first use).</summary>
    public static byte[] Master(StateDatabase db) => Masters.GetOrAdd(Path.GetFullPath(db.FilePath), _ => KeyVault.NewMasterKey());

    public static string ReviewText(StateDatabase db, GrantRecord row)
    {
        ReviewKey review = TestState.Current(db)!.Review!;
        byte[] key = KeyVault.UnwrapReview(review.Vault, Master(db), review.PublicKey);
        try
        {
            return DotenvxCipher.Instance.Decrypt(Encoding.UTF8.GetString(key), row.Evidence!.Ciphertext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, byte[]> Salts = new(StringComparer.Ordinal);

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, byte[]> RecoveryCodes = new(StringComparer.Ordinal);

    /// <summary>The recovery code (raw bytes) of the state at this database, made on first use: a test state's store gets a recovery slot for it.</summary>
    public static byte[] RecoveryCode(StateDatabase db) => RecoveryCodes.GetOrAdd(Path.GetFullPath(db.FilePath), _ => KeyVault.NewRecoveryCode());

    /// <summary>The recovery slot of this state's master key and recovery code, for the store with this public key.</summary>
    public static KeySlot RecoverySlot(StateDatabase db, string storePublicKey) => KeyVault.NewRecoverySlot(Master(db), RecoveryCode(db), storePublicKey);

    /// <summary>The one slot salt of the state at this database: every key's slot shares it.</summary>
    public static byte[] Salt(StateDatabase db) => Salts.GetOrAdd(Path.GetFullPath(db.FilePath), _ => KeyVault.NewSalt());

    /// <summary>The record with a slot of this state's master key, when its authenticator is known and has PRF.</summary>
    public static PasskeyRecord Reslot(StateDatabase db, PasskeyRecord record)
    {
        return TestAuthenticator.ById(record.Id) is { } authenticator && authenticator.Slot(Master(db), Salt(db)) is { } slot ? record with { Slot = slot } : record;
    }

    /// <summary>What <paramref name="who" /> releases at an approval: the PRF output for its slot salt in the stored manifest. Null when it has no slot or no PRF.</summary>
    public static Unlock? Unlock(StateDatabase db, TestAuthenticator who)
    {
        string id = TestAuthenticator.Encode(who.CredentialId);
        KeySlot? slot = TestState.Current(db)?.Keys.FirstOrDefault(key => key.Id == id)?.Slot;
        byte[]? output = slot is null ? null : who.Prf(Base64Url.DecodeFromChars(slot.Salt));

        return output is null ? null : new Unlock(id, output);
    }

    /// <summary>The vault for a store key made now: the private key wrapped under this state's master key.</summary>
    public static string Vault(StateDatabase db, string privateKey, string publicKey)
    {
        return KeyVault.WrapVault(Encoding.UTF8.GetBytes(privateKey), Master(db), publicKey);
    }
}

/// <summary>The writes the old passkey store had, now as signed manifest changes, so tests read the same.</summary>
internal static class PasskeyStoreTestExtensions
{
    public static bool Add(this PasskeyStore store, PasskeyRecord record) => TestState.Add(store.Database, record);

    public static bool RemoveById(this PasskeyStore store, string id)
    {
        Manifest? current;
        try
        {
            current = TestState.Current(store.Database);
        }
        catch (InvalidOperationException)
        {
            return false;
        }

        return current is not null && current.Keys.Any(key => key.Id == id && !key.Admin) && TestState.Write(store.Database, current.WithoutKey(id));
    }
}

/// <summary>What an approval page's PRF part looks like in a test: right, or one thing wrong.</summary>
internal enum PrfMode
{
    Normal,
    Missing,
    Garbled,
    WrongBind,
    OtherCredential,
    ShortOutput,

    /// <summary>Key A signs, but the page sends key B's valid PRF output for B's own salt.</summary>
    OtherOwnSalt,
}

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
    public static Enrollment Enrollment(IProofMethod method, WebApprover approver, Action<string> announce, AuditLog? audit = null)
    {
        return new Enrollment(EnrollmentTarget.For(method, approver), EnrollmentTarget.For(method, approver), announce, audit);
    }

    /// <summary>A sign count higher than any before in this process.</summary>
    public static uint NextCount() => (uint)Interlocked.Increment(ref _signs);

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
        TestAuthenticator? who = signer ?? TestAuthenticator.ById(sign.GetProperty("allowCredentials")[0].GetProperty("id").GetString()!);
        if (who is null)
        {
            return "";
        }

        string body = who.Assert((challenge ?? Manifest.Challenge)(bind, manifest), origin, rpId, NextCount());

        return Post(client, pageUrl + "/sign", body).Body;
    }

    /// <summary>
    /// Plays the approval page: reads its data block and posts a proof by <paramref name="signer" />, over the manifest
    /// challenge when the page signs a new state, else over "approve once".
    /// </summary>
    public static (int Status, string Body) Approve(HttpClient client, string pageUrl, string origin, string rpId, TestAuthenticator signer)
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

        return Post(client, pageUrl + "/proof", ReuseTests.Body(0, signer.Assert(challenge, origin, rpId, NextCount())));
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
    public static bool Add(StateDatabase db, PasskeyRecord record, ToolSettings? settings = null, bool admin = false)
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

        return Write(db, current is null ? Manifest.First(record, settings ?? ToolSettings.Defaults) : current.WithKey(record, admin));
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
            "reuseMinutes" => s with { ReuseMinutes = Number() },
            "reuseMaxMinutes" => s with { ReuseMaxMinutes = Number() },
            "method" => s with { Method = value },
            "baseUrl" => s with { BaseUrl = value },
            "port" => s with { Port = Number() },
            "timeoutMinutes" => s with { TimeoutMinutes = Number() },
            _ => throw new ArgumentOutOfRangeException(nameof(name)),
        };

        return Write(db, current.WithSettings(next));
    }
}

/// <summary>
/// Saves grants the way a real approval does, so tests read the same: the key named <paramref name="keyName" /> (else the
/// admin) signs a run approval text with the request id and the page issued time (the store's clock), for the minutes.
/// </summary>
internal static class GrantStoreTestExtensions
{
    private static int _signs = 3_000_000;

    /// <summary>A grant for the key that verifies and is in force, under the largest ceiling there is.</summary>
    public static bool TryGet(this GrantStore grants, string key, out DateTimeOffset approved, out DateTimeOffset expires)
    {
        return grants.TryGet(key, ReuseSettings.MaxMinutes, out approved, out expires);
    }

    /// <summary>A grant for the key that verifies, is in force now and lasts no longer than <paramref name="maxMinutes" />.</summary>
    public static bool TryGet(this GrantStore grants, string key, int maxMinutes, out DateTimeOffset approved, out DateTimeOffset expires)
    {
        GrantEntry? grant = grants.Find(key, maxMinutes).Grant;
        approved = grant?.Approved ?? default;
        expires = grant?.Expires ?? default;

        return grant is not null;
    }

    public static void Clear(this GrantStore grants) => grants.TryClear();

    public static bool Add(this GrantStore grants, string key, int minutes, string? keyName = null)
    {
        Manifest? manifest;
        try
        {
            manifest = TestState.Current(grants.Database);
        }
        catch (InvalidOperationException)
        {
            return false;
        }

        ManifestKey? signer = manifest?.Keys.FirstOrDefault(item => item.Name == keyName) ?? manifest?.Admins.FirstOrDefault();
        if (signer is null || TestAuthenticator.ById(signer.Id) is not { } authenticator)
        {
            return false;
        }

        string text = "Allow an agent to use secrets?\n" + ApprovalSummary.RequestIdPrefix + key + "\n" + ApprovalSummary.IssuedLine(grants.Now());
        string nonce = "test-nonce";
        string proof = authenticator.Assert(ReuseBinding.Challenge(RequestBinding.Compute(nonce, text), minutes), TestState.Origin, signer.RpId, (uint)Interlocked.Increment(ref _signs));

        return grants.Add(key, minutes, new ApprovalEvidence(nonce, text, proof));
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

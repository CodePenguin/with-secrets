using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>
/// Task 18b: the recovery code and slot (crypto and parser), the code at the first <c>--config</c>, <c>--recover</c> and
/// <c>--rotate-key</c> over real HTTP with software passkeys, and a scan of everything the tool writes or says for the
/// recovery code and the keys.
/// </summary>
internal static class RecoveryTests
{
    private static readonly string[] Names = ["A_NAME", "B_NAME", "C_NAME"];

    private static readonly Dictionary<string, string> Values = new(StringComparer.Ordinal)
    {
        ["A_NAME"] = "Recov-Alpha-Secret-1",
        ["B_NAME"] = "Recov-Bravo-Secret-2",
        ["C_NAME"] = "Recov-Charlie-Secret-3",
    };

    private static readonly ApprovalSettings Local = new("passkey", null, 0, TimeSpan.FromSeconds(20));

    private static readonly Regex CodePattern = new("[A-Z2-7]{4}(-[A-Z2-7]{4}){7}", RegexOptions.CultureInvariant);

    public static async Task Run(Action<bool, string> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "ws-recovery-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            Crypto(check);
            Parser(check);
            await FirstConfig(check, root);
            await Recover(check, root);
            await Rotate(check, root);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            Directory.Delete(root, true);
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Crypto and parser
    // ---------------------------------------------------------------------------------------------------------------

    private static bool Fails(Action call)
    {
        try
        {
            call();

            return false;
        }
        catch (CryptographicException)
        {
            return true;
        }
    }

    /// <summary>True when decrypting <paramref name="row" /> with <paramref name="privateKey" /> fails in any way.</summary>
    private static bool DecryptFails(string privateKey, string row)
    {
        try
        {
            DotenvxCipher.Instance.Decrypt(privateKey, row);

            return false;
        }
        catch (Exception)
        {
            return true;
        }
    }

    private static void Crypto(Action<bool, string> check)
    {
        byte[] master = KeyVault.NewMasterKey();
        byte[] code = KeyVault.NewRecoveryCode();
        const string Pub = "02aaaabbbbccccddddeeeeffff00001111222233334444555566667777888899";
        KeySlot slot = KeyVault.NewRecoverySlot(master, code, Pub);
        byte[] salt = Base64Url.DecodeFromChars(slot.Salt);
        check(code.Length == 20 && salt.Length == 32 && Base64Url.DecodeFromChars(slot.Wrap).Length == 60, "recovery crypto: a 20-byte code, a 32-byte salt and a 60-byte wrap (nonce 12, key 32, tag 16)");
        check(KeyVault.UnwrapRecovery(slot.Wrap, code, salt, Pub).AsSpan().SequenceEqual(master), "recovery crypto: wrap and unwrap round trip");

        // The format as the brief fixes it, derived here without KeyVault: RK = HKDF-SHA256(code, salt, "with-secrets/v1 recovery"),
        // AES-256-GCM, nonce || ciphertext || tag, associated data "with-secrets/v1 recovery" || store public key.
        byte[] rk = HKDF.DeriveKey(HashAlgorithmName.SHA256, code, 32, salt, Encoding.UTF8.GetBytes("with-secrets/v1 recovery"));
        byte[] raw = Base64Url.DecodeFromChars(slot.Wrap);
        byte[] opened = new byte[32];
        try
        {
            using AesGcm aes = new(rk, 16);
            byte[] aad = [.. Encoding.UTF8.GetBytes("with-secrets/v1 recovery"), .. Encoding.UTF8.GetBytes(Pub)];
            aes.Decrypt(raw[..12], raw[12..44], raw[44..], opened, aad);
        }
        catch (CryptographicException)
        {
            opened = [];
        }

        check(opened.AsSpan().SequenceEqual(master), "recovery crypto: the wrap is HKDF-SHA256(code, salt, info) + AES-256-GCM with the info and the store public key as associated data");

        byte[] wrongCode = KeyVault.NewRecoveryCode();
        check(Fails(() => KeyVault.UnwrapRecovery(slot.Wrap, wrongCode, salt, Pub)), "recovery crypto: a wrong code fails");
        check(Fails(() => KeyVault.UnwrapRecovery(slot.Wrap, code, salt, Pub[..^1] + "0")), "recovery crypto: another store public key (the associated data) fails");
        check(Fails(() => KeyVault.UnwrapRecovery(slot.Wrap, code, KeyVault.NewSalt(), Pub)), "recovery crypto: another salt fails");
        foreach (int at in new[] { 0, 20, 59 })
        {
            byte[] bytes = Base64Url.DecodeFromChars(slot.Wrap);
            bytes[at] ^= 1;
            check(Fails(() => KeyVault.UnwrapRecovery(Base64Url.EncodeToString(bytes), code, salt, Pub)), $"recovery crypto: a wrap with byte {at} changed fails");
        }

        check(Fails(() => KeyVault.UnwrapRecovery(slot.Wrap[..^4], code, salt, Pub)), "recovery crypto: a short wrap fails");
        Manifest manifest = new(1, [], ToolSettings.Defaults, Pub, new Dictionary<string, string>(), "", slot);
        check(KeyVault.OpenRecovery(manifest, code).AsSpan().SequenceEqual(master) && Fails(() => KeyVault.OpenRecovery(manifest, wrongCode)) && Fails(() => KeyVault.OpenRecovery(manifest with { Recovery = null }, code)),
            "recovery crypto: OpenRecovery opens with the code and fails for a wrong code or no recovery slot");
        check(KeyVault.NewRecoverySlot(master, code, Pub).Wrap != KeyVault.NewRecoverySlot(master, code, Pub).Wrap, "recovery crypto: a fresh salt and nonce every time");
    }

    private static void Parser(Action<bool, string> check)
    {
        byte[] code = KeyVault.NewRecoveryCode();
        string text = RecoveryCode.Format(code);
        check(Regex.IsMatch(text, "^[A-Z2-7]{4}(-[A-Z2-7]{4}){7}$") && text.Length == 39, "recovery code: 8 groups of 4 base32 characters joined by dashes (" + text.Length + " characters)");
        check(RecoveryCode.Format(new byte[20]) == "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA" && RecoveryCode.Format(Enumerable.Repeat((byte)0xFF, 20).ToArray()) == "7777-7777-7777-7777-7777-7777-7777-7777", "recovery code: RFC 4648 base32 with no padding (zeros are A, ones are 7)");
        check(RecoveryCode.TryParse(text, out byte[] back) && back.AsSpan().SequenceEqual(code), "recovery code: the text parses back to the bytes");
        string plain = text.Replace("-", "", StringComparison.Ordinal);
        (string Name, string Typed)[] good =
        [
            ("lower case", text.ToLowerInvariant()),
            ("spaces for dashes", text.Replace('-', ' ')),
            ("no separators", plain),
            ("spaces around and inside", "  " + text.Replace("-", " - ", StringComparison.Ordinal) + "  "),
            ("mixed case", string.Concat(plain.Select((c, i) => i % 2 == 0 ? char.ToLowerInvariant(c) : c))),
        ];
        foreach ((string name, string typed) in good)
        {
            check(RecoveryCode.TryParse(typed, out byte[] parsed) && parsed.AsSpan().SequenceEqual(code), "recovery code: typed input accepts " + name);
        }

        (string Name, string? Typed)[] bad =
        [
            ("null", null),
            ("empty", ""),
            ("31 characters", plain[..31]),
            ("33 characters", plain + "A"),
            ("a digit outside the alphabet (1)", "1" + plain[1..]),
            ("a digit outside the alphabet (0)", "0" + plain[1..]),
            ("a digit outside the alphabet (8)", "8" + plain[1..]),
            ("a symbol", "!" + plain[1..]),
            ("a full-width letter", "Ａ" + plain[1..]),
            ("a tab", plain[..16] + "\t" + plain[16..]),
            ("padding", plain[..31] + "="),
        ];
        foreach ((string name, string? typed) in bad)
        {
            check(!RecoveryCode.TryParse(typed, out _), "recovery code: typed input rejects " + name);
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Rig
    // ---------------------------------------------------------------------------------------------------------------

    private sealed class Flow
    {
        private readonly BlockingCollection<string> _links = [];
        private readonly BlockingCollection<string?> _codes = [];

        public Flow(Func<Action<string>, Func<string?>, ConfigChange> run)
        {
            Running = Task.Run(() => run(line =>
            {
                lock (Lines)
                {
                    Lines.Add(line);
                }

                _links.Add(line);
            }, () => _codes.TryTake(out string? code, TimeSpan.FromSeconds(30)) ? code : null));
        }

        public List<string> Lines { get; } = [];

        public Task<ConfigChange> Running { get; }

        public void Type(string? code) => _codes.Add(code);

        /// <summary>The next page announced: its URL for the client and its origin. Null when the flow ended first or nothing came.</summary>
        public (string Url, string Origin)? Next()
        {
            DateTime stop = DateTime.UtcNow.AddSeconds(25);
            while (DateTime.UtcNow < stop)
            {
                if (_links.TryTake(out string? line, 200))
                {
                    if (!line.Contains("http", StringComparison.Ordinal))
                    {
                        continue;
                    }

                    Uri uri = new(line[line.IndexOf("http", StringComparison.Ordinal)..]);

                    return ("http://127.0.0.1:" + uri.Port + uri.AbsolutePath, uri.GetLeftPart(UriPartial.Authority));
                }

                if (Running.IsCompleted)
                {
                    return null;
                }
            }

            return null;
        }

        public ConfigChange Result() => Running.Wait(TimeSpan.FromSeconds(30)) ? Running.Result : new ConfigChange(-1, "timed out");

        public string AllLines()
        {
            lock (Lines)
            {
                return string.Join("\n", Lines);
            }
        }
    }

    private static (EnrollmentTarget Primary, EnrollmentTarget Local) Targets(StateDatabase db, Action<string> announce, Func<string?>? readCode, ApprovalSettings? settings = null)
    {
        settings ??= Local;
        PasskeyMethod method = new(new PasskeyStore(db), settings, readCode);
        EnrollmentTarget target = EnrollmentTarget.For(method, new WebApprover(method, settings, announce, TimeSpan.Zero));

        return (target, target);
    }

    private sealed record World(StateDatabase Db, SecretStore Store, string Folder, TestAuthenticator Laptop, TestAuthenticator? Phone, string Code);

    /// <summary>A state with a laptop admin, optionally a phone admin and a viewer (not an admin), and three secrets with a known recovery code.</summary>
    private static World NewWorld(string root, TestAuthenticator laptop, TestAuthenticator? phone = null, TestAuthenticator? viewer = null)
    {
        string folder = Path.Combine(root, "w-" + Guid.NewGuid().ToString("N"));
        StateDatabase db = StateDatabase.InFolder(folder);
        TestState.Add(db, laptop.Record("localhost", "laptop"));
        if (phone is not null)
        {
            TestState.Add(db, phone.Record("localhost", "phone"), admin: true);
        }

        if (viewer is not null)
        {
            TestState.Add(db, viewer.Record("localhost", "viewer"));
        }

        SecretStore store = new(db);
        if (SecretStoreTests.Put(store, Values) is { } problem)
        {
            throw new InvalidOperationException(problem);
        }

        return new World(db, store, folder, laptop, phone, RecoveryCode.Format(TestVault.RecoveryCode(db)));
    }

    /// <summary>The secrets as an approved run by <paramref name="who" /> reads them (null when the store does not open for it).</summary>
    private static Dictionary<string, string>? ReadAll(StateDatabase db, TestAuthenticator who)
    {
        try
        {
            using Unlock? unlock = TestVault.Unlock(db, who);
            using SecretValues values = new SecretStore(db).GetValues(Names, unlock);

            return values.Texts();
        }
        catch (Exception failure) when (failure is SecretStoreException or CryptographicException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>The state as the tests compare it: manifest text, every row, in order. Sign counts and audit rows are not in it (they move on a refusal).</summary>
    private static string Snapshot(StateDatabase db)
    {
        SqliteConnection.ClearAllPools();
        (Manifest? manifest, Dictionary<string, string> rows) = new SecretStore(db).Snapshot();

        return (manifest?.Canonical() ?? "none") + "\n" + string.Join("\n", rows.OrderBy(item => item.Key, StringComparer.Ordinal).Select(item => item.Key + "=" + item.Value));
    }

    private static string OldStoreKey(StateDatabase db, TestAuthenticator who)
    {
        Manifest manifest = TestState.Current(db)!;
        using Unlock unlock = TestVault.Unlock(db, who)!;
        byte[] master = KeyVault.OpenMaster(manifest, unlock);
        byte[] key = KeyVault.UnwrapVault(manifest.Vault, master, manifest.Store);

        return Encoding.UTF8.GetString(key);
    }

    private static HttpClient NewClient()
    {
        HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
        client.Timeout = TimeSpan.FromSeconds(20);

        return client;
    }

    private static JsonElement StartOf(string page)
    {
        const string open = "<script type=\"application/json\" id=\"start\">";
        int from = page.IndexOf(open, StringComparison.Ordinal);
        if (from < 0)
        {
            return default;
        }

        from += open.Length;
        using JsonDocument document = JsonDocument.Parse(page[from..page.IndexOf("</script>", from, StringComparison.Ordinal)]);

        return document.RootElement.Clone();
    }

    /// <summary>The first-run page: registers <paramref name="key" /> over <paramref name="text" />, signs the first manifest, returns (page, reply to /create, reply to /sign).</summary>
    private static (string Page, string Create, string Sign) RegisterFirst(HttpClient client, (string Url, string Origin) link, TestAuthenticator key, string text)
    {
        (_, string page) = TestState.Get(client, link.Url);
        JsonElement start = StartOf(page);
        JsonElement options = start.GetProperty("options");
        byte[] seed = Base64Url.DecodeFromChars(options.GetProperty("challenge").GetString()!);
        string attested = TestState.WithPrf(key.Attest(SHA256.HashData([.. seed, .. SHA256.HashData(Encoding.UTF8.GetBytes(text))]), link.Origin, "localhost", "passkey"), options, key);
        Dictionary<string, string> body = JsonSerializer.Deserialize<Dictionary<string, string>>(attested)!;
        body["settings"] = text;
        (_, string create) = TestState.Post(client, link.Url + "/create", JsonSerializer.Serialize(body));
        string sign = TestState.SignStep(client, link.Url, link.Origin, create);

        return (page, create, sign);
    }

    private static string? Member(string json, string name)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(json);

            return document.RootElement.TryGetProperty(name, out JsonElement found) && found.ValueKind == JsonValueKind.String ? found.GetString() : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Every form of the code a leak could take: text with and without dashes, lower case, hex, base64 and base64url of the bytes.</summary>
    private static string[] CodeForms(string codeText)
    {
        RecoveryCode.TryParse(codeText, out byte[] bytes);
        string plain = codeText.Replace("-", "", StringComparison.Ordinal);

        return [codeText, plain, codeText.ToLowerInvariant(), plain.ToLowerInvariant(), .. WebApprovalTests.Forms(bytes)];
    }

    private static bool Holds(IEnumerable<string> texts, string[] forms) => texts.Any(text => forms.Any(form => text.Contains(form, StringComparison.Ordinal)));

    /// <summary>True when any file of the folder (and its sub folders) holds the code in any form or as raw bytes.</summary>
    private static bool FolderHoldsCode(string folder, string codeText)
    {
        SqliteConnection.ClearAllPools();
        if (!Directory.Exists(folder))
        {
            return false;
        }

        RecoveryCode.TryParse(codeText, out byte[] bytes);

        return CodeForms(codeText).Any(form => WebApprovalTests.FolderHolds(folder, Encoding.UTF8.GetBytes(form))) || WebApprovalTests.FolderHolds(folder, bytes);
    }

    private static string Audit(StateDatabase db) => StateDatabaseTests.AuditText(db.FilePath);

    private static IReadOnlyList<AuditRecord> AuditRows(StateDatabase db)
    {
        return new AuditLog(db).TryRead(50, null, out IReadOnlyList<AuditRecord> rows, out _) ? rows : [];
    }

    // ---------------------------------------------------------------------------------------------------------------
    // First --config
    // ---------------------------------------------------------------------------------------------------------------

    private static async Task FirstConfig(Action<bool, string> check, string root)
    {
        using HttpClient client = NewClient();
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        string text = ToolSettings.Defaults.Canonical();

        // The good flow.
        {
            StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "first-" + Guid.NewGuid().ToString("N")));
            Flow flow = new((announce, read) =>
            {
                (EnrollmentTarget primary, EnrollmentTarget local) = Targets(db, announce, read);

                return new SettingsPage(db, primary, local, announce, read).Run();
            });
            (string Url, string Origin)? link = flow.Next();
            (string page, string create, string sign) = link is null ? ("", "", "") : RegisterFirst(client, link.Value, laptop, text);
            string? recovery = Member(sign, "recovery");
            string? codeText = Member(sign, "code");
            (_, string again) = link is null ? (0, "") : TestState.Get(client, link.Value.Url);
            bool emptyBefore = !File.Exists(db.FilePath) || TestState.Current(db) is null;
            flow.Type(codeText);
            ConfigChange result = flow.Result();

            check(result.Code == 0 && recovery is not null && CodePattern.IsMatch(recovery) && recovery.Length == 39, "first config recovery: the final page reply has the recovery code in 8 groups of 4 (" + (recovery ?? "none") + ")");
            check(emptyBefore, "first config recovery: nothing is stored before the 6-digit code is typed");
            Manifest? manifest = TestState.Current(db);
            check(manifest is { Recovery: not null } && KeyVault.IsSalt(manifest.Recovery.Salt) && KeyVault.IsSlotWrap(manifest.Recovery.Wrap), "first config recovery: the signed manifest has recovery {salt, wrap}");
            check(manifest is not null && manifest.Canonical().Contains(",\"vault\":", StringComparison.Ordinal) && manifest.Canonical().Contains(",\"recovery\":{\"salt\":", StringComparison.Ordinal) && db.TryCheck(out _), "first config recovery: the canonical text carries recovery next to the vault and the state verifies");
            if (recovery is not null && manifest is not null && RecoveryCode.TryParse(recovery, out byte[] codeBytes))
            {
                byte[] master = KeyVault.OpenRecovery(manifest, codeBytes);
                byte[] key = KeyVault.UnwrapVault(manifest.Vault, master, manifest.Store);
                using Unlock released = TestVault.Unlock(db, laptop)!;
                byte[] viaPasskey = KeyVault.OpenMaster(manifest, released);
                check(DotenvxCipher.Instance.Derive(Encoding.UTF8.GetString(key)) == manifest.Store && master.AsSpan().SequenceEqual(viaPasskey), "first config recovery: the code opens the same master key as the passkey, and the vault holds the store key");

                string[] forms = CodeForms(recovery);
                string[] said = [.. flow.Lines, result.Detail, page, create, again, Audit(db)];
                check(!Holds(said, forms), "first config recovery: the code is in no page before the last, no terminal line, no result text and no audit entry (text, hex, base64)");
                check(sign.Split(recovery).Length == 2, "first config recovery: the code is in the final reply exactly once");
                check(!FolderHoldsCode(Path.GetDirectoryName(db.FilePath)!, recovery), "first config recovery: the code (text, hex, base64, raw bytes) is in no file of the state folder");
                check(!Holds(said, [Convert.ToHexStringLower(master), Convert.ToBase64String(master), Base64Url.EncodeToString(master), Convert.ToHexStringLower(key), Encoding.UTF8.GetString(key)]), "first config recovery: the master key and the store key are in no output");
                check(!WebApprovalTests.FolderHolds(Path.GetDirectoryName(db.FilePath)!, master) && !WebApprovalTests.FolderHolds(Path.GetDirectoryName(db.FilePath)!, key), "first config recovery: the master key and the store key are in no file");
            }
            else
            {
                check(false, "first config recovery: could not read the code or the manifest");
            }

            check(page.Contains("id=\"recovery-box\"", StringComparison.Ordinal) && page.Contains("id=\"recovery\"", StringComparison.Ordinal) && !page.Contains("innerHTML", StringComparison.Ordinal) && !CodePattern.IsMatch(page), "first config recovery: the page has a hidden box for the code, no innerHTML and no code in it");
            check(!CodePattern.IsMatch(create) && !CodePattern.IsMatch(again), "first config recovery: no reply before the final one has a code");
        }

        // An aborted first config (no 6-digit code typed, or Cancel) stores nothing and the code appears nowhere.
        foreach ((string name, bool cancel) in new[] { ("no code typed", false), ("cancelled", true) })
        {
            StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "first-abort-" + Guid.NewGuid().ToString("N")));
            Flow flow = new((announce, read) =>
            {
                (EnrollmentTarget primary, EnrollmentTarget local) = Targets(db, announce, read);

                return new SettingsPage(db, primary, local, announce, read).Run();
            });
            (string Url, string Origin)? link = flow.Next();
            string recovery = "";
            if (link is not null && cancel)
            {
                TestState.Get(client, link.Value.Url);
                TestState.Post(client, link.Value.Url + "/deny", "");
            }
            else if (link is not null)
            {
                recovery = Member(RegisterFirst(client, link.Value, laptop, text).Sign, "recovery") ?? "";
                flow.Type(null);
            }

            ConfigChange result = flow.Result();
            SqliteConnection.ClearAllPools();
            check(result.Code == RunCommand.Denied, $"first config recovery: {name}: denied ({result.Code} {result.Detail})");
            check(!File.Exists(db.FilePath) || TestState.Current(db) is null, $"first config recovery: {name}: no manifest is stored");
            check(recovery.Length == 0 || (!FolderHoldsCode(Path.GetDirectoryName(db.FilePath)!, recovery) && !Holds([result.Detail, flow.AllLines()], CodeForms(recovery))), $"first config recovery: {name}: the code was never stored or said");
            await Task.CompletedTask;
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // --recover
    // ---------------------------------------------------------------------------------------------------------------

    /// <summary>The page-1 body that sends <paramref name="code" /> sealed to the page's key (the scheme of the set page).</summary>
    private static string SealedCode(JsonElement start, string code)
    {
        byte[] bind = Base64Url.DecodeFromChars(start.GetProperty("bind").GetString()!);
        byte[] point = Base64Url.DecodeFromChars(start.GetProperty("serverKey").GetString()!);
        using ECDiffieHellman mine = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using ECDiffieHellman server = ECDiffieHellman.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = point[1..33], Y = point[33..] } });
        byte[] shared = mine.DeriveRawSecretAgreement(server.PublicKey);
        byte[] key = HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 32, bind, Encoding.UTF8.GetBytes("with-secrets/v1 secrets"));
        byte[] plain = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new Dictionary<string, string> { ["code"] = code }));
        byte[] iv = RandomNumberGenerator.GetBytes(12);
        byte[] ct = new byte[plain.Length];
        byte[] tag = new byte[16];
        using AesGcm aes = new(key, 16);
        aes.Encrypt(iv, plain, ct, tag, bind);
        ECParameters own = mine.ExportParameters(false);

        return JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["epk"] = Base64Url.EncodeToString([0x04, .. own.Q.X!, .. own.Q.Y!]),
            ["iv"] = Base64Url.EncodeToString(iv),
            ["ct"] = Base64Url.EncodeToString([.. ct, .. tag]),
        });
    }

    private static readonly DateTimeOffset Stamp = new(2026, 11, 3, 12, 0, 0, TimeSpan.Zero);

    private static Flow StartRecover(StateDatabase db, Action? beforeSwap = null)
    {
        return new Flow((announce, read) =>
        {
            (EnrollmentTarget primary, EnrollmentTarget local) = Targets(db, announce, read);

            return new StoreRecovery(db, primary, local, announce, read) { Clock = () => Stamp, BeforeSwap = beforeSwap }.Run();
        });
    }

    private static (int Status, string Body) SendCode(HttpClient client, (string Url, string Origin) link, string code)
    {
        (_, string page) = TestState.Get(client, link.Url);

        return TestState.Post(client, link.Url + "/code", SealedCode(StartOf(page), code));
    }

    private static string[] Files(string folder) => [.. Directory.EnumerateFiles(folder).Select(Path.GetFileName).OfType<string>().Order(StringComparer.Ordinal)];

    private static async Task Recover(Action<bool, string> check, string root)
    {
        using HttpClient client = NewClient();
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.RS256();
        using TestAuthenticator fresh = TestAuthenticator.ES256();
        string text = ToolSettings.Defaults.Canonical();

        // Right code, the old keys still exist, a new authenticator: all three values are in the new store.
        {
            World w = NewWorld(root, laptop, phone);
            Manifest before = TestState.Current(w.Db)!;
            string oldBytes = Snapshot(w.Db);
            string oldKey = OldStoreKey(w.Db, laptop);
            using Unlock oldUnlock = TestVault.Unlock(w.Db, laptop)!;
            string oldMaster = Convert.ToHexStringLower(KeyVault.OpenMaster(before, oldUnlock));
            Flow flow = StartRecover(w.Db);
            (string Url, string Origin)? one = flow.Next();
            string pageOne = one is null ? "" : TestState.Get(client, one.Value.Url).Body;
            (int codeStatus, string codeBody) = one is null ? (0, "") : SendCode(client, one.Value, w.Code.ToLowerInvariant().Replace('-', ' '));
            (string Url, string Origin)? two = flow.Next();
            (string page, string create, string sign) = two is null ? ("", "", "") : RegisterFirst(client, two.Value, fresh, text);
            string newCode = Member(sign, "recovery") ?? "";
            flow.Type(Member(sign, "code"));
            ConfigChange result = flow.Result();
            SqliteConnection.ClearAllPools();

            check(result.Code == 0, "recover: done (" + result.Detail + ")");
            check(flow.Lines.Count >= 2 && flow.Lines[0] == AdminKey.Line(before) + "\nCompare it with the fingerprint you noted. If it differs, do not type the code." && flow.Lines[1].StartsWith(StoreRecovery.AnnouncePrefix, StringComparison.Ordinal), "recover: the old admin fingerprint line and the compare warning are printed before the page-1 link");
            check(codeStatus == 200 && codeBody.Contains("\"ok\":true", StringComparison.Ordinal) && two is not null, "recover: the right code (typed in lower case with spaces) is accepted on page 1 and the new passkey page follows (" + codeStatus + ")");
            Manifest? after = TestState.Current(w.Db);
            check(after is { Version: 1 } && after.Keys.Count == 1 && after.Keys[0].Id == TestAuthenticator.Encode(fresh.CredentialId) && after.Store != before.Store && after.Recovery is not null && after.Recovery.Wrap != before.Recovery!.Wrap && after.Secrets.Count == 3,
                "recover: the new state has only the new passkey, a new store key, a new recovery slot and the three secrets");
            Dictionary<string, string>? read = ReadAll(w.Db, fresh);
            check(read is not null && Values.All(item => read.TryGetValue(item.Key, out string? value) && value == item.Value), "recover: all three values are read through the normal approved path with the new passkey");
            check(ReadAll(w.Db, laptop) is null && ReadAll(w.Db, phone) is null, "recover: the old admin keys are gone from the new state (they open nothing)");
            string renamed = Path.Combine(w.Folder, "state.db.recovered-20261103120000");
            check(File.Exists(renamed), "recover: the old file was renamed to state.db.recovered-<UTC yyyyMMddHHmmss>, not deleted (" + string.Join(", ", Files(w.Folder)) + ")");
            check(File.Exists(renamed) && Snapshot(new StateDatabase(renamed)) == oldBytes, "recover: the renamed file is the old state, unchanged");
            check(Files(w.Folder).All(name => !name.Contains(".recovering-", StringComparison.Ordinal)), "recover: no temporary file is left");
            IReadOnlyList<AuditRecord> rows = AuditRows(w.Db);
            AuditRecord? recovered = rows.FirstOrDefault(row => row.Event == "recovered");
            check(recovered is not null && recovered.Detail.Contains("3 secrets", StringComparison.Ordinal) && recovered.Detail.Contains("state.db.recovered-20261103120000", StringComparison.Ordinal), "recover: a `recovered` audit row names the secret count and the old file (" + recovered?.Detail + ")");
            check(after is not null && Fails(() => KeyVault.OpenRecovery(after, RecoveryCodeBytes(w.Code))), "recover: the old recovery code no longer opens the new store");
            check(after is not null && RecoveryCode.TryParse(newCode, out byte[] fresher) && KeyVault.UnwrapVault(after.Vault, KeyVault.OpenRecovery(after, fresher), after.Store).Length == 64, "recover: the new recovery code (final page) opens the new store");
            check(CodePattern.IsMatch(newCode) && newCode != w.Code, "recover: a new recovery code was shown on the last page");

            string[] said = [.. flow.Lines, result.Detail, pageOne, codeBody, page, create, Audit(w.Db)];
            string[] secrets = [.. Values.Values];
            check(!Holds(said, secrets), "recover: no secret value is in any output or audit entry");
            check(!Holds(said, [oldKey, oldMaster, Convert.ToBase64String(Convert.FromHexString(oldKey)), Convert.ToBase64String(Convert.FromHexString(oldMaster))]), "recover: the old store key and the old master key are in no output or audit entry");
            check(!Holds([.. said, flow.AllLines()], CodeForms(w.Code)) && !Holds(said, CodeForms(newCode).Where(form => !sign.Contains(form, StringComparison.Ordinal)).ToArray()), "recover: neither recovery code is in any terminal line, result text or earlier page");
            check(!pageOne.Contains(w.Code, StringComparison.Ordinal) && !codeBody.Contains(w.Code, StringComparison.Ordinal), "recover: page 1 and its answer never hold the code typed");
            string[] folderForms = [oldKey, oldMaster, Convert.ToBase64String(Convert.FromHexString(oldKey)), Convert.ToBase64String(Convert.FromHexString(oldMaster))];
            check(folderForms.All(form => !WebApprovalTests.FolderHolds(w.Folder, Encoding.UTF8.GetBytes(form))) && !WebApprovalTests.FolderHolds(w.Folder, Convert.FromHexString(oldMaster)) && !WebApprovalTests.FolderHolds(w.Folder, Encoding.UTF8.GetBytes(oldKey)),
                "recover: the old store key and master key (text, hex, base64, raw) are in no file of the folder, the renamed old file included");
            check(!FolderHoldsCode(w.Folder, w.Code) && !FolderHoldsCode(w.Folder, newCode), "recover: neither recovery code is in any file of the folder");
            check(secrets.All(value => !WebApprovalTests.FolderHolds(w.Folder, Encoding.UTF8.GetBytes(value))), "recover: no secret value is in any file of the folder");
        }

        // A wrong code three times: refused, the old state is unchanged, no new file, one change-denied row, one-line message.
        {
            World w = NewWorld(root, laptop);
            string before = Snapshot(w.Db);
            string[] filesBefore = Files(w.Folder);
            Flow flow = StartRecover(w.Db);
            (string Url, string Origin)? one = flow.Next();
            string wrong = RecoveryCode.Format(KeyVault.NewRecoveryCode());
            List<int> statuses = [];
            if (one is not null)
            {
                statuses.Add(SendCode(client, one.Value, wrong).Status);
                statuses.Add(SendCode(client, one.Value, "not a code").Status);
                statuses.Add(SendCode(client, one.Value, wrong).Status);
            }

            ConfigChange result = flow.Result();
            check(result.Code == RunCommand.Denied && !result.Detail.Contains('\n', StringComparison.Ordinal) && result.Detail.Length > 0, "recover: a wrong code is refused with a one-line message (" + result.Code + " " + result.Detail + ")");
            check(statuses.SequenceEqual([400, 400, 403]), "recover: page 1 answers 400 twice and 403 at the third wrong code (" + string.Join(",", statuses) + ")");
            check(Snapshot(w.Db) == before, "recover: after a wrong code the manifest and the rows are as they were");
            check(Files(w.Folder).SequenceEqual(filesBefore), "recover: after a wrong code there is no new file (" + string.Join(", ", Files(w.Folder)) + ")");
            check(flow.Next() is null, "recover: after a wrong code there is no second page");
            IReadOnlyList<AuditRecord> rows = AuditRows(w.Db);
            check(rows.Count(row => row.Event == AuditLog.ChangeDenied && row.Detail.StartsWith("--recover: ", StringComparison.Ordinal)) == 1 && rows.All(row => row.Event != "recovered"), "recover: a wrong code writes one change-denied row for --recover and no `recovered` row");
            check(!Holds([Audit(w.Db), result.Detail, flow.AllLines()], CodeForms(wrong)), "recover: the wrong code typed is in no audit entry or message");
            check(ReadAll(w.Db, laptop)?.Count == 3, "recover: the old state still works with its own key");
        }

        // The old store changes (a --set) after page 1 verified it and before the swap: refused, nothing swapped.
        {
            World w = NewWorld(root, laptop);
            Flow flow = StartRecover(w.Db, () => SecretStoreTests.Put(w.Store, new Dictionary<string, string> { ["D_NAME"] = "Recov-Delta-Secret-4" }));
            (string Url, string Origin)? one = flow.Next();
            if (one is not null)
            {
                SendCode(client, one.Value, w.Code);
                (string Url, string Origin)? two = flow.Next();
                if (two is not null)
                {
                    (_, _, string sign) = RegisterFirst(client, two.Value, fresh, text);
                    flow.Type(Member(sign, "code"));
                }
            }

            ConfigChange result = flow.Result();
            Manifest? now = TestState.Current(w.Db);
            check(result.Code != 0 && result.Detail.Contains("the old store changed while you were recovering; run --recover again", StringComparison.Ordinal), "recover: a --set between the check and the swap is refused (" + result.Detail + ")");
            check(now is not null && now.Keys.Count == 1 && now.Keys[0].Id == TestAuthenticator.Encode(laptop.CredentialId) && now.Secrets.ContainsKey("D_NAME") && Files(w.Folder).SequenceEqual(["state.db"]), "recover: after that refusal the old store (with the new secret) is in place and no recovered or temporary file exists (" + string.Join(", ", Files(w.Folder)) + ")");
        }

        // A right code, then a failure at the new-key step: cancelled on the passkey page, no 6-digit code, and a failed swap.
        foreach ((string name, int how) in new[] { ("cancelled on the new passkey page", 0), ("the 6-digit code not typed", 1), ("the swap fails", 2), ("cancelled on page 1", 3) })
        {
            World w = NewWorld(root, laptop);
            string before = Snapshot(w.Db);
            string[] filesBefore = Files(w.Folder);
            Flow flow = StartRecover(w.Db, how == 2 ? () => throw new IOException("test swap failure") : null);
            (string Url, string Origin)? one = flow.Next();
            string newCode = "";
            if (one is not null && how == 3)
            {
                TestState.Get(client, one.Value.Url);
                TestState.Post(client, one.Value.Url + "/deny", "");
            }
            else if (one is not null)
            {
                SendCode(client, one.Value, w.Code);
                (string Url, string Origin)? two = flow.Next();
                if (two is not null && how == 0)
                {
                    TestState.Get(client, two.Value.Url);
                    TestState.Post(client, two.Value.Url + "/deny", "");
                }
                else if (two is not null)
                {
                    (_, _, string sign) = RegisterFirst(client, two.Value, fresh, text);
                    newCode = Member(sign, "recovery") ?? "";
                    flow.Type(how == 2 ? Member(sign, "code") : null);
                }
            }

            ConfigChange result = flow.Result();
            check(result.Code != 0, $"recover: {name}: not done ({result.Code} {result.Detail})");
            check(Snapshot(w.Db) == before, $"recover: {name}: the old manifest and rows are untouched");
            check(Files(w.Folder).SequenceEqual(filesBefore), $"recover: {name}: no new, renamed or temporary file ({string.Join(", ", Files(w.Folder))})");
            check(ReadAll(w.Db, laptop)?.Count == 3, $"recover: {name}: the old state still opens with its own key");
            check(AuditRows(w.Db).All(row => row.Event != "recovered") && (newCode.Length == 0 || !FolderHoldsCode(w.Folder, newCode)), $"recover: {name}: no `recovered` row, and the new code is stored nowhere");
        }

        // The old state is not touched by --recover reading it: a state that fails verification is refused before any page.
        {
            World w = NewWorld(root, laptop);
            ManifestTests.Execute(w.Db.FilePath, "UPDATE secrets SET ciphertext = 'x' WHERE name = 'A_NAME'");
            Flow flow = StartRecover(w.Db);
            ConfigChange result = flow.Result();
            check(result.Code != 0 && flow.Next() is null && Files(w.Folder).Length == 1, "recover: a store that fails verification is refused before any page (" + result.Detail + ")");
        }

        // Nothing to recover.
        {
            StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "nothing-" + Guid.NewGuid().ToString("N")));
            Flow flow = StartRecover(db);
            ConfigChange result = flow.Result();
            check(result.Code != 0 && !File.Exists(db.FilePath), "recover: with no state.db there is nothing to recover and nothing is made (" + result.Detail + ")");
        }

        await Task.CompletedTask;
    }

    private static byte[] RecoveryCodeBytes(string code)
    {
        RecoveryCode.TryParse(code, out byte[] bytes);

        return bytes;
    }

    // ---------------------------------------------------------------------------------------------------------------
    // --rotate-key
    // ---------------------------------------------------------------------------------------------------------------

    private static Flow StartRotate(World w, Action<Dictionary<string, string>>? tamper = null, ApprovalSettings? settings = null)
    {
        return new Flow((announce, read) =>
        {
            (EnrollmentTarget primary, EnrollmentTarget local) = Targets(w.Db, announce, read, settings);

            return new KeyRotation(w.Db, w.Store, primary, local, announce) { RowsBeforeSign = tamper }.Run();
        });
    }

    private static async Task Rotate(Action<bool, string> check, string root)
    {
        using HttpClient client = NewClient();
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.RS256();
        using TestAuthenticator viewer = TestAuthenticator.ES256();

        // The good flow: tap 1 and tap 2 by the laptop; the phone is removed.
        {
            World w = NewWorld(root, laptop, phone);
            Manifest before = TestState.Current(w.Db)!;
            string oldKey = OldStoreKey(w.Db, laptop);
            using Unlock oldUnlock = TestVault.Unlock(w.Db, laptop)!;
            string oldMaster = Convert.ToHexStringLower(KeyVault.OpenMaster(before, oldUnlock));
            string oldPrf = Convert.ToHexStringLower(oldUnlock.Output);
            Dictionary<string, string> oldRows = new SecretStore(w.Db).Snapshot().Rows;
            Flow flow = StartRotate(w);
            (string Url, string Origin)? one = flow.Next();
            string pageOne = one is null ? "" : TestState.Get(client, one.Value.Url).Body;
            (int status1, string body1) = one is null ? (0, "") : TestState.Approve(client, one.Value.Url, one.Value.Origin, "localhost", laptop);
            (string Url, string Origin)? two = flow.Next();
            string pageTwo = two is null ? "" : TestState.Get(client, two.Value.Url).Body;
            (int status2, string body2) = two is null ? (0, "") : TestState.Approve(client, two.Value.Url, two.Value.Origin, "localhost", laptop);
            string resentBody = TestState.LastProofBody;
            (int resentStatus, string resentReply) = two is null ? (0, "") : TestState.Post(client, two.Value.Url + "/proof", resentBody);
            ConfigChange result = flow.Result();
            SqliteConnection.ClearAllPools();
            string? newCode = Member(body2, "recovery");
            check(resentStatus is 404 or 409 or 0 && Member(resentReply, "recovery") is null && !CodePattern.IsMatch(resentReply), "rotate: the same proof sent again (a page resend) gets 404 and no second code (" + resentStatus + ")");

            check(result.Code == 0 && status1 == 200 && status2 == 200, $"rotate: done after two taps ({result.Code} {result.Detail}; {status1}, {status2})");
            check(pageOne.Contains("These keys will be removed and must be enrolled again with --enroll: ", StringComparison.Ordinal) && pageOne.Contains("phone", StringComparison.Ordinal), "rotate: page 1 lists the keys that will be removed");
            check(flow.Lines.Count >= 3 && flow.Lines[0] == AdminKey.Line(before) + "\nCompare it with the fingerprint you noted. If it differs, do not approve." && flow.Lines[1].StartsWith("Approval needed", StringComparison.Ordinal), "rotate: the old admin fingerprint line and the compare warning are printed before the page-1 link");
            check(result.Detail.Contains("shown on the last page only once. If the page did not show it (lost connection), the old code is already dead: run --rotate-key again.", StringComparison.Ordinal), "rotate: the terminal text says the code is shown once and what to do if it was missed");
            check(pageTwo.Contains("Step 2 of 2", StringComparison.Ordinal) && pageTwo.Contains("id=\"approve\"", StringComparison.Ordinal), "rotate: page 2 is Step 2 of 2 with its own explicit button");
            Manifest? after = TestState.Current(w.Db);
            check(after is not null && after.Version == before.Version + 1 && after.Keys.Count == 1 && after.Keys[0].Id == TestAuthenticator.Encode(laptop.CredentialId) && after.Store != before.Store && after.Vault != before.Vault && after.Recovery!.Wrap != before.Recovery!.Wrap && after.Recovery.Salt != before.Recovery.Salt,
                "rotate: manifest v+1 has only the tapped key, a new store key, vault and recovery slot");
            check(after is not null && after.Keys[0].Slot is { } slot && slot.Salt == before.Keys.First(key => key.Name == "laptop").Slot!.Salt, "rotate: the kept key keeps its slot salt (its PRF output still works)");
            Dictionary<string, string>? read = ReadAll(w.Db, laptop);
            check(read is not null && Values.All(item => read.TryGetValue(item.Key, out string? value) && value == item.Value), "rotate: every value still decrypts through an approved read by the tapped key");
            Dictionary<string, string> newRows = new SecretStore(w.Db).Snapshot().Rows;
            check(newRows.Count == 3 && Names.All(name => newRows[name] != oldRows[name]), "rotate: every row is new ciphertext");
            check(newRows.Values.All(row => DecryptFails(oldKey, row)), "rotate: the old store key decrypts no new row");
            check(ReadAll(w.Db, phone) is null, "rotate: the removed key opens nothing");
            PasskeyMethod method = new(new PasskeyStore(w.Db), Local);
            check(method.Enrolled().Select(entry => entry.Name).SequenceEqual(["laptop"]), "rotate: --enrolled lists only the kept key (" + string.Join(", ", method.Enrolled().Select(entry => entry.Name)) + ")");
            check(after is not null && Fails(() => KeyVault.OpenRecovery(after, RecoveryCodeBytes(w.Code))), "rotate: the old recovery code fails");
            check(newCode is not null && CodePattern.IsMatch(newCode) && after is not null && RecoveryCode.TryParse(newCode, out byte[] fresher) && DotenvxCipher.Instance.Derive(Encoding.UTF8.GetString(KeyVault.UnwrapVault(after.Vault, KeyVault.OpenRecovery(after, fresher), after.Store))) == after.Store,
                "rotate: the new recovery code (final reply) opens the new store (" + (newCode ?? "none") + ")");
            IReadOnlyList<AuditRecord> rows = AuditRows(w.Db);
            AuditRecord? rotated = rows.FirstOrDefault(row => row.Event == "key-rotated");
            check(rotated is not null && rotated.Detail.Contains("phone", StringComparison.Ordinal) && rotated.Detail.Contains("1 key(s) removed", StringComparison.Ordinal) && rotated.KeyName == "laptop", "rotate: a key-rotated audit row names the removed keys and the count (" + rotated?.Detail + ")");

            string[] said = [.. flow.Lines, result.Detail, pageOne, pageTwo, body1, Audit(w.Db)];
            check(!Holds(said, [.. Values.Values]) && !Holds([body2], [.. Values.Values]), "rotate: no secret value is in any output");
            string[] keyForms = [oldKey, oldMaster, oldPrf, Convert.ToBase64String(Convert.FromHexString(oldKey)), Convert.ToBase64String(Convert.FromHexString(oldMaster)), Base64Url.EncodeToString(oldUnlock.Output)];
            check(!Holds([.. said, body2], keyForms), "rotate: the old store key, master key and PRF output are in no output");
            check(keyForms.All(form => !WebApprovalTests.FolderHolds(w.Folder, Encoding.UTF8.GetBytes(form))) && !WebApprovalTests.FolderHolds(w.Folder, Convert.FromHexString(oldMaster)) && !WebApprovalTests.FolderHolds(w.Folder, oldUnlock.Output), "rotate: the old keys and the PRF output are in no file");
            check(!Holds(said, CodeForms(w.Code)) && (newCode is null || !Holds(said, CodeForms(newCode))) && (newCode is null || !FolderHoldsCode(w.Folder, newCode)) && !FolderHoldsCode(w.Folder, w.Code), "rotate: neither recovery code is in any terminal line, earlier page, audit entry or file");
            check(pageTwo.Contains("id=\"recovery-box\"", StringComparison.Ordinal) && !CodePattern.IsMatch(pageTwo), "rotate: page 2 has a box for the code but not the code");
            check(new SecretStore(w.Db).ListNames().SequenceEqual(Names), "rotate: the names are the same");
        }

        // Rotation with only one key (nothing to remove) works, and a second rotation works on the result.
        {
            World w = NewWorld(root, laptop);
            for (int round = 1; round <= 2; round++)
            {
                Flow flow = StartRotate(w);
                (string Url, string Origin)? one = flow.Next();
                if (one is not null)
                {
                    TestState.Approve(client, one.Value.Url, one.Value.Origin, "localhost", laptop);
                }

                (string Url, string Origin)? two = flow.Next();
                if (two is not null)
                {
                    TestState.Approve(client, two.Value.Url, two.Value.Origin, "localhost", laptop);
                }

                ConfigChange result = flow.Result();
                Dictionary<string, string>? read = ReadAll(w.Db, laptop);
                check(result.Code == 0, $"rotate: round {round} with one key is done ({result.Detail})");
                check(read is not null && Values.All(item => read.TryGetValue(item.Key, out string? value) && value == item.Value), $"rotate: round {round} with one key keeps every value");
            }
        }

        // Failed or aborted rotations leave the state as it was.
        (string Name, int Case)[] refused =
        [
            ("aborted after tap 1, before tap 2", 0),
            ("a key that is not the tapped one confirms", 1),
            ("a non-admin key taps", 2),
            ("the state changes between the taps (stale version)", 3),
            ("a row is changed between the pages", 4),
            ("no answer to page 2 before the time limit", 5),
            ("the PRF output of another key is sent at tap 1", 6),
        ];
        foreach ((string name, int which) in refused)
        {
            World w = NewWorld(root, laptop, phone, viewer);
            string before = Snapshot(w.Db);
            string oldPhoneKey = OldStoreKey(w.Db, phone);
            string oldStore = TestState.Current(w.Db)!.Store;
            long concurrentVersion = 0;
            Action<Dictionary<string, string>>? tamper = which switch
            {
                3 => _ =>
                {
                    TestState.Settings(w.Db, ToolSettings.Defaults with { ReuseMinutes = 20 });
                    concurrentVersion = TestState.Current(w.Db)!.Version;
                },
                4 => rows => rows["A_NAME"] = rows["B_NAME"],
                _ => null,
            };
            Flow flow = StartRotate(w, tamper, which == 5 ? new ApprovalSettings("passkey", null, 0, TimeSpan.FromSeconds(3)) : null);
            (string Url, string Origin)? one = flow.Next();
            int status1 = 0;
            int status2 = 0;
            string body2 = "";
            if (one is not null)
            {
                (status1, _) = TestState.Approve(client, one.Value.Url, one.Value.Origin, "localhost", which == 2 ? viewer : laptop, which == 6 ? PrfMode.OtherOwnSalt : PrfMode.Normal, which == 6 ? phone : null);
            }

            (string Url, string Origin)? two = status1 == 200 ? flow.Next() : null;
            if (two is not null)
            {
                if (which == 0)
                {
                    TestState.Get(client, two.Value.Url);
                    status2 = TestState.Post(client, two.Value.Url + "/deny", "").Status;
                }
                else if (which != 5)
                {
                    (status2, body2) = TestState.Approve(client, two.Value.Url, two.Value.Origin, "localhost", which == 1 ? phone : laptop);
                }
            }

            ConfigChange result = flow.Result();
            string after = Snapshot(w.Db);
            string expected = which == 3 ? after : before;
            check(result.Code != 0 && result.Code != -1, $"rotate refused: {name}: not done ({result.Code} {result.Detail})");
            if (which == 3)
            {
                Manifest? now = TestState.Current(w.Db);
                check(now is not null && now.Version == concurrentVersion && now.Store == oldStore && now.Keys.Count == 3 && now.Settings.ReuseMinutes == 20, $"rotate refused: {name}: only the concurrent change is in the state, none of the rotation");
                check(ReadAll(w.Db, laptop)?.Count == 3 && ReadAll(w.Db, phone)?.Count == 3, $"rotate refused: {name}: every key still reads every value");
            }
            else
            {
                check(after == expected, $"rotate refused: {name}: manifest, keys and rows are unchanged");
                check(ReadAll(w.Db, laptop)?.Count == 3 && ReadAll(w.Db, phone)?.Count == 3, $"rotate refused: {name}: every key still reads every value");
            }

            check(AuditRows(w.Db).All(row => row.Event != "key-rotated") && AuditRows(w.Db).Count(row => row.Event == AuditLog.ChangeDenied && row.Detail.StartsWith("--rotate-key: ", StringComparison.Ordinal)) == 1, $"rotate refused: {name}: no key-rotated row; one change-denied row");
            check(!Holds([result.Detail, flow.AllLines(), body2], [oldPhoneKey]) && !Holds([result.Detail, body2], [.. Values.Values]), $"rotate refused: {name}: no key or value in the output");
            if (which == 4)
            {
                check(status2 == 403 && result.Detail.Contains("proof was not accepted", StringComparison.Ordinal), $"rotate refused: {name}: the confirmation is refused as a bad proof, because the signature covers the new ciphertext ({status2}; {result.Detail})");
            }

            if (which == 1)
            {
                check(status2 == 403, $"rotate refused: {name}: the confirming page answers 403 ({status2})");
            }
        }

        await Task.CompletedTask;
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Page scripts
    // ---------------------------------------------------------------------------------------------------------------

    internal static void PageScripts(Action<bool, string> check)
    {
        string recoveryPage = RecoveryPage.Build("Admins: laptop ab12", [1, 2, 3], "k", 3).Body;
        string rotation = ApprovalPage.Build(new ApprovalPrompt("Step 2 of 2", "t"), new ProofStart("webauthn", "{}"), "n", [1], TimeSpan.Zero, null, "{}", null, true).Body;
        string plainApproval = ApprovalPage.Build(new ApprovalPrompt("h", "t"), new ProofStart("webauthn", "{}"), "n", [1], TimeSpan.Zero, manifest: "{}").Body;
        string firstRun = ConfigPageHtml.Build(true, ToolSettings.Defaults, "{}", AdminKey.NotSetUp).Body;
        foreach ((string name, string page) in new[] { ("recovery", recoveryPage), ("rotation", rotation), ("first config", firstRun) })
        {
            string script = ScriptOf(page);
            check(!script.Contains("innerHTML", StringComparison.Ordinal) && !page.Contains("innerHTML", StringComparison.Ordinal) && !script.Contains("outerHTML", StringComparison.Ordinal) && !script.Contains("document.write", StringComparison.Ordinal) && !script.Contains("insertAdjacentHTML", StringComparison.Ordinal), $"recovery pages: the {name} page never builds HTML from data (no innerHTML)");
            check(TapRule.Violations(script).Count == 0, $"recovery pages: every passkey prompt on the {name} page starts in the tap (" + string.Join("; ", TapRule.Violations(script)) + ")");
            check(!Regex.IsMatch(page, "\\son[a-z]+=", RegexOptions.IgnoreCase), $"recovery pages: no inline event attributes on the {name} page");
        }

        check(rotation.Contains("\"recovery\":\"1\"", StringComparison.Ordinal) && rotation.Contains("id=\"recovery-box\"", StringComparison.Ordinal) && ScriptOf(rotation).Contains("showRecovery(data)", StringComparison.Ordinal) && ScriptOf(rotation).Contains("shown.textContent = data.recovery;", StringComparison.Ordinal), "recovery pages: the rotation page shows the code with textContent");
        check(!plainApproval.Contains("recovery-box", StringComparison.Ordinal) && !ScriptOf(plainApproval).Contains("shown.textContent", StringComparison.Ordinal), "recovery pages: an ordinary approval page has no recovery box and no code printing");
        check(Regex.Count(ScriptOf(rotation), @"credentials\.(get|create)\s*\(") == 1 && ScriptOf(rotation).Contains("= \"Cancel\";", StringComparison.Ordinal) && Regex.Count(ScriptOf(rotation), @"= \+\+attempt;") >= 1 && Regex.Count(ScriptOf(rotation), @"!== attempt\)") >= 2, "recovery pages: the rotation page keeps the Cancel label and the attempt counter");
        check(rotation.Contains("<button id=\"approve\"", StringComparison.Ordinal) && rotation.Contains("<button id=\"deny\"", StringComparison.Ordinal) && !rotation.Contains("allowCredentials", StringComparison.Ordinal), "recovery pages: the rotation page has an explicit confirm button and Deny, and names no credentials");

        string recoveryScript = ScriptOf(recoveryPage);
        check(recoveryScript.Contains("post(\"deny\"", StringComparison.Ordinal) && recoveryPage.Contains("id=\"deny\"", StringComparison.Ordinal) && recoveryScript.Contains("AbortController", StringComparison.Ordinal), "recovery pages: the code page has Cancel and a post that cannot hang");
        check(recoveryScript.Contains("var attempt = 0;", StringComparison.Ordinal) && recoveryScript.Contains("++attempt", StringComparison.Ordinal) && recoveryScript.Contains("mine !== attempt", StringComparison.Ordinal), "recovery pages: the code page has the attempt counter that its continuations check");
        check(recoveryScript.Contains("with-secrets/v1 secrets", StringComparison.Ordinal) && recoveryScript.Contains("additionalData: bind", StringComparison.Ordinal) && recoveryScript.Contains("post(\"code\", JSON.stringify(sealed))", StringComparison.Ordinal) && !recoveryScript.Contains("post(\"code\", text", StringComparison.Ordinal), "recovery pages: the code leaves the page only sealed to the page's key");
        check(recoveryPage.Contains("type=\"text\"", StringComparison.Ordinal) && recoveryPage.Contains("autocomplete=\"off\"", StringComparison.Ordinal) && recoveryPage.Contains("replaces the store", StringComparison.OrdinalIgnoreCase) && recoveryPage.Contains("old admin keys are gone", StringComparison.Ordinal), "recovery pages: the code page warns that it replaces the store and that the old admin keys are gone");
        check(!recoveryPage.Contains("allowCredentials", StringComparison.Ordinal), "recovery pages: the code page uses no passkey prompt");
    }

    private static string ScriptOf(string page)
    {
        int at = page.LastIndexOf("<script>", StringComparison.Ordinal) + "<script>".Length;

        return page[at..page.IndexOf("</script>", at, StringComparison.Ordinal)];
    }
}

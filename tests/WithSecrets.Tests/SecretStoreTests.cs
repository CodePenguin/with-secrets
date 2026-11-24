using System.Security.Cryptography;
using System.Text;

using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>Counts the decrypt calls, so a test can see that only the requested rows were decrypted.</summary>
internal sealed class CountingCipher : ISecretCipher
{
    private int _decrypts;

    public int Decrypts => _decrypts;

    public (string PublicKey, string PrivateKey) NewKeyPair() => DotenvxCipher.Instance.NewKeyPair();

    public string Encrypt(string value, string publicKey) => DotenvxCipher.Instance.Encrypt(value, publicKey);

    public string Decrypt(string privateKey, string ciphertext)
    {
        Interlocked.Increment(ref _decrypts);

        return DotenvxCipher.Instance.Decrypt(privateKey, ciphertext);
    }
}

/// <summary>
/// The secret store in with-secrets.db: one row per secret (the Dotenvx ciphertext), and the signed manifest has the store's public
/// key and the SHA-256 of every ciphertext. Reads decrypt only the requested rows; a row that does not match its signed hash,
/// a row without a hash and a hash without a row are a store that failed verification (exit 4).
/// </summary>
internal static class SecretStoreTests
{
    public static async Task Run(Action<bool, string> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "ws-store-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            ManifestText(check);
            RoundTrip(check, root);
            Tampers(check, root);
            await Runs(check, root);
            Zeroing(check);
            Transactions(check, root);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            Directory.Delete(root, true);
        }
    }

    private const string ValueA = "Alpha-Store-Value-1";
    private const string ValueB = "Bravo-Store-Value-2";
    private const string ValueC = "Charlie-Store-Value-3";

    /// <summary>
    /// Stores <paramref name="values" /> (and removes <paramref name="removes" />) the way --set and --remove do: the
    /// values are encrypted to the store key, the admin signs the next manifest with their hashes, and rows and manifest are
    /// written in one transaction. Null when written, else why not.
    /// </summary>
    public static string? Put(SecretStore store, IReadOnlyDictionary<string, string> values, IReadOnlyCollection<string>? removes = null)
    {
        Manifest current = TestState.Current(store.Database) ?? throw new InvalidOperationException("no manifest");
        (string publicKey, string? vault, ReviewKey? review) = KeyFor(store, current);
        Dictionary<string, string> rows = values.ToDictionary(item => item.Key, item => store.Encrypt(item.Value, publicKey), StringComparer.Ordinal);
        Manifest next = SecretStore.Next(current, publicKey, rows, removes ?? [], vault, review);

        // Like a first setup, the store has a recovery slot; a test knows its code (TestVault.RecoveryCode).
        next = next.Recovery is null && next.Store.Length > 0 ? next with { Recovery = TestVault.RecoverySlot(store.Database, next.Store) } : next;
        ManifestKey admin = current.Admins.First(key => TestAuthenticator.ById(key.Id) is not null);
        SignedManifest signed = TestState.Sign(TestAuthenticator.ById(admin.Id)!, next.Canonical(), admin.RpId);

        return store.TryApply(current.Version, signed, rows, removes ?? [], AdminEvent.Change("test-put", "test", admin.Name));
    }

    /// <summary>The store public key of <paramref name="manifest" /> (no vault); before the first secret, a new key pair and its vault under the state's master key.</summary>
    private static (string PublicKey, string? Vault, ReviewKey? Review) KeyFor(SecretStore store, Manifest manifest)
    {
        if (manifest.Store.Length > 0)
        {
            return (manifest.Store, null, null);
        }

        (string publicKey, string privateKey) = DotenvxCipher.Instance.NewKeyPair();

        return (publicKey, TestVault.Vault(store.Database, privateKey, publicKey), KeyVault.NewReviewKey(TestVault.Master(store.Database)));
    }

    /// <summary>What the test admin's passkey releases at an approval for this state (null when it cannot).</summary>
    public static Unlock? AdminUnlock(StateDatabase db)
    {
        Manifest manifest = TestState.Current(db) ?? throw new InvalidOperationException("no manifest");
        ManifestKey admin = manifest.Admins.First(key => TestAuthenticator.ById(key.Id) is not null);

        return TestVault.Unlock(db, TestAuthenticator.ById(admin.Id)!);
    }

    /// <summary>Reads the values with what the admin passkey releases.</summary>
    public static SecretValues Read(SecretStore store, IReadOnlyCollection<string> names, Unlock? with = null)
    {
        using Unlock? unlock = with is null ? AdminUnlock(store.Database) : null;

        return store.GetValues(names, with ?? unlock);
    }

    /// <summary>A seeded with-secrets.db with a store over it.</summary>
    private static (StateDatabase Db, SecretStore Store, CountingCipher Cipher) NewStore(string root, string name)
    {
        StateDatabase db = TestState.Seeded(Path.Combine(root, name, WithSecretsDatabase.FileName));
        CountingCipher cipher = new();

        return (db, new SecretStore(db, cipher), cipher);
    }

    private static void Sql(StateDatabase db, string sql, params (string Name, object Value)[] parameters)
    {
        using SqliteConnection connection = new(new SqliteConnectionStringBuilder { DataSource = db.FilePath, Pooling = false }.ToString());
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        foreach ((string key, object value) in parameters)
        {
            command.Parameters.AddWithValue(key, value);
        }

        command.ExecuteNonQuery();
    }

    private static string Row(StateDatabase db, string name)
    {
        using SqliteConnection connection = new(new SqliteConnectionStringBuilder { DataSource = db.FilePath, Pooling = false }.ToString());
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT ciphertext FROM secrets WHERE name = $name";
        command.Parameters.AddWithValue("$name", name);

        return command.ExecuteScalar() as string ?? "";
    }

    private static bool Fails(Func<object> read, out string message)
    {
        try
        {
            read();
            message = "";

            return false;
        }
        catch (SecretStoreException failure)
        {
            message = failure.Message;

            return true;
        }
    }

    private static void ManifestText(Action<bool, string> check)
    {
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        Manifest first = Manifest.First(laptop.Record("localhost", "laptop"), ToolSettings.Defaults);
        check(first.Store == "" && first.Vault == "" && first.Secrets.Count == 0, "store manifest: a new manifest has no store key, no vault and no secrets");
        check(first.Canonical().Contains(",\"store\":\"\",\"vault\":\"\",\"secrets\":{},\"settings\":", StringComparison.Ordinal), "store manifest: the text has store, vault and secrets before the settings (" + first.Canonical() + ")");
        check(first.SettingsPrefix().EndsWith(",\"store\":\"\",\"vault\":\"\",\"secrets\":{},\"settings\":", StringComparison.Ordinal), "store manifest: the settings prefix ends with store and secrets");

        (string publicKey, _) = DotenvxCipher.Instance.NewKeyPair();
        string hashB = new('b', 64);
        string hashA = new('a', 64);
        byte[] master = KeyVault.NewMasterKey();
        string vault = KeyVault.WrapVault(Encoding.UTF8.GetBytes(DotenvxCipher.Instance.NewKeyPair().PrivateKey), master, publicKey);
        ReviewKey review = KeyVault.NewReviewKey(master);
        Manifest withSecrets = first.WithSecrets(publicKey, new Dictionary<string, string> { ["B_NAME"] = hashB, ["A_NAME"] = hashA }, vault, review);
        string text = withSecrets.Canonical();
        check(withSecrets.Version == 2 && text.Contains(",\"secrets\":{\"A_NAME\":\"" + hashA + "\",\"B_NAME\":\"" + hashB + "\"},\"settings\":", StringComparison.Ordinal), "store manifest: the secrets are sorted by name");
        Manifest? parsed = Manifest.Parse(text, out string? error);
        check(parsed is not null && error is null && parsed.Store == publicKey && parsed.Secrets.Count == 2 && parsed.Secrets["A_NAME"] == hashA && parsed.Canonical() == text, "store manifest: round trip (" + error + ")");
        check(withSecrets.WithKey(TestAuthenticator.ES256().Record("localhost", "phone")).Secrets.Count == 2 && withSecrets.WithSettings(ToolSettings.Defaults).Store == publicKey, "store manifest: key and settings changes keep the store key and the hashes");

        (string Name, string Text)[] bad =
        [
            ("a hash that is not 64 hex digits", text.Replace(hashA, "abc", StringComparison.Ordinal)),
            ("an upper-case hash", text.Replace(hashA, hashA.ToUpperInvariant(), StringComparison.Ordinal)),
            ("a name that is not valid", text.Replace("\"A_NAME\"", "\"a_name\"", StringComparison.Ordinal)),
            ("a reserved name", text.Replace("\"A_NAME\"", "\"DOTENV_X\"", StringComparison.Ordinal)),
            ("names out of order", text.Replace("\"A_NAME\"", "\"C_NAME\"", StringComparison.Ordinal)),
            ("a store key that is not hex", text.Replace(publicKey, "zz" + publicKey[2..], StringComparison.Ordinal)),
            ("a store key of the wrong length", text.Replace(publicKey, publicKey[..64], StringComparison.Ordinal)),
            ("secrets without a store key", text.Replace("\"store\":\"" + publicKey + "\"", "\"store\":\"\"", StringComparison.Ordinal)),
            ("a hash that is not text", text.Replace("\"" + hashA + "\"", "1", StringComparison.Ordinal)),
            ("no secrets member", text.Replace(",\"secrets\":{\"A_NAME\":\"" + hashA + "\",\"B_NAME\":\"" + hashB + "\"}", "", StringComparison.Ordinal)),
            ("no store member", text.Replace(",\"store\":\"" + publicKey + "\"", "", StringComparison.Ordinal)),
        ];
        foreach ((string name, string value) in bad)
        {
            check(Manifest.Parse(value, out string? why) is null && why is not null, "store manifest: " + name + " is refused (" + why + ")");
        }

        check(SecretStore.Hash("encrypted:abc") == Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes("encrypted:abc"))), "store manifest: a hash is SHA-256 of the UTF-8 ciphertext, lower-case hex");
    }

    private static void RoundTrip(Action<bool, string> check, string root)
    {
        (StateDatabase db, SecretStore store, CountingCipher cipher) = NewStore(root, "round");
        check(store.Label == "global" && store.ListNames().Count == 0, "store: an empty store lists nothing");
        check(Put(store, new Dictionary<string, string> { ["A_NAME"] = ValueA, ["B_NAME"] = ValueB, ["C_NAME"] = ValueC }) is null, "store: three secrets are stored");
        Manifest manifest = TestState.Current(db)!;
        check(manifest.Store.Length == 66 && manifest.Vault.Length > 0, "store: the first write made one key pair; the manifest has its public key and the vault");
        check(manifest.Version == 2 && manifest.Secrets.Keys.SequenceEqual(["A_NAME", "B_NAME", "C_NAME"]) && manifest.Secrets.All(item => item.Value == SecretStore.Hash(Row(db, item.Key))), "store: the manifest has the hash of every row");
        check(Row(db, "A_NAME").StartsWith("encrypted:", StringComparison.Ordinal) && !File.ReadAllText(db.FilePath).Contains(ValueA, StringComparison.Ordinal), "store: a row is a Dotenvx ciphertext; no value is in with-secrets.db");
        check(store.ListNames().SequenceEqual(["A_NAME", "B_NAME", "C_NAME"]) && cipher.Decrypts == 0, "store: --list reads names and decrypts nothing (no private key opened)");

        using (SecretValues values = Read(store, ["B_NAME"]))
        {
            check(values.Names.SequenceEqual(["B_NAME"]) && Encoding.UTF8.GetString(values.Bytes("B_NAME")) == ValueB && values.Text("B_NAME") == ValueB, "store: GetValues returns the requested value");
            check(cipher.Decrypts == 1, "store: only the requested row is decrypted (" + cipher.Decrypts + " decrypts)");
        }

        using (SecretValues two = Read(store, ["C_NAME", "A_NAME"]))
        {
            check(two.Names.Count == 2 && two.Text("A_NAME") == ValueA && two.Text("C_NAME") == ValueC && cipher.Decrypts == 3, "store: two requested rows, two decrypts");
        }

        check(Fails(() => Read(store, ["NOPE_NAME"]), out string missing) && missing.Contains("NOPE_NAME", StringComparison.Ordinal) && cipher.Decrypts == 3, "store: a name that is not stored is an error and decrypts nothing (" + missing + ")");

        // Set again: one name replaced, one new; the key pair stays.
        string oldRow = Row(db, "B_NAME");
        check(Put(store, new Dictionary<string, string> { ["B_NAME"] = "Bravo-New-Value-9", ["D_NAME"] = "Delta-Store-Value-4" }) is null, "store: a replaced and a new name are stored");
        Manifest after = TestState.Current(db)!;
        using (SecretValues read = Read(store, ["B_NAME", "D_NAME"]))
        {
            check(after.Version == 3 && after.Vault == manifest.Vault && after.Store == manifest.Store && Row(db, "B_NAME") != oldRow && read.Text("B_NAME") == "Bravo-New-Value-9" && read.Text("D_NAME") == "Delta-Store-Value-4", "store: a replaced value reads back, the new one too, with the same key pair");
        }

        check(after.Secrets.Keys.SequenceEqual(["A_NAME", "B_NAME", "C_NAME", "D_NAME"]) && after.Secrets["A_NAME"] == manifest.Secrets["A_NAME"], "store: untouched hashes stay");

        // Remove re-signs: the hash and the row go together.
        check(Put(store, new Dictionary<string, string>(), ["C_NAME"]) is null, "store: a removal is stored");
        Manifest removed = TestState.Current(db)!;
        check(removed.Version == 4 && !removed.Secrets.ContainsKey("C_NAME") && Row(db, "C_NAME") == "" && store.ListNames().SequenceEqual(["A_NAME", "B_NAME", "D_NAME"]), "store: --remove signs a manifest without the hash and deletes the row");

        // No unlock, or an unlock of a credential without a slot, is a store error, not a crash.
        check(Fails(() => store.GetValues(["A_NAME"], null), out string noKey) && !noKey.Contains(ValueA, StringComparison.Ordinal), "store: no unlock is a store error (" + noKey + ")");
        using (Unlock stranger = new("c3RyYW5nZXI", new byte[32]))
        {
            check(Fails(() => store.GetValues(["A_NAME"], stranger), out string strangerWhy) && !strangerWhy.Contains(ValueA, StringComparison.Ordinal), "store: an unlock without a slot is a store error (" + strangerWhy + ")");
        }

        int decrypts = cipher.Decrypts;
        using (Unlock wrong = new(TestAuthenticator.Encode(TestAuthenticator.ById(TestState.Current(db)!.Admins[0].Id)!.CredentialId), RandomNumberGenerator.GetBytes(32)))
        {
            check(Fails(() => store.GetValues(["A_NAME"], wrong), out string wrongWhy) && !wrongWhy.Contains(ValueA, StringComparison.Ordinal) && cipher.Decrypts == decrypts, "store: a wrong PRF output opens nothing (" + wrongWhy + ")");
        }

        check(store.ListNames().Count == 3, "store: listing needs no private key");
    }

    private static void Tampers(Action<bool, string> check, string root)
    {
        (string Name, Action<StateDatabase, string> Edit, bool StateFails)[] edits =
        [
            ("a row replaced by another valid ciphertext made with the public key", (db, publicKey) => Sql(db, "UPDATE secrets SET ciphertext = $c WHERE name = 'A_NAME'", ("$c", DotenvxCipher.Instance.Encrypt("Attacker-Value-1", publicKey))), false),
            ("a row swapped with another row", (db, _) => Sql(db, "UPDATE secrets SET ciphertext = (SELECT ciphertext FROM secrets WHERE name = 'B_NAME') WHERE name = 'A_NAME'"), false),
            ("a row added without a hash", (db, publicKey) => Sql(db, "INSERT INTO secrets (name, ciphertext) VALUES ('EXTRA_NAME', $c)", ("$c", DotenvxCipher.Instance.Encrypt("Extra-Value-1", publicKey))), false),
            ("a row deleted (its hash stays)", (db, _) => Sql(db, "DELETE FROM secrets WHERE name = 'B_NAME'"), false),
            ("a hash removed from the manifest text", (db, _) => Sql(db, "UPDATE manifest SET text = replace(text, substr(text, instr(text, ',\"B_NAME\":'), 76), '')"), true),
            ("a hash changed in the manifest text", (db, _) => Sql(db, "UPDATE manifest SET text = replace(text, '\"A_NAME\":\"', '\"A_NAME\":\"0')"), true),
            ("the store key changed in the manifest text", (db, publicKey) => Sql(db, "UPDATE manifest SET text = replace(text, $p, $q)", ("$p", publicKey), ("$q", DotenvxCipher.Instance.NewKeyPair().PublicKey)), true),
        ];
        int index = 0;
        foreach ((string name, Action<StateDatabase, string> edit, bool stateFails) in edits)
        {
            (StateDatabase db, SecretStore store, CountingCipher cipher) = NewStore(root, "tamper-" + index++);
            Put(store, new Dictionary<string, string> { ["A_NAME"] = ValueA, ["B_NAME"] = ValueB });
            using Unlock? admin = AdminUnlock(db);
            edit(db, TestState.Current(db)!.Store);
            StateDatabase again = new(db.FilePath);
            // The admin passkey's unlock is at hand, so only the hash check can stop it.
            SecretStore reopened = new(again, cipher);
            bool listFails = Fails(() => reopened.ListNames(), out string listWhy);
            bool getFails = Fails(() => Read(reopened, ["A_NAME"], admin), out string getWhy);
            check(listFails && getFails && cipher.Decrypts == 0 && getWhy.Contains("failed verification", StringComparison.Ordinal), "store tamper: " + name + ": --list and a run fail verification with the unlock at hand; nothing decrypted (" + listWhy + " | " + getWhy + ")");
            check(again.TryCheck(out _) != stateFails, "store tamper: " + name + (stateFails ? ": the manifest fails verification for every command" : ": the manifest itself still verifies"));
            check(!listWhy.Contains(ValueA, StringComparison.Ordinal) && !getWhy.Contains(ValueB, StringComparison.Ordinal), "store tamper: " + name + ": the message has no value");
        }

        // Without a manifest, a secrets row is a tamper too.
        StateDatabase bare = new(Path.Combine(root, "bare", WithSecretsDatabase.FileName));
        bare.Write((connection, transaction) => WithSecretsDatabase.Execute(connection, transaction, "INSERT INTO secrets (name, ciphertext) VALUES ('A_NAME', 'encrypted:x')"));
        check(!new StateDatabase(bare.FilePath).TryCheck(out string? bareWhy) && Fails(() => new SecretStore(new StateDatabase(bare.FilePath)).ListNames(), out _), "store tamper: a secrets row without a manifest fails verification (" + bareWhy + ")");
    }

    /// <summary>A run reads only what it was approved for, and a tampered store stops it with exit 4.</summary>
    private static async Task Runs(Action<bool, string> check, string root)
    {
        string folder = Path.Combine(root, "runs");
        Directory.CreateDirectory(folder);
        string program = OperatingSystem.IsWindows() ? "show.cmd" : "show.sh";
        string path = Path.Combine(folder, program);
        if (OperatingSystem.IsWindows())
        {
            File.WriteAllText(path, "@echo off\r\necho a=%A_NAME% b=%B_NAME%\r\n");
        }
        else
        {
            File.WriteAllText(path, "#!/bin/sh\necho \"a=$A_NAME b=${B_NAME:-unset}\"\n");
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        (StateDatabase db, SecretStore store, CountingCipher cipher) = NewStore(root, "runs-db");
        Put(store, new Dictionary<string, string> { ["A_NAME"] = ValueA, ["B_NAME"] = ValueB, ["C_NAME"] = ValueC });
        RunArgs args = CliArgs.ParseRun(["--secrets", "A_NAME", "--reason", "store test", "--", "./" + program], out _)!;
        FakeApprover approver = new(true, unlock: () => AdminUnlock(db));
        StringWriter stdout = new();
        StringWriter stderr = new();
        int code = await new RunCommand(store, approver, stdout, stderr).ExecuteAsync(args, folder, TestAudit.Sink(db));
        check(code == 0 && stdout.ToString().Contains("a=[REDACTED]", StringComparison.Ordinal) && !stdout.ToString().Contains(ValueA, StringComparison.Ordinal), "store run: the requested secret reaches the program, redacted (" + code + " " + stderr + ")");
        check(cipher.Decrypts == 1, "store run: only the requested secret is decrypted; the other two never are (" + cipher.Decrypts + ")");
        check(approver.Requests.Single().Sources is { } sources && sources["A_NAME"] == "global" && ApprovalSummary.BuildMessage(approver.Requests[0]).Contains("Secrets: A_NAME (global)", StringComparison.Ordinal), "store run: the approval text names each secret's source");
        string audit = StateDatabaseTests.AuditText(db.FilePath);
        check(audit.Contains("\"outcome\":\"test-put\"", StringComparison.Ordinal) && audit.Contains("\"type\":\"execution\"", StringComparison.Ordinal), "store run: the signed audit has the store write and the run");
        string[] canaries = [ValueA, ValueB, ValueC, "encrypted:", Convert.ToHexString(TestVault.RecoveryCode(db))];
        check(canaries.All(canary => !audit.Contains(canary, StringComparison.Ordinal)), "audit canary: no secret value, ciphertext or recovery code appears in the admin or run events");
        check(TestAudit.MetadataClean(db, canaries, out HashSet<string> scanned) && AuditEventTypes.All.All(scanned.Contains), "audit canary: the metadata of every event type (" + string.Join(",", scanned) + ") holds no value, ciphertext or code");
        AuditEvent authorized = TestAudit.Events(db, all: true).First(item => item.Type == AuditEventTypes.Authorization && item.Outcome == "approved");
        check(authorized.Meta.TryGetValue("secrets", out string? named) && named == "A_NAME" && authorized.Meta.ContainsKey("files"), "run metadata: the approval event names the secrets and the file fingerprints (" + string.Join(",", authorized.Meta.Keys) + ")");

        // A swapped row: the run stops before it asks, with exit 4.
        Sql(db, "UPDATE secrets SET ciphertext = $c WHERE name = 'A_NAME'", ("$c", DotenvxCipher.Instance.Encrypt("Attacker-Value-1", TestState.Current(db)!.Store)));
        FakeApprover never = new(true, unlock: () => AdminUnlock(db));
        stderr = new StringWriter();
        code = await new RunCommand(new SecretStore(new StateDatabase(db.FilePath), cipher), never, new StringWriter(), stderr).ExecuteAsync(args, folder);
        check(code == RunCommand.StoreError && never.Requests.Count == 0 && cipher.Decrypts == 1 && stderr.ToString().Contains("failed verification", StringComparison.Ordinal), "store run: a swapped ciphertext is exit 4, nobody is asked, nothing is decrypted (" + stderr + ")");

        // A swap after the approval (between the check and the read): the read checks again.
        (StateDatabase late, SecretStore lateStore, CountingCipher lateCipher) = NewStore(root, "runs-late");
        Put(lateStore, new Dictionary<string, string> { ["A_NAME"] = ValueA });
        SwapApprover swap = new(late, TestState.Current(late)!.Store, false);
        code = await new RunCommand(lateStore, swap, new StringWriter(), new StringWriter()).ExecuteAsync(args, folder);
        check(code == RunCommand.StoreError && lateCipher.Decrypts == 0, "store run: a row swapped while the approval page was open is exit 4, nothing is decrypted");

        // A row added (without a hash) while the approval page was open: the read checks every row, so exit 4 too.
        (StateDatabase extra, SecretStore extraStore, CountingCipher extraCipher) = NewStore(root, "runs-extra");
        Put(extraStore, new Dictionary<string, string> { ["A_NAME"] = ValueA });
        code = await new RunCommand(extraStore, new SwapApprover(extra, TestState.Current(extra)!.Store, true), new StringWriter(), new StringWriter()).ExecuteAsync(args, folder);
        check(code == RunCommand.StoreError && extraCipher.Decrypts == 0, "store run: a row added while the approval page was open is exit 4, nothing is decrypted");
    }

    /// <summary>Approves, and while doing so swaps the A_NAME row for another valid ciphertext, or adds a row without a hash.</summary>
    private sealed class SwapApprover(StateDatabase db, string publicKey, bool addRow) : IApprover
    {
        public ApprovalDecision Request(ApprovalRequest request)
        {
            Unlock? unlock = AdminUnlock(db);
            string ciphertext = DotenvxCipher.Instance.Encrypt("Attacker-Value-1", publicKey);
            Sql(db, addRow ? "INSERT INTO secrets (name, ciphertext) VALUES ('EXTRA_NAME', $c)" : "UPDATE secrets SET ciphertext = $c WHERE name = 'A_NAME'", ("$c", ciphertext));

            return ApprovalDecision.Allow("approved", 0, null, unlock);
        }
    }

    private static void Zeroing(Action<bool, string> check)
    {
        SecretValues values = new(new Dictionary<string, byte[]> { ["A_NAME"] = Encoding.UTF8.GetBytes(ValueA), ["B_NAME"] = Encoding.UTF8.GetBytes(ValueB) });
        byte[] a = values.Bytes("A_NAME");
        byte[] b = values.Bytes("B_NAME");
        check(a.Length == ValueA.Length && a.Any(item => item != 0), "zeroing: the bytes are there before Dispose");
        values.Dispose();
        check(a.All(item => item == 0) && b.All(item => item == 0), "zeroing: Dispose zeroes every value's bytes");
        bool thrown = false;
        try
        {
            values.Bytes("A_NAME");
        }
        catch (ObjectDisposedException)
        {
            thrown = true;
        }

        check(thrown, "zeroing: a disposed set gives no value");
        values.Dispose();
        check(true, "zeroing: Dispose twice is fine");

        byte[] buffer = [1, 2, 3];
        SecretValues.Clear(buffer);
        SecretValues.Clear(null);
        check(buffer.All(item => item == 0), "zeroing: the helper zeroes a buffer and ignores null");
    }

    private static void Transactions(Action<bool, string> check, string root)
    {
        (StateDatabase db, SecretStore store, _) = NewStore(root, "tx");
        Put(store, new Dictionary<string, string> { ["A_NAME"] = ValueA });
        Manifest current = TestState.Current(db)!;
        string publicKey = current.Store;

        // A manifest for an older version: nothing is written.
        Dictionary<string, string> rows = new() { ["B_NAME"] = store.Encrypt(ValueB, publicKey) };
        Manifest next = SecretStore.Next(current, publicKey, rows, []);
        ManifestKey admin = current.Admins[0];
        SignedManifest signed = TestState.Sign(TestAuthenticator.ById(admin.Id)!, next.Canonical());
        string? stale = store.TryApply(current.Version - 1, signed, rows, [], AdminEvent.Change("secrets-set", "test", admin.Name));
        check(stale is not null && Row(db, "B_NAME") == "" && TestState.Current(db)!.Version == current.Version, "store write: a stale version writes nothing (" + stale + ")");

        // Rows that are not the ones the manifest names: refused, nothing written.
        Dictionary<string, string> other = new() { ["B_NAME"] = store.Encrypt("Other-Value-12", publicKey) };
        string? mismatch = store.TryApply(current.Version, signed, other, [], AdminEvent.Change("secrets-set", "test", admin.Name));
        check(mismatch is not null && Row(db, "B_NAME") == "" && TestState.Current(db)!.Version == current.Version, "store write: rows that do not match the signed hashes write nothing (" + mismatch + ")");

        // A failure inside the transaction (after the manifest and the rows): everything is rolled back.
        int before = TestAudit.TryRead(db, 100, null, out IReadOnlyList<AuditRow> rowsBefore, out _) ? rowsBefore.Count : -1;
        store.BeforeCommit = () => throw new IOException("the test write failed");
        string? failed = store.TryApply(current.Version, signed, rows, [], AdminEvent.Change("secrets-set", "test", admin.Name));
        store.BeforeCommit = null;
        int after = TestAudit.TryRead(db, 100, null, out IReadOnlyList<AuditRow> rowsAfter, out _) ? rowsAfter.Count : -1;
        check(failed is not null && Row(db, "B_NAME") == "" && TestState.Current(db)!.Version == current.Version && after == before, "store write: a failure in the transaction leaves rows, manifest and audit as they were (" + failed + ")");

        // The good write, with its audit row in the same transaction.
        check(store.TryApply(current.Version, signed, rows, [], AdminEvent.Change("secrets-set", "test", admin.Name)) is null && Row(db, "B_NAME") == rows["B_NAME"], "store write: the same write succeeds when nothing fails");
        check(TestAudit.TryRead(db, 100, null, out IReadOnlyList<AuditRow> rowsDone, out _) && rowsDone.Count == before + 1, "store write: the audit row is written with it");

        check(WithSecretsDatabase.SchemaVersion == 3, "store: the schema version is 3");
    }
}

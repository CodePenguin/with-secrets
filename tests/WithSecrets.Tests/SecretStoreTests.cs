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

/// <summary>Always makes the same key pair, so a test can put that key in custody before a first --set.</summary>
internal sealed class FixedPairCipher((string PublicKey, string PrivateKey) pair) : ISecretCipher
{
    public (string PublicKey, string PrivateKey) NewKeyPair() => pair;

    public string Encrypt(string value, string publicKey) => DotenvxCipher.Instance.Encrypt(value, publicKey);

    public string Decrypt(string privateKey, string ciphertext) => DotenvxCipher.Instance.Decrypt(privateKey, ciphertext);
}

/// <summary>The store's private keys in memory, as Credential Manager keeps them in the tool.</summary>
internal sealed class MemoryKeys : IStoreKeys
{
    public Dictionary<string, string> Keys { get; } = new(StringComparer.Ordinal);

    public int Reads { get; private set; }

    public List<string> Deleted { get; } = [];

    /// <summary>What <see cref="IStoreKeys.Unavailable" /> says; null means the custody works.</summary>
    public string? Problem { get; init; }

    public string? Unavailable => Problem;

    public void Save(string publicKey, string privateKey) => Keys[publicKey] = privateKey;

    public bool Exists(string publicKey) => Keys.ContainsKey(publicKey);

    public void Delete(string publicKey)
    {
        Deleted.Add(publicKey);
        Keys.Remove(publicKey);
    }

    public string PrivateKey(string publicKey)
    {
        Reads++;

        return Keys.TryGetValue(publicKey, out string? key) ? key : throw new KeyNotFoundException("no private key for the secret store");
    }
}

/// <summary>
/// The secret store in state.db: one row per secret (the Dotenvx ciphertext), and the signed manifest has the store's public
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
        string publicKey = KeyFor(store, current);
        Dictionary<string, string> rows = values.ToDictionary(item => item.Key, item => store.Encrypt(item.Value, publicKey), StringComparer.Ordinal);
        Manifest next = SecretStore.Next(current, publicKey, rows, removes ?? []);
        ManifestKey admin = current.Admins.First(key => TestAuthenticator.ById(key.Id) is not null);
        SignedManifest signed = TestState.Sign(TestAuthenticator.ById(admin.Id)!, next.Canonical(), admin.RpId);

        return store.TryApply(current.Version, signed, rows, removes ?? [], AuditLog.ChangeRow("test-put", "test", admin.Name));
    }

    /// <summary>The store public key of <paramref name="manifest" />; before the first secret, a new key pair saved to custody now.</summary>
    public static string KeyFor(SecretStore store, Manifest manifest)
    {
        if (manifest.Store.Length > 0)
        {
            return manifest.Store;
        }

        (string publicKey, string privateKey) = store.NewKeyPair();
        store.SaveKey(publicKey, privateKey);

        return publicKey;
    }

    /// <summary>A seeded state.db with a store over it.</summary>
    private static (StateDatabase Db, SecretStore Store, MemoryKeys Keys, CountingCipher Cipher) NewStore(string root, string name)
    {
        StateDatabase db = TestState.Seeded(Path.Combine(root, name, StateDatabase.FileName));
        MemoryKeys keys = new();
        CountingCipher cipher = new();

        return (db, new SecretStore(db, keys, cipher), keys, cipher);
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
        check(first.Store == "" && first.Secrets.Count == 0, "store manifest: a new manifest has no store key and no secrets");
        check(first.Canonical().Contains(",\"store\":\"\",\"secrets\":{},\"settings\":", StringComparison.Ordinal), "store manifest: the text has store and secrets before the settings (" + first.Canonical() + ")");
        check(first.SettingsPrefix().EndsWith(",\"store\":\"\",\"secrets\":{},\"settings\":", StringComparison.Ordinal), "store manifest: the settings prefix ends with store and secrets");

        (string publicKey, _) = DotenvxCipher.Instance.NewKeyPair();
        string hashB = new('b', 64);
        string hashA = new('a', 64);
        Manifest withSecrets = first.WithSecrets(publicKey, new Dictionary<string, string> { ["B_NAME"] = hashB, ["A_NAME"] = hashA });
        string text = withSecrets.Canonical();
        check(withSecrets.Version == 2 && text.Contains(",\"store\":\"" + publicKey + "\",\"secrets\":{\"A_NAME\":\"" + hashA + "\",\"B_NAME\":\"" + hashB + "\"},\"settings\":", StringComparison.Ordinal), "store manifest: the secrets are sorted by name, with the store key (" + text + ")");
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
        (StateDatabase db, SecretStore store, MemoryKeys keys, CountingCipher cipher) = NewStore(root, "round");
        check(store.Label == "global" && store.ListNames().Count == 0, "store: an empty store lists nothing");
        check(Put(store, new Dictionary<string, string> { ["A_NAME"] = ValueA, ["B_NAME"] = ValueB, ["C_NAME"] = ValueC }) is null, "store: three secrets are stored");
        Manifest manifest = TestState.Current(db)!;
        check(keys.Keys.Count == 1 && manifest.Store == keys.Keys.Keys.Single() && DotenvxCipher.Instance.Derive(keys.Keys.Values.Single()) == manifest.Store, "store: the first write made one key pair; the manifest has its public key, custody the private key");
        check(manifest.Version == 2 && manifest.Secrets.Keys.SequenceEqual(["A_NAME", "B_NAME", "C_NAME"]) && manifest.Secrets.All(item => item.Value == SecretStore.Hash(Row(db, item.Key))), "store: the manifest has the hash of every row");
        check(Row(db, "A_NAME").StartsWith("encrypted:", StringComparison.Ordinal) && !File.ReadAllText(db.FilePath).Contains(ValueA, StringComparison.Ordinal), "store: a row is a Dotenvx ciphertext; no value is in state.db");
        check(store.ListNames().SequenceEqual(["A_NAME", "B_NAME", "C_NAME"]) && cipher.Decrypts == 0 && keys.Reads == 0, "store: --list reads names and decrypts nothing (no private key read)");

        using (SecretValues values = store.GetValues(["B_NAME"]))
        {
            check(values.Names.SequenceEqual(["B_NAME"]) && Encoding.UTF8.GetString(values.Bytes("B_NAME")) == ValueB && values.Text("B_NAME") == ValueB, "store: GetValues returns the requested value");
            check(cipher.Decrypts == 1 && keys.Reads == 1, "store: only the requested row is decrypted (" + cipher.Decrypts + " decrypts)");
        }

        using (SecretValues two = store.GetValues(["C_NAME", "A_NAME"]))
        {
            check(two.Names.Count == 2 && two.Text("A_NAME") == ValueA && two.Text("C_NAME") == ValueC && cipher.Decrypts == 3, "store: two requested rows, two decrypts");
        }

        check(Fails(() => store.GetValues(["NOPE_NAME"]), out string missing) && missing.Contains("NOPE_NAME", StringComparison.Ordinal) && cipher.Decrypts == 3, "store: a name that is not stored is an error and decrypts nothing (" + missing + ")");

        // Set again: one name replaced, one new; the key pair stays.
        string oldRow = Row(db, "B_NAME");
        check(Put(store, new Dictionary<string, string> { ["B_NAME"] = "Bravo-New-Value-9", ["D_NAME"] = "Delta-Store-Value-4" }) is null, "store: a replaced and a new name are stored");
        Manifest after = TestState.Current(db)!;
        using (SecretValues read = store.GetValues(["B_NAME", "D_NAME"]))
        {
            check(after.Version == 3 && keys.Keys.Count == 1 && after.Store == manifest.Store && Row(db, "B_NAME") != oldRow && read.Text("B_NAME") == "Bravo-New-Value-9" && read.Text("D_NAME") == "Delta-Store-Value-4", "store: a replaced value reads back, the new one too, with the same key pair");
        }

        check(after.Secrets.Keys.SequenceEqual(["A_NAME", "B_NAME", "C_NAME", "D_NAME"]) && after.Secrets["A_NAME"] == manifest.Secrets["A_NAME"], "store: untouched hashes stay");

        // Remove re-signs: the hash and the row go together.
        check(Put(store, new Dictionary<string, string>(), ["C_NAME"]) is null, "store: a removal is stored");
        Manifest removed = TestState.Current(db)!;
        check(removed.Version == 4 && !removed.Secrets.ContainsKey("C_NAME") && Row(db, "C_NAME") == "" && store.ListNames().SequenceEqual(["A_NAME", "B_NAME", "D_NAME"]), "store: --remove signs a manifest without the hash and deletes the row");

        // A missing private key is a store error, not a crash.
        keys.Keys.Clear();
        check(Fails(() => store.GetValues(["A_NAME"]), out string noKey) && !noKey.Contains(ValueA, StringComparison.Ordinal), "store: no private key is a store error (" + noKey + ")");
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
            (StateDatabase db, SecretStore store, MemoryKeys keys, CountingCipher cipher) = NewStore(root, "tamper-" + index++);
            Put(store, new Dictionary<string, string> { ["A_NAME"] = ValueA, ["B_NAME"] = ValueB });
            edit(db, TestState.Current(db)!.Store);
            StateDatabase again = new(db.FilePath);
            // The original key custody: GetValues has the private key, so only the hash check can stop it.
            SecretStore reopened = new(again, keys, cipher);
            int reads = keys.Reads;
            bool listFails = Fails(() => reopened.ListNames(), out string listWhy);
            bool getFails = Fails(() => reopened.GetValues(["A_NAME"]), out string getWhy);
            check(listFails && getFails && cipher.Decrypts == 0 && keys.Reads == reads && getWhy.Contains("failed verification", StringComparison.Ordinal), "store tamper: " + name + ": --list and a run fail verification with the private key at hand; no key read, nothing decrypted (" + listWhy + " | " + getWhy + ")");
            check(again.TryCheck(out _) != stateFails, "store tamper: " + name + (stateFails ? ": the manifest fails verification for every command" : ": the manifest itself still verifies"));
            check(!listWhy.Contains(ValueA, StringComparison.Ordinal) && !getWhy.Contains(ValueB, StringComparison.Ordinal), "store tamper: " + name + ": the message has no value");
        }

        // Without a manifest, a secrets row is a tamper too.
        StateDatabase bare = new(Path.Combine(root, "bare", StateDatabase.FileName));
        bare.Write((connection, transaction) => StateDatabase.Execute(connection, transaction, "INSERT INTO secrets (name, ciphertext) VALUES ('A_NAME', 'encrypted:x')"));
        check(!new StateDatabase(bare.FilePath).TryCheck(out string? bareWhy) && Fails(() => new SecretStore(new StateDatabase(bare.FilePath), new MemoryKeys()).ListNames(), out _), "store tamper: a secrets row without a manifest fails verification (" + bareWhy + ")");
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

        (StateDatabase db, SecretStore store, _, CountingCipher cipher) = NewStore(root, "runs-db");
        Put(store, new Dictionary<string, string> { ["A_NAME"] = ValueA, ["B_NAME"] = ValueB, ["C_NAME"] = ValueC });
        RunArgs args = CliArgs.ParseRun(["--secrets", "A_NAME", "--reason", "store test", "--", "./" + program], out _)!;
        FakeApprover approver = new(true);
        StringWriter stdout = new();
        StringWriter stderr = new();
        int code = await new RunCommand(store, approver, new AuditLog(db), stdout, stderr).ExecuteAsync(args, folder);
        check(code == 0 && stdout.ToString().Contains("a=[REDACTED]", StringComparison.Ordinal) && !stdout.ToString().Contains(ValueA, StringComparison.Ordinal), "store run: the requested secret reaches the program, redacted (" + code + " " + stderr + ")");
        check(cipher.Decrypts == 1, "store run: only the requested secret is decrypted; the other two never are (" + cipher.Decrypts + ")");
        check(approver.Requests.Single().Sources is { } sources && sources["A_NAME"] == "global" && ApprovalSummary.BuildMessage(approver.Requests[0]).Contains("Secrets: A_NAME (global)", StringComparison.Ordinal), "store run: the approval text names each secret's source");
        string audit = StateDatabaseTests.AuditText(db.FilePath);
        check(audit.Contains("A_NAME", StringComparison.Ordinal) && !audit.Contains(ValueA, StringComparison.Ordinal) && !audit.Contains(ValueB, StringComparison.Ordinal) && !audit.Contains("encrypted:", StringComparison.Ordinal), "store run: the audit has names only (no value, no ciphertext)");

        // A swapped row: the run stops before it asks, with exit 4.
        Sql(db, "UPDATE secrets SET ciphertext = $c WHERE name = 'A_NAME'", ("$c", DotenvxCipher.Instance.Encrypt("Attacker-Value-1", TestState.Current(db)!.Store)));
        FakeApprover never = new(true);
        stderr = new StringWriter();
        code = await new RunCommand(new SecretStore(new StateDatabase(db.FilePath), new MemoryKeys(), cipher), never, new AuditLog(db), new StringWriter(), stderr).ExecuteAsync(args, folder);
        check(code == RunCommand.StoreError && never.Requests.Count == 0 && cipher.Decrypts == 1 && stderr.ToString().Contains("failed verification", StringComparison.Ordinal), "store run: a swapped ciphertext is exit 4, nobody is asked, nothing is decrypted (" + stderr + ")");

        // A swap after the approval (between the check and the read): the read checks again.
        (StateDatabase late, SecretStore lateStore, MemoryKeys lateKeys, CountingCipher lateCipher) = NewStore(root, "runs-late");
        Put(lateStore, new Dictionary<string, string> { ["A_NAME"] = ValueA });
        SwapApprover swap = new(late, TestState.Current(late)!.Store, false);
        code = await new RunCommand(lateStore, swap, new AuditLog(late), new StringWriter(), new StringWriter()).ExecuteAsync(args, folder);
        check(code == RunCommand.StoreError && lateCipher.Decrypts == 0 && lateKeys.Reads == 0, "store run: a row swapped while the approval page was open is exit 4, nothing is decrypted");

        // A row added (without a hash) while the approval page was open: the read checks every row, so exit 4 too.
        (StateDatabase extra, SecretStore extraStore, MemoryKeys extraKeys, CountingCipher extraCipher) = NewStore(root, "runs-extra");
        Put(extraStore, new Dictionary<string, string> { ["A_NAME"] = ValueA });
        code = await new RunCommand(extraStore, new SwapApprover(extra, TestState.Current(extra)!.Store, true), new AuditLog(extra), new StringWriter(), new StringWriter()).ExecuteAsync(args, folder);
        check(code == RunCommand.StoreError && extraCipher.Decrypts == 0 && extraKeys.Reads == 0, "store run: a row added while the approval page was open is exit 4, nothing is decrypted");
    }

    /// <summary>Approves, and while doing so swaps the A_NAME row for another valid ciphertext, or adds a row without a hash.</summary>
    private sealed class SwapApprover(StateDatabase db, string publicKey, bool addRow) : IApprover
    {
        public ApprovalDecision Request(ApprovalRequest request)
        {
            string ciphertext = DotenvxCipher.Instance.Encrypt("Attacker-Value-1", publicKey);
            Sql(db, addRow ? "INSERT INTO secrets (name, ciphertext) VALUES ('EXTRA_NAME', $c)" : "UPDATE secrets SET ciphertext = $c WHERE name = 'A_NAME'", ("$c", ciphertext));

            return ApprovalDecision.Allow();
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
        (StateDatabase db, SecretStore store, _, _) = NewStore(root, "tx");
        Put(store, new Dictionary<string, string> { ["A_NAME"] = ValueA });
        Manifest current = TestState.Current(db)!;
        string publicKey = current.Store;

        // A manifest for an older version: nothing is written.
        Dictionary<string, string> rows = new() { ["B_NAME"] = store.Encrypt(ValueB, publicKey) };
        Manifest next = SecretStore.Next(current, publicKey, rows, []);
        ManifestKey admin = current.Admins[0];
        SignedManifest signed = TestState.Sign(TestAuthenticator.ById(admin.Id)!, next.Canonical());
        string? stale = store.TryApply(current.Version - 1, signed, rows, [], AuditLog.ChangeRow("secrets-set", "test", admin.Name));
        check(stale is not null && Row(db, "B_NAME") == "" && TestState.Current(db)!.Version == current.Version, "store write: a stale version writes nothing (" + stale + ")");

        // Rows that are not the ones the manifest names: refused, nothing written.
        Dictionary<string, string> other = new() { ["B_NAME"] = store.Encrypt("Other-Value-12", publicKey) };
        string? mismatch = store.TryApply(current.Version, signed, other, [], AuditLog.ChangeRow("secrets-set", "test", admin.Name));
        check(mismatch is not null && Row(db, "B_NAME") == "" && TestState.Current(db)!.Version == current.Version, "store write: rows that do not match the signed hashes write nothing (" + mismatch + ")");

        // A failure inside the transaction (after the manifest and the rows): everything is rolled back.
        int before = new AuditLog(db).TryRead(100, null, out IReadOnlyList<AuditRecord> rowsBefore, out _) ? rowsBefore.Count : -1;
        store.BeforeCommit = () => throw new IOException("the test write failed");
        string? failed = store.TryApply(current.Version, signed, rows, [], AuditLog.ChangeRow("secrets-set", "test", admin.Name));
        store.BeforeCommit = null;
        int after = new AuditLog(db).TryRead(100, null, out IReadOnlyList<AuditRecord> rowsAfter, out _) ? rowsAfter.Count : -1;
        check(failed is not null && Row(db, "B_NAME") == "" && TestState.Current(db)!.Version == current.Version && after == before, "store write: a failure in the transaction leaves rows, manifest and audit as they were (" + failed + ")");

        // The good write, with its audit row in the same transaction.
        check(store.TryApply(current.Version, signed, rows, [], AuditLog.ChangeRow("secrets-set", "test", admin.Name)) is null && Row(db, "B_NAME") == rows["B_NAME"], "store write: the same write succeeds when nothing fails");
        check(new AuditLog(db).TryRead(100, null, out IReadOnlyList<AuditRecord> rowsDone, out _) && rowsDone.Count == before + 1, "store write: the audit row is written with it");

        check(StateDatabase.SchemaVersion == 7, "store: the schema version is 7");
    }
}

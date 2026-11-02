using System.Diagnostics;
using System.Text.Json;

using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>The SQLite state store: passkeys, saved approvals and the audit log in state.db, and --audit.</summary>
internal static class StateDatabaseTests
{
    /// <summary>The JSON entries the audit log holds, in order. Empty when there is no database.</summary>
    public static string[] AuditLines(string path) => [.. new AuditLog(new StateDatabase(path)).Lines()];

    public static string AuditText(string path) => string.Join("\n", AuditLines(path));

    public static async Task Run(Action<bool, string> check)
    {
        string folder = Path.Combine(Path.GetTempPath(), "ws-db-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            RoundTrips(check, folder);
            Concurrency(check, folder);
            Unusable(check, folder);
            Locked(check, folder);
            StaleWal(check, folder);
            WrongTypes(check, folder);
            Chain(check, folder);
            await AuditOutput(check, folder);
            AuditCli(check);
        }
        finally
        {
            Directory.Delete(folder, true);
        }
    }

    private static readonly DateTimeOffset Created = new(2026, 11, 1, 10, 0, 0, TimeSpan.FromHours(2));

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, TestAuthenticator> Authenticators = new(StringComparer.Ordinal);

    /// <summary>A real key for the label (the same one every time), so the admin can sign manifests. The name defaults to the label.</summary>
    private static PasskeyRecord Key(string label, string? name = null, string rp = "localhost")
    {
        return Authenticators.GetOrAdd(label, _ => TestAuthenticator.ES256()).Record(rp, name ?? label) with { Created = Created };
    }

    private static string Id(string label) => Key(label).Id;

    /// <summary>Adds a key, again and again while another writer's newer manifest makes this one stale, as a person would retry.</summary>
    private static bool AddRetrying(string folder, PasskeyRecord record)
    {
        for (int attempt = 0; attempt < 200; attempt++)
        {
            if (TestState.Add(StateDatabase.InFolder(folder), record))
            {
                return true;
            }
        }

        return false;
    }

    private static void RoundTrips(Action<bool, string> check, string root)
    {
        string folder = Path.Combine(root, "round");
        StateDatabase db = StateDatabase.InFolder(folder);
        check(db.FilePath == Path.Combine(folder, "state.db"), "db: the file is state.db in the store folder");
        check(db.TryCheck(out string? error) && error is null && !File.Exists(db.FilePath), "db: a missing database is fine and is not created by a check");

        PasskeyStore passkeys = new(db);
        check(passkeys.TryAll(out IReadOnlyList<PasskeyRecord> none) && none.Count == 0 && !File.Exists(db.FilePath), "db passkeys: missing database reads as empty and creates nothing");
        check(passkeys.Add(Key("id-1", "laptop")) && passkeys.Add(Key("id-2", "phone", "ws.example.com")), "db passkeys: add two");
        check(passkeys.UpdateSignCount(Id("id-1"), 4000000000u), "db passkeys: a large sign count is saved");
        IReadOnlyList<PasskeyRecord> loaded = new PasskeyStore(StateDatabase.InFolder(folder)).All();
        check(loaded.Count == 2 && loaded[0] == Key("id-1", "laptop") with { Admin = true, SignCount = 4000000000u } && loaded[1] == Key("id-2", "phone", "ws.example.com") && loaded[0].Created.Offset == TimeSpan.FromHours(2), "db passkeys: records round-trip in order (the admin first), with the offset and a large sign count");
        check(!passkeys.Add(Key("id-1", "again")), "db passkeys: a duplicate Id is refused");
        check(!passkeys.UpdateSignCount(Id("id-1"), 9) && passkeys.All()[0].SignCount == 4000000000u, "db passkeys: a lower sign count does not overwrite a higher one");
        check(!passkeys.UpdateSignCount(Id("id-1"), 4000000000u) && passkeys.All()[0].SignCount == 4000000000u, "db passkeys: an equal sign count changes nothing");
        check(passkeys.UpdateSignCount(Id("id-1"), 4000000001u) && passkeys.All()[0].SignCount == 4000000001u && !passkeys.UpdateSignCount("nope", 1), "db passkeys: a higher sign count is saved");
        check(!passkeys.RemoveById(Id("id-1")) && passkeys.RemoveById(Id("id-2")) && !passkeys.RemoveById(Id("id-2")) && passkeys.ForRp("localhost").Count == 1 && passkeys.ForRp("ws.example.com").Count == 0, "db passkeys: remove by Id; the admin key stays");
        check(passkeys.UnreadableMessage == "cannot read state.db; fix or delete it", "db passkeys: the message names state.db");

        DateTimeOffset clock = new(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);
        GrantStore grants = new(db, () => clock);
        check(!grants.TryGet("K1", out _, out _), "db grants: nothing at first");
        check(grants.Add("K1", 10) && new GrantStore(StateDatabase.InFolder(folder), () => clock).TryGet("K1", out DateTimeOffset approved, out DateTimeOffset expires)
            && approved == clock && expires == clock.AddMinutes(10), "db grants: round trip with the exact times");
        clock = clock.AddMinutes(11);
        check(!grants.TryGet("K1", out _, out _), "db grants: expired");
        check(grants.Add("K2", 5) && grants.TryClear() && !grants.TryGet("K2", out _, out _), "db grants: clear");

        AuditLog audit = new(db);
        ApprovalRequest request = new("tool", "/bin/tool", ["--x"], "/work", "why", ["DB_URL", "API_KEY"]);
        check(audit.TryWrite("approved", request, "passkey laptop verified") && audit.TryWrite("finished", request, "", 7) && audit.TryWriteChange("secrets-set", ["OTHER_NAME"], "passkey phone verified"), "db audit: three writes");
        string[] lines = [.. audit.Lines()];
        check(lines.Length == 3 && JsonDocument.Parse(lines[0]).RootElement.GetProperty("event").GetString() == "approved" && lines[1].Contains("\"exitCode\":7", StringComparison.Ordinal) && lines[2].Contains("\"names\":[\"OTHER_NAME\"]", StringComparison.Ordinal), "db audit: the entries keep the old line format");
        check(audit.TryRead(20, null, out IReadOnlyList<AuditRecord> all, out _) && all.Count == 3 && all[0].Event == "approved" && all[0].KeyName == "laptop" && all[0].Secrets.SequenceEqual(["DB_URL", "API_KEY"]) && all[0].Program == "/bin/tool"
            && all[1].Detail == "exit 7" && all[2].Secrets.SequenceEqual(["OTHER_NAME"]) && all[2].KeyName == "phone", "db audit: rows carry time, event, names, program, outcome and the key name");
        check(audit.TryRead(1, null, out IReadOnlyList<AuditRecord> last, out _) && last.Count == 1 && last[0].Event == "secrets-set", "db audit: --last keeps the newest");
        check(audit.TryRead(20, "API_KEY", out IReadOnlyList<AuditRecord> filtered, out _) && filtered.Count == 2 && filtered.All(row => row.Secrets.Contains("API_KEY")), "db audit: --secret filters by name");
        check(audit.Verify() is { Ok: true, Count: 3, BrokenAt: null }, "db audit: the chain verifies");
    }

    private static void Concurrency(Action<bool, string> check, string root)
    {
        string folder = Path.Combine(root, "parallel");
        const int Each = 30;
        Exception? failure = null;
        int refused = 0;
        void Writer(string prefix)
        {
            try
            {
                for (int index = 0; index < Each; index++)
                {
                    // A new StateDatabase each time, as a separate process would have.
                    StateDatabase db = StateDatabase.InFolder(folder);
                    ApprovalRequest request = new("tool", "/bin/tool", [], "/w", "r", ["A_NAME"]);
                    if (!AddRetrying(folder, Key(prefix + index)) || !new GrantStore(db).Add(prefix + index, 5) || !new AuditLog(db).TryWrite("approved", request, prefix + index))
                    {
                        Interlocked.Increment(ref refused);
                    }
                }
            }
            catch (Exception error)
            {
                failure = error;
            }
        }

        Thread one = new(() => Writer("a"));
        Thread two = new(() => Writer("b"));
        one.Start();
        two.Start();
        one.Join();
        two.Join();
        StateDatabase check1 = StateDatabase.InFolder(folder);
        GrantStore grants = new(check1);
        check(failure is null && refused == 0, "db parallel: no write was refused (" + failure?.Message + ", " + refused + ")");
        check(new PasskeyStore(check1).All().Count == 2 * Each && TestState.Current(check1)!.Version == 2 * Each, "db parallel: no passkey was lost; one manifest version per key");
        check(Enumerable.Range(0, Each).All(index => grants.TryGet("a" + index, out _, out _) && grants.TryGet("b" + index, out _, out _)), "db parallel: no grant was lost");
        check(new AuditLog(check1).Verify() is { Ok: true, Count: 2 * Each }, "db parallel: every audit row is there and the chain holds");
    }

    private static void Unusable(Action<bool, string> check, string root)
    {
        string folder = Path.Combine(root, "garbage");
        Directory.CreateDirectory(folder);
        StateDatabase db = StateDatabase.InFolder(folder);
        foreach (string content in new[] { "", "garbage bytes, not a database at all" })
        {
            File.WriteAllText(db.FilePath, content);
            ApprovalRequest request = new("tool", "/bin/tool", [], "/w", "r", ["A_NAME"]);
            check(!db.TryCheck(out string? error) && error is not null, $"db unusable '{content}': the check fails with a message");
            check(!new PasskeyStore(db).TryAll(out IReadOnlyList<PasskeyRecord> keys) && keys.Count == 0 && new PasskeyStore(db).All().Count == 0, $"db unusable '{content}': passkeys are an error, not an empty store");
            check(!new PasskeyStore(db).Add(Key("x")) && !new GrantStore(db).Add("K", 1) && !new GrantStore(db).TryGet("K", out _, out _), $"db unusable '{content}': no passkey or grant is written or read");
            check(!new AuditLog(db).TryWrite("approved", request, "x") && !new AuditLog(db).TryRead(20, null, out _, out _) && !new AuditLog(db).Verify().Ok, $"db unusable '{content}': the audit log cannot be written or read");
            StringWriter output = new();
            check(AuditCommand.Run(db, new CliCommand.Audit(20, null, false), output, new StringWriter()) == RunCommand.StoreError, $"db unusable '{content}': --audit exits 4");
            check(File.ReadAllText(db.FilePath) == content, $"db unusable '{content}': the file is left alone");
        }

        // A real database with a damaged page: the integrity check fails.
        File.Delete(db.FilePath);
        new PasskeyStore(db).Add(Key("damage-admin"));
        GrantStore store = new(db);
        for (int index = 0; index < 200; index++)
        {
            store.Add("damage-" + index + new string('n', 200), 5);
        }

        byte[] bytes = File.ReadAllBytes(db.FilePath);
        check(bytes.Length > 4096 * 4, "db damaged: the database spans several pages");
        // Damage a data page near the end (grant rows), not the schema: only the integrity check reads it at open.
        int page = bytes.Length / 4096 - 2;
        for (int index = page * 4096 + 8; index < (page + 1) * 4096; index++)
        {
            bytes[index] = 0x5A;
        }

        File.WriteAllBytes(db.FilePath, bytes);
        StateDatabase reopened = StateDatabase.InFolder(folder);
        check(!reopened.TryCheck(out string? damage) && damage is not null, "db damaged: the integrity check refuses it (" + damage + ")");
        check(!new PasskeyStore(StateDatabase.InFolder(folder)).TryAll(out _), "db damaged: passkeys are an error");
    }

    private static void Locked(Action<bool, string> check, string root)
    {
        string folder = Path.Combine(root, "locked");
        StateDatabase db = new(Path.Combine(folder, "state.db"), TimeSpan.FromSeconds(1));
        check(new PasskeyStore(db).Add(Key("first")), "db locked: a first record");
        using (SqliteConnection holder = new(new SqliteConnectionStringBuilder { DataSource = db.FilePath, Pooling = false }.ToString()))
        {
            holder.Open();
            using SqliteCommand begin = holder.CreateCommand();
            begin.CommandText = "BEGIN IMMEDIATE";
            begin.ExecuteNonQuery();

            Stopwatch watch = Stopwatch.StartNew();
            bool added = new PasskeyStore(new StateDatabase(db.FilePath, TimeSpan.FromSeconds(1))).Add(Key("second"));
            watch.Stop();
            check(!added && watch.Elapsed >= TimeSpan.FromMilliseconds(800) && watch.Elapsed < TimeSpan.FromSeconds(15), "db locked: a write waits for the timeout, then fails (" + watch.Elapsed + ")");
            ApprovalRequest request = new("tool", "/bin/tool", [], "/w", "r", ["A_NAME"]);
            check(!new AuditLog(new StateDatabase(db.FilePath, TimeSpan.FromSeconds(1))).TryWrite("approved", request, "x"), "db locked: an audit write fails, so the run stops");

            using SqliteCommand rollback = holder.CreateCommand();
            rollback.CommandText = "ROLLBACK";
            rollback.ExecuteNonQuery();
        }

        check(new PasskeyStore(db).Add(Key("second")) && new PasskeyStore(db).All().Count == 2, "db locked: after the lock ends, writes work");
    }

    /// <summary>A -wal or -shm left behind by an earlier state.db must not be applied to a new one.</summary>
    private static void StaleWal(Action<bool, string> check, string root)
    {
        string old = Path.Combine(root, "stale-old");
        StateDatabase oldDb = StateDatabase.InFolder(old);
        check(new PasskeyStore(oldDb).Add(Key("old-key")), "db stale wal: an old database");
        string connection = new SqliteConnectionStringBuilder { DataSource = oldDb.FilePath, Pooling = false }.ToString();
        string fresh = Path.Combine(root, "stale-new");
        Directory.CreateDirectory(fresh);
        using (SqliteConnection holder = new(connection))
        {
            holder.Open();
            using SqliteCommand command = holder.CreateCommand();
            command.CommandText = "PRAGMA wal_autocheckpoint = 0; INSERT INTO grants (key, approved, expires, minutes, key_name) VALUES ('planted', 0, 0, 0, 'planted');";
            command.ExecuteNonQuery();

            // Copy the WAL while it still holds the change, as a crash would leave it.
            foreach (string suffix in new[] { "-wal", "-shm" })
            {
                using FileStream source = new(oldDb.FilePath + suffix, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using FileStream target = File.Create(Path.Combine(fresh, "state.db" + suffix));
                source.CopyTo(target);
            }
        }

        StateDatabase newDb = StateDatabase.InFolder(fresh);
        bool added = new PasskeyStore(newDb).Add(Key("new-key"));
        check(added && newDb.TryCheck(out _) && new PasskeyStore(newDb).All().Select(item => item.Id).SequenceEqual([Id("new-key")]) && new GrantStore(newDb).Entries().Count == 0, "db stale wal: a new state.db ignores a leftover -wal and -shm ("
            + string.Join(",", new GrantStore(newDb).Entries().Select(item => item.Key)) + ")");
    }

    /// <summary>A hand-edited table with wrong column types or NULLs: reads fail closed or report, they never crash.</summary>
    private static void WrongTypes(Action<bool, string> check, string root)
    {
        string folder = Path.Combine(root, "wrong-types");
        StateDatabase db = StateDatabase.InFolder(folder);
        ApprovalRequest request = new("tool", "/bin/tool", [], "/w", "r", ["A_NAME"]);
        check(new PasskeyStore(db).Add(Key("k")) && new GrantStore(db).Add("GK", 10) && new AuditLog(db).TryWrite("approved", request, "x"), "db wrong types: a good database first");
        Execute(db.FilePath, "DROP TABLE manifest; CREATE TABLE manifest (id, version, text, bind, credential_id, authenticator_data, client_data, signature); "
            + "INSERT INTO manifest VALUES (1, 'one', NULL, 'AAAA', 'k', 5, NULL, '');");
        Execute(db.FilePath, "DROP TABLE grants; CREATE TABLE grants (key, approved, expires, minutes, key_name); INSERT INTO grants VALUES ('GK', 0, 'not a number', 'ten', NULL);");
        Execute(db.FilePath, "DROP TABLE audit; CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, time, event, secrets, program, detail, key_name, entry, prev_hash, hash); "
            + "INSERT INTO audit (time, event, secrets, program, detail, key_name, entry, prev_hash, hash) VALUES ('2026-11-01T10:00:00+00:00', 'approved', '[]', '', '', '', NULL, '', '');");
        StateDatabase reopened = StateDatabase.InFolder(folder);
        bool tryAll = true;
        bool tryGet = true;
        AuditVerification? verified = null;
        Exception? crash = null;
        try
        {
            tryAll = new PasskeyStore(reopened).TryAll(out _);
            tryGet = new GrantStore(reopened).TryGet("GK", out _, out _);
            verified = new AuditLog(reopened).Verify();
        }
        catch (Exception error)
        {
            crash = error;
        }

        check(crash is null, "db wrong types: no read throws (" + crash?.GetType().Name + ": " + crash?.Message + ")");
        check(!tryAll && new PasskeyStore(reopened).All().Count == 0, "db wrong types: a NULL in the manifest row is an error, not a passkey");
        check(!reopened.TryCheck(out string? wrong) && wrong is not null && wrong.Contains("state failed verification", StringComparison.Ordinal), "db wrong types: it is a verification failure (" + wrong + ")");
        check(!tryGet, "db wrong types: a grant with a non-number expiry is no approval");
        check(verified is { Ok: false, Error: not null }, "db wrong types: the chain check reports the damage");
    }

    private static void Chain(Action<bool, string> check, string root)
    {
        string folder = Path.Combine(root, "chain");
        StateDatabase db = StateDatabase.InFolder(folder);
        AuditLog audit = new(db);
        ApprovalRequest request = new("tool", "/bin/tool", [], "/w", "r", ["A_NAME"]);
        for (int index = 0; index < 4; index++)
        {
            audit.TryWrite("approved", request, "row " + index);
        }

        check(audit.Verify() is { Ok: true, Count: 4 }, "chain: a good chain");
        StringWriter good = new();
        check(AuditCommand.Run(db, new CliCommand.Audit(20, null, true), good, new StringWriter()) == 0 && good.ToString().Contains("ok", StringComparison.Ordinal), "chain: --audit --verify exits 0 on a good chain (" + good + ")");

        Execute(db.FilePath, "UPDATE audit SET detail = 'row X' WHERE id = 2");
        check(audit.Verify() is { Ok: false, BrokenAt: 2 }, "chain: an edited row is the first broken link");
        StringWriter broken = new();
        check(AuditCommand.Run(db, new CliCommand.Audit(20, null, true), broken, new StringWriter()) == RunCommand.StoreError && broken.ToString().Contains("2", StringComparison.Ordinal), "chain: --audit --verify exits 4 and names the entry (" + broken + ")");

        string other = Path.Combine(root, "chain-delete");
        AuditLog second = new(StateDatabase.InFolder(other));
        for (int index = 0; index < 4; index++)
        {
            second.TryWrite("approved", request, "row " + index);
        }

        Execute(Path.Combine(other, "state.db"), "DELETE FROM audit WHERE id = 2");
        check(second.Verify() is { Ok: false, BrokenAt: 3 }, "chain: a deleted row breaks the next link");
    }

    private static async Task AuditOutput(Action<bool, string> check, string root)
    {
        const string Value = "Audit-Secret-Value-77";
        string folder = Path.Combine(root, "output");
        Directory.CreateDirectory(folder);
        StateDatabase db = StateDatabase.InFolder(folder);
        string program = OperatingSystem.IsWindows() ? "hostname" : "true";
        RunArgs args = CliArgs.ParseRun(["--secrets", "AUDIT_NAME", "--reason", "audit output", "--", program], out _)!;
        int code = await new RunCommand(new MemoryStore(new Dictionary<string, string> { ["AUDIT_NAME"] = Value }), new FakeApprover(true), new AuditLog(db), new StringWriter(), new StringWriter()).ExecuteAsync(args, folder);
        check(code == 0, "audit output: the run worked (" + code + ")");
        new AuditLog(db).TryWriteChange("secrets-set", ["SET_NAME"], "passkey laptop verified");

        StringWriter output = new();
        StringWriter errors = new();
        check(AuditCommand.Run(db, new CliCommand.Audit(20, null, false), output, errors) == 0, "audit output: exits 0");
        string[] lines = output.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries);
        check(lines.Length == 4 && lines[0].Trim() == AdminKey.NotSetUp && lines[1].Contains("approved", StringComparison.Ordinal) && lines[1].Contains("AUDIT_NAME", StringComparison.Ordinal) && lines[1].Contains(program, StringComparison.Ordinal)
            && lines[2].Contains("finished", StringComparison.Ordinal) && lines[2].Contains("exit 0", StringComparison.Ordinal)
            && lines[3].Contains("SET_NAME", StringComparison.Ordinal) && lines[3].Split('\t')[^1].Trim() == "laptop", "audit output: the admin key header, then one line per entry with event, names, program, outcome and key (" + output + ")");
        check(!output.ToString().Contains(Value, StringComparison.Ordinal) && !errors.ToString().Contains(Value, StringComparison.Ordinal), "audit output: the secret value never appears");
        byte[] raw = File.ReadAllBytes(db.FilePath);
        check(!System.Text.Encoding.UTF8.GetString(raw).Contains(Value, StringComparison.Ordinal), "audit output: the value is not in the database file");

        StringWriter one = new();
        check(AuditCommand.Run(db, new CliCommand.Audit(1, null, false), one, new StringWriter()) == 0 && one.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries).Length == 2, "audit output: --last 1 (after the header)");
        StringWriter named = new();
        check(AuditCommand.Run(db, new CliCommand.Audit(20, "SET_NAME", false), named, new StringWriter()) == 0 && named.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries).Length == 2, "audit output: --secret (after the header)");

        StateDatabase empty = StateDatabase.InFolder(Path.Combine(root, "nothing-here"));
        StringWriter nothing = new();
        check(AuditCommand.Run(empty, new CliCommand.Audit(20, null, true), nothing, new StringWriter()) == 0 && !File.Exists(empty.FilePath), "audit output: an empty store exits 0 and creates nothing");
    }

    private static void AuditCli(Action<bool, string> check)
    {
        check(CliArgs.Parse(["--audit"], out _) is CliCommand.Audit { Last: 20, Secret: null, Verify: false }, "cli: --audit defaults to the last 20");
        check(CliArgs.Parse(["--audit", "--last", "5", "--secret", "X", "--verify"], out string error) is CliCommand.Audit { Last: 5, Secret: "X", Verify: true }, "cli: --audit --last 5 --secret X --verify (" + error + ")");
        check(CliArgs.Parse(["--audit", "--last", "1000"], out _) is CliCommand.Audit { Last: 1000 }, "cli: --last 1000 is allowed");
        foreach (string bad in new[] { "0", "abc", "1001", "-1", "" })
        {
            check(CliArgs.Parse(["--audit", "--last", bad], out error) is null && error.Length > 0, $"cli: --last '{bad}' is refused");
        }

        check(CliArgs.Parse(["--last", "5"], out _) is null && CliArgs.Parse(["--verify"], out _) is null && CliArgs.Parse(["--secret", "X"], out _) is null, "cli: --last, --secret and --verify need --audit");
        check(CliArgs.Parse(["--audit", "--secret", "bad name"], out _) is null, "cli: --secret takes a valid name");
        check(CliArgs.Parse(["--audit", "--list"], out _) is null, "cli: --audit is one command at a time");
        check(CliArgs.Parse(["--help"], out _) is CliCommand.Help { Text: var help } && help.Contains("--audit", StringComparison.Ordinal) && help.Contains("--verify", StringComparison.Ordinal), "cli: --help lists --audit");
    }

    private static void Execute(string path, string sql)
    {
        using SqliteConnection connection = new(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }
}

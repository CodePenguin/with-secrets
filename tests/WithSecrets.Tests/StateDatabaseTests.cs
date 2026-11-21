using System.Diagnostics;
using System.Text.Json;

using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>The SQLite state store: passkeys and saved approvals in state.db, and the signed audit events the administrative changes write (there is no audit table and no hash chain).</summary>
internal static class StateDatabaseTests
{
    /// <summary>The signed audit events (JSON, in order) of the store folder of <paramref name="path" />: the outbox beside it. Empty when there are none.</summary>
    public static string[] AuditLines(string path) => [.. TestAudit.Events(new StateDatabase(path), all: true).Select(item => item.ToJson())];

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
            Events(check, folder);
            Metadata(check);
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
        check(loaded.Count == 2 && loaded[0] == Key("id-1", "laptop") with { Admin = true, SignCount = 4000000000u, Slot = loaded[0].Slot } && loaded[1] == Key("id-2", "phone", "ws.example.com") with { Slot = loaded[1].Slot } && loaded.All(item => item.Slot is not null) && loaded[0].Created.Offset == TimeSpan.FromHours(2), "db passkeys: records round-trip in order (the admin first), with the offset and a large sign count");
        check(!passkeys.Add(Key("id-1", "again")), "db passkeys: a duplicate Id is refused");
        check(!passkeys.UpdateSignCount(Id("id-1"), 9) && passkeys.All()[0].SignCount == 4000000000u, "db passkeys: a lower sign count does not overwrite a higher one");
        check(!passkeys.UpdateSignCount(Id("id-1"), 4000000000u) && passkeys.All()[0].SignCount == 4000000000u, "db passkeys: an equal sign count changes nothing");
        check(passkeys.UpdateSignCount(Id("id-1"), 4000000001u) && passkeys.All()[0].SignCount == 4000000001u && !passkeys.UpdateSignCount("nope", 1), "db passkeys: a higher sign count is saved");
        check(!passkeys.RemoveById(Id("id-1")) && passkeys.RemoveById(Id("id-2")) && !passkeys.RemoveById(Id("id-2")) && passkeys.ForRp("localhost").Count == 1 && passkeys.ForRp("ws.example.com").Count == 0, "db passkeys: remove by Id; the admin key stays");
        check(passkeys.UnreadableMessage == "cannot read state.db; fix or delete it", "db passkeys: the message names state.db");

        AdminAudit audit = db.Audit;
        check(audit.TryRecord(AdminEvent.Change("key-enrolled", "passkey laptop verified", "laptop")) && audit.TryRecord(AdminEvent.Secrets("secrets-set", ["API_KEY", "DB_URL"], "passkey phone verified", "phone")) && audit.TryRecord(AdminEvent.Secrets("secrets-removed", ["OTHER_NAME"], "passkey phone verified", "phone")), "db audit: three writes");
        IReadOnlyList<AuditEvent> events = TestAudit.Events(db);
        check(events.Count == 3 && events.All(item => item.Type == AuditEventTypes.Admin && item.Verify(TestAudit.KeyOf(db).PublicKey)) && events.Select(item => item.Sequence).SequenceEqual([1L, 2L, 3L]), "db audit: three signed events of type admin, numbered 1 to 3");
        check(TestAudit.TryRead(db, 20, null, out IReadOnlyList<AuditRow> all, out _) && all.Count == 3 && all[0].Event == "key-enrolled" && all[0].KeyName == "laptop" && all[1].Secrets.SequenceEqual(["API_KEY", "DB_URL"]) && all[2].Secrets.SequenceEqual(["OTHER_NAME"]) && all[2].KeyName == "phone", "db audit: events carry the event name, the names and the key name");
        check(TestAudit.TryRead(db, 1, null, out IReadOnlyList<AuditRow> last, out _) && last.Count == 1 && last[0].Event == "secrets-removed", "db audit: the newest event");
        check(TestAudit.TryRead(db, 20, "API_KEY", out IReadOnlyList<AuditRow> filtered, out _) && filtered.Count == 1 && filtered[0].Secrets.Contains("API_KEY"), "db audit: filtering by name");
        check(Convert.ToInt32(Scalar(db.FilePath, "SELECT COUNT(*) FROM sqlite_master WHERE name = 'audit'")) == 0, "db audit: state.db has no audit table (the events are in the signed outbox)");
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
                    if (!AddRetrying(folder, Key(prefix + index)) || !db.Audit.TryRecord(AdminEvent.Change("test-written", prefix + index, "")))
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
        check(failure is null && refused == 0, "db parallel: no write was refused (" + failure?.Message + ", " + refused + ")");
        IReadOnlyList<PasskeyRecord> stored = new PasskeyStore(check1).All(); string[] expectedIds = [.. Enumerable.Range(0, Each).SelectMany(index => new[] { Id("a" + index), Id("b" + index) })]; string missing = string.Join(",", expectedIds.Except(stored.Select(item => item.Id)).Select(id => id[..Math.Min(8, id.Length)])); string distinct = expectedIds.Distinct().Count() + " distinct ids"; check(stored.Count == 2 * Each && TestState.Current(check1)!.Version == 2 * Each, "db parallel: no passkey was lost; one manifest version per key (" + stored.Count + " keys, version " + TestState.Current(check1)?.Version + ", expected " + 2 * Each + "; missing [" + missing + "]; " + distinct + ")");
        IReadOnlyList<AuditEvent> written = TestAudit.Events(check1);
        check(written.Count == 2 * Each && written.Select(item => item.Sequence).OrderBy(n => n).SequenceEqual(Enumerable.Range(1, 2 * Each).Select(n => (long)n)) && written.Select(item => item.EventId).Distinct().Count() == 2 * Each, "db parallel: every audit event is there, numbered without a gap or a repeat, by two writers");
    }

    private static void Unusable(Action<bool, string> check, string root)
    {
        string folder = Path.Combine(root, "garbage");
        Directory.CreateDirectory(folder);
        StateDatabase db = StateDatabase.InFolder(folder);
        foreach (string content in new[] { "", "garbage bytes, not a database at all" })
        {
            File.WriteAllText(db.FilePath, content);
            check(!db.TryCheck(out string? error) && error is not null, $"db unusable '{content}': the check fails with a message");
            check(!new PasskeyStore(db).TryAll(out IReadOnlyList<PasskeyRecord> keys) && keys.Count == 0 && new PasskeyStore(db).All().Count == 0, $"db unusable '{content}': passkeys are an error, not an empty store");
            check(!new PasskeyStore(db).Add(Key("x")), $"db unusable '{content}': no passkey is written or read");
            check(File.ReadAllText(db.FilePath) == content, $"db unusable '{content}': the file is left alone");
        }

        // A real database with a damaged page: the integrity check fails.
        File.Delete(db.FilePath);
        new PasskeyStore(db).Add(Key("damage-admin"));
        // Filler rows, so that the database spans several pages.
        Execute(db.FilePath, "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < 199) INSERT INTO sign_counts (id, count) SELECT 'damage-' || i || '" + new string('n', 200) + "', 1 FROM n");

        byte[] bytes = File.ReadAllBytes(db.FilePath);
        check(bytes.Length > 4096 * 4, "db damaged: the database spans several pages");
        // Damage a data page near the end (filler rows), not the schema: only the integrity check reads it at open.
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
            command.CommandText = "PRAGMA wal_autocheckpoint = 0; INSERT INTO sign_counts (id, count) VALUES ('planted', 1);";
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
        check(added && newDb.TryCheck(out _) && new PasskeyStore(newDb).All().Select(item => item.Id).SequenceEqual([Id("new-key")]), "db stale wal: a new state.db ignores a leftover -wal and -shm");
    }

    /// <summary>A hand-edited table with wrong column types or NULLs: reads fail closed or report, they never crash.</summary>
    private static void WrongTypes(Action<bool, string> check, string root)
    {
        string folder = Path.Combine(root, "wrong-types");
        StateDatabase db = StateDatabase.InFolder(folder);
        ApprovalRequest request = new("tool", "/bin/tool", [], "/w", "r", ["A_NAME"]);
        check(new PasskeyStore(db).Add(Key("k")), "db wrong types: a good database first");
        Execute(db.FilePath, "DROP TABLE manifest; CREATE TABLE manifest (id, version, text, bind, credential_id, authenticator_data, client_data, signature); "
            + "INSERT INTO manifest VALUES (1, 'one', NULL, 'AAAA', 'k', 5, NULL, '');");
        StateDatabase reopened = StateDatabase.InFolder(folder);
        bool tryAll = true;
        Exception? crash = null;
        try
        {
            tryAll = new PasskeyStore(reopened).TryAll(out _);
        }
        catch (Exception error)
        {
            crash = error;
        }

        check(crash is null, "db wrong types: no read throws (" + crash?.GetType().Name + ": " + crash?.Message + ")");
        check(!tryAll && new PasskeyStore(reopened).All().Count == 0, "db wrong types: a NULL in the manifest row is an error, not a passkey");
        check(!reopened.TryCheck(out string? wrong) && wrong is not null && wrong.Contains("state failed verification", StringComparison.Ordinal), "db wrong types: it is a verification failure (" + wrong + ")");
    }

    /// <summary>The signed events an administrative change writes: signed with the machine key, numbered, no value, and written before the change commits.</summary>
    private static void Events(Action<bool, string> check, string root)
    {
        string folder = Path.Combine(root, "events");
        StateDatabase db = StateDatabase.InFolder(folder);
        check(!db.Audit.TryWriteDenied("set-secrets", ["A_NAME"], "nothing here") && !File.Exists(db.FilePath) && TestAudit.Events(db).Count == 0, "audit events: a refusal with no state.db writes nothing and creates none");
        check(new PasskeyStore(db).Add(Key("k")), "audit events: a state exists");
        check(db.Audit.TryWriteDenied("set-secrets", ["A_NAME"], "the admin approval was denied") && TestAudit.Rows(db) is [{ Event: AdminEvent.ChangeDenied } denied] && denied.Detail.StartsWith("set-secrets: ", StringComparison.Ordinal) && denied.Secrets.SequenceEqual(["A_NAME"]), "audit events: a refused change is an event with the command, the names and the reason");

        // An event that cannot be committed fails the change: the audit is part of it.
        string refusedFile = Path.Combine(root, "events-refused", "state.db");
        StateDatabase refusing = new(refusedFile) { Audit = new AdminAudit(() => new RecordingAudit(refuse: true), refusedFile) };
        bool threw = false;
        try
        {
            refusing.Write((connection, transaction) =>
            {
                refusing.AppendAudit(AdminEvent.Change("key-enrolled", "x", "k"));

                return 0;
            });
        }
        catch (StateDatabaseException)
        {
            threw = true;
        }

        check(threw, "audit events: when the event cannot be committed the transaction fails (nothing changes)");
    }

    private static void Metadata(Action<bool, string> check)
    {
        using SoftwareSigningKey key = new();
        Dictionary<string, string> meta = new() { ["secrets"] = "DB_URL,API_KEY", ["key"] = "laptop", ["reuseMinutes"] = "10" };
        AuditFacts facts = new(AuditEventTypes.Authorization, "approved", "approved", "r1", "C:\\work", "deploy.cmd", ["--flag"], "", null, meta);
        AuditEvent signed = AuditEvent.Create(facts, "e1", 1, DateTimeOffset.UtcNow, key);
        check(signed.Verify(key.PublicKey) && signed.Canonical().Contains("\"metadata\":{\"key\":\"laptop\",\"reuseMinutes\":\"10\",\"secrets\":\"DB_URL,API_KEY\"}", StringComparison.Ordinal), "metadata: the event is signed over its metadata (members sorted)");
        check(!(signed with { Metadata = new Dictionary<string, string>(meta) { ["key"] = "other" } }).Verify(key.PublicKey) && !(signed with { Metadata = null }).Verify(key.PublicKey), "metadata: changing or removing a member breaks the signature");
        check(AuditEvent.TryParse(signed.ToJson(), out AuditEvent? parsed, out _) && parsed!.Verify(key.PublicKey) && parsed.Meta["key"] == "laptop" && parsed.ToJson() == signed.ToJson(), "metadata: it round-trips through the stored JSON");

        // An event without metadata has exactly the text (and signature) it always had, and one in the old format verifies.
        AuditEvent plain = AuditEvent.Create(facts with { Metadata = null }, "e2", 2, DateTimeOffset.UtcNow, key);
        check(!plain.ToJson().Contains("metadata", StringComparison.Ordinal) && AuditEvent.TryParse(plain.ToJson(), out AuditEvent? old, out _) && old!.Verify(key.PublicKey) && old.Meta.Count == 0 && old.Problem() is null, "metadata: an event without it keeps the old format and verifies");
        check(!AuditEvent.TryParse(signed.ToJson().Replace("\"key\":\"laptop\"", "\"key\":1", StringComparison.Ordinal), out _, out _), "metadata: a member that is not text is refused");

        // The built-in limits.
        check(AuditMetadata.Problem(Enumerable.Range(0, AuditMetadata.MaxMembers + 1).ToDictionary(index => "m" + index, _ => "v")) is not null, "metadata limit: too many members");
        check(AuditMetadata.Problem(new Dictionary<string, string> { ["bad name"] = "v" }) is not null && AuditMetadata.Problem(new Dictionary<string, string> { ["k"] = new string('x', AuditMetadata.MaxValue + 1) }) is not null, "metadata limit: a bad name or a long value");
        check(AuditMetadata.Problem(Enumerable.Range(0, 8).ToDictionary(index => "k" + index, _ => new string('x', 1500))) is not null, "metadata limit: the total size");
        check(AuditMetadata.Problem(new Dictionary<string, string> { ["k"] = "\ud800" }) is not null, "metadata limit: text that is not valid UTF-8");
        AuditEvent bounded = AuditEvent.Create(facts with { Metadata = Enumerable.Range(0, 40).ToDictionary(index => "m" + index.ToString("D2"), _ => new string('y', 3000)) }, "e3", 3, DateTimeOffset.UtcNow, key);
        check(bounded.Problem() is null && bounded.Verify(key.PublicKey) && bounded.Meta.Count <= AuditMetadata.MaxMembers, "metadata limit: what the host signs is cut to the limits, so the authority never refuses it for size");
    }

    private static void AuditCli(Action<bool, string> check)
    {
        check(CliArgs.Parse(["--audit"], out string error) is null && error.Length > 0, "cli: --audit is gone (the audit is read in the admin web app)");
        check(CliArgs.Parse(["--help"], out _) is CliCommand.Help { Text: var help } && !help.Contains("--audit", StringComparison.Ordinal) && !help.Contains("hash chain", StringComparison.OrdinalIgnoreCase) && help.Contains("admin web app", StringComparison.Ordinal), "cli: --help names no --audit and no hash chain");
    }

    private static void Execute(string path, string sql)
    {
        using SqliteConnection connection = new(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static object? Scalar(string path, string sql)
    {
        using SqliteConnection connection = new(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;

        return command.ExecuteScalar();
    }
}

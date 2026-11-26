using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

internal static class WithSecretsDatabaseTests
{
    public static async Task Run(Action<bool, string> check)
    {
        OneOpener(check);
        DirectoryInfo root = Directory.CreateTempSubdirectory("with-secrets-db-");
        try
        {
            WithSecretsDatabase db = New(root, "fresh");
            check(db.Read(connection => connection is null) && !Directory.Exists(Path.GetDirectoryName(db.FilePath)), "database: a read of a missing file creates nothing");
            db.Write((_, _) => 0);
            AuthorityStore authority = new(db);
            StateDatabase state = new(db);
            authority.RecordPairingEvent("pairing-test", null, "local");
            check(state.TryCheck(out _) && state.TryManifest(out Manifest? none, out _) && none is null
                && authority.FilePath == state.FilePath && authority.Audit().Any(item => item.Event == "pairing-test"),
                "database: an authority write shares an empty state store");
            check(db.FileLabel == "with-secrets.db" && (string?)RawScalar(db.FilePath, "PRAGMA journal_mode") == "wal"
                && (long?)RawScalar(db.FilePath, "SELECT version FROM schema_version") == 4, "database: one file, WAL, schema version 4");
            check(db.Read(connection =>
                (long?)WithSecretsDatabase.Scalar(connection!, null, "PRAGMA synchronous") == 2
                && (long?)WithSecretsDatabase.Scalar(connection!, null, "PRAGMA foreign_keys") == 1
                && (long?)WithSecretsDatabase.Scalar(connection!, null, "PRAGMA busy_timeout") == 5000), "database: reads use FULL durability, foreign keys and a five-second busy timeout");
            check(db.Write((connection, transaction) => (long?)WithSecretsDatabase.Scalar(connection, transaction, "PRAGMA synchronous") == 2
                && (long?)WithSecretsDatabase.Scalar(connection, transaction, "PRAGMA foreign_keys") == 1), "database: writes use FULL durability and foreign keys");
            check(db.Read(connection =>
            {
                using SqliteCommand command = WithSecretsDatabase.Command(connection!, null, "SELECT name FROM sqlite_schema WHERE type = 'table' AND name <> 'sqlite_sequence' ORDER BY name");
                using SqliteDataReader result = command.ExecuteReader();
                List<string> tables = [];
                while (result.Read()) tables.Add(result.GetString(0));
                return tables.SequenceEqual(WithSecretsDatabase.Tables) && new[] { "manifest", "grants", "provider_cache", "outbox_events", "pairing_invitations" }.All(tables.Contains);
            }), "database: the full schema includes state, authority, provider and outbox tables");
            check((long?)RawScalar(db.FilePath, "SELECT last_sequence FROM outbox_counter") == 0
                && (string?)RawScalar(db.FilePath, "SELECT machine FROM outbox_counter") == "", "database: the outbox starts without a machine or sequence");
            db.Write((connection, transaction) => WithSecretsDatabase.Execute(connection, transaction,
                "INSERT INTO outbox_events (machine, sequence, event_id, json, created, state) VALUES ('first', 1, 'old', '{}', 't', 'pending'), ('second', 1, 'new', '{}', 't', 'pending')"));
            check((string?)RawScalar(db.FilePath, "SELECT event_id FROM outbox_events ORDER BY id LIMIT 1") == "old"
                && (long?)RawScalar(db.FilePath, "SELECT COUNT(*) FROM outbox_events") == 2,
                "database: the outbox can retain an earlier epoch's sequence and preserves append order");

            // Mixed writers, each on its own instance of the one file: raw audit_history rows, authority audit rows, outbox appends (numbered and signed) and spent admin nonces.
            using SoftwareSigningKey machineKey = new();
            await Task.WhenAll(Enumerable.Range(0, 8).Select(task => Task.Run(() =>
            {
                WithSecretsDatabase writer = new(db.FilePath);
                HostAuditOutbox outbox = new(writer, machineKey);
                AuthorityStore store = new(writer);
                for (int index = 0; index < 25; index++)
                {
                    switch (task % 4)
                    {
                        case 0:
                            writer.Write((connection, transaction) => WithSecretsDatabase.Execute(connection, transaction,
                                "INSERT INTO audit_history (time, event, actor, detail) VALUES ('t', 'e', 'a', 'd')"));
                            break;
                        case 1:
                            store.RecordPairingEvent("e", null, "mixed writer");
                            break;
                        case 2:
                            outbox.Append(new AuditFacts(AuditEventTypes.Authorization, "approved", "approved", "req-mixed", "/work", "/work/show.sh", [], "", null));
                            break;
                        default:
                            store.TrySpendAdminNonce("mixed-" + task + "-" + index, DateTimeOffset.UtcNow.AddHours(1));
                            break;
                    }
                }
            })));
            HostAuditOutbox reader = new(db, machineKey);
            check((long?)RawScalar(db.FilePath, "SELECT COUNT(*) FROM audit_history WHERE event = 'e'") == 100
                && reader.Pending(1000).Where(item => item.MachineFingerprint == KeyIdentity.Fingerprint(machineKey.PublicKey)).Select(item => item.Sequence).SequenceEqual(Enumerable.Range(1, 50).Select(i => (long)i)),
                "database: eight mixed writers (raw rows, authority rows, outbox appends, spent nonces) commit 25 writes each; the outbox numbers stay gapless");
            check(Catch<InvalidOperationException>(() => db.Write((_, _) => new WithSecretsDatabase(db.FilePath).Write((_, _) => 0)))?.Message.Contains("inside another write", StringComparison.Ordinal) == true,
                "database: a nested write through another instance fails immediately");
            WithSecretsDatabase retry = new(db.FilePath) { BeginFault = attempt => attempt < 2 ? new SqliteException("protocol", 15) : null };
            int ran = 0;
            check(retry.Write((_, _) => ++ran) == 1 && ran == 1, "database: BEGIN is retried and the work runs once");
            WithSecretsDatabase stuck = new(db.FilePath, TimeSpan.FromMilliseconds(150)) { BeginFault = _ => new SqliteException("busy", 5) };
            check(Catch<WithSecretsDatabaseException>(() => stuck.Write((_, _) => 0))?.Message == "with-secrets.db is locked by another process; try again",
                "database: a busy BEGIN returns the lock error at its deadline");
            await OneDeadline(db, check);
            long history = (long)RawScalar(db.FilePath, "SELECT COUNT(*) FROM audit_history")!;
            check(Catch<WithSecretsDatabaseException>(() => db.Write<int>((connection, transaction) =>
            {
                WithSecretsDatabase.Execute(connection, transaction, "DELETE FROM audit_history");
                throw new SqliteException("busy during callback", 5);
            })) is not null && history > 100 && (long?)RawScalar(db.FilePath, "SELECT COUNT(*) FROM audit_history") == history,
                "database: a failed callback rolls back and is not retried");

            string copy = New(root, "copy").FilePath;
            Directory.CreateDirectory(Path.GetDirectoryName(copy)!);
            db.CopyTo(copy);
            check((long?)new WithSecretsDatabase(copy).Read(connection => WithSecretsDatabase.Scalar(connection!, null, "SELECT COUNT(*) FROM audit_history")) == history
                && Catch<WithSecretsDatabaseException>(() => db.CopyTo(copy)) is not null, "database: the snapshot carries committed rows and an existing target is refused");

            RawScalar(db.FilePath, "PRAGMA journal_mode = DELETE");
            RawScalar(db.FilePath, "UPDATE schema_version SET version = 2");
            check(Catch<WithSecretsDatabaseException>(() => new WithSecretsDatabase(db.FilePath).Read(_ => 0))?.Message
                == "with-secrets.db is not of schema version 4; delete with-secrets.db to start over"
                && (string?)RawScalar(db.FilePath, "PRAGMA journal_mode") == "delete", "database: a foreign schema version is refused without changing the database");

            WithSecretsDatabase edited = New(root, "edited");
            edited.Write((_, _) => 0);
            RawScalar(edited.FilePath, "ALTER TABLE secrets ADD COLUMN unexpected TEXT");
            check(Catch<WithSecretsDatabaseException>(() => new WithSecretsDatabase(edited.FilePath).Read(_ => 0))?.Message.Contains("unexpected definition of table secrets", StringComparison.Ordinal) == true,
                "database: an edited table is refused even when its name still matches");

            WithSecretsDatabase old = New(root, "old");
            string oldFolder = Path.GetDirectoryName(old.FilePath)!;
            Directory.CreateDirectory(oldFolder);
            File.WriteAllText(Path.Combine(oldFolder, "authority.db"), "old");
            check(Catch<WithSecretsDatabaseException>(() => old.Write((_, _) => 0))?.Message.EndsWith("still holds authority.db from an earlier version of with-secrets; delete it to start over (nothing is moved over)", StringComparison.Ordinal) == true
                && !File.Exists(old.FilePath) && File.Exists(Path.Combine(oldFolder, "authority.db")), "database: an old file is refused without creating or deleting files");

            WithSecretsDatabase damaged = New(root, "damaged");
            Directory.CreateDirectory(Path.GetDirectoryName(damaged.FilePath)!);
            File.WriteAllText(damaged.FilePath, "this is not a database file");
            check(Catch<WithSecretsDatabaseException>(() => damaged.Read(_ => 0))?.Message.StartsWith("with-secrets.db is damaged (", StringComparison.Ordinal) == true,
                "database: a damaged file is refused");

            WithSecretsDatabase gated = New(root, "gated");
            using (gated.HoldCreationGateForTests())
            {
                WithSecretsDatabase other = new(gated.FilePath, TimeSpan.FromMilliseconds(100));
                check(Catch<WithSecretsDatabaseException>(() => other.Write((_, _) => 0))?.Message.Contains("with-secrets.db.lock", StringComparison.Ordinal) == true
                    && !File.Exists(gated.FilePath), "database: creation waits for the shared lock and times out safely");

                WithSecretsDatabase late = new(gated.FilePath, TimeSpan.FromSeconds(1))
                {
                    OpenFault = _ =>
                    {
                        Thread.Sleep(750);
                        return null;
                    },
                };
                System.Diagnostics.Stopwatch clock = System.Diagnostics.Stopwatch.StartNew();
                string? failure = Catch<WithSecretsDatabaseException>(() => late.Write((_, _) => 0))?.Message;
                check(failure?.Contains("with-secrets.db.lock", StringComparison.Ordinal) == true && clock.Elapsed < TimeSpan.FromSeconds(1.55),
                    "database: the creation lock waits only for the remaining write budget");
            }
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    /// <summary>A write waits at most one busy timeout in all: the in-process gate, opening (its pragmas) and BEGIN share one deadline.</summary>
    private static async Task OneDeadline(WithSecretsDatabase db, Action<bool, string> check)
    {
        // The gate is held for 1.5 s of a 2 s budget, then BEGIN stays busy: the error comes at 2 s, not 1.5 s + 2 s.
        using (SemaphoreSlim inside = new(0, 1))
        using (SemaphoreSlim release = new(0, 1))
        {
            Task holder = Task.Run(() => new WithSecretsDatabase(db.FilePath).Write((_, _) =>
            {
                inside.Release();
                release.Wait(TimeSpan.FromSeconds(1.5));
                return 0;
            }));
            await inside.WaitAsync();
            WithSecretsDatabase late = new(db.FilePath, TimeSpan.FromSeconds(2)) { BeginFault = _ => new SqliteException("busy", 5) };
            System.Diagnostics.Stopwatch clock = System.Diagnostics.Stopwatch.StartNew();
            string? message = Catch<WithSecretsDatabaseException>(() => late.Write((_, _) => 0))?.Message;
            TimeSpan took = clock.Elapsed;
            await holder;
            check(message == "with-secrets.db is locked by another process; try again" && took < TimeSpan.FromSeconds(2.75),
                "database: the gate wait and the BEGIN retries share one busy timeout (" + took.TotalMilliseconds.ToString("F0", System.Globalization.CultureInfo.InvariantCulture) + " ms of 2000)");
        }

        // Another connection holds the write lock: SQLite's own wait and the driver's retry stay inside the budget too.
        using (SqliteConnection other = new(new SqliteConnectionStringBuilder { DataSource = db.FilePath, Mode = SqliteOpenMode.ReadWrite, Pooling = false }.ToString()))
        {
            other.Open();
            using SqliteTransaction held = other.BeginTransaction(deferred: false);
            WithSecretsDatabase blocked = new(db.FilePath, TimeSpan.FromSeconds(1.5));
            System.Diagnostics.Stopwatch clock = System.Diagnostics.Stopwatch.StartNew();
            string? message = Catch<WithSecretsDatabaseException>(() => blocked.Write((_, _) => 0))?.Message;
            TimeSpan took = clock.Elapsed;
            held.Rollback();
            check(message == "with-secrets.db is locked by another process; try again" && took >= TimeSpan.FromSeconds(1.3) && took < TimeSpan.FromSeconds(2.2),
                "database: a write lock held elsewhere gives the lock error at one busy timeout (" + took.TotalMilliseconds.ToString("F0", System.Globalization.CultureInfo.InvariantCulture) + " ms of 1500)");
        }

        // Opening for a write retries BUSY, LOCKED and PROTOCOL inside the same deadline, not failing at once.
        WithSecretsDatabase opening = new(db.FilePath) { OpenFault = attempt => attempt switch { 0 => new SqliteException("busy", 5), 1 => new SqliteException("locked", 6), 2 => new SqliteException("protocol", 15), _ => null } };
        int ran = 0;
        check(opening.Write((_, _) => ++ran) == 1 && ran == 1, "database: a busy, locked or protocol error while opening for a write is retried and the work runs once");
        WithSecretsDatabase neverOpens = new(db.FilePath, TimeSpan.FromMilliseconds(300)) { OpenFault = _ => new SqliteException("protocol", 15) };
        System.Diagnostics.Stopwatch opened = System.Diagnostics.Stopwatch.StartNew();
        string? refused = Catch<WithSecretsDatabaseException>(() => neverOpens.Write((_, _) => 0))?.Message;
        check(refused == "with-secrets.db is locked by another process; try again" && opened.Elapsed >= TimeSpan.FromMilliseconds(250),
            "database: an open that stays busy returns the lock error at its deadline, not at once");
    }

    // A connection made anywhere: `new SqliteConnection(`, a target-typed `new(` assigned to a SqliteConnection, or any `SqliteConnection(` call.
    private static readonly System.Text.RegularExpressions.Regex Connects = new(@"\bSqliteConnection\s*\(|\bSqliteConnection\??\s+\w+\s*=\s*new\s*\(|\bSqliteConnection\??\s+\w+\s*\([^)]*\)\s*=>\s*new\s*\(",System.Text.RegularExpressions.RegexOptions.Compiled);

    /// <summary>Only WithSecretsDatabase.cs opens a connection to with-secrets.db (with its pragmas, gate and retries); every other file goes through it.</summary>
    public static void OneOpener(Action<bool, string> check)
    {
        string? repo = AppContext.BaseDirectory;
        while (repo is not null && !File.Exists(Path.Combine(repo, "with-secrets.slnx")))
        {
            repo = Path.GetDirectoryName(repo);
        }

        string src = Path.Combine(repo ?? ".", "src");
        string[] files = [.. Directory.GetFiles(src, "*.cs", SearchOption.AllDirectories)
            .Where(file => !file.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(part => part is "bin" or "obj" or "node_modules"))];
        string[] openers = [.. files.Where(file => Connects.IsMatch(File.ReadAllText(file))).Select(file => Path.GetFileName(file)).Order(StringComparer.Ordinal)];
        check(files.Length > 50 && Connects.IsMatch("using SqliteConnection connection = new(text);") && Connects.IsMatch("new SqliteConnection(text)") && Connects.IsMatch("private SqliteConnection Connect(string a) => new(text);") &&!Connects.IsMatch("SqliteConnection connection, SqliteTransaction transaction")
            && openers.SequenceEqual(["WithSecretsDatabase.cs"]), "database: only WithSecretsDatabase.cs constructs a SqliteConnection in src (" + string.Join(", ", openers) + ")");
    }

    private static WithSecretsDatabase New(DirectoryInfo root, string name) => WithSecretsDatabase.InFolder(Path.Combine(root.FullName, name));

    private static object? RawScalar(string path, string sql)
    {
        using SqliteConnection connection = new(new SqliteConnectionStringBuilder { DataSource = path, Mode = SqliteOpenMode.ReadWrite, Pooling = false }.ToString());
        connection.Open();
        return WithSecretsDatabase.Scalar(connection, null, sql);
    }

    private static T? Catch<T>(Action action) where T : Exception
    {
        try
        {
            action();
            return null;
        }
        catch (T error)
        {
            return error;
        }
    }
}

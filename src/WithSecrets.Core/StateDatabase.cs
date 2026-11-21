using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Text.Json;

using Microsoft.Data.Sqlite;

namespace WithSecrets;

/// <summary>A state database that cannot be used: unreadable, locked past the timeout, damaged, or of an unknown schema.</summary>
public sealed class StateDatabaseException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// <c>state.db</c> in the protected store folder: the signed manifest (passkeys and settings, see <see cref="Manifest" />), the
/// sign counts and secrets, in SQLite. Every read of keys, settings or secrets verifies the manifest
/// first (see <see cref="CurrentManifest" />); a state that fails verification can be used for nothing. Every
/// write is one transaction that takes the write lock first (<c>BEGIN IMMEDIATE</c>), so two processes writing at once wait for
/// each other (up to the busy timeout) and no update is lost. A missing database is empty. A database that exists but cannot be
/// used (not a database, damaged, locked beyond the timeout, another schema version) is an error, never an empty store. A
/// database of another schema version is never moved forward: the message says to delete it and start over. It holds no
/// secret value in plain text: each secret is a row of Dotenvx ciphertext (see <see cref="SecretStore" />). The tool reads no
/// other file in the store folder.
/// </summary>
public sealed class StateDatabase
{
    public const string FileName = "state.db";
    public const int SchemaVersion = 11;

    public static readonly TimeSpan DefaultBusyTimeout = TimeSpan.FromSeconds(5);

    /// <summary>
    /// The tables. Keys and settings live only in the signed manifest (one row); sign counts sit beside it, outside the
    /// signature, because every approval raises them. Each secret is one
    /// row with its Dotenvx ciphertext; the manifest has the hash of each (see <see cref="SecretStore" />).
    /// </summary>
    private const string Schema = """
        CREATE TABLE schema_version (version INTEGER NOT NULL);
        CREATE TABLE manifest (
            id INTEGER PRIMARY KEY NOT NULL, version INTEGER NOT NULL, text TEXT NOT NULL, bind TEXT NOT NULL,
            credential_id TEXT NOT NULL, authenticator_data TEXT NOT NULL, client_data TEXT NOT NULL, signature TEXT NOT NULL);
        CREATE TABLE sign_counts (id TEXT PRIMARY KEY NOT NULL, count INTEGER NOT NULL);
        CREATE TABLE secrets (name TEXT PRIMARY KEY NOT NULL, ciphertext TEXT NOT NULL);
        """;

    /// <summary>
    /// The tables a store holds, all of them (sqlite_sequence may or may not be there). Any other table, any view, trigger or
    /// index other than SQLite's own primary-key indexes is an edit made outside the tool.
    /// </summary>
    private static readonly string[] Tables = ["manifest", "schema_version", "secrets", "sign_counts"];

    /// <summary>Manifests already verified in this process, by the stored row, so the signature is checked once per process.</summary>
    private static readonly ConcurrentDictionary<string, Manifest> Verified = new(StringComparer.Ordinal);

    private readonly TimeSpan _busyTimeout;
    private int _checked;

    public StateDatabase(string path) : this(path, DefaultBusyTimeout)
    {
    }

    internal StateDatabase(string path, TimeSpan busyTimeout)
    {
        FilePath = Path.GetFullPath(path);
        _busyTimeout = busyTimeout;
    }

    public string FilePath { get; }

    private AdminAudit? _audit;

    /// <summary>
    /// Where this store's administrative events go (the signed host audit; there is no audit table in state.db). By default the machine identity key of the platform key store
    /// and the outbox beside the state, opened on first use; the host service puts its own audit here so that an event wakes its uploader.
    /// </summary>
    public AdminAudit Audit
    {
        get => _audit ??= AdminAudit.ForState(FilePath);
        set => _audit = value;
    }

    /// <summary>Records one administrative event inside the caller's write transaction (just before it commits); throws <see cref="StateDatabaseException" /> when it cannot be committed, which rolls the change back.</summary>
    internal void AppendAudit(AdminEvent item) => Audit.Append(item);

    /// <summary>The file name, for messages.</summary>
    public string FileLabel => Path.GetFileName(FilePath);

    private string Folder => Path.GetDirectoryName(FilePath)!;

    public static StateDatabase InFolder(string folder) => new(Path.Combine(folder, FileName));

    /// <summary>The message for a state that fails verification. Never "not enrolled": deleting the file is the only way on.</summary>
    public string FailedMessage => $"state failed verification: delete {FileLabel} to start over (only if you did not edit it)";

    /// <summary>
    /// True when the database is missing (empty) or opens, passes the integrity check and its manifest verifies (or it is an
    /// empty state). Creates nothing.
    /// </summary>
    public bool TryCheck(out string? error)
    {
        try
        {
            Read(connection => CurrentManifest(connection, null));
            error = null;

            return true;
        }
        catch (StateDatabaseException failure)
        {
            error = failure.Message;

            return false;
        }
    }

    /// <summary>
    /// What every command does first: null when the state can be used, else the exit code (<see cref="RunCommand.StoreError" />)
    /// after writing why to <paramref name="stderr" />.
    /// </summary>
    public int? Gate(TextWriter stderr)
    {
        if (TryCheck(out string? error))
        {
            return null;
        }

        // Logged without the reason text: it can name a path. The terminal gets the reason.
        AppLog.Warn("the state failed its check, so the command stopped (exit {Code})", RunCommand.StoreError);
        stderr.WriteLine("with-secrets: " + error);

        return RunCommand.StoreError;
    }

    /// <summary>The verified manifest (null for an empty state), or false and why not. Creates nothing.</summary>
    public bool TryManifest(out Manifest? manifest, out string? error)
    {
        try
        {
            manifest = Read(connection => CurrentManifest(connection, null));
            error = null;

            return true;
        }
        catch (StateDatabaseException failure)
        {
            manifest = null;
            error = failure.Message;

            return false;
        }
    }

    /// <summary>
    /// The verified manifest on this connection, or null for an empty state: no database, or no manifest and no sign counts and
    /// no rows. Throws <see cref="StateDatabaseException" /> with <see cref="FailedMessage" /> for anything else: a
    /// manifest that does not verify, two rows, rows that need a manifest without one, a sign count for a key that is not in
    /// it, or a table that is not part of the store.
    /// </summary>
    internal Manifest? CurrentManifest(SqliteConnection? connection, SqliteTransaction? transaction)
    {
        if (connection is null)
        {
            return null;
        }

        try
        {
            return ReadManifest(connection, transaction);
        }
        catch (SqliteException failure) when (failure.SqliteErrorCode is not (5 or 6))
        {
            throw Failed("the manifest cannot be read: " + failure.Message);
        }
        catch (Exception failure) when (failure is not (StateDatabaseException or SqliteException))
        {
            throw Failed("the manifest cannot be read: " + failure.Message);
        }
    }

    private Manifest? ReadManifest(SqliteConnection connection, SqliteTransaction? transaction)
    {

        List<(string Type, string Name)> objects = [];
        using (SqliteCommand command = Command(connection, transaction, "SELECT type, name FROM sqlite_master"))
        using (SqliteDataReader reader = command.ExecuteReader())
        {
            while (reader.Read())
            {
                objects.Add((reader.GetString(0), reader.GetString(1)));
            }
        }

        HashSet<string> tables = [.. objects.Where(item => item.Type == "table").Select(item => item.Name).Where(name => name != "sqlite_sequence")];
        bool others = objects.Any(item => item.Type != "table" && !(item.Type == "index" && item.Name.StartsWith("sqlite_autoindex_", StringComparison.Ordinal)));
        if (others || !tables.SetEquals(Tables))
        {
            throw Failed("the tables are not those of the store");
        }

        List<(long Version, SignedManifest Signed)> rows = [];
        using (SqliteCommand command = Command(connection, transaction, "SELECT version, text, bind, credential_id, authenticator_data, client_data, signature FROM manifest"))
        using (SqliteDataReader reader = command.ExecuteReader())
        {
            while (reader.Read())
            {
                string bind = reader.GetString(2);
                if (!Base64Url.IsValid(bind))
                {
                    throw Failed("the manifest bind is not base64url");
                }

                string proof = JsonSerializer.Serialize(new Dictionary<string, string>
                {
                    ["id"] = reader.GetString(3),
                    ["authenticatorData"] = reader.GetString(4),
                    ["clientDataJSON"] = reader.GetString(5),
                    ["signature"] = reader.GetString(6),
                });
                rows.Add((reader.GetInt64(0), new SignedManifest(reader.GetString(1), Base64Url.DecodeFromChars(bind), proof)));
            }
        }

        Dictionary<string, long> counts = SignCounts(connection, transaction);
        if (rows.Count == 0)
        {
            if (counts.Count > 0 || Scalar(connection, transaction, "SELECT COUNT(*) FROM secrets") is not 0L)
            {
                throw Failed("keys or secrets without a manifest");
            }

            return null;
        }

        if (rows.Count > 1)
        {
            throw Failed("more than one manifest");
        }

        (long version, SignedManifest signed) = rows[0];
        string cacheKey = string.Join("\n", signed.Text, Convert.ToBase64String(signed.Bind), signed.Proof);
        if (!Verified.TryGetValue(cacheKey, out Manifest? manifest))
        {
            manifest = signed.Verify(out string? error) ?? throw Failed(error ?? "the manifest does not verify");
            Verified[cacheKey] = manifest;
        }

        if (manifest.Version != version)
        {
            throw Failed("the manifest version does not match its row");
        }

        if (counts.Any(item => item.Value is < 0 or > uint.MaxValue || !manifest.Keys.Any(key => key.Id == item.Key)))
        {
            throw Failed("a sign count that does not belong to an enrolled key");
        }

        return manifest;
    }

    /// <summary>The stored sign counts, by credential id.</summary>
    internal static Dictionary<string, long> SignCounts(SqliteConnection connection, SqliteTransaction? transaction)
    {
        Dictionary<string, long> counts = new(StringComparer.Ordinal);
        using SqliteCommand command = Command(connection, transaction, "SELECT id, count FROM sign_counts");
        using SqliteDataReader reader = command.ExecuteReader();
        while (reader.Read())
        {
            counts[reader.GetString(0)] = reader.GetInt64(1);
        }

        return counts;
    }

    /// <summary>
    /// Inside the caller's write transaction: replaces the manifest with <paramref name="next" />, only when the stored one is
    /// still version <paramref name="expectedVersion" /> (0 for none), <paramref name="next" /> is the version after it, and it
    /// is signed by a key that is an admin of the stored manifest and stays an admin in <paramref name="next" /> (see
    /// <see cref="SignedManifest.Verify(Manifest?, out string?)" />; on the first run, by an admin of <paramref name="next" />). Sign counts of keys that are no longer in it are removed. Null when it was written,
    /// else why not (nothing is written). The caller has already checked the assertion in full on the page.
    /// </summary>
    internal string? TryReplace(SqliteConnection connection, SqliteTransaction transaction, long expectedVersion, SignedManifest next)
    {
        Manifest? current = CurrentManifest(connection, transaction);
        if ((current?.Version ?? 0) != expectedVersion)
        {
            return "the state changed while the page was open; nothing was saved";
        }

        // Signed by a key that is an admin of the stored state (on the first run, of the new one), and that stays an admin, so the
        // new state verifies when it is read.
        Manifest? manifest = next.Verify(current, out string? error);
        if (manifest is null)
        {
            return "the new state does not verify (" + error + "); nothing was saved";
        }

        if (manifest.Version != expectedVersion + 1)
        {
            return "the new state is not the next version; nothing was saved";
        }

        using JsonDocument proof = JsonDocument.Parse(next.Proof);
        JsonElement root = proof.RootElement;
        string Field(string name) => root.GetProperty(name).GetString() ?? throw new FormatException(name);
        Execute(connection, transaction, "DELETE FROM manifest");
        Execute(connection, transaction,
            "INSERT INTO manifest (id, version, text, bind, credential_id, authenticator_data, client_data, signature) VALUES (1, $version, $text, $bind, $id, $ad, $cd, $sig)",
            ("$version", manifest.Version), ("$text", next.Text), ("$bind", Base64Url.EncodeToString(next.Bind)), ("$id", Field("id")),
            ("$ad", Field("authenticatorData")), ("$cd", Field("clientDataJSON")), ("$sig", Field("signature")));
        foreach (string id in SignCounts(connection, transaction).Keys.Where(id => !manifest.Keys.Any(key => key.Id == id)))
        {
            Execute(connection, transaction, "DELETE FROM sign_counts WHERE id = $id", ("$id", id));
        }

        return null;
    }

    private StateDatabaseException Failed(string why) => new(FailedMessage + " (" + why + ")");

    /// <summary>Runs <paramref name="work" /> on an open connection, or with null when there is no database. Creates nothing.</summary>
    internal T Read<T>(Func<SqliteConnection?, T> work)
    {
        return Use(false, work);
    }

    /// <summary>One write transaction, committed when <paramref name="work" /> returns. Creates the database when it is missing.</summary>
    internal T Write<T>(Func<SqliteConnection, SqliteTransaction, T> work)
    {
        return Use(true, connection =>
        {
            using SqliteTransaction transaction = connection!.BeginTransaction(deferred: false);
            T result = work(connection, transaction);
            transaction.Commit();

            return result;
        });
    }

    internal static SqliteCommand Command(SqliteConnection connection, SqliteTransaction? transaction, string sql, params (string Name, object? Value)[] parameters)
    {
        SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach ((string name, object? value) in parameters)
        {
            command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }

        return command;
    }

    internal static int Execute(SqliteConnection connection, SqliteTransaction? transaction, string sql, params (string Name, object? Value)[] parameters)
    {
        using SqliteCommand command = Command(connection, transaction, sql, parameters);

        return command.ExecuteNonQuery();
    }

    internal static object? Scalar(SqliteConnection connection, SqliteTransaction? transaction, string sql, params (string Name, object? Value)[] parameters)
    {
        using SqliteCommand command = Command(connection, transaction, sql, parameters);

        return command.ExecuteScalar();
    }

    private T Use<T>(bool create, Func<SqliteConnection?, T> work)
    {
        try
        {
            using SqliteConnection? connection = Open(create);

            return work(connection);
        }
        catch (SqliteException failure)
        {
            throw new StateDatabaseException(Describe(failure), failure);
        }
        catch (Exception failure) when (failure is IOException or UnauthorizedAccessException)
        {
            throw new StateDatabaseException($"cannot read {FileLabel}: {failure.Message}", failure);
        }
        catch (Exception failure) when (failure is not StateDatabaseException)
        {
            // Anything else from reading the rows (a NULL or a wrong type in a hand-edited table): the store cannot be used.
            throw new StateDatabaseException($"{FileLabel} holds data that cannot be read ({failure.Message}); fix or delete it", failure);
        }
    }

    private string Describe(SqliteException failure)
    {
        return failure.SqliteErrorCode is 5 or 6
            ? $"{FileLabel} is locked by another process; try again"
            : $"cannot read {FileLabel}: {failure.Message}";
    }

    private SqliteConnection? Open(bool create)
    {
        if (!File.Exists(FilePath))
        {
            if (!create)
            {
                return null;
            }

            Create();
        }

        SqliteConnection connection = Connect(FilePath, SqliteOpenMode.ReadWrite);
        try
        {
            connection.Open();
            Execute(connection, null, "PRAGMA busy_timeout = " + (int)_busyTimeout.TotalMilliseconds);
            if (Volatile.Read(ref _checked) == 0)
            {
                List<string> problems = [];
                using (SqliteCommand check = Command(connection, null, "PRAGMA integrity_check"))
                using (SqliteDataReader reader = check.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        problems.Add(reader.GetString(0));
                    }
                }

                if (problems is not ["ok"])
                {
                    string first = problems.Count == 0 ? "no result" : problems[0];
                    throw new StateDatabaseException($"{FileLabel} is damaged ({first}); fix or delete it");
                }
            }

            // A file with no schema (an empty file, or another database) is not our store, so it is not an empty one either.
            long found = Version(connection, null);
            if (found != SchemaVersion)
            {
                // Older or newer: never moved forward and never used.
                throw new StateDatabaseException($"{FileLabel} is not of schema version {SchemaVersion}; delete {FileLabel} to start over");
            }

            Volatile.Write(ref _checked, 1);

            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    /// <summary>The one schema version row, or -1 when there is not exactly one.</summary>
    private static long Version(SqliteConnection connection, SqliteTransaction? transaction)
    {
        using SqliteCommand version = Command(connection, transaction, "SELECT version FROM schema_version");
        using SqliteDataReader reader = version.ExecuteReader();
        if (!reader.Read())
        {
            return -1;
        }

        long value = reader.GetInt64(0);

        return reader.Read() ? -1 : value;
    }


    /// <summary>
    /// Builds the schema in a new file next to the database and moves it into place, so the database path only ever holds a
    /// complete store. When another process made one first, that one is used.
    /// </summary>
    private void Create()
    {
        Directory.CreateDirectory(Folder);

        // One creator at a time, across processes. The files of an earlier state.db are removed below only while there is no state.db; without this, a writer that saw no state.db a moment ago could remove the journal files of the
        // one that has just made it and written its first key (the key was lost, found by the parallel first-creation test). Under the gate that check and the removal cannot overlap with another creator.
        using FileStream gate = AcquireCreationGate();
        if (File.Exists(FilePath))
        {
            return;
        }

        // A -wal or -shm left behind by an earlier state.db would be applied to the new file. Remove them, but only while there
        // is still no state.db (another process may have just made one, and its journal files are its own).
        foreach (string stale in new[] { FilePath + "-wal", FilePath + "-shm" })
        {
            if (!File.Exists(FilePath))
            {
                File.Delete(stale);
            }
        }

        string temp = FilePath + "." + Guid.NewGuid().ToString("N") + ".new";
        try
        {
            using (SqliteConnection connection = Connect(temp, SqliteOpenMode.ReadWriteCreate))
            {
                connection.Open();
                Execute(connection, null, "PRAGMA journal_mode = WAL");
                using SqliteTransaction transaction = connection.BeginTransaction(deferred: false);
                Execute(connection, transaction, Schema);
                Execute(connection, transaction, "INSERT INTO schema_version (version) VALUES ($version)", ("$version", SchemaVersion));
                transaction.Commit();
            }

            try
            {
                File.Move(temp, FilePath, false);
            }
            catch (IOException) when (File.Exists(FilePath))
            {
                // Another process created it first: use that one.
            }
        }
        finally
        {
            foreach (string leftover in new[] { temp, temp + "-wal", temp + "-shm" })
            {
                try
                {
                    File.Delete(leftover);
                }
                catch (Exception failure) when (failure is IOException or UnauthorizedAccessException)
                {
                    // A stray temporary file is harmless.
                }
            }
        }
    }

    /// <summary>The lock file of the creation gate: one for the store folder, named for state.db whichever database file in the folder is being made (a recovery makes its new database under a temporary name; that must not leave a lock file of its own). It is coordination metadata (it holds nothing), lives in the same protected store folder and is never deleted or replaced.</summary>
    private string GatePath => Path.Combine(Folder, FileName + ".lock");

    /// <summary>
    /// The creation gate: an exclusive lock, held by the operating system for as long as the returned stream is open, that serializes the first creation of state.db between independent processes (and threads). The lock file is
    /// made once and never removed or replaced: a lock on a file that is unlinked while locked protects nothing, because the next process would make a new file at the same path and lock that one. The lock is a share-none open:
    /// on Linux and macOS .NET takes flock(LOCK_EX) on the one file; on Windows it is the file's share mode. Either way the operating system releases it when the process ends, however it ends, so a crashed creator never blocks
    /// the next. The gate is waited for as long as the busy timeout. What cannot be trusted is refused, not worked around: a lock file that is a link, is not a regular file, is not this user's, or is open to others (Unix),
    /// and a lock that does not exclude (a file system or setting without locking: a second exclusive open of the file must be refused).
    /// </summary>
    private FileStream AcquireCreationGate()
    {
        Directory.CreateDirectory(Folder);
        DateTime deadline = DateTime.UtcNow + _busyTimeout;
        string lastBusy = "";
        while (true)
        {
            CheckGateFile();
            FileStream? stream = null;
            try
            {
                stream = OpenGate();
                if (OpenGateOrNull() is { } intruder)
                {
                    // A second exclusive open of the same file was allowed: this lock excludes nobody, so it must not be used as one.
                    intruder.Dispose();
                    throw new StateDatabaseException($"{FileLabel} cannot be created safely: the lock file {GatePath} does not exclude other processes on this file system (file locking is off or not supported there)");
                }

                CheckGateFile();

                return stream;
            }
            catch (IOException busy)
            {
                stream?.Dispose();
                lastBusy = busy.Message;
                if (DateTime.UtcNow >= deadline)
                {
                    throw new StateDatabaseException($"{FileLabel} cannot be created: another process holds the creation lock {GatePath} ({lastBusy}). Nothing was changed; run again once the other with-secrets command has finished.", busy);
                }

                Thread.Sleep(5);
            }
            catch
            {
                stream?.Dispose();
                throw;
            }
        }
    }

    private FileStream OpenGate()
    {
        FileStreamOptions options = new()
        {
            Mode = FileMode.OpenOrCreate,
            Access = FileAccess.ReadWrite,
            Share = FileShare.None,
            BufferSize = 1,
        };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        return new FileStream(GatePath, options);
    }
    /// <summary>A second exclusive open of the lock file while it is held: null when it is refused (what a working lock does).</summary>
    private FileStream? OpenGateOrNull()
    {
        try
        {
            return OpenGate();
        }
        catch (IOException)
        {
            return null;
        }
    }

    /// <summary>On Linux and macOS the lock file, when there is one, is a regular file of this user that nobody else can open. Throws otherwise (the file is not touched).</summary>
    private void CheckGateFile()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        if (!File.Exists(GatePath) && !Directory.Exists(GatePath) && new FileInfo(GatePath).LinkTarget is null)
        {
            return;
        }

        UnixFileInfo? info = UnixFileInfo.Of(GatePath);
        if (info is null || !info.IsRegularFile || info.Owner != UnixSocketEndpoint.EffectiveUserId() || (info.Permissions & 0x3F) != 0)
        {
            throw new StateDatabaseException($"{FileLabel} cannot be created safely: the lock file {GatePath} is not a regular file of this user that only this user can open, so it is not used (it is not changed either)");
        }
    }

    /// <summary>For tests: takes the creation gate and holds it until the returned object is disposed (or the process ends).</summary>
    internal IDisposable HoldCreationGateForTests() => AcquireCreationGate();
    private SqliteConnection Connect(string path, SqliteOpenMode mode)
    {
        return new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = mode,
            // No pool: every connection really closes, so the files are released and WAL is checkpointed at the end.
            Pooling = false,
            DefaultTimeout = Math.Max(1, (int)Math.Ceiling(_busyTimeout.TotalSeconds)),
        }.ToString());
    }
}

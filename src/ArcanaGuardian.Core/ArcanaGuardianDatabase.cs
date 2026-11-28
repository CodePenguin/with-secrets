using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.CompilerServices;

using Microsoft.Data.Sqlite;

namespace ArcanaGuardian;

public sealed class ArcanaGuardianDatabaseException(string message, Exception? inner = null) : Exception(message, inner)
{
    internal bool InvalidLayout { get; init; }
}

/// <summary>Owns SQLite connections, creation and write transactions for one machine database.</summary>
public sealed partial class ArcanaGuardianDatabase
{
    public const string FileName = "arcana-guardian.db";
    public const int SchemaVersion = 4;
    public static readonly TimeSpan DefaultBusyTimeout = TimeSpan.FromSeconds(5);
    internal static readonly string[] OldFiles = ["state.db", "authority.db", "audit-outbox.db"];

    private static readonly ConcurrentDictionary<string, Writer> Writers = new(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
    private static readonly ConditionalWeakTable<SqliteTransaction, List<Action>> CommitActions = new();
    private static readonly Lazy<Dictionary<string, (string Type, string Sql)>> ExpectedLayout = new(() =>
    {
        using SqliteConnection connection = new("Data Source=:memory:;Pooling=False");
        connection.Open();
        Execute(connection, null, Schema);
        return Layout(connection, null);
    });

    private sealed class Writer
    {
        private readonly object _gate = new();
        private readonly LinkedList<int> _waiting = new();
        private int _owner;

        public bool Enter(long start, TimeSpan timeout)
        {
            lock (_gate)
            {
                int thread = Environment.CurrentManagedThreadId;
                if (_owner == thread)
                {
                    throw new InvalidOperationException("a write to arcana-guardian.db inside another write: pass the transaction instead");
                }

                if (_owner == 0 && _waiting.Count == 0)
                {
                    _owner = thread;
                    return true;
                }

                // A writer that immediately starts another write must queue behind those already waiting.
                LinkedListNode<int> waiter = _waiting.AddLast(thread);
                try
                {
                    while (timeout - Stopwatch.GetElapsedTime(start) is { Ticks: > 0 } left)
                    {
                        if (_owner == 0 && _waiting.First == waiter)
                        {
                            _owner = thread;
                            return true;
                        }

                        Monitor.Wait(_gate, left);
                    }

                    return false;
                }
                finally
                {
                    _waiting.Remove(waiter);
                    if (_owner == 0) Monitor.PulseAll(_gate);
                }
            }
        }

        public void Exit()
        {
            lock (_gate)
            {
                _owner = 0;
                Monitor.PulseAll(_gate);
            }
        }
    }

    private readonly TimeSpan _busyTimeout;
    private int _checked;

    public ArcanaGuardianDatabase(string path) : this(path, DefaultBusyTimeout)
    {
    }

    internal ArcanaGuardianDatabase(string path, TimeSpan busyTimeout)
    {
        FilePath = Path.GetFullPath(path);
        _busyTimeout = busyTimeout;
    }

    public static ArcanaGuardianDatabase InFolder(string folder) => new(Path.Combine(folder, FileName));

    public string FilePath { get; }
    public string FileLabel => Path.GetFileName(FilePath);
    private string Folder => Path.GetDirectoryName(FilePath)!;
    internal static IReadOnlyList<string> Tables => TableNames.Value;
    private static readonly Lazy<IReadOnlyList<string>> TableNames = new(() => [.. ExpectedLayout.Value
        .Where(item => item.Value.Type == "table").Select(item => item.Key).Order(StringComparer.Ordinal)]);
    internal Func<int, SqliteException?>? BeginFault { get; init; }
    internal Func<int, SqliteException?>? OpenFault { get; init; }
    internal Func<FileStream>? SecondGateOpen { get; set; }

    internal T Read<T>(Func<SqliteConnection?, T> work) => Use(() =>
    {
        using SqliteConnection? connection = Open(create: false);
        return work(connection);
    });

    internal static void AfterCommit(SqliteTransaction transaction, Action action) => CommitActions.GetOrCreateValue(transaction).Add(action);

    internal T Write<T>(Func<SqliteConnection, SqliteTransaction, T> work)
    {
        (T result, List<Action>? actions) = WithWriter(start => WriteInGate(work, start));
        if (actions is not null)
        {
            foreach (Action action in actions)
            {
                try
                {
                    action();
                }
                catch (Exception error) when (error is not OutOfMemoryException)
                {
                    AppLog.Warn("a post-commit notification failed ({Type})", error.GetType().Name);
                }
            }
        }
        return result;
    }

    // One deadline for acquiring the write transaction. Opening and BEGIN return lock errors immediately so only this loop retries them.
    private (T, List<Action>?) WriteInGate<T>(Func<SqliteConnection, SqliteTransaction, T> work, long start)
    {
        TimeSpan pause = TimeSpan.FromMilliseconds(10);
        for (int attempt = 0; ; attempt++)
        {
            SqliteConnection? connection = null;
            SqliteTransaction transaction;
            try
            {
                if (OpenFault?.Invoke(attempt) is { } openFault)
                {
                    throw openFault;
                }

                connection = Open(create: true, start)!;
                if (BeginFault?.Invoke(attempt) is { } fault)
                {
                    throw fault;
                }

                _ = BusyBudget(start);
                transaction = connection.BeginTransaction(deferred: false);
            }
            catch (SqliteException error) when (IsBusy(error))
            {
                connection?.Dispose();
                TimeSpan left = Left(start);
                if (left <= TimeSpan.Zero)
                {
                    throw Busy(error);
                }

                Thread.Sleep(pause < left ? pause : left);
                pause = TimeSpan.FromMilliseconds(Math.Min(pause.TotalMilliseconds * 2, 250));
                if (Left(start) <= TimeSpan.Zero)
                {
                    throw Busy(error);
                }

                continue;
            }
            catch
            {
                connection?.Dispose();
                throw;
            }

            using (connection)
            using (transaction)
            {
                try
                {
                    SetBusyTimeout(connection, transaction, _busyTimeout);
                    T result = work(connection, transaction);
                    transaction.Commit();
                    return (result, CommitActions.TryGetValue(transaction, out List<Action>? actions) ? actions : null);
                }
                finally
                {
                    CommitActions.Remove(transaction);
                }
            }
        }
    }

    private TimeSpan Left(long start) => _busyTimeout - Stopwatch.GetElapsedTime(start);

    private TimeSpan BusyBudget(long? start)
    {
        TimeSpan left = start is { } began ? Left(began) : _busyTimeout;
        return left > TimeSpan.Zero ? left : throw Busy();
    }

    internal void CopyTo(string path)
    {
        string target = Path.GetFullPath(path);
        WithWriter(_ =>
        {
            if (File.Exists(target))
            {
                throw new ArcanaGuardianDatabaseException("the database copy destination already exists");
            }

            using SqliteConnection connection = Open(create: false) ?? throw new ArcanaGuardianDatabaseException($"{FileLabel} does not exist");
            string temp = target + "." + Guid.NewGuid().ToString("N") + ".new";
            try
            {
                Execute(connection, null, "VACUUM INTO $path", ("$path", temp));
                File.Move(temp, target, overwrite: false);
            }
            finally
            {
                DeleteTemporaryFiles(temp);
            }

            return 0;
        });
    }

    /// <summary>Runs <paramref name="work" /> holding this file's in-process write gate; it is given the time the wait began, so the gate and the work share one deadline.</summary>
    private T WithWriter<T>(Func<long, T> work)
    {
        long start = Stopwatch.GetTimestamp();
        Writer writer = Writers.GetOrAdd(FilePath, static _ => new Writer());
        if (!writer.Enter(start, _busyTimeout))
        {
            throw Busy();
        }

        try
        {
            return Use(() => work(start));
        }
        finally
        {
            writer.Exit();
        }
    }

    private T Use<T>(Func<T> work)
    {
        try
        {
            return work();
        }
        catch (SqliteException error) when (IsBusy(error))
        {
            throw Busy(error);
        }
        catch (SqliteException error) when (error.SqliteErrorCode is 11 or 26)
        {
            throw Damaged(error.Message, error);
        }
        catch (Exception error) when (error is SqliteException or IOException or UnauthorizedAccessException)
        {
            throw new ArcanaGuardianDatabaseException($"cannot access {FileLabel}: {error.Message}", error);
        }
    }

    private static bool IsBusy(SqliteException error) => error.SqliteErrorCode is 5 or 6 or 15;
    private ArcanaGuardianDatabaseException Busy(Exception? inner = null) => new($"{FileLabel} is locked by another process; try again", inner);
    private ArcanaGuardianDatabaseException Damaged(string problem, Exception? inner = null) => new($"{FileLabel} is damaged ({problem}); delete {FileLabel} to start over", inner);

    private void RejectOldFiles()
    {
        string[] old = [.. OldFiles.Where(name => File.Exists(Path.Combine(Folder, name)))];
        if (old.Length > 0)
        {
            throw new ArcanaGuardianDatabaseException($"{Folder} still holds {string.Join(", ", old)} from an earlier version of Arcana Guardian; delete it to start over (nothing is moved over)");
        }
    }

    private SqliteConnection? Open(bool create, long? start = null)
    {
        RejectOldFiles();
        if (Directory.Exists(FilePath))
        {
            throw new ArcanaGuardianDatabaseException($"{FileLabel} is a directory; it cannot be opened as a database");
        }
        if (!File.Exists(FilePath))
        {
            if (!create)
            {
                return null;
            }
            Create(start);
        }

        SqliteConnection connection = Connect(FilePath, SqliteOpenMode.ReadWrite);
        try
        {
            Configure(connection, start);
            bool checking = Volatile.Read(ref _checked) == 0;
            if (checking)
            {
                string? check = Scalar(connection, null, "PRAGMA quick_check") as string;
                if (check != "ok")
                {
                    throw Damaged(check ?? "no result");
                }
                CheckVersion(connection);
                using SqliteTransaction snapshot = connection.BeginTransaction(deferred: true);
                if (LayoutProblem(connection, snapshot) is { } problem)
                {
                    throw new ArcanaGuardianDatabaseException($"{FileLabel} holds tables that are not those of Arcana Guardian ({problem}); delete {FileLabel} to start over")
                    {
                        InvalidLayout = true,
                    };
                }
            }

            EnsureWal(connection);
            if (checking)
            {
                UpgradeLayout(connection);
                Volatile.Write(ref _checked, 1);
            }
            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    private static void UpgradeLayout(SqliteConnection connection)
    {
        if (Scalar(connection, null, "PRAGMA user_version") is >= 2L)
        {
            return;
        }

        using SqliteTransaction transaction = connection.BeginTransaction();
        // A simultaneous opener may have upgraded while this connection was waiting for the writer.
        if (Scalar(connection, transaction, "PRAGMA user_version") is 0L)
        {
            Execute(connection, transaction, "PRAGMA secure_delete = ON");
            Execute(connection, transaction, "UPDATE provider_instances SET max_stale_seconds = 0 WHERE max_stale_seconds <> 0");
            Execute(connection, transaction, "DELETE FROM provider_cache");
        }
        if (Scalar(connection, transaction, "PRAGMA user_version") is < 2L)
        {
            if (!Layout(connection, transaction).ContainsKey("secret_writes"))
            {
                Execute(connection, transaction, SecretWritesSchema);
            }
            Execute(connection, transaction, "PRAGMA user_version = 2");
        }
        transaction.Commit();
    }

    private void CheckVersion(SqliteConnection connection)
    {
        if (Scalar(connection, null, "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = 'schema_version'") is 1L)
        {
            using SqliteCommand command = Command(connection, null, "SELECT * FROM schema_version");
            using SqliteDataReader rows = command.ExecuteReader();
            if (rows.FieldCount == 1 && rows.GetName(0) == "version" && rows.Read()
                && rows.GetValue(0) is long version && version == SchemaVersion && !rows.Read())
            {
                return;
            }
        }
        throw new ArcanaGuardianDatabaseException($"{FileLabel} is not of schema version {SchemaVersion}; delete {FileLabel} to start over");
    }

    private void Create(long? start)
    {
        using FileStream gate = AcquireCreationGate(Folder, FileName, FileLabel, BusyBudget(start), SecondGateOpen);
        RejectOldFiles();
        if (File.Exists(FilePath))
        {
            return;
        }

        File.Delete(FilePath + "-wal");
        File.Delete(FilePath + "-shm");
        string temp = FilePath + "." + Guid.NewGuid().ToString("N") + ".new";
        try
        {
            using (SqliteConnection connection = Connect(temp, SqliteOpenMode.ReadWriteCreate))
            {
                Configure(connection, start);
                EnsureWal(connection);
                using SqliteTransaction transaction = connection.BeginTransaction();
                Execute(connection, transaction, Schema);
                Execute(connection, transaction, "PRAGMA user_version = 2");
                Execute(connection, transaction, "INSERT INTO schema_version (version) VALUES ($version)", ("$version", SchemaVersion));
                Execute(connection, transaction, "INSERT INTO outbox_counter (id, last_sequence, epoch, machine) VALUES (1, 0, $epoch, '')",
                    ("$epoch", Guid.NewGuid().ToString("N")));
                transaction.Commit();
            }
            File.Move(temp, FilePath, overwrite: false);
        }
        finally
        {
            DeleteTemporaryFiles(temp);
        }
    }

    private static void DeleteTemporaryFiles(string temp)
    {
        foreach (string file in new[] { temp, temp + "-wal", temp + "-shm" })
        {
            try
            {
                File.Delete(file);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                // The temporary file has a unique name and will not be opened as the database.
            }
        }
    }

    private SqliteConnection Connect(string path, SqliteOpenMode mode) => new(new SqliteConnectionStringBuilder
    {
        DataSource = path,
        Mode = mode,
        Pooling = false,
        ForeignKeys = true,
    }.ToString());

    private void Configure(SqliteConnection connection, long? start)
    {
        _ = BusyBudget(start);
        // Microsoft.Data.Sqlite retries both prepare and step separately. A negative DefaultTimeout in the pinned driver
        // returns the first busy result. Disable SQLite's own busy handler too, so the write deadline is enforced in one place.
        connection.DefaultTimeout = start is null ? DriverTimeout(_busyTimeout) : -1;
        connection.Open();
        if (start is null)
        {
            SetBusyTimeout(connection, null, _busyTimeout);
        }
        else
        {
            Execute(connection, null, "PRAGMA busy_timeout = 0");
        }
        Execute(connection, null, "PRAGMA synchronous = FULL");
    }

    private static void SetBusyTimeout(SqliteConnection connection, SqliteTransaction? transaction, TimeSpan busy)
    {
        connection.DefaultTimeout = DriverTimeout(busy);
        Execute(connection, transaction, "PRAGMA busy_timeout = " + Math.Ceiling(busy.TotalMilliseconds).ToString(CultureInfo.InvariantCulture));
    }

    private static int DriverTimeout(TimeSpan busy) => Math.Max(1, (int)busy.TotalSeconds);

    private void EnsureWal(SqliteConnection connection)
    {
        if (Scalar(connection, null, "PRAGMA journal_mode") is not "wal" && Scalar(connection, null, "PRAGMA journal_mode = WAL") is not "wal")
        {
            throw new ArcanaGuardianDatabaseException($"{FileLabel} could not open in WAL mode");
        }
    }

    internal static string? LayoutProblem(SqliteConnection connection, SqliteTransaction? transaction)
    {
        Dictionary<string, (string Type, string Sql)> found = Layout(connection, transaction);
        foreach ((string name, (string Type, string Sql) definition) in ExpectedLayout.Value)
        {
            if (!found.Remove(name, out var actual))
            {
                if (name == "secret_writes" && Scalar(connection, transaction, "PRAGMA user_version") is < 2L)
                {
                    continue;
                }

                return $"missing {definition.Type} {name}";
            }
            if (actual != definition)
            {
                return $"unexpected definition of {definition.Type} {name}";
            }
        }
        return found.Count == 0 ? null : $"unexpected database object {found.Keys.First()}";
    }

    private static Dictionary<string, (string Type, string Sql)> Layout(SqliteConnection connection, SqliteTransaction? transaction)
    {
        using SqliteCommand command = Command(connection, transaction,
            "SELECT name, type, sql FROM sqlite_schema WHERE name <> 'sqlite_sequence' AND sql IS NOT NULL ORDER BY name");
        using SqliteDataReader rows = command.ExecuteReader();
        Dictionary<string, (string, string)> result = new(StringComparer.Ordinal);
        while (rows.Read())
        {
            result.Add(rows.GetString(0), (rows.GetString(1), rows.GetString(2).Replace("\r\n", "\n", StringComparison.Ordinal)));
        }
        return result;
    }

    internal IDisposable HoldCreationGateForTests() => AcquireCreationGate(Folder, FileName, FileLabel, _busyTimeout, SecondGateOpen);
}

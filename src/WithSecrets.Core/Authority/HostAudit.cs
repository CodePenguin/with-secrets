using System.Globalization;

using Microsoft.Data.Sqlite;

namespace WithSecrets;

/// <summary>The host's audit outbox cannot be used: unreadable, locked past the timeout, full, damaged or of another schema version.</summary>
public sealed class AuditOutboxException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// The host-local audit outbox: <c>audit-outbox.db</c> in the store folder (SQLite, WAL, <c>synchronous=FULL</c>, schema version 2). An event is numbered, signed by the
/// machine identity key and committed in ONE write transaction, so the per-machine sequence is monotonic and gapless (a failed append consumes no number), and a commit
/// that returned is on disk. Events stay until the authority acknowledges them; only then are they removed. No secret value, no environment value and no OS user is stored.
/// A file of another schema version, or a damaged one, is never repaired: delete it to start over (the sequence then restarts at 1 under a new epoch, which the authority records).
/// </summary>
public sealed class HostAuditOutbox(string path, ISigningKey machineKey, TimeProvider? clock = null)
{
    public const string FileName = "audit-outbox.db";
    public const int SchemaVersion = 2;
    public static readonly TimeSpan BusyTimeout = TimeSpan.FromSeconds(5);

    private const string Schema = """
        CREATE TABLE schema_version (version INTEGER NOT NULL);
        CREATE TABLE counter (id INTEGER PRIMARY KEY CHECK (id = 1), last_sequence INTEGER NOT NULL, epoch TEXT NOT NULL);
        INSERT INTO counter (id, last_sequence, epoch) VALUES (1, 0, $epoch);
        CREATE TABLE events (
            sequence INTEGER PRIMARY KEY NOT NULL, event_id TEXT NOT NULL UNIQUE, json TEXT NOT NULL, created TEXT NOT NULL,
            state TEXT NOT NULL, reason TEXT);
        """;

    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private int _checked;

    public string FilePath { get; } = Path.GetFullPath(path);

    public string FileLabel => Path.GetFileName(FilePath);

    public static HostAuditOutbox InFolder(string folder, ISigningKey machineKey, TimeProvider? clock = null) => new(Path.Combine(folder, FileName), machineKey, clock);

    /// <summary>For tests: called inside the append transaction at named points ("before-sign", "before-commit"); throwing from it must leave nothing behind.</summary>
    internal Action<string>? Fault { get; set; }

    /// <summary>
    /// Numbers, signs and durably commits one event. Throws <see cref="AuditOutboxException" /> when it could not be committed (nothing is then stored and no number is used).
    /// </summary>
    public AuditEvent Append(AuditFacts facts)
    {
        return Write((connection, transaction) =>
        {
            long next = Convert.ToInt64(StateDatabase.Scalar(connection, transaction, "SELECT last_sequence FROM counter WHERE id = 1"), CultureInfo.InvariantCulture) + 1;
            string epoch = (string)StateDatabase.Scalar(connection, transaction, "SELECT epoch FROM counter WHERE id = 1")!;
            Fault?.Invoke("before-sign");
            AuditEvent item = AuditEvent.Create(AuditRedaction.Bound(facts), Guid.NewGuid().ToString("D"), next, _clock.GetUtcNow(), machineKey, epoch);
            if (item.Problem() is { } problem)
            {
                // Nothing the authority would refuse is signed: the run that this records does not go ahead.
                throw new AuditOutboxException("the audit event is not valid: " + problem);
            }

            StateDatabase.Execute(connection, transaction, "INSERT INTO events (sequence, event_id, json, created, state, reason) VALUES ($seq, $id, $json, $now, 'pending', NULL)",
                ("$seq", next), ("$id", item.EventId), ("$json", item.ToJson()), ("$now", CanonicalJson.Time(_clock.GetUtcNow())));
            StateDatabase.Execute(connection, transaction, "UPDATE counter SET last_sequence = $seq WHERE id = 1", ("$seq", next));
            Fault?.Invoke("before-commit");

            return item;
        });
    }

    /// <summary>The events the authority has not acknowledged and has not rejected, oldest first. A stored row that cannot be read is marked rejected and skipped.</summary>
    public IReadOnlyList<AuditEvent> Pending(int limit)
    {
        List<long> unreadable = [];
        List<AuditEvent> events = Use(false, connection =>
        {
            Fault?.Invoke("pending");
            List<AuditEvent> found = [];
            if (connection is null)
            {
                return found;
            }

            using SqliteCommand command = StateDatabase.Command(connection, null, "SELECT sequence, json FROM events WHERE state = 'pending' ORDER BY sequence LIMIT $limit", ("$limit", limit));
            using SqliteDataReader reader = command.ExecuteReader();
            while (reader.Read())
            {
                if (AuditEvent.TryParse(reader.GetString(1), out AuditEvent? parsed, out _))
                {
                    found.Add(parsed!);
                }
                else
                {
                    unreadable.Add(reader.GetInt64(0));
                }
            }

            return found;
        });

        foreach (long sequence in unreadable)
        {
            Write((connection, transaction) => StateDatabase.Execute(connection, transaction, "UPDATE events SET state = 'rejected', reason = 'unreadable' WHERE sequence = $seq", ("$seq", sequence)));
        }

        return events;
    }

    /// <summary>The authority durably has these: removed from the outbox. Idempotent.</summary>
    public void Acknowledge(IEnumerable<string> eventIds)
    {
        List<string> ids = [.. eventIds];
        if (ids.Count == 0)
        {
            return;
        }

        Write((connection, transaction) =>
        {
            foreach (string id in ids)
            {
                StateDatabase.Execute(connection, transaction, "DELETE FROM events WHERE event_id = $id", ("$id", id));
            }

            Fault?.Invoke("after-acknowledge");

            return 0;
        });
    }

    /// <summary>The authority refused these for good (a bad signature, an event it cannot use): kept for the person to see, never sent again.</summary>
    public void Reject(IEnumerable<AuditAckEntry> entries)
    {
        List<AuditAckEntry> list = [.. entries];
        if (list.Count == 0)
        {
            return;
        }

        Write((connection, transaction) =>
        {
            foreach (AuditAckEntry entry in list)
            {
                StateDatabase.Execute(connection, transaction, "UPDATE events SET state = 'rejected', reason = $reason WHERE event_id = $id AND state = 'pending'", ("$id", entry.EventId), ("$reason", entry.Detail.Length > 200 ? entry.Detail[..200] : entry.Detail));
            }

            return 0;
        });
    }

    /// <summary>The number of events in the given state ("pending" or "rejected").</summary>
    public int Count(string state)
    {
        return Use(false, connection => connection is null ? 0 : Convert.ToInt32(StateDatabase.Scalar(connection, null, "SELECT COUNT(*) FROM events WHERE state = $state", ("$state", state)), CultureInfo.InvariantCulture));
    }

    /// <summary>The last sequence number used (0: none yet).</summary>
    public long LastSequence()
    {
        return Use(false, connection => connection is null ? 0L : Convert.ToInt64(StateDatabase.Scalar(connection, null, "SELECT last_sequence FROM counter WHERE id = 1"), CultureInfo.InvariantCulture));
    }

    // ---- plumbing ----

    private T Write<T>(Func<SqliteConnection, SqliteTransaction, T> work)
    {
        return Use(true, connection =>
        {
            using SqliteTransaction transaction = connection!.BeginTransaction(deferred: false);
            T result = work(connection, transaction);
            transaction.Commit();

            return result;
        });
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
            throw new AuditOutboxException(failure.SqliteErrorCode is 5 or 6 ? $"{FileLabel} is locked by another process" : failure.SqliteErrorCode is 13 ? $"{FileLabel} cannot grow: the disk is full" : $"cannot use {FileLabel}: {failure.Message}", failure);
        }
        catch (Exception failure) when (failure is IOException or UnauthorizedAccessException)
        {
            throw new AuditOutboxException($"cannot use {FileLabel}: {failure.Message}", failure);
        }
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
            StateDatabase.Execute(connection, null, "PRAGMA busy_timeout = " + (int)BusyTimeout.TotalMilliseconds);
            StateDatabase.Execute(connection, null, "PRAGMA synchronous = FULL");
            if (Volatile.Read(ref _checked) == 0 && StateDatabase.Scalar(connection, null, "PRAGMA quick_check") is not "ok")
            {
                throw new AuditOutboxException($"{FileLabel} is damaged; delete {FileLabel} to start over");
            }

            long found;
            try
            {
                found = Convert.ToInt64(StateDatabase.Scalar(connection, null, "SELECT version FROM schema_version"), CultureInfo.InvariantCulture);
            }
            catch (SqliteException)
            {
                found = -1;
            }

            if (found != SchemaVersion)
            {
                throw new AuditOutboxException($"{FileLabel} is not of schema version {SchemaVersion}; delete {FileLabel} to start over");
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

    private void Create()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        string temp = FilePath + "." + Guid.NewGuid().ToString("N") + ".new";
        try
        {
            using (SqliteConnection connection = Connect(temp, SqliteOpenMode.ReadWriteCreate))
            {
                connection.Open();
                StateDatabase.Execute(connection, null, "PRAGMA journal_mode = WAL");
                using SqliteTransaction transaction = connection.BeginTransaction(deferred: false);
                StateDatabase.Execute(connection, transaction, Schema, ("$epoch", Guid.NewGuid().ToString("N")));
                StateDatabase.Execute(connection, transaction, "INSERT INTO schema_version (version) VALUES ($version)", ("$version", SchemaVersion));
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

    private static SqliteConnection Connect(string file, SqliteOpenMode mode)
    {
        return new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = file,
            Mode = mode,
            Pooling = false,
            DefaultTimeout = Math.Max(1, (int)Math.Ceiling(BusyTimeout.TotalSeconds)),
        }.ToString());
    }
}

/// <summary>What a run records. <see cref="TryRecord" /> is true only when the event is signed and durably committed.</summary>
public interface IHostAudit
{
    bool TryRecord(AuditFacts facts);
}

/// <summary>What one drain of the outbox came to.</summary>
public sealed record AuditUploadResult(int Acknowledged, int Rejected, bool Failed);

/// <summary>
/// Sends the outbox to the authority and removes what the authority acknowledges. It never blocks a launch (nothing in a launch waits for it) and gives up on nothing:
/// every failure (the authority unreachable, an answer that does not verify, a database error) leaves the events where they are for the next try.
/// </summary>
public sealed class AuditUploader(HostAuditOutbox outbox, Func<IAuditSink> sink, Func<AuditAck, string, string, CancellationToken, Task<string?>> verify, string machineFingerprint, int batchSize = 50)
{
    /// <summary>Sends everything that is pending, batch by batch, until none is left or something fails.</summary>
    public async Task<AuditUploadResult> DrainAsync(CancellationToken cancel = default)
    {
        int acknowledged = 0;
        int rejected = 0;
        while (true)
        {
            IReadOnlyList<AuditEvent> pending;
            try
            {
                pending = outbox.Pending(batchSize);
            }
            catch (Exception error) when (error is not (OutOfMemoryException or OperationCanceledException))
            {
                AppLog.Warn("the audit outbox could not be read for upload: {Type}", error.GetType().Name);

                return new AuditUploadResult(acknowledged, rejected, true);
            }

            if (pending.Count == 0)
            {
                return new AuditUploadResult(acknowledged, rejected, false);
            }

            AuditBatch batch = new("ab-" + Guid.NewGuid().ToString("N"), machineFingerprint, pending);
            try
            {
                AuditAck ack = await sink().UploadAsync(batch, cancel);
                if (await verify(ack, batch.BatchId, batch.Digest(), cancel) is { } problem)
                {
                    AppLog.Warn("an audit acknowledgement did not verify: {Problem}", problem);

                    return new AuditUploadResult(acknowledged, rejected, true);
                }

                HashSet<string> sent = [.. pending.Select(item => item.EventId)];
                List<string> done = [.. ack.Entries.Where(entry => sent.Contains(entry.EventId) && AuditStatus.Done(entry.Status)).Select(entry => entry.EventId).Distinct()];
                List<AuditAckEntry> refused = [.. ack.Entries.Where(entry => sent.Contains(entry.EventId) && AuditStatus.Permanent(entry))];
                outbox.Acknowledge(done);
                outbox.Reject(refused);
                acknowledged += done.Count;
                rejected += refused.Count;
                if (done.Count + refused.Count == 0)
                {
                    // The authority took nothing for good from this batch (or only refused it for now, e.g. the machine is not enrolled yet): stop, so that it is not repeated in a tight loop.
                    return new AuditUploadResult(acknowledged, rejected, true);
                }
            }
            catch (Exception error) when (error is not OutOfMemoryException)
            {
                if (error is not OperationCanceledException)
                {
                    AppLog.Warn("the audit upload failed: {Type}", error.GetType().Name);
                }

                return new AuditUploadResult(acknowledged, rejected, true);
            }
        }
    }
}

/// <summary>
/// The host's audit: the outbox, the uploader and the loop that runs it. <see cref="TryRecord" /> commits one event and wakes the uploader, and returns without waiting for it.
/// </summary>
public sealed class HostAudit(HostAuditOutbox outbox, AuditUploader uploader) : IHostAudit
{
    private readonly SemaphoreSlim _wake = new(0, 1);

    public HostAuditOutbox Outbox => outbox;

    public AuditUploader Uploader => uploader;

    public bool TryRecord(AuditFacts facts)
    {
        try
        {
            outbox.Append(facts);
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            // The type only: the message of a database error can name a path.
            AppLog.Warn("an audit event could not be committed: {Type}", error.GetType().Name);

            return false;
        }

        Wake();

        return true;
    }

    /// <summary>Asks the loop to upload now.</summary>
    public void Wake()
    {
        try
        {
            _wake.Release();
        }
        catch (SemaphoreFullException)
        {
            // Already asked.
        }
    }

    /// <summary>
    /// Uploads whenever woken, and every <paramref name="interval" /> otherwise; after a failure it waits longer (doubling, up to <paramref name="maxBackoff" />) and tries again,
    /// for as long as the service runs.
    /// </summary>
    public async Task RunAsync(TimeSpan interval, TimeSpan maxBackoff, CancellationToken stop)
    {
        TimeSpan delay = interval;
        try
        {
            while (!stop.IsCancellationRequested)
            {
                bool failed;
                try
                {
                    failed = (await uploader.DrainAsync(stop)).Failed;
                }
                catch (Exception error) when (error is not (OutOfMemoryException or OperationCanceledException))
                {
                    // Whatever went wrong, the loop goes on (the events are still in the outbox); the type only is logged.
                    AppLog.Warn("the audit upload loop met an error and will retry: {Type}", error.GetType().Name);
                    failed = true;
                }

                delay = failed ? TimeSpan.FromTicks(Math.Min(maxBackoff.Ticks, delay.Ticks * 2)) : interval;
                await _wake.WaitAsync(delay, stop);
            }
        }
        catch (OperationCanceledException)
        {
            // The service is stopping.
        }
    }
}

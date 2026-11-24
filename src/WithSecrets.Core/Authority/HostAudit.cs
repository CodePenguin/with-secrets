using System.Globalization;

using Microsoft.Data.Sqlite;

namespace WithSecrets;

/// <summary>The host's audit outbox cannot be used: unreadable, locked past the timeout, full, damaged or of another schema version.</summary>
public sealed class AuditOutboxException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// The host-local audit outbox: <c>with-secrets.db</c> (SQLite, WAL, <c>synchronous=FULL</c>). An event is numbered, signed by the
/// machine identity key and committed in ONE write transaction, so the per-machine sequence is monotonic and gapless (a failed append consumes no number), and a commit
/// that returned is on disk. Events stay until the authority acknowledges them; only then are they removed. No secret value, no environment value and no OS user is stored.
/// A file of another schema version, or a damaged one, is never repaired: delete it to start over (the sequence then restarts at 1 under a new epoch, which the authority records).
/// </summary>
public sealed class HostAuditOutbox(WithSecretsDatabase database, ISigningKey machineKey, TimeProvider? clock = null)
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly string _fingerprint = KeyIdentity.Fingerprint(machineKey.PublicKey);

    public string FilePath => database.FilePath;
    public string FileLabel => database.FileLabel;

    public static HostAuditOutbox InFolder(string folder, ISigningKey machineKey, TimeProvider? clock = null) => new(WithSecretsDatabase.InFolder(folder), machineKey, clock);

    /// <summary>For tests: called inside the append transaction at named points ("before-sign", "before-commit"); throwing from it must leave nothing behind.</summary>
    internal Action<string>? Fault { get; set; }

    /// <summary>
    /// Numbers, signs and durably commits one event. Throws <see cref="AuditOutboxException" /> when it could not be committed (nothing is then stored and no number is used).
    /// </summary>
    public AuditEvent Append(AuditFacts facts) => AppendAll([facts])[0];

    /// <summary>Numbers, signs and durably commits several events in ONE write transaction: all of them are committed, or none (and no number is used).</summary>
    public IReadOnlyList<AuditEvent> AppendAll(IReadOnlyList<AuditFacts> facts)
        => Write((connection, transaction) => AppendIn(connection, transaction, facts));

    internal IReadOnlyList<AuditEvent> AppendIn(SqliteConnection connection, SqliteTransaction transaction, IReadOnlyList<AuditFacts> facts)
    {
        if (facts.Count == 0)
        {
            return [];
        }

        // A best-effort caller may keep its own change if writing the event fails.
        const string savepoint = "append_audit";
        transaction.Save(savepoint);
        try
        {
            long next = (long)WithSecretsDatabase.Scalar(connection, transaction, "SELECT last_sequence FROM outbox_counter WHERE id = 1")!;
            string epoch = (string)WithSecretsDatabase.Scalar(connection, transaction, "SELECT epoch FROM outbox_counter WHERE id = 1")!;
            string machine = (string)WithSecretsDatabase.Scalar(connection, transaction, "SELECT machine FROM outbox_counter WHERE id = 1")!;
            if (machine.Length > 0 && machine != _fingerprint)
            {
                next = 0;
                epoch = Guid.NewGuid().ToString("N");
            }

            List<AuditEvent> items = [];
            foreach (AuditFacts one in facts)
            {
                Fault?.Invoke("before-sign");
                AuditEvent item = AuditEvent.Create(AuditRedaction.Bound(one), Guid.NewGuid().ToString("D"), ++next, _clock.GetUtcNow(), machineKey, epoch);
                if (item.Problem() is { } problem)
                {
                    throw new AuditOutboxException("the audit event is not valid: " + problem);
                }

                WithSecretsDatabase.Execute(connection, transaction, "INSERT INTO outbox_events (machine, sequence, event_id, json, created, state) VALUES ($machine, $seq, $id, $json, $now, 'pending')",
                    ("$machine", _fingerprint), ("$seq", next), ("$id", item.EventId), ("$json", item.ToJson()), ("$now", CanonicalJson.Time(_clock.GetUtcNow())));
                items.Add(item);
            }

            WithSecretsDatabase.Execute(connection, transaction, "UPDATE outbox_counter SET last_sequence = $seq, epoch = $epoch, machine = $machine WHERE id = 1",
                ("$seq", next), ("$epoch", epoch), ("$machine", _fingerprint));
            Fault?.Invoke("before-commit");
            transaction.Release(savepoint);
            return items;
        }
        catch
        {
            transaction.Rollback(savepoint);
            transaction.Release(savepoint);
            throw;
        }
    }

    /// <summary>The events the authority has not acknowledged and has not rejected, oldest first. A stored row that cannot be read is marked rejected and skipped.</summary>
    public IReadOnlyList<AuditEvent> Pending(int limit) => Pending(limit, null);

    internal IReadOnlyList<AuditEvent> Pending(int limit, string? machine)
    {
        List<long> unreadable = [];
        List<AuditEvent> events = Read(connection =>
        {
            Fault?.Invoke("pending");
            List<AuditEvent> found = [];
            if (connection is null)
            {
                return found;
            }

            string filter = machine is null ? "" : " AND machine = $machine";
            using SqliteCommand command = WithSecretsDatabase.Command(connection, null,
                "SELECT id, json FROM outbox_events WHERE state = 'pending'" + filter + " ORDER BY id LIMIT $limit", ("$limit", limit));
            if (machine is not null)
            {
                command.Parameters.AddWithValue("$machine", machine);
            }
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
            Write((connection, transaction) => WithSecretsDatabase.Execute(connection, transaction, "UPDATE outbox_events SET state = 'rejected', reason = 'unreadable' WHERE id = $id AND state = 'pending'", ("$id", sequence)));
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
                WithSecretsDatabase.Execute(connection, transaction, "DELETE FROM outbox_events WHERE event_id = $id", ("$id", id));
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
                WithSecretsDatabase.Execute(connection, transaction, "UPDATE outbox_events SET state = 'rejected', reason = $reason WHERE event_id = $id AND state = 'pending'", ("$id", entry.EventId), ("$reason", entry.Detail.Length > 200 ? entry.Detail[..200] : entry.Detail));
            }

            return 0;
        });
    }

    /// <summary>The reason kept with the events of another machine (a restore onto this one) when the uploader passes them over.</summary>
    public const string OtherMachineReason = "signed by another machine";

    /// <summary>
    /// Marks every pending event signed by another machine than <paramref name="machine" /> rejected: only that machine could upload it, so it is kept for the person
    /// to see and never sent. Returns how many.
    /// </summary>
    public int RejectOtherMachines(string machine)
    {
        return Write((connection, transaction) => WithSecretsDatabase.Execute(connection, transaction,
            "UPDATE outbox_events SET state = 'rejected', reason = $reason WHERE state = 'pending' AND machine <> $machine", ("$reason", OtherMachineReason), ("$machine", machine)));
    }

    /// <summary>The number of events in the given state ("pending" or "rejected").</summary>
    public int Count(string state)
    {
        return Read(connection => connection is null ? 0 : Convert.ToInt32(WithSecretsDatabase.Scalar(connection, null, "SELECT COUNT(*) FROM outbox_events WHERE state = $state", ("$state", state)), CultureInfo.InvariantCulture));
    }

    /// <summary>The last sequence number used (0: none yet).</summary>
    public long LastSequence()
    {
        return Read(connection => connection is null ? 0L : Convert.ToInt64(WithSecretsDatabase.Scalar(connection, null, "SELECT last_sequence FROM outbox_counter WHERE id = 1"), CultureInfo.InvariantCulture));
    }

    private T Read<T>(Func<SqliteConnection?, T> work) => Use(() => database.Read(work));
    private T Write<T>(Func<SqliteConnection, SqliteTransaction, T> work) => Use(() => database.Write(work));

    private T Use<T>(Func<T> work)
    {
        try
        {
            return work();
        }
        catch (WithSecretsDatabaseException error)
        {
            string detail = error.InnerException is SqliteException { SqliteErrorCode: 13 }
                ? $"{FileLabel} cannot grow: the disk is full" : error.Message;
            throw new AuditOutboxException(detail, error);
        }
    }
}

/// <summary>What a run records. <see cref="TryRecord" /> is true only when the event is signed and durably committed.</summary>
public interface IHostAudit
{
    bool TryRecord(AuditFacts facts);
    void RecordIn(SqliteConnection connection, SqliteTransaction transaction, AuditFacts facts);
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
        int rejected;
        try
        {
            // A restored database can hold another machine's signed events. The upload session authenticates only this machine, so those can never
            // be sent from here: they are rejected (kept for the person to see), not left pending for ever.
            rejected = outbox.RejectOtherMachines(machineFingerprint);
        }
        catch (Exception error) when (error is not (OutOfMemoryException or OperationCanceledException))
        {
            AppLog.Warn("the audit outbox could not be read for upload: {Type}", error.GetType().Name);

            return new AuditUploadResult(0, 0, true);
        }

        while (true)
        {
            IReadOnlyList<AuditEvent> pending;
            try
            {
                pending = outbox.Pending(batchSize, machineFingerprint);
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

    public void RecordIn(SqliteConnection connection, SqliteTransaction transaction, AuditFacts facts)
    {
        outbox.AppendIn(connection, transaction, [facts]);
        WithSecretsDatabase.AfterCommit(transaction, Wake);
    }

    internal static bool TryRecordIn(IHostAudit audit, SqliteConnection connection, SqliteTransaction transaction, AuditFacts facts)
    {
        try
        {
            audit.RecordIn(connection, transaction, facts);
            return true;
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            AppLog.Warn("an audit event could not be recorded ({Type})", error.GetType().Name);
            return false;
        }
    }

    /// <summary>Commits the events in one transaction (all or none) and wakes the uploader. Throws when they could not be committed, so the caller fails closed.</summary>
    public void RecordAll(IReadOnlyList<AuditFacts> facts)
    {
        outbox.AppendAll(facts);
        Wake();
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

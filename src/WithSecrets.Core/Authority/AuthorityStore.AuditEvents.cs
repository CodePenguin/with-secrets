using System.Globalization;
using System.Text;

using Microsoft.Data.Sqlite;

namespace WithSecrets;

/// <summary>
/// The authority's side of the audit trail (schema 4 of <c>with-secrets.db</c>): signed events the hosts uploaded, the per-machine sequence state, the gaps it found, and the
/// retention setting. An upload is one transaction: every event is checked (the machine's signature, the shape, a known id) and stored, and the sequence state moves, or nothing
/// changes; the acknowledgement is signed only after the commit. A hole in a machine's sequence, or a number used twice, is recorded and never a reason to refuse an event.
/// Retention is the authority's setting; it removes only events that are acknowledged (every stored event is, because it is acknowledged in the commit that stores it).
/// </summary>
public sealed partial class AuthorityStore
{
    /// <summary>A year, until the authority's administrator sets another (provisional; 0 means keep everything).</summary>
    public const int DefaultAuditRetentionDays = 365;

    public const int MaxAuditRetentionDays = 36500;

    /// <summary>The most events one upload is processed for; the host sends the rest in the next batch.</summary>
    public const int MaxAuditBatch = 200;

    private const string RetentionSetting = "audit_retention_days";

    // ---- retention ----

    /// <summary>How many days the authority keeps audit events (0: forever).</summary>
    public int AuditRetentionDays()
    {
        return Read(connection => connection is null ? DefaultAuditRetentionDays : ReadRetention(connection, null));
    }

    /// <summary>The operation name and parameters an authorization for <see cref="SetAuditRetentionDays" /> must carry.</summary>
    public static (string Operation, IReadOnlyList<(string Name, string Value)> Parameters) RetentionOperation(int days) => ("set-audit-retention", [("days", days.ToString(CultureInfo.InvariantCulture))]);

    /// <summary>Sets the retention (0 keeps everything); recorded in the authority's own audit history. A security setting: it needs the administrator's fresh passkey authorization of exactly this change.</summary>
    public void SetAuditRetentionDays(int days, VerifiedAdmin admin)
    {
        if (days is < 0 or > MaxAuditRetentionDays)
        {
            throw new ArgumentOutOfRangeException(nameof(days), "retention is 0 to " + MaxAuditRetentionDays + " days");
        }

        (string operation, IReadOnlyList<(string Name, string Value)> parameters) = RetentionOperation(days);
        if (!admin.Consume(operation, AdminAuthorizer.Canonical(parameters)))
        {
            throw new UnauthorizedAccessException("the retention change was not authorized by a fresh administrator passkey tap for exactly this change");
        }

        string actor = admin.Actor;

        Write((connection, transaction) =>
        {
            int before = ReadRetention(connection, transaction);
            WithSecretsDatabase.Execute(connection, transaction, "INSERT INTO authority_settings (name, value) VALUES ($name, $value) ON CONFLICT(name) DO UPDATE SET value = $value",
                ("$name", RetentionSetting), ("$value", days.ToString(CultureInfo.InvariantCulture)));
            Audit(connection, transaction, "audit-retention-changed", null, null, actor, $"audit retention {before} to {days} days");

            return 0;
        });
    }

    private static int ReadRetention(SqliteConnection connection, SqliteTransaction? transaction)
    {
        object? stored = WithSecretsDatabase.Scalar(connection, transaction, "SELECT value FROM authority_settings WHERE name = $name", ("$name", RetentionSetting));

        return stored is string text && int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out int days) && days <= MaxAuditRetentionDays ? days : DefaultAuditRetentionDays;
    }

    /// <summary>Removes the events received before the retention allows. Returns how many.</summary>
    public int PruneAuditEvents()
    {
        return Write((connection, transaction) =>
        {
            int removed = PruneAudit(connection, transaction);
            if (removed > 0)
            {
                Audit(connection, transaction, "audit-pruned", null, null, "authority", $"{removed} audit event(s) older than the retention removed");
            }

            return removed;
        });
    }

    private int PruneAudit(SqliteConnection connection, SqliteTransaction transaction)
    {
        int days = ReadRetention(connection, transaction);

        return days == 0 ? 0 : WithSecretsDatabase.Execute(connection, transaction, "DELETE FROM audit_events WHERE acknowledged IS NOT NULL AND received < $cutoff", ("$cutoff", Time(Now - TimeSpan.FromDays(days))));
    }

    // ---- upload ----

    /// <summary>
    /// Stores what the machine uploaded, in one transaction, and says what became of each event. Nothing here is a reason to throw away the rest: an event that does not verify
    /// is refused (<see cref="AuditStatus.Rejected" />), one already stored is a <see cref="AuditStatus.Duplicate" />, one older than the retention is
    /// <see cref="AuditStatus.Expired" />, and a hole in the machine's sequence is recorded as a gap.
    /// </summary>
    public IReadOnlyList<AuditAckEntry> RecordAuditEvents(AuditBatch batch)
    {
        return Write((connection, transaction) =>
        {
            MachineRecord? machine = Query(connection, transaction, "SELECT * FROM machines WHERE fingerprint = $fp", Machine, ("$fp", batch.MachineFingerprint)).FirstOrDefault();
            DateTimeOffset now = Now;
            string nowText = Time(now);
            int days = ReadRetention(connection, transaction);
            DateTimeOffset? cutoff = days > 0 ? now - TimeSpan.FromDays(days) : null;
            PruneAudit(connection, transaction);

            List<AuditAckEntry> entries = [];
            int accepted = 0;
            int expired = 0;
            long first = long.MaxValue;
            long last = 0;
            long expiredFirst = long.MaxValue;
            long expiredLast = 0;
            foreach (AuditEvent item in batch.Events.Take(MaxAuditBatch))
            {
                AuditAckEntry entry = RecordOne(connection, transaction, machine, item, cutoff, nowText);
                entries.Add(entry);
                if (entry.Status == AuditStatus.Accepted)
                {
                    accepted++;
                    first = Math.Min(first, item.Sequence);
                    last = Math.Max(last, item.Sequence);
                }
                else if (entry.Status == AuditStatus.Expired)
                {
                    expired++;
                    expiredFirst = Math.Min(expiredFirst, item.Sequence);
                    expiredLast = Math.Max(expiredLast, item.Sequence);
                }
            }

            Fault?.Invoke("after-audit-events");
            if (accepted > 0)
            {
                Audit(connection, transaction, "audit-events-received", batch.MachineFingerprint, batch.BatchId, "authority", $"{accepted} event(s), sequence {first} to {last}");
            }

            if (expired > 0)
            {
                // Acknowledged but not stored (older than the retention by the machine's own clock): the drop leaves this trace, so a machine with a wrong clock shows.
                Audit(connection, transaction, "audit-events-expired", batch.MachineFingerprint, batch.BatchId, "authority", $"{expired} event(s) dated before the retention, acknowledged without being stored, sequence {expiredFirst} to {expiredLast}");
            }

            Fault?.Invoke("before-commit");

            return entries;
        });
    }

    private AuditAckEntry RecordOne(SqliteConnection connection, SqliteTransaction transaction, MachineRecord? machine, AuditEvent item, DateTimeOffset? cutoff, string nowText)
    {
        AuditAckEntry Refuse(string detail) => new(item.EventId, AuditStatus.Rejected, detail);

        if (machine is null)
        {
            return Refuse(AuditStatus.UnknownMachine);
        }

        if (!string.Equals(item.MachineFingerprint, machine.Fingerprint, StringComparison.Ordinal))
        {
            return Refuse("other-machine");
        }

        if (item.Problem() is { } shape)
        {
            return Refuse("invalid-event: " + shape);
        }

        if (!item.Verify(machine.PublicKey))
        {
            return Refuse("bad-signature");
        }

        if (WithSecretsDatabase.Scalar(connection, transaction, "SELECT event_json FROM audit_events WHERE fingerprint = $fp AND event_id = $id", ("$fp", item.MachineFingerprint), ("$id", item.EventId)) is string stored)
        {
            return string.Equals(stored, item.ToJson(), StringComparison.Ordinal) ? new AuditAckEntry(item.EventId, AuditStatus.Duplicate, "") : Refuse("event-id-reused");
        }

        if (cutoff is { } limit && item.Time < limit)
        {
            // Not stored. Its number still counts (it may be the next one, or fill a hole), but it can be one the authority already pruned, so it is never recorded as reused.
            TrackSequence(connection, transaction, item.MachineFingerprint, item.Epoch, item.Sequence, nowText, recordReuse: false);

            return new AuditAckEntry(item.EventId, AuditStatus.Expired, "older than the retention");
        }

        TrackSequence(connection, transaction, item.MachineFingerprint, item.Epoch, item.Sequence, nowText, recordReuse: true);
        WithSecretsDatabase.Execute(connection, transaction, "INSERT INTO audit_events (event_id, fingerprint, epoch, sequence, time, type, outcome, reason, request_id, folder, program, arguments, grant_id, exit_code, event_json, received, acknowledged) VALUES ($id, $fp, $epoch, $seq, $time, $type, $outcome, $reason, $request, $folder, $program, $arguments, $grant, $exit, $json, $now, $now)",
            ("$id", item.EventId), ("$fp", item.MachineFingerprint), ("$epoch", item.Epoch), ("$seq", item.Sequence), ("$time", Time(item.Time)), ("$type", item.Type), ("$outcome", item.Outcome), ("$reason", item.Reason),
            ("$request", item.RequestId), ("$folder", item.Folder), ("$program", item.Program), ("$arguments", ArgumentsText(item.Arguments)), ("$grant", item.GrantId), ("$exit", item.ExitCode),
            ("$json", item.ToJson()), ("$now", nowText));

        return new AuditAckEntry(item.EventId, AuditStatus.Accepted, "");
    }

    private static string ArgumentsText(IReadOnlyList<string> arguments)
    {
        StringBuilder text = new();
        CanonicalJson.Strings(text, arguments);

        return text.ToString();
    }

    /// <summary>
    /// Moves the machine's sequence state for one new event. The numbers are tracked per (machine, epoch), the epoch being the id of the host's outbox: the next number advances it;
    /// a number past the next records a missing range (and advances); a number at or below the highest either fills a recorded hole of the SAME epoch (shrinking or splitting it) or
    /// is a number used before (recorded as reused). The first event of a new epoch of a known machine records an epoch gap (its outbox was recreated), and a recreated outbox can
    /// never close a hole its predecessor left, because its numbers belong to another epoch.
    /// </summary>
    private static void TrackSequence(SqliteConnection connection, SqliteTransaction transaction, string fingerprint, string epoch, long sequence, string now, bool recordReuse)
    {
        object? known = WithSecretsDatabase.Scalar(connection, transaction, "SELECT highest FROM audit_machine_state WHERE fingerprint = $fp AND epoch = $epoch", ("$fp", fingerprint), ("$epoch", epoch));
        long highest = known is { } value ? Convert.ToInt64(value, CultureInfo.InvariantCulture) : 0;
        if (known is null && WithSecretsDatabase.Scalar(connection, transaction, "SELECT COUNT(*) FROM audit_machine_state WHERE fingerprint = $fp", ("$fp", fingerprint)) is { } others && Convert.ToInt64(others, CultureInfo.InvariantCulture) > 0)
        {
            AddGap(connection, transaction, fingerprint, epoch, "epoch", sequence, sequence, now);
        }

        if (sequence == highest + 1)
        {
            highest = sequence;
        }
        else if (sequence > highest + 1)
        {
            AddGap(connection, transaction, fingerprint, epoch, "missing", highest + 1, sequence - 1, now);
            highest = sequence;
        }
        else
        {
            using SqliteCommand find = WithSecretsDatabase.Command(connection, transaction, "SELECT id, from_sequence, to_sequence, detected FROM audit_gaps WHERE fingerprint = $fp AND epoch = $epoch AND kind = 'missing' AND resolved IS NULL AND from_sequence <= $seq AND to_sequence >= $seq LIMIT 1", ("$fp", fingerprint), ("$epoch", epoch), ("$seq", sequence));
            (long Id, long From, long To, string Detected)? gap = null;
            using (SqliteDataReader reader = find.ExecuteReader())
            {
                if (reader.Read())
                {
                    gap = (reader.GetInt64(0), reader.GetInt64(1), reader.GetInt64(2), reader.GetString(3));
                }
            }

            if (gap is { } hole)
            {
                if (hole.From == sequence && hole.To == sequence)
                {
                    WithSecretsDatabase.Execute(connection, transaction, "UPDATE audit_gaps SET resolved = $now WHERE id = $id", ("$now", now), ("$id", hole.Id));
                }
                else if (hole.From == sequence)
                {
                    WithSecretsDatabase.Execute(connection, transaction, "UPDATE audit_gaps SET from_sequence = $from WHERE id = $id", ("$from", sequence + 1), ("$id", hole.Id));
                }
                else if (hole.To == sequence)
                {
                    WithSecretsDatabase.Execute(connection, transaction, "UPDATE audit_gaps SET to_sequence = $to WHERE id = $id", ("$to", sequence - 1), ("$id", hole.Id));
                }
                else
                {
                    WithSecretsDatabase.Execute(connection, transaction, "UPDATE audit_gaps SET to_sequence = $to WHERE id = $id", ("$to", sequence - 1), ("$id", hole.Id));
                    WithSecretsDatabase.Execute(connection, transaction, "INSERT INTO audit_gaps (fingerprint, epoch, kind, from_sequence, to_sequence, detected, resolved) VALUES ($fp, $epoch, 'missing', $from, $to, $detected, NULL)",
                        ("$fp", fingerprint), ("$epoch", epoch), ("$from", sequence + 1), ("$to", hole.To), ("$detected", hole.Detected));
                }
            }
            else if (recordReuse)
            {
                AddGap(connection, transaction, fingerprint, epoch, "reused", sequence, sequence, now);
            }
        }

        WithSecretsDatabase.Execute(connection, transaction, "INSERT INTO audit_machine_state (fingerprint, epoch, highest, updated) VALUES ($fp, $epoch, $highest, $now) ON CONFLICT(fingerprint, epoch) DO UPDATE SET highest = $highest, updated = $now",
            ("$fp", fingerprint), ("$epoch", epoch), ("$highest", highest), ("$now", now));
    }

    private static void AddGap(SqliteConnection connection, SqliteTransaction transaction, string fingerprint, string epoch, string kind, long from, long to, string now)
    {
        WithSecretsDatabase.Execute(connection, transaction, "INSERT INTO audit_gaps (fingerprint, epoch, kind, from_sequence, to_sequence, detected, resolved) VALUES ($fp, $epoch, $kind, $from, $to, $now, NULL)",
            ("$fp", fingerprint), ("$epoch", epoch), ("$kind", kind), ("$from", from), ("$to", to), ("$now", now));
    }

    // ---- history ----

    /// <summary>The highest sequence number the authority has seen from the machine in its latest epoch (0: none).</summary>
    public long AuditHighestSequence(string fingerprint)
    {
        return Read(connection => connection is null ? 0L : WithSecretsDatabase.Scalar(connection, null, "SELECT highest FROM audit_machine_state WHERE fingerprint = $fp ORDER BY rowid DESC LIMIT 1", ("$fp", fingerprint)) is { } value ? Convert.ToInt64(value, CultureInfo.InvariantCulture) : 0L);
    }

    /// <summary>The recorded gaps (holes and reused numbers), oldest first; by default only those still open.</summary>
    public IReadOnlyList<AuditGap> AuditGaps(string? machinePrefix = null, bool openOnly = true)
    {
        return Read<IReadOnlyList<AuditGap>>(connection =>
        {
            if (connection is null)
            {
                return [];
            }

            string prefix = Escape(Hex(machinePrefix)) + "%";

            return Query(connection, null, "SELECT id, fingerprint, kind, from_sequence, to_sequence, detected, resolved, epoch FROM audit_gaps WHERE fingerprint LIKE $fp ESCAPE '\\' AND ($all OR resolved IS NULL) ORDER BY id",
                reader => new AuditGap(reader.GetInt64(0), reader.GetString(1), reader.GetString(2), reader.GetInt64(3), reader.GetInt64(4), ParseTime(reader.GetString(5)), reader.IsDBNull(6) ? null : ParseTime(reader.GetString(6)), reader.GetString(7)),
                ("$fp", prefix), ("$all", openOnly ? 0 : 1));
        });
    }

    /// <summary>The audit history: the events that match every filter given, newest first (by event time).</summary>
    public IReadOnlyList<AuditHistoryRecord> AuditHistory(AuditQuery query)
    {
        return Read<IReadOnlyList<AuditHistoryRecord>>(connection =>
        {
            if (connection is null)
            {
                return [];
            }

            List<string> where = [];
            List<(string Name, object? Value)> parameters = [];
            void Add(string condition, string name, object value)
            {
                where.Add(condition);
                parameters.Add((name, value));
            }

            if (!string.IsNullOrEmpty(query.MachinePrefix))
            {
                Add("fingerprint LIKE $fp ESCAPE '\\'", "$fp", Escape(Hex(query.MachinePrefix)) + "%");
            }

            if (query.From is { } from)
            {
                Add("time >= $from", "$from", Time(from));
            }

            if (query.To is { } to)
            {
                Add("time <= $to", "$to", Time(to));
            }

            if (!string.IsNullOrEmpty(query.Type))
            {
                Add("type = $type", "$type", query.Type);
            }

            if (!string.IsNullOrEmpty(query.Outcome))
            {
                Add("outcome = $outcome", "$outcome", query.Outcome);
            }

            if (!string.IsNullOrEmpty(query.GrantId))
            {
                Add("grant_id LIKE $grant ESCAPE '\\'", "$grant", Escape(query.GrantId) + "%");
            }

            if (!string.IsNullOrEmpty(query.Folder))
            {
                Add("folder LIKE $folder ESCAPE '\\'", "$folder", "%" + Escape(query.Folder) + "%");
            }

            if (!string.IsNullOrEmpty(query.Text))
            {
                // The arguments are stored as JSON text (backslashes, quotes and non-ASCII letters escaped): the search text is escaped the same way for them.
                parameters.Add(("$argtext", "%" + Escape(JsonEscaped(query.Text)) + "%"));
                Add("(program LIKE $text ESCAPE '\\' OR arguments LIKE $argtext ESCAPE '\\' OR folder LIKE $text ESCAPE '\\' OR outcome LIKE $text ESCAPE '\\' OR reason LIKE $text ESCAPE '\\' OR request_id LIKE $text ESCAPE '\\')", "$text", "%" + Escape(query.Text) + "%");
            }

            int limit = Math.Clamp(query.Limit, 1, AuditQuery.MaxLimit);
            parameters.Add(("$limit", limit));
            string sql = "SELECT event_json, received FROM audit_events" + (where.Count == 0 ? "" : " WHERE " + string.Join(" AND ", where)) + " ORDER BY time DESC, sequence DESC LIMIT $limit";

            return Query(connection, null, sql, reader =>
            {
                if (!AuditEvent.TryParse(reader.GetString(0), out AuditEvent? parsed, out string? problem))
                {
                    throw new AuthorityDatabaseException("a stored audit event cannot be read (" + problem + "); delete with-secrets.db to start over");
                }

                return new AuditHistoryRecord(parsed!, ParseTime(reader.GetString(1)));
            }, [.. parameters]);
        });
    }

    private static string JsonEscaped(string text)
    {
        string quoted = ArgumentsText([text]);

        return quoted[2..^2];
    }

    private static string Hex(string? text) => text is null ? "" : new string([.. text.Where(letter => letter is not (' ' or ':' or '-')).Select(char.ToUpperInvariant)]);

    private static string Escape(string text) => text.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("%", "\\%", StringComparison.Ordinal).Replace("_", "\\_", StringComparison.Ordinal);
}

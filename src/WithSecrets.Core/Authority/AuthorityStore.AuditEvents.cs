using System.Globalization;
using System.Text;

using Microsoft.Data.Sqlite;

namespace WithSecrets;

/// <summary>
/// The authority's side of the audit trail (schema 4 of <c>authority.db</c>): signed events the hosts uploaded, the per-machine sequence state, the gaps it found, and the
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

    private const string AuditSchema = """
        CREATE TABLE IF NOT EXISTS audit_events (
            event_id TEXT PRIMARY KEY NOT NULL, fingerprint TEXT NOT NULL, sequence INTEGER NOT NULL, time TEXT NOT NULL, type TEXT NOT NULL, outcome TEXT NOT NULL,
            reason TEXT NOT NULL, request_id TEXT NOT NULL, folder TEXT NOT NULL, program TEXT NOT NULL, arguments TEXT NOT NULL, grant_id TEXT NOT NULL,
            exit_code INTEGER, event_json TEXT NOT NULL, received TEXT NOT NULL, acknowledged TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS audit_events_machine ON audit_events (fingerprint, sequence);
        CREATE INDEX IF NOT EXISTS audit_events_time ON audit_events (time);
        CREATE TABLE IF NOT EXISTS audit_machine_state (fingerprint TEXT PRIMARY KEY NOT NULL, highest INTEGER NOT NULL, updated TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit_gaps (
            id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT NOT NULL, kind TEXT NOT NULL, from_sequence INTEGER NOT NULL, to_sequence INTEGER NOT NULL,
            detected TEXT NOT NULL, resolved TEXT);
        CREATE TABLE IF NOT EXISTS authority_settings (name TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL);
        """;

    // ---- retention ----

    /// <summary>How many days the authority keeps audit events (0: forever).</summary>
    public int AuditRetentionDays()
    {
        return Read(connection => connection is null ? DefaultAuditRetentionDays : ReadRetention(connection, null));
    }

    /// <summary>Sets the retention (0 keeps everything); recorded in the authority's own audit history.</summary>
    public void SetAuditRetentionDays(int days, string actor)
    {
        if (days is < 0 or > MaxAuditRetentionDays)
        {
            throw new ArgumentOutOfRangeException(nameof(days), "retention is 0 to " + MaxAuditRetentionDays + " days");
        }

        Write((connection, transaction) =>
        {
            int before = ReadRetention(connection, transaction);
            StateDatabase.Execute(connection, transaction, "INSERT INTO authority_settings (name, value) VALUES ($name, $value) ON CONFLICT(name) DO UPDATE SET value = $value",
                ("$name", RetentionSetting), ("$value", days.ToString(CultureInfo.InvariantCulture)));
            Audit(connection, transaction, "audit-retention-changed", null, null, actor, $"audit retention {before} to {days} days");

            return 0;
        });
    }

    private static int ReadRetention(SqliteConnection connection, SqliteTransaction? transaction)
    {
        object? stored = StateDatabase.Scalar(connection, transaction, "SELECT value FROM authority_settings WHERE name = $name", ("$name", RetentionSetting));

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

        return days == 0 ? 0 : StateDatabase.Execute(connection, transaction, "DELETE FROM audit_events WHERE acknowledged IS NOT NULL AND received < $cutoff", ("$cutoff", Time(Now - TimeSpan.FromDays(days))));
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
            long first = long.MaxValue;
            long last = 0;
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
            }

            Fault?.Invoke("after-audit-events");
            if (accepted > 0)
            {
                Audit(connection, transaction, "audit-events-received", batch.MachineFingerprint, batch.BatchId, "authority", $"{accepted} event(s), sequence {first} to {last}");
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
            return Refuse("unknown-machine");
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

        if (StateDatabase.Scalar(connection, transaction, "SELECT event_json FROM audit_events WHERE event_id = $id", ("$id", item.EventId)) is string stored)
        {
            return string.Equals(stored, item.ToJson(), StringComparison.Ordinal) ? new AuditAckEntry(item.EventId, AuditStatus.Duplicate, "") : Refuse("event-id-reused");
        }

        if (cutoff is { } limit && item.Time < limit)
        {
            // Not stored. Its number still counts (it may be the next one, or fill a hole), but it can be one the authority already pruned, so it is never recorded as reused.
            TrackSequence(connection, transaction, item.MachineFingerprint, item.Sequence, nowText, recordReuse: false);

            return new AuditAckEntry(item.EventId, AuditStatus.Expired, "older than the retention");
        }

        TrackSequence(connection, transaction, item.MachineFingerprint, item.Sequence, nowText, recordReuse: true);
        StateDatabase.Execute(connection, transaction, "INSERT INTO audit_events (event_id, fingerprint, sequence, time, type, outcome, reason, request_id, folder, program, arguments, grant_id, exit_code, event_json, received, acknowledged) VALUES ($id, $fp, $seq, $time, $type, $outcome, $reason, $request, $folder, $program, $arguments, $grant, $exit, $json, $now, $now)",
            ("$id", item.EventId), ("$fp", item.MachineFingerprint), ("$seq", item.Sequence), ("$time", Time(item.Time)), ("$type", item.Type), ("$outcome", item.Outcome), ("$reason", item.Reason),
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
    /// Moves the machine's sequence state for one new event: the next number advances it; a number past the next records a missing range (and advances); a number at or below
    /// the highest either fills a recorded hole (shrinking or splitting it) or is a number used before (recorded as reused).
    /// </summary>
    private static void TrackSequence(SqliteConnection connection, SqliteTransaction transaction, string fingerprint, long sequence, string now, bool recordReuse)
    {
        long highest = StateDatabase.Scalar(connection, transaction, "SELECT highest FROM audit_machine_state WHERE fingerprint = $fp", ("$fp", fingerprint)) is { } known ? Convert.ToInt64(known, CultureInfo.InvariantCulture) : 0;
        if (sequence == highest + 1)
        {
            highest = sequence;
        }
        else if (sequence > highest + 1)
        {
            AddGap(connection, transaction, fingerprint, "missing", highest + 1, sequence - 1, now);
            highest = sequence;
        }
        else
        {
            using SqliteCommand find = StateDatabase.Command(connection, transaction, "SELECT id, from_sequence, to_sequence, detected FROM audit_gaps WHERE fingerprint = $fp AND kind = 'missing' AND resolved IS NULL AND from_sequence <= $seq AND to_sequence >= $seq LIMIT 1", ("$fp", fingerprint), ("$seq", sequence));
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
                    StateDatabase.Execute(connection, transaction, "UPDATE audit_gaps SET resolved = $now WHERE id = $id", ("$now", now), ("$id", hole.Id));
                }
                else if (hole.From == sequence)
                {
                    StateDatabase.Execute(connection, transaction, "UPDATE audit_gaps SET from_sequence = $from WHERE id = $id", ("$from", sequence + 1), ("$id", hole.Id));
                }
                else if (hole.To == sequence)
                {
                    StateDatabase.Execute(connection, transaction, "UPDATE audit_gaps SET to_sequence = $to WHERE id = $id", ("$to", sequence - 1), ("$id", hole.Id));
                }
                else
                {
                    StateDatabase.Execute(connection, transaction, "UPDATE audit_gaps SET to_sequence = $to WHERE id = $id", ("$to", sequence - 1), ("$id", hole.Id));
                    StateDatabase.Execute(connection, transaction, "INSERT INTO audit_gaps (fingerprint, kind, from_sequence, to_sequence, detected, resolved) VALUES ($fp, 'missing', $from, $to, $detected, NULL)",
                        ("$fp", fingerprint), ("$from", sequence + 1), ("$to", hole.To), ("$detected", hole.Detected));
                }
            }
            else if (recordReuse)
            {
                AddGap(connection, transaction, fingerprint, "reused", sequence, sequence, now);
            }
        }

        StateDatabase.Execute(connection, transaction, "INSERT INTO audit_machine_state (fingerprint, highest, updated) VALUES ($fp, $highest, $now) ON CONFLICT(fingerprint) DO UPDATE SET highest = $highest, updated = $now",
            ("$fp", fingerprint), ("$highest", highest), ("$now", now));
    }

    private static void AddGap(SqliteConnection connection, SqliteTransaction transaction, string fingerprint, string kind, long from, long to, string now)
    {
        StateDatabase.Execute(connection, transaction, "INSERT INTO audit_gaps (fingerprint, kind, from_sequence, to_sequence, detected, resolved) VALUES ($fp, $kind, $from, $to, $now, NULL)",
            ("$fp", fingerprint), ("$kind", kind), ("$from", from), ("$to", to), ("$now", now));
    }

    // ---- history ----

    /// <summary>The highest sequence number the authority has seen from the machine (0: none).</summary>
    public long AuditHighestSequence(string fingerprint)
    {
        return Read(connection => connection is null ? 0L : StateDatabase.Scalar(connection, null, "SELECT highest FROM audit_machine_state WHERE fingerprint = $fp", ("$fp", fingerprint)) is { } value ? Convert.ToInt64(value, CultureInfo.InvariantCulture) : 0L);
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

            return Query(connection, null, "SELECT id, fingerprint, kind, from_sequence, to_sequence, detected, resolved FROM audit_gaps WHERE fingerprint LIKE $fp ESCAPE '\\' AND ($all OR resolved IS NULL) ORDER BY id",
                reader => new AuditGap(reader.GetInt64(0), reader.GetString(1), reader.GetString(2), reader.GetInt64(3), reader.GetInt64(4), ParseTime(reader.GetString(5)), reader.IsDBNull(6) ? null : ParseTime(reader.GetString(6))),
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
                Add("(program LIKE $text ESCAPE '\\' OR arguments LIKE $text ESCAPE '\\' OR folder LIKE $text ESCAPE '\\' OR outcome LIKE $text ESCAPE '\\' OR reason LIKE $text ESCAPE '\\' OR request_id LIKE $text ESCAPE '\\')", "$text", "%" + Escape(query.Text) + "%");
            }

            int limit = Math.Clamp(query.Limit, 1, AuditQuery.MaxLimit);
            parameters.Add(("$limit", limit));
            string sql = "SELECT event_json, received FROM audit_events" + (where.Count == 0 ? "" : " WHERE " + string.Join(" AND ", where)) + " ORDER BY time DESC, sequence DESC LIMIT $limit";

            return Query(connection, null, sql, reader =>
            {
                if (!AuditEvent.TryParse(reader.GetString(0), out AuditEvent? parsed, out string? problem))
                {
                    throw new AuthorityDatabaseException("a stored audit event cannot be read (" + problem + "); delete authority.db to start over");
                }

                return new AuditHistoryRecord(parsed!, ParseTime(reader.GetString(1)));
            }, [.. parameters]);
        });
    }

    private static string Hex(string? text) => text is null ? "" : new string([.. text.Where(letter => letter is not (' ' or ':' or '-')).Select(char.ToUpperInvariant)]);

    private static string Escape(string text) => text.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("%", "\\%", StringComparison.Ordinal).Replace("_", "\\_", StringComparison.Ordinal);
}

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

using Microsoft.Data.Sqlite;

namespace WithSecrets;

/// <summary>One audit row as <c>--audit</c> shows it. Names only, never values.</summary>
public sealed record AuditRecord(long Id, DateTimeOffset Time, string Event, IReadOnlyList<string> Secrets, string Program, string Detail, string KeyName);

/// <summary>The result of checking the hash chain. <see cref="BrokenAt" /> is the first row whose link does not hold.</summary>
public sealed record AuditVerification(bool Ok, int Count, long? BrokenAt, string? Error);

/// <summary>
/// The audit log, in <see cref="StateDatabase" />. One row per event: time, event, secret names, program, outcome and the name
/// of the approving key, plus the full entry as one line of JSON. It records names, never values. Each row
/// carries the SHA-256 of the row before it, so an edited or deleted row breaks the chain (<see cref="Verify" />). Removing
/// rows from the end cannot be detected this way.
/// </summary>
public sealed partial class AuditLog
{
    private const string Genesis = "0000000000000000000000000000000000000000000000000000000000000000";

    private readonly StateDatabase _db;

    public AuditLog(StateDatabase db)
    {
        _db = db;
    }

    /// <summary>
    /// Returns false when the entry could not be written. The caller then refuses to continue. <paramref name="reuseMinutes" />
    /// is the reuse time the person approved (0 for once); it goes into the entry and the outcome column. <paramref name="keyName" />
    /// is the approving key when the detail does not name it (a reused saved approval); else it is read from the detail.
    /// </summary>
    public bool TryWrite(string eventName, ApprovalRequest request, string detail, int? exitCode = null, IReadOnlyDictionary<string, string>? files = null, int? reuseMinutes = null, string? keyName = null)
    {
        DateTimeOffset time = DateTimeOffset.UtcNow;
        string entry = JsonSerializer.Serialize(new
        {
            time,
            @event = eventName,
            program = request.ResolvedProgram,
            arguments = request.Arguments,
            directory = request.WorkingDirectory,
            reason = request.Reason,
            secrets = request.SecretNames,
            variables = request.Mappings?.Select(pair => new { variable = pair.Variable, secret = pair.Secret }),
            envFiles = request.EnvFiles,
            envVariables = request.EnvNames,
            detail,
            files,
            typedArguments = request.TypedArguments,
            links = request.Links,
            exitCode,
            reuseMinutes,
            key = keyName,
            environmentHash = request.InheritedEnvironment is { } environment ? EnvironmentBinding.Prefix(environment) : null
        });

        string outcome = Outcome(detail, exitCode);
        if (reuseMinutes is { } minutes)
        {
            string chosen = minutes > 0 ? "approved for " + minutes.ToString(CultureInfo.InvariantCulture) + " min" : "approved once";
            outcome = outcome.Length == 0 ? chosen : outcome + "; " + chosen;
        }

        return TryAppend(new Row(time, eventName, request.SecretNames, request.ResolvedProgram, outcome, entry, keyName ?? KeyName(detail)));
    }

    /// <summary>A change to the store, such as "secrets-set" or "secrets-removed". Names only, never values.</summary>
    public bool TryWriteChange(string eventName, IReadOnlyList<string> names, string detail)
    {
        DateTimeOffset time = DateTimeOffset.UtcNow;
        string entry = JsonSerializer.Serialize(new
        {
            time,
            @event = eventName,
            names,
            detail
        });

        return TryAppend(new Row(time, eventName, names, "", detail, entry));
    }

    /// <summary>The event of a change that was refused or failed.</summary>
    public const string ChangeDenied = "change-denied";

    /// <summary>
    /// A change that was refused or failed: the command (such as "--set"), the secret names it named (names only) and why.
    /// Best effort: false when it could not be written. Nothing is written when there is no state.db yet, so a refusal never
    /// creates one.
    /// </summary>
    public bool TryWriteDenied(string command, IReadOnlyList<string> names, string reason)
    {
        if (!File.Exists(_db.FilePath))
        {
            return false;
        }

        DateTimeOffset time = DateTimeOffset.UtcNow;
        string detail = command + ": " + reason;
        string entry = JsonSerializer.Serialize(new
        {
            time,
            @event = ChangeDenied,
            command,
            names,
            detail
        });

        return TryAppend(new Row(time, ChangeDenied, names, "", detail, entry, ""));
    }

    /// <summary>
    /// A change to the secret store ("secrets-set" or "secrets-removed"), approved by <paramref name="keyName" />, for the
    /// store's own write transaction. Names only, never values or ciphertext.
    /// </summary>
    internal static Row SecretsRow(string eventName, IReadOnlyList<string> names, string detail, string keyName)
    {
        DateTimeOffset time = DateTimeOffset.UtcNow;
        string entry = JsonSerializer.Serialize(new
        {
            time,
            @event = eventName,
            names,
            detail,
            key = keyName
        });

        return new Row(time, eventName, names, "", detail, entry, keyName);
    }

    /// <summary>A change to what can approve (a key added or removed, approvals revoked), approved by <paramref name="keyName" />.</summary>
    internal static Row ChangeRow(string eventName, string detail, string keyName)
    {
        DateTimeOffset time = DateTimeOffset.UtcNow;
        string entry = JsonSerializer.Serialize(new
        {
            time,
            @event = eventName,
            detail,
            key = keyName
        });

        return new Row(time, eventName, [], "", detail, entry, keyName);
    }

    /// <summary>
    /// The newest <paramref name="last" /> rows, oldest first, only those naming <paramref name="secret" /> when it is given.
    /// A missing database is an empty log. False with a message when the database cannot be used.
    /// </summary>
    public bool TryRead(int last, string? secret, out IReadOnlyList<AuditRecord> records, out string? error)
    {
        try
        {
            records = _db.Read(connection =>
            {
                List<AuditRecord> rows = [];
                if (connection is null)
                {
                    return rows;
                }

                using SqliteCommand command = StateDatabase.Command(connection, null,
                    "SELECT id, time, event, secrets, program, detail, key_name FROM audit "
                    + "WHERE $secret IS NULL OR EXISTS (SELECT 1 FROM json_each(audit.secrets) WHERE json_each.value = $secret) "
                    + "ORDER BY id DESC LIMIT $last",
                    ("$secret", secret), ("$last", last));
                using SqliteDataReader reader = command.ExecuteReader();
                while (reader.Read())
                {
                    DateTimeOffset.TryParse(reader.GetString(1), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTimeOffset time);
                    IReadOnlyList<string> names = JsonSerializer.Deserialize<List<string>>(reader.GetString(3)) ?? [];
                    rows.Add(new AuditRecord(reader.GetInt64(0), time, reader.GetString(2), names, reader.GetString(4), reader.GetString(5), reader.GetString(6)));
                }

                rows.Reverse();

                return rows;
            });
            error = null;

            return true;
        }
        catch (Exception failure) when (failure is StateDatabaseException or JsonException)
        {
            records = [];
            error = failure.Message;

            return false;
        }
    }

    /// <summary>Checks every row's link to the one before it. A missing database is an empty, good chain.</summary>
    public AuditVerification Verify()
    {
        try
        {
            return _db.Read(connection =>
            {
                if (connection is null)
                {
                    return new AuditVerification(true, 0, null, null);
                }

                using SqliteCommand command = StateDatabase.Command(connection, null, "SELECT id, time, event, secrets, program, detail, key_name, entry, prev_hash, hash FROM audit ORDER BY id");
                using SqliteDataReader reader = command.ExecuteReader();
                string previous = Genesis;
                int count = 0;
                while (reader.Read())
                {
                    count++;
                    string expected = Hash(previous, reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetString(4), reader.GetString(5), reader.GetString(6), reader.GetString(7));
                    if (reader.GetString(8) != previous || reader.GetString(9) != expected)
                    {
                        return new AuditVerification(false, count, reader.GetInt64(0), null);
                    }

                    previous = reader.GetString(9);
                }

                return new AuditVerification(true, count, null, null);
            });
        }
        catch (StateDatabaseException failure)
        {
            return new AuditVerification(false, 0, null, failure.Message);
        }
    }

    /// <summary>The full entries (JSON lines) in order. Empty when the database is missing or unusable.</summary>
    internal IReadOnlyList<string> Lines()
    {
        try
        {
            return _db.Read(connection =>
            {
                List<string> lines = [];
                if (connection is null)
                {
                    return lines;
                }

                using SqliteCommand command = StateDatabase.Command(connection, null, "SELECT entry FROM audit ORDER BY id");
                using SqliteDataReader reader = command.ExecuteReader();
                while (reader.Read())
                {
                    lines.Add(reader.GetString(0));
                }

                return lines;
            });
        }
        catch (StateDatabaseException)
        {
            return [];
        }
    }

    /// <summary>What happened: the detail, with the exit code when there is one.</summary>
    internal static string Outcome(string detail, int? exitCode)
    {
        return exitCode is not { } code ? detail
            : detail.Length == 0 ? "exit " + code.ToString(CultureInfo.InvariantCulture)
            : detail + "; exit " + code.ToString(CultureInfo.InvariantCulture);
    }

    /// <summary>One row. <see cref="Key" /> is the approving key; when it is null it is read from the detail.</summary>
    internal sealed record Row(DateTimeOffset Time, string Event, IReadOnlyList<string> Secrets, string Program, string Detail, string Entry, string? Key = null);

    /// <summary>
    /// A change to the settings: the names of the settings that changed (in the names column), "name old -> new" for each in
    /// the detail (no setting is secret), and the key that approved it. <paramref name="note" /> is added to the detail.
    /// </summary>
    internal static Row SettingsRow(string eventName, IReadOnlyList<SettingChange> changes, string keyName, string? note = null)
    {
        DateTimeOffset time = DateTimeOffset.UtcNow;
        List<string> parts = [.. changes.Select(change => $"{change.Name} {change.Old} -> {change.New}")];
        if (parts.Count == 0)
        {
            parts.Add("no setting changed");
        }

        if (note is not null)
        {
            parts.Add(note);
        }

        string detail = string.Join("; ", parts);
        List<string> names = [.. changes.Select(change => change.Name)];
        string entry = JsonSerializer.Serialize(new
        {
            time,
            @event = eventName,
            names,
            changes = changes.Select(change => new { name = change.Name, old = change.Old, @new = change.New }),
            detail,
            key = keyName
        });

        return new Row(time, eventName, names, "", detail, entry, keyName);
    }

    /// <summary>Adds a row linked to the last one. Runs inside the caller's write transaction, so two writers cannot fork the chain.</summary>
    internal static void Append(SqliteConnection connection, SqliteTransaction transaction, Row row)
    {
        string previous = StateDatabase.Scalar(connection, transaction, "SELECT hash FROM audit ORDER BY id DESC LIMIT 1") as string ?? Genesis;
        string time = row.Time.ToString("O", CultureInfo.InvariantCulture);
        string secrets = JsonSerializer.Serialize(row.Secrets);
        string key = row.Key ?? KeyName(row.Detail);
        string hash = Hash(previous, time, row.Event, secrets, row.Program, row.Detail, key, row.Entry);
        StateDatabase.Execute(connection, transaction,
            "INSERT INTO audit (time, event, secrets, program, detail, key_name, entry, prev_hash, hash) VALUES ($time, $event, $secrets, $program, $detail, $key, $entry, $prev, $hash)",
            ("$time", time), ("$event", row.Event), ("$secrets", secrets), ("$program", row.Program), ("$detail", row.Detail), ("$key", key),
            ("$entry", row.Entry), ("$prev", previous), ("$hash", hash));
    }

    private bool TryAppend(Row row)
    {
        try
        {
            return _db.Write((connection, transaction) =>
            {
                Append(connection, transaction, row);

                return true;
            });
        }
        catch (StateDatabaseException)
        {
            AppLog.Warn("an audit log row could not be written");

            return false;
        }
    }

    /// <summary>
    /// The approving key, from the detail the passkey method writes ("passkey NAME verified", or "admin passkey NAME verified"
    /// for the admin key, which the detail column keeps), or empty.
    /// </summary>
    internal static string KeyName(string detail)
    {
        Match match = KeyPattern().Match(detail);

        return match.Success ? match.Groups[1].Value : "";
    }

    /// <summary>SHA-256 over the previous hash and every field, each written as its length and its text, so fields cannot run together.</summary>
    private static string Hash(string previous, params string[] fields)
    {
        StringBuilder text = new();
        foreach (string field in new[] { previous }.Concat(fields))
        {
            text.Append(field.Length.ToString(CultureInfo.InvariantCulture)).Append(':').Append(field).Append('\n');
        }

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text.ToString())));
    }

    [GeneratedRegex("^(?:admin )?passkey (.+) verified$", RegexOptions.CultureInvariant | RegexOptions.Singleline)]
    private static partial Regex KeyPattern();
}

/// <summary>
/// <c>--audit [--last N] [--secret NAME] [--verify]</c>: prints a header line with the admin keys' fingerprints (see
/// <see cref="AdminKey" />), then recent entries, one per line: time, event, secret names, program, outcome and key name,
/// separated by tabs. Read-only: it creates nothing. Terminal output is public, and
/// the log holds no values, so none can appear.
/// </summary>
public static class AuditCommand
{
    public const int DefaultLast = 20;
    public const int MaxLast = 1000;

    public static int Run(StateDatabase db, CliCommand.Audit command, TextWriter stdout, TextWriter stderr)
    {
        AuditLog audit = new(db);
        if (!audit.TryRead(command.Last, command.Secret, out IReadOnlyList<AuditRecord> rows, out string? error))
        {
            stderr.WriteLine("with-secrets: cannot read the audit log: " + error);

            return RunCommand.StoreError;
        }

        // The header: the admin keys' fingerprints, so the person can see that the state is still the one they set up.
        stdout.WriteLine(AdminKey.Line(db));
        foreach (AuditRecord row in rows)
        {
            stdout.WriteLine(Format(row));
        }

        if (rows.Count == 0)
        {
            stderr.WriteLine("No audit entries.");
        }

        if (!command.Verify)
        {
            return 0;
        }

        AuditVerification check = audit.Verify();
        if (check.Error is not null)
        {
            stderr.WriteLine("with-secrets: cannot check the audit log: " + check.Error);

            return RunCommand.StoreError;
        }

        if (!check.Ok)
        {
            stdout.WriteLine($"audit chain: broken at entry {check.BrokenAt}");

            return RunCommand.StoreError;
        }

        stdout.WriteLine($"audit chain: ok ({check.Count} entries)");

        return 0;
    }

    public static string Format(AuditRecord row)
    {
        static string Field(string value) => value.Length == 0 ? "-" : ApprovalSummary.Clean(value);

        return string.Join('\t',
            row.Time.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss'Z'", CultureInfo.InvariantCulture),
            Field(row.Event),
            Field(string.Join(",", row.Secrets)),
            Field(row.Program),
            Field(row.Detail),
            Field(row.KeyName));
    }
}

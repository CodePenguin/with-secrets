using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Microsoft.Data.Sqlite;

namespace WithSecrets;

/// <summary>What an approval covers. <see cref="Key" /> changes when anything the person approved changes.</summary>
public sealed record Fingerprint(string Key, IReadOnlyDictionary<string, string> Files);

/// <summary>
/// Identifies a request for approval reuse. The key is made of four things: the secret names, the full path of the program, the
/// working folder, and the full path and content of the script being executed. The script is the program itself
/// (<c>./check.sh</c>), or, when an interpreter runs it, the first argument that names an existing small file
/// (<c>pwsh -File run.ps1</c>, <c>node app.js</c>). Two programs with the same name in different places are different programs.
/// Flags, other arguments, and the agent's reason are not part of the key.
/// </summary>
public static class RequestFingerprint
{
    /// <summary>Larger files (programs such as dotnet.exe) are not hashed. Scripts are small.</summary>
    public const long MaxHashedFileBytes = 1024 * 1024;

    public static Fingerprint Compute(ApprovalRequest request)
    {
        SortedDictionary<string, string> files = new(StringComparer.Ordinal);
        AddHash(files, request.ResolvedProgram, request.WorkingDirectory);
        int script = PathExpander.ScriptArgumentIndex(request.Program, request.Arguments, request.WorkingDirectory);
        if (script >= 0)
        {
            AddHash(files, request.Arguments[script], request.WorkingDirectory);
        }

        StringBuilder text = new();
        text.Append(Normalize(request.ResolvedProgram)).Append('\0');
        text.Append(Normalize(request.WorkingDirectory)).Append('\0').Append('\u0001');
        foreach (string name in request.SecretNames.OrderBy(name => name, StringComparer.Ordinal))
        {
            text.Append(name).Append('\0');
        }

        text.Append('\u0001');
        // A plain --secrets run (every variable named like its secret, no .env) keeps the key it always had.
        if (request.Mappings is not null && (request.Mappings.Any(pair => pair.Variable != pair.Secret) || request.EnvFiles is { Count: > 0 } || request.EnvNames is { Count: > 0 } || request.EnvValues is { Count: > 0 }))
        {
            // Every pair and every file the declarations came from are part of what was approved.
            foreach (SecretMapping pair in request.Mappings.OrderBy(pair => pair.Variable, StringComparer.Ordinal))
            {
                text.Append(pair.Variable).Append('\0').Append(pair.Secret).Append('\0');
            }

            text.Append('\u0002');
            foreach (string file in (request.EnvFiles ?? []).Order(StringComparer.Ordinal))
            {
                text.Append(Normalize(file)).Append('\0');
            }

            text.Append('\u0002');
            foreach (string name in (request.EnvNames ?? []).Order(StringComparer.Ordinal))
            {
                text.Append(name).Append('\0');
            }

            text.Append('\u0002');
            foreach (KeyValuePair<string, string> variable in (request.EnvValues ?? new Dictionary<string, string>()).OrderBy(item => item.Key, StringComparer.Ordinal))
            {
                text.Append(variable.Key).Append('\0').Append(variable.Value).Append('\0');
            }

            text.Append('\u0001');
        }

        // The environment the program inherits (a request over the API) is part of what was approved. Absent: the key is unchanged.
        if (request.InheritedEnvironment is { } inherited)
        {
            text.Append((char)3).Append(EnvironmentBinding.Hash(inherited)).Append((char)3);
        }

        foreach ((string path, string hash) in files)
        {
            text.Append(Normalize(path)).Append('\0').Append(hash).Append('\0');
        }

        string key = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text.ToString())));

        return new Fingerprint(key, files);
    }

    /// <summary>A full path with no trailing separator. Windows paths ignore case, so they are compared in upper case.</summary>
    private static string Normalize(string path)
    {
        string full = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        return OperatingSystem.IsWindows() ? full.ToUpperInvariant() : full;
    }

    /// <summary>Adds the file's hash when the text names an existing file of a hashable size. Returns true when it did.</summary>
    private static bool AddHash(SortedDictionary<string, string> files, string candidate, string workingDirectory)
    {
        try
        {
            string full = Path.GetFullPath(candidate, workingDirectory);
            FileInfo info = new(full);
            if (!info.Exists || info.Length > MaxHashedFileBytes)
            {
                return false;
            }

            files[full] = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(full)));

            return true;
        }
        catch (Exception error) when (error is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return false;
        }
    }
}

/// <summary>One saved approval: its fingerprint key, when it was approved and ends, the minutes signed, and the approving key.</summary>
public sealed record GrantEntry(string Key, DateTimeOffset Approved, DateTimeOffset Expires, int Minutes, string KeyName);

/// <summary>
/// What <see cref="GrantStore.Find" /> found: a grant in force, nothing, or a saved approval that failed verification
/// (<see cref="Rejected" /> says why). A rejected grant is never used.
/// </summary>
public sealed record GrantLookup(GrantEntry? Grant, string? Rejected)
{
    public static GrantLookup None { get; } = new(null, null);
}

/// <summary>
/// Remembers approvals for a limited time, in <see cref="StateDatabase" />. A grant keeps what the person signed on the
/// approval page (<see cref="ApprovalEvidence" />), and it is checked again every time it is read, so an agent that can edit
/// state.db cannot make or stretch one. A grant is honoured only when all of this holds:
/// <list type="bullet">
/// <item>the approving credential is a key in the verified manifest;</item>
/// <item>its assertion verifies with that key over <see cref="ReuseBinding.Challenge" /> of
/// <see cref="RequestBinding.Compute" />(nonce, text) and the stored minutes (signature, challenge and type in the client
/// data, user presence and verification; the sign count is not checked again);</item>
/// <item>the signed text has exactly one request id line, naming this grant's key, and exactly one page issued line;</item>
/// <item>the minutes are 1 to <see cref="ReuseSettings.MaxMinutes" />, the approval was saved no earlier than the page was
/// issued and no later than <see cref="ApprovalSettings.MaxTimeoutMinutes" /> after it, and it ends exactly the minutes after
/// it was saved.</item>
/// </list>
/// A grant that fails any of these is ignored and reported (<see cref="GrantLookup.Rejected" />). One that holds is in force
/// while now is inside its lifetime and its minutes are within the ceiling given at read time (the current
/// <c>reuseMaxMinutes</c>); otherwise it is simply not used. Reuse never extends a grant. A database that cannot be used or
/// whose manifest fails verification means no approvals, so the person is asked again.
/// </summary>
public sealed class GrantStore
{
    /// <summary>What the run prints when a saved approval does not verify.</summary>
    public const string RejectedMessage = "a saved approval failed verification and was ignored";

    private readonly StateDatabase _db;
    private readonly Func<DateTimeOffset> _now;

    public GrantStore(StateDatabase db, Func<DateTimeOffset>? clock = null)
    {
        _db = db;
        _now = clock ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>The database, for tests.</summary>
    internal StateDatabase Database => _db;

    /// <summary>This store's clock, for tests.</summary>
    internal DateTimeOffset Now() => _now();

    /// <summary>One row as stored. Times are UTC ticks.</summary>
    private sealed record Row(string Key, string CredentialId, string AuthenticatorData, string ClientData, string Signature, string Nonce, string Text, long Minutes, long Approved, long Expires)
    {
        public string Proof => JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["id"] = CredentialId,
            ["authenticatorData"] = AuthenticatorData,
            ["clientDataJSON"] = ClientData,
            ["signature"] = Signature,
        });
    }

    /// <summary>The grant for the key: in force, none, or rejected because it does not verify.</summary>
    public GrantLookup Find(string key, int maxMinutes)
    {
        long now = _now().UtcTicks;
        try
        {
            return _db.Read(connection =>
            {
                // Nothing is honoured from a state that fails verification (that throws) or has no manifest.
                if (connection is null || _db.CurrentManifest(connection, null) is not { } manifest)
                {
                    return GrantLookup.None;
                }

                using SqliteCommand command = StateDatabase.Command(connection, null,
                    "SELECT key, credential_id, authenticator_data, client_data, signature, nonce, text, minutes, approved, expires FROM grants WHERE key = $key", ("$key", key));
                using SqliteDataReader reader = command.ExecuteReader();
                if (!reader.Read())
                {
                    return GrantLookup.None;
                }

                if (Read(reader) is not { } row)
                {
                    return new GrantLookup(null, "the saved approval cannot be read");
                }

                string? problem = Problem(manifest, row, out ManifestKey? signer);
                if (problem is not null)
                {
                    return new GrantLookup(null, problem);
                }

                // A good grant that has not started, has ended or is longer than the ceiling now is simply not used.
                return row.Approved > now || row.Expires <= now || row.Minutes > maxMinutes
                    ? GrantLookup.None
                    : new GrantLookup(Entry(row, signer!.Name), null);
            });
        }
        catch (StateDatabaseException)
        {
            return GrantLookup.None;
        }
    }

    /// <summary>
    /// Saves the approval the person signed on the page (<paramref name="evidence" />) for request <paramref name="key" />, for
    /// <paramref name="minutes" /> (1 to <see cref="ReuseSettings.MaxMinutes" />) from now. It is saved only when it would
    /// verify on reading. Returns false when it was not saved; the person is then asked again next time.
    /// </summary>
    public bool Add(string key, int minutes, ApprovalEvidence evidence)
    {
        if (minutes is < 1 or > ReuseSettings.MaxMinutes || ProofFields(evidence.Proof) is not { } fields)
        {
            return false;
        }

        long now = _now().UtcTicks;
        Row row = new(key, fields[0], fields[1], fields[2], fields[3], evidence.Nonce, evidence.Text, minutes, now, now + (minutes * TimeSpan.TicksPerMinute));
        try
        {
            // A grant needs a verified manifest: saved approvals without one make the state fail verification.
            return File.Exists(_db.FilePath) && _db.Write((connection, transaction) =>
            {
                if (_db.CurrentManifest(connection, transaction) is not { } manifest || Problem(manifest, row, out _) is not null)
                {
                    return false;
                }

                StateDatabase.Execute(connection, transaction, "DELETE FROM grants WHERE expires <= $now OR key = $key", ("$now", now), ("$key", key));
                StateDatabase.Execute(connection, transaction,
                    "INSERT INTO grants (key, credential_id, authenticator_data, client_data, signature, nonce, text, minutes, approved, expires) "
                    + "VALUES ($key, $id, $ad, $cd, $sig, $nonce, $text, $minutes, $approved, $expires)",
                    ("$key", row.Key), ("$id", row.CredentialId), ("$ad", row.AuthenticatorData), ("$cd", row.ClientData), ("$sig", row.Signature),
                    ("$nonce", row.Nonce), ("$text", row.Text), ("$minutes", row.Minutes), ("$approved", row.Approved), ("$expires", row.Expires));

                return true;
            });
        }
        catch (StateDatabaseException)
        {
            return false;
        }
    }

    /// <summary>Null when the row verifies against the manifest (see the class summary), else why not.</summary>
    private static string? Problem(Manifest manifest, Row row, out ManifestKey? signer)
    {
        signer = manifest.Keys.FirstOrDefault(item => item.Id == row.CredentialId);
        if (signer is null)
        {
            return "the approving key is not enrolled";
        }

        if (row.Minutes is < 1 or > ReuseSettings.MaxMinutes)
        {
            return "its minutes are out of range";
        }

        string[] lines = row.Text.Split('\n');
        string[] ids = [.. lines.Where(line => line.StartsWith(ApprovalSummary.RequestIdPrefix, StringComparison.Ordinal))];
        if (ids.Length != 1 || ids[0] != ApprovalSummary.RequestIdPrefix + row.Key)
        {
            return "the signed text is not for this request";
        }

        string[] issuedLines = [.. lines.Where(line => line.StartsWith(ApprovalSummary.IssuedPrefix, StringComparison.Ordinal))];
        if (issuedLines.Length != 1
            || !DateTimeOffset.TryParseExact(issuedLines[0][ApprovalSummary.IssuedPrefix.Length..], "O", CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTimeOffset issued))
        {
            return "the signed text has no page time";
        }

        long from = issued.UtcTicks;
        if (row.Approved < from || row.Approved > from + (ApprovalSettings.MaxTimeoutMinutes * TimeSpan.TicksPerMinute))
        {
            return "it was saved outside the time its page allows";
        }

        if (row.Expires != row.Approved + (row.Minutes * TimeSpan.TicksPerMinute))
        {
            return "its end does not match its minutes";
        }

        byte[] challenge = ReuseBinding.Challenge(RequestBinding.Compute(row.Nonce, row.Text), (int)row.Minutes);
        AssertionResult result = WebAuthn.VerifyStored(signer.Record(0), challenge, row.Proof);

        return result.Ok ? null : "the signature does not verify (" + result.Detail + ")";
    }

    /// <summary>The row, or null when a column has the wrong type (an edit made outside the tool).</summary>
    private static Row? Read(SqliteDataReader reader)
    {
        object[] values = new object[10];
        reader.GetValues(values);
        if (values[..7].Any(value => value is not string) || values[7..].Any(value => value is not long))
        {
            return null;
        }

        return new Row((string)values[0], (string)values[1], (string)values[2], (string)values[3], (string)values[4], (string)values[5], (string)values[6],
            (long)values[7], (long)values[8], (long)values[9]);
    }

    private static GrantEntry Entry(Row row, string keyName)
    {
        return new GrantEntry(row.Key, new DateTimeOffset(row.Approved, TimeSpan.Zero), new DateTimeOffset(row.Expires, TimeSpan.Zero), (int)row.Minutes, keyName);
    }

    /// <summary>The four strings of an assertion JSON object (id, authenticatorData, clientDataJSON, signature), or null.</summary>
    private static string[]? ProofFields(string proof)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(proof);
            JsonElement root = document.RootElement;
            string[] names = ["id", "authenticatorData", "clientDataJSON", "signature"];
            if (root.ValueKind != JsonValueKind.Object
                || names.Any(name => !root.TryGetProperty(name, out JsonElement value) || value.ValueKind != JsonValueKind.String))
            {
                return null;
            }

            return [.. names.Select(name => root.GetProperty(name).GetString()!)];
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Ends every approval now. False when the database cannot be used, so approvals may still be saved.</summary>
    public bool TryClear()
    {
        try
        {
            return !File.Exists(_db.FilePath) || _db.Write((connection, transaction) => StateDatabase.Execute(connection, transaction, "DELETE FROM grants") >= 0);
        }
        catch (StateDatabaseException)
        {
            return false;
        }
    }

    /// <summary>Every saved approval, expired or not, verified or not, with the name of the approving key when it is enrolled. For tests.</summary>
    internal IReadOnlyList<GrantEntry> Entries()
    {
        return _db.Read(connection =>
        {
            List<GrantEntry> entries = [];
            if (connection is null)
            {
                return entries;
            }

            Manifest? manifest = _db.CurrentManifest(connection, null);
            using SqliteCommand command = StateDatabase.Command(connection, null,
                "SELECT key, credential_id, authenticator_data, client_data, signature, nonce, text, minutes, approved, expires FROM grants ORDER BY rowid");
            using SqliteDataReader reader = command.ExecuteReader();
            while (reader.Read())
            {
                if (Read(reader) is { } row)
                {
                    entries.Add(Entry(row, manifest?.Keys.FirstOrDefault(item => item.Id == row.CredentialId)?.Name ?? ""));
                }
            }

            return entries;
        });
    }
}

/// <summary>
/// What the approval page may offer besides "Approve once": the fixed <see cref="Steps" /> up to the ceiling
/// <paramref name="MaxMinutes" /> (the <c>reuseMaxMinutes</c> setting). <paramref name="StartMinutes" /> (the
/// <c>reuseMinutes</c> setting) picks the entry the list starts on: the nearest step at or below it, or none.
/// </summary>
public sealed record ReuseOffer(int MaxMinutes, int StartMinutes)
{
    /// <summary>10 minutes, 1 hour, 4 hours, 8 hours.</summary>
    public static IReadOnlyList<int> Steps { get; } = [10, 60, 240, 480];

    /// <summary>Only "Approve once".</summary>
    public static ReuseOffer Off { get; } = new(0, 0);

    /// <summary>The times the page offers, shortest first: every step up to the ceiling.</summary>
    public IReadOnlyList<int> Choices => [.. Steps.Where(step => step <= MaxMinutes)];

    /// <summary>True when the page offers at least one time besides once.</summary>
    public bool IsOn => Choices.Count > 0;

    /// <summary>The entry the list starts on: the largest offered time at or below the start; null when there is none.</summary>
    public int? Preselected => Choices.Where(step => step <= StartMinutes).Select(step => (int?)step).LastOrDefault();

    /// <summary>True for 0 (once) and for every offered time. Anything else is refused.</summary>
    public bool Allows(int minutes) => minutes == 0 || Choices.Contains(minutes);

    /// <summary>A time as the page shows it: "10 minutes", "1 hour", "4 hours".</summary>
    public static string Label(int minutes)
    {
        string text = (minutes % 60 == 0 && minutes >= 60 ? minutes / 60 : minutes).ToString(CultureInfo.InvariantCulture);

        return minutes == 60 ? "1 hour" : minutes % 60 == 0 && minutes >= 60 ? text + " hours" : text + " minutes";
    }
}

/// <summary>
/// The reuse settings. They come from the settings in state.db in the protected store folder, never from the environment or
/// the command line, because the agent controls both of those.
/// </summary>
public static class ReuseSettings
{
    /// <summary>The default starting entry (reuseMinutes).</summary>
    public const int DefaultMinutes = 10;

    /// <summary>The default ceiling (reuseMaxMinutes).</summary>
    public const int DefaultMaxMinutes = 480;

    /// <summary>The lowest ceiling: the first step.</summary>
    public const int MinMaxMinutes = 10;

    /// <summary>The highest ceiling, and the longest grant ever honoured: 24 hours.</summary>
    public const int MaxMinutes = 1440;

    /// <summary>From state.db: the stored values, the defaults when none are stored, and no reuse when the settings cannot be used.</summary>
    public static ReuseOffer Load(StateDatabase db)
    {
        ToolSettings settings = ToolSettings.Load(db, out string? error);

        return error is null ? settings.Reuse : ReuseOffer.Off;
    }
}


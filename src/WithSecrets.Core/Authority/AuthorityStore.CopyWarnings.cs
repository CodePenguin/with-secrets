using Microsoft.Data.Sqlite;

namespace WithSecrets;

/// <summary>
/// The warning that a machine's identity may have been copied: the authority saw the machine's connection superseded by a connection from another address, repeatedly. It names only public things: the machine
/// fingerprint, two addresses and counts. It is a warning, never a decision: nothing is disabled by it.
/// </summary>
public sealed record CopyWarning(string Fingerprint, int Count, string FirstAddress, string LastAddress, DateTimeOffset FirstSeen, DateTimeOffset LastSeen, DateTimeOffset? Audited);

public sealed partial class AuthorityStore
{
    private const string CopyWarningSchema = """
        CREATE TABLE IF NOT EXISTS copy_warnings (
            fingerprint TEXT PRIMARY KEY NOT NULL, count INTEGER NOT NULL, first_address TEXT NOT NULL, last_address TEXT NOT NULL,
            first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, audited TEXT);
        """;

    private const string CopyWarningColumns = "fingerprint, count, first_address, last_address, first_seen, last_seen, audited";

    private static CopyWarning ReadCopyWarning(SqliteDataReader reader) => new(reader.GetString(0), reader.GetInt32(1), reader.GetString(2), reader.GetString(3), ParseTime(reader.GetString(4)), ParseTime(reader.GetString(5)),
        reader.IsDBNull(6) ? null : ParseTime(reader.GetString(6)));

    /// <summary>Every recorded copied-identity warning.</summary>
    public IReadOnlyList<CopyWarning> CopyWarnings() => Read(connection => connection is null ? [] : Query(connection, null, $"SELECT {CopyWarningColumns} FROM copy_warnings", ReadCopyWarning));

    /// <summary>The warning of one machine, or null.</summary>
    public CopyWarning? CopyWarningOf(string fingerprint) => Read(connection => connection is null ? null : Query(connection, null, $"SELECT {CopyWarningColumns} FROM copy_warnings WHERE fingerprint = $fp", ReadCopyWarning, ("$fp", fingerprint)).FirstOrDefault());

    /// <summary>
    /// Records that the machine's connection was superseded from another address repeatedly (<paramref name="count" /> times within the watch window): the first warning, or a refresh of it. Returns true when a signed audit event
    /// should be written now: the first time, and again at most once per <paramref name="auditEvery" />. Addresses are public data; nothing secret is stored.
    /// </summary>
    public bool RecordCopyWarning(string fingerprint, string olderAddress, string newerAddress, int count, TimeSpan auditEvery)
    {
        return Write((connection, transaction) =>
        {
            DateTimeOffset now = Now;
            CopyWarning? known = Query(connection, transaction, $"SELECT {CopyWarningColumns} FROM copy_warnings WHERE fingerprint = $fp", ReadCopyWarning, ("$fp", fingerprint)).FirstOrDefault();
            bool audit = known?.Audited is not { } last || now - last >= auditEvery;
            if (known is null)
            {
                StateDatabase.Execute(connection, transaction, "INSERT INTO copy_warnings (fingerprint, count, first_address, last_address, first_seen, last_seen, audited) VALUES ($fp, $count, $first, $last, $now, $now, $audited)",
                    ("$fp", fingerprint), ("$count", count), ("$first", olderAddress), ("$last", newerAddress), ("$now", Time(now)), ("$audited", audit ? Time(now) : null));
            }
            else
            {
                StateDatabase.Execute(connection, transaction, "UPDATE copy_warnings SET count = $count, last_address = $last, last_seen = $now, audited = $audited WHERE fingerprint = $fp",
                    ("$fp", fingerprint), ("$count", Math.Max(count, known.Count)), ("$last", newerAddress), ("$now", Time(now)), ("$audited", audit ? Time(now) : known.Audited is { } kept ? Time(kept) : null));
            }

            return audit;
        });
    }
}

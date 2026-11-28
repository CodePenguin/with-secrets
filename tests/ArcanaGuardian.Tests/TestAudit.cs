using System.Runtime.CompilerServices;

namespace ArcanaGuardian.Tests;

/// <summary>One administrative audit event as the tests read it (the outbox's signed event, shaped like the old rows so the assertions keep their meaning).</summary>
internal sealed record AuditRow(string Event, string Detail, IReadOnlyList<string> Secrets, string KeyName);

/// <summary>An <see cref="IHostAudit" /> that keeps what it is given, or refuses everything (for the exit 5 tests).</summary>
internal sealed class RecordingAudit(bool refuse = false) : IHostAudit
{
    public List<AuditFacts> Facts { get; } = [];

    public void RecordIn(Microsoft.Data.Sqlite.SqliteConnection connection, Microsoft.Data.Sqlite.SqliteTransaction transaction, AuditFacts facts)
    {
        if (refuse)
        {
            throw new AuditOutboxException("test audit refused");
        }
        ArcanaGuardianDatabase.AfterCommit(transaction, () => TryRecord(facts));
    }

    public bool TryRecord(AuditFacts facts)
    {
        if (refuse)
        {
            return false;
        }

        lock (Facts)
        {
            Facts.Add(facts);
        }

        return true;
    }
}

/// <summary>
/// Reads the administrative events a command wrote: they are signed events (type admin) in the outbox beside the state, signed with a software key here
/// (no real key store is touched).
/// </summary>
internal static class TestAudit
{
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, SoftwareSigningKey> Keys = new(StringComparer.OrdinalIgnoreCase);

    [ModuleInitializer]
    internal static void UseSoftwareKeys() => AdminAudit.KeyFactory = folder => new Shared(KeyOfFolder(folder));

    private static SoftwareSigningKey KeyOfFolder(string folder) => Keys.GetOrAdd(Path.GetFullPath(folder), _ => new SoftwareSigningKey());

    /// <summary>The machine key the events of this store folder are signed with (one per folder, so a second process-like writer signs with the same one).</summary>
    /// <summary>
    /// The metadata canary: true when no member (name or value) of any event's metadata holds one of <paramref name="canaries" /> (secret values, ciphertext, a recovery code, key material),
    /// and every event verifies. The types of the events scanned are returned so a test can insist that every event type was among them.
    /// </summary>
    public static bool MetadataClean(StateDatabase db, string[] canaries, out HashSet<string> types)
    {
        IReadOnlyList<AuditEvent> events = Events(db, all: true);
        types = [.. events.Select(item => item.Type)];

        return events.All(item => item.Meta.All(member => canaries.All(canary => !member.Key.Contains(canary, StringComparison.Ordinal) && !member.Value.Contains(canary, StringComparison.Ordinal))) && AuditMetadata.Problem(item.Meta) is null);
    }

    public static ISigningKey KeyOf(StateDatabase db) => KeyOfFolder(Path.GetDirectoryName(db.FilePath)!);

    private sealed class Shared(ISigningKey inner) : ISigningKey
    {
        public byte[] PublicKey => inner.PublicKey;

        public byte[] Sign(byte[] data) => inner.Sign(data);

        public void Dispose()
        {
        }
    }

    /// <summary>Every signed event in the outbox beside <paramref name="db" />, oldest first (admin ones only unless <paramref name="all" />).</summary>
    public static IReadOnlyList<AuditEvent> Events(StateDatabase db, bool all = false)
    {
        string folder = Path.GetDirectoryName(db.FilePath)!;
        HostAuditOutbox outbox = HostAuditOutbox.InFolder(folder, KeyOf(db));

        return [.. outbox.Pending(100000).Where(item => all || item.Type == AuditEventTypes.Admin)];
    }

    public static IReadOnlyList<AuditRow> Rows(StateDatabase db) => [.. Events(db).Select(Row)];

    public static AuditRow Row(AuditEvent item) => new(item.Outcome, item.Meta.GetValueOrDefault("detail", item.Reason), item.Arguments, item.Meta.GetValueOrDefault("key", ""));

    public static bool TryRead(StateDatabase db, int last, string? secret, out IReadOnlyList<AuditRow> rows, out string? error)
    {
        error = null;
        rows = [.. Rows(db).Where(row => secret is null || row.Secrets.Contains(secret)).TakeLast(last)];

        return true;
    }

    /// <summary>The signed sink a run without the service writes to: the outbox beside <paramref name="db" />, signed with its folder's machine key.</summary>
    public static IHostAudit Sink(StateDatabase db) => new OutboxAudit(HostAuditOutbox.InFolder(Path.GetDirectoryName(db.FilePath)!, KeyOf(db)));

    public static int Count(StateDatabase db, string eventName) => Rows(db).Count(row => row.Event == eventName);
}

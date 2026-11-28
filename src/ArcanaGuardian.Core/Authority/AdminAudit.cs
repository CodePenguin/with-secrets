using System.Text.RegularExpressions;

using Microsoft.Data.Sqlite;

namespace ArcanaGuardian;

/// <summary>
/// One administrative event: a change to the secret store, to what can approve (passkeys, approvals), to the settings or to the store itself, or a change that was
/// refused. It is recorded as a signed audit event of type <see cref="AuditEventTypes.Admin" />: the event name is the outcome, the detail (with the approving key's
/// name) is the reason, and the secret, setting or key names are the arguments; the metadata repeats them with the full detail and the key name. Names only: no secret value, no ciphertext, no key material, no code.
/// </summary>
internal sealed record AdminEvent(string Name, IReadOnlyList<string> Names, string Detail, string Key, VerifiedCredential? Credential = null)
{
    internal VerifiedCredential? SessionKey { get; init; }

    /// <summary>The event of a change that was refused or failed.</summary>
    public const string ChangeDenied = "change-denied";

    /// <summary>A change to what can approve (a key added or removed, approvals revoked), approved by <paramref name="key" />.</summary>
    public static AdminEvent Change(string name, string detail, string key, VerifiedCredential? credential = null) => new(name, [], detail, key, credential);

    /// <summary>A change to the secret store approved by <paramref name="key" />. Names only.</summary>
    public static AdminEvent Secrets(string name, IReadOnlyList<string> names, string detail, string key, VerifiedCredential? credential = null) => new(name, names, detail, key, credential);

    /// <summary>A change to provider instances or mounts, or a namespace refresh ("provider-added", "mount-removed", "namespace-refreshed" and so on). Names and counts only: never configuration values.</summary>
    public static AdminEvent Provider(string outcome, IReadOnlyList<string> names, string detail, string key, VerifiedCredential? credential = null) => new(outcome, names, detail, key, credential);

    /// <summary>
    /// A change to the settings: the names of the settings that changed, "name old -> new" for each in the detail (no setting is secret), and the key that approved it.
    /// <paramref name="note" /> is added to the detail.
    /// </summary>
    public static AdminEvent Settings(string name, IReadOnlyList<SettingChange> changes, string key, VerifiedCredential? credential = null, string? note = null)
    {
        List<string> parts = [.. changes.Select(change => $"{change.Name} {change.Old} -> {change.New}")];
        if (parts.Count == 0)
        {
            parts.Add("no setting changed");
        }

        if (note is not null)
        {
            parts.Add(note);
        }

        return new AdminEvent(name, [.. changes.Select(change => change.Name)], string.Join("; ", parts), key, credential);
    }

    internal AuditFacts ToFacts()
    {
        string reason = Key.Length == 0 || Detail.Contains(Key, StringComparison.Ordinal) ? Detail : $"{Detail}; key {Key}";

        // The metadata carries what the reason has no room for: the full detail, the approving key's name and the names the change touched. Names only.
        Dictionary<string, string> metadata = new(StringComparer.Ordinal) { ["detail"] = Detail };
        if (Key.Length > 0)
        {
            metadata["key"] = Key;
        }

        Credential?.AddTo(metadata, "key");
        SessionKey?.AddTo(metadata, "sessionKey");

        if (Names.Count > 0)
        {
            metadata["names"] = string.Join(",", Names);
        }

        return new AuditFacts(AuditEventTypes.Admin, Name, reason, "", "", "", Names, Metadata: metadata);
    }
}

/// <summary>
/// Where administrative events go: the host audit (signed with the machine identity key, committed to <c>arcana-guardian.db</c>, uploaded to the authority), the same road
/// the run events take. There is no other audit log and no hash chain. An event that cannot be committed fails the change it belongs to: <see cref="Append" /> is called inside
/// the change's own write transaction, just before it commits, and throws <see cref="StateDatabaseException" /> so the transaction is rolled back.
/// </summary>
public sealed class AdminAudit(Func<IHostAudit> source, ArcanaGuardianDatabase database)
{
    /// <summary>For tests: the machine key to sign with in a given store folder, so no real key store is touched. Null in production.</summary>
    internal static Func<string, ISigningKey>? KeyFactory { get; set; }

    private static readonly Regex KeyPattern = new("^(?:admin )?passkey (.+) verified$", RegexOptions.CultureInvariant | RegexOptions.Singleline | RegexOptions.Compiled);

    private readonly Lock _lock = new();
    private IHostAudit? _audit;

    /// <summary>The production audit of the store in <paramref name="stateFile" />'s folder: the machine identity key of the platform key store and the outbox beside the state.</summary>
    public static AdminAudit ForDatabase(ArcanaGuardianDatabase database)
    {
        string folder = Path.GetDirectoryName(database.FilePath)!;

        return new AdminAudit(() =>
        {
            ISigningKey key = KeyFactory?.Invoke(folder) ?? MachineKeyStore.OpenOrCreate(folder, KeyNames.Machine, out _);

            return new OutboxAudit(new HostAuditOutbox(database, key));
        }, database);
    }

    /// <summary>The approving key's name in a detail such as "passkey NAME verified" or "admin passkey NAME verified", or empty.</summary>
    internal static string KeyName(string detail)
    {
        Match match = KeyPattern.Match(detail);

        return match.Success ? match.Groups[1].Value : "";
    }

    /// <summary>Commits the event (signed, numbered); throws <see cref="StateDatabaseException" /> when it cannot, so the change being made is not made.</summary>
    internal void Append(SqliteConnection connection, SqliteTransaction transaction, AdminEvent item)
    {
        try
        {
            GetAudit().RecordIn(connection, transaction, item.ToFacts());
        }
        catch (Exception failure) when (failure is not OutOfMemoryException)
        {
            AppLog.Warn("an administrative audit event could not be committed: {Type}", failure.GetType().Name);
            throw new StateDatabaseException("the audit event could not be committed, so nothing was changed", failure);
        }
    }

    private IHostAudit GetAudit()
    {
        lock (_lock)
        {
            return _audit ??= source();
        }
    }

    internal bool TryRecord(AdminEvent item)
    {
        try
        {
            return GetAudit().TryRecord(item.ToFacts());
        }
        catch (Exception failure) when (failure is not OutOfMemoryException)
        {
            // The type only: the message of a key or database error can name a path.
            AppLog.Warn("an administrative audit event could not be committed: {Type}", failure.GetType().Name);

            return false;
        }
    }

    /// <summary>
    /// A change that was refused or failed: the operation (such as "set-secrets"), the secret names it named (names only) and why. Best effort: false when it could not be written.
    /// Nothing is written when there is no arcana-guardian.db yet, so a refusal never creates one.
    /// </summary>
    internal bool TryWriteDenied(string command, IReadOnlyList<string> names, string reason, VerifiedCredential? credential = null)
    {
        return File.Exists(database.FilePath) && TryRecord(new AdminEvent(AdminEvent.ChangeDenied, names, command + ": " + reason, credential?.Name ?? "", credential));
    }
}

/// <summary>An <see cref="IHostAudit" /> that only commits to the outbox (a command that is not the service; the service uploads what it finds there).</summary>
internal sealed class OutboxAudit(HostAuditOutbox outbox) : IHostAudit
{
    public void RecordIn(SqliteConnection connection, SqliteTransaction transaction, AuditFacts facts) => outbox.AppendIn(connection, transaction, [facts]);

    public bool TryRecord(AuditFacts facts)
    {
        try
        {
            outbox.Append(facts);

            return true;
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            AppLog.Warn("an audit event could not be committed: {Type}", error.GetType().Name);

            return false;
        }
    }
}

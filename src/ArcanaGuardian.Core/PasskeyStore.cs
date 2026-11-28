namespace ArcanaGuardian;

/// <summary>
/// A registered passkey. <see cref="Id" /> and <see cref="PublicKey" /> are base64url. The public key is the COSE key bytes.
/// <see cref="Admin" /> marks a key that may change the state (an admin key; see <see cref="Manifest" />). <see cref="Slot" /> is the
/// key's slot of the master key (see <see cref="KeyVault" />), present only for admin keys.
/// </summary>
public sealed record PasskeyRecord(string Id, string PublicKey, int Alg, string RpId, string Name, DateTimeOffset Created, uint SignCount, bool Admin = false, KeySlot? Slot = null);

/// <summary>
/// The passkeys that may approve requests: the keys of the verified manifest in <see cref="StateDatabase" />, with their sign
/// counts. Keys are added and removed only by writing a new manifest signed by an admin key. A database that cannot be used
/// or fails verification means no passkeys for approval, so nobody can approve through the page, and an error for changes.
/// </summary>
public sealed class PasskeyStore
{
    private readonly StateDatabase _db;

    /// <summary>A store in the database at <paramref name="path" />.</summary>
    public PasskeyStore(string path) : this(new StateDatabase(path))
    {
    }

    public PasskeyStore(StateDatabase db)
    {
        _db = db;
    }

    internal StateDatabase Database => _db;

    /// <summary>What enrollment says when the database exists but cannot be read or fails verification.</summary>
    public string UnreadableMessage => !_db.TryCheck(out string? error) && error!.StartsWith(_db.FailedMessage, StringComparison.Ordinal)
        ? error
        : $"cannot read {_db.FileLabel}; fix or delete it";

    /// <summary>For approval: a database that cannot be read gives no passkeys, so nobody can approve.</summary>
    public IReadOnlyList<PasskeyRecord> All() => TryAll(out IReadOnlyList<PasskeyRecord> records) ? records : [];

    public IReadOnlyList<PasskeyRecord> ForRp(string rpId) => [.. All().Where(item => item.RpId == rpId)];

    /// <summary>
    /// For changes: true with the records when the state is empty (none) or verified. False when it exists but cannot be used,
    /// so a change never starts from a store that only looks empty. The admin keys come first, then the others, each by creation.
    /// </summary>
    public bool TryAll(out IReadOnlyList<PasskeyRecord> records)
    {
        return TryRead(out records, out _);
    }

    /// <summary>The records and the verified manifest they come from (null for an empty state); false when the state cannot be used.</summary>
    internal bool TryRead(out IReadOnlyList<PasskeyRecord> records, out Manifest? manifest)
    {
        try
        {
            (IReadOnlyList<PasskeyRecord> Records, Manifest? Manifest) read = _db.Read<(IReadOnlyList<PasskeyRecord>, Manifest?)>(connection =>
            {
                Manifest? current = _db.CurrentManifest(connection, null);
                if (current is null || connection is null)
                {
                    return ([], current);
                }

                Dictionary<string, long> counts = StateDatabase.SignCounts(connection, null);

                return ([.. current.Keys
                    .OrderByDescending(key => key.Admin).ThenBy(key => key.Created).ThenBy(key => key.Id, StringComparer.Ordinal)
                    .Select(key => key.Record(counts.TryGetValue(key.Id, out long count) ? (uint)count : 0))], current);
            });
            records = read.Records;
            manifest = read.Manifest;

            return true;
        }
        catch (StateDatabaseException)
        {
            records = [];
            manifest = null;

            return false;
        }
    }

    /// <summary>
    /// Raises the stored sign count. It never goes down: two runs that verify at once cannot set an older count back. Returns
    /// false when no key in the verified manifest has this Id, the stored count is already this high or higher, or the change
    /// could not be saved.
    /// </summary>
    public bool UpdateSignCount(string id, uint signCount)
    {
        if (!File.Exists(_db.FilePath))
        {
            return false;
        }

        try
        {
            return _db.Write((connection, transaction) => Raise(_db, connection, transaction, id, signCount));
        }
        catch (StateDatabaseException)
        {
            return false;
        }
    }

    /// <summary>The same, inside the caller's write transaction.</summary>
    internal static bool Raise(StateDatabase db, Microsoft.Data.Sqlite.SqliteConnection connection, Microsoft.Data.Sqlite.SqliteTransaction transaction, string id, uint signCount)
    {
        Manifest? manifest = db.CurrentManifest(connection, transaction);
        // No row is a count of 0, so 0 never raises it.
        if (signCount == 0 || manifest is null || !manifest.Keys.Any(key => key.Id == id))
        {
            return false;
        }

        return ArcanaGuardianDatabase.Execute(connection, transaction,
            "INSERT INTO sign_counts (id, count) VALUES ($id, $count) ON CONFLICT (id) DO UPDATE SET count = excluded.count WHERE excluded.count > sign_counts.count",
            ("$id", id), ("$count", (long)signCount)) > 0;
    }
}

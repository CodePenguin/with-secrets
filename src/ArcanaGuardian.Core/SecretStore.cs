using System.Security.Cryptography;
using System.Text;


using Microsoft.Data.Sqlite;

namespace ArcanaGuardian;

/// <summary>
/// Where a run's secrets come from. <see cref="Label" /> names the source on the approval page (the global store, <see cref="SecretStore.GlobalLabel" />);
/// <see cref="LabelFor" /> names the source of one secret (a mounted secret's provider instance, see <see cref="ProviderSecretSource" />).
/// </summary>
public interface ISecretSource
{
    string Label { get; }

    /// <summary>The source of <paramref name="name" /> as the approval page shows it. Names only; nothing is read or decrypted.</summary>
    string LabelFor(string name) => Label;

    /// <summary>The names of the secrets. Decrypts nothing.</summary>
    IReadOnlyList<string> ListNames();

    /// <summary>
    /// Decrypts only the named values, with the store key an administrator's unlock opened (<see cref="UnlockedKeys" />). Called only after the run was authorized.
    /// Throws when a name is missing, the source cannot be trusted, the authority is locked or the key is not open.
    /// </summary>
    SecretValues GetValues(IReadOnlyCollection<string> names);
}

/// <summary>
/// Decrypted secret values as UTF-8 bytes, zeroed by <see cref="Dispose" />. The bytes are the one copy the tool can wipe.
/// Copies it cannot wipe: the string the JWE handler returns (dropped at once), every string made by <see cref="Text" /> (the
/// redactor and the child's environment need strings), and the child's environment block itself. .NET strings are immutable
/// and may be moved by the garbage collector, so they stay in memory until it reuses that memory.
/// </summary>
public sealed class SecretValues : IDisposable
{
    private readonly Dictionary<string, byte[]> _values;
    private bool _disposed;

    /// <summary>Takes ownership of the arrays: Dispose zeroes them.</summary>
    public SecretValues(IReadOnlyDictionary<string, byte[]> values)
    {
        _values = new Dictionary<string, byte[]>(values, StringComparer.Ordinal);
        Names = [.. values.Keys];
    }

    public IReadOnlyList<string> Names { get; }
    internal VerifiedCredential? OpenedBy { get; init; }

    /// <summary>The value's bytes (not a copy). Valid until Dispose.</summary>
    public byte[] Bytes(string name)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _values[name];
    }

    /// <summary>The value as a string, for the redactor and the child's environment. This copy cannot be wiped.</summary>
    public string Text(string name) => Encoding.UTF8.GetString(Bytes(name));

    /// <summary>Every value as a string (see <see cref="Text" />).</summary>
    public Dictionary<string, string> Texts() => Names.ToDictionary(name => name, Text, StringComparer.Ordinal);

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        foreach (byte[] value in _values.Values)
        {
            Clear(value);
        }
    }

    /// <summary>Zeroes <paramref name="buffer" />; null is ignored.</summary>
    public static void Clear(byte[]? buffer)
    {
        if (buffer is not null)
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }
}

/// <summary>The crypto of stored values: Authenticated public-key encryption.</summary>
public interface ISecretCipher
{
    /// <summary>A new key pair, encoded for storage.</summary>
    (string PublicKey, string PrivateKey) NewKeyPair();

    /// <summary>The sealed ciphertext of <paramref name="value" /> for <paramref name="publicKey" />.</summary>
    string Encrypt(string value, string publicKey);

    string Decrypt(string privateKey, string ciphertext);
}

/// <summary>The secret store cannot be used: it failed verification, a name is missing, or a value cannot be decrypted. Names only, never values.</summary>
public sealed class SecretStoreException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// The global secret store: table <c>secrets(name, ciphertext)</c> in arcana-guardian.db, one JWE ciphertext per secret. The signed
/// manifest holds the store's public key and <see cref="Hash" /> of every ciphertext, because anyone with the public key can
/// write a valid ciphertext: a row is used only when it matches its signed hash, and a row without a hash, or a hash without a
/// row, is a store that failed verification. Every read checks every row's hash (no decrypt); <see cref="GetValues" /> then
/// decrypts only the requested rows, with the private key an administrator's unlock opened (<paramref name="keys" />), used inside the authority's
/// lock (<paramref name="lockState" />) and passed as a parameter (never an environment variable or a file). A store made without keys decrypts nothing.
/// Changes go through <see cref="TryApply" />: the rows and the new manifest (signed by an admin) are one transaction that re-checks the version it replaces.
/// </summary>
public sealed class SecretStore(StateDatabase db, ISecretCipher? cipher = null, UnlockedKeys? keys = null, AuthorityLock? lockState = null) : ISecretSource
{
    public const string GlobalLabel = "global";

    private const string NoKeys = "the secret store key is not open here: an administrator unlocks the authority with an admin passkey, so nothing was decrypted";

    private readonly ISecretCipher _cipher = cipher ?? JweCipher.Instance;

    /// <summary>The same store over the same database and cipher, decrypting with <paramref name="unlocked" /> while <paramref name="authority" /> is unlocked.</summary>
    internal SecretStore Unlocking(UnlockedKeys unlocked, AuthorityLock authority) => new(db, _cipher, unlocked, authority);

    public string Label => GlobalLabel;

    public StateDatabase Database => db;

    /// <summary>For tests: runs inside the write transaction, after the rows, the manifest and the audit row, before the commit.</summary>
    internal Action? BeforeCommit { get; set; }

    /// <summary>The hash the manifest keeps for a stored ciphertext: SHA-256 of its UTF-8 text, 64 lower-case hex digits.</summary>
    public static string Hash(string ciphertext) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(ciphertext)));

    public IReadOnlyList<string> ListNames() => Verified((manifest, _, _) => (IReadOnlyList<string>)[.. manifest?.Secrets.Keys ?? []]);

    /// <summary>
    /// Decrypts only the named values with the unlocked store key, inside the authority's lock: a lock that has begun decrypts nothing, and the key is used once for the
    /// whole call. The hex text of the key is a .NET string for the decrypt call and cannot be wiped.
    /// </summary>
    public SecretValues GetValues(IReadOnlyCollection<string> names)
    {
        (Manifest? current, Dictionary<string, string> picked) = ReadRows(names);

        return WithStoreKey(current, privateKey => new SecretValues(DecryptRows(privateKey, picked)) { OpenedBy = OpenedBy });
    }

    /// <summary>
    /// The verified manifest and the ciphertexts of exactly <paramref name="names" />, read after every row was checked against its signed hash. Decrypts nothing.
    /// Throws <see cref="SecretStoreException" /> when a name is not valid or not stored, or the store fails verification.
    /// </summary>
    internal (Manifest? Manifest, Dictionary<string, string> Rows) ReadRows(IReadOnlyCollection<string> names)
    {
        if (names.Any(name => !SecretNames.IsValid(name)) || names.Distinct(StringComparer.Ordinal).Count() != names.Count)
        {
            throw new SecretStoreException("the secret names are not valid");
        }

        return Verified((manifest, connection, transaction) =>
        {
            Dictionary<string, string> rows = new(StringComparer.Ordinal);
            foreach (string name in names)
            {
                rows[name] = (connection is null ? null : ArcanaGuardianDatabase.Scalar(connection, transaction, "SELECT ciphertext FROM secrets WHERE name = $name", ("$name", name)) as string)
                    ?? throw new SecretStoreException(name + " is not in the store");
            }

            return (manifest, rows);
        });
    }

    /// <summary>The values of <paramref name="rows" /> decrypted with <paramref name="privateKey" />; on any failure every value made so far is zeroed and nothing is returned.</summary>
    internal Dictionary<string, byte[]> DecryptRows(string privateKey, IReadOnlyDictionary<string, string> rows)
    {
        Dictionary<string, byte[]> values = new(StringComparer.Ordinal);
        try
        {
            foreach ((string name, string ciphertext) in rows)
            {
                try
                {
                    values[name] = Encoding.UTF8.GetBytes(_cipher.Decrypt(privateKey, ciphertext));
                }
                catch (Exception failure)
                {
                    throw new SecretStoreException("cannot decrypt " + name + " (" + failure.GetType().Name + ")", failure);
                }
            }

            return values;
        }
        catch
        {
            foreach (byte[] value in values.Values)
            {
                SecretValues.Clear(value);
            }

            throw;
        }
    }

    /// <summary>
    /// Runs <paramref name="use" /> with the unlocked store key of <paramref name="current" />, inside the authority's lock (see <see cref="AuthorityLock.UseWhileUnlocked" />).
    /// Throws <see cref="AuthorityLockedException" /> while locked, and <see cref="SecretStoreException" /> when this store has no keys, there is no store yet, or the key is
    /// not open or not the current one (<see cref="UnlockedKeys.UseStoreKey" />).
    /// </summary>
    internal T WithStoreKey<T>(Manifest? current, Func<string, T> use)
    {
        if (keys is null || lockState is null || current is null || current.Store.Length == 0)
        {
            throw new SecretStoreException(NoKeys);
        }

        return lockState.UseWhileUnlocked(() => keys.UseStoreKey(current, use));
    }

    internal VerifiedCredential? OpenedBy => keys?.OpenedBy;

    /// <summary>Runs <paramref name="use" /> inside the authority's lock without the store key (a call that decrypts nothing). Throws as <see cref="WithStoreKey" /> does when locked or when this store has no lock.</summary>
    internal T WhileUnlocked<T>(Func<T> use) => lockState is null ? throw new SecretStoreException(NoKeys) : lockState.UseWhileUnlocked(use);

    /// <summary>
    /// Throws as <see cref="WithStoreKey" /> would, now, without using the key: a caller checks this before work that is useless without the key (a provider retrieval). The
    /// decryption itself still runs through <see cref="WithStoreKey" />, which checks again.
    /// </summary>
    internal void EnsureStoreKey(Manifest? current)
    {
        if (keys is null || lockState is null || current is null || current.Store.Length == 0)
        {
            throw new SecretStoreException(NoKeys);
        }

        lockState.EnsureUnlocked();
        if (!keys.CanUseStoreKey(current))
        {
            throw new SecretStoreException(NoKeys);
        }
    }

    internal string Encrypt(string value, string publicKey) => _cipher.Encrypt(value, publicKey);

    /// <summary>
    /// The verified manifest (null for an empty state) and the stored names, after every row was checked against its hash.
    /// Throws <see cref="SecretStoreException" /> when the state or the store fails.
    /// </summary>
    internal (Manifest? Manifest, IReadOnlyList<string> Names) Current() => Verified((manifest, _, _) => (manifest, (IReadOnlyList<string>)[.. manifest?.Secrets.Keys ?? []]));

    /// <summary>
    /// The verified manifest (null for an empty state) and every stored ciphertext by name, read in one snapshot after each row
    /// matched its signed hash. Throws <see cref="SecretStoreException" /> when the state or the store fails.
    /// </summary>
    internal (Manifest? Manifest, Dictionary<string, string> Rows) Snapshot() => Verified((manifest, connection, transaction) =>
        (manifest, connection is null ? new Dictionary<string, string>(StringComparer.Ordinal) : AllRows(connection, transaction)));

    /// <summary>
    /// The next manifest: <paramref name="current" /> with <paramref name="publicKey" />, without <paramref name="removes" />,
    /// and with the hash of every ciphertext in <paramref name="rows" /> (new or replaced).
    /// </summary>
    public static Manifest Next(Manifest current, string publicKey, IReadOnlyDictionary<string, string> rows, IReadOnlyCollection<string> removes, string? vault = null, ReviewKey? review = null)
    {
        Dictionary<string, string> secrets = new(current.Secrets.Where(item => !removes.Contains(item.Key)), StringComparer.Ordinal);
        foreach ((string name, string ciphertext) in rows)
        {
            secrets[name] = Hash(ciphertext);
        }

        return current.ArcanaGuardian(publicKey, secrets, vault, review);
    }

    /// <summary>
    /// One write transaction: the signed manifest replaces version <paramref name="expectedVersion" /> (see
    /// <see cref="StateDatabase.TryReplace" />: signed by an admin, the next version), <paramref name="removes" /> are deleted,
    /// <paramref name="rows" /> written, every row must then match the new manifest's hashes, and <paramref name="audit" /> is
    /// recorded in the signed audit (just before the commit; when it cannot be, nothing is written). Null when committed, else why not; then nothing was written.
    /// </summary>
    internal string? TryApply(long expectedVersion, SignedManifest signed, IReadOnlyDictionary<string, string> rows, IReadOnlyCollection<string> removes, AdminEvent audit,
        Func<SqliteConnection, SqliteTransaction, string?>? alsoInTransaction = null)
        => TryApply(rows, removes, audit, (connection, transaction) => db.TryReplace(connection, transaction, expectedVersion, signed), alsoInTransaction);

    internal string? TrySet(long expectedVersion, SignedSecretWrite signed, IReadOnlyDictionary<string, string> rows, AdminEvent audit)
        => TryApply(rows, [], audit, (connection, transaction) =>
        {
            Manifest? current = db.CurrentManifest(connection, transaction);
            if (current is null || current.Version != expectedVersion)
            {
                return "the state changed while the page was open; nothing was saved";
            }

            if (signed.Text != SignedSecretWrite.Prepare(current, rows) || signed.Verify(current) is not { } next)
            {
                return "the secret write does not verify; nothing was saved";
            }

            if (Problem(current, AllRows(connection, transaction)) is { } mismatch)
            {
                return "the secret store failed verification (" + mismatch + "); nothing was saved";
            }

            ArcanaGuardianDatabase.Execute(connection, transaction, "INSERT INTO secret_writes (version, text, bind, proof) VALUES ($version, $text, $bind, $proof)",
                ("$version", next.Version), ("$text", signed.Text), ("$bind", System.Buffers.Text.Base64Url.EncodeToString(signed.Bind)), ("$proof", signed.Proof));
            return null;
        });

    private string? TryApply(IReadOnlyDictionary<string, string> rows, IReadOnlyCollection<string> removes, AdminEvent audit,
        Func<SqliteConnection, SqliteTransaction, string?> writeState, Func<SqliteConnection, SqliteTransaction, string?>? alsoInTransaction = null)
    {
        try
        {
            return db.Write<string?>((connection, transaction) =>
            {
                if (writeState(connection, transaction) is { } problem)
                {
                    throw new Abort(problem);
                }

                foreach (string name in removes)
                {
                    ArcanaGuardianDatabase.Execute(connection, transaction, "DELETE FROM secrets WHERE name = $name", ("$name", name));
                }

                foreach ((string name, string ciphertext) in rows)
                {
                    ArcanaGuardianDatabase.Execute(connection, transaction,
                        "INSERT INTO secrets (name, ciphertext) VALUES ($name, $ciphertext) ON CONFLICT (name) DO UPDATE SET ciphertext = excluded.ciphertext",
                        ("$name", name), ("$ciphertext", ciphertext));
                }

                if (Problem(db.CurrentManifest(connection, transaction), AllRows(connection, transaction)) is { } mismatch)
                {
                    throw new Abort("the secrets do not match the new state (" + mismatch + "); nothing was stored");
                }

                if (alsoInTransaction?.Invoke(connection, transaction) is { } sideEffectProblem)
                {
                    throw new Abort(sideEffectProblem);
                }

                db.AppendAudit(connection, transaction, audit);
                BeforeCommit?.Invoke();

                return null;
            });
        }
        catch (StateDatabaseException failure) when (failure.InnerException is Abort abort)
        {
            return abort.Message;
        }
        catch (StateDatabaseException failure)
        {
            return "the secret store could not be written (" + failure.Message + "); nothing was stored";
        }
    }

    /// <summary>Runs <paramref name="work" /> on one snapshot, after the manifest verified and every row matched its hash.</summary>
    private T Verified<T>(Func<Manifest?, SqliteConnection?, SqliteTransaction?, T> work)
    {
        try
        {
            return db.Read(connection =>
            {
                if (connection is null)
                {
                    return work(null, null, null);
                }

                using SqliteTransaction transaction = connection.BeginTransaction(deferred: true);
                Manifest? manifest = db.CurrentManifest(connection, transaction);
                if (Problem(manifest, AllRows(connection, transaction)) is { } problem)
                {
                    throw new SecretStoreException("the secret store failed verification (" + problem + "): delete " + db.FileLabel + " to start over (only if you did not edit it)");
                }

                return work(manifest, connection, transaction);
            });
        }
        catch (StateDatabaseException failure) when (failure.InnerException is SecretStoreException inner)
        {
            throw inner;
        }
        catch (StateDatabaseException failure)
        {
            throw new SecretStoreException(failure.Message, failure);
        }
    }

    internal static Dictionary<string, string> AllRows(SqliteConnection connection, SqliteTransaction? transaction)
    {
        Dictionary<string, string> rows = new(StringComparer.Ordinal);
        using SqliteCommand command = ArcanaGuardianDatabase.Command(connection, transaction, "SELECT name, ciphertext FROM secrets");
        using SqliteDataReader reader = command.ExecuteReader();
        while (reader.Read())
        {
            rows[reader.GetString(0)] = reader.GetString(1);
        }

        return rows;
    }

    /// <summary>Null when the rows are exactly the manifest's secrets, each matching its hash; else why not (names only).</summary>
    internal static string? Problem(Manifest? manifest, Dictionary<string, string> rows)
    {
        IReadOnlyDictionary<string, string> hashes = manifest?.Secrets ?? new Dictionary<string, string>();
        if (rows.Keys.FirstOrDefault(name => !hashes.ContainsKey(name)) is { } extra)
        {
            return "a row without a signed hash: " + ApprovalSummary.Clean(extra);
        }

        if (hashes.Keys.FirstOrDefault(name => !rows.ContainsKey(name)) is { } missing)
        {
            return "a signed secret without its row: " + missing;
        }

        if (hashes.FirstOrDefault(item => !CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Hash(rows[item.Key])), Encoding.ASCII.GetBytes(item.Value))) is { Key: { } changed })
        {
            return "a row that does not match its signed hash: " + changed;
        }

        return null;
    }

    /// <summary>Ends a write transaction without committing it, with why.</summary>
    private sealed class Abort(string message) : Exception(message);
}

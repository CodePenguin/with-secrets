using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Text.Json;

using Microsoft.Data.Sqlite;
using static WithSecrets.WithSecretsDatabase;

namespace WithSecrets;

/// <summary>A state database that cannot be used: unreadable, locked past the timeout, damaged, or of an unknown schema.</summary>
public sealed class StateDatabaseException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// <c>with-secrets.db</c> in the protected store folder: the signed manifest (passkeys and settings, see <see cref="Manifest" />), the
/// sign counts and secrets, in SQLite. Every read of keys, settings or secrets verifies the manifest
/// first (see <see cref="CurrentManifest" />); a state that fails verification can be used for nothing. Every
/// write is one transaction that takes the write lock first (<c>BEGIN IMMEDIATE</c>), so two processes writing at once wait for
/// each other (up to the busy timeout) and no update is lost. A missing database is empty. A database that exists but cannot be
/// used (not a database, damaged, locked beyond the timeout, another schema version) is an error, never an empty store. A
/// database of another schema version is never moved forward: the message says to delete it and start over. It holds no
/// secret value in plain text: each secret is a row of Dotenvx ciphertext (see <see cref="SecretStore" />). The tool reads no
/// other file in the store folder.
/// </summary>
public sealed class StateDatabase
{
    /// <summary>Manifests already verified in this process, by the stored row, so the signature is checked once per process.</summary>
    private static readonly ConcurrentDictionary<string, Manifest> Verified = new(StringComparer.Ordinal);

    public StateDatabase(string path) : this(new WithSecretsDatabase(path))
    {
    }

    internal StateDatabase(string path, TimeSpan timeout) : this(new WithSecretsDatabase(path, timeout))
    {
    }

    internal Func<FileStream>? SecondGateOpen { init => Database.SecondGateOpen = value; }
    internal IDisposable HoldCreationGateForTests() => Database.HoldCreationGateForTests();

    public StateDatabase(WithSecretsDatabase database) => Database = database;

    public WithSecretsDatabase Database { get; }
    public string FilePath => Database.FilePath;
    public string FileLabel => Database.FileLabel;

    private AdminAudit? _audit;

    /// <summary>
    /// Where this store's administrative events go (the signed host audit in with-secrets.db). By default the machine identity key of the platform key store
    /// and the outbox beside the state, opened on first use; the host service puts its own audit here so that an event wakes its uploader.
    /// </summary>
    public AdminAudit Audit
    {
        get => _audit ??= AdminAudit.ForDatabase(Database);
        set => _audit = value;
    }

    internal void AppendAudit(SqliteConnection connection, SqliteTransaction transaction, AdminEvent item) => Audit.Append(connection, transaction, item);

    public static StateDatabase InFolder(string folder) => new(WithSecretsDatabase.InFolder(folder));

    /// <summary>The message for a state that fails verification. Never "not enrolled": deleting the file is the only way on.</summary>
    public string FailedMessage => $"state failed verification: delete {FileLabel} to start over (only if you did not edit it)";

    /// <summary>
    /// True when the database is missing (empty) or opens, passes the integrity check and its manifest verifies (or it is an
    /// empty state). Creates nothing.
    /// </summary>
    public bool TryCheck(out string? error)
    {
        try
        {
            Read(connection => CurrentManifest(connection, null));
            error = null;

            return true;
        }
        catch (StateDatabaseException failure)
        {
            error = failure.Message;

            return false;
        }
    }

    /// <summary>
    /// What every command does first: null when the state can be used, else the exit code (<see cref="RunCommand.StoreError" />)
    /// after writing why to <paramref name="stderr" />.
    /// </summary>
    public int? Gate(TextWriter stderr)
    {
        if (TryCheck(out string? error))
        {
            return null;
        }

        // Logged without the reason text: it can name a path. The terminal gets the reason.
        AppLog.Warn("the state failed its check, so the command stopped (exit {Code})", RunCommand.StoreError);
        stderr.WriteLine("with-secrets: " + error);

        return RunCommand.StoreError;
    }

    /// <summary>The verified manifest (null for an empty state), or false and why not. Creates nothing.</summary>
    public bool TryManifest(out Manifest? manifest, out string? error)
    {
        try
        {
            manifest = Read(connection => CurrentManifest(connection, null));
            error = null;

            return true;
        }
        catch (StateDatabaseException failure)
        {
            manifest = null;
            error = failure.Message;

            return false;
        }
    }

    /// <summary>
    /// The verified manifest on this connection, or null for an empty state: no database, or no manifest and no sign counts and
    /// no rows. Throws <see cref="StateDatabaseException" /> with <see cref="FailedMessage" /> for anything else: a
    /// manifest that does not verify, two rows, rows that need a manifest without one, a sign count for a key that is not in
    /// it, or a table that is not part of the store.
    /// </summary>
    internal Manifest? CurrentManifest(SqliteConnection? connection, SqliteTransaction? transaction)
    {
        if (connection is null)
        {
            return null;
        }

        try
        {
            return ReadManifest(connection, transaction);
        }
        catch (SqliteException failure) when (failure.SqliteErrorCode is not (5 or 6))
        {
            throw Failed("the manifest cannot be read: " + failure.Message);
        }
        catch (Exception failure) when (failure is not (StateDatabaseException or SqliteException))
        {
            throw Failed("the manifest cannot be read: " + failure.Message);
        }
    }

    private Manifest? ReadManifest(SqliteConnection connection, SqliteTransaction? transaction)
    {

        if (WithSecretsDatabase.LayoutProblem(connection, transaction) is { } problem)
        {
            throw Failed("the tables are not those of the store: " + problem);
        }

        List<(long Version, SignedManifest Signed)> rows = [];
        using (SqliteCommand command = Command(connection, transaction, "SELECT version, text, bind, credential_id, authenticator_data, client_data, signature FROM manifest"))
        using (SqliteDataReader reader = command.ExecuteReader())
        {
            while (reader.Read())
            {
                string bind = reader.GetString(2);
                if (!Base64Url.IsValid(bind))
                {
                    throw Failed("the manifest bind is not base64url");
                }

                string proof = JsonSerializer.Serialize(new Dictionary<string, string>
                {
                    ["id"] = reader.GetString(3),
                    ["authenticatorData"] = reader.GetString(4),
                    ["clientDataJSON"] = reader.GetString(5),
                    ["signature"] = reader.GetString(6),
                });
                rows.Add((reader.GetInt64(0), new SignedManifest(reader.GetString(1), Base64Url.DecodeFromChars(bind), proof)));
            }
        }

        Dictionary<string, long> counts = SignCounts(connection, transaction);
        if (rows.Count == 0)
        {
            if (counts.Count > 0 || Scalar(connection, transaction, "SELECT COUNT(*) FROM secrets") is not 0L)
            {
                throw Failed("keys or secrets without a manifest");
            }

            return null;
        }

        if (rows.Count > 1)
        {
            throw Failed("more than one manifest");
        }

        (long version, SignedManifest signed) = rows[0];
        string cacheKey = string.Join("\n", signed.Text, Convert.ToBase64String(signed.Bind), signed.Proof);
        if (!Verified.TryGetValue(cacheKey, out Manifest? manifest))
        {
            manifest = signed.Verify(out string? error) ?? throw Failed(error ?? "the manifest does not verify");
            Verified[cacheKey] = manifest;
        }

        if (manifest.Version != version)
        {
            throw Failed("the manifest version does not match its row");
        }

        if (counts.Any(item => item.Value is < 0 or > uint.MaxValue || !manifest.Keys.Any(key => key.Id == item.Key)))
        {
            throw Failed("a sign count that does not belong to an enrolled key");
        }

        return manifest;
    }

    /// <summary>The stored sign counts, by credential id.</summary>
    internal static Dictionary<string, long> SignCounts(SqliteConnection connection, SqliteTransaction? transaction)
    {
        Dictionary<string, long> counts = new(StringComparer.Ordinal);
        using SqliteCommand command = Command(connection, transaction, "SELECT id, count FROM sign_counts");
        using SqliteDataReader reader = command.ExecuteReader();
        while (reader.Read())
        {
            counts[reader.GetString(0)] = reader.GetInt64(1);
        }

        return counts;
    }

    /// <summary>
    /// Inside the caller's write transaction: replaces the manifest with <paramref name="next" />, only when the stored one is
    /// still version <paramref name="expectedVersion" /> (0 for none), <paramref name="next" /> is the version after it, and it
    /// is signed by a key that is an admin of the stored manifest and stays an admin in <paramref name="next" /> (see
    /// <see cref="SignedManifest.Verify(Manifest?, out string?)" />; on the first run, by an admin of <paramref name="next" />). Sign counts of keys that are no longer in it are removed. Null when it was written,
    /// else why not (nothing is written). The caller has already checked the assertion in full on the page.
    /// </summary>
    internal string? TryReplace(SqliteConnection connection, SqliteTransaction transaction, long expectedVersion, SignedManifest next)
    {
        Manifest? current = CurrentManifest(connection, transaction);
        if ((current?.Version ?? 0) != expectedVersion)
        {
            return "the state changed while the page was open; nothing was saved";
        }

        // Signed by a key that is an admin of the stored state (on the first run, of the new one), and that stays an admin, so the
        // new state verifies when it is read.
        Manifest? manifest = next.Verify(current, out string? error);
        if (manifest is null)
        {
            return "the new state does not verify (" + error + "); nothing was saved";
        }

        if (manifest.Version != expectedVersion + 1)
        {
            return "the new state is not the next version; nothing was saved";
        }

        using JsonDocument proof = JsonDocument.Parse(next.Proof);
        JsonElement root = proof.RootElement;
        string Field(string name) => root.GetProperty(name).GetString() ?? throw new FormatException(name);
        Execute(connection, transaction, "DELETE FROM manifest");
        Execute(connection, transaction,
            "INSERT INTO manifest (id, version, text, bind, credential_id, authenticator_data, client_data, signature) VALUES (1, $version, $text, $bind, $id, $ad, $cd, $sig)",
            ("$version", manifest.Version), ("$text", next.Text), ("$bind", Base64Url.EncodeToString(next.Bind)), ("$id", Field("id")),
            ("$ad", Field("authenticatorData")), ("$cd", Field("clientDataJSON")), ("$sig", Field("signature")));
        foreach (string id in SignCounts(connection, transaction).Keys.Where(id => !manifest.Keys.Any(key => key.Id == id)))
        {
            Execute(connection, transaction, "DELETE FROM sign_counts WHERE id = $id", ("$id", id));
        }

        return null;
    }

    private StateDatabaseException Failed(string why) => new(FailedMessage + " (" + why + ")");

    internal sealed record RecoveryRows(string Text, long Version, string Bind, string CredentialId, string AuthenticatorData, string ClientData, string Signature,
        IReadOnlyDictionary<string, long> Counts, IReadOnlyDictionary<string, string> Secrets);

    internal RecoveryRows ExportRecoveryRows() => Read(connection =>
    {
        if (connection is null || CurrentManifest(connection, null) is null)
        {
            throw Failed("the recovered store has no manifest");
        }

        using SqliteCommand command = Command(connection, null, "SELECT text, version, bind, credential_id, authenticator_data, client_data, signature FROM manifest");
        using SqliteDataReader reader = command.ExecuteReader();
        reader.Read();
        return new RecoveryRows(reader.GetString(0), reader.GetInt64(1), reader.GetString(2), reader.GetString(3), reader.GetString(4), reader.GetString(5), reader.GetString(6),
            SignCounts(connection, null), SecretStore.AllRows(connection, null));
    });

    internal bool ReplaceRecoveredStore(Manifest expected, IReadOnlyDictionary<string, string> expectedSecrets, RecoveryRows recovered, IReadOnlyList<AdminEvent> events)
        => Write((connection, transaction) =>
    {
        Manifest? current = CurrentManifest(connection, transaction);
        Dictionary<string, string> currentSecrets = SecretStore.AllRows(connection, transaction);
        if (current is null || current.Canonical() != expected.Canonical() || currentSecrets.Count != expectedSecrets.Count
            || expectedSecrets.Any(row => !currentSecrets.TryGetValue(row.Key, out string? value) || value != row.Value))
        {
            return false;
        }

        Execute(connection, transaction, "DELETE FROM manifest; DELETE FROM sign_counts; DELETE FROM secrets;");
        Execute(connection, transaction, "INSERT INTO manifest (id, version, text, bind, credential_id, authenticator_data, client_data, signature) VALUES (1, $version, $text, $bind, $id, $ad, $cd, $sig)",
            ("$version", recovered.Version), ("$text", recovered.Text), ("$bind", recovered.Bind), ("$id", recovered.CredentialId),
            ("$ad", recovered.AuthenticatorData), ("$cd", recovered.ClientData), ("$sig", recovered.Signature));
        foreach ((string id, long count) in recovered.Counts)
        {
            Execute(connection, transaction, "INSERT INTO sign_counts (id, count) VALUES ($id, $count)", ("$id", id), ("$count", count));
        }
        foreach ((string name, string ciphertext) in recovered.Secrets)
        {
            Execute(connection, transaction, "INSERT INTO secrets (name, ciphertext) VALUES ($name, $ciphertext)", ("$name", name), ("$ciphertext", ciphertext));
        }
        if (SecretStore.Problem(CurrentManifest(connection, transaction), SecretStore.AllRows(connection, transaction)) is { } problem)
        {
            throw Failed(problem);
        }
        foreach (AdminEvent item in events)
        {
            AppendAudit(connection, transaction, item);
        }
        return true;
    });

    /// <summary>Runs <paramref name="work" /> on an open connection, or with null when there is no database. Creates nothing.</summary>
    internal T Read<T>(Func<SqliteConnection?, T> work) => Use(() => Database.Read(work));

    /// <summary>One write transaction, committed when <paramref name="work" /> returns. Creates the database when it is missing.</summary>
    internal T Write<T>(Func<SqliteConnection, SqliteTransaction, T> work) => Use(() => Database.Write(work));

    private T Use<T>(Func<T> work)
    {
        try
        {
            return work();
        }
        catch (WithSecretsDatabaseException failure)
        {
            string detail = failure.InvalidLayout ? $"{FailedMessage} ({failure.Message})" : failure.Message;
            throw new StateDatabaseException(detail, failure);
        }
        catch (Exception failure) when (failure is not (StateDatabaseException or OutOfMemoryException))
        {
            throw new StateDatabaseException("the state could not be used", failure);
        }
    }
}

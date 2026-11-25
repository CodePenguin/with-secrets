using System.Text.Json.Nodes;

using Microsoft.Data.Sqlite;

namespace WithSecrets;

/// <summary>A configuration or mount request that is refused (bad name, over the stale cap, duplicate, still referenced). The message never carries configuration content.</summary>
public sealed class ProviderConfigurationException(string message) : Exception(message);

public enum MountKind
{
    Tree,
    Single,
}

public sealed record ProviderInstance(Guid Id, string Name, string ProviderType, string Configuration, TimeSpan MaxStale, int Revision);

public sealed record Mount(Guid Id, Guid InstanceId, MountKind Kind, string LogicalPath, string BasePath);

/// <summary>A provider_cache row as stored (unverified): last_verified is UTC ticks.</summary>
internal sealed record CacheRow(string Ciphertext, long LastVerified, string StorePublicKey, string AuthorityKey, byte[] Signature);

public sealed record NamespaceEntry(Guid MountId, string LogicalPath, string ProviderPath, string ExternalId, string? Description, DescriptionSource DescriptionSource);

/// <summary>Provider instances and mounts in with-secrets.db (schema 7). Every change is one transaction through <see cref="AuthorityStore" />.</summary>
public sealed class ProviderStore(AuthorityStore store)
{
    private readonly object _generationGate = new();
    private readonly Dictionary<Guid, long> _generations = [];

    private const string InstanceColumns = "id, name, provider_type, configuration, max_stale_seconds, revision";
    private const string MountColumns = "id, instance_id, kind, logical_path, base_path";
    private const string EntryColumns = "mount_id, logical_path, provider_path, external_id, description, description_source";
    private const int MaxTreeSegments = 3;

    /// <remarks>
    /// Every writer takes an optional <c>beforeCommit</c>: it runs INSIDE the write transaction after the rows changed, just before the commit (an admin change commits its
    /// audit event there). When it throws, the transaction is rolled back and nothing changed; a generation that moved inside the transaction stays moved (conservative).
    /// </remarks>
    public ProviderInstance AddInstance(string name, string providerType, string configurationJson, TimeSpan maxStale, Action<SqliteConnection, SqliteTransaction>? beforeCommit = null)
    {
        if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(providerType) || name != name.Trim())
        {
            throw new ProviderConfigurationException("An instance needs a name (without leading or trailing whitespace) and a provider type.");
        }

        RequireConfiguration(configurationJson);

        long seconds = Seconds(maxStale);

        return store.WriteTransaction((connection, transaction) =>
        {
            if (WithSecretsDatabase.Scalar(connection, transaction, "SELECT COUNT(*) FROM provider_instances WHERE name = $name", ("$name", name)) is not 0L)
            {
                throw new ProviderConfigurationException($"A provider instance named '{name}' already exists.");
            }

            ProviderInstance created = new(Guid.NewGuid(), name, providerType, configurationJson, maxStale, 1);
            WithSecretsDatabase.Execute(connection, transaction, $"INSERT INTO provider_instances ({InstanceColumns}) VALUES ($id, $name, $type, $config, $stale, 1)",
                ("$id", Id(created.Id)), ("$name", name), ("$type", providerType), ("$config", configurationJson), ("$stale", seconds));
            beforeCommit?.Invoke(connection, transaction);

            return created;
        });
    }

    public ProviderInstance UpdateConfiguration(Guid id, string configurationJson, Action<SqliteConnection, SqliteTransaction>? beforeCommit = null)
    {
        RequireConfiguration(configurationJson);

        return store.WriteTransaction((connection, transaction) =>
        {
            Require(connection, transaction, id);
            WithSecretsDatabase.Execute(connection, transaction, "UPDATE provider_instances SET configuration = $config, revision = revision + 1 WHERE id = $id", ("$config", configurationJson), ("$id", Id(id)));
            beforeCommit?.Invoke(connection, transaction);

            return Require(connection, transaction, id);
        });
    }

    internal static bool HasEncryptedConfigurations(SqliteConnection connection, SqliteTransaction transaction)
        => WithSecretsDatabase.Scalar(connection, transaction,
            "SELECT 1 FROM provider_instances WHERE json_type(configuration, '$.encryptedConfiguration') IS NOT NULL LIMIT 1") is not null;

    /// <summary>Seals provider configurations to the new review key in the caller's manifest rotation transaction.</summary>
    internal static IReadOnlyList<Guid> RekeyConfigurations(SqliteConnection connection, SqliteTransaction transaction,
        string oldReviewPrivate, string newReviewPublic)
    {
        List<ProviderInstance> encrypted = QueryAll(connection, transaction,
            $"SELECT {InstanceColumns} FROM provider_instances WHERE json_type(configuration, '$.encryptedConfiguration') IS NOT NULL",
            ReadInstance);
        foreach (ProviderInstance instance in encrypted)
        {
            string replacement;
            try
            {
                JsonObject configuration = JsonNode.Parse(instance.Configuration)!.AsObject();
                string ciphertext = configuration["encryptedConfiguration"]!.GetValue<string>();
                string plaintext = JweCipher.Instance.Decrypt(oldReviewPrivate, ciphertext);
                configuration["encryptedConfiguration"] = JweCipher.Instance.Encrypt(plaintext, newReviewPublic);
                replacement = configuration.ToJsonString();
            }
            catch (Exception error) when (error is not OutOfMemoryException)
            {
                throw new ProviderConfigurationException("a provider configuration could not be re-encrypted; nothing was changed");
            }

            WithSecretsDatabase.Execute(connection, transaction,
                "UPDATE provider_instances SET configuration = $config, revision = revision + 1 WHERE id = $id",
                ("$config", replacement), ("$id", Id(instance.Id)));
        }

        return [.. encrypted.Select(instance => instance.Id)];
    }


    /// <summary>Updates cache policy, purging the cache when disabled. The configuration revision stays.</summary>
    public ProviderInstance SetMaxStale(Guid id, TimeSpan maxStale, Action<SqliteConnection, SqliteTransaction>? beforeCommit = null)
    {
        long seconds = Seconds(maxStale);

        ProviderInstance changed = store.WriteTransaction((connection, transaction) =>
        {
            Require(connection, transaction, id);
            BumpGeneration(id);
            WithSecretsDatabase.Execute(connection, transaction, "UPDATE provider_instances SET max_stale_seconds = $stale WHERE id = $id", ("$stale", seconds), ("$id", Id(id)));
            if (seconds == 0)
            {
                WithSecretsDatabase.Execute(connection, transaction, "PRAGMA secure_delete = ON");
                DeleteCacheCore(connection, transaction, id, null);
            }
            beforeCommit?.Invoke(connection, transaction);

            return Require(connection, transaction, id);
        });
        BumpGeneration(id);
        return changed;
    }

    /// <summary>
    /// Removes an instance that has no mounts, and its cache rows in the same transaction (the generation moves inside and after it, as for every writer of cached data).
    /// Returns, and passes to <paramref name="beforeCommit" />, the number of cache rows deleted.
    /// </summary>
    public int RemoveInstance(Guid id, Action<SqliteConnection, SqliteTransaction, int>? beforeCommit = null)
    {
        int deleted = store.WriteTransaction((connection, transaction) =>
        {
            Require(connection, transaction, id);
            if (WithSecretsDatabase.Scalar(connection, transaction, "SELECT COUNT(*) FROM mounts WHERE instance_id = $id", ("$id", Id(id))) is not 0L)
            {
                throw new ProviderConfigurationException("The provider instance still has mounts; remove them first.");
            }

            BumpGeneration(id);
            int rows = DeleteCacheCore(connection, transaction, id, null);
            WithSecretsDatabase.Execute(connection, transaction, "DELETE FROM provider_instances WHERE id = $id", ("$id", Id(id)));
            store.Fault?.Invoke("provider-before-commit");
            beforeCommit?.Invoke(connection, transaction, rows);

            return rows;
        });

        BumpGeneration(id);

        return deleted;
    }

    public IReadOnlyList<ProviderInstance> Instances()
    {
        return store.ReadConnection(connection => connection is null ? [] : QueryAll(connection, null, $"SELECT {InstanceColumns} FROM provider_instances ORDER BY name", ReadInstance));
    }

    public ProviderInstance? Instance(Guid id)
    {
        return store.ReadConnection(connection => connection is null ? null : QueryAll(connection, null, $"SELECT {InstanceColumns} FROM provider_instances WHERE id = $id", ReadInstance, ("$id", Id(id))).FirstOrDefault());
    }

    /// <summary>Null when a mount of <paramref name="kind" /> at <paramref name="logicalPath" /> over <paramref name="basePath" /> is well formed, else why not (a constant naming the rule).</summary>
    internal static string? MountProblem(MountKind kind, string? logicalPath, string? basePath)
    {
        if (logicalPath is null || !ValidLogicalPath(kind, logicalPath))
        {
            return kind == MountKind.Single
                ? "An individual mount path must be a valid secret name."
                : $"A tree mount path must be 1 to {MaxTreeSegments} folder names separated by '/', with no trailing '/'.";
        }

        if (basePath is null || kind == MountKind.Single && string.IsNullOrWhiteSpace(basePath))
        {
            return "A mount needs a provider path.";
        }

        return kind == MountKind.Single && (basePath.StartsWith('/') || basePath.EndsWith('/')) ? "An individual mount provider path must not start or end with '/'." : null;
    }

    /// <summary>
    /// Adds a mount. Every active grant naming a name the new mount selects ends (ruling I1); how many is passed to <paramref name="beforeCommit" />, which runs inside the
    /// transaction after the rows changed.
    /// </summary>
    public Mount AddMount(Guid instanceId, MountKind kind, string logicalPath, string basePath, Action<SqliteConnection, SqliteTransaction, int>? beforeCommit = null)
    {
        if (MountProblem(kind, logicalPath, basePath) is { } problem)
        {
            throw new ProviderConfigurationException(problem);
        }

        HashSet<Guid> moved = [];
        Mount added = store.WriteTransaction((connection, transaction) =>
        {
            Require(connection, transaction, instanceId);
            string kindText = kind == MountKind.Tree ? "tree" : "single";
            if (WithSecretsDatabase.Scalar(connection, transaction, "SELECT COUNT(*) FROM mounts WHERE kind = $kind AND logical_path = $path", ("$kind", kindText), ("$path", logicalPath)) is not 0L)
            {
                throw new ProviderConfigurationException($"A {kindText} mount at '{logicalPath}' already exists.");
            }

            Mount created = new(Guid.NewGuid(), instanceId, kind, logicalPath, basePath);
            List<Mount> before = QueryAll(connection, transaction, $"SELECT {MountColumns} FROM mounts", ReadMount);
            Func<string, bool> takes = AddedSelects(before, created);

            // The instances that lose names to the new mount (their entries, or a name an active grant names) and the new mount's own instance move first.
            moved.Add(instanceId);
            foreach (NamespaceEntry entry in QueryAll(connection, transaction, $"SELECT {EntryColumns} FROM namespace_entries", ReadEntry).Where(entry => takes(entry.LogicalPath)))
            {
                moved.Add(before.First(mount => mount.Id == entry.MountId).InstanceId);
            }

            foreach (string name in ActiveGrantNames(connection, transaction).Where(takes))
            {
                if (MountResolver.Resolve(before, name) is { } previous)
                {
                    moved.Add(previous.InstanceId);
                }
            }

            foreach (Guid owner in moved)
            {
                BumpGeneration(owner);
            }

            // A name the new mount selects was served by the native store or another mount: an approval of it named a different secret, so it ends (ruling I1).
            int ended = InvalidateGrantsCore(connection, transaction, takes);
            WithSecretsDatabase.Execute(connection, transaction, $"INSERT INTO mounts ({MountColumns}) VALUES ($id, $instance, $kind, $path, $base)",
                ("$id", Id(created.Id)), ("$instance", Id(instanceId)), ("$kind", kindText), ("$path", logicalPath), ("$base", basePath));
            beforeCommit?.Invoke(connection, transaction, ended);

            return created;
        });

        // Bumped again after the commit (see Generation).
        foreach (Guid owner in moved)
        {
            BumpGeneration(owner);
        }

        return added;
    }

    /// <summary>
    /// Removes the mount and its namespace entries; cache rows stay (they are keyed by instance and external id). Every active grant naming a name the mount
    /// selected ends (with its host notice): that name now falls to the native store or a broader mount, a different secret. The instance generation moves inside
    /// the transaction, so a retrieval in flight for a path of this mount is discarded. How many grants ended is passed to <paramref name="beforeCommit" />.
    /// </summary>
    public void RemoveMount(Guid id, Action<SqliteConnection, SqliteTransaction, int>? beforeCommit = null)
    {
        Guid instanceId = store.WriteTransaction((connection, transaction) =>
        {
            List<Mount> mounts = QueryAll(connection, transaction, $"SELECT {MountColumns} FROM mounts", ReadMount);
            if (mounts.FirstOrDefault(mount => mount.Id == id) is not { } removed)
            {
                throw new ProviderConfigurationException("The mount does not exist.");
            }

            BumpGeneration(removed.InstanceId);

            int ended = InvalidateGrantsCore(connection, transaction, RemovedSelects(mounts, id));
            WithSecretsDatabase.Execute(connection, transaction, "DELETE FROM namespace_entries WHERE mount_id = $id", ("$id", Id(id)));
            WithSecretsDatabase.Execute(connection, transaction, "DELETE FROM mounts WHERE id = $id", ("$id", Id(id)));
            store.Fault?.Invoke("provider-before-commit");
            beforeCommit?.Invoke(connection, transaction, ended);

            return removed.InstanceId;
        });

        // Bumped again after the commit: a snapshot taken between the two bumps reads pre-commit data and must not match (see Generation).
        BumpGeneration(instanceId);
    }

    /// <summary>The number of active grants <see cref="AddMount" /> would end now for a new mount of <paramref name="kind" /> at <paramref name="logicalPath" /> (the same selection, read without changing anything).</summary>
    internal int GrantsEndingOnAdd(Guid instanceId, MountKind kind, string logicalPath)
    {
        return store.ReadConnection(connection =>
        {
            if (connection is null)
            {
                return 0;
            }

            Func<string, bool> takes = AddedSelects(QueryAll(connection, null, $"SELECT {MountColumns} FROM mounts", ReadMount), new Mount(Guid.NewGuid(), instanceId, kind, logicalPath, ""));

            return ActiveGrants(connection, null).Count(grant => grant.Names.Any(takes));
        });
    }

    /// <summary>The number of active grants <see cref="RemoveMount" /> would end now (the same selection, read without changing anything); 0 for an unknown mount.</summary>
    internal int GrantsEndingOnRemove(Guid mountId)
    {
        return store.ReadConnection(connection =>
        {
            if (connection is null)
            {
                return 0;
            }

            List<Mount> mounts = QueryAll(connection, null, $"SELECT {MountColumns} FROM mounts", ReadMount);
            Func<string, bool> selects = RemovedSelects(mounts, mountId);

            return mounts.Any(mount => mount.Id == mountId) ? ActiveGrants(connection, null).Count(grant => grant.Names.Any(selects)) : 0;
        });
    }

    /// <summary>The number of cache rows of an instance (what <see cref="RemoveInstance" /> would delete now).</summary>
    internal int CacheRowCount(Guid instanceId)
    {
        return store.ReadConnection(connection => connection is null ? 0
            : Convert.ToInt32(WithSecretsDatabase.Scalar(connection, null, "SELECT COUNT(*) FROM provider_cache WHERE instance_id = $instance", ("$instance", Id(instanceId))), System.Globalization.CultureInfo.InvariantCulture));
    }

    /// <summary>The names a new mount takes: those it selects once it is beside <paramref name="before" />.</summary>
    private static Func<string, bool> AddedSelects(List<Mount> before, Mount created)
    {
        List<Mount> after = [.. before, created];

        return name => MountResolver.Resolve(after, name)?.Id == created.Id;
    }

    /// <summary>The names a mount gives up when it is removed: those it selects among <paramref name="mounts" />.</summary>
    private static Func<string, bool> RemovedSelects(List<Mount> mounts, Guid id) => name => MountResolver.Resolve(mounts, name)?.Id == id;

    public IReadOnlyList<Mount> Mounts()
    {
        return store.ReadConnection(connection => connection is null ? [] : QueryAll(connection, null, $"SELECT {MountColumns} FROM mounts ORDER BY logical_path, kind", ReadMount));
    }

    /// <summary>The namespace entries of one mount, or of every mount.</summary>
    public IReadOnlyList<NamespaceEntry> Entries(Guid? mountId = null)
    {
        return store.ReadConnection(connection => connection is null ? [] : mountId is { } id
            ? QueryAll(connection, null, $"SELECT {EntryColumns} FROM namespace_entries WHERE mount_id = $mount ORDER BY logical_path", ReadEntry, ("$mount", Id(id)))
            : QueryAll(connection, null, $"SELECT {EntryColumns} FROM namespace_entries ORDER BY mount_id, logical_path", ReadEntry));
    }

    /// <summary>For tests: the entry a logical name resolves to (mount resolution first, then the entry of that mount), or null.</summary>
    internal NamespaceEntry? EntryFor(string logicalPath)
    {
        Mount? mount = MountResolver.Resolve(Mounts(), logicalPath);

        return mount is null ? null : Entries(mount.Id).FirstOrDefault(entry => string.Equals(entry.LogicalPath, logicalPath, StringComparison.Ordinal));
    }

    /// <summary>
    /// The in-memory per-instance generation: it moves whenever cached or listed data of the instance may have changed, so a retrieval that straddles a move is
    /// discarded. A writer bumps it TWICE: inside its write transaction (so a cache write, which compares it inside its own write transaction, cannot interleave)
    /// and again after the commit (reads are not serialized against writes, so a snapshot taken between the first bump and the commit may have read pre-commit
    /// data; the second bump makes every later comparison of that snapshot fail).
    /// </summary>
    public long Generation(Guid instanceId)
    {
        lock (_generationGate)
        {
            return _generations.GetValueOrDefault(instanceId);
        }
    }

    private long BumpGeneration(Guid instanceId)
    {
        lock (_generationGate)
        {
            return _generations[instanceId] = _generations.GetValueOrDefault(instanceId) + 1;
        }
    }

    /// <summary>For tests: replaces every entry of the mount in one transaction (the product writes entries only through a reconciliation).</summary>
    internal void ReplaceEntries(Guid mountId, IReadOnlyList<NamespaceEntry> entries)
    {
        store.WriteTransaction((connection, transaction) =>
        {
            ReplaceEntriesCore(connection, transaction, mountId, entries);

            return 0;
        });
    }

    /// <summary>For tests: deletes cached ciphertext of an instance: the listed external ids, or every row when <paramref name="externalIds" /> is null (the product deletes rows only by reconciliation or invalidation).</summary>
    internal int DeleteCache(Guid instanceId, IReadOnlyCollection<string>? externalIds)
    {
        return store.WriteTransaction((connection, transaction) => DeleteCacheCore(connection, transaction, instanceId, externalIds));
    }

    /// <summary>
    /// The stored cache row of (instance, external id) as written, unverified, or null (also when a column does not hold the type it should). See
    /// <see cref="ProviderCache.TryGet" /> for the only way a row is used.
    /// </summary>
    internal CacheRow? ReadCache(Guid instanceId, string externalId)
    {
        return store.ReadConnection(connection => connection is null ? null : QueryAll(connection, null,
            "SELECT ciphertext, last_verified, store_public_key, authority_key, signature FROM provider_cache WHERE instance_id = $instance AND external_id = $external",
            reader => reader.GetValue(0) is string ciphertext && reader.GetValue(1) is long verified && reader.GetValue(2) is string storeKey && reader.GetValue(3) is string authorityKey
                && reader.GetValue(4) is byte[] signature ? new CacheRow(ciphertext, verified, storeKey, authorityKey, signature) : null,
            ("$instance", Id(instanceId)), ("$external", externalId)).FirstOrDefault());
    }

    /// <summary>
    /// Writes (replaces) cache rows of one instance in one transaction. With <paramref name="expectedGeneration" />, the instance generation is compared INSIDE the
    /// write transaction (invalidations bump it inside theirs, so the two cannot interleave): when it moved, nothing is written (Invalidated). A row is never
    /// replaced by one with an OLDER last_verified (a retrieval that started earlier but commits later): that row is kept and the result is Superseded.
    /// </summary>
    internal CacheWrite WriteCache(Guid instanceId, IReadOnlyList<(string ExternalId, CacheRow Row)> rows, long? expectedGeneration)
    {
        return store.WriteTransaction((connection, transaction) =>
        {
            store.Fault?.Invoke("provider-cache-check");
            if ((expectedGeneration is { } expected && Generation(instanceId) != expected)
                || WithSecretsDatabase.Scalar(connection, transaction,
                    "SELECT max_stale_seconds FROM provider_instances WHERE id = $id", ("$id", Id(instanceId))) is not long maxStaleSeconds
                || maxStaleSeconds <= 0)
            {
                return CacheWrite.Invalidated;
            }

            CacheWrite result = CacheWrite.Written;
            foreach ((string externalId, CacheRow row) in rows)
            {
                int changed = WithSecretsDatabase.Execute(connection, transaction,
                    "INSERT INTO provider_cache (instance_id, external_id, ciphertext, last_verified, store_public_key, authority_key, signature) VALUES ($instance, $external, $ciphertext, $verified, $store, $authority, $signature) "
                    + "ON CONFLICT (instance_id, external_id) DO UPDATE SET ciphertext = excluded.ciphertext, last_verified = excluded.last_verified, store_public_key = excluded.store_public_key, authority_key = excluded.authority_key, signature = excluded.signature "
                    + "WHERE excluded.last_verified >= provider_cache.last_verified",
                    ("$instance", Id(instanceId)), ("$external", externalId), ("$ciphertext", row.Ciphertext), ("$verified", row.LastVerified), ("$store", row.StorePublicKey),
                    ("$authority", row.AuthorityKey), ("$signature", row.Signature));
                if (changed == 0)
                {
                    result = CacheWrite.Superseded;
                }
            }

            store.Fault?.Invoke("provider-cache-before-commit");

            return result;
        });
    }

    /// <summary>Every cache row's key and lastVerified (UTC ticks), unverified: what a refresh pass needs to find the rows that are due. A row whose columns hold the wrong types is left out.</summary>
    internal IReadOnlyList<(Guid InstanceId, string ExternalId, long LastVerified)> CacheIndex()
    {
        return store.ReadConnection(connection => connection is null ? [] : (IReadOnlyList<(Guid InstanceId, string ExternalId, long LastVerified)>)[.. QueryAll(connection, null,
            "SELECT instance_id, external_id, last_verified FROM provider_cache ORDER BY instance_id, external_id",
            reader => reader.GetValue(0) is string instance && Guid.TryParse(instance, out Guid id) && reader.GetValue(1) is string external && reader.GetValue(2) is long verified ? ((Guid, string, long)?)(id, external, verified) : null)
            .Where(row => row is not null).Select(row => row!.Value)]);
    }

    private const string Unreferenced = "FROM provider_cache WHERE NOT EXISTS (SELECT 1 FROM namespace_entries e JOIN mounts m ON m.id = e.mount_id "
        + "WHERE m.instance_id = provider_cache.instance_id AND e.external_id = provider_cache.external_id)";

    /// <summary>
    /// Deletes every cache row that no namespace entry references (a removed mount or a reconciliation of another mount can leave one) and returns how many. Only
    /// when there is one does it write: the generations of the instances it prunes move inside the transaction and after it.
    /// </summary>
    internal int PruneCache()
    {
        if (!store.ReadConnection(connection => connection is not null && QueryAll(connection, null, "SELECT 1 " + Unreferenced + " LIMIT 1", _ => true).Count > 0))
        {
            return 0;
        }

        HashSet<Guid> pruned = [];
        int deleted = store.WriteTransaction((connection, transaction) =>
        {
            foreach (string instance in QueryAll(connection, transaction, "SELECT DISTINCT instance_id " + Unreferenced, reader => reader.GetValue(0) as string ?? ""))
            {
                if (Guid.TryParse(instance, out Guid id) && pruned.Add(id))
                {
                    BumpGeneration(id);
                }
            }

            return WithSecretsDatabase.Execute(connection, transaction, "DELETE " + Unreferenced);
        });

        foreach (Guid id in pruned)
        {
            BumpGeneration(id);
        }

        return deleted;
    }

    /// <summary>A snapshot of every instance's generation (an instance not listed is at 0, as <see cref="Generation" /> says).</summary>
    internal IReadOnlyDictionary<Guid, long> Generations()
    {
        lock (_generationGate)
        {
            return new Dictionary<Guid, long>(_generations);
        }
    }

    /// <summary>
    /// One transaction for a reconciliation: <paramref name="build" /> receives the mount's current entries and returns the new ones; entries that disappear or change
    /// external id lose their grants, and their cache row goes unless another entry of the instance (read in the same transaction) still references it. The
    /// instance generation moves before any write when something was removed or re-identified.
    /// </summary>
    internal (int Added, int Removed, int Changed) ApplyReconciliation(Mount mount, Func<IReadOnlyList<NamespaceEntry>, (IReadOnlyList<NamespaceEntry> Next, int Added, int Changed)> build)
    {
        bool moved = false;
        (int, int, int) done = store.WriteTransaction((connection, transaction) =>
        {
            List<NamespaceEntry> old = QueryAll(connection, transaction, $"SELECT {EntryColumns} FROM namespace_entries WHERE mount_id = $mount", ReadEntry, ("$mount", Id(mount.Id)));
            (IReadOnlyList<NamespaceEntry> next, int added, int changed) = build(old);
            Dictionary<string, NamespaceEntry> nextByPath = next.ToDictionary(entry => entry.LogicalPath, StringComparer.Ordinal);
            List<NamespaceEntry> gone = [.. old.Where(entry => !nextByPath.TryGetValue(entry.LogicalPath, out NamespaceEntry? now) || !string.Equals(now.ExternalId, entry.ExternalId, StringComparison.Ordinal))];
            int removed = old.Count(entry => !nextByPath.ContainsKey(entry.LogicalPath));
            if (gone.Count > 0)
            {
                moved = true;
                BumpGeneration(mount.InstanceId);
            }

            HashSet<string> nextIds = new(next.Select(entry => entry.ExternalId), StringComparer.Ordinal);
            List<string> dropCache = [];
            foreach (string id in gone.Select(entry => entry.ExternalId).Distinct(StringComparer.Ordinal))
            {
                if (!nextIds.Contains(id) && WithSecretsDatabase.Scalar(connection, transaction,
                    "SELECT COUNT(*) FROM namespace_entries e JOIN mounts m ON m.id = e.mount_id WHERE m.instance_id = $instance AND e.mount_id <> $mount AND e.external_id = $external",
                    ("$instance", Id(mount.InstanceId)), ("$mount", Id(mount.Id)), ("$external", id)) is 0L)
                {
                    dropCache.Add(id);
                }
            }

            InvalidateGrantsCore(connection, transaction, [.. gone.Select(entry => entry.LogicalPath)]);
            DeleteCacheCore(connection, transaction, mount.InstanceId, dropCache);
            ReplaceEntriesCore(connection, transaction, mount.Id, next);
            store.Fault?.Invoke("provider-before-commit");

            return (added, removed, changed);
        });

        if (moved)
        {
            BumpGeneration(mount.InstanceId);
        }

        return done;
    }

    /// <summary>One transaction for an adapter's invalidation request. Returns the scope kind, the affected logical paths and the numbers of cache rows and grants dropped.</summary>
    internal (string Scope, IReadOnlyList<string> Paths, int CacheRows, int Grants) ApplyInvalidation(Guid instanceId, InvalidateProviderDataEvent evt,
        Action<SqliteConnection, SqliteTransaction, (string Scope, IReadOnlyList<string> Paths, int CacheRows, int Grants)>? beforeCommit = null)
    {
        (string, IReadOnlyList<string>, int, int) done = store.WriteTransaction((connection, transaction) =>
        {
            BumpGeneration(instanceId);
            HashSet<Guid> instanceMounts = [.. QueryAll(connection, transaction, $"SELECT {MountColumns} FROM mounts WHERE instance_id = $instance", ReadMount, ("$instance", Id(instanceId))).Select(mount => mount.Id)];
            List<NamespaceEntry> all = [.. QueryAll(connection, transaction, $"SELECT {EntryColumns} FROM namespace_entries", ReadEntry).Where(entry => instanceMounts.Contains(entry.MountId))];

            List<NamespaceEntry> affected;
            string scope;
            int cacheRows;
            if (evt.InvalidateEntireProviderInstance)
            {
                scope = "instance";
                affected = all;
                cacheRows = DeleteCacheCore(connection, transaction, instanceId, null);
            }
            else
            {
                HashSet<Guid> mounts = [.. (evt.MountIds ?? []).Where(instanceMounts.Contains)];
                HashSet<string> ids = new(evt.ExternalSecretIds ?? [], StringComparer.Ordinal);
                scope = evt.MountIds is { Count: > 0 } && ids.Count > 0 ? "mounts+external-ids" : ids.Count > 0 ? "external-ids" : "mounts";
                affected = [.. all.Where(entry => mounts.Contains(entry.MountId) || ids.Contains(entry.ExternalId))];

                // A mount-scoped request deletes the cache rows of the selected mounts' external ids, also when another mount's entry shares the row (rows are keyed
                // by instance and external id), but ends grants only for the selected mounts' entries: the other mount's paths just refetch on their next use.
                cacheRows = DeleteCacheCore(connection, transaction, instanceId, [.. affected.Select(entry => entry.ExternalId).Concat(ids)]);
            }

            List<string> paths = [.. affected.Select(entry => entry.LogicalPath).Distinct(StringComparer.Ordinal)];
            int grants = InvalidateGrantsCore(connection, transaction, paths);
            beforeCommit?.Invoke(connection, transaction, (scope, paths, cacheRows, grants));
            store.Fault?.Invoke("provider-before-commit");

            return (scope, paths, cacheRows, grants);
        });

        BumpGeneration(instanceId);

        return done;
    }

    private static void ReplaceEntriesCore(SqliteConnection connection, SqliteTransaction transaction, Guid mountId, IReadOnlyList<NamespaceEntry> entries)
    {
        if (WithSecretsDatabase.Scalar(connection, transaction, "SELECT COUNT(*) FROM mounts WHERE id = $id", ("$id", Id(mountId))) is not 1L)
        {
            throw new ProviderConfigurationException("The mount does not exist.");
        }

        WithSecretsDatabase.Execute(connection, transaction, "DELETE FROM namespace_entries WHERE mount_id = $id", ("$id", Id(mountId)));
        foreach (NamespaceEntry entry in entries)
        {
            WithSecretsDatabase.Execute(connection, transaction, $"INSERT INTO namespace_entries ({EntryColumns}) VALUES ($mount, $logical, $provider, $external, $description, $source)",
                ("$mount", Id(mountId)), ("$logical", entry.LogicalPath), ("$provider", entry.ProviderPath), ("$external", entry.ExternalId), ("$description", entry.Description),
                ("$source", entry.DescriptionSource == DescriptionSource.Local ? "local" : "provider"));
        }
    }

    private static int DeleteCacheCore(SqliteConnection connection, SqliteTransaction transaction, Guid instanceId, IReadOnlyCollection<string>? externalIds)
    {
        if (externalIds is null)
        {
            return WithSecretsDatabase.Execute(connection, transaction, "DELETE FROM provider_cache WHERE instance_id = $instance", ("$instance", Id(instanceId)));
        }

        int deleted = 0;
        foreach (string externalId in externalIds.Distinct(StringComparer.Ordinal))
        {
            deleted += WithSecretsDatabase.Execute(connection, transaction, "DELETE FROM provider_cache WHERE instance_id = $instance AND external_id = $external", ("$instance", Id(instanceId)), ("$external", externalId));
        }

        return deleted;
    }

    private int InvalidateGrantsCore(SqliteConnection connection, SqliteTransaction transaction, IReadOnlyCollection<string> logicalPaths)
    {
        if (logicalPaths.Count == 0)
        {
            return 0;
        }

        HashSet<string> paths = new(logicalPaths, StringComparer.Ordinal);

        return InvalidateGrantsCore(connection, transaction, paths.Contains);
    }

    private static List<(string Id, string Fingerprint, string Scope, int Revision, string[] Names)> ActiveGrants(SqliteConnection connection, SqliteTransaction? transaction)
    {
        return QueryAll(connection, transaction, "SELECT id, fingerprint, scope_key, grant_revision, secret_names FROM grants WHERE status = 'active'",
            reader => (reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetInt32(3), reader.GetString(4).Length == 0 ? [] : reader.GetString(4).Split(", ")));
    }

    private static IEnumerable<string> ActiveGrantNames(SqliteConnection connection, SqliteTransaction transaction)
    {
        return ActiveGrants(connection, transaction).SelectMany(grant => grant.Names).Distinct(StringComparer.Ordinal);
    }

    /// <summary>Ends every active grant that names a secret <paramref name="selects" /> accepts: status invalidated, revision bumped, and a grant event so the host drops it and its key.</summary>
    private int InvalidateGrantsCore(SqliteConnection connection, SqliteTransaction transaction, Func<string, bool> selects)
    {
        string now = store.Timestamp();
        int ended = 0;
        foreach ((string id, string fingerprint, string scope, int revision, string[] names) in ActiveGrants(connection, transaction))
        {
            if (!names.Any(selects))
            {
                continue;
            }

            ended += WithSecretsDatabase.Execute(connection, transaction,
                $"UPDATE grants SET status = 'invalidated', updated = $now, grant_revision = grant_revision + 1, {AuthorityStore.ClearGrantEvidence} WHERE id = $id AND status = 'active'",
                ("$now", now), ("$id", id));
            WithSecretsDatabase.Execute(connection, transaction,
                "INSERT INTO grant_events (fingerprint, grant_id, scope_key, kind, grant_revision, state, created, acknowledged) VALUES ($fp, $id, $scope, 'invalidated', $revision, 'Pending', $now, NULL)",
                ("$fp", fingerprint), ("$id", id), ("$scope", scope), ("$revision", revision + 1), ("$now", now));
        }

        return ended;
    }

    internal static bool ValidLogicalPath(MountKind kind, string path)
    {
        if (kind == MountKind.Single)
        {
            return SecretNames.IsValid(path);
        }

        string[] segments = path.Split('/');

        return segments.Length is >= 1 and <= MaxTreeSegments && segments.All(SecretNames.IsFolderSegment);
    }

    private static void RequireConfiguration(string? configurationJson)
    {
        if (string.IsNullOrWhiteSpace(configurationJson))
        {
            throw new ProviderConfigurationException("An instance needs a configuration.");
        }
    }

    private static long Seconds(TimeSpan maxStale)
    {
        if (ProviderPolicy.ValidateMaxStale(maxStale) is { } problem)
        {
            throw new ProviderConfigurationException(problem);
        }

        if (maxStale.Ticks % TimeSpan.TicksPerSecond != 0)
        {
            throw new ProviderConfigurationException("MaxStaleDuration must be a whole number of seconds.");
        }

        return maxStale.Ticks / TimeSpan.TicksPerSecond;
    }

    private static string Id(Guid id) => id.ToString("D");

    private static ProviderInstance Require(SqliteConnection connection, SqliteTransaction transaction, Guid id)
    {
        return QueryAll(connection, transaction, $"SELECT {InstanceColumns} FROM provider_instances WHERE id = $id", ReadInstance, ("$id", Id(id))).FirstOrDefault()
            ?? throw new ProviderConfigurationException("The provider instance does not exist.");
    }

    private static ProviderInstance ReadInstance(SqliteDataReader reader)
    {
        return new ProviderInstance(Guid.Parse(reader.GetString(0)), reader.GetString(1), reader.GetString(2), reader.GetString(3), TimeSpan.FromSeconds(reader.GetInt64(4)), reader.GetInt32(5));
    }

    private static Mount ReadMount(SqliteDataReader reader)
    {
        return new Mount(Guid.Parse(reader.GetString(0)), Guid.Parse(reader.GetString(1)), reader.GetString(2) == "tree" ? MountKind.Tree : MountKind.Single, reader.GetString(3), reader.GetString(4));
    }

    private static NamespaceEntry ReadEntry(SqliteDataReader reader)
    {
        return new NamespaceEntry(Guid.Parse(reader.GetString(0)), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.IsDBNull(4) ? null : reader.GetString(4),
            reader.GetString(5) == "local" ? DescriptionSource.Local : DescriptionSource.Provider);
    }

    private static List<T> QueryAll<T>(SqliteConnection connection, SqliteTransaction? transaction, string sql, Func<SqliteDataReader, T> read, params (string Name, object? Value)[] parameters)
    {
        using SqliteCommand command = WithSecretsDatabase.Command(connection, transaction, sql, parameters);
        using SqliteDataReader reader = command.ExecuteReader();
        List<T> rows = [];
        while (reader.Read())
        {
            rows.Add(read(reader));
        }

        return rows;
    }
}

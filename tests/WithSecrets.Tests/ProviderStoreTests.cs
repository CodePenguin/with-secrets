using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>Provider instances, mounts and the resolver on with-secrets.db (10.3.2).</summary>
internal static class ProviderStoreTests
{
    public static Task Run(Action<bool, string> check)
    {
        string folder = Path.Combine(Path.GetTempPath(), "ws-providerstore-" + Guid.NewGuid().ToString("N"));
        try
        {
            Schema(check, folder);
            Instances(check, folder);
            Mounts(check, folder);
            Resolver(check);
            Persistence(check, folder);
            Integrity(check, folder);
            RemovedInstanceCache(check, folder);
        }
        finally
        {
            try
            {
                Directory.Delete(folder, true);
            }
            catch (IOException)
            {
            }
        }

        return Task.CompletedTask;
    }

    private static ProviderStore Fresh(string folder, string name)
    {
        return new ProviderStore(AuthorityStore.InFolder(Path.Combine(folder, name)));
    }

    private static object? Scalar(string file, string sql)
    {
        using SqliteConnection connection = new("Data Source=" + file + ";Pooling=False");
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;

        return command.ExecuteScalar();
    }

    private static void Exec(string file, string sql)
    {
        using SqliteConnection connection = new("Data Source=" + file + ";Pooling=False");
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static bool Throws<T>(Action action) where T : Exception
    {
        try
        {
            action();
        }
        catch (T)
        {
            return true;
        }

        return false;
    }

    private static void Schema(Action<bool, string> check, string folder)
    {
        string dir = Path.Combine(folder, "schema");
        AuthorityStore store = AuthorityStore.InFolder(dir);
        new ProviderStore(store).AddInstance("one", "fake", "{}", TimeSpan.Zero);
        string file = store.FilePath;
        long tables = Convert.ToInt64(Scalar(file, "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('provider_instances','mounts','namespace_entries','provider_cache')"));
        check(WithSecretsDatabase.SchemaVersion == 3 && Convert.ToInt32(Scalar(file, "SELECT version FROM schema_version")) == 3 && tables == 4, "provider store: schema 3 is created with the four provider tables");

        Exec(file, "UPDATE schema_version SET version = 6");
        AuthorityDatabaseException? old = null;
        try
        {
            AuthorityStore.InFolder(dir).Machines();
        }
        catch (AuthorityDatabaseException error)
        {
            old = error;
        }

        check(old is not null && old.Message == "with-secrets.db is not of schema version 3; delete with-secrets.db to start over", "provider store: a schema 6 file is refused with the delete message (" + old?.Message + ")");
        check(Throws<AuthorityDatabaseException>(() => new ProviderStore(AuthorityStore.InFolder(dir)).Instances()), "provider store: a schema 6 file is refused for provider reads too");
    }

    private static void Instances(Action<bool, string> check, string folder)
    {
        ProviderStore providers = Fresh(folder, "instances");
        ProviderInstance one = providers.AddInstance("one", "fake", """{"a":1}""", TimeSpan.Zero);
        check(one.MaxStale == TimeSpan.Zero && one.Revision == 1 && providers.Instance(one.Id) == one && providers.Instances().Count == 1, "provider store: max stale default 0 stored, revision starts at 1");

        ProviderInstance day = providers.AddInstance("day", "fake", "{}", TimeSpan.FromHours(24));
        check(day.MaxStale == TimeSpan.FromHours(24), "provider store: max stale 24h accepted");
        check(Throws<ProviderConfigurationException>(() => providers.AddInstance("over", "fake", "{}", TimeSpan.FromHours(24) + TimeSpan.FromSeconds(1))), "provider store: 24h+1s rejected on add");
        check(Throws<ProviderConfigurationException>(() => providers.SetMaxStale(one.Id, TimeSpan.FromHours(24) + TimeSpan.FromSeconds(1))) && providers.Instance(one.Id) == one, "provider store: 24h+1s rejected on SetMaxStale and the row is unchanged");
        check(Throws<ProviderConfigurationException>(() => providers.SetMaxStale(one.Id, TimeSpan.FromSeconds(-1))) && providers.Instances().Count == 2, "provider store: negative max stale rejected");

        ProviderInstance set = providers.SetMaxStale(one.Id, TimeSpan.FromMinutes(5));
        check(set.MaxStale == TimeSpan.FromMinutes(5) && set.Revision == one.Revision && set.Configuration == one.Configuration && set.Name == one.Name && set.ProviderType == one.ProviderType && providers.Instance(one.Id) == set, "provider store: SetMaxStale changes only that column and keeps the revision");

        ProviderInstance updated = providers.UpdateConfiguration(one.Id, """{"a":2}""");
        check(updated.Revision == set.Revision + 1 && updated.Configuration == """{"a":2}""" && updated.MaxStale == set.MaxStale && providers.Instance(one.Id) == updated, "provider store: UpdateConfiguration bumps the revision");
        check(Throws<ProviderConfigurationException>(() => providers.UpdateConfiguration(Guid.NewGuid(), "{}")) && Throws<ProviderConfigurationException>(() => providers.SetMaxStale(Guid.NewGuid(), TimeSpan.Zero)), "provider store: an unknown instance is rejected");

        check(Throws<ProviderConfigurationException>(() => providers.AddInstance("one", "other", "{}", TimeSpan.Zero)) && providers.Instances().Count == 2, "provider store: duplicate instance name rejected");
        check(Throws<ProviderConfigurationException>(() => providers.SetMaxStale(one.Id, TimeSpan.FromMilliseconds(500))) && providers.Instance(one.Id) == updated, "provider store: a sub-second max stale (500 ms) is rejected, row unchanged");
        check(Throws<ProviderConfigurationException>(() => providers.AddInstance("half", "fake", "{}", TimeSpan.FromMilliseconds(500))), "provider store: a sub-second max stale (500 ms) is rejected on add");
        check(Throws<ProviderConfigurationException>(() => providers.AddInstance(" lead", "fake", "{}", TimeSpan.Zero)) && Throws<ProviderConfigurationException>(() => providers.AddInstance("trail ", "fake", "{}", TimeSpan.Zero))
            && Throws<ProviderConfigurationException>(() => providers.AddInstance("", "fake", "{}", TimeSpan.Zero)) && Throws<ProviderConfigurationException>(() => providers.AddInstance("  ", "fake", "{}", TimeSpan.Zero)), "provider store: names with leading or trailing whitespace, or empty, rejected");
        check(Throws<ProviderConfigurationException>(() => providers.AddInstance("cfg", "fake", " ", TimeSpan.Zero)) && Throws<ProviderConfigurationException>(() => providers.AddInstance("cfg", "fake", null!, TimeSpan.Zero))
            && Throws<ProviderConfigurationException>(() => providers.UpdateConfiguration(one.Id, "")) && Throws<ProviderConfigurationException>(() => providers.UpdateConfiguration(one.Id, null!)), "provider store: empty, whitespace or null configuration rejected");
        check(Throws<ProviderConfigurationException>(() => providers.RemoveInstance(Guid.NewGuid())) && Throws<ProviderConfigurationException>(() => providers.RemoveMount(Guid.NewGuid())), "provider store: removing an unknown instance or mount is rejected");

        Mount mount = providers.AddMount(one.Id, MountKind.Tree, "team", "base");
        check(Throws<ProviderConfigurationException>(() => providers.RemoveInstance(one.Id)) && providers.Instance(one.Id) is not null, "provider store: remove instance blocked while a mount references it");
        providers.RemoveMount(mount.Id);
        providers.RemoveInstance(one.Id);
        check(providers.Instance(one.Id) is null && providers.Instances().Count == 1, "provider store: remove instance allowed after RemoveMount");
        check(Throws<ProviderConfigurationException>(() => providers.AddMount(one.Id, MountKind.Tree, "gone", "b")), "provider store: a mount for an unknown instance is rejected");
    }

    /// <summary>Final review M3: removing an instance deletes its cache rows in the same transaction (and moves its generation inside and after it).</summary>
    private static void RemovedInstanceCache(Action<bool, string> check, string folder)
    {
        AuthorityStore authority = AuthorityStore.InFolder(Path.Combine(folder, "removed-cache"));
        ProviderStore providers = new(authority);
        ProviderInstance gone = providers.AddInstance("gone", "fake", "{}", TimeSpan.Zero);
        ProviderInstance kept = providers.AddInstance("kept", "fake", "{}", TimeSpan.Zero);
        foreach ((Guid instance, string external) in new[] { (gone.Id, "e1"), (gone.Id, "e2"), (kept.Id, "e1") })
        {
            Exec(authority.FilePath, $"INSERT INTO provider_cache (instance_id, external_id, ciphertext, last_verified, store_public_key, authority_key, signature) VALUES ('{instance:D}', '{external}', 'c', 1, 'k', 'a', x'00')");
        }

        long before = providers.Generation(gone.Id);
        long inside = -1;
        authority.Fault = point => inside = point == "provider-before-commit" ? providers.Generation(gone.Id) : inside;
        providers.RemoveInstance(gone.Id);
        authority.Fault = null;
        check(Convert.ToInt64(Scalar(authority.FilePath, $"SELECT COUNT(*) FROM provider_cache WHERE instance_id = '{gone.Id:D}'")) == 0
            && Convert.ToInt64(Scalar(authority.FilePath, $"SELECT COUNT(*) FROM provider_cache WHERE instance_id = '{kept.Id:D}'")) == 1, "provider store: removing an instance deletes its cache rows, only its");
        check(inside == before + 1 && providers.Generation(gone.Id) == before + 2, "provider store: removing an instance moves its generation inside and after the transaction");
    }

    private static void Mounts(Action<bool, string> check, string folder)
    {
        ProviderStore providers = Fresh(folder, "mounts");
        ProviderInstance instance = providers.AddInstance("i", "fake", "{}", TimeSpan.Zero);
        Mount tree = providers.AddMount(instance.Id, MountKind.Tree, "team/dev", "vault/dev");
        check(tree.Kind == MountKind.Tree && tree.LogicalPath == "team/dev" && tree.BasePath == "vault/dev" && providers.Mounts().Single() == tree, "provider store: a tree mount is stored");
        check(Throws<ProviderConfigurationException>(() => providers.AddMount(instance.Id, MountKind.Tree, "team/dev", "other")), "provider store: tree mount overlap at the same path rejected");
        Mount single = providers.AddMount(instance.Id, MountKind.Single, "team/dev/GITHUB", "vault/dev/gh");
        check(single.Kind == MountKind.Single && providers.Mounts().Count == 2, "provider store: a single mount inside a tree mount is allowed");
        check(Throws<ProviderConfigurationException>(() => providers.AddMount(instance.Id, MountKind.Single, "team/dev/GITHUB", "x")), "provider store: single mount at the same path rejected");
        check(providers.AddMount(instance.Id, MountKind.Single, "team/dev", "x").Kind == MountKind.Single, "provider store: a single and a tree may share a path string (different kinds)");

        string[] badTree = ["", "/team", "team/..", "a/b/c/d", "team/", "a//b", "a b", "../x", "."];
        bool treesRejected = badTree.All(path => Throws<ProviderConfigurationException>(() => providers.AddMount(instance.Id, MountKind.Tree, path, "b")));
        check(treesRejected, "provider store: invalid tree paths rejected (empty, leading slash, '..', 4 segments, trailing slash, empty segment, space, '.')");
        check(providers.AddMount(instance.Id, MountKind.Tree, "a/b/c", "b").Kind == MountKind.Tree, "provider store: a three segment tree path is accepted");
        string[] badSingle = ["", "/NAME", "team/../NAME", "a/b/c/d/NAME", "team/NAME/", "1bad"];
        check(badSingle.All(path => Throws<ProviderConfigurationException>(() => providers.AddMount(instance.Id, MountKind.Single, path, "b"))), "provider store: invalid single names rejected (empty, leading slash, '..', 5 segments, trailing slash, bad leaf)");

        check(Throws<ProviderConfigurationException>(() => providers.AddMount(instance.Id, MountKind.Single, "team/dev/A", " ")) && Throws<ProviderConfigurationException>(() => providers.AddMount(instance.Id, MountKind.Single, "team/dev/A", null!))
            && Throws<ProviderConfigurationException>(() => providers.AddMount(instance.Id, MountKind.Tree, "t", null!)), "provider store: a null or blank single base path, or a null tree base path, rejected");
        providers.RemoveMount(single.Id);
        check(providers.Mounts().All(mount => mount.Id != single.Id), "provider store: RemoveMount removes the mount");
    }

    private static Mount M(MountKind kind, string path) => new(Guid.NewGuid(), Guid.NewGuid(), kind, path, "b");

    private static void Resolver(Action<bool, string> check)
    {
        Mount tree = M(MountKind.Tree, "team");
        Mount deep = M(MountKind.Tree, "team/dev");
        Mount single = M(MountKind.Single, "team/dev/GITHUB");
        IReadOnlyList<Mount> all = [tree, deep, single];
        check(MountResolver.Resolve(all, "team/dev/GITHUB") == single, "resolver: exact single beats tree");
        check(MountResolver.Resolve(all, "team/dev/OTHER") == deep && MountResolver.Resolve(all, "team/OTHER") == tree, "resolver: longest prefix wins");
        check(MountResolver.Resolve([deep], "team/development/GITHUB") is null && MountResolver.Resolve([deep], "team/dev/GITHUB") == deep, "resolver: segment boundary respected (team/dev vs team/development)");
        check(MountResolver.Resolve(all, "other/NAME") is null && MountResolver.Resolve([], "NAME") is null && MountResolver.Resolve(all, "NAME") is null, "resolver: no match returns null");
        check(MountResolver.Resolve([deep], "team/dev") is null, "resolver: a tree mount does not match its own folder path as a name");
        check(MountResolver.Resolve([M(MountKind.Single, "team/dev")], "team/dev") is not null, "resolver: a single mount matches its own path");
    }

    private static void Persistence(Action<bool, string> check, string folder)
    {
        string dir = Path.Combine(folder, "persist");
        ProviderStore first = new(AuthorityStore.InFolder(dir));
        ProviderInstance instance = first.AddInstance("i", "fake", """{"k":"v"}""", TimeSpan.FromMinutes(30));
        Mount tree = first.AddMount(instance.Id, MountKind.Tree, "team", "base");
        Mount single = first.AddMount(instance.Id, MountKind.Single, "team/X", "p/x");
        ProviderStore second = new(AuthorityStore.InFolder(dir));
        check(second.Instances().Single() == instance && second.Instance(instance.Id) == instance, "provider store: persist then reopen gives the same instance");
        check(second.Mounts().OrderBy(mount => mount.LogicalPath, StringComparer.Ordinal).SequenceEqual(new[] { tree, single }.OrderBy(mount => mount.LogicalPath, StringComparer.Ordinal)), "provider store: persist then reopen gives the same mounts");
    }

    private static void Integrity(Action<bool, string> check, string folder)
    {
        AuthorityStore store = AuthorityStore.InFolder(Path.Combine(folder, "integrity"));
        ProviderStore providers = new(store);
        ProviderInstance instance = providers.AddInstance("i", "fake", "{}", TimeSpan.Zero);
        Mount mount = providers.AddMount(instance.Id, MountKind.Tree, "team", "b");

        bool Fails(string sql)
        {
            try
            {
                store.WriteTransaction((connection, transaction) => WithSecretsDatabase.Execute(connection, transaction, sql));
            }
            catch (AuthorityDatabaseException)
            {
                return true;
            }
            catch (SqliteException)
            {
                return true;
            }

            return false;
        }

        string ghost = Guid.NewGuid().ToString("D");
        check(Fails($"INSERT INTO mounts (id, instance_id, kind, logical_path, base_path) VALUES ('{Guid.NewGuid():D}', '{ghost}', 'tree', 'x', 'b')"), "provider store: foreign keys on, a mount for an unknown instance fails");
        check(Fails($"INSERT INTO namespace_entries (mount_id, logical_path, provider_path, external_id, description_source) VALUES ('{ghost}', 'x/A', 'a', 'e', 'provider')"), "provider store: foreign keys on, an entry for an unknown mount fails");
        check(Fails($"DELETE FROM provider_instances WHERE id = '{instance.Id:D}'") && providers.Instance(instance.Id) is not null, "provider store: foreign keys on, deleting a referenced instance fails");
        check(!Fails($"INSERT INTO namespace_entries (mount_id, logical_path, provider_path, external_id, description_source) VALUES ('{mount.Id:D}', 'team/A', 'a', 'e', 'provider')"), "provider store: a valid entry is accepted");
    }
}

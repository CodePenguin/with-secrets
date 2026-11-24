using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;

namespace WithSecrets.Tests;

/// <summary>Namespace reconciliation and provider-data invalidation (10.3, 10.3.1).</summary>
internal static class ProviderNamespaceTests
{
    private sealed class CaptureLogger : ILogger
    {
        public List<string> Lines { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) => Lines.Add(formatter(state, exception));
    }

    private sealed class Rig : IDisposable
    {
        private readonly string _folder = Path.Combine(Path.GetTempPath(), "ws-providerns-" + Guid.NewGuid().ToString("N"));

        public Rig()
        {
            Authority = AuthorityStore.InFolder(_folder);
            Store = new ProviderStore(Authority);
            Instance = Store.AddInstance("one", "fake", "{}", TimeSpan.Zero);
            Adapter = new FakeProviderAdapter();
            Reconciler = new NamespaceReconciler(Store, _ => Adapter, Log);
            List<(string Event, IReadOnlyDictionary<string, string> Data)> audits = [];
            Audits = audits;
            Invalidation = new ProviderInvalidation(Store, (name, data) => audits.Add((name, data)));
        }

        public AuthorityStore Authority { get; }

        public ProviderStore Store { get; }

        public ProviderInstance Instance { get; }

        public FakeProviderAdapter Adapter { get; }

        public CaptureLogger Log { get; } = new();

        public NamespaceReconciler Reconciler { get; }

        public ProviderInvalidation Invalidation { get; }

        public List<(string Event, IReadOnlyDictionary<string, string> Data)> Audits { get; }

        public void List(params (string Path, string Id, string? Description)[] items)
        {
            Adapter.ListHandler = (_, _) => Task.FromResult(new ListSecretsResult([.. items.Select(item => new ProviderSecretInfo(item.Path, item.Id, item.Description))], null, true));
        }

        public void Exec(string sql)
        {
            using SqliteConnection connection = new("Data Source=" + Authority.FilePath + ";Pooling=False");
            connection.Open();
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = sql;
            command.ExecuteNonQuery();
        }

        public long Count(string sql)
        {
            using SqliteConnection connection = new("Data Source=" + Authority.FilePath + ";Pooling=False");
            connection.Open();
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = sql;

            return Convert.ToInt64(command.ExecuteScalar());
        }

        public void Grant(string id, string names, string status = "active")
        {
            Exec($"INSERT INTO grants (id, fingerprint, scope_key, program, working_directory, secret_names, created, updated, grant_revision, security_revision, status, approved_by, usage) VALUES ('{id}', 'fp', 'scope', 'p', 'd', '{names}', 't', 't', 1, 1, '{status}', 'x', 'reusable')");
        }

        public string GrantStatus(string id)
        {
            using SqliteConnection connection = new("Data Source=" + Authority.FilePath + ";Pooling=False");
            connection.Open();
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = $"SELECT status FROM grants WHERE id = '{id}'";

            return (string)command.ExecuteScalar()!;
        }

        public void Cache(string externalId)
        {
            Exec($"INSERT INTO provider_cache (instance_id, external_id, ciphertext, last_verified, store_public_key, authority_key, signature) VALUES ('{Instance.Id:D}', '{externalId}', 'c', 1, 'k', 'a', x'00')");
        }

        public bool Cached(string externalId) => Count($"SELECT COUNT(*) FROM provider_cache WHERE external_id = '{externalId}'") == 1;

        public void Dispose()
        {
            try
            {
                Directory.Delete(_folder, true);
            }
            catch (IOException)
            {
            }
        }
    }

    public static async Task Run(Action<bool, string> check)
    {
        await Population(check);
        await Incomplete(check);
        await Atomicity(check);
        await Generation(check);
        Mounts(check);
        await Removal(check);
        await Descriptions(check);
        Invalidation(check);
        MountGrants(check);
    }

    /// <summary>Final review I1: a mount change that moves a name to another source ends the active grants naming it, so an old approval never releases a different secret.</summary>
    private static void MountGrants(Action<bool, string> check)
    {
        using Rig rig = new();
        Mount tree = rig.Store.AddMount(rig.Instance.Id, MountKind.Tree, "team/dev", "kv");
        rig.Store.ReplaceEntries(tree.Id, [new NamespaceEntry(tree.Id, "team/dev/GITHUB", "kv/GITHUB", "ext-gh", null, DescriptionSource.Provider)]);
        rig.Grant("g-mounted", "team/dev/GITHUB");
        rig.Grant("g-selected-no-entry", "team/dev/OTHER");
        rig.Grant("g-unrelated", "team/ops/GITHUB, NATIVE");
        long before = rig.Store.Generation(rig.Instance.Id);
        long inside = -1;
        rig.Authority.Fault = point => inside = point == "provider-before-commit" ? rig.Store.Generation(rig.Instance.Id) : inside;
        rig.Store.RemoveMount(tree.Id);
        rig.Authority.Fault = null;
        check(rig.GrantStatus("g-mounted") == "invalidated" && rig.GrantStatus("g-selected-no-entry") == "invalidated" && rig.GrantStatus("g-unrelated") == "active",
            "namespace: removing a mount invalidates the active grants naming the names it selected, only those");
        check(rig.Authority.PendingGrantEvents("fp") is { Count: 2 } removed && removed.All(e => e.Kind == "invalidated" && e.GrantRevision == 2)
            && removed.Select(e => e.GrantId).Order().SequenceEqual(["g-mounted", "g-selected-no-entry"]), "namespace: mount removal queues the host notice per grant (revision bumped)");
        check(rig.Store.EntryFor("team/dev/GITHUB") is null && MountResolver.Resolve(rig.Store.Mounts(), "team/dev/GITHUB") is null
            && rig.Count("SELECT COUNT(*) FROM grants WHERE status = 'active' AND secret_names LIKE '%team/dev/GITHUB%'") == 0,
            "namespace: after removal the name falls to the native store and no active grant names it (a new approval is needed)");
        check(inside == before + 1 && rig.Store.Generation(rig.Instance.Id) == before + 2, "namespace: mount removal moves the generation inside and after its transaction");

        // AddMount: a tree mount that shadows a native name, and a more specific mount over a broader one.
        using Rig add = new();
        ProviderInstance other = add.Store.AddInstance("two", "fake", "{}", TimeSpan.Zero);
        Mount broad = add.Store.AddMount(other.Id, MountKind.Tree, "team", "kv");
        add.Store.ReplaceEntries(broad.Id, [new NamespaceEntry(broad.Id, "team/dev/X", "kv/dev/X", "ext-x", null, DescriptionSource.Provider)]);
        add.Grant("g-native", "app/GITHUB");
        add.Grant("g-broad", "team/dev/X");
        add.Grant("g-keep", "team/ops/Y, NATIVE_ONE");
        add.Grant("g-revoked", "app/GITHUB", "revoked");
        long otherBefore = add.Store.Generation(other.Id);
        long mineBefore = add.Store.Generation(add.Instance.Id);
        add.Store.AddMount(add.Instance.Id, MountKind.Tree, "app", "vault/app");
        check(add.GrantStatus("g-native") == "invalidated" && add.GrantStatus("g-broad") == "active" && add.GrantStatus("g-keep") == "active" && add.GrantStatus("g-revoked") == "revoked",
            "namespace: adding a tree mount that shadows a native name invalidates the active grants naming it, only those");
        check(add.Authority.PendingGrantEvents("fp") is [{ GrantId: "g-native", Kind: "invalidated", GrantRevision: 2 }], "namespace: a shadowing AddMount queues the host notice");
        check(add.Store.Generation(add.Instance.Id) == mineBefore + 2, "namespace: AddMount moves the new mount's instance generation inside and after its transaction");

        add.Store.AddMount(add.Instance.Id, MountKind.Tree, "team/dev", "vault/dev");
        check(add.GrantStatus("g-broad") == "invalidated" && add.GrantStatus("g-keep") == "active" && add.Store.Generation(other.Id) == otherBefore + 2,
            "namespace: a more specific mount over a broader one invalidates the grants of the names it takes over and moves the previous owner's generation");

        add.Grant("g-single", "team/ops/Y");
        add.Store.AddMount(add.Instance.Id, MountKind.Single, "team/ops/Z", "vault/z");
        check(add.GrantStatus("g-single") == "active" && add.GrantStatus("g-keep") == "active", "namespace: a mount that takes over no granted name leaves every grant active");
        add.Store.AddMount(add.Instance.Id, MountKind.Single, "team/ops/Y", "vault/y");
        check(add.GrantStatus("g-single") == "invalidated" && add.GrantStatus("g-keep") == "invalidated", "namespace: an individual mount inside a tree mount invalidates the grants naming its path");
    }

    private static async Task Population(Action<bool, string> check)
    {
        using Rig tree = new();
        Mount mount = tree.Store.AddMount(tree.Instance.Id, MountKind.Tree, "team/db", "vault/db");
        tree.List(("user", "id-1", "the user"), ("pass", "id-2", null));
        ReconcileResult result = await tree.Reconciler.ReconcileAsync(mount, CancellationToken.None);
        IReadOnlyList<NamespaceEntry> entries = tree.Store.Entries(mount.Id);
        check(result == new ReconcileResult(true, 2, 0, 0) && entries.Count == 2 && entries.Any(entry => entry.LogicalPath == "team/db/user" && entry.ExternalId == "id-1" && entry.ProviderPath == "vault/db/user" && entry.Description == "the user"),
            "namespace: tree mount populates entries with logical = mount + relative path (" + result + ")");
        check(tree.Adapter.ListRequests is [{ Path: "vault/db", Filter: null, ContinuationToken: null }] && tree.Store.EntryFor("team/db/pass")?.ExternalId == "id-2" && tree.Store.EntryFor("team/db/none") is null,
            "namespace: the tree scope is listed once with the base path and no filter; EntryFor resolves through the mount");

        using Rig single = new();
        Mount one = single.Store.AddMount(single.Instance.Id, MountKind.Single, "api_key", "vault/app/key");
        single.List(("key", "id-9", "d"));
        ReconcileResult result2 = await single.Reconciler.ReconcileAsync(one, CancellationToken.None);
        check(result2.Complete && single.Store.EntryFor("api_key") is { ExternalId: "id-9", ProviderPath: "vault/app/key" }
            && single.Adapter.ListRequests is [{ Path: "vault/app", Filter: "key" }],
            "namespace: single mount resolves its external id from a filtered parent listing");

        using Rig paged = new();
        Mount pm = paged.Store.AddMount(paged.Instance.Id, MountKind.Tree, "p", "base");
        List<string?> tokens = [];
        paged.Adapter.ListHandler = (request, _) =>
        {
            tokens.Add(request.ContinuationToken);

            return Task.FromResult(request.ContinuationToken switch
            {
                null => new ListSecretsResult([new ProviderSecretInfo("a", "1", null)], "tok/1==", false),
                "tok/1==" => new ListSecretsResult([new ProviderSecretInfo("b", "2", null)], "tok-2", false),
                _ => new ListSecretsResult([new ProviderSecretInfo("c", "3", null)], null, true),
            });
        };
        ReconcileResult result3 = await paged.Reconciler.ReconcileAsync(pm, CancellationToken.None);
        check(result3.Complete && result3.Added == 3 && tokens.SequenceEqual([null, "tok/1==", "tok-2"]), "namespace: paged listing passes continuation tokens through unchanged");
    }

    private static bool Intact(Rig rig, Mount mount) => rig.Store.Entries(mount.Id).Count == 1 && rig.Cached("1") && rig.GrantStatus("g") == "active" && rig.Count("SELECT COUNT(*) FROM grant_events") == 0;

    private static async Task Incomplete(Action<bool, string> check)
    {
        using Rig rig = new();
        Mount mount = rig.Store.AddMount(rig.Instance.Id, MountKind.Tree, "t", "b");
        rig.List(("a", "1", null));
        await rig.Reconciler.ReconcileAsync(mount, CancellationToken.None);
        rig.Cache("1");
        rig.Grant("g", "t/a");

        rig.Adapter.ListHandler = (_, _) => Task.FromResult(new ListSecretsResult([], null, false));
        ReconcileResult incomplete = await rig.Reconciler.ReconcileAsync(mount, CancellationToken.None);
        check(!incomplete.Complete && Intact(rig, mount), "namespace: an incomplete listing leaves entries, cache and grants untouched");

        int calls = 0;
        rig.Adapter.ListHandler = (_, _) => Task.FromResult(++calls == 1 ? new ListSecretsResult([], "more", false) : new ListSecretsResult([], null, false));
        ReconcileResult pagedIncomplete = await rig.Reconciler.ReconcileAsync(mount, CancellationToken.None);
        check(!pagedIncomplete.Complete && Intact(rig, mount), "namespace: a final page that is not complete leaves entries, cache and grants untouched");

        rig.Adapter.ListHandler = (_, _) => throw new ProviderAdapterException(ProviderErrorKind.Unavailable, "down");
        bool failed = false;
        try
        {
            await rig.Reconciler.ReconcileAsync(mount, CancellationToken.None);
        }
        catch (ProviderAdapterException)
        {
            failed = true;
        }

        check(failed && Intact(rig, mount), "namespace: a failed listing leaves entries, cache and grants untouched");

        rig.List();
        using CancellationTokenSource cancelled = new();
        await cancelled.CancelAsync();
        bool cancelThrew = false;
        try
        {
            await rig.Reconciler.ReconcileAsync(mount, cancelled.Token);
        }
        catch (OperationCanceledException)
        {
            cancelThrew = true;
        }

        check(cancelThrew && Intact(rig, mount), "namespace: a cancelled listing leaves entries, cache and grants untouched");

        // Cancelled during the final page: the complete (empty) listing is not applied.
        using CancellationTokenSource late = new();
        rig.Adapter.ListHandler = (_, _) =>
        {
            late.Cancel();

            return Task.FromResult(new ListSecretsResult([], null, true));
        };
        bool lateThrew = false;
        try
        {
            await rig.Reconciler.ReconcileAsync(mount, late.Token);
        }
        catch (OperationCanceledException)
        {
            lateThrew = true;
        }

        check(lateThrew && Intact(rig, mount), "namespace: cancellation after the last page and before the write applies nothing");
    }

    private static async Task Atomicity(Action<bool, string> check)
    {
        using Rig rig = new();
        Mount mount = rig.Store.AddMount(rig.Instance.Id, MountKind.Tree, "t", "b");
        rig.List(("a", "1", null));
        await rig.Reconciler.ReconcileAsync(mount, CancellationToken.None);
        rig.Cache("1");
        rig.Grant("g", "t/a");

        rig.Authority.Fault = _ => throw new IOException("disk (test)");
        rig.List();
        bool threw = false;
        try
        {
            await rig.Reconciler.ReconcileAsync(mount, CancellationToken.None);
        }
        catch (AuthorityDatabaseException)
        {
            threw = true;
        }

        rig.Authority.Fault = null;
        check(threw && Intact(rig, mount), "namespace: a failure inside the reconcile transaction changes nothing (entries, cache, grants, events)");

        rig.Authority.Fault = _ => throw new IOException("disk (test)");
        bool applyThrew = false;
        try
        {
            rig.Invalidation.Apply(rig.Instance.Id, new InvalidateProviderDataEvent(InvalidateEntireProviderInstance: true));
        }
        catch (AuthorityDatabaseException)
        {
            applyThrew = true;
        }

        rig.Authority.Fault = null;
        check(applyThrew && Intact(rig, mount) && rig.Audits.Count == 0, "namespace: a failure inside the invalidation transaction changes nothing and writes no audit");

        // Two mounts hold the last two references to one external id; both lose it.
        using Rig two = new();
        Mount m1 = two.Store.AddMount(two.Instance.Id, MountKind.Tree, "one", "b1");
        Mount m2 = two.Store.AddMount(two.Instance.Id, MountKind.Tree, "two", "b2");
        two.List(("a", "shared", null));
        await two.Reconciler.ReconcileAsync(m1, CancellationToken.None);
        await two.Reconciler.ReconcileAsync(m2, CancellationToken.None);
        two.Cache("shared");
        two.List();
        await Task.WhenAll(two.Reconciler.ReconcileAsync(m1, CancellationToken.None), two.Reconciler.ReconcileAsync(m2, CancellationToken.None));
        check(two.Store.Entries().Count == 0 && !two.Cached("shared"), "namespace: concurrent reconciles removing the last two references leave no orphan cache row");
    }

    private static async Task Generation(Action<bool, string> check)
    {
        using Rig rig = new();
        Mount mount = rig.Store.AddMount(rig.Instance.Id, MountKind.Tree, "t", "b");
        rig.List(("a", "1", null), ("b", "2", null));
        await rig.Reconciler.ReconcileAsync(mount, CancellationToken.None);
        long afterAdd = rig.Store.Generation(rig.Instance.Id);

        rig.List(("a", "1", "new description"), ("b", "2", null), ("c", "3", null));
        await rig.Reconciler.ReconcileAsync(mount, CancellationToken.None);
        check(rig.Store.Generation(rig.Instance.Id) == afterAdd, "namespace: adding entries or changing a description does not move the generation");

        rig.List(("a", "1", null), ("c", "3", null));
        await rig.Reconciler.ReconcileAsync(mount, CancellationToken.None);
        long afterRemove = rig.Store.Generation(rig.Instance.Id);
        check(afterRemove > afterAdd, "namespace: removing an entry moves the generation");

        rig.List(("a", "other-id", null), ("c", "3", null));
        await rig.Reconciler.ReconcileAsync(mount, CancellationToken.None);
        check(rig.Store.Generation(rig.Instance.Id) > afterRemove, "namespace: an external id change moves the generation");

        long seenInside = -1;
        long before = rig.Store.Generation(rig.Instance.Id);
        rig.Authority.Fault = _ => seenInside = rig.Store.Generation(rig.Instance.Id);
        rig.Invalidation.Apply(rig.Instance.Id, new InvalidateProviderDataEvent(ExternalSecretIds: ["3"]));
        rig.Authority.Fault = null;
        check(seenInside == before + 1, "namespace: invalidation moves the generation before the transaction commits");
        check(rig.Store.Generation(rig.Instance.Id) > seenInside, "namespace: invalidation moves the generation again after the commit");
    }

    private static void Mounts(Action<bool, string> check)
    {
        using Rig rig = new();
        bool Refused(string path)
        {
            try
            {
                rig.Store.AddMount(rig.Instance.Id, MountKind.Single, "name" + Guid.NewGuid().ToString("N")[..4], path);

                return false;
            }
            catch (ProviderConfigurationException)
            {
                return true;
            }
        }

        check(Refused("vault/key/") && Refused("/vault/key") && !Refused("vault/key"), "namespace: an individual mount provider path with a leading or trailing '/' is refused");
    }

    private static async Task Removal(Action<bool, string> check)
    {
        using Rig rig = new();
        Mount mount = rig.Store.AddMount(rig.Instance.Id, MountKind.Tree, "t", "b");
        rig.List(("a", "id-a", null), ("b", "id-b", null), ("c", "id-c", null));
        await rig.Reconciler.ReconcileAsync(mount, CancellationToken.None);
        rig.Cache("id-a");
        rig.Cache("id-b");
        rig.Grant("g1", "t/a, other");
        rig.Grant("g2", "t/b");
        rig.Grant("g3", "t/a", "revoked");

        rig.List(("b", "id-b", null), ("c", "id-c", null));
        ReconcileResult result = await rig.Reconciler.ReconcileAsync(mount, CancellationToken.None);
        check(result.Complete && result.Removed == 1 && result.Added == 0 && rig.Store.EntryFor("t/a") is null, "namespace: absent from a complete listing removes the entry (" + result + ")");
        check(rig.GrantStatus("g1") == "invalidated" && rig.GrantStatus("g2") == "active" && rig.GrantStatus("g3") == "revoked", "namespace: removal invalidates only the active grants naming the path");
        check(rig.Authority.PendingGrantEvents("fp") is [{ GrantId: "g1", Kind: "invalidated", GrantRevision: 2 }], "namespace: removal queues the invalidation notice so the host drops the grant and its key");
        check(!rig.Cached("id-a") && rig.Cached("id-b"), "namespace: removal deletes the cache row of the removed external id only");

        // The external id still used by another logical path keeps its cache row.
        using Rig shared = new();
        Mount m1 = shared.Store.AddMount(shared.Instance.Id, MountKind.Tree, "one", "b1");
        Mount m2 = shared.Store.AddMount(shared.Instance.Id, MountKind.Tree, "two", "b2");
        shared.List(("a", "shared-id", null));
        await shared.Reconciler.ReconcileAsync(m1, CancellationToken.None);
        await shared.Reconciler.ReconcileAsync(m2, CancellationToken.None);
        shared.Cache("shared-id");
        shared.Grant("g", "one/a");
        shared.List();
        await shared.Reconciler.ReconcileAsync(m1, CancellationToken.None);
        check(shared.Store.EntryFor("one/a") is null && shared.Store.EntryFor("two/a") is not null && shared.GrantStatus("g") == "invalidated" && shared.Cached("shared-id"),
            "namespace: an external id still used by another logical path keeps the cache row (grants of the removed path still invalidated)");
        shared.List();
        await shared.Reconciler.ReconcileAsync(m2, CancellationToken.None);
        check(!shared.Cached("shared-id"), "namespace: the cache row goes once the last reference is gone");

        // Same path, new external id.
        using Rig renamed = new();
        Mount mount3 = renamed.Store.AddMount(renamed.Instance.Id, MountKind.Tree, "t", "b");
        renamed.List(("a", "old", null));
        await renamed.Reconciler.ReconcileAsync(mount3, CancellationToken.None);
        renamed.Cache("old");
        renamed.Grant("g", "t/a");
        renamed.List(("a", "new", null));
        ReconcileResult changedResult = await renamed.Reconciler.ReconcileAsync(mount3, CancellationToken.None);
        check(changedResult.Changed == 1 && renamed.Store.EntryFor("t/a")?.ExternalId == "new" && !renamed.Cached("old") && renamed.GrantStatus("g") == "invalidated",
            "namespace: same path with a new external id is a new identity: cache deleted, grants invalidated (" + changedResult + ")");
    }

    private static async Task Descriptions(Action<bool, string> check)
    {
        using Rig rig = new();
        Mount mount = rig.Store.AddMount(rig.Instance.Id, MountKind.Tree, "t", "b");
        rig.List(("a", "1", "first"), ("b", "2", "second"));
        await rig.Reconciler.ReconcileAsync(mount, CancellationToken.None);
        rig.Exec("UPDATE namespace_entries SET description = 'mine', description_source = 'local' WHERE logical_path = 't/b'");

        rig.List(("a", "1", "renamed"), ("b", "2", "other"));
        await rig.Reconciler.ReconcileAsync(mount, CancellationToken.None);
        check(rig.Store.EntryFor("t/a")?.Description == "renamed" && rig.Store.EntryFor("t/b") is { Description: "mine", DescriptionSource: DescriptionSource.Local }, "namespace: a provider description is refreshed; a local description is kept");

        rig.List(("a", "1", null), ("b", "2", null));
        ReconcileResult result = await rig.Reconciler.ReconcileAsync(mount, CancellationToken.None);
        check(rig.Store.EntryFor("t/a") is { Description: null, DescriptionSource: DescriptionSource.Provider } && rig.Store.EntryFor("t/b")?.Description == "mine" && result.Changed == 1,
            "namespace: a provider description refreshes to null (" + result + ")");

        rig.List(("ok", "3", null), ("Bad Name!", "ext-bad-4", "desc-secret"), ("a", "1", null));
        ReconcileResult result2 = await rig.Reconciler.ReconcileAsync(mount, CancellationToken.None);
        check(result2.Added == 1 && result2.Changed == 0 && result2.Removed == 1 && rig.Store.Entries(mount.Id).Count == 2 && rig.Store.EntryFor("t/Bad Name!") is null,
            "namespace: an invalid listed name is dropped, not counted as changed (" + result2 + ")");
        check(rig.Log.Lines.Any(line => line.Contains("t/Bad Name!")) && rig.Log.Lines.All(line => !line.Contains("ext-bad-4") && !line.Contains("desc-secret") && !line.Contains("renamed") && !line.Contains("mine")), "namespace: the dropped name is logged by name only (no external id, no description)");
    }

    private static void Invalidation(Action<bool, string> check)
    {
        using Rig rig = new();
        Mount m1 = rig.Store.AddMount(rig.Instance.Id, MountKind.Tree, "one", "b1");
        Mount m2 = rig.Store.AddMount(rig.Instance.Id, MountKind.Tree, "two", "b2");
        rig.Store.ReplaceEntries(m1.Id, [new NamespaceEntry(m1.Id, "one/a", "b1/a", "S", "private-description", DescriptionSource.Provider), new NamespaceEntry(m1.Id, "one/b", "b1/b", "B", null, DescriptionSource.Provider)]);
        rig.Store.ReplaceEntries(m2.Id, [new NamespaceEntry(m2.Id, "two/a", "b2/a", "S", null, DescriptionSource.Provider), new NamespaceEntry(m2.Id, "two/c", "b2/c", "C", null, DescriptionSource.Provider)]);
        void Seed()
        {
            rig.Exec("DELETE FROM provider_cache");
            rig.Exec("UPDATE grants SET status = 'active' WHERE status = 'invalidated'");
            foreach (string id in new[] { "S", "B", "C" })
            {
                rig.Cache(id);
            }
        }

        rig.Grant("ga", "one/a");
        rig.Grant("gb", "one/b");
        rig.Grant("gta", "two/a");
        rig.Grant("gc", "two/c");
        rig.Grant("gx", "unrelated");

        Seed();
        rig.Invalidation.Apply(rig.Instance.Id, new InvalidateProviderDataEvent(ExternalSecretIds: ["S"]));
        check(rig.GrantStatus("ga") == "invalidated" && rig.GrantStatus("gta") == "invalidated" && rig.GrantStatus("gb") == "active" && rig.GrantStatus("gx") == "active" && !rig.Cached("S") && rig.Cached("B"),
            "namespace: invalidation by external id hits every logical reference");
        IReadOnlyList<PendingGrantEvent> events = rig.Authority.PendingGrantEvents("fp");
        check(events.Count == 2 && events.All(e => e.Kind == "invalidated" && e.GrantRevision == 2 && e.ScopeKey == "scope") && events.Select(e => e.GrantId).Order().SequenceEqual(["ga", "gta"]),
            "namespace: ending grants queues a notice per grant for the host (revision bumped)");

        Seed();
        rig.Invalidation.Apply(rig.Instance.Id, new InvalidateProviderDataEvent(MountIds: [m2.Id]));
        check(rig.GrantStatus("gta") == "invalidated" && rig.GrantStatus("gc") == "invalidated" && rig.GrantStatus("ga") == "active" && !rig.Cached("C") && !rig.Cached("S") && rig.Cached("B"),
            "namespace: invalidation by mount covers the mount's entries");

        Seed();
        rig.Invalidation.Apply(rig.Instance.Id, new InvalidateProviderDataEvent(InvalidateEntireProviderInstance: true));
        check(new[] { "ga", "gb", "gta", "gc" }.All(id => rig.GrantStatus(id) == "invalidated") && rig.GrantStatus("gx") == "active" && rig.Count("SELECT COUNT(*) FROM provider_cache") == 0,
            "namespace: invalidation of the whole instance clears its cache and every grant naming its entries");

        string all = string.Join("|", rig.Audits.Select(audit => audit.Event + ":" + string.Join(",", audit.Data.Select(pair => pair.Key + "=" + pair.Value))));
        check(rig.Audits.Count == 3 && rig.Audits.All(audit => audit.Event == "provider-data-invalidated" && audit.Data["instance"] == rig.Instance.Id.ToString("D") && audit.Data.ContainsKey("scope")) && !all.Contains("private-description") && !all.Contains("ciphertext"),
            "namespace: invalidation is audited once per apply with instance, scope and counts, no values (" + all + ")");
        IReadOnlyDictionary<string, string> byMount = rig.Audits[1].Data;
        IReadOnlyDictionary<string, string> byId = rig.Audits[0].Data;
        check(byId["externalIds"] == "S" && byId["paths"].Contains("one/a") && byId["paths"].Contains("two/a") && byMount["mounts"] == m2.Id.ToString("D") && byMount["paths"].Contains("two/c"),
            "namespace: the audit carries the requested mount ids, external ids and affected logical paths");
        string big = ProviderInvalidation.Bounded(Enumerable.Range(0, 500).Select(i => "path/" + i));
        check(big.Length < 1700 && big.Contains("more)") && AuditMetadata.Problem(new Dictionary<string, string> { ["paths"] = big }) is null, "namespace: long identifier lists are cut with a count suffix inside the audit limits");

        long before = rig.Invalidation.Generation(rig.Instance.Id);
        rig.Invalidation.Apply(rig.Instance.Id, new InvalidateProviderDataEvent(ExternalSecretIds: ["nothing"]));
        check(before > 0 && rig.Invalidation.Generation(rig.Instance.Id) > before && rig.Invalidation.Generation(Guid.NewGuid()) == 0, "namespace: generation moves on every applied invalidation, per instance");
    }
}

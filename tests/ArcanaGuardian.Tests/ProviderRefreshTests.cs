using System.Text;

using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;

namespace ArcanaGuardian.Tests;

/// <summary>Proactive batch refresh (10.3.3, 10.3.4): a fake clock and fake adapters, no real waiting.</summary>
internal static class ProviderRefreshTests
{
    private static readonly TimeSpan Hour = TimeSpan.FromHours(1);

    private sealed class ManualClock(DateTimeOffset start) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = start;

        public override DateTimeOffset GetUtcNow() => Now;

        public void Advance(TimeSpan by) => Now += by;
    }

    private sealed class CapturingLogger : ILogger
    {
        public List<string> Lines { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            Lines.Add(formatter(state, exception) + " | " + (exception?.GetType().Name ?? ""));
        }
    }

    private sealed class Rig : IDisposable
    {
        private readonly string _folder = Path.Combine(Path.GetTempPath(), "ws-providerrefresh-" + Guid.NewGuid().ToString("N"));
        private readonly Dictionary<int, SoftwareSigningKey> _signing = [];
        private readonly Dictionary<Guid, FakeProviderAdapter> _adapters = [];

        public Rig(TimeSpan maxStale)
        {
            Db = TestState.Seeded(Path.Combine(_folder, "state", ArcanaGuardianDatabase.FileName));
            Native = new SecretStore(Db, new CountingCipher());
            if (SecretStoreTests.Put(Native, new Dictionary<string, string> { ["NATIVE_ONE"] = "native" }) is { } problem)
            {
                throw new InvalidOperationException(problem);
            }

            Authority = AuthorityStore.InFolder(Path.Combine(_folder, "authority"));
            Providers = new ProviderStore(Authority);
            Lock = AuthorityLock.UnlockedForTests();
            Keys = new AuthorityKeyRing(Authority, generation =>
            {
                lock (_signing)
                {
                    return _signing.TryGetValue(generation, out SoftwareSigningKey? known) ? known : _signing[generation] = new SoftwareSigningKey();
                }
            })
            { LockState = Lock };
            Cache = new ProviderCache(Providers, Keys);
            Invalidation = new ProviderInvalidation(Providers, (_, _) => { });
            Retriever = new ProviderRetriever(id => _adapters[id], Clock, (_, _) => Task.CompletedTask);
            Refresher = new ProviderRefresher(Providers, Retriever, Cache, () => StoreKey, Invalidation, Clock, Logger, (_, _) => Task.CompletedTask);

            Instance = Providers.AddInstance("vault-one", "fake", "{}", maxStale);
            Adapter = new FakeProviderAdapter();
            _adapters[Instance.Id] = Adapter;
            Tree = Providers.AddMount(Instance.Id, MountKind.Tree, "team", "kv");
        }

        public StateDatabase Db { get; }

        public SecretStore Native { get; }

        public string? StoreKey { get; set; }

        public AuthorityStore Authority { get; }

        public ProviderStore Providers { get; }

        public AuthorityLock Lock { get; }

        public AuthorityKeyRing Keys { get; }

        public ProviderCache Cache { get; }

        public ProviderInvalidation Invalidation { get; }

        public ManualClock Clock { get; } = new(new DateTimeOffset(2026, 11, 22, 8, 0, 0, TimeSpan.Zero));

        public ProviderRetriever Retriever { get; }

        public CapturingLogger Logger { get; } = new();

        public ProviderRefresher Refresher { get; }

        public ProviderInstance Instance { get; }

        public FakeProviderAdapter Adapter { get; }

        public Mount Tree { get; }

        public int Invocations => Adapter.Invocations.Count;

        public (ProviderInstance Instance, FakeProviderAdapter Adapter, Mount Mount) AddInstance(string name, TimeSpan maxStale, string mountPath)
        {
            ProviderInstance made = Providers.AddInstance(name, "fake", "{}", maxStale);
            FakeProviderAdapter adapter = new();
            _adapters[made.Id] = adapter;

            return (made, adapter, Providers.AddMount(made.Id, MountKind.Tree, mountPath, "kv"));
        }

        /// <summary>Adds an entry to the mount (keeping the others) and, with <paramref name="seed" />, a verified cache row stamped now.</summary>
        public void Add(Mount mount, ProviderInstance instance, string name, string external, bool seed = true)
        {
            List<NamespaceEntry> entries = [.. Providers.Entries(mount.Id), new NamespaceEntry(mount.Id, mount.LogicalPath + "/" + name, "kv/" + name, external, null, DescriptionSource.Provider)];
            Providers.ReplaceEntries(mount.Id, entries);
            if (seed)
            {
                Cache.PutAll(instance.Id, [(external, Encoding.UTF8.GetBytes("old-" + name))], Clock.Now, StoreKey!);
            }
        }

        public void Prepare()
        {
            (Manifest? manifest, _) = Native.Current();
            StoreKey = manifest!.Store;
        }

        public object? Scalar(string sql)
        {
            using SqliteConnection connection = new("Data Source=" + Authority.FilePath + ";Pooling=False");
            connection.Open();
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = sql;

            return command.ExecuteScalar();
        }

        public long CacheRows() => (long)Scalar("SELECT COUNT(*) FROM provider_cache")!;

        public (string Ciphertext, long LastVerified) Row(Guid instanceId, string externalId)
        {
            using SqliteConnection connection = new("Data Source=" + Authority.FilePath + ";Pooling=False");
            connection.Open();
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "SELECT ciphertext, last_verified FROM provider_cache WHERE instance_id = $i AND external_id = $e";
            command.Parameters.AddWithValue("$i", instanceId.ToString("D"));
            command.Parameters.AddWithValue("$e", externalId);
            using SqliteDataReader reader = command.ExecuteReader();

            return reader.Read() ? (reader.GetString(0), reader.GetInt64(1)) : ("", 0);
        }

        public (string Ciphertext, long LastVerified) Row(string externalId = "ext-a") => Row(Instance.Id, externalId);

        public Task Tick() => Refresher.TickAsync(CancellationToken.None);

        public void Dispose()
        {
            SqliteConnection.ClearAllPools();
            foreach (SoftwareSigningKey key in _signing.Values)
            {
                key.Dispose();
            }

            try
            {
                Directory.Delete(_folder, true);
            }
            catch (IOException)
            {
            }
        }
    }

    /// <summary>A rig with one entry (ALPHA, ext-a) and a row stamped now.</summary>
    private static Rig Single(TimeSpan maxStale)
    {
        Rig rig = new(maxStale);
        rig.Prepare();
        rig.Add(rig.Tree, rig.Instance, "ALPHA", "ext-a");
        rig.Adapter.Returns("kv/ALPHA", "new-alpha");

        return rig;
    }

    public static async Task Run(Action<bool, string> check)
    {
        await Threshold(check);
        await Failure(check);
        await Backoff(check);
        await Batching(check);
        await Halting(check);
        await Recovery(check);
        await Safety(check);
        await Isolation(check);
        await Loop(check);
    }

    private static async Task Threshold(Action<bool, string> check)
    {
        using (Rig rig = Single(Hour))
        {
            rig.Clock.Advance(TimeSpan.FromSeconds(0.74 * 3600));
            await rig.Tick();
            check(rig.Invocations == 0, "refresh: value at 74% is not refreshed");
        }

        using (Rig rig = Single(Hour))
        {
            (string ciphertext, long verified) = rig.Row();
            rig.Clock.Advance(TimeSpan.FromMinutes(45));
            await rig.Tick();
            (string after, long afterVerified) = rig.Row();
            check(rig.Invocations == 1 && afterVerified == rig.Clock.Now.UtcTicks && afterVerified > verified && after != ciphertext && rig.CacheRows() == 1,
                "refresh: at 75% refreshed once, last_verified reset, ciphertext replaced");
            await rig.Tick();
            check(rig.Invocations == 1, "refresh: a refreshed row is no longer due");
        }

        using (Rig rig = Single(Hour))
        {
            rig.Clock.Advance(TimeSpan.FromHours(5));
            await rig.Tick();
            check(rig.Invocations == 1 && rig.Row().LastVerified == rig.Clock.Now.UtcTicks, "refresh: a row past the stale window is refreshed (recovery attempt)");
        }

        using (Rig rig = Single(TimeSpan.Zero))
        {
            rig.Clock.Advance(TimeSpan.FromDays(100));
            await rig.Tick();
            check(rig.Invocations == 0 && rig.CacheRows() == 0, "refresh: live only has no stored row to refresh");
        }

        using (Rig rig = Single(Hour))
        {
            rig.Clock.Advance(TimeSpan.FromMinutes(50));
            rig.Adapter.Handler = (_, requests, _) =>
            {
                rig.Providers.SetMaxStale(rig.Instance.Id, TimeSpan.Zero);
                return Task.FromResult<IReadOnlyList<ProviderSecretResult>>(
                    [.. requests.Select(request => new ProviderSecretResult(request.RequestId, new RetrieveSecretResult("new-alpha"u8.ToArray())))]);
            };
            await rig.Tick();
            check(rig.Invocations == 1 && rig.CacheRows() == 0, "refresh: disabling the cache during retrieval prevents its result from repopulating the cache");
        }

        using (Rig rig = Single(Hour))
        {
            rig.StoreKey = null;
            rig.Clock.Advance(TimeSpan.FromHours(1));
            await rig.Tick();
            check(rig.Invocations == 0, "refresh: no store key yet means nothing to do");
        }

        using (Rig rig = new(Hour))
        {
            rig.Prepare();
            rig.Add(rig.Tree, rig.Instance, "ALPHA", "ext-a", seed: false);
            rig.Adapter.Returns("kv/ALPHA", "new-alpha");
            rig.Clock.Advance(TimeSpan.FromHours(3));
            await rig.Tick();
            check(rig.Invocations == 0 && rig.CacheRows() == 0, "refresh: never changes a row that is absent");
        }

        using (Rig rig = Single(Hour))
        {
            rig.Cache.PutAll(rig.Instance.Id, [("ext-orphan", Encoding.UTF8.GetBytes("x"))], rig.Clock.Now, rig.StoreKey!);
            rig.Clock.Advance(TimeSpan.FromHours(1));
            await rig.Tick();
            check(rig.Invocations == 1 && rig.Adapter.Invocations[0].Count == 1 && rig.Row("ext-orphan").LastVerified == 0 && rig.CacheRows() == 1,
                "refresh: an external id with no namespace entry is not retrieved; its row is pruned");
        }

        await Pruning(check);
    }

    /// <summary>Final review M3: a tick first deletes the cache rows no namespace entry references (a removed mount left them), moving the generation only when it deletes.</summary>
    private static async Task Pruning(Action<bool, string> check)
    {
        using Rig rig = Single(Hour);
        (ProviderInstance other, _, Mount otherMount) = rig.AddInstance("vault-two", Hour, "ops");
        rig.Add(otherMount, other, "BRAVO", "ext-b");
        rig.Add(rig.Tree, rig.Instance, "SHARED", "ext-s");
        Mount second = rig.Providers.AddMount(rig.Instance.Id, MountKind.Tree, "dev", "kv");
        rig.Add(second, rig.Instance, "SHARED", "ext-s", seed: false);

        long quiet = rig.Providers.Generation(rig.Instance.Id);
        await rig.Tick();
        check(rig.CacheRows() == 3 && rig.Providers.Generation(rig.Instance.Id) == quiet, "refresh: a tick with nothing to prune deletes nothing and leaves the generation");

        rig.Lock.Lock("test");
        rig.Providers.RemoveMount(otherMount.Id);
        await rig.Tick();
        check(rig.CacheRows() == 3, "refresh: a locked tick prunes nothing");
        rig.Lock.Unlock(UnlockMethod.Seam);

        long before = rig.Providers.Generation(other.Id);
        long mine = rig.Providers.Generation(rig.Instance.Id);
        await rig.Tick();
        check(rig.CacheRows() == 2 && rig.Row(other.Id, "ext-b").LastVerified == 0 && rig.Row("ext-a").LastVerified != 0 && rig.Row("ext-s").LastVerified != 0 && rig.Invocations == 0,
            "refresh: the row no entry references is pruned; referenced rows stay; nothing is retrieved");
        check(rig.Providers.Generation(other.Id) == before + 2 && rig.Providers.Generation(rig.Instance.Id) == mine, "refresh: pruning moves the generation of the pruned instance only (inside and after)");

        rig.Providers.RemoveMount(rig.Tree.Id);
        await rig.Tick();
        check(rig.CacheRows() == 1 && rig.Row("ext-s").LastVerified != 0, "refresh: a row still referenced by another mount's entry is kept");

        // A prune that fails (a busy database, say) is logged by type and the pass goes on to refresh.
        using Rig failing = Single(Hour);
        failing.Refresher.BeforePrune = () => throw new InvalidOperationException("prune-message-hunter2");
        failing.Clock.Advance(TimeSpan.FromMinutes(45));
        await failing.Tick();
        check(failing.Invocations == 1 && failing.Row().LastVerified == failing.Clock.Now.UtcTicks, "refresh: a failing prune does not stop the refresh of due rows");
        check(failing.Logger.Lines.Any(line => line.Contains("InvalidOperationException", StringComparison.Ordinal)) && !failing.Logger.Lines.Any(line => line.Contains("hunter2", StringComparison.Ordinal)),
            "refresh: a failing prune is logged by exception type only");
    }

    private static async Task Failure(Action<bool, string> check)
    {
        using Rig rig = Single(Hour);
        (string ciphertext, long verified) = rig.Row();
        rig.Adapter.Fails("kv/ALPHA", ProviderErrorKind.Unavailable);
        rig.Clock.Advance(TimeSpan.FromMinutes(50));
        await rig.Tick();
        check(rig.Invocations > 0 && rig.Row() == (ciphertext, verified), "refresh: failed refresh leaves ciphertext and last_verified unchanged");
    }

    private static async Task Backoff(Action<bool, string> check)
    {
        using (Rig rig = Single(Hour))
        {
            rig.Adapter.Fails("kv/ALPHA", ProviderErrorKind.SecretNotFound);
            rig.Clock.Advance(TimeSpan.FromMinutes(50));
            await rig.Tick();
            bool first = rig.Invocations == 1;
            rig.Clock.Advance(TimeSpan.FromSeconds(59));
            await rig.Tick();
            bool early = rig.Invocations == 1;
            rig.Clock.Advance(TimeSpan.FromSeconds(1));
            await rig.Tick();
            check(first && early && rig.Invocations == 2, "refresh: failed refresh not retried before backoff, retried after");

            // Delays now: 2, 4, 8, 15, 15 minutes.
            List<int> waits = [];
            foreach (int expected in new[] { 2, 4, 8, 15, 15 })
            {
                int before = rig.Invocations;
                rig.Clock.Advance(TimeSpan.FromMinutes(expected) - TimeSpan.FromSeconds(1));
                await rig.Tick();
                bool notYet = rig.Invocations == before;
                rig.Clock.Advance(TimeSpan.FromSeconds(1));
                await rig.Tick();
                waits.Add(notYet && rig.Invocations == before + 1 ? expected : -expected);
            }

            check(waits.SequenceEqual([2, 4, 8, 15, 15]), "refresh: backoff doubles from 1 minute, capped at 15 minutes (" + string.Join(",", waits) + ")");
        }

        using (Rig rig = Single(Hour))
        {
            rig.Adapter.Fails("kv/ALPHA", ProviderErrorKind.SecretNotFound);
            rig.Clock.Advance(TimeSpan.FromMinutes(50));
            for (int index = 0; index < 100; index++)
            {
                rig.Clock.Advance(TimeSpan.FromMilliseconds(10));
                await rig.Tick();
            }

            check(rig.Invocations == 1, "refresh: no tight loop, 100 ticks in one second produce one adapter call");
        }

        using (Rig rig = Single(Hour))
        {
            rig.Adapter.Fails("kv/ALPHA", ProviderErrorKind.SecretNotFound);
            rig.Clock.Advance(TimeSpan.FromMinutes(50));
            await rig.Tick();
            rig.Clock.Advance(TimeSpan.FromMinutes(1));
            await rig.Tick();
            rig.Adapter.Returns("kv/ALPHA", "new-alpha");
            rig.Clock.Advance(TimeSpan.FromMinutes(2));
            await rig.Tick();
            int afterSuccess = rig.Invocations;

            // Success reset the backoff: the next failure waits 1 minute again.
            rig.Clock.Advance(TimeSpan.FromMinutes(45));
            rig.Adapter.Fails("kv/ALPHA", ProviderErrorKind.SecretNotFound);
            await rig.Tick();
            rig.Clock.Advance(TimeSpan.FromMinutes(1));
            await rig.Tick();
            check(afterSuccess == 3 && rig.Invocations == 5, "refresh: backoff resets on success (" + afterSuccess + "," + rig.Invocations + ")");
        }
    }

    private static async Task Batching(Action<bool, string> check)
    {
        using (Rig rig = Single(Hour))
        {
            rig.Add(rig.Tree, rig.Instance, "BRAVO", "ext-b");
            rig.Adapter.Returns("kv/BRAVO", "new-bravo");
            rig.Clock.Advance(TimeSpan.FromMinutes(46));
            await rig.Tick();
            check(rig.Invocations == 1 && rig.Adapter.Invocations[0].Count == 2 && rig.Row("ext-a").LastVerified == rig.Clock.Now.UtcTicks && rig.Row("ext-b").LastVerified == rig.Clock.Now.UtcTicks,
                "refresh: two external ids same instance: one batch");
        }

        using (Rig rig = Single(Hour))
        {
            (ProviderInstance second, FakeProviderAdapter adapter2, Mount mount2) = rig.AddInstance("vault-two", Hour, "other");
            rig.Add(mount2, second, "CHARLIE", "ext-c");
            adapter2.Returns("kv/CHARLIE", "new-charlie");
            rig.Clock.Advance(TimeSpan.FromMinutes(46));
            await rig.Tick();
            check(rig.Invocations == 1 && adapter2.Invocations.Count == 1 && rig.Row(second.Id, "ext-c").LastVerified == rig.Clock.Now.UtcTicks, "refresh: two instances: one batch each");
        }
    }

    private static async Task Halting(Action<bool, string> check)
    {
        foreach (ProviderErrorKind kind in new[] { ProviderErrorKind.AccessDenied, ProviderErrorKind.AuthenticationFailed, ProviderErrorKind.InteractionRequired })
        {
            using Rig rig = Single(Hour);
            rig.Adapter.Fails("kv/ALPHA", kind);
            rig.Clock.Advance(TimeSpan.FromMinutes(50));
            await rig.Tick();
            rig.Clock.Advance(TimeSpan.FromHours(3));
            await rig.Tick();
            bool halted = rig.Invocations == 1;
            rig.Clock.Advance(TimeSpan.FromHours(20));
            await rig.Tick();
            check(halted && rig.Invocations == 1, "refresh: " + kind + " result is halted: later ticks do not retry it, however long the wait");
        }
    }

    private static async Task Recovery(Action<bool, string> check)
    {
        using (Rig rig = Single(Hour))
        {
            rig.Adapter.Fails("kv/ALPHA", ProviderErrorKind.AuthenticationFailed);
            rig.Clock.Advance(TimeSpan.FromMinutes(50));
            await rig.Tick();
            rig.Clock.Advance(TimeSpan.FromHours(3));
            await rig.Tick();
            bool halted = rig.Invocations == 1;

            // An on-demand success (a newer write) proves recovery: the halt is lifted, and the next due tick refreshes.
            rig.Cache.PutAll(rig.Instance.Id, [("ext-a", Encoding.UTF8.GetBytes("on-demand"))], rig.Clock.Now, rig.StoreKey!);
            rig.Adapter.Returns("kv/ALPHA", "new-alpha");
            await rig.Tick();
            bool notDue = rig.Invocations == 1;
            rig.Clock.Advance(TimeSpan.FromMinutes(50));
            await rig.Tick();
            check(halted && notDue && rig.Invocations == 2 && rig.Row().LastVerified == rig.Clock.Now.UtcTicks, "refresh: a newer on-demand write lifts a halt, the next due tick refreshes");
        }

        using (Rig rig = Single(Hour))
        {
            long original = rig.Row().LastVerified;
            rig.Adapter.Fails("kv/ALPHA", ProviderErrorKind.SecretNotFound);
            rig.Clock.Advance(TimeSpan.FromMinutes(50));
            await rig.Tick();

            // The row disappears and comes back (same lastVerified): the old backoff entry was pruned, so it is due at once.
            rig.Providers.DeleteCache(rig.Instance.Id, null);
            await rig.Tick();
            rig.Cache.PutAll(rig.Instance.Id, [("ext-a", Encoding.UTF8.GetBytes("again"))], new DateTimeOffset(original, TimeSpan.Zero), rig.StoreKey!);
            rig.Adapter.Returns("kv/ALPHA", "new-alpha");
            await rig.Tick();
            check(rig.Invocations == 2 && rig.Row().LastVerified == rig.Clock.Now.UtcTicks, "refresh: backoff state of a row that no longer exists is pruned");
        }
    }

    private static async Task Isolation(Action<bool, string> check)
    {
        static IReadOnlyList<ProviderSecretResult> Values(IReadOnlyList<ProviderSecretRequest> requests) =>
            [.. requests.Select(request => new ProviderSecretResult(request.RequestId, new RetrieveSecretResult(Encoding.UTF8.GetBytes("new-value"))))];

        using (Rig rig = Single(Hour))
        {
            // The authority locks while the batch is in flight: the write throws AuthorityLockedException, the tick ends quietly, nothing changes.
            (string ciphertext, long verified) = rig.Row();
            rig.Adapter.Handler = (_, requests, _) =>
            {
                rig.Lock.Lock("test");

                return Task.FromResult(Values(requests));
            };
            rig.Clock.Advance(TimeSpan.FromHours(1));
            Exception? thrown = null;
            try
            {
                await rig.Tick();
            }
            catch (Exception error)
            {
                thrown = error;
            }

            check(thrown is null && rig.Invocations == 1 && rig.Row() == (ciphertext, verified), "refresh: authority locking mid-tick (write path) ends the tick quietly, row unchanged");
        }

        using (Rig rig = Single(Hour))
        {
            (ProviderInstance second, FakeProviderAdapter adapter2, Mount mount2) = rig.AddInstance("vault-two", Hour, "other");
            rig.Add(mount2, second, "CHARLIE", "ext-c");
            adapter2.Returns("kv/CHARLIE", "new-charlie");
            rig.Adapter.Handler = (_, requests, _) =>
            {
                rig.Lock.Lock("test");

                return Task.FromResult<IReadOnlyList<ProviderSecretResult>>([.. requests.Select(request => new ProviderSecretResult(request.RequestId, null, ProviderErrorKind.SecretNotFound))]);
            };
            rig.Clock.Advance(TimeSpan.FromHours(1));
            await rig.Tick();
            check(rig.Invocations == 1 && adapter2.Invocations.Count == 0, "refresh: authority locking mid-tick: no further provider call");
        }

        using (Rig rig = Single(Hour))
        {
            (ProviderInstance second, FakeProviderAdapter adapter2, Mount mount2) = rig.AddInstance("vault-two", Hour, "other");
            rig.Add(mount2, second, "CHARLIE", "ext-c");
            adapter2.Returns("kv/CHARLIE", "new-charlie");
            (string ciphertext, long verified) = rig.Row();
            bool thrown = false;
            rig.Authority.Fault = point =>
            {
                if (point == "provider-cache-check" && !thrown)
                {
                    thrown = true;

                    throw new InvalidOperationException("scripted");
                }
            };
            rig.Clock.Advance(TimeSpan.FromHours(1));
            Exception? escaped = null;
            try
            {
                await rig.Tick();
            }
            catch (Exception error)
            {
                // A regression (the write's failure escaping the tick) is reported as a failed check, not an aborted run.
                escaped = error;
            }
            finally
            {
                rig.Authority.Fault = null;
            }

            check(escaped is null && thrown && rig.Row() == (ciphertext, verified) && rig.Row(second.Id, "ext-c").LastVerified == rig.Clock.Now.UtcTicks && rig.Logger.Lines.Any(line => line.Contains("InvalidOperationException")),
                "refresh: an instance whose write throws does not starve a later instance");
        }

        using (Rig rig = Single(Hour))
        {
            bool bumped = false;
            rig.Refresher.AfterBaseline = () =>
            {
                if (!bumped)
                {
                    bumped = true;
                    rig.Invalidation.Apply(rig.Instance.Id, new InvalidateProviderDataEvent(ExternalSecretIds: ["unrelated"]));
                }
            };
            rig.Clock.Advance(TimeSpan.FromHours(1));
            await rig.Tick();
            check(rig.Invocations == 0, "refresh: the baseline is taken before the reads: an invalidation after it skips the instance");
        }

        using (Rig rig = Single(Hour))
        {
            (ProviderInstance second, FakeProviderAdapter adapter2, Mount mount2) = rig.AddInstance("vault-two", Hour, "other");
            rig.Add(mount2, second, "CHARLIE", "ext-c");
            rig.Adapter.Handler = (_, requests, _) =>
            {
                rig.Invalidation.Apply(second.Id, new InvalidateProviderDataEvent(ExternalSecretIds: ["unrelated"]));

                return Task.FromResult(Values(requests));
            };
            rig.Clock.Advance(TimeSpan.FromHours(1));
            await rig.Tick();
            check(rig.Invocations == 1 && adapter2.Invocations.Count == 0, "refresh: an instance invalidated before its own retrieval is skipped");
        }

        using (Rig rig = Single(Hour))
        {
            string landed = "";
            long newer = 0;
            rig.Adapter.Handler = (_, requests, _) =>
            {
                rig.Clock.Advance(TimeSpan.FromMinutes(1));
                rig.Cache.PutAll(rig.Instance.Id, [("ext-a", Encoding.UTF8.GetBytes("on-demand"))], rig.Clock.Now, rig.StoreKey!);
                (landed, newer) = rig.Row();

                return Task.FromResult(Values(requests));
            };
            rig.Clock.Advance(TimeSpan.FromHours(1));
            await rig.Tick();
            check(rig.Invocations == 1 && rig.Row() == (landed, newer) && newer > 0, "refresh: a newer on-demand row landing during the refresh is kept (superseded)");
        }
    }

    private static async Task Safety(Action<bool, string> check)
    {
        using (Rig rig = new(Hour))
        {
            // A deployment with no due work (no rows; then no instance at all) never opens the native manifest: the store-key delegate is not called.
            int asked = 0;
            ProviderRefresher counting = new(rig.Providers, rig.Retriever, rig.Cache, () =>
            {
                asked++;

                return "unused";
            }, rig.Invalidation, rig.Clock, rig.Logger, (_, _) => Task.CompletedTask);
            await counting.TickAsync(CancellationToken.None);
            int withInstance = asked;
            ProviderStore empty = new(AuthorityStore.InFolder(Path.Combine(Path.GetTempPath(), "ws-providerrefresh-empty-" + Guid.NewGuid().ToString("N"))));
            ProviderRefresher bare = new(empty, rig.Retriever, rig.Cache, () =>
            {
                asked++;

                return "unused";
            }, new ProviderInvalidation(empty, (_, _) => { }), rig.Clock, rig.Logger, (_, _) => Task.CompletedTask);
            await bare.TickAsync(CancellationToken.None);
            check(withInstance == 0 && asked == 0 && rig.Invocations == 0, "refresh: with no cache rows, or no instance, a tick never asks for the store key (" + withInstance + ", " + asked + ")");
        }

        using (Rig rig = Single(Hour))
        {
            (string ciphertext, long verified) = rig.Row();
            rig.Lock.Lock("test");
            rig.Clock.Advance(TimeSpan.FromHours(2));
            Exception? thrown = null;
            try
            {
                await rig.Tick();
            }
            catch (Exception error)
            {
                thrown = error;
            }

            check(thrown is null && rig.Invocations == 0 && rig.Row() == (ciphertext, verified), "refresh: locked authority: tick does nothing, no exception (" + thrown?.GetType().Name + ")");
        }

        using (Rig rig = Single(Hour))
        {
            long grants = (long)rig.Scalar("SELECT COUNT(*) FROM grants")!;
            long events = (long)rig.Scalar("SELECT COUNT(*) FROM grant_events")!;
            rig.Clock.Advance(TimeSpan.FromHours(1));
            await rig.Tick();
            check(rig.Invocations == 1 && (long)rig.Scalar("SELECT COUNT(*) FROM grants")! == grants && (long)rig.Scalar("SELECT COUNT(*) FROM grant_events")! == events,
                "refresh: creates no grant and delivers nothing");
        }

        using (Rig rig = Single(Hour))
        {
            (string ciphertext, long verified) = rig.Row();
            rig.Adapter.Handler = (_, requests, _) =>
            {
                rig.Invalidation.Apply(rig.Instance.Id, new InvalidateProviderDataEvent(ExternalSecretIds: ["unrelated"]));

                return Task.FromResult<IReadOnlyList<ProviderSecretResult>>([.. requests.Select(request => new ProviderSecretResult(request.RequestId, new RetrieveSecretResult(Encoding.UTF8.GetBytes("new-alpha"))))]);
            };
            rig.Clock.Advance(TimeSpan.FromHours(1));
            await rig.Tick();
            check(rig.Invocations == 1 && rig.Row() == (ciphertext, verified), "refresh: invalidation during refresh discards the result");
        }
    }

    private static async Task Loop(Action<bool, string> check)
    {
        using Rig rig = Single(Hour);
        int calls = 0;
        int delays = 0;
        TaskCompletionSource secondTick = new(TaskCreationOptions.RunContinuationsAsynchronously);
        string key = rig.StoreKey!;
        ProviderRefresher refresher = new(rig.Providers, rig.Retriever, rig.Cache, () => ++calls == 1 ? throw new InvalidOperationException("boom secret-text") : key, rig.Invalidation, rig.Clock, rig.Logger, async (_, _) =>
        {
            rig.Clock.Advance(TimeSpan.FromMinutes(1));
            if (++delays == 2)
            {
                secondTick.TrySetResult();
            }

            await Task.Yield();
        });
        using CancellationTokenSource stop = new();
        rig.Clock.Advance(TimeSpan.FromMinutes(50));
        Task run = refresher.RunAsync(TimeSpan.FromMinutes(1), stop.Token);
        bool ticked = true;
        try
        {
            await secondTick.Task.WaitAsync(TimeSpan.FromSeconds(30));
        }
        catch (TimeoutException)
        {
            // A regression (the loop stopped after the failing tick) is reported as a failed check, not an aborted run.
            ticked = false;
        }

        stop.Cancel();
        Exception? ended = null;
        try
        {
            await run.WaitAsync(TimeSpan.FromSeconds(30));
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception error)
        {
            ended = error;
        }

        check(ticked && ended is null && rig.Invocations >= 1 && calls >= 2, "refresh: RunAsync survives a failing tick and keeps ticking (" + ended?.GetType().Name + ")");
        check(rig.Logger.Lines.Any(line => line.Contains("InvalidOperationException")) && !rig.Logger.Lines.Any(line => line.Contains("secret-text") || line.Contains("old-") || line.Contains("new-")),
            "refresh: a failing tick logs the exception type only");
    }
}

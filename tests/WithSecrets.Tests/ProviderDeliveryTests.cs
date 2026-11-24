using System.Text;

using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>
/// Mounted-secret delivery end to end through <see cref="ProviderSecretSource" />: a real native store and test unlock, a fake adapter, a manual clock (10.3,
/// 10.3.1, 10.3.3, 10.3.4). No test sleeps.
/// </summary>
internal static class ProviderDeliveryTests
{
    private const string Alpha = "Alpha-Provider-Value-1";
    private const string Bravo = "Bravo-Provider-Value-2";
    private const string Charlie = "Charlie-Provider-Value-3";
    private const string NativeValue = "Native-Store-Value-1";

    private sealed class ManualClock(DateTimeOffset start) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = start;

        public override DateTimeOffset GetUtcNow() => Now;

        public void Advance(TimeSpan by) => Now += by;
    }

    private sealed class Rig : IDisposable
    {
        private readonly string _folder = Path.Combine(Path.GetTempPath(), "ws-providerdelivery-" + Guid.NewGuid().ToString("N"));
        private readonly Dictionary<int, SoftwareSigningKey> _signing = [];
        private readonly Dictionary<Guid, FakeProviderAdapter> _adapters = [];

        public Rig(TimeSpan maxStale, bool withStoreKey = true)
        {
            Db = TestState.Seeded(Path.Combine(_folder, "state", WithSecretsDatabase.FileName));
            Native = new SecretStore(Db, Cipher);
            if (withStoreKey && SecretStoreTests.Put(Native, new Dictionary<string, string> { ["NATIVE_ONE"] = NativeValue }) is { } problem)
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
            Source = new ProviderSecretSource(Native, Providers, Retriever, Cache, Invalidation, Clock, records =>
            {
                AuditCalls++;
                Audits.AddRange(records);
            });

            Instance = Providers.AddInstance("vault-one", "fake", "{}", maxStale);
            Adapter = new FakeProviderAdapter();
            _adapters[Instance.Id] = Adapter;
            Tree = Providers.AddMount(Instance.Id, MountKind.Tree, "team", "kv");
            Entries(Tree, ("team/ALPHA", "kv/ALPHA", "ext-a"));
            Adapter.Returns("kv/ALPHA", Alpha);
        }

        public StateDatabase Db { get; }

        public CountingCipher Cipher { get; } = new();

        public SecretStore Native { get; }

        public AuthorityStore Authority { get; }

        public ProviderStore Providers { get; }

        public AuthorityLock Lock { get; }

        public AuthorityKeyRing Keys { get; }

        public ProviderCache Cache { get; }

        public ProviderInvalidation Invalidation { get; }

        public ManualClock Clock { get; } = new(new DateTimeOffset(2026, 11, 22, 8, 0, 0, TimeSpan.Zero));

        public ProviderRetriever Retriever { get; }

        public ProviderSecretSource Source { get; }

        public List<ProviderAudit> Audits { get; } = [];

        /// <summary>How many times the sink was called (once per call that audits anything).</summary>
        public int AuditCalls { get; set; }

        public ProviderInstance Instance { get; }

        public FakeProviderAdapter Adapter { get; }

        public Mount Tree { get; }

        public (ProviderInstance Instance, FakeProviderAdapter Adapter) AddInstance(string name, TimeSpan maxStale)
        {
            ProviderInstance made = Providers.AddInstance(name, "fake", "{}", maxStale);
            FakeProviderAdapter adapter = new();
            _adapters[made.Id] = adapter;

            return (made, adapter);
        }

        public void Entries(Mount mount, params (string Logical, string Provider, string External)[] entries)
        {
            Providers.ReplaceEntries(mount.Id, [.. entries.Select(entry => new NamespaceEntry(mount.Id, entry.Logical, entry.Provider, entry.External, null, DescriptionSource.Provider))]);
        }

        public SecretValues Get(params string[] names)
        {
            using Unlock? unlock = SecretStoreTests.AdminUnlock(Db);

            return Source.GetValues(names, unlock);
        }

        /// <summary>The values as text, or null when the call threw <see cref="SecretStoreException" /> (its message in <paramref name="error" />).</summary>
        public Dictionary<string, string>? TryGet(out string error, params string[] names)
        {
            try
            {
                using SecretValues values = Get(names);
                error = "";

                return values.Texts();
            }
            catch (SecretStoreException failure)
            {
                error = failure.Message;

                return null;
            }
        }

        public int Invocations => Adapter.Invocations.Count;

        public object? Scalar(string sql)
        {
            using SqliteConnection connection = new("Data Source=" + Authority.FilePath + ";Pooling=False");
            connection.Open();
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = sql;

            return command.ExecuteScalar();
        }

        public void Exec(string sql, params (string Name, object Value)[] parameters)
        {
            using SqliteConnection connection = new("Data Source=" + Authority.FilePath + ";Pooling=False");
            connection.Open();
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = sql;
            foreach ((string name, object value) in parameters)
            {
                command.Parameters.AddWithValue(name, value);
            }

            command.ExecuteNonQuery();
        }

        public long CacheRows() => (long)Scalar("SELECT COUNT(*) FROM provider_cache")!;

        public (string Ciphertext, long LastVerified) Row(string externalId = "ext-a")
        {
            using SqliteConnection connection = new("Data Source=" + Authority.FilePath + ";Pooling=False");
            connection.Open();
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "SELECT ciphertext, last_verified FROM provider_cache WHERE external_id = $e";
            command.Parameters.AddWithValue("$e", externalId);
            using SqliteDataReader reader = command.ExecuteReader();

            return reader.Read() ? (reader.GetString(0), reader.GetInt64(1)) : ("", 0);
        }

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

    private static readonly TimeSpan Hour = TimeSpan.FromHours(1);

    public static Task Run(Action<bool, string> check)
    {
        Fresh(check);
        Freshness(check);
        Rotation(check);
        Stale(check);
        StaleKinds(check);
        Policy(check);
        Resolution(check);
        Batching(check);
        Malformed(check);
        Invalidation(check);
        Mixed(check);
        Audit(check);
        Zeroing(check);
        Locked(check);
        NoStoreKey(check);
        Tampered(check);
        Listing(check);
        Races(check);
        WrongUnlock(check);
        CommitWindow(check);

        return Task.CompletedTask;
    }

    /// <summary>
    /// Runs <paramref name="write" /> on this thread; at its pre-commit fault point (after the in-transaction bump) a GetValues of team/ALPHA starts on another
    /// thread, takes its generation snapshot, resolves and reads the cache (all before the commit), then waits until the write has returned. Returns that call's values or null.
    /// </summary>
    private static Dictionary<string, string>? RaceCommit(Rig rig, Action write, out string error)
    {
        using ManualResetEventSlim readsDone = new();
        using ManualResetEventSlim committed = new();
        Task<(Dictionary<string, string>? Values, string Error)>? call = null;
        rig.Source.AfterReads = () =>
        {
            readsDone.Set();
            committed.Wait(TimeSpan.FromSeconds(20));
        };
        rig.Authority.Fault = point =>
        {
            if (point != "provider-before-commit" || call is not null)
            {
                return;
            }

            call = Task.Run(() => (rig.TryGet(out string message, "team/ALPHA"), message));
            readsDone.Wait(TimeSpan.FromSeconds(20));
        };
        try
        {
            write();
        }
        finally
        {
            rig.Authority.Fault = null;
            committed.Set();
        }

        if (call is null)
        {
            // Empty on purpose: every check requires a non-empty error, so a race that never started fails the check.
            error = "";

            return null;
        }

        (Dictionary<string, string>? values, string message) = call.GetAwaiter().GetResult();
        rig.Source.AfterReads = null;
        error = message;

        return values;
    }

    private static void CommitWindow(Action<bool, string> check)
    {
        using (Rig rig = new(Hour))
        {
            rig.TryGet(out _, "team/ALPHA");
            Dictionary<string, string>? got = RaceCommit(rig, () => rig.Invalidation.Apply(rig.Instance.Id, new InvalidateProviderDataEvent(ExternalSecretIds: ["ext-a"])), out string error);
            check(got is null && error.Length > 0 && rig.CacheRows() == 0,
                "delivery: a snapshot taken between an invalidation's bump and its commit fails closed (old cached row not served) (" + error + ")");
        }

        using (Rig rig = new(Hour))
        {
            rig.TryGet(out _, "team/ALPHA");
            Dictionary<string, string>? got = RaceCommit(rig, () => rig.Providers.ApplyReconciliation(rig.Tree, _ => ([], 0, 0)), out string error);
            check(got is null && error.Length > 0 && rig.CacheRows() == 0,
                "delivery: a snapshot taken between a reconcile removal's bump and its commit fails closed (removed path not served) (" + error + ")");
        }

        using (Rig rig = new(Hour))
        {
            rig.TryGet(out _, "team/ALPHA");
            Dictionary<string, string>? got = RaceCommit(rig, () => rig.Providers.RemoveMount(rig.Tree.Id), out string error);
            check(got is null && error.Length > 0, "delivery: a snapshot taken between a mount removal's bump and its commit fails closed (" + error + ")");
        }
    }

    private static ProviderSecretResult Ok(ProviderSecretRequest request, string value) => new(request.RequestId, new RetrieveSecretResult(Encoding.UTF8.GetBytes(value)));

    private static void Races(Action<bool, string> check)
    {
        using (Rig rig = new(Hour))
        {
            rig.TryGet(out _, "team/ALPHA");
            (ProviderInstance second, FakeProviderAdapter other) = rig.AddInstance("vault-two", TimeSpan.Zero);
            Mount mount = rig.Providers.AddMount(second.Id, MountKind.Tree, "ops", "base");
            rig.Entries(mount, ("ops/YANKEE", "base/YANKEE", "ext-y"));
            other.Handler = (_, requests, _) =>
            {
                rig.Providers.SetMaxStale(rig.Instance.Id, TimeSpan.Zero);
                return Task.FromResult<IReadOnlyList<ProviderSecretResult>>([Ok(requests[0], Bravo)]);
            };

            Dictionary<string, string>? got = rig.TryGet(out string error, "team/ALPHA", "ops/YANKEE");
            check(got is null && rig.Invocations == 1 && other.Invocations.Count == 1 && rig.CacheRows() == 0
                && error.Contains("team/ALPHA was invalidated", StringComparison.Ordinal),
                "delivery: disabling an earlier provider's cache during a later provider batch fails closed (" + error + ")");
        }

        // A call needs A/x and B/y; while A's batch is in flight a reconcile of instance B removes y. The baseline was taken before resolution: fail closed.
        using (Rig rig = new(Hour))
        {
            (ProviderInstance second, FakeProviderAdapter other) = rig.AddInstance("vault-two", Hour);
            Mount mount = rig.Providers.AddMount(second.Id, MountKind.Tree, "ops", "base");
            rig.Entries(mount, ("ops/YANKEE", "base/YANKEE", "ext-y"));
            other.Returns("base/YANKEE", Bravo);
            rig.Adapter.Handler = (_, requests, _) =>
            {
                rig.Providers.ApplyReconciliation(mount, _ => ([], 0, 0));

                return Task.FromResult<IReadOnlyList<ProviderSecretResult>>([Ok(requests[0], Alpha)]);
            };
            Dictionary<string, string>? got = rig.TryGet(out string error, "team/ALPHA", "ops/YANKEE");
            check(got is null && (long)rig.Scalar("SELECT COUNT(*) FROM provider_cache WHERE external_id = 'ext-y'")! == 0,
                "delivery: a reconcile of instance B during A's batch fails the call closed; no cache row for B's removed id (" + error + ")");
        }

        // Same, but the reconcile runs between resolution and the batch of the SAME instance (simulated as the first thing the adapter of another instance does).
        using (Rig rig = new(Hour))
        {
            (ProviderInstance second, FakeProviderAdapter other) = rig.AddInstance("vault-two", Hour);
            Mount mount = rig.Providers.AddMount(second.Id, MountKind.Tree, "ops", "base");
            rig.Entries(mount, ("ops/YANKEE", "base/YANKEE", "ext-y"));
            other.Returns("base/YANKEE", Bravo);
            rig.Adapter.Handler = (_, requests, _) =>
            {
                rig.Providers.ApplyReconciliation(mount, old => ([.. old.Select(entry => entry with { ExternalId = "ext-y2" })], 0, 1));

                return Task.FromResult<IReadOnlyList<ProviderSecretResult>>([Ok(requests[0], Alpha)]);
            };
            Dictionary<string, string>? got = rig.TryGet(out string error, "team/ALPHA", "ops/YANKEE");
            check(got is null && other.Invocations.Count == 0 && rig.CacheRows() == 1,
                "delivery: B's external id changed after resolution: B is not retrieved, nothing of B cached, the call fails (" + error + ")");
        }

        // R1 starts first and commits second with an older lastVerified: the row keeps R2's value.
        using (Rig rig = new(Hour))
        {
            rig.Adapter.Handler = (index, requests, _) =>
            {
                if (index == 0)
                {
                    rig.Clock.Advance(TimeSpan.FromMinutes(1));
                    using SecretValues newer = rig.Get("team/ALPHA");
                }

                return Task.FromResult<IReadOnlyList<ProviderSecretResult>>([Ok(requests[0], index == 0 ? Alpha : Bravo)]);
            };
            DateTimeOffset second = rig.Clock.Now.AddMinutes(1);
            Dictionary<string, string>? got = rig.TryGet(out string error, "team/ALPHA");
            check(got?["team/ALPHA"] == Alpha && rig.Audits.Count == 2 && rig.Audits.All(audit => audit.Outcome == RetrievalOutcomeKind.Fresh) && rig.Row().LastVerified == second.UtcTicks,
                "delivery: an older retrieval committing second delivers its own value (Fresh) but keeps the newer row (" + error + ")");
            rig.Adapter.Handler = null;
            rig.Clock.Advance(TimeSpan.FromMinutes(5));
            rig.Audits.Clear();
            got = rig.TryGet(out error, "team/ALPHA");
            check(got?["team/ALPHA"] == Bravo && rig.Audits.Single().Outcome == RetrievalOutcomeKind.Cached && rig.Invocations == 2, "delivery: the later request is served the newer value as Cached (" + error + ")");
        }

        // A mount removed during the retrieval: its path is not delivered.
        using (Rig rig = new(Hour))
        {
            long before = rig.Providers.Generation(rig.Instance.Id);
            rig.Adapter.Handler = (_, requests, _) =>
            {
                rig.Providers.RemoveMount(rig.Tree.Id);

                return Task.FromResult<IReadOnlyList<ProviderSecretResult>>([Ok(requests[0], Alpha)]);
            };
            Dictionary<string, string>? got = rig.TryGet(out string error, "team/ALPHA");
            check(rig.Providers.Generation(rig.Instance.Id) > before, "delivery: RemoveMount moves the instance generation");
            check(got is null && rig.CacheRows() == 0, "delivery: a mount removed during the retrieval: not delivered, not cached (" + error + ")");
        }
    }

    private static void WrongUnlock(Action<bool, string> check)
    {
        using Rig rig = new(Hour);
        string credential;
        using (Unlock? real = SecretStoreTests.AdminUnlock(rig.Db))
        {
            credential = real!.CredentialId;
        }

        using Unlock wrong = new(credential, System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        bool threw = false;
        try
        {
            using SecretValues values = rig.Source.GetValues(["team/ALPHA"], wrong);
        }
        catch (SecretStoreException)
        {
            threw = true;
        }

        check(threw && rig.Invocations == 0 && rig.CacheRows() == 0, "delivery: a non-opening unlock fails the call even when every value would be Fresh (no provider read)");

        using Rig empty = new(Hour, withStoreKey: false);
        using Unlock other = new(credential, System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        Dictionary<string, string>? got = null;
        try
        {
            using SecretValues values = empty.Source.GetValues(["team/ALPHA"], other);
            got = values.Texts();
        }
        catch (SecretStoreException)
        {
        }

        check(got?["team/ALPHA"] == Alpha, "delivery: with no store key yet there is no K to open; the fresh value is delivered");
    }

    private static void Fresh(Action<bool, string> check)
    {
        using Rig rig = new(Hour);
        Dictionary<string, string>? got = rig.TryGet(out string error, "team/ALPHA");
        check(got is not null && got["team/ALPHA"] == Alpha && rig.Invocations == 1 && rig.CacheRows() == 1, "delivery: fresh fetch delivers and caches (" + error + ")");
        check(rig.Audits.Count == 1 && rig.Audits[0].Outcome == RetrievalOutcomeKind.Fresh && rig.Audits[0].Path == "team/ALPHA", "delivery: a fresh fetch audits Fresh");
        check(rig.Row().LastVerified == rig.Clock.Now.UtcTicks, "delivery: the cached row's lastVerified is the retrieval time");
        check(rig.Source.Label == SecretStore.GlobalLabel && rig.Source.NeedsUnlock, "delivery: label is the native label and an unlock is needed");
    }

    private static void Freshness(Action<bool, string> check)
    {
        using Rig rig = new(Hour);
        rig.TryGet(out _, "team/ALPHA");
        rig.Clock.Advance(TimeSpan.FromMinutes(44));
        rig.Audits.Clear();
        Dictionary<string, string>? got = rig.TryGet(out string error, "team/ALPHA");
        check(got is not null && got["team/ALPHA"] == Alpha && rig.Invocations == 1 && rig.Audits.Single().Outcome == RetrievalOutcomeKind.Cached,
            "delivery: cached within 75% delivers with ZERO adapter calls (" + error + ")");

        rig.Clock.Advance(TimeSpan.FromMinutes(1));
        rig.Audits.Clear();
        got = rig.TryGet(out error, "team/ALPHA");
        check(got is not null && rig.Invocations == 2 && rig.Audits.Single().Outcome == RetrievalOutcomeKind.Fresh, "delivery: at 75% refetches (" + error + ")");
        check(rig.Row().LastVerified == rig.Clock.Now.UtcTicks, "delivery: the refetch resets lastVerified");
    }

    private static void Rotation(Action<bool, string> check)
    {
        using Rig rig = new(Hour);
        rig.TryGet(out _, "team/ALPHA");
        string before = rig.Row().Ciphertext;
        rig.Clock.Advance(TimeSpan.FromMinutes(50));
        rig.Adapter.Returns("kv/ALPHA", Bravo);
        Dictionary<string, string>? got = rig.TryGet(out _, "team/ALPHA");
        check(got?["team/ALPHA"] == Bravo && rig.CacheRows() == 1 && rig.Row().Ciphertext != before, "delivery: rotated value replaces the row");

        // The old value is never served again: an outage now serves the rotated value as stale.
        rig.Clock.Advance(TimeSpan.FromMinutes(50));
        rig.Adapter.Fails("kv/ALPHA", ProviderErrorKind.Unavailable);
        got = rig.TryGet(out string error, "team/ALPHA");
        check(got?["team/ALPHA"] == Bravo, "delivery: after rotation, stale serving gives the rotated value, never the old one (" + error + ")");
    }

    private static void Stale(Action<bool, string> check)
    {
        using (Rig rig = new(TimeSpan.Zero))
        {
            rig.TryGet(out _, "team/ALPHA");
            rig.TryGet(out _, "team/ALPHA");
            check(rig.Invocations == 2 && rig.CacheRows() == 0, "delivery: live only fetches on each run without persisting a value");
            rig.Adapter.Fails("kv/ALPHA", ProviderErrorKind.Unavailable);
            Dictionary<string, string>? got = rig.TryGet(out string error, "team/ALPHA");
            check(got is null && error.Contains("team/ALPHA", StringComparison.Ordinal) && error.Contains("Unavailable", StringComparison.Ordinal) && rig.CacheRows() == 0,
                "delivery: live only fails closed during a provider outage (" + error + ")");
        }

        using (Rig rig = new(Hour))
        {
            rig.TryGet(out _, "team/ALPHA");
            (string ciphertext, long verified) = rig.Row();
            rig.Clock.Advance(TimeSpan.FromMinutes(50));
            rig.Adapter.Fails("kv/ALPHA", ProviderErrorKind.Unavailable);
            rig.Audits.Clear();
            Dictionary<string, string>? got = rig.TryGet(out string error, "team/ALPHA");
            check(got?["team/ALPHA"] == Alpha && rig.Audits.Single().Outcome == RetrievalOutcomeKind.Stale && rig.Audits[0].ErrorKind == ProviderErrorKind.Unavailable
                && rig.Invocations == 1 + ProviderPolicy.MaxAttempts, "delivery: outage within window serves Stale after the retries (" + error + ")");
            check(rig.Row() == (ciphertext, verified), "delivery: failed refresh keeps old ciphertext and old last_verified");

            rig.Clock.Advance(TimeSpan.FromMinutes(10));
            got = rig.TryGet(out error, "team/ALPHA");
            check(got?["team/ALPHA"] == Alpha, "delivery: at exactly MaxStaleDuration the value is still served stale (" + error + ")");

            rig.Clock.Advance(TimeSpan.FromSeconds(1));
            rig.Audits.Clear();
            got = rig.TryGet(out error, "team/ALPHA");
            check(got is null && rig.Audits.Single().Outcome == RetrievalOutcomeKind.Failed && rig.Audits[0].ErrorKind == ProviderErrorKind.Unavailable,
                "delivery: outage past window fails closed (" + error + ")");
            check(rig.Row() == (ciphertext, verified), "delivery: failures never extend the stale window (row unchanged)");

            rig.Adapter.Returns("kv/ALPHA", Bravo);
            got = rig.TryGet(out error, "team/ALPHA");
            check(got?["team/ALPHA"] == Bravo && rig.Row().LastVerified == rig.Clock.Now.UtcTicks, "delivery: provider recovered: the next retrieval replaces the stale row");
        }
    }

    private static void StaleKinds(Action<bool, string> check)
    {
        foreach (ProviderErrorKind kind in Enum.GetValues<ProviderErrorKind>())
        {
            using Rig rig = new(Hour);
            rig.TryGet(out _, "team/ALPHA");
            rig.Clock.Advance(TimeSpan.FromMinutes(50));
            rig.Adapter.Fails("kv/ALPHA", kind);
            Dictionary<string, string>? got = rig.TryGet(out string error, "team/ALPHA");
            bool eligible = kind is ProviderErrorKind.Unavailable or ProviderErrorKind.RateLimited;
            check(eligible ? got?["team/ALPHA"] == Alpha : got is null && error.Contains(kind.ToString(), StringComparison.Ordinal),
                $"delivery: stale only for Unavailable/RateLimited: {kind} with a row within the window {(eligible ? "serves stale" : "still fails")} ({error})");
        }

        // A batch-wide exception is final for the whole batch the same way.
        using (Rig rig = new(Hour))
        {
            rig.TryGet(out _, "team/ALPHA");
            rig.Clock.Advance(TimeSpan.FromMinutes(50));
            rig.Adapter.Throws("kv/ALPHA", ProviderErrorKind.AccessDenied);
            check(rig.TryGet(out string error, "team/ALPHA") is null && error.Contains("AccessDenied", StringComparison.Ordinal), "delivery: batch-wide AccessDenied fails closed with a row in the window");
        }

        // An empty provider value is unset (ruling 8): a hard failure, never stale-served.
        using (Rig rig = new(Hour))
        {
            rig.TryGet(out _, "team/ALPHA");
            rig.Clock.Advance(TimeSpan.FromMinutes(50));
            rig.Adapter.ReturnsBytes("kv/ALPHA", []);
            check(rig.TryGet(out string error, "team/ALPHA") is null && error.Contains("SecretNotFound", StringComparison.Ordinal), "delivery: an empty provider value fails closed, not stale");
        }
    }

    private static void Policy(Action<bool, string> check)
    {
        using Rig rig = new(Hour);
        rig.TryGet(out _, "team/ALPHA");
        long verified = rig.Row().LastVerified;
        rig.Clock.Advance(TimeSpan.FromMinutes(30));
        rig.TryGet(out _, "team/ALPHA");
        check(rig.Invocations == 1, "delivery: at 30 minutes of 60 the value is cached");

        rig.Providers.SetMaxStale(rig.Instance.Id, TimeSpan.FromMinutes(20));
        rig.Adapter.Fails("kv/ALPHA", ProviderErrorKind.Unavailable);
        Dictionary<string, string>? got = rig.TryGet(out string error, "team/ALPHA");
        check(got is null && rig.Invocations > 1 && rig.Row().LastVerified == verified, "delivery: lowering MaxStale immediately enforces the shorter limit (" + error + ")");
    }

    private static void Resolution(Action<bool, string> check)
    {
        using (Rig rig = new(Hour))
        {
            // A native secret of the same name exists, and the mount selects the name: no fall through.
            if (SecretStoreTests.Put(rig.Native, new Dictionary<string, string> { ["team/MISSING"] = NativeValue }) is { } problem)
            {
                throw new InvalidOperationException(problem);
            }

            int decrypts = rig.Cipher.Decrypts;
            Dictionary<string, string>? got = rig.TryGet(out string error, "team/MISSING");
            check(got is null && error == "team/MISSING is not available" && rig.Cipher.Decrypts == decrypts && rig.Invocations == 0,
                "delivery: no entry -> hard error, native store NOT consulted (" + error + ")");

            got = rig.TryGet(out error, "team/MISSING", "NATIVE_ONE");
            check(got is null && rig.Cipher.Decrypts == decrypts && rig.Invocations == 0, "delivery: no entry fails the whole call before any decrypt");
        }

        using (Rig rig = new(Hour))
        {
            if (SecretStoreTests.Put(rig.Native, new Dictionary<string, string> { ["team/ALPHA"] = NativeValue }) is { } problem)
            {
                throw new InvalidOperationException(problem);
            }

            Dictionary<string, string>? got = rig.TryGet(out string error, "team/ALPHA");
            check(got?["team/ALPHA"] == Alpha, "delivery: mount shadows a same-named native secret (" + error + ")");

            // An individual mount inside the tree: exact path wins, and without its own entry it is a hard error (no fall through to the tree entry).
            rig.Providers.AddMount(rig.Instance.Id, MountKind.Single, "team/ALPHA", "elsewhere/ALPHA");
            rig.Audits.Clear();
            got = rig.TryGet(out error, "team/ALPHA");
            check(got is null && error == "team/ALPHA is not available" && rig.Audits is [{ Path: "team/ALPHA", Outcome: RetrievalOutcomeKind.Failed, ErrorKind: null, InstanceName: "vault-one" }],
                "delivery: an individual mount without its entry does not fall through to the tree entry, and is audited Failed against the selected instance");
        }
    }

    private static void Batching(Action<bool, string> check)
    {
        using (Rig rig = new(Hour))
        {
            Mount single = rig.Providers.AddMount(rig.Instance.Id, MountKind.Single, "solo/TOKEN", "kv/ALPHA");
            rig.Entries(single, ("solo/TOKEN", "kv/ALPHA", "ext-a"));
            using SecretValues values = rig.Get("team/ALPHA", "solo/TOKEN");
            check(rig.Invocations == 1 && rig.Adapter.Invocations[0].Count == 1 && rig.CacheRows() == 1 && values.Text("team/ALPHA") == Alpha && values.Text("solo/TOKEN") == Alpha
                && !ReferenceEquals(values.Bytes("team/ALPHA"), values.Bytes("solo/TOKEN")), "delivery: two logical paths one external id: one adapter request, one cache row, own arrays");
            check(rig.Audits.Count == 2 && rig.Audits.All(audit => audit.Outcome == RetrievalOutcomeKind.Fresh), "delivery: each logical path is audited");
        }

        using (Rig rig = new(Hour))
        {
            rig.Entries(rig.Tree, ("team/ALPHA", "kv/ALPHA", "ext-a"), ("team/BRAVO", "kv/BRAVO", "ext-b"), ("team/CHARLIE", "kv/CHARLIE", "ext-c"));
            rig.Adapter.Returns("kv/BRAVO", Bravo).Returns("kv/CHARLIE", Charlie);
            using SecretValues values = rig.Get("team/ALPHA", "team/BRAVO", "team/CHARLIE");
            check(rig.Invocations == 1 && rig.Adapter.Invocations[0].Count == 3 && values.Text("team/BRAVO") == Bravo && values.Text("team/CHARLIE") == Charlie && rig.CacheRows() == 3,
                "delivery: batch of three: one adapter invocation per instance");

            // Cache hits are not sent: only the uncached one goes to the adapter.
            rig.Entries(rig.Tree, ("team/ALPHA", "kv/ALPHA", "ext-a"), ("team/BRAVO", "kv/BRAVO", "ext-b"), ("team/CHARLIE", "kv/CHARLIE", "ext-c"), ("team/DELTA", "kv/DELTA", "ext-d"));
            rig.Adapter.Returns("kv/DELTA", "Delta-Provider-Value-4");
            using SecretValues more = rig.Get("team/ALPHA", "team/BRAVO", "team/DELTA");
            check(rig.Invocations == 2 && rig.Adapter.Invocations[1].Count == 1 && rig.Adapter.Invocations[1][0].Path == "kv/DELTA" && more.Text("team/DELTA") == "Delta-Provider-Value-4",
                "delivery: cache hits are not sent to the adapter");
        }

        using (Rig rig = new(Hour))
        {
            (ProviderInstance second, FakeProviderAdapter other) = rig.AddInstance("vault-two", Hour);
            Mount mount = rig.Providers.AddMount(second.Id, MountKind.Tree, "ops", "base");
            rig.Entries(mount, ("ops/BRAVO", "base/BRAVO", "ext-a"));
            other.Returns("base/BRAVO", Bravo);
            using SecretValues values = rig.Get("team/ALPHA", "ops/BRAVO");
            check(rig.Invocations == 1 && other.Invocations.Count == 1 && rig.Adapter.Invocations[0].Single().Path == "kv/ALPHA" && other.Invocations[0].Single().Path == "base/BRAVO"
                && values.Text("team/ALPHA") == Alpha && values.Text("ops/BRAVO") == Bravo && rig.CacheRows() == 2,
                "delivery: two instances: one invocation each, never combined (same external id text, two cache rows)");
            check(rig.Audits.Single(audit => audit.Path == "ops/BRAVO").InstanceId == second.Id && rig.Audits.Single(audit => audit.Path == "ops/BRAVO").InstanceName == "vault-two",
                "delivery: the audit names the selected instance");
        }
    }

    private static void Malformed(Action<bool, string> check)
    {
        using Rig rig = new(Hour);
        rig.Entries(rig.Tree, ("team/ALPHA", "kv/ALPHA", "ext-a"), ("team/BRAVO", "kv/BRAVO", "ext-b"));
        rig.Adapter.Handler = (_, requests, _) => Task.FromResult<IReadOnlyList<ProviderSecretResult>>(
            [new ProviderSecretResult(requests[0].RequestId, new RetrieveSecretResult(Encoding.UTF8.GetBytes(Alpha))), new ProviderSecretResult(requests[0].RequestId, new RetrieveSecretResult(Encoding.UTF8.GetBytes(Bravo)))]);
        Dictionary<string, string>? got = rig.TryGet(out string error, "team/ALPHA", "team/BRAVO");
        check(got is null && error.Contains("InvalidResponse", StringComparison.Ordinal) && rig.CacheRows() == 0 && !error.Contains(Alpha, StringComparison.Ordinal),
            "delivery: malformed batch delivers nothing and caches nothing (" + error + ")");

        // One item failing does not hide another's value, but the call still fails closed and the good one is cached.
        rig.Adapter.Handler = null;
        rig.Adapter.Fails("kv/BRAVO", ProviderErrorKind.AccessDenied);
        rig.Audits.Clear();
        rig.AuditCalls = 0;
        got = rig.TryGet(out error, "team/ALPHA", "team/BRAVO");
        check(got is null && error.Contains("team/BRAVO", StringComparison.Ordinal) && error.Contains("AccessDenied", StringComparison.Ordinal) && !error.Contains("team/ALPHA", StringComparison.Ordinal)
            && rig.CacheRows() == 1, "delivery: one AccessDenied item fails the call; the other item's value is still cached (" + error + ")");
        check(rig.AuditCalls == 1 && rig.Audits.Count == 2 && rig.Audits.All(audit => audit.Outcome == RetrievalOutcomeKind.Failed)
            && rig.Audits.Single(audit => audit.Path == "team/BRAVO").ErrorKind == ProviderErrorKind.AccessDenied && rig.Audits.Single(audit => audit.Path == "team/ALPHA").ErrorKind is null,
            "delivery: in one sink call, the failed name is audited Failed with its kind and the held-back success Failed with none");
    }

    private static void Invalidation(Action<bool, string> check)
    {
        using (Rig rig = new(Hour))
        {
            rig.Adapter.Handler = (_, requests, _) =>
            {
                rig.Invalidation.Apply(rig.Instance.Id, new InvalidateProviderDataEvent(ExternalSecretIds: ["ext-a"]));

                return Task.FromResult<IReadOnlyList<ProviderSecretResult>>([new ProviderSecretResult(requests[0].RequestId, new RetrieveSecretResult(Encoding.UTF8.GetBytes(Alpha)))]);
            };
            rig.Audits.Clear();
            Dictionary<string, string>? got = rig.TryGet(out string error, "team/ALPHA");
            check(got is null && rig.CacheRows() == 0 && !error.Contains(Alpha, StringComparison.Ordinal) && rig.Audits.Single().Outcome == RetrievalOutcomeKind.Failed,
                "delivery: invalidation during retrieval discards the result (not cached, not delivered) (" + error + ")");
        }

        using (Rig rig = new(Hour))
        {
            // A row exists in the stale window; the invalidation deletes it during an outage: no stale.
            rig.TryGet(out _, "team/ALPHA");
            rig.Clock.Advance(TimeSpan.FromMinutes(50));
            rig.Adapter.Handler = (_, requests, _) =>
            {
                rig.Invalidation.Apply(rig.Instance.Id, new InvalidateProviderDataEvent(ExternalSecretIds: ["ext-a"]));

                return Task.FromResult<IReadOnlyList<ProviderSecretResult>>([.. requests.Select(request => new ProviderSecretResult(request.RequestId, null, ProviderErrorKind.Unavailable))]);
            };
            Dictionary<string, string>? got = rig.TryGet(out string error, "team/ALPHA");
            check(got is null && rig.CacheRows() == 0, "delivery: an invalidation during an outage leaves nothing to serve stale (" + error + ")");
        }

        using (Rig rig = new(Hour))
        {
            // An invalidation of an unrelated mount of another instance does not disturb this one.
            (ProviderInstance second, _) = rig.AddInstance("vault-two", Hour);
            rig.Adapter.Handler = (_, requests, _) =>
            {
                rig.Invalidation.Apply(second.Id, new InvalidateProviderDataEvent(InvalidateEntireProviderInstance: true));

                return Task.FromResult<IReadOnlyList<ProviderSecretResult>>([new ProviderSecretResult(requests[0].RequestId, new RetrieveSecretResult(Encoding.UTF8.GetBytes(Alpha)))]);
            };
            Dictionary<string, string>? got = rig.TryGet(out string error, "team/ALPHA");
            check(got?["team/ALPHA"] == Alpha && rig.CacheRows() == 1, "delivery: an invalidation of another instance does not discard this retrieval (" + error + ")");
        }
    }

    private static void Mixed(Action<bool, string> check)
    {
        using Rig rig = new(Hour);
        using (SecretValues values = rig.Get("NATIVE_ONE", "team/ALPHA"))
        {
            check(values.Text("NATIVE_ONE") == NativeValue && values.Text("team/ALPHA") == Alpha && values.Names.Count == 2, "delivery: native and mounted names in one call both delivered");
            check(rig.Audits.Count == 1 && rig.Audits[0].Path == "team/ALPHA", "delivery: native names are not provider-audited");
        }

        using (SecretValues values = rig.Get("NATIVE_ONE"))
        {
            check(values.Text("NATIVE_ONE") == NativeValue && rig.Invocations == 1, "delivery: a native-only call never calls an adapter");
        }

        check(rig.TryGet(out string error, "NOT_THERE") is null && error.Contains("NOT_THERE is not in the store", StringComparison.Ordinal), "delivery: a missing native name keeps the native error");
        check(rig.TryGet(out error, "team/ALPHA", "team/ALPHA") is null && error == "the secret names are not valid", "delivery: duplicate names are refused");
        check(rig.TryGet(out error, "bad name") is null && error == "the secret names are not valid", "delivery: invalid names are refused");

        // Native fails (no unlock): the mounted value is not delivered either.
        int before = rig.Invocations;
        bool threw = false;
        try
        {
            rig.Source.GetValues(["NATIVE_ONE", "team/ALPHA"], null);
        }
        catch (SecretStoreException)
        {
            threw = true;
        }

        check(threw && rig.Invocations == before, "delivery: a native failure fails the whole call before any provider read");
    }

    private static void Audit(Action<bool, string> check)
    {
        using Rig rig = new(Hour);
        rig.TryGet(out _, "team/ALPHA");
        rig.Clock.Advance(TimeSpan.FromMinutes(10));
        rig.TryGet(out _, "team/ALPHA");
        rig.Clock.Advance(TimeSpan.FromMinutes(40));
        rig.Adapter.Fails("kv/ALPHA", ProviderErrorKind.RateLimited);
        rig.TryGet(out _, "team/ALPHA");
        rig.Clock.Advance(TimeSpan.FromMinutes(20));
        rig.TryGet(out _, "team/ALPHA");

        check(rig.Audits.Select(audit => audit.Outcome).SequenceEqual([RetrievalOutcomeKind.Fresh, RetrievalOutcomeKind.Cached, RetrievalOutcomeKind.Stale, RetrievalOutcomeKind.Failed])
            && rig.Audits.All(audit => audit.Path == "team/ALPHA" && audit.InstanceId == rig.Instance.Id && audit.InstanceName == "vault-one"),
            "delivery: audit outcomes Fresh, Cached, Stale, Failed carry path and instance");
        check(rig.Audits[0].ErrorKind is null && rig.Audits[1].ErrorKind is null && rig.Audits[3].ErrorKind == ProviderErrorKind.RateLimited, "delivery: audit error kinds");
        string text = string.Join("\n", rig.Audits.Select(audit => audit.ToString()));
        check(!text.Contains(Alpha, StringComparison.Ordinal) && !text.Contains("encrypted:", StringComparison.Ordinal) && !text.Contains("ext-a", StringComparison.Ordinal) && !text.Contains("{}", StringComparison.Ordinal),
            "delivery: audit records carry no value, ciphertext or configuration");
        check(typeof(ProviderAudit).GetProperties().All(property => property.PropertyType != typeof(byte[])), "delivery: ProviderAudit has no byte[] member");
    }

    private static void Zeroing(Action<bool, string> check)
    {
        using Rig rig = new(Hour);
        rig.Entries(rig.Tree, ("team/ALPHA", "kv/ALPHA", "ext-a"), ("team/BRAVO", "kv/BRAVO", "ext-b"));
        rig.Adapter.Fails("kv/BRAVO", ProviderErrorKind.AccessDenied);
        List<byte[]> zeroed = [];
        rig.Source.Discarded = buffers => zeroed.AddRange(buffers);
        Dictionary<string, string>? got = rig.TryGet(out _, "NATIVE_ONE", "team/ALPHA", "team/BRAVO");
        check(got is null && zeroed.Count >= 2 && zeroed.All(buffer => buffer.Length > 0 && buffer.All(b => b == 0)), "delivery: values zeroed on failure (native and retrieved) (" + zeroed.Count + " buffers)");

        // A cached value decrypted before a later failure is zeroed too.
        zeroed.Clear();
        rig.Clock.Advance(TimeSpan.FromMinutes(5));
        got = rig.TryGet(out _, "team/ALPHA", "team/BRAVO");
        check(got is null && rig.Invocations == 2 && zeroed.Count >= 1 && zeroed.All(buffer => buffer.Length > 0 && buffer.All(b => b == 0)), "delivery: a decrypted cached value is zeroed when the call fails");

        // On success the intermediate buffers are zeroed and the delivered ones are not.
        zeroed.Clear();
        using SecretValues values = rig.Get("NATIVE_ONE", "team/ALPHA");
        check(values.Text("team/ALPHA") == Alpha && values.Text("NATIVE_ONE") == NativeValue && zeroed.All(buffer => buffer.All(b => b == 0))
            && !zeroed.Any(buffer => ReferenceEquals(buffer, values.Bytes("team/ALPHA")) || ReferenceEquals(buffer, values.Bytes("NATIVE_ONE"))), "delivery: delivered arrays belong to the result; intermediates are zeroed");
    }

    private static void Locked(Action<bool, string> check)
    {
        using Rig rig = new(Hour);
        rig.TryGet(out _, "team/ALPHA");
        (string ciphertext, long verified) = rig.Row();
        rig.Lock.Lock("test");
        rig.Clock.Advance(TimeSpan.FromMinutes(10));
        rig.Audits.Clear();
        Dictionary<string, string>? got = rig.TryGet(out string error, "team/ALPHA");
        check(got is null && error == "the authority is locked, so no mounted secret is delivered" && rig.Invocations == 1 && rig.Row() == (ciphertext, verified),
            "delivery: locked authority: a mounted name fails closed (nothing read, retrieved or signed) (" + error + ")");
        check(rig.Audits is [{ Path: "team/ALPHA", Outcome: RetrievalOutcomeKind.Failed, ErrorKind: null }], "delivery: locked authority: the refused mounted name is audited Failed");

        rig.Audits.Clear();
        using (SecretValues native = rig.Get("NATIVE_ONE"))
        {
            check(native.Text("NATIVE_ONE") == NativeValue && rig.Audits.Count == 0, "delivery: locked authority: a native-only call is not affected");
        }

        rig.Clock.Advance(TimeSpan.FromMinutes(40));
        rig.Adapter.Fails("kv/ALPHA", ProviderErrorKind.Unavailable);
        got = rig.TryGet(out error, "team/ALPHA", "NATIVE_ONE");
        check(got is null && rig.Invocations == 1 && rig.Row() == (ciphertext, verified), "delivery: locked authority: no stale row is served during an outage (" + error + ")");

        rig.Lock.Unlock(UnlockMethod.Seam);
        got = rig.TryGet(out error, "team/ALPHA");
        check(got?["team/ALPHA"] == Alpha, "delivery: unlocked again: the mounted name is delivered (" + error + ")");
    }

    private static void NoStoreKey(Action<bool, string> check)
    {
        using Rig rig = new(Hour, withStoreKey: false);
        Dictionary<string, string>? got = rig.TryGet(out string error, "team/ALPHA");
        check(got?["team/ALPHA"] == Alpha && rig.Audits.Single().Outcome == RetrievalOutcomeKind.Fresh && rig.CacheRows() == 0,
            "delivery: no store key yet: the fresh value is delivered and not persisted (" + error + ")");
    }

    private static void Tampered(Action<bool, string> check)
    {
        using Rig rig = new(Hour);
        rig.TryGet(out _, "team/ALPHA");
        rig.Clock.Advance(TimeSpan.FromMinutes(10));

        // A planted ciphertext (valid for the store public key) is never served: a miss, refetched.
        string storeKey = TestState.Current(rig.Db)!.Store;
        rig.Exec("UPDATE provider_cache SET ciphertext = $c", ("$c", DotenvxCipher.Instance.Encrypt("Planted-Value-9", storeKey)));
        Dictionary<string, string>? got = rig.TryGet(out string error, "team/ALPHA");
        check(got?["team/ALPHA"] == Alpha && rig.Invocations == 2, "delivery: a tampered row is a miss and is refetched (" + error + ")");

        // During an outage a tampered row is not served stale either.
        rig.Clock.Advance(TimeSpan.FromMinutes(50));
        rig.Exec("UPDATE provider_cache SET ciphertext = $c", ("$c", DotenvxCipher.Instance.Encrypt("Planted-Value-9", storeKey)));
        rig.Adapter.Fails("kv/ALPHA", ProviderErrorKind.Unavailable);
        got = rig.TryGet(out error, "team/ALPHA");
        check(got is null && !error.Contains("Planted", StringComparison.Ordinal), "delivery: a tampered row is never served stale (" + error + ")");

        // A deleted row: nothing stale.
        rig.Adapter.Returns("kv/ALPHA", Alpha);
        rig.TryGet(out _, "team/ALPHA");
        rig.Clock.Advance(TimeSpan.FromMinutes(50));
        rig.Exec("DELETE FROM provider_cache");
        rig.Adapter.Fails("kv/ALPHA", ProviderErrorKind.Unavailable);
        check(rig.TryGet(out _, "team/ALPHA") is null, "delivery: a deleted row leaves nothing to serve stale");

        // A row with a pushed-forward last_verified (to look fresh) fails its seal.
        rig.Adapter.Returns("kv/ALPHA", Alpha);
        rig.TryGet(out _, "team/ALPHA");
        int before = rig.Invocations;
        rig.Clock.Advance(TimeSpan.FromMinutes(50));
        rig.Exec("UPDATE provider_cache SET last_verified = $t", ("$t", rig.Clock.Now.UtcTicks));
        rig.TryGet(out _, "team/ALPHA");
        check(rig.Invocations == before + 1, "delivery: a row whose last_verified was moved forward is a miss");
    }

    private static void Listing(Action<bool, string> check)
    {
        using Rig rig = new(Hour);
        rig.Entries(rig.Tree, ("team/ALPHA", "kv/ALPHA", "ext-a"), ("team/BRAVO", "kv/BRAVO", "ext-b"));
        if (SecretStoreTests.Put(rig.Native, new Dictionary<string, string> { ["team/ALPHA"] = NativeValue, ["ZED"] = NativeValue }) is { } problem)
        {
            throw new InvalidOperationException(problem);
        }

        check(rig.Source.ListNames().SequenceEqual(["NATIVE_ONE", "ZED", "team/ALPHA", "team/BRAVO"]), "delivery: ListNames is native plus namespace paths, distinct and sorted ordinal ("
            + string.Join(",", rig.Source.ListNames()) + ")");
    }
}

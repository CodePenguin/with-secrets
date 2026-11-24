using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text;

using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>
/// Mounted secrets through the real product wiring (10.3): a host service whose authority composes <see cref="ProviderSecretSource" /> over its native store, a
/// provider type "test" registered by the test (the product registers none), runs over the command line's endpoint, approvals, the signed audit pipeline,
/// the authority lock and, in remote mode, a host whose authority runs the adapters. The values here are canaries; none may appear in an event or the audit.
/// </summary>
internal static class ProviderEndToEndTests
{
    private const string Github = "Github-Provider-Canary-5f1e09";
    private const string Older = "Github-Older-Canary-77ad31";
    private const string NativeValue = "Native-Value-Canary-c0ffee";
    private const string Mounted = "team/dev/GITHUB";
    private const string ProviderPath = "kv/dev/GITHUB";
    private const string External = "ext-gh";
    private static readonly TimeSpan Hour = TimeSpan.FromHours(1);

    private sealed class Rig : IDisposable
    {
        private readonly string _dir;
        private HttpClient? _http;

        public Rig(string root, bool machineEndpoint = false, Action<FakeProviderAdapter>? configure = null)
        {
            configure?.Invoke(Adapter);
            _dir = Path.Combine(root, "e2e-" + Guid.NewGuid().ToString("N")[..8]);
            string state = Path.Combine(_dir, "state");
            Work = Path.Combine(_dir, "work");
            Directory.CreateDirectory(Work);
            State = TestState.Seeded(Path.Combine(state, WithSecretsDatabase.FileName));
            Native = new SecretStore(State);
            if (SecretStoreTests.Put(Native, new Dictionary<string, string> { ["NATIVE_ONE"] = NativeValue }) is { } problem)
            {
                throw new InvalidOperationException(problem);
            }

            TestSigner.Enroll(State);
            Machine = new TestMachine(state, trusted: true, hostName: "provider-authority");

            // The configuration rows are made before the service starts (the admin screens that make them are plan 3); the service adds the instance to its registry at startup.
            ProviderStore setup = new(Machine.Deployment.Store);
            Instance = setup.AddInstance("vault-one", "test", """{"label":"one"}""", Hour);
            Tree = setup.AddMount(Instance.Id, MountKind.Tree, "team", "kv");
            setup.ReplaceEntries(Tree.Id, [new NamespaceEntry(Tree.Id, Mounted, ProviderPath, External, null, DescriptionSource.Provider)]);
            Registry.RegisterType("test", "1.0", () => Adapter, () => new FakeConfiguration());
            Adapter.Returns(ProviderPath, Github);

            // The periodic reconciliation lists the mount once at startup: it lists the seeded entry, so it leaves the namespace as seeded.
            Adapter.ListHandler = (_, _) => Task.FromResult(new ListSecretsResult([new ProviderSecretInfo("dev/GITHUB", External, null)], null, true));

            Service = HostService.Start(new HostServiceOptions
            {
                CommandLineEndpoint = HostServiceTests.Rig.TestEndpoint(),
                Lock = AuthorityLock.UnlockedForTests(),
                UnlockProtection = new ReversibleProtection(),
                State = State,
                Store = Native,
                Deployment = Machine.Deployment,
                Port = 0,
                TimeLimit = TimeSpan.FromSeconds(30),
                ApproverFactory = (_, _) =>
                {
                    FakeApprover made = new(true, unlock: () =>
                    {
                        During?.Invoke();

                        return SecretStoreTests.AdminUnlock(State);
                    });
                    Approvers.Enqueue(made);

                    return made;
                },
                ProviderRegistry = Registry,
                MachineEndpoint = machineEndpoint ? new MachineListenerOptions { Port = 0 } : null,
                UseApprovalQueueForMachineLaunches = false,
                AuditUploadInterval = TimeSpan.FromMilliseconds(300),
            });
        }

        public string Work { get; }

        public StateDatabase State { get; }

        public SecretStore Native { get; }

        public TestMachine Machine { get; }

        public ProviderInstance Instance { get; }

        public Mount Tree { get; }

        public FakeProviderAdapter Adapter { get; } = new();

        public ProviderRegistry Registry { get; } = new();

        public HostService Service { get; }

        public ConcurrentQueue<FakeApprover> Approvers { get; } = new();

        /// <summary>Runs while the approving tap is made (after the decision, before anything is decrypted).</summary>
        public Action? During { get; set; }

        public ProviderAuthority Providers => Service.Providers ?? throw new InvalidOperationException("the service composed no provider source");

        public IReadOnlyList<ApprovalRequest> Pages => [.. Approvers.SelectMany(item => item.Requests)];

        public HttpClient Http => _http ??= new HttpClient(Service.Endpoint.CreateHandler()) { Timeout = TimeSpan.FromSeconds(60) };

        public string StoreKey => Native.Current().Manifest!.Store;

        /// <summary>Every signed event of this machine: those still in its outbox and those the authority already holds.</summary>
        public IReadOnlyList<AuditEvent> Audit()
        {
            Dictionary<string, AuditEvent> all = new(StringComparer.Ordinal);
            foreach (AuditEvent item in Service.Audit.Outbox.Pending(10000).Concat(Machine.Deployment.Store.AuditHistory(new AuditQuery(Limit: 1000)).Select(record => record.Event)))
            {
                all[item.EventId] = item;
            }

            return [.. all.Values.OrderBy(item => item.Sequence)];
        }

        public IReadOnlyList<AuditEvent> ProviderEvents() => [.. Audit().Where(item => item.Outcome.StartsWith("provider-", StringComparison.Ordinal) && item.Outcome != "provider-data-invalidated")];

        public void Dispose()
        {
            _http?.Dispose();
            Service.Dispose();
            Machine.Deployment.Dispose();
            Machine.Dispose();
        }
    }

    private sealed record Ran(HostServiceTests.Raw Raw, string? Value)
    {
        public bool Started => Value is not null;
    }

    /// <summary>A script that writes the TOKEN it was given beside it and prints it (the service redacts it), then exits 4.</summary>
    private static (string Program, string ValueFile) ValueScript(string work, string name)
    {
        string file = name + (OperatingSystem.IsWindows() ? ".cmd" : ".sh");
        string path = Path.Combine(work, file);
        if (OperatingSystem.IsWindows())
        {
            File.WriteAllText(path, "@echo off\r\necho %TOKEN%>\"%~dpn0.val\"\r\necho t=%TOKEN%\r\nexit /b 4\r\n");
        }
        else
        {
            File.WriteAllText(path, "#!/bin/sh\nprintf '%s' \"$TOKEN\" > \"" + path + ".val\"\necho \"t=$TOKEN\"\nexit 4\n");
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        return ("./" + file, Path.Combine(work, OperatingSystem.IsWindows() ? name + ".val" : file + ".val"));
    }

    private static LaunchRequest Request(string work, string program, string secret)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;

        return new LaunchRequest(LaunchProtocol.Version, "pe2e-" + Guid.NewGuid().ToString("N")[..12], now, now.AddMinutes(5), "bm9uY2UtMDAwMDAwMDE" + Guid.NewGuid().ToString("N")[..6], [secret], [new LaunchMapping("TOKEN", secret)],
            "provider test", program, [], work, [], [], new Dictionary<string, string>(), HostServiceTests.Env(), []);
    }

    private static async Task<HostServiceTests.Raw> Post(HttpClient http, Uri baseUri, LaunchRequest request)
    {
        using HttpRequestMessage message = new(HttpMethod.Post, new Uri(baseUri, "v1/launch")) { Content = new StringContent(request.Canonical(), new UTF8Encoding(false), new MediaTypeHeaderValue("application/json")) };
        message.Headers.Add(HostService.DigestHeader, request.Digest());
        message.Headers.ConnectionClose = true;
        using HttpResponseMessage response = await http.SendAsync(message, HttpCompletionOption.ResponseHeadersRead);
        using StreamReader reader = new(await response.Content.ReadAsStreamAsync(), new UTF8Encoding(false));
        List<string> lines = [];
        List<LaunchEvent> events = [];
        StringBuilder all = new();
        while (await reader.ReadLineAsync() is { } line)
        {
            all.AppendLine(line);
            if (response.StatusCode != HttpStatusCode.OK)
            {
                continue;
            }

            lines.Add(line);
            if (LaunchEvent.TryParse(line, out LaunchEvent? parsed, out _))
            {
                events.Add(parsed!);
            }
        }

        return new HostServiceTests.Raw(response.StatusCode, all.ToString(), lines, events);
    }

    private static async Task<Ran> Run(Rig rig, string name, string secret = Mounted)
    {
        (string program, string valueFile) = ValueScript(rig.Work, name);
        File.Delete(valueFile);
        HostServiceTests.Raw raw = await Post(rig.Http, rig.Service.Endpoint.BaseUri, Request(rig.Work, program, secret));

        return new Ran(raw, File.Exists(valueFile) ? File.ReadAllText(valueFile).Trim() : null);
    }

    private static bool Clean(string text) => !text.Contains(Github, StringComparison.Ordinal) && !text.Contains(Older, StringComparison.Ordinal) && !text.Contains(NativeValue, StringComparison.Ordinal) && !text.Contains("encrypted:", StringComparison.Ordinal);

    public static async Task Run(Action<bool, string> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "ws-providere2e-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);
        try
        {
            await Delivery(check, root);
            await Unavailable(check, root);
            await Locked(check, root);
            await HangingInitialize(check, root);
            await InvalidationWiring(check, root);
            AuditSink(check, root);
            Schema(check, root);
            await Remote(check, root);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            try
            {
                Directory.Delete(root, true);
            }
            catch (IOException)
            {
                // A stray temp file is harmless.
            }
        }
    }

    /// <summary>Fresh, then Cached after a new once-only approval, then Stale under an outage, then Failed for a final error, each audited with path and instance.</summary>
    private static async Task Delivery(Action<bool, string> check, string root)
    {
        using Rig rig = new(root);
        check(rig.Service.Providers is not null && rig.Registry.Status(rig.Instance.Id).Lifecycle == AdapterLifecycleState.Ready && rig.Adapter.Context?.ProviderType == "test",
            "e2e wiring: the service composes the provider source over its native store and adds the stored instance to the registry at startup");

        Ran first = await Run(rig, "fresh");
        ApprovalRequest? page = rig.Pages.FirstOrDefault();
        check(page?.Sources is { } sources && sources.TryGetValue(Mounted, out string? label) && label == "vault-one" && ApprovalSummary.BuildMessage(page).Contains(Mounted + " (vault-one)", StringComparison.Ordinal),
            "e2e fresh: the approval page names the provider instance for the mounted secret (" + (page is null ? "no page" : ApprovalSummary.BuildMessage(page).Split('\n').FirstOrDefault(line => line.Contains(Mounted, StringComparison.Ordinal))) + ")");
        check(first.Raw.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 4 } && first.Value == Github && first.Raw.Stdout.Contains("t=[REDACTED]", StringComparison.Ordinal) && rig.Adapter.Invocations.Count == 1,
            "e2e fresh: the provider value reaches the child (and only the child), retrieved in one batch (" + first.Raw.Result + " " + first.Raw.Stderr.Trim() + ")");
        bool audited = await HostServiceTests.WaitFor(() => rig.ProviderEvents().Any(item => item.Outcome == "provider-fresh"));
        AuditEvent? fresh = rig.ProviderEvents().FirstOrDefault(item => item.Outcome == "provider-fresh");
        check(audited && fresh is { Type: AuditEventTypes.Admin } && fresh.Meta.GetValueOrDefault("path") == Mounted && fresh.Meta.GetValueOrDefault("instance") == rig.Instance.Id.ToString("D") && fresh.Meta.GetValueOrDefault("instanceName") == "vault-one",
            "e2e fresh: a signed audit event names the path, the instance and the outcome Fresh (" + fresh?.ToJson() + ")");

        Ran second = await Run(rig, "cached");
        check(rig.Pages.Count == 2 && second.Value == Github && rig.Adapter.Invocations.Count == 1 && rig.Machine.Deployment.Store.Grants().Count(grant => grant.Usage == GrantUsage.Once && grant.Status == "consumed") == 2,
            "e2e cached: the same run again needs a new approval (the once-only grant was consumed) and the mounted value is served from the cache without a provider call (" + second.Raw.Result + " " + second.Raw.Stderr.Trim() + ")");
        check(await HostServiceTests.WaitFor(() => rig.ProviderEvents().Any(item => item.Outcome == "provider-cached" && item.Meta.GetValueOrDefault("path") == Mounted)), "e2e cached: audited Cached with the path");

        // The row was verified 50 minutes ago (beyond 75% of the hour): the provider is asked, is down, and the older value is served stale. (A row is never replaced by an
        // older one, so the current row goes first.)
        rig.Providers.Store.DeleteCache(rig.Instance.Id, null);
        rig.Providers.Cache.PutAll(rig.Instance.Id, [(External, Encoding.UTF8.GetBytes(Older))], DateTimeOffset.UtcNow - TimeSpan.FromMinutes(50), rig.StoreKey);
        rig.Adapter.Fails(ProviderPath, ProviderErrorKind.Unavailable);
        Ran stale = await Run(rig, "stale");
        check(stale.Value == Older && rig.Adapter.Invocations.Count == 1 + ProviderPolicy.MaxAttempts, "e2e stale: under an outage (retries exhausted) the older value within MaxStaleDuration is delivered (" + stale.Raw.Result + " " + stale.Raw.Stderr.Trim() + ")");
        check(await HostServiceTests.WaitFor(() => rig.ProviderEvents().Any(item => item.Outcome == "provider-stale" && item.Meta.GetValueOrDefault("errorKind") == "Unavailable")), "e2e stale: audited Stale with the error kind");

        rig.Adapter.Fails(ProviderPath, ProviderErrorKind.AccessDenied);
        Ran denied = await Run(rig, "denied");
        check(!denied.Started && denied.Raw.Result is { ExitCode: RunCommand.StoreError } && Clean(denied.Raw.Stderr), "e2e failed: a final AccessDenied fails closed and the child never starts (" + denied.Raw.Result + " " + denied.Raw.Stderr.Trim() + ")");
        check(await HostServiceTests.WaitFor(() => rig.ProviderEvents().Any(item => item.Outcome == "provider-failed" && item.Meta.GetValueOrDefault("errorKind") == "AccessDenied")), "e2e failed: audited Failed with the error kind");

        // The entry disappears while the approval is being made: the name still selects the mount, so it fails closed (no fall-through to the native store).
        rig.Adapter.Returns(ProviderPath, Github);
        rig.During = () => rig.Providers.Store.ReplaceEntries(rig.Tree.Id, []);
        int calls = rig.Adapter.Invocations.Count;
        Ran gone = await Run(rig, "gone");
        rig.During = null;
        check(!gone.Started && gone.Raw.Result is { ExitCode: RunCommand.StoreError } && rig.Adapter.Invocations.Count == calls && gone.Raw.Stderr.Contains("not available", StringComparison.Ordinal),
            "e2e no entry: a mounted name whose entry is gone fails closed, nothing is retrieved and the child never starts (" + gone.Raw.Result + " " + gone.Raw.Stderr.Trim() + ")");
        check(await HostServiceTests.WaitFor(() => rig.ProviderEvents().Count(item => item.Outcome == "provider-failed") == 2), "e2e no entry: audited Failed for the path the mount selects");
        Ran unknown = await Run(rig, "unknown");
        check(!unknown.Started && unknown.Raw.Result is { ExitCode: RunCommand.Usage } && rig.Adapter.Invocations.Count == calls, "e2e no entry: a mounted name never listed is not a secret: refused before any page, nothing runs (" + unknown.Raw.Result + ")");

        IReadOnlyList<AuditEvent> events = rig.Audit();
        check(events.Count > 0 && events.All(item => Clean(item.ToJson())) && Clean(string.Join("\n", rig.Approvers.SelectMany(item => item.Requests).Select(request => ApprovalSummary.BuildMessage(request)))),
            "e2e canary: no value or ciphertext in any audit event or approval text");
        check(!rig.ProviderEvents().Any(item => item.Meta.ContainsKey("externalId") || item.ToJson().Contains(External, StringComparison.Ordinal)), "e2e audit: the provider events carry no external id");
    }

    /// <summary>The native-only path is unchanged when no mount selects the name.</summary>
    private static async Task Unavailable(Action<bool, string> check, string root)
    {
        using Rig rig = new(root);
        Ran native = await Run(rig, "native", "NATIVE_ONE");
        check(native.Value == NativeValue && rig.Adapter.Invocations.Count == 0 && rig.Pages.Single().Sources?["NATIVE_ONE"] == SecretStore.GlobalLabel && rig.ProviderEvents().Count == 0,
            "e2e native: a native name is served by the native store (label global), no provider is called and nothing provider-specific is audited (" + native.Raw.Result + " " + native.Raw.Stderr.Trim() + ")");
    }

    private static async Task Locked(Action<bool, string> check, string root)
    {
        using Rig rig = new(root);
        Ran unlocked = await Run(rig, "before-lock");
        rig.Service.Lock.Lock("test");
        Ran locked = await Run(rig, "after-lock");
        check(unlocked.Value == Github && locked.Raw.Status == HttpStatusCode.Locked && !locked.Started && rig.Adapter.Invocations.Count == 1 && rig.Pages.Count == 1,
            "e2e locked: after the authority locks, a launch is refused (423) before any page, retrieval or start (" + locked.Raw.Status + ")");
        check(rig.Providers.Cache.IsLocked && rig.Providers.Cache.TryGet(rig.Instance.Id, External, rig.StoreKey) is null, "e2e locked: no cache row is served while locked");
    }

    /// <summary>An adapter whose InitializeAsync never completes and ignores its token cannot hang the service's start: the instance is dropped, its names fail closed, the rest works.</summary>
    private static async Task HangingInitialize(Action<bool, string> check, string root)
    {
        System.Diagnostics.Stopwatch clock = System.Diagnostics.Stopwatch.StartNew();
        Task<Rig> making = Task.Run(() => new Rig(root, configure: adapter => adapter.InitializeBehavior = _ => new TaskCompletionSource().Task));
        bool returned = await Task.WhenAny(making, Task.Delay(TimeSpan.FromSeconds(40))) == making;
        clock.Stop();
        check(returned && clock.Elapsed < ProviderAuthority.StartBound + TimeSpan.FromSeconds(5), "e2e hung init: the service start returns within the documented bound (" + clock.Elapsed.TotalSeconds.ToString("F1", System.Globalization.CultureInfo.InvariantCulture) + " s)");
        if (!returned)
        {
            return;
        }

        using Rig rig = await making;
        bool unregistered = false;
        try
        {
            rig.Registry.Status(rig.Instance.Id);
        }
        catch (KeyNotFoundException)
        {
            unregistered = true;
        }

        Ran native = await Run(rig, "hung-native", "NATIVE_ONE");
        Ran mounted = await Run(rig, "hung-mounted");
        check(unregistered && native.Value == NativeValue && !mounted.Started && mounted.Raw.Result is { ExitCode: RunCommand.StoreError } && rig.Adapter.Invocations.Count == 0,
            "e2e hung init: the instance is left unregistered, native runs work and its mounted names fail closed (" + mounted.Raw.Result + " " + mounted.Raw.Stderr.Trim() + ")");
    }

    /// <summary>An adapter's invalidation through the composed authority: cache row gone, the grant for the path invalidated and its host told, a signed audit event; also one reported during initialization.</summary>
    private static async Task InvalidationWiring(Action<bool, string> check, string root)
    {
        using Rig rig = new(root, configure: adapter => adapter.OnInitialize = reporter =>
        {
            reporter.Report(new LifecycleChangedEvent(AdapterLifecycleState.Ready));
            reporter.Report(new InvalidateProviderDataEvent(ExternalSecretIds: ["ext-during-init"]));
        });
        check(await HostServiceTests.WaitFor(() => rig.Audit().Any(item => item.Outcome == "provider-data-invalidated" && item.Meta.GetValueOrDefault("externalIds") == "ext-during-init")),
            "e2e invalidation: one reported during InitializeAsync is applied and audited (the subscription is in place before the instance is added)");

        Ran first = await Run(rig, "before-invalidation");
        string file = rig.Machine.Deployment.Store.FilePath;
        long Scalar(string sql)
        {
            using SqliteConnection connection = new("Data Source=" + file + ";Pooling=False");
            connection.Open();
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = sql;

            return Convert.ToInt64(command.ExecuteScalar() ?? 0L, System.Globalization.CultureInfo.InvariantCulture);
        }

        using (SqliteConnection connection = new("Data Source=" + file + ";Pooling=False"))
        {
            connection.Open();
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "INSERT INTO grants (id, fingerprint, scope_key, program, working_directory, secret_names, created, updated, grant_revision, security_revision, status, approved_by, usage) "
                + "VALUES ('g-provider-e2e', $fp, 'scope-e2e', 'p', 'd', $names, 't', 't', 1, 1, 'active', 'x', 'reusable')";
            command.Parameters.AddWithValue("$fp", rig.Machine.Fingerprint);
            command.Parameters.AddWithValue("$names", Mounted);
            command.ExecuteNonQuery();
        }

        long rowsBefore = Scalar("SELECT COUNT(*) FROM provider_cache");
        rig.Adapter.Reporter!.Report(new InvalidateProviderDataEvent(ExternalSecretIds: [External]));
        check(first.Value == Github && rowsBefore == 1 && Scalar("SELECT COUNT(*) FROM provider_cache") == 0 && Scalar("SELECT COUNT(*) FROM grants WHERE id = 'g-provider-e2e' AND status = 'invalidated'") == 1,
            "e2e invalidation: the adapter's event drops the cache row and invalidates the grant naming the path");
        check(await HostServiceTests.WaitFor(() => Scalar("SELECT COUNT(*) FROM grant_events WHERE grant_id = 'g-provider-e2e' AND kind = 'invalidated' AND acknowledged IS NOT NULL") == 1),
            "e2e invalidation: the host is told (the grant event is delivered and acknowledged)");
        check(await HostServiceTests.WaitFor(() => rig.Audit().Any(item => item.Outcome == "provider-data-invalidated" && item.Meta.GetValueOrDefault("paths") == Mounted && item.Meta.GetValueOrDefault("grants") == "1" && item.Verify(rig.Machine.MachineKey.PublicKey))),
            "e2e invalidation: a signed provider-data-invalidated event names the path and counts");
    }

    /// <summary>The audit of one call is ONE commit: a sink that cannot commit leaves no record of values that were then zeroed; a failed call audits every mounted name, held-back successes included.</summary>
    private static void AuditSink(Action<bool, string> check, string root)
    {
        string dir = Path.Combine(root, "sink-" + Guid.NewGuid().ToString("N")[..8]);
        StateDatabase db = TestState.Seeded(Path.Combine(dir, "state", WithSecretsDatabase.FileName));
        SecretStore native = new(db);
        if (SecretStoreTests.Put(native, new Dictionary<string, string> { ["NATIVE_ONE"] = NativeValue }) is { } problem)
        {
            throw new InvalidOperationException(problem);
        }

        using SoftwareSigningKey machine = new();
        using SoftwareSigningKey signing = new();
        HostAuditOutbox outbox = HostAuditOutbox.InFolder(dir, machine);
        HostAudit audit = new(outbox, new AuditUploader(outbox, () => throw new InvalidOperationException(), (_, _, _, _) => Task.FromResult<string?>(null), "fp"));
        AuthorityStore authority = AuthorityStore.InFolder(Path.Combine(dir, "authority"));
        ProviderStore providers = new(authority);
        AuthorityKeyRing keys = new(authority, _ => signing) { LockState = AuthorityLock.UnlockedForTests() };
        FakeProviderAdapter adapter = new();
        ProviderCache cache = new(providers, keys);
        ProviderSecretSource source = new(native, providers, new ProviderRetriever(_ => adapter, TimeProvider.System, (_, _) => Task.CompletedTask), cache, new ProviderInvalidation(providers, (_, _) => { }), TimeProvider.System, ProviderAuthority.AuditSink(audit));
        ProviderInstance instance = providers.AddInstance("vault-sink", "test", "{}", Hour);
        Mount mount = providers.AddMount(instance.Id, MountKind.Tree, "team", "kv");
        providers.ReplaceEntries(mount.Id, [new NamespaceEntry(mount.Id, "team/A", "kv/A", "ext-a", null, DescriptionSource.Provider), new NamespaceEntry(mount.Id, "team/B", "kv/B", "ext-b", null, DescriptionSource.Provider)]);
        adapter.Returns("kv/A", Github).Returns("kv/B", Older);

        List<byte[]> discarded = [];
        source.Discarded = buffers => discarded.AddRange(buffers);
        outbox.Fault = point =>
        {
            if (point == "before-commit")
            {
                throw new InvalidOperationException("scripted");
            }
        };
        Exception? thrown = null;
        try
        {
            using Unlock? unlock = SecretStoreTests.AdminUnlock(db);
            source.GetValues(["team/A", "team/B"], unlock).Dispose();
        }
        catch (Exception error)
        {
            thrown = error;
        }

        outbox.Fault = null;
        check(thrown is not null && outbox.Pending(100).Count == 0 && discarded.Count > 0 && discarded.All(buffer => buffer.All(item => item == 0)),
            "e2e audit sink: when the audit cannot be committed the call fails, no record of any name is left and every value is zeroed (" + thrown?.GetType().Name + ")");

        // A failure for B: A succeeded but is held back, so both are audited Failed in one commit (A with no kind, B with its kind).
        adapter.Fails("kv/B", ProviderErrorKind.AccessDenied);
        providers.DeleteCache(instance.Id, null);
        bool failed = false;
        try
        {
            using Unlock? unlock = SecretStoreTests.AdminUnlock(db);
            source.GetValues(["team/A", "team/B"], unlock).Dispose();
        }
        catch (SecretStoreException)
        {
            failed = true;
        }

        IReadOnlyList<AuditEvent> events = outbox.Pending(100);
        check(failed && events.Count == 2 && events.All(item => item.Outcome == "provider-failed" && item.Meta.GetValueOrDefault("instance") == instance.Id.ToString("D"))
            && events.Single(item => item.Meta.GetValueOrDefault("path") == "team/B").Meta.GetValueOrDefault("errorKind") == "AccessDenied"
            && !events.Single(item => item.Meta.GetValueOrDefault("path") == "team/A").Meta.ContainsKey("errorKind") && events.All(item => Clean(item.ToJson())),
            "e2e audit sink: a failed call audits every mounted name Failed (a held-back success without a kind), with path and instance, no value (" + string.Join(" | ", events.Select(item => item.ToJson())) + ")");

        // A failure at resolution (team/C selects the mount but has no entry) also audits every mounted name of the call, in one commit, and retrieves nothing.
        outbox.Acknowledge(events.Select(item => item.EventId));
        int calls = adapter.Invocations.Count;
        string unavailable = "";
        try
        {
            using Unlock? unlock = SecretStoreTests.AdminUnlock(db);
            source.GetValues(["team/A", "team/C"], unlock).Dispose();
        }
        catch (SecretStoreException error)
        {
            unavailable = error.Message;
        }

        IReadOnlyList<AuditEvent> resolved = outbox.Pending(100);
        check(unavailable == "team/C is not available" && adapter.Invocations.Count == calls && resolved.Count == 2 && resolved.All(item => item.Outcome == "provider-failed" && !item.Meta.ContainsKey("errorKind") && item.Meta.GetValueOrDefault("instance") == instance.Id.ToString("D"))
            && resolved.Select(item => item.Meta.GetValueOrDefault("path")).Order(StringComparer.Ordinal).SequenceEqual(["team/A", "team/C"]),
            "e2e audit sink: a call that fails at resolution audits every mounted name Failed, the available one included (" + unavailable + " | " + string.Join(" | ", resolved.Select(item => item.Meta.GetValueOrDefault("path"))) + ")");
        SqliteConnection.ClearAllPools();
    }

    private static void Schema(Action<bool, string> check, string root)
    {
        string folder = Path.Combine(root, "schema6-" + Guid.NewGuid().ToString("N")[..8], "state");
        using TestMachine machine = new(folder, trusted: true);
        string file = machine.Deployment.Store.FilePath;
        machine.Deployment.Dispose();
        SqliteConnection.ClearAllPools();
        using (SqliteConnection connection = new("Data Source=" + file + ";Pooling=False"))
        {
            connection.Open();
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "UPDATE schema_version SET version = 6";
            command.ExecuteNonQuery();
        }

        string? refused = null;
        try
        {
            using LocalDeployment again = machine.Open();
            again.Store.Machines();
        }
        catch (AuthorityDatabaseException error)
        {
            refused = error.Message;
        }

        check(refused is not null && refused.Contains("is not of schema version 3", StringComparison.Ordinal) && refused.Contains("delete with-secrets.db", StringComparison.Ordinal), "e2e schema: an with-secrets.db of schema 6 is refused with the delete message (" + refused + ")");
    }

    /// <summary>Remote mode: the adapters run at the remote authority; the host's own store is never read and its approval is the authority's.</summary>
    private static async Task Remote(Action<bool, string> check, string root)
    {
        if (PlatformSkip.NoServerTls13("mounted secrets through a remote authority"))
        {
            return;
        }

        using Rig auth = new(root, machineEndpoint: true);
        check(await HostServiceTests.WaitFor(() => auth.Service.MachinePort is not null), "e2e remote: the authority serves its machine endpoint");
        using TestMachine hostMachine = new(Path.Combine(root, "wsl-" + Guid.NewGuid().ToString("N")[..8], "state"), trusted: false, hostName: "wsl-provider");
        (CreatedInvitation? invitation, string? why) = auth.Service.Pairing.Create("test admin");
        PairingResult paired = await PairingClient.RunAsync(new PairingClientOptions { Bundle = PairingBundle.TryParse(invitation?.Bundle ?? throw new InvalidOperationException("no invitation: " + why))!, MachineKey = hostMachine.MachineKey, IdentityCertificate = hostMachine.Deployment.IdentityCertificate, HostName = "wsl-provider", HostConfig = hostMachine.Deployment.HostConfig, MachineTls = hostMachine.Deployment.Tls });
        if (!paired.Ok)
        {
            check(false, "e2e remote: the host pairs with the authority (" + paired.Message + ")");

            return;
        }

        RemoteAuthorityConfig config = hostMachine.Deployment.HostConfig.Load().Config!.Remote!;
        hostMachine.Deployment.UseRemote(new RemoteAuthority(config, hostMachine.Deployment.Tls, hostMachine.Deployment.HostConfig) { RetryPause = TimeSpan.FromMilliseconds(50), Retries = 6 });
        check(auth.Machine.Deployment.Store.Approve(hostMachine.Fingerprint, "wsl-provider", "test admin").Ok, "e2e remote: the administrator approves the host at the authority");

        // A host whose authority is remote, even over a REAL native store, composes no provider source: its runs are served by the authority.
        StateDatabase hostState = new(hostMachine.Deployment.Store.Database);
        using (HostService remoteHost = HostService.Start(new HostServiceOptions { CommandLineEndpoint = HostServiceTests.Rig.TestEndpoint(), State = hostState, Store = new SecretStore(hostState), Deployment = hostMachine.Deployment, Port = 0, ProviderRegistry = new ProviderRegistry() }))
        {
            check(remoteHost.Authorization.IsRemote && remoteHost.Providers is null, "e2e remote: a host service over a real native store with a remote authority composes no provider source");
        }
        using HostServiceTests.Rig host = new(root, new Dictionary<string, string> { [Mounted] = "host-decoy" }, machine: hostMachine, auditInterval: TimeSpan.FromMilliseconds(300));

        (string program, string valueFile) = ValueScript(host.Work, "remote");
        HostServiceTests.Raw raw = await HostServiceTests.Post(host, HostServiceTests.Req(host, program, pairs: [("TOKEN", Mounted)]));
        string? value = File.Exists(valueFile) ? File.ReadAllText(valueFile).Trim() : null;
        check(raw.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 4 } && value == Github && auth.Adapter.Invocations.Count == 1 && host.Store.Reads == 0,
            "e2e remote: the authority's adapter retrieves the mounted value and the program runs on the host; the host's store is never read (" + raw.Result + " " + raw.Stderr.Trim() + ")");
        check(auth.Pages.SingleOrDefault()?.Sources?.GetValueOrDefault(Mounted) == "vault-one", "e2e remote: the authority's approval page names the provider instance");
        check(await HostServiceTests.WaitFor(() => auth.ProviderEvents().Any(item => item.Outcome == "provider-fresh" && item.Meta.GetValueOrDefault("path") == Mounted)), "e2e remote: the retrieval is audited at the authority (Fresh)");
        check(hostState.Database.Read(connection => connection is not null
            && (long)WithSecretsDatabase.Scalar(connection, null, "SELECT last_sequence FROM outbox_counter")! > 0
            && (long)WithSecretsDatabase.Scalar(connection, null, """
                SELECT (SELECT COUNT(*) FROM manifest) + (SELECT COUNT(*) FROM secrets) + (SELECT COUNT(*) FROM grants)
                     + (SELECT COUNT(*) FROM provider_instances) + (SELECT COUNT(*) FROM machines) + (SELECT COUNT(*) FROM authority_keys)
                """)! == 0)
            && WithSecretsDatabase.OldFiles.All(name => !File.Exists(Path.Combine(hostMachine.Folder, name))),
            "e2e remote: the host writes its audit to the shared schema while the authority data and secret store stay empty");
    }
}

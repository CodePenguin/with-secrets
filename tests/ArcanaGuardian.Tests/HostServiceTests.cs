using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;

namespace ArcanaGuardian.Tests;

/// <summary>
/// Phase 1: the host service and the shared API. Request rejection, approval over real HTTP with a test authenticator, the child's
/// environment, redacted streaming, cancellation before the launch, the launch-versus-invalidation order, exit codes, the
/// service-not-running message, no secret in any event, two clients at once and a Docker stand-in.
/// </summary>
internal static class HostServiceTests
{
    private const string Value = "Canary-Value-48151623";
    private const string Other = "Canary-Other-9001337";

    /// <summary>A secret source in memory that counts decryptions.</summary>
    internal sealed class CountingStore(Dictionary<string, string> values) : ISecretSource
    {
        private int _reads;

        public int Reads => Volatile.Read(ref _reads);

        /// <summary>Makes the next reads fail, as a store that cannot open its key would.</summary>
        public bool Fail { get; set; }

        public string Label => SecretStore.GlobalLabel;

        public IReadOnlyList<string> ListNames() => [.. values.Keys];

        /// <summary>For tests: called as a decryption begins, before anything is read.</summary>
        public Action? OnRead { get; set; }

        public SecretValues GetValues(IReadOnlyCollection<string> names)
        {
            OnRead?.Invoke();
            Interlocked.Increment(ref _reads);
            if (Fail)
            {
                throw new SecretStoreException("the key could not be opened (test)");
            }

            return new SecretValues(names.ToDictionary(name => name, name => Encoding.UTF8.GetBytes(values[name]), StringComparer.Ordinal));
        }
    }

    /// <summary>An approver that waits for the test: it says when it was asked and answers when released.</summary>
    internal sealed class WaitingApprover(bool approve = true) : IApprover
    {
        public ManualResetEventSlim Asked { get; } = new(false);

        public ManualResetEventSlim Release { get; } = new(false);

        public ApprovalDecision Request(ApprovalRequest request)
        {
            Asked.Set();
            Release.Wait(TimeSpan.FromSeconds(30));

            return approve ? TestSigner.Allow(request) : ApprovalDecision.Deny("test denied");
        }
    }

    /// <summary>An approver that waits and honours the cancellation token, as the page approver does.</summary>
    internal sealed class CancelAwareApprover : IApprover
    {
        public ManualResetEventSlim Asked { get; } = new(false);

        public ManualResetEventSlim Release { get; } = new(false);

        public ManualResetEventSlim SawCancel { get; } = new(false);

        public ApprovalDecision Request(ApprovalRequest request) => Request(request, CancellationToken.None);

        public ApprovalDecision Request(ApprovalRequest request, CancellationToken cancel)
        {
            Asked.Set();
            int which = WaitHandle.WaitAny([Release.WaitHandle, cancel.WaitHandle], TimeSpan.FromSeconds(30));
            if (which == 1)
            {
                SawCancel.Set();

                return ApprovalDecision.Deny("cancelled by the client");
            }

            return TestSigner.Allow(request);
        }
    }

    private sealed class ThrowingApprover : IApprover
    {
        public ApprovalDecision Request(ApprovalRequest request) => throw new InvalidOperationException("approver failed");
    }

    /// <summary>The signed events of the host as text: those still in its outbox and those the service already uploaded (the authority holds them, and the outbox drops what is acknowledged).</summary>
    internal static string AuditOf(Rig rig) => string.Join((char)10, StateDatabaseTests.AuditLines(rig.State.FilePath).Concat(rig.Machine.Deployment.Store.AuditHistory(new AuditQuery(Limit: 1000)).Select(item => item.Event.ToJson())).Distinct());

    internal sealed class Rig : IDisposable
    {
        private readonly string _dir;
        private int _ids;

        public Rig(string parent, Dictionary<string, string>? values = null, Func<IApprover>? approver = null, TimeSpan? bodyTimeout = null, Action<PreparedChild>? afterPrepare = null, Action? afterCommit = null, bool trusted = true, TestMachine? machine = null, IMonotonicClock? monotonic = null, TestAuthenticator? enrolled = null, TimeSpan? auditInterval = null, bool startLocked = false, Func<Action<string>, IAdminAsker>? adminAskers = null)
        {
            _dir = Path.Combine(parent, "svc-" + Guid.NewGuid().ToString("N")[..8]);
            Work = Path.Combine(_dir, "work");
            Directory.CreateDirectory(Work);
            string stateFolder = machine?.Folder ?? Path.Combine(_dir, "state");
            Machine = machine ?? new TestMachine(stateFolder, trusted);
            State = new StateDatabase(Machine.Deployment.Store.Database);
            if (enrolled is not null)
            {
                // The key whose assertions back grants (the authority checks them against the signed manifest of this state).
                TestState.Add(State, enrolled.Record("localhost", "grant-test") with { Created = DateTimeOffset.UtcNow }, withStore: true);
            }

            Store = new CountingStore(values ?? new Dictionary<string, string> { ["TOKEN"] = Value, ["OTHER_KEY"] = Other });
            Approvers = [];
            Service = HostService.Start(new HostServiceOptions
            {
                CommandLineEndpoint = HostServiceTests.Rig.TestEndpoint(),
                Lock = startLocked ? null : AuthorityLock.UnlockedForTests(),
                AdminAskerFactory = adminAskers,
                State = State,
                Store = Store,
                Deployment = Machine.Deployment,
                Port = 0,
                BodyTimeout = bodyTimeout ?? TimeSpan.FromSeconds(15),
                ApproverFactory = (_, _) =>
                {
                    // Every approval is a grant: the key test approvers sign with when a test names none (see TestSigner). Enrolled when the first page is
                    // made, so it comes after the keys a test sets up (it never takes the first, admin, place of a key the test adds).
                    TestSigner.Enroll(State);
                    IApprover made = approver?.Invoke() ?? new FakeApprover(true);
                    Approvers.Add(made);

                    return made;
                },
                AfterPrepare = child => afterPrepare?.Invoke(child),
                AfterCommit = () => afterCommit?.Invoke(),
                Monotonic = monotonic,
                AuditUploadInterval = auditInterval ?? TimeSpan.FromSeconds(2),
                AuditMaxBackoff = auditInterval is { } interval ? interval * 4 : TimeSpan.FromSeconds(60),
            });
        }

        /// <summary>The command line's endpoint of a test service: Windows, a named pipe of its own; Linux and macOS, a socket in a private directory of its own.</summary>
        internal static LocalEndpoint TestEndpoint() => OperatingSystem.IsWindows() ? LocalEndpoint.NamedPipe("ws-test-" + Guid.NewGuid().ToString("N")) : LocalEndpoint.UnixSocket(NewSocketDirectory());

        /// <summary>A private socket directory of its own for one test service (short, because socket paths are limited to about 100 bytes).</summary>
        internal static string NewSocketDirectory()
        {
            string directory = Path.Combine(Path.GetTempPath(), "ws-" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(directory);
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }

            return directory;
        }

        public string Work { get; }

        public StateDatabase State { get; }

        public TestMachine Machine { get; }

        public CountingStore Store { get; }

        private HostService _service = null!;
        private HttpClient? _http;

        /// <summary>The service. A test that replaces it gets a client for the new one's endpoint.</summary>
        public HostService Service
        {
            get => _service;
            internal set
            {
                _service = value;
                _http?.Dispose();
                _http = null;
            }
        }

        /// <summary>A client for the command line's endpoint of the current service (the application protocol is the same over every endpoint).</summary>
        public HttpClient Http => _http ??= new HttpClient(Service.Endpoint.CreateHandler()) { Timeout = TimeSpan.FromSeconds(60) };

        public ConcurrentBag<IApprover> Approvers { get; }

        public string Url(string path) => Service.Endpoint.BaseUri.AbsoluteUri.TrimEnd('/') + path;

        public string NextId() => "req-" + Interlocked.Increment(ref _ids) + "-" + Guid.NewGuid().ToString("N")[..8];

        /// <summary>Writes a script into the work folder and returns the program to name ("./name.cmd" or "./name.sh").</summary>
        public string Script(string name, string windows, string unix)
        {
            string file = name + (OperatingSystem.IsWindows() ? ".cmd" : ".sh");
            string path = Path.Combine(Work, file);
            if (OperatingSystem.IsWindows())
            {
                File.WriteAllText(path, "@echo off\r\n" + windows.Replace("\n", "\r\n", StringComparison.Ordinal) + "\r\n");
            }
            else
            {
                // The program runs a private copy of the script, so $0 is not where the file is: a script names the file it means by its path.
                File.WriteAllText(path, "#!/bin/sh\n" + unix.Replace("$0", path, StringComparison.Ordinal) + "\n");
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }

            return "./" + file;
        }

        public string FileOf(string name) => Path.Combine(Work, name);

        public void Dispose()
        {
            _http?.Dispose();
            Service.Dispose();
            Machine.Deployment.Dispose();
        }
    }

    internal sealed record Raw(HttpStatusCode Status, string Body, List<string> Lines, List<LaunchEvent> Events)
    {
        public LaunchEvent? Result => Events.LastOrDefault(item => item.Kind == LaunchEvent.ResultKind);

        public string Stdout => string.Concat(Events.Where(item => item.Stream == "stdout").Select(item => item.Text));

        public string Stderr => string.Concat(Events.Where(item => item.Stream == "stderr").Select(item => item.Text));
    }

    internal static IReadOnlyDictionary<string, string> Env(params (string Name, string Value)[] extra)
    {
        Dictionary<string, string> map = LaunchClient.CurrentEnvironment()
            .Where(pair => !DotenvxRun.IsCredential(pair.Key))
            .ToDictionary(StringComparer.Ordinal);
        map.Remove("ARCANA_GUARDIAN_TEST_SERVICE_ONLY");
        foreach ((string name, string value) in extra)
        {
            map[name] = value;
        }

        return map;
    }

    internal static LaunchRequest Req(Rig rig, string program, string[]? args = null, (string Variable, string Secret)[]? pairs = null, IReadOnlyDictionary<string, string>? environment = null, Dictionary<string, string>? ordinary = null, string? id = null)
    {
        (string Variable, string Secret)[] mapped = pairs ?? [("TOKEN", "TOKEN")];
        Dictionary<string, string> variables = ordinary ?? [];
        DateTimeOffset now = DateTimeOffset.UtcNow;

        return new LaunchRequest(
            LaunchProtocol.Version,
            id ?? rig.NextId(),
            now,
            now.AddMinutes(5),
            "bm9uY2UtMDAwMDAwMDE" + Guid.NewGuid().ToString("N")[..6],
            [.. mapped.Select(pair => pair.Secret).Distinct(StringComparer.Ordinal)],
            [.. mapped.Select(pair => new LaunchMapping(pair.Variable, pair.Secret))],
            "service test",
            program,
            args ?? [],
            rig.Work,
            [],
            [.. variables.Keys.Order(StringComparer.Ordinal)],
            variables,
            environment ?? Env(),
            []);
    }

    internal static async Task<Raw> Post(Rig rig, LaunchRequest request, Action<LaunchEvent>? onEvent = null, CancellationToken cancel = default, Action<HttpRequestMessage>? tweak = null, string? body = null, string? digest = null, string path = "/v1/launch")
    {
        using HttpRequestMessage message = new(HttpMethod.Post, rig.Url(path))
        {
            Content = new StringContent(body ?? request.Canonical(), new UTF8Encoding(false), new MediaTypeHeaderValue("application/json"))
        };
        message.Headers.Add(HostService.DigestHeader, digest ?? request.Digest());
        message.Headers.ConnectionClose = true;
        tweak?.Invoke(message);
        using HttpResponseMessage response = await rig.Http.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, cancel);
        using StreamReader reader = new(await response.Content.ReadAsStreamAsync(cancel), new UTF8Encoding(false));
        List<string> lines = [];
        List<LaunchEvent> events = [];
        StringBuilder all = new();
        while (await reader.ReadLineAsync(cancel) is { } line)
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
                onEvent?.Invoke(parsed!);
            }
        }

        return new Raw(response.StatusCode, all.ToString(), lines, events);
    }

    internal static async Task<bool> WaitFor(Func<bool> condition, int seconds = 20)
    {
        DateTime end = DateTime.UtcNow.AddSeconds(seconds);
        while (DateTime.UtcNow < end)
        {
            if (condition())
            {
                return true;
            }

            await Task.Delay(25);
        }

        return condition();
    }

    /// <summary>
    /// The two surfaces of the service are on separate listeners and each answers only its own routes: the command line's endpoint (the pipe or the socket) answers /v1 and nothing of the browser administration; the loopback
    /// port answers the browser administration (/api, /admin) and nothing of /v1. The browser administration is therefore no way around the command line's access control, and the command line's routes are no longer
    /// reachable by any process that can merely open a loopback port.
    /// </summary>
    private static async Task Surfaces(Action<bool, string> check, string parent)
    {
        using Rig rig = new(parent);
        using HttpClient web = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(30) };
        string loopback = "http://127.0.0.1:" + rig.Service.Port;

        async Task<(HttpStatusCode Status, string Body)> OverEndpoint(HttpMethod method, string path, string? body = null)
        {
            using HttpRequestMessage message = new(method, rig.Url(path));
            if (body is not null)
            {
                message.Content = new StringContent(body, new UTF8Encoding(false), new MediaTypeHeaderValue("application/json"));
            }

            using HttpResponseMessage response = await rig.Http.SendAsync(message);

            return (response.StatusCode, await response.Content.ReadAsStringAsync());
        }

        async Task<(HttpStatusCode Status, string Body)> OverLoopback(HttpMethod method, string path, string? body = null)
        {
            using HttpRequestMessage message = new(method, loopback + path);
            if (body is not null)
            {
                message.Content = new StringContent(body, new UTF8Encoding(false), new MediaTypeHeaderValue("application/json"));
            }

            using HttpResponseMessage response = await web.SendAsync(message);

            return (response.StatusCode, await response.Content.ReadAsStringAsync());
        }

        const string Challenge = "{\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAA\"}";
        (HttpStatusCode Status, string Body) cli = await OverEndpoint(HttpMethod.Get, "/v1/status");
        (HttpStatusCode Status, string Body) browser = await OverLoopback(HttpMethod.Get, "/api/v1/status");
        check(cli.Status == HttpStatusCode.OK && cli.Body.Contains("\"running\":true", StringComparison.Ordinal) && !cli.Body.Contains("apiVersion", StringComparison.Ordinal), "surfaces: the command line's endpoint answers the command line's own status document");
        check(browser.Status == HttpStatusCode.OK && browser.Body.Contains("apiVersion", StringComparison.Ordinal), "surfaces: the loopback port answers the browser administration's API");

        // The browser administration is not on the command line's endpoint.
        (HttpStatusCode Status, string Body) apiOnCli = await OverEndpoint(HttpMethod.Get, "/api/v1/status");
        (HttpStatusCode Status, string Body) adminOnCli = await OverEndpoint(HttpMethod.Get, "/admin/");
        (HttpStatusCode Status, string Body) changeOnCli = await OverEndpoint(HttpMethod.Post, "/api/v1/unlock", "{\"authorization\":\"AAAAAAAAAAAA\"}");
        check(apiOnCli.Status == HttpStatusCode.NotFound && adminOnCli.Status == HttpStatusCode.NotFound && changeOnCli.Status == HttpStatusCode.NotFound && !apiOnCli.Body.Contains("apiVersion", StringComparison.Ordinal), "surfaces: /api and /admin are not answered on the command line's endpoint (" + (int)apiOnCli.Status + ", " + (int)adminOnCli.Status + ", " + (int)changeOnCli.Status + ")");

        // The command line's routes are not on the loopback port: no process that can open a port can reach them.
        (HttpStatusCode Status, string Body) statusOnLoopback = await OverLoopback(HttpMethod.Get, "/v1/status");
        (HttpStatusCode Status, string Body) identityOnLoopback = await OverLoopback(HttpMethod.Post, "/v1/identity", Challenge);
        (HttpStatusCode Status, string Body) launchOnLoopback = await OverLoopback(HttpMethod.Post, "/v1/launch", "{}");
        (HttpStatusCode Status, string Body) approveOnLoopback = await OverLoopback(HttpMethod.Post, "/v1/approve", "{}");
        (HttpStatusCode Status, string Body) cancelOnLoopback = await OverLoopback(HttpMethod.Post, "/v1/launch/req-x/cancel", "{}");
        check(new[] { statusOnLoopback, identityOnLoopback, launchOnLoopback, approveOnLoopback, cancelOnLoopback }.All(answer => answer.Status == HttpStatusCode.NotFound) && !statusOnLoopback.Body.Contains("protocolVersion", StringComparison.Ordinal) && rig.Approvers.IsEmpty, "surfaces: /v1 (status, identity, launch, approve, cancel) is not answered on the loopback port, and nothing reached an approver");

        // The same refusals hold on the command line's own routes.
        using HttpRequestMessage fromPage = new(HttpMethod.Post, rig.Url("/v1/identity"));
        fromPage.Headers.Add("Origin", "http://example.test");
        fromPage.Content = new StringContent(Challenge, new UTF8Encoding(false), new MediaTypeHeaderValue("application/json"));
        using HttpResponseMessage pageResponse = await rig.Http.SendAsync(fromPage);
        using HttpRequestMessage badHost = new(HttpMethod.Get, rig.Url("/v1/status"));
        badHost.Headers.Host = "evil.example";
        using HttpResponseMessage badHostResponse = await rig.Http.SendAsync(badHost);
        (HttpStatusCode Status, string Body) unknownCli = await OverEndpoint(HttpMethod.Get, "/v1/nothing");
        check(pageResponse.StatusCode == HttpStatusCode.Forbidden && badHostResponse.StatusCode == (HttpStatusCode)421 && unknownCli.Status == HttpStatusCode.NotFound, "surfaces: on the command line's routes, a request with an Origin (a web page) and one with a Host that is not a local name are refused, and an unknown route is 404");
    }
    public static async Task Run(Action<bool, string> check)
    {
        string parent = Path.Combine(Path.GetTempPath(), "ws-host-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(parent);
        try
        {
            Gate(check);
            await StressGate(check);
            await Rejections(check, parent);
            await ChildEnvironment(check, parent);
            await RedactedStreaming(check, parent);
            await ExitAndFailures(check, parent);
            await Cancellation(check, parent);
            await InvalidationOrder(check, parent);
            await NoSecretInEvents(check, parent);
            await TwoClients(check, parent);
            await DockerStandIn(check, parent);
            await ApprovalOverHttp(check, parent);
            await FixRound1(check, parent);
            await ClientAndCommandLine(check, parent);
            await Surfaces(check, parent);
            await MixedWriters(check, parent);
        }
        finally
        {
            try
            {
                Directory.Delete(parent, true);
            }
            catch (IOException)
            {
                // A child still holding a file: the temp folder is left.
            }
        }
    }

    /// <summary>One service process, one arcana-guardian.db: run events (outbox), authority audit rows and signed settings changes (state) written at once.</summary>
    private static async Task MixedWriters(Action<bool, string> check, string parent)
    {
        using TestAuthenticator admin = TestAuthenticator.ES256();
        using Rig rig = new(parent, enrolled: admin);
        HostService service = rig.Service;
        AuthorityStore store = rig.Machine.Deployment.Store;
        long before = service.Audit.Outbox.LastSequence();
        int failures = 0;
        int settings = 0;
        await Task.WhenAll(Enumerable.Range(0, 8).Select(task => Task.Run(() =>
        {
            for (int index = 0; index < 25; index++)
            {
                try
                {
                    if (task % 2 == 0)
                    {
                        if (!service.Audit.TryRecord(new AuditFacts(AuditEventTypes.Authorization, "approved", "approved", "mixed-" + task + "-" + index, "/work", "/work/show.sh", [], "", null)))
                        {
                            Interlocked.Increment(ref failures);
                        }
                    }
                    else
                    {
                        store.RecordDeliveryEvent(rig.Machine.Fingerprint, "mixed-" + task + "-" + index, "mixed-delivery", "contention test");
                        // One task changes the signed settings (a read-modify-write of the manifest, so one writer of it at a time).
                        if (task == 1 && index % 5 == 0)
                        {
                            if (TestState.Setting(rig.State, "timeoutMinutes", (2 + index / 5).ToString(System.Globalization.CultureInfo.InvariantCulture)))
                            {
                                Interlocked.Increment(ref settings);
                            }
                            else
                            {
                                Interlocked.Increment(ref failures);
                            }
                        }
                    }
                }
                catch (Exception)
                {
                    Interlocked.Increment(ref failures);
                }
            }
        })));

        // The uploader runs meanwhile: an event is either still in the outbox or already at the (local) authority. The outbox is read first, so none falls between.
        const int expectedEvents = 4 * 25;
        string machine = service.Authorization.Fingerprint;
        Dictionary<string, AuditEvent> all = new(StringComparer.Ordinal);
        foreach (AuditEvent item in service.Audit.Outbox.Pending(1000).Concat(store.AuditHistory(new AuditQuery(Limit: 1000)).Select(record => record.Event)))
        {
            all[item.EventId] = item;
        }

        long[] numbers = [.. all.Values.Where(item => item.MachineFingerprint == machine && item.Sequence > before).Select(item => item.Sequence).Order()];
        check(failures == 0 && settings == 5 && store.Audit().Count(entry => entry.Event == "mixed-delivery") == 100 && TestState.Current(rig.State)!.Settings.TimeoutMinutes == 6
            && service.Audit.Outbox.LastSequence() - before == expectedEvents && numbers.SequenceEqual(Enumerable.Range(1, expectedEvents).Select(i => before + i)),
            "contention: mixed store, authority and outbox writers in one service process all commit, and the outbox numbers stay gapless (failures " + failures + ", settings " + settings + ", numbers " + numbers.Length + ")");
    }

    private static void Gate(Action<bool, string> check)
    {
        LaunchGate gate = new();
        int revision = gate.Revision;
        bool ran = false;
        check(gate.TryCommit(revision, CancellationToken.None, () => ran = true) && ran, "gate: a launch commits when nothing changed");
        ran = false;
        gate.Invalidate();
        check(!gate.TryCommit(revision, CancellationToken.None, () => ran = true) && !ran, "gate: a launch that began before an invalidation does not commit");
        check(gate.TryCommit(gate.Revision, CancellationToken.None, () => ran = true) && ran, "gate: a launch that begins after the invalidation commits");
        ran = false;
        using CancellationTokenSource cancelled = new();
        cancelled.Cancel();
        check(!gate.TryCommit(gate.Revision, cancelled.Token, () => ran = true) && !ran, "gate: a cancelled launch does not commit");
        check(gate.Invalidate() == gate.Revision && gate.Revision > revision, "gate: the revision only grows");
    }

    private static async Task StressGate(Action<bool, string> check)
    {
        int committedFirst = 0;
        int invalidatedFirst = 0;
        int wrong = 0;
        for (int round = 0; round < 3000; round++)
        {
            LaunchGate gate = new();
            int revision = gate.Revision;
            long clock = 0;
            long commitStamp = 0;
            long invalidateStamp = 0;
            bool started = false;
            bool committed = false;
            using Barrier start = new(2);
            Task launch = Task.Run(() =>
            {
                start.SignalAndWait();
                committed = gate.TryCommit(revision, CancellationToken.None, () =>
                {
                    started = true;
                    commitStamp = Interlocked.Increment(ref clock);
                });
            });
            Task invalidate = Task.Run(() =>
            {
                start.SignalAndWait();
                gate.Invalidate();
                invalidateStamp = Interlocked.Increment(ref clock);
            });
            await Task.WhenAll(launch, invalidate);

            // Commit first: it finished before the invalidation returned. Invalidation first: nothing started.
            if (committed && started && commitStamp < invalidateStamp)
            {
                committedFirst++;
            }
            else if (!committed && !started)
            {
                invalidatedFirst++;
            }
            else
            {
                wrong++;
            }
        }

        check(wrong == 0, "gate stress: every one of 3000 races is either commit-then-invalidate or invalidate-then-nothing (" + wrong + " wrong, " + committedFirst + " commit first, " + invalidatedFirst + " invalidation first)");
    }

    private static async Task Rejections(Action<bool, string> check, string parent)
    {
        using Rig rig = new(parent);
        string show = rig.Script("show", "echo t=%TOKEN%", "echo \"t=$TOKEN\"");

        Raw ok = await Post(rig, Req(rig, show));
        check(ok.Status == HttpStatusCode.OK && ok.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 0 }, "service: a good request runs (" + ok.Status + " " + ok.Result + ")");

        LaunchRequest good = Req(rig, show);
        int approvedBefore = rig.Approvers.Count;
        Raw bad = await Post(rig, good, digest: new string('0', 64));
        check(bad.Status == HttpStatusCode.BadRequest && bad.Body.Contains("digest", StringComparison.Ordinal), "request rejection: a digest that is not the digest of the body is refused (" + bad.Status + " " + bad.Body.Trim() + ")");
        Raw missing = await Post(rig, Req(rig, show), tweak: message => message.Headers.Remove(HostService.DigestHeader));
        check(missing.Status == HttpStatusCode.BadRequest, "request rejection: a request without a digest is refused (" + missing.Status + ")");
        LaunchRequest tampered = Req(rig, show);
        Raw changed = await Post(rig, tampered, body: tampered.Canonical().Replace("service test", "another reason", StringComparison.Ordinal), digest: tampered.Digest());
        check(changed.Status == HttpStatusCode.BadRequest && changed.Body.Contains("digest", StringComparison.Ordinal), "request rejection: a body changed after its digest was made is refused");

        LaunchRequest future = Req(rig, show) with { ProtocolVersion = 2 };
        Raw version = await Post(rig, future);
        check(version.Status == HttpStatusCode.BadRequest && version.Body.Contains("protocol version 2", StringComparison.Ordinal), "request rejection: another protocol version is refused with its number (" + version.Body.Trim() + ")");

        DateTimeOffset now = DateTimeOffset.UtcNow;
        LaunchRequest expired = Req(rig, show) with { Created = now.AddMinutes(-15), Expires = now.AddMinutes(-6) };
        Raw late = await Post(rig, expired);
        check(late.Status == HttpStatusCode.BadRequest && late.Body.Contains("expired", StringComparison.Ordinal), "request rejection: an expired request is refused (" + late.Body.Trim() + ")");

        LaunchRequest unknown = Req(rig, show);
        string extra = unknown.Canonical().Replace("\"reason\"", "\"admin\":true,\"reason\"", StringComparison.Ordinal);
        Raw unknownField = await Post(rig, unknown, body: extra, digest: unknown.Digest());
        check(unknownField.Status == HttpStatusCode.BadRequest && unknownField.Body.Contains("unknown field admin", StringComparison.Ordinal), "request rejection: an unknown field is refused (" + unknownField.Body.Trim() + ")");

        string huge = "{\"padding\":\"" + new string('x', HostService.MaxBodyBytes + 10) + "\"}";
        string bigOutcome;
        try
        {
            bigOutcome = (await Post(rig, good, body: huge)).Status.ToString();
        }
        catch (HttpRequestException)
        {
            // The service answered 413 and closed the connection while the body was still being sent.
            bigOutcome = nameof(HttpStatusCode.RequestEntityTooLarge);
        }

        check(bigOutcome == nameof(HttpStatusCode.RequestEntityTooLarge), "request rejection: a body over 1 MB is refused (" + bigOutcome + ")");

        Raw host = await Post(rig, Req(rig, show), tweak: message => message.Headers.Host = "evil.example");
        check(host.Status == HttpStatusCode.MisdirectedRequest, "request rejection: a Host that is not a loopback name (DNS rebinding) is refused (" + host.Status + ")");
        Raw subHost = await Post(rig, Req(rig, show), tweak: message => message.Headers.Host = "127.0.0.1.evil.example:" + rig.Service.Port);
        check(subHost.Status == HttpStatusCode.MisdirectedRequest, "request rejection: a name that only starts like a loopback address is refused");
        Raw localhost = await Post(rig, Req(rig, show), tweak: message => message.Headers.Host = "localhost:" + rig.Service.Port);
        check(localhost.Status == HttpStatusCode.OK && localhost.Result is { ExitCode: 0 }, "request rejection: Host localhost is accepted (" + localhost.Status + ")");

        Raw type = await Post(rig, Req(rig, show), tweak: message => message.Content!.Headers.ContentType = new MediaTypeHeaderValue("text/plain"));
        check(type.Status == HttpStatusCode.UnsupportedMediaType, "request rejection: a content type that is not JSON is refused (" + type.Status + ")");
        Raw origin = await Post(rig, Req(rig, show), tweak: message => message.Headers.Add("Origin", "http://evil.example"));
        check(origin.Status == HttpStatusCode.Forbidden, "request rejection: a request from a web page (Origin header) is refused (" + origin.Status + ")");

        LaunchRequest once = Req(rig, show);
        Raw first = await Post(rig, once);
        Raw again = await Post(rig, once);
        check(first.Status == HttpStatusCode.OK && again.Status == HttpStatusCode.Conflict, "request rejection: a request id that was used before is refused (" + again.Status + ")");

        Raw badQuery = await Post(rig, Req(rig, show), path: "/v1/launch?admin=1");
        check(badQuery.Status == HttpStatusCode.BadRequest, "request rejection: an unknown query is refused");
        check((await rig.Http.GetAsync(rig.Url("/v1/launch"))).StatusCode == HttpStatusCode.MethodNotAllowed, "request rejection: GET on the launch route is refused");
        check((await rig.Http.GetAsync(rig.Url("/v1/secrets"))).StatusCode == HttpStatusCode.NotFound && (await rig.Http.GetAsync(rig.Url("/"))).StatusCode == HttpStatusCode.NotFound, "service: there is no route that lists or returns secrets");

        string status = await rig.Http.GetStringAsync(rig.Url("/v1/status"));
        check(status == "{\"protocolVersion\":1,\"running\":true,\"locked\":false,\"remote\":false,\"adminPort\":" + rig.Service.Port + "}", "service: /v1/status returns the version, running state, lock state, remote mode and the admin web app's port only (" + status + ")");
        if (Socket.OSSupportsIPv6)
        {
            try
            {
                string v6 = await rig.Http.GetStringAsync("http://[::1]:" + rig.Service.Port + "/v1/status");
                check(v6 == status, "service: it answers on [::1] too");
            }
            catch (HttpRequestException)
            {
                check(true, "service: no IPv6 loopback on this host");
            }
        }

        check(rig.Approvers.Count == approvedBefore + 2, "request rejection: no refused request reached the approver; only the two good ones did (" + (rig.Approvers.Count - approvedBefore) + ")");

        // A body that stalls (headers, then one byte of a hundred): answered 408 after the read timeout, nothing is started.
        using Rig slow = new(parent, bodyTimeout: TimeSpan.FromMilliseconds(500));
        using Stream wire = await slow.Service.Endpoint.ConnectAsync(CancellationToken.None);
        string head = string.Join("\r\n", "POST /v1/launch HTTP/1.1", "Host: localhost", "Content-Type: application/json", HostService.DigestHeader + ": " + new string((char)48, 64), "Content-Length: 100", "", "{");
        await wire.WriteAsync(Encoding.ASCII.GetBytes(head));
        using CancellationTokenSource limit = new(TimeSpan.FromSeconds(8));
        byte[] buffer = new byte[512];
        int got = 0;
        try
        {
            got = await wire.ReadAsync(buffer, limit.Token);
        }
        catch (OperationCanceledException)
        {
            // No answer in time: the check below fails.
        }

        string answer = Encoding.ASCII.GetString(buffer, 0, got);
        check(answer.StartsWith("HTTP/1.1 408", StringComparison.Ordinal) && slow.Approvers.IsEmpty, "request rejection: a body that does not arrive in time is refused (" + answer.Split((char)13)[0] + ")");
    }

    private static async Task ChildEnvironment(Action<bool, string> check, string parent)
    {
        Environment.SetEnvironmentVariable("ARCANA_GUARDIAN_TEST_SERVICE_ONLY", "only-in-the-service");
        try
        {
            using Rig rig = new(parent);
            string show = rig.Script("showenv", "set > \"%~dpn0.env.txt\"\necho %* > \"%~dpn0.args.txt\"\necho t=%TOKEN%\necho l=%LOG_LEVEL%", "env > \"$0.env.txt\"\necho \"$@\" > \"$0.args.txt\"\necho \"t=$TOKEN\"\necho \"l=$LOG_LEVEL\"");
            string envFile = rig.FileOf(Path.GetFileNameWithoutExtension(show) + ".env.txt");
            if (!OperatingSystem.IsWindows())
            {
                envFile = rig.FileOf(Path.GetFileName(show) + ".env.txt");
            }

            string argsFile = envFile.Replace(".env.txt", ".args.txt", StringComparison.Ordinal);
            Raw refused = await Post(rig, Req(rig, show, environment: Env(("DOTENV_PRIVATE_KEY", "dotenv-private"))));
            check(refused.Status == HttpStatusCode.BadRequest && refused.Body.Contains("dotenvx credential", StringComparison.Ordinal)
                && !refused.Body.Contains("dotenv-private", StringComparison.Ordinal) && rig.Store.Reads == 0,
                "child environment: a launch request with a dotenvx credential is refused before any secret is read");

            LaunchRequest request = Req(rig, show, ["one", "two"], [("TOKEN", "TOKEN")], Env(("CANARY_INHERITED", "inherited-ok"), ("NODE_OPTIONS", "--require evil"), ("CANARY_SHADOW", "from-request")), new Dictionary<string, string> { ["LOG_LEVEL"] = "Verbose7" });
            Raw run = await Post(rig, request);
            string env = File.Exists(envFile) ? File.ReadAllText(envFile) : "";
            string args = File.Exists(argsFile) ? File.ReadAllText(argsFile) : "";
            check(run.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 0 }, "child environment: the launch ran (" + run.Result + " " + run.Stderr + ")");
            check(env.Contains("TOKEN=" + Value, StringComparison.Ordinal), "child environment: the secret value is in the child's environment under the variable name");
            check(!env.Contains(Other, StringComparison.Ordinal), "child environment: a secret that was not named is not in the environment");
            check(env.Contains("CANARY_INHERITED=inherited-ok", StringComparison.Ordinal) && env.Contains("CANARY_SHADOW=from-request", StringComparison.Ordinal), "child environment: the child inherits the environment block of the request");
            check(!env.Contains("only-in-the-service", StringComparison.Ordinal), "child environment: the service's own environment does not leak into the child");
            check(!env.Contains("NODE_OPTIONS", StringComparison.Ordinal) && !env.Contains("DOTENV_PRIVATE_KEY", StringComparison.Ordinal), "child environment: the code-loading variable and dotenvx key never reach the child");
            check(env.Contains("LOG_LEVEL=Verbose7", StringComparison.Ordinal), "child environment: ordinary .env values are in the environment");
            check(args.Contains("one two", StringComparison.Ordinal) && !args.Contains(Value, StringComparison.Ordinal), "child environment: the arguments are the typed ones and carry no value");
            check(run.Stdout.Contains("t=[REDACTED]", StringComparison.Ordinal) && !string.Join("\n", run.Lines).Contains(Value, StringComparison.Ordinal), "child environment: the value never appears in an API event");
            check(rig.Store.Reads == 1, "child environment: one decryption for one launch (" + rig.Store.Reads + ")");

            // The variable names of the request map to the secrets: a pair maps TOKEN to another name.
            LaunchRequest paired = Req(rig, show, [], [("TOKEN", "OTHER_KEY")], Env());
            Raw mapped = await Post(rig, paired);
            check(mapped.Stdout.Contains("t=[REDACTED]", StringComparison.Ordinal) && File.ReadAllText(envFile).Contains("TOKEN=" + Other, StringComparison.Ordinal) && !File.ReadAllText(envFile).Contains(Value, StringComparison.Ordinal), "child environment: a pair gives the variable the value of the secret it names");

            // A PATH that is in the request decides the program that is found.
            string tools = Path.Combine(rig.Work, "tools");
            Directory.CreateDirectory(tools);
            string found = OperatingSystem.IsWindows() ? Path.Combine(tools, "wsprobe.cmd") : Path.Combine(tools, "wsprobe");
            File.WriteAllText(found, OperatingSystem.IsWindows() ? "@echo off\r\necho probe-ran\r\n" : "#!/bin/sh\necho probe-ran\n");
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(found, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }

            string pathName = LaunchClient.CurrentEnvironment().Keys.FirstOrDefault(key => key.Equals("PATH", StringComparison.OrdinalIgnoreCase)) ?? "PATH";
            string pathValue = tools + Path.PathSeparator + LaunchClient.CurrentEnvironment().GetValueOrDefault(pathName, "");
            Raw viaPath = await Post(rig, Req(rig, "wsprobe", [], [("TOKEN", "TOKEN")], Env((pathName, pathValue))));
            check(viaPath.Stdout.Contains("probe-ran", StringComparison.Ordinal), "child environment: the program is found on the PATH the request carries (" + viaPath.Stderr + ")");
        }
        finally
        {
            Environment.SetEnvironmentVariable("ARCANA_GUARDIAN_TEST_SERVICE_ONLY", null);
        }
    }

    private static async Task RedactedStreaming(Action<bool, string> check, string parent)
    {
        string secret = "SplitSecret-ABCDEF123456";
        using Rig rig = new(parent, new Dictionary<string, string> { ["TOKEN"] = secret });
        string half1 = secret[..12];
        string half2 = secret[12..];
        string split = rig.Script(
            "split",
            $"<nul set /p =before {half1}\nping -n 3 127.0.0.1 >nul\n<nul set /p ={half2} after\necho.",
            $"printf 'before {half1}'\nsleep 2\nprintf '{half2} after\\n'");
        Raw run = await Post(rig, Req(rig, split));
        string all = string.Concat(run.Events.Where(item => item.Stream == "stdout").Select(item => item.Text + "|"));
        check(run.Result is { ExitCode: 0 }, "redacted output: the program ran (" + run.Result + " " + run.Stderr + ")");
        check(run.Stdout.Contains("before [REDACTED] after", StringComparison.Ordinal), "redacted output: a secret split across two writes is redacted as one (" + run.Stdout.Trim() + ")");
        check(!all.Contains(secret, StringComparison.Ordinal) && !all.Contains(half1, StringComparison.Ordinal) && !all.Contains(half2, StringComparison.Ordinal), "redacted output: no output event holds the value or half of it (" + all.Replace((char)10, (char)32) + ")");
        check(run.Events.Count(item => item.Stream == "stdout") >= 1 && run.Events.Last().Kind == LaunchEvent.ResultKind, "redacted output: output events come before the result, which is the last line");

        // Output comes as it is made: the first part arrives before the program ends.
        DateTime? chunkAt = null;
        Raw streamed = await Post(rig, Req(rig, rig.Script("early", "echo early-line\nping -n 3 127.0.0.1 >nul\necho late-line", "echo early-line\nsleep 2\necho late-line")), onEvent: item =>
        {
            if (item.Stream == "stdout" && item.Text!.Contains("early-line", StringComparison.Ordinal) && chunkAt is null)
            {
                chunkAt = DateTime.UtcNow;
            }
        });
        check(chunkAt is { } at && (DateTime.UtcNow - at) > TimeSpan.FromMilliseconds(800) && streamed.Stdout.Contains("late-line", StringComparison.Ordinal), "redacted output: output is streamed while the program runs, not at the end (" + (chunkAt is { } shown ? (DateTime.UtcNow - shown).TotalSeconds.ToString("F1", System.Globalization.CultureInfo.InvariantCulture) : "never") + " s before the end)");
    }

    private static async Task ExitAndFailures(Action<bool, string> check, string parent)
    {
        using Rig rig = new(parent);
        Raw seven = await Post(rig, Req(rig, rig.Script("seven", "exit /b 7", "exit 7")));
        check(seven.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 7 }, "exit code: the program's own exit code is the result (" + seven.Result + ")");

        Raw unknownSecret = await Post(rig, Req(rig, rig.Script("x", "echo x", "echo x"), [], [("GHOST", "GHOST")]));
        check(unknownSecret.Result is { Outcome: LaunchOutcome.Failed, ExitCode: 2 } && unknownSecret.Stderr.Contains("Unknown secret: GHOST", StringComparison.Ordinal), "exit code: an unknown secret is a usage failure (2) and names the store's secrets (" + unknownSecret.Stderr.Trim() + ")");

        Raw notFound = await Post(rig, Req(rig, "no-such-program-xyz"));
        check(notFound.Result is { Outcome: LaunchOutcome.Failed, ExitCode: 127 } && notFound.Stderr.Contains("Program not found", StringComparison.Ordinal), "exit code: a program that is not on the PATH gives 127");

        Raw policy = await Post(rig, Req(rig, "env"));
        check(policy.Result is { Outcome: LaunchOutcome.Failed, ExitCode: 2 }, "exit code: the policy still refuses an environment dump (" + policy.Result + ")");

        LaunchRequest protectedName = Req(rig, rig.Script("y", "echo y", "echo y"), [], [("NODE_OPTIONS", "TOKEN")]);
        Raw protectedRun = await Post(rig, protectedName);
        check(protectedRun.Result is { Outcome: LaunchOutcome.Failed, ExitCode: 2 } && protectedRun.Stderr.Contains("NODE_OPTIONS", StringComparison.Ordinal) && !protectedRun.Stderr.Contains(Value, StringComparison.Ordinal), "request rejection: the service checks the protected variable names itself (" + protectedRun.Stderr.Trim() + ")");

        LaunchRequest ordinaryBad = Req(rig, rig.Script("z", "echo z", "echo z"), ordinary: new Dictionary<string, string> { ["NODE_OPTIONS"] = "--x" });
        Raw ordinaryRun = await Post(rig, ordinaryBad);
        check(ordinaryRun.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 0 }, "request rejection: a visible code-loading ordinary variable is passed on, not refused (maintainer decision; the page shows it) (" + ordinaryRun.Result + ")");

        LaunchRequest namesDiffer = Req(rig, rig.Script("w", "echo w", "echo w"), ordinary: new Dictionary<string, string> { ["LOG_LEVEL"] = "x" }) with { EnvNames = ["OTHER_NAME"] };
        Raw namesRun = await Post(rig, namesDiffer);
        check(namesRun.Result is { Outcome: LaunchOutcome.Failed, ExitCode: 2 }, "request rejection: ordinary names that do not match the ordinary values are refused");

        LaunchRequest relative = Req(rig, rig.Script("v", "echo v", "echo v")) with { EnvFiles = ["relative.env"] };
        Raw relativeRun = await Post(rig, relative);
        check(relativeRun.Result is { Outcome: LaunchOutcome.Failed, ExitCode: 2 }, "request rejection: an env file that is not a full path is refused");

        LaunchRequest many = Req(rig, rig.Script("u", "echo u", "echo u"), [], [.. Enumerable.Range(0, EnvDeclarations.MaxPairs + 1).Select(index => ("VAR_" + index, "TOKEN"))]);
        Raw manyRun = await Post(rig, many);
        check(manyRun.Status == HttpStatusCode.BadRequest || manyRun.Result is { Outcome: LaunchOutcome.Failed, ExitCode: 2 }, "request rejection: more pairs than the limit are refused");
        check(rig.Store.Reads <= 2, "exit code: failures before the approval decrypt nothing (" + rig.Store.Reads + " reads, the runs that started)");

        // A denial reads nothing and starts nothing; an approver that throws is a denial too.
        using Rig denied = new(parent, approver: () => new FakeApprover(false));
        Raw no = await Post(denied, Req(denied, denied.Script("ran", "echo ran > \"%~dpn0.marker.txt\"", "echo ran > \"$0.marker.txt\"")));
        check(no.Result is { Outcome: LaunchOutcome.Denied, ExitCode: RunCommand.Denied } && denied.Store.Reads == 0 && !Directory.GetFiles(denied.Work, "*.marker.txt").Any(), "local API alone does not authorize: a denial decrypts nothing and starts nothing (" + no.Result + ")");
        using Rig boom = new(parent, approver: () => new ThrowingApprover());
        Raw thrown = await Post(boom, Req(boom, boom.Script("ran", "echo ran > \"%~dpn0.marker.txt\"", "echo ran > \"$0.marker.txt\"")));
        check(thrown.Result is { Outcome: LaunchOutcome.Denied, ExitCode: RunCommand.Denied } && boom.Store.Reads == 0 && !Directory.GetFiles(boom.Work, "*.marker.txt").Any(), "local API alone does not authorize: an internal error is a denial that decrypts nothing (" + thrown.Result + ")");
    }

    internal static string Marker(Rig rig) => Directory.GetFiles(rig.Work, "*.marker.txt").FirstOrDefault() ?? "";

    private static async Task Cancellation(Action<bool, string> check, string parent)
    {
        // The client leaves while the page is open: nothing is decrypted and nothing starts.
        WaitingApprover waiting = new();
        using Rig rig = new(parent, approver: () => waiting);
        string ran = rig.Script("ran", "echo ran > \"%~dpn0.marker.txt\"", "echo ran > \"$0.marker.txt\"");
        using CancellationTokenSource leave = new();
        Task<Raw> pending = Post(rig, Req(rig, ran), cancel: leave.Token);
        check(await WaitFor(() => waiting.Asked.IsSet), "cancellation: the launch reached the approver");
        await leave.CancelAsync();
        try
        {
            await pending;
        }
        catch (OperationCanceledException)
        {
            // The client's side of the cancellation.
        }

        await Task.Delay(300);
        waiting.Release.Set();
        check(await WaitFor(() => rig.Service.ActiveLaunches == 0), "cancellation: the service ends the launch after the client left");
        check(rig.Store.Reads == 0 && Marker(rig).Length == 0, "cancellation: a client that disconnected before the commit got nothing decrypted and nothing started (" + rig.Store.Reads + " reads)");

        // An explicit cancel while the page is open.
        WaitingApprover second = new();
        using Rig explicitRig = new(parent, approver: () => second);
        string ran2 = explicitRig.Script("ran", "echo ran > \"%~dpn0.marker.txt\"", "echo ran > \"$0.marker.txt\"");
        LaunchRequest request = Req(explicitRig, ran2);
        Task<Raw> running = Post(explicitRig, request);
        check(await WaitFor(() => second.Asked.IsSet), "cancellation: the second launch reached the approver");
        Raw cancelled = await Post(explicitRig, request, path: "/v1/launch/" + request.RequestId + "/cancel", body: "");
        check(cancelled.Status == HttpStatusCode.OK, "cancellation: the cancel route answers 200 for a launch that is waiting (" + cancelled.Status + ")");
        second.Release.Set();
        Raw ended = await running;
        check(ended.Result is { Outcome: LaunchOutcome.Cancelled, ExitCode: RunCommand.Denied } && explicitRig.Store.Reads == 0 && Marker(explicitRig).Length == 0, "cancellation: an explicit cancel before the commit ends as cancelled, decrypts nothing and starts nothing (" + ended.Result + ")");
        Raw unknown = await Post(explicitRig, request, path: "/v1/launch/no-such-id/cancel", body: "");
        check(unknown.Status == HttpStatusCode.NotFound, "cancellation: cancelling an unknown launch is a 404");

        // Cancelled after the environment was prepared and before the commit: the prepared environment is discarded.
        HashSet<string> copiesBefore = [.. Directory.GetDirectories(Path.GetTempPath(), "arcana-guardian-*")];
        PreparedChild? prepared = null;
        Rig? late = null;
        late = new Rig(parent, afterPrepare: child =>
        {
            prepared = child;
            LaunchRequest current = lateRequest!;
            using HttpResponseMessage response = late!.Http.PostAsync(late.Url("/v1/launch/" + current.RequestId + "/cancel"), new StringContent("")).GetAwaiter().GetResult();
        });
        using (late)
        {
            string ran3 = late.Script("ran", "echo ran > \"%~dpn0.marker.txt\"", "echo ran > \"$0.marker.txt\"");
            lateRequest = Req(late, ran3);
            Raw result = await Post(late, lateRequest);
            check(prepared is { IsDiscarded: true, IsStarted: false, EnvironmentCount: 0 }, "cancellation: a launch cancelled after the environment was prepared discards it (" + prepared?.IsDiscarded + ")");
            check(result.Result is { Outcome: LaunchOutcome.Cancelled } && Marker(late).Length == 0 && late.Store.Reads == 1, "cancellation: it ends as cancelled and the program never started (" + result.Result + ")");
            check(Directory.GetDirectories(Path.GetTempPath(), "arcana-guardian-*").All(copiesBefore.Contains), "cancellation: a launch cancelled after its files were held leaves no private copy of them");
            string audit = AuditOf(late);
            check(audit.Contains("\"outcome\":\"cancelled\"", StringComparison.Ordinal) && !audit.Contains(Value, StringComparison.Ordinal), "cancellation: the audit trail says it was cancelled before the start");
        }
    }

    private static LaunchRequest? lateRequest;

    private static async Task InvalidationOrder(Action<bool, string> check, string parent)
    {
        // Invalidation wins: it happens after the child was prepared and before the commit.
        PreparedChild? prepared = null;
        Rig? invalidating = null;
        invalidating = new Rig(parent, afterPrepare: child =>
        {
            prepared = child;
            invalidating!.Service.Gate.Invalidate();
        });
        using (invalidating)
        {
            string ran = invalidating.Script("ran", "echo ran > \"%~dpn0.marker.txt\"", "echo ran > \"$0.marker.txt\"");
            Raw result = await Post(invalidating, Req(invalidating, ran));
            check(result.Result is { Outcome: LaunchOutcome.Cancelled } && prepared is { IsDiscarded: true, IsStarted: false, EnvironmentCount: 0 } && Marker(invalidating).Length == 0, "invalidation: an invalidation before the commit cancels the launch and discards the prepared environment (" + result.Result + ")");
        }

        // The commit wins: the child was started, then the authorization is invalidated; the child is not touched.
        Rig? committing = null;
        committing = new Rig(parent, afterCommit: () => committing!.Service.Gate.Invalidate());
        using (committing)
        {
            string slow = committing.Script("slow", "echo started\nping -n 3 127.0.0.1 >nul\necho done > \"%~dpn0.marker.txt\"\nexit /b 5", "echo started\nsleep 2\necho done > \"$0.marker.txt\"\nexit 5");
            int before = committing.Service.Gate.Revision;
            Raw result = await Post(committing, Req(committing, slow));
            check(committing.Service.Gate.Revision > before, "invalidation: the authorization was invalidated while the child ran");
            check(result.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 5 } && result.Stdout.Contains("started", StringComparison.Ordinal) && Marker(committing).Length > 0, "invalidation: a child started before a later invalidation runs to its end and reports its exit code (" + result.Result + ")");
        }

        // A stress loop: launches racing an invalidation at random moments. Each is exited with its marker, or cancelled without it.
        using Rig stress = new(parent);
        string quick = stress.Script("quick", "echo ran > \"%~dpn0.%RANID%.marker.txt\"\nexit /b 0", "echo ran > \"$0.$RANID.marker.txt\"\nexit 0");
        Random random = new(7);
        int exited = 0;
        int cancelledRuns = 0;
        int inconsistent = 0;
        for (int round = 0; round < 25; round++)
        {
            string id = "r" + round;
            int delay = random.Next(0, 140);
            Task invalidate = Task.Run(async () =>
            {
                await Task.Delay(delay);
                stress.Service.Gate.Invalidate();
            });
            Raw result = await Post(stress, Req(stress, quick, environment: Env(("RANID", id))));
            await invalidate;
            bool marker = Directory.GetFiles(stress.Work, "*." + id + ".marker.txt").Length > 0;
            if (result.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 0 } && marker)
            {
                exited++;
            }
            else if (result.Result is { Outcome: LaunchOutcome.Cancelled } && !marker)
            {
                cancelledRuns++;
            }
            else
            {
                inconsistent++;
            }
        }

        check(inconsistent == 0, "invalidation stress: 25 launches racing an invalidation are each exited with the program run, or cancelled with nothing run (" + exited + " exited, " + cancelledRuns + " cancelled, " + inconsistent + " inconsistent)");
    }

    private static async Task NoSecretInEvents(Action<bool, string> check, string parent)
    {
        using Rig rig = new(parent, new Dictionary<string, string> { ["TOKEN"] = Value, ["OTHER_KEY"] = Other });
        string prints = rig.Script("prints", "echo a=%TOKEN% b=%OTHER%\necho e=%TOKEN% 1>&2", "echo \"a=$TOKEN b=$OTHER\"\necho \"e=$TOKEN\" >&2");
        List<Raw> runs = [];
        runs.Add(await Post(rig, Req(rig, prints, [], [("TOKEN", "TOKEN"), ("OTHER", "OTHER_KEY")])));
        runs.Add(await Post(rig, Req(rig, prints, [], [("TOKEN", "TOKEN")])));
        runs.Add(await Post(rig, Req(rig, "no-such-program-xyz")));
        runs.Add(await Post(rig, Req(rig, prints), digest: new string('1', 64)));
        string everything = string.Join("\n", runs.Select(item => item.Body + string.Join("\n", item.Lines))) + await rig.Http.GetStringAsync(rig.Url("/v1/status"));
        string[] forms = [Value, Other, Convert.ToBase64String(Encoding.UTF8.GetBytes(Value)), Convert.ToHexString(Encoding.UTF8.GetBytes(Value)), Uri.EscapeDataString(Value)];
        check(runs[0].Stdout.Contains("a=[REDACTED] b=[REDACTED]", StringComparison.Ordinal) && runs[0].Stderr.Contains("e=[REDACTED]", StringComparison.Ordinal), "no secret in events: both values and both streams are redacted (" + runs[0].Stdout.Trim() + ")");
        check(forms.All(form => !everything.Contains(form, StringComparison.Ordinal)), "no secret in events: no canary value, in plain, base64, hex or URL form, is in any response body or event");
        check(runs.Where(item => item.Status == HttpStatusCode.OK).All(item => item.Events.All(e => e.Kind is LaunchEvent.ApprovalKind or LaunchEvent.OutputKind or LaunchEvent.ResultKind)) && runs[0].Lines.All(line => line.StartsWith("{\"event\":\"", StringComparison.Ordinal)), "no secret in events: every line is an approval, output or result event");
        check(!AuditOf(rig).Contains(Value, StringComparison.Ordinal), "no secret in events: the audit trail holds no value either");
    }

    private static async Task TwoClients(Action<bool, string> check, string parent)
    {
        Barrier both = new(2);
        int asked = 0;
        using Rig rig = new(parent, new Dictionary<string, string> { ["TOKEN_A"] = "Client-A-Value-1111", ["TOKEN_B"] = "Client-B-Value-2222" }, approver: () => new BarrierApprover(both, () => Interlocked.Increment(ref asked)));
        string a = rig.Script("a", "echo a=%TOKEN_A%\nping -n 2 127.0.0.1 >nul\necho a-end\nexit /b 11", "echo \"a=$TOKEN_A\"\nsleep 1\necho a-end\nexit 11");
        string b = rig.Script("b", "echo b=%TOKEN_B%\nping -n 2 127.0.0.1 >nul\necho b-end\nexit /b 22", "echo \"b=$TOKEN_B\"\nsleep 1\necho b-end\nexit 22");
        Task<Raw> first = Post(rig, Req(rig, a, [], [("TOKEN_A", "TOKEN_A")]));
        Task<Raw> second = Post(rig, Req(rig, b, [], [("TOKEN_B", "TOKEN_B")]));
        Raw[] done = await Task.WhenAll(first, second);
        check(done[0].Result is { ExitCode: 11 } && done[1].Result is { ExitCode: 22 }, "two clients: both launches finish with their own exit codes (" + done[0].Result + " / " + done[1].Result + ")");
        check(done[0].Stdout.Contains("a=[REDACTED]", StringComparison.Ordinal) && done[0].Stdout.Contains("a-end", StringComparison.Ordinal) && !done[0].Stdout.Contains("b=", StringComparison.Ordinal), "two clients: the first one gets only its own output");
        check(done[1].Stdout.Contains("b=[REDACTED]", StringComparison.Ordinal) && done[1].Stdout.Contains("b-end", StringComparison.Ordinal) && !done[1].Stdout.Contains("a=", StringComparison.Ordinal), "two clients: the second one gets only its own output");
        check(asked == 2 && rig.Store.Reads == 2, "two clients: both approvals were open at once, each decrypted its own secret (" + asked + " asks, " + rig.Store.Reads + " reads)");
    }

    private sealed class BarrierApprover(Barrier barrier, Action asked) : IApprover
    {
        public ApprovalDecision Request(ApprovalRequest request)
        {
            asked();

            return barrier.SignalAndWait(TimeSpan.FromSeconds(15)) ? TestSigner.Allow(request) : ApprovalDecision.Deny("the other client never asked");
        }
    }

    private static async Task DockerStandIn(Action<bool, string> check, string parent)
    {
        using Rig rig = new(parent, new Dictionary<string, string> { ["API_TOKEN"] = Value });
        string bin = Path.Combine(rig.Work, "bin");
        Directory.CreateDirectory(bin);
        string docker = Path.Combine(bin, OperatingSystem.IsWindows() ? "docker.cmd" : "docker");
        string log = Path.Combine(bin, "docker.log");
        if (OperatingSystem.IsWindows())
        {
            File.WriteAllText(docker, "@echo off\r\necho ARGS=%* > \"%~dp0docker.log\"\r\necho ENVTOKEN=%API_TOKEN% >> \"%~dp0docker.log\"\r\necho container-output=%API_TOKEN%\r\nexit /b 0\r\n");
        }
        else
        {
            File.WriteAllText(docker, "#!/bin/sh\necho \"ARGS=$*\" > \"" + log + "\"\necho \"ENVTOKEN=$API_TOKEN\" >> \"" + log + "\"\necho \"container-output=$API_TOKEN\"\n");
            File.SetUnixFileMode(docker, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        string pathName = LaunchClient.CurrentEnvironment().Keys.FirstOrDefault(key => key.Equals("PATH", StringComparison.OrdinalIgnoreCase)) ?? "PATH";
        IReadOnlyDictionary<string, string> env = Env((pathName, bin + Path.PathSeparator + LaunchClient.CurrentEnvironment().GetValueOrDefault(pathName, "")));
        Raw run = await Post(rig, Req(rig, "docker", ["run", "--rm", "-e", "API_TOKEN", "alpine", "echo", "hi"], [("API_TOKEN", "API_TOKEN")], env));
        string seen = File.Exists(log) ? File.ReadAllText(log) : "";
        check(run.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 0 }, "docker: a program called docker is launched like any other (" + run.Result + " " + run.Stderr.Trim() + ")");
        string argsLine = seen.Split('\n').FirstOrDefault(line => line.StartsWith("ARGS=", StringComparison.Ordinal)) ?? "";
        check(argsLine.Contains("-e API_TOKEN", StringComparison.Ordinal) && !argsLine.Contains(Value, StringComparison.Ordinal), "docker: the secret name is in the arguments and its value is not (" + argsLine.Trim() + ")");
        check(seen.Contains("ENVTOKEN=" + Value, StringComparison.Ordinal), "docker: the value reaches the docker client only through its environment");
        check(run.Stdout.Contains("container-output=[REDACTED]", StringComparison.Ordinal) && !string.Join("\n", run.Lines).Contains(Value, StringComparison.Ordinal), "docker: the output is redacted like any other");
    }

    private static async Task ApprovalOverHttp(Action<bool, string> check, string parent)
    {
        string folder = Path.Combine(parent, "http-" + Guid.NewGuid().ToString("N")[..8]);
        string work = Path.Combine(folder, "work");
        Directory.CreateDirectory(work);
        using HttpClient browser = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(30) };
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator stranger = TestAuthenticator.ES256();
        string program = OperatingSystem.IsWindows() ? "show.cmd" : "show.sh";
        string path = Path.Combine(work, program);
        if (OperatingSystem.IsWindows())
        {
            File.WriteAllText(path, "@echo off\r\necho t=%TOKEN%\r\nexit /b 4\r\n");
        }
        else
        {
            File.WriteAllText(path, "#!/bin/sh\necho \"t=$TOKEN\"\nexit 4\n");
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        async Task<(Raw Raw, string Page, int Reads, int Status)> Go(TestAuthenticator signer)
        {
            StateDatabase db = StateDatabase.InFolder(Path.Combine(folder, "state-" + Guid.NewGuid().ToString("N")[..6]));
            new PasskeyStore(db).Add(laptop.Record("localhost", "laptop"));
            using TestMachine machine = new(Path.GetDirectoryName(db.FilePath)!);
            CountingCipher cipher = new();
            SecretStore store = new(db, cipher);
            if (SecretStoreTests.Put(store, new Dictionary<string, string> { ["TOKEN"] = Value }) is { } problem)
            {
                throw new InvalidOperationException(problem);
            }

            using HostService service = HostService.Start(new HostServiceOptions { CommandLineEndpoint = HostServiceTests.Rig.TestEndpoint(), Lock = AuthorityLock.UnlockedForTests(), State = db, Store = store, Deployment = machine.Deployment, Port = 0, TimeLimit = TimeSpan.FromSeconds(30), ApproverFactory = (settings, announce) => CommandWiring.RunApprover(db, settings, announce) });
            SecretStoreTests.OpenKeys(service, db);
            using HttpClient client = new(service.Endpoint.CreateHandler()) { Timeout = TimeSpan.FromSeconds(60) };
            DateTimeOffset now = DateTimeOffset.UtcNow;
            LaunchRequest request = new(LaunchProtocol.Version, "http-" + Guid.NewGuid().ToString("N")[..8], now, now.AddMinutes(5), "bm9uY2UtMDAwMDAwMDEx" + Guid.NewGuid().ToString("N")[..6], ["TOKEN"], [new LaunchMapping("TOKEN", "TOKEN")], "approval over http", "./" + program, [], work, [], [], new Dictionary<string, string>(), Env(), []);
            string page = "";
            int status = 0;
            using HttpRequestMessage message = new(HttpMethod.Post, new Uri(service.Endpoint.BaseUri, "v1/launch")) { Content = new StringContent(request.Canonical(), new UTF8Encoding(false), new MediaTypeHeaderValue("application/json")) };
            message.Headers.Add(HostService.DigestHeader, request.Digest());
            using HttpResponseMessage response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead);
            using StreamReader reader = new(await response.Content.ReadAsStreamAsync(), new UTF8Encoding(false));
            List<string> lines = [];
            List<LaunchEvent> events = [];
            while (await reader.ReadLineAsync() is { } line)
            {
                lines.Add(line);
                if (LaunchEvent.TryParse(line, out LaunchEvent? parsed, out _))
                {
                    events.Add(parsed!);
                    if (parsed!.Kind == LaunchEvent.ApprovalKind)
                    {
                        Uri uri = new(parsed.Link!);
                        string baseUrl = "http://127.0.0.1:" + uri.Port + uri.AbsolutePath;
                        page = WebUtility.HtmlDecode(TestState.Get(browser, baseUrl).Body);
                        (status, _) = TestState.Approve(browser, baseUrl, uri.GetLeftPart(UriPartial.Authority), uri.IdnHost, signer);
                    }
                }
            }

            return (new Raw(response.StatusCode, "", lines, events), page, cipher.Decrypts, status);
        }

        (Raw approved, string page, int reads, int status) = await Go(laptop);
        check(approved.Events.Count(item => item.Kind == LaunchEvent.ApprovalKind) == 1 && approved.Events.Last().Kind == LaunchEvent.ResultKind, "approval over HTTP: the service announces the page link once, as an approval event");
        check(page.Contains("approval over http", StringComparison.Ordinal) && page.Contains("TOKEN", StringComparison.Ordinal) && !page.Contains(Value, StringComparison.Ordinal), "approval over HTTP: the page shows the request, names only (page status " + status + ")");
        check(approved.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 4 } && approved.Stdout.Contains("t=[REDACTED]", StringComparison.Ordinal) && reads == 1, "approval over HTTP: a passkey approval releases the value, the program runs and its exit code passes through (" + approved.Result + " " + approved.Stderr.Trim() + ")");
        check(!string.Join("\n", approved.Lines).Contains(Value, StringComparison.Ordinal), "approval over HTTP: the value is in no event");
        check(approved.Stderr.Contains("waiting for the user to approve this request", StringComparison.Ordinal), "approval over HTTP: the usual waiting line and request text are streamed as stderr");

        (Raw denied, _, int deniedReads, _) = await Go(stranger);
        check(denied.Result is { Outcome: LaunchOutcome.Denied, ExitCode: RunCommand.Denied } && deniedReads == 0 && !denied.Stdout.Contains("t=", StringComparison.Ordinal), "approval over HTTP: a proof from a key that is not enrolled is a denial, nothing is decrypted and nothing runs (" + denied.Result + ")");
    }

    private static async Task FixRound1(Action<bool, string> check, string parent)
    {
        // H1: the inherited environment is part of what is approved: fingerprint, page line (names only), mismatch, audit prefix.
        Dictionary<string, string> baseEnv = new() { ["PATH"] = "C:\\bin", ["LANG"] = "en", ["EDITOR_NOTE"] = "plain-value-1" };
        Dictionary<string, string> evilEnv = new(baseEnv) { ["HTTPS_PROXY"] = "http://127.0.0.1:9999/secretish", ["npm_config_script_shell"] = "C:\\agent\\evil.cmd", ["JDK_JAVA_OPTIONS"] = "-javaagent:x", ["CORECLR_PROFILER"] = "{guid}", ["SSL_CERT_FILE"] = "C:\\agent\\ca.pem", ["GIT_CONFIG_COUNT"] = "1", ["HOME"] = "C:\\agent" };
        string work = Path.Combine(parent, "h1");
        Directory.CreateDirectory(work);
        ApprovalRequest Make(IReadOnlyDictionary<string, string>? env) => new("prog", Path.Combine(work, "prog.cmd"), [], work, "why", ["TOKEN"], InheritedEnvironment: env);
        string plain = RequestFingerprint.Compute(Make(null)).Key;
        string a = RequestFingerprint.Compute(Make(baseEnv)).Key;
        string b = RequestFingerprint.Compute(Make(evilEnv)).Key;
        string reordered = RequestFingerprint.Compute(Make(new Dictionary<string, string> { ["EDITOR_NOTE"] = "plain-value-1", ["LANG"] = "en", ["PATH"] = "C:\\bin" })).Key;
        check(a != b && a != plain && a == reordered, "environment binding: a different inherited environment is a different fingerprint, so it cannot reuse an approval or a grant; order does not matter");
        string page = ApprovalSummary.BuildMessage(Make(evilEnv));
        check(page.Contains("Environment: 10 inherited variables; notable names: ", StringComparison.Ordinal) && new[] { "CORECLR_PROFILER", "GIT_CONFIG_COUNT", "HOME", "HTTPS_PROXY", "JDK_JAVA_OPTIONS", "SSL_CERT_FILE", "npm_config_script_shell", "PATH" }.All(name => page.Contains(name, StringComparison.Ordinal)), "environment binding: the page shows the count and the notable names (" + page.Split('\n').FirstOrDefault(line => line.StartsWith("Environment:", StringComparison.Ordinal)) + ")");
        check(!page.Contains("127.0.0.1:9999", StringComparison.Ordinal) && !page.Contains("evil.cmd", StringComparison.Ordinal) && !page.Contains("plain-value-1", StringComparison.Ordinal) && !page.Contains("EDITOR_NOTE", StringComparison.Ordinal), "environment binding: no value, and no plain variable name, is shown");
        check(!ApprovalSummary.BuildMessage(Make(null)).Contains("Environment:", StringComparison.Ordinal), "environment binding: a run without a request environment shows no such line");
        LaunchRequest sent = LaunchRequestBinding.From(Make(baseEnv), "req-1", "bm9uY2UtMDAwMDAwMDE", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(1), baseEnv);
        check(LaunchRequestBinding.Mismatch(sent, Make(baseEnv)) is null && LaunchRequestBinding.Mismatch(sent with { InheritedEnvironment = evilEnv }, Make(baseEnv)) is { } differs && differs.Contains("environment", StringComparison.Ordinal), "environment binding: a request whose environment is not the approved one is a mismatch");

        {
            using Rig rig = new(parent);
            string show = rig.Script("hone", "echo ok", "echo ok");
            await Post(rig, Req(rig, show, environment: Env(("HTTPS_PROXY", "http://127.0.0.1:9999/canary-proxy"))));
            string text = string.Join("\n", rig.Approvers.OfType<FakeApprover>().SelectMany(item => item.Requests).Select(item => ApprovalSummary.BuildMessage(item)));
            string audit = AuditOf(rig);
            check(text.Contains("notable names: ", StringComparison.Ordinal) && text.Contains("HTTPS_PROXY", StringComparison.Ordinal) && !text.Contains("canary-proxy", StringComparison.Ordinal), "environment binding: through the service the approver sees the variable name and never its value");
            check(audit.Contains("\"type\":\"launch\"", StringComparison.Ordinal) && !audit.Contains("canary-proxy", StringComparison.Ordinal), "environment binding: the signed audit events carry no environment value");
        }

        // M2: a client that leaves after the program started ends the program (and its children); the cancel route does the same.
        foreach (bool viaRoute in new[] { false, true })
        {
            using Rig rig = new(parent);
            string longRun = rig.Script("long", "echo started\nping -n 40 127.0.0.1 >nul\necho done > \"%~dpn0.marker.txt\"", "echo started\nsleep 40\necho done > \"$0.marker.txt\"");
            using CancellationTokenSource leave = new();
            LaunchRequest request = Req(rig, longRun);
            Task<Raw> running = Post(rig, request, onEvent: item =>
            {
                if (item.Stream == "stdout" && item.Text!.Contains("started", StringComparison.Ordinal))
                {
                    if (viaRoute)
                    {
                        using HttpResponseMessage response = rig.Http.PostAsync(rig.Url("/v1/launch/" + request.RequestId + "/cancel"), new StringContent("")).GetAwaiter().GetResult();
                    }
                    else
                    {
                        leave.Cancel();
                    }
                }
            }, cancel: leave.Token);
            try
            {
                await running;
            }
            catch (OperationCanceledException)
            {
                // The client's side of the disconnect.
            }

            bool ended = await WaitFor(() => rig.Service.ActiveLaunches == 0, 15);
            string audit = AuditOf(rig);
            check(ended && Marker(rig).Length == 0 && audit.Contains("\"outcome\":\"cancelled\"", StringComparison.Ordinal) || audit.Contains("\"type\":\"execution\"", StringComparison.Ordinal), "client cancel: " + (viaRoute ? "the cancel route" : "a disconnect") + " after the start ends the program within seconds, not after its 40 s, and the finish is audited (" + ended + "; " + string.Join("|", AuditOf(rig).Split((char)10)) + ")");
        }

        // L1/L2: a launch whose authorization was invalidated, or that expired, while its page was open decrypts nothing and is audited.
        {
            CancelAwareApprover waiting = new();
            using Rig rig = new(parent, approver: () => waiting);
            string ran = rig.Script("ran", "echo ran > \"%~dpn0.marker.txt\"", "echo ran > \"$0.marker.txt\"");
            Task<Raw> pending = Post(rig, Req(rig, ran));
            check(await WaitFor(() => waiting.Asked.IsSet), "stale launch: the approver was asked");
            rig.Service.Gate.Invalidate();
            waiting.Release.Set();
            Raw result = await pending;
            string audit = AuditOf(rig);
            check(result.Result is { Outcome: LaunchOutcome.Cancelled } && rig.Store.Reads == 0 && Marker(rig).Length == 0 && audit.Contains("authorization-invalidated", StringComparison.Ordinal), "stale launch: an invalidation while the page was open stops the decryption and is audited (" + result.Result + ", " + rig.Store.Reads + " reads, " + string.Join("|", AuditOf(rig).Split((char)10)) + ")");
        }

        {
            CancelAwareApprover waiting = new();
            using Rig rig = new(parent, approver: () => waiting);
            string ran = rig.Script("ran", "echo ran > \"%~dpn0.marker.txt\"", "echo ran > \"$0.marker.txt\"");
            DateTimeOffset now = DateTimeOffset.UtcNow;
            Task<Raw> pending = Post(rig, Req(rig, ran) with { Created = now.AddSeconds(-5), Expires = now.AddSeconds(2) });
            check(await WaitFor(() => waiting.Asked.IsSet), "expired launch: the approver was asked");
            await Task.Delay(2500);
            waiting.Release.Set();
            Raw result = await pending;
            check(result.Result is { Outcome: LaunchOutcome.Cancelled } && rig.Store.Reads == 0 && Marker(rig).Length == 0 && AuditOf(rig).Contains("request-expired", StringComparison.Ordinal), "expired launch: a request that expired while its page was open decrypts nothing");
        }

        // L3: an exception between prepare and commit discards the prepared environment; one after the start is reported as a failure, not a denial.
        {
            PreparedChild? prepared = null;
            using Rig rig = new(parent, afterPrepare: child =>
            {
                prepared = child;
                throw new InvalidOperationException("hook failed");
            });
            Raw result = await Post(rig, Req(rig, rig.Script("ran", "echo ran > \"%~dpn0.marker.txt\"", "echo ran > \"$0.marker.txt\"")));
            check(prepared is { IsDiscarded: true, EnvironmentCount: 0 } && Marker(rig).Length == 0 && result.Result is { Outcome: LaunchOutcome.Denied }, "exceptions: a failure between prepare and commit discards the prepared environment and starts nothing");
        }

        {
            using Rig rig = new(parent, afterCommit: () => throw new InvalidOperationException("hook failed"));
            Raw result = await Post(rig, Req(rig, rig.Script("slow", "echo started\nping -n 30 127.0.0.1 >nul", "echo started\nsleep 30")));
            string audit = AuditOf(rig);
            check(result.Result is { Outcome: LaunchOutcome.Failed, ExitCode: RunCommand.StoreError } && result.Stderr.Contains("after the program started", StringComparison.Ordinal) && !result.Stderr.Contains("did not approve (internal error)", StringComparison.Ordinal) && audit.Contains("\"reason\":\"internal-error\"", StringComparison.Ordinal), "exceptions: a failure after the start is reported as failed (4), not as a denial, and is audited (" + result.Result + ")");
        }

        // L4: at most 8 launches at once; a cancelled client closes the approval page (the approver sees the token).
        {
            using Rig rig = new(parent, approver: () => new CancelAwareApprover());
            string ran = rig.Script("ran", "echo ran", "echo ran");
            using CancellationTokenSource leaveAll = new();
            List<Task<Raw>> held = [];
            for (int index = 0; index < HostService.MaxConcurrentLaunches; index++)
            {
                held.Add(Post(rig, Req(rig, ran), cancel: leaveAll.Token));
            }

            check(await WaitFor(() => rig.Service.ActiveLaunches == HostService.MaxConcurrentLaunches), "concurrency: eight launches are accepted");
            Raw ninth = await Post(rig, Req(rig, ran));
            check(ninth.Status == HttpStatusCode.ServiceUnavailable && ninth.Body.Contains("too many launches", StringComparison.Ordinal), "concurrency: the ninth is refused with a clear message (" + ninth.Status + ")");
            await leaveAll.CancelAsync();
            check(await WaitFor(() => rig.Service.ActiveLaunches == 0, 10) && rig.Approvers.OfType<CancelAwareApprover>().All(item => item.SawCancel.IsSet), "concurrency: clients that left close their approvals at once, the approvers saw the token (active " + rig.Service.ActiveLaunches + ", approvers " + rig.Approvers.Count + ", saw " + rig.Approvers.OfType<CancelAwareApprover>().Count(item => item.SawCancel.IsSet) + ")");
            foreach (Task<Raw> task in held)
            {
                try
                {
                    await task;
                }
                catch (OperationCanceledException)
                {
                    // Expected.
                }
            }

            Raw after = await Post(rig, Req(rig, ran));
            check(after.Result is { ExitCode: 0 }, "concurrency: after they left a new launch is accepted");
        }

        // L7: stopping the service cancels the launches in progress.
        {
            CancelAwareApprover waiting = new();
            Rig rig = new(parent, approver: () => waiting);
            Task<Raw> pending = Post(rig, Req(rig, rig.Script("ran", "echo ran", "echo ran")));
            check(await WaitFor(() => waiting.Asked.IsSet), "shutdown: the approver was asked");
            rig.Service.Dispose();
            check(waiting.SawCancel.Wait(TimeSpan.FromSeconds(10)), "shutdown: stopping the service cancels a launch in progress");
            try
            {
                await pending;
            }
            catch (HttpRequestException)
            {
                // The service went away.
            }

            rig.Dispose();
        }

        // The real page approver: a client that leaves closes the page at once (its link then finds nothing).
        {
            string folder = Path.Combine(parent, "page-" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(Path.Combine(folder, "work"));
            using TestAuthenticator key = TestAuthenticator.ES256();
            StateDatabase db = StateDatabase.InFolder(Path.Combine(folder, "state"));
            new PasskeyStore(db).Add(key.Record("localhost", "laptop"));
            SecretStore store = new(db, new CountingCipher());
            SecretStoreTests.Put(store, new Dictionary<string, string> { ["TOKEN"] = Value });
            using TestMachine machine = new(Path.GetDirectoryName(db.FilePath)!);
            using HostService service = HostService.Start(new HostServiceOptions { CommandLineEndpoint = HostServiceTests.Rig.TestEndpoint(), Lock = AuthorityLock.UnlockedForTests(), State = db, Store = store, Deployment = machine.Deployment, Port = 0, TimeLimit = TimeSpan.FromSeconds(60), ApproverFactory = (settings, announce) => CommandWiring.RunApprover(db, settings, announce) });
            using HttpClient client = new(service.Endpoint.CreateHandler()) { Timeout = TimeSpan.FromSeconds(60) };
            string program = OperatingSystem.IsWindows() ? "p.cmd" : "p.sh";
            File.WriteAllText(Path.Combine(folder, "work", program), OperatingSystem.IsWindows() ? "@echo off\r\necho hi\r\n" : "#!/bin/sh\necho hi\n");
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(Path.Combine(folder, "work", program), UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }

            DateTimeOffset now = DateTimeOffset.UtcNow;
            LaunchRequest request = new(LaunchProtocol.Version, "page-" + Guid.NewGuid().ToString("N")[..8], now, now.AddMinutes(5), "bm9uY2UtMDAwMDAwMDEx" + Guid.NewGuid().ToString("N")[..6], ["TOKEN"], [new LaunchMapping("TOKEN", "TOKEN")], "page cancel", "./" + program, [], Path.Combine(folder, "work"), [], [], new Dictionary<string, string>(), Env(), []);
            using HttpRequestMessage message = new(HttpMethod.Post, new Uri(service.Endpoint.BaseUri, "v1/launch")) { Content = new StringContent(request.Canonical(), new UTF8Encoding(false), new MediaTypeHeaderValue("application/json")) };
            message.Headers.Add(HostService.DigestHeader, request.Digest());
            using CancellationTokenSource leave = new();
            string? link = null;
            try
            {
                using HttpResponseMessage response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, leave.Token);
                using StreamReader reader = new(await response.Content.ReadAsStreamAsync(leave.Token), new UTF8Encoding(false));
                while (await reader.ReadLineAsync(leave.Token) is { } line)
                {
                    if (LaunchEvent.TryParse(line, out LaunchEvent? parsed, out _) && parsed!.Kind == LaunchEvent.ApprovalKind)
                    {
                        link = parsed.Link;
                        leave.Cancel();
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // The client left.
            }

            bool closed = await WaitFor(() => service.ActiveLaunches == 0, 10);
            string pageStatus = "none";
            if (link is not null)
            {
                Uri uri = new(link);
                pageStatus = TestState.Get(client, "http://127.0.0.1:" + uri.Port + uri.AbsolutePath).Status.ToString();
            }

            check(link is not null && closed && pageStatus != "200", "client cancel: a client that leaves closes the approval page and ends the launch long before the time limit (page: " + pageStatus + ")");
        }

        // L5, L6: duplicate names that differ in case, a relative or missing working directory.
        {
            using Rig rig = new(parent);
            string show = rig.Script("hone", "echo ok", "echo ok");
            if (OperatingSystem.IsWindows())
            {
                Raw duplicate = await Post(rig, Req(rig, show, environment: Env(("PATH", "C:\\x"), ("Path", "C:\\y"))));
                check(duplicate.Result is { Outcome: LaunchOutcome.Failed, ExitCode: 2 } && duplicate.Stderr.Contains("more than once", StringComparison.Ordinal), "request rejection: PATH and Path together are refused (" + duplicate.Result + ")");
            }

            Raw relative = await Post(rig, Req(rig, show) with { WorkingDirectory = "relative\\folder" });
            check(relative.Result is { Outcome: LaunchOutcome.Failed, ExitCode: 2 } && relative.Stderr.Contains("working directory", StringComparison.Ordinal), "request rejection: a relative working directory is refused with its own message (" + relative.Result + ")");
            Raw missing = await Post(rig, Req(rig, show) with { WorkingDirectory = Path.Combine(rig.Work, "does-not-exist") });
            check(missing.Result is { Outcome: LaunchOutcome.Failed, ExitCode: 2 } && missing.Stderr.Contains("existing folder", StringComparison.Ordinal), "request rejection: a working directory that does not exist is refused");
        }
    }

    private static async Task ClientAndCommandLine(Action<bool, string> check, string parent)
    {
        // The service is not running: one clear line and the documented exit code, with nothing asked.
        int free;
        using (System.Net.Sockets.TcpListener probe = new(IPAddress.Loopback, 0))
        {
            probe.Start();
            free = ((IPEndPoint)probe.LocalEndpoint).Port;
        }

        StringWriter stdout = new();
        StringWriter stderr = new();
        RunArgs args = CliArgs.ParseRun(["--secrets", "TOKEN", "--reason", "no service", "--", "anything"], out _)!;
        int code = await LaunchClient.RunAsync(args, parent, LocalEndpoint.Loopback(free), null, stdout, stderr, new ServiceTrust(null));
        check(code == LaunchClient.ServiceNotRunning && LaunchClient.ServiceNotRunning == 6, "client: with no service the exit code is 6 (" + code + ")");
        check(stderr.ToString().Trim().StartsWith("using-secrets: the host service is not running. Start it with: using-secrets service (nothing answers on ", StringComparison.Ordinal) && stderr.ToString().Trim().Split('\n').Length == 1 && stdout.ToString().Length == 0, "client: with no service one clear line is printed and nothing else (" + stderr.ToString().Trim() + ")");

        // Through a running service: the same output and exit code as a direct run, the link printed where it always was.
        using Rig rig = new(parent);
        string show = rig.Script("show", "echo t=%TOKEN%\necho e=%TOKEN% 1>&2\nexit /b 9", "echo \"t=$TOKEN\"\necho \"e=$TOKEN\" >&2\nexit 9");
        StringWriter outText = new();
        StringWriter errText = new();
        RunArgs run = CliArgs.ParseRun(["--secrets", "TOKEN", "--reason", "via client", "--", show], out _)!;
        int exit = await LaunchClient.RunAsync(run, rig.Work, rig.Service.Endpoint, null, outText, errText, rig.Machine.Trust);
        check(exit == 9 && outText.ToString().Contains("t=[REDACTED]", StringComparison.Ordinal) && errText.ToString().Contains("e=[REDACTED]", StringComparison.Ordinal), "client: output goes to the same streams and the exit code passes through (" + exit + ")");
        check(errText.ToString().Contains("using-secrets: waiting for the user to approve this request...", StringComparison.Ordinal) && !outText.ToString().Contains(Value, StringComparison.Ordinal) && !errText.ToString().Contains(Value, StringComparison.Ordinal), "client: the terminal shows the usual waiting line and no value");

        // The client has no store: a request for an unknown secret is refused by the service.
        StringWriter unknownErr = new();
        int unknown = await LaunchClient.RunAsync(CliArgs.ParseRun(["--secrets", "GHOST", "--reason", "x", "--", show], out _)!, rig.Work, rig.Service.Endpoint, null, new StringWriter(), unknownErr, rig.Machine.Trust);
        check(unknown == RunCommand.Usage && unknownErr.ToString().Contains("Unknown secret: GHOST", StringComparison.Ordinal), "client: an unknown secret is refused by the service with the usual message and exit 2");

        // The usual client-side usage errors are unchanged.
        StringWriter usageErr = new();
        int usage = await LaunchClient.RunAsync(CliArgs.ParseRun(["--reason", "x", "--", show], out _)!, rig.Work, rig.Service.Endpoint, null, new StringWriter(), usageErr, rig.Machine.Trust);
        check(usage == RunCommand.Usage && usageErr.ToString().Contains("Name the secrets with --secrets", StringComparison.Ordinal), "client: a run that names no secret fails as before");

        // Command line.
        check(CliArgs.Parse(["service"], out _) is CliCommand.Service { AdminPort: null }, "command line: service takes no option");
        check(CliArgs.Parse(["service", "--port", "9100"], out _) is CliCommand.Service { AdminPort: 9100 }, "command line: service --port N sets the admin web app port");
        check(CliArgs.Parse(["service", "--port", "0"], out string portError) is null && portError.Contains("1 to 65535", StringComparison.Ordinal), "command line: service --port must be 1 to 65535");
        check(CliArgs.Parse(["service", "--frob"], out _) is null, "command line: service refuses other options");
        check(CliArgs.Parse(["--service-port", "9100", "--reason", "x", "--secrets", "A", "--", "p"], out _) is null && CliArgs.Parse(["--service-port", "9100", "--list"], out _) is null, "command line: there is no --service-port: a run does not name a port, it reaches the service over its own channel");
        check(AdminPort.Resolve(null, _ => null, out _) == 8765 && AdminPort.Resolve(null, name => name == "ARCANA_GUARDIAN_PORT" ? "9200" : null, out _) == 9200 && AdminPort.Resolve(9300, _ => "9200", out _) == 9300, "command line: the port is the option, else ARCANA_GUARDIAN_PORT, else 8765");
        check(AdminPort.Resolve(null, _ => "nope", out string? envError) is null && envError is not null, "command line: a ARCANA_GUARDIAN_PORT that is not a port is refused");

        // Events: one strict reader and writer.
        check(LaunchEvent.TryParse(LaunchEvent.Output("stdout", "line\n\"quoted\"\u0001"), out LaunchEvent? roundTrip, out _) && roundTrip!.Text == "line\n\"quoted\"\u0001", "events: output text round-trips through JSON");
        check(LaunchEvent.Result(LaunchOutcome.Exited, 3) == "{\"event\":\"result\",\"outcome\":\"exited\",\"exitCode\":3}" && LaunchEvent.Approval("http://localhost:1/a/x") == "{\"event\":\"approval\",\"link\":\"http://localhost:1/a/x\"}", "events: the result and approval lines have the documented shape");
        check(!LaunchEvent.TryParse("{\"event\":\"output\",\"stream\":\"stdout\",\"text\":\"x\",\"secret\":\"y\"}", out _, out _) && !LaunchEvent.TryParse("{\"event\":\"result\",\"outcome\":\"exited\"}", out _, out _) && !LaunchEvent.TryParse("{\"event\":\"other\"}", out _, out _), "events: an unknown member, a missing member and an unknown event are refused");
    }
}

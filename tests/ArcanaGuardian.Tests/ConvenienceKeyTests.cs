using System.Buffers.Text;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Microsoft.Data.Sqlite;

using AdminTap = ArcanaGuardian.Tests.Tapped;

namespace ArcanaGuardian.Tests;

/// <summary>
/// An approval releases no key. An administrator's PRF unlock opens the store key, and a convenience passkey without PRF (it can never open the master key) approves a run
/// once, through the approval page and through the approval queue, for a native and for a provider-mounted secret, locally and through a remote authority, and creates a grant
/// with no end under which later runs need no tap. After a lock, and after a restart before the next unlock, nothing is decrypted, under that grant too; a lock that arrives
/// between the approval and the decryption delivers nothing and starts nothing. A convenience session extends, revokes and replaces grants with its own tap (real runs show the
/// coverage), reads every read route with no secret in any answer, and its tap on the page of every admin-only operation changes nothing.
/// </summary>
internal static class ConvenienceKeyTests
{
    internal const string Value = "Convenience-Canary-6d2f0a91";
    private const string MountedValue = "Convenience-Mounted-Canary-3e81";
    private const string Mounted = "team/dev/TOKEN";
    private const string ProviderPath = "kv/dev/TOKEN";
    private const string External = "ext-token";

    public static async Task Run(Action<bool, string> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "ws-conv-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);
        try
        {
            await PageOnce(check, root);
            await QueueOnce(check, root);
            await GrantWithNoEnd(check, root);
            await LockBeforeDecryption(check, root);
            await ProviderMounted(check, root);
            await ProviderMountedQueue(check, root);
            await RemoteAuthority(check, root);
            await GrantChanges(check, root);
            await Reads(check, root);
            await AdminOnlyTaps(check, root);
        }
        finally
        {
            RunCommand.AfterHold = null;
            SqliteConnection.ClearAllPools();
            Directory.Delete(root, true);
        }
    }

    /// <summary>A local authority over a real store: the admin laptop (PRF) and the convenience phone (no PRF), the one-use approval page or the approval queue.</summary>
    internal sealed class Authority : IDisposable
    {
        private readonly bool _queue;
        private readonly bool _provider;
        private readonly bool _machineEndpoint;
        private HttpClient? _http;

        public Authority(string root, bool queue = false, bool provider = false, bool machineEndpoint = false, TimeProvider? clock = null)
        {
            _queue = queue;
            _provider = provider;
            _machineEndpoint = machineEndpoint;
            string folder = Path.Combine(root, "auth-" + Guid.NewGuid().ToString("N")[..8]);
            string state = Path.Combine(folder, "state");
            Work = Path.Combine(folder, "work");
            Directory.CreateDirectory(Work);
            Machine = new TestMachine(state, trusted: true, hostName: "convenience-authority", clock: clock);
            State = StateDatabase.InFolder(state);
            TestState.Add(State, Admin.Record("localhost", "laptop") with { Created = DateTimeOffset.UtcNow }, withStore: true);
            if (!TestState.AddConvenience(State, Phone, "phone"))
            {
                throw new InvalidOperationException("the convenience key could not be added");
            }

            Store = new SecretStore(State, Cipher);
            if (SecretStoreTests.Put(Store, new Dictionary<string, string> { ["TOKEN"] = Value }) is { } problem)
            {
                throw new InvalidOperationException(problem);
            }

            if (provider)
            {
                ProviderStore setup = new(Machine.Deployment.Store);
                ProviderInstance instance = setup.AddInstance("vault-one", "test", """{"label":"one"}""", TimeSpan.FromHours(1));
                Mount tree = setup.AddMount(instance.Id, MountKind.Tree, "team", "kv");
                setup.ReplaceEntries(tree.Id, [new NamespaceEntry(tree.Id, Mounted, ProviderPath, External, null, DescriptionSource.Provider)]);
                Registry.RegisterType("test", "1.0", () => Adapter, () => new FakeConfiguration());
                Adapter.Returns(ProviderPath, MountedValue);
                Adapter.ListHandler = (_, _) => Task.FromResult(new ListSecretsResult([new ProviderSecretInfo("dev/TOKEN", External, null)], null, true));
            }

            Service = Start(locked: false, Machine.Deployment);
        }

        public TestAuthenticator Admin { get; } = TestAuthenticator.ES256();

        public TestAuthenticator Phone { get; } = TestAuthenticator.ES256(prf: false);

        public string Work { get; }

        public TestMachine Machine { get; }

        public StateDatabase State { get; }

        public CountingCipher Cipher { get; } = new();

        public SecretStore Store { get; }

        public FakeProviderAdapter Adapter { get; } = new();

        public ProviderRegistry Registry { get; } = new();

        public HostService Service { get; private set; }

        /// <summary>Wraps the approver of each request (a test adds what happens right after the tap).</summary>
        public Func<IApprover, IApprover>? Wrap { get; set; }

        public HttpClient Http => _http ??= new HttpClient(Service.Endpoint.CreateHandler()) { Timeout = TimeSpan.FromSeconds(60) };

        public HttpClient Browser { get; } = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(30) };

        private HostService Start(bool locked, LocalDeployment deployment) => HostService.Start(new HostServiceOptions
        {
            HttpBrowserFixture = true,
            CommandLineEndpoint = HostServiceTests.Rig.TestEndpoint(),
            Lock = locked ? null : AuthorityLock.UnlockedForTests(),
            State = State,
            Store = Store,
            Deployment = deployment,
            Port = 0,
            TimeLimit = TimeSpan.FromSeconds(30),
            ApproverFactory = _queue ? null : (settings, announce) =>
            {
                IApprover page = CommandWiring.RunApprover(State, settings, announce);

                return Wrap?.Invoke(page) ?? page;
            },
            ProviderRegistry = _provider ? Registry : null,
            MachineEndpoint = _machineEndpoint ? new MachineListenerOptions { Port = 0 } : null,
            UseApprovalQueueForMachineLaunches = _queue,
            AuditUploadInterval = TimeSpan.FromMilliseconds(300),
        });

        /// <summary>What the admin's unlock does to the keys: the laptop's PRF output opens the store key and the review key.</summary>
        public bool OpenKeys()
        {
            using Unlock release = TestVault.Unlock(State, Admin)!;

            return Service.Keys!.TryOpen(TestState.Current(State)!, release);
        }

        /// <summary>A service restart: it starts locked, with no key open.</summary>
        public void Restart()
        {
            _http?.Dispose();
            _http = null;
            Service.Dispose();
            Service = Start(locked: true, Machine.Restart());
        }

        public LaunchRequest Request(string program, string secret = "TOKEN")
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;

            return new LaunchRequest(LaunchProtocol.Version, "conv-" + Guid.NewGuid().ToString("N")[..12], now, now.AddMinutes(5), "bm9uY2UtMDAwMDAwMDE" + Guid.NewGuid().ToString("N")[..6], [secret], [new LaunchMapping("TOKEN", secret)],
                "convenience test", program, [], Work, [], [], new Dictionary<string, string>(), HostServiceTests.Env(), []);
        }

        public Task<HostServiceTests.Raw> Post(LaunchRequest request, Action<LaunchEvent>? onEvent = null, string route = "v1/launch") => ConvenienceKeyTests.Post(Http, Service.Endpoint.BaseUri, request, onEvent, route);

        public void Dispose()
        {
            _http?.Dispose();
            Browser.Dispose();
            Service.Dispose();
            Machine.Deployment.Dispose();
            Machine.Dispose();
            Admin.Dispose();
            Phone.Dispose();
        }
    }

    /// <summary>An approver that passes the page's decision on and then locks the authority: the lock comes after the tap and before anything is decrypted.</summary>
    private sealed class LockAfterTap(IApprover inner, Func<AuthorityLock> authority) : IApprover
    {
        public ApprovalDecision Request(ApprovalRequest request) => Request(request, CancellationToken.None);

        public ApprovalDecision Request(ApprovalRequest request, CancellationToken cancel)
        {
            ApprovalDecision decision = inner.Request(request, cancel);
            authority().Lock("test: right after the tap");

            return decision;
        }
    }

    private static async Task<HostServiceTests.Raw> Post(HttpClient http, Uri baseUri, LaunchRequest request, Action<LaunchEvent>? onEvent, string route)
    {
        using HttpRequestMessage message = new(HttpMethod.Post, new Uri(baseUri, route)) { Content = new StringContent(request.Canonical(), new UTF8Encoding(false), new MediaTypeHeaderValue("application/json")) };
        message.Headers.Add(HostService.DigestHeader, request.Digest());
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
                onEvent?.Invoke(parsed!);
            }
        }

        return new HostServiceTests.Raw(response.StatusCode, all.ToString(), lines, events);
    }

    /// <summary>The page a tap was made on: its start data (what the passkey is asked for) and its text.</summary>
    internal sealed record Tapped(int Status, string Start, string Page);

    /// <summary>Plays the one-use approval page as the browser does for a passkey without PRF: the assertion over the chosen time, and no PRF member.</summary>
    internal static Tapped Tap(HttpClient browser, string link, TestAuthenticator who, int minutes = 0)
    {
        Uri uri = new(link);
        string url = "http://127.0.0.1:" + uri.Port + uri.AbsolutePath;
        (_, string page) = TestState.Get(browser, url);
        string start = Between(page, "<script type=\"application/json\" id=\"start\">", "</script>");
        if (start.Length == 0)
        {
            return new Tapped(0, "", page);
        }

        using JsonDocument data = JsonDocument.Parse(start);
        byte[] bind = Base64Url.DecodeFromChars(data.RootElement.GetProperty("bind").GetString()!);
        string assertion = who.Assert(ReuseBinding.Challenge(bind, minutes), uri.GetLeftPart(UriPartial.Authority), uri.IdnHost, TestState.NextCount());
        (int status, _) = TestState.Post(browser, url + "/proof", ReuseTests.Body(minutes, assertion));

        return new Tapped(status, start, WebUtility.HtmlDecode(page));
    }

    private static string Between(string text, string start, string end)
    {
        int from = text.IndexOf(start, StringComparison.Ordinal);
        if (from < 0)
        {
            return "";
        }

        from += start.Length;
        int to = text.IndexOf(end, from, StringComparison.Ordinal);

        return to < 0 ? "" : text[from..to];
    }

    /// <summary>A script that writes the TOKEN it was given beside it and prints it (the service redacts it), then exits 4.</summary>
    internal static (string Program, string ValueFile) ValueScript(string work, string name)
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

    internal static string? Read(string file) => File.Exists(file) ? File.ReadAllText(file).Trim() : null;

    private static bool AsksForPrf(string start) => start.Contains("prfKey", StringComparison.Ordinal);

    private static bool Shows(HostServiceTests.Raw raw, string value) => string.Join("\n", raw.Lines).Contains(value, StringComparison.Ordinal) || raw.Body.Contains(value, StringComparison.Ordinal);

    // ---------- once, on the page ----------

    private static async Task PageOnce(Action<bool, string> check, string root)
    {
        using Authority auth = new(root);
        Manifest manifest = TestState.Current(auth.State)!;
        string phoneId = TestAuthenticator.Encode(auth.Phone.CredentialId);
        check(manifest.Keys.Any(key => key.Id == phoneId && !key.Admin) && TestVault.Unlock(auth.State, auth.Phone) is null, "convenience key: the phone is enrolled, it is not an admin key and it has no PRF");
        check(auth.OpenKeys() && auth.Service.Keys!.OpenedBy?.Id == TestAuthenticator.Encode(auth.Admin.CredentialId), "convenience key: the admin laptop's PRF output opens the keys (the unlock)");

        (string program, string valueFile) = ValueScript(auth.Work, "page-once");
        List<Tapped> taps = [];
        HostServiceTests.Raw raw = await auth.Post(auth.Request(program), item =>
        {
            if (item.Kind == LaunchEvent.ApprovalKind)
            {
                taps.Add(Tap(auth.Browser, item.Link!, auth.Phone));
            }
        });
        check(raw.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 4 } && Read(valueFile) == Value && raw.Stdout.Contains("t=[REDACTED]", StringComparison.Ordinal), "convenience page: one tap by a passkey without PRF approves the run once and the child gets the value (" + raw.Result + " " + raw.Stderr.Trim() + ")");
        check(taps.Count == 1 && taps[0].Status == 200 && !AsksForPrf(taps[0].Start), "convenience page: one page and one tap, and the page's start data asks the passkey for no PRF output (" + taps.Count + " taps, " + string.Join(" | ", taps.Select(item => item.Status + " " + item.Start)) + ")");
        check(auth.Cipher.Decrypts == 1 && !Shows(raw, Value), "convenience page: only the requested value was decrypted, and it is in no event");
    }

    // ---------- the approval queue ----------

    /// <summary>What the approval queue showed and asked for one decision: the review (as the admin app reads it) and the passkey challenge, as JSON.</summary>
    internal sealed record Queued(string Review, string Challenge, string? Code);

    /// <summary>
    /// Posts <paramref name="request" /> and decides every request it puts in the approval queue as the admin app does: a challenge, an assertion by <paramref name="who" /> over the
    /// chosen time (0: once), no PRF member. Returns the run's events and what each decision showed.
    /// </summary>
    internal static async Task<(HostServiceTests.Raw Raw, List<Queued> Decisions)> PostQueued(Authority auth, LaunchRequest request, TestAuthenticator who, int minutes = 0, string route = "v1/launch")
    {
        List<Queued> decisions = [];
        HashSet<string> handled = new(StringComparer.Ordinal);
        Task<HostServiceTests.Raw> running = auth.Post(request, route: route);
        while (!running.IsCompleted)
        {
            await Task.WhenAny(running, Task.Delay(50));
            foreach (ApprovalQueueItemDto item in auth.Service.Approvals.ListPending(10, null, out _).Where(item => !handled.Contains(item.RequestId)))
            {
                IProofMethod method = auth.Service.Admin.ApprovalProof!;
                string review = JsonSerializer.Serialize(auth.Service.Approvals.GetDetail(item.RequestId, auth.Service.Admin.ProcessedApproval));
                (ApprovalChallengeDto? challenge, string? code, _) = auth.Service.Approvals.CreateOrReuseChallenge(item.RequestId, "conv-session", TestState.Origin, method);
                if (challenge is null)
                {
                    continue;
                }

                handled.Add(item.RequestId);
                byte[] bind = Base64Url.DecodeFromChars(challenge.Payload.GetProperty("bind").GetString()!);
                string proof = who.Assert(ReuseBinding.Challenge(bind, minutes), TestState.Origin, "localhost", TestState.NextCount());
                (_, string? approveCode, _) = auth.Service.Approvals.Approve(item.RequestId, "conv-session", challenge.FlowId, proof, method, auth.Service.Admin.ProcessedApproval, minutes: minutes);
                decisions.Add(new Queued(review, JsonSerializer.Serialize(challenge), code ?? approveCode));
            }
        }

        return (await running, decisions);
    }

    private static async Task QueueOnce(Action<bool, string> check, string root)
    {
        using Authority auth = new(root, queue: true);
        auth.OpenKeys();
        (string program, string valueFile) = ValueScript(auth.Work, "queue-once");
        (HostServiceTests.Raw raw, List<Queued> decisions) = await PostQueued(auth, auth.Request(program), auth.Phone);
        check(decisions.Count == 1 && decisions[0].Code is null && !decisions[0].Challenge.Contains("prf", StringComparison.OrdinalIgnoreCase) && !decisions[0].Review.Contains("Unlock", StringComparison.OrdinalIgnoreCase),
            "convenience queue: one decision, and neither the review nor the challenge asks the passkey for a PRF output or carries a key to seal one to (" + string.Join(" | ", decisions.Select(item => item.Code + " " + item.Challenge)) + ")");
        check(raw.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 4 } && Read(valueFile) == Value && auth.Cipher.Decrypts == 1, "convenience queue: approve once by a passkey without PRF delivers the value (" + raw.Result + " " + raw.Stderr.Trim() + ")");
    }

    // ---------- a grant with no end ----------

    private static async Task GrantWithNoEnd(Action<bool, string> check, string root)
    {
        using Authority auth = new(root, queue: true);
        auth.OpenKeys();
        (string program, string valueFile) = ValueScript(auth.Work, "granted");
        (HostServiceTests.Raw made, List<Queued> decisions) = await PostQueued(auth, auth.Request(program), auth.Phone, ReuseOffer.Always, "v1/approve");
        GrantRecord? grant = auth.Machine.Deployment.Store.Grants().FirstOrDefault(row => row.Usage == GrantUsage.Reusable);
        check(made.Result is { ExitCode: 0 } && decisions.Count == 1 && !decisions[0].Challenge.Contains("prf", StringComparison.OrdinalIgnoreCase) && grant is { Expires: null, Status: "active" } && made.Stdout.Contains("with no end", StringComparison.Ordinal),
            "convenience grant: one tap by a passkey without PRF creates a grant with no end, and the challenge asks for no PRF output (" + made.Result + " " + made.Stdout.Trim() + " " + made.Stderr.Trim() + " " + grant?.Status + ")");
        check(decisions.Count == 1 && !decisions[0].Review.Contains("KEY HELD", StringComparison.Ordinal) && !decisions[0].Review.Contains("first run", StringComparison.OrdinalIgnoreCase) && !made.Stdout.Contains("first run", StringComparison.OrdinalIgnoreCase),
            "convenience grant: neither the review nor the answer says anything about a key kept for the grant or a first run that taps");

        int taps = decisions.Count;
        async Task<HostServiceTests.Raw> Run()
        {
            File.Delete(valueFile);
            (HostServiceTests.Raw raw, List<Queued> asked) = await PostQueued(auth, auth.Request(program), auth.Phone);
            taps += asked.Count;

            return raw;
        }

        for (int run = 1; run <= 2; run++)
        {
            HostServiceTests.Raw again = await Run();
            check(again.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 4 } && Read(valueFile) == Value && taps == 1 && again.Events.All(item => item.Kind != LaunchEvent.ApprovalKind),
                "convenience grant: run " + run + " under the grant needs no tap and no page, and the child gets the value (" + again.Result + " " + again.Stderr.Trim() + ")");
        }

        int decrypts = auth.Cipher.Decrypts;
        (byte[]? openStore, byte[]? openReview) = auth.Service.Keys!.HeldForTests;
        auth.Service.Lock.Lock("test");
        (byte[]? store, byte[]? review) = auth.Service.Keys.HeldForTests;
        HostServiceTests.Raw locked = await Run();
        check(locked.Result is not { Outcome: LaunchOutcome.Exited } && Read(valueFile) is null && taps == 1 && auth.Cipher.Decrypts == decrypts && store is null && review is null && !auth.Service.Keys.IsOpen,
            "convenience grant: after a lock the grant delivers nothing and the keys are closed (" + locked.Status + " " + locked.Result + ")");
        check(openStore is { Length: > 0 } && openReview is { Length: > 0 } && openStore.All(b => b == 0) && openReview.All(b => b == 0) && !auth.Service.Authorization.Vouched && auth.Service.Authorization.SyncedGrants.Count == 0,
            "convenience grant: the lock zeroed the arrays that held the store key and the review key, and discarded the vouching and the synchronized grants");

        auth.Service.Lock.Unlock(UnlockMethod.Seam);
        bool ready = await HostServiceTests.WaitFor(() => auth.Service.Ready, 20);
        HostServiceTests.Raw closed = await Run();
        check(ready && closed.Result is not { Outcome: LaunchOutcome.Exited } && Read(valueFile) is null && taps == 1 && auth.Cipher.Decrypts == decrypts,
            "convenience grant: unlocked again without the admin's key release (a test seam), the grant still decrypts nothing, because the lock closed the keys (" + closed.Result + " " + closed.Stderr.Trim() + ")");

        auth.Restart();
        HostServiceTests.Raw restarted = await Run();
        check(auth.Service.Lock.IsLocked && !auth.Service.Keys!.IsOpen && restarted.Result is not { Outcome: LaunchOutcome.Exited } && Read(valueFile) is null && taps == 1 && auth.Cipher.Decrypts == decrypts,
            "convenience grant: after a restart, before an unlock, the grant delivers nothing (" + restarted.Status + " " + restarted.Result + ")");

        auth.Service.Lock.Unlock(UnlockMethod.Seam);
        check(auth.OpenKeys() && await HostServiceTests.WaitFor(() => auth.Service.Ready, 20), "convenience grant: the admin unlocks the restarted service");
        HostServiceTests.Raw unlocked = await Run();
        check(unlocked.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 4 } && Read(valueFile) == Value && taps == 1, "convenience grant: once the admin unlocks, the same grant covers the run again with no tap (" + unlocked.Result + " " + unlocked.Stderr.Trim() + ")");
    }

    // ---------- a lock between the approval and the decryption ----------

    private static async Task LockBeforeDecryption(Action<bool, string> check, string root)
    {
        using Authority auth = new(root);
        auth.OpenKeys();
        (string program, string valueFile) = ValueScript(auth.Work, "lock-hold");
        RunCommand.AfterHold = () => auth.Service.Lock.Lock("test: after the approval, before the decryption");
        try
        {
            HostServiceTests.Raw raw = await auth.Post(auth.Request(program), item =>
            {
                if (item.Kind == LaunchEvent.ApprovalKind)
                {
                    Tap(auth.Browser, item.Link!, auth.Phone);
                }
            });
            check(raw.Result is { Outcome: LaunchOutcome.Cancelled } && Read(valueFile) is null && auth.Cipher.Decrypts == 0 && !Shows(raw, Value), "convenience lock: a lock after the approval and before the decryption decrypts nothing, delivers nothing and starts no child (" + raw.Result + " " + raw.Stderr.Trim() + ")");
        }
        finally
        {
            RunCommand.AfterHold = null;
        }

        // The lock begins after every check that can stop a launch (the hold, the stale check, the grant check) and immediately before the decryption.
        using Authority late = new(root);
        late.OpenKeys();
        (string lateProgram, string lateValue) = ValueScript(late.Work, "lock-decrypt");
        bool lateOpen = false;
        RunCommand.BeforeDecrypt = () =>
        {
            late.Service.Lock.Lock("test: immediately before the decryption");
            lateOpen = late.OpenKeys() && late.Service.Lock.IsLocked;
        };
        try
        {
            HostServiceTests.Raw raw = await late.Post(late.Request(lateProgram), item =>
            {
                if (item.Kind == LaunchEvent.ApprovalKind)
                {
                    Tap(late.Browser, item.Link!, late.Phone);
                }
            });
            check(lateOpen && raw.Result is { Outcome: LaunchOutcome.Cancelled } && Read(lateValue) is null && late.Cipher.Decrypts == 0 && !Shows(raw, Value),
                "convenience lock: a lock that begins immediately before the decryption (after every other check; the keys opened again, so only the lock gate stops it) decrypts nothing, delivers nothing and starts no child; the run ends cancelled, not as a store error (" + raw.Result + " " + raw.Stderr.Trim() + ")");
        }
        finally
        {
            RunCommand.BeforeDecrypt = null;
        }
    }

    // ---------- a provider-mounted secret ----------

    private static async Task ProviderMounted(Action<bool, string> check, string root)
    {
        using Authority auth = new(root, provider: true);
        auth.OpenKeys();
        (string program, string valueFile) = ValueScript(auth.Work, "mounted");
        List<Tapped> taps = [];
        void TapOnce(LaunchEvent item)
        {
            if (item.Kind == LaunchEvent.ApprovalKind)
            {
                taps.Add(Tap(auth.Browser, item.Link!, auth.Phone));
            }
        }

        HostServiceTests.Raw fresh = await auth.Post(auth.Request(program, Mounted), TapOnce);
        check(fresh.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 4 } && Read(valueFile) == MountedValue && taps.Count == 1 && !AsksForPrf(taps[0].Start) && auth.Adapter.Invocations.Count == 1,
            "convenience mounted: one tap by a passkey without PRF approves a provider-mounted secret, retrieved from the provider, and the page asks for no PRF output (" + fresh.Result + " " + fresh.Stderr.Trim() + ")");

        File.Delete(valueFile);
        HostServiceTests.Raw cached = await auth.Post(auth.Request(program, Mounted), TapOnce);
        check(cached.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 4 } && Read(valueFile) == MountedValue && taps.Count == 2 && auth.Adapter.Invocations.Count == 1,
            "convenience mounted: the next approval is served from the cache, decrypted with the unlocked store key (" + cached.Result + " " + cached.Stderr.Trim() + ", " + auth.Adapter.Invocations.Count + " retrievals)");

        auth.Service.Lock.Lock("test");
        auth.Service.Lock.Unlock(UnlockMethod.Seam);
        await HostServiceTests.WaitFor(() => auth.Service.Ready, 20);
        File.Delete(valueFile);
        HostServiceTests.Raw closed = await auth.Post(auth.Request(program, Mounted), TapOnce);
        check(closed.Result is not { Outcome: LaunchOutcome.Exited } && Read(valueFile) is null && !Shows(closed, MountedValue), "convenience mounted: with the keys closed by a lock, an approved mounted secret is not delivered (" + closed.Result + " " + closed.Stderr.Trim() + ")");
    }

    private static async Task ProviderMountedQueue(Action<bool, string> check, string root)
    {
        using Authority auth = new(root, queue: true, provider: true);
        auth.OpenKeys();
        (string program, string valueFile) = ValueScript(auth.Work, "mounted-queue");
        (HostServiceTests.Raw raw, List<Queued> decisions) = await PostQueued(auth, auth.Request(program, Mounted), auth.Phone);
        check(raw.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 4 } && Read(valueFile) == MountedValue && decisions.Count == 1 && !decisions[0].Challenge.Contains("prf", StringComparison.OrdinalIgnoreCase) && auth.Adapter.Invocations.Count == 1,
            "convenience mounted queue: approve once in the queue by a passkey without PRF delivers a provider-mounted secret; the challenge asks for no PRF output (" + raw.Result + " " + raw.Stderr.Trim() + ")");
    }

    // ---------- through a remote authority ----------

    internal sealed class RemoteHost : IDisposable
    {
        public required TestMachine Machine { get; init; }

        public required HostServiceTests.Rig Rig { get; init; }

        public void Dispose()
        {
            Rig.Dispose();
            Machine.Dispose();
        }
    }

    /// <summary>A host in remote mode, paired with <paramref name="auth" /> and approved there, as in <see cref="RemoteLaunchTests" />.</summary>
    internal static async Task<RemoteHost> Pair(string root, Authority auth, string hostName)
    {
        TestMachine machine = new(Path.Combine(root, "host-" + Guid.NewGuid().ToString("N")[..8], "state"), trusted: false, hostName: hostName);
        (CreatedInvitation? invitation, string? why) = auth.Service.Pairing.Create("test admin");
        PairingResult paired = await PairingClient.RunAsync(new PairingClientOptions { Bundle = PairingBundle.TryParse(invitation?.Bundle ?? throw new InvalidOperationException("no invitation: " + why))!, MachineKey = machine.MachineKey, IdentityCertificate = machine.Deployment.IdentityCertificate, HostName = hostName, HostConfig = machine.Deployment.HostConfig, MachineTls = machine.Deployment.Tls });
        if (!paired.Ok)
        {
            throw new InvalidOperationException("the host could not pair: " + paired.Message);
        }

        RemoteAuthorityConfig config = machine.Deployment.HostConfig.Load().Config!.Remote!;
        machine.Deployment.UseRemote(new RemoteAuthority(config, machine.Deployment.Tls, machine.Deployment.HostConfig) { RetryPause = TimeSpan.FromMilliseconds(50), Retries = 6 });
        TransitionResult approved = auth.Machine.Deployment.Store.Approve(machine.Fingerprint, hostName, "test admin");
        if (!approved.Ok)
        {
            throw new InvalidOperationException("the host could not be approved: " + approved.Message);
        }

        HostServiceTests.Rig rig = new(root, new Dictionary<string, string> { ["TOKEN"] = "DECOY-HOST-VALUE" }, machine: machine, auditInterval: TimeSpan.FromMilliseconds(300));

        return new RemoteHost { Machine = machine, Rig = rig };
    }

    private static async Task RemoteAuthority(Action<bool, string> check, string root)
    {
        if (PlatformSkip.NoServerTls13("convenience passkey approvals through a remote authority"))
        {
            return;
        }

        using Authority auth = new(root, provider: true, machineEndpoint: true);
        auth.OpenKeys();
        using RemoteHost host = await Pair(root, auth, "wsl-convenience");
        string program = host.Rig.Script("remote-once", "echo %TOKEN%>\"%~dpn0.val\"\necho t=%TOKEN%\nexit /b 4", "printf '%s' \"$TOKEN\" > \"$0.val\"\necho \"t=$TOKEN\"\nexit 4");
        string valueFile = host.Rig.FileOf(OperatingSystem.IsWindows() ? "remote-once.val" : "remote-once.sh.val");
        List<Tapped> taps = [];
        HostServiceTests.Raw raw = await HostServiceTests.Post(host.Rig, HostServiceTests.Req(host.Rig, program), item =>
        {
            if (item.Kind == LaunchEvent.ApprovalKind && ApprovalLinkNotice.IsSafe(item.Link ?? ""))
            {
                taps.Add(Tap(auth.Browser, item.Link!, auth.Phone));
            }
        });
        check(raw.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 4 } && Read(valueFile) == Value && taps.Count == 1 && !AsksForPrf(taps[0].Start) && host.Rig.Store.Reads == 0 && auth.Cipher.Decrypts == 1,
            "convenience remote: one tap at the authority by a passkey without PRF approves a remote host's run, the authority decrypts once and the child on the host gets the value; the page asks for no PRF output (" + raw.Result + " " + raw.Stderr.Trim() + ")");

        (byte[]? storeKey, byte[]? reviewKey) = auth.Service.Keys!.HeldForTests;
        string[] keyTexts = [.. new[] { storeKey, reviewKey }.OfType<byte[]>().Select(Encoding.ASCII.GetString)];
        string hostFiles = string.Join("\n", Directory.EnumerateFiles(host.Machine.Folder, "*", SearchOption.AllDirectories).Where(file => !file.EndsWith("-shm", StringComparison.Ordinal)).Select(file =>
        {
            try
            {
                using FileStream stream = new(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using StreamReader reader = new(stream, Encoding.Latin1);
                return reader.ReadToEnd();
            }
            catch (FileNotFoundException) when (file.EndsWith("-wal", StringComparison.Ordinal))
            {
                // SQLite can checkpoint and remove the write-ahead log after enumeration. The database is checked separately.
                return "";
            }
        }));
        string said = string.Join("\n", raw.Lines) + raw.Stdout + raw.Stderr;
        check(keyTexts.Length == 2 && keyTexts.All(key => key.Length > 0 && !hostFiles.Contains(key, StringComparison.OrdinalIgnoreCase) && !said.Contains(key, StringComparison.OrdinalIgnoreCase)) && !hostFiles.Contains(Value, StringComparison.Ordinal) && !said.Contains(Value, StringComparison.Ordinal),
            "convenience remote: the remote host's disk (state, arcana-guardian.db, audit outbox, host.json) and the client's events hold neither the value nor the authority's store or review key");

        async Task<HostServiceTests.Raw> RunRemote(string secret = "TOKEN")
        {
            File.Delete(valueFile);

            return await HostServiceTests.Post(host.Rig, HostServiceTests.Req(host.Rig, program, pairs: [("TOKEN", secret)]), item =>
            {
                if (item.Kind == LaunchEvent.ApprovalKind && ApprovalLinkNotice.IsSafe(item.Link ?? ""))
                {
                    taps.Add(Tap(auth.Browser, item.Link!, auth.Phone));
                }
            });
        }

        async Task Reopen()
        {
            auth.Service.Lock.Unlock(UnlockMethod.Seam);
            auth.OpenKeys();
            await HostServiceTests.WaitFor(() => auth.Service.Ready, 20);
        }

        HostServiceTests.Raw mounted = await RunRemote(Mounted);
        check(mounted.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 4 } && Read(valueFile) == MountedValue && taps.Count == 2 && !AsksForPrf(taps[1].Start) && auth.Adapter.Invocations.Count == 1 && !Shows(mounted, MountedValue),
            "convenience remote mounted: one tap at the authority by a passkey without PRF approves a provider-mounted secret for a remote host (" + mounted.Result + " " + mounted.Stderr.Trim() + ")");

        int decrypts = auth.Cipher.Decrypts;
        bool openWhileLocked = false;
        AuthorityLaunchHandler.BeforeDecrypt = () =>
        {
            auth.Service.Lock.Lock("test: after the last check of the delivery, before the decryption");
            openWhileLocked = auth.OpenKeys() && auth.Service.Lock.IsLocked;
        };
        HostServiceTests.Raw beforeDecrypt;
        try
        {
            beforeDecrypt = await RunRemote();
        }
        finally
        {
            AuthorityLaunchHandler.BeforeDecrypt = null;
        }

        check(openWhileLocked && beforeDecrypt.Result is not { Outcome: LaunchOutcome.Exited } && Read(valueFile) is null && auth.Cipher.Decrypts == decrypts && !Shows(beforeDecrypt, Value),
            "convenience remote: a lock that begins after every check of the delivery and before the decryption decrypts nothing (the keys are open again, so only the lock gate stops it), delivers nothing and starts nothing on the host (" + beforeDecrypt.Result + " " + beforeDecrypt.Stderr.Trim() + ")");

        await Reopen();
        List<byte[]> copies = [];
        AuthorityLaunchHandler.AfterDecrypt = made =>
        {
            copies.AddRange(made);
            auth.Service.Lock.Lock("test: after the decryption, before the delivery is signed");
        };
        HostServiceTests.Raw afterDecrypt;
        try
        {
            afterDecrypt = await RunRemote();
        }
        finally
        {
            AuthorityLaunchHandler.AfterDecrypt = null;
        }

        check(afterDecrypt.Result is not { Outcome: LaunchOutcome.Exited } && Read(valueFile) is null && copies.Count == 1 && copies.All(copy => copy.Length > 0 && copy.All(b => b == 0)) && !Shows(afterDecrypt, Value),
            "convenience remote: a lock after the decryption and before the delivery is signed sends nothing, and the delivery's copies of the values are zeroed (" + copies.Count + " copies, " + afterDecrypt.Result + ")");

        await Reopen();
        auth.Wrap = page => new LockAfterTap(page, () => auth.Service.Lock);
        int tapsBefore = taps.Count;
        decrypts = auth.Cipher.Decrypts;
        HostServiceTests.Raw locked = await RunRemote();
        check(locked.Result is not { Outcome: LaunchOutcome.Exited } && Read(valueFile) is null && taps.Count == tapsBefore + 1 && auth.Cipher.Decrypts == decrypts && !Shows(locked, Value),
            "convenience remote: a lock right after the tap at the authority decrypts nothing, delivers nothing and starts nothing on the host (" + locked.Result + " " + locked.Stderr.Trim() + ")");
    }

    // ---------- grant changes by a convenience key ----------

    internal static HttpClient Pages() => new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false, UseCookies = false }) { Timeout = TimeSpan.FromSeconds(60) };

    /// <summary>What a tap on the admin page at <paramref name="pageUrl" /> signs, read from its start data.</summary>
    private static byte[] PageChallenge(HttpClient pages, string pageUrl)
    {
        (_, string page) = TestState.Get(pages, pageUrl);
        using JsonDocument start = JsonDocument.Parse(Between(page, "<script type=\"application/json\" id=\"start\">", "</script>"));

        return ReuseBinding.Challenge(Base64Url.DecodeFromChars(start.RootElement.GetProperty("bind").GetString()!), 0);
    }

    private static string Scope(string session)
    {
        using JsonDocument doc = JsonDocument.Parse(session);

        return doc.RootElement.TryGetProperty("scope", out JsonElement scope) ? scope.GetString() ?? "" : "";
    }

    /// <summary>
    /// A convenience session (the phone, no PRF) changes grants with the phone's own tap, and real runs show the result: extend and replace leave the run covered with no tap (so the
    /// authority's row check and seal check accept a convenience signer), revoke leaves it uncovered. The phone's tap without user verification, over another challenge, or over the page of
    /// other parameters, and the session without a tap, change nothing. Renew, an unenrolled key, a replayed proof and the removal of the signer are in <see cref="GrantAuthorityTests" />.
    /// </summary>
    private static async Task GrantChanges(Action<bool, string> check, string root)
    {
        using Authority auth = new(root, queue: true);
        auth.OpenKeys();
        AuthorityStore store = auth.Machine.Deployment.Store;
        (string program, string valueFile) = ValueScript(auth.Work, "changes");
        (HostServiceTests.Raw made, _) = await PostQueued(auth, auth.Request(program), auth.Phone, 60, "v1/approve");
        GrantRecord? grant = store.Grants().FirstOrDefault(row => row.Usage == GrantUsage.Reusable && row.Status == "active");
        check(made.Result is { ExitCode: 0 } && grant is { Expires: not null }, "convenience grant changes: the phone approves a grant for 60 minutes (" + made.Result + " " + made.Stderr.Trim() + ")");
        if (grant is null)
        {
            return;
        }

        string id = grant.Id;
        string State() => store.FindGrant(id) is { } row ? row.Status + "/" + row.Revision + "/" + row.Expires?.ToString("O") : "none";
        async Task<(HostServiceTests.Raw Raw, int Taps)> Run()
        {
            File.Delete(valueFile);
            (HostServiceTests.Raw raw, List<Queued> asked) = await PostQueued(auth, auth.Request(program), auth.Phone);

            return (raw, asked.Count);
        }

        bool Covered((HostServiceTests.Raw Raw, int Taps) run) => run.Taps == 0 && run.Raw.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 4 } && Read(valueFile) == Value;

        using HttpClient pages = Pages();
        AdminBrowser phone = new(auth.Service, pages);
        check(await phone.SignInAsync(auth.Phone) && Scope((await phone.GetAsync("/api/v1/session")).Html) == "approval", "convenience grant changes: the phone signs in to a convenience (approval) session");

        string before = State();
        AdminTap noUv = await phone.OpAsync("grant-extend", auth.Phone, false, null, true, ("id", id), ("minutes", "30"));
        check(noUv.Link is not null && noUv.ApproveStatus == 403 && noUv.MutationStatus == 0 && State() == before, "convenience grant changes: the phone's tap without user verification changes nothing (" + noUv.ApproveStatus + ")");
        AdminTap otherChallenge = await phone.OpAsync("grant-extend", auth.Phone, true, challenge => SHA256.HashData(challenge), true, ("id", id), ("minutes", "30"));
        check(otherChallenge.Link is not null && otherChallenge.ApproveStatus is 403 or 400 && otherChallenge.MutationStatus == 0 && State() == before, "convenience grant changes: the phone's signature over another challenge changes nothing (" + otherChallenge.ApproveStatus + ")");
        AdminTap shown = await phone.OpAsync("grant-extend", null, true, null, true, ("id", id), ("minutes", "30"));
        byte[] shownChallenge = shown.Link is null ? [] : PageChallenge(pages, shown.PageUrl);
        AdminTap crossed = await phone.OpAsync("grant-extend", auth.Phone, true, _ => shownChallenge, true, ("id", id), ("minutes", "45"));
        (int cancelled, _) = await phone.SendAsync(HttpMethod.Delete, "/api/v1/authorizations/" + shown.AuthorizationId, null);
        check(shown.Link is not null && crossed.Link is not null && crossed.ApproveStatus is 403 or 400 && crossed.MutationStatus == 0 && cancelled == 200 && State() == before,
            "convenience grant changes: the phone's valid signature over the page for 30 minutes, sent to the page for 45 (other parameters), changes nothing, and the session's untapped page changes nothing (" + crossed.ApproveStatus + " " + cancelled + ")");

        AdminTap extended = await phone.OpAsync("grant-extend", auth.Phone, true, null, true, ("id", id), ("minutes", "30"));
        bool longer = extended.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => store.FindGrant(id) is { Revision: 2 } row && row.Expires == grant.Expires!.Value.AddMinutes(30));
        (HostServiceTests.Raw Raw, int Taps) afterExtend = await Run();
        check(longer && Covered(afterExtend), "convenience grant extend: the phone's tap extends the grant by 30 minutes, and the next run is covered with no tap (" + State() + ", " + afterExtend.Taps + " taps, " + afterExtend.Raw.Result + ")");

        AdminTap revoked = await phone.OpAsync("grant-revoke", auth.Phone, true, null, true, ("id", id));
        bool ended = revoked.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => store.FindGrant(id) is { Status: "revoked" });
        (HostServiceTests.Raw Raw, int Taps) afterRevoke = await Run();
        check(ended && afterRevoke.Taps == 1 && afterRevoke.Raw.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 4 }, "convenience grant revoke: the phone's tap revokes the grant, and the next run is not covered (it asks for a tap, which the phone gives once) (" + State() + ", " + afterRevoke.Taps + " taps)");

        GrantRecord? once = store.Grants().LastOrDefault(row => row.Usage == GrantUsage.Once && row.Status == "consumed");
        AdminTap replaced = once is null ? new AdminTap(0, null, null, 0, "", "") : await phone.OpAsync("grant-replace", auth.Phone, true, null, true, ("id", once.Id), ("indefinite", "true"));
        bool fresh = replaced.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => store.Grants().Any(row => row.Replaces == once!.Id && row.Status == "active"));
        (HostServiceTests.Raw Raw, int Taps) afterReplace = await Run();
        check(fresh && Covered(afterReplace), "convenience grant replace: the phone's tap replaces the used once-only grant with one with no end, and the next run is covered with no tap (" + replaced.ApproveStatus + ", " + afterReplace.Taps + " taps, " + afterReplace.Raw.Result + ")");
    }

    // ---------- every read of a convenience session ----------

    private static async Task Reads(Action<bool, string> check, string root)
    {
        using Authority auth = new(root, provider: true);
        auth.OpenKeys();
        (string program, string valueFile) = ValueScript(auth.Work, "reads");
        void TapOnce(LaunchEvent item)
        {
            if (item.Kind == LaunchEvent.ApprovalKind)
            {
                Tap(auth.Browser, item.Link!, auth.Phone);
            }
        }

        HostServiceTests.Raw native = await auth.Post(auth.Request(program), TapOnce);
        bool nativeRan = Read(valueFile) == Value;
        HostServiceTests.Raw mounted = await auth.Post(auth.Request(program, Mounted), TapOnce);
        check(native.Result is { ExitCode: 4 } && nativeRan && mounted.Result is { ExitCode: 4 } && Read(valueFile) == MountedValue, "convenience reads: a native and a provider-mounted value were delivered (the store and the provider cache hold them)");

        AuthorityStore store = auth.Machine.Deployment.Store;
        ProviderStore providers = new(store);
        string grantId = store.Grants().First().Id;
        string instanceId = providers.Instances().Single().Id.ToString("D");
        string mountId = providers.Mounts().Single().Id.ToString("D");
        using HttpClient pages = Pages();
        AdminBrowser phone = new(auth.Service, pages);
        check(await phone.SignInAsync(auth.Phone), "convenience reads: the phone signs in");
        string token = phone.SessionToken ?? "(none)";

        string? Fill(string template)
        {
            string path = template.Replace("{fingerprint}", auth.Machine.Fingerprint, StringComparison.Ordinal);
            string id = path.StartsWith(AdminApi.Prefix + "/grants/", StringComparison.Ordinal) ? grantId
                : path.StartsWith(AdminApi.Prefix + "/providers/", StringComparison.Ordinal) ? instanceId
                : path.StartsWith(AdminApi.Prefix + "/mounts/", StringComparison.Ordinal) ? mountId
                : path.StartsWith(AdminApi.Prefix + "/provider-value-refreshes/", StringComparison.Ordinal) ? Guid.Empty.ToString("D") : "{id}";
            path = path.Replace("{id}", id, StringComparison.Ordinal);

            return path.Contains('{', StringComparison.Ordinal) ? null : path;
        }

        List<ApiRoute> reads = [.. auth.Service.Admin.Api.Routes.Where(route => (route.Access is ApiAccess.Read or ApiAccess.Public) && route.OperationId != "getOpenApi")];
        check(reads.Count >= 15 && reads.Any(route => route.OperationId == "getGrantReview"), "convenience reads: the route table has the read routes, the grant review among them (" + reads.Count + ")");
        foreach (ApiRoute route in reads)
        {
            string? path = Fill(route.Template);
            if (path is null)
            {
                check(false, "convenience reads: no test value for a placeholder of " + route.Template);

                continue;
            }

            (int status, string body, _) = await phone.GetAsync(path);
            string[] leaked = [.. new[] { Value, MountedValue, token, "authenticatorData", "clientDataJSON" }.Where(item => body.Contains(item, StringComparison.Ordinal))];
            int expected = route.OperationId == "getProviderValueRefresh" ? 404 : 200;
            check(status == expected && leaked.Length == 0, "convenience reads: " + route.Method + " " + path + " answers " + expected
                + " and holds no secret value, session secret or proof (" + status + (leaked.Length > 0 ? ", leaked " + leaked.Length : "") + ")");
        }

        (_, string review, _) = await phone.GetAsync(AdminApi.Prefix + "/grants/" + grantId + "/review");
        using JsonDocument reviewed = JsonDocument.Parse(review);
        check(reviewed.RootElement.GetProperty("state").GetString() == "open" && reviewed.RootElement.GetProperty("text").GetString() is { Length: > 0 }, "convenience reads: the grant review is open to the convenience session while the authority is unlocked");
    }

    // ---------- every admin-only operation refuses a convenience tap ----------

    private static async Task<(int Prepared, int Proof)> InlineTap(AdminBrowser browser, TestAuthenticator who, string op, params (string Name, string Value)[] args)
    {
        (int prepared, string json) = await browser.PostAsync(AdminApi.Prefix + "/authorizations/inline", AdminBrowser.AuthorizationBody(op, args));
        if (prepared != 201)
        {
            return (prepared, 0);
        }

        using JsonDocument created = JsonDocument.Parse(json);
        using JsonDocument payload = JsonDocument.Parse(created.RootElement.GetProperty("proof").GetProperty("payload").GetString()!);
        byte[] bind = Base64Url.DecodeFromChars(payload.RootElement.GetProperty("bind").GetString()!);
        string proof = who.Assert(bind, browser.Origin, payload.RootElement.GetProperty("rpId").GetString()!, TestState.NextCount());
        (int accepted, _) = await browser.PostAsync(AdminApi.Prefix + "/authorizations/" + created.RootElement.GetProperty("id").GetString() + "/proof", JsonSerializer.Serialize(new { proof }));

        return (prepared, accepted);
    }

    /// <summary>Everything an admin-only operation could change in <paramref name="app" />.</summary>
    private static string AdminState(AdminApp app, FakePasskeys passkeys)
    {
        AuthorityStore store = app.Store;
        ProviderStore providers = app.Service.Providers!.Store;
        Manifest? manifest = TestState.Current(app.State);
        string machines = string.Join(";", store.Machines().Select(machine => string.Join(",", machine.Fingerprint, machine.Status, machine.SecurityRevision, machine.FriendlyName, machine.HostName, store.DiagnosticsSettings(machine.Fingerprint).Level)));
        string hostConfig = File.Exists(app.Machine.Deployment.HostConfig.FilePath) ? File.ReadAllText(app.Machine.Deployment.HostConfig.FilePath) : "";

        return string.Join('|', machines, hostConfig, store.ActiveKey()?.Fingerprint, store.AuditRetentionDays(), store.SessionTimeouts(), string.Join(",", store.Grants().Select(row => row.Id + "/" + row.Status + "/" + row.Revision)),
            app.Service.Lock.IsLocked, app.Service.Keys?.IsOpen, manifest?.Version, string.Join(",", manifest?.Keys.Select(key => key.Id + "/" + key.Name + "/" + key.Admin) ?? []), string.Join(",", manifest?.Secrets.Keys ?? []),
            string.Join(",", store.Invitations().Select(item => item.Id + "/" + item.Status)), string.Join(",", providers.Instances().Select(item => item.Id + "/" + item.Revision + "/" + item.Configuration + "/" + item.MaxStale)),
            string.Join(",", providers.Mounts().Select(item => item.Id + "/" + item.LogicalPath)), passkeys.Calls.Count);
    }

    /// <summary>
    /// Every operation of the API's own operation list that <see cref="OperationPolicy" /> keeps for admin keys (unlock and lock included): its passkey page and its inline challenge, made for an
    /// admin session (for the unlock, a browser with no session), refuse the convenience key's genuine tap, the authorization it leaves cannot be spent, and nothing changes. An authorization
    /// made for the admin session cannot be used by the convenience session. The route and operation gates of the convenience session itself are in <see cref="ApiTests" />.
    /// </summary>
    private static async Task AdminOnlyTaps(Action<bool, string> check, string root)
    {
        ProviderRegistry registry = new();
        registry.RegisterType("test", "1.0", () => new FakeProviderAdapter(), () => new FakeConfiguration());
        FakePasskeys passkeys = new();
        using AdminApp app = new(root, passkeys: passkeys, machineEndpoint: true, providers: registry);
        AdminBrowser admin = await app.SignedIn();
        AdminBrowser phone = app.Browser();
        check(await phone.SignInAsync(app.Phone) && Scope((await phone.GetAsync("/api/v1/session")).Html) == "approval", "convenience taps: the non-admin key signs in to a convenience session");
        string fp = app.Fingerprint;
        ProviderStore providers = app.Service.Providers!.Store;
        async Task<bool> Admin(string op, params (string Name, string Value)[] args)
        {
            app.Clock.Advance(TimeSpan.FromSeconds(13));

            return (await admin.OpAsync(op, app.Laptop, true, null, true, args)).MutationStatus == 200;
        }

        bool ready = await Admin("provider-add", ("name", "vault-one"), ("type", "test"), ("config", """{"label":"one"}"""), ("max-stale-seconds", "3600"))
            && await Admin("provider-add", ("name", "vault-two"), ("type", "test"), ("config", """{"label":"two"}"""), ("max-stale-seconds", "3600"));
        ProviderInstance? one = providers.Instances().FirstOrDefault(item => item.Name == "vault-one");
        ProviderInstance? two = providers.Instances().FirstOrDefault(item => item.Name == "vault-two");
        ready = ready && one is not null && two is not null && await Admin("mount-add", ("instance", one.Id.ToString("D")), ("kind", "tree"), ("path", "team"), ("base", "kv"));
        Mount? mount = providers.Mounts().FirstOrDefault();
        (CreatedInvitation? invitation, string? why) = app.Service.Pairing.Create("test admin");
        check(ready && mount is not null && invitation is not null, "convenience taps: two provider instances, a mount and a pairing invitation exist to act on (" + why + ")");
        if (!ready || one is null || two is null || mount is null || invitation is null)
        {
            return;
        }

        string machine = fp[..20];
        (string Name, string Value)[]? Arguments(string op) => op switch
        {
            AdminService.OpUnlock or AdminService.OpLock or "authority-key-rotate" or "authority-key-recover" or "passkey-enroll" or "store-key-rotate" or "pairing-create" => [],
            "set-audit-retention" => [("days", "7")],
            "set-session-timeouts" => [("idle", "20"), ("absolute", "600")],
            "machine-approve" => [("fingerprint", fp), ("name", "approved again")],
            "machine-disable" or "machine-enable" or "machine-untrust" or "machine-host-change" => [("fingerprint", machine)],
            "machine-trust" => [("fingerprint", machine), ("confirm", fp)],
            "machine-rename" => [("fingerprint", machine), ("name", "renamed")],
            AuthorityStore.SetMachineLogLevelOperation => [("fingerprint", machine), ("level", "debug")],
            "passkey-unenroll" => [("name", "phone")],
            "pairing-revoke" => [("id", invitation.Id)],
            "provider-add" => [("name", "vault-three"), ("type", "test"), ("config", """{"label":"three"}"""), ("max-stale-seconds", "60")],
            "provider-config" => [("id", one.Id.ToString("D")), ("revision", one.Revision.ToString(System.Globalization.CultureInfo.InvariantCulture)), ("config", """{"label":"changed"}""")],
            "provider-max-stale" => [("id", one.Id.ToString("D")), ("revision", one.Revision.ToString(System.Globalization.CultureInfo.InvariantCulture)), ("max-stale-seconds", "120")],
            "provider-remove" => [("id", two.Id.ToString("D")), ("revision", two.Revision.ToString(System.Globalization.CultureInfo.InvariantCulture))],
            "mount-add" => [("instance", one.Id.ToString("D")), ("kind", "single"), ("path", "other/NAME"), ("base", "kv/other")],
            "mount-remove" => [("id", mount.Id.ToString("D"))],
            _ => null,
        };

        void Prepare(string op)
        {
            switch (op)
            {
                case "machine-enable":
                    app.Store.Disable(fp, "test");
                    break;
                case "machine-trust":
                    app.Store.Untrust(fp, "test");
                    break;
                case "machine-host-change":
                    app.Store.RecordHostMismatch(fp, "other-host");
                    break;
                case AdminService.OpUnlock:
                    app.Service.Lock.Lock("test: the unlock is asked of a locked authority");
                    break;
            }
        }

        void Restore(string op)
        {
            switch (op)
            {
                case "machine-enable":
                    app.Store.Enable(fp, "test");
                    break;
                case "machine-trust":
                    app.Store.Trust(fp, fp, "test");
                    break;
            }
        }

        string[] adminOnly = [.. AdminApi.Operations.Select(item => item.Operation).Where(op => !OperationPolicy.AnyKey(op) && !OperationPolicy.IsSessionControl(op)).OrderBy(op => op == AdminService.OpUnlock ? 1 : 0)];
        check(adminOnly.Length >= 20 && adminOnly.Contains(AdminService.OpUnlock) && adminOnly.Contains(AdminService.OpLock) && AdminApi.Operations.Where(item => OperationPolicy.AnyKey(item.Operation) && !OperationPolicy.IsSessionControl(item.Operation)).Select(item => item.Operation).Order(StringComparer.Ordinal).SequenceEqual(["grant-extend", "grant-renew", "grant-replace", "grant-revoke"], StringComparer.Ordinal),
            "convenience taps: the operation list has every admin-only operation, unlock and lock among them, and exactly the four grant changes open to any key (" + adminOnly.Length + ")");
        foreach (string op in adminOnly)
        {
            // InteractiveProviderRefreshTests stages the provider batch before checking both proof routes.
            if (op is "provider-refresh-values" or "authenticator-add" or "authenticator-remove")
            {
                continue;
            }

            if (Arguments(op) is not { } args)
            {
                check(false, "convenience taps: no test arguments for the admin-only operation " + op + "; add them so it is not skipped");

                continue;
            }

            app.Clock.Advance(TimeSpan.FromSeconds(13));
            Prepare(op);
            AdminBrowser asker = op == AdminService.OpUnlock ? app.Browser() : admin;
            string before = AdminState(app, passkeys);
            AdminTap page = await asker.OpAsync(op, app.Phone, true, null, true, args);
            (HttpMethod method, string path, string body) = asker.MutationRequest(op, page.AuthorizationId, args);
            (int forced, _) = await asker.SendAsync(method, path, body);
            (int prepared, int proof) = await InlineTap(asker, app.Phone, op, args);
            await Task.Delay(100);
            string after = AdminState(app, passkeys);
            check(page.Link is not null && page.ApproveStatus is 403 or 400 && page.MutationStatus == 0 && forced == 403 && prepared == 201 && proof != 200 && after == before,
                "convenience taps: " + op + ": the convenience key's tap on its page and on its inline challenge is refused, its authorization cannot be spent, and nothing changes (page " + (page.Link is null ? "none: " + page.Error : page.ApproveStatus.ToString(System.Globalization.CultureInfo.InvariantCulture))
                + ", forced " + forced + ", inline " + prepared + "/" + proof + (after == before ? "" : ", state changed") + ")");
            Restore(op);
        }

        check(app.Service.Lock.IsLocked && !app.Service.Keys!.IsOpen, "convenience taps: the authority is still locked after the convenience key's unlock taps, with no key open");
        app.Service.Lock.Unlock(UnlockMethod.Seam);
        admin = await app.SignedIn();
        check(await phone.SignInAsync(app.Phone), "convenience taps: the convenience key signs in again after the lock");
        AdminTap owned = await admin.OpAsync("machine-rename", null, true, null, true, ("fingerprint", machine), ("name", "owned"));
        (int foreignProof, _) = await phone.PostAsync(AdminApi.Prefix + "/authorizations/" + owned.AuthorizationId + "/proof", JsonSerializer.Serialize(new { proof = "x" }));
        (HttpMethod ownedMethod, string ownedPath, string ownedBody) = phone.MutationRequest("machine-rename", owned.AuthorizationId, ("fingerprint", machine), ("name", "owned"));
        (int foreignMutation, _) = await phone.SendAsync(ownedMethod, ownedPath, ownedBody);
        (int foreignRead, _, _) = await phone.GetAsync(AdminApi.Prefix + "/authorizations/" + owned.AuthorizationId);
        check(owned.Link is not null && foreignProof == 404 && foreignMutation == 403 && foreignRead == 404 && app.Store.Find(fp)!.FriendlyName != "owned",
            "convenience taps: an authorization made for the admin session cannot be proved, spent or read by the convenience session (" + foreignProof + " " + foreignMutation + " " + foreignRead + ")");
    }
}

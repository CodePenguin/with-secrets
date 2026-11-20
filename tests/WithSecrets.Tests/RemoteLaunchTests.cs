using System.Text.RegularExpressions;
using System.Collections.Concurrent;
using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;

using Microsoft.Data.Sqlite;

using Serilog.Core;
using Serilog.Events;

namespace WithSecrets.Tests;

/// <summary>
/// Phase 5b: the authority holds the store. A host service whose authority is remote (the WSL path: WSL host service -> encrypted machine connection -> Windows host service and authority) shows no page
/// of its own, reads no store and holds no key: the approval page, the passkey tap, the PRF unlock and the decryption are the authority's, and the values come back only as a signed
/// <see cref="SecretsDelivery" /> inside the end-to-end encrypted session. The suite runs the real thing over real HTTP and WebSocket: an authority service with its machine endpoint (an embedded relay and the authority
/// endpoint), host services with their own machine identities in remote mode, the approval page driven by a test authenticator, and checks where the values are and are not (canary scans of the relay's raw frames, the
/// client's events, the logs, the audit trail and the host's disk), hostile and broken deliveries, a locked or vanished authority, grants without a page, the key held for a grant, and two independently enrolled hosts.
/// </summary>
internal static class RemoteLaunchTests
{
    private const string Real = "Remote-Canary-7e41c9d2b8a3";
    private const string RealOther = "Remote-Canary-OTHER-5d0a77e1";
    private const string Decoy = "DECOY-LOCAL-0f3b6c9a";
    private const string KeyCanary = "KEY-CANARY-PRF-31c7a0d9e5b2f48a";

    private static readonly TimeSpan Fast = TimeSpan.FromMilliseconds(100);

    // ---------- fixtures ----------

    private sealed class Capture : ILogEventSink
    {
        public ConcurrentQueue<LogEvent> Events { get; } = new();

        public void Emit(LogEvent logEvent) => Events.Enqueue(logEvent);

        public string Everything() => string.Join("\n", Events.Select(item => AppLog.Render(item) + " " + string.Join(" ", item.Properties.Select(pair => pair.Key + "=" + pair.Value))));
    }

    /// <summary>An approver that waits for the test and gives up when its page is cancelled (the authority locked, or the session ended).</summary>
    private sealed class PageWaiter(bool approve = true, bool approveAfterCancel = false) : IApprover
    {
        public ManualResetEventSlim Asked { get; } = new(false);

        public ManualResetEventSlim Release { get; } = new(false);

        public bool Cancelled { get; private set; }

        public ApprovalDecision Request(ApprovalRequest request) => Request(request, CancellationToken.None);

        public ApprovalDecision Request(ApprovalRequest request, CancellationToken cancel)
        {
            Asked.Set();
            try
            {
                WaitHandle.WaitAny([Release.WaitHandle, cancel.WaitHandle], TimeSpan.FromSeconds(30));
            }
            catch (ObjectDisposedException)
            {
                // Gone.
            }

            if (cancel.IsCancellationRequested && !approveAfterCancel)
            {
                Cancelled = true;

                return ApprovalDecision.Deny("cancelled");
            }

            return approve ? ApprovalDecision.Allow() : ApprovalDecision.Deny("test denied");
        }
    }

    private sealed class Auth : IDisposable
    {
        private Auth()
        {
        }

        public TestMachine Machine { get; private set; } = null!;

        public StateDatabase State { get; private set; } = null!;

        public HostServiceTests.CountingStore Store { get; private set; } = null!;

        public HostService Service { get; private set; } = null!;

        public AuthorityLock Gate { get; } = AuthorityLock.UnlockedForTests();

        public TestAuthenticator Laptop { get; } = TestAuthenticator.ES256();

        public ConcurrentQueue<IApprover> Approvers { get; } = new();

        public Func<IApprover> Maker { get; set; } = () => new FakeApprover(true);

        public string Url => "https://127.0.0.1:" + Service.MachinePort;

        public string Fingerprint => KeyIdentity.Fingerprint(Machine.Deployment.Keys.CurrentRecord().PublicKey);

        /// <summary>What a host is configured with to reach this authority: its address and its identity certificate.</summary>
        public RemoteAuthorityConfig Config => new(Url, MachineCertificates.FingerprintOf(Machine.Deployment.IdentityCertificate)!, Machine.Deployment.IdentityCertificate);

        public IReadOnlyList<ApprovalRequest> Pages => [.. Approvers.OfType<FakeApprover>().SelectMany(item => item.Requests)];

        public static Auth Create(string root, Func<IApprover>? approver = null, bool realPage = false, bool needsUnlock = false, TimeSpan? idle = null, Dictionary<string, string>? values = null)
        {
            Auth auth = new();
            string folder = Path.Combine(root, "auth-" + Guid.NewGuid().ToString("N")[..8], "state");
            auth.Machine = new TestMachine(folder, trusted: true, hostName: "windows-authority");
            auth.State = StateDatabase.InFolder(folder);
            TestState.Add(auth.State, auth.Laptop.Record("localhost", "laptop") with { Created = DateTimeOffset.UtcNow });
            auth.Store = new HostServiceTests.CountingStore(values ?? new Dictionary<string, string> { ["TOKEN"] = Real, ["OTHER_KEY"] = RealOther }, needsUnlock);
            if (approver is not null)
            {
                auth.Maker = approver;
            }

            auth.Service = HostService.Start(new HostServiceOptions
            {
                Lock = auth.Gate,
                UnlockProtection = new ReversibleProtection(),
                State = auth.State,
                Store = auth.Store,
                Deployment = auth.Machine.Deployment,
                Port = 0,
                TimeLimit = TimeSpan.FromSeconds(30),
                ApproverFactory = realPage ? null : (_, _) =>
                {
                    IApprover made = auth.Maker();
                    auth.Approvers.Enqueue(made);

                    return made;
                },
                MachineEndpoint = new MachineListenerOptions { Port = 0 },
                UseApprovalQueueForMachineLaunches = false,
                AuditUploadInterval = TimeSpan.FromMilliseconds(300),
            });

            return auth;
        }

        public void Dispose()
        {
            Service.Dispose();
            Machine.Deployment.Dispose();
        }
    }

    /// <summary>Forwards everything to the real remote authority and can change what a launch gets back.</summary>
    private sealed class LaunchProxy(RemoteAuthority inner) : IAuthority, IAuditSink, ILaunchAuthority, INoticeSource
    {
        public Func<LaunchAuthorize, Task<LaunchAnswer>?>? Override { get; set; }

        public Func<LaunchAnswer, LaunchAnswer>? Alter { get; set; }

        public List<LaunchAnswer> Seen { get; } = [];

        public async Task<LaunchAnswer> AuthorizeLaunchAsync(LaunchAuthorize message, Action<ApprovalLinkNotice> onLink, CancellationToken cancel)
        {
            if (Override?.Invoke(message) is { } forged)
            {
                return await forged;
            }

            LaunchAnswer real = await inner.AuthorizeLaunchAsync(message, onLink, cancel);
            Seen.Add(real);

            return Alter is null ? real : Alter(real);
        }

        public Task<AuthorityResponse> DecideAsync(MachineRequestEnvelope envelope, CancellationToken cancel = default) => inner.DecideAsync(envelope, cancel);

        public Task<byte[]> BeginEnrollmentAsync(CancellationToken cancel = default) => inner.BeginEnrollmentAsync(cancel);

        public Task<EnrollmentResult> EnrollAsync(EnrollmentRequest request, CancellationToken cancel = default) => inner.EnrollAsync(request, cancel);

        public Task<IReadOnlyList<KeyTransition>> KeyTransitionsAsync(string afterKeyFingerprint, CancellationToken cancel = default) => inner.KeyTransitionsAsync(afterKeyFingerprint, cancel);

        public Task<IReadOnlyList<PendingInvalidation>> PendingInvalidationsAsync(string machineFingerprint, CancellationToken cancel = default) => inner.PendingInvalidationsAsync(machineFingerprint, cancel);

        public Task AcknowledgeInvalidationAsync(string machineFingerprint, int revision, CancellationToken cancel = default) => inner.AcknowledgeInvalidationAsync(machineFingerprint, revision, cancel);

        public Task<GrantResponse> GrantAsync(GrantEnvelope envelope, CancellationToken cancel = default) => inner.GrantAsync(envelope, cancel);

        public Task<ReconcileResponse> ReconcileAsync(ReconcileEnvelope envelope, CancellationToken cancel = default) => inner.ReconcileAsync(envelope, cancel);

        public Task<IReadOnlyList<PendingGrantEvent>> PendingGrantEventsAsync(string machineFingerprint, CancellationToken cancel = default) => inner.PendingGrantEventsAsync(machineFingerprint, cancel);

        public Task AcknowledgeGrantEventAsync(string machineFingerprint, long sequence, CancellationToken cancel = default) => inner.AcknowledgeGrantEventAsync(machineFingerprint, sequence, cancel);

        public Task<AuditAck> UploadAsync(AuditBatch batch, CancellationToken cancel = default) => inner.UploadAsync(batch, cancel);

        public Task<bool> EnsureAuthorityKeyPinnedAsync(CancellationToken cancel) => inner.EnsureAuthorityKeyPinnedAsync(cancel);

        public Task<AuthorityNotices> PollAsync(string machineFingerprint, CancellationToken cancel) => inner.PollAsync(machineFingerprint, cancel);
    }

    private sealed class Host : IDisposable
    {
        private Host()
        {
        }

        public TestMachine Machine { get; private set; } = null!;

        public RemoteAuthority Remote { get; private set; } = null!;

        public LaunchProxy Proxy { get; private set; } = null!;

        public HostServiceTests.Rig Rig { get; private set; } = null!;

        public string Fingerprint => Machine.Fingerprint;

        public HostAuthorization Authorization => Rig.Service.Authorization;

        public string Folder => Path.GetDirectoryName(Rig.State.FilePath)!;

        /// <summary>A host service in its own folder with its own machine identity, paired with the authority (public data in host.json), enrolled Pending and, unless told otherwise, approved by the administrator at the authority.</summary>
        public static async Task<Host> Create(string root, Auth auth, string hostName, bool approve = true, bool startLocked = false)
        {
            Host host = new();
            host.Machine = new TestMachine(Path.Combine(root, "wsl-" + Guid.NewGuid().ToString("N")[..8], "state"), trusted: false, hostName: hostName);
            // The host pairs with the authority the way a machine does: an invitation from the authority, the pairing client, a Pending record (task M2); host.json then names the authority.
            (CreatedInvitation? invitation, string? why) = auth.Service.Pairing.Create("test admin");
            PairingResult paired = await PairingClient.RunAsync(new PairingClientOptions { Bundle = PairingBundle.TryParse(invitation?.Bundle ?? throw new InvalidOperationException("no invitation: " + why))!, MachineKey = host.Machine.MachineKey, IdentityCertificate = host.Machine.Deployment.IdentityCertificate, HostName = hostName, HostConfig = host.Machine.Deployment.HostConfig, MachineTls = host.Machine.Deployment.Tls });
            if (!paired.Ok)
            {
                throw new InvalidOperationException("the host could not pair: " + paired.Message);
            }

            RemoteAuthorityConfig config = host.Machine.Deployment.HostConfig.Load().Config!.Remote!;
            host.Remote = new RemoteAuthority(config, host.Machine.Deployment.Tls, host.Machine.Deployment.HostConfig) { RetryPause = TimeSpan.FromMilliseconds(50), Retries = 6 };
            host.Machine.Deployment.UseRemote(host.Remote);
            host.Proxy = new LaunchProxy(host.Remote);
            host.Machine.Deployment.Link = host.Proxy;

            if (approve)
            {
                TransitionResult result = auth.Machine.Deployment.Store.Approve(host.Machine.Fingerprint, hostName, "test admin");
                if (!result.Ok)
                {
                    throw new InvalidOperationException("the host could not be approved: " + result.Message);
                }
            }

            host.Rig = new HostServiceTests.Rig(root, new Dictionary<string, string> { ["TOKEN"] = Decoy, ["OTHER_KEY"] = Decoy + "-2" }, machine: host.Machine, auditInterval: TimeSpan.FromMilliseconds(300), startLocked: startLocked);

            return host;
        }

        public void Dispose() => Rig.Dispose();
    }

    private static string Scope(string name) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("scope " + name)));

    /// <summary>A script that writes the TOKEN it was given to a file beside it (the one place the value legitimately goes: the child's environment) and prints it (the service redacts it).</summary>
    private static (string Program, string ValueFile) ValueScript(HostServiceTests.Rig rig, string name)
    {
        string program = rig.Script(name, "echo %TOKEN%>\"%~dpn0.val\"\necho t=%TOKEN%\nexit /b 4", "printf '%s' \"$TOKEN\" > \"$0.val\"\necho \"t=$TOKEN\"\nexit 4");

        return (program, rig.FileOf(OperatingSystem.IsWindows() ? name + ".val" : name + ".sh.val"));
    }

    private static string? Read(string file) => File.Exists(file) ? File.ReadAllText(file).Trim() : null;

    private sealed record Ran(HostServiceTests.Raw Raw, string? Value, string Name, LaunchRequest Request)
    {
        public bool Started => Value is not null;

        public string Everything => string.Join("\n", Raw.Lines);
    }

    private static async Task<Ran> Run(Host host, string name, Action<LaunchEvent>? onEvent = null, string? id = null, string? existing = null)
    {
        (string program, string valueFile) = existing is null ? ValueScript(host.Rig, name) : (existing, host.Rig.FileOf(OperatingSystem.IsWindows() ? name + ".val" : name + ".sh.val"));
        File.Delete(valueFile);
        LaunchRequest request = HostServiceTests.Req(host.Rig, program, id: id);
        HostServiceTests.Raw raw = await HostServiceTests.Post(host.Rig, request, onEvent);

        return new Ran(raw, Read(valueFile), name, request);
    }

    private static string Programs(Host host, string name) => ValueScript(host.Rig, name).Program;

    // ---------- scanning for values ----------

    private static IEnumerable<byte[]> Forms(string canary)
    {
        byte[] plain = Encoding.UTF8.GetBytes(canary);
        yield return plain;
        yield return Encoding.ASCII.GetBytes(Convert.ToBase64String(plain));
        yield return Encoding.ASCII.GetBytes(Convert.ToHexString(plain));
        yield return Encoding.ASCII.GetBytes(Convert.ToHexString(plain).ToLowerInvariant());
        yield return Encoding.ASCII.GetBytes(Uri.EscapeDataString(canary));
        yield return Encoding.Unicode.GetBytes(canary);
    }

    private static bool Leaks(byte[] haystack, string canary) => Forms(canary).Any(form => haystack.AsSpan().IndexOf(form) >= 0);

    private static bool Leaks(string haystack, string canary) => Leaks(Encoding.UTF8.GetBytes(haystack), canary);

    private static IEnumerable<string> FilesUnder(string folder) => Directory.Exists(folder) ? Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories) : [];

    private static bool DiskLeaks(string folder, params string[] canaries)
    {
        SqliteConnection.ClearAllPools();
        foreach (string file in FilesUnder(folder))
        {
            byte[] bytes;
            try
            {
                using FileStream stream = new(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using MemoryStream copy = new();
                stream.CopyTo(copy);
                bytes = copy.ToArray();
            }
            catch (IOException)
            {
                continue;
            }

            if (canaries.Any(canary => Leaks(bytes, canary)))
            {
                return true;
            }
        }

        return false;
    }

    // ---------- the suite ----------

    public static async Task Run(Action<bool, string> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "ws-rlaunch-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);
        string logs = Path.Combine(root, "logs");
        Capture capture = new();
        AppLog.LogFolder = logs;
        AppLog.Tap = capture;
        AppLog.Configure(false);
        try
        {
            WireForms(check);
            await PageAtTheAuthority(check, root, capture, logs);
            await EncryptedEnvValues(check, root);
            await CodeChangesParity(check, root);
            await Refusals(check, root);
            await Deliveries(check, root);
            await HostileAuthorityInput(check, root);
            await LockedAndGone(check, root);
            await Grants(check, root);
            await ChangeDuringKeepTap(check, root);
            await RequestedRecordFailsClosed(check, root);
            await LockCancelsUncommitted(check, root);
            await GrantContents(check, root);
            await TwoHosts(check, root);
            await Exposure(check, root);
        }
        finally
        {
            AppLog.Close();
            AppLog.LogFolder = null;
            AppLog.Tap = null;
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

    // ---------- messages ----------

    private static void WireForms(Action<bool, string> check)
    {
        using SoftwareSigningKey machine = new();
        using SoftwareSigningKey authority = new();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        LaunchRequest request = IdentityTests.Sample("wire-1", now);
        PageContext context = new("/work/tool.sh", ["/work/tool.sh", "--x"], ["note"], new ScriptView(new string('A', 64), 12, "echo \"hi\"\n\ttab", "/work/tool.sh", Bom: true), null, Scope("wire"));
        LaunchAuthorize message = LaunchAuthorize.Create(request, Scope("wire"), context, "wsl-host", machine);
        check(RemoteWire.TryRead(RemoteWire.Write(message), out LaunchAuthorize? back) && back is not null && back.Verify(machine.PublicKey) && back.Context.Canonical() == context.Canonical() && back.Context.Script!.Text == context.Script!.Text, "wire: a launch-authorize message round-trips and its machine signatures verify");
        check(!(back! with { Context = back.Context with { Arguments = ["/work/tool.sh", "--y"] } }).Verify(machine.PublicKey) && !(back with { Context = back.Context with { FingerprintKey = Scope("other") } }).Verify(machine.PublicKey)
            && !(back with { Context = back.Context with { Script = back.Context.Script! with { Text = "echo evil" } } }).Verify(machine.PublicKey), "wire: a changed argument, fingerprint or script text in the page context fails the machine's signature");
        using SoftwareSigningKey other = new();
        check(!back.Verify(other.PublicKey) && !(back with { Use = GrantEnvelope.Create(GrantOps.Use, IdentityTests.Sample("wire-2", now), Scope("wire"), "wsl-host", machine) }).Verify(machine.PublicKey), "wire: another key, or a use envelope for another request, is refused");
        check(!RemoteWire.TryRead(RemoteWire.Write(message).Replace("\"decide\"", "\"decidee\"", StringComparison.Ordinal), out LaunchAuthorize? _) && !RemoteWire.TryRead(RemoteWire.Write(message)[..^1] + ",\"extra\":1}", out LaunchAuthorize? _), "wire: a missing or an unknown member is refused (strict)");

        byte[] one = Encoding.UTF8.GetBytes("value-one");
        byte[] two = Encoding.UTF8.GetBytes("value-two");
        SecretsDelivery delivery = SecretsDelivery.Create("wire-1", request.Digest(), "FP", SecretsDelivery.ViaPage, "", 3, now, now.AddSeconds(60), [new DeliveredValue("A", one), new DeliveredValue("B", two)], authority);
        check(delivery.Verify(authority.PublicKey) && !delivery.Verify(other.PublicKey), "wire: a delivery verifies under the signing key only");
        check(!delivery.Canonical().Contains("value-one", StringComparison.Ordinal) && !delivery.Canonical().Contains(Convert.ToBase64String(one), StringComparison.Ordinal), "wire: the signed text carries salted proofs, never the values");
        check(LaunchAnswer.TryRead(new LaunchAnswer(delivery, null).ToJson(), out LaunchAnswer? read) && read!.Delivery is { } parsed && parsed.Verify(authority.PublicKey) && Encoding.UTF8.GetString(parsed.Values.First(item => item.Name == "A").Value) == "value-one", "wire: a delivery round-trips with its values and its signature");
        SecretsDelivery swapped = delivery with { Values = [new DeliveredValue("A", two), new DeliveredValue("B", one)] };
        SecretsDelivery changed = delivery with { Values = [new DeliveredValue("A", Encoding.UTF8.GetBytes("value-ONE")), new DeliveredValue("B", two)] };
        SecretsDelivery added = delivery with { Values = [.. delivery.Values, new DeliveredValue("C", one)] };
        check(!swapped.Verify(authority.PublicKey) && !changed.Verify(authority.PublicKey) && !added.Verify(authority.PublicKey), "wire: swapped, changed or added values fail the signature");
        check(!(delivery with { RequestId = "wire-9" }).Verify(authority.PublicKey) && !(delivery with { RequestDigest = new string('0', 64) }).Verify(authority.PublicKey) && !(delivery with { MachineFingerprint = "OTHER" }).Verify(authority.PublicKey)
            && !(delivery with { SecurityRevision = 4 }).Verify(authority.PublicKey) && !(delivery with { Via = SecretsDelivery.ViaGrant }).Verify(authority.PublicKey) && !(delivery with { GrantId = "g1" }).Verify(authority.PublicKey), "wire: the request id, digest, machine, revision, how it was authorized and the grant are each bound by the signature");
        check(!LaunchAnswer.TryRead("{\"delivery\":{},\"refusal\":{}}", out _) && !LaunchAnswer.TryRead("{}", out _) && !LaunchAnswer.TryRead(new LaunchAnswer(delivery, null).ToJson().Replace("\"value\":\"", "\"value\":\"!", StringComparison.Ordinal), out _), "wire: an answer with both parts, none, or a value that is not base64 is refused");

        check(ApprovalLinkNotice.IsSafe("http://127.0.0.1:5000/a?b=c") && !ApprovalLinkNotice.IsSafe("javascript:alert(1)") && !ApprovalLinkNotice.IsSafe("http://user:pw@host/x") && !ApprovalLinkNotice.IsSafe("http://host/x\nInjected line") && !ApprovalLinkNotice.IsSafe("file:///etc/passwd") && !ApprovalLinkNotice.IsSafe(""), "wire: only a plain http or https link without user info or control characters is passed on to a client");
        check(ApprovalLinkNotice.TryRead(new ApprovalLinkNotice("r1", 2, "http://x/y").ToJson(), out ApprovalLinkNotice? notice) && notice is { RequestId: "r1", Sequence: 2 }, "wire: an approval link notice round-trips");
    }

    // ---------- the page at the authority ----------

    private static async Task PageAtTheAuthority(Action<bool, string> check, string root, Capture capture, string logs)
    {
        using Auth auth = Auth.Create(root, realPage: true);
        using Host host = await Host.Create(root, auth, "wsl-one");
        using HttpClient browser = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(30) };
        string page = "";
        string link = "";
        int status = 0;
        (string program, string valueFile) = ValueScript(host.Rig, "page");
        LaunchRequest request = HostServiceTests.Req(host.Rig, program);
        HostServiceTests.Raw raw = await HostServiceTests.Post(host.Rig, request, item =>
        {
            if (item.Kind == LaunchEvent.ApprovalKind)
            {
                link = item.Link ?? "";
                if (!Uri.TryCreate(link, UriKind.Absolute, out Uri? uri) || uri.Scheme is not ("http" or "https"))
                {
                    return;
                }

                string baseUrl = "http://127.0.0.1:" + uri.Port + uri.AbsolutePath;
                page = WebUtility.HtmlDecode(TestState.Get(browser, baseUrl).Body);
                (status, _) = TestState.Approve(browser, baseUrl, uri.GetLeftPart(UriPartial.Authority), uri.IdnHost, auth.Laptop);
            }
        });
        string? value = Read(valueFile);
        int approvalEvents = raw.Events.Count(item => item.Kind == LaunchEvent.ApprovalKind);

        check(approvalEvents == 1 && ApprovalLinkNotice.IsSafe(link), "page at the authority: the authority's page link reaches the client as the usual approval event, once (events " + approvalEvents + ", link length " + link.Length + ", raw events " + string.Join(" | ", raw.Events.Select(item => System.Text.Json.JsonSerializer.Serialize(item))) + ")");
        if (ApprovalLinkNotice.IsSafe(link))
        {
            Uri uri = new(link);
            check(uri.Port != host.Rig.Service.Port && uri.Port != auth.Service.MachinePort, "page at the authority: the link is the authority's own page, not the host's API or the machine endpoint");
        }
        else
        {
            check(false, "page at the authority: the link is the authority's own page, not the host's API or the machine endpoint (no valid link was delivered)");
        }
        check(page.Contains("service test", StringComparison.Ordinal) && page.Contains("TOKEN", StringComparison.Ordinal) && page.Contains("wsl-one", StringComparison.Ordinal) && !Leaks(page, Real) && !Leaks(page, Decoy), "page at the authority: the page shows the request (names) and which machine asks, never a value (page status " + status + ")");
        check(page.Contains(Path.GetFileName(program).TrimStart('.', '/'), StringComparison.Ordinal) && page.Contains("echo", StringComparison.Ordinal), "page at the authority: the script the host read is shown, so the person approves what will run");
        check(raw.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 4 } && raw.Stdout.Contains("t=[REDACTED]", StringComparison.Ordinal), "page at the authority: the passkey tap there releases the values, the program runs on the host and its exit code passes through (" + raw.Result + " " + raw.Stderr.Trim() + ")");
        check(value == Real, "values: the child's environment has the authority's value (the host's own store holds a different decoy)");
        check(host.Rig.Store.Reads == 0 && host.Rig.Approvers.IsEmpty && auth.Store.Reads == 1, "host: no store read, no local approval page or approver; the authority decrypted once (host reads " + host.Rig.Store.Reads + ", authority reads " + auth.Store.Reads + ")");

        bool uploaded = await HostServiceTests.WaitFor(() => auth.Machine.Deployment.Store.AuditHistory(new AuditQuery(Limit: 50)).Count >= 2);
        string audit = string.Join("\n", auth.Machine.Deployment.Store.AuditHistory(new AuditQuery(Limit: 50)).Select(item => item.Event.ToJson()));
        check(uploaded && audit.Contains(host.Fingerprint, StringComparison.Ordinal) && audit.Contains("requested", StringComparison.Ordinal), "audit: the host's signed events (the request is recorded before the authority is asked) (authorization, launch, execution) reached the authority over the mutually authenticated connection");
        check(host.Authorization.Vouched, "check-in: the authority vouches for the host after the remote check-in");

        check(!Leaks(string.Join("\n", raw.Lines), Real) && !Leaks(raw.Stdout + raw.Stderr, Real), "canary: the client's events and output carry no value");
        AppLog.Close();
        string logText = string.Join("\n", FilesUnder(logs).Select(file => File.ReadAllText(file))) + "\n" + capture.Everything();
        check(!Leaks(logText, Real) && !Leaks(logText, RealOther), "canary: the logs (file and events) carry no value");
        check(!Leaks(audit, Real) && !DiskLeaks(host.Folder, Real, RealOther, KeyCanary), "canary: the host's disk (state, authority.db, audit outbox, host.json) holds no value and no key");
        AppLog.Configure(false);

        // Cancelling the page (the person refuses) is a denial at the authority: no program, no decrypt.
        string before = Programs(host, "refused");
        Auth deny = Auth.Create(root, () => new FakeApprover(false));
        using Host denied = await Host.Create(root, deny, "wsl-denied");
        Ran refused = await Run(denied, "refused");
        check(refused.Raw.Result is { Outcome: LaunchOutcome.Denied, ExitCode: RunCommand.Denied } && !refused.Started && deny.Store.Reads == 0 && refused.Raw.Stderr.Contains("did not approve", StringComparison.Ordinal), "refusal: the person's refusal at the authority is a denial, nothing is decrypted and nothing runs (" + refused.Raw.Result + ")");
        _ = before;
        deny.Dispose();
    }

    /// <summary>
    /// A Dotenvx encrypted .env value through a remote authority: the request carries the ciphertext, the authority's page and fingerprint cover it, the key secret is delivered like
    /// any secret, and the host decrypts it. The same rules hold as in local mode (a protected name is refused, a swapped ciphertext is another request).
    /// </summary>
    private static async Task EncryptedEnvValues(Action<bool, string> check, string root)
    {
        const string Plain = "Remote-Decrypted-8842";
        (string publicKey, string privateKey) = DotenvxCipher.Instance.NewKeyPair();
        string cipher = DotenvxCipher.Instance.Encrypt(Plain, publicKey);
        using Auth auth = Auth.Create(root, values: new Dictionary<string, string> { ["DOTENV_PRIVATE_KEY"] = privateKey });
        using Host host = await Host.Create(root, auth, "wsl-enc");
        (string program, string valueFile) = ValueScript(host.Rig, "enc");
        string envFile = Path.Combine(host.Rig.Work, ".env");

        LaunchRequest Make(string text, string variable = "TOKEN") => HostServiceTests.Req(host.Rig, program, pairs: []) with
        {
            SecretNames = ["DOTENV_PRIVATE_KEY"],
            EnvFiles = [envFile],
            Encrypted = [new LaunchEncrypted(variable, envFile, "DOTENV_PRIVATE_KEY", text)],
        };

        File.Delete(valueFile);
        HostServiceTests.Raw raw = await HostServiceTests.Post(host.Rig, Make(cipher));
        string? value = Read(valueFile);
        check(raw.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 4 } && value == Plain && raw.Stdout.Contains("t=[REDACTED]", StringComparison.Ordinal), "remote encrypted: the host decrypts with the key the authority delivered, the child has the value and the output is redacted (" + raw.Result + " " + raw.Stderr.Trim() + ")");
        check(auth.Pages.Count == 1 && auth.Pages[0].SecretNames.SequenceEqual(["DOTENV_PRIVATE_KEY"]) && auth.Pages[0].Decrypts is [{ Variable: "TOKEN", KeySecret: "DOTENV_PRIVATE_KEY" }] && auth.Pages[0].Decrypts![0].CipherSha256 == DecryptItem.HashOf(cipher), "remote encrypted: the authority's page lists the key secret and the decrypt item with the hash of the ciphertext");
        string page = ApprovalSummary.BuildMessage(auth.Pages[0]);
        check(page.Contains("decrypt with secret DOTENV_PRIVATE_KEY: TOKEN (cipher sha256 " + DecryptItem.HashOf(cipher)[..12] + ")", StringComparison.Ordinal) && !Leaks(page, Plain) && !Leaks(page, privateKey) && !page.Contains(cipher["encrypted:".Length..], StringComparison.Ordinal), "remote encrypted: the page text has the decrypt line and no value, key or ciphertext");
        check(host.Rig.Store.Reads == 0 && auth.Store.Reads == 1 && !Leaks(string.Join("\n", raw.Lines), Plain) && !Leaks(string.Join("\n", raw.Lines), privateKey), "remote encrypted: the host read no store, the authority decrypted once, the client's events carry neither the value nor the key");
        check(!DiskLeaks(host.Folder, privateKey), "remote encrypted: the host's disk holds no key");

        // a protected name is refused at the host service before the authority is asked
        int pages = auth.Pages.Count;
        HostServiceTests.Raw refused = await HostServiceTests.Post(host.Rig, Make(cipher, "NODE_OPTIONS"));
        check(refused.Result is { Outcome: not LaunchOutcome.Exited } && auth.Pages.Count == pages && refused.Stderr.Contains("NODE_OPTIONS", StringComparison.Ordinal), "remote encrypted: an encrypted value for NODE_OPTIONS is refused, the authority is not asked (" + refused.Result + ")");

        // a swapped ciphertext is a different request: the authority's page shows the other hash
        string swapped = DotenvxCipher.Instance.Encrypt("https://attacker.example", publicKey);
        File.Delete(valueFile);
        await HostServiceTests.Post(host.Rig, Make(swapped));
        check(auth.Pages.Count == pages + 1 && auth.Pages[^1].Decrypts![0].CipherSha256 == DecryptItem.HashOf(swapped) && auth.Pages[^1].Decrypts![0].CipherSha256 != auth.Pages[0].Decrypts![0].CipherSha256, "remote encrypted: a swapped ciphertext is another request at the authority (its hash differs)");
    }

    /// <summary>
    /// M6 parity: ordinary code-loading variables of a remote host's launch show the same warning section on the authority's own page, before the approve
    /// control, with the visible values escaped, and a changed value is another request at the authority.
    /// </summary>
    private static async Task CodeChangesParity(Action<bool, string> check, string root)
    {
        const string Hostile = "<script>alert(1)</script> & <b>";
        using Auth auth = Auth.Create(root, realPage: true);
        using Host host = await Host.Create(root, auth, "wsl-code");
        using HttpClient browser = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(30) };
        (string program, _) = ValueScript(host.Rig, "codechg");
        string page = "";
        string raw = "";
        LaunchRequest request = HostServiceTests.Req(host.Rig, program, ordinary: new Dictionary<string, string> { ["NODE_OPTIONS"] = Hostile, ["HTTPS_PROXY"] = "http://proxy.example:3128", ["LD_LIBRARY_PATH"] = "/opt/lib", ["GIT_SSH_COMMAND"] = "ssh -i key", ["LOG_LEVEL"] = "quiet" });
        HostServiceTests.Raw result = await HostServiceTests.Post(host.Rig, request, item =>
        {
            if (item.Kind == LaunchEvent.ApprovalKind)
            {
                Uri uri = new(item.Link!);
                string baseUrl = "http://127.0.0.1:" + uri.Port + uri.AbsolutePath;
                raw = TestState.Get(browser, baseUrl).Body;
                page = WebUtility.HtmlDecode(raw);
                TestState.Approve(browser, baseUrl, uri.GetLeftPart(UriPartial.Authority), uri.IdnHost, auth.Laptop);
            }
        });
        int section = raw.IndexOf("<section class=\"warn\"", StringComparison.Ordinal);
        int pre = raw.IndexOf("<pre id=\"request\">", StringComparison.Ordinal);
        int approve = raw.IndexOf("id=\"approve\"", StringComparison.Ordinal);
        string sectionHtml = section < 0 ? "" : raw[section..raw.IndexOf("</section>", section, StringComparison.Ordinal)];
        check(result.Result is { Outcome: LaunchOutcome.Exited } && section > 0 && section < pre && pre < approve && Regex.Matches(raw, "class=\"warn\"").Count == 1, "remote code changes: the authority's page has one warning section, before the request text and the approve control (" + result.Result + ")");
        check(sectionHtml.Contains("This run changes how the program loads code or where it sends data", StringComparison.Ordinal) && sectionHtml.Contains("Your approval covers exactly these values.", StringComparison.Ordinal) && sectionHtml.Contains("<code class=\"name\">HTTPS_PROXY</code> = <code class=\"value\">http://proxy.example:3128</code>", StringComparison.Ordinal) && sectionHtml.Contains("loads code", StringComparison.Ordinal) && sectionHtml.Contains("changes the library path", StringComparison.Ordinal) && sectionHtml.Contains("routes network traffic", StringComparison.Ordinal) && sectionHtml.Contains("changes git behaviour", StringComparison.Ordinal), "remote code changes: the section carries the heading, each name with its visible value, a reason per class and the covers-exactly sentence, as in local mode");
        check(!sectionHtml.Contains("<script", StringComparison.Ordinal) && !sectionHtml.Contains("<b>", StringComparison.Ordinal) && sectionHtml.Contains("&lt;script&gt;alert(1)&lt;/script&gt; &amp; &lt;b&gt;", StringComparison.Ordinal) && page.Contains("LOG_LEVEL=quiet", StringComparison.Ordinal), "remote code changes: a value with HTML is escaped on the authority's page, and an ordinary variable stays in the text");
        string first = request.Digest();
        LaunchRequest other = HostServiceTests.Req(host.Rig, program, ordinary: new Dictionary<string, string> { ["NODE_OPTIONS"] = Hostile, ["HTTPS_PROXY"] = "http://attacker.example:3128", ["LD_LIBRARY_PATH"] = "/opt/lib", ["GIT_SSH_COMMAND"] = "ssh -i key", ["LOG_LEVEL"] = "quiet" }, id: request.RequestId);
        check(other.Digest() != first, "remote code changes: a changed value is another request (another digest)");
    }

    // ---------- refusals that need no page ----------

    private static async Task Refusals(Action<bool, string> check, string root)
    {
        using Auth auth = Auth.Create(root);
        using Host pending = await Host.Create(root, auth, "wsl-pending", approve: false);
        Ran notYet = await Run(pending, "pending");
        check(!notYet.Started && notYet.Raw.Result is { Outcome: LaunchOutcome.Denied } && notYet.Raw.Stderr.Contains("not approved yet", StringComparison.Ordinal) && auth.Pages.Count == 0 && auth.Store.Reads == 0, "machine: a Pending machine is refused at the authority before any page or any decryption (" + notYet.Raw.Stderr.Trim() + ")");

        auth.Machine.Deployment.Store.Approve(pending.Fingerprint, "wsl-pending", "test admin");
        Ran now = await Run(pending, "pending-ok");
        check(now.Started && now.Value == Real && now.Raw.Result is { ExitCode: 4 }, "machine: once the administrator approves it the same host runs, with no change on the host (" + now.Raw.Stderr.Trim() + ")");

        // An unknown secret name: refused by the authority without a page.
        int pagesBefore = auth.Pages.Count;
        (string program, string valueFile) = ValueScript(pending.Rig, "unknown");
        LaunchRequest missing = HostServiceTests.Req(pending.Rig, program, pairs: [("NOPE", "NO_SUCH_SECRET")]);
        HostServiceTests.Raw rawMissing = await HostServiceTests.Post(pending.Rig, missing);
        check(rawMissing.Result is { Outcome: LaunchOutcome.Denied } && rawMissing.Stderr.Contains("no secret with one of the requested names", StringComparison.Ordinal) && auth.Pages.Count == pagesBefore && Read(valueFile) is null, "secrets: a name the authority does not have is refused there, before any page (" + rawMissing.Stderr.Trim() + ")");

        // Disabled at the authority: the next launch is refused, the page is not shown.
        int pages = auth.Pages.Count;
        auth.Machine.Deployment.Store.Disable(pending.Fingerprint, "test admin");
        Ran disabled = await Run(pending, "disabled");
        check(!disabled.Started && disabled.Raw.Result is { Outcome: LaunchOutcome.Denied or LaunchOutcome.Cancelled } && auth.Pages.Count == pages, "machine: after the authority disables the machine a launch is refused and no page is shown (" + disabled.Raw.Stderr.Trim() + ")");
    }

    // ---------- the host's checks of a delivery ----------

    private static LaunchAuthorize Message(Host host, string id, string[]? names = null)
    {
        LaunchRequest request = HostServiceTests.Req(host.Rig, "./never", id: id);
        PageContext context = new(Path.Combine(host.Rig.Work, "never"), [], [], null, null, Scope("ctx " + id));

        return LaunchAuthorize.Create(request, Scope("scope " + id), context, host.Machine.HostName, host.Machine.MachineKey);
    }

    private static SecretsDelivery Sign(Auth auth, LaunchRequest request, string machine, int revision, DateTimeOffset issued, DateTimeOffset expires, string via = SecretsDelivery.ViaPage, string grant = "", string[]? names = null, ISigningKey? key = null, string? requestId = null, string? digest = null)
        => SecretsDelivery.Create(requestId ?? request.RequestId, digest ?? request.Digest(), machine, via, grant, revision, issued, expires, [.. (names ?? ["TOKEN"]).Select(name => new DeliveredValue(name, Encoding.UTF8.GetBytes(Real)))], key ?? auth.Machine.AuthorityKey(1));

    private static async Task Deliveries(Action<bool, string> check, string root)
    {
        using Auth auth = Auth.Create(root);
        using Host host = await Host.Create(root, auth, "wsl-delivery");
        HostAuthorization authorization = host.Authorization;
        DateTimeOffset now = DateTimeOffset.UtcNow;
        int revision = authorization.KnownRevision ?? 0;
        using SoftwareSigningKey stranger = new();

        async Task<(RemoteAuthorization Outcome, SecretsDelivery Delivery)> Try(string label, Func<LaunchRequest, SecretsDelivery> forge, LaunchRequest? request = null)
        {
            LaunchRequest launch = request ?? HostServiceTests.Req(host.Rig, "./never", id: "forged-" + Guid.NewGuid().ToString("N")[..10]);
            SecretsDelivery delivery = forge(launch);
            host.Proxy.Override = _ => Task.FromResult(new LaunchAnswer(delivery, null));
            RemoteAuthorization outcome = await authorization.AuthorizeRemoteAsync(launch, Scope("s " + label), new PageContext(Path.Combine(host.Rig.Work, "never"), [], [], null, null, Scope("c " + label)), _ => { }, CancellationToken.None);

            return (outcome, delivery);
        }

        bool Zeroed(SecretsDelivery delivery) => delivery.Values.All(value => value.Value.All(b => b == 0));

        (RemoteAuthorization good, SecretsDelivery goodDelivery) = await Try("good", launch => Sign(auth, launch, host.Fingerprint, revision, now, now.AddSeconds(60)));
        check(good.Ok && good.Values is not null && Encoding.UTF8.GetString(good.Values.Bytes("TOKEN")) == Real && good.Via == SecretsDelivery.ViaPage, "delivery: a correctly signed delivery for this request, machine and revision is accepted (control for the refusals below)");
        good.Values?.Dispose();
        check(good.Values is not null && good.Values.Names.Count == 1 && Zeroed(goodDelivery), "delivery: the accepted values are zeroed when their owner disposes them");

        async Task Refused(string label, Func<LaunchRequest, SecretsDelivery> forge, string why)
        {
            (RemoteAuthorization outcome, SecretsDelivery delivery) = await Try(label, forge);
            check(!outcome.Ok && outcome.Values is null && Zeroed(delivery), "delivery refused (" + why + "): nothing is built, every value is zeroed (" + outcome.Code + ")");
        }

        await Refused("request-id", launch => Sign(auth, launch, host.Fingerprint, revision, now, now.AddSeconds(60), requestId: "another-request"), "signed for another request id");
        await Refused("digest", launch => Sign(auth, launch, host.Fingerprint, revision, now, now.AddSeconds(60), digest: new string('A', 64)), "signed for another request digest");
        await Refused("machine", launch => Sign(auth, launch, "OTHERMACHINE", revision, now, now.AddSeconds(60)), "signed for another machine");
        await Refused("stranger", launch => Sign(auth, launch, host.Fingerprint, revision, now, now.AddSeconds(60), key: stranger), "signed by a key that is not the pinned authority key");
        await Refused("expired", launch => Sign(auth, launch, host.Fingerprint, revision, now.AddMinutes(-10), now.AddMinutes(-9)), "expired");
        await Refused("long", launch => Sign(auth, launch, host.Fingerprint, revision, now, now.AddMinutes(30)), "valid for too long");
        await Refused("future", launch => Sign(auth, launch, host.Fingerprint, revision, now.AddMinutes(30), now.AddMinutes(31)), "issued in the future");
        await Refused("extra", launch => Sign(auth, launch, host.Fingerprint, revision, now, now.AddSeconds(60), names: ["TOKEN", "OTHER_KEY"]), "more secrets than were asked for");
        await Refused("other-name", launch => Sign(auth, launch, host.Fingerprint, revision, now, now.AddSeconds(60), names: ["OTHER_KEY"]), "other secrets than were asked for");
        await Refused("tampered", launch =>
        {
            SecretsDelivery signed = Sign(auth, launch, host.Fingerprint, revision, now, now.AddSeconds(60));
            signed.Values[0].Value[0] ^= 1;

            return signed;
        }, "a value changed after signing");
        await Refused("bad-version", launch => Sign(auth, launch, host.Fingerprint, revision, now, now.AddSeconds(60)) with { ProtocolVersion = 2 }, "another protocol version");
        await Refused("bad-via", launch => Sign(auth, launch, host.Fingerprint, revision, now, now.AddSeconds(60), via: "nowhere"), "an unknown way of authorizing");
        if (revision >= 1)
        {
            await Refused("old-revision", launch => Sign(auth, launch, host.Fingerprint, revision - 1, now, now.AddSeconds(60)), "an older security revision than the host applied");
        }

        // A refusal that says approved, or an approval without values, is not a delivery.
        host.Proxy.Override = launch => Task.FromResult(new LaunchAnswer(null, AuthorityResponse.Create("any", new string('A', 64), host.Fingerprint, AuthorityDecision.Approved, ReasonCodes.Approved, revision, now, now.AddSeconds(60), auth.Machine.AuthorityKey(1))));
        LaunchRequest approvedNoValues = HostServiceTests.Req(host.Rig, "./never", id: "no-values");
        host.Proxy.Override = _ => Task.FromResult(new LaunchAnswer(null, AuthorityResponse.Create("no-values", approvedNoValues.Digest(), host.Fingerprint, AuthorityDecision.Approved, ReasonCodes.Approved, revision, now, now.AddSeconds(60), auth.Machine.AuthorityKey(1))));
        RemoteAuthorization claim = await authorization.AuthorizeRemoteAsync(approvedNoValues, Scope("claim"), new PageContext("/x", [], [], null, null, Scope("c")), _ => { }, CancellationToken.None);
        check(!claim.Ok && claim.Values is null, "delivery refused (an 'approved' answer without values): it is not treated as an approval");
        host.Proxy.Override = _ => Task.FromResult(new LaunchAnswer(null, AuthorityResponse.Create("forged", new string('B', 64), host.Fingerprint, AuthorityDecision.Denied, ReasonCodes.UserDenied, revision, now, now.AddSeconds(60), stranger)));
        RemoteAuthorization forgedDenial = await authorization.AuthorizeRemoteAsync(HostServiceTests.Req(host.Rig, "./never", id: "forged"), Scope("forged"), new PageContext("/x", [], [], null, null, Scope("c")), _ => { }, CancellationToken.None);
        check(!forgedDenial.Ok && forgedDenial.Code == "response-invalid", "refusal: a refusal not signed by the pinned key is reported as an answer that did not verify, not believed (" + forgedDenial.Code + ")");

        // A delivery for the same id twice (a replayed answer): the second is refused. Then an old delivery for a new request (a captured answer reused).
        LaunchRequest repeat = HostServiceTests.Req(host.Rig, "./never", id: "twice-" + Guid.NewGuid().ToString("N")[..8]);
        SecretsDelivery once = Sign(auth, repeat, host.Fingerprint, revision, now, now.AddSeconds(60));
        host.Proxy.Override = _ => Task.FromResult(new LaunchAnswer(once, null));
        PageContext pageContext = new("/x", [], [], null, null, Scope("twice"));
        RemoteAuthorization first = await authorization.AuthorizeRemoteAsync(repeat, Scope("twice"), pageContext, _ => { }, CancellationToken.None);
        first.Values?.Dispose();
        SecretsDelivery again = Sign(auth, repeat, host.Fingerprint, revision, now, now.AddSeconds(60));
        host.Proxy.Override = _ => Task.FromResult(new LaunchAnswer(again, null));
        RemoteAuthorization second = await authorization.AuthorizeRemoteAsync(repeat, Scope("twice"), pageContext, _ => { }, CancellationToken.None);
        check(first.Ok && !second.Ok && second.Code == ReasonCodes.RequestIdReused && Zeroed(again), "replay: a second delivery for a request id that was delivered is refused and zeroed (" + second.Code + ")");
        LaunchRequest reused = HostServiceTests.Req(host.Rig, "./never", id: "new-" + Guid.NewGuid().ToString("N")[..8]);
        host.Proxy.Override = _ => Task.FromResult(new LaunchAnswer(once, null));
        RemoteAuthorization captured = await authorization.AuthorizeRemoteAsync(reused, Scope("new"), pageContext, _ => { }, CancellationToken.None);
        check(!captured.Ok && captured.Values is null, "replay: a delivery captured for one request is refused for another");

        // A link notice that is not a plain link, or is for another request, never reaches the client.
        List<string> links = [];
        LaunchRequest linked = HostServiceTests.Req(host.Rig, "./never", id: "link-" + Guid.NewGuid().ToString("N")[..8]);
        host.Proxy.Override = _ =>
        {
            ILaunchAuthority self = host.Proxy;

            return Task.FromResult(new LaunchAnswer(null, AuthorityResponse.Create(linked.RequestId, linked.Digest(), host.Fingerprint, AuthorityDecision.Denied, ReasonCodes.UserDenied, revision, now, now.AddSeconds(60), auth.Machine.AuthorityKey(1))));
        };
        await authorization.AuthorizeRemoteAsync(linked, Scope("link"), pageContext, links.Add, CancellationToken.None);
        host.Proxy.Override = null;
    }

    // ---------- hostile input at the authority ----------

    private static async Task HostileAuthorityInput(Action<bool, string> check, string root)
    {
        using Auth auth = Auth.Create(root);
        using Host host = await Host.Create(root, auth, "wsl-hostile");
        using Host other = await Host.Create(root, auth, "wsl-other");
        DateTimeOffset now = DateTimeOffset.UtcNow;

        LaunchAuthorize Make(string id, Host who, Func<PageContext, PageContext>? tweakContext = null, bool signContextWithOtherKey = false)
        {
            LaunchRequest request = HostServiceTests.Req(host.Rig, "./tool", id: id);
            PageContext context = new(Path.Combine(host.Rig.Work, "tool"), [], [], null, null, Scope("hostile " + id));
            LaunchAuthorize made = LaunchAuthorize.Create(request, GrantEvidence.Scope(who.Fingerprint, context.FingerprintKey, context.Arguments), context, who.Machine.HostName, who.Machine.MachineKey);

            return tweakContext is null ? made : made with { Context = tweakContext(context) };
        }

        // Same session, same id twice: the second is refused outright, and the page was shown once.
        LaunchAuthorize first = Make("dup-" + Guid.NewGuid().ToString("N")[..8], host);
        LaunchAnswer answer = await host.Remote.AuthorizeLaunchAsync(first, _ => { }, CancellationToken.None);
        answer.Delivery?.Zero();
        int pagesAfterFirst = auth.Pages.Count;
        string code = "";
        try
        {
            await host.Remote.AuthorizeLaunchAsync(first, _ => { }, CancellationToken.None);
        }
        catch (RemoteRefusedException error)
        {
            code = error.Code;
        }

        check(answer.Delivery is not null && code == "request-id-reused" && auth.Pages.Count == pagesAfterFirst && auth.Store.Reads == 1, "replay: the same launch message again in the same session is refused with request-id-reused; no second page, no second decryption (" + code + ")");

        // Same message in a new session (a new connection with new keys): the authority's committed answer is not a new approval, so no values.
        using RemoteAuthority second = new(auth.Config, host.Machine.Deployment.Tls, host.Machine.Deployment.HostConfig) { RetryPause = Fast, Retries = 3 };
        string replayCode = "";
        try
        {
            await second.AuthorizeLaunchAsync(first, _ => { }, CancellationToken.None);
        }
        catch (RemoteRefusedException error)
        {
            replayCode = error.Code;
        }

        check(replayCode == "request-id-reused" && auth.Store.Reads == 1 && auth.Pages.Count == pagesAfterFirst, "replay: the same launch message on a new connection is refused and delivers nothing (the id is spent for this machine, whatever the connection) (" + replayCode + ")");

        // L5: the authority restarts (a new handler with nothing in memory): the same message is not delivered again, because the one-time record is durable.
        using AuthorityLaunchHandler restarted = new(auth.Machine.Deployment.Authority, auth.Machine.Deployment.Keys, auth.Machine.Deployment.Store, auth.Store, _ => new FakeApprover(true), null);
        LaunchAnswer afterRestart = await restarted.AuthorizeAsync(host.Fingerprint, first, _ => { }, CancellationToken.None);
        check(auth.Machine.Deployment.Store.WasDelivered(host.Fingerprint, first.Decide.Request.RequestId) && afterRestart.Delivery is null && afterRestart.Refusal is { ReasonCode: ReasonCodes.RequestIdReused } && auth.Store.Reads == 1, "replay: after an authority restart the same launch message is still not delivered again (the delivery-prepared record is durable)");

        // Another machine's signature inside this machine's session: wrong-machine.
        LaunchAuthorize foreign = Make("foreign-" + Guid.NewGuid().ToString("N")[..8], other);
        string foreignCode = "";
        try
        {
            await host.Remote.AuthorizeLaunchAsync(foreign, _ => { }, CancellationToken.None);
        }
        catch (RemoteRefusedException error)
        {
            foreignCode = error.Code;
        }

        check(foreignCode == "wrong-machine" && auth.Store.Reads == 1, "binding: a launch signed by another machine inside this machine's session is refused (wrong-machine)");

        // Context tampered after signing: bad signature, and nothing is asked or decrypted.
        int pages = auth.Pages.Count;
        LaunchAuthorize tampered = Make("tamper-" + Guid.NewGuid().ToString("N")[..8], host, context => context with { Arguments = ["--injected"] });
        LaunchAnswer tamperedAnswer = await host.Remote.AuthorizeLaunchAsync(tampered, _ => { }, CancellationToken.None);
        check(tamperedAnswer.Delivery is null && tamperedAnswer.Refusal is { ReasonCode: ReasonCodes.BadSignature } && auth.Pages.Count == pages && auth.Store.Reads == 1, "tamper: a page context changed after the machine signed it is refused with bad-signature; no page, no decryption");

        // A launch for another digest than the use envelope's.
        LaunchAuthorize good = Make("mix-" + Guid.NewGuid().ToString("N")[..8], host);
        LaunchAuthorize mixed = good with { Use = GrantEnvelope.Create(GrantOps.Use, HostServiceTests.Req(host.Rig, "./tool", id: "mix-other"), good.Use.ScopeKey, host.Machine.HostName, host.Machine.MachineKey) };
        LaunchAnswer mixedAnswer = await host.Remote.AuthorizeLaunchAsync(mixed, _ => { }, CancellationToken.None);
        check(mixedAnswer.Delivery is null && mixedAnswer.Refusal is { ReasonCode: ReasonCodes.BadSignature } && auth.Store.Reads == 1, "tamper: envelopes for two different requests in one message are refused (bad-signature)");

        // An id that does not name the request, and a garbage body.
        string idCode = "";
        try
        {
            using RemoteAuthority raw = new(auth.Config, host.Machine.Deployment.Tls, host.Machine.Deployment.HostConfig);
            MethodCall(raw);
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            idCode = error.GetType().Name;
        }

        _ = idCode;

        // A machine nobody enrolled: its certificate is well formed (it reaches the pairing route) but it is not a known machine, so it gets nothing else.
        using TestMachine unknown = new(Path.Combine(root, "unknown-" + Guid.NewGuid().ToString("N")[..6], "state"), trusted: false, hostName: "stranger");
        unknown.Deployment.HostConfig.SetRemote(unknown.Fingerprint, auth.Config);
        using RemoteAuthority stranger = new(auth.Config, unknown.Deployment.Tls, unknown.Deployment.HostConfig) { RetryPause = Fast, Retries = 3 };
        LaunchRequest strangerRequest = HostServiceTests.Req(host.Rig, "./tool", id: "stranger-" + Guid.NewGuid().ToString("N")[..8]);
        string strangerCode = "";
        try
        {
            await stranger.AuthorizeLaunchAsync(LaunchAuthorize.Create(strangerRequest, GrantEvidence.Scope(unknown.Fingerprint, Scope("c"), []), new PageContext("/x", [], [], null, null, Scope("c")), "stranger", unknown.MachineKey), _ => { }, CancellationToken.None);
        }
        catch (RemoteRefusedException error)
        {
            strangerCode = error.Code;
        }

        check(strangerCode == "unknown-machine" && auth.Store.Reads == 1, "machine: a machine the authority never enrolled gets unknown-machine, no page, no decryption (" + strangerCode + ")");
        _ = now;
    }

    private static void MethodCall(RemoteAuthority raw) => _ = raw;

    // ---------- locked, disconnected ----------

    private static async Task LockedAndGone(Action<bool, string> check, string root)
    {
        // Locked before the request.
        PageWaiter waiter = new();
        using (Auth auth = Auth.Create(root, () => waiter))
        {
            using Host host = await Host.Create(root, auth, "wsl-locked");
            auth.Gate.Lock("test");
            Ran locked = await Run(host, "locked");
            check(!locked.Started && locked.Raw.Result is { Outcome: LaunchOutcome.Denied or LaunchOutcome.Cancelled or LaunchOutcome.Failed } && auth.Store.Reads == 0 && !waiter.Asked.IsSet, "locked: a locked authority delivers nothing, shows no page and decrypts nothing (" + locked.Raw.Stderr.Trim() + ")");
            auth.Gate.Unlock(UnlockMethod.Seam);
            waiter.Release.Set();
            bool back = true;
            Ran again = await Run(host, "unlocked");
            check(back && again.Started && again.Value == Real, "locked: once unlocked the host is served again after a new handshake (" + again.Raw.Stderr.Trim() + ")");
        }

        // Locked while the page is open: the page is cancelled, nothing is decrypted, nothing runs.
        PageWaiter open = new();
        using (Auth auth = Auth.Create(root, () => open))
        {
            using Host host = await Host.Create(root, auth, "wsl-lock-open");
            Task<Ran> running = Run(host, "lock-open");
            bool asked = await HostServiceTests.WaitFor(() => open.Asked.IsSet);
            auth.Gate.Lock("test during the page");
            Ran ended = await running.WaitAsync(TimeSpan.FromSeconds(30));
            check(asked && !ended.Started && ended.Raw.Result is { Outcome: not LaunchOutcome.Exited } && auth.Store.Reads == 0 && open.Cancelled, "locked: locking the authority while its page is open cancels the page; nothing is decrypted and nothing runs (" + ended.Raw.Stderr.Trim() + ")");
            check(auth.Service.Launches!.HeldKeys == 0, "locked: no key is held after the lock");
        }

        // The host's session breaks while the page is open: the host launches nothing, and the authority never decrypts for a session that is gone.
        PageWaiter broken = new();
        using (Auth auth = Auth.Create(root, () => broken))
        {
            using Host host = await Host.Create(root, auth, "wsl-broken");
            Task<Ran> running = Run(host, "broken");
            bool asked = await HostServiceTests.WaitFor(() => broken.Asked.IsSet);
            host.Remote.Disconnect();
            Ran ended = await running.WaitAsync(TimeSpan.FromSeconds(30));
            broken.Release.Set();
            await Task.Delay(500);
            check(asked && !ended.Started && ended.Raw.Result is { Outcome: not LaunchOutcome.Exited } && auth.Store.Reads == 0, "disconnected: a session that breaks while the page is open ends the launch with nothing run, and the authority decrypts nothing afterwards (" + ended.Raw.Stderr.Trim() + ")");
        }

        // L1: a lock that the authority reports at the handshake is the "locked" outcome (exit 8), worded as unverified.
        PageWaiter idle = new();
        using (Auth auth = Auth.Create(root, () => idle))
        {
            using Host host = await Host.Create(root, auth, "wsl-locked-exit");
            await Run(host, "warm");
            auth.Gate.Lock("test");
            await Task.Delay(500);
            Ran locked = await Run(host, "locked-exit");
            check(!locked.Started && locked.Raw.Result is { ExitCode: LaunchClient.AuthorityLocked } && locked.Raw.Stderr.Contains("locked", StringComparison.Ordinal), "locked: a lock the authority reports at the handshake gives the locked outcome and exit code 8, not 'could not be asked' (" + locked.Raw.Result + " " + locked.Raw.Stderr.Trim() + ")");
        }

        // L2: in remote mode the host's own local authority (key ring, admin app) keeps a real lock that starts locked, and it does not gate a remote run.
        using (Auth auth = Auth.Create(root))
        {
            using Host host = await Host.Create(root, auth, "wsl-own-lock", startLocked: true);
            Ran served = await Run(host, "own-lock");
            check(host.Rig.Service.Lock.IsLocked && served.Started && served.Value == Real, "locked: a remote-mode host's own authority lock is a real lock that starts locked (no test seam), and the run is served by the remote authority anyway (" + host.Rig.Service.Lock.IsLocked + " " + served.Raw.Status + " " + served.Raw.Body.Trim() + ")");
            bool refused = false;
            try
            {
                host.Machine.Deployment.Keys.Current();
            }
            catch (AuthorityLockedException)
            {
                refused = true;
            }

            check(refused, "locked: the host's own local authority key cannot be used while that lock is locked");
        }

        // L3: a lock that arrives between the decryption and the send: the values are not sent, and the authority's record says so.
        using (Auth auth = Auth.Create(root))
        {
            using Host host = await Host.Create(root, auth, "wsl-lock-send");
            auth.Store.OnRead = () => auth.Gate.Lock("during the decryption");
            Ran ended = await Run(host, "lock-send");
            await Task.Delay(300);
            string events = string.Join(",", auth.Machine.Deployment.Store.Audit(500).Select(item => item.Event));
            check(!ended.Started && auth.Store.Reads == 1 && !events.Contains("delivery-sent", StringComparison.Ordinal), "locked: a lock between the decryption and the send sends nothing (the signing key is locked too) and no delivery is recorded as sent (" + events + ")");
        }

        // Revocation racing the release: the machine is disabled between the decryption and the send. The final authorization checkpoint at the authority holds the values back; nothing runs and no delivery is recorded as sent.
        using (Auth auth = Auth.Create(root))
        {
            using Host host = await Host.Create(root, auth, "wsl-revoke-send");
            auth.Store.OnRead = () => auth.Machine.Deployment.Store.Disable(host.Fingerprint, "test admin");
            Ran ended = await Run(host, "revoke-send");
            await Task.Delay(300);
            string events = string.Join(",", auth.Machine.Deployment.Store.Audit(500).Select(item => item.Event));
            check(!ended.Started && auth.Store.Reads == 1 && !events.Contains("delivery-sent", StringComparison.Ordinal) && !Leaks(ended.Everything, Real), "revocation race: a machine disabled between the decryption and the send gets no values (final checkpoint), nothing runs, and no delivery is recorded as sent (" + events + ")");
        }

        // L4: approved at the authority but the session ended: the record says approved-not-delivered, nothing is decrypted. The two orders in which the approval and the end of the session can meet, each made certain (no timing):
        // (a) the session ends first: the page's answer comes only once the authority has seen the end (the approver waits for the cancellation and nothing else);
        PageWaiter late = new(approve: true, approveAfterCancel: true);
        using (Auth auth = Auth.Create(root, () => late))
        {
            using Host host = await Host.Create(root, auth, "wsl-approved-late");
            Task<Ran> running = Run(host, "late");
            await HostServiceTests.WaitFor(() => late.Asked.IsSet);
            host.Remote.Disconnect();
            await running.WaitAsync(TimeSpan.FromSeconds(30));
            bool noted = await HostServiceTests.WaitFor(() => auth.Machine.Deployment.Store.Audit(500).Any(item => item.Event == "approved-not-delivered"), 30);
            string events = string.Join(",", auth.Machine.Deployment.Store.Audit(500).Select(item => item.Event));
            check(noted && auth.Store.Reads == 0 && !events.Contains("delivery-", StringComparison.Ordinal), "audit: approval that comes after the session ended is recorded as approved-not-delivered, nothing was decrypted (noted " + noted + ", reads " + auth.Store.Reads + ", events " + events + ")");
        }

        // (b) the approval is committed first and the session ends before delivery: the end is placed exactly between the durable decision and the delivery check, and the authority must have seen it before it goes on.
        PageWaiter first = new(approve: true);
        using (Auth auth = Auth.Create(root, () => first))
        {
            using Host host = await Host.Create(root, auth, "wsl-approved-then-ended");
            bool seen = false;
            AuthorityLaunchHandler.AfterApprovalCommitted = token =>
            {
                host.Remote.Disconnect();
                seen = SpinWait.SpinUntil(() => token.IsCancellationRequested, TimeSpan.FromSeconds(30));
            };
            try
            {
                Task<Ran> running = Run(host, "committed-then-ended");
                await HostServiceTests.WaitFor(() => first.Asked.IsSet);
                first.Release.Set();
                Ran ran = await running.WaitAsync(TimeSpan.FromSeconds(60));
                bool decided = auth.Machine.Deployment.Store.GetProcessed(ran.Request.RequestId)?.Response.Decision == AuthorityDecision.Approved;
                bool noted = await HostServiceTests.WaitFor(() => auth.Machine.Deployment.Store.Audit(500).Any(item => item.Event == "approved-not-delivered"), 30);
                string[] events = [.. auth.Machine.Deployment.Store.Audit(500).Select(item => item.Event)];
                check(seen && noted && auth.Store.Reads == 0 && auth.Service.Launches!.Decryptions == 0 && decided && !events.Any(item => item.StartsWith("delivery-", StringComparison.Ordinal)), "audit: an approval committed just before the session ended is recorded as approved-not-delivered and the decision itself stays durable (approved) and nothing is decrypted or prepared (seen " + seen + ", noted " + noted + ", reads " + auth.Store.Reads + ", events " + string.Join(",", events) + ")");
            }
            finally
            {
                AuthorityLaunchHandler.AfterApprovalCommitted = null;
            }
        }

        // The authority goes away entirely.
        Auth gone = Auth.Create(root);
        using Host orphan = await Host.Create(root, gone, "wsl-orphan");
        Ran ok = await Run(orphan, "before-gone");
        gone.Dispose();
        Ran away = await Run(orphan, "after-gone");
        check(ok.Started && !away.Started && away.Raw.Result is { Outcome: not LaunchOutcome.Exited } && orphan.Rig.Store.Reads == 0, "disconnected: with the authority gone the host runs nothing and falls back to nothing local (" + away.Raw.Stderr.Trim() + ")");
    }

    // ---------- grants and the held key ----------

    private static ApprovalEvidence Sign(TestAuthenticator who, string text, int minutes)
    {
        string nonce = "nonce-" + Guid.NewGuid().ToString("N")[..8];
        string full = text + "\n" + ApprovalSummary.IssuedLine(DateTimeOffset.UtcNow);

        return new ApprovalEvidence(nonce, full, who.Assert(ReuseBinding.Challenge(RequestBinding.Compute(nonce, full), minutes), TestState.Origin, "localhost", TestState.NextCount()));
    }

    /// <summary>The grant a person approves for this machine and this page's scope, made through the authority protocol (the CLI path for a remote host is not built; see the report).</summary>
    private static async Task<string> MakeGrant(Auth auth, Host host, ApprovalRequest page, int minutes, LaunchRequest actual, IEnumerable<string>? names = null)
    {
        string scope = GrantEvidence.Scope(host.Fingerprint, page.RequestId!, page.Arguments);
        LaunchRequest request = actual with { RequestId = "mk-" + Guid.NewGuid().ToString("N")[..10], Created = DateTimeOffset.UtcNow, Expires = DateTimeOffset.UtcNow.AddMinutes(5), SecretNames = [.. names ?? actual.SecretNames] };
        GrantEnvelope envelope = GrantEnvelope.Create(GrantOps.Approve, request, scope, host.Machine.HostName, host.Machine.MachineKey);
        int revision = auth.Machine.Deployment.Store.Find(host.Fingerprint)!.SecurityRevision;
        LocalAuthority authority = auth.Machine.Deployment.Authority;
        string approveText = string.Join((char)10, GrantEvidence.ApproveLines(revision, scope, contents: GrantEvidence.ContentsKey(request.SecretNames, request.Program, request.WorkingDirectory))) + (char)10 + ApprovalSummary.RequestIdPrefix + scope;
        using IDisposable offer = authority.Offer(request.RequestId, request.Digest(), () => ApprovalDecision.Allow("approved with passkey laptop", minutes, Sign(auth.Laptop, approveText, minutes)));
        GrantResponse made = await authority.GrantAsync(envelope);

        return made.Outcome == GrantOps.Granted ? made.GrantId : "";
    }

    private static async Task Grants(Action<bool, string> check, string root)
    {
        // A store that needs no unlock: a grant stands in for the page.
        using (Auth auth = Auth.Create(root))
        {
            using Host host = await Host.Create(root, auth, "wsl-grant");
            (string program, _) = ValueScript(host.Rig, "grant");
            Ran viaPage = await Run(host, "grant", existing: program);
            check(viaPage.Started && viaPage.Value == Real && auth.Pages.Count == 1, "grant: the first run goes through the page");
            string grantId = await MakeGrant(auth, host, auth.Pages[0], 60, viaPage.Request);
            check(grantId.Length > 0, "grant: a grant for this machine and exactly this request exists at the authority");
            Ran viaGrant = await Run(host, "grant", existing: program);
            check(viaGrant.Started && viaGrant.Value == Real && auth.Pages.Count == 1 && auth.Store.Reads == 2, "grant: the next run is delivered with no page (approver asked " + auth.Pages.Count + " time), decrypted at the authority (" + viaGrant.Raw.Stderr.Trim() + ")");
            check(host.Rig.Store.Reads == 0 && host.Rig.Approvers.IsEmpty, "grant: the host still reads no store and shows no page");
            bool recorded = await HostServiceTests.WaitFor(() => auth.Machine.Deployment.Store.AuditHistory(new AuditQuery(Limit: 100, Type: AuditEventTypes.Authorization)).Any(item => item.Event.Outcome == "granted"));
            check(recorded, "grant: the host's signed audit trail names the grant-authorized run");

            // A different command is not covered by the grant: the page is asked again.
            (string other, _) = ValueScript(host.Rig, "grant-other");
            Ran notCovered = await Run(host, "grant-other", existing: other);
            check(notCovered.Started && auth.Pages.Count == 2, "grant: another script is not covered; the page is shown for it");

            // Disabled at the authority: the grant no longer applies.
            auth.Machine.Deployment.Store.Disable(host.Fingerprint, "test admin");
            int reads = auth.Store.Reads;
            Ran after = await Run(host, "grant", existing: program);
            check(!after.Started && auth.Store.Reads == reads, "grant: when the authority disables the machine the grant stops (nothing decrypted, nothing run)");
        }

        // A store that needs the passkey's PRF: the first run under the grant needs one tap (the page says the key is kept), the authority holds the key for the grant, later runs need no tap.
        Func<IApprover> maker = () => new FakeApprover(true, unlock: () => new Unlock("cred", Encoding.UTF8.GetBytes(KeyCanary)));
        using (Auth auth = Auth.Create(root, maker, needsUnlock: true))
        {
            using Host host = await Host.Create(root, auth, "wsl-keyed");
            (string program, _) = ValueScript(host.Rig, "keyed");
            Ran page = await Run(host, "keyed", existing: program);
            check(page.Started && page.Value == Real && auth.Store.KeyedReads == 1 && auth.Service.Launches!.HeldKeys == 0, "key: an ordinary page approval releases the key for one run and the authority holds nothing");
            string grantId = await MakeGrant(auth, host, auth.Pages[0], 60, page.Request);
            Ran tap = await Run(host, "keyed", existing: program);
            ApprovalRequest tapPage = auth.Pages[^1];
            check(grantId.Length > 0 && tap.Started && tapPage.Heading == HeldStoreKeyProvider.KeepHeading && (tapPage.ExtraLines ?? []).Any(line => line.StartsWith("KEY HELD", StringComparison.Ordinal)) && auth.Service.Launches!.HeldKeys == 1, "key: the first run under the grant takes one tap whose page says the authority keeps the key for the grant, and it holds it (grant " + grantId + ", started " + tap.Started + ", heading " + tapPage.Heading + ", held " + auth.Service.Launches!.HeldKeys + ", " + tap.Raw.Stderr.Trim() + ")");
            int pages = auth.Pages.Count;
            Ran silent = await Run(host, "keyed", existing: program);
            check(silent.Started && silent.Value == Real && auth.Pages.Count == pages && auth.Store.KeyedReads == 3, "key: later runs under the grant need no tap and no page; the held key opens the store each time");
            byte[]? held = auth.Service.Launches!.HeldBytes(host.Fingerprint);
            check(held is not null && held.Any(b => b != 0), "key: the held key is in the authority's memory only");
            check(!DiskLeaks(host.Folder, Real, KeyCanary), "key: it is never on the host's disk and");

            auth.Machine.Deployment.Store.Disable(host.Fingerprint, "test admin");
            auth.Service.Launches!.Sweep();
            check(auth.Service.Launches!.HeldKeys == 0 && held!.All(b => b == 0), "key: when the authority disables the machine the held key is dropped and its bytes are zeroed");
        }

        using (Auth auth = Auth.Create(root, maker, needsUnlock: true))
        {
            using Host host = await Host.Create(root, auth, "wsl-keyed-lock");
            (string program, _) = ValueScript(host.Rig, "keyed2");
            Ran firstKeyed = await Run(host, "keyed2", existing: program);
            await MakeGrant(auth, host, auth.Pages[0], 60, firstKeyed.Request);
            await Run(host, "keyed2", existing: program);
            byte[]? held = auth.Service.Launches!.HeldBytes(host.Fingerprint);
            bool was = auth.Service.Launches!.HeldKeys == 1 && held!.Any(b => b != 0);
            auth.Gate.Lock("test");
            check(was && auth.Service.Launches!.HeldKeys == 0 && held!.All(b => b == 0), "key: locking the authority drops and zeroes the held key at once");
        }
    }

    // ---------- a change while the keep-the-key page is open ----------

    private sealed class HookedTap(Action during) : IApprover
    {
        public ApprovalDecision Request(ApprovalRequest request)
        {
            during();

            return ApprovalDecision.Allow("approved", 0, null, new Unlock("cred", Encoding.UTF8.GetBytes(KeyCanary)));
        }
    }

    private static async Task ChangeDuringKeepTap(Action<bool, string> check, string root)
    {
        foreach (string change in new[] { "disable", "untrust", "revoke" })
        {
            Action? during = null;
            using Auth auth = Auth.Create(root, () => during is null ? new FakeApprover(true, unlock: () => new Unlock("cred", Encoding.UTF8.GetBytes(KeyCanary))) : new HookedTap(during), needsUnlock: true);
            using Host host = await Host.Create(root, auth, "wsl-keep-" + change);
            (string program, _) = ValueScript(host.Rig, "keep" + change);
            Ran page = await Run(host, "keep" + change, existing: program);
            string grantId = await MakeGrant(auth, host, auth.Pages[0], 60, page.Request);
            check(page.Started && grantId.Length > 0, "keep tap (" + change + "): a run by page and a grant exist");

            // The next run under the grant needs the keep-the-key tap; while that page is open the machine is disabled or untrusted, or the grant is revoked.
            AuthorityStore store = auth.Machine.Deployment.Store;
            during = change switch
            {
                "disable" => () => store.Disable(host.Fingerprint, "test admin"),
                "untrust" => () => store.Untrust(host.Fingerprint, "test admin"),
                _ => () => Sql(auth, "UPDATE grants SET status = 'revoked' WHERE id = $id", ("$id", grantId)),
            };
            int reads = auth.Store.Reads;
            Ran tapped = await Run(host, "keep" + change, existing: program);
            check(!tapped.Started && auth.Store.Reads == reads && auth.Service.Launches!.HeldKeys == 0, "keep tap (" + change + "): the tap arrives after the change; nothing is decrypted, nothing is delivered or run, no key is kept");
        }
    }

    private static async Task LockCancelsUncommitted(Action<bool, string> check, string root)
    {
        using Auth auth = Auth.Create(root);
        using Host host = await Host.Create(root, auth, "wsl-lock-cancel");
        (string program, _) = ValueScript(host.Rig, "lockcancel");
        Ran ok = await Run(host, "lockcancel", existing: program);
        int revision = host.Rig.Service.Gate.Revision;
        auth.Gate.Lock("test");
        bool moved = await HostServiceTests.WaitFor(() => host.Rig.Service.Gate.Revision != revision, 20);
        check(ok.Started && moved, "lock: a lock at the authority ends its session with the host and invalidates the host's launch gate, so a launch that has its values but has not started is cancelled");
    }

    private static async Task RequestedRecordFailsClosed(Action<bool, string> check, string root)
    {
        using Auth auth = Auth.Create(root);
        using Host host = await Host.Create(root, auth, "wsl-requested");
        (string program, _) = ValueScript(host.Rig, "requested");
        Ran ok = await Run(host, "requested", existing: program);
        int pages = auth.Pages.Count;
        int reads = auth.Store.Reads;
        host.Rig.Service.Audit!.Outbox.Fault = point => throw new IOException("the disk is full (test)");
        Ran blocked = await Run(host, "requested", existing: program);
        host.Rig.Service.Audit!.Outbox.Fault = null;
        check(ok.Started && !blocked.Started && blocked.Raw.Result is { ExitCode: RunCommand.AuditError } && auth.Pages.Count == pages && auth.Store.Reads == reads, "remote audit: when the host cannot commit its 'requested' event the authority is not asked: no page, no decryption, no value on the wire, exit 5");
    }

    // ---------- what a grant covers (H1 of the review) ----------

    private static void Sql(Auth auth, string text, params (string Name, object? Value)[] args)
    {
        SqliteConnection.ClearAllPools();
        using SqliteConnection connection = new("Data Source=" + auth.Machine.Deployment.Store.FilePath + ";Pooling=False");
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = text;
        foreach ((string name, object? value) in args)
        {
            command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }

        command.ExecuteNonQuery();
        SqliteConnection.ClearAllPools();
    }

    private static async Task GrantContents(Action<bool, string> check, string root)
    {
        using Auth auth = Auth.Create(root);
        using Host host = await Host.Create(root, auth, "wsl-scope");
        (string program, _) = ValueScript(host.Rig, "scoped");
        Ran first = await Run(host, "scoped", existing: program);
        string grantId = await MakeGrant(auth, host, auth.Pages[0], 60, first.Request);
        check(grantId.Length > 0 && auth.Machine.Deployment.Store.FindGrant(grantId) is { SecretNames: "TOKEN" } row && GrantEvidence.Line(row.Evidence!.Text, GrantEvidence.ContentsPrefix) == GrantEvidence.ContentsKey(first.Request.SecretNames, first.Request.Program, first.Request.WorkingDirectory), "grant contents: the grant row keeps the exact names, program and folder, and the passkey-signed text carries their digest");

        // From here no page is approved: only a grant can release anything.
        auth.Maker = () => new FakeApprover(false);
        int pages = auth.Pages.Count;
        Ran again = await Run(host, "scoped", existing: program);
        check(again.Started && again.Value == Real && auth.Pages.Count == pages, "grant contents: the approved request is served by the grant with no page (control)");

        // Another name under the very same scope key: not covered. The host signs a request naming OTHER_KEY with the grant's scope key and the context of the approved run.
        LaunchRequest other = first.Request with { RequestId = "other-" + Guid.NewGuid().ToString("N")[..8], Created = DateTimeOffset.UtcNow, Expires = DateTimeOffset.UtcNow.AddMinutes(5), SecretNames = ["OTHER_KEY"], Mappings = [new LaunchMapping("OTHER_KEY", "OTHER_KEY")] };
        string scope = GrantEvidence.Scope(host.Fingerprint, auth.Pages[0].RequestId!, auth.Pages[0].Arguments);
        PageContext context = new(first.Request.Program, auth.Pages[0].Arguments, [], null, null, auth.Pages[0].RequestId!);
        int reads = auth.Store.Reads;
        LaunchAnswer answer = await host.Remote.AuthorizeLaunchAsync(LaunchAuthorize.Create(other, scope, context, host.Machine.HostName, host.Machine.MachineKey), _ => { }, CancellationToken.None);
        check(answer.Delivery is null && answer.Refusal is { Decision: AuthorityDecision.Denied } && auth.Store.Reads == reads && auth.Pages.Count == pages + 1, "grant contents: other secret names under the same scope key are not released by the grant: the page is asked instead (and refused here), nothing is decrypted (" + (answer.Delivery is null) + " " + answer.Refusal?.Decision + " " + answer.Refusal?.ReasonCode + " reads " + auth.Store.Reads + "/" + reads + " pages " + auth.Pages.Count + "/" + pages + ")");
        answer.Delivery?.Zero();

        // More names than approved, and a different program: the same.
        LaunchRequest more = other with { RequestId = "more-" + Guid.NewGuid().ToString("N")[..8], SecretNames = ["TOKEN", "OTHER_KEY"], Mappings = [new LaunchMapping("TOKEN", "TOKEN"), new LaunchMapping("OTHER_KEY", "OTHER_KEY")] };
        LaunchAnswer extra = await host.Remote.AuthorizeLaunchAsync(LaunchAuthorize.Create(more, scope, context, host.Machine.HostName, host.Machine.MachineKey), _ => { }, CancellationToken.None);
        LaunchRequest elsewhere = other with { RequestId = "prog-" + Guid.NewGuid().ToString("N")[..8], SecretNames = first.Request.SecretNames, Mappings = first.Request.Mappings, Program = first.Request.Program + "-other" };
        _ = pages;
        LaunchAnswer moved = await host.Remote.AuthorizeLaunchAsync(LaunchAuthorize.Create(elsewhere, scope, context, host.Machine.HostName, host.Machine.MachineKey), _ => { }, CancellationToken.None);
        check(extra.Delivery is null && moved.Delivery is null && auth.Store.Reads == reads && auth.Pages.Count == pages + 3, "grant contents: more names than approved, or another program, under the same scope key are not covered either");

        // A scope key that the request's own context does not make is refused before anything else.
        LaunchRequest lie = first.Request with { RequestId = "lie-" + Guid.NewGuid().ToString("N")[..8], Created = DateTimeOffset.UtcNow, Expires = DateTimeOffset.UtcNow.AddMinutes(5) };
        LaunchAnswer lied = await host.Remote.AuthorizeLaunchAsync(LaunchAuthorize.Create(lie, scope, context with { Arguments = ["--other"] }, host.Machine.HostName, host.Machine.MachineKey), _ => { }, CancellationToken.None);
        check(lied.Delivery is null && lied.Refusal is { ReasonCode: ReasonCodes.InvalidRequest } && auth.Store.Reads == reads, "grant contents: a scope key that is not the one the signed context makes is refused (invalid-request)");

        // A row changed after approval (a planted or edited row): the signed text no longer matches, so it is no grant.
        Sql(auth, "UPDATE grants SET secret_names = $names WHERE id = $id", ("$names", "OTHER_KEY, TOKEN"), ("$id", grantId));
        Ran widened = await Run(host, "scoped", existing: program);
        check(!widened.Started && true, "grant contents: a grant row whose names were widened is ignored (the signed digest no longer matches): nothing runs");
        Sql(auth, "UPDATE grants SET secret_names = $names WHERE id = $id", ("$names", "TOKEN"), ("$id", grantId));
        Ran restored = await Run(host, "scoped", existing: program);
        check(restored.Started, "grant contents: put back, the same row serves again (the refusal was the tamper)");
        Sql(auth, "UPDATE grants SET program = $program WHERE id = $id", ("$program", "evil"), ("$id", grantId));
        Ran moved2 = await Run(host, "scoped", existing: program);
        Sql(auth, "UPDATE grants SET program = $program WHERE id = $id", ("$program", first.Request.Program), ("$id", grantId));
        check(!moved2.Started, "grant contents: a grant row whose program was edited is ignored");
        string text = auth.Machine.Deployment.Store.FindGrant(grantId)!.Evidence!.Text;
        Sql(auth, "UPDATE grants SET evidence_text = $text WHERE id = $id", ("$text", text.Replace(GrantEvidence.ContentsPrefix, GrantEvidence.ContentsPrefix + "0", StringComparison.Ordinal)), ("$id", grantId));
        Ran forged = await Run(host, "scoped", existing: program);
        check(!forged.Started, "grant contents: a signed text edited to say other contents no longer verifies: no grant");
    }

    // ---------- two hosts, one authority ----------

    private static async Task TwoHosts(Action<bool, string> check, string root)
    {
        using Auth auth = Auth.Create(root);
        using Host first = await Host.Create(root, auth, "wsl-first");
        using Host second = await Host.Create(root, auth, "docker-second", approve: false);
        check(first.Fingerprint != second.Fingerprint && auth.Machine.Deployment.Store.Find(first.Fingerprint)!.Status == MachineStatus.Trusted && auth.Machine.Deployment.Store.Find(second.Fingerprint)!.Status == MachineStatus.Pending, "two hosts: each has its own machine identity and its own status at the one authority (first Trusted, second Pending)");

        Ran a = await Run(first, "two-a");
        Ran b = await Run(second, "two-b");
        check(a.Started && !b.Started && b.Raw.Stderr.Contains("not approved yet", StringComparison.Ordinal), "two hosts: the Pending host is refused while the Trusted host runs");
        check(auth.Pages.Count == 1 && (auth.Pages[0].ExtraLines ?? []).Any(line => line.Contains("wsl-first", StringComparison.Ordinal)), "two hosts: the page says which machine asks");

        auth.Machine.Deployment.Store.Approve(second.Fingerprint, "docker-second", "test admin");
        (string shared, _) = ValueScript(first.Rig, "shared");
        Ran onFirst = await Run(first, "shared", existing: shared);
        string grant = await MakeGrant(auth, first, auth.Pages[^1], 60, onFirst.Request);
        int pages = auth.Pages.Count;
        Ran grantedFirst = await Run(first, "shared", existing: shared);
        check(grant.Length > 0 && grantedFirst.Started && auth.Pages.Count == pages, "two hosts: a grant for the first host's scope lets the first host run with no page (" + grant + " " + grantedFirst.Started + " " + auth.Pages.Count + "/" + pages + " " + grantedFirst.Raw.Stderr.Trim() + ")");

        // The second host asks for an identical command line: the grant is the first machine's, so the page is shown for the second.
        (string sharedSecond, _) = ValueScript(second.Rig, "shared");
        Ran onSecond = await Run(second, "shared", existing: sharedSecond);
        check(onSecond.Started && onSecond.Value == Real && auth.Pages.Count == pages + 1 && (auth.Pages[^1].ExtraLines ?? []).Any(line => line.Contains("docker-second", StringComparison.Ordinal)), "two hosts: a grant is for one machine; the same command from the second host shows the page (" + onSecond.Started + " " + auth.Pages.Count + "/" + pages + " " + onSecond.Raw.Stderr.Trim() + ")");
        _ = onFirst;

        // Disabling one host leaves the other alone.
        auth.Machine.Deployment.Store.Disable(first.Fingerprint, "test admin");
        Ran off = await Run(first, "off");
        Ran stillOn = await Run(second, "still");
        check(!off.Started && stillOn.Started, "two hosts: disabling the first leaves the second running");
        check(first.Rig.Store.Reads == 0 && second.Rig.Store.Reads == 0 && first.Rig.Approvers.IsEmpty && second.Rig.Approvers.IsEmpty, "two hosts: neither host read a store or showed a page");
        check(!DiskLeaks(first.Folder, Real, RealOther) && !DiskLeaks(second.Folder, Real, RealOther), "two hosts: neither host's disk holds a value");
    }

    // ---------- what the machine endpoint serves ----------

    private static async Task Exposure(Action<bool, string> check, string root)
    {
        using Auth auth = Auth.Create(root);
        check(auth.Service.MachinePort != auth.Service.Port, "exposure: the machine endpoint is its own listener, not the API's");
        check(new MachineListenerOptions { Bind = IPAddress.Any }.Problem() is { } any && any.Contains("every interface", StringComparison.Ordinal) && new MachineListenerOptions { Bind = IPAddress.IPv6Any }.Problem() is not null, "exposure: it will not listen on 0.0.0.0 or [::]");
        check(new MachineListenerOptions { Bind = IPAddress.Loopback, Port = 8790 }.Problem() is null && new MachineListenerOptions { Port = 70000 }.Problem() is not null, "exposure: loopback and a port in range are fine, a port out of range is not");

        CliCommand? Parse(params string[] args) => CliArgs.Parse(args, out _);
        check(Parse("service", "--machine-port", "8790") is CliCommand.Service { MachinePort: 8790, MachineBind: "127.0.0.1" } && Parse("service") is CliCommand.Service { MachinePort: null }, "command line: service --machine-port N serves the machine endpoint on loopback; plain service serves none");
        check(Parse("service", "--machine-port", "8790", "--machine-bind", "0.0.0.0") is null && Parse("service", "--machine-cert", "x.pfx") is null && Parse("service", "--machine-bind", "127.0.0.1") is null, "command line: 0.0.0.0 is never accepted, a bind without a port is refused and there is no certificate flag (the certificate is the machine's own)");
        check(Parse("pair") is CliCommand.Pair && Parse("pair", "--debug") is CliCommand.Pair { Debug: true } && Parse("admin") is CliCommand.AdminApp && Parse("admin", "--service-port", "9000") is CliCommand.AdminApp, "command line: pair is a top-level command with no argument; bare admin is still the local app");
        check(Parse("pair", "wsp1;https://127.0.0.1:8790;x;y") is null && Parse("pair", "--code", "x") is null && Parse("admin", "https://127.0.0.1:8790") is null && Parse("admin", "list") is null, "command line: pair takes no invitation, code or address argument (a code on the command line is refused), and admin keeps no verbs and no ADDRESS");
        await Task.CompletedTask;
    }
}

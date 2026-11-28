using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ArcanaGuardian.Tests;

/// <summary>
/// Fix round 1 for the machine transport: one outstanding poll per machine, dead connections released by HTTP/2 keep-alive, launch ids pruned by expiry, clock-skew tolerance, a healthy connection not cut when its certificate
/// later expires, the connection table pruned, transient failures not remembered under an id, and the grant re-checked at the last step before values leave.
/// </summary>
internal static partial class RemoteAuthorityTests
{
    /// <summary>A TCP relay in front of the listener that can be told to swallow everything in both directions (a peer that vanished: no FIN, no reset, no answers).</summary>
    private sealed class BlackHole : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();
        private readonly List<TcpClient> _clients = [];
        private volatile bool _swallow;

        public BlackHole(int target)
        {
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _ = Task.Run(async () =>
            {
                while (!_stop.IsCancellationRequested)
                {
                    TcpClient near;
                    try
                    {
                        near = await _listener.AcceptTcpClientAsync(_stop.Token);
                    }
                    catch (Exception error) when (error is OperationCanceledException or ObjectDisposedException or SocketException)
                    {
                        return;
                    }

                    TcpClient far = new();
                    await far.ConnectAsync(IPAddress.Loopback, target);
                    lock (_clients)
                    {
                        _clients.Add(near);
                        _clients.Add(far);
                    }

                    _ = Pump(near, far);
                    _ = Pump(far, near);
                }
            });
        }

        public int Port { get; }

        public void Swallow() => _swallow = true;

        private async Task Pump(TcpClient from, TcpClient to)
        {
            byte[] buffer = new byte[16384];
            try
            {
                NetworkStream source = from.GetStream();
                NetworkStream sink = to.GetStream();
                while (true)
                {
                    int read = await source.ReadAsync(buffer, _stop.Token);
                    if (read == 0)
                    {
                        return;
                    }

                    if (!_swallow)
                    {
                        await sink.WriteAsync(buffer.AsMemory(0, read), _stop.Token);
                    }
                }
            }
            catch (Exception error) when (error is OperationCanceledException or IOException or ObjectDisposedException or InvalidOperationException or SocketException)
            {
                // The relay is closing.
            }
        }

        public void Dispose()
        {
            _stop.Cancel();
            _listener.Stop();
            lock (_clients)
            {
                foreach (TcpClient client in _clients)
                {
                    client.Dispose();
                }
            }

            _stop.Dispose();
        }
    }

    /// <summary>Answers every launch at once with a refusal (the listener is what is under test, not the authority's decision).</summary>
    private sealed class QuickRefusal(ISigningKey key) : IRemoteLaunchHandler
    {
        private int _calls;

        public int Calls => Volatile.Read(ref _calls);

        public Task<LaunchAnswer> AuthorizeAsync(string machineFingerprint, LaunchAuthorize message, Action<string> announceLink, CancellationToken cancel)
        {
            Interlocked.Increment(ref _calls);
            LaunchRequest request = message.Decide.Request;
            AuthorityResponse refusal = AuthorityResponse.Create(request.RequestId, request.Digest(), machineFingerprint, AuthorityDecision.Denied, "test", 1, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(1), key);

            return Task.FromResult(new LaunchAnswer(null, refusal));
        }

        public void Sent(string machineFingerprint, string requestId, bool sent)
        {
        }
    }

    /// <summary>Answers with a delivery by grant (unsigned: the listener checks what the delivery names, the host's check of the signature is another suite's business).</summary>
    private sealed class GrantDelivery(string initialGrant) : IRemoteLaunchHandler
    {
        private int _sent = -1;

        public int Revision { get; set; }

        public string GrantId { get; set; } = initialGrant;

        public int SentState => Volatile.Read(ref _sent);

        public Task<LaunchAnswer> AuthorizeAsync(string machineFingerprint, LaunchAuthorize message, Action<string> announceLink, CancellationToken cancel)
        {
            LaunchRequest request = message.Decide.Request;
            SecretsDelivery delivery = new(LaunchProtocol.Version, request.RequestId, request.Digest(), machineFingerprint, SecretsDelivery.ViaGrant, GrantId, Revision, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddSeconds(60), "key", [new DeliveredValue("TOKEN", [1, 2, 3])], new byte[64]);

            return Task.FromResult(new LaunchAnswer(delivery, null));
        }

        public void Sent(string machineFingerprint, string requestId, bool sent) => Volatile.Write(ref _sent, sent ? 1 : 0);
    }

    private static string LaunchBody(Peer host, string requestId, DateTimeOffset now)
    {
        LaunchRequest request = Request(requestId) with { Created = now, Expires = now.AddMinutes(5) };
        PageContext context = new("/work/tool.sh", [], [], null, null, new string('A', 64));
        LaunchAuthorize message = LaunchAuthorize.Create(request, GrantEvidence.Scope(host.Fingerprint, context.FingerprintKey, context.Arguments), context, "fix-host", host.Machine.MachineKey);

        return RemoteWire.Write(message);
    }

    private static async Task FixRound1(Action<bool, string> check, string root)
    {
        await OnePoll(check, root);
        await AbandonedConnection(check, root);
        await LaunchIds(check, root);
        await Skew(check, root);
        await ReleaseCheckpoint(check, root);
        await TransientFailures(check, root);
        await IdentityRenewal(check, root);
    }

    private static async Task OnePoll(Action<bool, string> check, string root)
    {
        using Net net = Net.Start(root);
        Peer host = net.Host("one-poll");
        using Raw first = new(net.Url, net.Identity, host.Tls.Current);
        using Raw second = new(net.Url, net.Identity, host.Tls.Current);
        string body = RemoteWire.WriteFingerprint(host.Fingerprint);

        Task<(int Status, WireMessage? Message, string Body, HttpResponseMessage Response)> older = first.Call(RemoteOps.Poll, "poll:older", body);
        await Until(() => net.Listener.InFlight == 1);
        Task<(int Status, WireMessage? Message, string Body, HttpResponseMessage Response)> newer = second.Call(RemoteOps.Poll, "poll:newer", body);
        (int status, WireMessage? message, _, _) = await older.WaitAsync(TimeSpan.FromSeconds(15));
        await Task.Delay(300);
        check(status == 409 && message is { Ok: false, Error: "superseded" } && !newer.IsCompleted && net.Listener.InFlight == 1, "one poll: a machine's new poll supersedes its older one (the older is answered 409 superseded and released) while the new one stays outstanding");

        // A third from the first connection supersedes the second in turn: the machine never holds more than one.
        Task<(int Status, WireMessage? Message, string Body, HttpResponseMessage Response)> third = first.Call(RemoteOps.Poll, "poll:third", body);
        (int secondStatus, WireMessage? secondMessage, _, _) = await newer.WaitAsync(TimeSpan.FromSeconds(15));
        await Task.Delay(300);
        check(secondStatus == 409 && secondMessage is { Error: "superseded" } && !third.IsCompleted && net.Listener.InFlight == 1, "one poll: and that one is superseded in turn; exactly one is ever outstanding");

        // Disabling the machine ends the outstanding one normally (not as superseded).
        net.Authority.Deployment.Store.Disable(host.Fingerprint, "test admin");
        (int endStatus, WireMessage? endMessage, _, _) = await third.WaitAsync(TimeSpan.FromSeconds(15));
        check(endStatus != 200 && endMessage is not { Error: "superseded" } && await Until(() => net.Listener.InFlight == 0), "one poll: the poll that is left ends for the machine's own reasons (here its disabling), not as superseded");
    }

    private static async Task AbandonedConnection(Action<bool, string> check, string root)
    {
        MachineListenerOptions options = new() { Port = 0, Http2PingDelay = TimeSpan.FromSeconds(1), Http2PingTimeout = TimeSpan.FromSeconds(1) };
        using Net net = Net.Start(root, options);
        Peer host = net.Host("abandoned");
        using BlackHole relay = new(net.Listener.Port);
        using Raw through = new("https://127.0.0.1:" + relay.Port, net.Identity, host.Tls.Current);
        string body = RemoteWire.WriteFingerprint(host.Fingerprint);

        Task<(int Status, WireMessage? Message, string Body, HttpResponseMessage Response)> poll = through.Call(RemoteOps.Poll, "poll:abandoned", body);
        bool held = await Until(() => net.Listener.InFlight == 1 && net.Listener.Connections == 1);
        relay.Swallow();
        bool released = await Until(() => net.Listener.InFlight == 0 && net.Listener.Connections == 0, 30);
        check(held && released, "keep-alive: a connection whose peer vanished (nothing answers its HTTP/2 pings) is closed by the listener, which releases the poll it held and its entry in the connection table (held " + held + ", in flight " + net.Listener.InFlight + ", connections " + net.Listener.Connections + ")");
        _ = poll.ContinueWith(_ => { }, TaskScheduler.Default);

        // The table does not keep ordinary closed connections either.
        using (Raw plain = new(net.Url, net.Identity, host.Tls.Current))
        {
            (int status, _, _, _) = await plain.Call(RemoteOps.PendingInvalidations, "pi-1", RemoteWire.WriteFingerprint(host.Fingerprint));
            check(status == 200 && net.Listener.Connections == 1, "connections: an open connection is in the table (" + net.Listener.Connections + ")");
        }

        check(await Until(() => net.Listener.Connections == 0), "connections: a closed connection is removed from the table (" + net.Listener.Connections + " left)");
    }

    private static async Task LaunchIds(Action<bool, string> check, string root)
    {
        TestClock clock = new();
        using Net host0 = Net.Start(root, new MachineListenerOptions { Port = 0, Clock = clock, MaxLaunchesPerMachine = 3 }, new QuickRefusal(new EcKey()), clock);
        Peer host = host0.Host("ids");
        using Raw raw = new(host0.Url, host0.Identity, host.Tls.Current, clock: clock);
        int Status(string id, DateTimeOffset now) => raw.Call(RemoteOps.LaunchAuthorize, "launch:" + id, LaunchBody(host, id, now)).GetAwaiter().GetResult().Status;

        int[] first = [Status("fix-a", clock.GetUtcNow()), Status("fix-b", clock.GetUtcNow()), Status("fix-c", clock.GetUtcNow())];
        int over = Status("fix-d", clock.GetUtcNow());
        int again = Status("fix-a", clock.GetUtcNow());
        check(first.All(status => status == 200) && over == 409 && again == 409, "launch ids: the count ceiling holds while the ids are live, and a live id is never usable twice");

        // Once the requests have expired the ids are forgotten: more launches work (the table is bounded by time) ...
        clock.Advance(TimeSpan.FromMinutes(7));
        int fresh = Status("fix-e", clock.GetUtcNow());
        int fresh2 = Status("fix-f", clock.GetUtcNow());
        int fresh3 = Status("fix-g", clock.GetUtcNow());
        check(fresh == 200 && fresh2 == 200 && fresh3 == 200, "launch ids: after the earlier requests have expired their ids are forgotten and the machine can launch again");

        // ... but an id of a request that is still live is not forgotten.
        int live = Status("fix-e", clock.GetUtcNow());
        clock.Advance(TimeSpan.FromMinutes(1));
        int liveLater = Status("fix-f", clock.GetUtcNow());
        check(live == 409 && liveLater == 409, "launch ids: an id whose request has not expired is never released for reuse");
    }

    private static async Task Skew(Action<bool, string> check, string root)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using EcKey identityKey = new();
        string fingerprint = KeyIdentity.Fingerprint(identityKey.PublicKey);
        byte[] identityDer = MachineCertificates.CreateIdentity(identityKey, now);
        using X509Certificate2 identity = X509CertificateLoader.LoadCertificate(identityDer);
        Spec Spec(TimeSpan start, TimeSpan length) => new() { Issuer = identity.SubjectName, Signer = identityKey.Key, Fingerprint = fingerprint, Start = start, Length = length };
        string? Judge(TimeSpan start, TimeSpan length, DateTimeOffset at)
        {
            using Forged forged = new(Spec(start, length), now);

            return MachineCertificates.ValidateLeaf(forged.Certificate, identityDer, at, fingerprint);
        }

        TimeSpan skew = MachineCertificates.Skew;
        check(skew == TimeSpan.FromMinutes(5), "skew: the tolerance is fixed at five minutes");
        check(Judge(skew - TimeSpan.FromMinutes(1), TimeSpan.FromHours(1), now) is null && Judge(skew + TimeSpan.FromMinutes(1), TimeSpan.FromHours(1), now) is { } early && early.Contains("not valid yet", StringComparison.Ordinal),
            "skew: a certificate that starts up to five minutes in the future (the issuer's clock is ahead) is accepted, one that starts later is refused");
        TimeSpan length = TimeSpan.FromHours(1);
        check(Judge(-length - TimeSpan.FromMinutes(1), length, now) is null && Judge(-length - skew - TimeSpan.FromMinutes(1), length, now) is { } late && late.Contains("expired", StringComparison.Ordinal),
            "skew: a certificate that expired up to five minutes ago is accepted, one that expired longer ago is refused");

        // A fresh certificate is backdated so a peer a little behind still accepts it.
        using TemporaryCertificate temporary = new(identityKey, identityDer, new TestClock());
        X509Certificate2 leaf = temporary.Current;
        check(MachineCertificates.ValidateLeaf(leaf, identityDer, now - TimeSpan.FromMinutes(4), fingerprint) is null, "skew: a fresh certificate is valid for a peer whose clock is four minutes behind");

        // An established connection is not cut when its certificate later passes its end; a new handshake with it is refused (beyond the tolerance).
        TestClock clock = new();
        using Net net = Net.Start(root, new MachineListenerOptions { Port = 0, Clock = clock }, null, clock);
        Peer host = net.Host("skew-host");
        X509Certificate2 old = host.Tls.Current;
        DateTimeOffset end = old.NotAfter.ToUniversalTime();
        using Raw established = new(net.Url, net.Identity, old);
        string Reconcile(string id) => RemoteWire.Write(ReconcileEnvelope.Create(id, "skew-host", clock.GetUtcNow(), host.Machine.MachineKey));
        (int before, _, _, _) = await established.Call(RemoteOps.Reconcile, "skew-1", Reconcile("rc-skew-1"));

        clock.Advance(end + TimeSpan.FromMinutes(4) - clock.GetUtcNow());
        using Raw inside = new(net.Url, net.Identity, old, clock: clock);
        (int insideStatus, _, _, _) = await inside.Call(RemoteOps.Reconcile, "skew-2", Reconcile("rc-skew-2"));
        check(before == 200 && insideStatus == 200, "skew: four minutes after its end the listener still accepts the client's certificate on a new connection");

        clock.Advance(TimeSpan.FromMinutes(3));
        using Raw beyond = new(net.Url, net.Identity, old, clock: clock);
        Exception? refused = await Thrown<Exception>(() => beyond.Call(RemoteOps.Reconcile, "skew-3", Reconcile("rc-skew-3")));
        (int stillStatus, WireMessage? stillMessage, _, _) = await established.Call(RemoteOps.Reconcile, "skew-4", Reconcile("rc-skew-4"));
        check(refused is not null && stillStatus == 200 && stillMessage is { Ok: true }, "skew: seven minutes after its end a new handshake with the expired certificate is refused, while the established connection (healthy) is not interrupted and keeps being served");
    }

    private static async Task ReleaseCheckpoint(Action<bool, string> check, string root)
    {
        TestClock clock = new();
        MachineListenerOptions options = new() { Port = 0, Clock = clock };
        GrantDelivery bound = new("grant-1");
        using Net net = Net.Start(root, options, bound, clock);
        Peer host = net.Host("release-host");
        bound.Revision = net.Authority.Deployment.Store.Find(host.Fingerprint)!.SecurityRevision;
        using Raw raw = new(net.Url, net.Identity, host.Tls.Current, clock: clock);

        net.Authority.Deployment.Store.AddGrant("grant-1", host.Fingerprint, "scope", clock.GetUtcNow().AddMinutes(10));
        (int okStatus, _, string okBody, _) = await raw.Call(RemoteOps.LaunchAuthorize, "launch:rel-1", LaunchBody(host, "rel-1", clock.GetUtcNow()));
        check(okStatus == 200 && okBody.Contains("\"delivery\"", StringComparison.Ordinal) && bound.SentState == 1, "release: a delivery by a grant that is still usable is sent");

        // The grant ends between the authority's decision and the release: the final checkpoint stops the values.
        options.BeforeRelease = () => clock.Advance(TimeSpan.FromMinutes(30));
        (int goneStatus, _, string goneBody, _) = await raw.Call(RemoteOps.LaunchAuthorize, "launch:rel-2", LaunchBody(host, "rel-2", clock.GetUtcNow()));
        check(!goneBody.Contains("\"delivery\"", StringComparison.Ordinal) && goneBody.Contains("authorization-changed", StringComparison.Ordinal) && bound.SentState == 0 && goneStatus is 200 or 409 or 403, "release: a grant that ended just before the release stops the values (authorization-changed), and the authority is told they were not sent");

        // Gone altogether (deleted row): the same.
        options.BeforeRelease = null;
        bound.GrantId = "grant-missing";
        (_, _, string missingBody, _) = await raw.Call(RemoteOps.LaunchAuthorize, "launch:rel-3", LaunchBody(host, "rel-3", clock.GetUtcNow()));
        check(!missingBody.Contains("\"delivery\"", StringComparison.Ordinal) && missingBody.Contains("authorization-changed", StringComparison.Ordinal) && bound.SentState == 0, "release: a delivery that names a grant the authority no longer has stops too");
    }

    private static async Task TransientFailures(Action<bool, string> check, string root)
    {
        using Net net = Net.Start(root);
        AuthorityLock gate = AuthorityLock.UnlockedForTests();
        net.Authority.Deployment.Keys.LockState = gate;
        Peer host = net.Host("transient");
        using Raw raw = new(net.Url, net.Identity, host.Tls.Current);

        // The authority locks while a decision is being made: the machine is told "locked", and the same id works once it is unlocked (the failure was not kept under it).
        LaunchRequest request = Request("req-transient-1");
        MachineRequestEnvelope envelope = MachineRequestEnvelope.Create(request, "transient", host.Machine.MachineKey);
        int locks = 0;
        using IDisposable offer = net.Authority.Deployment.Authority.Offer(request.RequestId, request.Digest(), () =>
        {
            if (Interlocked.Increment(ref locks) == 1)
            {
                gate.Lock("test");
            }

            return ApprovalDecision.Allow();
        });
        (_, WireMessage? failed, _, _) = await raw.Call(RemoteOps.Decide, "decide-transient", RemoteWire.Write(envelope));
        gate.Unlock(UnlockMethod.Seam);
        (_, WireMessage? retried, _, _) = await raw.Call(RemoteOps.Decide, "decide-transient", RemoteWire.Write(envelope));
        check(failed is { Ok: false, Error: "locked" } && retried is not { Error: "locked" }, "transient: a failure caused by the authority locking mid-operation is not remembered under the request id (failed " + failed?.Error + ", then " + (retried?.Ok == true ? "ok" : retried?.Error) + ")");
    }
    private static async Task IdentityRenewal(Action<bool, string> check, string root)
    {
        TestClock clock = new();
        using Net net = Net.Start(root, null, null, clock);
        Peer host = net.Host("renewer");
        Peer pending = net.Host("not-approved", approve: false);
        host.Machine.Deployment.UseRemote(host.Remote);
        AuthorityStore store = net.Authority.Deployment.Store;
        byte[] original = host.Machine.Deployment.IdentityCertificate;
        check(!await host.Machine.Deployment.RenewIdentityIfDueAsync() && store.Certificate(host.Fingerprint)!.AsSpan().SequenceEqual(original), "renewal: a certificate with plenty of validity left is not renewed");

        // The authority's own checks: the same key only, and Trusted machines only; the stored certificate is untouched by a refusal.
        using EcKey stranger = new();
        byte[] foreign = MachineCertificates.CreateIdentity(stranger, clock.GetUtcNow());
        byte[] sameKey = MachineCertificates.CreateIdentity(host.Machine.MachineKey, clock.GetUtcNow());
        check(store.RenewCertificate(host.Fingerprint, foreign) is not null && store.RenewCertificate(host.Fingerprint, [1, 2, 3]) is not null && store.RenewCertificate(pending.Fingerprint, MachineCertificates.CreateIdentity(pending.Machine.MachineKey, clock.GetUtcNow())) is not null && store.Certificate(host.Fingerprint)!.AsSpan().SequenceEqual(original),
            "renewal: a certificate for another key, garbage, or a machine that is not Trusted is refused and the stored certificate stays");

        // Due: the authority hears of the new certificate over the authenticated connection first; the machine switches only after that.
        clock.Advance(TimeSpan.FromDays(3640));
        net.Authority.Deployment.Store.Disable(host.Fingerprint, "test admin");
        bool whileDisabled = await host.Machine.Deployment.RenewIdentityIfDueAsync();
        check(!whileDisabled && host.Machine.Deployment.IdentityCertificate.AsSpan().SequenceEqual(original) && store.Certificate(host.Fingerprint)!.AsSpan().SequenceEqual(original), "renewal: a machine the authority does not accept (Disabled) cannot renew, and nothing changes on either side");
        net.Authority.Deployment.Store.Enable(host.Fingerprint, "test admin");
        int revision = store.Find(host.Fingerprint)!.SecurityRevision;
        bool renewed = await host.Machine.Deployment.RenewIdentityIfDueAsync();
        byte[] now = host.Machine.Deployment.IdentityCertificate;
        byte[] onDisk = File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(host.Machine.Deployment.HostConfig.FilePath)!, MachineIdentityFile.FileName));
        check(renewed && !now.AsSpan().SequenceEqual(original) && store.Certificate(host.Fingerprint)!.AsSpan().SequenceEqual(now) && onDisk.AsSpan().SequenceEqual(now) && MachineCertificates.FingerprintOf(now) == host.Fingerprint, "renewal: a due certificate is renewed with the same key (same fingerprint): the authority stores it first, then the machine's file is replaced");
        check(store.Audit().Any(entry => entry.Event == "machine-identity-renewed") && store.Find(host.Fingerprint) is { Status: MachineStatus.Trusted } trusted && trusted.SecurityRevision == revision, "renewal: the renewal is audited at the authority and does not change the machine's status or security revision");
        check(!await host.Machine.Deployment.RenewIdentityIfDueAsync(), "renewal: it is not renewed again until it is due again");
    }
}

using System.Net.Security;
using System.Text;

using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>
/// Phase 5: the remote authority protocol and the relay. The handshake (mutual authentication over a transcript, HKDF session keys, AES-GCM with sequence numbers), the
/// canonical messages, replay and tampering at every layer, reconnect with new keys, relay restart, idempotent duplicates, invalidation delivery, a locked authority, the
/// relay's blindness (a capture scanned for canary values), and a launch through host service -> RemoteAuthority -> relay -> authority endpoint -> the same local authority.
/// </summary>
internal static class RemoteAuthorityTests
{
    private static readonly TimeSpan Fast = TimeSpan.FromMilliseconds(100);

    public static async Task Run(Action<bool, string> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "ws-remote-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);
        try
        {
            Handshake(check);
            Frames(check);
            Config(check);
            await Operations(check, root);
            await Duplicates(check, root);
            await Misbinding(check, root);
            await Reconnect(check, root);
            await Invalidations(check, root);
            await Locked(check, root);
            await RelayBlind(check, root);
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

    // ---------- pure handshake and frames ----------

    private sealed record Pair(SecureSession Host, SecureSession Authority, string MachineSeen);

    private static Pair Connect(ISigningKey machine, ISigningKey authority, TrustedAuthority trust, Func<string, IReadOnlyList<KeyTransition>>? transitions = null,
        Func<byte[], byte[]>? hello = null, Func<byte[], byte[]>? serverHello = null, Func<byte[], byte[]>? auth = null)
    {
        using InitiatorHandshake initiator = new(machine, trust);
        using ResponderHandshake responder = new(authority, transitions ?? (_ => []));
        byte[] h = initiator.Hello();
        byte[] sh = responder.Respond(hello?.Invoke(h) ?? h);
        (byte[] a, SecureSession hostSession, _, byte[] expected) = initiator.Complete(serverHello?.Invoke(sh) ?? sh);
        (SecureSession authoritySession, string seen, _, byte[] ready) = responder.Complete(auth?.Invoke(a) ?? a);
        if (!hostSession.Open(ready).AsSpan().SequenceEqual(expected))
        {
            throw new SecureChannelException("confirmation");
        }

        return new Pair(hostSession, authoritySession, seen);
    }

    private static bool Fails(Action action)
    {
        try
        {
            action();
        }
        catch (SecureChannelException)
        {
            return true;
        }

        return false;
    }

    private static TrustedAuthority Trust(ISigningKey authority, bool withKey = true) => new(KeyIdentity.Fingerprint(authority.PublicKey), withKey ? authority.PublicKey : null);

    private static void Handshake(Action<bool, string> check)
    {
        using SoftwareSigningKey machine = new();
        using SoftwareSigningKey authority = new();
        using SoftwareSigningKey other = new();

        Pair pair = Connect(machine, authority, Trust(authority));
        byte[] toAuthority = pair.Host.Seal("hello authority"u8);
        byte[] toHost = pair.Authority.Seal("hello host"u8);
        check(pair.MachineSeen == KeyIdentity.Fingerprint(machine.PublicKey) && Encoding.UTF8.GetString(pair.Authority.Open(toAuthority)) == "hello authority" && Encoding.UTF8.GetString(pair.Host.Open(toHost)) == "hello host", "handshake: both sides authenticate, the authority learns the machine fingerprint and both directions carry data");

        Pair again = Connect(machine, authority, Trust(authority));
        check(pair.Host.Id != again.Host.Id && pair.Host.Id == pair.Authority.Id, "handshake: each connection has its own session id (fresh keys), shared by both ends");
        byte[] old = pair.Host.Seal("old session"u8);
        check(Fails(() => again.Authority.Open(old)), "handshake: a frame of an old session is refused in a new one (fresh keys)");

        check(Fails(() => Connect(machine, authority, Trust(other))), "authentication: an authority whose key is not the trusted one is refused by the host (key substitution)");
        check(Fails(() => Connect(machine, authority, new TrustedAuthority(KeyIdentity.Fingerprint(other.PublicKey), other.PublicKey))), "authentication: the same with the full trusted key pinned");

        // A man in the middle that answers with its own key and signature, or with the real key but its own ephemeral key.
        check(Fails(() =>
        {
            using InitiatorHandshake initiator = new(machine, Trust(authority));
            using ResponderHandshake mitm = new(other, _ => []);
            initiator.Complete(mitm.Respond(initiator.Hello()));
        }), "authentication: an impostor that signs with its own key is refused");
        check(Fails(() =>
        {
            using InitiatorHandshake initiator = new(machine, Trust(authority));
            using ResponderHandshake real = new(authority, _ => []);
            using ResponderHandshake mitm = new(authority, _ => []);
            byte[] hello = initiator.Hello();
            real.Respond(hello);
            byte[] forged = mitm.Respond(hello);
            forged[10] ^= 1;
            initiator.Complete(forged);
        }), "tampering: a server hello with a changed ephemeral key (signature over the transcript) is refused");
        check(Fails(() => Connect(machine, authority, Trust(authority), serverHello: sh => { sh[^1] ^= 1; return sh; })), "tampering: a changed handshake signature is refused");
        check(Fails(() => Connect(machine, authority, Trust(authority), hello: h => { byte[] c = [.. h]; c[5] ^= 1; return c; })), "tampering: a hello altered on the way to the authority makes the authority sign another transcript; the host refuses");
        check(Fails(() => Connect(machine, authority, Trust(authority), hello: h => { byte[] c = [.. h]; c[^1] ^= 1; return c; })), "tampering: a changed anchor fingerprint in the hello is refused (transcript)");

        // The machine side: a wrong machine key (its signature is not by the key it presents) and a swapped key.
        check(Fails(() => Connect(machine, authority, Trust(authority), auth: a =>
        {
            using SoftwareSigningKey thief = new();
            byte[] copy = [.. a];
            byte[] key = thief.PublicKey;
            key.CopyTo(copy, 3);

            return copy;
        })), "mutual authentication: a machine key swapped into the authentication message does not match its signature, refused");
        check(Fails(() => Connect(machine, authority, Trust(authority), auth: a => { a[^1] ^= 1; return a; })), "mutual authentication: a changed machine signature is refused");
        check(Fails(() => Connect(machine, authority, Trust(authority), auth: a => a[..^1])), "mutual authentication: a truncated authentication message is refused");
        check(Fails(() => Connect(machine, authority, Trust(authority), hello: _ => [1, 0, 0, 0, 1])), "tampering: a malformed hello is refused");

        // A machine that signs with a key other than the one it presents (wrong machine key) fails as well.
        check(Fails(() =>
        {
            using InitiatorHandshake initiator = new(new Mismatched(machine, other), Trust(authority));
            using ResponderHandshake responder = new(authority, _ => []);
            (byte[] a, _, _, _) = initiator.Complete(responder.Respond(initiator.Hello()));
            responder.Complete(a);
        }), "mutual authentication: signing with another key than the presented one is refused");

        // Routine rotation: the host pinned the old key; the new key is accepted only through transitions the old key signed.
        using SoftwareSigningKey rotated = new();
        KeyTransition transition = KeyTransition.Create(authority, rotated.PublicKey, DateTimeOffset.UtcNow);
        check(Connect(machine, rotated, Trust(authority), _ => [transition]).Host.Id.Length == 32, "rotation: a key introduced by a transition signed by the pinned key is accepted");
        check(Fails(() => Connect(machine, rotated, Trust(authority, withKey: false), _ => [transition])), "rotation: a host that has only the fingerprint cannot follow a transition");
        check(Fails(() => Connect(machine, rotated, Trust(authority), _ => [])), "rotation: a new key with no transition is refused");
        KeyTransition forged = KeyTransition.Create(other, rotated.PublicKey, DateTimeOffset.UtcNow);
        check(Fails(() => Connect(machine, rotated, Trust(authority), _ => [forged])), "rotation: a transition signed by another key is refused");
        check(Fails(() => Connect(machine, other, Trust(authority), _ => [transition])), "rotation: a transition to a key other than the one that signed is refused");
    }

    private sealed class Mismatched(ISigningKey presented, ISigningKey signer) : ISigningKey
    {
        public byte[] PublicKey => presented.PublicKey;

        public byte[] Sign(byte[] data) => signer.Sign(data);

        public void Dispose()
        {
        }
    }

    private static void Frames(Action<bool, string> check)
    {
        using SoftwareSigningKey machine = new();
        using SoftwareSigningKey authority = new();
        Pair pair = Connect(machine, authority, Trust(authority));
        byte[] one = pair.Host.Seal("one"u8);
        byte[] two = pair.Host.Seal("two"u8);
        byte[] three = pair.Host.Seal("three"u8);
        check(Encoding.UTF8.GetString(pair.Authority.Open(one)) == "one" && Encoding.UTF8.GetString(pair.Authority.Open(two)) == "two", "frames: sequence numbers in order are accepted");
        check(Fails(() => pair.Authority.Open(two)) && Fails(() => pair.Authority.Open(three)), "replay: a repeated frame is refused and ends the session for good");

        Pair second = Connect(machine, authority, Trust(authority));
        byte[] a = second.Host.Seal("a"u8);
        byte[] b = second.Host.Seal("b"u8);
        check(Fails(() => second.Authority.Open(b)) && Fails(() => second.Authority.Open(a)), "out of order: a frame that skips ahead is refused, and so is everything after it");

        Pair gap = Connect(machine, authority, Trust(authority));
        gap.Host.Seal("lost"u8);
        byte[] after = gap.Host.Seal("after"u8);
        check(Fails(() => gap.Authority.Open(after)), "sequence gap: a dropped frame ends the session");

        // Tampering at every position of a frame: type, sequence, ciphertext, tag, length.
        byte[] sample = Connect(machine, authority, Trust(authority)).Host.Seal("payload bytes"u8);
        bool all = true;
        for (int position = 0; position < sample.Length; position++)
        {
            Pair fresh = Connect(machine, authority, Trust(authority));
            byte[] frame = fresh.Host.Seal("payload bytes"u8);
            frame[position] ^= 0x40;
            all &= Fails(() => fresh.Authority.Open(frame));
        }

        check(all, "tampering: a changed bit anywhere in a frame (type, sequence, ciphertext, tag) is refused");
        Pair truncated = Connect(machine, authority, Trust(authority));
        byte[] cut = truncated.Host.Seal("payload"u8);
        check(Fails(() => truncated.Authority.Open(cut[..^1])), "tampering: a truncated frame is refused");

        Pair reflect = Connect(machine, authority, Trust(authority));
        byte[] mine = reflect.Host.Seal("reflect"u8);
        check(Fails(() => reflect.Host.Open(mine)), "reflection: a frame sent by the host is not accepted by the host (direction is bound)");

        Pair x = Connect(machine, authority, Trust(authority));
        Pair y = Connect(machine, authority, Trust(authority));
        byte[] foreign = x.Host.Seal("foreign"u8);
        check(Fails(() => y.Authority.Open(foreign)), "wrong session: a frame of another session is refused");
        check(Fails(() => x.Host.Seal(new byte[ChannelFormat.MaxPlaintext + 1])), "limits: a message over the maximum is not sealed");
    }

    private static void Config(Action<bool, string> check)
    {
        string fp = new('A', 64);
        RemoteAuthorityConfig ok = new("http://127.0.0.1:8780", "reg-1", fp);
        check(RemoteTarget.Problem(ok) is null && RemoteTarget.Problem(ok with { RelayUrl = "https://relay.example.org" }) is null && RemoteTarget.Problem(ok with { RelayUrl = "wss://relay.example.org:9000" }) is null, "config: loopback http and any https/wss relay are usable");
        check(RemoteTarget.Problem(ok with { RelayUrl = "http://relay.example.org" }) is not null && RemoteTarget.Problem(ok with { RelayUrl = "ws://10.0.0.5:8780" }) is not null, "config: plain http or ws beyond the loopback is refused (HTTPS is required for an external relay)");
        check(RemoteTarget.Problem(ok with { RelayUrl = "ftp://x" }) is not null && RemoteTarget.Problem(ok with { RelayUrl = "https://u:p@relay.example.org" }) is not null && RemoteTarget.Problem(ok with { RegistrationId = "bad id" }) is not null
            && RemoteTarget.Problem(ok with { AuthorityFingerprint = "12" }) is not null && RemoteTarget.Problem(ok with { TlsPin = "zz" }) is not null, "config: bad scheme, user info, registration id, fingerprint or pin are refused");

        // Certificate validation is never weakened: any system error rejects; a pin only narrows.
        byte[] raw = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=x", System.Security.Cryptography.ECDsa.Create(), System.Security.Cryptography.HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1)).RawData;
        using System.Security.Cryptography.X509Certificates.X509Certificate2 cert = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(raw);
        string pin = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(cert.RawData));
        check(RelayTls.Accept(cert, SslPolicyErrors.None, "") && RelayTls.Accept(cert, SslPolicyErrors.None, pin) && !RelayTls.Accept(cert, SslPolicyErrors.None, new string('0', 64)), "tls: no errors and a matching (or no) pin is accepted; a different pin is not");
        check(!RelayTls.Accept(cert, SslPolicyErrors.RemoteCertificateChainErrors, "") && !RelayTls.Accept(cert, SslPolicyErrors.RemoteCertificateNameMismatch, pin) && !RelayTls.Accept(null, SslPolicyErrors.None, ""), "tls: a chain or name error is never accepted, not even with the right pin");

        string folder = Path.Combine(Path.GetTempPath(), "ws-remote-cfg-" + Guid.NewGuid().ToString("N")[..8]);
        try
        {
            HostConfigFile file = HostConfigFile.InFolder(folder);
            string machine = new('B', 64);
            file.SetRemote(machine, ok);
            HostConfigLoad load = file.Load();
            using SoftwareSigningKey key = new();
            file.Pin(machine, new PinnedAuthorityKey(KeyIdentity.Fingerprint(key.PublicKey), key.PublicKey, DateTimeOffset.UtcNow));
            HostConfigLoad pinned = file.Load();
            string text = File.ReadAllText(file.FilePath);
            check(load.Config?.Remote == ok, "config: remote read back (" + load.Problem + "|" + load.Config?.Remote + "|" + File.ReadAllText(file.FilePath) + ")");
            check(pinned.Config?.Remote == ok && pinned.Config?.Authority is not null && !text.Contains("PRIVATE", StringComparison.OrdinalIgnoreCase), "config: host.json carries the remote setting (public data) next to the pin, and keeps it when the key is pinned or replaced");
            file.SetRemote(machine, null);
            check(file.Load().Config?.Remote is null, "config: removing the setting returns to local mode");
            File.WriteAllText(file.FilePath, "{\"version\":1,\"machineFingerprint\":\"" + machine + "\",\"authority\":null,\"remote\":{\"relayUrl\":\"http://example.org\",\"registrationId\":\"r\",\"authorityFingerprint\":\"" + fp + "\",\"tlsPin\":\"\"}}");
            check(file.Load().Problem is not null, "config: a remote setting with an insecure external relay makes host.json unusable (fails closed)");
        }
        finally
        {
            try
            {
                Directory.Delete(folder, true);
            }
            catch (IOException)
            {
                // Harmless.
            }
        }
    }

    // ---------- rigs over a real relay ----------

    private sealed class Net : IAsyncDisposable
    {
        public required RelayServer Relay { get; set; }

        public required TestMachine Machine { get; init; }

        public required AuthorityEndpoint Endpoint { get; set; }

        public required RemoteAuthority Remote { get; init; }

        public required RemoteAuthorityConfig Config { get; init; }

        public List<(string From, byte[] Frame)> Captured { get; init; } = [];

        public ValueTask DisposeAsync() => Close();

        private async ValueTask Close()
        {
            Remote.Dispose();
            await Endpoint.DisposeAsync();
            await Relay.DisposeAsync();
        }
    }

    private static AuthorityEndpointOptions Quick => new() { PushInterval = Fast, MaxReconnectPause = TimeSpan.FromMilliseconds(300) };

    private static async Task<Net> Start(string root, TestMachine? machine = null, int? relayPort = null, TimeSpan? push = null, bool capture = false)
    {
        machine ??= new TestMachine(Path.Combine(root, "m-" + Guid.NewGuid().ToString("N")[..6]));
        List<(string From, byte[] Frame)> frames = [];
        RelayServer relay = await RelayServer.StartAsync(new RelayOptions { Port = relayPort ?? 0, CaptureRecords = true, Tap = capture ? (from, frame) => { lock (frames) { frames.Add((from, frame)); } } : null });
        string authorityFingerprint = KeyIdentity.Fingerprint(machine.Deployment.Keys.CurrentRecord().PublicKey);
        RemoteAuthorityConfig config = new(relay.Url, "reg-" + Guid.NewGuid().ToString("N")[..8], authorityFingerprint);
        AuthorityEndpoint endpoint = new(machine.Deployment.Authority, machine.Deployment.Keys, machine.Deployment.Store, config, push is { } p ? new AuthorityEndpointOptions { PushInterval = p, MaxReconnectPause = TimeSpan.FromMilliseconds(300) } : Quick);
        endpoint.Start();
        await endpoint.Registered.WaitAsync(TimeSpan.FromSeconds(10));
        RemoteAuthority remote = new(config, machine.MachineKey, machine.Deployment.HostConfig) { RetryPause = TimeSpan.FromMilliseconds(50), Retries = 6 };
        
        return new Net { Relay = relay, Machine = machine, Endpoint = endpoint, Remote = remote, Config = config, Captured = frames };
    }

    private static LaunchRequest Request(string id, string program = "/work/tool.sh", string reason = "remote test", string secret = "TOKEN", params string[] arguments)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;

        return new LaunchRequest(LaunchProtocol.Version, id, now, now.AddMinutes(5), "bm9uY2UtMDAwMDAwMDE" + Guid.NewGuid().ToString("N")[..6], [secret], [new LaunchMapping("TOKEN", secret)], reason, program, arguments, "/work", [], [], new Dictionary<string, string>(), new Dictionary<string, string>());
    }

    private static async Task<bool> Until(Func<bool> condition, int seconds = 10)
    {
        DateTime end = DateTime.UtcNow.AddSeconds(seconds);
        while (DateTime.UtcNow < end)
        {
            if (condition())
            {
                return true;
            }

            await Task.Delay(30);
        }

        return condition();
    }

    private static byte[] AuthorityKey(TestMachine machine) => machine.Deployment.Keys.CurrentRecord().PublicKey;

    // ---------- operations ----------

    private static async Task Operations(Action<bool, string> check, string root)
    {
        await using Net net = await Start(root);
        TestMachine machine = net.Machine;
        RemoteAuthority remote = net.Remote;

        ReconcileEnvelope reconcile = ReconcileEnvelope.Create("rc-1", machine.HostName, DateTimeOffset.UtcNow, machine.MachineKey);
        ReconcileResponse answer = await remote.ReconcileAsync(reconcile);
        check(answer.Verify(AuthorityKey(machine)) && answer.Status == "Trusted" && answer.HostNameBound && answer.LeaseSeconds > 0 && answer.RequestId == "rc-1", "remote: a check-in through the relay returns the authority's signed answer (verifies under the authority key)");

        LaunchRequest request = Request("req-decide-1");
        int presented = 0;
        using IDisposable offer = machine.Deployment.Authority.Offer(request.RequestId, request.Digest(), () => { Interlocked.Increment(ref presented); return ApprovalDecision.Allow(); });
        MachineRequestEnvelope envelope = MachineRequestEnvelope.Create(request, machine.HostName, machine.MachineKey);
        AuthorityResponse decided = await remote.DecideAsync(envelope);
        check(decided.Decision == AuthorityDecision.Approved && decided.Verify(AuthorityKey(machine)) && decided.RequestDigest == request.Digest() && presented == 1, "remote: a decision through the relay is the local authority's own signed, request-bound answer");
        check(machine.Deployment.Store.GetProcessed(request.RequestId) is not null, "remote: the same persistence is used (the decision is in authority.db processed_requests)");

        string challengeKey = Convert.ToBase64String(await remote.BeginEnrollmentAsync());
        EnrollmentResult enrolled = await remote.EnrollAsync(EnrollmentRequest.Create(machine.HostName, await remote.BeginEnrollmentAsync(), machine.MachineKey));
        check(challengeKey.Length > 0 && enrolled.Accepted && enrolled.Status == MachineStatus.Trusted, "remote: enrollment (challenge and proof of possession) works through the relay and reports the machine's real status");

        // Grant operation, key transitions, audit upload.
        LaunchRequest grantRequest = Request("req-grant-1");
        GrantEnvelope use = GrantEnvelope.Create(GrantOps.Use, grantRequest, new string('A', 64), machine.HostName, machine.MachineKey);
        GrantResponse grant = await remote.GrantAsync(use);
        check(grant.Verify(AuthorityKey(machine)) && grant.Outcome == GrantOps.None, "remote: a grant query returns the authority's signed answer");
        check((await remote.KeyTransitionsAsync(new string('C', 64))).Count == 0 && (await remote.PendingInvalidationsAsync(machine.Fingerprint)).Count == 0 && (await remote.PendingGrantEventsAsync(machine.Fingerprint)).Count == 0, "remote: reads (transitions, pending lists) work");

        HostAuditOutbox outbox = HostAuditOutbox.InFolder(Path.Combine(root, "outbox-" + Guid.NewGuid().ToString("N")[..6]), machine.MachineKey);
        outbox.Append(new AuditFacts(AuditEventTypes.Authorization, "approved", "approved", "req-audit", "/work", "/work/tool.sh", ["a"]));
        AuditBatch batch = new("batch-1", machine.Fingerprint, outbox.Pending(10));
        AuditAck ack = await remote.UploadAsync(batch);
        check(ack.Verify(AuthorityKey(machine)) && ack.Entries.Count == 1 && ack.Entries[0].Status == AuditStatus.Accepted && ack.RequestDigest == batch.Digest(), "remote: an audit batch is acknowledged by the authority's signed, batch-bound ack");
        AuditAck again = await remote.UploadAsync(batch with { BatchId = "batch-2" });
        check(again.Entries[0].Status == AuditStatus.Duplicate, "remote: the same batch again is a duplicate, not stored twice (idempotent)");

        // The wire carries the contracts losslessly: a tampered signed body is not accepted by the authority.
        check(RemoteWire.TryRead(RemoteWire.Write(envelope), out MachineRequestEnvelope? roundTrip) && roundTrip!.Verify(machine.MachineKey.PublicKey) && roundTrip.Request.Digest() == request.Digest(), "wire: a machine envelope round-trips through its canonical JSON and still verifies");
        check(!RemoteWire.TryRead(RemoteWire.Write(envelope).Replace("\"hostName\":\"" + machine.HostName + "\"", "\"hostName\":\"x\"", StringComparison.Ordinal), out MachineRequestEnvelope? changed) || !changed!.Verify(machine.MachineKey.PublicKey), "wire: a changed field breaks the machine's signature");
        check(!RemoteWire.TryRead(RemoteWire.Write(envelope).Replace("}", ",\"extra\":1}", StringComparison.Ordinal), out MachineRequestEnvelope? _), "wire: an unknown member is refused (strict reading)");
        check(RemoteWire.TryReadMessage(Encoding.UTF8.GetBytes("{\"v\":2,\"id\":\"a\",\"op\":\"x\",\"body\":{}}"), out _) == false, "wire: another message version is refused");
    }

    private static async Task Duplicates(Action<bool, string> check, string root)
    {
        await using Net net = await Start(root);
        TestMachine machine = net.Machine;
        LaunchRequest request = Request("req-dup-1");
        int presented = 0;
        using IDisposable offer = machine.Deployment.Authority.Offer(request.RequestId, request.Digest(), () => { Interlocked.Increment(ref presented); return ApprovalDecision.Allow(); });
        MachineRequestEnvelope envelope = MachineRequestEnvelope.Create(request, machine.HostName, machine.MachineKey);
        Task<AuthorityResponse> first = net.Remote.DecideAsync(envelope);
        Task<AuthorityResponse> second = net.Remote.DecideAsync(envelope);
        AuthorityResponse[] both = await Task.WhenAll(first, second);
        using RemoteAuthority other = new(net.Config, machine.MachineKey, machine.Deployment.HostConfig);
        AuthorityResponse viaNewSession = await other.DecideAsync(envelope);
        check(presented == 1 && both[0].ToJson() == both[1].ToJson() && viaNewSession.ToJson() == both[0].ToJson(), "duplicate: the same request id (same session, or a new one) returns the committed answer and asks nobody twice");

        // A raw client: the same op id with other content is refused; a replayed frame ends the session.
        await using RawClient raw = await RawClient.Connect(net.Config, machine.MachineKey, machine);
        string reconcileBody = RemoteWire.Write(ReconcileEnvelope.Create("rc-dup", machine.HostName, DateTimeOffset.UtcNow, machine.MachineKey));
        WireMessage? one = await raw.Call(RemoteOps.Reconcile, "same-id", reconcileBody);
        WireMessage? same = await raw.Call(RemoteOps.Reconcile, "same-id", reconcileBody);
        WireMessage? different = await raw.Call(RemoteOps.Reconcile, "same-id", RemoteWire.Write(ReconcileEnvelope.Create("rc-dup-2", machine.HostName, DateTimeOffset.UtcNow, machine.MachineKey)));
        check(one is { Ok: true } && same is { Ok: true } && same.Body == one.Body && different is { Ok: false, Error: "request-id-reused" }, "duplicate: one op id in a session returns the same result for the same content and is refused for other content");

        byte[] captured = raw.LastSent!;
        await raw.Channel.SendAsync(captured, CancellationToken.None);
        check(await raw.ExpectClosed(), "replay: a frame replayed to the authority ends the session (the connection is dropped)");
    }

    private static async Task Misbinding(Action<bool, string> check, string root)
    {
        await using Net net = await Start(root);
        TestMachine machine = net.Machine;
        using SoftwareSigningKey intruder = new();
        string intruderFp = KeyIdentity.Fingerprint(intruder.PublicKey);
        await using RawClient raw = await RawClient.Connect(net.Config, intruder, machine);

        // An unknown machine can enroll (Pending) but nothing else, and cannot speak for another machine.
        EnrollmentRequest enroll = EnrollmentRequest.Create("intruder-host", (await Decode(raw.Call(RemoteOps.BeginEnrollment, "b1", RemoteWire.Empty))), intruder);
        WireMessage? enrolled = await raw.Call(RemoteOps.Enroll, "e1", RemoteWire.Write(enroll));
        check(enrolled is { Ok: true } && RemoteWire.TryRead(enrolled.Body, out EnrollmentResult? result) && result!.Status == MachineStatus.Pending, "binding: a machine that proved its key can be recorded as Pending");

        WireMessage? asOther = await raw.Call(RemoteOps.PendingInvalidations, "p1", RemoteWire.WriteFingerprint(machine.Fingerprint));
        check(asOther is { Ok: false, Error: "wrong-machine" }, "binding: a session cannot read another machine's invalidations");
        WireMessage? ackOther = await raw.Call(RemoteOps.AcknowledgeInvalidation, "a1", RemoteWire.WriteAck(machine.Fingerprint, 5, true));
        check(ackOther is { Ok: false, Error: "wrong-machine" }, "binding: a session cannot acknowledge for another machine");
        LaunchRequest request = Request("req-mis-1");
        MachineRequestEnvelope forgedFor = MachineRequestEnvelope.Create(request, machine.HostName, machine.MachineKey);
        WireMessage? decide = await raw.Call(RemoteOps.Decide, "d1", RemoteWire.Write(forgedFor));
        check(decide is { Ok: false, Error: "wrong-machine" }, "binding: an envelope of another machine is refused even though it is validly signed");

        // The intruder's own envelope: Pending machine is denied (the authority's own rule).
        MachineRequestEnvelope own = MachineRequestEnvelope.Create(Request("req-mis-2"), "intruder-host", intruder);
        WireMessage? denied = await raw.Call(RemoteOps.Decide, "d2", RemoteWire.Write(own));
        check(denied is { Ok: true } && AuthorityResponse.TryParse(denied.Body, out AuthorityResponse? response, out _) && response!.Decision == AuthorityDecision.Denied && response.ReasonCode == ReasonCodes.MachinePending, "binding: the machine's own request while Pending is denied by the authority");

        // Application layer tampering: a validly encrypted envelope whose content was changed after signing.
        await using RawClient honest = await RawClient.Connect(net.Config, machine.MachineKey, machine);
        string body = RemoteWire.Write(MachineRequestEnvelope.Create(Request("req-mis-3"), machine.HostName, machine.MachineKey));
        WireMessage? tampered = await honest.Call(RemoteOps.Decide, "d3", body.Replace("remote test", "other reason", StringComparison.Ordinal));
        check(tampered is { Ok: true } && AuthorityResponse.TryParse(tampered.Body, out AuthorityResponse? bad, out _) && bad!.Decision == AuthorityDecision.Denied && bad.ReasonCode is ReasonCodes.BadSignature, "tampering: an envelope changed after signing is denied (bad signature) by the authority");
        WireMessage? junk = await honest.Call(RemoteOps.Decide, "d4", "{\"nonsense\":true}");
        WireMessage? unknown = await honest.Call("no-such-op", "u1", RemoteWire.Empty);
        check(junk is { Ok: false, Error: "bad-request" } && unknown is { Ok: false, Error: "unknown-operation" }, "wire: a malformed body and an unknown operation are refused with a code");
        _ = intruderFp;
    }

    private static async Task<byte[]> Decode(Task<WireMessage?> call)
    {
        WireMessage? message = await call;

        return RemoteWire.TryReadChallenge(message!.Body, out byte[] challenge) ? challenge : [];
    }

    private static async Task Reconnect(Action<bool, string> check, string root)
    {
        TestMachine machine = new(Path.Combine(root, "m-reconnect"));
        await using Net net = await Start(root, machine);
        ReconcileEnvelope first = ReconcileEnvelope.Create("rc-r1", machine.HostName, DateTimeOffset.UtcNow, machine.MachineKey);
        await net.Remote.ReconcileAsync(first);
        string sessionOne = net.Remote.SessionId;
        net.Remote.Disconnect();
        ReconcileResponse next = await net.Remote.ReconcileAsync(ReconcileEnvelope.Create("rc-r2", machine.HostName, DateTimeOffset.UtcNow, machine.MachineKey));
        check(next.Verify(AuthorityKey(machine)) && net.Remote.Connections == 2 && net.Remote.SessionId != sessionOne && net.Remote.SessionId.Length == 32, "reconnect: after a dropped session the next call handshakes again with a new session id and new keys");

        // Relay restart: every connection is lost, nothing durable; both sides come back by themselves on the same port.
        int port = net.Relay.Port;
        string sessionTwo = net.Remote.SessionId;
        await net.Relay.DisposeAsync();
        net.Relay = await RelayServer.StartAsync(new RelayOptions { Port = port, CaptureRecords = true });
        check(net.Relay.Records.Count == 0, "relay restart: a new relay knows nothing (no registrations, no sessions, no history)");
        bool back = await Until(() => net.Relay.AuthorityCount == 1);
        ReconcileResponse afterRestart = await net.Remote.ReconcileAsync(ReconcileEnvelope.Create("rc-r3", machine.HostName, DateTimeOffset.UtcNow, machine.MachineKey));
        check(back && afterRestart.Verify(AuthorityKey(machine)) && net.Remote.SessionId != sessionTwo, "relay restart: the authority re-registers by itself and the host reconnects with fresh session keys");

        // A call that was in flight when the connection broke is repeated under its id and answered once.
        LaunchRequest request = Request("req-restart-1");
        int presented = 0;
        using IDisposable offer = machine.Deployment.Authority.Offer(request.RequestId, request.Digest(), () => { Interlocked.Increment(ref presented); Thread.Sleep(600); return ApprovalDecision.Allow(); });
        MachineRequestEnvelope envelope = MachineRequestEnvelope.Create(request, machine.HostName, machine.MachineKey);
        Task<AuthorityResponse> pending = net.Remote.DecideAsync(envelope);
        await Task.Delay(250);
        net.Remote.Disconnect();
        AuthorityResponse decided = await pending.WaitAsync(TimeSpan.FromSeconds(20));
        check(decided.Decision == AuthorityDecision.Approved && presented == 1, "reconnect: a decision interrupted by a lost connection is retried with the same id and the approval is not asked twice");

        // The relay replaced a stale registration: a second authority with the same registration takes over.
        int before = net.Relay.AuthorityCount;
        await using AuthorityEndpoint second = new(machine.Deployment.Authority, machine.Deployment.Keys, machine.Deployment.Store, net.Config, Quick);
        second.Start();
        await second.Registered.WaitAsync(TimeSpan.FromSeconds(10));
        bool replaced = await Until(() => net.Relay.Records.Any(item => item.Event == "authority-replace"));
        check(before == 1 && replaced && net.Relay.AuthorityCount == 1, "relay: a newer registration replaces the stale one (one authority per registration id)");
    }

    private static async Task Invalidations(Action<bool, string> check, string root)
    {
        TestMachine machine = new(Path.Combine(root, "m-inval"));
        await using Net net = await Start(root, machine);
        int notified = 0;
        net.Remote.InvalidationNotified += _ => Interlocked.Increment(ref notified);
        await net.Remote.PendingInvalidationsAsync(machine.Fingerprint);
        TransitionResult disabled = machine.Deployment.Store.Disable(machine.Fingerprint, "test admin");
        bool pushed = await Until(() => Volatile.Read(ref notified) >= 2);
        IReadOnlyList<PendingInvalidation> pending = await net.Remote.PendingInvalidationsAsync(machine.Fingerprint);
        check(disabled.Ok && pushed && pending.Count == 1 && pending[0].Revision == 2, "invalidation: the authority pushes the unacknowledged invalidation and sends it again until it is acknowledged (and it is in the pending list)");

        await net.Remote.AcknowledgeInvalidationAsync(machine.Fingerprint, 2);
        int atAck = Volatile.Read(ref notified);
        await Task.Delay(500);
        check((await net.Remote.PendingInvalidationsAsync(machine.Fingerprint)).Count == 0 && machine.Deployment.Store.PendingInvalidations(machine.Fingerprint).Count == 0 && Volatile.Read(ref notified) <= atAck + 1, "invalidation: after the acknowledgement it is durable at the authority as delivered and no longer sent");

        // Delivery survives the authority endpoint restarting: an unacknowledged one is sent to the reconnecting host.
        machine.Deployment.Store.Enable(machine.Fingerprint, "test admin");
        machine.Deployment.Store.Disable(machine.Fingerprint, "test admin");
        await net.Endpoint.DisposeAsync();
        int seen = Volatile.Read(ref notified);
        net.Endpoint = new AuthorityEndpoint(machine.Deployment.Authority, machine.Deployment.Keys, machine.Deployment.Store, net.Config, Quick);
        net.Endpoint.Start();
        bool again = false;
        for (int attempt = 0; attempt < 40 && !again; attempt++)
        {
            // The host service polls every second; a poll reconnects (new session) and the push follows.
            try
            {
                await net.Remote.PendingInvalidationsAsync(machine.Fingerprint);
            }
            catch (RemoteTransportException)
            {
                // The authority is not back yet.
            }

            again = await Until(() => Volatile.Read(ref notified) > seen, 1);
        }

        check(again && machine.Deployment.Store.PendingInvalidations(machine.Fingerprint).Count == 1, "invalidation: after an authority restart the unacknowledged invalidation is delivered again (durable pending_invalidations)");
    }

    private static async Task Locked(Action<bool, string> check, string root)
    {
        TestMachine machine = new(Path.Combine(root, "m-locked"));
        AuthorityLock gate = AuthorityLock.UnlockedForTests();
        machine.Deployment.Keys.LockState = gate;
        await using Net net = await Start(root, machine);
        ReconcileResponse ok = await net.Remote.ReconcileAsync(ReconcileEnvelope.Create("rc-l1", machine.HostName, DateTimeOffset.UtcNow, machine.MachineKey));
        gate.Lock("test");
        bool refused = false;
        try
        {
            await net.Remote.ReconcileAsync(ReconcileEnvelope.Create("rc-l2", machine.HostName, DateTimeOffset.UtcNow, machine.MachineKey));
        }
        catch (Exception error) when (error is RemoteRefusedException or RemoteTransportException)
        {
            refused = true;
        }

        bool noNewSession = false;
        try
        {
            using RemoteAuthority fresh = new(net.Config, machine.MachineKey, machine.Deployment.HostConfig) { Retries = 0 };
            await fresh.ReconcileAsync(ReconcileEnvelope.Create("rc-l3", machine.HostName, DateTimeOffset.UtcNow, machine.MachineKey));
        }
        catch (RemoteTransportException error)
        {
            noNewSession = error.Message.Contains("locked", StringComparison.Ordinal);
        }

        check(ok.Status == "Trusted" && refused && noNewSession, "locked: a locked authority answers nothing (an open session is ended with a locked refusal) and refuses new sessions with a locked code");
        check(net.Endpoint.Sessions == 0, "locked: no session stays open while locked");
        gate.Unlock(UnlockMethod.Seam);
        ReconcileResponse back = await net.Remote.ReconcileAsync(ReconcileEnvelope.Create("rc-l4", machine.HostName, DateTimeOffset.UtcNow, machine.MachineKey));
        check(back.Status == "Trusted", "locked: once unlocked the host is served again after a new handshake");
    }

    private static async Task RelayBlind(Action<bool, string> check, string root)
    {
        const string CanaryReason = "CANARY-REASON-91c2";
        const string CanaryArgument = "CANARY-ARG-7f3a";
        const string CanarySecret = "CANARY_SECRET_NAME";
        const string CanaryProgram = "/work/CANARY-PROGRAM-55d0.sh";
        const string CanaryHost = "canary-host-3e8b";
        TestMachine machine = new(Path.Combine(root, "m-blind"), hostName: CanaryHost);
        await using Net net = await Start(root, machine, capture: true);
        LaunchRequest request = Request("req-blind-1", CanaryProgram, CanaryReason, CanarySecret, CanaryArgument);
        using IDisposable offer = machine.Deployment.Authority.Offer(request.RequestId, request.Digest(), () => ApprovalDecision.Allow());
        MachineRequestEnvelope envelope = MachineRequestEnvelope.Create(request, machine.HostName, machine.MachineKey);
        AuthorityResponse answer = await net.Remote.DecideAsync(envelope);
        await net.Remote.ReconcileAsync(ReconcileEnvelope.Create("rc-b1", machine.HostName, DateTimeOffset.UtcNow, machine.MachineKey));
        await Task.Delay(300);

        List<(string From, byte[] Frame)> seen;
        lock (net.Captured)
        {
            seen = [.. net.Captured];
        }

        string[] canaries = [CanaryReason, CanaryArgument, CanarySecret, CanaryProgram, CanaryHost, request.RequestId, machine.Fingerprint, request.Digest(), "approved", "decision", "protocolVersion", "machineFingerprint", "reconcile", "decide", "begin-enrollment"];
        bool leaked = seen.Any(item => canaries.Any(canary => Contains(item.Frame, Encoding.UTF8.GetBytes(canary)) || Contains(item.Frame, Encoding.UTF8.GetBytes(Convert.ToBase64String(Encoding.UTF8.GetBytes(canary)))) || Contains(item.Frame, Convert.FromHexString(machine.Fingerprint)) && canary == machine.Fingerprint));
        int dataFrames = seen.Count(item => item.Frame.Length > 12);
        check(answer.Decision == AuthorityDecision.Approved && seen.Count >= 8 && dataFrames >= 8 && !leaked, "relay inspection: across " + seen.Count + " raw frames the relay handled there is no canary (reason, arguments, secret name, program, host name, request id, digest, message types) in plaintext or base64");

        string[] allowed = ["authority-register", "host-connect", "frame-to-authority", "frame-to-host", "host-gone", "authority-gone", "authority-replace"];
        IReadOnlyList<RelayRecord> records = net.Relay.Records;
        check(records.Count > 0 && records.All(item => allowed.Contains(item.Event) && item.Registration == net.Config.RegistrationId && item.Connection.Length is 0 or 8) && records.All(item => item.GetType().GetProperties().Select(property => property.Name).Order().SequenceEqual(["Connection", "Event", "Length", "Registration", "Time"])),
            "relay inspection: the relay's own record is routing metadata only (event word, registration id, connection id, size, time)");
        check(!records.Any(item => item.Event.Contains("decide", StringComparison.Ordinal) || item.Registration.Contains(CanaryHost, StringComparison.Ordinal)), "relay inspection: no record names an operation or a machine");
        check(seen.Where(item => item.From == "from-host").All(item => item.Frame.Length > 0) && !seen.Any(item => item.Frame.Length > 12 && Contains(item.Frame, Encoding.ASCII.GetBytes("{\"v\":1"))), "relay inspection: no application JSON is visible in any frame");
    }

    private static bool Contains(byte[] haystack, byte[] needle) => needle.Length > 0 && haystack.AsSpan().IndexOf(needle) >= 0;

    // ---------- a raw client for hostile or odd messages ----------

    private sealed class RawClient : IAsyncDisposable
    {
        private SecureSession? _session;
        private IMessageChannel? _channel;
        private readonly ISigningKey _key;

        private RawClient(ISigningKey key) => _key = key;

        public IMessageChannel Channel => _channel!;

        public byte[]? LastSent { get; private set; }

        public static async Task<RawClient> Connect(RemoteAuthorityConfig config, ISigningKey key, TestMachine authorityMachine)
        {
            RawClient client = new(key);
            client._channel = await WebSocketChannel.ConnectAsync(config, RelayServer.HostPath, CancellationToken.None);
            using InitiatorHandshake handshake = new(key, new TrustedAuthority(KeyIdentity.Fingerprint(authorityMachine.Deployment.Keys.CurrentRecord().PublicKey), null));
            await client._channel.SendAsync(handshake.Hello(), CancellationToken.None);
            byte[] serverHello = (await client._channel.ReceiveAsync(CancellationToken.None))!;
            (byte[] auth, SecureSession session, _, byte[] expected) = handshake.Complete(serverHello);
            await client._channel.SendAsync(auth, CancellationToken.None);
            byte[] ready = (await client._channel.ReceiveAsync(CancellationToken.None))!;
            client._session = session;
            if (!session.Open(ready).AsSpan().SequenceEqual(expected))
            {
                throw new InvalidOperationException("not confirmed");
            }

            return client;
        }

        public async Task<WireMessage?> Call(string op, string id, string body)
        {
            byte[] frame = _session!.Seal(Encoding.UTF8.GetBytes(RemoteWire.Request(id, op, body)));
            LastSent = frame;
            await _channel!.SendAsync(frame, CancellationToken.None);
            using CancellationTokenSource limit = new(TimeSpan.FromSeconds(15));
            byte[]? reply = await _channel.ReceiveAsync(limit.Token);

            return reply is null ? null : RemoteWire.TryReadMessage(_session.Open(reply), out WireMessage? message) ? message : null;
        }

        public async Task<bool> ExpectClosed()
        {
            using CancellationTokenSource limit = new(TimeSpan.FromSeconds(10));
            try
            {
                while (await _channel!.ReceiveAsync(limit.Token) is not null)
                {
                }

                return true;
            }
            catch (Exception error) when (error is System.Net.WebSockets.WebSocketException or OperationCanceledException or IOException)
            {
                return error is not OperationCanceledException;
            }
        }

        public ValueTask DisposeAsync()
        {
            _channel?.Dispose();
            _ = _key;

            return ValueTask.CompletedTask;
        }
    }
}

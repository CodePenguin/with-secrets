using System.Collections.Concurrent;

namespace WithSecrets;

/// <summary>Settings of an <see cref="AuthorityEndpoint" />.</summary>
public sealed class AuthorityEndpointOptions
{
    /// <summary>How often an unacknowledged invalidation of a connected machine is sent again.</summary>
    public TimeSpan PushInterval { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>How long a machine has to finish the handshake.</summary>
    public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(15);

    public int MaxSessions { get; init; } = 128;

    /// <summary>The longest pause between attempts to reach the relay.</summary>
    public TimeSpan MaxReconnectPause { get; init; } = TimeSpan.FromSeconds(5);
}

/// <summary>
/// The authority's side of a remote deployment: it registers with the relay (outbound), answers the handshake of each host with the authority signing key, and serves the
/// ordinary <see cref="IAuthority" /> and <see cref="IAuditSink" /> operations of the SAME <see cref="LocalAuthority" /> (same logic, same <c>authority.db</c>, same
/// <c>processed_requests</c>) to the host the session authenticated. It adds no authorization of its own: every machine message is still verified by the local authority against the
/// machine's registered key; the endpoint only binds a session to the one machine that proved its key in the handshake (a request naming another machine is refused), refuses
/// everything while the authority is locked, and pushes the machine's unacknowledged invalidations until they are acknowledged.
/// </summary>
public sealed class AuthorityEndpoint(LocalAuthority authority, AuthorityKeyRing keys, AuthorityStore store, RemoteAuthorityConfig relay, AuthorityEndpointOptions? options = null, IRemoteLaunchHandler? launches = null) : IAsyncDisposable
{
    private const int MaxLaunchesPerSession = 4096;

    private const int MaxRemembered = 512;

    private readonly AuthorityEndpointOptions _options = options ?? new AuthorityEndpointOptions();
    private readonly CancellationTokenSource _stop = new();
    private readonly TaskCompletionSource _registered = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private Task _loop = Task.CompletedTask;
    private int _sessions;
    private int _pushed;
    private int _handshakeFailures;
    private int _requests;
    private string _lastSession = "";

    /// <summary>The sessions that completed the handshake and are open now.</summary>
    public int Sessions => Volatile.Read(ref _sessions);

    /// <summary>How many invalidation notices were sent (including repeats).</summary>
    public int Pushed => Volatile.Read(ref _pushed);

    public int HandshakeFailures => Volatile.Read(ref _handshakeFailures);

    public int Requests => Volatile.Read(ref _requests);

    /// <summary>The id (public) of the session that was established last.</summary>
    public string LastSessionId => Volatile.Read(ref _lastSession);

    /// <summary>Completes the first time the endpoint is registered at the relay (a test waits for it).</summary>
    public Task Registered => _registered.Task;

    private bool Locked => keys.LockState?.IsLocked == true;

    public void Start()
    {
        _loop = Task.Run(() => RunAsync(_stop.Token));
    }

    private async Task RunAsync(CancellationToken stop)
    {
        TimeSpan pause = TimeSpan.FromMilliseconds(100);
        while (!stop.IsCancellationRequested)
        {
            try
            {
                using WebSocketChannel channel = await WebSocketChannel.ConnectAsync(relay, RelayServer.AuthorityPath, stop);
                _registered.TrySetResult();
                pause = TimeSpan.FromMilliseconds(100);
                await ServeAsync(channel, stop);
            }
            catch (Exception error) when (error is not OutOfMemoryException)
            {
                if (stop.IsCancellationRequested)
                {
                    return;
                }

                AppLog.Warn("the authority endpoint lost the relay: {Type}", error.GetType().Name);
            }

            try
            {
                await Task.Delay(pause, stop);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            pause = TimeSpan.FromTicks(Math.Min(pause.Ticks * 2, _options.MaxReconnectPause.Ticks));
        }
    }

    private enum Stage
    {
        Hello,
        Auth,
        Ready,
    }

    private sealed class Peer(Guid id)
    {
        public Guid Id { get; } = id;

        public Stage Stage { get; set; } = Stage.Hello;

        public ResponderHandshake? Handshake { get; set; }

        public SecureSession? Session { get; set; }

        public string Machine { get; set; } = "";

        public byte[] MachineKey { get; set; } = [];

        public CancellationTokenSource Ended { get; } = new();

        public Lock Gate { get; } = new();

        /// <summary>Frames of one session must leave in sequence order, so sealing and sending happen under this.</summary>
        public SemaphoreSlim SendLock { get; } = new(1, 1);

        public Dictionary<string, (string Digest, Task<string> Result)> Known { get; } = new(StringComparer.Ordinal);

        public Queue<string> Order { get; } = new();

        /// <summary>The launch ids this session ran: a launch runs once per id, and its answer (which carries values) is never kept.</summary>
        public HashSet<string> LaunchIds { get; } = new(StringComparer.Ordinal);
    }

    private async Task ServeAsync(WebSocketChannel channel, CancellationToken stop)
    {
        ConcurrentDictionary<Guid, Peer> peers = new();
        try
        {
            while (await channel.ReceiveAsync(stop) is { } message)
            {
                if (message.Length < RelayServer.HeaderLength)
                {
                    continue;
                }

                Guid id = new(message.AsSpan(1, 16));
                switch (message[0])
                {
                    case RelayServer.KindOpen:
                        if (peers.Count < _options.MaxSessions)
                        {
                            Peer peer = new(id);
                            peers[id] = peer;
                            _ = Task.Run(() => ExpireHandshakeAsync(channel, peer, peers, stop), stop);
                        }
                        else
                        {
                            await SendAsync(channel, RelayServer.KindClose, id, [], stop);
                        }

                        break;
                    case RelayServer.KindClose:
                        if (peers.TryRemove(id, out Peer? gone))
                        {
                            End(gone);
                        }

                        break;
                    case RelayServer.KindData when peers.TryGetValue(id, out Peer? known):
                        await OnFrameAsync(channel, known, message[RelayServer.HeaderLength..], peers, stop);
                        break;
                }
            }
        }
        finally
        {
            foreach (Peer peer in peers.Values)
            {
                End(peer);
            }
        }
    }

    private async Task ExpireHandshakeAsync(WebSocketChannel channel, Peer peer, ConcurrentDictionary<Guid, Peer> peers, CancellationToken stop)
    {
        try
        {
            await Task.Delay(_options.HandshakeTimeout, stop);
            if (peer.Stage != Stage.Ready && peers.TryRemove(peer.Id, out _))
            {
                End(peer);
                await SendAsync(channel, RelayServer.KindClose, peer.Id, [], stop);
            }
        }
        catch (Exception error) when (error is OperationCanceledException or IOException or System.Net.WebSockets.WebSocketException or ObjectDisposedException)
        {
            // Shutting down, or the relay is gone.
        }
    }

    private void End(Peer peer)
    {
        lock (peer.Gate)
        {
            if (peer.Session is not null && peer.Stage == Stage.Ready)
            {
                Interlocked.Decrement(ref _sessions);
            }

            peer.Stage = Stage.Hello;
            peer.Handshake?.Dispose();
            peer.Handshake = null;
            peer.Session = null;
        }

        try
        {
            peer.Ended.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // Already ended.
        }
    }

    private async Task Drop(WebSocketChannel channel, Peer peer, ConcurrentDictionary<Guid, Peer> peers, string? code, CancellationToken stop)
    {
        peers.TryRemove(peer.Id, out _);
        End(peer);
        try
        {
            if (code is not null)
            {
                await SendAsync(channel, RelayServer.KindData, peer.Id, ChannelFormat.ErrorFrame(code), stop);
            }

            await SendAsync(channel, RelayServer.KindClose, peer.Id, [], stop);
        }
        catch (Exception error) when (error is OperationCanceledException or IOException or System.Net.WebSockets.WebSocketException or ObjectDisposedException)
        {
            // The relay is gone; the host will notice.
        }
    }

    private static Task SendAsync(WebSocketChannel channel, byte kind, Guid id, byte[] payload, CancellationToken stop) => channel.SendAsync([.. RelayServer.Header(kind, id), .. payload], stop);

    private async Task OnFrameAsync(WebSocketChannel channel, Peer peer, byte[] frame, ConcurrentDictionary<Guid, Peer> peers, CancellationToken stop)
    {
        try
        {
            switch (peer.Stage)
            {
                case Stage.Hello:
                    if (Locked)
                    {
                        await Drop(channel, peer, peers, "locked", stop);

                        return;
                    }

                    ResponderHandshake handshake = new(keys.Current(), fingerprint => store.TransitionsFrom(fingerprint));
                    peer.Handshake = handshake;
                    byte[] hello = handshake.Respond(frame);
                    peer.Stage = Stage.Auth;
                    await SendAsync(channel, RelayServer.KindData, peer.Id, hello, stop);
                    break;
                case Stage.Auth:
                    (SecureSession session, string machine, byte[] machineKey, byte[] ready) = peer.Handshake!.Complete(frame);
                    peer.Handshake.Dispose();
                    peer.Handshake = null;
                    peer.Session = session;
                    peer.Machine = machine;
                    peer.MachineKey = machineKey;
                    peer.Stage = Stage.Ready;
                    Interlocked.Increment(ref _sessions);
                    Volatile.Write(ref _lastSession, session.Id);
                    await SendAsync(channel, RelayServer.KindData, peer.Id, ready, stop);
                    _ = Task.Run(() => PushLoopAsync(channel, peer, peers, stop));
                    break;
                default:
                    byte[] plaintext = peer.Session!.Open(frame);
                    if (!RemoteWire.TryReadMessage(plaintext, out WireMessage? message) || message is null || !message.IsRequest)
                    {
                        await Drop(channel, peer, peers, null, stop);

                        return;
                    }

                    _ = Task.Run(() => HandleAsync(channel, peer, peers, message, stop));
                    break;
            }
        }
        catch (AuthorityLockedException)
        {
            await Drop(channel, peer, peers, "locked", stop);
        }
        catch (Exception error) when (error is SecureChannelException or System.Security.Cryptography.CryptographicException or ArgumentException)
        {
            Interlocked.Increment(ref _handshakeFailures);
            AppLog.Warn("a host's session was refused (handshake or frame)");
            await Drop(channel, peer, peers, null, stop);
        }
    }

    private static async Task SendSealedAsync(WebSocketChannel channel, Peer peer, SecureSession session, string message, CancellationToken stop)
    {
        await peer.SendLock.WaitAsync(stop);
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes(message);
        try
        {
            await SendAsync(channel, RelayServer.KindData, peer.Id, session.Seal(plaintext), stop);
        }
        finally
        {
            // What was sealed may carry values (a delivery): the plaintext copy of the frame is zeroed.
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(plaintext);
            peer.SendLock.Release();
        }
    }

    private async Task HandleAsync(WebSocketChannel channel, Peer peer, ConcurrentDictionary<Guid, Peer> peers, WireMessage message, CancellationToken stop)
    {
        Interlocked.Increment(ref _requests);
        string reply;
        bool close = false;
        SecretsDelivery? delivery = null;
        try
        {
            if (Locked)
            {
                reply = RemoteWire.Failure(message.Id, "locked");
                close = true;
            }
            else if (message.Op == RemoteOps.LaunchAuthorize)
            {
                (reply, delivery) = await LaunchAsync(channel, peer, message, stop);
            }
            else
            {
                reply = await Remembered(peer, message);
            }
        }
        catch (AuthorityLockedException)
        {
            reply = RemoteWire.Failure(message.Id, "locked");
            close = true;
        }
        catch (OperationCanceledException)
        {
            return;
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            AppLog.Warn("a remote operation failed: {Type}", error.GetType().Name);
            reply = RemoteWire.Failure(message.Id, "internal-error");
        }

        try
        {
            SecureSession? session = peer.Session;
            if (session is null)
            {
                return;
            }

            await SendSealedAsync(channel, peer, session, reply, stop);
            if (close)
            {
                await Drop(channel, peer, peers, null, stop);
            }
        }
        catch (Exception error) when (error is SecureChannelException or OperationCanceledException or IOException or System.Net.WebSockets.WebSocketException or ObjectDisposedException)
        {
            // The session or the relay is gone.
        }
        finally
        {
            // Sent or not, the values of a delivery are zeroed here, and the reply (the only other holder) is dropped.
            delivery?.Zero();
        }
    }

    /// <summary>
    /// A launch at this authority: approval and decryption happen here (see <see cref="AuthorityLaunchHandler" />). It is not run through <see cref="Remembered" />: an answer that carries values is never kept,
    /// and an id that was used in this session gets <c>request-id-reused</c> and nothing else (a delivery is one-time). The approval link goes to the host as soon as the page exists.
    /// </summary>
    private async Task<(string Reply, SecretsDelivery? Delivery)> LaunchAsync(WebSocketChannel channel, Peer peer, WireMessage message, CancellationToken stop)
    {
        if (launches is null)
        {
            return (RemoteWire.Failure(message.Id, "unsupported"), null);
        }

        if (!RemoteWire.TryRead(message.Body, out LaunchAuthorize? launch) || launch is null || message.Id != "launch:" + launch.Decide.Request.RequestId)
        {
            return (RemoteWire.Failure(message.Id, "bad-request"), null);
        }

        if (!string.Equals(launch.Decide.MachineFingerprint, peer.Machine, StringComparison.Ordinal) || !string.Equals(launch.Use.MachineFingerprint, peer.Machine, StringComparison.Ordinal))
        {
            return (RemoteWire.Failure(message.Id, "wrong-machine"), null);
        }

        lock (peer.Gate)
        {
            if (peer.LaunchIds.Count >= MaxLaunchesPerSession || !peer.LaunchIds.Add(message.Id))
            {
                return (RemoteWire.Failure(message.Id, "request-id-reused"), null);
            }
        }

        int sequence = 0;
        void Link(string link)
        {
            // Told to the host as the page exists; a link that cannot be sent leaves the person without it, and the request ends at its time limit.
            try
            {
                SecureSession? session = peer.Session;
                if (session is not null && ApprovalLinkNotice.IsSafe(link))
                {
                    string push = RemoteWire.Request("link-" + Guid.NewGuid().ToString("N"), RemoteOps.ApprovalLink, new ApprovalLinkNotice(launch.Decide.Request.RequestId, Interlocked.Increment(ref sequence), link).ToJson());
                    SendSealedAsync(channel, peer, session, push, stop).GetAwaiter().GetResult();
                }
            }
            catch (Exception error) when (error is SecureChannelException or OperationCanceledException or IOException or System.Net.WebSockets.WebSocketException or ObjectDisposedException)
            {
                // The session is gone.
            }
        }

        LaunchAnswer answer = await launches.AuthorizeAsync(peer.Machine, launch, Link, peer.Ended.Token);

        return (RemoteWire.Response(message.Id, answer.ToJson()), answer.Delivery);
    }

    /// <summary>
    /// One logical operation runs once per session: the same id with the same content returns the same answer (the one in flight, or the one already given); the same id with other content is refused.
    /// Across sessions and restarts the local authority's stored results (<c>processed_requests</c>) make a retry idempotent.
    /// </summary>
    private Task<string> Remembered(Peer peer, WireMessage message)
    {
        string digest = RemoteWire.Digest(message.Op + "\n" + message.Body);
        Task<string> task;
        lock (peer.Gate)
        {
            if (peer.Known.TryGetValue(message.Id, out (string Digest, Task<string> Result) known))
            {
                return known.Digest == digest ? known.Result : Task.FromResult(RemoteWire.Failure(message.Id, "request-id-reused"));
            }

            task = Task.Run(() => DispatchAsync(peer, message), peer.Ended.Token);
            peer.Known[message.Id] = (digest, task);
            peer.Order.Enqueue(message.Id);
            while (peer.Order.Count > MaxRemembered)
            {
                peer.Known.Remove(peer.Order.Dequeue());
            }
        }

        return task;
    }

    private async Task<string> DispatchAsync(Peer peer, WireMessage message)
    {
        string id = message.Id;
        string body = message.Body;
        CancellationToken cancel = peer.Ended.Token;
        string Fail(string code) => RemoteWire.Failure(id, code);
        string Ok(string json) => RemoteWire.Response(id, json);
        bool Mine(string fingerprint) => string.Equals(fingerprint, peer.Machine, StringComparison.Ordinal);

        switch (message.Op)
        {
            case RemoteOps.BeginEnrollment:
                return Ok(RemoteWire.WriteChallenge(await authority.BeginEnrollmentAsync(cancel)));
            case RemoteOps.Enroll:
                if (!RemoteWire.TryRead(body, out EnrollmentRequest? enrollment) || enrollment is null)
                {
                    return Fail("bad-request");
                }

                // The machine that enrolls is the one that proved its key in the handshake, not another.
                if (!Mine(enrollment.Fingerprint) || !enrollment.PublicKey.AsSpan().SequenceEqual(peer.MachineKey))
                {
                    return Fail("wrong-machine");
                }

                return Ok(RemoteWire.Write(await authority.EnrollAsync(enrollment, cancel)));
            case RemoteOps.Decide:
                if (!RemoteWire.TryRead(body, out MachineRequestEnvelope? envelope) || envelope is null)
                {
                    return Fail("bad-request");
                }

                return Mine(envelope.MachineFingerprint) ? Ok((await authority.DecideAsync(envelope, cancel)).ToJson()) : Fail("wrong-machine");
            case RemoteOps.Grant:
                if (!RemoteWire.TryRead(body, out GrantEnvelope? grant) || grant is null)
                {
                    return Fail("bad-request");
                }

                return Mine(grant.MachineFingerprint) ? Ok((await authority.GrantAsync(grant, cancel)).ToJson()) : Fail("wrong-machine");
            case RemoteOps.Reconcile:
                if (!RemoteWire.TryRead(body, out ReconcileEnvelope? reconcile) || reconcile is null)
                {
                    return Fail("bad-request");
                }

                return Mine(reconcile.MachineFingerprint) ? Ok(RemoteWire.Write(await authority.ReconcileAsync(reconcile, cancel))) : Fail("wrong-machine");
            case RemoteOps.KeyTransitions:
                return RemoteWire.TryReadText(body, "after", out string after) ? Ok(RemoteWire.Write(await authority.KeyTransitionsAsync(after, cancel))) : Fail("bad-request");
            case RemoteOps.PendingInvalidations:
                if (!RemoteWire.TryReadText(body, "fingerprint", out string pendingFor))
                {
                    return Fail("bad-request");
                }

                return Mine(pendingFor) ? Ok(RemoteWire.Write(await authority.PendingInvalidationsAsync(pendingFor, cancel))) : Fail("wrong-machine");
            case RemoteOps.AcknowledgeInvalidation:
                if (!RemoteWire.TryReadAck(body, true, out string ackFor, out long revision) || revision is < 0 or > int.MaxValue)
                {
                    return Fail("bad-request");
                }

                if (!Mine(ackFor))
                {
                    return Fail("wrong-machine");
                }

                await authority.AcknowledgeInvalidationAsync(ackFor, (int)revision, cancel);

                return Ok(RemoteWire.Empty);
            case RemoteOps.PendingGrantEvents:
                if (!RemoteWire.TryReadText(body, "fingerprint", out string eventsFor))
                {
                    return Fail("bad-request");
                }

                return Mine(eventsFor) ? Ok(RemoteWire.Write(await authority.PendingGrantEventsAsync(eventsFor, cancel))) : Fail("wrong-machine");
            case RemoteOps.AcknowledgeGrantEvent:
                if (!RemoteWire.TryReadAck(body, false, out string noticeFor, out long sequence))
                {
                    return Fail("bad-request");
                }

                if (!Mine(noticeFor))
                {
                    return Fail("wrong-machine");
                }

                await authority.AcknowledgeGrantEventAsync(noticeFor, sequence, cancel);

                return Ok(RemoteWire.Empty);
            case RemoteOps.AuditUpload:
                if (!RemoteWire.TryRead(body, out AuditBatch? batch) || batch is null)
                {
                    return Fail("bad-request");
                }

                return Mine(batch.MachineFingerprint) ? Ok(RemoteWire.Write(await authority.UploadAsync(batch, cancel))) : Fail("wrong-machine");
            default:
                return Fail("unknown-operation");
        }
    }

    /// <summary>Sends the machine's unacknowledged invalidations, and again every interval until the host acknowledges them (the host's acknowledgement is an ordinary operation).</summary>
    private async Task PushLoopAsync(WebSocketChannel channel, Peer peer, ConcurrentDictionary<Guid, Peer> peers, CancellationToken stop)
    {
        try
        {
            using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(stop, peer.Ended.Token);
            while (!linked.IsCancellationRequested)
            {
                if (Locked)
                {
                    await Drop(channel, peer, peers, null, stop);

                    return;
                }

                foreach (PendingInvalidation item in await authority.PendingInvalidationsAsync(peer.Machine, linked.Token))
                {
                    SecureSession? session = peer.Session;
                    if (session is null)
                    {
                        return;
                    }

                    string push = RemoteWire.Request("push-" + Guid.NewGuid().ToString("N"), RemoteOps.PushInvalidation, RemoteWire.WriteAck(item.Fingerprint, item.Revision, true));
                    await SendSealedAsync(channel, peer, session, push, stop);
                    Interlocked.Increment(ref _pushed);
                }

                await Task.Delay(_options.PushInterval, linked.Token);
            }
        }
        catch (Exception error) when (error is OperationCanceledException or SecureChannelException or IOException or System.Net.WebSockets.WebSocketException or ObjectDisposedException)
        {
            // The session ended.
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            AppLog.Warn("pushing invalidations failed: {Type}", error.GetType().Name);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        try
        {
            await _loop.WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch (Exception error) when (error is OperationCanceledException or TimeoutException)
        {
            // Stopped as far as it goes.
        }

        _stop.Dispose();
    }
}

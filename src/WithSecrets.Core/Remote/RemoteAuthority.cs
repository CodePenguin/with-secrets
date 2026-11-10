using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text;

namespace WithSecrets;

/// <summary>The authority could not be reached, or the session broke (connection, handshake, a frame that did not authenticate). The host treats it as "authority unavailable".</summary>
public sealed class RemoteTransportException(string message, bool reportsLocked = false) : IOException(message)
{
    /// <summary>The authority said "locked" before the session was authenticated. It proves nothing (anyone on the path can send it), so it only chooses the wording; the run is denied either way.</summary>
    public bool ReportsLocked { get; } = reportsLocked;
}

/// <summary>The authority answered over a good session with a refusal code (for example <c>locked</c> or <c>wrong-machine</c>). Retrying the same message would not help.</summary>
public sealed class RemoteRefusedException(string code) : InvalidOperationException("the remote authority refused the request: " + code)
{
    public string Code { get; } = code;
}

/// <summary>
/// The host service's client of a remote authority: <see cref="IAuthority" /> and <see cref="IAuditSink" /> over an end-to-end encrypted session through the relay. It performs a
/// fresh mutually authenticated handshake for each connection (the machine key proves the host; the authority must be signed by the key this host trusts), sends the canonical,
/// versioned messages of the existing contracts and nothing else, and on a dropped connection reconnects with new keys and repeats the operation under the SAME id, which the authority
/// answers from its committed results. It adds no trust of its own: the host still verifies every signed answer exactly as it does for the local authority.
/// </summary>
public sealed class RemoteAuthority : IAuthority, IAuditSink, ILaunchAuthority, IDisposable
{
    private readonly RemoteAuthorityConfig _config;
    private readonly ISigningKey _machineKey;
    private readonly HostConfigFile _hostConfig;
    private readonly Func<CancellationToken, Task<IMessageChannel>> _connect;
    private readonly TimeProvider _clock;
    private readonly SemaphoreSlim _connecting = new(1, 1);
    private readonly Lock _lock = new();
    private Link? _link;
    private int _disposed;
    private int _connections;
    private int _pushed;
    private readonly ConcurrentDictionary<string, Action<ApprovalLinkNotice>> _links = new(StringComparer.Ordinal);

    public RemoteAuthority(RemoteAuthorityConfig config, ISigningKey machineKey, HostConfigFile hostConfig, TimeProvider? clock = null)
        : this(config, machineKey, hostConfig, async cancel => await WebSocketChannel.ConnectAsync(config, RelayServer.HostPath, cancel), clock)
    {
    }

    internal RemoteAuthority(RemoteAuthorityConfig config, ISigningKey machineKey, HostConfigFile hostConfig, Func<CancellationToken, Task<IMessageChannel>> connect, TimeProvider? clock = null)
    {
        if (RemoteTarget.Problem(config) is { } problem)
        {
            throw new ArgumentException(problem);
        }

        _config = config;
        _machineKey = machineKey;
        _hostConfig = hostConfig;
        _connect = connect;
        _clock = clock ?? TimeProvider.System;
    }

    /// <summary>How often a message is repeated (same id, a new session) after the connection broke before the call fails.</summary>
    public int Retries { get; init; } = 2;

    /// <summary>How long the handshake may take.</summary>
    public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>The pause before a retry.</summary>
    public TimeSpan RetryPause { get; init; } = TimeSpan.FromMilliseconds(150);

    /// <summary>How many sessions were established (each with new keys).</summary>
    public int Connections => Volatile.Read(ref _connections);

    /// <summary>The id (public) of the session in use, or an empty string.</summary>
    public string SessionId
    {
        get
        {
            lock (_lock)
            {
                return _link is { Dead: false } link ? link.Session.Id : "";
            }
        }
    }

    /// <summary>How many invalidation notices the authority pushed.</summary>
    public int Pushed => Volatile.Read(ref _pushed);

    /// <summary>Raised when the authority pushes an invalidation notice (a prompt to look at the pending list; the list is the source of truth).</summary>
    public event Action<PendingInvalidation>? InvalidationNotified;

    /// <summary>Ends the current session (the next call connects again with new keys).</summary>
    public void Disconnect()
    {
        Link? link;
        lock (_lock)
        {
            link = _link;
            _link = null;
        }

        link?.Kill();
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
        {
            return;
        }

        Disconnect();
        _connecting.Dispose();
    }

    private sealed class Link(IMessageChannel channel, SecureSession session) : IDisposable
    {
        private readonly CancellationTokenSource _ended = new();
        private int _dead;

        public IMessageChannel Channel { get; } = channel;

        public SecureSession Session { get; } = session;

        public SemaphoreSlim SendLock { get; } = new(1, 1);

        public ConcurrentDictionary<string, TaskCompletionSource<WireMessage>> Pending { get; } = new(StringComparer.Ordinal);

        public bool Dead => Volatile.Read(ref _dead) == 1;

        public CancellationToken Ended => _ended.Token;

        public void Kill()
        {
            if (Interlocked.Exchange(ref _dead, 1) == 1)
            {
                return;
            }

            _ended.Cancel();
            Channel.Dispose();
            Session.Dispose();
            foreach (TaskCompletionSource<WireMessage> waiting in Pending.Values)
            {
                waiting.TrySetException(new RemoteTransportException("the session ended"));
            }
        }

        public void Dispose() => Kill();
    }

    private int _warnedPin;

    private TrustedAuthority Trusted()
    {
        HostConfigLoad load = _hostConfig.Load();
        if (load.Problem is not null)
        {
            throw new RemoteTransportException("host.json cannot be used");
        }

        if (load.Config?.Authority is { } pinned)
        {
            if (!string.Equals(pinned.Fingerprint, _config.AuthorityFingerprint, StringComparison.OrdinalIgnoreCase) && Interlocked.Exchange(ref _warnedPin, 1) == 0)
            {
                AppLog.Warn("host.json names authority key {Configured} but this host trusts the pinned key {Pinned}; only a rotation signed by the pinned key can change that", _config.AuthorityFingerprint, pinned.Fingerprint);
            }

            return new TrustedAuthority(pinned.Fingerprint, pinned.PublicKey);
        }

        return new TrustedAuthority(_config.AuthorityFingerprint, null);
    }

    private async Task<Link> EnsureLinkAsync(CancellationToken cancel)
    {
        lock (_lock)
        {
            if (_link is { Dead: false } alive)
            {
                return alive;
            }
        }

        await _connecting.WaitAsync(cancel);
        try
        {
            lock (_lock)
            {
                if (_link is { Dead: false } alive)
                {
                    return alive;
                }
            }

            Link link = await HandshakeAsync(cancel);
            lock (_lock)
            {
                _link = link;
            }

            Interlocked.Increment(ref _connections);
            _ = Task.Run(() => ReadAsync(link));

            return link;
        }
        finally
        {
            _connecting.Release();
        }
    }

    private async Task<Link> HandshakeAsync(CancellationToken cancel)
    {
        IMessageChannel channel;
        try
        {
            channel = await _connect(cancel);
        }
        catch (Exception error) when (error is WebSocketException or IOException or HttpRequestException or System.Security.Authentication.AuthenticationException or InvalidOperationException || error is OperationCanceledException && !cancel.IsCancellationRequested)
        {
            throw new RemoteTransportException("the relay cannot be reached (" + error.GetType().Name + ")");
        }

        try
        {
            using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(cancel);
            limit.CancelAfter(HandshakeTimeout);
            TrustedAuthority trust = Trusted();
            using InitiatorHandshake handshake = new(_machineKey, trust);
            await channel.SendAsync(handshake.Hello(), limit.Token);
            byte[] serverHello = await channel.ReceiveAsync(limit.Token) ?? throw new RemoteTransportException("the relay closed the connection");
            if (ChannelFormat.ErrorCode(serverHello) is { } refused)
            {
                throw new RemoteTransportException("the authority refused the connection (" + refused + ")", refused == "locked");
            }

            (byte[] auth, SecureSession session, byte[] authorityKey, byte[] expectedReady) = handshake.Complete(serverHello);
            await channel.SendAsync(auth, limit.Token);
            byte[] first = await channel.ReceiveAsync(limit.Token) ?? throw new RemoteTransportException("the connection closed before the authority confirmed the keys");
            if (!session.Open(first).AsSpan().SequenceEqual(expectedReady))
            {
                throw new SecureChannelException("the authority's confirmation is not for this session");
            }

            // The authority is who the configured fingerprint says. Until an administrator's approval pins the whole key (the enrollment flow does), the key that proved it is pinned here.
            if (trust.PublicKey is null)
            {
                HostConfigLoad load = _hostConfig.Load();
                if (load.Config is { Authority: null } config && string.Equals(config.MachineFingerprint, KeyIdentity.Fingerprint(_machineKey.PublicKey), StringComparison.Ordinal))
                {
                    _hostConfig.Pin(config.MachineFingerprint, new PinnedAuthorityKey(KeyIdentity.Fingerprint(authorityKey), authorityKey, _clock.GetUtcNow()));
                }
            }

            return new Link(channel, session);
        }
        catch (Exception error) when (error is SecureChannelException or WebSocketException or IOException or System.Security.Cryptography.CryptographicException || error is OperationCanceledException && !cancel.IsCancellationRequested)
        {
            channel.Dispose();
            if (error is RemoteTransportException)
            {
                throw;
            }

            throw new RemoteTransportException("the authority could not be authenticated or reached (" + error.GetType().Name + ")");
        }
        catch
        {
            channel.Dispose();

            throw;
        }
    }

    private async Task ReadAsync(Link link)
    {
        try
        {
            while (await link.Channel.ReceiveAsync(link.Ended) is { } frame)
            {
                if (ChannelFormat.ErrorCode(frame) is not null)
                {
                    break;
                }

                byte[] plaintext = link.Session.Open(frame);
                if (!RemoteWire.TryReadMessage(plaintext, out WireMessage? message) || message is null)
                {
                    break;
                }

                if (message.IsRequest)
                {
                    if (message.Op == RemoteOps.PushInvalidation && RemoteWire.TryReadAck(message.Body, true, out string fingerprint, out long revision) && revision is >= 0 and <= int.MaxValue)
                    {
                        Interlocked.Increment(ref _pushed);
                        InvalidationNotified?.Invoke(new PendingInvalidation(fingerprint, (int)revision));
                    }

                    if (message.Op == RemoteOps.ApprovalLink && ApprovalLinkNotice.TryRead(message.Body, out ApprovalLinkNotice? notice) && notice is not null && _links.TryGetValue(notice.RequestId, out Action<ApprovalLinkNotice>? listener))
                    {
                        listener(notice);
                    }

                    continue;
                }

                if (link.Pending.TryGetValue(message.Id, out TaskCompletionSource<WireMessage>? waiting))
                {
                    waiting.TrySetResult(message);
                }
            }
        }
        catch (Exception error) when (error is SecureChannelException or OperationCanceledException or IOException or WebSocketException or ObjectDisposedException)
        {
            // The session ended or broke; every waiting call fails and the next one reconnects.
        }
        finally
        {
            lock (_lock)
            {
                if (ReferenceEquals(_link, link))
                {
                    _link = null;
                }
            }

            link.Kill();
        }
    }

    /// <summary>Sends one operation and returns the body of the answer. A broken session is replaced and the message sent again under the same id, up to <see cref="Retries" /> times.</summary>
    private async Task<string> CallAsync(string op, string id, string body, CancellationToken cancel, bool repeatAfterSend = true)
    {
        if (Volatile.Read(ref _disposed) == 1)
        {
            throw new ObjectDisposedException(nameof(RemoteAuthority));
        }

        string request = RemoteWire.Request(id, op, body);
        for (int attempt = 0; ; attempt++)
        {
            Link? link = null;
            bool sent = false;
            try
            {
                link = await EnsureLinkAsync(cancel);
                TaskCompletionSource<WireMessage> waiting = link.Pending.GetOrAdd(id, _ => new TaskCompletionSource<WireMessage>(TaskCreationOptions.RunContinuationsAsynchronously));
                await link.SendLock.WaitAsync(cancel);
                try
                {
                    sent = true;
                    await link.Channel.SendAsync(link.Session.Seal(Encoding.UTF8.GetBytes(request)), cancel);
                }
                finally
                {
                    link.SendLock.Release();
                }

                WireMessage answer = await waiting.Task.WaitAsync(cancel);
                link.Pending.TryRemove(id, out _);
                if (!answer.Ok)
                {
                    throw new RemoteRefusedException(answer.Error);
                }

                return answer.Body;
            }
            catch (Exception error) when ((error is RemoteTransportException or SecureChannelException or IOException or WebSocketException or ObjectDisposedException) && Volatile.Read(ref _disposed) == 0)
            {
                link?.Pending.TryRemove(id, out _);
                if (link is not null)
                {
                    lock (_lock)
                    {
                        if (ReferenceEquals(_link, link))
                        {
                            _link = null;
                        }
                    }

                    link.Kill();
                }

                // A message that must not be repeated (a launch: a second one could show a second page or deliver twice) is never sent again once its send began.
                if (attempt >= Retries || cancel.IsCancellationRequested || sent && !repeatAfterSend)
                {
                    throw error as RemoteTransportException ?? new RemoteTransportException("the authority could not be reached (" + error.GetType().Name + ")");
                }

                await Task.Delay(RetryPause, cancel);
            }
        }
    }

    private static string Unreadable() => "the authority's answer could not be read";

    // ---- IAuthority ----

    public async Task<AuthorityResponse> DecideAsync(MachineRequestEnvelope envelope, CancellationToken cancel = default)
    {
        string body = await CallAsync(RemoteOps.Decide, "decide:" + envelope.Request.RequestId, RemoteWire.Write(envelope), cancel);

        return AuthorityResponse.TryParse(body, out AuthorityResponse? response, out _) ? response! : throw new RemoteTransportException(Unreadable());
    }

    public async Task<byte[]> BeginEnrollmentAsync(CancellationToken cancel = default)
    {
        string body = await CallAsync(RemoteOps.BeginEnrollment, "begin-enrollment:" + Guid.NewGuid().ToString("N"), RemoteWire.Empty, cancel);

        return RemoteWire.TryReadChallenge(body, out byte[] challenge) ? challenge : throw new RemoteTransportException(Unreadable());
    }

    public async Task<EnrollmentResult> EnrollAsync(EnrollmentRequest request, CancellationToken cancel = default)
    {
        string body = await CallAsync(RemoteOps.Enroll, "enroll:" + Guid.NewGuid().ToString("N"), RemoteWire.Write(request), cancel);

        return RemoteWire.TryRead(body, out EnrollmentResult? result) ? result! : throw new RemoteTransportException(Unreadable());
    }

    public async Task<IReadOnlyList<KeyTransition>> KeyTransitionsAsync(string afterKeyFingerprint, CancellationToken cancel = default)
    {
        string body = await CallAsync(RemoteOps.KeyTransitions, "key-transitions:" + Guid.NewGuid().ToString("N"), RemoteWire.WriteAfter(afterKeyFingerprint), cancel);

        return RemoteWire.TryReadTransitions(body, out List<KeyTransition> transitions) ? transitions : throw new RemoteTransportException(Unreadable());
    }

    public async Task<IReadOnlyList<PendingInvalidation>> PendingInvalidationsAsync(string machineFingerprint, CancellationToken cancel = default)
    {
        string body = await CallAsync(RemoteOps.PendingInvalidations, "pending-invalidations:" + Guid.NewGuid().ToString("N"), RemoteWire.WriteFingerprint(machineFingerprint), cancel);

        return RemoteWire.TryReadInvalidations(body, out List<PendingInvalidation> items) ? items : throw new RemoteTransportException(Unreadable());
    }

    public async Task AcknowledgeInvalidationAsync(string machineFingerprint, int revision, CancellationToken cancel = default)
    {
        await CallAsync(RemoteOps.AcknowledgeInvalidation, "ack-invalidation:" + machineFingerprint + ":" + revision, RemoteWire.WriteAck(machineFingerprint, revision, true), cancel);
    }

    public async Task<GrantResponse> GrantAsync(GrantEnvelope envelope, CancellationToken cancel = default)
    {
        string body = await CallAsync(RemoteOps.Grant, "grant:" + envelope.Operation + ":" + envelope.Request.RequestId, RemoteWire.Write(envelope), cancel);

        return GrantResponse.TryParse(body, out GrantResponse? response, out _) ? response! : throw new RemoteTransportException(Unreadable());
    }

    public async Task<ReconcileResponse> ReconcileAsync(ReconcileEnvelope envelope, CancellationToken cancel = default)
    {
        string body = await CallAsync(RemoteOps.Reconcile, "reconcile:" + envelope.RequestId, RemoteWire.Write(envelope), cancel);

        return RemoteWire.TryRead(body, out ReconcileResponse? response) ? response! : throw new RemoteTransportException(Unreadable());
    }

    public async Task<IReadOnlyList<PendingGrantEvent>> PendingGrantEventsAsync(string machineFingerprint, CancellationToken cancel = default)
    {
        string body = await CallAsync(RemoteOps.PendingGrantEvents, "pending-grant-events:" + Guid.NewGuid().ToString("N"), RemoteWire.WriteFingerprint(machineFingerprint), cancel);

        return RemoteWire.TryReadGrantEvents(body, out List<PendingGrantEvent> items) ? items : throw new RemoteTransportException(Unreadable());
    }

    public async Task AcknowledgeGrantEventAsync(string machineFingerprint, long sequence, CancellationToken cancel = default)
    {
        await CallAsync(RemoteOps.AcknowledgeGrantEvent, "ack-grant-event:" + machineFingerprint + ":" + sequence, RemoteWire.WriteAck(machineFingerprint, sequence, false), cancel);
    }

    // ---- ILaunchAuthority ----

    public async Task<LaunchAnswer> AuthorizeLaunchAsync(LaunchAuthorize message, Action<ApprovalLinkNotice> onLink, CancellationToken cancel)
    {
        string requestId = message.Decide.Request.RequestId;
        if (!_links.TryAdd(requestId, onLink))
        {
            throw new InvalidOperationException("a launch with this request id is already waiting");
        }

        try
        {
            string body = await CallAsync(RemoteOps.LaunchAuthorize, "launch:" + requestId, RemoteWire.Write(message), cancel, repeatAfterSend: false);

            return LaunchAnswer.TryRead(body, out LaunchAnswer? answer) ? answer! : throw new RemoteTransportException(Unreadable());
        }
        finally
        {
            _links.TryRemove(requestId, out _);
        }
    }

    // ---- IAuditSink ----

    public async Task<AuditAck> UploadAsync(AuditBatch batch, CancellationToken cancel = default)
    {
        string body = await CallAsync(RemoteOps.AuditUpload, "audit:" + batch.BatchId, RemoteWire.Write(batch), cancel);

        return RemoteWire.TryRead(body, out AuditAck? ack) ? ack! : throw new RemoteTransportException(Unreadable());
    }
}

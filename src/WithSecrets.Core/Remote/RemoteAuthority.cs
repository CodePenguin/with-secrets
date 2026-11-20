using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace WithSecrets;

/// <summary>The authority could not be reached, or what came back is not what the protocol allows (a refused handshake, a redirect, a body that is not the one JSON form). The host treats it as "authority unavailable".</summary>
public sealed class RemoteTransportException(string message) : IOException(message);


/// <summary>The authority answered over the authenticated connection with a refusal code (for example <c>locked</c>, <c>machine-not-trusted</c> or <c>wrong-machine</c>). Retrying the same message would not help.</summary>
public sealed class RemoteRefusedException(string code) : InvalidOperationException("the remote authority refused the request: " + code)
{
    public string Code { get; } = code;
}

/// <summary>What the long poll brought: the existing invalidation payload or the existing grant-revocation payload (one of them is not empty).</summary>
public sealed record AuthorityNotices(IReadOnlyList<PendingInvalidation> Invalidations, IReadOnlyList<PendingGrantEvent> GrantEvents);

/// <summary>Where a host gets its invalidation and grant-revocation messages from a remote authority: by one outstanding long poll, not by asking on a timer.</summary>
public interface INoticeSource
{
    /// <summary>Holds one request at the authority until the existing protocol has a message for this machine and returns its payload. A request that ends without one (cancelled, the connection broke) throws.</summary>
    Task<AuthorityNotices> PollAsync(string machineFingerprint, CancellationToken cancel);
}

/// <summary>
/// The host service's client of a remote authority: <see cref="IAuthority" /> and <see cref="IAuditSink" /> over HTTPS (TLS 1.3 mutual authentication, HTTP/2 only) directly to the ONE configured authority. TLS authenticates both
/// sides: this host presents its temporary certificate (signed by its machine identity key), and the authority's temporary certificate is validated against the configured authority identity certificate ALONE (never a trust
/// store, never an accept-anything callback; DNS names and addresses are routing, not identity). There is no relay, no redirect, no ambient proxy, no cache, no compression and no fallback address. The canonical, versioned
/// messages of the existing contracts travel in the request and response bodies; the host verifies every signed answer exactly as it does for the local authority.
/// <para>
/// Connections are kept (no idle or age limit). When the temporary certificate is replaced a new connection pool is made for new requests and the old one is drained and disposed after a bounded wait; a healthy connection
/// is never cut because the certificate it started with has since been replaced. A message that fails in transport is repeated under the SAME id up to <see cref="Retries" /> times with bounded exponential backoff and jitter
/// (the authority answers a repeat from its committed results); a launch is sent once and never repeated after the send began.
/// </para>
/// </summary>
public sealed class RemoteAuthority : IAuthority, IAuditSink, ILaunchAuthority, INoticeSource, IDisposable
{
    private const int MaxResponseBytes = 16 * 1024 * 1024;

    private readonly RemoteAuthorityConfig _config;
    private readonly TemporaryCertificate _tls;
    private readonly HostConfigFile _hostConfig;
    private readonly TimeProvider _clock;
    private readonly Uri _endpoint;
    private readonly Lock _lock = new();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, Action<ApprovalLinkNotice>> _links = new(StringComparer.Ordinal);
    private Pool? _pool;
    private CancellationTokenSource _rotation = new();
    private ITimer? _timer;
    private int _disposed;
    private int _connections;
    private int _pools;

    public RemoteAuthority(RemoteAuthorityConfig config, TemporaryCertificate tls, HostConfigFile hostConfig, TimeProvider? clock = null)
    {
        PlatformTls.EnableClientTls13();
        if (RemoteTarget.Problem(config) is { } problem)
        {
            throw new ArgumentException(problem);
        }

        RemoteTarget.Address(config.Endpoint, out Uri? endpoint);
        _config = config;
        _tls = tls;
        _hostConfig = hostConfig;
        _clock = clock ?? TimeProvider.System;
        _endpoint = endpoint!;
        ArmRotationTimer();
    }

    /// <summary>How often a message is repeated (same id) after the connection broke before the call fails.</summary>
    public int Retries { get; init; } = 2;

    /// <summary>The first pause before a repeat; it doubles each time (with jitter) up to <see cref="MaxRetryPause" />.</summary>
    public TimeSpan RetryPause { get; init; } = TimeSpan.FromMilliseconds(150);

    /// <summary>TEST ONLY: the local address connections are made from (default: the system chooses). A second client on another loopback address looks, to the authority, like a copy of the machine on another host.</summary>
    internal IPAddress? TestLocalAddress { get; init; }

    public TimeSpan MaxRetryPause { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>How long an ordinary request may take.</summary>
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>How long a connection of a replaced certificate may finish its requests before it is closed.</summary>
    public TimeSpan DrainTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>How long a TCP/TLS connect may take.</summary>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>The configured endpoint address (routing information; trust comes from the identity certificate).</summary>
    public Uri Endpoint => _endpoint;

    /// <summary>How many TLS connections were established (each a full certificate-authenticated handshake).</summary>
    public int Connections => Volatile.Read(ref _connections);

    /// <summary>How many connection pools were made (one per temporary certificate used).</summary>
    public int Pools => Volatile.Read(ref _pools);

    /// <summary>Raised when the connection to the authority ended unexpectedly (a poll or a request failed in transport, or the authority said <c>locked</c>): a host cancels the launches that have not started.</summary>
    public event Action? LinkEnded;

    /// <summary>
    /// Tells the authority this machine's renewed identity certificate (same key; <see cref="RemoteOps.RenewIdentity" />). The request id is made from the certificate, so repeating it is the same request. Returns true when the authority
    /// accepted it; the machine keeps using the old certificate until then.
    /// </summary>
    public async Task<bool> RenewIdentityAsync(byte[] identityCertificate, CancellationToken cancel = default)
    {
        string id = "renew-identity:" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(identityCertificate))[..32];
        string body = "{\"certificate\":\"" + Convert.ToBase64String(identityCertificate) + "\"}";
        try
        {
            await CallAsync(RemoteOps.RenewIdentity, id, body, cancel);

            return true;
        }
        catch (Exception error) when (error is RemoteTransportException or RemoteRefusedException)
        {
            return false;
        }
    }

    /// <summary>Closes every connection (the next call connects again with a fresh handshake).</summary>
    public void Disconnect()
    {
        Pool? pool;
        lock (_lock)
        {
            pool = _pool;
            _pool = null;
        }

        pool?.Dispose();
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
        {
            return;
        }

        _timer?.Dispose();
        Disconnect();
        try
        {
            _rotation.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // Done.
        }
    }

    // ---- the connection pool ----

    private sealed class Pool : IDisposable
    {
        private readonly HttpClient _client;
        private readonly SocketsHttpHandler _handler;
        private int _inFlight;
        private int _retired;
        private int _disposed;

        public Pool(SocketsHttpHandler handler, string thumbprint)
        {
            _handler = handler;
            _client = new HttpClient(handler, disposeHandler: false)
            {
                DefaultRequestVersion = HttpVersion.Version20,
                DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
                Timeout = Timeout.InfiniteTimeSpan,
            };
            Thumbprint = thumbprint;
        }

        public string Thumbprint { get; }

        public HttpClient Client => _client;

        public TaskCompletionSource Idle { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int InFlight => Volatile.Read(ref _inFlight);

        public void Enter() => Interlocked.Increment(ref _inFlight);

        public void Exit()
        {
            if (Interlocked.Decrement(ref _inFlight) == 0 && Volatile.Read(ref _retired) == 1)
            {
                Idle.TrySetResult();
            }
        }

        public void Retire()
        {
            Volatile.Write(ref _retired, 1);
            if (InFlight == 0)
            {
                Idle.TrySetResult();
            }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 1)
            {
                return;
            }

            _client.Dispose();
            _handler.Dispose();
        }
    }

    private Pool CurrentPool()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) == 1, this);
        X509Certificate2 certificate = _tls.Current;
        Pool? retired = null;
        lock (_lock)
        {
            if (_pool is { } existing && existing.Thumbprint == certificate.Thumbprint)
            {
                return existing;
            }

            Pool next = MakePool(certificate);
            retired = _pool;
            _pool = next;
            if (retired is not null)
            {
                // New requests use the new pool; a poll that is waiting on the old one is cancelled so it is asked again on the new connection (nothing is lost: the authority keeps the message until it is acknowledged).
                CancellationTokenSource old = _rotation;
                _rotation = new CancellationTokenSource();
                old.Cancel();
                old.Dispose();
            }
        }

        if (retired is not null)
        {
            DrainAsync(retired);
        }

        lock (_lock)
        {
            return _pool!;
        }
    }

    private async void DrainAsync(Pool old)
    {
        old.Retire();
        try
        {
            await Task.WhenAny(old.Idle.Task, Task.Delay(DrainTimeout, _clock));
        }
        catch (OperationCanceledException)
        {
            // Disposing anyway.
        }
        finally
        {
            old.Dispose();
        }
    }

    private Pool MakePool(X509Certificate2 certificate)
    {
        SocketsHttpHandler handler = new()
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None,
            PooledConnectionLifetime = Timeout.InfiniteTimeSpan,
            PooledConnectionIdleTimeout = Timeout.InfiniteTimeSpan,
            EnableMultipleHttp2Connections = false,
            ConnectTimeout = ConnectTimeout,

            // Ordinary network failure detection only: a dead path is noticed, a healthy one is never cut.
            KeepAlivePingPolicy = HttpKeepAlivePingPolicy.Always,
            KeepAlivePingDelay = TimeSpan.FromSeconds(30),
            KeepAlivePingTimeout = TimeSpan.FromSeconds(20),
            SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls13,
                ClientCertificates = [certificate],
                AllowTlsResume = false,
                ApplicationProtocols = [SslApplicationProtocol.Http2],
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                RemoteCertificateValidationCallback = ValidateAuthority,
            },
        };
        if (TestLocalAddress is { } local)
        {
            // TEST ONLY: connect from a chosen local address, so one authority sees two different remote addresses for one identity.
            handler.ConnectCallback = async (context, cancel) =>
            {
                Socket socket = new(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try
                {
                    socket.Bind(new IPEndPoint(local, 0));
                    await socket.ConnectAsync(context.DnsEndPoint, cancel);

                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();

                    throw;
                }
            };
        }

        Interlocked.Increment(ref _pools);

        return new Pool(handler, certificate.Thumbprint);
    }

    /// <summary>
    /// The only certificate rule of an outbound connection: the authority's temporary certificate must validate against the ONE configured authority identity certificate (its signature, validity, CA=false, key usage, both EKUs, and its
    /// SAN naming exactly that identity). The system's verdict (an untrusted root, a name that does not match the address) is ignored on purpose: the address is routing, the identity is the certificate.
    /// </summary>
    private bool ValidateAuthority(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
    {
        if (certificate is null)
        {
            return false;
        }

        try
        {
            using X509Certificate2 leaf = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
            if (MachineCertificates.ValidateLeaf(leaf, _config.AuthorityIdentityCertificate, _clock.GetUtcNow(), _config.AuthorityIdentityFingerprint) is not null)
            {
                return false;
            }
        }
        catch (Exception error) when (error is System.Security.Cryptography.CryptographicException or ArgumentException)
        {
            return false;
        }

        Interlocked.Increment(ref _connections);

        return true;
    }

    private void ArmRotationTimer()
    {
        TimeSpan due = _tls.NextRotation - _clock.GetUtcNow();
        if (due < TimeSpan.FromSeconds(1))
        {
            due = TimeSpan.FromSeconds(1);
        }

        _timer?.Dispose();
        _timer = _clock.CreateTimer(_ =>
        {
            if (Volatile.Read(ref _disposed) == 1)
            {
                return;
            }

            try
            {
                // Asking for the pool makes the replacement certificate and the new pool; the long poll moves to it.
                _ = CurrentPool();
                ArmRotationTimer();
            }
            catch (Exception error) when (error is ObjectDisposedException or System.Security.Cryptography.CryptographicException)
            {
                // Stopping.
            }
        }, null, due, Timeout.InfiniteTimeSpan);
    }

    // ---- requests ----

    private static bool IsJson(HttpContentHeaders headers) => headers.ContentType is { } type && string.Equals(type.MediaType, "application/json", StringComparison.OrdinalIgnoreCase) && (type.CharSet is null || string.Equals(type.CharSet, "utf-8", StringComparison.OrdinalIgnoreCase));

    private HttpRequestMessage Build(string op, string frame)
    {
        return new HttpRequestMessage(HttpMethod.Post, new Uri(_endpoint, MachineApi.OpPath(op)))
        {
            Version = HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
            Content = new StringContent(frame, new UTF8Encoding(false), "application/json"),
        };
    }

    /// <summary>Checks what the protocol allows of a response (HTTP/2, no redirect, the one JSON form) before anything is read.</summary>
    private static void CheckResponse(HttpResponseMessage response)
    {
        if (response.Version != HttpVersion.Version20)
        {
            throw new RemoteTransportException("the authority did not answer over HTTP/2");
        }

        if ((int)response.StatusCode is >= 300 and < 400)
        {
            throw new RemoteTransportException("the authority answered with a redirect, which is not followed");
        }

        if (response.Headers.Contains("Set-Cookie") || response.Content.Headers.ContentEncoding.Count > 0)
        {
            throw new RemoteTransportException("the authority's answer used a feature this protocol does not have");
        }

        if (!IsJson(response.Content.Headers))
        {
            throw new RemoteTransportException("the authority's answer is not UTF-8 JSON (HTTP " + (int)response.StatusCode + ")");
        }
    }

    private static async Task<WireMessage> ReadFrameAsync(HttpResponseMessage response, CancellationToken cancel)
    {
        CheckResponse(response);
        using Stream stream = await response.Content.ReadAsStreamAsync(cancel);
        using MemoryStream body = new();
        byte[] buffer = new byte[16 * 1024];
        int read;
        while ((read = await stream.ReadAsync(buffer, cancel)) > 0)
        {
            if (body.Length + read > MaxResponseBytes)
            {
                throw new RemoteTransportException("the authority's answer is too large");
            }

            body.Write(buffer, 0, read);
        }

        return Frame(body.ToArray(), response);
    }

    private static WireMessage Frame(byte[] bytes, HttpResponseMessage response)
    {
        if (!RemoteWire.TryReadMessage(bytes, out WireMessage? message) || message is null || message.IsRequest)
        {
            throw new RemoteTransportException("the authority's answer could not be read (HTTP " + (int)response.StatusCode + ")");
        }

        if (message.Ok != response.IsSuccessStatusCode)
        {
            throw new RemoteTransportException("the authority's answer contradicts its status");
        }

        return message;
    }

    private async Task<string> CallAsync(string op, string id, string body, CancellationToken cancel, bool repeatAfterSend = true, bool bounded = true)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) == 1, this);
        string frame = RemoteWire.Request(id, op, body);
        TimeSpan pause = RetryPause;
        for (int attempt = 0; ; attempt++)
        {
            bool sent = false;
            try
            {
                Pool pool = CurrentPool();
                pool.Enter();
                try
                {
                    using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(cancel);
                    if (bounded)
                    {
                        limit.CancelAfter(RequestTimeout);
                    }

                    using HttpRequestMessage request = Build(op, frame);
                    sent = true;
                    using HttpResponseMessage response = await pool.Client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, limit.Token);
                    WireMessage answer = await ReadFrameAsync(response, limit.Token);
                    if (!answer.Ok)
                    {
                        // A refusal that came before the request was read carries the listener's own correlation id instead of ours.
                        throw new RemoteRefusedException(answer.Error);
                    }

                    if (!string.Equals(answer.Id, id, StringComparison.Ordinal))
                    {
                        throw new RemoteTransportException("the authority's answer is for another request");
                    }

                    return answer.Body;
                }
                finally
                {
                    pool.Exit();
                }
            }
            catch (Exception error) when ((error is RemoteTransportException or HttpRequestException or IOException or AuthenticationException or ObjectDisposedException or OperationCanceledException) && !cancel.IsCancellationRequested)
            {
                if (Volatile.Read(ref _disposed) == 1)
                {
                    throw new RemoteTransportException("the authority link was closed");
                }

                // A message that must not be repeated (a launch: a second one could show a second page or deliver twice) is never sent again once its send began.
                if (attempt >= Retries || sent && !repeatAfterSend || error is RemoteTransportException)
                {
                    throw error as RemoteTransportException ?? new RemoteTransportException("the authority could not be reached (" + TransportFailure.Describe(error) + ")");
                }

                await Task.Delay(Jitter(pause), _clock, cancel);
                pause = TimeSpan.FromTicks(Math.Min(pause.Ticks * 2, MaxRetryPause.Ticks));
            }
        }
    }


    /// <summary>Between half and the whole of the pause (decorrelates hosts that lost the same authority at the same moment).</summary>
    private static TimeSpan Jitter(TimeSpan pause) => TimeSpan.FromTicks((long)(pause.Ticks * (0.5 + Random.Shared.NextDouble() / 2)));

    private static string Unreadable() => "the authority's answer could not be read";

    // ---- IAuthority ----

    public async Task<AuthorityResponse> DecideAsync(MachineRequestEnvelope envelope, CancellationToken cancel = default)
    {
        string body = await CallAsync(RemoteOps.Decide, "decide:" + envelope.Request.RequestId, RemoteWire.Write(envelope), cancel);

        return AuthorityResponse.TryParse(body, out AuthorityResponse? response, out _) ? response! : throw new RemoteTransportException(Unreadable());
    }

    /// <summary>First contact is pairing, which is not built yet: a machine becomes known to the authority only through the pairing route. This always refuses.</summary>
    public Task<byte[]> BeginEnrollmentAsync(CancellationToken cancel = default) => throw new RemoteRefusedException("not-implemented");

    /// <summary>See <see cref="BeginEnrollmentAsync" />.</summary>
    public Task<EnrollmentResult> EnrollAsync(EnrollmentRequest request, CancellationToken cancel = default) => throw new RemoteRefusedException("not-implemented");

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

    // ---- the long poll ----

    public async Task<AuthorityNotices> PollAsync(string machineFingerprint, CancellationToken cancel)
    {
        while (true)
        {
            CancellationToken rotation;
            lock (_lock)
            {
                rotation = _rotation.Token;
            }

            using CancellationTokenSource both = CancellationTokenSource.CreateLinkedTokenSource(cancel, rotation);
            try
            {
                // One attempt: a failed poll is not repeated here (the host's loop reconnects with backoff and checks in again). Not bounded in time: it ends with a message or a broken connection.
                string body = await CallAsync(RemoteOps.Poll, "poll:" + Guid.NewGuid().ToString("N"), RemoteWire.WriteFingerprint(machineFingerprint), both.Token, repeatAfterSend: false, bounded: false);
                if (RemoteWire.TryReadInvalidations(body, out List<PendingInvalidation> invalidations))
                {
                    return new AuthorityNotices(invalidations, []);
                }

                return RemoteWire.TryReadGrantEvents(body, out List<PendingGrantEvent> events) ? new AuthorityNotices([], events) : throw new RemoteTransportException(Unreadable());
            }
            catch (OperationCanceledException) when (rotation.IsCancellationRequested && !cancel.IsCancellationRequested)
            {
                // The certificate was replaced: ask again on the new connection.
                continue;
            }
            catch (Exception error) when (error is RemoteTransportException or RemoteRefusedException { Code: "locked" or "machine-not-trusted" })
            {
                LinkEnded?.Invoke();

                throw;
            }
        }
    }

    // ---- the authority's signing key ----

    /// <summary>
    /// A host that has no authority signing key pinned yet (its administrator approved it; nothing else was needed) learns it from the authority over the authenticated connection and pins it in host.json: the connection is
    /// to the authority identity this host was paired with, so the key it names is that authority's. Returns true when a key is pinned afterwards. Only a Trusted machine can ask; nothing changes when it cannot.
    /// </summary>
    public async Task<bool> EnsureAuthorityKeyPinnedAsync(CancellationToken cancel)
    {
        HostConfigLoad load = _hostConfig.Load();
        if (load.Problem is not null || load.Config is null)
        {
            return false;
        }

        if (load.Config.Authority is not null)
        {
            return true;
        }

        if (!string.Equals(load.Config.MachineFingerprint, _tls.IdentityFingerprint, StringComparison.Ordinal))
        {
            return false;
        }

        try
        {
            string body = await CallAsync(RemoteOps.AuthorityKey, "authority-key:" + Guid.NewGuid().ToString("N"), RemoteWire.Empty, cancel);
            if (!RemoteWire.TryReadText(body, "publicKey", out string text))
            {
                return false;
            }

            byte[] key = Convert.FromBase64String(text);
            if (!KeyIdentity.IsCanonicalP256(key))
            {
                return false;
            }

            // Re-read: nothing is pinned over a pin that appeared meanwhile.
            if (_hostConfig.Load().Config is { Authority: null } config && string.Equals(config.MachineFingerprint, _tls.IdentityFingerprint, StringComparison.Ordinal))
            {
                _hostConfig.Pin(config.MachineFingerprint, new PinnedAuthorityKey(KeyIdentity.Fingerprint(key), key, _clock.GetUtcNow()));
            }

            return true;
        }
        catch (Exception error) when (error is RemoteTransportException or RemoteRefusedException or FormatException)
        {
            return false;
        }
    }

    // ---- ILaunchAuthority ----

    public async Task<LaunchAnswer> AuthorizeLaunchAsync(LaunchAuthorize message, Action<ApprovalLinkNotice> onLink, CancellationToken cancel)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) == 1, this);
        string requestId = message.Decide.Request.RequestId;
        if (!_links.TryAdd(requestId, onLink))
        {
            throw new InvalidOperationException("a launch with this request id is already waiting");
        }

        try
        {
            string frame = RemoteWire.Request("launch:" + requestId, RemoteOps.LaunchAuthorize, RemoteWire.Write(message));
            Pool pool;
            try
            {
                pool = CurrentPool();
            }
            catch (Exception error) when (error is System.Security.Cryptography.CryptographicException or AuthenticationException)
            {
                throw new RemoteTransportException("the authority link could not be made (" + TransportFailure.Describe(error) + ")");
            }

            pool.Enter();
            try
            {
                using HttpRequestMessage request = Build(RemoteOps.LaunchAuthorize, frame);

                // Sent once: nothing below repeats it, whatever happens to the connection.
                using HttpResponseMessage response = await pool.Client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancel);
                CheckResponse(response);
                using Stream stream = await response.Content.ReadAsStreamAsync(cancel);
                using StreamReader lines = new(stream, new UTF8Encoding(false, true));
                long total = 0;
                while (await lines.ReadLineAsync(cancel) is { } line)
                {
                    total += line.Length;
                    if (total > MaxResponseBytes)
                    {
                        throw new RemoteTransportException("the authority's answer is too large");
                    }

                    if (!RemoteWire.TryReadMessage(Encoding.UTF8.GetBytes(line), out WireMessage? frameIn) || frameIn is null)
                    {
                        throw new RemoteTransportException(Unreadable());
                    }

                    if (frameIn.IsRequest)
                    {
                        if (frameIn.Op == RemoteOps.ApprovalLink && ApprovalLinkNotice.TryRead(frameIn.Body, out ApprovalLinkNotice? notice) && notice is not null && _links.TryGetValue(notice.RequestId, out Action<ApprovalLinkNotice>? listener))
                        {
                            listener(notice);
                        }

                        continue;
                    }

                    if (!frameIn.Ok)
                    {
                        throw new RemoteRefusedException(frameIn.Error);
                    }

                    if (!response.IsSuccessStatusCode)
                    {
                        throw new RemoteTransportException("the authority's answer contradicts its status");
                    }

                    return LaunchAnswer.TryRead(frameIn.Body, out LaunchAnswer? answer) ? answer! : throw new RemoteTransportException(Unreadable());
                }

                // A refusal before the stream started is one frame with an error status and no trailing newline: ReadLineAsync returned it above. Nothing came: the connection ended.
                throw new RemoteTransportException("the connection ended before the authority answered");
            }
            catch (Exception error) when (error is HttpRequestException or IOException or AuthenticationException or ObjectDisposedException)
            {
                throw new RemoteTransportException("the authority could not be reached (" + TransportFailure.Describe(error) + ")");
            }
            finally
            {
                pool.Exit();
            }
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

using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WithSecrets;

/// <summary>The fixed names of the machine API. Routes are an implementation choice; the transport policy is not.</summary>
public static class MachineApi
{
    public const string OpsPrefix = "/api/v1/machine/ops/";

    /// <summary>The single route that an unenrolled (but structurally valid) client certificate may reach: first contact and registration of a machine. It exists as a seam until pairing is implemented.</summary>
    public const string PairingPath = "/api/v1/pairing";

    public const string JsonType = "application/json; charset=utf-8";

    public static string OpPath(string op) => OpsPrefix + op;

    /// <summary>Every route of the machine listener, in the order they are documented (a test enumerates them).</summary>
    public static IReadOnlyList<string> Routes => [.. RemoteOps.Requests.Select(OpPath), PairingPath];
}

/// <summary>The kinds of peer a client certificate can be at the machine listener.</summary>
public enum PeerKind
{
    /// <summary>Not acceptable at all: no handshake.</summary>
    Rejected,

    /// <summary>Structurally valid, names a machine that is not enrolled here: it may reach the pairing route only.</summary>
    Provisional,

    /// <summary>The certificate chains to the enrolled identity certificate of the machine it names (its status is looked at on every request).</summary>
    Enrolled,
}

/// <summary>What the certificate says about the caller. The identity comes from the certificate alone.</summary>
public sealed record PeerIdentity(PeerKind Kind, string Fingerprint, string Reason);

/// <summary>
/// The narrow custom-root validation of an inbound client certificate: the machine identity is read from the SAN URI, THAT enrolled identity certificate is looked up, and the temporary leaf is validated against it
/// (signature, validity, CA=false, key usage, both EKUs, expected identity). No other root is tried. A certificate that names a machine nobody enrolled is "provisional" when its structure is sound: it can complete
/// the handshake so the pairing route can look at it, and is refused everywhere else.
/// </summary>
public sealed class MachinePeers(AuthorityStore store, TimeProvider clock)
{
    public PeerIdentity Classify(X509Certificate2 leaf, IEnumerable<X509Certificate2>? presented = null)
    {
        DateTimeOffset now = clock.GetUtcNow();
        if (MachineCertificates.SanFingerprint(leaf) is not { } fingerprint)
        {
            return new PeerIdentity(PeerKind.Rejected, "", "the certificate has no single, well-formed machine identity SAN");
        }

        MachineRecord? machine = store.Find(fingerprint);
        if (machine is not null)
        {
            if (store.Certificate(fingerprint) is not { } enrolled)
            {
                return new PeerIdentity(PeerKind.Rejected, fingerprint, "no identity certificate is enrolled for this machine");
            }

            return MachineCertificates.ValidateLeaf(leaf, enrolled, now, fingerprint) is { } problem ? new PeerIdentity(PeerKind.Rejected, fingerprint, problem) : new PeerIdentity(PeerKind.Enrolled, fingerprint, "");
        }

        if (MachineCertificates.ValidateLeafStructure(leaf, now, out _) is { } structure)
        {
            return new PeerIdentity(PeerKind.Rejected, fingerprint, structure);
        }

        // An identity certificate that arrived with it must really be the one the SAN names, and must have signed this leaf; the pairing route repeats the whole check on the identity it is given.
        foreach (X509Certificate2 extra in presented ?? [])
        {
            if (extra.Thumbprint != leaf.Thumbprint && string.Equals(MachineCertificates.FingerprintOf(extra.RawData), fingerprint, StringComparison.Ordinal) && MachineCertificates.ValidateLeaf(leaf, extra.RawData, now, fingerprint) is { } problem)
            {
                return new PeerIdentity(PeerKind.Rejected, fingerprint, problem);
            }
        }

        return new PeerIdentity(PeerKind.Provisional, fingerprint, "");
    }
}

/// <summary>What the pairing seam is handed: the HTTP request (already past the transport policy) and who the certificate says the caller is.</summary>
public sealed record PairingContext(HttpContext Http, PeerIdentity Peer, X509Certificate2 Certificate, byte[] Body);

/// <summary>The pairing route's handler (the one route an unenrolled certificate may reach). Without one (a listener nobody gave pairing to) the route answers 501 "not-implemented" and does nothing.</summary>
public interface IPairingHandler
{
    /// <summary>Handles the request (the body is already read, within the fixed limit). Returns the answer: a refusal code with its status, or the small JSON reply.</summary>
    Task<PairingReply> HandleAsync(PairingContext context, CancellationToken cancel);
}

internal sealed class NotImplementedPairing : IPairingHandler
{
    public Task<PairingReply> HandleAsync(PairingContext context, CancellationToken cancel) => Task.FromResult(new PairingReply(501, "not-implemented", null));
}

/// <summary>Where the machine listener listens, and (for tests) how it behaves. The limits are fixed built-in constants of the product; only a test narrows them.</summary>
public sealed class MachineListenerOptions
{
    /// <summary>The address to listen on: loopback (the default) or one specific address of a network. Never 0.0.0.0 or [::].</summary>
    public IPAddress Bind { get; init; } = IPAddress.Loopback;

    /// <summary>The port; 0 picks a free one (tests).</summary>
    public int Port { get; init; }

    /// <summary>Null when the address may be listened on, else why not.</summary>
    public string? Problem()
    {
        if (IPAddress.Any.Equals(Bind) || IPAddress.IPv6Any.Equals(Bind))
        {
            return "the machine endpoint will not listen on every interface (0.0.0.0 or [::]); name the one address it is for";
        }

        return Port is < 0 or > ToolSettings.MaxPort ? "the machine endpoint port must be 0 to " + ToolSettings.MaxPort : null;
    }

    /// <summary>Bytes in one request body.</summary>
    internal int MaxBodyBytes { get; init; } = 4 * 1024 * 1024;

    /// <summary>The pairing route's body limit.</summary>
    internal int MaxPairingBodyBytes { get; init; } = PairingProtocol.MaxBodyBytes;

    /// <summary>Requests being served at once, in all, and per machine. More are refused (429), never queued.</summary>
    internal int MaxConcurrent { get; init; } = 64;

    internal int MaxConcurrentPerMachine { get; init; } = 8;

    /// <summary>How long an ordinary operation may take before it is cancelled; a launch (it waits for a person) has its own limit. The long poll has none: it ends with a message, a closed connection or a revocation.</summary>
    internal TimeSpan OperationTimeout { get; init; } = TimeSpan.FromSeconds(30);

    internal TimeSpan LaunchTimeout { get; init; } = TimeSpan.FromMinutes(15);

    internal TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>After a machine's trust is withdrawn: GOAWAY first, the connections are closed after this.</summary>
    internal TimeSpan CloseGrace { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Launch ids remembered per machine while they can still be reused (one delivery per id): an id is forgotten once its request has expired (the request is then refused as expired by the handler), so the table is bounded by
    /// time and this count is only a ceiling on a burst of live requests.
    /// </summary>
    internal int MaxLaunchesPerMachine { get; init; } = 4096;

    /// <summary>HTTP/2 keep-alive: the server pings an idle connection this often and closes it when the ping is not answered within <see cref="Http2PingTimeout" /> (ordinary failure detection of a dead peer; not an idle timeout).</summary>
    internal TimeSpan Http2PingDelay { get; init; } = TimeSpan.FromSeconds(30);

    internal TimeSpan Http2PingTimeout { get; init; } = TimeSpan.FromSeconds(20);

    /// <summary>Open TLS connections in all (a fixed ceiling; a self-made certificate may connect, so the number is bounded).</summary>
    internal long MaxConnections { get; init; } = 256;

    /// <summary>For tests: called immediately before the final release checkpoint of a delivery.</summary>
    internal Action? BeforeRelease { get; set; }

    internal int MaxRemembered { get; init; } = 512;

    internal TimeProvider Clock { get; init; } = TimeProvider.System;

    internal IPairingHandler? Pairing { get; set; }
}

/// <summary>
/// The authority's machine listener (architecture 10.2): a Kestrel endpoint of its own, separate from the loopback browser and client APIs, that serves ONLY the machine API. TLS 1.3 and HTTP/2 only, no session resumption,
/// a mutual-TLS client certificate on every connection; the certificate it presents is the current temporary certificate of this running instance (chosen for each handshake). Every route requires the caller's certificate
/// to be validated against that machine's enrolled identity certificate AND the machine to be Trusted now; the one exception is the pairing route, which a structurally valid certificate of an unenrolled machine may reach
/// (and is a seam until pairing is built). The caller's identity is the certificate's, never a header or a field. The same <see cref="LocalAuthority" /> serves the operations (same logic, same <c>authority.db</c>, same
/// <c>processed_requests</c>): the listener adds transport policy and the binding of a request to the machine its certificate names, and it refuses everything while the authority is locked.
/// <para>
/// Policy: no redirects, no caching (<c>Cache-Control: no-store</c>, no validators, no conditional requests), no compression, UTF-8 <c>application/json</c> only, structured errors with a correlation id and no detail,
/// fixed limits (body size, concurrent requests in all and per machine, time; excess is refused, not queued). When a machine stops being Trusted (or the authority locks) its connections get GOAWAY and are closed after a bounded grace.
/// </para>
/// </summary>
public sealed class MachineListener : IDisposable
{
    private readonly LocalAuthority _authority;
    private readonly AuthorityKeyRing _keys;
    private readonly AuthorityStore _store;
    private readonly TemporaryCertificate _tls;
    private readonly MachineListenerOptions _options;
    private readonly IRemoteLaunchHandler? _launches;
    private readonly IPairingHandler _pairing;
    private readonly MachinePeers _peers;
    private readonly WebApplication _app;
    private readonly CancellationTokenSource _stop = new();
    private readonly ConcurrentDictionary<string, MachineState> _machines = new(StringComparer.Ordinal);
    private readonly MachineState _pairingState = new();
    private readonly ConcurrentDictionary<string, Connection> _connections = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, PeerIdentity> _established = new(StringComparer.Ordinal);
    private readonly Lock _signalLock = new();
    private TaskCompletionSource _changed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _global;
    private int _handshakeRejected;
    private int _requests;
    private int _closedByRevocation;
    private int _disposed;

    private sealed class Connection(string id, string fingerprint, IConnectionLifetimeNotificationFeature? notification, IConnectionLifetimeFeature? lifetime)
    {
        public string Id { get; } = id;

        public string Fingerprint { get; } = fingerprint;

        public IConnectionLifetimeNotificationFeature? Notification { get; } = notification;

        public IConnectionLifetimeFeature? Lifetime { get; } = lifetime;

        public int Closing;
    }

    private sealed class PollHold(CancellationTokenSource source)
    {
        public CancellationTokenSource Source { get; } = source;

        public bool Superseded { get; set; }
    }

    private sealed class MachineState
    {
        public Lock Gate { get; } = new();

        public Dictionary<string, (string Digest, Task<string> Result)> Known { get; } = new(StringComparer.Ordinal);

        public Queue<string> Order { get; } = new();

        /// <summary>The launch ids this machine ran, each until its request's expiry (plus a minute): a launch runs once per id, and its answer (which carries values) is never kept.</summary>
        public Dictionary<string, DateTimeOffset> LaunchIds { get; } = new(StringComparer.Ordinal);

        /// <summary>The poll this machine has outstanding (at most one: a new one supersedes it).</summary>
        public PollHold? Poll { get; set; }

        public int InFlight;
    }

    private MachineListener(LocalAuthority authority, AuthorityKeyRing keys, AuthorityStore store, TemporaryCertificate tls, MachineListenerOptions options, IRemoteLaunchHandler? launches)
    {
        _authority = authority;
        _keys = keys;
        _store = store;
        _tls = tls;
        _options = options;
        _launches = launches;
        _pairing = options.Pairing ?? new NotImplementedPairing();
        _peers = new MachinePeers(store, options.Clock);
        _app = Build();
        _store.Changed += OnChanged;
        keys.LockState?.OnLock(OnLocked);
    }

    /// <summary>Starts the machine listener. Throws when the address cannot be listened on or TLS 1.3 is not available.</summary>
    public static MachineListener Start(LocalAuthority authority, AuthorityKeyRing keys, AuthorityStore store, TemporaryCertificate tls, MachineListenerOptions options, IRemoteLaunchHandler? launches = null)
    {
        if (options.Problem() is { } problem)
        {
            throw new InvalidOperationException(problem);
        }

        MachineListener listener = new(authority, keys, store, tls, options, launches);
        try
        {
            listener._app.StartAsync().GetAwaiter().GetResult();
            listener.Port = new Uri(listener._app.Urls.First()).Port;

            return listener;
        }
        catch
        {
            listener.Dispose();

            throw;
        }
    }

    /// <summary>The port the listener holds.</summary>
    public int Port { get; private set; }

    /// <summary>How many requests were served (or refused) after the handshake.</summary>
    public int Requests => Volatile.Read(ref _requests);

    /// <summary>How many TLS handshakes were refused because the client certificate was not acceptable.</summary>
    public int HandshakeRejections => Volatile.Read(ref _handshakeRejected);

    /// <summary>How many connections are open now (one that has made at least one authenticated request).</summary>
    public int Connections => _connections.Count;

    /// <summary>How many connections were asked to close (and closed after the grace) because their machine lost trust or the authority locked.</summary>
    public int ClosedByRevocation => Volatile.Read(ref _closedByRevocation);

    /// <summary>Requests being served now.</summary>
    public int InFlight => Volatile.Read(ref _global);

    private bool Locked => _keys.LockState?.IsLocked == true;

    private WebApplication Build()
    {
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions
        {
            Args = [],
            ContentRootPath = AppContext.BaseDirectory,
            EnvironmentName = Environments.Production,
        });
        builder.Configuration.Sources.Clear();
        builder.Logging.ClearProviders();
        builder.Services.AddSingleton<IHostLifetime, QuietLifetime>();
        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.AddServerHeader = false;
            kestrel.Limits.MaxRequestBodySize = _options.MaxBodyBytes;
            kestrel.Limits.MaxRequestLineSize = 4096;
            kestrel.Limits.MaxRequestHeadersTotalSize = 16 * 1024;
            kestrel.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(15);
            kestrel.Limits.Http2.MaxStreamsPerConnection = Math.Max(_options.MaxConcurrentPerMachine * 2, 16);
            kestrel.Limits.KeepAliveTimeout = Timeout.InfiniteTimeSpan;
            kestrel.Limits.Http2.KeepAlivePingDelay = _options.Http2PingDelay;
            kestrel.Limits.Http2.KeepAlivePingTimeout = _options.Http2PingTimeout;
            kestrel.Limits.MaxConcurrentConnections = _options.MaxConnections;
            kestrel.Listen(_options.Bind, _options.Port, listen =>
            {
                listen.Protocols = HttpProtocols.Http2;
                listen.UseHttps(new HttpsConnectionAdapterOptions
                {
                    SslProtocols = SslProtocols.Tls13,
                    ClientCertificateMode = ClientCertificateMode.RequireCertificate,
                    ClientCertificateValidation = AcceptClientCertificate,
                    ServerCertificateSelector = (_, _) => _tls.Current,
                    CheckCertificateRevocation = false,
                    HandshakeTimeout = _options.HandshakeTimeout,
                    OnAuthenticate = (_, ssl) => ssl.AllowTlsResume = false,
                });
            });
        });
        WebApplication app = builder.Build();
        app.Run(HandleAsync);

        return app;
    }

    private sealed class QuietLifetime : IHostLifetime
    {
        public Task WaitForStartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }

    /// <summary>
    /// The TLS handshake's client certificate check: only the narrow validation of <see cref="MachinePeers" /> decides. A certificate that fails it ends the handshake; the system's own verdict (an untrusted root, a
    /// name that does not match) is deliberately not consulted, and nothing here is "accept anything".
    /// </summary>
    private bool AcceptClientCertificate(X509Certificate2 certificate, X509Chain? chain, SslPolicyErrors errors)
    {
        try
        {
            IEnumerable<X509Certificate2>? presented = chain?.ChainElements.Select(element => element.Certificate);
            if (_peers.Classify(certificate, presented).Kind != PeerKind.Rejected)
            {
                return true;
            }
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            AppLog.Warn("a client certificate could not be checked: {Type}", error.GetType().Name);
        }

        Interlocked.Increment(ref _handshakeRejected);

        return false;
    }

    // ---- responses ----

    private static string NewCorrelation() => Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();

    internal static async Task WriteAsync(HttpContext context, int status, string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        context.Response.StatusCode = status;
        context.Response.ContentType = MachineApi.JsonType;
        context.Response.ContentLength = bytes.Length;
        await context.Response.Body.WriteAsync(bytes, context.RequestAborted);
    }

    /// <summary>A refusal in the one error form: the frame <c>{"v":1,"id":S,"ok":false,"error":CODE}</c>. The id is the request's (or this answer's correlation id when the request has none); never a detail.</summary>
    private static Task FailAsync(HttpContext context, int status, string id, string code) => WriteAsync(context, status, RemoteWire.Failure(id, code));

    private static int StatusOf(string code) => code switch
    {
        "bad-request" => 400,
        "wrong-machine" => 403,
        "machine-not-trusted" => 403,
        "unknown-machine" => 403,
        "certificate-rejected" => 403,
        "unknown-operation" => 404,
        "method-not-allowed" => 405,
        "request-id-reused" => 409,
        "superseded" => 409,
        "unsupported-media-type" => 415,
        "too-large" => 413,
        "too-busy" => 429,
        "locked" => 503,
        "authorization-changed" => 409,
        "timeout" => 504,
        "not-implemented" => 501,
        "unsupported" => 501,
        "too-many-enrollments" => 429,
        _ => 500,
    };

    // ---- the request ----

    private async Task HandleAsync(HttpContext context)
    {
        string correlation = NewCorrelation();
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.XContentTypeOptions = "nosniff";
        context.Response.Headers["X-Correlation-Id"] = correlation;
        Interlocked.Increment(ref _requests);
        try
        {
            await ServeAsync(context, correlation);
        }
        catch (OperationCanceledException)
        {
            // The caller went away, or the listener is stopping.
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            AppLog.Warn("a machine request failed: {Type}", error.GetType().Name);
            if (!context.Response.HasStarted)
            {
                await FailAsync(context, 500, correlation, "internal-error");
            }
        }
    }

    private async Task ServeAsync(HttpContext context, string correlation)
    {
        HttpRequest request = context.Request;

        // The certificate decides who the caller is. Anything else about it (the route, the body, a header) is looked at only afterwards.
        X509Certificate2? certificate = context.Connection.ClientCertificate;
        PeerIdentity peer = certificate is null ? new PeerIdentity(PeerKind.Rejected, "", "no client certificate") : ClassifyConnection(context, certificate);
        if (request.Protocol != "HTTP/2" || peer.Kind == PeerKind.Rejected)
        {
            await FailAsync(context, 403, correlation, "certificate-rejected");

            return;
        }

        string path = request.Path.Value ?? "";
        bool pairing = path == MachineApi.PairingPath;
        if (!pairing && peer.Kind != PeerKind.Enrolled)
        {
            // An unknown machine's certificate reaches the pairing route and nothing else: not even a 404 that would say which routes exist.
            await FailAsync(context, 403, correlation, "unknown-machine");

            return;
        }

        if (Locked)
        {
            await FailAsync(context, 503, correlation, "locked");

            return;
        }

        if (!pairing)
        {
            // The machine must be Trusted (and so enabled) right now; a Pending, Disabled or Untrusted machine is turned away at the door, whatever its certificate says.
            MachineRecord? machine = _store.Find(peer.Fingerprint);
            if (machine is null || machine.Status != MachineStatus.Trusted)
            {
                await FailAsync(context, 403, correlation, "machine-not-trusted");
                CloseConnectionsOf(peer.Fingerprint);

                return;
            }
        }

        if (!HttpMethods.IsPost(request.Method))
        {
            await FailAsync(context, 405, correlation, "method-not-allowed");

            return;
        }

        if (!pairing && !path.StartsWith(MachineApi.OpsPrefix, StringComparison.Ordinal) || !pairing && !RemoteOps.Requests.Contains(path[MachineApi.OpsPrefix.Length..], StringComparer.Ordinal))
        {
            await FailAsync(context, 404, correlation, "unknown-operation");

            return;
        }

        // JSON in UTF-8 and nothing else: no other type, no content coding (nothing is ever compressed), no multipart, no form.
        if (!IsJson(request.ContentType) || request.Headers.ContentEncoding.Count > 0)
        {
            await FailAsync(context, 415, correlation, "unsupported-media-type");

            return;
        }

        int bodyLimit = pairing ? _options.MaxPairingBodyBytes : _options.MaxBodyBytes;
        if (request.ContentLength > bodyLimit)
        {
            await FailAsync(context, 413, correlation, "too-large");

            return;
        }

        context.Features.Get<IHttpMaxRequestBodySizeFeature>()?.MaxRequestBodySize = bodyLimit;

        // Every caller of the pairing route shares ONE state (the route is open to certificates nobody enrolled, so nothing may grow with the number of identities they invent).
        MachineState state = pairing ? _pairingState : _machines.GetOrAdd(peer.Fingerprint, _ => new MachineState());
        int global = Interlocked.Increment(ref _global);
        int mine = Interlocked.Increment(ref state.InFlight);
        if (global > _options.MaxConcurrent || mine > _options.MaxConcurrentPerMachine)
        {
            // Refused, not queued.
            Interlocked.Decrement(ref _global);
            Interlocked.Decrement(ref state.InFlight);
            await FailAsync(context, 429, correlation, "too-busy");

            return;
        }

        try
        {
            if (pairing)
            {
                await ServePairingAsync(context, peer, certificate!, correlation);

                return;
            }

            Track(context, peer.Fingerprint);
            await ServeOperationAsync(context, peer, state, path[MachineApi.OpsPrefix.Length..], correlation);
        }
        finally
        {
            Interlocked.Decrement(ref _global);
            Interlocked.Decrement(ref state.InFlight);
        }
    }

    /// <summary>
    /// Who a connection's certificate says its caller is. A connection that was accepted as an enrolled machine at its handshake is not interrupted when the certificate it used then later passes its end (10.2: a healthy connection is
    /// not cut for that): the classification is remembered for the life of the connection, and the per-request checks that matter (the machine is Trusted now, the lock, the binding of each operation) still run on every request. A
    /// certificate that was not enrolled is looked at again every time (the machine may have been approved since).
    /// </summary>
    private PeerIdentity ClassifyConnection(HttpContext context, X509Certificate2 certificate)
    {
        string id = context.Connection.Id;
        if (_established.TryGetValue(id, out PeerIdentity? known))
        {
            return known;
        }

        PeerIdentity peer = _peers.Classify(certificate);
        if (peer.Kind == PeerKind.Enrolled && _established.TryAdd(id, peer))
        {
            context.Features.Get<IConnectionLifetimeFeature>()?.ConnectionClosed.Register(() => _established.TryRemove(id, out _));
        }

        return peer;
    }

    private static bool IsJson(string? contentType)
    {
        if (contentType is null || !System.Net.Http.Headers.MediaTypeHeaderValue.TryParse(contentType, out System.Net.Http.Headers.MediaTypeHeaderValue? parsed))
        {
            return false;
        }

        return string.Equals(parsed.MediaType, "application/json", StringComparison.OrdinalIgnoreCase) && (parsed.CharSet is null || string.Equals(parsed.CharSet, "utf-8", StringComparison.OrdinalIgnoreCase));
    }

    private static async Task<byte[]?> ReadBodyAsync(HttpContext context, int limit, CancellationToken cancel)
    {
        using MemoryStream body = new();
        byte[] buffer = new byte[16 * 1024];
        try
        {
            int read;
            while ((read = await context.Request.Body.ReadAsync(buffer, cancel)) > 0)
            {
                if (body.Length + read > limit)
                {
                    return null;
                }

                body.Write(buffer, 0, read);
            }
        }
        catch (Microsoft.AspNetCore.Http.BadHttpRequestException)
        {
            return null;
        }

        return body.ToArray();
    }

    private async Task ServePairingAsync(HttpContext context, PeerIdentity peer, X509Certificate2 certificate, string correlation)
    {
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted, _stop.Token);
        limit.CancelAfter(_options.OperationTimeout);
        byte[]? body = await ReadBodyAsync(context, _options.MaxPairingBodyBytes, limit.Token);
        if (body is null)
        {
            await FailAsync(context, 413, correlation, "too-large");

            return;
        }

        PairingReply reply = await _pairing.HandleAsync(new PairingContext(context, peer, certificate, body), limit.Token);
        if (context.Response.HasStarted)
        {
            return;
        }

        if (reply.Body is { } json)
        {
            await WriteAsync(context, reply.Status, json);
        }
        else
        {
            await FailAsync(context, reply.Status, correlation, reply.Code);
        }
    }

    private async Task ServeOperationAsync(HttpContext context, PeerIdentity peer, MachineState state, string op, string correlation)
    {
        TimeSpan allowed = op switch
        {
            RemoteOps.Poll => Timeout.InfiniteTimeSpan,
            RemoteOps.LaunchAuthorize => _options.LaunchTimeout,
            _ => _options.OperationTimeout,
        };
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted, _stop.Token);
        if (allowed != Timeout.InfiniteTimeSpan)
        {
            limit.CancelAfter(allowed);
        }

        PollHold? hold = null;
        if (op == RemoteOps.Poll)
        {
            // Exactly one outstanding poll per machine: a new one supersedes (cancels, and so releases) the older, which a dead or abandoned connection may be holding.
            hold = new PollHold(limit);
            lock (state.Gate)
            {
                if (state.Poll is { } older)
                {
                    older.Superseded = true;
                    try
                    {
                        older.Source.Cancel();
                    }
                    catch (ObjectDisposedException)
                    {
                        // Already finished.
                    }
                }

                state.Poll = hold;
            }
        }

        try
        {
            await ServeOperationCoreAsync(context, peer, state, op, correlation, limit, hold);
        }
        finally
        {
            if (hold is not null)
            {
                lock (state.Gate)
                {
                    if (ReferenceEquals(state.Poll, hold))
                    {
                        state.Poll = null;
                    }
                }
            }
        }
    }

    private async Task ServeOperationCoreAsync(HttpContext context, PeerIdentity peer, MachineState state, string op, string correlation, CancellationTokenSource limit, PollHold? hold)
    {
        byte[]? raw = await ReadBodyAsync(context, _options.MaxBodyBytes, limit.Token);
        if (raw is null)
        {
            await FailAsync(context, 413, correlation, "too-large");

            return;
        }

        if (!RemoteWire.TryReadMessage(raw, out WireMessage? message) || message is null || !message.IsRequest || message.Op != op)
        {
            await FailAsync(context, 400, correlation, "bad-request");

            return;
        }

        string reply;
        try
        {
            if (op == RemoteOps.LaunchAuthorize)
            {
                await LaunchAsync(context, peer, state, message, limit.Token);

                return;
            }

            reply = op == RemoteOps.Poll ? await PollAsync(peer, message, limit.Token) : await Remembered(state, peer, message, limit.Token);
        }
        catch (AuthorityLockedException)
        {
            await FailAsync(context, 503, message.Id, "locked");
            CloseAll("the authority locked");

            return;
        }
        catch (OperationCanceledException) when (!limit.IsCancellationRequested || context.RequestAborted.IsCancellationRequested || _stop.IsCancellationRequested)
        {
            return;
        }
        catch (OperationCanceledException)
        {
            if (!context.Response.HasStarted)
            {
                await FailAsync(context, hold?.Superseded == true ? 409 : 504, message.Id, hold?.Superseded == true ? "superseded" : "timeout");
            }

            return;
        }

        await WriteAsync(context, StatusOfFrame(reply), reply);
    }

    /// <summary>The HTTP status of a reply frame: 200 for an answer, the code's status for a refusal.</summary>
    private static int StatusOfFrame(string reply)
    {
        if (!RemoteWire.TryReadMessage(Encoding.UTF8.GetBytes(reply), out WireMessage? parsed) || parsed is null)
        {
            return 500;
        }

        return parsed.Ok ? 200 : StatusOf(parsed.Error);
    }

    // ---- one operation, once ----

    /// <summary>
    /// One logical operation runs once per machine: the same id with the same content returns the same answer (the one in flight, or the one already given); the same id with other content is refused. Across restarts the
    /// local authority's stored results (<c>processed_requests</c>) make a retry idempotent.
    /// </summary>
    private async Task<string> Remembered(MachineState state, PeerIdentity peer, WireMessage message, CancellationToken cancel)
    {
        string digest = RemoteWire.Digest(message.Op + "\n" + message.Body);
        Task<string> task;
        lock (state.Gate)
        {
            if (state.Known.TryGetValue(message.Id, out (string Digest, Task<string> Result) known))
            {
                task = known.Digest == digest ? known.Result : Task.FromResult(RemoteWire.Failure(message.Id, "request-id-reused"));
            }
            else
            {
                task = Task.Run(async () =>
                {
                    string result = await DispatchAsync(peer, message, _stop.Token);
                    if (IsTransientFailure(result))
                    {
                        // A transient failure (the authority locked mid-operation, a database error) is not remembered: the same id may be tried again, and a retried acknowledgement must not replay the failure.
                        lock (state.Gate)
                        {
                            if (state.Known.TryGetValue(message.Id, out (string Digest, Task<string> Result) current) && current.Digest == digest)
                            {
                                state.Known.Remove(message.Id);
                            }
                        }
                    }

                    return result;
                }, _stop.Token);
                state.Known[message.Id] = (digest, task);
                state.Order.Enqueue(message.Id);
                while (state.Order.Count > _options.MaxRemembered)
                {
                    state.Known.Remove(state.Order.Dequeue());
                }
            }

        }
        return await task.WaitAsync(cancel);
    }

    private static bool IsTransientFailure(string reply) => RemoteWire.TryReadMessage(Encoding.UTF8.GetBytes(reply), out WireMessage? parsed) && parsed is { Ok: false } && parsed.Error is "locked" or "internal-error";

    private async Task<string> DispatchAsync(PeerIdentity peer, WireMessage message, CancellationToken cancel)
    {
        string id = message.Id;
        string body = message.Body;
        string Fail(string code) => RemoteWire.Failure(id, code);
        string Ok(string json) => RemoteWire.Response(id, json);
        bool Mine(string fingerprint) => string.Equals(fingerprint, peer.Fingerprint, StringComparison.Ordinal);

        try
        {
            switch (message.Op)
            {
                case RemoteOps.Decide:
                    if (!RemoteWire.TryRead(body, out MachineRequestEnvelope? envelope) || envelope is null)
                    {
                        return Fail("bad-request");
                    }

                    return Mine(envelope.MachineFingerprint) ? Ok((await _authority.DecideAsync(envelope, cancel)).ToJson()) : Fail("wrong-machine");
                case RemoteOps.Grant:
                    if (!RemoteWire.TryRead(body, out GrantEnvelope? grant) || grant is null)
                    {
                        return Fail("bad-request");
                    }

                    return Mine(grant.MachineFingerprint) ? Ok((await _authority.GrantAsync(grant, cancel)).ToJson()) : Fail("wrong-machine");
                case RemoteOps.Reconcile:
                    if (!RemoteWire.TryRead(body, out ReconcileEnvelope? reconcile) || reconcile is null)
                    {
                        return Fail("bad-request");
                    }

                    return Mine(reconcile.MachineFingerprint) ? Ok(RemoteWire.Write(await _authority.ReconcileAsync(reconcile, cancel))) : Fail("wrong-machine");
                case RemoteOps.KeyTransitions:
                    return RemoteWire.TryReadText(body, "after", out string after) ? Ok(RemoteWire.Write(await _authority.KeyTransitionsAsync(after, cancel))) : Fail("bad-request");
                case RemoteOps.RenewIdentity:
                {
                    if (!RemoteWire.TryReadText(body, "certificate", out string certificateText) || certificateText.Length > 8192)
                    {
                        return Fail("bad-request");
                    }

                    byte[] renewed;
                    try
                    {
                        renewed = Convert.FromBase64String(certificateText);
                    }
                    catch (FormatException)
                    {
                        return Fail("bad-request");
                    }

                    return _store.RenewCertificate(peer.Fingerprint, renewed) is not null ? Fail("invalid-certificate") : Ok(RemoteWire.Empty);
                }

                case RemoteOps.AuthorityKey:
                    return _keys.ActivePublicKey() is { } signing ? Ok("{\"publicKey\":\"" + Convert.ToBase64String(signing) + "\"}") : Fail("unsupported");
                case RemoteOps.PendingInvalidations:
                    if (!RemoteWire.TryReadText(body, "fingerprint", out string pendingFor))
                    {
                        return Fail("bad-request");
                    }

                    return Mine(pendingFor) ? Ok(RemoteWire.Write(await _authority.PendingInvalidationsAsync(pendingFor, cancel))) : Fail("wrong-machine");
                case RemoteOps.AcknowledgeInvalidation:
                    if (!RemoteWire.TryReadAck(body, true, out string ackFor, out long revision) || revision is < 0 or > int.MaxValue)
                    {
                        return Fail("bad-request");
                    }

                    if (!Mine(ackFor))
                    {
                        return Fail("wrong-machine");
                    }

                    await _authority.AcknowledgeInvalidationAsync(ackFor, (int)revision, cancel);

                    return Ok(RemoteWire.Empty);
                case RemoteOps.PendingGrantEvents:
                    if (!RemoteWire.TryReadText(body, "fingerprint", out string eventsFor))
                    {
                        return Fail("bad-request");
                    }

                    return Mine(eventsFor) ? Ok(RemoteWire.Write(await _authority.PendingGrantEventsAsync(eventsFor, cancel))) : Fail("wrong-machine");
                case RemoteOps.AcknowledgeGrantEvent:
                    if (!RemoteWire.TryReadAck(body, false, out string noticeFor, out long sequence))
                    {
                        return Fail("bad-request");
                    }

                    if (!Mine(noticeFor))
                    {
                        return Fail("wrong-machine");
                    }

                    await _authority.AcknowledgeGrantEventAsync(noticeFor, sequence, cancel);

                    return Ok(RemoteWire.Empty);
                case RemoteOps.AuditUpload:
                    if (!RemoteWire.TryRead(body, out AuditBatch? batch) || batch is null)
                    {
                        return Fail("bad-request");
                    }

                    return Mine(batch.MachineFingerprint) ? Ok(RemoteWire.Write(await _authority.UploadAsync(batch, cancel))) : Fail("wrong-machine");
                default:
                    return Fail("unknown-operation");
            }
        }
        catch (AuthorityLockedException)
        {
            return Fail("locked");
        }
        catch (Exception error) when (error is not (OperationCanceledException or OutOfMemoryException))
        {
            AppLog.Warn("a machine operation failed: {Type}", error.GetType().Name);

            return Fail("internal-error");
        }
    }

    // ---- the long poll ----

    private void OnChanged()
    {
        TaskCompletionSource previous;
        lock (_signalLock)
        {
            previous = _changed;
            _changed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        previous.TrySetResult();

        // Look at the trust of the connected machines off this thread (it reads the database).
        if (!_connections.IsEmpty && Volatile.Read(ref _disposed) == 0)
        {
            _ = Task.Run(RevokeWithdrawn);
        }
    }

    private Task NextChange()
    {
        lock (_signalLock)
        {
            return _changed.Task;
        }
    }

    /// <summary>
    /// The long poll of one machine: held until the existing protocol has a message for it, then answered with that message's existing payload (the pending invalidations first, then the pending grant revocations) and
    /// nothing more. It does not poll anything by time: the wait ends when the authority's database changes (a commit), the request is cancelled, the connection closes, the authority locks, or the machine loses trust.
    /// </summary>
    private async Task<string> PollAsync(PeerIdentity peer, WireMessage message, CancellationToken cancel)
    {
        if (!RemoteWire.TryReadText(message.Body, "fingerprint", out string who))
        {
            return RemoteWire.Failure(message.Id, "bad-request");
        }

        if (!string.Equals(who, peer.Fingerprint, StringComparison.Ordinal))
        {
            return RemoteWire.Failure(message.Id, "wrong-machine");
        }

        while (true)
        {
            Task changed = NextChange();
            if (Locked)
            {
                return RemoteWire.Failure(message.Id, "locked");
            }

            if (_store.Find(peer.Fingerprint) is not { Status: MachineStatus.Trusted })
            {
                return RemoteWire.Failure(message.Id, "machine-not-trusted");
            }

            IReadOnlyList<PendingInvalidation> invalidations = await _authority.PendingInvalidationsAsync(peer.Fingerprint, cancel);
            if (invalidations.Count > 0)
            {
                return RemoteWire.Response(message.Id, RemoteWire.Write(invalidations));
            }

            IReadOnlyList<PendingGrantEvent> events = await _authority.PendingGrantEventsAsync(peer.Fingerprint, cancel);
            if (events.Count > 0)
            {
                return RemoteWire.Response(message.Id, RemoteWire.Write(events));
            }

            await changed.WaitAsync(cancel);
        }
    }

    // ---- a launch ----

    /// <summary>
    /// A launch at this authority: approval and decryption happen here (see <see cref="AuthorityLaunchHandler" />). It is not run through <see cref="Remembered" />: an answer that carries values is never kept, and an id
    /// that was used for this machine gets <c>request-id-reused</c> and nothing else (a delivery is one-time). The response is streamed: the approval link goes to the host as soon as the page exists (one frame per line),
    /// the answer is the last line. The authorization is checked once more immediately before the values leave: if the machine is no longer Trusted or its security revision moved, nothing is sent.
    /// </summary>
    private async Task LaunchAsync(HttpContext context, PeerIdentity peer, MachineState state, WireMessage message, CancellationToken cancel)
    {
        if (_launches is null)
        {
            await FailAsync(context, 501, message.Id, "unsupported");

            return;
        }

        if (!RemoteWire.TryRead(message.Body, out LaunchAuthorize? launch) || launch is null || message.Id != "launch:" + launch.Decide.Request.RequestId)
        {
            await FailAsync(context, 400, message.Id, "bad-request");

            return;
        }

        if (!string.Equals(launch.Decide.MachineFingerprint, peer.Fingerprint, StringComparison.Ordinal) || !string.Equals(launch.Use.MachineFingerprint, peer.Fingerprint, StringComparison.Ordinal))
        {
            await FailAsync(context, 403, message.Id, "wrong-machine");

            return;
        }

        bool reused;
        lock (state.Gate)
        {
            // Ids are kept only while their request can still be used (until its expiry and a minute): older ones are forgotten, so the table does not grow without end and a live id is never reusable.
            DateTimeOffset now = _options.Clock.GetUtcNow();
            foreach (string old in state.LaunchIds.Where(item => item.Value < now).Select(item => item.Key).ToList())
            {
                state.LaunchIds.Remove(old);
            }

            reused = state.LaunchIds.Count >= _options.MaxLaunchesPerMachine || !state.LaunchIds.TryAdd(message.Id, launch.Decide.Request.Expires.AddMinutes(1));
        }

        if (reused)
        {
            await FailAsync(context, 409, "launch:" + launch.Decide.Request.RequestId, "request-id-reused");

            return;
        }

        SemaphoreSlim write = new(1, 1);
        int sequence = 0;
        bool started = false;

        async Task Line(string frame)
        {
            await write.WaitAsync(cancel);
            try
            {
                if (!started)
                {
                    started = true;
                    context.Response.StatusCode = 200;
                    context.Response.ContentType = MachineApi.JsonType;
                }

                byte[] bytes = Encoding.UTF8.GetBytes(frame + "\n");
                try
                {
                    await context.Response.Body.WriteAsync(bytes, cancel);
                    await context.Response.Body.FlushAsync(cancel);
                }
                finally
                {
                    // A frame may carry values (the answer): the plaintext copy is zeroed once written.
                    CryptographicOperations.ZeroMemory(bytes);
                }
            }
            finally
            {
                write.Release();
            }
        }

        void Link(string link)
        {
            // Told to the host as the page exists; a link that cannot be sent leaves the person without it, and the request ends at its time limit.
            try
            {
                if (ApprovalLinkNotice.IsSafe(link))
                {
                    Line(RemoteWire.Request("link-" + Guid.NewGuid().ToString("N"), RemoteOps.ApprovalLink, new ApprovalLinkNotice(launch.Decide.Request.RequestId, Interlocked.Increment(ref sequence), link).ToJson())).GetAwaiter().GetResult();
                }
            }
            catch (Exception error) when (error is OperationCanceledException or IOException or ObjectDisposedException or InvalidOperationException)
            {
                // The caller is gone.
            }
        }

        LaunchAnswer? answer = null;
        string requestId = launch.Decide.Request.RequestId;
        bool sentOk = false;
        bool handled = false;
        try
        {
            try
            {
                answer = await _launches.AuthorizeAsync(peer.Fingerprint, launch, Link, cancel);
                handled = true;
            }
            catch (AuthorityLockedException)
            {
                await Line(RemoteWire.Failure(message.Id, "locked"));
                CloseAll("the authority locked");

                return;
            }
            catch (OperationCanceledException)
            {
                return;
            }

            string reply;
            bool delivering = answer.Delivery is not null;
            if (answer.Delivery is { } delivery)
            {
                // The final authorization checkpoint, immediately before the values leave: a lock, a withdrawn trust, a newer security revision or (for a delivery by grant) a grant that is no longer usable means they do not.
                _options.BeforeRelease?.Invoke();
                MachineRecord? now = _store.Find(peer.Fingerprint);
                bool grantGone = delivery.Via == SecretsDelivery.ViaGrant && (_store.FindGrant(delivery.GrantId) is not { } liveGrant || !liveGrant.IsUsable(_options.Clock.GetUtcNow()));
                if (Locked)
                {
                    reply = RemoteWire.Failure(message.Id, "locked");
                    delivering = false;
                }
                else if (now is not { Status: MachineStatus.Trusted } || now.SecurityRevision != delivery.SecurityRevision || grantGone)
                {
                    reply = RemoteWire.Failure(message.Id, "authorization-changed");
                    delivering = false;
                }
                else
                {
                    reply = RemoteWire.Response(message.Id, answer.ToJson());
                }
            }
            else
            {
                reply = RemoteWire.Response(message.Id, answer.ToJson());
            }

            await Line(reply);
            sentOk = delivering;
        }
        catch (Exception error) when (error is IOException or ObjectDisposedException or InvalidOperationException)
        {
            // The connection is gone: the values were not delivered.
        }
        finally
        {
            if (handled && answer?.Delivery is not null)
            {
                _launches.Sent(peer.Fingerprint, requestId, sentOk);
            }

            // Sent or not, the values of a delivery are zeroed here; the authority's record says which.
            answer?.Delivery?.Zero();
            write.Dispose();
        }
    }

    // ---- connections ----

    private void Track(HttpContext context, string fingerprint)
    {
        string id = context.Connection.Id;
        if (!_connections.ContainsKey(id))
        {
            IConnectionLifetimeFeature? lifetime = context.Features.Get<IConnectionLifetimeFeature>();
            if (_connections.TryAdd(id, new Connection(id, fingerprint, context.Features.Get<IConnectionLifetimeNotificationFeature>(), lifetime)))
            {
                // Whatever ends the connection (a normal close, a reconnect, a dead peer, a revocation) removes its entry.
                lifetime?.ConnectionClosed.Register(() => _connections.TryRemove(id, out _));
            }
        }
    }

    private void RevokeWithdrawn()
    {
        try
        {
            string[] tracked = [.. _connections.Values.Select(connection => connection.Fingerprint).Distinct(StringComparer.Ordinal)];
            if (tracked.Length == 0)
            {
                return;
            }

            Dictionary<string, MachineStatus> status = _store.Machines().ToDictionary(machine => machine.Fingerprint, machine => machine.Status, StringComparer.Ordinal);
            foreach (string fingerprint in tracked)
            {
                if (!status.TryGetValue(fingerprint, out MachineStatus now) || now != MachineStatus.Trusted)
                {
                    CloseConnectionsOf(fingerprint);
                }
            }
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            AppLog.Warn("checking the connected machines' trust failed: {Type}", error.GetType().Name);
        }
    }

    private void OnLocked(string reason)
    {
        // A lock ends every machine connection: no new requests on them (GOAWAY), closed after the grace.
        CloseAll(reason);
        TaskCompletionSource previous;
        lock (_signalLock)
        {
            previous = _changed;
            _changed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        previous.TrySetResult();
    }

    private void CloseAll(string why)
    {
        foreach (string fingerprint in _connections.Values.Select(connection => connection.Fingerprint).Distinct(StringComparer.Ordinal).ToList())
        {
            CloseConnectionsOf(fingerprint);
        }
    }

    /// <summary>Stops a machine's connections: new requests are refused, HTTP/2 GOAWAY is sent, the rest is closed after the bounded grace. A connection is never kept as a standing authorization.</summary>
    private void CloseConnectionsOf(string fingerprint)
    {
        foreach (Connection connection in _connections.Values.Where(item => item.Fingerprint == fingerprint).ToList())
        {
            if (Interlocked.Exchange(ref connection.Closing, 1) == 1)
            {
                continue;
            }

            Interlocked.Increment(ref _closedByRevocation);
            try
            {
                connection.Notification?.RequestClose();
            }
            catch (Exception error) when (error is ObjectDisposedException or InvalidOperationException)
            {
                // Already closed.
            }

            _ = Task.Run(async () =>
            {
                try
                {
                    await Task.Delay(_options.CloseGrace, _options.Clock, _stop.Token);
                    connection.Lifetime?.Abort();
                }
                catch (Exception error) when (error is OperationCanceledException or ObjectDisposedException)
                {
                    // The listener stopped first.
                }
                finally
                {
                    _connections.TryRemove(connection.Id, out _);
                }
            });
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
        {
            return;
        }

        _store.Changed -= OnChanged;
        try
        {
            _stop.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // Stopped.
        }

        try
        {
            _app.StopAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();
        }
        catch (Exception error) when (error is OperationCanceledException or ObjectDisposedException or InvalidOperationException)
        {
            // Stopped as far as it goes.
        }

        _app.DisposeAsync().AsTask().GetAwaiter().GetResult();
        _stop.Dispose();
    }
}

using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Text;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WithSecrets;

/// <summary>The default port and the way a client or the service finds the port: --service-port / --port, then WITH_SECRETS_PORT, then the default.</summary>
public static class ServiceEndpoint
{
    public const int DefaultPort = 8765;
    public const string PortVariable = "WITH_SECRETS_PORT";

    /// <summary>The port to use: <paramref name="chosen" /> (a command line option), else the variable, else <see cref="DefaultPort" />. Null and a message when the variable is not a port.</summary>
    public static int? Resolve(int? chosen, Func<string, string?> environment, out string? error)
    {
        error = null;
        if (chosen is { } port)
        {
            return port;
        }

        if (environment(PortVariable) is not { Length: > 0 } text)
        {
            return DefaultPort;
        }

        if (!int.TryParse(text, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int parsed) || parsed is < 1 or > ToolSettings.MaxPort)
        {
            error = $"{PortVariable} must be a number from 1 to {ToolSettings.MaxPort}.";

            return null;
        }

        return parsed;
    }
}

/// <summary>What the host service works with. The state and the store are the ones of the user whose service this is.</summary>
public sealed class HostServiceOptions
{
    public required StateDatabase State { get; init; }

    public required ISecretSource Store { get; init; }

    /// <summary>This machine's identity, the authority and <c>host.json</c>. Every launch is answered for by the authority; there is no way to start the service without one.</summary>
    public required LocalDeployment Deployment { get; init; }

    /// <summary>Local authority: how often the service looks for invalidations of this machine that it has not applied (a launch also looks before it begins). Remote authority: no timer asks; this is only the first pause before a reconnect (it grows to a bound, with jitter) and how often the lease is checked for renewal.</summary>
    public TimeSpan InvalidationPoll { get; init; } = TimeSpan.FromSeconds(1);

    /// <summary>For tests: the clock for the check-in back-off (default: the system's monotonic clock).</summary>
    public IMonotonicClock? Monotonic { get; init; }

    /// <summary>How often the service sends its audit outbox to the authority when nothing wakes it (a new event always does). After a failure it waits longer, up to <see cref="AuditMaxBackoff" />.</summary>
    public TimeSpan AuditUploadInterval { get; init; } = TimeSpan.FromSeconds(2);

    public TimeSpan AuditMaxBackoff { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>The port on 127.0.0.1 and [::1]. 0 picks a free one (tests).</summary>
    public int Port { get; init; } = ServiceEndpoint.DefaultPort;

    /// <summary>For tests: replaces the approval time limit setting.</summary>
    public TimeSpan? TimeLimit { get; init; }

    /// <summary>For tests: the approver of a launch (the approval settings it is given, and where it announces the link). Default: the web page approver.</summary>
    public Func<ApprovalSettings, Action<string>, IApprover>? ApproverFactory { get; init; }

    /// <summary>For tests: the page port to use instead of the setting.</summary>
    public int? PagePort { get; init; }

    /// <summary>
    /// The authority's lock. Left null the service makes its own, LOCKED (the only way the program runs it). A test or tool that builds a service in code may pass one it
    /// unlocked (<see cref="AuthorityLock.UnlockedForTests" />); no command, setting or environment variable does.
    /// </summary>
    internal AuthorityLock? Lock { get; init; }

    /// <summary>How the unattended unlock material is protected on this platform (default: the platform's mechanism, or none with a clear message). Only used when the policy is unattended.</summary>
    public IUnlockProtection? UnlockProtection { get; init; }

    /// <summary>The asker for the admin page's operations: given where to announce the link of the one-use passkey page. Default: admin passkeys of this user's state, on the approval settings' page.</summary>
    public Func<Action<string>, IAdminAsker>? AdminAskerFactory { get; init; }

    /// <summary>The passkey administration of the admin app (add and remove a passkey). Default: the enrollment pages over this user's state.</summary>
    public Func<IPasskeyAdmin>? PasskeyAdminFactory { get; init; }

    /// <summary>For tests: the files of the administration web application (default: the ones embedded in this assembly).</summary>
    internal AdminWebAssets? WebAssets { get; init; }

    /// <summary>A request whose body has not fully arrived by then is answered 408.</summary>
    public TimeSpan BodyTimeout { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>The gate launches commit through; a later phase calls <see cref="LaunchGate.Invalidate" /> on it.</summary>
    public LaunchGate Gate { get; init; } = new();

    /// <summary>For tests: hooks passed to every launch.</summary>
    internal Action<PreparedChild>? AfterPrepare { get; init; }

    /// <summary>For tests.</summary>
    internal Action? AfterCommit { get; init; }

    /// <summary>For tests: replaces the key provider (default: the passkey tap).</summary>
    internal Func<IApprover, IStoreKeyProvider>? KeyProviderFactory { get; init; }

    /// <summary>
    /// Serve the machine listener (HTTPS: TLS 1.3 mutual authentication, HTTP/2 only) so that another machine's host service, for example the one in WSL, can ask this authority for launches. Null (the default): nothing listens
    /// beyond the loopback API. It serves nothing but the machine API: never the administration application, the API, the approval pages or a run (those stay on the loopback listener).
    /// </summary>
    public MachineListenerOptions? MachineEndpoint { get; init; }

    /// <summary>For transport tests only: exercises the authority approver directly, independently of the admin queue API tests.</summary>
    internal bool UseApprovalQueueForMachineLaunches { get; init; } = true;

    /// <summary>Called (with the port) when the machine listener starts after the service did: at the first approval that makes the authority signing key. Null: nothing is told.</summary>
    public Action<int>? MachineListenerStarted { get; init; }
}


/// <summary>
/// The host service: the trusted side of a run. It listens on loopback only, takes a <see cref="LaunchRequest" /> over HTTP, gets
/// the approval from the person on the one-use page, decrypts, builds the child's environment, starts the program and streams
/// its redacted output (see <see cref="LaunchEvent" />). It writes no secret anywhere and no response carries one. The local API
/// authenticates no caller: reaching it authorizes nothing, because the secrets are opened only after a passkey approved the page.
/// <para>
/// Routes: <c>GET /v1/status</c> (the protocol version), <c>POST /v1/launch</c> (body: the canonical request JSON; header
/// <c>X-Request-Digest</c>: its digest; optional query <c>pagePort</c>) and <c>POST /v1/launch/{id}/cancel</c>. A request is
/// refused when its Host is not a loopback name (DNS rebinding), when it has an Origin header (a browser page), when the content type is
/// not JSON, when the body is over 1 MB or slow, when it has an unknown or missing member, when its digest is not the digest of its
/// content, when its version is not this build's, when it is expired, and when its id was used before.
/// </para>
/// </summary>
public sealed class HostService : IDisposable
{
    public const int MaxBodyBytes = 1024 * 1024;
    public const string DigestHeader = "X-Request-Digest";

    private readonly HostServiceOptions _options;
    private readonly WebApplication _app;
    private readonly AdminWebAssets _web;
    private readonly Dictionary<string, CancellationTokenSource> _active = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DateTimeOffset> _seen = new(StringComparer.Ordinal);
    private readonly Lock _lock = new();
    private int _disposed;
    private bool _stopping;
    private readonly SemaphoreSlim _identitySlots = new(4);
    private readonly CancellationTokenSource _stop = new();
    private Task _pump = Task.CompletedTask;
    private string? _startupUnlockNote;

    /// <summary>The most launches in progress at once; each holds an approval page and a thread.</summary>
    public const int MaxConcurrentLaunches = 8;

    private HostService(HostServiceOptions options, WebApplication app, int port, LocalEndpoint endpoint)
    {
        _options = options;
        _web = options.WebAssets ?? AdminWebAssets.FromAssembly();
        _app = app;
        Port = port;
        Endpoint = endpoint;
        // The authority believes a grant only when a person's passkey assertion backs it: it checks those against the keys of the signed manifest.
        options.Deployment.Authority.Verifier ??= options.State is { } verifierState ? new ManifestApprovalVerifier(verifierState) : null;
        Authorization = options.Deployment.CreateAuthorization(options.Gate, options.Monotonic);
        TimeProvider authorityClock = options.Deployment.Clock ?? TimeProvider.System;
        Approvals = new ApprovalQueue(authorityClock, () => options.TimeLimit ?? ApprovalSettings.Load(options.State, out _).Timeout);

        // The authority starts LOCKED. The lock gates the authority signing key, the authority's decisions and grants, this host's runs and the memory it holds for a grant.
        // A host whose authority is remote has no authority lock of its own: the lock that matters is the authority's, enforced at its endpoint (a locked authority delivers nothing).
        Lock = options.Lock ?? new AuthorityLock();
        options.Deployment.Keys.LockState = Lock;
        Authorization.LockState = Authorization.IsRemote ? null : Lock;
        if (options.Deployment.Remote is { } remoteAuthority)
        {
            // A lock at the authority ends its session with this host. A launch that already received its values but has not started must not start: the gate is invalidated, as a lock does in local mode.
            remoteAuthority.LinkEnded += () => options.Gate.Invalidate();
        }

        Lock.OnLock(reason =>
        {
            Volatile.Write(ref _ready, false);
            Authorization.Discard(reason);

            // Every approval page that is open (a run, a grant) closes: nothing is decided, signed or granted after the lock.
            CancelActive();
        });
        IApprovalVerifier verifier = options.Deployment.Authority.Verifier ?? new ManifestApprovalVerifier(options.State);
        Func<Action<string>, IAdminAsker> askers = options.AdminAskerFactory ?? (announce =>
        {
            ApprovalSettings settings = ApprovalSettings.Load(options.State, out _);
            (EnrollmentTarget primary, EnrollmentTarget local) = CommandWiring.Targets(options.State, settings, announce, null);

            return new TargetAdminAsker(primary, local);
        });
        IPasskeyAdmin? passkeys = options.PasskeyAdminFactory?.Invoke() ?? (options.State is { } passkeyState ? new StatePasskeyAdmin(passkeyState) : null);
        IUnlockProtection protection = options.UnlockProtection ?? UnlockProtections.ForThisPlatform();
        options.Deployment.Store.EndOpenInvitations(); // an invitation's key is only in memory, so one made before this start can no longer be answered
        Pairing = new PairingService(options.Deployment.Store, options.Deployment.IdentityCertificate, () => MachineUrl, options.Deployment.Clock);
        Func<IProofMethod?> approvalProof = () =>
        {
            ApprovalSettings proofSettings = ApprovalSettings.Load(options.State, out _).WithPort(options.PagePort);
            if (options.TimeLimit is { } proofTimeout) proofSettings = proofSettings with { Timeout = proofTimeout };
            (EnrollmentTarget proofPrimary, EnrollmentTarget proofLocal) = CommandWiring.Targets(options.State, proofSettings, _ => { }, null);
            return EnrollmentTarget.FirstThatCanProve(proofPrimary, proofLocal)?.Method;
        };
        Admin = new AdminService(new AdminServiceParts(options.Deployment.Store, Lock, new AdminAuthorizer(options.Deployment.Store, verifier, options.Deployment.Clock), askers, protection, AfterUnlock, port,
            options.Deployment.Keys, options.Deployment.Authority, options.Deployment.HostConfig, options.Deployment.Fingerprint, passkeys, options.Deployment.Clock, Pairing, Approvals, approvalProof));

        // The host's audit: events are signed with the machine key and committed to the outbox (beside authority.db) before a run decrypts anything; the uploader sends them on its own.
        HostAuditOutbox outbox = HostAuditOutbox.InFolder(Path.GetDirectoryName(options.Deployment.Store.FilePath)!, options.Deployment.MachineKey, options.Deployment.Clock);
        Audit = new HostAudit(outbox, new AuditUploader(outbox, () => options.Deployment.AuditSink, (ack, id, digest, cancel) => Authorization.VerifyAnswerAsync(ack, id, digest, cancel), Authorization.Fingerprint));

        // The human commands' and the admin app's events (type admin) take the same road as a run's: signed with the machine key, committed to this outbox, sent by this uploader.
        options.State.Audit = new AdminAudit(() => Audit, options.State.FilePath);
        if (options.Store is SecretStore secretStore)
        {
            Admin.Secrets = new SecretFlows(secretStore, options.State.Audit, approvalProof, options.Deployment.Clock ?? TimeProvider.System);
        }
    }

    private Task _auditLoop = Task.CompletedTask;
    private volatile MachineListener? _machineListener;
    private readonly Lock _machineLock = new();
    private AuthorityLaunchHandler? _launches;

    /// <summary>The port of the machine listener, or null when this service serves none.</summary>
    public int? MachinePort => _machineListener?.Port;

    /// <summary>Pairing: creating invitations for the admin app, and the handler behind the machine listener's pairing route.</summary>
    public PairingService Pairing { get; }

    /// <summary>The address machines pair with and connect to (the machine listener's bind address and port), or null when this service serves no machine endpoint.</summary>
    private string? MachineUrl => _machineListener is { } listener && _options.MachineEndpoint is { } endpoint ? "https://" + (endpoint.Bind.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? "[" + endpoint.Bind + "]" : endpoint.Bind.ToString()) + ":" + listener.Port.ToString(System.Globalization.CultureInfo.InvariantCulture) : null;

    /// <summary>For tests: the machine listener (null when none is served).</summary>
    internal MachineListener? MachineListener => _machineListener;

    /// <summary>For tests: the authority-side launch handler (null when no machine endpoint is served).</summary>
    internal AuthorityLaunchHandler? Launches => _launches;

    /// <summary>The host's audit trail: the outbox and the uploader that sends it to the authority.</summary>
    public HostAudit Audit { get; }

    /// <summary>The authority's lock. The service starts locked.</summary>
    public AuthorityLock Lock { get; }

    /// <summary>The authority's in-memory pending run-approval queue (never persisted).</summary>
    public ApprovalQueue Approvals { get; }

    /// <summary>The authority's admin page and its operations (status, unlock, lock, unlock policy).</summary>
    public AdminService Admin { get; }

    /// <summary>What the unattended start came to (null when the policy is manual): one line for the startup output.</summary>
    public string? StartupUnlockNote => _startupUnlockNote;

    private void AfterUnlock()
    {
        // The authority is unlocked: check in with it as at a start (the machine's status and revision) before any run is served.
        StartupReconcile();
    }

    private bool _ready;

    /// <summary>True once the host has checked in with its authority at startup (or later): until then launches are refused with 503. An authority that answers with something this host cannot verify (nothing is pinned yet) counts: the launch is then denied with the reason.</summary>
    public bool Ready => Volatile.Read(ref _ready);


    /// <summary>The host's side of the authority protocol: signs requests, verifies answers, applies invalidations.</summary>
    public HostAuthorization Authorization { get; }

    /// <summary>The loopback port: where the browser administration is served (and, until the command line has its own endpoint, the command line).</summary>
    public int Port { get; }

    /// <summary>Where the command line reaches this service.</summary>
    public LocalEndpoint Endpoint { get; }

    public LaunchGate Gate => _options.Gate;

    /// <summary>The number of launches in progress (accepted and not yet ended).</summary>
    public int ActiveLaunches
    {
        get
        {
            lock (_lock)
            {
                return _active.Count;
            }
        }
    }

    /// <summary>Starts the service on 127.0.0.1 and [::1] (the second only where the host has IPv6). Throws when the port cannot be held.</summary>
    public static HostService Start(HostServiceOptions options)
    {
        int port = options.Port;
        if (port == 0)
        {
            using TcpListener probe = new(IPAddress.Loopback, 0);
            probe.Start();
            port = ((IPEndPoint)probe.LocalEndpoint).Port;
        }

        Exception? failure = null;
        foreach (bool withIpv6 in Socket.OSSupportsIPv6 ? new[] { true, false } : [false])
        {
            HostService? service = null;
            try
            {
                LocalEndpoint endpoint = LocalEndpoint.Loopback(port, withIpv6);
                WebApplication app = Build(options, endpoint);
                service = new HostService(options, app, port, endpoint);
                // Locked by default; unattended unlock applies only when the administrator chose it. Before any request is accepted: check machine status, host name binding and security
                // revision with the authority (it also vouches for the machine), which needs the authority unlocked.
                service._startupUnlockNote = service.Lock.IsLocked ? UnattendedUnlock.TryUnlock(options.Deployment.Store, options.Deployment.Keys, service.Lock, options.UnlockProtection ?? UnlockProtections.ForThisPlatform()) : null;
                if (service.Authorization.IsRemote || !service.Lock.IsLocked)
                {
                    service.StartupReconcile();
                }

                app.Run(service.Handle);
                app.StartAsync().GetAwaiter().GetResult();
                service._pump = Task.Run(service.PumpLoop);
                if (options.MachineEndpoint is { } machineEndpoint)
                {
                    service.StartMachineEndpoint(machineEndpoint);
                }

                try
                {
                    if (service.Audit.Outbox.Count("rejected") is var refused and > 0)
                    {
                        // Events the authority refused for good are kept apart and never resent: a person should know they exist.
                        AppLog.Warn("{Count} audit event(s) in the outbox were refused by the authority and are kept, not resent", refused);
                    }
                }
                catch (AuditOutboxException)
                {
                    // The same problem is met, and logged, by the first event and the upload.
                }

                service._auditLoop = Task.Run(() => service.Audit.RunAsync(options.AuditUploadInterval, options.AuditMaxBackoff, service._stop.Token));

                return service;
            }
            catch (Exception error) when (withIpv6)
            {
                // IPv6 loopback could not be held: try IPv4 alone (the failure is kept, so a start that fails for another reason is reported as that reason).
                failure = error;
                service?.Dispose();
            }
        }

        throw new InvalidOperationException("The host service could not listen on the loopback address.", failure);
    }

    /// <summary>
    /// Serves the machine listener of this authority (see <see cref="MachineListener" />): TLS 1.3 mutual authentication and HTTP/2 on its own address, with the launch handler that approves and decrypts here. A machine with no
    /// authority key yet serves none and says so in the log; an address that may not be listened on is an error.
    /// </summary>
    private void StartMachineEndpoint(MachineListenerOptions endpoint)
    {
        if (Authorization.IsRemote)
        {
            throw new InvalidOperationException("a host whose authority is remote is not an authority and serves no machine endpoint");
        }

        if (endpoint.Problem() is { } problem)
        {
            throw new InvalidOperationException(problem);
        }

        // The listener waits for the signing key (the first approval makes it): subscribe first and check second, so a key made in between is not missed. No listener exists before the key does.
        _options.Deployment.Keys.KeyRecorded += OnAuthorityKeyRecorded;
        TryStartMachineListener(endpoint, late: false);
    }

    private void OnAuthorityKeyRecorded()
    {
        // Called inside the key ring's lock: hand off, never start a listener here.
        if (_machineListener is null && _options.MachineEndpoint is { } endpoint && Volatile.Read(ref _disposed) == 0)
        {
            _ = Task.Run(() => TryStartMachineListener(endpoint, late: true));
        }
    }

    private void TryStartMachineListener(MachineListenerOptions endpoint, bool late)
    {
        lock (_machineLock)
        {
            if (_machineListener is not null || Volatile.Read(ref _disposed) != 0)
            {
                return;
            }

            try
            {
                if (_options.Deployment.Keys.ActivePublicKey() is null)
                {
                    AppLog.Warn("no machine endpoint yet: this authority has no signing key; it starts when the first approval makes one (no restart needed)");

                    return;
                }

                _launches = new AuthorityLaunchHandler(_options.Deployment.Authority, _options.Deployment.Keys, _options.Deployment.Store, _options.Store, MachineApprover, Lock, _options.Deployment.Clock, approvals: _options.UseApprovalQueueForMachineLaunches ? Approvals : null);
                endpoint.Pairing ??= new PairingHandler(Pairing);
                endpoint.Audit ??= Audit;
                _machineListener = MachineListener.Start(_options.Deployment.Authority, _options.Deployment.Keys, _options.Deployment.Store, _options.Deployment.Tls, endpoint, _launches);
            }
            catch (Exception error) when (late && error is not OutOfMemoryException)
            {
                // After the service started there is no caller to tell: the log says it (the type only), and the next restart tries again.
                AppLog.Warn("the machine endpoint could not be started after the first approval ({Type}); restart the service", error.GetType().Name);
                _launches?.Dispose();
                _launches = null;

                return;
            }

            if (late && _machineListener is { } started)
            {
                _options.MachineListenerStarted?.Invoke(started.Port);
            }
        }
    }

    /// <summary>The approver for a launch another machine asked for: the same page, passkeys and settings as a local launch, shown here.</summary>
    private IApprover MachineApprover(Action<string> announce)
    {
        ApprovalSettings settings = ApprovalSettings.Load(_options.State, out string? settingsError);
        if (settingsError is not null)
        {
            AppLog.Warn("a machine's launch was refused: the approval settings cannot be used");

            return new RefusingApprover("the approval settings at the authority cannot be used (fix them with: with-secrets admin)");
        }

        settings = settings.WithPort(_options.PagePort);
        if (_options.TimeLimit is { } limit)
        {
            settings = settings with { Timeout = limit };
        }

        return _options.ApproverFactory?.Invoke(settings, announce) ?? CommandWiring.RunApprover(_options.State, settings, announce);
    }

    /// <summary>Who is asked about a command run on this machine: the administration web app's approval queue, the same place as every other request. A grant is made there too, with its time signed.</summary>
    private IApprover LocalApprover(Action<string> announce)
    {
        return new QueueApprover(Approvals, new ApprovalMachineView(Authorization.Fingerprint, null, Environment.MachineName), Admin.PageUrl, _options.Deployment.Clock, announce);
    }

    private sealed class RefusingApprover(string reason) : IApprover
    {
        public ApprovalDecision Request(ApprovalRequest request) => ApprovalDecision.Deny(reason);
    }

    /// <summary>Renews the machine's identity certificate when it is near its end (checked at every check-in with the authority: start and each reconnect). A failure is logged and retried at the next one.</summary>
    private void RenewIdentity(CancellationToken cancel)
    {
        try
        {
            if (_options.Deployment.RenewIdentityIfDueAsync(cancel).GetAwaiter().GetResult())
            {
                AppLog.Warn("this machine's identity certificate was renewed (same key)");
            }
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            AppLog.Warn("renewing the identity certificate failed: {Type}", error.GetType().Name);
        }
    }

    private void StartupReconcile()
    {
        try
        {
            using CancellationTokenSource limit = new(TimeSpan.FromSeconds(10));
            _options.Deployment.Remote?.EnsureAuthorityKeyPinnedAsync(limit.Token).GetAwaiter().GetResult();
            Volatile.Write(ref _ready, Authorization.ReconcileAsync(limit.Token).GetAwaiter().GetResult() != HostAuthorization.Reconciliation.Unreachable);
            if (Ready)
            {
                RenewIdentity(limit.Token);
            }
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            AppLog.Warn("the startup check-in with the authority failed: {Type}", error.GetType().Name);
        }
    }

    private static WebApplication Build(HostServiceOptions options, LocalEndpoint endpoint)
    {
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions
        {
            Args = [],
            ContentRootPath = AppContext.BaseDirectory,
            EnvironmentName = Environments.Production
        });

        // No settings file or environment variable may add listeners.
        builder.Configuration.Sources.Clear();
        builder.Logging.ClearProviders();
        builder.Services.AddSingleton<IHostLifetime, QuietLifetime>();
        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.AddServerHeader = false;
            kestrel.Limits.MaxRequestBodySize = MaxBodyBytes;
            kestrel.Limits.MaxRequestLineSize = 4096;
            kestrel.Limits.MaxRequestHeadersTotalSize = 16 * 1024;
            kestrel.Limits.RequestHeadersTimeout = options.BodyTimeout;
            endpoint.Listen(kestrel);
        });

        return builder.Build();
    }

    private static readonly string[] LoopbackHosts = ["localhost", "127.0.0.1", "[::1]"];

    private async Task Handle(HttpContext context)
    {
        HttpResponse response = context.Response;
        response.Headers.CacheControl = "no-store";
        response.Headers.XContentTypeOptions = "nosniff";
        HttpRequest request = context.Request;

        // DNS rebinding: a page on another name that resolves to 127.0.0.1 still sends its own name as Host.
        string path = request.Path.Value ?? "";
        if (!LoopbackHosts.Contains(request.Host.Host, StringComparer.OrdinalIgnoreCase))
        {
            if (path == "/api" || path.StartsWith("/api/", StringComparison.Ordinal))
            {
                // The administration API answers in its own (problem document) form.
                await Admin.Api.RefuseHostAsync(context);

                return;
            }

            await Refuse(response, 421, "the Host header is not a loopback name");

            return;
        }

        // Two surfaces share this listener until the command line has its own endpoint: the browser administration (/api and the /admin application) and the command line's routes (/v1).
        // Each is handled apart, and nothing under /v1 is reachable from the browser's handler or the other way round.
        if (IsBrowserSurface(path))
        {
            await HandleBrowser(context, path);

            return;
        }

        await HandleCli(context, path);
    }

    private static bool IsBrowserSurface(string path) => path == "/api" || path.StartsWith("/api/", StringComparison.Ordinal) || AdminWebAssets.IsApplicationPath(path);

    /// <summary>The browser administration: the JSON API under /api and the single-page application under /admin. Every change needs its own passkey authorization (see AdminApi); sessions are read-only.</summary>
    private async Task HandleBrowser(HttpContext context, string path)
    {
        if (path == "/api" || path.StartsWith("/api/", StringComparison.Ordinal))
        {
            await Admin.Api.HandleAsync(context);

            return;
        }

        // The page for an application route, never for /api. Built without the frontend, its address answers a JSON 404 that says where the API is.
        await _web.ServeAsync(context, Admin.Api.NotBuiltAsync);
    }

    /// <summary>The command line's routes under /v1 (the application protocol: status, identity, launch, approve, cancel). Programs only.</summary>
    private async Task HandleCli(HttpContext context, string path)
    {
        HttpResponse response = context.Response;
        HttpRequest request = context.Request;
        // A browser page sends Origin on a cross-site request. This API is for programs, not pages.
        if (request.Headers.ContainsKey("Origin"))
        {
            await Refuse(response, 403, "requests from a web page are not accepted");

            return;
        }

        if (path == "/v1/status")
        {
            if (!HttpMethods.IsGet(request.Method))
            {
                await Refuse(response, 405, "use GET");

                return;
            }

            response.ContentType = "application/json";
            await response.WriteAsync("{\"protocolVersion\":" + LaunchProtocol.Version + ",\"running\":true,\"locked\":" + (Lock.IsLocked ? "true" : "false") + "}");

            return;
        }

        if (path == "/v1/identity")
        {
            if (!HttpMethods.IsPost(request.Method))
            {
                await Refuse(response, 405, "use POST");

                return;
            }

            await Identity(context);

            return;
        }

        if (path == "/v1/launch")
        {
            if (!HttpMethods.IsPost(request.Method))
            {
                await Refuse(response, 405, "use POST");

                return;
            }

            await Launch(context, approve: false);

            return;
        }

        if (path == "/v1/approve")
        {
            if (!HttpMethods.IsPost(request.Method))
            {
                await Refuse(response, 405, "use POST");

                return;
            }

            await Launch(context, approve: true);

            return;
        }

        if (path.StartsWith("/v1/launch/", StringComparison.Ordinal) && path.EndsWith("/cancel", StringComparison.Ordinal))
        {
            if (!HttpMethods.IsPost(request.Method))
            {
                await Refuse(response, 405, "use POST");

                return;
            }

            string id = path["/v1/launch/".Length..^"/cancel".Length];
            CancellationTokenSource? source;
            lock (_lock)
            {
                _active.TryGetValue(id, out source);
            }

            if (source is null)
            {
                await Refuse(response, 404, "no such launch");

                return;
            }

            try
            {
                source.Cancel();
            }
            catch (ObjectDisposedException)
            {
                // The launch ended just now: nothing is left to cancel.
            }

            response.ContentType = "application/json";
            await response.WriteAsync("{\"cancelled\":true}");

            return;
        }

        await Refuse(response, 404, "not found");
    }

    /// <summary>Cancels every launch or approval in progress (the authority locked): their pages close and nothing more is decided for them.</summary>
    private void CancelActive()
    {
        CancellationTokenSource[] sources;
        lock (_lock)
        {
            sources = [.. _active.Values];
        }

        foreach (CancellationTokenSource source in sources)
        {
            try
            {
                source.Cancel();
            }
            catch (ObjectDisposedException)
            {
                // The launch ended just now.
            }
        }
    }

    private static async Task Refuse(HttpResponse response, int status, string message)
    {
        response.StatusCode = status;
        response.ContentType = "application/json";
        StringBuilder text = new("{\"error\":");
        ToolSettings.QuoteJson(text, message);
        await response.WriteAsync(text.Append('}').ToString());
    }

    /// <summary>
    /// <c>POST /v1/identity</c> with <c>{"challenge":"..."}</c> (16 to 64 random bytes, base64url): answers with this machine's public key and
    /// fingerprint and a signature of the machine identity key over the challenge, so a client can tell this service from another program
    /// that holds the port before it sends anything. It authenticates the service to the client; it authenticates nobody.
    /// </summary>
    private async Task Identity(HttpContext context)
    {
        // The machine key signs here for any local caller, so only a few at a time: a busy answer, not a queue behind a slow TPM.
        if (!_identitySlots.Wait(0))
        {
            await Refuse(context.Response, 429, "the identity check is busy; try again");

            return;
        }

        try
        {
            await IdentityCore(context);
        }
        finally
        {
            _identitySlots.Release();
        }
    }

    private async Task IdentityCore(HttpContext context)
    {
        HttpRequest request = context.Request;
        HttpResponse response = context.Response;
        if (request.ContentType is not { } contentType || !contentType.Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase))
        {
            await Refuse(response, 415, "the body must be application/json");

            return;
        }

        if (request.ContentLength > 1024)
        {
            await Refuse(response, 413, "the body is over 1 KB");

            return;
        }

        byte[] body;
        Task<byte[]> reading = ReadBody(request.Body, context.RequestAborted);
        try
        {
            if (await Task.WhenAny(reading, Task.Delay(_options.BodyTimeout, context.RequestAborted)) != reading)
            {
                _ = reading.ContinueWith(task => task.Exception, TaskContinuationOptions.OnlyOnFaulted);
                response.Headers.Connection = "close";
                await Refuse(response, 408, "the body did not arrive in time");

                return;
            }

            body = await reading;
        }
        catch (Exception error) when (error is OperationCanceledException or BodyTooLargeException or BadHttpRequestException)
        {
            return;
        }

        string? challenge = null;
        try
        {
            using System.Text.Json.JsonDocument doc = System.Text.Json.JsonDocument.Parse(body);
            ContractReader reader = new(doc.RootElement, "challenge");
            if (reader.Problem is null && reader.Text("challenge", out string? text))
            {
                challenge = text;
            }
        }
        catch (Exception error) when (error is System.Text.Json.JsonException or ArgumentException)
        {
            // Not JSON: refused below.
        }

        if (challenge is null || challenge.Length is < 22 or > 86 || !challenge.All(letter => char.IsAsciiLetterOrDigit(letter) || letter is '-' or '_'))
        {
            await Refuse(response, 400, "the challenge must be 22 to 86 characters of base64url (16 to 64 random bytes)");

            return;
        }

        byte[] publicKey = _options.Deployment.MachineKey.PublicKey;
        byte[] signature = _options.Deployment.MachineKey.Sign(WireText.Bytes(WireText.IdentityDomain, challenge));
        StringBuilder answer = new("{\"protocolVersion\":" + LaunchProtocol.Version + ",\"fingerprint\":");
        ToolSettings.QuoteJson(answer, KeyIdentity.Fingerprint(publicKey));
        answer.Append(",\"publicKey\":");
        ToolSettings.QuoteJson(answer, Convert.ToBase64String(publicKey));
        answer.Append(",\"signature\":");
        ToolSettings.QuoteJson(answer, Convert.ToBase64String(signature));
        response.ContentType = "application/json";
        await response.WriteAsync(answer.Append('}').ToString());
    }

    /// <summary>
    /// A remote authority's invalidations and grant revocations arrive by ONE outstanding long poll (no timer, no heartbeat, no empty polling): the authority holds the request until the existing protocol has a message, the host
    /// applies it (cleanup and cancellation first), acknowledges through the existing operation and polls again at once. On every (re)connect the host first authenticates and checks in (status and security revision), which purges
    /// everything held when the revision differs. A failure backs off with bounded exponential delay and jitter; there is no other address to try. A machine the authority no longer trusts keeps nothing.
    /// </summary>
    private async Task RemoteLoop()
    {
        TimeSpan floor = _options.InvalidationPoll;
        TimeSpan pause = floor;
        bool reconnected = true;
        while (!_stop.IsCancellationRequested)
        {
            try
            {
                if (reconnected || !Ready)
                {
                    await _options.Deployment.Remote!.EnsureAuthorityKeyPinnedAsync(_stop.Token);
                    if (await Authorization.ReconcileAsync(_stop.Token) == HostAuthorization.Reconciliation.Unreachable)
                    {
                        throw new RemoteTransportException("the authority could not be reached");
                    }

                    Volatile.Write(ref _ready, true);
                    reconnected = false;
                    RenewIdentity(_stop.Token);
                }

                await Authorization.PollAsync(_stop.Token);
                pause = floor;
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested)
            {
                return;
            }
            catch (Exception error) when (error is not OutOfMemoryException)
            {
                reconnected = true;

                // Fail closed: with the authority out of reach (or refusing) the host keeps no store key it was lent.
                Authorization.DropKey("the authority link failed");
                if (error is RemoteRefusedException { Code: "machine-not-trusted" })
                {
                    // The authority turns this machine away: whatever it was told, it is not trusted now. Nothing it holds may be used; the next check-in says what it is now.
                    Authorization.Discard("the authority no longer trusts this machine");
                }

                AppLog.Warn("the authority link failed: {Type}", error is RemoteRefusedException refused ? "refused " + refused.Code : error.GetType().Name);
                try
                {
                    await Task.Delay(TimeSpan.FromTicks((long)(pause.Ticks * (0.5 + Random.Shared.NextDouble() / 2))), _stop.Token);
                }
                catch (OperationCanceledException)
                {
                    return;
                }

                pause = TimeSpan.FromTicks(Math.Min(pause.Ticks * 2, Math.Max(TimeSpan.FromSeconds(10).Ticks, floor.Ticks)));
            }
            finally
            {
                Authorization.SweepKey();
            }
        }
    }

    private async Task PumpLoop()
    {
        if (Authorization.IsRemote)
        {
            await RemoteLoop();

            return;
        }

        using PeriodicTimer timer = new(_options.InvalidationPoll);
        try
        {
            while (await timer.WaitForNextTickAsync(_stop.Token))
            {
                try
                {
                    if (!Authorization.IsRemote && Lock.IsLocked)
                    {
                        continue;
                    }

                    if (!Ready && await Authorization.ReconcileAsync(_stop.Token) != HostAuthorization.Reconciliation.Unreachable)
                    {
                        Volatile.Write(ref _ready, true);
                    }

                    await Authorization.PumpAsync(_stop.Token);
                }
                catch (Exception error) when (error is not OperationCanceledException)
                {
                    AppLog.Warn("applying an invalidation failed: {Type}", error.GetType().Name);
                }
                finally
                {
                    // Whatever the authority did or did not answer, a held key outlives neither its grant nor the authority's vouching.
                    Authorization.SweepKey();
                }
            }
        }
        catch (OperationCanceledException)
        {
            // The service is stopping.
        }
    }

    /// <summary>The locked refusal of a run: one clear line naming where to unlock (public; nothing secret).</summary>
    public string LockedRefusal => "the authority is locked, so nothing was asked or run. Unlock it in the administration web app: " + Admin.PageUrl + " (one passkey tap; no sign-in is needed to unlock)";

    private async Task Launch(HttpContext context, bool approve)
    {
        HttpRequest request = context.Request;
        HttpResponse response = context.Response;
        if (!Authorization.IsRemote && Lock.IsLocked)
        {
            await Refuse(response, StatusCodes.Status423Locked, LockedRefusal);

            return;
        }

        if (!Ready)
        {
            await Refuse(response, 503, "the host service has not checked in with its authority yet, so it accepts no requests; it keeps trying. Try again in a moment");

            return;
        }

        if (request.ContentType is not { } contentType || !contentType.Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase))
        {
            await Refuse(response, 415, "the body must be application/json");

            return;
        }

        if (request.ContentLength > MaxBodyBytes)
        {
            await Refuse(response, 413, "the body is over 1 MB");

            return;
        }

        if (!request.Headers.TryGetValue(DigestHeader, out Microsoft.Extensions.Primitives.StringValues digestValues) || digestValues.Count != 1)
        {
            await Refuse(response, 400, "the " + DigestHeader + " header is required");

            return;
        }

        if (request.Query.Keys.Any(key => key != "pagePort") || (request.Query.TryGetValue("pagePort", out Microsoft.Extensions.Primitives.StringValues pageText)
            && (pageText.Count != 1 || !int.TryParse(pageText[0], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int page) || page is < 1 or > ToolSettings.MaxPort)))
        {
            await Refuse(response, 400, "only pagePort (1 to 65535) is a valid query");

            return;
        }

        int? pagePort = request.Query.TryGetValue("pagePort", out Microsoft.Extensions.Primitives.StringValues pageValue) ? int.Parse(pageValue[0]!, System.Globalization.CultureInfo.InvariantCulture) : null;

        // The whole body must arrive within the read timeout, whatever the stream does with a cancellation token.
        byte[] body;
        Task<byte[]> reading = ReadBody(request.Body, context.RequestAborted);
        try
        {
            if (await Task.WhenAny(reading, Task.Delay(_options.BodyTimeout, context.RequestAborted)) != reading)
            {
                _ = reading.ContinueWith(task => task.Exception, TaskContinuationOptions.OnlyOnFaulted);
                response.Headers.Connection = "close";
                await Refuse(response, 408, "the body did not arrive in time");

                return;
            }

            body = await reading;
        }
        catch (OperationCanceledException)
        {
            return;
        }
        catch (BodyTooLargeException)
        {
            await Refuse(response, 413, "the body is over 1 MB");

            return;
        }
        catch (BadHttpRequestException error)
        {
            await Refuse(response, error.StatusCode == 413 ? 413 : 400, "the body could not be read");

            return;
        }

        string json;
        try
        {
            json = new UTF8Encoding(false, true).GetString(body);
        }
        catch (DecoderFallbackException)
        {
            await Refuse(response, 400, "the body is not UTF-8 text");

            return;
        }

        if (!LaunchRequest.TryParse(json, out LaunchRequest? launch, out string? parseError))
        {
            await Refuse(response, 400, "the request is not valid: " + parseError);

            return;
        }

        if (!string.Equals(digestValues[0], launch!.Digest(), StringComparison.OrdinalIgnoreCase))
        {
            await Refuse(response, 400, "the digest is not the digest of the request");

            return;
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (launch.Validate(now) is { } invalid)
        {
            await Refuse(response, 400, "the request is not valid: " + invalid);

            return;
        }

        using CancellationTokenSource cancel = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
        bool accepted;
        bool full;
        lock (_lock)
        {
            full = _stopping || _active.Count >= MaxConcurrentLaunches;
            foreach (string old in _seen.Where(item => item.Value < now).Select(item => item.Key).ToList())
            {
                _seen.Remove(old);
            }

            accepted = !full && _seen.TryAdd(launch.RequestId, launch.Expires);
            if (accepted)
            {
                _active[launch.RequestId] = cancel;
            }
        }

        if (full)
        {
            await Refuse(response, 503, "too many launches in progress (" + MaxConcurrentLaunches + "), or the service is stopping; try again later");

            return;
        }

        if (!accepted)
        {
            await Refuse(response, 409, "this request id was used before");

            return;
        }

        try
        {
            response.StatusCode = 200;
            response.ContentType = "application/x-ndjson";
            EventStream events = new(response.BodyWriter, context.RequestAborted);
            // Invalidations the authority announced before this launch are applied first, so they cancel nothing that begins now.
            try
            {
                await Authorization.PumpAsync(cancel.Token);
            }
            catch (Exception error) when (error is not OperationCanceledException)
            {
                AppLog.Warn("applying an invalidation failed: {Type}", error.GetType().Name);
            }

            int revision = _options.Gate.Revision;
            LaunchContext launchContext = new()
            {
                Authorization = Authorization,
                Audit = Audit,
                Gate = _options.Gate,
                Revision = revision,
                Cancel = cancel.Token,
                Environment = launch.InheritedEnvironment,
                AfterPrepare = _options.AfterPrepare,
                AfterCommit = _options.AfterCommit,
                OnApprovalLink = link => events.Send(LaunchEvent.Approval(link)),
            };

            (LaunchOutcome outcome, int exitCode) = await Task.Run(() => Run(launch, launchContext, pagePort, events, approve));
            events.Send(LaunchEvent.Result(outcome, exitCode));
            await events.Complete();
        }
        finally
        {
            lock (_lock)
            {
                _active.Remove(launch.RequestId);
            }
        }
    }

    private async Task<(LaunchOutcome Outcome, int ExitCode)> Run(LaunchRequest launch, LaunchContext context, int? pagePort, EventStream events, bool approve)
    {
        using EventTextWriter stdout = new("stdout", events);
        using EventTextWriter stderr = new("stderr", events);
        try
        {
            ApprovalSettings settings = ApprovalSettings.Load(_options.State, out string? settingsError);
            if (settingsError is not null)
            {
                await stderr.WriteLineAsync("with-secrets: settings: " + settingsError + " Fix them with: with-secrets admin");

                return (LaunchOutcome.Failed, RunCommand.StoreError);
            }

            settings = settings.WithPort(pagePort ?? _options.PagePort);
            if (_options.TimeLimit is { } limit)
            {
                settings = settings with { Timeout = limit };
            }

            Action<string> announce = line =>
            {
                if (line.StartsWith(WebApprover.LinkPrefix, StringComparison.Ordinal))
                {
                    events.Send(LaunchEvent.Approval(line[WebApprover.LinkPrefix.Length..]));
                }
                else
                {
                    stderr.WriteLine(line);
                }
            };

            ReuseOffer reuse = ReuseSettings.Load(_options.State);
            IApprover approver = Authorization.IsRemote ? new RefusingApprover("approval happens at the authority") : _options.ApproverFactory?.Invoke(settings, announce) ?? LocalApprover(announce);
            RunCommand run = new(_options.Store, approver, stdout, stderr, reuse, keyProvider: _options.KeyProviderFactory?.Invoke(approver) ?? new HeldStoreKeyProvider(approver, Authorization, reuse.IsOn ? reuse.MaxMinutes : ReuseSettings.DefaultMaxMinutes));
            int code = await run.ExecuteAsync(launch, context, approve);
            stdout.Complete();
            stderr.Complete();

            return (run.Outcome, code);
        }
        catch (Exception error)
        {
            // Fail closed: an error anywhere in a launch is a denial that says only that.
            AppLog.Warn("launch failed: {Type}", error.GetType().Name);
            await stderr.WriteLineAsync("with-secrets: The user did not approve (internal error). Do not retry. Ask the user.");

            return (LaunchOutcome.Denied, RunCommand.Denied);
        }
    }

    private static async Task<byte[]> ReadBody(Stream stream, CancellationToken token)
    {
        using MemoryStream copy = new();
        byte[] buffer = new byte[16 * 1024];
        int read;
        while ((read = await stream.ReadAsync(buffer, token)) > 0)
        {
            if (copy.Length + read > MaxBodyBytes)
            {
                throw new BodyTooLargeException();
            }

            copy.Write(buffer, 0, read);
        }

        return copy.ToArray();
    }

    private sealed class BodyTooLargeException : Exception;

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
        {
            return;
        }

        _stop.Cancel();
        try
        {
            _auditLoop.Wait(TimeSpan.FromSeconds(3));
        }
        catch (Exception error) when (error is AggregateException or OperationCanceledException)
        {
            // The loop was cancelled or failed; nothing more to wait for.
        }

        lock (_machineLock)
        {
            _options.Deployment.Keys.KeyRecorded -= OnAuthorityKeyRecorded;
            _machineListener?.Dispose();
            _launches?.Dispose();
        }

        Authorization.Keys.Dispose();
        CancellationTokenSource[] sources;
        lock (_lock)
        {
            _stopping = true;
            sources = [.. _active.Values];
        }

        foreach (CancellationTokenSource source in sources)
        {
            try
            {
                source.Cancel();
            }
            catch (ObjectDisposedException)
            {
                // Ended already.
            }
        }

        Admin.Secrets?.Dispose();
        Approvals.Dispose();

        try
        {
            using CancellationTokenSource stop = new(TimeSpan.FromSeconds(2));
            _app.StopAsync(stop.Token).GetAwaiter().GetResult();
        }
        catch (Exception error) when (error is OperationCanceledException or InvalidOperationException)
        {
            // Not started, or a request did not finish in time: the listener is closed either way.
        }
        finally
        {
            _app.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
    }

    private sealed class QuietLifetime : IHostLifetime
    {
        public Task WaitForStartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}

/// <summary>The response body of a launch: one JSON line per event, written in order and flushed at once. After the client left, writes are dropped.</summary>
internal sealed class EventStream(System.IO.Pipelines.PipeWriter body, CancellationToken aborted)
{
    private readonly Lock _lock = new();
    private bool _dead;

    public void Send(string line)
    {
        lock (_lock)
        {
            if (_dead || aborted.IsCancellationRequested)
            {
                return;
            }

            try
            {
                byte[] bytes = Encoding.UTF8.GetBytes(line + "\n");
                body.Write(bytes);
                body.FlushAsync(aborted).AsTask().GetAwaiter().GetResult();
            }
            catch (Exception error) when (error is OperationCanceledException or InvalidOperationException or IOException or ObjectDisposedException)
            {
                _dead = true;
            }
        }
    }

    public async Task Complete()
    {
        try
        {
            await body.CompleteAsync();
        }
        catch (Exception error) when (error is OperationCanceledException or InvalidOperationException or IOException or ObjectDisposedException)
        {
            // The client is gone.
        }
    }
}

/// <summary>
/// A text writer whose text becomes <c>output</c> events. A high surrogate at the end of a write is held for the next one, so no
/// event splits a character.
/// </summary>
internal sealed class EventTextWriter(string stream, EventStream events) : TextWriter
{
    private readonly Lock _lock = new();
    private char _held;

    public override Encoding Encoding => new UTF8Encoding(false);

    public override void Write(char value) => Emit(value.ToString());

    public override void Write(string? value) => Emit(value);

    public override void Write(char[] buffer, int index, int count) => Emit(new string(buffer, index, count));

    public override void Write(ReadOnlySpan<char> buffer) => Emit(new string(buffer));

    public override Task WriteAsync(string? value)
    {
        Emit(value);

        return Task.CompletedTask;
    }

    public override Task WriteAsync(char[] buffer, int index, int count)
    {
        Emit(new string(buffer, index, count));

        return Task.CompletedTask;
    }

    public override Task WriteAsync(ReadOnlyMemory<char> buffer, CancellationToken cancellationToken = default)
    {
        Emit(new string(buffer.Span));

        return Task.CompletedTask;
    }

    public override Task WriteLineAsync(string? value)
    {
        Emit(value + NewLine);

        return Task.CompletedTask;
    }

    public override Task FlushAsync() => Task.CompletedTask;

    public override void Flush()
    {
    }

    private void Emit(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return;
        }

        lock (_lock)
        {
            string whole = _held == '\0' ? text : _held + text;
            _held = '\0';
            if (char.IsHighSurrogate(whole[^1]))
            {
                _held = whole[^1];
                whole = whole[..^1];
            }

            if (whole.Length > 0)
            {
                events.Send(LaunchEvent.Output(stream, whole));
            }
        }
    }

    /// <summary>Sends what is still held (a high surrogate that no low one followed).</summary>
    public void Complete()
    {
        lock (_lock)
        {
            if (_held != '\0')
            {
                events.Send(LaunchEvent.Output(stream, _held.ToString()));
                _held = '\0';
            }
        }
    }
}

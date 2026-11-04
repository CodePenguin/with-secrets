using System.Buffers.Text;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Transport.Sockets;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WithSecrets;

/// <summary>What the handler of a <see cref="OneShotServer" /> sends back. A null policy means the strict default.</summary>
internal sealed record OneShotResponse(int Status, string ContentType, string Body, string? ContentSecurityPolicy = null, string? Outcome = null);

/// <summary>
/// The one line the terminal gets when a proof (or other signed step) arrives and one when it is finished, so a person can tell
/// "the page never sent it" from "the program is checking it". The lines hold a size and a verdict word only: never a key, a
/// PRF output, a code or a value. Tests replace <see cref="Sink" />.
/// </summary>
internal static class ProofLog
{
    public static Action<string> Sink { get; set; } = line => Console.Error.WriteLine(line);

    public static void Line(string text) => Sink("with-secrets: " + text);
}

/// <summary>
/// Network diagnostics for the terminal: a line when a connection is opened and when a request line and its headers were read,
/// with whole seconds since the link was made. The lines hold only a method, a route word (page, proof, sign, save, create, seal,
/// deny, code or other) and seconds: never a path with its token, a body, a key or a value. Tests replace <see cref="Sink" />.
/// </summary>
internal static class NetLog
{
    public static Action<string> Sink { get; set; } = line => Console.Error.WriteLine(line);

    public static void Line(string text) => Sink("with-secrets: " + text);

    private static readonly HashSet<string> Routes = new(StringComparer.Ordinal) { "proof", "sign", "save", "create", "seal", "deny", "code" };

    /// <summary>The route word of a suffix: "" is the page, an unknown one is "other".</summary>
    public static string Route(string? suffix) => suffix is null ? "other" : suffix.Length == 0 ? "page" : Routes.Contains(suffix) ? suffix : "other";

    public static string Method(string method) => method is "GET" or "POST" ? method : "other";

    public static string Seconds(System.Diagnostics.Stopwatch clock) => ((long)clock.Elapsed.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture) + " s";
}

/// <summary>
/// The guard every one-shot session wraps its handler in. A bug that throws while a request is handled ends the session at
/// once with a denial that says only "internal error" (never exception text) and answers 500, so nothing waits for the time
/// limit. When the session has already ended, the request gets the "already ended" answer instead.
/// </summary>
internal static class HandleGuard
{
    public const string Reason = "internal error";

    /// <summary>For tests only: called with the verb and suffix before the session handles a request; it may throw.</summary>
    internal static Action<string, string>? Fault { get; set; }

    /// <param name="deny">Records the denial; false when an outcome was already set.</param>
    public static OneShotResponse Run(string verb, string suffix, Func<OneShotResponse> handle, Func<bool> deny, OneShotResponse failed, OneShotResponse notFound)
    {
        try
        {
            Fault?.Invoke(verb, suffix);

            return handle();
        }
        catch (Exception)
        {
            return deny() ? failed : notFound;
        }
    }
}

/// <summary>
/// A small web server on loopback for one approval. It serves only /{prefix}/{token} and paths under it; every other path
/// and every other token is 404. The token is 16 random bytes, so only someone given the link can reach the handler.
/// </summary>
/// <remarks>
/// The link says localhost, and browsers try [::1] before 127.0.0.1. So the server holds both addresses on one port: another
/// program on [::1] could otherwise serve its own page at the same origin and pass the real challenge to the passkey.
/// </remarks>
internal sealed class OneShotServer : IDisposable
{
    public const int MaxBodyBytes = 1024 * 1024;

    /// <summary>A request whose body has not fully arrived by then is answered 408, so no request waits for ever.</summary>
    public static TimeSpan BodyTimeout { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>A body still being read after this long is logged once ("body slow").</summary>
    public static TimeSpan SlowBody { get; set; } = TimeSpan.FromSeconds(5);

    private readonly System.Diagnostics.Stopwatch _issued = System.Diagnostics.Stopwatch.StartNew();

    private const string StrictPolicy = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

    private static readonly OneShotResponse NotFound = new(404, "text/plain; charset=utf-8", "Not found.");

    private static readonly TimeSpan StopTimeout = TimeSpan.FromSeconds(2);

    private readonly WebApplication _app;
    private readonly string _prefix;
    private readonly Func<string, string, string, OneShotResponse> _handle;
    private readonly Socket _ipv4;
    private readonly Socket? _ipv6;
    private int _disposed;

    /// <summary>
    /// Starts listening on 127.0.0.1:port and [::1]:port (0 picks a free port). Throws when either address cannot be held,
    /// except that a host without IPv6 gets 127.0.0.1 only. The handler gets the method, the suffix ("" for the page) and the body.
    /// </summary>
    public OneShotServer(string prefix, int port, Func<string, string, string, OneShotResponse> handle)
    {
        _prefix = "/" + prefix + "/";
        _handle = handle;
        Token = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16));

        // IPv4 first, which picks the port when it is 0; then IPv6 on that same port.
        try
        {
            _ipv4 = BindSocket(IPAddress.Loopback, port);
        }
        catch (SocketException error) when (port != 0 && IsInUse(error))
        {
            throw InUse(port);
        }

        int chosen = ((IPEndPoint)_ipv4.LocalEndPoint!).Port;
        Port = chosen;
        try
        {
            _ipv6 = BindIpv6(chosen);
        }
        catch (Exception error)
        {
            _ipv4.Dispose();
            if (port != 0 && error is SocketException socket && IsInUse(socket))
            {
                throw InUse(port);
            }

            throw;
        }

        try
        {
            _app = Build(chosen);
        }
        catch
        {
            _ipv4.Dispose();
            _ipv6?.Dispose();
            throw;
        }

        try
        {
            _app.StartAsync().GetAwaiter().GetResult();

            ICollection<string> addresses = _app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()?.Addresses ?? [];
            HashSet<string> expected = ["http://127.0.0.1:" + chosen];
            if (_ipv6 is not null)
            {
                expected.Add("http://[::1]:" + chosen);
            }

            if (!expected.SetEquals(addresses) || addresses.Count != expected.Count)
            {
                throw new InvalidOperationException("The approval page did not listen on the loopback addresses only.");
            }
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    private WebApplication Build(int chosen)
    {
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions
        {
            Args = [],
            ContentRootPath = AppContext.BaseDirectory,
            EnvironmentName = Environments.Production
        });

        // No settings file or environment variable may add listeners (a "Kestrel" section can add endpoints next to ours).
        builder.Configuration.Sources.Clear();
        builder.Logging.ClearProviders();

        // The console lifetime would take Ctrl+C from the program and print to the console.
        builder.Services.AddSingleton<IHostLifetime, QuietLifetime>();

        // Kestrel listens on the sockets bound above, so no other program can take an address between the two binds.
        builder.WebHost.UseSockets(options => options.CreateBoundListenSocket = Take);
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.AddServerHeader = false;
            options.Limits.MaxRequestBodySize = MaxBodyBytes;
            options.Listen(IPAddress.Loopback, chosen, Opened);
            if (_ipv6 is not null)
            {
                options.Listen(IPAddress.IPv6Loopback, chosen, Opened);
            }
        });

        WebApplication app = builder.Build();
        app.Map("/{**path}", Serve);

        return app;
    }

    // Logs each accepted connection, then hands it on unchanged.
    private void Opened(Microsoft.AspNetCore.Server.Kestrel.Core.ListenOptions listen)
    {
        listen.Use(next => context =>
        {
            NetLog.Line($"connection opened ({NetLog.Seconds(_issued)})");

            return next(context);
        });
    }

    public int Port { get; }

    public string Token { get; }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
        {
            return;
        }

        try
        {
            using CancellationTokenSource stop = new(StopTimeout);
            _app.StopAsync(stop.Token).GetAwaiter().GetResult();
        }
        catch (Exception error) when (error is OperationCanceledException or InvalidOperationException)
        {
            // Not started, or a request did not finish in time: the listener is closed either way.
        }
        finally
        {
            _app.DisposeAsync().AsTask().GetAwaiter().GetResult();

            // Kestrel closes the sockets it used; these calls close them if it never got that far.
            _ipv4.Dispose();
            _ipv6?.Dispose();
        }
    }

    /// <summary>[::1] on the port; null only when this host has no IPv6, so a browser cannot reach [::1] either. In use is an error.</summary>
    private static Socket? BindIpv6(int port)
    {
        if (!Socket.OSSupportsIPv6)
        {
            return null;
        }

        try
        {
            return BindSocket(IPAddress.IPv6Loopback, port);
        }
        catch (SocketException error) when (error.SocketErrorCode is SocketError.AddressFamilyNotSupported
            or SocketError.ProtocolNotSupported or SocketError.AddressNotAvailable)
        {
            return null;
        }
    }

    // Windows reports an address held with ExclusiveAddressUse as access denied; elsewhere it is address in use.
    private static bool IsInUse(SocketException error) => error.SocketErrorCode is SocketError.AddressAlreadyInUse or SocketError.AccessDenied;

    private static ProofUnavailableException InUse(int port) =>
        new($"port {port.ToString(System.Globalization.CultureInfo.InvariantCulture)} is already in use; choose another with --port N, or stop the program that holds it");

    private static Socket BindSocket(IPAddress address, int port)
    {
        Socket socket = new(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            if (OperatingSystem.IsWindows())
            {
                // Without this, a program of the same user can bind the same address with SO_REUSEADDR and take connections.
                socket.ExclusiveAddressUse = true;
            }

            socket.Bind(new IPEndPoint(address, port));

            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>Gives Kestrel the socket bound for the endpoint it asks for. Anything else is refused.</summary>
    private Socket Take(EndPoint endpoint)
    {
        Socket? socket = endpoint is IPEndPoint ip && ip.Port == Port
            ? ip.Address.Equals(IPAddress.Loopback) ? _ipv4
            : ip.Address.Equals(IPAddress.IPv6Loopback) ? _ipv6
            : null
            : null;

        return socket ?? throw new InvalidOperationException("The approval page asked for an address it does not own.");
    }

    private async Task Serve(HttpContext context)
    {
        OneShotResponse response;
        string? suffix = Suffix(context.Request.Path.Value ?? "");
        if (suffix is null)
        {
            response = NotFound;
        }
        else
        {
            string route = NetLog.Route(suffix);
            NetLog.Line($"request {NetLog.Method(context.Request.Method)} /{route} (headers read, {NetLog.Seconds(_issued)})");
            using CancellationTokenSource slowEnd = new();
            _ = Task.Delay(SlowBody, slowEnd.Token).ContinueWith(
                finished => NetLog.Line($"request {NetLog.Method(context.Request.Method)} /{route} body slow ({NetLog.Seconds(_issued)})"),
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnRanToCompletion,
                TaskScheduler.Default);

            // A POST to a step other than deny is a proof (or another signed step): it is logged when it arrives and when it ends.
            bool tracked = context.Request.Method == "POST" && suffix is not ("" or "deny" or "seal");
            string label = suffix == "proof" ? "proof" : "step " + new string(suffix.Where(char.IsAsciiLetterOrDigit).Take(12).ToArray());
            string? body = null;
            bool timedOut = false;
            using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
            limit.CancelAfter(BodyTimeout);
            try
            {
                using StreamReader reader = new(context.Request.Body, new UTF8Encoding(false, true));
                body = await reader.ReadToEndAsync(limit.Token);
            }
            catch (Exception error) when (error is BadHttpRequestException or DecoderFallbackException or IOException or OperationCanceledException)
            {
                body = null;
                timedOut = error is OperationCanceledException && !context.RequestAborted.IsCancellationRequested;
            }

            slowEnd.Cancel();
            if (tracked)
            {
                ProofLog.Line(body is null ? $"{label} received (body not read)" : $"{label} received ({Encoding.UTF8.GetByteCount(body)} bytes)");
            }

            try
            {
                response = timedOut ? new OneShotResponse(408, "text/plain; charset=utf-8", "The request body did not arrive in time.")
                    : body is null ? new OneShotResponse(400, "text/plain; charset=utf-8", "The request body is over 1 MB or not UTF-8.", Outcome: "invalid body")
                    : _handle(context.Request.Method, suffix, body);
            }
            catch (Exception)
            {
                response = new OneShotResponse(500, "text/plain; charset=utf-8", "Something went wrong.");
            }

            if (tracked)
            {
                ProofLog.Line($"{label} checked: " + (response.Outcome ?? response.Status switch
                {
                    200 => "accepted",
                    403 => "refused",
                    400 => "invalid body",
                    404 => "already ended",
                    408 => "body timed out",
                    _ => "error " + response.Status.ToString(System.Globalization.CultureInfo.InvariantCulture)
                }));
            }
        }

        IHeaderDictionary headers = context.Response.Headers;
        context.Response.StatusCode = response.Status;
        context.Response.ContentType = response.ContentType;
        headers.CacheControl = "no-store";
        headers.XContentTypeOptions = "nosniff";
        headers.XFrameOptions = "DENY";
        headers["Referrer-Policy"] = "no-referrer";
        headers.ContentSecurityPolicy = response.ContentSecurityPolicy ?? StrictPolicy;
        try
        {
            await context.Response.WriteAsync(response.Body, Encoding.UTF8, context.RequestAborted);
        }
        catch (Exception error) when (error is IOException or OperationCanceledException)
        {
            // The browser went away.
        }
    }

    /// <summary>"" for /{prefix}/{token} or /{prefix}/{token}/, the rest for /{prefix}/{token}/rest, null for anything else.</summary>
    private string? Suffix(string path)
    {
        if (!path.StartsWith(_prefix, StringComparison.Ordinal))
        {
            return null;
        }

        string rest = path[_prefix.Length..];
        int slash = rest.IndexOf('/', StringComparison.Ordinal);
        string token = slash < 0 ? rest : rest[..slash];
        if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(token), Encoding.UTF8.GetBytes(Token)))
        {
            return null;
        }

        return slash < 0 ? "" : rest[(slash + 1)..];
    }

    private sealed class QuietLifetime : IHostLifetime
    {
        public Task WaitForStartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}

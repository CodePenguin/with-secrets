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
internal sealed record OneShotResponse(int Status, string ContentType, string Body, string? ContentSecurityPolicy = null);

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
        _ipv4 = BindSocket(IPAddress.Loopback, port);
        int chosen = ((IPEndPoint)_ipv4.LocalEndPoint!).Port;
        Port = chosen;
        try
        {
            _ipv6 = BindIpv6(chosen);
        }
        catch
        {
            _ipv4.Dispose();
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
            options.Listen(IPAddress.Loopback, chosen);
            if (_ipv6 is not null)
            {
                options.Listen(IPAddress.IPv6Loopback, chosen);
            }
        });

        WebApplication app = builder.Build();
        app.Map("/{**path}", Serve);

        return app;
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
            string? body;
            try
            {
                using StreamReader reader = new(context.Request.Body, new UTF8Encoding(false, true));
                body = await reader.ReadToEndAsync(context.RequestAborted);
            }
            catch (Exception error) when (error is BadHttpRequestException or DecoderFallbackException or IOException or OperationCanceledException)
            {
                body = null;
            }

            try
            {
                response = body is null ? new OneShotResponse(400, "text/plain; charset=utf-8", "The request body is over 1 MB or not UTF-8.") : _handle(context.Request.Method, suffix, body);
            }
            catch (Exception)
            {
                response = new OneShotResponse(500, "text/plain; charset=utf-8", "Something went wrong.");
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

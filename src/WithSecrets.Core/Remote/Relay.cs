using System.Collections.Concurrent;
using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography.X509Certificates;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WithSecrets;

/// <summary>What the relay may keep and report: a routing event (a word, the registration id, a connection id and a size). Never a payload.</summary>
public sealed record RelayRecord(DateTimeOffset Time, string Event, string Registration, string Connection, int Length);

/// <summary>Settings of a relay. Everything here is about listening and limits; the relay has no keys, no accounts and no policy.</summary>
public sealed class RelayOptions
{
    /// <summary>The port to listen on; 0 picks a free one (tests).</summary>
    public int Port { get; init; }

    /// <summary>The address to listen on. Loopback by default; any other address needs <see cref="Certificate" /> (TLS is required beyond the loopback).</summary>
    public IPAddress Bind { get; init; } = IPAddress.Loopback;

    /// <summary>The server certificate for https and wss.</summary>
    public X509Certificate2? Certificate { get; init; }

    /// <summary>For tests: keep a bounded list of routing events (<see cref="RelayServer.Records" />). Off by default; nothing is kept.</summary>
    public bool CaptureRecords { get; init; }

    /// <summary>For tests: receives every raw frame the relay handles, with the word for where it came from, so a test can prove there is no plaintext in it. Never set by the program.</summary>
    public Action<string, byte[]>? Tap { get; init; }

    public int MaxMessageBytes { get; init; } = 8 * 1024 * 1024;

    public int MaxRegistrations { get; init; } = 1024;

    public int MaxHostsPerRegistration { get; init; } = 64;
}

/// <summary>
/// The relay of architecture 10.2: an opaque, in-memory router. A host and an authority connect outward (WebSocket); the relay pairs them by registration id and copies frames
/// between them. It does not read, parse or type a frame, holds no key, no session and no account, makes no authorization decision, and keeps nothing on disk: a restart
/// loses only the live connections, which reconnect and handshake again. Between the relay and an authority every frame is <c>kind | connection id (16) | payload</c> (routing
/// metadata, then the payload untouched); between a host and the relay a frame is the payload itself.
/// </summary>
public sealed class RelayServer : IAsyncDisposable
{
    public const string AuthorityPath = "/relay/v1/authority";
    public const string HostPath = "/relay/v1/host";

    /// <summary>Relay to authority: a host connected (the payload is empty).</summary>
    public const byte KindOpen = 2;

    /// <summary>Both ways: a frame of a connection.</summary>
    public const byte KindData = 1;

    /// <summary>Both ways: the connection ended (from the relay: the host went away; from the authority: end this host's connection).</summary>
    public const byte KindClose = 3;

    public const int HeaderLength = 1 + 16;

    private readonly RelayOptions _options;
    private readonly WebApplication _app;
    private readonly Lock _lock = new();
    private readonly Dictionary<string, Registration> _registrations = new(StringComparer.Ordinal);
    private readonly List<RelayRecord> _records = [];
    private int _disposed;

    private sealed class Registration(string id)
    {
        public string Id { get; } = id;

        public RelaySocket? Authority { get; set; }

        public ConcurrentDictionary<Guid, RelaySocket> Hosts { get; } = new();
    }

    private RelayServer(RelayOptions options, WebApplication app, int port)
    {
        _options = options;
        _app = app;
        Port = port;
    }

    public int Port { get; }

    public string Scheme => _options.Certificate is null ? "http" : "https";

    /// <summary>The URL hosts and authorities use, on the loopback address when the relay listens on any.</summary>
    public string Url => $"{Scheme}://{(IPAddress.Any.Equals(_options.Bind) || IPAddress.IPv6Any.Equals(_options.Bind) ? "127.0.0.1" : _options.Bind.ToString())}:{Port}";

    /// <summary>The routing events kept so far (empty unless <see cref="RelayOptions.CaptureRecords" />).</summary>
    public IReadOnlyList<RelayRecord> Records
    {
        get
        {
            lock (_lock)
            {
                return [.. _records];
            }
        }
    }

    /// <summary>How many authorities are registered right now.</summary>
    public int AuthorityCount
    {
        get
        {
            lock (_lock)
            {
                return _registrations.Values.Count(item => item.Authority is not null);
            }
        }
    }

    public static async Task<RelayServer> StartAsync(RelayOptions options)
    {
        if (!IPAddress.IsLoopback(options.Bind) && options.Certificate is null)
        {
            throw new InvalidOperationException("a relay that listens beyond this machine needs a TLS certificate (https and wss)");
        }

        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [], ContentRootPath = AppContext.BaseDirectory, EnvironmentName = Environments.Production });
        builder.Configuration.Sources.Clear();
        builder.Logging.ClearProviders();
        builder.Services.AddSingleton<IHostLifetime, QuietLifetime>();
        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.AddServerHeader = false;
            kestrel.Limits.MaxRequestHeadersTotalSize = 16 * 1024;
            kestrel.Listen(options.Bind, options.Port, listen =>
            {
                if (options.Certificate is { } certificate)
                {
                    listen.UseHttps(certificate);
                }
            });
        });

        WebApplication app = builder.Build();
        app.UseWebSockets(new WebSocketOptions { KeepAliveInterval = TimeSpan.FromSeconds(30) });
        RelayServer? server = null;
        app.Run(context => server!.HandleAsync(context));
        await app.StartAsync();
        string address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
        server = new RelayServer(options, app, new Uri(address).Port);

        return server;
    }

    private async Task HandleAsync(HttpContext context)
    {
        string path = context.Request.Path.Value ?? "";
        string id = context.Request.Query["registration"].ToString();
        if (!context.WebSockets.IsWebSocketRequest || (path != AuthorityPath && path != HostPath) || !RemoteTarget.IsRegistrationId(id))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;

            return;
        }

        if (path == AuthorityPath)
        {
            await HandleAuthorityAsync(context, id);
        }
        else
        {
            await HandleHostAsync(context, id);
        }
    }

    private async Task HandleAuthorityAsync(HttpContext context, string id)
    {
        Registration registration;
        lock (_lock)
        {
            if (!_registrations.TryGetValue(id, out Registration? existing) && _registrations.Count >= _options.MaxRegistrations)
            {
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;

                return;
            }

            registration = existing ?? (_registrations[id] = new Registration(id));
        }

        using WebSocket socket = await context.WebSockets.AcceptWebSocketAsync();
        RelaySocket mine = new(socket, _options.MaxMessageBytes);

        // A newer connection replaces the stale one: the old authority socket and the hosts that were paired through it are closed, and they connect again.
        RelaySocket? stale;
        List<RelaySocket> orphaned;
        lock (_lock)
        {
            stale = registration.Authority;
            registration.Authority = mine;
            orphaned = stale is null ? [] : [.. registration.Hosts.Values];
            _registrations[id] = registration;
        }

        Note(stale is null ? "authority-register" : "authority-replace", id, Guid.Empty, 0);
        stale?.Abort();
        foreach (RelaySocket host in orphaned)
        {
            host.Abort();
        }

        try
        {
            while (await mine.ReceiveAsync(context.RequestAborted) is { } message)
            {
                _options.Tap?.Invoke("from-authority", message);
                if (message.Length < HeaderLength || !TryHost(registration, message, out RelaySocket? host, out Guid connection))
                {
                    continue;
                }

                if (message[0] == KindClose)
                {
                    host!.Abort();
                }
                else if (message[0] == KindData)
                {
                    Note("frame-to-host", id, connection, message.Length - HeaderLength);
                    await host!.SendAsync(message.AsMemory(HeaderLength), context.RequestAborted);
                }
            }
        }
        catch (Exception error) when (error is WebSocketException or OperationCanceledException or IOException or InvalidOperationException)
        {
            // The authority went away; the cleanup below is the same.
        }
        finally
        {
            List<RelaySocket> hosts = [];
            lock (_lock)
            {
                if (ReferenceEquals(registration.Authority, mine))
                {
                    registration.Authority = null;
                    hosts = [.. registration.Hosts.Values];
                    if (registration.Hosts.IsEmpty)
                    {
                        _registrations.Remove(id);
                    }
                }
            }

            foreach (RelaySocket host in hosts)
            {
                host.Abort();
            }

            mine.Abort();
            Note("authority-gone", id, Guid.Empty, 0);
        }
    }

    private static bool TryHost(Registration registration, byte[] message, out RelaySocket? host, out Guid connection)
    {
        connection = new Guid(message.AsSpan(1, 16));

        return registration.Hosts.TryGetValue(connection, out host);
    }

    private async Task HandleHostAsync(HttpContext context, string id)
    {
        Registration? registration;
        RelaySocket? authority;
        lock (_lock)
        {
            _registrations.TryGetValue(id, out registration);
            authority = registration?.Authority;
            if (authority is null || registration!.Hosts.Count >= _options.MaxHostsPerRegistration)
            {
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;

                return;
            }
        }

        using WebSocket socket = await context.WebSockets.AcceptWebSocketAsync();
        RelaySocket mine = new(socket, _options.MaxMessageBytes);
        Guid connection = Guid.NewGuid();
        registration!.Hosts[connection] = mine;
        Note("host-connect", id, connection, 0);
        try
        {
            await authority.SendAsync(Header(KindOpen, connection), context.RequestAborted);
            while (await mine.ReceiveAsync(context.RequestAborted) is { } message)
            {
                _options.Tap?.Invoke("from-host", message);
                RelaySocket? current;
                lock (_lock)
                {
                    current = registration.Authority;
                }

                if (current is null)
                {
                    break;
                }

                Note("frame-to-authority", id, connection, message.Length);
                byte[] routed = [.. Header(KindData, connection), .. message];
                await current.SendAsync(routed, context.RequestAborted);
            }
        }
        catch (Exception error) when (error is WebSocketException or OperationCanceledException or IOException or InvalidOperationException)
        {
            // The host or the authority went away.
        }
        finally
        {
            registration.Hosts.TryRemove(connection, out _);
            mine.Abort();
            RelaySocket? current;
            lock (_lock)
            {
                current = registration.Authority;
                if (current is null && registration.Hosts.IsEmpty)
                {
                    _registrations.Remove(id);
                }
            }

            if (current is not null)
            {
                try
                {
                    await current.SendAsync(Header(KindClose, connection), CancellationToken.None);
                }
                catch (Exception error) when (error is WebSocketException or OperationCanceledException or IOException or InvalidOperationException or ObjectDisposedException)
                {
                    // The authority is gone too.
                }
            }

            Note("host-gone", id, connection, 0);
        }
    }

    public static byte[] Header(byte kind, Guid connection)
    {
        byte[] header = new byte[HeaderLength];
        header[0] = kind;
        connection.TryWriteBytes(header.AsSpan(1, 16));

        return header;
    }

    private void Note(string what, string registration, Guid connection, int length)
    {
        if (!_options.CaptureRecords)
        {
            return;
        }

        lock (_lock)
        {
            if (_records.Count >= 10_000)
            {
                _records.RemoveAt(0);
            }

            _records.Add(new RelayRecord(DateTimeOffset.UtcNow, what, registration, connection == Guid.Empty ? "" : connection.ToString("N")[..8], length));
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
        {
            return;
        }

        List<RelaySocket> sockets = [];
        lock (_lock)
        {
            foreach (Registration registration in _registrations.Values)
            {
                if (registration.Authority is { } authority)
                {
                    sockets.Add(authority);
                }

                sockets.AddRange(registration.Hosts.Values);
            }
        }

        foreach (RelaySocket socket in sockets)
        {
            socket.Abort();
        }

        using CancellationTokenSource limit = new(TimeSpan.FromSeconds(5));
        try
        {
            await _app.StopAsync(limit.Token);
        }
        catch (OperationCanceledException)
        {
            // Stopped as far as it goes.
        }

        await _app.DisposeAsync();
    }

    private sealed class QuietLifetime : IHostLifetime
    {
        public Task WaitForStartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}

/// <summary>A WebSocket that sends one message at a time and receives whole messages up to a limit.</summary>
internal sealed class RelaySocket(WebSocket socket, int maxMessage)
{
    private readonly SemaphoreSlim _send = new(1, 1);

    public async Task SendAsync(ReadOnlyMemory<byte> message, CancellationToken cancel)
    {
        await _send.WaitAsync(cancel);
        try
        {
            using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(cancel);
            limit.CancelAfter(TimeSpan.FromSeconds(30));
            await socket.SendAsync(message, WebSocketMessageType.Binary, true, limit.Token);
        }
        catch (OperationCanceledException error) when (!cancel.IsCancellationRequested)
        {
            throw new IOException("the connection broke while sending", error);
        }
        finally
        {
            _send.Release();
        }
    }

    /// <summary>The next whole message, or null when the peer closed. A message above the limit, or a text message, ends the connection.</summary>
    public async Task<byte[]?> ReceiveAsync(CancellationToken cancel)
    {
        byte[] buffer = new byte[16 * 1024];
        using MemoryStream message = new();
        while (true)
        {
            ValueWebSocketReceiveResult result;
            try
            {
                result = await socket.ReceiveAsync(buffer.AsMemory(), cancel);
            }
            catch (WebSocketException) when (socket.State is WebSocketState.Aborted or WebSocketState.Closed)
            {
                return null;
            }

            if (result.MessageType == WebSocketMessageType.Close)
            {
                return null;
            }

            if (result.MessageType != WebSocketMessageType.Binary || message.Length + result.Count > maxMessage)
            {
                Abort();

                return null;
            }

            message.Write(buffer, 0, result.Count);
            if (result.EndOfMessage)
            {
                return message.ToArray();
            }
        }
    }

    public void Abort()
    {
        try
        {
            socket.Abort();
        }
        catch (ObjectDisposedException)
        {
            // Already gone.
        }
    }
}

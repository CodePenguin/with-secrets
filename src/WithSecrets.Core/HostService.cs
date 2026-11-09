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

/// <summary>What the host service works with. The state, the store and the grants are the ones of the user whose service this is.</summary>
public sealed class HostServiceOptions
{
    public required StateDatabase State { get; init; }

    public required ISecretSource Store { get; init; }

    public GrantStore? Grants { get; init; }

    /// <summary>This machine's identity, the authority and <c>host.json</c>. Every launch is answered for by the authority; there is no way to start the service without one.</summary>
    public required LocalDeployment Deployment { get; init; }

    /// <summary>How often the service asks the authority for invalidations of this machine that it has not applied (a launch also asks before it begins).</summary>
    public TimeSpan InvalidationPoll { get; init; } = TimeSpan.FromSeconds(1);

    /// <summary>The port on 127.0.0.1 and [::1]. 0 picks a free one (tests).</summary>
    public int Port { get; init; } = ServiceEndpoint.DefaultPort;

    /// <summary>For tests: replaces the approval time limit setting.</summary>
    public TimeSpan? TimeLimit { get; init; }

    /// <summary>For tests: the approver of a launch (the approval settings it is given, and where it announces the link). Default: the web page approver.</summary>
    public Func<ApprovalSettings, Action<string>, IApprover>? ApproverFactory { get; init; }

    /// <summary>For tests: the page port to use instead of the setting.</summary>
    public int? PagePort { get; init; }

    /// <summary>A request whose body has not fully arrived by then is answered 408.</summary>
    public TimeSpan BodyTimeout { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>The gate launches commit through; a later phase calls <see cref="LaunchGate.Invalidate" /> on it.</summary>
    public LaunchGate Gate { get; init; } = new();

    /// <summary>For tests: hooks passed to every launch.</summary>
    internal Action<PreparedChild>? AfterPrepare { get; init; }

    /// <summary>For tests.</summary>
    internal Action? AfterCommit { get; init; }
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
    private readonly Dictionary<string, CancellationTokenSource> _active = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DateTimeOffset> _seen = new(StringComparer.Ordinal);
    private readonly Lock _lock = new();
    private int _disposed;
    private bool _stopping;
    private readonly CancellationTokenSource _stop = new();
    private Task _pump = Task.CompletedTask;

    /// <summary>The most launches in progress at once; each holds an approval page and a thread.</summary>
    public const int MaxConcurrentLaunches = 8;

    private HostService(HostServiceOptions options, WebApplication app, int port)
    {
        _options = options;
        _app = app;
        Port = port;
        Authorization = options.Deployment.CreateAuthorization(options.Gate);
    }

    /// <summary>The host's side of the authority protocol: signs requests, verifies answers, applies invalidations.</summary>
    public HostAuthorization Authorization { get; }

    public int Port { get; }

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

        foreach (bool withIpv6 in Socket.OSSupportsIPv6 ? new[] { true, false } : [false])
        {
            HostService? service = null;
            try
            {
                WebApplication app = Build(options, port, withIpv6);
                service = new HostService(options, app, port);
                app.Run(service.Handle);
                app.StartAsync().GetAwaiter().GetResult();
                service._pump = Task.Run(service.PumpLoop);

                return service;
            }
            catch (Exception) when (withIpv6)
            {
                // IPv6 loopback could not be held: try IPv4 alone.
                service?.Dispose();
            }
        }

        throw new InvalidOperationException("The host service could not listen on the loopback address.");
    }

    private static WebApplication Build(HostServiceOptions options, int port, bool withIpv6)
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
            kestrel.Listen(IPAddress.Loopback, port);
            if (withIpv6)
            {
                kestrel.Listen(IPAddress.IPv6Loopback, port);
            }
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
        if (!LoopbackHosts.Contains(request.Host.Host, StringComparer.OrdinalIgnoreCase))
        {
            await Refuse(response, 421, "the Host header is not a loopback name");

            return;
        }

        // A browser page sends Origin on a cross-site request. This API is for programs, not pages.
        if (request.Headers.ContainsKey("Origin"))
        {
            await Refuse(response, 403, "requests from a web page are not accepted");

            return;
        }

        string path = request.Path.Value ?? "";
        if (path == "/v1/status")
        {
            if (!HttpMethods.IsGet(request.Method))
            {
                await Refuse(response, 405, "use GET");

                return;
            }

            response.ContentType = "application/json";
            await response.WriteAsync("{\"protocolVersion\":" + LaunchProtocol.Version + "}");

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

            await Launch(context);

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

    private async Task PumpLoop()
    {
        using PeriodicTimer timer = new(_options.InvalidationPoll);
        try
        {
            while (await timer.WaitForNextTickAsync(_stop.Token))
            {
                try
                {
                    await Authorization.PumpAsync(_stop.Token);
                }
                catch (Exception error) when (error is not OperationCanceledException)
                {
                    AppLog.Warn("applying an invalidation failed: {Type}", error.GetType().Name);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // The service is stopping.
        }
    }

    private async Task Launch(HttpContext context)
    {
        HttpRequest request = context.Request;
        HttpResponse response = context.Response;
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
                Gate = _options.Gate,
                Revision = revision,
                Cancel = cancel.Token,
                Environment = launch.InheritedEnvironment,
                AfterPrepare = _options.AfterPrepare,
                AfterCommit = _options.AfterCommit,
            };

            (LaunchOutcome outcome, int exitCode) = await Task.Run(() => Run(launch, launchContext, pagePort, events));
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

    private async Task<(LaunchOutcome Outcome, int ExitCode)> Run(LaunchRequest launch, LaunchContext context, int? pagePort, EventStream events)
    {
        using EventTextWriter stdout = new("stdout", events);
        using EventTextWriter stderr = new("stderr", events);
        try
        {
            ApprovalSettings settings = ApprovalSettings.Load(_options.State, out string? settingsError);
            if (settingsError is not null)
            {
                await stderr.WriteLineAsync("with-secrets: settings: " + settingsError + " Fix them with: with-secrets --config");

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

            IApprover approver = _options.ApproverFactory?.Invoke(settings, announce) ?? CommandWiring.RunApprover(_options.State, settings, announce);
            RunCommand run = new(_options.Store, approver, new AuditLog(_options.State), stdout, stderr, _options.Grants, ReuseSettings.Load(_options.State));
            int code = await run.ExecuteAsync(launch, context);
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

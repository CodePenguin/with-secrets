using System.Net;
using Microsoft.Extensions.DependencyInjection;

using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace WithSecrets;

/// <summary>
/// How the command line reaches the host service of this machine, and where the service listens for it. Only the way requests and answers are carried differs between endpoints: the routes, the models, the request digest,
/// the identity challenge and the streamed answers are the application protocol and are the same over every endpoint. Every endpoint is a plain HTTP/1.1 carrier (<see cref="BaseUri" /> names no host that is looked up).
/// </summary>
public abstract class LocalEndpoint
{
    /// <summary>The address requests are made to (routes are appended). Its host is one the service accepts as its own.</summary>
    public abstract Uri BaseUri { get; }

    /// <summary>For messages: where the service is expected, without any request content.</summary>
    public abstract string Describe();

    /// <summary>A connection handler that reaches this endpoint (no proxy, no redirects).</summary>
    public abstract SocketsHttpHandler CreateHandler();

    /// <summary>Makes the service listen here.</summary>
    internal abstract void Listen(KestrelServerOptions kestrel);

    /// <summary>Host-level settings this endpoint needs (before the listeners are made).</summary>
    internal virtual void Configure(Microsoft.AspNetCore.Hosting.IWebHostBuilder host)
    {
    }

    /// <summary>The loopback TCP endpoint on <paramref name="port" />: 127.0.0.1 and, where the host has IPv6, [::1].</summary>
    public static LocalEndpoint Loopback(int port, bool ipv6 = true) => new LoopbackEndpoint(port, ipv6);

    /// <summary>The endpoint the command line of this user uses on this platform. Windows: the user's named pipe. Elsewhere, until the Unix socket exists, the loopback port.</summary>
    public static LocalEndpoint ForCommandLine(int port) => OperatingSystem.IsWindows() ? new NamedPipeEndpoint(NamedPipeEndpoint.DefaultName()) : Loopback(port);

    /// <summary>A named pipe of the given name (Windows only; tests use a name of their own).</summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static LocalEndpoint NamedPipe(string name) => new NamedPipeEndpoint(name);
}

/// <summary>Plain HTTP on the loopback addresses. Any process of any user on this machine can connect: it is the transport this work replaces for the command line, and the one the browser administration still uses.</summary>
internal sealed class LoopbackEndpoint(int port, bool ipv6) : LocalEndpoint
{
    public int Port { get; } = port;

    public override Uri BaseUri { get; } = new("http://127.0.0.1:" + port.ToString(System.Globalization.CultureInfo.InvariantCulture) + "/");

    public override string Describe() => "port " + Port.ToString(System.Globalization.CultureInfo.InvariantCulture);

    public override SocketsHttpHandler CreateHandler() => new() { UseProxy = false, AllowAutoRedirect = false };

    internal override void Listen(KestrelServerOptions kestrel)
    {
        kestrel.Listen(IPAddress.Loopback, Port);
        if (ipv6)
        {
            kestrel.Listen(IPAddress.IPv6Loopback, Port);
        }
    }
}

/// <summary>
/// Windows: a named pipe that only the current user can open. The access list names that user's SID and nobody else, a deny entry refuses network (remote) clients outright, and the client asks for the pipe with
/// <c>CurrentUserOnly</c> (it will not talk to a pipe that another user created first) and an anonymous impersonation level (the service cannot act as the client).
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
internal sealed class NamedPipeEndpoint(string name) : LocalEndpoint
{
    /// <summary>A service that is running accepts at once; this is only how long a busy one (every pipe instance in use for a moment) is waited for.</summary>
    private const int ConnectTimeoutMilliseconds = 3000;

    public string Name { get; } = name;

    public override Uri BaseUri { get; } = new("http://localhost/");

    public override string Describe() => "the named pipe " + Name;

    /// <summary>The pipe of the current user: one per user, because pipe names are shared by every user of the machine.</summary>
    public static string DefaultName()
    {
        string sid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value ?? "unknown";

        return "with-secrets-" + sid;
    }

    public override SocketsHttpHandler CreateHandler() => new()
    {
        UseProxy = false,
        AllowAutoRedirect = false,
        ConnectCallback = async (_, cancel) =>
        {
            System.IO.Pipes.NamedPipeClientStream pipe = new(".", Name, System.IO.Pipes.PipeDirection.InOut, System.IO.Pipes.PipeOptions.Asynchronous | System.IO.Pipes.PipeOptions.CurrentUserOnly, System.Security.Principal.TokenImpersonationLevel.Anonymous);
            try
            {
                // A pipe that does not exist is a service that is not running: fail at once like a refused connection (the default is to wait for the pipe to appear, for ever).
                await pipe.ConnectAsync(ConnectTimeoutMilliseconds, cancel);
            }
            catch (TimeoutException)
            {
                await pipe.DisposeAsync();
                throw new IOException("no service answers on the pipe");
            }
            catch
            {
                await pipe.DisposeAsync();
                throw;
            }

            return pipe;
        },
    };

    internal override void Configure(Microsoft.AspNetCore.Hosting.IWebHostBuilder host)
    {
        host.ConfigureServices(services => services.Configure<Microsoft.AspNetCore.Server.Kestrel.Transport.NamedPipes.NamedPipeTransportOptions>(options =>
        {
            // Kestrel's own current-user mode and an explicit access list exclude each other: the list below says the same (this user) and also refuses network clients.
            options.CurrentUserOnly = false;
            options.PipeSecurity = BuildSecurity();
        }));
    }

    private static System.IO.Pipes.PipeSecurity BuildSecurity()
    {
        System.IO.Pipes.PipeSecurity security = new();
        System.Security.Principal.SecurityIdentifier me = System.Security.Principal.WindowsIdentity.GetCurrent().User!;
        security.AddAccessRule(new System.IO.Pipes.PipeAccessRule(new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.NetworkSid, null), System.IO.Pipes.PipeAccessRights.FullControl, System.Security.AccessControl.AccessControlType.Deny));
        security.AddAccessRule(new System.IO.Pipes.PipeAccessRule(me, System.IO.Pipes.PipeAccessRights.ReadWrite | System.IO.Pipes.PipeAccessRights.CreateNewInstance, System.Security.AccessControl.AccessControlType.Allow));
        security.SetOwner(me);

        return security;
    }
    internal override void Listen(KestrelServerOptions kestrel) => kestrel.ListenNamedPipe(Name);
}

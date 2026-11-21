using System.Net;
using System.Net.Sockets;
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

    /// <summary>The service is listening: what can only be done once the endpoint exists.</summary>
    internal virtual void Started()
    {
    }

    /// <summary>The service stopped: what the endpoint leaves behind is removed.</summary>
    internal virtual void Stopped()
    {
    }

    /// <summary>The loopback TCP endpoint on <paramref name="port" />: 127.0.0.1 and, where the host has IPv6, [::1].</summary>
    public static LocalEndpoint Loopback(int port, bool ipv6 = true) => new LoopbackEndpoint(port, ipv6);

    /// <summary>The endpoint the command line of this user uses on this platform. Windows: the user's named pipe. Linux and macOS: the user's Unix-domain socket.</summary>
    public static LocalEndpoint ForCommandLine() => OperatingSystem.IsWindows() ? new NamedPipeEndpoint(NamedPipeEndpoint.DefaultName()) : new UnixSocketEndpoint(UnixSocketEndpoint.DefaultDirectory());

    /// <summary>A Unix-domain socket in <paramref name="directory" /> (Linux and macOS; tests use a directory of their own).</summary>
    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    public static LocalEndpoint UnixSocket(string directory) => new UnixSocketEndpoint(directory);

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
        // The owner is the token's default owner, which is what the client's CurrentUserOnly check compares with: the user's own SID, or the Administrators group for an elevated process. Only the access list above decides who may open the pipe.
        security.SetOwner(System.Security.Principal.WindowsIdentity.GetCurrent().Owner!);

        return security;
    }
    internal override void Listen(KestrelServerOptions kestrel) => kestrel.ListenNamedPipe(Name);
}

/// <summary>
/// Linux and macOS: a Unix-domain socket in a directory that only the current user can enter. The directory is the access control (a path through it needs the owner's permission), the socket itself is owner-only as well.
/// The directory must be a real directory (never a link) with exactly the owner's permissions: anything else is refused, never repaired, because a directory somebody else could have prepared is not one to put the socket in.
/// A socket file that is left over from a service that is gone is replaced; one that something answers on is never touched.
/// </summary>
[System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
internal sealed class UnixSocketEndpoint : LocalEndpoint
{
    private const UnixFileMode OwnerOnlyDirectory = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode OwnerOnlyFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    /// <summary>The longest socket path that is accepted: the platforms' own limit is 104 (macOS) or 108 (Linux) bytes including the end.</summary>
    internal const int MaxPathBytes = 100;

    public UnixSocketEndpoint(string directory)
    {
        Directory = directory;
        SocketPath = Path.Combine(directory, "service.sock");
        if (System.Text.Encoding.UTF8.GetByteCount(SocketPath) > MaxPathBytes)
        {
            throw new IOException("the socket path is too long for this platform (" + MaxPathBytes + " bytes at most): " + SocketPath);
        }
    }

    public string Directory { get; }

    public string SocketPath { get; }

    public override Uri BaseUri { get; } = new("http://localhost/");

    public override string Describe() => "the socket " + SocketPath;

    /// <summary>
    /// The directory of the current user's service. Linux: <c>$XDG_RUNTIME_DIR/with-secrets</c> (the per-user runtime directory, owner-only, removed at logout) when it is set, else <c>/tmp/with-secrets-UID</c>.
    /// macOS: <c>with-secrets</c> in the per-user temporary directory (<c>$TMPDIR</c>, owner-only), else <c>/tmp/with-secrets-UID</c>. The fallback sits in a shared directory, which is why the permissions are checked.
    /// </summary>
    public static string DefaultDirectory()
    {
        string? runtime = OperatingSystem.IsLinux() ? Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR") : OperatingSystem.IsMacOS() ? Path.GetTempPath().TrimEnd('/') : null;
        if (!string.IsNullOrEmpty(runtime) && Path.IsPathRooted(runtime))
        {
            return Path.Combine(runtime, "with-secrets");
        }

        return "/tmp/with-secrets-" + UserId().ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    [System.Runtime.InteropServices.DllImport("libc", EntryPoint = "geteuid")]
    private static extern uint GetEffectiveUserId();

    private static uint UserId() => GetEffectiveUserId();

    public override SocketsHttpHandler CreateHandler() => new()
    {
        UseProxy = false,
        AllowAutoRedirect = false,
        ConnectCallback = async (_, cancel) =>
        {
            // Before connecting: the directory is private to this user and the socket path is not a link. A different directory is not this user's service.
            CheckDirectory(create: false);
            if (new FileInfo(SocketPath).LinkTarget is not null)
            {
                throw new IOException("the service socket is a link: " + SocketPath);
            }

            Socket socket = new(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            try
            {
                await socket.ConnectAsync(new UnixDomainSocketEndPoint(SocketPath), cancel);
            }
            catch
            {
                socket.Dispose();
                throw;
            }

            return new NetworkStream(socket, ownsSocket: true);
        },
    };

    internal override void Listen(KestrelServerOptions kestrel)
    {
        CheckDirectory(create: true);
        RemoveStaleSocket();
        kestrel.ListenUnixSocket(SocketPath);
    }

    /// <summary>The socket exists now: owner-only (the directory already keeps everyone else out; this is the second lock).</summary>
    internal override void Started()
    {
        File.SetUnixFileMode(SocketPath, OwnerOnlyFile);
    }

    internal override void Stopped()
    {
        try
        {
            if (File.Exists(SocketPath) && new FileInfo(SocketPath).LinkTarget is null)
            {
                File.Delete(SocketPath);
            }
        }
        catch (IOException)
        {
            // Left behind: the next start sees it is stale and replaces it.
        }
    }

    /// <summary>Makes the directory (owner-only) or checks the one that is there: a real directory, owner-only permissions. Throws with the reason otherwise.</summary>
    private void CheckDirectory(bool create)
    {
        if (!System.IO.Directory.Exists(Directory))
        {
            if (!create)
            {
                throw new IOException("no service directory: " + Directory);
            }

            string? parent = Path.GetDirectoryName(Directory);
            if (parent is null || !System.IO.Directory.Exists(parent))
            {
                throw new IOException("the directory for the service socket does not exist: " + parent);
            }

            System.IO.Directory.CreateDirectory(Directory, OwnerOnlyDirectory);
        }

        DirectoryInfo info = new(Directory);
        if (info.LinkTarget is not null || info.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new IOException("the service directory is a link, which is not accepted: " + Directory);
        }

        UnixFileMode mode = File.GetUnixFileMode(Directory);
        if (mode != OwnerOnlyDirectory)
        {
            throw new IOException("the service directory is not private to this user (mode " + Convert.ToString((int)mode, 8) + ", it must be 700): " + Directory);
        }

        if (!create)
        {
            // The client only connects: a directory that another user owns cannot be entered with these permissions, so the connection would fail anyway.
            return;
        }

        // The service makes a socket here: the directory is owner-only and this process can use it, so it is this user's (another user's 0700 directory cannot be entered; root's is root's).
        string probe = Path.Combine(Directory, ".probe-" + Guid.NewGuid().ToString("N")[..8]);
        try
        {
            using FileStream stream = new(probe, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.DeleteOnClose);
        }
        catch (UnauthorizedAccessException)
        {
            throw new IOException("the service directory cannot be used by this user: " + Directory);
        }
    }

    /// <summary>A socket file nobody answers on is from a service that is gone: removed. One that answers is a running service: nothing is touched and the start fails. A link is never followed or removed.</summary>
    private void RemoveStaleSocket()
    {
        FileInfo file = new(SocketPath);
        if (file.LinkTarget is not null)
        {
            throw new IOException("the service socket path is a link, which is not accepted: " + SocketPath);
        }

        if (!file.Exists)
        {
            return;
        }

        using Socket probe = new(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            probe.Connect(new UnixDomainSocketEndPoint(SocketPath));
        }
        catch (SocketException)
        {
            // Nothing answers: left over.
            File.Delete(SocketPath);

            return;
        }

        throw new IOException("a service is already running for this user (it answers on " + SocketPath + ")");
    }
}

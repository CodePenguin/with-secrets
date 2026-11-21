using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.DependencyInjection;

using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace WithSecrets;

/// <summary>
/// The command line's channel to the service exists but cannot be used safely, or was refused (a directory that is not private to this user, a socket or pipe that another user or another elevation level made, a path that is
/// not a socket). Its message names the place and the rule, never request content. Nothing is sent. It is not "the service is not running": that is a plain I/O error of the connection.
/// </summary>
public sealed class LocalChannelException(string message, Exception? inner = null) : IOException(message, inner)
{
    /// <summary>The channel problem in <paramref name="failure" /> or what it wraps (the HTTP client wraps what the connection throws), or null.</summary>
    public static LocalChannelException? Find(Exception? failure)
    {
        for (Exception? current = failure; current is not null; current = current.InnerException)
        {
            if (current is LocalChannelException found)
            {
                return found;
            }
        }

        return null;
    }
}

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
    public SocketsHttpHandler CreateHandler() => new()
    {
        UseProxy = false,
        AllowAutoRedirect = false,
        ConnectCallback = async (_, cancel) => await ConnectAsync(cancel),
    };

    /// <summary>Opens a connection to the endpoint (the one place that connects). Throws when nothing is listening there or the place is not safe to connect through.</summary>
    public abstract Task<Stream> ConnectAsync(CancellationToken cancel);

    /// <summary>Makes the service listen here.</summary>
    internal abstract void Listen(KestrelServerOptions kestrel);

    internal const string CommandLineSurface = "cli";
    internal const string BrowserSurface = "browser";
    internal const string SurfaceItem = "with-secrets.surface";

    /// <summary>Marks every connection on a listener with its surface, before anything of the request is read. The service answers a request only for the surface of the connection it came on.</summary>
    internal static Action<ListenOptions> Tag(string surface, Func<Microsoft.AspNetCore.Connections.ConnectionContext, bool>? admit = null) => listen => listen.Use(next => async context =>
    {
        if (admit is not null && !admit(context))
        {
            context.Abort();

            return;
        }

        context.Items[SurfaceItem] = surface;
        await next(context);
    });

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

    /// <summary>The loopback TCP listener of the browser administration on <paramref name="port" />: 127.0.0.1 and, where the host has IPv6, [::1]. The command line does not use it.</summary>
    internal static LocalEndpoint Loopback(int port, bool ipv6 = true) => new LoopbackEndpoint(port, ipv6);

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

    public override async Task<Stream> ConnectAsync(CancellationToken cancel)
    {
        TcpClient client = new();
        try
        {
            await client.ConnectAsync(IPAddress.Loopback, Port, cancel);
        }
        catch
        {
            client.Dispose();
            throw;
        }

        return client.GetStream();
    }

    internal override void Listen(KestrelServerOptions kestrel)
    {
        kestrel.Listen(IPAddress.Loopback, Port, Tag(BrowserSurface));
        if (ipv6)
        {
            kestrel.Listen(IPAddress.IPv6Loopback, Port, Tag(BrowserSurface));
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
    /// <summary>A service that is running accepts at once; this is only how long a busy one (every pipe instance in use for a moment, as when many commands start together) is waited for. A pipe that does not exist is not waited for.</summary>
    private const int ConnectTimeoutMilliseconds = 10000;

    public string Name { get; } = name;

    public override Uri BaseUri { get; } = new("http://localhost/");

    public override string Describe() => "the named pipe " + Name;

    /// <summary>The pipe of the current user: one per user, because pipe names are shared by every user of the machine.</summary>
    public static string DefaultName()
    {
        string sid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value ?? "unknown";

        return "with-secrets-" + sid;
    }

    /// <summary>Whether a pipe of this name exists now, from the list of pipes (nothing is opened, so no instance is taken).</summary>
    private static bool PipeExists(string name)
    {
        foreach (string entry in Directory.EnumerateFileSystemEntries(@"\\.\pipe\"))
        {
            if (string.Equals(Path.GetFileName(entry), name, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    public override async Task<Stream> ConnectAsync(CancellationToken cancel)
    {
        System.IO.Pipes.NamedPipeClientStream pipe = new(".", Name, System.IO.Pipes.PipeDirection.InOut, System.IO.Pipes.PipeOptions.Asynchronous | System.IO.Pipes.PipeOptions.CurrentUserOnly, System.Security.Principal.TokenImpersonationLevel.Anonymous);
        try
        {
            // A pipe that does not exist is a service that is not running: it fails at once, like a refused connection (the connect call itself would wait for the pipe to appear). One that exists but is busy is waited for.
            if (!PipeExists(Name))
            {
                throw new IOException("no service answers on the pipe");
            }

            await pipe.ConnectAsync(ConnectTimeoutMilliseconds, cancel);
        }
        catch (TimeoutException)
        {
            await pipe.DisposeAsync();
            throw new IOException("no service answers on the pipe");
        }
        catch (UnauthorizedAccessException refusal)
        {
            // The client's own check (CurrentUserOnly) found the pipe is not owned by this process's token owner, or the access list refused it. The owner of an elevated process is the Administrators group and of a normal one the
            // user, so a service and a command at different elevation levels (under the same account) refuse each other. Neither is relaxed: the pipe is the access control.
            await pipe.DisposeAsync();
            throw new LocalChannelException("the pipe " + Name + " was made by a process the command may not talk to: it is owned by another user, or the service and this command run at different elevation levels (one as administrator, one not). Run both at the same elevation level, as the same user.", refusal);
        }
        catch
        {
            await pipe.DisposeAsync();
            throw;
        }

        return pipe;
    }
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
    internal override void Listen(KestrelServerOptions kestrel) => kestrel.ListenNamedPipe(Name, Tag(CommandLineSurface));
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
            throw new LocalChannelException("the socket path is too long for this platform (" + MaxPathBytes + " bytes at most): " + SocketPath);
        }
    }

    public string Directory { get; }

    public string SocketPath { get; }

    public override Uri BaseUri { get; } = new("http://localhost/");

    public override string Describe() => "the socket " + SocketPath;

    /// <summary>Directories every user can write to: a socket directory is never made directly inside one of them under a shared name.</summary>
    private static readonly string[] SharedDirectories = ["/", "/tmp", "/var/tmp", "/usr/tmp", "/private/tmp", "/private/var/tmp", "/dev/shm", "/run", "/var/run"];

    /// <summary>
    /// The directory of the current user's service. Linux: <c>$XDG_RUNTIME_DIR/with-secrets</c>. macOS: <c>$TMPDIR/with-secrets</c>. Each only when the variable is set to a directory that is private to this user (owned by it,
    /// not writable by anyone else) and is not one of the shared system directories; otherwise <c>/tmp/with-secrets-UID</c>, a name that is different for every user. (.NET's own temporary-directory function answers
    /// <c>/tmp</c> when TMPDIR is unset, which is shared, so it is not used.) The directory is then checked as strictly as any other: owned by this user, mode 700, not a link; one that is not is refused, never repaired.
    /// </summary>
    public static string DefaultDirectory()
    {
        return ResolveDirectory(OperatingSystem.IsLinux(), OperatingSystem.IsMacOS(), Environment.GetEnvironmentVariable, GetEffectiveUserId(), IsPrivateRuntimeParent);
    }

    /// <summary>The choice of directory, with everything it depends on given (so that every case can be tested): the platform, the environment, the user id and whether a place is private to this user.</summary>
    internal static string ResolveDirectory(bool linux, bool macos, Func<string, string?> environment, uint userId, Func<string, bool> isPrivateToUser)
    {
        string? runtime = linux ? environment("XDG_RUNTIME_DIR") : macos ? environment("TMPDIR") : null;
        if (!string.IsNullOrEmpty(runtime) && Path.IsPathRooted(runtime))
        {
            string full = Path.GetFullPath(runtime).TrimEnd('/');
            if (full.Length > 0 && !SharedDirectories.Contains(full, StringComparer.Ordinal) && isPrivateToUser(full))
            {
                return Path.Combine(full, "with-secrets");
            }
        }

        return "/tmp/with-secrets-" + userId.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>A real directory (not a link) that this user owns and that no one else can write to: a place only this user can put a name in.</summary>
    internal static bool IsPrivateRuntimeParent(string path)
    {
        UnixFileInfo? info = UnixFileInfo.Of(path);

        return info is { IsDirectory: true } && info.Owner == GetEffectiveUserId() && (info.Permissions & 0x12) == 0;
    }
    [System.Runtime.InteropServices.DllImport("libc", EntryPoint = "geteuid")]
    private static extern uint GetEffectiveUserId();

    /// <summary>The effective user id of this process.</summary>
    internal static uint EffectiveUserId() => GetEffectiveUserId();

    public override async Task<Stream> ConnectAsync(CancellationToken cancel)
    {
        // Before connecting: the directory is private to this user and the socket path is not a link. A different directory is not this user's service.
        CheckDirectory(create: false);
        if (new FileInfo(SocketPath).LinkTarget is not null)
        {
            throw new LocalChannelException("the service socket is a link: " + SocketPath);
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
    }
    internal override void Listen(KestrelServerOptions kestrel)
    {
        CheckDirectory(create: true);
        RemoveStaleSocket();
        // Defense in depth: the directory already keeps other users out; every accepted connection is also asked who is on the other end (the kernel's record of the peer's user), and one that is not this user is closed
        // before a byte of it is read. When the peer cannot be determined the connection is refused as well.
        kestrel.ListenUnixSocket(SocketPath, Tag(CommandLineSurface, PeerIsThisUser));
    }

    /// <summary>For tests: the user id a peer must have (default: this process's effective user id).</summary>
    internal uint? ExpectedPeerUserId { get; init; }

    /// <summary>For tests: the user id that must own the directory (default: this process's effective user id). A directory owned by anyone else is refused.</summary>
    internal uint? ExpectedOwnerUserId { get; init; }

    private bool PeerIsThisUser(Microsoft.AspNetCore.Connections.ConnectionContext context)
    {
        try
        {
            Socket? socket = context.Features.Get<Microsoft.AspNetCore.Connections.Features.IConnectionSocketFeature>()?.Socket;

            return socket is not null && PeerUserId(socket) is { } peer && peer == (ExpectedPeerUserId ?? GetEffectiveUserId());
        }
        catch (Exception error) when (error is SocketException or InvalidOperationException or PlatformNotSupportedException or ObjectDisposedException)
        {
            return false;
        }
    }

    /// <summary>The user id of the process at the other end of a Unix socket, as the kernel recorded it when it connected (Linux SO_PEERCRED, macOS LOCAL_PEERCRED). Null where this platform has neither.</summary>
    internal static uint? PeerUserId(Socket socket)
    {
        if (OperatingSystem.IsLinux())
        {
            // struct ucred { pid_t pid; uid_t uid; gid_t gid; }
            byte[] value = new byte[12];
            socket.GetRawSocketOption(1, 17, value);

            return BitConverter.ToUInt32(value, 4);
        }

        if (OperatingSystem.IsMacOS())
        {
            // struct xucred { u_int cr_version; uid_t cr_uid; short cr_ngroups; gid_t cr_groups[16]; }, level SOL_LOCAL (0), LOCAL_PEERCRED (1)
            byte[] value = new byte[76];
            socket.GetRawSocketOption(0, 1, value);

            return BitConverter.ToUInt32(value, 4);
        }

        return null;
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
                throw new LocalChannelException("the directory for the service socket does not exist: " + parent);
            }

            System.IO.Directory.CreateDirectory(Directory, OwnerOnlyDirectory);
        }

        DirectoryInfo info = new(Directory);
        if (info.LinkTarget is not null || info.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new LocalChannelException("the service directory is a link, which is not accepted: " + Directory);
        }

        UnixFileInfo? directoryInfo = UnixFileInfo.Of(Directory);
        if (directoryInfo is null)
        {
            // Fail closed: what cannot be checked is not trusted.
            throw new LocalChannelException("the owner of the service directory cannot be determined: " + Directory);
        }

        if (!directoryInfo.IsDirectory || directoryInfo.Owner != (ExpectedOwnerUserId ?? GetEffectiveUserId()))
        {
            throw new LocalChannelException("the service directory is not owned by this user (it is owned by user " + directoryInfo.Owner.ToString(System.Globalization.CultureInfo.InvariantCulture) + "): " + Directory);
        }

        UnixFileMode mode = File.GetUnixFileMode(Directory);
        if (mode != OwnerOnlyDirectory)
        {
            throw new LocalChannelException("the service directory is not private to this user (mode " + Convert.ToString((int)mode, 8) + ", it must be 700): " + Directory);
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
            throw new LocalChannelException("the service directory cannot be used by this user: " + Directory);
        }
    }

    /// <summary>What a failed probe connection to an existing socket file says about the service behind it.</summary>
    internal enum ProbeVerdict
    {
        /// <summary>The kernel says nothing is listening on the socket: it is from a service that is gone.</summary>
        Stale,

        /// <summary>Anything else (no permission, a busy or interrupted probe, an unexpected error): not known that nothing answers, so nothing is touched.</summary>
        Unknown,
    }

    /// <summary>Only a refused connection (ECONNREFUSED: the file is a socket and nothing listens on it) proves a socket stale. Access, address, timeout and every other error do not.</summary>
    internal static ProbeVerdict ClassifyProbeFailure(SocketError error) => error == SocketError.ConnectionRefused ? ProbeVerdict.Stale : ProbeVerdict.Unknown;

    /// <summary>
    /// A socket file nobody answers on is from a service that is gone: removed. One that answers is a running service: nothing is touched and the start fails. Only a socket that this user owns is ever removed: a link, a
    /// file or directory that is not a socket, a socket of anyone else, and a socket whose state cannot be told are left as they are and the start fails with the reason.
    /// </summary>
    private void RemoveStaleSocket()
    {
        FileInfo file = new(SocketPath);
        if (file.LinkTarget is not null)
        {
            throw new LocalChannelException("the service socket path is a link, which is not accepted: " + SocketPath);
        }

        UnixFileInfo? entry = UnixFileInfo.Of(SocketPath);
        if (entry is null)
        {
            if (!file.Exists && !System.IO.Directory.Exists(SocketPath))
            {
                return;
            }

            throw new LocalChannelException("cannot tell what is at the socket path, so it is not touched: " + SocketPath);
        }

        if (!entry.IsSocket)
        {
            throw new LocalChannelException("the socket path holds something that is not a socket, so it is not touched: " + SocketPath);
        }

        if (entry.Owner != (ExpectedOwnerUserId ?? GetEffectiveUserId()))
        {
            throw new LocalChannelException("the socket at the socket path is not this user's, so it is not touched: " + SocketPath);
        }

        using Socket probe = new(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            probe.Connect(new UnixDomainSocketEndPoint(SocketPath));
        }
        catch (SocketException failure) when (ClassifyProbeFailure(failure.SocketErrorCode) == ProbeVerdict.Unknown)
        {
            throw new LocalChannelException("cannot tell whether a service answers on " + SocketPath + " (" + failure.SocketErrorCode + "), so it is not touched");
        }
        catch (SocketException)
        {
            // Refused: nothing listens, left over.
            try
            {
                File.Delete(SocketPath);
            }
            catch (Exception failure) when (failure is IOException or UnauthorizedAccessException)
            {
                throw new LocalChannelException("the socket left by a service that is gone cannot be removed (" + failure.GetType().Name + "): " + SocketPath, failure);
            }

            return;
        }

        throw new LocalChannelException("a service is already running for this user (it answers on " + SocketPath + ")");
    }
}

/// <summary>What the file system says about a path itself (a link is not followed): its owner, its permission bits and what kind of entry it is. Linux: statx; macOS: lstat. Null where it cannot be asked (the caller then does not trust the path).</summary>
[System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
internal sealed class UnixFileInfo
{
    private const uint FileTypeMask = 0xF000;
    private const uint DirectoryType = 0x4000;
    private const uint SocketType = 0xC000;

    private UnixFileInfo(uint owner, uint mode)
    {
        Owner = owner;
        Mode = mode;
    }

    public uint Owner { get; }

    /// <summary>The file type and permission bits (st_mode).</summary>
    public uint Mode { get; }

    /// <summary>The permission bits only (rwx for user, group and other).</summary>
    public uint Permissions => Mode & 0xFFF;

    public bool IsDirectory => (Mode & FileTypeMask) == DirectoryType;

    public bool IsSocket => (Mode & FileTypeMask) == SocketType;

    public static UnixFileInfo? Of(string path)
    {
        try
        {
            byte[] buffer = new byte[512];
            if (OperatingSystem.IsLinux())
            {
                // struct statx: stx_mask u32 at 0, stx_uid u32 at 20, stx_mode u16 at 28. AT_FDCWD = -100, AT_SYMLINK_NOFOLLOW = 0x100, STATX_TYPE | STATX_MODE | STATX_UID = 0x7.
                if (StatX(-100, path, 0x100, 0x7, buffer) != 0)
                {
                    return null;
                }

                return (BitConverter.ToUInt32(buffer, 0) & 0x7) == 0x7 ? new UnixFileInfo(BitConverter.ToUInt32(buffer, 20), BitConverter.ToUInt16(buffer, 28)) : null;
            }

            if (OperatingSystem.IsMacOS())
            {
                // struct stat (64-bit inodes): st_mode u16 at 4, st_uid u32 at 16. The Intel build of the system library names that variant lstat$INODE64.
                int result;
                try
                {
                    result = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture == System.Runtime.InteropServices.Architecture.X64 ? LStat64(path, buffer) : LStat(path, buffer);
                }
                catch (EntryPointNotFoundException)
                {
                    result = LStat(path, buffer);
                }

                return result == 0 ? new UnixFileInfo(BitConverter.ToUInt32(buffer, 16), BitConverter.ToUInt16(buffer, 4)) : null;
            }

            return null;
        }
        catch (Exception failure) when (failure is DllNotFoundException or EntryPointNotFoundException or System.Runtime.InteropServices.MarshalDirectiveException)
        {
            return null;
        }
    }

    [System.Runtime.InteropServices.DllImport("libc", EntryPoint = "statx")]
    private static extern int StatX(int directory, [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPUTF8Str)] string path, int flags, uint mask, byte[] buffer);

    [System.Runtime.InteropServices.DllImport("libc", EntryPoint = "lstat")]
    private static extern int LStat([System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPUTF8Str)] string path, byte[] buffer);

    [System.Runtime.InteropServices.DllImport("libc", EntryPoint = "lstat$INODE64")]
    private static extern int LStat64([System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPUTF8Str)] string path, byte[] buffer);
}
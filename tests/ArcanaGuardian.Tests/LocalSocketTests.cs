using System.Net;
using System.Net.Sockets;

namespace ArcanaGuardian.Tests;

/// <summary>
/// The command line's endpoint on Linux and macOS is a Unix-domain socket in a directory only the current user can enter. The same application protocol runs over it (the whole host-service suite runs over a socket there);
/// what is checked here is what is particular to the socket: the permissions of the directory and the socket, that an unsafe directory or path is refused (never repaired, never followed), that a socket something answers on is
/// never taken over or removed, that one left over is replaced, and that the client fails at once when there is no service. A second OS user cannot be made on a test machine, so "another user cannot connect" is shown through
/// the permissions (what the kernel checks) rather than by a connection attempt.
/// </summary>
internal static class LocalSocketTests
{
    public static async Task Run(Action<bool, string> check)
    {
        if (OperatingSystem.IsWindows())
        {
            Console.WriteLine("  SKIP unix socket endpoint: Linux and macOS only (Windows uses a named pipe)");

            return;
        }

        await SocketChecks(check);
        await HardeningChecks(check);
    }

    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private static async Task SocketChecks(Action<bool, string> check)
    {
        string parent = Path.Combine(Path.GetTempPath(), "ws-sock-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(parent);
        File.SetUnixFileMode(parent, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            using HostServiceTests.Rig rig = new(parent);
            UnixSocketEndpoint endpoint = (UnixSocketEndpoint)rig.Service.Endpoint;
            check(rig.Service.Endpoint.Describe().Contains("socket", StringComparison.Ordinal) && rig.Service.Endpoint.BaseUri.Host == "localhost", "socket: the command line's endpoint of the service is a Unix socket, addressed as http://localhost/ (no port)");
            using HttpResponseMessage status = await rig.Http.GetAsync(rig.Url("/v1/status"));
            check(status.IsSuccessStatusCode && (await status.Content.ReadAsStringAsync()).Contains("\"running\":true", StringComparison.Ordinal), "socket: a request over the socket is answered by the same application handler");

            UnixFileMode directoryMode = File.GetUnixFileMode(endpoint.Directory);
            UnixFileMode socketMode = File.GetUnixFileMode(endpoint.SocketPath);
            check(directoryMode == (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute), "socket: the directory is owner-only, mode 700 (" + Convert.ToString((int)directoryMode, 8) + ")");
            check(socketMode == (UnixFileMode.UserRead | UnixFileMode.UserWrite), "socket: the socket is owner-only, mode 600 (" + Convert.ToString((int)socketMode, 8) + ")");

            // Unsafe places are refused with a reason, not repaired and not followed.
            string openDirectory = Path.Combine(parent, "open");
            Directory.CreateDirectory(openDirectory);
            File.SetUnixFileMode(openDirectory, (UnixFileMode)Convert.ToInt32("755", 8));
            check(Starts(parent, LocalEndpoint.UnixSocket(openDirectory), out string openReason) is null && File.GetUnixFileMode(openDirectory) == (UnixFileMode)Convert.ToInt32("755", 8), "socket: a directory that others can enter is refused, and not changed (" + openReason + ")");

            string target = Path.Combine(parent, "target");
            Directory.CreateDirectory(target);
            File.SetUnixFileMode(target, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            string linked = Path.Combine(parent, "linked");
            Directory.CreateSymbolicLink(linked, target);
            check(Starts(parent, LocalEndpoint.UnixSocket(linked), out string linkReason) is null && Directory.GetFileSystemEntries(target).Length == 0, "socket: a directory that is a link is refused, and nothing was made behind it (" + linkReason + ")");

            string pathLink = Path.Combine(parent, "pathlink");
            Directory.CreateDirectory(pathLink);
            File.SetUnixFileMode(pathLink, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            string victim = Path.Combine(parent, "victim.txt");
            File.WriteAllText(victim, "keep");
            File.CreateSymbolicLink(Path.Combine(pathLink, "service.sock"), victim);
            check(Starts(parent, LocalEndpoint.UnixSocket(pathLink), out string socketLinkReason) is null && File.ReadAllText(victim) == "keep" && File.Exists(victim), "socket: a socket path that is a link is refused, and the file behind it is untouched (" + socketLinkReason + ")");

            string longDirectory = Path.Combine(parent, new string('d', 120));
            Exception? tooLong = null;
            try
            {
                _ = LocalEndpoint.UnixSocket(longDirectory);
            }
            catch (IOException error)
            {
                tooLong = error;
            }

            check(tooLong is not null && tooLong.Message.Contains("too long", StringComparison.Ordinal), "socket: a path that is too long for the platform is refused with that reason");

            // A running service is never taken over or removed: a second one on the same socket does not start and the first still answers.
            HostService? second = Starts(parent, LocalEndpoint.UnixSocket(endpoint.Directory), out string secondReason);
            second?.Dispose();
            using HttpResponseMessage after = await rig.Http.GetAsync(rig.Url("/v1/status"));
            check(second is null && secondReason.Contains("already running", StringComparison.Ordinal) && after.IsSuccessStatusCode && File.Exists(endpoint.SocketPath), "socket: a second service on a socket that is answering does not start, and the first keeps its socket (" + secondReason + ")");

            // A socket left by a service that is gone is replaced.
            string staleDirectory = Path.Combine(parent, "stale");
            Directory.CreateDirectory(staleDirectory);
            File.SetUnixFileMode(staleDirectory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            string stalePath = Path.Combine(staleDirectory, "service.sock");
            // Bound and never listening: the file is there and nothing answers on it (a closed socket would remove its own file).
            using Socket stale = new(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            stale.Bind(new UnixDomainSocketEndPoint(stalePath));
            bool left = File.Exists(stalePath);
            HostService? replaced = Starts(parent, LocalEndpoint.UnixSocket(staleDirectory), out string replacedReason);
            bool answers = false;
            if (replaced is not null)
            {
                using HttpClient client = new(replaced.Endpoint.CreateHandler()) { Timeout = TimeSpan.FromSeconds(10) };
                using HttpResponseMessage reply = await client.GetAsync(new Uri(replaced.Endpoint.BaseUri, "v1/status"));
                answers = reply.IsSuccessStatusCode;
                replaced.Dispose();
            }

            check(left && answers, "socket: a socket left by a service that is gone is replaced, and the new service answers (" + replacedReason + ")");
            check(replaced is not null && !File.Exists(stalePath), "socket: the socket is removed when the service stops");

            // The client checks the place before it connects: a directory that became open is not trusted.
            File.SetUnixFileMode(endpoint.Directory, (UnixFileMode)Convert.ToInt32("755", 8));
            Exception? refused = null;
            try
            {
                using HttpClient strict = new(endpoint.CreateHandler()) { Timeout = TimeSpan.FromSeconds(10) };
                await strict.GetAsync(rig.Url("/v1/status"));
            }
            catch (Exception error)
            {
                refused = error;
            }
            finally
            {
                File.SetUnixFileMode(endpoint.Directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }

            check(refused is HttpRequestException, "socket: the client does not connect through a directory that others can enter");

            // Defense in depth: a peer whose user is not the one expected is closed before anything is read. Here the expectation is changed, which is what a connection from another user looks like to the service.
            uint me = UnixSocketEndpoint.EffectiveUserId();
            string peerDirectory = Path.Combine(parent, "peer");
            Directory.CreateDirectory(peerDirectory);
            File.SetUnixFileMode(peerDirectory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            HostService? strictPeer = Starts(parent, new UnixSocketEndpoint(peerDirectory) { ExpectedPeerUserId = me + 1 }, out string strictReason);
            Exception? wrongUser = null;
            if (strictPeer is not null)
            {
                try
                {
                    using HttpClient stranger = new(strictPeer.Endpoint.CreateHandler()) { Timeout = TimeSpan.FromSeconds(10) };
                    await stranger.GetAsync(new Uri(strictPeer.Endpoint.BaseUri, "v1/status"));
                }
                catch (Exception error)
                {
                    wrongUser = error;
                }

                strictPeer.Dispose();
            }

            string rightDirectory = Path.Combine(parent, "peer2");
            Directory.CreateDirectory(rightDirectory);
            File.SetUnixFileMode(rightDirectory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            HostService? rightPeer = Starts(parent, new UnixSocketEndpoint(rightDirectory) { ExpectedPeerUserId = me }, out string rightReason);
            bool rightAnswers = false;
            if (rightPeer is not null)
            {
                using HttpClient friend = new(rightPeer.Endpoint.CreateHandler()) { Timeout = TimeSpan.FromSeconds(10) };
                using HttpResponseMessage friendReply = await friend.GetAsync(new Uri(rightPeer.Endpoint.BaseUri, "v1/status"));
                rightAnswers = friendReply.IsSuccessStatusCode;
                rightPeer.Dispose();
            }

            check(wrongUser is HttpRequestException && rightAnswers, "socket: the service asks the kernel who the peer is: a peer of another user is closed unanswered, the same user is answered (" + strictReason + ", " + rightReason + ")");
            // No service: the client fails at once with a connection error, and the command line says the service is not running (exit 6); there is no port to fall back to.
            string emptyDirectory = Path.Combine(parent, "empty");
            Directory.CreateDirectory(emptyDirectory);
            File.SetUnixFileMode(emptyDirectory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            StringWriter err = new();
            System.Diagnostics.Stopwatch clock = System.Diagnostics.Stopwatch.StartNew();
            int code = await LaunchClient.RunAsync(CliArgs.ParseRun(["--secrets", "TOKEN", "--reason", "no service", "--", "anything"], out _)!, rig.Work, LocalEndpoint.UnixSocket(emptyDirectory), null, new StringWriter(), err, rig.Machine.Trust);
            check(code == LaunchClient.ServiceNotRunning && err.ToString().Contains("not running", StringComparison.OrdinalIgnoreCase) && clock.Elapsed < TimeSpan.FromSeconds(10), "socket: a run with no service exits 6 at once and says the service is not running (" + code + ", " + clock.ElapsedMilliseconds + " ms)");
        }
        finally
        {
            foreach (HostServiceTests.Rig other in Others)
            {
                other.Dispose();
            }

            Others.Clear();
            try
            {
                Directory.Delete(parent, true);
            }
            catch (IOException)
            {
                // A stray temp file is harmless.
            }
        }
    }

    private const UnixFileMode Private = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private static string PrivateDirectory(string parent, string name)
    {
        string path = Path.Combine(parent, name);
        Directory.CreateDirectory(path);
        File.SetUnixFileMode(path, Private);

        return path;
    }

    /// <summary>
    /// Where the directory is (never a shared name), who must own it, and when a socket file may be removed. These are the cases of the review that followed the first implementation: an unset or shared TMPDIR on
    /// macOS, an unsafe directory that was already there, and a socket file that is not known to be stale (no permission, not a socket, a link, an error that proves nothing).
    /// </summary>
    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private static async Task HardeningChecks(Action<bool, string> check)
    {
        // ---- A: the directory of the service
        Func<string, bool> allPrivate = _ => true;
        Func<string, bool> nonePrivate = _ => false;
        string Resolve(bool linux, bool macos, string? variable, uint user, Func<string, bool> isPrivate) => UnixSocketEndpoint.ResolveDirectory(linux, macos, name => name is "TMPDIR" or "XDG_RUNTIME_DIR" ? variable : null, user, isPrivate);
        check(Resolve(false, true, null, 501, allPrivate) == "/tmp/arcana-guardian-501", "directory: macOS with TMPDIR unset uses the per-user fallback, not a name in the shared /tmp");
        check(Resolve(false, true, "/tmp", 501, allPrivate) == "/tmp/arcana-guardian-501" && Resolve(false, true, "/tmp/", 501, allPrivate) == "/tmp/arcana-guardian-501" && Resolve(false, true, "/private/tmp", 501, allPrivate) == "/tmp/arcana-guardian-501" && Resolve(false, true, "/var/tmp", 501, allPrivate) == "/tmp/arcana-guardian-501", "directory: a TMPDIR that is a shared system directory is not used");
        check(Resolve(false, true, "/var/folders/ab/cdef/T/", 501, allPrivate) == "/var/folders/ab/cdef/T/arcana-guardian", "directory: macOS uses the private per-user TMPDIR when it has one");
        check(Resolve(false, true, "/var/folders/ab/cdef/T/", 501, nonePrivate) == "/tmp/arcana-guardian-501", "directory: a TMPDIR that is not private to the user (not theirs, or others can write to it) is not used");
        check(Resolve(false, true, "relative/tmp", 501, allPrivate) == "/tmp/arcana-guardian-501", "directory: a TMPDIR that is not an absolute path is not used");
        check(Resolve(true, false, null, 1000, allPrivate) == "/tmp/arcana-guardian-1000" && Resolve(true, false, "/run/user/1000", 1000, allPrivate) == "/run/user/1000/arcana-guardian" && Resolve(true, false, "/tmp", 1000, allPrivate) == "/tmp/arcana-guardian-1000" && Resolve(true, false, "/run/user/1000", 1000, nonePrivate) == "/tmp/arcana-guardian-1000", "directory: Linux uses a private XDG_RUNTIME_DIR, else the per-user fallback");
        check(Resolve(false, true, null, 501, allPrivate) != Resolve(false, true, null, 502, allPrivate) && Resolve(true, false, null, 1000, allPrivate) != Resolve(true, false, null, 1001, allPrivate), "directory: two users get two different fallback directories");
        check(((UnixSocketEndpoint)LocalEndpoint.ForCommandLine()).Directory != "/tmp/arcana-guardian", "directory: the real default is never the shared name /tmp/arcana-guardian");

        string parent = Path.Combine(Path.GetTempPath(), "ws-hard-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(parent);
        File.SetUnixFileMode(parent, Private);
        List<Socket> held = [];
        try
        {
            uint me = UnixSocketEndpoint.EffectiveUserId();
            string mine = PrivateDirectory(parent, "mine");
            string wide = Path.Combine(parent, "wide");
            Directory.CreateDirectory(wide);
            File.SetUnixFileMode(wide, (UnixFileMode)Convert.ToInt32("777", 8));
            check(UnixSocketEndpoint.IsPrivateRuntimeParent(mine) && !UnixSocketEndpoint.IsPrivateRuntimeParent(wide) && !UnixSocketEndpoint.IsPrivateRuntimeParent("/tmp") && !UnixSocketEndpoint.IsPrivateRuntimeParent(Path.Combine(parent, "none")), "directory: a place counts as private only when it is a directory of this user that others cannot write to (a shared /tmp and a missing path do not)");
            UnixFileInfo? info = UnixFileInfo.Of(mine);
            check(info is { IsDirectory: true } && info.Owner == me && info.Permissions == (uint)Convert.ToInt32("700", 8), "directory: the file system's own owner, type and mode of a directory are read (owner " + info?.Owner + ")");
            UnixFileInfo? root = UnixFileInfo.Of("/");
            check(root is { IsDirectory: true, Owner: 0 }, "directory: the owner of a directory that is not the user's is read as another user (the root directory: " + root?.Owner + ")");

            // An unsafe directory that was already there: refused, left as it was, never taken over. Owned by another user (the expectation is changed, which is what a directory of another user looks like).
            string theirs = PrivateDirectory(parent, "theirs");
            string theirsMarker = Path.Combine(theirs, "keep.txt");
            File.WriteAllText(theirsMarker, "keep");
            HostService? notMine = Starts(parent, new UnixSocketEndpoint(theirs) { ExpectedOwnerUserId = me + 1 }, out string notMineReason);
            notMine?.Dispose();
            check(notMine is null && notMineReason.Contains("not owned by this user", StringComparison.Ordinal) && File.ReadAllText(theirsMarker) == "keep" && File.GetUnixFileMode(theirs) == Private && Directory.GetFileSystemEntries(theirs).Length == 1, "directory: a directory that another user owns is refused with the reason, and is not repaired or used (" + notMineReason + ")");
            Exception? clientRefused = null;
            try
            {
                using HttpClient strangers = new(new UnixSocketEndpoint(theirs) { ExpectedOwnerUserId = me + 1 }.CreateHandler()) { Timeout = TimeSpan.FromSeconds(10) };
                await strangers.GetAsync("http://localhost/v1/status");
            }
            catch (Exception error)
            {
                clientRefused = error;
            }

            check(LocalChannelException.Find(clientRefused) is { } found && found.Message.Contains("not owned by this user", StringComparison.Ordinal), "directory: the client does not connect through a directory that another user owns, and says why");

            // ---- C: when a socket file may be removed
            check(UnixSocketEndpoint.ClassifyProbeFailure(SocketError.ConnectionRefused) == UnixSocketEndpoint.ProbeVerdict.Stale, "stale: a refused connection is the one failure that proves a socket stale");
            SocketError[] unknown = [SocketError.AccessDenied, SocketError.TimedOut, SocketError.WouldBlock, SocketError.Interrupted, SocketError.AddressNotAvailable, SocketError.AddressAlreadyInUse, SocketError.InvalidArgument, SocketError.NotSocket, SocketError.TryAgain, SocketError.SocketError, SocketError.Shutdown, SocketError.ConnectionReset, SocketError.HostUnreachable, SocketError.NoBufferSpaceAvailable];
            check(unknown.All(error => UnixSocketEndpoint.ClassifyProbeFailure(error) == UnixSocketEndpoint.ProbeVerdict.Unknown), "stale: access, address, timeout, busy and every other error prove nothing, so nothing is removed");

            // A plain file or a directory where the socket belongs is not a socket: not touched.
            string fileDirectory = PrivateDirectory(parent, "file");
            string filePath = Path.Combine(fileDirectory, "service.sock");
            File.WriteAllText(filePath, "not a socket");
            HostService? overFile = Starts(parent, LocalEndpoint.UnixSocket(fileDirectory), out string overFileReason);
            overFile?.Dispose();
            check(overFile is null && overFileReason.Contains("not a socket", StringComparison.Ordinal) && File.ReadAllText(filePath) == "not a socket", "stale: a regular file at the socket path is not removed, and the start fails with the reason (" + overFileReason + ")");

            string folderDirectory = PrivateDirectory(parent, "folder");
            Directory.CreateDirectory(Path.Combine(folderDirectory, "service.sock"));
            HostService? overFolder = Starts(parent, LocalEndpoint.UnixSocket(folderDirectory), out string overFolderReason);
            overFolder?.Dispose();
            check(overFolder is null && Directory.Exists(Path.Combine(folderDirectory, "service.sock")), "stale: a directory at the socket path is not removed, and the start fails (" + overFolderReason + ")");

            // A link to a real socket is not followed or removed either.
            string realDirectory = PrivateDirectory(parent, "real");
            Socket realSocket = new(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            held.Add(realSocket);
            realSocket.Bind(new UnixDomainSocketEndPoint(Path.Combine(realDirectory, "target.sock")));
            string linkDirectory = PrivateDirectory(parent, "linkto");
            File.CreateSymbolicLink(Path.Combine(linkDirectory, "service.sock"), Path.Combine(realDirectory, "target.sock"));
            HostService? overLink = Starts(parent, LocalEndpoint.UnixSocket(linkDirectory), out string overLinkReason);
            overLink?.Dispose();
            check(overLink is null && new FileInfo(Path.Combine(linkDirectory, "service.sock")).LinkTarget is not null && File.Exists(Path.Combine(realDirectory, "target.sock")), "stale: a link to a socket is neither followed nor removed (" + overLinkReason + ")");

            // No permission to connect (a stale socket file whose mode forbids this user): not known to be stale, so it stays and the start fails. Root is not refused by modes, so this is for ordinary users only.
            if (me != 0)
            {
                string deniedDirectory = PrivateDirectory(parent, "denied");
                string deniedPath = Path.Combine(deniedDirectory, "service.sock");
                Socket denied = new(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                held.Add(denied);
                denied.Bind(new UnixDomainSocketEndPoint(deniedPath));
                File.SetUnixFileMode(deniedPath, UnixFileMode.None);
                HostService? overDenied = Starts(parent, LocalEndpoint.UnixSocket(deniedDirectory), out string overDeniedReason);
                overDenied?.Dispose();
                bool kept = File.Exists(deniedPath);
                File.SetUnixFileMode(deniedPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                check(overDenied is null && kept && overDeniedReason.Contains("not touched", StringComparison.Ordinal), "stale: a socket this user may not connect to is not removed as stale, and the start fails (" + overDeniedReason + ")");
            }
            else
            {
                Console.WriteLine("  SKIP socket without permission: running as root, which no mode refuses");
            }

            // Repeated start and stop on one directory, with a stale socket left by an earlier run each time: always the same result and nothing left behind.
            string repeat = PrivateDirectory(parent, "repeat");
            string repeatPath = Path.Combine(repeat, "service.sock");
            bool allStarted = true;
            bool allCleaned = true;
            for (int round = 0; round < 3; round++)
            {
                Socket leftover = new(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                held.Add(leftover);
                if (File.Exists(repeatPath))
                {
                    File.Delete(repeatPath);
                }

                leftover.Bind(new UnixDomainSocketEndPoint(repeatPath));
                HostService? again = Starts(parent, LocalEndpoint.UnixSocket(repeat), out _);
                allStarted &= again is not null;
                again?.Dispose();
                allCleaned &= !File.Exists(repeatPath);
            }

            check(allStarted && allCleaned, "stale: starting and stopping again and again on one directory, each time over a stale socket, replaces it every time and leaves nothing behind");
        }
        finally
        {
            foreach (Socket socket in held)
            {
                socket.Dispose();
            }

            try
            {
                Directory.Delete(parent, true);
            }
            catch (IOException)
            {
                // A stray temp file is harmless.
            }
        }
    }
    private static readonly List<HostServiceTests.Rig> Others = [];

    /// <summary>Starts a service on <paramref name="endpoint" />; null with the reason when it does not start.</summary>
    private static HostService? Starts(string parent, LocalEndpoint endpoint, out string reason)
    {
        // The rig stays alive with the service it gave its machine to; it is disposed with the test.
        HostServiceTests.Rig other = new(parent);
        Others.Add(other);
        try
        {
            reason = "started";

            return HostService.Start(new HostServiceOptions { HttpBrowserFixture = true, State = other.State, Store = other.Store, Deployment = other.Machine.Deployment, Port = 0, Lock = AuthorityLock.UnlockedForTests(), CommandLineEndpoint = endpoint });
        }
        catch (Exception error)
        {
            reason = error.GetType().Name + ": " + error.Message;

            return null;
        }
    }
}

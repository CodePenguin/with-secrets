using System.Net;
using System.Net.Sockets;

namespace WithSecrets.Tests;

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

            return HostService.Start(new HostServiceOptions { State = other.State, Store = other.Store, Deployment = other.Machine.Deployment, Port = 0, Lock = AuthorityLock.UnlockedForTests(), CommandLineEndpoint = endpoint });
        }
        catch (Exception error)
        {
            reason = error.GetType().Name + ": " + error.Message;

            return null;
        }
    }
}

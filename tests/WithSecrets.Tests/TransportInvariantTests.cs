using System.Net;

namespace WithSecrets.Tests;

/// <summary>
/// Reaching the command line's endpoint (the pipe or the socket) is not authority. These checks run over whatever endpoint the test service has (the named pipe on Windows, the Unix socket elsewhere) and show that the
/// application's own checks still decide every request: the service must prove its identity before anything is sent; a request is bound to its body by its digest; and an approval is still needed before a secret is read.
/// </summary>
internal static class TransportInvariantTests
{
    public static async Task Run(Action<bool, string> check)
    {
        string parent = Path.Combine(Path.GetTempPath(), "ws-inv-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(parent);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(parent, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        try
        {
            using HostServiceTests.Rig rig = new(parent);
            check(rig.Service.Endpoint is not LoopbackEndpoint, "invariants: the command line's endpoint of the test service is not the loopback port");

            // What the program itself uses (not only what the tests start): the default endpoint of the command line is a channel of this user, never a port.
            LocalEndpoint real = LocalEndpoint.ForCommandLine();
            check(real is not LoopbackEndpoint && real.BaseUri.Host == "localhost" && real.BaseUri.IsDefaultPort && (OperatingSystem.IsWindows() ? real.Describe().Contains("pipe", StringComparison.Ordinal) : real.Describe().Contains("socket", StringComparison.Ordinal)), "invariants: the command line's default endpoint is the user's own channel (" + real.Describe() + "), with no port");

            string program = rig.Script("marker", "echo ran> \"%~dpn0.marker.txt\"", "echo ran > \"$0.marker.txt\"");

            // The right service, pinned: the run goes through.
            StringWriter okOut = new();
            StringWriter okErr = new();
            int ok = await LaunchClient.RunAsync(CliArgs.ParseRun(["--secrets", "TOKEN", "--reason", "invariants", "--", program], out _)!, rig.Work, rig.Service.Endpoint, null, okOut, okErr, rig.Machine.Trust);
            check(ok == 0 && HostServiceTests.Marker(rig).Length > 0, "invariants: over the endpoint, a run to the pinned service goes through (" + ok + ", " + okErr.ToString().Trim() + ")");
            File.Delete(HostServiceTests.Marker(rig));

            // A service that is not the pinned one (or nothing pinned yet) is not trusted, whatever endpoint it answers on: nothing is sent and nothing runs.
            string other = new('A', 64);
            StringWriter wrongErr = new();
            int wrong = await LaunchClient.RunAsync(CliArgs.ParseRun(["--secrets", "TOKEN", "--reason", "invariants", "--", program], out _)!, rig.Work, rig.Service.Endpoint, null, new StringWriter(), wrongErr, new ServiceTrust(other));
            check(wrong == LaunchClient.ServiceNotAuthenticated && wrongErr.ToString().Length > 0 && HostServiceTests.Marker(rig).Length == 0 && rig.Store.Reads <= 1, "invariants: a service whose identity is not the pinned one is refused before anything is sent (" + wrong + ")");
            int reads = rig.Store.Reads;

            StringWriter unpinnedErr = new();
            int unpinned = await LaunchClient.RunAsync(CliArgs.ParseRun(["--secrets", "TOKEN", "--reason", "invariants", "--", program], out _)!, rig.Work, rig.Service.Endpoint, null, new StringWriter(), unpinnedErr, new ServiceTrust(null));
            check(unpinned == LaunchClient.ServiceNotAuthenticated && HostServiceTests.Marker(rig).Length == 0 && rig.Store.Reads == reads, "invariants: with no identity pinned the service is not trusted either, and the secret store was not read (" + unpinned + ")");

            // The request is bound to its body: a different body under the digest of another is refused, over the same endpoint.
            LaunchRequest request = HostServiceTests.Req(rig, program);
            HostServiceTests.Raw tampered = await HostServiceTests.Post(rig, request, digest: HostServiceTests.Req(rig, program, args: ["other"]).Digest());
            check(tampered.Status == HttpStatusCode.BadRequest && HostServiceTests.Marker(rig).Length == 0 && rig.Store.Reads == reads, "invariants: a request whose body is not the one its digest names is refused before any approval or secret read");
        }
        finally
        {
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
}

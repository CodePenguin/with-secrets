using System.Net;
using System.Text.Json;

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

            // The admin command prints the link of the port the running service reports, not a port it was merely told: a wrong --port must not give a dead link next to "running".
            StringWriter adminOut = new();
            int adminCode = await AdminAppCommand.RunAsync(1, adminOut, new StringWriter(), rig.Machine.Trust, endpoint: rig.Service.Endpoint);
            check(adminCode == 0 && adminOut.ToString().Contains("http://localhost:" + rig.Service.Port + "/admin", StringComparison.Ordinal) && adminOut.ToString().Contains("running", StringComparison.Ordinal), "invariants: admin prints the admin web app's real port as the service reports it, whatever port was asked for (" + adminOut.ToString().Trim().Replace("\n", " | ") + ")");

            await CheckCompanion(rig, check);
            using (HostServiceTests.Rig pending = new(parent, trusted: false, startLocked: true))
            {
                using HttpClient pendingLocal = new(pending.Service.Endpoint.CreateHandler());
                Uri pendingEndpoint = new(pending.Service.Endpoint.BaseUri, "v1/companion");
                using JsonDocument pendingStatus = JsonDocument.Parse(await pendingLocal.GetStringAsync(pendingEndpoint));
                check(pendingStatus.RootElement.GetProperty("needsDeviceApproval").GetBoolean() &&
                    pendingStatus.RootElement.GetProperty("locked").GetBoolean(), "companion: a pending local device offers an unlock and approval path");
            }

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

    private static async Task CheckCompanion(HostServiceTests.Rig rig, Action<bool, string> check)
    {
        const string requestId = "run-companion-test";
        DateTimeOffset now = DateTimeOffset.UtcNow;
        ApprovalRequest request = new("test", "test", [], rig.Work, "private test reason", ["PRIVATE_TEST_NAME"]);
        ApprovalMachineView machine = new(rig.Machine.Trust.PinnedFingerprint!, "Private test name", "private-test-host");
        check(rig.Service.Approvals.TryRegister(ApprovalQueue.BuildReview(requestId, new string('a', 64), now, now.AddMinutes(1), machine, request), out _), "companion: the request is pending");
        using HttpClient local = new(rig.Service.Endpoint.CreateHandler());
        Uri endpoint = new(rig.Service.Endpoint.BaseUri, "v1/companion");
        using JsonDocument snapshot = JsonDocument.Parse(await local.GetStringAsync(endpoint));
        JsonElement document = snapshot.RootElement;
        check(document.EnumerateObject().Count() == 5 && document.GetProperty("adminPort").GetInt32() == rig.Service.Port &&
            document.GetProperty("requestIds").EnumerateArray().Select(item => item.GetString()).SequenceEqual([requestId]), "companion: local snapshot contains only service status and pending request IDs");
        using HttpClient browser = new();
        using HttpResponseMessage reply = await browser.GetAsync($"http://localhost:{rig.Service.Port}/v1/companion");
        check(reply.StatusCode == HttpStatusCode.NotFound, "companion: the browser port has no companion endpoint");

        StringWriter output = new();
        int result = await CompanionWatch.RunAsync(new ServiceTrust(new string('A', 64)), output, TextWriter.Null, rig.Service.Endpoint);
        check(result == LaunchClient.ServiceNotAuthenticated && output.ToString() == "", "companion: an unpinned service produces no snapshots");
        rig.Service.Approvals.Withdraw(requestId);
    }
}

using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;

namespace WithSecrets.Tests;

/// <summary>
/// The command line's endpoint on Windows is a named pipe that only the current user can open. The same application protocol runs over it (the whole host-service suite runs over a pipe on Windows); what is checked here is what is
/// particular to the pipe: that it is the endpoint the command line uses, who may open it, that nobody can take its name, and that a second service of the same user cannot share it. A second OS user cannot be made on a
/// test machine, so "another user cannot connect" is shown through the pipe's access list (the thing Windows checks) rather than by a connection attempt.
/// </summary>
internal static class LocalPipeTests
{
    public static async Task Run(Action<bool, string> check)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.WriteLine("  SKIP named pipe endpoint: Windows only (Linux and macOS use a Unix socket)");

            return;
        }

        await PipeChecks(check);
        await ElevationChecks(check);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static async Task PipeChecks(Action<bool, string> check)
    {
        string parent = Path.Combine(Path.GetTempPath(), "ws-pipe-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(parent);
        try
        {
            using HostServiceTests.Rig rig = new(parent);
            string name = ((NamedPipeEndpoint)rig.Service.Endpoint).Name;
            check(rig.Service.Endpoint.Describe().Contains("named pipe", StringComparison.Ordinal) && rig.Service.Endpoint.BaseUri.Host == "localhost", "pipe: the command line's endpoint of the service is a named pipe, addressed as http://localhost/ (no port)");
            check(NamedPipeEndpoint.DefaultName() == "with-secrets-" + WindowsIdentity.GetCurrent().User!.Value, "pipe: the default name carries the user's SID, so two users' services never share a name");

            using HttpResponseMessage status = await rig.Http.GetAsync(rig.Url("/v1/status"));
            check(status.IsSuccessStatusCode && (await status.Content.ReadAsStringAsync()).Contains("\"running\":true", StringComparison.Ordinal), "pipe: a request over the pipe is answered by the same application handler");

            // Who may open it: the access list of the live pipe.
            using NamedPipeClientStream probe = new(".", name, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly, TokenImpersonationLevel.Anonymous);
            await probe.ConnectAsync(5000);
            PipeSecurity security = probe.GetAccessControl();
            SecurityIdentifier me = WindowsIdentity.GetCurrent().User!;
            SecurityIdentifier network = new(WellKnownSidType.NetworkSid, null);
            List<PipeAccessRule> rules = [.. security.GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<PipeAccessRule>()];
            IEnumerable<PipeAccessRule> allows = rules.Where(rule => rule.AccessControlType == AccessControlType.Allow);
            bool onlyMe = allows.Any() && allows.All(rule => rule.IdentityReference.Equals(me));
            bool refusesNetwork = rules.Any(rule => rule.AccessControlType == AccessControlType.Deny && rule.IdentityReference.Equals(network));
            string who = string.Join(", ", rules.Select(rule => rule.AccessControlType + " " + rule.IdentityReference.Value));
            check(onlyMe && refusesNetwork, "pipe: the access list allows only the current user and refuses network (remote) clients (" + who + ")");
            check(security.GetOwner(typeof(SecurityIdentifier))?.Equals(WindowsIdentity.GetCurrent().Owner) == true, "pipe: the pipe is owned by the current token's owner (the user, or Administrators when elevated: what the client's current-user check expects)");

            // Nobody can take the name over: a pipe of this name, made first-instance, cannot be made while the service holds it; a second service of this user cannot share it either.
            bool squatted = true;
            try
            {
                using NamedPipeServerStream squatter = new(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                squatted = false;
            }

            check(!squatted, "pipe: while the service holds the name, nobody can create the pipe first or share it");

            Exception? second = null;
            try
            {
                using HostServiceTests.Rig other = new(parent);
                HostService.Start(new HostServiceOptions { State = other.State, Store = other.Store, Deployment = other.Machine.Deployment, Port = 0, Lock = AuthorityLock.UnlockedForTests(), CommandLineEndpoint = LocalEndpoint.NamedPipe(name) }).Dispose();
            }
            catch (Exception error)
            {
                second = error;
            }

            check(second is not null, "pipe: a second service on the same pipe name does not start");

            // A pipe of another name does not answer for this service: the client asks for its own pipe and gets nothing else.
            using HttpClient wrong = new(LocalEndpoint.NamedPipe("ws-test-nothing-" + Guid.NewGuid().ToString("N")).CreateHandler()) { Timeout = TimeSpan.FromSeconds(30) };
            System.Diagnostics.Stopwatch clock = System.Diagnostics.Stopwatch.StartNew();
            Exception? absent = null;
            try
            {
                await wrong.GetAsync("http://localhost/v1/status");
            }
            catch (Exception error)
            {
                absent = error;
            }

            // The command line itself: no service on the pipe is "the service is not running" (exit 6), and nothing was sent anywhere else.
            StringWriter err = new();
            int code = await LaunchClient.RunAsync(CliArgs.ParseRun(["--secrets", "TOKEN", "--reason", "no service", "--", "anything"], out _)!, rig.Work, LocalEndpoint.NamedPipe("ws-test-nothing-" + Guid.NewGuid().ToString("N")), null, new StringWriter(), err, rig.Machine.Trust);
            check(code == LaunchClient.ServiceNotRunning && err.ToString().Contains("not running", StringComparison.OrdinalIgnoreCase), "pipe: a run with no service on the pipe exits 6 and says the service is not running (" + code + ")");
            check(absent is HttpRequestException && clock.Elapsed < TimeSpan.FromSeconds(10), "pipe: with no service on the pipe, the client fails at once with a connection error (it neither waits for ever nor falls back to a port) (" + absent?.GetType().Name + ", " + clock.ElapsedMilliseconds + " ms)");
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

    /// <summary>
    /// The supported contract: the service and the command run as the same user at the same elevation level. .NET's own client check (CurrentUserOnly) compares the owner of the pipe with the owner of the client's token,
    /// and that owner is the user for a normal process and the Administrators group for an elevated one, so a pipe made at one level is refused at the other. The pipe's access list is not relaxed to change that; the refusal is
    /// explained instead. Here the pipe is made the way a normal process makes it (owned by the user) and the client is the elevated test process, which expects Administrators: the real .NET behavior, shown where the
    /// machine is elevated (the CI runners are). A normal developer machine cannot make that case (it cannot give a pipe to Administrators), so there it is stated as skipped.
    /// </summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static async Task ElevationChecks(Action<bool, string> check)
    {
        WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier user = identity.User!;
        SecurityIdentifier owner = identity.Owner!;
        check(owner.Equals(user) || owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid), "pipe: the owner of this process's token is the user (normal) or the Administrators group (elevated), the two cases the contract names (" + owner.Value + ")");
        if (owner.Equals(user))
        {
            Console.WriteLine("  SKIP pipe made at another elevation level: this process is not elevated; the refusal between levels is shown on an elevated machine (the CI runners)");

            return;
        }

        string name = "ws-test-" + Guid.NewGuid().ToString("N")[..12];
        PipeSecurity security = new();
        security.AddAccessRule(new PipeAccessRule(user, PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance, AccessControlType.Allow));
        security.SetOwner(user);
        using NamedPipeServerStream server = NamedPipeServerStreamAcl.Create(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, security);
        NamedPipeEndpoint endpoint = new(name);
        LocalChannelException? refused = null;
        try
        {
            using Stream stream = await endpoint.ConnectAsync(CancellationToken.None);
        }
        catch (LocalChannelException error)
        {
            refused = error;
        }

        check(refused is not null && refused.Message.Contains("elevation", StringComparison.Ordinal), "pipe: an elevated client does not talk to a pipe a normal process made, and says why (different elevation levels)");

        // Through the HTTP client the command line uses: the same explanation arrives, and it is not "not running".
        using HttpClient commandLine = new(endpoint.CreateHandler()) { Timeout = TimeSpan.FromSeconds(10) };
        Exception? seen = null;
        try
        {
            await commandLine.GetAsync("http://localhost/v1/status");
        }
        catch (Exception error)
        {
            seen = error;
        }

        check(LocalChannelException.Find(seen) is not null, "pipe: the explanation of the refusal reaches the command line through the HTTP client");
    }}

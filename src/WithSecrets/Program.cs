using System.Globalization;
using System.Text;

namespace WithSecrets;

internal static class Program
{
    // Everything lives in the user profile: %USERPROFILE%\.with-secrets\state.db (passkeys, settings, approvals, audit and the
    // secrets as Dotenvx ciphertext). The store key is never stored: it is wrapped under keys that only the passkeys (WebAuthn PRF) can produce.
    private const string StoreFolder = ".with-secrets";

    /// <summary>True when the failure (or one inside it) is a socket that could not be bound because the address is already in use.</summary>
    private static bool PortInUse(Exception failure)
    {
        for (Exception? item = failure; item is not null; item = item.InnerException)
        {
            if (item is System.Net.Sockets.SocketException { SocketErrorCode: System.Net.Sockets.SocketError.AddressAlreadyInUse or System.Net.Sockets.SocketError.AccessDenied })
            {
                return true;
            }
        }

        return false;
    }

    private static async Task<int> Main(string[] args)
    {
        try
        {
            return await Execute(args);
        }
        finally
        {
            AppLog.Close();
        }
    }

    private static async Task<int> Execute(string[] args)
    {
        // The release check on the published program (see SelfCheck): a throwaway service, software keys, no user state.
        if (args is ["--self-check"])
        {
            return await SelfCheck.RunAsync(Console.Out);
        }

        CliCommand? command = CliArgs.Parse(args, out string error);
        if (command is null)
        {
            TerminalPrompt.Final("with-secrets: " + error);

            return RunCommand.Usage;
        }

        if (command is CliCommand.Help help)
        {
            Console.Out.Write(help.Text);

            return 0;
        }

        // Diagnostics: warnings go to the log file always; --debug (or WITH_SECRETS_DEBUG=1) adds the Debug events, to the terminal too.
        AppLog.Configure(AppLog.DebugRequested(command.Debug));

        // The relay is an opaque router: no store, no state.db, no keys.
        if (command is CliCommand.Relay relay)
        {
            return await RunRelay(relay);
        }

        // A run is a client of the host service: it opens no store and no state.db, decrypts nothing and starts nothing itself.
        if (command is CliCommand.Run run)
        {
            return await RunThroughService(run, run.Args, approve: false);
        }

        // admin (no verbs): the authority's admin web app. Nothing is opened or changed here; the link and the service's public status are printed.
        if (command is CliCommand.AdminApp app)
        {
            return await AdminAppCommand.RunAsync(app.ServicePort, Console.Out, Console.Error, ServiceTrust.From(HostConfigFile.InFolder(StorePath())), OpenInBrowser(app));
        }

        // admin ADDRESS --authority-fingerprint HEX: point this machine at an authority and enroll it there (Pending). Opens no store and no state.db.
        if (command is CliCommand.AdminPair pair)
        {
            return await RunPairAsync(pair);
        }

        // approve takes the same road to the service: the service shows the page and the authority records the grant; nothing is launched.
        if (command is CliCommand.Approve approve)
        {
            return await RunThroughService(approve, approve.Args, approve: true);
        }

        string folder = StorePath();
        StateDatabase state = StateDatabase.InFolder(folder);
        SecretStore store = new(state);

        // Every command checks state.db first, and its signed manifest. A database that cannot be used (damaged, locked, of
        // another schema version, or failing verification) stops here: nothing is asked, nothing is listed and nothing runs.
        if (state.Gate(Console.Error) is { } failed)
        {
            return failed;
        }

        // --audit only reads: it may run anywhere and creates nothing.
        if (command is CliCommand.Audit audit)
        {
            return AuditCommand.Run(state, audit, Console.Out, Console.Error);
        }

        // --revoke, --enroll, --enrolled, --unenroll and --config (not --config --show) are for a person in their own terminal.
        if (CliArgs.NeedsTerminal(command) && !HumanCommands.RequireTerminal(CliArgs.NoTerminalMessage(command)))
        {
            return RunCommand.Denied;
        }

        GrantStore grants = new(state);

        switch (command)
        {
            case CliCommand.List:
                try
                {
                    Console.WriteLine(string.Join(Environment.NewLine, store.ListNames()));

                    return 0;
                }
                catch (Exception failure)
                {
                    TerminalPrompt.Final("with-secrets: cannot read the secret store: " + failure.Message);

                    return RunCommand.StoreError;
                }

            case CliCommand.Needs needs:
                return NeedsCommand.Run(store, needs.EnvFiles, Directory.GetCurrentDirectory(), Console.Out, Console.Error);

            case CliCommand.Set or CliCommand.Remove:
                return CommandWiring.Change(command, store, state, command.Port);

            case CliCommand.Revoke:
                return CommandWiring.Revoke(state, grants, command.Port);

            case CliCommand.Enroll or CliCommand.Enrolled or CliCommand.Unenroll:
                return CommandWiring.Passkeys(command, state, command.Port);

            case CliCommand.Config { Show: true }:
                return ConfigShow.Run(state, Console.Out, Console.Error);

            case CliCommand.Recover:
                return CommandWiring.Recover(state, command.Port);

            case CliCommand.RotateKey:
                return CommandWiring.RotateKey(state, store, command.Port);

            case CliCommand.Config:
                return CommandWiring.Config(state, command.Port);

            case CliCommand.Service:
                return RunService(command, state, store, grants, folder);
        }

        return RunCommand.Usage;
    }

    /// <summary>Opens the admin link in the person's browser, only from a real terminal (never in an agent's redirected shell). Null when it should not.</summary>
    private static Action<string>? OpenInBrowser(CliCommand command)
    {
        if (Console.IsInputRedirected || Console.IsOutputRedirected || !OperatingSystem.IsWindows())
        {
            return null;
        }

        return link =>
        {
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(link) { UseShellExecute = true })?.Dispose();
            }
            catch (Exception error) when (error is System.ComponentModel.Win32Exception or InvalidOperationException)
            {
                // The link is printed anyway.
            }
        };
    }

    private static async Task<int> RunThroughService(CliCommand command, RunArgs args, bool approve)
    {
        int? port = ServiceEndpoint.Resolve(command.ServicePort, Environment.GetEnvironmentVariable, out string? portError);
        if (port is null)
        {
            TerminalPrompt.Final("with-secrets: " + portError);

            return RunCommand.Usage;
        }

        // The service must prove it is this machine's host service (the identity pinned in host.json) before anything is sent to it.
        ServiceTrust trust = ServiceTrust.From(HostConfigFile.InFolder(StorePath()));

        using Stream stdout = Console.OpenStandardOutput();
        using Stream stderr = Console.OpenStandardError();
        using StreamWriter outWriter = new(stdout, new UTF8Encoding(false)) { AutoFlush = true };
        using StreamWriter errWriter = new(stderr, new UTF8Encoding(false)) { AutoFlush = true };

        return await LaunchClient.RunAsync(args, Directory.GetCurrentDirectory(), port.Value, command.Port, outWriter, errWriter, trust, approve: approve);
    }

    /// <summary>The relay in the foreground, until Ctrl+C. It keeps registrations in memory only and logs nothing about payloads.</summary>
    private static async Task<int> RunRelay(CliCommand.Relay command)
    {
        System.Security.Cryptography.X509Certificates.X509Certificate2? certificate = null;
        if (command.CertificateFile is { } file)
        {
            try
            {
                certificate = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadPkcs12FromFile(file, command.CertificatePasswordVariable is { } name ? Environment.GetEnvironmentVariable(name) : null);
            }
            catch (Exception failure) when (failure is System.Security.Cryptography.CryptographicException or IOException or UnauthorizedAccessException)
            {
                TerminalPrompt.Final("with-secrets: the relay certificate cannot be read (" + failure.GetType().Name + ").");

                return RunCommand.StoreError;
            }
        }

        RelayServer server;
        try
        {
            server = await RelayServer.StartAsync(new RelayOptions { Port = command.ListenPort, Bind = System.Net.IPAddress.Parse(command.Bind), Certificate = certificate });
        }
        catch (Exception failure)
        {
            TerminalPrompt.Final($"with-secrets: the relay cannot listen on {command.Bind}:{command.ListenPort} ({failure.GetType().Name}).");

            return RunCommand.StoreError;
        }

        await using (server)
        {
            using ManualResetEventSlim stop = new(false);
            ConsoleCancelEventHandler handler = (_, e) =>
            {
                e.Cancel = true;
                stop.Set();
            };
            Console.CancelKeyPress += handler;
            TerminalPrompt.Line($"with-secrets relay: listening on {server.Url} ({(certificate is null ? "no TLS: loopback only" : "TLS")}). It routes opaque frames by registration id and keeps nothing. Press Ctrl+C to stop.");
            stop.Wait();
            Console.CancelKeyPress -= handler;
        }

        return 0;
    }

    /// <summary>The host service in the foreground, until Ctrl+C. Windows service installation and start at logon come later.</summary>
    private static string StorePath() => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), StoreFolder);

    private static async Task<int> RunPairAsync(CliCommand.AdminPair command)
    {
        if (!OperatingSystem.IsWindows())
        {
            TerminalPrompt.Final("with-secrets: the machine identity needs Windows CNG for now; this machine cannot be enrolled with an authority from this system.");

            return RunCommand.StoreError;
        }

        try
        {
            using LocalDeployment deployment = LocalDeployment.OpenProduction(StorePath());

            return await AuthorityPairing.RunAsync(command, deployment, Console.Out, Console.Error);
        }
        catch (Exception failure) when (failure is AuthorityDatabaseException or System.Security.Cryptography.CryptographicException)
        {
            TerminalPrompt.Final("with-secrets: the machine identity cannot be used: " + failure.Message);

            return RunCommand.StoreError;
        }
    }

    private static int RunService(CliCommand command, StateDatabase state, SecretStore store, GrantStore grants, string folder)
    {
        int? port = ServiceEndpoint.Resolve(command.ServicePort, Environment.GetEnvironmentVariable, out string? portError);
        if (port is null)
        {
            TerminalPrompt.Final("with-secrets: " + portError);

            return RunCommand.Usage;
        }

        if (!OperatingSystem.IsWindows())
        {
            TerminalPrompt.Final("with-secrets: the machine identity needs Windows CNG for now; the host service cannot start on this system.");

            return RunCommand.StoreError;
        }

        // The machine endpoint (an authority serving another machine's host service, such as WSL's): nothing but the encrypted machine protocol, never the admin app, the API or a page.
        MachineEndpointOptions? machineEndpoint = null;
        if (command is CliCommand.Service { MachinePort: { } machinePort } machineCommand)
        {
            System.Security.Cryptography.X509Certificates.X509Certificate2? certificate = null;
            if (machineCommand.MachineCertificate is { } certificateFile)
            {
                try
                {
                    certificate = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadPkcs12FromFile(certificateFile, machineCommand.MachineCertificatePasswordVariable is { } name ? Environment.GetEnvironmentVariable(name) : null);
                }
                catch (Exception failure) when (failure is System.Security.Cryptography.CryptographicException or IOException or UnauthorizedAccessException)
                {
                    TerminalPrompt.Final("with-secrets: the machine endpoint certificate cannot be read (" + failure.GetType().Name + ").");

                    return RunCommand.StoreError;
                }
            }

            machineEndpoint = new MachineEndpointOptions { Bind = System.Net.IPAddress.Parse(machineCommand.MachineBind), Port = machinePort, Certificate = certificate };
            if (machineEndpoint.Problem() is { } endpointProblem)
            {
                TerminalPrompt.Final("with-secrets: " + endpointProblem);

                return RunCommand.Usage;
            }
        }

        LocalDeployment deployment;
        EnrollmentResult enrolled;
        try
        {
            // The machine identity key is made on the first start (non-exportable, kept by Windows) and never leaves it.
            deployment = LocalDeployment.OpenProduction(folder);

            // host.json may select a remote authority (public data only: the relay, the registration id and the authority key fingerprint to trust).
            if (deployment.HostConfig.Load().Config?.Remote is { } remoteConfig)
            {
                deployment.UseRemote(new RemoteAuthority(remoteConfig, deployment.MachineKey, deployment.HostConfig));
                TerminalPrompt.Line("with-secrets service: remote authority mode: the authority is reached through the relay " + ApprovalSummary.Clean(remoteConfig.RelayUrl) + " (end-to-end encrypted; the authority key must have fingerprint " + KeyIdentity.Display(remoteConfig.AuthorityFingerprint) + ").");
            }

            try
            {
                enrolled = deployment.EnrollAsync().GetAwaiter().GetResult();
            }
            catch (Exception failure) when (deployment.Remote is not null && failure is RemoteTransportException or RemoteRefusedException)
            {
                enrolled = new EnrollmentResult(false, MachineStatus.Pending, deployment.Fingerprint, "the remote authority could not be reached; the service keeps trying, but runs fail until it can");
            }
        }
        catch (Exception failure) when (failure is AuthorityDatabaseException or System.Security.Cryptography.CryptographicException)
        {
            TerminalPrompt.Final("with-secrets: the machine identity or the authority cannot be used: " + failure.Message);

            return RunCommand.StoreError;
        }

        if (deployment.Remote is not null && machineEndpoint is not null)
        {
            TerminalPrompt.Final("with-secrets: this machine is paired with another machine's authority (see host.json), so it is not an authority and serves no machine endpoint.");
            deployment.Dispose();

            return RunCommand.Usage;
        }

        HostService service;
        try
        {
            service = HostService.Start(new HostServiceOptions { State = state, Store = store, Grants = grants, Port = port.Value, Deployment = deployment, MachineEndpoint = machineEndpoint });
        }
        catch (Exception failure)
        {
            TerminalPrompt.Final(PortInUse(failure)
                ? $"with-secrets: the host service cannot listen on port {port}: the port is in use. Is it already running? Use --port N for another port."
                : $"with-secrets: the host service could not start ({failure.GetType().Name}). The port is not the problem as far as is known; run again with --debug and read the log.");

            return RunCommand.StoreError;
        }

        using (service)
        {
            using ManualResetEventSlim stop = new(false);
            ConsoleCancelEventHandler handler = (_, e) =>
            {
                e.Cancel = true;
                stop.Set();
            };
            Console.CancelKeyPress += handler;
            foreach (string line in ServiceStartup.Lines(deployment.HostName, deployment.Fingerprint, enrolled))
            {
                TerminalPrompt.Line(line);
            }

            foreach (string line in ServiceStartup.LockLines(service.Lock.IsLocked, deployment.Store.GetUnlockPolicy(), service.StartupUnlockNote, service.Admin.PageUrl))
            {
                TerminalPrompt.Line(line);
            }

            if (service.MachinePort is { } machinePortNow)
            {
                TerminalPrompt.Line($"with-secrets service: machine endpoint on {machineEndpoint!.Bind}:{machinePortNow} (the encrypted machine protocol only: no administration, no pages). A firewall rule for that port is the administrator's to make.");
            }

            TerminalPrompt.Line($"with-secrets service: listening on 127.0.0.1 and [::1], port {service.Port} (this machine only). Press Ctrl+C to stop.");
            stop.Wait();
            Console.CancelKeyPress -= handler;
        }

        deployment.Dispose();

        return 0;
    }
}

/// <summary>
/// Commands for a person. Those that check the terminal (<see cref="CliArgs.NeedsTerminal" />) refuse when input or output is
/// redirected, as in an agent's shell. --set and --remove need a passkey on a web page instead.
/// </summary>
internal static class HumanCommands
{
    public static bool RequireTerminal(string message)
    {
        if (Console.IsInputRedirected || Console.IsOutputRedirected || Console.IsErrorRedirected)
        {
            TerminalPrompt.Final(message);

            return false;
        }

        return true;
    }
}

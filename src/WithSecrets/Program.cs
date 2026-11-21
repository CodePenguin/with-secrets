using System.Globalization;
using System.Text;

namespace WithSecrets;

internal static class Program
{
    // Everything lives in the user profile: %USERPROFILE%\.with-secrets\state.db (passkeys, settings, approvals and the
    // secrets as Dotenvx ciphertext). The store key is never stored: it is wrapped under keys that only the passkeys (WebAuthn PRF) can produce.
    private const string StoreFolder = ".with-secrets";

    /// <summary>True when the failure (or one inside it) is a socket that could not be bound because the address is already in use.</summary>
    /// <summary>The reason the command line's endpoint could not be made (a plain I/O error from the endpoint: a path and a rule), found in the chain of the start failure. Null when it is something else.</summary>
    private static string? EndpointProblem(Exception failure)
    {
        for (Exception? current = failure; current is not null; current = current.InnerException)
        {
            if (current.GetType() == typeof(IOException))
            {
                return current.Message;
            }
        }

        return null;
    }

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
        catch (KeyFileException refused)
        {
            // A key file or key folder that is not protected as required (or not this user's): one line with the path and the fix, no stack trace.
            TerminalPrompt.Final("with-secrets: " + refused.Message);

            return RunCommand.StoreError;
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

        // TEST ONLY isolation (WITH_SECRETS_TEST_STORE with WITH_SECRETS_TEST_KEY_PREFIX): refused when incomplete, malformed or aimed at the default store.
        if (TestIsolation.Problem is { } isolationProblem)
        {
            TerminalPrompt.Final("with-secrets: " + isolationProblem);

            return RunCommand.Usage;
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

        // A run is a client of the host service: it opens no store and no state.db, decrypts nothing and starts nothing itself.
        if (command is CliCommand.Run run)
        {
            return await RunThroughService(run, run.Args, approve: false);
        }

        // admin (no verbs): the authority's admin web app. Nothing is opened or changed here; the link and the service's public status are printed.
        if (command is CliCommand.AdminApp app)
        {
            // With nothing enrolled, admin is the first-time setup: the first passkey, then the link.
            StateDatabase first = StateDatabase.InFolder(StorePath());
            if (first.TryManifest(out Manifest? enrolled, out _) && enrolled is null)
            {
                if (!HumanCommands.RequireTerminal(CliArgs.NoTerminalMessage(command)))
                {
                    return RunCommand.Denied;
                }

                int setup = CommandWiring.Setup(first, null);
                if (setup != 0)
                {
                    return setup;
                }
            }

            return await AdminAppCommand.RunAsync(app.AdminPort, Console.Out, Console.Error, ServiceTrust.From(HostConfigFile.InFolder(StorePath())), OpenInBrowser(app));
        }

        // pair: pairing this machine with an authority by a one-time invitation (hidden prompt, or unattended from a secret file or WITH_SECRETS_PAIRING). Opens no store and no state.db.
        if (command is CliCommand.Pair)
        {
            return await RunPairAsync();
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

        // --recover is for a person in their own terminal.
        if (CliArgs.NeedsTerminal(command) && !HumanCommands.RequireTerminal(CliArgs.NoTerminalMessage(command)))
        {
            return RunCommand.Denied;
        }

        switch (command)
        {
            case CliCommand.Needs needs:
                return NeedsCommand.Run(store, needs.EnvFiles, Directory.GetCurrentDirectory(), Console.Out, Console.Error);

            case CliCommand.Recover:
                return CommandWiring.Recover(state, command.Port);

            case CliCommand.Service:
                return RunService(command, state, store, folder);
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
        // The service must prove it is this machine's host service (the identity pinned in host.json) before anything is sent to it.
        ServiceTrust trust = ServiceTrust.From(HostConfigFile.InFolder(StorePath()));

        using Stream stdout = Console.OpenStandardOutput();
        using Stream stderr = Console.OpenStandardError();
        using StreamWriter outWriter = new(stdout, new UTF8Encoding(false)) { AutoFlush = true };
        using StreamWriter errWriter = new(stderr, new UTF8Encoding(false)) { AutoFlush = true };

        return await LaunchClient.RunAsync(args, Directory.GetCurrentDirectory(), LocalEndpoint.ForCommandLine(), command.Port, outWriter, errWriter, trust, approve: approve);
    }

    /// <summary>The host service in the foreground, until Ctrl+C. Windows service installation and start at logon come later.</summary>
    private static string StorePath() => TestIsolation.Current?.StoreFolder ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), StoreFolder);

    private static async Task<int> RunPairAsync()
    {
        // The pairing command loads the machine key too: non-dumpable on Linux first (skipped on Windows).
        LinuxHardening.HardenProcess();

        return await AuthorityPairing.RunAsync(PairingEnvironment.ForThisProcess(OpenPairingMachine), Console.Out, Console.Error);
    }

    /// <summary>This machine's identity for pairing: the persistent key of the platform key store (Windows CNG, non-exportable; elsewhere an owner-only key file, weaker), made on first use, its identity certificate beside host.json, and the host name.</summary>
    private static PairingMachine OpenPairingMachine()
    {
        string folder = StorePath();
        ISigningKey key = MachineKeyStore.OpenOrCreate(folder, KeyNames.Machine, out _);

        return new PairingMachine(key, MachineIdentityFile.LoadOrCreate(folder, key, TimeProvider.System), Environment.MachineName, HostConfigFile.InFolder(folder), (name, detail) =>
        {
            AuthorityStore store = AuthorityStore.InFolder(folder);
            store.RecordPairingEvent(name, null, detail);
        });
    }

    private static int RunService(CliCommand command, StateDatabase state, SecretStore store, string folder)
    {
        int? port = AdminPort.Resolve(command.AdminPort, Environment.GetEnvironmentVariable, out string? portError);
        if (port is null)
        {
            TerminalPrompt.Final("with-secrets: " + portError);

            return RunCommand.Usage;
        }

        // The machine listener (an authority serving another machine's host service, such as WSL's): nothing but the machine API over TLS 1.3 mutual authentication and HTTP/2, never the admin app, the API or a page.
        MachineListenerOptions? machineEndpoint = null;
        if (command is CliCommand.Service { MachinePort: { } machinePort } machineCommand)
        {
            if (PlatformTls.MachineTransportUnsupported is { } unsupported)
            {
                TerminalPrompt.Final("with-secrets: " + unsupported);

                return RunCommand.Usage;
            }

            machineEndpoint = new MachineListenerOptions { Bind = System.Net.IPAddress.Parse(machineCommand.MachineBind), Port = machinePort };
            if (machineEndpoint.Problem() is { } endpointProblem)
            {
                TerminalPrompt.Final("with-secrets: " + endpointProblem);

                return RunCommand.Usage;
            }
        }

        // Linux: no core dump and no memory reading by another process of this user (non-dumpable) before any key is loaded. Skipped on Windows. A failure is one line in the log, never fatal.
        LinuxHardening.HardenProcess();

        LocalDeployment deployment;
        EnrollmentResult enrolled;
        try
        {
            // The machine identity key is made on the first start (Windows: a non-exportable CNG key that never leaves it; elsewhere an owner-only key file, which anything running as this user can copy).
            deployment = LocalDeployment.OpenProduction(folder);

            // host.json may select a remote authority (public data only: its endpoint address and its identity certificate).
            if (deployment.HostConfig.Load().Config?.Remote is { } remoteConfig)
            {
                if (PlatformTls.MachineTransportUnsupported is { } noTransport)
                {
                    TerminalPrompt.Final("with-secrets: this machine is set to use a remote authority, but " + noTransport);

                    return RunCommand.Usage;
                }

                deployment.UseRemote(new RemoteAuthority(remoteConfig, deployment.Tls, deployment.HostConfig));
                TerminalPrompt.Line("with-secrets service: remote authority mode: the authority at " + ApprovalSummary.Clean(remoteConfig.Endpoint) + " (TLS 1.3 mutual authentication; its identity must be " + KeyIdentity.Display(remoteConfig.AuthorityIdentityFingerprint) + ").");

                // A machine becomes known to a remote authority by pairing, not by this start.
                enrolled = new EnrollmentResult(true, MachineStatus.Pending, deployment.Fingerprint, "remote authority: the authority decides this machine's status");
            }
            else
            {
                enrolled = deployment.EnrollAsync().GetAwaiter().GetResult();
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
            service = HostService.Start(new HostServiceOptions { State = state, Store = store, Port = port.Value, CommandLineEndpoint = LocalEndpoint.ForCommandLine(), Deployment = deployment, MachineEndpoint = machineEndpoint, MachineListenerStarted = port => TerminalPrompt.Line($"with-secrets service: machine listener now on {machineEndpoint!.Bind}:{port} (the authority signing key was made by the first approval; no restart was needed)."), });
        }
        catch (Exception failure)
        {
            // The admin web app's port in use; or the command line's endpoint (the pipe or the socket) is unusable or taken: its reason is a path and a rule, nothing else, and is shown as it is.
            TerminalPrompt.Final(PortInUse(failure)
                ? $"with-secrets: the host service cannot listen on port {port} (the admin web app's port): the port is in use. Is it already running? Use --port N for another port."
                : EndpointProblem(failure) is { } endpointProblem
                    ? "with-secrets: the host service could not make the channel the command line uses: " + endpointProblem
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
                TerminalPrompt.Line($"with-secrets service: machine listener on {machineEndpoint!.Bind}:{machinePortNow} (HTTPS: TLS 1.3 mutual authentication and HTTP/2; the machine API only: no administration, no pages). A firewall rule for that port is the administrator's to make.");
            }

            if (machineEndpoint is not null && service.MachinePort is null)
            {
                TerminalPrompt.Line("with-secrets service: the machine listener starts as soon as the first approval makes the authority signing key (no restart needed); until then no machine can connect.");
            }

            TerminalPrompt.Line($"with-secrets service: the admin web app is on 127.0.0.1 and [::1], port {service.Port} (this machine only). The command line reaches this service over {service.Endpoint.Describe()}, which only this user can open. Press Ctrl+C to stop.");
            stop.Wait();
            Console.CancelKeyPress -= handler;
        }

        deployment.Dispose();

        return 0;
    }
}

/// <summary>
/// Commands for a person. Those that check the terminal (<see cref="CliArgs.NeedsTerminal" />) refuse when input or output is
/// redirected, as in an agent's shell. Everything else a person does is in the admin web app.
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

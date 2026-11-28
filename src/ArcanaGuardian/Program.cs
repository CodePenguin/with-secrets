using System.Globalization;
using System.IO.Pipes;
using System.Text;

using ArcanaGuardian.Bitwarden;
using ArcanaGuardian.LastPass;
using ArcanaGuardian.OnePassword;
using ArcanaGuardian.Vault;

namespace ArcanaGuardian;

internal static partial class Program
{
    // Everything lives in the user profile: %USERPROFILE%\.ArcanaGuardian\arcana-guardian.db (passkeys, settings, approvals and the
    // secrets as JWE ciphertext). The store key is wrapped under keys that only the passkeys (WebAuthn PRF) can produce.
    private const string StoreFolder = ".ArcanaGuardian";

    /// <summary>The reason the command line's endpoint could not be made (a plain I/O error from the endpoint: a path and a rule), found in the chain of the start failure. Null when it is something else.</summary>
    private static string? EndpointProblem(Exception failure)
    {
        for (Exception? current = failure; current is not null; current = current.InnerException)
        {
            if (current is LocalChannelException)
            {
                return current.Message;
            }
        }

        return null;
    }

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
        catch (KeyFileException refused)
        {
            // A key file or key folder that is not protected as required (or not this user's): one line with the path and the fix, no stack trace.
            TerminalPrompt.Final("using-secrets: " + refused.Message);

            return RunCommand.StoreError;
        }
        finally
        {
            AppLog.Close();
        }
    }

    private static async Task<int> Execute(string[] args)
    {
        if (args is [DotenvxRun.CaptureArgument, var pipe, .. var names])
        {
            return await DotenvxRun.CaptureAsync(pipe, names);
        }

        // The release check on the published program (see SelfCheck): a throwaway service, software keys, no user state.
        if (args is ["--self-check"])
        {
            return await SelfCheck.RunAsync(Console.Out);
        }

        // TEST ONLY isolation (ARCANA_GUARDIAN_TEST_STORE with ARCANA_GUARDIAN_TEST_KEY_PREFIX): refused when incomplete, malformed or aimed at the default store.
        if (TestIsolation.Problem is { } isolationProblem)
        {
            TerminalPrompt.Final("using-secrets: " + isolationProblem);

            return RunCommand.Usage;
        }

        if (args is ["--lastpass-refresh-helper", string channel])
        {
            return await RunLastPassRefreshHelper(channel);
        }

        if (args is ["--watch-companion"])
        {
            using StreamWriter snapshots = new(Console.OpenStandardOutput(), new UTF8Encoding(false));
            return await WatchDesktop(snapshots);
        }

        bool desktopSetup = args is ["--desktop-quick-start-worker", ..];
        bool quickStart = desktopSetup || args is ["--quick-start-worker", ..];
        if (quickStart && (!Console.IsInputRedirected || !Console.IsOutputRedirected || !Console.IsErrorRedirected))
        {
            return RunCommand.Denied;
        }
        CliCommand? command = CliArgs.Parse(quickStart ? ["service", .. args[1..]] : args, out string error);
        if (command is null)
        {
            TerminalPrompt.Final("using-secrets: " + error);

            return RunCommand.Usage;
        }

        if (command is CliCommand.Help help)
        {
            Console.Out.Write(help.Text);

            return 0;
        }

        // Diagnostics: warnings go to the log file always; --debug (or ARCANA_GUARDIAN_DEBUG=1) adds the Debug events, to the terminal too.
        AppLog.Configure(AppLog.DebugRequested(command.Debug));

        if (command is CliCommand.Certificate certificate)
        {
            try
            {
                LinuxHardening.HardenProcess();
                new BrowserCertificates(StorePath()).Run(certificate.Action,
                    Environment.UserInteractive && !Console.IsInputRedirected && !Console.IsOutputRedirected,
                    certificate.Chromium, certificate.Firefox, Console.Out);
                return 0;
            }
            catch (Exception failure) when (BrowserCertificates.IsLifecycleError(failure))
            {
                TerminalPrompt.Final("using-secrets: " + BrowserCertificates.Detail(failure));
                return RunCommand.StoreError;
            }
        }

        // The host service owns the Arcana Guardian store and the final application launch.
        if (command is CliCommand.Run run)
        {
            return await RunThroughService(run, run.Args, approve: false);
        }

        // admin (no verbs): the authority's admin web app. Nothing is opened or changed here; the link and the service's public status are printed.
        if (command is CliCommand.AdminApp app)
        {
            // A host with a remote authority has no local enrollment: the administration lives on the authority.
            var hostConfig = HostConfigFile.InFolder(StorePath());
            if (hostConfig.Load().Config?.Remote is not null)
            {
                return await AdminAppCommand.RunAsync(app.AdminPort, Console.Out, Console.Error, ServiceTrust.From(hostConfig));
            }

            // With nothing enrolled, admin is the first-time setup: the first passkey, then the link.
            StateDatabase first = StateDatabase.InFolder(StorePath());
            if (!first.TryManifest(out Manifest? enrolled, out string? storeError))
            {
                Console.Error.WriteLine("using-secrets: " + storeError);
                return RunCommand.StoreError;
            }

            if (enrolled is null)
            {
                if (!HumanCommands.RequireTerminal(CliArgs.NoTerminalMessage(command)))
                {
                    return RunCommand.Denied;
                }

                return await StartQuickStart(app);
            }

            return await AdminAppCommand.RunAsync(app.AdminPort, Console.Out, Console.Error, ServiceTrust.From(HostConfigFile.InFolder(StorePath())), OpenInBrowser(app));
        }

        // pair: pairing this machine with an authority by a one-time invitation (hidden prompt, or unattended from a secret file or ARCANA_GUARDIAN_PAIRING). Check the local database before pairing.
        if (command is CliCommand.Pair)
        {
            if (StateDatabase.InFolder(StorePath()).Gate(Console.Error) is { } refusal)
            {
                return refusal;
            }
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

        // Every command checks arcana-guardian.db first, and its signed manifest. A database that cannot be used (damaged, locked, of
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
                try
                {
                    return CommandWiring.Recover(state, command.Port);
                }
                catch (BrowserCertificateException failure)
                {
                    TerminalPrompt.Final("using-secrets: " + failure.Message);
                    return RunCommand.StoreError;
                }

            case CliCommand.Service:
                return RunService(command, state, store, folder, quickStart, desktopSetup);
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

        LocalEndpoint endpoint;
        try
        {
            endpoint = LocalEndpoint.ForCommandLine();
        }
        catch (IOException problem)
        {
            // The channel cannot be named safely here (for example a path too long for a socket): nothing is sent anywhere else.
            await errWriter.WriteLineAsync("using-secrets: the channel to the host service cannot be used: " + problem.Message);

            return RunCommand.Usage;
        }

        return await LaunchClient.RunAsync(args, Directory.GetCurrentDirectory(), endpoint, command.Port, outWriter, errWriter, trust, approve: approve);
    }

    /// <summary>The host service in the foreground, until Ctrl+C. Windows service installation and start at logon come later.</summary>
    private static async Task<int> RunLastPassRefreshHelper(string channel)
    {
        if (channel.Length != 32 || !channel.All(Uri.IsHexDigit)
            || Console.IsInputRedirected || Console.IsOutputRedirected)
        {
            Console.Error.WriteLine("Open the Arcana Guardian LastPass refresh from the browser in an interactive terminal.");
            return RunCommand.Usage;
        }

        HostConfigLoad config = HostConfigFile.InFolder(StorePath()).Load();
        if (config.Problem is not null || config.Config?.Authority is not { } authority)
        {
            Console.Error.WriteLine("This Arcana Guardian installation has no usable authority pin for the LastPass refresh.");
            return RunCommand.StoreError;
        }

        using CancellationTokenSource cancel = new();
        void OnCancel(object? sender, ConsoleCancelEventArgs args)
        {
            args.Cancel = true;
            cancel.Cancel();
        }
        Console.CancelKeyPress += OnCancel;
        try
        {
            using NamedPipeClientStream pipe = new(".", HelperPipe.GetName(LastPassRefreshLauncher.PipePrefix + channel), PipeDirection.InOut,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            await pipe.ConnectAsync(5000, cancel.Token);
            return await LastPassRefreshTerminal.RunAsync(pipe, authority.Fingerprint, cancel.Token);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or TimeoutException or OperationCanceledException)
        {
            Console.Error.WriteLine("The Arcana Guardian LastPass helper could not connect to the refresh request.");
            return 1;
        }
        finally { Console.CancelKeyPress -= OnCancel; }
    }

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

    private static int RunService(CliCommand command, StateDatabase state, SecretStore store, string folder, bool quickStart = false, bool desktopSetup = false)
    {
        if (quickStart && (command is CliCommand.Service { MachinePort: not null }
            || !state.TryManifest(out Manifest? manifest, out _) || manifest is not null
            || HostConfigFile.InFolder(folder).Load() is not { Config: null, Problem: null }))
        {
            TerminalPrompt.Final("using-secrets: Quick Start is only for an unconfigured local installation.");
            return RunCommand.Denied;
        }

        int? port = AdminPort.Resolve(command.AdminPort, Environment.GetEnvironmentVariable, out string? portError);
        if (port is null)
        {
            TerminalPrompt.Final("using-secrets: " + portError);

            return RunCommand.Usage;
        }

        // The machine listener (an authority serving another machine's host service, such as WSL's): nothing but the machine API over TLS 1.3 mutual authentication and HTTP/2, never the admin app, the API or a page.
        MachineListenerOptions? machineEndpoint = null;
        if (command is CliCommand.Service { MachinePort: { } machinePort } machineCommand)
        {
            if (PlatformTls.MachineTransportUnsupported is { } unsupported)
            {
                TerminalPrompt.Final("using-secrets: " + unsupported);

                return RunCommand.Usage;
            }

            machineEndpoint = new MachineListenerOptions { Bind = System.Net.IPAddress.Parse(machineCommand.MachineBind), Port = machinePort };
            if (machineEndpoint.Problem() is { } endpointProblem)
            {
                TerminalPrompt.Final("using-secrets: " + endpointProblem);

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
            deployment = LocalDeployment.OpenProduction(folder, state.Database);

            // host.json may select a remote authority (public data only: its endpoint address and its identity certificate).
            if (deployment.HostConfig.Load().Config?.Remote is { } remoteConfig)
            {
                if (PlatformTls.MachineTransportUnsupported is { } noTransport)
                {
                    TerminalPrompt.Final("using-secrets: this machine is set to use a remote authority, but " + noTransport);

                    return RunCommand.Usage;
                }

                deployment.UseRemote(new RemoteAuthority(remoteConfig, deployment.Tls, deployment.HostConfig));
                TerminalPrompt.Line("using-secrets service: remote authority mode: the authority at " + ApprovalSummary.Clean(remoteConfig.Endpoint) + " (TLS 1.3 mutual authentication; its identity must be " + KeyIdentity.Display(remoteConfig.AuthorityIdentityFingerprint) + ").");

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
            TerminalPrompt.Final("using-secrets: the machine identity or the authority cannot be used: " + failure.Message);

            return RunCommand.StoreError;
        }

        if (deployment.Remote is not null && machineEndpoint is not null)
        {
            TerminalPrompt.Final("using-secrets: this machine is paired with another machine's authority (see host.json), so it is not an authority and serves no machine endpoint.");
            deployment.Dispose();

            return RunCommand.Usage;
        }

        HostService service;
        try
        {
            service = HostService.Start(new HostServiceOptions
            {
                State = state,
                Store = store,
                Port = port.Value,
                CommandLineEndpoint = LocalEndpoint.ForCommandLine(),
                Deployment = deployment,
                ConfigureProviders = (registry, authorityLock, keys) =>
                {
                    LastPassProvider.RegisterInteractive(registry);
                    BitwardenProvider.Register(registry, authorityLock, keys);
                    OnePasswordProvider.Register(registry, authorityLock, keys,
                        Environment.GetEnvironmentVariable(OnePasswordProvider.ExecutableVariable) ?? "");
                    VaultProvider.Register(registry, authorityLock, keys,
                        Environment.GetEnvironmentVariable(VaultProvider.AddressVariable) ?? "",
                        Environment.GetEnvironmentVariable(VaultProvider.MountVariable) ?? "secret",
                        Environment.GetEnvironmentVariable(VaultProvider.NamespaceVariable));
                },
                LaunchInteractiveRefresh = LastPassRefreshLauncher.StartAsync,
                SealOnePasswordConfiguration = token => state.TryManifest(out Manifest? manifest, out _) && manifest?.Review is { } reviewKey
                    ? OnePasswordProvider.SealConfiguration(token, reviewKey.PublicKey) : null,
                SealVaultConfiguration = token => state.TryManifest(out Manifest? manifest, out _) && manifest?.Review is { } reviewKey
                    ? VaultProvider.SealConfiguration(token, reviewKey.PublicKey) : null,
                SealBitwardenConfiguration = (token, serverUrl) => state.TryManifest(out Manifest? manifest, out _) && manifest?.Review is { } reviewKey
                    ? BitwardenProvider.SealConfiguration(token, serverUrl, reviewKey.PublicKey) : null,
                MachineEndpoint = machineEndpoint,
                MachineListenerStarted = port => TerminalPrompt.Line($"using-secrets service: machine listener now on {machineEndpoint!.Bind}:{port} (the authority signing key was made by the first approval; no restart was needed)."),
            });
        }
        catch (Exception failure)
        {
            // The admin web app's port in use; or the command line's endpoint (the pipe or the socket) is unusable or taken: its reason is a path and a rule, nothing else, and is shown as it is.
            deployment.Dispose();
            TerminalPrompt.Final(failure is BrowserCertificateException
                ? "using-secrets: " + failure.Message
                : PortInUse(failure)
                ? $"using-secrets: the host service cannot listen on port {port} (the admin web app's port): the port is in use. Is it already running? Use --port N for another port."
                : EndpointProblem(failure) is { } endpointProblem
                    ? "using-secrets: the host service could not make the channel the command line uses: " + endpointProblem
                    : $"using-secrets: the host service could not start ({failure.GetType().Name}). The port is not the problem as far as is known; run again with --debug and read the log.");

            return RunCommand.StoreError;
        }

        using (service)
        {
            if (quickStart)
            {
                int setup = CommandWiring.Setup(state, null, service, Console.Out.WriteLine, ReadQuickStartCode,
                    desktopSetup ? code => Console.Out.WriteLine("quick-start:desktop-code:" + code) : null,
                    desktopSetup ? () => Task.Run(Console.ReadLine) : null);
                Console.Out.WriteLine(QuickStartResult + setup.ToString(CultureInfo.InvariantCulture));
                if (setup != 0) return setup;
            }

            using ManualResetEventSlim stop = new(false);
            ConsoleCancelEventHandler handler = (_, e) =>
            {
                e.Cancel = true;
                stop.Set();
            };
            Console.CancelKeyPress += handler;
            foreach (string line in quickStart ? [] : ServiceStartup.Lines(deployment.HostName, deployment.Fingerprint, enrolled, service.Authorization.IsRemote))
            {
                TerminalPrompt.Line(line);
            }

            if (!quickStart && !service.Authorization.IsRemote)
            {
                foreach (string line in ServiceStartup.LockLines(service.Lock.IsLocked, service.Admin.PageUrl))
                {
                    TerminalPrompt.Line(line);
                }
            }

            if (service.MachinePort is { } machinePortNow)
            {
                TerminalPrompt.Line($"using-secrets service: machine listener on {machineEndpoint!.Bind}:{machinePortNow} (HTTPS: TLS 1.3 mutual authentication and HTTP/2; the machine API only: no administration, no pages). A firewall rule for that port is the administrator's to make.");
            }

            if (machineEndpoint is not null && service.MachinePort is null)
            {
                TerminalPrompt.Line("using-secrets service: the machine listener starts as soon as the first approval makes the authority signing key (no restart needed); until then no machine can connect.");
            }

            if (!quickStart)
            {
                if (!service.Authorization.IsRemote)
                {
                    TerminalPrompt.Line("using-secrets service: the browser interface is on " + service.Admin.PageUrl + " (loopback only).");
                }

                TerminalPrompt.Line($"using-secrets service: the command line reaches this service over {service.Endpoint.Describe()}, which only this user can open. Press Ctrl+C to stop.");
            }
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

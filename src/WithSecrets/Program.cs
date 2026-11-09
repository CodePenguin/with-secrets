using System.Globalization;
using System.Text;

namespace WithSecrets;

internal static class Program
{
    // Everything lives in the user profile: %USERPROFILE%\.with-secrets\state.db (passkeys, settings, approvals, audit and the
    // secrets as Dotenvx ciphertext). The store key is never stored: it is wrapped under keys that only the passkeys (WebAuthn PRF) can produce.
    private const string StoreFolder = ".with-secrets";

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

            case CliCommand.Admin admin:
                return CommandWiring.Admin(admin, state, folder, command.Port);

            case CliCommand.GrantAdmin grantAdmin:
                return CommandWiring.AdminGrants(grantAdmin, state, folder, command.Port);

            case CliCommand.AuditAdmin auditAdmin:
                return CommandWiring.AdminAudit(auditAdmin, folder);
        }

        return RunCommand.Usage;
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

    /// <summary>The host service in the foreground, until Ctrl+C. Windows service installation and start at logon come later.</summary>
    private static string StorePath() => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), StoreFolder);

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

        LocalDeployment deployment;
        EnrollmentResult enrolled;
        try
        {
            // The machine identity key is made on the first start (non-exportable, kept by Windows) and never leaves it.
            deployment = LocalDeployment.OpenProduction(folder);
            enrolled = deployment.EnrollAsync().GetAwaiter().GetResult();
        }
        catch (Exception failure) when (failure is AuthorityDatabaseException or System.Security.Cryptography.CryptographicException)
        {
            TerminalPrompt.Final("with-secrets: the machine identity or the authority cannot be used: " + failure.Message);

            return RunCommand.StoreError;
        }

        HostService service;
        try
        {
            service = HostService.Start(new HostServiceOptions { State = state, Store = store, Grants = grants, Port = port.Value, Deployment = deployment });
        }
        catch (Exception failure)
        {
            TerminalPrompt.Final($"with-secrets: the host service cannot listen on port {port} ({failure.GetType().Name}). Is it already running? Use --port N for another port.");

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

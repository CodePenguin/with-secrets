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

        string folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), StoreFolder);
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
        }

        RunArgs parsed = ((CliCommand.Run)command).Args;
        using Stream stdout = Console.OpenStandardOutput();
        using Stream stderr = Console.OpenStandardError();
        using StreamWriter outWriter = new(stdout, new UTF8Encoding(false)) { AutoFlush = true };
        using StreamWriter errWriter = new(stderr, new UTF8Encoding(false)) { AutoFlush = true };
        return await CommandWiring.Run(state, store, grants, parsed, command.Port, outWriter, errWriter, Directory.GetCurrentDirectory());
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

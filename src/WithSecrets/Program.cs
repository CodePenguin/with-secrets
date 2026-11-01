using System.Text;

namespace WithSecrets;

internal static class Program
{
    // The store lives in the user profile: %USERPROFILE%\.with-secrets\.env.local
    private const string StoreFolder = ".with-secrets";

    private static async Task<int> Main(string[] args)
    {
        CliCommand? command = CliArgs.Parse(args, out string error);
        if (command is null)
        {
            Console.Error.WriteLine("with-secrets: " + error);

            return RunCommand.Usage;
        }

        if (command is CliCommand.Help help)
        {
            Console.Out.Write(help.Text);

            return 0;
        }

        string storeFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), StoreFolder, ".env.local");
        string folder = Path.GetDirectoryName(storeFile)!;
        ISecretStore store = new DotenvxSecretStore(storeFile);
        GrantStore grants = new(Path.Combine(folder, "grants.json"));

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
                    Console.Error.WriteLine("with-secrets: cannot read the secret store: " + failure.Message);

                    return RunCommand.StoreError;
                }

            case CliCommand.Set set:
                return HumanCommands.Set(store, set.Name);

            case CliCommand.Remove remove:
                return HumanCommands.Remove(store, remove.Name);

            case CliCommand.Revoke:
                return HumanCommands.Revoke(grants);
        }

        RunArgs parsed = ((CliCommand.Run)command).Args;
        using Stream stdout = Console.OpenStandardOutput();
        using Stream stderr = Console.OpenStandardError();
        using StreamWriter outWriter = new(stdout, new UTF8Encoding(false)) { AutoFlush = true };
        using StreamWriter errWriter = new(stderr, new UTF8Encoding(false)) { AutoFlush = true };
        RunCommand run = new(store, new ApproverChain(new ApprovalWindow(), new WindowsHelloApprover(message: ApprovalSummary.BuildConfirmMessage)), new AuditLog(Path.Combine(folder, "audit.log")), outWriter, errWriter, grants, ReuseSettings.Load(Path.Combine(folder, "settings.json")));

        return await run.ExecuteAsync(parsed, Directory.GetCurrentDirectory());
    }
}

/// <summary>Commands that only a person at a terminal may run. An agent's shell has redirected input and output, so they refuse.</summary>
internal static class HumanCommands
{
    public static int Set(ISecretStore store, string name)
    {
        if (!RequireTerminal())
        {
            return RunCommand.Denied;
        }

        if (!SecretNames.IsValid(name))
        {
            Console.Error.WriteLine("Use UPPER_SNAKE_CASE for the name (letters, digits, underscores). Names that start with DOTENV_ are reserved.");

            return RunCommand.Usage;
        }

        string first = ReadHidden($"Value for {name}: ");
        if (first.Length < SecretNames.MinValueLength)
        {
            Console.Error.WriteLine($"The value must have at least {SecretNames.MinValueLength} characters (short values cause over-redaction).");

            return RunCommand.Usage;
        }

        if (ReadHidden("Again to confirm: ") != first)
        {
            Console.Error.WriteLine("The two values differ. Nothing was stored.");

            return RunCommand.Usage;
        }

        store.Set(name, first);
        Console.Error.WriteLine($"Stored {name}.");

        return 0;
    }

    public static int Remove(ISecretStore store, string name)
    {
        if (!RequireTerminal())
        {
            return RunCommand.Denied;
        }

        bool removed = store.Remove(name);
        Console.Error.WriteLine(removed ? $"Removed {name}." : $"{name} is not in the store.");

        return removed ? 0 : RunCommand.Usage;
    }

    public static int Revoke(GrantStore grants)
    {
        if (!RequireTerminal())
        {
            return RunCommand.Denied;
        }

        grants.Clear();
        Console.Error.WriteLine("Every saved approval has ended.");

        return 0;
    }

    private static bool RequireTerminal()
    {
        if (Console.IsInputRedirected || Console.IsOutputRedirected || Console.IsErrorRedirected)
        {
            Console.Error.WriteLine("This command needs a real terminal. It is for people, not agents.");

            return false;
        }

        return true;
    }

    private static string ReadHidden(string prompt)
    {
        Console.Error.Write(prompt);
        StringBuilder value = new();
        while (true)
        {
            ConsoleKeyInfo key = Console.ReadKey(true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.Error.WriteLine();

                return value.ToString();
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (value.Length > 0)
                {
                    value.Length--;
                }
            }
            else if (!char.IsControl(key.KeyChar))
            {
                value.Append(key.KeyChar);
            }
        }
    }
}

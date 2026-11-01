using System.CommandLine;

namespace WithSecrets;

/// <summary>What the command line asks for. Exactly one of these per call.</summary>
public abstract record CliCommand
{
    /// <summary>--list: print the secret names.</summary>
    public sealed record List : CliCommand;

    /// <summary>--set NAME: a person stores a value.</summary>
    public sealed record Set(string Name) : CliCommand;

    /// <summary>--remove NAME: a person deletes a secret.</summary>
    public sealed record Remove(string Name) : CliCommand;

    /// <summary>--revoke: a person ends every saved approval.</summary>
    public sealed record Revoke : CliCommand;

    /// <summary>--secrets ... --reason ... -- PROGRAM [ARGS...]: run a program with secrets.</summary>
    public sealed record Run(RunArgs Args) : CliCommand;

    /// <summary>--help or --version: text for the person, nothing else to do.</summary>
    public sealed record Help(string Text) : CliCommand;
}

/// <summary>
/// Reads the command line with System.CommandLine, as dotnet-dotenvx does. The agent controls these arguments, so the parser
/// is used narrowly: only the part before the first <c>--</c> is parsed. Everything after it is the program and its own
/// arguments, taken as typed and never looked at by the parser. Response files (<c>@file</c>) are switched off, because a file
/// could add options the prompt does not show. An unknown directive such as <c>[env:NAME=value]</c> is an error.
/// </summary>
public static class CliArgs
{
    private const string Description = """
        Run a program with stored secrets, without showing the values to an agent.

        To run a program: with-secrets --secrets NAME[,NAME...] --reason "why" -- PROGRAM [ARGS...]
        The user approves the request. Then PROGRAM runs with only those secrets as environment variables, and its output is
        redacted. Write -- before the program. Use --list to see the names.

        An approval is reused for the same secrets, program, script, and folder for a limited time (settings.json in the store
        folder: {"reuseMinutes": 10}, at most 60, 0 turns reuse off).
        """;

    /// <summary>Returns the command, or null and an error message when the arguments are wrong.</summary>
    public static CliCommand? Parse(IReadOnlyList<string> args, out string error)
    {
        int separator = IndexOfSeparator(args);
        List<string> head = args.Count == 0 ? ["--help"] : [.. separator < 0 ? args : args.Take(separator)];
        List<string> tail = separator < 0 ? [] : [.. args.Skip(separator + 1)];

        Option<bool> list = new("--list", "-List") { Description = "Print the secret names. Nothing is decrypted." };
        Option<string?> set = new("--set") { Description = "A person stores a value (hidden prompt, real terminal).", HelpName = "NAME" };
        Option<string?> remove = new("--remove") { Description = "A person deletes a secret (real terminal).", HelpName = "NAME" };
        Option<bool> revoke = new("--revoke") { Description = "A person ends every saved approval now (real terminal)." };
        Option<string[]> secrets = new("--secrets")
        {
            Description = "Names of the secrets to give the program, separated by commas. Write every name. There is no option for all secrets.",
            HelpName = "NAME[,NAME...]"
        };
        Option<string?> reason = new("--reason") { Description = "Why the program needs the secrets, in one sentence.", HelpName = "TEXT" };

        RootCommand root = new(Description);
        // Do not clear root.Directives: with none registered, System.CommandLine silently drops any [name:value] token. With the
        // default ones, an unknown directive such as [env:PATH=x] is an error. [suggest] only prints completions (shown as Help).
        root.Options.Add(list);
        root.Options.Add(set);
        root.Options.Add(remove);
        root.Options.Add(revoke);
        root.Options.Add(secrets);
        root.Options.Add(reason);

        ParseResult result = root.Parse(head, new ParserConfiguration { ResponseFileTokenReplacer = null });
        if (result.Errors.Count > 0)
        {
            error = string.Join(" ", result.Errors.Select(item => item.Message));

            return null;
        }

        if (result.Action is not null)
        {
            StringWriter text = new();
            result.Invoke(new InvocationConfiguration { Output = text, Error = text });
            error = "";

            return new CliCommand.Help(text.ToString());
        }

        string[] names = [.. result.GetValue(secrets)!.SelectMany(value => value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))];
        string? reasonText = result.GetValue(reason);
        string? setName = result.GetValue(set);
        string? removeName = result.GetValue(remove);
        bool runRequested = names.Length > 0 || reasonText is not null || separator >= 0;

        int modes = (result.GetValue(list) ? 1 : 0) + (setName is not null ? 1 : 0) + (removeName is not null ? 1 : 0) + (result.GetValue(revoke) ? 1 : 0) + (runRequested ? 1 : 0);
        if (modes != 1)
        {
            error = modes == 0
                ? "Nothing to do. Use --list, or --secrets NAME[,NAME...] --reason TEXT -- PROGRAM [ARGS...]. Try --help."
                : "Use one command at a time: --list, --set, --remove, --revoke, or a run with --secrets.";

            return null;
        }

        error = "";
        if (!runRequested)
        {
            return result.GetValue(list) ? new CliCommand.List()
                : setName is not null ? new CliCommand.Set(setName)
                : removeName is not null ? new CliCommand.Remove(removeName)
                : new CliCommand.Revoke();
        }

        if (tail.Count == 0)
        {
            error = "Missing '-- PROGRAM'. Usage: with-secrets --secrets NAME[,NAME...] --reason TEXT -- PROGRAM [ARGS...]";

            return null;
        }

        if (string.IsNullOrWhiteSpace(reasonText))
        {
            error = "--reason is required. Say what the secrets are for, in one sentence.";

            return null;
        }

        if (names.Length == 0)
        {
            error = "Name the secrets with --secrets NAME[,NAME...]. There is no option for all secrets.";

            return null;
        }

        return new CliCommand.Run(new RunArgs(names.Distinct(StringComparer.Ordinal).ToList(), reasonText.Trim(), tail[0], tail.Skip(1).ToList()));
    }

    /// <summary>Parses a run: --secrets NAME[,NAME...] --reason TEXT -- PROGRAM [ARGS...]. Returns null and a message for anything else.</summary>
    public static RunArgs? ParseRun(IReadOnlyList<string> args, out string error)
    {
        CliCommand? command = Parse(args, out error);
        if (command is null)
        {
            return null;
        }

        if (command is CliCommand.Run run)
        {
            return run.Args;
        }

        error = "Expected: --secrets NAME[,NAME...] --reason TEXT -- PROGRAM [ARGS...]";

        return null;
    }

    private static int IndexOfSeparator(IReadOnlyList<string> args)
    {
        for (int index = 0; index < args.Count; index++)
        {
            if (args[index] == "--")
            {
                return index;
            }
        }

        return -1;
    }
}

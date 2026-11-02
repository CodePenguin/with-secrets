using System.CommandLine;
using System.Globalization;

namespace WithSecrets;

/// <summary>What the command line asks for. Exactly one of these per call.</summary>
public abstract record CliCommand
{
    /// <summary>--list: print the secret names.</summary>
    public sealed record List : CliCommand;

    /// <summary>--set NAME[,NAME...]: a person types the values on a web page; they are stored after a passkey proof.</summary>
    public sealed record Set(IReadOnlyList<string> Names) : CliCommand;

    /// <summary>--remove NAME[,NAME...]: a person approves on a web page; then the secrets are deleted.</summary>
    public sealed record Remove(IReadOnlyList<string> Names) : CliCommand;

    /// <summary>--revoke: a person ends every saved approval.</summary>
    public sealed record Revoke : CliCommand;

    /// <summary>--enroll [--local]: a person adds something that can approve runs, such as a passkey (named on the page).</summary>
    public sealed record Enroll(bool Local = false) : CliCommand;

    /// <summary>--enrolled: print what can approve runs.</summary>
    public sealed record Enrolled : CliCommand;

    /// <summary>--unenroll NAME [--local]: a person removes something that can approve runs.</summary>
    public sealed record Unenroll(string Name, bool Local = false) : CliCommand;

    /// <summary>--audit [--last N] [--secret NAME] [--verify]: print recent audit entries (names only), and check the chain.</summary>
    public sealed record Audit(int Last, string? Secret, bool Verify) : CliCommand;

    /// <summary>--config: a person changes the settings on a web page (first run: and adds the first passkey). --show prints them.</summary>
    public sealed record Config(bool Show) : CliCommand;

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

        On the approval page the user picks Approve once, or Approve for a time (10 minutes, 1 hour, 4 hours or 8 hours, up
        to the reuseMaxMinutes setting: default 480, 10 to 1440; reuseMinutes is the time the list starts on). A time-limited
        approval covers the same secrets, program, script, and folder, whatever the other arguments, until it ends: the same
        request then runs without asking. The chosen time is signed with the passkey, and a saved approval is used only
        while that signature verifies; one that does not is ignored (stderr says so) and the user is asked again.

        A person changes the settings with --config: the terminal shows only a link, the page shows every setting, and a
        passkey approves the change. With nothing enrolled, --config is the first-time setup: it also creates the first
        passkey, stored only after the person types the code from the page in the terminal. --config --show prints the
        settings.

        A person adds a passkey with --enroll (its name, and whether it is also an admin, are chosen on the page), sees
        them with --enrolled, and removes one with --unenroll NAME (any key but the last admin key). Admin keys change the
        state; two admin keys (laptop and phone) mean a lost device does not lock you out.
        Every page, --enrolled and --audit list the admin keys' fingerprints ("Admins: laptop ab12 cd34 ef56 7890, phone ...").
        Note them down; if they ever change without you, state.db was replaced.
        If baseUrl is set, add --local to use a page at http://localhost instead.

        A person stores secrets with --set NAME[,NAME...] and deletes them with --remove NAME[,NAME...]. Both open a web
        page and need a passkey; the terminal shows only the link and the names. Values are never typed in a terminal.

        --audit prints the admin keys' fingerprints, then the newest audit entries (default 20; --last N, 1 to 1000; --secret NAME for one secret): time, event,
        secret names, program, outcome and key name. Never values. --verify also checks the hash chain (exit 4 if broken).
        """;

    /// <summary>Returns the command, or null and an error message when the arguments are wrong.</summary>
    public static CliCommand? Parse(IReadOnlyList<string> args, out string error)
    {
        int separator = IndexOfSeparator(args);
        List<string> head = args.Count == 0 ? ["--help"] : [.. separator < 0 ? args : args.Take(separator)];
        List<string> tail = separator < 0 ? [] : [.. args.Skip(separator + 1)];

        Option<bool> list = new("--list", "-List") { Description = "Print the secret names. Nothing is decrypted." };
        Option<string?> set = new("--set") { Description = "A person types the values on a web page, then approves with a passkey.", HelpName = "NAME[,NAME...]" };
        Option<string?> remove = new("--remove") { Description = "A person approves on a web page, then the secrets are deleted.", HelpName = "NAME[,NAME...]" };
        Option<bool> revoke = new("--revoke") { Description = "A person ends every saved approval now (real terminal)." };
        Option<bool> enroll = new("--enroll") { Description = "A person adds a passkey on a web page and names it there; the terminal shows the link (real terminal)." };
        Option<bool> local = new("--local") { Description = "With --enroll or --unenroll: use the page at http://localhost:<port> and ignore baseUrl." };
        Option<bool> enrolled = new("--enrolled") { Description = "Print the admin keys' fingerprints, then the passkeys that can approve runs (real terminal)." };
        Option<string?> unenroll = new("--unenroll") { Description = "A person removes a passkey by name (real terminal).", HelpName = "NAME" };
        Option<bool> audit = new("--audit") { Description = "Print the admin keys' fingerprints, then the newest audit entries: time, event, secret names, program, outcome, key name. Never values." };
        Option<string?> last = new("--last") { Description = "With --audit: how many entries, 1 to 1000. Default: 20.", HelpName = "N" };
        Option<string?> secret = new("--secret") { Description = "With --audit: only entries that name this secret.", HelpName = "NAME" };
        Option<bool> verify = new("--verify") { Description = "With --audit: check the audit hash chain and report the first broken entry (exit 4)." };
        Option<bool> config = new("--config") { Description = "A person changes the settings on a web page with a passkey; with nothing enrolled, sets up the first passkey (real terminal)." };
        Option<bool> show = new("--show") { Description = "With --config: print the settings and their values (anywhere)." };
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
        root.Options.Add(enroll);
        root.Options.Add(local);
        root.Options.Add(enrolled);
        root.Options.Add(unenroll);
        root.Options.Add(audit);
        root.Options.Add(last);
        root.Options.Add(secret);
        root.Options.Add(verify);
        root.Options.Add(config);
        root.Options.Add(show);
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
        bool enrollRequested = result.GetValue(enroll);
        string? unenrollName = result.GetValue(unenroll);
        bool localRequested = result.GetValue(local);
        bool runRequested = names.Length > 0 || reasonText is not null || separator >= 0;

        if (localRequested && !enrollRequested && unenrollName is null)
        {
            error = "--local goes only with --enroll or --unenroll.";

            return null;
        }

        bool auditRequested = result.GetValue(audit);
        string? lastText = result.GetValue(last);
        string? secretName = result.GetValue(secret);
        bool verifyRequested = result.GetValue(verify);
        if ((lastText is not null || secretName is not null || verifyRequested) && !auditRequested)
        {
            error = "--last, --secret and --verify go only with --audit.";

            return null;
        }

        bool configRequested = result.GetValue(config);
        bool showRequested = result.GetValue(show);
        if (showRequested && !configRequested)
        {
            error = "--show goes only with --config.";

            return null;
        }

        int modes = (auditRequested ? 1 : 0) + (result.GetValue(list) ? 1 : 0) + (setName is not null ? 1 : 0) + (removeName is not null ? 1 : 0) + (result.GetValue(revoke) ? 1 : 0)
            + (enrollRequested ? 1 : 0) + (result.GetValue(enrolled) ? 1 : 0) + (unenrollName is not null ? 1 : 0) + (configRequested ? 1 : 0) + (runRequested ? 1 : 0);
        if (modes != 1)
        {
            error = modes == 0
                ? "Nothing to do. Use --list, --audit, --config, --enroll, --enrolled, --unenroll NAME, or --secrets NAME[,NAME...] --reason TEXT -- PROGRAM [ARGS...]. Try --help."
                : "Use one command at a time: --list, --set, --remove, --revoke, --enroll, --enrolled, --unenroll, --audit, --config, or a run with --secrets.";

            return null;
        }

        if (configRequested)
        {
            error = "";

            return new CliCommand.Config(showRequested);
        }

        IReadOnlyList<string>? changeNames = null;
        if (setName is not null || removeName is not null)
        {
            changeNames = SecretNameList(setName ?? removeName!, out error);
            if (changeNames is null)
            {
                return null;
            }
        }

        if (auditRequested)
        {
            return AuditArgs(lastText, secretName, verifyRequested, out error);
        }

        error = "";
        if (!runRequested)
        {
            return result.GetValue(list) ? new CliCommand.List()
                : setName is not null ? new CliCommand.Set(changeNames!)
                : removeName is not null ? new CliCommand.Remove(changeNames!)
                : enrollRequested ? new CliCommand.Enroll(localRequested)
                : result.GetValue(enrolled) ? new CliCommand.Enrolled()
                : unenrollName is not null ? new CliCommand.Unenroll(unenrollName, localRequested)
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

    /// <summary>
    /// True for the commands a person runs in a terminal of their own: they refuse when input or output is redirected, as in
    /// an agent's shell. That check cannot tell whose terminal it is; it only stops the plain case.
    /// </summary>
    public static bool NeedsTerminal(CliCommand command)
    {
        return command is CliCommand.Revoke or CliCommand.Enroll or CliCommand.Enrolled or CliCommand.Unenroll or CliCommand.Config { Show: false };
    }

    /// <summary>What a command that needs a terminal says when it has none.</summary>
    public static string NoTerminalMessage(CliCommand _)
    {
        return "This command needs a real terminal. It is for people, not agents.";
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

    /// <summary>
    /// The names of --set or --remove: split at commas, trimmed, empty and repeated names dropped. Null and a message when
    /// there are none, more than <see cref="SecretEntry.MaxNames" />, or a name that <see cref="SecretNames.IsValid" /> refuses.
    /// </summary>
    private static List<string>? SecretNameList(string text, out string error)
    {
        List<string> names = [.. text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.Ordinal)];
        error = names.Count == 0 ? "Give at least one secret name: NAME[,NAME...]."
            : names.Count > SecretEntry.MaxNames ? $"Give at most {SecretEntry.MaxNames} secret names at a time."
            : names.Any(name => !SecretNames.IsValid(name)) ? "Use UPPER_SNAKE_CASE for the names (letters, digits, underscores). Names that start with DOTENV_ are reserved."
            : "";

        return error.Length == 0 ? names : null;
    }

    private static CliCommand.Audit? AuditArgs(string? lastText, string? secretName, bool verify, out string error)
    {
        int count = AuditCommand.DefaultLast;
        if (lastText is not null && (!int.TryParse(lastText, NumberStyles.None, CultureInfo.InvariantCulture, out count) || count < 1 || count > AuditCommand.MaxLast))
        {
            error = $"--last takes a number from 1 to {AuditCommand.MaxLast}.";

            return null;
        }

        if (secretName is not null && !SecretNames.IsValid(secretName))
        {
            error = "--secret takes one secret name in UPPER_SNAKE_CASE.";

            return null;
        }

        error = "";

        return new CliCommand.Audit(count, secretName, verify);
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

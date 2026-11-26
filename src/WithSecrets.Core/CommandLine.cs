using System.CommandLine;
using System.Globalization;

namespace WithSecrets;

/// <summary>What the command line asks for. Exactly one of these per call.</summary>
public abstract record CliCommand
{
    /// <summary>--port N: where the one-use page listens for this call, in place of the port setting. Null: use the setting.</summary>
    public int? Port { get; init; }

    /// <summary>--debug (any command): diagnostic lines go to the terminal and the log file. Off by default.</summary>
    public bool Debug { get; init; }

    /// <summary>--port N with <c>service</c> or <c>admin</c>: the loopback port of the admin web app (a browser reaches it there; the command line does not use a port). Null: WITH_SECRETS_PORT, then the default.</summary>
    public int? AdminPort { get; init; }

    /// <summary>service [--port N] [--machine-port N [--machine-bind ADDRESS]]: run the host service in the foreground (loopback only for the API; the optional machine listener serves only the machine API, over TLS 1.3 mutual authentication and HTTP/2, for another machine's host service, such as the one in WSL).</summary>
    public sealed record Service(int? MachinePort = null, string MachineBind = "127.0.0.1") : CliCommand;

    /// <summary>pair [--debug]: pair this machine with an authority using the one-time invitation an administrator made in the admin web app (hidden prompt, or unattended from a secret file or WITH_SECRETS_PAIRING). Human-only when it must prompt; a new top-level command because administration has no verbs.</summary>
    public sealed record Pair : CliCommand;
    /// <summary>admin (no further words): go to the authority's admin web app, where all administration lives (machines, grants, audit, settings, lock and unlock). It has no verbs.</summary>
    public sealed record AdminApp : CliCommand;


    /// <summary>approve --secrets ... --reason ... -- PROGRAM [ARGS...]: the approval of a run (same grammar), but it makes a grant for the request and launches nothing.</summary>
    public sealed record Approve(RunArgs Args) : CliCommand;

    /// <summary>--recover: for when every passkey is lost. The recovery code opens the old store; a new passkey and new keys are made and the secrets carried over.</summary>
    public sealed record Recover : CliCommand;

    /// <summary>--needs [-f FILE]...: print what the project's .env files would ask for (names only; nothing is approved or decrypted).</summary>
    public sealed record Needs(IReadOnlyList<string> EnvFiles) : CliCommand;

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
    /// <summary>What a refused secret name is told.</summary>
    public const string SecretNameRule = "A secret name is NAME or folder/NAME (up to 3 folders, 200 characters in all). NAME is letters, digits and underscores starting with a letter, in any case (names are case-sensitive), and does not start with DOTENV_ (except DOTENV_PRIVATE_KEY...); a folder uses letters, digits, _ . - (1 to 64) and is not . or ..";

    private const string Description = """
        Run a program with stored secrets, without showing the values to an agent.

        Every run is approved once. A grant (below) lets one exact command run again without asking, for a time; reuseMaxMinutes sets the longest time.

        To run a program: with-secrets [--secrets NAME[,NAME...]] --reason "why" [-f .env] -- PROGRAM [ARGS...]
        Set WITH_SECRETS_ONEPASSWORD_EXECUTABLE to the trusted absolute path to op on the authority host.
        Set WITH_SECRETS_DOTENVX_EXECUTABLE in the requesting user's environment to the absolute path of a trusted dotenvx binary.


        A run goes through the host service, which must be running (with-secrets service, in a terminal of its own). The run reaches it over
        a channel only this user can open (Windows: a named pipe; Linux and macOS: a Unix socket), never over a network port. Without the service a run exits 6.
        The user approves the request. Then PROGRAM runs with only those secrets as environment variables, and its output is
        redacted. Write -- before the program. --needs shows what the project's .env asks for; the stored names are in the admin web app.

        The approval page shows what will run: the whole command line; inline code ("Inline code:", first 4000 characters);
        and every file read as code (the script an interpreter runs, and a program that is a text file) with its SHA-256 and
        contents ("Script contents:", first 200 lines, at most 16 KB). Every shown line starts with "  | ". The passkey
        signs this text. Interpreters are allowed in one strict form only, and anything else is refused ("put options inside
        the script file"): sh, bash, zsh, dash, ksh, fish, python: "PROG script [args]" or "PROG -c CODE"; node, perl, ruby:
        "PROG script [args]" or "PROG -e CODE"; powershell, pwsh: -NoProfile (required), -NonInteractive, -NoLogo, -ExecutionPolicy
        VALUE, then exactly -File path or -Command CODE; cmd: "cmd /d /c" with plain words starting with a .cmd/.bat file
        or echo, dir, type, ver. An interpreter with nothing to run, a script that cannot be read or is over 1 MB, and encoded
        commands are refused. The program gets no standard input and loses code-loading variables such as NODE_OPTIONS and
        BASH_ENV. On Windows the shown files are held open against changes until the program ends; elsewhere that is not
        enforced. A long or obfuscated script can still be hard to judge, and files a script loads are not shown.

        Grants. with-secrets approve --secrets NAME[,NAME...] --reason TEXT -- PROGRAM [ARGS...] takes the same arguments as a run and shows the
        same approval page, where the user also picks how long the approval lasts; the authority then records a grant for exactly that
        request (the secrets, the program, the working folder, the script and the .env plan; not the other arguments) and nothing is run.
        A later run of that request needs no approval page decision while the grant lasts, the machine is Trusted and the host service is
        in contact with its authority (a host that cannot reach its authority runs nothing: it fails closed). A request the grant does not cover, or one after it ends or is
        revoked, goes through the page as before. A store whose key is released by a passkey tap still asks for that tap at each run. A
        person lists and changes grants in the admin web app (with-secrets admin prints its link).

        New approvals offer 1, 2, 4, 8, or 24 hours, 7 or 30 days, or Always. Finite choices respect the signed reuseMaxMinutes
        ceiling (default 43200 minutes on a new store). The
        chosen time is signed with the passkey.

        A project declares what it needs in a .env file in the working directory (not searched upward); -f/--env-file PATH
        (repeatable) reads those files instead, and a missing -f file is an error. Lines are NAME=value, with # comments,
        optional export, and single, double or no quotes. A value TOKEN=secret://NAME (or secret://folder/NAME; the whole
        path is the store name) gives the program the secret under the variable TOKEN. Other values are ordinary variables
        (names only on the approval page). --secrets and --reason work as before: --secrets is optional when the .env has
        references, --reason is always required. The first file wins per name; an existing environment variable beats an
        ordinary .env value, but a secret:// reference beats it. The approval page shows every "VARIABLE <- secret NAME" and
        the .env paths, and the files are read once. Code-loading variables (NODE_OPTIONS...) are dropped from .env values
        and a reference to one, or to PATH, is refused. In dotenvx projects, dotenvx resolves approved encrypted and expanded values.
        --needs [-f PATH]... prints what the current project would ask for (names only) and whether each secret is in the store.

        Machines. Every host service has a machine identity (an ECDSA P-256 key that Windows keeps and nobody can read out; its
        fingerprint is the SHA-256 of the public key). The first time the service runs on a machine, the machine is Pending: it
        cannot get secrets until an administrator approves it. All administration is in the authority's admin web app, not in commands:
        with-secrets admin (no words) prints its link (http://localhost:8765/admin) and the service's status. Sign in there with one passkey tap
        (a read-only session of 15 minutes idle, 8 hours at most); every change (approve, disable, enable, untrust, trust, rename or approve a host
        name change of a machine; extend, renew or revoke a grant; passkeys; settings; the authority key; lock and unlock) is its own fresh
        passkey tap on a one-use page that names that change. Add --port N when the admin web app is not on the default port.

        Pairing a machine with an authority: an administrator creates a one-time pairing invitation in the authority's admin web app (Pairing:
        one passkey tap; the invitation is shown once and is valid for 10 minutes) and gives it to the new machine, which runs: with-secrets pair
        It asks for the invitation without showing it, or reads it unattended from a secret file (the path in WITH_SECRETS_PAIRING_FILE, or the Docker
        secret named with-secrets-pairing) or from WITH_SECRETS_PAIRING (a file is preferred). The invitation is never a command-line argument and its
        code is never sent: the machine and the authority prove to each other that they hold it, the machine verifies the authority before it sends
        anything about itself, and then it waits Pending. It prints only its fingerprint and host name; the administrator checks them in the admin
        web app and approves with a passkey tap.

        Audit trail. The host service signs an audit event with the machine key for every run (the authorization decision, the launch
        outcome and the execution outcome are separate events, numbered per machine) and commits the authorization event to its own
        outbox BEFORE a secret is decrypted: if that cannot be done the run does not happen (exit 5). It sends the events to the authority
        by itself and keeps them until the authority has them. A person reads what the authority holds in the admin web app (Audit: filter by machine,
        time, type, outcome, grant, folder or text; the sequence gaps of a machine's numbering). Arguments are recorded
        with values that look like secrets masked; no secret value, environment value or user name is recorded.
        Changes made in the admin web app, and --recover, record their own signed events
        (type admin: the event name and names only) the same way. There is no other audit log.

        First-time setup: with-secrets admin, with nothing enrolled, creates the first passkey on a web page (the terminal shows only
        the link) and stores it only after the person types the code from the page in the terminal. Settings are changed in the admin
        web app.

        First-time setup also shows a recovery code on its last page, once. Write it down and keep it offline: anyone with the
        code and with-secrets.db can open all secrets. If every passkey is lost, --recover asks for the code on a web page, makes a new
        passkey and new keys, and carries the secrets over; a snapshot of the previous database is saved (with-secrets.db.recovered-<time>).

        Everything else a person does is in the admin web app (with-secrets admin prints its link): storing and removing secrets (values
        are typed on a web page, never in a terminal), adding and removing passkeys, rotating the secret store key, and the page settings.
        Every page lists the admin keys' fingerprints ("Admins: laptop ab12 cd34 ef56 7890, phone ..."). Note them down; if they ever
        change without you, with-secrets.db was replaced.

        --port N (1 to 65535) with --recover or a run makes that call's web page listen on port N instead of the port setting (random free
        port if the setting is 0). It is not saved. If N is in use the call fails. Use it to forward the page over ssh: ssh -L N:localhost:N host.

        --debug (with any command, before --) shows diagnostic lines on the terminal (connections, requests, proof sizes and verdicts) and writes them to the log file; WITH_SECRETS_DEBUG=1 does the same for every call. Normally the terminal shows none of them. Warnings and errors always go to the log file, %USERPROFILE%\.with-secrets\logs\with-secrets-YYYYMMDD.log (1 MB per file, 7 files kept). The log holds route words, sizes, seconds and error type names, never a value, a code, a key or a link.

        --self-check (alone) is the release check: it starts a throwaway service (software keys, a temporary folder, a free loopback port; no user state, no Windows key), asks it for the administration web app and the API, and prints one JSON line with the backend version, the frontend version and the embedded files. Exit code 0 only when the web app is embedded, served from the one origin, and its version is the backend's.

        """;

    /// <summary>Returns the command, or null and an error message when the arguments are wrong.</summary>
    public static CliCommand? Parse(IReadOnlyList<string> args, out string error)
    {
        if (args.Count > 0 && args[0] == "service")
        {
            return ParseService(args, out error);
        }

        if (args.Count > 0 && args[0] == "admin")
        {
            if (args.Count == 1 || args[1].StartsWith("--", StringComparison.Ordinal))
            {
                return ParseAdminApp(args, out error);
            }

            error = "admin has no subcommands: all administration is in the authority's admin web app. Run: with-secrets admin   (it prints the link and the service's status)";

            return null;
        }

        if (args.Count > 0 && args[0] == "pair")
        {
            return ParsePair(args, out error);
        }

        if (args.Count > 0 && args[0] == "approve")
        {
            return ParseApprove(args, out error);
        }

        CliCommand? command = ParseCommand(args, out int? port, out bool debug, out error);
        if (command is null)
        {
            return null;
        }

        command = command with { Debug = debug };

        if (port is null)
        {
            return command;
        }

        if (command is CliCommand.Needs)
        {
            error = "--port goes only with a command that opens a web page: --recover, or a run.";

            return null;
        }

        return command with { Port = port };
    }

    /// <summary>approve ...: the arguments of a run, with the same checks; the result is an approval that makes a grant.</summary>
    private static CliCommand? ParseApprove(IReadOnlyList<string> args, out string error)
    {
        CliCommand? inner = Parse([.. args.Skip(1)], out error);
        if (inner is CliCommand.Help)
        {
            return inner;
        }

        if (inner is CliCommand.Run run)
        {
            return new CliCommand.Approve(run.Args) { Port = run.Port, Debug = run.Debug };
        }

        if (inner is null && error.Length > 0)
        {
            return null;
        }

        error = "approve takes the arguments of a run: with-secrets approve --secrets NAME[,NAME...] --reason TEXT -- PROGRAM [ARGS...]. It makes a grant for that exact request and runs nothing.";

        return null;
    }

    /// <summary>admin [--port N] [--debug]: the admin web app has no verbs; the port is where the browser reaches the app.</summary>
    private static CliCommand? ParseAdminApp(IReadOnlyList<string> args, out string error)
    {
        int? port = null;
        bool debug = false;
        for (int index = 1; index < args.Count; index++)
        {
            if (args[index] == "--debug")
            {
                debug = true;
            }
            else if (args[index] == "--port" && index + 1 < args.Count && int.TryParse(args[++index], NumberStyles.None, CultureInfo.InvariantCulture, out int parsed) && parsed is >= 1 and <= ToolSettings.MaxPort)
            {
                port = parsed;
            }
            else
            {
                error = "Usage: with-secrets admin [--port N] [--debug]   (opens nothing itself: it prints the link of the authority's admin web app)";

                return null;
            }
        }

        error = "";

        return new CliCommand.AdminApp { AdminPort = port, Debug = debug };
    }

    private const string PairUsage = "Usage: with-secrets pair [--debug]. It asks for the pairing invitation (hidden) that an administrator made in the authority's admin web app, or reads it from a secret file (WITH_SECRETS_PAIRING_FILE, or the Docker secret with-secrets-pairing) or from WITH_SECRETS_PAIRING. The invitation is never a command-line argument.";

    /// <summary>pair [--debug]: nothing else (the authority's address is in the invitation).</summary>
    private static CliCommand? ParsePair(IReadOnlyList<string> args, out string error)
    {
        bool debug = false;
        for (int index = 1; index < args.Count; index++)
        {
            if (args[index] == "--debug")
            {
                debug = true;
            }
            else
            {
                error = PairUsage;

                return null;
            }
        }

        error = "";

        return new CliCommand.Pair { Debug = debug };
    }

    /// <summary>service [--port N] [--debug]: nothing else.</summary>
    private static CliCommand? ParseService(IReadOnlyList<string> args, out string error)
    {
        int? port = null;
        int? machinePort = null;
        string machineBind = "127.0.0.1";
        bool bindGiven = false;
        bool debug = false;
        const string Usage = "Usage: with-secrets service [--port N] [--machine-port N [--machine-bind ADDRESS]]. N is the loopback port of the admin web app, 1 to 65535 (default 8765, or WITH_SECRETS_PORT); the command line reaches the service another way (a named pipe or a Unix socket of this user). --machine-port also serves the machine API (nothing else: no administration, no pages) over TLS 1.3 mutual authentication and HTTP/2 for another machine's host service such as the one in WSL; it listens on 127.0.0.1 unless --machine-bind names one address (never 0.0.0.0 or [::]).";
        int Number(string text) => int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out int parsed) && parsed >= 1 && parsed <= ToolSettings.MaxPort ? parsed : -1;
        for (int index = 1; index < args.Count; index++)
        {
            if (args[index] == "--debug")
            {
                debug = true;
            }
            else if (args[index] is "--port" or "--machine-port" && index + 1 < args.Count)
            {
                string option = args[index];
                int parsed = Number(args[++index]);
                if (parsed < 0)
                {
                    error = $"{option} takes a number from 1 to {ToolSettings.MaxPort}.";

                    return null;
                }

                if (option == "--port")
                {
                    port = parsed;
                }
                else
                {
                    machinePort = parsed;
                }
            }
            else if (args[index] == "--machine-bind" && index + 1 < args.Count && System.Net.IPAddress.TryParse(args[++index], out System.Net.IPAddress? address) && !System.Net.IPAddress.Any.Equals(address) && !System.Net.IPAddress.IPv6Any.Equals(address))
            {
                machineBind = args[index];
                bindGiven = true;
            }
            else
            {
                error = Usage;

                return null;
            }
        }

        if (machinePort is null && bindGiven)
        {
            error = "--machine-bind goes with --machine-port.";

            return null;
        }

        error = "";

        return new CliCommand.Service(machinePort, machineBind) { AdminPort = port, Debug = debug };
    }

    private static CliCommand? ParseCommand(IReadOnlyList<string> args, out int? portNumber, out bool debugRequested, out string error)
    {
        portNumber = null;
        debugRequested = false;
        int separator = IndexOfSeparator(args);
        List<string> head = args.Count == 0 ? ["--help"] : [.. separator < 0 ? args : args.Take(separator)];
        List<string> tail = separator < 0 ? [] : [.. args.Skip(separator + 1)];

        Option<bool> recover = new("--recover") { Description = "When every passkey is lost: type the recovery code on a web page, make a new passkey and new keys, and carry the secrets over. The old file is renamed, never deleted (real terminal)." };
        Option<string?> port = new("--port") { Description = "Where the one-use web page listens for this call, 1 to 65535, in place of the port setting (nothing is saved). If it is in use, the call fails. For ssh -L.", HelpName = "N" };
        Option<bool> debug = new("--debug") { Description = "With any command: show diagnostic lines on the terminal and write them to the log file (WITH_SECRETS_DEBUG=1 does it for every call). Warnings always go to the log file." };
        Option<string[]> secrets = new("--secrets")
        {
            Description = "Names of the secrets to give the program, separated by commas. Write every name. There is no option for all secrets.",
            HelpName = "NAME[,NAME...]"
        };
        Option<string?> reason = new("--reason") { Description = "Why the program needs the secrets, in one sentence.", HelpName = "TEXT" };
        Option<bool> needs = new("--needs") { Description = "Print what the project's .env files would ask for: the files, the ordinary variable names, and each secret reference with in store or NOT IN STORE. Names only. No approval." };
        Option<string[]> envFile = new("--env-file", "-f")
        {
            Description = "With a run or --needs: read this .env file (repeatable; the first file wins per name). Replaces the default .env in the working directory.",
            HelpName = "PATH"
        };

        RootCommand root = new(Description);
        // Do not clear root.Directives: with none registered, System.CommandLine silently drops any [name:value] token. With the
        // default ones, an unknown directive such as [env:PATH=x] is an error. [suggest] only prints completions (shown as Help).
        root.Options.Add(recover);
        root.Options.Add(port);
        root.Options.Add(debug);
        root.Options.Add(secrets);
        root.Options.Add(reason);
        root.Options.Add(needs);
        root.Options.Add(envFile);

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

        debugRequested = result.GetValue(debug);
        string[] names = [.. result.GetValue(secrets)!.SelectMany(value => value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))];
        string? reasonText = result.GetValue(reason);
        bool runRequested = names.Length > 0 || reasonText is not null || separator >= 0;
        string[] envFiles = [.. result.GetValue(envFile)!];
        bool needsRequested = result.GetValue(needs);
        if (envFiles.Length > 0 && !needsRequested && !runRequested)
        {
            error = "-f / --env-file goes only with a run or --needs.";

            return null;
        }

        if (result.GetValue(port) is { } portText)
        {
            if (!int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out int parsed) || parsed < 1 || parsed > ToolSettings.MaxPort)
            {
                error = $"--port takes a number from 1 to {ToolSettings.MaxPort}.";

                return null;
            }

            portNumber = parsed;
        }

        int modes = (needsRequested ? 1 : 0) + (result.GetValue(recover) ? 1 : 0) + (runRequested ? 1 : 0);
        if (modes != 1)
        {
            error = modes == 0
                ? "Nothing to do. Use --needs, --recover, or --reason TEXT [--secrets NAME[,NAME...]] -- PROGRAM [ARGS...]. Try --help."
                : "Use one command at a time: --needs, --recover, or a run with --secrets.";

            return null;
        }

        if (result.GetValue(recover))
        {
            error = "";

            return new CliCommand.Recover();
        }

        error = "";
        if (needsRequested)
        {
            return new CliCommand.Needs(envFiles);
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

        // --secrets may be empty: the project's .env can carry the references. A run with neither fails in RunCommand with this text.
        if (names.FirstOrDefault(name => name.Contains('/', StringComparison.Ordinal)) is { } folded)
        {
            error = $"--secrets cannot name {ApprovalSummary.Clean(folded)}: a secret in a folder is not an environment variable name. Put it in the .env as VARIABLE=secret://{ApprovalSummary.Clean(folded)}";

            return null;
        }

        return new CliCommand.Run(new RunArgs(names.Distinct(StringComparer.Ordinal).ToList(), reasonText.Trim(), tail[0], tail.Skip(1).ToList(), envFiles.Length == 0 ? null : envFiles));
    }

    /// <summary>
    /// True for the commands a person runs in a terminal of their own: they refuse when input or output is redirected, as in
    /// an agent's shell. That check cannot tell whose terminal it is; it only stops the plain case.
    /// </summary>
    public static bool NeedsTerminal(CliCommand command)
    {
        return command is CliCommand.Recover;
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

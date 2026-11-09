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

    /// <summary>--service-port N with a run, or --port N with <c>service</c>: the port of the host service. Null: WITH_SECRETS_PORT, then the default.</summary>
    public int? ServicePort { get; init; }

    /// <summary>service [--port N]: run the host service in the foreground (loopback only).</summary>
    public sealed record Service : CliCommand;

    /// <summary>relay [--port N] [--bind ADDRESS] [--cert FILE [--cert-password-env NAME]]: run the relay, an opaque in-memory router between host services and a remote authority.</summary>
    public sealed record Relay(int ListenPort, string Bind, string? CertificateFile, string? CertificatePasswordVariable) : CliCommand;

    /// <summary>admin (no further words): go to the authority's admin web app, where all administration lives (machines, grants, audit, settings, lock and unlock). It has no verbs.</summary>
    public sealed record AdminApp : CliCommand;


    /// <summary>approve --secrets ... --reason ... -- PROGRAM [ARGS...]: the approval of a run (same grammar), but it makes a grant for the request and launches nothing.</summary>
    public sealed record Approve(RunArgs Args) : CliCommand;

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

    /// <summary>--recover: for when every passkey is lost. The recovery code opens the old store; a new passkey and new keys are made and the secrets carried over.</summary>
    public sealed record Recover : CliCommand;

    /// <summary>--rotate-key: an admin makes a new store key and master key, keeps only the tapped key and gets a new recovery code.</summary>
    public sealed record RotateKey : CliCommand;

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
    public const string SecretNameRule = "A secret name is NAME or folder/NAME (up to 3 folders, 200 characters in all). NAME is UPPER_SNAKE_CASE (letters, digits, underscores) and does not start with DOTENV_; a folder uses letters, digits, _ . - (1 to 64) and is not . or ..";

    private const string Description = """
        Run a program with stored secrets, without showing the values to an agent.

        To run a program: with-secrets [--secrets NAME[,NAME...]] --reason "why" [-f .env] -- PROGRAM [ARGS...]
        A run goes through the host service, which must be running (with-secrets service, in a terminal of its own); it listens on
        127.0.0.1 and [::1] only, port 8765 or WITH_SECRETS_PORT or --service-port N (service: --port N). Without it a run exits 6.
        The user approves the request. Then PROGRAM runs with only those secrets as environment variables, and its output is
        redacted. Write -- before the program. Use --list to see the names.

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
        in contact with its authority or holds the grant under its offline lease. A request the grant does not cover, or one after it ends or is
        revoked, goes through the page as before. A store whose key is released by a passkey tap still asks for that tap at each run. A
        person lists and changes grants in the admin web app (with-secrets admin prints its link).

        Saved approvals do not apply while the secret store is protected by a passkey PRF (the only kind of store): every run
        asks, and the approval page offers only Approve once. The rest of this paragraph applies only to a store without that
        protection (none exists today).

        On the approval page the user picks Approve once, or Approve for a time (10 minutes, 1 hour, 4 hours or 8 hours, up
        to the reuseMaxMinutes setting: default 480, 10 to 1440; reuseMinutes is the time the list starts on). A time-limited
        approval covers the same secrets, program, script, and folder, whatever the other arguments, until it ends: the same
        request then runs without asking. The chosen time is signed with the passkey, and a saved approval is used only
        while that signature verifies; one that does not is ignored (stderr says so) and the user is asked again.

        A project declares what it needs in a .env file in the working directory (not searched upward); -f/--env-file PATH
        (repeatable) reads those files instead, and a missing -f file is an error. Lines are NAME=value, with # comments,
        optional export, and single, double or no quotes. A value TOKEN=secret://NAME (or secret://folder/NAME; the whole
        path is the store name) gives the program the secret under the variable TOKEN. Other values are ordinary variables
        (names only on the approval page). --secrets and --reason work as before: --secrets is optional when the .env has
        references, --reason is always required. The first file wins per name; an existing environment variable beats an
        ordinary .env value, but a secret:// reference beats it. The approval page shows every "VARIABLE <- secret NAME" and
        the .env paths, and the files are read once. Code-loading variables (NODE_OPTIONS...) are dropped from .env values
        and a reference to one, or to PATH, is refused. Dotenvx encrypted values and ${} expansion are not supported yet.
        --needs [-f PATH]... prints what the current project would ask for (names only) and whether each secret is in the store.

        Machines. Every host service has a machine identity (an ECDSA P-256 key that Windows keeps and nobody can read out; its
        fingerprint is the SHA-256 of the public key). The first time the service runs on a machine, the machine is Pending: it
        cannot get secrets until an administrator approves it. All administration is in the authority's admin web app, not in commands:
        with-secrets admin (no words) prints its link (http://localhost:8765/admin) and the service's status. Sign in there with one passkey tap
        (a read-only session of 15 minutes idle, 8 hours at most); every change (approve, disable, enable, untrust, trust, rename or approve a host
        name change of a machine; extend, renew or revoke a grant; passkeys; settings; the authority key; lock and unlock) is its own fresh
        passkey tap on a one-use page that names that change. Add --service-port N when the service is not on the default port.

        Audit trail. The host service signs an audit event with the machine key for every run (the authorization decision, the launch
        outcome and the execution outcome are separate events, numbered per machine) and commits the authorization event to its own
        outbox BEFORE a secret is decrypted: if that cannot be done the run does not happen (exit 5). It sends the events to the authority
        by itself and keeps them until the authority has them. A person reads what the authority holds in the admin web app (Audit: filter by machine,
        time, type, outcome, grant, folder or text; the sequence gaps of a machine's numbering). Arguments are recorded
        with values that look like secrets masked; no secret value, environment value or user name is recorded. (--audit is the older
        log of the human commands in state.db.)

        A person changes the settings with --config: the terminal shows only a link, the page shows every setting, and a
        passkey approves the change. With nothing enrolled, --config is the first-time setup: it also creates the first
        passkey, stored only after the person types the code from the page in the terminal. --config --show prints the
        settings.

        First-time --config also shows a recovery code on its last page, once. Write it down and keep it offline: anyone with the
        code and state.db can open all secrets. If every passkey is lost, --recover asks for the code on a web page, makes a new
        passkey and new keys, and carries the secrets over; the old file is renamed (state.db.recovered-<time>), never deleted.
        --rotate-key (admin) makes a new secret store key and master key and encrypts every secret again; only the key you tap
        stays (enroll the others again with --enroll) and a new recovery code is shown. It does not recall values already seen:
        change those secrets at their source.

        A person adds a passkey with --enroll (its name, and whether it is also an admin, are chosen on the page), sees
        them with --enrolled, and removes one with --unenroll NAME (any key but the last admin key). Admin keys change the
        state; two admin keys (laptop and phone) mean a lost device does not lock you out.
        Every page, --enrolled and --audit list the admin keys' fingerprints ("Admins: laptop ab12 cd34 ef56 7890, phone ...").
        Note them down; if they ever change without you, state.db was replaced.
        If baseUrl is set, add --local to use a page at http://localhost instead.

        A person stores secrets with --set NAME[,NAME...] and deletes them with --remove NAME[,NAME...]. Both open a web
        page and need a passkey; the terminal shows only the link and the names. Values are never typed in a terminal.

        --port N (1 to 65535) with --set, --remove, --revoke, --enroll, --unenroll, --config, --recover, --rotate-key or a run makes that call's web page listen
        on port N instead of the port setting (random free port if the setting is 0). It is not saved. If N is in use the call fails.
        Use it to forward the page over ssh: ssh -L N:localhost:N host.

        --debug (with any command, before --) shows diagnostic lines on the terminal (connections, requests, proof sizes and verdicts) and writes them to the log file; WITH_SECRETS_DEBUG=1 does the same for every call. Normally the terminal shows none of them. Warnings and errors always go to the log file, %USERPROFILE%\.with-secrets\logs\with-secrets-YYYYMMDD.log (1 MB per file, 7 files kept). The log holds route words, sizes, seconds and error type names, never a value, a code, a key or a link.

        --audit prints the admin keys' fingerprints, then the newest audit entries (default 20; --last N, 1 to 1000; --secret NAME for one secret): time, event,
        secret names, program, outcome and key name. Never values. --verify also checks the hash chain (exit 4 if broken).
        """;

    /// <summary>Returns the command, or null and an error message when the arguments are wrong.</summary>
    public static CliCommand? Parse(IReadOnlyList<string> args, out string error)
    {
        if (args.Count > 0 && args[0] == "service")
        {
            return ParseService(args, out error);
        }

        if (args.Count > 0 && args[0] == "relay")
        {
            return ParseRelay(args, out error);
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

        if (args.Count > 0 && args[0] == "approve")
        {
            return ParseApprove(args, out error);
        }

        CliCommand? command = ParseCommand(args, out int? port, out bool debug, out error, out int? servicePort);
        if (command is null)
        {
            return null;
        }

        command = command with { Debug = debug, ServicePort = servicePort };
        if (servicePort is not null && command is not CliCommand.Run)
        {
            error = "--service-port goes only with a run or approve.";

            return null;
        }

        if (port is null)
        {
            return command;
        }

        if (command is CliCommand.List or CliCommand.Needs or CliCommand.Enrolled or CliCommand.Audit or CliCommand.Config { Show: true })
        {
            error = "--port goes only with a command that opens a web page: --set, --remove, --revoke, --enroll, --unenroll, --config, --recover, --rotate-key, or a run.";

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
            return new CliCommand.Approve(run.Args) { Port = run.Port, Debug = run.Debug, ServicePort = run.ServicePort };
        }

        if (inner is null && error.Length > 0)
        {
            return null;
        }

        error = "approve takes the arguments of a run: with-secrets approve --secrets NAME[,NAME...] --reason TEXT -- PROGRAM [ARGS...]. It makes a grant for that exact request and runs nothing.";

        return null;
    }

    /// <summary>admin [--service-port N] [--debug]: the admin web app has no verbs; the port is where the service listens.</summary>
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
            else if (args[index] == "--service-port" && index + 1 < args.Count && int.TryParse(args[++index], NumberStyles.None, CultureInfo.InvariantCulture, out int parsed) && parsed is >= 1 and <= ToolSettings.MaxPort)
            {
                port = parsed;
            }
            else
            {
                error = "Usage: with-secrets admin [--service-port N] [--debug]   (opens nothing itself: it prints the link of the authority's admin web app)";

                return null;
            }
        }

        error = "";

        return new CliCommand.AdminApp { ServicePort = port, Debug = debug };
    }

    public const int DefaultRelayPort = 8780;

    private static readonly string RelayUsage = $"Usage: with-secrets relay [--port N] [--bind ADDRESS] [--cert FILE [--cert-password-env NAME]] [--debug]. The relay listens on 127.0.0.1 by default (port {DefaultRelayPort}); any other address needs --cert (TLS: https and wss).";

    /// <summary>relay [--port N] [--bind ADDRESS] [--cert FILE [--cert-password-env NAME]] [--debug].</summary>
    private static CliCommand? ParseRelay(IReadOnlyList<string> args, out string error)
    {
        int port = DefaultRelayPort;
        string bind = "127.0.0.1";
        string? cert = null;
        string? passwordVariable = null;
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
            else if (args[index] == "--bind" && index + 1 < args.Count && System.Net.IPAddress.TryParse(args[++index], out _))
            {
                bind = args[index];
            }
            else if (args[index] == "--cert" && index + 1 < args.Count)
            {
                cert = args[++index];
            }
            else if (args[index] == "--cert-password-env" && index + 1 < args.Count)
            {
                passwordVariable = args[++index];
            }
            else
            {
                error = RelayUsage;

                return null;
            }
        }

        if (cert is null && (!System.Net.IPAddress.IsLoopback(System.Net.IPAddress.Parse(bind)) || passwordVariable is not null))
        {
            error = cert is null && passwordVariable is not null ? "--cert-password-env goes with --cert." : "A relay that listens beyond this machine needs --cert FILE (TLS: https and wss).";

            return null;
        }

        error = "";

        return new CliCommand.Relay(port, bind, cert, passwordVariable) { Debug = debug };
    }

    /// <summary>service [--port N] [--debug]: nothing else.</summary>
    private static CliCommand? ParseService(IReadOnlyList<string> args, out string error)
    {
        int? port = null;
        bool debug = false;
        for (int index = 1; index < args.Count; index++)
        {
            if (args[index] == "--debug")
            {
                debug = true;
            }
            else if (args[index] == "--port" && index + 1 < args.Count)
            {
                if (!int.TryParse(args[++index], NumberStyles.None, CultureInfo.InvariantCulture, out int parsed) || parsed < 1 || parsed > ToolSettings.MaxPort)
                {
                    error = $"--port takes a number from 1 to {ToolSettings.MaxPort}.";

                    return null;
                }

                port = parsed;
            }
            else
            {
                error = "Usage: with-secrets service [--port N]. The service listens on 127.0.0.1 and [::1] only; N is 1 to 65535 (default " + ServiceEndpoint.DefaultPort + ", or WITH_SECRETS_PORT).";

                return null;
            }
        }

        error = "";

        return new CliCommand.Service { ServicePort = port, Debug = debug };
    }

    private static CliCommand? ParseCommand(IReadOnlyList<string> args, out int? portNumber, out bool debugRequested, out string error, out int? servicePortNumber)
    {
        servicePortNumber = null;
        portNumber = null;
        debugRequested = false;
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
        Option<bool> recover = new("--recover") { Description = "When every passkey is lost: type the recovery code on a web page, make a new passkey and new keys, and carry the secrets over. The old file is renamed, never deleted (real terminal)." };
        Option<bool> rotateKey = new("--rotate-key") { Description = "An admin makes a new store key and master key, keeps only the key tapped and shows a new recovery code. Removes the other keys (real terminal)." };
        Option<bool> show = new("--show") { Description = "With --config: print the settings and their values (anywhere)." };
        Option<string?> port = new("--port") { Description = "Where the one-use web page listens for this call, 1 to 65535, in place of the port setting (nothing is saved). If it is in use, the call fails. For ssh -L.", HelpName = "N" };
        Option<string?> servicePort = new("--service-port") { Description = "With a run: the port of the host service on this machine, 1 to 65535. Default: WITH_SECRETS_PORT, then 8765.", HelpName = "N" };
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
        root.Options.Add(recover);
        root.Options.Add(rotateKey);
        root.Options.Add(show);
        root.Options.Add(port);
        root.Options.Add(servicePort);
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
        string? setName = result.GetValue(set);
        string? removeName = result.GetValue(remove);
        bool enrollRequested = result.GetValue(enroll);
        string? unenrollName = result.GetValue(unenroll);
        bool localRequested = result.GetValue(local);
        bool runRequested = names.Length > 0 || reasonText is not null || separator >= 0;
        string[] envFiles = [.. result.GetValue(envFile)!];
        bool needsRequested = result.GetValue(needs);
        if (envFiles.Length > 0 && !needsRequested && !runRequested)
        {
            error = "-f / --env-file goes only with a run or --needs.";

            return null;
        }


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

        if (result.GetValue(port) is { } portText)
        {
            if (!int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out int parsed) || parsed < 1 || parsed > ToolSettings.MaxPort)
            {
                error = $"--port takes a number from 1 to {ToolSettings.MaxPort}.";

                return null;
            }

            portNumber = parsed;
        }

        if (result.GetValue(servicePort) is { } serviceText)
        {
            if (!int.TryParse(serviceText, NumberStyles.None, CultureInfo.InvariantCulture, out int parsedService) || parsedService < 1 || parsedService > ToolSettings.MaxPort)
            {
                error = $"--service-port takes a number from 1 to {ToolSettings.MaxPort}.";

                return null;
            }

            servicePortNumber = parsedService;
        }

        int modes = (auditRequested ? 1 : 0) + (result.GetValue(list) ? 1 : 0) + (needsRequested ? 1 : 0) + (setName is not null ? 1 : 0) + (removeName is not null ? 1 : 0) + (result.GetValue(revoke) ? 1 : 0)
            + (enrollRequested ? 1 : 0) + (result.GetValue(enrolled) ? 1 : 0) + (unenrollName is not null ? 1 : 0) + (configRequested ? 1 : 0) + (result.GetValue(recover) ? 1 : 0) + (result.GetValue(rotateKey) ? 1 : 0) + (runRequested ? 1 : 0);
        if (modes != 1)
        {
            error = modes == 0
                ? "Nothing to do. Use --list, --needs, --audit, --config, --enroll, --enrolled, --unenroll NAME, --recover, --rotate-key, or --reason TEXT [--secrets NAME[,NAME...]] -- PROGRAM [ARGS...]. Try --help."
                : "Use one command at a time: --list, --needs, --set, --remove, --revoke, --enroll, --enrolled, --unenroll, --audit, --config, --recover, --rotate-key, or a run with --secrets.";

            return null;
        }

        if (result.GetValue(recover))
        {
            error = "";

            return new CliCommand.Recover();
        }

        if (result.GetValue(rotateKey))
        {
            error = "";

            return new CliCommand.RotateKey();
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
        if (needsRequested)
        {
            return new CliCommand.Needs(envFiles);
        }

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
        return command is CliCommand.Revoke or CliCommand.Enroll or CliCommand.Enrolled or CliCommand.Unenroll or CliCommand.Config { Show: false } or CliCommand.Recover or CliCommand.RotateKey;
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
            : names.Any(name => !SecretNames.IsValid(name)) ? SecretNameRule
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
            error = "--secret takes one secret name. " + SecretNameRule;

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

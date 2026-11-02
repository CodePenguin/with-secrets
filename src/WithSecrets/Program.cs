using System.Globalization;
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
        StateDatabase state = StateDatabase.InFolder(folder);

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

        // --revoke, --enroll, --enrolled, --unenroll and --config (not --config --show) are for a person in their own terminal,
        // and so is the first --set (it creates the Dotenvx store, and Dotenvx asks where to keep its key).
        if (CliArgs.NeedsTerminal(command, File.Exists(storeFile)) && !HumanCommands.RequireTerminal(CliArgs.NoTerminalMessage(command)))
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
                    Console.Error.WriteLine("with-secrets: cannot read the secret store: " + failure.Message);

                    return RunCommand.StoreError;
                }

            case CliCommand.Set or CliCommand.Remove:
                return HumanCommands.Change(command, store, state);

            case CliCommand.Revoke:
                return HumanCommands.Revoke(state, grants);

            case CliCommand.Enroll or CliCommand.Enrolled or CliCommand.Unenroll:
                return HumanCommands.Passkeys(command, state);

            case CliCommand.Config { Show: true }:
                return ConfigShow.Run(state, Console.Out, Console.Error);

            case CliCommand.Config:
                return HumanCommands.Config(state);
        }

        RunArgs parsed = ((CliCommand.Run)command).Args;
        using Stream stdout = Console.OpenStandardOutput();
        using Stream stderr = Console.OpenStandardError();
        using StreamWriter outWriter = new(stdout, new UTF8Encoding(false)) { AutoFlush = true };
        using StreamWriter errWriter = new(stderr, new UTF8Encoding(false)) { AutoFlush = true };
        ApprovalSettings? settings = HumanCommands.LoadSettings(state);
        if (settings is null)
        {
            return RunCommand.StoreError;
        }

        // The page is served at the first target where an enrolled passkey works. When none works, the primary approver
        // gives its own message (set up the first passkey with --config) and the run is denied.
        (EnrollmentTarget primary, EnrollmentTarget local) = HumanCommands.Targets(state, settings, line => errWriter.WriteLine(line), null);
        WebApprover approver = (EnrollmentTarget.FirstThatCanProve(primary, local) ?? primary).Approver;
        RunCommand run = new(store, approver, new AuditLog(state), outWriter, errWriter, grants, ReuseSettings.Load(state));

        return await run.ExecuteAsync(parsed, Directory.GetCurrentDirectory());
    }
}

/// <summary>
/// Commands for a person. Those that check the terminal (<see cref="CliArgs.NeedsTerminal" />) refuse when input or output is
/// redirected, as in an agent's shell. --set and --remove need a passkey on a web page instead.
/// </summary>
internal static class HumanCommands
{
    /// <summary>
    /// --set and --remove. The values are typed on a web page, never here, so these need no terminal of their own. The
    /// terminal shows only the link and the result, which has names only.
    /// </summary>
    public static int Change(CliCommand command, ISecretStore store, StateDatabase state)
    {
        ApprovalSettings? settings = LoadSettings(state);
        if (settings is null)
        {
            return RunCommand.StoreError;
        }

        Action<string> announce = line => Console.Error.WriteLine(line);
        (EnrollmentTarget primary, EnrollmentTarget local) = Targets(state, settings, announce, null);
        SecretEntry entry = new(primary, local, store, new AuditLog(state), announce);
        SecretChange change = command switch
        {
            CliCommand.Set set => entry.Set(set.Names),
            CliCommand.Remove remove => entry.Remove(remove.Names),
            _ => new SecretChange(RunCommand.Usage, "not a change to the store"),
        };

        Console.Error.WriteLine(change.Done ? change.Detail : "with-secrets: " + change.Detail);

        return change.Code;
    }

    /// <summary>--revoke: the admin passkey approves on a web page, then every saved approval ends.</summary>
    public static int Revoke(StateDatabase state, GrantStore grants)
    {
        ApprovalSettings? settings = LoadSettings(state);
        if (settings is null)
        {
            return RunCommand.StoreError;
        }

        (EnrollmentTarget primary, EnrollmentTarget local) = Targets(state, settings, line => Console.Error.WriteLine(line), null);
        (int code, string detail) = Revocation.Run(state, primary, local, grants);
        Console.Error.WriteLine(code == 0 ? detail : "with-secrets: " + detail);

        return code;
    }

    /// <summary>--enroll, --enrolled and --unenroll. The terminal shows only links and results; never key bytes.</summary>
    public static int Passkeys(CliCommand command, StateDatabase state)
    {
        ApprovalSettings? settings = LoadSettings(state);
        if (settings is null)
        {
            return RunCommand.StoreError;
        }

        // --local makes the local target the place of the change.
        Action<string> announce = line => Console.Error.WriteLine(line);
        (EnrollmentTarget primary, EnrollmentTarget local) = Targets(state, settings, announce, CodeReader("If the page says nothing was added, press Ctrl+C."));
        bool useLocal = command is CliCommand.Enroll { Local: true } or CliCommand.Unenroll { Local: true };
        AuditLog audit = new(state);
        Enrollment enrollment = useLocal ? new(local, primary, announce, audit) : new(primary, local, announce, audit);

        switch (command)
        {
            case CliCommand.Enrolled:
                IReadOnlyList<EnrolledEntry> entries;
                try
                {
                    entries = enrollment.List();
                }
                catch (ProofUnavailableException failure)
                {
                    Console.Error.WriteLine("with-secrets: " + failure.Message);

                    return RunCommand.StoreError;
                }

                // The admin key's fingerprint, then one line per key: name, host, date, and "admin" for the admin key.
                EnrolledListing.Write(state, entries, Console.Out, Console.Error);

                return 0;

            case CliCommand.Enroll enroll:
                return Finish(enrollment.Enroll(enroll.Name ?? Enrollment.DefaultName));

            case CliCommand.Unenroll unenroll:
                return Finish(enrollment.Unenroll(unenroll.Name));

            default:
                return RunCommand.Usage;
        }
    }

    /// <summary>
    /// --config: the terminal shows only the link and the result. Settings that cannot be read are shown on the page as the
    /// defaults, so saving there repairs them; the page targets are then the default ones.
    /// </summary>
    public static int Config(StateDatabase state)
    {
        ToolSettings settings = ToolSettings.Load(state, out _);
        Action<string> announce = line => Console.Error.WriteLine(line);
        Func<string?> readCode = CodeReader("If the page says nothing was saved, press Ctrl+C.");
        (EnrollmentTarget primary, EnrollmentTarget local) = Targets(state, settings.Approval, announce, readCode);
        ConfigChange change = new SettingsPage(state, primary, local, announce, readCode).Run();
        Console.Error.WriteLine(change.Done ? change.Detail : "with-secrets: " + change.Detail);

        return change.Code;
    }

    /// <summary>The approval settings, or null after printing why the settings in state.db cannot be used.</summary>
    public static ApprovalSettings? LoadSettings(StateDatabase state)
    {
        ApprovalSettings settings = ApprovalSettings.Load(state, out string? error);
        if (error is not null)
        {
            Console.Error.WriteLine("with-secrets: settings: " + error + " Fix them with: with-secrets --config");

            return null;
        }

        return settings;
    }

    /// <summary>
    /// Two page targets share one passkey store: the primary one (baseUrl if set) and the local one (baseUrl ignored).
    /// Without a baseUrl they are the same.
    /// </summary>
    public static (EnrollmentTarget Primary, EnrollmentTarget Local) Targets(StateDatabase state, ApprovalSettings settings, Action<string> announce, Func<string?>? readCode)
    {
        PasskeyStore passkeys = new(state);
        EnrollmentTarget Target(ApprovalSettings forPage)
        {
            PasskeyMethod method = new(passkeys, forPage, readCode);

            return EnrollmentTarget.For(method, new WebApprover(method, forPage, announce));
        }

        return (Target(settings), Target(settings with { BaseUrl = null }));
    }

    public static bool RequireTerminal(string message)
    {
        if (Console.IsInputRedirected || Console.IsOutputRedirected || Console.IsErrorRedirected)
        {
            Console.Error.WriteLine(message);

            return false;
        }

        return true;
    }

    /// <summary>
    /// Reads the confirmation code from the page, typed in this terminal. The first prompt says what to do when the page
    /// failed. The code itself is never printed.
    /// </summary>
    private static Func<string?> CodeReader(string firstHint)
    {
        int asked = 0;

        return () =>
        {
            Console.Error.Write(asked++ == 0
                ? firstHint + Environment.NewLine + "Code shown in the browser: "
                : "That code is wrong. Code shown in the browser: ");

            return Console.ReadLine();
        };
    }

    private static int Finish(ApprovalDecision decision)
    {
        if (!decision.Approved)
        {
            Console.Error.WriteLine("with-secrets: " + decision.Detail);

            return RunCommand.Denied;
        }

        Console.Error.WriteLine(decision.Detail);

        return 0;
    }
}

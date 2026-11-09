using System.Text;

namespace WithSecrets;

/// <summary>
/// Shared wiring of the commands for a person (the program and the browser tests use the same one). Those that check the terminal (<see cref="CliArgs.NeedsTerminal" />) refuse when input or output is
/// redirected, as in an agent's shell. --set and --remove need a passkey on a web page instead.
/// </summary>
public static class CommandWiring
{
    /// <summary>
    /// --set and --remove. The values are typed on a web page, never here, so these need no terminal of their own. The
    /// terminal shows only the link and the result, which has names only.
    /// </summary>
    public static int Change(CliCommand command, SecretStore store, StateDatabase state, int? port)
    {
        ApprovalSettings? settings = LoadSettings(state, port);
        if (settings is null)
        {
            return RunCommand.StoreError;
        }

        Action<string> announce = TerminalPrompt.Line;
        (EnrollmentTarget primary, EnrollmentTarget local) = Targets(state, settings, announce, null);
        SecretEntry entry = new(primary, local, store, new AuditLog(state), announce);
        SecretChange change = command switch
        {
            CliCommand.Set set => entry.Set(set.Names),
            CliCommand.Remove remove => entry.Remove(remove.Names),
            _ => new SecretChange(RunCommand.Usage, "not a change to the store"),
        };

        TerminalPrompt.Final(change.Done ? change.Detail : "with-secrets: " + change.Detail);

        return change.Code;
    }

    /// <summary>
    /// admin ACTION: lists the machines, or, for every other action, shows the change on a one-use page and applies it after an admin passkey
    /// approved there. The terminal shows only the link and the result.
    /// </summary>
    public static int Admin(CliCommand.Admin command, StateDatabase state, string folder, int? port, TextWriter? output = null)
    {
        output ??= Console.Out;
        AuthorityStore store = AuthorityStore.InFolder(folder);
        if (command.Action == AdminAction.Machines)
        {
            try
            {
                AdminCommand.List(store, output);

                return 0;
            }
            catch (AuthorityDatabaseException failure)
            {
                TerminalPrompt.Final("with-secrets: " + failure.Message);

                return RunCommand.StoreError;
            }
        }

        ApprovalSettings? settings = LoadSettings(state, port);
        if (settings is null)
        {
            return RunCommand.StoreError;
        }

        if (!OperatingSystem.IsWindows())
        {
            TerminalPrompt.Final("with-secrets: the machine identity needs Windows CNG for now; admin commands cannot run on this system.");

            return RunCommand.StoreError;
        }

        (EnrollmentTarget primary, EnrollmentTarget local) = Targets(state, settings, TerminalPrompt.Line, null);
        AuthorityKeyRing keys = LocalDeployment.ProductionKeyRing(store);
        string? localFingerprint = LocalDeployment.ExistingMachineFingerprint();
        (int code, string detail) = AdminCommand.Run(command, new AdminContext(store, keys, HostConfigFile.InFolder(folder), localFingerprint, primary, local, new AuditLog(state), output));
        TerminalPrompt.Final(code == 0 ? detail : "with-secrets: " + detail);

        return code;
    }

    /// <summary>admin grant ACTION: lists the grants, or shows the change on a one-use page and applies it after an admin passkey approved there.</summary>
    public static int AdminGrants(CliCommand.GrantAdmin command, StateDatabase state, string folder, int? port, TextWriter? output = null)
    {
        output ??= Console.Out;
        AuthorityStore store = AuthorityStore.InFolder(folder);
        if (command.Action == GrantAdminAction.List)
        {
            try
            {
                AdminGrantCommand.List(store, output, DateTimeOffset.UtcNow);

                return 0;
            }
            catch (AuthorityDatabaseException failure)
            {
                TerminalPrompt.Final("with-secrets: " + failure.Message);

                return RunCommand.StoreError;
            }
        }

        ApprovalSettings? settings = LoadSettings(state, port);
        if (settings is null)
        {
            return RunCommand.StoreError;
        }

        if (!OperatingSystem.IsWindows())
        {
            TerminalPrompt.Final("with-secrets: the authority signing key needs Windows CNG for now; admin grant changes cannot run on this system.");

            return RunCommand.StoreError;
        }

        (EnrollmentTarget primary, EnrollmentTarget local) = Targets(state, settings, TerminalPrompt.Line, null);
        (int code, string detail) = AdminGrantCommand.Run(command, new AdminContext(store, LocalDeployment.ProductionKeyRing(store), HostConfigFile.InFolder(folder), null, primary, local, new AuditLog(state), output, null, new ManifestApprovalVerifier(state)));
        TerminalPrompt.Final(code == 0 ? detail : "with-secrets: " + detail);

        return code;
    }

    /// <summary>--revoke: an admin passkey approves on a web page, then every saved approval ends.</summary>
    public static int Revoke(StateDatabase state, GrantStore grants, int? port)
    {
        ApprovalSettings? settings = LoadSettings(state, port);
        if (settings is null)
        {
            return RunCommand.StoreError;
        }

        (EnrollmentTarget primary, EnrollmentTarget local) = Targets(state, settings, TerminalPrompt.Line, null);
        (int code, string detail) = Revocation.Run(state, primary, local, grants);
        TerminalPrompt.Final(code == 0 ? detail : "with-secrets: " + detail);

        return code;
    }

    /// <summary>--enroll, --enrolled and --unenroll. The terminal shows only links and results; never key bytes.</summary>
    public static int Passkeys(CliCommand command, StateDatabase state, int? port, TextWriter? output = null, TextWriter? error = null)
    {
        ApprovalSettings? settings = LoadSettings(state, port);
        if (settings is null)
        {
            return RunCommand.StoreError;
        }

        // --local makes the local target the place of the change.
        Action<string> announce = TerminalPrompt.Line;
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
                    TerminalPrompt.Final("with-secrets: " + failure.Message);

                    return RunCommand.StoreError;
                }

                // The admin keys' fingerprints, then one line per key: name, host, date, and "admin" for each admin key.
                EnrolledListing.Write(state, entries, output ?? Console.Out, error ?? Console.Error);

                return 0;

            case CliCommand.Enroll:
                return Finish(enrollment.Enroll());

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
    public static int Config(StateDatabase state, int? port)
    {
        ToolSettings settings = ToolSettings.Load(state, out _);
        Action<string> announce = TerminalPrompt.Line;
        Func<string?> readCode = CodeReader("If the page says nothing was saved, press Ctrl+C.");
        (EnrollmentTarget primary, EnrollmentTarget local) = Targets(state, settings.Approval.WithPort(port), announce, readCode);
        ConfigChange change = new SettingsPage(state, primary, local, announce, readCode).Run();
        TerminalPrompt.Final(change.Done ? change.Detail : "with-secrets: " + change.Detail);

        return change.Code;
    }

    /// <summary>
    /// --recover: the terminal shows one link (the recovery code page, which leads on to the new passkey) and the result. The
    /// recovery code is typed only into the page. The code that the new setup shows is read back in the terminal like --config.
    /// </summary>
    public static int Recover(StateDatabase state, int? port)
    {
        ToolSettings settings = ToolSettings.Load(state, out _);
        Action<string> announce = TerminalPrompt.Line;
        Func<string?> readCode = CodeReader("If the page says nothing was saved, press Ctrl+C.");
        (EnrollmentTarget primary, EnrollmentTarget local) = Targets(state, settings.Approval.WithPort(port), announce, readCode);
        ConfigChange change = new StoreRecovery(state, primary, local, announce, readCode).Run();
        TerminalPrompt.Final(change.Done ? change.Detail : "with-secrets: " + change.Detail);

        return change.Code;
    }

    /// <summary>--rotate-key: two taps of an admin key on pages the first one leads to; the terminal shows one link and the result, never a key or the recovery code.</summary>
    public static int RotateKey(StateDatabase state, SecretStore store, int? port)
    {
        ApprovalSettings? settings = LoadSettings(state, port);
        if (settings is null)
        {
            return RunCommand.StoreError;
        }

        (EnrollmentTarget primary, EnrollmentTarget local) = Targets(state, settings, TerminalPrompt.Line, null);
        ConfigChange change = new KeyRotation(state, store, primary, local, TerminalPrompt.Line).Run();
        TerminalPrompt.Final(change.Done ? change.Detail : "with-secrets: " + change.Detail);

        return change.Code;
    }

    /// <summary>
    /// The approver of a run: the page is served at the first target where an enrolled passkey works. When none works, the primary
    /// approver gives its own message (set up the first passkey with --config) and the run is denied.
    /// </summary>
    public static IApprover RunApprover(StateDatabase state, ApprovalSettings settings, Action<string> announce)
    {
        (EnrollmentTarget primary, EnrollmentTarget local) = Targets(state, settings, announce, null);

        return (EnrollmentTarget.FirstThatCanProve(primary, local) ?? primary).Approver;
    }

    /// <summary>The approval settings, or null after printing why the settings in state.db cannot be used.</summary>
    public static ApprovalSettings? LoadSettings(StateDatabase state, int? port = null)
    {
        ApprovalSettings settings = ApprovalSettings.Load(state, out string? error);
        if (error is not null)
        {
            TerminalPrompt.Final("with-secrets: settings: " + error + " Fix them with: with-secrets --config");

            return null;
        }

        // --port changes only where this call's page listens; the stored setting is not touched.
        return settings.WithPort(port);
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


    /// <summary>
    /// Reads the confirmation code from the page, typed in this terminal. The first prompt says what to do when the page
    /// failed. The code itself is never printed.
    /// </summary>
    public static Func<string?> CodeReader(string firstHint)
    {
        int asked = 0;

        return () =>
        {
            if (asked == 0)
            {
                TerminalPrompt.Line(firstHint);
            }

            // The prompt is the last thing on the terminal while it waits: in normal mode the command writes nothing else meanwhile.
            return TerminalPrompt.ReadCode(asked++ > 0);
        };
    }

    private static int Finish(ApprovalDecision decision)
    {
        if (!decision.Approved)
        {
            TerminalPrompt.Final("with-secrets: " + decision.Detail);

            return RunCommand.Denied;
        }

        TerminalPrompt.Final(decision.Detail);

        return 0;
    }
}

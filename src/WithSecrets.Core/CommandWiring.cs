using System.Globalization;
using System.Text;

namespace WithSecrets;

/// <summary>
/// Shared wiring of the commands for a person (the program and the browser tests use the same one). Those that check the terminal (<see cref="CliArgs.NeedsTerminal" />) refuse when input or output is
/// redirected, as in an agent's shell. Everything else a person does is in the admin web app.
/// </summary>
public static class CommandWiring
{
    /// <summary>
    /// First-time setup (<c>admin</c> with nothing enrolled): the terminal shows only the link and the result. The page makes the
    /// first passkey and the first state, with the default settings.
    /// </summary>
    public static int Setup(StateDatabase state, int? port, HostService? service = null, Action<string>? output = null, Func<string?>? input = null,
        Action<string>? desktopCode = null, Func<Task>? desktopCancellation = null)
    {
        Action<string> announce = output ?? TerminalPrompt.Line;
        Func<string?> readCode = input ?? CodeReader("Press Ctrl+C to cancel.");
        ApprovalSettings settings = ToolSettings.Defaults.Approval.WithPort(port);
        if (service is { } browser && browser.BrowserOrigin.StartsWith("https://", StringComparison.Ordinal))
        {
            settings = settings with { BaseUrl = browser.BrowserOrigin, Port = browser.Port };
        }

        (EnrollmentTarget primary, EnrollmentTarget local) = Targets(state, settings, announce, readCode);
        ConfigChange change = new FirstRunPage(state, primary, local, announce, readCode)
        {
            Service = service,
            DesktopCode = desktopCode,
            DesktopCancellation = desktopCancellation,
        }.Run();
        announce(change.Done ? change.Detail : "with-secrets: " + change.Detail);

        return change.Code;
    }

    /// <summary>
    /// --recover: the terminal shows one link (the recovery code page, which leads on to the new passkey) and the result. The
    /// recovery code is typed only into the page. The code that the new setup shows is read back in the terminal like the first-time setup.
    /// </summary>
    public static int Recover(StateDatabase state, int? port)
    {
        using BrowserCertificateLease tls = new BrowserCertificates(Path.GetDirectoryName(state.FilePath)!).OpenListener();
        using IDisposable flow = PageFlow.Enter(tls.Certificate);
        return RecoverCore(state, port, https: true);
    }

    internal static int RecoverCore(StateDatabase state, int? port, bool https)
    {
        ApprovalSettings settings = ToolSettings.Load(state, out _).Approval.WithPort(port);
        if (https) settings = settings with { BaseUrl = "https://" + BrowserAddress.Host };

        Action<string> announce = TerminalPrompt.Line;
        Func<string?> readCode = CodeReader("Press Ctrl+C to cancel.");
        (EnrollmentTarget primary, EnrollmentTarget local) = Targets(state, settings, announce, readCode);
        ConfigChange change = new StoreRecovery(state, primary, https ? primary : local, announce, readCode).Run();
        TerminalPrompt.Final(change.Done ? change.Detail : "with-secrets: " + change.Detail);

        return change.Code;
    }

    /// <summary>
    /// The approver of a run: the page is served at the first target where an enrolled passkey works. When none works, the primary
    /// approver gives its own message (set up the first passkey with admin) and the run is denied.
    /// </summary>
    public static IApprover RunApprover(StateDatabase state, ApprovalSettings settings, Action<string> announce)
    {
        (EnrollmentTarget primary, EnrollmentTarget local) = Targets(state, settings, announce, null);

        return (EnrollmentTarget.FirstThatCanProve(primary, local) ?? primary).Approver;
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

}

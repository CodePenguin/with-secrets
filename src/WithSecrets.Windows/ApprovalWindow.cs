namespace WithSecrets;

/// <summary>
/// Shows the whole request in a window the person can scroll: secrets, full command, folder, links, and the agent's reason.
/// Deny is the default, Approve waits two seconds, and closing the window denies. This window shows the request; it does not
/// prove a person is there, because a program in the same session could click it. Chain it with a second approver.
/// </summary>
public sealed class ApprovalWindow : IApprover
{
    private static readonly object VisualStyleGate = new();
    private static bool _visualStylesReady;

    private readonly TimeSpan _timeout;
    private readonly TimeSpan _approveDelay;

    public ApprovalWindow(TimeSpan? timeout = null)
        : this(timeout, TimeSpan.FromSeconds(2))
    {
    }

    internal ApprovalWindow(TimeSpan? timeout, TimeSpan approveDelay)
    {
        _timeout = timeout ?? TimeSpan.FromMinutes(5);
        _approveDelay = approveDelay;
    }

    public ApprovalDecision Request(ApprovalRequest request)
    {
        return Show(ApprovalSummary.BuildMessage(request), null);
    }

    /// <summary>Shows the window on its own thread (a window needs a single-threaded apartment). The hook lets a test act on the window.</summary>
    internal ApprovalDecision Show(string text, Action<ApprovalForm>? whenShown)
    {
        DialogResult result = DialogResult.None;
        Exception? failure = null;

        Thread thread = new(() =>
        {
            try
            {
                PrepareVisualStyles();
                using ApprovalForm form = new(text, _approveDelay, _timeout);
                if (whenShown is not null)
                {
                    form.Shown += (_, _) => whenShown(form);
                }

                result = form.ShowDialog();
            }
            catch (Exception error)
            {
                failure = error;
            }
        })
        {
            IsBackground = true
        };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();

        if (failure is not null)
        {
            return ApprovalDecision.Deny("approval window failed: " + failure.Message);
        }

        return result switch
        {
            DialogResult.OK => ApprovalDecision.Allow("approved in the window"),
            DialogResult.Abort => ApprovalDecision.Deny("no answer before the time limit"),
            _ => ApprovalDecision.Deny("denied in the window")
        };
    }

    private static void PrepareVisualStyles()
    {
        lock (VisualStyleGate)
        {
            if (_visualStylesReady)
            {
                return;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            _visualStylesReady = true;
        }
    }
}

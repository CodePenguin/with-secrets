using System.Drawing;

namespace WithSecrets;

/// <summary>
/// The approval window: the whole request in a box the person can scroll. Deny is the default button, and Enter and Escape
/// both deny. Approve is disabled at first, so a key press or click that was meant for another window cannot approve. Closing
/// the window denies. When the time limit passes, the window closes and the answer is "no answer".
/// </summary>
internal sealed class ApprovalForm : Form
{
    private readonly System.Windows.Forms.Timer _enableTimer = new();
    private readonly System.Windows.Forms.Timer _limitTimer = new();

    public ApprovalForm(string text, TimeSpan approveDelay, TimeSpan timeLimit)
    {
        Text = "with-secrets: approval request";
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(820, 520);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MinimizeBox = false;
        MaximizeBox = false;
        TopMost = true;
        ShowInTaskbar = true;

        Label heading = new()
        {
            Text = "An agent wants to run a program with these secrets. Read all of it before you approve.",
            AutoSize = false,
            Location = new Point(12, 10),
            Size = new Size(796, 36),
            Font = new Font("Segoe UI", 10, FontStyle.Bold)
        };

        DetailBox = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            WordWrap = true,
            Font = new Font("Consolas", 10),
            Location = new Point(12, 50),
            Size = new Size(796, 410),
            Text = text.ReplaceLineEndings("\r\n")
        };

        DenyButton = new Button { Text = "Deny", Location = new Point(708, 475), Size = new Size(100, 32), DialogResult = DialogResult.Cancel };
        ApproveButton = new Button
        {
            Text = "Approve (wait...)",
            Enabled = approveDelay <= TimeSpan.Zero,
            Location = new Point(560, 475),
            Size = new Size(140, 32),
            DialogResult = DialogResult.OK
        };

        AcceptButton = DenyButton;
        CancelButton = DenyButton;
        Controls.AddRange([heading, DetailBox, ApproveButton, DenyButton]);

        _enableTimer.Interval = (int)Math.Max(1, approveDelay.TotalMilliseconds);
        _enableTimer.Tick += (_, _) =>
        {
            _enableTimer.Stop();
            ApproveButton.Enabled = true;
            ApproveButton.Text = "Approve";
        };

        _limitTimer.Interval = (int)Math.Clamp(timeLimit.TotalMilliseconds, 1, int.MaxValue);
        _limitTimer.Tick += (_, _) =>
        {
            _limitTimer.Stop();
            DialogResult = DialogResult.Abort;
        };

        Shown += (_, _) =>
        {
            Activate();
            DenyButton.Focus();
            DetailBox.SelectionStart = 0;
            DetailBox.SelectionLength = 0;
            if (approveDelay > TimeSpan.Zero)
            {
                _enableTimer.Start();
            }

            _limitTimer.Start();
        };
    }

    public TextBox DetailBox { get; }

    public Button ApproveButton { get; }

    public Button DenyButton { get; }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _enableTimer.Dispose();
            _limitTimer.Dispose();
        }

        base.Dispose(disposing);
    }
}

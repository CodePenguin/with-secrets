using System.Runtime.InteropServices;

using Windows.Foundation;
using Windows.Security.Credentials.UI;

using WinRT;

namespace WithSecrets;

/// <summary>
/// Asks through the Windows Hello consent prompt (face, fingerprint or PIN). Windows draws that prompt, so the agent cannot
/// click it. The request text is the message of the prompt. Any problem means deny.
/// </summary>
/// <remarks>
/// A console program has no window, and a Hello prompt with no owner can open behind other windows. So the prompt is requested
/// for a small owner window that this class shows in front (IUserConsentVerifierInterop.RequestVerificationForWindowAsync).
/// </remarks>
public sealed class WindowsHelloApprover : IApprover
{
    private const string ClassName = "Windows.Security.Credentials.UI.UserConsentVerifier";

    // IUserConsentVerifierInterop: IInspectable (slots 0-5), then RequestVerificationForWindowAsync (slot 6).
    private static readonly Guid InteropIid = new("39E050C3-4E74-441A-8DC0-B81104DF949C");

    private readonly TimeSpan _timeout;
    private readonly Func<ApprovalRequest, string> _message;

    public WindowsHelloApprover(TimeSpan? timeout = null, Func<ApprovalRequest, string>? message = null)
    {
        _timeout = timeout ?? TimeSpan.FromMinutes(2);
        _message = message ?? ApprovalSummary.BuildMessage;
    }

    public ApprovalDecision Request(ApprovalRequest request)
    {
        string text = _message(request);
        UserConsentVerificationResult? outcome = null;
        string? failure = null;

        Thread thread = new(() =>
        {
            try
            {
                UserConsentVerifierAvailability availability = UserConsentVerifier.CheckAvailabilityAsync().AsTask().GetAwaiter().GetResult();
                if (availability != UserConsentVerifierAvailability.Available)
                {
                    failure = $"Windows Hello is not available ({availability})";

                    return;
                }

                (outcome, failure) = AskWithOwnerWindow(text, _timeout);
            }
            catch (Exception error)
            {
                failure = error.Message;
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
            return ApprovalDecision.Deny("Windows Hello failed: " + failure);
        }

        return outcome == UserConsentVerificationResult.Verified
            ? ApprovalDecision.Allow("Windows Hello verified")
            : ApprovalDecision.Deny(outcome?.ToString() ?? "no result");
    }

    /// <summary>Shows a small owner window in front, runs the prompt for it, and closes the window when the prompt ends.</summary>
    private static (UserConsentVerificationResult? Outcome, string? Failure) AskWithOwnerWindow(string text, TimeSpan timeout)
    {
        UserConsentVerificationResult? outcome = null;
        string? failure = null;
        IAsyncOperation<UserConsentVerificationResult>? pending = null;

        using Form owner = new()
        {
            FormBorderStyle = FormBorderStyle.None,
            ShowInTaskbar = false,
            StartPosition = FormStartPosition.CenterScreen,
            Size = new System.Drawing.Size(1, 1),
            TopMost = true
        };
        using System.Windows.Forms.Timer limit = new() { Interval = (int)Math.Clamp(timeout.TotalMilliseconds, 1, int.MaxValue) };
        limit.Tick += (_, _) =>
        {
            limit.Stop();
            pending?.Cancel();
        };

        owner.Shown += async (_, _) =>
        {
            try
            {
                owner.Activate();
                pending = RequestForWindow(owner.Handle, text);
                limit.Start();
                outcome = await pending;
            }
            catch (Exception error)
            {
                failure = error.Message;
            }
            finally
            {
                owner.Close();
            }
        };

        Application.Run(owner);

        return (outcome, failure);
    }

    private static unsafe IAsyncOperation<UserConsentVerificationResult> RequestForWindow(nint window, string text)
    {
        nint className = 0;
        nint message = 0;
        nint factory = 0;
        nint operation = 0;
        try
        {
            Check(WindowsCreateString(ClassName, ClassName.Length, out className));
            Guid interopIid = InteropIid;
            Check(RoGetActivationFactory(className, ref interopIid, out factory));
            Check(WindowsCreateString(text, text.Length, out message));

            Guid operationIid = GuidGenerator.GetIID(typeof(IAsyncOperation<UserConsentVerificationResult>));
            nint* table = *(nint**)factory;
            var requestForWindow = (delegate* unmanaged[Stdcall]<nint, nint, nint, Guid*, nint*, int>)table[6];
            Check(requestForWindow(factory, window, message, &operationIid, &operation));

            return MarshalInterface<IAsyncOperation<UserConsentVerificationResult>>.FromAbi(operation);
        }
        finally
        {
            if (operation != 0)
            {
                Marshal.Release(operation);
            }

            if (factory != 0)
            {
                Marshal.Release(factory);
            }

            if (message != 0)
            {
                WindowsDeleteString(message);
            }

            if (className != 0)
            {
                WindowsDeleteString(className);
            }
        }
    }

    private static void Check(int hresult)
    {
        if (hresult < 0)
        {
            Marshal.ThrowExceptionForHR(hresult);
        }
    }

    [DllImport("combase.dll", ExactSpelling = true)]
    private static extern int WindowsCreateString([MarshalAs(UnmanagedType.LPWStr)] string source, int length, out nint hstring);

    [DllImport("combase.dll", ExactSpelling = true)]
    private static extern int WindowsDeleteString(nint hstring);

    [DllImport("combase.dll", ExactSpelling = true)]
    private static extern int RoGetActivationFactory(nint classId, ref Guid iid, out nint factory);
}

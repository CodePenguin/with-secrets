namespace WithSecrets;

/// <summary>
/// Runs two approvers in order. The second is asked only when the first approves, and both must approve. The first shows the
/// request (a window with the whole command); the second proves that a person is present (Windows Hello today, a security key
/// later). A window alone is not enough: a program in the same session could click it.
/// </summary>
public sealed class ApproverChain(IApprover first, IApprover second) : IApprover
{
    public ApprovalDecision Request(ApprovalRequest request)
    {
        ApprovalDecision shown;
        try
        {
            shown = first.Request(request);
        }
        catch (Exception error)
        {
            return ApprovalDecision.Deny("approval window failed: " + error.Message);
        }

        if (!shown.Approved)
        {
            return shown;
        }

        try
        {
            ApprovalDecision confirmed = second.Request(request);

            return confirmed.Approved ? ApprovalDecision.Allow($"{shown.Detail}; {confirmed.Detail}") : confirmed;
        }
        catch (Exception error)
        {
            return ApprovalDecision.Deny("confirmation failed: " + error.Message);
        }
    }
}

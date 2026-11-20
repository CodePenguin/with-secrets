using System.Security.Cryptography;
using System.Text;

namespace WithSecrets;

/// <summary>
/// Asks about a command run on this machine in the authority's approval queue, so that it is decided in the administration web app
/// exactly like a request from a paired machine (same review, same passkey, same fresh challenge). The command line only announces
/// the address of the request. Fails closed: anything but an approval from the queue is a denial.
/// </summary>
internal sealed class QueueApprover(ApprovalQueue queue, ApprovalMachineView machine, string adminUrl, TimeProvider clock, Action<string> announce) : IApprover
{
    public bool OffersTime => true;

    public ApprovalDecision Request(ApprovalRequest request) => Request(request, CancellationToken.None);

    public ApprovalDecision Request(ApprovalRequest request, CancellationToken cancel)
    {
        DateTimeOffset now = clock.GetUtcNow();
        string id = "run-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant();
        string digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(ApprovalSummary.BuildMessage(request)))).ToLowerInvariant();
        ApprovalReviewProjection review = ApprovalQueue.BuildReview(id, digest, now, now.AddMinutes(ApprovalSettings.MaxTimeoutMinutes), machine, request);
        ApprovalDecision decision;
        switch (queue.Register(review, out _))
        {
            case ApprovalQueueRegistration.Created:
                announce(WebApprover.LinkPrefix + adminUrl + "/access/" + Uri.EscapeDataString(id));
                decision = queue.Wait(id, cancel);
                break;
            case ApprovalQueueRegistration.Full:
                return ApprovalDecision.Deny("the approval queue is full", reasonCode: ReasonCodes.ApprovalQueueFull);
            default:
                return ApprovalDecision.Deny("this request could not be queued");
        }

        queue.MarkDecided(id, decision);

        return decision;
    }
}

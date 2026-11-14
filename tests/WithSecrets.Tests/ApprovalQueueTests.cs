using System.Text.Json;

namespace WithSecrets.Tests;

/// <summary>Approvals queue invariants: bounded pagination, proof binding, one-winner decisions and commit reconciliation.</summary>
internal static class ApprovalQueueTests
{
    private sealed class FakeProofMethod : IProofMethod
    {
        public byte[]? StartedBind { get; private set; }
        public byte[]? VerifiedBind { get; private set; }

        public string Id => "fake-passkey";

        public ProofStart Start(ProofContext context)
        {
            StartedBind = [.. context.Bind];
            return new ProofStart("webauthn", JsonSerializer.Serialize(new
            {
                bind = Base64Url.EncodeToString(context.Bind),
                rpId = "localhost",
                timeout = 120_000,
                salt = (string?)null,
            }));
        }

        public ProofResult Verify(ProofContext context, string response)
        {
            VerifiedBind = [.. context.Bind];
            return response == "\"valid\""
                ? new ProofResult(true, "passkey approver verified", new VerifiedCredential("approver", false))
                : new ProofResult(false, "invalid proof");
        }

        public IReadOnlyList<EnrolledEntry> Enrolled() => [];
        public bool CanProve(string rpId) => rpId == "localhost";
        public ApprovalDecision Enroll(string name, Action<string> announce, Func<string, ManifestApproval>? askAdmin = null, Unlock? approval = null)
            => ApprovalDecision.Deny("not supported");
        public ApprovalDecision Unenroll(string name, Func<string, ManifestApproval> askAdmin)
            => ApprovalDecision.Deny("not supported");
    }

    public static void Run(Action<bool, string> check)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        MachineRecord machine = new("machine-fingerprint", [], "devbox", "Developer machine", MachineStatus.Trusted, 0, null, now, now);
        ApprovalRequest page = new("dotnet", "/usr/bin/dotnet", ["test"], "/work", "run the test suite", ["DB_URL"]);
        string digest = new('a', 64);

        ApprovalReviewProjection Review(string id, DateTimeOffset submitted)
            => ApprovalQueue.BuildReview(id, digest, submitted, submitted.AddMinutes(10), machine, page);

        // Queue capacity is authority-wide, duplicates do not consume another slot, and a full queue never evicts.
        ApprovalQueue bounded = new(TimeProvider.System, () => TimeSpan.FromMinutes(5));
        for (int i = 0; i < ApprovalQueue.MaxPending; i++)
        {
            check(bounded.TryRegister(Review($"req-{i:D2}", now.AddSeconds(i)), out _), $"approvals: register pending request {i}");
        }

        check(bounded.TryRegister(Review("req-00", now), out _), "approvals: duplicate request reuses its existing registration at capacity");
        check(!bounded.TryRegister(Review("req-overflow", now.AddMinutes(1)), out _), "approvals: 65th request is refused");
        check(bounded.PendingCount == ApprovalQueue.MaxPending, "approvals: full queue retains all existing requests");

        IReadOnlyList<ApprovalQueueItemDto> first = bounded.ListPending(50, null, out string? cursor);
        IReadOnlyList<ApprovalQueueItemDto> second = bounded.ListPending(50, cursor, out string? end);
        check(first.Count == 50 && second.Count == 14 && end is null, "approvals: cursor pages all 64 pending requests exactly once");
        check(cursor is not null && ApprovalQueue.IsCursorValid(cursor), "approvals: emitted cursor is valid");
        check(first.Select(item => item.RequestId).Intersect(second.Select(item => item.RequestId), StringComparer.Ordinal).Any() == false,
            "approvals: pages do not overlap");

        // A challenge is bound to the unique launch ID, digest and canonical review; its WebAuthn assertion uses reuse=0.
        ApprovalQueue queue = new(TimeProvider.System, () => TimeSpan.FromMinutes(5));
        check(queue.TryRegister(Review("req-proof", now), out _), "approvals: register proof request");
        FakeProofMethod proof = new();
        (ApprovalChallengeDto? challenge, string? challengeCode, _) = queue.CreateOrReuseChallenge("req-proof", "session-one", "http://localhost", proof);
        check(challenge is not null && challengeCode is null && challenge.PrfKey is null, "approvals: create WebAuthn challenge without an unnecessary PRF release");
        (ApprovalChallengeDto? reused, _, _) = queue.CreateOrReuseChallenge("req-proof", "session-one", "http://localhost", proof);
        check(reused?.FlowId == challenge?.FlowId, "approvals: same session reuses its live challenge");
        (ApprovalChallengeDto? other, string? otherCode, _) = queue.CreateOrReuseChallenge("req-proof", "session-two", "http://localhost", proof);
        check(other is null && otherCode == "approval-in-progress", "approvals: another session cannot replace an active challenge");

        (ApprovalDetailDto? pending, string? approveCode, _) = queue.Approve("req-proof", "session-one", challenge!.FlowId, "\"valid\"", proof, _ => null);
        check(pending is not null && pending.Status == ApprovalStatuses.Pending && pending.DecisionInProgress && approveCode is null,
            "approvals: API reports pending until the authority commits");
        ApprovalDecision decision = queue.Wait("req-proof", CancellationToken.None);
        check(decision.Approved && decision.Credential is { Name: "approver", Admin: false },
            "approvals: verified credential identity is preserved for authority audit");
        check(proof.StartedBind is not null && proof.VerifiedBind is not null
            && proof.VerifiedBind.SequenceEqual(ReuseBinding.Challenge(proof.StartedBind, 0)),
            "approvals: WebAuthn assertion is bound to the fixed approve-once operation");
        AuthorityResponse committed = new(1, "req-proof", digest, machine.Fingerprint, AuthorityDecision.Approved, ReasonCodes.Approved,
            0, now.AddSeconds(1), now.AddMinutes(1), "authority-key", []);
        queue.MarkCommitted("req-proof", committed);
        check(queue.GetDetail("req-proof", _ => null)?.Status == ApprovalStatuses.Approved,
            "approvals: terminal state appears only after authority commit");

        // Denial does not need a proof flow, but still waits for the authority's durable result.
        ApprovalQueue deniedQueue = new(TimeProvider.System, () => TimeSpan.FromMinutes(5));
        check(deniedQueue.TryRegister(Review("req-deny", now), out _), "approvals: register denial request");
        (ApprovalDetailDto? denying, string? denyCode, _) = deniedQueue.Deny("req-deny", "session-identity", _ => null);
        check(denying is { DecisionInProgress: true, Status: ApprovalStatuses.Pending } && denyCode is null,
            "approvals: denial is accepted without WebAuthn but remains in progress until commit");
        ApprovalDecision denied = deniedQueue.Wait("req-deny", CancellationToken.None);
        check(!denied.Approved && denied.Actor == "session-identity", "approvals: denial actor is the server-side session identity");
        AuthorityResponse denialCommitted = new(1, "req-deny", digest, machine.Fingerprint, AuthorityDecision.Denied, ReasonCodes.UserDenied,
            0, now.AddSeconds(1), now.AddMinutes(1), "authority-key", []);
        deniedQueue.MarkCommitted("req-deny", denialCommitted);
        check(deniedQueue.GetDetail("req-deny", _ => null)?.Status == ApprovalStatuses.Denied,
            "approvals: denial becomes terminal only after authority commit");

        check(SessionCapabilities.For(SessionScope.Approval).SequenceEqual([SessionCapabilities.ApprovalsRead, SessionCapabilities.ApprovalsDecide]),
            "sessions: approval scope receives only Approvals capabilities");
        check(SessionCapabilities.For(SessionScope.Admin).Contains(SessionCapabilities.AdminDecide)
            && SessionCapabilities.For(SessionScope.Admin).Contains(SessionCapabilities.ApprovalsDecide),
            "sessions: admin scope retains admin and Approvals capabilities");
    }
}

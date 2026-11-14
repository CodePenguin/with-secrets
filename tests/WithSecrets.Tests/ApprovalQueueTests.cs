using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WithSecrets.Tests;

/// <summary>Approvals queue invariants: bounded pagination, proof binding, one-winner decisions and commit reconciliation.</summary>
internal static class ApprovalQueueTests
{
    private sealed class ManualTimeProvider(DateTimeOffset start) : TimeProvider
    {
        private readonly List<ManualTimer> _timers = [];
        private DateTimeOffset _now = start;

        public override DateTimeOffset GetUtcNow() => _now;

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            ManualTimer timer = new(this, callback, state);
            timer.Change(dueTime, period);
            _timers.Add(timer);
            return timer;
        }

        public void Advance(TimeSpan amount)
        {
            _now += amount;
            while (true)
            {
                ManualTimer? next = _timers.Where(timer => timer.IsDue(_now)).OrderBy(timer => timer.Due).FirstOrDefault();
                if (next is null) return;
                next.Fire();
            }
        }

        private sealed class ManualTimer(ManualTimeProvider owner, TimerCallback callback, object? state) : ITimer
        {
            private DateTimeOffset? _due;
            private TimeSpan _period;
            private bool _disposed;

            public DateTimeOffset Due => _due ?? DateTimeOffset.MaxValue;
            public bool IsDue(DateTimeOffset now) => !_disposed && _due is { } due && due <= now;

            public bool Change(TimeSpan dueTime, TimeSpan period)
            {
                if (_disposed) return false;
                _period = period;
                _due = dueTime == Timeout.InfiniteTimeSpan ? null : owner._now + (dueTime < TimeSpan.Zero ? TimeSpan.Zero : dueTime);
                return true;
            }

            public void Fire()
            {
                if (_disposed || _due is null) return;
                _due = _period == Timeout.InfiniteTimeSpan ? null : owner._now + _period;
                callback(state);
            }

            public void Dispose()
            {
                _disposed = true;
                _due = null;
            }

            public ValueTask DisposeAsync()
            {
                Dispose();
                return ValueTask.CompletedTask;
            }
        }
    }

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

    private static void PrfRoundTrip(Action<bool, string> check)
    {
        (byte[] serverState, string serverPublic) = SecretCrypto.NewServerKey();
        byte[] bind = RandomNumberGenerator.GetBytes(32);
        byte[] plaintext = RandomNumberGenerator.GetBytes(32);
        byte[]? secret = null;
        byte[]? key = null;
        byte[]? opened = null;
        try
        {
            byte[] serverPoint = Base64Url.DecodeFromChars(serverPublic);
            using ECDiffieHellman serverPublicKey = ECDiffieHellman.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = serverPoint[1..33], Y = serverPoint[33..65] },
            });
            using ECDiffieHellman browser = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            ECParameters browserPublic = browser.ExportParameters(false);
            byte[] browserPoint = [0x04, .. browserPublic.Q.X!, .. browserPublic.Q.Y!];
            secret = browser.DeriveRawSecretAgreement(serverPublicKey.PublicKey);
            key = HKDF.DeriveKey(HashAlgorithmName.SHA256, secret, 32, bind, Encoding.UTF8.GetBytes(SecretCrypto.PrfInfo));
            byte[] iv = RandomNumberGenerator.GetBytes(12);
            byte[] sealedBytes = new byte[plaintext.Length + 16];
            using (AesGcm aes = new(key, 16))
            {
                aes.Encrypt(iv, plaintext, sealedBytes.AsSpan(0, plaintext.Length), sealedBytes.AsSpan(plaintext.Length), bind);
            }

            opened = SecretCrypto.DecryptBytes(serverState, bind, Base64Url.EncodeToString(browserPoint),
                Base64Url.EncodeToString(iv), Base64Url.EncodeToString(sealedBytes), SecretCrypto.PrfInfo);
            check(opened.SequenceEqual(plaintext), "approvals: authority opens the browser-sealed PRF output with the same request binding");
            bool wrongBindingRejected = false;
            try
            {
                byte[] wrongBind = [.. bind];
                wrongBind[0] ^= 0x01;
                byte[] unexpected = SecretCrypto.DecryptBytes(serverState, wrongBind, Base64Url.EncodeToString(browserPoint),
                    Base64Url.EncodeToString(iv), Base64Url.EncodeToString(sealedBytes), SecretCrypto.PrfInfo);
                CryptographicOperations.ZeroMemory(unexpected);
            }
            catch (CryptographicException)
            {
                wrongBindingRejected = true;
            }

            check(wrongBindingRejected, "approvals: PRF ciphertext cannot be opened under a different canonical request binding");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(serverState);
            CryptographicOperations.ZeroMemory(bind);
            CryptographicOperations.ZeroMemory(plaintext);
            if (secret is not null) CryptographicOperations.ZeroMemory(secret);
            if (key is not null) CryptographicOperations.ZeroMemory(key);
            if (opened is not null) CryptographicOperations.ZeroMemory(opened);
        }
    }

    public static void Run(Action<bool, string> check)
    {
        PrfRoundTrip(check);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        MachineRecord machine = new("machine-fingerprint", [], "devbox", "Developer machine", MachineStatus.Trusted, 0, null, now, now);
        ApprovalRequest page = new("dotnet", "/usr/bin/dotnet", ["test"], "/work", "run the test suite", ["DB_URL"]);
        string digest = new('a', 64);

        ApprovalReviewProjection Review(string id, DateTimeOffset submitted)
            => ApprovalQueue.BuildReview(id, digest, submitted, submitted.AddMinutes(10), machine, page);

        // Queue capacity is authority-wide, duplicates do not consume another slot, and a full queue never evicts.
        using ApprovalQueue bounded = new(TimeProvider.System, () => TimeSpan.FromMinutes(5));
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

        // A challenge is bound to the unique launch ID, digest, machine identity and canonical review; its WebAuthn assertion uses reuse=0.
        ApprovalReviewProjection proofReview = Review("req-proof", now);
        check(proofReview.RequestId == "req-proof" && proofReview.FingerprintKey == page.RequestId
            && proofReview.CanonicalText.Contains(machine.Fingerprint, StringComparison.Ordinal),
            "approvals: route identity is the unique launch request ID, distinct from the content fingerprint, and the canonical review binds the machine");
        using ApprovalQueue queue = new(TimeProvider.System, () => TimeSpan.FromMinutes(5));
        check(queue.TryRegister(Review("req-proof", now), out _), "approvals: register proof request");
        check(queue.Register(Review("req-proof", now), out _) == ApprovalQueueRegistration.ExistingPending,
            "approvals: a duplicate in-flight request cannot acquire ownership of the queue entry");
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
        check(queue.GetDetail("req-proof", _ => null)?.Status == ApprovalStatuses.Approved
            && queue.Register(Review("req-proof", now), out _) == ApprovalQueueRegistration.ExistingTerminal,
            "approvals: terminal state appears only after authority commit and duplicate retries do not reopen it");

        using ApprovalQueue raceQueue = new(TimeProvider.System, () => TimeSpan.FromMinutes(5));
        check(raceQueue.TryRegister(Review("req-race", now), out _), "approvals: register a request for the approve/deny race");
        FakeProofMethod raceProof = new();
        (ApprovalChallengeDto? raceChallenge, _, _) = raceQueue.CreateOrReuseChallenge("req-race", "race-session", "http://localhost", raceProof);
        using ManualResetEventSlim raceStart = new(false);
        Task<(ApprovalDetailDto? Detail, string? ProblemCode, string? DetailText)> approveRace = Task.Run(() =>
        {
            raceStart.Wait();
            return raceQueue.Approve("req-race", "race-session", raceChallenge!.FlowId, "\"valid\"", raceProof, _ => null);
        });
        Task<(ApprovalDetailDto? Detail, string? ProblemCode, string? DetailText)> denyRace = Task.Run(() =>
        {
            raceStart.Wait();
            return raceQueue.Deny("req-race", "race-session", _ => null);
        });
        raceStart.Set();
        Task.WaitAll(approveRace, denyRace);
        bool approveWon = approveRace.Result.ProblemCode is null;
        bool denyWon = denyRace.Result.ProblemCode is null;
        ApprovalDecision raceDecision = raceQueue.Wait("req-race", CancellationToken.None);
        check(approveWon != denyWon && raceDecision.Approved == approveWon
            && raceDecision.DecisionPrincipal?.Kind == (approveWon ? "passkey" : "session"),
            "approvals: concurrent approve and deny produce exactly one server-attributed winner");

        // Request expiry and terminal-review retention use the injected clock and are deterministic.
        ManualTimeProvider manualClock = new(now);
        using ApprovalQueue expiringQueue = new(manualClock, () => TimeSpan.FromMinutes(5));
        check(expiringQueue.TryRegister(Review("req-expire", now), out _), "approvals: register an expiring request");
        manualClock.Advance(TimeSpan.FromMinutes(5) + TimeSpan.FromSeconds(1));
        ApprovalDecision timedOut = expiringQueue.Wait("req-expire", CancellationToken.None);
        check(!timedOut.Approved && timedOut.ReasonCode == ReasonCodes.ApprovalTimeout,
            "approvals: effective approval deadline releases a timeout denial");
        AuthorityResponse timeoutCommitted = new(1, "req-expire", digest, machine.Fingerprint, AuthorityDecision.Denied, ReasonCodes.ApprovalTimeout,
            0, manualClock.GetUtcNow(), manualClock.GetUtcNow().AddMinutes(1), "authority-key", []);
        expiringQueue.MarkCommitted("req-expire", timeoutCommitted);
        manualClock.Advance(TimeSpan.FromMinutes(10) + TimeSpan.FromSeconds(6));
        check(expiringQueue.GetDetail("req-expire", _ => null) is null,
            "approvals: terminal review projection is discarded after its ten-minute retention");

        ApprovalQueue restartQueue = new(TimeProvider.System, () => TimeSpan.FromMinutes(5));
        check(restartQueue.TryRegister(Review("req-restart", now), out _), "approvals: register a request before service shutdown");
        restartQueue.Dispose();
        ApprovalDecision restartDecision = restartQueue.Wait("req-restart", CancellationToken.None);
        check(!restartDecision.Approved && restartDecision.ReasonCode == ReasonCodes.Cancelled
            && restartQueue.GetDetail("req-restart", _ => null) is null,
            "approvals: shutdown drops undecided in-memory requests and wakes the host with a fail-closed denial");

        // Denial does not need a proof flow, but still waits for the authority's durable result.
        using ApprovalQueue deniedQueue = new(TimeProvider.System, () => TimeSpan.FromMinutes(5));
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

using System.Globalization;
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace WithSecrets;

/// <summary>
/// The authority's signing keys, one active at a time. The private parts are held by <paramref name="open" /> (CNG in the program),
/// the public parts and the rotation history by the <see cref="AuthorityStore" />. A key that the store names but that cannot be
/// opened, or whose public part differs, is an error: nothing is signed with another key. A rotation or recovery uses <paramref name="create" />
/// (a key that is made new, never one found under the name) when it is given.
/// </summary>
public sealed class AuthorityKeyRing(AuthorityStore store, Func<int, ISigningKey> open, TimeProvider? clock = null, Func<int, ISigningKey>? create = null)
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly Lock _lock = new();
    private readonly Lock _openLock = new();
    private readonly Dictionary<string, ISigningKey> _opened = new(StringComparer.Ordinal);

    /// <summary>While this is locked no key is used, made or replaced: <see cref="Current" />, <see cref="Rotate" /> and <see cref="Recover" /> throw <see cref="AuthorityLockedException" />. The public record is still readable.</summary>
    public AuthorityLock? LockState { get; set; }

    /// <summary>Raised (on the calling thread, inside the key ring's lock: handlers must hand off at once) when the FIRST authority signing key was made, so something that waits for it can start.</summary>
    public event Action? KeyRecorded;

    /// <summary>The active key's record, making the first key when there is none.</summary>
    public AuthorityKeyRecord CurrentRecord()
    {
        lock (_lock)
        {
            if (store.ActiveKey() is { } active)
            {
                return active;
            }

            LockState?.EnsureUnlocked();

            ISigningKey first = open(1);
            AuthorityKeyRecord recorded = store.RecordFirstKey(first.PublicKey, "authority");
            Remember(recorded, first);
            KeyRecorded?.Invoke();

            return recorded;
        }
    }

    /// <summary>The active key, ready to sign.</summary>
    public ISigningKey Current()
    {
        LockState?.EnsureUnlocked();
        return Open(store.ActiveKey() ?? CurrentRecord());
    }

    internal ISigningKey Current(AuthorityKeyRecord active)
    {
        LockState?.EnsureUnlocked();
        return Open(active);
    }

    /// <summary>
    /// The active key's public part as the key store holds it (not as with-secrets.db says), for checking what the key signed. It does not sign and is not a use of the key,
    /// so it works while locked; null when there is no key yet. A key store that disagrees with with-secrets.db is an error, as everywhere.
    /// </summary>
    public byte[]? ActivePublicKey()
    {
        return store.ActiveKey() is { } active ? PublicKey(active) : null;
    }

    internal byte[] PublicKey(AuthorityKeyRecord active) => Open(active).PublicKey;

    private void Remember(AuthorityKeyRecord record, ISigningKey key)
    {
        lock (_openLock)
        {
            if (!_opened.TryAdd(record.Fingerprint, key) && !ReferenceEquals(_opened[record.Fingerprint], key))
            {
                key.Dispose();
            }
        }
    }

    private ISigningKey Open(AuthorityKeyRecord record)
    {
        lock (_openLock)
        {
            return OpenRecorded(record);
        }
    }

    private ISigningKey OpenRecorded(AuthorityKeyRecord record)
    {
        if (_opened.TryGetValue(record.Fingerprint, out ISigningKey? known) && known.PublicKey.AsSpan().SequenceEqual(record.PublicKey))
        {
            return known;
        }

        ISigningKey key = open(record.Generation);
        if (!key.PublicKey.AsSpan().SequenceEqual(record.PublicKey) || KeyIdentity.Fingerprint(key.PublicKey) != record.Fingerprint)
        {
            key.Dispose();
            throw new AuthorityDatabaseException("the authority signing key in the key store is not the one with-secrets.db names (generation " + record.Generation + "). Recover the authority key in the admin web app (with-secrets admin prints its link)");
        }

        _opened[record.Fingerprint] = key;

        return key;
    }

    /// <summary>Routine rotation: a new key, introduced by a transition that the current key signs. Hosts that pinned the current key accept the new one through that transition.</summary>
    public KeyTransition Rotate(string actor)
    {
        LockState?.EnsureUnlocked();
        lock (_lock)
        {
            AuthorityKeyRecord active = CurrentRecord();
            ISigningKey current = Open(active);
            ISigningKey next = (create ?? open)(active.Generation + 1);
            KeyTransition transition = KeyTransition.Create(current, next.PublicKey, _clock.GetUtcNow());
            AuthorityKeyRecord recorded = store.RecordRotation(transition, actor, tx => GrantSeals.Reseal(tx, current.PublicKey, next));
            Remember(recorded, next);

            return transition;
        }
    }

    /// <summary>Recovery after the current key was lost or must not be trusted: a new key with no transition. Hosts accept it only after an explicit administrator action (<see cref="HostConfigFile.Pin" />).</summary>
    public AuthorityKeyRecord Recover(string actor)
    {
        LockState?.EnsureUnlocked();
        lock (_lock)
        {
            AuthorityKeyRecord active = store.ActiveKey() ?? CurrentRecord();
            ISigningKey next = (create ?? open)(active.Generation + 1);
            AuthorityKeyRecord recorded = store.RecordRecovery(next.PublicKey, actor);
            Remember(recorded, next);

            return recorded;
        }
    }
}

/// <summary>
/// The authority of a local deployment: the host service and the authority in one process, through the same interface and the
/// same signatures a remote authority will use. It verifies the machine's signature, status and host name, runs the approval the
/// host offers for exactly that request digest, records the decision (with the machine's status and revision at that moment)
/// in <c>with-secrets.db</c> in one transaction, and answers with a response signed by the authority key. A retry of a request id
/// returns the committed answer and asks nobody again. It never sees or returns a secret value.
/// </summary>
public sealed class LocalAuthority(AuthorityStore store, AuthorityKeyRing keys, TimeProvider? clock = null) : IAuthority, IAuditSink
{
    /// <summary>How long an audit acknowledgement is valid after it was issued.</summary>
    public static readonly TimeSpan AuditAckLifetime = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Takes the events a host uploaded: each is checked and stored (or refused, or recognized as already stored) in one transaction, and only after that commit
    /// is the acknowledgement signed and returned. A failure to commit throws and acknowledges nothing, so the host keeps its events and sends them again.
    /// </summary>
    public Task<AuditAck> UploadAsync(AuditBatch batch, CancellationToken cancel = default)
    {
        cancel.ThrowIfCancellationRequested();

        // A locked authority stores, prunes and acknowledges nothing (the host keeps its events and sends them again after an unlock).
        ISigningKey ackKey = keys.Current();
        IReadOnlyList<AuditAckEntry> entries = store.RecordAuditEvents(batch);

        return Task.FromResult(AuditAck.Create(batch, entries, _clock.GetUtcNow(), AuditAckLifetime, ackKey));
    }

    /// <summary>How long a response is valid after it was issued.</summary>
    public static readonly TimeSpan ResponseLifetime = TimeSpan.FromSeconds(60);

    /// <summary>Checks the passkey assertions that back grants. Without one no grant is made or used (a grant counts only when a person's assertion backs its present state).</summary>
    private IApprovalVerifier? _verifier;

    public IApprovalVerifier? Verifier
    {
        get => _verifier;
        set
        {
            _verifier = value;
            store.Sealer = value is null ? null : new GrantSealer(store, keys, value);
        }
    }

    private static readonly TimeSpan ChallengeLifetime = TimeSpan.FromMinutes(2);
    private const int MaxChallenges = 64;

    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly ConcurrentDictionary<string, Offered> _offers = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, Lazy<Task<AuthorityResponse>>> _inflight = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, Lazy<Task<GrantResponse>>> _grantInflight = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _challenges = new(StringComparer.Ordinal);

    private sealed record Offered(string RequestDigest, Func<ApprovalDecision> Present, Action<AuthorityResponse>? Committed);

    /// <summary>
    /// How the host hands over the approval for a request: the authority calls <paramref name="present" /> (which shows the page and
    /// returns what the person answered) when, and only when, the machine may ask. Local mode only: the answer's unlock material
    /// goes from the page to the host, not through the response. Dispose to withdraw.
    /// </summary>
    public IDisposable Offer(string requestId, string requestDigest, Func<ApprovalDecision> present, Action<AuthorityResponse>? committed = null)
    {
        if (!_offers.TryAdd(requestId, new Offered(requestDigest, present, committed)))
        {
            throw new InvalidOperationException("an approval is already offered for this request id");
        }

        return new Withdraw(() => _offers.TryRemove(requestId, out _));
    }

    private sealed class Withdraw(Action action) : IDisposable
    {
        public void Dispose() => action();
    }

    public Task<AuthorityResponse> DecideAsync(MachineRequestEnvelope envelope, CancellationToken cancel = default)
    {
        // Only the SAME message (same machine, host name, request and signature) shares an answer in flight: another request, or a forged copy, under the same id must be judged on its own, even in the instant after the first finished.
        string id = string.Join('\n', envelope.Request.RequestId, envelope.MachineFingerprint, envelope.HostName, envelope.Request.Digest(), Convert.ToBase64String(envelope.Signature));
        Lazy<Task<AuthorityResponse>> shared = _inflight.GetOrAdd(id, _ => new Lazy<Task<AuthorityResponse>>(() => Task.Run(() => Decide(envelope, cancel))));
        Task<AuthorityResponse> task = shared.Value;
        _ = task.ContinueWith(_ => _inflight.TryRemove(new KeyValuePair<string, Lazy<Task<AuthorityResponse>>>(id, shared)), TaskScheduler.Default);

        return task;
    }

    private AuthorityResponse Decide(MachineRequestEnvelope envelope, CancellationToken cancel)
    {
        LaunchRequest request = envelope.Request;
        string digest = request.Digest();
        keys.Current();
        DateTimeOffset now = _clock.GetUtcNow();
        AuthorityResponse Answer(AuthorityDecision decision, string reason, int revision)
        {
            // Issued when it is signed (the approval may have taken minutes); the host checks the request's own expiry separately. The key is taken now, not at the start: a lock in between refuses.
            DateTimeOffset issued = _clock.GetUtcNow();

            return AuthorityResponse.Create(request.RequestId, digest, envelope.MachineFingerprint, decision, reason, revision, issued, issued + ResponseLifetime, keys.Current());
        }

        // Who is asking: a known machine, proved by its signature over exactly these fields. Nothing is stored for a stranger.
        MachineRecord? machine = store.Find(envelope.MachineFingerprint);
        if (machine is null)
        {
            return Answer(AuthorityDecision.Denied, ReasonCodes.UnknownMachine, 0);
        }

        if (!envelope.Verify(machine.PublicKey))
        {
            return Answer(AuthorityDecision.Denied, ReasonCodes.BadSignature, machine.SecurityRevision);
        }

        // A retry of a decided request id returns the committed answer; a different request under the same id is refused.
        if (store.GetProcessed(request.RequestId) is { } done)
        {
            return done.Fingerprint == machine.Fingerprint && done.RequestDigest == digest ? done.Response : Answer(AuthorityDecision.Denied, ReasonCodes.RequestIdReused, machine.SecurityRevision);
        }

        if (request.Validate(now) is { } invalid)
        {
            return store.RecordDecision(request.RequestId, digest, machine.Fingerprint, current => new DecisionPlan(Answer(AuthorityDecision.Denied, ReasonCodes.InvalidRequest, current?.SecurityRevision ?? 0), null, invalid));
        }

        if (Problem(machine, envelope) is not null)
        {
            return store.RecordDecision(request.RequestId, digest, machine.Fingerprint, current => Refusal(current, envelope, Answer));
        }

        if (!_offers.TryGetValue(request.RequestId, out Offered? offered) || offered.RequestDigest != digest)
        {
            string code = offered is null ? ReasonCodes.NoApprovalChannel : ReasonCodes.DigestMismatch;

            return store.RecordDecision(request.RequestId, digest, machine.Fingerprint, current => new DecisionPlan(Answer(AuthorityDecision.Denied, code, current?.SecurityRevision ?? 0), null, "nobody could be asked for exactly this request"));
        }

        // The machine may ask: show the approval for exactly this digest, then decide against the machine's state at the commit.
        int startRevision = machine.SecurityRevision;
        ApprovalDecision answered;
        try
        {
            answered = offered.Present();
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            answered = ApprovalDecision.Deny("the approval failed: " + error.GetType().Name);
        }

        bool cancelled = cancel.IsCancellationRequested;

        AuthorityResponse committedResponse = store.RecordDecision(request.RequestId, digest, machine.Fingerprint, current =>
        {
            // The approval may have taken minutes: a lock in that time stops the decision here, before anything is signed or stored.
            keys.LockState?.EnsureUnlocked();
            if (current is null || Problem(current, envelope) is not null)
            {
                return Refusal(current, envelope, Answer);
            }

            if (current.SecurityRevision != startRevision)
            {
                return new DecisionPlan(Answer(AuthorityDecision.Denied, ReasonCodes.AuthorizationChanged, current.SecurityRevision), null, "the security revision changed while the approval was open");
            }

            string detail = ApprovalSummary.Clean(answered.Detail);
            detail = detail.Length > 200 ? detail[..200] : detail;
            string? actor = answered.DecisionPrincipal?.AuditLabel
                ?? (answered.Credential is { } verifiedCredential
                    ? "passkey " + ApprovalSummary.Clean(verifiedCredential.Name)
                    : string.IsNullOrWhiteSpace(answered.Actor) ? null : ApprovalSummary.Clean(answered.Actor));
            if (!answered.Approved)
            {
                return new DecisionPlan(Answer(AuthorityDecision.Denied, answered.ReasonCode ?? (cancelled ? ReasonCodes.Cancelled : answered.TimedOut ? ReasonCodes.ApprovalTimeout : ReasonCodes.UserDenied), current.SecurityRevision), null, detail, Actor: actor);
            }

            return new DecisionPlan(Answer(AuthorityDecision.Approved, ReasonCodes.Approved, current.SecurityRevision), null, detail, Actor: actor);
        });

        // Notify the in-memory read model only after RecordDecision has committed its transaction.
        offered.Committed?.Invoke(committedResponse);

        return committedResponse;
    }

    /// <summary>The reason code that stops a machine from asking, or null when it may: its host name must be the bound one and its status Trusted.</summary>
    private static string? Problem(MachineRecord machine, MachineRequestEnvelope envelope) => Problem(machine, envelope.HostName);

    private static string? Problem(MachineRecord machine, string hostName)
    {
        if (!string.Equals(hostName, machine.HostName, StringComparison.Ordinal))
        {
            return ReasonCodes.HostNameMismatch;
        }

        return machine.Status switch
        {
            MachineStatus.Trusted => null,
            MachineStatus.Pending => ReasonCodes.MachinePending,
            MachineStatus.Disabled => ReasonCodes.MachineDisabled,
            _ => ReasonCodes.MachineUntrusted,
        };
    }

    private static DecisionPlan Refusal(MachineRecord? machine, MachineRequestEnvelope envelope, Func<AuthorityDecision, string, int, AuthorityResponse> answer)
    {
        if (machine is null)
        {
            return new DecisionPlan(answer(AuthorityDecision.Denied, ReasonCodes.UnknownMachine, 0), null, "", Store: false);
        }

        string code = Problem(machine, envelope) ?? ReasonCodes.AuthorizationChanged;

        return new DecisionPlan(answer(AuthorityDecision.Denied, code, machine.SecurityRevision), code == ReasonCodes.HostNameMismatch ? envelope.HostName : null, $"machine is {machine.Status}");
    }

    // ---- grants and reconciliation ----

    public Task<GrantResponse> GrantAsync(GrantEnvelope envelope, CancellationToken cancel = default)
    {
        string id = string.Join('\n', envelope.Request.RequestId, envelope.Operation, envelope.MachineFingerprint, envelope.HostName, envelope.ScopeKey, envelope.Request.Digest(), Convert.ToBase64String(envelope.Signature));
        Lazy<Task<GrantResponse>> shared = _grantInflight.GetOrAdd(id, _ => new Lazy<Task<GrantResponse>>(() => Task.Run(() => Grant(envelope, cancel))));
        Task<GrantResponse> task = shared.Value;
        _ = task.ContinueWith(_ => _grantInflight.TryRemove(new KeyValuePair<string, Lazy<Task<GrantResponse>>>(id, shared)), TaskScheduler.Default);

        return task;
    }

    private GrantResponse Grant(GrantEnvelope envelope, CancellationToken cancel)
    {
        LaunchRequest request = envelope.Request;
        string digest = request.Digest();
        keys.Current();
        GrantResponse Answer(string outcome, string reason, GrantInfo? grant, int revision)
        {
            DateTimeOffset issued = _clock.GetUtcNow();

            return GrantResponse.Create(request.RequestId, digest, envelope.MachineFingerprint, envelope.Operation, outcome, reason, grant, revision, issued, issued + ResponseLifetime, keys.Current());
        }

        GrantResponse Refuse(string reason, int revision) => Answer(GrantOps.Denied, reason, null, revision);

        MachineRecord? machine = store.Find(envelope.MachineFingerprint);
        if (machine is null)
        {
            return Refuse(ReasonCodes.UnknownMachine, 0);
        }

        if (!envelope.Verify(machine.PublicKey))
        {
            return Refuse(ReasonCodes.BadSignature, machine.SecurityRevision);
        }

        // A use is a read of the present state, evaluated each time and never stored or replayed: a stored answer could outlive a revocation.
        if (envelope.Operation == GrantOps.Approve && store.GetProcessedGrant(request.RequestId) is { } done)
        {
            return done.Fingerprint == machine.Fingerprint && done.RequestDigest == digest ? done.Response : Refuse(ReasonCodes.RequestIdReused, machine.SecurityRevision);
        }

        if (envelope.Operation is not (GrantOps.Use or GrantOps.Approve))
        {
            return Refuse(GrantReasons.BadOperation, machine.SecurityRevision);
        }

        if (request.Validate(_clock.GetUtcNow()) is not null)
        {
            return Refuse(ReasonCodes.InvalidRequest, machine.SecurityRevision);
        }

        if (!GrantOps.IsScopeKey(envelope.ScopeKey))
        {
            return Refuse(GrantReasons.BadScope, machine.SecurityRevision);
        }

        if (Problem(machine, envelope.HostName) is { } problem)
        {
            if (problem == ReasonCodes.HostNameMismatch)
            {
                store.RecordHostMismatch(machine.Fingerprint, envelope.HostName);
            }

            return Refuse(problem, machine.SecurityRevision);
        }

        return envelope.Operation == GrantOps.Use ? UseGrant(envelope, machine, Answer, Refuse) : ApproveGrant(envelope, machine, cancel, Answer, Refuse);
    }

    private GrantResponse UseGrant(GrantEnvelope envelope, MachineRecord machine, Func<string, string, GrantInfo?, int, GrantResponse> answer, Func<string, int, GrantResponse> refuse)
    {
        string digest = envelope.Request.Digest();

        return store.ApplyGrant(envelope.Request.RequestId, digest, machine.Fingerprint, (tx, current) =>
        {
            if (current is null || Problem(current, envelope.HostName) is not null)
            {
                return new AuthorityStore.GrantPlan(refuse(current is null ? ReasonCodes.UnknownMachine : Problem(current, envelope.HostName)!, current?.SecurityRevision ?? 0), null, "", false);
            }

            DateTimeOffset now = _clock.GetUtcNow();
            GrantRecord? grant = tx.FindByScope(machine.Fingerprint, envelope.ScopeKey);
            if (grant is null || grant.SecurityRevision != current.SecurityRevision)
            {
                return new AuthorityStore.GrantPlan(answer(GrantOps.None, GrantReasons.NoGrant, null, current.SecurityRevision), null, "", false);
            }

            // A once-only grant was used by the approval that made it: it never covers another run (a row set active again in the database stays void).
            if (grant.Usage != GrantUsage.Reusable)
            {
                return new AuthorityStore.GrantPlan(answer(GrantOps.None, GrantReasons.NoGrant, null, current.SecurityRevision), "grant-ignored", $"grant {grant.Id}: a once-only grant covers no further run", false);
            }

            // A row that no person's assertion backs (written, changed or planted by anything else) is not a grant.
            if (tx.SealProblem(grant) is { } rowProblem)
            {
                return new AuthorityStore.GrantPlan(answer(GrantOps.None, GrantReasons.NoGrant, null, current.SecurityRevision), "grant-ignored", $"grant {grant.Id}: {rowProblem}", false);
            }

            // A grant covers exactly the secret names, program and working folder the person approved (the passkey signed them, and the row was just checked against that text):
            // another set of names under the same scope key is not covered, whatever the host says the scope is.
            if (GrantEvidence.ContentsKey(envelope.Request.SecretNames, envelope.Request.Program, envelope.Request.WorkingDirectory) != GrantEvidence.ContentsKey(grant))
            {
                return new AuthorityStore.GrantPlan(answer(GrantOps.None, GrantReasons.NoGrant, null, current.SecurityRevision), "grant-ignored", $"grant {grant.Id}: the request's secret names, program or folder are not what the grant covers", false);
            }

            if (grant.IsExpired(now))
            {
                return new AuthorityStore.GrantPlan(answer(GrantOps.None, GrantReasons.Expired, null, current.SecurityRevision), null, "", false);
            }

            return new AuthorityStore.GrantPlan(answer(GrantOps.Granted, GrantReasons.Ok, grant.Info, current.SecurityRevision), "grant-use", $"grant {grant.Id} revision {grant.Revision}", false);
        }, replay: false);
    }

    private GrantResponse ApproveGrant(GrantEnvelope envelope, MachineRecord machine, CancellationToken cancel, Func<string, string, GrantInfo?, int, GrantResponse> answer, Func<string, int, GrantResponse> refuse)
    {
        LaunchRequest request = envelope.Request;
        string digest = request.Digest();
        if (!_offers.TryGetValue(request.RequestId, out Offered? offered) || offered.RequestDigest != digest)
        {
            return refuse(offered is null ? ReasonCodes.NoApprovalChannel : ReasonCodes.DigestMismatch, machine.SecurityRevision);
        }

        int startRevision = machine.SecurityRevision;
        ApprovalDecision answered;
        try
        {
            answered = offered.Present();
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            answered = ApprovalDecision.Deny("the approval failed: " + error.GetType().Name);
        }

        bool cancelled = cancel.IsCancellationRequested;
        string detail = ApprovalSummary.Clean(answered.Detail);
        detail = detail.Length > 200 ? detail[..200] : detail;
        string keyName = AdminAudit.KeyName(answered.Detail);
        string approvedBy = keyName.Length > 0 ? "passkey " + ApprovalSummary.Clean(keyName) : "approval page";

        return store.ApplyGrant(request.RequestId, digest, machine.Fingerprint, (tx, current) =>
        {
            // The approval may have taken minutes: a lock in that time stops the grant here, before a row is written or anything is signed.
            keys.LockState?.EnsureUnlocked();
            if (current is null || Problem(current, envelope.HostName) is not null)
            {
                return new AuthorityStore.GrantPlan(refuse(current is null ? ReasonCodes.UnknownMachine : Problem(current, envelope.HostName)!, current?.SecurityRevision ?? 0), null, "", false);
            }

            if (current.SecurityRevision != startRevision)
            {
                return new AuthorityStore.GrantPlan(refuse(ReasonCodes.AuthorizationChanged, current.SecurityRevision), "grant-denied", "the security revision changed while the approval was open");
            }

            if (!answered.Approved)
            {
                return new AuthorityStore.GrantPlan(refuse(cancelled ? ReasonCodes.Cancelled : answered.TimedOut ? ReasonCodes.ApprovalTimeout : ReasonCodes.UserDenied, current.SecurityRevision), "grant-denied", detail);
            }

            // "Approve once" (no time) with the person's assertion records a consumed once-only grant; without one it is what it always was: no time chosen.
            bool once = answered.ReuseMinutes == 0 && answered.Evidence is not null;
            if (!once && answered.ReuseMinutes != ReuseOffer.Always && answered.ReuseMinutes is < 1 or > ReuseSettings.MaxMinutes)
            {
                return new AuthorityStore.GrantPlan(refuse(GrantReasons.NoTime, current.SecurityRevision), "grant-denied", "no time was chosen on the approval page");
            }

            // The grant is made only on the person's own assertion, which names this scope and this security revision and is kept with the grant.
            DateTimeOffset now = _clock.GetUtcNow();
            if (answered.Evidence is not { } evidence)
            {
                return new AuthorityStore.GrantPlan(refuse(GrantReasons.NoEvidence, current.SecurityRevision), "grant-denied", "the approval carried no passkey assertion");
            }

            if (ApproveEvidenceProblem(evidence, answered.ReuseMinutes, envelope.ScopeKey, current.SecurityRevision, request, now) is { } evidenceProblem)
            {
                return new AuthorityStore.GrantPlan(refuse(GrantReasons.BadEvidence, current.SecurityRevision), "grant-denied", evidenceProblem);
            }

            if (once)
            {
                return RecordOnce(tx, machine.Fingerprint, envelope.ScopeKey, request, evidence, current.SecurityRevision, approvedBy, now, answer);
            }

            DateTimeOffset? expires = answered.ReuseMinutes == ReuseOffer.Always ? null : now.AddMinutes(answered.ReuseMinutes);
            PlainEvidence stored = new(GrantEvidence.ApproveKind, evidence, answered.ReuseMinutes);
            GrantRecord? existing = tx.FindByScope(machine.Fingerprint, envelope.ScopeKey);
            string names = GrantEvidence.NamesText(request.SecretNames);
            GrantRecord grant = existing is null
                ? tx.Create(machine.Fingerprint, envelope.ScopeKey, request.Program, request.WorkingDirectory, names, expires, current.SecurityRevision, approvedBy, stored, now)
                : tx.SetExpiry(existing.Id, expires, approvedBy, stored, now, (request.Program, request.WorkingDirectory, names));

            return new AuthorityStore.GrantPlan(answer(GrantOps.Granted, GrantReasons.Ok, grant.Info, current.SecurityRevision), existing is null ? "grant-created" : "grant-updated", $"grant {grant.Id}, {(answered.ReuseMinutes == ReuseOffer.Always ? "no end" : answered.ReuseMinutes + " min")}, by {approvedBy}");
        }, sealRefusal: current => SealRefusal(refuse(GrantReasons.BadEvidence, current?.SecurityRevision ?? 0)));
    }

    /// <summary>The audit text of a grant that could not be sealed (no review key, no signing key, or evidence that does not back the row): constant, so no evidence text reaches the audit.</summary>
    internal const string SealRefusedDetail = "the grant could not be sealed";

    private static AuthorityStore.GrantPlan SealRefusal(GrantResponse refusal, bool store = true) => new(refusal, "grant-denied", SealRefusedDetail, store);

    /// <summary>
    /// Null when <paramref name="evidence" /> is a verified passkey assertion, made for <paramref name="minutes" /> (0: once), over a page issued just now that names
    /// exactly this scope, this security revision and these contents; else why not. Once is never taken from a page that only makes a grant (it offers no once).
    /// </summary>
    private string? ApproveEvidenceProblem(ApprovalEvidence evidence, int minutes, string scopeKey, int securityRevision, LaunchRequest request, DateTimeOffset now)
    {
        DateTimeOffset? pageIssued = GrantEvidence.Line(evidence.Text, ApprovalSummary.IssuedPrefix) is { } issuedText && DateTimeOffset.TryParseExact(issuedText, "O", CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTimeOffset parsed) ? parsed : null;
        ApprovalCheck check = Verifier?.Verify(evidence, minutes) ?? new ApprovalCheck(false, "", false, "no verifier");
        if (!check.Ok || pageIssued is null || now < pageIssued - GrantEvidence.Skew || now > pageIssued.Value.AddMinutes(ApprovalSettings.MaxTimeoutMinutes - 1)
            || GrantEvidence.Line(evidence.Text, ApprovalSummary.RequestIdPrefix) != scopeKey
            || GrantEvidence.Line(evidence.Text, GrantEvidence.SecurityRevisionPrefix) != securityRevision.ToString(CultureInfo.InvariantCulture)
            || GrantEvidence.Line(evidence.Text, GrantEvidence.ContentsPrefix) != GrantEvidence.ContentsKey(request.SecretNames, request.Program, request.WorkingDirectory)
            || minutes == 0 && GrantEvidence.Line(evidence.Text, GrantEvidence.DecisionPrefix) == ApprovalQueue.GrantDecision)
        {
            return "the passkey assertion does not back this grant (" + (check.Ok ? "wrong text or time" : check.Detail) + ")";
        }

        return null;
    }

    /// <summary>The consumed once-only grant of an approval given once (its one run is that approval's): always a new row, never a change to an existing grant.</summary>
    private static AuthorityStore.GrantPlan RecordOnce(AuthorityStore.GrantTx tx, string fingerprint, string scopeKey, LaunchRequest request, ApprovalEvidence evidence, int securityRevision, string approvedBy, DateTimeOffset now, Func<string, string, GrantInfo?, int, GrantResponse> answer)
    {
        PlainEvidence stored = new(GrantEvidence.ApproveKind, evidence, 0);
        GrantRecord grant = tx.Create(fingerprint, scopeKey, request.Program, request.WorkingDirectory, GrantEvidence.NamesText(request.SecretNames), null, securityRevision, approvedBy, stored, now, GrantUsage.Once, consumed: true);

        return new AuthorityStore.GrantPlan(answer(GrantOps.Recorded, GrantReasons.Ok, grant.Info, securityRevision), "grant-once-recorded", $"grant {grant.Id}, once, by {approvedBy}");
    }

    /// <summary>
    /// Records the consumed once-only grant of a launch that a person approved once on the page shown here (remote mode: the page is the authority's, and the
    /// machine's use envelope, already checked against the request, names the scope). The same checks as "Approve once" through <see cref="GrantAsync" />: the
    /// machine still Trusted at the revision the page showed, and the person's assertion (made for once) over a page that names this scope, revision and
    /// contents. Returns the signed answer; the launch goes on only when its outcome is <see cref="GrantOps.Recorded" />.
    /// </summary>
    public GrantResponse RecordOnceGrant(GrantEnvelope use, ApprovalDecision decision, int startRevision)
    {
        LaunchRequest request = use.Request;
        string digest = request.Digest();
        keys.Current();
        GrantResponse Answer(string outcome, string reason, GrantInfo? grant, int revision)
        {
            DateTimeOffset issued = _clock.GetUtcNow();

            return GrantResponse.Create(request.RequestId, digest, use.MachineFingerprint, GrantOps.Approve, outcome, reason, grant, revision, issued, issued + ResponseLifetime, keys.Current());
        }

        GrantResponse Refuse(string reason, int revision) => Answer(GrantOps.Denied, reason, null, revision);

        MachineRecord? machine = store.Find(use.MachineFingerprint);
        if (machine is null)
        {
            return Refuse(ReasonCodes.UnknownMachine, 0);
        }

        if (!use.Verify(machine.PublicKey))
        {
            return Refuse(ReasonCodes.BadSignature, machine.SecurityRevision);
        }

        if (!GrantOps.IsScopeKey(use.ScopeKey))
        {
            return Refuse(GrantReasons.BadScope, machine.SecurityRevision);
        }

        string detail = ApprovalSummary.Clean(decision.Detail);
        detail = detail.Length > 200 ? detail[..200] : detail;
        string keyName = AdminAudit.KeyName(decision.Detail);
        string approvedBy = keyName.Length > 0 ? "passkey " + ApprovalSummary.Clean(keyName) : "approval page";

        // Stored under its own id: the launch's request id belongs to the decision, and a retry returns this answer and records nothing twice.
        return store.ApplyGrant("once-" + request.RequestId, digest, machine.Fingerprint, (tx, current) =>
        {
            keys.LockState?.EnsureUnlocked();
            if (current is null || Problem(current, use.HostName) is not null)
            {
                return new AuthorityStore.GrantPlan(Refuse(current is null ? ReasonCodes.UnknownMachine : Problem(current, use.HostName)!, current?.SecurityRevision ?? 0), null, "", false);
            }

            if (current.SecurityRevision != startRevision)
            {
                return new AuthorityStore.GrantPlan(Refuse(ReasonCodes.AuthorizationChanged, current.SecurityRevision), "grant-denied", "the security revision changed while the approval was open");
            }

            if (!decision.Approved)
            {
                return new AuthorityStore.GrantPlan(Refuse(ReasonCodes.UserDenied, current.SecurityRevision), "grant-denied", detail);
            }

            if (decision.ReuseMinutes != 0)
            {
                return new AuthorityStore.GrantPlan(Refuse(GrantReasons.NoTime, current.SecurityRevision), "grant-denied", "a time was chosen where only once is offered");
            }

            DateTimeOffset now = _clock.GetUtcNow();
            if (decision.Evidence is not { } evidence)
            {
                return new AuthorityStore.GrantPlan(Refuse(GrantReasons.NoEvidence, current.SecurityRevision), "grant-denied", "the approval carried no passkey assertion");
            }

            if (ApproveEvidenceProblem(evidence, 0, use.ScopeKey, current.SecurityRevision, request, now) is { } evidenceProblem)
            {
                return new AuthorityStore.GrantPlan(Refuse(GrantReasons.BadEvidence, current.SecurityRevision), "grant-denied", evidenceProblem);
            }

            return RecordOnce(tx, machine.Fingerprint, use.ScopeKey, request, evidence, current.SecurityRevision, approvedBy, now, Answer);
        }, sealRefusal: current => SealRefusal(Refuse(GrantReasons.BadEvidence, current?.SecurityRevision ?? 0)));
    }

    /// <summary>
    /// An administrator's extend, renew or revoke of a grant (the admin passkey approved it in the caller). Extend lengthens an active grant (by
    /// <see cref="GrantAdminCommand.Minutes" />, or makes it indefinite), renew gives an expired grant a new end counted from now, and revoke ends it and tells its
    /// machine; replace makes a new grant in place of a consumed once-only one (see <see cref="ReplaceGrant" />). The answer is signed and stored under the request id; a retry
    /// returns it. None of them touches the machine's security revision or any lease.
    /// </summary>
    public GrantResponse AdminGrant(GrantAdminCommand command)
    {
        string digest = command.Digest();
        keys.Current();
        GrantRecord? first = store.FindGrant(command.GrantId);
        string fingerprint = first?.Fingerprint ?? "";

        // The machine's security revision in the answer is read inside the transaction that applies the change; outside it only a refusal reads it.
        GrantResponse Answer(string outcome, string reason, GrantInfo? info, int revision)
        {
            DateTimeOffset issued = _clock.GetUtcNow();

            return GrantResponse.Create(command.RequestId, digest, fingerprint, command.Operation, outcome, reason, info, revision, issued, issued + ResponseLifetime, keys.Current());
        }

        GrantResponse Refuse(string reason) => Answer(GrantOps.Denied, reason, null, first is null ? 0 : store.Find(first.Fingerprint)?.SecurityRevision ?? 0);

        if (first is null)
        {
            return Refuse(GrantReasons.NotFound);
        }

        if (store.GetProcessedGrant(command.RequestId) is { } done)
        {
            return done.Fingerprint == fingerprint && done.RequestDigest == digest ? done.Response : Refuse(ReasonCodes.RequestIdReused);
        }

        if (command.Operation is not (GrantOps.Extend or GrantOps.Renew or GrantOps.Revoke or GrantOps.Replace))
        {
            return Refuse(GrantReasons.BadOperation);
        }

        if (command.Operation != GrantOps.Revoke && !command.Indefinite && command.Minutes is null or < 1 or > ReuseSettings.MaxMinutes)
        {
            return Refuse(GrantReasons.NoTime);
        }

        return store.ApplyGrant(command.RequestId, digest, fingerprint, (tx, machine) =>
        {
            int revision = machine?.SecurityRevision ?? 0;
            GrantResponse RefuseIn(string reason) => Answer(GrantOps.Denied, reason, null, revision);
            GrantRecord? grant = tx.Find(command.GrantId);
            if (grant is null)
            {
                return new AuthorityStore.GrantPlan(RefuseIn(GrantReasons.NotFound), null, "", false);
            }

            if (command.ExpectedRevision is { } expected && expected != grant.Revision)
            {
                return new AuthorityStore.GrantPlan(RefuseIn(GrantReasons.RevisionChanged), null, "", false);
            }

            DateTimeOffset now = _clock.GetUtcNow();
            if (command.Operation == GrantOps.Replace)
            {
                return ReplaceGrant(tx, command, grant, machine, now, Answer, RefuseIn);
            }

            if (grant.Status != "active")
            {
                return new AuthorityStore.GrantPlan(RefuseIn(GrantReasons.NotActive), null, "", false);
            }

            // Only an admin passkey's assertion over a page that says exactly this change to this grant (as it is now) changes it.
            if (GrantEvidence.AdminProblem(Verifier, command, grant, now) is { } evidenceProblem)
            {
                return new AuthorityStore.GrantPlan(RefuseIn(command.Evidence is null ? GrantReasons.NoEvidence : GrantReasons.BadEvidence), "grant-denied", $"grant {grant.Id}: {evidenceProblem}", false);
            }

            if (command.Operation != GrantOps.Revoke && tx.SealProblem(grant) is { } rowProblem)
            {
                return new AuthorityStore.GrantPlan(RefuseIn(GrantReasons.BadEvidence), "grant-denied", $"grant {grant.Id}: {rowProblem}", false);
            }

            PlainEvidence adminEvidence = new(GrantEvidence.AdminKind, command.Evidence!, 0);

            switch (command.Operation)
            {
                case GrantOps.Revoke:
                    GrantRecord revoked = tx.Revoke(grant.Id);

                    return new AuthorityStore.GrantPlan(Answer(GrantOps.Revoked, GrantReasons.Ok, revoked.Info, revision), "grant-revoked", $"grant {grant.Id} by {command.Actor}");
                case GrantOps.Extend:
                    if (grant.IsExpired(now))
                    {
                        return new AuthorityStore.GrantPlan(RefuseIn(GrantReasons.Expired), null, "", false);
                    }

                    if (grant.Expires is null || !command.Indefinite && command.NewEnd <= grant.Expires)
                    {
                        return new AuthorityStore.GrantPlan(RefuseIn(GrantReasons.NotExpired), null, "", false);
                    }

                    GrantRecord extended = tx.SetExpiry(grant.Id, command.Indefinite ? null : command.NewEnd, command.Actor, adminEvidence, now);

                    return new AuthorityStore.GrantPlan(Answer(GrantOps.Extended, GrantReasons.Ok, extended.Info, revision), "grant-extended", $"grant {grant.Id} by {command.Actor}; " + (command.Indefinite ? "indefinite" : $"{command.Minutes} min"));
                default:
                    if (!grant.IsExpired(now) || !command.Indefinite && command.NewEnd <= now)
                    {
                        return new AuthorityStore.GrantPlan(RefuseIn(GrantReasons.NotExpired), null, "", false);
                    }

                    GrantRecord renewed = tx.SetExpiry(grant.Id, command.Indefinite ? null : command.NewEnd, command.Actor, adminEvidence, now);

                    return new AuthorityStore.GrantPlan(Answer(GrantOps.Renewed, GrantReasons.Ok, renewed.Info, revision), "grant-renewed", $"grant {grant.Id} by {command.Actor}; " + (command.Indefinite ? "indefinite" : $"{command.Minutes} min"));
            }
        }, sealRefusal: machine => SealRefusal(Answer(GrantOps.Denied, GrantReasons.BadEvidence, null, machine?.SecurityRevision ?? 0), store: false));
    }

    /// <summary>
    /// An administrator's replace of a consumed once-only grant (inside the transaction of <see cref="AdminGrant" />): a new reusable grant with the id the page named, for exactly the
    /// original's scope (scope key, machine, program, folder, secret names, security revision), linked to it. Only for an original that a person's assertion backs, on a machine still at the
    /// original's security revision, with no active grant for the scope, and only on an admin passkey's assertion over a page that names exactly this replacement. The original is not changed.
    /// </summary>
    private AuthorityStore.GrantPlan ReplaceGrant(AuthorityStore.GrantTx tx, GrantAdminCommand command, GrantRecord original, MachineRecord? machine, DateTimeOffset now, Func<string, string, GrantInfo?, int, GrantResponse> answer, Func<string, GrantResponse> refuse)
    {
        if (original.Status != "consumed" || original.Usage != GrantUsage.Once)
        {
            return new AuthorityStore.GrantPlan(refuse(GrantReasons.NotActive), null, "", false);
        }

        // A once row that no person's assertion backs (written, changed or planted by anything else) was never a grant, so there is nothing to replace.
        if (tx.SealProblem(original) is { } rowProblem)
        {
            return new AuthorityStore.GrantPlan(refuse(GrantReasons.NotActive), "grant-denied", $"grant {original.Id}: not replaced: {rowProblem}", false);
        }

        // The approval the original carries was for the machine as it was then: a change of its security revision since (disable, untrust, ...) ends that authorization.
        if (machine is not { Status: MachineStatus.Trusted } || machine.SecurityRevision != original.SecurityRevision)
        {
            return new AuthorityStore.GrantPlan(refuse(ReasonCodes.AuthorizationChanged), "grant-denied", $"grant {original.Id}: not replaced: the machine's security revision changed since its approval", false);
        }

        // Only an admin passkey's assertion over a page that names exactly this replacement (the new id, this original, its scope, the end) makes the grant; a page's new id is used once.
        if (GrantEvidence.AdminProblem(Verifier, command, original, now) is { } evidenceProblem)
        {
            return new AuthorityStore.GrantPlan(refuse(command.Evidence is null ? GrantReasons.NoEvidence : GrantReasons.BadEvidence), "grant-denied", $"grant {original.Id}: {evidenceProblem}", false);
        }

        if (!GrantOps.IsGrantId(command.NewGrantId) || tx.Find(command.NewGrantId!) is not null)
        {
            return new AuthorityStore.GrantPlan(refuse(GrantReasons.BadEvidence), "grant-denied", $"grant {original.Id}: the new grant id of the page is not unused", false);
        }

        if (!command.Indefinite && command.NewEnd <= now)
        {
            return new AuthorityStore.GrantPlan(refuse(GrantReasons.NoTime), null, "", false);
        }

        if (tx.FindByScope(original.Fingerprint, original.ScopeKey) is { } active)
        {
            return new AuthorityStore.GrantPlan(refuse(GrantReasons.Exists), "grant-denied", $"grant {original.Id}: not replaced: grant {active.Id} is active for the scope", false);
        }

        PlainEvidence adminEvidence = new(GrantEvidence.AdminKind, command.Evidence!, 0);
        GrantRecord made = tx.Create(original.Fingerprint, original.ScopeKey, original.Program, original.WorkingDirectory, original.SecretNames, command.Indefinite ? null : command.NewEnd, original.SecurityRevision, command.Actor, adminEvidence, now,
            GrantUsage.Reusable, replaces: original.Id, id: command.NewGrantId);

        return new AuthorityStore.GrantPlan(answer(GrantOps.Replaced, GrantReasons.Ok, made.Info, machine.SecurityRevision), "grant-replaced", $"grant {made.Id} replaces {original.Id} by {command.Actor}; " + (command.Indefinite ? "indefinite" : $"{command.Minutes} min"));
    }

    public Task<ReconcileResponse> ReconcileAsync(ReconcileEnvelope envelope, CancellationToken cancel = default)
    {
        string digest = envelope.Digest();
        ISigningKey key = keys.Current();
        DateTimeOffset now = _clock.GetUtcNow();
        ReconcileResponse Answer(string status, bool bound, int revision) => ReconcileResponse.Create(envelope.RequestId, digest, envelope.MachineFingerprint, status, bound, revision, now, now + ResponseLifetime, key);

        MachineRecord? machine = store.Find(envelope.MachineFingerprint);
        if (machine is null || !envelope.Verify(machine.PublicKey) || (envelope.Created - now).Duration() > TimeSpan.FromMinutes(5))
        {
            return Task.FromResult(Answer("Unknown", false, machine?.SecurityRevision ?? 0));
        }

        bool bound = string.Equals(envelope.HostName, machine.HostName, StringComparison.Ordinal);
        if (!bound)
        {
            store.RecordHostMismatch(machine.Fingerprint, envelope.HostName);
        }

        return Task.FromResult(Answer(machine.Status.ToString(), bound, machine.SecurityRevision));
    }

    public Task<IReadOnlyList<PendingGrantEvent>> PendingGrantEventsAsync(string machineFingerprint, CancellationToken cancel = default)
    {
        return Task.FromResult(store.PendingGrantEvents(machineFingerprint));
    }

    public Task AcknowledgeGrantEventAsync(string machineFingerprint, long sequence, CancellationToken cancel = default)
    {
        store.AcknowledgeGrantEvent(machineFingerprint, sequence);

        return Task.CompletedTask;
    }

    // ---- enrollment, key transitions, invalidations ----

    public Task<byte[]> BeginEnrollmentAsync(CancellationToken cancel = default)
    {
        DateTimeOffset now = _clock.GetUtcNow();
        foreach (string old in _challenges.Where(item => item.Value < now).Select(item => item.Key).ToList())
        {
            _challenges.TryRemove(old, out _);
        }

        if (_challenges.Count >= MaxChallenges)
        {
            throw new InvalidOperationException("too many enrollments are waiting");
        }

        byte[] challenge = RandomNumberGenerator.GetBytes(32);
        _challenges[Convert.ToBase64String(challenge)] = now + ChallengeLifetime;

        return Task.FromResult(challenge);
    }

    /// <summary>How many machines may wait Pending at once, and with one host name.</summary>
    public const int MaxPendingMachines = 32;

    public const int MaxPendingPerHostName = 4;

    public Task<EnrollmentResult> EnrollAsync(EnrollmentRequest request, CancellationToken cancel = default)
    {
        EnrollmentResult Refuse(string message) => new(false, MachineStatus.Pending, request.Fingerprint, message);

        if (WireText.HostNameProblem(request.HostName) is { } hostProblem)
        {
            return Task.FromResult(Refuse(hostProblem));
        }

        if (!KeyIdentity.IsCanonicalP256(request.PublicKey) || !string.Equals(request.Fingerprint, KeyIdentity.Fingerprint(request.PublicKey), StringComparison.Ordinal))
        {
            return Task.FromResult(Refuse("the public key is not a canonical P-256 key with this fingerprint"));
        }

        // The challenge is single use and short lived: a proof made for another challenge, or used twice, proves nothing.
        string challengeKey = Convert.ToBase64String(request.Challenge);
        if (!_challenges.TryRemove(challengeKey, out DateTimeOffset expires) || expires < _clock.GetUtcNow())
        {
            return Task.FromResult(Refuse("the challenge is unknown, used or expired"));
        }

        if (!KeyIdentity.Verify(request.PublicKey, request.SigningBytes(), request.Signature))
        {
            return Task.FromResult(Refuse("the proof of possession does not verify"));
        }

        // The identity certificate, when the machine sends one, must contain exactly the machine's public key and have the profile of 10.2 (a CA-capable self-signed anchor, valid now). Possession of a
        // certificate trusts nothing by itself: the machine is Pending until an administrator approves it.
        if (request.IdentityCertificate is { } identityCertificate && MachineCertificates.ValidateIdentity(identityCertificate, _clock.GetUtcNow(), request.PublicKey) is { } certificateProblem)
        {
            return Task.FromResult(Refuse(certificateProblem));
        }

        // A machine that is not yet known can wait for approval only while there is room: any process that reaches the endpoint may enroll, so the list an administrator reviews is bounded
        // (in all, and per host name, so one name cannot crowd the list or copy the name of a real host many times).
        if (store.Find(request.Fingerprint) is null)
        {
            IReadOnlyList<MachineRecord> waiting = [.. store.Machines().Where(item => item.Status == MachineStatus.Pending)];
            if (waiting.Count >= MaxPendingMachines || waiting.Count(item => string.Equals(item.HostName, request.HostName, StringComparison.OrdinalIgnoreCase)) >= MaxPendingPerHostName)
            {
                return Task.FromResult(Refuse("too many machines are waiting for approval; an administrator must approve or remove some first"));
            }
        }

        MachineRecord machine = store.Register(request.PublicKey, request.HostName, request.Fingerprint, request.IdentityCertificate);
        if (machine.HostName != request.HostName)
        {
            store.RecordHostMismatch(machine.Fingerprint, request.HostName);
        }

        return Task.FromResult(new EnrollmentResult(true, machine.Status, machine.Fingerprint, machine.Status == MachineStatus.Pending ? "pending administrator approval" : machine.Status.ToString()));
    }

    public Task<IReadOnlyList<KeyTransition>> KeyTransitionsAsync(string afterKeyFingerprint, CancellationToken cancel = default)
    {
        return Task.FromResult(store.TransitionsFrom(afterKeyFingerprint));
    }

    public Task<IReadOnlyList<PendingInvalidation>> PendingInvalidationsAsync(string machineFingerprint, CancellationToken cancel = default)
    {
        return Task.FromResult(store.PendingInvalidations(machineFingerprint));
    }

    public Task AcknowledgeInvalidationAsync(string machineFingerprint, int revision, CancellationToken cancel = default)
    {
        store.Acknowledge(machineFingerprint, revision);

        return Task.CompletedTask;
    }
}

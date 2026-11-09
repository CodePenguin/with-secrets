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
    private readonly Dictionary<string, ISigningKey> _opened = new(StringComparer.Ordinal);

    /// <summary>The active key's record, making the first key when there is none.</summary>
    public AuthorityKeyRecord CurrentRecord()
    {
        lock (_lock)
        {
            if (store.ActiveKey() is { } active)
            {
                return active;
            }

            ISigningKey first = open(1);
            AuthorityKeyRecord recorded = store.RecordFirstKey(first.PublicKey, "authority");
            _opened[recorded.Fingerprint] = first;

            return recorded;
        }
    }

    /// <summary>The active key, ready to sign.</summary>
    public ISigningKey Current()
    {
        lock (_lock)
        {
            return Open(CurrentRecord());
        }
    }

    private ISigningKey Open(AuthorityKeyRecord record)
    {
        if (_opened.TryGetValue(record.Fingerprint, out ISigningKey? known))
        {
            return known;
        }

        ISigningKey key = open(record.Generation);
        if (!key.PublicKey.AsSpan().SequenceEqual(record.PublicKey))
        {
            key.Dispose();
            throw new AuthorityDatabaseException("the authority signing key in the key store is not the one authority.db names (generation " + record.Generation + "). Recover with: with-secrets admin recover-authority");
        }

        _opened[record.Fingerprint] = key;

        return key;
    }

    /// <summary>Routine rotation: a new key, introduced by a transition that the current key signs. Hosts that pinned the current key accept the new one through that transition.</summary>
    public KeyTransition Rotate(string actor)
    {
        lock (_lock)
        {
            AuthorityKeyRecord active = CurrentRecord();
            ISigningKey current = Open(active);
            ISigningKey next = (create ?? open)(active.Generation + 1);
            KeyTransition transition = KeyTransition.Create(current, next.PublicKey, _clock.GetUtcNow());
            AuthorityKeyRecord recorded = store.RecordRotation(transition, actor);
            _opened[recorded.Fingerprint] = next;

            return transition;
        }
    }

    /// <summary>Recovery after the current key was lost or must not be trusted: a new key with no transition. Hosts accept it only after an explicit administrator action (<see cref="HostConfigFile.Pin" />).</summary>
    public AuthorityKeyRecord Recover(string actor)
    {
        lock (_lock)
        {
            AuthorityKeyRecord active = store.ActiveKey() ?? CurrentRecord();
            ISigningKey next = (create ?? open)(active.Generation + 1);
            AuthorityKeyRecord recorded = store.RecordRecovery(next.PublicKey, actor);
            _opened[recorded.Fingerprint] = next;

            return recorded;
        }
    }
}

/// <summary>
/// The authority of a local deployment: the host service and the authority in one process, through the same interface and the
/// same signatures a remote authority will use. It verifies the machine's signature, status and host name, runs the approval the
/// host offers for exactly that request digest, records the decision (with the machine's status and revision at that moment)
/// in <c>authority.db</c> in one transaction, and answers with a response signed by the authority key. A retry of a request id
/// returns the committed answer and asks nobody again. It never sees or returns a secret value.
/// </summary>
public sealed class LocalAuthority(AuthorityStore store, AuthorityKeyRing keys, TimeProvider? clock = null) : IAuthority
{
    /// <summary>How long a response is valid after it was issued.</summary>
    public static readonly TimeSpan ResponseLifetime = TimeSpan.FromSeconds(60);

    /// <summary>The longest a host may go on using what it synchronized while it cannot reach the authority: the authority's policy (a provisional default of 15 minutes), sent to the host in each reconcile answer. A connected host applies a change at its next check-in.</summary>
    public TimeSpan LeaseDuration { get; set; } = TimeSpan.FromMinutes(15);

    private static readonly TimeSpan ChallengeLifetime = TimeSpan.FromMinutes(2);
    private const int MaxChallenges = 64;

    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly ConcurrentDictionary<string, Offered> _offers = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, Lazy<Task<AuthorityResponse>>> _inflight = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, Lazy<Task<GrantResponse>>> _grantInflight = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _challenges = new(StringComparer.Ordinal);

    private sealed record Offered(string RequestDigest, Func<ApprovalDecision> Present);

    /// <summary>
    /// How the host hands over the approval for a request: the authority calls <paramref name="present" /> (which shows the page and
    /// returns what the person answered) when, and only when, the machine may ask. Local mode only: the answer's unlock material
    /// goes from the page to the host, not through the response. Dispose to withdraw.
    /// </summary>
    public IDisposable Offer(string requestId, string requestDigest, Func<ApprovalDecision> present)
    {
        if (!_offers.TryAdd(requestId, new Offered(requestDigest, present)))
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
        string id = envelope.Request.RequestId;
        Lazy<Task<AuthorityResponse>> shared = _inflight.GetOrAdd(id, _ => new Lazy<Task<AuthorityResponse>>(() => Task.Run(() => Decide(envelope, cancel))));
        Task<AuthorityResponse> task = shared.Value;
        _ = task.ContinueWith(_ => _inflight.TryRemove(new KeyValuePair<string, Lazy<Task<AuthorityResponse>>>(id, shared)), TaskScheduler.Default);

        return task;
    }

    private AuthorityResponse Decide(MachineRequestEnvelope envelope, CancellationToken cancel)
    {
        LaunchRequest request = envelope.Request;
        string digest = request.Digest();
        ISigningKey key = keys.Current();
        DateTimeOffset now = _clock.GetUtcNow();
        AuthorityResponse Answer(AuthorityDecision decision, string reason, int revision)
        {
            // Issued when it is signed (the approval may have taken minutes); the host checks the request's own expiry separately.
            DateTimeOffset issued = _clock.GetUtcNow();

            return AuthorityResponse.Create(request.RequestId, digest, envelope.MachineFingerprint, decision, reason, revision, issued, issued + ResponseLifetime, key);
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

        return store.RecordDecision(request.RequestId, digest, machine.Fingerprint, current =>
        {
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
            if (!answered.Approved)
            {
                return new DecisionPlan(Answer(AuthorityDecision.Denied, cancelled ? ReasonCodes.Cancelled : ReasonCodes.UserDenied, current.SecurityRevision), null, detail);
            }

            return new DecisionPlan(Answer(AuthorityDecision.Approved, ReasonCodes.Approved, current.SecurityRevision), null, detail);
        });
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
        string id = envelope.Request.RequestId;
        Lazy<Task<GrantResponse>> shared = _grantInflight.GetOrAdd(id, _ => new Lazy<Task<GrantResponse>>(() => Task.Run(() => Grant(envelope, cancel))));
        Task<GrantResponse> task = shared.Value;
        _ = task.ContinueWith(_ => _grantInflight.TryRemove(new KeyValuePair<string, Lazy<Task<GrantResponse>>>(id, shared)), TaskScheduler.Default);

        return task;
    }

    private GrantResponse Grant(GrantEnvelope envelope, CancellationToken cancel)
    {
        LaunchRequest request = envelope.Request;
        string digest = request.Digest();
        ISigningKey key = keys.Current();
        GrantResponse Answer(string outcome, string reason, GrantInfo? grant, int revision)
        {
            DateTimeOffset issued = _clock.GetUtcNow();

            return GrantResponse.Create(request.RequestId, digest, envelope.MachineFingerprint, envelope.Operation, outcome, reason, grant, revision, issued, issued + ResponseLifetime, key);
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

        if (store.GetProcessedGrant(request.RequestId) is { } done)
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

            if (grant.IsExpired(now))
            {
                return new AuthorityStore.GrantPlan(answer(GrantOps.None, GrantReasons.Expired, null, current.SecurityRevision), null, "", false);
            }

            return new AuthorityStore.GrantPlan(answer(GrantOps.Granted, GrantReasons.Ok, grant.Info, current.SecurityRevision), "grant-use", $"grant {grant.Id} revision {grant.Revision}");
        });
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
        string keyName = AuditLog.KeyName(answered.Detail);
        string approvedBy = keyName.Length > 0 ? "passkey " + ApprovalSummary.Clean(keyName) : "approval page";

        return store.ApplyGrant(request.RequestId, digest, machine.Fingerprint, (tx, current) =>
        {
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
                return new AuthorityStore.GrantPlan(refuse(cancelled ? ReasonCodes.Cancelled : ReasonCodes.UserDenied, current.SecurityRevision), "grant-denied", detail);
            }

            if (answered.ReuseMinutes is < 1 or > ReuseSettings.MaxMinutes)
            {
                return new AuthorityStore.GrantPlan(refuse(GrantReasons.NoTime, current.SecurityRevision), "grant-denied", "no time was chosen on the approval page");
            }

            DateTimeOffset now = _clock.GetUtcNow();
            DateTimeOffset expires = now.AddMinutes(answered.ReuseMinutes);
            GrantRecord? existing = tx.FindByScope(machine.Fingerprint, envelope.ScopeKey);
            string names = string.Join(", ", request.SecretNames.Order(StringComparer.Ordinal));
            GrantRecord grant = existing is null
                ? tx.Create(machine.Fingerprint, envelope.ScopeKey, Short(request.Program), Short(request.WorkingDirectory), Short(names), expires, current.SecurityRevision, approvedBy)
                : tx.SetExpiry(existing.Id, expires, approvedBy);

            return new AuthorityStore.GrantPlan(answer(GrantOps.Granted, GrantReasons.Ok, grant.Info, current.SecurityRevision), existing is null ? "grant-created" : "grant-updated", $"grant {grant.Id}, {answered.ReuseMinutes} min, by {approvedBy}");
        });
    }

    private static string Short(string text)
    {
        string clean = ApprovalSummary.Clean(text);

        return clean.Length > 300 ? clean[..300] : clean;
    }

    /// <summary>
    /// An administrator's extend, renew or revoke of a grant (the admin passkey approved it in the caller). Extend lengthens an active grant (by
    /// <see cref="GrantAdminCommand.Minutes" />, or makes it indefinite), renew gives an expired grant a new end counted from now, and revoke ends it and tells its
    /// machine. The answer is signed and stored under the request id; a retry returns it. None of them touches the machine's security revision or any lease.
    /// </summary>
    public GrantResponse AdminGrant(GrantAdminCommand command)
    {
        string digest = command.Digest();
        ISigningKey key = keys.Current();
        GrantRecord? first = store.FindGrant(command.GrantId);
        string fingerprint = first?.Fingerprint ?? "";
        int machineRevision = first is null ? 0 : store.Find(first.Fingerprint)?.SecurityRevision ?? 0;
        GrantResponse Answer(string outcome, string reason, GrantInfo? info)
        {
            DateTimeOffset issued = _clock.GetUtcNow();

            return GrantResponse.Create(command.RequestId, digest, fingerprint, command.Operation, outcome, reason, info, machineRevision, issued, issued + ResponseLifetime, key);
        }

        GrantResponse Refuse(string reason) => Answer(GrantOps.Denied, reason, null);

        if (first is null)
        {
            return Refuse(GrantReasons.NotFound);
        }

        if (store.GetProcessedGrant(command.RequestId) is { } done)
        {
            return done.Fingerprint == fingerprint && done.RequestDigest == digest ? done.Response : Refuse(ReasonCodes.RequestIdReused);
        }

        if (command.Operation is not (GrantOps.Extend or GrantOps.Renew or GrantOps.Revoke))
        {
            return Refuse(GrantReasons.BadOperation);
        }

        if (command.Operation != GrantOps.Revoke && !command.Indefinite && command.Minutes is null or < 1 or > ReuseSettings.MaxMinutes)
        {
            return Refuse(GrantReasons.NoTime);
        }

        return store.ApplyGrant(command.RequestId, digest, fingerprint, (tx, machine) =>
        {
            GrantRecord? grant = tx.Find(command.GrantId);
            if (grant is null)
            {
                return new AuthorityStore.GrantPlan(Refuse(GrantReasons.NotFound), null, "", false);
            }

            if (command.ExpectedRevision is { } expected && expected != grant.Revision)
            {
                return new AuthorityStore.GrantPlan(Refuse(GrantReasons.RevisionChanged), null, "", false);
            }

            DateTimeOffset now = _clock.GetUtcNow();
            if (grant.Status != "active")
            {
                return new AuthorityStore.GrantPlan(Refuse(GrantReasons.NotActive), null, "", false);
            }

            switch (command.Operation)
            {
                case GrantOps.Revoke:
                    GrantRecord revoked = tx.Revoke(grant.Id);

                    return new AuthorityStore.GrantPlan(Answer(GrantOps.Revoked, GrantReasons.Ok, revoked.Info), "grant-revoked", $"grant {grant.Id} by {command.Actor}");
                case GrantOps.Extend:
                    if (grant.IsExpired(now))
                    {
                        return new AuthorityStore.GrantPlan(Refuse(GrantReasons.Expired), null, "", false);
                    }

                    if (grant.Expires is null)
                    {
                        return new AuthorityStore.GrantPlan(Refuse(GrantReasons.NotExpired), null, "", false);
                    }

                    GrantRecord extended = tx.SetExpiry(grant.Id, command.Indefinite ? null : grant.Expires.Value.AddMinutes(command.Minutes!.Value), command.Actor);

                    return new AuthorityStore.GrantPlan(Answer(GrantOps.Extended, GrantReasons.Ok, extended.Info), "grant-extended", $"grant {grant.Id} by {command.Actor}; " + (command.Indefinite ? "indefinite" : $"{command.Minutes} min"));
                default:
                    if (!grant.IsExpired(now))
                    {
                        return new AuthorityStore.GrantPlan(Refuse(GrantReasons.NotExpired), null, "", false);
                    }

                    GrantRecord renewed = tx.SetExpiry(grant.Id, command.Indefinite ? null : now.AddMinutes(command.Minutes!.Value), command.Actor);

                    return new AuthorityStore.GrantPlan(Answer(GrantOps.Renewed, GrantReasons.Ok, renewed.Info), "grant-renewed", $"grant {grant.Id} by {command.Actor}; " + (command.Indefinite ? "indefinite" : $"{command.Minutes} min"));
            }
        });
    }

    public Task<ReconcileResponse> ReconcileAsync(ReconcileEnvelope envelope, CancellationToken cancel = default)
    {
        string digest = envelope.Digest();
        ISigningKey key = keys.Current();
        DateTimeOffset now = _clock.GetUtcNow();
        ReconcileResponse Answer(string status, bool bound, int revision, TimeSpan lease) => ReconcileResponse.Create(envelope.RequestId, digest, envelope.MachineFingerprint, status, bound, revision, (int)lease.TotalSeconds, now, now + ResponseLifetime, key);

        MachineRecord? machine = store.Find(envelope.MachineFingerprint);
        if (machine is null || !envelope.Verify(machine.PublicKey) || (envelope.Created - now).Duration() > TimeSpan.FromMinutes(5))
        {
            return Task.FromResult(Answer("Unknown", false, machine?.SecurityRevision ?? 0, TimeSpan.Zero));
        }

        bool bound = string.Equals(envelope.HostName, machine.HostName, StringComparison.Ordinal);
        if (!bound)
        {
            store.RecordHostMismatch(machine.Fingerprint, envelope.HostName);
        }

        return Task.FromResult(Answer(machine.Status.ToString(), bound, machine.SecurityRevision, machine.Status == MachineStatus.Trusted && bound ? LeaseDuration : TimeSpan.Zero));
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

        MachineRecord machine = store.Register(request.PublicKey, request.HostName, request.Fingerprint);
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

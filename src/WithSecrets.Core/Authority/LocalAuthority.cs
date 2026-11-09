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

    private static readonly TimeSpan ChallengeLifetime = TimeSpan.FromMinutes(2);
    private const int MaxChallenges = 64;

    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly ConcurrentDictionary<string, Offered> _offers = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, Lazy<Task<AuthorityResponse>>> _inflight = new(StringComparer.Ordinal);
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
    private static string? Problem(MachineRecord machine, MachineRequestEnvelope envelope)
    {
        if (!string.Equals(envelope.HostName, machine.HostName, StringComparison.Ordinal))
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

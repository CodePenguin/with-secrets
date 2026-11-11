using System.Globalization;
using System.Security.Cryptography;

namespace WithSecrets;

/// <summary>
/// Where an authorization stands. It is made Pending and the passkey tap makes it Verified or Refused. The service applies the plan the tap authorized at once (Verified is the moment between the tap and
/// that), which makes it Consumed with its <see cref="AuthorizationResult" /> (applied, started or failed). Nothing waits for the browser to come back.
/// </summary>
public enum AuthorizationState
{
    Pending,
    Verified,
    Refused,
    Consumed,
    Expired,
}

/// <summary>What an authorization looks like to the caller that asked for it (nothing in it authorizes anything by itself: only the verified tap does, and only for the one mutation it names).</summary>
public sealed record AuthorizationView(string Id, string Operation, AuthorizationState State, string? Detail, string? Link, string Sentence, IReadOnlyList<(string Name, string Value)> Parameters, DateTimeOffset Created, DateTimeOffset Expires,
    AuthorizationResult? Result = null);

/// <summary>
/// How the change a tap authorized came out: <c>applied</c>, <c>started</c> (the operation's own passkey pages continue at <see cref="Link" />) or <c>failed</c> with a code and one safe line. The bundle of a new
/// invitation is in <see cref="Invitation" /> in ONE answer only; <see cref="InvitationGone" /> says that it was already given or has been held long enough.
/// </summary>
public sealed record AuthorizationResult(string Outcome, string? Code, string? Detail, string? Link, InvitationCreatedDto? Invitation, bool InvitationGone);

/// <summary>What a mutation came to: applied (200), a passkey page to open for a delegated operation (202), or a refusal with its code, status and one safe line. <see cref="Repeat" /> is true for an answer to a retry.</summary>
internal sealed record MutationResult(int Status, string? Code, string? Detail, string? Link = null, InvitationCreatedDto? Invitation = null, bool Repeat = false)
{
    public bool Applied => Status == 200;
}

/// <summary>
/// The operation-bound authorizations of the administration API. An authorization is made for one operation and its parameters (the plan is made, and refused if it does not apply, before any
/// page exists), shows one one-use passkey page (user verification, the operation and every security-relevant parameter in the signed text), and becomes Verified only through the existing
/// proof check (<see cref="AdminAuthorizer" />). The mutation that follows must carry its id, come from the caller it was made for, name the same operation with the same parameters, and arrive within
/// <see cref="AuthorizationLifetime" /> of the tap; it spends the authorization (whatever its outcome), so a replay, a second mutation, other parameters or another operation find nothing. A session
/// never satisfies a mutation and an earlier authorization never satisfies another. A lock destroys them all.
/// </summary>
public sealed partial class AdminService
{
    /// <summary>How long a verified authorization may wait for its mutation.</summary>
    public static readonly TimeSpan AuthorizationLifetime = TimeSpan.FromMinutes(2);

    /// <summary>The most authorizations held at once (pending, verified and not yet spent), Lock apart: Lock has its own room (<see cref="MaxLockAuthorizations" />) that nothing else uses up.</summary>
    public const int MaxAuthorizations = 32;

    /// <summary>The most Lock authorizations a signed-in session's callers hold at once (anonymous ones have <see cref="MaxLockPages" /> and push the oldest out when full).</summary>
    public const int MaxLockAuthorizations = 64;

    /// <summary>The most of <see cref="MaxAuthorizations" /> that callers without a session (the unlock) may hold.</summary>
    public const int MaxAnonymousAuthorizations = 16;

    /// <summary>How long the bundle of a new invitation stays in service memory for the browser that asked for it to collect (once). After that, or after the first collection, it is gone.</summary>
    public static readonly TimeSpan BundleHold = TimeSpan.FromMinutes(5);

    private sealed class AuthorizationRecord(string id, object owner, string operation, string argumentsKey, AdminPlan plan, DateTimeOffset created, int epoch)
    {
        /// <summary>What applying the plan came to (null until then).</summary>
        public MutationResult? Outcome { get; set; }

        public DateTimeOffset? AppliedAt { get; set; }

        /// <summary>Completes when the outcome is known.</summary>
        public TaskCompletionSource Done { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        /// <summary>True once the bundle of a new invitation was given (or held too long): it is never given again.</summary>
        public bool BundleGone { get; set; }

        /// <summary>How many mutation requests were answered with the outcome (the first is the answer, later ones are retries).</summary>
        public int Answers { get; set; }

        /// <summary>The lock count from before the plan was made: a lock since then ends this authorization.</summary>
        public int Epoch { get; } = epoch;

        public string Id { get; } = id;

        public object Owner { get; } = owner;

        public string Operation { get; } = operation;

        public string ArgumentsKey { get; } = argumentsKey;

        public AdminPlan Plan { get; } = plan;

        public DateTimeOffset Created { get; } = created;

        public DateTimeOffset? VerifiedAt { get; set; }

        public AuthorizationState State { get; set; } = AuthorizationState.Pending;

        public string? Detail { get; set; }

        public string? Link { get; set; }

        public AdminAuthorization? Result { get; set; }
    }

    private readonly Lock _authorizationGate = new();
    private readonly Dictionary<string, AuthorizationRecord> _authorizations = new(StringComparer.Ordinal);

    /// <summary>The number of authorizations held (not yet spent or expired).</summary>
    public int AuthorizationCount
    {
        get
        {
            lock (_authorizationGate)
            {
                SweepAuthorizations();

                return _authorizations.Count;
            }
        }
    }

    /// <summary>The arguments of an operation as one comparable text: sorted names, values as given.</summary>
    internal static string ArgumentsKey(IReadOnlyDictionary<string, string> args) => string.Join('\n', args.OrderBy(item => item.Key, StringComparer.Ordinal).Select(item => item.Key + "=" + item.Value));

    private static bool SameOwner(object left, object right) => left is string leftText ? right is string rightText && leftText == rightText : ReferenceEquals(left, right);

    private static void Release(AuthorizationRecord record)
    {
        if (record.Plan.Material is not null)
        {
            CryptographicOperations.ZeroMemory(record.Plan.Material);
        }
    }

    private static bool Active(AuthorizationRecord record) => record.State is AuthorizationState.Pending or AuthorizationState.Verified;

    /// <summary>
    /// Ends what has run out (zeroing any held material) and forgets, a few minutes later, what has ended, so a replay is told "used" or "expired" rather than "unknown" for a while. Caller holds <c>_authorizationGate</c>.
    /// </summary>
    private void SweepAuthorizations()
    {
        DateTimeOffset now = _clock.GetUtcNow();
        foreach (AuthorizationRecord record in _authorizations.Values.ToList())
        {
            if (Expired(record, now))
            {
                record.State = AuthorizationState.Expired;
                Release(record);
            }

            if (record.Outcome?.Invitation is not null && record.AppliedAt is { } applied && now - applied > BundleHold)
            {
                record.Outcome = record.Outcome with { Invitation = null };
                record.BundleGone = true;
            }

            if (!Active(record) && now - (record.VerifiedAt ?? record.Created) > AuthorizationLifetime + TimeSpan.FromMinutes(ApprovalSettings.MaxTimeoutMinutes + 5))
            {
                _authorizations.Remove(record.Id);
            }
        }
    }

    private static bool Expired(AuthorizationRecord record, DateTimeOffset now) => record.State == AuthorizationState.Verified
        ? now - record.VerifiedAt!.Value > AuthorizationLifetime
        : record.State == AuthorizationState.Pending && now - record.Created > TimeSpan.FromMinutes(ApprovalSettings.MaxTimeoutMinutes + 5);

    /// <summary>A lock ends every authorization (a tap before the lock authorizes nothing after it) and zeroes what they held.</summary>
    internal void ClearAuthorizations()
    {
        lock (_authorizationGate)
        {
            foreach (AuthorizationRecord record in _authorizations.Values)
            {
                Release(record);
            }

            _authorizations.Clear();
        }
    }

    /// <summary>
    /// Makes an authorization for <paramref name="owner" /> (the caller's <see cref="AdminSession" />, or for the unlock the text of the browser's pre-session cookie) to run <paramref name="op" /> with
    /// <paramref name="args" />: the plan is made and refused here when it does not apply, then a one-use passkey page is made whose signed text names the operation and every parameter.
    /// </summary>
    internal async Task<(AuthorizationView? View, AdminStart Start)> BeginAuthorizationAsync(object owner, string op, IReadOnlyDictionary<string, string> args, CancellationToken cancel)
    {
        bool isSession = owner is AdminSession;
        string caller = CallerOf(owner);
        int epoch = Volatile.Read(ref _epoch);
        if (!isSession && !NeedsNoSession(op))
        {
            Refused(op, "no administrator session", caller);

            return (null, new AdminStart(null, "sign in first: this needs an administrator session", 401));
        }

        if (!TakeStart((op == OpLock ? "L" : "") + caller))
        {
            Refused(op, "too many requests", caller);

            return (null, new AdminStart(null, "too many requests; wait a minute", 429));
        }

        AdminPlan? plan = Plan(op, args, out string? refusal, out int refusalStatus);
        if (plan is null)
        {
            Refused(op, refusal ?? "refused", caller);

            return (null, new AdminStart(null, refusal, refusalStatus));
        }

        AfterPlanForTests?.Invoke();

        string id = Convert.ToBase64String(RandomNumberGenerator.GetBytes(18)).Replace('+', '-').Replace('/', '_');
        AuthorizationRecord record = new(id, owner, op, ArgumentsKey(args), plan, _clock.GetUtcNow(), epoch);
        lock (_authorizationGate)
        {
            SweepAuthorizations();
            if (Volatile.Read(ref _epoch) != epoch)
            {
                // A lock came between planning and keeping this: it ends here, so no page is made and nothing is held.
                Release(record);
                Refused(op, "the authority was locked", caller);

                return (null, new AdminStart(null, "the authority was locked while this was being started", 423));
            }

            List<AuthorizationRecord> active = [.. _authorizations.Values.Where(Active)];
            if (op == OpLock && !isSession)
            {
                // The anonymous Lock room is full: the oldest of those ends to make room, so a new Lock request is never refused for it.
                List<AuthorizationRecord> anonymous = [.. active.Where(item => item.Operation == OpLock && item.Owner is string).OrderBy(item => item.Created)];
                for (int i = 0; anonymous.Count - i >= MaxLockPages; i++)
                {
                    anonymous[i].State = AuthorizationState.Expired;
                    Release(anonymous[i]);
                }
            }

            bool full = op == OpLock
                ? isSession && active.Count(item => item.Operation == OpLock && item.Owner is AdminSession) >= MaxLockAuthorizations
                : active.Count(item => item.Operation != OpLock) >= MaxAuthorizations || (!isSession && active.Count(item => item.Operation != OpLock && item.Owner is string) >= MaxAnonymousAuthorizations);
            if (full)
            {
                Release(record);
                Refused(op, "too many authorizations waiting", caller);

                return (null, new AdminStart(null, "too many authorizations are waiting; wait for them to end", 429));
            }

            _authorizations[id] = record;
        }

        bool Complete(AdminAuthorization result)
        {
            lock (_authorizationGate)
            {
                if (record.State != AuthorizationState.Pending || !_authorizations.ContainsKey(id) || Volatile.Read(ref _epoch) != epoch)
                {
                    return false;
                }

                record.Result = result;
                record.Detail = result.Ok ? null : ApprovalSummary.Clean(result.Detail);
                record.State = result.Ok ? AuthorizationState.Verified : AuthorizationState.Refused;
                record.VerifiedAt = result.Ok ? _clock.GetUtcNow() : null;
                if (!result.Ok)
                {
                    Release(record);
                }

                return result.Ok;
            }
        }

        // The service applies the plan the tap authorized as soon as the tap is judged good, so a browser that has gone away (a phone's backgrounded tab) loses nothing. The plan of an operation with passkey pages of
        // its own is started when this page has closed (its slot is free then).
        bool startDelegated = false;
        AdminPlan asked = plan with { OnRefused = reason => Complete(new AdminAuthorization(null, reason)) };
        AdminStart started = await Run(asked, caller, epoch, cancel, (item, asker, announce, token) =>
        {
            AdminAuthorization result = _p.Authorizer.Authorize(asker, Heading, item.Sentence, item.Operation, item.Parameters, token);
            bool verified = Complete(result);
            Note(item.Operation + (result.Ok ? ": authorized" : ": refused"));
            if (verified)
            {
                if (plan.Delegated is null)
                {
                    ApplyAtTap(record, caller);
                }
                else
                {
                    startDelegated = true;
                }
            }

            return result.Ok ? "authorized" : result.Detail;
        }, keepMaterial: true, afterPage: () =>
        {
            if (startDelegated)
            {
                _ = StartDelegatedAsync(record, caller);
            }
        });
        if (started.Link is null)
        {
            // No page was made (nothing enrolled, too slow, ...): nothing is held.
            lock (_authorizationGate)
            {
                Release(record);
                _authorizations.Remove(id);
            }

            return (null, started);
        }

        lock (_authorizationGate)
        {
            record.Link = started.Link;
        }

        return (View(record), started);
    }

    /// <summary>The view of a record. Caller holds <c>_authorizationGate</c>. The bundle of a new invitation is given only when <paramref name="takeBundle" /> (and then it is gone).</summary>
    private AuthorizationView View(AuthorizationRecord record, bool takeBundle = false) => new(record.Id, record.Operation, record.State, record.Detail, record.State == AuthorizationState.Pending ? record.Link : null,
        AdminAuthorizer.PageText(record.Plan.Sentence, record.Plan.Operation, record.Plan.Parameters), record.Plan.Parameters, record.Created,
        record.State == AuthorizationState.Verified && record.VerifiedAt is { } verified ? verified + AuthorizationLifetime : record.Created.AddMinutes(ApprovalSettings.MaxTimeoutMinutes + 5),
        record.Outcome is { } outcome ? ResultOf(record, outcome, takeBundle) : null);

    private static AuthorizationResult ResultOf(AuthorizationRecord record, MutationResult outcome, bool takeBundle)
    {
        InvitationCreatedDto? bundle = null;
        if (outcome.Invitation is not null && takeBundle)
        {
            bundle = outcome.Invitation;
            record.Outcome = outcome with { Invitation = null };
            record.BundleGone = true;
        }

        return new AuthorizationResult(outcome.Status == 200 ? "applied" : outcome.Status == 202 ? "started" : "failed", outcome.Code, outcome.Detail, outcome.Link, bundle, bundle is null && record.BundleGone);
    }

    /// <summary>The state of an authorization, for the caller it was made for; null for an unknown one or another caller's.</summary>
    internal AuthorizationView? FindAuthorization(object owner, string id, bool takeBundle = false)
    {
        lock (_authorizationGate)
        {
            SweepAuthorizations();

            return _authorizations.TryGetValue(id, out AuthorizationRecord? record) && SameOwner(record.Owner, owner) ? View(record, takeBundle) : null;
        }
    }

    /// <summary>
    /// Cancels an authorization whose tap has not been made: it can no longer become a change (a tap on its page afterwards authorizes nothing). Only for the caller it was made for. Returns null for an
    /// unknown one, false when the tap was already judged (its change was made or refused and cannot be taken back), true when it is cancelled (or already ended).
    /// </summary>
    internal bool? CancelAuthorization(object owner, string id)
    {
        lock (_authorizationGate)
        {
            SweepAuthorizations();
            if (!_authorizations.TryGetValue(id, out AuthorizationRecord? record) || !SameOwner(record.Owner, owner))
            {
                return null;
            }

            if (record.State is AuthorizationState.Verified or AuthorizationState.Consumed)
            {
                return false;
            }

            if (record.State == AuthorizationState.Pending)
            {
                record.State = AuthorizationState.Refused;
                record.Detail = "cancelled before the passkey tap";
                Release(record);
            }

            return true;
        }
    }

    /// <summary>Takes the right to apply the plan (Verified to Consumed): false when it was not Verified, or a lock has come since (then the outcome is the lock's).</summary>
    private bool Claim(AuthorizationRecord record)
    {
        bool locked;
        lock (_authorizationGate)
        {
            if (record.State != AuthorizationState.Verified || !_authorizations.ContainsKey(record.Id))
            {
                return false;
            }

            record.State = AuthorizationState.Consumed;
            locked = record.Epoch != Volatile.Read(ref _epoch);
        }

        if (locked)
        {
            Release(record);
            Finish(record, new MutationResult(423, "authority-locked", "the authority was locked after this authorization was made; make a new one"));

            return false;
        }

        return true;
    }

    private void Finish(AuthorizationRecord record, MutationResult outcome)
    {
        lock (_authorizationGate)
        {
            record.Outcome = outcome;
            record.AppliedAt = _clock.GetUtcNow();
        }

        record.Done.TrySetResult();
    }

    /// <summary>Applies the plan that the verified tap authorized, once, and keeps how it came out. Runs on the passkey page's thread right after the tap is judged.</summary>
    private void ApplyAtTap(AuthorizationRecord record, string caller)
    {
        if (!Claim(record))
        {
            return;
        }

        MutationResult outcome;
        try
        {
            AdminAuthorization result = record.Result!;
            if (_p.Lock.IsLocked && record.Operation != OpUnlock)
            {
                Refused(record.Operation, "the authority is locked", caller);
                outcome = new MutationResult(423, "authority-locked", "the authority is locked; unlock it first");
            }
            else
            {
                string? failure = ApplyAuthorized(record.Plan, result, result.Admin!);
                if (failure is not null)
                {
                    outcome = new MutationResult(409, "operation-failed", ApprovalSummary.Clean(failure));
                }
                else
                {
                    // The bundle of a new invitation is kept here, in this record, to be given once to the caller it was made for; the plan's own box is emptied now.
                    InvitationCreatedDto? created = record.Plan.Output?.Value;
                    if (record.Plan.Output is { } box)
                    {
                        box.Value = null;
                    }

                    outcome = new MutationResult(200, null, null, null, created);
                }
            }
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            AppLog.Warn("an administrator change failed unexpectedly: {Type}", error.GetType().Name);
            outcome = new MutationResult(500, "operation-failed", "the change failed");
        }
        finally
        {
            Release(record);
        }

        Finish(record, outcome);
    }

    /// <summary>Starts the passkey pages of an operation that has its own (adding or removing a passkey) once the authorization page has closed, and keeps the link of the first.</summary>
    private async Task StartDelegatedAsync(AuthorizationRecord record, string caller)
    {
        if (!Claim(record))
        {
            return;
        }

        MutationResult outcome;
        try
        {
            if (_p.Lock.IsLocked)
            {
                outcome = new MutationResult(423, "authority-locked", "the authority is locked; unlock it first");
            }
            else
            {
                // The passkey pages of the operation are its own taps (each binds its own text and checks user verification); the authorization above is what let it start.
                AdminStart started = await Run(record.Plan, caller, record.Epoch, CancellationToken.None);
                outcome = started.Link is not null ? new MutationResult(202, null, null, started.Link) : new MutationResult(started.Status, "operation-refused", started.Error);
            }
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            AppLog.Warn("an administrator change failed unexpectedly: {Type}", error.GetType().Name);
            outcome = new MutationResult(500, "operation-failed", "the change failed");
        }
        finally
        {
            Release(record);
        }

        Finish(record, outcome);
    }

    /// <summary>
    /// The mutation request of the API. The service has applied (or refused) the plan its tap authorized by itself, so this applies nothing: it checks that the request names exactly the operation and the
    /// parameters the authorization was made for, waits for the outcome and answers it. The first answer is the outcome, a retry gets the same outcome marked as a repeat (nothing is applied twice, and the
    /// bundle of an invitation is never given twice). Another operation or other parameters change nothing and are refused.
    /// </summary>
    internal async Task<MutationResult> MutateAsync(object owner, string op, IReadOnlyDictionary<string, string> args, string? authorization, CancellationToken cancel)
    {
        AuthorizationRecord? record = null;
        (int Status, string Code, string Detail)? refusal = null;
        string caller = CallerOf(owner);
        lock (_authorizationGate)
        {
            SweepAuthorizations();
            if (authorization is null || !_authorizations.TryGetValue(authorization, out record) || !SameOwner(record.Owner, owner))
            {
                record = null;
                refusal = (403, "authorization-invalid", "this change needs a fresh passkey authorization made for it (POST /api/v1/authorizations); none was found for this caller");
            }
            else if (record.State == AuthorizationState.Pending)
            {
                refusal = (403, "authorization-pending", "the passkey tap for this authorization has not been made yet");
                record = null;
            }
            else if (record.State == AuthorizationState.Refused)
            {
                refusal = (403, "authorization-refused", "the passkey tap for this authorization was refused");
                record = null;
            }
            else if (record.State == AuthorizationState.Expired)
            {
                refusal = (403, "authorization-expired", "this authorization expired; make a new one");
                record = null;
            }
            else if (record.Operation != op || record.ArgumentsKey != ArgumentsKey(args))
            {
                refusal = (403, "authorization-mismatch", "this authorization was made for another operation or other parameters");
                record = null;
            }
        }

        if (refusal is { } refused)
        {
            Refused(op, refused.Code.Replace('-', ' '), caller);

            return new MutationResult(refused.Status, refused.Code, refused.Detail);
        }

        await Task.WhenAny(record!.Done.Task, Task.Delay(LinkWait + CloseWait, cancel));
        lock (_authorizationGate)
        {
            if (record.Outcome is not { } outcome)
            {
                return new MutationResult(504, "operation-pending", "the change is still being made; ask again for the same authorization");
            }

            bool repeat = record.Answers++ > 0;
            InvitationCreatedDto? bundle = null;
            if (!repeat && outcome.Invitation is not null)
            {
                bundle = outcome.Invitation;
                record.Outcome = outcome with { Invitation = null };
                record.BundleGone = true;
            }

            return outcome with { Invitation = bundle, Repeat = repeat };
        }
    }

    /// <summary>The authorization lifetime as seconds, for the documents.</summary>
    internal static string LifetimeText => ((int)AuthorizationLifetime.TotalSeconds).ToString(CultureInfo.InvariantCulture);
}

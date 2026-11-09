using System.Globalization;
using System.Security.Cryptography;

namespace WithSecrets;

/// <summary>Where an authorization stands. It is made Pending, the passkey tap makes it Verified or Refused, and the one mutation that carries it makes it Consumed (also when that mutation is refused).</summary>
public enum AuthorizationState
{
    Pending,
    Verified,
    Refused,
    Consumed,
    Expired,
}

/// <summary>What an authorization looks like to the caller that asked for it (nothing in it authorizes anything by itself: only the verified tap does, and only for the one mutation it names).</summary>
public sealed record AuthorizationView(string Id, string Operation, AuthorizationState State, string? Detail, string? Link, string Sentence, IReadOnlyList<(string Name, string Value)> Parameters, DateTimeOffset Created, DateTimeOffset Expires);

/// <summary>What a mutation came to: applied (200), a passkey page to open for a delegated operation (202), or a refusal with its code, status and one safe line.</summary>
internal sealed record MutationResult(int Status, string? Code, string? Detail, string? Link = null)
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

    /// <summary>The most authorizations held at once (pending, verified and not yet spent).</summary>
    public const int MaxAuthorizations = 32;

    private sealed class AuthorizationRecord(string id, object owner, string operation, string argumentsKey, AdminPlan plan, DateTimeOffset created)
    {
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
        if (!isSession && !NeedsNoSession(op))
        {
            Refused(op, "no administrator session");

            return (null, new AdminStart(null, "sign in first: this needs an administrator session", 401));
        }

        if (!TakeStart(isSession ? 1 : 0))
        {
            Refused(op, "too many requests");

            return (null, new AdminStart(null, "too many requests; wait a minute", 429));
        }

        AdminPlan? plan = Plan(op, args, out string? refusal, out int refusalStatus);
        if (plan is null)
        {
            Refused(op, refusal ?? "refused");

            return (null, new AdminStart(null, refusal, refusalStatus));
        }

        string id = Convert.ToBase64String(RandomNumberGenerator.GetBytes(18)).Replace('+', '-').Replace('/', '_');
        AuthorizationRecord record = new(id, owner, op, ArgumentsKey(args), plan, _clock.GetUtcNow());
        lock (_authorizationGate)
        {
            SweepAuthorizations();
            if (_authorizations.Values.Count(Active) >= MaxAuthorizations)
            {
                if (plan.Material is not null)
                {
                    CryptographicOperations.ZeroMemory(plan.Material);
                }

                Refused(op, "too many authorizations waiting");

                return (null, new AdminStart(null, "too many authorizations are waiting; wait for them to end", 429));
            }

            _authorizations[id] = record;
        }

        void Complete(AdminAuthorization result)
        {
            lock (_authorizationGate)
            {
                if (record.State != AuthorizationState.Pending || !_authorizations.ContainsKey(id))
                {
                    return;
                }

                record.Result = result;
                record.Detail = result.Ok ? null : ApprovalSummary.Clean(result.Detail);
                record.State = result.Ok ? AuthorizationState.Verified : AuthorizationState.Refused;
                record.VerifiedAt = result.Ok ? _clock.GetUtcNow() : null;
                if (!result.Ok)
                {
                    Release(record);
                }
            }
        }

        AdminPlan asked = plan with { OnRefused = reason => Complete(new AdminAuthorization(null, reason)) };
        AdminStart started = await Run(asked, isSession, cancel, (item, asker, announce, token) =>
        {
            AdminAuthorization result = _p.Authorizer.Authorize(asker, Heading, item.Sentence, item.Operation, item.Parameters, token);
            Complete(result);
            Note(item.Operation + (result.Ok ? ": authorized" : ": refused"));

            return result.Ok ? "authorized" : result.Detail;
        }, keepMaterial: true);
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

    private AuthorizationView View(AuthorizationRecord record) => new(record.Id, record.Operation, record.State, record.Detail, record.State == AuthorizationState.Pending ? record.Link : null,
        AdminAuthorizer.PageText(record.Plan.Sentence, record.Plan.Operation, record.Plan.Parameters), record.Plan.Parameters, record.Created, record.Created.AddMinutes(ApprovalSettings.MaxTimeoutMinutes + 5));

    /// <summary>The state of an authorization, for the caller it was made for; null for an unknown one or another caller's.</summary>
    internal AuthorizationView? FindAuthorization(object owner, string id)
    {
        lock (_authorizationGate)
        {
            SweepAuthorizations();

            return _authorizations.TryGetValue(id, out AuthorizationRecord? record) && SameOwner(record.Owner, owner) ? View(record) : null;
        }
    }

    /// <summary>
    /// The mutation: spends the authorization <paramref name="authorization" /> for exactly <paramref name="op" /> and <paramref name="args" /> and applies the plan that its tap authorized. Every refusal
    /// changes nothing and is audited; a refusal after the authorization was found (another operation, other parameters, too late) spends it.
    /// </summary>
    internal async Task<MutationResult> MutateAsync(object owner, string op, IReadOnlyDictionary<string, string> args, string? authorization, CancellationToken cancel)
    {
        AuthorizationRecord? record = null;
        (int Status, string Code, string Detail)? refusal = null;
        lock (_authorizationGate)
        {
            SweepAuthorizations();
            DateTimeOffset now = _clock.GetUtcNow();
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
            else if (record.State != AuthorizationState.Verified)
            {
                refusal = (403, "authorization-used", "this authorization was already used");
                record = null;
            }
            else if (record.Operation != op || record.ArgumentsKey != ArgumentsKey(args))
            {
                refusal = (403, "authorization-mismatch", "this authorization was made for another operation or other parameters");
                record.State = AuthorizationState.Consumed;
                Release(record);
                record = null;
            }
            else
            {
                record.State = AuthorizationState.Consumed;
            }
        }

        if (refusal is { } refused)
        {
            Refused(op, refused.Code.Replace('-', ' '));

            return new MutationResult(refused.Status, refused.Code, refused.Detail);
        }

        AdminAuthorization result = record!.Result!;
        AdminPlan plan = record.Plan;
        try
        {
            if (_p.Lock.IsLocked && op != OpUnlock)
            {
                Refused(op, "the authority is locked");

                return new MutationResult(423, "authority-locked", "the authority is locked; unlock it first");
            }

            if (plan.Delegated is not null)
            {
                // The passkey pages of the operation are its own taps (each binds its own text and checks user verification); the authorization above is what let it start.
                AdminStart started = await Run(plan, owner is AdminSession, cancel);

                return started.Link is not null ? new MutationResult(202, null, null, started.Link) : new MutationResult(started.Status, "operation-refused", started.Error);
            }

            string? failure = ApplyAuthorized(plan, result, result.Admin!);

            return failure is null ? new MutationResult(200, null, null) : new MutationResult(409, "operation-failed", ApprovalSummary.Clean(failure));
        }
        finally
        {
            Release(record);
        }
    }

    /// <summary>The authorization lifetime as seconds, for the documents.</summary>
    internal static string LifetimeText => ((int)AuthorizationLifetime.TotalSeconds).ToString(CultureInfo.InvariantCulture);
}

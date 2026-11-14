using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;

namespace WithSecrets;

/// <summary>What the admin page and <c>GET /v1/status</c> report. Nothing here is sensitive.</summary>
public sealed record AuthorityStatus(bool Locked, UnlockMethod? How, UnlockPolicy Policy);

/// <summary>The answer to a request to start an operation: a link to the one-use passkey page, or why none was made.</summary>
public sealed record AdminStart(string? Link, string? Error, int Status = 200);

/// <summary>Who asks: a browser with an admin session, or one without (which may only ask for what needs no session: unlock and sign in).</summary>
public sealed record AdminCaller(AdminSession? Session);

/// <summary>What the service needs to run the administration of the authority.</summary>
public sealed record AdminServiceParts(AuthorityStore Store, AuthorityLock Lock, AdminAuthorizer Authorizer, Func<Action<string>, IAdminAsker> Askers, IUnlockProtection Protection, Action OnUnlocked, int Port,
    AuthorityKeyRing Keys, LocalAuthority Authority, HostConfigFile HostConfig, string? LocalFingerprint, IPasskeyAdmin? Passkeys, TimeProvider? Clock = null, PairingService? Pairing = null,
    ApprovalQueue? Approvals = null, Func<IProofMethod?>? ApprovalProof = null);

/// <summary>
/// The authority's administration, served by the service on its own loopback port as a small server-rendered web app (<see cref="AdminWeb" />). Everything an administrator does lives here;
/// <c>with-secrets admin</c> only prints the link.
/// <para>
/// A <b>session</b> (<see cref="AdminSessions" />) is the right to READ: status, machines, grants, audit history, settings. One fresh passkey tap starts it. It authorizes nothing
/// else: every operation on the sensitive list (a machine's trust, a grant, passkeys, settings, the authority key, lock and unlock) is its own fresh, single-use, time-limited
/// passkey tap with user verification on a one-use page whose signed text names the operation and its parameters (<see cref="AdminAuthorizer" />); a session, an earlier unlock or an earlier
/// tap never satisfies it. A request to change something also needs the anti-forgery value of its page, a same-origin request and a loopback Host. A failed or unavailable passkey is a refusal.
/// </para>
/// </summary>
public sealed partial class AdminService
{
    public const string OpUnlock = "unlock";
    public const string OpLock = "lock";
    public const string OpPolicyManual = "policy-manual";
    public const string OpPolicyUnattended = "policy-unattended";
    public const string OpLogin = "admin-login";

    private const string Heading = "Check this change to the authority. Nothing is changed unless you approve here with your passkey.";
    private static readonly TimeSpan LinkWait = TimeSpan.FromSeconds(30);

    /// <summary>How long a new operation waits for the page it replaces to close.</summary>
    private static readonly TimeSpan CloseWait = TimeSpan.FromSeconds(5);

    /// <summary>The most operations one caller (a session, or a browser's pre-session cookie) may start per minute: a local program cannot flood the passkey prompts. Every caller has its own count, and Lock has its own too.</summary>
    public const int MaxStartsPerMinute = 30;

    /// <summary>The most passkey pages that callers without a session may have waiting at once (one each). A further caller is refused; no waiting page is ever closed by another caller.</summary>
    public const int MaxAnonymousPages = 32;

    /// <summary>
    /// The most Lock pages that callers without a session may have waiting at once. Lock has lanes of its own, so no other kind of request (and no other caller's page) can use them up or close them; when the
    /// anonymous lane is full a new Lock request is NOT refused: the oldest anonymous Lock page is closed instead, so a flood of identities can only push an older page out, never keep a newer one from being made.
    /// A signed-in administrator's Lock page is in a lane no anonymous caller can touch.
    /// </summary>
    public const int MaxLockPages = 8;

    /// <summary>The most refusal rows one caller may have written per minute; refusals beyond it are counted and written as one summary row.</summary>
    public const int MaxRefusalRowsPerCaller = 20;

    private const int MaxRefusalRowsAll = 200;

    private readonly AdminServiceParts _p;
    private readonly TimeProvider _clock;
    private readonly Lock _gate = new();
    private readonly Dictionary<string, Pending> _slots = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Queue<DateTimeOffset>> _starts = new(StringComparer.Ordinal);
    private int _epoch;

    /// <summary>A test seam (internal): runs between a plan being made and its authorization or page being kept, where a lock can come in.</summary>
    internal Action? AfterPlanForTests { get; set; }
    private static long _order;
    private readonly ConcurrentQueue<string> _recent = new();

    private sealed class Pending(CancellationTokenSource cancel)
    {
        public CancellationTokenSource Cancel { get; } = cancel;

        public long Order { get; } = Interlocked.Increment(ref _order);

        public TaskCompletionSource Done { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    public AdminService(AdminServiceParts parts)
    {
        _p = parts;
        _clock = parts.Clock ?? TimeProvider.System;
        Sessions = new AdminSessions(_clock, () =>
        {
            (int idle, int absolute) = parts.Store.SessionTimeouts();

            return (TimeSpan.FromMinutes(idle), TimeSpan.FromMinutes(absolute));
        });
        // A lock ends every session and every unclaimed login, and closes every passkey page that is waiting.
        parts.Lock.OnLock(_ =>
        {
            Interlocked.Increment(ref _epoch);
            Sessions.DestroyAll();
            ClearInlineLogins();
            ClearAuthorizations();
            CancelPending();
        });
    }

    /// <summary>The sessions (service memory only).</summary>
    public AdminSessions Sessions { get; }

    internal ApprovalQueue? Approvals => _p.Approvals;

    internal IProofMethod? ApprovalProof => _p.ApprovalProof?.Invoke();

    internal ProcessedRequest? ProcessedApproval(string requestId) => _p.Store.GetProcessed(requestId);

    internal DateTimeOffset UtcNow => _clock.GetUtcNow();

    /// <summary>The HTTP side of the administration: the JSON API under <c>/api/v1/</c> (the service routes <c>/api</c> requests here).</summary>
    internal AdminApi Api => _api ??= new AdminApi(this, _p.Port);

    private AdminApi? _api;
    private sealed class RefusalWindow
    {
        public Queue<DateTimeOffset> Rows { get; } = new();

        public int Dropped { get; set; }
    }

    private readonly Dictionary<string, RefusalWindow> _refusals = new(StringComparer.Ordinal);
    private readonly Queue<DateTimeOffset> _refusalRowsAll = new();

    /// <summary>
    /// Audits a refused request (no session, no anti-forgery value, an operation that does not apply). Each caller may have 20 rows a minute written (and the whole service 200), so a program that keeps
    /// sending bad requests cannot flood the audit history, and what it does cannot hide another caller's refusals: what is not written is counted and written as one summary row per caller.
    /// </summary>
    internal void Refused(string operation, string reason, string? caller = null)
    {
        int dropped = 0;
        bool write = true;
        List<int> flushed = [];
        lock (_gate)
        {
            DateTimeOffset now = _clock.GetUtcNow();
            TimeSpan minute = TimeSpan.FromMinutes(1);
            while (_refusalRowsAll.Count > 0 && now - _refusalRowsAll.Peek() > minute)
            {
                _refusalRowsAll.Dequeue();
            }

            foreach ((string key, RefusalWindow window) in _refusals.ToList())
            {
                while (window.Rows.Count > 0 && now - window.Rows.Peek() > minute)
                {
                    window.Rows.Dequeue();
                }

                if (window.Rows.Count == 0 && key != (caller ?? "anonymous"))
                {
                    if (window.Dropped > 0)
                    {
                        flushed.Add(window.Dropped);
                    }

                    _refusals.Remove(key);
                }
            }

            string own = caller ?? "anonymous";
            if (!_refusals.TryGetValue(own, out RefusalWindow? current))
            {
                current = new RefusalWindow();
                _refusals[own] = current;
            }

            if (current.Rows.Count >= MaxRefusalRowsPerCaller || _refusalRowsAll.Count >= MaxRefusalRowsAll)
            {
                current.Dropped++;
                write = false;
            }
            else
            {
                current.Rows.Enqueue(now);
                _refusalRowsAll.Enqueue(now);
                dropped = current.Dropped;
                current.Dropped = 0;
            }
        }

        if (write)
        {
            if (dropped > 0)
            {
                _p.Authorizer.RecordRefusal("refusals", dropped.ToString(CultureInfo.InvariantCulture) + " earlier refusals from this caller were not written one by one (too many in a minute)");
            }

            _p.Authorizer.RecordRefusal(operation.Length > 40 ? operation[..40] : operation, reason);
        }

        foreach (int count in flushed)
        {
            _p.Authorizer.RecordRefusal("refusals", count.ToString(CultureInfo.InvariantCulture) + " refusals from one caller were not written one by one (too many in a minute)");
        }
    }

    /// <summary>The caller an authorization or sign-in belongs to, for rate limits and waiting pages: a session, or a browser's pre-session cookie. Never the cookie itself.</summary>
    internal static string CallerOf(object owner) => owner is AdminSession session ? "s:" + session.Id : AdminSessions.BrowserCaller((string)owner);

    /// <summary>Writes the end of the sessions that ran out (idle or absolute timeout) since the last time. Called at the start of every API request.</summary>
    internal void RecordEndedSessions()
    {
        foreach ((AdminSession session, string how) in Sessions.TakeEnded())
        {
            RecordSessionEnd(session, how);
        }
    }

    internal AdminAuthorizer Authorizer => _p.Authorizer;

    internal AuthorityStore Store => _p.Store;

    internal TimeProvider Clock => _clock;

    /// <summary>The authority's page, for the message of a refused run and the startup lines. Public; it carries nothing.</summary>
    public string PageUrl => $"http://localhost:{_p.Port}/admin";

    public AuthorityStatus Status() => new(_p.Lock.IsLocked, _p.Lock.How, _p.Store.GetUnlockPolicy());

    /// <summary>The last operations and how they ended (names and outcomes only), newest first, for the dashboard of a session.</summary>
    internal IReadOnlyList<string> Recent => [.. _recent.Reverse()];

    private void Note(string text)
    {
        _recent.Enqueue(_clock.GetUtcNow().UtcDateTime.ToString("HH:mm:ss", CultureInfo.InvariantCulture) + " " + text);
        while (_recent.Count > 10 && _recent.TryDequeue(out _))
        {
        }
    }

    /// <summary>True for the operations a browser without a session may ask for (each still needs its own fresh passkey tap): unlock (the only thing a locked authority allows) and Lock (which only restricts, so an emergency lock cannot be starved by a missing or blocked sign-in). Everything else needs a session.</summary>
    public static bool NeedsNoSession(string op) => op is OpUnlock or OpLock;

    /// <summary>Closes every passkey page that is waiting (a lock does this).</summary>
    public void CancelPending()
    {
        lock (_gate)
        {
            foreach (Pending pending in _slots.Values)
            {
                CancelQuietly(pending);
            }
        }
    }

    private static void CancelQuietly(Pending? pending)
    {
        try
        {
            pending?.Cancel.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // It ended just now.
        }
    }

    /// <summary>One start for <paramref name="key" /> (a caller, or the Lock lane of a caller); false when that caller already started 30 in the last minute. Other callers are not affected.</summary>
    private bool TakeStart(string key)
    {
        lock (_gate)
        {
            DateTimeOffset now = _clock.GetUtcNow();
            TimeSpan minute = TimeSpan.FromMinutes(1);
            if (_starts.Count > 256)
            {
                foreach (string stale in _starts.Where(item => item.Value.Count == 0 || now - item.Value.Peek() > minute && now - item.Value.Last() > minute).Select(item => item.Key).ToList())
                {
                    _starts.Remove(stale);
                }
            }

            if (!_starts.TryGetValue(key, out Queue<DateTimeOffset>? queue))
            {
                queue = new Queue<DateTimeOffset>();
                _starts[key] = queue;
            }

            while (queue.Count > 0 && now - queue.Peek() > minute)
            {
                queue.Dequeue();
            }

            if (queue.Count >= MaxStartsPerMinute)
            {
                return false;
            }

            queue.Enqueue(now);

            return true;
        }
    }

    /// <summary>
    /// Shows one passkey page for <paramref name="caller" />. Each caller has one waiting page (a new request from the same caller replaces its own earlier page, never another caller's) and the callers
    /// without a session share a limited number (a further one is refused, nothing waiting is closed). Lock pages have a lane of their own that nothing else uses up. <paramref name="epoch" /> is the lock
    /// count from before the plan was made: a lock since then ends the request.
    /// </summary>
    private async Task<AdminStart> Run(AdminPlan plan, string caller, int epoch, CancellationToken cancel, Func<AdminPlan, IAdminAsker, Action<string>, CancellationToken, string>? execute = null, bool keepMaterial = false, Action? afterPage = null)
    {
        bool lockLane = plan.Operation == "lock-authority";
        string slot = (lockLane ? "L" : "") + caller;
        CancellationTokenSource source = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken.None);
        Pending pending = new(source);
        Pending? before;
        AdminStart? refused = null;
        lock (_gate)
        {
            _slots.TryGetValue(slot, out before);
            if (Volatile.Read(ref _epoch) != epoch)
            {
                refused = new AdminStart(null, "the authority was locked while this was being started", 423);
            }
            else if (before is null && !lockLane && caller.StartsWith("b:", StringComparison.Ordinal) && _slots.Keys.Count(key => key.StartsWith("b:", StringComparison.Ordinal)) >= MaxAnonymousPages)
            {
                refused = new AdminStart(null, "too many passkey pages are waiting for browsers that are not signed in; wait for them to end", 429);
            }
            else
            {
                CancelQuietly(before);
                if (before is null && lockLane && caller.StartsWith("b:", StringComparison.Ordinal))
                {
                    // The anonymous Lock lane is full: the oldest page there makes room (a new Lock request is never the one refused).
                    List<KeyValuePair<string, Pending>> lane = [.. _slots.Where(item => item.Key.StartsWith("Lb:", StringComparison.Ordinal)).OrderBy(item => item.Value.Order)];
                    for (int i = 0; lane.Count - i >= MaxLockPages; i++)
                    {
                        CancelQuietly(lane[i].Value);
                        _slots.Remove(lane[i].Key);
                    }
                }

                _slots[slot] = pending;
            }
        }

        if (refused is not null)
        {
            source.Dispose();

            return refused;
        }

        if (before is not null)
        {
            await Task.WhenAny(before.Done.Task, Task.Delay(CloseWait, cancel));
        }

        TaskCompletionSource<string> link = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Action<string> announce = text =>
        {
            if (text.Contains("http", StringComparison.Ordinal))
            {
                link.TrySetResult(text);
            }
            else
            {
                TerminalPrompt.Line(text);
            }
        };
        IAdminAsker asker = _p.Askers(announce);
        CancellationToken token = source.Token;
        _ = Task.Run(() =>
        {
            try
            {
                string outcome = execute is null ? Execute(plan, asker, announce, token) : execute(plan, asker, announce, token);
                link.TrySetResult("done: " + outcome);
            }
            catch (Exception error) when (error is not OutOfMemoryException)
            {
                AppLog.Warn("an administrator operation failed unexpectedly: {Type}", error.GetType().Name);
                plan.OnRefused?.Invoke("the operation failed");
                link.TrySetResult("done: the operation failed");
            }
            finally
            {
                if (plan.Material is not null && !keepMaterial)
                {
                    CryptographicOperations.ZeroMemory(plan.Material);
                }

                lock (_gate)
                {
                    if (_slots.TryGetValue(slot, out Pending? held) && ReferenceEquals(held, pending))
                    {
                        _slots.Remove(slot);
                    }
                }

                source.Dispose();
                pending.Done.TrySetResult();
                afterPage?.Invoke();
            }
        }, CancellationToken.None);

        Task first = await Task.WhenAny(link.Task, Task.Delay(LinkWait, cancel));
        if (first != link.Task)
        {
            CancelQuietly(pending);

            return new AdminStart(null, "the passkey page was not made in time", 504);
        }

        string text = link.Task.Result;
        if (text.StartsWith("done: ", StringComparison.Ordinal))
        {
            // Finished without a page: the asker refused (for example no passkey is enrolled), so nothing changed.
            return new AdminStart(null, text["done: ".Length..], 409);
        }

        int at = text.IndexOf("http", StringComparison.Ordinal);

        return at < 0 ? new AdminStart(null, "the passkey page was not made", 500) : new AdminStart(text[at..], null);
    }

    /// <summary>Runs a plan to its end: the tap, the check, the change. Returns the one line for the person.</summary>
    private string Execute(AdminPlan plan, IAdminAsker asker, Action<string> announce, CancellationToken cancel)
    {
        if (plan.Delegated is { } delegated)
        {
            // An operation whose own pages are the taps (adding and removing a passkey): audited here, each page binds its own text and checks user verification.
            if (!_p.Authorizer.Record(plan.Operation, "requested", "", AdminAuthorizer.Canonical(plan.Parameters)))
            {
                return "the audit history cannot be written, so nothing was started";
            }

            (bool ok, string detail, string actor) = delegated(announce, () => cancel.IsCancellationRequested ? "the request was cancelled" : _p.Lock.IsLocked ? "the authority is locked" : null);
            _p.Authorizer.Record(plan.Operation, ok ? "applied" : "refused: " + ApprovalSummary.Clean(detail), ok ? actor : "", AdminAuthorizer.Canonical(plan.Parameters));
            Note(plan.Operation + (ok ? ": applied" : ": refused"));

            return detail;
        }

        AdminAuthorization authorized = _p.Authorizer.Authorize(asker, Heading, plan.Sentence, plan.Operation, plan.Parameters, cancel);
        if (authorized.Admin is not { } admin)
        {
            Note(plan.Operation + ": refused");
            plan.OnRefused?.Invoke(authorized.Detail);

            return authorized.Detail;
        }

        string? failure = ApplyAuthorized(plan, authorized, admin);

        return failure ?? "applied";
    }

    /// <summary>
    /// Applies a plan after its verified tap: the lock is re-checked first (nothing is applied by a locked authority, except the unlock itself), a failure becomes one safe line, and the
    /// outcome is audited. Returns null when it was applied, else why not.
    /// </summary>
    private string? ApplyAuthorized(AdminPlan plan, AdminAuthorization authorized, VerifiedAdmin admin)
    {
        string? failure;
        try
        {
            if (_p.Lock.IsLocked && plan.Operation != "unlock-authority")
            {
                throw new AuthorityLockedException();
            }

            failure = plan.Apply(authorized);
        }
        catch (AuthorityLockedException)
        {
            failure = "the authority is locked";
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            AppLog.Warn("an administrator change failed: {Type}", error.GetType().Name);
            failure = error is AuthorityDatabaseException ? "the authority database could not be written" : "the change failed";
        }

        _p.Authorizer.Outcome(admin, failure is null ? "applied" : "failed: " + ApprovalSummary.Clean(failure));
        Note(plan.Operation + (failure is null ? ": applied" : ": failed"));

        return failure;
    }

    // ---- signing in ----

    /// <summary>
    /// Starts a browser login. Any enrolled passkey may sign in; the trusted credential record determines whether the claimed session has admin or approval scope.
    /// The browser that began the login claims the session (<see cref="AdminSessions.Claim" />). Refused while the authority is locked.
    /// </summary>
    public async Task<(AdminStart Start, string? Ticket)> BeginLoginAsync(string browserId, CancellationToken cancel)
    {
        string caller = AdminSessions.BrowserCaller(browserId);
        int epoch = Volatile.Read(ref _epoch);
        if (!TakeStart(caller))
        {
            Refused(OpLogin, "too many requests", caller);

            return (new AdminStart(null, "too many requests; wait a minute", 429), null);
        }

        if (_p.Lock.IsLocked)
        {
            Refused(OpLogin, "the authority is locked", caller);

            return (new AdminStart(null, "the authority is locked: unlock it first (no session starts on a locked authority)", 423), null);
        }

        if (Sessions.BeginLogin(browserId) is not { } begun)
        {
            Refused(OpLogin, "too many sign-ins waiting", caller);

            return (new AdminStart(null, "too many sign-ins are waiting; wait for them to end", 429), null);
        }

        (string ticket, string code) = begun;
        AfterPlanForTests?.Invoke();
        (int idle, int absolute) = _p.Store.SessionTimeouts();
        AdminPlan plan = new(OpLogin, "start a read-only browser session on the administration app. Its capabilities are determined by the enrolled passkey that signs in; it changes nothing, and every administrative change requires its own passkey tap. Session access lasts up to "
            + absolute.ToString(CultureInfo.InvariantCulture) + " minutes, ending after " + idle.ToString(CultureInfo.InvariantCulture) + " minutes without use; it changes nothing and every change still needs its own passkey tap",
            [("login", code)],
            authorization =>
            {
                VerifiedCredential? credential = authorization.Credential;
                string identity = credential?.Name ?? (authorization.Admin!.Signer.Length > 0 ? authorization.Admin.Signer : "(unnamed)");
                Sessions.CompleteLogin(code, identity, null, credential is null ? SessionScope.Approval : SessionCapabilities.FromAdminFlag(credential.Admin));

                return null;
            },
            OnRefused: reason => Sessions.CompleteLogin(code, null, reason));
        AdminStart started = await Run(plan, caller, epoch, cancel);
        if (started.Link is null)
        {
            Sessions.Forget(ticket, browserId);
        }

        return (started, started.Link is not null ? ticket : null);
    }

    /// <summary>Called once a browser's scoped session starts: the start is audited durably (no secret in it).</summary>
    public void RecordSessionStart(AdminSession session)
    {
        _p.Authorizer.Record("admin-session", "started", "passkey " + ApprovalSummary.Clean(session.Identity), "");
        Note("admin session started");
    }

    public void RecordSessionEnd(AdminSession session, string how)
    {
        _p.Authorizer.Record("admin-session", how, "passkey " + ApprovalSummary.Clean(session.Identity), "");
    }
}

/// <summary>One operation as it will be asked and applied: its name, the sentence the person reads, its parameters (all of them are signed), and what runs after the verified tap.</summary>
internal sealed record AdminPlan(string Operation, string Sentence, IReadOnlyList<(string Name, string Value)> Parameters, Func<AdminAuthorization, string?> Apply, byte[]? Material = null,
    Func<Action<string>, Func<string?>, (bool Ok, string Detail, string Actor)>? Delegated = null, Action<string>? OnRefused = null, System.Runtime.CompilerServices.StrongBox<InvitationCreatedDto?>? Output = null);

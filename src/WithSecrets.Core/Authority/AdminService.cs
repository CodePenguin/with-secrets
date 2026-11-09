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
    AuthorityKeyRing Keys, LocalAuthority Authority, HostConfigFile HostConfig, string? LocalFingerprint, IPasskeyAdmin? Passkeys, TimeProvider? Clock = null);

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

    /// <summary>The most operations a caller may start per minute: a local program cannot flood the audit history or the passkey prompts. Session callers and others count apart, so one cannot use up the other's.</summary>
    public const int MaxStartsPerMinute = 30;

    private readonly AdminServiceParts _p;
    private readonly TimeProvider _clock;
    private readonly Lock _gate = new();
    private readonly Pending?[] _slots = new Pending?[2];
    private readonly Queue<DateTimeOffset>[] _starts = [new(), new()];
    private readonly ConcurrentQueue<string> _recent = new();

    private sealed class Pending(CancellationTokenSource cancel)
    {
        public CancellationTokenSource Cancel { get; } = cancel;

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
            Sessions.DestroyAll();
            ClearAuthorizations();
            CancelPending();
        });
    }

    /// <summary>The sessions (service memory only).</summary>
    public AdminSessions Sessions { get; }

    /// <summary>The HTTP side of the administration: the JSON API under <c>/api/v1/</c> (the service routes <c>/api</c> requests here).</summary>
    internal AdminApi Api => _api ??= new AdminApi(this, _p.Port);

    private AdminApi? _api;
    private readonly Queue<DateTimeOffset> _refusalRows = new();

    /// <summary>
    /// Audits a refused request (no session, no anti-forgery value, an operation that does not apply). At most 20 rows a minute, so a program that keeps sending bad requests cannot flood the
    /// audit history; a refusal is a refusal whether or not it was written.
    /// </summary>
    internal void Refused(string operation, string reason)
    {
        lock (_gate)
        {
            DateTimeOffset now = _clock.GetUtcNow();
            while (_refusalRows.Count > 0 && now - _refusalRows.Peek() > TimeSpan.FromMinutes(1))
            {
                _refusalRows.Dequeue();
            }

            if (_refusalRows.Count >= 20)
            {
                return;
            }

            _refusalRows.Enqueue(now);
        }

        _p.Authorizer.RecordRefusal(operation.Length > 40 ? operation[..40] : operation, reason);
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

    /// <summary>True for the operation a browser without a session may ask for: unlock (the only thing a locked authority allows). Everything else needs a session.</summary>
    public static bool NeedsNoSession(string op) => op == OpUnlock;

    /// <summary>Closes every passkey page that is waiting (a lock does this, and so does a new request from the admin app).</summary>
    public void CancelPending()
    {
        lock (_gate)
        {
            foreach (Pending? pending in _slots)
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

    private bool TakeStart(int slot)
    {
        lock (_gate)
        {
            DateTimeOffset now = _clock.GetUtcNow();
            Queue<DateTimeOffset> queue = _starts[slot];
            while (queue.Count > 0 && now - queue.Peek() > TimeSpan.FromMinutes(1))
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

    private async Task<AdminStart> Run(AdminPlan plan, bool isSession, CancellationToken cancel, Func<AdminPlan, IAdminAsker, Action<string>, CancellationToken, string>? execute = null, bool keepMaterial = false)
    {
        int slot = isSession ? 1 : 0;
        CancellationTokenSource source = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken.None);
        Pending pending = new(source);
        Pending?[] before;
        lock (_gate)
        {
            before = plan.Operation == "lock-authority" ? [.. _slots] : [_slots[slot]];
            foreach (Pending? old in before)
            {
                CancelQuietly(old);
            }

            _slots[slot] = pending;
        }

        foreach (Pending? old in before.Where(item => item is not null))
        {
            await Task.WhenAny(old!.Done.Task, Task.Delay(CloseWait, cancel));
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
                link.TrySetResult("done: the operation failed (" + error.GetType().Name + ")");
            }
            finally
            {
                if (plan.Material is not null && !keepMaterial)
                {
                    CryptographicOperations.ZeroMemory(plan.Material);
                }

                lock (_gate)
                {
                    if (ReferenceEquals(_slots[slot], pending))
                    {
                        _slots[slot] = null;
                    }
                }

                source.Dispose();
                pending.Done.TrySetResult();
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

            (bool ok, string detail, string actor) = delegated(announce);
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
            failure = error is AuthorityDatabaseException ? error.Message : "the change failed (" + error.GetType().Name + ")";
        }

        _p.Authorizer.Outcome(admin, failure is null ? "applied" : "failed: " + ApprovalSummary.Clean(failure));
        Note(plan.Operation + (failure is null ? ": applied" : ": failed"));

        return failure;
    }

    // ---- signing in ----

    /// <summary>
    /// Starts a login for a browser: the tap (one fresh passkey page whose signed text names this login) proves an administrator is here, and the browser that began the login then claims its
    /// session (<see cref="AdminSessions.Claim" />). Refused while the authority is locked (it can only be unlocked).
    /// </summary>
    public async Task<(AdminStart Start, string? Ticket)> BeginLoginAsync(CancellationToken cancel)
    {
        if (!TakeStart(0))
        {
            Refused(OpLogin, "too many requests");

            return (new AdminStart(null, "too many requests; wait a minute", 429), null);
        }

        if (_p.Lock.IsLocked)
        {
            Refused(OpLogin, "the authority is locked");

            return (new AdminStart(null, "the authority is locked: unlock it first (no session starts on a locked authority)", 423), null);
        }

        (string ticket, string code) = Sessions.BeginLogin();
        (int idle, int absolute) = _p.Store.SessionTimeouts();
        AdminPlan plan = new("admin-session", "start an administrator session on the admin web app. Only tap if you just chose to sign in there yourself. The session lets this browser READ (status, machines, grants, audit, settings) for up to "
            + absolute.ToString(CultureInfo.InvariantCulture) + " minutes, ending after " + idle.ToString(CultureInfo.InvariantCulture) + " minutes without use; it changes nothing and every change still needs its own passkey tap",
            [("login", code)],
            authorization =>
            {
                Sessions.CompleteLogin(code, authorization.Admin!.Signer.Length > 0 ? authorization.Admin.Signer : "(unnamed)", null);

                return null;
            },
            OnRefused: reason => Sessions.CompleteLogin(code, null, reason));
        AdminStart started = await Run(plan, false, cancel);

        return (started, started.Link is not null ? ticket : null);
    }

    /// <summary>Called once a browser's session starts: the start is audited durably (no secret in it).</summary>
    public void RecordSessionStart(AdminSession session)
    {
        _p.Authorizer.Record("admin-session", "started", "admin passkey " + session.Admin, "");
        Note("admin session started");
    }

    public void RecordSessionEnd(AdminSession session, string how)
    {
        _p.Authorizer.Record("admin-session", how, "admin passkey " + session.Admin, "");
    }
}

/// <summary>One operation as it will be asked and applied: its name, the sentence the person reads, its parameters (all of them are signed), and what runs after the verified tap.</summary>
internal sealed record AdminPlan(string Operation, string Sentence, IReadOnlyList<(string Name, string Value)> Parameters, Func<AdminAuthorization, string?> Apply, byte[]? Material = null,
    Func<Action<string>, (bool Ok, string Detail, string Actor)>? Delegated = null, Action<string>? OnRefused = null);

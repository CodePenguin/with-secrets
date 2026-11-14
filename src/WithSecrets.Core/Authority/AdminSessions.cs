using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace WithSecrets;

/// <summary>An administrator's session on the admin web app. It authorizes read-only views and nothing else: every change still needs its own fresh passkey tap.</summary>
public sealed class AdminSession
{
    internal AdminSession(string token, string identity, SessionScope scope, DateTimeOffset started, string csrf)
    {
        Token = token;
        Csrf = csrf;
        Id = Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
        Identity = identity;
        Scope = scope;
        Started = started;
        LastSeen = started;
    }

    /// <summary>The random value the browser holds in its cookie. Never shown on a page, never logged.</summary>
    internal string Token { get; }

    /// <summary>
    /// The second secret of the session: a random value given once, in the answer that claims the session, to the page that began the sign-in. It is kept in the page (per origin, so another program on
    /// another localhost port that is sent the cookie does not have it) and sent in a header with every request; the cookie alone is not enough. It is never derived again or shown a second time.
    /// </summary>
    internal string Csrf { get; }

    /// <summary>A short random name for this session (rate limits and waiting pages are kept per caller). Not secret and not the token.</summary>
    internal string Id { get; }

    /// <summary>The trusted enrolled credential identity that signed in (a name, no key material).</summary>
    public string Identity { get; }

    /// <summary>Compatibility alias for existing admin-only display/audit code; authorization uses <see cref="Scope" />.</summary>
    public string Admin => Identity;

    /// <summary>The server-derived capabilities of the credential that signed in.</summary>
    public SessionScope Scope { get; }

    public DateTimeOffset Started { get; }

    internal DateTimeOffset LastSeen { get; set; }
}

/// <summary>Where a login attempt stands (see <see cref="AdminSessions.BeginLogin" />).</summary>
public enum LoginState
{
    Unknown,
    Waiting,
    Failed,
    Ready,
}

/// <summary>
/// The admin sessions, in the service's memory only (never written anywhere, so a restart or a lock ends every one). A session starts when an administrator's fresh passkey tap
/// (user verification, a one-use page whose signed text names this login) has been verified, and the browser that began the login claims it: the random token goes to that browser in an
/// HttpOnly, SameSite=Strict cookie and nowhere else. It ends at the idle timeout (each use renews it), at the absolute timeout, on logout, on lock and when the service stops.
/// A session never authorizes a change; it is only the right to read. A session is the cookie AND a second random secret (<see cref="AdminSession.Csrf" />) that is given once, in the answer that claims
/// the session, and sent as a header: a program that is only sent the cookie (cookies are not isolated by port on localhost) cannot read or use the session. Before a session the browser's pre-session
/// cookie has its own anti-forgery value (an HMAC of the cookie under a key made at start), given once when the cookie is made.
/// </summary>
public sealed class AdminSessions(TimeProvider clock, Func<(TimeSpan Idle, TimeSpan Absolute)> timeouts)
{
    public const string SessionCookie = "ws_session";
    public const string LoginCookie = "ws_login";
    public const string BrowserCookie = "ws_pre";

    /// <summary>The most sessions at once and the most unclaimed logins; more are refused, oldest first for logins.</summary>
    public const int MaxSessions = 8;

    public const int MaxLogins = 32;

    internal static readonly TimeSpan LoginLifetime = TimeSpan.FromMinutes(ApprovalSettings.MaxTimeoutMinutes + 5);

    private sealed class Login(string code, string browserKey, DateTimeOffset created)
    {
        /// <summary>The browser (its pre-session cookie, hashed) that began this login: only it may read or claim it.</summary>
        public string BrowserKey { get; } = browserKey;

        public string Code { get; } = code;

        public DateTimeOffset Created { get; } = created;

        public LoginState State { get; set; } = LoginState.Waiting;

        public string? Identity { get; set; }

        public SessionScope Scope { get; set; } = SessionScope.Admin;

        public string? Problem { get; set; }
    }

    private readonly Lock _lock = new();
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    private readonly Dictionary<string, AdminSession> _sessions = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Login> _logins = new(StringComparer.Ordinal);
    private readonly System.Collections.Concurrent.ConcurrentQueue<(AdminSession Session, string How)> _ended = new();

    /// <summary>The sessions that ran out (idle or absolute timeout) since the last call, with how, so that the service can audit them.</summary>
    public IReadOnlyList<(AdminSession Session, string How)> TakeEnded()
    {
        List<(AdminSession, string)> taken = [];
        while (_ended.TryDequeue(out (AdminSession Session, string How) item))
        {
            taken.Add(item);
        }

        return taken;
    }

    /// <summary>The number of live sessions (the expired ones are dropped first).</summary>
    public int Count
    {
        get
        {
            lock (_lock)
            {
                Sweep();

                return _sessions.Count;
            }
        }
    }

    private static string KeyOf(string token) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    private static string NewToken() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));

    private void Sweep()
    {
        DateTimeOffset now = clock.GetUtcNow();
        (TimeSpan idle, TimeSpan absolute) = timeouts();
        foreach (string key in _sessions.Where(item => Expired(item.Value, now, idle, absolute)).Select(item => item.Key).ToList())
        {
            AdminSession ended = _sessions[key];
            _ended.Enqueue((ended, now - ended.Started >= absolute ? "ended: absolute timeout" : "ended: idle timeout"));
            _sessions.Remove(key);
        }

        foreach (string key in _logins.Where(item => now - item.Value.Created > LoginLifetime).Select(item => item.Key).ToList())
        {
            _logins.Remove(key);
        }
    }

    private static bool Expired(AdminSession session, DateTimeOffset now, TimeSpan idle, TimeSpan absolute) => now - session.LastSeen >= idle || now - session.Started >= absolute;

    /// <summary>
    /// The live session of a cookie value, renewed for the idle timeout; null for none, an expired one, a made-up value, or a cookie presented without the session's own secret
    /// (<paramref name="presented" />, from the header the page sends). A cookie replayed alone renews nothing and finds nothing.
    /// </summary>
    public AdminSession? Validate(string? token, string? presented)
    {
        if (string.IsNullOrEmpty(token) || token.Length > 128 || string.IsNullOrEmpty(presented) || presented.Length > 128)
        {
            return null;
        }

        lock (_lock)
        {
            Sweep();
            if (!_sessions.TryGetValue(KeyOf(token), out AdminSession? session) || !CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(session.Csrf), Encoding.UTF8.GetBytes(presented)))
            {
                return null;
            }

            session.LastSeen = clock.GetUtcNow();

            return session;
        }
    }

    /// <summary>Ends the session of a cookie value (logout). Unknown values are ignored.</summary>
    public void Destroy(string? token)
    {
        if (string.IsNullOrEmpty(token))
        {
            return;
        }

        lock (_lock)
        {
            _sessions.Remove(KeyOf(token));
        }
    }

    /// <summary>Ends every session and every unclaimed login (the authority locked).</summary>
    public int DestroyAll()
    {
        lock (_lock)
        {
            int ended = _sessions.Count;
            _sessions.Clear();
            _logins.Clear();

            return ended;
        }
    }

    /// <summary>
    /// A login attempt of the browser <paramref name="browserId" /> (its pre-session cookie): returns the ticket the browser keeps in its login cookie and the short code that the passkey page shows and
    /// signs, so the tap is for this attempt. A browser has one login at a time (a new one replaces its own earlier one, never another browser's). Null when too many logins are waiting: the new one is
    /// refused, no waiting login is ever evicted by another caller.
    /// </summary>
    public (string Ticket, string Code)? BeginLogin(string browserId)
    {
        lock (_lock)
        {
            Sweep();
            string browserKey = KeyOf(browserId);
            foreach (string own in _logins.Where(item => item.Value.BrowserKey == browserKey).Select(item => item.Key).ToList())
            {
                _logins.Remove(own);
            }

            if (_logins.Count >= MaxLogins)
            {
                return null;
            }

            string ticket = NewToken();
            string code = Convert.ToHexString(RandomNumberGenerator.GetBytes(4));
            _logins[KeyOf(ticket)] = new Login(code, browserKey, clock.GetUtcNow());

            return (ticket, code);
        }
    }

    /// <summary>The tap for a login was verified (<paramref name="admin" /> is the key's name) or refused (<paramref name="problem" />).</summary>
    public void CompleteLogin(string code, string? identity, string? problem, SessionScope scope = SessionScope.Admin)
    {
        lock (_lock)
        {
            Login? login = _logins.Values.FirstOrDefault(item => item.Code == code);
            if (login is null)
            {
                return;
            }

            login.Identity = identity;
            login.Scope = scope;
            login.Problem = problem;
            login.State = identity is null ? LoginState.Failed : LoginState.Ready;
        }
    }

    public (LoginState State, string? Problem) LoginStatus(string? ticket, string? browserId)
    {
        if (string.IsNullOrEmpty(ticket) || ticket.Length > 128 || string.IsNullOrEmpty(browserId) || browserId.Length > 128)
        {
            return (LoginState.Unknown, null);
        }

        lock (_lock)
        {
            Sweep();

            return _logins.TryGetValue(KeyOf(ticket), out Login? login) && login.BrowserKey == KeyOf(browserId) ? (login.State, login.Problem) : (LoginState.Unknown, null);
        }
    }

    /// <summary>
    /// The browser that began a login comes back with its ticket: when the tap was verified the session is made now (one claim per ticket) and the ticket is spent. Null when the login
    /// is unknown, still waiting, failed, or too many sessions are live.
    /// </summary>
    public AdminSession? Claim(string? ticket, string? browserId)
    {
        if (string.IsNullOrEmpty(ticket) || ticket.Length > 128 || string.IsNullOrEmpty(browserId) || browserId.Length > 128)
        {
            return null;
        }

        lock (_lock)
        {
            Sweep();
            string key = KeyOf(ticket);
            if (!_logins.TryGetValue(key, out Login? login) || login.BrowserKey != KeyOf(browserId) || login.State != LoginState.Ready || login.Identity is null)
            {
                return null;
            }

            _logins.Remove(key);
            if (_sessions.Count >= MaxSessions)
            {
                string oldest = _sessions.OrderBy(item => item.Value.LastSeen).First().Key;
                _sessions.Remove(oldest);
            }

            string token = NewToken();
            AdminSession session = new(token, login.Identity, login.Scope, clock.GetUtcNow(), NewToken());
            _sessions[KeyOf(token)] = session;

            return session;
        }
    }

    /// <summary>Forgets a login that did not finish (its cookie is dropped by the caller).</summary>
    public void Forget(string? ticket, string? browserId)
    {
        if (string.IsNullOrEmpty(ticket) || string.IsNullOrEmpty(browserId))
        {
            return;
        }

        lock (_lock)
        {
            if (_logins.TryGetValue(KeyOf(ticket), out Login? login) && login.BrowserKey == KeyOf(browserId))
            {
                _logins.Remove(KeyOf(ticket));
            }
        }
    }

    /// <summary>A short name for a browser's pre-session cookie, for rate limits and waiting pages (a hash; the cookie value itself is not kept).</summary>
    public static string BrowserCaller(string browserId) => "b:" + KeyOf(browserId)[..16];

    /// <summary>A fresh random value for the browser's pre-session cookie.</summary>
    public static string NewBrowserId() => NewToken();

    /// <summary>The anti-forgery value for a cookie value: <paramref name="purpose" /> is "session" for a session token and "browser" before a session.</summary>
    public string AntiForgery(string purpose, string cookieValue)
    {
        using HMACSHA256 mac = new(_key);

        return Base64Url.EncodeToString(mac.ComputeHash(Encoding.UTF8.GetBytes("with-secrets admin anti-forgery v1\n" + purpose + "\n" + cookieValue)));
    }

    /// <summary>True when <paramref name="presented" /> is the anti-forgery value of the cookie (compared in constant time).</summary>
    public bool AntiForgeryMatches(string purpose, string? cookieValue, string? presented)
    {
        if (string.IsNullOrEmpty(cookieValue) || string.IsNullOrEmpty(presented) || presented.Length > 128 || cookieValue.Length > 128)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(AntiForgery(purpose, cookieValue)), Encoding.UTF8.GetBytes(presented));
    }
}

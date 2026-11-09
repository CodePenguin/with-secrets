using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace WithSecrets;

/// <summary>An administrator's session on the admin web app. It authorizes read-only views and nothing else: every change still needs its own fresh passkey tap.</summary>
public sealed class AdminSession
{
    internal AdminSession(string token, string admin, DateTimeOffset started)
    {
        Token = token;
        Admin = admin;
        Started = started;
        LastSeen = started;
    }

    /// <summary>The random value the browser holds in its cookie. Never shown on a page, never logged.</summary>
    internal string Token { get; }

    /// <summary>The admin key that tapped to start it (a name, no key material).</summary>
    public string Admin { get; }

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
/// A session never authorizes a change; it is only the right to read. The anti-forgery value of a page is an HMAC of the session token (or, before a session, of the
/// browser's pre-session cookie) under a key made at start, so it cannot be computed without the cookie and cannot be reused for another browser.
/// </summary>
public sealed class AdminSessions(TimeProvider clock, Func<(TimeSpan Idle, TimeSpan Absolute)> timeouts)
{
    public const string SessionCookie = "ws_session";
    public const string LoginCookie = "ws_login";
    public const string BrowserCookie = "ws_pre";

    /// <summary>The most sessions at once and the most unclaimed logins; more are refused, oldest first for logins.</summary>
    public const int MaxSessions = 8;

    public const int MaxLogins = 8;

    private static readonly TimeSpan LoginLifetime = TimeSpan.FromMinutes(ApprovalSettings.MaxTimeoutMinutes + 5);

    private sealed class Login(string code, DateTimeOffset created)
    {
        public string Code { get; } = code;

        public DateTimeOffset Created { get; } = created;

        public LoginState State { get; set; } = LoginState.Waiting;

        public string? Admin { get; set; }

        public string? Problem { get; set; }
    }

    private readonly Lock _lock = new();
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    private readonly Dictionary<string, AdminSession> _sessions = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Login> _logins = new(StringComparer.Ordinal);

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
            _sessions.Remove(key);
        }

        foreach (string key in _logins.Where(item => now - item.Value.Created > LoginLifetime).Select(item => item.Key).ToList())
        {
            _logins.Remove(key);
        }
    }

    private static bool Expired(AdminSession session, DateTimeOffset now, TimeSpan idle, TimeSpan absolute) => now - session.LastSeen >= idle || now - session.Started >= absolute;

    /// <summary>The live session of a cookie value, renewed for the idle timeout; null for none, an expired one or a made-up value.</summary>
    public AdminSession? Validate(string? token)
    {
        if (string.IsNullOrEmpty(token) || token.Length > 128)
        {
            return null;
        }

        lock (_lock)
        {
            Sweep();
            if (!_sessions.TryGetValue(KeyOf(token), out AdminSession? session))
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
    /// A login attempt: returns the ticket the browser keeps in its login cookie and the short code that the passkey page shows and signs, so the tap is for this attempt. Null when
    /// too many are waiting (the oldest is replaced, so an unclaimed flood cannot block a real login).
    /// </summary>
    public (string Ticket, string Code) BeginLogin()
    {
        lock (_lock)
        {
            Sweep();
            while (_logins.Count >= MaxLogins)
            {
                string oldest = _logins.OrderBy(item => item.Value.Created).First().Key;
                _logins.Remove(oldest);
            }

            string ticket = NewToken();
            string code = Convert.ToHexString(RandomNumberGenerator.GetBytes(4));
            _logins[KeyOf(ticket)] = new Login(code, clock.GetUtcNow());

            return (ticket, code);
        }
    }

    /// <summary>The tap for a login was verified (<paramref name="admin" /> is the key's name) or refused (<paramref name="problem" />).</summary>
    public void CompleteLogin(string code, string? admin, string? problem)
    {
        lock (_lock)
        {
            Login? login = _logins.Values.FirstOrDefault(item => item.Code == code);
            if (login is null)
            {
                return;
            }

            login.Admin = admin;
            login.Problem = problem;
            login.State = admin is null ? LoginState.Failed : LoginState.Ready;
        }
    }

    public (LoginState State, string? Problem) LoginStatus(string? ticket)
    {
        if (string.IsNullOrEmpty(ticket) || ticket.Length > 128)
        {
            return (LoginState.Unknown, null);
        }

        lock (_lock)
        {
            Sweep();

            return _logins.TryGetValue(KeyOf(ticket), out Login? login) ? (login.State, login.Problem) : (LoginState.Unknown, null);
        }
    }

    /// <summary>
    /// The browser that began a login comes back with its ticket: when the tap was verified the session is made now (one claim per ticket) and the ticket is spent. Null when the login
    /// is unknown, still waiting, failed, or too many sessions are live.
    /// </summary>
    public AdminSession? Claim(string? ticket)
    {
        if (string.IsNullOrEmpty(ticket) || ticket.Length > 128)
        {
            return null;
        }

        lock (_lock)
        {
            Sweep();
            string key = KeyOf(ticket);
            if (!_logins.TryGetValue(key, out Login? login) || login.State != LoginState.Ready || login.Admin is null)
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
            AdminSession session = new(token, login.Admin, clock.GetUtcNow());
            _sessions[KeyOf(token)] = session;

            return session;
        }
    }

    /// <summary>Forgets a login that did not finish (its cookie is dropped by the caller).</summary>
    public void Forget(string? ticket)
    {
        if (string.IsNullOrEmpty(ticket))
        {
            return;
        }

        lock (_lock)
        {
            _logins.Remove(KeyOf(ticket));
        }
    }

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

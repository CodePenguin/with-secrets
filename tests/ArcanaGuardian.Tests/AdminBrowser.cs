using System.Net;
using System.Text;
using System.Text.Json;

namespace ArcanaGuardian.Tests;

/// <summary>
/// What one operation of the administration API came to when the test acted as the person: the authorization request, the passkey page and the tap, and (when the tap was approved and judged good) the
/// mutation that carried the authorization.
/// </summary>
internal sealed record Tapped(int PostStatus, string? Link, string? Error, int ApproveStatus, string PageUrl, string ProofBody, string Page = "", string? AuthorizationId = null, int MutationStatus = 0, string MutationBody = "");

/// <summary>
/// A browser, for tests of the administration API: it keeps cookies, keeps (as the page does, in memory) the secret that <c>POST /api/v1/browser</c> gives before a session and the one that
/// <c>POST /api/v1/session/claim</c> gives for the session, sends the right one as the header, sends the Origin a page sends, and acts as the person on the passkey pages with a software authenticator.
/// Each of those can be left out or changed to test the refusals.
/// </summary>
internal sealed class AdminBrowser(HostService service, HttpClient http)
{
    private readonly Dictionary<string, string> _cookies = new(StringComparer.Ordinal);
    private readonly HttpClient _web = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false, UseCookies = false }) { Timeout = TimeSpan.FromSeconds(60) };

    /// <summary>The secret given once with the browser's pre-session cookie (<c>POST /browser</c>).</summary>
    public string? BrowserToken { get; set; }

    /// <summary>The session's own secret, given once by <c>POST /session/claim</c>.</summary>
    public string? SessionToken { get; set; }

    /// <summary>What the page sends as X-Admin-Token: the session's secret while it has one, else the browser's.</summary>
    public string? Csrf => SessionToken ?? BrowserToken;

    public string Base => "http://127.0.0.1:" + service.Port;

    public string Origin => "http://localhost:" + service.Port;

    public IReadOnlyDictionary<string, string> Cookies => _cookies;

    public string LastSetCookie { get; private set; } = "";

    /// <summary>The headers of the last answer, one per line.</summary>
    public string LastHeaders { get; private set; } = "";

    /// <summary>Everything this browser was answered (headers and bodies), for the scans for secrets that must never appear.</summary>
    public List<string> Seen { get; } = [];

    public bool HasSession => _cookies.ContainsKey(AdminSessions.SessionCookie);

    public void ForgetCookies() => _cookies.Clear();

    public void SetCookie(string name, string value) => _cookies[name] = value;

    /// <summary>True when the browser holds a session the service still honours (a read-only view is served).</summary>
    public async Task<bool> StillSignedIn() => HasSession && (await GetAsync("/api/v1/approvals")).Status == 200;

    private void Keep(HttpResponseMessage response)
    {
        StringBuilder all = new();
        if (response.Headers.TryGetValues("Set-Cookie", out IEnumerable<string>? values))
        {
            foreach (string line in values)
            {
                all.Append(line).Append('\n');
                string[] parts = line.Split(';');
                int equals = parts[0].IndexOf('=', StringComparison.Ordinal);
                string name = parts[0][..equals].Trim();
                string value = parts[0][(equals + 1)..];
                bool expired = parts.Any(part => part.Trim().StartsWith("max-age=0", StringComparison.OrdinalIgnoreCase)) || value.Length == 0;
                if (expired)
                {
                    _cookies.Remove(name);
                }
                else
                {
                    _cookies[name] = value;
                }
            }
        }

        LastSetCookie = all.ToString();
        LastHeaders = string.Join("\n", response.Headers.Select(header => header.Key + ": " + string.Join(",", header.Value)).Concat(response.Content.Headers.Select(header => header.Key + ": " + string.Join(",", header.Value))));
    }

    public async Task<(int Status, string Html, HttpResponseMessage Response)> GetAsync(string path, string? origin = null, bool withCookies = true, string? host = null, string? token = "page")
    {
        using HttpRequestMessage request = new(HttpMethod.Get, Base + path);
        if (origin is not null)
        {
            request.Headers.Add("Origin", origin);
        }

        if ((token == "page" ? Csrf : token) is { } header)
        {
            request.Headers.Add(AdminApi.TokenHeader, header);
        }

        if (host is not null)
        {
            request.Headers.Host = host;
        }

        if (withCookies && _cookies.Count > 0)
        {
            request.Headers.Add("Cookie", string.Join("; ", _cookies.Select(item => item.Key + "=" + item.Value)));
        }

        HttpResponseMessage response = await _web.SendAsync(request);
        Keep(response);
        string body = await response.Content.ReadAsStringAsync();
        if (path == "/api/v1/session" && response.IsSuccessStatusCode)
        {
            using JsonDocument session = JsonDocument.Parse(body);
            if (!session.RootElement.GetProperty("authenticated").GetBoolean())
            {
                // The page learns it is signed out and drops the session's secret.
                SessionToken = null;
            }
        }

        Seen.Add(LastHeaders + "\n" + body);

        return ((int)response.StatusCode, body, response);
    }

    /// <summary>A request as the page's script sends it. Pass <paramref name="token" /> null to send none, <paramref name="origin" /> null to send no Origin.</summary>
    public async Task<(int Status, string Body)> SendAsync(HttpMethod method, string path, string? json, string? token = "page", string? origin = "page", string? host = null, bool withCookies = true, string contentType = "application/json")
    {
        using HttpRequestMessage request = new(method, Base + path);
        if (json is not null)
        {
            request.Content = new StringContent(json, Encoding.UTF8, contentType);
        }

        if (origin is not null)
        {
            request.Headers.Add("Origin", origin == "page" ? Origin : origin);
        }

        string? send = token == "page" ? Csrf : token;
        if (send is not null)
        {
            request.Headers.Add(AdminApi.TokenHeader, send);
        }

        if (host is not null)
        {
            request.Headers.Host = host;
        }

        if (withCookies && _cookies.Count > 0)
        {
            request.Headers.Add("Cookie", string.Join("; ", _cookies.Select(item => item.Key + "=" + item.Value)));
        }

        using HttpResponseMessage response = await _web.SendAsync(request);
        Keep(response);
        string answer = await response.Content.ReadAsStringAsync();
        Seen.Add(LastHeaders + "\n" + answer);

        return ((int)response.StatusCode, answer);
    }

    public Task<(int Status, string Body)> PostAsync(string path, string json, string? token = "page", string? origin = "page", string? host = null, bool withCookies = true, string contentType = "application/json") => SendAsync(HttpMethod.Post, path, json, token, origin, host, withCookies, contentType);

    /// <summary>The names whose values are numbers (or true/false) in a request body, as the API's schemas type them.</summary>
    private static readonly string[] Numbers = ["days", "idle", "absolute", "minutes"];

    private static object Typed(string name, string value) => Numbers.Contains(name) && int.TryParse(value, out int number) ? number : name == "indefinite" && bool.TryParse(value, out bool flag) ? flag : value;

    /// <summary>The body of <c>POST /api/v1/authorizations</c>.</summary>
    public static string AuthorizationBody(string op, params (string Name, string Value)[] args) => JsonSerializer.Serialize(new Dictionary<string, object> { ["operation"] = op, ["parameters"] = args.ToDictionary(item => item.Name, item => Typed(item.Name, item.Value)) });

    /// <summary>The mutation request for an operation: the route of the API that names it, the path parameters filled in and the authorization id in the body.</summary>
    public (HttpMethod Method, string Path, string Body) MutationRequest(string op, string? authorization, params (string Name, string Value)[] args)
    {
        ApiRoute route = service.Admin.Api.Routes.First(item => item.Access == ApiAccess.Mutation && item.Operation == op);
        string path = route.Template;
        Dictionary<string, object> body = [];
        if (authorization is not null)
        {
            body["authorization"] = authorization;
        }

        foreach ((string name, string value) in args)
        {
            if (path.Contains("{" + name + "}", StringComparison.Ordinal))
            {
                path = path.Replace("{" + name + "}", Uri.EscapeDataString(value), StringComparison.Ordinal);
            }
            else
            {
                body[name] = Typed(name, value);
            }
        }

        return (new HttpMethod(route.Method), path, JsonSerializer.Serialize(body));
    }

    /// <summary>What the page does on load: reads the session resource (and drops the session's secret when it is signed out) and makes the browser's identity when it has none.</summary>
    public async Task<string> LoadAsync(string path = "/api/v1/session")
    {
        string html = (await GetAsync(path)).Html;
        if (!_cookies.ContainsKey(AdminSessions.BrowserCookie) || BrowserToken is null)
        {
            await StartBrowserAsync();
        }

        return html;
    }

    /// <summary>Makes the browser's identity: the cookie, and the secret (kept here, as the page keeps it in memory) that is given once.</summary>
    public async Task<string> StartBrowserAsync()
    {
        (int status, string body) = await SendAsync(HttpMethod.Post, "/api/v1/browser", "{}", token: null);
        if (status == 201)
        {
            using JsonDocument doc = JsonDocument.Parse(body);
            BrowserToken = doc.RootElement.GetProperty("antiForgery").GetString();
        }

        return body;
    }

    /// <summary>Asks the service to claim the session of the sign-in this browser began; keeps the session's secret when it was given.</summary>
    public async Task<(int Status, string Body)> ClaimAsync()
    {
        (int status, string body) = await PostAsync("/api/v1/session/claim", "{}");
        if (status == 201)
        {
            using JsonDocument doc = JsonDocument.Parse(body);
            SessionToken = doc.RootElement.GetProperty("antiForgery").GetString();
        }

        return (status, body);
    }

    private async Task<Tapped> Tap(int status, string body, TestAuthenticator? signer, bool userVerified, Func<byte[], byte[]>? change)
    {
        using JsonDocument doc = JsonDocument.Parse(body);
        string? link = doc.RootElement.TryGetProperty("link", out JsonElement l) && l.ValueKind == JsonValueKind.String ? l.GetString() : null;
        string? error = doc.RootElement.TryGetProperty("detail", out JsonElement e) ? e.GetString() : null;
        string? id = doc.RootElement.TryGetProperty("id", out JsonElement i) ? i.GetString() : null;
        if (link is null || signer is null)
        {
            return new Tapped(status, link, error, 0, link is null ? "" : "http://127.0.0.1:" + new Uri(link).Port + new Uri(link).AbsolutePath, "", AuthorizationId: id);
        }

        Uri uri = new(link);
        string url = "http://127.0.0.1:" + uri.Port + uri.AbsolutePath;
        string pageText = WebUtility.HtmlDecode(TestState.Get(http, url).Body);
        (int approved, _) = TestState.Approve(http, url, "http://localhost:" + uri.Port, "localhost", signer, userVerified: userVerified, changeChallenge: change);

        return new Tapped(status, link, null, approved, url, TestState.LastProofBody, pageText, id);
    }

    /// <summary>
    /// Waits until the service has judged the tap of an authorization and made the change it authorized (it does both a moment after the page says Approved). Returns the state: "consumed" when the change was
    /// made (or refused: see the result), "refused", "expired" or "unknown" (an authorization that is gone, for example after a lock).
    /// </summary>
    public async Task<string> WaitAuthorizationAsync(string id)
    {
        string state = "pending";
        for (int i = 0; i < 200; i++)
        {
            (int status, string body) = await SendAsync(HttpMethod.Get, "/api/v1/authorizations/" + id, null);
            if (status != 200)
            {
                return "unknown";
            }

            using JsonDocument doc = JsonDocument.Parse(body);
            state = doc.RootElement.GetProperty("state").GetString()!;
            // Consumed is a state before it is a result: the plan is applied just after the state changes, so a reader can see consumed with no result for a moment. Wait for the result too.
            bool resultThere = doc.RootElement.TryGetProperty("result", out JsonElement result) && result.ValueKind == JsonValueKind.Object;
            if (state is not ("pending" or "verified") && (state != "consumed" || resultThere))
            {
                return state;
            }

            await Task.Delay(50);
        }

        return state;
    }

    /// <summary>
    /// Asks for an authorization (as the page's script would, with the page's anti-forgery value), taps on the page it names with a signer and, when the tap was approved and judged good, sends the one mutation
    /// that carries the authorization. Without a signer only the authorization is asked for.
    /// </summary>
    public async Task<Tapped> OpAsync(string op, TestAuthenticator? signer, bool userVerified = true, Func<byte[], byte[]>? change = null, bool reload = true, params (string Name, string Value)[] args)
    {
        if (reload)
        {
            await LoadAsync();
        }

        (int status, string body) = await PostAsync("/api/v1/authorizations", AuthorizationBody(op, args));
        Tapped tapped = await Tap(status, body, signer, userVerified, change);
        if (tapped.AuthorizationId is null || tapped.ApproveStatus != 200 || await WaitAuthorizationAsync(tapped.AuthorizationId) is not ("verified" or "consumed"))
        {
            return tapped;
        }

        (HttpMethod method, string path, string json) = MutationRequest(op, tapped.AuthorizationId, args);
        (int mutationStatus, string mutationBody) = await SendAsync(method, path, json);

        return tapped with { MutationStatus = mutationStatus, MutationBody = mutationBody };
    }

    /// <summary>As <see cref="OpAsync" /> but without the mutation: the authorization is asked for and tapped, and the caller decides what to send.</summary>
    public async Task<Tapped> OpAsyncWithoutMutation(string op, TestAuthenticator? signer, bool userVerified, params (string Name, string Value)[] args)
    {
        await LoadAsync();
        (int status, string body) = await PostAsync("/api/v1/authorizations", AuthorizationBody(op, args));

        return await Tap(status, body, signer, userVerified, null);
    }

    public Task<Tapped> OpAsyncWithoutMutation(string op, TestAuthenticator? signer, params (string Name, string Value)[] args) => OpAsyncWithoutMutation(op, signer, true, args);

    /// <summary>The sign-in: the login request, one tap on its page, and the page's return, which asks until the login is ready and claims the session. True when a session started.</summary>
    public async Task<bool> SignInAsync(TestAuthenticator signer, bool userVerified = true, Func<byte[], byte[]>? change = null)
    {
        Tapped tapped = await StartSignInAsync(signer, userVerified, change);
        if (tapped.ApproveStatus != 200)
        {
            return false;
        }

        return await FinishSignInAsync();
    }

    /// <summary>The first half of a sign-in: the login request and, with a signer, the tap. Without a signer only the login is asked for (the passkey page waits).</summary>
    public async Task<Tapped> StartSignInAsync(TestAuthenticator? signer = null, bool userVerified = true, Func<byte[], byte[]>? change = null)
    {
        await LoadAsync();
        (int status, string body) = await PostAsync("/api/v1/session", "{}");

        return await Tap(status, body, signer, userVerified, change);
    }

    /// <summary>The second half of a sign-in: asks the session resource until the login is ready (the service verifies the tap a moment after the page says Approved), then claims the session.</summary>
    public async Task<bool> FinishSignInAsync()
    {
        for (int i = 0; i < 40; i++)
        {
            (_, string state, _) = await GetAsync("/api/v1/session");
            if (state.Contains("\"ready\"", StringComparison.Ordinal) || state.Contains("\"failed\"", StringComparison.Ordinal))
            {
                break;
            }
        }

        (int claimed, _) = await ClaimAsync();

        return claimed == 201 && HasSession;
    }

    /// <summary>The text of a passkey page (what the person reads, and the passkey signs), decoded.</summary>
    public static string PageText(HttpClient client, string url) => WebUtility.HtmlDecode(TestState.Get(client, url).Body);
}

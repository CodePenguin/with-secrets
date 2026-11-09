using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace WithSecrets.Tests;

/// <summary>What one operation of the admin app came to when the test acted as the person: the start request, the passkey page and the tap.</summary>
internal sealed record Tapped(int PostStatus, string? Link, string? Error, int ApproveStatus, string PageUrl, string ProofBody, string Page = "");

/// <summary>
/// A browser, for tests of the admin web app: it keeps cookies, reads the anti-forgery value from the page it was served and sends it back, sends the Origin a page sends, and acts as the
/// person on the passkey pages with a software authenticator. Each of those can be left out or changed to test the refusals.
/// </summary>
internal sealed class AdminBrowser(HostService service, HttpClient http)
{
    private readonly Dictionary<string, string> _cookies = new(StringComparer.Ordinal);
    private readonly HttpClient _web = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false, UseCookies = false }) { Timeout = TimeSpan.FromSeconds(60) };

    public string? Csrf { get; private set; }

    public string Base => "http://127.0.0.1:" + service.Port;

    public string Origin => "http://localhost:" + service.Port;

    public IReadOnlyDictionary<string, string> Cookies => _cookies;

    public string LastSetCookie { get; private set; } = "";

    public bool HasSession => _cookies.ContainsKey(AdminSessions.SessionCookie);

    public void ForgetCookies() => _cookies.Clear();

    public void SetCookie(string name, string value) => _cookies[name] = value;

    /// <summary>True when the browser holds a session the service still honours (a read-only view is served).</summary>
    public async Task<bool> StillSignedIn() => HasSession && (await GetAsync("/admin/machines")).Status == 200;

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
    }

    public async Task<(int Status, string Html, HttpResponseMessage Response)> GetAsync(string path, string? origin = null, bool withCookies = true)
    {
        using HttpRequestMessage request = new(HttpMethod.Get, Base + path);
        if (origin is not null)
        {
            request.Headers.Add("Origin", origin);
        }

        if (withCookies && _cookies.Count > 0)
        {
            request.Headers.Add("Cookie", string.Join("; ", _cookies.Select(item => item.Key + "=" + item.Value)));
        }

        HttpResponseMessage response = await _web.SendAsync(request);
        Keep(response);
        string html = await response.Content.ReadAsStringAsync();
        if (Regex.Match(html, "<meta name=\"anti-forgery\" content=\"([^\"]+)\"") is { Success: true } meta)
        {
            Csrf = WebUtility.HtmlDecode(meta.Groups[1].Value);
        }

        return ((int)response.StatusCode, html, response);
    }

    /// <summary>A POST as the page's script sends it. Pass <paramref name="token" /> null to send none, <paramref name="origin" /> null to send no Origin.</summary>
    public async Task<(int Status, string Body)> PostAsync(string path, string json, string? token = "page", string? origin = "page", string? host = null, bool withCookies = true, string contentType = "application/json")
    {
        using HttpRequestMessage request = new(HttpMethod.Post, Base + path) { Content = new StringContent(json, Encoding.UTF8, contentType) };
        if (origin is not null)
        {
            request.Headers.Add("Origin", origin == "page" ? Origin : origin);
        }

        string? send = token == "page" ? Csrf : token;
        if (send is not null)
        {
            request.Headers.Add(AdminWeb.TokenHeader, send);
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

        return ((int)response.StatusCode, await response.Content.ReadAsStringAsync());
    }

    private static string Json(string op, params (string Name, string Value)[] args) => JsonSerializer.Serialize(new[] { ("op", op) }.Concat(args).ToDictionary(item => item.Item1, item => item.Item2));

    /// <summary>Loads the status page (cookies and the anti-forgery value of the page).</summary>
    public async Task<string> LoadAsync(string path = "/admin") => (await GetAsync(path)).Html;

    private async Task<Tapped> Tap(int status, string body, TestAuthenticator? signer, bool userVerified, Func<byte[], byte[]>? change)
    {
        using JsonDocument doc = JsonDocument.Parse(body);
        string? link = doc.RootElement.TryGetProperty("link", out JsonElement l) ? l.GetString() : null;
        string? error = doc.RootElement.TryGetProperty("error", out JsonElement e) ? e.GetString() : null;
        if (link is null || signer is null)
        {
            return new Tapped(status, link, error, 0, link is null ? "" : "http://127.0.0.1:" + new Uri(link).Port + new Uri(link).AbsolutePath, "");
        }

        Uri uri = new(link);
        string url = "http://127.0.0.1:" + uri.Port + uri.AbsolutePath;
        string pageText = WebUtility.HtmlDecode(TestState.Get(http, url).Body);
        (int approved, _) = TestState.Approve(http, url, "http://localhost:" + uri.Port, "localhost", signer, userVerified: userVerified, changeChallenge: change);

        return new Tapped(status, link, null, approved, url, TestState.LastProofBody, pageText);
    }

    /// <summary>Starts an operation (as the page's script would, with the page's anti-forgery value) and, with a signer, taps on the page it names.</summary>
    public async Task<Tapped> OpAsync(string op, TestAuthenticator? signer, bool userVerified = true, Func<byte[], byte[]>? change = null, bool reload = true, params (string Name, string Value)[] args)
    {
        if (reload)
        {
            await LoadAsync();
        }

        (int status, string body) = await PostAsync("/admin/op", Json(op, args));

        return await Tap(status, body, signer, userVerified, change);
    }

    /// <summary>The sign-in: the login request, one tap on its page, and the browser's return to the app, which claims the session. True when a session started.</summary>
    public async Task<bool> SignInAsync(TestAuthenticator signer, bool userVerified = true, Func<byte[], byte[]>? change = null)
    {
        await LoadAsync();
        (int status, string body) = await PostAsync("/admin/login", "{}");
        Tapped tapped = await Tap(status, body, signer, userVerified, change);
        if (tapped.ApproveStatus != 200)
        {
            return false;
        }

        await Task.Delay(150);
        await LoadAsync();

        return HasSession;
    }

    /// <summary>The text of a passkey page (what the person reads, and the passkey signs), decoded.</summary>
    public static string PageText(HttpClient client, string url) => WebUtility.HtmlDecode(TestState.Get(client, url).Body);
}

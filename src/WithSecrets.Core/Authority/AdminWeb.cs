using System.Text;
using System.Text.Json;

using Microsoft.AspNetCore.Http;

namespace WithSecrets;

/// <summary>
/// The HTTP side of the admin web app, on the service's own loopback port (the service has already refused any Host that is not a loopback name, so a page on another name that resolves
/// to 127.0.0.1 gets nothing). <c>GET</c> views other than the public status page need a session cookie. Every <c>POST</c> needs: an Origin that is exactly this service on a loopback name,
/// a small JSON body, and the anti-forgery value of the page that made the request (a value only a page served to this browser carries); and, but for unlock, a session. A request that
/// fails any of these changes nothing and is refused (and audited, within a limit). None of this authorizes a change: that is the one-use passkey page the answer names.
/// </summary>
internal sealed class AdminWeb(AdminService admin, int port)
{
    public const string TokenHeader = "X-Admin-Token";

    private const int MaxBody = 2048;
    private const int MaxMembers = 12;
    private const int MaxValue = 300;

    private string[] AllowedOrigins() => [$"http://localhost:{port}", $"http://127.0.0.1:{port}", $"http://[::1]:{port}"];

    private static CookieOptions Options(bool expire = false) => new() { HttpOnly = true, SameSite = SameSiteMode.Strict, Path = "/admin", IsEssential = true, MaxAge = expire ? TimeSpan.Zero : null };

    public async Task HandleAsync(HttpContext context)
    {
        HttpRequest request = context.Request;
        HttpResponse response = context.Response;
        response.Headers["X-Frame-Options"] = "DENY";
        response.Headers["Referrer-Policy"] = "no-referrer";

        // A request from a page must come from this page: its Origin is exactly this service on a loopback name and this port. A request from any other site is refused.
        if (request.Headers.TryGetValue("Origin", out Microsoft.Extensions.Primitives.StringValues origins)
            && (origins.Count != 1 || !AllowedOrigins().Contains(origins[0]!, StringComparer.OrdinalIgnoreCase)))
        {
            await Refuse(response, 403, "requests from another web page are not accepted");

            return;
        }

        string path = request.Path.Value ?? "";
        if (path is "/admin/op" or "/admin/login" or "/admin/logout")
        {
            await Post(context, path);

            return;
        }

        if (!HttpMethods.IsGet(request.Method))
        {
            await Refuse(response, 405, "use GET");

            return;
        }

        await Get(context, path);
    }

    private static string? Cookie(HttpRequest request, string name) => request.Cookies.TryGetValue(name, out string? value) && value.Length <= 128 ? value : null;

    private async Task Get(HttpContext context, string path)
    {
        HttpRequest request = context.Request;
        HttpResponse response = context.Response;
        string? token = Cookie(request, AdminSessions.SessionCookie);
        AdminSession? session = admin.Sessions.Validate(token);
        string? ticket = Cookie(request, AdminSessions.LoginCookie);
        string? loginProblem = null;
        if (session is null && ticket is not null)
        {
            // The browser that began a login comes back: when the tap was verified its session starts now.
            (LoginState state, string? problem) = admin.Sessions.LoginStatus(ticket);
            for (int wait = 0; state == LoginState.Waiting && wait < 30 && !context.RequestAborted.IsCancellationRequested; wait++)
            {
                // The tap was just made: the service verifies it a moment after the page says Approved.
                await Task.Delay(50, CancellationToken.None);
                (state, problem) = admin.Sessions.LoginStatus(ticket);
            }

            if (state == LoginState.Ready && !admin.Status().Locked && admin.Sessions.Claim(ticket) is { } claimed)
            {
                session = claimed;
                token = claimed.Token;
                response.Cookies.Append(AdminSessions.SessionCookie, claimed.Token, Options());
                response.Cookies.Delete(AdminSessions.LoginCookie, Options(expire: true));
                admin.RecordSessionStart(claimed);
            }
            else if (state == LoginState.Failed)
            {
                loginProblem = problem ?? "the passkey was refused";
                admin.Sessions.Forget(ticket);
                response.Cookies.Delete(AdminSessions.LoginCookie, Options(expire: true));
            }
            else if (state == LoginState.Unknown)
            {
                response.Cookies.Delete(AdminSessions.LoginCookie, Options(expire: true));
            }
        }

        string? browser = Cookie(request, AdminSessions.BrowserCookie);
        if (browser is null)
        {
            browser = AdminSessions.NewBrowserId();
            response.Cookies.Append(AdminSessions.BrowserCookie, browser, Options());
        }

        string csrf = session is not null ? admin.Sessions.AntiForgery("session", token!) : admin.Sessions.AntiForgery("browser", browser);
        string nonce = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
        response.Headers.ContentSecurityPolicy = $"default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-{nonce}'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
        string? page = admin.Page(path, nonce, session, csrf, name => request.Query.TryGetValue(name, out Microsoft.Extensions.Primitives.StringValues values) && values.Count == 1 && values[0] is { Length: <= 200 } text ? text : null, loginProblem);
        if (page is null)
        {
            if (session is null && AdminService.Pages.Any(item => item.Path == path))
            {
                // A view that needs a session, asked for without one: nothing of it is served.
                response.StatusCode = 401;
                response.ContentType = "text/html; charset=utf-8";
                await response.WriteAsync(admin.SignInRequired(nonce));

                return;
            }

            await Refuse(response, 404, "not found");

            return;
        }

        response.ContentType = "text/html; charset=utf-8";
        await response.WriteAsync(page);
    }

    private async Task Post(HttpContext context, string path)
    {
        HttpRequest request = context.Request;
        HttpResponse response = context.Response;
        if (!HttpMethods.IsPost(request.Method))
        {
            await Refuse(response, 405, "use POST");

            return;
        }

        // Only the page itself starts anything: a request with no Origin (a program) is not the page.
        if (!request.Headers.ContainsKey("Origin"))
        {
            admin.Refused(path, "no Origin (not the admin page)");
            await Refuse(response, 403, "operations are started from the admin page");

            return;
        }

        if (request.ContentType is not { } contentType || !contentType.Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase) || request.ContentLength is null or > MaxBody)
        {
            await Refuse(response, 415, "the body must be small application/json");

            return;
        }

        Dictionary<string, string>? members = await ReadMembers(request, context.RequestAborted);
        if (members is null)
        {
            await Refuse(response, 400, "the body is a JSON object of text, number and true/false members");

            return;
        }

        string? token = Cookie(request, AdminSessions.SessionCookie);
        AdminSession? session = admin.Sessions.Validate(token);
        string? browser = Cookie(request, AdminSessions.BrowserCookie);
        string? presented = request.Headers.TryGetValue(TokenHeader, out Microsoft.Extensions.Primitives.StringValues values) && values.Count == 1 ? values[0] : null;
        string op = path == "/admin/op" ? members.GetValueOrDefault("op") ?? "" : path;

        // A request that is not from a page this browser was served (no anti-forgery value, or one for another cookie) changes nothing.
        bool forgery = session is not null ? admin.Sessions.AntiForgeryMatches("session", token, presented) : admin.Sessions.AntiForgeryMatches("browser", browser, presented);
        if (!forgery)
        {
            admin.Refused(op, "anti-forgery value missing or wrong");
            await Refuse(response, 403, "this request did not come from a page served to this browser; reload the page");

            return;
        }

        switch (path)
        {
            case "/admin/logout":
                if (session is null)
                {
                    await Refuse(response, 401, "no session");

                    return;
                }

                admin.Sessions.Destroy(token);
                admin.RecordSessionEnd(session, "ended: sign out");
                response.Cookies.Delete(AdminSessions.SessionCookie, Options(expire: true));
                response.ContentType = "application/json";
                await response.WriteAsync("{\"ok\":true}");

                return;

            case "/admin/login":
                if (session is not null)
                {
                    await Refuse(response, 409, "already signed in");

                    return;
                }

                (AdminStart login, string? issued) = await admin.BeginLoginAsync(context.RequestAborted);
                if (issued is not null)
                {
                    response.Cookies.Append(AdminSessions.LoginCookie, issued, Options());
                }

                await Answer(response, login);

                return;
        }

        if (op.Length == 0)
        {
            await Refuse(response, 400, "the body is {\"op\":NAME, ...}");

            return;
        }

        members.Remove("op");
        AdminStart started = await admin.StartAsync(new AdminCaller(session), op, members, context.RequestAborted);
        await Answer(response, started);
    }

    private static async Task Answer(HttpResponse response, AdminStart started)
    {
        response.StatusCode = started.Status;
        response.ContentType = "application/json";
        StringBuilder answer = new("{");
        if (started.Link is not null)
        {
            answer.Append("\"link\":");
            ToolSettings.QuoteJson(answer, started.Link);
        }
        else
        {
            answer.Append("\"error\":");
            ToolSettings.QuoteJson(answer, started.Error ?? "not started");
        }

        await response.WriteAsync(answer.Append('}').ToString());
    }

    /// <summary>The members of a small JSON object as text (numbers and true/false become text); null when the body is anything else.</summary>
    private static async Task<Dictionary<string, string>?> ReadMembers(HttpRequest request, CancellationToken cancel)
    {
        try
        {
            using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(cancel);
            limit.CancelAfter(TimeSpan.FromSeconds(10));
            using MemoryStream body = new();
            byte[] buffer = new byte[512];
            int read;
            while ((read = await request.Body.ReadAsync(buffer, limit.Token)) > 0)
            {
                if (body.Length + read > MaxBody)
                {
                    return null;
                }

                body.Write(buffer, 0, read);
            }

            using JsonDocument doc = JsonDocument.Parse(body.ToArray());
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            Dictionary<string, string> members = new(StringComparer.Ordinal);
            foreach (JsonProperty property in doc.RootElement.EnumerateObject())
            {
                string? text = property.Value.ValueKind switch
                {
                    JsonValueKind.String => property.Value.GetString(),
                    JsonValueKind.Number => property.Value.GetRawText(),
                    JsonValueKind.True => "true",
                    JsonValueKind.False => "false",
                    _ => null,
                };
                if (text is null || text.Length > MaxValue || property.Name.Length > 32 || members.Count >= MaxMembers || !members.TryAdd(property.Name, text))
                {
                    return null;
                }
            }

            return members;
        }
        catch (Exception error) when (error is JsonException or OperationCanceledException or BadHttpRequestException or IOException)
        {
            return null;
        }
    }

    private static async Task Refuse(HttpResponse response, int status, string message)
    {
        response.StatusCode = status;
        response.ContentType = "application/json";
        StringBuilder text = new("{\"error\":");
        ToolSettings.QuoteJson(text, message);
        await response.WriteAsync(text.Append('}').ToString());
    }
}

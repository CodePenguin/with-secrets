using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

using Microsoft.AspNetCore.Http;

namespace WithSecrets;

/// <summary>
/// The administration API under <c>/api/v1/</c> on the service's own loopback port: JSON only, nothing falls through to anything else (an unknown path under <c>/api</c> is a JSON 404, an unsupported
/// version a documented JSON error). The browser session is READ-ONLY (<see cref="AdminSessions" />): reads need it, and a change needs a fresh, single-use, time-limited passkey authorization made for
/// exactly that operation and its parameters (<see cref="AdminService.BeginAuthorizationAsync" />, <see cref="AdminService.MutateAsync" />), enforced here and in the service, never in a page. Every change
/// also needs a same-origin request (an exact Origin on a loopback name and this port), a loopback Host and the anti-forgery value of the browser's cookie. There is no CORS. Bodies are small, schema-checked JSON
/// and are never logged or echoed; every refusal is an RFC 9457 problem document with a short safe sentence and a stable code. The routes in <see cref="BuildRoutes" /> are the one source of the dispatch and the OpenAPI document.
/// </summary>
internal sealed partial class AdminApi
{
    public const string TokenHeader = "X-Admin-Token";
    public const string VersionHeader = "X-Api-Version";
    private const string ProblemType = "urn:with-secrets:problem:";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never };
    private static readonly Regex VersionSegment = new("^v[0-9]+$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private readonly AdminService admin;
    private readonly int _port;
    private readonly IReadOnlyList<ApiRoute> _routes;
    private readonly Lazy<JsonObject> _document;

    public AdminApi(AdminService admin, int port)
    {
        this.admin = admin;
        _port = port;
        _routes = BuildRoutes();
        _document = new Lazy<JsonObject>(() => BuildDocument(_routes, port));
    }

    /// <summary>The route table, for tests and the document.</summary>
    internal IReadOnlyList<ApiRoute> Routes => _routes;

    /// <summary>The OpenAPI document.</summary>
    internal JsonObject Document => _document.Value;

    private string[] AllowedOrigins() => [$"http://localhost:{_port}", $"http://127.0.0.1:{_port}", $"http://[::1]:{_port}"];

    private static CookieOptions Options(bool expire = false) => new() { HttpOnly = true, SameSite = SameSiteMode.Strict, Path = Prefix, IsEssential = true, MaxAge = expire ? TimeSpan.Zero : null };

    /// <summary>
    /// Cookie values are bound to this service's port ("PORT.value"): another service on another localhost port that sets or is sent these names is not mistaken for this one. Cookies are still sent to every
    /// port of localhost (browsers do not isolate them by port), which is why a cookie alone never gives a session (see <see cref="AdminSession.Csrf" />).
    /// </summary>
    private string? Cookie(HttpRequest request, string name)
    {
        string prefix = _port.ToString(CultureInfo.InvariantCulture) + ".";

        return request.Cookies.TryGetValue(name, out string? value) && value.Length <= 128 && value.StartsWith(prefix, StringComparison.Ordinal) && value.Length > prefix.Length ? value[prefix.Length..] : null;
    }

    private void SetCookie(HttpResponse response, string name, string value) => response.Cookies.Append(name, _port.ToString(CultureInfo.InvariantCulture) + "." + value, Options());

    private static void DropCookie(HttpResponse response, string name) => response.Cookies.Delete(name, Options(expire: true));

    private static string Title(int status) => status switch
    {
        400 => "Bad request",
        401 => "Sign in required",
        403 => "Refused",
        404 => "Not found",
        405 => "Method not allowed",
        409 => "Conflict",
        413 => "Request too large",
        415 => "Unsupported media type",
        421 => "Misdirected request",
        423 => "Locked",
        429 => "Too many requests",
        503 => "Unavailable",
        504 => "Timed out",
        _ => status >= 500 ? "Server error" : "Error",
    };

    /// <summary>The path as the API sees it: the segments after <c>/api</c>.</summary>
    public async Task HandleAsync(HttpContext context)
    {
        HttpResponse response = context.Response;
        response.Headers["X-Frame-Options"] = "DENY";
        response.Headers["Referrer-Policy"] = "no-referrer";
        response.Headers.ContentSecurityPolicy = "default-src 'none'; frame-ancestors 'none'";
        response.Headers[VersionHeader] = "1";
        try
        {
            ApiProblem? refused = await DispatchAsync(context);
            if (refused is not null)
            {
                await WriteProblem(response, refused);
            }
        }
        catch (OperationCanceledException)
        {
            // The client went away.
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            // Only the kind of failure is kept (never a message: it could carry a request value).
            AppLog.Warn("an administration API request failed unexpectedly: {Type}", error.GetType().Name);
            if (!response.HasStarted)
            {
                response.Headers.Remove("Content-Type");
                await WriteProblem(response, new ApiProblem(500, "internal-error", "the request failed; nothing was changed that the response does not say"));
            }
        }
    }

    /// <summary>The answer for the address of the web application while none is built in: a JSON 404 (never HTML, never a fall-through to anything).</summary>
    public async Task NotBuiltAsync(HttpContext context)
    {
        context.Response.Headers[VersionHeader] = "1";
        await WriteProblem(context.Response, new ApiProblem(404, "web-application-not-built", "the administration web application is not part of this build; the JSON API is at " + Prefix + "/ (" + Prefix + "/openapi.json)"));
    }

    /// <summary>The answer for a request whose Host is not a loopback name (DNS rebinding): the service refuses before the API sees it.</summary>
    public async Task RefuseHostAsync(HttpContext context)
    {
        context.Response.Headers[VersionHeader] = "1";
        await WriteProblem(context.Response, new ApiProblem(421, "host-not-allowed", "the Host header is not a loopback name"));
    }

    private static async Task WriteProblem(HttpResponse response, ApiProblem problem)
    {
        response.StatusCode = problem.Status;
        response.ContentType = "application/problem+json";
        Dictionary<string, object?> document = new()
        {
            ["type"] = ProblemType + problem.Code,
            ["title"] = Title(problem.Status),
            ["status"] = problem.Status,
            ["detail"] = problem.Detail,
            ["code"] = problem.Code,
        };
        if (problem.SupportedVersions is not null)
        {
            document["supportedVersions"] = problem.SupportedVersions;
        }

        await JsonSerializer.SerializeAsync(response.Body, document, Json);
    }

    private static async Task WriteJson(HttpResponse response, int status, object? body)
    {
        response.StatusCode = status;
        response.ContentType = "application/json";
        await JsonSerializer.SerializeAsync(response.Body, body, Json);
    }

    private static string Text(string value, int max) => value.Length > max ? value[..max] : value;

    private static bool Match(string template, string path, out Dictionary<string, string> values)
    {
        values = [];
        string[] want = template.Split('/');
        string[] have = path.Split('/');
        if (want.Length != have.Length)
        {
            return false;
        }

        for (int i = 0; i < want.Length; i++)
        {
            if (want[i].StartsWith('{'))
            {
                if (have[i].Length == 0 || have[i].Length > 120)
                {
                    return false;
                }

                values[want[i].Trim('{', '}')] = have[i];
            }
            else if (want[i] != have[i])
            {
                return false;
            }
        }

        return true;
    }

    private async Task<ApiProblem?> DispatchAsync(HttpContext context)
    {
        HttpRequest request = context.Request;
        HttpResponse response = context.Response;
        string path = request.Path.Value ?? "";

        // The version: /api/v1/... only. Another version number is a documented error (not a 404, so a client can tell); anything else under /api is not an API route.
        string[] parts = path.Split('/');
        if (parts.Length < 3 || parts[1] != "api" || parts[2].Length == 0)
        {
            return new ApiProblem(404, "route-not-found", "there is no such route; the API is under " + Prefix + "/ (see " + Prefix + "/openapi.json)");
        }

        if (!VersionSegment.IsMatch(parts[2]))
        {
            return new ApiProblem(404, "route-not-found", "there is no such route; the API is under " + Prefix + "/ (see " + Prefix + "/openapi.json)");
        }

        if (!parts[2].Equals(Version, StringComparison.OrdinalIgnoreCase) || parts[2] != Version)
        {
            return new ApiProblem(400, "unsupported-api-version", "this service speaks API version " + Version + " only (" + Prefix + "/)", [Version]);
        }

        // A client may also say which version it speaks (X-Api-Version: 1); another value is the same documented error as another version in the path.
        if (request.Headers.TryGetValue(VersionHeader, out Microsoft.Extensions.Primitives.StringValues asked) && (asked.Count != 1 || asked[0] is not ("1" or "v1")))
        {
            return new ApiProblem(400, "unsupported-api-version", "this service speaks API version " + Version + " only (" + Prefix + "/)", [Version]);
        }

        // Defence in depth: the service already refuses a Host that is not a loopback name; the API does not rely on that.
        if (request.Host.Host is not ("localhost" or "127.0.0.1" or "[::1]" or "::1"))
        {
            return new ApiProblem(421, "host-not-allowed", "the Host header is not a loopback name");
        }

        // A request from a page must come from this service's own page: no CORS, and another site's Origin is refused for every method.
        if (request.Headers.TryGetValue("Origin", out Microsoft.Extensions.Primitives.StringValues origins) && (origins.Count != 1 || !AllowedOrigins().Contains(origins[0]!, StringComparer.OrdinalIgnoreCase)))
        {
            return new ApiProblem(403, "origin-not-allowed", "requests from another web page are not accepted");
        }

        ApiRoute? route = null;
        Dictionary<string, string> values = [];
        List<string> allowed = [];
        foreach (ApiRoute candidate in _routes)
        {
            if (!Match(candidate.Template, path, out Dictionary<string, string> found))
            {
                continue;
            }

            allowed.Add(candidate.Method);
            if (candidate.Method.Equals(request.Method, StringComparison.Ordinal))
            {
                route = candidate;
                values = found;
            }
        }

        if (route is null)
        {
            if (allowed.Count > 0)
            {
                response.Headers.Allow = string.Join(", ", allowed);

                return new ApiProblem(405, "method-not-allowed", "this route answers " + string.Join(", ", allowed));
            }

            return new ApiProblem(404, "route-not-found", "there is no such route; see " + Prefix + "/openapi.json");
        }

        // Reading the status or the document is not a use of a session (so polling them keeps no session alive). A session is its cookie AND its own secret (the X-Admin-Token header): a cookie that is
        // presented alone (another program on another localhost port is sent it too) finds no session, renews nothing and gets no answer a session would get.
        string? token = Cookie(request, AdminSessions.SessionCookie);
        string? presented = request.Headers.TryGetValue(TokenHeader, out Microsoft.Extensions.Primitives.StringValues presentedValues) && presentedValues.Count == 1 ? presentedValues[0] : null;
        AdminSession? session = route.OperationId is "getStatus" or "getOpenApi" or "startBrowser" ? null : admin.Sessions.Validate(token, presented);
        admin.RecordEndedSessions();
        string? browserCookie = Cookie(request, AdminSessions.BrowserCookie);

        // The pre-session cookie is an identity only together with its own anti-forgery value (given once, by POST /browser).
        string? browser = browserCookie is not null && admin.Sessions.AntiForgeryMatches("browser", browserCookie, presented) ? browserCookie : null;
        string caller = session is not null ? "s:" + session.Id : browser is not null ? AdminSessions.BrowserCaller(browser) : "anonymous";
        string name = route.OperationId;

        if (route.Access is ApiAccess.Public or ApiAccess.Owner)
        {
            if (route.OperationId == "getOpenApi")
            {
                await WriteJson(response, 200, Document);

                return null;
            }

            return await Respond(response, route, new ApiCall(context, values, null, session, browser, token));
        }

        if (route.Access == ApiAccess.Read)
        {
            if (session is null)
            {
                return new ApiProblem(401, "session-required", "this needs an administrator session; sign in with a passkey (POST " + Prefix + "/session)");
            }

            return await Respond(response, route, new ApiCall(context, values, null, session, browser, token));
        }

        // Everything below changes (or starts) something: it needs a same-origin request that a page of this browser made.
        if (!request.Headers.ContainsKey("Origin"))
        {
            admin.Refused(name, "no Origin (not the admin page)", caller);

            return new ApiProblem(403, "origin-required", "this request must come from the administration page: it carries no Origin");
        }

        if (route.Access != ApiAccess.Open && session is null && browser is null)
        {
            admin.Refused(name, "anti-forgery value missing or wrong", caller);

            return new ApiProblem(403, "anti-forgery", "this request did not come from a page served to this browser; reload the page and try again");
        }

        bool needsSession = route.Access is ApiAccess.Logout or ApiAccess.Authorize or ApiAccess.Mutation;
        bool noSessionOperation = route.Operation is AdminService.OpUnlock or AdminService.OpLock;
        if (needsSession && session is null && !noSessionOperation && route.Access != ApiAccess.Authorize)
        {
            admin.Refused(name, "no administrator session", caller);

            return new ApiProblem(401, "session-required", "this needs an administrator session; sign in with a passkey (POST " + Prefix + "/session)");
        }

        if (route.Access is ApiAccess.Login or ApiAccess.Claim && session is not null)
        {
            return new ApiProblem(409, "already-signed-in", "this browser already has a session");
        }

        if (route.Access is ApiAccess.Login or ApiAccess.Claim && browser is null)
        {
            admin.Refused(name, "no browser identity", caller);

            return new ApiProblem(403, "anti-forgery", "this request did not come from a page served to this browser; reload the page and try again");
        }

        JsonElement? body = null;
        if (route.Request is not null)
        {
            (JsonElement? parsed, ApiProblem? problem) = await ReadBody(request, route.Request, context.RequestAborted);
            if (problem is not null)
            {
                admin.Refused(name, "invalid request: " + problem.Code, caller);

                return problem;
            }

            body = parsed;
        }

        return await Respond(response, route, new ApiCall(context, values, body, session, browser, token));
    }

    private async Task<ApiProblem?> Respond(HttpResponse response, ApiRoute route, ApiCall call)
    {
        ApiResult result = await route.Handle(call);
        if (result.Body is ApiProblem problem)
        {
            return problem;
        }

        await WriteJson(response, result.Status, result.Body);

        return null;
    }

    /// <summary>The body as a checked JSON object: small, application/json, no duplicate members, and exactly what the route's schema allows.</summary>
    private async Task<(JsonElement? Body, ApiProblem? Problem)> ReadBody(HttpRequest request, JsonObject schema, CancellationToken cancel)
    {
        if (request.ContentType is not { } contentType || !contentType.Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase))
        {
            return (null, new ApiProblem(415, "unsupported-media-type", "the body must be application/json"));
        }

        if (request.ContentLength is > MaxBody)
        {
            return (null, new ApiProblem(413, "payload-too-large", "the body is at most " + MaxBody.ToString(CultureInfo.InvariantCulture) + " bytes"));
        }

        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        limit.CancelAfter(TimeSpan.FromSeconds(10));
        using MemoryStream bytes = new();
        try
        {
            byte[] buffer = new byte[1024];
            int read;
            while ((read = await request.Body.ReadAsync(buffer, limit.Token)) > 0)
            {
                if (bytes.Length + read > MaxBody)
                {
                    return (null, new ApiProblem(413, "payload-too-large", "the body is at most " + MaxBody.ToString(CultureInfo.InvariantCulture) + " bytes"));
                }

                bytes.Write(buffer, 0, read);
            }
        }
        catch (Exception error) when (error is OperationCanceledException or BadHttpRequestException or IOException)
        {
            return (null, new ApiProblem(400, "invalid-request", "the body could not be read in time"));
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(bytes.ToArray(), new JsonDocumentOptions { MaxDepth = 4, AllowDuplicateProperties = false });
        }
        catch (JsonException)
        {
            return (null, new ApiProblem(400, "invalid-json", "the body is not valid JSON (an object, each member once)"));
        }

        using (document)
        {
            JsonElement root = document.RootElement.Clone();
            string? invalid = ApiValidator.Validate(root, schema, (JsonObject)Document["components"]!["schemas"]!);

            return invalid is null ? (root, null) : (null, new ApiProblem(400, "invalid-request", invalid));
        }
    }

    // ---- handlers ----

    private static string AsText(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString() ?? "",
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        _ => value.GetRawText(),
    };

    /// <summary>The caller an authorization is bound to: the session, or, for the one change that needs none (the unlock), the browser's pre-session cookie.</summary>
    private static object? OwnerOf(ApiCall call) => call.Session is not null ? call.Session : call.Browser;

    private static ApiProblem FromStart(AdminStart start) => new(start.Status, start.Status switch
    {
        401 => "session-required",
        423 => "authority-locked",
        429 => "too-many-requests",
        504 => "passkey-page-timeout",
        400 => "invalid-request",
        404 => "not-found",
        _ => "operation-refused",
    }, ApprovalSummary.Clean(start.Error ?? "refused"));

    private Task<ApiResult> StartBrowserAsync(ApiCall call)
    {
        string browser = AdminSessions.NewBrowserId();
        SetCookie(call.Context.Response, AdminSessions.BrowserCookie, browser);

        // The one time the value is given: from now on it exists only in the page that asked.
        return Task.FromResult(new ApiResult(201, new BrowserDto(admin.Sessions.AntiForgery("browser", browser))));
    }

    /// <summary>Who is signed in, and how this browser's sign-in stands. It only reads: it claims no session, sets no cookie and writes nothing.</summary>
    private async Task<ApiResult> GetSessionAsync(ApiCall call)
    {
        HttpContext context = call.Context;
        AdminSession? session = call.Session;
        LoginDto? login = null;
        if (session is null && call.Browser is { } browser && Cookie(context.Request, AdminSessions.LoginCookie) is { } ticket)
        {
            (LoginState state, string? problem) = admin.Sessions.LoginStatus(ticket, browser);
            for (int wait = 0; state == LoginState.Waiting && wait < 30 && !context.RequestAborted.IsCancellationRequested; wait++)
            {
                // The tap was just made: the service verifies it a moment after the page says Approved.
                await Task.Delay(50, CancellationToken.None);
                (state, problem) = admin.Sessions.LoginStatus(ticket, browser);
            }

            login = state switch
            {
                LoginState.Waiting => new LoginDto("waiting", null),
                LoginState.Ready => new LoginDto("ready", null),
                LoginState.Failed => new LoginDto("failed", ApprovalSummary.Clean(problem ?? "the passkey was refused")),
                _ => null,
            };
        }

        if (session is null)
        {
            return new ApiResult(200, new SessionDto(false, null, null, null, null, login, []));
        }

        (DateTimeOffset idle, DateTimeOffset absolute) = admin.SessionEnds(session);

        return new ApiResult(200, new SessionDto(true, ApprovalSummary.Clean(session.Admin), session.Started, idle, absolute, null, admin.Recent));
    }

    /// <summary>
    /// The browser that began a sign-in comes back (a POST, with its browser identity and its login cookie): when the tap was verified the session is made now and its own secret is given, once, in this
    /// answer. A program that was only sent the cookies has neither the browser's anti-forgery value nor can it make this request.
    /// </summary>
    private async Task<ApiResult> ClaimSessionAsync(ApiCall call)
    {
        HttpResponse response = call.Context.Response;
        string? ticket = Cookie(call.Context.Request, AdminSessions.LoginCookie);
        string browser = call.Browser!;
        (LoginState state, string? problem) = admin.Sessions.LoginStatus(ticket, browser);
        for (int wait = 0; state == LoginState.Waiting && wait < 30 && !call.Context.RequestAborted.IsCancellationRequested; wait++)
        {
            await Task.Delay(50, CancellationToken.None);
            (state, problem) = admin.Sessions.LoginStatus(ticket, browser);
        }

        switch (state)
        {
            case LoginState.Unknown:
                DropCookie(response, AdminSessions.LoginCookie);

                return new ApiResult(404, new ApiProblem(404, "no-sign-in", "this browser has no sign-in waiting; start one (POST " + Prefix + "/session)"));

            case LoginState.Waiting:
                return new ApiResult(409, new ApiProblem(409, "sign-in-pending", "the passkey tap for this sign-in has not been made yet"));

            case LoginState.Failed:
                admin.Sessions.Forget(ticket, browser);
                DropCookie(response, AdminSessions.LoginCookie);

                return new ApiResult(409, new ApiProblem(409, "sign-in-failed", ApprovalSummary.Clean(problem ?? "the passkey was refused")));
        }

        if (admin.Status().Locked)
        {
            return new ApiResult(423, new ApiProblem(423, "authority-locked", "the authority is locked: unlock it first (no session starts on a locked authority)"));
        }

        if (admin.Sessions.Claim(ticket, browser) is not { } claimed)
        {
            return new ApiResult(409, new ApiProblem(409, "no-sign-in", "this sign-in cannot be claimed"));
        }

        SetCookie(response, AdminSessions.SessionCookie, claimed.Token);
        DropCookie(response, AdminSessions.LoginCookie);
        admin.RecordSessionStart(claimed);
        (DateTimeOffset idle, DateTimeOffset absolute) = admin.SessionEnds(claimed);

        return new ApiResult(201, new ClaimDto(claimed.Csrf, new SessionDto(true, ApprovalSummary.Clean(claimed.Admin), claimed.Started, idle, absolute, null, admin.Recent)));
    }

    private async Task<ApiResult> StartSessionAsync(ApiCall call)
    {
        (AdminStart start, string? ticket) = await admin.BeginLoginAsync(call.Browser!, call.Context.RequestAborted);
        if (ticket is not null)
        {
            SetCookie(call.Context.Response, AdminSessions.LoginCookie, ticket);
        }

        return start.Link is not null ? new ApiResult(202, new { link = start.Link }) : new ApiResult(start.Status, FromStart(start));
    }

    private Task<ApiResult> EndSessionAsync(ApiCall call)
    {
        admin.Sessions.Destroy(call.Token);
        admin.RecordSessionEnd(call.Session!, "ended: sign out");
        DropCookie(call.Context.Response, AdminSessions.SessionCookie);

        return Task.FromResult(new ApiResult(200, new { ok = true }));
    }

    private Task<ApiResult> GetMachineAsync(ApiCall call)
    {
        (MachineDto? machine, string? problem, int status) = admin.FindMachineView(call.Path["fingerprint"]);

        return Task.FromResult(machine is not null ? new ApiResult(200, machine) : new ApiResult(status, new ApiProblem(status, status == 404 ? "not-found" : "invalid-request", problem ?? "not found")));
    }

    private Task<ApiResult> GetGrantAsync(ApiCall call)
    {
        (GrantDto? grant, string? problem, int status) = admin.FindGrantView(call.Path["id"]);

        return Task.FromResult(grant is not null ? new ApiResult(200, grant) : new ApiResult(status, new ApiProblem(status, status == 404 ? "not-found" : "invalid-request", problem ?? "not found")));
    }

    private (AuditQuery? Query, ApiProblem? Problem) AuditQueryOf(ApiCall call, ApiRoute? route = null)
    {
        IQueryCollection query = call.Context.Request.Query;
        ApiRoute self = route ?? _routes.First(item => item.Template == call.Context.Request.Path.Value && item.Method == "GET");
        foreach (string key in query.Keys)
        {
            if (!self.Query.Any(item => item.Name == key) || query[key].Count != 1)
            {
                return (null, new ApiProblem(400, "invalid-request", "the query has a parameter this route does not take, or one given twice"));
            }
        }

        foreach (ApiQuery item in self.Query)
        {
            if (query.TryGetValue(item.Name, out Microsoft.Extensions.Primitives.StringValues one) && one[0] is { } text)
            {
                using JsonDocument probe = JsonDocument.Parse(JsonSerializer.Serialize(text));
                if (item.Name != "last" && ApiValidator.Validate(probe.RootElement, item.Schema, []) is { } invalid)
                {
                    return (null, new ApiProblem(400, "invalid-request", item.Name + ": " + invalid[(invalid.IndexOf(' ', StringComparison.Ordinal) + 1)..]));
                }
            }
        }

        (AuditQuery? parsed, string? error) = AdminService.ParseAuditQuery(name => query.TryGetValue(name, out Microsoft.Extensions.Primitives.StringValues values) && values.Count == 1 ? values[0] : null);

        return parsed is null ? (null, new ApiProblem(400, "invalid-request", error ?? "the query is not valid")) : (parsed, null);
    }

    private Task<ApiResult> AuditEventsAsync(ApiCall call)
    {
        (AuditQuery? query, ApiProblem? problem) = AuditQueryOf(call);
        if (query is null)
        {
            return Task.FromResult(new ApiResult(problem!.Status, problem));
        }

        try
        {
            return Task.FromResult(new ApiResult(200, new { items = admin.AuditEventsView(query) }));
        }
        catch (AuthorityDatabaseException)
        {
            return Task.FromResult(new ApiResult(503, new ApiProblem(503, "audit-unavailable", "the audit history could not be read")));
        }
    }

    private Task<ApiResult> AuditChangesAsync(ApiCall call)
    {
        (AuditQuery? query, ApiProblem? problem) = AuditQueryOf(call);
        if (query is null)
        {
            return Task.FromResult(new ApiResult(problem!.Status, problem));
        }

        try
        {
            return Task.FromResult(new ApiResult(200, new { items = admin.AuditChangesView(query) }));
        }
        catch (AuthorityDatabaseException)
        {
            return Task.FromResult(new ApiResult(503, new ApiProblem(503, "audit-unavailable", "the audit history could not be read")));
        }
    }

    private Task<ApiResult> AuditGapsAsync(ApiCall call)
    {
        (AuditQuery? query, ApiProblem? problem) = AuditQueryOf(call);
        if (query is null)
        {
            return Task.FromResult(new ApiResult(problem!.Status, problem));
        }

        try
        {
            return Task.FromResult(new ApiResult(200, new { items = admin.AuditGapsView(query.MachinePrefix) }));
        }
        catch (AuthorityDatabaseException)
        {
            return Task.FromResult(new ApiResult(503, new ApiProblem(503, "audit-unavailable", "the audit history could not be read")));
        }
    }

    private AuthorizationDto Dto(AuthorizationView view) => new(view.Id, view.Operation, view.State.ToString().ToLowerInvariant(), view.Detail, view.Link, view.Sentence, [.. view.Parameters.Select(item => new NameValueDto(item.Name, item.Value))], view.Created, view.Expires,
        (int)AdminService.AuthorizationLifetime.TotalSeconds);

    private async Task<ApiResult> CreateAuthorizationAsync(ApiCall call)
    {
        JsonElement body = call.Body!.Value;
        string op = body.GetProperty("operation").GetString()!;
        string[] allowed = Operations.First(item => item.Operation == op).Parameters;
        Dictionary<string, string> args = [];
        if (body.TryGetProperty("parameters", out JsonElement parameters))
        {
            foreach (JsonProperty parameter in parameters.EnumerateObject())
            {
                if (!allowed.Contains(parameter.Name))
                {
                    return new ApiResult(400, new ApiProblem(400, "invalid-request", "the operation " + op + " takes " + (allowed.Length == 0 ? "no parameters" : "only the parameters " + string.Join(", ", allowed)) + ""));
                }

                if (ApiValidator.Validate(parameter.Value, ParameterSchema(parameter.Name), []) is { } invalid)
                {
                    return new ApiResult(400, new ApiProblem(400, "invalid-request", "parameters." + invalid["body.".Length..]));
                }

                args[parameter.Name] = AsText(parameter.Value);
            }
        }

        object? owner = OwnerOf(call);
        if (owner is null)
        {
            return new ApiResult(401, new ApiProblem(401, "session-required", "this needs an administrator session"));
        }

        (AuthorizationView? view, AdminStart start) = await admin.BeginAuthorizationAsync(owner, op, args, call.Context.RequestAborted);

        return view is not null ? new ApiResult(201, Dto(view)) : new ApiResult(start.Status, FromStart(start));
    }

    private Task<ApiResult> GetAuthorizationAsync(ApiCall call)
    {
        object? owner = OwnerOf(call);
        AuthorizationView? view = owner is null ? null : admin.FindAuthorization(owner, call.Path["id"]);

        return Task.FromResult(view is not null ? new ApiResult(200, Dto(view)) : new ApiResult(404, new ApiProblem(404, "not-found", "no such authorization for this caller")));
    }

    private async Task<ApiResult> MutateAsync(ApiCall call, string operation, string[] pathParameters)
    {
        JsonElement body = call.Body!.Value;
        string? authorization = body.TryGetProperty("authorization", out JsonElement id) ? id.GetString() : null;
        Dictionary<string, string> args = [];
        foreach (string key in pathParameters)
        {
            args[key] = call.Path[key];
        }

        string op = operation;
        foreach (JsonProperty member in body.EnumerateObject())
        {
            if (member.Name == "authorization")
            {
                continue;
            }

            if (member.Name == "policy")
            {
                op = "policy-" + member.Value.GetString();

                continue;
            }

            args[member.Name] = AsText(member.Value);
        }

        object? owner = OwnerOf(call);
        if (owner is null)
        {
            return new ApiResult(401, new ApiProblem(401, "session-required", "this needs an administrator session"));
        }

        if (call.Session is null && !AdminService.NeedsNoSession(op))
        {
            admin.Refused(op, "no administrator session", AdminService.CallerOf(owner));

            return new ApiResult(401, new ApiProblem(401, "session-required", "this needs an administrator session"));
        }

        MutationResult result = await admin.MutateAsync(owner, op, args, authorization, call.Context.RequestAborted);
        if (result.Status is 200 or 202)
        {
            return new ApiResult(result.Status, new MutationResponse(op, result.Status == 200 ? "applied" : "started", result.Link));
        }

        return new ApiResult(result.Status, new ApiProblem(result.Status, result.Code ?? "operation-refused", result.Detail ?? "refused"));
    }
}

internal sealed record ApiCall(HttpContext Context, Dictionary<string, string> Path, JsonElement? Body, AdminSession? Session, string? Browser, string? Token);

internal sealed record NameValueDto(string Name, string Value);

internal sealed record AuthorizationDto(string Id, string Operation, string State, string? Detail, string? Link, string Sentence, IReadOnlyList<NameValueDto> Parameters, DateTimeOffset Created, DateTimeOffset Expires, int LifetimeSeconds);

internal sealed record MutationResponse(string Operation, string Outcome, string? Link);

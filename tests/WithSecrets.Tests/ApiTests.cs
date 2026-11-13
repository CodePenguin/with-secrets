using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>
/// Phase 6b-1: the administration JSON API under /api/v1. No page, no UI: every check is a request to the API. A session reads and changes nothing; every change is its own fresh, single-use,
/// time-limited, operation-and-parameter-bound passkey authorization (POST /api/v1/authorizations, the tap with user verification, then the one mutation that carries its id); a request that changes
/// anything also needs a same-origin request, a loopback Host and the anti-forgery value. The functions of the removed admin verbs and of the Phase 6a pages are checked here against the API.
/// </summary>
internal static class ApiTests
{
    public static async Task Run(Action<bool, string> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "ws-api-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);
        try
        {
            await PublicAndSignIn(check, root);
            await InlineSignIn(check, root);
            await SessionTimeouts(check, root);
            await LogoutLockRestart(check, root);
            await ForgeryAndOrigin(check, root);
            await SensitiveMatrix(check, root);
            await Binding(check, root);
            await InlineAuthorizations(check, root);
            await ApiTapTimeTests.Run(check, root);
            await MachineFunctions(check, root);
            await SettingsAndPasskeys(check, root);
            await Pending(check, root);
            await LockedState(check, root);
            await VersionsAndFallback(check, root);
            await WebApplication(check, root);
            await OpenApiDocument(check, root);
            await ProblemsAndCanaries(check, root);
            await ApiHardeningTests.Run(check, root);
            await PairingAdminTests.Run(check, root);
            await PairingAdminTests.Refusals(check, root);
            await VerbsAreGone(check);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            try
            {
                Directory.Delete(root, true);
            }
            catch (IOException)
            {
                // A stray temp file is harmless.
            }
        }
    }

    private static async Task InlineAuthorizations(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root);
        AdminBrowser browser = await app.SignedIn();
        string fingerprint = app.Fingerprint;

        async Task<(string Id, string Bind, string RpId)> Prepare(string name)
        {
            (int status, string body) = await browser.PostAsync("/api/v1/authorizations/inline", AdminBrowser.AuthorizationBody("machine-rename", ("fingerprint", fingerprint[..20]), ("name", name)));
            using JsonDocument response = JsonDocument.Parse(body);
            JsonElement item = response.RootElement;
            string id = item.GetProperty("id").GetString()!;
            JsonElement payload = JsonDocument.Parse(item.GetProperty("proof").GetProperty("payload").GetString()!).RootElement;
            check(status == 201 && item.GetProperty("state").GetString() == "pending" && item.GetProperty("link").ValueKind == JsonValueKind.Null,
                "inline authorization: challenge is prepared without a passkey page or an applied change");
            return (id, payload.GetProperty("bind").GetString()!, payload.GetProperty("rpId").GetString()!);
        }

        static byte[] Decode(string text) => Convert.FromBase64String(text.Replace('-', '+').Replace('_', '/') + new string('=', (4 - text.Length % 4) % 4));
        async Task<(int Status, string Body)> Submit(string id, string assertion) => await browser.SendAsync(HttpMethod.Post, "/api/v1/authorizations/" + id + "/proof", JsonSerializer.Serialize(new { proof = assertion }));

        (string id, string bind, string rpId) = await Prepare("inline-approved");
        string signed = app.Laptop.Assert(Decode(bind), browser.Origin, rpId, TestState.NextCount());
        (int accepted, string acceptedBody) = await Submit(id, signed);
        (_, string stateBody, _) = await browser.GetAsync("/api/v1/authorizations/" + id);
        string? refusal = JsonDocument.Parse(stateBody).RootElement.GetProperty("detail").GetString();
        check(accepted == 200 && app.Store.Find(fingerprint)!.FriendlyName == "inline-approved", "inline authorization: full origin, RP id, challenge and user-verification check applies the retained exact plan (" + accepted + ", " + acceptedBody + ", " + refusal + ")");
        (int replay, _) = await Submit(id, signed);
        check(replay == 409 && app.Store.Find(fingerprint)!.FriendlyName == "inline-approved", "inline authorization: a verified assertion is single-use and replay changes nothing");

        string beforeCancel = app.Store.Find(fingerprint)!.FriendlyName!;
        (string cancelId, _, _) = await Prepare("must-not-apply");
        (int cancelled, _) = await browser.SendAsync(HttpMethod.Delete, "/api/v1/authorizations/" + cancelId, null);
        check(cancelled == 200 && app.Store.Find(fingerprint)!.FriendlyName == beforeCancel, "inline authorization: cancellation before the tap applies nothing");

        (string badId, string badBind, string badRpId) = await Prepare("bad-assertion");
        string bad = app.Phone.Assert(Decode(badBind), browser.Origin, badRpId, TestState.NextCount());
        (int refused, _) = await Submit(badId, bad);
        check(refused == 409 && app.Store.Find(fingerprint)!.FriendlyName == beforeCancel, "inline authorization: a non-admin assertion is refused without applying the plan");

        (string alteredId, string alteredBind, string alteredRpId) = await Prepare("original-operation");
        string altered = app.Laptop.Assert(Decode(alteredBind), "https://attacker.invalid", alteredRpId, TestState.NextCount());
        (int wrongOrigin, _) = await Submit(alteredId, altered);
        check(wrongOrigin == 409 && app.Store.Find(fingerprint)!.FriendlyName == beforeCancel, "inline authorization: wrong-origin assertions do not apply the prepared operation");
    }

    private static async Task InlineSignIn(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root);
        AdminBrowser browser = app.Browser();
        await browser.LoadAsync();
        (int started, string body) = await browser.PostAsync("/api/v1/session/inline", "{}");
        using JsonDocument response = JsonDocument.Parse(body);
        string payloadText = response.RootElement.GetProperty("proof").GetProperty("payload").GetString()!;
        using JsonDocument payload = JsonDocument.Parse(payloadText);
        string bind = payload.RootElement.GetProperty("bind").GetString()!;
        string rpId = payload.RootElement.GetProperty("rpId").GetString()!;
        bool noLink = !response.RootElement.TryGetProperty("link", out _);
        byte[] challenge = Convert.FromBase64String(bind.Replace('-', '+').Replace('_', '/') + new string('=', (4 - bind.Length % 4) % 4));
        string signed = app.Laptop.Assert(challenge, browser.Origin, rpId, TestState.NextCount());
        (int verified, _) = await browser.PostAsync("/api/v1/session/inline/proof", JsonSerializer.Serialize(new { proof = signed }));
        (int claimed, _) = await browser.ClaimAsync();
        check(started == 201 && noLink && verified == 200 && claimed == 201 && await browser.StillSignedIn(), "inline sign-in: service challenge is tapped and claimed in the same SPA without a passkey page");

        AdminBrowser cancelled = app.Browser();
        await cancelled.LoadAsync();
        (int pending, _) = await cancelled.PostAsync("/api/v1/session/inline", "{}");
        (int cancelledStatus, _) = await cancelled.SendAsync(HttpMethod.Delete, "/api/v1/session/inline", null);
        (int noLogin, string noLoginBody, _) = await cancelled.GetAsync("/api/v1/session");
        check(pending == 201 && cancelledStatus == 200 && noLogin == 200 && !noLoginBody.Contains("\"waiting\"", StringComparison.Ordinal), "inline sign-in: cancellation discards the pending challenge and starts no session");
    }

    /// <summary>What an administrator change could touch.</summary>
    private static string Snapshot(AdminApp app)
    {
        AuthorityStore store = app.Store;
        MachineRecord machine = store.Find(app.Fingerprint)!;

        return string.Join('|', machine.Status, machine.SecurityRevision, machine.FriendlyName, machine.HostName, machine.PendingHostName, store.ActiveKey()?.Fingerprint, store.GetUnlockPolicy(), store.AuditRetentionDays(), store.SessionTimeouts(), store.Grants().Count, app.Service.Lock.IsLocked);
    }

    private static string AuditText(AuthorityStore store) => string.Join("\n", store.Audit(1000).Select(entry => entry.Event + "|" + entry.Actor + "|" + entry.Detail));

    private static string Fill(ApiRoute route) => route.Template.Replace("{fingerprint}", "aaaaaaaaaaaa", StringComparison.Ordinal).Replace("{id}", "abcd1234", StringComparison.Ordinal).Replace("{name}", "phone", StringComparison.Ordinal);

    private static string? Code(string body)
    {
        try
        {
            using JsonDocument doc = JsonDocument.Parse(body);

            return doc.RootElement.TryGetProperty("code", out JsonElement code) ? code.GetString() : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? Member(string body, string name)
    {
        using JsonDocument doc = JsonDocument.Parse(body);

        return doc.RootElement.TryGetProperty(name, out JsonElement value) ? (value.ValueKind == JsonValueKind.String ? value.GetString() : value.GetRawText()) : null;
    }

    private static string ContentType(HttpResponseMessage response) => response.Content.Headers.ContentType?.MediaType ?? "";

    // ---- the public status, the sign-in and the cookie ----

    private static async Task PublicAndSignIn(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root);
        AdminBrowser b = app.Browser();
        (int status, string body, HttpResponseMessage response) = await b.GetAsync("/api/v1/status");
        check(status == 200 && Member(body, "running") == "true" && Member(body, "locked") == "false" && Member(body, "unlockMode") == "manual" && Member(body, "apiVersion") == "v1" && !body.Contains(app.Fingerprint, StringComparison.Ordinal), "api status: public, shows running, the lock state, the unlock mode and the versions, and nothing of any machine");
        check(ContentType(response) == "application/json" && response.Headers.GetValues("X-Api-Version").Single() == "1" && response.Headers.Contains("X-Frame-Options") && response.Headers.GetValues("Cache-Control").Single().Contains("no-store", StringComparison.Ordinal)
            && response.Headers.GetValues("X-Content-Type-Options").Single() == "nosniff" && response.Headers.GetValues("Content-Security-Policy").Single().Contains("default-src 'none'", StringComparison.Ordinal), "api status: JSON, version header, not frameable, not cached, no sniffing, a locked-down CSP");

        List<ApiRoute> reads = [.. app.Service.Admin.Api.Routes.Where(route => route.Access == ApiAccess.Read)];
        check(reads.Count >= 9, "api reads: the route table has the read routes (" + reads.Count + ")");
        foreach (ApiRoute route in reads)
        {
            (int readStatus, string readBody, HttpResponseMessage readResponse) = await b.GetAsync(Fill(route));
            check(readStatus == 401 && ContentType(readResponse) == "application/problem+json" && Code(readBody) == "session-required" && !readBody.Contains(app.Fingerprint, StringComparison.Ordinal), "api read " + route.Template + " is not served without a session (401 session-required)");
        }

        // Only an admin key's fresh tap with user verification, on the page of this login, starts a session.
        (string Label, TestAuthenticator Who, bool Uv, Func<byte[], byte[]>? Change)[] bad =
        [
            ("a key that is not an admin key", app.Phone, true, null),
            ("an assertion without user verification", app.Laptop, false, null),
            ("a signature over another challenge", app.Laptop, true, challenge => SHA256.HashData(challenge)),
        ];
        foreach ((string label, TestAuthenticator who, bool uv, Func<byte[], byte[]>? change) in bad)
        {
            bool started = await b.SignInAsync(who, uv, change);
            check(!started && !b.HasSession && (await b.GetAsync("/api/v1/machines")).Status == 401, "session: " + label + " starts no session");
        }

        check(app.Service.Admin.Sessions.Count == 0, "session: after refused sign-ins the service holds no session");
        string whoamiBefore = (await b.GetAsync("/api/v1/session")).Html;
        string browserToken = b.BrowserToken!;
        check(Member(whoamiBefore, "authenticated") == "false", "session: whoami says there is no session before the tap");
        check(await b.SignInAsync(app.Laptop) && b.HasSession, "session: the admin key's tap (with user verification) starts one");
        string cookie = b.LastSetCookie.Split('\n').FirstOrDefault(line => line.StartsWith(AdminSessions.SessionCookie + "=", StringComparison.Ordinal)) ?? "";
        string token = b.Cookies[AdminSessions.SessionCookie];
        check(cookie.Length == 0 || (cookie.Contains("httponly", StringComparison.OrdinalIgnoreCase) && cookie.Contains("samesite=strict", StringComparison.OrdinalIgnoreCase) && cookie.Contains("path=/api/v1", StringComparison.OrdinalIgnoreCase)), "session: the cookie (when set) is HttpOnly, SameSite=Strict and scoped to /api/v1");
        (int whoStatus, string whoami, HttpResponseMessage whoResponse) = await b.GetAsync("/api/v1/session");
        check(whoStatus == 200 && Member(whoami, "authenticated") == "true" && Member(whoami, "admin") == "laptop" && !whoami.Contains("antiForgery", StringComparison.OrdinalIgnoreCase) && b.SessionToken != browserToken && !whoami.Contains(b.SessionToken!, StringComparison.Ordinal) && Member(whoami, "idleExpires") is { Length: > 10 } && Member(whoami, "absoluteExpires") is { Length: > 10 } && !whoami.Contains(token, StringComparison.Ordinal), "session: whoami names the key that tapped, when it ends, never the token or any secret (the session secret is given once, by the claim)");
        _ = whoResponse;
        string seen = string.Join("\n", b.Seen);
        check(!seen.Contains(token, StringComparison.Ordinal) || seen.Split('\n').Where(line => line.Contains(token, StringComparison.Ordinal)).All(line => line.StartsWith("Set-Cookie", StringComparison.OrdinalIgnoreCase)), "session: the token is in the Set-Cookie header only, in no body");
        foreach (ApiRoute route in reads.Where(item => !item.Template.Contains('{', StringComparison.Ordinal)))
        {
            (int viewStatus, string viewBody, _) = await b.GetAsync(route.Template);
            check(viewStatus == 200 && !viewBody.Contains(token, StringComparison.Ordinal) && !viewBody.Contains("authenticatorData", StringComparison.Ordinal), "session: " + route.Template + " is served read-only to the session (no token, no proof)");
        }

        string audit = AuditText(app.Store);
        check(app.Store.Audit(1000).Any(entry => entry.Event == "admin-operation" && entry.Detail.StartsWith("admin-session; started", StringComparison.Ordinal) && entry.Actor == "admin passkey laptop"), "session: the start is in the authority's audit history with the key that tapped");
        check(!audit.Contains(token, StringComparison.Ordinal) && !audit.Contains("authenticatorData", StringComparison.Ordinal), "session: the audit history holds neither the token nor a proof");
        string machines = (await b.GetAsync("/api/v1/machines")).Html;
        using (JsonDocument doc = JsonDocument.Parse(machines))
        {
            JsonElement one = doc.RootElement.GetProperty("items")[0];
            check(one.GetProperty("fingerprint").GetString() == app.Fingerprint && one.GetProperty("display").GetString() == KeyIdentity.Display(app.Fingerprint) && one.GetProperty("status").GetString() == "trusted" && one.GetProperty("hostName").GetString() == app.Machine.HostName, "machines: the list shows the fingerprint, status and host name");
        }

        (int detailStatus, string detail, _) = await b.GetAsync("/api/v1/machines/" + KeyIdentity.Display(app.Fingerprint).Replace(" ", "", StringComparison.Ordinal)[..16]);
        check(detailStatus == 200 && Member(detail, "fingerprint") == app.Fingerprint, "machines: one machine by an unambiguous start of its fingerprint");
        check((await b.GetAsync("/api/v1/machines/" + new string('0', 20))).Status == 404 && (await b.GetAsync("/api/v1/machines/zz")).Status == 400, "machines: an unknown machine is 404 and a malformed fingerprint 400");
        string settings = (await b.GetAsync("/api/v1/settings")).Html;
        check(Member(settings, "auditRetentionDays") == "365" && Member(settings, "sessionIdleMinutes") == "15" && Member(settings, "sessionAbsoluteMinutes") == "480" && Member(settings, "unlockMode") == "manual", "settings: the audit retention, the session timeouts and the unlock mode");
        check(Member((await b.GetAsync("/api/v1/passkeys")).Html, "available") == "true" && (await b.GetAsync("/api/v1/passkeys")).Html.Contains("laptop", StringComparison.Ordinal), "passkeys: the enrolled passkeys are listed (names and kinds only)");
    }

    // ---- the idle and absolute timeouts, with a fake clock ----

    private static async Task SessionTimeouts(Action<bool, string> check, string root)
    {
        // Idle: each use renews; fifteen minutes of nothing ends it.
        using (AdminApp app = new(root))
        {
            AdminBrowser b = await app.SignedIn();
            app.Clock.Advance(TimeSpan.FromMinutes(14));
            bool first = (await b.GetAsync("/api/v1/machines")).Status == 200;
            app.Clock.Advance(TimeSpan.FromMinutes(14));
            bool renewed = (await b.GetAsync("/api/v1/machines")).Status == 200;
            app.Clock.Advance(TimeSpan.FromMinutes(16));
            (int expired, _, _) = await b.GetAsync("/api/v1/machines");
            check(first && renewed && expired == 401 && app.Service.Admin.Sessions.Count == 0, "session: it ends after the idle timeout (15 minutes) without use, and each use renews it");
            await b.LoadAsync();
            check((await b.GetAsync("/api/v1/grants")).Status == 401 && (await b.PostAsync("/api/v1/lock", "{\"authorization\":\"AAAAAAAAAAAA\"}")).Status is 401 or 403, "session: an expired session's cookie reads and changes nothing");
        }

        // Absolute: however busy, it ends at the absolute timeout. The timeouts are a setting (a tap of their own).
        using AdminApp absolute = new(root);
        AdminBrowser c = await absolute.SignedIn();
        Tapped set = await c.OpAsync("set-session-timeouts", absolute.Laptop, true, null, true, ("idle", "5"), ("absolute", "10"));
        check(set.MutationStatus == 200 && absolute.Store.SessionTimeouts() == (5, 10), "settings: the session timeouts are changed by a tap of their own (5 and 10 minutes) " + set.PostStatus + " " + set.Error + " " + set.ApproveStatus + " " + set.MutationStatus + " " + set.MutationBody);
        absolute.Clock.Advance(TimeSpan.FromMinutes(4));
        bool a1 = (await c.GetAsync("/api/v1/machines")).Status == 200;
        absolute.Clock.Advance(TimeSpan.FromMinutes(4));
        bool a2 = (await c.GetAsync("/api/v1/machines")).Status == 200;
        absolute.Clock.Advance(TimeSpan.FromMinutes(4));
        check(a1 && a2 && (await c.GetAsync("/api/v1/machines")).Status == 401, "session: it ends at the absolute timeout even when it was used within the idle timeout");
    }

    // ---- logout, lock and restart end sessions ----

    private static async Task LogoutLockRestart(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root);
        AdminBrowser b = await app.SignedIn();
        string token = b.Cookies[AdminSessions.SessionCookie];
        (int noToken, _) = await b.SendAsync(HttpMethod.Delete, "/api/v1/session", null, token: null);
        check(noToken == 403 && b.HasSession, "session: sign out without the anti-forgery value is refused");
        (int outStatus, _) = await b.SendAsync(HttpMethod.Delete, "/api/v1/session", null);
        AdminBrowser replay = app.Browser();
        replay.SetCookie(AdminSessions.SessionCookie, token);
        check(outStatus == 200 && !b.HasSession && (await replay.GetAsync("/api/v1/machines")).Status == 401 && app.Service.Admin.Sessions.Count == 0, "session: sign out ends it; the old cookie value is refused afterwards");
        check(app.Store.Audit(1000).Any(entry => entry.Event == "admin-operation" && entry.Detail.StartsWith("admin-session; ended: sign out", StringComparison.Ordinal)), "session: the end is audited too");

        // Lock destroys every session, and a locked authority starts none.
        AdminBrowser one = await app.SignedIn();
        AdminBrowser two = await app.SignedIn();
        check(app.Service.Admin.Sessions.Count == 2, "session: two browsers can be signed in at once");
        Tapped lockTap = await one.OpAsync(AdminService.OpLock, app.Laptop);
        check(lockTap.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => app.Service.Lock.IsLocked), "lock: the admin key's fresh tap locks");
        check(app.Service.Admin.Sessions.Count == 0 && (await one.GetAsync("/api/v1/machines")).Status == 401 && (await two.GetAsync("/api/v1/grants")).Status == 401, "lock: it destroys every session at once");
        // M4: with the authority locked the key operations (and every other change) are refused before any page, and the refusal is audited.
        AdminSession forged = new("t", "laptop", app.Clock.GetUtcNow(), "c");
        string keyBefore = app.Store.ActiveKey()?.Fingerprint ?? "";
        int askedLocked = app.Asked;
        List<AdminStart> lockedAnswers = [];
        foreach (string lockedOp in new[] { "authority-key-rotate", "authority-key-recover", "machine-disable", "set-audit-retention", "policy-unattended" })
        {
            lockedAnswers.Add((await app.Service.Admin.BeginAuthorizationAsync(forged, lockedOp, new Dictionary<string, string> { ["fingerprint"] = app.Fingerprint[..20], ["days"] = "5" }, CancellationToken.None)).Start);
        }

        check(lockedAnswers.All(answer => answer.Status == 423 && answer.Link is null) && app.Asked == askedLocked && (app.Store.ActiveKey()?.Fingerprint ?? "") == keyBefore && app.Store.AuditRetentionDays() == 365, "lock: while locked no operation but the unlock gets a page (423); the key is not rotated or recovered");
        check(app.Store.Audit(1000).Count(entry => entry.Event == "admin-operation" && entry.Detail.Contains("authority is locked", StringComparison.Ordinal)) >= 3, "lock: those refused attempts are in the audit history");
        await two.LoadAsync();
        (int loginStatus, string loginBody) = await two.PostAsync("/api/v1/session", "{}");
        check(loginStatus == 423 && Code(loginBody) == "authority-locked" && (await two.GetAsync("/api/v1/machines")).Status == 401 && app.Service.Admin.Sessions.Count == 0, "lock: a locked authority refuses to start a session (" + loginBody + ")");
        Tapped unlock = await two.OpAsync(AdminService.OpUnlock, app.Laptop);
        check(unlock.MutationStatus == 200 && !app.Service.Lock.IsLocked && app.Service.Admin.Sessions.Count == 0, "lock: unlock needs no session and starts none " + unlock.PostStatus + " " + unlock.Error + " " + unlock.ApproveStatus + " " + unlock.MutationStatus + " " + unlock.MutationBody);

        // A restart destroys them: the sessions are in memory only.
        AdminBrowser before = await app.SignedIn();
        string oldToken = before.Cookies[AdminSessions.SessionCookie];
        app.Start(true);
        AdminBrowser after = app.Browser();
        after.SetCookie(AdminSessions.SessionCookie, oldToken);
        check((await after.GetAsync("/api/v1/machines")).Status == 401 && app.Service.Admin.Sessions.Count == 0, "session: a service restart destroys every session");
        string files = string.Join("\n", Directory.EnumerateFiles(app.Machine.Folder, "*", SearchOption.AllDirectories).Where(file => !file.EndsWith("-shm", StringComparison.Ordinal)).Select(file =>
        {
            using FileStream stream = new(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using StreamReader reader = new(stream, Encoding.Latin1);

            return reader.ReadToEnd();
        }));
        check(!files.Contains(oldToken, StringComparison.Ordinal), "session: the token is in no file of the authority (memory only)");
    }

    // ---- anti-forgery, origin, host, body ----

    private static async Task ForgeryAndOrigin(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root);
        AdminBrowser b = app.Browser();
        await b.LoadAsync();
        string browserToken = b.Csrf!;
        check(await b.SignInAsync(app.Laptop), "forgery: signed in");
        string sessionToken = b.Csrf!;
        check(sessionToken.Length > 0 && sessionToken != browserToken, "forgery: the anti-forgery value changes with the session");
        AdminBrowser other = app.Browser();
        await other.LoadAsync();

        string before = Snapshot(app);
        int asked = app.Asked;
        string fp = app.Fingerprint[..20];
        string authorize = AdminBrowser.AuthorizationBody("machine-disable", ("fingerprint", fp));
        string mutate = "{\"authorization\":\"AAAAAAAAAAAA\"}";
        string disablePath = "/api/v1/machines/" + fp + "/disable";
        foreach ((string path, string body, string kind) in new[] { ("/api/v1/authorizations", authorize, "authorization request"), (disablePath, mutate, "change") })
        {
            (string Label, Func<Task<(int Status, string Body)>> Send, int Expect)[] cases =
            [
                ("no Origin (a program, not a page)", () => b.PostAsync(path, body, origin: null), 403),
                ("an Origin of another site", () => b.PostAsync(path, body, origin: "http://evil.example"), 403),
                ("an Origin of another port on this machine", () => b.PostAsync(path, body, origin: "http://localhost:1"), 403),
                ("the Origin null of a sandboxed page", () => b.PostAsync(path, body, origin: "null"), 403),
                ("no anti-forgery value", () => b.PostAsync(path, body, token: null), 403),
                ("a wrong anti-forgery value", () => b.PostAsync(path, body, token: "AAAA"), 403),
                ("another browser's anti-forgery value", () => b.PostAsync(path, body, token: other.Csrf), 403),
                ("the anti-forgery value of the time before the session (the browser's, not the session's)", () => b.PostAsync(path, body, token: browserToken), 401),
                ("a valid value but no cookies (a script that stole the value, not the cookie)", () => b.PostAsync(path, body, withCookies: false), 403),
                ("a Host that is not a loopback name (DNS rebinding)", () => b.PostAsync(path, body, host: "evil.example:" + app.Service.Port), 421),
                ("a body that is not JSON", () => b.PostAsync(path, "op=lock", contentType: "text/plain"), 415),
                ("a body that is too large", () => b.PostAsync(path, "{\"authorization\":\"" + new string('a', 5000) + "\"}"), 413),
                ("a body that is broken JSON", () => b.PostAsync(path, "{\"authorization\":"), 400),
                ("a body with a member twice", () => b.PostAsync(path, "{\"authorization\":\"AAAAAAAAAAAA\",\"authorization\":\"BBBBBBBBBBBB\"}"), 400),
                ("a body that is not an object", () => b.PostAsync(path, "[1]"), 400),
                ("a body with a member the route does not take", () => b.PostAsync(path, "{\"authorization\":\"AAAAAAAAAAAA\",\"policy\":\"x\",\"extra\":1}"), 400),
                ("a body with the wrong type", () => b.PostAsync(path, "{\"authorization\":12345678}"), 400),
            ];
            foreach ((string label, Func<Task<(int Status, string Body)>> send, int expect) in cases)
            {
                (int status, string answer) = await send();
                bool nonsenseForOtherRoute = path.EndsWith("/authorizations", StringComparison.Ordinal) && expect == 400;
                check(status == expect || nonsenseForOtherRoute && status == 400, "forgery (" + kind + "): " + label + " is refused (" + status + ")");
                check(answer.Length == 0 || Code(answer) is not null || status == 421, "forgery (" + kind + "): " + label + " answers a problem document");
            }
        }

        check(Snapshot(app) == before && app.Asked == asked, "forgery: none of those started a passkey page or changed anything");
        (int getOrigin, _, _) = await b.GetAsync("/api/v1/machines", origin: "http://evil.example");
        (int getHost, _, _) = await b.GetAsync("/api/v1/machines", host: "evil.example:" + app.Service.Port);
        (int getStatusOrigin, _, _) = await b.GetAsync("/api/v1/status", origin: "http://evil.example");
        (int getDoc, _, _) = await b.GetAsync("/api/v1/openapi.json", origin: "http://evil.example");
        check(getOrigin == 403 && getHost == 421 && getStatusOrigin == 403 && getDoc == 403, "forgery: a read (even of the public status and the document) from another site or another Host is refused; there is no CORS");
        using (HttpRequestMessage preflight = new(HttpMethod.Options, b.Base + "/api/v1/machines"))
        {
            preflight.Headers.Add("Origin", "http://evil.example");
            preflight.Headers.Add("Access-Control-Request-Method", "POST");
            using HttpResponseMessage preflightAnswer = await app.Http.SendAsync(preflight);
            check((int)preflightAnswer.StatusCode is 403 or 405 && !preflightAnswer.Headers.Contains("Access-Control-Allow-Origin") && !preflightAnswer.Headers.Contains("Access-Control-Allow-Methods"), "forgery: a CORS preflight is refused and no Access-Control header is ever sent");
        }

        // Without a session, a sensitive operation is refused even with a valid page value; the unlock is the one thing it may ask for.
        AdminBrowser anon = app.Browser();
        await anon.LoadAsync();
        (int anonAuthorize, string anonBody) = await anon.PostAsync("/api/v1/authorizations", authorize);
        (int anonMutate, _) = await anon.PostAsync(disablePath, mutate);
        check(anonAuthorize == 401 && Code(anonBody) == "session-required" && anonMutate == 401 && app.Asked == asked && Snapshot(app) == before, "forgery: a sensitive operation with no session is refused (401) and asks for no passkey");
        (int unlockStatus, _) = await anon.PostAsync("/api/v1/authorizations", AdminBrowser.AuthorizationBody("unlock"));
        check(unlockStatus == 409, "forgery: asking to unlock without a session reaches the service (here already unlocked: " + unlockStatus + ")");
        check(app.Store.Audit(1000).Count(entry => entry.Event == "admin-operation" && entry.Detail.Contains("refused", StringComparison.Ordinal)) >= 3, "forgery: refused requests are audited");
    }

    // ---- every sensitive operation: a session is not enough ----

    private static async Task SensitiveMatrix(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root, protection: true);
        string fp = app.Fingerprint;
        AdminBrowser b = await app.SignedIn();
        int refusals = 0;
        async Task Operation(string label, string op, params (string, string)[] args)
        {
            app.Clock.Advance(TimeSpan.FromSeconds(31));
            string before = Snapshot(app);
            (string Name, TestAuthenticator Who, bool Uv, Func<byte[], byte[]>? Change)[] variants =
            [
                ("a key that is not an admin key", app.Phone, true, null),
                ("an assertion without user verification", app.Laptop, false, null),
                ("a signature over another challenge", app.Laptop, true, challenge => SHA256.HashData(challenge)),
            ];
            foreach ((string name, TestAuthenticator who, bool uv, Func<byte[], byte[]>? change) in variants)
            {
                Tapped denied = await b.OpAsync(op, who, uv, change, true, args);
                refusals++;
                (HttpMethod method, string path, string json) = b.MutationRequest(op, denied.AuthorizationId, args);
                (int forced, string forcedBody) = await b.SendAsync(method, path, json);
                check(denied.Link is not null && denied.ApproveStatus is 403 or 400 && denied.MutationStatus == 0 && forced == 403 && Snapshot(app) == before, $"sensitive {label}: {name} changes nothing, and its authorization cannot be spent ({Code(forcedBody)})");
            }

            Tapped done = await b.OpAsync(op, app.Laptop, true, null, true, args);
            check(done.ApproveStatus == 200 && done.MutationStatus == 200 && Snapshot(app) != before, $"sensitive {label}: the genuine fresh tap and its mutation apply it");
            string settled = Snapshot(app);
            TestState.Post(app.Http, done.PageUrl + "/proof", done.ProofBody);
            (HttpMethod method2, string path2, string json2) = b.MutationRequest(op, done.AuthorizationId, args);
            (int again, string againBody) = await b.SendAsync(method2, path2, json2);
            check(Snapshot(app) == settled && again == 200 && againBody.Contains("\"already-applied\"", StringComparison.Ordinal), $"sensitive {label}: replaying the proof, or the authorization, applies nothing again (the retry is answered as already applied)");
        }

        // A session alone (and the sign-in tap before it) changes nothing and asks for a page of its own.
        string start = Snapshot(app);
        int askedBefore = app.Asked;
        Tapped sessionOnly = await b.OpAsync("machine-disable", null, true, null, true, ("fingerprint", fp[..20]));
        await Task.Delay(300);
        check(sessionOnly.Link is not null && app.Asked == askedBefore + 1 && Snapshot(app) == start, "sensitive: a signed-in session starts the operation's own passkey page and, without its tap, changes nothing");
        (HttpMethod pm, string pp, string pj) = b.MutationRequest("machine-disable", sessionOnly.AuthorizationId, ("fingerprint", fp[..20]));
        (int pendingStatus, string pendingBody) = await b.SendAsync(pm, pp, pj);
        check(pendingStatus == 403 && Code(pendingBody) == "authorization-pending" && Snapshot(app) == start, "sensitive: the mutation sent before the tap is refused (authorization-pending)");

        await Operation("rename", "machine-rename", ("fingerprint", fp[..20]), ("name", "renamed again"));
        await Operation("disable", "machine-disable", ("fingerprint", fp[..20]));
        await Operation("enable", "machine-enable", ("fingerprint", fp[..20]));
        await Operation("untrust", "machine-untrust", ("fingerprint", fp[..20]));
        await Operation("trust", "machine-trust", ("fingerprint", fp[..20]), ("confirm", fp));
        await Operation("rotate-authority-key", "authority-key-rotate");
        await Operation("recover-authority-key", "authority-key-recover");
        await Operation("audit retention", "set-audit-retention", ("days", "7"));
        await Operation("session timeouts", "set-session-timeouts", ("idle", "20"), ("absolute", "600"));
        await Operation("unattended unlock", "policy-unattended");
        await Operation("manual unlock", "policy-manual");
        check(refusals == 33, "sensitive: eleven operations (the host name change is in the machine functions: the running host keeps reporting its own name), three refusals each (" + refusals + ")");

        // A tap for one operation, replayed on the page of another (other operation or other parameters), changes nothing.
        app.Clock.Advance(TimeSpan.FromSeconds(31));
        Tapped first = await b.OpAsync("machine-rename", app.Laptop, true, null, true, ("fingerprint", fp[..20]), ("name", "first name"));
        Tapped second = await b.OpAsync("machine-rename", null, true, null, true, ("fingerprint", fp[..20]), ("name", "second name"));
        (int crossed, _) = TestState.Post(app.Http, second.PageUrl + "/proof", first.ProofBody);
        string secondState = await b.WaitAuthorizationAsync(second.AuthorizationId!);
        check(crossed != 200 && app.Store.Find(fp)!.FriendlyName == "first name" && secondState != "verified", "sensitive: a proof made for one set of parameters, sent to another operation's page, authorizes nothing");
        Tapped third = await b.OpAsync("machine-disable", null, true, null, true, ("fingerprint", fp[..20]));
        (int crossedOp, _) = TestState.Post(app.Http, third.PageUrl + "/proof", first.ProofBody);
        check(crossedOp != 200 && app.Store.Find(fp)!.Status == MachineStatus.Trusted, "sensitive: a proof made for another operation, sent to this page, changes nothing");

        // Fail closed with no answer at all: the page times out and nothing changes.
        using AdminApp silent = new(root, askSeconds: 2);
        AdminBrowser s = await silent.SignedIn();
        string silentBefore = Snapshot(silent);
        Tapped nobody = await s.OpAsync("machine-disable", null, true, null, true, ("fingerprint", silent.Fingerprint[..20]));
        await Task.Delay(TimeSpan.FromSeconds(3.5));
        (HttpMethod sm, string sp, string sj) = s.MutationRequest("machine-disable", nobody.AuthorizationId, ("fingerprint", silent.Fingerprint[..20]));
        (int silentStatus, string silentBody) = await s.SendAsync(sm, sp, sj);
        check(nobody.Link is not null && Snapshot(silent) == silentBefore && silentStatus == 403 && Code(silentBody) == "authorization-refused" && silent.Store.Audit(1000).Any(entry => entry.Event == "admin-operation" && entry.Detail.StartsWith("disable-machine; refused", StringComparison.Ordinal)), "sensitive: a passkey page nobody taps ends at its time limit; the authorization is refused, nothing changes and the refusal is audited");

        // The audit history names every attempt and its outcome and holds no proof.
        string audit = AuditText(app.Store);
        check(audit.Contains("rename-machine; requested", StringComparison.Ordinal) && audit.Contains("rename-machine; authorized", StringComparison.Ordinal) && audit.Contains("rename-machine; applied", StringComparison.Ordinal) && audit.Contains("rename-machine; refused", StringComparison.Ordinal), "sensitive: every attempt and its outcome (requested, refused, authorized, applied) is in the audit history");
        check(!audit.Contains("authenticatorData", StringComparison.Ordinal) && !audit.Contains("clientDataJSON", StringComparison.Ordinal), "sensitive: the audit history holds no proof");
    }

    // ---- the authorization is bound: operation, parameters, caller, freshness, single use ----

    private static async Task Binding(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root, protection: true);
        string fp = app.Fingerprint[..20];
        AdminBrowser b = await app.SignedIn();

        async Task<(Tapped Tap, string State)> Authorized(string op, params (string, string)[] args)
        {
            app.Clock.Advance(TimeSpan.FromSeconds(31));
            Tapped made = await b.OpAsyncWithoutMutation(op, app.Laptop, args);

            return (made, made.AuthorizationId is null ? "none" : await b.WaitAuthorizationAsync(made.AuthorizationId));
        }

        async Task<(int Status, string Body)> Send(string op, string? authorization, params (string, string)[] args)
        {
            (HttpMethod method, string path, string json) = b.MutationRequest(op, authorization, args);

            return await b.SendAsync(method, path, json);
        }

        // a. A session alone, with no authorization or a made-up one: nothing, and no passkey is asked for.
        string start = Snapshot(app);
        int asked = app.Asked;
        (int noAuthorization, string noAuthorizationBody) = await b.SendAsync(HttpMethod.Post, "/api/v1/machines/" + fp + "/disable", "{}");
        (int madeUp, string madeUpBody) = await Send("machine-disable", "AAAAAAAAAAAAAAAAAAAA", ("fingerprint", fp));
        check(noAuthorization == 400 && madeUp == 403 && Code(madeUpBody) == "authorization-invalid" && Snapshot(app) == start && app.Asked == asked, "binding: a session alone changes nothing; no authorization (400) or a made-up one (403) is refused and asks for no passkey (" + noAuthorizationBody.Length + ")");

        // b. An authorization for one operation does not authorize another. The service made the change its tap authorized when the tap was verified, so a request for another operation changes nothing.
        (Tapped rename, string renameState) = await Authorized("machine-rename", ("fingerprint", fp), ("name", "alpha"));
        (int wrongOp, string wrongOpBody) = await Send("machine-disable", rename.AuthorizationId, ("fingerprint", fp));
        (int afterWrongOp, string afterWrongOpBody) = await Send("machine-rename", rename.AuthorizationId, ("fingerprint", fp), ("name", "alpha"));
        check(renameState == "consumed" && wrongOp == 403 && Code(wrongOpBody) == "authorization-mismatch" && app.Store.Find(app.Fingerprint)!.Status == MachineStatus.Trusted && app.Store.Find(app.Fingerprint)!.FriendlyName == "alpha" && afterWrongOp == 200 && afterWrongOpBody.Contains("\"applied\"", StringComparison.Ordinal), "binding: an authorization for another operation is refused (mismatch) and changes nothing; the right request is answered with the outcome of the change its tap made (" + Code(afterWrongOpBody) + ")");

        // c. Other parameters: another name, another spelling of the fingerprint.
        (Tapped alpha, _) = await Authorized("machine-rename", ("fingerprint", fp), ("name", "alpha"));
        (int otherName, string otherNameBody) = await Send("machine-rename", alpha.AuthorizationId, ("fingerprint", fp), ("name", "beta"));
        check(otherName == 403 && Code(otherNameBody) == "authorization-mismatch" && app.Store.Find(app.Fingerprint)!.FriendlyName != "beta", "binding: the same operation with another name is refused (mismatch)");
        (Tapped alpha2, _) = await Authorized("machine-rename", ("fingerprint", fp), ("name", "alpha"));
        (int otherFingerprint, string otherFingerprintBody) = await Send("machine-rename", alpha2.AuthorizationId, ("fingerprint", app.Fingerprint[..18]), ("name", "alpha"));
        check(otherFingerprint == 403 && Code(otherFingerprintBody) == "authorization-mismatch", "binding: the same operation with another spelling of the machine is refused (mismatch)");
        (Tapped extra, _) = await Authorized("machine-rename", ("fingerprint", fp), ("name", "alpha"));
        (int moreParameters, string moreParametersBody) = await Send("machine-rename", extra.AuthorizationId, ("fingerprint", fp), ("name", "alpha"), ("minutes", "5"));
        check(moreParameters is 400 or 403 && app.Store.Find(app.Fingerprint)!.FriendlyName == "alpha" && app.Store.Find(app.Fingerprint)!.Status == MachineStatus.Trusted, "binding: an extra parameter is refused (" + moreParameters + " " + Code(moreParametersBody) + ")");

        // d. Another caller cannot spend it, or even see it.
        AdminBrowser thief = await app.SignedIn();
        (Tapped mine, _) = await Authorized("machine-rename", ("fingerprint", fp), ("name", "gamma"));
        (HttpMethod tm, string tp, string tj) = thief.MutationRequest("machine-rename", mine.AuthorizationId, ("fingerprint", fp), ("name", "gamma"));
        (int stolen, string stolenBody) = await thief.SendAsync(tm, tp, tj);
        (int seen, _) = await thief.SendAsync(HttpMethod.Get, "/api/v1/authorizations/" + mine.AuthorizationId, null);
        check(stolen == 403 && Code(stolenBody) == "authorization-invalid" && seen == 404, "binding: another session cannot spend or look at an authorization made for this one");
        (int owner, string ownerBody) = await Send("machine-rename", mine.AuthorizationId, ("fingerprint", fp), ("name", "gamma"));
        (int ownerSees, string ownerSeesBody) = await b.SendAsync(HttpMethod.Get, "/api/v1/authorizations/" + mine.AuthorizationId, null);
        check(owner == 200 && ownerBody.Contains("\"applied\"", StringComparison.Ordinal) && ownerSees == 200 && ownerSeesBody.Contains("\"outcome\":\"applied\"", StringComparison.Ordinal) && app.Store.Find(app.Fingerprint)!.FriendlyName == "gamma", "binding: the caller it was made for gets the outcome of the change its tap made, and no other");

        // e. An earlier authorization never satisfies another operation.
        (int reuse, string reuseBody) = await Send("machine-disable", mine.AuthorizationId, ("fingerprint", fp));
        check(reuse == 403 && Code(reuseBody) == "authorization-mismatch" && app.Store.Find(app.Fingerprint)!.Status == MachineStatus.Trusted, "binding: a spent authorization satisfies no other change (mismatch)");

        // f. The change was made at the tap, so a retry long after changes nothing; an authorization whose tap never came expires.
        (Tapped late, string lateState) = await Authorized("machine-rename", ("fingerprint", fp), ("name", "late"));
        app.Clock.Advance(AdminService.AuthorizationLifetime + TimeSpan.FromSeconds(5));
        await Send("machine-rename", late.AuthorizationId, ("fingerprint", fp), ("name", "late"));
        (int retried, string retriedBody) = await Send("machine-rename", late.AuthorizationId, ("fingerprint", fp), ("name", "late"));
        check(lateState == "consumed" && retried == 200 && retriedBody.Contains("\"already-applied\"", StringComparison.Ordinal) && app.Store.Find(app.Fingerprint)!.FriendlyName == "late", "binding: the change was made at the tap; a retry after " + AdminService.LifetimeText + " seconds is answered as already applied and applies nothing again");

        // g. A tap by another key, or without user verification, never becomes a usable authorization.
        Tapped outsider = await b.OpAsyncWithoutMutation("machine-rename", app.Phone, ("fingerprint", fp), ("name", "outsider"));
        Tapped noUv = await b.OpAsyncWithoutMutation("machine-rename", app.Laptop, userVerified: false, args: [("fingerprint", fp), ("name", "no uv")]);
        (int fromOutsider, _) = await Send("machine-rename", outsider.AuthorizationId, ("fingerprint", fp), ("name", "outsider"));
        (int fromNoUv, _) = await Send("machine-rename", noUv.AuthorizationId, ("fingerprint", fp), ("name", "no uv"));
        check(fromOutsider == 403 && fromNoUv == 403 && app.Store.Find(app.Fingerprint)!.FriendlyName == "late", "binding: a tap by a non-admin key, or without user verification, authorizes nothing");

        // h. The passkey signs the operation and every parameter: they are the page's text and the authorization's text.
        string text = alpha.Page;
        check(text.Contains("Operation: rename-machine", StringComparison.Ordinal) && text.Contains("Parameter friendly-name: alpha", StringComparison.Ordinal) && text.Contains("Parameter machine: " + app.Fingerprint, StringComparison.Ordinal) && text.Contains("Ticket: ", StringComparison.Ordinal), "binding: the page the passkey signs names the operation, the machine and the name");
        (int createStatus, string created) = await b.PostAsync("/api/v1/authorizations", AdminBrowser.AuthorizationBody("machine-rename", ("fingerprint", fp), ("name", "shown")));
        check(createStatus == 201 && Member(created, "operation") == "machine-rename" && Member(created, "sentence")!.Contains("Parameter friendly-name: shown", StringComparison.Ordinal) && Member(created, "state") == "pending" && Member(created, "lifetimeSeconds") == AdminService.LifetimeText, "binding: the authorization carries the exact text to show the person, its state and its lifetime");

        // i. A lock ends every authorization: a page that was waiting before the lock authorizes nothing after it, and the lock discards what was kept.
        Tapped waitingBeforeLock = await b.OpAsyncWithoutMutation("machine-rename", null, ("fingerprint", fp), ("name", "before lock"));
        (Tapped beforeLock, string beforeLockState) = await Authorized("machine-rename", ("fingerprint", fp), ("name", "tapped before lock"));
        app.Service.Lock.Lock("test");
        check(app.Service.Admin.AuthorizationCount == 0, "binding: a lock discards every authorization");
        app.Service.Lock.Unlock(UnlockMethod.Seam);
        AdminBrowser again = await app.SignedIn();
        (HttpMethod am, string ap, string aj) = again.MutationRequest("machine-rename", beforeLock.AuthorizationId, ("fingerprint", fp), ("name", "tapped before lock"));
        (int afterLock, _) = await again.SendAsync(am, ap, aj);
        (int lateTap, _) = TestState.Approve(app.Http, waitingBeforeLock.PageUrl, "http://localhost:" + new Uri(waitingBeforeLock.Link!).Port, "localhost", app.Laptop);
        check(beforeLockState == "consumed" && afterLock == 403 && lateTap != 200 && app.Store.Find(app.Fingerprint)!.FriendlyName == "tapped before lock", "binding: after a lock and an unlock an old authorization is gone (403) and the page that was waiting takes no tap");

        // j. Policy: the unlock mode is one route; the operation follows the body, so a tap for unattended is not a tap for manual.
        AdminBrowser c = await app.SignedIn();
        app.Clock.Advance(TimeSpan.FromSeconds(31));
        Tapped unattended = await c.OpAsyncWithoutMutation("policy-unattended", app.Laptop);
        await c.WaitAuthorizationAsync(unattended.AuthorizationId!);
        (int wrongPolicy, string wrongPolicyBody) = await c.SendAsync(HttpMethod.Put, "/api/v1/settings/unlock-policy", "{\"authorization\":\"" + unattended.AuthorizationId + "\",\"policy\":\"manual\"}");
        check(wrongPolicy == 403 && Code(wrongPolicyBody) == "authorization-mismatch" && app.Store.GetUnlockPolicy() == UnlockPolicy.Unattended, "binding: an authorization for the unattended unlock mode does not set another mode (the tap made the mode it named)");
        Tapped retention = await c.OpAsyncWithoutMutation("set-audit-retention", app.Laptop, ("days", "10"));
        await c.WaitAuthorizationAsync(retention.AuthorizationId!);
        (int wrongDays, string wrongDaysBody) = await c.SendAsync(HttpMethod.Put, "/api/v1/settings/audit-retention", "{\"authorization\":\"" + retention.AuthorizationId + "\",\"days\":0}");
        check(wrongDays == 403 && Code(wrongDaysBody) == "authorization-mismatch" && app.Store.AuditRetentionDays() == 10, "binding: an authorization for 10 days does not set 0 (keep everything)");

        string audit = AuditText(app.Store);
        check(audit.Contains("authorization mismatch", StringComparison.Ordinal) && audit.Contains("authorization invalid", StringComparison.Ordinal), "binding: every refusal (mismatch, invalid) is in the audit history");

        // k. An authorization whose tap never came expires (in its own app: the clock moves far, and a passkey page is only good for the time it was made for).
        using AdminApp slow = new(root, protection: true);
        AdminBrowser sb = await slow.SignedIn();
        await sb.LoadAsync();
        (int untappedStatus, string untapped) = await sb.PostAsync("/api/v1/authorizations", AdminBrowser.AuthorizationBody("machine-rename", ("fingerprint", slow.Fingerprint[..20]), ("name", "untapped")));
        for (int step = 0; step < 3; step++)
        {
            // The session is kept in use (its idle timeout is shorter than the time an untapped authorization may wait: 35 minutes; it is forgotten after 37).
            slow.Clock.Advance(TimeSpan.FromMinutes(12));
            await sb.GetAsync("/api/v1/machines");
        }

        (HttpMethod xm, string xp, string xj) = sb.MutationRequest("machine-rename", Member(untapped, "id"), ("fingerprint", slow.Fingerprint[..20]), ("name", "untapped"));
        (int expired, string expiredBody) = await sb.SendAsync(xm, xp, xj);
        check(untappedStatus == 201 && expired == 403 && Code(expiredBody) == "authorization-expired" && slow.Store.Find(slow.Fingerprint)!.FriendlyName != "untapped" && AuditText(slow.Store).Contains("authorization expired", StringComparison.Ordinal), "binding: an authorization whose tap never came expires (expired), changes nothing and is audited");

    }

    // ---- the machine functions of the old admin verbs ----

    private static async Task MachineFunctions(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root, trusted: false);
        AdminBrowser b = await app.SignedIn();
        AuthorityStore store = app.Store;
        string fp = app.Fingerprint;
        string display = KeyIdentity.Display(fp);
        HostConfigFile hostConfig = app.Machine.Deployment.HostConfig;
        async Task<Tapped> Go(string op, TestAuthenticator? who, params (string, string)[] args)
        {
            app.Clock.Advance(TimeSpan.FromSeconds(13));

            return await b.OpAsync(op, who, true, null, true, args);
        }

        string view = (await b.GetAsync("/api/v1/machines")).Html;
        using (JsonDocument doc = JsonDocument.Parse(view))
        {
            JsonElement machine = doc.RootElement.GetProperty("items")[0];
            string[] actions = [.. machine.GetProperty("actions").EnumerateArray().Select(item => item.GetString()!)];
            check(machine.GetProperty("display").GetString() == display && machine.GetProperty("status").GetString() == "pending" && actions.Contains("approve") && !actions.Contains("trust"), "machines: a Pending machine offers approve, with its fingerprint");
        }

        Tapped wrong = await Go("machine-approve", app.Phone, ("fingerprint", fp[..16]), ("name", "dev laptop"));
        check(wrong.ApproveStatus == 403 && store.Find(fp)!.Status == MachineStatus.Pending && !File.Exists(hostConfig.FilePath), "machine approve: a key that is not an admin key is refused (403); nothing changes and nothing is pinned");
        Tapped approved = await Go("machine-approve", app.Laptop, ("fingerprint", fp[..16]), ("name", "dev laptop"));
        check(approved.MutationStatus == 200 && store.Find(fp) is { Status: MachineStatus.Trusted, FriendlyName: "dev laptop" }, "machine approve: the admin key's tap approves the machine");
        check(approved.Page.Contains(display, StringComparison.Ordinal) && approved.Page.Contains("approve this machine", StringComparison.Ordinal) && approved.Page.Contains("dev laptop", StringComparison.Ordinal), "machine approve: the page (which the passkey signs) shows the action, the full fingerprint and the name");
        check(hostConfig.Load().Config is { Authority: not null } config && config.MachineFingerprint == fp, "machine approve: the authority key is pinned in host.json");
        check(store.Audit().Any(entry => entry.Event == "machine-approve" && entry.Actor == "admin passkey laptop"), "machine approve: the audit history names the admin key that tapped");

        (string Op, string? Name, string Phrase, MachineStatus After)[] steps =
        [
            ("machine-rename", "renamed", "rename this machine", MachineStatus.Trusted),
            ("machine-disable", null, "disable this machine", MachineStatus.Disabled),
            ("machine-enable", null, "enable this machine", MachineStatus.Trusted),
            ("machine-untrust", null, "withdraw trust", MachineStatus.Untrusted),
            ("machine-trust", null, "trust this machine again", MachineStatus.Trusted),
        ];
        foreach ((string op, string? name, string phrase, MachineStatus after) in steps)
        {
            (string, string)[] args = op == "machine-trust" ? [("fingerprint", fp[..20]), ("confirm", fp)] : name is null ? [("fingerprint", fp[..20])] : [("fingerprint", fp[..20]), ("name", name)];
            MachineRecord prior = store.Find(fp)!;
            Tapped denied = await Go(op, app.Phone, args);
            check(denied.ApproveStatus == 403 && store.Find(fp) is { } unchanged && unchanged.Status == prior.Status && unchanged.FriendlyName == prior.FriendlyName && unchanged.SecurityRevision == prior.SecurityRevision, op + ": a non-admin key changes nothing");
            Tapped ok = await Go(op, app.Laptop, args);
            check(ok.MutationStatus == 200 && store.Find(fp)!.Status == after && (name is null || store.Find(fp)!.FriendlyName == name) && ok.Page.Contains(phrase, StringComparison.Ordinal) && ok.Page.Contains(display, StringComparison.Ordinal), op + ": the admin tap applies it, and the page named the action and the full fingerprint");
        }

        check(store.Find(fp)!.FriendlyName == "renamed" && store.Find(fp)!.SecurityRevision == 3, "machine functions: rename kept the revision; disable and untrust raised it to 3");

        // Refused before any page.
        int asked = app.Asked;
        Tapped badState = await Go("machine-enable", null, ("fingerprint", fp[..20]));
        Tapped unknown = await Go("machine-disable", null, ("fingerprint", "00" + fp[2..22]));
        Tapped shortPrefix = await Go("machine-disable", null, ("fingerprint", "AB"));
        Tapped notHex = await Go("machine-disable", null, ("fingerprint", "ZZZZZZZZZZZZ"));
        check(badState.Link is null && badState.PostStatus == 409 && unknown.Link is null && shortPrefix.Link is null && notHex.Link is null && app.Asked == asked, "machine functions: a machine not in the right state, an unknown or malformed fingerprint is refused before any page");
        store.Disable(fp, "test");
        store.Untrust(fp, "test");
        Tapped prefixTrust = await Go("machine-trust", null, ("fingerprint", fp[..20]), ("confirm", fp[..20]));
        Tapped noConfirm = await Go("machine-trust", null, ("fingerprint", fp[..20]));
        check(prefixTrust.Link is null && prefixTrust.PostStatus == 400 && noConfirm.Link is null && app.Asked == asked, "machine trust: a fingerprint prefix (or nothing) is not the confirmation; refused before any page");
        check((await b.GetAsync("/api/v1/machines")).Html.Contains("\"trust\"", StringComparison.Ordinal), "machines: an Untrusted machine offers trust (its full fingerprint is the confirmation)");
        store.Trust(fp, fp, "test");

        Tapped nameless = await Go("machine-rename", null, ("fingerprint", fp[..20]), ("name", ""));
        check(nameless.Link is null && nameless.PostStatus == 400, "machine rename: an empty name is refused before any page");

        Tapped disable = await Go("machine-disable", app.Laptop, ("fingerprint", fp[..20]));
        check(disable.Page.Contains("disable this machine", StringComparison.Ordinal) && !disable.Page.Contains("enable this machine", StringComparison.Ordinal), "machine functions: the page text names exactly the requested action");
        store.Enable(fp, "test");

        // A host name change: the page shows the new name; the tap binds exactly it.
        store.RecordHostMismatch(fp, "other-host");
        string pendingView = (await b.GetAsync("/api/v1/machines/" + fp[..20])).Html;
        check(Member(pendingView, "pendingHostName") == "other-host" && pendingView.Contains("approve-host-change", StringComparison.Ordinal), "machines: a waiting host name change is shown with its action");
        Tapped hostNoUv = await b.OpAsync("machine-host-change", app.Laptop, false, null, true, ("fingerprint", fp[..20]));
        Tapped hostOther = await b.OpAsync("machine-host-change", app.Laptop, true, challenge => SHA256.HashData(challenge), true, ("fingerprint", fp[..20]));
        Tapped hostPhone = await b.OpAsync("machine-host-change", app.Phone, true, null, true, ("fingerprint", fp[..20]));
        check(hostNoUv.ApproveStatus == 403 && hostOther.ApproveStatus is 403 or 400 && hostPhone.ApproveStatus == 403 && store.Find(fp) is { HostName: "test-host" }, "machine host-change: no user verification, another challenge or a non-admin key each change nothing");
        Tapped host = await Go("machine-host-change", app.Laptop, ("fingerprint", fp[..20]));
        check(host.MutationStatus == 200 && store.Find(fp) is { HostName: "other-host", PendingHostName: null } && host.Page.Contains("other-host", StringComparison.Ordinal), "machine host-change: the page shows the new name; the tap binds it");

        // A state that changed after the tap: the stale authorization changes nothing.
        // The service applies the change when the tap is verified, so the state that changes is one that changed between the authorization and the tap.
        Tapped staleTapped = await b.OpAsyncWithoutMutation("machine-disable", null, ("fingerprint", fp[..20]));
        store.Disable(fp, "someone else");
        int revision = store.Find(fp)!.SecurityRevision;
        TestState.Approve(app.Http, staleTapped.PageUrl, "http://localhost:" + new Uri(staleTapped.Link!).Port, "localhost", app.Laptop);
        string staleState = await b.WaitAuthorizationAsync(staleTapped.AuthorizationId!);
        (_, string staleView) = await b.SendAsync(HttpMethod.Get, "/api/v1/authorizations/" + staleTapped.AuthorizationId, null);
        (HttpMethod sm, string sp, string sj) = b.MutationRequest("machine-disable", staleTapped.AuthorizationId, ("fingerprint", fp[..20]));
        (int staleStatus, string staleBody) = await b.SendAsync(sm, sp, sj);
        check(store.Find(fp) is { Status: MachineStatus.Disabled } stillDisabled && stillDisabled.SecurityRevision == revision && staleState == "consumed" && staleView.Contains("\"outcome\":\"failed\"", StringComparison.Ordinal) && staleStatus == 409 && Code(staleBody) == "operation-failed", "machine functions: a machine that changed between the authorization and the tap is not changed again by the tap (failed, 409)");
        store.Enable(fp, "test");

        // A different host name arriving after the tap is not applied.
        store.RecordHostMismatch(fp, "shown-name");
        Tapped race = await b.OpAsyncWithoutMutation("machine-host-change", null, ("fingerprint", fp[..20]));
        store.RecordHostMismatch(fp, "other-name");
        TestState.Approve(app.Http, race.PageUrl, "http://localhost:" + new Uri(race.Link!).Port, "localhost", app.Laptop);
        await b.WaitAuthorizationAsync(race.AuthorizationId!);
        (HttpMethod rm, string rp, string rj) = b.MutationRequest("machine-host-change", race.AuthorizationId, ("fingerprint", fp[..20]));
        (int raceStatus, _) = await b.SendAsync(rm, rp, rj);
        check(store.Find(fp) is { HostName: "other-host" } && raceStatus == 409, "machine host-change: a host name that replaced the shown one is not applied by the tap (" + store.Find(fp)!.HostName + ")");

        // Re-pin on an already Trusted machine says so on the page and keeps its name.
        Tapped repin = await Go("machine-approve", app.Laptop, ("fingerprint", fp), ("name", "ignored name"));
        check(repin.MutationStatus == 200 && repin.Page.Contains("re-pin the authority key", StringComparison.Ordinal) && repin.Page.Contains("already Trusted", StringComparison.Ordinal) && store.Find(fp)!.FriendlyName == "renamed", "machine approve: on a Trusted machine the page says it re-pins the key and the name is not changed");
    }

    // ---- settings, passkeys ----

    private static async Task SettingsAndPasskeys(Action<bool, string> check, string root)
    {
        FakePasskeys fake = new();
        using AdminApp app = new(root, passkeys: fake);
        AdminBrowser b = await app.SignedIn();
        Tapped retention = await b.OpAsync("set-audit-retention", app.Laptop, true, null, true, ("days", "30"));
        check(retention.MutationStatus == 200 && app.Store.AuditRetentionDays() == 30 && retention.Page.Contains("30 days", StringComparison.Ordinal), "settings: the retention changes after its own tap; the page names the number of days");
        check(Member((await b.GetAsync("/api/v1/settings")).Html, "auditRetentionDays") == "30", "settings: the API shows the new retention");
        Tapped bad = await b.OpAsync("set-audit-retention", app.Laptop, true, null, true, ("days", "-1"));
        Tapped huge = await b.OpAsync("set-audit-retention", app.Laptop, true, null, true, ("days", "999999"));
        Tapped lateIdle = await b.OpAsync("set-session-timeouts", app.Laptop, true, null, true, ("idle", "50"), ("absolute", "10"));
        check(bad.Link is null && huge.Link is null && lateIdle.Link is null && app.Store.AuditRetentionDays() == 30 && app.Store.SessionTimeouts() == (15, 480), "settings: out of range values (and an idle timeout longer than the absolute one) are refused before any page");
        Tapped manual = await b.OpAsync("policy-manual", null);
        check(manual.Link is null && manual.PostStatus == 409, "settings: making unlock manual when it is manual already is refused before any page");

        // Passkey administration: its own pages (the existing enrollment ceremony) are the taps after the authorization; the API only starts them, for a session.
        string passkeys = (await b.GetAsync("/api/v1/passkeys")).Html;
        check(Member(passkeys, "available") == "true", "passkeys: the list is available");
        Tapped enroll = await b.OpAsync("passkey-enroll", app.Laptop);
        check(enroll.MutationStatus == 202 && Member(enroll.MutationBody, "outcome") == "started" && Member(enroll.MutationBody, "link") is { Length: > 8 } && await HostServiceTests.WaitFor(() => fake.Calls.Contains("enroll")), "passkeys: adding one needs its authorization, then starts the enrollment pages (their own taps)");
        Tapped remove = await b.OpAsync("passkey-unenroll", app.Laptop, true, null, true, ("name", "phone"));
        check(remove.MutationStatus == 202 && await HostServiceTests.WaitFor(() => fake.Calls.Contains("unenroll phone")), "passkeys: removing one needs its authorization, then starts the removal pages (their own taps)");
        int calls = fake.Calls.Count;
        Tapped untapped = await b.OpAsync("passkey-enroll", null);
        (HttpMethod um, string up, string uj) = b.MutationRequest("passkey-enroll", untapped.AuthorizationId);
        (int untappedStatus, _) = await b.SendAsync(um, up, uj);
        check(untappedStatus == 403 && fake.Calls.Count == calls, "passkeys: without the authorization's tap the enrollment pages are not started");
        Tapped noName = await b.OpAsync("passkey-unenroll", null, true, null, true, ("name", ""));
        check(noName.Link is null && !fake.Calls.Contains("unenroll "), "passkeys: a removal with no name is refused before any page");
        AdminBrowser anon = app.Browser();
        await anon.LoadAsync();
        calls = fake.Calls.Count;
        (int s1, _) = await anon.PostAsync("/api/v1/passkeys", "{\"authorization\":\"AAAAAAAAAAAA\"}");
        (int s2, _) = await anon.PostAsync("/api/v1/passkeys/phone/remove", "{\"authorization\":\"AAAAAAAAAAAA\"}");
        check(s1 == 401 && s2 == 401 && fake.Calls.Count == calls, "passkeys: with no session neither adding nor removing a passkey is started");
        check(app.Store.Audit(1000).Any(entry => entry.Event == "admin-operation" && entry.Detail.StartsWith("enroll-passkey; requested", StringComparison.Ordinal)), "passkeys: the attempt is audited");
    }

    // ---- one page at a time, a limit, lock always proceeds ----

    private static async Task Pending(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root, askSeconds: 20);
        AdminBrowser b = await app.SignedIn();
        string fp = app.Fingerprint[..20];

        // A new request replaces the page the last one was waiting on: its page is closed, and it cannot be tapped.
        Tapped one = await b.OpAsync("machine-rename", null, true, null, true, ("fingerprint", fp), ("name", "one"));
        Tapped two = await b.OpAsync("machine-rename", null, true, null, true, ("fingerprint", fp), ("name", "two"));
        (int closed, _) = TestState.Approve(app.Http, one.PageUrl, "http://localhost:" + new Uri(one.Link!).Port, "localhost", app.Laptop);
        await Task.Delay(300);
        check(two.Link is not null && closed != 200 && app.Store.Find(app.Fingerprint)!.FriendlyName != "one", "pending: a newer request closes the page of the older one; a tap on the old page changes nothing");
        (int okStatus, _) = TestState.Approve(app.Http, two.PageUrl, "http://localhost:" + new Uri(two.Link!).Port, "localhost", app.Laptop);
        check(okStatus == 200 && await b.WaitAuthorizationAsync(two.AuthorizationId!) == "consumed", "pending: the newest page still works (its tap made the change)");
        (HttpMethod m2, string p2, string j2) = b.MutationRequest("machine-rename", two.AuthorizationId, ("fingerprint", fp), ("name", "two"));
        check((await b.SendAsync(m2, p2, j2)).Status == 200 && app.Store.Find(app.Fingerprint)!.FriendlyName == "two", "pending: and its mutation applies it");

        // A flood of starts is limited, and the limit does not stop a lock.
        int refused = 0;
        for (int i = 0; i < 40; i++)
        {
            (int status, _) = await b.PostAsync("/api/v1/authorizations", AdminBrowser.AuthorizationBody("machine-rename", ("fingerprint", fp), ("name", "n" + i)));
            refused += status == 429 ? 1 : 0;
        }

        check(refused >= 8, "pending: more than 30 starts a minute from the session are refused (429); " + refused + " were");
        int audits = app.Store.Audit(1000).Count(entry => entry.Event == "admin-operation" && entry.Detail.Contains("too many requests", StringComparison.Ordinal));
        check(audits <= 20, "pending: the refusal rows are capped so the audit history cannot be flooded (" + audits + ")");

        // Lock cancels the pending page, and a flood does not hold it out.
        AdminBrowser publicCaller = app.Browser();
        await publicCaller.LoadAsync();
        app.Clock.Advance(TimeSpan.FromMinutes(2));
        Tapped pendingRename = await b.OpAsync("machine-rename", null, true, null, true, ("fingerprint", fp), ("name", "will not happen"));
        Tapped lockPage = await b.OpAsync(AdminService.OpLock, null);
        check(lockPage.Link is not null, "pending: the lock page is made even while another page is waiting");
        (int lockStatus, _) = TestState.Approve(app.Http, lockPage.PageUrl, "http://localhost:" + new Uri(lockPage.Link!).Port, "localhost", app.Laptop);
        check(lockStatus == 200 && await HostServiceTests.WaitFor(() => app.Service.Lock.IsLocked), "pending: the lock still goes through (its tap locks the authority)");
        (int pendingStatus, _) = TestState.Approve(app.Http, pendingRename.PageUrl, "http://localhost:" + new Uri(pendingRename.Link!).Port, "localhost", app.Laptop);
        check(pendingStatus != 200 && app.Store.Find(app.Fingerprint)!.FriendlyName != "will not happen", "pending: the page that was waiting when the lock came was closed by it, and its tap changes nothing");

        // M1: locking while a passkey page waits closes it; the tap that comes after changes nothing.
        using AdminApp second = new(root, askSeconds: 20);
        AdminBrowser s = await second.SignedIn();
        Tapped waiting = await s.OpAsync("machine-rename", null, true, null, true, ("fingerprint", second.Fingerprint[..20]), ("name", "late"));
        second.Service.Lock.Lock("test");
        await Task.Delay(500);
        (int lateStatus, _) = TestState.Approve(second.Http, waiting.PageUrl, "http://localhost:" + new Uri(waiting.Link!).Port, "localhost", second.Laptop);
        await Task.Delay(300);
        check(lateStatus != 200 && second.Store.Find(second.Fingerprint)!.FriendlyName != "late", "lock: a passkey page that was waiting when the authority locked is closed; a later tap changes nothing");
    }

    // ---- the locked state ----

    private static async Task LockedState(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root, unlocked: false);
        AdminBrowser b = app.Browser();
        string status = (await b.GetAsync("/api/v1/status")).Html;
        check(Member(status, "locked") == "true" && Member(status, "running") == "true", "locked: the public status says so");
        foreach (ApiRoute route in app.Service.Admin.Api.Routes.Where(item => item.Access == ApiAccess.Read))
        {
            check((await b.GetAsync(Fill(route))).Status == 401, "locked: " + route.Template + " needs a session, and none can exist");
        }

        await b.LoadAsync();
        (int loginStatus, string loginBody) = await b.PostAsync("/api/v1/session", "{}");
        check(loginStatus == 423 && Code(loginBody) == "authority-locked" && app.Asked == 0, "locked: a sign-in is refused (423) and asks for no passkey");
        (int lockStatus, _) = await b.PostAsync("/api/v1/lock", "{\"authorization\":\"AAAAAAAAAAAA\"}");
        (int policyStatus, _) = await b.PostAsync("/api/v1/authorizations", AdminBrowser.AuthorizationBody("policy-unattended"));
        check(lockStatus == 403 && policyStatus == 401 && app.Asked == 0, "locked: nothing but the unlock (and a lock, which needs its own authorization) can be asked for without a session");
        Tapped bad = await b.OpAsync(AdminService.OpUnlock, app.Phone);
        check(bad.ApproveStatus == 403 && app.Service.Lock.IsLocked, "locked: a non-admin key cannot unlock");
        Tapped unlock = await b.OpAsync(AdminService.OpUnlock, app.Laptop);
        check(unlock.MutationStatus == 200 && !app.Service.Lock.IsLocked && Member((await b.GetAsync("/api/v1/status")).Html, "locked") == "false", "locked: an admin key's own authorization unlocks, and the status follows");
        (int replay, string replayBody) = await b.SendAsync(HttpMethod.Post, "/api/v1/unlock", "{\"authorization\":\"" + unlock.AuthorizationId + "\"}");
        check(replay == 200 && replayBody.Contains("\"already-applied\"", StringComparison.Ordinal) && !app.Service.Lock.IsLocked, "locked: the unlock authorization is answered as already applied and unlocks nothing twice");
    }

    // ---- versions and the fallback ----

    private static async Task VersionsAndFallback(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root, web: new AdminWebAssets([]));
        AdminBrowser b = app.Browser();
        foreach (string path in new[] { "/api/v2/status", "/api/v0/status", "/api/v10/machines", "/api/V1/status", "/api/v2/", "/api/v2" })
        {
            (int status, string body, HttpResponseMessage response) = await b.GetAsync(path);
            using JsonDocument doc = JsonDocument.Parse(body);
            check(status == 400 && Code(body) == "unsupported-api-version" && ContentType(response) == "application/problem+json" && doc.RootElement.GetProperty("supportedVersions")[0].GetString() == "v1", "version: " + path + " is the documented unsupported-version error (400, supportedVersions v1)");
        }

        foreach (string path in new[] { "/api", "/api/", "/api/v1", "/api/v1/", "/api/v1/nope", "/api/v1/machines/", "/api/v1/status/extra", "/api/nonsense" })
        {
            (int status, string body, HttpResponseMessage response) = await b.GetAsync(path);
            check(status == 404 && ContentType(response) == "application/problem+json" && Code(body) == "route-not-found", "fallback: " + path + " is a JSON 404 (route-not-found), never a page (" + status + " " + ContentType(response) + ")");
        }

        foreach (string path in new[] { "/admin", "/admin/", "/admin/machines", "/admin/anything/else" })
        {
            (int status, string body, HttpResponseMessage response) = await b.GetAsync(path);
            check(status == 404 && ContentType(response) == "application/problem+json" && Code(body) == "web-application-not-built" && !body.Contains("<", StringComparison.Ordinal), "fallback: " + path + " is a JSON 404 while the web application is not built in (no HTML)");
        }

        using (HttpRequestMessage html = new(HttpMethod.Get, b.Base + "/api/v1/nope"))
        {
            html.Headers.Add("Accept", "text/html");
            using HttpResponseMessage answer = await app.Http.SendAsync(html);
            check(ContentType(answer) == "application/problem+json", "fallback: a browser's Accept: text/html still gets JSON under /api");
        }

        (int wrongMethod, string wrongBody, HttpResponseMessage wrongResponse) = await b.GetAsync("/api/v1/lock");
        check(wrongMethod == 405 && Code(wrongBody) == "method-not-allowed" && wrongResponse.Content.Headers.Allow.Contains("POST"), "fallback: a known path with the wrong method is 405 with the allowed methods");
        (int del, _) = await b.SendAsync(HttpMethod.Delete, "/api/v1/status", null);
        (int patch, _) = await b.SendAsync(HttpMethod.Patch, "/api/v1/machines", "{}");
        check(del == 405 && patch == 405, "fallback: DELETE and PATCH where the API has none are 405");
        check(app.Service.Admin.Api.Routes.All(route => route.Template.StartsWith("/api/v1/", StringComparison.Ordinal)), "versions: every route is under /api/v1/");
    }

    // ---- the administration web application (single-page application) ----

    private static async Task WebApplication(Action<bool, string> check, string root)
    {
        const string index = "<!doctype html><html><head><title>t</title><script type=\"module\" src=\"/admin/assets/app.js\"></script></head><body><div id=\"root\"></div></body></html>";
        static KeyValuePair<string, byte[]> File(string name, string content) => new(name, Encoding.UTF8.GetBytes(content));
        AdminWebAssets assets = new([File("index.html", index), File("assets/app.js", "console.log(1)"), File("assets/app.css", "body{margin:0}"), File("version.json", "{\"version\":\"9.9.9\"}")]);
        using AdminApp app = new(root, web: assets);
        AdminBrowser b = app.Browser();

        // Every application route is the one page; the router of the page reads the address.
        foreach (string path in new[] { "/admin", "/admin/", "/admin/machines", "/admin/grants", "/admin/audit/changes", "/admin/deep/er/route" })
        {
            (int status, string body, HttpResponseMessage response) = await b.GetAsync(path);
            string csp = response.Headers.TryGetValues("Content-Security-Policy", out IEnumerable<string>? values) ? string.Join(";", values) : "";
            check(status == 200 && (response.Content.Headers.ContentType?.MediaType ?? "") == "text/html" && body == index, "spa: " + path + " is the page (200 text/html)");
            check(csp == AdminWebAssets.ContentSecurityPolicy && csp.Contains("script-src 'self'", StringComparison.Ordinal) && csp.Contains("frame-ancestors 'none'", StringComparison.Ordinal)
                && !csp.Contains("unsafe-inline", StringComparison.Ordinal) && !csp.Contains("unsafe-eval", StringComparison.Ordinal) && !csp.Contains("http:", StringComparison.Ordinal) && !csp.Contains("https:", StringComparison.Ordinal) && !csp.Contains('*', StringComparison.Ordinal)
                && response.Headers.Contains("X-Frame-Options") && response.Headers.GetValues("Referrer-Policy").Single() == "no-referrer" && response.Headers.GetValues("X-Content-Type-Options").Single() == "nosniff" && response.Headers.CacheControl?.NoStore == true,
                "spa: " + path + " carries a strict policy (same origin only, no inline script or style, no frames), no-store, nosniff and no referrer");
        }

        // A file is answered only if it exists; a missing file is never answered with the page.
        (int js, string jsBody, HttpResponseMessage jsResponse) = await b.GetAsync("/admin/assets/app.js");
        (int css, _, HttpResponseMessage cssResponse) = await b.GetAsync("/admin/assets/app.css");
        (int version, string versionBody, _) = await b.GetAsync("/admin/version.json");
        check(js == 200 && jsBody == "console.log(1)" && jsResponse.Content.Headers.ContentType?.MediaType == "text/javascript" && css == 200 && cssResponse.Content.Headers.ContentType?.MediaType == "text/css" && version == 200 && versionBody.Contains("9.9.9", StringComparison.Ordinal),
            "spa: the files are served with their types");
        foreach (string path in new[] { "/admin/assets/nope.js", "/admin/nope.png", "/admin/assets/app.js.map", "/admin/assets/%2e%2e/%2e%2e/api/v1/status", "/admin/..%2fapi/v1/status.json", "/admin/assets/..%5c..%5cindex.html" })
        {
            (int status, string body, _) = await b.GetAsync(path);
            check(status != 200 || (!body.Contains("<div id", StringComparison.Ordinal) && !body.Contains("openapi", StringComparison.Ordinal)), "spa: " + path + " is not the page and leaks nothing (" + status + ")");
        }

        (int missing, string missingBody, _) = await b.GetAsync("/admin/assets/nope.js");
        check(missing == 404 && missingBody.Length == 0, "spa: a missing file is a 404 with no body (never the page)");

        // The API never falls through to the page.
        (int api404, string api404Body, HttpResponseMessage api404Response) = await b.GetAsync("/api/v1/does-not-exist");
        check(api404 == 404 && ContentType(api404Response) == "application/problem+json" && !api404Body.Contains("<div", StringComparison.Ordinal), "spa: an unknown /api path is a JSON 404, never the page");
        (int sibling, _, HttpResponseMessage siblingResponse) = await b.GetAsync("/administrator");
        check(!(sibling == 200 && siblingResponse.Content.Headers.ContentType?.MediaType == "text/html"), "spa: /administrator is not an application route (only /admin and below)");

        // Methods, HEAD, Host.
        using (HttpRequestMessage post = new(HttpMethod.Post, b.Base + "/admin/machines") { Content = new StringContent("{}", Encoding.UTF8, "application/json") })
        {
            using HttpResponseMessage answer = await app.Http.SendAsync(post);
            check((int)answer.StatusCode == 405 && answer.Content.Headers.Allow.Contains("GET") && answer.Content.Headers.Allow.Contains("HEAD"), "spa: POST to the page is 405 (GET and HEAD only)");
        }

        using (HttpRequestMessage head = new(HttpMethod.Head, b.Base + "/admin/machines"))
        {
            using HttpResponseMessage answer = await app.Http.SendAsync(head);
            check(answer.IsSuccessStatusCode && answer.Content.Headers.ContentLength == index.Length && (await answer.Content.ReadAsStringAsync()).Length == 0, "spa: HEAD answers the headers and no body");
        }

        (int rebound, _, _) = await b.GetAsync("/admin", host: "evil.example");
        check(rebound == 421, "spa: a request with a Host that is not a loopback name is refused (DNS rebinding) before the page");
        check(app.Service.Admin.Api.Routes.All(route => !route.Template.StartsWith("/admin", StringComparison.Ordinal)), "spa: no API route lives under /admin");

        // The files embedded in this assembly (the build puts the frontend's output there).
        AdminWebAssets real = AdminWebAssets.FromAssembly();
        if (!real.Available)
        {
            check(false, "embedded: this assembly was built without the frontend, so no application is embedded; the check cannot pass (build with Node.js 22 or newer)");

            return;
        }

        using AdminApp embedded = new(root);
        AdminBrowser e = embedded.Browser();
        (int status200, string page, HttpResponseMessage pageResponse) = await e.GetAsync("/admin/machines");
        check(status200 == 200 && pageResponse.Content.Headers.ContentType?.MediaType == "text/html" && page.Contains("<div id=\"root\">", StringComparison.Ordinal), "embedded: the service serves the built page from the assembly");
        check(!System.Text.RegularExpressions.Regex.IsMatch(page, @"<script(?![^>]*\bsrc=)", System.Text.RegularExpressions.RegexOptions.IgnoreCase) && !page.Contains(" style=", StringComparison.OrdinalIgnoreCase) && !page.Contains("<style", StringComparison.OrdinalIgnoreCase)
            && !System.Text.RegularExpressions.Regex.IsMatch(page, @"\son[a-z]+=", System.Text.RegularExpressions.RegexOptions.IgnoreCase) && !page.Contains("http://", StringComparison.OrdinalIgnoreCase) && !page.Contains("https://", StringComparison.OrdinalIgnoreCase),
            "embedded: the page has no inline script, style or handler and names no external address");
        List<string> referenced = [.. System.Text.RegularExpressions.Regex.Matches(page, "(?:src|href)=\"(/admin/[^\"]+)\"").Select(match => match.Groups[1].Value)];
        bool allThere = referenced.Count >= 2;
        foreach (string path in referenced)
        {
            (int fileStatus, string fileBody, _) = await e.GetAsync(path);
            allThere &= fileStatus == 200 && fileBody.Length > 0;
            if (path.EndsWith(".css", StringComparison.Ordinal))
            {
                allThere &= !fileBody.Contains("@import", StringComparison.Ordinal) && !System.Text.RegularExpressions.Regex.IsMatch(fileBody, @"url\(\s*['""]?(https?:)?//", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            }
        }

        check(allThere, "embedded: the script and stylesheet the page names are embedded, and the stylesheet loads nothing from elsewhere (" + referenced.Count + " files)");
        (_, string embeddedVersion, _) = await e.GetAsync("/admin/version.json");
        check(real.FrontendVersion == AdminService.Version && embeddedVersion.Contains(AdminService.Version, StringComparison.Ordinal), "embedded: the frontend was built with the backend's version (" + AdminService.Version + ")");
        (_, string statusBody, _) = await e.GetAsync("/api/v1/status");
        check(statusBody.Contains("\"version\":\"" + AdminService.Version + "\"", StringComparison.Ordinal), "embedded: /api/v1/status reports the same version as the embedded frontend");
    }

    // ---- the OpenAPI document ----

    private static string RepoFile(params string[] parts)
    {
        string? dir = AppContext.BaseDirectory;
        while (dir is not null && !File.Exists(Path.Combine(dir, "with-secrets.slnx")))
        {
            dir = Path.GetDirectoryName(dir);
        }

        return Path.Combine([dir ?? ".", .. parts]);
    }

    private static async Task OpenApiDocument(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root);
        AdminBrowser b = app.Browser();
        (int status, string body, HttpResponseMessage response) = await b.GetAsync("/api/v1/openapi.json");
        check(status == 200 && ContentType(response) == "application/json" && response.Headers.GetValues("X-Api-Version").Single() == "1", "openapi: the document is public JSON with the version header");
        JsonNode? parsed = JsonNode.Parse(body);
        JsonObject doc = parsed!.AsObject();
        JsonObject paths = doc["paths"]!.AsObject();
        check(doc["openapi"]!.GetValue<string>() == "3.1.0" && doc["info"]!["version"] is not null && doc["components"]!["schemas"]!["Problem"] is not null && doc["x-versioning"]!["unsupportedVersionProblem"]!.GetValue<string>() == "unsupported-api-version", "openapi: version 3.1, the info, the problem schema and the unsupported-version error are documented");

        // The routes and the document agree, both ways.
        HashSet<string> routes = [.. app.Service.Admin.Api.Routes.Select(route => route.Method.ToLowerInvariant() + " " + route.Template)];
        HashSet<string> documented = [.. paths.SelectMany(path => path.Value!.AsObject().Select(method => method.Key + " " + path.Key))];
        check(routes.SetEquals(documented) && routes.Count >= 30, "openapi: every route is documented and every documented operation is a route (" + routes.Count + ")");
        check(app.Service.Admin.Api.Routes.Select(route => route.OperationId).Distinct().Count() == routes.Count, "openapi: every operation has its own operationId");

        // And the service serves every documented operation (none answers "no such route").
        foreach (ApiRoute route in app.Service.Admin.Api.Routes)
        {
            (int probe, string probeBody) = await b.SendAsync(new HttpMethod(route.Method), Fill(route), route.Request is null ? null : "{}", token: null);
            check(Code(probeBody) is not ("route-not-found" or "method-not-allowed" or "web-application-not-built") && probe != 404 || Code(probeBody) == "not-found", "openapi: " + route.Method + " " + route.Template + " is served by the service");
        }

        // Every operation says how it is secured and what it answers.
        bool described = true;
        foreach ((string path, JsonNode? item) in paths)
        {
            foreach ((string method, JsonNode? operation) in item!.AsObject())
            {
                bool problems = operation!["responses"]!.AsObject().Where(pair => pair.Key.StartsWith('4') || pair.Key.StartsWith('5')).All(pair => pair.Value!["content"]!["application/problem+json"]!["schema"]!["$ref"]!.GetValue<string>().EndsWith("/Problem", StringComparison.Ordinal));
                described &= operation["operationId"] is not null && operation["x-access"] is not null && operation["summary"] is not null && problems && operation["responses"]!.AsObject().Any(pair => pair.Key.StartsWith('2'));
                if (method != "get")
                {
                    described &= operation["requestBody"] is not null || method == "delete";
                }
            }
        }

        check(described, "openapi: every operation has an id, a summary, its access rule, a success answer and problem-document errors, and every change has a request body");
        JsonObject schemas = doc["components"]!["schemas"]!.AsObject();
        bool referencesResolve = body.Split("#/components/schemas/").Skip(1).Select(part => part[..part.IndexOf('"', StringComparison.Ordinal)]).All(name => schemas[name] is not null);
        check(referencesResolve, "openapi: every $ref names a schema that exists");
        check(!body.Contains("Canary", StringComparison.Ordinal) && !body.Contains(app.Fingerprint, StringComparison.Ordinal) && !body.Contains(app.Machine.HostName, StringComparison.Ordinal), "openapi: the document holds no secret, no machine and no value of this installation");

        // The checked-in copy (the input of the generated TypeScript client) is the generated document.
        string file = RepoFile("docs", "api", "openapi.json");
        string generated = doc.ToJsonString(new JsonSerializerOptions { WriteIndented = true }).Replace("\r\n", "\n", StringComparison.Ordinal) + "\n";
        if (Environment.GetEnvironmentVariable("WS_UPDATE_OPENAPI") == "1")
        {
            Directory.CreateDirectory(Path.GetDirectoryName(file)!);
            File.WriteAllText(file, generated);
        }

        check(File.Exists(file) && File.ReadAllText(file).Replace("\r\n", "\n", StringComparison.Ordinal) == generated, "openapi: docs/api/openapi.json is the generated document (run the tests with WS_UPDATE_OPENAPI=1 to refresh it after a change to the API)");

        // The answers have the shapes the document promises.
        AdminBrowser s = await app.SignedIn();
        JsonObject components = schemas;
        string? Conform(string schema, string answer)
        {
            using JsonDocument value = JsonDocument.Parse(answer);

            return ApiValidator.Validate(value.RootElement, S.Ref(schema), components, schema);
        }

        (string Path, string Schema)[] shapes =
        [
            ("/api/v1/status", "Status"), ("/api/v1/session", "Session"), ("/api/v1/machines", "MachineList"), ("/api/v1/machines/" + app.Fingerprint[..20], "Machine"), ("/api/v1/grants", "GrantList"), ("/api/v1/audit/events", "AuditEventList"),
            ("/api/v1/audit/changes", "AuditChangeList"), ("/api/v1/audit/gaps", "AuditGapList"), ("/api/v1/settings", "Settings"), ("/api/v1/passkeys", "Passkeys"),
        ];
        foreach ((string path, string schema) in shapes)
        {
            (int shapeStatus, string answer, _) = await s.GetAsync(path);
            check(shapeStatus == 200 && Conform(schema, answer) is null, "openapi: the answer of " + path + " conforms to " + schema + " (" + Conform(schema, answer) + ")");
        }

        (int createStatus, string createBody) = await s.PostAsync("/api/v1/authorizations", AdminBrowser.AuthorizationBody("machine-rename", ("fingerprint", app.Fingerprint[..20]), ("name", "shape")));
        check(createStatus == 201 && Conform("Authorization", createBody) is null, "openapi: the answer of POST /authorizations conforms to Authorization (" + Conform("Authorization", createBody) + ")");
        Tapped done = await s.OpAsync("machine-rename", app.Laptop, true, null, true, ("fingerprint", app.Fingerprint[..20]), ("name", "shape"));
        check(done.MutationStatus == 200 && Conform("MutationResponse", done.MutationBody) is null, "openapi: the answer of a mutation conforms to MutationResponse");
        (_, string problem, _) = await s.GetAsync("/api/v1/machines/" + new string('0', 20));
        check(Conform("Problem", problem) is null, "openapi: a problem document conforms to Problem");

        // Requests are checked against the same schemas: each change refuses a body that does not fit.
        foreach (ApiRoute route in app.Service.Admin.Api.Routes.Where(item => item.Access == ApiAccess.Mutation))
        {
            (int unfit, string unfitBody) = await s.SendAsync(new HttpMethod(route.Method), Fill(route), "{\"authorization\":\"AAAAAAAAAAAA\",\"unexpected-member\":true}");
            check(unfit == 400 && Code(unfitBody) == "invalid-request", "openapi: " + route.Method + " " + route.Template + " refuses a body with a member its schema does not have");
        }
    }

    // ---- problem documents, secrets and logs ----

    private sealed class Capture : Serilog.Core.ILogEventSink
    {
        public System.Collections.Concurrent.ConcurrentQueue<Serilog.Events.LogEvent> Events { get; } = new();

        public void Emit(Serilog.Events.LogEvent logEvent) => Events.Enqueue(logEvent);

        public string Everything() => string.Join("\n", Events.Select(item => AppLog.Render(item) + "\n" + string.Join("\n", item.Properties.Select(pair => pair.Key + "=" + pair.Value))));
    }

    private static async Task ProblemsAndCanaries(Action<bool, string> check, string root)
    {
        string logFolder = Path.Combine(root, "logs");
        Directory.CreateDirectory(logFolder);
        Capture capture = new();
        TextWriter? previousOutput = TerminalPrompt.Output;
        StringWriter terminal = new();
        TerminalPrompt.Output = terminal;
        AppLog.LogFolder = logFolder;
        AppLog.Tap = capture;
        AppLog.Configure(true);
        List<string> everything = [];
        try
        {
            using AdminApp app = new(root, passkeys: new FakePasskeys());
            AdminBrowser b = await app.SignedIn();
            const string bodyCanary = "BODY-CANARY-77123";
            const string memberCanary = "MEMBER-CANARY-55871";

            // Problem documents have one shape, say little, and never echo the request.
            (string Label, Func<Task<(int Status, string Body)>> Send)[] bad =
            [
                ("unknown member", () => b.PostAsync("/api/v1/machines/" + app.Fingerprint[..20] + "/disable", "{\"authorization\":\"AAAAAAAAAAAA\",\"" + memberCanary + "\":\"" + bodyCanary + "\"}")),
                ("wrong type", () => b.PostAsync("/api/v1/machines/" + app.Fingerprint[..20] + "/disable", "{\"authorization\":[\"" + bodyCanary + "\"]}")),
                ("not JSON", () => b.PostAsync("/api/v1/machines/" + app.Fingerprint[..20] + "/disable", "<" + bodyCanary + ">")),
                ("too long", () => b.PostAsync("/api/v1/authorizations", "{\"operation\":\"machine-rename\",\"parameters\":{\"name\":\"" + new string('x', 60) + bodyCanary + "\"}}")),
                ("unknown operation", () => b.PostAsync("/api/v1/authorizations", "{\"operation\":\"" + bodyCanary + "\"}")),
                ("unknown parameter", () => b.PostAsync("/api/v1/authorizations", "{\"operation\":\"lock\",\"parameters\":{\"" + memberCanary + "\":\"" + bodyCanary + "\"}}")),
                ("unknown query", () => b.SendAsync(HttpMethod.Get, "/api/v1/audit/events?" + memberCanary + "=" + bodyCanary, null)),
                ("bad time", () => b.SendAsync(HttpMethod.Get, "/api/v1/audit/events?since=" + bodyCanary, null)),
                ("bad path", () => b.SendAsync(HttpMethod.Get, "/api/v1/machines/" + bodyCanary, null)),
            ];
            foreach ((string label, Func<Task<(int Status, string Body)>> send) in bad)
            {
                (int status, string body) = await send();
                using JsonDocument doc = JsonDocument.Parse(body);
                JsonElement root1 = doc.RootElement;
                string[] names = [.. root1.EnumerateObject().Select(item => item.Name)];
                check(status is >= 400 and < 500 && names.Order().SequenceEqual(new[] { "code", "detail", "status", "title", "type" }) && root1.GetProperty("status").GetInt32() == status && root1.GetProperty("type").GetString()!.StartsWith("urn:with-secrets:problem:", StringComparison.Ordinal)
                    && root1.GetProperty("type").GetString() == "urn:with-secrets:problem:" + root1.GetProperty("code").GetString(), "problem (" + label + "): RFC 9457 members only (type, title, status, detail, code) and the status matches (" + status + ")");
                check(!body.Contains(bodyCanary, StringComparison.Ordinal) && !body.Contains(memberCanary, StringComparison.Ordinal) && !body.Contains("   at ", StringComparison.Ordinal) && !body.Contains("Exception", StringComparison.Ordinal) && !body.Contains(root, StringComparison.OrdinalIgnoreCase), "problem (" + label + "): the answer echoes none of the request and carries no stack, exception type or path");
            }

            // Use every read and one full change, and look for what must never appear: a secret value, a proof, the session token, a key.
            foreach (ApiRoute route in app.Service.Admin.Api.Routes.Where(item => item.Access is ApiAccess.Read or ApiAccess.Public && !item.Template.Contains('{', StringComparison.Ordinal)))
            {
                await b.GetAsync(route.Template);
            }

            Tapped renamed = await b.OpAsync("machine-rename", app.Laptop, true, null, true, ("fingerprint", app.Fingerprint[..20]), ("name", "canary rename"));
            Tapped secretLook = await b.OpAsync("machine-disable", app.Laptop, true, null, true, ("fingerprint", app.Fingerprint[..20]));
            check(renamed.MutationStatus == 200 && secretLook.MutationStatus == 200, "canary: the changes ran");
            everything.AddRange(b.Seen);
            string token = b.Cookies.GetValueOrDefault(AdminSessions.SessionCookie, "");
            string sessionToken = token;
            string all = string.Join("\n", everything);
            string proof = renamed.ProofBody;
            check(!all.Contains("Canary-Value-48151623", StringComparison.Ordinal) && !all.Contains("Canary-Other-9001337", StringComparison.Ordinal), "canary: no secret value is in any answer");
            check(proof.Length > 40 && !all.Contains(proof[..Math.Min(60, proof.Length)], StringComparison.Ordinal) && !all.Contains("authenticatorData", StringComparison.Ordinal) && !all.Contains("clientDataJSON", StringComparison.Ordinal), "canary: no passkey proof is in any answer");
            check(sessionToken.Length > 20 && !all.Split('\n').Any(line => line.Contains(sessionToken, StringComparison.Ordinal) && !line.StartsWith("Set-Cookie", StringComparison.OrdinalIgnoreCase)), "canary: the session token is only ever in the Set-Cookie header");
            check(!all.Contains("PRIVATE KEY", StringComparison.Ordinal) && !all.Contains("recovery", StringComparison.OrdinalIgnoreCase) || !all.Contains("recovery code", StringComparison.OrdinalIgnoreCase), "canary: no private key or recovery material is in any answer");
        }
        finally
        {
            string files = "";
            AppLog.Close();
            foreach (string file in Directory.Exists(logFolder) ? Directory.EnumerateFiles(logFolder, "with-secrets-*.log") : [])
            {
                using FileStream stream = new(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using StreamReader reader = new(stream);
                files += reader.ReadToEnd();
            }

            string logged = capture.Everything() + "\n" + files + "\n" + terminal;
            check(!logged.Contains("BODY-CANARY-77123", StringComparison.Ordinal) && !logged.Contains("MEMBER-CANARY-55871", StringComparison.Ordinal) && !logged.Contains("Canary-Value-48151623", StringComparison.Ordinal) && !logged.Contains("authenticatorData", StringComparison.Ordinal), "canary: a request body, a secret value or a proof is in no log line, log file or terminal output (" + capture.Events.Count + " events)");
            AppLog.LogFolder = null;
            AppLog.Tap = null;
            TerminalPrompt.Output = previousOutput;
        }
    }

    // ---- the verbs are gone ----

    private static Task VerbsAreGone(Action<bool, string> check)
    {
        string fp = new('A', 64);
        string[][] verbs =
        [
            ["admin", "machines"], ["admin", "approve", fp[..12], "--name", "x"], ["admin", "disable", fp[..12]], ["admin", "enable", fp[..12]], ["admin", "untrust", fp[..12]], ["admin", "trust", fp], ["admin", "rename", fp[..12], "n"],
            ["admin", "approve-host-change", fp[..12]], ["admin", "grant", "list"], ["admin", "grant", "extend", "g-abcd", "--minutes", "5"], ["admin", "grant", "renew", "g-abcd", "--indefinite"], ["admin", "grant", "revoke", "g-abcd"],
            ["admin", "audit"], ["admin", "audit", "--gaps"], ["admin", "rotate-authority-key"], ["admin", "recover-authority"], ["admin", "lock"], ["admin", "unlock"], ["admin", "frobnicate"],
        ];
        check(verbs.All(args => CliArgs.Parse(args, out string error) is null && error.Length > 0), "verbs: every old admin verb (machines, approve, disable, enable, untrust, trust, rename, approve-host-change, grant ..., audit, rotate-authority-key, recover-authority) is refused");
        check(CliArgs.Parse(["admin"], out _) is { } bare && !CliArgs.NeedsTerminal(bare), "admin: with no words it is the one form (the app link and the public status)");
        check(CliArgs.Parse(["admin", "--service-port", "4000", "--debug"], out _) is { }, "admin: --service-port and --debug are still accepted");
        check(CliArgs.Parse(["--help"], out _) is CliCommand.Help { Text: var help } && help.Contains("admin web app", StringComparison.Ordinal) && !help.Contains("approve-host-change", StringComparison.Ordinal) && !help.Contains("rotate-authority-key", StringComparison.Ordinal), "help: it describes the admin web app, not the removed verbs");

        return Task.CompletedTask;
    }
}

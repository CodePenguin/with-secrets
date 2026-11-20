using System.Text.Json;

using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>
/// Phase 6b-1 fix round (review of 81c9e24 and c3b027f): a session is the cookie AND a secret given once (cookies are sent to every localhost port); a sign-in is read-only to read and claimed by its own
/// browser with a POST; limits and waiting pages are per caller and nothing a caller without a session does can close another's page or keep Lock from being asked; the authority key is checked when a
/// key-related change is applied; a lock between planning and keeping ends the request; passkey changes stop on a lock; refusals are audited per caller; problems are RFC 9457 and never carry exception text.
/// </summary>
internal static class ApiHardeningTests
{
    public static async Task Run(Action<bool, string> check, string root)
    {
        await CookiesAloneAreNotASession(check, root);
        await SignInIsClaimedByItsBrowser(check, root);
        await LimitsAndPagesArePerCaller(check, root);
        await LockCannotBeStarved(check, root);
        await KeyAndLockWindows(check, root);
        await PasskeyChangesStop(check, root);
        await AuditAndProblems(check, root);
        await TwoMutationsOneAuthorization(check, root);
    }

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

    private static string AuditText(AuthorityStore store) => string.Join("\n", store.Audit(5000).Select(entry => entry.Event + "|" + entry.Actor + "|" + entry.Detail));

    private static int Tap(AdminApp app, Tapped tapped, TestAuthenticator signer) => TestState.Approve(app.Http, tapped.PageUrl, "http://localhost:" + new Uri(tapped.Link!).Port, "localhost", signer).Item1;

    private static void CopyCookies(AdminBrowser from, AdminBrowser to, params string[] names)
    {
        foreach ((string name, string value) in from.Cookies.Where(item => names.Length == 0 || names.Contains(item.Key)))
        {
            to.SetCookie(name, value);
        }
    }

    // ---- M1: the cookie alone is not a session ----

    private static async Task CookiesAloneAreNotASession(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root);
        AdminBrowser b = await app.SignedIn();
        string port = app.Service.Port.ToString(System.Globalization.CultureInfo.InvariantCulture);
        string cookie = b.Cookies[AdminSessions.SessionCookie];
        check(cookie.StartsWith(port + ".", StringComparison.Ordinal) && b.Cookies[AdminSessions.BrowserCookie].StartsWith(port + ".", StringComparison.Ordinal), "cookies: the cookie values are bound to this service's port");
        check((await b.GetAsync("/api/v1/machines")).Status == 200, "cookies: the page (cookie and its own secret) reads");

        // Another program on another localhost port is sent the cookies; it replays them here without the page's secret.
        AdminBrowser thief = app.Browser();
        CopyCookies(b, thief);
        List<ApiRoute> reads = [.. app.Service.Admin.Api.Routes.Where(route => route.Access == ApiAccess.Read && !route.Template.Contains('{', StringComparison.Ordinal))];
        int served = 0;
        foreach (ApiRoute route in reads)
        {
            served += (await thief.GetAsync(route.Template)).Status == 200 ? 1 : 0;
        }

        check(reads.Count >= 6 && served == 0, "cookies: with the session cookie alone no read is served (" + served + " of " + reads.Count + ")");
        served = 0;
        foreach (ApiRoute route in reads)
        {
            served += (await thief.GetAsync(route.Template, token: "AAAA")).Status == 200 ? 1 : 0;
        }

        check(served == 0, "cookies: with the session cookie and a made-up secret no read is served");
        check((await thief.GetAsync("/api/v1/machines", token: b.BrowserToken)).Status == 401, "cookies: the browser's secret is not the session's");
        (int whoStatus, string who, _) = await thief.GetAsync("/api/v1/session");
        check(whoStatus == 200 && Member(who, "authenticated") == "false" && !who.Contains("antiForgery", StringComparison.OrdinalIgnoreCase) && thief.LastSetCookie.Length == 0, "cookies: GET /session with the cookie alone says nobody is signed in, gives no secret and sets no cookie");
        int askedBefore = app.Asked;
        (int authorize, _) = await thief.PostAsync("/api/v1/authorizations", AdminBrowser.AuthorizationBody("machine-disable", ("fingerprint", app.Fingerprint[..20])), token: null);
        (int authorizeWrong, _) = await thief.PostAsync("/api/v1/authorizations", AdminBrowser.AuthorizationBody("machine-disable", ("fingerprint", app.Fingerprint[..20])), token: "AAAA");
        check(authorize == 403 && authorizeWrong == 403 && app.Asked == askedBefore, "cookies: with the cookies alone no authorization (and no passkey prompt) can be started");
        AdminBrowser moved = app.Browser();
        moved.SetCookie(AdminSessions.SessionCookie, cookie[(cookie.IndexOf('.', StringComparison.Ordinal) + 1)..]);
        moved.BrowserToken = null;
        moved.SessionToken = b.SessionToken;
        check((await moved.GetAsync("/api/v1/machines")).Status == 401, "cookies: a cookie value that is not bound to this port is not a session, whatever secret is sent");

        // A replayed cookie does not keep the session alive.
        app.Clock.Advance(TimeSpan.FromMinutes(10));
        check((await thief.GetAsync("/api/v1/machines")).Status == 401, "cookies: replayed alone after 10 minutes");
        app.Clock.Advance(TimeSpan.FromMinutes(10));
        check((await b.GetAsync("/api/v1/machines")).Status == 401, "cookies: the replay renewed nothing (the idle timeout ended the session 20 minutes after its last real use)");
    }

    // ---- L8 and M1: GET /session claims nothing, the claim is a POST by the browser that began the sign-in ----

    private static async Task SignInIsClaimedByItsBrowser(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root);
        AdminBrowser victim = app.Browser();
        Tapped started = await victim.StartSignInAsync(app.Laptop);
        check(started.ApproveStatus == 200 && !victim.HasSession, "claim: the tap alone starts no session");
        string ready = "";
        for (int i = 0; i < 40 && !ready.Contains("ready", StringComparison.Ordinal); i++)
        {
            ready = (await victim.GetAsync("/api/v1/session")).Html;
        }

        check(Member(ready, "authenticated") == "false" && ready.Contains("\"ready\"", StringComparison.Ordinal) && !victim.HasSession && victim.LastSetCookie.Length == 0 && app.Service.Admin.Sessions.Count == 0, "claim: GET /session says the login is ready but claims nothing and sets no cookie (L8)");

        // A program that was sent the cookies (but has not the browser's secret) cannot see or claim the login.
        AdminBrowser sniffer = app.Browser();
        CopyCookies(victim, sniffer);
        (int sniffStatus, string sniffed, _) = await sniffer.GetAsync("/api/v1/session");
        (int sniffClaim, string sniffClaimBody) = await sniffer.PostAsync("/api/v1/session/claim", "{}", token: null);
        check(sniffStatus == 200 && !sniffed.Contains("ready", StringComparison.Ordinal) && sniffClaim == 403 && Code(sniffClaimBody) == "anti-forgery" && app.Service.Admin.Sessions.Count == 0, "claim: the cookies alone neither show the login nor claim it");

        // Another browser identity with the victim's login cookie cannot claim it: a login belongs to the browser that began it.
        AdminBrowser other = app.Browser();
        await other.LoadAsync();
        other.SetCookie(AdminSessions.LoginCookie, victim.Cookies[AdminSessions.LoginCookie]);
        (int otherClaim, string otherBody) = await other.PostAsync("/api/v1/session/claim", "{}");
        check(otherClaim == 404 && Code(otherBody) == "no-sign-in" && app.Service.Admin.Sessions.Count == 0, "claim: another browser with the login cookie cannot claim it");
        (int noOrigin, _) = await victim.PostAsync("/api/v1/session/claim", "{}", origin: null);
        (int otherOrigin, _) = await victim.PostAsync("/api/v1/session/claim", "{}", origin: "http://evil.example");
        check(noOrigin == 403 && otherOrigin == 403 && app.Service.Admin.Sessions.Count == 0, "claim: it needs a same-origin request");

        (int claim, string claimBody) = await victim.ClaimAsync();
        string secret = victim.SessionToken ?? "";
        check(claim == 201 && victim.HasSession && secret.Length >= 32 && Member(claimBody, "antiForgery") == secret && claimBody.Contains("\"authenticated\":true", StringComparison.Ordinal), "claim: the browser that began the sign-in claims it with a POST and is given the session's secret, once");
        int mark = victim.Seen.Count;
        (int again, string againBody) = await victim.ClaimAsync();
        await victim.GetAsync("/api/v1/session");
        await victim.GetAsync("/api/v1/machines");
        await victim.GetAsync("/api/v1/settings");
        await victim.SendAsync(HttpMethod.Delete, "/api/v1/session", null).ContinueWith(_ => { });
        check(again is 409 or 404 or 403 && !againBody.Contains(secret, StringComparison.Ordinal) && victim.Seen.Skip(mark).All(seen => !seen.Contains(secret, StringComparison.Ordinal)), "claim: it is not given again, and the secret is in no later answer");
    }

    // ---- M2: per-caller limits and pages, nothing evicted by a caller without a session ----

    private static async Task LimitsAndPagesArePerCaller(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root, askSeconds: 30);
        AdminBrowser honest = app.Browser();
        Tapped honestPage = await honest.StartSignInAsync();
        check(honestPage.Link is not null, "pages: a sign-in page is waiting");

        // One caller floods: it is limited, and only it.
        AdminBrowser attacker = app.Browser();
        await attacker.LoadAsync();
        int limited = 0;
        for (int i = 0; i < 40; i++)
        {
            limited += (await attacker.PostAsync("/api/v1/session", "{}")).Status == 429 ? 1 : 0;
        }

        check(limited >= 8, "pages: a caller that starts more than 30 a minute is refused (429): " + limited);
        AdminBrowser second = app.Browser();
        Tapped secondPage = await second.StartSignInAsync();
        check(secondPage.Link is not null, "pages: another caller's starts are not used up by the flood");
        check(Tap(app, honestPage, app.Laptop) == 200 && await honest.FinishSignInAsync(), "pages: the waiting sign-in of another caller was not closed or evicted by the flood, and still signs in");

        // Callers without a session share a limited number of waiting pages: more are refused, and no waiting page is closed.
        List<AdminBrowser> crowd = [];
        List<int> statuses = [];
        for (int i = 0; i < AdminService.MaxAnonymousPages + 3; i++)
        {
            AdminBrowser extra = app.Browser();
            await extra.LoadAsync();
            statuses.Add((await extra.PostAsync("/api/v1/session", "{}")).Status);
            crowd.Add(extra);
        }

        int refused = statuses.Count(status => status == 429);
        check(refused >= 3 && statuses.Count(status => status == 202) >= AdminService.MaxAnonymousPages - 3, "pages: callers without a session share a limited number of waiting pages; further ones are refused (" + refused + " refused)");
        check(Tap(app, secondPage, app.Laptop) == 200 && await second.FinishSignInAsync(), "pages: the pages that were waiting are not closed by the refused ones");

        // A signed-in administrator is not affected by the crowd.
        check(honest.HasSession && (await honest.GetAsync("/api/v1/machines")).Status == 200, "pages: a signed-in administrator still reads");
        Tapped rename = await honest.OpAsync("machine-rename", app.Laptop, true, null, true, ("fingerprint", app.Fingerprint[..20]), ("name", "crowded"));
        check(rename.MutationStatus == 200, "pages: and still changes something (authorize, tap, mutate) while callers without a session fill their pages");
    }

    // ---- M2: Lock has a path that cannot be starved, and still needs its own fresh tap ----

    private static async Task LockCannotBeStarved(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root, askSeconds: 30);
        AdminBrowser admin = await app.SignedIn();
        List<AdminBrowser> crowd = [];
        for (int i = 0; i < AdminService.MaxAnonymousPages + 2; i++)
        {
            AdminBrowser extra = app.Browser();
            await extra.LoadAsync();
            await extra.PostAsync("/api/v1/session", "{}");
            crowd.Add(extra);
        }

        // Without a session, a lock needs its own authorization: nothing locks by itself.
        AdminBrowser nobody = app.Browser();
        await nobody.LoadAsync();
        (int bare, string bareBody) = await nobody.PostAsync("/api/v1/lock", "{\"authorization\":\"AAAAAAAAAAAA\"}");
        check(bare == 403 && !app.Service.Lock.IsLocked, "lock: with no session and no authorization nothing locks (" + bare + " " + Code(bareBody) + ")");
        Tapped phone = await nobody.OpAsync(AdminService.OpLock, app.Phone);
        check(phone.ApproveStatus != 200 && phone.MutationStatus == 0 && !app.Service.Lock.IsLocked, "lock: a tap by a key that is not an admin locks nothing");

        // The page crowd is full of callers without a session, and 12 more ask for Lock pages: none is refused, the newest works.
        List<AdminBrowser> lockers = [];
        List<Tapped> pages = [];
        for (int i = 0; i < AdminService.MaxLockPages + 4; i++)
        {
            AdminBrowser locker = app.Browser();
            lockers.Add(locker);
            pages.Add(await locker.OpAsyncWithoutMutation(AdminService.OpLock, null));
        }

        check(pages.All(page => page.Link is not null && page.PostStatus == 201), "lock: while callers without a session fill their pages, every request for a Lock page is answered with one (none is refused)");
        check(Tap(app, pages[0], app.Laptop) != 200, "lock: the oldest page, pushed out by newer ones, is closed");
        Tapped newest = pages[^1];
        check(Tap(app, newest, app.Laptop) == 200, "lock: the newest page takes the tap");
        check(await HostServiceTests.WaitFor(() => app.Service.Lock.IsLocked) && app.Service.Admin.Sessions.Count == 0 && (await admin.GetAsync("/api/v1/machines")).Status == 401, "lock: a fresh tap (no session, a Lock page of its own) locks, and ends every session");
    }

    // ---- L1, L2: the key that was signed, and a lock that comes between planning and keeping ----

    private static async Task KeyAndLockWindows(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root);
        AdminBrowser b = await app.SignedIn();

        // L1: two rotations are authorized (each names "Current key: K1"); the first is applied, so the second is for a key that is no longer current.
        // The service applies each change when its tap is verified, so two sessions each ask for a rotation (each page names the current key) and the second tap comes after the first rotation was applied.
        AdminBrowser other = await app.SignedIn();
        Tapped first = await b.OpAsyncWithoutMutation("authority-key-rotate", null);
        Tapped second = await other.OpAsyncWithoutMutation("authority-key-rotate", null);
        string k1 = app.Store.ActiveKey()?.Fingerprint ?? "";
        check(first.Link is not null && second.Link is not null && Tap(app, first, app.Laptop) == 200 && await b.WaitAuthorizationAsync(first.AuthorizationId!) == "consumed", "key: two rotations are authorized, and the first tap rotates the key");
        app.Clock.Advance(TimeSpan.FromSeconds(31));
        string k2 = app.Store.ActiveKey()?.Fingerprint ?? "";
        int secondTap = Tap(app, second, app.Laptop);
        await other.WaitAuthorizationAsync(second.AuthorizationId!);
        (HttpMethod m2, string p2, string j2) = other.MutationRequest("authority-key-rotate", second.AuthorizationId);
        (int stale, string staleBody) = await other.SendAsync(m2, p2, j2);
        int rotated = secondTap == 200 ? 200 : 0;
        check(rotated == 200 && k2 != k1 && stale == 409 && Code(staleBody) == "operation-failed" && app.Store.ActiveKey()?.Fingerprint == k2 && staleBody.Contains("authority key changed", StringComparison.Ordinal), "key: the second rotation was signed for the old key, so it is refused when applied and the key is still the first rotation's");

        // The same for a lock that was authorized for a key that was rotated away since.
        Tapped lockTap = await b.OpAsyncWithoutMutation(AdminService.OpLock, null);
        Tapped third = await b.OpAsyncWithoutMutation("authority-key-rotate", null);
        app.Clock.Advance(TimeSpan.FromSeconds(31));
        Tap(app, third, app.Laptop);
        await b.WaitAuthorizationAsync(third.AuthorizationId!);
        app.Clock.Advance(TimeSpan.FromSeconds(31));
        Tap(app, lockTap, app.Laptop);
        await b.WaitAuthorizationAsync(lockTap.AuthorizationId!);
        (HttpMethod ml, string pl, string jl) = b.MutationRequest(AdminService.OpLock, lockTap.AuthorizationId);
        (int staleLock, _) = await b.SendAsync(ml, pl, jl);
        check(staleLock == 409 && !app.Service.Lock.IsLocked, "key: a lock that was authorized for a key that has since been rotated is refused when applied");

        // L2: a lock that comes between planning and keeping the authorization ends the request: no page, nothing held.
        int asked = app.Asked;
        app.Service.Admin.AfterPlanForTests = () => app.Service.Lock.Lock("test");
        (AuthorizationView? view, AdminStart start) = await app.Service.Admin.BeginAuthorizationAsync(Sessions(app, b), "machine-rename", new Dictionary<string, string> { ["fingerprint"] = app.Fingerprint[..20], ["name"] = "window" }, CancellationToken.None);
        app.Service.Admin.AfterPlanForTests = null;
        check(view is null && start.Status == 423 && app.Asked == asked && app.Service.Admin.AuthorizationCount == 0, "window: a lock between planning and keeping an authorization ends it (423): no page is made and nothing is held");
        app.Service.Lock.Unlock(UnlockMethod.Manual);
        AdminBrowser c = await app.SignedIn();
        asked = app.Asked;
        app.Service.Admin.AfterPlanForTests = () => app.Service.Lock.Lock("test");
        (AdminStart loginStart, string? ticket) = await app.Service.Admin.BeginLoginAsync("browser-id-for-test", CancellationToken.None);
        app.Service.Admin.AfterPlanForTests = null;
        check(loginStart.Status == 423 && ticket is null && app.Asked == asked, "window: a lock between starting a sign-in and its page ends it as well");
        _ = c;
    }

    private static AdminSession Sessions(AdminApp app, AdminBrowser b)
    {
        // The session object of a browser that is signed in, found by its cookie and secret (the service validates both).
        string cookie = b.Cookies[AdminSessions.SessionCookie];

        return app.Service.Admin.Sessions.Validate(cookie[(cookie.IndexOf('.', StringComparison.Ordinal) + 1)..], b.SessionToken) ?? throw new InvalidOperationException("no session");
    }

    // ---- L3: passkey changes stop on a lock ----

    private static async Task PasskeyChangesStop(Action<bool, string> check, string root)
    {
        StoppablePasskeys stoppable = new();
        using AdminApp rig = new(root, askSeconds: 20, passkeys: stoppable);
        AdminBrowser b = await rig.SignedIn();
        Tapped tapped = await b.OpAsync("passkey-enroll", rig.Laptop);
        check(tapped.MutationStatus == 202, "passkeys: the enrollment pages are started after the authorization (" + tapped.MutationStatus + ")");
        rig.Service.Lock.Lock("test");
        Task done = await Task.WhenAny(stoppable.Stopped, Task.Delay(5000));
        check(done == stoppable.Stopped && stoppable.Stopped.IsCompletedSuccessfully, "passkeys: a lock stops the enrollment flow (its pages are cancelled and it is told why)");
        await Task.Delay(300);
        string audit = AuditText(rig.Store);
        check(!audit.Contains("enroll-passkey; applied", StringComparison.Ordinal) && audit.Contains("enroll-passkey", StringComparison.Ordinal) && audit.Contains("refused", StringComparison.Ordinal), "passkeys: the audit history says the enrollment was refused, not applied");
    }

    // ---- L4 to L7: audit, problems, expiry ----

    private static async Task AuditAndProblems(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root);
        AdminBrowser b = await app.SignedIn();
        string fp = app.Fingerprint[..20];

        // L4: a caller that floods refusals cannot hide another caller's.
        AdminBrowser junk = app.Browser();
        for (int i = 0; i < 60; i++)
        {
            await junk.PostAsync("/api/v1/authorizations", "{}", origin: null);
        }

        (int noAuthorization, _) = await b.SendAsync(HttpMethod.Post, "/api/v1/machines/" + fp + "/disable", "{\"authorization\":\"ZZZZZZZZZZZZ\"}");
        string audit = AuditText(app.Store);
        check(noAuthorization == 403 && audit.Contains("authorization invalid", StringComparison.Ordinal), "audit: another caller's refusal is written although a program flooded refusals just before");
        app.Clock.Advance(TimeSpan.FromMinutes(2));
        await b.GetAsync("/api/v1/status");
        (int again, _) = await junk.PostAsync("/api/v1/authorizations", "{}", origin: null);
        audit = AuditText(app.Store);
        check(again == 403 && audit.Contains("refusals from one caller were not written one by one", StringComparison.Ordinal) || audit.Contains("earlier refusals from this caller were not written one by one", StringComparison.Ordinal), "audit: what was not written one by one is counted in a summary row");

        // A body that does not fit the schema, on a route that changes something, is a refusal that is audited.
        (int schema, _) = await b.PostAsync("/api/v1/authorizations", "{\"operation\":\"no-such-operation\"}");
        check(schema == 400 && AuditText(app.Store).Contains("invalid request: invalid-request", StringComparison.Ordinal), "audit: a body that fails the schema is refused (400) and the refusal is audited");

        // The end of a session by its idle timeout is audited.
        AdminBrowser idle = await app.SignedIn();
        app.Clock.Advance(TimeSpan.FromMinutes(16));
        await b.GetAsync("/api/v1/status");
        (int ended, _) = await idle.GetAsync("/api/v1/machines").ContinueWith(task => (task.Result.Status, 0));
        check(ended == 401 && AuditText(app.Store).Contains("ended: idle timeout", StringComparison.Ordinal), "audit: a session that ran out (idle timeout) is audited");

        // L5: every refusal is a problem document, also the 404 of an authorization that is not the caller's.
        AdminBrowser c = await app.SignedIn();
        (int missing, string missingBody, HttpResponseMessage missingResponse) = await c.GetAsync("/api/v1/authorizations/doesnotexist");
        using JsonDocument problem = JsonDocument.Parse(missingBody);
        check(missing == 404 && missingResponse.Content.Headers.ContentType?.MediaType == "application/problem+json" && problem.RootElement.TryGetProperty("type", out _) && problem.RootElement.TryGetProperty("title", out _) && problem.RootElement.GetProperty("status").GetInt32() == 404 && Code(missingBody) == "not-found" && !missingBody.Contains("supportedVersions", StringComparison.Ordinal), "problems: the 404 of an authorization that is not the caller's is an RFC 9457 document (type, title, status, code)");

        // L7: a verified authorization reports when it really ends.
        Tapped tapped = await c.OpAsyncWithoutMutation("set-audit-retention", app.Laptop, ("days", "30"));
        await c.WaitAuthorizationAsync(tapped.AuthorizationId!);
        (_, string state, _) = await c.GetAsync("/api/v1/authorizations/" + tapped.AuthorizationId);
        check(Member(state, "state") == "consumed" && state.Contains("\"outcome\":\"applied\"", StringComparison.Ordinal) && app.Store.AuditRetentionDays() == 30, "expiry: a tap that was verified has already made its change, and the authorization says it was applied (there is no window to wait out)");

        // L6: a failure of the store is one fixed sentence, never the text of the exception.
        Tapped held = await c.OpAsyncWithoutMutation("set-audit-retention", null, ("days", "31"));
        using (SqliteConnection hold = new("Data Source=" + app.Store.FilePath + ";Pooling=False"))
        {
            hold.Open();
            using (SqliteCommand begin = hold.CreateCommand())
            {
                begin.CommandText = "BEGIN EXCLUSIVE";
                begin.ExecuteNonQuery();
            }

            Tap(app, held, app.Laptop);
            await c.WaitAuthorizationAsync(held.AuthorizationId!);
            (HttpMethod method, string path, string json) = c.MutationRequest("set-audit-retention", held.AuthorizationId, ("days", "31"));
            (int failed, string failedBody) = await c.SendAsync(method, path, json);
            using JsonDocument failure = JsonDocument.Parse(failedBody);
            string detail = failure.RootElement.TryGetProperty("detail", out JsonElement d) ? d.GetString() ?? "" : "";
            check(failed >= 400 && !detail.Contains("Sqlite", StringComparison.OrdinalIgnoreCase) && !detail.Contains("Exception", StringComparison.OrdinalIgnoreCase) && !detail.Contains(app.Store.FilePath, StringComparison.OrdinalIgnoreCase) && !detail.Contains("SQLite", StringComparison.OrdinalIgnoreCase), "problems: a store failure carries no exception text (" + failed + ")");
        }

        // The request header: a client may say which version it speaks.
        (int okVersion, _) = await c.SendAsync(HttpMethod.Get, "/api/v1/status", null, token: null, origin: null);
        using HttpRequestMessage two = new(HttpMethod.Get, c.Base + "/api/v1/status");
        two.Headers.Add("X-Api-Version", "2");
        using HttpClient raw = new(new SocketsHttpHandler { UseProxy = false });
        using HttpResponseMessage twoResponse = await raw.SendAsync(two);
        string twoBody = await twoResponse.Content.ReadAsStringAsync();
        using HttpRequestMessage one = new(HttpMethod.Get, c.Base + "/api/v1/status");
        one.Headers.Add("X-Api-Version", "1");
        using HttpResponseMessage oneResponse = await raw.SendAsync(one);
        check(okVersion == 200 && (int)twoResponse.StatusCode == 400 && Code(twoBody) == "unsupported-api-version" && twoBody.Contains("supportedVersions", StringComparison.Ordinal) && (int)oneResponse.StatusCode == 200, "versions: the X-Api-Version request header is checked (2 is refused with the supported versions, 1 is served)");
    }

    // ---- the race: two mutations carrying one authorization ----

    private static async Task TwoMutationsOneAuthorization(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root);
        AdminBrowser b = await app.SignedIn();
        Tapped tapped = await b.OpAsyncWithoutMutation("set-audit-retention", app.Laptop, ("days", "12"));
        check(await b.WaitAuthorizationAsync(tapped.AuthorizationId!) == "consumed" && app.Store.AuditRetentionDays() == 12, "race: the tap made the change when it was verified");
        (HttpMethod method, string path, string json) = b.MutationRequest("set-audit-retention", tapped.AuthorizationId, ("days", "12"));
        Task<(int Status, string Body)>[] sends = [.. Enumerable.Range(0, 8).Select(_ => b.SendAsync(method, path, json))];
        (int Status, string Body)[] answers = await Task.WhenAll(sends);
        int applied = answers.Count(answer => answer.Status == 200 && Member(answer.Body, "outcome") == "applied");
        int used = answers.Count(answer => answer.Status == 200 && Member(answer.Body, "outcome") == "already-applied");
        int appliedRows = AuditText(app.Store).Split('\n').Count(line => line.Contains("set-audit-retention", StringComparison.Ordinal) && line.Contains("applied", StringComparison.Ordinal));
        check(applied == 1 && used == 7 && app.Store.AuditRetentionDays() == 12 && appliedRows == 1, "race: eight mutations that carry one authorization at the same time apply nothing again: one is the answer, seven are told it was already applied (" + applied + " applied, " + used + " repeats, " + appliedRows + " audit rows)");
    }
}

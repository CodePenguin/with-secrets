using System.Net;
using System.Security.Cryptography;
using System.Text;

using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>
/// Phase 6a: the admin web app. A session (one fresh passkey tap, an HttpOnly SameSite=Strict cookie, in the service's memory only, idle and absolute timeouts) reads and changes nothing;
/// every sensitive operation is its own fresh, single-use passkey tap with user verification bound to that operation and its parameters; a request that changes anything also needs the
/// anti-forgery value, a same-origin request and a loopback Host. The functions of the removed <c>admin</c> verbs are checked here against the web endpoints.
/// </summary>
internal static class AdminAppTests
{
    public static async Task Run(Action<bool, string> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "ws-app-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);
        try
        {
            await PublicAndSignIn(check, root);
            await SessionTimeouts(check, root);
            await LogoutLockRestart(check, root);
            await ForgeryAndOrigin(check, root);
            await SensitiveMatrix(check, root);
            await MachineFunctions(check, root);
            await SettingsAndPasskeys(check, root);
            await Pending(check, root);
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

    private static readonly string[] Views = ["/admin/machines", "/admin/grants", "/admin/audit", "/admin/settings", "/admin/passkeys"];

    /// <summary>What an administrator change could touch.</summary>
    private static string Snapshot(AdminApp app)
    {
        AuthorityStore store = app.Store;
        MachineRecord machine = store.Find(app.Fingerprint)!;

        return string.Join('|', machine.Status, machine.SecurityRevision, machine.FriendlyName, machine.HostName, machine.PendingHostName, store.ActiveKey()?.Fingerprint, store.GetUnlockPolicy(), store.AuditRetentionDays(), store.SessionTimeouts(), store.Grants().Count, app.Service.Lock.IsLocked);
    }

    private static string AuditText(AuthorityStore store) => string.Join("\n", store.Audit(1000).Select(entry => entry.Event + "|" + entry.Actor + "|" + entry.Detail));

    // ---- the public page, the sign-in and the cookie ----

    private static async Task PublicAndSignIn(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root);
        AdminBrowser b = app.Browser();
        (int status, string html, HttpResponseMessage response) = await b.GetAsync("/admin");
        check(status == 200 && html.Contains("running", StringComparison.Ordinal) && html.Contains("Sign in with passkey", StringComparison.Ordinal) && !html.Contains(app.Fingerprint, StringComparison.Ordinal), "app: the status page is public and shows only the state and the sign-in");
        check(response.Headers.Contains("X-Frame-Options") && response.Headers.GetValues("Content-Security-Policy").Single().Contains("script-src 'nonce-", StringComparison.Ordinal) && !html.Contains("http://", StringComparison.Ordinal) && !html.Contains("https://", StringComparison.Ordinal), "app: the page is protected against framing and inline script and loads nothing from anywhere");
        foreach (string view in Views)
        {
            (int viewStatus, string viewHtml, _) = await b.GetAsync(view);
            check(viewStatus == 401 && !viewHtml.Contains("<table", StringComparison.Ordinal) && !viewHtml.Contains(app.Fingerprint, StringComparison.Ordinal), "app: " + view + " is not served without a session");
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
            await b.LoadAsync();
            check(!started && !b.HasSession && (await b.GetAsync("/admin/machines")).Status == 401, "session: " + label + " starts no session");
        }

        check(app.Service.Admin.Sessions.Count == 0, "session: after refused sign-ins the service holds no session");
        check(await b.SignInAsync(app.Laptop) && b.HasSession, "session: the admin key's tap (with user verification) starts one");
        string cookie = b.LastSetCookie.Split('\n').First(line => line.StartsWith(AdminSessions.SessionCookie + "=", StringComparison.Ordinal));
        string token = b.Cookies[AdminSessions.SessionCookie];
        check(cookie.Contains("httponly", StringComparison.OrdinalIgnoreCase) && cookie.Contains("samesite=strict", StringComparison.OrdinalIgnoreCase) && cookie.Contains("path=/admin", StringComparison.OrdinalIgnoreCase) && !cookie.Contains("expires", StringComparison.OrdinalIgnoreCase), "session: the cookie is HttpOnly, SameSite=Strict, scoped to /admin and a session cookie (no expiry)");
        string pageAfter = (await b.GetAsync("/admin")).Html;
        check(!pageAfter.Contains(token, StringComparison.Ordinal), "session: the token is in the cookie only, not on any page");
        foreach (string view in Views)
        {
            (int viewStatus, string viewHtml, _) = await b.GetAsync(view);
            check(viewStatus == 200 && !viewHtml.Contains(token, StringComparison.Ordinal) && !viewHtml.Contains("http://", StringComparison.Ordinal) && !viewHtml.Contains("src=", StringComparison.Ordinal), "session: " + view + " is served read-only to the session, with no asset from elsewhere and no token");
        }

        string audit = AuditText(app.Store);
        check(audit.Contains("admin-operation||admin-session; started", StringComparison.Ordinal) || app.Store.Audit(1000).Any(entry => entry.Event == "admin-operation" && entry.Detail.StartsWith("admin-session; started", StringComparison.Ordinal) && entry.Actor == "admin passkey laptop"), "session: the start is in the authority's audit history with the key that tapped");
        check(!audit.Contains(token, StringComparison.Ordinal) && !audit.Contains("authenticatorData", StringComparison.Ordinal), "session: the audit history holds neither the token nor a proof");
        (_, string machines, _) = await b.GetAsync("/admin/machines");
        check(machines.Contains(KeyIdentity.Display(app.Fingerprint), StringComparison.Ordinal) && machines.Contains("Trusted", StringComparison.Ordinal) && machines.Contains(app.Machine.HostName, StringComparison.Ordinal), "machines view: shows the fingerprint, status and host name");
        (_, string settings, _) = await b.GetAsync("/admin/settings");
        check(settings.Contains("365", StringComparison.Ordinal) && settings.Contains("15", StringComparison.Ordinal) && settings.Contains("480", StringComparison.Ordinal) && settings.Contains("manual", StringComparison.OrdinalIgnoreCase), "settings view: shows the audit retention, the session timeouts and the unlock mode");
    }

    // ---- the idle and absolute timeouts, with a fake clock ----

    private static async Task SessionTimeouts(Action<bool, string> check, string root)
    {
        // Idle: each use renews; fifteen minutes of nothing ends it.
        using (AdminApp app = new(root))
        {
            AdminBrowser b = await app.SignedIn();
            app.Clock.Advance(TimeSpan.FromMinutes(14));
            bool first = (await b.GetAsync("/admin/machines")).Status == 200;
            app.Clock.Advance(TimeSpan.FromMinutes(14));
            bool renewed = (await b.GetAsync("/admin/machines")).Status == 200;
            app.Clock.Advance(TimeSpan.FromMinutes(16));
            (int expired, _, _) = await b.GetAsync("/admin/machines");
            check(first && renewed && expired == 401 && app.Service.Admin.Sessions.Count == 0, "session: it ends after the idle timeout (15 minutes) without use, and each use renews it");
            await b.LoadAsync();
            check(!(await b.GetAsync("/admin/grants")).Html.Contains("<table", StringComparison.Ordinal) && (await b.PostAsync("/admin/op", "{\"op\":\"lock\"}")).Status is 401 or 403, "session: an expired session's cookie reads and starts nothing");
        }

        // Absolute: however busy, it ends at the absolute timeout. The timeouts are a setting (a tap of their own).
        using AdminApp absolute = new(root);
        AdminBrowser c = await absolute.SignedIn();
        Tapped set = await c.OpAsync("set-session-timeouts", absolute.Laptop, true, null, true, ("idle", "5"), ("absolute", "10"));
        check(set.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => absolute.Store.SessionTimeouts() == (5, 10)), "settings: the session timeouts are changed by a tap of their own (5 and 10 minutes)");
        absolute.Clock.Advance(TimeSpan.FromMinutes(4));
        bool a1 = (await c.GetAsync("/admin/machines")).Status == 200;
        absolute.Clock.Advance(TimeSpan.FromMinutes(4));
        bool a2 = (await c.GetAsync("/admin/machines")).Status == 200;
        absolute.Clock.Advance(TimeSpan.FromMinutes(4));
        check(a1 && a2 && (await c.GetAsync("/admin/machines")).Status == 401, "session: it ends at the absolute timeout even when it was used within the idle timeout");
    }

    // ---- logout, lock and restart end sessions ----

    private static async Task LogoutLockRestart(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root);
        AdminBrowser b = await app.SignedIn();
        string token = b.Cookies[AdminSessions.SessionCookie];
        await b.LoadAsync("/admin/machines");
        (int outStatus, _) = await b.PostAsync("/admin/logout", "{}");
        AdminBrowser replay = app.Browser();
        replay.SetCookie(AdminSessions.SessionCookie, token);
        check(outStatus == 200 && !b.HasSession && (await replay.GetAsync("/admin/machines")).Status == 401 && app.Service.Admin.Sessions.Count == 0, "session: sign out ends it; the old cookie value is refused afterwards");
        check(app.Store.Audit(1000).Any(entry => entry.Event == "admin-operation" && entry.Detail.StartsWith("admin-session; ended: sign out", StringComparison.Ordinal)), "session: the end is audited too");

        // Lock destroys every session, and a locked authority starts none.
        AdminBrowser one = await app.SignedIn();
        AdminBrowser two = await app.SignedIn();
        check(app.Service.Admin.Sessions.Count == 2, "session: two browsers can be signed in at once");
        Tapped lockTap = await one.OpAsync(AdminService.OpLock, app.Laptop);
        check(lockTap.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => app.Service.Lock.IsLocked), "lock: the admin key's fresh tap locks");
        check(app.Service.Admin.Sessions.Count == 0 && (await one.GetAsync("/admin/machines")).Status == 401 && (await two.GetAsync("/admin/grants")).Status == 401, "lock: it destroys every session at once");
        // M4: with the authority locked the key operations (and every other change) are refused before any page, and the refusal is audited.
        AdminCaller forgedCaller = new(new AdminSession("t", "laptop", app.Clock.GetUtcNow()));
        string keyBefore = app.Store.ActiveKey()?.Fingerprint ?? "";
        List<AdminStart> lockedAnswers = [];
        foreach (string lockedOp in new[] { "authority-key-rotate", "authority-key-recover", "machine-disable", "set-audit-retention", "policy-unattended" })
        {
            lockedAnswers.Add(await app.Service.Admin.StartAsync(forgedCaller, lockedOp, new Dictionary<string, string> { ["fingerprint"] = app.Fingerprint[..20], ["days"] = "5" }, CancellationToken.None));
        }

        check(lockedAnswers.All(answer => answer.Status == 423 && answer.Link is null) && (app.Store.ActiveKey()?.Fingerprint ?? "") == keyBefore && app.Store.AuditRetentionDays() == 365, "lock: while locked no operation but the unlock gets a page (423); the key is not rotated or recovered");
        check(app.Store.Audit(1000).Count(entry => entry.Event == "admin-operation" && entry.Detail.Contains("authority is locked", StringComparison.Ordinal)) >= 3, "lock: those refused attempts are in the audit history");
        await two.LoadAsync();
        (int loginStatus, string loginBody) = await two.PostAsync("/admin/login", "{}");
        check(loginStatus == 423 && (await two.GetAsync("/admin/machines")).Status == 401 && app.Service.Admin.Sessions.Count == 0, "lock: a locked authority refuses to start a session (" + loginBody + ")");
        Tapped unlock = await two.OpAsync(AdminService.OpUnlock, app.Laptop);
        check(unlock.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => !app.Service.Lock.IsLocked) && app.Service.Admin.Sessions.Count == 0, "lock: unlock needs no session and starts none");

        // A restart destroys them: the sessions are in memory only.
        AdminBrowser before = await app.SignedIn();
        string oldToken = before.Cookies[AdminSessions.SessionCookie];
        app.Start(true);
        AdminBrowser after = app.Browser();
        after.SetCookie(AdminSessions.SessionCookie, oldToken);
        check((await after.GetAsync("/admin/machines")).Status == 401 && app.Service.Admin.Sessions.Count == 0, "session: a service restart destroys every session");
        string files = string.Join("\n", Directory.EnumerateFiles(app.Machine.Folder, "*", SearchOption.AllDirectories).Where(file => !file.EndsWith("-shm", StringComparison.Ordinal)).Select(file =>
        {
            using FileStream stream = new(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using StreamReader reader = new(stream, Encoding.Latin1);

            return reader.ReadToEnd();
        }));
        check(!files.Contains(oldToken, StringComparison.Ordinal), "session: the token is in no file of the authority (memory only)");
    }

    // ---- anti-forgery, origin and host ----

    private static async Task ForgeryAndOrigin(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root);
        AdminBrowser b = app.Browser();
        await b.LoadAsync();
        string browserToken = b.Csrf!;
        check(await b.SignInAsync(app.Laptop), "forgery: signed in");
        string sessionToken = (await b.GetAsync("/admin")).Status == 200 ? b.Csrf! : "";
        check(sessionToken.Length > 0 && sessionToken != browserToken, "forgery: the page's anti-forgery value changes with the session");
        AdminBrowser other = app.Browser();
        await other.LoadAsync();

        string before = Snapshot(app);
        int asked = app.Asked;
        string body = "{\"op\":\"machine-disable\",\"fingerprint\":\"" + app.Fingerprint[..20] + "\"}";
        (string Label, Func<Task<(int Status, string Body)>> Send, int Expect)[] cases =
        [
            ("no Origin (a program, not a page)", () => b.PostAsync("/admin/op", body, origin: null), 403),
            ("an Origin of another site", () => b.PostAsync("/admin/op", body, origin: "http://evil.example"), 403),
            ("an Origin of another port on this machine", () => b.PostAsync("/admin/op", body, origin: "http://localhost:1"), 403),
            ("no anti-forgery value", () => b.PostAsync("/admin/op", body, token: null), 403),
            ("a wrong anti-forgery value", () => b.PostAsync("/admin/op", body, token: "AAAA"), 403),
            ("another browser's anti-forgery value", () => b.PostAsync("/admin/op", body, token: other.Csrf), 403),
            ("the anti-forgery value of the time before the session", () => b.PostAsync("/admin/op", body, token: browserToken), 403),
            ("a valid value but no cookies (a script that stole the value, not the cookie)", () => b.PostAsync("/admin/op", body, withCookies: false), 403),
            ("a Host that is not a loopback name (DNS rebinding)", () => b.PostAsync("/admin/op", body, host: "evil.example:" + app.Service.Port), 421),
            ("a body that is not JSON", () => b.PostAsync("/admin/op", "op=lock", contentType: "text/plain"), 415),
            ("a body that is too large", () => b.PostAsync("/admin/op", "{\"op\":\"x\",\"pad\":\"" + new string('a', 5000) + "\"}"), 415),
        ];
        foreach ((string label, Func<Task<(int Status, string Body)>> send, int expect) in cases)
        {
            (int status, _) = await send();
            check(status == expect, "forgery: " + label + " is refused (" + status + ")");
        }

        check(Snapshot(app) == before && app.Asked == asked, "forgery: none of those started a passkey page or changed anything");
        (int getHost, _, _) = await b.GetAsync("/admin/machines", origin: "http://evil.example");
        check(getHost == 403, "forgery: a view requested from another site is refused");

        // Without a session, a sensitive operation is refused even with a valid page value; the unlock is the one thing it may ask for.
        AdminBrowser anon = app.Browser();
        await anon.LoadAsync();
        (int anonStatus, _) = await anon.PostAsync("/admin/op", body);
        check(anonStatus == 401 && app.Asked == asked && Snapshot(app) == before, "forgery: a sensitive operation with no session is refused (401) and asks for no passkey");
        (int unlockStatus, _) = await anon.PostAsync("/admin/op", "{\"op\":\"unlock\"}");
        check(unlockStatus == 409, "forgery: unlock without a session reaches the service (here already unlocked: " + unlockStatus + ")");
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
                await Task.Delay(60);
                check(denied.Link is not null && denied.ApproveStatus is 403 or 400 && Snapshot(app) == before, $"sensitive {label}: {name} changes nothing (a session does not make it allowed)");
            }

            Tapped done = await b.OpAsync(op, app.Laptop, true, null, true, args);
            check(done.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => Snapshot(app) != before), $"sensitive {label}: the genuine fresh tap applies it");
            string settled = Snapshot(app);
            TestState.Post(app.Http, done.PageUrl + "/proof", done.ProofBody);
            await Task.Delay(150);
            check(Snapshot(app) == settled, $"sensitive {label}: replaying the proof changes nothing");
        }

        // A session alone (and the sign-in tap before it) changes nothing and asks for a page of its own.
        string start = Snapshot(app);
        int askedBefore = app.Asked;
        Tapped sessionOnly = await b.OpAsync("machine-disable", null, true, null, true, ("fingerprint", fp[..20]));
        await Task.Delay(300);
        check(sessionOnly.Link is not null && app.Asked == askedBefore + 1 && Snapshot(app) == start, "sensitive: a signed-in session starts the operation's own passkey page and, without its tap, changes nothing");

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
        await HostServiceTests.WaitFor(() => app.Store.Find(fp)!.FriendlyName == "first name");
        Tapped second = await b.OpAsync("machine-rename", null, true, null, true, ("fingerprint", fp[..20]), ("name", "second name"));
        (int crossed, _) = TestState.Post(app.Http, second.PageUrl + "/proof", first.ProofBody);
        await Task.Delay(300);
        check(crossed != 200 && app.Store.Find(fp)!.FriendlyName == "first name", "sensitive: a proof made for one set of parameters, sent to another operation's page, changes nothing");
        Tapped third = await b.OpAsync("machine-disable", null, true, null, true, ("fingerprint", fp[..20]));
        (int crossedOp, _) = TestState.Post(app.Http, third.PageUrl + "/proof", first.ProofBody);
        await Task.Delay(300);
        check(crossedOp != 200 && app.Store.Find(fp)!.Status == MachineStatus.Trusted, "sensitive: a proof made for another operation, sent to this page, changes nothing");

        // Fail closed with no answer at all: the page times out and nothing changes.
        using AdminApp silent = new(root, askSeconds: 2);
        AdminBrowser s = await silent.SignedIn();
        string silentBefore = Snapshot(silent);
        Tapped nobody = await s.OpAsync("machine-disable", null, true, null, true, ("fingerprint", silent.Fingerprint[..20]));
        await Task.Delay(TimeSpan.FromSeconds(3.5));
        check(nobody.Link is not null && Snapshot(silent) == silentBefore && silent.Store.Audit(1000).Any(entry => entry.Event == "admin-operation" && entry.Detail.StartsWith("disable-machine; refused", StringComparison.Ordinal)), "sensitive: a passkey page nobody taps ends at its time limit; nothing changes and the refusal is audited");

        // The audit history names every attempt and its outcome and holds no proof.
        string audit = AuditText(app.Store);
        check(audit.Contains("rename-machine; requested", StringComparison.Ordinal) && audit.Contains("rename-machine; authorized", StringComparison.Ordinal) && audit.Contains("rename-machine; applied", StringComparison.Ordinal) && audit.Contains("rename-machine; refused", StringComparison.Ordinal), "sensitive: every attempt and its outcome (requested, refused, authorized, applied) is in the audit history");
        check(!audit.Contains("authenticatorData", StringComparison.Ordinal) && !audit.Contains("clientDataJSON", StringComparison.Ordinal), "sensitive: the audit history holds no proof");
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

        (_, string view, _) = await b.GetAsync("/admin/machines");
        check(view.Contains(display, StringComparison.Ordinal) && view.Contains("Pending", StringComparison.Ordinal) && view.Contains("data-op=\"machine-approve\"", StringComparison.Ordinal) && !view.Contains("data-op=\"machine-trust\"", StringComparison.Ordinal), "machines view: a Pending machine offers approve, with its fingerprint");

        Tapped wrong = await Go("machine-approve", app.Phone, ("fingerprint", fp[..16]), ("name", "dev laptop"));
        check(wrong.ApproveStatus == 403 && store.Find(fp)!.Status == MachineStatus.Pending && !File.Exists(hostConfig.FilePath), "machine approve: a key that is not an admin key is refused (403); nothing changes and nothing is pinned");
        Tapped approved = await Go("machine-approve", app.Laptop, ("fingerprint", fp[..16]), ("name", "dev laptop"));
        check(approved.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => store.Find(fp) is { Status: MachineStatus.Trusted, FriendlyName: "dev laptop" }), "machine approve: the admin key's tap approves the machine");
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
            check(ok.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => store.Find(fp)!.Status == after && (name is null || store.Find(fp)!.FriendlyName == name)) && ok.Page.Contains(phrase, StringComparison.Ordinal) && ok.Page.Contains(display, StringComparison.Ordinal), op + ": the admin tap applies it, and the page named the action and the full fingerprint");
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
        (_, string untrustedView, _) = await b.GetAsync("/admin/machines");
        check(untrustedView.Contains("data-op=\"machine-trust\"", StringComparison.Ordinal) && untrustedView.Contains("full fingerprint", StringComparison.Ordinal), "machines view: an Untrusted machine asks for its full fingerprint to trust it again");
        store.Trust(fp, fp, "test");

        Tapped nameless = await Go("machine-rename", null, ("fingerprint", fp[..20]), ("name", ""));
        check(nameless.Link is null && nameless.PostStatus == 400, "machine rename: an empty name is refused before any page");

        Tapped disable = await Go("machine-disable", app.Laptop, ("fingerprint", fp[..20]));
        check(disable.Page.Contains("disable this machine", StringComparison.Ordinal) && !disable.Page.Contains("enable this machine", StringComparison.Ordinal), "machine functions: the page text names exactly the requested action");
        await HostServiceTests.WaitFor(() => store.Find(fp)!.Status == MachineStatus.Disabled);
        store.Enable(fp, "test");

        // A host name change: the page shows the new name; the tap binds exactly it.
        store.RecordHostMismatch(fp, "other-host");
        (_, string pendingView, _) = await b.GetAsync("/admin/machines");
        check(pendingView.Contains("other-host", StringComparison.Ordinal) && pendingView.Contains("machine-host-change", StringComparison.Ordinal), "machines view: a waiting host name change is shown with its action");
        Tapped hostNoUv = await b.OpAsync("machine-host-change", app.Laptop, false, null, true, ("fingerprint", fp[..20]));
        Tapped hostOther = await b.OpAsync("machine-host-change", app.Laptop, true, challenge => SHA256.HashData(challenge), true, ("fingerprint", fp[..20]));
        Tapped hostPhone = await b.OpAsync("machine-host-change", app.Phone, true, null, true, ("fingerprint", fp[..20]));
        check(hostNoUv.ApproveStatus == 403 && hostOther.ApproveStatus is 403 or 400 && hostPhone.ApproveStatus == 403 && store.Find(fp) is { HostName: "test-host" }, "machine host-change: no user verification, another challenge or a non-admin key each change nothing");
        Tapped host = await Go("machine-host-change", app.Laptop, ("fingerprint", fp[..20]));
        check(host.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => store.Find(fp) is { HostName: "other-host", PendingHostName: null }) && host.Page.Contains("other-host", StringComparison.Ordinal), "machine host-change: the page shows the new name; the tap binds it");

        // A state that changed while the page was open: the stale tap changes nothing.
        Tapped stale = await Go("machine-disable", null, ("fingerprint", fp[..20]));
        store.Disable(fp, "someone else");
        int revision = store.Find(fp)!.SecurityRevision;
        TestState.Approve(app.Http, stale.PageUrl, "http://localhost:" + new Uri(stale.Link!).Port, "localhost", app.Laptop);
        await Task.Delay(500);
        check(store.Find(fp) is { Status: MachineStatus.Disabled } stillDisabled && stillDisabled.SecurityRevision == revision, "machine functions: a machine that changed while the page was open is not changed again by the stale tap");
        store.Enable(fp, "test");

        // A different host name arriving while the page is open is not applied by the tap.
        store.RecordHostMismatch(fp, "shown-name");
        Tapped race = await Go("machine-host-change", null, ("fingerprint", fp[..20]));
        store.RecordHostMismatch(fp, "other-name");
        TestState.Approve(app.Http, race.PageUrl, "http://localhost:" + new Uri(race.Link!).Port, "localhost", app.Laptop);
        await Task.Delay(500);
        check(store.Find(fp) is { HostName: "other-host" }, "machine host-change: a host name that replaced the shown one is not applied by the tap (" + store.Find(fp)!.HostName + ")");

        // Re-pin on an already Trusted machine says so on the page and keeps its name.
        Tapped repin = await Go("machine-approve", app.Laptop, ("fingerprint", fp), ("name", "ignored name"));
        check(repin.ApproveStatus == 200 && repin.Page.Contains("re-pin the authority key", StringComparison.Ordinal) && repin.Page.Contains("already Trusted", StringComparison.Ordinal) && store.Find(fp)!.FriendlyName == "renamed", "machine approve: on a Trusted machine the page says it re-pins the key and the name is not changed");
    }

    // ---- settings, passkeys ----

    private static async Task SettingsAndPasskeys(Action<bool, string> check, string root)
    {
        FakePasskeys fake = new();
        using AdminApp app = new(root, passkeys: fake);
        AdminBrowser b = await app.SignedIn();
        Tapped retention = await b.OpAsync("set-audit-retention", app.Laptop, true, null, true, ("days", "30"));
        check(retention.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => app.Store.AuditRetentionDays() == 30) && retention.Page.Contains("30 days", StringComparison.Ordinal), "settings: the retention changes after its own tap; the page names the number of days");
        Tapped bad = await b.OpAsync("set-audit-retention", app.Laptop, true, null, true, ("days", "-1"));
        Tapped huge = await b.OpAsync("set-audit-retention", app.Laptop, true, null, true, ("days", "999999"));
        Tapped lateIdle = await b.OpAsync("set-session-timeouts", app.Laptop, true, null, true, ("idle", "50"), ("absolute", "10"));
        check(bad.Link is null && huge.Link is null && lateIdle.Link is null && app.Store.AuditRetentionDays() == 30 && app.Store.SessionTimeouts() == (15, 480), "settings: out of range values (and an idle timeout longer than the absolute one) are refused before any page");

        // Passkey administration: its own pages (the existing enrollment ceremony) are the taps; the app only starts them, for a session.
        (_, string passkeys, _) = await b.GetAsync("/admin/passkeys");
        check(passkeys.Contains("data-op=\"passkey-enroll\"", StringComparison.Ordinal) || passkeys.Contains("passkey-enroll", StringComparison.Ordinal), "passkeys view: offers adding a passkey");
        Tapped enroll = await b.OpAsync("passkey-enroll", null);
        check(enroll.Link is not null && fake.Calls.Contains("enroll"), "passkeys: adding one starts the enrollment pages (their own taps)");
        Tapped remove = await b.OpAsync("passkey-unenroll", null, true, null, true, ("name", "phone"));
        check(remove.Link is not null && fake.Calls.Contains("unenroll phone"), "passkeys: removing one starts the removal pages (their own taps)");
        Tapped noName = await b.OpAsync("passkey-unenroll", null, true, null, true, ("name", ""));
        check(noName.Link is null && !fake.Calls.Contains("unenroll "), "passkeys: a removal with no name is refused before any page");
        AdminBrowser anon = app.Browser();
        await anon.LoadAsync();
        int calls = fake.Calls.Count;
        (int s1, _) = await anon.PostAsync("/admin/op", "{\"op\":\"passkey-enroll\"}");
        (int s2, _) = await anon.PostAsync("/admin/op", "{\"op\":\"passkey-unenroll\",\"name\":\"phone\"}");
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
        check(okStatus == 200 && await HostServiceTests.WaitFor(() => app.Store.Find(app.Fingerprint)!.FriendlyName == "two"), "pending: the newest page still works");

        // A flood of starts is limited, and the limit does not stop a lock.
        int refused = 0;
        for (int i = 0; i < 40; i++)
        {
            (int status, _) = await b.PostAsync("/admin/op", "{\"op\":\"machine-rename\",\"fingerprint\":\"" + fp + "\",\"name\":\"" + "n" + i + "\"}");
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
        (int pendingStatus, _) = TestState.Approve(app.Http, pendingRename.PageUrl, "http://localhost:" + new Uri(pendingRename.Link!).Port, "localhost", app.Laptop);
        check(pendingStatus != 200 && app.Store.Find(app.Fingerprint)!.FriendlyName != "will not happen", "pending: the waiting page was closed by the newer request and its tap changes nothing");
        (int lockStatus, _) = TestState.Approve(app.Http, lockPage.PageUrl, "http://localhost:" + new Uri(lockPage.Link!).Port, "localhost", app.Laptop);
        check(lockStatus == 200 && await HostServiceTests.WaitFor(() => app.Service.Lock.IsLocked), "pending: the lock still goes through");

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

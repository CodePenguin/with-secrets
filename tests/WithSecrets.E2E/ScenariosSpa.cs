using Microsoft.Playwright;

namespace WithSecrets.E2E;

/// <summary>
/// Phase 6b-2: the administration single-page application driven in a real browser, against the host service that serves it (embedded in the assembly) and the API from one origin. The admin passkey is the
/// browser's virtual authenticator. A sign-in is one tap and gives a read-only session; every change is the application's own dialog (the exact operation and parameters, then a request for authorization),
/// the tap on the service's one-use passkey page (the link the application offers opens it in a new tab), and then the one mutation that carries the authorization id. These scenarios replace the earlier
/// API-driven browser scenarios (i1 to i4); the API itself is still tested directly, without a browser, in the unit suite (Api).
/// </summary>
internal static class ScenariosSpa
{
    private const string SecretValue = "s3cr3t-e2e-value-1";

    public static async Task SignInAndOut(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using SpaApp app = new(rig);

        IResponse? page = await c.Page.GotoAsync(app.Url);
        s.Check(page is { Status: 200 } && page.Headers.GetValueOrDefault("content-security-policy") == AdminWebAssets.ContentSecurityPolicy, "the application is served from the service's origin with its strict Content-Security-Policy");
        await Spa.Heading(c, "Sign in").WaitForAsync();
        s.Check(await c.PasskeyCalls() == 0, "tap rule: the application itself never asks for a passkey");
        s.Check(await c.Page.GetByRole(AriaRole.Navigation, new() { Name = "Main" }).IsVisibleAsync(), "the navigation is there before sign-in, but no view is: the sign-in takes its place");
        await Spa.Axe(c, s, "sign-in");

        await Spa.Button(c, "Sign in", exact: true).ClickAsync();
        string request = await Spa.Tap(c, s);
        s.Check(request.Contains("start an administrator session", StringComparison.Ordinal) && request.Contains("login:", StringComparison.Ordinal), "the passkey page says what the tap does and carries this login's code");
        await Spa.Heading(c, "Overview").WaitForAsync(new() { Timeout = 20000 });
        s.Check((await c.Page.GetByText("Signed in as").First.TextContentAsync() ?? "").Contains("Signed in as", StringComparison.Ordinal), "signed in: the header says who and until when");
        s.Check(await c.PasskeyCalls() == 0, "tap rule: still no passkey call from the application after the sign-in");
        await Spa.Axe(c, s, "overview");

        s.Check(!(await c.Page.EvaluateAsync<string>("() => document.cookie")).Contains(AdminSessions.SessionCookie, StringComparison.Ordinal), "script cannot read the session cookie (HttpOnly)");
        s.Check(await c.Page.EvaluateAsync<bool>("() => localStorage.length === 0 && sessionStorage.length === 0"), "nothing is kept in localStorage or sessionStorage");
        IReadOnlyList<BrowserContextCookiesResult> cookies = await c.Context.CookiesAsync();
        BrowserContextCookiesResult? session = cookies.FirstOrDefault(cookie => cookie.Name == AdminSessions.SessionCookie);
        s.Check(session is { HttpOnly: true, Path: "/api/v1", SameSite: SameSiteAttribute.Strict }, "the session cookie is HttpOnly, SameSite=Strict and scoped to /api/v1");

        // A reload keeps the session (the cookie), and the address is the view.
        await Spa.GoTo(c, "Machines", "Machines");
        s.Check(c.Page.Url.EndsWith("/admin/machines", StringComparison.Ordinal), "a view is an address (/admin/machines)");
        await c.Page.ReloadAsync();
        await Spa.Heading(c, "Machines").WaitForAsync();
        s.Check(await c.Page.GetByText("Signed in as").First.IsVisibleAsync(), "a reload on a view lands on the same view, still signed in");

        // Sign out ends the session at the service.
        await Spa.Button(c, "Sign out").ClickAsync();
        await Spa.Heading(c, "Sign in").WaitForAsync();
        c.Ignore("401");
        string after = await c.Page.EvaluateAsync<string>("async () => (await fetch('/api/v1/machines')).status + ''");
        s.Check(after == "401", "after sign out the service refuses the views (401)");
        s.NoProblems(c);
    }

    public static async Task ApproveMachine(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using SpaApp app = new(rig);
        using SoftwareSigningKey other = new();
        string fp = KeyIdentity.Fingerprint(other.PublicKey);
        byte[] challenge = await rig.Machine.Deployment.Authority.BeginEnrollmentAsync();
        await rig.Machine.Deployment.Authority.EnrollAsync(EnrollmentRequest.Create("other-host", challenge, other));
        AuthorityStore store = rig.Machine.Deployment.Store;
        s.Check(store.Find(fp) is { Status: MachineStatus.Pending }, "fixture: a second machine is waiting as Pending");
        await Spa.SignIn(c, app, s);
        (_, long signsAfterSignIn) = await c.AuthOps();

        await Spa.GoTo(c, "Machines", "Machines");
        ILocator row = c.Page.GetByRole(AriaRole.Listitem).Filter(new() { HasText = KeyIdentity.Display(fp) });
        await row.WaitForAsync();
        string rowText = await row.TextContentAsync() ?? "";
        s.Check(rowText.Contains("pending", StringComparison.Ordinal) && rowText.Contains("other-host", StringComparison.Ordinal), "the machines view lists the Pending machine with its host name and its status in words");
        await Spa.Axe(c, s, "machines");

        await row.GetByRole(AriaRole.Button, new() { Name = "Approve" }).ClickAsync();
        ILocator dialog = Spa.Dialog(c);
        await dialog.WaitForAsync();
        await dialog.GetByLabel("Friendly name").FillAsync("e2e second");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Review" }).ClickAsync();
        string review = await dialog.TextContentAsync() ?? "";
        s.Check(review.Contains("machine-approve", StringComparison.Ordinal) && review.Contains(fp, StringComparison.Ordinal) && review.Contains("e2e second", StringComparison.Ordinal), "the dialog names the exact operation and every parameter (operation, full fingerprint, name) before anything is asked");
        s.Check(store.Find(fp)!.Status == MachineStatus.Pending && await c.PasskeyCalls() == 0, "nothing is changed and no passkey is asked for in review");
        await Spa.Axe(c, s, "the authorization dialog (review)");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Ask for passkey authorization" }).ClickAsync();
        await dialog.GetByRole(AriaRole.Link, new() { Name = "Open the passkey page" }).WaitForAsync();
        string signed = await dialog.Locator("blockquote").TextContentAsync() ?? "";
        s.Check(signed.Contains("approve this machine", StringComparison.OrdinalIgnoreCase) && signed.Contains("e2e second", StringComparison.Ordinal), "the dialog shows the sentence the passkey signs");
        s.Check(store.Find(fp)!.Status == MachineStatus.Pending, "still Pending while the tap is outstanding (the authorization changes nothing)");
        await Spa.Axe(c, s, "the authorization dialog (waiting for the tap)");

        string page = await Spa.Tap(c, s);
        s.Check(page.Contains("approve this machine", StringComparison.OrdinalIgnoreCase) && page.Contains(KeyIdentity.Display(fp), StringComparison.Ordinal) && page.Contains("e2e second", StringComparison.Ordinal) && page.Contains("Operation: approve-machine", StringComparison.Ordinal), "its own passkey page shows the action, the full fingerprint and the name");
        await dialog.GetByText("Done").First.WaitForAsync(new() { Timeout = 20000 });
        s.Check(store.Find(fp) is { Status: MachineStatus.Trusted, FriendlyName: "e2e second" }, "the tap and its one mutation approve the machine");
        s.Check(store.Audit(100).Any(entry => entry.Event == "machine-approve" && entry.Actor.StartsWith("admin passkey", StringComparison.Ordinal)), "the audit history names the admin passkey that tapped");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Close" }).ClickAsync();
        await dialog.WaitForAsync(new() { State = WaitForSelectorState.Detached });
        await c.Page.GetByRole(AriaRole.Heading, new() { Name = "e2e second" }).WaitForAsync();
        s.Check((await row.TextContentAsync() ?? "").Contains("trusted", StringComparison.Ordinal) || (await c.Page.GetByRole(AriaRole.Listitem).Filter(new() { HasText = "e2e second" }).TextContentAsync() ?? "").Contains("trusted", StringComparison.Ordinal), "the list shows it Trusted under its new name");

        // The next change needs its own tap: a rename is a new authorization, a new passkey page and one more signature.
        (_, long signsAfterApprove) = await c.AuthOps();
        s.Check(signsAfterApprove == signsAfterSignIn + 1, "the approval was exactly one passkey signature");
        ILocator renamed = c.Page.GetByRole(AriaRole.Listitem).Filter(new() { HasText = "e2e second" });
        await renamed.GetByRole(AriaRole.Button, new() { Name = "Rename" }).ClickAsync();
        await dialog.GetByLabel("New name").FillAsync("e2e renamed");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Review" }).ClickAsync();
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Ask for passkey authorization" }).ClickAsync();
        s.Check(store.Find(fp)!.FriendlyName == "e2e second", "the earlier approval does not authorize the rename (it is still the old name before the tap)");
        string renamePage = await Spa.Tap(c, s);
        await dialog.GetByText("Done").First.WaitForAsync(new() { Timeout = 20000 });
        s.Check(renamePage.Contains("e2e renamed", StringComparison.Ordinal) && store.Find(fp)!.FriendlyName == "e2e renamed", "a second change needed a second tap and a new passkey page");
        (_, long signsAfterRename) = await c.AuthOps();
        s.Check(signsAfterRename == signsAfterApprove + 1, "each change is exactly one more passkey signature");
        s.NoProblems(c);
    }

    private static async Task<string> MakeGrant(Ctx c, Rig rig, SpaApp app, S s)
    {
        await Scenarios3.SeedSecret(rig, c);
        File.WriteAllLines(Path.Combine(rig.Work, "check.cmd"), ["@echo off", "echo script-value=%E2E_SECRET%"]);
        CliCommand.Run run = (CliCommand.Run)Cmds.Parse(["--secrets", "E2E_SECRET", "--reason", "e2e grant", "--", "cmd", "/d", "/c", "check.cmd"]);
        using Cmd<int> approve = new((port, o, e) => LaunchClient.RunAsync(run.Args, rig.Work, app.Service.Port, port, o, e, rig.Machine.Trust, approve: true).GetAwaiter().GetResult());
        await c.Page.GotoAsync(await approve.LinkAsync());
        await c.TextAppears("#request");
        await c.Page.Locator("#reuse").SelectOptionAsync(new SelectOptionValue { Index = 1 });
        await c.Click("#approve-for");
        await c.StatusContains("Approved");
        s.Check(await approve.Result.WaitAsync(TimeSpan.FromSeconds(30)) == 0, "fixture: a grant was made from the approval page");

        return rig.Machine.Deployment.Store.Grants().Single().Id;
    }

    public static async Task RevokeGrant(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using SpaApp app = new(rig);
        string id = await MakeGrant(c, rig, app, s);
        AuthorityStore store = rig.Machine.Deployment.Store;
        await Spa.SignIn(c, app, s);
        await Spa.GoTo(c, "Grants", "Grants");
        ILocator row = c.Page.GetByRole(AriaRole.Listitem).Filter(new() { HasText = id });
        await row.WaitForAsync();
        string text = await row.TextContentAsync() ?? "";
        s.Check(text.Contains("active", StringComparison.Ordinal) && text.Contains("E2E_SECRET", StringComparison.Ordinal) && text.Contains("Program", StringComparison.Ordinal) && text.Contains("cmd", StringComparison.Ordinal), "the grants view lists the grant with its state, the secret NAMES and the program (" + System.Text.RegularExpressions.Regex.Replace(text, @"\s+", " ") + ")");
        s.Check(!(await c.Page.ContentAsync()).Contains(SecretValue, StringComparison.Ordinal), "no secret value is anywhere in the page");
        await Spa.Axe(c, s, "grants");

        await row.GetByRole(AriaRole.Button, new() { Name = "Revoke" }).ClickAsync();
        ILocator dialog = Spa.Dialog(c);
        await dialog.WaitForAsync();
        s.Check(await dialog.GetByRole(AriaRole.Button, new() { Name = "Ask for passkey authorization" }).IsVisibleAsync() && (await dialog.TextContentAsync() ?? "").Contains("grant-revoke", StringComparison.Ordinal) && (await dialog.TextContentAsync() ?? "").Contains(id, StringComparison.Ordinal), "the dialog names the revocation and the grant before anything is asked");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Ask for passkey authorization" }).ClickAsync();
        s.Check(store.FindGrant(id) is { Status: "active" }, "nothing changed before the tap");
        string page = await Spa.Tap(c, s);
        await dialog.GetByText("Done").First.WaitForAsync(new() { Timeout = 20000 });
        s.Check(page.Contains("revoke this grant", StringComparison.OrdinalIgnoreCase) && page.Contains(id, StringComparison.Ordinal) && page.Contains("Operation: revoke-grant", StringComparison.Ordinal), "its own passkey page names the revocation and the grant");
        s.Check(store.FindGrant(id) is { Status: "revoked" }, "the tap and its one mutation revoke the grant");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Close" }).ClickAsync();
        await row.GetByText("revoked").First.WaitForAsync(new() { Timeout = 20000 });
        s.Check(await row.GetByRole(AriaRole.Button).CountAsync() == 0, "the revoked grant offers no further action");
        s.NoProblems(c);
    }

    public static async Task AuditSearch(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        await Scenarios3.SeedSecret(rig, c);
        File.WriteAllLines(Path.Combine(rig.Work, "check.cmd"), ["@echo off", "echo script-value=%E2E_SECRET%"]);
        using SpaApp app = new(rig);
        CliCommand.Run run = (CliCommand.Run)Cmds.Parse(["--secrets", "E2E_SECRET", "--reason", "e2e audit", "--", "cmd", "/d", "/c", "check.cmd"]);
        using (Cmd<int> cmd = new((port, o, e) => LaunchClient.RunAsync(run.Args, rig.Work, app.Service.Port, port, o, e, rig.Machine.Trust).GetAwaiter().GetResult()))
        {
            await c.Page.GotoAsync(await cmd.LinkAsync());
            await c.TextAppears("#request");
            await c.Click("#approve");
            s.Check(await cmd.Result.WaitAsync(TimeSpan.FromSeconds(30)) == 0, "fixture: a run was approved and ran");
        }

        await Spa.SignIn(c, app, s);
        await Spa.GoTo(c, "Audit", "Audit");
        // The host uploads its events a moment after the run.
        ILocator results = c.Page.GetByRole(AriaRole.List, new() { Name = "Host events" });
        bool found = false;
        for (int i = 0; i < 30 && !found; i++)
        {
            await c.Page.GetByLabel("Contains text").FillAsync("check.cmd");
            await c.Page.GetByRole(AriaRole.Button, new() { Name = "Search", Exact = true }).ClickAsync();
            try
            {
                await results.GetByText("check.cmd").First.WaitForAsync(new() { Timeout = 1500 });
                found = true;
            }
            catch (Exception)
            {
                // Not uploaded yet (a timeout).
            }

            if (!found)
            {
                await Task.Delay(1000);
            }
        }

        s.Check(found, "the audit view shows the run's events once the host has uploaded them");
        string all = await results.TextContentAsync() ?? "";
        s.Check(all.Contains("approved", StringComparison.Ordinal) && all.Contains("started", StringComparison.Ordinal) && !all.Contains(SecretValue, StringComparison.Ordinal), "it shows the authorization and launch outcomes and no secret value");
        s.Check(c.Page.Url.Contains("text=check.cmd", StringComparison.Ordinal), "the search is in the address");
        await Spa.Axe(c, s, "audit events");

        await c.Page.GetByLabel("Kind of event").SelectOptionAsync("launch");
        await c.Page.GetByRole(AriaRole.Button, new() { Name = "Search", Exact = true }).ClickAsync();
        await c.Page.WaitForFunctionAsync("() => location.search.includes('type=launch')");
        await c.Page.GetByRole(AriaRole.Status).Filter(new() { HasText = "found" }).First.WaitForAsync();
        string narrowed = await results.TextContentAsync() ?? "";
        s.Check(narrowed.Contains("launch:", StringComparison.Ordinal) && !narrowed.Contains("authorization:", StringComparison.Ordinal), "the kind filter narrows the events to the launch");

        // A reload keeps the search (it is in the address).
        await c.Page.ReloadAsync();
        await Spa.Heading(c, "Audit").WaitForAsync();
        s.Check(await c.Page.GetByLabel("Contains text").InputValueAsync() == "check.cmd" && await c.Page.GetByLabel("Kind of event").InputValueAsync() == "launch", "a reload keeps the search");

        await c.Page.GetByLabel("Contains text").FillAsync("nothing-like-this");
        await c.Page.GetByRole(AriaRole.Button, new() { Name = "Search", Exact = true }).ClickAsync();
        await c.Page.GetByText("No events found.").WaitForAsync();
        s.Check(true, "a search with no match says so");
        await c.Page.GetByRole(AriaRole.Link, new() { Name = "Authority changes" }).ClickAsync();
        await c.Page.GetByRole(AriaRole.List, new() { Name = "Authority changes" }).WaitForAsync();
        s.Check(true, "the authority's own change history is a view of its own");
        await Spa.Axe(c, s, "audit changes");
        await c.Page.GetByRole(AriaRole.Link, new() { Name = "Numbering gaps" }).ClickAsync();
        await c.Page.GetByText("No open gap").WaitForAsync();
        await Spa.Axe(c, s, "audit gaps");
        s.NoProblems(c);
    }

    public static async Task LockUnlock(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using SpaApp app = new(rig);
        await Spa.SignIn(c, app, s);
        s.Check(!app.Service.Lock.IsLocked && await c.Page.GetByText("Authority unlocked").First.IsVisibleAsync(), "the header says the authority is unlocked");

        await Spa.Button(c, "Lock the authority").ClickAsync();
        ILocator dialog = Spa.Dialog(c);
        await dialog.WaitForAsync();
        s.Check((await dialog.TextContentAsync() ?? "").Contains("every signed-in session ends", StringComparison.OrdinalIgnoreCase), "the dialog warns that every session ends");
        c.Ignore("401");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Ask for passkey authorization" }).ClickAsync();
        await Spa.Tap(c, s);
        await dialog.GetByText("Done").First.WaitForAsync(new() { Timeout = 20000 });
        s.Check(app.Service.Lock.IsLocked, "the tap and its one mutation lock the authority");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Close" }).ClickAsync();
        await Spa.Heading(c, "Sign in").WaitForAsync(new() { Timeout = 20000 });
        s.Check(await c.Page.GetByText("The authority is locked").First.IsVisibleAsync(), "the locked authority is said in words on the sign-in view, which offers the unlock");
        await Spa.Axe(c, s, "sign-in while locked");

        // Unlock needs its own authorization but no session.
        await Spa.Button(c, "Unlock the authority").ClickAsync();
        await dialog.WaitForAsync();
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Ask for passkey authorization" }).ClickAsync();
        string page = await Spa.Tap(c, s);
        await dialog.GetByText("Done").First.WaitForAsync(new() { Timeout = 20000 });
        s.Check(!app.Service.Lock.IsLocked, "the tap and its one mutation unlock the authority, with no session");
        s.Check(page.Contains("unlock", StringComparison.OrdinalIgnoreCase), "the passkey page names the unlock (" + page.Split('\n')[0] + ")");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Close" }).ClickAsync();
        await c.Page.GetByText("Authority unlocked").First.WaitForAsync(new() { Timeout = 20000 });

        // The session ended with the lock: signing in again is a new tap.
        await Spa.Button(c, "Sign in", exact: true).ClickAsync();
        await Spa.Tap(c, s);
        await Spa.Heading(c, "Overview").WaitForAsync(new() { Timeout = 20000 });
        s.Check(true, "after the unlock a new sign-in starts a new read-only session");
        s.NoProblems(c);
    }

    public static async Task Settings(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using SpaApp app = new(rig);
        AuthorityStore store = rig.Machine.Deployment.Store;
        await Spa.SignIn(c, app, s);
        await Spa.GoTo(c, "Settings", "Settings");
        await Spa.Axe(c, s, "settings");
        int before = store.AuditRetentionDays();

        await Spa.Button(c, "Change audit retention").ClickAsync();
        ILocator dialog = Spa.Dialog(c);
        await dialog.WaitForAsync();
        ILocator days = dialog.GetByLabel("Days to keep audit events");
        await days.FillAsync("abc");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Review" }).ClickAsync();
        ILocator error = dialog.GetByRole(AriaRole.Alert);
        await error.WaitForAsync();
        s.Check((await error.TextContentAsync() ?? "").Contains("whole number", StringComparison.Ordinal) && await days.GetAttributeAsync("aria-invalid") == "true", "an invalid value is refused on the field, announced as an alert, and the field is marked invalid");
        await Spa.Axe(c, s, "the dialog with a validation error");
        await days.FillAsync("30");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Review" }).ClickAsync();
        string review = await dialog.TextContentAsync() ?? "";
        s.Check(review.Contains("set-audit-retention", StringComparison.Ordinal) && review.Contains("days", StringComparison.Ordinal) && review.Contains("30", StringComparison.Ordinal), "the review names the operation and the new value");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Ask for passkey authorization" }).ClickAsync();
        s.Check(store.AuditRetentionDays() == before, "the setting is unchanged until the tap");
        string page = await Spa.Tap(c, s);
        await dialog.GetByText("Done").First.WaitForAsync(new() { Timeout = 20000 });
        s.Check(store.AuditRetentionDays() == 30, "the tap and its one mutation change the setting");
        s.Check(page.Contains("30", StringComparison.Ordinal), "the passkey page shows the new value");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Close" }).ClickAsync();
        await c.Page.GetByText("30 days", new() { Exact = true }).WaitForAsync();
        s.Check(true, "the settings view shows the new retention");
        s.NoProblems(c);
    }

    public static async Task RefusedWithoutAuthorization(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using SpaApp app = new(rig);
        using SoftwareSigningKey other = new();
        string fp = KeyIdentity.Fingerprint(other.PublicKey);
        byte[] challenge = await rig.Machine.Deployment.Authority.BeginEnrollmentAsync();
        await rig.Machine.Deployment.Authority.EnrollAsync(EnrollmentRequest.Create("other-host", challenge, other));
        AuthorityStore store = rig.Machine.Deployment.Store;
        List<string> mutations = [];
        c.Page.Request += (_, request) =>
        {
            if (request.Method != "GET")
            {
                mutations.Add(request.Method + " " + new Uri(request.Url).AbsolutePath);
            }
        };
        await Spa.SignIn(c, app, s);
        await Spa.GoTo(c, "Machines", "Machines");

        // In the application: asking for the authorization and not tapping changes nothing, and no mutation is sent.
        ILocator row = c.Page.GetByRole(AriaRole.Listitem).Filter(new() { HasText = KeyIdentity.Display(fp) });
        await row.GetByRole(AriaRole.Button, new() { Name = "Approve" }).ClickAsync();
        ILocator dialog = Spa.Dialog(c);
        await dialog.GetByLabel("Friendly name").FillAsync("");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Review" }).ClickAsync();
        s.Check((await dialog.GetByRole(AriaRole.Alert).TextContentAsync() ?? "").Contains("Enter a friendly name", StringComparison.Ordinal), "a pending machine cannot be approved without a name: refused on the field before anything is asked");
        await dialog.GetByLabel("Friendly name").FillAsync("e2e untapped");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Review" }).ClickAsync();
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Ask for passkey authorization" }).ClickAsync();
        await dialog.GetByRole(AriaRole.Link, new() { Name = "Open the passkey page" }).WaitForAsync();
        await Task.Delay(2500);
        s.Check(!mutations.Any(item => item.Contains("/approve", StringComparison.Ordinal)) && store.Find(fp)!.Status == MachineStatus.Pending, "without the tap the application sends no mutation and the machine stays Pending (it waits, with no limit of its own)");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Cancel" }).ClickAsync();
        await dialog.WaitForAsync(new() { State = WaitForSelectorState.Detached });
        s.Check(store.Find(fp)!.Status == MachineStatus.Pending && !mutations.Any(item => item.Contains("/approve", StringComparison.Ordinal)), "cancelling changes nothing");

        // At the server: a script in the page (as a compromised page would) with the session, the anti-forgery value and the right Origin, but no tap.
        c.Ignore("403");
        c.Ignore("400");
        c.Ignore("Content Security Policy");
        string result = await c.Page.EvaluateAsync<string>("""
            async (fingerprint) => {
              const who = await (await fetch('/api/v1/session')).json();
              const send = async (path, body) => {
                const r = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Admin-Token': who.antiForgery }, body: JSON.stringify(body) });
                const j = await r.json();
                return r.status + ' ' + j.code;
              };
              return [
                await send('/api/v1/machines/' + fingerprint + '/approve', { authorization: 'AAAAAAAAAAAA', name: 'sneaky' }),
                await send('/api/v1/lock', { authorization: 'AAAAAAAAAAAA' }),
                await send('/api/v1/machines/' + fingerprint + '/approve', { name: 'no-authorization-member' }),
              ].join(' | ');
            }
            """, fp);
        string[] parts = result.Split(" | ");
        s.Check(parts[0] == "403 authorization-invalid" && parts[1] == "403 authorization-invalid" && parts.Length == 3 && parts[2].StartsWith("4", StringComparison.Ordinal), "the server refuses a change with a session and no valid authorization (" + result + ")");
        s.Check(store.Find(fp)!.Status == MachineStatus.Pending && !app.Service.Lock.IsLocked, "nothing was changed by those attempts");

        // And a change from another origin is refused whatever it carries.
        string cross = await c.Page.EvaluateAsync<string>("""
            async () => {
              try {
                const r = await fetch('http://127.0.0.1:' + location.port + '/api/v1/lock', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
                return 'status ' + r.status;
              } catch (e) { return 'blocked: ' + e.name; }
            }
            """);
        s.Check(cross.StartsWith("blocked", StringComparison.Ordinal), "the page's own Content-Security-Policy (connect-src 'self') stops it sending anything to another origin (" + cross + ")");
        s.NoProblems(c);
    }

    public static async Task Accessibility(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using SpaApp app = new(rig);
        using SoftwareSigningKey other = new();
        byte[] challenge = await rig.Machine.Deployment.Authority.BeginEnrollmentAsync();
        await rig.Machine.Deployment.Authority.EnrollAsync(EnrollmentRequest.Create("other-host", challenge, other));
        await Spa.SignIn(c, app, s);

        string[] views = ["Overview", "Machines", "Grants", "Audit", "Settings", "Passkeys"];
        foreach ((string width, int w, int h) in new[] { ("desktop", 1280, 800), ("tablet", 768, 1024), ("phone", 375, 667), ("200% zoom on a phone (320 CSS px wide)", 320, 568), ("400% zoom on a desktop (320 CSS px wide)", 320, 256) })
        {
            await c.Page.SetViewportSizeAsync(w, h);
            foreach (string view in views)
            {
                await Spa.GoTo(c, view, view);
                await c.Page.WaitForLoadStateAsync(LoadState.NetworkIdle);
                bool overflow = await c.Page.EvaluateAsync<bool>("() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1");
                s.Check(!overflow, $"no horizontal scrolling on {view} at {width}");
                if (w is 1280 or 320)
                {
                    await Spa.Axe(c, s, $"{view} at {width}");
                }
            }
        }

        // Touch targets: every button and link of a view is at least 24 CSS px (WCAG 2.2) in both directions; ours are 44.
        await c.Page.SetViewportSizeAsync(375, 667);
        await Spa.GoTo(c, "Machines", "Machines");
        int small = await c.Page.EvaluateAsync<int>("() => [...document.querySelectorAll('main a, main button, nav a, header button')].filter(e => { const r = e.getBoundingClientRect(); return r.width > 0 && (r.width < 44 || r.height < 44); }).length");
        s.Check(small == 0, "every control is at least 44 by 44 CSS px on a phone (" + small + " smaller)");

        // Dark scheme and reduced motion.
        await c.Page.SetViewportSizeAsync(1280, 800);
        await c.Page.EmulateMediaAsync(new() { ColorScheme = ColorScheme.Dark, ReducedMotion = ReducedMotion.Reduce });
        foreach (string view in new[] { "Overview", "Machines", "Settings" })
        {
            await Spa.GoTo(c, view, view);
            await Spa.Axe(c, s, $"{view} in the dark scheme");
        }

        string duration = await c.Page.EvaluateAsync<string>("() => getComputedStyle(document.querySelector('main button, nav a')).transitionDuration");
        s.Check(duration.StartsWith("1e-05", StringComparison.Ordinal) || duration.StartsWith("0.00001", StringComparison.Ordinal) || duration == "0s", "reduced motion removes transitions (" + duration + ")");
        await c.Page.EmulateMediaAsync(new() { ColorScheme = ColorScheme.Light, ReducedMotion = ReducedMotion.NoPreference });

        // Keyboard only: the skip link, the navigation, a dialog (focus inside, Escape closes it, focus returns).
        await c.Page.ReloadAsync();
        await Spa.Heading(c, "Settings").WaitForAsync();
        await c.Page.Keyboard.PressAsync("Tab");
        string first = await c.Page.EvaluateAsync<string>("() => document.activeElement.textContent.trim()");
        s.Check(first.StartsWith("Skip to the main content", StringComparison.Ordinal), "the first Tab stop is the skip link");
        bool visible = await c.Page.EvaluateAsync<bool>("() => document.activeElement.getBoundingClientRect().top >= 0");
        s.Check(visible, "the skip link is visible when focused");
        await c.Page.Keyboard.PressAsync("Enter");
        await c.Page.Keyboard.PressAsync("Tab");
        s.Check(await c.Page.EvaluateAsync<bool>("() => !!document.activeElement.closest('main')"), "after the skip link, Tab continues inside the main content");

        await Spa.GoTo(c, "Machines", "Machines");
        ILocator approve = c.Page.GetByRole(AriaRole.Button, new() { Name = "Approve" }).First;
        await approve.FocusAsync();
        await c.Page.Keyboard.PressAsync("Enter");
        ILocator dialog = Spa.Dialog(c);
        await dialog.WaitForAsync();
        s.Check(await c.Page.EvaluateAsync<bool>("() => !!document.activeElement.closest('dialog')"), "opening a dialog by keyboard puts focus inside it");
        bool trapped = true;
        for (int i = 0; i < 10; i++)
        {
            await c.Page.Keyboard.PressAsync("Tab");
            // Inside the dialog, or out of the document altogether (the browser's own controls); never an element of the page behind it.
            trapped &= await c.Page.EvaluateAsync<bool>("() => document.activeElement === document.body || !!document.activeElement.closest('dialog')");
        }

        s.Check(trapped, "Tab never reaches the page behind the dialog (it is inert)");
        await c.Page.Keyboard.PressAsync("Escape");
        await dialog.WaitForAsync(new() { State = WaitForSelectorState.Detached });
        string back = await c.Page.EvaluateAsync<string>("() => document.activeElement.textContent.trim()");
        s.Check(back.StartsWith("Approve", StringComparison.Ordinal), "Escape closes the dialog and focus returns to the control that opened it (" + back + ")");

        // Visible focus: the focused element has an outline.
        await c.Page.Keyboard.PressAsync("Tab");
        string outline = await c.Page.EvaluateAsync<string>("() => getComputedStyle(document.activeElement).outlineStyle + ' ' + getComputedStyle(document.activeElement).outlineWidth");
        s.Check(outline.StartsWith("solid 3px", StringComparison.Ordinal), "the focused control has a visible 3 px outline (" + outline + ")");

        // Text scaling: the root font size follows the person's setting (rem units), so a larger text size reflows without loss.
        string rootSize = await c.Page.EvaluateAsync<string>("() => getComputedStyle(document.documentElement).fontSize");
        s.Check(rootSize == "16px", "text is sized from the browser's own setting (" + rootSize + ")");
        s.NoProblems(c);
    }
}

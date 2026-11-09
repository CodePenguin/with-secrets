namespace WithSecrets.E2E;

/// <summary>
/// Phase 6a: the admin web app in a real browser. The admin passkey is the browser's virtual authenticator. A session starts with one tap and reads only; every change opens its own
/// one-use passkey page (the tap is on that page, never on the app's page).
/// </summary>
internal static class ScenariosAdmin
{
    private sealed class App : IDisposable
    {
        public App(Rig rig)
        {
            Service = HostService.Start(new HostServiceOptions { Lock = AuthorityLock.UnlockedForTests(), State = rig.State, Store = rig.Store, Grants = rig.Grants, Deployment = rig.Machine.Deployment, Port = 0 });
            Home = $"http://localhost:{Service.Port}/admin";
        }

        public HostService Service { get; }

        public string Home { get; }

        public void Dispose() => Service.Dispose();
    }

    /// <summary>The sign-in: Sign in on the status page, the passkey page of this login (one tap), and the return to the app.</summary>
    private static async Task SignIn(Ctx c, App app, S s)
    {
        await c.Page.GotoAsync(app.Home);
        s.Check(await c.Page.Locator("#login").CountAsync() == 1 && await c.Page.Locator("nav a[href='/admin/machines']").CountAsync() == 0, "the status page offers only the sign-in; no view is listed before it");
        await c.Click("#login");
        string request = await c.TextAppears("#request");
        s.Check(request.Contains("start an administrator session") && request.Contains("login:"), "the sign-in page says what the tap does and carries this login's code (" + request.Split('\n')[0] + ")");
        s.Check(await c.PasskeyCalls() == 0, "tap rule: no passkey prompt on load of the sign-in page");
        await c.Click("#approve");
        await c.StatusContains("Approved");
        await c.Page.GotoAsync(app.Home);
        await c.Page.WaitForSelectorAsync(".who", new() { Timeout = 10000 });
    }

    public static async Task Login(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using App app = new(rig);
        await SignIn(c, app, s);
        string who = await c.Text(".who");
        s.Check(who.Contains("read-only session"), "signed in: the page says the session is read-only (" + who + ")");
        IReadOnlyList<Microsoft.Playwright.BrowserContextCookiesResult> cookies = await c.Context.CookiesAsync();
        Microsoft.Playwright.BrowserContextCookiesResult? session = cookies.FirstOrDefault(cookie => cookie.Name == AdminSessions.SessionCookie);
        s.Check(session is { HttpOnly: true, SameSite: Microsoft.Playwright.SameSiteAttribute.Strict } && session.Path == "/admin", "the session cookie is HttpOnly, SameSite=Strict and scoped to /admin");
        string visible = await c.Page.EvaluateAsync<string>("() => document.cookie");
        s.Check(!visible.Contains(AdminSessions.SessionCookie, StringComparison.Ordinal) && !(await c.Page.ContentAsync()).Contains(session!.Value, StringComparison.Ordinal), "script cannot read the session cookie and it is on no page");
        await c.Page.GotoAsync(app.Home + "/machines");
        s.Check((await c.Text("#machines")).Contains(KeyIdentity.Display(rig.Machine.Deployment.Fingerprint)[..19]) && (await c.Text("#machines")).Contains("Trusted"), "the machines view shows the machine and its status");
        s.Check(rig.Machine.Deployment.Store.Audit(100).Any(entry => entry.Event == "admin-operation" && entry.Detail.StartsWith("admin-session; started", StringComparison.Ordinal)), "the session start is in the authority's audit history");

        // Sign out ends it: the views need a new sign-in.
        await c.Page.GotoAsync(app.Home);
        await c.Click("#logout");
        await c.Page.WaitForSelectorAsync("#login", new() { Timeout = 10000 });
        c.Ignore("status of 401");
        Microsoft.Playwright.IResponse? after = await c.Page.GotoAsync(app.Home + "/machines");
        s.Check(after?.Status == 401, "after sign out the machines view is refused (401)");
        s.NoProblems(c);
    }

    public static async Task ApproveMachine(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using App app = new(rig);
        using SoftwareSigningKey other = new();
        string fp = KeyIdentity.Fingerprint(other.PublicKey);
        byte[] challenge = await rig.Machine.Deployment.Authority.BeginEnrollmentAsync();
        await rig.Machine.Deployment.Authority.EnrollAsync(EnrollmentRequest.Create("other-host", challenge, other));
        AuthorityStore store = rig.Machine.Deployment.Store;
        s.Check(store.Find(fp) is { Status: MachineStatus.Pending }, "fixture: a second machine is waiting as Pending");
        await SignIn(c, app, s);
        await c.Page.GotoAsync(app.Home + "/machines");
        string row = $"tr[data-fingerprint='{fp}']";
        s.Check((await c.Text(row)).Contains("Pending"), "the machines view lists the Pending machine");
        await c.Page.FillAsync(row + " input[name=name]", "e2e second");
        await c.Click(row + " button[data-op=machine-approve]");
        string request = await c.TextAppears("#request");
        s.Check(request.Contains("approve this machine") && request.Contains(KeyIdentity.Display(fp)) && request.Contains("e2e second") && request.Contains("Operation: approve-machine"), "its own passkey page shows the action, the full fingerprint and the name");
        s.Check(await c.PasskeyCalls() == 0 && store.Find(fp)!.Status == MachineStatus.Pending, "tap rule: nothing is asked or changed before the tap");
        await c.Click("#approve");
        await c.StatusContains("Approved");
        await Task.Delay(500);
        s.Check(store.Find(fp) is { Status: MachineStatus.Trusted, FriendlyName: "e2e second" }, "the tap approves the machine");
        await c.Page.GotoAsync(app.Home + "/machines");
        s.Check((await c.Text(row)).Contains("Trusted"), "the machines view now shows it Trusted");
        s.Check(store.Audit(100).Any(entry => entry.Event == "machine-approve" && entry.Actor.StartsWith("admin passkey", StringComparison.Ordinal)), "the audit history names the admin passkey that tapped");
        s.NoProblems(c);
    }

    private static async Task<string> MakeGrant(Ctx c, Rig rig, App app, S s)
    {
        await Scenarios3.SeedSecret(rig, c);
        File.WriteAllLines(Path.Combine(rig.Work, "check.cmd"), ["@echo off", "echo script-value=%E2E_SECRET%"]);
        CliCommand.Run run = (CliCommand.Run)Cmds.Parse(["--secrets", "E2E_SECRET", "--reason", "e2e grant", "--", "cmd", "/d", "/c", "check.cmd"]);
        using Cmd<int> approve = new((port, o, e) => LaunchClient.RunAsync(run.Args, rig.Work, app.Service.Port, port, o, e, rig.Machine.Trust, approve: true).GetAwaiter().GetResult());
        await c.Page.GotoAsync(await approve.LinkAsync());
        await c.TextAppears("#request");
        await c.Page.Locator("#reuse").SelectOptionAsync(new Microsoft.Playwright.SelectOptionValue { Index = 1 });
        await c.Click("#approve-for");
        await c.StatusContains("Approved");
        s.Check(await approve.Result.WaitAsync(TimeSpan.FromSeconds(30)) == 0, "fixture: a grant was made from the approval page");
        GrantRecord grant = rig.Machine.Deployment.Store.Grants().Single();

        return grant.Id;
    }

    public static async Task GrantRevoke(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using App app = new(rig);
        string id = await MakeGrant(c, rig, app, s);
        AuthorityStore store = rig.Machine.Deployment.Store;
        await SignIn(c, app, s);
        await c.Page.GotoAsync(app.Home + "/grants");
        string row = $"tr[data-grant='{id}']";
        string text = await c.Text(row);
        s.Check(text.Contains("active") && text.Contains("E2E_SECRET") && text.Contains("cmd"), "the grants view lists the grant with its state, secret names and program (" + text.Replace('\n', ' ')[..Math.Min(200, text.Length)] + ")");
        await c.Click(row + " button[data-op=grant-revoke]");
        string request = await c.TextAppears("#request");
        s.Check(request.Contains("revoke this grant") && request.Contains(id) && request.Contains("Operation: revoke-grant"), "its own passkey page names the revocation and the grant");
        s.Check(store.FindGrant(id) is { Status: "active" }, "nothing changed before the tap");
        await c.Click("#approve");
        await c.StatusContains("Approved");
        await Task.Delay(800);
        s.Check(store.FindGrant(id) is { Status: "revoked" }, "the tap revokes the grant");
        await c.Page.GotoAsync(app.Home + "/grants");
        s.Check((await c.Text(row)).Contains("revoked") && await c.Page.Locator(row + " button[data-op=grant-revoke]").CountAsync() == 0, "the grants view shows it revoked, with no further action");
        s.NoProblems(c);
    }

    public static async Task AuditSearch(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        await Scenarios3.SeedSecret(rig, c);
        File.WriteAllLines(Path.Combine(rig.Work, "check.cmd"), ["@echo off", "echo script-value=%E2E_SECRET%"]);
        using App app = new(rig);
        CliCommand.Run run = (CliCommand.Run)Cmds.Parse(["--secrets", "E2E_SECRET", "--reason", "e2e audit", "--", "cmd", "/d", "/c", "check.cmd"]);
        using (Cmd<int> cmd = new((port, o, e) => LaunchClient.RunAsync(run.Args, rig.Work, app.Service.Port, port, o, e, rig.Machine.Trust).GetAwaiter().GetResult()))
        {
            await c.Page.GotoAsync(await cmd.LinkAsync());
            await c.TextAppears("#request");
            await c.Click("#approve");
            s.Check(await cmd.Result.WaitAsync(TimeSpan.FromSeconds(30)) == 0, "fixture: a run was approved and ran");
        }

        await SignIn(c, app, s);
        bool found = false;
        for (int i = 0; i < 30 && !found; i++)
        {
            await c.Page.GotoAsync(app.Home + "/audit");
            found = (await c.Text("#events")).Contains("check.cmd");
            if (!found)
            {
                await Task.Delay(1000);
            }
        }

        s.Check(found, "the audit view shows the run's events once the host has uploaded them");
        string all = await c.Text("#events");
        s.Check(all.Contains("approved") && all.Contains("started") && !all.Contains("s3cr3t-e2e-value-1"), "it shows the authorization and launch outcomes and no secret value");
        await c.Page.FillAsync("input[name=text]", "check.cmd");
        await c.Page.SelectOptionAsync("select[name=type]", "launch");
        await c.Click("#audit-filter button[type=submit]");
        await c.Page.WaitForURLAsync("**/admin/audit?*");
        string filtered = await c.Text("#events");
        s.Check(filtered.Contains("launch") && !filtered.Contains("authorization"), "the type and text filters narrow the events to the launch");
        await c.Page.GotoAsync(app.Home + "/audit?text=nothing-like-this");
        s.Check((await c.Text("#no-events")).Contains("No audit events match"), "a search with no match says so");
        await c.Page.GotoAsync(app.Home + "/audit?gaps=1");
        s.Check((await c.Page.ContentAsync()).Contains("No open gaps") || await c.Page.Locator("#gaps").CountAsync() == 1, "the gap view is available");
        s.NoProblems(c);
    }
}

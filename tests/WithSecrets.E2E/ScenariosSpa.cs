using Microsoft.Playwright;

namespace WithSecrets.E2E;

/// <summary>
/// The administration single-page application driven in a real browser, against the host service and API from one origin. The admin passkey is the
/// browser's virtual authenticator. Sign-in and every change prepare a service-owned challenge; a final user gesture invokes WebAuthn directly in the SPA. The service applies its retained operation only after verification. These scenarios replace the earlier
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
        s.Check(page is { Status: 200 } && page.Headers.GetValueOrDefault("content-security-policy") == AdminWebAssets.ContentSecurityPolicy && page.Headers.GetValueOrDefault("permissions-policy") == "camera=(), microphone=(), geolocation=(), publickey-credentials-get=(self), publickey-credentials-create=()", "the application is served with a strict same-origin policy that enables passkey retrieval only in this page");
        await Spa.Heading(c, "Sign in").WaitForAsync();
        s.Check(await c.PasskeyCalls() == 0, "tap rule: the application itself never asks for a passkey");
        s.Check(await c.Page.GetByRole(AriaRole.Navigation, new() { Name = "Main" }).IsVisibleAsync(), "the navigation is there before sign-in, but no view is: the sign-in takes its place");
        await Spa.Axe(c, s, "sign-in");

        await Spa.Button(c, "Sign in", exact: true).ClickAsync();
        await Spa.Tap(c, s);
        await Spa.Heading(c, "Overview").WaitForAsync(new() { Timeout = 20000 });
        s.Check((await c.Page.GetByText("Signed in as").First.TextContentAsync() ?? "").Contains("Signed in as", StringComparison.Ordinal), "signed in: the header says who and until when");
        s.Check(await c.PasskeyCalls() == 1, "sign-in invokes exactly one in-page WebAuthn request");
        await Spa.Axe(c, s, "overview");

        s.Check(!(await c.Page.EvaluateAsync<string>("() => document.cookie")).Contains(AdminSessions.SessionCookie, StringComparison.Ordinal), "script cannot read the session cookie (HttpOnly)");
        s.Check(await c.Page.EvaluateAsync<bool>("() => localStorage.length === 0 && Object.keys(sessionStorage).every((key) => key === 'ws.session-secret' || key === 'ws.browser-secret')"), "nothing is kept in localStorage, and sessionStorage holds only the two secrets the service gave once");
        s.Check(!(await c.Page.ContentAsync()).Contains((await c.Page.EvaluateAsync<string>("() => sessionStorage.getItem('ws.session-secret') ?? ''")), StringComparison.Ordinal), "the secret is in no page text");
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
        List<string> mutations = [];
        c.Page.Request += (_, request) =>
        {
            if (request.Method != "GET")
            {
                mutations.Add(request.Method + " " + new Uri(request.Url).AbsolutePath);
            }
        };
        await Spa.SignIn(c, app, s);
        (_, long signsAfterSignIn) = await c.AuthOps();

        await Spa.GoTo(c, "Machines", "Machines");
        ILocator row = c.Page.GetByRole(AriaRole.Listitem).Filter(new() { HasText = KeyIdentity.Display(fp) });
        await row.WaitForAsync();
        string rowText = await row.TextContentAsync() ?? "";
        s.Check(rowText.Contains("pending", StringComparison.Ordinal) && rowText.Contains("other-host", StringComparison.Ordinal), "the machines view lists the Pending machine with its host name and its status in words");
        s.Check(await c.Page.GetByRole(AriaRole.Region, new() { Name = "A machine paired and is waiting for you" }).CountAsync() == 1 && await c.Page.GetByRole(AriaRole.Listitem).Filter(new() { HasText = KeyIdentity.Display(fp) }).CountAsync() == 1, "the paired machine is shown once, as the card that asks to check its fingerprint and host name");
        await Spa.Axe(c, s, "machines");

        // Approving a machine: review, prepare the challenge, then confirm with one in-page WebAuthn gesture.
        mutations.Clear();
        Spa.Clicks = 0;
        await Spa.Click(row.GetByRole(AriaRole.Button, new() { Name = "Approve" }));
        ILocator dialog = Spa.Dialog(c);
        await dialog.WaitForAsync();
        s.Check(await dialog.GetByLabel("Friendly name").InputValueAsync() == "other-host", "the friendly name starts as the host name the machine reported");
        await dialog.GetByLabel("Friendly name").FillAsync("e2e second");
        int callsBefore = await c.PasskeyCalls();
        s.Check(store.Find(fp)!.Status == MachineStatus.Pending && callsBefore == 1 && !mutations.Any(), "nothing is changed and WebAuthn is not requested before challenge preparation");
        await Spa.Axe(c, s, "the authorization dialog (form)");
        IPage passkeyPage = await Spa.OpenPasskeyPage(c, s, dialog);
        await dialog.GetByText("Review before confirming").WaitForAsync();
        string review = await dialog.TextContentAsync() ?? "";
        s.Check(review.Contains("Approve machine " + KeyIdentity.Display(fp), StringComparison.Ordinal) && review.Contains("e2e second", StringComparison.Ordinal), "after browser Back, the dialog identifies the pending change by action and friendly name");
        s.Check(store.Find(fp)!.Status == MachineStatus.Pending, "still Pending while the tap is outstanding (the authorization changes nothing)");
        await Spa.Axe(c, s, "the authorization dialog (waiting for the tap)");

        string page = await Spa.TapAfterBack(c, s, passkeyPage, null);
        s.Check(page.Contains("approve this machine", StringComparison.OrdinalIgnoreCase) && page.Contains(KeyIdentity.Display(fp), StringComparison.Ordinal) && page.Contains("e2e second", StringComparison.Ordinal), "the SPA result retains the approved action, fingerprint and name");
        await dialog.GetByText("Done").First.WaitForAsync(new() { Timeout = 20000 });
        s.Check(store.Find(fp) is { Status: MachineStatus.Trusted, FriendlyName: "e2e second" }, "the tap approves the machine (the service made the change when the tap was verified)");
        s.Check(Spa.Clicks == 3, "approval took three intentional clicks: open, prepare, and confirm (" + Spa.Clicks + ")");
        s.Check(await c.PasskeyCalls() == callsBefore + 1 && mutations.Count == 2 && mutations[0] == "POST /api/v1/authorizations/inline" && new Uri(c.Page.Url).AbsolutePath.StartsWith("/admin", StringComparison.Ordinal) && mutations[1].StartsWith("POST /api/v1/authorizations/", StringComparison.Ordinal) && mutations[1].EndsWith("/proof", StringComparison.Ordinal), "challenge preparation and assertion submission stay inside the SPA without a separate operation endpoint (" + string.Join(", ", mutations) + ")");
        s.Check(store.Audit(100).Any(entry => entry.Event == "machine-approve" && entry.Actor.StartsWith("admin passkey", StringComparison.Ordinal)), "the audit history names the admin passkey that tapped");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Close" }).ClickAsync();
        await dialog.WaitForAsync(new() { State = WaitForSelectorState.Detached });
        await c.Page.GetByRole(AriaRole.Heading, new() { Name = "e2e second" }).WaitForAsync();
        s.Check((await row.TextContentAsync() ?? "").Contains("trusted", StringComparison.Ordinal) || (await c.Page.GetByRole(AriaRole.Listitem).Filter(new() { HasText = "e2e second" }).TextContentAsync() ?? "").Contains("trusted", StringComparison.Ordinal), "the list shows it Trusted under its new name");

        // The next change needs its own challenge and a new assertion.
        (_, long signsAfterApprove) = await c.AuthOps();
        s.Check(signsAfterApprove == signsAfterSignIn + 1, "the approval was exactly one passkey signature");
        ILocator renamed = c.Page.GetByRole(AriaRole.Listitem).Filter(new() { HasText = "e2e second" });
        Spa.Clicks = 0;
        await Spa.Click(renamed.GetByRole(AriaRole.Button, new() { Name = "Rename" }));
        await dialog.GetByLabel("New name").FillAsync("e2e renamed");
        IPage renamePageTab = await Spa.OpenPasskeyPage(c, s, dialog);
        await dialog.GetByText("Review before confirming").WaitForAsync();
        s.Check(store.Find(fp)!.FriendlyName == "e2e second", "the earlier approval does not authorize the rename (it is still the old name before the tap)");
        string renamePage = await Spa.TapAfterBack(c, s, renamePageTab, null);
        await dialog.GetByText("Done").First.WaitForAsync(new() { Timeout = 20000 });
        s.Check(renamePage.Contains("e2e renamed", StringComparison.Ordinal) && store.Find(fp)!.FriendlyName == "e2e renamed", "a second change needed its own assertion and was applied by the service");
        s.Check(Spa.Clicks == 3, "an administrative rename took three clicks: open, prepare, and confirm (" + Spa.Clicks + ")");
        (_, long signsAfterRename) = await c.AuthOps();
        s.Check(signsAfterRename == signsAfterApprove + 1, "each change is exactly one more passkey signature");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Close" }).ClickAsync();
        await dialog.WaitForAsync(new() { State = WaitForSelectorState.Detached });

        // Cancelling the browser's pending passkey prompt leaves the operation unapplied.
        using SoftwareSigningKey refusedKey = new();
        byte[] refusedChallenge = await rig.Machine.Deployment.Authority.BeginEnrollmentAsync();
        await rig.Machine.Deployment.Authority.EnrollAsync(EnrollmentRequest.Create("refused-host", refusedChallenge, refusedKey));
        string refusedFp = KeyIdentity.Fingerprint(refusedKey.PublicKey);
        ILocator refusedRow = c.Page.GetByRole(AriaRole.Listitem).Filter(new() { HasText = KeyIdentity.Display(refusedFp) });
        await refusedRow.GetByRole(AriaRole.Button, new() { Name = "Approve" }).ClickAsync();
        await dialog.GetByLabel("Friendly name").FillAsync("refused host");
        IPage failedPage = await Spa.OpenPasskeyPage(c, s, dialog);
        await c.Presence(false);
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Confirm this change" }).ClickAsync();
        await Task.Delay(100);
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Cancel the request" }).ClickAsync();
        await dialog.GetByRole(AriaRole.Alert).WaitForAsync(new() { Timeout = 20000 });
        string passkeyFailure = await dialog.GetByRole(AriaRole.Alert).TextContentAsync() ?? "";
        s.Check(passkeyFailure.Contains("cancel", StringComparison.OrdinalIgnoreCase) && store.Find(refusedFp) is { Status: MachineStatus.Pending }, "cancelling WebAuthn in the same SPA reports cancellation and changes nothing");
        await c.Presence(true);
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Close" }).ClickAsync();
        await dialog.WaitForAsync(new() { State = WaitForSelectorState.Detached });
        s.Check(store.Find(refusedFp) is { Status: MachineStatus.Pending }, "after cancelling the passkey prompt and closing the dialog the machine remains Pending");
        s.NoProblems(c);
    }

    /// <summary>The tap is never lost: the application tab is reloaded after the passkey page was opened but before the tap, and again right after the tap; the change is made once, by the service, and the page reads the outcome.</summary>
    public static async Task ReloadBetweenTapAndResult(Host host, S s)
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
        mutations.Clear();
        await Spa.GoTo(c, "Machines", "Machines");
        ILocator dialog = Spa.Dialog(c);
        int approvesBefore = store.Audit(200).Count(entry => entry.Event == "machine-approve");

        // 1. Reload while the passkey page waits for its tap: the application finds the waiting authorization again, and shows what the tap came to.
        await Spa.Click(c.Page.GetByRole(AriaRole.Listitem).Filter(new() { HasText = KeyIdentity.Display(fp) }).GetByRole(AriaRole.Button, new() { Name = "Approve" }));
        await dialog.GetByLabel("Friendly name").FillAsync("reloaded one");
        IPage passkeyPage = await Spa.OpenPasskeyPage(c, s, dialog);
        await dialog.GetByText("Review before confirming").WaitForAsync();
        await c.Page.ReloadAsync();
        await dialog.GetByText("Review before confirming").WaitForAsync(new() { Timeout = 20000 });
        s.Check(store.Find(fp)!.Status == MachineStatus.Pending, "after the reload the machine is still Pending (no tap yet)");
        s.Check(await c.Page.EvaluateAsync<bool>("() => Object.keys(sessionStorage).every((key) => ['ws.session-secret', 'ws.browser-secret', 'ws.pending-authorization'].includes(key)) && !sessionStorage.getItem('ws.pending-authorization').includes('http') && localStorage.length === 0"), "the tab keeps only the id and the title of the waiting authorization (no link, no parameter), and nothing in localStorage");
        await Spa.TapAfterBack(c, s, passkeyPage, null);
        await dialog.GetByText("Done").First.WaitForAsync(new() { Timeout = 20000 });
        s.Check(store.Find(fp) is { Status: MachineStatus.Trusted, FriendlyName: "reloaded one" }, "the tap made after the reload approved the machine: the service made the change, the page only read the outcome");
        s.Check(mutations.Count(item => item == "POST /api/v1/authorizations/inline") == 1 && mutations.Count(item => item.EndsWith("/proof", StringComparison.Ordinal)) == 1 && !mutations.Any(item => item.Contains("/approve", StringComparison.Ordinal)), "the SPA only prepared and submitted the assertion; it sent no operation mutation before or after reload (" + string.Join(", ", mutations) + ")");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Close" }).ClickAsync();
        s.Check(await c.Page.EvaluateAsync<bool>("() => sessionStorage.getItem('ws.pending-authorization') === null"), "the waiting record is gone when the result was seen");

        // 2. Reload right after the tap (the tab never saw the result): the change is made, once, and the page never offers it again.
        await Spa.Click(c.Page.GetByRole(AriaRole.Listitem).Filter(new() { HasText = "reloaded one" }).GetByRole(AriaRole.Button, new() { Name = "Rename" }));
        await dialog.GetByLabel("New name").FillAsync("reloaded two");
        await Spa.Continue(c, s, dialog);
        await c.Page.ReloadAsync();
        await Spa.Heading(c, "Machines").WaitForAsync();
        await c.Page.GetByRole(AriaRole.Heading, new() { Name = "reloaded two" }).WaitForAsync(new() { Timeout = 20000 });
        s.Check(store.Find(fp)!.FriendlyName == "reloaded two", "a reload right after the tap loses nothing: the rename was made by the service");
        s.Check(store.Audit(200).Count(entry => entry.Event == "machine-approve") == approvesBefore + 1 && store.Audit(200).Count(entry => entry.Event == "machine-rename") == 1, "each change is in the audit once (" + string.Join(", ", store.Audit(200).Select(entry => entry.Event)) + ")");
        s.NoProblems(c);
    }

    public static async Task AcceptHostName(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using SpaApp app = new(rig);
        using SoftwareSigningKey other = new();
        string fp = KeyIdentity.Fingerprint(other.PublicKey);
        byte[] challenge = await rig.Machine.Deployment.Authority.BeginEnrollmentAsync();
        await rig.Machine.Deployment.Authority.EnrollAsync(EnrollmentRequest.Create("laptop-old", challenge, other));
        AuthorityStore store = rig.Machine.Deployment.Store;
        store.Approve(fp, "travel laptop", "e2e fixture");
        store.RecordHostMismatch(fp, "laptop-new");
        int revision = store.Find(fp)!.SecurityRevision;
        s.Check(store.Find(fp) is { Status: MachineStatus.Trusted, HostName: "laptop-old", PendingHostName: "laptop-new" }, "fixture: a Trusted machine reports a new host name, which is only recorded as waiting");
        await Spa.SignIn(c, app, s);
        (_, long signsAfterSignIn) = await c.AuthOps();

        await Spa.GoTo(c, "Machines", "Machines");
        ILocator row = c.Page.GetByRole(AriaRole.Listitem).Filter(new() { HasText = "travel laptop" });
        await row.WaitForAsync();
        string text = await row.TextContentAsync() ?? "";
        s.Check(text.Contains("New host name reported", StringComparison.Ordinal) && text.Contains("laptop-old", StringComparison.Ordinal) && text.Contains("laptop-new", StringComparison.Ordinal), "the machines view shows the enrolled and the reported host name and says a new name was reported");
        await Spa.Axe(c, s, "machines with a reported host name");

        await row.GetByRole(AriaRole.Button, new() { Name = "Accept host name" }).ClickAsync();
        ILocator dialog = Spa.Dialog(c);
        await dialog.WaitForAsync();
        string review = await dialog.TextContentAsync() ?? "";
        s.Check(review.Contains("machine-host-change", StringComparison.Ordinal) && review.Contains("laptop-new", StringComparison.Ordinal) && review.Contains(fp, StringComparison.Ordinal), "the dialog names the exact operation, the machine and the host name that would be accepted");
        s.Check(store.Find(fp) is { HostName: "laptop-old" } && await c.PasskeyCalls() == 1, "nothing changed and WebAuthn was not invoked before the final confirmation");
        string page = await Spa.Continue(c, s, dialog);
        await dialog.GetByText("Done").First.WaitForAsync(new() { Timeout = 20000 });
        s.Check(page.Contains("laptop-new", StringComparison.Ordinal) && page.Contains(KeyIdentity.Display(fp), StringComparison.Ordinal), "the result dialog confirms the accepted host name and identifies its machine");
        s.Check(store.Find(fp) is { HostName: "laptop-new", PendingHostName: null } done && done.SecurityRevision == revision, "the tap binds the new host name and leave the security revision alone");
        (_, long signs) = await c.AuthOps();
        s.Check(signs == signsAfterSignIn + 1, "exactly one passkey signature");
        s.Check(store.History(fp).Any(entry => entry.Kind == "host-name-mismatch") && store.Audit(100).Any(entry => entry.Actor.StartsWith("admin passkey", StringComparison.Ordinal) && entry.Detail.Contains("laptop-new", StringComparison.Ordinal)), "the history records the mismatch and the audit names the admin passkey that accepted the name");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Close" }).ClickAsync();
        await dialog.WaitForAsync(new() { State = WaitForSelectorState.Detached });
        s.Check(await row.GetByText("New host name reported").CountAsync() == 0, "the warning is gone from the list");
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
        s.Check(await dialog.GetByRole(AriaRole.Button, new() { Name = "Prepare confirmation" }).IsVisibleAsync() && (await dialog.TextContentAsync() ?? "").Contains("grant-revoke", StringComparison.Ordinal) && (await dialog.TextContentAsync() ?? "").Contains(id, StringComparison.Ordinal), "the dialog names the revocation and the grant before challenge preparation");
        s.Check(store.FindGrant(id) is { Status: "active" }, "nothing changed before the tap");
        string page = await Spa.Continue(c, s, dialog);
        await dialog.GetByText("Done").First.WaitForAsync(new() { Timeout = 20000 });
        s.Check(page.Contains("revoke this grant", StringComparison.OrdinalIgnoreCase) && page.Contains(id, StringComparison.Ordinal), "the result dialog retains the revocation and grant details");
        s.Check(store.FindGrant(id) is { Status: "revoked" }, "the tap revokes the grant");
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
        await c.Page.GetByRole(AriaRole.Status).Filter(new() { HasText = "Showing" }).First.WaitForAsync();
        string narrowed = await results.TextContentAsync() ?? "";
        for (int attempt = 0; attempt < 20 && (narrowed.Contains("authorization:", StringComparison.Ordinal) || !narrowed.Contains("launch:", StringComparison.Ordinal)); attempt++)
        {
            // The status line that says "found" is also there from the search before: wait for the list itself to be the narrowed one.
            await Task.Delay(500);
            narrowed = await results.TextContentAsync() ?? "";
        }

        s.Check(narrowed.Contains("launch:", StringComparison.Ordinal) && !narrowed.Contains("authorization:", StringComparison.Ordinal), "the kind filter narrows the events to the launch");

        // A reload keeps the search (it is in the address).
        await c.Page.ReloadAsync();
        await Spa.Heading(c, "Audit").WaitForAsync();
        s.Check(await c.Page.GetByLabel("Contains text").InputValueAsync() == "check.cmd" && await c.Page.GetByLabel("Kind of event").InputValueAsync() == "launch", "a reload keeps the search");

        await c.Page.GetByLabel("Contains text").FillAsync("nothing-like-this");
        await c.Page.GetByRole(AriaRole.Button, new() { Name = "Search", Exact = true }).ClickAsync();
        await c.Page.GetByText("No events match these filters.").WaitForAsync();
        s.Check(true, "a search with no match says so");
        await c.Page.GetByRole(AriaRole.Link, new() { Name = "Authority changes" }).ClickAsync();
        await c.Page.GetByRole(AriaRole.List, new() { Name = "Authority changes" }).WaitForAsync();
        s.Check(true, "the authority's own change history is a view of its own");
        await Spa.Axe(c, s, "audit changes");
        await c.Page.GetByRole(AriaRole.Link, new() { Name = "Numbering gaps" }).ClickAsync();
        await c.Page.GetByText("No numbering anomaly matches this filter.").WaitForAsync();
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
        c.Ignore("404");
        await Spa.Continue(c, s, dialog);
        await dialog.GetByText("Done").First.WaitForAsync(new() { Timeout = 20000 });
        s.Check(app.Service.Lock.IsLocked, "the tap locks the authority");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Close" }).ClickAsync();
        await Spa.Heading(c, "Sign in").WaitForAsync(new() { Timeout = 20000 });
        s.Check(await c.Page.GetByText("The authority is locked").First.IsVisibleAsync(), "the locked authority is said in words on the sign-in view, which offers the unlock");
        await Spa.Axe(c, s, "sign-in while locked");

        // Unlock needs its own authorization but no session.
        await Spa.Button(c, "Unlock the authority").ClickAsync();
        await dialog.WaitForAsync();
        string page = await Spa.Continue(c, s, dialog);
        await dialog.GetByText("Done").First.WaitForAsync(new() { Timeout = 20000 });
        s.Check(!app.Service.Lock.IsLocked, "the tap unlocks the authority, with no session");
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
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Prepare confirmation" }).ClickAsync();
        ILocator error = dialog.GetByRole(AriaRole.Alert);
        await error.WaitForAsync();
        s.Check((await error.TextContentAsync() ?? "").Contains("whole number", StringComparison.Ordinal) && await days.GetAttributeAsync("aria-invalid") == "true", "an invalid value is refused on the field, announced as an alert, and the field is marked invalid");
        await Spa.Axe(c, s, "the dialog with a validation error");
        await days.FillAsync("30");
        IPage passkeyPage = await Spa.OpenPasskeyPage(c, s, dialog);
        await dialog.GetByText("Review before confirming").WaitForAsync();
        string review = await dialog.TextContentAsync() ?? "";
        s.Check(review.Contains("Keep audit events for 30 days", StringComparison.Ordinal), "after browser Back, the dialog names the pending retention change");
        s.Check(store.AuditRetentionDays() == before, "the setting is unchanged until the tap");
        string page = await Spa.TapAfterBack(c, s, passkeyPage, null);
        await dialog.GetByText("Done").First.WaitForAsync(new() { Timeout = 20000 });
        s.Check(store.AuditRetentionDays() == 30, "the tap changes the setting");
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
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Prepare confirmation" }).ClickAsync();
        s.Check((await dialog.GetByRole(AriaRole.Alert).TextContentAsync() ?? "").Contains("Enter a friendly name", StringComparison.Ordinal), "a pending machine cannot be approved without a name: refused on the field before anything is asked");
        await dialog.GetByLabel("Friendly name").FillAsync("e2e untapped");
        IPage passkeyPage = await Spa.OpenPasskeyPage(c, s, dialog);
        await dialog.GetByText("Review before confirming").WaitForAsync();
        await Task.Delay(2500);
        s.Check(!mutations.Any(item => item.Contains("/approve", StringComparison.Ordinal)) && store.Find(fp)!.Status == MachineStatus.Pending, "without the tap the application sends no mutation and the machine stays Pending (it waits, with no limit of its own)");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Cancel the request" }).ClickAsync();
        await dialog.WaitForAsync(new() { State = WaitForSelectorState.Detached });
        s.Check(store.Find(fp)!.Status == MachineStatus.Pending && !mutations.Any(item => item.Contains("/approve", StringComparison.Ordinal)), "cancelling changes nothing");

        // At the server: a script in the page (as a compromised page would) with the session, its secret and the right Origin, but no tap.
        c.Ignore("403");
        c.Ignore("400");
        c.Ignore("Content Security Policy");
        string result = await c.Page.EvaluateAsync<string>("""
            async (fingerprint) => {
              const secret = sessionStorage.getItem('ws.session-secret');
              const send = async (path, body) => {
                const r = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Admin-Token': secret }, body: JSON.stringify(body) });
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

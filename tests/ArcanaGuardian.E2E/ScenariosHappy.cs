using Microsoft.Playwright;

namespace ArcanaGuardian.E2E;

/// <summary>
/// The whole happy path in one run: set up the authority, sign in, store a secret, approve an agent's run, allow repeat runs,
/// add a second machine, read the audit history, then lock and unlock.
/// </summary>
internal static class ScenariosHappy
{
    private const string SecretValue = "s3cr3t-e2e-value-1";

    public static async Task HappyPath(Host host, S s)
    {
        if (PlatformSkip.NoServerTls13("a second host pairing with the authority"))
        {
            return;
        }

        using Rig rig = new(trusted: false);
        await using Ctx c = await Ctx.NewAsync(host);
        AuthorityStore store = rig.Machine.Deployment.Store;

        using SpaApp app = new(rig, unlocked: false, machineEndpoint: true, timeLimit: TimeSpan.FromSeconds(20));
        await ScenariosQuickStart.Start(rig, c, app, s);

        // 3. Store a secret: name, value, one passkey tap. The value is sealed in the browser and never shown again.
        await Spa.Click(c.Page.GetByRole(AriaRole.Link, new() { Name = "Secrets", Exact = true }));
        await c.DemoPressAsync(Spa.Button(c, "Add secret", exact: true), "Choose Add secret.");
        await Spa.Click(Spa.Button(c, "Add secret", exact: true));
        await c.Page.GetByLabel("Name").FillAsync("E2E_SECRET");
        await c.Page.GetByLabel("Value").FillAsync(SecretValue);
        await c.DemoPressAsync(Spa.Button(c, "Save secret", exact: true), "Enter a name and value, then choose Save secret and confirm with your passkey.");
        await Spa.Click(Spa.Button(c, "Save secret", exact: true));
        await c.Page.GetByText("Saved E2E_SECRET.").First.WaitForAsync(new() { Timeout = 20000 });
        await c.DemoCaptionAsync("The secret is stored. Only its name is listed.");
        s.Check(rig.Store.ListNames().SequenceEqual(["E2E_SECRET"]), "the secret is stored under its name");

        // 4. An agent runs a command with the secret: the command line prints a link, the person reviews the request and approves once.
        rig.WriteScript("check", "script-value");
        using (Cmd<int> run = Cmds.Run(rig, "E2E_SECRET", Rig.ScriptCommand("check"), app: app))
        {
            await c.DemoCaptionAsync("Run a command that requests the secret. The terminal prints a link to review it.");
            await ReviewWaiting(c, run, app, s, Rig.ScriptFile("check"));
            await Spa.ShowRequestVariants(c, s);
            await c.DemoCaptionAsync("The request shows what would run and which secrets it would get. Approve asks for one tap.");
            await Spa.ApproveOnce(c);
            s.Check(await run.Result.WaitAsync(TimeSpan.FromSeconds(30)) == 0 && run.Out.Text.Contains("script-value=" + StreamRedactor.Mask), "the approved run got the secret and its output was redacted");
            await c.Page.GetByText("Approved.").First.WaitForAsync(new() { Timeout = 20000 });
            await c.DemoCaptionAsync("Approved. The command ran with the secret; its output is redacted.");
        }

        // 5. Turn the completed one-time approval into permission to repeat the same command.
        GrantRecord once = store.Grants().Single(grant => grant.Usage == GrantUsage.Once && grant.Status == "consumed");
        ILocator grants = c.Page.GetByRole(AriaRole.Table, new() { Name = "Grants", Exact = true });
        ILocator used = grants.GetByRole(AriaRole.Row).Filter(new() { HasText = once.Id });
        ILocator viewGrant = used.GetByRole(AriaRole.Button);
        await viewGrant.WaitForAsync(new() { Timeout = 20000 });
        s.Check(await used.GetByText("Used once", new() { Exact = true }).IsVisibleAsync(), "the approved run appears as used once in Grants");
        await c.DemoPressAsync(viewGrant, "The approved request is listed in Grants. Select its row to open the details.");
        await Spa.Click(viewGrant);
        ILocator dialog = Spa.Dialog(c);
        ILocator allowRepeat = dialog.GetByRole(AriaRole.Button, new() { Name = "Allow repeat runs" });
        await c.DemoPressAsync(allowRepeat, "Choose Allow repeat runs to extend the same grant.");
        await Spa.Click(allowRepeat);
        ILocator choice = c.Page.GetByRole(AriaRole.Menuitem, new() { Name = "7 days", Exact = true });
        await c.DemoPressAsync(choice, "Choose a duration. Selecting it starts the passkey prompt.");
        int taps = await c.PasskeyCalls();
        await Spa.Click(choice);
        await Spa.PageFeedback(c).GetByText($"Extended grant {once.Id} for 7 days.").WaitForAsync(new() { Timeout = 20000 });
        GrantRecord reusable = store.Grants().Single();
        s.Check(reusable.Id == once.Id && reusable.Usage == GrantUsage.Reusable && reusable.Revision == once.Revision + 1
            && reusable.Expires > reusable.Updated.AddDays(6), "repeat runs extend the existing grant to a seven-day duration");
        s.Check(await dialog.CountAsync() == 0 && await c.PasskeyCalls() == taps + 1, "the duration choice starts one passkey prompt and success is shown on the page");
        await grants.GetByRole(AriaRole.Button, new() { Name = "View grant " + reusable.Id }).WaitForAsync(new() { Timeout = 20000 });
        await c.DemoSnapAsync("The original grant now allows repeat runs for seven days. The confirmation is on the page.");

        // The existing grant covers the first matching run while the authority is unlocked.
        using (Cmd<int> again = Cmds.Run(rig, "E2E_SECRET", Rig.ScriptCommand("check"), app: app))
        {
            int exit = await again.Result.WaitAsync(TimeSpan.FromSeconds(30));
            s.Check(exit == 0 && again.Out.Text.Contains("script-value=" + StreamRedactor.Mask), "the first run under the grant goes through without asking (exit " + exit + ": " + again.Err.Text.Replace('\n', ' ') + ")");
            await c.DemoCaptionAsync("The next run of that command went through without asking.");
        }

        // 5b. The same choice on a normal run: once, or a time. A time runs it now and lets it run again without asking.
        rig.WriteScript("timed", "timed-value");
        using (Cmd<int> timed = Cmds.Run(rig, "E2E_SECRET", Rig.ScriptCommand("timed"), app: app))
        {
            await c.DemoCaptionAsync("Approve runs it once. The arrow offers a time or Always, which also lets it run again without asking.");
            await ReviewWaiting(c, timed, app, s, Rig.ScriptFile("timed"));
            await Spa.ApproveFor(c, "Approve always");
            int exit = await timed.Result.WaitAsync(TimeSpan.FromSeconds(30));
            s.Check(exit == 0 && timed.Out.Text.Contains("timed-value=" + StreamRedactor.Mask) && store.Grants().Count(grant => grant.Usage == GrantUsage.Reusable) == 2 && store.Grants().Count(grant => grant.Usage == GrantUsage.Reusable && grant.Expires is null) == 1, "a run approved as Always ran, and made a grant with no end (exit " + exit + ": " + timed.Err.Text.Replace('\n', ' ') + ")");
            await c.Page.GetByText("can run it now and again at any time").First.WaitForAsync(new() { Timeout = 20000 });
        }

        await Spa.GoTo(c, "Access", "Access");
        await c.DemoCaptionAsync("Find active grants under Access. Use Revoke to end a grant.");

        // 6. Add a machine: an invitation, the second machine pairs, the person approves it.
        await Spa.GoTo(c, "Machines", "Machines");
        await c.DemoCaptionAsync("To connect a second machine, choose Add a machine and confirm to create a one-time invitation.");
        await Spa.Click(Spa.Button(c, "Add a machine"));
        await dialog.WaitForAsync();
        IPage invitationPage = await Spa.OpenPasskeyPage(c, s, dialog);
        await Spa.TapAfterBack(c, s, invitationPage, null);
        ILocator box = dialog.Locator("textarea#pairing-bundle");
        await box.WaitForAsync(new() { Timeout = 20000 });
        string bundleText = await box.InputValueAsync();
        PairingBundle? bundle = PairingBundle.TryParse(bundleText);
        await c.DemoCaptionAsync("The invitation is shown once. The person copies it to the new machine, where it runs: using-secrets pair.");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Close" }).ClickAsync();
        await dialog.WaitForAsync(new() { State = WaitForSelectorState.Detached });

        string folder = Path.Combine(rig.Folder, "paired-host");
        using SoftwareSigningKey machineKey = new();
        Dictionary<int, SoftwareSigningKey> authorityKeys = [];
        using LocalDeployment hostDeployment = LocalDeployment.Create(folder, machineKey, generation => authorityKeys.TryGetValue(generation, out SoftwareSigningKey? key) ? key : authorityKeys[generation] = new SoftwareSigningKey(), "paired-host");
        PairingResult paired = await PairingClient.RunAsync(new PairingClientOptions
        {
            Bundle = bundle!,
            MachineKey = machineKey,
            IdentityCertificate = hostDeployment.IdentityCertificate,
            HostName = "paired-host",
            HostConfig = hostDeployment.HostConfig,
            MachineTls = hostDeployment.Tls,
        });
        string fp = KeyIdentity.Fingerprint(machineKey.PublicKey);
        s.Check(paired.Ok && store.Find(fp) is { Status: MachineStatus.Pending }, "the second machine paired and waits for approval (" + (paired.Ok ? "paired" : paired.Message) + ")");
        ILocator row = c.Page.GetByRole(AriaRole.Region, new() { Name = "A machine paired and is waiting for you" }).GetByRole(AriaRole.Row).Filter(new() { HasText = KeyIdentity.Display(fp) });
        await row.WaitForAsync(new() { Timeout = 45000 });
        await c.DemoPressAsync(row.GetByRole(AriaRole.Button), "Invitations are listed first. Select the new machine in the table below.");
        await Spa.Click(row.GetByRole(AriaRole.Button));
        await c.DemoPressAsync(dialog.GetByRole(AriaRole.Button, new() { Name = "Approve" }), "Compare the fingerprint and host name, then choose Approve.");
        await Spa.Click(dialog.GetByRole(AriaRole.Button, new() { Name = "Approve" }));
        await dialog.WaitForAsync();
        IPage approvePage = await Spa.OpenPasskeyPage(c, s, dialog);
        await Spa.TapAfterBack(c, s, approvePage, null);
        await Spa.PageFeedback(c).WaitForAsync(new() { Timeout = 20000 });
        s.Check(store.Find(fp) is { Status: MachineStatus.Trusted }, "the approval makes the machine trusted");
        await c.DemoCaptionAsync("The machine is trusted and can now ask for secrets.");

        // 7. The audit history.
        await Spa.GoTo(c, "Audit", "Audit");
        await c.DemoCaptionAsync("Audit shows recorded changes and runs, including who approved them.");

        // 8. Lock and unlock.
        await Spa.GoTo(c, "Overview", "Overview");
        await Spa.Button(c, "Lock the authority").ClickAsync();
        await dialog.WaitForAsync();
        await c.DemoCaptionAsync("Lock the authority from Overview. It ends every session and stops secret delivery until you unlock it.");
        c.Ignore("401");
        c.Ignore("404");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Lock", Exact = true }).ClickAsync();
        await Spa.PageFeedback(c).GetByText("The authority is locked.").WaitForAsync(new() { Timeout = 20000 });
        s.Check(app.Service.Lock.IsLocked, "the session locks the authority");
        await c.DemoCaptionAsync("The authority is locked.");
        await Spa.Heading(c, "Overview").WaitForAsync(new() { Timeout = 20000 });
        await Spa.Button(c, "Unlock the authority").ClickAsync();
        await dialog.WaitForAsync();
        await Spa.Continue(c, s, dialog);
        await Spa.PageFeedback(c).WaitForAsync(new() { Timeout = 20000 });
        s.Check(!app.Service.Lock.IsLocked, "the tap unlocks the authority");
        await c.Page.GetByText("Authority unlocked").First.WaitForAsync(new() { Timeout = 20000 });
        await c.DemoCaptionAsync("Unlocked. Sign in again to continue.");

        List<string> events = [.. AuditChecks.Events(rig)];
        s.Check(new[] { "setup", "secrets-set", "authorization-approved", "authorization-granted", "key-enrolled" }.Take(4).All(events.Contains), "the audit holds the setup, the secret, the approval and the grant (" + string.Join(", ", events) + ")");
        s.NoProblems(c);
    }

    private static async Task ReviewWaiting(Ctx c, Cmd<int> run, SpaApp app, S s, string script)
    {
        string link = await run.LinkAsync();
        s.Check(link.StartsWith(app.Url + "/access/", StringComparison.Ordinal), "the terminal links to the same request shown in the queue");
        await Spa.GoTo(c, "Access", "Access", capture: false);
        ILocator review = c.Page.GetByRole(AriaRole.Table, new() { Name = "Run requests" })
            .Locator("a[href=\"" + new Uri(link).AbsolutePath + "\"]");
        await review.WaitForAsync(new() { Timeout = 20000 });
        s.Check((await review.TextContentAsync())?.Contains(script, StringComparison.Ordinal) == true, "the queue names the script rather than just its shell");
        await c.DemoPressAsync(review, "Under Waiting for you, check the requesting machine and time left, then select the command to review it.");
        await Spa.Click(review);
        await c.Page.GetByRole(AriaRole.Dialog, new() { Name = "Run request from" }).WaitForAsync(new() { Timeout = 20000 });
        await c.DemoSnapAsync("The request opens over Access with the command, secrets, and reason.");
    }
}

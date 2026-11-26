using Microsoft.Playwright;

namespace WithSecrets.E2E;

/// <summary>
/// The whole happy path in one run, as a person lives it: set up the authority, sign in, store a secret, approve an agent's run, give a
/// pre-approval and see a run go through without asking, add a second machine, read the audit history, then lock and unlock.
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
        await c.DemoCaptionAsync("Open Secrets and enter a name and value for the secret your command will need.");
        await c.Page.GetByLabel("Name").FillAsync("E2E_SECRET");
        await c.Page.GetByLabel("Value").FillAsync(SecretValue);
        await c.DemoCaptionAsync("Save secret asks for one passkey tap.");
        await Spa.Click(Spa.Button(c, "Save secret", exact: true));
        await c.Page.GetByText("Saved E2E_SECRET.").First.WaitForAsync(new() { Timeout = 20000 });
        await c.DemoCaptionAsync("The secret is stored. Only its name is listed.");
        s.Check(rig.Store.ListNames().SequenceEqual(["E2E_SECRET"]), "the secret is stored under its name");

        // 4. An agent runs a command with the secret: the command line prints a link, the person reviews the request and approves once.
        rig.WriteScript("check", "script-value");
        using (Cmd<int> run = Cmds.Run(rig, "E2E_SECRET", Rig.ScriptCommand("check"), app: app))
        {
            await c.DemoCaptionAsync("Run a command that requests the secret. The terminal prints a link to review it.");
            await Spa.OpenRequest(c, run, app, s);
            await Spa.ShowRequestVariants(c, s);
            await c.DemoCaptionAsync("The request shows what would run and which secrets it would get. Approve asks for one tap.");
            await Spa.ApproveOnce(c);
            s.Check(await run.Result.WaitAsync(TimeSpan.FromSeconds(30)) == 0 && run.Out.Text.Contains("script-value=" + StreamRedactor.Mask), "the approved run got the secret and its output was redacted");
            await c.Page.GetByText("Approved.").First.WaitForAsync(new() { Timeout = 20000 });
            await c.DemoCaptionAsync("Approved. The command ran with the secret; its output is redacted.");
        }

        // 5. A pre-approval: the same kind of request, but it lets the same command run again for a while without asking.
        CliCommand.Run grantRun = (CliCommand.Run)Cmds.Parse(["--secrets", "E2E_SECRET", "--reason", "e2e run", "--", ..Rig.ScriptCommand("check")]);
        using (Cmd<int> preApprove = new((port, o, e) => LaunchClient.RunAsync(grantRun.Args, rig.Work, app.Service.Endpoint, null, o, e, rig.Machine.Trust, approve: true).GetAwaiter().GetResult()))
        {
            await c.DemoCaptionAsync("Create a pre-approval to let the same command run later for a period you choose.");
            await Spa.OpenRequest(c, preApprove, app, s, "Run request from");
            await c.DemoCaptionAsync("The arrow beside Approve chooses how long it lasts, and asks for one tap.");
            await Spa.ApproveFor(c, "Approve for 1 hour");
            await c.Page.GetByText("Grant created for").First.WaitForAsync(new() { Timeout = 20000 });
            s.Check(await preApprove.Result.WaitAsync(TimeSpan.FromSeconds(30)) == 0 && store.Grants().Count(grant => grant.Usage == GrantUsage.Reusable) == 1 && store.Grants().Count(grant => grant.Usage == GrantUsage.Once && grant.Status == "consumed") == 1, "the first run (Approve once) recorded a used once-only grant and the pre-approval made one reusable grant");
            await c.DemoCaptionAsync("The grant exists. The next run of that command will not ask.");
        }

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
            await Spa.OpenRequest(c, timed, app, s);
            await Spa.ApproveFor(c, "Approve always");
            int exit = await timed.Result.WaitAsync(TimeSpan.FromSeconds(30));
            s.Check(exit == 0 && timed.Out.Text.Contains("timed-value=" + StreamRedactor.Mask) && store.Grants().Count(grant => grant.Usage == GrantUsage.Reusable) == 2 && store.Grants().Count(grant => grant.Usage == GrantUsage.Reusable && grant.Expires is null) == 1, "a run approved as Always ran, and made a grant with no end (exit " + exit + ": " + timed.Err.Text.Replace('\n', ' ') + ")");
            await c.Page.GetByText("can run it now and again at any time").First.WaitForAsync(new() { Timeout = 20000 });
        }

        await Spa.GoTo(c, "Access", "Access");
        await c.DemoCaptionAsync("The Grants page lists the active grants. Revoke ends one with one tap.");

        ILocator dialog = Spa.Dialog(c);

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
        await c.DemoCaptionAsync("The invitation is shown once. The person copies it to the new machine, where it runs: with-secrets pair.");
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
        ILocator row = c.Page.GetByRole(AriaRole.Region, new() { Name = "A machine paired and is waiting for you" }).GetByRole(AriaRole.Listitem).Filter(new() { HasText = KeyIdentity.Display(fp) });
        await row.WaitForAsync(new() { Timeout = 45000 });
        await c.DemoCaptionAsync("The new machine appears by itself. Check the fingerprint and host name, then Approve.");
        await Spa.Click(row.GetByRole(AriaRole.Button, new() { Name = "Approve" }));
        await dialog.WaitForAsync();
        IPage approvePage = await Spa.OpenPasskeyPage(c, s, dialog);
        await Spa.TapAfterBack(c, s, approvePage, null);
        await dialog.GetByText("Done").First.WaitForAsync(new() { Timeout = 20000 });
        s.Check(store.Find(fp) is { Status: MachineStatus.Trusted }, "the approval makes the machine trusted");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Close" }).ClickAsync();
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
        await Spa.Continue(c, s, dialog);
        await dialog.GetByText("The authority is locked.").First.WaitForAsync(new() { Timeout = 20000 });
        s.Check(app.Service.Lock.IsLocked, "the tap locks the authority");
        await c.DemoCaptionAsync("The authority is locked.");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Close" }).ClickAsync();
        await Spa.Heading(c, "with-secrets").WaitForAsync(new() { Timeout = 20000 });
        await Spa.Button(c, "Unlock the authority").ClickAsync();
        await dialog.WaitForAsync();
        await Spa.Continue(c, s, dialog);
        await dialog.GetByText("Done").First.WaitForAsync(new() { Timeout = 20000 });
        s.Check(!app.Service.Lock.IsLocked, "the tap unlocks the authority");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Close" }).ClickAsync();
        await c.Page.GetByText("Authority unlocked").First.WaitForAsync(new() { Timeout = 20000 });
        await c.DemoCaptionAsync("Unlocked. Sign in again to continue.");

        List<string> events = [.. AuditChecks.Events(rig)];
        s.Check(new[] { "setup", "secrets-set", "authorization-approved", "authorization-granted", "key-enrolled" }.Take(4).All(events.Contains), "the audit holds the setup, the secret, the approval and the grant (" + string.Join(", ", events) + ")");
        s.NoProblems(c);
    }
}

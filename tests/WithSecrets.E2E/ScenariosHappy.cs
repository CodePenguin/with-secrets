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
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        AuthorityStore store = rig.Machine.Deployment.Store;

        // 1. First run: one page, one passkey, and the recovery code. This is the only step that is not in the administration app.
        await c.DemoCaptionAsync("1. First run: the command line prints a link. The person opens it to create the first passkey and the recovery code.");
        await Flows.Configure(rig, c, null, keepSetup: true);
        using SpaApp app = new(rig, machineEndpoint: true, timeLimit: TimeSpan.FromSeconds(20));

        // 2. Sign in to the administration app with the passkey: one click.
        await c.DemoCaptionAsync("2. Open the administration app and sign in with the passkey: one click.");
        await Spa.SignIn(c, app, s);

        // 3. Store a secret: name, value, one passkey tap. The value is sealed in the browser and never shown again.
        await Spa.GoTo(c, "Secrets", "Secrets");
        await c.DemoCaptionAsync("3. Secrets: type the name and the value. The value is sealed in the browser and is never shown again.");
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
            await c.DemoCaptionAsync("4. An agent runs a command that needs the secret. The command line prints a link to the request.");
            await Spa.OpenRequest(c, run, app, s);
            await Spa.ShowRequestVariants(c);
            await c.DemoCaptionAsync("The request shows what would run and which secrets it would get. Approve asks for one tap.");
            await Spa.ApproveOnce(c);
            s.Check(await run.Result.WaitAsync(TimeSpan.FromSeconds(30)) == 0 && run.Out.Text.Contains("script-value=" + StreamRedactor.Mask), "the approved run got the secret and its output was redacted");
            await c.Page.GetByText("Approved.").First.WaitForAsync(new() { Timeout = 20000 });
            await c.DemoCaptionAsync("Approved. The command ran with the secret; its output is redacted.");
        }

        // 5. A pre-approval: the same kind of request, but it lets the same command run again for a while without asking.
        CliCommand.Run grantRun = (CliCommand.Run)Cmds.Parse(["--secrets", "E2E_SECRET", "--reason", "e2e run", "--", ..Rig.ScriptCommand("check")]);
        using (Cmd<int> preApprove = new((port, o, e) => LaunchClient.RunAsync(grantRun.Args, rig.Work, app.Service.Port, null, o, e, rig.Machine.Trust, approve: true).GetAwaiter().GetResult()))
        {
            await c.DemoCaptionAsync("5. A pre-approval lets the same command run again without asking, for a time the person chooses.");
            await Spa.OpenRequest(c, preApprove, app, s, "Run request from");
            await c.DemoCaptionAsync("The arrow beside Approve chooses how long it lasts, and asks for one tap.");
            await Spa.ApproveFor(c, "Approve for 1 hour");
            await c.Page.GetByText("Grant created for").First.WaitForAsync(new() { Timeout = 20000 });
            s.Check(await preApprove.Result.WaitAsync(TimeSpan.FromSeconds(30)) == 0 && store.Grants().Count == 1, "the pre-approval made one grant");
            await c.DemoCaptionAsync("The grant exists. The next run of that command will not ask.");
        }

        // The first run under a grant releases the store key to the service: one more tap. After that, runs under the grant do not ask.
        using (Cmd<int> first = Cmds.Run(rig, "E2E_SECRET", Rig.ScriptCommand("check"), app: app))
        {
            await c.DemoCaptionAsync("The first run under the grant asks for one tap, so that the service can keep the key for it.");
            await Spa.OpenRequest(c, first, app, s);
            await Spa.ApproveOnce(c);
            int exit = await first.Result.WaitAsync(TimeSpan.FromSeconds(30));
            s.Check(exit == 0 && first.Out.Text.Contains("script-value=" + StreamRedactor.Mask), "the first run under the grant runs after that tap");
        }

        using (Cmd<int> again = Cmds.Run(rig, "E2E_SECRET", Rig.ScriptCommand("check"), app: app))
        {
            int exit = await again.Result.WaitAsync(TimeSpan.FromSeconds(30));
            s.Check(exit == 0 && again.Out.Text.Contains("script-value=" + StreamRedactor.Mask), "later runs under the grant go through without asking (exit " + exit + ": " + again.Err.Text.Replace('\n', ' ') + ")");
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
            s.Check(exit == 0 && timed.Out.Text.Contains("timed-value=" + StreamRedactor.Mask) && store.Grants().Count == 2 && store.Grants().Count(grant => grant.Expires is null) == 1, "a run approved as Always ran, and made a grant with no end (exit " + exit + ": " + timed.Err.Text.Replace('\n', ' ') + ")");
            await c.Page.GetByText("can run it now and again at any time").First.WaitForAsync(new() { Timeout = 20000 });
        }

        await Spa.GoTo(c, "Access", "Access");
        await c.DemoCaptionAsync("The Grants page lists the active grants. Revoke ends one with one tap.");

        ILocator dialog = Spa.Dialog(c);

        // 6. Add a machine: an invitation, the second machine pairs, the person approves it.
        await Spa.GoTo(c, "Machines", "Machines");
        await c.DemoCaptionAsync("6. Add a second machine: Add a machine creates a one-time invitation with one tap.");
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
        await c.DemoCaptionAsync("7. Audit: every change and every run is recorded, with who approved it.");

        // 8. Lock and unlock.
        await Spa.GoTo(c, "Overview", "Overview");
        await Spa.Button(c, "Lock the authority").ClickAsync();
        await dialog.WaitForAsync();
        await c.DemoCaptionAsync("8. Lock the authority: every session ends and no secret is released until it is unlocked.");
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

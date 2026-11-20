using System.Net.Http.Headers;
using System.Text;
using Microsoft.Playwright;

namespace WithSecrets.E2E;

/// <summary>
/// A machine is paired with the authority from start to end. The administrator creates the invitation in the SPA, confirms its prepared challenge with one passkey tap, and sees the bundle once. A second host pairs with it and appears for review; the administrator approves it with a second in-page assertion.
/// </summary>
internal static class ScenariosPairing
{
    private const string SecretValue = "s3cr3t-e2e-value-1";

    public static async Task PairMachine(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using SpaApp app = new(rig, machineEndpoint: true);
        AuthorityStore store = rig.Machine.Deployment.Store;
        await Spa.SignIn(c, app, s);
        (_, long signsAfterSignIn) = await c.AuthOps();

        // 1. The administrator creates the invitation: the dialog, the tap, and the bundle once.
        await Spa.GoTo(c, "Machines", "Machines");
        s.Check(await c.Page.GetByRole(AriaRole.Navigation, new() { Name = "Main" }).GetByRole(AriaRole.Link, new() { Name = "Pairing" }).CountAsync() == 0, "pairing is part of Machines: the navigation has no Pairing entry");
        await Spa.Axe(c, s, "machines (empty)");
        Spa.Clicks = 0;
        await Spa.Click(Spa.Button(c, "Add a machine"));
        ILocator dialog = Spa.Dialog(c);
        await dialog.WaitForAsync();
        IPage invitationPage = await Spa.OpenPasskeyPage(c, s, dialog);
        s.Check(store.Invitations().Count == 0, "nothing is created while the tap is outstanding");
        string page = await Spa.TapAfterBack(c, s, invitationPage, null);
        s.Check(page.Contains("Done", StringComparison.Ordinal) && page.Contains("one-time invitation", StringComparison.OrdinalIgnoreCase), "the SPA displays the service-confirmed one-time invitation: " + page);
        ILocator box = dialog.Locator("textarea#pairing-bundle");
        await box.WaitForAsync(new() { Timeout = 20000 });
        string bundleText = await box.InputValueAsync();
        s.Check(Spa.Clicks == 2, "creating an invitation took two clicks: Add a machine and confirm (" + Spa.Clicks + ")");
        PairingBundle? bundle = PairingBundle.TryParse(bundleText);
        s.Check(bundle is not null && store.Invitation(bundle.InvitationId) is { Status: "pending" }, "the bundle is shown once, after the tap, and the invitation is pending");
        await Spa.Axe(c, s, "the invitation dialog");
        string code = bundleText.Split(';')[3];
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Close" }).ClickAsync();
        await dialog.WaitForAsync(new() { State = WaitForSelectorState.Detached });
        s.Check(!(await c.Page.ContentAsync()).Contains(code, StringComparison.Ordinal) && !c.Page.Url.Contains(code, StringComparison.Ordinal), "after the dialog is closed the code is nowhere on the page or in its address");
        await c.Page.ReloadAsync();
        await Spa.Heading(c, "Machines").WaitForAsync();
        s.Check(!(await c.Page.ContentAsync()).Contains(code, StringComparison.Ordinal) && (await c.Page.GetByRole(AriaRole.List, new() { Name = "Invitations" }).TextContentAsync() ?? "").Contains("pending", StringComparison.Ordinal), "after a reload the invitation is listed by status only; the bundle cannot be shown again");

        // 2. A second host pairs (its own identity and folder).
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
        s.Check(paired.Ok && paired.MachineFingerprint == fp && store.Find(fp) is { Status: MachineStatus.Pending, HostName: "paired-host" } && store.Invitation(bundle!.InvitationId) is { Status: "consumed" }, "the second host pairs: it is Pending at the authority with its host name and the invitation is consumed");

        // 3. The administrator sees it Pending with the fingerprint and host name and approves it (the existing operation, its own tap).
        ILocator row = c.Page.GetByRole(AriaRole.Region, new() { Name = "A machine paired and is waiting for you" }).GetByRole(AriaRole.Listitem).Filter(new() { HasText = KeyIdentity.Display(fp) });
        await row.WaitForAsync(new() { Timeout = 45000 });
        s.Check(await c.Page.GetByRole(AriaRole.Region, new() { Name = "A machine paired and is waiting for you" }).CountAsync() == 1, "the machine that paired appears by itself, as a card to check and approve");
        string rowText = await row.TextContentAsync() ?? "";
        s.Check(rowText.Contains("pending", StringComparison.Ordinal) && rowText.Contains("paired-host", StringComparison.Ordinal), "the machines view shows the paired machine Pending with its host name and fingerprint");
        Spa.Clicks = 0;
        await Spa.Click(row.GetByRole(AriaRole.Button, new() { Name = "Approve" }));
        await dialog.WaitForAsync();
        await Spa.WaitForPasskeyStep(dialog);
        s.Check((await dialog.TextContentAsync() ?? "").Contains("as \"paired-host\"", StringComparison.Ordinal), "the machine is approved under its host name unless the person changes it");
        IPage approvePage = await Spa.OpenPasskeyPage(c, s, dialog);
        s.Check(store.Find(fp)!.Status == MachineStatus.Pending, "still Pending until the second tap");
        await Spa.TapAfterBack(c, s, approvePage, null);
        await dialog.GetByText("Done").First.WaitForAsync(new() { Timeout = 20000 });
        s.Check(store.Find(fp) is { Status: MachineStatus.Trusted, FriendlyName: "paired-host" }, "the approval makes the host Trusted");
        (_, long signsAfterApprove) = await c.AuthOps();
        s.Check(Spa.Clicks == 2, "approving the paired machine took two clicks: Approve and confirm (" + Spa.Clicks + ")");
        s.Check(signsAfterApprove == signsAfterSignIn + 2, "creating the invitation and approving the machine were two passkey taps, one each");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Close" }).ClickAsync();

        // 4. The host pins the authority key (M1) and asks the authority to run a command.
        // Seeding the secret used the shared page's one-shot link, whose command has since stopped. The Approvals queue
        // belongs to the live authority SPA and to the session this tab kept there, so return to it before the launch.
        await Scenarios3.SeedSecret(rig, c, app);
        await Spa.Open(c, app);
        await Spa.Heading(c, "Overview").WaitForAsync(new() { Timeout = 20000 });
        RemoteAuthorityConfig config = hostDeployment.HostConfig.Load().Config!.Remote!;
        using RemoteAuthority remote = new(config, hostDeployment.Tls, hostDeployment.HostConfig);
        hostDeployment.UseRemote(remote);
        s.Check(await remote.EnsureAuthorityKeyPinnedAsync(CancellationToken.None) && hostDeployment.HostConfig.Load().Config?.Authority is not null, "the host pins the authority's signing key");

        string script = rig.WriteScript("remote", "remote-value", runnable: true);
        StateDatabase hostState = StateDatabase.InFolder(folder);
        using HostService hostService = HostService.Start(new HostServiceOptions { Lock = AuthorityLock.UnlockedForTests(), State = hostState, Store = new SecretStore(hostState), Deployment = hostDeployment, Port = 0, TimeLimit = TimeSpan.FromSeconds(60) });
        Dictionary<string, string> environment = Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>().ToDictionary(entry => (string)entry.Key, entry => (string)(entry.Value ?? ""), StringComparer.OrdinalIgnoreCase);
        using HttpClient http = new() { Timeout = TimeSpan.FromSeconds(120) };

        // The paired host asks to run the script. Its request waits in the authority's Approvals queue; a person decides it on the Approvals page.
        async Task<(LaunchEvent? Result, string Output, string All)> Launch(string reason, Func<Task> decide)
        {
            LaunchRequest request = new(LaunchProtocol.Version, "e2e-" + Guid.NewGuid().ToString("N")[..8], DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), "bm9uY2UtMDAwMDAwMDE" + Guid.NewGuid().ToString("N")[..6], ["E2E_SECRET"], [new LaunchMapping("E2E_SECRET", "E2E_SECRET")], reason, script, [], rig.Work, [], [], new Dictionary<string, string>(), environment, []);
            using HttpRequestMessage message = new(HttpMethod.Post, $"http://127.0.0.1:{hostService.Port}/v1/launch") { Content = new StringContent(request.Canonical(), new UTF8Encoding(false), new MediaTypeHeaderValue("application/json")) };
            message.Headers.Add(HostService.DigestHeader, request.Digest());
            using HttpResponseMessage response = await http.SendAsync(message, HttpCompletionOption.ResponseHeadersRead);
            using StreamReader reader = new(await response.Content.ReadAsStreamAsync(), new UTF8Encoding(false));
            StringBuilder output = new();
            StringBuilder all = new();
            LaunchEvent? result = null;
            Task decision = decide();
            while (await reader.ReadLineAsync() is { } line)
            {
                all.AppendLine(line);
                if (!LaunchEvent.TryParse(line, out LaunchEvent? launchEvent, out _) || launchEvent is null)
                {
                    continue;
                }

                if (launchEvent.Kind == LaunchEvent.OutputKind)
                {
                    output.Append(launchEvent.Text);
                }
                else if (launchEvent.Kind == LaunchEvent.ResultKind)
                {
                    result = launchEvent;
                }
            }

            await decision;

            return (result, output.ToString(), all.ToString());
        }

        // 4a. A person denies the request on the Approvals page.
        (LaunchEvent? denied, string deniedOutput, string deniedAll) = await Launch("e2e paired host", () => DecideOnApprovalsPage(c, s, approve: false, "e2e paired host"));
        s.Check(denied is { Outcome: LaunchOutcome.Denied, ExitCode: RunCommand.Denied }
            && !deniedOutput.Contains(SecretValue, StringComparison.Ordinal)
            && deniedAll.Contains("user-denied", StringComparison.Ordinal),
            "the paired host's request reached the Approvals page and Deny ended it (nothing ran)");

        // 4b. A person approves a second request with their passkey; the sealed PRF output opens the secret for exactly this run.
        (LaunchEvent? approved, string approvedOutput, _) = await Launch("e2e paired host, approved", () => DecideOnApprovalsPage(c, s, approve: true, "e2e paired host, approved"));
        s.Check(approved is { Outcome: LaunchOutcome.Exited, ExitCode: 0 } && approvedOutput.Contains("remote-value=[REDACTED]", StringComparison.Ordinal) && !approvedOutput.Contains(SecretValue, StringComparison.Ordinal),
            "Approve on the Access screen, with one passkey tap, let the paired host's command run, its output redacted (" + approved?.Outcome + ", " + approved?.ExitCode + ", output: " + approvedOutput.Replace(SecretValue, "<secret>").Trim() + ")");
        s.Check(!(await c.Page.ContentAsync()).Contains(SecretValue, StringComparison.Ordinal), "the secret value is nowhere in the Approvals page");

        // 5. Nothing of the pairing code is anywhere on disk or in the audit.
        bool leaked = Directory.EnumerateFiles(rig.Folder, "*", SearchOption.AllDirectories).ToList().Any(file =>
        {
            try
            {
                using FileStream stream = new(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using MemoryStream memory = new();
                stream.CopyTo(memory);

                return Encoding.Latin1.GetString(memory.ToArray()).Contains(code, StringComparison.Ordinal);
            }
            catch (Exception failure) when (failure is IOException or UnauthorizedAccessException)
            {
                // SQLite is deleting its -shm or -wal file: Windows reports a file that is going away as access denied.
                return false;
            }
        });
        IReadOnlyList<AuditEntry> audit = store.Audit(500);
        s.Check(!leaked && !string.Join('\n', audit.Select(entry => entry.Detail)).Contains(code, StringComparison.Ordinal), "the pairing code is in no file of the authority or the host and not in the audit");
        s.Check(audit.Any(entry => entry.Event == "pairing-invitation-created") && audit.Any(entry => entry.Event == "pairing-invitation-consumed") && audit.Any(entry => entry.Event == "machine-approve"), "the audit holds the creation, the consumption and the approval");
        s.NoProblems(c);
    }
 
    private static void RequireAuthorityOrigin(IPage page, SpaApp app)
    {
        if (new Uri(page.Url).GetLeftPart(UriPartial.Authority) != new Uri(app.Url).GetLeftPart(UriPartial.Authority))
            throw new InvalidOperationException("The Approvals queue belongs to the live authority SPA at " + app.Url + ", but the page is at " + page.Url);
    }

    /// <summary>Decides the waiting request with this reason the way a person does: Access in the navigation, Review, then Deny or Approve once.</summary>
    private static async Task DecideOnApprovalsPage(Ctx c, S s, bool approve, string reason)
    {
        await Spa.GoTo(c, "Access", "Access");
        // This request, by its reason: the list is polled, so a request that was decided a moment ago can still be listed, and Review for that one opens a request that is already over.
        ILocator review = c.Page.GetByRole(AriaRole.Listitem).Filter(new() { HasText = reason }).GetByRole(AriaRole.Link, new() { Name = "Review" }).First;
        await review.WaitForAsync(new() { Timeout = 60000 });
        await Spa.Shot(c, "approvals-list");
        await Spa.Axe(c, s, "approvals (a request is waiting)");
        await Spa.Click(review);
        await c.Page.GetByRole(AriaRole.Dialog, new() { Name = "Run request from" }).WaitForAsync(new() { Timeout = 20000 });
        string text = await c.Page.Locator("main").TextContentAsync() ?? "";
        s.Check(text.Contains("E2E_SECRET", StringComparison.Ordinal) && text.Contains(Rig.ScriptFile("remote"), StringComparison.Ordinal) && text.Contains("echo remote-value", StringComparison.Ordinal), "the request page names the secret, the program and the script's contents before any decision");
        await Spa.Shot(c, "approval-request");
        await Spa.Axe(c, s, "a run request");
        if (!approve)
        {
            await Spa.Click(c.Page.GetByRole(AriaRole.Button, new() { Name = "Deny", Exact = true }));
            await c.Page.GetByText("Denied.").First.WaitForAsync(new() { Timeout = 20000 });

            return;
        }

        ILocator approveButton = c.Page.GetByRole(AriaRole.Button, new() { Name = "Approve", Exact = true });
        await approveButton.WaitForAsync(new() { Timeout = 20000 });
        await c.Page.WaitForFunctionAsync("() => { const b = [...document.querySelectorAll('button')].find((x) => x.textContent.trim() === 'Approve'); return !!b && !b.disabled; }", null, new() { Timeout = 20000 });
        int before = await c.PasskeyCalls();
        await Spa.Click(approveButton);
        await c.Page.GetByText("Approved.").First.WaitForAsync(new() { Timeout = 30000 });
        s.Check(await c.PasskeyCalls() == before + 1, "Approve used the passkey exactly once");
    }
}

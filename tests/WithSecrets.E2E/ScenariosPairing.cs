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
        await dialog.GetByText("Review before confirming").WaitForAsync();
        s.Check(store.Invitations().Count == 0, "nothing is created while the tap is outstanding");
        string page = await Spa.TapAfterBack(c, s, invitationPage, null);
        s.Check(page.Contains("Done", StringComparison.Ordinal) && page.Contains("one-time invitation", StringComparison.OrdinalIgnoreCase), "the SPA displays the service-confirmed one-time invitation: " + page);
        ILocator box = dialog.Locator("textarea#pairing-bundle");
        await box.WaitForAsync(new() { Timeout = 20000 });
        string bundleText = await box.InputValueAsync();
        s.Check(Spa.Clicks == 3, "creating an invitation took three clicks: Add a machine, prepare, and confirm (" + Spa.Clicks + ")");
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
        s.Check(await dialog.GetByLabel("Friendly name").InputValueAsync() == "paired-host", "the friendly name starts as the host name");
        await dialog.GetByLabel("Friendly name").FillAsync("paired box");
        IPage approvePage = await Spa.OpenPasskeyPage(c, s, dialog);
        await dialog.GetByText("Review before confirming").WaitForAsync();
        s.Check(store.Find(fp)!.Status == MachineStatus.Pending, "still Pending until the second tap");
        await Spa.TapAfterBack(c, s, approvePage, null);
        await dialog.GetByText("Done").First.WaitForAsync(new() { Timeout = 20000 });
        s.Check(store.Find(fp) is { Status: MachineStatus.Trusted, FriendlyName: "paired box" }, "the approval makes the host Trusted");
        (_, long signsAfterApprove) = await c.AuthOps();
        s.Check(Spa.Clicks == 3, "approving the paired machine took three clicks: Approve, prepare, and confirm (" + Spa.Clicks + ")");
        s.Check(signsAfterApprove == signsAfterSignIn + 2, "creating the invitation and approving the machine were two passkey taps, one each");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Close" }).ClickAsync();

        // 4. The host pins the authority key (M1) and asks the authority to run a command.
        await Scenarios3.SeedSecret(rig, c);
        RemoteAuthorityConfig config = hostDeployment.HostConfig.Load().Config!.Remote!;
        using RemoteAuthority remote = new(config, hostDeployment.Tls, hostDeployment.HostConfig);
        hostDeployment.UseRemote(remote);
        s.Check(await remote.EnsureAuthorityKeyPinnedAsync(CancellationToken.None) && hostDeployment.HostConfig.Load().Config?.Authority is not null, "the host pins the authority's signing key");

        string script = Path.Combine(rig.Work, "remote.cmd");
        File.WriteAllLines(script, ["@echo off", "echo remote-value=%E2E_SECRET%"]);
        StateDatabase hostState = StateDatabase.InFolder(folder);
        using HostService hostService = HostService.Start(new HostServiceOptions { Lock = AuthorityLock.UnlockedForTests(), State = hostState, Store = new SecretStore(hostState), Deployment = hostDeployment, Port = 0, TimeLimit = TimeSpan.FromSeconds(60) });
        DateTimeOffset now = DateTimeOffset.UtcNow;
        Dictionary<string, string> environment = Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>().ToDictionary(entry => (string)entry.Key, entry => (string)(entry.Value ?? ""), StringComparer.OrdinalIgnoreCase);
        LaunchRequest request = new(LaunchProtocol.Version, "e2e-" + Guid.NewGuid().ToString("N")[..8], now, now.AddMinutes(5), "bm9uY2UtMDAwMDAwMDE" + Guid.NewGuid().ToString("N")[..6], ["E2E_SECRET"], [new LaunchMapping("E2E_SECRET", "E2E_SECRET")], "e2e paired host", script, [], rig.Work, [], [], new Dictionary<string, string>(), environment, []);
        using HttpClient http = new() { Timeout = TimeSpan.FromSeconds(90) };
        using HttpRequestMessage message = new(HttpMethod.Post, $"http://127.0.0.1:{hostService.Port}/v1/launch") { Content = new StringContent(request.Canonical(), new UTF8Encoding(false), new MediaTypeHeaderValue("application/json")) };
        message.Headers.Add(HostService.DigestHeader, request.Digest());
        using HttpResponseMessage response = await http.SendAsync(message, HttpCompletionOption.ResponseHeadersRead);
        using StreamReader reader = new(await response.Content.ReadAsStreamAsync(), new UTF8Encoding(false));
        StringBuilder output = new();
        StringBuilder all = new();
        LaunchEvent? result = null;

        // The authority now exposes run approvals through its authenticated queue API, not a per-request browser page link.
        // Denial needs an approval-capable session but deliberately does not need a passkey assertion.
        Task<string> denyTask = DenyQueuedRequest(c.Page, fp);
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

        string requestId = await denyTask;
        string terminalStatus = await ReadQueuedStatus(c.Page, requestId);
        s.Check(result is { Outcome: LaunchOutcome.Denied, ExitCode: RunCommand.Denied }
            && terminalStatus == ApprovalStatuses.Denied
            && !output.ToString().Contains(SecretValue, StringComparison.Ordinal)
            && all.ToString().Contains("user-denied", StringComparison.Ordinal),
            "the paired host's request reached the authority's authenticated Approvals queue and a session denial ended it (nothing ran)");

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
            catch (IOException)
            {
                return false;
            }
        });
        IReadOnlyList<AuditEntry> audit = store.Audit(500);
        s.Check(!leaked && !string.Join('\n', audit.Select(entry => entry.Detail)).Contains(code, StringComparison.Ordinal), "the pairing code is in no file of the authority or the host and not in the audit");
        s.Check(audit.Any(entry => entry.Event == "pairing-invitation-created") && audit.Any(entry => entry.Event == "pairing-invitation-consumed") && audit.Any(entry => entry.Event == "machine-approve"), "the audit holds the creation, the consumption and the approval");
        s.NoProblems(c);
    }
 
    private static async Task<string> DenyQueuedRequest(IPage page, string fingerprint)
    {
        for (int attempt = 0; attempt < 240; attempt++)
        {
            string response = await page.EvaluateAsync<string>(@"async () => {
                const token = sessionStorage.getItem('ws.session-secret');
                const result = await fetch('/api/v1/approvals', {
                    headers: { 'X-Admin-Token': token ?? '' },
                    credentials: 'same-origin',
                    cache: 'no-store'
                });
                return JSON.stringify({ status: result.status, body: await result.json() });
            }");
            using System.Text.Json.JsonDocument document = System.Text.Json.JsonDocument.Parse(response);
            int status = document.RootElement.GetProperty("status").GetInt32();
            if (status != 200)
                throw new InvalidOperationException("Could not read the authenticated Approvals queue: HTTP " + status + " " + document.RootElement.GetProperty("body"));

            System.Text.Json.JsonElement items = document.RootElement.GetProperty("body").GetProperty("items");
            foreach (System.Text.Json.JsonElement item in items.EnumerateArray())
            {
                if (!string.Equals(item.GetProperty("machine").GetProperty("fingerprint").GetString(), fingerprint, StringComparison.Ordinal))
                    continue;

                string requestId = item.GetProperty("requestId").GetString()!;
                string denied = await page.EvaluateAsync<string>(@"async (id) => {
                    const token = sessionStorage.getItem('ws.session-secret');
                    const result = await fetch('/api/v1/approvals/' + encodeURIComponent(id) + '/deny', {
                        method: 'POST',
                        headers: { 'X-Admin-Token': token ?? '' },
                        credentials: 'same-origin',
                        cache: 'no-store'
                    });
                    return JSON.stringify({ status: result.status, body: await result.json() });
                }", requestId);
                using System.Text.Json.JsonDocument denial = System.Text.Json.JsonDocument.Parse(denied);
                int denialStatus = denial.RootElement.GetProperty("status").GetInt32();
                if (denialStatus != 200)
                    throw new InvalidOperationException("Could not deny the paired host's queued request: HTTP " + denialStatus + " " + denial.RootElement.GetProperty("body"));
                return requestId;
            }

            await Task.Delay(250);
        }

        throw new TimeoutException("The paired host's request did not appear in the authority's Approvals queue.");
    }

    private static async Task<string> ReadQueuedStatus(IPage page, string requestId)
    {
        string response = await page.EvaluateAsync<string>(@"async (id) => {
            const token = sessionStorage.getItem('ws.session-secret');
            const result = await fetch('/api/v1/approvals/' + encodeURIComponent(id), {
                headers: { 'X-Admin-Token': token ?? '' },
                credentials: 'same-origin',
                cache: 'no-store'
            });
            return JSON.stringify({ status: result.status, body: await result.json() });
        }", requestId);
        using System.Text.Json.JsonDocument document = System.Text.Json.JsonDocument.Parse(response);
        int status = document.RootElement.GetProperty("status").GetInt32();
        if (status != 200)
            throw new InvalidOperationException("Could not read the terminal approval result: HTTP " + status + " " + document.RootElement.GetProperty("body"));
        return document.RootElement.GetProperty("body").GetProperty("status").GetString()!;
    }
}

using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Playwright;

namespace WithSecrets.E2E;

internal static class Scenarios
{
    public static async Task FirstRunConfig(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        using Cmd<int> cmd = new((port, o, e) => CommandWiring.Config(rig.State, port));
        string link = await cmd.LinkAsync();
        await c.Page.GotoAsync(link);
        await Task.Delay(300);
        s.Check(await c.PasskeyCalls() == 0 && (await c.AuthOps()) == (0, 0), "tap rule: no passkey prompt before the first click");
        s.Check(cmd.LinkCount == 1, "the command printed exactly one link");
        s.Check((await c.Page.TitleAsync()).Contains("settings"), "settings page opened");

        await c.Click("#save");
        await c.Click("#confirm");
        string code = await c.TextAppears("#code");
        string recovery = await c.TextAppears("#recovery");
        s.Check(await c.Page.Locator("#recovery-box").IsVisibleAsync(), "recovery code box is shown on the final page");
        s.Check(recovery.Length >= 20, "recovery code is on the page");
        s.Check((await c.Text("#status")).Contains("Type this code in the terminal"), "page tells the person to type the code");
        s.Check((await c.AuthOps()).Credentials == 1, "virtual authenticator created one credential");
        await cmd.WaitPromptAsync();
        s.Check(cmd.Err.Text.EndsWith(TerminalPrompt.Waiting, StringComparison.Ordinal), "the terminal prompt is the last thing shown while waiting");
        s.Check(cmd.LinkCount == 1, "still exactly one link after the code page");
        cmd.Type(code);
        int exit = await cmd.Result.WaitAsync(TimeSpan.FromSeconds(30));
        s.Check(exit == 0, "command exit code 0");
        s.Check(cmd.Err.Text.Contains("Saved the settings"), "the terminal shows the result");
        s.Check(!cmd.Err.Text.Contains(recovery) && !cmd.Err.Text.Contains(code), "neither code is printed on the terminal");

        bool have = rig.State.TryManifest(out Manifest? manifest, out _);
        s.Check(have && manifest is { Recovery: not null } && manifest.Keys.Count == 1 && manifest.Keys[0].Admin, "state: signed manifest with one admin key and a recovery slot");
        s.Check(rig.State.TryCheck(out _), "state.db passes its own check");
        AuditChecks.Expect(s, rig, "settings-setup");

        bool dead;
        try
        {
            dead = (await c.Context.APIRequest.GetAsync(link)).Status == 404;
        }
        catch (PlaywrightException)
        {
            dead = true;
        }

        s.Check(dead, "the one-shot link is dead after the command finished");
        s.NoProblems(c);
    }
}

internal static class Scenarios2
{
    private const string Secret = "s3cr3t-e2e-value-1";

    private static async Task<string> RawState(Rig rig)
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        StringBuilder text = new();
        foreach (string file in Directory.GetFiles(rig.Folder))
        {
            using FileStream stream = new(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            byte[] bytes = new byte[stream.Length];
            await stream.ReadExactlyAsync(bytes);
            text.Append(System.Text.Encoding.Latin1.GetString(bytes));
        }

        return text.ToString();
    }

    public static async Task SetRemove(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);

        using (Cmd<int> set = Cmds.Set(rig, "E2E_SECRET"))
        {
            string link = await set.LinkAsync();
            await c.Page.GotoAsync(link);
            await Task.Delay(300);
            s.Check((await c.Text("#request")).Contains("E2E_SECRET"), "the page names the secret");
            
            await c.Page.FillAsync("#v0", Secret);
            await PageSteps.TapSave(c);
            await c.StatusContains("Stored", 20000);
            s.Check(set.LinkCount == 1, "one link");
            int exit = await set.Result.WaitAsync(TimeSpan.FromSeconds(30));
            s.Check(exit == 0, "--set exit code 0");
            s.Check(set.Err.Text.Contains("E2E_SECRET") && !set.Err.Text.Contains(Secret), "the terminal names the secret and never shows the value");
        }

        s.Check(rig.Store.ListNames().SequenceEqual(["E2E_SECRET"]), "state lists the secret name");
        s.Check(!(await RawState(rig)).Contains(Secret), "state.db holds no plaintext of the value");
        s.Check(rig.State.TryCheck(out _), "state.db passes its check");

        // Decrypting works: a run through the page gets the value (its output is redacted, so the mask shows it was there).
        File.WriteAllLines(Path.Combine(rig.Work, "show.cmd"), ["@echo off", "echo got=%E2E_SECRET%"]);
        using (Cmd<int> run = Cmds.Run(rig, "E2E_SECRET", ["cmd", "/d", "/c", "show.cmd"]))
        {
            await c.Page.GotoAsync(await run.LinkAsync());
            await c.Click("#approve");
            s.Check(await run.Result.WaitAsync(TimeSpan.FromSeconds(30)) == 0 && run.Out.Text.Contains("got=" + StreamRedactor.Mask), "a run decrypts the stored value (output redacted)");
        }

        // --remove through the page.
        using (Cmd<int> remove = Cmds.Remove(rig, "E2E_SECRET"))
        {
            await c.Page.GotoAsync(await remove.LinkAsync());
            s.Check((await c.Text("#request")).Contains("E2E_SECRET"), "the remove page names the secret");
            await c.Click("#approve");
            int exit = await remove.Result.WaitAsync(TimeSpan.FromSeconds(30));
            s.Check(exit == 0, "--remove exit code 0");
            s.Check(remove.Err.Text.Contains("E2E_SECRET"), "the terminal names the removed secret");
        }

        s.Check(rig.Store.ListNames().Count == 0, "state no longer lists the secret");
        s.Check(!(await RawState(rig)).Contains(Secret), "state.db still holds no plaintext");
        AuditChecks.Expect(s, rig, "settings-setup", "secrets-set", "authorization-approved", "launch-started", "execution-exited", "secrets-removed");
        s.NoProblems(c);
    }

    private static IEnumerable<string> AuditEvents(Rig rig) => AuditChecks.Events(rig);
}

internal static class Scenarios3
{
    private const string Secret = "s3cr3t-e2e-value-1";

    /// <summary>Sets E2E_SECRET through the page (a fixture of the run scenarios).</summary>
    public static async Task SeedSecret(Rig rig, Ctx c)
    {
        using Cmd<int> set = Cmds.Set(rig, "E2E_SECRET");
        await c.Page.GotoAsync(await set.LinkAsync());
        await c.Page.FillAsync("#v0", Secret);
        await PageSteps.TapSave(c);
        await c.StatusContains("Stored");
        await set.Result.WaitAsync(TimeSpan.FromSeconds(30));
    }

    private static readonly string[] Script =
    [
        "@echo off",
        "echo script-value=%E2E_SECRET%",
    ];

    public static async Task RunApproval(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        await SeedSecret(rig, c);
        File.WriteAllLines(Path.Combine(rig.Work, "check.cmd"), Script);

        // 1. A script file: the page shows its contents; approve once; the program output appears.
        using (Cmd<int> run = Cmds.Run(rig, "E2E_SECRET", ["cmd", "/d", "/c", "check.cmd"]))
        {
            await c.Page.GotoAsync(await run.LinkAsync());
            string request = await c.TextAppears("#request");
            s.Check(request.Contains("Script contents:") && request.Contains("echo script-value=%E2E_SECRET%"), "the page shows the script contents");
            s.Check(request.Contains("E2E_SECRET") && request.Contains("check.cmd"), "the page shows the secret name and the command");
            s.Check(await c.PasskeyCalls() == 0, "tap rule: no passkey prompt on load of the approval page");
            s.Check(await c.Page.Locator("#approve-for").CountAsync() == 0 || !await c.Page.Locator("#approve-for").IsVisibleAsync(), "only Approve once is offered");
            await c.Click("#approve");
            int exit = await run.Result.WaitAsync(TimeSpan.FromSeconds(30));
            s.Check(exit == 0, "run exit code 0 (the program's own)");
            s.Check(run.Out.Text.Contains("script-value=" + StreamRedactor.Mask), "the program ran with the decrypted secret and its output was redacted");
            s.Check(!run.Out.Text.Contains(Secret) && !run.Err.Text.Contains(Secret), "the secret value is never printed");
            await c.StatusContains("Approved");
        }

        // 2. Inline code: the page shows it (labelled), approve once, the output is redacted.
        using (Cmd<int> run = Cmds.Run(rig, "E2E_SECRET", ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Write-Output ('inline-' + $env:E2E_SECRET)"]))
        {
            await c.Page.GotoAsync(await run.LinkAsync());
            string request = await c.TextAppears("#request");
            s.Check(request.Contains("Inline code:") && request.Contains("Write-Output ('inline-' + $env:E2E_SECRET)"), "the page shows the inline code");
            await c.Click("#approve");
            s.Check(await run.Result.WaitAsync(TimeSpan.FromSeconds(30)) == 0, "inline run exit code 0");
            s.Check(run.Out.Text.Contains("inline-" + StreamRedactor.Mask) && !run.Out.Text.Contains(Secret), "inline run output is redacted");
        }

        // 3. Deny: nothing runs.
        using (Cmd<int> run = Cmds.Run(rig, "E2E_SECRET", ["cmd", "/d", "/c", "check.cmd"]))
        {
            await c.Page.GotoAsync(await run.LinkAsync());
            await c.TextAppears("#request");
            await c.Click("#deny");
            int exit = await run.Result.WaitAsync(TimeSpan.FromSeconds(30));
            s.Check(exit == RunCommand.Denied, "denied run exits with the denied code (" + exit + ")");
            s.Check(run.Out.Text.Length == 0, "nothing ran after Deny");
            await c.StatusContains("Denied");
        }

        // 4. Timeout: the page is left alone; the run is denied at the limit.
        using (Cmd<int> run = Cmds.Run(rig, "E2E_SECRET", ["cmd", "/d", "/c", "check.cmd"], TimeSpan.FromSeconds(3)))
        {
            await c.Page.GotoAsync(await run.LinkAsync());
            await c.TextAppears("#request");
            int exit = await run.Result.WaitAsync(TimeSpan.FromSeconds(30));
            s.Check(exit == RunCommand.Denied && run.Out.Text.Length == 0, "an unanswered run is denied at the time limit and nothing ran");
            s.Check(run.Err.Text.Contains("time limit"), "the terminal says it was the time limit");
        }

        IReadOnlyList<AuditEvent> events = AuditChecks.All(rig);
        s.Check(events.Count(e => e.Type == AuditEventTypes.Authorization && e.Outcome == "denied" && e.Reason == ReasonCodes.UserDenied) >= 1, "audit records the Deny");
        s.Check(events.Count(e => e.Type == AuditEventTypes.Authorization && e.Outcome == "denied") >= 2, "audit records the time limit as a second denial (both carry the reason user-denied)");

        AuditChecks.Expect(s, rig, "settings-setup", "secrets-set", "authorization-approved", "launch-started", "execution-exited", "authorization-approved", "launch-started", "execution-exited", "authorization-denied", "authorization-denied");
        s.NoProblems(c);
    }

}
internal static class Scenarios4
{
    public static async Task Rotate(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        Flows.Configured first = await Flows.Configure(rig, c);
        await Scenarios3.SeedSecret(rig, c);

        using Cmd<int> cmd = new((port, o, e) => CommandWiring.RotateKey(rig.State, rig.Store, port));
        string link = await cmd.LinkAsync();
        await c.Page.GotoAsync(link);
        string firstUrl = c.Page.Url;
        string request = await c.TextAppears("#request");
        s.Check(request.Contains("Rotate the store keys"), "page 1 explains the rotation");
        await c.Click("#approve");
        await c.Page.WaitForURLAsync(u => u != firstUrl, new() { Timeout = 20000 });
        string request2 = await c.TextAppears("#request");
        s.Check(request2.Contains("Rotate the store keys and keep only") && request2 != request, "the automatic next page is a different page that shows the new state");
        s.Check((await c.Text("h1")).Length > 0 && c.Page.Url != firstUrl, "the page address changed by itself (no second link)");
        s.Check(await c.PasskeyCalls() == 0, "tap rule: Step 2 page makes no passkey prompt on load");
        s.Check(cmd.LinkCount == 1, "one link for the whole rotation");
        await c.Click("#approve");
        string recovery = await c.TextAppears("#recovery");
        s.Check(recovery != first.Recovery, "the final page shows a new recovery code");
        s.Check(await c.Page.Locator("#recovery-box").IsVisibleAsync(), "recovery box visible");
        int exit = await cmd.Result.WaitAsync(TimeSpan.FromSeconds(30));
        s.Check(exit == 0, "--rotate-key exit code 0");
        s.Check(cmd.LinkCount == 1 && !cmd.Err.Text.Contains(recovery), "still one link; the new code is not on the terminal");
        s.Check(rig.State.TryManifest(out Manifest? manifest, out _) && manifest!.Keys.Count == 1 && manifest.Recovery is not null, "state: one key, a recovery slot");
        s.Check(rig.Store.ListNames().SequenceEqual(["E2E_SECRET"]), "the secret survived the rotation");

        // The old recovery code stops working: the recovery page does not accept it (its 400 reply is expected in the console).
        c.Ignore("status of 400");
        using Cmd<int> again = new((port, o, e) => CommandWiring.Recover(rig.State, port));
        await c.Page.GotoAsync(await again.LinkAsync());
        string recoverUrl = c.Page.Url;
        await c.Page.FillAsync("#recovery-code", first.Recovery);
        await c.Click("#unlock");
        await c.Page.WaitForFunctionAsync("() => document.getElementById('status').textContent.trim().length > 0", null, new() { Timeout = 20000 });
        await Task.Delay(500);
        string why = await c.Text("#status");
        s.Check(c.Page.Url == recoverUrl && !(await c.Page.TitleAsync()).Contains("settings"), "the old recovery code is refused: the page does not move on (" + why + ")");
        await c.Click("#deny");
        s.Check(await again.Result.WaitAsync(TimeSpan.FromSeconds(30)) != 0, "--recover with the old code does not succeed");
        AuditChecks.Expect(s, rig, "settings-setup", "secrets-set", "key-rotated", "change-denied");
        s.Check(rig.State.TryManifest(out Manifest? after, out _) && after!.Keys.Count == 1 && !Directory.GetFiles(rig.Folder, "state.db.recovered-*").Any(), "state is unchanged by the refused recovery");

        s.NoProblems(c);
    }
}

internal static class Scenarios5
{
    public static async Task Recover(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        Flows.Configured first = await Flows.Configure(rig, c);
        await Scenarios3.SeedSecret(rig, c);

        await c.ClearCredentials(); // every passkey is lost: that is why --recover is used
        using Cmd<int> cmd = new((port, o, e) => CommandWiring.Recover(rig.State, port));
        await c.Page.GotoAsync(await cmd.LinkAsync());
        s.Check(await c.PasskeyCalls() == 0, "tap rule: no prompt on the recovery page");
        string url1 = c.Page.Url;
        await c.Page.FillAsync("#recovery-code", first.Recovery);
        await c.Click("#unlock");
        await c.Page.WaitForURLAsync(u => u != url1, new() { Timeout = 20000 });
        s.Check((await c.Page.TitleAsync()).Contains("settings") && cmd.LinkCount == 1, "the code page led by itself to the new passkey page, still one link");
        s.Check(await c.PasskeyCalls() == 0, "tap rule: the new passkey page makes no prompt on load");
        await c.Click("#save");
        await c.Click("#confirm");
        string code = await c.TextAppears("#code");
        string recovery = await c.TextAppears("#recovery");
        s.Check(recovery != first.Recovery, "the final page shows a new recovery code");
        await cmd.WaitPromptAsync();
        s.Check(cmd.Err.Text.EndsWith(TerminalPrompt.Waiting, StringComparison.Ordinal) && cmd.LinkCount == 1, "the terminal prompt is the last thing shown; still one link");
        cmd.Type(code);
        int exit = await cmd.Result.WaitAsync(TimeSpan.FromSeconds(30));
        s.Check(exit == 0, "--recover exit code 0");
        s.Check(!cmd.Err.Text.Contains(code) && !cmd.Err.Text.Contains(recovery) && !cmd.Err.Text.Contains(first.Recovery), "no code is printed on the terminal");
        s.Check(Directory.GetFiles(rig.Folder, "state.db.recovered-*").Length == 1, "the old file was renamed (state.db.recovered-<time>), not deleted");
        s.Check(rig.State.TryManifest(out Manifest? manifest, out _) && manifest!.Keys.Count == 1 && manifest.Recovery is not null, "new state: one key and a recovery slot");
        s.Check(rig.Store.ListNames().SequenceEqual(["E2E_SECRET"]), "the secret was carried over");
        // The folder holds the events of the first setup and its secret too; the recovery adds the setup of the new state and "recovered" (recorded when the swap succeeded).
        AuditChecks.Expect(s, rig, "settings-setup", "secrets-set", "settings-setup", "recovered");
    }
}

internal static class Scenarios6
{
    public static async Task EnrollSameHost(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        await Scenarios3.SeedSecret(rig, c);
        CliCommand enroll = Cmds.Parse("--enroll");

        using Cmd<int> cmd = new((port, o, e) => CommandWiring.Passkeys(enroll, rig.State, port, o, e));
        await c.Page.GotoAsync(await cmd.LinkAsync());
        string url1 = c.Page.Url;
        s.Check((await c.Text("#request")).Contains("Add a"), "page 1 asks an admin key to approve the new passkey");
        s.Check(await c.PasskeyCalls() == 0, "tap rule: no prompt on page 1");
        string adminAuth = c.AuthId;
        string second = await c.AddAuthenticator(true, "usb"); // Chrome allows one internal authenticator: the second device is a security key
        await c.Presence(false, second); // only the admin's device answers the approval
        await c.Click("#approve");
        await c.Page.WaitForURLAsync(u => u != url1, new() { Timeout = 20000 });
        s.Check((await c.Page.TitleAsync()).Contains("Add a passkey") && cmd.LinkCount == 1, "page 1 led by itself to the new passkey page; one link");
        s.Check(await c.PasskeyCalls() == 0, "tap rule: no prompt on the new passkey page load");
        await c.Page.FillAsync("#f-key-name", "second key");
        // The new key is made on the second device (the first one holds a credential the page excludes).
        await c.Presence(false, adminAuth);
        await c.Presence(true, second);
        await c.Click("#create");
        await c.Page.WaitForFunctionAsync("() => { var b = document.getElementById('confirm'); return b && !b.hidden && !b.disabled; }", null, new() { Timeout = 20000 });
        s.Check((await c.Text("#status")).Contains("second key"), "step 1 names the new key");
        // Step 2: the admin key signs the new state.
        await c.Presence(false, second);
        await c.Presence(true, adminAuth);
        await c.Click("#confirm");
        string code = await c.TextAppears("#code");
        await cmd.WaitPromptAsync();
        s.Check(cmd.Err.Text.EndsWith(TerminalPrompt.Waiting, StringComparison.Ordinal) && cmd.LinkCount == 1, "the terminal prompt is last; still one link");
        cmd.Type(code);
        int exit = await cmd.Result.WaitAsync(TimeSpan.FromSeconds(30));
        s.Check(exit == 0, "--enroll exit code 0");
        s.Check(!cmd.Err.Text.Contains(code), "the code is not printed");
        AuditChecks.Expect(s, rig, "settings-setup", "secrets-set", "key-enrolled");
        s.Check(rig.State.TryManifest(out Manifest? manifest, out _) && manifest!.Keys.Count == 2 && manifest.Keys.Count(k => k.Admin) == 1 && manifest.Keys.Any(k => k.Name == "second key" && !k.Admin), "state: two keys, the new one is not an admin");

        // The second key approves a run on its own: the first device is gone.
        await c.Presence(false, adminAuth);
        await c.Presence(true, second);
        File.WriteAllLines(Path.Combine(rig.Work, "show.cmd"), ["@echo off", "echo got=%E2E_SECRET%"]);
        using Cmd<int> run = Cmds.Run(rig, "E2E_SECRET", ["cmd", "/d", "/c", "show.cmd"]);
        await c.Page.GotoAsync(await run.LinkAsync());
        await c.TextAppears("#request");
        (int _, long signsFirst) = await c.AuthOps(adminAuth);
        (int _, long signsSecond) = await c.AuthOps(second);
        await c.Click("#approve");
        s.Check(await run.Result.WaitAsync(TimeSpan.FromSeconds(30)) == 0 && run.Out.Text.Contains("got=" + StreamRedactor.Mask), "the second key approved a run and the secret was released");
        s.Check((await c.AuthOps(second)).Signs > signsSecond && (await c.AuthOps(adminAuth)).Signs == signsFirst, "the signature came from the second device");
        AuditChecks.Expect(s, rig, "settings-setup", "secrets-set", "key-enrolled", "authorization-approved", "launch-started", "execution-exited");
        s.NoProblems(c);
    }
}

internal static class Scenarios7
{
    /// <summary>
    /// Enroll across hosts cannot run end to end in a browser: the program refuses a page on any host but localhost unless it is
    /// https ("Passkeys need an https address or localhost"), and the test server speaks http only. Chromium would accept
    /// http://ws.localhost (a secure context, resolved to loopback), but the guard is the program's. So this covers what a
    /// browser can reach: the one link and the admin approval at localhost, then the refusal at the step that needs the new
    /// host, with nothing enrolled. The server side of the full cross-host flow is covered by OneFlowTests.CrossHostEnroll.
    /// </summary>
    public static async Task EnrollCrossHost(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);

        using Cmd<ApprovalDecision> cmd = new((port, o, e) =>
        {
            ApprovalSettings remote = new("passkey", "http://ws.localhost:" + port, port, TimeSpan.FromSeconds(60));
            (EnrollmentTarget primary, EnrollmentTarget other) = CommandWiring.Targets(rig.State, remote, TerminalPrompt.Line, CommandWiring.CodeReader("If the page says nothing was added, press Ctrl+C."));

            return new Enrollment(primary, other, TerminalPrompt.Line, rig.State.Audit).Enroll();
        });
        string link = await cmd.LinkAsync();
        s.Check(new Uri(link).Host == "localhost" && cmd.LinkCount == 1, "the one link is at the admin key's host (localhost)");
        await c.Page.GotoAsync(link);
        s.Check(await c.PasskeyCalls() == 0, "tap rule: no prompt on page 1");
        c.Ignore("ERR_CONNECTION_REFUSED");
        await c.Click("#approve");
        ApprovalDecision result = await cmd.Result.WaitAsync(TimeSpan.FromSeconds(30));
        s.Check(!result.Approved && result.Detail.Contains("https address or localhost"), "the program refuses the non-https cross host and says why (" + result.Detail + ")");
        s.Check(rig.State.TryManifest(out Manifest? manifest, out _) && manifest!.Keys.Count == 1, "nothing was enrolled");
        s.Check(AuditChecks.All(rig).Any(e => e.Type == AuditEventTypes.Admin && e.Outcome == AdminEvent.ChangeDenied && e.Reason.Contains("https address or localhost")), "audit records the refusal");
        s.NoProblems(c);
    }
}

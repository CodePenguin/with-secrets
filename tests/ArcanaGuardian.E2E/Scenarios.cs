using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Playwright;

namespace ArcanaGuardian.E2E;

internal static class Scenarios
{
    public static async Task FirstRunSetup(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        using Cmd<int> cmd = new((port, o, e) => CommandWiring.Setup(rig.State, port));
        string link = await cmd.LinkAsync();
        await c.Page.GotoAsync(link);
        await c.Page.Locator("#save").WaitForAsync();
        s.Check(await c.PasskeyCalls() == 0 && (await c.AuthOps()) == (0, 0), "tap rule: no passkey prompt before the first click");
        s.Check(cmd.LinkCount == 1, "the command printed exactly one link");
        s.Check((await c.Page.TitleAsync()).Contains("Set up"), "setup page opened");

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
        int exit = await c.TypeCodeAsync(cmd, code);
        s.Check(exit == 0, "command exit code 0");
        s.Check(cmd.Err.Text.Contains("Set up. Admin passkey"), "the terminal shows the result");
        s.Check(!cmd.Err.Text.Contains(recovery) && !cmd.Err.Text.Contains(code), "neither code is printed on the terminal");

        bool have = rig.State.TryManifest(out Manifest? manifest, out _);
        s.Check(have && manifest is { Recovery: not null } && manifest.Keys.Count == 1 && manifest.Keys[0].Admin, "state: signed manifest with one admin key and a recovery slot");
        s.Check(rig.State.TryCheck(out _), "arcana-guardian.db passes its own check");
        AuditChecks.Expect(s, rig, "setup");

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

    /// <summary>The first-run setup with a time limit, for the cases that end by it (the command is the same as <see cref="CommandWiring.Setup" />).</summary>
    private static Cmd<int> SetupWithin(Rig rig, TimeSpan limit)
    {
        return new Cmd<int>((port, _, _) =>
        {
            Action<string> announce = TerminalPrompt.Line;
            Func<string?> readCode = CommandWiring.CodeReader("Press Ctrl+C to cancel.");
            ApprovalSettings settings = ToolSettings.Defaults.Approval.WithPort(port) with { Timeout = limit };
            (EnrollmentTarget primary, EnrollmentTarget local) = CommandWiring.Targets(rig.State, settings, announce, readCode);
            ConfigChange change = new FirstRunPage(rig.State, primary, local, announce, readCode).Run();
            TerminalPrompt.Final(change.Done ? change.Detail : "using-secrets: " + change.Detail);

            return change.Code;
        });
    }

    /// <summary>Nothing is set up: no signed state, no passkey and no audit row. A setup that did not finish must leave the authority exactly as it found it.</summary>
    private static bool Untouched(Rig rig)
    {
        bool none = rig.State.TryManifest(out Manifest? manifest, out _) && manifest is null;

        return none && !AuditChecks.Events(rig).Any();
    }

    /// <summary>
    /// First-time setup as a security sequence, with the real browser and the virtual authenticator: the first passkey (with PRF, which protects the secret
    /// store key), the second prompt over the first manifest, the recovery code, the code typed in the terminal, then the signed state and the audit;
    /// and every way it can stop before that, each of which must leave nothing set up.
    /// </summary>
    public static async Task FirstRunSecurity(Host host, S s)
    {
        // 1. The whole sequence: two passkey prompts, then the code. Nothing is saved before the code is typed.
        using (Rig rig = new())
        {
            await using Ctx c = await Ctx.NewAsync(host);
            using Cmd<int> cmd = new((port, o, e) => CommandWiring.Setup(rig.State, port));
            await c.Page.GotoAsync(await cmd.LinkAsync());
            await c.Page.Locator("#save").WaitForAsync();
            await c.DemoIntroAsync(c.ScenarioIntroduction());
            s.Check(await c.PasskeyCalls() == 0 && Untouched(rig), "sequence: opening the page asks for no passkey and saves nothing");
            await c.Click("#save");
            await c.Page.Locator("#confirm").WaitForAsync(new() { State = WaitForSelectorState.Visible, Timeout = 20000 });
            s.Check(await c.PasskeyCalls() == 1 && (await c.AuthOps()).Credentials == 1, "sequence: the first prompt made one passkey");
            s.Check(Untouched(rig), "sequence: after the first prompt nothing is saved yet");
            s.Check((await c.Text("#status")).Contains("Now confirm it", StringComparison.Ordinal), "sequence: the page asks for the second prompt");
            (_, long signsBefore) = await c.AuthOps();
            await c.Click("#confirm");
            string code = await c.TextAppears("#code");
            s.Check(await c.PasskeyCalls() == 2 && (await c.AuthOps()).Signs == signsBefore + 1, "sequence: the second prompt is a second passkey tap, a signature by the new passkey over the first manifest");
            string recovery = await c.TextAppears("#recovery");
            s.Check(recovery.Length >= 20 && await c.Page.Locator("#recovery-box").IsVisibleAsync(), "sequence: the recovery code is shown");
            s.Check(Untouched(rig), "sequence: with both prompts done and the code on the page, nothing is saved until the code is typed in the terminal");
            await cmd.WaitPromptAsync();
            int exit = await c.TypeCodeAsync(cmd, code);
            s.Check(exit == 0, "sequence: typing the code finishes the setup");

            bool have = rig.State.TryManifest(out Manifest? manifest, out _);
            s.Check(have && manifest is { Recovery: not null, Version: 1 } && manifest.Keys.Count == 1 && manifest.Keys[0].Admin && manifest.Store.Length > 0, "sequence: the signed state has one admin key, a recovery slot and the secret store key");
            s.Check(rig.State.TryCheck(out _), "sequence: the state passes its own check");
            AuditChecks.Expect(s, rig, "setup");
            s.Check(AuditChecks.Events(rig).Count(name => name == "setup") == 1, "sequence: one audit event records the setup");
            s.Check(!cmd.Err.Text.Contains(recovery, StringComparison.Ordinal) && !cmd.Err.Text.Contains(code, StringComparison.Ordinal), "sequence: neither code is on the terminal");

            // The administration works with that passkey at once: sign in and see the Overview.
            using SpaApp app = new(rig);
            await Spa.SignIn(c, app, s);
            await Spa.Heading(c, "Overview").WaitForAsync(new() { Timeout = 20000 });
            s.Check(true, "sequence: the new passkey signs in to the administration");
            s.NoProblems(c);
        }

        // 2. The person cancels the first prompt: nothing is saved, and Deny ends the command.
        using (Rig rig = new())
        {
            await using Ctx c = await Ctx.NewAsync(host);
            using Cmd<int> cmd = new((port, o, e) => CommandWiring.Setup(rig.State, port));
            await c.Page.GotoAsync(await cmd.LinkAsync());
            await c.Page.Locator("#save").WaitForAsync();
            await c.DemoSnapAsync("A fresh setup. Cancel the Create passkey prompt to return to the form.");
            await c.Presence(false);
            await c.Click("#save");
            await c.StatusContains("Waiting for your passkey");
            s.Check(await c.Page.Locator("#save").IsDisabledAsync() &&
                await c.Page.GetByRole(AriaRole.Button, new() { Name = "Cancel", Exact = true }).CountAsync() == 1,
                "cancel 1: while the first prompt is open there is one Cancel and Create passkey is disabled");
            await c.Click("#deny");
            await c.StatusContains("Cancelled");
            await c.Presence(true);
            await c.QuietAsync();
            s.Check(!cmd.Result.IsCompleted && Untouched(rig) && await c.Page.Locator("#confirm").IsHiddenAsync(), "cancel 1: nothing was saved and the page did not move on");
            await c.Click("#deny");
            s.Check(await cmd.Result.WaitAsync(TimeSpan.FromSeconds(30)) == RunCommand.Denied && Untouched(rig), "cancel 1: Deny ends the command and nothing is set up");
            s.NoProblems(c);
        }

        // 3. The person cancels the second prompt after the passkey was made: still nothing is saved.
        using (Rig rig = new())
        {
            await using Ctx c = await Ctx.NewAsync(host);
            using Cmd<int> cmd = new((port, o, e) => CommandWiring.Setup(rig.State, port));
            await c.Page.GotoAsync(await cmd.LinkAsync());
            await c.Page.Locator("#save").WaitForAsync();
            await c.DemoSnapAsync("Start over with a fresh setup. This time, cancel the confirmation prompt.");
            await c.Click("#save");
            await c.Page.Locator("#confirm").WaitForAsync(new() { State = WaitForSelectorState.Visible, Timeout = 20000 });
            await c.Presence(false);
            await c.Click("#confirm");
            await c.StatusContains("Waiting for your passkey");
            s.Check(await c.Page.Locator("#confirm").IsDisabledAsync() &&
                await c.Page.GetByRole(AriaRole.Button, new() { Name = "Cancel", Exact = true }).CountAsync() == 1,
                "cancel 2: while the second prompt is open there is one Cancel and confirmation is disabled");
            await c.Click("#deny");
            await c.StatusContains("Cancelled");
            await c.Presence(true);
            await c.QuietAsync();
            s.Check(!cmd.Result.IsCompleted && Untouched(rig) && !await c.Page.Locator("#code").IsVisibleAsync(), "cancel 2: no state, no code, although the passkey exists in the authenticator");
            await c.Click("#deny");
            s.Check(await cmd.Result.WaitAsync(TimeSpan.FromSeconds(30)) == RunCommand.Denied && Untouched(rig), "cancel 2: Deny ends the command and nothing is set up");
            s.NoProblems(c);
        }

        // 4. The second prompt is refused (user verification fails): the page says so, nothing is saved, and nothing is shown that could be typed.
        using (Rig rig = new())
        {
            await using Ctx c = await Ctx.NewAsync(host);
            using Cmd<int> cmd = new((port, o, e) => CommandWiring.Setup(rig.State, port));
            await c.Page.GotoAsync(await cmd.LinkAsync());
            await c.Page.Locator("#save").WaitForAsync();
            await c.DemoSnapAsync("In a new attempt, the authenticator refuses the confirmation.");
            await c.Click("#save");
            await c.Page.Locator("#confirm").WaitForAsync(new() { State = WaitForSelectorState.Visible, Timeout = 20000 });
            await c.Verified(false);
            await c.Click("#confirm");
            await c.StatusContains("No passkey was used");
            s.Check(Untouched(rig) && !cmd.Result.IsCompleted && string.IsNullOrWhiteSpace(await c.Page.Locator("#code").TextContentAsync()), "confirmation refused: nothing is saved, there is no code, the command still waits");
            await c.Click("#deny");
            s.Check(await cmd.Result.WaitAsync(TimeSpan.FromSeconds(30)) == RunCommand.Denied && Untouched(rig), "confirmation refused: Deny ends the command and nothing is set up");
            s.NoProblems(c);
        }

        // 5. A passkey without PRF cannot protect the secret store key: refused, with the reason, before anything is stored.
        using (Rig rig = new())
        {
            await using Ctx c = await Ctx.NewAsync(host, hasPrf: false);
            c.Ignore("status of 400"); // the program refuses a passkey without PRF with a 400, which the browser logs
            using Cmd<int> cmd = new((port, o, e) => CommandWiring.Setup(rig.State, port));
            await c.Page.GotoAsync(await cmd.LinkAsync());
            await c.Page.Locator("#save").WaitForAsync();
            await c.DemoSnapAsync("Try a passkey without PRF. Setup requires PRF to protect the store key.");
            await c.Click("#save");
            await c.StatusContains("cannot do PRF");
            int code = await cmd.Result.WaitAsync(TimeSpan.FromSeconds(30));
            s.Check(code != 0 && Untouched(rig) && await c.Page.Locator("#confirm").IsHiddenAsync(), "no PRF: the setup is refused, the page does not go on to the second prompt, nothing is saved (exit " + code + ")");
            s.Check(cmd.Err.Text.Contains("PRF", StringComparison.Ordinal), "no PRF: the terminal says why");
            s.NoProblems(c);
        }

        // 6. The browser is closed between the two prompts. The command ends at its time limit with nothing saved, and a new setup on the same state then works.
        using (Rig rig = new())
        {
            Ctx c = await Ctx.NewAsync(host);
            using (Cmd<int> cmd = SetupWithin(rig, TimeSpan.FromSeconds(10)))
            {
                await c.Page.GotoAsync(await cmd.LinkAsync());
                await c.Page.Locator("#save").WaitForAsync();
                await c.DemoSnapAsync("Close the setup tab after creating the passkey to see how an interrupted setup ends.");
                await c.Click("#save");
                await c.Page.Locator("#confirm").WaitForAsync(new() { State = WaitForSelectorState.Visible, Timeout = 20000 });
                await c.Context.CloseAsync();
                int ended = await cmd.Result.WaitAsync(TimeSpan.FromSeconds(60));
                s.Check(ended != 0 && Untouched(rig), "browser closed: the command ends at its limit and nothing is saved (exit " + ended + ")");
                s.Check(cmd.Err.Text.Contains("nothing was saved", StringComparison.OrdinalIgnoreCase) || cmd.Err.Text.Contains("time", StringComparison.OrdinalIgnoreCase), "browser closed: the terminal says that it stopped without saving (" + cmd.Err.Text.Trim().Split('\n')[^1] + ")");
            }

            await using Ctx again = await Ctx.NewAsync(host);
            using Cmd<int> fresh = new((port, o, e) => CommandWiring.Setup(rig.State, port));
            await again.Page.GotoAsync(await fresh.LinkAsync());
            await again.Page.Locator("#save").WaitForAsync();
            await again.DemoSnapAsync("The interrupted setup expired. Start setup again and complete both prompts.");
            await again.Click("#save");
            await again.Page.Locator("#confirm").WaitForAsync(new() { State = WaitForSelectorState.Visible, Timeout = 20000 });
            await again.Click("#confirm");
            string code = await again.TextAppears("#code");
            await fresh.WaitPromptAsync();
            s.Check(await again.TypeCodeAsync(fresh, code) == 0 && rig.State.TryManifest(out Manifest? manifest, out _) && manifest is { Version: 1 } && manifest.Keys.Count == 1, "browser closed: a new setup on the same folder works and makes exactly one admin passkey");
            s.NoProblems(again);
        }
    }
}

internal static class Scenarios2
{
    private const string Secret = "s3cr3t-e2e-value-1";

    internal static async Task<string> RawState(Rig rig)
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        StringBuilder text = new();
        foreach (string file in Directory.GetFiles(rig.Folder))
        {
            // SQLite removes its -shm and -wal files when the last connection closes, between the listing and the read (Windows then reports access denied).
            try
            {
                using FileStream stream = new(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                byte[] bytes = new byte[stream.Length];
                await stream.ReadExactlyAsync(bytes);
                text.Append(System.Text.Encoding.Latin1.GetString(bytes));
            }
            catch (Exception failure) when (failure is FileNotFoundException or UnauthorizedAccessException)
            {
            }
        }

        return text.ToString();
    }

    private static IEnumerable<string> AuditEvents(Rig rig) => AuditChecks.Events(rig);
}

internal static class Scenarios3
{
    private const string Secret = "s3cr3t-e2e-value-1";

    /// <summary>Sets a fixture secret through the page.</summary>
    public static async Task SeedSecret(Rig rig, Ctx c, SpaApp? signedIn = null, string name = "E2E_SECRET")
    {
        // As a person does it: in the admin app, one tap. The session cookie is shared by every localhost port, so a
        // scenario that already has its app signed in seeds through that one.
        using SpaApp? own = signedIn is null ? new SpaApp(rig) : null;
        if (own is not null)
        {
            await Spa.SignIn(c, own, new S("seed"));
        }
        await Spa.GoTo(c, "Secrets", "Secrets");
        await Spa.Click(Spa.Button(c, "Add secret", exact: true));
        await c.Page.GetByLabel("Name").FillAsync(name);
        await c.Page.GetByLabel("Value").FillAsync(Secret);
        await Spa.Click(Spa.Button(c, "Save secret", exact: true));
        await c.Page.GetByText($"Saved {name}.").First.WaitForAsync(new() { Timeout = 20000 });
    }

    public static async Task RunApproval(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        await SeedSecret(rig, c);
        rig.WriteScript("check", "script-value");
        using SpaApp app = new(rig, unlocked: false, timeLimit: TimeSpan.FromSeconds(12));
        await Spa.Unlock(c, app, s);
        await Spa.SignIn(c, app, s);
        await Spa.StartDemoFromOverview(c);

        // 1. A script file: the request shows its contents; approve once; the program output appears.
        using (Cmd<int> run = Cmds.Run(rig, "E2E_SECRET", Rig.ScriptCommand("check"), app: app))
        {
            await Spa.OpenRequest(c, run, app, s);
            string request = await c.Page.Locator("main").InnerTextAsync();
            s.Check(request.Contains(Rig.ScriptEcho("script-value")), "the request shows the script contents");
            s.Check(request.Split(ApprovalSummary.ScriptBoundary, StringSplitOptions.None).Length == 2 &&
                run.Err.Text.Contains(ApprovalSummary.ScriptBoundary, StringComparison.Ordinal),
                "the request and terminal explain that other files can run with their current contents");
            s.Check(request.Contains("E2E_SECRET") && request.Contains(Rig.ScriptFile("check")), "the request shows the secret name and the command");
            int before = await c.PasskeyCalls();
            s.Check(!(await Spa.Button(c, "Approve once", exact: true).IsEnabledAsync()) || before == 1, "tap rule: opening the request asks for no passkey");
            await Spa.ApproveOnce(c);
            int exit = await run.Result.WaitAsync(TimeSpan.FromSeconds(30));
            s.Check(exit == 0, "run exit code 0 (the program's own)");
            s.Check(run.Out.Text.Contains("script-value=" + StreamRedactor.Mask), "the program ran with the decrypted secret and its output was redacted");
            s.Check(!run.Out.Text.Contains(Secret) && !run.Err.Text.Contains(Secret), "the secret value is never printed");
            s.Check(await c.PasskeyCalls() == before + 1, "approving used the passkey exactly once");
            await c.Page.GetByText("Approved.").First.WaitForAsync(new() { Timeout = 20000 });
            await c.DemoSnapAsync("The approved command ran. The terminal redacts the secret from its output.");
        }

        // 2. Inline code: the request shows it, approve once, the output is redacted.
        using (Cmd<int> run = Cmds.Run(rig, "E2E_SECRET", Rig.InlineCommand, app: app))
        {
            await Spa.OpenRequest(c, run, app, s);
            await c.DemoSnapAsync("When code is supplied inline, it appears with the command in the review.");
            string request = await c.Page.Locator("main").InnerTextAsync();
            s.Check(!request.Contains("Code it runs") && request.Contains(Rig.InlineCode), "the request shows the inline code once, in the Runs line");
            await Spa.ApproveOnce(c);
            s.Check(await run.Result.WaitAsync(TimeSpan.FromSeconds(30)) == 0, "inline run exit code 0");
            s.Check(run.Out.Text.Contains("inline-" + StreamRedactor.Mask) && !run.Out.Text.Contains(Secret), "inline run output is redacted");
        }

        // 3. Deny: nothing runs.
        using (Cmd<int> run = Cmds.Run(rig, "E2E_SECRET", Rig.ScriptCommand("check"), app: app))
        {
            await Spa.OpenRequest(c, run, app, s);
            ILocator deny = Spa.Button(c, "Deny", exact: true);
            await c.DemoPressAsync(deny, "Select Deny to refuse this request.");
            await Spa.Click(deny);
            int exit = await run.Result.WaitAsync(TimeSpan.FromSeconds(30));
            s.Check(exit == RunCommand.Denied, "denied run exits with the denied code (" + exit + ")");
            s.Check(run.Out.Text.Length == 0, "nothing ran after Deny");
            await c.Page.GetByText("Denied.").First.WaitForAsync(new() { Timeout = 20000 });
            await c.DemoSnapAsync("The request is denied and the command did not run.");
        }

        // 4. Timeout: nobody answers; the run is denied at the limit and the request page says it expired.
        string expiredLink;
        using (Cmd<int> run = Cmds.Run(rig, "E2E_SECRET", Rig.ScriptCommand("check"), app: app))
        {
            expiredLink = await run.LinkAsync();
            int exit = await run.Result.WaitAsync(TimeSpan.FromSeconds(30));
            s.Check(exit == RunCommand.Denied && run.Out.Text.Length == 0, "an unanswered run is denied at the time limit and nothing ran");
            s.Check(run.Err.Text.Contains("time limit"), "the terminal says it was the time limit");
        }

        await c.Page.GotoAsync(expiredLink);
        await c.Page.GetByText("This request expired.").First.WaitForAsync(new() { Timeout = 20000 });
        await c.DemoSnapAsync("An unanswered request expires. The command stops without running.");
        s.Check(await Spa.Button(c, "Approve once", exact: true).CountAsync() == 0, "an expired request cannot be approved");

        IReadOnlyList<AuditEvent> events = AuditChecks.All(rig);
        s.Check(events.Count(e => e.Type == AuditEventTypes.Authorization && e.Outcome == "denied") >= 2, "audit records the Deny and the time limit as denials");
        s.Check(events.Count(e => e.Type == AuditEventTypes.Authorization && e.Outcome == "approved") >= 2, "audit records both approvals");
        s.NoProblems(c);
    }

    /// <summary>
    /// M6: a project .env that sets variables which change how the program loads code or where it sends data. The page shows one prominent warning section
    /// before the approve control, with every name, its visible value (escaped, never HTML) and a reason; axe finds no WCAG 2.2 A/AA violation at desktop and phone width.
    /// </summary>
    public static async Task CodeChanges(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        await SeedSecret(rig, c);
        rig.WriteScript("check", "script-value");
        File.WriteAllText(Path.Combine(rig.Work, ".env"), "NODE_OPTIONS=--require ./hook.js\nHTTPS_PROXY=http://proxy.example:3128\nLD_LIBRARY_PATH=/opt/lib\nGIT_SSH_COMMAND=ssh -o \"<img src=x onerror=alert(1)>\" & <b>\nLOG_LEVEL=quiet\n");

        using SpaApp app = new(rig, unlocked: false);
        await Spa.Unlock(c, app, s);
        await Spa.SignIn(c, app, s);
        await Spa.StartDemoFromOverview(c);
        using Cmd<int> run = Cmds.Run(rig, "E2E_SECRET", Rig.ScriptCommand("check"), app: app);
        await Spa.OpenRequest(c, run, app, s);
        ILocator warning = c.Page.GetByRole(AriaRole.Region, new() { Name = "Code changes" });
        await c.DemoSnapAsync("Review environment settings that can change what the program loads or where it sends data.");
        s.Check(await warning.CountAsync() == 1, "exactly one warning is on the page");
        string warned = await warning.InnerTextAsync();
        s.Check(warned.Contains("This changes how the program loads code or where it sends data"), "the warning has its heading");
        foreach (string expected in new[] { "NODE_OPTIONS=--require ./hook.js", "HTTPS_PROXY=http://proxy.example:3128", "LD_LIBRARY_PATH=/opt/lib", "GIT_SSH_COMMAND=", "loads code", "library path", "network traffic", "git" })
        {
            s.Check(warned.Contains(expected, StringComparison.Ordinal), "the warning shows " + expected);
        }

        string main = await c.Page.Locator("main").InnerTextAsync();
        s.Check(!warned.Contains("LOG_LEVEL") && main.Contains("LOG_LEVEL"), "an ordinary variable is not in the warning");
        s.Check(warned.Contains("<img src=x onerror=alert(1)>") && await c.Page.Locator("main img, main b").CountAsync() == 0, "a value with HTML is shown as text, never as markup");
        bool before = await c.Page.EvaluateAsync<bool>("() => { const w = document.querySelector('[role=region]'); const a = [...document.querySelectorAll('button')].find((x) => x.textContent.trim() === 'Approve once'); return !!w && !!a && !!(w.compareDocumentPosition(a) & Node.DOCUMENT_POSITION_FOLLOWING); }");
        s.Check(before, "the warning comes before the approve control in the page");
        s.Check(await c.PasskeyCalls() == 0, "tap rule: opening the request asked for no passkey");
        await Spa.Axe(c, s, "the run request with the warning (desktop)");
        await c.Page.SetViewportSizeAsync(375, 667);
        await Spa.Axe(c, s, "the run request with the warning (phone width)");
        bool scrolls = await c.Page.EvaluateAsync<bool>("() => document.documentElement.scrollWidth > window.innerWidth + 1");
        s.Check(!scrolls, "the page does not scroll sideways at phone width");
        await c.Page.SetViewportSizeAsync(1280, 800);
        await Spa.Click(Spa.Button(c, "Deny", exact: true));
        await run.Result.WaitAsync(TimeSpan.FromSeconds(30));
        await c.Page.GetByText("Denied.").First.WaitForAsync();
        await c.DemoSnapAsync("This example denies the request after reviewing the environment changes.");
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
        await c.StartDemoAsync();

        using Cmd<int> cmd = Cmds.Rotate(rig);
        string link = await cmd.LinkAsync();
        await c.Page.GotoAsync(link);
        string firstUrl = c.Page.Url;
        string request = await c.TextAppears("#request");
        await c.DemoSnapAsync("Start key rotation from Settings. Review which passkey will stay before approving with an admin passkey.");
        s.Check(request.Contains("Only the key you tap now stays"), "page 1 explains the rotation");
        await c.Click("#approve");
        await c.Page.WaitForURLAsync(u => u != firstUrl, new() { Timeout = 20000 });
        string request2 = await c.TextAppears("#request");
        await c.DemoSnapAsync("Review the new store and passkey state, then confirm the rotation.");
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
        await c.DemoSnapAsync("Rotation is complete. Save the new recovery code.");

        // The old recovery code stops working: the recovery page does not accept it (its 400 reply is expected in the console).
        c.Ignore("status of 400");
        using Cmd<int> again = new((port, o, e) => CommandWiring.Recover(rig.State, port));
        await c.Page.GotoAsync(await again.LinkAsync());
        string recoverUrl = c.Page.Url;
        await c.Page.FillAsync("#recovery-code", first.Recovery);
        await c.Click("#unlock");
        // The refusal is shown and the button is ready again: the attempt is over and the page stayed.
        await c.Page.WaitForFunctionAsync("() => document.getElementById('status').textContent.trim().length > 0 && !document.getElementById('unlock').disabled", null, new() { Timeout = 20000 });
        string why = await c.Text("#status");
        await c.DemoSnapAsync("The old recovery code is refused. Use the replacement code for future recovery.");
        s.Check(c.Page.Url == recoverUrl && !(await c.Page.TitleAsync()).Contains("Set up"), "the old recovery code is refused: the page does not move on (" + why + ")");
        await c.Click("#deny");
        s.Check(await again.Result.WaitAsync(TimeSpan.FromSeconds(30)) != 0, "--recover with the old code does not succeed");
        AuditChecks.Expect(s, rig, "setup", "secrets-set", "key-rotated", "change-denied");
        s.Check(rig.State.TryManifest(out Manifest? after, out _) && after!.Keys.Count == 1 && !Directory.GetFiles(rig.Folder, "arcana-guardian.db.recovered-*").Any(), "state is unchanged by the refused recovery");

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
        await c.StartDemoAsync();

        await c.ClearCredentials(); // every passkey is lost: that is why --recover is used
        using Cmd<int> cmd = new((port, o, e) => CommandWiring.Recover(rig.State, port));
        await c.Page.GotoAsync(await cmd.LinkAsync());
        await c.DemoSnapAsync("Run using-secrets --recover in your terminal. On the page it opens, enter your saved recovery code.");
        s.Check(await c.PasskeyCalls() == 0, "tap rule: no prompt on the recovery page");
        string url1 = c.Page.Url;
        await c.Page.FillAsync("#recovery-code", first.Recovery);
        await c.Click("#unlock");
        await c.Page.WaitForURLAsync(u => u != url1, new() { Timeout = 20000 });
        s.Check((await c.Page.TitleAsync()).Contains("Set up") && cmd.LinkCount == 1, "the code page led by itself to the new passkey page, still one link");
        s.Check(await c.PasskeyCalls() == 0, "tap rule: the new passkey page makes no prompt on load");
        await c.DemoSnapAsync("Create a replacement admin passkey and confirm it to restore access.");
        await c.Click("#save");
        await c.Click("#confirm");
        string code = await c.TextAppears("#code");
        string recovery = await c.TextAppears("#recovery");
        s.Check(recovery != first.Recovery, "the final page shows a new recovery code");
        await cmd.WaitPromptAsync();
        s.Check(cmd.Err.Text.EndsWith(TerminalPrompt.Waiting, StringComparison.Ordinal) && cmd.LinkCount == 1, "the terminal prompt is the last thing shown; still one link");
        int exit = await c.TypeCodeAsync(cmd, code);
        s.Check(exit == 0, "--recover exit code 0");
        s.Check(!cmd.Err.Text.Contains(code) && !cmd.Err.Text.Contains(recovery) && !cmd.Err.Text.Contains(first.Recovery), "no code is printed on the terminal");
        s.Check(Directory.GetFiles(rig.Folder, "arcana-guardian.db.recovered-*").Count(path => !path.EndsWith("-wal", StringComparison.Ordinal) && !path.EndsWith("-shm", StringComparison.Ordinal)) == 1,
            "recovery takes one snapshot of the previous database");
        s.Check(rig.State.TryManifest(out Manifest? manifest, out _) && manifest!.Keys.Count == 1 && manifest.Recovery is not null, "new state: one key and a recovery slot");
        s.Check(rig.Store.ListNames().SequenceEqual(["E2E_SECRET"]), "the secret was carried over");
        await c.DemoSnapAsync("Recovery finished. The existing secrets were carried over. Save the new recovery code for future use.");
        // The folder holds the events of the first setup and its secret too; the recovery adds the setup of the new state and "recovered" (recorded when the swap succeeded).
        AuditChecks.Expect(s, rig, "setup", "secrets-set", "setup", "recovered");
    }
}

internal static class Scenarios6
{
    internal static async Task ShowPasskeysEntry(Ctx c, string caption)
    {
        await c.Page.GetByRole(AriaRole.Navigation, new() { Name = "Main" })
            .GetByRole(AriaRole.Link, new() { Name = "Passkeys", Exact = true }).ClickAsync();
        await Spa.Heading(c, "Passkeys").WaitForAsync();
        ILocator passkey = c.Page.GetByRole(AriaRole.Table, new() { Name = "Enrolled passkeys" }).GetByRole(AriaRole.Button, new() { Name = "View passkey" }).First;
        await c.DemoPressAsync(passkey, "The Passkeys list shows each credential's role and creation date. Select one to see its details.");
        await passkey.ClickAsync();
        ILocator details = Spa.Dialog(c);
        await details.GetByText("Kind", new() { Exact = true }).WaitForAsync();
        await c.DemoSnapAsync("Passkey details explain what the role can do and give admins a place to remove that credential.");
        await details.GetByRole(AriaRole.Button, new() { Name = "Close", Exact = true }).ClickAsync();
        ILocator add = Spa.Button(c, "Add passkey", exact: true);
        await add.WaitForAsync();
        await c.DemoPressAsync(add, caption);
    }

    public static async Task EnrollSameHost(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using (SpaApp fixtureApp = new(rig))
        {
            await Spa.SignIn(c, fixtureApp, new S("seed"));
            await Scenarios3.SeedSecret(rig, c, fixtureApp);
            if (c.IsDemo)
            {
                // The secret is a fixture for the approval at the end of the walkthrough.
                await Spa.StartDemoFromOverview(c);
                await ShowPasskeysEntry(c, "Start in Passkeys and choose Add passkey. Confirm the request with your admin passkey, then continue to the enrollment page.");
            }
            await c.Page.GotoAsync("about:blank");
        }
        using Cmd<int> cmd = Cmds.Enroll(rig);
        await c.Page.GotoAsync(await cmd.LinkAsync());
        string url1 = c.Page.Url;
        s.Check((await c.Text("#request")).Contains("Add a"), "page 1 asks an admin key to approve the new passkey");
        await c.DemoSnapAsync("The enrollment page asks your current admin passkey to approve adding the new one.");
        s.Check(await c.PasskeyCalls() == 0, "tap rule: no prompt on page 1");
        string adminAuth = c.AuthId;
        string second = await c.AddAuthenticator(false, "usb"); // Chrome allows one internal authenticator: the second device is a security key
        await c.Presence(false, second); // only the admin's device answers the approval
        await c.Click("#approve");
        await c.Page.WaitForURLAsync(u => u != url1, new() { Timeout = 20000 });
        s.Check((await c.Page.TitleAsync()).Contains("Add a passkey") && cmd.LinkCount == 1, "page 1 led by itself to the new passkey page; one link");
        s.Check(await c.PasskeyCalls() == 0, "tap rule: no prompt on the new passkey page load");
        await c.Page.FillAsync("#f-key-name", "second key");
        await c.DemoSnapAsync("On the Add a passkey page, name the new passkey and select Create passkey.");
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
        int exit = await c.TypeCodeAsync(cmd, code);
        s.Check(exit == 0, "--enroll exit code 0");
        s.Check(!cmd.Err.Text.Contains(code), "the code is not printed");
        AuditChecks.Expect(s, rig, "setup", "secrets-set", "key-enrolled");
        s.Check(rig.State.TryManifest(out Manifest? manifest, out _) && manifest!.Keys.Count == 2 && manifest.Keys.Count(k => k.Admin) == 1 && manifest.Keys.Any(k => k.Name == "second key" && !k.Admin), "state: two keys, the new one is not an admin");

        using SpaApp app = new(rig, unlocked: false);
        await Spa.Unlock(c, app, s);

        // The convenience key approves after the admin has unlocked the authority.
        await c.Presence(false, adminAuth);
        await c.Presence(true, second);
        rig.WriteScript("show", "got");
        await Spa.SignIn(c, app, s);
        (int _, long signsFirst) = await c.AuthOps(adminAuth);
        (int _, long signsSecond) = await c.AuthOps(second);
        using (Cmd<int> run = Cmds.Run(rig, "E2E_SECRET", Rig.ScriptCommand("show"), app))
        {
            await Spa.OpenRequest(c, run, app, s);
            await Spa.ApproveFor(c, "Approve for 1 hour");
            s.Check(await run.Result.WaitAsync(TimeSpan.FromSeconds(30)) == 0 && run.Out.Text.Contains("got=" + StreamRedactor.Mask), "the passkey without PRF approved the run and the secret was released");
        }

        AuthorityStore store = rig.Machine.Deployment.Store;
        GrantRecord grant = store.Grants().Single(item => item.Usage == GrantUsage.Reusable);
        await Spa.GoTo(c, "Access", "Access");
        await Spa.Button(c, "View grant " + grant.Id).ClickAsync();
        await Spa.Button(c, "Extend grant " + grant.Id).ClickAsync();
        ILocator dialog = Spa.Dialog(c);
        await dialog.GetByLabel("Minutes to add to the present end").FillAsync("30");
        long beforeExtend = (await c.AuthOps(second)).Signs;
        await Spa.Continue(c, s, dialog);
        await Spa.PageFeedback(c).WaitForAsync(new() { Timeout = 20000 });
        GrantRecord? changed = store.FindGrant(grant.Id);
        s.Check(grant.Expires is { } previous && changed?.Expires == previous.AddMinutes(30), "the convenience passkey extended the same grant by 30 minutes");
        s.Check(beforeExtend > signsSecond && (await c.AuthOps(second)).Signs > beforeExtend && (await c.AuthOps(adminAuth)).Signs == signsFirst, "the approval and extension both came from the device without PRF");
        AuditChecks.Expect(s, rig, "setup", "secrets-set", "key-enrolled", "authorization-approved", "launch-started", "execution-exited");
        IReadOnlyList<AuditEvent> events = AuditChecks.All(rig);
        AuditEvent? written = events.SingleOrDefault(item => item.Outcome == "secrets-set");
        s.Check(written is not null && written.Verify(E2EAudit.KeyFor(rig.Folder).PublicKey)
            && written.Meta.GetValueOrDefault("keyId") == manifest!.Keys.Single(key => key.Admin).Id
            && written.Meta.GetValueOrDefault("keyAdmin") == "true", "the signed secret-change event names the admin credential");
        s.Check(changed?.ChangedKey is { Admin: false, Name: "second key" }, "the grant records who extended it");
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
        using SpaApp app = new(rig);
        if (c.IsDemo)
        {
            await Spa.SignIn(c, app, new S("demo sign-in"));
            await Spa.StartDemoFromOverview(c);
            await Spa.GoTo(c, "Settings", "Settings", capture: false);
            ILocator address = c.Page.GetByLabel("Address of the pages", new() { Exact = false });
            await address.WaitForAsync();
            await c.DemoPressAsync(address, "In Settings, find Approval pages. The address for another host name needs HTTPS. This example tries an HTTP address.");
            await Scenarios6.ShowPasskeysEntry(c, "Open Passkeys and choose Add passkey. Confirm with your current admin passkey to reach the enrollment review.");
        }

        using Cmd<ApprovalDecision> cmd = new((port, o, e) =>
        {
            ApprovalSettings remote = new("http://ws.localhost:" + port, port, TimeSpan.FromSeconds(60));
            (EnrollmentTarget primary, EnrollmentTarget other) = CommandWiring.Targets(rig.State, remote, TerminalPrompt.Line, CommandWiring.CodeReader("Press Ctrl+C to cancel."));

            ApprovalDecision decision = new Enrollment(primary, other, TerminalPrompt.Line, rig.State.Audit).Enroll();
            TerminalPrompt.Final(decision.Detail);

            return decision;
        });
        string link = await cmd.LinkAsync();
        s.Check(new Uri(link).Host == "localhost" && cmd.LinkCount == 1, "the one link is at the admin key's host (localhost)");
        await c.Page.GotoAsync(link);
        s.Check(await c.PasskeyCalls() == 0, "tap rule: no prompt on page 1");
        await c.DemoSnapAsync("The review opens at the current admin passkey’s host. Check the destination address before approving with the current passkey.");
        c.Ignore("ERR_CONNECTION_REFUSED");
        await c.Click("#approve");
        ApprovalDecision result = await cmd.Result.WaitAsync(TimeSpan.FromSeconds(30));
        s.Check(!result.Approved && result.Detail.Contains("https address or localhost"), "the program refuses the non-https cross host and says why (" + result.Detail + ")");
        s.Check(rig.State.TryManifest(out Manifest? manifest, out _) && manifest!.Keys.Count == 1, "nothing was enrolled");
        s.Check(AuditChecks.All(rig).Any(e => e.Type == AuditEventTypes.Admin && e.Outcome == AdminEvent.ChangeDenied && e.Reason.Contains("https address or localhost")), "audit records the refusal");
        if (c.IsDemo)
        {
            try
            {
                await c.Page.WaitForURLAsync(url => url.StartsWith("http://ws.localhost:", StringComparison.Ordinal)
                    || url.StartsWith("chrome-error:", StringComparison.Ordinal), new() { WaitUntil = WaitUntilState.Commit, Timeout = 10000 });
            }
            catch (PlaywrightException error) when (error.Message.Contains("ERR_CONNECTION_REFUSED", StringComparison.Ordinal))
            {
                // The server refuses the HTTP handoff. Chromium may report the failed navigation before showing its error page.
            }
            await c.Page.GotoAsync(app.Url + "/passkeys");
            await Spa.Heading(c, "Passkeys").WaitForAsync();
            await c.DemoSnapAsync("Enrollment stopped because the other host uses HTTP. Only the original passkey is listed. Set an HTTPS address and start again.");
        }
        s.NoProblems(c);
    }
}

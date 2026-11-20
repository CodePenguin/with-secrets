using System.Text.RegularExpressions;
using Microsoft.Playwright;

namespace WithSecrets.E2E;

/// <summary>Page behaviours: Cancel and retry, resend after an aborted POST, a lost reply, the Continue fallback, the tap rule.</summary>
internal static class ScenariosH
{
    private static async Task<(Rig Rig, Ctx C)> Fixture(Host host)
    {
        Rig rig = new();
        Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        await Scenarios3.SeedSecret(rig, c);
        rig.WriteScript("show", "got");

        return (rig, c);
    }

    private static Cmd<int> ShowRun(Rig rig) => Cmds.Run(rig, "E2E_SECRET", Rig.ScriptCommand("show"));

    /// <summary>Cancel while the passkey prompt is pending, a refused passkey (NotAllowedError), and a retry that works.</summary>
    public static async Task CancelAndRetry(Host host, S s)
    {
        (Rig rig, Ctx c) = await Fixture(host);
        using Rig _ = rig;
        using Cmd<int> run = ShowRun(rig);
        await c.Page.GotoAsync(await run.LinkAsync());
        await c.TextAppears("#request");

        // 1. The device refuses (user verification fails): a clear message, nothing is sent, and the page can try again.
        await c.Verified(false);
        await c.Click("#approve");
        await c.StatusContains("No passkey was used");
        string refused = await c.Text("#status");
        s.Check(refused.Contains("NotAllowedError", StringComparison.Ordinal), "a refused passkey shows the browser's error name (" + refused.Split('.')[0] + ")");
        s.Check(!refused.Contains("Diagnostics:", StringComparison.Ordinal), "no Diagnostics line for a passkey that was refused (only after a failed post)");
        s.Check(!run.Result.IsCompleted, "the program is still waiting after the refusal");
        s.Check(await c.Page.Locator("#approve").IsEnabledAsync() && await c.Page.Locator("#deny").IsEnabledAsync(), "the buttons are usable again");

        // 2. Deny ends it. (A retry after a refused passkey is not tested: after a user-verification failure the Chromium virtual
        // authenticator keeps refusing, even once verification is switched back on; see the report.)
        await c.Click("#deny");
        s.Check(await run.Result.WaitAsync(TimeSpan.FromSeconds(30)) == RunCommand.Denied && run.Out.Text.Length == 0, "Deny after the refusal ends the run with nothing run");

        // 3. A prompt nobody answers: the tapped button reads Cancel; Cancel abandons the attempt and sends nothing.
        // (Chromium keeps the abandoned request open, so an immediate second tap says "A request is already pending": a hand test on real devices.)
        using Cmd<int> second = ShowRun(rig);
        await c.Page.GotoAsync(await second.LinkAsync());
        await c.TextAppears("#request");
        await c.Presence(false);
        await c.Click("#approve");
        await c.StatusContains("Waiting for your passkey");
        s.Check(await c.Text("#approve") == "Cancel", "while the prompt is pending the tapped button reads Cancel");
        await c.Click("#approve");
        await c.StatusContains("Cancelled");
        s.Check((await c.Text("#approve")).StartsWith("Approve", StringComparison.Ordinal), "after Cancel the button is Approve again");
        await c.Presence(true);
        await c.QuietAsync();
        s.Check(!second.Result.IsCompleted && !(await c.Text("#status")).Contains("Approved"), "the abandoned attempt, once it ended, sent nothing to the program");
        await c.Click("#deny");
        s.Check(await second.Result.WaitAsync(TimeSpan.FromSeconds(30)) == RunCommand.Denied && second.Out.Text.Length == 0, "Deny after a Cancel ends the run with nothing run");
        s.NoProblems(c);
    }

    /// <summary>The first proof POST is aborted before it reaches the program: the page shows Diagnostics, resends, and the run is approved once.</summary>
    public static async Task ResendAfterAbort(Host host, S s)
    {
        (Rig rig, Ctx c) = await Fixture(host);
        using Rig _ = rig;
        using Cmd<int> run = ShowRun(rig);
        c.Ignore("net::ERR");
        int posts = 0;
        string statusAtResend = "";
        await c.Page.RouteAsync(new Regex("/proof$"), async route =>
        {
            int n = Interlocked.Increment(ref posts);
            if (n == 1)
            {
                await route.AbortAsync();

                return;
            }

            statusAtResend = await c.Text("#status");
            await route.ContinueAsync();
        });
        await c.Page.GotoAsync(await run.LinkAsync());
        await c.TextAppears("#request");
        await c.Click("#approve");
        int exit = await run.Result.WaitAsync(TimeSpan.FromSeconds(40));
        s.Check(exit == 0 && run.Out.Text.Contains("got=" + StreamRedactor.Mask), "the run was approved by the resent POST and ran");
        s.Check(posts == 2, "the page sent the proof twice (the first was aborted): " + posts);
        s.Check(statusAtResend.Contains("retry 2 of 3") && statusAtResend.Contains("Diagnostics:") && statusAtResend.Contains("attempt 1"), "after the failed post the status shows the retry and the Diagnostics line");
        await c.StatusContains("Approved");
        s.Check(!(await c.Text("#status")).Contains("Diagnostics:", StringComparison.Ordinal), "the Diagnostics line is gone after success");
        s.Check(run.Out.Text.Split("got=").Length == 2, "the program ran exactly once");
        s.NoProblems(c);
    }

    /// <summary>The program processed the last reply but it never reached the page: the identical resend gets the same reply (the same code).</summary>
    public static async Task LostReply(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        c.Ignore("net::ERR");
        string? droppedCode = null;
        int withCode = 0;
        await c.Page.RouteAsync(new Regex("/sign$"), async route =>
        {
            IAPIResponse response = await route.FetchAsync();
            string body = await response.TextAsync();
            if (body.Contains("\"code\"", StringComparison.Ordinal) && Interlocked.Increment(ref withCode) == 1)
            {
                droppedCode = System.Text.Json.JsonDocument.Parse(body).RootElement.GetProperty("code").GetString();
                await route.AbortAsync(); // the program answered; the reply is lost

                return;
            }

            await route.FulfillAsync(new() { Response = response, Body = body });
        });
        using Cmd<int> cmd = new((port, o, e) => CommandWiring.Setup(rig.State, port));
        await c.Page.GotoAsync(await cmd.LinkAsync());
        await c.Click("#save");
        await c.Click("#confirm");
        string code = await c.TextAppears("#code");
        s.Check(withCode >= 2 && droppedCode is not null, "the first reply with the code was dropped and the page asked again");
        s.Check(code == droppedCode, "the identical resend returned the same code");
        s.Check((await c.TextAppears("#recovery")).Length > 10, "and the recovery code");
        s.Check(await c.TypeCodeAsync(cmd, code) == 0, "the code typed in the terminal finished the command");
        s.Check(rig.State.TryManifest(out Manifest? m, out _) && m!.Keys.Count == 1, "state has the key");
        s.NoProblems(c);
    }

    /// <summary>Navigation to the next step is blocked: the page shows the link and a Continue button; Continue then works.</summary>
    public static async Task ContinueFallback(Host host, S s)
    {
        (Rig rig, Ctx c) = await Fixture(host);
        using Rig _ = rig;
        using Cmd<int> cmd = Cmds.Rotate(rig);
        string link = await cmd.LinkAsync();
        c.Ignore("net::ERR");
        // The navigation is blocked the way a page can block one: a beforeunload prompt that the person (here the test) declines.
        bool blocking = true;
        int blocked = 0;
        await c.Page.AddInitScriptAsync("window.addEventListener('beforeunload', function (e) { e.preventDefault(); e.returnValue = ''; });");
        c.Page.Dialog += async (_, dialog) =>
        {
            if (blocking && dialog.Type == "beforeunload")
            {
                Interlocked.Increment(ref blocked);
                await dialog.DismissAsync();
            }
            else
            {
                await dialog.AcceptAsync();
            }
        };
        await c.Page.GotoAsync(link);
        await c.TextAppears("#request");
        // The tap starts a navigation that hangs; Playwright would wait for it, so do not wait for the click to return.
        await c.Click("#approve");
        await c.StatusContains("did not open by itself", 15000);
        s.Check(await c.Page.Locator("#next").IsVisibleAsync() && await c.Page.Locator("#next a").CountAsync() == 1 && await c.Page.Locator("#next button").CountAsync() == 1, "the link and the Continue button are shown");
        s.Check((await c.Text("#next a")).StartsWith("http://localhost:", StringComparison.Ordinal), "the link is the next step's address");
        blocking = false;
        await c.Click("#next button");
        await c.Page.WaitForURLAsync(u => u != link, new() { Timeout = 20000 });
        s.Check(blocked >= 1, "the first navigation was really blocked (" + blocked + " beforeunload prompt declined)");
        await c.TextAppears("#request");
        await c.Click("#approve");
        await c.TextAppears("#recovery", 20000);
        s.Check(await cmd.Result.WaitAsync(TimeSpan.FromSeconds(30)) == 0, "Continue led to the next step and the command finished");
        s.NoProblems(c);
    }

    /// <summary>The tap rule: loading a page never starts a passkey prompt; only a tap does.</summary>
    public static async Task TapRule(Host host, S s)
    {
        (Rig rig, Ctx c) = await Fixture(host);
        using Rig _ = rig;
        (int Credentials, long Signs) baseline = await c.AuthOps();
        async Task Idle(string what, Cmd<int> cmd)
        {
            await c.Page.GotoAsync(await cmd.LinkAsync());
            await c.Page.Locator("#deny").WaitForAsync();
            await c.QuietAsync();
            s.Check(await c.PasskeyCalls() == 0 && await c.AuthOps() == baseline, "no passkey operation on load of the " + what + " page");
            await c.Click("#deny");
            await cmd.Result.WaitAsync(TimeSpan.FromSeconds(30));
        }

        using (Cmd<int> run = ShowRun(rig))
        {
            await Idle("run approval", run);
        }

        using (Cmd<int> rotate = Cmds.Rotate(rig))
        {
            await Idle("rotate-key", rotate);
        }

        s.NoProblems(c);
    }
}

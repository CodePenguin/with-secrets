using Microsoft.Playwright;

namespace ArcanaGuardian.E2E;

/// <summary>Opt-in real browser trust and passkey continuity. Uses system certificate validation throughout.</summary>
internal static class ScenariosBrowserHttps
{
    public static async Task<int> RunAsync(string[] args)
    {
        if (OperatingSystem.IsLinux() && args is ["firefox", var firefoxProfile])
        {
            return await RunFirefoxAsync(firefoxProfile);
        }

        string? profile = OperatingSystem.IsLinux() ? args.FirstOrDefault() : null;
        if (!OperatingSystem.IsWindows() && !(OperatingSystem.IsLinux() && profile is not null))
        {
            Console.Error.WriteLine("Run on Windows with a desktop confirmation, or provide an isolated Chromium NSS directory on Linux.");
            return 2;
        }

        string? channel = OperatingSystem.IsWindows() ? args.FirstOrDefault() ?? "msedge" : "chromium";
        using var rig = new Rig(trusted: false);
        var certificates = new BrowserCertificates(rig.Folder);
        var checks = new S("browser-https");
        string trusted = "";
        string? active = null;
        int port = Rig.FreePort();

        try
        {
            Console.WriteLine("Disposable HTTPS scenario. Verify each Windows confirmation against the printed SHA-1.");
            certificates.Run("setup", true, profile, null, Console.Out);
            using (var initial = certificates.Open()) trusted = BrowserCertificate.Digest(initial);
            await using var host = await Host.StartAsync(channel: channel);
            Console.WriteLine(channel + " " + host.Browser.Version);
            await using var browser = await Ctx.NewAsync(host);

            string approvalOnly;
            string recovery;
            using (var first = new SpaApp(rig, unlocked: false, https: true, browserPort: port))
            {
                recovery = await ScenariosQuickStart.Start(rig, browser, first, checks);
                checks.Check(new Uri(first.Url).Scheme == "https" && await browser.Page.EvaluateAsync<bool>("isSecureContext"),
                    "quick start enrolled and authenticated the administrator over browser-validated HTTPS");
                await Scenarios3.SeedSecret(rig, browser, first);
                approvalOnly = await EnrollApprovalOnlyAsync(rig, browser, first, checks);
            }

            using (var second = new SpaApp(rig, unlocked: false, https: true, browserPort: port))
            {
                using var persisted = certificates.Open();
                checks.Check(BrowserCertificate.Digest(persisted) == trusted, "ordinary restart serves the same certificate");
                await Spa.Unlock(browser, second, checks);
                await Spa.SignIn(browser, second, checks);
            }

            certificates.Run("replace", true, profile, null, Console.Out);
            using (var replacement = certificates.Open()) active = BrowserCertificate.Digest(replacement);
            checks.Check(active != trusted, "the explicit replacement changed the leaf");
            await browser.Page.GotoAsync("about:blank");
            using (var third = new SpaApp(rig, unlocked: false, https: true, browserPort: port))
            {
                await Spa.Unlock(browser, third, checks);
                await Spa.SignIn(browser, third, checks);
                checks.Check(rig.State.TryManifest(out Manifest? manifest, out _) &&
                    manifest!.Keys.All(key => key.RpId == BrowserAddress.Host),
                    "the existing administrator passkey still works at the same origin after replacement");

                await browser.Page.Context.ClearCookiesAsync();
                await browser.Presence(false, browser.AuthId);
                await browser.Presence(true, approvalOnly);
                await Spa.Open(browser, third, "/sign-in", capture: false);
                await Spa.Tap(browser, checks, capture: false);
                rig.WriteScript("https-approval", "approved");
                using var run = Cmds.Run(rig, "E2E_SECRET", Rig.ScriptCommand("https-approval"), third);
                await Spa.OpenRequest(browser, run, third, checks);
                await Spa.ApproveOnce(browser);
                checks.Check(await run.Result.WaitAsync(TimeSpan.FromSeconds(30)) == 0,
                    "the existing approval-only passkey authorizes a launch after certificate replacement");
            }

            await using var recoveryBrowser = await Ctx.NewAsync(host);
            await Scenarios5.RunRecovery(rig, recoveryBrowser, recovery, checks, https: true);
        }
        finally
        {
            try
            {
                certificates.Run("remove", true, profile, null, Console.Out);
            }
            catch
            {
                rig.KeepState = true;
                Console.Error.WriteLine("Preserved lifecycle state for retrying trust cleanup: " + rig.Folder);
                throw;
            }
        }

        foreach (string line in checks.Lines) Console.WriteLine(line);
        Console.WriteLine(checks.Failed == 0 ? "ALL PASSED" : "HTTPS scenario failed");
        return checks.Failed == 0 ? 0 : 1;
    }

    private static async Task<int> RunFirefoxAsync(string profile)
    {
        using var rig = new Rig(trusted: false);
        using var playwright = await Playwright.CreateAsync();
        var certificates = new BrowserCertificates(rig.Folder);
        int port = Rig.FreePort();
        try
        {
            async Task ProbeAsync(string action)
            {
                certificates.Run(action, false, null, profile, Console.Out);
                using var app = new SpaApp(rig, unlocked: false, https: true, browserPort: port);
                await using var context = await playwright.Firefox.LaunchPersistentContextAsync(profile, new() { Timeout = 20000 });
                IPage page = context.Pages[0];
                var response = await page.GotoAsync(app.Url);
                Console.WriteLine((context.Browser?.Version ?? await page.EvaluateAsync<string>("navigator.userAgent")) + " " + action);
                if (response is not { Ok: true } || !await page.EvaluateAsync<bool>("isSecureContext"))
                {
                    throw new InvalidOperationException("Firefox did not load the production HTTPS SPA as a secure context.");
                }
            }

            await ProbeAsync("setup");
            await ProbeAsync("replace");
        }
        finally
        {
            try
            {
                certificates.Run("remove", false, null, profile, Console.Out);
            }
            catch
            {
                rig.KeepState = true;
                Console.Error.WriteLine("Preserved lifecycle state for retrying trust cleanup: " + rig.Folder);
                throw;
            }
        }

        Console.WriteLine("ALL PASSED");
        return 0;
    }

    private static async Task<string> EnrollApprovalOnlyAsync(Rig rig, Ctx browser, SpaApp app, S checks)
    {
        await Spa.GoTo(browser, "Passkeys", "Passkeys", capture: false);
        await Spa.Button(browser, "Add passkey", exact: true).ClickAsync();
        await Spa.Continue(browser, checks, Spa.Dialog(browser));
        var continuation = browser.Page.GetByRole(AriaRole.Link, new() { Name = "Continue to the next passkey page" });
        await continuation.WaitForAsync(new() { Timeout = 20000 });
        await continuation.ClickAsync();
        checks.Check(new Uri(browser.Page.Url).GetLeftPart(UriPartial.Authority) == app.Service.BrowserOrigin,
            "the enrollment continuation uses the same authority HTTPS origin");

        string admin = browser.AuthId;
        string approval = await browser.AddAuthenticator(false, "usb");
        await browser.Presence(false, approval);
        await browser.Click("#approve");
        await browser.Page.Locator("#f-key-name").FillAsync("HTTPS approval-only");
        await browser.Presence(false, admin);
        await browser.Presence(true, approval);
        await browser.Click("#create");
        await browser.Page.Locator("#confirm:not([hidden]):enabled").WaitForAsync();
        await browser.Presence(false, approval);
        await browser.Presence(true, admin);

        var code = new TaskCompletionSource<string?>(TaskCreationOptions.RunContinuationsAsynchronously);
        TerminalPrompt.Input = () => code.Task.WaitAsync(TimeSpan.FromSeconds(20)).GetAwaiter().GetResult();
        TerminalPrompt.Output = TextWriter.Null;
        try
        {
            await browser.Click("#confirm");
            code.TrySetResult(await browser.TextAppears("#code"));
            bool enrolled = false;
            for (int attempt = 0; attempt < 100 && !enrolled; attempt++)
            {
                enrolled = rig.State.TryManifest(out Manifest? manifest, out _) && manifest!.Keys.Any(key =>
                    key.Name == "HTTPS approval-only" && !key.Admin && key.RpId == BrowserAddress.Host);
                if (!enrolled) await Task.Delay(100);
            }

            if (!enrolled) throw new InvalidOperationException("The approval-only passkey was not committed.");
            checks.Check(true, "the approval-only passkey was enrolled through the authority HTTPS listener");
        }
        finally
        {
            code.TrySetResult(null);
            TerminalPrompt.Input = null;
            TerminalPrompt.Output = null;
        }

        return approval;
    }

}

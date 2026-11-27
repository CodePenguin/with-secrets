using Microsoft.Playwright;

namespace WithSecrets.E2E;

internal static class ScenariosQuickStart
{
    public static async Task Start(Rig rig, Ctx browser, SpaApp app, S checks, bool showExample = false, bool desktop = false)
    {
        string? desktopCode = null;
        using Cmd<int> command = new((_, _, _) => CommandWiring.Setup(rig.State, null, app.Service,
            desktopCode: desktop ? code => desktopCode = code : null));
        string link = await command.LinkAsync();
        // Check each button's exact clipboard payload without writing to the desktop clipboard.
        await browser.Context.AddInitScriptAsync("""
            Object.defineProperty(navigator, "clipboard", { value: {
                writeText: async (value) => { window.__copiedSetupCode = value; }
            } });
            """);
        await browser.Page.GotoAsync(link);
        await browser.Page.Locator("#device-fingerprint").WaitForAsync();
        await browser.DemoSnapAsync("Run with-secrets admin in your terminal to open Quick Start.");
        checks.Check((await browser.Page.Locator("header.bar").InnerTextAsync()) == "with-secrets",
            "the setup header shows the product name");
        ILocator name = browser.Page.GetByLabel("Passkey name");
        ILocator verify = browser.Page.Locator("#verify-device");
        checks.Check(app.Service.Lock.IsLocked && await browser.PasskeyCalls() == 0 && await name.IsHiddenAsync() &&
            await browser.Page.Locator("#save").IsHiddenAsync() && !await verify.IsEnabledAsync(),
            "service is running locked and the page offers no passkey before terminal verification");
        string fingerprint = await browser.Text("#device-fingerprint");
        checks.Check(command.Err.Text.Contains(fingerprint, StringComparison.Ordinal) &&
            fingerprint == KeyIdentity.Display(rig.Machine.Deployment.Fingerprint), "same full device fingerprint on the page and terminal");
        IAPIResponse forged = await browser.Context.APIRequest.PostAsync(link + "/create", new()
        {
            Headers = new Dictionary<string, string> { ["Origin"] = "http://localhost:1" },
            Data = "{}",
        });
        checks.Check(forged.Status == 403, "a page on a different origin cannot register a passkey");
        IAPIResponse early = await browser.Context.APIRequest.PostAsync(link + "/create", new()
        {
            Headers = new Dictionary<string, string> { ["Origin"] = new Uri(link).GetLeftPart(UriPartial.Authority) },
            Data = "{}",
        });
        checks.Check(early.Status == 403, "even a same-origin registration is refused until the terminal is verified");
        await browser.DemoSnapAsync("Quick Start shows the device fingerprint and a code for the terminal.");

        string code = (await browser.Text("#quick-code code")).Trim();
        if (desktop)
        {
            checks.Check(desktopCode == code && (await browser.Text("#quick-terminal")).Contains("With Secrets tray menu", StringComparison.Ordinal),
                "desktop setup shows the same code to the tray and directs the user to verify it there");
        }
        else
        {
            await CheckCopy(browser, checks, "#quick-code", "Copy terminal code", code);
        }
        await command.WaitPromptAsync();
        if (browser.IsDemo) await browser.DemoSnapAsync("Enter the six-digit code in the terminal.");
        command.Type(code);
        await browser.Page.WaitForFunctionAsync("() => !document.getElementById('verify-device').disabled");
        checks.Check(await name.IsHiddenAsync() && await browser.PasskeyCalls() == 0,
            "the passkey name stays hidden until the person confirms the fingerprint");
        IAPIResponse beforeFingerprint = await browser.Context.APIRequest.PostAsync(link + "/create", new()
        {
            Headers = new Dictionary<string, string> { ["Origin"] = new Uri(link).GetLeftPart(UriPartial.Authority) },
            Data = "{}",
        });
        checks.Check(beforeFingerprint.Status == 403, "the server requires explicit device verification after accepting the code");
        await browser.DemoSnapAsync("The code is accepted. Compare the full fingerprint, then choose Fingerprint matches.");
        const string background = "element => getComputedStyle(element).backgroundColor";
        string verifyColor = await verify.EvaluateAsync<string>(background);
        string cancelColor = await browser.Page.Locator("#deny").EvaluateAsync<string>(background);
        await browser.Click("#verify-device");
        ILocator create = browser.Page.Locator("#save");
        await create.WaitForAsync(new() { State = WaitForSelectorState.Visible });
        checks.Check(verifyColor != cancelColor && verifyColor == await create.EvaluateAsync<string>(background),
            "the fingerprint confirmation and passkey creation use the same primary color");
        checks.Check(await name.IsVisibleAsync() && await browser.PasskeyCalls() == 0 &&
            (await browser.Page.Locator("[aria-current=step]").TextContentAsync()) == "Create passkey",
            "the second step reveals the passkey name without opening a prompt");
        await browser.DemoSnapAsync("Create passkey is where you can name and create the admin passkey.");
        checks.Check(!command.Result.IsCompleted && app.Service.Lock.IsLocked, "terminal verification alone saves no setup and leaves the service locked");
        await browser.Click("#save");
        await browser.Page.Locator("#confirm").WaitForAsync(new() { State = WaitForSelectorState.Visible });
        checks.Check(await browser.PasskeyCalls() == 1 && rig.State.TryManifest(out Manifest? before, out _) && before is null && app.Service.Lock.IsLocked,
            "creating a passkey does not commit the store");
        checks.Check((await browser.Page.Locator("[aria-current=step]").TextContentAsync()) == "Finish setup" &&
            await browser.Page.Locator("#recovery").IsHiddenAsync(), "Finish setup awaits the second gesture before showing recovery");
        await browser.DemoSnapAsync("The second passkey prompt confirms setup, trusts this device, unlocks, and signs in.");
        await browser.Click("#confirm");
        await browser.Page.Locator("#quick-done").WaitForAsync(new() { State = WaitForSelectorState.Visible });
        checks.Check(await command.Result.WaitAsync(TimeSpan.FromSeconds(20)) == 0 && await browser.PasskeyCalls() == 2,
            "Quick Start finished with two passkey gestures");
        checks.Check(app.Service.Keys?.IsOpen == true && !app.Service.Lock.IsLocked &&
            rig.Machine.Deployment.Store.Find(rig.Machine.Deployment.Fingerprint)?.Status == MachineStatus.Trusted,
            "the final gesture unlocks the service and trusts only the local device");
        checks.Check(rig.Machine.Deployment.HostConfig.Load().Config?.Authority is not null, "Quick Start pins the local authority");
        checks.Check(await browser.Page.Locator("#recovery").IsVisibleAsync() &&
            (await browser.Page.Locator("[aria-current=step]").TextContentAsync()) == "Finish setup", "the recovery code is shown on Finish setup after confirmation");
        await browser.DemoSnapAsync("Setup is complete. Save the one-time recovery code before continuing.");
        await CheckCopy(browser, checks, "#recovery-box", "Copy recovery code", (await browser.Text("#recovery")).Trim());
        if (showExample) await ShowExample(rig, browser, checks);
        await Spa.Click(browser.Page.GetByRole(AriaRole.Link, new() { Name = "Open with-secrets", Exact = true }));
        await Spa.Heading(browser, "Overview").WaitForAsync();
        await browser.DemoSnapAsync("Open with-secrets takes you straight to Overview. You’re already signed in.");
        checks.Check(await browser.PasskeyCalls() == 0, "already signed in on the same browser and no extra prompt");
        checks.Check(!(await browser.Page.Locator("header").InnerTextAsync()).Contains("administration", StringComparison.OrdinalIgnoreCase),
            "the signed-in header uses the product brand without an administration label");
    }

    private static async Task ShowExample(Rig rig, Ctx browser, S checks)
    {
        ILocator example = browser.Page.Locator("#quick-done details");
        ILocator command = example.Locator("pre");
        checks.Check(await command.IsHiddenAsync() && await browser.Page.Locator("#form").IsHiddenAsync(),
            "the example is collapsed and the completed setup controls are hidden");
        await Spa.Click(example.GetByText("See how a secret is used", new() { Exact = true }));
        checks.Check(await command.IsVisibleAsync() && (await command.InnerTextAsync()).Contains("--secrets REPORT_TOKEN", StringComparison.Ordinal),
            "the optional example shows how to request a secret");
        checks.Check(rig.Store.ListNames().Count == 0 && await browser.PasskeyCalls() == 2,
            "viewing the example saves no secret and asks for no additional passkey prompt");
        await browser.DemoSnapAsync("The optional example shows how an approved command gets a secret. You can open the app whenever you are ready.");
    }

    private static async Task CheckCopy(Ctx browser, S checks, string row, string label, string expected)
    {
        await browser.Page.GetByRole(AriaRole.Button, new() { Name = label, Exact = true }).ClickAsync();
        await browser.Page.Locator(row).GetByText("Copied.", new() { Exact = true }).WaitForAsync();
        checks.Check(await browser.Page.EvaluateAsync<string>("() => window.__copiedSetupCode") == expected,
            label + " copies only the displayed code");
    }

    public static async Task FirstRun(Host host, S checks)
    {
        using Rig rig = new(trusted: false);
        await using Ctx browser = await Ctx.NewAsync(host);
        using SpaApp app = new(rig, unlocked: false);
        await Start(rig, browser, app, checks, showExample: true);
        checks.Check(rig.Store.ListNames().Count == 0 && await browser.PasskeyCalls() == 0, "opening the app saves no secret and makes no passkey prompt");
        checks.NoProblems(browser);
        await RefuseWrongCode(host, checks);
    }

    public static async Task DesktopFirstRun(Host host, S checks)
    {
        using Rig rig = new(trusted: false);
        await using Ctx browser = await Ctx.NewAsync(host);
        using SpaApp app = new(rig, unlocked: false);
        await Start(rig, browser, app, checks, desktop: true);
        checks.NoProblems(browser);
    }

    private static async Task RefuseWrongCode(Host host, S checks)
    {
        using Rig rig = new(trusted: false);
        await using Ctx browser = await Ctx.NewAsync(host);
        using SpaApp app = new(rig, unlocked: false);
        using Cmd<int> command = new((_, _, _) => CommandWiring.Setup(rig.State, null, app.Service));
        await browser.Page.GotoAsync(await command.LinkAsync());
        string code = await browser.Text("#quick-code code");
        string wrong = code.StartsWith('0') ? "111111" : "000000";
        await command.WaitPromptAsync();
        command.Type(wrong);
        await command.WaitPromptAsync(TerminalPrompt.Wrong);
        command.Type(wrong);
        command.Type(wrong);
        checks.Check(await command.Result.WaitAsync(TimeSpan.FromSeconds(20)) == RunCommand.Denied, "three wrong codes stop Quick Start");
        checks.Check(await browser.PasskeyCalls() == 0 && app.Service.Lock.IsLocked &&
            rig.State.TryManifest(out Manifest? manifest, out _) && manifest is null &&
            rig.Machine.Deployment.Store.Find(rig.Machine.Deployment.Fingerprint)?.Status == MachineStatus.Pending,
            "wrong codes do not enroll a passkey, trust the device, or unlock");
    }
}

using System.Text.Json;

using Microsoft.Playwright;

namespace ArcanaGuardian.E2E;

/// <summary>The host service of a scenario, serving the embedded administration web application and the API on one loopback origin (a free port).</summary>
internal sealed class SpaApp : IDisposable
{
    public SpaApp(Rig rig, bool unlocked = true, bool machineEndpoint = false, TimeSpan? timeLimit = null, ProviderRegistry? providers = null, bool directApproval = false,
        Func<string, string, string?>? sealBitwarden = null, Func<string, string?>? sealOnePassword = null, Func<string, string?>? sealVault = null)
    {
        Service = HostService.Start(new HostServiceOptions { CommandLineEndpoint = E2EEndpoint.Make(), Lock = unlocked ? AuthorityLock.UnlockedForTests() : null, State = rig.State, Store = rig.Store, Deployment = rig.Machine.Deployment, Port = 0, MachineEndpoint = machineEndpoint ? new MachineListenerOptions { Port = 0 } : null, TimeLimit = timeLimit ?? TimeSpan.FromSeconds(60), ProviderRegistry = providers, SealBitwardenConfiguration = sealBitwarden, SealOnePasswordConfiguration = sealOnePassword, SealVaultConfiguration = sealVault, ApproverFactory = directApproval ? (settings, announce) => CommandWiring.RunApprover(rig.State, settings, announce) : null });
    }

    public HostService Service { get; }

    /// <summary>The address of the application as a person types it (a loopback name, the service's port).</summary>
    public string Url => $"http://localhost:{Service.Port}/admin";

    public void Dispose() => Service.Dispose();
}

/// <summary>The SPA prepares each challenge, and the final confirmation gesture invokes the browser's virtual authenticator in the same page.</summary>
internal static class Spa
{
    private static string? _axe;

    public static ILocator Heading(Ctx c, string name) => c.Page.GetByRole(AriaRole.Heading, new() { Name = name, Level = 1 });

    public static ILocator Button(Ctx c, string name, bool exact = false) => c.Page.GetByRole(AriaRole.Button, new() { Name = name, Exact = exact });

    public static ILocator Dialog(Ctx c) => c.Page.GetByRole(AriaRole.Dialog);

    /// <summary>The dialog has asked the authority for its passkey challenge and offers the confirmation.</summary>
    public static Task WaitForPasskeyStep(ILocator dialog) => dialog.Locator("xpath=self::*[@data-step='waiting']").WaitForAsync(new() { Timeout = 20000 });

    public static async Task Open(Ctx c, SpaApp app, string path = "", bool capture = true)
    {
        await c.Page.GotoAsync(app.Url + path);
        if (!c.IsDemo || !capture) return;
        // The picture is taken once the app has drawn its first screen, not while the previous page is still showing.
        try { await c.Page.WaitForFunctionAsync("() => !!document.querySelector('h1')", null, new() { Timeout = 5000 }); }
        catch (TimeoutException) { /* A screen without a heading is pictured as it is. */ }
        await c.DemoCaptionAsync("Open Arcana Guardian.");
    }

    /// <summary>Follows a link of the main navigation and waits for the view's heading.</summary>
    public static async Task GoTo(Ctx c, string navName, string heading, bool capture = true)
    {
        ILocator nav = c.Page.GetByRole(AriaRole.Navigation, new() { Name = "Main" });
        ILocator link = nav.GetByRole(AriaRole.Link, new() { Name = navName, Exact = true });
        if (!await link.IsVisibleAsync())
        {
            await nav.GetByRole(AriaRole.Button, new() { Name = "Menu" }).ClickAsync();
            await link.WaitForAsync();
        }

        if (capture) await c.DemoPressAsync(link, $"Open {navName}.");
        await link.ClickAsync();
        await Heading(c, heading).WaitForAsync();
    }

    /// <summary>Completes the prepared in-page sign-in with a user gesture that directly invokes WebAuthn.</summary>
    public static async Task Tap(Ctx c, S s, string linkName = "Sign in with passkey", Func<IPage, string, Task>? beforeTap = null, bool capture = true)
    {
        ILocator signIn = c.Page.GetByRole(AriaRole.Link, new() { Name = "Sign in", Exact = true });
        if (await signIn.IsVisibleAsync()) await signIn.ClickAsync();
        if (beforeTap is not null) await beforeTap(c.Page, "starts an administrator session");
        ILocator button = c.Page.GetByRole(AriaRole.Button, new() { Name = linkName, Exact = true });
        await button.WaitForAsync(new() { Timeout = 20000 });
        if (capture) await c.DemoPressAsync(button, $"Select {linkName}, then use your passkey.");
        await button.ClickAsync(new() { Timeout = 20000 });
        Clicks++;
        await Heading(c, "Overview").WaitForAsync(new() { Timeout = 20000 });
        await Button(c, "Sign out", exact: true).WaitForAsync(new() { Timeout = 20000 });
        s.Check(!c.Page.Url.EndsWith("/sign-in", StringComparison.Ordinal), "sign-in returns to the Admin view in the same tab");
    }

    /// <summary>
    /// Gets the dialog to its confirm step while the SPA stays loaded. A change that needs nothing typed has its challenge prepared as the dialog opens; one with a form
    /// is prepared by Continue (a click). The next gesture invokes WebAuthn.
    /// </summary>
    public static async Task<IPage> OpenPasskeyPage(Ctx c, S s, ILocator dialog, bool capture = true)
    {
        string before = c.Page.Url;
        ILocator next = dialog.GetByRole(AriaRole.Button, new() { Name = "Continue", Exact = true });
        if (await next.CountAsync() > 0 && await next.IsEnabledAsync())
        {
            if (capture) await c.DemoPressAsync(next, "Select Continue to review the change before confirming with your passkey.");
            await next.ClickAsync();
            Clicks++;
        }
        await Spa.WaitForPasskeyStep(dialog);
        s.Check(c.Page.Url == before, "challenge preparation makes no full-page navigation");
        return c.Page;
    }

    /// <summary>Edits the name of a prepared pending machine: Change details returns to the form, Continue prepares the challenge for the new name.</summary>
    public static async Task ChangeName(ILocator dialog, string label, string name)
    {
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Change details" }).ClickAsync();
        Clicks++;
        await dialog.GetByLabel(label).FillAsync(name);
    }

    /// <summary>Prepares the challenge and taps it in the SPA. Returns the review and resulting feedback.</summary>
    public static async Task<string> Continue(Ctx c, S s, ILocator dialog, Func<IPage, string, Task>? beforeTap = null) => await TapAfterBack(c, s, await OpenPasskeyPage(c, s, dialog), beforeTap);

    /// <summary>Clicks a control of the application and counts the click.</summary>
    public static async Task Click(ILocator locator)
    {
        await locator.ClickAsync();
        Clicks++;
    }

    /// <summary>The person opens the address the terminal gave for a command's request; the request page is the one that shows.</summary>
    public static async Task OpenRequest(Ctx c, Cmd<int> run, SpaApp app, S s, string heading = "Run request from")
    {
        string link = await run.LinkAsync();
        s.Check(link.StartsWith(app.Url + "/access/", StringComparison.Ordinal), "the terminal's only instruction is the address of the request in the web app (" + link + ")");
        await c.Page.GotoAsync(link);
        await c.Page.GetByRole(AriaRole.Dialog, new() { Name = heading }).WaitForAsync(new() { Timeout = 20000 });
        await c.DemoSnapAsync("The request opens over the Access screen: what would run, and why.");
    }

    /// <summary>Approve once, as soon as the button is usable. One click, one passkey tap.</summary>
    public static async Task ApproveOnce(Ctx c, string label = "Approve once")
    {
        await c.Page.WaitForFunctionAsync("(label) => { const b = [...document.querySelectorAll('button')].find((x) => x.textContent.trim() === label); return !!b && !b.disabled; }", label, new() { Timeout = 20000 });
        await Click(Button(c, label, exact: true));
        await c.DemoSnapAsync("The passkey was used. The page shows the outcome.");
    }

    /// <summary>Approve for longer than once: the arrow beside Approve, then the named choice (for example "Approve for 1 hour"). One passkey tap.</summary>
    public static async Task ApproveFor(Ctx c, string choice)
    {
        ILocator primary = Button(c, choice, exact: true);
        if (await primary.CountAsync() != 0)
        {
            await Click(primary);
        }
        else
        {
            await c.Page.WaitForFunctionAsync("() => { const b = document.querySelector('button[aria-label=\"Approve for longer\"]'); return !!b && !b.disabled; }", null, new() { Timeout = 20000 });
            await Click(c.Page.GetByRole(AriaRole.Button, new() { Name = "Approve for longer" }));
            await Click(c.Page.GetByRole(AriaRole.Menuitem, new() { Name = choice, Exact = true }));
        }
        await c.DemoSnapAsync("The passkey was used. The page shows the outcome.");
    }

    /// <summary>For the recording: the open request in the dark scheme, then with the arrow beside Approve opened, and back to the light scheme. Nothing is approved.</summary>
    public static async Task ShowRequestVariants(Ctx c, S? checks = null)
    {
        if (!c.IsDemo && checks is null) return;
        await c.Page.WaitForFunctionAsync("() => { const b = document.querySelector('button[aria-label=\"Approve for longer\"]'); return !!b && !b.disabled; }", null, new() { Timeout = 20000 });
        await c.Page.EmulateMediaAsync(new() { ColorScheme = ColorScheme.Dark });
        await c.DemoSnapAsync("The same request in the dark scheme.");
        await Click(c.Page.GetByRole(AriaRole.Button, new() { Name = "Approve for longer" }));
        if (checks is not null)
        {
            string[] options = [.. await c.Page.GetByRole(AriaRole.Menuitem).AllTextContentsAsync()];
            checks.Check(options.SequenceEqual(["Approve for 1 hour", "Approve for 2 hours", "Approve for 4 hours", "Approve for 8 hours",
                "Approve for 24 hours", "Approve for 7 days", "Approve for 30 days", "Approve always"]), "the duration menu offers exactly the approved set");
        }
        await c.DemoSnapAsync("The arrow beside Approve offers a time or Always. Approve itself approves once.");
        await c.Page.Keyboard.PressAsync("Escape");
        await c.Page.EmulateMediaAsync(new() { ColorScheme = ColorScheme.Light });
    }

    /// <summary>For a person reviewing the screens: with ARCANA_GUARDIAN_SHOTS set to a folder, saves a screenshot of the page (and of the page at phone width) there. Does nothing otherwise.</summary>
    public static async Task Shot(Ctx c, string name)
    {
        string? folder = Environment.GetEnvironmentVariable("ARCANA_GUARDIAN_SHOTS");
        if (string.IsNullOrEmpty(folder) || c.IsDemo) return;
        Directory.CreateDirectory(folder);
        await c.Page.ScreenshotAsync(new() { Path = Path.Combine(folder, name + ".png"), FullPage = false });
        var size = c.Page.ViewportSize;
        await c.Page.SetViewportSizeAsync(390, 844);
        await c.SettledAsync();
        await c.Page.ScreenshotAsync(new() { Path = Path.Combine(folder, name + "-phone.png"), FullPage = false });
        if (size is not null) await c.Page.SetViewportSizeAsync(size.Width, size.Height);
        await c.SettledAsync();
    }

    /// <summary>The final button of a prepared dialog (last in its footer): named for what the tap does.</summary>
    public static ILocator ConfirmButton(ILocator dialog) => dialog.GetByRole(AriaRole.Button).Last;

    public static ILocator PageFeedback(Ctx c) => c.Page.Locator("main [data-page-feedback]");

    /// <summary>The clicks a person made since <see cref="Clicks" /> was last set to zero.</summary>
    public static int Clicks { get; set; }

    public static async Task<string> TapAfterBack(Ctx c, S s, IPage page, Func<IPage, string, Task>? beforeTap, bool capture = true)
    {
        ILocator dialog = Spa.Dialog(c);
        string beforeUrl = c.Page.Url;
        string beforeText = await dialog.TextContentAsync() ?? "";
        int beforeCalls = await c.PasskeyCalls();
        if (beforeTap is not null) await beforeTap(page, beforeText);
        // After a reload the dialog first finds its request again: until then its last button is Cancel, not the confirmation.
        await c.Page.WaitForFunctionAsync("() => { const d = document.querySelector('dialog[open]'); const b = d && [...d.querySelectorAll('button')].at(-1); return !!b && !b.disabled && !/^Cancel/.test(b.textContent.trim()); }", null, new() { Timeout = 20000 });
        if (capture) await c.DemoPressAsync(ConfirmButton(dialog), "The user confirms the change with the passkey.");
        await ConfirmButton(dialog).ClickAsync(new() { Timeout = 20000 });
        Clicks++;
        await page.WaitForFunctionAsync("() => { const dialog = document.querySelector('dialog[open]'); return dialog ? dialog.dataset.step === 'done' || !!dialog.querySelector('[role=alert]') : !!document.querySelector('main [data-page-feedback]'); }", null, new() { Timeout = 20000 });
        bool staysOpen = await dialog.CountAsync() != 0;
        if (capture) await c.DemoSnapAsync(staysOpen ? "The passkey was used. The dialog shows the next step." : "The dialog closes and the page confirms the change.");
        s.Check(await c.PasskeyCalls() == beforeCalls + 1, "the final confirmation gesture made exactly one WebAuthn call");
        s.Check(c.Page.Url == beforeUrl, "passkey authentication kept the SPA loaded in the same tab");
        return staysOpen ? await dialog.TextContentAsync() ?? "" : beforeText + "\n" + await PageFeedback(c).TextContentAsync();
    }

    public static async Task Unlock(Ctx c, SpaApp app, S s)
    {
        await Open(c, app, capture: false);
        await Button(c, "Unlock the authority").ClickAsync();
        ILocator dialog = Dialog(c);
        await dialog.WaitForAsync();
        await TapAfterBack(c, s, await OpenPasskeyPage(c, s, dialog, capture: false), null, capture: false);
        await PageFeedback(c).WaitForAsync(new() { Timeout = 20000 });
        await c.Page.GetByText("Authority unlocked").First.WaitForAsync(new() { Timeout = 20000 });
    }

    /// <summary>Signs in through the real UI, then captures Overview for demos where sign-in is a prerequisite.</summary>
    public static async Task SignIn(Ctx c, SpaApp app, S s)
    {
        if (c.Page.Url.TrimEnd('/') != app.Url)
        {
            await Open(c, app, capture: false);
        }
        await Heading(c, "Overview").WaitForAsync();
        await Tap(c, s, capture: false);
        await c.DemoSnapAsync("Overview is open and you’re signed in.");
    }

    public static async Task StartDemoFromOverview(Ctx c)
    {
        if (!c.IsDemo) return;
        if (!await Heading(c, "Overview").IsVisibleAsync()) await GoTo(c, "Overview", "Overview", capture: false);
        await c.StartDemoAsync();
        await c.DemoSnapAsync("Overview is open and you’re signed in.");
    }

    /// <summary>Runs axe-core (WCAG 2.0, 2.1 and 2.2 A and AA rules, contrast included) in the real browser against the page as it is and checks that nothing is violated.</summary>
    public static async Task Axe(Ctx c, S s, string what)
    {
        _axe ??= await File.ReadAllTextAsync(Path.Combine(RepoRoot(), "src", "ArcanaGuardian.Admin.Web", "node_modules", "axe-core", "axe.min.js"));
        // Evaluated by the browser's debugger protocol, so the page's own Content Security Policy (no inline script) does not apply to it.
        if (!await c.Page.EvaluateAsync<bool>("() => typeof axe !== 'undefined'"))
        {
            await c.Page.EvaluateAsync(_axe);
        }

        string json = await c.Page.EvaluateAsync<string>("async () => JSON.stringify((await axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] } })).violations.map(v => ({ id: v.id, impact: v.impact, nodes: v.nodes.slice(0, 3).map(n => n.target.join(' ') + ' | ' + (n.failureSummary || '').split('\\n').slice(0, 2).join(' ')) })))");
        using JsonDocument document = JsonDocument.Parse(json);
        s.Check(document.RootElement.GetArrayLength() == 0, "axe-core finds no WCAG 2.2 A/AA violation: " + what);
        foreach (JsonElement violation in document.RootElement.EnumerateArray())
        {
            s.Lines.Add("    axe " + violation.GetProperty("id").GetString() + " (" + violation.GetProperty("impact").GetString() + "): " + string.Join(" || ", violation.GetProperty("nodes").EnumerateArray().Select(node => node.GetString())));
        }
    }

    public static string RepoRoot()
    {
        string? dir = AppContext.BaseDirectory;
        while (dir is not null && !File.Exists(Path.Combine(dir, "arcana-guardian.slnx")))
        {
            dir = Path.GetDirectoryName(dir);
        }

        return dir ?? throw new InvalidOperationException("the repository root (arcana-guardian.slnx) was not found above " + AppContext.BaseDirectory);
    }
}

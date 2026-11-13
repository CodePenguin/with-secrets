using System.Text.Json;
using Microsoft.Playwright;

namespace WithSecrets.E2E;

/// <summary>The host service of a scenario, serving the embedded administration web application and the API on one loopback origin (a free port).</summary>
internal sealed class SpaApp : IDisposable
{
    public SpaApp(Rig rig, bool unlocked = true, bool machineEndpoint = false)
    {
        Service = HostService.Start(new HostServiceOptions { Lock = unlocked ? AuthorityLock.UnlockedForTests() : null, State = rig.State, Store = rig.Store, Grants = rig.Grants, Deployment = rig.Machine.Deployment, Port = 0, MachineEndpoint = machineEndpoint ? new MachineListenerOptions { Port = 0 } : null, TimeLimit = TimeSpan.FromSeconds(60) });
    }

    public HostService Service { get; }

    /// <summary>The address of the application as a person types it (a loopback name, the service's port).</summary>
    public string Url => $"http://localhost:{Service.Port}/admin";

    public void Dispose() => Service.Dispose();
}

/// <summary>Passkey pages replace the application page in this tab. These helpers navigate back and forward to exercise the browser history path.</summary>
internal static class Spa
{
    private static string? _axe;

    public static ILocator Heading(Ctx c, string name) => c.Page.GetByRole(AriaRole.Heading, new() { Name = name, Level = 1 });

    public static ILocator Button(Ctx c, string name, bool exact = false) => c.Page.GetByRole(AriaRole.Button, new() { Name = name, Exact = exact });

    public static ILocator Dialog(Ctx c) => c.Page.GetByRole(AriaRole.Dialog);

    public static async Task Open(Ctx c, SpaApp app, string path = "")
    {
        await c.Page.GotoAsync(app.Url + path);
    }

    /// <summary>Follows a link of the main navigation and waits for the view's heading.</summary>
    public static async Task GoTo(Ctx c, string navName, string heading)
    {
        ILocator nav = c.Page.GetByRole(AriaRole.Navigation, new() { Name = "Main" });
        ILocator link = nav.GetByRole(AriaRole.Link, new() { Name = navName, Exact = true });
        if (!await link.IsVisibleAsync())
        {
            await nav.GetByRole(AriaRole.Button, new() { Name = "Menu" }).ClickAsync();
            await link.WaitForAsync();
        }

        await link.ClickAsync();
        await Heading(c, heading).WaitForAsync();
    }

    /// <summary>Follows the sign-in link in this tab, taps there, then returns with browser Back.</summary>
    public static async Task<string> Tap(Ctx c, S s, string linkName = "Open the passkey page", Func<IPage, string, Task>? beforeTap = null)
    {
        ILocator link = c.Page.GetByRole(AriaRole.Link, new() { Name = linkName });
        await link.First.WaitForAsync(new() { Timeout = 20000 });
        s.Check(await link.First.GetAttributeAsync("target") is null, "the passkey page link stays in this tab");
        await link.First.ClickAsync();

        return await TapCurrent(c, s, beforeTap, returnWithBack: true);
    }

    /// <summary>The one step of an administrative change. It follows Continue into the passkey page, then Back to the waiting dialog.</summary>
    public static async Task<IPage> OpenPasskeyPage(Ctx c, S s, ILocator dialog)
    {
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Continue to passkey" }).ClickAsync();
        Clicks++;
        await c.Page.WaitForFunctionAsync("() => !!document.querySelector('#request')?.textContent.trim()", null, new() { Timeout = 20000 });
        await c.Page.GoBackAsync();
        await dialog.GetByText("Waiting for your passkey tap").First.WaitForAsync(new() { Timeout = 20000 });

        return c.Page;
    }

    /// <summary>Continue, browser Back, browser Forward, then tap and Back to the result. Returns what the passkey page said.</summary>
    public static async Task<string> Continue(Ctx c, S s, ILocator dialog, Func<IPage, string, Task>? beforeTap = null) => await TapAfterBack(c, s, await OpenPasskeyPage(c, s, dialog), beforeTap);

    /// <summary>Clicks a control of the application and counts the click.</summary>
    public static async Task Click(ILocator locator)
    {
        await locator.ClickAsync();
        Clicks++;
    }

    /// <summary>The clicks a person made since <see cref="Clicks" /> was last set to zero (the passkey page's own Approve counts).</summary>
    public static int Clicks { get; set; }

    public static async Task<string> TapAfterBack(Ctx c, S s, IPage page, Func<IPage, string, Task>? beforeTap)
    {
        await page.GoForwardAsync();
        await page.WaitForFunctionAsync("() => !!document.querySelector('#request')?.textContent.trim()", null, new() { Timeout = 20000 });
        return await TapCurrent(c, s, beforeTap, returnWithBack: true);
    }

    private static async Task<string> TapCurrent(Ctx c, S s, Func<IPage, string, Task>? beforeTap, bool returnWithBack)
    {
        IPage page = c.Page;
        await page.WaitForFunctionAsync("() => { var e = document.querySelector('#request'); return !!e && e.textContent.trim().length > 0; }", null, new() { Timeout = 20000 });
        string request = ((await page.Locator("#request").TextContentAsync()) ?? "").Trim();
        int before = await page.EvaluateAsync<int>("() => window.__credCalls || 0");
        s.Check(before == 0, "tap rule: no passkey prompt when the passkey page loads");
        if (beforeTap is not null)
        {
            await beforeTap(page, request);
        }

        await page.Locator("#approve").ClickAsync(new() { Timeout = 20000 });
        Clicks++;
        await page.WaitForFunctionAsync("() => { var e = document.getElementById('status'); return !!e && /^(Approved\\b|Change confirmed\\.)/.test(e.textContent.trim()); }", null, new() { Timeout = 20000 });
        if (returnWithBack) await page.GoBackAsync();

        return request;
    }

    /// <summary>Signs in: Sign in, the tap on the passkey page, and the Overview appears by itself.</summary>
    public static async Task SignIn(Ctx c, SpaApp app, S s)
    {
        await Open(c, app);
        await Heading(c, "Sign in").WaitForAsync();
        await Button(c, "Sign in", exact: true).ClickAsync();
        string request = await Tap(c, s);
        s.Check(request.Contains("start an administrator session", StringComparison.Ordinal) && request.Contains("login:", StringComparison.Ordinal), "the sign-in passkey page says it starts an administrator session and carries this login's code");
        await Heading(c, "Overview").WaitForAsync(new() { Timeout = 20000 });
    }

    /// <summary>Runs axe-core (WCAG 2.0, 2.1 and 2.2 A and AA rules, contrast included) in the real browser against the page as it is and checks that nothing is violated.</summary>
    public static async Task Axe(Ctx c, S s, string what)
    {
        _axe ??= await File.ReadAllTextAsync(Path.Combine(RepoRoot(), "src", "WithSecrets.Admin.Web", "node_modules", "axe-core", "axe.min.js"));
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
        while (dir is not null && !File.Exists(Path.Combine(dir, "with-secrets.slnx")))
        {
            dir = Path.GetDirectoryName(dir);
        }

        return dir ?? throw new InvalidOperationException("the repository root (with-secrets.slnx) was not found above " + AppContext.BaseDirectory);
    }
}

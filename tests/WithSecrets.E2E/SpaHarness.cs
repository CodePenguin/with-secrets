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

/// <summary>The SPA prepares each challenge, and the final confirmation gesture invokes the browser's virtual authenticator in the same page.</summary>
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

    /// <summary>Completes the prepared in-page sign-in with a user gesture that directly invokes WebAuthn.</summary>
    public static async Task Tap(Ctx c, S s, string linkName = "Sign in with passkey", Func<IPage, string, Task>? beforeTap = null)
    {
        string before = c.Page.Url;
        if (beforeTap is not null) await beforeTap(c.Page, "starts a read-only administrator session");
        ILocator button = c.Page.GetByRole(AriaRole.Button, new() { Name = linkName, Exact = true });
        await button.WaitForAsync(new() { Timeout = 20000 });
        await button.ClickAsync(new() { Timeout = 20000 });
        Clicks++;
        await Heading(c, "Overview").WaitForAsync(new() { Timeout = 20000 });
        s.Check(c.Page.Url == before, "sign-in keeps the SPA loaded in the same tab");
    }

    /// <summary>Prepares the operation-bound challenge while the SPA stays loaded. The next gesture invokes WebAuthn.</summary>
    public static async Task<IPage> OpenPasskeyPage(Ctx c, S s, ILocator dialog)
    {
        string before = c.Page.Url;
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Prepare confirmation" }).ClickAsync();
        Clicks++;
        await dialog.GetByText("Review before confirming").WaitForAsync(new() { Timeout = 20000 });
        s.Check(c.Page.Url == before, "challenge preparation makes no full-page navigation");
        return c.Page;
    }

    /// <summary>Prepares the challenge and taps it in the SPA. Returns the result dialog text.</summary>
    public static async Task<string> Continue(Ctx c, S s, ILocator dialog, Func<IPage, string, Task>? beforeTap = null) => await TapAfterBack(c, s, await OpenPasskeyPage(c, s, dialog), beforeTap);

    /// <summary>Clicks a control of the application and counts the click.</summary>
    public static async Task Click(ILocator locator)
    {
        await locator.ClickAsync();
        Clicks++;
    }

    /// <summary>The clicks a person made since <see cref="Clicks" /> was last set to zero.</summary>
    public static int Clicks { get; set; }

    public static async Task<string> TapAfterBack(Ctx c, S s, IPage page, Func<IPage, string, Task>? beforeTap)
    {
        ILocator dialog = Spa.Dialog(c);
        string beforeUrl = c.Page.Url;
        string beforeText = await dialog.TextContentAsync() ?? "";
        int beforeCalls = await c.PasskeyCalls();
        if (beforeTap is not null) await beforeTap(page, beforeText);
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Confirm this change" }).ClickAsync(new() { Timeout = 20000 });
        Clicks++;
        await page.WaitForFunctionAsync("() => !!document.querySelector('dialog[open]') && (document.querySelector('dialog[open]')?.textContent.includes('Done') || !!document.querySelector('dialog[open] [role=alert]'))", null, new() { Timeout = 20000 });
        s.Check(await c.PasskeyCalls() == beforeCalls + 1, "the final confirmation gesture made exactly one WebAuthn call");
        s.Check(c.Page.Url == beforeUrl, "passkey authentication kept the SPA loaded in the same tab");
        return await dialog.TextContentAsync() ?? "";
    }

    /// <summary>Signs in with a prepared challenge and an in-page WebAuthn gesture.</summary>
    public static async Task SignIn(Ctx c, SpaApp app, S s)
    {
        await Open(c, app);
        await Heading(c, "Sign in").WaitForAsync();
        await Button(c, "Sign in", exact: true).ClickAsync();
        await Tap(c, s);
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

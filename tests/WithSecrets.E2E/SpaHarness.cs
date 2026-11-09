using System.Text.Json;
using Microsoft.Playwright;

namespace WithSecrets.E2E;

/// <summary>The host service of a scenario, serving the embedded administration web application and the API on one loopback origin (a free port).</summary>
internal sealed class SpaApp : IDisposable
{
    public SpaApp(Rig rig, bool unlocked = true)
    {
        Service = HostService.Start(new HostServiceOptions { Lock = unlocked ? AuthorityLock.UnlockedForTests() : null, State = rig.State, Store = rig.Store, Grants = rig.Grants, Deployment = rig.Machine.Deployment, Port = 0 });
    }

    public HostService Service { get; }

    /// <summary>The address of the application as a person types it (a loopback name, the service's port).</summary>
    public string Url => $"http://localhost:{Service.Port}/admin";

    public void Dispose() => Service.Dispose();
}

/// <summary>
/// What a person does in the administration application, as page steps. The passkey tap is never in the application's page: it is on the service's own one-use page, which the application offers as
/// a link that opens in a new tab. <see cref="Tap" /> clicks that link and taps there, with the same (virtual) passkey as the rest of the scenario.
/// </summary>
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
        await c.Page.GetByRole(AriaRole.Navigation, new() { Name = "Main" }).GetByRole(AriaRole.Link, new() { Name = navName, Exact = true }).ClickAsync();
        await Heading(c, heading).WaitForAsync();
    }

    private static Dictionary<string, object> AuthenticatorOptions() => new()
    {
        ["options"] = new Dictionary<string, object>
        {
            ["protocol"] = "ctap2",
            ["transport"] = "internal",
            ["hasResidentKey"] = true,
            ["hasUserVerification"] = true,
            ["isUserVerified"] = true,
            ["automaticPresenceSimulation"] = true,
            ["hasPrf"] = true,
        },
    };

    private static async Task<JsonElement> Credentials(ICDPSession cdp, string authenticator)
    {
        JsonElement? reply = await cdp.SendAsync("WebAuthn.getCredentials", new Dictionary<string, object> { ["authenticatorId"] = authenticator });

        return reply!.Value.GetProperty("credentials");
    }

    /// <summary>
    /// Clicks the passkey-page link the application offers (it opens in a new tab), waits for that page to say what is being authorized, runs <paramref name="beforeTap" />, taps, and closes the tab.
    /// The new tab gets its own virtual authenticator holding the scenario's passkey (a tab has none of its own); the sign count is copied back so the next tab's tap counts on from it.
    /// Returns the text the passkey page showed.
    /// </summary>
    public static async Task<string> Tap(Ctx c, S s, string linkName = "Open the passkey page", Func<IPage, string, Task>? beforeTap = null)
    {
        ILocator link = c.Page.GetByRole(AriaRole.Link, new() { Name = linkName });
        await link.First.WaitForAsync(new() { Timeout = 20000 });
        s.Check(await link.First.GetAttributeAsync("target") == "_blank" && (await link.First.GetAttributeAsync("rel") ?? "").Contains("noopener", StringComparison.Ordinal), "the application opens the passkey page in a new tab (target _blank, noopener)");
        IPage popup = await c.Page.RunAndWaitForPopupAsync(() => link.First.ClickAsync());
        ICDPSession cdp = await c.Context.NewCDPSessionAsync(popup);
        await cdp.SendAsync("WebAuthn.enable");
        JsonElement? added = await cdp.SendAsync("WebAuthn.addVirtualAuthenticator", AuthenticatorOptions());
        string authenticator = added!.Value.GetProperty("authenticatorId").GetString()!;
        foreach (JsonElement credential in (await Credentials(c.Cdp, c.AuthId)).EnumerateArray())
        {
            await cdp.SendAsync("WebAuthn.addCredential", new Dictionary<string, object> { ["authenticatorId"] = authenticator, ["credential"] = credential });
        }

        await popup.WaitForFunctionAsync("() => { var e = document.querySelector('#request'); return !!e && e.textContent.trim().length > 0; }", null, new() { Timeout = 20000 });
        string request = ((await popup.Locator("#request").TextContentAsync()) ?? "").Trim();
        int before = await popup.EvaluateAsync<int>("() => window.__credCalls || 0");
        s.Check(before == 0, "tap rule: no passkey prompt when the passkey page loads");
        if (beforeTap is not null)
        {
            await beforeTap(popup, request);
        }

        await popup.Locator("#approve").ClickAsync(new() { Timeout = 20000 });
        await popup.WaitForFunctionAsync("() => { var e = document.getElementById('status'); return !!e && e.textContent.indexOf('Approved') >= 0; }", null, new() { Timeout = 20000 });

        // Back to the scenario's authenticator: the sign counts the tap moved.
        foreach (JsonElement credential in (await Credentials(cdp, authenticator)).EnumerateArray())
        {
            string id = credential.GetProperty("credentialId").GetString()!;
            await c.Cdp.SendAsync("WebAuthn.removeCredential", new Dictionary<string, object> { ["authenticatorId"] = c.AuthId, ["credentialId"] = id });
            await c.Cdp.SendAsync("WebAuthn.addCredential", new Dictionary<string, object> { ["authenticatorId"] = c.AuthId, ["credential"] = credential });
        }

        await popup.CloseAsync();

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

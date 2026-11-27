using Microsoft.Playwright;
using WithSecrets.Bitwarden;
using WithSecrets.LastPass;
using WithSecrets.OnePassword;
using WithSecrets.Vault;

namespace WithSecrets.E2E;

/// <summary>
/// The administration single-page application driven in a real browser, against the host service and API from one origin. The admin passkey is the
/// browser's virtual authenticator. Sign-in and every change prepare a service-owned challenge; a final user gesture invokes WebAuthn directly in the SPA. The service applies its retained operation only after verification. These scenarios replace the earlier
/// API-driven browser scenarios (i1 to i4); the API itself is still tested directly, without a browser, in the unit suite (Api).
/// </summary>
internal static class ScenariosSpa
{
    private const string SecretValue = "s3cr3t-e2e-value-1";
    private const string BitwardenProjectPath = "11111111-1111-4111-8111-111111111111";

    private class TestProvider<TConfiguration> : ProviderAdapter<TConfiguration> where TConfiguration : class, IAdapterConfiguration
    {
        protected override Task InitializeAsync(TConfiguration configuration, AdapterInitializationContext context, CancellationToken cancellationToken)
        {
            context.StatusReporter.Report(new LifecycleChangedEvent(AdapterLifecycleState.Ready));
            context.StatusReporter.Report(new HealthChangedEvent(AdapterHealthState.Healthy));
            return Task.CompletedTask;
        }

        protected override Task UpdateConfigurationAsync(TConfiguration configuration, CancellationToken cancellationToken) => Task.CompletedTask;
        protected override Task<IReadOnlyList<ProviderValidationIssue>> ValidateConfigurationAsync(TConfiguration configuration, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<ProviderValidationIssue>>([]);
        protected override Task<IReadOnlyList<ProviderValidationIssue>> ValidateMountAsync(TConfiguration configuration, string basePath, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<ProviderValidationIssue>>([]);
        public override Task ShutdownAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public override Task<IReadOnlyList<ProviderSecretResult>> RetrieveSecretsAsync(IReadOnlyList<ProviderSecretRequest> requests, CancellationToken cancellationToken) => throw new InvalidOperationException("Provider administration should not retrieve secret values.");
        public override Task<ListSecretsResult> ListSecretsAsync(ListSecretsRequest request, CancellationToken cancellationToken) =>
            Task.FromResult(new ListSecretsResult([new ProviderSecretInfo("TOKEN", "test-token", "Deployment token metadata")], null, true));
    }

    private sealed class TestBitwardenProvider : TestProvider<BitwardenConfiguration>, IProviderMountBrowser
    {
        public Task<IReadOnlyList<ProviderMountOption>> BrowseMountOptionsAsync(string? parentPath, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<ProviderMountOption>>(parentPath switch
            {
                null => [new(BitwardenProjectPath, "Build project"), new("22222222-2222-4222-8222-222222222222", "Staging")],
                BitwardenProjectPath => [new(BitwardenProjectPath + "/TOKEN", "Deployment token")],
                _ => [],
            });
    }

    public static async Task Providers(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        ProviderRegistry registry = new();
        registry.RegisterType("bitwarden", "1.0", () => new TestBitwardenProvider(), () => new BitwardenConfiguration());
        using SpaApp app = new(rig, providers: registry, sealBitwarden: (token, url) =>
            rig.State.TryManifest(out Manifest? manifest, out _) && manifest?.Review is { } review
                ? BitwardenProvider.SealConfiguration(token, url, review.PublicKey) : null);
        await Spa.SignIn(c, app, s);
        await Scenarios3.SeedSecret(rig, c, app, "apps/API_KEY");
        await Spa.StartDemoFromOverview(c);
        await Spa.GoTo(c, "Providers", "Providers");
        ILocator dialog = Spa.Dialog(c);

        async Task Complete(string expected)
        {
            await Spa.OpenPasskeyPage(c, s, dialog);
            ILocator confirm = Spa.ConfirmButton(dialog);
            await c.DemoPressAsync(confirm, "Review the change and confirm it with your passkey.");
            await Spa.Click(confirm);
            await dialog.WaitForAsync(new() { State = WaitForSelectorState.Detached });
            ILocator banner = c.Page.Locator("main").GetByText(expected, new() { Exact = true });
            await banner.WaitForAsync();
            s.Check(await banner.IsVisibleAsync(), "provider administration reports success on the page: " + expected);
            await c.DemoSnapAsync(expected);
        }

        ILocator add = Spa.Button(c, "Add provider", exact: true);
        await c.DemoPressAsync(add, "From Providers, select Add provider.");
        await Spa.Click(add);
        await dialog.GetByLabel("Provider name").FillAsync("Build vault");
        await dialog.GetByLabel("Provider type").SelectOptionAsync("bitwarden");
        await dialog.GetByLabel("Bitwarden access token").FillAsync("demo-bitwarden-token-first");
        await c.DemoSnapAsync("Choose Bitwarden Secrets Manager and enter the access token. WithSecrets encrypts it before asking for passkey approval.");
        await Complete("Added provider Build vault.");
        ILocator providerRow = c.Page.GetByRole(AriaRole.Table, new() { Name = "Providers" }).GetByRole(AriaRole.Link, new() { Name = "Build vault" });
        await c.DemoPressAsync(providerRow, "Compare provider health and mount counts in the list. Select Build vault for its settings.");
        await providerRow.ClickAsync();
        await Spa.Heading(c, "Build vault").WaitForAsync();
        s.Check(await c.Page.GetByText("healthy", new() { Exact = true }).IsVisibleAsync(), "the registered adapter reports healthy");
        await Spa.Axe(c, s, "provider detail");

        await Spa.Button(c, "Change configuration Build vault").ClickAsync();
        await dialog.GetByLabel("Bitwarden access token").FillAsync("demo-bitwarden-token-replacement");
        ILocator freshness = dialog.GetByRole(AriaRole.Group, new() { Name = "Cache freshness" });
        await freshness.GetByLabel("Minutes").FillAsync("10");
        s.Check(await dialog.GetByLabel("Provider type").CountAsync() == 0, "editing shows the existing provider type without an editable type control");
        await c.DemoSnapAsync("Edit the connection and cache freshness together. Hours and Minutes are grouped under Cache freshness.");
        await Complete("Configuration saved.");
        await c.Page.GetByText("10 min", new() { Exact = true }).WaitForAsync();
        s.Check(await Spa.Button(c, "Change maximum staleness Build vault").CountAsync() == 0 &&
            !(await Scenarios2.RawState(rig)).Contains("demo-bitwarden-token-replacement", StringComparison.Ordinal),
            "the same save changed the cache policy and provider settings without storing the Bitwarden token in plaintext");

        await Spa.GoTo(c, "Secrets", "Secrets");
        ILocator tree = c.Page.GetByRole(AriaRole.List, new() { Name = "Secrets", Exact = true });
        await tree.GetByText("apps", new() { Exact = true }).ClickAsync();
        ILocator mountProvider = Spa.Button(c, "Mount provider", exact: true);
        await c.DemoPressAsync(mountProvider, "Review the tree, then choose Mount provider at the top of Secrets.");
        await Spa.Click(mountProvider);
        await dialog.GetByLabel("Project").SelectOptionAsync(new SelectOptionValue { Label = "Build project" });
        await dialog.GetByLabel("Mount kind").SelectOptionAsync(new SelectOptionValue { Label = "Single secret" });
        await dialog.GetByLabel("Secret").SelectOptionAsync(new SelectOptionValue { Label = "Deployment token" });
        await c.DemoSnapAsync("For a single-secret mount, choose the Bitwarden project and secret by name.");
        await dialog.GetByLabel("Mount kind").SelectOptionAsync(new SelectOptionValue { Label = "Entire project" });
        await dialog.GetByLabel("Logical path").FillAsync("team");
        await c.DemoSnapAsync("Mount the entire Build project at team.");
        await Complete("Added mount team.");
        ILocator mounted = tree.Locator("summary").Filter(new() { HasText = "team" });
        await c.DemoPressAsync(mounted, "In Secrets, open team to browse every name under that path.");
        await mounted.ClickAsync();
        await tree.GetByText("TOKEN", new() { Exact = true }).WaitForAsync();
        s.Check(await tree.GetByText("API_KEY", new() { Exact = true }).IsVisibleAsync(),
            "after mounting, Secrets keeps the open folder and shows the new provider folder in the same tree");
        await c.DemoSnapAsync("The same tree shows the manual secret under apps and the provider secret under team.");
        await Spa.GoTo(c, "Providers", "Providers");
        await c.Page.GetByRole(AriaRole.Link, new() { Name = "Build vault" }).ClickAsync();
        await Spa.Heading(c, "Build vault").WaitForAsync();
        await Spa.Button(c, "Show entries for team").ClickAsync();
        await c.Page.GetByText("team/TOKEN", new() { Exact = true }).WaitForAsync();
        s.Check(await c.Page.GetByText(BitwardenProjectPath + "/TOKEN", new() { Exact = true }).IsVisibleAsync(), "the immediate reconciliation listed entry metadata");
        await Spa.Button(c, "Refresh namespace team").ClickAsync();
        await c.Page.GetByText("Namespace refreshed. Added", new() { Exact = false }).WaitForAsync();
        await c.DemoSnapAsync("In Providers, Show entries lists the mount's metadata. Refresh namespace updates it.");

        await Spa.Button(c, "Remove mount team").ClickAsync();
        await Complete("Removed mount team.");
        await c.Page.GetByText("No mounts configured.").WaitForAsync();
        await Spa.Button(c, "Remove provider Build vault").ClickAsync();
        await Complete("Removed provider Build vault.");
        await Spa.Heading(c, "Providers").WaitForAsync();
        await c.Page.GetByText("No provider instances configured.").WaitForAsync();

        await app.Service.Audit.Uploader.DrainAsync();
        await Spa.GoTo(c, "Audit", "Audit");
        foreach (string outcome in new[] { "provider-added", "provider-config-changed", "provider-max-stale-changed", "mount-added", "namespace-refreshed", "mount-removed", "provider-removed" })
        {
            await c.Page.GetByRole(AriaRole.Table, new() { Name = "Host events" }).GetByRole(AriaRole.Cell, new() { Name = outcome, Exact = true }).First.WaitForAsync();
        }
        s.Check(!(await c.Page.ContentAsync()).Contains("demo-bitwarden-token-replacement", StringComparison.Ordinal), "the audit page omits the Bitwarden token");
        s.NoProblems(c);
    }

    public static Task OnePasswordSetup(Host host, S s)
    {
        const string token = "ops_demo_service_account_token";
        return ProviderSetup(host, s, "onepassword", "Team 1Password", "Enter a 1Password service-account token. WithSecrets seals it before passkey confirmation.",
            dialog => dialog.GetByLabel("1Password service-account token").FillAsync(token), token);
    }

    public static Task VaultSetup(Host host, S s)
    {
        const string token = "hvs.demo_vault_token";
        return ProviderSetup(host, s, "vault", "Team Vault", "Enter a token for the Vault server configured on the authority. WithSecrets seals it before passkey confirmation.",
            dialog => dialog.GetByLabel("Vault token").FillAsync(token), token);
    }

    public static Task LastPassSetup(Host host, S s) =>
        ProviderSetup(host, s, LastPassProvider.InteractiveType, "Team LastPass",
            "Enter the account email and select its region. LastPass uses values from a manual refresh.",
            async dialog =>
            {
                await dialog.GetByLabel("LastPass account email").FillAsync("vault@example.test");
                await dialog.GetByLabel("LastPass region").SelectOptionAsync("eu");
            });

    private static async Task ProviderSetup(Host host, S s, string type, string name, string caption, Func<ILocator, Task> fill, string? token = null)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        string reviewKey = rig.State.TryManifest(out Manifest? manifest, out _) && manifest?.Review is { } review
            ? review.PublicKey : throw new InvalidOperationException("Setup did not create a review key.");
        ProviderRegistry registry = new();
        registry.RegisterType("onepassword", "1.0", () => new TestProvider<OnePasswordConfiguration>(), () => new OnePasswordConfiguration());
        registry.RegisterType("vault", "1.0", () => new TestProvider<VaultConfiguration>(), () => new VaultConfiguration());
        LastPassProvider.RegisterInteractive(registry);
        using SpaApp app = new(rig, providers: registry,
            sealOnePassword: value => OnePasswordProvider.SealConfiguration(value, reviewKey),
            sealVault: value => VaultProvider.SealConfiguration(value, reviewKey));
        await Spa.SignIn(c, app, s);
        await Spa.GoTo(c, "Providers", "Providers");
        ILocator add = Spa.Button(c, "Add provider", exact: true);
        await c.DemoPressAsync(add, "From Providers, select Add provider.");
        await Spa.Click(add);
        ILocator dialog = Spa.Dialog(c);
        await dialog.GetByLabel("Provider name").FillAsync(name);
        await dialog.GetByLabel("Provider type").SelectOptionAsync(type);
        await fill(dialog);
        await c.DemoSnapAsync(caption);
        await Spa.Axe(c, s, "provider setup form");
        await Spa.OpenPasskeyPage(c, s, dialog);
        ILocator confirm = Spa.ConfirmButton(dialog);
        await c.DemoPressAsync(confirm, "Confirm with an admin passkey to save the provider.");
        await Spa.Click(confirm);
        await dialog.WaitForAsync(new() { State = WaitForSelectorState.Detached });
        await c.Page.GetByRole(AriaRole.Main).GetByText($"Added provider {name}.", new() { Exact = true }).WaitForAsync();
        ILocator providerRow = c.Page.GetByRole(AriaRole.Table, new() { Name = "Providers" }).GetByRole(AriaRole.Link, new() { Name = name });
        await providerRow.WaitForAsync();
        await c.DemoSnapAsync("The list shows the new provider, its type, health, and mount count. Select its row to open its settings.");
        ProviderInstance stored = app.Service.Providers!.Store.Instances().Single();
        s.Check(stored.ProviderType == type && stored.Name == name, "the selected provider is saved");
        if (token is { } fixture)
            s.Check(stored.Configuration.Contains("encryptedConfiguration", StringComparison.Ordinal) && !(await Scenarios2.RawState(rig)).Contains(fixture, StringComparison.Ordinal),
                "the token was stored encrypted");
        else
        {
            s.Check(stored.MaxStale == TimeSpan.FromHours(1) && stored.Configuration.Contains("\"european\":true", StringComparison.Ordinal),
                "LastPass saves the selected region and applies the built-in refresh lifetime");
            s.Check(await c.Page.GetByText("Cache freshness", new() { Exact = true }).CountAsync() == 0,
                "LastPass hides cache freshness in the provider list");
            await providerRow.ClickAsync();
            await Spa.Button(c, $"Change configuration {name}", exact: true).ClickAsync();
            await dialog.WaitForAsync();
            s.Check(await dialog.GetByRole(AriaRole.Group, new() { Name = "Cache freshness" }).CountAsync() == 0,
                "LastPass hides cache freshness in the edit dialog");
            await dialog.GetByRole(AriaRole.Button, new() { Name = "Cancel", Exact = true }).ClickAsync();
        }
        s.NoProblems(c);
    }

    public static async Task SignInAndOut(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using SpaApp app = new(rig);

        IResponse? page = await c.Page.GotoAsync(app.Url);
        s.Check(page is { Status: 200 } && page.Headers.GetValueOrDefault("content-security-policy") == AdminWebAssets.ContentSecurityPolicy && page.Headers.GetValueOrDefault("permissions-policy") == "camera=(), microphone=(), geolocation=(), publickey-credentials-get=(self), publickey-credentials-create=()", "the application is served with a strict same-origin policy that enables passkey retrieval only in this page");
        await Spa.Heading(c, "with-secrets").WaitForAsync();
        s.Check(await c.PasskeyCalls() == 0, "tap rule: the application itself never asks for a passkey");
        s.Check(await c.Page.GetByRole(AriaRole.Navigation, new() { Name = "Main" }).CountAsync() == 0, "no navigation before sign-in: the sign-in is all there is");
        await Spa.Axe(c, s, "sign-in");

        await Spa.Tap(c, s);
        await Spa.Heading(c, "Overview").WaitForAsync(new() { Timeout = 20000 });
        s.Check((await c.Page.GetByText("Signed in with").First.TextContentAsync() ?? "").Contains("Signed in with", StringComparison.Ordinal), "signed in: the header says who and until when");
        s.Check(await c.PasskeyCalls() == 1, "sign-in invokes exactly one in-page WebAuthn request");
        await Spa.Axe(c, s, "overview");

        s.Check(!(await c.Page.EvaluateAsync<string>("() => document.cookie")).Contains(AdminSessions.SessionCookie, StringComparison.Ordinal), "script cannot read the session cookie (HttpOnly)");
        s.Check(await c.Page.EvaluateAsync<bool>("() => localStorage.length === 0 && Object.keys(sessionStorage).every((key) => key === 'ws.session-secret' || key === 'ws.browser-secret')"), "nothing is kept in localStorage, and sessionStorage holds only the two secrets the service gave once");
        s.Check(!(await c.Page.ContentAsync()).Contains((await c.Page.EvaluateAsync<string>("() => sessionStorage.getItem('ws.session-secret') ?? ''")), StringComparison.Ordinal), "the secret is in no page text");
        IReadOnlyList<BrowserContextCookiesResult> cookies = await c.Context.CookiesAsync();
        BrowserContextCookiesResult? session = cookies.FirstOrDefault(cookie => cookie.Name == AdminSessions.SessionCookie);
        s.Check(session is { HttpOnly: true, Path: "/api/v1", SameSite: SameSiteAttribute.Strict }, "the session cookie is HttpOnly, SameSite=Strict and scoped to /api/v1");

        // A reload keeps the session (the cookie), and the address is the view.
        await Spa.GoTo(c, "Machines", "Machines");
        s.Check(c.Page.Url.EndsWith("/admin/machines", StringComparison.Ordinal), "a view is an address (/admin/machines)");
        await c.Page.ReloadAsync();
        await Spa.Heading(c, "Machines").WaitForAsync();
        s.Check(await c.Page.GetByText("Signed in with").First.IsVisibleAsync(), "a reload on a view lands on the same view, still signed in");

        // Sign out ends the session at the service.
        await c.DemoPressAsync(Spa.Button(c, "Sign out"), "Select Sign out to end this browser session.");
        await Spa.Button(c, "Sign out").ClickAsync();
        await Spa.Heading(c, "with-secrets").WaitForAsync();
        await c.DemoSnapAsync("You’re back on the sign-in page.");
        c.Ignore("401");
        string after = await c.Page.EvaluateAsync<string>("async () => (await fetch('/api/v1/machines')).status + ''");
        s.Check(after == "401", "after sign out the service refuses the views (401)");
        s.NoProblems(c);
    }

    /// <summary>Backing out of the passkey prompt on the sign-in screen: Cancel is offered only while the prompt is open, and signing in works again afterwards.</summary>
    public static async Task SignInCancel(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using SpaApp app = new(rig);

        await Spa.Open(c, app);
        await Spa.Heading(c, "with-secrets").WaitForAsync();
        ILocator use = Spa.Button(c, "Sign in with passkey", exact: true);
        ILocator cancel = Spa.Button(c, "Cancel", exact: true);
        await use.WaitForAsync(new() { Timeout = 20000 });
        s.Check(await cancel.CountAsync() == 0, "before the prompt there is nothing to cancel, so there is no Cancel button");

        // The passkey is not answered, so the browser's prompt stays open.
        await c.Presence(false);
        await c.DemoPressAsync(use, "The user selects the passkey. The browser's prompt opens and waits.");
        await use.ClickAsync();
        await cancel.WaitForAsync(new() { Timeout = 20000 });
        await c.DemoSnapAsync("While the prompt is open, Cancel is offered.");
        await Spa.Axe(c, s, "sign-in while the passkey prompt is open");
        s.Check(await c.PasskeyCalls() == 1 && await use.IsDisabledAsync(), "the prompt was asked once and the passkey button waits for it");

        await c.DemoPressAsync(cancel, "The user cancels the prompt.");
        await cancel.ClickAsync();
        ILocator note = c.Page.GetByText("Sign-in cancelled.");
        await note.WaitForAsync(new() { Timeout = 20000 });
        await c.Page.WaitForFunctionAsync("() => { const b = [...document.querySelectorAll('button')].find((x) => x.textContent.trim() === 'Sign in with passkey'); return !!b && !b.disabled; }", null, new() { Timeout = 20000 });
        await c.DemoSnapAsync("Nothing was signed in. The page says so and is ready for another try.");
        await Spa.Axe(c, s, "sign-in after the prompt was cancelled");
        s.Check(await note.GetAttributeAsync("role") == "status", "the cancelled note is a status message, so a screen reader announces it");
        s.Check(await cancel.CountAsync() == 0 && await c.Page.GetByRole(AriaRole.Alert).CountAsync() == 0, "cancelling is not an error: Cancel goes away with the prompt and no problem is shown");
        s.Check(await c.Page.GetByRole(AriaRole.Navigation, new() { Name = "Main" }).CountAsync() == 0, "nothing was signed in");

        // Signing in works again with one click: the fresh sign-in was prepared already.
        await c.Presence(true);
        await Spa.Tap(c, s);
        s.Check(await c.PasskeyCalls() == 2, "the second attempt asked for the passkey once more");
        await c.DemoSnapAsync("The retry signed you in and opened Overview.");
        c.Ignore("401");
        s.NoProblems(c);
    }

    public static async Task MachineDiagnostics(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using SpaApp app = new(rig);
        LocalDeployment deployment = rig.Machine.Deployment;

        await Spa.SignIn(c, app, s);
        await Spa.GoTo(c, "Machines", "Machines");
        ILocator row = c.Page.GetByRole(AriaRole.Row).Filter(new() { HasText = KeyIdentity.Display(deployment.Fingerprint) });
        await row.GetByRole(AriaRole.Button).ClickAsync();
        await Spa.Dialog(c).GetByRole(AriaRole.Link, new() { Name = "View diagnostic logs" }).ClickAsync();
        await c.Page.GetByText("No diagnostics have been received from this machine.").WaitForAsync();
        s.Check(new Uri(c.Page.Url).AbsolutePath.EndsWith("/" + deployment.Fingerprint + "/diagnostics", StringComparison.Ordinal), "the machine details link opens an address for that machine's diagnostics");

        deployment.Store.Diagnostics.Record(deployment.Fingerprint,
            [new DiagnosticEvent(Guid.NewGuid(), DateTimeOffset.UtcNow.AddMinutes(-1), DiagnosticCatalog.CheckInFailed),
             new DiagnosticEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, DiagnosticCatalog.LaunchFailed)]);
        await c.Page.ReloadAsync();
        ILocator log = c.Page.GetByRole(AriaRole.Table, new() { Name = "Diagnostic log" });
        await log.GetByRole(AriaRole.Cell, new() { Name = "The machine could not check in with its authority." }).WaitForAsync();
        s.Check(await log.Locator("time[datetime]").CountAsync() == 4, "each diagnostic displays the recorded and received times after reload");
        s.Check(await log.GetByRole(AriaRole.Row).Filter(new() { HasText = "A command launch failed" })
            .GetByRole(AriaRole.Cell, new() { Name = "Error" }).IsVisibleAsync(), "an error has its own severity in the diagnostic log");
        await Spa.Axe(c, s, "machine diagnostics");

        await c.Page.GetByRole(AriaRole.Button, new() { Name = "Change log level" }).ClickAsync();
        ILocator settings = Spa.Dialog(c);
        await settings.GetByLabel("Log level").SelectOptionAsync("debug");
        s.Check(await settings.GetByRole(AriaRole.Spinbutton).CountAsync() == 0, "the log level is the only diagnostic setting exposed");
        IPage passkey = await Spa.OpenPasskeyPage(c, s, settings);
        s.Check(deployment.Store.DiagnosticsSettings(deployment.Fingerprint) == DiagnosticSettings.Default, "the log level stays unchanged until the passkey tap");
        await Spa.TapAfterBack(c, s, passkey, null);
        await Spa.PageFeedback(c).WaitForAsync(new() { Timeout = 20000 });
        s.Check(deployment.Store.DiagnosticsSettings(deployment.Fingerprint) == new DiagnosticSettings("debug"),
            "the passkey authorizes the selected log level");
        await c.Page.GetByText("Debug", new() { Exact = true }).WaitForAsync();

        await c.Page.GetByRole(AriaRole.Link, new() { Name = "Back to machines" }).ClickAsync();
        await c.Page.GetByRole(AriaRole.Heading, new() { Name = "Machines", Exact = true }).WaitForAsync();
    }

    public static async Task ApproveMachine(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using SpaApp app = new(rig);
        using SoftwareSigningKey other = new();
        string fp = KeyIdentity.Fingerprint(other.PublicKey);
        byte[] challenge = await rig.Machine.Deployment.Authority.BeginEnrollmentAsync();
        await rig.Machine.Deployment.Authority.EnrollAsync(EnrollmentRequest.Create("other-host", challenge, other));
        AuthorityStore store = rig.Machine.Deployment.Store;
        s.Check(store.Find(fp) is { Status: MachineStatus.Pending }, "fixture: a second machine is waiting as Pending");
        List<string> mutations = [];
        c.Page.Request += (_, request) =>
        {
            if (request.Method != "GET")
            {
                mutations.Add(request.Method + " " + new Uri(request.Url).AbsolutePath);
            }
        };
        await Spa.SignIn(c, app, s);
        (_, long signsAfterSignIn) = await c.AuthOps();

        await Spa.GoTo(c, "Machines", "Machines");
        ILocator row = c.Page.GetByRole(AriaRole.Row).Filter(new() { HasText = KeyIdentity.Display(fp) });
        await row.WaitForAsync();
        string rowText = await row.TextContentAsync() ?? "";
        s.Check(rowText.Contains("pending", StringComparison.Ordinal) && rowText.Contains("other-host", StringComparison.Ordinal), "the machines view lists the Pending machine with its host name and its status in words");
        s.Check(await c.Page.GetByRole(AriaRole.Region, new() { Name = "A machine paired and is waiting for you" }).CountAsync() == 1 && await row.CountAsync() == 1, "the paired machine has one row in the waiting table");
        await Spa.Axe(c, s, "machines");

        // Approving a machine: review, prepare the challenge, then confirm with one in-page WebAuthn gesture.
        await c.DemoPressAsync(row.GetByRole(AriaRole.Button), "Select the pending machine to open its details.");
        await row.GetByRole(AriaRole.Button).ClickAsync();
        ILocator dialog = Spa.Dialog(c);
        ILocator approve = dialog.GetByRole(AriaRole.Button, new() { Name = "Approve" });
        await c.DemoPressAsync(approve, "Compare the name and fingerprint with the paired device, then choose Approve.");
        mutations.Clear();
        Spa.Clicks = 0;
        await Spa.Click(approve);
        await dialog.WaitForAsync();
        await Spa.WaitForPasskeyStep(dialog);
        s.Check((await dialog.TextContentAsync() ?? "").Contains("as \"other-host\"", StringComparison.Ordinal), "the machine is approved under the host name the machine reported unless the person changes it");
        int callsBefore = await c.PasskeyCalls();
        s.Check(store.Find(fp)!.Status == MachineStatus.Pending && callsBefore == 1 && !mutations.Any(item => item.EndsWith("/proof", StringComparison.Ordinal)), "nothing is changed and WebAuthn is not requested by preparing the challenge");
        IPage passkeyPage = await Spa.OpenPasskeyPage(c, s, dialog);
        await Spa.Shot(c, "dialog-approve-machine");
        string review = await dialog.TextContentAsync() ?? "";
        s.Check(review.Contains("Approve machine " + KeyIdentity.Display(fp), StringComparison.Ordinal) && review.Contains("other-host", StringComparison.Ordinal), "after browser Back, the dialog identifies the pending change by action and friendly name");
        s.Check(store.Find(fp)!.Status == MachineStatus.Pending, "still Pending while the tap is outstanding (the authorization changes nothing)");
        await Spa.Axe(c, s, "the authorization dialog (waiting for the tap)");

        string page = await Spa.TapAfterBack(c, s, passkeyPage, null);
        s.Check(page.Contains("approve this machine", StringComparison.OrdinalIgnoreCase) && page.Contains(KeyIdentity.Display(fp), StringComparison.Ordinal) && page.Contains("other-host", StringComparison.Ordinal), "the SPA result retains the approved action, fingerprint and name");
        await Spa.PageFeedback(c).WaitForAsync(new() { Timeout = 20000 });
        s.Check(store.Find(fp) is { Status: MachineStatus.Trusted, FriendlyName: "other-host" }, "the tap approves the machine (the service made the change when the tap was verified)");
        s.Check(Spa.Clicks == 2, "approval took two clicks from the details: approve and confirm (" + Spa.Clicks + ")");
        s.Check(await c.PasskeyCalls() == callsBefore + 1 && mutations.Count == 2 && mutations[0] == "POST /api/v1/authorizations/inline" && new Uri(c.Page.Url).AbsolutePath.StartsWith("/admin", StringComparison.Ordinal) && mutations[1].StartsWith("POST /api/v1/authorizations/", StringComparison.Ordinal) && mutations[1].EndsWith("/proof", StringComparison.Ordinal), "challenge preparation and assertion submission stay inside the SPA without a separate operation endpoint (" + string.Join(", ", mutations) + ")");
        s.Check(store.Audit(100).Any(entry => entry.Event == "machine-approve" && entry.Actor.StartsWith("admin passkey", StringComparison.Ordinal)), "the audit history names the admin passkey that tapped");
        await dialog.WaitForAsync(new() { State = WaitForSelectorState.Detached });
        await row.GetByText("trusted").WaitForAsync();
        s.Check((await row.TextContentAsync() ?? "").Contains("other-host", StringComparison.Ordinal), "the table shows the trusted machine under its name");
        await c.DemoSnapAsync("The machine is now trusted.");

        // The next change needs its own challenge and a new assertion.
        (_, long signsAfterApprove) = await c.AuthOps();
        s.Check(signsAfterApprove == signsAfterSignIn + 1, "the approval was exactly one passkey signature");
        await row.GetByRole(AriaRole.Button).ClickAsync();
        Spa.Clicks = 0;
        await Spa.Click(dialog.GetByRole(AriaRole.Button, new() { Name = "Rename" }));
        await dialog.GetByLabel("New name").FillAsync("e2e renamed");
        await c.DemoSnapAsync("Choose Rename to give the trusted machine a different name. Confirm that change with a separate passkey prompt.");
        IPage renamePageTab = await Spa.OpenPasskeyPage(c, s, dialog);
        s.Check(store.Find(fp)!.FriendlyName == "other-host", "the earlier approval does not authorize the rename (it is still the old name before the tap)");
        string renamePage = await Spa.TapAfterBack(c, s, renamePageTab, null);
        await Spa.PageFeedback(c).WaitForAsync(new() { Timeout = 20000 });
        s.Check(renamePage.Contains("e2e renamed", StringComparison.Ordinal) && store.Find(fp)!.FriendlyName == "e2e renamed", "a second change needed its own assertion and was applied by the service");
        s.Check(Spa.Clicks == 3, "an administrative rename took three clicks: open, prepare, and confirm (" + Spa.Clicks + ")");
        (_, long signsAfterRename) = await c.AuthOps();
        s.Check(signsAfterRename == signsAfterApprove + 1, "each change is exactly one more passkey signature");
        await dialog.WaitForAsync(new() { State = WaitForSelectorState.Detached });

        // Cancelling the browser's pending passkey prompt leaves the operation unapplied.
        using SoftwareSigningKey refusedKey = new();
        byte[] refusedChallenge = await rig.Machine.Deployment.Authority.BeginEnrollmentAsync();
        await rig.Machine.Deployment.Authority.EnrollAsync(EnrollmentRequest.Create("refused-host", refusedChallenge, refusedKey));
        string refusedFp = KeyIdentity.Fingerprint(refusedKey.PublicKey);
        ILocator refusedRow = c.Page.GetByRole(AriaRole.Row).Filter(new() { HasText = KeyIdentity.Display(refusedFp) });
        await refusedRow.GetByRole(AriaRole.Button).ClickAsync();
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Approve" }).ClickAsync();
        IPage failedPage = await Spa.OpenPasskeyPage(c, s, dialog);
        await c.Presence(false);
        await Spa.ConfirmButton(dialog).ClickAsync();
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Cancel", Exact = true }).ClickAsync();
        await dialog.GetByText("Passkey prompt cancelled.").WaitForAsync(new() { Timeout = 20000 });
        await c.DemoSnapAsync("Cancelling the prompt is not an error: the request stays ready.");
        await Spa.Axe(c, s, "the dialog after the passkey prompt was cancelled");
        s.Check(await dialog.GetByRole(AriaRole.Alert).CountAsync() == 0 && await Spa.ConfirmButton(dialog).IsEnabledAsync() && store.Find(refusedFp) is { Status: MachineStatus.Pending }, "cancelling WebAuthn in the same SPA says so quietly, keeps the request ready and changes nothing");
        await c.Presence(true);
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Cancel", Exact = true }).ClickAsync();
        await dialog.WaitForAsync(new() { State = WaitForSelectorState.Detached });
        s.Check(store.Find(refusedFp) is { Status: MachineStatus.Pending }, "after cancelling the passkey prompt and closing the dialog the machine remains Pending");
        s.NoProblems(c);
    }

    /// <summary>The tap is never lost: the application tab is reloaded after the passkey page was opened but before the tap, and again right after the tap; the change is made once, by the service, and the page reads the outcome.</summary>
    public static async Task ReloadBetweenTapAndResult(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using SpaApp app = new(rig);
        using SoftwareSigningKey other = new();
        string fp = KeyIdentity.Fingerprint(other.PublicKey);
        byte[] challenge = await rig.Machine.Deployment.Authority.BeginEnrollmentAsync();
        await rig.Machine.Deployment.Authority.EnrollAsync(EnrollmentRequest.Create("other-host", challenge, other));
        AuthorityStore store = rig.Machine.Deployment.Store;
        List<string> mutations = [];
        c.Page.Request += (_, request) =>
        {
            if (request.Method != "GET")
            {
                mutations.Add(request.Method + " " + new Uri(request.Url).AbsolutePath);
            }
        };
        await Spa.SignIn(c, app, s);
        mutations.Clear();
        await Spa.GoTo(c, "Machines", "Machines");
        ILocator dialog = Spa.Dialog(c);
        int approvesBefore = store.Audit(200).Count(entry => entry.Event == "machine-approve");

        // 1. Reload while the passkey page waits for its tap: the application finds the waiting authorization again, and shows what the tap came to.
        ILocator machineRow = c.Page.GetByRole(AriaRole.Row).Filter(new() { HasText = KeyIdentity.Display(fp) });
        await machineRow.GetByRole(AriaRole.Button).ClickAsync();
        await Spa.Click(dialog.GetByRole(AriaRole.Button, new() { Name = "Approve" }));
        await Spa.ChangeName(dialog, "Friendly name", "reloaded one");
        IPage passkeyPage = await Spa.OpenPasskeyPage(c, s, dialog);
        await c.Page.ReloadAsync();
        await dialog.GetByText("This page was reloaded").WaitForAsync(new() { Timeout = 20000 });
        await c.DemoSnapAsync("After reloading before confirmation, the request is still available and the machine is pending.");
        s.Check(store.Find(fp)!.Status == MachineStatus.Pending, "after the reload the machine is still Pending (no tap yet)");
        s.Check(await c.Page.EvaluateAsync<bool>("() => Object.keys(sessionStorage).every((key) => ['ws.session-secret', 'ws.browser-secret', 'ws.pending-authorization'].includes(key)) && !sessionStorage.getItem('ws.pending-authorization').includes('http') && localStorage.length === 0"), "the tab keeps only the id and the title of the waiting authorization (no link, no parameter), and nothing in localStorage");
        await Spa.TapAfterBack(c, s, passkeyPage, null);
        await Spa.PageFeedback(c).WaitForAsync(new() { Timeout = 20000 });
        s.Check(store.Find(fp) is { Status: MachineStatus.Trusted, FriendlyName: "reloaded one" }, "the tap made after the reload approved the machine: the service made the change, the page only read the outcome");
        s.Check(mutations.Count(item => item == "POST /api/v1/authorizations/inline") == 2 && mutations.Count(item => item.StartsWith("DELETE /api/v1/authorizations/", StringComparison.Ordinal)) == 1 && mutations.Count(item => item.EndsWith("/proof", StringComparison.Ordinal)) == 1 && !mutations.Any(item => item.Contains("/approve", StringComparison.Ordinal)), "the SPA only prepared and submitted the assertion; it sent no operation mutation before or after reload (" + string.Join(", ", mutations) + ")");
        s.Check(await c.Page.EvaluateAsync<bool>("() => sessionStorage.getItem('ws.pending-authorization') === null"), "the waiting record is gone when the result was seen");

        // 2. Reload right after the tap (the tab never saw the result): the change is made, once, and the page never offers it again.
        await machineRow.GetByRole(AriaRole.Button).ClickAsync();
        await Spa.Click(dialog.GetByRole(AriaRole.Button, new() { Name = "Rename" }));
        await dialog.GetByLabel("New name").FillAsync("reloaded two");
        await Spa.Continue(c, s, dialog);
        await c.Page.ReloadAsync();
        await Spa.Heading(c, "Machines").WaitForAsync();
        await machineRow.GetByText("reloaded two", new() { Exact = true }).WaitForAsync(new() { Timeout = 20000 });
        await c.DemoSnapAsync("After confirming and reloading, Machines shows the saved name.");
        s.Check(store.Find(fp)!.FriendlyName == "reloaded two", "a reload right after the tap loses nothing: the rename was made by the service");
        s.Check(store.Audit(200).Count(entry => entry.Event == "machine-approve") == approvesBefore + 1 && store.Audit(200).Count(entry => entry.Event == "machine-rename") == 1, "each change is in the audit once (" + string.Join(", ", store.Audit(200).Select(entry => entry.Event)) + ")");
        s.NoProblems(c);
    }

    public static async Task AcceptHostName(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using SpaApp app = new(rig);
        using SoftwareSigningKey other = new();
        string fp = KeyIdentity.Fingerprint(other.PublicKey);
        byte[] challenge = await rig.Machine.Deployment.Authority.BeginEnrollmentAsync();
        await rig.Machine.Deployment.Authority.EnrollAsync(EnrollmentRequest.Create("laptop-old", challenge, other));
        AuthorityStore store = rig.Machine.Deployment.Store;
        store.Approve(fp, "travel laptop", "e2e fixture");
        store.RecordHostMismatch(fp, "laptop-new");
        int revision = store.Find(fp)!.SecurityRevision;
        s.Check(store.Find(fp) is { Status: MachineStatus.Trusted, HostName: "laptop-old", PendingHostName: "laptop-new" }, "fixture: a Trusted machine reports a new host name, which is only recorded as waiting");
        await Spa.SignIn(c, app, s);
        (_, long signsAfterSignIn) = await c.AuthOps();

        await Spa.GoTo(c, "Machines", "Machines");
        ILocator row = c.Page.GetByRole(AriaRole.Row).Filter(new() { HasText = "travel laptop" });
        await row.WaitForAsync();
        s.Check(await row.GetByText("New host name reported").IsVisibleAsync(), "the table flags the reported host name");
        await c.DemoPressAsync(row.GetByRole(AriaRole.Button), "Open the machine marked New host name reported.");
        await row.GetByRole(AriaRole.Button).ClickAsync();
        ILocator dialog = Spa.Dialog(c);
        string text = await dialog.TextContentAsync() ?? "";
        s.Check(text.Contains("laptop-old", StringComparison.Ordinal) && text.Contains("laptop-new", StringComparison.Ordinal), "the details show the enrolled and reported host names");
        ILocator accept = dialog.GetByRole(AriaRole.Button, new() { Name = "Accept host name" });
        await c.DemoPressAsync(accept, "Compare the existing and reported host names. Choose Accept host name if you recognize the change.");
        await Spa.Axe(c, s, "machines with a reported host name");

        await accept.ClickAsync();
        await dialog.WaitForAsync();
        string review = await dialog.TextContentAsync() ?? "";
        s.Check(review.Contains("machine-host-change", StringComparison.Ordinal) && review.Contains("laptop-new", StringComparison.Ordinal) && review.Contains(fp, StringComparison.Ordinal), "the dialog names the exact operation, the machine and the host name that would be accepted");
        s.Check(store.Find(fp) is { HostName: "laptop-old" } && await c.PasskeyCalls() == 1, "nothing changed and WebAuthn was not invoked before the final confirmation");
        string page = await Spa.Continue(c, s, dialog);
        await Spa.PageFeedback(c).WaitForAsync(new() { Timeout = 20000 });
        s.Check(page.Contains("laptop-new", StringComparison.Ordinal) && page.Contains(KeyIdentity.Display(fp), StringComparison.Ordinal), "the result dialog confirms the accepted host name and identifies its machine");
        s.Check(store.Find(fp) is { HostName: "laptop-new", PendingHostName: null } done && done.SecurityRevision == revision, "the tap binds the new host name and leave the security revision alone");
        (_, long signs) = await c.AuthOps();
        s.Check(signs == signsAfterSignIn + 1, "exactly one passkey signature");
        s.Check(store.History(fp).Any(entry => entry.Kind == "host-name-mismatch") && store.Audit(100).Any(entry => entry.Actor.StartsWith("admin passkey", StringComparison.Ordinal) && entry.Detail.Contains("laptop-new", StringComparison.Ordinal)), "the history records the mismatch and the audit names the admin passkey that accepted the name");
        await dialog.WaitForAsync(new() { State = WaitForSelectorState.Detached });
        // The list is refetched when the result is settled (the dialog invalidates every query); that answer can land after the dialog closes, so wait for it.
        bool gone = true;
        try
        {
            await row.GetByText("New host name reported").WaitForAsync(new() { State = WaitForSelectorState.Detached, Timeout = 10000 });
        }
        catch (TimeoutException)
        {
            gone = false;
        }

        s.Check(gone, "the warning is gone from the list");
        await c.DemoSnapAsync("The page confirms the accepted host name and clears the warning.");
        s.NoProblems(c);
    }

    private static async Task<string> MakeGrant(Ctx c, Rig rig, SpaApp app, S s)
    {
        await Scenarios3.SeedSecret(rig, c, app);
        rig.WriteScript("check", "script-value");
        CliCommand.Run run = (CliCommand.Run)Cmds.Parse(["--secrets", "E2E_SECRET", "--reason", "e2e grant", "--", ..Rig.ScriptCommand("check")]);
        using Cmd<int> approve = new((port, o, e) => LaunchClient.RunAsync(run.Args, rig.Work, app.Service.Endpoint, null, o, e, rig.Machine.Trust, approve: true).GetAwaiter().GetResult());

        // The pre-approval waits in the Approvals queue like any request; the person picks how long it lasts and taps once.
        await Spa.OpenRequest(c, approve, app, s, "Run request from");
        string request = await c.Page.Locator("main").InnerTextAsync();
        s.Check(request.Contains("THIS CREATES A GRANT", StringComparison.OrdinalIgnoreCase) || request.Contains("Create a GRANT", StringComparison.OrdinalIgnoreCase), "the request says plainly that it creates a grant");
        await Spa.ApproveFor(c, "Approve for 1 hour");
        await c.Page.GetByText("Grant created for").First.WaitForAsync(new() { Timeout = 20000 });
        s.Check(await approve.Result.WaitAsync(TimeSpan.FromSeconds(30)) == 0, "fixture: a grant was made from the Approvals page");

        return rig.Machine.Deployment.Store.Grants().Single().Id;
    }

    public static async Task RevokeGrant(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using SpaApp app = new(rig);
        await Spa.SignIn(c, app, s);
        string id = await MakeGrant(c, rig, app, s);
        await Spa.StartDemoFromOverview(c);
        AuthorityStore store = rig.Machine.Deployment.Store;
        await Spa.GoTo(c, "Access", "Access");
        ILocator row = c.Page.GetByRole(AriaRole.Table, new() { Name = "Grants" }).GetByRole(AriaRole.Row).Filter(new() { HasText = id });
        await row.WaitForAsync();
        s.Check(await row.GetByText("active").IsVisibleAsync(), "the grants table shows the active grant");
        await Spa.Axe(c, s, "grants");

        await c.DemoPressAsync(row.GetByRole(AriaRole.Button), "Select a grant in Access to open its details.");
        await row.GetByRole(AriaRole.Button).ClickAsync();
        ILocator dialog = Spa.Dialog(c);
        string text = await dialog.TextContentAsync() ?? "";
        s.Check(text.Contains("E2E_SECRET", StringComparison.Ordinal) && text.Contains("Program", StringComparison.Ordinal), "the grant details show the secret name and program");
        s.Check(!(await c.Page.ContentAsync()).Contains(SecretValue, StringComparison.Ordinal), "no secret value is anywhere in the page");
        await Spa.Axe(c, s, "grant details");
        ILocator revoke = dialog.GetByRole(AriaRole.Button, new() { Name = "Revoke" });
        await c.DemoPressAsync(revoke, "Choose Revoke in the grant details.");
        await revoke.ClickAsync();
        await dialog.WaitForAsync();
        await Spa.WaitForPasskeyStep(dialog);
        s.Check((await Spa.ConfirmButton(dialog).TextContentAsync() ?? "").Contains("Revoke grant", StringComparison.Ordinal) && (await dialog.TextContentAsync() ?? "").Contains("grant-revoke", StringComparison.Ordinal) && (await dialog.TextContentAsync() ?? "").Contains(id, StringComparison.Ordinal), "the dialog names the revocation and the grant, and its button says what the tap does");
        s.Check(store.FindGrant(id) is { Status: "active" }, "nothing changed before the tap");
        string page = await Spa.Continue(c, s, dialog);
        await Spa.PageFeedback(c).WaitForAsync(new() { Timeout = 20000 });
        s.Check(page.Contains("revoke this grant", StringComparison.OrdinalIgnoreCase) && page.Contains(id, StringComparison.Ordinal), "the result dialog retains the revocation and grant details");
        s.Check(store.FindGrant(id) is { Status: "revoked" }, "the tap revokes the grant");
        await row.GetByText("revoked").First.WaitForAsync(new() { Timeout = 20000 });
        await c.DemoSnapAsync("The grant is revoked. Future requests need a new approval.");
        await row.GetByRole(AriaRole.Button).ClickAsync();
        s.Check(await dialog.GetByRole(AriaRole.Button, new() { Name = "Revoke" }).CountAsync() == 0, "the revoked grant offers no further action");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Close", Exact = true }).ClickAsync();
        s.NoProblems(c);
    }

    public static async Task AuditSearch(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        await Scenarios3.SeedSecret(rig, c);
        rig.WriteScript("check", "script-value");
        using SpaApp app = new(rig, unlocked: false);
        await Spa.Unlock(c, app, s);
        await Spa.SignIn(c, app, s);
        using (Cmd<int> cmd = Cmds.Run(rig, "E2E_SECRET", Rig.ScriptCommand("check"), app: app))
        {
            await Spa.OpenRequest(c, cmd, app, s);
            await Spa.ApproveOnce(c);
            s.Check(await cmd.Result.WaitAsync(TimeSpan.FromSeconds(30)) == 0, "fixture: a run was approved and ran");
        }

        await Spa.StartDemoFromOverview(c);
        await Spa.GoTo(c, "Audit", "Audit");
        // The host uploads its events a moment after the run.
        ILocator results = c.Page.GetByRole(AriaRole.Table, new() { Name = "Host events" });
        bool found = false;
        for (int i = 0; i < 30 && !found; i++)
        {
            await c.Page.GetByLabel("Contains text").FillAsync(Rig.ScriptFile("check"));
            await c.Page.GetByRole(AriaRole.Button, new() { Name = "Search", Exact = true }).ClickAsync();
            try
            {
                await results.GetByRole(AriaRole.Cell, new() { Name = "approved", Exact = true }).First.WaitForAsync(new() { Timeout = 1500 });
                // The events arrive one after the other: the run's first event is not all of them. Done when the authorization and the start have both come.
                string seen = await results.TextContentAsync() ?? "";
                found = seen.Contains("approved", StringComparison.Ordinal) && seen.Contains("started", StringComparison.Ordinal);
            }
            catch (Exception)
            {
                // Not uploaded yet (a timeout).
            }
        }

        s.Check(found, "the audit view shows the run's events (the authorization and the start) once the host has uploaded them");
        await c.DemoSnapAsync("In Audit, enter part of the command name in Contains text and choose Search. The matching host events appear below.");
        string all = await results.TextContentAsync() ?? "";
        s.Check(all.Contains("approved", StringComparison.Ordinal) && all.Contains("started", StringComparison.Ordinal) && !all.Contains(SecretValue, StringComparison.Ordinal), "it shows the authorization and launch outcomes and no secret value");
        s.Check(c.Page.Url.Contains("text=" + Rig.ScriptFile("check"), StringComparison.Ordinal), "the search is in the address");
        await Spa.Axe(c, s, "audit events");
        // Measure the app at 320 px without the recorder's side-by-side terminal taking up part of that width.
        if (!c.IsDemo)
        {
            var desktop = c.Page.ViewportSize;
            await c.Page.SetViewportSizeAsync(320, 568);
            s.Check(await results.EvaluateAsync<bool>("table => table.getBoundingClientRect().width <= table.parentElement.clientWidth + 1"),
                "the audit results fit a 320 px viewport");
            if (desktop is not null) await c.Page.SetViewportSizeAsync(desktop.Width, desktop.Height);
        }
        await results.GetByRole(AriaRole.Button, new() { Name = "View approved event" }).First.ClickAsync();
        ILocator eventDetails = c.Page.GetByRole(AriaRole.Dialog, new() { Name = "authorization: approved" });
        await eventDetails.GetByText("Received", new() { Exact = true }).WaitForAsync();
        ILocator command = eventDetails.GetByText("Program", new() { Exact = true }).Locator("xpath=following-sibling::dd");
        s.Check((await command.TextContentAsync())?.Contains(Rig.ScriptFile("check"), StringComparison.Ordinal) == true, "the event dialog shows the complete script command");
        await c.DemoSnapAsync("Select an event to inspect the command, full machine fingerprint, and other audit evidence.");
        await eventDetails.GetByRole(AriaRole.Button, new() { Name = "Close", Exact = true }).ClickAsync();

        await c.Page.GetByText("More filters", new() { Exact = true }).ClickAsync();
        await c.Page.GetByLabel("Time range").SelectOptionAsync("day");
        await c.Page.GetByLabel("Kind of event").SelectOptionAsync("launch");
        await c.Page.GetByRole(AriaRole.Button, new() { Name = "Search", Exact = true }).ClickAsync();
        await c.Page.WaitForFunctionAsync("() => location.search.includes('type=launch')");
        await c.Page.GetByRole(AriaRole.Status).Filter(new() { HasTextRegex = new System.Text.RegularExpressions.Regex(@"^(Showing \d+ events\.|1 event found\.)$") }).First.WaitForAsync();
        // The status line that says "found" is also there from the search before: wait for the list itself to be the narrowed one.
        await c.Page.WaitForFunctionAsync("() => { const t = document.querySelector('[aria-label=\"Host events\"]')?.textContent ?? ''; return t.includes('launch') && !t.includes('authorization'); }", null, new() { Timeout = 10000 });
        string narrowed = await results.TextContentAsync() ?? "";

        s.Check(narrowed.Contains("launch", StringComparison.Ordinal) && !narrowed.Contains("authorization", StringComparison.Ordinal) && c.Page.Url.Contains("since=", StringComparison.Ordinal) && c.Page.Url.Contains("until=", StringComparison.Ordinal), "the kind filter narrows the events to the launch");
        await c.DemoSnapAsync("Choose Past 24 hours and set Kind of event under More filters to see only recent launch events.");

        // A reload keeps the search (it is in the address).
        await c.Page.ReloadAsync();
        await Spa.Heading(c, "Audit").WaitForAsync();
        s.Check(await c.Page.GetByLabel("Contains text").InputValueAsync() == Rig.ScriptFile("check") && await c.Page.GetByLabel("Kind of event").InputValueAsync() == "launch" && await c.Page.GetByLabel("Time range").InputValueAsync() == "day", "a reload keeps the search and time range");

        await c.Page.GetByLabel("Contains text").FillAsync("nothing-like-this");
        await c.Page.GetByRole(AriaRole.Button, new() { Name = "Search", Exact = true }).ClickAsync();
        await c.Page.GetByText("No events match these filters.").WaitForAsync();
        s.Check(true, "a search with no match says so");
        await c.Page.GetByRole(AriaRole.Link, new() { Name = "Authority changes" }).ClickAsync();
        await c.Page.GetByRole(AriaRole.Table, new() { Name = "Authority changes" }).WaitForAsync();
        await c.DemoSnapAsync("Authority changes shows administrative actions, such as a secret being saved.");
        s.Check(true, "the authority's own change history is a view of its own");
        await Spa.Axe(c, s, "audit changes");
        await c.Page.GetByRole(AriaRole.Link, new() { Name = "Numbering gaps" }).ClickAsync();
        await c.Page.GetByText("No numbering anomaly matches this filter.").WaitForAsync();
        await Spa.Axe(c, s, "audit gaps");
        s.NoProblems(c);
    }

    public static async Task LockUnlock(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using SpaApp app = new(rig);
        await Spa.SignIn(c, app, s);
        s.Check(!app.Service.Lock.IsLocked && await c.Page.GetByText("Authority unlocked").First.IsVisibleAsync(), "the header says the authority is unlocked");

        await c.DemoPressAsync(Spa.Button(c, "Lock the authority"), "From Overview, select Lock the authority. Locking ends all sessions.");
        await Spa.Button(c, "Lock the authority").ClickAsync();
        ILocator dialog = Spa.Dialog(c);
        await dialog.WaitForAsync();
        s.Check((await dialog.TextContentAsync() ?? "").Contains("ends every session", StringComparison.OrdinalIgnoreCase), "the dialog warns that every session ends");
        c.Ignore("401");
        c.Ignore("404");
        await Spa.Continue(c, s, dialog);
        // The lock ends the session, so the page confirms the lock using the public authority status.
        await Spa.PageFeedback(c).GetByText("The authority is locked.").WaitForAsync(new() { Timeout = 20000 });
        s.Check(app.Service.Lock.IsLocked, "the tap locks the authority");
        s.Check(await dialog.CountAsync() == 0, "the lock confirmation appears on the page with the dialog closed");
        await Spa.Heading(c, "with-secrets").WaitForAsync(new() { Timeout = 20000 });
        s.Check(await c.Page.GetByText("The authority is locked").First.IsVisibleAsync(), "the locked authority is said in words on the sign-in view, which offers the unlock");
        await Spa.Axe(c, s, "sign-in while locked");

        // Unlock needs its own authorization but no session.
        await c.DemoPressAsync(Spa.Button(c, "Unlock the authority"), "From the signed-out page, unlock the authority with an admin passkey that supports PRF.");
        await Spa.Button(c, "Unlock the authority").ClickAsync();
        await dialog.WaitForAsync();
        string page = await Spa.Continue(c, s, dialog);
        await Spa.PageFeedback(c).WaitForAsync(new() { Timeout = 20000 });
        s.Check(!app.Service.Lock.IsLocked, "the tap unlocks the authority, with no session");
        s.Check(page.Contains("unlock", StringComparison.OrdinalIgnoreCase), "the passkey page names the unlock (" + page.Split('\n')[0] + ")");
        await c.Page.GetByText("Authority unlocked").First.WaitForAsync(new() { Timeout = 20000 });

        // The session ended with the lock: signing in again is a new tap.
        await Spa.Tap(c, s);
        await Spa.Heading(c, "Overview").WaitForAsync(new() { Timeout = 20000 });
        await c.DemoSnapAsync("The authority is unlocked and a fresh sign-in returns you to Overview.");
        s.Check(true, "after the unlock a new sign-in starts a new read-only session");
        s.NoProblems(c);
    }

    public static async Task Settings(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using SpaApp app = new(rig);
        AuthorityStore store = rig.Machine.Deployment.Store;
        await Spa.SignIn(c, app, s);
        await Spa.GoTo(c, "Settings", "Settings");
        await Spa.Axe(c, s, "settings");
        int before = store.AuditRetentionDays();

        await Spa.Button(c, "Change audit retention").ClickAsync();
        ILocator dialog = Spa.Dialog(c);
        await dialog.WaitForAsync();
        ILocator days = dialog.GetByLabel("Days to keep audit events");
        await days.FillAsync("abc");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Continue", Exact = true }).ClickAsync();
        ILocator error = dialog.GetByRole(AriaRole.Alert);
        await error.WaitForAsync();
        await c.DemoSnapAsync("In Settings, choose Change audit retention. The number of days must be a whole number.");
        s.Check((await error.TextContentAsync() ?? "").Contains("whole number", StringComparison.Ordinal) && await days.GetAttributeAsync("aria-invalid") == "true", "an invalid value is refused on the field, announced as an alert, and the field is marked invalid");
        await Spa.Axe(c, s, "the dialog with a validation error");
        await days.FillAsync("30");
        IPage passkeyPage = await Spa.OpenPasskeyPage(c, s, dialog);
        string review = await dialog.TextContentAsync() ?? "";
        s.Check(review.Contains("Keep audit events for 30 days", StringComparison.Ordinal), "after browser Back, the dialog names the pending retention change");
        s.Check(store.AuditRetentionDays() == before, "the setting is unchanged until the tap");
        string page = await Spa.TapAfterBack(c, s, passkeyPage, null);
        await Spa.PageFeedback(c).WaitForAsync(new() { Timeout = 20000 });
        s.Check(store.AuditRetentionDays() == 30, "the tap changes the setting");
        s.Check(page.Contains("30", StringComparison.Ordinal), "the passkey page shows the new value");
        await c.Page.GetByText("30 days", new() { Exact = true }).WaitForAsync();
        await c.DemoSnapAsync("Settings now shows the confirmed retention of 30 days.");
        s.Check(true, "the settings view shows the new retention");
        s.NoProblems(c);
    }

    public static async Task RefusedWithoutAuthorization(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using SpaApp app = new(rig);
        using SoftwareSigningKey other = new();
        string fp = KeyIdentity.Fingerprint(other.PublicKey);
        byte[] challenge = await rig.Machine.Deployment.Authority.BeginEnrollmentAsync();
        await rig.Machine.Deployment.Authority.EnrollAsync(EnrollmentRequest.Create("other-host", challenge, other));
        AuthorityStore store = rig.Machine.Deployment.Store;
        List<string> mutations = [];
        c.Page.Request += (_, request) =>
        {
            if (request.Method != "GET")
            {
                mutations.Add(request.Method + " " + new Uri(request.Url).AbsolutePath);
            }
        };
        await Spa.SignIn(c, app, s);
        await Spa.GoTo(c, "Machines", "Machines");

        // In the application: asking for the authorization and not tapping changes nothing, and no mutation is sent.
        ILocator row = c.Page.GetByRole(AriaRole.Row).Filter(new() { HasText = KeyIdentity.Display(fp) });
        await row.GetByRole(AriaRole.Button).ClickAsync();
        ILocator dialog = Spa.Dialog(c);
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Approve" }).ClickAsync();
        await Spa.ChangeName(dialog, "Friendly name", "");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Continue", Exact = true }).ClickAsync();
        s.Check((await dialog.GetByRole(AriaRole.Alert).TextContentAsync() ?? "").Contains("Enter a friendly name", StringComparison.Ordinal), "a pending machine cannot be approved without a name: refused on the field before anything is asked");
        await dialog.GetByLabel("Friendly name").FillAsync("e2e untapped");
        IPage passkeyPage = await Spa.OpenPasskeyPage(c, s, dialog);
        await Spa.WaitForPasskeyStep(dialog);
        await c.QuietAsync();
        s.Check(!mutations.Any(item => item.Contains("/approve", StringComparison.Ordinal)) && store.Find(fp)!.Status == MachineStatus.Pending, "without the tap the application sends no mutation and the machine stays Pending (it waits, with no limit of its own)");
        await c.DemoPressAsync(dialog.GetByRole(AriaRole.Button, new() { Name = "Cancel", Exact = true }), "Cancel before using the passkey. Opening the review does not approve the machine.");
        await dialog.GetByRole(AriaRole.Button, new() { Name = "Cancel", Exact = true }).ClickAsync();
        await dialog.WaitForAsync(new() { State = WaitForSelectorState.Detached });
        s.Check(store.Find(fp)!.Status == MachineStatus.Pending && !mutations.Any(item => item.Contains("/approve", StringComparison.Ordinal)), "cancelling changes nothing");
        await c.DemoSnapAsync("The machine is still pending and can be reviewed later.");

        // At the server: a script in the page (as a compromised page would) with the session, its secret and the right Origin, but no tap.
        c.Ignore("403");
        c.Ignore("400");
        string result = await c.Page.EvaluateAsync<string>("""
            async (fingerprint) => {
              const secret = sessionStorage.getItem('ws.session-secret');
              const send = async (path, body) => {
                const r = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Admin-Token': secret }, body: JSON.stringify(body) });
                const j = await r.json();
                return r.status + ' ' + j.code;
              };
              return [
                await send('/api/v1/machines/' + fingerprint + '/approve', { authorization: 'AAAAAAAAAAAA', name: 'sneaky' }),
                await send('/api/v1/lock', { authorization: 'AAAAAAAAAAAA' }),
                await send('/api/v1/machines/' + fingerprint + '/approve', { name: 'no-authorization-member' }),
              ].join(' | ');
            }
            """, fp);
        string[] parts = result.Split(" | ");
        s.Check(parts[0] == "403 authorization-invalid" && parts[1] == "403 authorization-invalid" && parts.Length == 3 && parts[2].StartsWith("4", StringComparison.Ordinal), "the server refuses a change with a session and no valid authorization (" + result + ")");
        s.Check(store.Find(fp)!.Status == MachineStatus.Pending && !app.Service.Lock.IsLocked, "nothing was changed by those attempts");

        // And a change from another origin is refused whatever it carries.
        // The console reports this step is meant to cause, only for the other-origin address it sends to: the browser's own lines (their wording differs between Chromium versions) and the harness's securitypolicyviolation
        // echo. Any other CSP violation (another directive or another target) is still a problem.
        string blocked = "http://127.0.0.1:" + new Uri(app.Url).Port + "/api/v1/lock";
        c.Ignore("Connecting to '" + blocked + "' violates the following Content Security Policy directive: \"connect-src 'self'\"");
        c.Ignore("Fetch API cannot load " + blocked + ". Refused to connect because it violates the document's Content Security Policy.");
        c.Ignore("Refused to connect to '" + blocked + "' because it violates the following Content Security Policy directive: \"connect-src 'self'\"");
        c.Ignore("CSP violation: connect-src " + blocked);
        string cross = await c.Page.EvaluateAsync<string>("""
            async () => {
              try {
                const r = await fetch('http://127.0.0.1:' + location.port + '/api/v1/lock', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
                return 'status ' + r.status;
              } catch (e) { return 'blocked: ' + e.name; }
            }
            """);
        s.Check(cross.StartsWith("blocked", StringComparison.Ordinal), "the page's own Content-Security-Policy (connect-src 'self') stops it sending anything to another origin (" + cross + ")");
        s.NoProblems(c);
    }

    public static async Task Accessibility(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using SpaApp app = new(rig);
        using SoftwareSigningKey other = new();
        string longHost = "a-very-long-reporting-host-name-that-keeps-going-for-layout-checks.example.internal";
        byte[] challenge = await rig.Machine.Deployment.Authority.BeginEnrollmentAsync();
        await rig.Machine.Deployment.Authority.EnrollAsync(EnrollmentRequest.Create(longHost, challenge, other));
        await Spa.SignIn(c, app, s);

        string[] views = ["Overview", "Machines", "Access", "Audit", "Settings", "Passkeys"];
        foreach ((string width, int w, int h) in new[]
                 {
                     ("desktop", 1280, 800), ("large desktop", 1440, 900), ("small laptop", 1024, 768), ("tablet", 768, 1024), ("wide phone", 430, 932),
                     ("phone", 375, 667), ("200% zoom on a phone (320 CSS px wide)", 320, 568), ("200% zoom on a desktop (640 CSS px wide)", 640, 512),
                     ("400% zoom on a desktop (320 CSS px wide)", 320, 256),
                 })
        {
            await c.Page.SetViewportSizeAsync(w, h);
            foreach (string view in views)
            {
                // GoTo waits for the SPA view's heading.
                await Spa.GoTo(c, view, view, capture: false);
                bool overflow = await c.Page.EvaluateAsync<bool>("() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1");
                s.Check(!overflow, $"no horizontal scrolling on {view} at {width}");
                if (w is 1280 or 320)
                {
                    await Spa.Axe(c, s, $"{view} at {width}");
                }
            }
        }

        // Long identifiers and a revealed full fingerprint stay inside the narrowest page.
        await c.Page.SetViewportSizeAsync(320, 568);
        await Spa.GoTo(c, "Machines", "Machines", capture: false);
        await c.Page.GetByRole(AriaRole.Button, new() { Name = longHost }).ClickAsync();
        ILocator fingerprintDetails = Spa.Dialog(c);
        await fingerprintDetails.Locator("summary").ClickAsync();
        string fullFingerprint = await fingerprintDetails.Locator("details code").TextContentAsync() ?? "";
        bool revealedOverflow = await fingerprintDetails.EvaluateAsync<bool>("element => element.scrollWidth > element.clientWidth + 1");
        s.Check(fullFingerprint.Length == 64, "the complete machine fingerprint is revealed, not a shortened value (" + fullFingerprint.Length + " characters)");
        s.Check(!revealedOverflow, "no horizontal scrolling with a long host name and a full fingerprint revealed at 320 px");
        ILocator copyFull = c.Page.GetByRole(AriaRole.Button, new() { Name = "Copy full fingerprint for " + longHost });
        s.Check(await copyFull.CountAsync() == 1 && await copyFull.First.IsVisibleAsync(), "the revealed complete fingerprint has a copy control for the machine it belongs to");
        await c.DemoSnapAsync("At 320 pixels wide, Machines can show and copy the complete device fingerprint.");
        await fingerprintDetails.GetByRole(AriaRole.Button, new() { Name = "Close", Exact = true }).ClickAsync();

        // The complete public authority fingerprint also stays readable and copyable inside Settings at the same width.
        await Spa.GoTo(c, "Settings", "Settings", capture: false);
        string authorityFingerprint = await c.Page.Locator("main code").First.TextContentAsync() ?? "";
        bool settingsOverflow = await c.Page.EvaluateAsync<bool>("() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1");
        s.Check(authorityFingerprint.Replace(" ", "").Length == 64, "Settings shows the complete public authority fingerprint (" + authorityFingerprint.Replace(" ", "").Length + " characters)");
        s.Check(!settingsOverflow, "no horizontal scrolling with the full authority fingerprint at 320 px");
        s.Check(await c.Page.GetByRole(AriaRole.Button, new() { Name = "Copy fingerprint" }).IsVisibleAsync(), "the full authority fingerprint has a copy control");

        // Touch targets: every button and link of a view is at least 24 CSS px (WCAG 2.2) in both directions; ours are 44.
        await c.Page.SetViewportSizeAsync(375, 667);
        await Spa.GoTo(c, "Machines", "Machines", capture: false);
        int small = await c.Page.EvaluateAsync<int>("() => [...document.querySelectorAll('main a, main button, nav a, header button')].filter(e => { const r = e.getBoundingClientRect(); return r.width > 0 && (r.width < 44 || r.height < 44); }).length");
        s.Check(small == 0, "every control is at least 44 by 44 CSS px on a phone (" + small + " smaller)");
        await c.DemoSnapAsync("Machines on a phone.");

        // Dark scheme and reduced motion.
        await c.Page.SetViewportSizeAsync(1280, 800);
        await c.Page.EmulateMediaAsync(new() { ColorScheme = ColorScheme.Dark, ReducedMotion = ReducedMotion.Reduce });
        foreach (string view in new[] { "Overview", "Machines", "Settings" })
        {
            await Spa.GoTo(c, view, view, capture: false);
            // The scheme has just changed: wait until the page has painted it and nothing is still animating, so that axe never sees the text colour of one scheme on the background of the other (seen once on macOS: 1.03:1).
            await c.Page.EvaluateAsync("() => new Promise(done => requestAnimationFrame(() => requestAnimationFrame(done)))");
            await c.Page.WaitForFunctionAsync("() => document.getAnimations().length === 0 && matchMedia('(prefers-color-scheme: dark)').matches");
            await Spa.Axe(c, s, $"{view} in the dark scheme");
            await c.DemoSnapAsync($"{view} in the dark scheme.");
        }

        string duration = await c.Page.EvaluateAsync<string>("() => getComputedStyle(document.querySelector('main button, nav a')).transitionDuration");
        s.Check(duration.StartsWith("1e-05", StringComparison.Ordinal) || duration.StartsWith("0.00001", StringComparison.Ordinal) || duration == "0s", "reduced motion removes transitions (" + duration + ")");
        await c.Page.EmulateMediaAsync(new() { ColorScheme = ColorScheme.Light, ReducedMotion = ReducedMotion.NoPreference });

        // Keyboard only: the skip link, the navigation, a dialog (focus inside, Escape closes it, focus returns).
        await c.Page.ReloadAsync();
        await Spa.Heading(c, "Settings").WaitForAsync();
        await c.Page.Keyboard.PressAsync("Tab");
        string first = await c.Page.EvaluateAsync<string>("() => document.activeElement.textContent.trim()");
        s.Check(first.StartsWith("Skip to the main content", StringComparison.Ordinal), "the first Tab stop is the skip link");
        bool visible = await c.Page.EvaluateAsync<bool>("() => document.activeElement.getBoundingClientRect().top >= 0");
        s.Check(visible, "the skip link is visible when focused");
        await c.DemoSnapAsync("With the keyboard, the first Tab reveals Skip to the main content.");
        await c.Page.Keyboard.PressAsync("Enter");
        await c.Page.Keyboard.PressAsync("Tab");
        s.Check(await c.Page.EvaluateAsync<bool>("() => !!document.activeElement.closest('main')"), "after the skip link, Tab continues inside the main content");

        await Spa.GoTo(c, "Machines", "Machines", capture: false);
        ILocator machineDetails = c.Page.GetByRole(AriaRole.Button, new() { Name = "View machine" }).First;
        await machineDetails.FocusAsync();
        await c.Page.Keyboard.PressAsync("Enter");
        ILocator dialog = Spa.Dialog(c);
        await dialog.WaitForAsync();
        s.Check(await c.Page.EvaluateAsync<bool>("() => !!document.activeElement.closest('dialog')"), "opening a dialog by keyboard puts focus inside it");
        await c.DemoSnapAsync("Enter opens the focused control. Tab stays within the dialog, and Escape returns focus to the control.");
        bool trapped = true;
        for (int i = 0; i < 10; i++)
        {
            await c.Page.Keyboard.PressAsync("Tab");
            // Inside the dialog, or out of the document altogether (the browser's own controls); never an element of the page behind it.
            trapped &= await c.Page.EvaluateAsync<bool>("() => document.activeElement === document.body || !!document.activeElement.closest('dialog')");
        }

        s.Check(trapped, "Tab never reaches the page behind the dialog (it is inert)");
        await c.Page.Keyboard.PressAsync("Escape");
        await dialog.WaitForAsync(new() { State = WaitForSelectorState.Detached });
        string back = await c.Page.EvaluateAsync<string>("() => document.activeElement.textContent.trim()");
        s.Check(back.Contains("View machine", StringComparison.Ordinal), "Escape returns focus to the machine row (" + back + ")");

        // Visible focus: the focused element has an outline.
        await c.Page.Keyboard.PressAsync("Tab");
        string outline = await c.Page.EvaluateAsync<string>("() => getComputedStyle(document.activeElement).outlineStyle + ' ' + getComputedStyle(document.activeElement).outlineWidth");
        s.Check(outline.StartsWith("solid 3px", StringComparison.Ordinal), "the focused control has a visible 3 px outline (" + outline + ")");

        // Text scaling: the root font size follows the person's setting (rem units), so a larger text size reflows without loss.
        string rootSize = await c.Page.EvaluateAsync<string>("() => getComputedStyle(document.documentElement).fontSize");
        s.Check(rootSize == "16px", "text is sized from the browser's own setting (" + rootSize + ")");
        s.NoProblems(c);
    }

    public static async Task Secrets(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using SpaApp app = new(rig, unlocked: false, timeLimit: TimeSpan.FromSeconds(12));
        await Spa.Unlock(c, app, s);
        await Spa.SignIn(c, app, s);
        await Spa.StartDemoFromOverview(c);

        // Add: type the name and the value, one tap.
        await Spa.GoTo(c, "Secrets", "Secrets");
        ILocator add = Spa.Button(c, "Add secret", exact: true);
        ILocator dialog = c.Page.GetByRole(AriaRole.Dialog, new() { Name = "Add secret" });
        s.Check(await c.Page.GetByLabel("Value").CountAsync() == 0, "the secret form is hidden until Add secret is opened");
        await c.DemoPressAsync(add, "Choose Add secret to open the form.");
        await Spa.Click(add);
        await Spa.Axe(c, s, "add secret dialog");
        await c.Page.GetByLabel("Name").FillAsync("E2E_SECRET");
        await c.Page.GetByLabel("Value").FillAsync(SecretValue);
        int before = await c.PasskeyCalls();
        await c.DemoPressAsync(Spa.Button(c, "Save secret", exact: true), "Enter a name and value, then choose Save secret and confirm with your passkey.");
        await Spa.Click(Spa.Button(c, "Save secret", exact: true));
        await c.Page.GetByText("Saved E2E_SECRET.").First.WaitForAsync(new() { Timeout = 20000 });
        s.Check(await dialog.CountAsync() == 0, "saving closes the Add secret dialog");
        s.Check(await c.PasskeyCalls() == before + 1, "saving used the passkey exactly once");
        s.Check(rig.Store.ListNames().SequenceEqual(["E2E_SECRET"]), "state lists the secret name");
        s.Check(!(await c.Page.ContentAsync()).Contains(SecretValue, StringComparison.Ordinal), "the value is nowhere in the page");
        s.Check(!(await Scenarios2.RawState(rig)).Contains(SecretValue, StringComparison.Ordinal), "with-secrets.db holds no plaintext of the value");
        s.Check(rig.State.TryCheck(out _), "with-secrets.db passes its check");
        await c.Page.GetByRole(AriaRole.List, new() { Name = "Secrets", Exact = true }).GetByText("E2E_SECRET", new() { Exact = true }).WaitForAsync();
        await c.DemoSnapAsync("The saved secret appears by name.");

        // A run gets the stored value (the output is redacted: the mask shows it was there).
        rig.WriteScript("show", "got");
        using (Cmd<int> run = Cmds.Run(rig, "E2E_SECRET", Rig.ScriptCommand("show"), app: app))
        {
            await Spa.OpenRequest(c, run, app, s);
            await Spa.ApproveOnce(c);
            s.Check(await run.Result.WaitAsync(TimeSpan.FromSeconds(30)) == 0 && run.Out.Text.Contains("got=" + StreamRedactor.Mask), "a run decrypts the stored value (output redacted)");
        }

        // Move and rename without a replacement.
        await Spa.GoTo(c, "Secrets", "Secrets");
        ILocator edit = Spa.Button(c, "Edit secret E2E_SECRET", exact: true);
        await c.DemoPressAsync(edit, "Choose the pencil beside a secret to edit it.");
        await Spa.Click(edit);
        ILocator editor = c.Page.GetByRole(AriaRole.Dialog, new() { Name = "Edit secret" });
        ILocator newValue = editor.GetByLabel("New value");
        s.Check(await newValue.InputValueAsync() == "" && await newValue.GetAttributeAsync("type") == "password",
            "editing shows a blank, masked replacement field");
        await Spa.Axe(c, s, "edit secret dialog");
        await editor.GetByLabel("Name").FillAsync("DEPLOY_KEY");
        await editor.GetByLabel("Folder path").FillAsync("apps");
        ILocator saveChanges = Spa.Button(c, "Save changes", exact: true);
        before = await c.PasskeyCalls();
        await c.DemoPressAsync(saveChanges, "Change the name or folder. Leave New value blank to keep the saved value.");
        await Spa.Click(saveChanges);
        const string moved = "apps/DEPLOY_KEY";
        await c.Page.GetByText("Saved " + moved + ".").First.WaitForAsync(new() { Timeout = 20000 });
        s.Check(rig.Store.ListNames().SequenceEqual([moved]) && await c.PasskeyCalls() == before + 1, "moving and renaming uses one passkey tap");
        await c.Page.Locator("summary").GetByText("apps", new() { Exact = true }).ClickAsync();

        // Replace a value from the same editor.
        await Spa.Click(Spa.Button(c, "Edit secret " + moved, exact: true));
        s.Check(await newValue.InputValueAsync() == "", "opening the editor again leaves the saved value hidden");
        await newValue.FillAsync(SecretValue + "-2");
        await c.DemoPressAsync(saveChanges, "To replace a value, enter the new value here and choose Save changes.");
        await Spa.Click(saveChanges);
        await editor.WaitForAsync(new() { State = WaitForSelectorState.Detached });
        await c.Page.GetByText("Saved " + moved + ".").First.WaitForAsync(new() { Timeout = 20000 });
        s.Check(rig.Store.ListNames().SequenceEqual([moved]) && !(await c.Page.ContentAsync()).Contains(SecretValue, StringComparison.Ordinal),
            "replacing a value keeps the path and leaves no secret value on the page");

        // Remove: one tap.
        before = await c.PasskeyCalls();
        await c.DemoPressAsync(Spa.Button(c, "Remove secret " + moved), "Choose the trash can beside the secret and confirm with your passkey.");
        await Spa.Click(Spa.Button(c, "Remove secret " + moved));
        await c.Page.GetByText("Removed " + moved + ".").First.WaitForAsync(new() { Timeout = 20000 });
        await c.DemoSnapAsync("The secret was removed.");
        s.Check(await c.PasskeyCalls() == before + 1, "removing used the passkey exactly once");
        s.Check(rig.Store.ListNames().Count == 0, "state no longer lists the secret");
        s.Check(!(await Scenarios2.RawState(rig)).Contains(SecretValue, StringComparison.Ordinal), "with-secrets.db still holds no plaintext");
        await Spa.Axe(c, s, "secrets");
        AuditChecks.Expect(s, rig, "setup", "secrets-set", "authorization-approved", "launch-started", "execution-exited", "secrets-edited", "secrets-edited", "secrets-removed");
        s.NoProblems(c);
    }
}

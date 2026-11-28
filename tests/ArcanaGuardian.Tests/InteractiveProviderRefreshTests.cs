using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcanaGuardian.LastPass;

namespace ArcanaGuardian.Tests;

internal static class InteractiveProviderRefreshTests
{
    private const string Path = "100/F_70617373776F7264";
    private const string Name = "APP_PASSWORD";
    private const string Value = "synthetic LastPass value";
    private const string Account = "Vault@example.test";

    internal static async Task Run(Action<bool, string> check, string root)
    {
        ProviderRegistry registry = new();
        LastPassProvider.RegisterInteractive(registry);
        Helper? helper = null;
        using AdminApp app = new(root, providers: registry, launchInteractiveRefresh: (request, _, _) =>
            Task.FromResult<IInteractiveProviderRefresh>(helper = new Helper(request)));
        using (Unlock unlock = TestVault.Unlock(app.State, app.Laptop)!)
        {
            check(app.Service.Keys!.TryOpen(TestState.Current(app.State)!, unlock), "interactive LastPass: the admin unlock opens the store key");
        }

        ProviderAuthority providers = app.Service.Providers!;
        ProviderInstance instance = providers.Store.AddInstance("test-account", LastPassProvider.InteractiveType,
            JsonSerializer.Serialize(new { username = Account, european = true }), TimeSpan.FromMinutes(10));
        await providers.StartInstanceAsync(instance);
        Mount mount = providers.Store.AddMount(instance.Id, MountKind.Single, Name, Path);
        check((await providers.Reconciler.ReconcileAsync(mount, CancellationToken.None)).Complete,
            "interactive LastPass maps an exact item field without a vendor connection");
        AdminBrowser browser = await app.SignedIn();
        AdminBrowser other = await app.SignedIn();
        AdminBrowser convenience = app.Browser();
        check(await convenience.SignInAsync(app.Phone), "interactive LastPass: the convenience key can sign in");
        string launch = $"/api/v1/providers/{instance.Id:D}/value-refreshes";
        const string authorizations = "/api/v1/authorizations";
        const string operation = "provider-refresh-values";

        async Task<string> Start()
        {
            using RSA browserKey = RSA.Create(2048);
            (int status, string body) = await browser.PostAsync(launch,
                JsonSerializer.Serialize(new { browserKey = Base64Url.EncodeToString(browserKey.ExportSubjectPublicKeyInfo()) }));
            using JsonDocument json = JsonDocument.Parse(body);
            string encryptedCode = json.RootElement.GetProperty("encryptedCode").GetString()!;
            string code = Encoding.ASCII.GetString(browserKey.Decrypt(Base64Url.DecodeFromChars(encryptedCode), RSAEncryptionPadding.OaepSHA256));
            check(status == 201 && code == "A7BW" && json.RootElement.GetProperty("refresh").GetProperty("account").GetString() == Account
                && body.Contains(Name, StringComparison.Ordinal),
                "interactive LastPass encrypts its matching code to the browser and shows the full configured email and scope");
            return json.RootElement.GetProperty("refresh").GetProperty("id").GetString()!;
        }

        async Task<string> Stage(string id)
        {
            helper!.Complete();
            for (int attempt = 0; attempt < 50; attempt++)
            {
                (_, string body, _) = await browser.GetAsync(Status(id));
                if (body.Contains("\"state\":\"ready\"", StringComparison.Ordinal)) return body;
                await Task.Delay(10);
            }
            throw new InvalidOperationException("The fixture failed to stage an interactive refresh.");
        }

        async Task<(string Id, string Assertion)> Prepare(string id, TestAuthenticator? signer = null)
        {
            (int status, string body) = await browser.PostAsync(authorizations + "/inline", AdminBrowser.AuthorizationBody(operation, ("id", id)));
            using JsonDocument document = JsonDocument.Parse(body);
            JsonElement json = document.RootElement;
            check(status == 201 && body.Contains("encrypted-batch-sha256", StringComparison.Ordinal)
                && !body.Contains(Value, StringComparison.Ordinal), "interactive LastPass passkey challenge covers the staged batch digest");
            using JsonDocument payload = JsonDocument.Parse(json.GetProperty("proof").GetProperty("payload").GetString()!);
            return (json.GetProperty("id").GetString()!, (signer ?? app.Laptop).Assert(
                Base64Url.DecodeFromChars(payload.RootElement.GetProperty("bind").GetString()!), browser.Origin,
                payload.RootElement.GetProperty("rpId").GetString()!, TestState.NextCount()));
        }

        async Task<int> Submit(string id, string assertion)
            => (await browser.PostAsync(authorizations + "/" + id + "/proof", JsonSerializer.Serialize(new { proof = assertion }))).Status;

        string refresh = await Start();
        check(helper!.Request.RequestedBy == "laptop" && helper.Request.Account == Account
            && helper.Request.Mappings.Single() == (Path, Name) && helper.Request.European,
            "interactive LastPass takes the requester from the authenticated admin session");
        check((await other.GetAsync(Status(refresh))).Status == 404
            && (await other.SendAsync(HttpMethod.Delete, Status(refresh), null)).Status == 404
            && (await browser.PostAsync(authorizations + "/inline", AdminBrowser.AuthorizationBody(operation, ("id", refresh)))).Status == 409,
            "interactive LastPass refuses cross-session access and approval before staging");
        string staged = await Stage(refresh);
        check(!staged.Contains(Value, StringComparison.Ordinal) && !staged.Contains(JweCipher.Prefix, StringComparison.Ordinal) && !staged.Contains("A7BW", StringComparison.Ordinal)
            && providers.Store.ReadCache(instance.Id, Path) is null,
            "interactive LastPass exposes neither plaintext nor ciphertext in the browser and writes nothing before approval");
        string request = AdminBrowser.AuthorizationBody(operation, ("id", refresh));
        check((await convenience.GetAsync(Status(refresh))).Status == 404 && (await convenience.PostAsync(authorizations + "/inline", request)).Status == 403,
            "interactive LastPass: a convenience session cannot read or authorize the staged refresh");
        Tapped wrongKey = await browser.OpAsyncWithoutMutation(operation, app.Phone, ("id", refresh));
        (string wrongAuthorization, string wrongAssertion) = await Prepare(refresh, app.Phone);
        int wrongStatus = await Submit(wrongAuthorization, wrongAssertion);
        check(wrongKey.Link is not null && wrongKey.ApproveStatus is 403 or 400 && wrongStatus == 409
            && providers.Store.ReadCache(instance.Id, Path) is null,
            "interactive LastPass: a convenience key cannot authorize the staged refresh through the page or inline (page " + wrongKey.ApproveStatus + ", start " + wrongKey.PostStatus + ", inline " + wrongStatus + ", " + wrongKey.Error + ")");

        (string authorization, string assertion) = await Prepare(refresh);
        check(await Submit(authorization, assertion) == 200 && await Submit(authorization, assertion) == 409
            && providers.Store.ReadCache(instance.Id, Path) is { } row && JweCipher.IsCiphertext(row.Ciphertext)
            && (await browser.GetAsync(Status(refresh))).Status == 404,
            "interactive LastPass commits once after the operation-bound WebAuthn assertion");

        app.Clock.Advance(TimeSpan.FromMinutes(9));
        using (SecretValues values = providers.Source.GetValues([Name]))
            check(values.Text(Name) == Value, "interactive LastPass runs use the approved cache for the configured lifetime");
        app.Clock.Advance(TimeSpan.FromMinutes(2));
        bool expired = false;
        try { using SecretValues values = providers.Source.GetValues([Name]); }
        catch (SecretStoreException refusal) { expired = refusal.Message.Contains("InteractionRequired", StringComparison.Ordinal); }
        check(expired, "interactive LastPass runs require another refresh after the cache expires");

        string cancelled = await Start();
        check((await browser.SendAsync(HttpMethod.Delete, Status(cancelled), null)).Status == 200
            && (await browser.GetAsync(Status(cancelled))).Status == 404,
            "interactive LastPass cancellation drops the waiting terminal session");

        string changed = await Start();
        await Stage(changed);
        (authorization, assertion) = await Prepare(changed);
        providers.Store.RemoveMount(mount.Id);
        int drifted = await Submit(authorization, assertion);
        (_, string outcome, _) = await browser.GetAsync(authorizations + "/" + authorization);
        check(drifted == 200 && outcome.Contains("mounts changed", StringComparison.Ordinal),
            "interactive LastPass refuses an otherwise valid approval after the mount changed");

        check(registry.Types().Select(type => type.Type).SequenceEqual([LastPassProvider.InteractiveType]),
            "only the interactive LastPass provider is registered");
    }

    private static string Status(string id) => "/api/v1/provider-value-refreshes/" + id;

    private sealed class Helper(InteractiveProviderRefreshRequest request) : IInteractiveProviderRefresh
    {
        private readonly TaskCompletionSource<IReadOnlyDictionary<string, string>> _stage = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public InteractiveProviderRefreshRequest Request { get; } = request;
        public string MatchingCode => "A7BW";
        public void Complete() => _stage.TrySetResult(new Dictionary<string, string>
        {
            [Path] = JweCipher.Instance.Encrypt(Value, Request.StorePublicKey),
        });
        public Task<IReadOnlyDictionary<string, string>> ReceiveAsync(CancellationToken cancel) => _stage.Task.WaitAsync(cancel);
        public void Dispose() { }
    }
}

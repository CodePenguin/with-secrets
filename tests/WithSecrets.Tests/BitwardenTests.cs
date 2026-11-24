using System.Text;
using System.Text.Json;

using Microsoft.Extensions.Logging.Abstractions;

using WithSecrets.Bitwarden;

namespace WithSecrets.Tests;

internal static class BitwardenTests
{
    private const string Project = "a1111111-1111-4111-8111-111111111111";
    private const string OtherProject = "a2222222-2222-4222-8222-222222222222";
    private const string Secret = "b1111111-1111-4111-8111-111111111111";
    private const string MovedSecret = "b2222222-2222-4222-8222-222222222222";
    private const string WrongSecret = "b3333333-3333-4333-8333-333333333333";
    private const string SlowSecret = "b4444444-4444-4444-8444-444444444444";
    private const string Leaf = "S_b1111111111141118111111111111111";
    private const string MovedLeaf = "S_b2222222222242228222222222222222";
    private const string WrongLeaf = "S_b3333333333343338333333333333333";
    private const string SlowLeaf = "S_b4444444444444448444444444444444";
    private const string DefaultServer = "https://vault.bitwarden.com";
    private const string CustomServer = "https://vault.bitwarden.eu";
    private const string Token = "fake-bws-token";
    private const string Value = "line one\r\nline two\n";

    internal static int FakeBws(string[] args)
    {
        if (args is not [.., "--server-url", string server, "--output", "json"]
            || Environment.GetEnvironmentVariable("BWS_ACCESS_TOKEN") != Token
            || Environment.GetEnvironmentVariable("BWS_SERVER_URL") is not null)
        {
            Console.Error.Write("private CLI detail");
            return 1;
        }

        switch (args[..^4])
        {
            case ["project", "list"] when server is DefaultServer or CustomServer:
                Console.Write(JsonSerializer.Serialize(new[] { new { id = Project } }));
                break;
            case ["project", "get", Project] when server == DefaultServer:
                Console.Write(JsonSerializer.Serialize(new { id = Project }));
                break;
            case ["project", "get", OtherProject] when server == CustomServer:
                Console.Write(JsonSerializer.Serialize(new { id = OtherProject }));
                break;
            case ["secret", "list", Project] when server == DefaultServer:
                Console.Write(JsonSerializer.Serialize(new[] { new { id = Secret, projectId = Project, value = Value } }));
                break;
            case ["secret", "get", Secret] when server == DefaultServer:
                Console.Write(JsonSerializer.Serialize(new { id = Secret, projectId = Project, value = Value }));
                break;
            case ["secret", "get", MovedSecret] when server == DefaultServer:
                Console.Write(JsonSerializer.Serialize(new { id = MovedSecret, projectIds = new[] { OtherProject }, value = Value }));
                break;
            case ["secret", "get", WrongSecret] when server == DefaultServer:
                Console.Write(JsonSerializer.Serialize(new { id = Secret, projectId = Project, value = Value }));
                break;
            case ["secret", "get", SlowSecret] when server == DefaultServer:
                Thread.Sleep(TimeSpan.FromSeconds(20));
                break;
            default:
                Console.Error.Write("private CLI detail");
                return 1;
        }

        return 0;
    }

    internal static async Task Run(Action<bool, string> check)
    {
        string? previousServer = Environment.GetEnvironmentVariable("BWS_SERVER_URL");
        string? previousToken = Environment.GetEnvironmentVariable("BWS_ACCESS_TOKEN");
        string? previousTokenServer = Environment.GetEnvironmentVariable("BWS_ACCESS_TOKEN_SERVER_URL");
        var authorityLock = AuthorityLock.UnlockedForTests();
        int credentialReads = 0;
        var reporter = new Reporter();
        string executablePath = Path.Combine(AppContext.BaseDirectory,
            OperatingSystem.IsWindows() ? "WithSecrets.Tests.exe" : "WithSecrets.Tests");
        IProviderAdapter adapter = new BitwardenAdapter(executablePath, (reference, _) =>
        {
            credentialReads++;
            return reference == "BWS_ACCESS_TOKEN" ? Token : null;
        }, () => authorityLock.UnlockSessionToken);
        try
        {
            Environment.SetEnvironmentVariable("BWS_SERVER_URL", "https://example.invalid");
            Environment.SetEnvironmentVariable("BWS_ACCESS_TOKEN", Token);
            Environment.SetEnvironmentVariable("BWS_ACCESS_TOKEN_SERVER_URL", null);
            const string json = """{"tokenEnv":"BWS_ACCESS_TOKEN","serverUrl":"https://vault.bitwarden.com"}""";
            var registry = new ProviderRegistry();
            BitwardenProvider.Register(registry, authorityLock, executablePath);
            check(registry.Types().Single().Type == BitwardenAdapter.ProviderType && ProviderAdmin.ConfigurationScreen(json) is null
                && (await registry.ValidateProposedAsync(BitwardenAdapter.ProviderType, json, Project, NullLogger.Instance, default)).Count == 0,
                "Bitwarden is advertised and validates the SPA configuration and mount through the production registry factory");
            const string customJson = """{"tokenEnv":"BWS_ACCESS_TOKEN","serverUrl":"https://vault.bitwarden.eu"}""";
            check((await registry.ValidateProposedAsync(BitwardenAdapter.ProviderType, customJson, null, NullLogger.Instance, default)).Single().Target == "serverUrl"
                && ProviderAdmin.ConfigurationScreen("""{"tokenEnv":"0.raw-token:secret"}""") is not null
                && ProviderAdmin.ConfigurationScreen("""{"accessToken":"canary"}""") is not null,
                "Bitwarden refuses unbound endpoints and the admin screen rejects raw credentials");
            Environment.SetEnvironmentVariable("BWS_ACCESS_TOKEN_SERVER_URL", CustomServer);
            check((await registry.ValidateProposedAsync(BitwardenAdapter.ProviderType, customJson, OtherProject, NullLogger.Instance, default)).Count == 0,
                "Bitwarden validates a custom endpoint bound by the authority environment");
            var config = new BitwardenConfiguration();
            using JsonDocument document = JsonDocument.Parse(json);
            config.Load(document);
            await adapter.InitializeAsync(config,
                new(Guid.NewGuid(), BitwardenAdapter.ProviderType, BitwardenAdapter.AdapterVersion, NullLogger.Instance, reporter), default);
            check(reporter.Events.Contains(new LifecycleChangedEvent(AdapterLifecycleState.Ready)), "Bitwarden reports readiness after initialization");
            check((await adapter.ValidateConfigurationAsync(config, default)).Count == 0
                && (await adapter.ValidateMountAsync(config, Project, default)).Count == 0
                && (await adapter.ValidateMountAsync(config, Project + "/" + Leaf, default)).Count == 0
                && (await adapter.ValidateMountAsync(config, Project + "/" + MovedLeaf, default)).Count == 1,
                "Bitwarden validates credentials, project mounts and individual secret mounts");

            var custom = new BitwardenConfiguration();
            using JsonDocument customDocument = JsonDocument.Parse(JsonSerializer.Serialize(
                new { tokenEnv = "BWS_ACCESS_TOKEN", serverUrl = CustomServer + "/" }));
            custom.Load(customDocument);
            check((await adapter.ValidateMountAsync(custom, OtherProject, default)).Count == 0,
                "Bitwarden passes the configured server URL explicitly and ignores the inherited override");

            foreach (string serverUrl in new[] { "http://example.invalid", "https://user:pass@example.invalid", "https://example.invalid?query", "https://example.invalid#fragment" })
            {
                using JsonDocument invalid = JsonDocument.Parse(JsonSerializer.Serialize(
                    new { tokenEnv = "BWS_ACCESS_TOKEN", serverUrl }));
                custom.Load(invalid);
                check((await adapter.ValidateConfigurationAsync(custom, default)).Single().Target == "serverUrl",
                    "Bitwarden rejects invalid server URLs before starting the CLI");
            }

            ListSecretsResult listed = await adapter.ListSecretsAsync(new(Project, null, null), default);
            ProviderSecretInfo info = listed.Secrets.Single();
            check(listed.IsComplete && listed.NextContinuationToken is null && info.Path == Leaf
                && info.ExternalSecretId == Project + "/" + Leaf && info.Description is null
                && (await adapter.ListSecretsAsync(new(Project, MovedLeaf, null), default)).Secrets.Count == 0
                && (await adapter.ListSecretsAsync(new(OtherProject, MovedLeaf, null), default)).Secrets.Single().Path == MovedLeaf,
                "Bitwarden lists stable relative paths and resolves single-secret mounts without a project listing");

            int before = credentialReads;
            ProviderSecretRequest[] requests = [new(Guid.NewGuid(), Project + "/" + Leaf), new(Guid.NewGuid(), Project + "/" + Leaf),
                new(Guid.NewGuid(), Project + "/" + MovedLeaf), new(Guid.NewGuid(), OtherProject + "/" + MovedLeaf),
                new(Guid.NewGuid(), Project + "/" + WrongLeaf), new(Guid.NewGuid(), "../bad")];
            IReadOnlyList<ProviderSecretResult> results = await adapter.RetrieveSecretsAsync(requests, default);
            check(credentialReads == before + 1 && results.Select(result => result.RequestId).SequenceEqual(requests.Select(request => request.RequestId))
                && results[0].Secret?.Value.SequenceEqual(Encoding.UTF8.GetBytes(Value)) == true
                && results[1].Secret?.Value.SequenceEqual(Encoding.UTF8.GetBytes(Value)) == true
                && !ReferenceEquals(results[0].Secret?.Value, results[1].Secret?.Value)
                && results[2].ErrorKind == ProviderErrorKind.SecretNotFound
                && results[3].Secret?.Value.SequenceEqual(Encoding.UTF8.GetBytes(Value)) == true
                && results[4].ErrorKind == ProviderErrorKind.InvalidResponse
                && results[5].ErrorKind == ProviderErrorKind.InvalidConfiguration,
                "Bitwarden reads requested IDs without listing their projects and verifies returned IDs and membership");
            check(reporter.Events.Last() is HealthChangedEvent { State: AdapterHealthState.Degraded }, "Bitwarden reports an invalid response as degraded");

            Task<IReadOnlyList<ProviderSecretResult>> inProgress = adapter.RetrieveSecretsAsync([new(Guid.NewGuid(), Project + "/" + SlowLeaf)], default);
            authorityLock.Lock("test");
            await Fails(ProviderErrorKind.InteractionRequired, () => inProgress, check);
            await Fails(ProviderErrorKind.InteractionRequired, () => adapter.ListSecretsAsync(new(Project, null, null), default), check);
            authorityLock.Unlock(UnlockMethod.Seam);
            await Fails(ProviderErrorKind.Unknown,
                () => adapter.ListSecretsAsync(new("a4444444-4444-4444-8444-444444444444", null, null), default), check);
            using var deadline = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
            try
            {
                await adapter.RetrieveSecretsAsync([new(Guid.NewGuid(), Project + "/" + SlowLeaf)], deadline.Token);
                check(false, "Bitwarden cancels a pending CLI call");
            }
            catch (OperationCanceledException) when (deadline.IsCancellationRequested)
            {
                check(true, "Bitwarden cancels a pending CLI call");
            }

            var updated = new BitwardenConfiguration();
            using JsonDocument updatedDocument = JsonDocument.Parse("""{"tokenEnv":"WITH_SECRETS_BITWARDEN_TOKEN_OTHER"}""");
            updated.Load(updatedDocument);
            await adapter.UpdateConfigurationAsync(updated, default);
            check(reporter.Events.Last() is InvalidateProviderDataEvent { InvalidateEntireProviderInstance: true },
                "Bitwarden invalidates provider data when the connection configuration changes");
            await Fails(ProviderErrorKind.AuthenticationFailed, () => adapter.ListSecretsAsync(new(Project, null, null), default), check);
        }
        finally
        {
            await adapter.ShutdownAsync(default);
            Environment.SetEnvironmentVariable("BWS_SERVER_URL", previousServer);
            Environment.SetEnvironmentVariable("BWS_ACCESS_TOKEN", previousToken);
            Environment.SetEnvironmentVariable("BWS_ACCESS_TOKEN_SERVER_URL", previousTokenServer);
        }
    }

    private sealed class Reporter : IAdapterStatusReporter
    {
        public List<AdapterStatusEvent> Events { get; } = [];

        public void Report(AdapterStatusEvent statusEvent) => Events.Add(statusEvent);
    }

    private static async Task Fails(ProviderErrorKind kind, Func<Task> call, Action<bool, string> check)
    {
        try
        {
            await call();
            check(false, "Bitwarden reports " + kind);
        }
        catch (ProviderAdapterException error)
        {
            check(error.Kind == kind && !error.Message.Contains("private CLI detail", StringComparison.Ordinal),
                "Bitwarden reports " + kind + " without CLI stderr");
        }
    }
}

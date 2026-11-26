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
    private const string RefusedSecret = "b5555555-5555-4555-8555-555555555555";
    private const string RefusedLeaf = "S_b5555555555545558555555555555555";
    private const string GoneSecret = "b6666666-6666-4666-8666-666666666666";
    private const string GoneLeaf = "S_b6666666666646668666666666666666";
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
        if (args is not [.., "--config-file", string configPath, "--profile", "default", "--output", "json"]
            || Environment.GetEnvironmentVariable("BWS_ACCESS_TOKEN") != Token
            || Environment.GetEnvironmentVariable("BWS_SERVER_URL") is not null
            || File.ReadAllLines(configPath) is not ["[profiles.default]", string serverSetting, "state_opt_out = true"]
            || !serverSetting.StartsWith("server_base = ", StringComparison.Ordinal))
        {
            Console.Error.Write("private CLI detail");
            return 1;
        }

        string? server = JsonSerializer.Deserialize<string>(serverSetting["server_base = ".Length..]);
        switch (args[..^6])
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
            case ["secret", "get", GoneSecret] when server == DefaultServer:
                // The text bws 2.1.0 prints for an unknown secret.
                Console.Error.Write("Error: \n   0: Received error message from server: [404 Not Found] {\"message\":\"Resource not found.\"}");
                return 1;
            case ["secret", "get", RefusedSecret] when server == DefaultServer:
                // The text bws 2.1.0 prints for a token the server refused.
                Console.Error.Write("Error: \n   0: Received error message from server: [400 Bad Request] {\"error\":\"invalid_client\"}");
                return 1;
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
        var authorityLock = AuthorityLock.UnlockedForTests();
        int decryptions = 0;
        var (reviewPublic, reviewPrivate) = JweCipher.Instance.NewKeyPair();
        string Decrypt(string ciphertext)
        {
            decryptions++;
            return JweCipher.Instance.Decrypt(reviewPrivate, ciphertext);
        }
        var reporter = new Reporter();
        string executablePath = Path.Combine(AppContext.BaseDirectory,
            OperatingSystem.IsWindows() ? "WithSecrets.Tests.exe" : "WithSecrets.Tests");
        IProviderAdapter adapter = new BitwardenAdapter(executablePath, Decrypt, () => authorityLock.UnlockSessionToken);
        try
        {
            Environment.SetEnvironmentVariable("BWS_SERVER_URL", "https://example.invalid");
            Environment.SetEnvironmentVariable("BWS_ACCESS_TOKEN", "inherited-token-must-not-be-used");
            string json = BitwardenProvider.SealConfiguration(Token, DefaultServer, reviewPublic);
            var registry = new ProviderRegistry();
            BitwardenProvider.Register(registry, authorityLock, executablePath, Decrypt);
            check(registry.Types().Single().Type == BitwardenAdapter.ProviderType && !json.Contains(Token, StringComparison.Ordinal)
                && ProviderAdmin.ConfigurationScreen(json) is null
                && (await registry.ValidateProposedAsync(BitwardenAdapter.ProviderType, json, Project, NullLogger.Instance, default)).Count == 0,
                "Bitwarden validates an encrypted token and ignores inherited token and server variables");
            string customJson = BitwardenProvider.SealConfiguration(Token, CustomServer, reviewPublic);
            check((await registry.ValidateProposedAsync(BitwardenAdapter.ProviderType, customJson, OtherProject, NullLogger.Instance, default)).Count == 0,
                "Bitwarden validates a custom HTTPS server bound to the encrypted token");
            const string variableConfiguration = """{"tokenEnv":"BWS_ACCESS_TOKEN","serverUrl":"https://vault.bitwarden.com"}""";
            check(ProviderAdmin.ConfigurationScreen(variableConfiguration) is not null &&
                (await registry.ValidateProposedAsync(BitwardenAdapter.ProviderType, variableConfiguration, null, NullLogger.Instance, default)).Count == 1 &&
                (await registry.ValidateProposedAsync(BitwardenAdapter.ProviderType, """{"serverUrl":"https://vault.bitwarden.com"}""", null, NullLogger.Instance, default)).Count == 1,
                "Bitwarden requires a sealed token");
            using JsonDocument redirected = JsonDocument.Parse(json.Replace(DefaultServer, CustomServer, StringComparison.Ordinal));
            BitwardenConfiguration stored = new();
            stored.Load(redirected);
            check((await adapter.ValidateConfigurationAsync(stored, default)).Count == 1,
                "changing only the stored server URL cannot send the encrypted Bitwarden credential to a different server");
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
            using JsonDocument customDocument = JsonDocument.Parse(customJson);
            custom.Load(customDocument);
            check((await adapter.ValidateMountAsync(custom, OtherProject, default)).Count == 0,
                "Bitwarden passes the configured server URL explicitly and ignores the inherited override");

            foreach (string serverUrl in new[] { "http://example.invalid", "https://user:pass@example.invalid", "https://example.invalid?query", "https://example.invalid#fragment" })
            {
                using JsonDocument invalid = JsonDocument.Parse(JsonSerializer.Serialize(
                    new { encryptedConfiguration = config.EncryptedConfiguration, serverUrl }));
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

            int before = decryptions;
            ProviderSecretRequest[] requests = [new(Guid.NewGuid(), Project + "/" + Leaf), new(Guid.NewGuid(), Project + "/" + Leaf),
                new(Guid.NewGuid(), Project + "/" + MovedLeaf), new(Guid.NewGuid(), OtherProject + "/" + MovedLeaf),
                new(Guid.NewGuid(), Project + "/" + WrongLeaf), new(Guid.NewGuid(), "../bad")];
            IReadOnlyList<ProviderSecretResult> results = await adapter.RetrieveSecretsAsync(requests, default);
            check(decryptions == before + 1 && results.Select(result => result.RequestId).SequenceEqual(requests.Select(request => request.RequestId))
                && results[0].Secret?.Value.SequenceEqual(Encoding.UTF8.GetBytes(Value)) == true
                && results[1].Secret?.Value.SequenceEqual(Encoding.UTF8.GetBytes(Value)) == true
                && !ReferenceEquals(results[0].Secret?.Value, results[1].Secret?.Value)
                && results[2].ErrorKind == ProviderErrorKind.SecretNotFound
                && results[3].Secret?.Value.SequenceEqual(Encoding.UTF8.GetBytes(Value)) == true
                && results[4].ErrorKind == ProviderErrorKind.InvalidResponse
                && results[5].ErrorKind == ProviderErrorKind.InvalidConfiguration,
                "Bitwarden reads requested IDs without listing their projects and verifies returned IDs and membership");
            check(reporter.Events.OfType<HealthChangedEvent>().Last() is { State: AdapterHealthState.Degraded }, "Bitwarden reports an invalid response as degraded");
            IReadOnlyList<ProviderSecretResult> refused = await adapter.RetrieveSecretsAsync([new(Guid.NewGuid(), Project + "/" + RefusedLeaf)], default);
            check(refused.Single().ErrorKind == ProviderErrorKind.AuthenticationFailed && reporter.Events.OfType<HealthChangedEvent>().Last() is { State: AdapterHealthState.Misconfigured },
                "Bitwarden classifies a refused token from the CLI diagnostics and reports it as misconfigured");

            // An unknown secret is 404 from the CLI: a finding about the mount or a missing secret, never a failed validation or a provider health problem.
            ProviderSecretRequest goneRequest = new(Guid.NewGuid(), Project + "/" + GoneLeaf);
            IReadOnlyList<ProviderSecretResult> gone = await adapter.RetrieveSecretsAsync([goneRequest], default);
            check(gone.Single().ErrorKind == ProviderErrorKind.SecretNotFound
                && reporter.Events.OfType<HealthChangedEvent>().Last() is { State: AdapterHealthState.Healthy },
                "Bitwarden reports a 404 as a missing secret without changing provider health");
            check((await adapter.ValidateMountAsync(config, Project + "/" + GoneLeaf, default)).Single().Target == "basePath"
                && (await adapter.ListSecretsAsync(new(Project, GoneLeaf, null), default)).Secrets.Count == 0,
                "Bitwarden validates and lists an unknown secret as nothing found, not as a failure");

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
            updated.Load(redirected);
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

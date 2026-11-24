using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using WithSecrets.OnePassword;

namespace WithSecrets.Tests;

internal static class OnePasswordTests
{
    internal const string FakeToken = "fake-op-token";
    internal const string SlowToken = "fake-op-slow-token";
    private const string Leaf = "F_70617373776F7264";
    private const string Value = "test line one\r\ntest line two\n";

    internal static int FakeOp(string[] args)
    {
        if (Environment.GetEnvironmentVariable("OP_CONNECT_HOST") is not null || Environment.GetEnvironmentVariable("OP_SESSION_test") is not null)
        {
            return 3;
        }

        switch (args)
        {
            case ["user", "get", "--me", "--format", "json"]:
                if (Environment.GetEnvironmentVariable("OP_SERVICE_ACCOUNT_TOKEN") == SlowToken)
                {
                    Thread.Sleep(TimeSpan.FromSeconds(20));
                }

                Console.Write("""{"id":"fake-user"}""");
                break;
            case ["vault", "get", "vault", "--format", "json"]:
                Console.Write("""{"id":"vault"}""");
                break;
            case ["item", "list", "--vault", "vault", "--format", "json"]:
                Console.Write("""[{"id":"item"},{"id":"archived","state":"ARCHIVED"}]""");
                break;
            case ["item", "get", "item", "--vault", "vault", "--format", "json"]:
            case ["item", "get", "item", "--vault", "vault", "--format", "json", "--reveal"]:
                Console.Write(JsonSerializer.Serialize(new
                {
                    id = "item",
                    vault = new { id = "vault" },
                    fields = new[] { new { id = "password", value = Value }, new { id = "empty", value = "" } }
                }));
                break;
            case ["item", "get", "invalid", ..]:
                Console.Write("malformed canary");
                break;
            case ["vault", "get", "gone", ..]:
            case ["item", "list", "--vault", "gone", ..]:
                Console.Error.Write("\"gone\" isn't a vault in this account");
                return 1;
            case ["item", "get", "gone", ..]:
                Console.Error.Write("\"gone\" isn't an item in the vault");
                return 1;
            case ["item", "get", "badauth", ..]:
                Console.Error.Write("[ERROR] error initializing client: Signin credentials are not compatible with the provided user auth from server");
                return 1;
            case ["item", "get", "limited", ..]:
                Console.Error.Write("Too many requests");
                return 1;
            case ["item", "get", "dupes", ..]:
                // Field ids are unique only within a section: "dupe" occurs twice, "uniq" once.
                Console.Write(JsonSerializer.Serialize(new
                {
                    id = "dupes",
                    vault = new { id = "vault" },
                    fields = new[] { new { id = "dupe", value = "one" }, new { id = "uniq", value = "two" }, new { id = "dupe", value = "three" } }
                }));
                break;
            case ["item", "get", "slow", ..]:
                Thread.Sleep(TimeSpan.FromSeconds(20));
                break;
            default:
                Console.Error.Write("private failure canary");
                return 1;
        }

        return 0;
    }

    public static async Task Run(Action<bool, string> check)
    {
        string? previousHost = Environment.GetEnvironmentVariable("OP_CONNECT_HOST");
        string? previousSession = Environment.GetEnvironmentVariable("OP_SESSION_test");
        string executablePath = Path.Combine(AppContext.BaseDirectory,
            OperatingSystem.IsWindows() ? "WithSecrets.Tests.exe" : "WithSecrets.Tests");
        using var unlockSession = new CancellationTokenSource();
        CancellationToken authorityLockToken = unlockSession.Token;
        IProviderAdapter adapter = new OnePasswordAdapter(executablePath, () => authorityLockToken,
            (reference, _) => ValueTask.FromResult<string?>(reference switch { "encrypted:ZmFrZQ==" => Plaintext(FakeToken), "encrypted:c2xvdw==" => Plaintext(SlowToken), _ => null }));
        try
        {
            Environment.SetEnvironmentVariable("OP_CONNECT_HOST", "unused");
            Environment.SetEnvironmentVariable("OP_SESSION_test", "unused");
            OnePasswordConfiguration config = Configuration("encrypted:ZmFrZQ==");
            var reporter = new Reporter();
            await adapter.InitializeAsync(config, new(Guid.NewGuid(), OnePasswordAdapter.ProviderType, OnePasswordAdapter.AdapterVersion, NullLogger.Instance, reporter), default);
            check(reporter.Events.ToArray() is [LifecycleChangedEvent { State: AdapterLifecycleState.Ready }, HealthChangedEvent { State: AdapterHealthState.Initializing }, ..],
                "1Password initializes and reports readiness separately from connectivity");
            check(await HostServiceTests.WaitFor(() => reporter.Events.Contains(new HealthChangedEvent(AdapterHealthState.Healthy))),
                "1Password reports health after the CLI probe");

            using JsonDocument inline = JsonDocument.Parse("""{"token":"private failure canary"}""");
            await Fails(ProviderErrorKind.InvalidConfiguration, () =>
            {
                new OnePasswordConfiguration().Load(inline);
                return Task.CompletedTask;
            }, check);


            using JsonDocument executableOverride = JsonDocument.Parse("""{"encryptedConfiguration":"fake","executablePath":"untrusted"}""");
            await Fails(ProviderErrorKind.InvalidConfiguration, () =>
            {
                new OnePasswordConfiguration().Load(executableOverride);
                return Task.CompletedTask;
            }, check);


            var issues = await adapter.ValidateConfigurationAsync(Configuration(""), default);
            check(issues.Single().Target == "encryptedConfiguration", "1Password reports a missing encrypted configuration");
            check((await adapter.ValidateMountAsync(config, "vault", default)).Count == 0
                && (await adapter.ValidateMountAsync(config, "vault/item/F_61", default)).Count == 1, "1Password validates vault and field mounts");

            authorityLockToken = new CancellationToken(canceled: true);
            await Fails(ProviderErrorKind.InteractionRequired, () => adapter.ListSecretsAsync(new("vault", null, null), default), check);
            authorityLockToken = unlockSession.Token;

            ListSecretsResult tree = await adapter.ListSecretsAsync(new("vault", null, null), default);
            ListSecretsResult single = await adapter.ListSecretsAsync(new("vault/item", Leaf, null), default);
            check(tree.IsComplete && tree.NextContinuationToken is null && tree.Secrets.Count == 2
                && single.Secrets.Single() is { } field && field.Path == Leaf
                && tree.Secrets.Single(secret => secret.Path == "item/" + Leaf).ExternalSecretId == field.ExternalSecretId
                && tree.Secrets.All(secret => secret.Description is null)
                && !JsonSerializer.Serialize(tree).Contains("test line one", StringComparison.Ordinal), "1Password lists nested field paths with stable IDs and no values");
            await Fails(ProviderErrorKind.InvalidResponse, () => adapter.ListSecretsAsync(new("vault/invalid", null, null), default), check);
            await Fails(ProviderErrorKind.Unknown, () => adapter.ListSecretsAsync(new("vault/failure", null, null), default), check);
            await Fails(ProviderErrorKind.InvalidConfiguration, () => adapter.ListSecretsAsync(new("vault", null, "unexpected"), default), check);

            ProviderSecretRequest[] requests = [new(Guid.NewGuid(), "vault/item/" + Leaf),
                new(Guid.NewGuid(), "vault/item/F_61"), new(Guid.NewGuid(), "vault/item/F_656D707479"),
                new(Guid.NewGuid(), "vault/invalid/" + Leaf), new(Guid.NewGuid(), "../bad")];
            var results = (await adapter.RetrieveSecretsAsync(requests, default)).ToDictionary(result => result.RequestId);
            check(results.Count == requests.Length && results[requests[0].RequestId].Secret?.Value.SequenceEqual(Encoding.UTF8.GetBytes(Value)) == true
                && results[requests[1].RequestId].ErrorKind == ProviderErrorKind.SecretNotFound
                && results[requests[2].RequestId].Secret?.Value.Length == 0
                && results[requests[3].RequestId].ErrorKind == ProviderErrorKind.InvalidResponse
                && results[requests[4].RequestId].ErrorKind == ProviderErrorKind.InvalidConfiguration, "1Password returns the exact UTF-8 value and individual failures");

            // CLI diagnostics become common kinds (the text itself is never returned); an unlisted item stays Unknown.
            ProviderSecretRequest[] classified = [new(Guid.NewGuid(), "vault/gone/" + Leaf), new(Guid.NewGuid(), "vault/limited/" + Leaf),
                new(Guid.NewGuid(), "vault/failure/" + Leaf)];
            var classifiedResults = (await adapter.RetrieveSecretsAsync(classified, default)).ToDictionary(result => result.RequestId);
            check(classifiedResults[classified[0].RequestId].ErrorKind == ProviderErrorKind.SecretNotFound
                && classifiedResults[classified[1].RequestId].ErrorKind == ProviderErrorKind.RateLimited
                && classifiedResults[classified[2].RequestId].ErrorKind == ProviderErrorKind.Unknown, "1Password classifies CLI failures by fixed diagnostics");
            await Fails(ProviderErrorKind.AuthenticationFailed, () => adapter.RetrieveSecretsAsync([new(Guid.NewGuid(), "vault/badauth/" + Leaf)], default), check);
            check(reporter.Events.OfType<HealthChangedEvent>().Last() is { State: AdapterHealthState.Misconfigured }, "1Password reports a refused credential as misconfigured");
            check(reporter.Events.OfType<InvalidateProviderDataEvent>().Any(evt => evt.ExternalSecretIds?.SequenceEqual(["vault/gone/" + Leaf]) == true),
                "1Password invalidates an item the CLI reports as removed");

            // An id that occurs twice in an item names no single field: it is neither retrievable nor listed, the item's other fields still work.
            ProviderSecretRequest[] ambiguous = [new(Guid.NewGuid(), "vault/dupes/F_64757065"), new(Guid.NewGuid(), "vault/dupes/F_756E6971")];
            var ambiguousResults = (await adapter.RetrieveSecretsAsync(ambiguous, default)).ToDictionary(result => result.RequestId);
            AdapterHealthState afterAmbiguous = reporter.Events.OfType<HealthChangedEvent>().Last().State;
            ListSecretsResult dupes = await adapter.ListSecretsAsync(new("vault/dupes", null, null), default);
            check(ambiguousResults[ambiguous[0].RequestId].ErrorKind == ProviderErrorKind.InvalidResponse
                && ambiguousResults[ambiguous[1].RequestId].Secret?.Value.SequenceEqual("two"u8.ToArray()) == true
                && dupes.Secrets.Select(secret => secret.Path).SequenceEqual(["F_756E6971"]), "1Password leaves an ambiguous field id out instead of failing the item");
            check(!reporter.Events.OfType<InvalidateProviderDataEvent>().Any(evt => evt.ExternalSecretIds?.Any(id => id.Contains("dupes", StringComparison.Ordinal)) == true),
                "1Password never treats an ambiguous field id as a removed secret");
            check(afterAmbiguous == AdapterHealthState.Degraded
                && (await adapter.ValidateMountAsync(config, "vault/dupes/F_64757065", default)).Single().Message.Contains("more than one", StringComparison.Ordinal),
                "1Password degrades health on an ambiguous field id and says so when validating the mount");
            check((await adapter.ValidateMountAsync(config, "gone", default)).Single().Target == "basePath"
                && (await adapter.ListSecretsAsync(new("gone", null, null), default)).Secrets.Count == 0
                && reporter.Events.OfType<HealthChangedEvent>().Last() is { State: AdapterHealthState.Healthy },
                "1Password validates and lists an unknown vault as nothing found, not as a failure");

            check(reporter.Events.OfType<InvalidateProviderDataEvent>().Any(evt =>
                evt.ExternalSecretIds?.SequenceEqual(["vault/item/F_61"]) == true),
                "1Password invalidates only the field confirmed missing from a successful item read");

            using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));
            try
            {
                await adapter.ListSecretsAsync(new("vault/slow", null, null), cancel.Token);
                check(false, "1Password cancels a running CLI");
            }
            catch (OperationCanceledException) when (cancel.IsCancellationRequested)
            {
                check(true, "1Password cancels a running CLI");
            }

            var timedOut = (await adapter.RetrieveSecretsAsync([new(Guid.NewGuid(), "vault/slow/" + Leaf)], default)).Single();
            check(timedOut.ErrorKind == ProviderErrorKind.Unavailable, "1Password classifies its command deadline as unavailable");

            Task<ListSecretsResult> listing = adapter.ListSecretsAsync(new("vault/slow", null, null), default);
            Task<IReadOnlyList<ProviderSecretResult>> retrieval = adapter.RetrieveSecretsAsync(
                [new(Guid.NewGuid(), "vault/slow/" + Leaf)], default);
            unlockSession.Cancel();
            await CheckCancellation(listing, "1Password cancels an active listing when the authority locks", check);
            await CheckCancellation(retrieval, "1Password cancels an active retrieval when the authority locks", check);
            using var nextUnlockSession = new CancellationTokenSource();
            authorityLockToken = nextUnlockSession.Token;
            check((await adapter.ListSecretsAsync(new("vault/item", Leaf, null), default)).Secrets.Count == 1,
                "1Password accepts calls in a new unlock session");


            Task slowUpdate = adapter.UpdateConfigurationAsync(Configuration("encrypted:c2xvdw=="), default);
            check(slowUpdate.IsCompletedSuccessfully && reporter.Events.OfType<HealthChangedEvent>().LastOrDefault() is HealthChangedEvent { State: AdapterHealthState.Initializing },
                "1Password starts a replacement probe without waiting for connectivity");
            await slowUpdate;
            await adapter.UpdateConfigurationAsync(Configuration(""), default);
            check(await HostServiceTests.WaitFor(() => reporter.Events.LastOrDefault() is HealthChangedEvent { State: AdapterHealthState.Misconfigured })
                && reporter.Events.OfType<InvalidateProviderDataEvent>().Any(evt => evt.InvalidateEntireProviderInstance),
                "1Password reconverges and invalidates data when configuration is replaced");
            await adapter.UpdateConfigurationAsync(config, default);
            Task<ListSecretsResult> shutdownListing = adapter.ListSecretsAsync(new("vault/slow", null, null), default);
            await adapter.ShutdownAsync(default);
            await CheckCancellation(shutdownListing, "1Password cancels active calls when the adapter shuts down", check);
            await Fails(ProviderErrorKind.InvalidConfiguration, () => adapter.ListSecretsAsync(new("vault", null, null), default), check);
            await RegisteredProvider(executablePath, check);
        }
        finally
        {
            await adapter.ShutdownAsync(default);
            Environment.SetEnvironmentVariable("OP_CONNECT_HOST", previousHost);
            Environment.SetEnvironmentVariable("OP_SESSION_test", previousSession);
        }
    }

    private static async Task RegisteredProvider(string executablePath, Action<bool, string> check)
    {
        string databasePath = Path.Combine(Path.GetTempPath(), "with-secrets-1password-" + Guid.NewGuid().ToString("N"), WithSecretsDatabase.FileName);
        StateDatabase state = new(databasePath);
        if (!TestState.Add(state, TestAuthenticator.ES256().Record("localhost", "onepassword-admin"), withStore: true))
        {
            throw new InvalidOperationException("Could not create the 1Password integration test store.");
        }
        Manifest manifest = TestState.Current(state)!;
        using Unlock unlock = SecretStoreTests.AdminUnlock(state)!;
        using var review = new ReviewKeys();
        var authorityLock = new AuthorityLock();
        CancellationToken lockedToken = authorityLock.UnlockSessionToken;
        var registry = new ProviderRegistry();
        OnePasswordProvider.Register(registry, authorityLock, review, executablePath);

        string configuration = OnePasswordProvider.SealConfiguration(FakeToken, manifest.Review!.PublicKey);
        check(lockedToken.IsCancellationRequested && registry.Types().Single().Type == "onepassword"
            && ProviderAdmin.ConfigurationScreen(configuration) is null && !configuration.Contains(FakeToken, StringComparison.Ordinal),
            "1Password registers with an admin-accepted configuration containing ciphertext only");

        Guid instanceId = Guid.NewGuid();
        await registry.AddInstanceAsync(instanceId, OnePasswordAdapter.ProviderType, configuration, NullLogger.Instance, default);
        try
        {
            IProviderAdapter mounted = registry.Adapter(instanceId);
            await Fails(ProviderErrorKind.InteractionRequired, () => mounted.ListSecretsAsync(new("vault", null, null), default), check);
            authorityLock.Unlock(UnlockMethod.Manual);
            check(review.TryOpen(manifest, unlock), "1Password integration opens the actual passkey-protected review key");
            CancellationToken session = authorityLock.UnlockSessionToken;
            var entries = await mounted.ListSecretsAsync(new("vault", null, null), default);
            var results = await mounted.RetrieveSecretsAsync([new(Guid.NewGuid(), "vault/item/" + Leaf)], default);
            check(entries is { IsComplete: true, Secrets.Count: 2 }
                && results.Single().Secret?.Value.SequenceEqual(Encoding.UTF8.GetBytes(Value)) == true,
                "Registered 1Password decrypts its sealed configuration and reads mounted values after unlock");

            Task<ListSecretsResult> slow = mounted.ListSecretsAsync(new("vault/slow", null, null), default);
            authorityLock.Lock("test");
            review.Close();
            await CheckCancellation(slow, "Registered 1Password uses the authority's real lock signal", check);
            authorityLock.Unlock(UnlockMethod.Manual);
            check(session.IsCancellationRequested && !authorityLock.UnlockSessionToken.IsCancellationRequested,
                "Authority unlock sessions issue independent cancellation tokens");
            await Fails(ProviderErrorKind.InteractionRequired, () => mounted.ListSecretsAsync(new("vault", null, null), default), check);
        }
        finally
        {
            await registry.RemoveInstanceAsync(instanceId, TimeSpan.FromSeconds(5), default);
        }
    }


    private static string Plaintext(string token) => JsonSerializer.Serialize(new { serviceAccountToken = token });


    private static OnePasswordConfiguration Configuration(string encryptedConfiguration)
    {
        using JsonDocument document = JsonDocument.Parse(JsonSerializer.Serialize(new { encryptedConfiguration }));
        var configuration = new OnePasswordConfiguration();
        configuration.Load(document);
        return configuration;
    }

    private static async Task CheckCancellation(Task operation, string message, Action<bool, string> check)
    {
        try
        {
            await operation.WaitAsync(TimeSpan.FromSeconds(3));
            check(false, message);
        }
        catch (OperationCanceledException)
        {
            check(true, message);
        }
        catch (TimeoutException)
        {
            check(false, message);
        }
    }


    private static async Task Fails(ProviderErrorKind expected, Func<Task> operation, Action<bool, string> check)
    {
        try
        {
            await operation();
            check(false, "1Password expected failure " + expected);
        }
        catch (ProviderAdapterException error)
        {
            check(error.Kind == expected && !error.ToString().Contains("canary", StringComparison.Ordinal), "1Password returns a safe " + expected + " failure");
        }
    }

    private sealed class Reporter : IAdapterStatusReporter
    {
        public ConcurrentQueue<AdapterStatusEvent> Events { get; } = new();
        public void Report(AdapterStatusEvent statusEvent) => Events.Enqueue(statusEvent);
    }
}

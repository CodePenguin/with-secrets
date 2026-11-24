using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using WithSecrets.LastPass;

namespace WithSecrets.Tests;

internal static class LastPassTests
{
    internal const string FakePassword = "fake-lpass-password";
    internal const string SlowPassword = "fake-lpass-slow-password";
    private const string EncryptedFake = "encrypted:ZmFrZQ==";
    private const string EncryptedSlow = "encrypted:c2xvdw==";
    private const string EncryptedWrong = "encrypted:d3Jvbmc=";
    private const string FakeUsername = "user@example.test";
    private const string Leaf = "F_70617373776F7264";
    private const string NoteLeaf = "F_6E6F7465";
    private const string Value = "test line one\r\ntest line two\n";

    /// <summary>The test runner doubles as lpass: the adapter starts it with a private LPASS_HOME and the password on stdin.</summary>
    internal static int FakeLpass(string[] args)
    {
        string? home = Environment.GetEnvironmentVariable("LPASS_HOME");
        if (Environment.GetEnvironmentVariable("WS_LPASS_FAKE") != "1"
            || Environment.GetEnvironmentVariable("LPASS_AGENT_DISABLE") != "1"
            || Environment.GetEnvironmentVariable("LPASS_DISABLE_PINENTRY") != "1"
            || string.IsNullOrEmpty(home)
            || Environment.GetEnvironmentVariable("LPASS_ASKPASS") is not null
            || Environment.GetEnvironmentVariable("LPASS_PINENTRY") is not null)
        {
            return 3;
        }

        string? password = Console.In.ReadLine();
        if (password is not (FakePassword or SlowPassword))
        {
            Console.Error.Write("incorrect master password");
            return 1;
        }

        if (password == SlowPassword || args.Contains("999", StringComparer.Ordinal))
        {
            Thread.Sleep(TimeSpan.FromSeconds(20));
        }

        switch (args)
        {
            case ["login", "--force", "--color=never", "--", FakeUsername]:
                File.WriteAllText(Path.Combine(home, "session"), FakeUsername);
                Console.Write("Success: Logged in as " + FakeUsername + "\n");
                break;
            case ["ls", "--format=%ai", "--color=never", "--sync=now"]:
                Console.Write("100\n101\n");
                break;
            case ["show", "--json", "--color=never", "--sync=now", "100"]:
                Console.Write("[" + JsonSerializer.Serialize(new
                {
                    id = "100",
                    name = "item",
                    fullname = "group/item",
                    username = "user",
                    password = Value,
                    url = "https://example.test",
                    note = ""
                }) + "]");
                break;
            case ["show", "--json", "--color=never", "--sync=now", "101"]:
                Console.Write("""
                    [{"id":"101","name":"empty","fullname":"group/empty","username":"other","password":"","url":"https://empty.test"}]
                    """);
                break;
            case ["show", "--json", "--color=never", "--sync=now", "999"]:
                Console.Write("[]");
                break;
            case ["show", "--json", "--color=never", "--sync=now", "103"]:
                Console.Write("malformed canary");
                break;
            case ["show", "--json", "--color=never", "--sync=now", "102"]:
                Console.Error.Write("private failure canary");
                return 1;
            case ["show", "--json", "--color=never", "--sync=now", "104"]:
                Console.Error.WriteLine("Error: Could not find specified account(s).");
                return 1;
            case ["show", "--json", "--color=never", "--sync=now", "105"]:
                Console.Write("""[{"id":"105","password":""}]""");
                Console.Error.WriteLine("Error: Account 105: field password could not be decrypted.");
                return 1;
            case ["show", "--json", "--color=never", "--sync=now", "106"]:
                string expired = Path.Combine(home, "expired");
                string session = Path.Combine(home, "session");
                if (!File.Exists(expired))
                {
                    File.WriteAllText(expired, "");
                    File.Delete(session);
                }
                if (!File.Exists(session))
                {
                    Console.Error.WriteLine("Error: Could not find session. Perhaps you need to login with `lpass login`.");
                    return 1;
                }
                Console.Write("""[{"id":"106","password":"renewed"}]""");
                break;
            default:
                Console.Error.Write("private failure canary");
                return 1;
        }

        return 0;
    }

    public static async Task Run(Action<bool, string> check)
    {
        string? previousFake = Environment.GetEnvironmentVariable("WS_LPASS_FAKE");
        string? previousAskpass = Environment.GetEnvironmentVariable("LPASS_ASKPASS");
        string? previousHome = Environment.GetEnvironmentVariable("LPASS_HOME");
        string executablePath = Path.Combine(AppContext.BaseDirectory,
            OperatingSystem.IsWindows() ? "WithSecrets.Tests.exe" : "WithSecrets.Tests");
        using var unlockSession = new CancellationTokenSource();
        CancellationToken authorityLockToken = unlockSession.Token;
        IProviderAdapter adapter = new LastPassAdapter(executablePath, () => authorityLockToken,
            (ciphertext, _) => ValueTask.FromResult<string?>(ciphertext switch
            {
                EncryptedFake => Plaintext(FakePassword),
                EncryptedSlow => Plaintext(SlowPassword),
                EncryptedWrong => Plaintext("wrong-lpass-password"),
                _ => null
            }), () => true);
        try
        {
            // An inherited pinentry or home must not survive into the child, even when the parent is hostile.
            Environment.SetEnvironmentVariable("LPASS_ASKPASS", "canary");
            Environment.SetEnvironmentVariable("LPASS_HOME", "canary");
            Environment.SetEnvironmentVariable("WS_LPASS_FAKE", "1");
            LastPassConfiguration config = Configuration(EncryptedFake);
            var reporter = new Reporter();
            await adapter.InitializeAsync(config, new(Guid.NewGuid(), LastPassAdapter.ProviderType, LastPassAdapter.AdapterVersion, NullLogger.Instance, reporter), default);
            check(reporter.Events.ToArray() is [LifecycleChangedEvent { State: AdapterLifecycleState.Ready }, HealthChangedEvent { State: AdapterHealthState.Initializing }, ..],
                "LastPass initializes and reports readiness separately from connectivity");
            check(await HostServiceTests.WaitFor(() => reporter.Events.Contains(new HealthChangedEvent(AdapterHealthState.Healthy))),
                "LastPass reports health after the lpass probe");

            using JsonDocument inline = JsonDocument.Parse("""{"token":"private failure canary"}""");
            await Fails(ProviderErrorKind.InvalidConfiguration, () =>
            {
                new LastPassConfiguration().Load(inline);
                return Task.CompletedTask;
            }, check);

            using JsonDocument plaintextCredential = JsonDocument.Parse("""{"username":"user@example.test","credentialReference":"fake"}""");
            await Fails(ProviderErrorKind.InvalidConfiguration, () =>
            {
                new LastPassConfiguration().Load(plaintextCredential);
                return Task.CompletedTask;
            }, check);

            using JsonDocument executableOverride = JsonDocument.Parse("""{"username":"user@example.test","encryptedConfiguration":"encrypted:ZmFrZQ==","executablePath":"untrusted"}""");
            await Fails(ProviderErrorKind.InvalidConfiguration, () =>
            {
                new LastPassConfiguration().Load(executableOverride);
                return Task.CompletedTask;
            }, check);

            using JsonDocument emptyValues = JsonDocument.Parse("""{"username":"","encryptedConfiguration":""}""");
            var missingConfiguration = new LastPassConfiguration();
            missingConfiguration.Load(emptyValues);
            var issues = await adapter.ValidateConfigurationAsync(missingConfiguration, default);
            check(issues.Any(issue => issue.Target == "encryptedConfiguration"), "LastPass reports a missing encrypted configuration");
            check(issues.Any(issue => issue.Target == "username"), "LastPass reports a missing username");
            check((await adapter.ValidateMountAsync(config, "100", default)).Count == 0
                && (await adapter.ValidateMountAsync(config, "100/F_61", default)).Count == 1, "LastPass validates account and field mounts");
            check((await adapter.ValidateMountAsync(config, "104", default)).Single().Target == "basePath",
                "LastPass reports a missing account as a mount validation issue");
            await Fails(ProviderErrorKind.AuthenticationFailed, () =>
                adapter.ValidateMountAsync(Configuration(EncryptedWrong), "100", default), check);

            authorityLockToken = new CancellationToken(canceled: true);
            await Fails(ProviderErrorKind.InteractionRequired, () => adapter.ListSecretsAsync(new("100", null, null), default), check);
            authorityLockToken = unlockSession.Token;

            ListSecretsResult tree = await adapter.ListSecretsAsync(new("100", null, null), default);
            ListSecretsResult single = await adapter.ListSecretsAsync(new("100", Leaf, null), default);
            check(tree.IsComplete && tree.NextContinuationToken is null && tree.Secrets.Count == 4
                && single.Secrets.Single() is { } field && field.Path == Leaf
                && tree.Secrets.Single(secret => secret.Path == Leaf).ExternalSecretId == field.ExternalSecretId
                && tree.Secrets.All(secret => secret.Description is null)
                && !JsonSerializer.Serialize(tree).Contains("test line one", StringComparison.Ordinal), "LastPass lists field paths with stable IDs and no values");
            await Fails(ProviderErrorKind.InvalidResponse, () => adapter.ListSecretsAsync(new("103", null, null), default), check);
            await Fails(ProviderErrorKind.Unknown, () => adapter.ListSecretsAsync(new("102", null, null), default), check);
            await Fails(ProviderErrorKind.Unknown, () => adapter.ListSecretsAsync(new("105", null, null), default), check);
            await Fails(ProviderErrorKind.InvalidConfiguration, () => adapter.ListSecretsAsync(new("100", null, "unexpected"), default), check);
            check(await adapter.ListSecretsAsync(new("104", null, null), default) is { IsComplete: true, Secrets.Count: 0 },
                "LastPass reconciles a confirmed deleted account as an empty listing");
            check((await adapter.ListSecretsAsync(new("106", Leaf, null), default)).Secrets.Count == 1,
                "LastPass renews an expired CLI session and retries the command");

            ProviderSecretRequest[] requests = [new(Guid.NewGuid(), "100/" + Leaf),
                new(Guid.NewGuid(), "101/" + Leaf), new(Guid.NewGuid(), "101/" + NoteLeaf),
                new(Guid.NewGuid(), "103/" + Leaf), new(Guid.NewGuid(), "../bad"),
                new(Guid.NewGuid(), "104/" + Leaf), new(Guid.NewGuid(), "105/" + Leaf)];
            var results = (await adapter.RetrieveSecretsAsync(requests, default)).ToDictionary(result => result.RequestId);
            check(results.Count == requests.Length && results[requests[0].RequestId].Secret?.Value.SequenceEqual(Encoding.UTF8.GetBytes(Value)) == true
                && results[requests[1].RequestId].Secret?.Value.Length == 0
                && results[requests[2].RequestId].ErrorKind == ProviderErrorKind.SecretNotFound
                && results[requests[3].RequestId].ErrorKind == ProviderErrorKind.InvalidResponse
                && results[requests[4].RequestId].ErrorKind == ProviderErrorKind.InvalidConfiguration
                && results[requests[5].RequestId].ErrorKind == ProviderErrorKind.SecretNotFound
                && results[requests[6].RequestId].ErrorKind == ProviderErrorKind.Unknown,
                "LastPass distinguishes empty values from missing accounts and undecryptable fields");

            check(reporter.Events.OfType<InvalidateProviderDataEvent>().Any(evt =>
                evt.ExternalSecretIds?.SequenceEqual(["101/" + NoteLeaf, "104/" + Leaf]) == true),
                "LastPass invalidates only confirmed missing fields and accounts");

            using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));
            try
            {
                await adapter.ListSecretsAsync(new("999", null, null), cancel.Token);
                check(false, "LastPass cancels a running CLI");
            }
            catch (OperationCanceledException) when (cancel.IsCancellationRequested)
            {
                check(true, "LastPass cancels a running CLI");
            }

            var timedOut = (await adapter.RetrieveSecretsAsync([new(Guid.NewGuid(), "999/" + Leaf)], default)).Single();
            check(timedOut.ErrorKind == ProviderErrorKind.Unavailable, "LastPass classifies its command deadline as unavailable");

            Task<ListSecretsResult> listing = adapter.ListSecretsAsync(new("999", null, null), default);
            Task<IReadOnlyList<ProviderSecretResult>> retrieval = adapter.RetrieveSecretsAsync(
                [new(Guid.NewGuid(), "999/" + Leaf)], default);
            unlockSession.Cancel();
            await CheckCancellation(listing, "LastPass cancels an active listing when the authority locks", check);
            await CheckCancellation(retrieval, "LastPass cancels an active retrieval when the authority locks", check);
            using var nextUnlockSession = new CancellationTokenSource();
            authorityLockToken = nextUnlockSession.Token;
            check((await adapter.ListSecretsAsync(new("100", Leaf, null), default)).Secrets.Count == 1,
                "LastPass accepts calls in a new unlock session");

            await Fails(ProviderErrorKind.AuthenticationFailed, () => adapter.ValidateConfigurationAsync(Configuration(EncryptedWrong), default), check);

            Task slowUpdate = adapter.UpdateConfigurationAsync(Configuration(EncryptedSlow), default);
            check(slowUpdate.IsCompletedSuccessfully && reporter.Events.OfType<HealthChangedEvent>().LastOrDefault() is HealthChangedEvent { State: AdapterHealthState.Initializing },
                "LastPass starts a replacement probe without waiting for connectivity");
            await slowUpdate;
            await adapter.UpdateConfigurationAsync(Configuration(""), default);
            check(await HostServiceTests.WaitFor(() => reporter.Events.LastOrDefault() is HealthChangedEvent { State: AdapterHealthState.Misconfigured })
                && reporter.Events.OfType<InvalidateProviderDataEvent>().Any(evt => evt.InvalidateEntireProviderInstance),
                "LastPass reconverges and invalidates data when configuration is replaced");
            await adapter.UpdateConfigurationAsync(config, default);
            Task<ListSecretsResult> shutdownListing = adapter.ListSecretsAsync(new("999", null, null), default);
            await adapter.ShutdownAsync(default);
            await CheckCancellation(shutdownListing, "LastPass cancels active calls when the adapter shuts down", check);
            await Fails(ProviderErrorKind.InvalidConfiguration, () => adapter.ListSecretsAsync(new("100", null, null), default), check);

            if (OperatingSystem.IsWindows())
            {
                await WindowsFailsClosed(executablePath, check);
            }
        }
        finally
        {
            await adapter.ShutdownAsync(default);
            Environment.SetEnvironmentVariable("WS_LPASS_FAKE", previousFake);
            Environment.SetEnvironmentVariable("LPASS_ASKPASS", previousAskpass);
            Environment.SetEnvironmentVariable("LPASS_HOME", previousHome);
        }
    }

    private static async Task WindowsFailsClosed(string executablePath, Action<bool, string> check)
    {
        var reporter = new Reporter();
        IProviderAdapter windows = new LastPassAdapter(executablePath, () => default,
            (reference, _) => ValueTask.FromResult<string?>(FakePassword));
        await windows.InitializeAsync(Configuration(EncryptedFake),
            new(Guid.NewGuid(), LastPassAdapter.ProviderType, LastPassAdapter.AdapterVersion, NullLogger.Instance, reporter), default);
        IReadOnlyList<ProviderValidationIssue> issues = await windows.ValidateConfigurationAsync(Configuration(EncryptedFake), default);
        check(issues.Any(issue => issue.Message.Contains("Linux", StringComparison.Ordinal)), "LastPass reports that Windows is unsupported without starting a CLI");
        await Fails(ProviderErrorKind.Unavailable, () => windows.ListSecretsAsync(new("100", null, null), default), check);
        await windows.ShutdownAsync(default);
    }

    private static LastPassConfiguration Configuration(string encryptedConfiguration)
    {
        using JsonDocument document = JsonDocument.Parse(JsonSerializer.Serialize(new { username = FakeUsername, encryptedConfiguration }));
        var configuration = new LastPassConfiguration();
        configuration.Load(document);
        return configuration;
    }

    private static string Plaintext(string masterPassword) => JsonSerializer.Serialize(new { masterPassword });

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
            check(false, "LastPass expected failure " + expected);
        }
        catch (ProviderAdapterException error)
        {
            check(error.Kind == expected && !error.ToString().Contains("canary", StringComparison.Ordinal), "LastPass returns a safe " + expected + " failure");
        }
    }

    private sealed class Reporter : IAdapterStatusReporter
    {
        public ConcurrentQueue<AdapterStatusEvent> Events { get; } = new();
        public void Report(AdapterStatusEvent statusEvent) => Events.Enqueue(statusEvent);
    }
}

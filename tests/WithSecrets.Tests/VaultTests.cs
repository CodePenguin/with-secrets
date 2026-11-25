using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;

using Microsoft.Extensions.Logging.Abstractions;
using WithSecrets.Vault;

namespace WithSecrets.Tests;

internal static class VaultTests
{
    public static async Task Run(Action<bool, string> check)
    {
        const string token = "hvs.vault-token-canary";
        var (publicKey, privateKey) = JweCipher.Instance.NewKeyPair();
        string sealedConfiguration = VaultProvider.SealConfiguration(token, publicKey);
        using JsonDocument document = JsonDocument.Parse(sealedConfiguration);
        VaultConfiguration configuration = new();
        configuration.Load(document);
        check(!sealedConfiguration.Contains(token, StringComparison.Ordinal), "Vault configuration stores the token sealed");

        using var authority = new CancellationTokenSource();
        using var slowReadStarted = new SemaphoreSlim(0);
        ConcurrentQueue<string> paths = new();
        ConcurrentQueue<bool> headers = new();
        using HttpClient http = new(new FakeVault(async (request, cancellationToken) =>
        {
            string path = request.RequestUri!.PathAndQuery;
            paths.Enqueue(path);
            headers.Enqueue(request.Method == HttpMethod.Get && request.RequestUri.Scheme == "https"
                && request.RequestUri.Host == "vault.example.test"
                && request.Headers.GetValues("X-Vault-Token").Single() == token
                && request.Headers.GetValues("X-Vault-Namespace").Single() == "teams/demo");
            if (path.StartsWith("/v1/team/kv/data/slow-batch", StringComparison.Ordinal))
            {
                await Task.Delay(Timeout.Infinite, cancellationToken);
            }

            if (path == "/v1/team/kv/data/slow")
            {
                slowReadStarted.Release();
                await Task.Delay(Timeout.Infinite, cancellationToken);
            }

            return path switch
            {
                "/v1/auth/token/lookup-self" => Response("""{"data":{}}"""),
                "/v1/team/kv/metadata/apps/?list=true" => Response("""{"data":{"keys":["db","other/","../"]}}"""),
                "/v1/team/kv/metadata/apps/other/?list=true" => Response("""{"data":{"keys":["worker"]}}"""),
                "/v1/team/kv/subkeys/apps/db?depth=1" => Response("""{"data":{"subkeys":{"PASSWORD":null,"SETTINGS":null}}}"""),
                "/v1/team/kv/subkeys/apps/other/worker?depth=1" => Response("""{"data":{"subkeys":{"TOKEN":null}}}"""),
                "/v1/team/kv/data/apps/db" => Response("""{"data":{"data":{"PASSWORD":"pássword","SETTINGS":{"timeout":30}}}}"""),
                "/v1/team/kv/data/denied" => new(HttpStatusCode.Forbidden),
                "/v1/team/kv/metadata/broken/?list=true" or "/v1/team/kv/data/broken" =>
                    Response("""{"errors":["no handler for route"]}""", HttpStatusCode.NotFound),
                "/v1/team/kv/subkeys/deleted?depth=1" =>
                    Response("""{"data":{"subkeys":null,"metadata":{"destroyed":true}}}""", HttpStatusCode.NotFound),
                "/v1/team/kv/data/deleted" =>
                    Response("""{"data":{"data":null,"metadata":{"deletion_time":"2024-01-01T00:00:00Z"}}}""", HttpStatusCode.NotFound),
                _ => Response("""{"errors":[]}""", HttpStatusCode.NotFound),
            };
        }));
        IProviderAdapter adapter = new VaultAdapter("https://vault.example.test", "team/kv", "teams/demo", () => authority.Token,
            (ciphertext, _) => ValueTask.FromResult<string?>(JweCipher.Instance.Decrypt(privateKey, ciphertext)), http);
        StatusReporter status = new();
        await adapter.InitializeAsync(configuration,
            new(Guid.NewGuid(), VaultAdapter.ProviderType, VaultAdapter.AdapterVersion, NullLogger.Instance, status), default);
        try
        {
            check((await adapter.ValidateConfigurationAsync(configuration, default)).Count == 0, "Vault validates the sealed token");
            check((await adapter.ValidateMountAsync(configuration, "apps/db/PASSWORD", MountKind.Single, default)).Count == 0,
                "Vault validates a single field in its document");
            check((await adapter.ValidateMountAsync(configuration, "apps/db", MountKind.Tree, default)).Count == 0
                && (await adapter.ValidateMountAsync(configuration, "apps/db", MountKind.Single, default)).Count == 1
                && (await adapter.ValidateMountAsync(configuration, "apps/db/PASSWORD", MountKind.Tree, default)).Count == 1,
                "Vault validates a path only against the selected mount kind");
            var tree = await adapter.ListSecretsAsync(new("apps/", null, null), default);
            check(tree.IsComplete && tree.Secrets.Select(secret => secret.Path).ToHashSet(StringComparer.Ordinal)
                    .SetEquals(["db/PASSWORD", "db/SETTINGS", "other/worker/TOKEN"])
                && !paths.Any(path => path.Contains("/data/", StringComparison.Ordinal)),
                "Vault discovers folders and fields without reading their values");
            var single = await adapter.ListSecretsAsync(new("apps/db", "PASSWORD", null), default);
            check(single.Secrets.SequenceEqual([new ProviderSecretInfo("PASSWORD", "apps/db/PASSWORD", null)]),
                "Vault discovery preserves the exact field identity");

            var empty = await adapter.ListSecretsAsync(new("empty/", null, null), default);
            var deleted = await adapter.ListSecretsAsync(new("deleted", null, null), default);
            check(empty.IsComplete && empty.Secrets.Count == 0 && deleted.IsComplete && deleted.Secrets.Count == 0,
                "Vault recognizes empty directories and deleted documents");
            try
            {
                await adapter.ListSecretsAsync(new("broken/", null, null), default);
                check(false, "Vault refuses to publish a complete listing after a routing failure");
            }
            catch (ProviderAdapterException error)
            {
                check(error.Kind == ProviderErrorKind.InvalidResponse, "Vault refuses to publish a complete listing after a routing failure");
            }

            ProviderSecretRequest[] requests = new[] { "apps/db/PASSWORD", "apps/db/SETTINGS", "apps/db/MISSING", "denied/PASSWORD", "../PASSWORD" }
                .Select(path => new ProviderSecretRequest(Guid.NewGuid(), path)).ToArray();
            var results = (await adapter.RetrieveSecretsAsync(requests, default)).ToDictionary(result => result.RequestId);
            check(Encoding.UTF8.GetString(results[requests[0].RequestId].Secret!.Value) == "pássword"
                && Encoding.UTF8.GetString(results[requests[1].RequestId].Secret!.Value) == """{"timeout":30}"""
                && paths.Count(path => path == "/v1/team/kv/data/apps/db") == 1,
                "Vault batches field reads and preserves text and structured values");
            check(results[requests[2].RequestId].ErrorKind == ProviderErrorKind.SecretNotFound
                && results[requests[3].RequestId].ErrorKind == ProviderErrorKind.AccessDenied
                && results[requests[4].RequestId].ErrorKind == ProviderErrorKind.InvalidConfiguration
                && status.Events.OfType<InvalidateProviderDataEvent>().Any(evt => evt.ExternalSecretIds?.SequenceEqual(["apps/db/MISSING"]) == true),
                "Vault distinguishes missing, denied, and invalid paths and invalidates missing fields");

            ProviderSecretResult[] notFound = (await adapter.RetrieveSecretsAsync(
                [new(Guid.NewGuid(), "broken/PASSWORD"), new(Guid.NewGuid(), "deleted/PASSWORD")], default)).ToArray();
            check(notFound[0].ErrorKind == ProviderErrorKind.InvalidResponse && notFound[1].ErrorKind == ProviderErrorKind.SecretNotFound
                && !status.Events.OfType<InvalidateProviderDataEvent>().Any(evt => evt.ExternalSecretIds?.Contains("broken/PASSWORD") == true),
                "Vault distinguishes a routing error from a deleted secret during retrieval");

            ProviderSecretRequest[] batch = [.. Enumerable.Range(0, 5).Select(index =>
                new ProviderSecretRequest(Guid.NewGuid(), $"slow-batch{index}/PASSWORD")), new(Guid.NewGuid(), "apps/db/PASSWORD")];
            ProviderRetriever retriever = new(_ => adapter, TimeProvider.System, Task.Delay);
            IReadOnlyDictionary<Guid, RetrievalOutcome> partial = await retriever.RetrieveAsync(Guid.NewGuid(), batch, default);
            check(partial[batch[^1].RequestId] is RetrievalSuccess
                && batch[..^1].All(request => partial[request.RequestId] is RetrievalFailure { Kind: ProviderErrorKind.Unavailable }),
                "Vault preserves successful document reads when slow documents exhaust the batch deadline");

            Task<IReadOnlyList<ProviderSecretResult>> slowRead = adapter.RetrieveSecretsAsync([new(Guid.NewGuid(), "slow/PASSWORD")], default);
            check(await slowReadStarted.WaitAsync(TimeSpan.FromSeconds(3)), "Vault starts the request before the authority locks");
            authority.Cancel();
            try
            {
                await slowRead;
                check(false, "The authority lock cancels an in-flight Vault read");
            }
            catch (OperationCanceledException)
            {
                check(true, "The authority lock cancels an in-flight Vault read");
            }

            check(headers.Count > 0 && headers.All(valid => valid), "Vault sends the token only as a header to the trusted HTTPS origin");
        }
        finally
        {
            await adapter.ShutdownAsync(default);
        }
    }

    private static HttpResponseMessage Response(string json, HttpStatusCode status = HttpStatusCode.OK)
        => new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private sealed class FakeVault(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => send(request, cancellationToken);
    }

    private sealed class StatusReporter : IAdapterStatusReporter
    {
        public ConcurrentQueue<AdapterStatusEvent> Events { get; } = new();

        public void Report(AdapterStatusEvent statusEvent) => Events.Enqueue(statusEvent);
    }
}

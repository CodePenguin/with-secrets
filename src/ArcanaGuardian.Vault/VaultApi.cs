using System.Buffers;
using System.Security.Cryptography;
using System.Text.Json;

namespace ArcanaGuardian.Vault;

internal sealed class VaultApi(HttpClient http, Uri address, string mount, string? vaultNamespace, string token)
{
    private const int MaxResponseBytes = 4 * 1024 * 1024;

    private enum ResponseType { Token, Secret, Fields, Directory }

    internal static HttpClient SharedClient { get; } = new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
    });

    public async Task CheckTokenAsync(CancellationToken cancellationToken)
    {
        await ReadAsync("auth/token/lookup-self", root =>
        {
            if (root.GetProperty("data").ValueKind != JsonValueKind.Object)
            {
                throw InvalidResponse();
            }

            return true;
        }, ResponseType.Token, cancellationToken).ConfigureAwait(false);
    }

    public Task<T> ReadSecretAsync<T>(string path, Func<JsonElement, T> select, CancellationToken cancellationToken)
        => ReadAsync(mount + "/data/" + path, root =>
        {
            JsonElement fields = root.GetProperty("data").GetProperty("data");
            return fields.ValueKind == JsonValueKind.Object ? select(fields) : throw InvalidResponse();
        }, ResponseType.Secret, cancellationToken);

    public Task<string[]> ReadFieldsAsync(string path, CancellationToken cancellationToken)
        => ReadAsync(mount + "/subkeys/" + path + "?depth=1", root =>
            root.GetProperty("data").GetProperty("subkeys").EnumerateObject().Select(field => field.Name).ToArray(),
            ResponseType.Fields, cancellationToken);

    public async Task<string[]> ReadDirectoryAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            return await ReadAsync(mount + "/metadata/" + path + "?list=true", root =>
                root.GetProperty("data").GetProperty("keys").EnumerateArray()
                    .Select(key => key.GetString() ?? throw InvalidResponse()).ToArray(),
                ResponseType.Directory, cancellationToken).ConfigureAwait(false);
        }
        catch (ProviderAdapterException error) when (error.Kind == ProviderErrorKind.SecretNotFound)
        {
            return [];
        }
    }

    private async Task<T> ReadAsync<T>(string path, Func<JsonElement, T> select, ResponseType responseType, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(address, "v1/" + path));
        request.Headers.Add("X-Vault-Token", token);
        if (vaultNamespace is not null)
        {
            request.Headers.Add("X-Vault-Namespace", vaultNamespace);
        }

        try
        {
            using HttpResponseMessage response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            bool checkNotFound = (int)response.StatusCode == 404 && responseType != ResponseType.Token;
            if (!response.IsSuccessStatusCode && !checkNotFound)
            {
                throw StatusError(response, responseType);
            }

            using Stream input = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
            using var output = new MemoryStream();
            byte[] buffer = ArrayPool<byte>.Shared.Rent(8192);
            try
            {
                int count;
                while ((count = await input.ReadAsync(buffer.AsMemory(0, 8192), deadline.Token).ConfigureAwait(false)) != 0)
                {
                    if (output.Length + count > MaxResponseBytes)
                    {
                        throw InvalidResponse();
                    }

                    output.Write(buffer, 0, count);
                }

                using JsonDocument document = JsonDocument.Parse(output.GetBuffer().AsMemory(0, (int)output.Length));
                cancellationToken.ThrowIfCancellationRequested();
                if (checkNotFound)
                {
                    throw IsMissing(document.RootElement, responseType)
                        ? new ProviderAdapterException(ProviderErrorKind.SecretNotFound, "The Vault path is missing.")
                        : InvalidResponse();
                }

                T result = select(document.RootElement);
                cancellationToken.ThrowIfCancellationRequested();
                return result;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
                CryptographicOperations.ZeroMemory(output.GetBuffer().AsSpan(0, (int)output.Length));
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new ProviderAdapterException(ProviderErrorKind.Unavailable, "The Vault request timed out.");
        }
        catch (Exception error) when (error is HttpRequestException or IOException)
        {
            throw new ProviderAdapterException(ProviderErrorKind.Unavailable, "Could not communicate with Vault.");
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException or ArgumentException)
        {
            throw InvalidResponse();
        }
    }

    private static bool IsMissing(JsonElement root, ResponseType responseType)
    {
        if (root.ValueKind != JsonValueKind.Object
            || root.TryGetProperty("warnings", out JsonElement warnings) && !EmptyMessages(warnings))
        {
            return false;
        }

        bool hasErrors = root.TryGetProperty("errors", out JsonElement errors);
        if (hasErrors && !EmptyMessages(errors))
        {
            return false;
        }

        if (!root.TryGetProperty("data", out JsonElement data) || data.ValueKind == JsonValueKind.Null)
        {
            // Vault uses an empty errors array for an empty LIST or an absent document.
            return hasErrors && errors.ValueKind == JsonValueKind.Array;
        }

        // The KV plugin sends a different 404 envelope for deleted or destroyed versions.
        return responseType is ResponseType.Secret or ResponseType.Fields && data.ValueKind == JsonValueKind.Object
            && data.TryGetProperty(responseType == ResponseType.Secret ? "data" : "subkeys", out JsonElement value)
            && value.ValueKind == JsonValueKind.Null
            && data.TryGetProperty("metadata", out JsonElement metadata) && metadata.ValueKind == JsonValueKind.Object
            && (metadata.TryGetProperty("destroyed", out JsonElement destroyed) && destroyed.ValueKind == JsonValueKind.True
                || metadata.TryGetProperty("deletion_time", out JsonElement deletion) && deletion.ValueKind == JsonValueKind.String
                && deletion.TryGetDateTimeOffset(out _));
    }

    private static bool EmptyMessages(JsonElement value)
        => value.ValueKind == JsonValueKind.Null || value.ValueKind == JsonValueKind.Array && value.GetArrayLength() == 0;

    private static ProviderAdapterException StatusError(HttpResponseMessage response, ResponseType responseType)
    {
        int status = (int)response.StatusCode;
        ProviderErrorKind kind = status switch
        {
            401 => ProviderErrorKind.AuthenticationFailed,
            403 when responseType == ResponseType.Token => ProviderErrorKind.AuthenticationFailed,
            403 => ProviderErrorKind.AccessDenied,
            408 or 412 or >= 500 => ProviderErrorKind.Unavailable,
            429 => ProviderErrorKind.RateLimited,
            400 => ProviderErrorKind.InvalidConfiguration,
            _ => ProviderErrorKind.InvalidResponse,
        };

        var retry = response.Headers.RetryAfter;
        TimeSpan? delay = retry?.Delta ?? (retry?.Date - DateTimeOffset.UtcNow);
        return new ProviderAdapterException(kind, $"Vault returned HTTP {status}.", retryAfter: delay > TimeSpan.Zero ? delay : null);
    }

    private static ProviderAdapterException InvalidResponse()
        => new(ProviderErrorKind.InvalidResponse, "Vault returned an invalid response.");
}

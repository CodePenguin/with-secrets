using System.Text.Unicode;

namespace WithSecrets;

/// <summary>
/// The core's check of a batch retrieval before any result is used (10.3.1): one result for every request id and no others, each with exactly one of a value
/// and an error. A malformed batch fails as <see cref="ProviderErrorKind.InvalidResponse" />; the core never guesses which value belongs to which request.
/// Messages carry counts only, never a value.
/// </summary>
public static class ProviderBatch
{
    /// <summary>Returns the results in the order of <paramref name="requests" />.</summary>
    public static IReadOnlyList<ProviderSecretResult> Validate(IReadOnlyList<ProviderSecretRequest> requests, IReadOnlyList<ProviderSecretResult> results)
    {
        HashSet<Guid> requested = [];
        foreach (ProviderSecretRequest request in requests)
        {
            if (!requested.Add(request.RequestId))
            {
                throw Invalid("A request id was used twice in one batch.");
            }
        }

        Dictionary<Guid, ProviderSecretResult> byId = [];
        foreach (ProviderSecretResult result in results)
        {
            if (!requested.Contains(result.RequestId))
            {
                throw Invalid("The provider answered a request id that was not asked.");
            }

            if (!byId.TryAdd(result.RequestId, result))
            {
                throw Invalid("The provider answered a request id twice.");
            }

            bool hasSecret = result.Secret?.Value is not null;
            if (hasSecret == result.ErrorKind.HasValue)
            {
                throw Invalid("A provider result must carry exactly one of a value and an error.");
            }
        }

        if (byId.Count != requests.Count)
        {
            throw Invalid("The provider did not answer every request.");
        }

        return [.. requests.Select(request => byId[request.RequestId])];
    }

    /// <summary>True when <paramref name="value" /> is well-formed UTF-8 (no lone or truncated sequence, no overlong form, no surrogate).</summary>
    public static bool IsStrictUtf8(byte[] value) => Utf8.IsValid(value);

    private static ProviderAdapterException Invalid(string message) => new(ProviderErrorKind.InvalidResponse, message);
}

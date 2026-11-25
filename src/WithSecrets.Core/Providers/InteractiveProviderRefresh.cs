namespace WithSecrets;

/// <summary>The account designation for a provider whose values can only be updated by a person.</summary>
public interface IInteractiveProviderAdapter
{
    (string Account, bool European) ReadAccount(string configuration);
}

public sealed record InteractiveProviderRefreshRequest(Guid Id, Guid InstanceId, string RequestedBy, string ProviderName,
    string Account, bool European, DateTimeOffset Expires, string StorePublicKey, IReadOnlyList<(string Path, string LocalName)> Mappings);

/// <summary>A live local helper connection. Its result contains ciphertext keyed by provider path.</summary>
public interface IInteractiveProviderRefresh : IDisposable
{
    string MatchingCode { get; }
    Task<IReadOnlyDictionary<string, string>> ReceiveAsync(CancellationToken cancel);
}

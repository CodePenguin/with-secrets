using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace WithSecrets;

public sealed record ReconcileResult(bool Complete, int Added, int Removed, int Changed);

/// <summary>
/// Refreshes one mount's namespace entries from a provider listing (10.3, ruling 3). The mount's entries change only after a complete listing; a failure,
/// cancellation or incomplete listing leaves them untouched.
/// </summary>
public sealed class NamespaceReconciler(ProviderStore store, Func<Guid, IProviderAdapter> adapters, ILogger? logger = null)
{
    private const int MaxPages = 10_000;

    private readonly ILogger _logger = logger ?? NullLogger.Instance;

    internal async Task<ReconcileResult> ReconcileWithinAsync(Mount mount, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using CancellationTokenSource deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        CancellationToken token = deadline.Token;
        // A provider can block before returning its task or disregard cancellation while listing.
        Task<ReconcileResult> listing = Task.Run(() => ReconcileAsync(mount, token), token);
        _ = listing.ContinueWith(done => done.Exception, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default);
        try
        {
            return await listing.WaitAsync(token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("The provider listing timed out.");
        }
    }

    public async Task<ReconcileResult> ReconcileAsync(Mount mount, CancellationToken cancel)
    {
        IProviderAdapter adapter = adapters(mount.InstanceId);
        (string scope, string? leaf) = Scope(mount);

        List<ProviderSecretInfo> listed = [];
        string? token = null;
        HashSet<string> seen = new(StringComparer.Ordinal);
        bool complete = false;
        for (int page = 0; page < MaxPages; page++)
        {
            cancel.ThrowIfCancellationRequested();
            ListSecretsResult result = await adapter.ListSecretsAsync(new ListSecretsRequest(scope, leaf, token), cancel).ConfigureAwait(false);
            listed.AddRange(result.Secrets);
            if (result.NextContinuationToken is null)
            {
                complete = result.IsComplete;
                break;
            }

            if (!seen.Add(result.NextContinuationToken))
            {
                break;
            }

            token = result.NextContinuationToken;
        }

        if (!complete)
        {
            return new ReconcileResult(false, 0, 0, 0);
        }

        cancel.ThrowIfCancellationRequested();

        (int added, int removed, int changed) = store.ApplyReconciliation(mount, old => Merge(mount, leaf, listed, old));

        return new ReconcileResult(true, added, removed, changed);
    }

    private (IReadOnlyList<NamespaceEntry> Next, int Added, int Changed) Merge(Mount mount, string? leaf, List<ProviderSecretInfo> listed, IReadOnlyList<NamespaceEntry> oldEntries)
    {
        Dictionary<string, NamespaceEntry> old = oldEntries.ToDictionary(entry => entry.LogicalPath, StringComparer.Ordinal);
        Dictionary<string, NamespaceEntry> next = new(StringComparer.Ordinal);
        int added = 0, changed = 0;
        foreach (ProviderSecretInfo item in listed)
        {
            if (leaf is not null && !string.Equals(item.Path, leaf, StringComparison.Ordinal))
            {
                continue;
            }

            string logical = mount.Kind == MountKind.Single ? mount.LogicalPath : mount.LogicalPath + "/" + item.Path;
            if (!SecretNames.IsValid(logical))
            {
                _logger.LogWarning("A provider listed a secret whose name '{Name}' is not a valid secret name; it was dropped.", logical);
                continue;
            }

            if (next.ContainsKey(logical))
            {
                continue;
            }

            string providerPath = mount.Kind == MountKind.Single ? mount.BasePath : mount.BasePath.Length == 0 ? item.Path : mount.BasePath.TrimEnd('/') + "/" + item.Path;
            NamespaceEntry entry;
            if (old.TryGetValue(logical, out NamespaceEntry? before))
            {
                entry = before.DescriptionSource == DescriptionSource.Local
                    ? before with { ProviderPath = providerPath, ExternalId = item.ExternalSecretId }
                    : before with { ProviderPath = providerPath, ExternalId = item.ExternalSecretId, Description = item.Description, DescriptionSource = DescriptionSource.Provider };
                if (entry != before)
                {
                    changed++;
                }
            }
            else
            {
                entry = new NamespaceEntry(mount.Id, logical, providerPath, item.ExternalSecretId, item.Description, DescriptionSource.Provider);
                added++;
            }

            next[logical] = entry;
        }

        return ([.. next.Values], added, changed);
    }

    private static (string Scope, string? Leaf) Scope(Mount mount)
    {
        if (mount.Kind == MountKind.Tree)
        {
            return (mount.BasePath, null);
        }

        int slash = mount.BasePath.LastIndexOf('/');

        return slash < 0 ? ("", mount.BasePath) : (mount.BasePath[..slash], mount.BasePath[(slash + 1)..]);
    }
}

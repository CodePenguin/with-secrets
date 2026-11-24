using Microsoft.Extensions.Logging;

namespace WithSecrets;

/// <summary>
/// Proactive refresh (10.3.3): one pass finds every EXISTING cache row whose age is at least 75% of its instance's MaxStaleDuration (above zero), including rows
/// already past the stale window (a recovery attempt), and retrieves them in one batch per instance. A success replaces the row (new lastVerified); a failure
/// changes nothing. A row that is absent is never created. Per (instance, external id), in memory: a failed refresh is not retried before nextAttempt, which
/// doubles from one minute to at most 15 minutes and resets on success; a result that needs a person (AuthenticationFailed, InteractionRequired) or a policy
/// change (AccessDenied) is not retried by ticks until a NEWER lastVerified (an on-demand success) proves the provider works again. A pass first deletes the rows
/// that no namespace entry references (they can never be served or refreshed); a prune that fails is logged by type and the pass goes on. The pass never starts interactive authentication, never creates or extends a grant,
/// never delivers a value, and ends quietly while the authority is locked. Nothing it logs carries a value, ciphertext or credential.
/// </summary>
public sealed class ProviderRefresher(
    ProviderStore store,
    ProviderRetriever retriever,
    ProviderCache cache,
    Func<string?> storePublicKey,
    ProviderInvalidation invalidation,
    TimeProvider clock,
    ILogger logger,
    Func<TimeSpan, CancellationToken, Task>? delay = null)
{
    private static readonly TimeSpan FirstBackoff = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan MaxBackoff = TimeSpan.FromMinutes(15);

    private sealed record Attempt(DateTimeOffset Next, TimeSpan Wait, bool Halted, long VerifiedAtFailure);

    private readonly object _gate = new();
    private readonly Dictionary<(Guid, string), Attempt> _attempts = [];
    private readonly Func<TimeSpan, CancellationToken, Task> _delay = delay ?? ((wait, cancel) => Task.Delay(wait, clock, cancel));

    /// <summary>Ticks every <paramref name="interval" /> (default one minute) until cancelled. A tick that throws is logged by exception type and the loop continues.</summary>
    public async Task RunAsync(TimeSpan? interval, CancellationToken cancel)
    {
        TimeSpan every = interval ?? TimeSpan.FromMinutes(1);
        while (!cancel.IsCancellationRequested)
        {
            try
            {
                await TickAsync(cancel).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancel.IsCancellationRequested)
            {
                return;
            }
            catch (Exception error)
            {
                logger.LogWarning("Provider refresh pass failed ({ExceptionType}).", error.GetType().Name);
            }

            try
            {
                await _delay(every, cancel).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancel.IsCancellationRequested)
            {
                return;
            }
        }
    }

    /// <summary>For tests: runs after the generation baseline, before the cache rows are read.</summary>
    internal Action? AfterBaseline { get; set; }

    /// <summary>For tests: runs just before the unreferenced rows are pruned.</summary>
    internal Action? BeforePrune { get; set; }

    /// <summary>One pass.</summary>
    public async Task TickAsync(CancellationToken cancel)
    {
        // Locked: nothing is read, retrieved or signed.
        if (cache.IsLocked)
        {
            return;
        }

        // Rows no namespace entry references any more are deleted first (moving their instances' generations), before the baseline below. A prune that fails
        // (a busy database, say) is retried next pass; it never stops this pass's refresh.
        try
        {
            BeforePrune?.Invoke();
            store.PruneCache();
        }
        catch (Exception error) when (error is not OperationCanceledException and not OutOfMemoryException)
        {
            logger.LogWarning("Provider cache prune failed ({ExceptionType}).", error.GetType().Name);
        }

        // Baseline BEFORE any read, as delivery does: an invalidation after this point discards that instance's results.
        IReadOnlyList<ProviderInstance> instances = store.Instances();
        Dictionary<Guid, long> generations = instances.ToDictionary(instance => instance.Id, instance => invalidation.Generation(instance.Id));
        DateTimeOffset now = clock.GetUtcNow();
        AfterBaseline?.Invoke();
        IReadOnlyList<(Guid InstanceId, string ExternalId, long LastVerified)> rows = store.CacheIndex();
        Forget(rows);

        // Only with something to refresh is the native manifest opened for the store key (a native-only deployment never reads it here).
        if (rows.Count == 0 || !instances.Any(instance => instance.MaxStale > TimeSpan.Zero) || storePublicKey() is not { Length: > 0 } key)
        {
            return;
        }
        Dictionary<Guid, Guid> mountInstance = store.Mounts().ToDictionary(mount => mount.Id, mount => mount.InstanceId);
        Dictionary<(Guid, string), string> paths = [];
        foreach (NamespaceEntry entry in store.Entries())
        {
            if (mountInstance.TryGetValue(entry.MountId, out Guid owner))
            {
                paths.TryAdd((owner, entry.ExternalId), entry.ProviderPath);
            }
        }

        foreach (ProviderInstance instance in instances.Where(instance => instance.MaxStale > TimeSpan.Zero))
        {
            cancel.ThrowIfCancellationRequested();
            if (cache.IsLocked)
            {
                return;
            }

            List<(string ExternalId, string Path, long Verified)> due = [];
            TimeSpan threshold = ProviderPolicy.RefreshDue(instance.MaxStale);
            foreach ((Guid instanceId, string externalId, long verified) in rows.Where(row => row.InstanceId == instance.Id))
            {
                if (verified < DateTimeOffset.MinValue.UtcTicks || verified > DateTimeOffset.MaxValue.UtcTicks
                    || now - new DateTimeOffset(verified, TimeSpan.Zero) < threshold
                    || !paths.TryGetValue((instanceId, externalId), out string? path)
                    || !Allowed(instanceId, externalId, now))
                {
                    continue;
                }

                due.Add((externalId, path, verified));
            }

            if (due.Count == 0)
            {
                continue;
            }

            // Invalidated since the baseline: its rows or listing may have changed, so this pass leaves it alone.
            long baseline = generations.GetValueOrDefault(instance.Id);
            if (invalidation.Generation(instance.Id) != baseline)
            {
                continue;
            }

            try
            {
                if (!await RefreshInstanceAsync(instance, due, key, baseline, cancel).ConfigureAwait(false))
                {
                    return;
                }
            }
            catch (Exception error) when (error is not OperationCanceledException and not AuthorityLockedException)
            {
                // One instance's failure never starves the others.
                logger.LogWarning("Provider refresh of an instance failed ({ExceptionType}).", error.GetType().Name);
            }
            catch (AuthorityLockedException)
            {
                return;
            }
        }
    }

    // Drops state for rows that no longer exist, and lifts a halt or backoff when a NEWER write (an on-demand success) proves the provider works again.
    private void Forget(IReadOnlyList<(Guid InstanceId, string ExternalId, long LastVerified)> rows)
    {
        Dictionary<(Guid, string), long> current = [];
        foreach ((Guid instanceId, string externalId, long verified) in rows)
        {
            current[(instanceId, externalId)] = verified;
        }

        lock (_gate)
        {
            foreach (((Guid, string) key, Attempt attempt) in _attempts.ToList())
            {
                if (!current.TryGetValue(key, out long verified) || verified > attempt.VerifiedAtFailure)
                {
                    _attempts.Remove(key);
                }
            }
        }
    }

    private bool Allowed(Guid instanceId, string externalId, DateTimeOffset now)
    {
        lock (_gate)
        {
            return !_attempts.TryGetValue((instanceId, externalId), out Attempt? attempt) || (!attempt.Halted && now >= attempt.Next);
        }
    }

    // False when the authority is locked (the pass ends).
    private async Task<bool> RefreshInstanceAsync(ProviderInstance instance, List<(string ExternalId, string Path, long Verified)> due, string key, long generation, CancellationToken cancel)
    {
        DateTimeOffset started = clock.GetUtcNow();
        List<ProviderSecretRequest> requests = [.. due.Select(item => new ProviderSecretRequest(Guid.NewGuid(), item.Path))];
        IReadOnlyDictionary<Guid, RetrievalOutcome> outcomes = await retriever.RetrieveAsync(instance.Id, requests, cancel).ConfigureAwait(false);

        List<(string ExternalId, byte[] Value)> fresh = [];
        try
        {
            for (int index = 0; index < due.Count; index++)
            {
                string externalId = due[index].ExternalId;
                if (outcomes.TryGetValue(requests[index].RequestId, out RetrievalOutcome? outcome) && outcome is RetrievalSuccess success)
                {
                    fresh.Add((externalId, success.Value));
                }
                else
                {
                    Failed(instance.Id, externalId, (outcome as RetrievalFailure)?.Kind, started, due[index].Verified);
                }
            }

            if (fresh.Count > 0)
            {
                CacheWrite written;
                try
                {
                    written = cache.PutAll(instance.Id, fresh, started, key, generation);
                }
                catch (AuthorityLockedException)
                {
                    return false;
                }

                if (written != CacheWrite.Invalidated)
                {
                    lock (_gate)
                    {
                        foreach ((string externalId, _) in fresh)
                        {
                            _attempts.Remove((instance.Id, externalId));
                        }
                    }
                }
            }
        }
        finally
        {
            foreach ((_, byte[] value) in fresh)
            {
                SecretValues.Clear(value);
            }
        }

        return true;
    }

    private void Failed(Guid instanceId, string externalId, ProviderErrorKind? kind, DateTimeOffset now, long verified)
    {
        bool halted = kind is ProviderErrorKind.AuthenticationFailed or ProviderErrorKind.InteractionRequired or ProviderErrorKind.AccessDenied;
        lock (_gate)
        {
            TimeSpan wait = _attempts.TryGetValue((instanceId, externalId), out Attempt? previous) ? TimeSpan.FromTicks(Math.Min(previous.Wait.Ticks * 2, MaxBackoff.Ticks)) : FirstBackoff;
            _attempts[(instanceId, externalId)] = new Attempt(now + wait, wait, halted, verified);
        }

        logger.LogDebug("Provider refresh of an instance item failed ({Kind}).", kind?.ToString() ?? "Unknown");
    }
}

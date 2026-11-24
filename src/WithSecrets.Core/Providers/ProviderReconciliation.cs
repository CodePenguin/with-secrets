using Microsoft.Extensions.Logging;

namespace WithSecrets;

/// <summary>
/// Periodic namespace reconciliation (10.3): a pass reconciles every mount whose last attempt (success or failure) is at least <see cref="ReconcileInterval" />
/// old, so a provider-side change reaches the namespace without anyone asking. Last attempts are kept in memory per mount id: a restart reconciles every mount
/// once. A mount whose instance is not registered or not Ready is skipped (and not counted as attempted). A mount's failure is logged by exception type only and
/// never stops the others; the entries of a failed or incomplete listing stay as they were (<see cref="NamespaceReconciler" />). While the authority is locked no
/// provider is called; a lock refusal met during a pass (reading the mounts or reconciling one) ends that pass quietly and records no attempt.
/// </summary>
public sealed class ProviderReconciliation(
    ProviderStore store,
    NamespaceReconciler reconciler,
    Func<bool> locked,
    Func<Guid, bool> instanceReady,
    TimeProvider clock,
    ILogger logger,
    Func<TimeSpan, CancellationToken, Task>? delay = null)
{
    public static readonly TimeSpan ReconcileInterval = TimeSpan.FromMinutes(15);

    private static readonly TimeSpan DefaultTick = TimeSpan.FromMinutes(1);

    private readonly object _gate = new();
    private readonly Dictionary<Guid, DateTimeOffset> _attempted = [];
    private readonly Func<TimeSpan, CancellationToken, Task> _delay = delay ?? ((wait, cancel) => Task.Delay(wait, clock, cancel));

    /// <summary>Ticks every <paramref name="tick" /> (default one minute) until cancelled. A tick that throws is logged by exception type and the loop continues.</summary>
    public async Task RunAsync(TimeSpan? tick, CancellationToken cancel)
    {
        TimeSpan every = tick ?? DefaultTick;
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
                logger.LogWarning("Provider namespace reconciliation pass failed ({ExceptionType}).", error.GetType().Name);
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

    /// <summary>For tests: runs just before the mounts are read.</summary>
    internal Action? BeforeMounts { get; set; }

    /// <summary>One pass.</summary>
    public async Task TickAsync(CancellationToken cancel)
    {
        if (locked())
        {
            return;
        }

        IReadOnlyList<Mount> mounts;
        try
        {
            BeforeMounts?.Invoke();
            mounts = store.Mounts();
        }
        catch (AuthorityLockedException)
        {
            return;
        }

        lock (_gate)
        {
            HashSet<Guid> current = [.. mounts.Select(mount => mount.Id)];
            foreach (Guid gone in _attempted.Keys.Where(id => !current.Contains(id)).ToList())
            {
                _attempted.Remove(gone);
            }
        }

        foreach (Mount mount in mounts)
        {
            cancel.ThrowIfCancellationRequested();
            if (locked())
            {
                return;
            }

            DateTimeOffset now = clock.GetUtcNow();
            if (!instanceReady(mount.InstanceId) || !Due(mount.Id, now))
            {
                continue;
            }

            // Recorded before the call: a failing mount waits its interval too.
            DateTimeOffset? previous;
            lock (_gate)
            {
                previous = _attempted.TryGetValue(mount.Id, out DateTimeOffset last) ? last : null;
                _attempted[mount.Id] = now;
            }

            try
            {
                await reconciler.ReconcileWithinAsync(mount, ProviderPolicy.Deadline, cancel).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancel.IsCancellationRequested)
            {
                throw;
            }
            catch (AuthorityLockedException)
            {
                // Locked meanwhile: not an attempt (the earlier one, if any, stands), and the pass ends.
                lock (_gate)
                {
                    if (previous is { } earlier)
                    {
                        _attempted[mount.Id] = earlier;
                    }
                    else
                    {
                        _attempted.Remove(mount.Id);
                    }
                }

                return;
            }
            catch (Exception error)
            {
                logger.LogWarning("Provider namespace reconciliation of a mount failed ({ExceptionType}).", error.GetType().Name);
            }
        }
    }

    private bool Due(Guid mountId, DateTimeOffset now)
    {
        lock (_gate)
        {
            return !_attempted.TryGetValue(mountId, out DateTimeOffset last) || now - last >= ReconcileInterval;
        }
    }
}

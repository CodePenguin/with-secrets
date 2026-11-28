namespace ArcanaGuardian;

/// <summary>
/// The one place where a launch is committed and where local authorization is invalidated, under one lock, so the two never
/// interleave. A launch reads <see cref="Revision" /> when it begins and later asks <see cref="TryCommit" /> to start the process:
/// the commit happens only if the launch was not cancelled and the revision is still the one it began with. <see cref="Invalidate" />
/// (for later phases: a revoked grant, a disabled machine) changes the revision, so every launch that has not committed yet is
/// refused. A launch that committed first is not touched: nothing here reaches a running child.
/// </summary>
public sealed class LaunchGate
{
    private readonly Lock _lock = new();
    private int _revision;

    /// <summary>The current local authorization revision. It only grows.</summary>
    public int Revision
    {
        get
        {
            lock (_lock)
            {
                return _revision;
            }
        }
    }

    /// <summary>Ends the authorization of every launch that has not committed yet. Waits for a commit in progress. Returns the new revision.</summary>
    public int Invalidate()
    {
        lock (_lock)
        {
            return ++_revision;
        }
    }

    /// <summary>
    /// Runs <paramref name="commit" /> (which starts the process) while holding the gate, and returns true, but only when
    /// <paramref name="cancelled" /> is not set and the revision still equals <paramref name="expectedRevision" />. Otherwise
    /// nothing runs and the result is false. <paramref name="commit" /> must be short: it blocks <see cref="Invalidate" />.
    /// </summary>
    public bool TryCommit(int expectedRevision, CancellationToken cancelled, Action commit, Func<bool>? stillValid = null)
    {
        lock (_lock)
        {
            if (cancelled.IsCancellationRequested || _revision != expectedRevision || stillValid is not null && !stillValid())
            {
                return false;
            }

            commit();

            return true;
        }
    }
}

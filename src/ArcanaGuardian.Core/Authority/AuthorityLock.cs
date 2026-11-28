namespace ArcanaGuardian;

/// <summary>How the authority became unlocked. <see cref="Seam" /> exists for tests and tools that build a service in code; no command line, setting or environment variable can choose it.</summary>
public enum UnlockMethod
{
    Manual,
    Seam,
}

/// <summary>How <see cref="AuthorityLock.UnlockWith" /> ended.</summary>
internal enum UnlockOutcome
{
    Unlocked,
    AlreadyUnlocked,
    Locking,
    NotOpened,
}

/// <summary>Thrown by anything that needs the authority's protected keys while the authority is locked.</summary>
public sealed class AuthorityLockedException() : InvalidOperationException(AuthorityLock.LockedMessage);

/// <summary>
/// Whether the authority may use its protected keys and serve anything secret-related. The service starts LOCKED. While locked, the authority signing key is not
/// used (<see cref="AuthorityKeyRing" /> refuses), the authority decides and grants nothing, the host serves no run, nothing is decrypted, the keys the unlock opened (<see cref="UnlockedKeys" />) are zeroed, and what the host
/// learned for its grants (the vouching state, synchronized grants) is discarded. This is a gate in the authority process, not a second encryption layer: the signing key stays
/// protected by the operating system (CNG), the lock decides when this process may ask the system to use it. Unlocking is an administrator ceremony
/// (a fresh, operation-bound passkey tap on the authority's own admin page);
/// it creates no grant and widens none.
/// </summary>
public sealed class AuthorityLock
{
    public const string LockedMessage = "the authority is locked; it serves nothing secret-related until an administrator unlocks it";

    private readonly Lock _gate = new();
    private readonly List<Action<string>> _onLock = [];
    private bool _locked = true;
    private int _discarding;
    private UnlockMethod? _how;
    private CancellationTokenSource? _unlockSession;

    /// <summary>A lock that starts locked, as every service does.</summary>
    public AuthorityLock()
    {
    }

    /// <summary>The test seam: an already unlocked lock, passed in <see cref="HostServiceOptions.Lock" />. The program never makes one.</summary>
    internal static AuthorityLock UnlockedForTests()
    {
        AuthorityLock made = new();
        made.Unlock(UnlockMethod.Seam);

        return made;
    }

    public bool IsLocked
    {
        get
        {
            lock (_gate)
            {
                return _locked;
            }
        }
    }

    /// <summary>A token that is cancelled when this unlock session ends. While locked it is already cancelled.</summary>
    public CancellationToken UnlockSessionToken
    {
        get
        {
            lock (_gate)
            {
                return _unlockSession?.Token ?? new CancellationToken(canceled: true);
            }
        }
    }


    public UnlockMethod? How
    {
        get
        {
            lock (_gate)
            {
                return _how;
            }
        }
    }

    /// <summary>Registers what must be discarded when the authority locks (the unlocked keys and the host's vouching state).</summary>
    public void OnLock(Action<string> discard)
    {
        lock (_gate)
        {
            _onLock.Add(discard);
        }
    }

    public void EnsureUnlocked()
    {
        if (IsLocked)
        {
            throw new AuthorityLockedException();
        }
    }

    internal void Unlock(UnlockMethod how)
    {
        lock (_gate)
        {
            UnlockInGate(how);
        }
    }

    /// <summary>
    /// Unlocks only when <paramref name="open" /> (opening the unlocked keys) succeeds, both inside this lock's gate, so a lock comes wholly before or wholly after. While the discards of a lock are still
    /// running nothing is opened, so a lock never ends with keys held; an authority that is unlocked already is left as it is (its keys are not touched).
    /// </summary>
    internal UnlockOutcome UnlockWith(UnlockMethod how, Func<bool> open)
    {
        lock (_gate)
        {
            if (!_locked)
            {
                return UnlockOutcome.AlreadyUnlocked;
            }

            if (_discarding > 0)
            {
                return UnlockOutcome.Locking;
            }

            if (!open())
            {
                return UnlockOutcome.NotOpened;
            }

            UnlockInGate(how);

            return UnlockOutcome.Unlocked;
        }
    }

    private void UnlockInGate(UnlockMethod how)
    {
        _unlockSession ??= new CancellationTokenSource();
        _locked = false;
        _how = how;
    }

    internal bool WhileUnlocked(Func<bool> use)
    {
        lock (_gate)
        {
            return !_locked && use();
        }
    }

    /// <summary>
    /// Runs <paramref name="use" /> inside this lock's gate, so a lock comes wholly before it (then it throws <see cref="AuthorityLockedException" /> and nothing runs) or wholly after it.
    /// A decryption runs here: a lock that has begun never lets one start, even before its discards have closed the keys.
    /// </summary>
    internal T UseWhileUnlocked<T>(Func<T> use)
    {
        lock (_gate)
        {
            return _locked ? throw new AuthorityLockedException() : use();
        }
    }

    /// <summary>Locks at once and runs every registered discard (key material zeroed as far as the runtime permits). Idempotent.</summary>
    public void Lock(string reason)
    {
        Action<string>[] discards;
        lock (_gate)
        {
            if (_unlockSession is { } session)
            {
                // CancelAsync marks the token before returning and runs callbacks outside this gate.
                _ = session.CancelAsync();
                _unlockSession = null;
            }

            _locked = true;
            _how = null;
            _discarding++;
            discards = [.. _onLock];
        }

        try
        {
            foreach (Action<string> discard in discards)
            {
                discard(reason);
            }
        }
        finally
        {
            lock (_gate)
            {
                _discarding--;
            }
        }
    }
}

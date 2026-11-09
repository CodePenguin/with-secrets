namespace WithSecrets;

/// <summary>
/// What a <see cref="IStoreKeyProvider" /> found. <see cref="Unlock" /> is what opens the store for this one run (null when the store needs
/// nothing); the caller uses it once and disposes it. When <see cref="Ok" /> is false the run stops: <see cref="Detail" /> says why, in words with no value in them.
/// </summary>
public sealed record KeyRelease(bool Ok, Unlock? Unlock, string Detail)
{
    public static KeyRelease Released(Unlock? unlock) => new(true, unlock, "");

    public static KeyRelease Refused(string detail) => new(false, null, detail);
}

/// <summary>
/// Where the store key comes from for a run that was authorized without an approval page decision (a grant). This is a seam, not a
/// decision: how a grant-based run obtains the key K without a passkey tap is an open question for the maintainer (see
/// IMPLEMENTATION_PROGRESS.md, "Blockers requiring maintainer input"). The only implementation today is <see cref="TapStoreKeyProvider" />, the
/// existing way: the passkey tap that the store needs. A provider returns what it was given for this run and keeps nothing: neither K nor the
/// master key is held in memory between runs.
/// </summary>
public interface IStoreKeyProvider
{
    /// <summary>
    /// Obtains what <paramref name="store" /> needs to open the secrets of <paramref name="request" />. <paramref name="note" /> prints one
    /// public line for the person at the terminal (how the key is obtained).
    /// </summary>
    KeyRelease Obtain(ISecretSource store, ApprovalRequest request, CancellationToken cancel, Action<string> note, string? grantId = null);

    /// <summary>The run that used the key failed: whatever the provider holds is dropped and zeroed.</summary>
    void Discard() { }
}

/// <summary>
/// The existing unlock: a store that needs a passkey release (WebAuthn PRF) gets it from the approval page the person taps, one tap per run,
/// and says so in one line; a store that needs nothing gets nothing. The page is the ordinary approval page for this request, so under a
/// grant the run is authorized by the grant and the tap only releases the key.
/// </summary>
public sealed class TapStoreKeyProvider(IApprover approver) : IStoreKeyProvider
{
    public const string TapNote = "with-secrets: the secret store's key is released only by a passkey tap, so the approval page opens for it (a grant does not replace that tap).";

    public KeyRelease Obtain(ISecretSource store, ApprovalRequest request, CancellationToken cancel, Action<string> note, string? grantId = null)
    {
        if (!store.NeedsUnlock)
        {
            return KeyRelease.Released(null);
        }

        note(TapNote);
        ApprovalDecision decision = approver.Request(request, cancel);
        if (!decision.Approved)
        {
            decision.Unlock?.Dispose();

            return KeyRelease.Refused($"The user did not approve the key release ({decision.Detail}). Do not retry. Ask the user.");
        }

        return KeyRelease.Released(decision.Unlock);
    }
}

/// <summary>
/// The key material a passkey tap released (the WebAuthn PRF output, which opens the master key and so the store key K), held in this service's
/// memory for the life of one grant, so that runs under that grant need no further tap (maintainer decision; a cleaner mitigation is an open item,
/// see IMPLEMENTATION_PROGRESS.md). The PRF output is held rather than K itself because it is a byte array that can be zeroed; K is opened from it
/// for each run and zeroed there. The holder keeps one key for one grant. It is dropped and zeroed by <see cref="Drop" />; the host calls that when the
/// grant ends or is revoked, the machine is disabled or untrusted, the security revision changes, the lease ends, or a run fails. Nothing is written to disk or a log.
/// </summary>
public sealed class StoreKeyHolder : IDisposable
{
    private readonly object _lock = new();
    private Unlock? _key;

    public string? GrantId { get; private set; }

    public bool IsHeld
    {
        get
        {
            lock (_lock)
            {
                return _key is not null;
            }
        }
    }

    /// <summary>Why the last held key was dropped (a short word, for tests); null while one is held or none ever was.</summary>
    public string? LastDropReason { get; private set; }

    /// <summary>Holds a copy of <paramref name="key" /> for <paramref name="grantId" />; the caller still owns (and disposes) its own. Replaces and zeroes what was held.</summary>
    public void Hold(Unlock key, string grantId)
    {
        Unlock copy = new(key.CredentialId, [.. key.Output]);
        lock (_lock)
        {
            _key?.Dispose();
            _key = copy;
            GrantId = grantId;
            LastDropReason = null;
        }
    }

    /// <summary>A copy for one run under <paramref name="grantId" /> (the caller disposes it), or null when none is held for that grant.</summary>
    public Unlock? Borrow(string grantId)
    {
        lock (_lock)
        {
            return _key is { } held && GrantId == grantId ? new Unlock(held.CredentialId, [.. held.Output]) : null;
        }
    }

    public void Drop(string reason)
    {
        lock (_lock)
        {
            if (_key is null)
            {
                return;
            }

            _key.Dispose();
            _key = null;
            GrantId = null;
            LastDropReason = reason;
        }
    }

    /// <summary>For tests: the held bytes themselves, to show they are zeroed after a drop.</summary>
    internal byte[]? HeldBytes
    {
        get
        {
            lock (_lock)
            {
                return _key?.Output;
            }
        }
    }

    public void Dispose() => Drop("service stopped");
}

/// <summary>
/// The maintainer's decision for the key (see <see cref="StoreKeyHolder" />): the first run under a grant gets the key from one passkey tap, as before,
/// and the service then holds it for that grant; further runs under the same grant need no tap. Anything else (no grant, or the host no longer
/// vouches for it) is the plain tap, and nothing is held.
/// </summary>
public sealed class HeldStoreKeyProvider(IApprover approver, HostAuthorization host) : IStoreKeyProvider
{
    public const string HeldNote = "with-secrets: using the secret store key held since the passkey tap for this grant; no new tap is needed.";

    public KeyRelease Obtain(ISecretSource store, ApprovalRequest request, CancellationToken cancel, Action<string> note, string? grantId = null)
    {
        if (!store.NeedsUnlock)
        {
            return KeyRelease.Released(null);
        }

        if (grantId is not null && host.BorrowKey(grantId) is { } borrowed)
        {
            note(HeldNote);

            return KeyRelease.Released(borrowed);
        }

        KeyRelease tapped = new TapStoreKeyProvider(approver).Obtain(store, request, cancel, note, grantId);
        if (tapped.Ok && tapped.Unlock is { } fresh && grantId is not null)
        {
            host.HoldKey(grantId, fresh);
        }

        return tapped;
    }

    public void Discard() => host.DropKey("run failed");
}

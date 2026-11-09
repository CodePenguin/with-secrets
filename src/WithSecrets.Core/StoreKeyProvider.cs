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
    KeyRelease Obtain(ISecretSource store, ApprovalRequest request, CancellationToken cancel, Action<string> note, string? grantId = null, string? scopeKey = null);

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

    public KeyRelease Obtain(ISecretSource store, ApprovalRequest request, CancellationToken cancel, Action<string> note, string? grantId = null, string? scopeKey = null)
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

/// <summary>What a held key is bound to, fixed at the tap: the grant, its scope key, the grant revision the host had, and the grant's end (null: none).</summary>
public sealed record HeldKeyBinding(string GrantId, string ScopeKey, int Revision, DateTimeOffset? Expires);

/// <summary>
/// The key material a passkey tap released (the WebAuthn PRF output, which opens the master key and so the store key K), held in this service's
/// memory for the life of one grant, so that runs under that grant need no further tap (maintainer decision; a cleaner mitigation is an open item,
/// see IMPLEMENTATION_PROGRESS.md). The PRF output is held rather than K itself because it is a byte array that can be zeroed; K is opened from it
/// for each run and zeroed there. The holder keeps one key for one <see cref="HeldKeyBinding" /> and lends it only to a run whose grant id and scope key
/// are the bound ones. It is dropped and zeroed by <see cref="Drop" />; the host calls that when the grant ends or is revoked or changes, the machine is
/// disabled or untrusted, the security revision changes, the lease ends, or a run fails. Nothing is written to disk or a log. The held bytes (and each copy
/// lent to a run) are in pinned arrays, so the garbage collector never moves them and leaves no unzeroed copy behind; the array the page's tap handed over
/// is the caller's and is zeroed when it is disposed.
/// </summary>
public sealed class StoreKeyHolder : IDisposable
{
    private readonly object _lock = new();
    private Unlock? _key;

    public HeldKeyBinding? Binding { get; private set; }

    public string? GrantId => Binding?.GrantId;

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

    private static Unlock Pinned(Unlock source)
    {
        byte[] copy = GC.AllocateArray<byte>(source.Output.Length, pinned: true);
        source.Output.CopyTo(copy, 0);

        return new Unlock(source.CredentialId, copy);
    }

    /// <summary>Holds a copy of <paramref name="key" /> under <paramref name="binding" />; the caller still owns (and disposes) its own. Replaces and zeroes what was held.</summary>
    public void Hold(Unlock key, HeldKeyBinding binding)
    {
        Unlock copy = Pinned(key);
        lock (_lock)
        {
            _key?.Dispose();
            _key = copy;
            Binding = binding;
            LastDropReason = null;
        }
    }

    /// <summary>A copy for one run under <paramref name="grantId" /> and <paramref name="scopeKey" /> (the caller disposes it), or null when none is held for exactly those.</summary>
    public Unlock? Borrow(string grantId, string scopeKey)
    {
        lock (_lock)
        {
            return _key is { } held && Binding is { } bound && bound.GrantId == grantId && bound.ScopeKey == scopeKey ? Pinned(held) : null;
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
            Binding = null;
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
/// and the service then holds it for that grant; further runs under the same grant need no tap. The page of that first tap says so plainly (in the
/// text the passkey signs): the service keeps the key for the grant until its end, or until restart for a grant with no end. Anything else (no grant, or the
/// host no longer vouches for it) is the plain tap, and nothing is held.
/// </summary>
public sealed class HeldStoreKeyProvider(IApprover approver, HostAuthorization host) : IStoreKeyProvider
{
    public const string HeldNote = "with-secrets: using the secret store key held since the passkey tap for this grant; no new tap is needed.";
    public const string KeepHeading = "This tap makes the service KEEP the secret store key for a grant. Read all of it before you approve.";

    /// <summary>The sentence the page shows (and the passkey signs) before a key-holding tap.</summary>
    public static string KeepText(string grantId, DateTimeOffset? end)
    {
        string until = end is { } at ? "until " + CanonicalJson.Time(at) + " (or until the grant is revoked or changed, the lease ends, or the service restarts)" : "until the service restarts (this grant has no end; it also stops if the grant is revoked or changed or the lease ends)";

        return $"KEY HELD: after this tap the service will keep the secret store key, which opens ALL your secrets, in its memory for grant {grantId}, {until}. Runs under the grant then need no tap and no page.";
    }

    public KeyRelease Obtain(ISecretSource store, ApprovalRequest request, CancellationToken cancel, Action<string> note, string? grantId = null, string? scopeKey = null)
    {
        if (!store.NeedsUnlock)
        {
            return KeyRelease.Released(null);
        }

        bool inGrant = grantId is not null && scopeKey is not null;
        if (inGrant && host.BorrowKey(grantId!, scopeKey!) is { } borrowed)
        {
            note(HeldNote);

            return KeyRelease.Released(borrowed);
        }

        ApprovalRequest shown = request;
        string? keep = null;
        if (inGrant && host.GrantEnd(grantId!) is { Known: true } known)
        {
            keep = KeepText(grantId!, known.Expires);
            shown = request with { Heading = KeepHeading, ExtraLines = [.. request.ExtraLines ?? [], keep] };
        }

        note(keep is null ? TapStoreKeyProvider.TapNote : "with-secrets: this run needs a passkey tap, and the page says that the tap makes the service keep the secret store key for the grant.");
        ApprovalDecision decision = approver.Request(shown, cancel);
        if (!decision.Approved)
        {
            decision.Unlock?.Dispose();

            return KeyRelease.Refused($"The user did not approve the key release ({decision.Detail}). Do not retry. Ask the user.");
        }

        if (decision.Unlock is { } fresh && keep is not null)
        {
            host.HoldKey(grantId!, scopeKey!, fresh);
        }

        return KeyRelease.Released(decision.Unlock);
    }

    public void Discard() => host.DropKey("run failed");
}

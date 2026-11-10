namespace WithSecrets;

/// <summary>The authority endpoint's seam for a launch: approve at the authority, decrypt at the authority, answer. Implemented by <see cref="AuthorityLaunchHandler" />.</summary>
public interface IRemoteLaunchHandler
{
    /// <summary>
    /// Handles one <see cref="LaunchAuthorize" /> from the machine whose session this is. <paramref name="announceLink" /> is told where the approval page is (a public link). Returns the answer, or throws
    /// <see cref="AuthorityLockedException" /> when the authority is locked; it never returns a value in any other way.
    /// </summary>
    Task<LaunchAnswer> AuthorizeAsync(string machineFingerprint, LaunchAuthorize message, Action<string> announceLink, CancellationToken cancel);

    /// <summary>Tells the handler whether the answer for this request id (which carried values) was actually sent to the machine, so the authority's record says what happened.</summary>
    void Sent(string machineFingerprint, string requestId, bool sent);
}

/// <summary>
/// The authority's side of a remote launch (architecture 10.2 as decided by the maintainer: the authority holds the store). For a request from an enrolled machine it (1) verifies the machine's
/// signatures through the same <see cref="LocalAuthority" /> that serves local launches, (2) when a valid grant covers the request, uses the key the authority itself holds for that grant (or
/// asks for the one tap that releases and holds it), else shows the ordinary approval page here with the passkey tap and PRF unlock, and records the decision exactly as a local approval is
/// recorded, (3) decrypts only the named secrets, and (4) returns them as a signed <see cref="SecretsDelivery" />. Nothing decrypted outlives the call: the values are zeroed by the
/// caller after the answer is sealed, the store key material released by the tap is zeroed here, and a held key (the maintainer's grant decision) is bound to its grant, scope, revisions and end,
/// kept per machine in this process only, and dropped on a lock, a revoke, an end, a disable, a revision change and any failure. A request id is delivered at most once.
/// </summary>
public sealed class AuthorityLaunchHandler : IRemoteLaunchHandler, IDisposable
{
    private readonly LocalAuthority _authority;
    private readonly AuthorityKeyRing _keys;
    private readonly AuthorityStore _store;
    private readonly ISecretSource _secrets;
    private readonly Func<Action<string>, IApprover> _approver;
    private readonly AuthorityLock? _lock;
    private readonly TimeProvider _clock;
    private readonly Lock _gate = new();
    private readonly HashSet<CancellationTokenSource> _open = [];
    private readonly Dictionary<string, Held> _held = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DateTimeOffset> _delivered = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _sweeper;

    private sealed record Held(StoreKeyHolder Holder, int SecurityRevision);

    public AuthorityLaunchHandler(LocalAuthority authority, AuthorityKeyRing keys, AuthorityStore store, ISecretSource secrets, Func<Action<string>, IApprover> approver, AuthorityLock? lockState, TimeProvider? clock = null, TimeSpan? sweepInterval = null)
    {
        _authority = authority;
        _keys = keys;
        _store = store;
        _secrets = secrets;
        _approver = approver;
        _lock = lockState;
        _clock = clock ?? TimeProvider.System;
        lockState?.OnLock(reason =>
        {
            CancelAll();
            DropKeys("authority locked");
        });
        _sweeper = Task.Run(() => SweepLoopAsync(sweepInterval ?? TimeSpan.FromSeconds(1)));
    }

    /// <summary>How many secret reads this handler made for launches (for tests and status; a count only).</summary>
    public int Decryptions => Volatile.Read(ref _decryptions);

    private int _decryptions;

    /// <summary>The number of machines for which a store key is held right now (for tests and status).</summary>
    public int HeldKeys
    {
        get
        {
            lock (_gate)
            {
                return _held.Values.Count(item => item.Holder.IsHeld);
            }
        }
    }

    /// <summary>For tests: the held key bytes of a machine, to show they are zeroed after a drop.</summary>
    internal byte[]? HeldBytes(string machineFingerprint)
    {
        lock (_gate)
        {
            return _held.TryGetValue(machineFingerprint, out Held? held) ? held.Holder.HeldBytes : null;
        }
    }

    /// <summary>Cancels every approval page that is open for a launch (the authority locked, or the handler stops).</summary>
    public void CancelAll()
    {
        CancellationTokenSource[] sources;
        lock (_gate)
        {
            sources = [.. _open];
        }

        foreach (CancellationTokenSource source in sources)
        {
            try
            {
                source.Cancel();
            }
            catch (ObjectDisposedException)
            {
                // Ended already.
            }
        }
    }

    private void DropKeys(string reason)
    {
        lock (_gate)
        {
            foreach (Held held in _held.Values)
            {
                held.Holder.Drop(reason);
            }
        }
    }

    private async Task SweepLoopAsync(TimeSpan interval)
    {
        using PeriodicTimer timer = new(interval);
        try
        {
            while (await timer.WaitForNextTickAsync(_stop.Token))
            {
                try
                {
                    Sweep();
                }
                catch (Exception error) when (error is not OutOfMemoryException)
                {
                    AppLog.Warn("sweeping the held keys failed: {Type}", error.GetType().Name);
                    DropKeys("sweep failed");
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Stopping.
        }
    }

    /// <summary>Drops every held key whose justification is gone: the grant is not usable or changed, the machine is not Trusted or its security revision moved, or the grant ended.</summary>
    public void Sweep()
    {
        KeyValuePair<string, Held>[] all;
        lock (_gate)
        {
            all = [.. _held];
        }

        foreach ((string machineFingerprint, Held held) in all)
        {
            if (held.Holder.Binding is not { } bound)
            {
                continue;
            }

            MachineRecord? machine = _store.Find(machineFingerprint);
            GrantRecord? grant = _store.FindGrant(bound.GrantId);
            DateTimeOffset now = _clock.GetUtcNow();
            if (_lock?.IsLocked == true)
            {
                held.Holder.Drop("authority locked");
            }
            else if (machine is not { Status: MachineStatus.Trusted } || machine.SecurityRevision != held.SecurityRevision)
            {
                held.Holder.Drop("machine changed");
            }
            else if (grant is null || !grant.IsUsable(now) || grant.Revision != bound.Revision || grant.ScopeKey != bound.ScopeKey)
            {
                held.Holder.Drop("grant ended or changed");
            }
            else if (bound.Expires is { } end && now >= end)
            {
                held.Holder.Drop("grant expired");
            }
        }
    }

    public async Task<LaunchAnswer> AuthorizeAsync(string machineFingerprint, LaunchAuthorize message, Action<string> announceLink, CancellationToken cancel)
    {
        LaunchRequest request = message.Decide.Request;
        string digest = request.Digest();
        DateTimeOffset now = _clock.GetUtcNow();
        LaunchAnswer Deny(string code, int revision)
        {
            DateTimeOffset issued = _clock.GetUtcNow();

            return new LaunchAnswer(null, AuthorityResponse.Create(request.RequestId, digest, machineFingerprint, AuthorityDecision.Denied, code, revision, issued, issued + LocalAuthority.ResponseLifetime, _keys.Current()));
        }

        _lock?.EnsureUnlocked();
        MachineRecord? machine = _store.Find(machineFingerprint);
        if (machine is null)
        {
            return Deny(ReasonCodes.UnknownMachine, 0);
        }

        if (!message.Verify(machine.PublicKey))
        {
            return Deny(ReasonCodes.BadSignature, machine.SecurityRevision);
        }

        if (request.Validate(now) is not null)
        {
            return Deny(ReasonCodes.InvalidRequest, machine.SecurityRevision);
        }

        // A request id is delivered once: a repeat (a replayed or re-sent message, in this or an earlier session) gets nothing.
        lock (_gate)
        {
            foreach (string old in _delivered.Where(item => item.Value < now).Select(item => item.Key).ToList())
            {
                _delivered.Remove(old);
            }

            if (!_delivered.TryAdd(machineFingerprint + "\n" + request.RequestId, request.Expires.AddMinutes(1)))
            {
                return Deny(ReasonCodes.RequestIdReused, machine.SecurityRevision);
            }
        }

        // Across restarts too: values prepared for this id once are never prepared again (the durable row is written before they are sent).
        if (_store.WasDelivered(machineFingerprint, request.RequestId))
        {
            return Deny(ReasonCodes.RequestIdReused, machine.SecurityRevision);
        }

        // Only a machine that may ask learns whether a name exists; the others are refused by the same checks that refuse them in local mode.
        if (machine.Status == MachineStatus.Trusted && string.Equals(machine.HostName, message.Decide.HostName, StringComparison.Ordinal))
        {
            IReadOnlyList<string> available = _secrets.ListNames();
            if (request.SecretNames.Any(name => !available.Contains(name, StringComparer.Ordinal)))
            {
                return Deny(ReasonCodes.UnknownSecret, machine.SecurityRevision);
            }
        }

        using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        lock (_gate)
        {
            _open.Add(linked);
        }

        try
        {
            ApprovalRequest page = Page(machine, message, request);

            // The scope key must be the one these contents make (the machine's fingerprint, the fingerprint key and the expanded arguments the machine signed): a use cannot name a scope
            // the request does not belong to. What the grant covers (names, program, folder) is checked by the authority against the grant itself.
            if (message.Use.ScopeKey != GrantEvidence.Scope(machineFingerprint, message.Context.FingerprintKey, message.Context.Arguments))
            {
                return Deny(ReasonCodes.InvalidRequest, machine.SecurityRevision);
            }

            // A grant that covers exactly this request stands in for the page's decision: the authority answers from its own record (the same check as in local mode).
            GrantResponse grant = await _authority.GrantAsync(message.Use, linked.Token);
            if (grant.Outcome == GrantOps.Granted && grant.GrantId.Length > 0 && grant.ScopeKey == message.Use.ScopeKey)
            {
                return await ViaGrantAsync(machine, message, page, grant, announceLink, linked.Token, Deny);
            }

            return await ViaPageAsync(machine, message, page, announceLink, linked.Token, Deny);
        }
        finally
        {
            lock (_gate)
            {
                _open.Remove(linked);
            }
        }
    }

    private ApprovalRequest Page(MachineRecord machine, LaunchAuthorize message, LaunchRequest request)
    {
        PageContext context = message.Context;
        Dictionary<string, string> sources = request.SecretNames.ToDictionary(name => name, _ => _secrets.Label, StringComparer.Ordinal);
        string name = string.IsNullOrWhiteSpace(machine.FriendlyName) ? machine.HostName : machine.FriendlyName!;

        return new ApprovalRequest(request.Program, context.ResolvedProgram, context.Arguments, request.WorkingDirectory, request.Reason, request.SecretNames, null, request.Arguments, context.Links, context.FingerprintKey, sources, _secrets.NeedsUnlock, context.Script, context.ProgramFile,
            [.. request.Mappings.Select(mapping => new SecretMapping(mapping.Variable, mapping.Secret))], request.EnvFiles, request.EnvNames, request.EnvVariables, request.InheritedEnvironment,
            ExtraLines: [$"This request comes from another machine: {ApprovalSummary.Clean(name)} (host name {ApprovalSummary.Clean(message.Decide.HostName)}, key fingerprint {KeyIdentity.Display(machine.Fingerprint)}). The program runs there; the secrets are decrypted here and sent to it over the encrypted machine connection."]);
    }

    private Action<string> Announce(Action<string> announceLink) => line =>
    {
        if (line.StartsWith(WebApprover.LinkPrefix, StringComparison.Ordinal))
        {
            announceLink(line[WebApprover.LinkPrefix.Length..]);
        }
    };

    private async Task<LaunchAnswer> ViaPageAsync(MachineRecord machine, LaunchAuthorize message, ApprovalRequest page, Action<string> announceLink, CancellationToken cancel, Func<string, int, LaunchAnswer> deny)
    {
        LaunchRequest request = message.Decide.Request;
        ApprovalDecision? decision = null;
        bool presented = false;
        IDisposable offer;
        try
        {
            offer = _authority.Offer(request.RequestId, request.Digest(), () =>
            {
                presented = true;
                IApprover approver = _approver(Announce(announceLink));
                decision = approver.Request(page, cancel);

                return decision;
            });
        }
        catch (InvalidOperationException)
        {
            return deny(ReasonCodes.RequestIdReused, machine.SecurityRevision);
        }

        Unlock? unlock = null;
        try
        {
            AuthorityResponse response;
            using (offer)
            {
                response = await _authority.DecideAsync(message.Decide, cancel);
            }

            unlock = decision?.Unlock;
            if (response.Decision != AuthorityDecision.Approved)
            {
                return new LaunchAnswer(null, response);
            }

            // Approved, but not by a page this call showed: an earlier session's committed answer. The values were (or were not) delivered then; never again.
            if (!presented || decision is not { Approved: true })
            {
                return deny(ReasonCodes.RequestIdReused, response.SecurityRevision);
            }

            if (cancel.IsCancellationRequested)
            {
                _store.RecordDeliveryEvent(machine.Fingerprint, message.Decide.Request.RequestId, "approved-not-delivered", "the approval was given but the session ended or the launch was cancelled before any value was decrypted");
                return deny(ReasonCodes.Cancelled, response.SecurityRevision);
            }

            return Deliver(message, SecretsDelivery.ViaPage, "", response.SecurityRevision, unlock, deny);
        }
        finally
        {
            unlock?.Dispose();
        }
    }

    private async Task<LaunchAnswer> ViaGrantAsync(MachineRecord machine, LaunchAuthorize message, ApprovalRequest page, GrantResponse grant, Action<string> announceLink, CancellationToken cancel, Func<string, int, LaunchAnswer> deny)
    {
        Unlock? unlock = null;
        try
        {
            if (_secrets.NeedsUnlock)
            {
                unlock = Borrow(machine.Fingerprint, grant);
                if (unlock is null)
                {
                    // The first run under the grant: one tap releases the key, and the authority keeps it for the grant (the page says so, and the passkey signs that text).
                    string keep = HeldStoreKeyProvider.KeepText(grant.GrantId, grant.Indefinite ? null : grant.GrantExpires);
                    ApprovalRequest shown = page with { Heading = HeldStoreKeyProvider.KeepHeading, ExtraLines = [.. page.ExtraLines ?? [], keep] };
                    ApprovalDecision tap = await Task.Run(() => _approver(Announce(announceLink)).Request(shown, cancel), cancel);
                    if (!tap.Approved)
                    {
                        tap.Unlock?.Dispose();

                        return deny(cancel.IsCancellationRequested ? ReasonCodes.Cancelled : ReasonCodes.UserDenied, grant.SecurityRevision);
                    }

                    unlock = tap.Unlock;
                    if (unlock is not null)
                    {
                        Hold(machine.Fingerprint, grant, unlock);
                    }
                }
            }

            if (cancel.IsCancellationRequested)
            {
                return deny(ReasonCodes.Cancelled, grant.SecurityRevision);
            }

            return Deliver(message, SecretsDelivery.ViaGrant, grant.GrantId, grant.SecurityRevision, unlock, deny);
        }
        finally
        {
            unlock?.Dispose();
        }
    }

    private Unlock? Borrow(string machineFingerprint, GrantResponse grant)
    {
        lock (_gate)
        {
            if (!_held.TryGetValue(machineFingerprint, out Held? held) || held.Holder.Binding is not { } bound)
            {
                return null;
            }

            DateTimeOffset? end = grant.Indefinite ? null : grant.GrantExpires;
            if (bound.GrantId != grant.GrantId || bound.ScopeKey != grant.ScopeKey || bound.Revision != grant.GrantRevision || bound.Expires != end || held.SecurityRevision != grant.SecurityRevision)
            {
                held.Holder.Drop("grant changed");

                return null;
            }

            return held.Holder.Borrow(grant.GrantId, grant.ScopeKey);
        }
    }

    private void Hold(string machineFingerprint, GrantResponse grant, Unlock key)
    {
        lock (_gate)
        {
            if (!_held.TryGetValue(machineFingerprint, out Held? held))
            {
                _held[machineFingerprint] = held = new Held(new StoreKeyHolder(), grant.SecurityRevision);
            }
            else if (held.SecurityRevision != grant.SecurityRevision)
            {
                held.Holder.Dispose();
                _held[machineFingerprint] = held = new Held(new StoreKeyHolder(), grant.SecurityRevision);
            }

            held.Holder.Hold(key, new HeldKeyBinding(grant.GrantId, grant.ScopeKey, grant.GrantRevision, grant.Indefinite ? null : grant.GrantExpires));
        }
    }

    private LaunchAnswer Deliver(LaunchAuthorize message, string via, string grantId, int revision, Unlock? unlock, Func<string, int, LaunchAnswer> deny)
    {
        LaunchRequest request = message.Decide.Request;

        // A lock since the approval ends it here: nothing is decrypted.
        _lock?.EnsureUnlocked();
        SecretValues values;
        try
        {
            Interlocked.Increment(ref _decryptions);
            values = _secrets.GetValues(request.SecretNames, unlock);
        }
        catch (Exception error) when (error is not OutOfMemoryException and not AuthorityLockedException)
        {
            AppLog.Warn("the authority could not decrypt for a launch: {Type}", error.GetType().Name);
            if (via == SecretsDelivery.ViaGrant)
            {
                DropKeys("decrypt failed");
            }

            return deny(ReasonCodes.Internal, revision);
        }

        // The delivery's byte arrays are the SecretValues' own: the caller zeroes them once the answer is sealed (see AuthorityEndpoint).
        try
        {
            DateTimeOffset issued = _clock.GetUtcNow();
            List<DeliveredValue> list = [.. values.Names.Select(name => new DeliveredValue(name, [.. values.Bytes(name)]))];
            SecretsDelivery delivery = SecretsDelivery.Create(request.RequestId, request.Digest(), message.Decide.MachineFingerprint, via, grantId, revision, issued, issued + SecretsDelivery.MaxLifetime, list, _keys.Current());

            // Written before the answer can be sent: a restart cannot prepare values for this id again.
            _store.RecordDeliveryEvent(message.Decide.MachineFingerprint, request.RequestId, "delivery-prepared", via == SecretsDelivery.ViaGrant ? "by grant " + grantId : "by the approval page");

            return new LaunchAnswer(delivery, null);
        }
        finally
        {
            values.Dispose();
        }
    }

    public void Sent(string machineFingerprint, string requestId, bool sent)
    {
        try
        {
            _store.RecordDeliveryEvent(machineFingerprint, requestId, sent ? "delivery-sent" : "delivery-not-sent", sent ? "the answer with the values was sent into the session" : "the values were prepared but not sent (the session ended or the authority locked)");
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            AppLog.Warn("a delivery outcome could not be recorded: {Type}", error.GetType().Name);
        }
    }
    public void Dispose()
    {
        _stop.Cancel();
        try
        {
            _sweeper.Wait(TimeSpan.FromSeconds(2));
        }
        catch (Exception error) when (error is AggregateException or OperationCanceledException)
        {
            // Stopped.
        }

        CancelAll();
        lock (_gate)
        {
            foreach (Held held in _held.Values)
            {
                held.Holder.Dispose();
            }

            _held.Clear();
        }

        _stop.Dispose();
    }
}

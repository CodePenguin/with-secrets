namespace WithSecrets;

/// <summary>
/// What the host learned from the authority: <see cref="Decision" /> is the person's own answer when the authority approved (it
/// carries the unlock material the page released, which never travels through the authority's response), or a denial.
/// <see cref="AuthorityMessage" /> is the one-line text for a denial that did not come from the person (the machine's status, an
/// answer that did not verify, an authority that did not answer); null otherwise. <see cref="Code" /> is the reason code.
/// </summary>
public sealed record AuthorizationOutcome(ApprovalDecision Decision, string? AuthorityMessage, string Code, int Revision = -1);

/// <summary>
/// The host service's side of the authority protocol. For one launch it signs the request with the machine identity key, asks the
/// authority, and checks the answer before the caller decrypts anything: the signature must be that of the pinned authority key (a
/// rotation is accepted only through a transition the pinned key signed), the request id, digest and machine must be the ones sent,
/// the answer must not have expired, and the security revision must not be older than the one already applied. A newer revision
/// than the host knew means its cache and grants are stale: they are cleared (<see cref="LaunchGate.Invalidate" />) and this launch
/// is refused; the next one starts from the new revision. Anything that does not verify is a denial.
/// </summary>
public sealed class HostAuthorization(IAuthority authority, ISigningKey machineKey, string hostName, HostConfigFile config, LaunchGate gate, Func<string, string, Func<ApprovalDecision>, IDisposable> offer, TimeProvider? clock = null, Action? clearSaved = null, IMonotonicClock? monotonic = null)
{
    private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(1);

    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly Lock _lock = new();
    private int? _knownRevision;
    private readonly Dictionary<string, int> _saved = [];
    private readonly Dictionary<string, SyncedGrant> _synced = new(StringComparer.Ordinal);
    private readonly IMonotonicClock _monotonic = monotonic ?? SystemMonotonicClock.Instance;
    private long _reconcileNotBefore;
    private int _reconciling;

    /// <summary>The offline-authorization lease: in memory only, issued by the authority's reconcile answer, measured on the monotonic clock. None after a restart.</summary>
    public OfflineLease Lease { get; } = new(monotonic ?? SystemMonotonicClock.Instance);

    public string Fingerprint { get; } = KeyIdentity.Fingerprint(machineKey.PublicKey);

    /// <summary>The store key material held for one grant after its approving tap (see <see cref="StoreKeyHolder" />). Dropped by <see cref="SweepKey" /> whenever what justified holding it is gone.</summary>
    public StoreKeyHolder Keys { get; } = new();

    /// <summary>
    /// Drops the held key unless this host still vouches for its grant: the grant is synchronized and has not ended, and the lease runs (a revision
    /// change or a disable forgets every grant, which ends here). Called wherever one of those can change, and before a key is lent.
    /// </summary>
    public void SweepKey()
    {
        lock (_lock)
        {
            if (Keys.Binding is not { } bound)
            {
                return;
            }

            // The key is bound to what was true at the tap (grant, scope, revision, end). Whatever the host learns later never moves that: a grant that
            // changed (any new revision, even an authenticated extension) or a scope that differs ends the hold and the next run taps again.
            SyncedGrant? grant = _synced.Values.FirstOrDefault(item => item.GrantId == bound.GrantId);
            if (grant is null)
            {
                Keys.Drop("grant gone");
            }
            else if (grant.ScopeKey != bound.ScopeKey || grant.Revision != bound.Revision)
            {
                Keys.Drop("grant changed");
            }
            else if (!Lease.IsValid)
            {
                Keys.Drop("lease ended");
            }
            else if (bound.Expires is { } end && _clock.GetUtcNow() >= end)
            {
                Keys.Drop("grant expired");
            }
        }
    }

    /// <summary>A copy of the held key for a run under <paramref name="grantId" />, or null (swept first, so a stale key is never lent).</summary>
    public Unlock? BorrowKey(string grantId, string scopeKey)
    {
        lock (_lock)
        {
            SweepKey();

            return Keys.Borrow(grantId, scopeKey);
        }
    }

    /// <summary>The end of a synchronized grant as the host knows it (null: no end) and whether the host vouches for it now, for the page of a key-holding tap.</summary>
    public (bool Known, DateTimeOffset? Expires) GrantEnd(string grantId)
    {
        lock (_lock)
        {
            SyncedGrant? grant = _synced.Values.FirstOrDefault(item => item.GrantId == grantId);

            return grant is null ? (false, null) : (true, grant.Expires);
        }
    }

    /// <summary>Holds a copy of the key a tap released for this grant, if the host still vouches for the grant.</summary>
    public void HoldKey(string grantId, string scopeKey, Unlock key)
    {
        lock (_lock)
        {
            SyncedGrant? grant = _synced.Values.FirstOrDefault(item => item.GrantId == grantId && item.ScopeKey == scopeKey && (item.Expires is null || _clock.GetUtcNow() < item.Expires));
            if (Lease.IsValid && grant is not null)
            {
                Keys.Hold(key, new HeldKeyBinding(grant.GrantId, grant.ScopeKey, grant.Revision, grant.Expires));
            }
        }
    }

    public void DropKey(string reason) => Keys.Drop(reason);

    /// <summary>The grants this host has synchronized with the authority (the scopes it may use while the authority cannot be reached, within the lease).</summary>
    public IReadOnlyList<SyncedGrant> SyncedGrants
    {
        get
        {
            lock (_lock)
            {
                return [.. _synced.Values];
            }
        }
    }

    public string HostName => hostName;

    /// <summary>The security revision of this machine that the host last applied, or null before the first answer.</summary>
    public int? KnownRevision
    {
        get
        {
            lock (_lock)
            {
                return _knownRevision;
            }
        }
    }

    /// <summary>
    /// Notes that the saved approval for <paramref name="requestKey" /> was made under the revision this host has applied. A saved approval
    /// is honoured only while the machine's revision is that one; this note lives in memory only, so none survives a restart.
    /// </summary>
    public void RememberSaved(string requestKey)
    {
        lock (_lock)
        {
            if (_knownRevision is { } known)
            {
                _saved[requestKey] = known;
            }
        }
    }

    /// <summary>True when a saved approval for <paramref name="requestKey" /> was made under the revision this host currently has applied.</summary>
    public bool SavedStillValid(string requestKey)
    {
        lock (_lock)
        {
            return _knownRevision is { } known && _saved.TryGetValue(requestKey, out int made) && made == known;
        }
    }

    /// <summary>Forgets every saved approval (in this host and in the store behind <c>clearSaved</c>), every synchronized grant and the offline lease. Called with the lock held.</summary>
    private void ForgetSaved()
    {
        _saved.Clear();
        clearSaved?.Invoke();
        _synced.Clear();
        Lease.Clear();
        Keys.Drop("authorization changed");
        _reconcileNotBefore = 0;
    }

    /// <summary>The one-line text for a reason code that stops a machine (names the command that fixes it).</summary>
    public string Message(string code) => code switch
    {
        ReasonCodes.MachinePending => $"this machine is not approved yet. Ask the administrator to run: with-secrets admin approve {Fingerprint} --name NAME",
        ReasonCodes.MachineDisabled => $"this machine is disabled. Ask the administrator to run: with-secrets admin enable {Fingerprint}",
        ReasonCodes.MachineUntrusted => $"this machine is not trusted. Ask the administrator to run: with-secrets admin trust {Fingerprint}",
        ReasonCodes.UnknownMachine => "the authority does not know this machine. Start the service again (with-secrets service); it enrolls the machine",
        ReasonCodes.HostNameMismatch => $"the host name {ApprovalSummary.Clean(hostName)} is not the one this machine was approved with. Ask the administrator to run: with-secrets admin approve-host-change {Fingerprint}",
        ReasonCodes.AuthorizationChanged => "the machine's authorization changed while the request was open. Ask again",
        GrantReasons.NoEvidence or GrantReasons.BadEvidence => "the approval did not carry a passkey assertion that backs the grant, so none was made. Nothing was saved",
        GrantReasons.NoTime => "no grant time was chosen on the approval page (choose one of the times it offers). Nothing was saved",
        _ => "the authority refused the request (" + code + ")",
    };

    /// <summary>
    /// Asks the authority about <paramref name="launch" />. <paramref name="present" /> shows the approval and returns the person's answer;
    /// the authority calls it only when the machine may ask. Nothing here decrypts or starts anything.
    /// </summary>
    public async Task<AuthorizationOutcome> AuthorizeAsync(LaunchRequest launch, Func<ApprovalDecision> present, CancellationToken cancel)
    {
        AuthorizationOutcome Deny(string code, string message) => new(ApprovalDecision.Deny(message), message, code);

        HostConfigLoad load = config.Load();
        if (load.Problem is not null)
        {
            return Deny("host-config", load.Problem);
        }

        if (load.Config?.Authority is null)
        {
            return Deny(ReasonCodes.MachinePending, Message(ReasonCodes.MachinePending));
        }

        if (load.Config.MachineFingerprint != Fingerprint)
        {
            return Deny(ReasonCodes.MachinePending, "host.json is for another machine identity; " + Message(ReasonCodes.MachinePending));
        }

        ApprovalDecision? local = null;
        AuthorityResponse response;
        try
        {
            MachineRequestEnvelope envelope = MachineRequestEnvelope.Create(launch, hostName, machineKey);
            using IDisposable offered = offer(launch.RequestId, envelope.RequestDigest, () => local = present());
            response = await authority.DecideAsync(envelope, cancel);
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            local?.Unlock?.Dispose();
            AppLog.Warn("the authority did not answer: {Type}", error.GetType().Name);

            return Deny("authority-unavailable", "the authority could not be asked (" + error.GetType().Name + "). Nothing was run");
        }

        string? problem;
        string? revisionProblem = null;
        try
        {
            problem = await Verify(response, launch, cancel);
            if (problem is null)
            {
                revisionProblem = RevisionProblem(response.SecurityRevision);
            }
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            // A failure while checking the answer (the database, host.json) is a denial, and what the page released is zeroed.
            local?.Unlock?.Dispose();
            AppLog.Warn("the authority's answer could not be checked: {Type}", error.GetType().Name);

            return Deny("response-invalid", "the authority's answer could not be verified (" + error.GetType().Name + "). Nothing was run");
        }

        if (problem is not null)
        {
            local?.Unlock?.Dispose();

            return Deny("response-invalid", "the authority's answer could not be verified (" + problem + "). Nothing was run");
        }

        if (revisionProblem is not null)
        {
            local?.Unlock?.Dispose();

            return Deny(ReasonCodes.AuthorizationChanged, revisionProblem);
        }

        if (response.Decision == AuthorityDecision.Approved)
        {
            if (local is not { Approved: true })
            {
                local?.Unlock?.Dispose();

                return Deny("no-approval", "the authority approved, but this host has no approval of its own for it. Nothing was run");
            }

            // No valid lease, no use of secrets: a host that cannot show a current lease from its authority fails closed.
            if (!await EnsureLeaseAsync(cancel))
            {
                local.Unlock?.Dispose();

                return Deny("no-lease", NoLeaseMessage);
            }

            return new AuthorizationOutcome(local, null, response.ReasonCode, response.SecurityRevision);
        }

        local?.Unlock?.Dispose();
        if (response.ReasonCode is ReasonCodes.UserDenied or ReasonCodes.Cancelled && local is not null)
        {
            return new AuthorizationOutcome(local, null, response.ReasonCode, response.SecurityRevision);
        }

        return Deny(response.ReasonCode, Message(response.ReasonCode));
    }

    /// <summary>Checks any signed answer of the authority against the pinned key (and a rotation through its transitions), the request it answers and its validity. Null when it holds, else why not.</summary>
    internal Task<string?> VerifyAnswerAsync(ISignedAnswer answer, string requestId, string requestDigest, CancellationToken cancel) => Verify(answer, requestId, requestDigest, cancel);

    private Task<string?> Verify(AuthorityResponse response, LaunchRequest launch, CancellationToken cancel) => Verify(response, launch.RequestId, launch.Digest(), cancel);

    private async Task<string?> Verify(ISignedAnswer response, string requestId, string requestDigest, CancellationToken cancel)
    {
        if (response.ProtocolVersion != LaunchProtocol.Version)
        {
            return "another protocol version";
        }

        PinnedAuthorityKey? pinned = Pinned();
        if (pinned is null)
        {
            return "no authority key is pinned";
        }

        // A key this host has not pinned: a routine rotation is accepted only through the transitions the pinned key signed.
        if (response.AuthorityKeyId != pinned.Fingerprint)
        {
            foreach (KeyTransition transition in await authority.KeyTransitionsAsync(pinned.Fingerprint, cancel))
            {
                if (config.TryApplyTransition(transition) is not null)
                {
                    break;
                }
            }

            pinned = Pinned();
            if (pinned is null || response.AuthorityKeyId != pinned.Fingerprint)
            {
                return "signed by a key that is not pinned";
            }
        }

        if (!response.Verify(pinned.PublicKey))
        {
            return "the signature does not verify";
        }

        DateTimeOffset now = _clock.GetUtcNow();
        if (response.RequestId != requestId)
        {
            return "another request id";
        }

        if (!string.Equals(response.RequestDigest, requestDigest, StringComparison.Ordinal))
        {
            return "another request digest";
        }

        if (response.MachineFingerprint != Fingerprint)
        {
            return "another machine";
        }

        if (response.Issued > now + ClockSkew)
        {
            return "issued in the future";
        }

        if (response.Expires - response.Issued > AuthorityResponse.MaxLifetime)
        {
            return "valid for too long";
        }

        return now >= response.Expires ? "expired" : null;
    }

    private PinnedAuthorityKey? Pinned() => config.Load().Config?.Authority;

    /// <summary>Applies a revision learned from a verified response. A revision older than the applied one is refused; a newer one clears the host's authorization state and refuses this launch.</summary>
    private string? RevisionProblem(int revision)
    {
        lock (_lock)
        {
            if (_knownRevision is not { } known)
            {
                _knownRevision = revision;

                return null;
            }

            if (revision < known)
            {
                return "the authority's answer is for an older security revision than this host has applied";
            }

            if (revision > known)
            {
                _knownRevision = revision;
                gate.Invalidate();
                ForgetSaved();

                return "the machine's security revision changed, so the host cleared its authorization state. Ask again";
            }

            return null;
        }
    }

    /// <summary>The line a run or approval gets when the host has no valid lease from its authority.</summary>
    public const string NoLeaseMessage = "this host has no valid offline-authorization lease (the authority has not been reached lately, or the machine is not Trusted), so secrets cannot be used. The service reconnects by itself; ask again in a moment";

    /// <summary>
    /// Applies an invalidation the authority announced (clears the host's authorization state, synchronized grants and lease; pending launches are
    /// cancelled at their commit), then acknowledges it; applies the grant revocations the same way; then renews the lease while the authority answers.
    /// A host that cannot reach its authority throws from here and renews nothing.
    /// </summary>
    public async Task PumpAsync(CancellationToken cancel = default)
    {
        foreach (PendingInvalidation invalidation in await authority.PendingInvalidationsAsync(Fingerprint, cancel))
        {
            lock (_lock)
            {
                if (_knownRevision is not { } known || invalidation.Revision > known)
                {
                    _knownRevision = invalidation.Revision;
                }

                gate.Invalidate();
                ForgetSaved();
            }

            // Acknowledged only after the cleanup above: an unacknowledged one is delivered again.
            await authority.AcknowledgeInvalidationAsync(Fingerprint, invalidation.Revision, cancel);
        }

        foreach (PendingGrantEvent notice in await authority.PendingGrantEventsAsync(Fingerprint, cancel))
        {
            lock (_lock)
            {
                // The revoked scope is dropped, and every launch that has not committed is cancelled (the gate does not know which grant a launch used).
                foreach (string scope in _synced.Where(item => item.Value.GrantId == notice.GrantId || item.Key == notice.ScopeKey).Select(item => item.Key).ToList())
                {
                    _synced.Remove(scope);
                }

                Keys.Drop("grant revoked");
                gate.Invalidate();
            }

            await authority.AcknowledgeGrantEventAsync(Fingerprint, notice.Sequence, cancel);
        }

        // A lease that is half gone, or none, is renewed now (the local authority always answers; a remote one that does not leaves the lease to run out).
        if (!Lease.IsValid && _monotonic.Milliseconds >= Volatile.Read(ref _reconcileNotBefore) || Lease.IsValid && Lease.Remaining < Lease.Duration / 2)
        {
            await ReconcileAsync(cancel);
        }

        SweepKey();
    }

    /// <summary>What a check-in with the authority came to.</summary>
    public enum Reconciliation
    {
        /// <summary>The authority answered and its answer verified (a lease was issued when the machine is Trusted).</summary>
        Reconciled,

        /// <summary>The authority could not be reached.</summary>
        Unreachable,

        /// <summary>The authority answered with something that did not verify, or this host cannot verify (nothing pinned).</summary>
        Unverified,
    }

    /// <summary>
    /// Checks in with the authority: it must answer for this machine (status, host name binding, security revision) with a signature of the pinned
    /// key, and, when the machine is Trusted, it issues the lease, which starts on the monotonic clock now and replaces the one there was. A revision
    /// newer than the one applied clears every cache first (so no state outlives an administrative change). Called at startup (before requests
    /// are accepted), on reconnect and on renewal; the same code runs in local mode.
    /// </summary>
    public async Task<Reconciliation> ReconcileAsync(CancellationToken cancel = default)
    {
        // One check-in at a time.
        if (Interlocked.Exchange(ref _reconciling, 1) == 1)
        {
            return Lease.IsValid ? Reconciliation.Reconciled : Reconciliation.Unverified;
        }

        try
        {
            HostConfigLoad load = config.Load();
            if (load.Problem is not null || load.Config?.Authority is null || load.Config.MachineFingerprint != Fingerprint)
            {
                Lease.Clear();
                Keys.Drop("lease not renewed");
                Volatile.Write(ref _reconcileNotBefore, _monotonic.Milliseconds + 5000);

                return Reconciliation.Unverified;
            }

            ReconcileEnvelope envelope = ReconcileEnvelope.Create("rc-" + Guid.NewGuid().ToString("N"), hostName, _clock.GetUtcNow(), machineKey);
            ReconcileResponse response;
            try
            {
                response = await authority.ReconcileAsync(envelope, cancel);
            }
            catch (Exception error) when (error is not OutOfMemoryException)
            {
                AppLog.Warn("the authority could not be reached for a check-in: {Type}", error.GetType().Name);

                return Reconciliation.Unreachable;
            }

            try
            {
                if (await Verify(response, envelope.RequestId, envelope.Digest(), cancel) is not null || response.Status == "Unknown")
                {
                    Lease.Clear();
                    Keys.Drop("lease not renewed");
                    Volatile.Write(ref _reconcileNotBefore, _monotonic.Milliseconds + 5000);

                    return Reconciliation.Unverified;
                }
            }
            catch (Exception error) when (error is not OutOfMemoryException)
            {
                AppLog.Warn("the authority's check-in answer could not be checked: {Type}", error.GetType().Name);
                Lease.Clear();
                Keys.Drop("check-in failed");
                Volatile.Write(ref _reconcileNotBefore, _monotonic.Milliseconds + 5000);

                return Reconciliation.Unverified;
            }

            lock (_lock)
            {
                if (_knownRevision is { } known && response.SecurityRevision < known)
                {
                    // An answer for an older revision than the one applied is not accepted, and no lease comes of it.
                    Lease.Clear();
                    Keys.Drop("check-in older than the applied revision");

                    return Reconciliation.Unverified;
                }

                if (_knownRevision is null)
                {
                    _knownRevision = response.SecurityRevision;
                }
                else if (response.SecurityRevision > _knownRevision)
                {
                    _knownRevision = response.SecurityRevision;
                    gate.Invalidate();
                    ForgetSaved();
                }

                bool trusted = response.Status == nameof(MachineStatus.Trusted) && response.HostNameBound && response.LeaseSeconds > 0;
                if (trusted)
                {
                    Lease.Issue(TimeSpan.FromSeconds(response.LeaseSeconds));
                }
                else
                {
                    // A machine that is not Trusted keeps nothing: no lease, no synchronized grant.
                    Lease.Clear();
                    _synced.Clear();
                    Keys.Drop("authority no longer trusts this machine");
                    Volatile.Write(ref _reconcileNotBefore, _monotonic.Milliseconds + 5000);
                }
            }

            return Reconciliation.Reconciled;
        }
        finally
        {
            Volatile.Write(ref _reconciling, 0);
        }
    }

    /// <summary>True when the lease is valid, after a check-in with the authority if it was not.</summary>
    private async Task<bool> EnsureLeaseAsync(CancellationToken cancel)
    {
        if (Lease.IsValid)
        {
            return true;
        }

        await ReconcileAsync(cancel);

        return Lease.IsValid;
    }

    /// <summary>
    /// Is there a grant for exactly this request (the scope key the host made from it)? Online, the authority answers (signed); a grant it names is then
    /// remembered here as synchronized. When the authority cannot be reached, only a grant remembered here counts, and only while the lease is valid and
    /// the grant's own end has not come: the lease is never longer because a grant is, and an indefinite grant does not make it indefinite.
    /// Anything that is not a verified, applicable grant is <see cref="GrantUseKind.NoGrant" />, and the request then goes through the ordinary approval.
    /// </summary>
    public async Task<GrantUse> TryUseGrantAsync(LaunchRequest launch, string scopeKey, CancellationToken cancel)
    {
        GrantUse NoGrant() => new(GrantUseKind.NoGrant, "");

        HostConfigLoad load = config.Load();
        if (load.Problem is not null || load.Config?.Authority is null || load.Config.MachineFingerprint != Fingerprint)
        {
            return NoGrant();
        }

        GrantEnvelope envelope = GrantEnvelope.Create(GrantOps.Use, launch, scopeKey, hostName, machineKey);
        GrantResponse response;
        try
        {
            response = await authority.GrantAsync(envelope, cancel);
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            if (cancel.IsCancellationRequested)
            {
                return NoGrant();
            }

            AppLog.Warn("the authority could not be asked about a grant: {Type}", error.GetType().Name);

            // Only a failed transport to a remote authority is "offline". The local authority has no network: its failure (a database or key error) is not
            // an absence, so nothing is used on the strength of an earlier answer.
            if (authority is LocalAuthority || !IsTransportFailure(error))
            {
                return new GrantUse(GrantUseKind.Denied, "the authority failed to answer about a grant (" + error.GetType().Name + "). Nothing was run");
            }

            return OfflineUse(scopeKey);
        }

        string? problem;
        string? revisionProblem = null;
        try
        {
            problem = await Verify(response, launch.RequestId, envelope.RequestDigest, cancel);
            if (problem is null && response.Operation != GrantOps.Use)
            {
                problem = "another operation";
            }

            if (problem is null)
            {
                revisionProblem = RevisionProblem(response.SecurityRevision);
            }
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            AppLog.Warn("the authority's grant answer could not be checked: {Type}", error.GetType().Name);

            return new GrantUse(GrantUseKind.Denied, "the authority's answer about a grant could not be verified. Nothing was run");
        }

        if (problem is not null)
        {
            return new GrantUse(GrantUseKind.Denied, "the authority's answer about a grant could not be verified (" + problem + "). Nothing was run");
        }

        if (revisionProblem is not null)
        {
            return new GrantUse(GrantUseKind.Denied, revisionProblem);
        }

        if (response.Outcome == GrantOps.Granted && response.GrantId.Length > 0 && response.ScopeKey == scopeKey)
        {
            if (!await EnsureLeaseAsync(cancel))
            {
                return new GrantUse(GrantUseKind.Denied, NoLeaseMessage);
            }

            lock (_lock)
            {
                _synced[scopeKey] = new SyncedGrant(response.GrantId, scopeKey, response.GrantRevision, response.Indefinite ? null : response.GrantExpires);
                SweepKey();
            }

            return new GrantUse(GrantUseKind.Granted, "", response.GrantId);
        }

        // The authority says there is none (or it ended): nothing is remembered for the scope.
        lock (_lock)
        {
            _synced.Remove(scopeKey);
            SweepKey();
        }

        return NoGrant();
    }

    private static bool IsTransportFailure(Exception error) => error is System.Net.Http.HttpRequestException or System.Net.Sockets.SocketException or TimeoutException or IOException && error is not AuthorityDatabaseException;

    /// <summary>The authority cannot be reached: a grant this host already synchronized counts only while the lease runs (monotonic clock) and the grant has not ended.</summary>
    private GrantUse OfflineUse(string scopeKey)
    {
        lock (_lock)
        {
            if (_synced.TryGetValue(scopeKey, out SyncedGrant? grant) && Lease.IsValid && (grant.Expires is null || _clock.GetUtcNow() < grant.Expires))
            {
                return new GrantUse(GrantUseKind.Granted, "", grant.GrantId, Offline: true);
            }
        }

        return new GrantUse(GrantUseKind.NoGrant, "");
    }

    /// <summary>
    /// The human approval that creates or updates the grant for this request's scope (no launch). <paramref name="present" /> shows the page; the
    /// authority calls it only when the machine may ask, and records the grant for the time chosen there. Needs the authority: while it cannot be
    /// reached nothing is approved. What the page released (the unlock material) is never used here and is zeroed.
    /// </summary>
    public async Task<GrantApproval> ApproveGrantAsync(LaunchRequest launch, string scopeKey, Func<ApprovalDecision> present, CancellationToken cancel)
    {
        GrantApproval Deny(string message, string code) => new(false, message, code, null);

        HostConfigLoad load = config.Load();
        if (load.Problem is not null)
        {
            return Deny(load.Problem, "host-config");
        }

        if (load.Config?.Authority is null || load.Config.MachineFingerprint != Fingerprint)
        {
            return Deny(Message(ReasonCodes.MachinePending), ReasonCodes.MachinePending);
        }

        ApprovalDecision? local = null;
        GrantResponse response;
        GrantEnvelope envelope = GrantEnvelope.Create(GrantOps.Approve, launch, scopeKey, hostName, machineKey);
        try
        {
            using IDisposable offered = offer(launch.RequestId, envelope.RequestDigest, () => local = present());
            response = await authority.GrantAsync(envelope, cancel);
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            local?.Unlock?.Dispose();
            AppLog.Warn("the authority did not answer a grant approval: {Type}", error.GetType().Name);

            return Deny("the authority could not be asked (" + error.GetType().Name + "); a new approval needs the authority, so nothing was saved", "authority-unavailable");
        }

        try
        {
            string? problem = await Verify(response, launch.RequestId, envelope.RequestDigest, cancel);
            if (problem is null && response.Operation != GrantOps.Approve)
            {
                problem = "another operation";
            }

            if (problem is not null)
            {
                return Deny("the authority's answer could not be verified (" + problem + "). Nothing was saved", "response-invalid");
            }

            if (RevisionProblem(response.SecurityRevision) is { } revisionProblem)
            {
                return Deny(revisionProblem, ReasonCodes.AuthorizationChanged);
            }

            if (response.Outcome == GrantOps.Granted && response.ScopeKey == scopeKey && response.GrantId.Length > 0 && local is { Approved: true })
            {
                lock (_lock)
                {
                    _synced[scopeKey] = new SyncedGrant(response.GrantId, scopeKey, response.GrantRevision, response.Indefinite ? null : response.GrantExpires);
                }

                return new GrantApproval(true, "", response.ReasonCode, response.GrantId, response.Indefinite ? null : response.GrantExpires);
            }

            if (response.ReasonCode is ReasonCodes.UserDenied or ReasonCodes.Cancelled && local is not null)
            {
                return Deny("The user did not approve (" + ApprovalSummary.Clean(local.Detail) + "). Do not retry. Ask the user.", response.ReasonCode);
            }

            return Deny(Message(response.ReasonCode), response.ReasonCode);
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            AppLog.Warn("the authority's grant answer could not be checked: {Type}", error.GetType().Name);

            return Deny("the authority's answer could not be verified (" + error.GetType().Name + "). Nothing was saved", "response-invalid");
        }
        finally
        {
            local?.Unlock?.Dispose();
        }
    }
}

/// <summary>A grant this host has synchronized: its id, scope key, the grant revision it saw, and when it ends (null: indefinite).</summary>
public sealed record SyncedGrant(string GrantId, string ScopeKey, int Revision, DateTimeOffset? Expires);

public enum GrantUseKind
{
    /// <summary>A grant applies: the request needs no approval page decision.</summary>
    Granted,

    /// <summary>No applicable grant (none, ended, other scope, or the authority cannot be reached and none is synchronized): the ordinary approval follows.</summary>
    NoGrant,

    /// <summary>The answer could not be trusted, or the machine's state changed: the request is refused with the message.</summary>
    Denied,
}

/// <summary>The answer to a grant check. <see cref="Offline" /> is true when the authority could not be reached and a synchronized grant under a valid lease was used.</summary>
public sealed record GrantUse(GrantUseKind Kind, string Message, string GrantId = "", bool Offline = false);

/// <summary>The result of an approval that makes a grant: the grant (id and end, null for indefinite) or why not (a message with no value in it).</summary>
public sealed record GrantApproval(bool Granted, string Message, string Code, string? GrantId, DateTimeOffset? Expires = null);

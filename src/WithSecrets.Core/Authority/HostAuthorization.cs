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
public sealed class HostAuthorization(IAuthority authority, ISigningKey machineKey, string hostName, HostConfigFile config, LaunchGate gate, Func<string, string, Func<ApprovalDecision>, IDisposable> offer, TimeProvider? clock = null, Action? clearSaved = null)
{
    private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(1);

    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly Lock _lock = new();
    private int? _knownRevision;
    private readonly Dictionary<string, int> _saved = [];

    public string Fingerprint { get; } = KeyIdentity.Fingerprint(machineKey.PublicKey);

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

    /// <summary>Forgets every saved approval: in this host and in the store behind <c>clearSaved</c>. Called with the lock held.</summary>
    private void ForgetSaved()
    {
        _saved.Clear();
        clearSaved?.Invoke();
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

            return new AuthorizationOutcome(local, null, response.ReasonCode, response.SecurityRevision);
        }

        local?.Unlock?.Dispose();
        if (response.ReasonCode is ReasonCodes.UserDenied or ReasonCodes.Cancelled && local is not null)
        {
            return new AuthorizationOutcome(local, null, response.ReasonCode, response.SecurityRevision);
        }

        return Deny(response.ReasonCode, Message(response.ReasonCode));
    }

    private async Task<string?> Verify(AuthorityResponse response, LaunchRequest launch, CancellationToken cancel)
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
        if (response.RequestId != launch.RequestId)
        {
            return "another request id";
        }

        if (!string.Equals(response.RequestDigest, launch.Digest(), StringComparison.Ordinal))
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

    /// <summary>Applies an invalidation the authority announced: clears the host's authorization state (pending launches are cancelled at their commit), then acknowledges it.</summary>
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
    }
}

namespace ArcanaGuardian;

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
/// signatures through the same <see cref="LocalAuthority" /> that serves local launches, (2) when a valid grant covers the request, reads what that grant rests on again, else shows the ordinary
/// approval page here with its passkey tap and records the decision exactly as a local approval is recorded, (3) decrypts only the named secrets with the store key an administrator's unlock
/// opened, inside the authority's lock, and (4) returns them as a signed <see cref="SecretsDelivery" />. Nothing decrypted outlives the call: the values are zeroed by the caller after the answer
/// is sealed. A request id is delivered at most once.
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
    private readonly ApprovalQueue? _approvals;
    private readonly Lock _gate = new();
    private readonly HashSet<CancellationTokenSource> _open = [];
    private readonly Dictionary<string, DateTimeOffset> _delivered = new(StringComparer.Ordinal);

    private sealed class NoopDisposable : IDisposable
    {
        public static readonly NoopDisposable Instance = new();
        private NoopDisposable() { }
        public void Dispose() { }
    }

    public AuthorityLaunchHandler(LocalAuthority authority, AuthorityKeyRing keys, AuthorityStore store, ISecretSource secrets, Func<Action<string>, IApprover> approver, AuthorityLock? lockState, TimeProvider? clock = null, ApprovalQueue? approvals = null)
    {
        _authority = authority;
        _keys = keys;
        _store = store;
        _secrets = secrets;
        _approver = approver;
        _lock = lockState;
        _clock = clock ?? TimeProvider.System;
        _approvals = approvals;
        lockState?.OnLock(_ => CancelAll());
    }

    /// <summary>TEST ONLY: runs once an approval from the approval page is committed durably and before it is checked for delivery, with the session's token (a test ends the session here to put the end exactly between the two).</summary>
    internal static Action<CancellationToken>? AfterApprovalCommitted { get; set; }

    /// <summary>TEST ONLY: runs once a grant was found to cover a request and before what it rests on is read again (a test changes the machine or the grant here).</summary>
    internal static Action? BeforeGrantDelivery { get; set; }

    /// <summary>TEST ONLY: runs after the last lock check of a delivery and immediately before the values are read.</summary>
    internal static Action? BeforeDecrypt { get; set; }

    /// <summary>TEST ONLY: runs with the delivery's copies of the values once they are made, before the delivery is signed and recorded.</summary>
    internal static Action<IReadOnlyList<byte[]>>? AfterDecrypt { get; set; }

    /// <summary>How many secret reads this handler made for launches (for tests and status; a count only).</summary>
    public int Decryptions => Volatile.Read(ref _decryptions);

    private int _decryptions;

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
                return ViaGrant(machine, message, grant, linked.Token, Deny);
            }

            // Every approval is a grant: what the person signs on the page names what the once-only grant records (its scope, the machine's security revision, its contents).
            List<string> onceLines = [.. page.ExtraLines ?? []];
            onceLines.AddRange(GrantEvidence.ApproveLines(machine.SecurityRevision, message.Use.ScopeKey, contents: GrantEvidence.ContentsKey(request.SecretNames, request.Program, request.WorkingDirectory)));

            return await ViaPageAsync(machine, message, page with { RequestId = message.Use.ScopeKey, ExtraLines = onceLines }, announceLink, linked.Token, Deny);
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
        Dictionary<string, string> sources = request.SecretNames.ToDictionary(name => name, _secrets.LabelFor, StringComparer.Ordinal);
        string name = string.IsNullOrWhiteSpace(machine.FriendlyName) ? machine.HostName : machine.FriendlyName!;

        return new ApprovalRequest(request.Program, context.ResolvedProgram, context.Arguments, request.WorkingDirectory, request.Reason, request.SecretNames, null, request.Arguments, context.Links, context.FingerprintKey, sources, context.Script, context.ProgramFile,
            [.. request.Mappings.Select(mapping => new SecretMapping(mapping.Variable, mapping.Secret))], request.EnvFiles, request.EnvNames, request.EnvVariables, request.InheritedEnvironment,
            Decrypts: [.. request.Encrypted.Select(item => new DecryptItem(item.Variable, item.File, item.PublicKey, DecryptItem.HashOf(item.Ciphertext)))],
            DotenvxInputDigest: request.DotenvxInputDigest,
            DotenvxDynamicNames: request.DotenvxDynamicNames,
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
        bool ownsQueueRegistration = false;
        IDisposable offer;
        try
        {
            if (_approvals is not null)
            {
                ApprovalReviewProjection review = ApprovalQueue.BuildReview(request.RequestId, request.Digest(), _clock.GetUtcNow(), request.Expires, machine, page);
                ApprovalQueueRegistration registration = _approvals.Register(review, out _);
                switch (registration)
                {
                    case ApprovalQueueRegistration.Created:
                        ownsQueueRegistration = true;
                        offer = _authority.Offer(request.RequestId, request.Digest(), () =>
                        {
                            presented = true;
                            decision = _approvals.Wait(request.RequestId, cancel);
                            return decision;
                        }, response => _approvals.MarkCommitted(request.RequestId, response));
                        break;
                    case ApprovalQueueRegistration.ExistingTerminal:
                        // The durable result already exists. Let LocalAuthority return its exact stored response without opening another page.
                        offer = NoopDisposable.Instance;
                        break;
                    case ApprovalQueueRegistration.Full:
                        offer = _authority.Offer(request.RequestId, request.Digest(),
                            () => ApprovalDecision.Deny("the authority approval queue is full", reasonCode: ReasonCodes.ApprovalQueueFull));
                        break;
                    case ApprovalQueueRegistration.ExistingPending:
                    case ApprovalQueueRegistration.Conflict:
                        return deny(ReasonCodes.RequestIdReused, machine.SecurityRevision);
                    default:
                        throw new InvalidOperationException("unknown approval queue registration result");
                }
            }
            else
            {
                offer = _authority.Offer(request.RequestId, request.Digest(), () =>
                {
                    presented = true;
                    IApprover approver = _approver(Announce(announceLink));
                    decision = approver.Request(page, cancel);
                    return decision;
                });
            }
        }
        catch (InvalidOperationException)
        {
            if (ownsQueueRegistration) _approvals?.Withdraw(request.RequestId);
            return deny(ReasonCodes.RequestIdReused, machine.SecurityRevision);
        }

        try
        {
            AuthorityResponse response;
            using (offer)
            {
                response = await _authority.DecideAsync(message.Decide, cancel);
            }

            if (response.Decision != AuthorityDecision.Approved)
            {
                return new LaunchAnswer(null, response);
            }

            // Approved, but not by a page this call showed: an earlier session's committed answer. The values were (or were not) delivered then; never again.
            if (!presented || decision is not { Approved: true })
            {
                return deny(ReasonCodes.RequestIdReused, response.SecurityRevision);
            }

            AfterApprovalCommitted?.Invoke(cancel);

            if (cancel.IsCancellationRequested)
            {
                _store.RecordDeliveryEvent(machine.Fingerprint, message.Decide.Request.RequestId, "approved-not-delivered", "the approval was given but the session ended or the launch was cancelled before any value was decrypted");
                return deny(ReasonCodes.Cancelled, response.SecurityRevision);
            }

            // The approval is recorded as a consumed once-only grant (the same checks as in local mode, against the revision the page showed) before anything is decrypted. If it cannot be, nothing is delivered.
            GrantResponse once;
            try
            {
                once = _authority.RecordOnceGrant(message.Use, decision, machine.SecurityRevision);
            }
            catch (AuthorityLockedException)
            {
                // A lock between the tap and the record: nothing is recorded or delivered, and the record says the approval was not delivered; the lock itself ends the session (see the interface).
                _store.RecordDeliveryEvent(machine.Fingerprint, request.RequestId, "approved-not-delivered", "the approval could not be recorded as a once-only grant (the authority locked)");

                throw;
            }

            if (once.Outcome != GrantOps.Recorded)
            {
                _store.RecordDeliveryEvent(machine.Fingerprint, request.RequestId, "approved-not-delivered", "the approval could not be recorded as a once-only grant (" + once.ReasonCode + ")");

                return deny(once.ReasonCode, once.SecurityRevision);
            }

            return Deliver(message, SecretsDelivery.ViaPage, "", response.SecurityRevision, deny, new AuditKeys(Key: once.Keys?.GrantApproved ?? decision.Credential));
        }
        finally
        {
            // Remove only the entry this handler created if the durable authority decision failed or the offer was withdrawn.
            if (ownsQueueRegistration) _approvals?.Withdraw(request.RequestId);
        }
    }

    private LaunchAnswer ViaGrant(MachineRecord machine, LaunchAuthorize message, GrantResponse grant, CancellationToken cancel, Func<string, int, LaunchAnswer> deny)
    {
        BeforeGrantDelivery?.Invoke();
        if (cancel.IsCancellationRequested)
        {
            return deny(ReasonCodes.Cancelled, grant.SecurityRevision);
        }

        // What the grant's decision rested on is read again now, at the authority, immediately before anything is decrypted. The machine must still be Trusted at the same security revision and the grant must be the same, active, sealed grant; otherwise nothing is decrypted.
        if (ChangedSince(machine.Fingerprint, grant))
        {
            return deny(ReasonCodes.AuthorizationChanged, grant.SecurityRevision);
        }

        return Deliver(message, SecretsDelivery.ViaGrant, grant.GrantId, grant.SecurityRevision, deny, grant.Keys);
    }

    private bool ChangedSince(string machineFingerprint, GrantResponse grant)
    {
        MachineRecord? now = _store.Find(machineFingerprint);
        GrantRecord? row = _store.FindGrant(grant.GrantId);

        return now is not { Status: MachineStatus.Trusted } || now.SecurityRevision != grant.SecurityRevision
            || row is null || !row.IsUsable(_clock.GetUtcNow()) || row.Revision != grant.GrantRevision || row.ScopeKey != grant.ScopeKey || row.Fingerprint != machineFingerprint
            || _store.Sealer is not { } sealer || sealer.Problem(row) is not null;
    }

    private LaunchAnswer Deliver(LaunchAuthorize message, string via, string grantId, int revision, Func<string, int, LaunchAnswer> deny, AuditKeys? attribution)
    {
        LaunchRequest request = message.Decide.Request;

        // A lock since the approval ends it here: nothing is decrypted (the store decrypts inside the lock as well, so a lock that begins now decrypts nothing either).
        _lock?.EnsureUnlocked();
        BeforeDecrypt?.Invoke();
        SecretValues values;
        try
        {
            Interlocked.Increment(ref _decryptions);
            values = request.SecretNames.Count == 0 ? new SecretValues(new Dictionary<string, byte[]>()) : _secrets.GetValues(request.SecretNames);
        }
        catch (Exception error) when (error is not OutOfMemoryException and not AuthorityLockedException)
        {
            AppLog.Warn("the authority could not decrypt for a launch: {Type}", error.GetType().Name);

            return deny(ReasonCodes.Internal, revision);
        }

        // The delivery's copies of the values belong to the answer once it is returned (the caller zeroes them after sealing, see AuthorityEndpoint); on any failure before that they are zeroed here.
        List<DeliveredValue> list = [];
        SecretsDelivery? delivery = null;
        bool handedOver = false;
        try
        {
            DateTimeOffset issued = _clock.GetUtcNow();
            list = [.. values.Names.Select(name => new DeliveredValue(name, [.. values.Bytes(name)]))];
            AfterDecrypt?.Invoke([.. list.Select(item => item.Value)]);
            AuditKeys audit = (attribution ?? new AuditKeys()) with { Unlock = values.OpenedBy };
            delivery = SecretsDelivery.Create(request.RequestId, request.Digest(), message.Decide.MachineFingerprint, via, grantId, revision, issued, issued + SecretsDelivery.MaxLifetime, list, _keys.Current(), audit);

            // Written before the answer can be sent: a restart cannot prepare values for this id again.
            _store.RecordDeliveryEvent(message.Decide.MachineFingerprint, request.RequestId, "delivery-prepared", via == SecretsDelivery.ViaGrant ? "by grant " + grantId : "by the approval page", audit.Key, (audit with { Key = null }).Metadata());
            handedOver = true;

            return new LaunchAnswer(delivery, null);
        }
        finally
        {
            values.Dispose();
            if (!handedOver)
            {
                delivery?.Zero();
                foreach (DeliveredValue item in list)
                {
                    SecretValues.Clear(item.Value);
                }
            }
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

    public void Dispose() => CancelAll();
}

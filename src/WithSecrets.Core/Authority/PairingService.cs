using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace WithSecrets;

/// <summary>A freshly made invitation, as the administrator is shown it once. <see cref="Bundle" /> holds the pairing code: it is handed to the admin app's answer and to nothing else, and the object never prints it.</summary>
public sealed class CreatedInvitation(string id, DateTimeOffset expires, string bundle)
{
    public string Id { get; } = id;

    public DateTimeOffset Expires { get; } = expires;

    /// <summary>The credential bundle (<see cref="PairingBundle.Format" />). Never stored, never logged, never retrievable again.</summary>
    public string Bundle { get; } = bundle;

    public override string ToString() => "invitation " + Id + " (bundle hidden)";
}

/// <summary>What the pairing route answers: a status and code for a refusal, or the (small, public) reply.</summary>
public sealed record PairingReply(int Status, string Code, string? Body)
{
    public static PairingReply Refused { get; } = new(403, "pairing-refused", null);

    public static PairingReply BadRequest { get; } = new(400, "bad-request", null);

    public static PairingReply Busy { get; } = new(429, "too-busy", null);

    public static PairingReply Ok(string body) => new(200, "", body);
}

/// <summary>
/// The authority's side of pairing (architecture 10.2): creating invitations, answering the bootstrap (an HMAC proof that the authority holds the invitation, over its identity certificate), verifying a registration (certificate profile,
/// proof of possession, registration proof) and consuming the invitation together with the Pending registration in one atomic step (<see cref="AuthorityStore.ConsumeAndRegister" />).
/// <para>
/// The pairing code is never stored. What is stored is <c>K</c> (HKDF of the code, see <see cref="PairingProtocol" />), sealed by the authority-side protection (<see cref="IUnlockProtection" />: DPAPI for this user on Windows) and
/// wiped when the invitation is used, expires, is revoked or is withdrawn. Verifying a proof needs K; nothing here can recover the code from it. Every refusal that reaches the network is the same one answer (403 pairing-refused): a wrong, expired,
/// consumed, withdrawn or unknown invitation, and a machine that may not register, cannot be told apart. The reasons are in the durable audit, which never holds a code, a proof or a key.
/// </para>
/// </summary>
public sealed class PairingService(AuthorityStore store, IUnlockProtection protection, byte[] identityCertificate, Func<string?> authorityUrl, TimeProvider? clock = null)
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly SemaphoreSlim _registrations = new(PairingProtocol.MaxConcurrentRegistrations);
    private readonly Lock _gate = new();
    private readonly Queue<DateTimeOffset> _failures = new();
    private readonly Queue<DateTimeOffset> _auditRows = new();
    private int _suppressed;

    /// <summary>At most this many audit rows of refused or ordinary attempts per minute; the rest are counted and written as one summary row.</summary>
    public const int MaxAuditRowsPerMinute = 30;

    /// <summary>The authority's identity fingerprint (what the proofs are bound to).</summary>
    public string AuthorityFingerprint { get; } = MachineCertificates.FingerprintOf(identityCertificate) ?? throw new ArgumentException("not an identity certificate", nameof(identityCertificate));

    /// <summary>For tests: called with the peer fingerprint the TLS handshake showed, on every request.</summary>
    internal Action<string>? SeenPeer { get; set; }

    /// <summary>For tests: called while a registration holds one of the concurrent slots (a test holds some to show the limit).</summary>
    internal Action? WhileRegistering { get; set; }

    // ---- creating ----

    /// <summary>Makes an invitation (the administrator's passkey tap has been verified by the caller): a random 128-bit code and a unique identifier, valid for <see cref="PairingProtocol.InvitationLifetime" />. Returns it, or why not.</summary>
    /// <summary>Why an invitation cannot be made now (no way to protect the key material, no machine endpoint), or null.</summary>
    public string? Unavailable => protection.Unavailable is { } unavailable ? "this platform cannot protect the invitation's key material: " + unavailable : authorityUrl() is null ? "this service serves no machine endpoint, so there is nowhere for a machine to pair (start it with --machine-port)" : null;

    /// <summary>The address the invitation carries (the machine endpoint), or null when there is none.</summary>
    public string? AuthorityUrl => authorityUrl();

    public (CreatedInvitation? Created, string? Problem) Create(string actor)
    {
        if (protection.Unavailable is { } unavailable)
        {
            return (null, "this platform cannot protect the invitation's key material: " + unavailable);
        }

        if (authorityUrl() is not { } url)
        {
            return (null, "this service serves no machine endpoint, so there is nowhere for a machine to pair (start it with --machine-port)");
        }

        string id = PairingProtocol.NewToken(PairingProtocol.IdBytes);
        byte[] code = RandomNumberGenerator.GetBytes(PairingProtocol.CodeBytes);
        byte[] key = PairingProtocol.DeriveKey(code, id);
        try
        {
            byte[] sealedKey = protection.Seal(key);
            DateTimeOffset expires = _clock.GetUtcNow() + PairingProtocol.InvitationLifetime;
            if (store.CreateInvitation(id, sealedKey, expires, actor, PairingProtocol.MaxOpenInvitations) is { } problem)
            {
                return (null, problem);
            }

            return (new CreatedInvitation(id, expires, PairingBundle.Create(url, id, code).Format()), null);
        }
        catch (Exception error) when (error is CryptographicException or InvalidOperationException)
        {
            return (null, "the invitation's key material could not be protected");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(code);
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public bool Revoke(string id, string actor) => store.RevokeInvitation(id, actor);

    // ---- limits and audit ----

    private bool Blocked()
    {
        lock (_gate)
        {
            DateTimeOffset now = _clock.GetUtcNow();
            while (_failures.Count > 0 && now - _failures.Peek() > PairingProtocol.FailureWindow)
            {
                _failures.Dequeue();
            }

            return _failures.Count >= PairingProtocol.MaxFailedOverall;
        }
    }

    private void Failed(string detail, string? fingerprint = null)
    {
        lock (_gate)
        {
            _failures.Enqueue(_clock.GetUtcNow());
        }

        Audit("pairing-refused", fingerprint, detail);
    }

    private void Audit(string eventName, string? fingerprint, string detail)
    {
        bool write;
        int dropped = 0;
        lock (_gate)
        {
            DateTimeOffset now = _clock.GetUtcNow();
            while (_auditRows.Count > 0 && now - _auditRows.Peek() > TimeSpan.FromMinutes(1))
            {
                _auditRows.Dequeue();
            }

            write = _auditRows.Count < MaxAuditRowsPerMinute;
            if (write)
            {
                _auditRows.Enqueue(now);
                dropped = Interlocked.Exchange(ref _suppressed, 0);
            }
            else
            {
                _suppressed++;
            }
        }

        try
        {
            if (dropped > 0)
            {
                store.RecordPairingEvent("pairing-refusals-suppressed", null, dropped + " further pairing attempt(s) were not written individually (limit " + MaxAuditRowsPerMinute + " rows a minute)");
            }

            if (write)
            {
                store.RecordPairingEvent(eventName, fingerprint, detail);
            }
        }
        catch (AuthorityDatabaseException)
        {
            AppLog.Warn("a pairing audit row could not be written");
        }
    }

    private byte[]? OpenKey(PairingInvitationRecord invitation)
    {
        try
        {
            return invitation.ProtectedKey is { } sealedKey ? protection.Open(sealedKey) : null;
        }
        catch (Exception error) when (error is CryptographicException or InvalidOperationException)
        {
            return null;
        }
    }

    // ---- the bootstrap ----

    /// <summary>First request: the invitation id and the client's nonce. Answers the authority's identity certificate, a fresh nonce and the proof, or the one refusal.</summary>
    public PairingReply Bootstrap(PairingBootstrapRequest request)
    {
        if (Blocked())
        {
            return PairingReply.Busy;
        }

        store.ExpireInvitations();
        if (store.Invitation(request.InvitationId) is not { } invitation || invitation.StatusAt(_clock.GetUtcNow()) != "pending" || OpenKey(invitation) is not { } key)
        {
            Failed("bootstrap for an invitation that is unknown, expired, used or withdrawn");

            return PairingReply.Refused;
        }

        try
        {
            byte[] serverNonce = RandomNumberGenerator.GetBytes(PairingProtocol.NonceBytes);
            byte[] proof = PairingProtocol.BootstrapProof(key, request.InvitationId, AuthorityFingerprint, request.Nonce, serverNonce);
            Audit("pairing-bootstrap", null, "invitation " + request.InvitationId[..8] + ": the authority proved itself");

            return PairingReply.Ok(PairingWire.Write(new PairingBootstrapReply(identityCertificate, serverNonce, proof)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    // ---- the registration ----

    /// <summary>
    /// Second request, on the connection pinned to this authority: verifies the certificate, the proof of possession and the registration proof, then consumes the invitation and creates (or refreshes) the Pending record in one step.
    /// <paramref name="peerFingerprint" /> is what the TLS client certificate says; <paramref name="leaf" /> is that certificate.
    /// </summary>
    public PairingReply Register(PairingRegistrationRequest request, string peerFingerprint, X509Certificate2 leaf)
    {
        if (Blocked())
        {
            return PairingReply.Busy;
        }

        if (!_registrations.Wait(0))
        {
            return PairingReply.Busy;
        }

        try
        {
            WhileRegistering?.Invoke();

            return RegisterCore(request, peerFingerprint, leaf);
        }
        finally
        {
            _registrations.Release();
        }
    }

    private PairingReply RegisterCore(PairingRegistrationRequest request, string peerFingerprint, X509Certificate2 leaf)
    {
        DateTimeOffset now = _clock.GetUtcNow();
        string digest = request.Digest();
        string shortId = request.InvitationId[..8];
        if (WireText.HostNameProblem(request.HostName) is not null || KeyIdentity.ParseHex(request.MachineFingerprint, true) != request.MachineFingerprint)
        {
            Failed("registration with an unusable host name or fingerprint", null);

            return PairingReply.BadRequest;
        }

        // A machine that asks again after a lost answer gets the original result (same invitation, fingerprint and proofs); nothing is created again.
        store.ExpireInvitations();
        PairingInvitationRecord? invitation = store.Invitation(request.InvitationId);
        if (invitation is { Status: "consumed" } && invitation.RequestDigest == digest && invitation.MachineFingerprint == request.MachineFingerprint && request.MachineFingerprint == peerFingerprint && invitation.Result is { } committed)
        {
            Audit("pairing-retry", request.MachineFingerprint, "invitation " + shortId + ": the same registration again after it was committed; the original result was returned");

            return PairingReply.Ok(PairingWire.Write(new PairingRegistrationReply(request.MachineFingerprint, committed)));
        }

        // Structure first: the identity certificate (profile, 10-year validity), that it is the key behind the fingerprint and the TLS certificate, and that this TLS certificate was signed by it.
        byte[] publicKey;
        try
        {
            if (MachineCertificates.ValidateIdentity(request.MachineCertificate, now) is { } profile)
            {
                Failed("registration whose identity certificate is not acceptable: " + profile, request.MachineFingerprint);

                return PairingReply.Refused;
            }

            using X509Certificate2 identity = X509CertificateLoader.LoadCertificate(request.MachineCertificate);
            publicKey = identity.PublicKey.ExportSubjectPublicKeyInfo();
        }
        catch (CryptographicException)
        {
            Failed("registration with an unreadable identity certificate", request.MachineFingerprint);

            return PairingReply.Refused;
        }

        if (!KeyIdentity.IsCanonicalP256(publicKey) || KeyIdentity.Fingerprint(publicKey) != request.MachineFingerprint || request.MachineFingerprint != peerFingerprint
            || MachineCertificates.ValidateLeaf(leaf, request.MachineCertificate, now, request.MachineFingerprint) is not null)
        {
            Failed("registration whose certificates do not name one machine", request.MachineFingerprint);

            return PairingReply.Refused;
        }

        if (invitation is null || invitation.StatusAt(now) != "pending" || OpenKey(invitation) is not { } key)
        {
            Failed("registration for an invitation that is unknown, expired, used or withdrawn", request.MachineFingerprint);

            return PairingReply.Refused;
        }

        try
        {
            byte[] expected = PairingProtocol.RegistrationProof(key, request.InvitationId, AuthorityFingerprint, request.MachineFingerprint, request.HostName, request.Nonce);
            if (!PairingProtocol.Same(expected, request.Proof))
            {
                store.RecordInvitationFailure(request.InvitationId, "wrong registration proof", PairingProtocol.MaxFailedPerInvitation);
                lock (_gate)
                {
                    _failures.Enqueue(now);
                }

                return PairingReply.Refused;
            }

            if (!KeyIdentity.Verify(publicKey, PairingProtocol.PossessionMessage(request.InvitationId, AuthorityFingerprint, request.MachineFingerprint, request.HostName, request.Nonce), request.Possession))
            {
                store.RecordInvitationFailure(request.InvitationId, "wrong proof of possession of the identity key", PairingProtocol.MaxFailedPerInvitation);
                lock (_gate)
                {
                    _failures.Enqueue(now);
                }

                return PairingReply.Refused;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }

        PairingConsumeResult result = store.ConsumeAndRegister(request.InvitationId, digest, publicKey, request.HostName, request.MachineCertificate, LocalAuthority.MaxPendingMachines, LocalAuthority.MaxPendingPerHostName);
        switch (result.Outcome)
        {
            case PairingOutcome.Registered:
            case PairingOutcome.Refreshed:
            case PairingOutcome.Replayed:
                return PairingReply.Ok(PairingWire.Write(new PairingRegistrationReply(request.MachineFingerprint, result.Status)));
            default:
                Failed("registration refused at the last step: " + result.Reason, request.MachineFingerprint);

                return PairingReply.Refused;
        }
    }
}

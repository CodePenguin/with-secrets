using System.Globalization;
using System.Text;
using System.Text.Json;

namespace WithSecrets;

/// <summary>What the authority decided about a request.</summary>
public enum AuthorityDecision
{
    Approved,
    Denied,
}

/// <summary>The reason codes of an <see cref="AuthorityResponse" />. Codes only: no free text and never a value.</summary>
public static class ReasonCodes
{
    public const string Approved = "approved";
    public const string UserDenied = "user-denied";
    public const string ApprovalTimeout = "approval-timeout";
    public const string Cancelled = "cancelled";
    public const string MachinePending = "machine-pending";
    public const string MachineDisabled = "machine-disabled";
    public const string MachineUntrusted = "machine-untrusted";
    public const string UnknownMachine = "unknown-machine";
    public const string HostNameMismatch = "host-name-mismatch";
    public const string BadSignature = "bad-signature";
    public const string InvalidRequest = "invalid-request";
    public const string RequestIdReused = "request-id-reused";
    public const string DigestMismatch = "digest-mismatch";
    public const string NoApprovalChannel = "no-approval-channel";
    public const string AuthorizationChanged = "authorization-changed";
    public const string Internal = "internal-error";
    public const string UnknownSecret = "unknown-secret";
    public const string ApprovalQueueFull = "approval-queue-full";
}

/// <summary>Shared text rules of the authority messages.</summary>
internal static class WireText
{
    public const string RequestDomain = "with-secrets machine request v1\n";
    public const string ResponseDomain = "with-secrets authority response v1\n";
    public const string EnrollmentDomain = "with-secrets machine enrollment v1\n";
    public const string TransitionDomain = "with-secrets authority key transition v1\n";
    public const string IdentityDomain = "with-secrets service identity v1\n";

    public static byte[] Bytes(string domain, string text) => Encoding.UTF8.GetBytes(domain + text);

    /// <summary>Null when <paramref name="name" /> may be a host name: 1 to 255 characters, no control or line characters.</summary>
    public static string? HostNameProblem(string name)
    {
        if (name.Length is 0 or > 255)
        {
            return "the host name must be 1 to 255 characters";
        }

        return name.Any(letter => char.IsControl(letter) || char.IsSurrogate(letter) || char.GetUnicodeCategory(letter) is System.Globalization.UnicodeCategory.LineSeparator or System.Globalization.UnicodeCategory.ParagraphSeparator) ? "the host name has a control character" : null;
    }
}

/// <summary>
/// A launch request as the host service sends it to its authority: the <see cref="LaunchRequest" />, the machine's fingerprint
/// and current host name, and an ECDSA P-256 signature by the machine identity key over the canonical bytes. Nothing in it is a
/// secret value. The signed text is <c>"with-secrets machine request v1" LF</c> followed by <see cref="Canonical" />.
/// </summary>
public sealed record MachineRequestEnvelope(int ProtocolVersion, string MachineFingerprint, string HostName, string RequestDigest, LaunchRequest Request, byte[] Signature)
{
    /// <summary>The canonical JSON of everything that is signed: <c>{"protocolVersion":N,"machineFingerprint":S,"hostName":S,"requestDigest":S,"request":{...}}</c>.</summary>
    public string Canonical()
    {
        StringBuilder text = new();
        text.Append("{\"protocolVersion\":").Append(ProtocolVersion.ToString(CultureInfo.InvariantCulture)).Append(",\"machineFingerprint\":");
        ToolSettings.QuoteJson(text, MachineFingerprint);
        text.Append(",\"hostName\":");
        ToolSettings.QuoteJson(text, HostName);
        text.Append(",\"requestDigest\":");
        ToolSettings.QuoteJson(text, RequestDigest);
        text.Append(",\"request\":").Append(Request.Canonical());

        return text.Append('}').ToString();
    }

    public static MachineRequestEnvelope Create(LaunchRequest request, string hostName, ISigningKey machineKey)
    {
        MachineRequestEnvelope unsigned = new(LaunchProtocol.Version, KeyIdentity.Fingerprint(machineKey.PublicKey), hostName, request.Digest(), request, []);

        return unsigned with { Signature = machineKey.Sign(WireText.Bytes(WireText.RequestDomain, unsigned.Canonical())) };
    }

    /// <summary>True when the signature is the machine's over exactly these fields, the digest is the request's, and the fingerprint is the key's.</summary>
    public bool Verify(byte[] machinePublicKey)
    {
        return ProtocolVersion == LaunchProtocol.Version
            && string.Equals(MachineFingerprint, KeyIdentity.Fingerprint(machinePublicKey), StringComparison.Ordinal)
            && string.Equals(RequestDigest, Request.Digest(), StringComparison.Ordinal)
            && KeyIdentity.Verify(machinePublicKey, WireText.Bytes(WireText.RequestDomain, Canonical()), Signature);
    }
}

/// <summary>
/// The authority's answer to a <see cref="MachineRequestEnvelope" />, signed by an authority key. It names the request (id and
/// digest) and the machine, the decision, a reason code, the machine's security revision, and when it was issued and expires. It never
/// carries a secret value. The signed text is <c>"with-secrets authority response v1" LF</c> followed by <see cref="Canonical" />;
/// <see cref="ToJson" /> is that object with the signature (base64) as a last member.
/// </summary>
public sealed record AuthorityResponse(
    int ProtocolVersion,
    string RequestId,
    string RequestDigest,
    string MachineFingerprint,
    AuthorityDecision Decision,
    string ReasonCode,
    int SecurityRevision,
    DateTimeOffset Issued,
    DateTimeOffset Expires,
    string AuthorityKeyId,
    byte[] Signature,
    AuditKeys? Keys = null) : ISignedAnswer
{
    /// <summary>The longest a response may be valid (issue to expiry); a host rejects a longer one.</summary>
    public static readonly TimeSpan MaxLifetime = TimeSpan.FromMinutes(5);

    public string Canonical()
    {
        StringBuilder text = new();
        Body(text);

        return text.Append('}').ToString();
    }

    private void Body(StringBuilder text)
    {
        text.Append("{\"protocolVersion\":").Append(ProtocolVersion.ToString(CultureInfo.InvariantCulture)).Append(",\"requestId\":");
        ToolSettings.QuoteJson(text, RequestId);
        text.Append(",\"requestDigest\":");
        ToolSettings.QuoteJson(text, RequestDigest);
        text.Append(",\"machineFingerprint\":");
        ToolSettings.QuoteJson(text, MachineFingerprint);
        text.Append(",\"decision\":");
        ToolSettings.QuoteJson(text, Decision.ToString().ToLowerInvariant());
        text.Append(",\"reasonCode\":");
        ToolSettings.QuoteJson(text, ReasonCode);
        text.Append(",\"securityRevision\":").Append(SecurityRevision.ToString(CultureInfo.InvariantCulture)).Append(",\"issued\":");
        ToolSettings.QuoteJson(text, CanonicalJson.Time(Issued));
        text.Append(",\"expires\":");
        ToolSettings.QuoteJson(text, CanonicalJson.Time(Expires));
        text.Append(",\"authorityKeyId\":");
        ToolSettings.QuoteJson(text, AuthorityKeyId);
        if (Keys is { } keys)
        {
            text.Append(",\"auditKeys\":");
            ToolSettings.QuoteJson(text, keys.Wire());
        }
    }

    /// <summary>The object with its signature, as stored and sent.</summary>
    public string ToJson()
    {
        StringBuilder text = new();
        Body(text);
        text.Append(",\"signature\":");
        ToolSettings.QuoteJson(text, Convert.ToBase64String(Signature));

        return text.Append('}').ToString();
    }

    public static AuthorityResponse Create(string requestId, string requestDigest, string machineFingerprint, AuthorityDecision decision, string reasonCode, int revision, DateTimeOffset issued, DateTimeOffset expires, ISigningKey key, AuditKeys? keys = null)
    {
        AuthorityResponse unsigned = new(LaunchProtocol.Version, requestId, requestDigest, machineFingerprint, decision, reasonCode, revision, issued, expires, KeyIdentity.Fingerprint(key.PublicKey), [], keys);

        return unsigned with { Signature = key.Sign(WireText.Bytes(WireText.ResponseDomain, unsigned.Canonical())) };
    }

    /// <summary>True when <paramref name="authorityPublicKey" /> signed exactly these fields and names itself as the signer.</summary>
    public bool Verify(byte[] authorityPublicKey)
    {
        return string.Equals(AuthorityKeyId, KeyIdentity.Fingerprint(authorityPublicKey), StringComparison.Ordinal)
            && KeyIdentity.Verify(authorityPublicKey, WireText.Bytes(WireText.ResponseDomain, Canonical()), Signature);
    }

    /// <summary>Reads a response, strictly (every member, none unknown or repeated, each of its type). The protocol version is judged by the verifier.</summary>
    public static bool TryParse(string json, out AuthorityResponse? response, out string? error)
    {
        response = null;
        if (!CanonicalJson.Open(json, out JsonDocument? doc, out error))
        {
            return false;
        }

        using (doc)
        {
            JsonElement root = doc!.RootElement;
            string[] fields = ["protocolVersion", "requestId", "requestDigest", "machineFingerprint", "decision", "reasonCode", "securityRevision", "issued", "expires", "authorityKeyId", "signature"];
            bool hasAuditKeys = root.ValueKind == JsonValueKind.Object && root.TryGetProperty("auditKeys", out _);
            ContractReader reader = new(root, hasAuditKeys ? [.. fields, "auditKeys"] : fields);
            if (reader.Problem is not null || !reader.Int("protocolVersion", out int version) || !reader.Text("requestId", out string? id) || !reader.Text("requestDigest", out string? digest)
                || !reader.Text("machineFingerprint", out string? machine) || !reader.Text("decision", out string? decisionName) || !reader.Text("reasonCode", out string? reason)
                || !reader.Int("securityRevision", out int revision) || !reader.Time("issued", out DateTimeOffset issued) || !reader.Time("expires", out DateTimeOffset expires)
                || !reader.Text("authorityKeyId", out string? keyId) || !reader.Text("signature", out string? signature))
            {
                error = reader.Problem;

                return false;
            }

            if (!Enum.TryParse(decisionName, true, out AuthorityDecision decision) || !Enum.IsDefined(decision) || decisionName != decisionName!.ToLowerInvariant())
            {
                error = "unknown decision";

                return false;
            }

            byte[] bytes = new byte[64];
            if (!Convert.TryFromBase64String(signature!, bytes, out int written) || written != 64)
            {
                error = "the signature is not 64 bytes of base64";

                return false;
            }

            AuditKeys? keys = null;
            if (hasAuditKeys && (!reader.Text("auditKeys", out string? text) || !AuditKeys.TryRead(text, out keys) || keys is null))
            {
                error = reader.Problem ?? "invalid audit keys";

                return false;
            }

            error = null;
            response = new AuthorityResponse(version, id!, digest!, machine!, decision, reason!, revision, issued, expires, keyId!, bytes, keys);

            return true;
        }
    }
}

/// <summary>First contact of a machine: its public key, fingerprint and host name, and a signature over the authority's challenge (proof of possession).</summary>
public sealed record EnrollmentRequest(string Fingerprint, byte[] PublicKey, string HostName, byte[] Challenge, byte[] Signature, byte[]? IdentityCertificate = null)
{
    /// <summary>The request, signed with the machine key. With <paramref name="identityCertificate" /> (the machine's self-signed identity certificate, public data) the signature covers its hash too.</summary>
    public static EnrollmentRequest Create(string hostName, byte[] challenge, ISigningKey machineKey, byte[]? identityCertificate = null)
    {
        byte[] publicKey = machineKey.PublicKey;
        string fingerprint = KeyIdentity.Fingerprint(publicKey);
        EnrollmentRequest unsigned = new(fingerprint, publicKey, hostName, challenge, [], identityCertificate);

        return unsigned with { Signature = machineKey.Sign(unsigned.SigningBytes()) };
    }

    internal byte[] SigningBytes() => WireText.Bytes(WireText.EnrollmentDomain, Fingerprint + "\n" + HostName + "\n" + Convert.ToBase64String(Challenge) + (IdentityCertificate is null ? "" : "\n" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(IdentityCertificate))));
}

/// <summary>What the authority says about an enrolling machine: a code and the status it has (Pending for a new one).</summary>
public sealed record EnrollmentResult(bool Accepted, MachineStatus Status, string Fingerprint, string Message);

/// <summary>
/// A routine authority key change: the new public key, signed by the key it replaces. A host that pinned the old key accepts the
/// new one only through this message.
/// </summary>
public sealed record KeyTransition(string OldFingerprint, string NewFingerprint, byte[] NewPublicKey, DateTimeOffset Created, byte[] Signature)
{
    internal byte[] SigningBytes() => WireText.Bytes(WireText.TransitionDomain, OldFingerprint + "\n" + NewFingerprint + "\n" + Convert.ToBase64String(NewPublicKey) + "\n" + CanonicalJson.Time(Created));

    public static KeyTransition Create(ISigningKey oldKey, byte[] newPublicKey, DateTimeOffset created)
    {
        KeyTransition unsigned = new(KeyIdentity.Fingerprint(oldKey.PublicKey), KeyIdentity.Fingerprint(newPublicKey), newPublicKey, created, []);

        return unsigned with { Signature = oldKey.Sign(unsigned.SigningBytes()) };
    }

    /// <summary>True when the old key (the pinned one) signed this change to a canonical new key whose fingerprint is the named one.</summary>
    public bool Verify(byte[] oldPublicKey)
    {
        return string.Equals(OldFingerprint, KeyIdentity.Fingerprint(oldPublicKey), StringComparison.Ordinal)
            && string.Equals(NewFingerprint, KeyIdentity.Fingerprint(NewPublicKey), StringComparison.Ordinal)
            && KeyIdentity.IsCanonicalP256(NewPublicKey)
            && KeyIdentity.Verify(oldPublicKey, SigningBytes(), Signature);
    }
}

/// <summary>A notification that a machine's security revision went up. A notification, not the source of truth: the revision in a response is.</summary>
public sealed record PendingInvalidation(string Fingerprint, int Revision);

/// <summary>
/// The authority, as the host service uses it. The local authority (<see cref="LocalAuthority" />) and the remote one of a later
/// phase implement the same contract. Nothing here carries a secret value.
/// </summary>
public interface IAuthority
{
    /// <summary>Decides one request: checks the machine's signature, status and host name, gets the person's approval for exactly this request, and answers with a signed response. A retry of the same request id returns the committed answer.</summary>
    Task<AuthorityResponse> DecideAsync(MachineRequestEnvelope envelope, CancellationToken cancel = default);

    /// <summary>A fresh single-use challenge for <see cref="EnrollAsync" />.</summary>
    Task<byte[]> BeginEnrollmentAsync(CancellationToken cancel = default);

    /// <summary>First contact: records the machine as Pending (or reports the status it already has) after it proved it holds the private key.</summary>
    Task<EnrollmentResult> EnrollAsync(EnrollmentRequest request, CancellationToken cancel = default);

    /// <summary>The signed key changes from the key whose fingerprint is <paramref name="afterKeyFingerprint" /> to the current one, in order.</summary>
    Task<IReadOnlyList<KeyTransition>> KeyTransitionsAsync(string afterKeyFingerprint, CancellationToken cancel = default);

    /// <summary>Invalidations for the machine that it has not acknowledged yet, oldest first.</summary>
    Task<IReadOnlyList<PendingInvalidation>> PendingInvalidationsAsync(string machineFingerprint, CancellationToken cancel = default);

    /// <summary>The machine has cleaned up for this revision (pending work cancelled, cache and grants cleared).</summary>
    Task AcknowledgeInvalidationAsync(string machineFingerprint, int revision, CancellationToken cancel = default);

    /// <summary>Asks about a grant for a request (use) or gets one made by the person's approval (approve). Idempotent by request id; the answer is signed.</summary>
    Task<GrantResponse> GrantAsync(GrantEnvelope envelope, CancellationToken cancel = default);

    /// <summary>A machine's check-in: its status, host name binding, security revision. Signed.</summary>
    Task<ReconcileResponse> ReconcileAsync(ReconcileEnvelope envelope, CancellationToken cancel = default);

    /// <summary>Grant revocations for the machine that it has not acknowledged yet, oldest first.</summary>
    Task<IReadOnlyList<PendingGrantEvent>> PendingGrantEventsAsync(string machineFingerprint, CancellationToken cancel = default);

    /// <summary>The machine has dropped the grant and cancelled the pending work that used it.</summary>
    Task AcknowledgeGrantEventAsync(string machineFingerprint, long sequence, CancellationToken cancel = default);
}

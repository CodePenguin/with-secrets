using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WithSecrets;

/// <summary>The fields every signed answer of the authority carries, so that the host verifies them in one place.</summary>
public interface ISignedAnswer
{
    int ProtocolVersion { get; }

    string RequestId { get; }

    string RequestDigest { get; }

    string MachineFingerprint { get; }

    DateTimeOffset Issued { get; }

    DateTimeOffset Expires { get; }

    string AuthorityKeyId { get; }

    bool Verify(byte[] authorityPublicKey);
}

/// <summary>The operations on a grant, and the outcomes a <see cref="GrantResponse" /> reports. Words, never free text.</summary>
public static class GrantOps
{
    /// <summary>The host asks whether a grant applies to this request.</summary>
    public const string Use = "use";

    /// <summary>The human approval (the page) that creates or updates a grant for a scope.</summary>
    public const string Approve = "approve";

    public const string Extend = "extend";
    public const string Renew = "renew";
    public const string Revoke = "revoke";

    public const string Granted = "granted";
    public const string None = "none";
    public const string Denied = "denied";
    public const string Extended = "extended";
    public const string Renewed = "renewed";
    public const string Revoked = "revoked";

    /// <summary>A scope key is the upper-case hex SHA-256 the host made from the request it approved (see <see cref="RequestFingerprint" />).</summary>
    public static bool IsScopeKey(string text) => text.Length == 64 && text.All(letter => letter is >= '0' and <= '9' or >= 'A' and <= 'F');
}

/// <summary>Reason codes that only grants use (see also <see cref="ReasonCodes" />).</summary>
public static class GrantReasons
{
    public const string NoGrant = "no-grant";
    public const string BadScope = "bad-scope";
    public const string NoTime = "no-time-chosen";
    public const string NotFound = "grant-not-found";
    public const string NotActive = "grant-not-active";
    public const string NotExpired = "grant-not-expired";
    public const string Expired = "grant-expired";
    public const string RevisionChanged = "grant-changed";
    public const string BadOperation = "bad-operation";
    public const string NoEvidence = "no-evidence";
    public const string BadEvidence = "bad-evidence";
    public const string Ok = "ok";
}

/// <summary>
/// A grant request as the host service sends it to its authority, signed by the machine identity key: the operation (use or
/// approve), the launch request (so the authority can show and record what the grant is for), the machine's fingerprint and host
/// name, and the scope key the host made from the request it validated. The authority cannot recompute the scope key (it does not
/// see the script files); it stores it and compares it for equality. Nothing here is a secret value.
/// </summary>
public sealed record GrantEnvelope(int ProtocolVersion, string Operation, string MachineFingerprint, string HostName, string RequestDigest, string ScopeKey, LaunchRequest Request, byte[] Signature)
{
    public const string Domain = "with-secrets grant request v1\n";

    public string Canonical()
    {
        StringBuilder text = new();
        text.Append("{\"protocolVersion\":").Append(ProtocolVersion.ToString(CultureInfo.InvariantCulture)).Append(",\"operation\":");
        ToolSettings.QuoteJson(text, Operation);
        text.Append(",\"machineFingerprint\":");
        ToolSettings.QuoteJson(text, MachineFingerprint);
        text.Append(",\"hostName\":");
        ToolSettings.QuoteJson(text, HostName);
        text.Append(",\"requestDigest\":");
        ToolSettings.QuoteJson(text, RequestDigest);
        text.Append(",\"scopeKey\":");
        ToolSettings.QuoteJson(text, ScopeKey);
        text.Append(",\"request\":").Append(Request.Canonical());

        return text.Append('}').ToString();
    }

    public static GrantEnvelope Create(string operation, LaunchRequest request, string scopeKey, string hostName, ISigningKey machineKey)
    {
        GrantEnvelope unsigned = new(LaunchProtocol.Version, operation, KeyIdentity.Fingerprint(machineKey.PublicKey), hostName, request.Digest(), scopeKey, request, []);

        return unsigned with { Signature = machineKey.Sign(WireText.Bytes(Domain, unsigned.Canonical())) };
    }

    /// <summary>True when the signature is the machine's over exactly these fields, the digest is the request's, and the fingerprint is the key's.</summary>
    public bool Verify(byte[] machinePublicKey)
    {
        return ProtocolVersion == LaunchProtocol.Version
            && string.Equals(MachineFingerprint, KeyIdentity.Fingerprint(machinePublicKey), StringComparison.Ordinal)
            && string.Equals(RequestDigest, Request.Digest(), StringComparison.Ordinal)
            && KeyIdentity.Verify(machinePublicKey, WireText.Bytes(Domain, Canonical()), Signature);
    }
}

/// <summary>
/// The authority's signed answer about a grant: what was asked (<see cref="Operation" />), the outcome and a reason code, the grant
/// (id, scope key, revision of the grant, and when it ends: a time, <see cref="Indefinite" />, or none), the machine's security
/// revision, and how long the answer is valid. Never a secret value.
/// </summary>
public sealed record GrantResponse(
    int ProtocolVersion,
    string RequestId,
    string RequestDigest,
    string MachineFingerprint,
    string Operation,
    string Outcome,
    string ReasonCode,
    string GrantId,
    string ScopeKey,
    int GrantRevision,
    bool Indefinite,
    DateTimeOffset? GrantExpires,
    int SecurityRevision,
    DateTimeOffset Issued,
    DateTimeOffset Expires,
    string AuthorityKeyId,
    byte[] Signature) : ISignedAnswer
{
    public const string Domain = "with-secrets grant response v1\n";

    /// <summary>True when the outcome gives (or changes) a grant that exists.</summary>
    public bool HasGrant => Outcome is GrantOps.Granted or GrantOps.Extended or GrantOps.Renewed;

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
        text.Append(",\"operation\":");
        ToolSettings.QuoteJson(text, Operation);
        text.Append(",\"outcome\":");
        ToolSettings.QuoteJson(text, Outcome);
        text.Append(",\"reasonCode\":");
        ToolSettings.QuoteJson(text, ReasonCode);
        text.Append(",\"grantId\":");
        ToolSettings.QuoteJson(text, GrantId);
        text.Append(",\"scopeKey\":");
        ToolSettings.QuoteJson(text, ScopeKey);
        text.Append(",\"grantRevision\":").Append(GrantRevision.ToString(CultureInfo.InvariantCulture)).Append(",\"grantExpires\":");
        ToolSettings.QuoteJson(text, Indefinite ? "indefinite" : GrantExpires is { } at ? CanonicalJson.Time(at) : "");
        text.Append(",\"securityRevision\":").Append(SecurityRevision.ToString(CultureInfo.InvariantCulture)).Append(",\"issued\":");
        ToolSettings.QuoteJson(text, CanonicalJson.Time(Issued));
        text.Append(",\"expires\":");
        ToolSettings.QuoteJson(text, CanonicalJson.Time(Expires));
        text.Append(",\"authorityKeyId\":");
        ToolSettings.QuoteJson(text, AuthorityKeyId);
    }

    public string ToJson()
    {
        StringBuilder text = new();
        Body(text);
        text.Append(",\"signature\":");
        ToolSettings.QuoteJson(text, Convert.ToBase64String(Signature));

        return text.Append('}').ToString();
    }

    public static GrantResponse Create(string requestId, string requestDigest, string machineFingerprint, string operation, string outcome, string reasonCode, GrantInfo? grant, int securityRevision, DateTimeOffset issued, DateTimeOffset expires, ISigningKey key)
    {
        GrantResponse unsigned = new(LaunchProtocol.Version, requestId, requestDigest, machineFingerprint, operation, outcome, reasonCode, grant?.Id ?? "", grant?.ScopeKey ?? "", grant?.Revision ?? 0,
            grant is { Expires: null }, grant?.Expires, securityRevision, issued, expires, KeyIdentity.Fingerprint(key.PublicKey), []);

        return unsigned with { Signature = key.Sign(WireText.Bytes(Domain, unsigned.Canonical())) };
    }

    public bool Verify(byte[] authorityPublicKey)
    {
        return string.Equals(AuthorityKeyId, KeyIdentity.Fingerprint(authorityPublicKey), StringComparison.Ordinal)
            && KeyIdentity.Verify(authorityPublicKey, WireText.Bytes(Domain, Canonical()), Signature);
    }

    /// <summary>Reads a response, strictly. The protocol version is judged by the verifier.</summary>
    public static bool TryParse(string json, out GrantResponse? response, out string? error)
    {
        response = null;
        if (!CanonicalJson.Open(json, out JsonDocument? doc, out error))
        {
            return false;
        }

        using (doc)
        {
            ContractReader reader = new(doc!.RootElement, "protocolVersion", "requestId", "requestDigest", "machineFingerprint", "operation", "outcome", "reasonCode", "grantId", "scopeKey", "grantRevision", "grantExpires", "securityRevision", "issued", "expires", "authorityKeyId", "signature");
            if (reader.Problem is not null || !reader.Int("protocolVersion", out int version) || !reader.Text("requestId", out string? id) || !reader.Text("requestDigest", out string? digest)
                || !reader.Text("machineFingerprint", out string? machine) || !reader.Text("operation", out string? operation) || !reader.Text("outcome", out string? outcome) || !reader.Text("reasonCode", out string? reason)
                || !reader.Text("grantId", out string? grantId) || !reader.Text("scopeKey", out string? scope) || !reader.Int("grantRevision", out int grantRevision) || !reader.Text("grantExpires", out string? ends)
                || !reader.Int("securityRevision", out int revision) || !reader.Time("issued", out DateTimeOffset issued) || !reader.Time("expires", out DateTimeOffset expires)
                || !reader.Text("authorityKeyId", out string? keyId) || !reader.Text("signature", out string? signature))
            {
                error = reader.Problem;

                return false;
            }

            bool indefinite = ends == "indefinite";
            DateTimeOffset? grantExpires = null;
            if (!indefinite && ends!.Length > 0)
            {
                if (!DateTimeOffset.TryParseExact(ends, "O", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTimeOffset parsed))
                {
                    error = "grantExpires is not a time";

                    return false;
                }

                grantExpires = parsed;
            }

            byte[] bytes = new byte[64];
            if (!Convert.TryFromBase64String(signature!, bytes, out int written) || written != 64)
            {
                error = "the signature is not 64 bytes of base64";

                return false;
            }

            error = null;
            response = new GrantResponse(version, id!, digest!, machine!, operation!, outcome!, reason!, grantId!, scope!, grantRevision, indefinite, grantExpires, revision, issued, expires, keyId!, bytes);

            return true;
        }
    }
}

/// <summary>What the host needs to know about a grant: its id, scope key and revision, and when it ends (null: indefinite).</summary>
public sealed record GrantInfo(string Id, string ScopeKey, int Revision, DateTimeOffset? Expires);

/// <summary>A grant as the authority stores it. <see cref="Status"/> is active, revoked or invalidated; <see cref="Expires"/> null is an indefinite grant.</summary>
public sealed record GrantRecord(string Id, string Fingerprint, string ScopeKey, string Program, string WorkingDirectory, string SecretNames, DateTimeOffset Created, DateTimeOffset Updated, DateTimeOffset? Expires, int Revision, int SecurityRevision, string Status, string ApprovedBy, DateTimeOffset? Revoked, StoredEvidence? Evidence = null)
{
    public bool IsExpired(DateTimeOffset now) => Expires is { } at && now >= at;

    /// <summary>Active and not past its end.</summary>
    public bool IsUsable(DateTimeOffset now) => Status == "active" && !IsExpired(now);

    public GrantInfo Info => new(Id, ScopeKey, Revision, Expires);
}

/// <summary>A notification that a grant was revoked, for the machine it belongs to. The source of truth is the answer to a use request; this lets a connected host stop at once.</summary>
public sealed record PendingGrantEvent(long Sequence, string Fingerprint, string GrantId, string ScopeKey, string Kind, int GrantRevision);

/// <summary>
/// An administrator's change to a grant (extend, renew, revoke), made in the authority after the admin passkey approved the page.
/// <see cref="RequestId" /> makes a retry return the committed answer. <see cref="ExpectedRevision" /> is the grant revision the page showed.
/// <see cref="NewEnd" /> is the absolute end the page showed (extend, renew; null for indefinite or revoke) and <see cref="Evidence" /> the admin passkey's assertion over that page: the authority applies the change only if the evidence verifies and says exactly this.
/// </summary>
public sealed record GrantAdminCommand(string RequestId, string Operation, string GrantId, int? Minutes, bool Indefinite, int? ExpectedRevision, string Actor, DateTimeOffset? NewEnd = null, ApprovalEvidence? Evidence = null)
{
    /// <summary>The digest of what is asked, so a request id cannot be reused for another change.</summary>
    public string Digest()
    {
        string text = string.Join('\n', "with-secrets grant admin v1", Operation, GrantId, Minutes?.ToString(CultureInfo.InvariantCulture) ?? "", Indefinite ? "indefinite" : "", ExpectedRevision?.ToString(CultureInfo.InvariantCulture) ?? "", NewEnd is { } end ? CanonicalJson.Time(end) : "");

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
    }
}

/// <summary>A host's check-in with its authority (startup, reconnect, after a change), signed by the machine key. Carries no request content.</summary>
public sealed record ReconcileEnvelope(int ProtocolVersion, string RequestId, string MachineFingerprint, string HostName, DateTimeOffset Created, byte[] Signature)
{
    public const string Domain = "with-secrets reconcile request v1\n";

    public string Canonical()
    {
        StringBuilder text = new();
        text.Append("{\"protocolVersion\":").Append(ProtocolVersion.ToString(CultureInfo.InvariantCulture)).Append(",\"requestId\":");
        ToolSettings.QuoteJson(text, RequestId);
        text.Append(",\"machineFingerprint\":");
        ToolSettings.QuoteJson(text, MachineFingerprint);
        text.Append(",\"hostName\":");
        ToolSettings.QuoteJson(text, HostName);
        text.Append(",\"created\":");
        ToolSettings.QuoteJson(text, CanonicalJson.Time(Created));

        return text.Append('}').ToString();
    }

    public string Digest() => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Canonical())));

    public static ReconcileEnvelope Create(string requestId, string hostName, DateTimeOffset created, ISigningKey machineKey)
    {
        ReconcileEnvelope unsigned = new(LaunchProtocol.Version, requestId, KeyIdentity.Fingerprint(machineKey.PublicKey), hostName, created, []);

        return unsigned with { Signature = machineKey.Sign(WireText.Bytes(Domain, unsigned.Canonical())) };
    }

    public bool Verify(byte[] machinePublicKey)
    {
        return ProtocolVersion == LaunchProtocol.Version
            && string.Equals(MachineFingerprint, KeyIdentity.Fingerprint(machinePublicKey), StringComparison.Ordinal)
            && KeyIdentity.Verify(machinePublicKey, WireText.Bytes(Domain, Canonical()), Signature);
    }
}

/// <summary>
/// The authority's signed answer to a <see cref="ReconcileEnvelope" />: the machine's status, whether the host name is the bound one
/// and the security revision. A host is vouched for only while its last check-in said Trusted and bound; there is no lease that lets it go on without the authority.
/// </summary>
public sealed record ReconcileResponse(int ProtocolVersion, string RequestId, string RequestDigest, string MachineFingerprint, string Status, bool HostNameBound, int SecurityRevision, DateTimeOffset Issued, DateTimeOffset Expires, string AuthorityKeyId, byte[] Signature) : ISignedAnswer
{
    public const string Domain = "with-secrets reconcile response v1\n";

    public string Canonical()
    {
        StringBuilder text = new();
        text.Append("{\"protocolVersion\":").Append(ProtocolVersion.ToString(CultureInfo.InvariantCulture)).Append(",\"requestId\":");
        ToolSettings.QuoteJson(text, RequestId);
        text.Append(",\"requestDigest\":");
        ToolSettings.QuoteJson(text, RequestDigest);
        text.Append(",\"machineFingerprint\":");
        ToolSettings.QuoteJson(text, MachineFingerprint);
        text.Append(",\"status\":");
        ToolSettings.QuoteJson(text, Status);
        text.Append(",\"hostName\":");
        ToolSettings.QuoteJson(text, HostNameBound ? "bound" : "mismatch");
        text.Append(",\"securityRevision\":").Append(SecurityRevision.ToString(CultureInfo.InvariantCulture)).Append(",\"issued\":");
        ToolSettings.QuoteJson(text, CanonicalJson.Time(Issued));
        text.Append(",\"expires\":");
        ToolSettings.QuoteJson(text, CanonicalJson.Time(Expires));
        text.Append(",\"authorityKeyId\":");
        ToolSettings.QuoteJson(text, AuthorityKeyId);

        return text.Append('}').ToString();
    }

    public static ReconcileResponse Create(string requestId, string requestDigest, string machineFingerprint, string status, bool hostNameBound, int securityRevision, DateTimeOffset issued, DateTimeOffset expires, ISigningKey key)
    {
        ReconcileResponse unsigned = new(LaunchProtocol.Version, requestId, requestDigest, machineFingerprint, status, hostNameBound, securityRevision, issued, expires, KeyIdentity.Fingerprint(key.PublicKey), []);

        return unsigned with { Signature = key.Sign(WireText.Bytes(Domain, unsigned.Canonical())) };
    }

    public bool Verify(byte[] authorityPublicKey)
    {
        return string.Equals(AuthorityKeyId, KeyIdentity.Fingerprint(authorityPublicKey), StringComparison.Ordinal)
            && KeyIdentity.Verify(authorityPublicKey, WireText.Bytes(Domain, Canonical()), Signature);
    }
}

/// <summary>A clock for short back-off waits: milliseconds that only go forward and do not change when the system date or time is changed.</summary>
public interface IMonotonicClock
{
    long Milliseconds { get; }
}

/// <summary>The system's monotonic clock (a stopwatch, not the wall clock).</summary>
public sealed class SystemMonotonicClock : IMonotonicClock
{
    public static SystemMonotonicClock Instance { get; } = new();

    public long Milliseconds => (long)(System.Diagnostics.Stopwatch.GetTimestamp() * 1000.0 / System.Diagnostics.Stopwatch.Frequency);
}

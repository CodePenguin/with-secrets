using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WithSecrets;

/// <summary>
/// What only the host's own file system knows and the approval page must show: the resolved program, the expanded arguments, the files that will be read as code (their text and
/// hash as the host read them), the symbolic-link notes, and the request fingerprint the host made from them. The authority cannot recompute any of it (it does not see the host's
/// files); the machine key signs it together with the request digest and the scope key, so the page the authority shows is made of what an enrolled, trusted machine vouched for. Nothing
/// here is a secret value.
/// </summary>
public sealed record PageContext(string ResolvedProgram, IReadOnlyList<string> Arguments, IReadOnlyList<string> Links, ScriptView? Script, ScriptView? ProgramFile, string FingerprintKey)
{
    public const int MaxLinks = 64;

    /// <summary>The canonical text that is signed and sent.</summary>
    public string Canonical()
    {
        StringBuilder text = new("{\"resolvedProgram\":");
        ToolSettings.QuoteJson(text, ResolvedProgram);
        text.Append(",\"arguments\":");
        CanonicalJson.Strings(text, Arguments);
        text.Append(",\"links\":");
        CanonicalJson.Strings(text, Links);
        text.Append(",\"scripts\":[");
        AppendView(text, Script);
        text.Append("],\"programFiles\":[");
        AppendView(text, ProgramFile);
        text.Append("],\"fingerprintKey\":");
        ToolSettings.QuoteJson(text, FingerprintKey);

        return text.Append('}').ToString();
    }

    private static void AppendView(StringBuilder text, ScriptView? view)
    {
        if (view is null)
        {
            return;
        }

        text.Append("{\"sha256\":");
        ToolSettings.QuoteJson(text, view.Sha256);
        text.Append(",\"length\":").Append(view.Length.ToString(CultureInfo.InvariantCulture)).Append(",\"hasText\":").Append(view.Text is null ? "false" : "true").Append(",\"text\":");
        ToolSettings.QuoteJson(text, view.Text ?? "");
        text.Append(",\"path\":");
        ToolSettings.QuoteJson(text, view.Path);
        text.Append(",\"guessed\":").Append(view.Guessed ? "true" : "false").Append(",\"bom\":").Append(view.Bom ? "true" : "false").Append(",\"nonAscii\":").Append(view.NonAscii ? "true" : "false").Append('}');
    }

    public static bool TryRead(JsonElement element, out PageContext? context)
    {
        context = null;
        ContractReader reader = new(element, "resolvedProgram", "arguments", "links", "scripts", "programFiles", "fingerprintKey");
        if (reader.Problem is not null || !reader.Text("resolvedProgram", out string? resolved) || !reader.Strings("arguments", out List<string>? arguments) || !reader.Strings("links", out List<string>? links) || links!.Count > MaxLinks
            || !reader.Array("scripts", out JsonElement scripts) || !reader.Array("programFiles", out JsonElement programFiles) || !reader.Text("fingerprintKey", out string? key) || !GrantOps.IsScopeKey(key!)
            || !ReadViews(scripts, out ScriptView? script) || !ReadViews(programFiles, out ScriptView? programFile))
        {
            return false;
        }

        context = new PageContext(resolved!, arguments!, links, script, programFile, key!);

        return true;
    }

    private static bool ReadViews(JsonElement array, out ScriptView? view)
    {
        view = null;
        int count = array.GetArrayLength();
        if (count > 1)
        {
            return false;
        }

        if (count == 0)
        {
            return true;
        }

        ContractReader reader = new(array[0], "sha256", "length", "hasText", "text", "path", "guessed", "bom", "nonAscii");
        if (reader.Problem is not null || !reader.Text("sha256", out string? hash) || !reader.Long("length", out long length) || !reader.Bool("hasText", out bool hasText) || !reader.Text("text", out string? text) || !reader.Text("path", out string? path)
            || !reader.Bool("guessed", out bool guessed) || !reader.Bool("bom", out bool bom) || !reader.Bool("nonAscii", out bool nonAscii) || length < 0 || hash!.Length != 64)
        {
            return false;
        }

        view = new ScriptView(hash, length, hasText ? text : null, path!, guessed, bom, nonAscii);

        return true;
    }
}

/// <summary>
/// The host's one message to start a launch at a remote authority: the ordinary machine-signed decision envelope and the machine-signed grant-use envelope (both exactly the existing
/// contracts, so the authority's existing checks, records and idempotency apply unchanged) plus the <see cref="PageContext" /> with its own machine signature. The authority approves
/// (a grant, or the page and the passkey tap), decrypts at its own side and answers with <see cref="LaunchAnswer" />. Nothing here is a secret value.
/// </summary>
public sealed record LaunchAuthorize(MachineRequestEnvelope Decide, GrantEnvelope Use, PageContext Context, byte[] ContextSignature)
{
    public const string ContextDomain = "with-secrets page context v1\n";

    private static string SignedText(string digest, string scopeKey, string hostName, PageContext context) => digest + "\n" + scopeKey + "\n" + hostName + "\n" + context.Canonical();

    public static LaunchAuthorize Create(LaunchRequest request, string scopeKey, PageContext context, string hostName, ISigningKey machineKey)
    {
        MachineRequestEnvelope decide = MachineRequestEnvelope.Create(request, hostName, machineKey);
        GrantEnvelope use = GrantEnvelope.Create(GrantOps.Use, request, scopeKey, hostName, machineKey);

        return new LaunchAuthorize(decide, use, context, machineKey.Sign(Encoding.UTF8.GetBytes(ContextDomain + SignedText(request.Digest(), scopeKey, hostName, context))));
    }

    /// <summary>True when both envelopes are for the same request, machine and host name, the use envelope is a use, and the machine signed the context for exactly this request and scope.</summary>
    public bool Verify(byte[] machinePublicKey)
    {
        return Decide.Request.Digest() == Use.RequestDigest
            && Decide.MachineFingerprint == Use.MachineFingerprint
            && Decide.HostName == Use.HostName
            && Use.Operation == GrantOps.Use
            && Decide.Verify(machinePublicKey)
            && Use.Verify(machinePublicKey)
            && KeyIdentity.Verify(machinePublicKey, Encoding.UTF8.GetBytes(ContextDomain + SignedText(Use.RequestDigest, Use.ScopeKey, Use.HostName, Context)), ContextSignature);
    }
}

/// <summary>One secret handed to the host: its name and its value's bytes (the receiver zeroes them).</summary>
public sealed record DeliveredValue(string Name, byte[] Value);

/// <summary>
/// The decrypted values of an approved launch, signed by the authority and sent only inside the end-to-end encrypted session. It is bound to the request id, the request digest, the machine,
/// the machine's security revision and how it was authorized (the page, or a grant), and valid for a short time; each value is covered by a salted hash in the signed text (so a changed,
/// swapped or added value fails the signature without the signed text carrying the value). It answers one request id once: the host refuses a second delivery for an id, and the authority
/// never repeats one. Never logged, never stored.
/// </summary>
public sealed record SecretsDelivery(int ProtocolVersion, string RequestId, string RequestDigest, string MachineFingerprint, string Via, string GrantId, int SecurityRevision, DateTimeOffset Issued, DateTimeOffset Expires, string AuthorityKeyId, IReadOnlyList<DeliveredValue> Values, byte[] Signature) : ISignedAnswer
{
    public const string Domain = "with-secrets secrets delivery v1\n";
    public const string ViaPage = "page";
    public const string ViaGrant = "grant";

    /// <summary>The longest a delivery may be valid (issue to expiry).</summary>
    public static readonly TimeSpan MaxLifetime = TimeSpan.FromSeconds(120);

    public const int MaxValues = EnvDeclarations.MaxPairs;

    /// <summary>The salted hash of one value as the signed text carries it: SHA-256 over request id, name and value.</summary>
    internal static string Proof(string requestId, string name, byte[] value)
    {
        byte[] prefix = Encoding.UTF8.GetBytes(requestId + "\0" + name + "\0");
        byte[] all = [.. prefix, .. value];
        try
        {
            return Convert.ToHexString(SHA256.HashData(all));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(all);
        }
    }

    public string Canonical()
    {
        StringBuilder text = new("{\"protocolVersion\":");
        text.Append(ProtocolVersion.ToString(CultureInfo.InvariantCulture)).Append(",\"requestId\":");
        ToolSettings.QuoteJson(text, RequestId);
        text.Append(",\"requestDigest\":");
        ToolSettings.QuoteJson(text, RequestDigest);
        text.Append(",\"machineFingerprint\":");
        ToolSettings.QuoteJson(text, MachineFingerprint);
        text.Append(",\"via\":");
        ToolSettings.QuoteJson(text, Via);
        text.Append(",\"grantId\":");
        ToolSettings.QuoteJson(text, GrantId);
        text.Append(",\"securityRevision\":").Append(SecurityRevision.ToString(CultureInfo.InvariantCulture)).Append(",\"issued\":");
        ToolSettings.QuoteJson(text, CanonicalJson.Time(Issued));
        text.Append(",\"expires\":");
        ToolSettings.QuoteJson(text, CanonicalJson.Time(Expires));
        text.Append(",\"authorityKeyId\":");
        ToolSettings.QuoteJson(text, AuthorityKeyId);
        text.Append(",\"values\":[");
        bool first = true;
        foreach (DeliveredValue value in Values.OrderBy(item => item.Name, StringComparer.Ordinal))
        {
            text.Append(first ? "" : ",").Append("{\"name\":");
            first = false;
            ToolSettings.QuoteJson(text, value.Name);
            text.Append(",\"proof\":");
            ToolSettings.QuoteJson(text, Proof(RequestId, value.Name, value.Value));
            text.Append('}');
        }

        return text.Append("]}").ToString();
    }

    public static SecretsDelivery Create(string requestId, string requestDigest, string machineFingerprint, string via, string grantId, int revision, DateTimeOffset issued, DateTimeOffset expires, IReadOnlyList<DeliveredValue> values, ISigningKey key)
    {
        SecretsDelivery unsigned = new(LaunchProtocol.Version, requestId, requestDigest, machineFingerprint, via, grantId, revision, issued, expires, KeyIdentity.Fingerprint(key.PublicKey), values, []);

        return unsigned with { Signature = key.Sign(WireText.Bytes(Domain, unsigned.Canonical())) };
    }

    public bool Verify(byte[] authorityPublicKey)
    {
        return string.Equals(AuthorityKeyId, KeyIdentity.Fingerprint(authorityPublicKey), StringComparison.Ordinal)
            && Via is ViaPage or ViaGrant
            && KeyIdentity.Verify(authorityPublicKey, WireText.Bytes(Domain, Canonical()), Signature);
    }

    /// <summary>Zeroes every value's bytes.</summary>
    public void Zero()
    {
        foreach (DeliveredValue value in Values)
        {
            CryptographicOperations.ZeroMemory(value.Value);
        }
    }

    /// <summary>The wire form: the signed members, each value with its base64 bytes, and the signature.</summary>
    public string ToJson()
    {
        StringBuilder text = new("{\"protocolVersion\":");
        text.Append(ProtocolVersion.ToString(CultureInfo.InvariantCulture)).Append(",\"requestId\":");
        ToolSettings.QuoteJson(text, RequestId);
        text.Append(",\"requestDigest\":");
        ToolSettings.QuoteJson(text, RequestDigest);
        text.Append(",\"machineFingerprint\":");
        ToolSettings.QuoteJson(text, MachineFingerprint);
        text.Append(",\"via\":");
        ToolSettings.QuoteJson(text, Via);
        text.Append(",\"grantId\":");
        ToolSettings.QuoteJson(text, GrantId);
        text.Append(",\"securityRevision\":").Append(SecurityRevision.ToString(CultureInfo.InvariantCulture)).Append(",\"issued\":");
        ToolSettings.QuoteJson(text, CanonicalJson.Time(Issued));
        text.Append(",\"expires\":");
        ToolSettings.QuoteJson(text, CanonicalJson.Time(Expires));
        text.Append(",\"authorityKeyId\":");
        ToolSettings.QuoteJson(text, AuthorityKeyId);
        text.Append(",\"values\":[");
        bool first = true;
        foreach (DeliveredValue value in Values.OrderBy(item => item.Name, StringComparer.Ordinal))
        {
            text.Append(first ? "" : ",").Append("{\"name\":");
            first = false;
            ToolSettings.QuoteJson(text, value.Name);
            text.Append(",\"value\":\"").Append(Convert.ToBase64String(value.Value)).Append("\"}");
        }

        text.Append("],\"signature\":");
        ToolSettings.QuoteJson(text, Convert.ToBase64String(Signature));

        return text.Append('}').ToString();
    }

    public static bool TryRead(JsonElement element, out SecretsDelivery? delivery)
    {
        delivery = null;
        ContractReader reader = new(element, "protocolVersion", "requestId", "requestDigest", "machineFingerprint", "via", "grantId", "securityRevision", "issued", "expires", "authorityKeyId", "values", "signature");
        if (reader.Problem is not null || !reader.Int("protocolVersion", out int version) || !reader.Text("requestId", out string? id) || !reader.Text("requestDigest", out string? digest) || !reader.Text("machineFingerprint", out string? machine)
            || !reader.Text("via", out string? via) || !reader.Text("grantId", out string? grant) || !reader.Int("securityRevision", out int revision) || !reader.Time("issued", out DateTimeOffset issued) || !reader.Time("expires", out DateTimeOffset expires)
            || !reader.Text("authorityKeyId", out string? keyId) || !reader.Array("values", out JsonElement array) || !reader.Text("signature", out string? signatureText) || array.GetArrayLength() > MaxValues)
        {
            return false;
        }

        byte[] signature = new byte[64];
        if (!Convert.TryFromBase64String(signatureText!, signature, out int written) || written != 64)
        {
            return false;
        }

        List<DeliveredValue> values = [];
        foreach (JsonElement item in array.EnumerateArray())
        {
            ContractReader entry = new(item, "name", "value") { Where = "values" };
            if (entry.Problem is not null || !entry.Text("name", out string? name) || !entry.Text("value", out string? base64) || name!.Length == 0)
            {
                Zero(values);

                return false;
            }

            byte[] bytes = new byte[base64!.Length / 4 * 3 + 3];
            if (!Convert.TryFromBase64String(base64, bytes, out int length))
            {
                CryptographicOperations.ZeroMemory(bytes);
                Zero(values);

                return false;
            }

            byte[] exact = bytes[..length];
            CryptographicOperations.ZeroMemory(bytes);
            values.Add(new DeliveredValue(name, exact));
        }

        delivery = new SecretsDelivery(version, id!, digest!, machine!, via!, grant!, revision, issued, expires, keyId!, values, signature);

        return true;
    }

    private static void Zero(List<DeliveredValue> values)
    {
        foreach (DeliveredValue value in values)
        {
            CryptographicOperations.ZeroMemory(value.Value);
        }
    }
}

/// <summary>The authority's answer to a <see cref="LaunchAuthorize" />: the delivery of the approved values, or a signed refusal (the same <see cref="AuthorityResponse" /> as a refusal in local mode).</summary>
public sealed record LaunchAnswer(SecretsDelivery? Delivery, AuthorityResponse? Refusal)
{
    public string ToJson() => Delivery is not null ? "{\"delivery\":" + Delivery.ToJson() + "}" : "{\"refusal\":" + Refusal!.ToJson() + "}";

    /// <summary>Strict: exactly one of the two members. On failure nothing is returned and any value bytes read are zeroed.</summary>
    public static bool TryRead(string body, out LaunchAnswer? answer)
    {
        answer = null;
        if (!CanonicalJson.Open(body, out JsonDocument? doc, out _))
        {
            return false;
        }

        using (doc)
        {
            JsonElement root = doc!.RootElement;
            int members = root.EnumerateObject().Count();
            if (members != 1)
            {
                return false;
            }

            if (root.TryGetProperty("delivery", out JsonElement deliveryElement))
            {
                if (!SecretsDelivery.TryRead(deliveryElement, out SecretsDelivery? delivery))
                {
                    return false;
                }

                answer = new LaunchAnswer(delivery, null);

                return true;
            }

            if (root.TryGetProperty("refusal", out JsonElement refusalElement) && AuthorityResponse.TryParse(refusalElement.GetRawText(), out AuthorityResponse? refusal, out _))
            {
                answer = new LaunchAnswer(null, refusal);

                return true;
            }

            return false;
        }
    }
}

/// <summary>The authority's notice of where the approval page is (sent while the request waits; one per request, repeated only if the page moves). A link, never a value.</summary>
public sealed record ApprovalLinkNotice(string RequestId, int Sequence, string Link)
{
    public const int MaxLinkLength = 2048;

    /// <summary>True for an absolute http or https address with no control character and no user info: all the host will pass to its client.</summary>
    public static bool IsSafe(string link) => link.Length is > 0 and <= MaxLinkLength && !link.Any(char.IsControl) && Uri.TryCreate(link, UriKind.Absolute, out Uri? uri) && uri.Scheme is "http" or "https" && uri.UserInfo.Length == 0;

    public string ToJson()
    {
        StringBuilder text = new("{\"requestId\":");
        ToolSettings.QuoteJson(text, RequestId);
        text.Append(",\"sequence\":").Append(Sequence.ToString(CultureInfo.InvariantCulture)).Append(",\"link\":");
        ToolSettings.QuoteJson(text, Link);

        return text.Append('}').ToString();
    }

    public static bool TryRead(string body, out ApprovalLinkNotice? notice)
    {
        notice = null;
        if (!CanonicalJson.Open(body, out JsonDocument? doc, out _))
        {
            return false;
        }

        using (doc)
        {
            ContractReader reader = new(doc!.RootElement, "requestId", "sequence", "link");
            if (reader.Problem is not null || !reader.Text("requestId", out string? id) || !reader.Int("sequence", out int sequence) || !reader.Text("link", out string? link) || sequence < 0)
            {
                return false;
            }

            notice = new ApprovalLinkNotice(id!, sequence, link!);

            return true;
        }
    }
}

/// <summary>What a host needs of an authority that decrypts for it: ask for one launch, be told where the approval page is, get the values or a refusal. Implemented by <see cref="RemoteAuthority" />.</summary>
public interface ILaunchAuthority
{
    /// <summary>
    /// Sends <paramref name="message" /> and waits for the answer. <paramref name="onLink" /> is called (possibly more than once) with the notices the authority sends while the request waits. The message is sent once:
    /// a broken connection after the send ends the call with an exception (the host then launches nothing); it is never sent again under the same id.
    /// </summary>
    Task<LaunchAnswer> AuthorizeLaunchAsync(LaunchAuthorize message, Action<ApprovalLinkNotice> onLink, CancellationToken cancel);

    /// <summary>
    /// A host with no authority signing key pinned yet learns it from the authority (over the identity-pinned connection, and only when the authority trusts this machine) and pins it. True when a key is pinned afterwards.
    /// </summary>
    Task<bool> EnsureAuthorityKeyPinnedAsync(CancellationToken cancel);
}

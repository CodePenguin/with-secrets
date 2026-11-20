namespace WithSecrets;

/// <summary>
/// The page side of WebAuthn PRF, shared by the pages that create or use a passkey. The scripts have the line
/// <c>//@SEAL_PRF@</c> where the two functions go (they use the page's <c>encoder</c>, <c>fromBase64Url</c> and <c>toBase64Url</c>).
/// <see cref="Fill" /> puts the text in before the script is hashed for the page's content security policy.
/// <para>
/// <c>sealPrf</c> encrypts the 32-byte PRF output to the page's server key before it leaves the page, with the same scheme as the
/// values of the set page: a fresh ECDH P-256 key, HKDF-SHA-256 (salt: the bind, info: "with-secrets/v1 prf") and AES-256-GCM
/// (12-byte iv, the bind as associated data), so a tunnel that ends TLS sees only the sealed text. It does not stop an active
/// man in the middle who replaces the page's server key. <c>prfOutput</c> reads the 32 bytes out of the browser's passkey
/// result, or gives null when the passkey did not return them.
/// </para>
/// </summary>
internal static class PrfClient
{
    public const string Token = "//@SEAL_PRF@";

    public const string Seal = """
        function sealPrf(output, bind, serverKey) {
                var subtle = window.crypto.subtle;
                var curve = { name: "ECDH", namedCurve: "P-256" };
                var iv = window.crypto.getRandomValues(new Uint8Array(12));
                var mine;
                var ct;
                return subtle.generateKey(curve, false, ["deriveBits"]).then(function (pair) {
                    mine = pair;
                    return subtle.importKey("raw", serverKey, curve, false, []);
                }).then(function (server) {
                    return subtle.deriveBits({ name: "ECDH", public: server }, mine.privateKey, 256);
                }).then(function (shared) {
                    return subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
                }).then(function (material) {
                    return subtle.deriveKey(
                        { name: "HKDF", hash: "SHA-256", salt: bind, info: encoder.encode("with-secrets/v1 prf") },
                        material, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
                }).then(function (key) {
                    return subtle.encrypt({ name: "AES-GCM", iv: iv, additionalData: bind, tagLength: 128 }, key, output);
                }).then(function (sealed) {
                    ct = new Uint8Array(sealed);
                    return subtle.exportKey("raw", mine.publicKey);
                }).then(function (epk) {
                    return { epk: toBase64Url(epk), iv: toBase64Url(iv), ct: toBase64Url(ct) };
                });
            }

            function passkeyLabel(guid, name) {
                var room = 64 - 13 - 1 - guid.length;
                var part = room > 0 ? name.slice(0, room) : "";
                if (part.length > 0 && /[\uD800-\uDBFF]/.test(part.charAt(part.length - 1))) {
                    part = part.slice(0, -1);
                }
                part = part.replace(/\s+$/, "");
                return "with-secrets " + (part.length > 0 ? part + " " : "") + guid;
            }

            function prfOutput(credential) {
                var extensions = credential.getClientExtensionResults ? credential.getClientExtensionResults() : null;
                var first = extensions && extensions.prf && extensions.prf.results ? extensions.prf.results.first : null;
                if (!first) {
                    return null;
                }
                var bytes = new Uint8Array(first);
                return bytes.length === 32 ? bytes : null;
            }
        """;

    /// <summary>The script with the PRF functions in place of the token. Line endings are the caller's business.</summary>
    public static string Fill(string script) => script.Replace(Token, Seal, StringComparison.Ordinal);

    /// <summary>What a page that creates a passkey says: only a passkey that can do PRF can be used.</summary>
    public const string RequiredText = "Use a phone or a security key. The passkey must support PRF, or it is refused.";

    /// <summary>What an approval page that releases the secret store key says.</summary>
    public const string ApprovalHint = "Your passkey must support PRF: tapping it also releases the secret store key for this approval's run. "
        + "The key is not stored; it is rebuilt from your passkey each time.";

    /// <summary>What a page says when the browser returned no PRF output for a passkey that was asked for it.</summary>
    public const string NoPrfOutput = "Your passkey did not release its PRF key, which this approval needs to open the secrets. Nothing was approved. Use a passkey from your phone or a security key.";

    /// <summary>The PRF refusal the person reads: the passkey cannot protect the secret store key.</summary>
    public const string CannotPrf = "This passkey cannot do PRF (it cannot protect the secret store key). Use a passkey from your phone or a security key.";
}

/// <summary>
/// The label a password manager shows for a new passkey (WebAuthn <c>user.name</c> and <c>displayName</c>):
/// <c>with-secrets &lt;key name&gt; &lt;guid&gt;</c>, within 64 characters; the name is cut first, never the prefix or the GUID.
/// Display only: nothing signed or stored depends on it. The page builds the same text with <c>passkeyLabel</c>.
/// </summary>
internal static class PasskeyLabel
{
    public const int MaxLength = 64;
    private const string Prefix = "with-secrets ";

    /// <summary>A fresh random id, one per create() call (the server sends it to the page).</summary>
    public static string NewId() => Guid.NewGuid().ToString();

    public static string Compose(string guid, string name)
    {
        int room = MaxLength - Prefix.Length - 1 - guid.Length;
        string part = room > 0 ? name[..Math.Min(name.Length, room)] : "";
        if (part.Length > 0 && char.IsHighSurrogate(part[^1]))
        {
            part = part[..^1];
        }

        part = part.TrimEnd();

        return Prefix + (part.Length > 0 ? part + " " : "") + guid;
    }
}

/// <summary>The sealed PRF output a page sends: base64url <c>epk</c>, <c>iv</c> and <c>ct</c> (see <see cref="PrfClient" />).</summary>
internal sealed record PrfBody(string Epk, string Iv, string Ct)
{
    /// <summary>An object with exactly the three string members <c>epk</c>, <c>iv</c> and <c>ct</c>.</summary>
    public static bool TryRead(System.Text.Json.JsonElement element, out PrfBody? body)
    {
        body = null;
        if (element.ValueKind != System.Text.Json.JsonValueKind.Object)
        {
            return false;
        }

        Dictionary<string, string> members = new(StringComparer.Ordinal);
        foreach (System.Text.Json.JsonProperty property in element.EnumerateObject())
        {
            if (property.Value.ValueKind != System.Text.Json.JsonValueKind.String || !members.TryAdd(property.Name, property.Value.GetString()!))
            {
                return false;
            }
        }

        if (members.Count != 3 || !members.TryGetValue("epk", out string? epk) || !members.TryGetValue("iv", out string? iv) || !members.TryGetValue("ct", out string? ct))
        {
            return false;
        }

        body = new PrfBody(epk, iv, ct);

        return true;
    }

    /// <summary>The flat form a registration body uses: <c>prfEpk</c>, <c>prfIv</c> and <c>prfCt</c>, all three or none (null).</summary>
    public static PrfBody? FromFlat(IReadOnlyDictionary<string, string> members)
    {
        return members.TryGetValue("prfEpk", out string? epk) && members.TryGetValue("prfIv", out string? iv) && members.TryGetValue("prfCt", out string? ct) ? new PrfBody(epk, iv, ct) : null;
    }
}

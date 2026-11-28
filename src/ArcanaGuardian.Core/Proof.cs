using System.Security.Cryptography;
using System.Text;

namespace ArcanaGuardian;

/// <summary>What a proof is tied to. <see cref="Bind" /> is <see cref="RequestBinding.Compute" /> of this request.</summary>
public sealed record ProofContext(byte[] Bind, string Origin);

/// <summary>What the page needs to start a proof. Mode "webauthn"; Payload is JSON.</summary>
public sealed record ProofStart(string Mode, string Payload);

/// <summary>The enrolled credential that verified a passkey assertion: identity and trusted admin flag from the store record, never from client input.</summary>
public sealed record VerifiedCredential(string Id, string Name, bool Admin)
{
    internal static VerifiedCredential From(ManifestKey key) => new(key.Id, key.Name, key.Admin);

    internal void AddTo(IDictionary<string, string> metadata, string prefix)
    {
        metadata[prefix + "Id"] = Id;
        metadata[prefix + "Name"] = Name;
        metadata[prefix + "Admin"] = Admin ? "true" : "false";
    }
}

/// <summary>What a proof check came to. When <see cref="Ok" />, <see cref="Credential" /> is the trusted enrolled record that verified.</summary>
public sealed record ProofResult(bool Ok, string Detail, VerifiedCredential? Credential = null);

/// <summary>This proof method cannot run now (for example, nothing is enrolled).</summary>
public sealed class ProofUnavailableException(string message) : Exception(message);

/// <summary>One thing a proof method trusts, such as a key or a subject. <see cref="Admin" /> marks one that may change the state (there may be several).</summary>
public sealed record EnrolledEntry(string Name, string Detail, DateTimeOffset Created, bool Admin = false);

/// <summary>A way for the person to prove they approve one specific request. Must fail closed.</summary>
public interface IProofMethod
{
    string Id { get; }

    /// <summary>Throws <see cref="ProofUnavailableException" /> when the method cannot run.</summary>
    ProofStart Start(ProofContext context);

    ProofResult Verify(ProofContext context, string response);

    /// <summary>What this method trusts: keys, subjects.</summary>
    IReadOnlyList<EnrolledEntry> Enrolled();

    /// <summary>True when at least one enrolled entry works at this host name. An unreadable store gives false.</summary>
    bool CanProve(string rpId);

    /// <summary>
    /// Person-facing setup for this method. <paramref name="name" /> is the name the setup suggests; the person chooses the
    /// name there. <paramref name="askAdmin" /> asks an admin to sign a new manifest text on an approval page, when the
    /// method cannot ask for it on its own page. <paramref name="approval" /> is what the approving admin passkey released (WebAuthn
    /// PRF) at the approval that came first: it opens the master key, which the new key's slot wraps. The caller disposes it.
    /// </summary>
    ApprovalDecision Enroll(string name, Action<string> announce, Func<string, ManifestApproval>? askAdmin = null, Unlock? approval = null);

    /// <summary>Removes the entry with this stored name, with an admin's signature over the new manifest from <paramref name="askAdmin" />.</summary>
    ApprovalDecision Unenroll(string name, Func<string, ManifestApproval> askAdmin);

    /// <summary>
    /// The line every page shows about the admin keys (see <see cref="AdminKey.Line(StateDatabase)" />), or null when the method
    /// keeps no state of its own.
    /// </summary>
    string? AdminLine() => null;
}

/// <summary>Ties a proof to one request: SHA-256 of the nonce, a newline, and the request text.</summary>
public static class RequestBinding
{
    public static byte[] Compute(string nonce, string requestText)
    {
        return SHA256.HashData(Encoding.UTF8.GetBytes(nonce + "\n" + requestText));
    }
}

/// <summary>
/// Ties the chosen reuse time to the proof: the passkey signs <c>SHA-256(bind || "reuse=" || minutes)</c>, the bind's bytes
/// followed by the ASCII text "reuse=" and the minutes in decimal (no sign, no padding; 0 is "approve once"). A page or a relay
/// cannot change the time after the person signed it.
/// </summary>
public static class ReuseBinding
{
    public static byte[] Challenge(byte[] bind, int minutes)
    {
        return SHA256.HashData([.. bind, .. Encoding.ASCII.GetBytes("reuse=" + minutes.ToString(System.Globalization.CultureInfo.InvariantCulture))]);
    }
}

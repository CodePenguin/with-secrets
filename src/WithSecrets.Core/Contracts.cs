using System.Text.RegularExpressions;

namespace WithSecrets;

/// <summary>Rules for secret names and values.</summary>
public static class SecretNames
{
    /// <summary>Short values cause over-redaction, so the store refuses them.</summary>
    public const int MinValueLength = 6;

    private static readonly Regex Pattern = new("^[A-Z][A-Z0-9_]*$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>UPPER_SNAKE_CASE. Names that start with DOTENV_ belong to dotenvx (public and private keys).</summary>
    public static bool IsValid(string name)
    {
        return Pattern.IsMatch(name) && !name.StartsWith("DOTENV_", StringComparison.Ordinal);
    }
}

/// <summary>
/// What the agent asked for. Every field except <see cref="SecretNames" />, <see cref="Reuse" />, <see cref="RequestId" /> and
/// <see cref="Sources" /> comes from the agent. <see cref="Reuse" /> is the reuse the page may offer (from the settings); null
/// offers only "Approve once". <see cref="RequestId" /> is the request's fingerprint key (see <see cref="RequestFingerprint" />),
/// shown in the text the person signs so that a saved approval names the request it covers. <see cref="Sources" /> is where
/// each secret comes from (see <see cref="ISecretSource.Label" />), shown after each name. <see cref="Unlock" /> is true when the
/// approving passkey must also release the secret store key (WebAuthn PRF, see <see cref="KeyVault" />). <see cref="Script" />
/// is the script file the run executes and <see cref="ProgramFile" /> the program itself when it is a text file, each read once for the approval text (see <see cref="ApprovalSummary" />); null when there is none.
/// </summary>
public sealed record ApprovalRequest(
    string Program,
    string ResolvedProgram,
    IReadOnlyList<string> Arguments,
    string WorkingDirectory,
    string Reason,
    IReadOnlyList<string> SecretNames,
    ReuseOffer? Reuse = null,
    IReadOnlyList<string>? TypedArguments = null,
    IReadOnlyList<string>? Links = null,
    string? RequestId = null,
    IReadOnlyDictionary<string, string>? Sources = null,
    bool Unlock = false,
    ScriptView? Script = null,
    ScriptView? ProgramFile = null);

/// <summary>
/// What a person signed on an approval page: the page nonce, the exact text that was bound (see <see cref="RequestBinding" />)
/// and the passkey assertion JSON (<c>{"id","authenticatorData","clientDataJSON","signature"}</c>, base64url) over
/// <see cref="ReuseBinding.Challenge" />. A saved approval keeps it, so it can be checked again every time it is used.
/// </summary>
public sealed record ApprovalEvidence(string Nonce, string Text, string Proof);

/// <summary>
/// The person's answer. <see cref="ReuseMinutes" /> is the reuse time they approved and signed; 0 is "once".
/// <see cref="Evidence" /> is what they signed, when the proof method has one to keep (a passkey on a run approval page).
/// <see cref="Unlock" /> is what the approving passkey released by WebAuthn PRF when the page asked for it (a run, or the approval
/// that precedes an enrollment): the caller uses it once and disposes it, which zeroes it.
/// </summary>
public sealed record ApprovalDecision(bool Approved, string Detail, int ReuseMinutes = 0, ApprovalEvidence? Evidence = null, Unlock? Unlock = null)
{
    public static ApprovalDecision Allow(string detail = "approved", int reuseMinutes = 0, ApprovalEvidence? evidence = null, Unlock? unlock = null) => new(true, detail, reuseMinutes, evidence, unlock);

    public static ApprovalDecision Deny(string detail) => new(false, detail);
}

/// <summary>Asks the person. Must fail closed: any doubt means deny.</summary>
public interface IApprover
{
    ApprovalDecision Request(ApprovalRequest request);
}

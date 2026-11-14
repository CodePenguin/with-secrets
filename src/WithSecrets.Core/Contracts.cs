using System.Text.RegularExpressions;

namespace WithSecrets;

/// <summary>Rules for secret names and values.</summary>
public static class SecretNames
{
    /// <summary>Short values cause over-redaction, so the store refuses them.</summary>
    public const int MinValueLength = 6;

    /// <summary>The most characters of a whole secret name, folders included.</summary>
    public const int MaxNameLength = 200;

    /// <summary>The most segments of a name: up to three folders and the name itself.</summary>
    public const int MaxSegments = 4;

    // \z, not $: "$" also matches before a final line break.
    private static readonly Regex Pattern = new("^[A-Za-z][A-Za-z0-9_]*\\z", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex Folder = new("^[A-Za-z0-9_.-]{1,64}\\z", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>
    /// The one rule for a secret name, used by --set, --remove, --list, --audit, --needs, .env references and the store.
    /// <c>[folder/]*NAME</c>: 1 to <see cref="MaxSegments" /> segments separated by a single '/', at most
    /// <see cref="MaxNameLength" /> characters in all. The last segment is letters, digits and '_' starting with a letter (any case), and does not start with DOTENV_ (those
    /// belong to dotenvx: public and private keys) except DOTENV_PRIVATE_KEY, the name a Dotenvx private key is stored under. Each folder segment is 1 to 64 of letters, digits, '_', '.', '-', and is not
    /// '.' or '..'. The whole text is the store name; it is data, never a file path. A name is compared exactly (case counts); see <see cref="CaseTwins" />.
    /// </summary>
    public static bool IsValid(string name)
    {
        if (name.Length is 0 or > MaxNameLength)
        {
            return false;
        }

        string[] parts = name.Split('/');
        if (parts.Length > MaxSegments)
        {
            return false;
        }

        string last = parts[^1];
        if (!Pattern.IsMatch(last) || last.StartsWith("DOTENV_", StringComparison.OrdinalIgnoreCase) && !last.StartsWith(PrivateKeyPrefix, StringComparison.Ordinal))
        {
            return false;
        }

        return parts.Take(parts.Length - 1).All(part => Folder.IsMatch(part) && part is not "." and not "..");
    }

    /// <summary>Secrets whose last segment starts with this hold a Dotenvx private key: used only to decrypt .env values, never given to a program.</summary>
    public const string PrivateKeyPrefix = "DOTENV_PRIVATE_KEY";

    /// <summary>True when the last segment of the name starts with <see cref="PrivateKeyPrefix" />.</summary>
    public static bool IsPrivateKeyName(string name) => name[(name.LastIndexOf('/') + 1)..].StartsWith(PrivateKeyPrefix, StringComparison.Ordinal);

    /// <summary>
    /// The names in <paramref name="existing" /> that equal <paramref name="name" /> when case is ignored (whole path, ordinal) but are
    /// not identical to it. Names are case-sensitive in the store, so these are different secrets that are easy to confuse.
    /// </summary>
    public static IReadOnlyList<string> CaseTwins(string name, IEnumerable<string> existing)
    {
        return [.. existing.Where(other => string.Equals(other, name, StringComparison.OrdinalIgnoreCase) && !string.Equals(other, name, StringComparison.Ordinal)).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)];
    }

    /// <summary>
    /// The names in <paramref name="existing" /> that are not identical to <paramref name="name" /> and do not equal it when case is ignored, but read alike:
    /// they are equal once I, l and 1 are one character and O and 0 are one character (and case is ignored). APl_KEY and API_KEY are such a pair.
    /// </summary>
    public static IReadOnlyList<string> LookAlikes(string name, IEnumerable<string> existing)
    {
        string folded = Fold(name);

        return [.. existing.Where(other => !string.Equals(other, name, StringComparison.OrdinalIgnoreCase) && Fold(other) == folded).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)];
    }

    private static string Fold(string name) => new([.. name.Select(letter => char.ToUpperInvariant(letter) is 'I' or 'L' or '1' ? 'I' : char.ToUpperInvariant(letter) is 'O' or '0' ? 'O' : char.ToUpperInvariant(letter))]);

    /// <summary>True when the name can also be an environment variable name: valid and without a folder.</summary>
    public static bool IsEnvName(string name) => name.IndexOf('/', StringComparison.Ordinal) < 0 && IsValid(name);
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
    ScriptView? ProgramFile = null,
    IReadOnlyList<SecretMapping>? Mappings = null,
    IReadOnlyList<string>? EnvFiles = null,
    IReadOnlyList<string>? EnvNames = null,
    IReadOnlyDictionary<string, string>? EnvValues = null,
    IReadOnlyDictionary<string, string>? InheritedEnvironment = null,
    string? Heading = null,
    IReadOnlyList<string>? ExtraLines = null,
    IReadOnlyList<DecryptItem>? Decrypts = null);

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
public sealed record ApprovalDecision(bool Approved, string Detail, int ReuseMinutes = 0, ApprovalEvidence? Evidence = null, Unlock? Unlock = null, string? Actor = null, string? ReasonCode = null)
{
    public static ApprovalDecision Allow(string detail = "approved", int reuseMinutes = 0, ApprovalEvidence? evidence = null, Unlock? unlock = null, string? actor = null) => new(true, detail, reuseMinutes, evidence, unlock, actor);

    public static ApprovalDecision Deny(string detail, string? actor = null, string? reasonCode = null) => new(false, detail, Actor: actor, ReasonCode: reasonCode);

    /// <summary>The detail of a decision that came from the approval time limit running out (nobody answered).</summary>
    public const string TimeLimitDetail = "no answer before the time limit";

    /// <summary>The approval was not answered before the time limit: a different outcome from a person pressing Deny.</summary>
    public bool TimedOut => !Approved && Detail == TimeLimitDetail;
}

/// <summary>Asks the person. Must fail closed: any doubt means deny.</summary>
public interface IApprover
{
    ApprovalDecision Request(ApprovalRequest request);

    /// <summary>As <see cref="Request(ApprovalRequest)" />, and an approver that waits for a person closes its page and denies when <paramref name="cancel" /> is set.</summary>
    ApprovalDecision Request(ApprovalRequest request, CancellationToken cancel) => Request(request);
}

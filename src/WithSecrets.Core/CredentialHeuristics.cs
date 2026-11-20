using System.Text.RegularExpressions;

namespace WithSecrets;

/// <summary>
/// A short list of signs that a name or a value is a credential, used to keep plaintext credentials off the approval page and to warn about them. It is a
/// heuristic, not a scanner: it misses what it does not list, and it can hide a value that is harmless. What it hides is only what the page shows. The
/// request's fingerprint, and so the approval, still covers the real value, and nothing here changes the environment the program gets.
/// </summary>
internal static partial class CredentialHeuristics
{
    /// <summary>What the page shows in place of a value (or of the part of it) that looks like a credential.</summary>
    public const string Hidden = "[hidden]";

    // Parts of a name, compared in capitals with the underscores and dashes kept. PWD is not here: it is the working folder.
    private static readonly string[] NameParts = ["PASSWORD", "PASSWD", "TOKEN", "SECRET", "APIKEY", "API_KEY", "PRIVATE_KEY", "CREDENTIAL", "BEARER"];

    // Whole words of a name: DB_PASS and AUTH_URL, but not AUTHOR_NAME.
    private static readonly string[] NameWords = ["PASS", "AUTH", "AUTHORIZATION"];

    /// <summary>True when the name of a variable says that its value is a credential: PASSWORD, PASSWD, TOKEN, SECRET, API_KEY, PRIVATE_KEY, AUTH, CREDENTIAL, in any case.</summary>
    public static bool NameLooksLikeCredential(string name)
    {
        // camelCase is read as words (dbPassword, authToken); the upper-case form covers the rest (APIKEY, DBPASSWORD).
        string upper = name.ToUpperInvariant();
        if (NameParts.Any(part => upper.Contains(part, StringComparison.Ordinal)))
        {
            return true;
        }

        string spaced = CamelBoundary().Replace(name, "_").ToUpperInvariant();

        return spaced.Split(['_', '-', '.'], StringSplitOptions.RemoveEmptyEntries).Any(word => NameWords.Contains(word, StringComparer.Ordinal));
    }

    /// <summary>
    /// The value as the approval page shows it: hidden whole when its name says it is a credential or it has the shape of a known token, and with the
    /// credential part hidden when it is a URL with a password, a connection string with a password, or an Authorization header value. Anything else as it is.
    /// </summary>
    public static string Display(string name, string value)
    {
        if (value.Length == 0)
        {
            return value;
        }

        if (NameLooksLikeCredential(name) || KnownToken().IsMatch(value))
        {
            return Hidden;
        }

        return MaskParts(value);
    }

    /// <summary>
    /// The names of the ordinary .env variables (plain text in the file: references and encrypted values are not among them) that look like credentials, in order.
    /// With the values at hand a name counts when its name or its value looks like one; with names only (the terminal echo), by the name alone.
    /// </summary>
    public static IReadOnlyList<string> PlaintextEnvNames(ApprovalRequest request)
    {
        if (request.EnvValues is { } values)
        {
            return [.. values.Where(item => item.Value.Length > 0 && !string.Equals(Display(item.Key, item.Value), item.Value, StringComparison.Ordinal)).Select(item => item.Key).Order(StringComparer.Ordinal)];
        }

        return [.. (request.EnvNames ?? []).Where(NameLooksLikeCredential).Order(StringComparer.Ordinal)];
    }

    /// <summary>True when the value, whatever its name, has a credential in it: the same signs as <see cref="Display" /> uses for the parts and for the shapes.</summary>
    public static bool ValueLooksLikeCredential(string value) => KnownToken().IsMatch(value) || !string.Equals(MaskParts(value), value, StringComparison.Ordinal);

    /// <summary>The text with the credential parts hidden: a password in a URL, a password-like key in a connection string, a bearer or basic credential.</summary>
    public static string MaskParts(string text)
    {
        string masked = UrlPassword().Replace(text, "${scheme}${user}:" + Hidden + "@");
        masked = KeyedSecret().Replace(masked, "${key}=" + Hidden);

        return AuthorizationValue().Replace(masked, "${kind} " + Hidden);
    }

    /// <summary>
    /// What kind of credential is written into a command line or the text of a script: PGPASSWORD=value (any NAME with PASSWORD, TOKEN, SECRET or API_KEY in it
    /// assigned a literal), sshpass -p value, an Authorization: Bearer or Basic value. Names of kinds and variables only: the credential itself is never returned.
    /// A value that refers to something else ($VAR, secret://NAME) is not a credential written in.
    /// </summary>
    public static IReadOnlyList<string> InlineCredentialKinds(string text)
    {
        List<string> kinds = [];
        foreach (Match match in InlineAssignment().Matches(text))
        {
            string kind = match.Groups["name"].Value + "=";
            if (!kinds.Contains(kind))
            {
                kinds.Add(kind);
            }
        }

        if (InlineSshpass().IsMatch(text))
        {
            kinds.Add("sshpass -p");
        }

        if (InlineAuthorization().IsMatch(text))
        {
            kinds.Add("Authorization: Bearer/Basic");
        }

        return kinds;
    }

    // NAME=literal, where NAME has a credential word in it. A value that starts with $ (a variable), % (cmd) or secret:// refers to something else; an empty one has nothing in it.
    [GeneratedRegex(@"(?<![A-Za-z0-9_])(?<name>[A-Za-z0-9_]*(?:PASSWORD|PASSWD|TOKEN|SECRET|API_?KEY)[A-Za-z0-9_]*)=(?![\s$%""']?(?:\$|%|secret://))(?=[^\s""'])", RegexOptions.IgnoreCase)]
    private static partial Regex InlineAssignment();

    [GeneratedRegex(@"\bsshpass\s+-p\s*[^\s]", RegexOptions.IgnoreCase)]
    private static partial Regex InlineSshpass();

    [GeneratedRegex(@"Authorization\s*[:=]\s*[""']?(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=\-]{8,}", RegexOptions.IgnoreCase)]
    private static partial Regex InlineAuthorization();

    [GeneratedRegex("(?<=[a-z0-9])(?=[A-Z])")]
    private static partial Regex CamelBoundary();

    // scheme://user:password@host. The password may not contain a slash, a space or an at sign.
    [GeneratedRegex(@"(?<scheme>[A-Za-z][A-Za-z0-9+.\-]*://)(?<user>[^/\s:@]*):(?<password>[^@\s/]+)@")]
    private static partial Regex UrlPassword();

    // Password=...; Pwd=...; token=... in a connection string or a query: up to the next ; & or space.
    [GeneratedRegex(@"(?<![A-Za-z0-9_])(?<key>password|passwd|pwd|pass|secret|token|apikey|api_key|accountkey|sharedaccesskey|client_secret)\s*=\s*[^;&\s]+", RegexOptions.IgnoreCase)]
    private static partial Regex KeyedSecret();

    // Bearer abc... or Basic abc...: the credential of an Authorization header.
    [GeneratedRegex(@"\b(?<kind>Bearer|Basic)\s+[A-Za-z0-9._~+/=\-]{8,}", RegexOptions.IgnoreCase)]
    private static partial Regex AuthorizationValue();

    // The look of the tokens of common services and of a JWT.
    [GeneratedRegex(@"^(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|glpat-|sk-|sk_live_|sk_test_|rk_live_|xox[abprs]-|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.)")]
    private static partial Regex KnownToken();
}

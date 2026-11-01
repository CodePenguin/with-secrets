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

/// <summary>Where secrets live. The production implementation wraps the Dotenvx library.</summary>
public interface ISecretStore
{
    /// <summary>Names of the secret entries. Reads the file as text. Decrypts nothing.</summary>
    IReadOnlyList<string> ListNames();

    /// <summary>Decrypts the store and returns only the named values. Throws if a name is missing.</summary>
    IReadOnlyDictionary<string, string> GetValues(IReadOnlyCollection<string> names);

    void Set(string name, string value);

    /// <summary>Returns false when the name does not exist.</summary>
    bool Remove(string name);
}

/// <summary>What the agent asked for. Every field except <see cref="SecretNames" /> comes from the agent.</summary>
public sealed record ApprovalRequest(
    string Program,
    string ResolvedProgram,
    IReadOnlyList<string> Arguments,
    string WorkingDirectory,
    string Reason,
    IReadOnlyList<string> SecretNames,
    int ReuseMinutes = 0,
    IReadOnlyList<string>? TypedArguments = null,
    IReadOnlyList<string>? Links = null);

public sealed record ApprovalDecision(bool Approved, string Detail)
{
    public static ApprovalDecision Allow(string detail = "approved") => new(true, detail);

    public static ApprovalDecision Deny(string detail) => new(false, detail);
}

/// <summary>Asks the person. Must fail closed: any doubt means deny.</summary>
public interface IApprover
{
    ApprovalDecision Request(ApprovalRequest request);
}

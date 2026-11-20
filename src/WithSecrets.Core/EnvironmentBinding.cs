using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace WithSecrets;

/// <summary>
/// The environment a program inherits is chosen by the sender, so it is part of what a person approves: a hash of it goes into the
/// approval fingerprint (a grant covers only the same environment), and the page shows how many variables there are and the NAMES
/// of those that change which code runs or where traffic goes. Values are never shown or recorded. The service computes all of
/// this itself from the request.
/// </summary>
public static class EnvironmentBinding
{
    private static readonly string[] ExtraNames =
    [
        "HOME", "PSModulePath", "JDK_JAVA_OPTIONS", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO",
    ];

    private static readonly string[] ExtraPrefixes = ["npm_config_", "GIT_CONFIG_", "CORECLR_", "COR_"];

    /// <summary>SHA-256 of the sorted name=value pairs, upper-case hex. Names are compared without regard to case on Windows.</summary>
    public static string Hash(IReadOnlyDictionary<string, string> environment)
    {
        StringComparer order = StringComparer.Ordinal;
        StringBuilder text = new();
        foreach (KeyValuePair<string, string> item in environment.OrderBy(entry => OperatingSystem.IsWindows() ? entry.Key.ToUpperInvariant() : entry.Key, order))
        {
            text.Append(OperatingSystem.IsWindows() ? item.Key.ToUpperInvariant() : item.Key).Append('=').Append(item.Value).Append('\0');
        }

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text.ToString())));
    }

    /// <summary>True for the names a person should see: the code-loading and protected lists, proxies, and the extra names above.</summary>
    public static bool IsNotable(string name)
    {
        StringComparison comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

        return EnvDeclarations.IsProtectedVariable(name) || ExtraNames.Any(item => string.Equals(item, name, comparison)) || ExtraPrefixes.Any(prefix => name.StartsWith(prefix, comparison));
    }

    /// <summary>The one line of the approval text: the count and the notable names. Never a value.</summary>
    public static string Line(IReadOnlyDictionary<string, string> environment)
    {
        string[] notable = [.. environment.Keys.Where(IsNotable).Order(StringComparer.Ordinal).Select(ApprovalSummary.Clean)];

        return "Environment: " + environment.Count.ToString(CultureInfo.InvariantCulture) + " inherited variables" + (notable.Length > 0 ? "; notable names: " + string.Join(", ", notable) : "");
    }

    /// <summary>The first 12 characters of the hash, for the audit row.</summary>
    public static string Prefix(IReadOnlyDictionary<string, string> environment) => Hash(environment)[..12];
}

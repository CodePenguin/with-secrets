using System.Text.Json;
using System.Text.RegularExpressions;

namespace WithSecrets.Bitwarden;

public sealed class BitwardenConfiguration : IAdapterConfiguration
{
    internal const string DefaultServerUrl = "https://vault.bitwarden.com";
    internal const string DefaultTokenEnv = "BWS_ACCESS_TOKEN";
    internal const string TokenPrefix = "WITH_SECRETS_BITWARDEN_TOKEN_";
    internal const string ServerSuffix = "_SERVER_URL";
    private static readonly Regex AccountName = new(@"^[A-Z][A-Z0-9_]{0,63}\z", RegexOptions.CultureInvariant);

    public string TokenEnv { get; private set; } = DefaultTokenEnv;
    public string ServerUrl { get; private set; } = DefaultServerUrl;

    public void Load(JsonDocument document)
    {
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw Invalid();
        }

        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (JsonProperty property in document.RootElement.EnumerateObject())
        {
            if (property.Name is not ("tokenEnv" or "serverUrl")
                || property.Value.ValueKind != JsonValueKind.String
                || !fields.TryAdd(property.Name, property.Value.GetString()!))
            {
                throw Invalid();
            }
        }

        TokenEnv = fields.GetValueOrDefault("tokenEnv", DefaultTokenEnv);
        ServerUrl = fields.GetValueOrDefault("serverUrl", DefaultServerUrl);
    }

    private static ProviderAdapterException Invalid()
        => new(ProviderErrorKind.InvalidConfiguration, "Bitwarden configuration accepts a token environment variable name and a server URL.");

    internal static bool IsTokenEnvironmentName(string name)
        => name == DefaultTokenEnv || (name.Length > TokenPrefix.Length && name.StartsWith(TokenPrefix, StringComparison.Ordinal)
            && !name.EndsWith(ServerSuffix, StringComparison.Ordinal) && AccountName.IsMatch(name));

    internal static Uri? ParseServerUrl(string value)
        => Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) && uri.Scheme == Uri.UriSchemeHttps && uri.Host.Length != 0
            && uri.IsWellFormedOriginalString() && uri.UserInfo.Length == 0 && uri.Query.Length == 0 && uri.Fragment.Length == 0
            ? uri : null;

    internal static string ServerArgument(Uri uri) => uri.AbsoluteUri.TrimEnd('/');
}

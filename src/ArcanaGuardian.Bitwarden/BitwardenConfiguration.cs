using System.Text.Json;

namespace ArcanaGuardian.Bitwarden;

public sealed class BitwardenConfiguration : IAdapterConfiguration
{
    public string ServerUrl { get; private set; } = "";
    public string EncryptedConfiguration { get; private set; } = "";

    public void Load(JsonDocument document)
    {
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw Invalid();
        }

        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (JsonProperty property in document.RootElement.EnumerateObject())
        {
            if (property.Name is not ("serverUrl" or "encryptedConfiguration")
                || property.Value.ValueKind != JsonValueKind.String
                || !fields.TryAdd(property.Name, property.Value.GetString()!))
            {
                throw Invalid();
            }
        }

        if (!fields.TryGetValue("encryptedConfiguration", out string? encrypted) || !JweCipher.IsCiphertext(encrypted)
            || !fields.TryGetValue("serverUrl", out string? serverUrl))
            throw Invalid();
        EncryptedConfiguration = encrypted;
        ServerUrl = serverUrl;
    }

    private static ProviderAdapterException Invalid()
        => new(ProviderErrorKind.InvalidConfiguration, "Bitwarden configuration requires a sealed access token and a server URL.");

    internal static string? ReadToken(string? plaintext, Uri server)
    {
        if (plaintext is null) return null;
        try
        {
            using JsonDocument document = JsonDocument.Parse(plaintext);
            JsonElement root = document.RootElement;
            return root.ValueKind == JsonValueKind.Object
                && root.TryGetProperty("serverUrl", out JsonElement origin) && origin.ValueKind == JsonValueKind.String
                && string.Equals(origin.GetString(), ServerArgument(server), StringComparison.Ordinal)
                && root.TryGetProperty("bitwardenAccessToken", out JsonElement token) && token.ValueKind == JsonValueKind.String
                ? token.GetString() : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    internal static Uri? ParseServerUrl(string value)
        => Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) && uri.Scheme == Uri.UriSchemeHttps && uri.Host.Length != 0
            && uri.IsWellFormedOriginalString() && uri.UserInfo.Length == 0 && uri.Query.Length == 0 && uri.Fragment.Length == 0
            ? uri : null;

    internal static string ServerArgument(Uri uri) => uri.AbsoluteUri.TrimEnd('/');
}

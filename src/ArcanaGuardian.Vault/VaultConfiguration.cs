using System.Text.Json;

namespace ArcanaGuardian.Vault;

public sealed class VaultConfiguration : IAdapterConfiguration
{

    public string EncryptedConfiguration { get; private set; } = "";

    public void Load(JsonDocument document)
    {
        JsonElement root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object
            || root.GetPropertyCount() != 1
            || !root.TryGetProperty("encryptedConfiguration", out JsonElement value)
            || value.ValueKind != JsonValueKind.String)
        {
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "Vault configuration accepts only an encrypted configuration.");
        }

        EncryptedConfiguration = value.GetString()!;
    }

    internal bool IsEncrypted => JweCipher.IsCiphertext(EncryptedConfiguration);

    internal static bool ValidToken(string? token)
        => token is { Length: > 0 and <= 2000 }
            && token.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-' or '=' or '+' or '/');

    internal static string? ReadToken(string? plaintext)
    {
        if (plaintext is null)
        {
            return null;
        }

        try
        {
            using JsonDocument contents = JsonDocument.Parse(plaintext);
            if (contents.RootElement.ValueKind == JsonValueKind.Object
                && contents.RootElement.TryGetProperty("token", out JsonElement entry)
                && entry.ValueKind == JsonValueKind.String && ValidToken(entry.GetString()))
            {
                return entry.GetString();
            }
        }
        catch (JsonException)
        {
        }

        return null;
    }
}

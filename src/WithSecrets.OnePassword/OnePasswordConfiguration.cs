using System.Text.Json;

namespace WithSecrets.OnePassword;

public sealed class OnePasswordConfiguration : IAdapterConfiguration
{
    public string EncryptedConfiguration { get; private set; } = "";

    public void Load(JsonDocument document)
    {
        if (document.RootElement.ValueKind != JsonValueKind.Object
            || document.RootElement.EnumerateObject().Any(property => property.Name != "encryptedConfiguration"))
        {
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "1Password configuration accepts only an encrypted configuration.");
        }

        EncryptedConfiguration = Read(document.RootElement, "encryptedConfiguration");
    }

    private static string Read(JsonElement root, string name)
        => root.ValueKind == JsonValueKind.Object && root.TryGetProperty(name, out JsonElement value)
            && value.ValueKind == JsonValueKind.String ? value.GetString()! : "";

}

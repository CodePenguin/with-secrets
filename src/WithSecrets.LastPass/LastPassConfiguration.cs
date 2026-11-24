using System.Text.Json;

namespace WithSecrets.LastPass;

/// <summary>
/// The LastPass account name and the authority-sealed master password. The password is written only by the admin
/// app's seal endpoint and is never a plain field in the stored configuration.
/// </summary>
public sealed class LastPassConfiguration : IAdapterConfiguration
{
    public string Username { get; private set; } = "";

    public string EncryptedConfiguration { get; private set; } = "";

    public void Load(JsonDocument document)
    {
        if (document.RootElement.ValueKind != JsonValueKind.Object
            || document.RootElement.EnumerateObject().Any(property => property.Name is not ("username" or "encryptedConfiguration")))
        {
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "LastPass configuration accepts only a username and an encrypted configuration.");
        }

        Username = Read(document.RootElement, "username");
        EncryptedConfiguration = Read(document.RootElement, "encryptedConfiguration");
    }

    private static string Read(JsonElement root, string name)
        => root.ValueKind == JsonValueKind.Object && root.TryGetProperty(name, out JsonElement value)
            && value.ValueKind == JsonValueKind.String ? value.GetString()! : "";
}

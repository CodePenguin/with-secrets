using System.Security.Cryptography;
using System.Text.Json;

namespace ArcanaGuardian;

internal static class SealedPrf
{
    internal static bool TryOpen(string? json, byte[] serverState, byte[] bind, string proof, out Unlock? unlock)
    {
        unlock = null;
        byte[]? output = null;
        try
        {
            if (json is null || PasskeyMethod.ResponseId(proof) is not { } credentialId) return false;
            using JsonDocument document = JsonDocument.Parse(json);
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return false;
            string? epk = null, iv = null, ct = null;
            int count = 0;
            foreach (JsonProperty property in root.EnumerateObject())
            {
                count++;
                if (property.Name == "epk" && epk is null && property.Value.ValueKind == JsonValueKind.String) epk = property.Value.GetString();
                else if (property.Name == "iv" && iv is null && property.Value.ValueKind == JsonValueKind.String) iv = property.Value.GetString();
                else if (property.Name == "ct" && ct is null && property.Value.ValueKind == JsonValueKind.String) ct = property.Value.GetString();
                else return false;
            }
            if (count != 3 || string.IsNullOrEmpty(epk) || string.IsNullOrEmpty(iv) || string.IsNullOrEmpty(ct)) return false;
            output = SecretCrypto.DecryptBytes(serverState, bind, epk, iv, ct, SecretCrypto.PrfInfo);
            if (output.Length != KeyVault.KeyBytes) return false;
            unlock = new Unlock(credentialId, output);
            output = null;
            return true;
        }
        catch (Exception error) when (error is not OutOfMemoryException) { return false; }
        finally { if (output is not null) CryptographicOperations.ZeroMemory(output); }
    }
}

using System.Text.Json;

namespace WithSecrets;

/// <summary>A passkey assertion over a batch of ciphertext hashes and the state it updates.</summary>
internal sealed record SignedSecretWrite(string Text, byte[] Bind, string Proof)
{
    private const string Domain = "with-secrets secret write v1\n";
    private static readonly JsonDocumentOptions Strict = new() { AllowDuplicateProperties = false, MaxDepth = 2 };

    internal static string Prepare(Manifest current, IReadOnlyDictionary<string, string> rows)
    {
        SortedDictionary<string, string> hashes = new(StringComparer.Ordinal);
        foreach ((string name, string ciphertext) in rows)
        {
            hashes.Add(name, SecretStore.Hash(ciphertext));
        }

        return Header(current) + JsonSerializer.Serialize(hashes);
    }

    private static string Header(Manifest current) => Domain + SecretStore.Hash(current.Canonical()) + "\n";

    /// <summary>Verifies the assertion against the current enrollment and applies only additions and replacements.</summary>
    internal Manifest? Verify(Manifest current)
    {
        string header = Header(current);
        if (current.Store.Length == 0 || Bind.Length != 64 || !Text.StartsWith(header, StringComparison.Ordinal)
            || PasskeyMethod.ResponseId(Proof) is not { } id || current.Keys.FirstOrDefault(key => key.Id == id) is not { } signer)
        {
            return null;
        }

        using JsonDocument document = JsonDocument.Parse(Text.AsMemory(header.Length), Strict);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        Dictionary<string, string> hashes = new(current.Secrets, StringComparer.Ordinal);
        int count = 0;
        foreach (JsonProperty property in document.RootElement.EnumerateObject())
        {
            if (++count > SecretEntry.MaxNames || !SecretNames.IsValid(property.Name) || property.Value.ValueKind != JsonValueKind.String
                || property.Value.GetString() is not { Length: 64 } hash || hash.Any(c => c is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
            {
                return null;
            }

            hashes[property.Name] = hash;
        }

        return count != 0 && WebAuthn.VerifyStored(signer.Record(0), Manifest.Challenge(Bind, Text), Proof).Ok
            ? current.WithSecrets(current.Store, hashes)
            : null;
    }
}

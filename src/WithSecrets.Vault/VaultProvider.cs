using System.Text.Json;

namespace WithSecrets.Vault;

public static class VaultProvider
{
    public const string AddressVariable = "WITH_SECRETS_VAULT_ADDR";
    public const string MountVariable = "WITH_SECRETS_VAULT_MOUNT";
    public const string NamespaceVariable = "WITH_SECRETS_VAULT_NAMESPACE";

    public static void Register(ProviderRegistry registry, AuthorityLock authorityLock, ReviewKeys review,
        string address, string mount, string? vaultNamespace)
    {
        registry.RegisterType(VaultAdapter.ProviderType, VaultAdapter.AdapterVersion,
            () => new VaultAdapter(address, mount, vaultNamespace, () => authorityLock.UnlockSessionToken, (ciphertext, cancellationToken) =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                authorityLock.EnsureUnlocked();
                if (!review.IsOpen)
                {
                    throw new ProviderAdapterException(ProviderErrorKind.InteractionRequired,
                        "Open the authority review key with an administrator passkey to use HashiCorp Vault.");
                }

                return ValueTask.FromResult(review.TryDecryptCurrent(ciphertext));
            }),
            () => new VaultConfiguration());
    }

    public static string SealConfiguration(string token, string reviewPublicKey)
    {
        if (!VaultConfiguration.ValidToken(token))
        {
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "Enter a valid Vault token.");
        }

        string ciphertext = JweCipher.Instance.Encrypt(JsonSerializer.Serialize(new { token }), reviewPublicKey);
        return JsonSerializer.Serialize(new { encryptedConfiguration = ciphertext });
    }
}

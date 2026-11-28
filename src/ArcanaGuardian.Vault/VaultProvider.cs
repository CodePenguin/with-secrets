using System.Text.Json;

namespace ArcanaGuardian.Vault;

public static class VaultProvider
{
    public const string AddressVariable = "ARCANA_GUARDIAN_VAULT_ADDR";
    public const string MountVariable = "ARCANA_GUARDIAN_VAULT_MOUNT";
    public const string NamespaceVariable = "ARCANA_GUARDIAN_VAULT_NAMESPACE";

    public static void Register(ProviderRegistry registry, AuthorityLock authorityLock, UnlockedKeys keys,
        string address, string mount, string? vaultNamespace)
    {
        registry.RegisterType(VaultAdapter.ProviderType, VaultAdapter.AdapterVersion,
            () => new VaultAdapter(address, mount, vaultNamespace, () => authorityLock.UnlockSessionToken, (ciphertext, cancellationToken) =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                authorityLock.EnsureUnlocked();
                if (!keys.IsOpen)
                {
                    throw new ProviderAdapterException(ProviderErrorKind.InteractionRequired,
                        "Unlock the authority with an administrator passkey to use HashiCorp Vault.");
                }

                return ValueTask.FromResult(keys.TryDecryptCurrentReview(ciphertext));
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

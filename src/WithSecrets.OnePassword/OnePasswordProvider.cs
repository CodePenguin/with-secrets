using System.Text.Json;

namespace WithSecrets.OnePassword;

/// <summary>Local-authority composition and provisioning for the bundled 1Password provider.</summary>
public static class OnePasswordProvider
{
    public const string ExecutableVariable = "WITH_SECRETS_ONEPASSWORD_EXECUTABLE";

    public static void Register(ProviderRegistry registry, AuthorityLock authorityLock, ReviewKeys review, string executablePath)
    {
        registry.RegisterType(OnePasswordAdapter.ProviderType, OnePasswordAdapter.AdapterVersion,
            () => new OnePasswordAdapter(executablePath, () => authorityLock.UnlockSessionToken, (ciphertext, cancellationToken) =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                authorityLock.EnsureUnlocked();
                if (!review.IsOpen)
                {
                    throw new ProviderAdapterException(ProviderErrorKind.InteractionRequired,
                        "Open the authority review key with an administrator passkey to use 1Password.");
                }

                return ValueTask.FromResult(review.TryDecryptCurrent(ciphertext));
            }),
            () => new OnePasswordConfiguration());
    }

    /// <summary>Seals the provider-specific configuration to the authority's public review key.</summary>
    public static string SealConfiguration(string token, string reviewPublicKey)
    {
        if (!OnePasswordAdapter.IsServiceAccountToken(token))
        {
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "Enter a valid 1Password service-account token.");
        }

        string ciphertext = DotenvxCipher.Instance.Encrypt(JsonSerializer.Serialize(new { serviceAccountToken = token }), reviewPublicKey);
        return JsonSerializer.Serialize(new { encryptedConfiguration = ciphertext });
    }
}

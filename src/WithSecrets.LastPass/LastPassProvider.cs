using System.Text.Json;

namespace WithSecrets.LastPass;

/// <summary>Local-authority composition and provisioning for the bundled LastPass provider.</summary>
public static class LastPassProvider
{
    public const string ExecutableVariable = "WITH_SECRETS_LASTPASS_EXECUTABLE";

    public static void Register(ProviderRegistry registry, AuthorityLock authorityLock, ReviewKeys review, string executablePath)
    {
        registry.RegisterType(LastPassAdapter.ProviderType, LastPassAdapter.AdapterVersion,
            () => new LastPassAdapter(executablePath, () => authorityLock.UnlockSessionToken, (ciphertext, cancellationToken) =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                authorityLock.EnsureUnlocked();
                if (!review.IsOpen)
                {
                    throw new ProviderAdapterException(ProviderErrorKind.InteractionRequired,
                        "Open the authority review key with an administrator passkey to use LastPass.");
                }

                return ValueTask.FromResult(review.TryDecryptCurrent(ciphertext));
            }),
            () => new LastPassConfiguration());
    }

    /// <summary>Seals the write-only master password to the authority's public review key.</summary>
    public static string SealConfiguration(string username, string masterPassword, string reviewPublicKey)
    {
        if (!LastPassAdapter.IsUsername(username))
        {
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "Enter a valid LastPass account username.");
        }

        if (!LastPassAdapter.IsMasterPassword(masterPassword))
        {
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "Enter a valid LastPass master password.");
        }

        string ciphertext = DotenvxCipher.Instance.Encrypt(JsonSerializer.Serialize(new { masterPassword }), reviewPublicKey);
        return JsonSerializer.Serialize(new { username, encryptedConfiguration = ciphertext });
    }
}

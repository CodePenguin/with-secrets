using System.Text.Json;

namespace ArcanaGuardian.Bitwarden;

/// <summary>Registers Bitwarden on the local authority.</summary>
public static class BitwardenProvider
{
    public static void Register(ProviderRegistry registry, AuthorityLock authorityLock, UnlockedKeys keys)
    {
        string executableName = OperatingSystem.IsWindows() ? "bws.exe" : "bws";
        string executablePath = ProgramResolver.Resolve(executableName, AppContext.BaseDirectory, pathExt: ".EXE") ?? "";
        Register(registry, authorityLock, executablePath, keys.TryDecryptCurrentReview);
    }

    internal static void Register(ProviderRegistry registry, AuthorityLock authorityLock, string executablePath, Func<string, string?> decryptConfiguration)
    {
        registry.RegisterType(BitwardenAdapter.ProviderType, BitwardenAdapter.AdapterVersion,
            () => new BitwardenAdapter(executablePath, decryptConfiguration, () => authorityLock.UnlockSessionToken),
            () => new BitwardenConfiguration());
    }

    public static string SealConfiguration(string token, string serverUrl, string reviewPublicKey)
    {
        if (token.Length == 0 || token.Any(ch => ch is <= ' ' or > '~')
            || BitwardenConfiguration.ParseServerUrl(serverUrl) is not { } server)
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "Enter a Bitwarden access token and HTTPS server URL.");

        string boundServer = BitwardenConfiguration.ServerArgument(server);
        string ciphertext = JweCipher.Instance.Encrypt(JsonSerializer.Serialize(new { bitwardenAccessToken = token, serverUrl = boundServer }), reviewPublicKey);
        return JsonSerializer.Serialize(new { serverUrl = boundServer, encryptedConfiguration = ciphertext });
    }
}

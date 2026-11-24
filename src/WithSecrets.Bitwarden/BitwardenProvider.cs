namespace WithSecrets.Bitwarden;

/// <summary>Registers Bitwarden on the local authority using the service account's environment.</summary>
public static class BitwardenProvider
{
    public static void Register(ProviderRegistry registry, AuthorityLock authorityLock)
    {
        string executableName = OperatingSystem.IsWindows() ? "bws.exe" : "bws";
        string executablePath = ProgramResolver.Resolve(executableName, AppContext.BaseDirectory, pathExt: ".EXE") ?? "";
        Register(registry, authorityLock, executablePath);
    }

    internal static void Register(ProviderRegistry registry, AuthorityLock authorityLock, string executablePath)
    {
        registry.RegisterType(BitwardenAdapter.ProviderType, BitwardenAdapter.AdapterVersion,
            () => new BitwardenAdapter(executablePath, ResolveCredential, () => authorityLock.UnlockSessionToken),
            () => new BitwardenConfiguration());
    }

    internal static string? ResolveCredential(string tokenEnv, Uri server)
    {
        if (!BitwardenConfiguration.IsTokenEnvironmentName(tokenEnv))
        {
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "Use a Bitwarden token environment variable name.");
        }

        // Provider rows are not sealed. Bind each credential to a service-controlled endpoint before reading it.
        string allowed = Environment.GetEnvironmentVariable(tokenEnv + BitwardenConfiguration.ServerSuffix) ?? BitwardenConfiguration.DefaultServerUrl;
        if (BitwardenConfiguration.ParseServerUrl(allowed) is not { } trusted
            || !string.Equals(BitwardenConfiguration.ServerArgument(trusted), BitwardenConfiguration.ServerArgument(server), StringComparison.Ordinal))
        {
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration,
                "The server URL does not match the Bitwarden endpoint configured for this token variable.", "server-url-mismatch");
        }

        return Environment.GetEnvironmentVariable(tokenEnv);
    }
}

namespace WithSecrets.LastPass;

/// <summary>Registers the terminal refresh provider with a local authority.</summary>
public static class LastPassProvider
{
    public const string InteractiveType = "lastpass-refresh";

    public static void RegisterInteractive(ProviderRegistry registry)
        => registry.RegisterType(InteractiveType, "1", () => new LastPassInteractiveAdapter(), () => new LastPassInteractiveConfiguration(), interactive: true);
}

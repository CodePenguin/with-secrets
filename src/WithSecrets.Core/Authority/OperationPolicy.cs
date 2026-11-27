namespace WithSecrets;

/// <summary>Which sensitive operations any enrolled passkey may authorize.</summary>
public static class OperationPolicy
{
    public static bool AnyKey(string? operation) => operation is AdminService.OpLogin or "grant-extend" or "grant-renew" or "grant-replace" or "grant-revoke";

    internal static bool IsSessionControl(string? operation) => operation is "session-resume-editing" or "session-lock-editing";

    internal static string SessionCapability(string? operation) => operation == SecretFlows.SetCommand
        ? SessionCapabilities.SecretsWrite
        : AnyKey(operation) ? SessionCapabilities.GrantsDecide : SessionCapabilities.AdminDecide;
}

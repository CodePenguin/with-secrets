using System.Text.Json;

using Microsoft.Extensions.Logging;

namespace ArcanaGuardian;

// The provider adapter contract (docs/architecture.md 10.3.1 and 10.3.4). Adapters run in process with the authority, are read-only with respect to provider data,
// and never own the cache or its timestamps. The core depends only on these types.

/// <summary>The common error categories. Core behavior depends only on the kind, never on provider-specific types or message text.</summary>
public enum ProviderErrorKind
{
    Unavailable,
    RateLimited,
    AuthenticationFailed,
    InteractionRequired,
    AccessDenied,
    SecretNotFound,
    InvalidConfiguration,
    InvalidResponse,
    Unknown,
}

/// <summary>A provider failure translated by an adapter. Messages never carry secret values, credentials or raw provider response bodies.</summary>
public sealed class ProviderAdapterException : Exception
{
    public ProviderAdapterException(
        ProviderErrorKind kind,
        string message,
        string? providerCode = null,
        TimeSpan? retryAfter = null,
        Exception? innerException = null)
        : base(message, innerException)
    {
        Kind = kind;
        ProviderCode = providerCode;
        RetryAfter = retryAfter;
    }

    public ProviderErrorKind Kind { get; }

    public string? ProviderCode { get; }

    public TimeSpan? RetryAfter { get; }
}

public enum ValidationSeverity
{
    Error,
    Warning,
}

public sealed record ProviderValidationIssue(
    string Message,
    ValidationSeverity Severity,
    string? Target = null,
    string? ProviderCode = null);

/// <summary>Lifecycle and health are independent. The authority sets Initializing and ShuttingDown; the adapter may report Ready or Unavailable.</summary>
public enum AdapterLifecycleState
{
    Initializing,
    Ready,
    Unavailable,
    ShuttingDown,
}

public enum AdapterHealthState
{
    Initializing,
    Healthy,
    Degraded,
    Unavailable,
    Misconfigured,
}

public interface IAdapterStatusReporter
{
    void Report(AdapterStatusEvent statusEvent);
}

public abstract record AdapterStatusEvent;

public sealed record LifecycleChangedEvent(
    AdapterLifecycleState State,
    string? Message = null) : AdapterStatusEvent;

public sealed record HealthChangedEvent(
    AdapterHealthState State,
    string? Message = null) : AdapterStatusEvent;

public sealed record InvalidateProviderDataEvent(
    IReadOnlyList<Guid>? MountIds = null,
    IReadOnlyList<string>? ExternalSecretIds = null,
    bool InvalidateEntireProviderInstance = false) : AdapterStatusEvent;

public sealed record AdapterInitializationContext(
    Guid InstanceId,
    string ProviderType,
    string AdapterVersion,
    ILogger Logger,
    IAdapterStatusReporter StatusReporter);

public sealed record ProviderSecretRequest(
    Guid RequestId,
    string Path);

public sealed record RetrieveSecretResult(byte[] Value);

public sealed record ProviderSecretResult(
    Guid RequestId,
    RetrieveSecretResult? Secret,
    ProviderErrorKind? ErrorKind = null,
    string? ProviderCode = null,
    TimeSpan? RetryAfter = null);

public sealed record ListSecretsRequest(
    string Path,
    string? Filter,
    string? ContinuationToken);

public sealed record ListSecretsResult(
    IReadOnlyList<ProviderSecretInfo> Secrets,
    string? NextContinuationToken,
    bool IsComplete);

public sealed record ProviderSecretInfo(
    string Path,
    string ExternalSecretId,
    string? Description);

public enum DescriptionSource
{
    Provider,
    Local,
}

/// <summary>A provider adapter's strongly typed configuration. JSON is only the persistence format.</summary>
public interface IAdapterConfiguration
{
    void Load(JsonDocument document);
}

public interface IProviderMountBrowser
{
    Task<IReadOnlyList<ProviderMountOption>> BrowseMountOptionsAsync(string? parentPath, CancellationToken cancellationToken);
}

public sealed record ProviderMountOption(string Path, string Name);

public interface IProviderAdapter
{
    Type ConfigurationType { get; }

    Task InitializeAsync(
        IAdapterConfiguration configuration,
        AdapterInitializationContext context,
        CancellationToken cancellationToken);

    Task UpdateConfigurationAsync(
        IAdapterConfiguration configuration,
        CancellationToken cancellationToken);

    Task ShutdownAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<ProviderValidationIssue>> ValidateConfigurationAsync(
        IAdapterConfiguration configuration,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<ProviderValidationIssue>> ValidateMountAsync(
        IAdapterConfiguration configuration,
        string basePath,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<ProviderValidationIssue>> ValidateMountAsync(
        IAdapterConfiguration configuration,
        string basePath,
        MountKind? kind,
        CancellationToken cancellationToken)
        => ValidateMountAsync(configuration, basePath, cancellationToken);

    Task<IReadOnlyList<ProviderSecretResult>> RetrieveSecretsAsync(
        IReadOnlyList<ProviderSecretRequest> requests,
        CancellationToken cancellationToken);

    Task<ListSecretsResult> ListSecretsAsync(
        ListSecretsRequest request,
        CancellationToken cancellationToken);
}

/// <summary>
/// Typed configuration storage, type checking and dispatch only: the untyped contract methods cast the configuration to <typeparamref name="TConfiguration" />
/// (or fail as <see cref="ProviderErrorKind.InvalidConfiguration" />) and call the typed methods. It manages no provider connection, recovery or rollback.
/// </summary>
public abstract class ProviderAdapter<TConfiguration> : IProviderAdapter
    where TConfiguration : class, IAdapterConfiguration
{
    public Type ConfigurationType => typeof(TConfiguration);

    protected TConfiguration? Configuration { get; private set; }

    public Task InitializeAsync(IAdapterConfiguration configuration, AdapterInitializationContext context, CancellationToken cancellationToken)
    {
        Configuration = Typed(configuration);

        return InitializeAsync(Configuration, context, cancellationToken);
    }

    public Task UpdateConfigurationAsync(IAdapterConfiguration configuration, CancellationToken cancellationToken)
    {
        Configuration = Typed(configuration);

        return UpdateConfigurationAsync(Configuration, cancellationToken);
    }

    public Task<IReadOnlyList<ProviderValidationIssue>> ValidateConfigurationAsync(IAdapterConfiguration configuration, CancellationToken cancellationToken)
        => ValidateConfigurationAsync(Typed(configuration), cancellationToken);

    public Task<IReadOnlyList<ProviderValidationIssue>> ValidateMountAsync(IAdapterConfiguration configuration, string basePath, CancellationToken cancellationToken)
        => ValidateMountAsync(Typed(configuration), basePath, cancellationToken);

    public Task<IReadOnlyList<ProviderValidationIssue>> ValidateMountAsync(
        IAdapterConfiguration configuration, string basePath, MountKind? kind, CancellationToken cancellationToken)
        => ValidateMountAsync(Typed(configuration), basePath, kind, cancellationToken);

    protected virtual Task<IReadOnlyList<ProviderValidationIssue>> ValidateMountAsync(
        TConfiguration configuration, string basePath, MountKind? kind, CancellationToken cancellationToken)
        => ValidateMountAsync(configuration, basePath, cancellationToken);

    public abstract Task ShutdownAsync(CancellationToken cancellationToken);

    public abstract Task<IReadOnlyList<ProviderSecretResult>> RetrieveSecretsAsync(IReadOnlyList<ProviderSecretRequest> requests, CancellationToken cancellationToken);

    public abstract Task<ListSecretsResult> ListSecretsAsync(ListSecretsRequest request, CancellationToken cancellationToken);

    protected abstract Task InitializeAsync(TConfiguration configuration, AdapterInitializationContext context, CancellationToken cancellationToken);

    protected abstract Task UpdateConfigurationAsync(TConfiguration configuration, CancellationToken cancellationToken);

    protected abstract Task<IReadOnlyList<ProviderValidationIssue>> ValidateConfigurationAsync(TConfiguration configuration, CancellationToken cancellationToken);

    protected abstract Task<IReadOnlyList<ProviderValidationIssue>> ValidateMountAsync(TConfiguration configuration, string basePath, CancellationToken cancellationToken);

    private static TConfiguration Typed(IAdapterConfiguration configuration)
        => configuration as TConfiguration
            ?? throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "The adapter was given a configuration of the wrong type.");
}

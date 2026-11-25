using System.Text.Json;

namespace WithSecrets.LastPass;

public sealed class LastPassInteractiveConfiguration : IAdapterConfiguration
{
    public string Username { get; private set; } = "";
    public bool European { get; private set; }

    public void Load(JsonDocument document)
    {
        JsonElement root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Any(property => property.Name is not ("username" or "european"))
            || !root.TryGetProperty("username", out JsonElement name) || name.ValueKind != JsonValueKind.String
            || !LastPassRefreshSelection.IsAccount(name.GetString())
            || (root.TryGetProperty("european", out JsonElement region) && region.ValueKind is not (JsonValueKind.True or JsonValueKind.False)))
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "Enter a LastPass email address and choose its region.");
        Username = name.GetString()!;
        European = root.TryGetProperty("european", out region) && region.GetBoolean();
    }
}

internal sealed class LastPassInteractiveAdapter : ProviderAdapter<LastPassInteractiveConfiguration>, IInteractiveProviderAdapter
{
    public (string Account, bool European) ReadAccount(string configuration)
    {
        using JsonDocument json = JsonDocument.Parse(configuration);
        LastPassInteractiveConfiguration account = new();
        account.Load(json);
        return (account.Username, account.European);
    }

    protected override Task InitializeAsync(LastPassInteractiveConfiguration configuration, AdapterInitializationContext context, CancellationToken cancellationToken)
    {
        context.StatusReporter.Report(new LifecycleChangedEvent(AdapterLifecycleState.Ready));
        context.StatusReporter.Report(new HealthChangedEvent(AdapterHealthState.Healthy));
        return Task.CompletedTask;
    }

    protected override Task UpdateConfigurationAsync(LastPassInteractiveConfiguration configuration, CancellationToken cancellationToken)
        => Task.CompletedTask;

    public override Task ShutdownAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    protected override Task<IReadOnlyList<ProviderValidationIssue>> ValidateConfigurationAsync(
        LastPassInteractiveConfiguration configuration, CancellationToken cancellationToken)
        => Task.FromResult<IReadOnlyList<ProviderValidationIssue>>([]);

    protected override Task<IReadOnlyList<ProviderValidationIssue>> ValidateMountAsync(
        LastPassInteractiveConfiguration configuration, string basePath, CancellationToken cancellationToken)
        => ValidateMountAsync(configuration, basePath, MountKind.Single, cancellationToken);

    protected override Task<IReadOnlyList<ProviderValidationIssue>> ValidateMountAsync(
        LastPassInteractiveConfiguration configuration, string basePath, MountKind? kind, CancellationToken cancellationToken)
        => Task.FromResult<IReadOnlyList<ProviderValidationIssue>>(kind != MountKind.Tree && LastPassRefreshSelection.IsPath(basePath)
            ? []
            : [new("Mount a single LastPass item field by its numeric item ID and field path.", ValidationSeverity.Error)]);

    public override Task<ListSecretsResult> ListSecretsAsync(ListSecretsRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string path = request.Path + "/" + request.Filter;
        return Task.FromResult(request.ContinuationToken is null && LastPassRefreshSelection.IsPath(path)
            ? new ListSecretsResult([new(request.Filter!, path, null)], null, true)
            : new ListSecretsResult([], null, false));
    }

    public override Task<IReadOnlyList<ProviderSecretResult>> RetrieveSecretsAsync(
        IReadOnlyList<ProviderSecretRequest> requests, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult<IReadOnlyList<ProviderSecretResult>>(
            [.. requests.Select(request => new ProviderSecretResult(request.RequestId, null, ProviderErrorKind.InteractionRequired))]);
    }
}

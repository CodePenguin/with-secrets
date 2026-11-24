using System.Text;
using System.Text.Json;

namespace WithSecrets.Tests;

/// <summary>The fake adapter's configuration: <c>{"label": "..."}</c>.</summary>
internal class FakeConfiguration : IAdapterConfiguration
{
    public string Label { get; private set; } = "";

    public virtual void Load(JsonDocument document) => Label = document.RootElement.GetProperty("label").GetString() ?? "";
}

/// <summary>A configuration whose Load fails with a message that quotes the input (as a careless adapter's might).</summary>
internal sealed class LeakyConfiguration : FakeConfiguration
{
    public override void Load(JsonDocument document) => throw new ArgumentException("bad value hunter2");
}

/// <summary>A configuration type the fake adapter does not accept.</summary>
internal sealed class OtherConfiguration : IAdapterConfiguration
{
    public void Load(JsonDocument document)
    {
    }
}

/// <summary>
/// A scripted adapter for the provider tests. Records every call; retrieval is scripted by provider path: value bytes, an item error kind, or an
/// exception to throw (a batch-wide failure). A path with no script is an item SecretNotFound.
/// </summary>
internal sealed class FakeProviderAdapter : ProviderAdapter<FakeConfiguration>
{
    private readonly object _gate = new();
    private readonly Dictionary<string, Func<ProviderSecretResult, ProviderSecretResult>> _script = new(StringComparer.Ordinal);

    public List<string> Calls { get; } = [];

    /// <summary>The requests of every RetrieveSecretsAsync invocation, in order.</summary>
    public List<IReadOnlyList<ProviderSecretRequest>> Invocations { get; } = [];

    /// <summary>Every ListSecretsAsync request, in order.</summary>
    public List<ListSecretsRequest> ListRequests { get; } = [];

    /// <summary>When set, answers ListSecretsAsync (default: an empty complete listing).</summary>
    public Func<ListSecretsRequest, CancellationToken, Task<ListSecretsResult>>? ListHandler { get; set; }

    public IAdapterStatusReporter? Reporter { get; private set; }

    public AdapterInitializationContext? Context { get; private set; }

    public string? CurrentLabel => Configuration?.Label;

    /// <summary>What the adapter reports as it initializes (default: lifecycle Ready).</summary>
    public Action<IAdapterStatusReporter>? OnInitialize { get; set; } = reporter => reporter.Report(new LifecycleChangedEvent(AdapterLifecycleState.Ready));

    public Action<IAdapterStatusReporter>? OnUpdate { get; set; } = reporter => reporter.Report(new HealthChangedEvent(AdapterHealthState.Initializing));

    public Action<IAdapterStatusReporter>? OnShutdown { get; set; }

    /// <summary>When set, ShutdownAsync returns this task (it may ignore the token, never complete, or fail).</summary>
    public Func<Task>? ShutdownBehavior { get; set; }

    /// <summary>When set, InitializeAsync awaits this (with the token it was given) after reporting.</summary>
    public Func<CancellationToken, Task>? InitializeBehavior { get; set; }

    public FakeProviderAdapter Returns(string path, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        _script[path] = result => result with { Secret = new RetrieveSecretResult(bytes), ErrorKind = null };

        return this;
    }

    public FakeProviderAdapter ReturnsBytes(string path, byte[] bytes)
    {
        _script[path] = result => result with { Secret = new RetrieveSecretResult(bytes), ErrorKind = null };

        return this;
    }

    public FakeProviderAdapter Fails(string path, ProviderErrorKind kind, TimeSpan? retryAfter = null)
    {
        _script[path] = result => result with { Secret = null, ErrorKind = kind, RetryAfter = retryAfter };

        return this;
    }

    public FakeProviderAdapter Throws(string path, ProviderErrorKind kind)
    {
        _script[path] = _ => throw new ProviderAdapterException(kind, "scripted failure");

        return this;
    }

    protected override Task InitializeAsync(FakeConfiguration configuration, AdapterInitializationContext context, CancellationToken cancellationToken)
    {
        Record("initialize");
        Context = context;
        Reporter = context.StatusReporter;
        OnInitialize?.Invoke(context.StatusReporter);

        return InitializeBehavior?.Invoke(cancellationToken) ?? Task.CompletedTask;
    }

    protected override Task UpdateConfigurationAsync(FakeConfiguration configuration, CancellationToken cancellationToken)
    {
        Record("update");
        if (Reporter is not null)
        {
            OnUpdate?.Invoke(Reporter);
        }

        return UpdateBehavior?.Invoke() ?? Task.CompletedTask;
    }

    /// <summary>When set, the result of UpdateConfigurationAsync (a test makes the running adapter refuse a new configuration).</summary>
    public Func<Task>? UpdateBehavior { get; set; }

    /// <summary>When set, answers ValidateConfigurationAsync (default: no issues).</summary>
    public Func<FakeConfiguration, Task<IReadOnlyList<ProviderValidationIssue>>>? ValidateConfigurationHandler { get; set; }

    /// <summary>When set, answers ValidateMountAsync (default: no issues).</summary>
    public Func<FakeConfiguration, string, Task<IReadOnlyList<ProviderValidationIssue>>>? ValidateMountHandler { get; set; }

    protected override Task<IReadOnlyList<ProviderValidationIssue>> ValidateConfigurationAsync(FakeConfiguration configuration, CancellationToken cancellationToken)
    {
        Record("validate-configuration");

        return ValidateConfigurationHandler?.Invoke(configuration) ?? Task.FromResult<IReadOnlyList<ProviderValidationIssue>>([]);
    }

    protected override Task<IReadOnlyList<ProviderValidationIssue>> ValidateMountAsync(FakeConfiguration configuration, string basePath, CancellationToken cancellationToken)
    {
        Record("validate-mount");

        return ValidateMountHandler?.Invoke(configuration, basePath) ?? Task.FromResult<IReadOnlyList<ProviderValidationIssue>>([]);
    }

    public override Task ShutdownAsync(CancellationToken cancellationToken)
    {
        Record("shutdown");
        if (Reporter is not null)
        {
            OnShutdown?.Invoke(Reporter);
        }

        return ShutdownBehavior?.Invoke() ?? Task.CompletedTask;
    }

    /// <summary>When set, replaces the path script: receives the zero-based invocation index, the requests and the token.</summary>
    public Func<int, IReadOnlyList<ProviderSecretRequest>, CancellationToken, Task<IReadOnlyList<ProviderSecretResult>>>? Handler { get; set; }

    public override Task<IReadOnlyList<ProviderSecretResult>> RetrieveSecretsAsync(IReadOnlyList<ProviderSecretRequest> requests, CancellationToken cancellationToken)
    {
        int index;
        lock (_gate)
        {
            Calls.Add("retrieve");
            index = Invocations.Count;
            Invocations.Add(requests);
        }

        if (Handler is not null)
        {
            return Handler(index, requests, cancellationToken);
        }

        List<ProviderSecretResult> results = [];
        foreach (ProviderSecretRequest request in requests)
        {
            ProviderSecretResult blank = new(request.RequestId, null, ProviderErrorKind.SecretNotFound);
            results.Add(_script.TryGetValue(request.Path, out Func<ProviderSecretResult, ProviderSecretResult>? make) ? make(blank) : blank);
        }

        return Task.FromResult<IReadOnlyList<ProviderSecretResult>>(results);
    }

    public override Task<ListSecretsResult> ListSecretsAsync(ListSecretsRequest request, CancellationToken cancellationToken)
    {
        Record("list");
        lock (_gate)
        {
            ListRequests.Add(request);
        }

        return ListHandler is null ? Task.FromResult(new ListSecretsResult([], null, true)) : ListHandler(request, cancellationToken);
    }

    private void Record(string call)
    {
        lock (_gate)
        {
            Calls.Add(call);
        }
    }
}

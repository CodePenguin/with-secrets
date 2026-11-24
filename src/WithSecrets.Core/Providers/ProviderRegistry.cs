using System.Text.Json;

using Microsoft.Extensions.Logging;

namespace WithSecrets;

/// <summary>The latest lifecycle and health of an instance, each with its message and the registry's time of receipt. Nothing here is persisted.</summary>
public sealed record InstanceStatus(
    AdapterLifecycleState Lifecycle,
    string? LifecycleMessage,
    DateTimeOffset LifecycleAt,
    AdapterHealthState Health,
    string? HealthMessage,
    DateTimeOffset HealthAt);

/// <summary>
/// The bundled adapter types and the running provider instances (10.3.1). The registry owns the lifecycle boundary (Initializing, ShuttingDown), stamps every
/// status report with its clock, ignores invalid, stale or post-shutdown reports (logged at Debug, never thrown back to the adapter), and raises
/// <see cref="InvalidationRequested" /> for accepted invalidations.
/// </summary>
public sealed class ProviderRegistry(TimeProvider? clock = null)
{
    private sealed record ProviderType(string AdapterVersion, Func<IProviderAdapter> Factory, Func<IAdapterConfiguration> NewConfiguration);

    private sealed class Instance(Guid id, string providerType, IProviderAdapter adapter, ILogger logger, DateTimeOffset now) : IAdapterStatusReporter
    {
        private readonly object _gate = new();
        private InstanceStatus _status = new(AdapterLifecycleState.Initializing, null, now, AdapterHealthState.Initializing, null, now);
        private bool _shuttingDown;

        public Guid Id { get; } = id;

        public string ProviderType { get; } = providerType;

        public IProviderAdapter Adapter { get; } = adapter;

        public ILogger Logger { get; } = logger;

        public CancellationTokenSource Cancellation { get; } = new();
        public SemaphoreSlim ConfigurationUpdates { get; } = new(1);

        public required ProviderRegistry Owner { get; init; }

        public InstanceStatus Status
        {
            get
            {
                lock (_gate)
                {
                    return _status;
                }
            }
        }

        public bool IsShuttingDown
        {
            get
            {
                lock (_gate)
                {
                    return _shuttingDown;
                }
            }
        }

        /// <summary>True for the first caller only: a later removal of the same instance has nothing to do.</summary>
        public bool BeginShutdown()
        {
            lock (_gate)
            {
                if (_shuttingDown)
                {
                    return false;
                }

                _shuttingDown = true;
                _status = _status with { Lifecycle = AdapterLifecycleState.ShuttingDown, LifecycleMessage = null, LifecycleAt = Owner._clock.GetUtcNow() };

                return true;
            }
        }

        /// <summary>The registry resets health when it applies a new configuration (the adapter also reports it).</summary>
        public void ResetHealth()
        {
            lock (_gate)
            {
                if (!_shuttingDown)
                {
                    _status = _status with { Health = AdapterHealthState.Initializing, HealthMessage = null, HealthAt = Owner._clock.GetUtcNow() };
                }
            }
        }

        /// <summary>After a configuration the adapter took: Ready again (an earlier refused or overrunning update had made it Unavailable).</summary>
        public void SetLifecycleReady()
        {
            lock (_gate)
            {
                if (!_shuttingDown)
                {
                    _status = _status with { Lifecycle = AdapterLifecycleState.Ready, LifecycleMessage = null, LifecycleAt = Owner._clock.GetUtcNow() };
                }
            }
        }

        public void SetLifecycleUnavailable(string message)
        {
            lock (_gate)
            {
                if (!_shuttingDown)
                {
                    _status = _status with { Lifecycle = AdapterLifecycleState.Unavailable, LifecycleMessage = message, LifecycleAt = Owner._clock.GetUtcNow() };
                }
            }
        }

        public void Report(AdapterStatusEvent statusEvent)
        {
            InvalidateProviderDataEvent? accepted = null;
            lock (_gate)
            {
                if (_shuttingDown)
                {
                    Logger.LogDebug("Provider instance {Instance}: a {Event} report after shutdown began was ignored.", Id, statusEvent.GetType().Name);

                    return;
                }

                DateTimeOffset now = Owner._clock.GetUtcNow();
                switch (statusEvent)
                {
                    case LifecycleChangedEvent lifecycle when lifecycle.State is AdapterLifecycleState.Ready or AdapterLifecycleState.Unavailable:
                        _status = _status with { Lifecycle = lifecycle.State, LifecycleMessage = lifecycle.Message, LifecycleAt = now };
                        break;
                    case LifecycleChangedEvent lifecycle:
                        Logger.LogDebug("Provider instance {Instance}: an adapter report of lifecycle {State} was ignored (the registry owns it).", Id, lifecycle.State);
                        break;
                    case HealthChangedEvent health:
                        _status = _status with { Health = health.State, HealthMessage = health.Message, HealthAt = now };
                        break;
                    case InvalidateProviderDataEvent invalidation:
                        accepted = invalidation;
                        break;
                    default:
                        Logger.LogDebug("Provider instance {Instance}: an unknown status event was ignored.", Id);
                        break;
                }
            }

            if (accepted is not null)
            {
                Owner.RaiseInvalidation(this, accepted);
            }
        }
    }

    private static readonly TimeSpan ShutdownDeadline = TimeSpan.FromSeconds(5);

    /// <summary>The most a proposed-configuration validation (initialize, validate configuration, validate mount) takes. For tests: shortened.</summary>
    internal TimeSpan ValidationDeadline { get; set; } = TimeSpan.FromSeconds(10);

    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly object _gate = new();
    private readonly Dictionary<string, ProviderType> _types = new(StringComparer.Ordinal);
    private readonly Dictionary<Guid, Instance> _instances = [];

    /// <summary>Raised for each accepted <see cref="InvalidateProviderDataEvent" />, with the reporting instance's id. Not raised after shutdown began.</summary>
    public event Action<Guid, InvalidateProviderDataEvent>? InvalidationRequested;

    public void RegisterType(string providerType, string adapterVersion, Func<IProviderAdapter> factory, Func<IAdapterConfiguration> newConfiguration)
    {
        lock (_gate)
        {
            if (!_types.TryAdd(providerType, new ProviderType(adapterVersion, factory, newConfiguration)))
            {
                throw new InvalidOperationException($"Provider type '{providerType}' is already registered.");
            }
        }
    }

    /// <summary>
    /// Creates, registers and initializes an instance. Both status dimensions start Initializing. An initialization failure inside the adapter leaves the instance registered with lifecycle Unavailable,
    /// so it can recover; a configuration that cannot be loaded or is of the wrong type is rejected before anything is registered.
    /// </summary>
    public async Task AddInstanceAsync(Guid id, string providerType, string configurationJson, ILogger logger, CancellationToken cancellationToken)
    {
        ProviderType type;
        lock (_gate)
        {
            if (!_types.TryGetValue(providerType, out type!))
            {
                throw new InvalidOperationException($"Provider type '{providerType}' is not registered.");
            }

            if (_instances.ContainsKey(id))
            {
                throw new InvalidOperationException("A provider instance with this id already exists.");
            }
        }

        IProviderAdapter adapter = type.Factory();
        IAdapterConfiguration configuration = LoadConfiguration(adapter, type.NewConfiguration(), configurationJson);
        Instance instance = new(id, providerType, adapter, logger, _clock.GetUtcNow()) { Owner = this };
        lock (_gate)
        {
            if (!_instances.TryAdd(id, instance))
            {
                throw new InvalidOperationException("A provider instance with this id already exists.");
            }
        }

        AdapterInitializationContext context = new(id, providerType, type.AdapterVersion, logger, instance);
        using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, instance.Cancellation.Token);
        try
        {
            await adapter.InitializeAsync(configuration, context, linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Cancelled by the caller or by a removal: leave nothing registered and shut the adapter down.
            if (!instance.IsShuttingDown)
            {
                await RemoveInstanceAsync(id, TimeSpan.FromSeconds(5), CancellationToken.None).ConfigureAwait(false);
            }

            throw;
        }
        catch (Exception exception)
        {
            // The adapter remains registered so it can recover. The message is generic: an exception text could carry provider detail.
            logger.LogWarning("Provider instance {Instance} failed to initialize ({ExceptionType}).", id, exception.GetType().Name);
            instance.SetLifecycleUnavailable("Initialization failed.");
        }
    }

    /// <summary>The registered types with their adapter versions, ordered by type name.</summary>
    public IReadOnlyList<(string Type, string AdapterVersion)> Types()
    {
        lock (_gate)
        {
            return [.. _types.OrderBy(item => item.Key, StringComparer.Ordinal).Select(item => (item.Key, item.Value.AdapterVersion))];
        }
    }

    /// <summary>
    /// Validates a configuration (and, with <paramref name="mountBasePath" />, a mount of it) that nothing has stored: a temporary adapter from the type's factory is
    /// loaded, initialized with a throwaway context, asked, and shut down again, within the start deadline and the shutdown deadline. It is never registered, and it is shut
    /// down whatever happens. An unregistered type, a configuration that cannot be loaded, an initialization or validation that fails or overruns each become ONE Error
    /// issue with a constant message: neither configuration text nor an exception text is ever returned. Only the adapter's own issues are passed on as they are.
    /// </summary>
    public async Task<IReadOnlyList<ProviderValidationIssue>> ValidateProposedAsync(string providerType, string configurationJson, string? mountBasePath, ILogger logger, CancellationToken cancellationToken)
    {
        ProviderType? type;
        lock (_gate)
        {
            _types.TryGetValue(providerType, out type);
        }

        if (type is null)
        {
            return [Refusal("The provider type is not available.")];
        }

        IProviderAdapter? adapter = null;
        try
        {
            adapter = type.Factory();
            IAdapterConfiguration configuration = LoadConfiguration(adapter, type.NewConfiguration(), configurationJson);
            using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            limit.CancelAfter(ValidationDeadline);
            CancellationToken token = limit.Token;
            AdapterInitializationContext context = new(Guid.NewGuid(), providerType, type.AdapterVersion, logger, DiscardingReporter.Instance);
            IProviderAdapter validating = adapter;

            async Task<IReadOnlyList<ProviderValidationIssue>> Ask()
            {
                await validating.InitializeAsync(configuration, context, token).ConfigureAwait(false);
                List<ProviderValidationIssue> issues = [.. await validating.ValidateConfigurationAsync(configuration, token).ConfigureAwait(false)];
                if (mountBasePath is not null)
                {
                    issues.AddRange(await validating.ValidateMountAsync(configuration, mountBasePath, token).ConfigureAwait(false));
                }

                return issues;
            }

            // WaitAsync enforces the one deadline even for an adapter that ignores its token.
            Task<IReadOnlyList<ProviderValidationIssue>> asking = Task.Run(Ask, CancellationToken.None);

            // An abandoned run (deadline, cancellation) may fault later: observe it so it is never an unobserved task exception.
            _ = asking.ContinueWith(done => done.Exception, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default);

            return await asking.WaitAsync(ValidationDeadline, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            // The kind only: the text of a failure can quote the configuration or the provider's response.
            logger.LogWarning("Validating a proposed {Type} configuration failed ({ExceptionType}).", providerType, exception.GetType().Name);

            return [Refusal("The provider could not validate this configuration.")];
        }
        finally
        {
            if (adapter is not null)
            {
                await ShutDownQuietlyAsync(adapter, logger).ConfigureAwait(false);
            }
        }
    }

    private static ProviderValidationIssue Refusal(string message) => new(message, ValidationSeverity.Error);

    private static async Task ShutDownQuietlyAsync(IProviderAdapter adapter, ILogger logger)
    {
        try
        {
            using CancellationTokenSource deadline = new(ShutdownDeadline);
            await adapter.ShutdownAsync(deadline.Token).WaitAsync(ShutdownDeadline).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            logger.LogWarning("A temporary validation adapter did not shut down cleanly ({ExceptionType}).", exception.GetType().Name);
        }
    }

    /// <summary>The status reporter of a validation adapter: nothing it reports is kept.</summary>
    private sealed class DiscardingReporter : IAdapterStatusReporter
    {
        public static readonly DiscardingReporter Instance = new();

        public void Report(AdapterStatusEvent statusEvent)
        {
        }
    }

    /// <summary>
    /// Applies an already committed configuration. Health goes Initializing; the adapter reconnects asynchronously. When the adapter takes it, lifecycle is Ready; when it
    /// refuses it, lifecycle goes Unavailable (with a constant message) and the failure is rethrown.
    /// </summary>
    public Task UpdateInstanceAsync(Guid id, string configurationJson, CancellationToken cancellationToken)
        => UpdateInstanceAsync(id, () => configurationJson, cancellationToken);

    internal async Task UpdateInstanceAsync(Guid id, Func<string> readConfiguration, CancellationToken cancellationToken)
    {
        Instance instance = Active(id);
        ProviderType type;
        lock (_gate)
        {
            type = _types[instance.ProviderType];
        }

        CancellationTokenSource linked;
        try
        {
            linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, instance.Cancellation.Token);
        }
        catch (ObjectDisposedException)
        {
            // Removed between the check and here.
            throw new InvalidOperationException("The provider instance is shutting down.");
        }

        using (linked)
        {
            await instance.ConfigurationUpdates.WaitAsync(linked.Token).ConfigureAwait(false);
            try
            {
                IAdapterConfiguration configuration = LoadConfiguration(instance.Adapter, type.NewConfiguration(), readConfiguration());
                instance.ResetHealth();
                await instance.Adapter.UpdateConfigurationAsync(configuration, linked.Token).ConfigureAwait(false);
                linked.Token.ThrowIfCancellationRequested();
                instance.SetLifecycleReady();
            }
            catch (Exception exception) when (exception is not (OperationCanceledException or OutOfMemoryException))
            {
                // Visible as the instance's status; the kind only goes to the log (an exception text could carry provider detail).
                instance.Logger.LogWarning("Provider instance {Instance} could not apply its new configuration ({ExceptionType}).", id, exception.GetType().Name);
                instance.SetLifecycleUnavailable("The new configuration could not be applied.");

                throw;
            }
            finally
            {
                instance.ConfigurationUpdates.Release();
            }
        }
    }

    /// <summary>
    /// Sets lifecycle ShuttingDown (no new operations, no more status or invalidation reports), cancels background work, calls <c>ShutdownAsync</c> within
    /// <paramref name="shutdownDeadline" />, then forgets the instance. A failing or overrunning shutdown still forgets it. Only the first removal of an instance
    /// does this; a concurrent or later one (while it is still known) returns at once.
    /// </summary>
    public async Task RemoveInstanceAsync(Guid id, TimeSpan shutdownDeadline, CancellationToken cancellationToken)
    {
        Instance instance = Find(id);
        if (!instance.BeginShutdown())
        {
            return;
        }

        try
        {
            await instance.Cancellation.CancelAsync().ConfigureAwait(false);
            using CancellationTokenSource deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(shutdownDeadline);
            try
            {
                // WaitAsync enforces the deadline even for an adapter that ignores its token.
                await instance.Adapter.ShutdownAsync(deadline.Token).WaitAsync(shutdownDeadline, cancellationToken).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                instance.Logger.LogWarning("Provider instance {Id} did not shut down within its deadline.", id);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                instance.Logger.LogWarning("Provider instance {Id} did not shut down within its deadline.", id);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                instance.Logger.LogWarning("Provider instance {Id} failed to shut down cleanly ({ExceptionType}).", id, exception.GetType().Name);
            }
        }
        finally
        {
            lock (_gate)
            {
                _instances.Remove(id);
            }

            instance.Cancellation.Dispose();
        }
    }

    /// <summary>Marks a registered instance Unavailable with a constant message (an update that did not finish within its deadline). Nothing for an unknown instance.</summary>
    internal void MarkUnavailable(Guid id, string message)
    {
        Instance? instance;
        lock (_gate)
        {
            _instances.TryGetValue(id, out instance);
        }

        instance?.SetLifecycleUnavailable(message);
    }

    /// <summary>The adapter of an instance. Throws when the instance is unknown or shutting down.</summary>
    public IProviderAdapter Adapter(Guid id) => Active(id).Adapter;

    public InstanceStatus Status(Guid id) => Find(id).Status;

    private Instance Active(Guid id)
    {
        Instance instance = Find(id);
        if (instance.IsShuttingDown)
        {
            throw new InvalidOperationException("The provider instance is shutting down.");
        }

        return instance;
    }

    private Instance Find(Guid id)
    {
        lock (_gate)
        {
            return _instances.TryGetValue(id, out Instance? instance) ? instance : throw new KeyNotFoundException("Unknown provider instance.");
        }
    }

    private static IAdapterConfiguration LoadConfiguration(IProviderAdapter adapter, IAdapterConfiguration configuration, string json)
    {
        if (!adapter.ConfigurationType.IsInstanceOfType(configuration))
        {
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "The configuration type does not match the adapter.");
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(json);
            configuration.Load(document);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // The text of any failure (a parse error, an adapter's own exception) can quote the input, which may hold a credential: report the kind only.
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "The configuration could not be loaded.");
        }

        return configuration;
    }

    private void RaiseInvalidation(Instance instance, InvalidateProviderDataEvent invalidation)
    {
        try
        {
            InvalidationRequested?.Invoke(instance.Id, invalidation);
        }
        catch (Exception exception)
        {
            instance.Logger.LogWarning("An invalidation handler for provider instance {Id} failed ({ExceptionType}).", instance.Id, exception.GetType().Name);
        }
    }
}

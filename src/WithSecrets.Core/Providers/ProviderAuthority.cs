using Microsoft.Extensions.Logging;

namespace WithSecrets;

/// <summary>
/// The authority's provider side (10.3), composed once per authority process: this machine's service in local mode, the authority's service in remote mode (a host
/// whose authority is remote composes none; its runs get their values from the authority). It holds the provider store over <c>with-secrets.db</c> (whose per-instance
/// generations live in memory, so this process is the only writer of provider data), the cache sealed with the authority key ring, invalidation (subscribed to the
/// registry), bounded retrieval, the source a run reads through (<see cref="ProviderSecretSource" /> over the native store) and the proactive refresher.
/// <see cref="Start" /> adds the stored instances to the registry and starts the refresher; <see cref="Dispose" /> stops it and shuts the instances down. Retrieval
/// outcomes and invalidations are signed host audit events.
/// </summary>
public sealed class ProviderAuthority : IDisposable
{
    private static readonly TimeSpan StartDeadline = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan ShutdownDeadline = TimeSpan.FromSeconds(5);

    /// <summary>The most <see cref="Start" /> takes, however many instances and however their adapters behave: the start deadline plus the shutdown deadline of those that missed it.</summary>
    public static readonly TimeSpan StartBound = StartDeadline + ShutdownDeadline;

    private readonly CancellationTokenSource _stop = new();
    private readonly ILogger _logger = new AppLogLogger();
    private readonly List<Guid> _started = [];
    private Task _refresh = Task.CompletedTask;
    private Task _reconcile = Task.CompletedTask;
    private int _disposed;

    public ProviderAuthority(SecretStore native, AuthorityStore authority, AuthorityKeyRing keys, ProviderRegistry registry, HostAudit audit, TimeProvider clock)
    {
        Registry = registry;
        Store = new ProviderStore(authority);
        Cache = new ProviderCache(Store, keys);
        Invalidation = new ProviderInvalidation(Store, audit);
        ProviderRetriever retriever = new(registry.Adapter, clock, (wait, cancel) => Task.Delay(wait, clock, cancel));
        Source = new ProviderSecretSource(native, Store, retriever, Cache, Invalidation, clock, AuditSink(audit), registry.IsInteractiveType);
        Reconciler = new NamespaceReconciler(Store, registry.Adapter, _logger);
        Refresher = new ProviderRefresher(Store, retriever, Cache, () => native.Current().Manifest?.Store, Invalidation, clock, _logger,
            interactive: registry.IsInteractiveType);
        ReconcileLoop = new ProviderReconciliation(Store, Reconciler, () => Cache.IsLocked, InstanceReady, clock, _logger);
    }

    /// <summary>The periodic loop that runs <see cref="Reconciler" /> over every due mount.</summary>
    public ProviderReconciliation ReconcileLoop { get; }

    private bool InstanceReady(Guid id)
    {
        try
        {
            return Registry.Status(id).Lifecycle == AdapterLifecycleState.Ready;
        }
        catch (KeyNotFoundException)
        {
            return false;
        }
    }

    public ProviderRegistry Registry { get; }

    internal IInteractiveProviderAdapter? InteractiveAdapter(Guid id)
    {
        try { return Registry.Adapter(id) as IInteractiveProviderAdapter; }
        catch (KeyNotFoundException) { return null; }
        catch (InvalidOperationException) { return null; }
    }

    public ProviderStore Store { get; }

    public ProviderCache Cache { get; }

    public ProviderInvalidation Invalidation { get; }

    /// <summary>What a run reads: the native store plus every mounted secret.</summary>
    public ProviderSecretSource Source { get; }

    public ProviderRefresher Refresher { get; }

    /// <summary>Refreshes a mount's namespace entries through its instance's adapter.</summary>
    public NamespaceReconciler Reconciler { get; }

    /// <summary>The sink of <see cref="ProviderSecretSource" />: one call's records committed to the host audit outbox in ONE transaction. Throws when they cannot be, so the call fails closed.</summary>
    public static Action<IReadOnlyList<ProviderAudit>> AuditSink(HostAudit audit) => records => audit.RecordAll([.. records.Select(record => record.ToFacts())]);

    /// <summary>
    /// Subscribes invalidation (first, so one reported during initialization is not missed), adds every stored instance to the registry at once and starts the
    /// refresher. It returns within <see cref="StartBound" /> whatever the adapters do: an instance whose initialization has not returned by the start deadline
    /// (even one that ignores its token) is removed again within the shutdown deadline and stays unregistered, as is one that cannot be added; its mounted secrets
    /// fail closed. Each is logged by instance name and exception type only.
    /// </summary>
    public void Start()
    {
        Registry.InvalidationRequested += OnInvalidation;
        using CancellationTokenSource limit = new(StartDeadline);

        // Read here, not inside the lambdas below: one that runs only after this method returned would touch a disposed source.
        CancellationToken startToken = limit.Token;
        CancellationToken stopToken = _stop.Token;
        IReadOnlyList<ProviderInstance> instances = Store.Instances();
        List<(ProviderInstance Instance, Task Adding)> adding = [];
        foreach (ProviderInstance instance in instances)
        {
            // Task.Run: an adapter that blocks synchronously inside InitializeAsync blocks a pool thread, never this one.
            Task task = Task.Run(() => Registry.AddInstanceAsync(instance.Id, instance.ProviderType, instance.Configuration, _logger, startToken));
            _ = task.ContinueWith(done => done.Exception, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default);
            adding.Add((instance, task));
        }

        try
        {
            Task.WhenAll(adding.Select(item => item.Adding)).Wait(StartDeadline);
        }
        catch (AggregateException)
        {
            // Each failure is looked at below.
        }

        limit.Cancel();
        List<Task> removing = [];
        foreach ((ProviderInstance instance, Task task) in adding)
        {
            if (task.IsCompletedSuccessfully)
            {
                lock (_started)
                {
                    _started.Add(instance.Id);
                }

                continue;
            }

            AppLog.Warn("provider instance {Name} could not be started ({Type}); its mounted secrets fail closed", instance.Name, task.IsCompleted ? task.Exception?.InnerException?.GetType().Name ?? "Cancelled" : "TimeoutException");
            if (!task.IsCompleted)
            {
                // Still inside the adapter: take it out of the registry (bounded by the shutdown deadline), so nothing is retrieved through it.
                removing.Add(RemoveQuietly(instance.Id));
            }
        }

        Task.WhenAll(removing).Wait(ShutdownDeadline);
        _refresh = Task.Run(() => Refresher.RunAsync(null, stopToken));
        _reconcile = Task.Run(() => ReconcileLoop.RunAsync(null, stopToken));
    }

    /// <summary>The most adding or reconfiguring one instance after an administrator's change takes (the start deadline). For tests: shortened.</summary>
    internal TimeSpan ChangeDeadline { get; set; } = StartDeadline;

    /// <summary>
    /// Adds an instance an administrator just committed to the registry, bounded as <see cref="Start" /> bounds each (an initialization that has not returned by the start
    /// deadline is removed again). Throws when it could not be added: its mounted secrets fail closed and its status shows it is not running.
    /// </summary>
    internal async Task StartInstanceAsync(ProviderInstance instance)
    {
        using CancellationTokenSource limit = new(ChangeDeadline);
        CancellationToken token = limit.Token;
        Task adding = Task.Run(() => Registry.AddInstanceAsync(instance.Id, instance.ProviderType, instance.Configuration, _logger, token));
        _ = adding.ContinueWith(done => done.Exception, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default);
        try
        {
            await adding.WaitAsync(ChangeDeadline).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            await limit.CancelAsync().ConfigureAwait(false);
            await RemoveQuietly(instance.Id).ConfigureAwait(false);

            throw;
        }

        lock (_started)
        {
            _started.Add(instance.Id);
        }
    }

    /// <summary>
    /// Applies a configuration an administrator just committed to the running instance (within the start deadline), or adds the instance when it is not running. Throws when
    /// the adapter did not take it; the registry then shows the instance Unavailable.
    /// </summary>
    internal async Task ReconfigureInstanceAsync(ProviderInstance instance)
    {
        try
        {
            Registry.Status(instance.Id);
        }
        catch (KeyNotFoundException)
        {
            await StartInstanceAsync(instance).ConfigureAwait(false);

            return;
        }

        using CancellationTokenSource limit = new(ChangeDeadline);
        CancellationToken token = limit.Token;
        Task updating = Task.Run(() => Registry.UpdateInstanceAsync(instance.Id, () => Store.Instance(instance.Id)?.Configuration
            ?? throw new ProviderConfigurationException("The provider instance no longer exists."), token), token);
        _ = updating.ContinueWith(done => done.Exception, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default);
        try
        {
            // WaitAsync enforces the deadline even for an adapter that ignores its token; the abandoned update is observed above.
            await updating.WaitAsync(token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            Registry.MarkUnavailable(instance.Id, "The new configuration was not applied in time.");

            throw;
        }
    }

    internal Task ReloadConfigurationsAsync(IReadOnlyList<Guid> instances)
        => Task.WhenAll(instances.Select(ReloadConfigurationAsync));

    private async Task ReloadConfigurationAsync(Guid id)
    {
        try
        {
            if (Store.Instance(id) is { } instance)
            {
                await ReconfigureInstanceAsync(instance).ConfigureAwait(false);
            }
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            AppLog.Warn("Provider instance {Instance} did not reload after review-key rotation ({Type}).", id, error.GetType().Name);
        }
    }


    /// <summary>Shuts down and forgets the running instance of a removed configuration (within the shutdown deadline). Nothing to do when it is not running.</summary>
    internal async Task StopInstanceAsync(Guid id)
    {
        lock (_started)
        {
            _started.Remove(id);
        }

        try
        {
            await Registry.RemoveInstanceAsync(id, ShutdownDeadline, CancellationToken.None).ConfigureAwait(false);
        }
        catch (KeyNotFoundException)
        {
            // It was not running.
        }
    }

    private async Task RemoveQuietly(Guid id)
    {
        try
        {
            await Registry.RemoveInstanceAsync(id, ShutdownDeadline, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            // Not registered (it never got that far) or already removed: nothing to take out.
            AppLog.Debug("removing a provider instance that did not start: {Type}", error.GetType().Name);
        }
    }

    private void OnInvalidation(Guid instanceId, InvalidateProviderDataEvent evt)
    {
        try
        {
            Invalidation.Apply(instanceId, evt);
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            // Never thrown back to the adapter. The type only: a database message can name a path.
            AppLog.Warn("an invalidation of provider instance {Instance} could not be applied ({Type})", instanceId, error.GetType().Name);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
        {
            return;
        }

        _stop.Cancel();
        try
        {
            Task.WhenAll(_refresh, _reconcile).Wait(ShutdownDeadline);
        }
        catch (AggregateException)
        {
            // The loop ended with an error; nothing more to wait for.
        }

        Registry.InvalidationRequested -= OnInvalidation;
        List<Guid> started;
        lock (_started)
        {
            started = [.. _started];
        }

        foreach (Guid id in started)
        {
            try
            {
                Registry.RemoveInstanceAsync(id, ShutdownDeadline, CancellationToken.None).GetAwaiter().GetResult();
            }
            catch (Exception error) when (error is not OutOfMemoryException)
            {
                AppLog.Warn("provider instance {Instance} did not shut down cleanly ({Type})", id, error.GetType().Name);
            }
        }

        // A loop that did not end within the deadline may still read the token: the source is left to the collector then.
        if (_refresh.IsCompleted && _reconcile.IsCompleted)
        {
            _stop.Dispose();
        }
    }

    /// <summary>
    /// The provider code's and the adapters' <see cref="ILogger" /> use the machine's local log level. Only the rendered message is written (the
    /// provider code's templates carry ids, kinds and exception type names); the exception object itself is never logged.
    /// </summary>
    private sealed class AppLogLogger : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.None) return;
            string text = formatter(state, null);
            switch (logLevel)
            {
                case LogLevel.Error or LogLevel.Critical:
                    AppLog.Error("provider: {Message}", text);
                    break;
                case LogLevel.Warning:
                    AppLog.Warn("provider: {Message}", text);
                    break;
                case LogLevel.Information:
                    AppLog.Info("provider: {Message}", text);
                    break;
                default:
                    AppLog.Debug("provider: {Message}", text);
                    break;
            }
        }
    }
}

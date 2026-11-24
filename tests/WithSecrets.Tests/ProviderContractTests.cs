using Microsoft.Extensions.Logging.Abstractions;

namespace WithSecrets.Tests;

/// <summary>
/// The provider adapter contract: batch result validation, strict UTF-8, and the registry that owns each instance's lifecycle and health
/// (10.3.1, 10.3.4). Driven by <see cref="FakeProviderAdapter" />.
/// </summary>
internal static class ProviderContractTests
{
    private sealed class ManualClock(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _now = start;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }

    private static readonly DateTimeOffset Start = new(2026, 11, 22, 10, 0, 0, TimeSpan.Zero);
    private const string Json = """{"label": "one"}""";

    public static async Task Run(Action<bool, string> check)
    {
        BatchValidation(check);
        StrictUtf8(check);
        await Registry(check);
        await Hardening(check);
    }

    private static ProviderSecretResult Value(Guid id, string text = "S3cretValue-xyz") => new(id, new RetrieveSecretResult(System.Text.Encoding.UTF8.GetBytes(text)));

    private static ProviderSecretResult Error(Guid id) => new(id, null, ProviderErrorKind.AccessDenied);

    private static bool Rejects(IReadOnlyList<ProviderSecretRequest> requests, IReadOnlyList<ProviderSecretResult> results)
    {
        try
        {
            ProviderBatch.Validate(requests, results);

            return false;
        }
        catch (ProviderAdapterException exception)
        {
            return exception.Kind == ProviderErrorKind.InvalidResponse && !exception.Message.Contains("S3cretValue", StringComparison.Ordinal);
        }
    }

    private static void BatchValidation(Action<bool, string> check)
    {
        Guid a = Guid.NewGuid();
        Guid b = Guid.NewGuid();
        ProviderSecretRequest[] requests = [new(a, "x"), new(b, "x")];

        // Results may arrive in any order; the output is in request order.
        IReadOnlyList<ProviderSecretResult> ok = ProviderBatch.Validate(requests, [Error(b), Value(a)]);
        check(ok.Count == 2 && ok[0].RequestId == a && ok[1].RequestId == b, "batch validate accepts exact match");

        check(Rejects(requests, [Value(a)]), "batch validate rejects missing result");
        check(Rejects(requests, [Value(a), Value(a), Value(b)]), "batch validate rejects duplicate result id");
        check(Rejects(requests, [Value(a), Value(b), Value(Guid.NewGuid())]), "batch validate rejects unknown result id");
        check(Rejects(requests, [Value(a), new ProviderSecretResult(b, null)]), "batch validate rejects neither secret nor error");
        check(Rejects(requests, [Value(a), new ProviderSecretResult(b, new RetrieveSecretResult([1]), ProviderErrorKind.Unknown)]), "batch validate rejects both secret and error");
        check(Rejects([new(a, "x"), new(a, "y")], [Value(a)]), "batch validate rejects duplicate request id");
    }

    private static void StrictUtf8(Action<bool, string> check)
    {
        check(ProviderBatch.IsStrictUtf8(System.Text.Encoding.UTF8.GetBytes("café € \U0001F600")), "strict utf8: valid multibyte is true");
        check(!ProviderBatch.IsStrictUtf8([0x61, 0xC3]), "strict utf8: lone 0xC3 is false");
        check(!ProviderBatch.IsStrictUtf8([0xC0, 0x80]), "strict utf8: overlong is false");
    }

    private static (ProviderRegistry Registry, FakeProviderAdapter Adapter, ManualClock Clock) NewRegistry()
    {
        ManualClock clock = new(Start);
        ProviderRegistry registry = new(clock);
        FakeProviderAdapter adapter = new();
        registry.RegisterType("fake", "1.0", () => adapter, () => new FakeConfiguration());

        return (registry, adapter, clock);
    }

    private static async Task Registry(Action<bool, string> check)
    {
        Guid id = Guid.NewGuid();

        // A new instance starts Initializing / Initializing (the fake does not report during initialize here).
        {
            (ProviderRegistry registry, FakeProviderAdapter adapter, ManualClock _) = NewRegistry();
            adapter.OnInitialize = null;
            await registry.AddInstanceAsync(id, "fake", Json, NullLogger.Instance, CancellationToken.None);
            InstanceStatus status = registry.Status(id);
            check(status.Lifecycle == AdapterLifecycleState.Initializing && status.Health == AdapterHealthState.Initializing && status.LifecycleAt == Start && status.HealthAt == Start, "registry: new instance starts Initializing/Initializing");
            check(adapter.Context is { ProviderType: "fake", AdapterVersion: "1.0" } context && context.InstanceId == id && adapter.CurrentLabel == "one", "registry: context carries the identity and the loaded configuration");
        }

        // A Ready report is accepted and stamped; a stale Ready after shutdown began is ignored.
        {
            (ProviderRegistry registry, FakeProviderAdapter adapter, ManualClock clock) = NewRegistry();
            await registry.AddInstanceAsync(id, "fake", Json, NullLogger.Instance, CancellationToken.None);
            check(registry.Status(id).Lifecycle == AdapterLifecycleState.Ready, "registry: adapter Ready report accepted");
            adapter.Reporter!.Report(new LifecycleChangedEvent(AdapterLifecycleState.Unavailable, "down"));
            clock.Advance(TimeSpan.FromSeconds(5));
            adapter.Reporter.Report(new LifecycleChangedEvent(AdapterLifecycleState.Ready, "back"));
            InstanceStatus ready = registry.Status(id);
            check(ready.Lifecycle == AdapterLifecycleState.Ready && ready.LifecycleMessage == "back" && ready.LifecycleAt == Start.AddSeconds(5), "registry: lifecycle changes are stamped with the registry clock");

            AdapterLifecycleState? duringShutdown = null;
            adapter.OnShutdown = reporter =>
            {
                reporter.Report(new LifecycleChangedEvent(AdapterLifecycleState.Ready, "late"));
                duringShutdown = registry.Status(id).Lifecycle;
            };
            await registry.RemoveInstanceAsync(id, TimeSpan.FromSeconds(5), CancellationToken.None);
            check(duringShutdown == AdapterLifecycleState.ShuttingDown, "registry: stale Ready after shutdown ignored");
        }

        // ShuttingDown is set only by the registry.
        {
            (ProviderRegistry registry, FakeProviderAdapter adapter, ManualClock _) = NewRegistry();
            await registry.AddInstanceAsync(id, "fake", Json, NullLogger.Instance, CancellationToken.None);
            adapter.Reporter!.Report(new LifecycleChangedEvent(AdapterLifecycleState.ShuttingDown));
            adapter.Reporter.Report(new LifecycleChangedEvent(AdapterLifecycleState.Initializing));
            bool stillReady = registry.Status(id).Lifecycle == AdapterLifecycleState.Ready;
            bool usable = registry.Adapter(id) == adapter;
            check(stillReady && usable, "registry: lifecycle ShuttingDown set only by the registry (an adapter report of ShuttingDown is ignored)");
        }

        // Health is accepted until shutdown begins, then ignored with the last value kept.
        {
            (ProviderRegistry registry, FakeProviderAdapter adapter, ManualClock _) = NewRegistry();
            await registry.AddInstanceAsync(id, "fake", Json, NullLogger.Instance, CancellationToken.None);
            adapter.Reporter!.Report(new HealthChangedEvent(AdapterHealthState.Healthy));
            AdapterHealthState? during = null;
            adapter.OnShutdown = reporter =>
            {
                reporter.Report(new HealthChangedEvent(AdapterHealthState.Unavailable, "gone"));
                during = registry.Status(id).Health;
            };
            await registry.RemoveInstanceAsync(id, TimeSpan.FromSeconds(5), CancellationToken.None);
            check(during == AdapterHealthState.Healthy, "registry: health reports ignored after shutdown begins, last health kept");
        }

        // Invalidation is accepted while active and rejected once removal began.
        {
            (ProviderRegistry registry, FakeProviderAdapter adapter, ManualClock _) = NewRegistry();
            List<(Guid, InvalidateProviderDataEvent)> seen = [];
            registry.InvalidationRequested += (instance, evt) => seen.Add((instance, evt));
            await registry.AddInstanceAsync(id, "fake", Json, NullLogger.Instance, CancellationToken.None);
            adapter.Reporter!.Report(new InvalidateProviderDataEvent(ExternalSecretIds: ["ext-1"]));
            check(seen.Count == 1 && seen[0].Item1 == id && seen[0].Item2.ExternalSecretIds![0] == "ext-1", "registry: invalidation accepted while Ready");
            adapter.OnShutdown = reporter => reporter.Report(new InvalidateProviderDataEvent(InvalidateEntireProviderInstance: true));
            await registry.RemoveInstanceAsync(id, TimeSpan.FromSeconds(5), CancellationToken.None);
            adapter.Reporter.Report(new InvalidateProviderDataEvent(InvalidateEntireProviderInstance: true));
            check(seen.Count == 1, "registry: invalidation rejected after RemoveInstance began");
        }

        // Unknown instance throws (before add, and after remove).
        {
            (ProviderRegistry registry, FakeProviderAdapter _, ManualClock _) = NewRegistry();
            bool before = Throws(() => registry.Adapter(id)) && Throws(() => registry.Status(id));
            await registry.AddInstanceAsync(id, "fake", Json, NullLogger.Instance, CancellationToken.None);
            await registry.RemoveInstanceAsync(id, TimeSpan.FromSeconds(5), CancellationToken.None);
            check(before && Throws(() => registry.Adapter(id)) && Throws(() => registry.Status(id)), "registry: unknown instance throws");
        }

        // A configuration update reaches the adapter and health goes Initializing.
        {
            (ProviderRegistry registry, FakeProviderAdapter adapter, ManualClock _) = NewRegistry();
            await registry.AddInstanceAsync(id, "fake", Json, NullLogger.Instance, CancellationToken.None);
            adapter.Reporter!.Report(new HealthChangedEvent(AdapterHealthState.Healthy));
            await registry.UpdateInstanceAsync(id, """{"label": "two"}""", CancellationToken.None);
            check(adapter.Calls.Contains("update") && adapter.CurrentLabel == "two" && registry.Status(id).Health == AdapterHealthState.Initializing, "registry: config update calls UpdateConfigurationAsync and health goes Initializing");
        }

        // A configuration of the wrong type is InvalidConfiguration (from the base class and from the registry).
        {
            FakeProviderAdapter adapter = new();
            bool direct = await IsInvalidConfiguration(() => adapter.UpdateConfigurationAsync(new OtherConfiguration(), CancellationToken.None))
                && await IsInvalidConfiguration(() => adapter.ValidateConfigurationAsync(new OtherConfiguration(), CancellationToken.None))
                && await IsInvalidConfiguration(() => adapter.ValidateMountAsync(new OtherConfiguration(), "base", CancellationToken.None));

            ProviderRegistry registry = new(new ManualClock(Start));
            registry.RegisterType("fake", "1.0", () => new FakeProviderAdapter(), () => new OtherConfiguration());
            bool viaRegistry = await IsInvalidConfiguration(() => registry.AddInstanceAsync(id, "fake", Json, NullLogger.Instance, CancellationToken.None));
            check(direct && viaRegistry && Throws(() => registry.Status(id)), "registry: wrong configuration type is InvalidConfiguration");
        }
    }

    private static async Task Hardening(Action<bool, string> check)
    {
        Guid id = Guid.NewGuid();
        TimeSpan deadline = TimeSpan.FromMilliseconds(200);

        // A shutdown that ignores its token is cut off at the deadline; the instance is forgotten.
        {
            (ProviderRegistry registry, FakeProviderAdapter adapter, ManualClock _) = NewRegistry();
            adapter.ShutdownBehavior = () => new TaskCompletionSource().Task;
            await registry.AddInstanceAsync(id, "fake", Json, NullLogger.Instance, CancellationToken.None);
            Task remove = registry.RemoveInstanceAsync(id, deadline, CancellationToken.None);
            bool finished = await Task.WhenAny(remove, Task.Delay(TimeSpan.FromSeconds(10))) == remove;
            if (finished)
            {
                await remove;
            }

            check(finished && Throws(() => registry.Status(id)), "registry: a shutdown that ignores its token is forgotten within the deadline");
        }

        // A shutdown that throws still forgets the instance.
        {
            (ProviderRegistry registry, FakeProviderAdapter adapter, ManualClock _) = NewRegistry();
            adapter.ShutdownBehavior = () => Task.FromException(new InvalidOperationException("boom"));
            await registry.AddInstanceAsync(id, "fake", Json, NullLogger.Instance, CancellationToken.None);
            await registry.RemoveInstanceAsync(id, TimeSpan.FromSeconds(5), CancellationToken.None);
            check(Throws(() => registry.Status(id)), "registry: a shutdown that throws still forgets the instance");
        }

        // Update after remove, and during shutdown, is a clean refusal.
        {
            (ProviderRegistry registry, FakeProviderAdapter adapter, ManualClock _) = NewRegistry();
            await registry.AddInstanceAsync(id, "fake", Json, NullLogger.Instance, CancellationToken.None);
            bool during = false;
            adapter.ShutdownBehavior = () =>
            {
                during = ThrowsOnly<InvalidOperationException>(() => registry.UpdateInstanceAsync(id, Json, CancellationToken.None).GetAwaiter().GetResult());

                return Task.CompletedTask;
            };
            await registry.RemoveInstanceAsync(id, TimeSpan.FromSeconds(5), CancellationToken.None);
            bool after = false;
            try
            {
                await registry.UpdateInstanceAsync(id, Json, CancellationToken.None);
            }
            catch (KeyNotFoundException)
            {
                after = true;
            }

            check(during, "registry: update while shutting down is refused");
            check(after, "registry: update after remove is refused without touching a disposed token");
        }

        // A configuration whose Load throws with its own text is InvalidConfiguration without that text.
        {
            ProviderRegistry registry = new(new ManualClock(Start));
            registry.RegisterType("leaky", "1.0", () => new FakeProviderAdapter(), () => new LeakyConfiguration());
            bool ok = false;
            try
            {
                await registry.AddInstanceAsync(id, "leaky", Json, NullLogger.Instance, CancellationToken.None);
            }
            catch (ProviderAdapterException exception)
            {
                ok = exception.Kind == ProviderErrorKind.InvalidConfiguration && !exception.Message.Contains("hunter2", StringComparison.Ordinal) && exception.InnerException is null;
            }
            catch (Exception)
            {
                ok = false;
            }

            check(ok, "registry: a failing configuration Load is InvalidConfiguration without its text");
        }

        // A caller cancelling initialization leaves nothing registered and the adapter shut down.
        {
            (ProviderRegistry registry, FakeProviderAdapter adapter, ManualClock _) = NewRegistry();
            adapter.InitializeBehavior = token => Task.Delay(Timeout.Infinite, token);
            using CancellationTokenSource cancel = new();
            Task add = registry.AddInstanceAsync(id, "fake", Json, NullLogger.Instance, cancel.Token);
            cancel.CancelAfter(TimeSpan.FromMilliseconds(100));
            bool cancelled = false;
            try
            {
                await add;
            }
            catch (OperationCanceledException)
            {
                cancelled = true;
            }

            check(cancelled && Throws(() => registry.Status(id)) && adapter.Calls.Contains("shutdown"), "registry: a cancelled add unregisters the instance and shuts the adapter down");
        }

        // Final review M4: a second (concurrent or duplicate) removal does not shut the adapter down again.
        {
            (ProviderRegistry registry, FakeProviderAdapter adapter, ManualClock _) = NewRegistry();
            TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
            adapter.ShutdownBehavior = () => release.Task;
            await registry.AddInstanceAsync(id, "fake", Json, NullLogger.Instance, CancellationToken.None);
            Task first = registry.RemoveInstanceAsync(id, TimeSpan.FromSeconds(10), CancellationToken.None);
            Task second = registry.RemoveInstanceAsync(id, TimeSpan.FromSeconds(10), CancellationToken.None);
            bool secondDone = await Task.WhenAny(second, Task.Delay(TimeSpan.FromSeconds(5))) == second && second.IsCompletedSuccessfully;
            release.SetResult();
            await first;
            int shutdowns = adapter.Calls.Count(call => call == "shutdown");
            check(secondDone && shutdowns == 1 && Throws(() => registry.Status(id)), "registry: a duplicate removal while one is running is a no-op (one ShutdownAsync) (" + shutdowns + ")");
        }
    }

    private static bool ThrowsOnly<T>(Action action) where T : Exception
    {
        try
        {
            action();

            return false;
        }
        catch (T)
        {
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static bool Throws(Action action)
    {
        try
        {
            action();

            return false;
        }
        catch (Exception)
        {
            return true;
        }
    }

    private static async Task<bool> IsInvalidConfiguration(Func<Task> action)
    {
        try
        {
            await action();

            return false;
        }
        catch (ProviderAdapterException exception)
        {
            return exception.Kind == ProviderErrorKind.InvalidConfiguration;
        }
    }
}

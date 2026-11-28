using Microsoft.Extensions.Logging;

namespace ArcanaGuardian.Tests;

/// <summary>Periodic namespace reconciliation (10.3): a fake clock, fake adapters, no real waiting.</summary>
internal static class ProviderReconcileScheduleTests
{
    private sealed class ManualClock(DateTimeOffset start) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = start;

        public override DateTimeOffset GetUtcNow() => Now;

        public void Advance(TimeSpan by) => Now += by;
    }

    private sealed class CapturingLogger : ILogger
    {
        public List<string> Lines { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Lines.Add(formatter(state, exception) + " | " + (exception?.GetType().Name ?? ""));
    }

    private sealed class Rig : IDisposable
    {
        private readonly string _folder = Path.Combine(Path.GetTempPath(), "ws-providerreconcile-" + Guid.NewGuid().ToString("N"));
        private readonly Dictionary<Guid, FakeProviderAdapter> _adapters = [];

        public Rig()
        {
            Authority = AuthorityStore.InFolder(_folder);
            Store = new ProviderStore(Authority);
            Reconciler = new NamespaceReconciler(Store, id => _adapters[id], Logger);
            ReconcileLoop = new ProviderReconciliation(Store, Reconciler, () => Locked, id => Ready.Contains(id), Clock, Logger, (_, _) => Task.CompletedTask);
            (_, AdapterOne, MountOne) = Add("one", "team/one");
        }

        public AuthorityStore Authority { get; }

        public ProviderStore Store { get; }

        public NamespaceReconciler Reconciler { get; }

        public ProviderReconciliation ReconcileLoop { get; }

        public ManualClock Clock { get; } = new(new DateTimeOffset(2026, 11, 23, 8, 0, 0, TimeSpan.Zero));

        public CapturingLogger Logger { get; } = new();

        public bool Locked { get; set; }

        public HashSet<Guid> Ready { get; } = [];

        public FakeProviderAdapter AdapterOne { get; }

        public Mount MountOne { get; }

        public (ProviderInstance Instance, FakeProviderAdapter Adapter, Mount Mount) Add(string name, string logical, bool ready = true)
        {
            ProviderInstance instance = Store.AddInstance(name, "fake", "{}", TimeSpan.Zero);
            FakeProviderAdapter adapter = new();
            _adapters[instance.Id] = adapter;
            if (ready)
            {
                Ready.Add(instance.Id);
            }

            return (instance, adapter, Store.AddMount(instance.Id, MountKind.Tree, logical, "kv"));
        }

        public void Dispose()
        {
            try
            {
                Directory.Delete(_folder, true);
            }
            catch (IOException)
            {
            }
        }
    }

    private static Task<ListSecretsResult> One(string path, string id) => Task.FromResult(new ListSecretsResult([new ProviderSecretInfo(path, id, null)], null, true));

    public static async Task Run(Action<bool, string> check)
    {
        await Schedule(check);
        await Skipped(check);
        await Failures(check);
        await LockRefusals(check);
        await Loop(check);
    }

    // The authority locking between the locked() check and the work: a lock refusal ends the pass quietly and records no attempt.
    private static async Task LockRefusals(Action<bool, string> check)
    {
        using Rig rig = new();
        rig.AdapterOne.ListHandler = (_, _) => One("a", "1");
        rig.ReconcileLoop.BeforeMounts = () => throw new AuthorityLockedException();
        bool threw = false;
        try
        {
            await rig.ReconcileLoop.TickAsync(CancellationToken.None);
        }
        catch (AuthorityLockedException)
        {
            threw = true;
        }

        check(!threw && rig.AdapterOne.Calls.Count == 0 && rig.Logger.Lines.Count == 0, "reconcile schedule: a lock refusal reading the mounts ends the pass quietly");
        rig.ReconcileLoop.BeforeMounts = null;

        (_, FakeProviderAdapter other, _) = rig.Add("two", "team/two");
        other.ListHandler = (_, _) => One("b", "2");
        rig.AdapterOne.ListHandler = (_, _) => throw new AuthorityLockedException();
        threw = false;
        try
        {
            await rig.ReconcileLoop.TickAsync(CancellationToken.None);
        }
        catch (AuthorityLockedException)
        {
            threw = true;
        }

        check(!threw && rig.Logger.Lines.Count == 0, "reconcile schedule: a lock refusal reconciling a mount ends the pass quietly (no warning)");
        check(other.ListRequests.Count == 0, "reconcile schedule: after a lock refusal no other mount is reconciled in that pass");

        rig.AdapterOne.ListHandler = (_, _) => One("a", "1");
        await rig.ReconcileLoop.TickAsync(CancellationToken.None);
        check(rig.AdapterOne.ListRequests.Count == 2 && rig.Store.Entries(rig.MountOne.Id).Count == 1 && other.ListRequests.Count == 1,
            "reconcile schedule: a lock refusal records no attempt, so the next pass reconciles the mount at once (" + rig.AdapterOne.ListRequests.Count + " listings)");

        // A refusal after an earlier success keeps that earlier attempt's time: the mount is not due again before its interval.
        rig.Clock.Advance(ProviderReconciliation.ReconcileInterval);
        rig.AdapterOne.ListHandler = (_, _) => throw new AuthorityLockedException();
        await rig.ReconcileLoop.TickAsync(CancellationToken.None);
        rig.AdapterOne.ListHandler = (_, _) => One("a", "1");
        await rig.ReconcileLoop.TickAsync(CancellationToken.None);
        check(rig.AdapterOne.ListRequests.Count == 4, "reconcile schedule: after a refusal the due mount is retried on the next pass");
    }

    private static async Task Schedule(Action<bool, string> check)
    {
        using Rig rig = new();
        check(ProviderReconciliation.ReconcileInterval == TimeSpan.FromMinutes(15), "reconcile schedule: the interval is 15 minutes");
        rig.AdapterOne.ListHandler = (_, _) => One("a", "1");
        await rig.ReconcileLoop.TickAsync(CancellationToken.None);
        check(rig.AdapterOne.ListRequests.Count == 1 && rig.Store.Entries(rig.MountOne.Id).Count == 1, "reconcile schedule: a mount is reconciled when never attempted");

        rig.Clock.Advance(TimeSpan.FromMinutes(14));
        await rig.ReconcileLoop.TickAsync(CancellationToken.None);
        check(rig.AdapterOne.ListRequests.Count == 1, "reconcile schedule: not again before 15 minutes");

        rig.Clock.Advance(TimeSpan.FromMinutes(1));
        await rig.ReconcileLoop.TickAsync(CancellationToken.None);
        check(rig.AdapterOne.ListRequests.Count == 2, "reconcile schedule: again at 15 minutes");

        rig.Clock.Advance(TimeSpan.FromMinutes(10));
        rig.Add("two", "team/two");
        await rig.ReconcileLoop.TickAsync(CancellationToken.None);
        check(rig.AdapterOne.ListRequests.Count == 2, "reconcile schedule: a new mount does not reset another mount's clock");
    }

    private static async Task Skipped(Action<bool, string> check)
    {
        using Rig rig = new();
        (_, FakeProviderAdapter notReady, _) = rig.Add("idle", "team/idle", ready: false);
        (ProviderInstance gone, FakeProviderAdapter goneAdapter, _) = rig.Add("gone", "team/gone");
        rig.Ready.Remove(gone.Id);
        await rig.ReconcileLoop.TickAsync(CancellationToken.None);
        check(notReady.ListRequests.Count == 0 && goneAdapter.ListRequests.Count == 0 && rig.AdapterOne.ListRequests.Count == 1, "reconcile schedule: an unregistered or not-Ready instance is skipped, the others are not");

        rig.Ready.Add(gone.Id);
        await rig.ReconcileLoop.TickAsync(CancellationToken.None);
        check(goneAdapter.ListRequests.Count == 1, "reconcile schedule: a skipped mount is reconciled as soon as its instance is Ready");

        using Rig locked = new();
        locked.Locked = true;
        await locked.ReconcileLoop.TickAsync(CancellationToken.None);
        check(locked.AdapterOne.Calls.Count == 0, "reconcile schedule: locked, no provider call");
        locked.Locked = false;
        await locked.ReconcileLoop.TickAsync(CancellationToken.None);
        check(locked.AdapterOne.ListRequests.Count == 1, "reconcile schedule: unlocked, the mount is reconciled");
    }

    private static async Task Failures(Action<bool, string> check)
    {
        using Rig rig = new();
        rig.AdapterOne.ListHandler = (_, _) => One("a", "1");
        await rig.ReconcileLoop.TickAsync(CancellationToken.None);
        (_, FakeProviderAdapter other, Mount otherMount) = rig.Add("two", "team/two");
        other.ListHandler = (_, _) => One("b", "2");
        rig.Clock.Advance(ProviderReconciliation.ReconcileInterval);
        rig.AdapterOne.ListHandler = (_, _) => throw new ProviderAdapterException(ProviderErrorKind.Unavailable, "secret-message-hunter2");
        await rig.ReconcileLoop.TickAsync(CancellationToken.None);
        check(rig.Store.Entries(rig.MountOne.Id).Count == 1 && rig.Store.Entries(otherMount.Id).Count == 1, "reconcile schedule: a failing listing leaves its entries and does not abort other mounts");
        check(rig.Logger.Lines.Any(line => line.Contains("ProviderAdapterException")) && !rig.Logger.Lines.Any(line => line.Contains("hunter2")), "reconcile schedule: the failure is logged by exception type only");

        int before = rig.AdapterOne.ListRequests.Count;
        await rig.ReconcileLoop.TickAsync(CancellationToken.None);
        check(rig.AdapterOne.ListRequests.Count == before, "reconcile schedule: a failed attempt is not retried before the interval");
    }

    private static async Task Loop(Action<bool, string> check)
    {
        using Rig rig = new();
        using CancellationTokenSource stop = new();
        rig.AdapterOne.ListHandler = (_, _) => throw new InvalidOperationException("boom");

        // The delay hook stands in for the wait: it advances the clock a full interval, counts rounds and cancels after the third.
        int rounds = 0;
        ProviderReconciliation loop = new(rig.Store, rig.Reconciler, () => false, id => rig.Ready.Contains(id), rig.Clock, rig.Logger, (_, cancel) =>
        {
            rounds++;
            rig.Clock.Advance(ProviderReconciliation.ReconcileInterval);
            if (rounds == 3)
            {
                stop.Cancel();
            }

            cancel.ThrowIfCancellationRequested();

            return Task.CompletedTask;
        });
        await loop.RunAsync(null, stop.Token);
        check(rounds == 3 && rig.AdapterOne.ListRequests.Count == 3, "reconcile schedule: RunAsync survives failing ticks and stops on cancel (" + rounds + " rounds, " + rig.AdapterOne.ListRequests.Count + " listings)");
    }
}

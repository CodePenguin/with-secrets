using System.Text;

namespace ArcanaGuardian.Tests;

/// <summary>The retrieval engine (bounded retries, deadline, per-item outcomes) and the freshness policy (10.3.3, 10.3.4). No test really sleeps.</summary>
internal static class ProviderRetrievalTests
{
    private static readonly Guid Instance = Guid.NewGuid();

    /// <summary>A clock whose timers fire after 30 ms of real time whatever was asked, so the 10 s deadline can expire inside a test.</summary>
    private sealed class FastTimerClock : TimeProvider
    {
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
            => base.CreateTimer(callback, state, TimeSpan.FromMilliseconds(30), period);
    }

    private sealed class Rig
    {
        public FakeProviderAdapter Adapter { get; } = new();

        public List<TimeSpan> Delays { get; } = [];

        public ProviderRetriever Retriever { get; }

        public Rig(TimeProvider? clock = null)
        {
            Retriever = new ProviderRetriever(
                _ => Adapter,
                clock ?? TimeProvider.System,
                (span, _) =>
                {
                    Delays.Add(span);

                    return Task.CompletedTask;
                });
        }

        public Task<IReadOnlyDictionary<Guid, RetrievalOutcome>> Run(IReadOnlyList<ProviderSecretRequest> requests, CancellationToken cancel = default)
            => Retriever.RetrieveAsync(Instance, requests, cancel);
    }

    public static async Task Run(Action<bool, string> check)
    {
        Policy(check);
        await Retrieval(check);
        await Failures(check);
        await Cancellation(check);
        await Wiping(check);
        Classifier(check);
    }

    private static void Classifier(Action<bool, string> check)
    {
        (string, ProviderErrorKind)[] rules = [("not found", ProviderErrorKind.SecretNotFound), ("too many", ProviderErrorKind.RateLimited)];
        byte[] Bytes(string text) => Encoding.UTF8.GetBytes(text);
        check(CliFailureClassifier.Classify(Bytes("Error: Resource NOT FOUND"), rules) == ProviderErrorKind.SecretNotFound, "classifier: a phrase matches without regard to case");
        check(CliFailureClassifier.Classify(Bytes("something else"), rules) == ProviderErrorKind.Unknown && CliFailureClassifier.Classify([], rules) == ProviderErrorKind.Unknown, "classifier: no phrase and no text are Unknown");
        check(CliFailureClassifier.Classify(Bytes("too many requests" + new string('x', 6000)), rules) == ProviderErrorKind.RateLimited, "classifier: a phrase in the first 4096 bytes counts even when the text is longer");
        check(CliFailureClassifier.Classify(Bytes(new string('x', 6000) + "Error: not found"), rules) == ProviderErrorKind.SecretNotFound, "classifier: a phrase in the tail of a long text counts");
        check(CliFailureClassifier.Classify(Bytes(new string('x', 3000) + "not found" + new string('x', 3000)), rules) == ProviderErrorKind.Unknown, "classifier: a phrase between the head and the tail of a long text is not read");
    }

    /// <summary>The core keeps its own copy of a retrieved value and wipes the adapter's array (success and invalid UTF-8 alike).</summary>
    private static async Task Wiping(Action<bool, string> check)
    {
        Rig rig = new();
        byte[] good = Encoding.UTF8.GetBytes("value");
        byte[] bad = [0xC3, 0x28];
        ProviderSecretRequest goodRequest = Req("good");
        ProviderSecretRequest badRequest = Req("bad");
        rig.Adapter.Handler = (_, _, _) => Results(new ProviderSecretResult(goodRequest.RequestId, new RetrieveSecretResult(good)),
            new ProviderSecretResult(badRequest.RequestId, new RetrieveSecretResult(bad)));
        IReadOnlyDictionary<Guid, RetrievalOutcome> outcomes = await rig.Run([goodRequest, badRequest]);
        check(IsValue(outcomes, goodRequest.RequestId, "value") && good.All(b => b == 0), "retrieval wipes the adapter's array once the core has copied it");
        check(IsFailure(outcomes, badRequest.RequestId, ProviderErrorKind.InvalidResponse) && bad.All(b => b == 0), "retrieval wipes an invalid value instead of keeping it");

        Rig malformed = new();
        byte[] first = Encoding.UTF8.GetBytes("one");
        byte[] second = Encoding.UTF8.GetBytes("two");
        ProviderSecretRequest request = Req("twice");
        malformed.Adapter.Handler = (_, _, _) => Results(new ProviderSecretResult(request.RequestId, new RetrieveSecretResult(first)),
            new ProviderSecretResult(request.RequestId, new RetrieveSecretResult(second)));
        IReadOnlyDictionary<Guid, RetrievalOutcome> rejected = await malformed.Run([request]);
        check(IsFailure(rejected, request.RequestId, ProviderErrorKind.InvalidResponse) && first.All(b => b == 0) && second.All(b => b == 0),
            "retrieval wipes every value of a batch it rejects");
    }

    private static ProviderSecretRequest Req(string path) => new(Guid.NewGuid(), path);

    private static ProviderSecretResult Ok(Guid id, string text) => new(id, new RetrieveSecretResult(Encoding.UTF8.GetBytes(text)));

    private static ProviderSecretResult Err(Guid id, ProviderErrorKind kind, TimeSpan? retryAfter = null) => new(id, null, kind, "code-1", retryAfter);

    private static Task<IReadOnlyList<ProviderSecretResult>> Results(params ProviderSecretResult[] results) => Task.FromResult<IReadOnlyList<ProviderSecretResult>>(results);

    private static bool IsFailure(IReadOnlyDictionary<Guid, RetrievalOutcome> outcomes, Guid id, ProviderErrorKind kind)
        => outcomes[id] is RetrievalFailure failure && failure.Kind == kind;

    private static bool IsValue(IReadOnlyDictionary<Guid, RetrievalOutcome> outcomes, Guid id, string text)
        => outcomes[id] is RetrievalSuccess success && Encoding.UTF8.GetString(success.Value) == text;

    private static void Policy(Action<bool, string> check)
    {
        check(ProviderPolicy.ValidateMaxStale(TimeSpan.FromHours(24)) is null && ProviderPolicy.ValidateMaxStale(TimeSpan.Zero) is null, "retrieval policy: max stale 24h ok");
        check(ProviderPolicy.ValidateMaxStale(TimeSpan.FromHours(25)) is not null, "retrieval policy: 25h rejected not clamped");
        check(ProviderPolicy.ValidateMaxStale(TimeSpan.FromSeconds(-1)) is not null, "retrieval policy: negative rejected");

        TimeSpan max = TimeSpan.FromHours(24);
        check(ProviderPolicy.IsFreshEnough(max * 0.74, max), "retrieval policy: IsFreshEnough at 74% true");
        check(!ProviderPolicy.IsFreshEnough(max * 0.75, max), "retrieval policy: IsFreshEnough at 75% false");
        check(!ProviderPolicy.IsFreshEnough(TimeSpan.Zero, TimeSpan.Zero), "retrieval policy: IsFreshEnough with maxStale 0 false");
        check(ProviderPolicy.RefreshDue(max) == TimeSpan.FromHours(18), "retrieval policy: refresh due at 75%");
        check(ProviderPolicy.WithinStaleWindow(max, max) && !ProviderPolicy.WithinStaleWindow(max + TimeSpan.FromTicks(1), max) && !ProviderPolicy.WithinStaleWindow(TimeSpan.Zero, TimeSpan.Zero),
            "retrieval policy: WithinStaleWindow boundary inclusive");

        bool only = true;
        foreach (ProviderErrorKind kind in Enum.GetValues<ProviderErrorKind>())
        {
            bool expected = kind is ProviderErrorKind.Unavailable or ProviderErrorKind.RateLimited;
            only &= ProviderPolicy.StaleEligible(kind) == expected && ProviderPolicy.IsRetryable(kind) == expected;
        }

        check(only, "retrieval policy: stale eligible and retryable only Unavailable and RateLimited");
        check(ProviderPolicy.MaxAttempts == 3 && ProviderPolicy.RetryAfterCap == TimeSpan.FromSeconds(2) && ProviderPolicy.Deadline == TimeSpan.FromSeconds(10)
            && ProviderPolicy.Backoff.SequenceEqual([TimeSpan.FromMilliseconds(200), TimeSpan.FromMilliseconds(400)]), "retrieval policy: constants");
    }

    private static async Task Retrieval(Action<bool, string> check)
    {
        Rig rig = new();
        ProviderSecretRequest a = Req("p/a");
        ProviderSecretRequest b = Req("p/b");
        rig.Adapter.Returns("p/a", "alpha").Returns("p/b", "beta");
        IReadOnlyDictionary<Guid, RetrievalOutcome> outcomes = await rig.Run([a, b]);
        check(rig.Adapter.Invocations.Count == 1 && rig.Adapter.Invocations[0].Count == 2 && IsValue(outcomes, a.RequestId, "alpha") && IsValue(outcomes, b.RequestId, "beta")
            && rig.Delays.Count == 0, "retrieval: one invocation per instance batch with every request");

        rig = new Rig();
        a = Req("p/a");
        b = Req("p/b");
        rig.Adapter.Handler = (index, requests, _) => index == 0
            ? Results(Err(a.RequestId, ProviderErrorKind.Unavailable), Ok(b.RequestId, "beta"))
            : Results(Ok(a.RequestId, "alpha"));
        outcomes = await rig.Run([a, b]);
        check(rig.Adapter.Invocations.Count == 2 && rig.Adapter.Invocations[1].Count == 1 && rig.Adapter.Invocations[1][0].RequestId == a.RequestId
            && IsValue(outcomes, a.RequestId, "alpha") && IsValue(outcomes, b.RequestId, "beta"), "retrieval: Unavailable then success retries only the still-failing request");

        rig = new Rig();
        a = Req("p/a");
        rig.Adapter.Fails("p/a", ProviderErrorKind.Unavailable);
        outcomes = await rig.Run([a]);
        check(rig.Adapter.Invocations.Count == 3 && IsFailure(outcomes, a.RequestId, ProviderErrorKind.Unavailable)
            && rig.Delays.SequenceEqual([TimeSpan.FromMilliseconds(200), TimeSpan.FromMilliseconds(400)]), "retrieval: three Unavailable gives up, 3 invocations, delays 200ms and 400ms");

        rig = new Rig();
        a = Req("p/a");
        rig.Adapter.Fails("p/a", ProviderErrorKind.RateLimited, TimeSpan.FromSeconds(60));
        outcomes = await rig.Run([a]);
        check(rig.Delays.Count == 2 && rig.Delays.All(delay => delay == TimeSpan.FromSeconds(2)) && IsFailure(outcomes, a.RequestId, ProviderErrorKind.RateLimited),
            "retrieval: RateLimited with RetryAfter 60s waits only 2s");

        rig = new Rig();
        a = Req("p/a");
        rig.Adapter.Fails("p/a", ProviderErrorKind.RateLimited, TimeSpan.FromMilliseconds(5));
        await rig.Run([a]);
        check(rig.Delays.SequenceEqual([TimeSpan.FromMilliseconds(200), TimeSpan.FromMilliseconds(400)]), "retrieval: a short RetryAfter never shortens the backoff");

        rig = new Rig();
        a = Req("p/a");
        rig.Adapter.Fails("p/a", ProviderErrorKind.AccessDenied);
        outcomes = await rig.Run([a]);
        check(rig.Adapter.Invocations.Count == 1 && IsFailure(outcomes, a.RequestId, ProviderErrorKind.AccessDenied) && ((RetrievalFailure)outcomes[a.RequestId]).ProviderCode is null,
            "retrieval: AccessDenied not retried");

        rig = new Rig();
        a = Req("p/a");
        b = Req("p/b");
        rig.Adapter.Handler = (index, _, _) => index == 0
            ? throw new ProviderAdapterException(ProviderErrorKind.Unavailable, "down", "net")
            : Results(Ok(a.RequestId, "alpha"), Ok(b.RequestId, "beta"));
        outcomes = await rig.Run([a, b]);
        check(rig.Adapter.Invocations.Count == 2 && rig.Adapter.Invocations[1].Count == 2 && IsValue(outcomes, a.RequestId, "alpha") && IsValue(outcomes, b.RequestId, "beta"),
            "retrieval: batch-wide Unavailable exception retried for all outstanding");

        rig = new Rig();
        a = Req("p/a");
        b = Req("p/b");
        rig.Adapter.Handler = (_, _, _) => throw new ProviderAdapterException(ProviderErrorKind.Unavailable, "down", "net");
        outcomes = await rig.Run([a, b]);
        check(rig.Adapter.Invocations.Count == 3 && IsFailure(outcomes, a.RequestId, ProviderErrorKind.Unavailable) && IsFailure(outcomes, b.RequestId, ProviderErrorKind.Unavailable)
            && ((RetrievalFailure)outcomes[a.RequestId]).ProviderCode == "net", "retrieval: batch-wide exception exhausts for all outstanding, code kept");

        rig = new Rig();
        a = Req("p/a");
        b = Req("p/b");
        rig.Adapter.Handler = (_, _, _) => throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "bad");
        outcomes = await rig.Run([a, b]);
        check(rig.Adapter.Invocations.Count == 1 && IsFailure(outcomes, a.RequestId, ProviderErrorKind.InvalidConfiguration) && IsFailure(outcomes, b.RequestId, ProviderErrorKind.InvalidConfiguration),
            "retrieval: batch-wide InvalidConfiguration final for all");

        rig = new Rig();
        a = Req("p/a");
        b = Req("p/b");
        rig.Adapter.Handler = (_, _, _) => Results(Ok(a.RequestId, "S3cret-leak"), Ok(a.RequestId, "S3cret-leak"));
        outcomes = await rig.Run([a, b]);
        check(rig.Adapter.Invocations.Count == 1 && IsFailure(outcomes, a.RequestId, ProviderErrorKind.InvalidResponse) && IsFailure(outcomes, b.RequestId, ProviderErrorKind.InvalidResponse),
            "retrieval: malformed batch fails every outstanding request InvalidResponse, no value");

        rig = new Rig();
        a = Req("p/a");
        b = Req("p/a");
        rig.Adapter.Returns("p/a", "alpha");
        outcomes = await rig.Run([a, b]);
        check(outcomes.Count == 2 && IsValue(outcomes, a.RequestId, "alpha") && IsValue(outcomes, b.RequestId, "alpha"), "retrieval: repeated paths with distinct request ids stay attributed");

        rig = new Rig();
        a = Req("p/a");
        b = Req("p/b");
        rig.Adapter.Fails("p/a", ProviderErrorKind.AccessDenied).Returns("p/b", "beta");
        outcomes = await rig.Run([a, b]);
        check(IsFailure(outcomes, a.RequestId, ProviderErrorKind.AccessDenied) && IsValue(outcomes, b.RequestId, "beta") && rig.Adapter.Invocations.Count == 1,
            "retrieval: one item AccessDenied and one success are both reported, the success keeps its bytes");

        check((await rig.Run([])).Count == 0 && rig.Adapter.Invocations.Count == 1, "retrieval: no requests means no invocation");
    }

    private static async Task Failures(Action<bool, string> check)
    {
        Rig rig = new();
        ProviderSecretRequest a = Req("p/a");
        rig.Adapter.ReturnsBytes("p/a", [0xC3, 0x28]);
        IReadOnlyDictionary<Guid, RetrievalOutcome> outcomes = await rig.Run([a]);
        check(IsFailure(outcomes, a.RequestId, ProviderErrorKind.InvalidResponse), "retrieval: non-UTF8 value is InvalidResponse");

        rig = new Rig();
        a = Req("p/a");
        rig.Adapter.ReturnsBytes("p/a", []);
        outcomes = await rig.Run([a]);
        check(IsFailure(outcomes, a.RequestId, ProviderErrorKind.SecretNotFound), "retrieval: empty value is SecretNotFound");

        rig = new Rig();
        a = Req("p/a");
        rig.Adapter.Handler = (_, _, _) => throw new InvalidOperationException("boom hunter2");
        outcomes = await rig.Run([a]);
        check(IsFailure(outcomes, a.RequestId, ProviderErrorKind.Unknown) && rig.Adapter.Invocations.Count == 1, "retrieval: unexpected exception is Unknown, not retried");
    }

    private static async Task Cancellation(Action<bool, string> check)
    {
        Rig rig = new();
        ProviderSecretRequest a = Req("p/a");
        using CancellationTokenSource caller = new();
        rig.Adapter.Handler = (_, _, token) =>
        {
            caller.Cancel();
            token.ThrowIfCancellationRequested();

            return Results();
        };
        bool propagated = false;
        try
        {
            await rig.Run([a], caller.Token);
        }
        catch (OperationCanceledException)
        {
            propagated = true;
        }

        check(propagated && rig.Adapter.Invocations.Count == 1, "retrieval: caller cancellation propagates OperationCanceledException");

        a = Req("p/a");
        using CancellationTokenSource duringDelay = new();
        Rig cancelling = new();
        cancelling.Adapter.Fails("p/a", ProviderErrorKind.Unavailable);
        ProviderRetriever retriever = new(_ => cancelling.Adapter, TimeProvider.System, (_, token) =>
        {
            duringDelay.Cancel();
            token.ThrowIfCancellationRequested();

            return Task.CompletedTask;
        });
        propagated = false;
        try
        {
            await retriever.RetrieveAsync(Instance, [a], duringDelay.Token);
        }
        catch (OperationCanceledException)
        {
            propagated = true;
        }

        check(propagated && cancelling.Adapter.Invocations.Count == 1,"retrieval: caller cancellation during backoff propagates, no stale outcome");

        rig = new Rig(new FastTimerClock());
        a = Req("p/a");
        ProviderSecretRequest b = Req("p/b");
        rig.Adapter.Handler = async (_, _, token) =>
        {
            await Task.Delay(Timeout.Infinite, token);

            return [];
        };
        IReadOnlyDictionary<Guid, RetrievalOutcome> outcomes = await rig.Run([a, b], CancellationToken.None);
        check(IsFailure(outcomes, a.RequestId, ProviderErrorKind.Unavailable) && IsFailure(outcomes, b.RequestId, ProviderErrorKind.Unavailable) && rig.Adapter.Invocations.Count == 1,
            "retrieval: deadline exceeded while caller active is Unavailable");

        // Wrapped caller cancellation is still cancellation.
        rig = new Rig();
        a = Req("p/a");
        using CancellationTokenSource wrapped = new();
        rig.Adapter.Handler = (_, _, _) =>
        {
            wrapped.Cancel();

            throw new ProviderAdapterException(ProviderErrorKind.Unavailable, "wrapped");
        };
        check(await Rethrows(() => rig.Run([a], wrapped.Token)) && rig.Adapter.Invocations.Count == 1, "retrieval: cancellation wrapped in ProviderAdapterException still rethrows");

        rig = new Rig();
        using CancellationTokenSource wrappedOther = new();
        rig.Adapter.Handler = (_, _, _) =>
        {
            wrappedOther.Cancel();

            throw new InvalidOperationException("wrapped");
        };
        check(await Rethrows(() => rig.Run([a], wrappedOther.Token)), "retrieval: cancellation wrapped in another exception still rethrows");

        rig = new Rig();
        using CancellationTokenSource already = new();
        already.Cancel();
        check(await Rethrows(() => rig.Run([a], already.Token)) && rig.Adapter.Invocations.Count == 0, "retrieval: an already-cancelled token makes no adapter invocation");

        // An adapter that ignores its token cannot hold the deadline open.
        rig = new Rig(new FastTimerClock());
        a = Req("p/a");
        TaskCompletionSource<IReadOnlyList<ProviderSecretResult>> never = new();
        rig.Adapter.Handler = (_, _, _) => never.Task;
        outcomes = await rig.Run([a]);
        check(IsFailure(outcomes, a.RequestId, ProviderErrorKind.Unavailable), "retrieval: hung adapter that ignores its token fails Unavailable at the deadline");

        // What an abandoned adapter returns late is wiped, not left in memory.
        byte[] late = Encoding.UTF8.GetBytes("late");
        never.SetResult([new ProviderSecretResult(a.RequestId, new RetrieveSecretResult(late))]);
        for (int wait = 0; wait < 100 && !late.All(b => b == 0); wait++)
        {
            await Task.Delay(50);
        }

        check(late.All(b => b == 0), "retrieval: a result an abandoned adapter returns after the deadline is wiped");

        // Deadline during a backoff wait is Unavailable, not the last recorded kind.
        Rig limited = new();
        a = Req("p/a");
        limited.Adapter.Fails("p/a", ProviderErrorKind.RateLimited);
        ProviderRetriever waiting = new(_ => limited.Adapter, new FastTimerClock(), (_, token) => Task.Delay(Timeout.Infinite, token));
        outcomes = await waiting.RetrieveAsync(Instance, [a], CancellationToken.None);
        check(IsFailure(outcomes, a.RequestId, ProviderErrorKind.Unavailable), "retrieval: deadline during backoff is Unavailable");

        // A caller who cancels after part of a batch succeeded gets the cancellation, never partial outcomes.
        Rig partial = new();
        a = Req("p/a");
        ProviderSecretRequest second = Req("p/b");
        partial.Adapter.Handler = (_, _, _) => Results(Ok(a.RequestId, "alpha"), Err(second.RequestId, ProviderErrorKind.RateLimited));
        using CancellationTokenSource midway = new();
        ProviderRetriever interrupted = new(_ => partial.Adapter, TimeProvider.System, (_, token) =>
        {
            midway.Cancel();

            return Task.FromCanceled(midway.Token);
        });
        check(await Rethrows(() => interrupted.RetrieveAsync(Instance, [a, second], midway.Token)), "retrieval: cancelling after a partial success rethrows the cancellation");

        // The outcome owns its bytes.
        rig = new Rig();
        a = Req("p/a");
        byte[] source = Encoding.UTF8.GetBytes("alpha");
        rig.Adapter.ReturnsBytes("p/a", source);
        outcomes = await rig.Run([a]);
        Array.Clear(source);
        check(IsValue(outcomes, a.RequestId, "alpha"), "retrieval: the outcome does not alias the adapter's array");
    }

    private static async Task<bool> Rethrows(Func<Task> action)
    {
        try
        {
            await action();

            return false;
        }
        catch (OperationCanceledException)
        {
            return true;
        }
    }
}

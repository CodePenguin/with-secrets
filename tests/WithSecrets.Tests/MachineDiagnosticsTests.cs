namespace WithSecrets.Tests;

internal static class MachineDiagnosticsTests
{
    private sealed class RetryClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
        public void Advance(TimeSpan amount) => now += amount;

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
            => base.CreateTimer(callback, state, TimeSpan.FromMilliseconds(20), TimeSpan.FromMilliseconds(20));
    }

    public static async Task Run(Action<bool, string> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "ws-diagnostics-" + Guid.NewGuid().ToString("N"));
        string path = Path.Combine(root, "outbox", "pending.json");
        const string fingerprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        DateTimeOffset recorded = DateTimeOffset.UtcNow.AddHours(-2);
        RetryClock clock = new(recorded);
        try
        {
            DiagnosticOutbox original = new(path, clock);
            original.Report(DiagnosticCatalog.AuthorityConnected);
            original.Report(DiagnosticCatalog.AuthorityPollCompleted);
            original.Report(DiagnosticCatalog.InvalidationFailed);
            const int warningCount = 2 * DiagnosticWire.BatchLimit;
            for (int index = 0; index < warningCount; index++)
            {
                original.Report(DiagnosticCatalog.AuthorityLinkFailed);
                original.Report(DiagnosticCatalog.AuthorityLinkFailed);
                clock.Advance(TimeSpan.FromMinutes(1));
            }

            DiagnosticEvent[] expected = [.. DiagnosticFile.Read<DiagnosticEvent>(path)];
            check(expected.Length == warningCount + 1 && expected[0].Code == DiagnosticCatalog.InvalidationFailed && expected[0].Time == recorded
                && expected.Skip(1).All(item => item.Code == DiagnosticCatalog.AuthorityLinkFailed),
                "diagnostics: the default forwards errors and warnings, and coalesces repeats within a minute");

            using (CancellationTokenSource stopOffline = new(TimeSpan.FromSeconds(5)))
            {
                await original.RunAsync((_, _) =>
                {
                    stopOffline.Cancel();
                    throw new IOException("the connection is unavailable");
                }, stopOffline.Token);
            }
            check(DiagnosticFile.Read<DiagnosticEvent>(path).SequenceEqual(expected), "diagnostics: disconnect and host shutdown leave the pending warnings on disk");

            MachineDiagnosticsStore authority = new(Path.Combine(root, "authority"), TimeProvider.System);
            DiagnosticOutbox restarted = new(path, clock);
            using CancellationTokenSource stop = new(TimeSpan.FromSeconds(10));
            int attempts = 0;
            await restarted.RunAsync((batch, _) =>
            {
                authority.Record(fingerprint, batch);
                if (++attempts == 1)
                {
                    // The authority stored the batch, but the connection dropped before the host saw the acknowledgement.
                    check(DiagnosticFile.Read<DiagnosticEvent>(path).SequenceEqual(expected), "diagnostics: the first attempt after restart carries the original queue");
                    throw new IOException("the acknowledgement was lost");
                }

                if (authority.View(fingerprint).Items.Count == expected.Length)
                    stop.Cancel();
                return Task.CompletedTask;
            }, stop.Token);

            MachineDiagnosticsView received = authority.View(fingerprint);
            check(attempts == (expected.Length + DiagnosticWire.BatchLimit - 1) / DiagnosticWire.BatchLimit + 1
                && received.Items.Reverse().Select(item => item.Id).SequenceEqual(expected.Select(item => item.Id))
                && received.Items.Reverse().Select(item => item.Time).SequenceEqual(expected.Select(item => item.Time)),
                "diagnostics: reconnect automatically sends the persisted batches and retries a lost acknowledgement without duplicates");
            check(DiagnosticFile.Read<DiagnosticEvent>(path).Count == 0, "diagnostics: acknowledged warnings are removed from the durable outbox");

            DateTimeOffset now = clock.GetUtcNow();
            DiagnosticEvent expired = new(Guid.NewGuid(), now.AddHours(-73), DiagnosticCatalog.InvalidationFailed);
            DiagnosticEvent keep = new(Guid.NewGuid(), now.AddMinutes(-59), DiagnosticCatalog.InvalidationFailed);
            List<DiagnosticEvent> oversized = [expired, keep];
            oversized.AddRange(Enumerable.Range(0, 3000).Select(index =>
                new DiagnosticEvent(Guid.NewGuid(), now.AddSeconds(-index), DiagnosticCatalog.AuthorityPollCompleted)));
            DiagnosticFile.Write(path, oversized);
            DiagnosticSettings debug = new("debug");
            DiagnosticSettings? applied = null;
            using CancellationTokenSource stopBudget = new(TimeSpan.FromSeconds(5));
            await restarted.RunAsync((_, _) =>
            {
                stopBudget.Cancel();
                throw new IOException("the connection is unavailable");
            }, stopBudget.Token, _ => Task.FromResult(debug), level => applied = level);
            List<DiagnosticEvent> trimmed = DiagnosticFile.Read<DiagnosticEvent>(path, DiagnosticOutbox.QueueBytes);
            check(applied == debug && new FileInfo(path).Length <= DiagnosticOutbox.QueueBytes && trimmed.Contains(keep) && !trimmed.Contains(expired)
                && trimmed.Count < oversized.Count && trimmed.Any(item => item.Code == DiagnosticCatalog.AuthorityPollCompleted),
                "diagnostics: the disk budget retains errors ahead of debug entries and expires old entries");
            DiagnosticOutbox configuredRestart = new(path, clock);
            configuredRestart.Report(DiagnosticCatalog.AuthorityConnected);
            check(DiagnosticFile.Read<DiagnosticEvent>(path, DiagnosticOutbox.QueueBytes).Any(item => item.Code == DiagnosticCatalog.AuthorityConnected),
                "diagnostics: the machine log level is remembered across an offline restart");
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }
}

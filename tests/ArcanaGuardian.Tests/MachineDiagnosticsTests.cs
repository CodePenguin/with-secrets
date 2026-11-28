namespace ArcanaGuardian.Tests;

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
            const int warningCount = 4 * DiagnosticWire.BatchLimit;
            for (int index = 0; index < warningCount / 2; index++)
            {
                original.Report(DiagnosticCatalog.AuthorityLinkFailed);
                original.Report(DiagnosticCatalog.AuthorityLinkFailed);
                clock.Advance(TimeSpan.FromMinutes(1));
            }

            DiagnosticEvent[] expected = [.. DiagnosticFile.Read<DiagnosticEvent>(path)];
            check(expected.Length == warningCount + 1 && expected[0].Code == DiagnosticCatalog.InvalidationFailed && expected[0].Time == recorded
                && expected.Skip(1).All(item => item.Code == DiagnosticCatalog.AuthorityLinkFailed),
                "diagnostics: the default forwards errors and warnings, including repeated messages");

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

            DateTimeOffset oldTime = clock.GetUtcNow().AddDays(-7);
            DiagnosticEvent first = new(Guid.NewGuid(), oldTime, DiagnosticCatalog.InvalidationFailed);
            List<DiagnosticEvent> full = [first];
            full.AddRange(Enumerable.Range(1, DiagnosticOutbox.Capacity - 1).Select(_ =>
                new DiagnosticEvent(Guid.NewGuid(), oldTime, DiagnosticCatalog.AuthorityLinkFailed)));
            DiagnosticFile.Write(path, full);
            restarted.Report(DiagnosticCatalog.CheckInFailed);
            List<DiagnosticEvent> trimmed = DiagnosticFile.Read<DiagnosticEvent>(path, maxBytes: 1024 * 1024);
            check(trimmed.Count == 1000 && trimmed.Take(trimmed.Count - 1).SequenceEqual(full.Skip(1))
                && trimmed[^1].Code == DiagnosticCatalog.CheckInFailed,
                "diagnostics: the newest 1,000 queued messages are retained in arrival order, with no age or severity preference");

            DiagnosticSettings debug = new("debug");
            DiagnosticSettings? applied = null;
            using CancellationTokenSource stopDisconnected = new(TimeSpan.FromSeconds(5));
            await restarted.RunAsync((_, _) =>
            {
                stopDisconnected.Cancel();
                throw new IOException("the connection is unavailable");
            }, stopDisconnected.Token, _ => Task.FromResult(debug), level => applied = level);
            check(applied == debug && DiagnosticFile.Read<DiagnosticEvent>(path, maxBytes: 1024 * 1024).SequenceEqual(trimmed),
                "diagnostics: queued messages remain eligible for upload after a week offline");
            DiagnosticOutbox configuredRestart = new(path, clock);
            configuredRestart.Report(DiagnosticCatalog.AuthorityConnected);
            check(DiagnosticFile.Read<DiagnosticEvent>(path, maxBytes: 1024 * 1024).Any(item => item.Code == DiagnosticCatalog.AuthorityConnected),
                "diagnostics: the machine log level is remembered across an offline restart");
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }
}

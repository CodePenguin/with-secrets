namespace WithSecrets.Tests;

internal static class MachineDiagnosticsTests
{
    private sealed class RetryClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
            => base.CreateTimer(callback, state, TimeSpan.FromMilliseconds(20), TimeSpan.FromMilliseconds(20));
    }

    public static async Task Run(Action<bool, string> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "ws-diagnostics-" + Guid.NewGuid().ToString("N"));
        string path = Path.Combine(root, "outbox", "pending.json");
        const string fingerprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        DateTimeOffset recorded = DateTimeOffset.UtcNow.AddMinutes(-5);
        RetryClock clock = new(recorded);
        try
        {
            DiagnosticOutbox original = new(path, clock);
            for (int count = 0; count < DiagnosticOutbox.Capacity + 1; count++)
                original.Report(count == 0 ? DiagnosticCatalog.CheckInFailed : DiagnosticCatalog.AuthorityLinkFailed);

            DiagnosticEvent[] expected = [.. DiagnosticFile.Read<DiagnosticEvent>(path)];
            check(expected.Length == DiagnosticOutbox.Capacity && expected.All(item => item.Time == recorded && item.Code == DiagnosticCatalog.AuthorityLinkFailed),
                "diagnostics: the persisted outbox keeps the newest warnings with their original timestamps");

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
            check(attempts == (DiagnosticOutbox.Capacity + DiagnosticWire.BatchLimit - 1) / DiagnosticWire.BatchLimit + 1
                && received.Items.Reverse().Select(item => item.Id).SequenceEqual(expected.Select(item => item.Id))
                && received.Items.All(item => item.Time == recorded && item.ReceivedAt > item.Time),
                "diagnostics: reconnect automatically sends the persisted batches and retries a lost acknowledgement without duplicates");
            check(DiagnosticFile.Read<DiagnosticEvent>(path).Count == 0, "diagnostics: acknowledged warnings are removed from the durable outbox");
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }
}

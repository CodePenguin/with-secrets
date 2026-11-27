using System.Text.Json;
using System.Text.Json.Serialization;

namespace WithSecrets;

internal sealed record DiagnosticEvent(Guid Id, DateTimeOffset Time, string Code);
internal sealed record DiagnosticBatch(DiagnosticEvent[] Events);
internal sealed record ReceivedDiagnostic(DiagnosticEvent Event, DateTimeOffset ReceivedAt);
internal sealed record DiagnosticView(Guid Id, DateTimeOffset Time, DateTimeOffset ReceivedAt, string Severity, string Component, string Message);
internal sealed record MachineDiagnosticsView(DateTimeOffset? LastReceivedAt, IReadOnlyList<DiagnosticView> Items);

internal static class DiagnosticCatalog
{
    public const string CheckInFailed = "check-in-failed";
    public const string IdentityRenewalFailed = "identity-renewal-failed";
    public const string AuditEventsRejected = "audit-events-rejected";
    public const string AuthorityLinkFailed = "authority-link-failed";

    public static (string Component, string Message) Describe(string code) => code switch
    {
        CheckInFailed => ("Connection", "The machine could not check in with its authority."),
        IdentityRenewalFailed => ("Identity", "The machine could not renew its identity certificate."),
        AuditEventsRejected => ("Audit", "The authority refused one or more audit events."),
        AuthorityLinkFailed => ("Connection", "An operation could not reach its authority."),
        _ => ("", ""),
    };

    public static bool Valid(DiagnosticEvent? item) =>
        item is { Code: not null } && item.Id != Guid.Empty &&
        item.Time >= DateTimeOffset.UnixEpoch && Describe(item.Code).Component.Length > 0;
}

internal static class DiagnosticWire
{
    public const int BatchLimit = 24;
    internal static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        AllowDuplicateProperties = false,
    };

    public static bool TryRead(string body, out DiagnosticEvent[] events)
    {
        events = [];
        if (body.Length > 8192) return false;
        try
        {
            DiagnosticEvent[]? parsed = JsonSerializer.Deserialize<DiagnosticBatch>(body, Json)?.Events;
            if (parsed is not { Length: > 0 and <= BatchLimit } || !parsed.All(DiagnosticCatalog.Valid)) return false;
            events = parsed;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}

/// <summary>Bounded, best-effort host queue. Failed delivery leaves the entries queued while the service is running.</summary>
internal sealed class DiagnosticOutbox(TimeProvider clock)
{
    private const int Capacity = 128;
    private readonly Lock _gate = new();
    private readonly Queue<DiagnosticEvent> _events = new();

    public void Report(string code)
    {
        lock (_gate)
        {
            if (_events.Count >= Capacity) _events.Dequeue();
            _events.Enqueue(new DiagnosticEvent(Guid.NewGuid(), clock.GetUtcNow(), code));
        }
    }

    public async Task RunAsync(Func<DiagnosticEvent[], CancellationToken, Task> deliver, CancellationToken stop)
    {
        try
        {
            using PeriodicTimer timer = new(TimeSpan.FromSeconds(15));
            while (await timer.WaitForNextTickAsync(stop))
            {
                DiagnosticEvent[] batch;
                lock (_gate)
                {
                    batch = [.. _events.Take(DiagnosticWire.BatchLimit)];
                }
                if (batch.Length == 0) continue;

                try
                {
                    await deliver(batch, stop);
                }
                catch (Exception error) when (error is not OutOfMemoryException)
                {
                    // The queue is best effort and independent of audit and approvals.
                    if (stop.IsCancellationRequested) return;
                    continue;
                }

                HashSet<Guid> delivered = batch.Select(item => item.Id).ToHashSet();
                lock (_gate)
                {
                    while (_events.TryPeek(out DiagnosticEvent? next) && delivered.Contains(next.Id))
                    {
                        _events.Dequeue();
                    }
                }
            }
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested)
        {
            // The service is shutting down.
        }
    }
}

/// <summary>The authority keeps the most recent entries for each machine in the private state directory.</summary>
internal sealed class MachineDiagnosticsStore(string folder, TimeProvider clock)
{
    internal const int RetainedPerMachine = 200;
    private readonly Lock _gate = new();

    public void Record(string fingerprint, DiagnosticEvent[] batch)
    {
        string path = PathFor(fingerprint);
        lock (_gate)
        {
            List<ReceivedDiagnostic> entries = Read(path);
            HashSet<Guid> known = entries.Select(row => row.Event.Id).ToHashSet();
            int previousCount = entries.Count;
            DateTimeOffset received = clock.GetUtcNow();
            foreach (DiagnosticEvent item in batch)
            {
                if (DiagnosticCatalog.Valid(item) && known.Add(item.Id)) entries.Add(new ReceivedDiagnostic(item, received));
            }
            if (entries.Count == previousCount) return;
            if (entries.Count > RetainedPerMachine)
                entries.RemoveRange(0, entries.Count - RetainedPerMachine);

            if (OperatingSystem.IsWindows())
                Directory.CreateDirectory(folder);
            else
                Directory.CreateDirectory(folder, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                FileStreamOptions options = new() { Mode = FileMode.CreateNew, Access = FileAccess.Write };
                if (!OperatingSystem.IsWindows())
                    options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
                using (FileStream stream = new(temporary, options))
                    JsonSerializer.Serialize(stream, entries, DiagnosticWire.Json);
                File.Move(temporary, path, overwrite: true);
            }
            finally
            {
                File.Delete(temporary);
            }
        }
    }

    public MachineDiagnosticsView View(string fingerprint)
    {
        List<ReceivedDiagnostic> entries;
        lock (_gate) entries = Read(PathFor(fingerprint));
        DateTimeOffset? lastReceivedAt = entries.Count == 0 ? null : entries[^1].ReceivedAt;
        entries.Reverse();
        return new MachineDiagnosticsView(lastReceivedAt, [.. entries.Select(row =>
        {
            (string component, string message) = DiagnosticCatalog.Describe(row.Event.Code);
            return new DiagnosticView(row.Event.Id, row.Event.Time, row.ReceivedAt, "warning", component, message);
        })]);
    }

    private string PathFor(string fingerprint)
    {
        if (fingerprint.Length != 64 || !fingerprint.All(Uri.IsHexDigit))
            throw new ArgumentException("a full machine fingerprint is required", nameof(fingerprint));
        return Path.Combine(folder, fingerprint.ToUpperInvariant() + ".json");
    }

    private static List<ReceivedDiagnostic> Read(string path)
    {
        try
        {
            using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
            if (stream.Length > 65536) throw new IOException("the machine diagnostics file is too large");
            List<ReceivedDiagnostic>? rows = JsonSerializer.Deserialize<List<ReceivedDiagnostic>>(stream, DiagnosticWire.Json);
            return rows is null ? [] : rows.Where(row => DiagnosticCatalog.Valid(row?.Event)).TakeLast(RetainedPerMachine).ToList();
        }
        catch (Exception error) when (error is FileNotFoundException or DirectoryNotFoundException)
        {
            return [];
        }
    }
}

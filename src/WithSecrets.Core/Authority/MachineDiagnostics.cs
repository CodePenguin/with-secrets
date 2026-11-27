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

/// <summary>The host keeps its newest unsent warnings and removes them after the authority accepts the upload.</summary>
internal sealed class DiagnosticOutbox(string path, TimeProvider clock)
{
    internal const int Capacity = 128;
    private readonly Lock _gate = new();

    public void Report(string code)
    {
        try
        {
            lock (_gate)
            {
                List<DiagnosticEvent> pending = ReadPending();
                pending.Add(new DiagnosticEvent(Guid.NewGuid(), clock.GetUtcNow(), code));
                if (pending.Count > Capacity)
                    pending.RemoveRange(0, pending.Count - Capacity);
                DiagnosticFile.Write(path, pending);
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            AppLog.Warn("a machine diagnostic could not be queued: {Type}", error.GetType().Name);
        }
    }

    public async Task RunAsync(Func<DiagnosticEvent[], CancellationToken, Task> deliver, CancellationToken stop)
    {
        try
        {
            using PeriodicTimer timer = new(TimeSpan.FromSeconds(15), clock);
            do
            {
                try
                {
                    await DrainAsync(deliver, stop);
                }
                catch (Exception error) when (error is not OutOfMemoryException)
                {
                    // Failed delivery and local storage failures can be retried on the next tick.
                    if (stop.IsCancellationRequested) return;
                }
            } while (await timer.WaitForNextTickAsync(stop));
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested)
        {
            // The service is shutting down.
        }
    }

    private async Task DrainAsync(Func<DiagnosticEvent[], CancellationToken, Task> deliver, CancellationToken stop)
    {
        List<DiagnosticEvent> snapshot;
        lock (_gate) snapshot = ReadPending();

        foreach (DiagnosticEvent[] batch in snapshot.Chunk(DiagnosticWire.BatchLimit))
        {
            stop.ThrowIfCancellationRequested();
            await deliver(batch, stop);

            HashSet<Guid> acknowledged = batch.Select(item => item.Id).ToHashSet();
            lock (_gate)
            {
                List<DiagnosticEvent> pending = ReadPending();
                if (pending.RemoveAll(item => acknowledged.Contains(item.Id)) != 0)
                    DiagnosticFile.Write(path, pending);
            }
        }
    }

    private List<DiagnosticEvent> ReadPending()
    {
        try
        {
            return DiagnosticFile.Read<DiagnosticEvent>(path).Where(DiagnosticCatalog.Valid).TakeLast(Capacity).ToList();
        }
        catch (JsonException)
        {
            // A malformed snapshot cannot be replayed. The next warning can start a fresh queue.
            return [];
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

            DiagnosticFile.Write(path, entries);
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

    private static List<ReceivedDiagnostic> Read(string path) => DiagnosticFile.Read<ReceivedDiagnostic>(path)
        .Where(row => DiagnosticCatalog.Valid(row?.Event)).TakeLast(RetainedPerMachine).ToList();
}

/// <summary>Private, bounded snapshots for the host outbox and authority history.</summary>
internal static class DiagnosticFile
{
    public static List<T> Read<T>(string path)
    {
        try
        {
            using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
            if (stream.Length > 65536) throw new IOException("the machine diagnostics file is too large");
            return JsonSerializer.Deserialize<List<T>>(stream, DiagnosticWire.Json) ?? [];
        }
        catch (Exception error) when (error is FileNotFoundException or DirectoryNotFoundException)
        {
            return [];
        }
    }

    public static void Write<T>(string path, List<T> rows)
    {
        string folder = Path.GetDirectoryName(path)!;
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
            {
                JsonSerializer.Serialize(stream, rows, DiagnosticWire.Json);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
            if (OperatingSystem.IsLinux())
                LinuxHardening.SyncDirectory(folder);
        }
        finally
        {
            File.Delete(temporary);
        }
    }
}

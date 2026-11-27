using System.Text.Json;
using System.Text.Json.Serialization;

namespace WithSecrets;

internal sealed record DiagnosticEvent(Guid Id, DateTimeOffset Time, string Code);
internal sealed record DiagnosticBatch(DiagnosticEvent[] Events);
internal sealed record ReceivedDiagnostic(DiagnosticEvent Event, DateTimeOffset ReceivedAt);
internal sealed record DiagnosticView(Guid Id, DateTimeOffset Time, DateTimeOffset ReceivedAt, string Severity, string Component, string Message);
internal sealed record MachineDiagnosticsView(DateTimeOffset? LastReceivedAt, IReadOnlyList<DiagnosticView> Items);

internal sealed record DiagnosticSettings(string Level, int QueueKiB, int RetentionHours)
{
    public const int MinQueueKiB = 16;
    public const int MaxQueueKiB = 1024;
    public const int MaxRetentionHours = 168;
    public static readonly string[] Levels = ["error", "warning", "information", "debug"];
    public static DiagnosticSettings Default { get; } = new("warning", 256, 72);

    public bool Valid() => Levels.Contains(Level, StringComparer.Ordinal)
        && QueueKiB is >= MinQueueKiB and <= MaxQueueKiB && RetentionHours is >= 1 and <= MaxRetentionHours;

    public bool Includes(string code) => Rank(DiagnosticCatalog.Describe(code).Severity) >= Rank(Level);

    public static int Rank(string severity) => severity switch
    {
        "error" => 3,
        "warning" => 2,
        "information" => 1,
        "debug" => 0,
        _ => -1,
    };
}

internal static class DiagnosticCatalog
{
    public const string CheckInFailed = "check-in-failed";
    public const string IdentityRenewalFailed = "identity-renewal-failed";
    public const string AuditEventsRejected = "audit-events-rejected";
    public const string AuthorityLinkFailed = "authority-link-failed";
    public const string MachineEndpointFailed = "machine-endpoint-failed";
    public const string InvalidationFailed = "invalidation-failed";
    public const string LaunchFailed = "launch-failed";
    public const string AuthorityConnected = "authority-connected";
    public const string IdentityRenewed = "identity-renewed";
    public const string AuthorityPollCompleted = "authority-poll-completed";

    public static (string Severity, string Component, string Message) Describe(string code) => code switch
    {
        CheckInFailed => ("warning", "Connection", "The machine could not check in with its authority."),
        IdentityRenewalFailed => ("warning", "Identity", "The machine could not renew its identity certificate."),
        AuditEventsRejected => ("warning", "Audit", "The authority refused one or more audit events."),
        AuthorityLinkFailed => ("warning", "Connection", "The machine could not complete an operation with its authority."),
        MachineEndpointFailed => ("error", "Connection", "The authority could not start its machine endpoint."),
        InvalidationFailed => ("error", "Authorization", "The machine could not apply a change from its authority."),
        LaunchFailed => ("error", "Launch", "A command launch failed inside the host service."),
        AuthorityConnected => ("information", "Connection", "The machine checked in with its authority."),
        IdentityRenewed => ("information", "Identity", "The machine renewed its identity certificate."),
        AuthorityPollCompleted => ("debug", "Connection", "The machine completed a poll of its authority."),
        _ => ("", "", ""),
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
    private readonly Lock _gate = new();
    private readonly Dictionary<string, DateTimeOffset> _reported = new(StringComparer.Ordinal);
    private DiagnosticSettings? _settings;

    public void Report(string code)
    {
        try
        {
            lock (_gate)
            {
                DiagnosticSettings settings = CurrentSettings();
                if (!settings.Includes(code)) return;
                DateTimeOffset now = clock.GetUtcNow();
                DateTimeOffset repeatSince = now.AddMinutes(-1);
                if (_reported.TryGetValue(code, out DateTimeOffset last) && last > repeatSince) return;
                List<DiagnosticEvent> pending = ReadPending();
                if (pending.Any(item => item.Code == code && item.Time > repeatSince))
                    return;
                pending.Add(new DiagnosticEvent(Guid.NewGuid(), now, code));
                Prune(pending, settings, now);
                DiagnosticFile.Write(path, pending);
                _reported[code] = now;
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            AppLog.Warn("a machine diagnostic could not be queued: {Type}", error.GetType().Name);
        }
    }

    public async Task RunAsync(Func<DiagnosticEvent[], CancellationToken, Task> deliver, CancellationToken stop,
        Func<CancellationToken, Task<DiagnosticSettings>>? fetchSettings = null)
    {
        try
        {
            using PeriodicTimer timer = new(TimeSpan.FromSeconds(15), clock);
            do
            {
                try
                {
                    List<DiagnosticEvent> snapshot;
                    try
                    {
                        if (fetchSettings is not null) ApplySettings(await fetchSettings(stop));
                    }
                    finally
                    {
                        // Expire queued events even when the authority is unreachable.
                        snapshot = stop.IsCancellationRequested ? [] : PendingSnapshot();
                    }
                    await DrainAsync(snapshot, deliver, stop);
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

    private List<DiagnosticEvent> PendingSnapshot()
    {
        lock (_gate)
        {
            List<DiagnosticEvent> snapshot = ReadPending();
            if (Prune(snapshot, CurrentSettings(), clock.GetUtcNow()))
                DiagnosticFile.Write(path, snapshot);
            return snapshot;
        }
    }

    private async Task DrainAsync(List<DiagnosticEvent> snapshot, Func<DiagnosticEvent[], CancellationToken, Task> deliver, CancellationToken stop)
    {
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
            return DiagnosticFile.Read<DiagnosticEvent>(path, DiagnosticSettings.MaxQueueKiB * 1024).Where(DiagnosticCatalog.Valid).ToList();
        }
        catch (JsonException)
        {
            // A malformed snapshot cannot be replayed. The next warning can start a fresh queue.
            return [];
        }
    }

    private DiagnosticSettings CurrentSettings()
    {
        if (_settings is not null) return _settings;
        try
        {
            DiagnosticSettings? saved = DiagnosticFile.Read<DiagnosticSettings>(path + ".settings").FirstOrDefault();
            return _settings = saved is not null && saved.Valid() ? saved : DiagnosticSettings.Default;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException)
        {
            return _settings = DiagnosticSettings.Default;
        }
    }

    private void ApplySettings(DiagnosticSettings settings)
    {
        if (!settings.Valid()) throw new IOException("the authority returned invalid diagnostics settings");
        lock (_gate)
        {
            if (settings == CurrentSettings()) return;
            DiagnosticFile.Write<DiagnosticSettings>(path + ".settings", [settings]);
            _settings = settings;
        }
    }

    private static bool Prune(List<DiagnosticEvent> pending, DiagnosticSettings settings, DateTimeOffset now)
    {
        DateTimeOffset cutoff = now.AddHours(-settings.RetentionHours);
        int removed = pending.RemoveAll(item => item.Time < cutoff || !settings.Includes(item.Code));
        int budget = settings.QueueKiB * 1024;
        int size = JsonSerializer.SerializeToUtf8Bytes(pending, DiagnosticWire.Json).Length;
        if (size <= budget) return removed > 0;

        HashSet<Guid> evicted = [];
        foreach (DiagnosticEvent item in pending.OrderBy(item => DiagnosticSettings.Rank(DiagnosticCatalog.Describe(item.Code).Severity)).ThenBy(item => item.Time))
        {
            evicted.Add(item.Id);
            size -= JsonSerializer.SerializeToUtf8Bytes(item, DiagnosticWire.Json).Length + 1;
            if (size <= budget) break;
        }
        pending.RemoveAll(item => evicted.Contains(item.Id));
        return true;
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
            (string severity, string component, string message) = DiagnosticCatalog.Describe(row.Event.Code);
            return new DiagnosticView(row.Event.Id, row.Event.Time, row.ReceivedAt, severity, component, message);
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
    public static List<T> Read<T>(string path, int maxBytes = 65536)
    {
        try
        {
            using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
            if (stream.Length > maxBytes) throw new IOException("the machine diagnostics file is too large");
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

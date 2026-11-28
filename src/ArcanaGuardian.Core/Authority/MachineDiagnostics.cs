using System.Text.Json;
using System.Text.Json.Serialization;

namespace ArcanaGuardian;

internal sealed record DiagnosticEvent(Guid Id, DateTimeOffset Time, string Code);
internal sealed record DiagnosticBatch(DiagnosticEvent[] Events);
internal sealed record ReceivedDiagnostic(DiagnosticEvent Event, DateTimeOffset ReceivedAt);
internal sealed record DiagnosticView(Guid Id, DateTimeOffset Time, DateTimeOffset ReceivedAt, string Severity, string Component, string Message);
internal sealed record MachineDiagnosticsView(DateTimeOffset? LastReceivedAt, IReadOnlyList<DiagnosticView> Items);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Skip)]
internal sealed record DiagnosticSettings(string Level)
{
    public static readonly string[] Levels = ["error", "warning", "information", "debug"];
    public static DiagnosticSettings Default { get; } = new("warning");

    public bool Valid() => Levels.Contains(Level, StringComparer.Ordinal);

    public bool Includes(string code) => Rank(DiagnosticCatalog.Describe(code).Severity) >= Rank(Level);

    private static int Rank(string severity) => severity switch
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

/// <summary>The host keeps its newest unsent messages and removes them after the authority accepts the upload.</summary>
internal sealed class DiagnosticOutbox(string path, TimeProvider clock)
{
    internal const int Capacity = 1000;
    private readonly Lock _gate = new();
    private DiagnosticSettings? _settings;

    internal DiagnosticSettings Settings
    {
        get { lock (_gate) return CurrentSettings(); }
    }

    public void Report(string code)
    {
        try
        {
            lock (_gate)
            {
                DiagnosticSettings settings = CurrentSettings();
                if (!settings.Includes(code)) return;
                List<DiagnosticEvent> pending = ReadPending();
                pending.Add(new DiagnosticEvent(Guid.NewGuid(), clock.GetUtcNow(), code));
                pending.RemoveRange(0, Math.Max(0, pending.Count - Capacity));
                DiagnosticFile.Write(path, pending);
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            AppLog.Warn("a machine diagnostic could not be queued: {Type}", error.GetType().Name);
        }
    }

    public async Task RunAsync(Func<DiagnosticEvent[], CancellationToken, Task> deliver, CancellationToken stop,
        Func<CancellationToken, Task<DiagnosticSettings>>? fetchSettings = null, Action<DiagnosticSettings>? onLevelChanged = null)
    {
        try
        {
            using PeriodicTimer timer = new(TimeSpan.FromSeconds(15), clock);
            do
            {
                try
                {
                    if (fetchSettings is not null)
                    {
                        DiagnosticSettings settings = await fetchSettings(stop);
                        if (ApplySettings(settings)) onLevelChanged?.Invoke(settings);
                    }
                    await DrainAsync(PendingSnapshot(), deliver, stop);
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
            int previousCount = snapshot.Count;
            DiagnosticSettings settings = CurrentSettings();
            snapshot.RemoveAll(item => !settings.Includes(item.Code));
            snapshot.RemoveRange(0, Math.Max(0, snapshot.Count - Capacity));
            if (snapshot.Count != previousCount)
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
            // Read prior development snapshots up to their former limit so they can be trimmed in place.
            return DiagnosticFile.Read<DiagnosticEvent>(path, 1024 * 1024).Where(DiagnosticCatalog.Valid).ToList();
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

    private bool ApplySettings(DiagnosticSettings settings)
    {
        if (!settings.Valid()) throw new IOException("the authority returned invalid diagnostics settings");
        lock (_gate)
        {
            if (settings == CurrentSettings()) return false;
            try
            {
                DiagnosticFile.Write<DiagnosticSettings>(path + ".settings", [settings]);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                AppLog.Warn("the machine log level could not be saved for restart: {Type}", error.GetType().Name);
            }
            _settings = settings;
            return true;
        }
    }
}

/// <summary>The authority keeps the most recent entries for each machine in the private state directory.</summary>
internal sealed class MachineDiagnosticsStore(string folder, TimeProvider clock)
{
    internal const int RetainedPerMachine = DiagnosticOutbox.Capacity;
    private const int MaxHistoryBytes = 256 * 1024;
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

    private static List<ReceivedDiagnostic> Read(string path) => DiagnosticFile.Read<ReceivedDiagnostic>(path, MaxHistoryBytes)
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

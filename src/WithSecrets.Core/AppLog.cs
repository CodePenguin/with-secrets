using System.Globalization;
using System.Text;

using Serilog;
using Serilog.Core;
using Serilog.Events;

namespace WithSecrets;

/// <summary>
/// Diagnostics, through Serilog. The program's own output (results, errors, links, prompts) is not logged here: it goes to the
/// terminal as before. This is for the lines that explain what the program is doing, such as "connection opened (3 s)".
/// <list type="bullet">
/// <item>Normal mode: Debug events go nowhere. Warnings and above are written to the log file only.</item>
/// <item>--debug or WITH_SECRETS_DEBUG=1: Debug events go to the terminal (through <see cref="TerminalPrompt.Noise" />, written as
/// they arrive) and, with everything above, to the file.</item>
/// </list>
/// A running host service uses its machine log level as the minimum for both its local logs and its structured diagnostics.
/// The file is %USERPROFILE%\.with-secrets\logs\with-secrets-YYYYMMDD.log: daily, 1 MB per file, 7 files kept. A file that cannot
/// be opened or written never fails a command.
/// <para>
/// What may be logged: route words, sizes, whole seconds, exception type names. Call sites use constant templates only; never a
/// path with its token, a request body, a key, PRF output, a code, a secret name with its value, or exception text.
/// </para>
/// </summary>
public static class AppLog
{
    /// <summary>The environment variable that switches --debug on for every command.</summary>
    public const string DebugVariable = "WITH_SECRETS_DEBUG";

    internal const long DefaultFileSizeLimit = 1024 * 1024;

    internal const int RetainedFiles = 7;

    private const string FileName = "with-secrets-.log";

    private const string Prefix = "with-secrets: ";

    private static readonly Lock Gate = new();
    private static readonly LoggingLevelSwitch OutputLevel = new(LogEventLevel.Warning);
    private static Logger? _logger;

    /// <summary>For tests: where the log file goes (the user's .with-secrets\logs when null).</summary>
    internal static string? LogFolder { get; set; }

    /// <summary>For tests: the size at which a log file rolls.</summary>
    internal static long FileSizeLimit { get; set; } = DefaultFileSizeLimit;

    /// <summary>For tests: also receives every event, whatever the mode (null when not set).</summary>
    internal static ILogEventSink? Tap { get; set; }

    internal static string DefaultFolder => Path.Combine(TestIsolation.StoreFolder, "logs");

    /// <summary>True when --debug was given or WITH_SECRETS_DEBUG is 1.</summary>
    public static bool DebugRequested(bool flag) => flag || Environment.GetEnvironmentVariable(DebugVariable) == "1";

    /// <summary>
    /// Starts logging for this run. In debug mode the Debug events go to the terminal and the file; otherwise only warnings and
    /// above go to the file. Never throws: when the file cannot be opened the run goes on without one.
    /// </summary>
    public static void Configure(bool debug)
    {
        Logger created = Build(debug, true);
        Logger? old;
        lock (Gate)
        {
            OutputLevel.MinimumLevel = debug ? LogEventLevel.Debug : LogEventLevel.Warning;
            old = _logger;
            _logger = created;
        }

        old?.Dispose();
    }

    internal static void SetMachineLogLevel(DiagnosticSettings settings) => OutputLevel.MinimumLevel = settings.Level switch
    {
        "error" => LogEventLevel.Error,
        "information" => LogEventLevel.Information,
        "debug" => LogEventLevel.Debug,
        _ => LogEventLevel.Warning,
    };

    /// <summary>Ends logging (flushes the file). Events after this go nowhere until <see cref="Configure" />.</summary>
    public static void Close()
    {
        Logger? old;
        lock (Gate)
        {
            old = _logger;
            _logger = null;
        }

        old?.Dispose();
    }

    /// <summary>A diagnostic event at Debug level.</summary>
    internal static void Debug(string template, params object?[] values) => Write(LogEventLevel.Debug, template, values);

    internal static void Info(string template, params object?[] values) => Write(LogEventLevel.Information, template, values);

    /// <summary>Something went wrong that the person may be asked about later.</summary>
    internal static void Warn(string template, params object?[] values) => Write(LogEventLevel.Warning, template, values);

    internal static void Error(string template, params object?[] values) => Write(LogEventLevel.Error, template, values);

    /// <summary>The line as the terminal and the tests see it: the message with the program's prefix.</summary>
    internal static string Render(LogEvent logEvent) => Prefix + logEvent.RenderMessage(CultureInfo.InvariantCulture);

    private static void Write(LogEventLevel level, string template, object?[] values)
    {
        try
        {
            Logger? logger;
            lock (Gate)
            {
                logger = _logger ??= Build(false, false);
            }

            logger.Write(level, template, values);
        }
        catch (Exception)
        {
            // Logging never fails a command.
        }
    }

    private static Logger Build(bool debug, bool toFile)
    {
        if (toFile)
        {
            try
            {
                return Make(debug, true);
            }
            catch (Exception)
            {
                // No file: the run goes on with the terminal side only.
            }
        }

        return Make(debug, false);
    }

    private static Logger Make(bool debug, bool withFile)
    {
        // The Tap sink is read at event time, so a test can set it before or after Configure.
        LoggerConfiguration config = new LoggerConfiguration().MinimumLevel.Debug().WriteTo.Sink(new TapSink());
        if (debug)
        {
            config.WriteTo.Sink(new TerminalSink(), levelSwitch: OutputLevel);
        }

        if (withFile)
        {
            config.WriteTo.File(
                Path.Combine(LogFolder ?? DefaultFolder, FileName),
                levelSwitch: OutputLevel,
                outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:l}{NewLine}",
                formatProvider: CultureInfo.InvariantCulture,
                fileSizeLimitBytes: FileSizeLimit,
                rollingInterval: RollingInterval.Day,
                rollOnFileSizeLimit: true,
                retainedFileCountLimit: RetainedFiles,
                shared: true,
                encoding: new UTF8Encoding(false));
        }

        return config.CreateLogger();
    }

    private sealed class TapSink : ILogEventSink
    {
        public void Emit(LogEvent logEvent) => Tap?.Emit(logEvent);
    }

    /// <summary>The terminal side of --debug: each line is written as it arrives.</summary>
    private sealed class TerminalSink : ILogEventSink
    {
        public void Emit(LogEvent logEvent) => TerminalPrompt.Noise(Render(logEvent));
    }
}

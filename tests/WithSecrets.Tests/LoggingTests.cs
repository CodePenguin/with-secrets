using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

using Microsoft.Data.Sqlite;

using Serilog.Core;
using Serilog.Events;

namespace WithSecrets.Tests;

/// <summary>
/// Diagnostics through Serilog. Normal mode: the terminal shows what it always showed (results, errors, links, prompts) and no
/// diagnostic line; warnings and above go to the log file. --debug (or WITH_SECRETS_DEBUG=1): Debug events go to the terminal
/// (dropped while the code prompt waits) and to the file. The log holds route words, sizes and seconds, never a value.
/// </summary>
internal static class LoggingTests
{
    private const string Boom = "FAULT-TEXT-9917";
    private static readonly Regex Diagnostic = new("^with-secrets: (connection opened|request |proof |step )", RegexOptions.CultureInvariant);
    private static readonly Regex LogLine = new(@"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3} [+-]\d\d:\d\d \[(DBG|WRN|ERR|INF)\] [A-Za-z0-9 ():,./'-]+$", RegexOptions.CultureInvariant);
    private static readonly Regex LinkText = new("https?://\\S+", RegexOptions.CultureInvariant);

    /// <summary>Collects every event the logger dispatches (any level), as the tests' view of "what was logged".</summary>
    private sealed class Capture : ILogEventSink
    {
        public ConcurrentQueue<LogEvent> Events { get; } = new();

        public void Emit(LogEvent logEvent) => Events.Enqueue(logEvent);

        public string[] Lines(LogEventLevel? level = null) => [.. Events.Where(item => level is null || item.Level == level).Select(AppLog.Render)];

        /// <summary>The message and every property value of every event: where a value must never be.</summary>
        public string[] Everything() => [.. Events.Select(item => AppLog.Render(item) + "\n" + string.Join("\n", item.Properties.Select(pair => pair.Key + "=" + pair.Value)))];
    }

    private sealed class Setup : IDisposable
    {
        private readonly TextWriter? _before = TerminalPrompt.Output;

        public Setup(string folder, bool debug)
        {
            Folder = folder;
            Terminal = new StringWriter();
            Events = new Capture();
            TerminalPrompt.Output = Terminal;
            AppLog.LogFolder = folder;
            AppLog.Tap = Events;
            AppLog.Configure(debug);
        }

        public string Folder { get; }

        public StringWriter Terminal { get; }

        public Capture Events { get; }

        /// <summary>The terminal text so far.</summary>
        public string Screen
        {
            get
            {
                lock (Terminal)
                {
                    return Terminal.ToString().Replace("\r\n", "\n", StringComparison.Ordinal);
                }
            }
        }

        /// <summary>Ends the logger (everything is on disk) and gives the log files' text.</summary>
        public string Files()
        {
            AppLog.Close();

            return LogText(Folder);
        }

        public void Dispose()
        {
            AppLog.Close();
            AppLog.LogFolder = null;
            AppLog.Tap = null;
            AppLog.FileSizeLimit = AppLog.DefaultFileSizeLimit;
            TerminalPrompt.Output = _before;
            TerminalPrompt.Input = null;
        }
    }

    private static string[] LogFiles(string folder) => Directory.Exists(folder) ? [.. Directory.EnumerateFiles(folder, "with-secrets-*.log").Order(StringComparer.Ordinal)] : [];

    private static string LogText(string folder) => string.Join("\n", LogFiles(folder).Select(file => Encoding.UTF8.GetString(ReadShared(file))));

    private static byte[] ReadShared(string file)
    {
        using FileStream stream = new(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using MemoryStream copy = new();
        stream.CopyTo(copy);

        return copy.ToArray();
    }

    public static async Task Run(Action<bool, string> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "ws-logging-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            CommandLineFlag(check);
            Folders(check, root);
            await NormalMode(check, root);
            await DebugMode(check, root);
            await PromptGate(check, root);
            await PromptLastNormal(check, root);
            FileRules(check, root);
            await Faults(check, root);
            await Flows(check, root);
            await Leaks(check, root);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            AppLog.Close();
            Directory.Delete(root, true);
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // The command line
    // ---------------------------------------------------------------------------------------------------------------

    private static void CommandLineFlag(Action<bool, string> check)
    {
        (string Mode, string[] Args)[] modes =
        [
            ("--needs", ["--needs"]),
            ("--needs -f", ["--needs", "-f", ".env"]),
            ("--recover", ["--recover"]),
            ("a run", ["--secrets", "A_NAME", "--reason", "why", "--", "prog", "arg"]),
            ("a run with only a reason", ["--reason", "why", "--", "prog"]),
        ];
        foreach ((string mode, string[] args) in modes)
        {
            CliCommand? plain = CliArgs.Parse(args, out string plainError);
            string[] withFlag = [.. args.TakeWhile(item => item != "--"), "--debug", .. args.SkipWhile(item => item != "--")];
            CliCommand? flagged = CliArgs.Parse(withFlag, out string flagError);
            CliCommand? first = CliArgs.Parse(["--debug", .. args], out string firstError);
            check(plain is not null && !plain.Debug && flagged is not null && flagged.Debug && first is not null && first.Debug, $"debug flag: {mode}: --debug is accepted and set, and off by default ({plainError}{flagError}{firstError})");
            check(plain is not null && flagged is not null && plain.GetType() == flagged.GetType() && plain.Port == flagged.Port, $"debug flag: {mode}: --debug changes nothing else in the command");
        }

        CliCommand? withPort = CliArgs.Parse(["--recover", "--port", "4455", "--debug"], out _);
        check(withPort is { Debug: true, Port: 4455 }, "debug flag: --debug together with --port");
        CliCommand? tail = CliArgs.Parse(["--reason", "x", "--", "prog", "--debug"], out _);
        check(tail is CliCommand.Run { Debug: false } run && run.Args.Arguments.SequenceEqual(["--debug"]), "debug flag: a --debug after -- belongs to the program and does not switch debug on");
        check(CliArgs.Parse(["--debug"], out _) is null, "debug flag: --debug alone is not a command");
        check(CliArgs.Parse(["--help"], out _) is CliCommand.Help { Text: var help } && help.Contains("--debug", StringComparison.Ordinal) && help.Contains("WITH_SECRETS_DEBUG", StringComparison.Ordinal), "debug flag: --help describes --debug and the environment variable");

        string? saved = Environment.GetEnvironmentVariable(AppLog.DebugVariable);
        try
        {
            Environment.SetEnvironmentVariable(AppLog.DebugVariable, null);
            check(!AppLog.DebugRequested(false) && AppLog.DebugRequested(true), "debug flag: without the variable, only the flag switches debug on");
            Environment.SetEnvironmentVariable(AppLog.DebugVariable, "1");
            check(AppLog.DebugRequested(false), "debug flag: WITH_SECRETS_DEBUG=1 switches debug on");
            Environment.SetEnvironmentVariable(AppLog.DebugVariable, "0");
            check(!AppLog.DebugRequested(false), "debug flag: WITH_SECRETS_DEBUG=0 does not");
        }
        finally
        {
            Environment.SetEnvironmentVariable(AppLog.DebugVariable, saved);
        }
    }

    private static void Folders(Action<bool, string> check, string root)
    {
        check(AppLog.DefaultFileSizeLimit == 1024 * 1024 && AppLog.RetainedFiles == 7, "log file: the cap is 1 MB per file and 7 files are kept");
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        check(AppLog.DefaultFolder == Path.Combine(home, ".with-secrets", "logs"), "log file: the default folder is ~/.with-secrets/logs (" + AppLog.DefaultFolder + ")");
        check(root.Length > 0 && !root.StartsWith(Path.Combine(home, ".with-secrets"), StringComparison.OrdinalIgnoreCase), "log file: these tests use a temp folder, not the real one");
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Normal mode and --debug on the terminal
    // ---------------------------------------------------------------------------------------------------------------

    /// <summary>A server with a request or two, and a handler that fails, as a person's program would see them.</summary>
    private static async Task Traffic(string marker, string[] seenToken)
    {
        using HttpClient client = RecoveryTests.NewClient();
        using OneShotServer server = new("a", 0, (verb, suffix, body) => suffix == "save" ? throw new InvalidOperationException(Boom) : new OneShotResponse(200, "application/json", "{\"ok\":true}"));
        seenToken[0] = server.Token;
        string url = $"http://127.0.0.1:{server.Port}/a/{server.Token}";
        await client.GetAsync(url);
        using (HttpRequestMessage message = new(HttpMethod.Post, url + "/proof") { Content = new StringContent("{\"x\":\"" + marker + "\"}", Encoding.UTF8, "application/json") })
        {
            using HttpResponseMessage reply = await client.SendAsync(message);
        }

        using (HttpRequestMessage message = new(HttpMethod.Post, url + "/save") { Content = new StringContent("{}", Encoding.UTF8, "application/json") })
        {
            using HttpResponseMessage reply = await client.SendAsync(message);
        }
    }

    private static async Task NormalMode(Action<bool, string> check, string root)
    {
        string folder = Path.Combine(root, "normal");
        string[] token = [""];
        const string Marker = "NORMAL_BODY_5521";
        using Setup setup = new(folder, debug: false);
        TerminalPrompt.Line("with-secrets: a result line");
        await Traffic(Marker, token);
        string screen = setup.Screen;
        string[] debugEvents = setup.Events.Lines(LogEventLevel.Debug);
        check(debugEvents.Any(line => line.StartsWith("with-secrets: connection opened (", StringComparison.Ordinal)) && debugEvents.Any(line => line.StartsWith("with-secrets: proof received (", StringComparison.Ordinal)), "normal mode: the diagnostics are still logged as Debug events");
        check(!screen.Split('\n').Any(line => Diagnostic.IsMatch(line)), "normal mode: no connection or request diagnostic line on the terminal (" + screen.Replace("\n", "|") + ")");
        check(screen == "with-secrets: a result line\n", "normal mode: the terminal shows only the program's own lines (" + screen.Replace("\n", "|") + ")");
        string files = setup.Files();
        check(files.Length > 0 && !files.Contains("connection opened", StringComparison.Ordinal) && !files.Contains("proof received", StringComparison.Ordinal), "normal mode: the Debug events are not in the file");
        check(files.Contains("[WRN]", StringComparison.Ordinal) && files.Contains("InvalidOperationException", StringComparison.Ordinal), "normal mode: a warning (a failed handler) is written to the file without --debug");
        check(!files.Contains(Boom, StringComparison.Ordinal) && !files.Contains(token[0], StringComparison.Ordinal) && !files.Contains(Marker, StringComparison.Ordinal), "normal mode: the file has no exception text, token or body");
    }

    private static async Task DebugMode(Action<bool, string> check, string root)
    {
        string folder = Path.Combine(root, "debug");
        string[] token = [""];
        const string Marker = "DEBUG_BODY_7703";
        using Setup setup = new(folder, debug: true);
        TerminalPrompt.Line("with-secrets: a result line");
        await Traffic(Marker, token);
        string screen = setup.Screen;
        string[] lines = screen.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        check(lines[0] == "with-secrets: a result line" && lines.Skip(1).All(line => Diagnostic.IsMatch(line) || line.StartsWith("with-secrets: request POST /save", StringComparison.Ordinal)), "debug: the terminal shows the program's lines and the diagnostic lines (" + screen.Replace("\n", "|") + ")");
        check(lines.Contains("with-secrets: request GET /page (headers read, 0 s)") && lines.Any(line => line.StartsWith("with-secrets: proof received (", StringComparison.Ordinal)) && lines.Any(line => line.StartsWith("with-secrets: connection opened (", StringComparison.Ordinal)), "debug: the connection, request and proof lines appear on the terminal with the same text as before");
        string files = setup.Files();
        check(files.Contains("[DBG] connection opened (", StringComparison.Ordinal) && files.Contains("[DBG] request GET /page (headers read, 0 s)", StringComparison.Ordinal) && files.Contains("[DBG] proof received (", StringComparison.Ordinal), "debug: the same events are in the log file");
        check(files.Contains("[WRN] ", StringComparison.Ordinal), "debug: warnings are in the file too");
        check(!files.Contains(token[0], StringComparison.Ordinal) && !screen.Contains(token[0], StringComparison.Ordinal) && !files.Contains(Marker, StringComparison.Ordinal) && !screen.Contains(Marker, StringComparison.Ordinal) && !files.Contains(Boom, StringComparison.Ordinal) && !screen.Contains(Boom, StringComparison.Ordinal), "debug: no token, body or exception text in the file or on the terminal");
        check(LogFiles(folder).Length == 1 && Regex.IsMatch(Path.GetFileName(LogFiles(folder)[0]), "^with-secrets-\\d{8}\\.log$"), "debug: the file is with-secrets-YYYYMMDD.log in the logs folder (" + string.Join(",", LogFiles(folder).Select(Path.GetFileName)) + ")");
    }

    private static bool WaitFor(Func<bool> done)
    {
        DateTime stop = DateTime.UtcNow.AddSeconds(15);
        while (DateTime.UtcNow < stop)
        {
            if (done())
            {
                return true;
            }

            Thread.Sleep(50);
        }

        return false;
    }

    private static async Task PromptGate(Action<bool, string> check, string root)
    {
        string folder = Path.Combine(root, "gate");
        using Setup setup = new(folder, debug: true);
        BlockingCollection<string?> typed = [];
        TerminalPrompt.Input = () => typed.Take();
        Task<string?> reading = Task.Run(() => TerminalPrompt.ReadCode(false));
        WaitFor(() => setup.Screen.EndsWith(TerminalPrompt.Waiting, StringComparison.Ordinal));

        check(setup.Screen == TerminalPrompt.Waiting, "debug prompt: the prompt is the last text when the wait starts");
        using (HttpClient client = RecoveryTests.NewClient())
        using (OneShotServer server = new("a", 0, (verb, suffix, body) => new OneShotResponse(200, "application/json", "{\"ok\":true}")))
        {
            await client.GetAsync($"http://127.0.0.1:{server.Port}/a/{server.Token}");
            using HttpRequestMessage message = new(HttpMethod.Post, $"http://127.0.0.1:{server.Port}/a/{server.Token}/proof") { Content = new StringContent("{}", Encoding.UTF8, "application/json") };
            using HttpResponseMessage reply = await client.SendAsync(message);
        }

        string during = setup.Screen;
        check(during.StartsWith(TerminalPrompt.Waiting + "\nwith-secrets: connection opened (", StringComparison.Ordinal) && during.Contains("request GET /page", StringComparison.Ordinal), "debug prompt: --debug lines print at once while the prompt waits (" + during.Replace("\n", "|") + ")");
        typed.Add("123456");
        reading.Wait(TimeSpan.FromSeconds(10));

        check(setup.Screen.Replace("\n", "") == during.Replace("\n", ""), "debug prompt: nothing is held and replayed after Enter");
        string files = setup.Files();
        check(files.Contains("connection opened (", StringComparison.Ordinal) && files.Contains("proof received (", StringComparison.Ordinal), "debug prompt: the file gets the same lines");
    }

    // ---------------------------------------------------------------------------------------------------------------
    // The file
    // ---------------------------------------------------------------------------------------------------------------

    private static void FileRules(Action<bool, string> check, string root)
    {
        // Rolling by size, keeping 7 files.
        string folder = Path.Combine(root, "rolling");
        using (Setup setup = new(folder, debug: false))
        {
            AppLog.FileSizeLimit = 3000;
            AppLog.Configure(false);
            for (int index = 0; index < 400; index++)
            {
                AppLog.Warn("filler line {Index} of a size test", index);
            }

            AppLog.Close();
            string[] files = LogFiles(folder);
            check(files.Length == 7, "log file: rolling by size keeps 7 files (" + files.Length + ")");
            check(files.Length > 0 && files.All(file => new FileInfo(file).Length <= 3000 + 200), "log file: no file is much over the size cap (" + string.Join(",", files.Select(file => new FileInfo(file).Length)) + ")");
            check(LogText(folder).Contains("filler line 399 of a size test", StringComparison.Ordinal) && !LogText(folder).Contains("filler line 0 of", StringComparison.Ordinal), "log file: the newest lines are kept and the oldest rolled away");
        }

        // A folder that cannot be created never fails a command.
        string blocker = Path.Combine(root, "not-a-folder");
        File.WriteAllText(blocker, "a file");
        using (Setup setup = new(Path.Combine(blocker, "logs"), debug: true))
        {
            bool threw = false;
            try
            {
                AppLog.Warn("a warning with no file to go to");
                AppLog.Debug("a debug line with no file to go to");
                using OneShotServer server = new("a", 0, (verb, suffix, body) => new OneShotResponse(200, "text/plain", "ok"));
                using HttpClient client = RecoveryTests.NewClient();
                client.GetAsync($"http://127.0.0.1:{server.Port}/a/{server.Token}").GetAwaiter().GetResult().Dispose();
            }
            catch (Exception)
            {
                threw = true;
            }

            check(!threw, "log file: an unwritable log folder does not fail a command");
            check(setup.Screen.Contains("with-secrets: a debug line with no file to go to", StringComparison.Ordinal), "log file: without a file the terminal still gets the debug lines");
            check(setup.Events.Lines().Any(line => line.Contains("a warning with no file", StringComparison.Ordinal)), "log file: without a file the events are still made");
        }

        // A folder given as a path that is itself an existing file, and a read-only target: the same.
        using (Setup setup = new(blocker, debug: false))
        {
            AppLog.Warn("a warning into a folder that is a file");
            check(true, "log file: a log folder that is a file does not throw");
        }

        // Before anything is configured, nothing is written anywhere.
        AppLog.Close();
        AppLog.LogFolder = Path.Combine(root, "never");
        AppLog.Warn("unconfigured warning");
        AppLog.Debug("unconfigured debug");
        check(!Directory.Exists(Path.Combine(root, "never")), "log file: an unconfigured logger writes no file");
        AppLog.LogFolder = null;
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Faults, audit, state
    // ---------------------------------------------------------------------------------------------------------------

    private static async Task Faults(Action<bool, string> check, string root)
    {
        string folder = Path.Combine(root, "faults");
        using Setup setup = new(folder, debug: false);
        OneShotResponse failed = new(500, "text/plain", "failed");
        OneShotResponse gone = new(404, "text/plain", "gone");
        OneShotResponse result = HandleGuard.Run("POST", "proof", () => throw new InvalidOperationException(Boom), () => true, failed, gone);
        check(result == failed, "guard log: a fault still ends the session with the failed answer");
        string[] warnings = setup.Events.Lines(LogEventLevel.Warning);
        check(warnings.Length == 1 && warnings[0].Contains("InvalidOperationException", StringComparison.Ordinal), "guard log: a handler fault is one warning that names the exception type (" + string.Join(" | ", warnings) + ")");
        check(warnings.All(line => !line.Contains(Boom, StringComparison.Ordinal)) && setup.Events.Everything().All(text => !text.Contains(Boom, StringComparison.Ordinal)), "guard log: the exception text is in no message and no property");
        check(setup.Events.Events.Where(item => item.Level == LogEventLevel.Warning).All(item => item.Exception is null), "guard log: no exception object is attached to the event");
        string files = setup.Files();
        check(files.Contains("[WRN]", StringComparison.Ordinal) && files.Contains("InvalidOperationException", StringComparison.Ordinal) && !files.Contains(Boom, StringComparison.Ordinal), "guard log: the warning is in the file without --debug, with the type name only");

        // The guard of a real session: HandleFaultTests drives all the commands; here one request through a server.
        using Setup second = new(Path.Combine(root, "faults2"), debug: false);
        HandleGuard.Fault = (_, _) => throw new InvalidOperationException(Boom);
        try
        {
            using OneShotServer server = new("a", 0, (verb, suffix, body) => HandleGuard.Run(verb, suffix, () => new OneShotResponse(200, "text/plain", "fine"), () => true, failed, gone));
            using HttpClient client = RecoveryTests.NewClient();
            using HttpResponseMessage reply = await client.GetAsync($"http://127.0.0.1:{server.Port}/a/{server.Token}");
            check((int)reply.StatusCode == 500 && second.Events.Lines(LogEventLevel.Warning).Any(line => line.Contains("InvalidOperationException", StringComparison.Ordinal)), "guard log: a fault in a served request answers 500 and is warned about");
        }
        finally
        {
            HandleGuard.Fault = null;
        }

        // Audit write failure and a state that fails its check are warnings too (names only).
        using Setup third = new(Path.Combine(root, "faults3"), debug: false);
        string blocked = Path.Combine(root, "audit-blocked");
        File.WriteAllText(blocked, "a file, not a directory");
        StateDatabase blockedState = new(Path.Combine(blocked, "audit.db"));
        bool written = blockedState.Audit.TryRecord(AdminEvent.Change("key-enrolled", "d", ""));
        check(!written && third.Events.Lines(LogEventLevel.Warning).Any(line => line.Contains("audit", StringComparison.OrdinalIgnoreCase)), "audit log: a failed write is a warning");
        string damaged = Path.Combine(root, "damaged");
        Directory.CreateDirectory(damaged);
        File.WriteAllText(Path.Combine(damaged, "state.db"), "this is not a database");
        StateDatabase state = StateDatabase.InFolder(damaged);
        StringWriter stderr = new();
        int? code = state.Gate(stderr);
        check(code == RunCommand.StoreError && third.Events.Lines(LogEventLevel.Warning).Any(line => line.Contains("state", StringComparison.OrdinalIgnoreCase)), "state log: a state that fails its check is a warning");
        check(third.Events.Everything().All(text => !text.Contains("this is not a database", StringComparison.Ordinal) && !text.Contains(damaged, StringComparison.Ordinal) && !text.Contains(blocked, StringComparison.Ordinal)), "state log: no path or file text in the warnings");
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Normal mode: the code prompt is the last thing on the terminal when the code is asked for, and no diagnostic appeared
    // ---------------------------------------------------------------------------------------------------------------

    private static async Task PromptLastNormal(Action<bool, string> check, string root)
    {
        using HttpClient client = RecoveryTests.NewClient();
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.RS256();
        using TestAuthenticator fresh = TestAuthenticator.ES256();
        string settingsText = ToolSettings.Defaults.Canonical();
        foreach (string name in new[] { "first setup", "--enroll", "--recover new-store step" })
        {
            using Setup setup = new(Path.Combine(root, "last-" + name.GetHashCode(StringComparison.Ordinal).ToString(System.Globalization.CultureInfo.InvariantCulture)), debug: false);
            BlockingCollection<string?> typed = [];
            TerminalPrompt.Input = () => typed.Take();
            int asked = 0;
            Func<string?> readCode = () => TerminalPrompt.ReadCode(asked++ > 0);
            Action<Action<string>, string> noop = (_, _) => { };
            RecoveryTests.Flow flow;
            RecoveryTests.World? w = name == "first setup" ? null : RecoveryTests.NewWorld(root, laptop);
            StateDatabase firstDb = StateDatabase.InFolder(Path.Combine(root, "last-first-" + Guid.NewGuid().ToString("N")));
            Func<Action<string>, ConfigChange> command = name switch
            {
                "first setup" => announce =>
                {
                    (EnrollmentTarget primary, EnrollmentTarget local) = RecoveryTests.Targets(firstDb, announce, readCode);

                    return new FirstRunPage(firstDb, primary, local, announce, readCode).Run();
                },
                "--enroll" => announce =>
                {
                    (EnrollmentTarget target, _) = RecoveryTests.Targets(w!.Db, announce, readCode);
                    ApprovalDecision decision = new Enrollment(target, target, announce, w.Db.Audit).Enroll();

                    return new ConfigChange(decision.Approved ? 0 : 1, decision.Detail);
                },
                _ => announce =>
                {
                    (EnrollmentTarget primary, EnrollmentTarget local) = RecoveryTests.Targets(w!.Db, announce, readCode);

                    return new StoreRecovery(w.Db, primary, local, announce, readCode) { Clock = () => RecoveryTests.Stamp }.Run();
                },
            };
            flow = new RecoveryTests.Flow((announce, _) => command(line =>
            {
                announce(line);
                TerminalPrompt.Line(line);
            }));

            (string Url, string Origin)? one = flow.Next();
            (string Url, string Origin) last;
            string? confirm;
            if (name == "first setup")
            {
                (_, _, string sign) = one is null ? ("", "", "") : RecoveryTests.RegisterFirst(client, one.Value, laptop, settingsText);
                confirm = RecoveryTests.Member(sign, "code");
                last = one ?? ("", "");
            }
            else if (name == "--enroll")
            {
                (_, string body1) = one is null ? (0, "") : TestState.Approve(client, one.Value.Url, one.Value.Origin, "localhost", laptop);
                (string Url, string Origin)? two = RecoveryTests.NextLink(body1);
                (_, string reply) = two is null ? ("", "") : OneFlowTests.Create(client, two.Value, phone, "localhost", "phone", false);
                string signed = two is null ? "" : TestState.SignStep(client, two.Value.Url, two.Value.Origin, reply, laptop);
                confirm = RecoveryTests.Member(signed, "code");
                last = two ?? ("", "");
            }
            else
            {
                (_, string codeBody) = one is null ? (0, "") : RecoveryTests.SendCode(client, one.Value, w!.Code);
                (string Url, string Origin)? two = RecoveryTests.NextLink(codeBody);
                (_, _, string sign) = two is null ? ("", "", "") : RecoveryTests.RegisterFirst(client, two.Value, fresh, settingsText);
                confirm = RecoveryTests.Member(sign, "code");
                last = two ?? ("", "");
            }

            bool shown = WaitFor(() => setup.Screen.EndsWith(TerminalPrompt.Waiting, StringComparison.Ordinal));

            // Network traffic while the prompt waits: in normal mode it writes nothing.
            if (last.Url.Length > 0)
            {
                TestState.Get(client, last.Url);
                TestState.Post(client, last.Url + "/sign", "{}");
            }

            Thread.Sleep(300);
            string waiting = setup.Screen;
            check(shown && waiting.EndsWith(TerminalPrompt.Waiting, StringComparison.Ordinal) && waiting.Split(TerminalPrompt.Waiting).Length == 2, $"prompt last (normal mode): {name}: the terminal ends with the prompt when the code is asked for, and nothing is printed after it (" + waiting[Math.Max(0, waiting.Length - 120)..].Replace("\n", "|") + ")");
            typed.Add(confirm);
            ConfigChange result = flow.Result();
            SqliteConnection.ClearAllPools();
            string[] lines = setup.Screen.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            check(result.Code == 0, $"prompt last (normal mode): {name}: the flow finished after the code (" + result.Detail + ")");
            check(!lines.Any(line => Diagnostic.IsMatch(line)), $"prompt last (normal mode): {name}: no diagnostic line on the terminal in the whole flow (" + string.Join("|", lines.Where(line => Diagnostic.IsMatch(line))) + ")");
            check(confirm is not null && !setup.Screen.Contains(confirm, StringComparison.Ordinal), $"prompt last (normal mode): {name}: the code is not printed");
            _ = noop;
        }

        await Task.CompletedTask;
    }

    // ---------------------------------------------------------------------------------------------------------------
    // The terminal is the same with and without --debug (apart from the diagnostic lines)
    // ---------------------------------------------------------------------------------------------------------------

    private static RecoveryTests.Flow Rotation(RecoveryTests.World w)
    {
        return new RecoveryTests.Flow((announce, read) =>
        {
            Action<string> both = line =>
            {
                announce(line);
                TerminalPrompt.Line(line);
            };
            (EnrollmentTarget primary, EnrollmentTarget local) = RecoveryTests.Targets(w.Db, both, read);
            ConfigChange change = new KeyRotation(w.Db, w.Store, primary, local, both).Run();
            TerminalPrompt.Final(change.Done ? change.Detail : "with-secrets: " + change.Detail);

            return change;
        });
    }

    private static string Normalised(string screen) => LinkText.Replace(screen, "<link>");

    private static async Task Flows(Action<bool, string> check, string root)
    {
        using HttpClient client = RecoveryTests.NewClient();
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.RS256();
        string[] screens = new string[2];
        int[] codes = new int[2];
        for (int mode = 0; mode < 2; mode++)
        {
            using Setup setup = new(Path.Combine(root, "same-" + mode), debug: mode == 1);
            RecoveryTests.World w = RecoveryTests.NewWorld(root, laptop, phone);
            RecoveryTests.Flow flow = Rotation(w);
            (string Url, string Origin)? one = flow.Next();
            (_, string body1) = one is null ? (0, "") : TestState.Approve(client, one.Value.Url, one.Value.Origin, "localhost", laptop);
            (string Url, string Origin)? two = RecoveryTests.NextLink(body1);
            if (two is not null)
            {
                TestState.Approve(client, two.Value.Url, two.Value.Origin, "localhost", laptop);
            }

            ConfigChange result = flow.Result();
            SqliteConnection.ClearAllPools();
            codes[mode] = result.Code;
            screens[mode] = setup.Screen;
        }

        string[] normalLines = screens[0].Split('\n', StringSplitOptions.RemoveEmptyEntries);
        string[] debugLines = screens[1].Split('\n', StringSplitOptions.RemoveEmptyEntries);
        check(codes[0] == 0 && codes[1] == 0, "same terminal: --rotate-key finishes with exit 0 with and without --debug (" + codes[0] + ", " + codes[1] + ")");
        check(!normalLines.Any(line => Diagnostic.IsMatch(line)), "same terminal: a rotate in normal mode has no diagnostic line (" + string.Join("|", normalLines.Where(line => Diagnostic.IsMatch(line))) + ")");
        check(debugLines.Any(line => Diagnostic.IsMatch(line)), "same terminal: the same rotate with --debug shows diagnostic lines");
        check(Normalised(string.Join("\n", normalLines)) == Normalised(string.Join("\n", debugLines.Where(line => !Diagnostic.IsMatch(line)))), "same terminal: apart from the diagnostic lines the terminal is the same with --debug (results, links, notes)");
        check(normalLines.Count(line => line.Contains("http://", StringComparison.Ordinal)) == 1, "same terminal: one link, as before");
        await Task.CompletedTask;
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Leak scan: whole flows with --debug, then the file and the terminal are searched for what must never be there
    // ---------------------------------------------------------------------------------------------------------------

    private const string CanaryValue = "Canary-Secret-Value-Q7Z-3319";
    private const string CanaryRunValue = "Canary-Run-Value-K2M-8841";

    private static string Token(string url) => new Uri(url).AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries)[^1];

    private static IEnumerable<string> TokensIn(IEnumerable<string> lines) => lines.SelectMany(line => LinkText.Matches(line).Select(match => Token(match.Value)));

    /// <summary>The ways a leak could be written: the text, its hex, its base64 and base64url (of the UTF-8 bytes).</summary>
    private static IEnumerable<string> Forms(string text)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text);
        yield return text;
        yield return Convert.ToHexStringLower(bytes);
        yield return Convert.ToHexString(bytes);
        yield return Convert.ToBase64String(bytes);
        yield return Convert.ToBase64String(bytes).TrimEnd('=');
        yield return Base64Url.EncodeToString(bytes);
    }

    private static async Task Leaks(Action<bool, string> check, string root)
    {
        string folder = Path.Combine(root, "leaks");
        List<string> secrets = [CanaryValue, CanaryRunValue];
        List<string> numbers = [];
        List<string> tokens = [];
        using HttpClient client = RecoveryTests.NewClient();
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.RS256();
        using TestAuthenticator fresh = TestAuthenticator.ES256();
        string settingsText = ToolSettings.Defaults.Canonical();
        string[] events;
        string screen;
        string files;
        int flowsRun = 0;
        using (Setup setup = new(folder, debug: true))
        {
            // --config: the first run makes the recovery code and the confirmation code.
            {
                StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "leak-config"));
                RecoveryTests.Flow flow = new((announce, read) =>
                {
                    (EnrollmentTarget primary, EnrollmentTarget local) = RecoveryTests.Targets(db, announce, read);

                    return new FirstRunPage(db, primary, local, announce, read).Run();
                });
                (string Url, string Origin)? link = flow.Next();
                (_, _, string sign) = link is null ? ("", "", "") : RecoveryTests.RegisterFirst(client, link.Value, laptop, settingsText);
                string? recovery = RecoveryTests.Member(sign, "recovery");
                string? confirm = RecoveryTests.Member(sign, "code");
                flow.Type(confirm);
                flow.Result();
                SqliteConnection.ClearAllPools();
                secrets.AddRange(recovery is null ? [] : RecoveryTests.CodeForms(recovery));
                numbers.AddRange(confirm is null ? [] : [confirm]);
                tokens.AddRange(TokensIn(flow.Lines));
                check(recovery is not null && confirm is not null, "leak scan: the first-setup flow ran and made a recovery code and a confirmation code");
                flowsRun++;
            }

            // --recover and --rotate-key and --enroll on worlds with a known recovery code and three stored values.
            {
                RecoveryTests.World w = RecoveryTests.NewWorld(root, laptop, phone);
                secrets.AddRange(RecoveryTests.CodeForms(w.Code));
                secrets.AddRange(RecoveryTests.Values.Values);
                RecoveryTests.Flow flow = RecoveryTests.StartRecover(w.Db);
                (string Url, string Origin)? one = flow.Next();
                (int status, string codeBody) = one is null ? (0, "") : RecoveryTests.SendCode(client, one.Value, w.Code);
                (string Url, string Origin)? two = RecoveryTests.NextLink(codeBody);
                (_, _, string sign) = two is null ? ("", "", "") : RecoveryTests.RegisterFirst(client, two.Value, fresh, settingsText);
                string? newCode = RecoveryTests.Member(sign, "recovery");
                string? confirm = RecoveryTests.Member(sign, "code");
                flow.Type(confirm);
                ConfigChange result = flow.Result();
                SqliteConnection.ClearAllPools();
                secrets.AddRange(newCode is null ? [] : RecoveryTests.CodeForms(newCode));
                numbers.AddRange(confirm is null ? [] : [confirm]);
                tokens.AddRange(TokensIn(flow.Lines));
                tokens.AddRange(new[] { one?.Url, two?.Url }.OfType<string>().Select(Token));
                check(status == 200 && result.Code == 0, "leak scan: the --recover flow ran (" + status + ", " + result.Detail + ")");
                flowsRun++;
            }

            {
                RecoveryTests.World w = RecoveryTests.NewWorld(root, laptop, phone);
                secrets.AddRange(RecoveryTests.CodeForms(w.Code));
                RecoveryTests.Flow flow = RecoveryTests.StartRotate(w);
                (string Url, string Origin)? one = flow.Next();
                (_, string body1) = one is null ? (0, "") : TestState.Approve(client, one.Value.Url, one.Value.Origin, "localhost", laptop);
                (string Url, string Origin)? two = RecoveryTests.NextLink(body1);
                (_, string body2) = two is null ? (0, "") : TestState.Approve(client, two.Value.Url, two.Value.Origin, "localhost", laptop);
                ConfigChange result = flow.Result();
                SqliteConnection.ClearAllPools();
                string? newCode = RecoveryTests.Member(body2, "recovery");
                secrets.AddRange(newCode is null ? [] : RecoveryTests.CodeForms(newCode));
                tokens.AddRange(TokensIn(flow.Lines));
                tokens.AddRange(new[] { one?.Url, two?.Url }.OfType<string>().Select(Token));
                check(result.Code == 0 && newCode is not null, "leak scan: the --rotate-key flow ran and made a new recovery code (" + result.Detail + ")");
                flowsRun++;
            }

            {
                RecoveryTests.World w = RecoveryTests.NewWorld(root, laptop);
                secrets.AddRange(RecoveryTests.CodeForms(w.Code));
                RecoveryTests.Flow flow = new((announce, read) =>
                {
                    (EnrollmentTarget target, _) = RecoveryTests.Targets(w.Db, announce, read);
                    ApprovalDecision decision = new Enrollment(target, target, announce, w.Db.Audit).Enroll();

                    return new ConfigChange(decision.Approved ? 0 : 1, decision.Detail);
                });
                (string Url, string Origin)? one = flow.Next();
                (_, string body1) = one is null ? (0, "") : TestState.Approve(client, one.Value.Url, one.Value.Origin, "localhost", laptop);
                (string Url, string Origin)? two = RecoveryTests.NextLink(body1);
                (_, string reply) = two is null ? ("", "") : OneFlowTests.Create(client, two.Value, phone, "localhost", "phone", false);
                string signed = two is null ? "" : TestState.SignStep(client, two.Value.Url, two.Value.Origin, reply, laptop);
                string? confirm = RecoveryTests.Member(signed, "code");
                flow.Type(confirm);
                ConfigChange result = flow.Result();
                SqliteConnection.ClearAllPools();
                numbers.AddRange(confirm is null ? [] : [confirm]);
                tokens.AddRange(TokensIn(flow.Lines));
                tokens.AddRange(new[] { one?.Url, two?.Url }.OfType<string>().Select(Token));
                check(result.Code == 0 && confirm is not null, "leak scan: the --enroll flow ran and made a confirmation code (" + result.Detail + ")");
                flowsRun++;
            }

            // --set: the value is typed on the page and sealed to the program.
            {
                StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "leak-set"));
                PasskeyStore passkeys = new(db);
                TestState.Add(db, laptop.Record("localhost", "laptop"), withStore: true);
                SecretStore store = new(db);
                ApprovalSettings local = new(null, 0, TimeSpan.FromSeconds(20));
                WebApprovalTests.EntryRun run = WebApprovalTests.SetRun(passkeys, store, ["CANARY_NAME"], laptop, JsonSerializer.Serialize(new Dictionary<string, string> { ["CANARY_NAME"] = CanaryValue }));
                SqliteConnection.ClearAllPools();
                check(run.Result is { Code: 0 }, "leak scan: the --set flow stored a value (" + run.Result?.Detail + ")");
                flowsRun++;
            }

            // A run: a program gets a secret; its output is redacted, and the approval is a web session too (the proof posts).
            {
                string audit = Path.Combine(root, "leak-run-audit.db");
                RunArgs args = CliArgs.ParseRun(["--secrets", "CANARY_RUN", "--reason", "leak scan", "--", "dotnet", "--version"], out _)!;
                int code = await new RunCommand(new MemoryStore(new Dictionary<string, string> { ["CANARY_RUN"] = CanaryRunValue }), new FakeApprover(true), new StringWriter(), new StringWriter()).ExecuteAsync(args, root);
                check(code == 0, "leak scan: the run with a secret ran (" + code + ")");
                flowsRun++;
            }

            // A server request that carries the canary in its body and in its path, as a program under attack would send it.
            {
                using OneShotServer server = new("a", 0, (verb, suffix, body) => new OneShotResponse(200, "application/json", "{\"ok\":true}"));
                tokens.Add(server.Token);
                using HttpRequestMessage message = new(HttpMethod.Post, $"http://127.0.0.1:{server.Port}/a/{server.Token}/proof") { Content = new StringContent("{\"x\":\"" + CanaryValue + "\"}", Encoding.UTF8, "application/json") };
                using HttpResponseMessage reply = await client.SendAsync(message);
                using HttpResponseMessage other = await client.GetAsync($"http://127.0.0.1:{server.Port}/a/{server.Token}/{CanaryRunValue}");
                flowsRun++;
            }

            events = setup.Events.Everything();
            screen = setup.Screen;
            files = setup.Files();
        }

        byte[] haystack = [.. LogFiles(folder).SelectMany(ReadShared), .. Encoding.UTF8.GetBytes(screen), .. Encoding.UTF8.GetBytes(string.Join("\n", events))];
        string asText = Encoding.Latin1.GetString(haystack);
        check(flowsRun == 7 && files.Contains("connection opened (", StringComparison.Ordinal) && files.Contains("proof received (", StringComparison.Ordinal) && files.Length > 500, "leak scan: the log file really holds the debug events of the flows (" + files.Length + " characters)");

        string[] never = [.. secrets.Distinct().Where(item => item.Length > 0).SelectMany(item => item.Length >= 8 ? Forms(item) : [item]).Distinct()];
        string? found = never.FirstOrDefault(form => form.Length >= 6 && asText.Contains(form, StringComparison.Ordinal));
        check(found is null, "leak scan: no canary value, recovery code or key text in the log file, the terminal or the events, in plain, hex or base64 (" + (found is null ? "" : found[..Math.Min(found.Length, 6)] + "...") + ")");
        string? number = numbers.Distinct().FirstOrDefault(code => Regex.IsMatch(asText, "(?<!\\d)" + Regex.Escape(code) + "(?!\\d)") || Forms(code).Skip(1).Any(form => asText.Contains(form, StringComparison.Ordinal)));
        check(number is null && numbers.Count >= 3, "leak scan: no confirmation code in the log file, the terminal or the events (" + numbers.Count + " codes checked)");
        string[] tokenForms = [.. tokens.Distinct().Where(item => item.Length >= 16).SelectMany(Forms).Distinct()];
        string? token = tokenForms.FirstOrDefault(form => asText.Contains(form, StringComparison.Ordinal));
        check(token is null && tokens.Distinct().Count() >= 8, "leak scan: no token or token path in the log file, the terminal or the events (" + tokens.Distinct().Count() + " tokens checked)");
        check(!files.Contains("/a/", StringComparison.Ordinal) && !files.Contains("/c/", StringComparison.Ordinal) && !files.Contains("/e/", StringComparison.Ordinal) && !files.Contains("127.0.0.1", StringComparison.Ordinal), "leak scan: no request path or address in the log file");
        Regex tokenShape = new("(?=[A-Za-z0-9_-]*\\d)[A-Za-z0-9_-]{22,}", RegexOptions.CultureInvariant);
        string? shaped = files.Split('\n').FirstOrDefault(line => tokenShape.IsMatch(line));
        check(shaped is null, "leak scan: no line of the log file holds a token-shaped run (" + shaped + ")");
        string[] logLines = [.. files.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line => line.TrimEnd('\r'))];
        string? oddLine = logLines.FirstOrDefault(line => !LogLine.IsMatch(line));
        check(oddLine is null, "leak scan: every log line is a timestamp, a level and route words, sizes and seconds only (" + oddLine + ")");
    }
}

using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>Settings in state.db, --config (passkey-gated and first-run) and --config --show.</summary>
internal static class ConfigTests
{
    public const string ConfigPrefix = "To change the settings, open this link: ";


    public static async Task Run(Action<bool, string> check)
    {
        string folder = Path.Combine(Path.GetTempPath(), "ws-config-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            Validation(check);
            RoundTrip(check, folder);
            Schema(check, folder);
            Cli(check);
            Show(check, folder);
            await Gated(check, folder);
            await FirstRun(check, folder);
            await PortOption(check, folder);
        }
        finally
        {
            Directory.Delete(folder, true);
        }
    }

    private static string Canonical(int reuse, string method, string? baseUrl, int port, int timeout, int reuseMax = 480)
    {
        return "{\"reuseMinutes\":" + reuse + ",\"reuseMaxMinutes\":" + reuseMax + ",\"method\":" + JsonSerializer.Serialize(method) + ",\"baseUrl\":" + (baseUrl is null ? "null" : "\"" + baseUrl + "\"")
            + ",\"port\":" + port + ",\"timeoutMinutes\":" + timeout + "}";
    }

    private static void Validation(Action<bool, string> check)
    {
        ToolSettings defaults = ToolSettings.Defaults;
        check(defaults == new ToolSettings(10, 480, "passkey", null, 0, 5), "settings: the defaults");
        check(defaults.Canonical() == "{\"reuseMinutes\":10,\"reuseMaxMinutes\":480,\"method\":\"passkey\",\"baseUrl\":null,\"port\":0,\"timeoutMinutes\":5}", "settings: canonical JSON has a fixed key order (" + defaults.Canonical() + ")");
        check(new ToolSettings(0, 480, "passkey", "https://ws.example.com/a\"b\\c", 8765, 30).Canonical()
            == "{\"reuseMinutes\":0,\"reuseMaxMinutes\":480,\"method\":\"passkey\",\"baseUrl\":\"https://ws.example.com/a\\\"b\\\\c\",\"port\":8765,\"timeoutMinutes\":30}", "settings: canonical JSON escapes quote and backslash");
        check(new ToolSettings(10, 480, "passkey", "https://bücher.example/é", 0, 5).Canonical().Contains("b\\u00fccher.example/\\u00e9", StringComparison.Ordinal), "settings: canonical JSON writes non-ASCII as lower-case \\u escapes");
        check(defaults.Approval == new ApprovalSettings("passkey", null, 0, TimeSpan.FromMinutes(5)) && defaults.Reuse == new ReuseOffer(480, 10), "settings: the approval and reuse views");

        (ToolSettings Value, bool Good, string Key)[] cases =
        [
            (defaults with { TimeoutMinutes = 0 }, false, "timeoutMinutes"),
            (defaults with { TimeoutMinutes = 1 }, true, ""),
            (defaults with { TimeoutMinutes = 30 }, true, ""),
            (defaults with { TimeoutMinutes = 31 }, false, "timeoutMinutes"),
            (defaults with { ReuseMinutes = -1 }, false, "reuseMinutes"),
            (defaults with { ReuseMinutes = 0 }, true, ""),
            (defaults with { ReuseMinutes = 480 }, true, ""),
            (defaults with { ReuseMinutes = 481 }, false, "reuseMinutes"),
            (defaults with { ReuseMinutes = 100, ReuseMaxMinutes = 60 }, false, "reuseMinutes"),
            (defaults with { ReuseMinutes = 0, ReuseMaxMinutes = 10 }, true, ""),
            (defaults with { ReuseMinutes = 0, ReuseMaxMinutes = 9 }, false, "reuseMaxMinutes"),
            (defaults with { ReuseMinutes = 10, ReuseMaxMinutes = 10 }, true, ""),
            (defaults with { ReuseMinutes = 10, ReuseMaxMinutes = 1440 }, true, ""),
            (defaults with { ReuseMinutes = 10, ReuseMaxMinutes = 1441 }, false, "reuseMaxMinutes"),
            (defaults with { ReuseMinutes = 1440, ReuseMaxMinutes = 1440 }, true, ""),
            (defaults with { Port = -1 }, false, "port"),
            (defaults with { Port = 65535 }, true, ""),
            (defaults with { Port = 65536 }, false, "port"),
            (defaults with { Method = "oidc" }, false, "method"),
            (defaults with { BaseUrl = "not a url" }, false, "baseUrl"),
            (defaults with { BaseUrl = "ftp://ws.example.com" }, false, "baseUrl"),
            (defaults with { BaseUrl = "https://user:pw@ws.example.com" }, false, "baseUrl"),
            (defaults with { BaseUrl = "https://user@ws.example.com" }, false, "baseUrl"),
            (defaults with { BaseUrl = "https://ws.example.com/\n" }, false, "baseUrl"),
            (defaults with { BaseUrl = "https://ws.example.com/" + new string('a', 2100) }, false, "baseUrl"),
            (defaults with { BaseUrl = "" }, false, "baseUrl"),
            (defaults with { BaseUrl = "https://ws.example.com" }, true, ""),
            (defaults with { BaseUrl = "http://localhost:8080" }, true, ""),
        ];
        foreach ((ToolSettings value, bool good, string key) in cases)
        {
            string? problem = value.Problem();
            check(good ? problem is null : problem is not null && problem.Contains("'" + key + "'", StringComparison.Ordinal), $"settings: limits {value.Canonical()} -> {(good ? "good" : "refused, names " + key)} ({problem})");
        }

        ToolSettings? parsed = ToolSettings.FromCanonical(Canonical(30, "passkey", "https://ws.example.com", 8765, 10), out string? error);
        check(parsed == new ToolSettings(30, 480, "passkey", "https://ws.example.com", 8765, 10) && error is null, "settings: canonical JSON parses back (" + error + ")");
        string[] refused =
        [
            "not json",
            "[]",
            "{\"method\":\"passkey\",\"reuseMinutes\":10,\"reuseMaxMinutes\":480,\"baseUrl\":null,\"port\":0,\"timeoutMinutes\":5}",
            "{\"reuseMinutes\":10,\"reuseMaxMinutes\":480,\"method\":\"passkey\",\"baseUrl\":null,\"port\":0}",
            "{\"reuseMinutes\":10,\"reuseMaxMinutes\":480,\"method\":\"passkey\",\"baseUrl\":null,\"port\":0,\"timeoutMinutes\":5,\"extra\":1}",
            "{\"reuseMinutes\":10.0,\"reuseMaxMinutes\":480,\"method\":\"passkey\",\"baseUrl\":null,\"port\":0,\"timeoutMinutes\":5}",
            "{\"reuseMinutes\":1e1,\"reuseMaxMinutes\":480,\"method\":\"passkey\",\"baseUrl\":null,\"port\":0,\"timeoutMinutes\":5}",
            "{\"reuseMinutes\":\"10\",\"reuseMaxMinutes\":480,\"method\":\"passkey\",\"baseUrl\":null,\"port\":0,\"timeoutMinutes\":5}",
            "{ \"reuseMinutes\":10,\"reuseMaxMinutes\":480,\"method\":\"passkey\",\"baseUrl\":null,\"port\":0,\"timeoutMinutes\":5}",
            Canonical(10, "passkey", null, 0, 31),
            Canonical(10, "passkey", "https://u:p@ws.example.com", 0, 5),
            Canonical(10, "passkey", null, 0, 5, 1441),
            Canonical(100, "passkey", null, 0, 5, 60),
            "{\"reuseMinutes\":10,\"method\":\"passkey\",\"baseUrl\":null,\"port\":0,\"timeoutMinutes\":5}",
            "{\"reuseMaxMinutes\":480,\"reuseMinutes\":10,\"method\":\"passkey\",\"baseUrl\":null,\"port\":0,\"timeoutMinutes\":5}",
        ];
        foreach (string text in refused)
        {
            check(ToolSettings.FromCanonical(text, out string? why) is null && why is not null, "settings: not canonical or not valid is refused: " + text + " (" + why + ")");
        }

        IReadOnlyList<SettingChange> changes = defaults.Changes(defaults with { Port = 8765, BaseUrl = "https://ws.example.com" });
        check(changes.Count == 2 && changes[0] == new SettingChange("baseUrl", "none", "https://ws.example.com") && changes[1] == new SettingChange("port", "0", "8765"), "settings: changes in key order, none for no baseUrl");
        check(defaults.Changes(defaults).Count == 0, "settings: no change");
    }

    /// <summary>Changes one setting in the signed manifest (signed by the admin), as a --config save would.</summary>
    private static void Row(StateDatabase db, string name, string value)
    {
        if (!TestState.Setting(db, name, value))
        {
            throw new InvalidOperationException("the setting could not be written");
        }
    }

    /// <summary>The manifest version, 0 when there is none.</summary>
    private static long Version(StateDatabase db) => TestState.Current(db)?.Version ?? 0;

    private static void RoundTrip(Action<bool, string> check, string root)
    {
        StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "round"));
        check(ToolSettings.Load(db, out string? error) == ToolSettings.Defaults && error is null && !File.Exists(db.FilePath), "db settings: a missing database gives the defaults and creates nothing");
        check(ApprovalSettings.Load(db, out error) == ToolSettings.Defaults.Approval && error is null, "db settings: approval settings from a missing database are the defaults");
        check(ReuseSettings.Load(db) == new ReuseOffer(480, 10), "db settings: reuse from a missing database is the default");

        TestState.Seeded(db.FilePath);
        check(ToolSettings.Load(db, out error) == ToolSettings.Defaults && error is null, "db settings: the first manifest holds the defaults");
        Row(db, "reuseMinutes", "30");
        Row(db, "reuseMaxMinutes", "600");
        Row(db, "baseUrl", "https://ws.example.com");
        Row(db, "port", "8765");
        Row(db, "timeoutMinutes", "12");
        check(ToolSettings.Load(db, out error) == new ToolSettings(30, 600, "passkey", "https://ws.example.com", 8765, 12) && error is null, "db settings: settings round trip through the signed manifest (" + error + ")");
        check(ApprovalSettings.Load(db, out error) == new ApprovalSettings("passkey", "https://ws.example.com", 8765, TimeSpan.FromMinutes(12)) && error is null, "db settings: approval settings from the manifest");
        check(ReuseSettings.Load(db) == new ReuseOffer(600, 30), "db settings: reuse from the manifest: the ceiling and the starting entry");
        check(!TestState.Settings(db, ToolSettings.Defaults with { TimeoutMinutes = 31 }) && ToolSettings.Load(db, out _).TimeoutMinutes == 12, "db settings: a manifest with a value out of its limits is never stored");

        // Settings edited by hand in state.db: verification fails, so the defaults and an error; reuse is off.
        ManifestTests.Execute(db.FilePath, "UPDATE manifest SET text = replace(text, '\"port\":8765', '\"port\":8766')");
        ToolSettings loaded = ToolSettings.Load(db, out string? why);
        check(loaded == ToolSettings.Defaults && why is not null && why.Contains("state failed verification", StringComparison.Ordinal), "db settings: an edited setting gives the defaults and a verification error (" + why + ")");
        check(ApprovalSettings.Load(db, out string? approvalError) == ToolSettings.Defaults.Approval && approvalError is not null, "db settings: edited: approval settings are the defaults with an error");
        check(ReuseSettings.Load(db) == ReuseOffer.Off, "db settings: edited: reuse is off");

        string garbage = Path.Combine(root, "garbage");
        Directory.CreateDirectory(garbage);
        File.WriteAllText(Path.Combine(garbage, "state.db"), "not a database");
        StateDatabase unreadable = StateDatabase.InFolder(garbage);
        check(ToolSettings.Load(unreadable, out string? garbageError) == ToolSettings.Defaults && garbageError is not null, "db settings: an unreadable database gives the defaults and an error");
        check(ReuseSettings.Load(unreadable) == ReuseOffer.Off, "db settings: an unreadable database turns reuse off");
    }

    /// <summary>A database of an older (or newer) schema is not moved forward: it is an error, and nothing in it is used or changed.</summary>
    private static void Schema(Action<bool, string> check, string root)
    {
        string path = SchemaOne(Path.Combine(root, "old-schema"));
        byte[] before = File.ReadAllBytes(path);
        StateDatabase db = new(path);
        check(StateDatabase.SchemaVersion == 10, "db schema: the schema version is 10");
        check(!db.TryCheck(out string? error) && error is not null && error.Contains("delete state.db to start over", StringComparison.Ordinal), "db schema: an older database is an error that says to delete state.db (" + error + ")");
        check(!new PasskeyStore(db).TryAll(out _) && new PasskeyStore(db).All().Count == 0, "db schema: its passkeys are not used");
        check(ToolSettings.Load(db, out error) == ToolSettings.Defaults && error is not null && ReuseSettings.Load(db) == ReuseOffer.Off, "db schema: settings from it are an error");
        check(!new PasskeyStore(db).Add(new PasskeyRecord("k-new", "a2V5", -7, "localhost", "x", DateTimeOffset.UtcNow, 0)) && File.ReadAllBytes(path).AsSpan().SequenceEqual(before), "db schema: nothing is written to it");

        string newer = Path.Combine(root, "new-schema");
        StateDatabase newerDb = TestState.Seeded(Path.Combine(newer, StateDatabase.FileName));
        check(new GrantStore(newerDb).Add("K", 1), "db schema: a current database");
        using (SqliteConnection connection = new(new SqliteConnectionStringBuilder { DataSource = newerDb.FilePath, Pooling = false }.ToString()))
        {
            connection.Open();
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "UPDATE schema_version SET version = " + (StateDatabase.SchemaVersion + 1);
            command.ExecuteNonQuery();
        }

        check(!StateDatabase.InFolder(newer).TryCheck(out string? newerError) && newerError is not null && newerError.Contains("delete state.db to start over", StringComparison.Ordinal), "db schema: a newer database is an error too (" + newerError + ")");
        ManifestTests.Execute(newerDb.FilePath, "UPDATE schema_version SET version = 4");
        check(!StateDatabase.InFolder(newer).TryCheck(out string? fourError) && fourError is not null && fourError.Contains("delete state.db to start over", StringComparison.Ordinal), "db schema: a schema 4 database (unsigned grants) is an error that says to delete state.db (" + fourError + ")");
    }

    /// <summary>A schema 1 state.db (as Task 13a made it) with one passkey enrolled. Returns its path.</summary>
    private static string SchemaOne(string folder)
    {
        Directory.CreateDirectory(folder);
        string path = Path.Combine(folder, "state.db");
        using (SqliteConnection connection = new(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false, Mode = SqliteOpenMode.ReadWriteCreate }.ToString()))
        {
            connection.Open();
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = """
                PRAGMA journal_mode = WAL;
                CREATE TABLE schema_version (version INTEGER NOT NULL);
                CREATE TABLE passkeys (
                    id TEXT PRIMARY KEY NOT NULL, public_key TEXT NOT NULL, alg INTEGER NOT NULL, rp_id TEXT NOT NULL,
                    name TEXT NOT NULL, created TEXT NOT NULL, sign_count INTEGER NOT NULL);
                CREATE TABLE grants (key TEXT PRIMARY KEY NOT NULL, approved INTEGER NOT NULL, expires INTEGER NOT NULL);
                CREATE TABLE audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT NOT NULL, event TEXT NOT NULL, secrets TEXT NOT NULL,
                    program TEXT NOT NULL, detail TEXT NOT NULL, key_name TEXT NOT NULL, entry TEXT NOT NULL,
                    prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
                INSERT INTO schema_version (version) VALUES (1);
                INSERT INTO passkeys VALUES ('old-id', 'a2V5', -7, 'localhost', 'laptop', '2026-11-01T10:00:00.0000000+00:00', 3);
                """;
            command.ExecuteNonQuery();
        }

        return path;
    }

    private static void Cli(Action<bool, string> check)
    {
        check(CliArgs.Parse(["--config"], out _) is CliCommand.Config { Show: false }, "cli: --config");
        check(CliArgs.Parse(["--config", "--show"], out _) is CliCommand.Config { Show: true }, "cli: --config --show");
        check(CliArgs.Parse(["--show", "--config"], out _) is CliCommand.Config { Show: true }, "cli: --show may come first");
        check(CliArgs.Parse(["--show"], out string alone) is null && alone.Contains("--show", StringComparison.Ordinal), "cli: --show alone is refused (" + alone + ")");
        check(CliArgs.Parse(["--list", "--show"], out _) is null, "cli: --show goes only with --config");
        check(CliArgs.Parse(["--config", "extra"], out _) is null, "cli: --config takes no argument");
        check(CliArgs.Parse(["--config", "--show", "extra"], out _) is null, "cli: --config --show takes no argument");
        check(CliArgs.Parse(["--config", "--baseUrl", "x"], out _) is null, "cli: --config has no setting options");
        check(CliArgs.Parse(["--config", "--list"], out string two) is null && two.Contains("one command at a time", StringComparison.Ordinal), "cli: --config with another command is refused");
        check(CliArgs.Parse(["--config", "--", "p"], out _) is null, "cli: --config with a run is refused");
        check(CliArgs.Parse(["--config", "--name", "x"], out _) is null, "cli: --name does not go with --config");
        check(CliArgs.Parse(["--help"], out _) is CliCommand.Help { Text: var help } && help.Contains("--config", StringComparison.Ordinal) && help.Contains("--show", StringComparison.Ordinal), "cli: --help lists --config and --show");

        check(CliArgs.NeedsTerminal(new CliCommand.Config(false)), "cli: --config needs a real terminal");
        check(!CliArgs.NeedsTerminal(new CliCommand.Config(true)), "cli: --config --show works anywhere");
        check(CliArgs.NeedsTerminal(new CliCommand.Enroll()) && CliArgs.NeedsTerminal(new CliCommand.Enrolled()) && CliArgs.NeedsTerminal(new CliCommand.Unenroll("x")) && CliArgs.NeedsTerminal(new CliCommand.Revoke()), "cli: --enroll, --enrolled, --unenroll and --revoke need a real terminal");
        check(!CliArgs.NeedsTerminal(new CliCommand.List()) && !CliArgs.NeedsTerminal(new CliCommand.Set(["A_B"])), "cli: --list and --set do not");
    }

    private static void Show(Action<bool, string> check, string root)
    {
        StateDatabase empty = StateDatabase.InFolder(Path.Combine(root, "show-empty"));
        StringWriter stdout = new();
        StringWriter stderr = new();
        check(ConfigShow.Run(empty, stdout, stderr) == 0 && !File.Exists(empty.FilePath), "config --show: exit 0 with nothing enrolled, creates nothing");
        string[] lines = stdout.ToString().Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);
        check(lines.SequenceEqual(["reuseMinutes\t10", "reuseMaxMinutes\t480", "method\tpasskey", "baseUrl\tnone", "port\t0", "timeoutMinutes\t5"]), "config --show: prints every setting, one per line (" + string.Join(" | ", lines) + ")");

        StateDatabase set = TestState.Seeded(Path.Combine(root, "show-set", StateDatabase.FileName));
        Row(set, "baseUrl", "https://ws.example.com");
        stdout = new StringWriter();
        check(ConfigShow.Run(set, stdout, new StringWriter()) == 0 && stdout.ToString().Contains("baseUrl\thttps://ws.example.com", StringComparison.Ordinal), "config --show: prints a stored value");

        StateDatabase bad = TestState.Seeded(Path.Combine(root, "show-bad", StateDatabase.FileName));
        ManifestTests.Execute(bad.FilePath, "UPDATE manifest SET text = replace(text, '\"port\":0', '\"port\":1')");
        stderr = new StringWriter();
        check(ConfigShow.Run(bad, new StringWriter(), stderr) == RunCommand.StoreError && stderr.ToString().Contains("state failed verification", StringComparison.Ordinal), "config --show: an edited setting is exit 4 with the verification message");
    }

    private sealed class ConfigRun
    {
        public ConfigChange? Result { get; set; }

        public List<string> Lines { get; } = [];

        public Uri? Link { get; set; }

        public string Page { get; set; } = "";

        public string Policy { get; set; } = "";

        public int Status { get; set; }

        public string Reply { get; set; } = "";

        public bool AgainGone { get; set; }

        public bool EmptyBeforeCode { get; set; }

        /// <summary>The reply to /create (the sign step) on the first run.</summary>
        public string First { get; set; } = "";
    }

    private sealed class Codes
    {
        private readonly System.Collections.Concurrent.BlockingCollection<string?> _queue = [];

        public void Type(string? code) => _queue.Add(code);

        public string? Read() => _queue.TryTake(out string? code, TimeSpan.FromSeconds(30)) ? code : null;
    }

    private static HttpResponseMessage? Send(HttpClient client, HttpMethod method, string url, string? body = null)
    {
        try
        {
            using HttpRequestMessage message = new(method, url);
            if (body is not null)
            {
                message.Content = new StringContent(body, Encoding.UTF8, "application/json");
            }

            return client.Send(message);
        }
        catch (HttpRequestException)
        {
            return null;
        }
    }

    private static string Text(HttpResponseMessage? response) => response?.Content.ReadAsStringAsync().GetAwaiter().GetResult() ?? "";

    private static bool Gone(HttpResponseMessage? response) => response is null || response.StatusCode == HttpStatusCode.NotFound;

    private static JsonElement Start(string page)
    {
        const string open = "<script type=\"application/json\" id=\"start\">";
        int from = page.IndexOf(open, StringComparison.Ordinal);
        if (from < 0)
        {
            return default;
        }

        from += open.Length;
        int to = page.IndexOf("</script>", from, StringComparison.Ordinal);
        try
        {
            using JsonDocument document = JsonDocument.Parse(page[from..to]);

            return document.RootElement.Clone();
        }
        catch (JsonException)
        {
            return default;
        }
    }

    private static byte[] Challenge(byte[] seed, string text) => SHA256.HashData([.. seed, .. SHA256.HashData(Encoding.UTF8.GetBytes(text))]);

    private static SettingsPage Page(StateDatabase db, ApprovalSettings settings, Action<string> announce, Func<string?>? readCode)
    {
        PasskeyStore passkeys = new(db);
        EnrollmentTarget Target(ApprovalSettings forPage)
        {
            PasskeyMethod method = new(passkeys, forPage, readCode);

            return EnrollmentTarget.For(method, new WebApprover(method, forPage, announce, TimeSpan.Zero));
        }

        return new SettingsPage(db, Target(settings), Target(settings with { BaseUrl = null }), announce, readCode);
    }

    /// <summary>Runs --config on its own task. When the link is announced, <paramref name="act" /> plays the browser.</summary>
    private static async Task<ConfigRun> Drive(StateDatabase db, ApprovalSettings settings, Func<string?>? readCode, Action<ConfigRun, string> act)
    {
        ConfigRun run = new();
        System.Collections.Concurrent.BlockingCollection<string> queue = [];
        Task<ConfigChange> task = Task.Run(() => Page(db, settings, queue.Add, readCode).Run());
        DateTime stop = DateTime.UtcNow.AddSeconds(25);
        while (!task.IsCompleted && DateTime.UtcNow < stop)
        {
            if (queue.TryTake(out string? line, 200))
            {
                run.Lines.Add(line);
                if (line.StartsWith(ConfigPrefix, StringComparison.Ordinal))
                {
                    run.Link = new Uri(line[ConfigPrefix.Length..]);
                    act(run, "http://127.0.0.1:" + run.Link.Port + run.Link.AbsolutePath);
                }
            }
        }

        Task done = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(20)));
        while (queue.TryTake(out string? rest))
        {
            run.Lines.Add(rest);
        }

        run.Result = done == task ? task.Result : null;

        return run;
    }

    private enum Twist
    {
        None,
        OtherBind,
        SignOtherValues,
        Cancel,
    }

    /// <summary>Gets the page, signs <paramref name="signed" /> (or other values), posts <paramref name="sent" /> to /save, then tries again.</summary>
    private static Action<ConfigRun, string> Save(HttpClient client, TestAuthenticator key, string signed, string sent, Twist twist = Twist.None)
    {
        return (run, url) =>
        {
            using HttpResponseMessage? page = Send(client, HttpMethod.Get, url);
            run.Page = Text(page);
            run.Policy = page is not null && page.Headers.TryGetValues("Content-Security-Policy", out IEnumerable<string>? policy) ? string.Join(",", policy) : "";
            JsonElement start = Start(run.Page);
            byte[] bind = start.ValueKind == JsonValueKind.Object && start.TryGetProperty("bind", out JsonElement value) ? Base64Url.DecodeFromChars(value.GetString()!) : [];
            if (twist == Twist.OtherBind)
            {
                bind = RandomNumberGenerator.GetBytes(32);
            }

            // The admin signs the new manifest: the prefix the page was given, the canonical settings and "}".
            string prefix = start.ValueKind == JsonValueKind.Object && start.TryGetProperty("prefix", out JsonElement given) ? given.GetString() ?? "" : "";
            string origin = run.Link!.GetLeftPart(UriPartial.Authority);
            Dictionary<string, string> body = JsonSerializer.Deserialize<Dictionary<string, string>>(key.Assert(Challenge(bind, prefix + signed + "}"), origin, run.Link.IdnHost, TestState.NextCount()))!;
            body["settings"] = sent;
            string json = JsonSerializer.Serialize(body);
            using HttpResponseMessage? reply = twist == Twist.Cancel ? Send(client, HttpMethod.Post, url + "/deny", "") : Send(client, HttpMethod.Post, url + "/save", json);
            run.Status = (int?)reply?.StatusCode ?? 0;
            run.Reply = Text(reply);
            using HttpResponseMessage? again = Send(client, HttpMethod.Post, url + "/save", json);
            using HttpResponseMessage? againPage = Send(client, HttpMethod.Get, url);
            run.AgainGone = Gone(again) && Gone(againPage);
        };
    }

    private static async Task Gated(Action<bool, string> check, string root)
    {
        using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
        client.Timeout = TimeSpan.FromSeconds(20);
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.ES256();
        using TestAuthenticator stranger = TestAuthenticator.ES256();
        ApprovalSettings local = new("passkey", null, 0, TimeSpan.FromSeconds(20));

        // The admin (laptop), a second key that only approves runs (phone), and the settings: version 3.
        StateDatabase NewDb()
        {
            StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "gated-" + Guid.NewGuid().ToString("N")));
            new PasskeyStore(db).Add(laptop.Record("localhost", "laptop"));
            new PasskeyStore(db).Add(phone.Record("localhost", "phone"));
            Row(db, "timeoutMinutes", "5");

            return db;
        }

        string current = Canonical(10, "passkey", null, 0, 5);
        string wanted = Canonical(30, "passkey", "https://ws.example.com", 8765, 10, 600);

        // A good save: the values are checked, stored, and the audit names the settings, old -> new, and the key.
        {
            StateDatabase db = NewDb();
            ConfigRun run = await Drive(db, local, null, Save(client, laptop, wanted, wanted));
            check(run.Result is { Code: 0 }, "config: a good save is done (" + run.Result?.Detail + ")");
            check(ToolSettings.Load(db, out string? error) == new ToolSettings(30, 600, "passkey", "https://ws.example.com", 8765, 10) && error is null, "config: the new values are in state.db");
            check(Version(db) == 4 && new PasskeyStore(db).All().Select(item => (item.Name, item.Admin)).SequenceEqual([("laptop", true), ("phone", false)]), "config: a new manifest (version 4) with the same keys");
            check(run.Status == 200 && run.Reply.Contains("\"ok\":true", StringComparison.Ordinal), "config: the save reply is ok (" + run.Reply + ")");
            check(run.AgainGone, "config: after the save, the page and a second POST are 404");
            string token = run.Link?.AbsolutePath.Split('/')[^1] ?? "";
            check(run.Lines.Count == 1 && run.Link is not null && run.Lines[0] == ConfigPrefix + "http://localhost:" + run.Link.Port + "/c/" + token && token.Length == 22, "config: the terminal gets only the link /c/<token> (" + string.Join(" | ", run.Lines) + ")");
            check(TestAudit.TryRead(db, 5, null, out IReadOnlyList<AuditRow> rows, out _) && rows.Count == 1 && rows[0].Event == "settings-changed"
                && rows[0].Secrets.SequenceEqual(["reuseMinutes", "reuseMaxMinutes", "baseUrl", "port", "timeoutMinutes"]) && rows[0].KeyName == "laptop"
                && rows[0].Detail == "reuseMinutes 10 -> 30; reuseMaxMinutes 480 -> 600; baseUrl none -> https://ws.example.com; port 0 -> 8765; timeoutMinutes 5 -> 10", "config: the audit row has the names, old -> new and the key (" + (rows.Count > 0 ? rows[0].Detail + " / " + rows[0].KeyName : "none") + ")");
            string entry = StateDatabaseTests.AuditText(db.FilePath);
            check(TestAudit.Events(db, all: true).All(item => !item.Reason.Contains("signature", StringComparison.Ordinal) && item.Meta.Values.All(value => !value.Contains("signature", StringComparison.Ordinal))) && !entry.Contains("clientDataJSON", StringComparison.Ordinal) && !entry.Contains("authenticatorData", StringComparison.Ordinal) && entry.Contains("settings-changed", StringComparison.Ordinal) && entry.Contains("reuseMinutes 10 -> 30", StringComparison.Ordinal), "config: the audit event holds the changes and no proof material");
            check(TestAudit.Events(db).All(item => item.Verify(TestAudit.KeyOf(db).PublicKey)), "config: the audit event is signed by the machine key");

            // The page: every setting, its current value and its limits; one-use token path; CSP with hashes; no inline handlers.
            check(run.Page.Contains("data-setting=\"reuseMinutes\"", StringComparison.Ordinal) && run.Page.Contains("data-setting=\"reuseMaxMinutes\"", StringComparison.Ordinal) && run.Page.Contains("data-setting=\"method\"", StringComparison.Ordinal)
                && run.Page.Contains("data-setting=\"baseUrl\"", StringComparison.Ordinal) && run.Page.Contains("data-setting=\"port\"", StringComparison.Ordinal)
                && run.Page.Contains("data-setting=\"timeoutMinutes\"", StringComparison.Ordinal), "config page: a field for every setting");
            check(run.Page.Contains("0 to reuseMaxMinutes", StringComparison.Ordinal) && run.Page.Contains("10 to 1440", StringComparison.Ordinal) && run.Page.Contains("0 to 65535", StringComparison.Ordinal) && run.Page.Contains("1 to 30", StringComparison.Ordinal), "config page: the limits");
            check(run.Page.Contains("Current: 10", StringComparison.Ordinal) && run.Page.Contains("Current: 480", StringComparison.Ordinal) && run.Page.Contains("Current: 5", StringComparison.Ordinal) && run.Page.Contains("Current: none", StringComparison.Ordinal), "config page: the current values");
            check(run.Page.Contains("id=\"changes\"", StringComparison.Ordinal), "config page: a change summary");
            check(run.Policy.Contains("script-src 'sha256-", StringComparison.Ordinal) && run.Policy.Contains("style-src 'sha256-", StringComparison.Ordinal) && run.Policy.Contains("frame-ancestors 'none'", StringComparison.Ordinal) && run.Policy.Contains("form-action 'none'", StringComparison.Ordinal), "config page: CSP allows the inline script and style by hash only (" + run.Policy + ")");
            check(!System.Text.RegularExpressions.Regex.IsMatch(run.Page, "\\son[a-z]+=", System.Text.RegularExpressions.RegexOptions.IgnoreCase), "config page: no inline event attributes");
            check(!run.Page.Contains("ctrlKey", StringComparison.Ordinal) && !run.Page.Contains("metaKey", StringComparison.Ordinal), "config page: no Ctrl+Enter shortcut");
            string slash = ((char)92).ToString();
            check(run.Page.Contains("[" + slash + "u007f-" + slash + "uffff]", StringComparison.Ordinal) && run.Page.All(c => c < 128), "config page: the escape range is written with escapes and the page is plain ASCII");
            int scriptAt = run.Page.LastIndexOf("<script>", StringComparison.Ordinal) + "<script>".Length;
            string served = run.Page[scriptAt..run.Page.IndexOf("</script>", scriptAt, StringComparison.Ordinal)];
            check(run.Policy.Contains("script-src " + ApprovalPage.Hash(served) + ";", StringComparison.Ordinal), "config page: the CSP hash is of the script as served");
            JsonElement start = Start(run.Page);
            check(start.ValueKind == JsonValueKind.Object && start.GetProperty("flow").GetString() == "assert" && start.GetProperty("current").GetRawText() == current, "config page: the start data has the flow and the current values (" + (start.ValueKind == JsonValueKind.Object ? start.GetRawText() : "") + ")");
            string payload = start.ValueKind == JsonValueKind.Object ? start.GetProperty("payload").GetString() ?? "" : "";
            check(!payload.Contains("allowCredentials", StringComparison.Ordinal) && !payload.Contains(TestAuthenticator.Encode(laptop.CredentialId), StringComparison.Ordinal), "config page: the payload names no credential (the server checks the signer is an admin)");
            check(start.ValueKind == JsonValueKind.Object && start.GetProperty("prefix").GetString() is { } prefix && prefix.StartsWith("{\"v\":4,\"keys\":[", StringComparison.Ordinal) && prefix.EndsWith(",\"settings\":", StringComparison.Ordinal), "config page: the page gets the next manifest's text up to the settings");
            check(run.Page.Contains("start.prefix + text + \"}\"", StringComparison.Ordinal), "config page: the script signs the prefix, the settings and the closing brace");
        }

        // Proofs that do not cover these values, a value that is not allowed, and a key that is not enrolled: nothing is saved.
        (string Name, Action<ConfigRun, string> Act, int Status)[] refused =
        [
            ("an assertion over another page", Save(client, laptop, wanted, wanted, Twist.OtherBind), 403),
            ("an assertion over other values", Save(client, laptop, Canonical(30, "passkey", null, 8765, 10), wanted), 403),
            ("a value changed after the assertion", Save(client, laptop, wanted, Canonical(30, "passkey", "https://ws.example.com", 8766, 10)), 403),
            ("a value outside its limits", Save(client, laptop, Canonical(10, "passkey", null, 0, 31), Canonical(10, "passkey", null, 0, 31)), 400),
            ("a starting entry above the ceiling", Save(client, laptop, Canonical(100, "passkey", null, 0, 5, 60), Canonical(100, "passkey", null, 0, 5, 60)), 400),
            ("a ceiling above 1440", Save(client, laptop, Canonical(10, "passkey", null, 0, 5, 1441), Canonical(10, "passkey", null, 0, 5, 1441)), 400),
            ("a bad baseUrl", Save(client, laptop, Canonical(10, "passkey", "https://u:p@ws.example.com", 0, 5), Canonical(10, "passkey", "https://u:p@ws.example.com", 0, 5)), 400),
            ("text that is not canonical", Save(client, laptop, wanted.Replace(",", ", ", StringComparison.Ordinal), wanted.Replace(",", ", ", StringComparison.Ordinal)), 400),
            ("a key that is not enrolled", Save(client, stranger, wanted, wanted), 403),
            ("a key that is not the admin", Save(client, phone, wanted, wanted), 403),
            ("cancel", Save(client, laptop, wanted, wanted, Twist.Cancel), 200),
        ];
        foreach ((string name, Action<ConfigRun, string> act, int status) in refused)
        {
            StateDatabase db = NewDb();
            ConfigRun run = await Drive(db, local, null, act);
            check(run.Result is { Code: RunCommand.Denied }, $"config: {name}: denied ({run.Result?.Code} {run.Result?.Detail})");
            check(run.Status == status, $"config: {name}: status {status} ({run.Status})");
            check(ToolSettings.Load(db, out _) == ToolSettings.Defaults && Version(db) == 3 && OnlyDenied(db), $"config: {name}: nothing saved, no settings audit row, one change-denied row");
            check(run.AgainGone, $"config: {name}: after the outcome, the page and a second POST are 404");
        }

        // A second admin key may change the settings too; the page offers both admin keys.
        {
            StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "gated-two-" + Guid.NewGuid().ToString("N")));
            TestState.Add(db, laptop.Record("localhost", "laptop"));
            TestState.Add(db, phone.Record("localhost", "phone"), admin: true);
            TestState.Add(db, stranger.Record("localhost", "runs-only"));
            ConfigRun run = await Drive(db, local, null, Save(client, phone, wanted, wanted));
            string payload = Start(run.Page) is { ValueKind: JsonValueKind.Object } start ? start.GetProperty("payload").GetString() ?? "" : "";
            check(!payload.Contains("allowCredentials", StringComparison.Ordinal) && !payload.Contains(TestAuthenticator.Encode(stranger.CredentialId), StringComparison.Ordinal), "config: with two admins, the payload names no credential");
            check(run.Result is { Code: 0 } && ToolSettings.Load(db, out _).Port == 8765 && db.TryCheck(out _), "config: the second admin key saves the settings (" + run.Result?.Detail + ")");
            check(TestAudit.TryRead(db, 5, null, out IReadOnlyList<AuditRow> rows, out _) && rows.Count == 1 && rows[0].KeyName == "phone", "config: the audit row names the second admin");
            run = await Drive(db, local, null, Save(client, stranger, Canonical(10, "passkey", null, 0, 5), Canonical(10, "passkey", null, 0, 5)));
            check(run.Result is { Code: RunCommand.Denied } && run.Status == 403 && ToolSettings.Load(db, out _).Port == 8765, "config: a key that is not an admin still cannot save (" + run.Result?.Detail + ")");
        }

        // An admin assertion over the right values but an older manifest (the page started from another state): nothing saved.
        {
            StateDatabase db = NewDb();
            ConfigRun run = await Drive(db, local, null, (r, url) =>
            {
                Row(db, "reuseMinutes", "20");
                Save(client, laptop, wanted, wanted)(r, url);
            });
            check(run.Result is { Code: RunCommand.Denied } && ToolSettings.Load(db, out _).ReuseMinutes == 20 && Version(db) == 4 && OnlyDenied(db), "config: a save from a state that changed meanwhile is refused (" + run.Result?.Detail + ")");
        }

        // The time limit: nothing saved.
        {
            StateDatabase db = NewDb();
            ConfigRun run = await Drive(db, local with { Timeout = TimeSpan.FromSeconds(1) }, null, (_, _) => { });
            check(run.Result is { Code: RunCommand.Denied } && ToolSettings.Load(db, out _) == ToolSettings.Defaults && Version(db) == 3, "config: the time limit saves nothing (" + run.Result?.Detail + ")");
        }

        // Settings changed by someone else while the page was open: nothing saved.
        {
            StateDatabase db = NewDb();
            ConfigRun run = await Drive(db, local, null, (r, url) =>
            {
                Row(db, "port", "4444");
                Save(client, laptop, wanted, wanted)(r, url);
            });
            check(run.Result is { Code: RunCommand.Denied } && ToolSettings.Load(db, out _).Port == 4444 && OnlyDenied(db), "config: settings that changed while the page was open are not overwritten (" + run.Result?.Detail + ")");
        }

        // A key enrolled only for baseUrl's host and a baseUrl set: no key works at localhost, so the page is not served there.
        {
            StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "gated-other-" + Guid.NewGuid().ToString("N")));
            new PasskeyStore(db).Add(laptop.Record("ws.example.com", "laptop"));
            ConfigRun run = await Drive(db, local, null, (_, _) => { });
            check(run.Result is { Code: RunCommand.Denied } && run.Link is null && run.Result.Detail.Contains("localhost", StringComparison.Ordinal), "config: no key works at the page host: denied, no link (" + run.Result?.Detail + ")");
        }

        // An unreadable passkey store: exit 4, no link.
        {
            string garbage = Path.Combine(root, "gated-garbage");
            Directory.CreateDirectory(garbage);
            File.WriteAllText(Path.Combine(garbage, "state.db"), "not a database");
            ConfigRun run = await Drive(StateDatabase.InFolder(garbage), local, null, (_, _) => { });
            check(run.Result is { Code: RunCommand.StoreError } && run.Link is null, "config: an unreadable database is exit 4 with no link (" + run.Result?.Detail + ")");
            StateDatabase edited = NewDb();
            ManifestTests.Execute(edited.FilePath, "UPDATE manifest SET text = replace(text, '\"admin\":false', '\"admin\":true')");
            run = await Drive(edited, local, null, (_, _) => { });
            check(run.Result is { Code: RunCommand.StoreError } && run.Link is null && run.Result.Detail.Contains("state failed verification", StringComparison.Ordinal), "config: a state that fails verification is exit 4 with no link, never first-run (" + run.Result?.Detail + ")");
        }
    }

    /// <summary>Gets the first-run page, registers a new passkey over <paramref name="text" />, and returns the code (or "").</summary>
    private static string Register(HttpClient client, ConfigRun run, string url, TestAuthenticator key, string text, string? sent = null, TestAuthenticator? signer = null, bool skipSign = false, string? keyName = null, PrfMode prf = PrfMode.Normal)
    {
        using HttpResponseMessage? page = Send(client, HttpMethod.Get, url);
        run.Page = Text(page);
        run.Policy = page is not null && page.Headers.TryGetValues("Content-Security-Policy", out IEnumerable<string>? policy) ? string.Join(",", policy) : "";
        JsonElement start = Start(run.Page);
        byte[] seed = start.ValueKind == JsonValueKind.Object && start.TryGetProperty("options", out JsonElement options) ? Base64Url.DecodeFromChars(options.GetProperty("challenge").GetString()!) : [];
        string attested = key.Attest(Challenge(seed, text), "http://localhost:" + run.Link!.Port, "localhost", "passkey");
        if (start.ValueKind == JsonValueKind.Object && start.TryGetProperty("options", out JsonElement pageOptions))
        {
            attested = TestState.WithPrf(attested, pageOptions, key, prf);
        }

        Dictionary<string, string> body = JsonSerializer.Deserialize<Dictionary<string, string>>(attested)!;
        body["settings"] = sent ?? text;
        if (keyName is not null)
        {
            body["name"] = keyName;
        }

        using HttpResponseMessage? reply = Send(client, HttpMethod.Post, url + "/create", JsonSerializer.Serialize(body));
        run.Status = (int?)reply?.StatusCode ?? 0;
        run.Reply = Text(reply);
        run.First = run.Reply;
        if (run.Status == 200 && signer is not { } && skipSign)
        {
            return "";
        }

        if (run.Status == 200)
        {
            run.Reply = TestState.SignStep(client, url, "http://localhost:" + run.Link!.Port, run.Reply, signer);
        }
        try
        {
            using JsonDocument document = JsonDocument.Parse(run.Reply);

            return document.RootElement.TryGetProperty("code", out JsonElement code) ? code.GetString() ?? "" : "";
        }
        catch (JsonException)
        {
            return "";
        }
    }

    /// <summary>The audit log has exactly one row, the change-denied row of --config, and no settings row.</summary>
    private static bool OnlyDenied(StateDatabase db) => TestAudit.TryRead(db, 10, null, out IReadOnlyList<AuditRow> rows, out _) && rows.Count == 1 && rows[0].Event == AdminEvent.ChangeDenied && rows[0].Detail.StartsWith("--config: ", StringComparison.Ordinal);

    private static bool Empty(StateDatabase db) => !File.Exists(db.FilePath) || (Version(db) == 0 && new PasskeyStore(db).All().Count == 0 && TestAudit.Events(db).Count == 0);

    private static int FreePort()
    {
        System.Net.Sockets.TcpListener probe = new(IPAddress.Loopback, 0);
        probe.Start();
        try
        {
            return ((IPEndPoint)probe.LocalEndpoint).Port;
        }
        finally
        {
            probe.Stop();
        }
    }

    /// <summary>--port N: parsing, the override over the setting, a port in use, nothing saved, and the first run.</summary>
    private static async Task PortOption(Action<bool, string> check, string root)
    {
        // Parsing: 1..65535 only; the number rides on any command that opens a page.
        check(CliArgs.Parse(["--config", "--port", "8765"], out _) is CliCommand.Config { Show: false, Port: 8765 }, "port: --config --port 8765");
        check(CliArgs.Parse(["--port", "1", "--set", "A"], out _) is CliCommand.Set { Port: 1 }, "port: --set with --port 1");
        check(CliArgs.Parse(["--remove", "A", "--port", "65535"], out _) is CliCommand.Remove { Port: 65535 }, "port: --remove with --port 65535");
        check(CliArgs.Parse(["--revoke", "--port", "9000"], out _) is CliCommand.Revoke { Port: 9000 }, "port: --revoke with --port");
        check(CliArgs.Parse(["--enroll", "--local", "--port", "9000"], out _) is CliCommand.Enroll { Local: true, Port: 9000 }, "port: --enroll with --port");
        check(CliArgs.Parse(["--unenroll", "x", "--port", "9000"], out _) is CliCommand.Unenroll { Port: 9000 }, "port: --unenroll with --port");
        check(CliArgs.Parse(["--secrets", "A", "--reason", "r", "--port", "9000", "--", "p", "--port", "1"], out _) is CliCommand.Run { Port: 9000, Args.Program: "p" } run1 && run1.Args.Arguments.SequenceEqual(["--port", "1"]), "port: a run with --port; the program keeps its own --port");
        check(CliArgs.Parse(["--config"], out _) is CliCommand.Config { Port: null }, "port: none given is null");
        foreach (string bad in new[] { "0", "65536", "-1", "abc", "", "80x", "1.5", "99999999999" })
        {
            check(CliArgs.Parse(["--config", "--port", bad], out string message) is null && message.Contains("--port", StringComparison.Ordinal) && message.Contains("65535", StringComparison.Ordinal), "port: '" + bad + "' is refused (" + message + ")");
        }

        check(CliArgs.Parse(["--list", "--port", "9000"], out _) is null && CliArgs.Parse(["--enrolled", "--port", "9000"], out _) is null
            && CliArgs.Parse(["--config", "--show", "--port", "9000"], out _) is null, "port: commands that open no page refuse --port");
        check(CliArgs.Parse(["--help"], out _) is CliCommand.Help { Text: var help } && help.Contains("--port", StringComparison.Ordinal) && help.Contains("ssh -L", StringComparison.Ordinal), "port: --help describes --port");

        // The override replaces the setting; null keeps it.
        ApprovalSettings set = new("passkey", "https://ws.example.com", 5555, TimeSpan.FromSeconds(20));
        check(set.WithPort(7777) == set with { Port = 7777 } && set.WithPort(null) == set, "port: WithPort replaces the port and keeps baseUrl");

        using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
        client.Timeout = TimeSpan.FromSeconds(20);
        using TestAuthenticator laptop = TestAuthenticator.ES256();

        StateDatabase NewDb()
        {
            StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "port-" + Guid.NewGuid().ToString("N")));
            new PasskeyStore(db).Add(laptop.Record("localhost", "laptop"));
            Row(db, "port", "5555");

            return db;
        }

        // The override wins over the stored setting, and the manifest is not touched.
        {
            StateDatabase db = NewDb();
            string before = TestState.Current(db)!.Canonical();
            int wanted = FreePort();
            ApprovalSettings stored = ApprovalSettings.Load(db, out _);
            ConfigRun run = await Drive(db, stored.WithPort(wanted), null, Save(client, laptop, "{}", "{}", Twist.Cancel));
            check(stored.Port == 5555 && run.Link?.Port == wanted, "port: the override wins over the port setting (" + run.Link + ")");
            check(TestState.Current(db)!.Canonical() == before && ToolSettings.Load(db, out _).Port == 5555, "port: the override is not stored (the manifest text is unchanged)");
        }

        // A port in use: one clear line, no link, and no fallback to another port.
        {
            StateDatabase db = NewDb();
            int taken = FreePort();
            System.Net.Sockets.TcpListener holder = new(IPAddress.Loopback, taken);
            holder.Start();
            try
            {
                ConfigRun run = await Drive(db, ApprovalSettings.Load(db, out _).WithPort(taken), null, Save(client, laptop, "{}", "{}", Twist.Cancel));
                string detail = run.Result?.Detail ?? "";
                check(run.Result is { Code: RunCommand.Denied } && run.Link is null && run.Lines.Count == 0, "port: a port in use fails without a link (" + detail + ")");
                check(detail.Contains("port " + taken + " is already in use", StringComparison.Ordinal) && !detail.Contains('\n'), "port: the message is one clear line (" + detail + ")");
            }
            finally
            {
                holder.Stop();
            }
        }

        // The same for a run approval.
        {
            int taken = FreePort();
            System.Net.Sockets.TcpListener holder = new(IPAddress.Loopback, taken);
            holder.Start();
            try
            {
                StateDatabase db = NewDb();
                ApprovalSettings settings = ApprovalSettings.Load(db, out _).WithPort(taken);
                List<string> lines = [];
                WebApprover approver = new(new PasskeyMethod(new PasskeyStore(db), settings, null), settings, lines.Add, TimeSpan.Zero);
                ApprovalDecision decision = approver.Ask(new ApprovalPrompt("Run", "x"));
                check(!decision.Approved && decision.Detail.Contains("port " + taken + " is already in use", StringComparison.Ordinal) && lines.Count == 0, "port: a run approval on a port in use is denied with the clear message (" + decision.Detail + ")");
            }
            finally
            {
                holder.Stop();
            }
        }

        // The first run (nothing enrolled) honors --port too, and stores the form's port, not the override.
        {
            StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "port-first-" + Guid.NewGuid().ToString("N")));
            using TestAuthenticator fresh = TestAuthenticator.ES256();
            Codes codes = new();
            int wanted = FreePort();
            string chosen = Canonical(30, "passkey", null, 0, 10);
            ConfigRun run = await Drive(db, new ApprovalSettings("passkey", null, 0, TimeSpan.FromSeconds(20)).WithPort(wanted), codes.Read, (r, url) => codes.Type(Register(client, r, url, fresh, chosen)));
            check(run.Result is { Code: 0 } && run.Link?.Port == wanted, "port: the first --config listens on the --port (" + run.Link + ", " + run.Result?.Detail + ")");
            check(ToolSettings.Load(db, out _).Port == 0, "port: the first run stores the form's port, not the override");
        }
    }

    private static async Task FirstRun(Action<bool, string> check, string root)
    {
        using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
        client.Timeout = TimeSpan.FromSeconds(20);
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator stranger = TestAuthenticator.ES256();
        using TestAuthenticator noPrf = TestAuthenticator.ES256(prf: false);
        ApprovalSettings local = new("passkey", null, 0, TimeSpan.FromSeconds(20));
        string wanted = Canonical(30, "passkey", null, 8765, 10);

        // The good flow: the form, then the passkey, then the code typed in the terminal. Nothing is written before the code.
        {
            StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "first-" + Guid.NewGuid().ToString("N")));
            Codes codes = new();
            ConfigRun run = await Drive(db, local, codes.Read, (r, url) =>
            {
                string code = Register(client, r, url, laptop, wanted);
                r.EmptyBeforeCode = Empty(db);
                codes.Type(code);
            });
            check(run.Result is { Code: 0 }, "config first run: done (" + run.Result?.Detail + ")");
            check(run.EmptyBeforeCode, "config first run: nothing is in state.db before the code is typed");
            check(run.Status == 200 && System.Text.RegularExpressions.Regex.IsMatch(run.Reply, "\"code\":\"[0-9]{6}\""), "config first run: the page gets a six-digit code (" + run.Reply + ")");
            check(!run.Lines.Any(line => System.Text.RegularExpressions.Regex.IsMatch(line, "(?<![0-9])[0-9]{6}(?![0-9])") && !line.StartsWith(ConfigPrefix, StringComparison.Ordinal)), "config first run: the code is never announced");
            check(run.Lines.Count == 1 && run.Lines[0].StartsWith(ConfigPrefix + "http://localhost:", StringComparison.Ordinal), "config first run: the terminal gets only the link (" + string.Join(" | ", run.Lines) + ")");
            check(ToolSettings.Load(db, out _) == new ToolSettings(30, 480, "passkey", null, 8765, 10), "config first run: the settings are stored");
            IReadOnlyList<PasskeyRecord> keys = new PasskeyStore(db).All();
            check(keys.Count == 1 && keys[0].RpId == "localhost" && keys[0].Name == "passkey" && keys[0].Admin && keys[0].Id == TestAuthenticator.Encode(laptop.CredentialId), "config first run: the passkey is stored for localhost, as the admin");
            check(Version(db) == 1 && db.TryCheck(out _), "config first run: the first manifest (version 1) verifies");
            {
                // The first key's slot: its salt is the one the page asked the passkey for, and the PRF output opens the master key
                // that nothing else in the state holds. The same first manifest has the store public key and the vault (the store's
                // private key under that master key), so the first --set needs no PRF.
                Manifest? first = TestState.Current(db);
                using Unlock? released = TestVault.Unlock(db, laptop);
                byte[]? master = null;
                byte[]? privateKey = null;
                try
                {
                    master = first is not null && released is not null ? KeyVault.OpenMaster(first, released) : null;
                    check(keys[0].Slot is not null && master is { Length: 32 }, "config first run: the first key has a key slot that its PRF output opens");
                    check(first is { Version: 1, Secrets.Count: 0 } && first.Store.Length == 66 && KeyVault.IsVault(first.Vault), "config first run: the first manifest has the store public key and the vault (and no secrets)");
                    privateKey = first is not null && master is not null ? KeyVault.UnwrapVault(first.Vault, master, first.Store) : null;
                    string privateHex = privateKey is null ? "" : Encoding.UTF8.GetString(privateKey);
                    check(privateHex.Length == 64 && DotenvxCipher.Instance.Derive(privateHex) == first!.Store, "config first run: the vault holds the private key of the stored public key, and the passkey's PRF output opens it");
                    SqliteConnection.ClearAllPools();
                    string stateFolder = Path.GetDirectoryName(db.FilePath)!;
                    bool leaked = privateKey is null || WebApprovalTests.FolderHolds(stateFolder, privateKey) || WebApprovalTests.FolderHolds(stateFolder, Encoding.UTF8.GetBytes(privateHex.ToUpperInvariant()))
                        || WebApprovalTests.FolderHolds(stateFolder, Convert.FromHexString(privateHex)) || WebApprovalTests.FolderHolds(stateFolder, Encoding.ASCII.GetBytes(Convert.ToBase64String(Convert.FromHexString(privateHex))));
                    check(!leaked, "config first run: the store private key (hex, upper hex, raw, base64) is in no file of the store folder: not state.db, its WAL or anything else");
                    check(!WebApprovalTests.FolderHolds(stateFolder, master!), "config first run: the master key is in no file either");
                    check(!Directory.EnumerateFiles(stateFolder, ".env*", SearchOption.AllDirectories).Any(), "config first run: no .env.keys or other key file");
                    string seen = StateDatabaseTests.AuditText(db.FilePath) + run.Reply + run.First + string.Join("|", run.Lines) + run.Result!.Detail + run.Page;
                    check(!seen.Contains(privateHex, StringComparison.OrdinalIgnoreCase), "config first run: the store private key is in no reply, page, audit entry or message");
                    check(run.Page.Contains("prf", StringComparison.Ordinal) && run.Page.Contains("PRF", StringComparison.Ordinal), "config first run: the page asks for a PRF passkey");
                }
                finally
                {
                    SecretValues.Clear(master);
                    SecretValues.Clear(privateKey);
                }

                string everything = StateDatabaseTests.AuditText(db.FilePath) + run.Reply + run.First + string.Join("|", run.Lines) + run.Result!.Detail;
                check(!everything.Contains(Convert.ToHexStringLower(laptop.PrfSecret), StringComparison.Ordinal) && !File.ReadAllText(db.FilePath, System.Text.Encoding.Latin1).Contains(Convert.ToBase64String(laptop.PrfSecret), StringComparison.Ordinal), "config first run: the PRF secret is in no reply, audit entry or message");
            }

            string fingerprint = "Admins: passkey " + GrantTests.Expected(laptop);
            check(run.Page.Contains(AdminKey.NotSetUp, StringComparison.Ordinal), "config first run: the page says the admin key is not set up yet");
            check(run.Reply.Contains("\"admin\":\"" + fingerprint + "\"", StringComparison.Ordinal), "config first run: the code reply shows the new admin key's fingerprint (" + run.Reply + ")");
            check(run.Result!.Detail.Contains(fingerprint, StringComparison.Ordinal) && run.Result.Detail.Contains("Note this fingerprint down", StringComparison.Ordinal), "config first run: the terminal shows the fingerprint to note down (" + run.Result.Detail + ")");
            using (JsonDocument step = JsonDocument.Parse(run.First))
            {
                JsonElement sign = step.RootElement.GetProperty("sign");
                Manifest? first = Manifest.Parse(sign.GetProperty("manifest").GetString()!, out _);
                check(first is { Version: 1 } && first.Store.Length == 66 && KeyVault.IsVault(first.Vault) && first.Settings == new ToolSettings(30, 480, "passkey", null, 8765, 10) && first.Admins.Single().Id == TestAuthenticator.Encode(laptop.CredentialId) && sign.GetProperty("first").GetBoolean()
                    && !sign.TryGetProperty("allowCredentials", out _), "config first run: after the registration the new key is asked to sign the first manifest, with it as admin (" + run.First + ")");
            }

            string script = run.Page[(run.Page.LastIndexOf("<script>", StringComparison.Ordinal) + 8)..];
            check(script.Contains("post(\"sign\"", StringComparison.Ordinal) && script.Contains("navigator.credentials.get", StringComparison.Ordinal) && script.Contains("navigator.credentials.create", StringComparison.Ordinal), "config first run: the page script has the second prompt (get, then post sign)");
            check(TestAudit.TryRead(db, 5, null, out IReadOnlyList<AuditRow> rows, out _) && rows.Count == 1 && rows[0].Event == "settings-setup" && rows[0].KeyName == "passkey"
                && rows[0].Secrets.SequenceEqual(["reuseMinutes", "port", "timeoutMinutes"]), "config first run: one audit row with the names and the new key (" + (rows.Count > 0 ? rows[0].Event + " " + rows[0].Detail : "none") + ")");
            JsonElement start = Start(run.Page);
            check(start.ValueKind == JsonValueKind.Object && start.GetProperty("flow").GetString() == "register" && start.GetProperty("options").GetProperty("rp").GetProperty("id").GetString() == "localhost", "config first run: the page creates a passkey for localhost");
            check(run.Page.Contains("data-setting=\"port\"", StringComparison.Ordinal) && run.Page.Contains("0 to 65535", StringComparison.Ordinal) && run.Policy.Contains("script-src 'sha256-", StringComparison.Ordinal), "config first run: the page has the form, the limits and the CSP");
        }

        // Three wrong codes, no code, cancel, a bad value, a registration over other values: nothing is stored.
        (string Name, string[] Typed, Func<HttpClient, ConfigRun, string, string> Act)[] refused =
        [
            ("three wrong codes", ["000000x", "111111x", "222222x"], (c, r, url) => Register(c, r, url, laptop, wanted)),
            ("no code (Ctrl+C)", [], (c, r, url) => Register(c, r, url, laptop, wanted)),
            ("a value outside its limits", [], (c, r, url) => Register(c, r, url, laptop, Canonical(10, "passkey", null, 0, 0))),
            ("a passkey without PRF", [], (c, r, url) => Register(c, r, url, noPrf, wanted)),
            ("a registration without the PRF payload", [], (c, r, url) => Register(c, r, url, laptop, wanted, null, null, false, null, PrfMode.Missing)),
            ("a garbled PRF payload", [], (c, r, url) => Register(c, r, url, laptop, wanted, null, null, false, null, PrfMode.Garbled)),
            ("a PRF payload sealed to another page", [], (c, r, url) => Register(c, r, url, laptop, wanted, null, null, false, null, PrfMode.WrongBind)),
            ("a PRF output of the wrong size", [], (c, r, url) => Register(c, r, url, laptop, wanted, null, null, false, null, PrfMode.ShortOutput)),
            ("a registration over other values", [], (c, r, url) => Register(c, r, url, laptop, Canonical(10, "passkey", null, 1, 5), wanted)),
            ("the manifest signed by another key", [], (c, r, url) => Register(c, r, url, laptop, wanted, null, stranger)),
            ("no manifest signature", [], (c, r, url) => Register(c, r, url, laptop, wanted, null, null, true)),
            ("a manifest signature but no code", [], (c, r, url) => Register(c, r, url, laptop, wanted)),
            ("cancel", [], (c, r, url) =>
            {
                Send(c, HttpMethod.Get, url)?.Dispose();
                Send(c, HttpMethod.Post, url + "/deny", "")?.Dispose();
                return "";
            }),
        ];
        foreach ((string name, string[] typed, Func<HttpClient, ConfigRun, string, string> act) in refused)
        {
            StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "first-bad-" + Guid.NewGuid().ToString("N")));
            Codes codes = new();
            ConfigRun run = await Drive(db, local, codes.Read, (r, url) =>
            {
                act(client, r, url);
                foreach (string code in typed)
                {
                    codes.Type(code);
                }

                if (typed.Length == 0)
                {
                    codes.Type(null);
                }
            });
            check(run.Result is { Code: RunCommand.Denied }, $"config first run: {name}: denied ({run.Result?.Code} {run.Result?.Detail})");
            check(Empty(db), $"config first run: {name}: nothing stored");
            SqliteConnection.ClearAllPools();
            check(!Directory.Exists(Path.GetDirectoryName(db.FilePath)!) || !Directory.EnumerateFiles(Path.GetDirectoryName(db.FilePath)!, "*", SearchOption.AllDirectories).Any(file => !Path.GetFileName(file).StartsWith(StateDatabase.FileName, StringComparison.Ordinal))
                && (!File.Exists(db.FilePath) || TestState.Current(db) is null), $"config first run: {name}: no store key, vault or key file is left");
        }

        // The name for the first passkey: a field on the page (default "passkey"), checked like the name field on the enroll page, in the signed
        // manifest and the Admins line. Empty means the default.
        foreach ((string sent, string stored) in new[] { ("work laptop", "work laptop"), ("  Büro  ", "Büro"), ("", Enrollment.DefaultName), ("   ", Enrollment.DefaultName) })
        {
            StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "first-name-" + Guid.NewGuid().ToString("N")));
            Codes codes = new();
            ConfigRun run = await Drive(db, local, codes.Read, (r, url) => codes.Type(Register(client, r, url, laptop, wanted, keyName: sent)));
            string line = "Admins: " + stored + " " + GrantTests.Expected(laptop);
            string signedName = Manifest.Parse(JsonDocument.Parse(run.First).RootElement.GetProperty("sign").GetProperty("manifest").GetString() ?? "", out _)?.Keys.Single().Name ?? "";
            check(run.Result is { Code: 0 } && new PasskeyStore(db).All().Single() is { Name: var name, Admin: true } && name == stored && signedName == stored && AdminKey.Line(db) == line
                && run.Reply.Contains(JsonSerializer.Serialize(line)[1..^1], StringComparison.Ordinal) && run.Result.Detail.Contains(line, StringComparison.Ordinal),
                $"config first run name: \"{sent}\" is stored as \"{stored}\", signed in the manifest and shown in the Admins line ({run.Result?.Detail})");
            check(run.Page.Contains("<label for=\"f-key-name\">Name for this passkey</label>", StringComparison.Ordinal) && run.Page.Contains("id=\"f-key-name\"", StringComparison.Ordinal)
                && run.Page.Contains("value=\"" + Enrollment.DefaultName + "\"", StringComparison.Ordinal) && run.Page.Contains("maxlength=\"" + Enrollment.MaxNameLength + "\"", StringComparison.Ordinal), "config first run name: the page has the name field with the default");
        }

        foreach (string bad in new[] { new string('a', Enrollment.MaxNameLength + 1), "a" + (char)1 + "b", "a\nb", "a" + (char)0x202E + "b", "a" + (char)0x200B + "b" })
        {
            StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "first-badname-" + Guid.NewGuid().ToString("N")));
            Codes codes = new();
            ConfigRun run = await Drive(db, local, codes.Read, (r, url) =>
            {
                Register(client, r, url, laptop, wanted, keyName: bad);
                codes.Type(null);
            });
            check(run.Result is { Code: RunCommand.Denied } && run.Status == 400 && Empty(db) && !run.First.Contains("\"sign\"", StringComparison.Ordinal), $"config first run name: a bad name (length {bad.Length}) is refused and nothing is stored ({run.Status} {run.Result?.Detail})");
        }

        // A good code, but a passkey was enrolled elsewhere meanwhile: nothing from this page is stored.
        {
            StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "first-race-" + Guid.NewGuid().ToString("N")));
            using TestAuthenticator other = TestAuthenticator.ES256();
            Codes codes = new();
            ConfigRun run = await Drive(db, local, codes.Read, (r, url) =>
            {
                string code = Register(client, r, url, laptop, wanted);
                new PasskeyStore(db).Add(other.Record("localhost", "other"));
                codes.Type(code);
            });
            check(run.Result is { Code: RunCommand.Denied } && ToolSettings.Load(db, out _) == ToolSettings.Defaults && new PasskeyStore(db).All().Select(item => item.Name).SequenceEqual(["other"]), "config first run: a key added meanwhile: nothing from the page is stored (" + run.Result?.Detail + ")");
        }

        // No way to read a code: nothing starts.
        {
            StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "first-nocode-" + Guid.NewGuid().ToString("N")));
            ConfigRun run = await Drive(db, local, null, (_, _) => { });
            check(run.Result is { Code: RunCommand.Denied } && run.Link is null && Empty(db), "config first run: without a code reader nothing starts");
        }
    }
}

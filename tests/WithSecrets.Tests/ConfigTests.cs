using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>Settings in with-secrets.db, the first-run setup page, and the --port option.</summary>
internal static class ConfigTests
{
    public const string ConfigPrefix = "To set up with-secrets, open this link: ";

    public static async Task Run(Action<bool, string> check)
    {
        string folder = Path.Combine(Path.GetTempPath(), "ws-config-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            Validation(check);
            RoundTrip(check, folder);
            Schema(check, folder);
            await FirstRun(check, folder);
            await PortOption(check, folder);
        }
        finally
        {
            Directory.Delete(folder, true);
        }
    }

    private static string Canonical(string? baseUrl, int port, int timeout, int reuseMax = 480)
    {
        return "{\"reuseMaxMinutes\":" + reuseMax + ",\"baseUrl\":" + (baseUrl is null ? "null" : "\"" + baseUrl + "\"")
            + ",\"port\":" + port + ",\"timeoutMinutes\":" + timeout + "}";
    }

    private static void Validation(Action<bool, string> check)
    {
        ToolSettings defaults = ToolSettings.Defaults;
        check(defaults == new ToolSettings(43200, null, 0, 15), "settings: the defaults");
        check(defaults.Canonical() == "{\"reuseMaxMinutes\":43200,\"baseUrl\":null,\"port\":0,\"timeoutMinutes\":15}", "settings: canonical JSON has a fixed key order (" + defaults.Canonical() + ")");
        check(new ToolSettings(480, "https://ws.example.com/a\"b\\c", 8765, 30).Canonical()
            == "{\"reuseMaxMinutes\":480,\"baseUrl\":\"https://ws.example.com/a\\\"b\\\\c\",\"port\":8765,\"timeoutMinutes\":30}", "settings: canonical JSON escapes quote and backslash");
        check(new ToolSettings(480, "https://b\u00fccher.example/\u00e9", 0, 5).Canonical().Contains("b\\u00fccher.example/\\u00e9", StringComparison.Ordinal), "settings: canonical JSON writes non-ASCII as lower-case \\u escapes");
        check(defaults.Approval == new ApprovalSettings(null, 0, TimeSpan.FromMinutes(15)) && defaults.Reuse == new ReuseOffer(43200), "settings: the approval and grant time views");

        (ToolSettings Value, bool Good, string Key)[] cases =
        [
            (defaults with { TimeoutMinutes = 0 }, false, "timeoutMinutes"),
            (defaults with { TimeoutMinutes = 1 }, true, ""),
            (defaults with { TimeoutMinutes = 30 }, true, ""),
            (defaults with { TimeoutMinutes = 31 }, false, "timeoutMinutes"),
            (defaults with { ReuseMaxMinutes = 9 }, false, "reuseMaxMinutes"),
            (defaults with { ReuseMaxMinutes = 10 }, true, ""),
            (defaults with { ReuseMaxMinutes = 1440 }, true, ""),
            (defaults with { ReuseMaxMinutes = 43200 }, true, ""),
            (defaults with { ReuseMaxMinutes = 43201 }, false, "reuseMaxMinutes"),
            (defaults with { Port = -1 }, false, "port"),
            (defaults with { Port = 65535 }, true, ""),
            (defaults with { Port = 65536 }, false, "port"),
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

        ToolSettings? parsed = ToolSettings.FromCanonical(Canonical("https://ws.example.com", 8765, 10), out string? error);
        check(parsed == new ToolSettings(480, "https://ws.example.com", 8765, 10) && error is null, "settings: canonical JSON parses back (" + error + ")");
        string[] refused =
        [
            "not json",
            "[]",
            "{\"baseUrl\":null,\"reuseMaxMinutes\":480,\"port\":0,\"timeoutMinutes\":5}",
            "{\"reuseMaxMinutes\":480,\"baseUrl\":null,\"port\":0}",
            "{\"reuseMaxMinutes\":480,\"baseUrl\":null,\"port\":0,\"timeoutMinutes\":5,\"extra\":1}",
            "{\"reuseMaxMinutes\":480,\"method\":\"passkey\",\"baseUrl\":null,\"port\":0,\"timeoutMinutes\":5}",
            "{\"reuseMinutes\":10,\"reuseMaxMinutes\":480,\"baseUrl\":null,\"port\":0,\"timeoutMinutes\":5}",
            "{\"reuseMaxMinutes\":480.0,\"baseUrl\":null,\"port\":0,\"timeoutMinutes\":5}",
            "{\"reuseMaxMinutes\":4.8e2,\"baseUrl\":null,\"port\":0,\"timeoutMinutes\":5}",
            "{\"reuseMaxMinutes\":\"480\",\"baseUrl\":null,\"port\":0,\"timeoutMinutes\":5}",
            "{ \"reuseMaxMinutes\":480,\"baseUrl\":null,\"port\":0,\"timeoutMinutes\":5}",
            Canonical(null, 0, 31),
            Canonical("https://u:p@ws.example.com", 0, 5),
            Canonical(null, 0, 5, 43201),
        ];
        foreach (string text in refused)
        {
            check(ToolSettings.FromCanonical(text, out string? why) is null && why is not null, "settings: not canonical or not valid is refused: " + text + " (" + why + ")");
        }

        IReadOnlyList<SettingChange> changes = defaults.Changes(defaults with { Port = 8765, BaseUrl = "https://ws.example.com" });
        check(changes.Count == 2 && changes[0] == new SettingChange("baseUrl", "none", "https://ws.example.com") && changes[1] == new SettingChange("port", "0", "8765"), "settings: changes in key order, none for no baseUrl");
        check(defaults.Changes(defaults).Count == 0, "settings: no change");
    }

    /// <summary>Changes one setting in the signed manifest (signed by the admin), as the admin web app does.</summary>
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
        check(ReuseSettings.Load(db) == new ReuseOffer(43200), "db settings: grant times from a missing database are the default");

        TestState.Seeded(db.FilePath);
        check(ToolSettings.Load(db, out error) == ToolSettings.Defaults && error is null, "db settings: the first manifest holds the defaults");
        Row(db, "reuseMaxMinutes", "600");
        Row(db, "baseUrl", "https://ws.example.com");
        Row(db, "port", "8765");
        Row(db, "timeoutMinutes", "12");
        check(ToolSettings.Load(db, out error) == new ToolSettings(600, "https://ws.example.com", 8765, 12) && error is null, "db settings: settings round trip through the signed manifest (" + error + ")");
        check(ApprovalSettings.Load(db, out error) == new ApprovalSettings("https://ws.example.com", 8765, TimeSpan.FromMinutes(12)) && error is null, "db settings: approval settings from the manifest");
        check(ReuseSettings.Load(db) == new ReuseOffer(600), "db settings: grant times from the manifest: the ceiling");
        check(!TestState.Settings(db, ToolSettings.Defaults with { TimeoutMinutes = 31 }) && ToolSettings.Load(db, out _).TimeoutMinutes == 12, "db settings: a manifest with a value out of its limits is never stored");

        // Settings edited by hand in with-secrets.db: verification fails, so the defaults and an error; reuse is off.
        ManifestTests.Execute(db.FilePath, "UPDATE manifest SET text = replace(text, '\"port\":8765', '\"port\":8766')");
        ToolSettings loaded = ToolSettings.Load(db, out string? why);
        check(loaded == ToolSettings.Defaults && why is not null && why.Contains("state failed verification", StringComparison.Ordinal), "db settings: an edited setting gives the defaults and a verification error (" + why + ")");
        check(ApprovalSettings.Load(db, out string? approvalError) == ToolSettings.Defaults.Approval && approvalError is not null, "db settings: edited: approval settings are the defaults with an error");
        check(ReuseSettings.Load(db) == ReuseOffer.Off, "db settings: edited: reuse is off");

        string garbage = Path.Combine(root, "garbage");
        Directory.CreateDirectory(garbage);
        File.WriteAllText(Path.Combine(garbage, "with-secrets.db"), "not a database");
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
        check(WithSecretsDatabase.SchemaVersion == 4, "db schema: the schema version is 4");
        check(!db.TryCheck(out string? error) && error is not null && error.Contains("delete with-secrets.db to start over", StringComparison.Ordinal), "db schema: an older database is an error that says to delete with-secrets.db (" + error + ")");
        check(!new PasskeyStore(db).TryAll(out _) && new PasskeyStore(db).All().Count == 0, "db schema: its passkeys are not used");
        check(ToolSettings.Load(db, out error) == ToolSettings.Defaults && error is not null && ReuseSettings.Load(db) == ReuseOffer.Off, "db schema: settings from it are an error");
        check(!new PasskeyStore(db).Add(new PasskeyRecord("k-new", "a2V5", -7, "localhost", "x", DateTimeOffset.UtcNow, 0)) && File.ReadAllBytes(path).AsSpan().SequenceEqual(before), "db schema: nothing is written to it");

        string newer = Path.Combine(root, "new-schema");
        StateDatabase newerDb = TestState.Seeded(Path.Combine(newer, WithSecretsDatabase.FileName));
        check(newerDb.TryCheck(out _), "db schema: a current database");
        using (SqliteConnection connection = new(new SqliteConnectionStringBuilder { DataSource = newerDb.FilePath, Pooling = false }.ToString()))
        {
            connection.Open();
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "UPDATE schema_version SET version = " + (WithSecretsDatabase.SchemaVersion + 1);
            command.ExecuteNonQuery();
        }

        check(!StateDatabase.InFolder(newer).TryCheck(out string? newerError) && newerError is not null && newerError.Contains("delete with-secrets.db to start over", StringComparison.Ordinal), "db schema: a newer database is an error too (" + newerError + ")");
        ManifestTests.Execute(newerDb.FilePath, "UPDATE schema_version SET version = " + (WithSecretsDatabase.SchemaVersion - 1));
        check(!StateDatabase.InFolder(newer).TryCheck(out string? fourError) && fourError is not null && fourError.Contains("delete with-secrets.db to start over", StringComparison.Ordinal), "db schema: a previous schema database is an error that says to delete with-secrets.db (" + fourError + ")");
    }

    /// <summary>An earlier store database with one passkey enrolled. Returns its path.</summary>
    private static string SchemaOne(string folder)
    {
        Directory.CreateDirectory(folder);
        string path = Path.Combine(folder, "with-secrets.db");
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

    private static FirstRunPage Page(StateDatabase db, ApprovalSettings settings, Action<string> announce, Func<string?>? readCode)
    {
        PasskeyStore passkeys = new(db);
        EnrollmentTarget Target(ApprovalSettings forPage)
        {
            PasskeyMethod method = new(passkeys, forPage, readCode);

            return EnrollmentTarget.For(method, new WebApprover(method, forPage, announce, TimeSpan.Zero));
        }

        return new FirstRunPage(db, Target(settings), Target(settings with { BaseUrl = null }), announce, readCode);
    }

    /// <summary>Runs the first-run setup on its own task. When the link is announced, <paramref name="act" /> plays the browser.</summary>
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
        check(CliArgs.Parse(["--port", "1", "--recover"], out _) is CliCommand.Recover { Port: 1 }, "port: --recover with --port 1");
        check(CliArgs.Parse(["--recover", "--port", "65535"], out _) is CliCommand.Recover { Port: 65535 }, "port: --recover with --port 65535");
        check(CliArgs.Parse(["--secrets", "A", "--reason", "r", "--port", "9000", "--", "p", "--port", "1"], out _) is CliCommand.Run { Port: 9000, Args.Program: "p" } run1 && run1.Args.Arguments.SequenceEqual(["--port", "1"]), "port: a run with --port; the program keeps its own --port");
        check(CliArgs.Parse(["--recover"], out _) is CliCommand.Recover { Port: null }, "port: none given is null");
        foreach (string bad in new[] { "0", "65536", "-1", "abc", "", "80x", "1.5", "99999999999" })
        {
            check(CliArgs.Parse(["--recover", "--port", bad], out string message) is null && message.Contains("--port", StringComparison.Ordinal) && message.Contains("65535", StringComparison.Ordinal), "port: '" + bad + "' is refused (" + message + ")");
        }

        check(CliArgs.Parse(["--needs", "--port", "9000"], out _) is null, "port: commands that open no page refuse --port");
        check(CliArgs.Parse(["--help"], out _) is CliCommand.Help { Text: var help } && help.Contains("--port", StringComparison.Ordinal) && help.Contains("ssh -L", StringComparison.Ordinal), "port: --help describes --port");

        // The override replaces the setting; null keeps it.
        ApprovalSettings set = new("https://ws.example.com", 5555, TimeSpan.FromSeconds(20));
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
            StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "port-empty-" + Guid.NewGuid().ToString("N")));
            int wanted = FreePort();
            ApprovalSettings stored = new(null, 5555, TimeSpan.FromSeconds(20));
            ConfigRun run = await Drive(db, stored.WithPort(wanted), () => null, (r, url) =>
            {
                Send(client, HttpMethod.Get, url)?.Dispose();
                Send(client, HttpMethod.Post, url + "/deny", "")?.Dispose();
            });
            check(stored.Port == 5555 && run.Link?.Port == wanted, "port: the override wins over the port setting (" + run.Link + ")");
            check(Empty(db), "port: the override stores nothing");
        }

        // A port in use: one clear line, no link, and no fallback to another port.
        {
            StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "port-taken-" + Guid.NewGuid().ToString("N")));
            int taken = FreePort();
            System.Net.Sockets.TcpListener holder = new(IPAddress.Loopback, taken);
            holder.Start();
            try
            {
                ConfigRun run = await Drive(db, new ApprovalSettings(null, 0, TimeSpan.FromSeconds(20)).WithPort(taken), (() => "0"), (_, _) => { });
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
    }

    private static async Task FirstRun(Action<bool, string> check, string root)
    {
        using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
        client.Timeout = TimeSpan.FromSeconds(20);
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator stranger = TestAuthenticator.ES256();
        using TestAuthenticator noPrf = TestAuthenticator.ES256(prf: false);
        ApprovalSettings local = new(null, 0, TimeSpan.FromSeconds(20));
        string wanted = ToolSettings.Defaults.Canonical();

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
            check(run.Result is { Code: 0 }, "first-run setup: done (" + run.Result?.Detail + ")");
            check(run.EmptyBeforeCode, "first-run setup: nothing is in with-secrets.db before the code is typed");
            check(run.Status == 200 && System.Text.RegularExpressions.Regex.IsMatch(run.Reply, "\"code\":\"[0-9]{6}\""), "first-run setup: the page gets a six-digit code (" + run.Reply + ")");
            check(!run.Lines.Any(line => System.Text.RegularExpressions.Regex.IsMatch(line, "(?<![0-9])[0-9]{6}(?![0-9])") && !line.StartsWith(ConfigPrefix, StringComparison.Ordinal)), "first-run setup: the code is never announced");
            check(run.Lines.Count == 1 && run.Lines[0].StartsWith(ConfigPrefix + "http://localhost:", StringComparison.Ordinal), "first-run setup: the terminal gets only the link (" + string.Join(" | ", run.Lines) + ")");
            check(ToolSettings.Load(db, out _) == ToolSettings.Defaults, "first-run setup: the default settings are stored");
            IReadOnlyList<PasskeyRecord> keys = new PasskeyStore(db).All();
            check(keys.Count == 1 && keys[0].RpId == "localhost" && keys[0].Name == "passkey" && keys[0].Admin && keys[0].Id == TestAuthenticator.Encode(laptop.CredentialId), "first-run setup: the passkey is stored for localhost, as the admin");
            check(Version(db) == 1 && db.TryCheck(out _), "first-run setup: the first manifest (version 1) verifies");
            {
                // The first key's slot: its salt is the one the page asked the passkey for, and the PRF output opens the master key
                // that nothing else in the state holds. The same first manifest has the store public key and the vault (the store's
                // private key under that master key), so the first --set needs no PRF.
                Manifest? first = TestState.Current(db);
                using Unlock? released = TestVault.Unlock(db, laptop);
                byte[]? master = null;
                byte[]? privateKey = null;
                byte[]? reviewKey = null;
                try
                {
                    master = first is not null && released is not null ? KeyVault.OpenMaster(first, released) : null;
                    check(keys[0].Slot is not null && master is { Length: 32 }, "first-run setup: the first key has a key slot that its PRF output opens");
                    check(first is { Version: 1, Secrets.Count: 0 } && JweCipher.IsPublicKey(first.Store) && KeyVault.IsVault(first.Vault), "first-run setup: the first manifest has the store public key and the vault (and no secrets)");
                    privateKey = first is not null && master is not null ? KeyVault.UnwrapVault(first.Vault, master, first.Store) : null;
                    string privateHex = privateKey is null ? "" : Encoding.UTF8.GetString(privateKey);
                    check(JweCipher.Instance.Derive(privateHex) == first!.Store, "first-run setup: the vault holds the private key of the stored public key, and the passkey's PRF output opens it");
                    SqliteConnection.ClearAllPools();
                    string stateFolder = Path.GetDirectoryName(db.FilePath)!;
                    bool leaked = privateKey is null || WebApprovalTests.FolderHolds(stateFolder, privateKey) || WebApprovalTests.FolderHolds(stateFolder, Encoding.UTF8.GetBytes(privateHex.ToUpperInvariant()))
                        || WebApprovalTests.FolderHolds(stateFolder, System.Buffers.Text.Base64Url.DecodeFromChars(privateHex)) || WebApprovalTests.FolderHolds(stateFolder, Encoding.ASCII.GetBytes(Convert.ToBase64String(System.Buffers.Text.Base64Url.DecodeFromChars(privateHex))));
                    check(!leaked, "first-run setup: the store private key (hex, upper hex, raw, base64) is in no file of the store folder: not with-secrets.db, its WAL or anything else");
                    check(!WebApprovalTests.FolderHolds(stateFolder, master!), "first-run setup: the master key is in no file either");
                    check(!Directory.EnumerateFiles(stateFolder, ".env*", SearchOption.AllDirectories).Any(), "first-run setup: no .env.keys or other key file");
                    string seen = StateDatabaseTests.AuditText(db.FilePath) + run.Reply + run.First + string.Join("|", run.Lines) + run.Result!.Detail + run.Page;
                    check(!seen.Contains(privateHex, StringComparison.OrdinalIgnoreCase), "first-run setup: the store private key is in no reply, page, audit entry or message");
                    if (first?.Review is { } review && master is not null)
                    {
                        reviewKey = KeyVault.UnwrapReview(review.Vault, master, review.PublicKey);
                        check(review.PublicKey != first.Store && JweCipher.Instance.Derive(Encoding.UTF8.GetString(reviewKey)) == review.PublicKey
                            && !WebApprovalTests.FolderHolds(stateFolder, reviewKey) && !seen.Contains(Encoding.UTF8.GetString(reviewKey), StringComparison.OrdinalIgnoreCase),
                            "first-run setup: the independently generated review key is wrapped and its private part stays out of files and output");
                    }
                    else
                    {
                        check(false, "first-run setup: the review key is present with the store key");
                    }
                    check(run.Page.Contains("prf", StringComparison.Ordinal) && run.Page.Contains("PRF", StringComparison.Ordinal), "first-run setup: the page asks for a PRF passkey");
                }
                finally
                {
                    SecretValues.Clear(master);
                    SecretValues.Clear(privateKey);
                    SecretValues.Clear(reviewKey);
                }

                string everything = StateDatabaseTests.AuditText(db.FilePath) + run.Reply + run.First + string.Join("|", run.Lines) + run.Result!.Detail;
                check(!everything.Contains(Convert.ToHexStringLower(laptop.PrfSecret), StringComparison.Ordinal) && !File.ReadAllText(db.FilePath, System.Text.Encoding.Latin1).Contains(Convert.ToBase64String(laptop.PrfSecret), StringComparison.Ordinal), "first-run setup: the PRF secret is in no reply, audit entry or message");
            }

            string fingerprint = "Admins: passkey " + GrantTests.Expected(laptop);
            check(!run.Page.Contains("Admins:", StringComparison.Ordinal), "first-run setup: the page has no admin line before there is an admin");
            check(run.Reply.Contains("\"admin\":\"" + fingerprint + "\"", StringComparison.Ordinal), "first-run setup: the code reply shows the new admin key's fingerprint (" + run.Reply + ")");
            check(run.Result!.Detail.Contains(fingerprint, StringComparison.Ordinal) && run.Result.Detail.Contains("Note the fingerprint", StringComparison.Ordinal), "first-run setup: the terminal shows the fingerprint to note down (" + run.Result.Detail + ")");
            using (JsonDocument step = JsonDocument.Parse(run.First))
            {
                JsonElement sign = step.RootElement.GetProperty("sign");
                Manifest? first = Manifest.Parse(sign.GetProperty("manifest").GetString()!, out _);
                check(first is { Version: 1 } && JweCipher.IsPublicKey(first.Store) && KeyVault.IsVault(first.Vault) && first.Settings == ToolSettings.Defaults && first.Admins.Single().Id == TestAuthenticator.Encode(laptop.CredentialId) && sign.GetProperty("first").GetBoolean()
                    && !sign.TryGetProperty("allowCredentials", out _), "first-run setup: after the registration the new key is asked to sign the first manifest, with it as admin (" + run.First + ")");
            }

            string script = run.Page[(run.Page.LastIndexOf("<script>", StringComparison.Ordinal) + 8)..];
            check(script.Contains("post(\"sign\"", StringComparison.Ordinal) && script.Contains("navigator.credentials.get", StringComparison.Ordinal) && script.Contains("navigator.credentials.create", StringComparison.Ordinal), "first-run setup: the page script has the second prompt (get, then post sign)");
            check(TestAudit.TryRead(db, 5, null, out IReadOnlyList<AuditRow> rows, out _) && rows.Count == 1 && rows[0].Event == "setup" && rows[0].KeyName == "passkey"
                && rows[0].Secrets.Count == 0, "first-run setup: one audit row with the names and the new key (" + (rows.Count > 0 ? rows[0].Event + " " + rows[0].Detail : "none") + ")");
            JsonElement start = Start(run.Page);
            check(start.ValueKind == JsonValueKind.Object && start.GetProperty("settings").GetString() == wanted && start.GetProperty("options").GetProperty("rp").GetProperty("id").GetString() == "localhost", "first-run setup: the page creates a passkey for localhost");
            check(run.Policy.Contains("script-src 'sha256-", StringComparison.Ordinal), "first-run setup: the page has the form, the limits and the CSP");
        }

        // Three wrong codes, no code, cancel, a bad value, a registration over other values: nothing is stored.
        (string Name, string[] Typed, Func<HttpClient, ConfigRun, string, string> Act)[] refused =
        [
            ("three wrong codes", ["000000x", "111111x", "222222x"], (c, r, url) => Register(c, r, url, laptop, wanted)),
            ("no code (Ctrl+C)", [], (c, r, url) => Register(c, r, url, laptop, wanted)),
            ("a passkey without PRF", [], (c, r, url) => Register(c, r, url, noPrf, wanted)),
            ("a registration without the PRF payload", [], (c, r, url) => Register(c, r, url, laptop, wanted, null, null, false, null, PrfMode.Missing)),
            ("a garbled PRF payload", [], (c, r, url) => Register(c, r, url, laptop, wanted, null, null, false, null, PrfMode.Garbled)),
            ("a PRF payload sealed to another page", [], (c, r, url) => Register(c, r, url, laptop, wanted, null, null, false, null, PrfMode.WrongBind)),
            ("a PRF output of the wrong size", [], (c, r, url) => Register(c, r, url, laptop, wanted, null, null, false, null, PrfMode.ShortOutput)),
            ("a registration over other settings", [], (c, r, url) => Register(c, r, url, laptop, Canonical(null, 1, 5), wanted)),
            ("settings other than the defaults", [], (c, r, url) => Register(c, r, url, laptop, Canonical(null, 1, 5))),
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
            check(run.Result is { Code: RunCommand.Denied }, $"first-run setup: {name}: denied ({run.Result?.Code} {run.Result?.Detail})");
            check(Empty(db), $"first-run setup: {name}: nothing stored");
            SqliteConnection.ClearAllPools();
            check(!Directory.Exists(Path.GetDirectoryName(db.FilePath)!) || !Directory.EnumerateFiles(Path.GetDirectoryName(db.FilePath)!, "*", SearchOption.AllDirectories).Any(file => !Path.GetFileName(file).StartsWith(WithSecretsDatabase.FileName, StringComparison.Ordinal))
                && (!File.Exists(db.FilePath) || TestState.Current(db) is null), $"first-run setup: {name}: no store key, vault or key file is left");
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
                $"first-run setup name: \"{sent}\" is stored as \"{stored}\", signed in the manifest and shown in the Admins line ({run.Result?.Detail})");
            check(run.Page.Contains("<label for=\"f-key-name\">Passkey name</label>", StringComparison.Ordinal) && run.Page.Contains("id=\"f-key-name\"", StringComparison.Ordinal)
                && run.Page.Contains("value=\"" + Enrollment.DefaultName + "\"", StringComparison.Ordinal) && run.Page.Contains("maxlength=\"" + Enrollment.MaxNameLength + "\"", StringComparison.Ordinal), "first-run setup name: the page has the name field with the default");
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
            check(run.Result is { Code: RunCommand.Denied } && run.Status == 400 && Empty(db) && !run.First.Contains("\"sign\"", StringComparison.Ordinal), $"first-run setup name: a bad name (length {bad.Length}) is refused and nothing is stored ({run.Status} {run.Result?.Detail})");
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
            check(run.Result is { Code: RunCommand.Denied } && ToolSettings.Load(db, out _) == ToolSettings.Defaults && new PasskeyStore(db).All().Select(item => item.Name).SequenceEqual(["other"]), "first-run setup: a key added meanwhile: nothing from the page is stored (" + run.Result?.Detail + ")");
        }

        // No way to read a code: nothing starts.
        {
            StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "first-nocode-" + Guid.NewGuid().ToString("N")));
            ConfigRun run = await Drive(db, local, null, (_, _) => { });
            check(run.Result is { Code: RunCommand.Denied } && run.Link is null && Empty(db), "first-run setup: without a code reader nothing starts");
        }
    }
}

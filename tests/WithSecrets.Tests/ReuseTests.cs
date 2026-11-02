using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>
/// Per-approval reuse: the page offers "Approve once" and "Approve for..." (a fixed list cut at the ceiling), the chosen time is
/// bound into the passkey challenge, the server accepts only an offered time, and a grant lasts exactly the signed time.
/// </summary>
internal static class ReuseTests
{
    private const string AnnouncePrefix = "Approval needed. Ask the person to open: ";
    private const string Secret = "Reuse-Secret-9182";

    private static int _signs;

    public static async Task Run(Action<bool, string> check)
    {
        string folder = Path.Combine(Path.GetTempPath(), "ws-reuse-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            Binding(check);
            Offers(check);
            Grants(check, folder);
            Page(check);
            using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
            client.Timeout = TimeSpan.FromSeconds(20);
            await Server(check, client, folder);
            await Chain(check, client, folder);
        }
        finally
        {
            Directory.Delete(folder, true);
        }
    }

    /// <summary>The body the page posts: the chosen minutes and the assertion.</summary>
    public static string Body(int minutes, string assertion) => "{\"reuse\":" + minutes + ",\"proof\":" + assertion + "}";

    private static void Binding(Action<bool, string> check)
    {
        byte[] bind = RandomNumberGenerator.GetBytes(32);
        byte[] once = ReuseBinding.Challenge(bind, 0);
        byte[] ten = ReuseBinding.Challenge(bind, 10);
        check(once.AsSpan().SequenceEqual(SHA256.HashData([.. bind, .. Encoding.ASCII.GetBytes("reuse=0")])), "reuse binding: SHA-256(bind || \"reuse=0\") for once");
        check(ten.AsSpan().SequenceEqual(SHA256.HashData([.. bind, .. Encoding.ASCII.GetBytes("reuse=10")])), "reuse binding: SHA-256(bind || \"reuse=10\") for 10 minutes");
        check(!once.AsSpan().SequenceEqual(ten) && !once.AsSpan().SequenceEqual(bind), "reuse binding: once and 10 minutes differ, and neither is the bare bind");
    }

    private static void Offers(Action<bool, string> check)
    {
        check(ReuseOffer.Steps.SequenceEqual([10, 60, 240, 480]), "reuse offer: the steps are 10 min, 1 h, 4 h, 8 h");
        check(new ReuseOffer(480, 10).Choices.SequenceEqual([10, 60, 240, 480]), "reuse offer: a ceiling of 480 offers every step");
        check(new ReuseOffer(1440, 10).Choices.SequenceEqual([10, 60, 240, 480]), "reuse offer: a ceiling of 1440 offers every step");
        check(new ReuseOffer(100, 10).Choices.SequenceEqual([10, 60]), "reuse offer: a ceiling of 100 offers only the steps up to it");
        check(new ReuseOffer(10, 10).Choices.SequenceEqual([10]), "reuse offer: a ceiling of 10 offers only 10 minutes");
        check(!ReuseOffer.Off.IsOn && ReuseOffer.Off.Choices.Count == 0 && new ReuseOffer(480, 0).IsOn, "reuse offer: off offers nothing; a start of 0 is still on");
        check(new ReuseOffer(480, 10).Preselected == 10 && new ReuseOffer(480, 30).Preselected == 10 && new ReuseOffer(480, 300).Preselected == 240 && new ReuseOffer(480, 480).Preselected == 480, "reuse offer: the start snaps to the nearest step at or below it");
        check(new ReuseOffer(480, 0).Preselected is null && new ReuseOffer(480, 5).Preselected is null, "reuse offer: a start of 0 (or below the first step) preselects nothing");
        check(new ReuseOffer(100, 100).Preselected == 60, "reuse offer: the start never goes past the ceiling");
        ReuseOffer offer = new(100, 10);
        check(offer.Allows(0) && offer.Allows(10) && offer.Allows(60), "reuse offer: once and every offered step are allowed");
        check(!offer.Allows(7) && !offer.Allows(-1) && !offer.Allows(99999) && !offer.Allows(240) && !offer.Allows(480), "reuse offer: a time not offered or above the ceiling is not allowed");
        check(ReuseOffer.Off.Allows(0) && !ReuseOffer.Off.Allows(10), "reuse offer: with reuse off only once is allowed");
    }

    private static void Grants(Action<bool, string> check, string root)
    {
        DateTimeOffset clock = new(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);
        StateDatabase db = TestState.Seeded(Path.Combine(root, "grants", StateDatabase.FileName));
        GrantStore grants = new(db, () => clock);
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        check(TestState.Add(db, laptop.Record("localhost", "laptop")), "reuse grants: a second key is enrolled");
        check(grants.Add("K", 240, "laptop"), "reuse grants: a 240-minute grant is saved");
        check(grants.TryGet("K", 480, out _, out DateTimeOffset ends) && ends == clock.AddMinutes(240), "reuse grants: honoured under a ceiling of 480, ends at +240 min");
        check(!grants.TryGet("K", 60, out _, out _), "reuse grants: a grant longer than the current ceiling is not honoured");
        GrantEntry entry = grants.Entries().Single();
        check(entry.Minutes == 240 && entry.KeyName == "laptop" && entry.Expires - entry.Approved == TimeSpan.FromMinutes(240), "reuse grants: the grant stores its minutes and the key name");
        check(!grants.Add("X", ReuseSettings.MaxMinutes + 1) && !grants.Add("Y", -1), "reuse grants: a lifetime outside 1..1440 minutes is refused");

        // A row whose times do not match its minutes (edited by hand) is not honoured.
        using (SqliteConnection connection = new(new SqliteConnectionStringBuilder { DataSource = db.FilePath, Pooling = false }.ToString()))
        {
            connection.Open();
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "UPDATE grants SET minutes = 10 WHERE key = 'K'";
            command.ExecuteNonQuery();
        }

        check(!grants.TryGet("K", 480, out _, out _), "reuse grants: a row whose minutes do not match its times is not honoured");
        check(StateDatabase.SchemaVersion == 7, "reuse grants: the schema version is 7");
    }

    private static ApprovalRequest Request(ReuseOffer? offer) => new("tool", "/bin/tool", ["--x"], "/work", "testing", ["API_KEY"], offer);

    private static string Built(ReuseOffer? offer)
    {
        return ApprovalPage.Build(new ApprovalPrompt("h", ApprovalSummary.BuildMessage(Request(offer))), new ProofStart("webauthn", "{}"), "n", [1, 2, 3], TimeSpan.FromSeconds(2), offer).Body;
    }

    private static string[] Options(string page) => [.. Regex.Matches(page, "<option value=\"([0-9]+)\"").Select(match => match.Groups[1].Value)];

    private static void Page(Action<bool, string> check)
    {
        string page = Built(new ReuseOffer(480, 10));
        check(page.Contains("<button id=\"approve\" type=\"button\" disabled data-delay=\"2000\">Approve once</button>", StringComparison.Ordinal), "reuse page: Approve once is its own button, off for the start delay");
        check(page.Contains("<select id=\"reuse\" disabled>", StringComparison.Ordinal) && page.Contains("<button id=\"approve-for\" type=\"button\" disabled>Approve for selected time</button>", StringComparison.Ordinal), "reuse page: a duration select and an Approve for button, both off at first");
        check(Options(page).SequenceEqual(["10", "60", "240", "480"]), "reuse page: the select offers 10, 60, 240, 480 minutes (" + string.Join(",", Options(page)) + ")");
        check(page.Contains("<option value=\"10\" selected>10 minutes</option>", StringComparison.Ordinal) && page.Contains("<option value=\"480\">8 hours</option>", StringComparison.Ordinal), "reuse page: reuseMinutes picks the starting entry; entries have readable names");
        check(page.IndexOf("id=\"deny\"", StringComparison.Ordinal) < page.IndexOf("id=\"approve\"", StringComparison.Ordinal) && page.IndexOf("id=\"approve\"", StringComparison.Ordinal) < page.IndexOf("id=\"reuse\"", StringComparison.Ordinal), "reuse page: Deny, then Approve once, then the duration control");
        check(page.IndexOf("id=\"request\"", StringComparison.Ordinal) < page.IndexOf("id=\"approve\"", StringComparison.Ordinal), "reuse page: the command is shown before the controls");
        check(page.Contains("whatever the other arguments", StringComparison.Ordinal) && page.Contains("without asking", StringComparison.Ordinal), "reuse page: says what a saved approval covers and that the agent can run it again without asking");
        check(page.Contains("Ctrl+Enter", StringComparison.Ordinal), "reuse page: shows the Ctrl+Enter hint");

        string capped = Built(new ReuseOffer(100, 10));
        check(Options(capped).SequenceEqual(["10", "60"]), "reuse page: a ceiling of 100 offers only 10 and 60 (" + string.Join(",", Options(capped)) + ")");
        string unset = Built(new ReuseOffer(480, 0));
        check(Options(unset).SequenceEqual(["10", "60", "240", "480"]) && !Regex.IsMatch(unset, "<option value=\"[0-9]+\" selected") && unset.Contains("<option value=\"\" selected disabled>", StringComparison.Ordinal), "reuse page: reuseMinutes 0 preselects no time, and the select is still there");
        string snapped = Built(new ReuseOffer(480, 300));
        check(snapped.Contains("<option value=\"240\" selected>4 hours</option>", StringComparison.Ordinal), "reuse page: 300 minutes starts on 4 hours");

        foreach ((string name, string off) in new[] { ("no offer", Built(null)), ("reuse off", Built(ReuseOffer.Off)) })
        {
            check(off.Contains(">Approve once</button>", StringComparison.Ordinal) && !off.Contains("id=\"reuse\"", StringComparison.Ordinal) && !off.Contains("id=\"approve-for\"", StringComparison.Ordinal) && Options(off).Length == 0, "reuse page: " + name + " shows only Approve once");
        }

        // The script: Ctrl+Enter (Cmd+Enter) is Approve once, the challenge is SHA-256(bind || "reuse=" || minutes).
        string script = Between(page, "<script>", "</script>");
        check(script.Contains("event.key === \"Enter\"", StringComparison.Ordinal) && script.Contains("event.ctrlKey || event.metaKey", StringComparison.Ordinal), "reuse page: the script handles Ctrl+Enter and Cmd+Enter");
        check(script.Contains("approveWith(0)", StringComparison.Ordinal), "reuse page: the shortcut approves once (0 minutes)");
        check(script.Contains("\"reuse=\" + minutes", StringComparison.Ordinal) && script.Contains("crypto.subtle.digest(\"SHA-256\"", StringComparison.Ordinal), "reuse page: the script binds the minutes into the challenge");
        check(!Regex.IsMatch(page, "\\son[a-z]+=", RegexOptions.IgnoreCase), "reuse page: no inline event attributes");
        OneShotResponse response = ApprovalPage.Build(new ApprovalPrompt("h", "t"), new ProofStart("webauthn", "{}"), "n", [1], TimeSpan.Zero, new ReuseOffer(480, 10));
        string served = Between(response.Body, "<script>", "</script>");
        check((response.ContentSecurityPolicy ?? "").Contains("script-src " + ApprovalPage.Hash(served) + ";", StringComparison.Ordinal) && !served.Contains('\r'), "reuse page: the CSP hash is of the LF script as served");

        string text = ApprovalSummary.BuildMessage(Request(new ReuseOffer(100, 10)));
        check(text.Contains("up to 60 min", StringComparison.Ordinal) && text.Contains("whatever the other arguments", StringComparison.Ordinal), "reuse text: the request text says the longest time offered and what it covers");
        check(!ApprovalSummary.BuildMessage(Request(null)).Contains("whatever the other arguments", StringComparison.Ordinal), "reuse text: no reuse line when reuse is off");
    }

    /// <summary>
    /// Runs WebApprover.Request with a passkey; <paramref name="body" /> gets the page's bind and origin and returns what to
    /// post to /proof. Returns the decision, the status of the post and the page.
    /// </summary>
    private static async Task<(ApprovalDecision? Decision, int Status, string Page)> Ask(HttpClient client, PasskeyStore store, ReuseOffer? offer, Func<byte[], string, string> body)
    {
        TaskCompletionSource<string> line = new(TaskCreationOptions.RunContinuationsAsynchronously);
        ApprovalSettings settings = new("passkey", null, 0, TimeSpan.FromSeconds(20));
        WebApprover approver = new(new PasskeyMethod(store, settings), settings, text => line.TrySetResult(text), TimeSpan.Zero);
        Task<ApprovalDecision> ask = Task.Run(() => approver.Request(Request(offer)));
        Task first = await Task.WhenAny(line.Task, ask, Task.Delay(TimeSpan.FromSeconds(20)));
        if (first != line.Task)
        {
            return (first == ask ? ask.Result : null, 0, "");
        }

        Uri link = new(line.Task.Result[AnnouncePrefix.Length..]);
        string url = "http://127.0.0.1:" + link.Port + link.AbsolutePath;
        string page = Text(Send(client, HttpMethod.Get, url));
        byte[] bind = Base64Url.DecodeFromChars(JsonSerializer.Deserialize<Dictionary<string, string>>(Between(page, "<script type=\"application/json\" id=\"start\">", "</script>"))!["bind"]);
        using HttpResponseMessage? posted = Send(client, HttpMethod.Post, url + "/proof", body(bind, "http://localhost:" + link.Port));
        Task done = await Task.WhenAny(ask, Task.Delay(TimeSpan.FromSeconds(20)));

        return (done == ask ? ask.Result : null, (int?)posted?.StatusCode ?? 0, page);
    }

    private static uint Next() => (uint)Interlocked.Increment(ref _signs);

    private static async Task Server(Action<bool, string> check, HttpClient client, string root)
    {
        using TestAuthenticator key = TestAuthenticator.ES256();
        PasskeyStore store = new(StateDatabase.InFolder(Path.Combine(root, "server")));
        check(store.Add(key.Record("localhost", "laptop")), "reuse server: key stored");
        ReuseOffer offer = new(100, 10);

        string Sign(byte[] bind, string origin, int minutes) => key.Assert(ReuseBinding.Challenge(bind, minutes), origin, "localhost", Next());

        (ApprovalDecision? decision, int status, _) = await Ask(client, store, offer, (bind, origin) => Body(0, Sign(bind, origin, 0)));
        check(status == 200 && decision is { Approved: true, ReuseMinutes: 0 }, "reuse server: once, signed for once, approves with 0 minutes (" + decision?.Detail + ")");
        (decision, status, _) = await Ask(client, store, offer, (bind, origin) => Body(10, Sign(bind, origin, 10)));
        check(status == 200 && decision is { Approved: true, ReuseMinutes: 10 } && decision.Detail.Contains("passkey laptop verified", StringComparison.Ordinal), "reuse server: 10 minutes, signed for 10, approves with 10 minutes (" + decision?.Detail + ")");
        (decision, status, _) = await Ask(client, store, offer, (bind, origin) => Body(60, Sign(bind, origin, 60)));
        check(status == 200 && decision is { Approved: true, ReuseMinutes: 60 }, "reuse server: 60 minutes under a ceiling of 100 approves (" + decision?.Detail + ")");

        (decision, status, _) = await Ask(client, store, offer, (bind, origin) => Body(10, Sign(bind, origin, 0)));
        check(status == 403 && decision is { Approved: false, ReuseMinutes: 0 }, "reuse server: a signature made for once, sent as 10 minutes, denies (" + decision?.Detail + ")");
        (decision, status, _) = await Ask(client, store, offer, (bind, origin) => Body(0, Sign(bind, origin, 10)));
        check(status == 403 && decision is { Approved: false }, "reuse server: a signature made for 10 minutes, sent as once, denies (" + decision?.Detail + ")");
        (decision, status, _) = await Ask(client, store, offer, (bind, origin) => Body(0, key.Assert(bind, origin, "localhost", Next())));
        check(status == 403 && decision is { Approved: false }, "reuse server: a signature over the bare bind denies (" + decision?.Detail + ")");

        foreach (int minutes in new[] { 7, -1, 99999, 240, 480, 1440 })
        {
            (decision, status, _) = await Ask(client, store, offer, (bind, origin) => Body(minutes, Sign(bind, origin, minutes)));
            check(status == 400 && decision is { Approved: false, ReuseMinutes: 0 } && decision.Detail.Contains("not offered", StringComparison.Ordinal), $"reuse server: {minutes} minutes (not offered or above the ceiling of 100), even signed, denies ({decision?.Detail})");
        }

        (decision, status, _) = await Ask(client, store, null, (bind, origin) => Body(10, Sign(bind, origin, 10)));
        check(status == 400 && decision is { Approved: false }, "reuse server: 10 minutes when reuse is off denies (" + decision?.Detail + ")");
        (decision, status, _) = await Ask(client, store, null, (bind, origin) => Body(0, Sign(bind, origin, 0)));
        check(status == 200 && decision is { Approved: true, ReuseMinutes: 0 }, "reuse server: once when reuse is off approves (" + decision?.Detail + ")");

        Func<byte[], string, string>[] malformed =
        [
            (bind, origin) => "{\"reuse\":\"10\",\"proof\":" + Sign(bind, origin, 10) + "}",
            (bind, origin) => "{\"reuse\":\"abc\",\"proof\":" + Sign(bind, origin, 0) + "}",
            (bind, origin) => "{\"reuse\":10.0,\"proof\":" + Sign(bind, origin, 10) + "}",
            (bind, origin) => "{\"reuse\":1e1,\"proof\":" + Sign(bind, origin, 10) + "}",
            (bind, origin) => "{\"reuse\":null,\"proof\":" + Sign(bind, origin, 0) + "}",
            (bind, origin) => "{\"reuse\":99999999999,\"proof\":" + Sign(bind, origin, 0) + "}",
            (bind, origin) => "{\"reuse\":-0,\"proof\":" + Sign(bind, origin, 0) + "}",
            (bind, origin) => "{\"reuse\":010,\"proof\":" + Sign(bind, origin, 10) + "}",
            (bind, origin) => "{\"proof\":" + Sign(bind, origin, 0) + "}",
            (bind, origin) => "{\"reuse\":0,\"reuse\":10,\"proof\":" + Sign(bind, origin, 10) + "}",
            (bind, origin) => "{\"reuse\":0,\"proof\":" + Sign(bind, origin, 0) + ",\"extra\":1}",
            (bind, origin) => "{\"reuse\":0,\"proof\":" + JsonSerializer.Serialize(Sign(bind, origin, 0)) + "}",
            (bind, origin) => Sign(bind, origin, 0),
            (_, _) => "not json",
        ];
        foreach ((Func<byte[], string, string> body, int index) in malformed.Select((body, index) => (body, index)))
        {
            (decision, status, _) = await Ask(client, store, offer, body);
            check(status == 400 && decision is { Approved: false, ReuseMinutes: 0 }, $"reuse server: malformed body {index} (non-numeric, int32 overflow, -0, leading zero, missing or repeated minutes, extra member, bare assertion) denies and grants nothing ({status}; {decision?.Detail})");
        }
    }

    /// <summary>
    /// RunCommand with the real WebApprover and PasskeyMethod, saved approvals in state.db and a real child process.
    /// <paramref name="minutes" /> is the time chosen on the page, or null to answer nothing (no page is expected).
    /// </summary>
    private static async Task<(int Code, string Out, string Err, int Announced)> Drive(HttpClient client, StateDatabase db, string folder, string program, TestAuthenticator key, GrantStore grants, ReuseOffer? offer, int? minutes, int? sendAs = null)
    {
        TaskCompletionSource<string> link = new(TaskCreationOptions.RunContinuationsAsynchronously);
        StringWriter stdout = new();
        StringWriter stderr = new();
        TextWriter errors = TextWriter.Synchronized(stderr);
        int announced = 0;
        ApprovalSettings settings = new("passkey", null, 0, TimeSpan.FromSeconds(minutes is null ? 2 : 20));
        WebApprover approver = new(new PasskeyMethod(new PasskeyStore(db), settings), settings, line =>
        {
            Interlocked.Increment(ref announced);
            errors.WriteLine(line);
            link.TrySetResult(line);
        }, TimeSpan.Zero);
        RunCommand run = new(new MemoryStore(new Dictionary<string, string> { ["MY_SECRET"] = Secret }), approver, new AuditLog(db), TextWriter.Synchronized(stdout), errors, grants, offer);
        RunArgs args = CliArgs.ParseRun(["--secrets", "MY_SECRET", "--reason", "reuse test", "--", "./" + program], out _)!;
        Task<int> running = Task.Run(() => run.ExecuteAsync(args, folder));
        if (minutes is { } chosen)
        {
            Task first = await Task.WhenAny(link.Task, running, Task.Delay(TimeSpan.FromSeconds(20)));
            if (first == link.Task)
            {
                Uri uri = new(link.Task.Result[AnnouncePrefix.Length..]);
                string url = "http://127.0.0.1:" + uri.Port + uri.AbsolutePath;
                string page = Text(Send(client, HttpMethod.Get, url));
                byte[] bind = Base64Url.DecodeFromChars(JsonSerializer.Deserialize<Dictionary<string, string>>(Between(page, "<script type=\"application/json\" id=\"start\">", "</script>"))!["bind"]);
                string assertion = key.Assert(ReuseBinding.Challenge(bind, chosen), "http://localhost:" + uri.Port, "localhost", Next());
                Send(client, HttpMethod.Post, url + "/proof", Body(sendAs ?? chosen, assertion))?.Dispose();
            }
        }

        Task done = await Task.WhenAny(running, Task.Delay(TimeSpan.FromSeconds(30)));

        return (done == running ? running.Result : -1, stdout.ToString(), stderr.ToString(), Volatile.Read(ref announced));
    }

    private static async Task Chain(Action<bool, string> check, HttpClient client, string root)
    {
        string folder = Path.Combine(root, "chain");
        Directory.CreateDirectory(folder);
        string program = OperatingSystem.IsWindows() ? "show.cmd" : "show.sh";
        string path = Path.Combine(folder, program);
        if (OperatingSystem.IsWindows())
        {
            File.WriteAllText(path, "@echo off\r\necho %MY_SECRET%\r\n");
        }
        else
        {
            File.WriteAllText(path, "#!/bin/sh\necho \"$MY_SECRET\"\n");
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        using TestAuthenticator key = TestAuthenticator.ES256();
        ReuseOffer offer = new(480, 10);

        StateDatabase NewDb()
        {
            StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "chain-" + Guid.NewGuid().ToString("N")));
            new PasskeyStore(db).Add(key.Record("localhost", "chain-key"));

            return db;
        }

        // Approve for 10 minutes: a grant that ends at +10 min; a second identical run inside it does not ask.
        {
            StateDatabase db = NewDb();
            DateTimeOffset before = DateTimeOffset.UtcNow;
            (int code, string stdout, string stderr, int announced) = await Drive(client, db, folder, program, key, new GrantStore(db), offer, 10);
            DateTimeOffset after = DateTimeOffset.UtcNow;
            check(code == 0 && announced == 1 && stdout.Contains("[REDACTED]", StringComparison.Ordinal) && !stdout.Contains(Secret, StringComparison.Ordinal), "reuse chain: approved for 10 minutes runs, output redacted (" + code + "; " + stderr + ")");
            IReadOnlyList<GrantEntry> entries = new GrantStore(db).Entries();
            check(entries.Count == 1 && entries[0].Minutes == 10 && entries[0].Expires - entries[0].Approved == TimeSpan.FromMinutes(10) && entries[0].Approved >= before.AddSeconds(-1) && entries[0].Approved <= after.AddSeconds(1) && entries[0].KeyName == "chain-key", "reuse chain: one grant, exactly 10 minutes from approval, with the key name");

            (code, stdout, stderr, announced) = await Drive(client, db, folder, program, key, new GrantStore(db, () => DateTimeOffset.UtcNow.AddMinutes(9)), offer, null);
            check(code == 0 && announced == 0 && stderr.Contains("reusing the approval", StringComparison.Ordinal), "reuse chain: a second identical run inside the 10 minutes does not ask (" + code + "; " + stderr + ")");
            (code, _, stderr, announced) = await Drive(client, db, folder, program, key, new GrantStore(db, () => DateTimeOffset.UtcNow.AddMinutes(11)), offer, null);
            check(code == RunCommand.Denied && announced == 1, "reuse chain: an expired grant is ignored and the run asks again (" + code + ")");

            string audit = StateDatabaseTests.AuditText(db.FilePath);
            check(audit.Contains("\"reuseMinutes\":10", StringComparison.Ordinal) && !audit.Contains(Secret, StringComparison.Ordinal), "reuse chain: the audit entry records 10 minutes and no secret value");
            check(new AuditLog(db).TryRead(10, null, out IReadOnlyList<AuditRecord> rows, out _) && rows.Any(row => row.Event == "approved" && row.Detail.Contains("approved for 10 min", StringComparison.Ordinal) && row.KeyName == "chain-key"), "reuse chain: --audit shows the chosen time and the key name");
        }

        // A second key, not the admin, approves runs; the audit and the grant name it, without the admin marker.
        {
            StateDatabase db = NewDb();
            using TestAuthenticator phone = TestAuthenticator.ES256();
            check(new PasskeyStore(db).Add(phone.Record("localhost", "phone")), "reuse chain: a second key is enrolled");
            (int code, string stdout, string stderr, int announced) = await Drive(client, db, folder, program, phone, new GrantStore(db), offer, 10);
            check(code == 0 && announced == 1 && stdout.Contains("[REDACTED]", StringComparison.Ordinal), "reuse chain: a run approved by the second key runs (" + code + "; " + stderr + ")");
            check(new GrantStore(db).Entries().Single().KeyName == "phone", "reuse chain: the grant names the second key");
            check(new AuditLog(db).TryRead(10, null, out IReadOnlyList<AuditRecord> rows, out _) && rows.Any(row => row.Event == "approved" && row.KeyName == "phone" && row.Detail.StartsWith("passkey phone verified", StringComparison.Ordinal)), "reuse chain: the audit names the key and it is not the admin");
            (code, _, _, _) = await Drive(client, db, folder, program, key, new GrantStore(db, () => DateTimeOffset.UtcNow.AddMinutes(11)), offer, 0);
            check(code == 0 && new AuditLog(db).TryRead(10, null, out rows, out _) && rows.Any(row => row.Event == "approved" && row.KeyName == "chain-key" && row.Detail.StartsWith("admin passkey chain-key verified", StringComparison.Ordinal)), "reuse chain: a run approved by the admin key records the admin marker");
        }

        // Approve once: no grant; the next run asks again.
        {
            StateDatabase db = NewDb();
            (int code, _, _, int announced) = await Drive(client, db, folder, program, key, new GrantStore(db), offer, 0);
            check(code == 0 && announced == 1 && new GrantStore(db).Entries().Count == 0, "reuse chain: approve once runs and saves no grant (" + code + ")");
            check(new AuditLog(db).TryRead(10, null, out IReadOnlyList<AuditRecord> rows, out _) && rows.Any(row => row.Event == "approved" && row.Detail.Contains("approved once", StringComparison.Ordinal)) && StateDatabaseTests.AuditText(db.FilePath).Contains("\"reuseMinutes\":0", StringComparison.Ordinal), "reuse chain: the audit says approved once (0 minutes)");
            (code, _, _, announced) = await Drive(client, db, folder, program, key, new GrantStore(db), offer, 0);
            check(code == 0 && announced == 1, "reuse chain: after once, the next run asks again");
        }

        // A grant longer than the current ceiling is not honoured.
        {
            StateDatabase db = NewDb();
            (int code, _, _, _) = await Drive(client, db, folder, program, key, new GrantStore(db), offer, 240);
            check(code == 0 && new GrantStore(db).Entries().Single().Minutes == 240, "reuse chain: approved for 4 hours saves a 240-minute grant");
            (code, _, _, int announced) = await Drive(client, db, folder, program, key, new GrantStore(db), new ReuseOffer(60, 10), null);
            check(code == RunCommand.Denied && announced == 1, "reuse chain: with the ceiling lowered to 60, the 240-minute grant is not used (" + code + ")");
            (code, _, _, announced) = await Drive(client, db, folder, program, key, new GrantStore(db), offer, null);
            check(code == 0 && announced == 0, "reuse chain: under a ceiling of 480 the same grant still holds");
        }

        // A time that was not offered: denied, nothing runs, nothing is saved.
        {
            StateDatabase db = NewDb();
            (int code, string stdout, _, _) = await Drive(client, db, folder, program, key, new GrantStore(db), new ReuseOffer(60, 10), 240);
            check(code == RunCommand.Denied && !stdout.Contains("[REDACTED]", StringComparison.Ordinal) && new GrantStore(db).Entries().Count == 0, "reuse chain: 240 minutes above a ceiling of 60 is denied and saves nothing (" + code + ")");
            (code, _, _, _) = await Drive(client, db, folder, program, key, new GrantStore(db), offer, 0, sendAs: 10);
            check(code == RunCommand.Denied && new GrantStore(db).Entries().Count == 0, "reuse chain: a signature for once sent as 10 minutes is denied and saves nothing");
        }

        // Reuse off (settings that cannot be used): only once; a longer time is denied, and saved grants are not used.
        {
            StateDatabase db = NewDb();
            (int code, _, _, _) = await Drive(client, db, folder, program, key, new GrantStore(db), offer, 10);
            check(code == 0 && new GrantStore(db).Entries().Count == 1, "reuse chain: a grant for the reuse-off checks");
            (code, _, _, int announced) = await Drive(client, db, folder, program, key, new GrantStore(db), ReuseOffer.Off, null);
            check(code == RunCommand.Denied && announced == 1, "reuse chain: with reuse off a saved grant is not used");
            (code, _, _, _) = await Drive(client, db, folder, program, key, new GrantStore(db), ReuseOffer.Off, 10);
            check(code == RunCommand.Denied, "reuse chain: with reuse off 10 minutes is denied");
        }

        // An approver that returns a time that was not offered: denied (RunCommand checks it too).
        {
            StateDatabase db = NewDb();
            FakeApprover sly = new(true, 7);
            int code = await new RunCommand(new MemoryStore(new Dictionary<string, string> { ["MY_SECRET"] = Secret }), sly, new AuditLog(db), new StringWriter(), new StringWriter(), new GrantStore(db), offer)
                .ExecuteAsync(CliArgs.ParseRun(["--secrets", "MY_SECRET", "--reason", "x", "--", "./" + program], out _)!, folder);
            check(code == RunCommand.Denied && new GrantStore(db).Entries().Count == 0 && sly.Requests.Single().Reuse == offer, "reuse chain: an approval for a time that was not offered is denied; the request carried the offer");
        }
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

    private static string Between(string text, string start, string end)
    {
        int from = text.IndexOf(start, StringComparison.Ordinal);
        if (from < 0)
        {
            return "";
        }

        from += start.Length;
        int to = text.IndexOf(end, from, StringComparison.Ordinal);

        return to < 0 ? "" : text[from..to];
    }
}

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>
/// Signed grants and the admin key fingerprint. A saved approval is honoured only with the passkey assertion that approved
/// exactly that request for exactly that time, by a key in the verified manifest. Every edit an agent can make to the grants
/// table makes the grant ignored (reported once on stderr) and the run asks again. The admin key's fingerprint is on every page,
/// in --enrolled and in --audit.
/// </summary>
internal static class GrantTests
{
    private const string Secret = "Grant-Secret-5531";
    private const string Rejected = "a saved approval failed verification and was ignored";
    private static readonly Regex Link = new("https?://[^\\s]+", RegexOptions.CultureInvariant);

    private static int _signs = 2_000_000;

    public static async Task Run(Action<bool, string> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "ws-grant-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            Fingerprints(check, root);
            Store(check, root);
            using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
            client.Timeout = TimeSpan.FromSeconds(20);
            await Chain(check, client, root);
            await Pages(check, client, root);
            await AuditEvents(check, client, root);
            Listings(check, root);
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }

    private static uint Next() => (uint)Interlocked.Increment(ref _signs);

    /// <summary>What the test expects: the first 8 bytes of SHA-256 of the COSE key, as four groups of four hex digits.</summary>
    internal static string Expected(TestAuthenticator key)
    {
        string hex = Convert.ToHexStringLower(SHA256.HashData(key.CoseKey())[..8]);

        return hex[..4] + " " + hex[4..8] + " " + hex[8..12] + " " + hex[12..];
    }

    private static void Fingerprints(Action<bool, string> check, string root)
    {
        using TestAuthenticator one = TestAuthenticator.ES256();
        using TestAuthenticator two = TestAuthenticator.RS256();
        string first = AdminKey.Fingerprint(one.Record("localhost", "a").PublicKey);
        check(first == AdminKey.Fingerprint(one.Record("localhost", "b").PublicKey), "fingerprint: deterministic for the same public key");
        check(Regex.IsMatch(first, "^[0-9a-f]{4} [0-9a-f]{4} [0-9a-f]{4} [0-9a-f]{4}$"), "fingerprint: four groups of four hex digits (" + first + ")");
        check(first == Expected(one), "fingerprint: the first 8 bytes of SHA-256 of the stored public key bytes");
        check(AdminKey.Fingerprint(two.Record("localhost", "a").PublicKey) != first, "fingerprint: another key has another fingerprint");

        StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "fp"));
        check(AdminKey.Line(db) == "Admins: not set up yet", "fingerprint: an empty state has no admin key yet (" + AdminKey.Line(db) + ")");
        DateTimeOffset when = new(2026, 11, 2, 9, 0, 0, TimeSpan.Zero);
        TestState.Add(db, one.Record("localhost", "laptop") with { Created = when });
        check(AdminKey.Line(db) == "Admins: laptop " + Expected(one), "fingerprint: the line names the key and its fingerprint (" + AdminKey.Line(db) + ")");
        TestState.Add(db, two.Record("localhost", "phone") with { Created = when.AddMinutes(1) });
        check(AdminKey.Line(db) == "Admins: laptop " + Expected(one), "fingerprint: a key that is not an admin is not listed");

        // Every admin is listed, oldest first: a second admin changes the line.
        using TestAuthenticator three = TestAuthenticator.ES256();
        TestState.Add(db, three.Record("localhost", "tablet") with { Created = when.AddMinutes(2) }, admin: true);
        check(AdminKey.Line(db) == "Admins: laptop " + Expected(one) + ", tablet " + Expected(three), "fingerprint: the line lists every admin (" + AdminKey.Line(db) + ")");

        StateDatabase other = StateDatabase.InFolder(Path.Combine(root, "fp-other"));
        TestState.Add(other, two.Record("localhost", "laptop"));
        check(AdminKey.Line(other) != AdminKey.Line(db) && AdminKey.Line(other).Contains(Expected(two), StringComparison.Ordinal), "fingerprint: a state with another admin key shows another fingerprint");
        check(AdminKey.Line(Manifest.First(one.Record("localhost", "a" + (char)0x202E + "b"), ToolSettings.Defaults)) == "Admins: a□b " + Expected(one), "fingerprint: the names in the line are cleaned");
    }

    /// <summary>A text as the approval page binds it: the request id line and the page issued line.</summary>
    private static string Text(string key, DateTimeOffset issued, string extra = "Agent says: test")
    {
        return "Allow an agent to use secrets?\n" + extra + "\n" + ApprovalSummary.RequestIdPrefix + key + "\n" + ApprovalSummary.IssuedLine(issued);
    }

    private static ApprovalEvidence Evidence(TestAuthenticator key, string text, int minutes, string nonce = "nonce-1")
    {
        return new ApprovalEvidence(nonce, text, key.Assert(ReuseBinding.Challenge(RequestBinding.Compute(nonce, text), minutes), TestState.Origin, "localhost", Next()));
    }

    private static void Store(Action<bool, string> check, string root)
    {
        using TestAuthenticator admin = TestAuthenticator.ES256();
        using TestAuthenticator outsider = TestAuthenticator.ES256();
        DateTimeOffset issued = new(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);
        DateTimeOffset clock = issued.AddMinutes(1);
        StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "store"));
        TestState.Add(db, admin.Record("localhost", "laptop"));
        GrantStore grants = new(db, () => clock);

        check(StateDatabase.SchemaVersion == 9, "grant store: the schema version is 9");
        check(grants.Add("K", 10, Evidence(admin, Text("K", issued), 10)), "grant store: a grant with the assertion over its request and time is saved");
        GrantLookup found = grants.Find("K", 480);
        check(found.Grant is { Minutes: 10, KeyName: "laptop" } grant && grant.Approved == clock && grant.Expires == clock.AddMinutes(10) && found.Rejected is null, "grant store: it is honoured, names the key from the manifest, and lasts exactly 10 minutes");
        check(grants.TryGet("K", 480, out _, out DateTimeOffset ends) && ends == clock.AddMinutes(10), "grant store: TryGet gives the same grant");

        check(!grants.Add("A", 10, Evidence(admin, Text("B", issued), 10)) && grants.Find("A", 480).Grant is null, "grant store: an assertion for another request is not saved");
        check(!grants.Add("C", 10, Evidence(admin, Text("C", issued), 0)), "grant store: an assertion made for once is not saved as 10 minutes");
        check(!grants.Add("D", 0, Evidence(admin, Text("D", issued), 0)), "grant store: approve once saves no grant");
        check(!grants.Add("E", 10, Evidence(outsider, Text("E", issued), 10)), "grant store: an assertion by a key that is not enrolled is not saved");
        check(!grants.Add("F", 10, new ApprovalEvidence("n", Text("F", issued), "{}")), "grant store: no assertion, no grant");
        check(!grants.Add("G", 10, Evidence(admin, "Request id: G", 10)), "grant store: a text without the page issued time is not saved");
        check(!new GrantStore(db, () => issued.AddMinutes(31)).Add("H", 10, Evidence(admin, Text("H", issued), 10)), "grant store: an approval later than 30 minutes after the page was issued is not saved");
        check(!new GrantStore(db, () => issued.AddMinutes(-1)).Add("I", 10, Evidence(admin, Text("I", issued), 10)), "grant store: an approval before the page was issued is not saved");
        check(!grants.Add("J", 10, Evidence(admin, Text("J", issued, "Agent says: x\nRequest id: K"), 10)), "grant store: two request id lines are not saved");
        check(!grants.Add("L", ReuseSettings.MaxMinutes + 1, Evidence(admin, Text("L", issued), ReuseSettings.MaxMinutes + 1)), "grant store: more than 1440 minutes is not saved");
        check(grants.Entries().Select(item => item.Key).SequenceEqual(["K"]), "grant store: only the good grant is stored");

        // In force and ceiling: ignored without a verification failure.
        check(grants.Find("K", 5) is { Grant: null, Rejected: null }, "grant store: a ceiling below the grant ignores it, no verification failure");
        clock = issued.AddMinutes(12);
        check(grants.Find("K", 480) is { Grant: null, Rejected: null }, "grant store: an expired grant is ignored, no verification failure");
        clock = issued.AddMinutes(5);

        // Edits to the row: each is a verification failure.
        (string Name, string Sql)[] edits =
        [
            ("minutes edited", "UPDATE grants SET minutes = 60, expires = approved + 60 * 600000000"),
            ("expires edited", "UPDATE grants SET expires = expires + 600000000"),
            ("approved edited later", "UPDATE grants SET approved = approved + 31 * 600000000, expires = expires + 31 * 600000000"),
            ("text edited", "UPDATE grants SET text = replace(text, 'Agent says: test', 'Agent says: other')"),
            ("nonce edited", "UPDATE grants SET nonce = 'other'"),
            ("signature emptied", "UPDATE grants SET signature = ''"),
            ("credential id unknown", "UPDATE grants SET credential_id = 'AAAA'"),
        ];
        foreach ((string name, string sql) in edits)
        {
            StateDatabase copy = Copy(db, root);
            ManifestTests.Execute(copy.FilePath, sql);
            GrantLookup lookup = new GrantStore(copy, () => issued.AddMinutes(40)).Find("K", 480);
            check(lookup is { Grant: null, Rejected: not null }, "grant store: " + name + ": ignored as a verification failure (" + lookup.Rejected + ")");
        }
    }

    private static StateDatabase Copy(StateDatabase db, string root)
    {
        string folder = Path.Combine(root, "copy-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        string path = Path.Combine(folder, StateDatabase.FileName);
        using (SqliteConnection connection = new(new SqliteConnectionStringBuilder { DataSource = db.FilePath, Pooling = false }.ToString()))
        {
            connection.Open();
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "VACUUM INTO $path";
            command.Parameters.AddWithValue("$path", path);
            command.ExecuteNonQuery();
        }

        return new StateDatabase(path);
    }

    /// <summary>One grant row as stored.</summary>
    private sealed record Row(string Key, string CredentialId, string Nonce, string Text, long Minutes, long Approved, long Expires);

    private static Row Single(StateDatabase db)
    {
        using SqliteConnection connection = new(new SqliteConnectionStringBuilder { DataSource = db.FilePath, Pooling = false }.ToString());
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT key, credential_id, nonce, text, minutes, approved, expires FROM grants";
        using SqliteDataReader reader = command.ExecuteReader();
        reader.Read();

        return new Row(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetInt64(4), reader.GetInt64(5), reader.GetInt64(6));
    }

    /// <summary>Puts <paramref name="key" />'s assertion over the row's own nonce and text, for <paramref name="minutes" />, into the row.</summary>
    private static void Resign(StateDatabase db, TestAuthenticator key, int minutes)
    {
        Row row = Single(db);
        using JsonDocument proof = JsonDocument.Parse(key.Assert(ReuseBinding.Challenge(RequestBinding.Compute(row.Nonce, row.Text), minutes), TestState.Origin, "localhost", Next()));
        JsonElement r = proof.RootElement;
        ManifestTests.Execute(db.FilePath, "UPDATE grants SET credential_id = $id, authenticator_data = $ad, client_data = $cd, signature = $sig",
            ("$id", r.GetProperty("id").GetString()!), ("$ad", r.GetProperty("authenticatorData").GetString()!), ("$cd", r.GetProperty("clientDataJSON").GetString()!), ("$sig", r.GetProperty("signature").GetString()!));
    }

    /// <summary>
    /// RunCommand with the real WebApprover and PasskeyMethod and a real child. <paramref name="minutes" /> is the time chosen on
    /// the page (signed by <paramref name="key" />), or null to answer nothing.
    /// </summary>
    private static async Task<(int Code, string Out, string Err, int Announced, string Page)> Drive(HttpClient client, StateDatabase db, string folder, string program, TestAuthenticator key, ReuseOffer offer, int? minutes, Func<DateTimeOffset>? clock = null)
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
        RunCommand run = new(new MemoryStore(new Dictionary<string, string> { ["MY_SECRET"] = Secret }), approver, new AuditLog(db), TextWriter.Synchronized(stdout), errors, new GrantStore(db, clock), offer);
        RunArgs args = CliArgs.ParseRun(["--secrets", "MY_SECRET", "--reason", "grant test", "--", "./" + program], out _)!;
        Task<int> running = Task.Run(() => run.ExecuteAsync(args, folder));
        string page = "";
        if (minutes is { } chosen)
        {
            Task first = await Task.WhenAny(link.Task, running, Task.Delay(TimeSpan.FromSeconds(20)));
            if (first == link.Task)
            {
                Uri uri = new(Link.Match(link.Task.Result).Value);
                string url = "http://127.0.0.1:" + uri.Port + uri.AbsolutePath;
                (_, page) = TestState.Get(client, url);
                byte[] bind = Base64Url.DecodeFromChars(JsonSerializer.Deserialize<Dictionary<string, string>>(Between(page, "<script type=\"application/json\" id=\"start\">", "</script>"))!["bind"]);
                string assertion = key.Assert(ReuseBinding.Challenge(bind, chosen), "http://localhost:" + uri.Port, "localhost", Next());
                TestState.Post(client, url + "/proof", ReuseTests.Body(chosen, assertion));
            }
        }

        Task done = await Task.WhenAny(running, Task.Delay(TimeSpan.FromSeconds(30)));

        return (done == running ? running.Result : -1, stdout.ToString(), stderr.ToString(), Volatile.Read(ref announced), page);
    }

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

    private static string Script(string folder, string name)
    {
        string program = OperatingSystem.IsWindows() ? name + ".cmd" : name + ".sh";
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

        return program;
    }

    private static async Task Chain(Action<bool, string> check, HttpClient client, string root)
    {
        string folder = Path.Combine(root, "chain");
        Directory.CreateDirectory(folder);
        string program = Script(folder, "show");
        string otherProgram = Script(folder, "other");
        using TestAuthenticator key = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.ES256();
        using TestAuthenticator outsider = TestAuthenticator.ES256();
        ReuseOffer offer = new(480, 10);

        StateDatabase NewDb()
        {
            StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "chain-" + Guid.NewGuid().ToString("N")));
            TestState.Add(db, key.Record("localhost", "chain-key"));
            TestState.Add(db, phone.Record("localhost", "phone"));

            return db;
        }

        // The good grant: approved for 10 minutes; an identical run inside it does not ask, and the audit names the key.
        {
            StateDatabase db = NewDb();
            (int code, string stdout, string stderr, int announced, string page) = await Drive(client, db, folder, program, key, offer, 10);
            check(code == 0 && announced == 1 && stdout.Contains("[REDACTED]", StringComparison.Ordinal), "grant chain: approved for 10 minutes runs (" + code + "; " + stderr + ")");
            Row row = Single(db);
            check(row.Minutes == 10 && row.Expires - row.Approved == 10 * TimeSpan.TicksPerMinute && row.CredentialId == TestAuthenticator.Encode(key.CredentialId), "grant chain: the row has the minutes, the times and the approving credential");
            check(row.Text.Split('\n').Contains(ApprovalSummary.RequestIdPrefix + row.Key) && row.Text.Split('\n').Any(line => line.StartsWith(ApprovalSummary.IssuedPrefix, StringComparison.Ordinal))
                && row.Text.Split('\n').Contains("Admins: chain-key " + Expected(key)), "grant chain: the bound text has the request id, the page issued time and the admin key (" + row.Text + ")");
            check(page.Contains(System.Net.WebUtility.HtmlEncode(ApprovalSummary.RequestIdPrefix + row.Key), StringComparison.Ordinal) && page.Contains("Admins: chain-key " + Expected(key), StringComparison.Ordinal), "grant chain: the page shows the request id and the admin key");
            check(!row.Text.Contains(Secret, StringComparison.Ordinal) && !page.Contains(Secret, StringComparison.Ordinal), "grant chain: no secret value in the bound text or the page");

            (code, stdout, stderr, announced, _) = await Drive(client, db, folder, program, key, offer, null, () => DateTimeOffset.UtcNow.AddMinutes(9));
            check(code == 0 && announced == 0 && stderr.Contains("reusing the approval", StringComparison.Ordinal) && !stderr.Contains(Rejected, StringComparison.Ordinal) && stdout.Contains("[REDACTED]", StringComparison.Ordinal), "grant chain: a good grant is reused without a page (" + code + "; " + stderr + ")");
            check(new AuditLog(db).TryRead(20, null, out IReadOnlyList<AuditRecord> rows, out _) && rows.Any(item => item.Event == "reused" && item.KeyName == "chain-key")
                && rows.Any(item => item.Event == "approved" && item.KeyName == "chain-key" && item.Detail.Contains("approved for 10 min", StringComparison.Ordinal)), "grant chain: the audit names the approving key when the grant is made and when it is used");
            check(!StateDatabaseTests.AuditText(db.FilePath).Contains(Secret, StringComparison.Ordinal), "grant chain: the audit has no secret value");
        }

        // Each edit: the grant is ignored, reported once, and the run asks again and works through the normal approval.
        (string Name, Action<StateDatabase> Tamper, Func<DateTimeOffset>? Clock)[] tampers =
        [
            ("a row inserted with no assertion", db => ManifestTests.Execute(db.FilePath, "UPDATE grants SET authenticator_data = '', client_data = '', signature = ''"), null),
            ("a row inserted with an invalid assertion", db => ManifestTests.Execute(db.FilePath, "UPDATE grants SET authenticator_data = 'AAAA', client_data = 'AAAA', signature = 'AAAA'"), null),
            ("an assertion by a key not in the manifest", db => Resign(db, outsider, 10), null),
            ("an assertion made for once, minutes edited to 10", db => Resign(db, key, 0), null),
            ("minutes edited upward (10 -> 480)", db => ManifestTests.Execute(db.FilePath, "UPDATE grants SET minutes = 480, expires = approved + 480 * 600000000"), null),
            ("expires edited later", db => ManifestTests.Execute(db.FilePath, "UPDATE grants SET expires = expires + 60 * 600000000"), null),
            ("approved edited later than the page allows", db => ManifestTests.Execute(db.FilePath, "UPDATE grants SET approved = approved + 31 * 600000000, expires = expires + 31 * 600000000"), () => DateTimeOffset.UtcNow.AddMinutes(35)),
            ("text edited", db => ManifestTests.Execute(db.FilePath, "UPDATE grants SET text = replace(text, 'grant test', 'grant TEST')"), null),
            ("credential id swapped to another enrolled key", db => ManifestTests.Execute(db.FilePath, "UPDATE grants SET credential_id = $id", ("$id", TestAuthenticator.Encode(phone.CredentialId))), null),
        ];
        foreach ((string name, Action<StateDatabase> tamper, Func<DateTimeOffset>? clock) in tampers)
        {
            StateDatabase db = NewDb();
            (int code, _, string stderr, _, _) = await Drive(client, db, folder, program, key, offer, 10);
            check(code == 0 && Single(db).Minutes == 10, "grant tamper: " + name + ": a real grant first (" + code + "; " + stderr + ")");
            tamper(db);
            (code, string stdout, stderr, int announced, _) = await Drive(client, db, folder, program, key, offer, 0, clock);
            check(code == 0 && announced == 1 && stdout.Contains("[REDACTED]", StringComparison.Ordinal) && !stderr.Contains("reusing the approval", StringComparison.Ordinal), "grant tamper: " + name + ": the grant is not used; the run asks again and works (" + code + "; " + stderr + ")");
            check(Regex.Matches(stderr, Regex.Escape(Rejected)).Count == 1, "grant tamper: " + name + ": reported once on stderr (" + stderr + ")");
        }

        // The request id edited to another request's fingerprint.
        {
            StateDatabase db = NewDb();
            await Drive(client, db, folder, otherProgram, key, offer, 10);
            string otherKey = Single(db).Key;
            ManifestTests.Execute(db.FilePath, "DELETE FROM grants");
            await Drive(client, db, folder, program, key, offer, 10);
            ManifestTests.Execute(db.FilePath, "UPDATE grants SET key = $key", ("$key", otherKey));
            (int code, string stdout, string stderr, int announced, _) = await Drive(client, db, folder, otherProgram, key, offer, 0);
            check(code == 0 && announced == 1 && stdout.Contains("[REDACTED]", StringComparison.Ordinal) && Regex.Matches(stderr, Regex.Escape(Rejected)).Count == 1, "grant tamper: the request id edited to another request's: ignored, reported, asks again (" + code + "; " + stderr + ")");
        }

        // Expired, and the ceiling lowered below the grant: ignored and the run asks again.
        {
            StateDatabase db = NewDb();
            await Drive(client, db, folder, program, key, offer, 10);
            (int code, string stdout, string stderr, int announced, _) = await Drive(client, db, folder, program, key, offer, 0, () => DateTimeOffset.UtcNow.AddMinutes(11));
            check(code == 0 && announced == 1 && stdout.Contains("[REDACTED]", StringComparison.Ordinal) && !stderr.Contains("reusing the approval", StringComparison.Ordinal), "grant: an expired grant is ignored and the run asks again (" + code + ")");

            StateDatabase lowered = NewDb();
            await Drive(client, lowered, folder, program, key, offer, 240);
            (code, stdout, stderr, announced, _) = await Drive(client, lowered, folder, program, key, new ReuseOffer(60, 10), 0);
            check(code == 0 && announced == 1 && stdout.Contains("[REDACTED]", StringComparison.Ordinal) && !stderr.Contains("reusing the approval", StringComparison.Ordinal), "grant: a ceiling lowered below the grant ignores it and the run asks again (" + code + ")");
        }

        // --unenroll of a key that approved a grant: the grant ends with the key, and the next run asks normally (no failure line).
        {
            StateDatabase db = NewDb();
            await Drive(client, db, folder, program, phone, offer, 10);
            check(new GrantStore(db).Entries().Single().KeyName == "phone", "grant unenroll: a grant approved by the second key");
            ApprovalSettings settings = new("passkey", null, 0, TimeSpan.FromSeconds(10));
            await Served(client, announce =>
            {
                PasskeyMethod method = new(new PasskeyStore(db), settings, () => null);
                EnrollmentTarget target = EnrollmentTarget.For(method, new WebApprover(method, settings, announce, TimeSpan.Zero));

                return new Enrollment(target, target, announce).Unenroll("phone");
            }, key, 1);
            check(new PasskeyStore(db).All().Select(item => item.Name).SequenceEqual(["chain-key"]) && new GrantStore(db).Entries().Count == 0, "grant unenroll: the key and its grant are gone together");
            (int code, string stdout, string stderr, int announced, _) = await Drive(client, db, folder, program, key, offer, 0);
            check(code == 0 && announced == 1 && stdout.Contains("[REDACTED]", StringComparison.Ordinal) && !stderr.Contains(Rejected, StringComparison.Ordinal), "grant unenroll: the next run asks normally, with no verification failure line (" + stderr + ")");
        }

        // An approver that says yes for 10 minutes but brings no signed approval: nothing is saved.
        {
            StateDatabase db = NewDb();
            FakeApprover sly = new(true, 10);
            int code = await new RunCommand(new MemoryStore(new Dictionary<string, string> { ["MY_SECRET"] = Secret }), sly, new AuditLog(db), new StringWriter(), new StringWriter(), new GrantStore(db), offer)
                .ExecuteAsync(CliArgs.ParseRun(["--secrets", "MY_SECRET", "--reason", "x", "--", "./" + program], out _)!, folder);
            check(code == 0 && new GrantStore(db).Entries().Count == 0, "grant: an approval without a signed approval runs once and saves nothing");
            check(sly.Requests.Single().RequestId is { Length: > 0 } id && ApprovalSummary.BuildMessage(sly.Requests[0]).Split('\n').Contains(ApprovalSummary.RequestIdPrefix + id), "grant: the request carries its request id, and the prompt text shows it");
        }
    }

    /// <summary>
    /// Runs <paramref name="call" />, answers approval pages with <paramref name="admin" /> while <paramref name="approve" /> says
    /// so, and returns every other page body (each then cancelled with /deny).
    /// </summary>
    internal static async Task<List<string>> Served(HttpClient client, Func<Action<string>, object?> call, TestAuthenticator admin, int approve = 0)
    {
        System.Collections.Concurrent.BlockingCollection<string> queue = [];
        Task<object?> task = Task.Run(() => call(text => queue.Add(text)));
        List<string> pages = [];
        DateTime stop = DateTime.UtcNow.AddSeconds(25);
        while (!task.IsCompleted && DateTime.UtcNow < stop)
        {
            if (!queue.TryTake(out string? text, 200) || Link.Match(text) is not { Success: true } match)
            {
                continue;
            }

            Uri link = new(match.Value);
            string url = "http://127.0.0.1:" + link.Port + link.AbsolutePath;
            (_, string page) = TestState.Get(client, url);
            pages.Add(page);
            if (approve-- > 0)
            {
                (_, string reply) = TestState.Approve(client, url, link.GetLeftPart(UriPartial.Authority), link.IdnHost, admin);

                // The approval leads to the next page by itself: read it, then end it.
                if (RecoveryTests.Member(reply, "next") is { } next)
                {
                    Uri following = new(next);
                    string followUrl = "http://127.0.0.1:" + following.Port + following.AbsolutePath;
                    pages.Add(TestState.Get(client, followUrl).Body);
                    TestState.Post(client, followUrl + "/deny", "");
                }
            }
            else
            {
                TestState.Post(client, url + "/deny", "");
            }
        }

        await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(20)));

        return pages;
    }

    private static async Task Pages(Action<bool, string> check, HttpClient client, string root)
    {
        using TestAuthenticator admin = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.ES256();
        StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "pages"));
        using TestAuthenticator second = TestAuthenticator.ES256();
        DateTimeOffset when = new(2026, 11, 2, 9, 0, 0, TimeSpan.Zero);
        TestState.Add(db, admin.Record("localhost", "laptop") with { Created = when });
        TestState.Add(db, phone.Record("localhost", "phone") with { Created = when.AddMinutes(1) });
        TestState.Add(db, second.Record("localhost", "desk") with { Created = when.AddMinutes(2) }, admin: true);

        // Every page lists every admin.
        string line = "Admins: laptop " + Expected(admin) + ", desk " + Expected(second);
        ApprovalSettings settings = new("passkey", null, 0, TimeSpan.FromSeconds(10));
        SecretStore secrets = new(db);
        SecretStoreTests.Put(secrets, new Dictionary<string, string> { ["OLD_NAME"] = Secret });

        (EnrollmentTarget, EnrollmentTarget) Targets(Action<string> announce)
        {
            PasskeyMethod method = new(new PasskeyStore(db), settings, () => null);
            EnrollmentTarget target = EnrollmentTarget.For(method, new WebApprover(method, settings, announce, TimeSpan.Zero));

            return (target, target);
        }

        (string Name, Func<Action<string>, object?> Call, int Approve)[] kinds =
        [
            ("run approval", announce => Targets(announce).Item1.Approver.Request(new ApprovalRequest("tool", "/bin/tool", [], "/work", "r", ["OLD_NAME"], null, null, null, "REQ")), 0),
            ("enroll approval", announce => new Enrollment(Targets(announce).Item1, Targets(announce).Item2, announce).Enroll(), 0),
            ("enroll page", announce => new Enrollment(Targets(announce).Item1, Targets(announce).Item2, announce).Enroll(), 1),
            ("unenroll", announce => new Enrollment(Targets(announce).Item1, Targets(announce).Item2, announce).Unenroll("phone"), 0),
            ("set", announce => new SecretEntry(Targets(announce).Item1, Targets(announce).Item2, secrets, new AuditLog(db), announce).Set(["NEW_NAME"]), 0),
            ("remove", announce => new SecretEntry(Targets(announce).Item1, Targets(announce).Item2, secrets, new AuditLog(db), announce).Remove(["OLD_NAME"]), 0),
            ("config", announce => new SettingsPage(db, Targets(announce).Item1, Targets(announce).Item2, announce, () => null).Run(), 0),
            ("revoke", announce => Revocation.Run(db, Targets(announce).Item1, Targets(announce).Item2, new GrantStore(db)), 0),
        ];
        foreach ((string name, Func<Action<string>, object?> call, int approve) in kinds)
        {
            List<string> pages = await Served(client, call, admin, approve);
            string page = pages.Count > approve ? pages[approve] : "";
            check(page.Contains(line, StringComparison.Ordinal), "fingerprint page: " + name + ": shows \"" + line + "\" (" + pages.Count + " pages)");
            check(!page.Contains(Secret, StringComparison.Ordinal), "fingerprint page: " + name + ": no secret value");
            if (name != "enroll page")
            {
                // Pages that change the state offer every admin key and no other; a run approval offers every key.
                int at = page.IndexOf("\"payload\":\"", StringComparison.Ordinal);
                string payload = at < 0 ? "" : page[at..page.IndexOf("\",\"", at, StringComparison.Ordinal)];
                bool ids = payload.Contains("allowCredentials", StringComparison.Ordinal) || payload.Contains(TestAuthenticator.Encode(admin.CredentialId), StringComparison.Ordinal) || payload.Contains(TestAuthenticator.Encode(phone.CredentialId), StringComparison.Ordinal);
                check(!ids, "fingerprint page: " + name + ": the payload names no credential");
            }
        }

        // The first run, before any key: the page says the admin key is not set up yet.
        StateDatabase empty = StateDatabase.InFolder(Path.Combine(root, "pages-empty"));
        List<string> first = await Served(client, announce =>
        {
            PasskeyMethod method = new(new PasskeyStore(empty), settings, () => null);
            EnrollmentTarget target = EnrollmentTarget.For(method, new WebApprover(method, settings, announce, TimeSpan.Zero));

            return new SettingsPage(empty, target, target, announce, () => null).Run();
        }, admin);
        check(first.Count == 1 && first[0].Contains("Admins: not set up yet", StringComparison.Ordinal), "fingerprint page: the first-run settings page says the admin key is not set up yet");
    }

    /// <summary>
    /// Runs --enroll through both pages: the admin approves, then <paramref name="creator" /> registers, the admin signs the
    /// new manifest on the registration page, and the code is typed. With <paramref name="deny" /> the approval page is denied.
    /// </summary>
    internal static async Task<ApprovalDecision?> Enroll(HttpClient client, StateDatabase db, TestAuthenticator admin, TestAuthenticator creator, string name, bool deny, bool makeAdmin = false, List<string>? replies = null)
    {
        System.Collections.Concurrent.BlockingCollection<string> queue = [];
        System.Collections.Concurrent.BlockingCollection<string?> codes = [];
        ApprovalSettings settings = new("passkey", null, 0, TimeSpan.FromSeconds(10));
        PasskeyMethod method = new(new PasskeyStore(db), settings, () => codes.TryTake(out string? code, TimeSpan.FromSeconds(15)) ? code : null);
        EnrollmentTarget target = EnrollmentTarget.For(method, new WebApprover(method, settings, text => queue.Add(text), TimeSpan.Zero));
        Task<ApprovalDecision> task = Task.Run(() => new Enrollment(target, target, text => queue.Add(text), new AuditLog(db)).Enroll());
        DateTime stop = DateTime.UtcNow.AddSeconds(25);
        while (!task.IsCompleted && DateTime.UtcNow < stop)
        {
            if (!queue.TryTake(out string? text, 200) || Link.Match(text) is not { Success: true } match)
            {
                continue;
            }

            Uri link = new(match.Value);
            string url = "http://127.0.0.1:" + link.Port + link.AbsolutePath;
            string origin = link.GetLeftPart(UriPartial.Authority);
            if (link.AbsolutePath.StartsWith("/a/", StringComparison.Ordinal))
            {
                if (deny)
                {
                    TestState.Get(client, url);
                    TestState.Post(client, url + "/deny", "");

                    continue;
                }

                // The approval answers with the address of the enrollment page: the page moves on by itself.
                (_, string approved) = TestState.Approve(client, url, origin, link.IdnHost, admin);
                if (RecoveryTests.Member(approved, "next") is not { } next)
                {
                    continue;
                }

                link = new Uri(next);
                url = "http://127.0.0.1:" + link.Port + link.AbsolutePath;
                origin = link.GetLeftPart(UriPartial.Authority);
            }

            (_, string page) = TestState.Get(client, url);
            using JsonDocument options = JsonDocument.Parse(Between(page, "<script type=\"application/json\" id=\"options\">", "</script>"));
            byte[] challenge = Base64Url.DecodeFromChars(options.RootElement.GetProperty("challenge").GetString()!);
            TestState.Note(options.RootElement);
            // The page sends the "Also make this key an admin" box with the registration.
            string registration = TestState.Register(creator, challenge, origin, link.IdnHost, name);
            registration = registration[..^1] + ",\"name\":" + JsonSerializer.Serialize(name) + ",\"admin\":" + (makeAdmin ? "true" : "false") + "}";
            (_, string reply) = TestState.Post(client, url + "/create", registration);
            replies?.Add(page);
            replies?.Add(reply);
            reply = TestState.SignStep(client, url, origin, reply, admin);
            replies?.Add(reply);
            using JsonDocument done = JsonDocument.Parse(reply);
            codes.Add(done.RootElement.TryGetProperty("code", out JsonElement code) ? code.GetString() : null);
        }

        Task finished = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(20)));

        return finished == task ? task.Result : null;
    }

    private static IReadOnlyList<AuditRecord> Rows(StateDatabase db) => new AuditLog(db).TryRead(100, null, out IReadOnlyList<AuditRecord> rows, out _) ? rows : [];

    private static async Task AuditEvents(Action<bool, string> check, HttpClient client, string root)
    {
        using TestAuthenticator admin = TestAuthenticator.ES256();
        using TestAuthenticator tablet = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.ES256();
        StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "events"));
        TestState.Add(db, admin.Record("localhost", "laptop"));
        TestState.Add(db, phone.Record("localhost", "phone"));
        ApprovalSettings settings = new("passkey", null, 0, TimeSpan.FromSeconds(10));
        SecretStore secrets = new(db);
        SecretStoreTests.Put(secrets, new Dictionary<string, string> { ["OLD_NAME"] = Secret });

        (EnrollmentTarget, EnrollmentTarget) Targets(Action<string> announce)
        {
            PasskeyMethod method = new(new PasskeyStore(db), settings, () => null);
            EnrollmentTarget target = EnrollmentTarget.For(method, new WebApprover(method, settings, announce, TimeSpan.Zero));

            return (target, target);
        }

        // --enroll: a denial, then a success.
        ApprovalDecision? enrolled = await Enroll(client, db, admin, tablet, "tablet", true);
        check(enrolled is { Approved: false } && Rows(db).Count(row => row.Event == AuditLog.ChangeDenied && row.Detail.StartsWith("--enroll: ", StringComparison.Ordinal)) == 1, "audit events: a denied --enroll is a change-denied row (" + enrolled?.Detail + ")");
        enrolled = await Enroll(client, db, admin, tablet, "tablet", false);
        AuditRecord? added = Rows(db).SingleOrDefault(row => row.Event == "key-enrolled");
        check(enrolled is { Approved: true } && added is { KeyName: "laptop" } && added.Detail.Contains("\"tablet\"", StringComparison.Ordinal) && added.Detail.Contains("admin passkey laptop verified", StringComparison.Ordinal)
            && added.Detail.Contains("(approves runs only)", StringComparison.Ordinal), "audit events: --enroll writes key-enrolled with the new key, that it is not an admin, and the approving admin (" + enrolled?.Detail + "; " + added?.Detail + ")");

        // --unenroll: a denial, then a success.
        Func<Action<string>, object?> unenroll = announce => new Enrollment(Targets(announce).Item1, Targets(announce).Item2, announce, new AuditLog(db)).Unenroll("phone");
        await Served(client, unenroll, admin, 0);
        check(Rows(db).Count(row => row.Event == AuditLog.ChangeDenied && row.Detail.StartsWith("--unenroll: ", StringComparison.Ordinal)) == 1, "audit events: a denied --unenroll is a change-denied row");
        await Served(client, unenroll, admin, 1);
        AuditRecord? removed = Rows(db).SingleOrDefault(row => row.Event == "key-removed");
        check(removed is { KeyName: "laptop" } && removed.Detail.Contains("\"phone\"", StringComparison.Ordinal) && removed.Detail.Contains("admin passkey laptop verified", StringComparison.Ordinal), "audit events: --unenroll writes key-removed with the removed key and the approving admin (" + removed?.Detail + ")");

        // --revoke: a denial, then a success that says how many were cleared.
        check(new GrantStore(db).Add("K", 10, "laptop"), "audit events: a grant to revoke");
        Func<Action<string>, object?> revoke = announce => Revocation.Run(db, Targets(announce).Item1, Targets(announce).Item2, new GrantStore(db));
        await Served(client, revoke, admin, 0);
        check(Rows(db).Count(row => row.Event == AuditLog.ChangeDenied && row.Detail.StartsWith("--revoke: ", StringComparison.Ordinal)) == 1 && new GrantStore(db).Entries().Count == 1, "audit events: a denied --revoke is a change-denied row and clears nothing");
        await Served(client, revoke, admin, 1);
        AuditRecord? revoked = Rows(db).SingleOrDefault(row => row.Event == "approvals-revoked");
        check(revoked is { KeyName: "laptop" } && revoked.Detail.StartsWith("1 saved approval(s) cleared; admin passkey laptop verified", StringComparison.Ordinal) && new GrantStore(db).Entries().Count == 0, "audit events: --revoke writes approvals-revoked with the count and the approving admin (" + revoked?.Detail + ")");

        // --set and --remove denied: change-denied rows with the names only.
        await Served(client, announce => new SecretEntry(Targets(announce).Item1, Targets(announce).Item2, secrets, new AuditLog(db), announce).Set(["NEW_NAME"]), admin, 0);
        await Served(client, announce => new SecretEntry(Targets(announce).Item1, Targets(announce).Item2, secrets, new AuditLog(db), announce).Remove(["OLD_NAME"]), admin, 0);
        check(Rows(db).Any(row => row.Event == AuditLog.ChangeDenied && row.Detail.StartsWith("--set: ", StringComparison.Ordinal) && row.Secrets.SequenceEqual(["NEW_NAME"])), "audit events: a denied --set is a change-denied row with the name");
        check(Rows(db).Any(row => row.Event == AuditLog.ChangeDenied && row.Detail.StartsWith("--remove: ", StringComparison.Ordinal) && row.Secrets.SequenceEqual(["OLD_NAME"])) && secrets.ListNames().Contains("OLD_NAME"), "audit events: a denied --remove is a change-denied row with the name, and nothing is removed");

        // --audit shows them, and no value.
        StringWriter output = new();
        AuditCommand.Run(db, new CliCommand.Audit(100, null, false), output, new StringWriter());
        string shown = output.ToString();
        check(new[] { "key-enrolled", "key-removed", "approvals-revoked", AuditLog.ChangeDenied }.All(name => shown.Contains("\t" + name + "\t", StringComparison.Ordinal)) && !shown.Contains(Secret, StringComparison.Ordinal), "audit events: --audit shows every new event and no value");
        check(new AuditLog(db).Verify() is { Ok: true }, "audit events: the hash chain holds");

        // A refusal with no state.db creates nothing.
        StateDatabase none = StateDatabase.InFolder(Path.Combine(root, "events-none"));
        check(!new AuditLog(none).TryWriteDenied("--set", [], "x") && !File.Exists(none.FilePath), "audit events: a refusal with no state.db creates none");
    }

    private static void Listings(Action<bool, string> check, string root)
    {
        // The first --set no longer asks anything in the terminal (the store key pair is made in memory and kept in the key
        // custody), so --set and --remove never need a terminal of their own; --revoke still does.
        CliCommand set = CliArgs.Parse(["--set", "A_NAME"], out _)!;
        CliCommand remove = CliArgs.Parse(["--remove", "A_NAME"], out _)!;
        check(!CliArgs.NeedsTerminal(set) && !CliArgs.NeedsTerminal(remove) && CliArgs.NeedsTerminal(CliArgs.Parse(["--revoke"], out _)!), "first --set: --set and --remove need no terminal; --revoke does");
        check(CliArgs.NoTerminalMessage(set) == CliArgs.NoTerminalMessage(new CliCommand.Revoke()) && !CliArgs.NoTerminalMessage(set).Contains("Dotenvx", StringComparison.Ordinal), "first --set: there is no Dotenvx key prompt message any more");

        using TestAuthenticator admin = TestAuthenticator.ES256();
        StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "listings"));
        using TestAuthenticator phone = TestAuthenticator.ES256();
        using TestAuthenticator desk = TestAuthenticator.ES256();
        DateTimeOffset when = new(2026, 11, 2, 9, 0, 0, TimeSpan.Zero);
        TestState.Add(db, admin.Record("localhost", "laptop") with { Created = when });
        TestState.Add(db, phone.Record("localhost", "phone") with { Created = when.AddMinutes(1) }, admin: true);
        TestState.Add(db, desk.Record("localhost", "desk") with { Created = when.AddMinutes(2) });
        string line = "Admins: laptop " + Expected(admin) + ", phone " + Expected(phone);
        new AuditLog(db).TryWrite("approved", new ApprovalRequest("tool", "/bin/tool", [], "/work", "r", ["NAME_A"]), "passkey laptop verified");

        StringWriter audit = new();
        check(AuditCommand.Run(db, new CliCommand.Audit(20, null, false), audit, new StringWriter()) == 0 && audit.ToString().Split('\n')[0].TrimEnd('\r') == line, "fingerprint --audit: the header line lists every admin key (" + audit + ")");
        StringWriter enrolled = new();
        StringWriter errors = new();
        EnrolledListing.Write(db, new PasskeyMethod(new PasskeyStore(db), new ApprovalSettings("passkey", null, 0, TimeSpan.FromSeconds(5))).Enrolled(), enrolled, errors);
        string[] lines = [.. enrolled.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(item => item.TrimEnd('\r'))];
        check(lines.Length == 4 && lines[0] == line && lines[1].StartsWith("laptop\tlocalhost\t", StringComparison.Ordinal) && lines[1].EndsWith("\tadmin", StringComparison.Ordinal)
            && lines[2].StartsWith("phone\tlocalhost\t", StringComparison.Ordinal) && lines[2].EndsWith("\tadmin", StringComparison.Ordinal)
            && lines[3].StartsWith("desk\tlocalhost\t", StringComparison.Ordinal) && !lines[3].EndsWith("\tadmin", StringComparison.Ordinal), "fingerprint --enrolled: the header line lists every admin, then one line per key, admins marked (" + enrolled + ")");

        StateDatabase empty = StateDatabase.InFolder(Path.Combine(root, "listings-empty"));
        StringWriter none = new();
        check(AuditCommand.Run(empty, new CliCommand.Audit(20, null, false), none, new StringWriter()) == 0 && none.ToString().StartsWith("Admins: not set up yet", StringComparison.Ordinal) && !File.Exists(empty.FilePath), "fingerprint --audit: an empty store says not set up yet and creates nothing");
    }
}

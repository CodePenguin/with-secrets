using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

using Microsoft.Data.Sqlite;

namespace ArcanaGuardian.Tests;

/// <summary>
/// The admin key fingerprint, which is on every approval page, in --enrolled and in --audit, and the admin events these commands write.
/// </summary>
internal static class GrantTests
{
    private const string Secret = "Grant-Secret-5531";
    private static readonly Regex Link = new("https?://[^\\s]+", RegexOptions.CultureInvariant);

    private static int _signs = 2_000_000;

    public static async Task Run(Action<bool, string> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "ws-grant-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            Fingerprints(check, root);
            using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
            client.Timeout = TimeSpan.FromSeconds(20);
            await Pages(check, client, root);
            await AuditEvents(check, client, root);
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
        ApprovalSettings settings = new(null, 0, TimeSpan.FromSeconds(10));
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

        // The first run, before any key: there is no admin line to show.
        StateDatabase empty = StateDatabase.InFolder(Path.Combine(root, "pages-empty"));
        List<string> first = await Served(client, announce =>
        {
            PasskeyMethod method = new(new PasskeyStore(empty), settings, () => null);
            EnrollmentTarget target = EnrollmentTarget.For(method, new WebApprover(method, settings, announce, TimeSpan.Zero));

            return new FirstRunPage(empty, target, target, announce, () => null).Run();
        }, admin);
        check(first.Count == 1 && !first[0].Contains("Admins:", StringComparison.Ordinal), "fingerprint page: the first-run page has no admin line before there is an admin");
    }

    /// <summary>
    /// Runs --enroll through both pages: the admin approves, then <paramref name="creator" /> registers, the admin signs the
    /// new manifest on the registration page, and the code is typed. With <paramref name="deny" /> the approval page is denied.
    /// </summary>
    internal static async Task<ApprovalDecision?> Enroll(HttpClient client, StateDatabase db, TestAuthenticator admin, TestAuthenticator creator, string name, bool deny, bool makeAdmin = false, List<string>? replies = null)
    {
        System.Collections.Concurrent.BlockingCollection<string> queue = [];
        System.Collections.Concurrent.BlockingCollection<string?> codes = [];
        ApprovalSettings settings = new(null, 0, TimeSpan.FromSeconds(10));
        PasskeyMethod method = new(new PasskeyStore(db), settings, () => codes.TryTake(out string? code, TimeSpan.FromSeconds(15)) ? code : null);
        EnrollmentTarget target = EnrollmentTarget.For(method, new WebApprover(method, settings, text => queue.Add(text), TimeSpan.Zero));
        Task<ApprovalDecision> task = Task.Run(() => new Enrollment(target, target, text => queue.Add(text), db.Audit).Enroll());
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
            string registration = TestState.Register(creator, challenge, origin, link.IdnHost, name, makeAdmin ? PrfMode.Normal : PrfMode.Missing);
            registration = registration[..^1] + ",\"name\":" + JsonSerializer.Serialize(name) + ",\"admin\":" + (makeAdmin ? "true" : "false") + "}";
            (_, string reply) = TestState.Post(client, url + "/create", registration);
            replies?.Add(page);
            replies?.Add(reply);
            while (RecoveryTests.Member(reply, "next") is { } nextStep)
            {
                link = new Uri(nextStep);
                url = "http://127.0.0.1:" + link.Port + link.AbsolutePath;
                origin = link.GetLeftPart(UriPartial.Authority);
                replies?.Add(TestState.Get(client, url).Body);
                (_, reply) = TestState.Approve(client, url, origin, link.IdnHost, admin);
            }
            reply = TestState.SignStep(client, url, origin, reply, admin);
            replies?.Add(reply);
            using JsonDocument done = JsonDocument.Parse(reply);
            codes.Add(done.RootElement.TryGetProperty("code", out JsonElement code) ? code.GetString() : null);
        }

        Task finished = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(20)));

        return finished == task ? task.Result : null;
    }

    private static IReadOnlyList<AuditRow> Rows(StateDatabase db) => TestAudit.TryRead(db, 100, null, out IReadOnlyList<AuditRow> rows, out _) ? rows : [];

    private static async Task AuditEvents(Action<bool, string> check, HttpClient client, string root)
    {
        using TestAuthenticator admin = TestAuthenticator.ES256();
        using TestAuthenticator tablet = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.ES256();
        StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "events"));
        TestState.Add(db, admin.Record("localhost", "laptop"));
        TestState.Add(db, phone.Record("localhost", "phone"));
        ApprovalSettings settings = new(null, 0, TimeSpan.FromSeconds(10));
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
        check(enrolled is { Approved: false } && Rows(db).Count(row => row.Event == AdminEvent.ChangeDenied && row.Detail.StartsWith("enroll-passkey: ", StringComparison.Ordinal)) == 1, "audit events: a denied --enroll is a change-denied row (" + enrolled?.Detail + ")");
        enrolled = await Enroll(client, db, admin, tablet, "tablet", false);
        AuditRow? added = Rows(db).SingleOrDefault(row => row.Event == "key-enrolled");
        check(enrolled is { Approved: true } && added is { KeyName: "laptop" } && added.Detail.Contains("\"tablet\"", StringComparison.Ordinal) && added.Detail.Contains("admin passkey laptop verified", StringComparison.Ordinal)
            && added.Detail.Contains("(convenience key)", StringComparison.Ordinal), "audit events: --enroll writes key-enrolled with the new key, that it is not an admin, and the approving admin (" + enrolled?.Detail + "; " + added?.Detail + ")");

        // --unenroll: a denial, then a success.
        Func<Action<string>, object?> unenroll = announce => new Enrollment(Targets(announce).Item1, Targets(announce).Item2, announce, db.Audit).Unenroll("phone");
        await Served(client, unenroll, admin, 0);
        check(Rows(db).Count(row => row.Event == AdminEvent.ChangeDenied && row.Detail.StartsWith("unenroll-passkey: ", StringComparison.Ordinal)) == 1, "audit events: a denied --unenroll is a change-denied row");
        await Served(client, unenroll, admin, 1);
        AuditRow? removed = Rows(db).SingleOrDefault(row => row.Event == "key-removed");
        check(removed is { KeyName: "laptop" } && removed.Detail.Contains("\"phone\"", StringComparison.Ordinal) && removed.Detail.Contains("admin passkey laptop verified", StringComparison.Ordinal), "audit events: --unenroll writes key-removed with the removed key and the approving admin (" + removed?.Detail + ")");


        // They are signed events, and no value.
        string shown = StateDatabaseTests.AuditText(db.FilePath);
        check(new[] { "key-enrolled", "key-removed", AdminEvent.ChangeDenied }.All(name => Rows(db).Any(row => row.Event == name)) && !shown.Contains(Secret, StringComparison.Ordinal), "audit events: the key and denial events are all recorded, and no value");
        check(TestAudit.Events(db).All(item => item.Verify(TestAudit.KeyOf(db).PublicKey)), "audit events: every event is signed by the machine key");
        check(TestAudit.MetadataClean(db, [Secret], out _) && TestAudit.Events(db).Any(item => item.Outcome == "key-removed" && item.Meta.GetValueOrDefault("key") == "laptop"
            && item.Meta.GetValueOrDefault("keyId") == TestAuthenticator.Encode(admin.CredentialId) && item.Meta.GetValueOrDefault("keyAdmin") == "true" && item.Meta.ContainsKey("detail")), "audit canary: the metadata of the admin events holds the key name and detail and no value");

        // A refusal with no arcana-guardian.db creates nothing.
        StateDatabase none = StateDatabase.InFolder(Path.Combine(root, "events-none"));
        check(!none.Audit.TryWriteDenied("set-secrets", [], "x") && !File.Exists(none.FilePath), "audit events: a refusal with no arcana-guardian.db creates none");
    }
}

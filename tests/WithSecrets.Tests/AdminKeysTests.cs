using System.Text.Json;

namespace WithSecrets.Tests;

/// <summary>
/// Several admin keys: the "Also make this key an admin" box on the --enroll page, a second admin doing everything the first
/// can (and removing the first), a key that is not an admin doing none of it, and the last admin staying.
/// </summary>
internal static class AdminKeysTests
{
    public static async Task Run(Action<bool, string> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "ws-admins-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(20) };
            await Box(check, client, root);
            await SecondAdmin(check, client, root);
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }

    private static readonly ApprovalSettings Settings = new(null, 0, TimeSpan.FromSeconds(10));

    private static (EnrollmentTarget, EnrollmentTarget) Targets(StateDatabase db, Action<string> announce)
    {
        PasskeyMethod method = new(new PasskeyStore(db), Settings, () => null);
        EnrollmentTarget target = EnrollmentTarget.For(method, new WebApprover(method, Settings, announce, TimeSpan.Zero));

        return (target, target);
    }

    private static Func<Action<string>, object?> Unenroll(StateDatabase db, string name) => announce =>
    {
        (EnrollmentTarget a, EnrollmentTarget b) = Targets(db, announce);

        return new Enrollment(a, b, announce, db.Audit).Unenroll(name);
    };

    private static IReadOnlyList<AuditRow> Rows(StateDatabase db) => TestAudit.TryRead(db, 100, null, out IReadOnlyList<AuditRow> rows, out _) ? rows : [];

    /// <summary>The box: ticked makes the new key an admin in the signed manifest; not ticked (or not sent) does not.</summary>
    private static async Task Box(Action<bool, string> check, HttpClient client, string root)
    {
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.ES256();
        using TestAuthenticator tablet = TestAuthenticator.ES256(prf: false);
        StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "box"));
        DateTimeOffset when = new(2026, 11, 2, 9, 0, 0, TimeSpan.Zero);
        TestState.Add(db, laptop.Record("localhost", "laptop") with { Created = when });

        // Not ticked: the new key only approves runs.
        List<string> replies = [];
        ApprovalDecision? decision = await GrantTests.Enroll(client, db, laptop, tablet, "tablet", false, false, replies);
        check(decision is { Approved: true } && new PasskeyStore(db).All().Single(key => key.Name == "tablet") is { Admin: false, Slot: null } && TestState.Current(db)!.Admins.Count == 1,
            "admin box: without the box, a non-PRF passkey enrolls with no slot (" + decision?.Detail + ")");
        check(replies.Count == 3 && replies[0].Contains("<input id=\"make-admin\" type=\"checkbox\">", StringComparison.Ordinal), "admin box: the enroll page has the box");
        check(Rows(db).Single(row => row.Event == "key-enrolled").Detail.Contains("(convenience key)", StringComparison.Ordinal), "admin box: the audit row says the key is not an admin");

        // Ticked: the manifest the admin signs makes the new key an admin, the page is told, and every admin is listed.
        replies.Clear();
        decision = await GrantTests.Enroll(client, db, laptop, phone, "phone", false, true, replies);
        Manifest current = TestState.Current(db)!;
        string phoneId = TestAuthenticator.Encode(phone.CredentialId);
        check(decision is { Approved: true } && current.Keys.Single(key => key.Id == phoneId).Admin && current.Admins.Count == 2, "admin box: ticked, the new key is an admin (" + decision?.Detail + ")");
        if (replies.Count == 5)
        {
            const string open = "<script type=\"application/json\" id=\"start\">";
            string page = replies[3];
            int start = page.IndexOf(open, StringComparison.Ordinal) + open.Length;
            using JsonDocument step = JsonDocument.Parse(page[start..page.IndexOf("</script>", start, StringComparison.Ordinal)]);
            JsonElement sign = step.RootElement;
            Manifest? signed = Manifest.Parse(sign.GetProperty("manifest").GetString()!, out _);
            check(signed is not null && signed.Keys.Single(key => key.Id == phoneId) is { Admin: true, Slot: not null }
                && page.Contains("The new passkey will be an admin", StringComparison.Ordinal), "admin box: the manifest to sign makes the new key an admin with a slot, and the page says so");
            using JsonDocument payload = JsonDocument.Parse(sign.GetProperty("payload").GetString()!);
            check(!payload.RootElement.TryGetProperty("allowCredentials", out _), "admin box: the sign step names no credential (the server checks the signer is an admin)");
            string expected = "Admins: laptop " + GrantTests.Expected(laptop) + ", phone " + GrantTests.Expected(phone);
            check(page.Contains(expected, StringComparison.Ordinal), "admin box: the confirmation page lists both admins");
            check(AdminKey.Line(db) == expected, "admin box: the fingerprint line lists both admins (" + AdminKey.Line(db) + ")");
        }
        else
        {
            check(false, "admin box: the enroll page answered (" + replies.Count + " replies)");
        }

        check(Rows(db).Any(row => row.Event == "key-enrolled" && row.Detail.Contains("\"phone\"", StringComparison.Ordinal) && row.Detail.Contains("as an admin", StringComparison.Ordinal)), "admin box: the audit row says the key is an admin");

        // With two admins at this host, the enroll page's sign step offers both.
        replies.Clear();
        using TestAuthenticator watch = TestAuthenticator.ES256();
        decision = await GrantTests.Enroll(client, db, phone, watch, "watch", false, false, replies);
        if (replies.Count == 3)
        {
            using JsonDocument step = JsonDocument.Parse(replies[1]);
            check(!step.RootElement.GetProperty("sign").TryGetProperty("allowCredentials", out _), "admin box: the sign step with two admins names no credential");
        }

        check(decision is { Approved: true } && Rows(db).Single(row => row.Event == "key-enrolled" && row.Detail.Contains("\"watch\"", StringComparison.Ordinal)) is { KeyName: "phone" } row
            && row.Detail.Contains("admin passkey phone verified", StringComparison.Ordinal), "admin box: a key enrolled by the second admin names it in the audit row (" + decision?.Detail + ")");
    }

    /// <summary>A second admin can do what the first can, including removing it; a key that is not an admin cannot; the last admin stays.</summary>
    private static async Task SecondAdmin(Action<bool, string> check, HttpClient client, string root)
    {
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.ES256();
        using TestAuthenticator runner = TestAuthenticator.ES256();
        string laptopId = TestAuthenticator.Encode(laptop.CredentialId);
        string phoneId = TestAuthenticator.Encode(phone.CredentialId);
        StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "second"));
        DateTimeOffset when = new(2026, 11, 2, 9, 0, 0, TimeSpan.Zero);
        TestState.Add(db, laptop.Record("localhost", "laptop") with { Created = when });
        TestState.Add(db, phone.Record("localhost", "phone") with { Created = when.AddMinutes(1) }, admin: true);
        TestState.Add(db, runner.Record("localhost", "runner") with { Created = when.AddMinutes(2) });

        // A key that is not an admin cannot enroll or remove anything.
        using TestAuthenticator spare = TestAuthenticator.ES256();
        ApprovalDecision? decision = await GrantTests.Enroll(client, db, runner, spare, "spare", false);
        check(decision is { Approved: false } && new PasskeyStore(db).All().Count == 3, "second admin: a key that is not an admin cannot enroll (" + decision?.Detail + ")");
        await GrantTests.Served(client, Unenroll(db, "laptop"), runner, 1);
        check(new PasskeyStore(db).All().Count == 3, "second admin: a key that is not an admin cannot remove an admin");

        // The second admin enrolls a key.
        decision = await GrantTests.Enroll(client, db, phone, spare, "spare", false);
        check(decision is { Approved: true } && new PasskeyStore(db).All().Count == 4, "second admin: the second admin enrolls a key (" + decision?.Detail + ")");

        // The removal page names no credential (the server accepts only the admins that stay); the second admin removes the first.
        List<string> pages = await GrantTests.Served(client, Unenroll(db, "laptop"), phone, 1);
        string payload = pages.Count == 1 ? Between(pages[0], "\"payload\":", ",\"bind\"") : "";
        check(!payload.Contains(phoneId, StringComparison.Ordinal) && !payload.Contains(laptopId, StringComparison.Ordinal) && !payload.Contains("allowCredentials", StringComparison.Ordinal), "second admin: the removal page names no credential; the server accepts only an admin that stays (" + payload + ")");
        Manifest current = TestState.Current(db)!;
        check(current.Keys.All(key => key.Id != laptopId) && current.Admins.Select(key => key.Name).SequenceEqual(["phone"]) && db.TryCheck(out _), "second admin: the second admin removes the first admin");
        check(AdminKey.Line(db) == "Admins: phone " + GrantTests.Expected(phone), "second admin: the fingerprint line shows the change (" + AdminKey.Line(db) + ")");
        check(Rows(db).Any(row => row.Event == "key-removed" && row.KeyName == "phone" && row.Detail.Contains("\"laptop\"", StringComparison.Ordinal) && row.Detail.Contains("admin passkey phone verified", StringComparison.Ordinal)), "second admin: the audit row names the key removed and the admin that approved it");

        // The removed admin can approve nothing that changes the state.
        decision = await GrantTests.Enroll(client, db, laptop, spare, "spare2", false);
        check(decision is { Approved: false } && new PasskeyStore(db).All().Count == 3, "second admin: the removed admin cannot enroll (" + decision?.Detail + ")");

        // The last admin cannot be removed: refused before anything opens.
        pages = await GrantTests.Served(client, Unenroll(db, "phone"), phone, 1);
        check(pages.Count == 0 && TestState.Current(db)!.Admins.Count == 1 && Rows(db).Any(row => row.Event == AdminEvent.ChangeDenied && row.Detail.Contains(Enrollment.LastAdmin, StringComparison.Ordinal)), "second admin: the last admin cannot be removed, with a clear message");

        // Other keys can still be removed by the admin.
        await GrantTests.Served(client, Unenroll(db, "runner"), phone, 1);
        check(new PasskeyStore(db).All().Select(key => key.Name).Order().SequenceEqual(["phone", "spare"]), "second admin: the remaining admin removes a key that is not an admin");
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
}

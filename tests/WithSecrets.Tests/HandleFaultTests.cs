using System.Diagnostics;
using System.Text.RegularExpressions;

namespace WithSecrets.Tests;

/// <summary>
/// An unexpected exception inside the request handler of any one-shot web session (run approval, enroll, unenroll, revoke,
/// set, remove, settings) ends that session at once: a denial that says "internal error" and no exception text, the page gets
/// 500, any later request gets the already-ended answer, nothing is stored and the program does not wait for the time limit.
/// </summary>
internal static class HandleFaultTests
{
    private const string Boom = "FAULT-TEXT-7731";
    private static readonly Regex Link = new("https?://[^\\s]+", RegexOptions.CultureInvariant);

    private sealed record Kind(string Name, Func<Action<string>, StateDatabase, SecretStore, object?> Call, int Approvals, string? Audit);

    private static volatile bool _armed;

    public static async Task Run(Action<bool, string> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "ws-fault-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        Action<string, string>? saved = HandleGuard.Fault;
        HandleGuard.Fault = (_, _) =>
        {
            if (_armed)
            {
                throw new InvalidOperationException(Boom);
            }
        };
        try
        {
            using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
            client.Timeout = TimeSpan.FromSeconds(20);
            ApprovalSettings settings = new("passkey", null, 0, TimeSpan.FromSeconds(30));

            (EnrollmentTarget, EnrollmentTarget) Targets(StateDatabase db, Action<string> announce)
            {
                PasskeyMethod method = new(new PasskeyStore(db), settings, () => null);
                EnrollmentTarget target = EnrollmentTarget.For(method, new WebApprover(method, settings, announce, TimeSpan.Zero));

                return (target, target);
            }

            Kind[] kinds =
            [
                new("run approval", (announce, db, _) => Targets(db, announce).Item1.Approver.Request(new ApprovalRequest("tool", "/bin/tool", [], "/work", "r", ["OLD_NAME"], null, null, null, "REQ")), 0, null),
                new("enroll approval", (announce, db, _) => new Enrollment(Targets(db, announce).Item1, Targets(db, announce).Item2, announce, new AuditLog(db)).Enroll(), 0, "--enroll: "),
                new("enroll page", (announce, db, _) => new Enrollment(Targets(db, announce).Item1, Targets(db, announce).Item2, announce, new AuditLog(db)).Enroll(), 1, "--enroll: "),
                new("unenroll", (announce, db, _) => new Enrollment(Targets(db, announce).Item1, Targets(db, announce).Item2, announce, new AuditLog(db)).Unenroll("phone"), 0, "--unenroll: "),
                new("set", (announce, db, secrets) => new SecretEntry(Targets(db, announce).Item1, Targets(db, announce).Item2, secrets, new AuditLog(db), announce).Set(["NEW_NAME"]), 0, "--set: "),
                new("remove", (announce, db, secrets) => new SecretEntry(Targets(db, announce).Item1, Targets(db, announce).Item2, secrets, new AuditLog(db), announce).Remove(["OLD_NAME"]), 0, "--remove: "),
                new("config", (announce, db, _) => new SettingsPage(db, Targets(db, announce).Item1, Targets(db, announce).Item2, announce, () => null).Run(), 0, "--config: "),
                new("revoke", (announce, db, _) => Revocation.Run(db, Targets(db, announce).Item1, Targets(db, announce).Item2, new GrantStore(db)), 0, "--revoke: "),
            ];

            foreach (Kind kind in kinds)
            {
                await One(check, client, root, kind);
            }
        }
        finally
        {
            _armed = false;
            HandleGuard.Fault = saved;
            Directory.Delete(root, true);
        }
    }

    private static async Task One(Action<bool, string> check, HttpClient client, string root, Kind kind)
    {
        using TestAuthenticator admin = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.ES256();
        StateDatabase db = StateDatabase.InFolder(Path.Combine(root, kind.Name.Replace(' ', '-')));
        TestState.Add(db, admin.Record("localhost", "laptop"));
        TestState.Add(db, phone.Record("localhost", "phone"));
        SecretStore secrets = new(db);
        SecretStoreTests.Put(secrets, new Dictionary<string, string> { ["OLD_NAME"] = "Fault-Secret-1" });
        new GrantStore(db).Add("K", 10, "laptop");

        long version = TestState.Current(db)?.Version ?? 0;
        int keys = new PasskeyStore(db).All().Count;
        string[] names = [.. secrets.ListNames()];
        int grants = new GrantStore(db).Entries().Count;
        int auditBefore = Rows(db).Count;

        _armed = false;
        System.Collections.Concurrent.BlockingCollection<string> queue = [];
        List<string> lines = [];
        Stopwatch clock = Stopwatch.StartNew();
        Task<object?> task = Task.Run(() => kind.Call(queue.Add, db, secrets));
        int approved = 0;
        int faulted = 0;
        int again = -2;
        DateTime stop = DateTime.UtcNow.AddSeconds(25);
        while (!task.IsCompleted && DateTime.UtcNow < stop)
        {
            if (!queue.TryTake(out string? line, 200))
            {
                continue;
            }

            lines.Add(line);
            if (Link.Match(line) is not { Success: true } match)
            {
                continue;
            }

            Uri link = new(match.Value);
            string url = "http://127.0.0.1:" + link.Port + link.AbsolutePath;
            bool moved = false;
            while (link.AbsolutePath.StartsWith("/a/", StringComparison.Ordinal) && approved < kind.Approvals)
            {
                approved++;
                (_, string reply) = TestState.Approve(client, url, link.GetLeftPart(UriPartial.Authority), link.IdnHost, admin);
                moved = true;

                // The approval leads to the next page by itself (no second link in the terminal).
                if (RecoveryTests.Member(reply, "next") is not { } next)
                {
                    break;
                }

                link = new Uri(next);
                url = "http://127.0.0.1:" + link.Port + link.AbsolutePath;
            }

            if (moved && !link.AbsolutePath.StartsWith("/e/", StringComparison.Ordinal))
            {
                continue;
            }

            // The page loads, then the next request meets the fault.
            TestState.Get(client, url);
            _armed = true;
            faulted = TestState.Post(client, url + "/deny", "").Status;
            again = TestState.Post(client, url + "/deny", "").Status;
        }

        Task done = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(5)));
        _armed = false;
        bool prompt = done == task && clock.Elapsed < TimeSpan.FromSeconds(20);
        string label = "handler fault: " + kind.Name + ": ";
        check(prompt, label + "the command returns promptly, long before the 30 second limit (" + clock.Elapsed.TotalSeconds.ToString("F1", System.Globalization.CultureInfo.InvariantCulture) + " s)");
        check(faulted == 500, label + "the request that met the fault got 500 (" + faulted + ")");
        check(again is 404 or 0, label + "a further request gets the already-ended answer (" + again + ")");
        if (!prompt)
        {
            return;
        }

        (bool failed, int? code, string detail) = task.Result switch
        {
            ApprovalDecision decision => (!decision.Approved, (int?)null, decision.Detail),
            SecretChange change => (!change.Done, (int?)change.Code, change.Detail),
            ConfigChange change => (!change.Done, (int?)change.Code, change.Detail),
            ValueTuple<int, string> pair => (pair.Item1 != 0, (int?)pair.Item1, pair.Item2),
            _ => (false, (int?)null, ""),
        };
        check(failed && detail.Contains(HandleGuard.Reason, StringComparison.Ordinal), label + "the outcome is a denial that says internal error (" + detail + ")");
        check(code is null || code == RunCommand.Denied, label + "the exit code is the existing denied code (" + code + ")");
        check(!detail.Contains(Boom, StringComparison.Ordinal) && !lines.Any(item => item.Contains(Boom, StringComparison.Ordinal)), label + "no exception text in the outcome or the terminal lines");
        check((TestState.Current(db)?.Version ?? 0) == version && new PasskeyStore(db).All().Count == keys && secrets.ListNames().SequenceEqual(names) && new GrantStore(db).Entries().Count == grants, label + "nothing is stored or changed");
        if (kind.Audit is not null)
        {
            IReadOnlyList<AuditRecord> rows = Rows(db);
            check(rows.Count == auditBefore + 1 && rows[^1].Event == AuditLog.ChangeDenied && rows[^1].Detail.StartsWith(kind.Audit, StringComparison.Ordinal) && !rows[^1].Detail.Contains(Boom, StringComparison.Ordinal), label + "the audit row is change-denied (" + (rows.Count > 0 ? rows[^1].Event + " " + rows[^1].Detail : "none") + ")");
        }
    }

    private static IReadOnlyList<AuditRecord> Rows(StateDatabase db) => new AuditLog(db).TryRead(100, null, out IReadOnlyList<AuditRecord> rows, out _) ? rows : [];
}

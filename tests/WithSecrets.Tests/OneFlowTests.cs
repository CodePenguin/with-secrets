using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;

using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>
/// One workflow per command: a command prints ONE link, and every step after the first is reached from the page itself by a
/// <c>next</c> member in the reply of the step before (created only after that step verified). Driven over real HTTP with
/// software passkeys. <c>--recover</c> and <c>--rotate-key</c> are also covered in <see cref="RecoveryTests" />.
/// </summary>
internal static class OneFlowTests
{
    private static readonly Regex Json = new("<script type=\"application/json\" id=\"options\">(.*?)</script>", RegexOptions.Singleline | RegexOptions.CultureInvariant);

    public static async Task Run(Action<bool, string> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "ws-oneflow-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            await SameHostEnroll(check, root);
            await CrossHostEnroll(check, root);
            await Safety(check, root);
            await PromptLast(check, root);
            await Resend(check, root);
            await Ended(check);
            Pages(check);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            Directory.Delete(root, true);
        }
    }

    /// <summary>A command running on a task: every terminal line, the links among them, and a queue of codes typed in the terminal.</summary>
    private sealed class Rig
    {
        private readonly BlockingCollection<string> _links = [];
        private readonly BlockingCollection<string?> _codes = [];
        private int _asked;

        public Rig(Func<Action<string>, Func<string?>, ApprovalDecision> run)
        {
            Running = Task.Run(() => run(line =>
            {
                lock (Lines)
                {
                    Lines.Add(line);
                }

                _links.Add(line);
            }, () =>
            {
                Interlocked.Increment(ref _asked);

                return _codes.TryTake(out string? code, TimeSpan.FromSeconds(30)) ? code : null;
            }));
        }

        public List<string> Lines { get; } = [];

        public Task<ApprovalDecision> Running { get; }

        /// <summary>How many times the terminal asked for the code.</summary>
        public int Asked => Volatile.Read(ref _asked);

        public void Type(string? code) => _codes.Add(code);

        public (string Url, string Origin)? First()
        {
            DateTime stop = DateTime.UtcNow.AddSeconds(25);
            while (DateTime.UtcNow < stop)
            {
                if (_links.TryTake(out string? line, 200) && line.Contains("http", StringComparison.Ordinal))
                {
                    return Map(line[line.IndexOf("http", StringComparison.Ordinal)..]);
                }

                if (Running.IsCompleted)
                {
                    return null;
                }
            }

            return null;
        }

        public ApprovalDecision Result() => Running.Wait(TimeSpan.FromSeconds(30)) ? Running.Result : ApprovalDecision.Deny("timed out");

        public int Links
        {
            get
            {
                lock (Lines)
                {
                    return RecoveryTests.LinkLines(Lines);
                }
            }
        }

        public string All
        {
            get
            {
                lock (Lines)
                {
                    return string.Join("\n", Lines);
                }
            }
        }
    }

    /// <summary>The URL the test client uses (loopback, plain http) and the origin the page signs for.</summary>
    private static (string Url, string Origin) Map(string link)
    {
        Uri uri = new(link);

        return ("http://127.0.0.1:" + uri.Port + uri.AbsolutePath, uri.GetLeftPart(UriPartial.Authority));
    }

    private static (string Url, string Origin)? Next(string reply) => RecoveryTests.NextLink(reply);

    private static int FreePort()
    {
        using TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start();

        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private static (EnrollmentTarget Target, PasskeyMethod Method) Target(StateDatabase db, ApprovalSettings settings, Action<string> announce, Func<string?> read)
    {
        PasskeyMethod method = new(new PasskeyStore(db), settings, read);

        return (EnrollmentTarget.For(method, new WebApprover(method, settings, announce, TimeSpan.Zero)), method);
    }

    /// <summary>The enrollment page as the browser makes the registration: reads the options, registers <paramref name="creator" />, posts it.</summary>
    private static (string Page, string Reply) Create(HttpClient client, (string Url, string Origin) link, TestAuthenticator creator, string rpId, string name, bool admin)
    {
        (_, string page) = TestState.Get(client, link.Url);
        Match options = Json.Match(page);
        using JsonDocument document = JsonDocument.Parse(options.Groups[1].Value);
        byte[] challenge = Base64Url.DecodeFromChars(document.RootElement.GetProperty("challenge").GetString()!);
        TestState.Note(document.RootElement);
        string registration = TestState.Register(creator, challenge, link.Origin, rpId, name);
        registration = registration[..^1] + ",\"name\":" + JsonSerializer.Serialize(name) + ",\"admin\":" + (admin ? "true" : "false") + "}";

        LastCreate = registration;

        return (page, TestState.Post(client, link.Url + "/create", registration).Body);
    }

    /// <summary>The body of the last registration that <see cref="Create" /> posted.</summary>
    private static string LastCreate { get; set; } = "";

    private static HttpClient Client() => RecoveryTests.NewClient();

    // ---------------------------------------------------------------------------------------------------------------
    // --enroll, the admin key works at this host
    // ---------------------------------------------------------------------------------------------------------------

    private static async Task SameHostEnroll(Action<bool, string> check, string root)
    {
        using HttpClient client = Client();
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.RS256();
        RecoveryTests.World w = RecoveryTests.NewWorld(root, laptop);
        ApprovalSettings settings = new("passkey", null, 0, TimeSpan.FromSeconds(20));
        Rig rig = new((announce, read) =>
        {
            (EnrollmentTarget target, _) = Target(w.Db, settings, announce, read);

            return new Enrollment(target, target, announce, new AuditLog(w.Db)).Enroll();
        });

        (string Url, string Origin)? one = rig.First();
        string pageOne = one is null ? "" : TestState.Get(client, one.Value.Url).Body;

        // The pages after the first have tokens nobody knows yet: a guess, or the first token under another page's path, finds nothing.
        string token = one is null ? "x" : one.Value.Url[(one.Value.Url.LastIndexOf('/') + 1)..];
        string host = one is null ? "" : one.Value.Url[..one.Value.Url.IndexOf("/a/", StringComparison.Ordinal)];
        int guess = one is null ? 0 : TestState.Get(client, host + "/e/" + Base64Url.EncodeToString(Guid.NewGuid().ToByteArray())).Status;
        int moved = one is null ? 0 : TestState.Get(client, host + "/e/" + token).Status;
        check(guess == 404 && moved == 404, "enroll one flow: the next page's token is unknown before step 1 verified: a guess or the first token on the enrollment path is 404 (" + guess + ", " + moved + ")");

        (int status1, string body1) = one is null ? (0, "") : TestState.Approve(client, one.Value.Url, one.Value.Origin, "localhost", laptop);
        (string Url, string Origin)? two = Next(body1);
        check(status1 == 200 && two is not null && two.Value.Url.Contains("/e/", StringComparison.Ordinal) && one is not null && new Uri(one.Value.Url).Port == new Uri(two.Value.Url).Port, "enroll one flow: the approval reply carries next, the enrollment page on the same port (" + body1 + ")");
        string proofOne = TestState.LastProofBody;
        (int resent1, string resentBody1) = one is null ? (0, "") : TestState.Post(client, one.Value.Url + "/proof", proofOne);
        int other1 = one is null ? 0 : TestState.Post(client, one.Value.Url + "/proof", proofOne + " ").Status;
        check(resent1 == 200 && resentBody1 == body1 && other1 == 404, "enroll one flow: the same approval sent again after step 2 started gets the same reply (same next), any other body gets 404 (" + resent1 + ", " + other1 + ")");

        (string page, string reply) = two is null ? ("", "") : Create(client, two.Value, phone, "localhost", "phone", false);
        check(reply.Contains("\"sign\"", StringComparison.Ordinal) && !reply.Contains("\"next\"", StringComparison.Ordinal), "enroll one flow: with an admin key at this host the create reply asks for Step 2 on the same page and has no next");
        string signed = two is null ? "" : TestState.SignStep(client, two.Value.Url, two.Value.Origin, reply, laptop);
        string? code = RecoveryTests.Member(signed, "code");
        bool oneKeyBeforeCode = new PasskeyStore(w.Db).All().Count == 1;
        check(code is not null && rig.Asked <= 1 && oneKeyBeforeCode && !rig.Running.IsCompleted, "enroll one flow: nothing is stored before the code is typed (" + rig.Asked + " asked)");
        rig.Type(code);
        ApprovalDecision result = rig.Result();
        SqliteConnection.ClearAllPools();
        check(result.Approved && new PasskeyStore(w.Db).All().Select(item => item.Name).SequenceEqual(["laptop", "phone"]), "enroll one flow: done, the key is added (" + result.Detail + ")");
        check(rig.Links == 1 && !RecoveryTests.Holds([rig.All, pageOne, page, reply, signed, result.Detail], ["Go back to the terminal", "go back to the terminal"]), "enroll one flow: the terminal gets exactly one link line (" + rig.Links + ")");
        check(RecoveryTests.Holds([page], ["Otherwise the terminal shows a link"]) is false, "enroll one flow: the enrollment page no longer sends the person to the terminal for a link");
    }

    // ---------------------------------------------------------------------------------------------------------------
    // --enroll, the admin key works only at another host
    // ---------------------------------------------------------------------------------------------------------------

    private static async Task CrossHostEnroll(Action<bool, string> check, string root)
    {
        using HttpClient client = Client();
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.RS256();
        foreach (bool admin in new[] { false, true })
        {
            RecoveryTests.World w = RecoveryTests.NewWorld(root, laptop);
            int port = FreePort();
            ApprovalSettings remote = new("passkey", "https://ws.example.com:" + port, port, TimeSpan.FromSeconds(20));
            ApprovalSettings localOnly = remote with { BaseUrl = null };
            int codeAskedAtSign = -1;
            Rig rig = new((announce, read) =>
            {
                (EnrollmentTarget primary, _) = Target(w.Db, remote, announce, read);
                (EnrollmentTarget other, _) = Target(w.Db, localOnly, announce, read);

                return new Enrollment(primary, other, announce, new AuditLog(w.Db)).Enroll();
            });

            // The command target is the baseUrl host; the admin key works only at localhost, so the approval and the signature are there.
            (string Url, string Origin)? one = rig.First();
            string pageOne = one is null ? "" : TestState.Get(client, one.Value.Url).Body;
            (int status1, string body1) = one is null ? (0, "") : TestState.Approve(client, one.Value.Url, one.Value.Origin, "localhost", laptop);
            string? next1 = RecoveryTests.Member(body1, "next");
            (string Url, string Origin)? two = Next(body1);
            check(status1 == 200 && next1 is not null && new Uri(next1).Host == "ws.example.com" && new Uri(next1).Port == port && next1.Contains("/e/", StringComparison.Ordinal), "enroll cross host: the approval reply's next is the enrollment page at the baseUrl host (" + next1 + ")");

            (string page, string reply) = two is null ? ("", "") : Create(client, two.Value, phone, "ws.example.com", "phone", admin);
            string? next2 = RecoveryTests.Member(reply, "next");
            (string Url, string Origin)? three = Next(reply);
            check(next2 is not null && new Uri(next2).Host == "localhost" && new Uri(next2).Port == port && next2.Contains("/a/", StringComparison.Ordinal) && !reply.Contains("\"code\"", StringComparison.Ordinal), "enroll cross host: the create reply's next is the admin signing page at the admin key's host, and holds no code (" + reply + ")");
            check(rig.Asked == 0 && new PasskeyStore(w.Db).All().Count == 1, "enroll cross host: the terminal has not asked for the code, nothing is stored, before the admin signed");

            string pageThree = three is null ? "" : TestState.Get(client, three.Value.Url).Body;
            (int status3, string body3) = three is null ? (0, "") : TestState.Approve(client, three.Value.Url, three.Value.Origin, "localhost", laptop);
            codeAskedAtSign = rig.Asked;
            string? code = RecoveryTests.Member(body3, "code");
            check(status3 == 200 && code is not null && Regex.IsMatch(code, "^[0-9]{6}$") && pageThree.Contains(admin ? "The new passkey will be an admin" : "The new passkey will only approve runs (not an admin)", StringComparison.Ordinal),
                "enroll cross host: the admin page reads what will be signed and its final reply has the code (" + body3 + ")");
            check(!RecoveryTests.Holds([pageThree], [code ?? "none"]) && !RecoveryTests.Holds([rig.All], [code ?? "none"]), "enroll cross host: the code is in no page before the last and in no terminal line");
            check(new PasskeyStore(w.Db).All().Count == 1, "enroll cross host: still nothing stored while the code waits for the terminal");
            rig.Type(code);
            ApprovalDecision result = rig.Result();
            SqliteConnection.ClearAllPools();
            PasskeyStore store = new(w.Db);
            check(result.Approved && store.All().Select(item => (item.Name, item.RpId, item.Admin)).SequenceEqual([("laptop", "localhost", true), ("phone", "ws.example.com", admin)]), "enroll cross host: done, the new key is for the baseUrl host (admin=" + admin + "; " + result.Detail + ")");
            check(rig.Links == 1 && !RecoveryTests.Holds([rig.All, pageOne, page, reply, pageThree, body3, result.Detail], ["Go back to the terminal", "go back to the terminal"]) && codeAskedAtSign <= 1, "enroll cross host: the terminal gets exactly one link line (" + rig.Links + ")");
        }

        await Task.CompletedTask;
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Safety
    // ---------------------------------------------------------------------------------------------------------------

    private static async Task Safety(Action<bool, string> check, string root)
    {
        using HttpClient client = Client();
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.RS256();
        using TestAuthenticator viewer = TestAuthenticator.ES256();

        // A failed step gives no next, and the flow ends with nothing stored (rotate-key, enroll: a key that is not an admin; recover: a wrong code).
        {
            RecoveryTests.World w = RecoveryTests.NewWorld(root, laptop, phone, viewer);
            string before = RecoveryTests.Snapshot(w.Db);
            RecoveryTests.Flow flow = RecoveryTests.StartRotate(w);
            (string Url, string Origin)? one = flow.Next();
            (int status, string body) = one is null ? (0, "") : TestState.Approve(client, one.Value.Url, one.Value.Origin, "localhost", viewer);
            ConfigChange result = flow.Result();
            check(status != 200 && !body.Contains("next", StringComparison.Ordinal) && result.Code != 0 && RecoveryTests.Snapshot(w.Db) == before, "one flow safety: a rotate-key tap by a key that is not an admin gets no next and changes nothing (" + status + "; " + body + ")");
            check(flow.Next() is null && RecoveryTests.LinkLines(flow.Lines) == 1, "one flow safety: no second link appears after the failed tap");
        }

        {
            RecoveryTests.World w = RecoveryTests.NewWorld(root, laptop);
            RecoveryTests.Flow flow = RecoveryTests.StartRecover(w.Db);
            (string Url, string Origin)? one = flow.Next();
            (int status, string body) = one is null ? (0, "") : RecoveryTests.SendCode(client, one.Value, RecoveryCode.Format(KeyVault.NewRecoveryCode()));
            check(status == 400 && !body.Contains("next", StringComparison.Ordinal), "one flow safety: a wrong recovery code gets no next (" + status + "; " + body + ")");
            (_, string good) = one is null ? (0, "") : RecoveryTests.SendCode(client, one.Value, w.Code);
            check(Next(good) is not null, "one flow safety: the right code on the same page then gets next");
            (string Url, string Origin)? two = Next(good);
            if (two is not null)
            {
                TestState.Get(client, two.Value.Url);
                TestState.Post(client, two.Value.Url + "/deny", "");
            }

            ConfigChange result = flow.Result();
            check(result.Code != 0 && RecoveryTests.Files(w.Folder).SequenceEqual(["state.db"]), "one flow safety: Cancel on the page reached by next ends the command and stores nothing (" + result.Detail + ")");
        }

        // The page reached by next is one-use: once its step is done, its token finds nothing; and the link before it stays dead.
        {
            RecoveryTests.World w = RecoveryTests.NewWorld(root, laptop);
            RecoveryTests.Flow flow = RecoveryTests.StartRotate(w);
            (string Url, string Origin)? one = flow.Next();
            (_, string body1) = one is null ? (0, "") : TestState.Approve(client, one.Value.Url, one.Value.Origin, "localhost", laptop);
            (string Url, string Origin)? two = Next(body1);
            int firstGet = two is null ? 0 : TestState.Get(client, two.Value.Url).Status;
            (int status2, _) = two is null ? (0, "") : TestState.Approve(client, two.Value.Url, two.Value.Origin, "localhost", laptop);
            flow.Result();
            int again = two is null ? 0 : TestState.Post(client, two.Value.Url + "/proof", TestState.LastProofBody).Status;
            check(firstGet == 200 && status2 == 200 && again is 404 or 0, "one flow safety: the page reached by next is served until its step is done, then it finds nothing (" + firstGet + ", " + status2 + ", " + again + ")");
        }

        // The time limit is the command's, not each step's: step 2 gets what is left.
        {
            RecoveryTests.World w = RecoveryTests.NewWorld(root, laptop);
            string before = RecoveryTests.Snapshot(w.Db);
            ApprovalSettings quick = new("passkey", null, 0, TimeSpan.FromSeconds(4));
            RecoveryTests.Flow flow = RecoveryTests.StartRotate(w, null, quick);
            (string Url, string Origin)? one = flow.Next();
            System.Diagnostics.Stopwatch clock = System.Diagnostics.Stopwatch.StartNew();
            Thread.Sleep(2500);
            (_, string body1) = one is null ? (0, "") : TestState.Approve(client, one.Value.Url, one.Value.Origin, "localhost", laptop);
            ConfigChange result = flow.Result();
            clock.Stop();
            check(result.Code != 0 && clock.Elapsed < TimeSpan.FromSeconds(5) && RecoveryTests.Snapshot(w.Db) == before, "one flow safety: the limit is shared; step 2 gets only what step 1 left (" + clock.Elapsed.TotalSeconds.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture) + " s; " + result.Detail + ")");
        }

        await Task.CompletedTask;
    }

    // ---------------------------------------------------------------------------------------------------------------
    // The prompt for the typed code is the last thing on the terminal while it waits
    // ---------------------------------------------------------------------------------------------------------------

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

    private static string Unix(StringWriter output) => Snapshot(output).Replace("\r\n", "\n", StringComparison.Ordinal);

    private static string Snapshot(StringWriter output)
    {
        lock (output)
        {
            return output.ToString();
        }
    }

    private static async Task PromptLast(Action<bool, string> check, string root)
    {
        StringWriter output = new();
        BlockingCollection<string?> typed = [];
        TerminalPrompt.Output = output;
        TerminalPrompt.Input = () => typed.Take();
        try
        {
            // The gate itself: lines that arrive while the prompt waits are held (diagnostics dropped) and shown after Enter.
            Task<string?> reading = Task.Run(() => TerminalPrompt.ReadCode(false));
            WaitFor(() => Snapshot(output).EndsWith(TerminalPrompt.Waiting, StringComparison.Ordinal));
            TerminalPrompt.Line("with-secrets: a late line");
            TerminalPrompt.Noise("with-secrets: connection opened (1 s)");
            string during = Snapshot(output);
            check(during == TerminalPrompt.Waiting, "prompt: the prompt is the only text, with no new line after it, while it waits (" + during + ")");
            typed.Add("111111");
            check(reading.Wait(TimeSpan.FromSeconds(10)) && reading.Result == "111111", "prompt: the typed line is returned");
            string after = Snapshot(output);
            check(after.IndexOf("a late line", StringComparison.Ordinal) > after.IndexOf("Paste it here", StringComparison.Ordinal) && !after.Contains("connection opened", StringComparison.Ordinal), "prompt: the held line is shown after Enter and the diagnostic is dropped");
            check(TerminalPrompt.Waiting.EndsWith(": ", StringComparison.Ordinal) && !TerminalPrompt.Waiting.Contains('\n') && TerminalPrompt.Waiting.StartsWith("Waiting for the code from the page. Paste it here and press Enter", StringComparison.Ordinal), "prompt: the text names the page and Enter and ends so that the cursor stays on its line");

            // The whole --enroll flow, with the real gate as terminal: after the last tap the prompt is last, whatever the network does.
            output.GetStringBuilder().Clear();
            using HttpClient client = Client();
            using TestAuthenticator laptop = TestAuthenticator.ES256();
            using TestAuthenticator phone = TestAuthenticator.RS256();
            RecoveryTests.World w = RecoveryTests.NewWorld(root, laptop);
            ApprovalSettings settings = new("passkey", null, 0, TimeSpan.FromSeconds(20));
            int asked = 0;
            Rig rig = new((announce, unused) =>
            {
                Action<string> both = line =>
                {
                    announce(line);
                    TerminalPrompt.Line(line);
                };
                (EnrollmentTarget target, _) = Target(w.Db, settings, both, () => TerminalPrompt.ReadCode(asked++ > 0));

                return new Enrollment(target, target, both, new AuditLog(w.Db)).Enroll();
            });
            (string Url, string Origin)? one = rig.First();
            (_, string body1) = one is null ? (0, "") : TestState.Approve(client, one.Value.Url, one.Value.Origin, "localhost", laptop);
            (string Url, string Origin)? two = Next(body1);
            (string _, string reply) = two is null ? ("", "") : Create(client, two.Value, phone, "localhost", "phone", false);
            string signed = two is null ? "" : TestState.SignStep(client, two.Value.Url, two.Value.Origin, reply, laptop);
            string? code = RecoveryTests.Member(signed, "code");
            bool shown = WaitFor(() => Snapshot(output).EndsWith(TerminalPrompt.Waiting, StringComparison.Ordinal));
            if (two is not null)
            {
                TestState.Get(client, two.Value.Url);
                TestState.Post(client, two.Value.Url + "/sign", "{}");
            }

            Thread.Sleep(300);
            string waiting = Snapshot(output);
            check(shown && waiting.EndsWith(TerminalPrompt.Waiting, StringComparison.Ordinal) && waiting.Split(TerminalPrompt.Waiting).Length == 2, "prompt: in the --enroll flow the last text before the typing is the prompt, shown once, with no line after it");
            typed.Add(code);
            ApprovalDecision result = rig.Result();
            check(result.Approved && !Snapshot(output).Contains(code ?? "none", StringComparison.Ordinal), "prompt: the flow finishes after the code and the code is never printed");
        }
        finally
        {
            TerminalPrompt.Output = null;
            TerminalPrompt.Input = null;
        }

        await Task.CompletedTask;
    }

    // ---------------------------------------------------------------------------------------------------------------
    // A lost reply of a verified step: the same body sent again gets the same reply; any other body gets 404
    // ---------------------------------------------------------------------------------------------------------------

    private static async Task Resend(Action<bool, string> check, string root)
    {
        using HttpClient client = Client();
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.RS256();

        // Rotate, step 1: tap 1 verified; its reply (next) is "lost"; the identical body gets the same next, before and after step 2 started.
        {
            RecoveryTests.World w = RecoveryTests.NewWorld(root, laptop, phone);
            RecoveryTests.Flow flow = RecoveryTests.StartRotate(w);
            (string Url, string Origin)? one = flow.Next();
            (int status1, string body1) = one is null ? (0, "") : TestState.Approve(client, one.Value.Url, one.Value.Origin, "localhost", laptop);
            string proof = TestState.LastProofBody;
            (string Url, string Origin)? two = Next(body1);
            (int again, string againBody) = one is null ? (0, "") : TestState.Post(client, one.Value.Url + "/proof", proof);
            int other = one is null ? 0 : TestState.Post(client, one.Value.Url + "/proof", proof + " ").Status;
            int otherPath = one is null ? 0 : TestState.Post(client, one.Value.Url + "/deny", proof).Status;
            check(status1 == 200 && two is not null && again == 200 && againBody == body1 && other == 404 && otherPath == 404, "resend rotate: the same tap-1 body gets the same next, another body and another path get 404 (" + again + ", " + other + ", " + otherPath + ")");
            int page2 = two is null ? 0 : TestState.Get(client, two.Value.Url).Status;
            (int late, string lateBody) = one is null ? (0, "") : TestState.Post(client, one.Value.Url + "/proof", proof);
            check(page2 == 200 && late == 200 && lateBody == body1, "resend rotate: after step 2 started the same body still gets the same reply (" + late + ")");
            (int status2, string body2) = two is null ? (0, "") : TestState.Approve(client, two.Value.Url, two.Value.Origin, "localhost", laptop);
            string proof2 = TestState.LastProofBody;
            (int late2, string lateBody2) = two is null ? (0, "") : TestState.Post(client, two.Value.Url + "/proof", proof2);
            (int last, string lastBody) = one is null ? (0, "") : TestState.Post(client, one.Value.Url + "/proof", proof);
            ConfigChange result = flow.Result();
            SqliteConnection.ClearAllPools();
            check(status2 == 200 && result.Code == 0 && RecoveryTests.LinkLines(flow.Lines) == 1, "resend rotate: the command finished once with one link (" + result.Detail + ")");
            check((late2 != 200 || lateBody2 == body2) && (last != 200 || lastBody == body1), "resend rotate: a resend of the last step is the same reply, never a second recovery code (" + late2 + ", " + last + ")");
        }

        // Recover, the code step: the same sealed code sent again gets the same next and opens nothing twice.
        {
            RecoveryTests.World w = RecoveryTests.NewWorld(root, laptop);
            RecoveryTests.Flow flow = RecoveryTests.StartRecover(w.Db);
            (string Url, string Origin)? one = flow.Next();
            string page = one is null ? "" : TestState.Get(client, one.Value.Url).Body;
            string sealedBody = one is null ? "" : RecoveryTests.SealedCode(RecoveryTests.StartOf(page), w.Code);
            (int status, string reply) = one is null ? (0, "") : TestState.Post(client, one.Value.Url + "/code", sealedBody);
            (string Url, string Origin)? two = Next(reply);
            (int again, string againReply) = one is null ? (0, "") : TestState.Post(client, one.Value.Url + "/code", sealedBody);
            int other = one is null ? 0 : TestState.Post(client, one.Value.Url + "/code", RecoveryTests.SealedCode(RecoveryTests.StartOf(page), w.Code)).Status;
            check(status == 200 && two is not null && again == 200 && againReply == reply && other == 404, "resend recover: the same sealed code gets the same next, a freshly sealed one gets 404 (" + again + ", " + other + ")");
            int page2 = two is null ? 0 : TestState.Get(client, two.Value.Url).Status;
            (int late, string lateReply) = one is null ? (0, "") : TestState.Post(client, one.Value.Url + "/code", sealedBody);
            check(page2 == 200 && late == 200 && lateReply == reply && RecoveryTests.LinkLines(flow.Lines) == 1, "resend recover: after the new passkey page started the same body still gets the same reply and no second link appears (" + late + ")");
            if (two is not null)
            {
                TestState.Post(client, two.Value.Url + "/deny", "");
            }

            flow.Result();
        }

        // Cross-host enroll: the create reply (next) and the admin page's final reply (the code) are kept for their own bodies.
        {
            RecoveryTests.World w = RecoveryTests.NewWorld(root, laptop);
            int port = FreePort();
            ApprovalSettings remote = new("passkey", "https://ws.example.com:" + port, port, TimeSpan.FromSeconds(20));
            ApprovalSettings localOnly = remote with { BaseUrl = null };
            Rig rig = new((announce, read) =>
            {
                (EnrollmentTarget primary, _) = Target(w.Db, remote, announce, read);
                (EnrollmentTarget other, _) = Target(w.Db, localOnly, announce, read);

                return new Enrollment(primary, other, announce, new AuditLog(w.Db)).Enroll();
            });
            (string Url, string Origin)? one = rig.First();
            (_, string body1) = one is null ? (0, "") : TestState.Approve(client, one.Value.Url, one.Value.Origin, "localhost", laptop);
            (string Url, string Origin)? two = Next(body1);
            (_, string reply) = two is null ? ("", "") : Create(client, two.Value, phone, "ws.example.com", "phone", false);
            string created = LastCreate;
            (string Url, string Origin)? three = Next(reply);
            (int again, string againReply) = two is null ? (0, "") : TestState.Post(client, two.Value.Url + "/create", created);
            int other = two is null ? 0 : TestState.Post(client, two.Value.Url + "/create", created + " ").Status;
            check(three is not null && again == 200 && againReply == reply && other == 404 && !reply.Contains("\"code\"", StringComparison.Ordinal), "resend enroll: the same create body gets the same next (and no code), another body gets 404 (" + again + ", " + other + ")");
            int page3 = three is null ? 0 : TestState.Get(client, three.Value.Url).Status;
            (int late, string lateReply) = two is null ? (0, "") : TestState.Post(client, two.Value.Url + "/create", created);
            check(page3 == 200 && late == 200 && lateReply == reply && rig.Links == 1, "resend enroll: after the admin page started the same create body still gets the same reply, no second page (" + late + ")");
            (_, string body3) = three is null ? (0, "") : TestState.Approve(client, three.Value.Url, three.Value.Origin, "localhost", laptop);
            string proof3 = TestState.LastProofBody;
            string? code = RecoveryTests.Member(body3, "code");
            (int lostCode, string lostBody) = three is null ? (0, "") : TestState.Post(client, three.Value.Url + "/proof", proof3);
            int otherProof = three is null ? 0 : TestState.Post(client, three.Value.Url + "/proof", proof3 + " ").Status;
            check(code is not null && lostCode == 200 && lostBody == body3 && RecoveryTests.Member(lostBody, "code") == code && otherProof == 404, "resend enroll: the admin page's final proof sent again gets the same code, never a second one (" + lostCode + ", " + otherProof + ")");
            (int lateCreate, string lateCreateReply) = two is null ? (0, "") : TestState.Post(client, two.Value.Url + "/create", created);
            check(lateCreate == 200 && lateCreateReply == reply && !lateCreateReply.Contains(code ?? "none", StringComparison.Ordinal), "resend enroll: the create body after the code was made still gets only its own reply (" + lateCreate + ")");
            rig.Type(code);
            ApprovalDecision result = rig.Result();
            SqliteConnection.ClearAllPools();
            check(result.Approved && rig.Links == 1 && !RecoveryTests.Holds([rig.All], [code ?? "none"]), "resend enroll: the command finished once with one link and the code never in the terminal (" + result.Detail + ")");
        }

        await Task.CompletedTask;
    }

    // ---------------------------------------------------------------------------------------------------------------
    // A page whose step is gone, and the end of a wait that the read outlived
    // ---------------------------------------------------------------------------------------------------------------

    private static async Task Ended(Action<bool, string> check)
    {
        // A reserved page whose step never comes up: a readable 404, no secrets, not the bare "Not found.".
        TimeSpan before = OneShotServer.BoundWait;
        OneShotServer.BoundWait = TimeSpan.FromSeconds(1);
        try
        {
            using HttpClient client = Client();
            using OneShotServer server = new("a", 0, (verb, suffix, body) => new OneShotResponse(200, "text/plain; charset=utf-8", "first"));
            PageRoute reserved = server.Reserve("e");
            string url = "http://127.0.0.1:" + server.Port + "/e/" + reserved.Token;
            (int status, string text) = TestState.Get(client, url);
            check(status == 404 && text.Contains("This step is no longer available. Check the terminal for the reason.", StringComparison.Ordinal) && !text.Contains("Not found.", StringComparison.Ordinal), "ended page: a reserved page that never came up answers 404 with a readable text (" + status + ")");

            PageRoute second = server.Reserve("e");
            Task<(int Status, string Body)> waiting = Task.Run(() => TestState.Get(client, "http://127.0.0.1:" + server.Port + "/e/" + second.Token));
            Thread.Sleep(200);
            server.Remove(second);
            (int status2, string text2) = waiting.Result;
            check(status2 == 404 && text2.Contains("This step is no longer available.", StringComparison.Ordinal) && text2.Length < 400, "ended page: a reserved page taken away while a request waits answers the same readable 404 (" + status2 + ")");
        }
        finally
        {
            OneShotServer.BoundWait = before;
        }

        // The wait ended (time limit or Cancel on the page) while the read still blocks: the result starts on a new line.
        StringWriter output = new();
        BlockingCollection<string?> typed = [];
        TerminalPrompt.Output = output;
        TerminalPrompt.Input = () => typed.Take();
        try
        {
            Task<string?> reading = Task.Run(() => TerminalPrompt.ReadCode(false));
            WaitFor(() => Snapshot(output).EndsWith(TerminalPrompt.Waiting, StringComparison.Ordinal));
            TerminalPrompt.Line("with-secrets: held line");
            TerminalPrompt.Final("with-secrets: the time limit passed");
            string text = Unix(output);
            check(text == TerminalPrompt.Waiting + "\nwith-secrets: held line\nwith-secrets: the time limit passed\n", "prompt: when the wait ended while the read still blocks, the next line starts on a new line (" + text.Replace("\n", "|") + ")");
            typed.Add(null);
            reading.Wait(TimeSpan.FromSeconds(10));
            check(Unix(output) == text, "prompt: nothing more is printed when the blocked read ends later");
            TerminalPrompt.Final("with-secrets: later");
            check(Unix(output) == text + "with-secrets: later\n", "prompt: a result line with no prompt waiting is printed as it is");
        }
        finally
        {
            TerminalPrompt.Output = null;
            TerminalPrompt.Input = null;
        }

        await Task.CompletedTask;
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Page scripts
    // ---------------------------------------------------------------------------------------------------------------

    private static string ScriptOf(string page)
    {
        int at = page.LastIndexOf("<script>", StringComparison.Ordinal) + "<script>".Length;

        return page[at..page.IndexOf("</script>", at, StringComparison.Ordinal)];
    }

    internal static void Pages(Action<bool, string> check)
    {
        string recovery = RecoveryPage.Build("Admins: laptop ab12", [1, 2, 3], "k", 3).Body;
        string approval = ApprovalPage.Build(new ApprovalPrompt("h", "t"), new ProofStart("webauthn", "{}"), "n", [1], TimeSpan.Zero, null, null, "k").Body;
        string signing = ApprovalPage.Build(new ApprovalPrompt("h", "t"), new ProofStart("webauthn", "{}"), "n", [1], TimeSpan.Zero, null, "{}", null, false, "123456").Body;
        string enroll = PasskeyRegistration.Build("laptop", "localhost", "{}", PasskeyRegistration.Script, ApprovalPage.Style, "Admin key: x").Body;
        foreach ((string name, string page) in new[] { ("recovery", recovery), ("approval", approval), ("signing", signing), ("enroll", enroll) })
        {
            string script = ScriptOf(page);
            int calls = Regex.Count(script, @"location\.assign\(");
            check(calls == 1 && script.Contains("function follow(next)", StringComparison.Ordinal) && Regex.Count(script, @"\bfollow\(") >= 2, $"one flow pages: the {name} page navigates only through follow(), with location.assign (" + calls + ")");
            check(Regex.Matches(script, @"follow\(data\.next\)").Count == Regex.Matches(script, @"typeof data\.next === ""string""").Count, $"one flow pages: the {name} page calls follow only on a verified reply that carries next");
            check(script.Contains("setTimeout(", StringComparison.Ordinal) && script.Contains("2000", StringComparison.Ordinal) && script.Contains("\"Continue\"", StringComparison.Ordinal) && script.Contains("createElement(\"a\")", StringComparison.Ordinal) && script.Contains("link.textContent = next;", StringComparison.Ordinal),
                $"one flow pages: the {name} page shows the link and a Continue button when the navigation did not happen within 2 s");
            check(Regex.IsMatch(script, @"/\^https\?:\\/\\/") && script.Contains("Step done. Continuing...", StringComparison.Ordinal), $"one flow pages: the {name} page only follows an http(s) address and says Step done. Continuing...");
            check(TapRule.Violations(script).Count == 0 && !script.Contains("innerHTML", StringComparison.Ordinal) && !page.Contains("innerHTML", StringComparison.Ordinal) && !script.Contains("insertAdjacentHTML", StringComparison.Ordinal), $"one flow pages: the {name} page starts no passkey prompt outside a tap and builds no HTML from server text");
            check(!page.Contains("Go back to the terminal", StringComparison.Ordinal) && !script.Contains("Go back to the terminal", StringComparison.Ordinal) && !script.Contains("shows a link", StringComparison.Ordinal) && !page.Contains("terminal shows a link", StringComparison.Ordinal), $"one flow pages: the {name} page never sends the person to the terminal for a link");
            check(script.Contains("post(\"deny\"", StringComparison.Ordinal) && script.Contains("diagnostics()", StringComparison.Ordinal) && script.Contains("AbortController", StringComparison.Ordinal) && script.Contains("retry \" + (number + 2) + \" of 3", StringComparison.Ordinal), $"one flow pages: the {name} page still has Cancel, the resends and the diagnostics");
        }

        // The prompts did not move: start of each follow is after a reply, never in a handler that starts a prompt.
        check(Regex.Count(ScriptOf(approval), @"credentials\.(get|create)\s*\(") == 1 && Regex.Count(ScriptOf(enroll), @"credentials\.(get|create)\s*\(") == 2 && Regex.Count(ScriptOf(recovery), @"credentials\.(get|create)\s*\(") == 0, "one flow pages: following next adds no passkey prompt");
        check(signing.Contains("\"code\":\"1\"", StringComparison.Ordinal) && signing.Contains("<p id=\"code\"></p>", StringComparison.Ordinal) && ScriptOf(signing).Contains("code.textContent = data.code;", StringComparison.Ordinal) && !signing.Contains("123456", StringComparison.Ordinal), "one flow pages: the admin signing page has a box for the code, set with textContent, and not the code itself");
    }
}

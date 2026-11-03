using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace WithSecrets.Tests;

/// <summary>
/// Every request to a proof path gets an answer (a status) and never hangs: accepted, refused, bad body, oversized body, a body
/// that stops arriving, a handler that throws, a repeat after the verdict. The terminal gets one line when a proof arrives and
/// one when it is checked, with no key, PRF, code or value text. The pages give up on a post after 20 seconds.
/// </summary>
internal static class ProofReplyTests
{
    private const string AnnouncePrefix = "Approval needed. Ask the person to open: ";
    private static readonly Regex LineShape = new("^with-secrets: (proof|step [A-Za-z0-9]{1,12}) (received \\((\\d+ bytes|body not read)\\)|checked: [A-Za-z0-9 ]{1,30})$", RegexOptions.CultureInvariant);

    public static async Task Run(Action<bool, string> check)
    {
        List<string> lines = [];
        Action<string> saved = ProofLog.Sink;
        ProofLog.Sink = line =>
        {
            lock (lines)
            {
                lines.Add(line);
            }
        };
        try
        {
            using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
            client.Timeout = TimeSpan.FromSeconds(20);
            await Statuses(check, client, lines);
            await Server(check, client, lines);
            PageTimeouts(check);
        }
        finally
        {
            ProofLog.Sink = saved;
        }
    }

    private static string[] Snapshot(List<string> lines)
    {
        lock (lines)
        {
            string[] copy = [.. lines];
            lines.Clear();

            return copy;
        }
    }

    /// <summary>The terminal lines say a size and a verdict and nothing else: never the body, a key, PRF text, a code or a value.</summary>
    private static bool Clean(IEnumerable<string> lines, params string[] forbidden)
        => lines.All(line => LineShape.IsMatch(line) && forbidden.All(text => text.Length == 0 || !line.Contains(text, StringComparison.OrdinalIgnoreCase)));

    private static async Task<(int Status, bool Hung)> Post(HttpClient client, string url, string body)
    {
        using CancellationTokenSource limit = new(TimeSpan.FromSeconds(15));
        try
        {
            using HttpRequestMessage message = new(HttpMethod.Post, url) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            using HttpResponseMessage reply = await client.SendAsync(message, limit.Token);

            return ((int)reply.StatusCode, false);
        }
        catch (OperationCanceledException)
        {
            return (0, true);
        }
        catch (HttpRequestException)
        {
            // The program already ended and closed its page: a refused connection is an answer too, not a hang.
            return (-1, false);
        }
    }

    private static async Task<(string Base, Task<ApprovalDecision> Decision)> Open(FakeProofMethod fake)
    {
        TaskCompletionSource<string> link = new(TaskCreationOptions.RunContinuationsAsynchronously);
        WebApprover approver = new(fake, new ApprovalSettings("passkey", null, 0, TimeSpan.FromSeconds(30)), line => link.TrySetResult(line), TimeSpan.Zero);
        Task<ApprovalDecision> decision = Task.Run(() => approver.Ask(new ApprovalPrompt("heading", "text")));
        Task first = await Task.WhenAny(link.Task, decision, Task.Delay(TimeSpan.FromSeconds(20)));
        if (first != link.Task)
        {
            return ("", decision);
        }

        Uri uri = new(link.Task.Result[AnnouncePrefix.Length..]);

        return ("http://127.0.0.1:" + uri.Port + uri.AbsolutePath, decision);
    }

    private static async Task Statuses(Action<bool, string> check, HttpClient client, List<string> lines)
    {
        // accepted
        Snapshot(lines);
        (string url, Task<ApprovalDecision> decision) = await Open(new FakeProofMethod());
        (int status, bool hung) = await Post(client, url + "/proof", FakeProofMethod.Good);
        check(status == 200 && !hung && (await decision).Approved, "proof replies: an accepted proof gets 200 and the decision is made");
        string[] seen = Snapshot(lines);
        check(seen.Length == 2 && seen[0] == "with-secrets: proof received (" + Encoding.UTF8.GetByteCount(FakeProofMethod.Good) + " bytes)" && seen[1] == "with-secrets: proof checked: accepted", "proof log: one line on arrival and one when accepted (" + string.Join(" | ", seen) + ")");
        check(Clean(seen, "good", "proof\":"), "proof log: no body text in the lines");

        // refused
        (url, decision) = await Open(new FakeProofMethod());
        (status, hung) = await Post(client, url + "/proof", "{\"reuse\":0,\"proof\":{\"proof\":\"bad\"}}");
        check(status == 403 && !hung && !(await decision).Approved, "proof replies: a refused proof gets 403");
        seen = Snapshot(lines);
        check(seen.Length == 2 && seen[1] == "with-secrets: proof checked: refused" && Clean(seen, "bad"), "proof log: refused");

        // bad body
        (url, decision) = await Open(new FakeProofMethod());
        (status, hung) = await Post(client, url + "/proof", "this is not json");
        check(status == 400 && !hung && !(await decision).Approved, "proof replies: a body that is not valid gets 400 and denies");
        seen = Snapshot(lines);
        check(seen.Length == 2 && seen[1] == "with-secrets: proof checked: invalid body" && Clean(seen, "this is not"), "proof log: invalid body");

        // oversized body (over 1 MB): answered by the server, and the page still takes a good proof afterwards
        (url, decision) = await Open(new FakeProofMethod());
        (status, hung) = await Post(client, url + "/proof", "{\"reuse\":0,\"proof\":{\"x\":\"" + new string('a', 1_100_000) + "\"}}");
        check(!hung && status is 400 or 413, "proof replies: an oversized body gets an answer (" + status + ")");
        (status, hung) = await Post(client, url + "/proof", FakeProofMethod.Good);
        check(!hung && status == 200 && (await decision).Approved, "proof replies: after an oversized body a good proof is still accepted");
        Snapshot(lines);

        // a throwing verifier is still answered
        (url, decision) = await Open(new FakeProofMethod { VerifyThrows = true });
        (status, hung) = await Post(client, url + "/proof", FakeProofMethod.Good);
        check(!hung && status == 403 && !(await decision).Approved, "proof replies: a verifier that throws still gets an answer (403) and denies");
        Snapshot(lines);

        // a repeat after the verdict is answered (404, or a closed page), never left waiting
        (url, decision) = await Open(new FakeProofMethod());
        await Post(client, url + "/proof", FakeProofMethod.Good);
        await decision;
        (status, hung) = await Post(client, url + "/proof", FakeProofMethod.Good);
        check(!hung && status is 404 or -1, "proof replies: a repeat after the verdict is answered or refused, not left waiting (" + status + ")");
        (status, hung) = await Post(client, url + "/deny", "");
        check(!hung && status is 404 or -1, "proof replies: a deny after the verdict is answered or refused, not left waiting (" + status + ")");
        Snapshot(lines);
    }

    private static async Task Server(Action<bool, string> check, HttpClient client, List<string> lines)
    {
        Snapshot(lines);

        // The server alone: a handler that throws, a repeat after a verdict, a body that stops arriving.
        using (OneShotServer server = new("a", 0, (verb, suffix, body) => throw new InvalidOperationException("handler broke")))
        {
            (int status, bool hung) = await Post(client, $"http://127.0.0.1:{server.Port}/a/{server.Token}/proof", "{}");
            check(!hung && status == 500, "server: a handler that throws is answered with 500 (" + status + ")");
            string[] seen = Snapshot(lines);
            check(seen.Length == 2 && seen[1] == "with-secrets: proof checked: error 500" && Clean(seen), "server log: the failure is a verdict word only");
        }

        bool decided = false;
        using (OneShotServer server = new("a", 0, (verb, suffix, body) =>
        {
            bool again = decided;
            decided = true;

            return again ? new OneShotResponse(404, "text/plain", "Not found.") : new OneShotResponse(200, "application/json", "{\"ok\":true}");
        }))
        {
            string url = $"http://127.0.0.1:{server.Port}/a/{server.Token}/proof";
            (int first, _) = await Post(client, url, "{}");
            (int second, bool hung) = await Post(client, url, "{}");
            check(first == 200 && second == 404 && !hung, "server: a repeat after a verdict gets the already-ended answer on the open server");
            string[] seen = Snapshot(lines);
            check(seen.Length == 4 && seen[3] == "with-secrets: proof checked: already ended", "server log: a repeat says already ended");
        }

        // A body that stops after its headers: answered 408 after the body time limit.
        TimeSpan saved = OneShotServer.BodyTimeout;
        OneShotServer.BodyTimeout = TimeSpan.FromSeconds(1);
        try
        {
            using OneShotServer server = new("a", 0, (verb, suffix, body) => new OneShotResponse(200, "application/json", "{\"ok\":true}"));
            using TcpClient raw = new();
            await raw.ConnectAsync(IPAddress.Loopback, server.Port);
            NetworkStream stream = raw.GetStream();
            byte[] head = Encoding.ASCII.GetBytes($"POST /a/{server.Token}/proof HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 500\r\n\r\n{{\"reuse\":");
            await stream.WriteAsync(head);
            using CancellationTokenSource limit = new(TimeSpan.FromSeconds(10));
            byte[] buffer = new byte[512];
            int read = 0;
            try
            {
                read = await stream.ReadAsync(buffer, limit.Token);
            }
            catch (OperationCanceledException)
            {
            }

            string reply = Encoding.ASCII.GetString(buffer, 0, read);
            check(reply.StartsWith("HTTP/1.1 408", StringComparison.Ordinal), "server: a body that stops arriving is answered 408 (" + reply.Split('\r')[0] + ")");
            string[] seen = Snapshot(lines);
            check(seen.Length == 2 && seen[0] == "with-secrets: proof received (body not read)" && seen[1] == "with-secrets: proof checked: body timed out" && Clean(seen), "server log: a stalled body is logged without text");
        }
        finally
        {
            OneShotServer.BodyTimeout = saved;
        }
    }

    private static void PageTimeouts(Action<bool, string> check)
    {
        string message = "The program did not answer within 20 seconds. Check the terminal. Tap again to retry.";
        string approval = ApprovalPage.Build(new ApprovalPrompt("h", "t"), new ProofStart("webauthn", "{}"), "n", [1, 2, 3], TimeSpan.Zero).Body;
        (string Name, string Script)[] pages =
        [
            ("approval", approval),
            ("settings", Source("SettingsPage.cs")),
            ("enroll", Source("PasskeyRegistration.cs")),
            ("set", Source("SecretEntry.cs")),
        ];
        foreach ((string name, string script) in pages)
        {
            check(script.Contains("new AbortController()", StringComparison.Ordinal) && script.Contains("}, 20000)", StringComparison.Ordinal) && script.Contains("signal: controller.signal", StringComparison.Ordinal), "page timeout: the " + name + " page aborts a post after 20 seconds");
            check(script.Contains(message, StringComparison.Ordinal) && script.Contains("\"AbortError\"", StringComparison.Ordinal), "page timeout: the " + name + " page says the program did not answer and tells the person to tap again");
        }

        // The approval page ignores a reply of an old attempt and turns its controls back on when it is not finished.
        int at = approval.IndexOf("\"AbortError\"", StringComparison.Ordinal);
        string around = approval[Math.Max(0, at - 300)..Math.Min(approval.Length, at + 400)];
        check(around.Contains("mine !== attempt", StringComparison.Ordinal) && around.Contains("if (!finished)", StringComparison.Ordinal) && around.Contains("controls(true)", StringComparison.Ordinal), "page timeout: the approval page ignores an old attempt and turns the controls back on when not finished");
    }

    private static string Source(string file)
    {
        string? folder = AppContext.BaseDirectory;
        while (folder is not null && !File.Exists(Path.Combine(folder, "with-secrets.slnx")))
        {
            folder = Path.GetDirectoryName(folder);
        }

        return File.ReadAllText(Path.Combine(folder!, "src", "WithSecrets.Core", file));
    }
}

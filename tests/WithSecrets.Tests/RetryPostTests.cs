using System.Text.RegularExpressions;

namespace WithSecrets.Tests;

/// <summary>
/// A page post that gets no answer is sent again with the same body (attempts of 8, 8 and 20 seconds), because the connection can
/// be stale after the phone suspended the page. The program keeps the first outcome, so a resend after the first was processed
/// gets 404 and changes nothing; the page then says the program already finished.
/// </summary>
internal static class RetryPostTests
{
    private static readonly Regex Link = new("https?://[^\\s]+", RegexOptions.CultureInvariant);

    public static async Task Run(Action<bool, string> check)
    {
        Structure(check);
        await RunApproval(check);
    }

    private static void Structure(Action<bool, string> check)
    {
        string approval = ApprovalPage.Build(new ApprovalPrompt("h", "t"), new ProofStart("webauthn", "{}"), "n", [1, 2, 3], TimeSpan.Zero).Body;
        (string Name, string Script)[] pages =
        [
            ("approval", approval),
            ("setup", Source("FirstRunPage.cs")),
            ("enroll", Source("PasskeyRegistration.cs")),
            ("recovery", Source("StoreRecovery.cs")),
        ];
        foreach ((string name, string script) in pages)
        {
            string label = "resend: the " + name + " page ";
            check(script.Contains("[8000, 8000, 20000]", StringComparison.Ordinal) && script.Contains("new AbortController()", StringComparison.Ordinal) && script.Contains("signal: controller.signal", StringComparison.Ordinal), label + "tries three times (8, 8 and 20 seconds), each with a fresh AbortController");
            check(script.Contains("return send(number + 1);", StringComparison.Ordinal) && script.Contains("body: body,", StringComparison.Ordinal) && !script.Contains("body: JSON", StringComparison.Ordinal), label + "sends the same body again, the one it already built");
            check(script.Contains("cache: \"no-store\"", StringComparison.Ordinal) && script.Contains("keepalive: false", StringComparison.Ordinal), label + "does not cache and does not keep the request alive");
            check(script.Contains("Still waiting for the program... (retry \" + (number + 2) + \" of 3)", StringComparison.Ordinal), label + "shows the retry counter");
            check(script.Contains("number + 1 >= limits.length || finished", StringComparison.Ordinal), label + "stops resending after the third attempt and when the page is finished (Cancel)");
            check(script.Contains("The program already finished this request. If this page did not move on, press Ctrl+C in the terminal and run the command again.", StringComparison.Ordinal) && script.Contains("resent && (reply.status === 404 || reply.status === 409)", StringComparison.Ordinal), label + "says the program already finished when a resend gets 404 or 409");
            check(script.Contains("what === \"deny\" ? [20000]", StringComparison.Ordinal), label + "sends Cancel only once");
            check(script.Contains("The program did not answer within 20 seconds. Check the terminal. Tap again to retry.", StringComparison.Ordinal), label + "still ends with the old message after the third failure");
        }
    }

    // A run approval: the proof is processed once. The same body sent again (a page resend) gets 404 and changes nothing.
    private static async Task RunApproval(Action<bool, string> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "ws-retry-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
            client.Timeout = TimeSpan.FromSeconds(20);
            using TestAuthenticator admin = TestAuthenticator.ES256();
            StateDatabase db = StateDatabase.InFolder(root);
            TestState.Add(db, admin.Record("localhost", "laptop"));
            ApprovalSettings settings = new(null, 0, TimeSpan.FromSeconds(30));
            PasskeyMethod method = new(new PasskeyStore(db), settings, () => null);
            System.Collections.Concurrent.BlockingCollection<string> queue = [];
            IApprover approver = EnrollmentTarget.For(method, new WebApprover(method, settings, queue.Add, TimeSpan.Zero)).Approver;
            Task<ApprovalDecision> task = Task.Run(() => approver.Request(new ApprovalRequest("tool", "/bin/tool", [], "/work", "r", ["OLD_NAME"], null, null, null, "REQ")));
            int first = 0;
            int again = -2;
            int third = -2;
            DateTime stop = DateTime.UtcNow.AddSeconds(25);
            while (!task.IsCompleted && DateTime.UtcNow < stop)
            {
                if (!queue.TryTake(out string? line, 200) || Link.Match(line) is not { Success: true } match)
                {
                    continue;
                }

                Uri link = new(match.Value);
                string url = "http://127.0.0.1:" + link.Port + link.AbsolutePath;
                first = TestState.Approve(client, url, link.GetLeftPart(UriPartial.Authority), link.IdnHost, admin).Status;
                string body = TestState.LastProofBody;
                again = TestState.Post(client, url + "/proof", body).Status;
                third = TestState.Post(client, url + "/proof", body).Status;
            }

            ApprovalDecision? decision = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(5))) == task ? task.Result : null;
            check(first == 200 && decision is { Approved: true }, "resend: the first proof is approved (" + first + ")");
            check(again is 404 or 409 or 0 && third is 404 or 409 or 0, "resend: the same proof sent again gets 404 and changes nothing (" + again + ", " + third + ")");
            check(decision is { Approved: true }, "resend: the decision stays the first one");
        }
        finally
        {
            Directory.Delete(root, true);
        }
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

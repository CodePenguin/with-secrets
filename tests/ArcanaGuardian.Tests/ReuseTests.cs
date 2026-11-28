using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ArcanaGuardian.Tests;

/// <summary>
/// The time bound into a passkey proof and the times a grant may last: the time is part of the challenge, the approval page offers
/// "Approve once" only and accepts nothing else, and the web app offers the grant times up to the ceiling.
/// </summary>
internal static class ReuseTests
{
    private const string AnnouncePrefix = "Approval needed. Ask the person to open: ";

    private static int _signs;

    public static async Task Run(Action<bool, string> check)
    {
        string folder = Path.Combine(Path.GetTempPath(), "ws-reuse-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            Binding(check);
            Offers(check);
            Page(check);
            using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
            client.Timeout = TimeSpan.FromSeconds(20);
            await Server(check, client, folder);
        }
        finally
        {
            Directory.Delete(folder, true);
        }
    }

    /// <summary>The body the page posts: the time (always 0) and the assertion.</summary>
    public static string Body(int minutes, string assertion) => "{\"reuse\":" + minutes + ",\"proof\":" + assertion + "}";

    private static void Binding(Action<bool, string> check)
    {
        byte[] bind = RandomNumberGenerator.GetBytes(32);
        byte[] once = ReuseBinding.Challenge(bind, 0);
        byte[] ten = ReuseBinding.Challenge(bind, 10);
        check(once.AsSpan().SequenceEqual(SHA256.HashData([.. bind, .. Encoding.ASCII.GetBytes("reuse=0")])), "time binding: SHA-256(bind || \"reuse=0\") for once");
        check(ten.AsSpan().SequenceEqual(SHA256.HashData([.. bind, .. Encoding.ASCII.GetBytes("reuse=10")])), "time binding: SHA-256(bind || \"reuse=10\") for 10 minutes");
        check(!once.AsSpan().SequenceEqual(ten) && !once.AsSpan().SequenceEqual(bind), "time binding: once and 10 minutes differ, and neither is the bare bind");
    }

    private static void Offers(Action<bool, string> check)
    {
        check(ReuseOffer.Steps.SequenceEqual([60, 120, 240, 480, 1440, 10080, 43200]), "grant times: hour and day options through 30 days");
        check(new ReuseOffer(480).Choices.SequenceEqual([60, 120, 240, 480]), "grant times: the existing ceiling still applies");
        check(new ReuseOffer(1440).Choices.SequenceEqual([60, 120, 240, 480, 1440]), "grant times: the 24-hour option fits a one-day ceiling");
        check(new ReuseOffer(100).Choices.SequenceEqual([60]), "grant times: a ceiling of 100 offers only the steps up to it");
        check(new ReuseOffer(10).WithAlways.SequenceEqual([ReuseOffer.Always]), "grant times: legacy minimum offers only Always");
        check(!ReuseOffer.Off.IsOn && ReuseOffer.Off.Choices.Count == 0 && new ReuseOffer(480).IsOn, "grant times: off offers nothing");
        ReuseOffer offer = new(100);
        check(!offer.Allows(10) && offer.Allows(60) && offer.Allows(ReuseOffer.Always), "grant times: only offered steps and Always are authorized");
        check(!offer.Allows(0) && !offer.Allows(7) && !offer.Allows(-1) && !offer.Allows(99999) && !offer.Allows(240) && !offer.Allows(480), "grant times: a time not offered, above the ceiling, or once (a grant needs a time) is not allowed");
        check(!ReuseOffer.Off.Allows(0) && !ReuseOffer.Off.Allows(10), "grant times: with none offered nothing is allowed");
    }

    private static ApprovalRequest Request() => new("tool", "/bin/tool", ["--x"], "/work", "testing", ["API_KEY"]);

    private static string Built()
    {
        return ApprovalPage.Build(new ApprovalPrompt("h", ApprovalSummary.BuildMessage(Request())), new ProofStart("webauthn", "{}"), "n", [1, 2, 3], TimeSpan.FromSeconds(2)).Body;
    }

    private static void Page(Action<bool, string> check)
    {
        string page = Built();
        check(page.Contains("<button id=\"approve\" type=\"button\" disabled data-delay=\"2000\">Approve once</button>", StringComparison.Ordinal), "approval page: Approve once is its own button, off for the start delay");
        check(!page.Contains("id=\"reuse\"", StringComparison.Ordinal) && !page.Contains("id=\"approve-for\"", StringComparison.Ordinal) && !page.Contains("<option", StringComparison.Ordinal), "approval page: no time is offered");
        check(page.IndexOf("id=\"deny\"", StringComparison.Ordinal) < page.IndexOf("id=\"approve\"", StringComparison.Ordinal), "approval page: Deny comes before Approve once");
        check(page.IndexOf("id=\"request\"", StringComparison.Ordinal) < page.IndexOf("id=\"approve\"", StringComparison.Ordinal), "approval page: the command is shown before the controls");

        // The script: Ctrl+Enter (Cmd+Enter) is Approve once, the challenge is SHA-256(bind || "reuse=0").
        string script = Between(page, "<script>", "</script>");
        check(script.Contains("event.key === \"Enter\"", StringComparison.Ordinal) && script.Contains("event.ctrlKey || event.metaKey", StringComparison.Ordinal), "approval page: the script handles Ctrl+Enter and Cmd+Enter");
        check(script.Contains("approveWith(0, approve)", StringComparison.Ordinal), "approval page: the shortcut approves once (0 minutes)");
        check(script.Contains("\"reuse=0\"", StringComparison.Ordinal) && script.Contains("crypto.subtle.digest(\"SHA-256\"", StringComparison.Ordinal), "approval page: the script binds the time (0) into the challenge");
        check(!script.Contains("approve-for", StringComparison.Ordinal) && !script.Contains("reuse.options", StringComparison.Ordinal), "approval page: the script has no time choice");
        check(!Regex.IsMatch(page, "\\son[a-z]+=", RegexOptions.IgnoreCase), "approval page: no inline event attributes");
        OneShotResponse response = ApprovalPage.Build(new ApprovalPrompt("h", "t"), new ProofStart("webauthn", "{}"), "n", [1], TimeSpan.Zero);
        string served = Between(response.Body, "<script>", "</script>");
        check((response.ContentSecurityPolicy ?? "").Contains("script-src " + ApprovalPage.Hash(served) + ";", StringComparison.Ordinal) && !served.Contains('\r'), "approval page: the CSP hash is of the LF script as served");

        string text = ApprovalSummary.BuildMessage(Request());
        check(!text.Contains("Approve for a time", StringComparison.Ordinal) && !text.Contains("whatever the other arguments", StringComparison.Ordinal), "approval text: no saved approval is offered");
    }

    /// <summary>
    /// Runs WebApprover.Request with a passkey; <paramref name="body" /> gets the page's bind and origin and returns what to
    /// post to /proof. Returns the decision, the status of the post and the page.
    /// </summary>
    private static async Task<(ApprovalDecision? Decision, int Status, string Page)> Ask(HttpClient client, PasskeyStore store, Func<byte[], string, string> body)
    {
        TaskCompletionSource<string> line = new(TaskCreationOptions.RunContinuationsAsynchronously);
        ApprovalSettings settings = new(null, 0, TimeSpan.FromSeconds(20));
        WebApprover approver = new(new PasskeyMethod(store, settings), settings, text => line.TrySetResult(text), TimeSpan.Zero);
        Task<ApprovalDecision> ask = Task.Run(() => approver.Request(Request()));
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
        check(store.Add(key.Record("localhost", "laptop")), "approval page server: key stored");

        string Sign(byte[] bind, string origin, int minutes) => key.Assert(ReuseBinding.Challenge(bind, minutes), origin, "localhost", Next());

        (ApprovalDecision? decision, int status, _) = await Ask(client, store, (bind, origin) => Body(0, Sign(bind, origin, 0)));
        check(status == 200 && decision is { Approved: true, ReuseMinutes: 0 } && decision.Detail.Contains("passkey laptop verified", StringComparison.Ordinal), "approval page server: once, signed for once, approves with 0 minutes (" + decision?.Detail + ")");

        (decision, status, _) = await Ask(client, store, (bind, origin) => Body(10, Sign(bind, origin, 0)));
        check(status == 400 && decision is { Approved: false, ReuseMinutes: 0 }, "approval page server: a time other than once denies (" + decision?.Detail + ")");
        (decision, status, _) = await Ask(client, store, (bind, origin) => Body(0, Sign(bind, origin, 10)));
        check(status == 403 && decision is { Approved: false }, "approval page server: a signature made for 10 minutes, sent as once, denies (" + decision?.Detail + ")");
        (decision, status, _) = await Ask(client, store, (bind, origin) => Body(0, key.Assert(bind, origin, "localhost", Next())));
        check(status == 403 && decision is { Approved: false }, "approval page server: a signature over the bare bind denies (" + decision?.Detail + ")");

        foreach (int minutes in new[] { 10, 7, -1, 99999, 1440 })
        {
            (decision, status, _) = await Ask(client, store, (bind, origin) => Body(minutes, Sign(bind, origin, minutes)));
            check(status == 400 && decision is { Approved: false, ReuseMinutes: 0 } && decision.Detail.Contains("approves once", StringComparison.Ordinal), $"approval page server: {minutes} minutes, even signed, denies ({decision?.Detail})");
        }

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
            (decision, status, _) = await Ask(client, store, body);
            check(status == 400 && decision is { Approved: false, ReuseMinutes: 0 }, $"approval page server: malformed body {index} (non-numeric, int32 overflow, -0, leading zero, missing or repeated time, extra member, bare assertion) denies ({status}; {decision?.Detail})");
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

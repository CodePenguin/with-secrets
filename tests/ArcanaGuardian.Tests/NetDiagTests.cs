using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

using Serilog.Core;
using Serilog.Events;

namespace ArcanaGuardian.Tests;

/// <summary>
/// Network diagnostics. The pages show timings after a failed post only (no key, PRF, value or code is read); the program prints
/// a line when a connection opens and when a request's headers were read, with a route word and whole seconds, never the path
/// with its token, a body or a key.
/// </summary>
internal static class NetDiagTests
{
    private static readonly Regex LineShape = new("^using-secrets: (connection opened \\(\\d+ s\\)|request (GET|POST|other) /(page|proof|sign|save|create|seal|deny|code|other) (\\(headers read, \\d+ s\\)|body slow \\(\\d+ s\\)))$", RegexOptions.CultureInvariant);

    public static async Task Run(Action<bool, string> check)
    {
        Structure(check);
        await Server(check);
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
            string label = "diagnostics: the " + name + " page ";
            int from = script.IndexOf("var diagStart", StringComparison.Ordinal);
            int to = script.IndexOf("return send(0);", StringComparison.Ordinal);
            string block = from >= 0 && to > from ? script[from..to] : "";
            check(block.Length > 0 && block.Contains("\"Diagnostics: \"", StringComparison.Ordinal), label + "builds a Diagnostics line");
            foreach (string event_ in new[] { "visibilitychange", "pagehide", "pageshow", "freeze", "resume", "navigator.onLine", "document.visibilityState", "performance.now()", "navigator.credentials" })
            {
                check(block.Contains(event_, StringComparison.Ordinal), label + "records " + event_);
            }

            // Only the failure path sets the line; a reply clears it. Nothing secret is read by the diagnostics.
            int error = block.IndexOf("}, function (error) {", StringComparison.Ordinal);
            int line = block.IndexOf("diagLine = diagnostics();", StringComparison.Ordinal);
            check(error > 0 && line > error && block.Split("diagLine = diagnostics();").Length == 2, label + "sets the line only in the failure handler");
            int reply = block.IndexOf(".then(function (reply) {", StringComparison.Ordinal);
            check(reply > 0 && block.IndexOf("diagLine = \"\";", reply, StringComparison.Ordinal) is > 0 and var cleared && cleared < error, label + "clears the line on any reply");
            string lower = script[from..script.IndexOf("// A post that gets no answer", StringComparison.Ordinal)].ToLowerInvariant();
            check(new[] { "prf", "secret", "signature", "rawid", "password", "recovery", "response", "body", "value", "json", "challenge", "assertion", "attestation" }.All(word => !lower.Contains(word, StringComparison.Ordinal)), label + "diagnostics reference no key, PRF, value or code variable");
            check(script.Contains("status.textContent = text + (diagLine ? \" \" + diagLine : \"\");", StringComparison.Ordinal), label + "shows the line next to the status");
        }
    }

    private static async Task Server(Action<bool, string> check)
    {
        List<string> lines = [];
        TimeSpan savedSlow = OneShotServer.SlowBody;
        TimeSpan savedBody = OneShotServer.BodyTimeout;
        AppLog.Tap = new LineSink(lines, LogEventLevel.Debug, "^using-secrets: (connection opened|request )");
        OneShotServer.SlowBody = TimeSpan.FromSeconds(1);
        OneShotServer.BodyTimeout = TimeSpan.FromSeconds(3);
        try
        {
            using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
            client.Timeout = TimeSpan.FromSeconds(20);
            using OneShotServer server = new("a", 0, (verb, suffix, body) => new OneShotResponse(200, "application/json", "{\"ok\":true}"));
            string url = $"http://127.0.0.1:{server.Port}/a/{server.Token}";
            const string Marker = "BODY_MARK_8841";
            await client.GetAsync(url);
            using (HttpRequestMessage message = new(HttpMethod.Post, url + "/proof") { Content = new StringContent("{\"x\":\"" + Marker + "\"}", Encoding.UTF8, "application/json") })
            {
                using HttpResponseMessage reply = await client.SendAsync(message);
            }

            await client.GetAsync($"http://127.0.0.1:{server.Port}/a/wrong-token-77/proof");
            await client.GetAsync(url + "/whatever-route");

            // A body that stops arriving is logged as slow.
            using (TcpClient raw = new())
            {
                await raw.ConnectAsync(IPAddress.Loopback, server.Port);
                NetworkStream stream = raw.GetStream();
                await stream.WriteAsync(Encoding.ASCII.GetBytes($"POST /a/{server.Token}/save HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 500\r\n\r\n{{\"a\":"));
                await Task.Delay(1800);
                using CancellationTokenSource limit = new(TimeSpan.FromSeconds(8));
                try
                {
                    _ = await stream.ReadAsync(new byte[256], limit.Token);
                }
                catch (OperationCanceledException)
                {
                }
            }

            string[] seen;
            lock (lines)
            {
                seen = [.. lines];
            }

            check(seen.Length > 0 && seen.All(line => LineShape.IsMatch(line)), "net log: every line is a connection or request line with a route word and seconds (" + string.Join(" | ", seen.Where(line => !LineShape.IsMatch(line))) + ")");
            check(seen.All(line => !line.Contains(server.Token, StringComparison.Ordinal) && !line.Contains(Marker, StringComparison.Ordinal) && !line.Contains("wrong-token", StringComparison.Ordinal) && !line.Contains("whatever-route", StringComparison.Ordinal)), "net log: no token, body or path text in any line");
            check(seen.Any(line => line.StartsWith("using-secrets: connection opened (", StringComparison.Ordinal)), "net log: a connection is logged");
            check(seen.Contains("using-secrets: request GET /page (headers read, 0 s)") && seen.Contains("using-secrets: request POST /proof (headers read, 0 s)"), "net log: the page and the proof request are logged with their route word");
            check(seen.Any(line => line.StartsWith("using-secrets: request POST /save body slow (", StringComparison.Ordinal)), "net log: a body still arriving after the slow limit is logged");
            check(seen.Count(line => line.Contains("body slow", StringComparison.Ordinal)) == 1, "net log: body slow is logged once, and not for the requests whose body arrived");
        }
        finally
        {
            AppLog.Tap = null;
            OneShotServer.SlowBody = savedSlow;
            OneShotServer.BodyTimeout = savedBody;
        }
    }

    private static string Source(string file)
    {
        string? folder = AppContext.BaseDirectory;
        while (folder is not null && !File.Exists(Path.Combine(folder, "arcana-guardian.slnx")))
        {
            folder = Path.GetDirectoryName(folder);
        }

        return File.ReadAllText(Path.Combine(folder!, "src", "ArcanaGuardian.Core", file));
    }
}

/// <summary>Collects the rendered lines of the events at one level (optionally only those matching a pattern), as the old line sinks did.</summary>
internal sealed class LineSink(List<string> lines, LogEventLevel level, string? pattern = null) : ILogEventSink
{
    private readonly Regex? _pattern = pattern is null ? null : new Regex(pattern, RegexOptions.CultureInvariant);

    public void Emit(LogEvent logEvent)
    {
        string line = AppLog.Render(logEvent);
        if (logEvent.Level != level || (_pattern is not null && !_pattern.IsMatch(line)))
        {
            return;
        }

        lock (lines)
        {
            lines.Add(line);
        }
    }
}

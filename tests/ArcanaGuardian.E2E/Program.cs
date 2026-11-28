using System.Diagnostics;
using System.Net;
using System.Text.Json;

namespace ArcanaGuardian.E2E;

internal static class Program
{
    private static readonly (string Name, Func<Host, S, Task> Run)[] All =
    [
        ("a-first-run-setup", ScenariosQuickStart.FirstRun),
        ("a1-desktop-first-run", ScenariosQuickStart.DesktopFirstRun),
        ("a1-desktop-cancel-setup", ScenariosQuickStart.DesktopCancellation),
        ("a2-first-run-security", Scenarios.FirstRunSecurity),
        ("b-spa-secrets", ScenariosSpa.Secrets),
        ("c-run-approval", Scenarios3.RunApproval),
        ("c2-run-code-changes", Scenarios3.CodeChanges),
        ("d-rotate-key", Scenarios4.Rotate),
        ("e-recover", Scenarios5.Recover),
        ("f-enroll-same-host", Scenarios6.EnrollSameHost),
        ("g-enroll-cross-host", Scenarios7.EnrollCrossHost),
        ("h1-refusal-and-cancel", ScenariosH.CancelAndRetry),
        ("h2-resend-after-abort", ScenariosH.ResendAfterAbort),
        ("h3-lost-reply", ScenariosH.LostReply),
        ("h4-continue-fallback", ScenariosH.ContinueFallback),
        ("h5-tap-rule", ScenariosH.TapRule),
        ("i1-spa-sign-in-out", ScenariosSpa.SignInAndOut),
        ("i1b-spa-sign-in-cancel", ScenariosSpa.SignInCancel),
        ("i2-spa-approve-machine", ScenariosSpa.ApproveMachine),
        ("i2-spa-machine-diagnostics", ScenariosSpa.MachineDiagnostics),
        ("i3-spa-revoke-grant", ScenariosSpa.RevokeGrant),
        ("i4-spa-audit-search", ScenariosSpa.AuditSearch),
        ("i5-spa-lock-unlock", ScenariosSpa.LockUnlock),
        ("i5b-spa-authenticator-editing", ScenariosSpa.AuthenticatorEditing),
        ("i6-spa-settings-change", ScenariosSpa.Settings),
        ("i7-spa-refused-without-authorization", ScenariosSpa.RefusedWithoutAuthorization),
        ("i8-spa-accept-host-name", ScenariosSpa.AcceptHostName),
        ("i9-spa-reload-between-tap-and-result", ScenariosSpa.ReloadBetweenTapAndResult),
        ("i10a-provider-bitwarden", ScenariosSpa.Providers),
        ("i10b-provider-1password", ScenariosSpa.OnePasswordSetup),
        ("i10c-provider-vault", ScenariosSpa.VaultSetup),
        ("i10d-provider-lastpass", ScenariosSpa.LastPassSetup),
        ("j1-spa-accessibility", ScenariosSpa.Accessibility),
        ("k1-spa-pair-machine", ScenariosPairing.PairMachine),
        ("z-happy-path", ScenariosHappy.HappyPath),
    ];

    private sealed record ScenarioResult(string Name, bool Passed, int ChecksPassed, int ChecksFailed, double Seconds, string[] Videos, string[] ConsoleLogs, string[] Screenshots, string? Diagnostics);

    private static async Task<int> Main(string[] args)
    {
        if (args is ["--browser-https", ..])
        {
            return await ScenariosBrowserHttps.RunAsync(args[1..]);
        }

        bool demo = args.Length > 0 && args[0].Equals("--demo", StringComparison.OrdinalIgnoreCase);
        string? only = demo ? (args.Length > 2 ? args[2] : null) : args.FirstOrDefault();
        string? demoDirectory = null;
        DemoOutput? output;
        try
        {
            output = demo ? DemoOutput.Open(Spa.RepoRoot(), args.Length > 1 ? args[1] : null) : null;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or InvalidOperationException)
        {
            Console.Error.WriteLine("UX demo output: " + error.Message);
            return 2;
        }
        using DemoOutput? runOutput = output;
        if (runOutput is not null)
        {
            demoDirectory = runOutput.WorkingDirectory;
            Console.WriteLine("UX demo output: " + runOutput.Destination);
        }

        Stopwatch total = Stopwatch.StartNew();
        await using Host host = await Host.StartAsync(demoDirectory);
        Console.WriteLine("chromium " + host.Browser.Version);
        int failed = 0;
        List<ScenarioResult> results = [];
        foreach ((string name, Func<Host, S, Task> run) in All.Where(x => only is null || x.Name.StartsWith(only, StringComparison.Ordinal)))
        {
            host.BeginScenario(name);
            S s = new(name);
            Stopwatch clock = Stopwatch.StartNew();
            try
            {
                // Demo step viewers pause after meaningful states and use slow motion, so they need a longer guard
                // than an ordinary run; the scenarios themselves are the same.
                await run(host, s).WaitAsync(TimeSpan.FromSeconds(demoDirectory is null ? 120 : 300));
            }
            catch (Exception failure)
            {
                s.Check(false, "scenario threw " + failure.GetType().Name + ": " + failure.Message.Split('\n')[0]);
                s.Lines.Add("  exception details: " + failure);
                if (Ctx.Last is { } last)
                {
                    s.Lines.Add(await last.Dump());
                }
            }

            Console.WriteLine($"{(s.Failed == 0 ? "OK  " : "FAIL")} {name} ({clock.Elapsed.TotalSeconds:F1}s, {s.Passed} checks)");
            foreach (string line in s.Lines.Where(l => s.Failed > 0 || !l.StartsWith("  PASS", StringComparison.Ordinal)))
            {
                Console.WriteLine(line);
            }

            string[] screenshots = [];
            string? diagnostics = null;
            if (demoDirectory is not null && s.Failed > 0)
            {
                (screenshots, diagnostics) = await host.CaptureFailureAsync(name, s);
            }

            await host.CloseScenarioAsync();
            string[] videos = [.. host.WriteViewer(name)];
            string[] consoleLogs = [.. host.ConsoleLogsFor(name)];
            results.Add(new(name, s.Failed == 0, s.Passed, s.Failed, clock.Elapsed.TotalSeconds, videos, consoleLogs, screenshots, diagnostics));
            failed += s.Failed;
        }

        Console.WriteLine($"{(failed == 0 ? "ALL PASSED" : failed + " FAILED")} in {total.Elapsed.TotalSeconds:F1}s");
        if (demoDirectory is not null)
        {
            await WriteDemoIndex(demoDirectory, results, total.Elapsed.TotalSeconds);
            runOutput!.Publish();
            Console.WriteLine("Demo index: " + Path.Combine(runOutput.Destination, "index.html"));
        }

        return failed == 0 ? 0 : 1;
    }

    private static async Task WriteDemoIndex(string directory, IReadOnlyList<ScenarioResult> results, double seconds)
    {
        string esc(string value) => WebUtility.HtmlEncode(value);
        string relative(string path) => Path.GetRelativePath(directory, path).Replace(Path.DirectorySeparatorChar, '/');
        ScenarioResult? firstProvider = results.FirstOrDefault(result => result.Name.StartsWith("i10", StringComparison.Ordinal));
        string rows = string.Join(Environment.NewLine, results.Select(result =>
        {
            string status = result.Passed ? "Passed" : "Failed";
            string title = esc(DemoViewer.Title(result.Name));
            string videos = result.Videos.Length == 0
                ? "<span class=\"muted\">No steps captured</span>"
                : string.Join(" ", result.Videos.Select((path, index) =>
                    $"<a class=\"recording-link\" href=\"{esc(relative(path))}\" title=\"Step through {title}\">{title}{(index == 0 ? "" : $" ({index + 1})")}</a>"));
            List<string> evidence = [];
            evidence.AddRange(result.Screenshots.Select((path, index) => $"<a href=\"{esc(relative(path))}\">Screenshot {index + 1}</a>"));
            if (result.Diagnostics is not null)
            {
                evidence.Add($"<a href=\"{esc(relative(result.Diagnostics))}\">Diagnostics</a>");
            }

            string diagnostics = evidence.Count == 0 ? "<span class=\"muted\">—</span>" : string.Join(" ", evidence);
            string group = ReferenceEquals(result, firstProvider) ? "<tr><th colspan=\"5\">i10. Provider checks</th></tr>" + Environment.NewLine : "";
            return group + $"<tr><td>{(result.Videos.Length == 0 ? $"<code>{esc(result.Name)}</code>" : videos)}</td><td class=\"{(result.Passed ? "pass" : "fail")}\">{status}</td><td>{result.ChecksPassed} passed / {result.ChecksFailed} failed</td><td>{result.Seconds:F1}s</td><td>{diagnostics}</td></tr>";
        }));
        string html = $$"""
            <!doctype html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1">
              <title>Arcana Guardian UX demo</title>
              <style>
                body{font:16px system-ui,sans-serif;max-width:1200px;margin:40px auto;padding:0 20px;color:#20242b}
                h1{margin-bottom:4px} .muted{color:#68717d} table{border-collapse:collapse;width:100%;margin-top:24px}
                th,td{text-align:left;padding:12px;border-bottom:1px solid #ddd;vertical-align:top}
                th{background:#f5f6f8}.pass{color:#16713a;font-weight:600}.fail{color:#b42318;font-weight:600}
                a{margin-right:12px}.recording-link{font-weight:650;white-space:nowrap}code{font-size:.92em}li{margin:6px 0}
              </style>
            </head>
            <body>
              <h1>Arcana Guardian UX demo</h1>
              <p class="muted">Generated {{DateTimeOffset.Now:yyyy-MM-dd HH:mm zzz}} · {{results.Count}} scenarios · {{results.Sum(result => result.Videos.Length)}} step viewers · {{seconds:F1}} seconds</p>
              <p>Open a scenario to step through its screenshots: Back and Next, or the arrow keys. The left side is the command line, the caption says what happens, and the right side is the browser. Screenshots come from the real Playwright browser used by the end-to-end scenario; captions are added only in demo mode.</p>
              <p class="muted">Step viewers show the real interaction, including one-time codes, so they can be reviewed as the person sees them. They use throwaway test state and must stay local; CLI stdout and stderr appear as one live transcript in the full-height left terminal pane; narration appears at its bottom. The browser occupies the right pane without terminal overlap. See the E2E README.</p>
              <table>
                <thead><tr><th>Test / recording</th><th>Result</th><th>Checks</th><th>Duration</th><th>Failure evidence</th></tr></thead>
                <tbody>{{rows}}</tbody>
              </table>
            </body>
            </html>
            """;
        await File.WriteAllTextAsync(Path.Combine(directory, "index.html"), html);
        await File.WriteAllTextAsync(Path.Combine(directory, "summary.json"), JsonSerializer.Serialize(new
        {
            generatedAt = DateTimeOffset.Now,
            durationSeconds = Math.Round(seconds, 1),
            passed = results.Count(x => x.Passed),
            failed = results.Count(x => !x.Passed),
            viewers = results.Sum(x => x.Videos.Length),
            scenarios = results.Select(result => new
            {
                result.Name,
                result.Passed,
                result.ChecksPassed,
                result.ChecksFailed,
                Seconds = Math.Round(result.Seconds, 1),
                Videos = result.Videos.Select(relative).ToArray(),
                ConsoleLogs = result.ConsoleLogs.Select(relative).ToArray(),
                Screenshots = result.Screenshots.Select(relative).ToArray(),
                Diagnostics = result.Diagnostics is null ? null : relative(result.Diagnostics)
            })
        }, new JsonSerializerOptions { WriteIndented = true }));
    }
}

using System.Diagnostics;

namespace WithSecrets.E2E;

internal static class Program
{
    private static readonly (string Name, Func<Host, S, Task> Run)[] All =
    [
        ("a-first-run-config", Scenarios.FirstRunConfig),
        ("b-set-remove", Scenarios2.SetRemove),
        ("c-run-approval", Scenarios3.RunApproval),
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
        ("i2-spa-approve-machine", ScenariosSpa.ApproveMachine),
        ("i3-spa-revoke-grant", ScenariosSpa.RevokeGrant),
        ("i4-spa-audit-search", ScenariosSpa.AuditSearch),
        ("i5-spa-lock-unlock", ScenariosSpa.LockUnlock),
        ("i6-spa-settings-change", ScenariosSpa.Settings),
        ("i7-spa-refused-without-authorization", ScenariosSpa.RefusedWithoutAuthorization),
        ("i8-spa-accept-host-name", ScenariosSpa.AcceptHostName),
        ("i9-spa-reload-between-tap-and-result", ScenariosSpa.ReloadBetweenTapAndResult),
        ("j1-spa-accessibility", ScenariosSpa.Accessibility),
        ("k1-spa-pair-machine", ScenariosPairing.PairMachine),
    ];

    private static async Task<int> Main(string[] args)
    {
        string? only = args.FirstOrDefault();
        Stopwatch total = Stopwatch.StartNew();
        await using Host host = await Host.StartAsync();
        Console.WriteLine("chromium " + host.Browser.Version);
        int failed = 0;
        foreach ((string name, Func<Host, S, Task> run) in All.Where(x => only is null || x.Name.StartsWith(only, StringComparison.Ordinal)))
        {
            S s = new(name);
            Stopwatch clock = Stopwatch.StartNew();
            try
            {
                await run(host, s).WaitAsync(TimeSpan.FromSeconds(120));
            }
            catch (Exception failure)
            {
                s.Check(false, "scenario threw " + failure.GetType().Name + ": " + failure.Message.Split('\n')[0]);
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

            if (Ctx.Last is { } done) { await done.CloseAsync(); }

            failed += s.Failed;
        }

        Console.WriteLine($"{(failed == 0 ? "ALL PASSED" : failed + " FAILED")} in {total.Elapsed.TotalSeconds:F1}s");

        return failed == 0 ? 0 : 1;
    }
}

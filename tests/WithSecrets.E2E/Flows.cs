using Microsoft.Playwright;

namespace WithSecrets.E2E;

/// <summary>Reusable page flows (the fixture steps of several scenarios).</summary>
internal static class Flows
{
    public sealed record Configured(string Recovery, int Code);

    /// <summary>First-run setup in the browser: save, Step 2, read the code and the recovery code from the page, type the code.</summary>
    public static async Task<Configured> Configure(Rig rig, Ctx c, S? s = null, bool keepSetup = false)
    {
        using Cmd<int> cmd = new((port, o, e) => CommandWiring.Setup(rig.State, port));
        string link = await cmd.LinkAsync();
        await c.Page.GotoAsync(link);
        if (s is not null)
        {
            s.Check(await c.PasskeyCalls() == 0, "tap rule: no passkey prompt on page load");
        }

        await c.Click("#save");
        await c.Click("#confirm");
        string code = await c.TextAppears("#code");
        string recovery = await c.TextAppears("#recovery");
        int exit = await c.TypeCodeAsync(cmd, code);

        // The shared first-run setup is identical in every scenario, so demo recordings are trimmed to start at the
        // scenario's own steps instead of replaying it.
        if (c.IsDemo && !keepSetup)
        {
            c.MarkScenarioStart();
            await c.DemoIntroAsync(c.ScenarioIntroduction());
        }

        return new Configured(recovery, exit);
    }
}

internal static class Cmds
{
    public static CliCommand Parse(params string[] args)
    {
        CliCommand? command = CliArgs.Parse(args, out string error);

        return command ?? throw new InvalidOperationException("bad test arguments: " + error);
    }

    /// <summary>
    /// A run of a program with secrets, on its own task. Without <paramref name="app" /> the command's own page shows the approval (what a run does while "allow again
    /// for a few minutes" is on). With it the run goes to that app's service and the request waits in its Approvals queue, as it does by default.
    /// </summary>
    public static Cmd<int> Run(Rig rig, string secrets, string[] program, TimeSpan? timeLimit = null, SpaApp? app = null)
    {
        CliCommand.Run run = (CliCommand.Run)Parse(["--secrets", secrets, "--reason", "e2e run", "--", .. program]);

        // The run goes through the host service, as the program does: the service is in this process on a free port, and the CLI client
        // talks to it over HTTP. The page listens on the port the harness chose (the --port of the run).
        return new Cmd<int>((port, o, e) =>
        {
            // The machine is enrolled and approved through AdminActions (what the admin web app does after the passkey tap), with software keys.
            E2EMachine machine = rig.Machine;
            if (app is not null)
            {
                return LaunchClient.RunAsync(run.Args, rig.Work, app.Service.Port, null, o, e, machine.Trust).GetAwaiter().GetResult();
            }

            using HostService service = HostService.Start(new HostServiceOptions { Lock = AuthorityLock.UnlockedForTests(), State = rig.State, Store = rig.Store, Deployment = machine.Deployment, Port = 0, TimeLimit = timeLimit, ApproverFactory = (settings, announce) => CommandWiring.RunApprover(rig.State, settings, announce) });

            return LaunchClient.RunAsync(run.Args, rig.Work, service.Port, port, o, e, machine.Trust).GetAwaiter().GetResult();
        });
    }

    /// <summary>The passkey enrollment pages (what the admin app starts after its tap), with the confirmation code typed in this terminal.</summary>
    public static Cmd<int> Enroll(Rig rig)
    {
        return new Cmd<int>((port, o, e) =>
        {
            Action<string> announce = TerminalPrompt.Line;
            (EnrollmentTarget primary, EnrollmentTarget local) = CommandWiring.Targets(rig.State, ApprovalSettings.Load(rig.State, out _).WithPort(port), announce, CommandWiring.CodeReader("Press Ctrl+C to cancel."));
            ApprovalDecision decision = new Enrollment(primary, local, announce, rig.State.Audit).Enroll();
            TerminalPrompt.Final(decision.Approved ? decision.Detail : "with-secrets: " + decision.Detail);

            return decision.Approved ? 0 : RunCommand.Denied;
        });
    }

    /// <summary>The rotation of the store keys (what the admin app starts after its tap): two admin taps on pages the link leads to.</summary>
    public static Cmd<int> Rotate(Rig rig)
    {
        return new Cmd<int>((port, o, e) =>
        {
            Action<string> announce = TerminalPrompt.Line;
            (EnrollmentTarget primary, EnrollmentTarget local) = CommandWiring.Targets(rig.State, ApprovalSettings.Load(rig.State, out _).WithPort(port), announce, null);
            ConfigChange change = new KeyRotation(rig.State, rig.Store, primary, local, announce).Run();
            TerminalPrompt.Final(change.Done ? change.Detail : "with-secrets: " + change.Detail);

            return change.Code;
        });
    }
}

internal static class PageSteps
{
    /// <summary>
    /// The Save tap of the value pages: the first tap may only wait for the values to be sealed ("Ready. Tap Save."); the prompt
    /// starts in the next tap (the iOS rule), so tap again then.
    /// </summary>
    public static async Task TapSave(Ctx c)
    {
        await c.Click("#save");
        await c.Page.WaitForFunctionAsync("() => { var t = document.getElementById('status').textContent; return /Ready[.] Tap Save|Waiting for your passkey|Saving|Stored|Nothing was stored/.test(t); }", null, new() { Timeout = 20000 });
        if ((await c.Text("#status")).Contains("Ready. Tap Save"))
        {
            await c.Click("#save");
        }
    }
}

internal static class AuditChecks
{
    /// <summary>
    /// The audit events, oldest first: what the authority already has plus what is still in the outbox (the service uploads and removes). An administrative event is
    /// named by its event name, a run's by "type-outcome" (authorization-approved, launch-started, execution-exited).
    /// </summary>
    public static IReadOnlyList<AuditEvent> All(Rig rig)
    {
        Dictionary<string, AuditEvent> events = [];
        foreach (AuditHistoryRecord item in rig.Machine.Deployment.Store.AuditHistory(new AuditQuery(Limit: AuditQuery.MaxLimit)))
        {
            events[item.Event.EventId] = item.Event;
        }

        foreach (AuditEvent item in HostAuditOutbox.InFolder(rig.Folder, E2EAudit.KeyFor(rig.Folder)).Pending(100000))
        {
            events[item.EventId] = item;
        }

        return [.. events.Values.OrderBy(item => item.Sequence)];
    }

    public static string Name(AuditEvent item) => item.Type == AuditEventTypes.Admin ? item.Outcome : item.Type + "-" + item.Outcome;

    public static IReadOnlyList<string> Events(Rig rig) => [.. All(rig).Select(Name)];

    public static void Expect(S s, Rig rig, params string[] expected)
    {
        IReadOnlyList<string> events = Events(rig);
        s.Check(events.SequenceEqual(expected) && All(rig).All(item => item.Verify(E2EAudit.KeyFor(rig.Folder).PublicKey)), "audit events (signed): " + string.Join(", ", expected) + (events.SequenceEqual(expected) ? "" : " (got " + string.Join(", ", events) + ")"));
    }
}

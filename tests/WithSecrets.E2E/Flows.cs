using Microsoft.Playwright;

namespace WithSecrets.E2E;

/// <summary>Reusable page flows (the fixture steps of several scenarios).</summary>
internal static class Flows
{
    public sealed record Configured(string Recovery, int Code);

    /// <summary>First-run --config in the browser: save, Step 2, read the code and the recovery code from the page, type the code.</summary>
    public static async Task<Configured> Configure(Rig rig, Ctx c, S? s = null)
    {
        using Cmd<int> cmd = new((port, o, e) => CommandWiring.Config(rig.State, port));
        string link = await cmd.LinkAsync();
        await c.Page.GotoAsync(link);
        if (s is not null)
        {
            await Task.Delay(300);
            s.Check(await c.PasskeyCalls() == 0, "tap rule: no passkey prompt on page load");
        }

        await c.Click("#save");
        await c.Click("#confirm");
        string code = await c.TextAppears("#code");
        string recovery = await c.TextAppears("#recovery");
        cmd.Type(code);

        return new Configured(recovery, await cmd.Result.WaitAsync(TimeSpan.FromSeconds(30)));
    }
}

internal static class Cmds
{
    public static CliCommand Parse(params string[] args)
    {
        CliCommand? command = CliArgs.Parse(args, out string error);

        return command ?? throw new InvalidOperationException("bad test arguments: " + error);
    }

    /// <summary>A run of a program with secrets, on its own task; the page shows the approval.</summary>
    public static Cmd<int> Run(Rig rig, string secrets, string[] program, TimeSpan? timeLimit = null)
    {
        CliCommand.Run run = (CliCommand.Run)Parse(["--secrets", secrets, "--reason", "e2e run", "--", .. program]);

        // The run goes through the host service, as the program does: the service is in this process on a free port, and the CLI client
        // talks to it over HTTP. The page listens on the port the harness chose (the --port of the run).
        return new Cmd<int>((port, o, e) =>
        {
            // The machine is enrolled and approved through AdminActions (what `admin approve` does after the passkey tap), with software keys.
            E2EMachine machine = rig.Machine;
            using HostService service = HostService.Start(new HostServiceOptions { State = rig.State, Store = rig.Store, Grants = rig.Grants, Deployment = machine.Deployment, Port = 0, TimeLimit = timeLimit });

            return LaunchClient.RunAsync(run.Args, rig.Work, service.Port, port, o, e, machine.Trust).GetAwaiter().GetResult();
        });
    }

    public static Cmd<int> Set(Rig rig, params string[] names)
    {
        CliCommand command = Parse(["--set", string.Join(',', names)]);

        return new Cmd<int>((port, o, e) => CommandWiring.Change(command, rig.Store, rig.State, port));
    }

    public static Cmd<int> Remove(Rig rig, params string[] names)
    {
        CliCommand command = Parse(["--remove", string.Join(',', names)]);

        return new Cmd<int>((port, o, e) => CommandWiring.Change(command, rig.Store, rig.State, port));
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
    /// <summary>The audit event names, oldest first.</summary>
    public static IReadOnlyList<string> Events(Rig rig)
    {
        new AuditLog(rig.State).TryRead(200, null, out IReadOnlyList<AuditRecord> rows, out _);

        return [.. rows.Select(r => r.Event)];
    }

    public static void Expect(S s, Rig rig, params string[] expected)
    {
        IReadOnlyList<string> events = Events(rig);
        s.Check(events.SequenceEqual(expected) && new AuditLog(rig.State).Verify().Ok, "audit rows: " + string.Join(", ", expected) + (events.SequenceEqual(expected) ? "" : " (got " + string.Join(", ", events) + ")"));
    }
}

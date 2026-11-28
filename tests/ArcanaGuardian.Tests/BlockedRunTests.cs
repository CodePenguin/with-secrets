using System.Text.RegularExpressions;

namespace ArcanaGuardian.Tests;

/// <summary>
/// A run that is blocked on approval ends in one of three clearly different ways, all reported to the command line (the real client, the real service, the real approval page and a test authenticator):
/// approved (the program runs and its own exit code is the result), refused (the person pressed Deny: exit 3, "The user did not approve (denied on the page)") and timed out (nobody answered: also exit 3, which the
/// exit-code table already assigns to "Deny on the page, wrong proof, time limit", but with its own sentence and its own audit reason code, so a caller can tell them apart and knows it may ask again).
/// </summary>
internal static class BlockedRunTests
{
    private const string Value = "Canary-Blocked-Run-5150";

    public static async Task Run(Action<bool, string> check)
    {
        string parent = Path.Combine(Path.GetTempPath(), "ws-blocked-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(parent);
        try
        {
            await Outcomes(check, parent);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try
            {
                Directory.Delete(parent, true);
            }
            catch (IOException)
            {
                // A stray file in the temp folder is harmless.
            }
        }
    }

    private sealed record Ended(int Exit, string Stdout, string Stderr, int Reads, string Audit, bool Ran, string RemoteMessage);

    private static async Task<Ended> Blocked(string parent, string answer, TimeSpan limit)
    {
        string folder = Path.Combine(parent, "run-" + Guid.NewGuid().ToString("N")[..6]);
        string work = Path.Combine(folder, "work");
        Directory.CreateDirectory(work);
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        string program = OperatingSystem.IsWindows() ? "show.cmd" : "show.sh";
        string marker = Path.Combine(work, "ran.marker.txt");
        string path = Path.Combine(work, program);
        if (OperatingSystem.IsWindows())
        {
            File.WriteAllText(path, "@echo off\r\necho t=%TOKEN%\r\necho ran> \"" + marker + "\"\r\nexit /b 4\r\n");
        }
        else
        {
            File.WriteAllText(path, "#!/bin/sh\necho \"t=$TOKEN\"\necho ran > '" + marker + "'\nexit 4\n");
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        StateDatabase db = StateDatabase.InFolder(Path.Combine(folder, "state"));
        new PasskeyStore(db).Add(laptop.Record("localhost", "laptop"));
        using TestMachine machine = new(Path.GetDirectoryName(db.FilePath)!);
        CountingCipher cipher = new();
        SecretStore store = new(db, cipher);
        if (SecretStoreTests.Put(store, new Dictionary<string, string> { ["TOKEN"] = Value }) is { } problem)
        {
            throw new InvalidOperationException(problem);
        }

        using HostService service = HostService.Start(new HostServiceOptions { HttpBrowserFixture = true, CommandLineEndpoint = HostServiceTests.Rig.TestEndpoint(), Lock = AuthorityLock.UnlockedForTests(), State = db, Store = store, Deployment = machine.Deployment, Port = 0, TimeLimit = limit, ApproverFactory = (settings, announce) => CommandWiring.RunApprover(db, settings, announce) });
        SecretStoreTests.OpenKeys(service, db);
        using HttpClient browser = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(30) };
        StringWriter stdout = new();
        StringWriter stderr = new();
        RunArgs args = CliArgs.ParseRun(["--secrets", "TOKEN", "--reason", "a blocked run", "--", "./" + program], out _)!;
        Task<int> client = LaunchClient.RunAsync(args, work, service.Endpoint, null, stdout, stderr, machine.Trust);

        // The person: finds the link the command line printed and answers it (or does nothing).
        DateTime end = DateTime.UtcNow.AddSeconds(20);
        string? link = null;
        while (DateTime.UtcNow < end && link is null && !client.IsCompleted)
        {
            Match match = Regex.Match(stderr.ToString(), Regex.Escape(WebApprover.LinkPrefix) + @"(\S+)");
            link = match.Success ? match.Groups[1].Value : null;
            if (link is null)
            {
                await Task.Delay(25);
            }
        }

        if (link is not null && answer != "none")
        {
            Uri uri = new(link);
            string baseUrl = "http://127.0.0.1:" + uri.Port + uri.AbsolutePath;
            if (answer == "approve")
            {
                TestState.Approve(browser, baseUrl, uri.GetLeftPart(UriPartial.Authority), uri.IdnHost, laptop);
            }
            else
            {
                TestState.Post(browser, baseUrl + "/deny", "");
            }
        }

        int exit = await client.WaitAsync(TimeSpan.FromSeconds(60));
        string audit = string.Join("\n", StateDatabaseTests.AuditLines(db.FilePath).Concat(machine.Deployment.Store.AuditHistory(new AuditQuery(Limit: 1000)).Select(item => item.Event.ToJson())).Distinct());

        return new Ended(exit, stdout.ToString(), stderr.ToString(), cipher.Decrypts, audit, File.Exists(marker), service.Authorization.Message(ReasonCodes.ApprovalTimeout));
    }

    private static async Task Outcomes(Action<bool, string> check, string parent)
    {
        Ended approved = await Blocked(parent, "approve", TimeSpan.FromSeconds(30));
        check(approved.Exit == 4 && approved.Ran && approved.Reads == 1 && approved.Stdout.Contains("t=[REDACTED]", StringComparison.Ordinal) && !approved.Stderr.Contains("did not approve", StringComparison.Ordinal), $"blocked run: approved on the page, the program runs and its own exit code is the result (exit {approved.Exit}, reads {approved.Reads})");
        check(approved.Audit.Contains("\"outcome\":\"approved\"", StringComparison.Ordinal) && !approved.Audit.Contains("approval-timeout", StringComparison.Ordinal), "blocked run: the approved run's signed authorization event says approved");

        Ended refused = await Blocked(parent, "deny", TimeSpan.FromSeconds(30));
        check(refused.Exit == RunCommand.Denied && !refused.Ran && refused.Reads == 0 && refused.Stderr.Contains("The user did not approve (denied on the page)", StringComparison.Ordinal), $"blocked run: Deny on the page is exit 3 with the line naming the denial, nothing decrypted, nothing run (exit {refused.Exit}, reads {refused.Reads})");
        check(refused.Audit.Contains("user-denied", StringComparison.Ordinal) && !refused.Audit.Contains("approval-timeout", StringComparison.Ordinal), "blocked run: a refusal is audited as user-denied");

        Ended timedOut = await Blocked(parent, "none", TimeSpan.FromSeconds(2));
        check(timedOut.Exit == RunCommand.Denied && !timedOut.Ran && timedOut.Reads == 0 && timedOut.Stderr.Contains("Nobody answered before the approval time limit", StringComparison.Ordinal) && !timedOut.Stderr.Contains("The user did not approve", StringComparison.Ordinal), $"blocked run: no answer before the time limit is exit 3 with its own sentence, nothing decrypted, nothing run (exit {timedOut.Exit}, reads {timedOut.Reads})");
        check(timedOut.Audit.Contains("approval-timeout", StringComparison.Ordinal) && !timedOut.Audit.Contains("user-denied", StringComparison.Ordinal), "blocked run: a timeout is audited as approval-timeout, not as a refusal");

        string refusedLine = refused.Stderr.Split('\n').LastOrDefault(line => line.Contains("did not approve", StringComparison.Ordinal)) ?? "";
        string timeoutLine = timedOut.Stderr.Split('\n').LastOrDefault(line => line.Contains("Nobody answered", StringComparison.Ordinal)) ?? "";
        check(approved.Exit != refused.Exit && refusedLine != timeoutLine && !timeoutLine.Contains("Do not retry", StringComparison.Ordinal), "blocked run: approved, refused and timed out are three different outcomes (exit code or sentence), and a timeout does not say not to retry");
        check(!(approved.Stdout + approved.Stderr + refused.Stderr + timedOut.Stderr + refused.Audit + timedOut.Audit).Contains(Value, StringComparison.Ordinal), "blocked run: no secret value in any output or audit event of the three outcomes");

        // A timeout where the authority is another machine reports the same: the reason code travels in the signed answer.
        check(ReasonCodes.ApprovalTimeout == "approval-timeout" && timedOut.RemoteMessage == HostAuthorization.TimeoutMessage, "blocked run: the reason code of a timeout has its own message at a host whose authority is remote");
    }
}

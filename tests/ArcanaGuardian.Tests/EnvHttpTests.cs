using System.Net;

namespace ArcanaGuardian.Tests;

internal static partial class WebApprovalTests
{
    /// <summary>
    /// A run that declares its secrets in the project's .env, over real HTTP with a test authenticator and the real signed store:
    /// the page shows every pair and the path, the mapping injects the value under the left-side name, the output is redacted,
    /// a deny reads nothing, and a .env changed while the page is open changes nothing.
    /// </summary>
    internal static async Task EnvHttp(Action<bool, string> check, string parent)
    {
        string folder = Path.Combine(parent, "http-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(folder);
        using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
        client.Timeout = TimeSpan.FromSeconds(20);
        ApprovalSettings local = new(null, 0, TimeSpan.FromSeconds(20));
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        const string Stripe = "team/payments/STRIPE_KEY";
        const string StripeValue = "Stripe-Value-4711";
        const string Unrelated = "Unrelated-Value-0815";
        const string Ordinary = "Verbose7";
        int states = 0;

        string scripts = Path.Combine(folder, "project");
        Directory.CreateDirectory(scripts);
        string program = OperatingSystem.IsWindows() ? "show.cmd" : "show.sh";
        string programPath = Path.Combine(scripts, program);
        string envFile = Path.Combine(scripts, "env.txt");
        string dotenv = Path.Combine(scripts, ".env");
        if (OperatingSystem.IsWindows())
        {
            File.WriteAllText(programPath, "@echo off\r\nset > \"%~dp0env.txt\"\r\necho t=%TOKEN%\r\necho l=%LOG_LEVEL%\r\n");
        }
        else
        {
            File.WriteAllText(programPath, "#!/bin/sh\nenv > \"" + envFile + "\"\necho \"t=$TOKEN\"\necho \"l=$LOG_LEVEL\"\n");
            File.SetUnixFileMode(programPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        (StateDatabase Db, PasskeyStore Passkeys, SecretStore Store, CountingCipher Cipher) NewState()
        {
            StateDatabase db = StateDatabase.InFolder(Path.Combine(folder, "state-" + Interlocked.Increment(ref states)));
            PasskeyStore passkeys = new(db);
            passkeys.Add(laptop.Record("localhost", "laptop"));
            CountingCipher cipher = new();
            SecretStore store = new(db, cipher);
            if (SecretStoreTests.Put(store, new Dictionary<string, string> { [Stripe] = StripeValue, ["UNRELATED_KEY"] = Unrelated }) is { } problem)
            {
                throw new InvalidOperationException(problem);
            }

            return (db, passkeys, store, cipher);
        }

        async Task<(int Code, string Out, string Err, List<string> Seen, bool Ran)> RunWith(StateDatabase db, PasskeyStore passkeys, SecretStore store, Func<string, string, string, (int Status, string Body)> approve)
        {
            File.Delete(envFile);
            TaskCompletionSource<string> link = new(TaskCreationOptions.RunContinuationsAsynchronously);
            StringWriter stdout = new();
            StringWriter stderr = new();
            TextWriter errors = TextWriter.Synchronized(stderr);
            PasskeyMethod method = new(passkeys, local);
            WebApprover approver = new(method, local, line =>
            {
                errors.WriteLine(line);
                link.TrySetResult(line);
            }, TimeSpan.Zero);
            RunArgs args = CliArgs.ParseRun(["--reason", "env http test", "--", "./" + program], out _)!;
            RunCommand command = new(SecretStoreTests.Unlocked(store), approver, TextWriter.Synchronized(stdout), errors, environment: _ => null);
            Task<int> running = Task.Run(() => command.ExecuteAsync(args, scripts, TestAudit.Sink(db)));
            List<string> seen = [];
            Task first = await Task.WhenAny(link.Task, running, Task.Delay(TimeSpan.FromSeconds(20)));
            if (first == link.Task)
            {
                Uri uri = new(link.Task.Result[AnnouncePrefix.Length..]);
                string baseUrl = "http://127.0.0.1:" + uri.Port + uri.AbsolutePath;
                seen.Add(Text(Send(client, HttpMethod.Get, baseUrl)));
                (int status, string body) = approve(baseUrl, uri.GetLeftPart(UriPartial.Authority), uri.IdnHost);
                seen.Add(status + " " + body);
            }

            Task done = await Task.WhenAny(running, Task.Delay(TimeSpan.FromSeconds(30)));

            return (done == running ? running.Result : -1, stdout.ToString(), stderr.ToString(), seen, File.Exists(envFile));
        }

        // approved: the mapping, the page text, redaction, one decrypt
        File.WriteAllText(dotenv, $"TOKEN=secret://{Stripe}\nLOG_LEVEL={Ordinary}\n");
        (StateDatabase db, PasskeyStore passkeys, SecretStore store, CountingCipher cipher) = NewState();
        var result = await RunWith(db, passkeys, store, (url, origin, rp) => TestState.Approve(client, url, origin, rp, laptop));
        string env = File.Exists(envFile) ? File.ReadAllText(envFile) : "";
        string page = WebUtility.HtmlDecode(result.Seen.FirstOrDefault() ?? "");
        string audit = StateDatabaseTests.AuditText(db.FilePath);
        check(result.Code == 0 && result.Out.Contains("t=[REDACTED]", StringComparison.Ordinal) && result.Out.Contains("l=" + Ordinary, StringComparison.Ordinal), "env http: approved, the value reaches the program as TOKEN and the output is redacted (" + result.Code + " " + result.Err + ")");
        check(env.Contains("TOKEN=" + StripeValue, StringComparison.Ordinal) && !env.Contains(Unrelated, StringComparison.Ordinal) && cipher.Decrypts == 1, "env http: the program has the mapped value only, and one row was decrypted (" + cipher.Decrypts + ")");
        check(page.Contains($"TOKEN <- secret {Stripe}", StringComparison.Ordinal) && page.Contains(dotenv, StringComparison.Ordinal) && page.Contains("LOG_LEVEL", StringComparison.Ordinal), "env http: the page shows the pair, the .env path and the ordinary name");
        string everything = string.Join("\n", [.. result.Seen, result.Out, result.Err, audit]);
        check(!everything.Contains(StripeValue, StringComparison.Ordinal) && page.Contains("\n  | LOG_LEVEL=" + Ordinary, StringComparison.Ordinal) && !result.Err.Contains(Ordinary, StringComparison.Ordinal) && !audit.Contains(Ordinary, StringComparison.Ordinal), "env http: no secret value is on the page, stderr or audit; the ordinary value is on the page and not on the terminal");
        check(audit.Contains("\"outcome\":\"approved\"", StringComparison.Ordinal) && !audit.Contains(StripeValue, StringComparison.Ordinal), "env http: the signed authorization event is there and has no value");

        // denied: no row is decrypted, nothing runs
        (db, passkeys, store, cipher) = NewState();
        using TestAuthenticator stranger = TestAuthenticator.ES256();
        result = await RunWith(db, passkeys, store, (url, origin, rp) => TestState.Approve(client, url, origin, rp, stranger));
        check(result.Code == RunCommand.Denied && cipher.Decrypts == 0 && !result.Ran && !result.Out.Contains(StripeValue, StringComparison.Ordinal), "env http: denied means nothing is decrypted and nothing runs (" + result.Code + ")");

        // the agent edits the .env after the page was built and before the tap: the run is what the page showed
        (db, passkeys, store, cipher) = NewState();
        result = await RunWith(db, passkeys, store, (url, origin, rp) =>
        {
            File.WriteAllText(dotenv, "TOKEN=secret://UNRELATED_KEY\nNODE_OPTIONS=--require x\nLOG_LEVEL=changed\n");

            return TestState.Approve(client, url, origin, rp, laptop);
        });
        env = File.Exists(envFile) ? File.ReadAllText(envFile) : "";
        check(result.Code == 0 && env.Contains("TOKEN=" + StripeValue, StringComparison.Ordinal) && !env.Contains(Unrelated, StringComparison.Ordinal) && !env.Contains("LOG_LEVEL=changed", StringComparison.Ordinal) && cipher.Decrypts == 1, "env http: a .env changed while the page is open changes nothing (" + result.Code + " " + result.Err + ")");
        File.WriteAllText(dotenv, $"TOKEN=secret://{Stripe}\n");

        // --set with a folder name, then a run that reads it through the .env: the whole path is the store name
        {
            StateDatabase setDb = StateDatabase.InFolder(Path.Combine(folder, "state-set"));
            PasskeyStore setPasskeys = new(setDb);
            TestState.Add(setDb, laptop.Record("localhost", "laptop"), withStore: true);
            SecretStore setStore = new(setDb);
            EntryRun set = SetRun(setPasskeys, setStore, [Stripe], laptop, Values((Stripe, StripeValue)));
            check(set.Result is { Code: 0 } && setStore.ListNames().SequenceEqual([Stripe]) && StateDatabaseTests.AuditText(setDb.FilePath).Contains(Stripe, StringComparison.Ordinal), "env http: --set takes a folder name, the whole path is the store name (" + set.Result?.Detail + ")");
            File.WriteAllText(dotenv, $"TOKEN=secret://{Stripe}\n");
            result = await RunWith(setDb, setPasskeys, setStore, (url, origin, rp) => TestState.Approve(client, url, origin, rp, laptop));
            check(result.Code == 0 && result.Out.Contains("t=[REDACTED]", StringComparison.Ordinal) && File.ReadAllText(envFile).Contains("TOKEN=" + StripeValue, StringComparison.Ordinal), "env http: set then run with a folder name: the value reaches TOKEN (" + result.Code + " " + result.Err + ")");
        }
    }
}

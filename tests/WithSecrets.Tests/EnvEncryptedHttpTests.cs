using System.Collections.Concurrent;
using System.Net;
using System.Text;

using Serilog.Core;
using Serilog.Events;

namespace WithSecrets.Tests;

internal static partial class WebApprovalTests
{
    private sealed class LogCapture : ILogEventSink
    {
        public ConcurrentQueue<LogEvent> Events { get; } = new();

        public void Emit(LogEvent logEvent) => Events.Enqueue(logEvent);

        public string Everything() => string.Join("\n", Events.Select(item => AppLog.Render(item) + "\n" + string.Join("\n", item.Properties.Select(pair => pair.Key + "=" + pair.Value))));
    }

    /// <summary>Delegated dotenvx and store values over the real passkey approval page.</summary>
    internal static async Task EnvEncryptedHttp(Action<bool, string> check, string parent)
    {
        string folder = Path.Combine(parent, "enc-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(folder);
        using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
        client.Timeout = TimeSpan.FromSeconds(20);
        ApprovalSettings local = new(null, 0, TimeSpan.FromSeconds(20));
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        const string Plain = "Decrypted-Value-6021";
        const string ApiValue = "Api-Value-4711";
        const string Ordinary = "Verbose7";
        int states = 0;

        using var fake = new FakeDotenvx();
        string privateKey = FakeDotenvx.Credential;
        string cipher = FakeDotenvx.Cipher(Plain);
        const string stranger = "encrypted:YmFkLXNlY29uZA==";
        string cipherBody = cipher["encrypted:".Length..];

        string project = Path.Combine(folder, "project");
        Directory.CreateDirectory(project);
        string program = OperatingSystem.IsWindows() ? "show.cmd" : "show.sh";
        string programPath = Path.Combine(project, program);
        string envFile = Path.Combine(project, "env.txt");
        string dotenv = Path.Combine(project, ".env");
        if (OperatingSystem.IsWindows())
        {
            File.WriteAllText(programPath, "@echo off\r\nset > \"%~dp0env.txt\"\r\necho d=%DB_PASS%\r\necho t=%TOKEN%\r\necho l=%LOG_LEVEL%\r\n");
        }
        else
        {
            File.WriteAllText(programPath, "#!/bin/sh\nenv > \"" + envFile + "\"\necho \"d=$DB_PASS\"\necho \"t=$TOKEN\"\necho \"l=$LOG_LEVEL\"\n");
            File.SetUnixFileMode(programPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        (StateDatabase Db, PasskeyStore Passkeys, SecretStore Store, CountingCipher Cipher) NewState()
        {
            StateDatabase db = StateDatabase.InFolder(Path.Combine(folder, "state-" + Interlocked.Increment(ref states)));
            PasskeyStore passkeys = new(db);
            passkeys.Add(laptop.Record("localhost", "laptop"));
            CountingCipher counting = new();
            SecretStore store = new(db, counting);
            Dictionary<string, string> values = new() { ["team/API_KEY"] = ApiValue };
            if (SecretStoreTests.Put(store, values) is { } problem)
            {
                throw new InvalidOperationException(problem);
            }

            return (db, passkeys, store, counting);
        }

        async Task<(int Code, string Out, string Err, string Page, string Reply, bool Ran)> RunWith(StateDatabase db, PasskeyStore passkeys, SecretStore store, Func<string, string?>? os = null)
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
            RunArgs args = CliArgs.ParseRun(["--reason", "encrypted env test", "--", "./" + program], out _)!;
            RunCommand command = new(store, approver, TextWriter.Synchronized(stdout), errors, environment: name => os?.Invoke(name));
            Task<int> running = Task.Run(() => command.ExecuteAsync(args, project, TestAudit.Sink(db)));
            string page = "";
            string reply = "";
            Task first = await Task.WhenAny(link.Task, running, Task.Delay(TimeSpan.FromSeconds(20)));
            if (first == link.Task)
            {
                Uri uri = new(link.Task.Result[AnnouncePrefix.Length..]);
                string baseUrl = "http://127.0.0.1:" + uri.Port + uri.AbsolutePath;
                page = WebUtility.HtmlDecode(Text(Send(client, HttpMethod.Get, baseUrl)));
                (int status, string body) = TestState.Approve(client, baseUrl, uri.GetLeftPart(UriPartial.Authority), uri.IdnHost, laptop);
                reply = status + " " + body;
            }

            Task done = await Task.WhenAny(running, Task.Delay(TimeSpan.FromSeconds(30)));

            return (done == running ? running.Result : -1, stdout.ToString(), stderr.ToString(), page, reply, File.Exists(envFile));
        }

        // approved: the decrypted value reaches DB_PASS, redacted; the key is on no surface
        File.WriteAllText(dotenv, $"DB_PASS={cipher}\nTOKEN=secret://team/API_KEY\nLOG_LEVEL={Ordinary}\n");
        LogCapture capture = new();
        TextWriter? terminalBefore = TerminalPrompt.Output;
        StringWriter debugScreen = new();
        string logFolder = Path.Combine(folder, "logs");
        TerminalPrompt.Output = debugScreen;
        AppLog.LogFolder = logFolder;
        AppLog.Tap = capture;
        AppLog.Configure(true);
        (StateDatabase db, PasskeyStore passkeys, SecretStore store, CountingCipher counting) = NewState();
        var result = await RunWith(db, passkeys, store);
        AppLog.Close();
        string logFiles = Directory.Exists(logFolder) ? string.Join("\n", Directory.EnumerateFiles(logFolder).Select(file =>
        {
            using FileStream stream = new(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using StreamReader reader = new(stream, Encoding.UTF8);

            return reader.ReadToEnd();
        })) : "";
        string logEverything = capture.Everything() + "\n" + logFiles;
        string terminalDebug = debugScreen.ToString();
        AppLog.LogFolder = null;
        AppLog.Tap = null;
        TerminalPrompt.Output = terminalBefore;

        string env = File.Exists(envFile) ? File.ReadAllText(envFile) : "";
        string audit = StateDatabaseTests.AuditText(db.FilePath);
        check(result.Code == 0 && result.Out.Contains("d=[REDACTED]", StringComparison.Ordinal) && result.Out.Contains("t=[REDACTED]", StringComparison.Ordinal) && result.Out.Contains("l=" + Ordinary, StringComparison.Ordinal), "env encrypted http: approved, the decrypted value is injected and redacted (" + result.Code + " " + result.Err + ")");
        check(env.Contains("DB_PASS=" + Plain, StringComparison.Ordinal) && env.Contains("TOKEN=" + ApiValue, StringComparison.Ordinal), "env encrypted http: the program has the decrypted value as DB_PASS and the reference as TOKEN");
        check(!env.Contains("DOTENV_PRIVATE_KEY", StringComparison.Ordinal) && !env.Contains(privateKey, StringComparison.Ordinal) && !env.Contains(cipherBody, StringComparison.Ordinal), "env encrypted http: the private key is not in the child's environment, and neither is the ciphertext");
        check(counting.Decrypts == 1, "env encrypted http: the store decrypted only the WithSecrets reference (" + counting.Decrypts + ")");
        check(result.Page.Contains("\nresolve with dotenvx: DB_PASS (cipher sha256 " + DecryptItem.HashOf(cipher)[..12] + ") from " + dotenv, StringComparison.Ordinal) && result.Page.Split('\n').FirstOrDefault(line => line.StartsWith("Secrets: ", StringComparison.Ordinal))?.Contains("DOTENV_PRIVATE_KEY", StringComparison.Ordinal) == false, "env encrypted http: the page has the decrypt line and requests no Dotenvx key from the store");
        string everything = string.Join("\n", [result.Page, result.Reply, result.Out, result.Err, audit, logEverything, terminalDebug]);
        check(!everything.Contains(privateKey, StringComparison.Ordinal) && !everything.Contains(Plain, StringComparison.Ordinal) && !everything.Contains(cipherBody, StringComparison.Ordinal) && !everything.Contains(ApiValue, StringComparison.Ordinal), "env encrypted http: the key, the decrypted value, the ciphertext and the reference value are on no page, stdout, stderr, audit row, log or debug line");
        check(logFiles.Length > 0 || capture.Events.Count > 0, "env encrypted http: the leak check had log output to look at");
        check(audit.Contains("\"decrypts\":\"DB_PASS:" + DecryptItem.HashOf(cipher)[..12] + "\"", StringComparison.Ordinal) && audit.Contains("\"outcome\":\"approved\"", StringComparison.Ordinal), "env encrypted http: the signed events name the variable and the short cipher fingerprint");

        // an OS variable hides the encrypted value: it is not decrypted and the key is not requested, even when the store has none
        (db, passkeys, store, counting) = NewState();
        result = await RunWith(db, passkeys, store, name => name == "DB_PASS" ? "from-os" : null);
        env = File.Exists(envFile) ? File.ReadAllText(envFile) : "";
        check(result.Code == 0 && counting.Decrypts == 1 && !result.Page.Contains("decrypt ", StringComparison.Ordinal) && !result.Page.Contains("DOTENV_PRIVATE_KEY", StringComparison.Ordinal) && !env.Contains(Plain, StringComparison.Ordinal), "env encrypted http: an overridden encrypted value is not decrypted and its key is not requested (" + result.Code + " " + result.Err + ")");

        // a value that does not decrypt (damaged, or made for another key): exit 2 naming the variable only, nothing runs
        foreach ((string label, string bad) in new[] { ("damaged", "encrypted:" + new string('A', 120)), ("another key", stranger) })
        {
            File.WriteAllText(dotenv, $"DB_PASS={bad}\nTOKEN=secret://team/API_KEY\n");
            (db, passkeys, store, counting) = NewState();
            result = await RunWith(db, passkeys, store);
            audit = StateDatabaseTests.AuditText(db.FilePath);
            string badBody = bad["encrypted:".Length..];
            check(result.Code == RunCommand.Usage && result.Err.Contains("with dotenvx", StringComparison.Ordinal) && !result.Ran && !result.Out.Contains(ApiValue, StringComparison.Ordinal), "env encrypted http: a " + label + " value is exit 2 naming the variable, and the program does not run (" + result.Code + ")");
            check(!result.Err.Contains(badBody, StringComparison.Ordinal) && !result.Page.Contains(badBody, StringComparison.Ordinal) && !audit.Contains(badBody, StringComparison.Ordinal) && !result.Err.Contains(privateKey, StringComparison.Ordinal) && !result.Out.Contains(privateKey, StringComparison.Ordinal), "env encrypted http: a " + label + " value leaves no ciphertext or key on stderr, page or audit");
        }

        // --set: a name that differs only by case from a stored one gets a visible warning on the page, and may still be saved
        {
            StateDatabase setDb = StateDatabase.InFolder(Path.Combine(folder, "state-case"));
            PasskeyStore setPasskeys = new(setDb);
            TestState.Add(setDb, laptop.Record("localhost", "laptop"), withStore: true);
            SecretStore setStore = new(setDb);
            EntryRun first = SetRun(setPasskeys, setStore, ["team/API_KEY"], laptop, Values(("team/API_KEY", ApiValue)));
            string firstPage = WebUtility.HtmlDecode((first.Entry?.Text ?? ""));
            check(first.Result is { Code: 0 } && !firstPage.Contains("Warning:", StringComparison.Ordinal), "env encrypted http: --set of a name with no case twin shows no warning (" + first.Result?.Detail + ")");
            EntryRun second = SetRun(setPasskeys, setStore, ["Team/Api_Key"], laptop, Values(("Team/Api_Key", "Other-Value-0815")));
            string secondPage = WebUtility.HtmlDecode((second.Entry?.Text ?? ""));
            check(secondPage.Contains("Warning: Team/Api_Key differs only by case from the existing name: team/API_KEY", StringComparison.Ordinal), "env encrypted http: --set text warns that the name differs only by case from the existing name, naming it");
            check(second.Result is { Code: 0 } && setStore.ListNames().Order(StringComparer.Ordinal).SequenceEqual(["Team/Api_Key", "team/API_KEY"]), "env encrypted http: the warning is not a refusal, both names are stored (" + second.Result?.Detail + ")");
            check(!string.Join("\n", second.Seen).Contains("Other-Value-0815", StringComparison.Ordinal), "env encrypted http: the new value is in no text");
            EntryRun same = SetRun(setPasskeys, setStore, ["team/API_KEY"], laptop, Values(("team/API_KEY", "Replaced-Value-77")));
            string samePage = WebUtility.HtmlDecode((same.Entry?.Text ?? ""));
            check(samePage.Contains("Warning: team/API_KEY differs only by case from the existing name: Team/Api_Key", StringComparison.Ordinal) && samePage.Contains("team/API_KEY (replace)", StringComparison.Ordinal), "env encrypted http: replacing a name still warns about its case twin");
        }
    }
}

using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace WithSecrets.Tests;

internal sealed class FakeApprover(bool approve) : IApprover
{
    public List<ApprovalRequest> Requests { get; } = [];

    public ApprovalDecision Request(ApprovalRequest request)
    {
        Requests.Add(request);

        return approve ? ApprovalDecision.Allow() : ApprovalDecision.Deny("test denied");
    }
}

internal sealed class EditingApprover(string file) : IApprover
{
    public ApprovalDecision Request(ApprovalRequest request)
    {
        File.WriteAllText(file, "#!/bin/sh\necho swapped\n");

        return ApprovalDecision.Allow();
    }
}

internal sealed class ThrowingApprover : IApprover
{
    public ApprovalDecision Request(ApprovalRequest request) => throw new InvalidOperationException("boom");
}

internal sealed class MemoryStore(Dictionary<string, string> values) : ISecretStore
{
    public IReadOnlyList<string> ListNames() => values.Keys.ToList();

    public IReadOnlyDictionary<string, string> GetValues(IReadOnlyCollection<string> names)
        => names.ToDictionary(name => name, name => values[name]);

    public void Set(string name, string value) => values[name] = value;

    public bool Remove(string name) => values.Remove(name);
}

internal static class Program
{
    private static int _failed;
    private static int _passed;

    /// <summary>Runs the action on the window's own thread after a delay. A window that is already gone is ignored.</summary>
    private static void Later(Control form, int milliseconds, Action action)
    {
        _ = Task.Delay(milliseconds).ContinueWith(
            _ =>
            {
                try
                {
                    form.BeginInvoke(action);
                }
                catch (Exception error) when (error is ObjectDisposedException or InvalidOperationException)
                {
                    // The window closed first.
                }
            },
            TaskScheduler.Default);
    }

    private static void Check(bool condition, string name)
    {
        if (condition)
        {
            _passed++;
        }
        else
        {
            _failed++;
            Console.WriteLine("FAIL: " + name);
        }
    }

    private static string Redact(IEnumerable<string> secrets, params string[] chunks)
    {
        StreamRedactor redactor = new(secrets);
        StringBuilder output = new();
        foreach (string chunk in chunks)
        {
            output.Append(redactor.Push(chunk));
        }

        return output.Append(redactor.Finish()).ToString();
    }

    private static int Main()
    {
        const string Secret = "S3cr3t-Value/with+chars==";

        // --- redaction: forms
        Check(Redact([Secret], $"a {Secret} b") == "a [REDACTED] b", "exact value");
        Check(Redact([Secret], $"a {Convert.ToBase64String(Encoding.UTF8.GetBytes(Secret))} b").Contains("S3cr3t", StringComparison.Ordinal) == false, "base64 value");
        foreach (string prefix in new[] { "", "x", "xy" })
        {
            string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(prefix + Secret + "tail"));
            string redacted = Redact([Secret], "data=" + encoded + ";");
            string[] pieces = ["UzNjcjN0", "czNjcjN0", "MzY3IzN0"];
            Check(redacted.Contains("[REDACTED]", StringComparison.Ordinal), $"base64 inside larger text, offset '{prefix}'");
            Check(!pieces.Any(piece => redacted.Contains(piece, StringComparison.Ordinal)), $"base64 not left behind, offset '{prefix}'");
        }

        Check(Redact([Secret], $"url={Uri.EscapeDataString(Secret)}") == "url=[REDACTED]", "url-escaped value");
        Check(Redact([Secret], $"hex={Convert.ToHexString(Encoding.UTF8.GetBytes(Secret)).ToLowerInvariant()}") == "hex=[REDACTED]", "hex value");
        Check(Redact(["pa\"ss\\word1"], "{\"k\":\"pa\\\"ss\\\\word1\"}") == "{\"k\":\"[REDACTED]\"}", "json-escaped value");
        Check(Redact(["abcdef123456"], "nothing to see") == "nothing to see", "no secret, text unchanged");

        // --- redaction: chunk boundaries
        Check(Redact(["abcdef123456"], "x abcd", "ef123456 y") == "x [REDACTED] y", "secret split across two chunks");
        Check(Redact(["abcdef123456"], "x ", "abc", "def", "123", "456", " y") == "x [REDACTED] y", "secret split across many chunks");
        Check(Redact(["abcdef123456"], "end abcdef") == "end [REDACTED]", "unfinished prefix is masked at the end");
        Check(Redact(["abcdef123456"], "ab", "xyz") == "abxyz", "held-back text is released when it cannot be a secret");
        Check(Redact(["abcdef", "abcdefghij"], "abcdefghij") == "[REDACTED]", "longest match wins");

        // --- policy
        string tricky = new(['a', (char)0x202E, 'b', (char)0x200B, (char)0x2028, (char)0x2029, (char)0x2066, 'c']);
        Check(ApprovalSummary.Clean(tricky) == "a□b□⏎⏎□c", "clean: bidi override, zero-width, line and paragraph separators, isolates are replaced");
        Check(ApprovalSummary.Clean("dotnet test --x=1 é ü 日本") == "dotnet test --x=1 é ü 日本", "clean: ordinary text, accents and CJK are unchanged");
        Check(Policy.Check("env", []) is not null, "env dump refused");
        Check(Policy.Check("/usr/bin/printenv", ["A"]) is not null, "printenv refused");
        Check(Policy.Check("bash", ["-c", "echo $A"]) is not null, "bash -c refused");
        Check(Policy.Check("bash", ["-lc", "echo $A"]) is not null, "bash -lc refused");
        Check(Policy.Check("bash", ["script.sh"]) is null, "bash script.sh allowed");
        Check(Policy.Check("cmd.exe", ["/c", "echo"]) is not null, "cmd /c refused");
        Check(Policy.Check("pwsh", ["-Command", "x"]) is not null, "pwsh -Command refused");
        Check(Policy.Check("pwsh.exe", ["-NoProfile", "-File", "run.ps1"]) is null, "pwsh -File allowed");
        Check(Policy.Check("dotnet", ["test"]) is null, "dotnet test allowed");
        Check(Policy.CheckBatchFile(@"C:\x\npm.CMD", ["run", "build", "--", "--flag=1"]) is null, "batch file: plain arguments allowed");
        Check(Policy.CheckBatchFile(@"C:\x\run.bat", ["x\" & echo INJECTED & \""]) is not null, "batch file: quote breakout refused");
        Check(Policy.CheckBatchFile(@"C:\x\run.bat", ["a&calc"]) is not null, "batch file: & refused");
        Check(Policy.CheckBatchFile(@"C:\x\run.cmd", ["%DB_URL%"]) is not null, "batch file: %VAR% expansion refused");
        Check(Policy.CheckBatchFile(@"C:\x\run.cmd", ["a|b", "c>d", "e<f", "g^h", "!V!", "a\nb"]) is not null, "batch file: | > < ^ ! and line breaks refused");
        Check(Policy.CheckBatchFile(@"C:\x\tool.exe", ["a&b", "%X%", "\"q\""]) is null, "batch file: rules apply only to .cmd and .bat");
        Check(Policy.Check("dotnet", [new string('x', 600)]) is null, "a 600 character command is allowed");
        Check(Policy.Check("dotnet", [new string('x', 3000)]) is null, "a 3000 character command is allowed");
        Check(Policy.Check("dotnet", [new string('x', 17000)]) is not null, "a command past the technical limit is refused");

        // --- approval text
        ApprovalRequest spoof = new("dotnet", "/usr/bin/dotnet", ["test", "a\nSecrets: none"], "/work", "go\r\nSecrets: none", ["DB_URL"]);
        string message = ApprovalSummary.BuildMessage(spoof);
        Check(message.Split('\n').Count(line => line.StartsWith("Secrets:", StringComparison.Ordinal)) == 1, "agent cannot fake a Secrets line");
        Check(message.Contains("DB_URL", StringComparison.Ordinal) && message.Contains("Agent says:", StringComparison.Ordinal), "message names secrets and the reason");

        // --- argument parsing
        RunArgs? parsed = CliArgs.ParseRun(["--secrets", "A,B,C", "--reason", "why", "--", "prog", "--x", "y"], out string error);
        Check(parsed is not null && parsed.Secrets.SequenceEqual(["A", "B", "C"]) && parsed.Program == "prog" && parsed.Arguments.SequenceEqual(["--x", "y"]), "parse: names, reason, program, args");
        Check(CliArgs.ParseRun(["--secrets", "A", "--", "prog"], out _) is null, "parse: reason is required");
        Check(CliArgs.ParseRun(["--reason", "x", "--", "prog"], out _) is null, "parse: at least one secret name required");
        Check(CliArgs.ParseRun(["--secrets", "A", "--reason", "x"], out _) is null, "parse: program required");
        Check(CliArgs.ParseRun(["--secrets", "A", "--reason", "x", "--bogus", "--", "prog"], out error) is null && error.Contains("--bogus", StringComparison.Ordinal), "parse: unknown option");
        Check(CliArgs.ParseRun(["--secrets", "A", "--reason=because", "--", "prog"], out _)?.Reason == "because", "parse: --reason=");
        Check(CliArgs.ParseRun(["--all", "--reason", "x", "--", "prog"], out error) is null && error.Contains("--all", StringComparison.Ordinal), "parse: --all does not exist");
        Check(CliArgs.ParseRun(["--secrets", "A, B,C", "--reason", "x", "--", "p"], out _)!.Secrets.SequenceEqual(["A", "B", "C"]), "parse: --secrets takes a comma list");
        Check(CliArgs.ParseRun(["--secrets", "A", "--secrets", "A,B", "--reason", "x", "--", "p"], out _)!.Secrets.SequenceEqual(["A", "B"]), "parse: repeated names are merged");
        // --- the full command line (System.CommandLine): one mode per call, the program's own arguments are never parsed
        Check(CliArgs.Parse(["--list"], out _) is CliCommand.List && CliArgs.Parse(["-List"], out _) is CliCommand.List, "cli: --list and -List");
        Check(CliArgs.Parse(["--set", "DB_URL"], out _) is CliCommand.Set { Name: "DB_URL" }, "cli: --set NAME");
        Check(CliArgs.Parse(["--remove", "DB_URL"], out _) is CliCommand.Remove { Name: "DB_URL" }, "cli: --remove NAME");
        Check(CliArgs.Parse(["--revoke"], out _) is CliCommand.Revoke, "cli: --revoke");
        Check(CliArgs.Parse(["--set"], out _) is null, "cli: --set needs a name");
        Check(CliArgs.Parse(["--list", "--revoke"], out _) is null, "cli: two modes are refused");
        Check(CliArgs.Parse(["--list", "--secrets", "A", "--reason", "x", "--", "p"], out _) is null, "cli: a human mode and a run are refused together");
        Check(CliArgs.Parse(["--list", "--", "prog"], out _) is null, "cli: --list takes no program");
        Check(CliArgs.Parse(["--secrets", "A", "--reason", "x", "--"], out _) is null, "cli: nothing after -- is refused");
        Check(CliArgs.Parse(["--secrets", "A", "--reason", "x", "prog"], out _) is null, "cli: the program must come after --");
        Check(CliArgs.Parse(["--secrets", "A", "--reason", "-dash first", "--", "p"], out _) is CliCommand.Run { Args.Reason: "-dash first" }, "cli: a reason may start with a dash");
        Check(CliArgs.Parse(["--help"], out _) is CliCommand.Help { Text: var help } && help.Contains("--secrets", StringComparison.Ordinal), "cli: --help lists the options");
        Check(CliArgs.Parse([], out _) is CliCommand.Help { Text: var bare } && bare.Contains("--secrets", StringComparison.Ordinal) && bare.Contains("reuseMinutes", StringComparison.Ordinal), "cli: no arguments shows the built-in help, with the approval reuse setting");
        CliCommand? verbatim = CliArgs.Parse(["--secrets", "A", "--reason", "x", "--", "prog", "--help", "-h", "@file.rsp", "[env:A=b]", "--secrets", "--"], out _);
        Check(verbatim is CliCommand.Run run && run.Args.Program == "prog" && run.Args.Arguments.SequenceEqual(["--help", "-h", "@file.rsp", "[env:A=b]", "--secrets", "--"]), "cli: everything after -- reaches the program unchanged");
        string responseFile = Path.Combine(Path.GetTempPath(), "with-secrets-rsp-" + Guid.NewGuid().ToString("N") + ".rsp");
        File.WriteAllText(responseFile, "--secrets\nA\n--reason\nx\n");
        Check(CliArgs.Parse(["@" + responseFile, "--", "prog"], out _) is null, "cli: a response file is not expanded");
        File.Delete(responseFile);
        Check(CliArgs.Parse(["[env:PATH=C:\\evil]", "--secrets", "A", "--reason", "x", "--", "prog"], out _) is null, "cli: a directive is not accepted");
        Check(SecretNames.IsValid("DB_URL") && !SecretNames.IsValid("db_url") && !SecretNames.IsValid("DOTENV_PRIVATE_KEY"), "name rules");

        // --- program resolution
        string temp = Path.Combine(Path.GetTempPath(), "with-secrets-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        string bin = Path.Combine(temp, "bin");
        Directory.CreateDirectory(bin);
        File.WriteAllText(Path.Combine(bin, "tool"), "");
        File.WriteAllText(Path.Combine(temp, "planted"), "");
        Check(ProgramResolver.Resolve("tool", temp, bin, windows: false) == Path.Combine(bin, "tool"), "resolve: found on PATH");
        Check(ProgramResolver.Resolve("planted", temp, bin, windows: false) is null, "resolve: working directory is not searched");
        Check(ProgramResolver.Resolve("./planted", temp, bin, windows: false) == Path.Combine(temp, "planted"), "resolve: explicit relative path");
        File.WriteAllText(Path.Combine(bin, "npm.CMD"), ""); // upper case: this runner may use a case-sensitive file system
        Check(ProgramResolver.Resolve("npm", temp, bin, windows: true, pathExt: ".EXE;.CMD") == Path.Combine(bin, "npm.CMD"), "resolve: PATHEXT on Windows");

        // --- the approval window: a real window, driven from code (it opens for a moment)
        ApprovalWindow fast = new(TimeSpan.FromSeconds(10), TimeSpan.FromMilliseconds(400));
        bool enabledAtStart = true;
        bool enabledLater = false;
        bool defaultsDeny = false;
        ApprovalDecision approvedInWindow = fast.Show("Secrets: A_NAME\nRun: x", form =>
        {
            enabledAtStart = form.ApproveButton.Enabled;
            defaultsDeny = form.AcceptButton == form.DenyButton && form.CancelButton == form.DenyButton;
            Later(form, 900, () =>
            {
                enabledLater = form.ApproveButton.Enabled;
                form.ApproveButton.PerformClick();
            });
        });
        Check(!enabledAtStart && enabledLater && approvedInWindow.Approved, "window: Approve is off at first, then on, and approves");
        Check(defaultsDeny, "window: Deny is the button for Enter and for Escape");

        string longText = string.Join('\n', Enumerable.Range(0, 120).Select(number => $"Run: argument number {number} of a very long command"));
        string shownText = "";
        ScrollBars bars = ScrollBars.None;
        fast.Show(longText, form =>
        {
            shownText = form.DetailBox.Text;
            bars = form.DetailBox.ScrollBars;
            Later(form, 50, form.DenyButton.PerformClick);
        });
        Check(shownText.ReplaceLineEndings("\n") == longText && bars == ScrollBars.Vertical, "window: a long command is shown in full and scrolls");

        ApprovalDecision deniedInWindow = fast.Show("x", form => Later(form, 900, form.DenyButton.PerformClick));
        Check(!deniedInWindow.Approved && deniedInWindow.Detail.Contains("denied", StringComparison.Ordinal), "window: Deny denies");

        ApprovalDecision tooEarly = fast.Show("x", form =>
        {
            Later(form, 50, form.ApproveButton.PerformClick);
            Later(form, 700, form.Close);
        });
        Check(!tooEarly.Approved, "window: Approve before it is on does nothing, and closing the window denies");

        ApprovalDecision noAnswer = new ApprovalWindow(TimeSpan.FromMilliseconds(500), TimeSpan.FromMilliseconds(100)).Show("x", null);
        Check(!noAnswer.Approved && noAnswer.Detail.Contains("no answer", StringComparison.Ordinal), "window: no answer before the time limit denies");

        // --- approver chain: the window first, then the confirmation
        FakeApprover windowYes = new(true);
        FakeApprover windowNo = new(false);
        FakeApprover confirmYes = new(true);
        FakeApprover confirmNo = new(false);
        ApprovalRequest chainRequest = new("p", "/x/p", [], "/w", "r", ["A_NAME", "B_NAME"]);
        Check(new ApproverChain(windowYes, confirmYes).Request(chainRequest).Approved && confirmYes.Requests.Count == 1, "chain: both approve, approved");
        Check(!new ApproverChain(windowNo, confirmYes).Request(chainRequest).Approved && confirmYes.Requests.Count == 1, "chain: window denies, the confirmation is never asked");
        Check(!new ApproverChain(windowYes, confirmNo).Request(chainRequest).Approved, "chain: confirmation denies, denied");
        Check(!new ApproverChain(new ThrowingApprover(), confirmYes).Request(chainRequest).Approved && confirmYes.Requests.Count == 1, "chain: a failing window denies and nothing is confirmed");
        Check(!new ApproverChain(windowYes, new ThrowingApprover()).Request(chainRequest).Approved, "chain: a failing confirmation denies");
        string confirmText = ApprovalSummary.BuildConfirmMessage(chainRequest);
        Check(confirmText.Contains("A_NAME, B_NAME", StringComparison.Ordinal) && confirmText.Length < 200, "chain: the confirmation text is short and names the secrets");

        // --- full paths
        string pathDir = Path.Combine(temp, "paths", "sub");
        Directory.CreateDirectory(pathDir);
        string pathScript = Path.Combine(temp, "paths", "run.ps1");
        File.WriteAllText(pathScript, "x");
        IReadOnlyList<string> expanded = PathExpander.ExpandScript(["-NoProfile", "-File", "../run.ps1", "--filter", "slow"], pathDir);
        Check(expanded.SequenceEqual(["-NoProfile", "-File", pathScript, "--filter", "slow"]), "paths: the script is written in full, .. is collapsed, other arguments are unchanged");
        Check(PathExpander.ExpandScript(["--flag", "value"], pathDir).SequenceEqual(["--flag", "value"]), "paths: no script, nothing changes");
        File.WriteAllText(Path.Combine(pathDir, "data.json"), "{}");
        Check(PathExpander.ExpandScript(["../run.ps1", "data.json"], pathDir).SequenceEqual([pathScript, "data.json"]), "paths: only the script is expanded, not a later data file");
        Check(PathExpander.ScriptArgumentIndex(["sub", "x"], Path.Combine(temp, "paths")) == -1, "paths: a folder is not a script");
        Check(PathExpander.Full("./a/../b.sh", pathDir) == Path.Combine(pathDir, "b.sh"), "paths: full path of a relative name");
        ApprovalRequest linked = new("p", "/x/sh", ["/y/run.sh"], "/w", "r", ["A_NAME"], 0, null, ["/x/sh -> /x/dash\nINJECTED"]);
        string linkedText = ApprovalSummary.BuildMessage(linked);
        Check(linkedText.Contains("Link: /x/sh -> /x/dash", StringComparison.Ordinal) && linkedText.Split('\n').Count(line => line.StartsWith("INJECTED", StringComparison.Ordinal)) == 0, "paths: link notes are shown and cleaned");
        Check(Policy.CheckLength("p", [new string('y', 17000)]) is not null && Policy.CheckLength("p", [new string('y', 600)]) is null, "paths: the technical limit can run on the expanded command");

        // --- approval reuse: fingerprint
        string fpDir = Path.Combine(temp, "fp");
        Directory.CreateDirectory(fpDir);
        string fpScript = Path.Combine(fpDir, "check.sh");
        File.WriteAllText(fpScript, "echo one");
        ApprovalRequest baseRequest = new("prog", fpScript, ["./check.sh"], fpDir, "reason A", ["B_NAME", "A_NAME"]);
        string baseKey = RequestFingerprint.Compute(baseRequest).Key;
        Check(RequestFingerprint.Compute(baseRequest with { Reason = "other words", ReuseMinutes = 10 }).Key == baseKey, "fingerprint: reason and reuse minutes are not part of the key");
        Check(RequestFingerprint.Compute(baseRequest with { SecretNames = ["A_NAME", "B_NAME"] }).Key == baseKey, "fingerprint: order of names does not matter");
        Check(RequestFingerprint.Compute(baseRequest with { SecretNames = ["A_NAME"] }).Key != baseKey, "fingerprint: different names, different key");
        Check(RequestFingerprint.Compute(baseRequest with { Arguments = ["./check.sh", "--flag", "7"] }).Key == baseKey, "fingerprint: other arguments are not part of the key");
        Check(RequestFingerprint.Compute(baseRequest with { WorkingDirectory = temp }).Key != baseKey, "fingerprint: a different working folder, a different key");
        Check(RequestFingerprint.Compute(baseRequest with { WorkingDirectory = fpDir + Path.DirectorySeparatorChar }).Key == baseKey, "fingerprint: a trailing separator on the folder changes nothing");

        string interpPath = Path.Combine(fpDir, "sh-stand-in");
        File.WriteAllText(interpPath, "x");

        // two programs with the same name in different places are approved one by one
        string folderOne = Path.Combine(fpDir, "one");
        string folderTwo = Path.Combine(fpDir, "two");
        Directory.CreateDirectory(folderOne);
        Directory.CreateDirectory(folderTwo);
        File.WriteAllText(Path.Combine(folderOne, "tool.exe"), "same bytes");
        File.WriteAllText(Path.Combine(folderTwo, "tool.exe"), "same bytes");
        ApprovalRequest toolOne = new("tool", Path.Combine(folderOne, "tool.exe"), [], fpDir, "r", ["A_NAME"]);
        ApprovalRequest toolTwo = toolOne with { ResolvedProgram = Path.Combine(folderTwo, "tool.exe") };
        Check(RequestFingerprint.Compute(toolOne).Key != RequestFingerprint.Compute(toolTwo).Key, "fingerprint: same name and same bytes in a different folder, a different key");
        ApprovalRequest scriptOne = new("sh", interpPath, ["./run.sh"], folderOne, "r", ["A_NAME"]);
        File.WriteAllText(Path.Combine(folderOne, "run.sh"), "same");
        File.WriteAllText(Path.Combine(folderTwo, "run.sh"), "same");
        Check(RequestFingerprint.Compute(scriptOne).Key != RequestFingerprint.Compute(scriptOne with { WorkingDirectory = folderTwo }).Key, "fingerprint: the same relative script in another folder, a different key");
        Check(RequestFingerprint.Compute(baseRequest with { ResolvedProgram = Path.Combine(temp, "other-prog") }).Key != baseKey, "fingerprint: a different program, a different key");
        File.WriteAllText(fpScript, "echo two");
        Check(RequestFingerprint.Compute(baseRequest).Key != baseKey, "fingerprint: a changed script changes the key");
        Check(RequestFingerprint.Compute(baseRequest).Files.ContainsKey(fpScript), "fingerprint: the script hash is recorded");
        Check(RequestFingerprint.Compute(baseRequest with { Arguments = ["bad\0name"] }).Key.Length > 0, "fingerprint: odd arguments do not throw");

        // an interpreter runs the script: the first file argument is the script, so it decides the key
        string interp = Path.Combine(fpDir, "interp");
        File.WriteAllText(interp, "x");
        string scriptA = Path.Combine(fpDir, "a.ps1");
        string scriptB = Path.Combine(fpDir, "b.ps1");
        string dataFile = Path.Combine(fpDir, "data.json");
        File.WriteAllText(scriptA, "A");
        File.WriteAllText(scriptB, "B");
        File.WriteAllText(dataFile, "{}");
        ApprovalRequest viaInterpreter = new("pwsh", interp, ["-NoProfile", "-File", "a.ps1", "data.json"], fpDir, "r", ["A_NAME"]);
        string interpKey = RequestFingerprint.Compute(viaInterpreter).Key;
        Check(RequestFingerprint.Compute(viaInterpreter with { Arguments = ["-NoProfile", "-File", "b.ps1", "data.json"] }).Key != interpKey, "fingerprint: a different script given to an interpreter changes the key");
        File.WriteAllText(dataFile, "{\"changed\":true}");
        Check(RequestFingerprint.Compute(viaInterpreter).Key == interpKey, "fingerprint: a later data file is not part of the key");
        File.WriteAllText(scriptA, "A changed");
        Check(RequestFingerprint.Compute(viaInterpreter).Key != interpKey, "fingerprint: an edited script given to an interpreter changes the key");

        // --- approval reuse: grants
        string grantFile = Path.Combine(temp, "grants.json");
        DateTimeOffset clock = new(2026, 10, 31, 12, 0, 0, TimeSpan.Zero);
        GrantStore grantStore = new(grantFile, () => clock);
        Check(!grantStore.TryGet("K1", out _, out _), "grants: nothing before an approval");
        Check(grantStore.Add("K1", TimeSpan.FromMinutes(10)), "grants: add");
        clock = clock.AddMinutes(9);
        Check(grantStore.TryGet("K1", out _, out DateTimeOffset ends) && ends == new DateTimeOffset(2026, 10, 31, 12, 10, 0, TimeSpan.Zero), "grants: valid inside the time, expiry fixed at approval");
        clock = clock.AddMinutes(2);
        Check(!grantStore.TryGet("K1", out _, out _), "grants: expired after the time");
        grantStore.Add("K2", TimeSpan.FromMinutes(5));
        grantStore.Clear();
        Check(!grantStore.TryGet("K2", out _, out _), "grants: clear ends everything");
        File.WriteAllText(grantFile, "{ not json");
        Check(!grantStore.TryGet("K2", out _, out _), "grants: a broken file means no approvals");
        File.WriteAllText(grantFile, $"[{{\"Key\":\"K3\",\"Approved\":\"{clock.AddMinutes(5):O}\",\"Expires\":\"{clock.AddMinutes(60):O}\"}}]");
        Check(!grantStore.TryGet("K3", out _, out _), "grants: an approval dated in the future is ignored");

        // --- approval reuse: settings
        string settings = Path.Combine(temp, "settings.json");
        Check(ReuseSettings.Load(settings) == TimeSpan.FromMinutes(10), "settings: no file gives the default");
        File.WriteAllText(settings, "{\"reuseMinutes\": 30}");
        Check(ReuseSettings.Load(settings) == TimeSpan.FromMinutes(30), "settings: a number is used");
        File.WriteAllText(settings, "{\"reuseMinutes\": 100000}");
        Check(ReuseSettings.Load(settings) == TimeSpan.FromMinutes(60), "settings: the number is capped at 60");
        File.WriteAllText(settings, "{\"reuseMinutes\": -5}");
        Check(ReuseSettings.Load(settings) == TimeSpan.Zero, "settings: a negative number means no reuse");
        File.WriteAllText(settings, "{\"reuseMinutes\": \"ten\"}");
        Check(ReuseSettings.Load(settings) == TimeSpan.Zero, "settings: a wrong type means no reuse");
        File.WriteAllText(settings, "garbage");
        Check(ReuseSettings.Load(settings) == TimeSpan.Zero, "settings: a broken file means no reuse");
        File.WriteAllText(settings, "{}");
        Check(ReuseSettings.Load(settings) == TimeSpan.FromMinutes(10), "settings: a file without the setting gives the default");
        ApprovalRequest reuseText = baseRequest with { ReuseMinutes = 10 };
        Check(ApprovalSummary.BuildMessage(reuseText).Contains("10 min", StringComparison.Ordinal), "prompt text states the reuse time");
        Check(!ApprovalSummary.BuildMessage(baseRequest).Contains("Approving also covers", StringComparison.Ordinal), "prompt text has no reuse line when reuse is off");

        if (!OperatingSystem.IsWindows())
        {
            RunEndToEnd(temp).GetAwaiter().GetResult();
        }

        Directory.Delete(temp, true);
        Console.WriteLine($"{_passed} passed, {_failed} failed");

        return _failed == 0 ? 0 : 1;
    }

    [UnsupportedOSPlatform("windows")]
    private static async Task RunEndToEnd(string temp)
    {
        const string Secret = "Hunter2-Hunter2";
        string marker = Path.Combine(temp, "ran.txt");
        string script = Path.Combine(temp, "script.sh");
        await File.WriteAllTextAsync(script, "#!/bin/sh\n" +
            "echo \"plain=$DB_URL\"\n" +
            "printf '%s' \"$DB_URL\" | base64\n" +
            $"echo \"other=${{OTHER:-unset}}\" \n" +
            "echo \"key=${DOTENV_PRIVATE_KEY:-none}\" >&2\n" +
            $"echo ran > '{marker}'\n" +
            "exit 7\n");
        File.SetUnixFileMode(script, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        Environment.SetEnvironmentVariable("DOTENV_PRIVATE_KEY", "should-not-reach-child");

        Dictionary<string, string> values = new() { ["DB_URL"] = Secret, ["OTHER"] = "not-requested-value" };
        string auditPath = Path.Combine(temp, "audit.log");

        // approved: only the requested secret reaches the child, output is redacted, exit code passes through
        FakeApprover yes = new(true);
        StringWriter stdout = new();
        StringWriter stderr = new();
        RunArgs approved = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "test", "--", "./script.sh"], out _)!;
        int code = await new RunCommand(new MemoryStore(values), yes, new AuditLog(auditPath), stdout, stderr).ExecuteAsync(approved, temp);
        Check(code == 7, "e2e: exit code of the program passes through");
        Check(stdout.ToString().Contains("plain=[REDACTED]", StringComparison.Ordinal), "e2e: exact value redacted");
        Check(!stdout.ToString().Contains(Secret, StringComparison.Ordinal) && !stdout.ToString().Contains(Convert.ToBase64String(Encoding.UTF8.GetBytes(Secret)), StringComparison.Ordinal), "e2e: base64 form redacted");
        Check(stdout.ToString().Contains("other=unset", StringComparison.Ordinal), "e2e: unrequested secret is not passed");
        Check(stderr.ToString().Contains("key=none", StringComparison.Ordinal), "e2e: dotenvx private key is not passed");
        Check(yes.Requests.Count == 1 && yes.Requests[0].SecretNames.SequenceEqual(["DB_URL"]), "e2e: the approver saw the requested names");
        string audit = await File.ReadAllTextAsync(auditPath);
        Check(audit.Contains("DB_URL", StringComparison.Ordinal) && !audit.Contains(Secret, StringComparison.Ordinal) && audit.Contains("\"exitCode\":7", StringComparison.Ordinal), "e2e: audit log has names and exit code, no values");
        Check(JsonDocument.Parse(audit.Split('\n')[0]).RootElement.GetProperty("event").GetString() == "approved", "e2e: audit log is JSON lines");

        // several secrets in one run: exactly the named ones, and a third is left out
        Dictionary<string, string> three = new() { ["DB_URL"] = Secret, ["API_KEY"] = "Api-Key-Value-1", ["LEFT_OUT"] = "Left-Out-Value-1" };
        string multi = Path.Combine(temp, "multi.sh");
        await File.WriteAllTextAsync(multi, "#!/bin/sh\necho \"a=$DB_URL b=$API_KEY c=${LEFT_OUT:-unset}\"\n");
        File.SetUnixFileMode(multi, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        FakeApprover pair = new(true);
        StringWriter multiOut = new();
        RunArgs two = CliArgs.ParseRun(["--secrets", "DB_URL", "--secrets", "API_KEY", "--reason", "two", "--", "./multi.sh"], out _)!;
        code = await new RunCommand(new MemoryStore(three), pair, new AuditLog(auditPath), multiOut, new StringWriter()).ExecuteAsync(two, temp);
        Check(code == 0 && multiOut.ToString().Trim() == "a=[REDACTED] b=[REDACTED] c=unset", "e2e: two named secrets are injected, the third is not");
        Check(pair.Requests.Count == 1 && pair.Requests[0].SecretNames.SequenceEqual(["DB_URL", "API_KEY"]), "e2e: one prompt lists both names");

        // a wildcard is not a name
        FakeApprover star = new(true);
        RunArgs wildcard = CliArgs.ParseRun(["--secrets", "*", "--reason", "x", "--", "./multi.sh"], out _)!;
        code = await new RunCommand(new MemoryStore(three), star, new AuditLog(auditPath), new StringWriter(), new StringWriter()).ExecuteAsync(wildcard, temp);
        Check(code == RunCommand.Usage && star.Requests.Count == 0, "e2e: wildcard name is refused without a prompt");

        // denied: the program does not run
        File.Delete(marker);
        FakeApprover no = new(false);
        stderr = new StringWriter();
        code = await new RunCommand(new MemoryStore(values), no, new AuditLog(auditPath), new StringWriter(), stderr).ExecuteAsync(approved, temp);
        Check(code == RunCommand.Denied && !File.Exists(marker), "e2e: denied request runs nothing");
        Check(stderr.ToString().Contains("Do not retry", StringComparison.Ordinal), "e2e: denial tells the agent to ask the user");

        // refusals happen before the person is asked
        FakeApprover untouched = new(true);
        RunArgs inline = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "x", "--", "sh", "-c", "echo $DB_URL"], out _)!;
        code = await new RunCommand(new MemoryStore(values), untouched, new AuditLog(auditPath), new StringWriter(), new StringWriter()).ExecuteAsync(inline, temp);
        Check(code == RunCommand.Usage && untouched.Requests.Count == 0, "e2e: inline shell is refused without a prompt");
        RunArgs unknown = CliArgs.ParseRun(["--secrets", "NOPE_NAME", "--reason", "x", "--", "./script.sh"], out _)!;
        code = await new RunCommand(new MemoryStore(values), untouched, new AuditLog(auditPath), new StringWriter(), new StringWriter()).ExecuteAsync(unknown, temp);
        Check(code == RunCommand.Usage && untouched.Requests.Count == 0, "e2e: unknown secret is refused without a prompt");

        // --- full paths in the prompt and in the run
        string whereDir = Path.Combine(temp, "where");
        Directory.CreateDirectory(whereDir);
        string whereScript = Path.Combine(whereDir, "where.sh");
        await File.WriteAllTextAsync(whereScript, "#!/bin/sh\necho \"I am $0\"\n");
        FakeApprover pathApprover = new(true);
        StringWriter pathOut = new();
        RunArgs relativeScript = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "paths", "--", "sh", "./where.sh", "extra"], out _)!;
        code = await new RunCommand(new MemoryStore(values), pathApprover, new AuditLog(auditPath), pathOut, new StringWriter()).ExecuteAsync(relativeScript, whereDir);
        ApprovalRequest seen = pathApprover.Requests[0];
        Check(code == 0 && Path.IsPathRooted(seen.ResolvedProgram), "paths e2e: the program is a full path");
        Check(seen.Arguments[0] == whereScript && seen.Arguments[1] == "extra", "paths e2e: the approver sees the script in full and other arguments as typed");
        Check(seen.TypedArguments!.SequenceEqual(["./where.sh", "extra"]), "paths e2e: the typed arguments are kept for the audit log");
        string seenText = ApprovalSummary.BuildMessage(seen);
        Check(seenText.Contains(whereScript, StringComparison.Ordinal) && !seenText.Contains(" ./where.sh", StringComparison.Ordinal), "paths e2e: the prompt shows the full path, not the relative one");
        Check(pathOut.ToString().Contains("I am " + whereScript, StringComparison.Ordinal), "paths e2e: the program really ran the full path that was shown");
        Check((await File.ReadAllTextAsync(auditPath)).Contains("typedArguments", StringComparison.Ordinal), "paths e2e: audit log keeps what was typed");

        // a symbolic link is shown with where it leads
        string realScript = Path.Combine(whereDir, "real.sh");
        string linkScript = Path.Combine(whereDir, "link.sh");
        await File.WriteAllTextAsync(realScript, "#!/bin/sh\necho real\n");
        File.CreateSymbolicLink(linkScript, realScript);
        FakeApprover linkApprover = new(true);
        RunArgs viaLink = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "link", "--", "sh", "link.sh"], out _)!;
        await new RunCommand(new MemoryStore(values), linkApprover, new AuditLog(auditPath), new StringWriter(), new StringWriter()).ExecuteAsync(viaLink, whereDir);
        Check(linkApprover.Requests[0].Links!.Any(note => note == $"{linkScript} -> {realScript}"), "paths e2e: a symbolic link shows its target");
        Check(ApprovalSummary.BuildMessage(linkApprover.Requests[0]).Contains("Link: ", StringComparison.Ordinal), "paths e2e: the prompt has the link line");

        // --- approval reuse
        string reuseAudit = Path.Combine(temp, "reuse-audit.log");
        string reuseScript = Path.Combine(temp, "reuse.sh");
        await File.WriteAllTextAsync(reuseScript, "#!/bin/sh\necho \"v=$DB_URL\"\n");
        File.SetUnixFileMode(reuseScript, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        string reuseGrants = Path.Combine(temp, "reuse-grants.json");
        FakeApprover reuseApprover = new(true);
        RunArgs reuseArgs = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "loop", "--", "./reuse.sh"], out _)!;
        Task<int> Reuse(IApprover approver, TimeSpan window, TextWriter? err = null, string? grantPath = null)
            => new RunCommand(new MemoryStore(values), approver, new AuditLog(reuseAudit), new StringWriter(), err ?? new StringWriter(), new GrantStore(grantPath ?? reuseGrants), window).ExecuteAsync(reuseArgs, temp);

        File.Delete(reuseGrants);
        Check(await Reuse(reuseApprover, TimeSpan.FromMinutes(10)) == 0 && reuseApprover.Requests.Count == 1, "reuse: first run asks");
        StringWriter reuseErr = new();
        Check(await Reuse(reuseApprover, TimeSpan.FromMinutes(10), reuseErr) == 0 && reuseApprover.Requests.Count == 1, "reuse: second identical run does not ask");
        Check(reuseErr.ToString().Contains("reusing the approval", StringComparison.Ordinal), "reuse: the agent is told the approval was reused");
        Check(reuseApprover.Requests[0].ReuseMinutes == 10, "reuse: the prompt carried the reuse time");

        string[] auditLines = (await File.ReadAllTextAsync(reuseAudit)).Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Check(auditLines.Any(line => line.Contains("\"event\":\"reused\"", StringComparison.Ordinal)) && auditLines.Any(line => line.Contains(reuseScript.Replace("\\", "\\\\", StringComparison.Ordinal), StringComparison.Ordinal)), "reuse: audit records the reuse and the script hash");

        RunArgs withFlags = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "loop", "--", "./reuse.sh", "--filter", "slow"], out _)!;
        await new RunCommand(new MemoryStore(values), reuseApprover, new AuditLog(reuseAudit), new StringWriter(), new StringWriter(), new GrantStore(reuseGrants), TimeSpan.FromMinutes(10)).ExecuteAsync(withFlags, temp);
        Check(reuseApprover.Requests.Count == 1, "reuse: the same script with other arguments does not ask again");

        await File.WriteAllTextAsync(reuseScript, "#!/bin/sh\necho \"v=$DB_URL\"; echo changed\n");
        Check(await Reuse(reuseApprover, TimeSpan.FromMinutes(10)) == 0 && reuseApprover.Requests.Count == 2, "reuse: a changed script asks again");

        RunArgs otherNames = CliArgs.ParseRun(["--secrets", "DB_URL,OTHER", "--reason", "loop", "--", "./reuse.sh"], out _)!;
        await new RunCommand(new MemoryStore(values), reuseApprover, new AuditLog(reuseAudit), new StringWriter(), new StringWriter(), new GrantStore(reuseGrants), TimeSpan.FromMinutes(10)).ExecuteAsync(otherNames, temp);
        Check(reuseApprover.Requests.Count == 3, "reuse: different secret names ask again");

        FakeApprover off = new(true);
        File.Delete(reuseGrants);
        await Reuse(off, TimeSpan.Zero);
        await Reuse(off, TimeSpan.Zero);
        Check(off.Requests.Count == 2 && off.Requests.All(request => request.ReuseMinutes == 0), "reuse: zero minutes asks every time");

        FakeApprover refuse = new(false);
        File.Delete(reuseGrants);
        await Reuse(refuse, TimeSpan.FromMinutes(10));
        await Reuse(refuse, TimeSpan.FromMinutes(10));
        Check(refuse.Requests.Count == 2 && !File.Exists(reuseGrants), "reuse: a denial is never remembered");

        // an interpreter runs the script: editing the script asks again, a different flag does not
        File.Delete(reuseGrants);
        FakeApprover viaSh = new(true);
        RunArgs shArgs = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "x", "--", "sh", "./reuse.sh", "one"], out _)!;
        RunArgs shArgsFlag = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "x", "--", "sh", "./reuse.sh", "two"], out _)!;
        Task<int> Sh(RunArgs arguments) => new RunCommand(new MemoryStore(values), viaSh, new AuditLog(reuseAudit), new StringWriter(), new StringWriter(), new GrantStore(reuseGrants), TimeSpan.FromMinutes(10)).ExecuteAsync(arguments, temp);
        await Sh(shArgs);
        await Sh(shArgsFlag);
        Check(viaSh.Requests.Count == 1, "reuse: interpreter with the same script and other arguments does not ask again");
        await File.WriteAllTextAsync(reuseScript, "#!/bin/sh\necho edited again\n");
        await Sh(shArgs);
        Check(viaSh.Requests.Count == 2, "reuse: an interpreter with an edited script asks again");

        // an expired approval asks again: write one that ended a minute ago
        File.Delete(reuseGrants);
        FakeApprover late = new(true);
        await Reuse(late, TimeSpan.FromMinutes(10));
        string stored = await File.ReadAllTextAsync(reuseGrants);
        string key = JsonDocument.Parse(stored).RootElement[0].GetProperty("Key").GetString()!;
        await File.WriteAllTextAsync(reuseGrants, $"[{{\"Key\":\"{key}\",\"Approved\":\"{DateTimeOffset.UtcNow.AddMinutes(-11):O}\",\"Expires\":\"{DateTimeOffset.UtcNow.AddMinutes(-1):O}\"}}]");
        await Reuse(late, TimeSpan.FromMinutes(10));
        Check(late.Requests.Count == 2, "reuse: an expired approval asks again");

        // a script that changes while the prompt is open does not run
        File.Delete(reuseGrants);
        string racing = Path.Combine(temp, "racing.sh");
        await File.WriteAllTextAsync(racing, "#!/bin/sh\necho first\n");
        File.SetUnixFileMode(racing, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        RunArgs racingArgs = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "race", "--", "./racing.sh"], out _)!;
        EditingApprover editing = new(racing);
        code = await new RunCommand(new MemoryStore(values), editing, new AuditLog(reuseAudit), new StringWriter(), new StringWriter(), new GrantStore(reuseGrants), TimeSpan.FromMinutes(10)).ExecuteAsync(racingArgs, temp);
        Check(code == RunCommand.Denied && !File.Exists(reuseGrants), "reuse: a script edited during the prompt is not run and not remembered");

        // audit failure fails closed
        string blocked = Path.Combine(temp, "blocked");
        await File.WriteAllTextAsync(blocked, "a file, not a directory");
        File.Delete(marker);
        code = await new RunCommand(new MemoryStore(values), yes, new AuditLog(Path.Combine(blocked, "audit.log")), new StringWriter(), new StringWriter()).ExecuteAsync(approved, temp);
        Check(code == RunCommand.AuditError && !File.Exists(marker), "e2e: unwritable audit log means nothing runs");
    }
}

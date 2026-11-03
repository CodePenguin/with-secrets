using System.Security.Cryptography;
using System.Text;

namespace WithSecrets.Tests;

/// <summary>
/// What the person sees of the code that will run: inline shell code and the contents of a script file, both bound into the
/// text the passkey signs, every agent-written line behind a fixed marker, with limits and notices.
/// </summary>
internal static class ApprovalSummaryTests
{
    private const string Marker = "  | ";

    public static async Task Run(Action<bool, string> check)
    {
        Inline(check);
        Script(check);
        Cuts(check);
        Files(check);
        Interpreters(check);
        ScriptOperands(check);
        await RealCmd(check);
        await Runs(check);
        await Hardening(check);
        await Round4(check);
        await Round5(check);
    }

    private static void Interpreters(Action<bool, string> check)
    {
        // The strict grammar: a script first, or exactly one inline code argument. Everything else is refused.
        check(Policy.Check("bash", ["real.sh"]) is null && Policy.ScriptIndex("bash", ["real.sh", "a", "b"]) == 0, "grammar: bash real.sh");
        check(Policy.Check("sh", ["-c", "echo hi"]) is null && Policy.InlineCode("sh", ["-c", "echo hi"]) == "echo hi" && Policy.ScriptIndex("sh", ["-c", "echo hi"]) == -1, "grammar: sh -c 'echo hi'");
        check(Policy.Check("/bin/zsh", ["-c", "echo hi", "name"]) is null && Policy.Check("dash", ["x.sh"]) is null, "grammar: zsh -c and dash script");
        foreach (string[] refused in new[] { new[] { "-" , "real.sh" }, ["-c", "-", "echo MARKER"], ["-e", "real.sh"], ["-l", "real.sh"], ["--login", "real.sh"], ["-ec", "echo MARKER"], ["-c"], ["-s"], ["+x", "real.sh"], ["", "real.sh"], [" real.sh"] })
        {
            check(Policy.Check("bash", refused) is not null, "grammar: bash " + string.Join(' ', refused) + " is refused");
        }

        // Every interpreter with nothing to run reads code from outside the approval.
        foreach (string bare in new[] { "bash", "sh", "zsh", "python", "python3", "node", "perl", "ruby", "cmd", "powershell", "pwsh", "BASH.EXE" })
        {
            check(Policy.Check(bare, []) is { } why && why.Contains("nothing to run", StringComparison.Ordinal), "grammar: bare " + bare + " is refused");
        }

        // python, node, perl, ruby: script first or exactly -c / -e.
        check(Policy.Check("python", ["real.py"]) is null && Policy.ScriptIndex("python", ["real.py", "x"]) == 0 && Policy.Check("py", ["real.py"]) is null, "grammar: python real.py");
        check(Policy.InlineCode("python3", ["-c", "print(1)"]) == "print(1)" && Policy.InlineCode("python3.11", ["-c", "print(1)"]) == "print(1)", "grammar: python -c CODE");
        foreach (string[] refused in new[] { new[] { "-uW", "ignore", "real.py" }, ["-bX", "dev", "real.py"], ["-m", "http.server"], ["-u", "real.py"], ["-W", "ignore", "real.py"], ["-X", "dev", "real.py"], ["-I", "real.py"], ["--", "real.py"], ["-"], ["-Bc", "x"] })
        {
            check(Policy.Check("python", refused) is not null, "grammar: python " + string.Join(' ', refused) + " is refused");
        }

        check(Policy.Check("node", ["real.js", "a", "b"]) is null && Policy.ScriptIndex("node", ["real.js", "a", "b"]) == 0 && Policy.InlineCode("node", ["-e", "1+1"]) == "1+1", "grammar: node real.js a b; node -e CODE");
        foreach (string[] refused in new[] { new[] { "-C", "data", "real.js" }, ["--env-file=x", "real.js"], ["--", "real.js"], ["--test"], ["--require", "x", "real.js"], ["-r", "x", "real.js"], ["--eval", "1"], ["-p", "1"], ["--max-old-space-size", "4096", "real.js"] })
        {
            check(Policy.Check("node", refused) is not null, "grammar: node " + string.Join(' ', refused) + " is refused");
        }

        check(Policy.Check("perl", ["real.pl"]) is null && Policy.InlineCode("perl", ["-e", "print 1"]) == "print 1" && Policy.Check("ruby", ["real.rb"]) is null && Policy.InlineCode("ruby", ["-e", "puts 1"]) == "puts 1", "grammar: perl and ruby script or -e");
        foreach (string[] refused in new[] { new[] { "-wI.", "-wMMOD", "real.pl" }, ["-w", "real.pl"], ["-ne", "print"], ["-MFoo", "real.pl"], ["-E", "say 1"] })
        {
            check(Policy.Check("perl", refused) is not null, "grammar: perl " + string.Join(' ', refused) + " is refused");
        }

        foreach (string[] refused in new[] { new[] { "-C", "data", "real.rb" }, ["-E", "utf-8", "real.rb"], ["-rfoo", "-e", "1"], ["-ne", "1"] })
        {
            check(Policy.Check("ruby", refused) is not null, "grammar: ruby " + string.Join(' ', refused) + " is refused");
        }

        // PowerShell: fixed switches, then exactly -File or -Command, written in full.
        check(Policy.Check("powershell", ["-NoProfile", "-File", "m.ps1"]) is null && Policy.ScriptIndex("powershell", ["-NoProfile", "-File", "m.ps1", "x"]) == 2, "grammar: powershell -NoProfile -File m.ps1");
        check(Policy.Check("powershell", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "m.ps1"]) is null && Policy.ScriptIndex("powershell", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "m.ps1"]) == 4, "grammar: powershell -NoProfile -ExecutionPolicy Bypass -File m.ps1");
        check(Policy.Check("pwsh", ["-nologo", "-noprofile", "-noninteractive", "-command", "echo MARKER"]) is null && Policy.InlineCode("pwsh", ["-NoProfile", "-Command", "echo MARKER"]) == "echo MARKER", "grammar: pwsh -Command CODE, any case");
        foreach (string[] refused in new[] { new[] { "m.ps1" }, ["-NoProfile", "m.ps1"], [" -EncodedCommand", "AAAA"], [" -File", "m.ps1"], ["-File ", "m.ps1"], ["-EncodedCommand", "AAAA"], ["-enc", "AAAA"], ["-e", "AAAA"], ["-ec", "AAAA"],
            ["-f", "m.ps1"], ["-c", "x"], ["-Command", "a", "b"], ["-NoProfile", "-NoProfile", "-File", "m.ps1"], ["-ExecutionPolicy", "Evil", "-File", "m.ps1"], ["-ExecutionPolicy"], ["-File"], ["-File", "-NoProfile"],
            ["-"], ["/File", "m.ps1"], ["-Command"], ["-Sta", "-File", "m.ps1"], ["–EncodedCommand", "AAAA"], ["—File", "m.ps1"], ["―enc", "AAAA"], ["−ec", "AAAA"], ["-NoProfile", "Write-Host x", "-File", "a.ps1"] })
        {
            check(Policy.Check("pwsh", refused) is not null && Policy.Check("powershell", refused) is not null, "grammar: pwsh " + string.Join(' ', refused) + " is refused");
        }

        check(Policy.Check("pwsh", ["-EncodedCommand", "AAAA"]) is { } encoded && encoded.Contains("not readable", StringComparison.Ordinal), "encoded: the message says why");

        // cmd: `cmd [/d] /c TAIL` with plain words, starting with a .cmd/.bat file or echo, dir, type, ver.
        check(Policy.Check("cmd", ["/d", "/c", "echo", "hi"]) is null && Policy.InlineCode("cmd", ["/d", "/c", "echo", "hi"]) == "echo hi" && Policy.ScriptIndex("cmd", ["/d", "/c", "echo", "hi"]) == -1, "grammar: cmd /c echo hi");
        check(Policy.Check("cmd.exe", ["/d", "/c", "hi.cmd"]) is null && Policy.ScriptIndex("cmd.exe", ["/d", "/c", "hi.cmd", "x"]) == 2 && Policy.ScriptIndex("cmd", ["/d", "/C", "sub\\hi.BAT"]) == 2, "grammar: cmd /d /c hi.cmd shows hi.cmd as the script");
        check(Policy.Check("cmd", ["/d", "/c", "dir"]) is null && Policy.Check("cmd", ["/d", "/k", "ver"]) is null && Policy.Check("cmd", ["/D", "/r", "type", "a.txt"]) is null, "grammar: dir, ver, type");
        foreach (string[] refused in new[] { new[] { "/s", "/c", "a b.cmd" }, ["/c", "a b.cmd", "c d"], ["/c", "MARKC"], ["/c", "echo", "a b"], ["/c", "echo", "a&b"], ["/c", "echo", "%PATH%"], ["/c", "echo", "\"x\""], ["/c", "echo", "a|b"], ["/c", "echo", "a^b"], ["/c", "echo", "a<b"], ["/c", "echo", "a>b"], ["/c", "echo", "a!b"],
            ["/q", "/c", "echo", "hi"], ["/d"], ["/c"], ["/s", "/d", "/c", "dir"], ["/c", "powershell"], ["/c", "hi"], ["/c", "start", "x"] })
        {
            check(Policy.Check("cmd", refused) is not null, "grammar: cmd " + string.Join(' ', refused) + " is refused");
        }

        check(Policy.Check("sh", ["-c", "pwsh -EncodedCommand AAAA"]) is not null && Policy.Check("sh", ["-c", "echo -e hi"]) is null, "encoded: nested inside sh -c is refused; -e alone is fine");

        // Other programs have no analyzer: unchanged.
        check(Policy.Check("dotnet", ["test"]) is null && Policy.Check("git", ["status"]) is null && Policy.ScriptIndex("mytool", ["a.txt"]) is null, "grammar: other programs are untouched");
    }

    private static void ScriptOperands(Action<bool, string> check)
    {
        string folder = Path.Combine(Path.GetTempPath(), "ws-operand-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            foreach (string name in new[] { "data.txt", "real.py", "real.sh", "real.js" })
            {
                File.WriteAllText(Path.Combine(folder, name), "data " + name + "\n");
            }

            string[] python = ["real.py", "data.txt"];
            check(PathExpander.ScriptArgumentIndex("python", python, folder) == 0 && PathExpander.ScriptArgumentIndex(["data.txt", "real.py"], folder) == 0, "operand: python real.py data.txt picks real.py");
            check(PathExpander.ExpandScript("python", python, folder).SequenceEqual([Path.Combine(folder, "real.py"), "data.txt"]), "operand: only the real script is written in full");
            check(PathExpander.ScriptArgumentIndex("node", ["real.js", "a", "b"], folder) == 0 && PathExpander.ScriptArgumentIndex("bash", ["real.sh"], folder) == 0, "operand: node real.js a b and bash real.sh");
            check(PathExpander.ScriptArgumentIndex("python", ["missing.py"], folder) == -1, "operand: a script that does not exist has no index");
            check(PathExpander.IsGuess("mytool", ["data.txt"]) && !PathExpander.IsGuess("python", python), "operand: only a program without an analyzer is a guess");

            // The fingerprint hashes the same file.
            string[] expanded = [.. PathExpander.ExpandScript("python", python, folder)];
            Fingerprint print = RequestFingerprint.Compute(new ApprovalRequest("python", "python", expanded, folder, "r", ["A"]));
            check(print.Files.Keys.Any(path => path.EndsWith("real.py", StringComparison.Ordinal)) && !print.Files.Keys.Any(path => path.EndsWith("data.txt", StringComparison.Ordinal)), "operand: the fingerprint covers real.py and not data.txt");

            // A guess is marked on the page.
            string guessed = ApprovalSummary.BuildMessage(Request("mytool", ["a"], ScriptView.Read(Path.Combine(folder, "data.txt")) with { Guessed = true }));
            check(guessed.Contains("(guessed from the arguments, not verified)", StringComparison.Ordinal), "operand: a guessed script is marked not verified");
        }
        finally
        {
            Directory.Delete(folder, true);
        }
    }

    // Fix round 4: the expanded arguments are checked too, the stricter shells, quoting, text rules.
    private static async Task Round4(Action<bool, string> check)
    {
        bool windows = OperatingSystem.IsWindows();

        // The grammar needs -NoProfile for PowerShell and /d for cmd.
        check(Policy.Check("pwsh", ["-File", "m.ps1"]) is { } noProfile && noProfile.Contains("NoProfile", StringComparison.Ordinal) && Policy.Check("powershell", ["-Command", "echo MARKER"]) is not null, "round4: PowerShell without -NoProfile is refused");
        check(Policy.Check("cmd", ["/c", "echo", "hi"]) is { } noD && noD.Contains("/d", StringComparison.Ordinal) && Policy.Check("cmd", ["/c", "hi.cmd"]) is not null && Policy.Check("cmd", ["/k", "dir"]) is not null, "round4: cmd /c without /d is refused");
        check(Policy.Check("pwsh", ["-NoProfile", "-File", "/home/user/m.ps1"]) is null && Policy.ScriptIndex("pwsh", ["-NoProfile", "-File", "/home/user/m.ps1"]) == 2, "round4: pwsh -File with an absolute path starting with a slash is accepted");

        // The expanded arguments: a script path with spaces is fine, one with cmd special characters is not.
        string[] typed = ["/d", "/c", "t.cmd", "x"];
        string[] spaced = ["/d", "/c", @"C:\my proj (x86)\t.cmd", "x"];
        check(Policy.Check("cmd", spaced) is not null && Policy.CheckExpanded("cmd", typed, spaced) is null && Policy.ScriptIndex("cmd", spaced) == 2 && Policy.InlineCode("cmd", spaced) is not null, "round4: cmd with a script path with spaces and brackets passes the expanded check and is shown");
        check(Policy.CheckExpanded("cmd", typed, ["/d", "/c", @"C:\a&b\t.cmd", "x"]) is { } amp && amp.Contains("folder name", StringComparison.Ordinal), "round4: a folder with & is refused for cmd with the folder message");
        foreach (string special in new[] { "a|b", "a^b", "a%b", "a!b", "a<b", "a>b", "a\"b" })
        {
            check(Policy.CheckExpanded("cmd", typed, ["/d", "/c", @"C:\" + special + @"\t.cmd", "x"]) is not null, "round4: cmd folder with " + special + " is refused");
        }

        check(Policy.CheckExpanded("cmd", typed, ["/d", "/c", @"C:\p\t.cmd", "x y"]) is not null, "round4: an expanded argument outside the grammar is refused");
        check(Policy.CheckExpanded("bash", ["-c", "echo MARKER"], ["real.sh"]) is not null && Policy.CheckExpanded("bash", ["real.sh"], ["-c", "echo MARKER"]) is not null, "round4: the script/inline decision must be the same before and after expansion");
        check(Policy.CheckExpanded("bash", ["real.sh", "a"], ["/tmp/my dir/real.sh", "a"]) is null && Policy.CheckExpanded("sh", ["-c", "echo MARKER"], ["-c", "echo MARKER"]) is null, "round4: bash with a spaced script path passes");

        // The environment denylist.
        check(ChildRunner.IsCodeLoading("BASH_FUNC_ws%%", false) && ChildRunner.IsCodeLoading("PERLLIB", false) && ChildRunner.IsCodeLoading("ZDOTDIR", false) && ChildRunner.IsCodeLoading("PYTHONUSERBASE", false)
            && ChildRunner.IsCodeLoading("PYTHONWARNINGS", false) && ChildRunner.IsCodeLoading("NODE_PATH", false) && ChildRunner.IsCodeLoading("GIT_CONFIG_GLOBAL", false) && ChildRunner.IsCodeLoading("GIT_CONFIG_SYSTEM", false)
            && ChildRunner.IsCodeLoading("GIT_EXEC_PATH", false) && ChildRunner.IsCodeLoading("GIT_SSH_COMMAND", false) && ChildRunner.IsCodeLoading("GIT_ASKPASS", false) && ChildRunner.IsCodeLoading("RUBYLIB", false), "round4: the denylist has the new names and the BASH_FUNC_ prefix");
        check(!ChildRunner.IsCodeLoading("PATH", false) && !ChildRunner.IsCodeLoading("MY_BASH_FUNC_X", false) && !ChildRunner.IsCodeLoading("perllib", false) && ChildRunner.IsCodeLoading("perllib", true) && ChildRunner.IsCodeLoading("bash_func_x", true), "round4: the denylist is exact, and case-insensitive only where the environment is");

        // Quoting follows CommandLineToArgvW.
        check(ApprovalSummary.Quote("PSMARK dir\\") == "\"PSMARK dir\\\\\"" && ApprovalSummary.Quote("PSMARK\\") == "PSMARK\\" && ApprovalSummary.Quote("a\\\"b c") == "\"a\\\\\\\"b c\"" && ApprovalSummary.Quote("a b") == "\"a b\"" && ApprovalSummary.Quote("") == "\"\"",
            "round4: Quote doubles a trailing backslash before the closing quote");
        check(ApprovalSummary.CommandLine("p", ["PSMARK dir\\", "x"]) == "p \"PSMARK dir\\\\\" x", "round4: the command line shows the doubled backslash");

        // BOM and non-ASCII bytes are recorded.
        ScriptView bom = ScriptView.FromBytes([0xEF, 0xBB, 0xBF, (byte)'a'], "x");
        ScriptView accent = ScriptView.FromBytes(Encoding.UTF8.GetBytes("caf\u00e9"), "x");
        ScriptView ascii = ScriptView.FromBytes("abc"u8.ToArray(), "x");
        check(bom.Bom && !bom.NonAscii && accent.NonAscii && !accent.Bom && !ascii.Bom && !ascii.NonAscii, "round4: a script view records a BOM and non-ASCII bytes");

        string folder = Path.Combine(Path.GetTempPath(), "ws-r4-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        string audit = Path.Combine(folder, "audit.db");
        Dictionary<string, string> values = new() { ["DB_URL"] = "Summary-Secret-1234" };
        try
        {
            string extension = windows ? ".cmd" : ".sh";
            string shell = windows ? "cmd" : "sh";
            string[] Prefix(string script) => windows ? [shell, "/d", "/c", script] : [shell, script];
            string? resolvedShell = ProgramResolver.Resolve(shell, folder);
            if (resolvedShell is not null)
            {
                // A script that does not exist is refused before any prompt.
                FakeApprover never = new(true);
                StringWriter errors = new();
                RunArgs missing = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "x", "--", .. Prefix("nope" + extension)], out _)!;
                int code = await new RunCommand(new MemoryStore(values), never, new AuditLog(new StateDatabase(audit)), new StringWriter(), errors).ExecuteAsync(missing, folder);
                check(code == RunCommand.Usage && never.Requests.Count == 0 && errors.ToString().Contains("does not exist", StringComparison.Ordinal), "round4 run: a script that does not exist is refused before any prompt");

                // A binary script is refused.
                await File.WriteAllBytesAsync(Path.Combine(folder, "bin" + extension), [0, 1, 2, 3]);
                errors = new StringWriter();
                RunArgs binary = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "x", "--", .. Prefix("bin" + extension)], out _)!;
                code = await new RunCommand(new MemoryStore(values), never, new AuditLog(new StateDatabase(audit)), new StringWriter(), errors).ExecuteAsync(binary, folder);
                check(code == RunCommand.Usage && never.Requests.Count == 0 && errors.ToString().Contains("Binary scripts", StringComparison.Ordinal), "round4 run: a binary script given to an interpreter is refused");

                // A working folder with spaces and brackets works, and the script is shown, hashed and held.
                string spacedFolder = Path.Combine(folder, "my proj (x86)");
                Directory.CreateDirectory(spacedFolder);
                string scriptName = "t" + extension;
                await File.WriteAllTextAsync(Path.Combine(spacedFolder, scriptName), windows ? "@echo off\r\necho SPACE_MARK_OK\r\n" : "echo SPACE_MARK_OK\n");
                FakeApprover approver = new(true);
                StringWriter output = new();
                errors = new StringWriter();
                RunArgs spacedRun = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "x", "--", .. Prefix(scriptName)], out _)!;
                code = await new RunCommand(new MemoryStore(values), approver, new AuditLog(new StateDatabase(audit)), output, errors).ExecuteAsync(spacedRun, spacedFolder);
                ApprovalRequest? seen = approver.Requests.SingleOrDefault();
                bool shown = seen?.Script is { Text: not null } view && view.Path.StartsWith(spacedFolder, StringComparison.Ordinal) && ApprovalSummary.BuildMessage(seen).Contains(Marker + "echo SPACE_MARK_OK", StringComparison.Ordinal);
                check(code == 0 && shown && output.ToString().Contains("SPACE_MARK_OK", StringComparison.Ordinal), "round4 run: a folder with spaces and brackets runs and the script is shown (" + code + " " + errors.ToString().Trim().Replace('\n', ' ') + ")");
                if (seen?.Script is { } script)
                {
                    check(RequestFingerprint.Compute(seen).Files.TryGetValue(script.Path, out string? hash) && hash == script.Sha256, "round4 run: the script of a folder with spaces is hashed");
                    using HeldFiles held = new();
                    check(held.Hold([script]) is null, "round4 run: the script of a folder with spaces can be held");
                    if (windows)
                    {
                        bool writable = true;
                        try
                        {
                            File.WriteAllText(script.Path, "changed");
                        }
                        catch (IOException)
                        {
                            writable = false;
                        }

                        check(!writable, "round4 run: the held script of a folder with spaces cannot be written");
                    }
                }

                // A folder with & is refused for cmd.
                if (windows)
                {
                    string ampFolder = Path.Combine(folder, "a&b");
                    Directory.CreateDirectory(ampFolder);
                    await File.WriteAllTextAsync(Path.Combine(ampFolder, scriptName), "@echo off\r\necho AMP_MARK\r\n");
                    FakeApprover none = new(true);
                    errors = new StringWriter();
                    code = await new RunCommand(new MemoryStore(values), none, new AuditLog(new StateDatabase(audit)), new StringWriter(), errors).ExecuteAsync(spacedRun, ampFolder);
                    check(code == RunCommand.Usage && none.Requests.Count == 0 && errors.ToString().Contains("folder name", StringComparison.Ordinal), "round4 run: cmd in a folder with & is refused with a clear message");
                }
            }

            // Windows PowerShell 5.1 reads a script without a BOM in the ANSI code page.
            if (windows && ProgramResolver.Resolve("powershell", folder) is not null)
            {
                await File.WriteAllBytesAsync(Path.Combine(folder, "u.ps1"), Encoding.UTF8.GetBytes("Write-Output 'caf\u00e9'\n"));
                await File.WriteAllBytesAsync(Path.Combine(folder, "b.ps1"), [.. Encoding.UTF8.GetPreamble(), .. Encoding.UTF8.GetBytes("Write-Output 'caf\u00e9'\n")]);
                FakeApprover deny = new(false);
                StringWriter errors = new();
                RunArgs noBom = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "x", "--", "powershell", "-NoProfile", "-File", "u.ps1"], out _)!;
                int code = await new RunCommand(new MemoryStore(values), deny, new AuditLog(new StateDatabase(audit)), new StringWriter(), errors).ExecuteAsync(noBom, folder);
                check(code == RunCommand.Usage && deny.Requests.Count == 0 && errors.ToString().Contains("byte order mark", StringComparison.Ordinal), "round4 run: powershell.exe refuses a non-ASCII script without a BOM");
                RunArgs withBom = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "x", "--", "powershell", "-NoProfile", "-File", "b.ps1"], out _)!;
                await new RunCommand(new MemoryStore(values), deny, new AuditLog(new StateDatabase(audit)), new StringWriter(), new StringWriter()).ExecuteAsync(withBom, folder);
                check(deny.Requests.Count == 1, "round4 run: powershell.exe accepts the same script with a BOM");
            }
        }
        finally
        {
            Directory.Delete(folder, true);
        }
    }

    // Fix round 5: cmd command-word delimiters, PowerShell wildcards, aliases, batch files.
    private static async Task Round5(Action<bool, string> check)
    {
        bool windows = OperatingSystem.IsWindows();

        // PowerShell reads -File paths as wildcards.
        foreach (string shell in new[] { "powershell", "pwsh" })
        {
            check(Policy.Check(shell, ["-NoProfile", "-File", "t[1].ps1"]) is { } wild && wild.Contains("wildcards", StringComparison.Ordinal), "round5: " + shell + " -File t[1].ps1 is refused");
            check(Policy.Check(shell, ["-NoProfile", "-File", "t`1.ps1"]) is not null && Policy.Check(shell, ["-NoProfile", "-File", "t.ps1"]) is null, "round5: " + shell + " -File with a backtick is refused, a plain name is not");
            check(Policy.CheckExpanded(shell, ["-NoProfile", "-File", "t.ps1"], ["-NoProfile", "-File", windows ? @"C:\x\a[bc]\t.ps1" : "/x/a[bc]/t.ps1"]) is { } folder && folder.Contains("wildcards", StringComparison.Ordinal), "round5: " + shell + " in a folder with [ ] is refused after expansion");
            check(Policy.CheckExpanded(shell, ["-NoProfile", "-File", "t.ps1"], ["-NoProfile", "-File", windows ? @"C:\x\my proj (x86)\t.ps1" : "/x/my proj (x86)/t.ps1"]) is null, "round5: " + shell + " in a plain folder with spaces passes");
        }

        // The environment denylist and the alias rule.
        check(new[] { "SHELLOPTS", "BASHOPTS", "PS4", "PS0", "PROMPT_COMMAND" }.All(name => ChildRunner.IsCodeLoading(name, false)), "round5: the denylist has SHELLOPTS, BASHOPTS, PS4, PS0 and PROMPT_COMMAND");
        string aliasPath = @"C:\Users\u\AppData\Local\Microsoft\WindowsApps\python3.exe";
        check(RunCommand.IsAlias(aliasPath, FileAttributes.ReparsePoint | FileAttributes.Archive, 0) && !RunCommand.IsAlias(aliasPath, FileAttributes.Archive, 0) && !RunCommand.IsAlias(aliasPath, FileAttributes.ReparsePoint, 10)
            && !RunCommand.IsAlias(@"C:\Python\python.exe", FileAttributes.ReparsePoint, 0), "round5: only a zero-length reparse point under WindowsApps is an alias");
        string python = RunCommand.AliasMessage("python3");
        string winget = RunCommand.AliasMessage("winget.exe");
        check(python.Contains("python3", StringComparison.Ordinal) && python.Contains("python.exe", StringComparison.Ordinal) && winget.Contains("winget", StringComparison.Ordinal) && !winget.Contains("python.exe", StringComparison.Ordinal)
            && winget.Contains("resolves to an App Execution Alias: use the full path to the real program", StringComparison.Ordinal), "round5: the alias message names the program and mentions python.exe only for python");

        if (!windows)
        {
            return;
        }

        string root = Path.Combine(Path.GetTempPath(), "ws-r5-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        string audit = Path.Combine(root, "audit.db");
        Dictionary<string, string> values = new() { ["DB_URL"] = "Summary-Secret-1234" };
        try
        {
            // cmd cuts the command word at , ; = and white space: the first word after /c is always quoted.
            await File.WriteAllTextAsync(Path.Combine(root, "a.cmd"), "@echo off\r\necho HIDDEN_A_MARKER\r\n");
            foreach (string name in new[] { "a,b", "a;b", "a=b", "br[1]", "a+b", "my proj (x86)" })
            {
                string folder = Path.Combine(root, name);
                Directory.CreateDirectory(folder);
                await File.WriteAllTextAsync(Path.Combine(folder, "t.cmd"), "@echo off\r\necho SHOWN_T %1\r\n");
                FakeApprover approver = new(true);
                StringWriter output = new();
                StringWriter errors = new();
                RunArgs run = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "x", "--", "cmd", "/d", "/c", "t.cmd", "x1"], out _)!;
                int code = await new RunCommand(new MemoryStore(values), approver, new AuditLog(new StateDatabase(audit)), output, errors).ExecuteAsync(run, folder);
                string text = output.ToString();
                check(code == 0 && text.Contains("SHOWN_T x1", StringComparison.Ordinal) && !text.Contains("HIDDEN_A_MARKER", StringComparison.Ordinal) && approver.Requests.Single().Script is { Text: not null } shown && shown.Path.StartsWith(folder, StringComparison.Ordinal),
                    "round5 run: cmd /d /c t.cmd in a folder named '" + name + "' runs the shown file (" + code + " " + errors.ToString().Trim().Replace('\n', ' ') + ")");
            }

            // A batch file run directly is started through cmd /d /c with the same quoting.
            string batchFolder = Path.Combine(root, "b,c (x)");
            Directory.CreateDirectory(batchFolder);
            string batch = Path.Combine(batchFolder, "hi.cmd");
            await File.WriteAllTextAsync(batch, "@echo off\r\necho DIRECT_MARK %1\r\n");
            (string file, string? raw) = ChildRunner.Launch(new ChildSpec(batch, ["x 1"], batchFolder, new Dictionary<string, string>()));
            check(file.EndsWith("cmd.exe", StringComparison.OrdinalIgnoreCase) && raw is not null && raw.StartsWith("/d /c \"\"" + batch + "\"", StringComparison.Ordinal), "round5: a batch file is started as cmd.exe /d /c with the path in quotes");
            StringWriter direct = new();
            int exit = await ChildRunner.RunAsync(new ChildSpec(batch, ["x1"], batchFolder, new Dictionary<string, string>()), direct, new StringWriter());
            check(exit == 0 && direct.ToString().Contains("DIRECT_MARK x1", StringComparison.Ordinal), "round5 run: a batch file in a folder with a comma and brackets runs directly");

            // A batch file must be ASCII.
            await File.WriteAllBytesAsync(Path.Combine(root, "u.cmd"), Encoding.UTF8.GetBytes("@echo off\r\necho caf\u00e9\r\n"));
            foreach (string[] words in new[] { new[] { "cmd", "/d", "/c", "u.cmd" }, ["./u.cmd"] })
            {
                FakeApprover none = new(true);
                StringWriter errors = new();
                RunArgs run = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "x", "--", .. words], out _)!;
                int code = await new RunCommand(new MemoryStore(values), none, new AuditLog(new StateDatabase(audit)), new StringWriter(), errors).ExecuteAsync(run, root);
                check(code == RunCommand.Usage && none.Requests.Count == 0 && errors.ToString().Contains("batch files must be ASCII", StringComparison.Ordinal), "round5 run: a non-ASCII batch file is refused (" + string.Join(' ', words) + ")");
            }

            // Real Windows PowerShell: a plain folder works, a folder with [ ] is refused before any prompt.
            if (ProgramResolver.Resolve("powershell", root) is not null)
            {
                string plain = Path.Combine(root, "plain dir");
                string wild = Path.Combine(root, "a[bc]");
                Directory.CreateDirectory(plain);
                Directory.CreateDirectory(wild);
                await File.WriteAllTextAsync(Path.Combine(plain, "t.ps1"), "Write-Output 'PS_MARK_OK'\r\n");
                await File.WriteAllTextAsync(Path.Combine(wild, "t.ps1"), "Write-Output 'PS_WILD_MARK'\r\n");
                RunArgs psRun = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "x", "--", "powershell", "-NoProfile", "-File", "t.ps1"], out _)!;
                FakeApprover approver = new(true);
                StringWriter output = new();
                int code = await new RunCommand(new MemoryStore(values), approver, new AuditLog(new StateDatabase(audit)), output, new StringWriter()).ExecuteAsync(psRun, plain);
                check(code == 0 && output.ToString().Contains("PS_MARK_OK", StringComparison.Ordinal), "round5 run: powershell -File in a plain folder with a space runs");
                FakeApprover none = new(true);
                StringWriter errors = new();
                code = await new RunCommand(new MemoryStore(values), none, new AuditLog(new StateDatabase(audit)), new StringWriter(), errors).ExecuteAsync(psRun, wild);
                check(code == RunCommand.Usage && none.Requests.Count == 0 && errors.ToString().Contains("wildcards", StringComparison.Ordinal), "round5 run: powershell -File in a folder with [ ] is refused before any prompt");
            }
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }

    private static async Task RealCmd(Action<bool, string> check)
    {
        if (!OperatingSystem.IsWindows() || ProgramResolver.Resolve("cmd", Path.GetTempPath()) is not { } cmd)
        {
            return;
        }

        string[] arguments = ["/d", "/c", "echo", "CMD_MARKER_OK"];
        StringWriter output = new();
        check(Policy.Check("cmd", arguments) is null, "cmd real: the plain echo passes the policy");
        await ChildRunner.RunAsync(new ChildSpec(cmd, arguments, Path.GetTempPath(), new Dictionary<string, string>()), output, new StringWriter());
        check(output.ToString().Contains("CMD_MARKER_OK", StringComparison.Ordinal), "cmd real: cmd.exe /c echo runs and prints the marker");
        check(Policy.InlineCode("cmd", arguments) == "echo CMD_MARKER_OK", "cmd real: the page shows the tail cmd receives");
    }

    private static string? Interp(string folder) => OperatingSystem.IsWindows() ? "cmd" : ProgramResolver.Resolve("sh", folder);

    private static async Task Hardening(Action<bool, string> check)
    {
        string folder = Path.Combine(Path.GetTempPath(), "ws-harden-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        string audit = Path.Combine(folder, "audit.db");
        Dictionary<string, string> values = new() { ["DB_URL"] = "Summary-Secret-1234" };
        try
        {
            // (1) a program that is itself a text file is shown, and the script argument as well.
            bool windows = OperatingSystem.IsWindows();
            string evil = Path.Combine(folder, windows ? "evil.cmd" : "evil.sh");
            await File.WriteAllTextAsync(evil, windows ? "@echo off\r\necho EVIL_MARK\r\n" : "#!/bin/sh\necho EVIL_MARK\n");
            if (!windows)
            {
                File.SetUnixFileMode(evil, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }

            string data = Path.Combine(folder, "data.txt");
            await File.WriteAllTextAsync(data, "just data\n");
            FakeApprover deny = new(false);
            RunArgs benign = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "x", "--", "./" + Path.GetFileName(evil), "hello"], out _)!;
            int code = await new RunCommand(new MemoryStore(values), deny, new AuditLog(new StateDatabase(audit)), new StringWriter(), new StringWriter()).ExecuteAsync(benign, folder);
            ApprovalRequest seen = deny.Requests.Single();
            string message = ApprovalSummary.BuildMessage(seen);
            check(code == RunCommand.Denied && seen.ProgramFile is { Text: not null } && seen.Script is null && Lines(message).Contains(Marker + "echo EVIL_MARK"), "program file: a script run directly is shown even with a benign argument");

            deny = new FakeApprover(false);
            RunArgs both = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "x", "--", "./" + Path.GetFileName(evil), "./data.txt"], out _)!;
            await new RunCommand(new MemoryStore(values), deny, new AuditLog(new StateDatabase(audit)), new StringWriter(), new StringWriter()).ExecuteAsync(both, folder);
            message = ApprovalSummary.BuildMessage(deny.Requests.Single());
            check(Lines(message).Count(line => line.StartsWith("Script file: ", StringComparison.Ordinal)) == 2 && Lines(message).Contains(Marker + "echo EVIL_MARK") && Lines(message).Contains(Marker + "just data"), "program file: the program and its script argument are both shown, each with its hash");
            check(Lines(message).Count(line => line.StartsWith("Script SHA-256: ", StringComparison.Ordinal)) == 2, "program file: two hashes");

            // (5) more than 1 MB is never run unseen: as a program, and as the script of an interpreter. Without the refusal the
            // run would go to the prompt (never records it), so each check fails when the refusal is removed.
            string bigName = windows ? "big.cmd" : "big.sh";
            await File.WriteAllBytesAsync(Path.Combine(folder, bigName), new byte[1024 * 1024 + 10]);
            FakeApprover never = new(true);
            StringWriter errors = new();
            string? interpreter = Interp(folder);
            if (interpreter is not null)
            {
                RunArgs bigRun = CliArgs.ParseRun(windows ? ["--secrets", "DB_URL", "--reason", "x", "--", "cmd", "/d", "/c", bigName] : ["--secrets", "DB_URL", "--reason", "x", "--", "sh", bigName], out _)!;
                code = await new RunCommand(new MemoryStore(values), never, new AuditLog(new StateDatabase(audit)), new StringWriter(), errors).ExecuteAsync(bigRun, folder);
                check(code == RunCommand.Usage && never.Requests.Count == 0 && errors.ToString().Contains("larger than 1 MB", StringComparison.Ordinal), "big: a script over 1 MB given to an interpreter is refused before any prompt (" + code + ")");
            }

            RunArgs bigDirect = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "x", "--", "./" + bigName], out _)!;
            errors = new StringWriter();
            code = await new RunCommand(new MemoryStore(values), never, new AuditLog(new StateDatabase(audit)), new StringWriter(), errors).ExecuteAsync(bigDirect, folder);
            check(code == RunCommand.Usage && never.Requests.Count == 0 && errors.ToString().Contains("larger than 1 MB", StringComparison.Ordinal), "big: a script over 1 MB run directly is refused before any prompt (" + code + ")");

            // bare interpreter through a run: refused without a prompt
            if (interpreter is not null)
            {
                RunArgs bare = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "x", "--", interpreter], out _)!;
                errors = new StringWriter();
                code = await new RunCommand(new MemoryStore(values), never, new AuditLog(new StateDatabase(audit)), new StringWriter(), errors).ExecuteAsync(bare, folder);
                check(code == RunCommand.Usage && never.Requests.Count == 0 && errors.ToString().Contains("nothing to run", StringComparison.Ordinal), "bare: an interpreter with nothing to run is refused before any prompt");
            }

            // (7) the shown file must be the file the fingerprint covers: changed between reading it and fingerprinting it.
            string racer = Path.Combine(folder, windows ? "racer.cmd" : "racer.sh");
            await File.WriteAllTextAsync(racer, windows ? "@echo off\r\necho first\r\n" : "#!/bin/sh\necho first\n");
            if (!windows)
            {
                File.SetUnixFileMode(racer, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }

            FakeApprover approver = new(true);
            RunArgs racerRun = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "race", "--", "./" + Path.GetFileName(racer)], out _)!;
            RunCommand.AfterScriptRead = () => File.WriteAllText(racer, windows ? "@echo off\r\necho second\r\n" : "#!/bin/sh\necho second\n");
            try
            {
                errors = new StringWriter();
                code = await new RunCommand(new MemoryStore(values), approver, new AuditLog(new StateDatabase(audit)), new StringWriter(), errors).ExecuteAsync(racerRun, folder);
            }
            finally
            {
                RunCommand.AfterScriptRead = null;
            }

            check(code == RunCommand.Usage && approver.Requests.Count == 0 && errors.ToString().Contains("while the request was being made", StringComparison.Ordinal), "race: a file that changed between being shown and being fingerprinted is refused before any prompt (" + code + ")");

            // a file edited while the prompt is open is not run (the fingerprint check after the approval)
            await File.WriteAllTextAsync(racer, windows ? "@echo off\r\necho first\r\n" : "#!/bin/sh\necho first\n");
            errors = new StringWriter();
            code = await new RunCommand(new MemoryStore(values), new EditingApprover(racer), new AuditLog(new StateDatabase(audit)), new StringWriter(), errors).ExecuteAsync(racerRun, folder);
            check(code == RunCommand.Denied && errors.ToString().Contains("while the prompt was open", StringComparison.Ordinal), "race: a file edited while the prompt is open is refused by the fingerprint check (" + code + "; " + errors + ")");

            // held files: nobody can write or delete a shown file while it is held (Windows); a changed file is caught on every system
            await File.WriteAllTextAsync(data, "just data\n");
            ScriptView shownData = ScriptView.Read(data);
            using (HeldFiles held = new())
            {
                check(held.Hold([shownData]) is null, "hold: a shown file can be held");
                if (windows)
                {
                    bool writeBlocked = false;
                    bool deleteBlocked = false;
                    try
                    {
                        File.WriteAllText(data, "changed\n");
                    }
                    catch (Exception error) when (error is IOException or UnauthorizedAccessException)
                    {
                        writeBlocked = true;
                    }

                    try
                    {
                        File.Delete(data);
                    }
                    catch (Exception error) when (error is IOException or UnauthorizedAccessException)
                    {
                        deleteBlocked = true;
                    }

                    check(writeBlocked && deleteBlocked, "hold: on Windows a held file cannot be written or deleted");
                    check(File.ReadAllText(data) == "just data\n", "hold: a held file can still be read");
                }
            }

            await File.WriteAllTextAsync(data, "changed\n");
            using HeldFiles changed = new();
            check(changed.Hold([shownData]) is { } why && why.Contains("changed after it was shown", StringComparison.Ordinal), "hold: a file that no longer matches what was shown is refused");
            using HeldFiles missing = new();
            check(missing.Hold([shownData with { Path = Path.Combine(folder, "gone.txt") }]) is not null, "hold: a file that cannot be opened is refused");

            // (6) stdin is closed and code-loading variables are removed
            string reader = windows ? "sort" : "cat";
            string? readerPath = ProgramResolver.Resolve(reader, folder);
            if (readerPath is not null)
            {
                Task<int> finished = ChildRunner.RunAsync(new ChildSpec(readerPath, [], folder, new Dictionary<string, string>()), new StringWriter(), new StringWriter());
                check(await Task.WhenAny(finished, Task.Delay(TimeSpan.FromSeconds(20))) == finished, "stdin: a program that reads standard input gets end of file at once");
            }

            string marker = "--require=scrub-marker-" + Guid.NewGuid().ToString("N");
            Environment.SetEnvironmentVariable("NODE_OPTIONS", marker);
            Environment.SetEnvironmentVariable("BASH_ENV", marker);
            try
            {
                string? shell = windows ? ProgramResolver.Resolve("cmd", folder) : ProgramResolver.Resolve("sh", folder);
                if (shell is not null)
                {
                    StringWriter output = new();
                    string[] shellArguments = windows ? ["/c", "set"] : ["-c", "env"];
                    await ChildRunner.RunAsync(new ChildSpec(shell, shellArguments, folder, new Dictionary<string, string> { ["DB_URL"] = "Summary-Secret-1234" }), output, new StringWriter());
                    string dump = output.ToString();
                    check(dump.Contains("PATH", StringComparison.OrdinalIgnoreCase) && !dump.Contains(marker, StringComparison.Ordinal), "env: NODE_OPTIONS and BASH_ENV are removed from the child's environment");
                }
            }
            finally
            {
                Environment.SetEnvironmentVariable("NODE_OPTIONS", null);
                Environment.SetEnvironmentVariable("BASH_ENV", null);
            }
        }
        finally
        {
            Directory.Delete(folder, true);
        }
    }

    private static ApprovalRequest Request(string program, string[] arguments, ScriptView? script = null)
        => new(program, program, arguments, "/work", "reason", ["DB_URL"], RequestId: "ABC123", Script: script);

    private static string[] Lines(string message) => message.Split('\n');

    private static void Inline(Action<bool, string> check)
    {
        check(Policy.InlineCode("bash", ["-c", "echo $A"]) == "echo $A", "inline: bash -c code is the next argument");
        check(Policy.InlineCode("/bin/sh", ["-c", "echo $A", "name"]) == "echo $A", "inline: sh -c code is the next argument only");
        check(Policy.InlineCode("bash", ["script.sh"]) is null, "inline: a script is not inline code");
        check(Policy.InlineCode("cmd.exe", ["/d", "/c", "echo", "hi", "there"]) == "echo hi there", "inline: cmd /c code is the rest of the line");
        check(Policy.InlineCode("cmd", ["/d", "/K", "dir"]) == "dir", "inline: cmd /K code");
        check(Policy.InlineCode("pwsh", ["-NoProfile", "-Command", "Get-Date -Format o"]) == "Get-Date -Format o", "inline: pwsh -Command code is its one argument");
        check(Policy.InlineCode("pwsh", ["-c", "1+1"]) is null && Policy.Check("powershell", ["-co", "1+1"]) is not null, "inline: -c and -co are not -Command (no abbreviations)");
        check(Policy.InlineCode("pwsh", ["-NoProfile", "Get-Date"]) is null && Policy.Check("pwsh", ["-NoProfile", "Get-Date"]) is not null, "inline: pwsh with a bare positional is refused");
        check(Policy.InlineCode("pwsh", ["-ExecutionPolicy", "Bypass", "-File", "run.ps1"]) is null, "inline: pwsh -File is a script, a flag's value is not code");
        check(Policy.Check("pwsh", ["-NoProfile"]) is not null, "inline: pwsh with nothing to show is refused");
        check(Policy.Check("pwsh", ["-EncodedCommand", "AAAA"]) is { } encoded && encoded.Contains("not readable", StringComparison.Ordinal), "inline: -EncodedCommand is refused as not readable");
        check(Policy.Check("powershell", ["-enc", "AAAA"]) is not null && Policy.Check("pwsh", ["-e", "AAAA"]) is not null && Policy.Check("pwsh", ["-ec", "AAAA"]) is not null, "inline: -enc, -e and -ec are refused");
        check(Policy.Check("pwsh", ["-"]) is not null, "inline: pwsh reading standard input is refused");
        check(Policy.Check("env", []) is not null, "inline: other refusals stay (env)");
        check(Policy.CheckBatchFile(@"C:\x\run.cmd", ["a&b"]) is not null, "inline: the .cmd metacharacter rule stays");

        string message = ApprovalSummary.BuildMessage(Request("bash", ["-c", "echo one\necho two"]));
        string[] lines = Lines(message);
        int header = Array.IndexOf(lines, "Inline code:");
        check(header >= 0 && lines[header + 1] == Marker + "echo one" && lines[header + 2] == Marker + "echo two", "inline: the page text has an Inline code block, one marked line per code line");
        check(!ApprovalSummary.BuildMessage(Request("bash", ["script.sh"])).Contains("Inline code:", StringComparison.Ordinal), "inline: no block when there is no inline code");

        string changed = ApprovalSummary.BuildMessage(Request("bash", ["-c", "echo one\necho twO"]));
        check(changed != message, "inline: changing one character changes the text");
        check(!RequestBinding.Compute("n", message).SequenceEqual(RequestBinding.Compute("n", changed)), "inline: changing one character changes the bind the passkey signs");
        check(message.Contains("Run: bash -c", StringComparison.Ordinal), "inline: the Run line is still there");

        // The forged line is behind the marker even inside inline code.
        string forged = ApprovalSummary.BuildMessage(Request("sh", ["-c", "x\nRequest id: FAKE\nAdmin key: y\nRun: z"]));
        check(Lines(forged).Count(line => line.StartsWith("Request id: ", StringComparison.Ordinal)) == 1
            && Lines(forged).Count(line => line.StartsWith("Admin key:", StringComparison.Ordinal)) == 0
            && Lines(forged).Count(line => line.StartsWith("Run: ", StringComparison.Ordinal)) == 1, "inline: a forged page line in the code stays behind the marker");
    }

    private static void Script(Action<bool, string> check)
    {
        ScriptView script = new("HASH", 100, "echo hi\nRequest id: x\nAdmin key: y\nPage issued: now\nRun: rm -rf /\r\nSecrets: none\r\tindented\n");
        string message = ApprovalSummary.BuildMessage(Request("sh", ["/work/a.sh"], script));
        string[] lines = Lines(message);
        check(lines.Contains("Script SHA-256: HASH") && lines.Contains("Script contents:"), "script: the text states the hash and has a Script contents block");
        check(lines.Count(line => line.StartsWith("Request id: ", StringComparison.Ordinal)) == 1 && lines.Last() == "Request id: ABC123", "script: only the real Request id line starts with Request id");
        check(!lines.Any(line => line.StartsWith("Admin key:", StringComparison.Ordinal) || line.StartsWith("Page issued:", StringComparison.Ordinal)), "script: fake Admin key and Page issued lines cannot start a line");
        check(lines.Count(line => line.StartsWith("Run: ", StringComparison.Ordinal)) == 1 && lines.Count(line => line.StartsWith("Secrets:", StringComparison.Ordinal)) == 1, "script: fake Run and Secrets lines cannot start a line");
        int start = Array.IndexOf(lines, "Script contents:");
        string[] shown = lines[(start + 1)..^1];
        check(shown.Length == 7 && shown.All(line => line.StartsWith(Marker, StringComparison.Ordinal)), "script: every content line is behind the marker (" + shown.Length + ")");
        check(shown[0] == Marker + "echo hi" && shown[1] == Marker + "Request id: x", "script: content is shown as it is after the marker");
        check(shown[5] == Marker + "Secrets: none" && shown[6] == Marker + "    indented", "script: CR is a line break and a tab is 4 spaces");

        // Control, bidi and zero-width characters, and Unicode line separators, are replaced.
        string tricky = "a" + (char)0x202E + "b" + (char)0x200B + "c" + (char)0x07 + "d" + (char)0x2028 + "Request id: z" + (char)0x85 + "e" + (char)0x1B + "[2J";
        string cleaned = ApprovalSummary.BuildMessage(Request("sh", ["/work/a.sh"], new ScriptView("H", 5, tricky)));
        check(!cleaned.Any(character => character is (char)0x202E or (char)0x200B or (char)0x07 or (char)0x2028 or (char)0x85 or (char)0x1B), "script: control, bidi, zero-width and separator characters are stripped");
        check(Lines(cleaned).Count(line => line.StartsWith("Request id: ", StringComparison.Ordinal)) == 1, "script: a Unicode line separator does not start a page line");
        string inlineClean = ApprovalSummary.BuildMessage(Request("sh", ["-c", tricky]));
        check(!inlineClean.Any(character => character is (char)0x202E or (char)0x200B or (char)0x07 or (char)0x1B), "inline: control, bidi and zero-width characters are stripped");

        // Changing one character of the file changes the text and the bind.
        string one = ApprovalSummary.BuildMessage(Request("sh", ["/work/a.sh"], new ScriptView("H", 5, "echo a")));
        string two = ApprovalSummary.BuildMessage(Request("sh", ["/work/a.sh"], new ScriptView("H", 5, "echo b")));
        check(one != two && !RequestBinding.Compute("n", one).SequenceEqual(RequestBinding.Compute("n", two)), "script: a changed character changes the text and the bind");

        check(ApprovalSummary.BuildMessage(Request("sh", ["/work/a.sh"], new ScriptView("H", 0, ""))).Contains("Script contents: empty file", StringComparison.Ordinal), "script: an empty file says so");
    }

    private static void Cuts(Action<bool, string> check)
    {
        // Inline: 4000 characters are shown whole, 4001 are cut with a count.
        string exact = ApprovalSummary.BuildMessage(Request("sh", ["-c", new string('x', 4000)]));
        check(!exact.Contains("...cut", StringComparison.Ordinal) && exact.Contains(Marker + new string('x', 4000), StringComparison.Ordinal), "cut: 4000 inline characters are shown whole");
        string cut = ApprovalSummary.BuildMessage(Request("sh", ["-c", new string('x', 4007)]));
        check(cut.Contains("...cut (7 more characters)", StringComparison.Ordinal) && cut.Contains(Marker + new string('x', 4000) + "\n", StringComparison.Ordinal) && !Lines(cut).Any(line => line.StartsWith(Marker, StringComparison.Ordinal) && line.Length > Marker.Length + 4000), "cut: inline code past 4000 characters is cut with the number left out");
        string surrogate = new string('x', 3999) + "\U0001F600" + "tail";
        string splitPair = ApprovalSummary.BuildMessage(Request("sh", ["-c", surrogate]));
        check(!Lines(splitPair).Where(line => line.StartsWith(Marker, StringComparison.Ordinal)).Any(line => line.Any(char.IsHighSurrogate)) && splitPair.Contains("...cut (", StringComparison.Ordinal), "cut: a surrogate pair is not split");

        // Script lines: 200 shown whole, 201 cut.
        string Many(int count) => string.Join('\n', Enumerable.Range(1, count).Select(number => "line" + number));
        string whole = ApprovalSummary.BuildMessage(Request("sh", ["a"], new ScriptView("H", 1, Many(200) + "\n")));
        check(!whole.Contains("...cut", StringComparison.Ordinal) && whole.Contains(Marker + "line200", StringComparison.Ordinal), "cut: 200 lines are shown whole");
        string lines = ApprovalSummary.BuildMessage(Request("sh", ["a"], new ScriptView("H", 1, Many(250))));
        check(lines.Contains("...cut: showing 200 of 250 lines", StringComparison.Ordinal) && lines.Contains(Marker + "line200", StringComparison.Ordinal) && !lines.Contains("line201", StringComparison.Ordinal), "cut: past 200 lines the text says showing 200 of 250 lines");

        // Script bytes: 100 lines of 400 characters is 40 KB; only 16 KB shows.
        string wide = string.Join('\n', Enumerable.Range(0, 100).Select(_ => new string('w', 400)));
        string bytes = ApprovalSummary.BuildMessage(Request("sh", ["a"], new ScriptView("H", 40_000, wide)));
        string[] shown = Lines(bytes).Where(line => line.StartsWith(Marker, StringComparison.Ordinal)).ToArray();
        int size = shown.Sum(line => Encoding.UTF8.GetByteCount(line[Marker.Length..]) + 1);
        check(size <= ApprovalSummary.MaxScriptBytes && size > ApprovalSummary.MaxScriptBytes - 401 && bytes.Contains("...cut: showing ", StringComparison.Ordinal) && bytes.Contains(" of 100 lines", StringComparison.Ordinal), "cut: at most 16 KB of a script is shown with a notice (" + size + ")");

        // One enormous line (a minified file) is cut within the line.
        string minified = ApprovalSummary.BuildMessage(Request("sh", ["a"], new ScriptView("H", 30_000, new string('m', 30_000))));
        string[] one = Lines(minified).Where(line => line.StartsWith(Marker, StringComparison.Ordinal)).ToArray();
        check(one.Length == 1 && one[0].Length - Marker.Length == ApprovalSummary.MaxScriptBytes - 1 && minified.Contains("(last line cut)", StringComparison.Ordinal), "cut: a single huge line is cut at the byte limit and says so");
    }

    private static void Files(Action<bool, string> check)
    {
        string folder = Path.Combine(Path.GetTempPath(), "ws-summary-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            string text = Path.Combine(folder, "t.sh");
            byte[] utf8 = Encoding.UTF8.GetBytes("echo caf\u00e9\n");
            File.WriteAllBytes(text, utf8);
            ScriptView view = ScriptView.Read(text);
            check(view.Text == "echo caf\u00e9\n" && view.Length == utf8.Length && view.Sha256 == Convert.ToHexString(SHA256.HashData(utf8)), "file: UTF-8 text is read with its SHA-256 and size");

            File.WriteAllBytes(text, [0xEF, 0xBB, 0xBF, .. Encoding.ASCII.GetBytes("echo bom\n")]);
            check(ScriptView.Read(text).Text == "echo bom\n", "file: a UTF-8 BOM is not part of the text");

            string binary = Path.Combine(folder, "b.bin");
            File.WriteAllBytes(binary, [0x4D, 0x5A, 0x00, 0x01, 0x02]);
            ScriptView nul = ScriptView.Read(binary);
            check(nul.Text is null && nul.Length == 5, "file: a NUL byte means binary");
            string notice = ApprovalSummary.BuildMessage(Request("x", [], nul));
            check(Lines(notice).Contains("Script contents: binary file, 5 bytes (not shown)") && notice.Contains("Script SHA-256: " + nul.Sha256, StringComparison.Ordinal), "file: the binary notice names the size and the hash is still stated");

            File.WriteAllBytes(binary, [0x65, 0x63, 0x68, 0x6F, 0xFF, 0xFE, 0x41]);
            ScriptView latin = ScriptView.Read(binary);
            check(latin.Text is null && ApprovalSummary.BuildMessage(Request("x", [], latin)).Contains("binary file, 7 bytes (not shown)", StringComparison.Ordinal), "file: bytes that are not valid UTF-8 are treated as binary");

            File.WriteAllBytes(binary, Encoding.Unicode.GetBytes("echo utf16"));
            check(ScriptView.Read(binary).Text is null, "file: UTF-16 (it has NUL bytes) is shown as binary, not as garbled text");
        }
        finally
        {
            Directory.Delete(folder, true);
        }
    }

    private static async Task Runs(Action<bool, string> check)
    {
        string folder = Path.Combine(Path.GetTempPath(), "ws-summary-run-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        string audit = Path.Combine(folder, "audit.db");
        Dictionary<string, string> values = new() { ["DB_URL"] = "Summary-Secret-1234" };
        if (ProgramResolver.Resolve("sh", folder) is null)
        {
            // No sh on this machine: these runs need one, so they are skipped (not failed).
            Directory.Delete(folder, true);
            check(true, "runs: skipped, sh is not installed");

            return;
        }

        try
        {
            string script = Path.Combine(folder, "show.sh");
            string content = "echo start\nRequest id: forged\nAdmin key: forged\n";
            File.WriteAllText(script, content);
            FakeApprover deny = new(false);
            RunArgs run = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "show", "--", "sh", "./show.sh"], out _)!;
            int code = await new RunCommand(new MemoryStore(values), deny, new AuditLog(new StateDatabase(audit)), new StringWriter(), new StringWriter()).ExecuteAsync(run, folder);
            ApprovalRequest seen = deny.Requests.Single();
            string message = ApprovalSummary.BuildMessage(seen);
            check(code == RunCommand.Denied && seen.Script is { } view && view.Sha256 == Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(script))), "run: the request carries the script that will run, with its hash");
            check(message.Contains("Script SHA-256: ", StringComparison.Ordinal) && Lines(message).Contains(Marker + "echo start") && Lines(message).Count(line => line.StartsWith("Request id: ", StringComparison.Ordinal)) == 1, "run: the page text shows the script behind the marker, with no forged line");

            // The program itself, when it is a script.
            FakeApprover direct = new(false);
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(script, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                RunArgs self = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "self", "--", "./show.sh"], out _)!;
                await new RunCommand(new MemoryStore(values), direct, new AuditLog(new StateDatabase(audit)), new StringWriter(), new StringWriter()).ExecuteAsync(self, folder);
                check(direct.Requests.Single().Script is not null, "run: a script run directly is shown too");
            }

            // Inline code now gets a page that shows it.
            FakeApprover inline = new(false);
            RunArgs code1 = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "inline", "--", "sh", "-c", "echo $DB_URL"], out _)!;
            code = await new RunCommand(new MemoryStore(values), inline, new AuditLog(new StateDatabase(audit)), new StringWriter(), new StringWriter()).ExecuteAsync(code1, folder);
            check(code == RunCommand.Denied && inline.Requests.Count == 1 && ApprovalSummary.BuildMessage(inline.Requests[0]).Contains(Marker + "echo $DB_URL", StringComparison.Ordinal), "run: sh -c reaches the approval page with its code shown");
            foreach ((string program, string[] arguments) in new (string, string[])[] { ("cmd.exe", ["/d", "/c", "echo"]), ("pwsh", ["-NoProfile", "-Command", "x"]), ("bash", ["-c", "x"]) })
            {
                check(Policy.Check(program, arguments) is null, "run: " + program + " " + arguments[0] + " is no longer refused");
            }

            // An option value that names a data file before the real script: the page, the fingerprint and the lock use the real script.
            File.WriteAllText(Path.Combine(folder, "data"), "just a data file\n");
            File.WriteAllText(Path.Combine(folder, "real.sh"), "echo REAL_MARKER\n");
            FakeApprover optionApprover = new(false);
            RunArgs optionRun = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "x", "--", "sh", "real.sh", "data"], out _)!;
            await new RunCommand(new MemoryStore(values), optionApprover, new AuditLog(new StateDatabase(audit)), new StringWriter(), new StringWriter()).ExecuteAsync(optionRun, folder);
            ApprovalRequest optionSeen = optionApprover.Requests.Single();
            Fingerprint optionPrint = RequestFingerprint.Compute(optionSeen);
            check(optionSeen.Script is { } realView && realView.Path.EndsWith("real.sh", StringComparison.Ordinal) && !realView.Guessed && Lines(ApprovalSummary.BuildMessage(optionSeen)).Contains(Marker + "echo REAL_MARKER")
                && optionPrint.Files.Keys.Any(path => path.EndsWith("real.sh", StringComparison.Ordinal)) && !optionPrint.Files.Keys.Any(path => path.EndsWith("data", StringComparison.Ordinal) && !path.EndsWith("real.sh", StringComparison.Ordinal))
                && optionSeen.Arguments[1] == "data", "run: sh real.sh data shows, fingerprints and locks real.sh, not the data file");

            // An unreadable script is refused, not approved unseen.
            string locked = Path.Combine(folder, "locked.sh");
            File.WriteAllText(locked, "echo locked\n");
            FakeApprover unseen = new(true);
            StringWriter errors = new();
            RunArgs lockedRun = CliArgs.ParseRun(["--secrets", "DB_URL", "--reason", "locked", "--", "sh", "./locked.sh"], out _)!;
            bool blocked;
            if (OperatingSystem.IsWindows())
            {
                using FileStream hold = new(locked, FileMode.Open, FileAccess.Read, FileShare.None);
                code = await new RunCommand(new MemoryStore(values), unseen, new AuditLog(new StateDatabase(audit)), new StringWriter(), errors).ExecuteAsync(lockedRun, folder);
                blocked = true;
            }
            else
            {
                File.SetUnixFileMode(locked, UnixFileMode.None);
                blocked = !CanRead(locked);
                code = blocked ? await new RunCommand(new MemoryStore(values), unseen, new AuditLog(new StateDatabase(audit)), new StringWriter(), errors).ExecuteAsync(lockedRun, folder) : 0;
            }

            if (blocked)
            {
                check(code == RunCommand.Usage && unseen.Requests.Count == 0 && errors.ToString().Contains("Cannot read the script", StringComparison.Ordinal) && errors.ToString().Contains("Nothing was run", StringComparison.Ordinal), "run: an unreadable script is refused with a clear message and no prompt");
            }
        }
        finally
        {
            Directory.Delete(folder, true);
        }
    }

    private static bool CanRead(string path)
    {
        try
        {
            File.ReadAllBytes(path);

            return true;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}

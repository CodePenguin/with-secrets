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
        await Runs(check);
    }

    private static ApprovalRequest Request(string program, string[] arguments, ScriptView? script = null)
        => new(program, program, arguments, "/work", "reason", ["DB_URL"], RequestId: "ABC123", Script: script);

    private static string[] Lines(string message) => message.Split('\n');

    private static void Inline(Action<bool, string> check)
    {
        check(Policy.InlineCode("bash", ["-c", "echo $A"]) == "echo $A", "inline: bash -c code is the next argument");
        check(Policy.InlineCode("/bin/sh", ["-lc", "echo $A", "name"]) == "echo $A", "inline: sh -lc code is the next argument only");
        check(Policy.InlineCode("bash", ["script.sh"]) is null, "inline: a script is not inline code");
        check(Policy.InlineCode("cmd.exe", ["/d", "/c", "echo", "hi", "&", "dir"]) == "echo hi & dir", "inline: cmd /c code is the rest of the line");
        check(Policy.InlineCode("cmd", ["/K", "dir"]) == "dir", "inline: cmd /K code");
        check(Policy.InlineCode("pwsh", ["-NoProfile", "-Command", "Get-Date", "-Format", "o"]) == "Get-Date -Format o", "inline: pwsh -Command code is the rest of the line");
        check(Policy.InlineCode("pwsh", ["-c", "1+1"]) == "1+1" && Policy.InlineCode("powershell", ["-co", "1+1"]) == "1+1", "inline: -c and -co are -Command");
        check(Policy.InlineCode("pwsh", ["-NoProfile", "Get-Date"]) == "Get-Date", "inline: pwsh without a flag runs its arguments as a command");
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
            foreach ((string program, string[] arguments) in new (string, string[])[] { ("cmd.exe", ["/c", "echo"]), ("pwsh", ["-Command", "x"]), ("bash", ["-lc", "x"]) })
            {
                check(Policy.Check(program, arguments) is null, "run: " + program + " " + arguments[0] + " is no longer refused");
            }

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

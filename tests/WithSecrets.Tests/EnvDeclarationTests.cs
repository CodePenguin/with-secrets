using System.Net;
using System.Text;

namespace WithSecrets.Tests;

/// <summary>A secret source in memory that remembers what was asked: the names listed and every decrypt request.</summary>
internal sealed class RecordingSource(Dictionary<string, string> values, bool failList = false) : ISecretSource
{
    public string Label => SecretStore.GlobalLabel;

    public List<string[]> Requests { get; } = [];

    public IReadOnlyList<string> ListNames() => failList ? throw new SecretStoreException("the secret store failed verification (test)") : [.. values.Keys];

    public SecretValues GetValues(IReadOnlyCollection<string> names, Unlock? unlock)
    {
        Requests.Add([.. names]);

        return new SecretValues(names.ToDictionary(name => name, name => Encoding.UTF8.GetBytes(values[name]), StringComparer.Ordinal));
    }
}

/// <summary>Approves, but first changes the .env the way an agent could while the page is open.</summary>
internal sealed class EnvEditingApprover(string envPath, string newText) : IApprover
{
    public List<ApprovalRequest> Requests { get; } = [];

    public ApprovalDecision Request(ApprovalRequest request)
    {
        Requests.Add(request);
        File.WriteAllText(envPath, newText);

        return ApprovalDecision.Allow();
    }
}

/// <summary>
/// Project .env declarations: the parser, the composition rules, the secret:// grammar and the secret-name rule, the run (the
/// mapping, the page text, the trust rules), and --needs.
/// </summary>
internal static class EnvDeclarationTests
{
    private const string Token = "tok-Value-9912";
    private const string Ordinary = "Verbose7";

    public static async Task Run(Action<bool, string> check)
    {
        string folder = Path.Combine(Path.GetTempPath(), "ws-env-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            Names(check);
            Parser(check);
            Grammar(check);
            Composition(check, folder);
            CommandLineArgs(check);
            FixRound(check, folder);
            await Runs(check, folder);
            await Needs(check, folder);
            await WebApprovalTests.EnvHttp(check, folder);
        }
        finally
        {
            try
            {
                Directory.Delete(folder, true);
            }
            catch (IOException)
            {
            }
        }
    }

    private static string Fresh(string parent)
    {
        string path = Path.Combine(parent, "d" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(path);

        return path;
    }

    private static EnvResult Compose(string folder, string text, IEnumerable<string>? secrets = null, Dictionary<string, string>? environment = null, string fileName = ".env")
    {
        File.WriteAllText(Path.Combine(folder, fileName), text);

        return EnvDeclarations.Compose(null, folder, secrets ?? [], name => environment is not null && environment.TryGetValue(name, out string? value) ? value : null);
    }

    // --- the one secret-name rule
    private static void Names(Action<bool, string> check)
    {
        string[] good = ["A", "DB_URL", "team/STRIPE_KEY", "team/payments/STRIPE_KEY", "a.b-c_1/X", "user/X", "project/X", "a/b/c/NAME", "Team/X", new string('f', 64) + "/X"];
        foreach (string name in good)
        {
            check(SecretNames.IsValid(name), "name: accepted: " + name);
        }

        string[] bad = ["", "/A", "A/", "a//B", "../A", "./A", "a/../B", "a/./B", "a\\B", "a b/C", "a?/B", "a#/B", "a%2F/B", "a:/B", "team/stripe_key", "db_url", "DOTENV_X", "team/DOTENV_X",
            "a/b/c/d/NAME", new string('f', 65) + "/X", "A\n", "team/A\n", "a\0/B", "ü/X", new string('f', 64) + "/" + new string('g', 64) + "/" + new string('h', 64) + "/ABCDEFGHIJ", "1A", "_A"];
        foreach (string name in bad)
        {
            check(!SecretNames.IsValid(name), "name: refused: " + ApprovalSummary.Clean(name));
        }

        check(new string('f', 64) + "/" + new string('g', 64) + "/" + new string('h', 64) + "/ABCDE" is { Length: 200 } exact && SecretNames.IsValid(exact), "name: 200 characters is the longest");
        check(SecretNames.IsEnvName("DB_URL") && !SecretNames.IsEnvName("team/DB_URL"), "name: only a plain name can be an environment variable");
        check(CliArgs.Parse(["--set", "team/payments/STRIPE_KEY"], out _) is CliCommand.Set { Names: ["team/payments/STRIPE_KEY"] }, "name: --set takes a folder name");
        check(CliArgs.Parse(["--set", "team//KEY"], out string error) is null && error.Contains("folder", StringComparison.Ordinal), "name: --set refuses //");
        check(CliArgs.Parse(["--remove", "../KEY"], out _) is null, "name: --remove refuses ..");
        check(CliArgs.Parse(["--audit", "--secret", "team/KEY"], out _) is CliCommand.Audit { Secret: "team/KEY" }, "name: --audit --secret takes a folder name");
    }

    // --- the parser
    private static void Parser(Action<bool, string> check)
    {
        (IReadOnlyList<EnvDeclarations.Entry>? entries, string? error) = EnvDeclarations.Parse("f.env",
            "A=1\nexport B = two words # c\nC=\"x\\ny\\\"z\"\n# comment\n\nD='lit\\n'\r\nE=\"q\" # trailing\nF=  \nG=a#b\n  H=indented\nexport  I=2\nJ=\"a # not a comment\"\nK=${A}\nA=again\n");
        Dictionary<string, string> values = entries?.ToDictionary(entry => entry.Name, entry => entry.Value) ?? [];
        check(error is null && entries is not null, "parse: a mixed file parses (" + error + ")");
        check(values.GetValueOrDefault("A") == "again" && entries!.Count(entry => entry.Name == "A") == 1, "parse: a name repeated in one file: the last line wins");
        check(values.GetValueOrDefault("B") == "two words", "parse: export, spaces around =, inline comment");
        check(values.GetValueOrDefault("C") == "x\ny\"z", "parse: double quotes allow \\n and \\\"");
        check(values.GetValueOrDefault("D") == "lit\\n", "parse: single quotes are literal, CRLF is fine");
        check(values.GetValueOrDefault("E") == "q" && values.GetValueOrDefault("F") == "" && values.GetValueOrDefault("G") == "a#b", "parse: comment after a quote, empty value, # without space is data");
        check(values.GetValueOrDefault("H") == "indented" && values.GetValueOrDefault("I") == "2", "parse: indentation and export with two spaces");
        check(values.GetValueOrDefault("J") == "a # not a comment", "parse: # inside quotes is data");
        check(values.GetValueOrDefault("K") == "${A}", "parse: no expansion");
        check(entries!.Select(entry => entry.Name).SequenceEqual(["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K"]), "parse: order of first appearance");
        check(entries!.First(entry => entry.Name == "B").Line == 2, "parse: line numbers");

        (string Text, string Line)[] bad =
        [
            ("OK=1\n1BAD=s3cr3tvalue", "f.env:2:"), ("bad name=s3cr3tvalue", "f.env:1:"), ("NOEQUALS", "f.env:1:"), ("=s3cr3tvalue", "f.env:1:"), ("A=\"s3cr3tvalue", "f.env:1:"),
            ("A=\"s3cr3tvalue\" junk", "f.env:1:"), ("A='s3cr3tvalue' junk", "f.env:1:"), ("\n\nA-B=s3cr3tvalue", "f.env:3:"), ("A=\"s3cr3tvalue\\u0000\"\nB=\"x\0y\"", "f.env:2:"),
        ];
        foreach ((string text, string line) in bad)
        {
            (IReadOnlyList<EnvDeclarations.Entry>? none, string? message) = EnvDeclarations.Parse("f.env", text);
            check(none is null && message is not null && message.StartsWith(line, StringComparison.Ordinal) && !message.Contains("s3cr3tvalue", StringComparison.Ordinal), "parse: a bad line names file and line and never the value: " + ApprovalSummary.Clean(text).Replace('\n', '|') + " -> " + message);
        }
    }

    // --- secret://
    private static void Grammar(Action<bool, string> check)
    {
        (string Value, string Store)[] good =
        [
            ("secret://X_KEY", "X_KEY"), ("secret://team/X_KEY", "team/X_KEY"), ("secret://user/X_KEY", "user/X_KEY"), ("secret://project/X_KEY", "project/X_KEY"),
            ("secret://team/payments/STRIPE_KEY", "team/payments/STRIPE_KEY"), ("SECRET://X_KEY", "X_KEY"), ("secret://a.b-c/d_e/f/KEY", "a.b-c/d_e/f/KEY"),
        ];
        foreach ((string value, string store) in good)
        {
            check(EnvDeclarations.ParseReference(value, out _) == store, "grammar: accepted " + value);
        }

        string[] bad = ["secret://", "secret:///X", "secret://a//X", "secret://X?y=1", "secret://X#f", "secret://X Y", "secret://X%41", "secret://../X", "secret://./X", "secret://a/b/c/d/X", "secret://X/", "secret://x_lower",
            "secret://DOTENV_X", "secret://a\\X", " secret://X", "secret://X ", "secret://team/payments/stripe_key"];
        foreach (string value in bad)
        {
            check(EnvDeclarations.ParseReference(value, out string? problem) is null && problem is not null, "grammar: refused '" + value + "'");
        }
    }

    // --- composition
    private static void Composition(Action<bool, string> check, string parent)
    {
        string folder = Fresh(parent);
        EnvResult none = EnvDeclarations.Compose(null, folder, [], _ => null);
        check(none.Plan is { Files.Count: 0, Mappings.Count: 0, Ordinary.Count: 0 }, "compose: no default .env is no declarations, not an error");

        // first file wins; replaces the default list
        File.WriteAllText(Path.Combine(folder, "one.env"), "A=one\nT=secret://FIRST\n");
        File.WriteAllText(Path.Combine(folder, "two.env"), "A=two\nB=b\nT=plain\nU=secret://SECOND\n");
        File.WriteAllText(Path.Combine(folder, ".env"), "FROM_DEFAULT=1\n");
        EnvResult layered = EnvDeclarations.Compose(["one.env", "two.env"], folder, [], _ => null);
        check(layered.Plan is { } lp && lp.Ordinary["A"] == "one" && lp.Ordinary["B"] == "b" && !lp.Ordinary.ContainsKey("FROM_DEFAULT") && lp.Files.Count == 2, "compose: first file wins per name, -f replaces the default .env");
        check(layered.Plan!.Mappings.Select(pair => pair.Display).SequenceEqual(["T <- secret FIRST", "U <- secret SECOND"]), "compose: references from both files, the first file's T");
        EnvResult reversed = EnvDeclarations.Compose(["two.env", "one.env"], folder, [], _ => null);
        check(reversed.Plan is { } rp && rp.Ordinary["T"] == "plain" && rp.Ordinary["A"] == "two" && rp.Mappings.Select(pair => pair.Display).SequenceEqual(["U <- secret SECOND"]), "compose: an earlier ordinary value hides a later reference: the reference is not asked for");
        EnvResult missing = EnvDeclarations.Compose(["nope.env"], folder, [], _ => null);
        check(missing.Plan is null && missing.Error!.Contains("does not exist", StringComparison.Ordinal), "compose: a missing -f file is an error");
        EnvResult twice = EnvDeclarations.Compose(["one.env", Path.Combine(folder, "one.env")], folder, [], _ => null);
        check(twice.Plan is { Files.Count: 1 }, "compose: the same file twice is read once");

        // the OS variable beats an ordinary value; a reference beats the OS variable
        folder = Fresh(parent);
        Dictionary<string, string> os = new() { ["A"] = "from-os", ["T"] = "from-os" };
        EnvResult mixed = Compose(folder, "A=env\nT=secret://TOK\nB=env\n", environment: os);
        check(mixed.Plan is { } mp && !mp.Ordinary.ContainsKey("A") && mp.Ordinary["B"] == "env" && mp.Mappings.Select(pair => pair.Display).SequenceEqual(["T <- secret TOK"]), "compose: OS variable beats an ordinary .env value; a reference beats the OS variable");

        // --secrets plus references
        EnvResult union = Compose(folder, "B=secret://team/B_KEY\nC=secret://C\n", ["A"]);
        check(union.Plan is { } up && up.Mappings.Select(pair => pair.Display).SequenceEqual(["A", "B <- secret team/B_KEY", "C"]), "compose: --secrets and references are added together");
        check(Compose(folder, "A=secret://A\n", ["A"]).Plan is { Mappings.Count: 1 }, "compose: the same pair from --secrets and a reference is one pair");
        EnvResult conflict = Compose(folder, "A=secret://OTHER\n", ["A"]);
        check(conflict.Plan is null && conflict.Error!.Contains('A', StringComparison.Ordinal) && conflict.Error.Contains("different reference", StringComparison.Ordinal), "compose: the same variable from --secrets and from a different reference is an error");
        check(Compose(folder, "A=plain\nB=x\n", ["A"]).Plan is { } sp && !sp.Ordinary.ContainsKey("A") && sp.Mappings.Count == 1, "compose: --secrets beats an ordinary .env value of the same name");
        check(Compose(folder, "", ["team/KEY"]).Error!.Contains(".env", StringComparison.Ordinal), "compose: --secrets with a folder name is refused and points at the .env");

        // encrypted values
        EnvResult encrypted = Compose(folder, "X=encrypted:BDQ3s0m3\n");
        check(encrypted.Plan is null && encrypted.Error!.Contains("Dotenvx encrypted values in .env are not supported yet", StringComparison.Ordinal) && encrypted.Error.Contains('X', StringComparison.Ordinal) && !encrypted.Error.Contains("BDQ3s0m3", StringComparison.Ordinal), "compose: an effective encrypted value is an error, without the value");
        check(Compose(folder, "X=encrypted:BDQ3s0m3\n", environment: new() { ["X"] = "os" }).Plan is not null, "compose: an encrypted value hidden by an OS variable is ignored");
        check(Compose(folder, "X=encrypted:BDQ3s0m3\n", ["X"]).Plan is { Mappings.Count: 1 }, "compose: an encrypted value hidden by --secrets is ignored");
        File.WriteAllText(Path.Combine(folder, "first.env"), "X=plain\n");
        File.WriteAllText(Path.Combine(folder, "second.env"), "X=encrypted:BDQ3s0m3\nY=secret://Y\n");
        check(EnvDeclarations.Compose(["first.env", "second.env"], folder, [], _ => null).Plan is { } ep && ep.Ordinary["X"] == "plain", "compose: an encrypted value hidden by an earlier file is ignored");
        check(EnvDeclarations.Compose(["second.env", "first.env"], folder, [], _ => null).Plan is null, "compose: the same value first is an error");

        // bad references and bad lines name the variable or the line, never the value
        EnvResult badRef = Compose(folder, "TOKEN=secret://a b/HIDDENPART\n");
        check(badRef.Plan is null && badRef.Error!.Contains("TOKEN", StringComparison.Ordinal) && !badRef.Error.Contains("HIDDENPART", StringComparison.Ordinal), "compose: a bad reference names the variable, not the value");
        EnvResult badLine = Compose(folder, "TOKEN=ok\nbad line here\n");
        check(badLine.Plan is null && badLine.Error!.Contains(".env:2:", StringComparison.Ordinal), "compose: a bad line is an error with file and line");
        File.WriteAllText(Path.Combine(folder, "big.env"), "#" + new string('x', (int)EnvDeclarations.MaxFileBytes));
        check(EnvDeclarations.Compose(["big.env"], folder, [], _ => null).Error!.Contains("larger", StringComparison.Ordinal), "compose: a file over 256 KB is refused");
        File.WriteAllText(Path.Combine(folder, "edge.env"), "#" + new string('x', (int)EnvDeclarations.MaxFileBytes - 1));
        check(EnvDeclarations.Compose(["edge.env"], folder, [], _ => null).Plan is not null, "compose: a file of exactly 256 KB is read");
        File.WriteAllBytes(Path.Combine(folder, "latin.env"), [0x41, 0x3D, 0xFF, 0x0A]);
        check(EnvDeclarations.Compose(["latin.env"], folder, [], _ => null).Error is not null, "compose: a file that is not UTF-8 is an error");
        check(Compose(folder, string.Join('\n', Enumerable.Range(0, EnvDeclarations.MaxPairs + 1).Select(index => $"V{index}=secret://S{index}"))).Error!.Contains("at most", StringComparison.Ordinal), "compose: too many pairs are refused");

        // trust: a reference to a variable that changes which code runs is refused
        foreach (string variable in new[] { "NODE_OPTIONS", "BASH_ENV", "LD_PRELOAD", "PATH", "PATHEXT", "COMSPEC", "SystemRoot", "windir", "path", "DOTENV_PRIVATE_KEY_X", "BASH_FUNC_x%%" })
        {
            EnvResult refused = Compose(folder, $"{variable}=secret://TOK\n");
            check(variable.Contains('%', StringComparison.Ordinal) || refused.Plan is null && refused.Error!.Contains(variable, StringComparison.Ordinal), "compose: a reference to " + variable + " is refused");
        }

        // trust: a code-loading variable among the ordinary values is dropped, with a note that has the name only
        EnvResult dropped = Compose(folder, "NODE_OPTIONS=--require /evil/hook.js\nLOG=ok\nDOTENV_PRIVATE_KEY=abc123\n");
        check(dropped.Plan is { } dp && !dp.Ordinary.ContainsKey("NODE_OPTIONS") && !dp.Ordinary.ContainsKey("DOTENV_PRIVATE_KEY") && dp.Ordinary["LOG"] == "ok" && dp.Notes.Count == 2
            && dp.Notes.Any(note => note.Contains("NODE_OPTIONS", StringComparison.Ordinal)) && dp.Notes.All(note => !note.Contains("evil", StringComparison.Ordinal) && !note.Contains("abc123", StringComparison.Ordinal)), "compose: ordinary code-loading variables are dropped with a note naming only the variable");
    }

    // --- review fixes: limits, sinks, marks, page layout
    private static void FixRound(Action<bool, string> check, string parent)
    {
        string folder = Fresh(parent);
        string Lines(int count, Func<int, string> line) => string.Join('\n', Enumerable.Range(0, count).Select(line));

        // limits: over is an error, never cut
        check(Compose(folder, new string('A', EnvDeclarations.MaxVariableName) + "=x\n").Plan is not null && Compose(folder, new string('A', EnvDeclarations.MaxVariableName + 1) + "=x\n").Error!.Contains("longer than", StringComparison.Ordinal), "limits: a variable name of 64 is fine, 65 is an error");
        check(Compose(folder, "A=" + new string('v', EnvDeclarations.MaxValue) + "\n").Plan is not null && Compose(folder, "A=" + new string('v', EnvDeclarations.MaxValue + 1) + "\n").Error!.Contains("A", StringComparison.Ordinal), "limits: a value of 512 is fine, 513 is an error");
        check(Compose(folder, Lines(EnvDeclarations.MaxOrdinary, index => $"V{index}=x")).Plan is { Ordinary.Count: 50 } && Compose(folder, Lines(EnvDeclarations.MaxOrdinary + 1, index => $"V{index}=x")).Error!.Contains("at most", StringComparison.Ordinal), "limits: 50 ordinary variables are fine, 51 is an error");
        string[] files = [.. Enumerable.Range(0, 9).Select(index => $"f{index}.env")];
        foreach (string file in files)
        {
            File.WriteAllText(Path.Combine(folder, file), "X=1\n");
        }

        check(EnvDeclarations.Compose(files[..8], folder, [], _ => null).Plan is not null && EnvDeclarations.Compose(files, folder, [], _ => null).Error!.Contains("at most 8", StringComparison.Ordinal), "limits: 8 -f files are fine, 9 is an error");

        // sinks: a secret may not be steered into these
        foreach (string variable in new[] { "HTTP_PROXY", "https_proxy", "ALL_PROXY", "NO_PROXY", "FTP_PROXY", "MY_PROXY", "GIT_AUTHOR_NAME", "git_committer_email" })
        {
            check(Compose(folder, $"{variable}=secret://TOK\n").Plan is null, "sinks: a reference to " + variable + " is refused");
        }

        check(Compose(folder, "PROXY_HOST=secret://TOK\nGIT_TOKEN=secret://TOK\n").Plan is { Mappings.Count: 2 }, "sinks: other names are still allowed");

        // the stderr note says what it did and what it did not
        EnvResult dropped = Compose(folder, "NODE_OPTIONS=--require x\n");
        check(dropped.Plan is { Notes: [var note] } && note.Contains("left out of the program's environment", StringComparison.Ordinal) && note.Contains("may still load it", StringComparison.Ordinal) && !note.Contains("not passed", StringComparison.Ordinal), "note: a dropped variable is described exactly");

        // marks for env files outside the working directory and links
        string project = Fresh(parent);
        string elsewhere = Fresh(parent);
        File.WriteAllText(Path.Combine(elsewhere, "far.env"), "A=1\n");
        File.WriteAllText(Path.Combine(project, "near.env"), "A=1\n");
        EnvResult outside = EnvDeclarations.Compose([Path.Combine(elsewhere, "far.env")], project, [], _ => null);
        check(outside.Plan is { Links: [var mark] } && mark.Contains("outside the working directory", StringComparison.Ordinal) && mark.Contains("far.env", StringComparison.Ordinal), "marks: a -f file outside the working directory is marked");
        check(EnvDeclarations.Compose(["near.env"], project, [], _ => null).Plan is { Links: [] }, "marks: a file inside the working directory has no mark");
        try
        {
            File.CreateSymbolicLink(Path.Combine(project, "link.env"), Path.Combine(elsewhere, "far.env"));
            EnvResult linked = EnvDeclarations.Compose(["link.env"], project, [], _ => null);
            check(linked.Plan is { Links: [var linkMark] } && linkMark.Contains("link.env", StringComparison.Ordinal) && linkMark.Contains("far.env", StringComparison.Ordinal) && linkMark.Contains("a link", StringComparison.Ordinal), "marks: a symlinked .env shows where it leads");
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            check(true, "marks: symbolic links cannot be made here (skipped)");
        }

        // regular files only, size cap while reading
        Directory.CreateDirectory(Path.Combine(project, "dir.env"));
        check(EnvDeclarations.Compose(["dir.env"], project, [], _ => null).Error is not null, "read: a directory is not an env file");

        // the page: values shown and cleaned, marked like script lines; layout; the terminal stays names only
        ApprovalRequest request = new("prog", Path.Combine(project, "prog"), [], project, "reason", ["A_KEY"], Mappings: [new SecretMapping("A_KEY", "A_KEY"), new SecretMapping("DEPLOY", "prod/DEPLOY_KEY")],
            EnvFiles: [Path.Combine(project, "near.env")], EnvNames: ["EVIL", "PLAIN"], EnvValues: new Dictionary<string, string> { ["EVIL"] = "a\nPair: FAKE <- secret X‮b", ["PLAIN"] = "v1" });
        string text = ApprovalSummary.BuildMessage(request);
        string[] lines = text.Split('\n');
        check(lines.Contains("Pair: A_KEY") && lines.Contains("Pair: DEPLOY <- secret prod/DEPLOY_KEY (renamed)") && lines.Count(line => line.StartsWith("Pair: ", StringComparison.Ordinal)) == 2, "page: one pair per line, only the renamed one is marked");
        check(lines.Contains("  | PLAIN=v1") && lines.Contains("  | EVIL=a⏎Pair: FAKE <- secret X□b"), "page: ordinary values are shown with the script mark and cleaned of control and bidi characters");
        check(lines.Any(line => line.StartsWith("Run: ", StringComparison.Ordinal)) && Array.FindIndex(lines, line => line.StartsWith("Env file: ", StringComparison.Ordinal)) > Array.FindIndex(lines, line => line.StartsWith("Agent says:", StringComparison.Ordinal)), "page: the .env block is after the Run line");
        string terminal = ApprovalSummary.BuildMessage(request, showValues: false);
        check(!terminal.Contains("v1", StringComparison.Ordinal) && terminal.Contains("(names only): EVIL, PLAIN", StringComparison.Ordinal) && !terminal.Contains("FAKE", StringComparison.Ordinal), "page: the terminal echo has names only");
        check(!text.Contains("more", StringComparison.Ordinal) || !text.Contains("...and", StringComparison.Ordinal), "page: nothing is hidden behind 'and N more'");

        // two small hardening fixes
        check(Policy.Check("cmd.exe", ["/d", "/c", "echo", "a\n"]) is not null, "policy: a cmd word ending in a line break is refused");
        check(CliArgs.Parse(["--secrets", "a/b‮c", "--reason", "r", "--", "p"], out string message) is null && !message.Contains('‮', StringComparison.Ordinal), "cli: the echoed name is cleaned");
    }

    // --- the command line
    private static void CommandLineArgs(Action<bool, string> check)
    {
        check(CliArgs.Parse(["--needs"], out _) is CliCommand.Needs { EnvFiles.Count: 0 }, "cli: --needs");
        check(CliArgs.Parse(["--needs", "-f", "a.env", "--env-file", "b.env"], out _) is CliCommand.Needs { EnvFiles: ["a.env", "b.env"] }, "cli: --needs -f -f (repeatable)");
        check(CliArgs.Parse(["--needs", "--secrets", "A"], out _) is null && CliArgs.Parse(["--needs", "--reason", "x"], out _) is null && CliArgs.Parse(["--needs", "--", "p"], out _) is null, "cli: --needs is not a run");
        check(CliArgs.Parse(["--needs", "--list"], out _) is null && CliArgs.Parse(["--needs", "--set", "A"], out _) is null && CliArgs.Parse(["--needs", "--audit"], out _) is null, "cli: --needs excludes the other modes");
        check(CliArgs.Parse(["--needs", "--port", "5000"], out _) is null, "cli: --needs opens no page, so no --port");
        check(!CliArgs.NeedsTerminal(new CliCommand.Needs([])), "cli: --needs runs without a terminal");
        check(CliArgs.Parse(["-f", "a.env", "--list"], out string error) is null && error.Contains("--needs", StringComparison.Ordinal) && CliArgs.Parse(["-f", "a.env"], out _) is null && CliArgs.Parse(["--set", "A", "-f", "x"], out _) is null, "cli: -f goes only with a run or --needs");
        check(CliArgs.Parse(["--reason", "r", "-f", "a.env", "-f", "b.env", "--", "prog", "-f", "x"], out _) is CliCommand.Run { Args: { Secrets.Count: 0, EnvFiles: ["a.env", "b.env"], Arguments: ["-f", "x"] } }, "cli: a run with no --secrets and -f; -f after -- is the program's");
        check(CliArgs.Parse(["--reason", "r", "--", "prog"], out _) is CliCommand.Run { Args: { Secrets.Count: 0, EnvFiles: null } }, "cli: --secrets is optional on the command line (the .env may supply the names)");
        check(CliArgs.Parse(["--secrets", "A", "--", "prog"], out error) is null && error.Contains("--reason", StringComparison.Ordinal), "cli: --reason is still required");
        check(CliArgs.Parse(["--secrets", "team/A", "--reason", "r", "--", "prog"], out error) is null && error.Contains(".env", StringComparison.Ordinal) && error.Contains("secret://team/A", StringComparison.Ordinal), "cli: --secrets with a folder name is refused and points at the .env");
        check(CliArgs.Parse(["--help"], out _) is CliCommand.Help { Text: var help } && help.Contains("--needs", StringComparison.Ordinal) && help.Contains("--env-file", StringComparison.Ordinal) && help.Contains("secret://", StringComparison.Ordinal) && help.Contains("-f", StringComparison.Ordinal), "cli: help describes --needs, -f and secret://");
        check(CliArgs.Parse(["--list", "--", "p"], out _) is null, "cli: --list still takes no program");
    }

    // --- a run
    private static (string Folder, string Script, string EnvDump) Project(string parent, string? env)
    {
        string folder = Fresh(parent);
        string script = OperatingSystem.IsWindows() ? "show.cmd" : "show.sh";
        string path = Path.Combine(folder, script);
        if (OperatingSystem.IsWindows())
        {
            File.WriteAllText(path, "@echo off\r\nset > \"%~dp0env.txt\"\r\necho t=%TOKEN%\r\necho l=%LOG_LEVEL%\r\n");
        }
        else
        {
            File.WriteAllText(path, "#!/bin/sh\nenv > \"$(dirname \"$0\")/env.txt\"\necho \"t=$TOKEN\"\necho \"l=$LOG_LEVEL\"\n");
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        if (env is not null)
        {
            File.WriteAllText(Path.Combine(folder, ".env"), env);
        }

        return (folder, "./" + script, Path.Combine(folder, "env.txt"));
    }

    private sealed record RunResult(int Code, string Out, string Err, string Audit, string EnvDump);

    private static async Task<RunResult> Execute(string parent, string folder, string script, string envDump, ISecretSource source, IApprover approver, string[] secrets, string[]? envFiles = null, Dictionary<string, string>? os = null)
    {
        string audit = Path.Combine(Fresh(parent), "audit.db");
        StringWriter stdout = new();
        StringWriter stderr = new();
        RunArgs args = new(secrets, "env test", script, [], envFiles);
        int code = await new RunCommand(source, approver, new AuditLog(new StateDatabase(audit)), stdout, stderr, environment: name => os is not null && os.TryGetValue(name, out string? value) ? value : null).ExecuteAsync(args, folder);

        return new RunResult(code, stdout.ToString(), stderr.ToString(), File.Exists(audit) ? StateDatabaseTests.AuditText(audit) : "", File.Exists(envDump) ? File.ReadAllText(envDump) : "");
    }

    private static async Task Runs(Action<bool, string> check, string parent)
    {
        const string Stripe = "team/payments/STRIPE_KEY";

        // the mapping: the value reaches the program under the left-side name, redacted in the output; an ordinary value is passed on
        (string folder, string script, string dump) = Project(parent, $"TOKEN=secret://{Stripe}\nLOG_LEVEL={Ordinary}\nUNUSED=secret://OTHER_KEY # a comment\n");
        RecordingSource source = new(new() { [Stripe] = Token, ["OTHER_KEY"] = "other-Value-77" });
        FakeApprover approver = new(true);
        RunResult run = await Execute(parent, folder, script, dump, source, approver, []);
        check(run.Code == 0 && run.Out.Contains("t=[REDACTED]", StringComparison.Ordinal) && !run.Out.Contains(Token, StringComparison.Ordinal), "run: the secret reaches the program as TOKEN and its output is redacted (" + run.Code + " " + run.Err + ")");
        check(run.EnvDump.Contains("TOKEN=" + Token, StringComparison.Ordinal) && run.EnvDump.Contains("LOG_LEVEL=" + Ordinary, StringComparison.Ordinal) && run.Out.Contains("l=" + Ordinary, StringComparison.Ordinal), "run: the program has TOKEN and the ordinary LOG_LEVEL (not redacted)");
        check(!run.EnvDump.Contains(Stripe, StringComparison.Ordinal) || !run.EnvDump.Contains(Stripe + "=", StringComparison.Ordinal), "run: the secret is not also set under its store name");
        check(source.Requests.Count == 1 && source.Requests[0].Order().SequenceEqual(["OTHER_KEY", Stripe]), "run: both references are decrypted once, as store names");
        ApprovalRequest seen = approver.Requests[0];
        string text = ApprovalSummary.BuildMessage(seen);
        check(seen.Mappings!.Select(pair => pair.Display).SequenceEqual([$"TOKEN <- secret {Stripe}", "UNUSED <- secret OTHER_KEY"]) && text.Contains($"TOKEN <- secret {Stripe}", StringComparison.Ordinal) && text.Contains("UNUSED <- secret OTHER_KEY", StringComparison.Ordinal), "run: the page text shows every VARIABLE <- secret NAME pair");
        check(text.Contains("Env file: " + Path.Combine(folder, ".env"), StringComparison.Ordinal) && text.Contains("\n  | LOG_LEVEL=" + Ordinary, StringComparison.Ordinal) && !text.Contains(Token, StringComparison.Ordinal), "run: the page text shows the .env path and every ordinary variable with its value, marked like script lines");
        string terminal = ApprovalSummary.BuildMessage(seen, showValues: false);
        check(terminal.Contains("(names only): LOG_LEVEL", StringComparison.Ordinal) && !terminal.Contains(Ordinary, StringComparison.Ordinal) && !run.Err.Contains(Ordinary, StringComparison.Ordinal), "run: the terminal echo lists the ordinary names only");
        check(text.IndexOf("Env file:", StringComparison.Ordinal) > text.IndexOf("Run: ", StringComparison.Ordinal) && text.IndexOf("Pair: ", StringComparison.Ordinal) > text.IndexOf("Agent says:", StringComparison.Ordinal), "run: the .env block comes after the Run line");
        check(text.Split('\n').Where(line => line.StartsWith("Pair: ", StringComparison.Ordinal)).SequenceEqual([$"Pair: TOKEN <- secret {Stripe} (renamed)", "Pair: UNUSED <- secret OTHER_KEY (renamed)"]), "run: one pair per line, renamed pairs marked");
        check(RequestFingerprint.Compute(seen with { EnvValues = new Dictionary<string, string> { ["LOG_LEVEL"] = "other" } }).Key != RequestFingerprint.Compute(seen).Key, "run: an ordinary value is part of the fingerprint");
        check(!run.Out.Contains(Token, StringComparison.Ordinal) && !run.Err.Contains(Token, StringComparison.Ordinal) && !run.Audit.Contains(Token, StringComparison.Ordinal) && !run.Audit.Contains(Ordinary, StringComparison.Ordinal) && !text.Contains("other-Value-77", StringComparison.Ordinal), "run: values are in no stderr, audit or page text");
        check(run.Audit.Contains($"\"variable\":\"TOKEN\",\"secret\":\"{Stripe}\"", StringComparison.Ordinal) && run.Audit.Contains(".env", StringComparison.Ordinal) && run.Audit.Contains("LOG_LEVEL", StringComparison.Ordinal), "run: the audit row has the variable mapping, the file and the ordinary names");

        // a pair is part of the fingerprint
        string baseKey = RequestFingerprint.Compute(seen).Key;
        check(RequestFingerprint.Compute(seen with { Mappings = [new SecretMapping("OTHER", Stripe), seen.Mappings![1]] }).Key != baseKey, "run: another variable for the same secret is another fingerprint");
        check(RequestFingerprint.Compute(seen with { EnvFiles = [Path.Combine(folder, "x.env")] }).Key != baseKey, "run: another .env path is another fingerprint");
        check(RequestFingerprint.Compute(seen with { EnvNames = [] }).Key != baseKey, "run: another set of ordinary names is another fingerprint");

        // denied: no values read, nothing runs
        (folder, script, dump) = Project(parent, $"TOKEN=secret://{Stripe}\n");
        source = new(new() { [Stripe] = Token });
        run = await Execute(parent, folder, script, dump, source, new FakeApprover(false), []);
        check(run.Code == RunCommand.Denied && source.Requests.Count == 0 && run.EnvDump.Length == 0 && !run.Out.Contains(Token, StringComparison.Ordinal) && !run.Err.Contains(Token, StringComparison.Ordinal), "run: denied means no values are read and nothing runs");

        // an overridden reference is never asked for; only final ones reach the approver and the store
        (folder, script, dump) = Project(parent, null);
        File.WriteAllText(Path.Combine(folder, "a.env"), "TOKEN=plainvalue1\nLOG_LEVEL=secret://LOG_SECRET\n");
        File.WriteAllText(Path.Combine(folder, "b.env"), "TOKEN=secret://TOKEN_SECRET\nLOG_LEVEL=ignored\nOTHER=secret://OTHER_KEY\n");
        source = new(new() { ["TOKEN_SECRET"] = "token-secret-value", ["LOG_SECRET"] = "log-secret-value", ["OTHER_KEY"] = "other-key-value" });
        approver = new(true);
        run = await Execute(parent, folder, script, dump, source, approver, [], ["a.env", "b.env"]);
        check(run.Code == 0 && approver.Requests[0].SecretNames.SequenceEqual(["LOG_SECRET", "OTHER_KEY"]) && source.Requests.Count == 1 && source.Requests[0].Order().SequenceEqual(["LOG_SECRET", "OTHER_KEY"]), "run: only the final references reach the approver and the store (" + run.Err + ")");
        check(run.EnvDump.Contains("TOKEN=plainvalue1", StringComparison.Ordinal) && !run.EnvDump.Contains("token-secret-value", StringComparison.Ordinal), "run: the first file's ordinary TOKEN wins over the later reference");

        // trust: the OS variable beats an ordinary value but not a reference
        (folder, script, dump) = Project(parent, $"LOG_LEVEL=fromfile\nTOKEN=secret://TOKEN_SECRET\n");
        source = new(new() { ["TOKEN_SECRET"] = Token });
        run = await Execute(parent, folder, script, dump, source, new FakeApprover(true), [], null, new() { ["LOG_LEVEL"] = "fromos", ["TOKEN"] = "fromos" });
        check(run.Code == 0 && run.EnvDump.Contains("TOKEN=" + Token, StringComparison.Ordinal) && !run.EnvDump.Contains("LOG_LEVEL=fromfile", StringComparison.Ordinal), "run: a reference beats an OS variable; an OS variable beats an ordinary .env value");

        // trust: a code-loading variable among the ordinary values is dropped, with a note
        (folder, script, dump) = Project(parent, "NODE_OPTIONS=--require ./evil-hook.js\nPYTHONSTARTUP=/tmp/evil.py\nTOKEN=secret://TOKEN_SECRET\nLOG_LEVEL=ok1\n");
        run = await Execute(parent, folder, script, dump, source, new FakeApprover(true), []);
        string[] lines = run.EnvDump.Split('\n').Select(line => line.Trim()).ToArray();
        check(run.Code == 0 && !lines.Any(line => line.StartsWith("NODE_OPTIONS=", StringComparison.OrdinalIgnoreCase) || line.StartsWith("PYTHONSTARTUP=", StringComparison.OrdinalIgnoreCase)) && lines.Contains("LOG_LEVEL=ok1"), "trust run: code-loading variables from the .env do not reach the program");
        check(run.Err.Contains("NODE_OPTIONS", StringComparison.Ordinal) && run.Err.Contains("PYTHONSTARTUP", StringComparison.Ordinal) && !run.Err.Contains("evil", StringComparison.Ordinal), "trust run: a note on stderr names each dropped variable, not its value");

        // trust: a reference to a code-loading or PATH-like variable is refused before any prompt
        foreach (string variable in new[] { "NODE_OPTIONS", "PATH", "COMSPEC" })
        {
            (folder, script, dump) = Project(parent, $"{variable}=secret://TOKEN_SECRET\n");
            source = new(new() { ["TOKEN_SECRET"] = Token });
            approver = new(true);
            run = await Execute(parent, folder, script, dump, source, approver, []);
            check(run.Code == RunCommand.Usage && approver.Requests.Count == 0 && source.Requests.Count == 0 && run.EnvDump.Length == 0, "trust run: a reference to " + variable + " is refused with exit 2, no prompt, nothing decrypted");
        }

        // trust: the .env changes while the page is open: the pairs and the values stay as shown
        (folder, script, dump) = Project(parent, "TOKEN=secret://TOKEN_SECRET\nLOG_LEVEL=shown1\n");
        source = new(new() { ["TOKEN_SECRET"] = Token, ["EVIL_SECRET"] = "evil-secret-value" });
        EnvEditingApprover editing = new(Path.Combine(folder, ".env"), "TOKEN=secret://EVIL_SECRET\nLOG_LEVEL=changed\nNODE_OPTIONS=--require x\nEXTRA=secret://EVIL_SECRET\n");
        run = await Execute(parent, folder, script, dump, source, editing, []);
        check(run.Code == 0 && source.Requests.Count == 1 && source.Requests[0].SequenceEqual(["TOKEN_SECRET"]) && run.EnvDump.Contains("TOKEN=" + Token, StringComparison.Ordinal)
            && run.EnvDump.Contains("LOG_LEVEL=shown1", StringComparison.Ordinal) && !run.EnvDump.Contains("evil-secret-value", StringComparison.Ordinal) && !run.EnvDump.Contains("EXTRA=", StringComparison.Ordinal), "trust run: a .env changed while the page was open changes nothing (read once)");
        check(editing.Requests[0].Mappings!.Select(pair => pair.Display).SequenceEqual(["TOKEN <- secret TOKEN_SECRET"]) && !run.Audit.Contains("EVIL_SECRET", StringComparison.Ordinal), "trust run: the request and the audit keep the pairs that were shown");

        // errors before any prompt
        (folder, script, dump) = Project(parent, null);
        source = new(new() { ["A_KEY"] = "aaaa-value-1" });
        approver = new(true);
        run = await Execute(parent, folder, script, dump, source, approver, []);
        check(run.Code == RunCommand.Usage && run.Err.Contains("Name the secrets with --secrets NAME[,NAME...]. There is no option for all secrets.", StringComparison.Ordinal) && approver.Requests.Count == 0, "run: neither --secrets nor references gives today's error");
        run = await Execute(parent, folder, script, dump, source, approver, ["team/A_KEY"]);
        check(run.Code == RunCommand.Usage && run.Err.Contains("VARIABLE=secret://team/A_KEY", StringComparison.Ordinal) && approver.Requests.Count == 0, "run: --secrets with a folder name is refused");
        run = await Execute(parent, folder, script, dump, source, approver, [], ["missing.env"]);
        check(run.Code == RunCommand.Usage && approver.Requests.Count == 0, "run: a missing -f file is exit 2");
        File.WriteAllText(Path.Combine(folder, ".env"), "ENC=encrypted:BDQ3s0m3\nTOKEN=secret://A_KEY\n");
        run = await Execute(parent, folder, script, dump, source, approver, []);
        check(run.Code == RunCommand.Usage && run.Err.Contains("Dotenvx encrypted values in .env are not supported yet", StringComparison.Ordinal) && approver.Requests.Count == 0 && source.Requests.Count == 0, "run: an effective encrypted value is exit 2");
        File.WriteAllText(Path.Combine(folder, ".env"), "TOKEN=secret://NO_SUCH_KEY\n");
        run = await Execute(parent, folder, script, dump, source, approver, []);
        check(run.Code == RunCommand.Usage && run.Err.Contains("Unknown secret: NO_SUCH_KEY", StringComparison.Ordinal) && approver.Requests.Count == 0, "run: a reference to a name not in the store is exit 2");
        File.WriteAllText(Path.Combine(folder, ".env"), "TOKEN=secret://A_KEY\nbad line\n");
        run = await Execute(parent, folder, script, dump, source, approver, []);
        check(run.Code == RunCommand.Usage && run.Err.Contains(".env:2:", StringComparison.Ordinal) && approver.Requests.Count == 0, "run: a bad .env line is exit 2 with file and line");

        // --secrets still works alone, and with the .env together
        File.WriteAllText(Path.Combine(folder, ".env"), "LOG_LEVEL=viaenv\n");
        run = await Execute(parent, folder, script, dump, source, new FakeApprover(true), ["A_KEY"]);
        check(run.Code == 0 && run.EnvDump.Contains("A_KEY=aaaa-value-1", StringComparison.Ordinal) && run.EnvDump.Contains("LOG_LEVEL=viaenv", StringComparison.Ordinal), "run: --secrets and the ordinary .env together");
    }

    // --- --needs
    private static async Task Needs(Action<bool, string> check, string parent)
    {
        string folder = Fresh(parent);
        File.WriteAllText(Path.Combine(folder, ".env"), "LOG_LEVEL=Verbose7\nZED=1\nAPI=secret://team/API_KEY\nDB=secret://DB_URL\nNODE_OPTIONS=--require evil.js\nBAD=1\n");
        RecordingSource source = new(new() { ["team/API_KEY"] = "api-Value-1234", ["OTHER"] = "x-Value-9999" });
        StringWriter stdout = new();
        StringWriter stderr = new();
        int code = await Task.Run(() => NeedsCommand.Run(source, null, folder, stdout, stderr, _ => null));
        string output = stdout.ToString();
        string[] lines = output.Split('\n').Select(line => line.TrimEnd('\r')).ToArray();
        check(code == 0 && lines.Contains("Env file: " + Path.Combine(folder, ".env")), "needs: exit 0, the file used is listed");
        check(lines.Where(line => line.StartsWith("Variable: ", StringComparison.Ordinal)).SequenceEqual(["Variable: BAD", "Variable: LOG_LEVEL", "Variable: ZED"]), "needs: ordinary variable names, sorted");
        check(lines.Contains("Secret: API <- secret team/API_KEY  in store") && lines.Contains("Secret: DB <- secret DB_URL  NOT IN STORE"), "needs: each reference with in store or NOT IN STORE");
        check(source.Requests.Count == 0 && !output.Contains("Verbose7", StringComparison.Ordinal) && !output.Contains("api-Value-1234", StringComparison.Ordinal) && !output.Contains("evil", StringComparison.Ordinal) && !stderr.ToString().Contains("evil", StringComparison.Ordinal), "needs: nothing is decrypted, no value is printed");
        check(stderr.ToString().Contains("NODE_OPTIONS", StringComparison.Ordinal) && !output.Contains("NODE_OPTIONS", StringComparison.Ordinal), "needs: the dropped code-loading variable is noted on stderr, not listed");

        stdout = new();
        stderr = new();
        check(NeedsCommand.Run(source, null, Fresh(parent), stdout, stderr, _ => null) == 0 && stdout.ToString().Contains("none", StringComparison.Ordinal), "needs: no .env is exit 0 and says so");
        stdout = new();
        stderr = new();
        File.WriteAllText(Path.Combine(folder, "bad.env"), "TOKEN=\"s3cr3tvalue\" junk\n");
        check(NeedsCommand.Run(source, ["bad.env"], folder, stdout, stderr, _ => null) == RunCommand.Usage && stderr.ToString().Contains("bad.env:1:", StringComparison.Ordinal) && !stderr.ToString().Contains("s3cr3tvalue", StringComparison.Ordinal) && stdout.ToString().Length == 0, "needs: a parse error is exit 2 with file and line, no value");
        File.WriteAllText(Path.Combine(folder, "enc.env"), "X=encrypted:BDQ3s0m3\n");
        check(NeedsCommand.Run(source, ["enc.env"], folder, new StringWriter(), stderr = new StringWriter(), _ => null) == RunCommand.Usage && stderr.ToString().Contains("not supported yet", StringComparison.Ordinal), "needs: an effective encrypted value is exit 2");
        File.WriteAllText(Path.Combine(folder, "ref.env"), "NODE_OPTIONS=secret://X\n");
        check(NeedsCommand.Run(source, ["ref.env"], folder, new StringWriter(), new StringWriter(), _ => null) == RunCommand.Usage, "needs: a reference to a code-loading variable is exit 2");
        check(NeedsCommand.Run(source, ["missing.env"], folder, new StringWriter(), new StringWriter(), _ => null) == RunCommand.Usage, "needs: a missing -f file is exit 2");
        check(NeedsCommand.Run(new RecordingSource([], true), null, folder, new StringWriter(), stderr = new StringWriter(), _ => null) == RunCommand.StoreError && stderr.ToString().Contains("cannot read the secret store", StringComparison.Ordinal), "needs: a store that fails verification is exit 4");
        check(WebUtility.HtmlEncode("x") == "x", "needs: helper sanity");
    }
}

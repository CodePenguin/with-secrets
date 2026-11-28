using System.Net;
using System.Text;

namespace ArcanaGuardian.Tests;

/// <summary>A secret source in memory that remembers what was asked: the names listed and every decrypt request.</summary>
internal sealed class RecordingSource(Dictionary<string, string> values, bool failList = false) : ISecretSource
{
    public string Label => SecretStore.GlobalLabel;

    public List<string[]> Requests { get; } = [];

    public IReadOnlyList<string> ListNames() => failList ? throw new SecretStoreException("the secret store failed verification (test)") : [.. values.Keys];

    public SecretValues GetValues(IReadOnlyCollection<string> names)
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

        return TestSigner.Allow(request);
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
            CodeChangesTests.Run(check);
            Names(check);
            Parser(check);
            Grammar(check);
            Composition(check, folder);
            CommandLineArgs(check);
            FixRound(check, folder);
            await Runs(check, folder);
            await Needs(check, folder);
            await WebApprovalTests.EnvHttp(check, folder);
            await WebApprovalTests.EnvEncryptedHttp(check, folder);
            await Encrypted(check, folder);
            await ClientDotenvx(check, folder);
            await ReviewFixes(check, folder);
            EnvParserPinTests.Run(check, folder);
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
        string[] good = ["A", "DB_URL", "team/STRIPE_KEY", "team/payments/STRIPE_KEY", "a.b-c_1/X", "user/X", "project/X", "a/b/c/NAME", "Team/X", new string('f', 64) + "/X", "db_url", "team/stripe_key", "team/Payments/Stripe_Key", "MixedCase", "x", "DOTENV_PRIVATE_KEY", "DOTENV_PRIVATE_KEY_PRODUCTION", "team/DOTENV_PRIVATE_KEY"];
        foreach (string name in good)
        {
            check(SecretNames.IsValid(name), "name: accepted: " + name);
        }

        string[] bad = ["", "/A", "A/", "a//B", "../A", "./A", "a/../B", "a/./B", "a\\B", "a b/C", "a?/B", "a#/B", "a%2F/B", "a:/B", "DOTENV_X", "team/DOTENV_X", "dotenv_x", "DOTENV_PUBLIC_KEY", "Dotenv_private_key",
            "a/b/c/d/NAME", new string('f', 65) + "/X", "A\n", "team/A\n", "a\0/B", "ü/X", new string('f', 64) + "/" + new string('g', 64) + "/" + new string('h', 64) + "/ABCDEFGHIJ", "1A", "_A"];
        foreach (string name in bad)
        {
            check(!SecretNames.IsValid(name), "name: refused: " + ApprovalSummary.Clean(name));
        }

        check(new string('f', 64) + "/" + new string('g', 64) + "/" + new string('h', 64) + "/ABCDE" is { Length: 200 } exact && SecretNames.IsValid(exact), "name: 200 characters is the longest");
        check(!SecretNames.IsValid(new string('f', 64) + "/" + new string('g', 64) + "/" + new string('h', 64) + "/ABCDEx"), "name: 201 characters is refused (the length rule is unchanged)");

        // names are case-sensitive; a case-only difference of the whole path is found, an identical or different name is not
        check(SecretNames.CaseTwins("Team/Stripe_Key", ["team/STRIPE_KEY", "TEAM/stripe_key", "Team/Stripe_Key", "team/OTHER"]).SequenceEqual(["TEAM/stripe_key", "team/STRIPE_KEY"]), "name: case twins are the other names equal when case is ignored");
        check(SecretNames.CaseTwins("A", ["A"]).Count == 0 && SecretNames.CaseTwins("A", ["B", "AA"]).Count == 0, "name: the same name or a different one is no case twin");
        check(SecretNames.IsEnvName("DB_URL") && !SecretNames.IsEnvName("team/DB_URL"), "name: only a plain name can be an environment variable");
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
            ("secret://x_lower", "x_lower"), ("secret://team/payments/stripe_key", "team/payments/stripe_key"), ("secret://Team/Mixed_Case", "Team/Mixed_Case"),
        ];
        foreach ((string value, string store) in good)
        {
            check(EnvDeclarations.ParseReference(value, out _) == store, "grammar: accepted " + value);
        }

        string[] bad = ["secret://", "secret:///X", "secret://a//X", "secret://X?y=1", "secret://X#f", "secret://X Y", "secret://X%41", "secret://../X", "secret://./X", "secret://a/b/c/d/X", "secret://X/",
            "secret://DOTENV_X", "secret://a\\X", " secret://X", "secret://X ", "secret://dotenv_x"];
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

        // encrypted values: the effective one is listed with its key secret (nothing decrypted here); an overridden one is ignored
        EnvResult encrypted = Compose(folder, "X=encrypted:BDQ3s0m3\nY=plain\n");
        check(encrypted.Plan is { } xp && xp.Encrypted is [{ Variable: "X", PublicKey: "" } ev] && ev.File.EndsWith(".env", StringComparison.Ordinal) && xp.Mappings.Count == 0 && !xp.Ordinary.ContainsKey("X") && xp.Ordinary["Y"] == "plain", "compose: an effective encrypted value is planned with the key secret DOTENV_PRIVATE_KEY, not as an ordinary value");
        check(encrypted.Plan!.Encrypted![0].ToString() == "encrypted X (" + encrypted.Plan.Encrypted[0].File + ")", "compose: an encrypted value prints names only");
        check(Compose(folder, "X=encrypted:BDQ3s0m3\n", environment: new() { ["X"] = "os" }).Plan is { Encrypted.Count: 0 }, "compose: an encrypted value hidden by an OS variable is ignored, its key is not needed");
        check(Compose(folder, "X=encrypted:BDQ3s0m3\n", ["X"]).Plan is { Mappings.Count: 1, Encrypted.Count: 0 }, "compose: an encrypted value hidden by --secrets is ignored");
        File.WriteAllText(Path.Combine(folder, "first.env"), "X=plain\n");
        File.WriteAllText(Path.Combine(folder, "second.env"), "X=encrypted:BDQ3s0m3\nY=secret://Y\n");
        check(EnvDeclarations.Compose(["first.env", "second.env"], folder, [], _ => null).Plan is { } ep && ep.Ordinary["X"] == "plain" && ep.Encrypted!.Count == 0, "compose: an encrypted value hidden by an earlier file is ignored");
        check(EnvDeclarations.Compose(["second.env", "first.env"], folder, [], _ => null).Plan is { Encrypted: [{ Variable: "X" }] }, "compose: the same value first is planned");
        check(Compose(folder, "X=encrypted:BDQ3s0m3\nX2=encrypted:BDQ3s0m4\nY=secret://K\n").Plan is { Encrypted.Count: 2 }, "compose: more than one encrypted value");
        check(Compose(folder, "X=encrypted:" + new string('A', EnvDeclarations.MaxEncrypted)).Error!.Contains("longer than", StringComparison.Ordinal), "compose: an over-long encrypted value is an error");

        File.WriteAllText(Path.Combine(folder, ".env.staging"), $"DOTENV_PUBLIC_KEY_STAGING={FakeDotenvx.PublicKey}\nS=encrypted:BDQ3s0m3\n");
        check(EnvDeclarations.Compose([".env.staging"], folder, [], _ => null).Plan?.Encrypted?.Single().PublicKey == FakeDotenvx.PublicKey,
            "compose: encrypted values carry the public metadata from their source file");
        check(Compose(folder, "DOTENV_PUBLIC_KEY=bad\nX=encrypted:BDQ3s0m3\n").Plan is null,
            "compose: malformed public metadata is refused");

        check(Compose(folder, "A=secret://DOTENV_PRIVATE_KEY_PRODUCTION\n").Error!.Contains("private key", StringComparison.Ordinal) && Compose(folder, "A=secret://team/DOTENV_PRIVATE_KEY\n").Plan is null, "compose: a reference to a Dotenvx private key secret is refused");

        // bad references and bad lines name the variable or the line, never the value
        EnvResult badRef = Compose(folder, "TOKEN=secret://a b/HIDDENPART\n");
        check(badRef.Plan is null && badRef.Error!.Contains("TOKEN", StringComparison.Ordinal) && !badRef.Error.Contains("HIDDENPART", StringComparison.Ordinal), "compose: a bad reference names the variable, not the value");
        EnvResult badLine = Compose(folder, "TOKEN=ok\nbad line here\n");
        check(badLine.Plan is null && badLine.Error!.Contains(".env:2:", StringComparison.Ordinal), "compose: a bad line is an error with file and line");
        File.WriteAllText(Path.Combine(folder, "big.env"), "#" + new string('x', (int)EnvDeclarations.MaxFileBytes));
        check(EnvDeclarations.Compose(["big.env"], folder, [], _ => null).Error!.Contains("larger than 1024 KB", StringComparison.Ordinal) && EnvDeclarations.MaxFileBytes == 1024 * 1024, "compose: a file over 1 MB is refused");
        File.WriteAllText(Path.Combine(folder, "edge.env"), "#" + new string('x', (int)EnvDeclarations.MaxFileBytes - 1));
        check(EnvDeclarations.Compose(["edge.env"], folder, [], _ => null).Plan is not null, "compose: a file of exactly 1 MB is read");
        File.WriteAllBytes(Path.Combine(folder, "latin.env"), [0x41, 0x3D, 0xFF, 0x0A]);
        check(EnvDeclarations.Compose(["latin.env"], folder, [], _ => null).Error is not null, "compose: a file that is not UTF-8 is an error");
        check(EnvDeclarations.MaxPairs == 200 && Compose(folder, string.Join('\n', Enumerable.Range(0, EnvDeclarations.MaxPairs).Select(index => $"V{index}=secret://S{index}"))).Plan is { Mappings.Count: 200 }, "compose: 200 pairs are accepted");
        check(Compose(folder, string.Join('\n', Enumerable.Range(0, EnvDeclarations.MaxPairs + 1).Select(index => $"V{index}=secret://S{index}"))).Error!.Contains("at most 200", StringComparison.Ordinal), "compose: 201 pairs are refused");

        // trust: a reference to a variable that changes which code runs is refused
        foreach (string variable in new[] { "NODE_OPTIONS", "BASH_ENV", "LD_PRELOAD", "PATH", "PATHEXT", "COMSPEC", "SystemRoot", "windir", "path", "DOTENV_PRIVATE_KEY_X", "BASH_FUNC_x%%" })
        {
            EnvResult refused = Compose(folder, $"{variable}=secret://TOK\n");
            check(variable.Contains('%', StringComparison.Ordinal) || refused.Plan is null && refused.Error!.Contains(variable, StringComparison.Ordinal), "compose: a reference to " + variable + " is refused");
        }

        // an ordinary value that is on the code-loading list is passed on like any other (the page shows it); only a Dotenvx private key is left out, with a note of the name
        EnvResult passed = Compose(folder, "NODE_OPTIONS=--require /evil/hook.js\nLOG=ok\nDOTENV_PRIVATE_KEY=abc123\n");
        check(passed.Plan is { } dp && dp.Ordinary["NODE_OPTIONS"] == "--require /evil/hook.js" && dp.Ordinary["LOG"] == "ok" && !dp.Ordinary.ContainsKey("DOTENV_PRIVATE_KEY") && dp.Encrypted!.Count == 0, "compose: an ordinary code-loading value is passed through; a Dotenvx private key value is not");
        check(passed.Plan!.Notes.Count == 1 && passed.Plan.Notes[0].Contains("DOTENV_PRIVATE_KEY", StringComparison.Ordinal) && !passed.Plan.Notes[0].Contains("abc123", StringComparison.Ordinal) && !passed.Plan.Notes.Any(note => note.Contains("code-loading", StringComparison.Ordinal)), "compose: the only note names the private key variable, not its value, and there is no code-loading note");
    }

    // --- review fixes: limits, sinks, marks, page layout
    private static void FixRound(Action<bool, string> check, string parent)
    {
        string folder = Fresh(parent);
        string Lines(int count, Func<int, string> line) => string.Join('\n', Enumerable.Range(0, count).Select(line));

        // limits: over is an error, never cut
        check(Compose(folder, new string('A', EnvDeclarations.MaxVariableName) + "=x\n").Plan is not null && Compose(folder, new string('A', EnvDeclarations.MaxVariableName + 1) + "=x\n").Error!.Contains("longer than", StringComparison.Ordinal), "limits: a variable name of 128 is fine, 129 is an error");
        check(Compose(folder, "A=" + new string('v', EnvDeclarations.MaxValue) + "\n").Plan is not null && Compose(folder, "A=" + new string('v', EnvDeclarations.MaxValue + 1) + "\n").Error!.Contains("A", StringComparison.Ordinal), "limits: a value of 4096 is fine, 4097 is an error");
        check(Compose(folder, Lines(EnvDeclarations.MaxOrdinary, index => $"V{index}=x")).Plan is { Ordinary.Count: 200 } && Compose(folder, Lines(EnvDeclarations.MaxOrdinary + 1, index => $"V{index}=x")).Error!.Contains("at most", StringComparison.Ordinal), "limits: 200 ordinary variables are fine, 201 is an error");
        string[] files = [.. Enumerable.Range(0, 17).Select(index => $"f{index}.env")];
        foreach (string file in files)
        {
            File.WriteAllText(Path.Combine(folder, file), "X=1\n");
        }

        check(EnvDeclarations.Compose(files[..16], folder, [], _ => null).Plan is not null && EnvDeclarations.Compose(files, folder, [], _ => null).Error!.Contains("at most 16", StringComparison.Ordinal), "limits: 16 -f files are fine, 17 is an error");
        check(EnvDeclarations.MaxFiles == 16 && EnvDeclarations.MaxOrdinary == 200 && EnvDeclarations.MaxPairs == 200 && EnvDeclarations.MaxVariableName == 128 && EnvDeclarations.MaxValue == 4096 && EnvDeclarations.MaxFileBytes == 1024 * 1024, "limits: the raised values are 1 MB, 16 files, 200 pairs, 200 variables, 128-character names, 4096-character values");
        check(Compose(folder, Lines(EnvDeclarations.MaxOrdinary, index => $"V{index}=encrypted:BDQ3s0m3")).Plan is { Encrypted.Count: 200 } && Compose(folder, Lines(EnvDeclarations.MaxOrdinary, index => $"V{index}=x") + "\nEXTRA=encrypted:BDQ3s0m3").Error!.Contains("at most 200", StringComparison.Ordinal), "limits: encrypted values count with the ordinary variables");

        // sinks: a secret may not be steered into these
        foreach (string variable in new[] { "HTTP_PROXY", "https_proxy", "ALL_PROXY", "NO_PROXY", "FTP_PROXY", "MY_PROXY", "GIT_AUTHOR_NAME", "git_committer_email" })
        {
            check(Compose(folder, $"{variable}=secret://TOK\n").Plan is null, "sinks: a reference to " + variable + " is refused");
        }

        check(Compose(folder, "PROXY_HOST=secret://TOK\nGIT_TOKEN=secret://TOK\n").Plan is { Mappings.Count: 2 }, "sinks: other names are still allowed");

        // the stderr note says what it did and what it did not
        EnvResult dropped = Compose(folder, "DOTENV_PRIVATE_KEY_X=abc12345\n");
        check(dropped.Plan is { Notes: [var note] } && note.Contains("left out of the program's environment", StringComparison.Ordinal) && note.Contains("DOTENV_PRIVATE_KEY_X", StringComparison.Ordinal) && !note.Contains("abc12345", StringComparison.Ordinal), "note: a dropped private key variable is described by name only");

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

        // credentials: the page and the review show names, and hide a value that looks like one (a short heuristic, on purpose)
        foreach (string name in new[] { "DB_PASSWORD", "db_passwd", "ApiToken", "MY_SECRET", "STRIPE_API_KEY", "STRIPE_APIKEY", "SSH_PRIVATE_KEY", "AUTH_HEADER", "service_credential", "dbPassword", "authToken", "DB_PASS", "GITHUB_TOKEN", "Authorization" })
        {
            check(CredentialHeuristics.NameLooksLikeCredential(name), "credentials: " + name + " looks like a credential name");
        }

        foreach (string name in new[] { "LOG_LEVEL", "AUTHOR_NAME", "PWD", "PATH", "HOME", "PASSAGE", "KEYBOARD", "NODE_OPTIONS", "HTTPS_PROXY" })
        {
            check(!CredentialHeuristics.NameLooksLikeCredential(name), "credentials: " + name + " is an ordinary name");
        }

        const string Plain = "hunter2-Plaintext";
        string shapedToken = "ghp_" + new string('a', 36);
        Dictionary<string, string> envValues = new()
        {
            ["LOG_LEVEL"] = "debug",
            ["AUTHOR_NAME"] = "Ada",
            ["PWD"] = "/home/ada",
            ["DB_PASSWORD"] = Plain,
            ["db_passwd"] = Plain,
            ["dbPassword"] = Plain,
            ["EMPTY_PASSWORD"] = "",
            ["DATABASE_URL"] = "postgres://app:" + Plain + "@db.example.com:5432/app",
            ["CONN"] = "Server=db;User Id=app;Password=" + Plain + ";Encrypt=true",
            ["HEADER_VALUE"] = "Bearer abcdefgh12345678",
            ["NOTE"] = shapedToken,
            ["HTTPS_PROXY"] = "http://user:" + Plain + "@proxy.example.com:8080",
            ["NODE_OPTIONS"] = "--require ./hook.js",
        };
        ApprovalRequest credentialRequest = new("prog", Path.Combine(project, "prog"), [], project, "reason", ["A_KEY"], Mappings: [new SecretMapping("A_KEY", "A_KEY")], EnvNames: [.. envValues.Keys], EnvValues: envValues);
        string credentialText = ApprovalSummary.BuildMessage(credentialRequest);
        string[] credentialLines = credentialText.Split('\n');
        check(credentialLines.Contains("  | LOG_LEVEL=debug") && credentialLines.Contains("  | AUTHOR_NAME=Ada") && credentialLines.Contains("  | PWD=/home/ada"), "credentials: ordinary values stay visible");
        check(credentialLines.Contains("  | DB_PASSWORD=[hidden]") && credentialLines.Contains("  | db_passwd=[hidden]") && credentialLines.Contains("  | dbPassword=[hidden]"), "credentials: a credential name hides its value, in any case");
        check(credentialLines.Contains("  | EMPTY_PASSWORD="), "credentials: an empty value has nothing to hide");
        check(credentialLines.Contains("  | DATABASE_URL=postgres://app:[hidden]@db.example.com:5432/app") && credentialLines.Contains("  | CONN=Server=db;User Id=app;Password=[hidden];Encrypt=true") && credentialLines.Contains("  | HEADER_VALUE=Bearer [hidden]"), "credentials: a password in a URL, a connection string or an Authorization value is hidden and the rest stays");
        check(credentialLines.Contains("  | NOTE=[hidden]"), "credentials: a value with the look of a known token is hidden whatever its name");
        check(credentialLines.Contains("  | HTTPS_PROXY=http://user:[hidden]@proxy.example.com:8080") && credentialLines.Contains("  | NODE_OPTIONS=--require ./hook.js"), "credentials: the warning block hides the credential part only: the address and the code the program loads stay visible");
        check(!credentialText.Contains(Plain, StringComparison.Ordinal) && !credentialText.Contains(shapedToken, StringComparison.Ordinal) && !credentialText.Contains("abcdefgh12345678", StringComparison.Ordinal), "credentials: no plaintext credential is anywhere in the page text");
        ApprovalReviewProjection review = ApprovalQueue.BuildReview("launch-1", new string('A', 64), DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddMinutes(5), new ApprovalMachineView(new string('B', 64), null, "host"), credentialRequest);
        string reviewJson = System.Text.Json.JsonSerializer.Serialize(review);
        check(!reviewJson.Contains(Plain, StringComparison.Ordinal) && !reviewJson.Contains(shapedToken, StringComparison.Ordinal) && !reviewJson.Contains("abcdefgh12345678", StringComparison.Ordinal), "credentials: the review the browser receives has no plaintext credential in any field, the signed text included");
        check(review.ShownEnvValues.Any(item => item is { Name: "LOG_LEVEL", Value: "debug" }) && review.ShownEnvValues.Any(item => item is { Name: "DB_PASSWORD", Value: CredentialHeuristics.Hidden }), "credentials: the review lists ordinary values and the hidden ones by name");
        check(review.CodeChangeWarnings.Any(item => item.Name == "NODE_OPTIONS" && item.Value == "--require ./hook.js") && review.CodeChangeWarnings.Any(item => item.Name == "HTTPS_PROXY" && item.Value == "http://user:[hidden]@proxy.example.com:8080"), "credentials: the code-change warnings of the review go through the same hiding");
        check(RequestFingerprint.Compute(credentialRequest).Key != RequestFingerprint.Compute(credentialRequest with { EnvValues = new Dictionary<string, string>(envValues) { ["DB_PASSWORD"] = "another" } }).Key, "credentials: the approval still covers the real value, hidden or not");

        // plaintext .env credentials: a warning with names and files, no value, and no change to what is approved or run
        string warningLine = credentialLines.Single(line => line.StartsWith("Warning: plaintext credentials in .env: ", StringComparison.Ordinal));
        check(warningLine.Contains("DB_PASSWORD") && warningLine.Contains("DATABASE_URL") && warningLine.Contains("CONN") && warningLine.Contains("NOTE") && warningLine.Contains("HEADER_VALUE") && !warningLine.Contains("LOG_LEVEL") && !warningLine.Contains("PWD") && !warningLine.Contains("NODE_OPTIONS"), "plaintext warning: lists the credential-looking names and not the ordinary ones");
        check(!warningLine.Contains(Plain, StringComparison.Ordinal) && !warningLine.Contains("abcdefgh12345678", StringComparison.Ordinal) && !warningLine.Contains(shapedToken, StringComparison.Ordinal), "plaintext warning: never repeats a value");
        ApprovalRequest withFile = credentialRequest with { EnvFiles = [Path.Combine(project, "app.env")] };
        check(ApprovalSummary.BuildMessage(withFile).Contains("(in " + Path.Combine(project, "app.env") + ")", StringComparison.Ordinal), "plaintext warning: names the file it is in");
        ApprovalRequest cleanRequest = new("prog", Path.Combine(project, "prog"), [], project, "reason", ["A_KEY"], Mappings: [new SecretMapping("A_KEY", "A_KEY")], EnvNames: ["LOG_LEVEL"], EnvValues: new Dictionary<string, string> { ["LOG_LEVEL"] = "debug" });
        check(!ApprovalSummary.BuildMessage(cleanRequest).Contains("plaintext credentials", StringComparison.Ordinal), "plaintext warning: none when nothing looks like a credential");
        ApprovalRequest namesOnly = credentialRequest with { EnvValues = null };
        string echo = ApprovalSummary.BuildMessage(namesOnly, showValues: false);
        check(echo.Contains("Warning: plaintext credentials in .env: ", StringComparison.Ordinal) && echo.Contains("DB_PASSWORD"), "plaintext warning: the terminal echo, with names only, warns by name");
        check(RequestFingerprint.Compute(credentialRequest).Key == RequestFingerprint.Compute(credentialRequest with { ExtraLines = null }).Key, "plaintext warning: it is display only and not part of the fingerprint");

        // a credential written into the command or the script: a warning of the kind and the place, never the credential, no rewrite
        const string InlineCanary = "InlineCanary-9x7";
        ApprovalRequest Inline(string[] arguments, string? scriptText = null) => new("sh", Path.Combine(project, "sh"), arguments, project, "reason", ["A_KEY"], Mappings: [new SecretMapping("A_KEY", "A_KEY")], Script: scriptText is null ? null : ScriptView.FromBytes(System.Text.Encoding.UTF8.GetBytes(scriptText), Path.Combine(project, "run.sh")));
        string pg = ApprovalSummary.BuildMessage(Inline(["-c", "PGPASSWORD=" + InlineCanary + " psql -h db"]));
        string pgWarning = pg.Split('\n').Single(line => line.StartsWith("Warning: a credential is written in ", StringComparison.Ordinal));
        check(pgWarning.Contains("PGPASSWORD=") && pgWarning.Contains("the command line") && !pgWarning.Contains(InlineCanary, StringComparison.Ordinal), "inline credential: PGPASSWORD=value in the command warns by kind and place and does not repeat the value");
        check(pg.Contains("PGPASSWORD=" + InlineCanary, StringComparison.Ordinal), "inline credential: the command is shown as it is, not rewritten");
        string ssh = ApprovalSummary.BuildMessage(Inline(["-c", "sshpass -p " + InlineCanary + " ssh host"]));
        check(ssh.Contains("(sshpass -p)", StringComparison.Ordinal), "inline credential: sshpass -p value warns");
        string bearer = ApprovalSummary.BuildMessage(Inline(["-c", "curl -H 'Authorization: Bearer " + InlineCanary + "' https://x"]));
        check(bearer.Contains("Authorization: Bearer/Basic", StringComparison.Ordinal) && !bearer.Split('\n').Single(line => line.StartsWith("Warning: a credential", StringComparison.Ordinal)).Contains(InlineCanary, StringComparison.Ordinal), "inline credential: an Authorization: Bearer value warns and is not repeated");
        string inScript = ApprovalSummary.BuildMessage(Inline(["run.sh"], "#!/bin/sh\nexport API_TOKEN=" + InlineCanary + "\ncurl https://x\n"));
        check(inScript.Contains("the script") && inScript.Contains("API_TOKEN="), "inline credential: a credential written in the script warns, naming the script");
        check(!ApprovalSummary.BuildMessage(Inline(["-c", "PGPASSWORD=$PGPASSWORD psql"], "echo ${API_TOKEN}\nTOKEN=secret://TOKEN\nTOKEN=\n")).Contains("Warning: a credential is written", StringComparison.Ordinal), "inline credential: a reference ($VAR, secret://NAME) or an empty value is not a credential written in");
        check(!ApprovalSummary.BuildMessage(Inline(["build", "--verbose"])).Contains("Warning: a credential is written", StringComparison.Ordinal), "inline credential: no warning for an ordinary command");

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
        check(CliArgs.Parse(["--needs", "--list"], out _) is null && CliArgs.Parse(["--needs", "--set", "A"], out _) is null, "cli: --needs excludes the other modes");
        check(CliArgs.Parse(["--needs", "--port", "5000"], out _) is null, "cli: --needs opens no page, so no --port");
        check(!CliArgs.NeedsTerminal(new CliCommand.Needs([])), "cli: --needs runs without a terminal");
        check(CliArgs.Parse(["-f", "a.env", "--recover"], out string error) is null && error.Contains("--needs", StringComparison.Ordinal) && CliArgs.Parse(["-f", "a.env"], out _) is null && CliArgs.Parse(["--recover", "-f", "x"], out _) is null, "cli: -f goes only with a run or --needs");
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
            File.WriteAllText(path, "#!/bin/sh\nenv > \"" + Path.Combine(folder, "env.txt") + "\"\necho \"t=$TOKEN\"\necho \"l=$LOG_LEVEL\"\n");
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
        StateDatabase auditState = new(Path.Combine(Fresh(parent), "audit.db"));
        StringWriter stdout = new();
        StringWriter stderr = new();
        RunArgs args = new(secrets, "env test", script, [], envFiles);
        int code = await new RunCommand(source, approver, stdout, stderr, environment: name => os is not null && os.TryGetValue(name, out string? value) ? value : null).ExecuteAsync(args, folder, TestAudit.Sink(auditState));

        return new RunResult(code, stdout.ToString(), stderr.ToString(), StateDatabaseTests.AuditText(auditState.FilePath), File.Exists(envDump) ? File.ReadAllText(envDump) : "");
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
        check(run.Audit.Contains("\"type\":\"authorization\"", StringComparison.Ordinal) && run.Audit.Contains("\"outcome\":\"approved\"", StringComparison.Ordinal), "run: the signed audit events are there (and hold no value)");

        // a pair is part of the fingerprint
        string baseKey = RequestFingerprint.Compute(seen).Key;
        check(RequestFingerprint.Compute(seen with { Mappings = [new SecretMapping("OTHER", Stripe), seen.Mappings![1]] }).Key != baseKey, "run: another variable for the same secret is another fingerprint");
        check(RequestFingerprint.Compute(seen with { EnvFiles = [Path.Combine(folder, "x.env")] }).Key != baseKey, "run: another .env path is another fingerprint");
        check(RequestFingerprint.Compute(seen with { EnvNames = [] }).Key != baseKey, "run: another set of ordinary names is another fingerprint");

        // names of any case, a long value in full on the page (one line with the marker), the .env block after Run:
        (folder, script, dump) = Project(parent, $"TOKEN=secret://team/Payments/stripe_key\nLONGV={new string('x', EnvDeclarations.MaxValue)}\n");
        approver = new(true);
        run = await Execute(parent, folder, script, dump, new RecordingSource(new() { ["team/Payments/stripe_key"] = Token }), approver, []);
        string longText = ApprovalSummary.BuildMessage(approver.Requests[0]);
        check(run.Code == 0 && run.EnvDump.Contains("TOKEN=" + Token, StringComparison.Ordinal) && longText.Contains("\n  | LONGV=" + new string('x', EnvDeclarations.MaxValue) + "\n", StringComparison.Ordinal) && longText.IndexOf("  | LONGV=", StringComparison.Ordinal) > longText.IndexOf("Run: ", StringComparison.Ordinal), "run: a lower-case secret name works, and a 4096-character value is shown in full on one line after Run: (" + run.Err + ")");

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

        // an ordinary code-loading value is passed on and shown on the page like any other; the inherited-environment denylist is separate
        (folder, script, dump) = Project(parent, "NODE_OPTIONS=--require ./hook-file.js\nPYTHONSTARTUP=/tmp/startup.py\nTOKEN=secret://TOKEN_SECRET\nLOG_LEVEL=ok1\nDOTENV_PRIVATE_KEY=priv-not-for-child\n");
        approver = new(true);
        run = await Execute(parent, folder, script, dump, source, approver, []);
        string[] lines = run.EnvDump.Split('\n').Select(line => line.Trim()).ToArray();
        check(run.Code == 0 && lines.Contains("NODE_OPTIONS=--require ./hook-file.js") && lines.Contains("PYTHONSTARTUP=/tmp/startup.py") && lines.Contains("LOG_LEVEL=ok1"), "run: ordinary code-loading values from the .env reach the program (shown on the page, not dropped)");
        string codeText = ApprovalSummary.BuildMessage(approver.Requests[0]);
        check(codeText.Contains("\n  | NODE_OPTIONS=--require ./hook-file.js", StringComparison.Ordinal) && codeText.Contains("\n  | PYTHONSTARTUP=/tmp/startup.py", StringComparison.Ordinal), "run: the page shows the code-loading values in full, one per line with the marker");
        check(!lines.Any(line => line.StartsWith("DOTENV_PRIVATE_KEY", StringComparison.Ordinal)) && !codeText.Contains("priv-not-for-child", StringComparison.Ordinal) && run.Err.Contains("DOTENV_PRIVATE_KEY", StringComparison.Ordinal) && !run.Err.Contains("priv-not-for-child", StringComparison.Ordinal) && !run.Err.Contains("hook-file", StringComparison.Ordinal), "run: a DOTENV_PRIVATE_KEY variable is still left out, with a note of its name only; no code-loading note");
        {
            // the denylist for what the agent's own shell supplies stays: an inherited NODE_OPTIONS never reaches the child
            string? before = Environment.GetEnvironmentVariable("NODE_OPTIONS");
            Environment.SetEnvironmentVariable("NODE_OPTIONS", "--inherited-flag");
            try
            {
                (folder, script, dump) = Project(parent, "TOKEN=secret://TOKEN_SECRET\n");
                run = await Execute(parent, folder, script, dump, source, new FakeApprover(true), []);
                check(run.Code == 0 && !run.EnvDump.Contains("inherited-flag", StringComparison.Ordinal), "run: an inherited code-loading variable is still removed from the child");
            }
            finally
            {
                Environment.SetEnvironmentVariable("NODE_OPTIONS", before);
            }
        }

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
        check(run.Code == RunCommand.Usage && run.Err.Contains(DotenvxRun.ExecutableVariable, StringComparison.Ordinal) && run.Err.Contains("ENC", StringComparison.Ordinal) && !run.Err.Contains("BDQ3s0m3", StringComparison.Ordinal) && approver.Requests.Count == 0 && source.Requests.Count == 0, "run: an effective encrypted value requires an explicitly configured dotenvx executable before approval");
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

    private static async Task Encrypted(Action<bool, string> check, string parent)
    {
        const string plain = "Decrypted-Value-6021";
        const string stored = "Stored-Value-4711";
        string cipher = FakeDotenvx.Cipher(plain);
        string text = $"DOTENV_PUBLIC_KEY={FakeDotenvx.PublicKey}\nDB_PASS={cipher}\nTOKEN=secret://TEAM/API_KEY\n";
        var (folder, script, dump) = Project(parent, text);
        using var fake = new FakeDotenvx();
        var source = new RecordingSource(new() { ["TEAM/API_KEY"] = stored });

        string? executable = Environment.GetEnvironmentVariable(DotenvxRun.ExecutableVariable);
        var missing = new FakeApprover(true);
        try
        {
            Environment.SetEnvironmentVariable(DotenvxRun.ExecutableVariable, "dotenvx");
            var refusal = await Execute(parent, folder, script, dump, source, missing, []);
            check(refusal.Code == RunCommand.Usage && refusal.Err.Contains(DotenvxRun.ExecutableVariable, StringComparison.Ordinal)
                && refusal.Err.Contains("DB_PASS", StringComparison.Ordinal) && missing.Requests.Count == 0,
                "dotenvx: a relative executable is refused before approval");
        }
        finally
        {
            Environment.SetEnvironmentVariable(DotenvxRun.ExecutableVariable, executable);
        }

        var approval = new FakeApprover(true);
        var result = await Execute(parent, folder, script, dump, source, approval, []);
        var approved = approval.Requests.Single();
        check(result.Code == 0 && result.EnvDump.Contains("DB_PASS=" + plain, StringComparison.Ordinal)
            && result.EnvDump.Contains("TOKEN=" + stored, StringComparison.Ordinal), "dotenvx: the child receives both sets of values (" + result.Err + ")");
        check(source.Requests.Single().SequenceEqual(["TEAM/API_KEY"]) && approved.SecretNames.SequenceEqual(["TEAM/API_KEY"]),
            "dotenvx: a launch requests only Arcana Guardian values from the store");
        check(approved.Decrypts is [{ Variable: "DB_PASS" } item] && item.PublicKey == FakeDotenvx.PublicKey
            && item.CipherSha256 == DecryptItem.HashOf(cipher), "dotenvx: the approval binds the public key and ciphertext");
        string surfaces = result.Out + result.Err + result.Audit + ApprovalSummary.BuildMessage(approved);
        check(new[] { plain, stored, cipher, FakeDotenvx.Credential }.All(value => !surfaces.Contains(value, StringComparison.Ordinal))
            && !result.EnvDump.Contains("DOTENVX_ARMOR_TOKEN", StringComparison.Ordinal), "dotenvx: values and the resolver credential stay out of output and audit");

        File.Delete(dump);
        var denied = await Execute(parent, folder, script, dump, source, new FakeApprover(false), []);
        check(denied.Code == RunCommand.Denied && !File.Exists(dump), "dotenvx: denial prevents the launch");
    }

    private static readonly string[] ProtectedNames =
    [
        "NODE_OPTIONS", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "LD_PRELOAD", "BASH_ENV", "GIT_SSH_COMMAND", "PYTHONSTARTUP", "DOTNET_STARTUP_HOOKS", "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL",
        "GIT_COMMITTER_NAME", "PATH", "COMSPEC", "PYTHONPATH", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "JAVA_TOOL_OPTIONS", "RUBYOPT", "PERL5OPT", "ENV", "ZDOTDIR", "SystemRoot", "windir", "PATHEXT", "https_proxy", "node_options",
    ];

    private static async Task ClientDotenvx(Action<bool, string> check, string parent)
    {
        const string projectValue = "Client-Dotenvx-8214";
        const string storeValue = "Service-Only-8811";
        using var fake = new FakeDotenvx();
        string? edited = null;
        using var rig = new HostServiceTests.Rig(parent, new() { ["TOKEN"] = storeValue },
            approver: () => edited is null ? new FakeApprover(true) : new EnvEditingApprover(edited, "DB_PASS=changed\n"));
        string env = Path.Combine(rig.Work, ".env");
        string text = $"DB_PASS={FakeDotenvx.Cipher(projectValue)}\nTOKEN=secret://TOKEN\nLOG_LEVEL=visible\nCOMPUTED=$LOG_LEVEL\n";
        File.WriteAllText(env, text);
        string program = rig.Script("dotenvx", "echo db=%DB_PASS% store=%TOKEN% log=%LOG_LEVEL% computed=%COMPUTED% armor=[%DOTENVX_TOKEN%]", "echo \"db=$DB_PASS store=$TOKEN log=$LOG_LEVEL computed=$COMPUTED armor=[$DOTENVX_TOKEN]\"");
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();
        var args = new RunArgs([], "review client dotenvx", program, []);
        Task<int> Run() => LaunchClient.RunAsync(args, rig.Work, rig.Service.Endpoint, null, stdout, stderr, rig.Machine.Trust);
        int result = await Run();
        check(result == 0 && stdout.ToString().Contains("db=[REDACTED] store=[REDACTED] log=visible computed=[REDACTED] armor=[]", StringComparison.Ordinal)
            && rig.Store.Reads == 1, "dotenvx client: the app receives the merged values after the private handoff (" + result + " " + stderr + ")");

        File.WriteAllText(Path.Combine(rig.Work, "Envfile"), "strict true\n");
        File.WriteAllText(env, "TOKEN=secret://TOKEN\nLOG_LEVEL=visible\n");
        stdout.GetStringBuilder().Clear();
        stderr.GetStringBuilder().Clear();
        using (var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
        {
            result = await LaunchClient.RunAsync(args, rig.Work, rig.Service.Endpoint, null, stdout, stderr, rig.Machine.Trust, cancel: deadline.Token);
        }
        check(result == RunCommand.Usage && stdout.ToString().Length == 0 && rig.Store.Reads == 1
            && stderr.ToString().Contains(DotenvxRun.ApprovalError, StringComparison.Ordinal)
            && !stderr.ToString().Contains("simulated prompt", StringComparison.Ordinal),
            "dotenvx client: policy-only runs fail promptly on the Armor marker without forwarding the prompt or reading the store");
        File.Delete(Path.Combine(rig.Work, "Envfile"));
        File.WriteAllText(env, text);

        edited = env;
        stdout.GetStringBuilder().Clear();
        stderr.GetStringBuilder().Clear();
        result = await Run();
        check(result == RunCommand.Usage && stdout.ToString().Length == 0 && rig.Store.Reads == 1,
            "dotenvx client: project inputs edited during approval fail before the store is read (" + result + " " + stderr + ")");
    }

    private static LaunchRequest Launch(string folder, string envFile, LaunchEncrypted item, IReadOnlyList<string>? secretNames = null, IReadOnlyDictionary<string, string>? ordinary = null)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;

        return new LaunchRequest(LaunchProtocol.Version, "req-" + Guid.NewGuid().ToString("N")[..8], now, now.AddMinutes(5), "bm9uY2UtMDAwMDAwMDE" + Guid.NewGuid().ToString("N")[..6], secretNames ?? [item.PublicKey], [], "review test", "prog", [], folder, [envFile],
            [.. (ordinary ?? new Dictionary<string, string>()).Keys.Order(StringComparer.Ordinal)], ordinary ?? new Dictionary<string, string>(), new Dictionary<string, string>(), [item]);
    }

    private static async Task ReviewFixes(Action<bool, string> check, string parent)
    {
        const string Plain = "Decrypted-Value-6021";
        using var fake = new FakeDotenvx();
        string cipher = FakeDotenvx.Cipher(Plain);
        string cipherBody = cipher["encrypted:".Length..];

        // H1: an encrypted value is one the page cannot show, so it may not go to a name that changes which code runs, where traffic goes or who a commit is by
        foreach (string name in ProtectedNames)
        {
            EnvResult composed = Compose(Fresh(parent), $"{name}={cipher}\n");
            check(composed.Plan is null && composed.Error!.Contains("encrypted value cannot be given to this variable", StringComparison.Ordinal) && composed.Error.Contains(name, StringComparison.Ordinal) && !composed.Error.Contains(cipherBody, StringComparison.Ordinal), "protected encrypted: " + name + " is refused at composition, naming the variable and no ciphertext");
            EnvResult overridden = Compose(Fresh(parent), $"{name}={cipher}\n", environment: new() { [name] = "from-os" });
            check(overridden.Plan is null, "protected encrypted: " + name + " is refused even when the environment has a value of that name (not safe by luck)");
        }

        foreach (string name in new[] { "NODE_OPTIONS", "HTTPS_PROXY", "LD_PRELOAD", "BASH_ENV", "GIT_SSH_COMMAND", "PYTHONSTARTUP", "DOTNET_STARTUP_HOOKS", "GIT_AUTHOR_NAME", "PATH" })
        {
            (string folder, string script, string dump) = Project(parent, $"{name}={cipher}\n");
            RecordingSource source = new(new() {  });
            FakeApprover approver = new(true);
            RunResult run = await Execute(parent, folder, script, dump, source, approver, []);
            check(run.Code == RunCommand.Usage && approver.Requests.Count == 0 && source.Requests.Count == 0 && run.EnvDump.Length == 0 && !run.Err.Contains(cipherBody, StringComparison.Ordinal), "protected encrypted run: " + name + " is exit 2 before any page, nothing is read or run");
        }

        // the same rule for a secret named with --secrets, and in the last filter before the child starts
        {
            (string folder, string script, string dump) = Project(parent, null);
            FakeApprover approver = new(true);
            RunResult run = await Execute(parent, folder, script, dump, new RecordingSource(new() { ["NODE_OPTIONS"] = "--require ./x-1.js" }), approver, ["NODE_OPTIONS"]);
            check(run.Code == RunCommand.Usage && approver.Requests.Count == 0 && run.EnvDump.Length == 0, "protected secret: --secrets NODE_OPTIONS is refused before any page");
            PreparedChild prepared = ChildRunner.Prepare(new ChildSpec(Path.Combine(folder, "none"), [], folder, new Dictionary<string, string> { ["NODE_OPTIONS"] = "--require ./x-1.js", ["HTTPS_PROXY"] = "http://evil.example", ["GIT_AUTHOR_NAME"] = "x", ["TOKEN"] = "tok-value-1" }, null, new Dictionary<string, string>()));
            check(prepared.EnvironmentCount == 1, "protected secret: the last filter drops every protected name from the secrets before the child's environment is built (" + prepared.EnvironmentCount + " left)");
            prepared.Discard();
        }

        // H1 over the API: the service checks the request again with the same rule
        {
            string folder = Fresh(parent);
            string envFile = Path.Combine(folder, ".env");
            LaunchEncrypted fine = new("DB_PASS", envFile, "", cipher);
            check(EnvDeclarations.FromRequest(Launch(folder, envFile, fine)) is { Plan.Encrypted: [{ Variable: "DB_PASS" }] }, "request: an encrypted value for an ordinary name is accepted");
            foreach (string name in new[] { "NODE_OPTIONS", "HTTPS_PROXY", "LD_PRELOAD", "BASH_ENV", "GIT_SSH_COMMAND", "PYTHONSTARTUP", "DOTNET_STARTUP_HOOKS", "GIT_AUTHOR_NAME", "PATH", "DOTENV_PRIVATE_KEY_X" })
            {
                check(EnvDeclarations.FromRequest(Launch(folder, envFile, fine with { Variable = name })) is { Plan: null, Error: { } error } && error.Contains(name, StringComparison.Ordinal) && !error.Contains(cipherBody, StringComparison.Ordinal), "request: an encrypted value for " + name + " is refused by the service");
            }

            check(EnvDeclarations.FromRequest(Launch(folder, envFile, fine with { PublicKey = "DOTENV_PRIVATE_KEY_STAGING" }, ["DOTENV_PRIVATE_KEY_STAGING"])).Plan is null, "request: a key secret other than the one the file name gives is refused");
            check(EnvDeclarations.FromRequest(Launch(folder, envFile, fine with { File = Path.Combine(folder, "other.env") })).Plan is null, "request: an encrypted value from a file that is not among the env files is refused");
            check(EnvDeclarations.FromRequest(Launch(folder, envFile, fine with { Ciphertext = "plain text" })).Plan is null && EnvDeclarations.FromRequest(Launch(folder, envFile, fine with { Ciphertext = "encrypted:" + new string('A', EnvDeclarations.MaxEncrypted) })).Plan is null, "request: a ciphertext that is not encrypted: text, or is longer than the limit, is refused");
            check(EnvDeclarations.FromRequest(Launch(folder, envFile, fine, null, new Dictionary<string, string> { ["DB_PASS"] = "x" })).Plan is null, "request: a variable that is both ordinary and encrypted is refused");
            check(EnvDeclarations.FromRequest(Launch(folder, envFile, fine, null, new Dictionary<string, string> { ["NODE_OPTIONS"] = "--max-old-space-size=100" })).Plan is { } passed && passed.Ordinary.ContainsKey("NODE_OPTIONS"), "request: an ordinary code-loading value is passed on (the page shows it)");
        }

        // H2: the fingerprint covers the ciphertext, so a swapped one is another request
        {
            string swapped = FakeDotenvx.Cipher("https://attacker.example/x");
            (string folder, string script, string dump) = Project(parent, $"API_BASE_URL={cipher}\n");
            StateDatabase db = TestState.Seeded(Path.Combine(Fresh(parent), ArcanaGuardianDatabase.FileName));
            async Task<(int Code, string Err, FakeApprover Approver, string Dump)> RunSaved(string env)
            {
                File.WriteAllText(Path.Combine(folder, ".env"), env);
                File.Delete(dump);
                FakeApprover approver = new(true);
                StringWriter stderr = new();
                RunCommand command = new(new RecordingSource([]), approver, new StringWriter(), stderr, environment: _ => null);
                int code = await command.ExecuteAsync(new RunArgs([], "review test", script, [], null), folder, TestAudit.Sink(db));

                return (code, stderr.ToString(), approver, File.Exists(dump) ? File.ReadAllText(dump) : "");
            }

            var first = await RunSaved($"API_BASE_URL={cipher}\n");
            string key = RequestFingerprint.Compute(first.Approver.Requests[0]).Key;
            check(first.Code == 0 && first.Approver.Requests.Count == 1, "ciphertext: the first run asks");
            var again = await RunSaved($"API_BASE_URL={cipher}\n");
            check(again.Code == 0 && again.Approver.Requests.Count == 1 && RequestFingerprint.Compute(again.Approver.Requests[0]).Key == key && again.Dump.Contains("API_BASE_URL=" + Plain, StringComparison.Ordinal), "ciphertext: the same ciphertext asks again and has the same fingerprint (" + again.Err.Trim() + ")");
            var swap = await RunSaved($"API_BASE_URL={swapped}\n");
            check(swap.Approver.Requests.Count == 1 && RequestFingerprint.Compute(swap.Approver.Requests[0]).Key != key, "ciphertext: a swapped ciphertext is another fingerprint");
            check(swap.Approver.Requests.Count == 1 && swap.Approver.Requests[0].Decrypts![0].CipherSha256 == DecryptItem.HashOf(swapped) && swap.Approver.Requests[0].Decrypts![0].CipherSha256 != first.Approver.Requests[0].Decrypts![0].CipherSha256, "ciphertext: the item carries the SHA-256 of exactly the ciphertext that will be decrypted");
            string independent = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(cipher)));
            check(first.Approver.Requests[0].Decrypts![0].CipherSha256 == independent, "ciphertext: the hash is the plain SHA-256 of the ciphertext text");
            check(RequestFingerprint.Compute(first.Approver.Requests[0] with { Decrypts = [first.Approver.Requests[0].Decrypts![0] with { CipherSha256 = DecryptItem.HashOf(swapped) }] }).Key != key, "ciphertext: the hash is part of the fingerprint");
            ApprovalRequest approved = first.Approver.Requests[0];
            DateTimeOffset now = DateTimeOffset.UtcNow;
            LaunchRequest expected = LaunchRequestBinding.From(approved, "req-bind-0001", "bm9uY2UtMDAwMDAwMDE", now, now.AddMinutes(5)) with { Encrypted = [new LaunchEncrypted("API_BASE_URL", Path.Combine(folder, ".env"), "", cipher)] };
            check(LaunchRequestBinding.Mismatch(expected, approved) is null, "ciphertext: the request with the approved ciphertext matches the approval (" + LaunchRequestBinding.Mismatch(expected, approved) + ")");
            check(LaunchRequestBinding.Mismatch(expected with { Encrypted = [expected.Encrypted[0] with { Ciphertext = swapped }] }, approved) is { } mismatch && mismatch.Contains("encrypted", StringComparison.Ordinal), "ciphertext: a request whose ciphertext differs from the approved one does not match the approval");
        }

        // M3: a short fingerprint of each ciphertext, a warning when the file is not the project's own, and the plain statement that anyone with the public key can write one
        {
            (string folder, string script, string dump) = Project(parent, $"DB_PASS={cipher}\n");
            Directory.CreateDirectory(Path.Combine(folder, "scratch"));
            File.WriteAllText(Path.Combine(folder, "scratch", ".env.production"), $"LOG_FORMAT={cipher}\n");
            File.WriteAllText(Path.Combine(folder, ".env.production"), $"LOG_FORMAT={cipher}\n");
            File.WriteAllText(Path.Combine(folder, "secrets.txt"), $"LOG_FORMAT={cipher}\n");
            string outside = Fresh(parent);
            File.WriteAllText(Path.Combine(outside, ".env"), $"LOG_FORMAT={cipher}\n");
            RecordingSource source = new(new() {  });
            string fingerprint = DecryptItem.HashOf(cipher)[..12];
            foreach ((string label, string[]? files, bool warns) in new (string, string[]?, bool)[]
            {
                ("the project's own .env", null, false),
                ("the project's own .env.production", [".env.production"], false),
                ("a .env.production in a sub folder", [Path.Combine("scratch", ".env.production")], true),
                ("a file that is not named .env*", ["secrets.txt"], true),
                ("a .env in another folder", [Path.Combine(outside, ".env")], true),
            })
            {
                FakeApprover approver = new(true);
                RunResult run = await Execute(parent, folder, script, dump, source, approver, [], files);
                string text = ApprovalSummary.BuildMessage(approver.Requests[0]);
                string echo = ApprovalSummary.BuildMessage(approver.Requests[0], showValues: false);
                string line = text.Split('\n').First(item => item.StartsWith("resolve with dotenvx: ", StringComparison.Ordinal));
                check(run.Code == 0 && line.Contains("(cipher sha256 " + fingerprint + ") from ", StringComparison.Ordinal) && echo.Contains(fingerprint, StringComparison.Ordinal), "transplant (" + label + "): the decrypt line shows the short fingerprint of the ciphertext, on the page and in the terminal echo (" + run.Err.Trim() + ")");
                check(text.Contains("Anyone who has the public key", StringComparison.Ordinal), "transplant (" + label + "): the page says that anyone with the public key can write an encrypted value");
                check(text.Contains("is decrypted from a file that is not this project's own .env file", StringComparison.Ordinal) == warns && echo.Contains("not this project's own", StringComparison.Ordinal) == warns, "transplant (" + label + "): the warning is " + (warns ? "shown" : "not shown"));
                check(!text.Contains(cipherBody, StringComparison.Ordinal) && !text.Contains(Plain, StringComparison.Ordinal) && !text.Contains(FakeDotenvx.Credential, StringComparison.Ordinal), "transplant (" + label + "): names and the short fingerprint only, never the ciphertext, the value or the key");
            }

            // the warning is part of the text the person signs and of nothing else: the fingerprint of the request does not need it, the text does
            FakeApprover warned = new(true);
            await Execute(parent, folder, script, dump, source, warned, [], [Path.Combine("scratch", ".env.production")]);
            check(ApprovalSummary.BuildMessage(warned.Requests[0]).Contains("Warning: LOG_FORMAT is decrypted from a file", StringComparison.Ordinal), "transplant: the warning names the variable");
        }

        // F6: the directory part of -f is the agent's, and it cannot pose as the key or end the line early
        {
            (string folder, string script, string dump) = Project(parent, null);
            string forged = "x) with secret DOTENV_PRIVATE_KEY_DEV and (y";
            Directory.CreateDirectory(Path.Combine(folder, forged));
            File.WriteAllText(Path.Combine(folder, forged, ".env.production"), $"DB_PASS={cipher}\n");
            FakeApprover approver = new(true);
            RunResult run = await Execute(parent, folder, script, dump, new RecordingSource([]), approver, [], [Path.Combine(forged, ".env.production")]);
            string[] lines = ApprovalSummary.BuildMessage(approver.Requests[0]).Split('\n');
            check(run.Code == 0 && lines.Count(item => item.StartsWith("resolve with dotenvx: ", StringComparison.Ordinal)) == 1 && lines.First(item => item.StartsWith("resolve with dotenvx: ", StringComparison.Ordinal)).StartsWith("resolve with dotenvx: DB_PASS (cipher sha256 ", StringComparison.Ordinal), "forged path: the real key secret comes first on the decrypt line, before any text of the path");
        }


        // M4: NUL and other control characters in a decrypted value never reach the child's environment
        foreach ((string label, string bad) in new[] { ("NUL and a second variable", "ok123\0NODE_OPTIONS=--require ./x.js"), ("a line break", "line-one\nline-two"), ("a bell", "ring\u0007ring-1"), ("DEL", "del\u007Fvalue-1"), ("a C1 control", "c1\u0085control-1") })
        {
            (string folder, string script, string dump) = Project(parent, $"DB_PASS={FakeDotenvx.Cipher(bad)}\nOK_VAR=fine1\n");
            FakeApprover approver = new(true);
            RunResult run = await Execute(parent, folder, script, dump, new RecordingSource([]), approver, []);
            check(run.Code == RunCommand.Usage && run.Err.Contains("with dotenvx", StringComparison.Ordinal) && run.EnvDump.Length == 0 && !run.Err.Contains("NODE_OPTIONS", StringComparison.Ordinal) && !run.Err.Contains("ring", StringComparison.Ordinal), "control characters (" + label + "): exit 2 naming the variable only, the program is not run (" + run.Code + ")");
            check(run.Audit.Contains("dotenvx-failed", StringComparison.Ordinal) && run.Audit.Contains("\"type\":\"launch\"", StringComparison.Ordinal), "control characters (" + label + "): the failure is in the signed audit as a failed launch (finding 12)");
        }

        {
            (string folder, string script, string dump) = Project(parent, $"DB_PASS={FakeDotenvx.Cipher("tab\tallowed-1")}\n");
            RunResult run = await Execute(parent, folder, script, dump, new RecordingSource([]), new FakeApprover(true), []);
            check(run.Code == 0 && run.EnvDump.Contains("DB_PASS=tab\tallowed-1", StringComparison.Ordinal), "control characters: a tab is allowed (" + run.Code + " " + run.Err.Trim() + ")");
            check(!RunCommand.UsablePlaintext(new string('a', SecretNames.MinValueLength - 1)) && RunCommand.UsablePlaintext(new string('a', SecretNames.MinValueLength)) && RunCommand.UsablePlaintext(new string('a', EnvDeclarations.MaxValue)) && !RunCommand.UsablePlaintext(new string('a', EnvDeclarations.MaxValue + 1)) && !RunCommand.UsablePlaintext("abc\0def"), "length bounds: a decrypted value of 6 to 4096 characters without NUL is usable, and nothing else");
        }

        // length bounds of the ciphertext itself, and a wrong key or a tampered ciphertext (no oracle: one message, no value)
        {
            string longest = "BIG=encrypted:" + new string('A', EnvDeclarations.MaxEncrypted - "encrypted:".Length);
            check(Compose(Fresh(parent), longest).Plan is { Encrypted.Count: 1 }, "ciphertext length: the longest allowed ciphertext is accepted at composition");
            check(Compose(Fresh(parent), longest + "A").Error is { } tooLong && tooLong.Contains("longer than", StringComparison.Ordinal) && !tooLong.Contains("AAAAAAAA", StringComparison.Ordinal), "ciphertext length: one character more is refused, naming the variable and the limit only");

            string tampered = cipher[..^8] + (cipher[^8] == 'A' ? 'B' : 'A') + cipher[^7..];
            string[] messages = new string[3];
            int index = 0;
            foreach (string bad in new[] { tampered, "encrypted:YmFkLXNlY29uZA==", "encrypted:" + new string('B', 100) })
            {
                (string folder, string script, string dump) = Project(parent, $"DB_PASS={bad}\n");
                RunResult run = await Execute(parent, folder, script, dump, new RecordingSource([]), new FakeApprover(true), []);
                messages[index++] = run.Err.Split('\n').Last(line => line.Trim().Length > 0);
                check(run.Code == RunCommand.Usage && run.EnvDump.Length == 0 && !run.Err.Contains(bad["encrypted:".Length..], StringComparison.Ordinal), "tampered, wrong-key and damaged ciphertext: exit 2, the program is not run, no ciphertext in the message");
            }

            check(messages.Distinct().Count() == 1, "no oracle: a tampered, a wrong-key and a damaged ciphertext get exactly the same message");
        }

        // M5: the ordinary variables that change which code runs are named in a warning at the top of the .env block, however long the list
        {
            StringBuilder env = new();
            for (int index = 0; index < 150; index++)
            {
                env.Append("NOISE_").Append(index.ToString("D3", System.Globalization.CultureInfo.InvariantCulture)).Append('=').Append(new string('n', 400)).Append('\n');
            }

            env.Append("NODE_OPTIONS=--require ./x-hook.js\nHTTPS_PROXY=http://proxy.example:3128\nLOG_LEVEL=ok1\nTOKEN=secret://TOKEN_SECRET\n");
            (string folder, string script, string dump) = Project(parent, env.ToString());
            FakeApprover approver = new(true);
            RunResult run = await Execute(parent, folder, script, dump, new RecordingSource(new() { ["TOKEN_SECRET"] = Token }), approver, []);
            string text = ApprovalSummary.BuildMessage(approver.Requests[0]);
            string echo = ApprovalSummary.BuildMessage(approver.Requests[0], showValues: false);
            int warning = text.IndexOf("Warning: " + ApprovalSummary.CodeChangesHeading, StringComparison.Ordinal);
            check(run.Code == 0 && warning > 0 && warning < text.IndexOf("Env file:", StringComparison.Ordinal) && warning < text.IndexOf("  | NOISE_000", StringComparison.Ordinal) && text.Contains("  | HTTPS_PROXY=http://proxy.example:3128", StringComparison.Ordinal) && text.Contains("  | NODE_OPTIONS=--require ./x-hook.js", StringComparison.Ordinal), "flooding: the warning shows NODE_OPTIONS and HTTPS_PROXY with their values before the first of 150 long values (" + run.Code + " " + run.Err.Trim() + ")");
            check(echo.Contains("  | HTTPS_PROXY" + (char)10 + "  Why: ", StringComparison.Ordinal) && !echo.Contains("x-hook.js", StringComparison.Ordinal), "flooding: the terminal echo carries the warning too");
            check(run.EnvDump.Contains("NODE_OPTIONS=--require ./x-hook.js", StringComparison.Ordinal), "flooding: the values are still passed on (they are bound by the fingerprint and shown)");
            (folder, script, dump) = Project(parent, "LOG_LEVEL=ok1\nTOKEN=secret://TOKEN_SECRET\n");
            approver = new(true);
            await Execute(parent, folder, script, dump, new RecordingSource(new() { ["TOKEN_SECRET"] = Token }), approver, []);
            check(!ApprovalSummary.BuildMessage(approver.Requests[0]).Contains("Warning:", StringComparison.Ordinal), "flooding: no warning when no such variable is set");
        }

        // F11: parsing stops at the entry limit instead of building a huge list first
        {
            string folder = Fresh(parent);
            StringBuilder many = new();
            for (int index = 0; index <= EnvDeclarations.MaxEntriesPerFile; index++)
            {
                many.Append('V').Append(index.ToString(System.Globalization.CultureInfo.InvariantCulture)).Append("=1\n");
            }

            (IReadOnlyList<EnvDeclarations.Entry>? entries, string? error) = EnvDeclarations.Parse("big.env", many.ToString());
            check(entries is null && error!.Contains("more than " + EnvDeclarations.MaxEntriesPerFile, StringComparison.Ordinal) && error.Contains("big.env:" + (EnvDeclarations.MaxEntriesPerFile + 1), StringComparison.Ordinal), "parse limit: the file is refused at the first entry over the limit, naming the line (" + error + ")");
            (entries, error) = EnvDeclarations.Parse("ok.env", many.ToString().Replace("V" + EnvDeclarations.MaxEntriesPerFile + "=1\n", "", StringComparison.Ordinal));
            check(entries is { Count: EnvDeclarations.MaxEntriesPerFile }, "parse limit: exactly the limit is accepted");
        }

        // F8: the private key is masked in the output even if the program learns it some other way (it is not in the environment)
        {
            (string folder, string script, string dump) = Project(parent, null);
            string canary = "Key-Canary-Value-5150";
            StringWriter stdout = new();
            StringWriter stderr = new();
            string showProgram = OperatingSystem.IsWindows() ? Path.Combine(folder, "show.cmd") : Path.Combine(folder, "show.sh");
            int code = await ChildRunner.RunAsync(new ChildSpec(showProgram, [], folder, new Dictionary<string, string>(), new Dictionary<string, string> { ["TOKEN"] = canary }, null, [canary]), stdout, stderr);
            check(code == 0 && stdout.ToString().Contains("t=[REDACTED]", StringComparison.Ordinal) && !stdout.ToString().Contains(canary, StringComparison.Ordinal), "redactor: a value given only to the redactor is masked in the output (" + code + ")");
        }

        // F9: look-alike characters and case twins among the names of one request
        {
            check(SecretNames.LookAlikes("APl_KEY", ["API_KEY", "APl_KEY", "OTHER"]).SequenceEqual(["API_KEY"]) && SecretNames.LookAlikes("A0", ["AO", "a0"]).SequenceEqual(["AO"]) && SecretNames.LookAlikes("KEY1", ["KEYl", "KEYI"]).SequenceEqual(["KEYI", "KEYl"]), "look-alikes: l, I, 1 and O, 0 are found, case twins are left to the case rule");
            string folder = Fresh(parent);
            File.WriteAllText(Path.Combine(folder, ".env"), "A=secret://API_KEY\n");
            StringWriter stdout = new();
            check(NeedsCommand.Run(new RecordingSource(new() { ["APl_KEY"] = "value-1234" }), null, folder, stdout, new StringWriter(), _ => null) == 0 && stdout.ToString().Contains("Secret: A <- secret API_KEY  NOT IN STORE; looks like: APl_KEY", StringComparison.Ordinal), "look-alikes: --needs notes a stored name that looks like the referenced one");
        }

        // the key secret is in the redactor's reach and the audit of a failed decrypt names no value
        {
            (string folder, string script, string dump) = Project(parent, $"DB_PASS={cipher}\n");
            RunResult run = await Execute(parent, folder, script, dump, new RecordingSource([]), new FakeApprover(true), []);
            check(run.Code == 0 && run.Audit.Contains("\"decrypts\":\"DB_PASS:" + DecryptItem.HashOf(cipher)[..12] + "\"", StringComparison.Ordinal) && TestAuditFree(run.Audit, FakeDotenvx.Credential, Plain, cipherBody), "audit: every event of a decrypting run carries the variable, key secret name and short fingerprint, and no key, value or ciphertext");
        }
    }

    private static bool TestAuditFree(string audit, params string[] canaries) => canaries.All(canary => !audit.Contains(canary, StringComparison.Ordinal));

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
        check(lines.Where(line => line.StartsWith("Variable: ", StringComparison.Ordinal)).SequenceEqual(["Variable: BAD", "Variable: LOG_LEVEL", "Variable: NODE_OPTIONS", "Variable: ZED"]), "needs: ordinary variable names, sorted");
        check(lines.Contains("Secret: API <- secret team/API_KEY  in store") && lines.Contains("Secret: DB <- secret DB_URL  NOT IN STORE"), "needs: each reference with in store or NOT IN STORE");
        check(source.Requests.Count == 0 && !output.Contains("Verbose7", StringComparison.Ordinal) && !output.Contains("api-Value-1234", StringComparison.Ordinal) && !output.Contains("evil", StringComparison.Ordinal) && !stderr.ToString().Contains("evil", StringComparison.Ordinal), "needs: nothing is decrypted, no value is printed");
        check(output.Contains("Variable: NODE_OPTIONS", StringComparison.Ordinal) && stderr.ToString().Length == 0, "needs: a code-loading ordinary variable is listed by name like any other, with no note");

        stdout = new();
        stderr = new();
        check(NeedsCommand.Run(source, null, Fresh(parent), stdout, stderr, _ => null) == 0 && stdout.ToString().Contains("none", StringComparison.Ordinal), "needs: no .env is exit 0 and says so");
        stdout = new();
        stderr = new();
        File.WriteAllText(Path.Combine(folder, "bad.env"), "TOKEN=\"s3cr3tvalue\" junk\n");
        check(NeedsCommand.Run(source, ["bad.env"], folder, stdout, stderr, _ => null) == RunCommand.Usage && stderr.ToString().Contains("bad.env:1:", StringComparison.Ordinal) && !stderr.ToString().Contains("s3cr3tvalue", StringComparison.Ordinal) && stdout.ToString().Length == 0, "needs: a parse error is exit 2 with file and line, no value");
        File.WriteAllText(Path.Combine(folder, "enc.env"), "X=encrypted:BDQ3s0m3\n");
        stdout = new();
        check(NeedsCommand.Run(source, ["enc.env"], folder, stdout, stderr = new StringWriter(), _ => null) == 0 && stdout.ToString().Contains("Encrypted: X (requires dotenvx, file " + Path.Combine(folder, "enc.env") + ")", StringComparison.Ordinal) && !stdout.ToString().Contains("BDQ3s0m3", StringComparison.Ordinal), "needs: an encrypted value is listed as requiring dotenvx, with no ciphertext");
        stdout = new();
        RecordingSource withKey = new(new() { ["DOTENV_PRIVATE_KEY_STAGING"] = "key-never-printed-1", ["Team/Api_Key"] = "x-Value-1", ["team/API_KEY"] = "x-Value-2" });
        File.WriteAllText(Path.Combine(folder, ".env.staging"), "S=encrypted:BDQ3s0m3\n");
        File.WriteAllText(Path.Combine(folder, "case.env"), "A=secret://team/Api_Key\nB=secret://TEAM/api_key\nC=secret://team/API_KEY\n");
        check(NeedsCommand.Run(withKey, [".env.staging"], folder, stdout, new StringWriter(), _ => null) == 0 && stdout.ToString().Contains("Encrypted: S (requires dotenvx, file ", StringComparison.Ordinal) && withKey.Requests.Count == 0 && !stdout.ToString().Contains("key-never-printed-1", StringComparison.Ordinal), "needs: encrypted values report the resolver and nothing is decrypted");
        stdout = new();
        check(NeedsCommand.Run(withKey, ["case.env"], folder, stdout, new StringWriter(), _ => null) == 0, "needs: case.env runs");
        string[] caseLines = stdout.ToString().Split('\n').Select(line => line.TrimEnd('\r')).ToArray();
        check(caseLines.Contains("Secret: A <- secret team/Api_Key  NOT IN STORE; differs only by case from: Team/Api_Key, team/API_KEY") && caseLines.Contains("Secret: B <- secret TEAM/api_key  NOT IN STORE; differs only by case from: Team/Api_Key, team/API_KEY") && caseLines.Contains("Secret: C <- secret team/API_KEY  in store; differs only by case from: Team/Api_Key"), "needs: a reference gets a differs-only-by-case note naming the other stored names (public), also when it is itself in the store");
        File.WriteAllText(Path.Combine(folder, "ref.env"), "NODE_OPTIONS=secret://X\n");
        check(NeedsCommand.Run(source, ["ref.env"], folder, new StringWriter(), new StringWriter(), _ => null) == RunCommand.Usage, "needs: a reference to a code-loading variable is exit 2");
        check(NeedsCommand.Run(source, ["missing.env"], folder, new StringWriter(), new StringWriter(), _ => null) == RunCommand.Usage, "needs: a missing -f file is exit 2");
        check(NeedsCommand.Run(new RecordingSource([], true), null, folder, new StringWriter(), stderr = new StringWriter(), _ => null) == RunCommand.StoreError && stderr.ToString().Contains("cannot read the secret store", StringComparison.Ordinal), "needs: a store that fails verification is exit 4");
        check(WebUtility.HtmlEncode("x") == "x", "needs: helper sanity");
    }
}

namespace WithSecrets.Tests;

/// <summary>Project declarations stay literal until delegated encrypted values are resolved.</summary>
internal static class EnvParserPinTests
{
    private const string Canary = "CANARY-expand-7731";
    private const string CanaryVar = "WS_PIN_CANARY";

    public static void Run(Action<bool, string> check, string parent)
    {
        string folder = Path.Combine(parent, "pin-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(folder);
        ParserIsLiteral(check, folder);
        ParserRejects(check);
    }

    private static string Marker(string folder) => Path.Combine(folder, "marker-" + Guid.NewGuid().ToString("N")[..8]);

    // 1: $(...), backticks, ${VAR} and $VAR stay text, unquoted, single and double quoted; nothing runs, nothing expands.
    private static void ParserIsLiteral(Action<bool, string> check, string folder)
    {
        string? before = Environment.GetEnvironmentVariable(CanaryVar);
        Environment.SetEnvironmentVariable(CanaryVar, Canary);
        try
        {
            string marker = Marker(folder);
            string command = "echo x > " + marker.Replace('\\', '/');
            string[] bodies = ["$(" + command + ")", "`" + command + "`", "${" + CanaryVar + "}", "$" + CanaryVar, "pre-${" + CanaryVar + ":-dflt}-post", "$(" + command + ")${" + CanaryVar + "}`" + command + "`"];
            foreach (string body in bodies)
            {
                foreach ((string label, string raw, string expected) in new[]
                {
                    ("unquoted", "A=" + body, body),
                    ("single-quoted", "A='" + body + "'", body),
                    ("double-quoted", "A=\"" + body + "\"", body),
                })
                {
                    (IReadOnlyList<EnvDeclarations.Entry>? entries, string? error) = EnvDeclarations.Parse("f.env", raw + "\n");
                    check(error is null && entries is [{ Name: "A" } entry] && entry.Value == expected && !entry.Value.Contains(Canary, StringComparison.Ordinal), "pin parse: " + label + " " + (body.Length > 20 ? body[..20] : body) + "... is returned literally (" + error + ")");
                }
            }

            check(!File.Exists(marker), "pin parse: no command ran (the marker file does not exist)");
            (IReadOnlyList<EnvDeclarations.Entry>? chain, _) = EnvDeclarations.Parse("f.env", "A=" + Canary + "\nB=${A}\nC=$A\n");
            check(chain is { Count: 3 } && chain[1].Value == "${A}" && chain[2].Value == "$A", "pin parse: a variable of the same file is not expanded either");
        }
        finally
        {
            Environment.SetEnvironmentVariable(CanaryVar, before);
        }
    }

    // 2: an encrypted value whose plaintext looks like a command or an expansion comes back as that text.
    private static void ParserRejects(Action<bool, string> check)
    {
        // a lone CR does not end a line; it is data (never a break that hides a second declaration)
        (IReadOnlyList<EnvDeclarations.Entry>? cr, string? crError) = EnvDeclarations.Parse("f.env", "A=one\rB=two\n");
        check(crError is null && cr is [{ Name: "A" }] && cr[0].Value == "one\rB=two", "pin parse: a lone CR does not end a line; the rest stays in the value of A (no second variable B)");
        (IReadOnlyList<EnvDeclarations.Entry>? crq, string? crqError) = EnvDeclarations.Parse("f.env", "A=\"one\rB=two\"\n");
        check(crqError is null && crq is [{ Name: "A" }] && crq[0].Value == "one\rB=two", "pin parse: a lone CR inside quotes is data");
        check(EnvDeclarations.Parse("f.env", "A=1\r\nB=2\r\n").Entries is [{ Value: "1" }, { Value: "2" }], "pin parse: CRLF ends a line");

        // # without a preceding space is data, with a space it starts a comment (our documented grammar)
        check(EnvDeclarations.Parse("f.env", "A=a#b\nB=a #b\nC='a #b'\n").Entries is [{ Value: "a#b" }, { Value: "a" }, { Value: "a #b" }], "pin parse: A=a#b is kept whole; ' #' starts a comment only outside quotes");

        foreach (string text in new[] { "\0A=1", "A\0B=1", "A=1\0", "A=x\0y" })
        {
            (IReadOnlyList<EnvDeclarations.Entry>? entries, string? error) = EnvDeclarations.Parse("f.env", text);
            check(entries is null && error is not null && error.StartsWith("f.env:1:", StringComparison.Ordinal), "pin parse: a raw NUL is refused: " + text.Replace("\0", "<NUL>"));
        }

        foreach (string name in new[] { "A.B", "A-B", "9A", "A B", "A$B" })
        {
            (IReadOnlyList<EnvDeclarations.Entry>? entries, string? error) = EnvDeclarations.Parse("f.env", name + "=v\n");
            check(entries is null && error is not null, "pin parse: variable name '" + name + "' is refused");
        }

        // fixed limits, owned by Compose
        string folder = Path.Combine(Path.GetTempPath(), "ws-pin-limits-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(folder);
        try
        {
            EnvResult Compose(string text)
            {
                File.WriteAllText(Path.Combine(folder, ".env"), text);

                return EnvDeclarations.Compose(null, folder, [], _ => null);
            }

            check(Compose("A=" + new string('x', EnvDeclarations.MaxValue) + "\n").Plan is not null, "pin limits: a value of exactly the limit is accepted");
            EnvResult longValue = Compose("A=" + new string('x', EnvDeclarations.MaxValue + 1) + "\n");
            check(longValue.Plan is null && longValue.Error!.Contains("longer than", StringComparison.Ordinal) && !longValue.Error.Contains("xxxxxxxx", StringComparison.Ordinal), "pin limits: a value over the limit is refused, without the value");
            EnvResult longName = Compose(new string('A', EnvDeclarations.MaxVariableName + 1) + "=1\n");
            check(longName.Plan is null && longName.Error is not null, "pin limits: a name over the limit is refused");
            check(Compose(string.Concat(Enumerable.Range(0, EnvDeclarations.MaxEntriesPerFile + 1).Select(index => "V" + index + "=1\n"))).Plan is null, "pin limits: more variables than the per-file limit are refused");
            File.WriteAllBytes(Path.Combine(folder, ".env"), Enumerable.Repeat((byte)'a', (int)EnvDeclarations.MaxFileBytes + 1).ToArray());
            check(EnvDeclarations.Compose(null, folder, [], _ => null).Plan is null, "pin limits: a file over the size limit is refused");
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
}

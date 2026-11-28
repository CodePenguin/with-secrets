using System.Text.RegularExpressions;

namespace ArcanaGuardian.Tests;

/// <summary>
/// M6: the warning about ordinary variables that change how the program loads code or where it sends data. One block in the request text, shown by
/// the page as its own section above the text and the approve control; the values stay bound in the fingerprint.
/// </summary>
internal static class CodeChangesTests
{
    private const string LoadsCode = "loads code";
    private const string LibraryPath = "changes the library path";
    private const string Network = "routes network traffic";
    private const string Git = "changes git behaviour";

    private static ApprovalRequest Request(params (string Name, string Value)[] variables)
    {
        Dictionary<string, string> values = variables.ToDictionary(item => item.Name, item => item.Value);

        return new ApprovalRequest("tool", "/bin/tool", ["--x"], "/work", "testing", ["API_KEY"], Mappings: [], EnvFiles: ["/work/.env"], EnvNames: [.. values.Keys.Order(StringComparer.Ordinal)], EnvValues: values);
    }

    private static string Page(ApprovalRequest request)
    {
        return ApprovalPage.Build(new ApprovalPrompt("Run", ApprovalSummary.BuildMessage(request)), new ProofStart("webauthn", "{}"), "n", [1, 2, 3], TimeSpan.FromSeconds(2)).Body;
    }

    private static string Section(string html)
    {
        int start = html.IndexOf("<section class=\"warn\"", StringComparison.Ordinal);

        return start < 0 ? "" : html[start..html.IndexOf("</section>", start, StringComparison.Ordinal)];
    }

    public static void Run(Action<bool, string> check)
    {
        // every class: the name, the visible value and the reason of its class, in the text
        (string Name, string Class)[] classes =
        [
            ("NODE_OPTIONS", LoadsCode), ("LD_PRELOAD", LoadsCode), ("PYTHONSTARTUP", LoadsCode), ("BASH_ENV", LoadsCode), ("ENV", LoadsCode), ("PERL5OPT", LoadsCode),
            ("RUBYOPT", LoadsCode), ("JAVA_TOOL_OPTIONS", LoadsCode), ("_JAVA_OPTIONS", LoadsCode), ("DOTNET_STARTUP_HOOKS", LoadsCode), ("DYLD_INSERT_LIBRARIES", LoadsCode),
            ("PATH", LoadsCode), ("LD_AUDIT", LoadsCode),
            ("LD_LIBRARY_PATH", LibraryPath), ("DYLD_LIBRARY_PATH", LibraryPath), ("DYLD_FRAMEWORK_PATH", LibraryPath), ("PYTHONPATH", LibraryPath), ("NODE_PATH", LibraryPath),
            ("HTTP_PROXY", Network), ("HTTPS_PROXY", Network), ("ALL_PROXY", Network), ("NO_PROXY", Network), ("https_proxy", Network),
            ("GIT_SSH_COMMAND", Git), ("GIT_ASKPASS", Git), ("GIT_CONFIG_GLOBAL", Git), ("GIT_AUTHOR_NAME", Git)
        ];
        foreach ((string name, string kind) in classes)
        {
            string[] lines = ApprovalSummary.BuildMessage(Request((name, "value-of-" + name), ("LOG_LEVEL", "quiet"))).Split('\n');
            int at = Array.IndexOf(lines, "Warning: " + ApprovalSummary.CodeChangesHeading + ".");
            check(at >= 0 && lines[at + 1] == ApprovalSummary.CodeMarker + name + "=value-of-" + name && lines[at + 2].StartsWith(ApprovalSummary.CodeChangesWhy + kind, StringComparison.Ordinal) && lines[at + 3] == ApprovalSummary.CodeChangesCover, "code changes: " + name + " is listed with its value and the reason '" + kind + "'");
            check(Array.IndexOf(lines, ApprovalSummary.CodeMarker + "LOG_LEVEL=quiet") > at + 3, "code changes: an ordinary variable is listed after the block, not in it (" + name + ")");
        }

        // none when absent
        string plain = ApprovalSummary.BuildMessage(Request(("LOG_LEVEL", "quiet"), ("PATHLIKE", "x")));
        string plainPage = Page(Request(("LOG_LEVEL", "quiet")));
        check(!plain.Contains("Warning:", StringComparison.Ordinal) && !plainPage.Contains("<section", StringComparison.Ordinal), "code changes: no warning in the text or on the page when no such variable is set");
        check(ApprovalSummary.CodeChanges(Request()).Count == 0 && !Page(new ApprovalRequest("t", "/t", [], "/w", "r", ["A"])).Contains("<section", StringComparison.Ordinal), "code changes: a request without any .env has none");

        // a Dotenvx private key is never given to the program, so it is not a warning
        check(ApprovalSummary.CodeChanges(Request(("DOTENV_PRIVATE_KEY", "k"), ("DOTENV_PRIVATE_KEY_CI", "k"))).Count == 0, "code changes: a Dotenvx private key is not listed");

        // the page: one section, before the text and the approve control, the pairs and reasons in it, the block not repeated in the text
        ApprovalRequest mixed = Request(("NODE_OPTIONS", "--require ./hook.js"), ("HTTPS_PROXY", "http://proxy.example:3128"), ("LD_LIBRARY_PATH", "/opt/lib"), ("GIT_SSH_COMMAND", "ssh -i key"), ("LOG_LEVEL", "quiet"));
        string html = Page(mixed);
        int section = html.IndexOf("<section class=\"warn\"", StringComparison.Ordinal);
        int pre = html.IndexOf("<pre id=\"request\">", StringComparison.Ordinal);
        int approve = html.IndexOf("id=\"approve\"", StringComparison.Ordinal);
        int deny = html.IndexOf("id=\"deny\"", StringComparison.Ordinal);
        check(section > 0 && section < pre && pre < approve && section < deny, "code changes: the warning section comes before the request text and before the Deny and Approve controls in the page");
        check(Regex.Matches(html, "class=\"warn\"").Count == 1 && Regex.Matches(html, Regex.Escape(ApprovalSummary.CodeChangesHeading)).Count == 1, "code changes: one warning, the heading appears once in the page (no second, competing block)");
        string sectionHtml = Section(html);
        check(sectionHtml.Contains("<h2 id=\"warn-title\">Warning: This run changes how the program loads code or where it sends data</h2>", StringComparison.Ordinal) && sectionHtml.Contains("aria-labelledby=\"warn-title\"", StringComparison.Ordinal), "code changes: the section has a heading that begins with the word Warning (colour is not the only signal) and is labelled by it");
        check(sectionHtml.Contains("<code class=\"name\">NODE_OPTIONS</code> = <code class=\"value\">--require ./hook.js</code>", StringComparison.Ordinal) && sectionHtml.Contains("<code class=\"value\">http://proxy.example:3128</code>", StringComparison.Ordinal) && sectionHtml.Contains(LoadsCode, StringComparison.Ordinal) && sectionHtml.Contains(LibraryPath, StringComparison.Ordinal) && sectionHtml.Contains(Network, StringComparison.Ordinal) && sectionHtml.Contains(Git, StringComparison.Ordinal), "code changes: every name, its value and a reason per class are in the section");
        check(sectionHtml.Contains("Your approval covers exactly these values.", StringComparison.Ordinal), "code changes: the section says the approval covers exactly these values");
        string preHtml = html[pre..html.IndexOf("</pre>", pre, StringComparison.Ordinal)];
        check(!preHtml.Contains("Warning:", StringComparison.Ordinal) && !preHtml.Contains("NODE_OPTIONS", StringComparison.Ordinal) && preHtml.Contains("LOG_LEVEL=quiet", StringComparison.Ordinal), "code changes: the request text holds the other variables and not the warning block again");
        check(html.IndexOf("NODE_OPTIONS", StringComparison.Ordinal) < pre, "code changes: the first mention of a warned name is in the section, above the text");
        int git = sectionHtml.IndexOf("GIT_SSH_COMMAND", StringComparison.Ordinal);
        int https = sectionHtml.IndexOf("HTTPS_PROXY", StringComparison.Ordinal);
        int library = sectionHtml.IndexOf("LD_LIBRARY_PATH", StringComparison.Ordinal);
        int node = sectionHtml.IndexOf("NODE_OPTIONS", StringComparison.Ordinal);
        check(git >= 0 && git < https && https < library && library < node, "code changes: the variables are in name order (GIT, HTTPS, LD, NODE)");

        // values are data, never HTML
        const string Hostile = "</pre><script>alert(1)</script><img src=x onerror=alert(2)> & \" ' <b>";
        string hostile = Page(Request(("NODE_OPTIONS", Hostile), ("PYTHONPATH", "a\nb<c>")));
        string hostileHtml = Section(hostile);
        check(hostileHtml.Length > 0 && !hostileHtml.Contains("<script", StringComparison.Ordinal) && !hostileHtml.Contains("<img", StringComparison.Ordinal) && !hostileHtml.Contains("<b>", StringComparison.Ordinal) && !hostileHtml.Contains("</pre>", StringComparison.Ordinal) && hostileHtml.Contains("&lt;script&gt;alert(1)&lt;/script&gt;", StringComparison.Ordinal) && hostileHtml.Contains("&lt;img src=x onerror=alert(2)&gt; &amp;", StringComparison.Ordinal), "code changes: HTML and script in a value are escaped in the section");
        check(Regex.Matches(hostile, "<script").Count == 2 && Regex.Matches(hostile, "<section").Count == 1 && hostileHtml.Contains("a⏎b&lt;c&gt;", StringComparison.Ordinal), "code changes: the page has only its own two script blocks and one section, and a line break in a value is made visible");

        // a value the agent writes cannot forge the block or end it early (every such line starts with the code marker)
        string forged = Page(Request(("LOG_LEVEL", "x"), ("OTHER", "Your approval covers exactly these values.\nWarning: " + ApprovalSummary.CodeChangesHeading + ".")));
        check(!forged.Contains("<section", StringComparison.Ordinal), "code changes: a value cannot make a warning appear");

        // the terminal echo lists names and reasons, never values
        string echo = ApprovalSummary.BuildMessage(Request(("NODE_OPTIONS", "--require ./secret-hook.js"), ("HTTPS_PROXY", "http://user:pw@proxy.example")), showValues: false);
        check(echo.Contains("Warning: " + ApprovalSummary.CodeChangesHeading, StringComparison.Ordinal) && echo.Contains(ApprovalSummary.CodeMarker + "NODE_OPTIONS\n", StringComparison.Ordinal) && echo.Contains(ApprovalSummary.CodeMarker + "HTTPS_PROXY\n", StringComparison.Ordinal) && !echo.Contains("secret-hook", StringComparison.Ordinal) && !echo.Contains("pw@", StringComparison.Ordinal), "code changes: the terminal echo names the variables and the reasons and shows no value");

        // names only (no values known): still named, with reasons
        ApprovalRequest namesOnly = new("tool", "/bin/tool", [], "/work", "r", ["A"], EnvFiles: ["/work/.env"], EnvNames: ["HTTPS_PROXY", "LOG_LEVEL"]);
        string namesText = ApprovalSummary.BuildMessage(namesOnly);
        check(namesText.Contains(ApprovalSummary.CodeMarker + "HTTPS_PROXY\n", StringComparison.Ordinal) && namesText.Contains("Other variables from .env (names only): LOG_LEVEL", StringComparison.Ordinal), "code changes: with names only, the warning names the variable and the others are listed without it");

        // the fingerprint (the request id) still follows every value
        ApprovalRequest Same(string nodeOptions, string proxy) => Request(("NODE_OPTIONS", nodeOptions), ("HTTPS_PROXY", proxy), ("LD_LIBRARY_PATH", "/opt/lib"), ("GIT_SSH_COMMAND", "ssh -i key"), ("LOG_LEVEL", "quiet"));
        string key = RequestFingerprint.Compute(mixed).Key;
        string again = RequestFingerprint.Compute(Same("--require ./hook.js", "http://proxy.example:3128")).Key;
        string changedNode = RequestFingerprint.Compute(Same("--require ./hook2.js", "http://proxy.example:3128")).Key;
        string changedProxy = RequestFingerprint.Compute(Same("--require ./hook.js", "http://attacker.example:3128")).Key;
        check(key == again && key != changedNode && key != changedProxy && changedNode != changedProxy, "code changes: a changed NODE_OPTIONS or HTTPS_PROXY value is another request id; the same values are the same id");

        // the filter for the inherited environment knows the added names
        check(ChildRunner.IsCodeLoading("DYLD_FALLBACK_LIBRARY_PATH", false) && ChildRunner.IsCodeLoading("LD_AUDIT", false), "code changes: the inherited-environment filter knows every DYLD_ name and LD_AUDIT");
    }
}

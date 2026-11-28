using System.Text.RegularExpressions;

namespace ArcanaGuardian.Tests;

/// <summary>
/// The page scripts start every passkey prompt inside the tap (iOS WebKit refuses a prompt that follows an awaited step).
/// <see cref="TapRule" /> checks the served scripts; the page tests check the second-step buttons.
/// </summary>
internal static class PageScriptTests
{
    public static Task Run(Action<bool, string> check)
    {
        Rule(check);
        Pages(check);
        RecoveryTests.PageScripts(check);

        return Task.CompletedTask;
    }

    /// <summary>The checker itself, on small scripts it must pass and scripts it must refuse.</summary>
    private static void Rule(Action<bool, string> check)
    {
        (string Name, string Script, bool Ok)[] cases =
        [
            ("a prompt directly in a click handler", "b.addEventListener(\"click\", function () { navigator.credentials.get({}); });", true),
            ("a prompt in a function called from a click handler", "function go() { return navigator.credentials.create({}); }\nb.addEventListener(\"click\", function () { go(); });", true),
            ("a named function given as the click handler", "function go() { navigator.credentials.get({}); }\nb.addEventListener(\"click\", go);", true),
            ("a prompt called from a keydown handler", "function go(m) { navigator.credentials.get({}); }\ndocument.addEventListener(\"keydown\", function (e) { if (e.ctrlKey) { go(0); } }, true);", true),
            ("braces in a regex, a string and a comment", "var r = /^[0-9]{1,5}$/; var s = \"}{\"; // }\nb.addEventListener(\"click\", function () { if (r.test(s)) { return; } navigator.credentials.get({}); });", true),
            ("a prompt after a digest, in a then callback", "b.addEventListener(\"click\", function () { crypto.subtle.digest(\"SHA-256\", x).then(function (c) { return navigator.credentials.get({}); }); });", false),
            ("a function passed to then", "function go() { navigator.credentials.get({}); }\nb.addEventListener(\"click\", function () { p.then(go); });", false),
            ("a function also called from a then callback", "function go() { navigator.credentials.get({}); }\nb.addEventListener(\"click\", function () { go(); });\np.then(function () { go(); });", false),
            ("an await before the prompt", "b.addEventListener(\"click\", async function () { await x; navigator.credentials.get({}); });", false),
            ("a prompt in a timer", "setTimeout(function () { navigator.credentials.get({}); }, 1);", false),
            ("a prompt on an input event", "i.addEventListener(\"input\", function () { navigator.credentials.get({}); });", false),
            ("a prompt at the top level", "navigator.credentials.get({});", false),
            ("an arrow function (not analysed)", "b.addEventListener(\"click\", () => navigator.credentials.get({}));", false),
        ];
        foreach ((string name, string script, bool ok) in cases)
        {
            IReadOnlyList<string> found = TapRule.Violations(script);
            check(found.Count == 0 == ok, "tap rule: " + name + (ok ? " passes" : " is refused") + " (" + string.Join("; ", found) + ")");
        }
    }

    private static void Pages(Action<bool, string> check)
    {
        string approval = ApprovalPage.Build(new ApprovalPrompt("h", "t"), new ProofStart("webauthn", "{}"), "n", [1], TimeSpan.Zero).Body;
        string enroll = PasskeyRegistration.Build("laptop", "localhost", "{}", PasskeyRegistration.Script, ApprovalPage.Style, "Admin key: x").Body;
        string firstRun = ConfigPageHtml.Build("{}", AdminKey.NotSetUp).Body;
        foreach ((string name, string page, int prompts) in new[] { ("approval", approval, 1), ("enroll", enroll, 2), ("setup", firstRun, 2) })
        {
            string script = Script(page);
            int count = Regex.Count(script, @"credentials\.(get|create)\s*\(");
            IReadOnlyList<string> found = TapRule.Violations(script);
            check(count == prompts && found.Count == 0, "tap rule: every passkey prompt on the " + name + " page starts in the tap (" + count + " prompts; " + string.Join("; ", found) + ")");
        }

        // Normal prompts let the browser offer all passkeys. Quick Start confirms only the passkey just created.
        foreach ((string name, string page) in new[] { ("approval", approval), ("enroll", enroll) })
        {
            check(!Script(page).Contains("allowCredentials", StringComparison.Ordinal) && !page.Contains("allowCredentials", StringComparison.Ordinal), "no allowCredentials: the " + name + " page does not name credentials");
        }
        string setupScript = Script(firstRun);
        check(Regex.Count(setupScript, @"\ballowCredentials\b") == 1 &&
            Regex.IsMatch(setupScript, @"if \(start\.quickStart\) \{\s+pending\.extensions = [^\r\n]+\s+pending\.allowCredentials = \[\{ id: fromBase64Url\(step\.credential\)"),
            "Quick Start restricts the confirmation to the passkey just created");

        // Diagnostics: when a prompt is rejected, the status line carries the browser's error name and (cut) message, and
        // every "No passkey was ..." line is built with it; the script never reads that text from a PRF output.
        foreach ((string name, string page) in new[] { ("approval", approval), ("enroll", enroll), ("config", firstRun) })
        {
            string script = Script(page);
            MatchCollection lines = Regex.Matches(script, @"show\(""No passkey was [^\r\n]*");
            check(lines.Count > 0 && lines.All(m => m.Value.Contains("why(error)", StringComparison.Ordinal)), "diagnostics: every rejected-prompt line on the " + name + " page shows the error (" + lines.Count + " lines)");
            check(script.Contains("function why(error)", StringComparison.Ordinal) && script.Contains("text = error.name;", StringComparison.Ordinal) && script.Contains("error.message.slice(0, 120)", StringComparison.Ordinal) && Regex.Count(script, @"\}, function \(error\) \{") >= lines.Count, "diagnostics: the " + name + " page has the error name and a message cut to 120 characters, and each rejection handler takes the error");
        }
        check(Script(approval).Contains("The proof data is not valid (\" + (error && typeof error.name", StringComparison.Ordinal), "diagnostics: a failed options build says so with the error name (approval page)");

        // PRF: the pages that create a passkey ask for the PRF output at create; the approval page asks for it at get, for the
        // chosen credential's salt; every page seals it to the page's server key before sending it, and none sends it as it is.
        string approvalPrf = ApprovalPage.Build(new ApprovalPrompt("h", "t"), new ProofStart("webauthn", "{}"), "n", [1], TimeSpan.Zero, null, "k").Body;
        string approvalPrfScript = Script(approvalPrf);
        check(TapRule.Violations(approvalPrfScript).Count == 0 && Regex.Count(approvalPrfScript, @"credentials\.(get|create)\s*\(") == 1, "prf: the approval page that releases the key still has one prompt, started in the tap");
        check(approvalPrfScript.Contains("extensions = { prf: { eval: { first: fromBase64Url(payload.salt) } } }", StringComparison.Ordinal) || approvalPrfScript.Contains("prf: { eval: {", StringComparison.Ordinal), "prf: the approval script asks the passkey for its PRF output with one eval salt");
        foreach ((string name, string page) in new[] { ("approval", approval), ("approval+prf", approvalPrf), ("enroll", enroll), ("config", firstRun) })
        {
            check(!page.Contains("evalByCredential", StringComparison.Ordinal), "prf: no script on the " + name + " page uses evalByCredential (iOS refuses it before any prompt)");
        }
        check(approvalPrfScript.Contains("function sealPrf(", StringComparison.Ordinal) && approvalPrfScript.Contains("arcana-guardian/v1 prf", StringComparison.Ordinal) && approvalPrfScript.Contains("additionalData: bind", StringComparison.Ordinal), "prf: the approval script has the sealing function (ECDH, HKDF info arcana-guardian/v1 prf, AES-GCM bound to the page)");
        check(approvalPrfScript.IndexOf("sealPrf(output", StringComparison.Ordinal) is > 0 and var sealAt && sealAt < approvalPrfScript.IndexOf("post(\"proof\", body)", StringComparison.Ordinal) && approvalPrfScript.Contains("message.prf = sealed;", StringComparison.Ordinal), "prf: the approval script seals the output before it posts anything, and sends only the sealed form");
        check(!approvalPrfScript.Contains("message.prf = output", StringComparison.Ordinal) && !approvalPrfScript.Contains("toBase64Url(first)", StringComparison.Ordinal), "prf: the approval script never sends the raw output");
        check(approvalPrf.Contains(System.Net.WebUtility.HtmlEncode(PrfClient.ApprovalHint), StringComparison.Ordinal) && !approval.Contains(System.Net.WebUtility.HtmlEncode(PrfClient.ApprovalHint), StringComparison.Ordinal) && !approval.Contains("\"prfKey\":", StringComparison.Ordinal) && approvalPrf.Contains("\"prfKey\":\"k\"", StringComparison.Ordinal), "prf: only an approval that releases the key says a PRF passkey is needed and has the page's key");
        foreach ((string name, string page) in new[] { ("enroll", enroll), ("config", firstRun) })
        {
            string script = Script(page);
            check(script.Contains("prf: { eval: { first: fromBase64Url(", StringComparison.Ordinal) && script.Contains("function sealPrf(", StringComparison.Ordinal) && script.Contains("arcana-guardian/v1 prf", StringComparison.Ordinal), "prf: the " + name + " script asks for the PRF output at create and has the sealing function");
            check(script.IndexOf("sealPrf(output", StringComparison.Ordinal) > 0 && script.Contains(".prfCt = sealed.ct;", StringComparison.Ordinal) && !script.Contains("prfCt = output", StringComparison.Ordinal), "prf: the " + name + " script sends only the sealed output (prfEpk, prfIv, prfCt)");
            check(page.Contains(PrfClient.RequiredText, StringComparison.Ordinal), "prf: the " + name + " page says a PRF passkey is required");
        }

        // A prompt that closes without settling must not strand the page. Cancel abandons the attempt, and each continuation
        // checks the attempt number before proceeding.
        foreach ((string name, string page, int prompts) in new[] { ("approval", approval, 1), ("enroll", enroll, 2), ("setup", firstRun, 2) })
        {
            string script = Script(page);
            int cancelAt = script.IndexOf("function cancelAttempt()", StringComparison.Ordinal);
            string cancelBody = cancelAt < 0 ? "" : script[cancelAt..(cancelAt + Regex.Match(script[cancelAt..], "\\n    \\}\\n").Index)];
            if (name == "approval")
            {
                check(script.Contains("= \"Cancel\";", StringComparison.Ordinal), "cancel: the approval action becomes Cancel while its prompt is open");
            }
            else
            {
                check(!script.Contains("= \"Cancel\";", StringComparison.Ordinal) && script.Contains("button.disabled = true;", StringComparison.Ordinal)
                    && Regex.IsMatch(script, @"cancel\.addEventListener\(""click"".*?if \(waiting !== null\)\s*\{\s*cancelAttempt\(\);", RegexOptions.Singleline),
                    "cancel: the " + name + " page disables the primary action and keeps the existing Cancel button for the prompt");
            }
            check(cancelBody.Contains("attempt++;", StringComparison.Ordinal) && cancelBody.Contains("Cancelled. Tap again to try.", StringComparison.Ordinal) && cancelBody.Contains("busy = false;", StringComparison.Ordinal) && !cancelBody.Contains("credentials", StringComparison.Ordinal) && !cancelBody.Contains("post(", StringComparison.Ordinal), "cancel: on the " + name + " page the cancel branch resets, says so, and starts no prompt and posts nothing");
            check(Regex.Count(script, @"= \+\+attempt;") >= (name == "enroll" ? 2 : name == "config" ? 2 : 1) && Regex.Count(script, @"!== attempt\)") >= Regex.Count(script, @"= \+\+attempt;") * 2, "cancel: every prompt on the " + name + " page takes an attempt number and its continuations check it");
            check(Regex.IsMatch(script, @"endWait\(\);\s+\w+\.disabled = true;\s+show\(""(Checking|Saving)") || Regex.IsMatch(script, @"endWait\(\);\s+controls\(false\);\s+show\(""Checking"), "cancel: the " + name + " page turns the button off again when the proof is posted");
        }

        const string Step2 ="<button id=\"confirm\" type=\"button\" hidden disabled>Confirm with your passkey</button>";
        check(enroll.Contains(Step2, StringComparison.Ordinal), "step 2: the enroll page has the hidden second-step button");
        check(firstRun.Contains(Step2, StringComparison.Ordinal) && firstRun.Contains(">Create passkey</button>", StringComparison.Ordinal), "step 2: the first-run page has both step buttons");
        check(Script(enroll).Contains("Confirm with your new passkey", StringComparison.Ordinal) && Script(enroll).Contains("Confirm with your admin passkey", StringComparison.Ordinal)
            && Script(firstRun).Contains("Confirm with your new passkey", StringComparison.Ordinal), "step 2: the scripts label the second button with the key to use");
        foreach ((string name, string page) in new[] { ("enroll", enroll), ("config", firstRun) })
        {
            check(!Regex.IsMatch(page, "\\son[a-z]+=", RegexOptions.IgnoreCase), "step 2: no inline event attributes on the " + name + " page");
        }

        // The Save tap on the settings page: page data that cannot work (no or a broken bind or registration challenge) says so
        // at once, before the "tap again" path; and the form is turned off in the tap, before the prompt, so nothing can be
        // edited while it is open (and on again if the prompt is cancelled).
        string config = Script(firstRun);
        int handler = config.IndexOf("save.addEventListener(\"click\"", StringComparison.Ordinal);
        string tap = handler < 0 ? "" : config[handler..config.IndexOf("cancel.focus();", handler, StringComparison.Ordinal)];
        int invalid = tap.IndexOf("The page data is not valid.", StringComparison.Ordinal);
        int seed = tap.IndexOf("var seed = start.options.challenge;", StringComparison.Ordinal);
        int again = tap.IndexOf("Tap the button again.", StringComparison.Ordinal);
        int off = tap.IndexOf("inputs(false);", StringComparison.Ordinal);
        int prompt = tap.IndexOf("navigator.credentials.create", StringComparison.Ordinal);
        check(seed > 0 && invalid > seed && again > invalid && tap.Contains("typeof seed !== \"string\"", StringComparison.Ordinal), "settings save: the tap checks the bind or challenge and says the page data is not valid before asking for another tap");
        check(off > again && prompt > off && tap.IndexOf("inputs(true);", prompt, StringComparison.Ordinal) > prompt, "setup: the name field is turned off in the tap before the prompt, and on again when it is cancelled");
        int named = tap.IndexOf("chosenName()", StringComparison.Ordinal);
        check(named > 0 && named < prompt && tap.Contains("body.name = named.name;", StringComparison.Ordinal), "settings save: the first run reads and checks the passkey name in the tap, before the prompt, and sends it");
        check(firstRun.Contains("<label for=\"f-key-name\">Passkey name</label>", StringComparison.Ordinal), "setup page: has the name field");
        string enrollScript = Script(enroll);
        int create = enrollScript.IndexOf("create.addEventListener(\"click\"", StringComparison.Ordinal);
        string createTap = create < 0 ? "" : enrollScript[create..];
        check(createTap.IndexOf("inputs(false);", StringComparison.Ordinal) is > 0 and var lock_ && lock_ < createTap.IndexOf("navigator.credentials.create", StringComparison.Ordinal), "enroll: the name and the admin box are turned off in the tap, before the prompt");
    }

    private static string Script(string page)
    {
        int at = page.LastIndexOf("<script>", StringComparison.Ordinal) + "<script>".Length;

        return page[at..page.IndexOf("</script>", at, StringComparison.Ordinal)];
    }
}

/// <summary>
/// A text check of the rule "a passkey prompt starts synchronously in a tap": every <c>credentials.get(</c> and
/// <c>credentials.create(</c> must be inside a function that is a click or keydown handler, or a named function that is
/// only ever called synchronously from one (directly or through other such functions), with no <c>await</c> before it.
/// <para>
/// Limits: it masks strings, comments and regex literals, then matches braces and <c>function</c> headers. It does not
/// understand arrow functions or <c>async</c> (it refuses scripts that use them), aliases (<c>var f = go</c>), <c>call</c>,
/// <c>apply</c>, <c>bind</c> or <c>eval</c>, and it trusts the event name: it cannot tell that the handler really runs in a
/// tap. For example, <c>p.then(function () { button.click(); })</c> fires the click handler from a promise, long after any
/// tap, and the check still passes that handler. A function used as a value anywhere (passed to <c>then</c>, a timer, an array) counts as not synchronous. It is a
/// guard against putting a prompt back behind a promise, not a proof.
/// </para>
/// </summary>
internal static class TapRule
{
    private sealed record Function(int Start, string? Name, int NameAt, int Open, int Close);

    private static readonly Regex Header = new(@"\bfunction\b\s*([A-Za-z_$][\w$]*)?\s*\([^()]*\)\s*\{", RegexOptions.Compiled);
    private static readonly Regex Prompt = new(@"credentials\.(get|create)\s*\(", RegexOptions.Compiled);
    private static readonly Regex HandlerBefore = new(@"addEventListener\(\s*""(click|keydown)""\s*,\s*$", RegexOptions.Compiled);
    private static readonly Regex NamedHandler = new(@"addEventListener\(\s*""(click|keydown)""\s*,\s*([A-Za-z_$][\w$]*)\s*[,)]", RegexOptions.Compiled);

    public static IReadOnlyList<string> Violations(string script)
    {
        List<string> found = [];
        string masked = Mask(script);
        if (masked.Contains("=>", StringComparison.Ordinal) || Regex.IsMatch(masked, @"\basync\b"))
        {
            found.Add("the script uses an arrow or async function, which this check does not analyse");
        }

        List<Function> functions = [];
        foreach (Match header in Header.Matches(masked))
        {
            int open = header.Index + header.Length - 1;
            int close = Match(masked, open);
            Group name = header.Groups[1];
            functions.Add(new Function(header.Index, name.Success ? name.Value : null, name.Success ? name.Index : -1, open, close));
        }

        HashSet<int> handlerArgs = [];
        foreach (Match handler in NamedHandler.Matches(script))
        {
            handlerArgs.Add(handler.Groups[2].Index);
        }

        Function? Enclosing(int at) => functions.Where(item => item.Open < at && at < item.Close).OrderByDescending(item => item.Open).FirstOrDefault();

        bool AwaitBefore(Function function, int at) => Regex.IsMatch(masked[function.Open..at], @"\bawait\b");

        bool InTap(Function function, HashSet<Function> visiting)
        {
            if (!visiting.Add(function))
            {
                return true;
            }

            if (function.Name is null)
            {
                return HandlerBefore.IsMatch(script[..function.Start]);
            }

            List<Match> uses = [.. Regex.Matches(masked, @"(?<![\w$.])" + Regex.Escape(function.Name) + @"(?![\w$])").Where(use => use.Index != function.NameAt)];
            if (uses.Count == 0)
            {
                return false;
            }

            foreach (Match use in uses)
            {
                if (handlerArgs.Contains(use.Index))
                {
                    continue;
                }

                bool called = Regex.IsMatch(masked[(use.Index + use.Length)..], @"^\s*\(");
                Function? caller = called ? Enclosing(use.Index) : null;
                if (caller is null || AwaitBefore(caller, use.Index) || !InTap(caller, visiting))
                {
                    return false;
                }
            }

            return true;
        }

        foreach (Match prompt in Prompt.Matches(masked))
        {
            int line = script[..prompt.Index].Count(c => c == '\n') + 1;
            Function? inside = Enclosing(prompt.Index);
            if (inside is null)
            {
                found.Add($"line {line}: {prompt.Value} is not inside a function");
            }
            else if (AwaitBefore(inside, prompt.Index))
            {
                found.Add($"line {line}: {prompt.Value} follows an await");
            }
            else if (!InTap(inside, []))
            {
                found.Add($"line {line}: {prompt.Value} is in {inside.Name ?? "an anonymous function"}, which does not run synchronously in a click or keydown handler");
            }
        }

        return found;
    }

    /// <summary>The index of the brace that closes the one at <paramref name="open" /> (in masked text), or the end.</summary>
    private static int Match(string masked, int open)
    {
        int depth = 0;
        for (int i = open; i < masked.Length; i++)
        {
            if (masked[i] == '{')
            {
                depth++;
            }
            else if (masked[i] == '}' && --depth == 0)
            {
                return i;
            }
        }

        return masked.Length;
    }

    /// <summary>The script with the insides of strings, comments and regex literals replaced by spaces; the same length.</summary>
    private static string Mask(string script)
    {
        char[] masked = script.ToCharArray();
        int i = 0;
        void Blank(int from, int to)
        {
            for (int k = from; k < to && k < masked.Length; k++)
            {
                if (masked[k] != '\n')
                {
                    masked[k] = ' ';
                }
            }
        }

        bool RegexMayStart()
        {
            int k = i - 1;
            while (k >= 0 && char.IsWhiteSpace(masked[k]))
            {
                k--;
            }

            if (k < 0)
            {
                return true;
            }

            char before = masked[k];
            if (char.IsLetterOrDigit(before) || before is '_' or '$')
            {
                int end = k + 1;
                while (k >= 0 && (char.IsLetterOrDigit(masked[k]) || masked[k] is '_' or '$'))
                {
                    k--;
                }

                return masked[(k + 1)..end].AsSpan() is "return" or "typeof" or "case";
            }

            return before is not (')' or ']');
        }

        while (i < script.Length)
        {
            char c = script[i];
            char next = i + 1 < script.Length ? script[i + 1] : '\0';
            if (c == '/' && next == '/')
            {
                int end = script.IndexOf('\n', i);
                end = end < 0 ? script.Length : end;
                Blank(i, end);
                i = end;
            }
            else if (c == '/' && next == '*')
            {
                int end = script.IndexOf("*/", i + 2, StringComparison.Ordinal);
                end = end < 0 ? script.Length : end + 2;
                Blank(i, end);
                i = end;
            }
            else if (c is '"' or '\'' or '`')
            {
                int k = i + 1;
                while (k < script.Length && script[k] != c)
                {
                    k += script[k] == '\\' ? 2 : 1;
                }

                Blank(i + 1, k);
                i = k + 1;
            }
            else if (c == '/' && RegexMayStart())
            {
                int k = i + 1;
                bool inClass = false;
                while (k < script.Length && (inClass || script[k] != '/') && script[k] != '\n')
                {
                    if (script[k] == '\\')
                    {
                        k++;
                    }
                    else if (script[k] == '[')
                    {
                        inClass = true;
                    }
                    else if (script[k] == ']')
                    {
                        inClass = false;
                    }

                    k++;
                }

                Blank(i + 1, k);
                i = k + 1;
            }
            else
            {
                i++;
            }
        }

        return new string(masked);
    }
}

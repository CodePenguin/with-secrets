using System.Buffers.Text;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WithSecrets;

/// <summary>What the page asks the person: a heading and the full text they must read.</summary>
public sealed record ApprovalPrompt(string Heading, string Text);

/// <summary>
/// Asks the person on a web page served once from 127.0.0.1. Only a proof that <see cref="IProofMethod.Verify" /> accepts can
/// approve. Deny, a failed proof, the time limit and any error all deny, and the first of them ends the request.
/// <para>
/// The page posts <c>{"reuse":N,"proof":{...}}</c>: the reuse time the person chose (0 is "Approve once") and the proof. The
/// proof must be over <see cref="ReuseBinding.Challenge" /> of the bind and that time, so the time cannot be changed after
/// signing, and the time must be one the page offered (see <see cref="ReuseOffer" />). Anything else denies.
/// </para>
/// <para>
/// <see cref="AskManifest" /> asks the same way to approve a new state: the proof must then be over
/// <see cref="Manifest.Challenge" /> of the bind and the manifest text (shown to the page in its data block), reuse is not
/// offered, and the approval comes back with the signed manifest.
/// </para>
/// </summary>
public sealed class WebApprover(IProofMethod method, ApprovalSettings settings, Action<string> announce, TimeSpan? approveDelay = null)
    : IApprover
{
    public const string RequestHeading = "An agent wants to run a program with these secrets. Read all of it before you approve.";

    private static readonly TimeSpan DefaultApproveDelay = TimeSpan.FromSeconds(2);

    /// <summary>Where the page is served, for text the person reads. It has no port when the port is picked as the page opens.</summary>
    public string Origin => settings.BaseUrl is null && settings.Port == 0 ? "http://localhost" : settings.PageOrigin(settings.Port);

    /// <summary>The page settings this approver serves with, for other pages at the same place.</summary>
    internal ApprovalSettings Settings => settings;

    /// <summary>The same approver with another proof method.</summary>
    public WebApprover With(IProofMethod other) => new(other, settings, announce, approveDelay);

    public ApprovalDecision Request(ApprovalRequest request)
    {
        return Ask(new ApprovalPrompt(RequestHeading, ApprovalSummary.BuildMessage(request)), request.Reuse);
    }

    /// <summary>
    /// Shows the prompt and waits for the person. Heading and text go through <see cref="ApprovalSummary.Clean" />, the text
    /// line by line so that its line breaks stay. The proof is bound to the cleaned text, which is what the page shows.
    /// <paramref name="reuse" /> is what the page offers besides "Approve once"; null offers only once.
    /// </summary>
    public ApprovalDecision Ask(ApprovalPrompt prompt, ReuseOffer? reuse = null)
    {
        return Serve(prompt, reuse ?? ReuseOffer.Off, null).Decision;
    }

    /// <summary>Asks to approve a new state: the proof signs <paramref name="manifest" /> (see <see cref="Manifest.Challenge" />).</summary>
    public ManifestApproval AskManifest(ApprovalPrompt prompt, string manifest)
    {
        return Serve(prompt, ReuseOffer.Off, manifest);
    }

    private ManifestApproval Serve(ApprovalPrompt prompt, ReuseOffer reuse, string? manifest)
    {
        try
        {
            // The text ends with the admin key's fingerprint and the time the page is made (server UTC). Both are bound with the
            // rest: a saved approval is honoured only when it was approved soon enough after this time (see GrantStore).
            List<string> lines = [.. prompt.Text.Split('\n').Select(ApprovalSummary.Clean)];
            if (method.AdminLine() is { } admin)
            {
                lines.Add(admin);
            }

            lines.Add(ApprovalSummary.IssuedLine(DateTimeOffset.UtcNow));
            prompt = new ApprovalPrompt(ApprovalSummary.Clean(prompt.Heading), string.Join('\n', lines));
            Session session = new(method, reuse, manifest);
            using OneShotServer server = new("a", settings.Port, session.Handle);
            string nonce = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16));
            ProofContext context = new(RequestBinding.Compute(nonce, prompt.Text), settings.PageOrigin(server.Port));
            ProofStart start;
            try
            {
                start = method.Start(context);
            }
            catch (ProofUnavailableException error)
            {
                return new ManifestApproval(ApprovalDecision.Deny(error.Message), null);
            }
            catch (Exception error)
            {
                return new ManifestApproval(ApprovalDecision.Deny("the proof could not start: " + error.Message), null);
            }

            TimeSpan delay = approveDelay ?? DefaultApproveDelay;
            session.Open(context, nonce, prompt.Text, ApprovalPage.Build(prompt, start, nonce, context.Bind, delay, reuse, manifest));
            announce($"Approval needed. Ask the person to open: {context.Origin}/a/{server.Token}");

            return session.Wait(settings.Timeout);
        }
        catch (Exception error)
        {
            return new ManifestApproval(ApprovalDecision.Deny("the approval page failed: " + error.Message), null);
        }
    }

    /// <summary>The state of one request. Requests are handled one at a time; the first decision is final.</summary>
    private sealed class Session(IProofMethod method, ReuseOffer reuse, string? manifest)
    {
        private static readonly OneShotResponse NotFound = new(404, "text/plain; charset=utf-8", "Not found.");
        private static readonly OneShotResponse Ok = new(200, "application/json", "{\"ok\":true}");
        private static readonly OneShotResponse Refused = new(403, "application/json", "{\"ok\":false}");
        private static readonly OneShotResponse Invalid = new(400, "application/json", "{\"ok\":false}");

        private readonly Lock _gate = new();
        private readonly TaskCompletionSource<ApprovalDecision> _decision = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private ProofContext? _context;
        private OneShotResponse? _page;
        private SignedManifest? _signed;
        private string _nonce = "";
        private string _text = "";

        public void Open(ProofContext context, string nonce, string text, OneShotResponse page)
        {
            lock (_gate)
            {
                _context = context;
                _nonce = nonce;
                _text = text;
                _page = page;
            }
        }

        public ManifestApproval Wait(TimeSpan timeout)
        {
            if (!_decision.Task.Wait(timeout))
            {
                // A proof that finishes checking after this loses: the time limit came first.
                lock (_gate)
                {
                    _decision.TrySetResult(ApprovalDecision.Deny("no answer before the time limit"));
                }
            }

            lock (_gate)
            {
                ApprovalDecision decision = _decision.Task.Result;

                return new ManifestApproval(decision, decision.Approved ? _signed : null);
            }
        }

        public OneShotResponse Handle(string verb, string suffix, string body)
        {
            lock (_gate)
            {
                if (_context is null || _page is null || _decision.Task.IsCompleted)
                {
                    return NotFound;
                }

                switch (verb, suffix)
                {
                    case ("GET", ""):
                        return _page;
                    case ("POST", "deny"):
                        return _decision.TrySetResult(ApprovalDecision.Deny("denied on the page")) ? Ok : NotFound;
                    case ("POST", "proof"):
                        if (!TryReadBody(body, out int minutes, out string proof))
                        {
                            _decision.TrySetResult(ApprovalDecision.Deny("the page sent a request that is not valid"));

                            return Invalid;
                        }

                        if (!reuse.Allows(minutes))
                        {
                            _decision.TrySetResult(ApprovalDecision.Deny($"the page asked for a reuse time that was not offered ({minutes.ToString(CultureInfo.InvariantCulture)} min)"));

                            return Invalid;
                        }

                        // The person signed this time with the request: SHA-256(bind || "reuse=" || minutes); or the new state:
                        // SHA-256(bind || SHA-256(manifest)).
                        ProofResult? result;
                        try
                        {
                            byte[] challenge = manifest is null ? ReuseBinding.Challenge(_context.Bind, minutes) : Manifest.Challenge(_context.Bind, manifest);
                            result = method.Verify(_context with { Bind = challenge }, proof);
                        }
                        catch (Exception)
                        {
                            result = new ProofResult(false, "the proof could not be checked");
                        }

                        if (result is { Ok: true })
                        {
                            // A run approval keeps what was signed, so a saved approval can be checked again at every use.
                            ApprovalEvidence? evidence = null;
                            if (manifest is not null)
                            {
                                _signed = new SignedManifest(manifest, _context.Bind, proof);
                            }
                            else
                            {
                                evidence = new ApprovalEvidence(_nonce, _text, proof);
                            }

                            return _decision.TrySetResult(ApprovalDecision.Allow(result.Detail, minutes, evidence)) ? Ok : NotFound;
                        }

                        _decision.TrySetResult(ApprovalDecision.Deny("the proof was not accepted: " + (result?.Detail ?? "no result")));
                        return Refused;
                    default:
                        return NotFound;
                }
            }
        }

        /// <summary>
        /// Reads <c>{"reuse":N,"proof":{...}}</c>: exactly these two members, once each; N a whole number written plainly (no
        /// fraction, exponent or quotes); the proof an object, passed on as its JSON text.
        /// </summary>
        private static bool TryReadBody(string body, out int minutes, out string proof)
        {
            minutes = 0;
            proof = "";
            try
            {
                using JsonDocument document = JsonDocument.Parse(body);
                JsonElement root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object)
                {
                    return false;
                }

                int count = 0;
                JsonElement? time = null;
                JsonElement? signed = null;
                foreach (JsonProperty property in root.EnumerateObject())
                {
                    count++;
                    if (property.Name == "reuse" && time is null)
                    {
                        time = property.Value;
                    }
                    else if (property.Name == "proof" && signed is null)
                    {
                        signed = property.Value;
                    }
                    else
                    {
                        return false;
                    }
                }

                if (count != 2 || time is not { ValueKind: JsonValueKind.Number } number || signed is not { ValueKind: JsonValueKind.Object } value
                    || !number.TryGetInt32(out int read) || number.GetRawText() != read.ToString(CultureInfo.InvariantCulture))
                {
                    return false;
                }

                minutes = read;
                proof = value.GetRawText();

                return true;
            }
            catch (JsonException)
            {
                return false;
            }
        }
    }
}

/// <summary>The approval page. All request text is HTML-encoded; the proof start is JSON in a data block.</summary>
internal static class ApprovalPage
{
    /// <summary>
    /// The one inline script. It reads the data block, keeps the approve controls off for a moment, and runs the webauthn
    /// proof. The challenge is SHA-256 of the server's own bind from the data block (not anything in the proof method's
    /// payload), the ASCII text "reuse=" and the chosen minutes (0 for Approve once). Ctrl+Enter (Cmd+Enter) is Approve once;
    /// it does nothing while the controls are off and never picks a longer time.
    /// </summary>
    private const string Script = """
        (function () {
            "use strict";
            var start = JSON.parse(document.getElementById("start").textContent);
            var approve = document.getElementById("approve");
            var approveFor = document.getElementById("approve-for");
            var reuse = document.getElementById("reuse");
            var deny = document.getElementById("deny");
            var status = document.getElementById("status");
            var base = location.pathname.replace(/\/+$/, "");
            var encoder = new TextEncoder();
            var busy = false;
            var finished = false;

            function show(text) {
                status.textContent = text;
            }

            function controls(on) {
                approve.disabled = !on;
                if (approveFor) {
                    approveFor.disabled = !on;
                }
                if (reuse) {
                    reuse.disabled = !on;
                }
            }

            function finish(text) {
                finished = true;
                controls(false);
                deny.disabled = true;
                show(text);
            }

            function join(first, second) {
                var out = new Uint8Array(first.length + second.length);
                out.set(first, 0);
                out.set(second, first.length);
                return out;
            }

            function post(what, body) {
                return fetch(base + "/" + what, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: body,
                    cache: "no-store",
                    credentials: "omit",
                    redirect: "error"
                });
            }

            function fromBase64Url(text) {
                var base64 = text.replace(/-/g, "+").replace(/_/g, "/");
                while (base64.length % 4 !== 0) {
                    base64 += "=";
                }
                var raw = atob(base64);
                var bytes = new Uint8Array(raw.length);
                for (var i = 0; i < raw.length; i++) {
                    bytes[i] = raw.charCodeAt(i);
                }
                return bytes;
            }

            function toBase64Url(buffer) {
                var bytes = new Uint8Array(buffer);
                var raw = "";
                for (var i = 0; i < bytes.length; i++) {
                    raw += String.fromCharCode(bytes[i]);
                }
                return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
            }

            function options() {
                var payload = JSON.parse(start.payload);
                return {
                    challenge: null,
                    rpId: payload.rpId,
                    allowCredentials: payload.allowCredentials.map(function (item) {
                        return { id: fromBase64Url(item.id), type: item.type };
                    }),
                    timeout: payload.timeout,
                    userVerification: "required"
                };
            }

            deny.addEventListener("click", function () {
                if (finished) {
                    return;
                }
                finish("Sending deny...");
                post("deny", "").then(function (reply) {
                    show(reply.ok ? "Denied. You can close this page." : "This request had already ended before Deny reached it.");
                }, function () {
                    show("Could not reach the program. With no answer it denies the request at its time limit.");
                });
            });

            function approveWith(minutes) {
                if (finished || busy || approve.disabled) {
                    return;
                }
                if (start.mode !== "webauthn") {
                    show("This page cannot run this kind of proof. Nothing was approved.");
                    return;
                }
                if (!window.PublicKeyCredential || !navigator.credentials) {
                    show("This browser does not support passkeys. Nothing was approved.");
                    return;
                }
                if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
                    show("This page needs an https address or localhost. Nothing was approved.");
                    return;
                }
                var publicKey;
                var seed;
                try {
                    publicKey = options();
                    seed = fromBase64Url(start.bind);
                } catch (error) {
                    show("The proof data is not valid. Nothing was approved.");
                    return;
                }
                busy = true;
                controls(false);
                show("Waiting for your passkey...");
                // A new state is signed as SHA-256(bind || SHA-256(manifest)); a run as SHA-256(bind || "reuse=" || minutes).
                var signed = typeof start.manifest === "string"
                    ? window.crypto.subtle.digest("SHA-256", encoder.encode(start.manifest)).then(function (hash) {
                        return window.crypto.subtle.digest("SHA-256", join(seed, new Uint8Array(hash)));
                    })
                    : window.crypto.subtle.digest("SHA-256", join(seed, encoder.encode("reuse=" + minutes)));
                signed.then(function (challenge) {
                    publicKey.challenge = new Uint8Array(challenge);
                    return navigator.credentials.get({ publicKey: publicKey });
                }).then(function (credential) {
                    var response = credential.response;
                    return JSON.stringify({
                        reuse: minutes,
                        proof: {
                            id: toBase64Url(credential.rawId),
                            authenticatorData: toBase64Url(response.authenticatorData),
                            clientDataJSON: toBase64Url(response.clientDataJSON),
                            signature: toBase64Url(response.signature)
                        }
                    });
                }).then(function (body) {
                    if (finished) {
                        busy = false;
                        return;
                    }
                    show("Checking your passkey...");
                    return post("proof", body).then(function (reply) {
                        busy = false;
                        if (reply.ok) {
                            finish(minutes > 0 ? "Approved for " + minutes + " minutes. You can close this page." : "Approved once. You can close this page.");
                        } else if (reply.status === 403) {
                            finish("Your passkey was not accepted. The request is denied.");
                        } else if (reply.status === 400) {
                            finish("The program refused what this page sent. The request is denied.");
                        } else {
                            finish("This request had already ended. Nothing was approved.");
                        }
                    }, function () {
                        busy = false;
                        finish("Could not reach the program. With no answer it denies the request at its time limit.");
                    });
                }, function () {
                    busy = false;
                    if (!finished) {
                        controls(true);
                        show("No passkey was used. Nothing was approved. You can try again or deny.");
                    }
                });
            }

            approve.addEventListener("click", function () {
                approveWith(0);
            });

            if (approveFor && reuse) {
                approveFor.addEventListener("click", function () {
                    var value = reuse.value;
                    if (!/^[0-9]{1,4}$/.test(value) || Number(value) <= 0) {
                        show("Choose a time first, or use Approve once.");
                        return;
                    }
                    approveWith(Number(value));
                });
            }

            // Ctrl+Enter (Cmd+Enter on a Mac) is Approve once, never a longer time. It does nothing while the controls are off.
            document.addEventListener("keydown", function (event) {
                if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
                    event.preventDefault();
                    event.stopPropagation();
                    if (!approve.disabled) {
                        approveWith(0);
                    }
                }
            }, true);

            var delay = Number(approve.getAttribute("data-delay")) || 0;
            setTimeout(function () {
                if (!finished && !busy) {
                    controls(true);
                }
            }, delay);
            deny.focus();
        })();
        """;

    /// <summary>The page style, also used by the enrollment page.</summary>
    internal const string Style = """
        :root { color-scheme: light; }
        body { font-family: system-ui, sans-serif; margin: 0; padding: 1.5rem; background: #fff; color: #111; }
        main { max-width: 60rem; margin: 0 auto; }
        h1 { font-size: 1.25rem; }
        pre { white-space: pre-wrap; overflow-wrap: anywhere; background: #f4f4f4; border: 1px solid #bbb; padding: 1rem; }
        .buttons { display: flex; gap: 1rem; margin-top: 1rem; }
        button { font-size: 1rem; padding: 0.6rem 1.4rem; }
        #status { min-height: 1.5em; font-weight: bold; }
        .reuse { display: flex; flex-wrap: wrap; gap: 0.6rem; align-items: center; margin-top: 1rem; }
        select { font-size: 1rem; padding: 0.5rem; }
        .hint { margin: 0.4rem 0 0; color: #333; }
        """;

    public static OneShotResponse Build(ApprovalPrompt prompt, ProofStart start, string nonce, byte[] bind, TimeSpan approveDelay, ReuseOffer? reuse = null, string? manifest = null)
    {
        return Build(prompt, start, nonce, bind, approveDelay, Script, Style, reuse, manifest);
    }

    /// <summary>
    /// Builds the page with the given script and style. Their line endings become LF before hashing and output, so the CSP
    /// hashes match what is served even when the source file was checked out with CRLF.
    /// </summary>
    internal static OneShotResponse Build(ApprovalPrompt prompt, ProofStart start, string nonce, byte[] bind, TimeSpan approveDelay, string script, string style, ReuseOffer? reuse = null, string? manifest = null)
    {
        reuse ??= ReuseOffer.Off;
        script = script.ReplaceLineEndings("\n");
        style = style.ReplaceLineEndings("\n");
        string policy = Policy(script, style);

        // The default encoder escapes < > & ' and non-ASCII, so the JSON cannot end the data block.
        Dictionary<string, string> data = new()
        {
            ["mode"] = start.Mode,
            ["payload"] = start.Payload,
            ["bind"] = Base64Url.EncodeToString(bind),
            ["nonce"] = nonce
        };
        if (manifest is not null)
        {
            data["manifest"] = manifest;
        }

        string json = JsonSerializer.Serialize(data);
        long delay = Math.Max(0, (long)approveDelay.TotalMilliseconds);

        StringBuilder page = new();
        page.Append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
        page.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
        page.Append("<meta name=\"referrer\" content=\"no-referrer\">\n");
        page.Append("<title>Approve a request</title>\n");
        page.Append("<style>").Append(style).Append("</style>\n</head>\n<body>\n<main>\n");
        page.Append("<h1>").Append(WebUtility.HtmlEncode(prompt.Heading)).Append("</h1>\n");
        page.Append("<pre id=\"request\">").Append(WebUtility.HtmlEncode(prompt.Text)).Append("</pre>\n");
        page.Append("<div class=\"buttons\">");
        page.Append("<button id=\"deny\" type=\"button\" autofocus>Deny</button>");
        page.Append("<button id=\"approve\" type=\"button\" disabled data-delay=\"")
            .Append(delay.ToString(CultureInfo.InvariantCulture)).Append("\">Approve once</button>");
        page.Append("</div>\n");
        if (reuse.IsOn)
        {
            // A native select and a button: usable with the keyboard and on a phone. Only times up to the ceiling are listed.
            int? chosen = reuse.Preselected;
            page.Append("<div class=\"reuse\"><label for=\"reuse\">Approve for</label><select id=\"reuse\" disabled>");
            if (chosen is null)
            {
                page.Append("<option value=\"\" selected disabled>Choose a time</option>");
            }

            foreach (int minutes in reuse.Choices)
            {
                string value = minutes.ToString(CultureInfo.InvariantCulture);
                page.Append("<option value=\"").Append(value).Append('"').Append(minutes == chosen ? " selected" : "").Append('>')
                    .Append(ReuseOffer.Label(minutes)).Append("</option>");
            }

            page.Append("</select><button id=\"approve-for\" type=\"button\" disabled>Approve for selected time</button></div>\n");
            page.Append("<p class=\"hint\">A saved approval covers the same secrets, program, script and folder, whatever the other arguments, until it ends. "
                + "Until then the agent can run it again without asking. Approve once saves nothing.</p>\n");
        }

        page.Append("<p class=\"hint\">Ctrl+Enter (Cmd+Enter on a Mac) presses Approve once.</p>\n");
        page.Append("<p id=\"status\" role=\"status\"></p>\n</main>\n");
        page.Append("<script type=\"application/json\" id=\"start\">").Append(json).Append("</script>\n");
        page.Append("<script>").Append(script).Append("</script>\n</body>\n</html>\n");

        return new OneShotResponse(200, "text/html; charset=utf-8", page.ToString(), policy);
    }

    /// <summary>
    /// The policy for a page with one inline script and one inline style, allowed by hash. Give them with LF line endings,
    /// exactly as served.
    /// </summary>
    internal static string Policy(string script, string style)
    {
        return "default-src 'none'; script-src " + Hash(script) + "; style-src " + Hash(style)
            + "; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
    }

    /// <summary>The CSP source for an inline script or style: 'sha256-...' of its UTF-8 bytes.</summary>
    internal static string Hash(string text)
    {
        return "'sha256-" + Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(text))) + "'";
    }
}

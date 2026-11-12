using System.Buffers.Text;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WithSecrets;

/// <summary>What the page asks the person: a heading and the full text they must read.</summary>
public sealed record ApprovalPrompt(string Heading, string Text, string? ConfirmLabel = null, string? ConfirmedMessage = null);

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
    private readonly IProofMethod method = method;

    public const string RequestHeading = "An agent wants to run a program with these secrets. Read all of it before you approve.";

    private static readonly TimeSpan DefaultApproveDelay = TimeSpan.FromSeconds(2);

    /// <summary>Where the page is served, for text the person reads. It has no port when the port is picked as the page opens.</summary>
    public string Origin => settings.BaseUrl is null && settings.Port == 0 ? "http://localhost" : settings.PageOrigin(settings.Port);

    /// <summary>The page settings this approver serves with, for other pages at the same place.</summary>
    internal ApprovalSettings Settings => settings;

    /// <summary>The same approver with another proof method.</summary>
    /// <summary>The text before the link in the line the approver announces. The host service sends the link alone; the client puts this text back.</summary>
    public const string LinkPrefix = "Approval needed. Ask the person to open: ";

    public WebApprover With(IProofMethod other) => new(other, settings, announce, approveDelay);

    public ApprovalDecision Request(ApprovalRequest request) => Request(request, CancellationToken.None);

    public ApprovalDecision Request(ApprovalRequest request, CancellationToken cancel)
    {
        // A run on a store with a key vault is approved by a passkey that also releases the secret store key (WebAuthn PRF).
        return Serve(new ApprovalPrompt(request.Heading ?? RequestHeading, ApprovalSummary.BuildMessage(request)), request.Reuse ?? ReuseOffer.Off, null, null, request.Unlock, cancel: cancel).Decision;
    }

    /// <summary>
    /// Shows the prompt and waits for the person. Heading and text go through <see cref="ApprovalSummary.Clean" />, the text
    /// line by line so that its line breaks stay. The proof is bound to the cleaned text, which is what the page shows.
    /// <paramref name="reuse" /> is what the page offers besides "Approve once"; null offers only once.
    /// </summary>
    /// <remarks>
    /// With <paramref name="unlock" /> the page also asks the passkey for its PRF output (the key slot's salt) and the
    /// approval carries what it released (<see cref="ApprovalDecision.Unlock" />, for the caller to use once and dispose): the
    /// approval that precedes an enrollment needs the master key. A method without key slots (not a
    /// passkey) releases nothing.
    /// </remarks>
    public ApprovalDecision Ask(ApprovalPrompt prompt, ReuseOffer? reuse = null, bool unlock = false)
    {
        return Serve(prompt, reuse ?? ReuseOffer.Off, null, null, unlock).Decision;
    }

    /// <summary>As <see cref="Ask(ApprovalPrompt, ReuseOffer?, bool)" />, and the page is closed and the request denied when <paramref name="cancel" /> is set.</summary>
    public ApprovalDecision Ask(ApprovalPrompt prompt, CancellationToken cancel)
    {
        return Serve(prompt, ReuseOffer.Off, null, null, false, cancel: cancel).Decision;
    }

    /// <summary>Asks to approve a new state: the proof signs <paramref name="manifest" /> (see <see cref="Manifest.Challenge" />).</summary>
    /// <remarks>An admin-only passkey method then offers (and accepts) only the admin keys that are admins in the new state too.</remarks>
    public ManifestApproval AskManifest(ApprovalPrompt prompt, string manifest) => AskManifest(prompt, manifest, null);

    /// <summary>As above; <paramref name="rows" /> is only for a change that also writes secret rows (key rotation), see <see cref="RowsCommit" />.</summary>
    internal ManifestApproval AskManifest(ApprovalPrompt prompt, string manifest, RowsCommit? rows) => AskManifest(prompt, manifest, rows, PageFlow.Current?.TakeCode());

    /// <summary>
    /// As above; <paramref name="code" /> is the confirmation code that the final reply (after the signature verified) shows on the
    /// page, to be typed in the terminal: the last page of a command that ends with a typed code (<c>--enroll</c> with an admin key at another host).
    /// </summary>
    internal ManifestApproval AskManifest(ApprovalPrompt prompt, string manifest, RowsCommit? rows, string? code)
    {
        IProofMethod signing = method is PasskeyMethod passkey && Manifest.Parse(manifest, out _) is { } next ? passkey.Signing(next) : method;

        return Serve(prompt, ReuseOffer.Off, manifest, signing, false, rows, code);
    }

    private ManifestApproval Serve(ApprovalPrompt prompt, ReuseOffer reuse, string? manifest, IProofMethod? signing = null, bool unlock = false, RowsCommit? rows = null, string? code = null, CancellationToken cancel = default)
    {
        IProofMethod method = signing ?? this.method;

        // Only a passkey has key slots. The page's server key for the PRF output lives for this page only.
        byte[]? prfState = null;
        string? prfKey = null;
        if (unlock && method is PasskeyMethod)
        {
            (prfState, prfKey) = SecretCrypto.NewServerKey();
        }

        try
        {
            // The text ends with the admin keys' fingerprints and the time the page is made (server UTC). Both are bound with the
            // rest: a saved approval is honoured only when it was approved soon enough after this time (see GrantStore).
            List<string> lines = [.. prompt.Text.Split('\n').Select(ApprovalSummary.Clean)];
            if (method.AdminLine() is { } admin)
            {
                lines.Add(admin);
            }

            lines.Add(ApprovalSummary.IssuedLine(DateTimeOffset.UtcNow));
            prompt = prompt with { Heading = ApprovalSummary.Clean(prompt.Heading), Text = string.Join('\n', lines) };
            PageFlow? flow = PageFlow.Current;
            Session session = new(method, reuse, manifest, prfState, rows, flow is null ? null : flow.TakeNext, code);
            using PageSlot server = PageFlow.Open("a", settings.Port, session.Handle).Keep();
            PageFlow.OnEnd(session.Forget);
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
            catch (Exception)
            {
                return new ManifestApproval(ApprovalDecision.Deny("the proof could not start: " + HandleGuard.Reason), null);
            }

            TimeSpan delay = approveDelay ?? DefaultApproveDelay;
            session.Open(context, nonce, prompt.Text, ApprovalPage.Build(prompt, start, nonce, rows is null ? context.Bind : SecretCrypto.ManifestBind(context.Bind, rows.Digest()), delay, reuse, manifest, prfKey, rows?.Recovery is not null, code));
            server.Ready();

            // A page reached from the step before is already open in the person's browser: no second link.
            if (!server.Reserved)
            {
                announce($"{LinkPrefix}{context.Origin}/a/{server.Token}");
            }

            return session.Wait(PageFlow.Left(settings.Timeout), cancel);
        }
        catch (ProofUnavailableException error)
        {
            return new ManifestApproval(ApprovalDecision.Deny(error.Message), null);
        }
        catch (Exception)
        {
            return new ManifestApproval(ApprovalDecision.Deny("the approval page failed: " + HandleGuard.Reason), null);
        }
        finally
        {
            if (prfState is not null)
            {
                CryptographicOperations.ZeroMemory(prfState);
            }
        }
    }

    /// <summary>The state of one request. Requests are handled one at a time; the first decision is final.</summary>
    private sealed class Session(IProofMethod method, ReuseOffer reuse, string? manifest, byte[]? prfState, RowsCommit? rows = null, Func<string?>? takeNext = null, string? finalCode = null)
    {
        private static readonly OneShotResponse NotFound = new(404, "text/plain; charset=utf-8", "Not found.");
        private static readonly OneShotResponse Ok = new(200, "application/json", "{\"ok\":true}");
        private static readonly OneShotResponse Refused = new(403, "application/json", "{\"ok\":false}");
        private static readonly OneShotResponse Invalid = new(400, "application/json", "{\"ok\":false}");
        private static readonly OneShotResponse PrfNotOpened = new(400, "application/json", "{\"ok\":false}", Outcome: "PRF not opened");
        private static readonly OneShotResponse Failed = new(500, "application/json", "{\"ok\":false}", Outcome: "error");

        private readonly Lock _gate = new();
        private readonly TaskCompletionSource<ApprovalDecision> _decision = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private ProofContext? _context;
        private OneShotResponse? _page;
        private SignedManifest? _signed;
        private string _nonce = "";
        private string _text = "";
        private OneShotResponse? _reply;
        private byte[]? _replyFor;

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

        public ManifestApproval Wait(TimeSpan timeout, CancellationToken cancel = default)
        {
            bool answered;
            try
            {
                answered = _decision.Task.Wait(timeout, cancel);
            }
            catch (OperationCanceledException)
            {
                // The caller left: the page is closed and the request is denied.
                lock (_gate)
                {
                    _decision.TrySetResult(ApprovalDecision.Deny("cancelled by the client"));
                }

                answered = true;
            }

            if (!answered)
            {
                // A proof that finishes checking after this loses: the time limit came first.
                lock (_gate)
                {
                    _decision.TrySetResult(ApprovalDecision.Deny(ApprovalDecision.TimeLimitDetail));
                }
            }

            lock (_gate)
            {
                ApprovalDecision decision = _decision.Task.Result;

                return new ManifestApproval(decision, decision.Approved ? _signed : null);
            }
        }

        /// <summary>
        /// Every request gets an answer. A bug that throws while a request is handled denies the request (the first outcome is
        /// final) and answers 500, so the page never waits and the program never waits for a decision nobody will make.
        /// </summary>
        public OneShotResponse Handle(string verb, string suffix, string body)
        {
            return HandleGuard.Run(verb, suffix, () => HandleRequest(verb, suffix, body), () => _decision.TrySetResult(ApprovalDecision.Deny(HandleGuard.Reason)), Failed, NotFound);
        }

        private OneShotResponse HandleRequest(string verb, string suffix, string body)
        {
            lock (_gate)
            {
                if (_context is null || _page is null)
                {
                    return NotFound;
                }

                if (_decision.Task.IsCompleted)
                {
                    return Again(verb, suffix, body);
                }

                switch (verb, suffix)
                {
                    case ("GET", ""):
                        return _page;
                    case ("POST", "deny"):
                        return _decision.TrySetResult(ApprovalDecision.Deny("denied on the page")) ? Ok : NotFound;
                    case ("POST", "proof"):
                        if (!TryReadBody(body, out int minutes, out string proof, out PrfBody? released))
                        {
                            _decision.TrySetResult(ApprovalDecision.Deny("the page sent a request that is not valid"));

                            return Invalid;
                        }

                        // The PRF output comes with the proof exactly when this page asked for it. A page that cannot send it (a
                        // passkey without PRF) is a denial: nothing else ever stands in for the key.
                        if (prfState is null != (released is null))
                        {
                            _decision.TrySetResult(ApprovalDecision.Deny(prfState is null ? "the page sent a request that is not valid" : "the page did not send the PRF output, so the secret store key cannot be released"));

                            return prfState is null ? Invalid : PrfNotOpened;
                        }

                        if (!reuse.Allows(minutes))
                        {
                            _decision.TrySetResult(ApprovalDecision.Deny($"the page asked for a reuse time that was not offered ({minutes.ToString(CultureInfo.InvariantCulture)} min)"));

                            return Invalid;
                        }

                        // The person signed this time with the request: SHA-256(bind || "reuse=" || minutes); or the new state:
                        // SHA-256(bind || SHA-256(manifest)).
                        ProofResult? result;
                        byte[] signedBind = _context.Bind;
                        try
                        {
                            signedBind = rows is null ? _context.Bind : SecretCrypto.ManifestBind(_context.Bind, rows.Digest());
                            byte[] challenge = manifest is null ? ReuseBinding.Challenge(_context.Bind, minutes) : Manifest.Challenge(signedBind, manifest);
                            result = method.Verify(_context with { Bind = challenge }, proof);
                        }
                        catch (Exception)
                        {
                            result = new ProofResult(false, "the proof could not be checked");
                        }

                        if (result is { Ok: true })
                        {
                            // The assertion verified first. Then the PRF output is opened with the page's server key (the bind is
                            // the associated data, so output sealed for another page does not open) and kept with the credential
                            // id that signed. Any doubt denies.
                            Unlock? unlock = null;
                            if (released is not null)
                            {
                                unlock = OpenRelease(proof, released, _context.Bind);
                                if (unlock is null)
                                {
                                    _decision.TrySetResult(ApprovalDecision.Deny("the PRF output from the page could not be opened, so the secret store key cannot be released; nothing was approved"));

                                    return PrfNotOpened;
                                }
                            }

                            // A run approval keeps what was signed, so a saved approval can be checked again at every use.
                            ApprovalEvidence? evidence = null;
                            if (manifest is not null)
                            {
                                _signed = new SignedManifest(manifest, signedBind, proof);
                            }
                            else
                            {
                                evidence = new ApprovalEvidence(_nonce, _text, proof);
                            }

                            // A change that writes rows is committed here, under the lock, before the page is told: the recovery
                            // code goes to the page only when the write happened.
                            if (rows is not null && _signed is not null)
                            {
                                string? why = rows.Apply(_signed, result.Detail);
                                if (why is not null)
                                {
                                    _decision.TrySetResult(ApprovalDecision.Deny(why));

                                    return Failed;
                                }
                            }

                            // A step that a page follows (the PRF release before a new key or a rotation) makes its next page now, after the
                            // proof verified and before the command goes on; a signature of a new state makes none.
                            string? next = manifest is null ? takeNext?.Invoke() : null;
                            if (_decision.TrySetResult(ApprovalDecision.Allow(result.Detail, minutes, evidence, unlock)))
                            {
                                OneShotResponse reply = rows?.Recovery is { } recovery ? new OneShotResponse(200, "application/json", JsonSerializer.Serialize(new { ok = true, recovery }))
                                    : finalCode is not null && manifest is not null ? new OneShotResponse(200, "application/json", JsonSerializer.Serialize(new { ok = true, code = finalCode }))
                                    : next is null ? Ok
                                    : new OneShotResponse(200, "application/json", JsonSerializer.Serialize(new { ok = true, next }));

                                // The reply is kept for this one body: if it is lost on the way, the same body sent again gets it again.
                                _reply = reply;
                                _replyFor = SHA256.HashData(Encoding.UTF8.GetBytes(body));

                                return reply;
                            }

                            unlock?.Dispose();

                            return NotFound;
                        }

                        _decision.TrySetResult(ApprovalDecision.Deny("the proof was not accepted: " + (result?.Detail ?? "no result")));
                        return Refused;
                    default:
                        return NotFound;
                }
            }
        }

        /// <summary>
        /// After the decision: the verified proof sent again, byte for byte, gets the kept reply (it holds the next address or the code, which
        /// only the browser that sent the proof can have asked for). Any other request gets 404. Called with the lock held.
        /// </summary>
        private OneShotResponse Again(string verb, string suffix, string body)
        {
            if (verb == "POST" && suffix == "proof" && _reply is not null && _replyFor is not null
                && CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(body)), _replyFor))
            {
                return _reply;
            }

            return NotFound;
        }

        /// <summary>Drops the kept reply (the flow ended).</summary>
        public void Forget()
        {
            lock (_gate)
            {
                _reply = null;
                _replyFor = null;
            }
        }

        /// <summary>
        /// Reads <c>{"reuse":N,"proof":{...}}</c>: exactly these two members, once each; N a whole number written plainly (no
        /// fraction, exponent or quotes); the proof an object, passed on as its JSON text.
        /// </summary>
        private static bool TryReadBody(string body, out int minutes, out string proof, out PrfBody? released)
        {
            minutes = 0;
            proof = "";
            released = null;
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
                JsonElement? sealedPrf = null;
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
                    else if (property.Name == "prf" && sealedPrf is null)
                    {
                        sealedPrf = property.Value;
                    }
                    else
                    {
                        return false;
                    }
                }

                if (count != (sealedPrf is null ? 2 : 3) || time is not { ValueKind: JsonValueKind.Number } number || signed is not { ValueKind: JsonValueKind.Object } value
                    || !number.TryGetInt32(out int read) || number.GetRawText() != read.ToString(CultureInfo.InvariantCulture))
                {
                    return false;
                }

                if (sealedPrf is { } prf && !PrfBody.TryRead(prf, out released))
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

        /// <summary>
        /// The PRF output the page sealed to this page's server key, opened and bound to the credential id of the proof that
        /// verified. Null when it does not open (another page's bind, another key, damaged text) or is not 32 bytes.
        /// </summary>
        private Unlock? OpenRelease(string proof, PrfBody sealedPrf, byte[] bind)
        {
            byte[]? output = null;
            try
            {
                string? id = PasskeyMethod.ResponseId(proof);
                if (id is null || prfState is null)
                {
                    return null;
                }

                output = SecretCrypto.DecryptBytes(prfState, bind, sealedPrf.Epk, sealedPrf.Iv, sealedPrf.Ct, SecretCrypto.PrfInfo);
                if (output.Length != KeyVault.KeyBytes)
                {
                    return null;
                }

                Unlock unlock = new(id, output);
                output = null;

                return unlock;
            }
            catch (Exception)
            {
                return null;
            }
            finally
            {
                if (output is not null)
                {
                    CryptographicOperations.ZeroMemory(output);
                }
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
    /// payload), the ASCII text "reuse=" and the chosen minutes (0 for Approve once). It makes the challenge for every time
    /// offered before the controls go on, so the tap starts the passkey prompt with nothing awaited first (iOS WebKit refuses
    /// a prompt that does not start in the tap). Ctrl+Enter (Cmd+Enter) is Approve once; it does nothing while the controls
    /// are off and never picks a longer time.
    /// </summary>
    private const string Script = """
        (function () {
            "use strict";
            var start = JSON.parse(document.getElementById("start").textContent);
            var approve = document.getElementById("approve");
            var approveFor = document.getElementById("approve-for");
            var reuse = document.getElementById("reuse");
            var deny = document.getElementById("deny");
            var code = document.getElementById("code");
            var status = document.getElementById("status");
            var base = location.pathname.replace(/\/+$/, "");
            var encoder = new TextEncoder();
            var busy = false;
            var attempt = 0;
            var waiting = null;
            var waitingLabel = "";
            var finished = false;
            var ready = {};
            var prepared = false;
            var waited = false;

            function show(text) {
                status.textContent = text + (diagLine ? " " + diagLine : "");
            }

            //@FOLLOW@

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

            // Timings for a failed post, shown on the page only after a failure or timeout (never on success): when the page was opened,
            // when the passkey prompt started and answered, how long the page was hidden, each attempt, the network state. Times only:
            // no key, PRF output, value or code is ever read here.
            var diagStart = Date.now() - Math.round(performance.now());
            var diag = { tap: null, answered: null, hidden: 0, hiddenAt: null, events: [], attempts: [] };
            var diagLine = "";
            function diagSec(ms) { return Math.round(ms / 100) / 10; }
            function diagSince(time) { return diagSec(time - diagStart); }
            function diagMark(name) {
                diag.events.push(name + " " + diagSince(Date.now()) + " s");
                if (diag.events.length > 8) { diag.events.shift(); }
            }
            document.addEventListener("visibilitychange", function () {
                if (document.visibilityState === "hidden") { diag.hiddenAt = Date.now(); }
                else if (diag.hiddenAt !== null) { diag.hidden += Date.now() - diag.hiddenAt; diag.hiddenAt = null; }
                diagMark(document.visibilityState);
            });
            ["pagehide", "pageshow"].forEach(function (name) { window.addEventListener(name, function () { diagMark(name); }); });
            ["freeze", "resume"].forEach(function (name) { document.addEventListener(name, function () { diagMark(name); }); });
            try {
                ["get", "create"].forEach(function (method) {
                    var original = navigator.credentials && navigator.credentials[method];
                    if (typeof original !== "function") { return; }
                    navigator.credentials[method] = function () {
                        diag.tap = Date.now();
                        diagLine = "";
                        diag.answered = null;
                        var promise = original.apply(navigator.credentials, arguments);
                        promise.then(function () { diag.answered = Date.now(); }, function () { diag.answered = Date.now(); });
                        return promise;
                    };
                });
            } catch (ignored) { }
            function diagnostics() {
                var parts = ["open " + diagSince(Date.now()) + " s"];
                if (diag.tap !== null) { parts.push("tap at " + diagSince(diag.tap) + " s"); }
                if (diag.answered !== null && diag.tap !== null) { parts.push("passkey answered at " + diagSince(diag.answered) + " s (" + diagSec(diag.answered - diag.tap) + " s)"); }
                var hidden = diag.hidden + (diag.hiddenAt !== null ? Date.now() - diag.hiddenAt : 0);
                parts.push("hidden " + diagSec(hidden) + " s");
                parts = parts.concat(diag.attempts);
                parts.push("online=" + navigator.onLine, "state=" + document.visibilityState);
                if (diag.events.length > 0) { parts.push("events " + diag.events.join(", ")); }
                return "Diagnostics: " + parts.join("; ");
            }

            // A post that gets no answer is aborted (its error is named AbortError) and sent again with the same body, up to 3 attempts in all
            // (8, 8 and 20 seconds): after the phone suspended the page the connection can be stale, and the first attempt never arrives.
            // The program keeps the first outcome, so a resend that comes after it was processed is answered "already ended" (404)
            // and changes nothing. Cancel (the page is finished) stops the resends.
            var resent = false;
            function post(what, body) {
                var limits = what === "deny" ? [20000] : [8000, 8000, 20000];
                resent = false;
                diag.attempts = [];
                function send(number) {
                    var controller = new AbortController();
                    var started = Date.now();
                    var timer = setTimeout(function () { controller.abort(); }, limits[number]);
                    return fetch(base + "/" + what, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: body,
                        cache: "no-store",
                        keepalive: false,
                        credentials: "omit",
                        redirect: "error",
                        signal: controller.signal
                    }).then(function (reply) {
                        clearTimeout(timer);
                        diagLine = "";
                        if (resent && (reply.status === 404 || reply.status === 409)) {
                            finish("The program already finished this request. If this page did not move on, press Ctrl+C in the terminal and run the command again.");
                            return new Promise(function () { });
                        }
                        return reply;
                    }, function (error) {
                        clearTimeout(timer);
                        diag.attempts.push("attempt " + (number + 1) + " sent at " + diagSince(started) + " s, " + (error && error.name === "AbortError" ? "timed out" : "failed") + " after " + diagSec(Date.now() - started) + " s (" + (error && typeof error.name === "string" ? error.name : "Error") + ")");
                        diagLine = diagnostics();
                        if (number + 1 >= limits.length || finished) {
                            throw error;
                        }
                        resent = true;
                        show("Still waiting for the program... (retry " + (number + 2) + " of 3)");
                        return send(number + 1);
                    });
                }
                return send(0);
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

            //@SEAL_PRF@

            // A page that releases the secret store key asks the chosen passkey for its PRF output with the one salt all slots share
            // (the key the page shows in prfKey is the one the output is sealed to).
            var wantsPrf = typeof start.prfKey === "string";

            function options() {
                var payload = JSON.parse(start.payload);
                var result = {
                    challenge: null,
                    rpId: payload.rpId,
                    timeout: payload.timeout,
                    userVerification: "required"
                };
                if (wantsPrf) {
                    result.extensions = { prf: { eval: { first: fromBase64Url(payload.salt) } } };
                }
                return result;
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

            // The challenges, made before the controls go on, so that a tap starts the passkey prompt at once (WebKit refuses a
            // prompt that follows an awaited step). A new state is signed as SHA-256(bind || SHA-256(manifest)); a run as
            // SHA-256(bind || "reuse=" || minutes): one for Approve once (0) and one for each time offered.
            function prepare() {
                var seed = fromBase64Url(start.bind);
                if (typeof start.manifest === "string") {
                    return window.crypto.subtle.digest("SHA-256", encoder.encode(start.manifest)).then(function (hash) {
                        return window.crypto.subtle.digest("SHA-256", join(seed, new Uint8Array(hash)));
                    }).then(function (challenge) {
                        ready.manifest = new Uint8Array(challenge);
                    });
                }
                var times = [0];
                if (reuse) {
                    Array.prototype.forEach.call(reuse.options, function (option) {
                        if (/^[0-9]{1,4}$/.test(option.value) && Number(option.value) > 0) {
                            times.push(Number(option.value));
                        }
                    });
                }
                return Promise.all(times.map(function (minutes) {
                    return window.crypto.subtle.digest("SHA-256", join(seed, encoder.encode("reuse=" + minutes))).then(function (challenge) {
                        ready["reuse=" + minutes] = new Uint8Array(challenge);
                    });
                }));
            }

            function enable() {
                if (prepared && waited && !finished && !busy) {
                    controls(true);
                }
            }

            // The browser's own error, for the status line: its name and message (cut to 120 characters). Never any proof or key text.
            //@SHOW_RECOVERY@

            function why(error) {
                if (!error || typeof error.name !== "string") {
                    return "";
                }
                var text = error.name;
                if (typeof error.message === "string" && error.message) {
                    text += ": " + error.message.slice(0, 120);
                }
                return " (" + text + ")";
            }

            // While the passkey prompt is open the tapped button stays on and reads "Cancel": a prompt that closes
            // without ever settling must not leave the page stuck. The cancel starts no prompt; it only abandons the attempt.
            function endWait() {
                if (waiting !== null) {
                    waiting.textContent = waitingLabel;
                    waiting = null;
                }
            }

            function cancelAttempt() {
                attempt++;
                endWait();
                busy = false;
                controls(true);
                show("Cancelled. Tap again to try.");
            }

            // Runs in the tap: nothing is awaited before the passkey prompt.
            function approveWith(minutes, button) {
                if (finished) {
                    return;
                }
                if (waiting !== null) {
                    cancelAttempt();
                    return;
                }
                if (busy || approve.disabled) {
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
                var publicKey = null;
                var challenge = typeof start.manifest === "string" ? ready.manifest : ready["reuse=" + minutes];
                try {
                    publicKey = options();
                } catch (error) {
                    show("The proof data is not valid (" + (error && typeof error.name === "string" ? error.name : "Error") + "). Nothing was approved.");
                    return;
                }
                if (!challenge) {
                    show("The proof data is not valid. Nothing was approved.");
                    return;
                }
                publicKey.challenge = challenge;
                var mine = ++attempt;
                busy = true;
                controls(false);
                waiting = button;
                waitingLabel = button.textContent;
                button.textContent = "Cancel";
                button.disabled = false;
                show("Waiting for your passkey...");
                navigator.credentials.get({ publicKey: publicKey }).then(function (credential) {
                    if (mine !== attempt) {
                        return null;
                    }
                    var response = credential.response;
                    var message = {
                        reuse: minutes,
                        proof: {
                            id: toBase64Url(credential.rawId),
                            authenticatorData: toBase64Url(response.authenticatorData),
                            clientDataJSON: toBase64Url(response.clientDataJSON),
                            signature: toBase64Url(response.signature)
                        }
                    };
                    if (!wantsPrf) {
                        return JSON.stringify(message);
                    }
                    // The PRF output leaves the page only sealed to the program's key for this page.
                    var output = prfOutput(credential);
                    if (output === null) {
                        throw new Error("no prf");
                    }
                    return sealPrf(output, fromBase64Url(start.bind), fromBase64Url(start.prfKey)).then(function (sealed) {
                        message.prf = sealed;
                        return JSON.stringify(message);
                    });
                }).then(function (body) {
                    if (mine !== attempt) {
                        return;
                    }
                    if (finished) {
                        busy = false;
                        return;
                    }
                    endWait();
                    controls(false);
                    show("Checking your passkey...");
                    return post("proof", body).then(function (reply) {
                        busy = false;
                        if (reply.ok) {
                            return reply.json().then(function (data) { return data; }, function () { return null; }).then(function (data) {
                                if (data && typeof data.next === "string") {
                                    follow(data.next);
                                    return;
                                }
                                finish(typeof start.confirmedMessage === "string" && minutes === 0 ? start.confirmedMessage : minutes > 0 ? "Approved for " + minutes + " minutes. You can close this page." : "Approved once. You can close this page.");
                                if (start.recovery === "1" && data) {
                                    finish("Done. The keys were changed. Write down the recovery code below before you close this page.");
                                    showRecovery(data);
                                }
                                if (start.code === "1" && code && data && typeof data.code === "string") {
                                    finish("Done. Type this code in the terminal to finish.");
                                    code.textContent = data.code;
                                }
                            });
                        } else if (reply.status === 403) {
                            finish("Your passkey was not accepted. The request is denied.");
                        } else if (reply.status === 400) {
                            finish("The program refused what this page sent. The request is denied.");
                        } else {
                            finish("This request had already ended. Nothing was approved.");
                        }
                    }, function (error) {
                        if (mine !== attempt) {
                            return;
                        }
                        busy = false;
                        if (error && error.name === "AbortError") {
                            if (!finished) {
                                controls(true);
                                show("The program did not answer within 20 seconds. Check the terminal. Tap again to retry.");
                            }
                            return;
                        }
                        finish("Could not reach the program. With no answer it denies the request at its time limit.");
                    });
                }, function (error) {
                    if (mine !== attempt) {
                        return;
                    }
                    busy = false;
                    endWait();
                    if (error && error.message === "no prf" && !finished) {
                        // The passkey answered but returned no PRF output: it cannot release the key, so nothing can be approved.
                        finish("Your passkey did not release its PRF key, which this approval needs to open the secrets. Nothing was approved. Use a passkey from your phone or a security key.");
                        post("deny", "").then(null, function () { });
                    } else if (!finished) {
                        controls(true);
                        show("No passkey was used" + why(error) + ". Nothing was approved. You can try again or deny.");
                    }
                });
            }

            approve.addEventListener("click", function () {
                approveWith(0, approve);
            });

            if (approveFor && reuse) {
                approveFor.addEventListener("click", function () {
                    var value = reuse.value;
                    if (!/^[0-9]{1,4}$/.test(value) || Number(value) <= 0) {
                        show("Choose a time first, or use Approve once.");
                        return;
                    }
                    approveWith(Number(value), approveFor);
                });
            }

            // Ctrl+Enter (Cmd+Enter on a Mac) is Approve once, never a longer time. It does nothing while the controls are off.
            document.addEventListener("keydown", function (event) {
                if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
                    event.preventDefault();
                    event.stopPropagation();
                    if (!approve.disabled) {
                        approveWith(0, approve);
                    }
                }
            }, true);

            // The controls go on after the delay and once the challenges are made (or could not be made: then a tap says so).
            function done() {
                prepared = true;
                enable();
            }
            if (start.mode === "webauthn" && window.isSecureContext && window.crypto && window.crypto.subtle) {
                try {
                    prepare().then(done, done);
                } catch (error) {
                    done();
                }
            } else {
                done();
            }
            var delay = Number(approve.getAttribute("data-delay")) || 0;
            setTimeout(function () {
                waited = true;
                enable();
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
        .warn { border: 0.3rem solid #7a3e00; background: #fff3e0; color: #111; padding: 0.8rem 1rem; margin: 0 0 1rem; }
        .warn h2 { font-size: 1.1rem; margin: 0 0 0.5rem; }
        .warn ul { margin: 0.5rem 0; padding-left: 1.2rem; }
        .warn li { margin: 0.5rem 0; }
        .warn code { overflow-wrap: anywhere; word-break: break-all; font-weight: bold; }
        .warn .why { color: #333; }
        """;

    /// <summary>
    /// Takes the warning block about variables that change how the program loads code or where it sends data (see
    /// <see cref="ApprovalSummary.CodeChangesHeading" />) out of the text and builds its own section for it, to be put above the text and the
    /// approve control. The text is unchanged otherwise. The block is the one the summary wrote (a line the agent wrote starts with the code marker, so it
    /// cannot start the block); every value is HTML-encoded. Null section: the text has no such block.
    /// </summary>
    internal static (string Text, string? Section) SplitWarning(string text)
    {
        string[] lines = text.Split('\n');
        string start = "Warning: " + ApprovalSummary.CodeChangesHeading + ".";
        int first = Array.IndexOf(lines, start);
        int last = first < 0 ? -1 : Array.IndexOf(lines, ApprovalSummary.CodeChangesCover, first);
        if (first < 0 || last < 0)
        {
            return (text, null);
        }

        StringBuilder section = new();
        section.Append("<section class=\"warn\" aria-labelledby=\"warn-title\">\n<h2 id=\"warn-title\">Warning: ").Append(WebUtility.HtmlEncode(ApprovalSummary.CodeChangesHeading)).Append("</h2>\n<ul>\n");
        for (int index = first + 1; index < last; index++)
        {
            string line = lines[index];
            if (line.StartsWith(ApprovalSummary.CodeMarker, StringComparison.Ordinal))
            {
                string pair = line[ApprovalSummary.CodeMarker.Length..];
                int equals = pair.IndexOf('=', StringComparison.Ordinal);
                string name = equals < 0 ? pair : pair[..equals];
                section.Append("<li><code class=\"name\">").Append(WebUtility.HtmlEncode(name)).Append("</code>");
                if (equals >= 0)
                {
                    section.Append(" = <code class=\"value\">").Append(WebUtility.HtmlEncode(pair[(equals + 1)..])).Append("</code>");
                }

                section.Append('\n');
            }
            else if (line.StartsWith(ApprovalSummary.CodeChangesWhy, StringComparison.Ordinal))
            {
                section.Append("<br><span class=\"why\">").Append(WebUtility.HtmlEncode(line[ApprovalSummary.CodeChangesWhy.Length..])).Append("</span></li>\n");
            }
        }

        section.Append("</ul>\n<p><strong>").Append(WebUtility.HtmlEncode(ApprovalSummary.CodeChangesCover)).Append("</strong></p>\n</section>\n");

        return (string.Join('\n', lines.Take(first).Concat(lines.Skip(last + 1))), section.ToString());
    }

    public static OneShotResponse Build(ApprovalPrompt prompt, ProofStart start, string nonce, byte[] bind, TimeSpan approveDelay, ReuseOffer? reuse = null, string? manifest = null, string? prfKey = null, bool recovery = false, string? code = null)
    {
        return Build(prompt, start, nonce, bind, approveDelay, Script, Style, reuse, manifest, prfKey, recovery, code);
    }

    /// <summary>
    /// Builds the page with the given script and style. Their line endings become LF before hashing and output, so the CSP
    /// hashes match what is served even when the source file was checked out with CRLF.
    /// </summary>
    internal static OneShotResponse Build(ApprovalPrompt prompt, ProofStart start, string nonce, byte[] bind, TimeSpan approveDelay, string script, string style, ReuseOffer? reuse = null, string? manifest = null, string? prfKey = null, bool recovery = false, string? code = null)
    {
        reuse ??= ReuseOffer.Off;
        script = PrfClient.Fill(PageContinue.Fill(script.ReplaceLineEndings("\n"))).Replace("//@SHOW_RECOVERY@", recovery ? PasskeyRegistration.RecoveryScript.ReplaceLineEndings("\n") : "", StringComparison.Ordinal);
        style = (recovery || code is not null ? style + "\n" + PasskeyRegistration.CodeStyle : style).ReplaceLineEndings("\n");
        string policy = Policy(script, style);

        // The default encoder escapes < > & ' and non-ASCII, so the JSON cannot end the data block.
        Dictionary<string, string> data = new()
        {
            ["mode"] = start.Mode,
            ["payload"] = start.Payload,
            ["bind"] = Base64Url.EncodeToString(bind),
            ["nonce"] = nonce
        };
        if (prompt.ConfirmedMessage is not null)
        {
            data["confirmedMessage"] = prompt.ConfirmedMessage;
        }
        if (manifest is not null)
        {
            data["manifest"] = manifest;
        }

        if (recovery)
        {
            // The final page shows the new recovery code (it arrives in the answer to the proof, after the write).
            data["recovery"] = "1";
        }

        if (code is not null)
        {
            // The final page shows the confirmation code (it arrives in the answer to the proof), to be typed in the terminal.
            data["code"] = "1";
        }

        if (prfKey is not null)
        {
            // This page also asks the passkey for its PRF output and seals it to this key (see PrfClient).
            data["prfKey"] = prfKey;
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
        (string requestText, string? warning) = SplitWarning(prompt.Text);
        if (warning is not null)
        {
            page.Append(warning);
        }

        page.Append("<pre id=\"request\">").Append(WebUtility.HtmlEncode(requestText)).Append("</pre>\n");
        page.Append("<div class=\"buttons\">");
        page.Append("<button id=\"deny\" type=\"button\" autofocus>Deny</button>");
        page.Append("<button id=\"approve\" type=\"button\" disabled data-delay=\"")
            .Append(delay.ToString(CultureInfo.InvariantCulture)).Append("\">").Append(WebUtility.HtmlEncode(prompt.ConfirmLabel ?? "Approve once")).Append("</button>");
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

        if (prfKey is not null)
        {
            page.Append("<p class=\"hint\">" + WebUtility.HtmlEncode(PrfClient.ApprovalHint) + "</p>\n");
        }

        page.Append("<p class=\"hint\">Ctrl+Enter (Cmd+Enter on a Mac) presses Approve once.</p>\n");
        page.Append("<p id=\"status\" role=\"status\"></p>\n");
        page.Append(PageContinue.Box);
        if (code is not null)
        {
            page.Append("<p id=\"code\"></p>\n");
        }

        if (recovery)
        {
            page.Append(PasskeyRegistration.RecoveryBox);
        }

        page.Append("</main>\n");
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

/// <summary>
/// What a manifest approval that also writes secret rows (<c>--rotate-key</c>) adds. <see cref="Digest" /> is the digest of
/// exactly those rows, read when the page is made and again when the proof is checked: the signed bind is
/// <see cref="SecretCrypto.ManifestBind" /> of the request bind and it, so a row changed in between fails the check.
/// <see cref="Apply" /> runs under the page's lock right after the proof verified, with the signed manifest and who signed
/// (null when committed, else why not). <see cref="Recovery" /> is the new recovery code the final page shows once, only when
/// <see cref="Apply" /> committed; the page puts it in with textContent.
/// </summary>
internal sealed record RowsCommit(Func<byte[]> Digest, Func<SignedManifest, string, string?> Apply, string? Recovery);

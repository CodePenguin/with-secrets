using System.Buffers.Text;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WithSecrets;

/// <summary>
/// How one registration page differs from the plain <c>--enroll</c> page. The first-run <c>--config</c> page uses it to bind
/// the settings into the passkey's challenge and to store them with the key in one transaction.
/// </summary>
/// <param name="Prefix">The first part of the page path, before the token.</param>
/// <param name="AnnouncePrefix">The text before the link in the terminal.</param>
/// <param name="Page">Builds the page from the rpId and the creation options JSON.</param>
/// <param name="Read">From the server's challenge and the POST body: the challenge the passkey signed and the registration JSON, or null when the body is not valid.</param>
/// <param name="Accept">After the registration is checked and before the manifest step: null to go on, else why not.</param>
/// <param name="Next">The new manifest that holds the new key. Its admin key signs it: the new key itself on the first run.</param>
/// <param name="Commit">After the signed manifest and the right code: stores it (and anything that goes with it) and says how it went.</param>
internal sealed record RegistrationPlan(
    string Prefix,
    string AnnouncePrefix,
    Func<string, string, OneShotResponse> Page,
    Func<byte[], string, (byte[] Challenge, string Registration)?> Read,
    Func<string?> Accept,
    Func<PasskeyRecord, Manifest> Next,
    Func<SignedManifest, PasskeyRecord, ApprovalDecision> Commit);

/// <summary>An approval of a new manifest: the decision and, when approved, the manifest with the admin assertion over it.</summary>
public sealed record ManifestApproval(ApprovalDecision Decision, SignedManifest? Signed);

/// <summary>
/// Adds a passkey through a web page served once, the same way the approval page is served. The terminal gets only the
/// link. The page asks the browser to create a passkey for the page's host; only a registration made for this page's own
/// challenge and origin can be accepted. Then the admin key signs the new manifest that holds the new key: on the same page
/// when the admin key works at this host (on the first run the new key is the admin and signs it itself), else on an
/// approval page where the admin key works, after the code. The key is stored only after both and after the person types,
/// in the terminal, the code the page shows. The link alone is not enough: whoever registers first gets the code on their
/// page, not in the terminal. Cancel, a bad registration, a wrong or missing admin assertion, a wrong code, a store that
/// changed, the time limit and any error store nothing.
/// </summary>
/// <remarks>Limit: a program that owns the person's terminal (for example a pseudo-console) can read both the link and the code.</remarks>
internal static class PasskeyRegistration
{
    public const string AnnouncePrefix = "To add the passkey, open this link: ";

    private const string NameTaken = "a passkey with that name is already enrolled";

    private const string Script = """
        (function () {
            "use strict";
            var options = JSON.parse(document.getElementById("options").textContent);
            var create = document.getElementById("create");
            var cancel = document.getElementById("deny");
            var status = document.getElementById("status");
            var code = document.getElementById("code");
            var base = location.pathname.replace(/\/+$/, "");
            var busy = false;
            var finished = false;

            function show(text) {
                status.textContent = text;
            }

            function finish(text) {
                finished = true;
                create.disabled = true;
                cancel.disabled = true;
                show(text);
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

            function join(first, second) {
                var out = new Uint8Array(first.length + second.length);
                out.set(first, 0);
                out.set(second, first.length);
                return out;
            }

            // The second prompt: the admin passkey (on the first run, the new one) signs the new state, the manifest.
            function sign(step) {
                var encoder = new TextEncoder();
                show(step.first ? "Confirm with your new passkey..." : "Confirm with your admin passkey...");
                return window.crypto.subtle.digest("SHA-256", encoder.encode(step.manifest)).then(function (hash) {
                    return window.crypto.subtle.digest("SHA-256", join(fromBase64Url(step.bind), new Uint8Array(hash)));
                }).then(function (challenge) {
                    return navigator.credentials.get({ publicKey: {
                        challenge: new Uint8Array(challenge),
                        rpId: step.rpId,
                        allowCredentials: step.allowCredentials.map(function (item) {
                            return { id: fromBase64Url(item.id), type: item.type };
                        }),
                        timeout: step.timeout,
                        userVerification: "required"
                    } });
                }).then(function (credential) {
                    var response = credential.response;
                    return post("sign", JSON.stringify({
                        id: toBase64Url(credential.rawId),
                        authenticatorData: toBase64Url(response.authenticatorData),
                        clientDataJSON: toBase64Url(response.clientDataJSON),
                        signature: toBase64Url(response.signature)
                    }));
                });
            }

            // A reply with a code ends the page; a reply with a sign step runs it first.
            function answer(reply) {
                if (!reply.ok) {
                    busy = false;
                    finish(reply.status === 403
                        ? "The passkey was not accepted. Nothing was added. If the terminal asks for a code, press Ctrl+C."
                        : "Nothing was added. If the terminal asks for a code, press Ctrl+C.");
                    return;
                }
                return reply.json().then(function (data) {
                    if (data.sign && typeof data.sign.manifest === "string") {
                        return sign(data.sign).then(answer);
                    }
                    busy = false;
                    if (typeof data.code !== "string") {
                        throw new Error("no code");
                    }
                    finish((data.later ? "Type this code in the terminal. The terminal then shows a link where your admin passkey confirms the change."
                        : "Type this code in the terminal to finish.")
                        + (typeof data.admin === "string" ? " " + data.admin + ". Pages and --enrolled show this; if it ever changes, the state was replaced." : ""));
                    code.textContent = data.code;
                });
            }

            function publicKey() {
                return {
                    challenge: fromBase64Url(options.challenge),
                    rp: { id: options.rp.id, name: options.rp.name },
                    user: {
                        id: fromBase64Url(options.user.id),
                        name: options.user.name,
                        displayName: options.user.displayName
                    },
                    pubKeyCredParams: options.pubKeyCredParams,
                    authenticatorSelection: options.authenticatorSelection,
                    attestation: options.attestation,
                    excludeCredentials: options.excludeCredentials.map(function (item) {
                        return { id: fromBase64Url(item.id), type: item.type };
                    }),
                    timeout: options.timeout
                };
            }

            cancel.addEventListener("click", function () {
                if (finished) {
                    return;
                }
                finish("Sending cancel...");
                post("deny", "").then(function (reply) {
                    show(reply.ok ? "Cancelled. Nothing was added. You can close this page." : "This enrollment had already ended.");
                }, function () {
                    show("Could not reach the program. With no answer it adds nothing at its time limit.");
                });
            });

            create.addEventListener("click", function () {
                if (finished || busy) {
                    return;
                }
                if (!window.PublicKeyCredential || !navigator.credentials) {
                    show("This browser does not support passkeys. Nothing was added.");
                    return;
                }
                if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
                    show("This page needs an https address or localhost. Nothing was added.");
                    return;
                }
                var request;
                try {
                    request = publicKey();
                } catch (error) {
                    show("The page data is not valid. Nothing was added.");
                    return;
                }
                busy = true;
                create.disabled = true;
                show("Waiting for your passkey...");
                navigator.credentials.create({ publicKey: request }).then(function (credential) {
                    var response = credential.response;
                    return JSON.stringify({
                        id: toBase64Url(credential.rawId),
                        clientDataJSON: toBase64Url(response.clientDataJSON),
                        attestationObject: toBase64Url(response.attestationObject)
                    });
                }).then(function (body) {
                    if (finished) {
                        busy = false;
                        return;
                    }
                    show("Checking your passkey...");
                    return post("create", body).then(answer).then(null, function () {
                        // Also when the second prompt was cancelled: tell the program, so it stops waiting.
                        busy = false;
                        finish("Nothing was added. If the terminal asks for a code, press Ctrl+C.");
                        post("deny", "").then(null, function () { });
                    });
                }, function () {
                    busy = false;
                    if (!finished) {
                        create.disabled = false;
                        show("No passkey was made. Nothing was added. You can try again or cancel.");
                    }
                });
            });
            cancel.focus();
        })();
        """;

    /// <summary>
    /// Serves the page until the first outcome or the time limit. Refuses before anything starts when the name, the address
    /// or the store cannot be used. After the browser's registration is checked, the page shows a code; the key is stored
    /// only when <paramref name="readCode" /> returns that code, within three tries and the time limit.
    /// </summary>
    public static ApprovalDecision Run(PasskeyStore store, ApprovalSettings settings, string name, Action<string> announce, Func<string?> readCode, Func<string, ManifestApproval>? askAdmin = null)
    {
        return Run(store, settings, name, announce, readCode, null, askAdmin);
    }

    /// <summary>
    /// The same, with a page of another kind (<paramref name="plan" />; null is the plain enrollment page, which needs an
    /// enrolled admin key). Everything else is the same: the checks before start, the one accepted registration, the signed
    /// manifest, the code in the terminal, the time limit. <paramref name="askAdmin" /> asks the admin key to sign the new
    /// manifest on another page, for when the admin key does not work at this page's host; without it that case is refused.
    /// </summary>
    internal static ApprovalDecision Run(PasskeyStore store, ApprovalSettings settings, string name, Action<string> announce, Func<string?> readCode, RegistrationPlan? plan, Func<string, ManifestApproval>? askAdmin = null)
    {
        string? nameError = Enrollment.NameError(name);
        if (nameError is not null)
        {
            return ApprovalDecision.Deny(nameError);
        }

        name = name.Trim();
        string rpId;
        try
        {
            // The host does not depend on the port, so this is checked before anything listens.
            rpId = PasskeyMethod.RpIdOf(settings.PageOrigin(settings.Port));
        }
        catch (ProofUnavailableException error)
        {
            return ApprovalDecision.Deny(error.Message);
        }

        // What the store holds now. The key is stored only if the store still holds exactly these keys.
        if (!store.TryRead(out IReadOnlyList<PasskeyRecord> snapshot, out Manifest? current))
        {
            return ApprovalDecision.Deny(store.UnreadableMessage);
        }

        // The plain enrollment page adds a key the admin approves; the first key comes with the settings (--config).
        if (plan is null && current is null)
        {
            return ApprovalDecision.Deny(NothingEnrolled);
        }

        if (snapshot.Any(item => string.Equals(item.Name, name, StringComparison.OrdinalIgnoreCase)))
        {
            return ApprovalDecision.Deny(NameTaken);
        }

        string enrolledName = name;
        string adminLine = AdminKey.Line(current);
        plan ??= new RegistrationPlan(
            "e",
            AnnouncePrefix,
            (rp, options) => Build(enrolledName, rp, options, Script, ApprovalPage.Style + CodeStyle, adminLine),
            (challenge, body) => (challenge, body),
            () => null,
            key => current!.WithKey(key),
            (signed, key) => Commit(store.Database, signed, () => ApprovalDecision.Allow($"Added the passkey named \"{enrolledName}\" for {key.RpId}."),
                (connection, transaction) => AuditLog.Append(connection, transaction, AuditLog.ChangeRow("key-enrolled",
                    $"passkey \"{enrolledName}\" added for {key.RpId}; admin passkey {current!.Admin!.Name} verified", current.Admin.Name))));

        try
        {
            byte[] challenge = RandomNumberGenerator.GetBytes(32);
            Session session = new(store, name, challenge, [.. snapshot.Select(item => item.Id)], plan, settings, askAdmin);
            using OneShotServer server = new(plan.Prefix, settings.Port, session.Handle);
            string origin = settings.PageOrigin(server.Port);
            if (PasskeyMethod.RpIdOf(origin) != rpId)
            {
                return ApprovalDecision.Deny("the enrollment page address changed");
            }

            string options = JsonSerializer.Serialize(new
            {
                challenge = Base64Url.EncodeToString(challenge),
                rp = new { id = rpId, name = "with-secrets" },
                user = new { id = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16)), name = "with-secrets", displayName = name },
                pubKeyCredParams = new[] { new { type = "public-key", alg = WebAuthn.ES256 }, new { type = "public-key", alg = WebAuthn.RS256 } },
                authenticatorSelection = new { residentKey = "preferred", userVerification = "required" },
                attestation = "none",
                excludeCredentials = snapshot.Where(item => item.RpId == rpId).Select(item => new { id = item.Id, type = "public-key" }).ToArray(),
                timeout = (long)settings.Timeout.TotalMilliseconds,
            });

            session.Open(origin, rpId, plan.Page(rpId, options));
            announce(plan.AnnouncePrefix + origin + "/" + plan.Prefix + "/" + server.Token);

            return session.Wait(settings.Timeout, readCode);
        }
        catch (ProofUnavailableException error)
        {
            return ApprovalDecision.Deny(error.Message);
        }
        catch (Exception error)
        {
            return ApprovalDecision.Deny("the enrollment page failed: " + error.Message);
        }
    }

    internal const string NothingEnrolled = "Nothing is enrolled. Set up the first passkey with: with-secrets --config (with-secrets --enroll adds more).";

    /// <summary>
    /// Stores a signed manifest in one transaction, only when the stored one is still the version before it; then runs
    /// <paramref name="also" /> in the same transaction (for an audit row) and returns its decision. A stale or bad manifest
    /// stores nothing.
    /// </summary>
    internal static ApprovalDecision Commit(StateDatabase db, SignedManifest signed, Func<ApprovalDecision> done, Action<Microsoft.Data.Sqlite.SqliteConnection, Microsoft.Data.Sqlite.SqliteTransaction>? also = null)
    {
        Manifest? next = Manifest.Parse(signed.Text, out string? error);
        if (next is null)
        {
            return ApprovalDecision.Deny("the new state is not valid (" + error + "); nothing was saved");
        }

        return db.Write((connection, transaction) =>
        {
            string? problem = db.TryReplace(connection, transaction, next.Version - 1, signed);
            if (problem is not null)
            {
                return ApprovalDecision.Deny(problem);
            }

            also?.Invoke(connection, transaction);

            return done();
        });
    }

    internal const string CodeStyle = """
        #code { font-size: 3rem; font-family: ui-monospace, monospace; letter-spacing: 0.3em; }
        """;

    /// <summary>
    /// Builds the page. Script and style line endings become LF before hashing and output, so the CSP hashes match what is
    /// served. The name is HTML-encoded; the options are JSON in a data block, with &lt; and &gt; escaped.
    /// </summary>
    internal static OneShotResponse Build(string name, string rpId, string options, string script, string style, string adminLine)
    {
        script = script.ReplaceLineEndings("\n");
        style = style.ReplaceLineEndings("\n");
        string policy = ApprovalPage.Policy(script, style);
        string text = "Name: " + ApprovalSummary.Clean(name) + "\nWorks on: " + ApprovalSummary.Clean(rpId) + "\n" + ApprovalSummary.Clean(adminLine);

        StringBuilder page = new();
        page.Append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
        page.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
        page.Append("<meta name=\"referrer\" content=\"no-referrer\">\n");
        page.Append("<title>Add a passkey</title>\n");
        page.Append("<style>").Append(style).Append("</style>\n</head>\n<body>\n<main>\n");
        page.Append("<h1>Add a passkey for with-secrets</h1>\n");
        page.Append("<pre id=\"request\">").Append(WebUtility.HtmlEncode(text)).Append("</pre>\n");
        page.Append("<p>This passkey will be able to approve runs that use your secrets. Make it only on a device you keep with you.</p>\n");
        page.Append("<div class=\"buttons\">");
        page.Append("<button id=\"deny\" type=\"button\" autofocus>Cancel</button>");
        page.Append("<button id=\"create\" type=\"button\">Create passkey</button>");
        page.Append("</div>\n<p id=\"status\" role=\"status\"></p>\n<p id=\"code\"></p>\n</main>\n");
        page.Append("<script type=\"application/json\" id=\"options\">").Append(options).Append("</script>\n");
        page.Append("<script>").Append(script).Append("</script>\n</body>\n</html>\n");

        return new OneShotResponse(200, "text/html; charset=utf-8", page.ToString(), policy);
    }

    /// <summary>
    /// The state of one enrollment. Requests are handled one at a time. Only the first registration that is accepted goes
    /// on: to the admin's assertion over the new manifest (when it can be made on this page), then the code. After that the
    /// page answers only Cancel. The first final outcome wins.
    /// </summary>
    private sealed class Session(PasskeyStore store, string name, byte[] challenge, HashSet<string> snapshot, RegistrationPlan plan, ApprovalSettings settings, Func<string, ManifestApproval>? askAdmin)
    {
        private const int CodeTries = 3;

        private static readonly OneShotResponse NotFound = new(404, "text/plain; charset=utf-8", "Not found.");
        private static readonly OneShotResponse Ok = new(200, "application/json", "{\"ok\":true}");
        private static readonly OneShotResponse Refused = new(403, "application/json", "{\"ok\":false}");
        private static readonly OneShotResponse Invalid = new(400, "application/json", "{\"ok\":false}");
        private static readonly OneShotResponse Failed = new(500, "application/json", "{\"ok\":false}");

        private readonly Lock _gate = new();
        private readonly TaskCompletionSource<ApprovalDecision> _decision = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<PasskeyRecord> _verified = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private string? _origin;
        private string? _rpId;
        private OneShotResponse? _page;
        private string _code = "";

        // After an accepted registration: the key, the manifest to sign, who signs it, and (once signed) the signed manifest.
        private PasskeyRecord? _key;
        private Manifest? _next;
        private PasskeyRecord? _signer;
        private byte[]? _bind;
        private SignedManifest? _signed;

        public void Open(string origin, string rpId, OneShotResponse page)
        {
            lock (_gate)
            {
                _origin = origin;
                _rpId = rpId;
                _page = page;
            }
        }

        /// <summary>Waits for a checked registration, then for its code. Every way out other than the right code stores nothing.</summary>
        public ApprovalDecision Wait(TimeSpan timeout, Func<string?> readCode)
        {
            Stopwatch clock = Stopwatch.StartNew();
            TimeSpan Left() => timeout > clock.Elapsed ? timeout - clock.Elapsed : TimeSpan.Zero;

            if (Task.WaitAny([_decision.Task, _verified.Task], Left()) != 1 || _decision.Task.IsCompleted)
            {
                return End(ApprovalDecision.Deny("no answer before the time limit"));
            }

            PasskeyRecord key = _verified.Task.Result;
            for (int attempt = 0; attempt < CodeTries; attempt++)
            {
                Task<string?> read = Task.Run(readCode);
                if (Task.WaitAny([read, _decision.Task], Left()) != 0)
                {
                    // The time limit, or Cancel on the page (End keeps a decision already made).
                    return End(ApprovalDecision.Deny("no answer before the time limit"));
                }

                if (read.IsFaulted || read.Result is not string typed)
                {
                    return End(ApprovalDecision.Deny("no code was typed; nothing was added"));
                }

                if (CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(typed.Trim()), Encoding.UTF8.GetBytes(_code)))
                {
                    return SignElsewhere() ?? Store(key);
                }
            }

            return End(ApprovalDecision.Deny("the code was wrong three times; nothing was added"));
        }

        /// <summary>
        /// When the admin key does not work at this page's host, it signs the new manifest on an approval page where it works.
        /// Null to go on to storing, else the end. Runs outside the lock, so Cancel on this page still ends it.
        /// </summary>
        private ApprovalDecision? SignElsewhere()
        {
            Manifest next;
            lock (_gate)
            {
                if (_decision.Task.IsCompleted)
                {
                    return _decision.Task.Result;
                }

                if (_signed is not null)
                {
                    return null;
                }

                next = _next!;
            }

            if (askAdmin is null)
            {
                return End(ApprovalDecision.Deny("the admin passkey does not work at this page's address; nothing was added"));
            }

            ManifestApproval approval;
            try
            {
                approval = askAdmin(next.Canonical());
            }
            catch (Exception)
            {
                approval = new ManifestApproval(ApprovalDecision.Deny("the admin approval failed"), null);
            }

            if (!approval.Decision.Approved || approval.Signed is null || approval.Signed.Text != next.Canonical())
            {
                return End(approval.Decision.Approved ? ApprovalDecision.Deny("the admin approval did not sign the new state; nothing was added") : approval.Decision);
            }

            lock (_gate)
            {
                _signed = approval.Signed;
            }

            return null;
        }

        public OneShotResponse Handle(string verb, string suffix, string body)
        {
            lock (_gate)
            {
                if (_origin is null || _rpId is null || _page is null || _decision.Task.IsCompleted)
                {
                    return NotFound;
                }

                if (verb == "POST" && suffix == "deny")
                {
                    return _decision.TrySetResult(ApprovalDecision.Deny("cancelled on the page")) ? Ok : NotFound;
                }

                // After the first accepted registration, only its sign step and Cancel are answered: no second code, no page.
                if (_verified.Task.IsCompleted)
                {
                    return NotFound;
                }

                if (_key is not null)
                {
                    return verb == "POST" && suffix == "sign" ? Sign(_origin, _rpId, body) : NotFound;
                }

                switch (verb, suffix)
                {
                    case ("GET", ""):
                        return _page;
                    case ("POST", "create"):
                        return Register(_origin, _rpId, body);
                    default:
                        return NotFound;
                }
            }
        }

        /// <summary>Sets the outcome unless one is set (a decision already made stands) and returns the outcome.</summary>
        private ApprovalDecision End(ApprovalDecision decision)
        {
            lock (_gate)
            {
                _decision.TrySetResult(decision);
            }

            return _decision.Task.Result;
        }

        /// <summary>Called with the lock held. A checked registration goes on to the sign step or the code; anything else ends the enrollment.</summary>
        private OneShotResponse Register(string origin, string rpId, string body)
        {
            try
            {
                // What the passkey was asked to sign, and the registration itself, from the body.
                (byte[] Challenge, string Registration)? read = plan.Read(challenge, body);
                if (read is not { } signed)
                {
                    _decision.TrySetResult(ApprovalDecision.Deny("the page sent a request that is not valid"));

                    return Invalid;
                }

                RegistrationResult result = WebAuthn.VerifyRegistration(signed.Challenge, origin, rpId, name, signed.Registration);
                if (!result.Ok || result.Key is null)
                {
                    _decision.TrySetResult(ApprovalDecision.Deny("the passkey was not accepted: " + result.Detail));

                    return Refused;
                }

                string? problem = Problem(result.Key);
                if (problem is not null)
                {
                    _decision.TrySetResult(ApprovalDecision.Deny(problem));

                    return Refused;
                }

                string? refused = plan.Accept();
                if (refused is not null)
                {
                    _decision.TrySetResult(ApprovalDecision.Deny(refused));

                    return Invalid;
                }

                // The manifest with the new key, and who signs it: its admin key (the new key itself on the first run).
                Manifest next = plan.Next(result.Key);
                ManifestKey admin = next.Admin ?? throw new InvalidOperationException("no admin key");
                PasskeyRecord? signer = admin.Id == result.Key.Id ? result.Key
                    : store.TryAll(out IReadOnlyList<PasskeyRecord> keys) ? keys.FirstOrDefault(item => item.Id == admin.Id) : null;
                if (signer is null)
                {
                    _decision.TrySetResult(ApprovalDecision.Deny("the admin passkey cannot be read"));

                    return Failed;
                }

                _key = result.Key;
                _next = next;
                _signer = signer;
                if (signer.RpId != rpId)
                {
                    // The admin key does not work here: it signs on another page after the code.
                    return Code(true);
                }

                _bind = RandomNumberGenerator.GetBytes(32);

                return new OneShotResponse(200, "application/json", JsonSerializer.Serialize(new
                {
                    ok = true,
                    sign = new
                    {
                        manifest = next.Canonical(),
                        bind = Base64Url.EncodeToString(_bind),
                        rpId,
                        allowCredentials = new[] { new { id = signer.Id, type = "public-key" } },
                        timeout = (long)settings.Timeout.TotalMilliseconds,
                        first = signer.Id == result.Key.Id,
                    },
                }));
            }
            catch (Exception)
            {
                _decision.TrySetResult(ApprovalDecision.Deny("the passkey could not be checked"));

                return Failed;
            }
        }

        /// <summary>Called with the lock held. The admin's assertion over the new manifest; then the code.</summary>
        private OneShotResponse Sign(string origin, string rpId, string body)
        {
            try
            {
                Dictionary<string, string>? members = SettingsPage.StringMembers(body);
                if (members is null || members.Count != 4 || new[] { "id", "authenticatorData", "clientDataJSON", "signature" }.Any(field => !members.ContainsKey(field)))
                {
                    _decision.TrySetResult(ApprovalDecision.Deny("the page sent a request that is not valid"));

                    return Invalid;
                }

                string proof = JsonSerializer.Serialize(members);
                string text = _next!.Canonical();
                AssertionResult result = WebAuthn.VerifyAssertion(_signer!, Manifest.Challenge(_bind!, text), origin, rpId, proof);
                if (!result.Ok)
                {
                    _decision.TrySetResult(ApprovalDecision.Deny("the admin passkey did not sign the new state: " + result.Detail));

                    return Refused;
                }

                if (_signer!.Id != _key!.Id)
                {
                    // The assertion was valid, so it stands even if the new count could not be saved.
                    store.UpdateSignCount(_signer.Id, result.NewSignCount);
                }

                _signed = new SignedManifest(text, _bind!, proof);

                return Code(false);
            }
            catch (Exception)
            {
                _decision.TrySetResult(ApprovalDecision.Deny("the passkey could not be checked"));

                return Failed;
            }
        }

        /// <summary>Called with the lock held. The code goes only to the page that sent this registration, never to the terminal.</summary>
        private OneShotResponse Code(bool later)
        {
            _code = RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6", CultureInfo.InvariantCulture);
            _verified.TrySetResult(_key!);

            // The admin key of the new state, so the person sees its fingerprint (on the first run, for the first time).
            string admin = AdminKey.Line(_next);

            return new OneShotResponse(200, "application/json", later
                ? JsonSerializer.Serialize(new { ok = true, code = _code, later = true, admin })
                : JsonSerializer.Serialize(new { ok = true, code = _code, admin }));
        }

        /// <summary>Stores the signed manifest after the right code, unless the enrollment has ended or the store changed since it started.</summary>
        private ApprovalDecision Store(PasskeyRecord key)
        {
            lock (_gate)
            {
                if (!_decision.Task.IsCompleted)
                {
                    string? problem = Problem(key);
                    ApprovalDecision outcome;
                    try
                    {
                        outcome = problem is not null ? ApprovalDecision.Deny(problem)
                            : _signed is null ? ApprovalDecision.Deny("the new state was not signed; nothing was added")
                            : plan.Commit(_signed, key);
                    }
                    catch (Exception)
                    {
                        outcome = ApprovalDecision.Deny("the passkey could not be saved");
                    }

                    _decision.TrySetResult(outcome);
                }
            }

            return _decision.Task.Result;
        }

        /// <summary>Reads the store again, strictly: null when the key may be added, else why not.</summary>
        private string? Problem(PasskeyRecord key)
        {
            if (!store.TryAll(out IReadOnlyList<PasskeyRecord> stored))
            {
                return store.UnreadableMessage;
            }

            if (stored.Any(item => item.Id == key.Id))
            {
                return "that passkey is already enrolled";
            }

            if (!snapshot.SetEquals(stored.Select(item => item.Id)))
            {
                return "the passkeys changed while you enrolled; nothing was added";
            }

            return stored.Any(item => string.Equals(item.Name, name, StringComparison.OrdinalIgnoreCase)) ? NameTaken : null;
        }
    }
}

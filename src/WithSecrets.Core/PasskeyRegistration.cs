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
/// <param name="Next">The new manifest that holds the new key, an admin or not (the page's box). An admin of the stored state signs it: the new key itself on the first run.</param>
/// <param name="Commit">After the signed manifest and the right code: stores it (and anything that goes with it) and says how it went.</param>
internal sealed record RegistrationPlan(
    string Prefix,
    string AnnouncePrefix,
    Func<string, string, OneShotResponse> Page,
    Func<byte[], string, (byte[] Challenge, string Registration)?> Read,
    Func<string?> Accept,
    Func<PasskeyRecord, bool, Manifest> Next,
    Func<SignedManifest, PasskeyRecord, ApprovalDecision> Commit);

/// <summary>An approval of a new manifest: the decision and, when approved, the manifest with the admin assertion over it.</summary>
public sealed record ManifestApproval(ApprovalDecision Decision, SignedManifest? Signed);

/// <summary>
/// Adds a passkey through a web page served once, the same way the approval page is served. The terminal gets only the
/// link. The page asks the browser to create a passkey for the page's host; only a registration made for this page's own
/// challenge and origin can be accepted. Then an admin key signs the new manifest that holds the new key: on the same page
/// when an admin key works at this host (on the first run the new key is the admin and signs it itself), else on an
/// approval page where an admin key works, after the code. The key is stored only after both and after the person types,
/// in the terminal, the code the page shows. The link alone is not enough: whoever registers first gets the code on their
/// page, not in the terminal. Cancel, a bad registration, a wrong or missing admin assertion, a wrong code, a store that
/// changed, the time limit and any error store nothing.
/// </summary>
/// <remarks>Limit: a program that owns the person's terminal (for example a pseudo-console) can read both the link and the code.</remarks>
internal static class PasskeyRegistration
{
    public const string AnnouncePrefix = "To add the passkey, open this link: ";

    private const string NameTaken = "a passkey with that name is already enrolled";

    internal const string Script = """
        (function () {
            "use strict";
            var options = JSON.parse(document.getElementById("options").textContent);
            var create = document.getElementById("create");
            var second = document.getElementById("confirm");
            var cancel = document.getElementById("deny");
            var status = document.getElementById("status");
            var code = document.getElementById("code");
            var keyName = document.getElementById("f-key-name");
            var makeAdmin = document.getElementById("make-admin");
            var base = location.pathname.replace(/\/+$/, "");
            var encoder = new TextEncoder();
            var busy = false;
            var finished = false;
            var pending = null;
            var chosen = null;
            var noPrf = false;

            function show(text) {
                status.textContent = text;
            }

            function inputs(on) {
                keyName.disabled = !on;
                makeAdmin.disabled = !on;
            }

            function finish(text) {
                finished = true;
                create.disabled = true;
                second.disabled = true;
                cancel.disabled = true;
                inputs(false);
                show(text);
            }

            // The name, checked with the rules the program applies again: empty is the suggested name; at most the field's
            // length; no control, hidden or line-break characters; not a name already enrolled (without regard to case).
            function chosenName() {
                var text = keyName.value.trim();
                if (text.length === 0) {
                    text = keyName.getAttribute("data-default");
                }
                var taken = JSON.parse(keyName.getAttribute("data-taken"));
                if (text.length > Number(keyName.getAttribute("maxlength"))) {
                    return { error: "The name is longer than " + keyName.getAttribute("maxlength") + " characters." };
                }
                if (/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}]/u.test(text)) {
                    return { error: "The name has a control or hidden character." };
                }
                for (var i = 0; i < taken.length; i++) {
                    if (taken[i].toUpperCase() === text.toUpperCase()) {
                        return { error: "A passkey named \"" + taken[i] + "\" is already enrolled. Choose another name." };
                    }
                }
                return { name: text };
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

            //@SEAL_PRF@

            // Step 2: an admin passkey (on the first run, the new one) signs the new state, the manifest. Its challenge and
            // options are made here, before the person taps the Step 2 button, so the tap starts the prompt at once (iOS
            // WebKit refuses a second prompt that does not start in its own tap).
            function prepare(step) {
                return window.crypto.subtle.digest("SHA-256", encoder.encode(step.manifest)).then(function (hash) {
                    return window.crypto.subtle.digest("SHA-256", join(fromBase64Url(step.bind), new Uint8Array(hash)));
                }).then(function (challenge) {
                    busy = false;
                    if (finished) {
                        return;
                    }
                    pending = {
                        challenge: new Uint8Array(challenge),
                        rpId: step.rpId,
                        allowCredentials: step.allowCredentials.map(function (item) {
                            return { id: fromBase64Url(item.id), type: item.type };
                        }),
                        timeout: step.timeout,
                        userVerification: "required"
                    };
                    second.textContent = step.first ? "Step 2 of 2: confirm with your new passkey" : "Step 2 of 2: confirm with your admin passkey";
                    second.hidden = false;
                    second.disabled = false;
                    show("Step 1 is done: your passkey \"" + step.name + "\" was made. " + (step.makeAdmin ? "It will be an admin. " : "It will only approve runs (not an admin). ")
                        + "Now tap \"" + second.textContent + "\". Nothing is added until you do and type the code in the terminal.");
                    second.focus();
                });
            }

            // A reply with a code ends the page; a reply with a sign step shows the Step 2 button.
            function answer(reply) {
                if (!reply.ok) {
                    busy = false;
                    finish(noPrf
                        ? "This passkey cannot do PRF (it cannot protect the secret store key). Use a passkey from your phone or a security key. Nothing was added."
                        : reply.status === 403
                        ? "The passkey was not accepted. Nothing was added. If the terminal asks for a code, press Ctrl+C."
                        : "Nothing was added. If the terminal asks for a code, press Ctrl+C.");
                    return;
                }
                return reply.json().then(function (data) {
                    if (data.sign && typeof data.sign.manifest === "string" && pending === null) {
                        return prepare(data.sign);
                    }
                    busy = false;
                    if (typeof data.code !== "string") {
                        throw new Error("no code");
                    }
                    finish((data.later ? "Type this code in the terminal. The terminal then shows a link where an admin passkey confirms the change"
                        + (data.makeAdmin ? " (the new passkey will be an admin)." : " (the new passkey will only approve runs).")
                        : "Type this code in the terminal to finish.")
                        + (typeof data.admin === "string" ? " " + data.admin + ". Pages and --enrolled show this; if it ever changes, the state was replaced." : ""));
                    code.textContent = data.code;
                });
            }

            function publicKey(name) {
                return {
                    challenge: fromBase64Url(options.challenge),
                    rp: { id: options.rp.id, name: options.rp.name },
                    user: {
                        id: fromBase64Url(options.user.id),
                        name: options.user.name,
                        displayName: name
                    },
                    pubKeyCredParams: options.pubKeyCredParams,
                    authenticatorSelection: options.authenticatorSelection,
                    attestation: options.attestation,
                    excludeCredentials: options.excludeCredentials.map(function (item) {
                        return { id: fromBase64Url(item.id), type: item.type };
                    }),
                    timeout: options.timeout,
                    // The new key's slot: its PRF output for the salt the program chose, returned at create.
                    extensions: { prf: { eval: { first: fromBase64Url(options.prf.salt) } } }
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
                    chosen = chosenName();
                    request = chosen.error ? null : publicKey(chosen.name);
                } catch (error) {
                    show("The page data is not valid. Nothing was added.");
                    return;
                }
                if (chosen.error) {
                    show(chosen.error + " Nothing was added.");
                    keyName.focus();
                    return;
                }
                busy = true;
                create.disabled = true;
                inputs(false);
                show("Waiting for your passkey...");
                navigator.credentials.create({ publicKey: request }).then(function (credential) {
                    var response = credential.response;
                    var message = {
                        id: toBase64Url(credential.rawId),
                        clientDataJSON: toBase64Url(response.clientDataJSON),
                        attestationObject: toBase64Url(response.attestationObject),
                        name: chosen.name,
                        admin: makeAdmin.checked
                    };
                    var output = prfOutput(credential);
                    if (output === null) {
                        // No PRF at create: the program refuses this passkey (and says why) before anything is stored.
                        noPrf = true;
                        return JSON.stringify(message);
                    }
                    // The PRF output leaves the page only sealed to the program's key for this page.
                    return sealPrf(output, fromBase64Url(options.challenge), fromBase64Url(options.prf.serverKey)).then(function (sealed) {
                        message.prfEpk = sealed.epk;
                        message.prfIv = sealed.iv;
                        message.prfCt = sealed.ct;
                        return JSON.stringify(message);
                    });
                }).then(function (body) {
                    if (finished) {
                        busy = false;
                        return;
                    }
                    show("Checking your passkey...");
                    return post("create", body).then(answer).then(null, failed);
                }, function () {
                    busy = false;
                    if (!finished) {
                        create.disabled = false;
                        inputs(true);
                        show("No passkey was made. Nothing was added. You can try again or cancel.");
                    }
                });
            });

            // A step that failed after the server took part: tell the program, so it stops waiting.
            function failed() {
                busy = false;
                finish("Nothing was added. If the terminal asks for a code, press Ctrl+C.");
                post("deny", "").then(null, function () { });
            }

            // Step 2 runs in its own tap: the prompt starts at once, with the challenge made before.
            second.addEventListener("click", function () {
                if (finished || busy || pending === null) {
                    return;
                }
                busy = true;
                second.disabled = true;
                show("Waiting for your passkey...");
                navigator.credentials.get({ publicKey: pending }).then(function (credential) {
                    var response = credential.response;
                    if (finished) {
                        busy = false;
                        return;
                    }
                    show("Checking...");
                    return post("sign", JSON.stringify({
                        id: toBase64Url(credential.rawId),
                        authenticatorData: toBase64Url(response.authenticatorData),
                        clientDataJSON: toBase64Url(response.clientDataJSON),
                        signature: toBase64Url(response.signature)
                    })).then(answer).then(null, failed);
                }, function () {
                    busy = false;
                    if (!finished) {
                        second.disabled = false;
                        show("No passkey was used. Nothing was added yet. Tap \"" + second.textContent + "\" again, or cancel.");
                    }
                });
            });
            cancel.focus();
        })();
        """;

    /// <summary>
    /// Serves the page until the first outcome or the time limit. Refuses before anything starts when the address or the
    /// store cannot be used. The person chooses the key's name on the page (<paramref name="name" /> is the suggestion,
    /// used when the field is empty); it follows the rules of <see cref="Enrollment.NameError" /> and must not be enrolled
    /// already. After the browser's registration is checked, the page shows a code; the key is stored only when
    /// <paramref name="readCode" /> returns that code, within three tries and the time limit.
    /// </summary>
    public static ApprovalDecision Run(PasskeyStore store, ApprovalSettings settings, string name, Action<string> announce, Func<string?> readCode, Func<string, ManifestApproval>? askAdmin = null, Unlock? approval = null)
    {
        return Run(store, settings, name, announce, readCode, null, askAdmin, approval);
    }

    /// <summary>
    /// The same, with a page of another kind (<paramref name="plan" />; null is the plain enrollment page, which needs an
    /// enrolled admin key). Everything else is the same: the checks before start, the one accepted registration, the signed
    /// manifest, the code in the terminal, the time limit. <paramref name="askAdmin" /> asks an admin key to sign the new
    /// manifest on another page, for when no admin key works at this page's host; without it that case is refused.
    /// </summary>
    internal static ApprovalDecision Run(PasskeyStore store, ApprovalSettings settings, string name, Action<string> announce, Func<string?> readCode, RegistrationPlan? plan, Func<string, ManifestApproval>? askAdmin = null, Unlock? approval = null)
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
            name = Enrollment.Suggest(snapshot.Select(item => item.Name));
        }

        string suggestion = name;
        string adminLine = AdminKey.Line(current);
        string[] taken = [.. snapshot.Select(item => item.Name)];
        plan ??= new RegistrationPlan(
            "e",
            AnnouncePrefix,
            (rp, options) => Build(suggestion, rp, options, Script, ApprovalPage.Style + CodeStyle, adminLine, taken),
            (challenge, body) => (challenge, body),
            () => null,
            (key, admin) => current!.WithKey(key, admin),
            (signed, key) =>
            {
                Manifest next = Manifest.Parse(signed.Text, out _) ?? current!;
                bool admin = next.IsAdmin(key.Id);
                string signer = PasskeyMethod.Signer(current!, signed);

                return Commit(store.Database, signed, () => ApprovalDecision.Allow($"Added the passkey named \"{key.Name}\" for {key.RpId}" + (admin ? ", as an admin." : ".")),
                    (connection, transaction) => AuditLog.Append(connection, transaction, AuditLog.ChangeRow("key-enrolled",
                        $"passkey \"{key.Name}\" added for {key.RpId}" + (admin ? " as an admin" : " (approves runs only)") + $"; admin passkey {signer} verified", signer)));
            });

        // The master key the new key's slot will wrap. The first key makes it (nothing else needs it: it lives in this page only,
        // wrapped for that key). A key added to a state gets it from the approval that came first: the PRF output an existing
        // admin key released opens that key's slot. Zeroed on every way out.
        byte[]? master = null;
        (byte[] State, string PublicKey)? serverKey = null;
        try
        {
            if (current is null)
            {
                master = KeyVault.NewMasterKey();
            }
            else
            {
                try
                {
                    master = approval is null ? null : KeyVault.OpenMaster(current, approval);
                }
                catch (CryptographicException)
                {
                    master = null;
                }

                if (master is null)
                {
                    return ApprovalDecision.Deny("the approving passkey did not release the key that opens the master key (a passkey with PRF must approve), so the new passkey cannot get its slot; nothing was added");
                }
            }

            byte[] challenge = RandomNumberGenerator.GetBytes(32);
            byte[] slotSalt = KeyVault.NewSalt();
            serverKey = SecretCrypto.NewServerKey();
            Session session = new(store, name, challenge, [.. snapshot.Select(item => item.Id)], plan, settings, askAdmin, new PrfContext(serverKey.Value.State, slotSalt, master));
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
                // The page puts the name the person chose in place of this one.
                user = new { id = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16)), name = "with-secrets", displayName = name },
                pubKeyCredParams = new[] { new { type = "public-key", alg = WebAuthn.ES256 }, new { type = "public-key", alg = WebAuthn.RS256 } },
                authenticatorSelection = new { residentKey = "preferred", userVerification = "required" },
                attestation = "none",
                excludeCredentials = snapshot.Where(item => item.RpId == rpId).Select(item => new { id = item.Id, type = "public-key" }).ToArray(),
                timeout = (long)settings.Timeout.TotalMilliseconds,

                // The slot of the new key: the salt its PRF is asked with at create, and the key the page seals the PRF output to.
                prf = new { salt = Base64Url.EncodeToString(slotSalt), serverKey = serverKey.Value.PublicKey },
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
        finally
        {
            SecretValues.Clear(master);
            SecretValues.Clear(serverKey?.State);
        }
    }

    /// <summary>
    /// What one registration page needs to give its new key a slot: the page's server key (private state, to open the PRF output
    /// the page seals to it), the 32-byte salt the new key's PRF is evaluated with, and the master key the slot wraps. The
    /// arrays belong to <see cref="Run(PasskeyStore, ApprovalSettings, string, Action{string}, Func{string?}, RegistrationPlan?, Func{string, ManifestApproval}?, Unlock?)" />,
    /// which zeroes them when the page ends.
    /// </summary>
    private sealed record PrfContext(byte[] ServerState, byte[] Salt, byte[] Master);

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

    /// <summary>The Step 2 button of a page with two passkey prompts: hidden until step 1 is done, then the script names the key.</summary>
    internal const string StepTwoButton = "<button id=\"confirm\" type=\"button\" hidden disabled>Step 2 of 2: confirm with your passkey</button>";

    internal const string CodeStyle = """
        #code { font-size: 3rem; font-family: ui-monospace, monospace; letter-spacing: 0.3em; }
        """;

    /// <summary>The style of the name field and the admin box on the enrollment page.</summary>
    internal const string FieldStyle = """
        .field { margin: 1rem 0; }
        .field label { display: block; font-weight: bold; margin-bottom: 0.3rem; }
        .field input[type=text] { font-size: 1rem; padding: 0.5rem; width: 100%; max-width: 30rem; box-sizing: border-box; }
        .check label { display: inline; font-weight: normal; }
        """;

    /// <summary>
    /// The "Name for this passkey" field of every page that creates a passkey: prefilled with <paramref name="suggestion" />
    /// (also used when it is left empty), with the names already enrolled for the page's own check (the program checks
    /// again). HTML-encoded.
    /// </summary>
    internal static string NameField(string suggestion, IEnumerable<string> taken)
    {
        string limit = Enrollment.MaxNameLength.ToString(CultureInfo.InvariantCulture);
        string value = WebUtility.HtmlEncode(suggestion);

        return "<div class=\"field\"><label for=\"f-key-name\">Name for this passkey</label><input id=\"f-key-name\" type=\"text\" autocomplete=\"off\" autocapitalize=\"off\" spellcheck=\"false\" maxlength=\""
            + limit + "\" value=\"" + value + "\" data-default=\"" + value + "\" data-taken=\"" + WebUtility.HtmlEncode(JsonSerializer.Serialize(taken)) + "\">"
            + "<p class=\"hint\">Up to " + limit + " characters, and not a name already enrolled (without regard to case). Empty is \"" + value + "\". Pages, --enrolled and --audit show it.</p></div>\n";
    }

    /// <summary>
    /// Builds the page. Script and style line endings become LF before hashing and output, so the CSP hashes match what is
    /// served. The name is HTML-encoded; the options are JSON in a data block, with &lt; and &gt; escaped.
    /// </summary>
    internal static OneShotResponse Build(string name, string rpId, string options, string script, string style, string adminLine, IEnumerable<string>? taken = null)
    {
        script = PrfClient.Fill(script.ReplaceLineEndings("\n"));
        style = (style + FieldStyle).ReplaceLineEndings("\n");
        string policy = ApprovalPage.Policy(script, style);
        string text = "Works on: " + ApprovalSummary.Clean(rpId) + "\n" + ApprovalSummary.Clean(adminLine);

        StringBuilder page = new();
        page.Append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
        page.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
        page.Append("<meta name=\"referrer\" content=\"no-referrer\">\n");
        page.Append("<title>Add a passkey</title>\n");
        page.Append("<style>").Append(style).Append("</style>\n</head>\n<body>\n<main>\n");
        page.Append("<h1>Add a passkey for with-secrets</h1>\n");
        page.Append("<pre id=\"request\">").Append(WebUtility.HtmlEncode(text)).Append("</pre>\n");
        page.Append("<p>This passkey will be able to approve runs that use your secrets. Make it only on a device you keep with you.</p>\n");
        page.Append("<p>" + WebUtility.HtmlEncode(PrfClient.RequiredText) + "</p>\n");
        page.Append(NameField(name, taken ?? []));
        page.Append("<div class=\"field check\"><input id=\"make-admin\" type=\"checkbox\"> <label for=\"make-admin\">Also make this key an admin</label>"
            + "<p class=\"hint\">An admin key can change the settings, the secrets and the passkeys, and remove other admin keys. Leave it off for a key that only approves runs. "
            + "Two admin keys (for example a laptop and a phone) mean a lost device does not lock you out.</p></div>\n");
        page.Append("<p>Choose the name, then tap Create passkey. When an admin passkey works on this page, a second button then appears: tap it to confirm with your admin passkey (Step 2 of 2). Otherwise the terminal shows a link for that after the code.</p>\n");
        page.Append("<div class=\"buttons\">");
        page.Append("<button id=\"deny\" type=\"button\" autofocus>Cancel</button>");
        page.Append("<button id=\"create\" type=\"button\">Create passkey</button>");
        page.Append(StepTwoButton);
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
    private sealed class Session(PasskeyStore store, string name, byte[] challenge, HashSet<string> snapshot, RegistrationPlan plan, ApprovalSettings settings, Func<string, ManifestApproval>? askAdmin, PrfContext prf)
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

        // The name the person chose on the page (the suggestion until a registration comes), and whether the key becomes an admin.
        private readonly string _suggestion = name;
        private string _name = name;
        private bool _admin;

        // After an accepted registration: the key, the manifest to sign, the keys that may sign it, and (once signed) the signed manifest.
        private PasskeyRecord? _key;
        private Manifest? _next;
        private IReadOnlyList<PasskeyRecord> _signers = [];
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
        /// When no admin key works at this page's host, one signs the new manifest on an approval page where it works.
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

        /// <summary>
        /// The name the person chose and the "Also make this key an admin" box, from the body: "name" (a string; empty or
        /// missing is the suggestion) and "admin" (true or false; missing is false). False when either has another type or
        /// the body is not a JSON object.
        /// </summary>
        private bool TryChoice(string body, out string chosen, out bool admin)
        {
            chosen = _suggestion;
            admin = false;
            try
            {
                using JsonDocument document = JsonDocument.Parse(body, new JsonDocumentOptions { AllowDuplicateProperties = false });
                JsonElement root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object)
                {
                    return false;
                }

                if (root.TryGetProperty("name", out JsonElement typed))
                {
                    if (typed.ValueKind != JsonValueKind.String)
                    {
                        return false;
                    }

                    string text = typed.GetString()!.Trim();
                    chosen = text.Length == 0 ? _suggestion : text;
                }

                if (root.TryGetProperty("admin", out JsonElement box))
                {
                    if (box.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                    {
                        return false;
                    }

                    admin = box.ValueKind == JsonValueKind.True;
                }

                return true;
            }
            catch (JsonException)
            {
                return false;
            }
        }

        /// <summary>Called with the lock held. A checked registration goes on to the sign step or the code; anything else ends the enrollment.</summary>
        private OneShotResponse Register(string origin, string rpId, string body)
        {
            try
            {
                // The name and the admin box: checked here again, whatever the page checked before its prompt.
                if (!TryChoice(body, out string chosen, out bool admin))
                {
                    _decision.TrySetResult(ApprovalDecision.Deny("the page sent a request that is not valid"));

                    return Invalid;
                }

                string? nameError = Enrollment.NameError(chosen);
                if (nameError is not null)
                {
                    _decision.TrySetResult(ApprovalDecision.Deny(nameError + "; nothing was added"));

                    return Invalid;
                }

                _name = chosen;
                _admin = admin;

                // What the passkey was asked to sign, and the registration itself, from the body.
                (byte[] Challenge, string Registration)? read = plan.Read(challenge, body);
                if (read is not { } signed)
                {
                    _decision.TrySetResult(ApprovalDecision.Deny("the page sent a request that is not valid"));

                    return Invalid;
                }

                RegistrationResult result = WebAuthn.VerifyRegistration(signed.Challenge, origin, rpId, _name, signed.Registration);
                if (!result.Ok || result.Key is null)
                {
                    _decision.TrySetResult(ApprovalDecision.Deny("the passkey was not accepted: " + result.Detail));

                    return Refused;
                }

                string? problem = Problem(result.Key);
                if (problem is not null)
                {
                    _decision.TrySetResult(ApprovalDecision.Deny(problem));

                    return problem == NameTaken ? Invalid : Refused;
                }

                string? refused = plan.Accept();
                if (refused is not null)
                {
                    _decision.TrySetResult(ApprovalDecision.Deny(refused));

                    return Invalid;
                }

                // The new key's slot: only a passkey that did PRF at create (and sent its output, sealed to this page's server
                // key) can be enrolled. Refused here, before anything is stored: the person is told why.
                PasskeyRecord? slotted = WithSlot(result.Key, body);
                if (slotted is null)
                {
                    return Invalid;
                }

                result = result with { Key = slotted };

                // The manifest with the new key, and who may sign it: on the first run the new key itself, else every admin
                // key of the stored state that stays an admin. Those that work at this host may sign here.
                Manifest next = plan.Next(result.Key, _admin);
                bool first = next.Version == 1;
                List<PasskeyRecord> admins = first ? next.IsAdmin(result.Key.Id) ? [result.Key] : []
                    : store.TryAll(out IReadOnlyList<PasskeyRecord> keys) ? [.. keys.Where(item => item.Admin && next.IsAdmin(item.Id))] : [];
                if (admins.Count == 0)
                {
                    _decision.TrySetResult(ApprovalDecision.Deny("no admin passkey can be read"));

                    return Failed;
                }

                _key = result.Key;
                _next = next;
                _signers = [.. admins.Where(item => item.RpId == rpId)];
                if (_signers.Count == 0)
                {
                    // No admin key works here: one signs on another page after the code.
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
                        allowCredentials = _signers.Select(item => new { id = item.Id, type = "public-key" }).ToArray(),
                        timeout = (long)settings.Timeout.TotalMilliseconds,
                        first,
                        name = _name,
                        makeAdmin = next.IsAdmin(result.Key.Id),
                    },
                }));
            }
            catch (Exception)
            {
                _decision.TrySetResult(ApprovalDecision.Deny("the passkey could not be checked"));

                return Failed;
            }
        }

        /// <summary>
        /// Called with the lock held. The key with its slot: the master key wrapped under the PRF output the page sent (sealed to
        /// this page's server key, with the page's bind as associated data), for this credential and this page's salt. Null, with
        /// the decision set, when the page sent none or it does not open: a key that cannot do PRF is refused. The PRF output
        /// and its copies are zeroed here.
        /// </summary>
        private PasskeyRecord? WithSlot(PasskeyRecord key, string body)
        {
            byte[]? output = null;
            try
            {
                PrfBody? sealedPrf = ReadPrf(body);
                if (sealedPrf is null)
                {
                    _decision.TrySetResult(ApprovalDecision.Deny(PrfClient.CannotPrf));

                    return null;
                }

                output = SecretCrypto.DecryptBytes(prf.ServerState, challenge, sealedPrf.Epk, sealedPrf.Iv, sealedPrf.Ct, SecretCrypto.PrfInfo);
                if (output.Length != KeyVault.KeyBytes)
                {
                    _decision.TrySetResult(ApprovalDecision.Deny(PrfClient.CannotPrf));

                    return null;
                }

                string wrap = KeyVault.WrapSlot(prf.Master, output, Base64Url.DecodeFromChars(key.Id), prf.Salt);

                return key with { Slot = new KeySlot(Base64Url.EncodeToString(prf.Salt), wrap) };
            }
            catch (Exception)
            {
                _decision.TrySetResult(ApprovalDecision.Deny("the PRF output from the page could not be opened, so the passkey cannot protect the secret store key; nothing was added"));

                return null;
            }
            finally
            {
                SecretValues.Clear(output);
            }
        }

        /// <summary>The sealed PRF output in the body (<c>prfEpk</c>, <c>prfIv</c>, <c>prfCt</c>), or null when it has none.</summary>
        private static PrfBody? ReadPrf(string body)
        {
            try
            {
                using JsonDocument document = JsonDocument.Parse(body);
                Dictionary<string, string> members = new(StringComparer.Ordinal);
                foreach (JsonProperty property in document.RootElement.EnumerateObject())
                {
                    if (property.Value.ValueKind == JsonValueKind.String)
                    {
                        members[property.Name] = property.Value.GetString()!;
                    }
                }

                return PrfBody.FromFlat(members);
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>Called with the lock held. An admin's assertion over the new manifest, by a key the sign step offered; then the code.</summary>
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

                PasskeyRecord? signer = _signers.FirstOrDefault(item => item.Id == members["id"]);
                if (signer is null)
                {
                    _decision.TrySetResult(ApprovalDecision.Deny("the admin passkey did not sign the new state: the key that signed is not an admin key offered here"));

                    return Refused;
                }

                string proof = JsonSerializer.Serialize(members);
                string text = _next!.Canonical();
                AssertionResult result = WebAuthn.VerifyAssertion(signer, Manifest.Challenge(_bind!, text), origin, rpId, proof);
                if (!result.Ok)
                {
                    _decision.TrySetResult(ApprovalDecision.Deny("the admin passkey did not sign the new state: " + result.Detail));

                    return Refused;
                }

                if (signer.Id != _key!.Id)
                {
                    // The assertion was valid, so it stands even if the new count could not be saved.
                    store.UpdateSignCount(signer.Id, result.NewSignCount);
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

            // The admin keys of the new state, so the person sees their fingerprints (on the first run, for the first time).
            string admin = AdminKey.Line(_next);

            return new OneShotResponse(200, "application/json", later
                ? JsonSerializer.Serialize(new { ok = true, code = _code, later = true, admin, name = _name, makeAdmin = _next!.IsAdmin(_key!.Id) })
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

            return stored.Any(item => string.Equals(item.Name, _name, StringComparison.OrdinalIgnoreCase)) ? NameTaken : null;
        }
    }
}

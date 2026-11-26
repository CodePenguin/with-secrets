using System.Buffers.Text;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WithSecrets;

/// <summary>
/// How one registration page differs from the plain enrollment page. The first-run first-run setup page uses it to bind
/// the settings into the passkey's challenge and to store them with the key in one transaction.
/// </summary>
/// <param name="Prefix">The first part of the page path, before the token.</param>
/// <param name="AnnouncePrefix">The text before the link in the terminal.</param>
/// <param name="Page">Builds the page from the rpId and the creation options JSON.</param>
/// <param name="Read">From the server's challenge and the POST body: the challenge the passkey signed and the registration JSON, or null when the body is not valid.</param>
/// <param name="Accept">After the registration is checked and before the manifest step: null to go on, else why not.</param>
/// <param name="Next">The new manifest that holds the new key, an admin or not (the page's box). An admin of the stored state signs it: the new key itself on the first run.</param>
/// <param name="Commit">After the signed manifest and the right code: stores it (and anything that goes with it) and says how it went.</param>
/// <param name="Reencrypt">Only for <c>--recover</c>: from the new store's public key, the old secrets re-encrypted for it (name to ciphertext). They go into the first manifest as hashes, and are stored with it by <paramref name="Commit" />.</param>
/// <param name="WrapReview">Only for <c>--recover</c>: wraps the original review key under the new master key.</param>
internal sealed record RegistrationPlan(
    string Prefix,
    string AnnouncePrefix,
    Func<string, string, OneShotResponse> Page,
    Func<byte[], string, (byte[] Challenge, string Registration)?> Read,
    Func<string?> Accept,
    Func<PasskeyRecord, bool, Manifest> Next,
    Func<SignedManifest, PasskeyRecord, ApprovalDecision> Commit,
    Func<string, IReadOnlyDictionary<string, string>>? Reencrypt = null,
    Func<byte[], ReviewKey>? WrapReview = null);

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
            var attempt = 0;
            var waiting = null;
            var waitingLabel = "";
            var finished = false;
            var pending = null;
            var chosen = null;
            var noPrf = false;

            function show(text) {
                status.textContent = text + (diagLine ? " " + diagLine : "");
            }

            //@PROGRESS@

            //@FOLLOW@

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
                        timeout: step.timeout,
                        userVerification: "required"
                    };
                    second.textContent = step.first ? "Confirm with your new passkey" : "Confirm with your admin passkey";
                    second.hidden = false;
                    progress(2);
                    second.disabled = false;
                    show("Passkey \"" + step.name + "\" created. " + (step.makeAdmin ? "It will be an admin. " : "It will only approve runs. ") + "Now confirm it.");
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
                    if (typeof data.next === "string") {
                        follow(data.next);
                        return;
                    }
                    if (data.later === true) {
                        finish("Your passkey was made. An admin passkey confirms next, on the page the program opens.");
                        return;
                    }
                    if (typeof data.code !== "string") {
                        throw new Error("no code");
                    }
                    finish("Type this code in the terminal to finish. Nothing is saved until you do."
                        + (typeof data.admin === "string" ? " " + data.admin + "." : ""));
                    code.textContent = data.code;
                    progress(3);
                });
            }

            function publicKey(name, admin) {
                var key = {
                    challenge: fromBase64Url(options.challenge),
                    rp: { id: options.rp.id, name: options.rp.name },
                    user: {
                        id: fromBase64Url(options.user.id),
                        name: passkeyLabel(options.user.name, name),
                        displayName: passkeyLabel(options.user.displayName, name)
                    },
                    pubKeyCredParams: options.pubKeyCredParams,
                    authenticatorSelection: options.authenticatorSelection,
                    attestation: options.attestation,
                    excludeCredentials: options.excludeCredentials.map(function (item) {
                        return { id: fromBase64Url(item.id), type: item.type };
                    }),
                    timeout: options.timeout
                };
                if (admin) {
                    key.extensions = { prf: { eval: { first: fromBase64Url(options.prf.salt) } } };
                }
                return key;
            }

            // While a passkey prompt is open the tapped button stays on and reads "Cancel": a prompt that closes without ever
            // settling must not leave the page stuck. The cancel starts no prompt; it only abandons the attempt.
            function startWait(button) {
                waiting = button;
                waitingLabel = button.textContent;
                button.textContent = "Cancel";
                button.disabled = false;
            }

            function endWait() {
                if (waiting !== null) {
                    waiting.textContent = waitingLabel;
                    waiting = null;
                }
            }

            function cancelAttempt() {
                attempt++;
                var button = waiting;
                endWait();
                busy = false;
                if (button === create) {
                    inputs(true);
                }
                show("Cancelled. Tap again to try.");
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
                if (finished) {
                    return;
                }
                if (waiting === create) {
                    cancelAttempt();
                    return;
                }
                if (busy) {
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
                var admin = makeAdmin.checked;
                try {
                    chosen = chosenName();
                    request = chosen.error ? null : publicKey(chosen.name, admin);
                } catch (error) {
                    show("The page data is not valid. Nothing was added.");
                    return;
                }
                if (chosen.error) {
                    show(chosen.error + " Nothing was added.");
                    keyName.focus();
                    return;
                }
                var mine = ++attempt;
                busy = true;
                startWait(create);
                inputs(false);
                show("Waiting for your passkey...");
                navigator.credentials.create({ publicKey: request }).then(function (credential) {
                    if (mine !== attempt) {
                        return null;
                    }
                    var response = credential.response;
                    var message = {
                        id: toBase64Url(credential.rawId),
                        clientDataJSON: toBase64Url(response.clientDataJSON),
                        attestationObject: toBase64Url(response.attestationObject),
                        name: chosen.name,
                        admin: admin
                    };
                    if (!admin) {
                        return JSON.stringify(message);
                    }
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
                    if (mine !== attempt) {
                        return;
                    }
                    if (finished) {
                        busy = false;
                        return;
                    }
                    endWait();
                    create.disabled = true;
                    show("Checking your passkey...");
                    return post("create", body).then(answer).then(null, failed);
                }, function (error) {
                    if (mine !== attempt) {
                        return;
                    }
                    busy = false;
                    endWait();
                    if (!finished) {
                        create.disabled = false;
                        inputs(true);
                        show("No passkey was made" + why(error) + ". Nothing was added. You can try again or cancel.");
                    }
                });
            });

            // The browser's own error, for the status line: its name and message (cut to 120 characters). Never any key text.
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

            // No answer from the program within 20 seconds: the action button is on again, the page is not finished.
            function timedOut() {
                if (pending === null) {
                    create.disabled = false;
                    inputs(true);
                } else {
                    second.disabled = false;
                }
                show("The program did not answer within 20 seconds. Check the terminal. Tap again to retry.");
            }

            // A step that failed after the server took part: tell the program, so it stops waiting.
            function failed(error) {
                busy = false;
                if (error && error.name === "AbortError") {
                    if (!finished) {
                        timedOut();
                    }
                    return;
                }
                finish("Nothing was added. If the terminal asks for a code, press Ctrl+C.");
                post("deny", "").then(null, function () { });
            }

            // Step 2 runs in its own tap: the prompt starts at once, with the challenge made before.
            second.addEventListener("click", function () {
                if (finished) {
                    return;
                }
                if (waiting === second) {
                    cancelAttempt();
                    return;
                }
                if (busy || pending === null) {
                    return;
                }
                var mine = ++attempt;
                busy = true;
                startWait(second);
                show("Waiting for your passkey...");
                navigator.credentials.get({ publicKey: pending }).then(function (credential) {
                    if (mine !== attempt) {
                        return;
                    }
                    var response = credential.response;
                    if (finished) {
                        busy = false;
                        return;
                    }
                    endWait();
                    second.disabled = true;
                    show("Checking...");
                    return post("sign", JSON.stringify({
                        id: toBase64Url(credential.rawId),
                        authenticatorData: toBase64Url(response.authenticatorData),
                        clientDataJSON: toBase64Url(response.clientDataJSON),
                        signature: toBase64Url(response.signature)
                    })).then(answer).then(null, failed);
                }, function (error) {
                    if (mine !== attempt) {
                        return;
                    }
                    busy = false;
                    endWait();
                    if (!finished) {
                        second.disabled = false;
                        show("No passkey was used" + why(error) + ". Nothing was added yet. Tap \"" + second.textContent + "\" again, or cancel.");
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
    internal static ApprovalDecision Run(PasskeyStore store, ApprovalSettings settings, string name, Action<string> announce, Func<string?> readCode, RegistrationPlan? plan, Func<string, ManifestApproval>? askAdmin = null, Unlock? approval = null, Func<string, ApprovalDecision>? releaseAdmin = null)
    {
        using IDisposable flowScope = PageFlow.Enter();
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

        // The plain enrollment page adds a key the admin approves; the first key comes with the settings.
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
                VerifiedCredential? signer = PasskeyMethod.Signer(current!, signed);

                return Commit(store.Database, signed, () => ApprovalDecision.Allow($"Added the passkey named \"{key.Name}\" for {key.RpId}" + (admin ? ", as an admin." : ".")),
                    (connection, transaction) => store.Database.AppendAudit(connection, transaction, AdminEvent.Change("key-enrolled",
                        $"passkey \"{key.Name}\" added for {key.RpId}" + (admin ? " as an admin" : " (convenience key)") + $"; admin passkey {signer?.Name ?? "?"} verified", signer?.Name ?? "", signer)));
            });

        // The first setup generates the master key. In an existing state, only an admin enrollment needs to open it.
        byte[]? master = null;
        (byte[] State, string PublicKey)? serverKey = null;
        FirstStore? firstStore = null;
        try
        {
            if (current is null)
            {
                master = KeyVault.NewMasterKey();

                // First setup also makes the store's key pair, in memory: the public key and the private key wrapped under the master
                // key (the vault) go into the same first manifest the admin signs. The private key is written nowhere else, so a
                // page that does not finish leaves nothing behind. (Its hex text is a .NET string for a moment and cannot be wiped.)
                byte[]? privateKey = null;
                byte[]? recoveryCode = null;
                try
                {
                    (string publicKey, string privateText) = JweCipher.Instance.NewKeyPair();
                    privateKey = Encoding.UTF8.GetBytes(privateText);

                    // The recovery code (shown once, on the last page, never to the terminal) with its slot of the master key. The slot
                    // goes into the same signed first manifest as the vault; only the page ever gets the code.
                    recoveryCode = KeyVault.NewRecoveryCode();
                    KeySlot recovery = KeyVault.NewRecoverySlot(master, recoveryCode, publicKey);
                    IReadOnlyDictionary<string, string> rows = plan.Reencrypt?.Invoke(publicKey) ?? new Dictionary<string, string>();
                    ReviewKey review = plan?.WrapReview?.Invoke(master) ?? KeyVault.NewReviewKey(master);
                    firstStore = new FirstStore(publicKey, KeyVault.WrapVault(privateKey, master, publicKey), review, recovery, recoveryCode, rows);
                    recoveryCode = null;
                }
                finally
                {
                    SecretValues.Clear(privateKey);
                    SecretValues.Clear(recoveryCode);
                }
            }
            byte[] challenge = RandomNumberGenerator.GetBytes(32);
            // All admin slots share one salt, which the browser can pass as a single `eval` input.
            string? sharedSalt = current?.Keys.Select(item => item.Slot?.Salt).FirstOrDefault(item => item is not null);
            byte[] slotSalt = sharedSalt is null ? KeyVault.NewSalt() : Base64Url.DecodeFromChars(sharedSalt);
            serverKey = SecretCrypto.NewServerKey();
            PageFlow? flow = PageFlow.Current;
            Session session = new(store, name, challenge, [.. snapshot.Select(item => item.Id)], plan, settings, askAdmin, current,
                new PrfContext(serverKey.Value.State, slotSalt, master, firstStore), approval, releaseAdmin, flow is null ? null : flow.TakeNext);
            using PageSlot server = PageFlow.Open(plan.Prefix, settings.Port, session.Handle).Keep();
            PageFlow.OnEnd(session.Forget);
            string origin = settings.PageOrigin(server.Port);
            if (PasskeyMethod.RpIdOf(origin) != rpId)
            {
                return ApprovalDecision.Deny("the enrollment page address changed");
            }

            string label = PasskeyLabel.NewId();
            string options = JsonSerializer.Serialize(new
            {
                challenge = Base64Url.EncodeToString(challenge),
                rp = new { id = rpId, name = "with-secrets" },
                // A random id; the page makes the display label "with-secrets <chosen name> <id>" (see PasskeyLabel).
                user = new { id = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16)), name = label, displayName = label },
                pubKeyCredParams = new[] { new { type = "public-key", alg = WebAuthn.ES256 }, new { type = "public-key", alg = WebAuthn.RS256 } },
                authenticatorSelection = new { residentKey = "required", requireResidentKey = true, userVerification = "required" },
                attestation = "none",
                excludeCredentials = snapshot.Where(item => item.RpId == rpId).Select(item => new { id = item.Id, type = "public-key" }).ToArray(),
                timeout = (long)settings.Timeout.TotalMilliseconds,

                // The slot of the new key: the salt its PRF is asked with at create, and the key the page seals the PRF output to.
                prf = new { salt = Base64Url.EncodeToString(slotSalt), serverKey = serverKey.Value.PublicKey },
            });

            session.Open(origin, rpId, plan.Page(rpId, options));
            server.Ready();
            // A page reached from the step before is already open in the person's browser: no second link.
            if (!server.Reserved)
            {
                announce(plan.AnnouncePrefix + origin + "/" + plan.Prefix + "/" + server.Token);
            }

            return session.Wait(PageFlow.Left(settings.Timeout), readCode);
        }
        catch (ProofUnavailableException error)
        {
            return ApprovalDecision.Deny(error.Message);
        }
        catch (Exception)
        {
            return ApprovalDecision.Deny("the enrollment page failed: " + HandleGuard.Reason);
        }
        finally
        {
            SecretValues.Clear(master);
            SecretValues.Clear(serverKey?.State);
            SecretValues.Clear(firstStore?.RecoveryCode);
        }
    }

    /// <summary>
    /// What a first setup makes besides the first key: the store's public key and its vault, the recovery slot (and the recovery
    /// code itself, which only the last page ever shows; zeroed when the page ends) and, for <c>--recover</c>, the old secrets
    /// re-encrypted for the new store key.
    /// </summary>
    private sealed record FirstStore(string PublicKey, string Vault, ReviewKey Review, KeySlot Recovery, byte[] RecoveryCode, IReadOnlyDictionary<string, string> Rows);

    /// <summary>
    /// What one registration page needs to give its new key a slot: the page's server key (private state, to open the PRF output
    /// the page seals to it), the 32-byte salt the new key's PRF is evaluated with, and the master key the slot wraps. The
    /// arrays are zeroed when the page ends.
    /// </summary>
    private sealed record PrfContext(byte[] ServerState, byte[] Salt, byte[]? Master, FirstStore? FirstStore);

    internal const string NothingEnrolled = "Nothing is enrolled. Set up the first passkey with: with-secrets admin (more are added in the admin web app).";

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

    /// <summary>The three steps of a page that makes a passkey: the script marks the current one (<c>progress(n)</c>).</summary>
    internal const string Steps = "<ol class=\"steps\" aria-label=\"Steps\"><li id=\"s1\" aria-current=\"step\">Create the passkey</li><li id=\"s2\">Confirm it</li><li id=\"s3\">Type the code</li></ol>\n";

    /// <summary>The script's <c>progress(n)</c>: steps before n are done, step n is the current one. Nothing happens on a page without the steps.</summary>
    internal const string ProgressScript = """
        function progress(n) {
                for (var i = 1; i <= 3; i++) {
                    var item = document.getElementById("s" + i);
                    if (!item) { continue; }
                    item.className = i < n ? "done" : "";
                    if (i === n) { item.setAttribute("aria-current", "step"); } else { item.removeAttribute("aria-current"); }
                }
                var intro = document.getElementById("intro");
                var form = document.getElementById("form");
                if (intro) { intro.hidden = n > 1; }
                if (form) { form.hidden = n > 2; }
                var first = document.getElementById("save") || document.getElementById("create");
                if (first) { first.hidden = n > 1; }
            }
        """;

    /// <summary>The Step 2 button of a page with two passkey prompts: hidden until step 1 is done, then the script names the key.</summary>
    internal const string StepTwoButton = "<button id=\"confirm\" type=\"button\" hidden disabled>Confirm with your passkey</button>";

    internal const string CodeStyle = """
        #code { margin: 1rem 0; font-size: 2.5rem; font-family: ui-monospace, 'Cascadia Mono', Consolas, monospace; letter-spacing: 0.3em; }
        #recovery { margin: 0 0 1rem; font-size: 1.3rem; font-family: ui-monospace, 'Cascadia Mono', Consolas, monospace; letter-spacing: 0.1em; overflow-wrap: anywhere; background: var(--surface-2); border: 2px solid var(--border); border-radius: 0.5rem; padding: 1rem; }
        """;

    /// <summary>
    /// The box of the last page that shows the recovery code (hidden until the code arrives). The code is put in with
    /// <c>textContent</c>, never as HTML.
    /// </summary>
    internal const string RecoveryBox = "<div id=\"recovery-box\" hidden><h2>Recovery code</h2>"
        + "<p>Write it down and keep it offline. It is shown once. If every passkey is lost, it is the only way back to your secrets (with-secrets --recover).</p>"
        + "<p id=\"recovery\"></p></div>\n";

    /// <summary>
    /// The script that shows a recovery code from a reply (<c>data.recovery</c>) in the <see cref="RecoveryBox" />: the page's
    /// <c>showRecovery(data)</c>. Text only (<c>textContent</c>).
    /// </summary>
    internal const string RecoveryScript = """
        function showRecovery(data) {
                var box = document.getElementById("recovery-box");
                var shown = document.getElementById("recovery");
                if (box && shown && typeof data.recovery === "string") {
                    shown.textContent = data.recovery;
                    box.hidden = false;
                }
            }
        """;

    /// <summary>The style of the name field and the admin box on the enrollment page.</summary>
    internal const string FieldStyle = """
        .field { margin: 1rem 0; }
        .field label { display: block; font-weight: 700; margin-bottom: 0.3rem; }
        .field input[type=text] { font: inherit; padding: 0.5rem 0.75rem; width: 100%; border: 2px solid var(--border); border-radius: 0.5rem; background: var(--surface); color: var(--text); }
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

        return "<div class=\"field\"><label for=\"f-key-name\">Passkey name</label><input id=\"f-key-name\" type=\"text\" autocomplete=\"off\" autocapitalize=\"off\" spellcheck=\"false\" maxlength=\""
            + limit + "\" value=\"" + value + "\" data-default=\"" + value + "\" data-taken=\"" + WebUtility.HtmlEncode(JsonSerializer.Serialize(taken)) + "\">"
            + "<p class=\"hint\">Up to " + limit + " characters. Shown in the app and the audit history.</p></div>\n";
    }

    /// <summary>
    /// Builds the page. Script and style line endings become LF before hashing and output, so the CSP hashes match what is
    /// served. The name is HTML-encoded; the options are JSON in a data block, with &lt; and &gt; escaped.
    /// </summary>
    internal static OneShotResponse Build(string name, string rpId, string options, string script, string style, string adminLine, IEnumerable<string>? taken = null)
    {
        script = PrfClient.Fill(PageContinue.Fill(script.Replace("//@PROGRESS@", ProgressScript, StringComparison.Ordinal).ReplaceLineEndings("\n")));
        style = (style + FieldStyle).ReplaceLineEndings("\n");
        string policy = ApprovalPage.Policy(script, style);
        string text = "Works on: " + ApprovalSummary.Clean(rpId) + "\n" + ApprovalSummary.Clean(adminLine);

        StringBuilder page = new();
        page.Append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
        page.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
        page.Append("<meta name=\"referrer\" content=\"no-referrer\">\n");
        page.Append("<title>Add a passkey</title>\n");
        page.Append("<style>").Append(style).Append("</style>\n</head>\n<body>\n<header class=\"bar\">with-secrets administration</header>\n<main class=\"setup\">\n");
        page.Append("<h1>Add a passkey</h1>\n");
        page.Append(Steps);
        page.Append("<div id=\"intro\">\n<pre id=\"request\">").Append(WebUtility.HtmlEncode(text)).Append("</pre>\n");
        page.Append("<p>" + WebUtility.HtmlEncode(PrfClient.RequiredText) + "</p>\n</div>\n<div id=\"form\">\n");
        page.Append(NameField(name, taken ?? []));
        page.Append("<div class=\"field check\"><input id=\"make-admin\" type=\"checkbox\"> <label for=\"make-admin\">Also make this key an admin</label>"
            + "<p class=\"hint\">An admin key can also change settings, secrets and passkeys. Keep two, on different devices.</p></div>\n");
        page.Append("<div class=\"buttons\">");
        page.Append("<button id=\"create\" type=\"button\">Create passkey</button>");
        page.Append(StepTwoButton);
        page.Append("<button id=\"deny\" type=\"button\" autofocus>Cancel</button>");
        page.Append("</div>\n</div>\n<p id=\"status\" role=\"status\"></p>\n" + PageContinue.Box + "<p id=\"code\"></p>\n</main>\n");
        page.Append("<script type=\"application/json\" id=\"options\">").Append(options).Append("</script>\n");
        page.Append("<script>").Append(script).Append("</script>\n</body>\n</html>\n");

        return new OneShotResponse(200, "text/html; charset=utf-8", page.ToString(), policy);
    }

    /// <summary>
    /// The state of one enrollment. Requests are handled one at a time. Only the first registration that is accepted goes
    /// on: to the admin's assertion over the new manifest (when it can be made on this page), then the code. After that the
    /// page answers only Cancel. The first final outcome wins.
    /// </summary>
    private sealed class Session(PasskeyStore store, string name, byte[] challenge, HashSet<string> snapshot, RegistrationPlan plan,
        ApprovalSettings settings, Func<string, ManifestApproval>? askAdmin, Manifest? current, PrfContext prf,
        Unlock? approval, Func<string, ApprovalDecision>? releaseAdmin, Func<string?>? takeNext)
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
        private OneShotResponse? _reply;
        private byte[]? _replyFor;
        private string _replyStep = "";

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
        private PrfBody? _adminPrf;

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
            if (_adminPrf is { } pending)
            {
                if (FinishAdmin(key, pending) is { } refused)
                {
                    return refused;
                }

                key = _key!;
            }

            // If confirmation happens on its own page, it shows the code after the signature.
            if (SignElsewhere() is { } ended)
            {
                return ended;
            }

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
                    return Store(key);
                }
            }

            return End(ApprovalDecision.Deny("the code was wrong three times; nothing was added"));
        }

        private ApprovalDecision? FinishAdmin(PasskeyRecord key, PrfBody pending)
        {
            ApprovalDecision released = releaseAdmin!(key.Name);
            using Unlock? unlock = released.Unlock;
            if (!released.Approved)
            {
                return End(released);
            }

            lock (_gate)
            {
                if (_decision.Task.IsCompleted)
                {
                    return _decision.Task.Result;
                }

                if (OpenAdminSlot(key, pending, unlock) is not { } slotted)
                {
                    return _decision.Task.Result;
                }

                _key = slotted;
                _next = plan.Next(slotted, true);
                _code = NewCode();

                return null;
            }
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
                PageFlow.OfferCode(_code);
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

        /// <summary>Every request gets an answer. A bug that throws ends the page with "internal error" and answers 500.</summary>
        public OneShotResponse Handle(string verb, string suffix, string body)
        {
            return HandleGuard.Run(verb, suffix, () => HandleRequest(verb, suffix, body),
                () => _decision.TrySetResult(ApprovalDecision.Deny(HandleGuard.Reason + "; nothing was added")), Failed, NotFound);
        }

        private OneShotResponse HandleRequest(string verb, string suffix, string body)
        {
            lock (_gate)
            {
                if (_origin is null || _rpId is null || _page is null)
                {
                    return NotFound;
                }

                // The verified step's reply is kept for the body that earned it: sent again byte for byte (the reply was lost), it gets the
                // same reply, which makes no second page and no second code. Any other request after the decision gets 404.
                if (_reply is not null && _replyFor is not null && verb == "POST" && suffix == _replyStep
                    && CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(body)), _replyFor))
                {
                    return _reply;
                }

                if (_decision.Task.IsCompleted)
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
                    return verb == "POST" && suffix == "sign" ? Kept(suffix, body, Sign(_origin, _rpId, body)) : NotFound;
                }

                switch (verb, suffix)
                {
                    case ("GET", ""):
                        return _page;
                    case ("POST", "create"):
                        return Kept(suffix, body, Register(_origin, _rpId, body));
                    default:
                        return NotFound;
                }
            }
        }

        /// <summary>Called with the lock held. When the step just verified (its reply was made by <see cref="Code" />), keeps the reply for this body.</summary>
        private OneShotResponse Kept(string step, string body, OneShotResponse reply)
        {
            if (_reply is not null && _replyFor is null && ReferenceEquals(reply, _reply))
            {
                _replyStep = step;
                _replyFor = SHA256.HashData(Encoding.UTF8.GetBytes(body));
            }

            return reply;
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

                if (_admin || prf.FirstStore is not null)
                {
                    if (ReadPrf(body) is not { } sealedPrf)
                    {
                        _decision.TrySetResult(ApprovalDecision.Deny(PrfClient.CannotPrf));

                        return Invalid;
                    }

                    if (prf.Master is null && approval is null && releaseAdmin is not null && takeNext?.Invoke() is { } nextPage)
                    {
                        _adminPrf = sealedPrf;
                        _key = result.Key;
                        _reply = new OneShotResponse(200, "application/json", JsonSerializer.Serialize(new { ok = true, next = nextPage }));
                        _verified.TrySetResult(result.Key);

                        return _reply;
                    }

                    PasskeyRecord? slotted = prf.Master is { } master ? WithSlot(result.Key, sealedPrf, master) : OpenAdminSlot(result.Key, sealedPrf, approval);
                    if (slotted is null)
                    {
                        return Invalid;
                    }

                    result = result with { Key = slotted };
                }

                // The manifest with the new key, and who may sign it: on the first run the new key itself, else every admin
                // key of the stored state that stays an admin. Those that work at this host may sign here.
                Manifest next = plan.Next(result.Key, _admin);
                bool first = next.Version == 1;
                if (first && prf.FirstStore is { } firstStore)
                {
                    // The first manifest already holds the store key and its vault: the first secret needs only an admin signature.
                    next = next with
                    {
                        Store = firstStore.PublicKey,
                        Vault = firstStore.Vault,
                        Review = firstStore.Review,
                        Recovery = firstStore.Recovery,
                        Secrets = new SortedDictionary<string, string>(firstStore.Rows.ToDictionary(item => item.Key, item => SecretStore.Hash(item.Value)), StringComparer.Ordinal),
                    };
                }

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

        private PasskeyRecord? OpenAdminSlot(PasskeyRecord key, PrfBody sealedPrf, Unlock? unlock)
        {
            byte[]? master = null;
            try
            {
                if (current is not null && unlock is not null)
                {
                    master = KeyVault.OpenMaster(current, unlock);

                    return WithSlot(key, sealedPrf, master);
                }
            }
            catch (CryptographicException)
            {
                // A verified passkey may still be unable to open the master key.
            }
            finally
            {
                SecretValues.Clear(master);
            }

            _decision.TrySetResult(ApprovalDecision.Deny("the approving passkey did not release the key that opens the master key (a passkey with PRF must approve), so the new passkey cannot get its slot; nothing was added"));

            return null;
        }

        /// <summary>Wraps the master key under the new admin's PRF output, sealed to this page by the browser.</summary>
        private PasskeyRecord? WithSlot(PasskeyRecord key, PrfBody sealedPrf, byte[] master)
        {
            byte[]? output = null;
            try
            {
                output = SecretCrypto.DecryptBytes(prf.ServerState, challenge, sealedPrf.Epk, sealedPrf.Iv, sealedPrf.Ct, SecretCrypto.PrfInfo);
                if (output.Length != KeyVault.KeyBytes)
                {
                    _decision.TrySetResult(ApprovalDecision.Deny(PrfClient.CannotPrf));

                    return null;
                }

                string wrap = KeyVault.WrapSlot(master, output, Base64Url.DecodeFromChars(key.Id), prf.Salt);

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
                Dictionary<string, string>? members = FirstRunPage.StringMembers(body);
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
            _code = NewCode();

            // The admin keys of the new state, so the person sees their fingerprints (on the first run, for the first time).
            string admin = AdminKey.Line(_next);

            if (later)
            {
                // An admin signs on another page, which the reply leads to (made now, before the command goes on). That page shows
                // the code after the signature verified; this reply holds none.
                string? next = takeNext?.Invoke();
                _verified.TrySetResult(_key!);

                _reply = new OneShotResponse(200, "application/json", next is null
                    ? JsonSerializer.Serialize(new { ok = true, later = true, name = _name })
                    : JsonSerializer.Serialize(new { ok = true, next }));

                return _reply;
            }

            _verified.TrySetResult(_key!);

            // A first setup also shows the recovery code, on this last page only (see RecoveryCode): written down by the person, never printed.
            _reply = new OneShotResponse(200, "application/json", prf.FirstStore is { } first
                ? JsonSerializer.Serialize(new { ok = true, code = _code, admin, recovery = RecoveryCode.Format(first.RecoveryCode) })
                : JsonSerializer.Serialize(new { ok = true, code = _code, admin }));

            return _reply;
        }

        private static string NewCode() => RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6", CultureInfo.InvariantCulture);

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

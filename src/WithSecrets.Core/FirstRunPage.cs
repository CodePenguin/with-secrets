using System.Buffers.Text;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WithSecrets;

/// <summary>How a human command ended: 0 when it was done, else a <see cref="RunCommand" /> exit code and why.</summary>
public sealed record ConfigChange(int Code, string Detail)
{
    public bool Done => Code == 0;
}

/// <summary>
/// The first-run setup, run by <c>with-secrets admin</c> when nothing is enrolled (and by <c>--recover</c> for a new state): a
/// page served once creates the first passkey for the page's host (normally localhost), which is the first admin key. The
/// passkey is created over a challenge built from the registration's own random challenge and the settings of the new state
/// (the defaults, or those carried by a recovery); then the new key signs the first manifest (a second passkey prompt). The page
/// shows a code; only when the person types it in the terminal (three tries) are the manifest and the audit row written, in one
/// transaction. There is no save without both proofs. Cancel, a wrong proof, the time limit and any error save nothing. The
/// first outcome ends the page; after it every request is 404. Later changes to the settings are made in the admin web app.
/// </summary>
public sealed class FirstRunPage(StateDatabase db, EnrollmentTarget primaryTarget, EnrollmentTarget localTarget, Action<string> announce, Func<string?>? readCode)
{
    private readonly EnrollmentTarget primary = primaryTarget;
    private readonly EnrollmentTarget local = localTarget;

    public const string AnnouncePrefix = "To set up with-secrets, open this link: ";

    internal const string PathPrefix = "c";

    private static readonly OneShotResponse NotFound = new(404, "text/plain; charset=utf-8", "Not found.");

    /// <summary>Only for <c>--recover</c>: the old rows and settings carried into this first setup.</summary>
    internal RecoveryCarry? Carry { get; set; }

    /// <summary>The local service already running for a fresh interactive setup.</summary>
    public HostService? Service { get; init; }

    /// <summary>The challenge the passkey signs for these settings: SHA-256(seed || SHA-256(UTF-8 of the canonical JSON)).</summary>
    internal static byte[] Challenge(byte[] seed, string canonical)
    {
        return SHA256.HashData([.. seed, .. SHA256.HashData(Encoding.UTF8.GetBytes(canonical))]);
    }

    public ConfigChange Run()
    {
        using IDisposable flow = PageFlow.Enter();
        if (!db.TryManifest(out Manifest? manifest, out string? error))
        {
            return new ConfigChange(RunCommand.StoreError, error!);
        }

        PasskeyStore passkeys = new(db);
        ConfigChange change;
        try
        {
            change = manifest is null ? FirstRun(passkeys, Carry?.Settings ?? ToolSettings.Defaults) : Denied("something is enrolled already; set up is only for a state with nothing in it");
        }
        catch (ProofUnavailableException failure)
        {
            change = Denied(failure.Message);
        }
        catch (Exception)
        {
            change = Denied("the settings page failed; nothing was saved");
        }

        return change;
    }

    private static ConfigChange Denied(string detail) => new(RunCommand.Denied, detail);

    /// <summary>Nothing is enrolled: the first passkey, then its signature over the first manifest, then the code, then one write.</summary>
    private ConfigChange FirstRun(PasskeyStore passkeys, ToolSettings current)
    {
        if (readCode is null)
        {
            return Denied("this setup has no way to ask for the code from the page; nothing was saved");
        }

        // The page host is where the key works: the primary page when passkeys can work there, else localhost.
        EnrollmentTarget target = Usable(primary) ? primary : local;
        string? sent = null;
        int failure = RunCommand.Denied;
        IReadOnlyDictionary<string, string> carried = new Dictionary<string, string>();
        QuickStartRegistration? quickStart = Service is { } service && Carry is null ? new(service) : null;
        if (quickStart is not null)
        {
            announce("Quick Start · local service running");
            announce("Device: " + ApprovalSummary.Clean(quickStart.DeviceName));
            announce("Device fingerprint: " + quickStart.Fingerprint);
        }

        RegistrationPlan plan = new(
            PathPrefix,
            AnnouncePrefix,
            (_, options) => ConfigPageHtml.Build(JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["options"] = Parse(options),
                ["settings"] = current.Canonical(),
                ["quickStart"] = quickStart is not null,
            }), Carry?.PageNote, quickStart),
            (challenge, body) =>
            {
                Dictionary<string, string>? members = StringMembers(body);
                if (members is null || new[] { "settings", "id", "clientDataJSON", "attestationObject" }.Any(field => !members.ContainsKey(field)))
                {
                    return null;
                }

                sent = members["settings"];
                if (sent != current.Canonical())
                {
                    return null;
                }

                string registration = JsonSerializer.Serialize(new Dictionary<string, string>
                {
                    ["id"] = members["id"],
                    ["clientDataJSON"] = members["clientDataJSON"],
                    ["attestationObject"] = members["attestationObject"],
                });

                return (Challenge(challenge, sent), registration);
            },
            () => sent is null ? "no settings were sent; nothing was saved" : null,
            (key, _) => Manifest.First(key, current),
            (signed, key) =>
            {
                try
                {
                    // Version 0 expected: a passkey enrolled elsewhere meanwhile makes this stale, and nothing is saved.
                    ApprovalDecision done = PasskeyRegistration.Commit(db, signed,
                        () => ApprovalDecision.Allow($"Set up. Admin passkey \"{key.Name}\" added.\n"
                            + $"Admins: {AdminKey.Entry(key.Name, key.PublicKey)}. Note the fingerprint.\nThe recovery code was shown once. If you missed it, rotate the keys in the admin app."),
                        (connection, transaction) =>
                        {
                            foreach ((string name, string ciphertext) in carried)
                            {
                                WithSecretsDatabase.Execute(connection, transaction, "INSERT INTO secrets (name, ciphertext) VALUES ($name, $ciphertext)", ("$name", name), ("$ciphertext", ciphertext));
                            }

                            if (SecretStore.Problem(db.CurrentManifest(connection, transaction), SecretStore.AllRows(connection, transaction)) is { } mismatch)
                            {
                                throw new InvalidOperationException("the carried secrets do not match the new state (" + mismatch + ")");
                            }

                            AdminEvent setup = AdminEvent.Change("setup", $"first passkey \"{key.Name}\" (admin) added for {key.RpId}", key.Name, new VerifiedCredential(key.Id, key.Name, true));
                            if (Carry is { } carry)
                            {
                                // Recovery writes these events when it installs the recovered store in the live database.
                                carry.Pending.Add(setup);
                                carry.Pending.Add(AdminEvent.Change("recovered", $"recovered {carry.Count} secrets from {carry.OldFileName} (copied to {carry.RecoveredName}); new keys made", key.Name, new VerifiedCredential(key.Id, key.Name, true)));
                            }
                            else
                            {
                                db.AppendAudit(connection, transaction, setup);
                            }
                        });

                    return done.Approved ? done : ApprovalDecision.Deny("a passkey was enrolled or the state changed while the page was open; nothing was saved");
                }
                catch (StateDatabaseException error)
                {
                    failure = RunCommand.StoreError;

                    return ApprovalDecision.Deny("the settings and the passkey could not be saved (" + error.Message + "); nothing was saved");
                }
            },
            Carry is { } recovery ? publicKey => carried = recovery.Reencrypt(publicKey) : null,
            Carry is { } carryReview ? carryReview.WrapReview : null,
            quickStart);

        ApprovalDecision decision = PasskeyRegistration.Run(passkeys, target.Approver.Settings, Enrollment.DefaultName, announce, readCode, plan);

        return decision.Approved ? new ConfigChange(0, decision.Detail) : new ConfigChange(failure, decision.Detail);
    }

    private static bool Usable(EnrollmentTarget target)
    {
        try
        {
            ApprovalSettings settings = target.Approver.Settings;
            PasskeyMethod.RpIdOf(settings.PageOrigin(settings.Port));

            return true;
        }
        catch (ProofUnavailableException)
        {
            return false;
        }
    }

    private static JsonElement Parse(string json)
    {
        using JsonDocument document = JsonDocument.Parse(json);

        return document.RootElement.Clone();
    }

    /// <summary>The members of a JSON object whose values are all strings. Null for anything else or a name that appears twice.</summary>
    internal static Dictionary<string, string>? StringMembers(string json)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            Dictionary<string, string> members = new(StringComparer.Ordinal);
            foreach (JsonProperty property in document.RootElement.EnumerateObject())
            {
                if (property.Value.ValueKind != JsonValueKind.String || !members.TryAdd(property.Name, property.Value.GetString()!))
                {
                    return null;
                }
            }

            return members;
        }
        catch (JsonException)
        {
            return null;
        }
    }

}

/// <summary>The first-run page. All text is HTML-encoded.</summary>
internal static class ConfigPageHtml
{
    /// <summary>
    /// The one inline script. A new passkey is created over the settings of the new state; then the server sends the first
    /// manifest and the new passkey signs it (a second prompt, behind its own Step 2 button); then the page shows the code to
    /// type in the terminal. Every challenge is made before the tap that uses it (when the page opens, or when step 1 ends),
    /// so each tap starts its passkey prompt with nothing awaited first. There is no keyboard shortcut.
    /// </summary>
    private const string Script = """
        (function () {
            "use strict";
            var start = JSON.parse(document.getElementById("start").textContent);
            var save = document.getElementById("save");
            var second = document.getElementById("confirm");
            var cancel = document.getElementById("deny");
            var status = document.getElementById("status");
            var code = document.getElementById("code");
            var base = location.pathname.replace(/\/+$/, "");
            var encoder = new TextEncoder();
            var busy = false;
            var attempt = 0;
            var waiting = null;
            var finished = false;
            var ready = null;
            var pending = null;
            var keyName = document.getElementById("f-key-name");
            var noPrf = false;
            var deviceVerified = !start.quickStart;
            var verifyDevice = document.getElementById("verify-device");

            function show(text) {
                status.textContent = text + (diagLine ? " " + diagLine : "");
            }

            //@PROGRESS@

            // The name field on or off: off while a passkey prompt is open and at the end.
            function inputs(on) {
                keyName.disabled = !on;
            }

            function finish(text) {
                finished = true;
                save.disabled = true;
                second.disabled = true;
                cancel.disabled = true;
                if (verifyDevice) verifyDevice.disabled = true;
                inputs(false);
                show(text);
            }

            // The first run's name, checked with the rules the program applies again: empty is the default name; at most the
            // field's length; no control, hidden or line-break characters.
            function chosenName() {
                var text = keyName.value.trim();
                if (text.length === 0) {
                    text = keyName.getAttribute("data-default");
                }
                if (text.length > Number(keyName.getAttribute("maxlength"))) {
                    return { error: "The name is longer than " + keyName.getAttribute("maxlength") + " characters." };
                }
                if (/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}]/u.test(text)) {
                    return { error: "The name has a control or hidden character." };
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
                        credentials: start.quickStart && what === "sign" ? "same-origin" : "omit",
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

            //@SHOW_RECOVERY@

            function creation(challenge, name) {
                var options = start.options;
                return {
                    challenge: challenge,
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
                    timeout: options.timeout,
                    // The first key's slot: its PRF output for the salt the program chose, returned at create.
                    extensions: { prf: { eval: { first: fromBase64Url(options.prf.salt) } } }
                };
            }

            // The challenge of the registration, made when the page opens (not in the tap), so that the first tap starts the
            // passkey prompt at once: iOS WebKit refuses a prompt that follows an awaited step. It binds the passkey to the
            // settings of the new state: SHA-256(seed || SHA-256(settings)).
            function prepare() {
                if (finished || busy || !window.crypto || !window.crypto.subtle || ready !== null) {
                    return;
                }
                var seed;
                try {
                    seed = fromBase64Url(start.options.challenge);
                } catch (error) {
                    return;
                }
                window.crypto.subtle.digest("SHA-256", encoder.encode(start.settings)).then(function (hash) {
                    return window.crypto.subtle.digest("SHA-256", join(seed, new Uint8Array(hash)));
                }).then(function (challenge) {
                    ready = { challenge: new Uint8Array(challenge) };
                }, function () { });
            }

            // The first run's step 2: the new passkey signs the first manifest. Its challenge is made here, before the
            // person taps the Step 2 button, so that tap starts the prompt at once; the reply then has the code.
            function confirm(step) {
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
                    if (start.quickStart) {
                        pending.extensions = { prf: { eval: { first: fromBase64Url(start.options.prf.salt) } } };
                        pending.allowCredentials = [{ id: fromBase64Url(step.credential), type: "public-key" }];
                        pending.bind = fromBase64Url(step.bind);
                    }
                    inputs(false);
                    second.textContent = start.quickStart ? "Confirm setup and unlock" : "Confirm with your new passkey";
                    second.hidden = false;
                    progress(start.quickStart ? 3 : 2);
                    if (start.quickStart) {
                        document.getElementById("quick-passkey-name").hidden = true;
                        document.getElementById("quick-finish").hidden = false;
                        document.getElementById("form").hidden = false;
                    }
                    second.disabled = false;
                    show(start.quickStart ? "Confirm to trust this device, unlock the service, and sign in on this browser." :
                        "Passkey \"" + step.name + "\" created. Now confirm it.");
                    second.focus();
                });
            }

            function coded(data) {
                if (start.quickStart && data.quickStart) {
                    var signedIn = typeof data.antiForgery === "string";
                    if (signedIn) {
                        try { sessionStorage.setItem("ws.session-secret", data.antiForgery); }
                        catch (error) { signedIn = false; }
                    }
                    finish(signedIn ? "This device is trusted and the service is unlocked." : "Setup was saved. Open the app to finish.");
                    progress(3);
                    showRecovery(data);
                    document.getElementById("quick-device").hidden = true;
                    document.getElementById("form").hidden = true;
                    document.getElementById("quick-done").hidden = false;
                    return;
                }
                if (typeof data.code !== "string") {
                    throw new Error("no code");
                }
                finish("Type this code in the terminal to finish. Nothing is saved until you do.");
                code.textContent = data.code;
                progress(3);
                showRecovery(data);
            }

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

            // Keep the page's Cancel button available if the passkey prompt stalls.
            // During the prompt it abandons the attempt and leaves the page ready to retry.
            function startWait(button) {
                waiting = button;
                button.disabled = true;
            }

            function endWait() {
                waiting = null;
            }

            function cancelAttempt() {
                attempt++;
                var button = waiting;
                endWait();
                busy = false;
                button.disabled = false;
                if (button === save) {
                    inputs(true);
                }
                show("Cancelled. Tap again to try.");
            }

            // A first-run step that failed after the server took part: tell the program, so it stops waiting.
            // No answer from the program within 20 seconds: the action button is on again, the page is not finished.
            function timedOut() {
                if (pending !== null) {
                    second.disabled = false;
                } else {
                    save.disabled = false;
                    inputs(true);
                }
                show("The program did not answer within 20 seconds. Check the terminal. Tap again to retry.");
            }

            function failed(error) {
                busy = false;
                if (error && error.name === "AbortError") {
                    if (!finished) {
                        timedOut();
                    }
                    return;
                }
                finish("Nothing was saved, or the answer could not be read. The terminal says what was saved.");
                post("deny", "").then(null, function () { });
            }

            // Step 2 runs in its own tap: the prompt starts at once, with the challenge made before.
            second.addEventListener("click", function () {
                if (finished) {
                    return;
                }
                if (busy || pending === null) {
                    return;
                }
                var mine = ++attempt;
                busy = true;
                startWait(second);
                show("Waiting for your passkey...");
                var proofOptions = Object.assign({}, pending);
                delete proofOptions.bind;
                navigator.credentials.get({ publicKey: proofOptions }).then(function (credential) {
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
                    var proof = {
                        id: toBase64Url(credential.rawId),
                        authenticatorData: toBase64Url(response.authenticatorData),
                        clientDataJSON: toBase64Url(response.clientDataJSON),
                        signature: toBase64Url(response.signature)
                    };
                    var payload = Promise.resolve(proof);
                    if (start.quickStart) {
                        var output = prfOutput(credential);
                        if (output === null) {
                            failed(new Error("the passkey did not release an unlock key"));
                            return;
                        }
                        payload = sealPrf(output, pending.bind, fromBase64Url(start.options.prf.serverKey)).then(function (sealed) {
                            proof.prf = JSON.stringify(sealed);
                            return proof;
                        });
                    }
                    return payload.then(function (value) {
                        return post("sign", JSON.stringify(value));
                    }).then(function (reply) {
                        if (!reply.ok) {
                            throw new Error("refused");
                        }
                        return reply.json();
                    }).then(function (data) {
                        busy = false;
                        coded(data);
                    }).then(null, failed);
                }, function (error) {
                    if (mine !== attempt) {
                        return;
                    }
                    busy = false;
                    endWait();
                    if (!finished) {
                        second.disabled = false;
                        show("No passkey was used" + why(error) + ". Nothing was saved yet. Tap \"" + second.textContent + "\" again, or cancel.");
                    }
                });
            });

            cancel.addEventListener("click", function () {
                if (finished) {
                    return;
                }
                if (waiting !== null) {
                    cancelAttempt();
                    return;
                }
                finish("Sending cancel...");
                post("deny", "").then(function (reply) {
                    show(reply.ok ? "Cancelled. Nothing was saved. You can close this page." : "This page had already ended.");
                }, function () {
                    show("Could not reach the program. With no answer it saves nothing at its time limit.");
                });
            });

            save.addEventListener("click", function () {
                if (finished || !deviceVerified) {
                    return;
                }
                if (busy) {
                    return;
                }
                if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
                    show("This page needs an https address or localhost. Nothing was saved.");
                    return;
                }
                if (!window.PublicKeyCredential || !navigator.credentials) {
                    show("This browser does not support passkeys. Nothing was saved.");
                    return;
                }
                var request;
                var named = chosenName();
                if (named.error) {
                    show(named.error + " Nothing was saved.");
                    keyName.focus();
                    return;
                }
                try {
                    // The seed of the challenge must be there and be base64url, or no tap can ever succeed: say so now,
                    // rather than asking for another tap.
                    var seed = start.options.challenge;
                    if (typeof seed !== "string" || !/^[A-Za-z0-9_-]+$/.test(seed)) {
                        throw new Error("no seed");
                    }
                    fromBase64Url(seed);
                    request = creation(null, named.name);
                } catch (error) {
                    show("The page data is not valid. Nothing was saved.");
                    return;
                }
                if (ready === null) {
                    // The challenge is not made yet: make it, and ask for another tap.
                    prepare();
                    show("Getting ready. Tap the button again.");
                    return;
                }
                request.challenge = ready.challenge;
                var mine = ++attempt;
                busy = true;
                startWait(save);
                // The name cannot be edited while the prompt is open.
                inputs(false);
                show("Waiting for your passkey...");
                // Runs in the tap: nothing is awaited before the passkey prompt.
                navigator.credentials.create({ publicKey: request }).then(function (credential) {
                    if (mine !== attempt) {
                        return null;
                    }
                    var response = credential.response;
                    var body = {
                        settings: start.settings,
                        id: toBase64Url(credential.rawId),
                        clientDataJSON: toBase64Url(response.clientDataJSON)
                    };
                    body.attestationObject = toBase64Url(response.attestationObject);
                    body.name = named.name;
                    var output = prfOutput(credential);
                    if (output === null) {
                        // No PRF at create: the program refuses this passkey (and says why) before anything is stored.
                        noPrf = true;
                        return JSON.stringify(body);
                    }
                    // The PRF output leaves the page only sealed to the program's key for this page.
                    return sealPrf(output, fromBase64Url(start.options.challenge), fromBase64Url(start.options.prf.serverKey)).then(function (sealed) {
                        body.prfEpk = sealed.epk;
                        body.prfIv = sealed.iv;
                        body.prfCt = sealed.ct;
                        return JSON.stringify(body);
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
                    save.disabled = true;
                    show("Checking your passkey...");
                    return post("create", body).then(function (reply) {
                        if (!reply.ok) {
                            busy = false;
                            finish(noPrf ? "This passkey cannot do PRF (it cannot protect the secret store key). Use a passkey from your phone or a security key. Nothing was saved."
                                : (reply.status === 403 ? "Your passkey was not accepted. Nothing was saved." : "Nothing was saved. The terminal says why.")
                                + " If the terminal asks for a code, press Ctrl+C.");
                            return;
                        }
                        return reply.json().then(function (data) {
                            if (data.sign && typeof data.sign.manifest === "string") {
                                // Step 1 is done; step 2 waits for its own tap.
                                return confirm(data.sign);
                            }
                            busy = false;
                            coded(data);
                        });
                    }).then(null, failed);
                }, function (error) {
                    if (mine !== attempt) {
                        return;
                    }
                    busy = false;
                    endWait();
                    if (!finished) {
                        save.disabled = false;
                        inputs(true);
                        show("No passkey was used" + why(error) + ". Nothing was saved. You can try again or cancel.");
                    }
                });
            });

            function checkTerminal() {
                if (finished) return;
                fetch(base + "/verified", { cache: "no-store" }).then(function (reply) {
                    if (!reply.ok) {
                        finish("This setup has ended. Check the terminal.");
                        return;
                    }
                    return reply.json().then(function (session) {
                        if (finished) return;
                        if (!session.verified) {
                            setTimeout(checkTerminal, 350);
                            return;
                        }
                        document.getElementById("quick-terminal").textContent = "Code accepted. Compare the fingerprint with the one in your terminal.";
                        document.getElementById("quick-code").hidden = true;
                        verifyDevice.disabled = false;
                    });
                }).catch(function () {
                    if (!finished) setTimeout(checkTerminal, 750);
                });
            }
            prepare();
            if (start.quickStart) {
                inputs(false);
                checkTerminal();
                verifyDevice.addEventListener("click", function () {
                    verifyDevice.disabled = true;
                    post("verify-device", "").then(function (reply) {
                        if (finished) return;
                        if (!reply.ok) {
                            finish("This setup has ended. Check the terminal.");
                            return;
                        }
                        deviceVerified = true;
                        document.getElementById("quick-device").hidden = true;
                        verifyDevice.hidden = true;
                        progress(2);
                        document.getElementById("intro").hidden = false;
                        document.getElementById("quick-passkey-name").hidden = false;
                        save.hidden = false;
                        inputs(true);
                        show("");
                        keyName.focus();
                    }).catch(function () {
                        if (!finished) {
                            verifyDevice.disabled = false;
                            show("Could not confirm the fingerprint. Try again.");
                        }
                    });
                });
            }
            cancel.focus();
        })();
        """;

    /// <summary>
    /// Builds the page. Script and style line endings become LF before hashing and output, so the CSP hashes match what is
    /// served. <paramref name="start" /> is the JSON for the data block, made with the default encoder (which escapes &lt;,
    /// &gt; and &amp;, so it cannot end the block).
    /// </summary>
    public static OneShotResponse Build(string start, string? note, QuickStartRegistration? quickStart = null)
    {
        string script = PrfClient.Fill(Script.Replace("//@SHOW_RECOVERY@", PasskeyRegistration.RecoveryScript, StringComparison.Ordinal).Replace("//@PROGRESS@", PasskeyRegistration.ProgressScript, StringComparison.Ordinal).ReplaceLineEndings("\n"));
        string quickStyle = quickStart is null ? "" : """

            #quick-code code { font-size: 2rem; letter-spacing: .22em; font-weight: 700; }
            #quick-done { margin-top: 1.25rem; }
            #quick-done summary { min-height: 2.75rem; padding: 0.5rem 0; color: var(--accent); font-weight: 600; cursor: pointer; }
            #quick-done summary:focus-visible, #quick-done a:focus-visible { outline: 3px solid var(--accent); outline-offset: 3px; }
            #quick-done a { display: inline-flex; align-items: center; min-height: 2.75rem; padding: 0.5rem 1rem; border-radius: 0.5rem; background: var(--accent); color: var(--accent-text); font-weight: 600; text-decoration: none; }
            #quick-done a:hover { filter: brightness(0.94); }
            """;
        string style = (ApprovalPage.Style + PasskeyRegistration.CodeStyle + PasskeyRegistration.FieldStyle + quickStyle).ReplaceLineEndings("\n");
        string policy = ApprovalPage.Policy(script, style);

        StringBuilder page = new();
        page.Append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
        page.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
        page.Append("<meta name=\"referrer\" content=\"no-referrer\">\n");
        page.Append("<title>Set up with-secrets</title>\n");
        page.Append("<style>").Append(style).Append("</style>\n</head>\n<body>\n<header class=\"bar\">with-secrets</header>\n<main class=\"setup\">\n");
        page.Append("<h1>Set up with-secrets</h1>\n");
        if (quickStart is null)
        {
            page.Append(PasskeyRegistration.Steps);
        }
        else
        {
            page.Append("<p><strong>Quick Start</strong></p>\n<ol class=\"steps\" aria-label=\"Steps\"><li id=\"s1\" aria-current=\"step\">Verify device</li><li id=\"s2\">Create passkey</li><li id=\"s3\">Finish setup</li></ol>\n");
            page.Append("<section id=\"quick-device\"><h2>Verify this device</h2><p id=\"quick-terminal\">Enter this six-digit code in the terminal that opened Quick Start.</p><div id=\"quick-code\" class=\"code-copy-row\"><div class=\"code-copy-actions\"><code id=\"terminal-code\">")
                .Append(quickStart.Code).Append("</code>").Append(PasskeyRegistration.CopyCodeButton("terminal-code", "Copy terminal code"))
                .Append("</div>").Append(PasskeyRegistration.CopyFeedback).Append("</div><p>Device fingerprint for ").Append(Encode(quickStart.DeviceName))
                .Append("</p><p><code id=\"device-fingerprint\">").Append(Encode(quickStart.Fingerprint)).Append("</code></p></section>\n");
            page.Append("<h2 id=\"quick-finish\" hidden>Finish setup</h2>\n");
        }
        page.Append(quickStart is null ? "<div id=\"intro\">\n" : "<div id=\"intro\" hidden><h2>Create your passkey</h2>\n");
        page.Append("<p>Create the first passkey. It becomes your admin key: the one that can change settings, secrets and passkeys.</p>\n");
        page.Append("<p>" + WebUtility.HtmlEncode(PrfClient.RequiredText) + "</p>\n");
        if (note is not null)
        {
            page.Append("<p id=\"note\" class=\"hint\">").Append(Encode(note)).Append("</p>\n");
        }

        page.Append("</div>\n<div id=\"form\">\n");
        if (quickStart is not null) page.Append("<div id=\"quick-passkey-name\" hidden>");
        page.Append(PasskeyRegistration.NameField(Enrollment.DefaultName, []));
        if (quickStart is not null) page.Append("</div>\n");
        page.Append("<div class=\"buttons\">");
        if (quickStart is not null) page.Append("<button id=\"verify-device\" type=\"button\" disabled>Fingerprint matches. Continue</button>");
        page.Append(quickStart is null ? "<button id=\"save\" type=\"button\">Create passkey</button>"
            : "<button id=\"save\" type=\"button\" hidden>Create passkey</button>");
        page.Append(PasskeyRegistration.StepTwoButton);
        page.Append("<button id=\"deny\" type=\"button\" autofocus>Cancel</button>");
        page.Append("</div>\n</div>\n<p id=\"status\" role=\"status\"></p>\n<p id=\"code\"></p>\n");
        page.Append(PasskeyRegistration.RecoveryBox);
        if (quickStart is not null)
        {
            page.Append("""
                <div id="quick-done" hidden>
                  <details>
                    <summary>See how a secret is used</summary>
                    <p>Say you store a secret named <code>REPORT_TOKEN</code>. A reporting script can request it with this command.</p>
                    <pre><code>with-secrets --secrets REPORT_TOKEN --reason "Generate report" -- node report.js</code></pre>
                    <p>When you approve the request, the script receives <code>REPORT_TOKEN</code> as an environment variable.</p>
                  </details>
                  <a href="/admin/">Open with-secrets</a>
                </div>
                """);
        }
        page.Append("</main>\n");
        page.Append("<script type=\"application/json\" id=\"start\">").Append(start).Append("</script>\n");
        page.Append("<script>").Append(script).Append("</script>\n</body>\n</html>\n");

        return new OneShotResponse(200, "text/html; charset=utf-8", page.ToString(), policy);
    }

    private static string Encode(string text) => WebUtility.HtmlEncode(ApprovalSummary.Clean(text));
}

using System.Buffers.Text;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WithSecrets;

/// <summary>How <c>--config</c> ended: 0 when the settings were saved (or nothing changed), else a <see cref="RunCommand" /> exit code and why.</summary>
public sealed record ConfigChange(int Code, string Detail)
{
    public bool Done => Code == 0;
}

/// <summary>
/// <c>--config</c>: the settings change only on a web page served once, never in the terminal, which gets only the link. The
/// page shows every setting with its current value and its limits as a form, and a summary of the changes.
/// <para>
/// With a passkey enrolled, Save is approved with the admin passkey: it signs the new manifest (the current one with the new
/// settings and the next version, see <see cref="Manifest" />), <c>SHA-256(bind || SHA-256(manifest))</c>. The page builds the
/// manifest text from the prefix it is given and the canonical JSON of the form (see <see cref="ToolSettings.Canonical" />).
/// The server checks the assertion with the admin key first, then checks every value, then writes the new manifest (only if
/// the stored one is still the version the page started from) and an audit row (the names of the settings that changed,
/// old -> new, and the key) in one transaction. The page is served at the first of the two targets where the admin key works.
/// </para>
/// <para>
/// With nothing enrolled this is the first-run setup: the same form, and Save creates the first passkey for the page's host
/// (normally localhost) over a challenge built from the registration's own random challenge and the settings; then the new
/// key, which is the admin, signs the first manifest (a second passkey prompt). The page shows a code; only when the person
/// types it in the terminal (three tries) are the manifest and the audit row written, in one transaction. There is no save
/// without both proofs.
/// </para>
/// Cancel, a wrong proof, a key other than the admin, a value out of its limits, a state that changed while the page was open,
/// the time limit and any error save nothing. The first outcome ends the page; after it every request is 404.
/// </summary>
public sealed class SettingsPage(StateDatabase db, EnrollmentTarget primaryTarget, EnrollmentTarget localTarget, Action<string> announce, Func<string?>? readCode)
{
    // Only the admin key may change the settings.
    private readonly EnrollmentTarget primary = primaryTarget.Admin();
    private readonly EnrollmentTarget local = localTarget.Admin();

    public const string AnnouncePrefix = "To change the settings, open this link: ";

    internal const string PathPrefix = "c";

    private static readonly OneShotResponse NotFound = new(404, "text/plain; charset=utf-8", "Not found.");

    /// <summary>The challenge the passkey signs for these settings: SHA-256(seed || SHA-256(UTF-8 of the canonical JSON)).</summary>
    internal static byte[] Challenge(byte[] seed, string canonical)
    {
        return SHA256.HashData([.. seed, .. SHA256.HashData(Encoding.UTF8.GetBytes(canonical))]);
    }

    public ConfigChange Run()
    {
        if (!db.TryManifest(out Manifest? manifest, out string? error))
        {
            return new ConfigChange(RunCommand.StoreError, error!);
        }

        PasskeyStore passkeys = new(db);
        ConfigChange change;
        try
        {
            change = manifest is null ? FirstRun(passkeys, ToolSettings.Defaults) : Gated(manifest);
        }
        catch (ProofUnavailableException failure)
        {
            change = Denied(failure.Message);
        }
        catch (Exception)
        {
            change = Denied("the settings page failed; nothing was saved");
        }

        // A refused or failed change is recorded (never on the first run, which has no state.db yet).
        if (!change.Done)
        {
            new AuditLog(db).TryWriteDenied("--config", [], change.Detail);
        }

        return change;
    }

    private static ConfigChange Denied(string detail) => new(RunCommand.Denied, detail);

    /// <summary>Something is enrolled: the page is served where the admin key works, and Save needs the admin key.</summary>
    private ConfigChange Gated(Manifest manifest)
    {
        ToolSettings current = manifest.Settings;
        EnrollmentTarget? target = EnrollmentTarget.FirstThatCanProve(primary, local);
        if (target is null)
        {
            return Denied(Enrollment.NoTargetMessage(primary.Method.Id, primary.Host, local.Host));
        }

        ApprovalSettings settings = target.Approver.Settings;

        // Passkeys need https or localhost; this throws before anything listens.
        PasskeyMethod.RpIdOf(settings.PageOrigin(settings.Port));
        Session session = new(db, target.Method, manifest);
        try
        {
            using OneShotServer server = new(PathPrefix, settings.Port, session.Handle);
            string origin = settings.PageOrigin(server.Port);
            string nonce = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16));
            string adminLine = AdminKey.Line(manifest);
            byte[] bind = RequestBinding.Compute(nonce, "Change the with-secrets settings from " + current.Canonical() + "\n" + adminLine);
            ProofStart start = target.Method.Start(new ProofContext(bind, origin));
            string json = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["flow"] = "assert",
                ["mode"] = start.Mode,
                ["payload"] = start.Payload,
                ["bind"] = Base64Url.EncodeToString(bind),
                ["nonce"] = nonce,
                ["current"] = Current(current),
                ["prefix"] = manifest.WithSettings(current).SettingsPrefix(),
            });

            session.Open(origin, bind, ConfigPageHtml.Build(false, current, json, adminLine));
            announce(AnnouncePrefix + origin + "/" + PathPrefix + "/" + server.Token);

            return session.Wait(settings.Timeout);
        }
        finally
        {
            session.Close();
        }
    }

    /// <summary>Nothing is enrolled: the form, then the first passkey, then its signature over the first manifest, then the code, then one write.</summary>
    private ConfigChange FirstRun(PasskeyStore passkeys, ToolSettings current)
    {
        if (readCode is null)
        {
            return Denied("this setup has no way to ask for the code from the page; nothing was saved");
        }

        // The page host is where the key works: the primary page when passkeys can work there, else localhost.
        EnrollmentTarget target = Usable(primary) ? primary : local;
        string? sent = null;
        ToolSettings? chosen = null;
        int failure = RunCommand.Denied;

        RegistrationPlan plan = new(
            PathPrefix,
            AnnouncePrefix,
            (_, options) => ConfigPageHtml.Build(true, current, JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["flow"] = "register",
                ["options"] = Parse(options),
                ["current"] = Current(current),
            }), AdminKey.NotSetUp),
            (challenge, body) =>
            {
                Dictionary<string, string>? members = StringMembers(body);
                if (members is null || new[] { "settings", "id", "clientDataJSON", "attestationObject" }.Any(field => !members.ContainsKey(field)))
                {
                    return null;
                }

                sent = members["settings"];
                string registration = JsonSerializer.Serialize(new Dictionary<string, string>
                {
                    ["id"] = members["id"],
                    ["clientDataJSON"] = members["clientDataJSON"],
                    ["attestationObject"] = members["attestationObject"],
                });

                return (Challenge(challenge, sent), registration);
            },
            () =>
            {
                if (sent is null)
                {
                    return "no settings were sent; nothing was saved";
                }

                chosen = ToolSettings.FromCanonical(sent, out string? error);

                return chosen is null ? "the settings are not valid (" + error + "); nothing was saved" : null;
            },
            key => Manifest.First(key, chosen!),
            (signed, key) =>
            {
                IReadOnlyList<SettingChange> changes = current.Changes(chosen!);
                try
                {
                    // Version 0 expected: a passkey enrolled elsewhere meanwhile makes this stale, and nothing is saved.
                    ApprovalDecision done = PasskeyRegistration.Commit(db, signed,
                        () => ApprovalDecision.Allow($"Saved the settings and added the passkey named \"{key.Name}\" for {key.RpId}.\n"
                            + $"Admin key: {AdminKey.Fingerprint(key.PublicKey)} ({ApprovalSummary.Clean(key.Name)}). Note this fingerprint down: every page shows it, and if it ever changes, the state was replaced."),
                        (connection, transaction) => AuditLog.Append(connection, transaction, AuditLog.SettingsRow("settings-setup", changes, key.Name, $"first passkey \"{key.Name}\" (admin) added for {key.RpId}")));

                    return done.Approved ? done : ApprovalDecision.Deny("a passkey was enrolled or the state changed while the page was open; nothing was saved");
                }
                catch (StateDatabaseException error)
                {
                    failure = RunCommand.StoreError;

                    return ApprovalDecision.Deny("the settings and the passkey could not be saved (" + error.Message + "); nothing was saved");
                }
            });

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

    /// <summary>The current values as a JSON value for the page's data block.</summary>
    private static JsonElement Current(ToolSettings current) => Parse(current.Canonical());

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

    /// <summary>
    /// The state of one passkey-gated page. Requests are handled one at a time under one lock; the first outcome is final, and
    /// after it every request is 404. The write happens inside the lock, so the time limit cannot cut it in half.
    /// </summary>
    private sealed class Session(StateDatabase db, IProofMethod method, Manifest manifest)
    {
        private readonly ToolSettings current = manifest.Settings;

        private static readonly OneShotResponse Ok = new(200, "application/json", "{\"ok\":true}");
        private static readonly OneShotResponse Refused = new(403, "application/json", "{\"ok\":false}");
        private static readonly OneShotResponse Invalid = new(400, "application/json", "{\"ok\":false}");
        private static readonly OneShotResponse Conflict = new(409, "application/json", "{\"ok\":false}");
        private static readonly OneShotResponse Failed = new(500, "application/json", "{\"ok\":false}");

        private static readonly string[] Fields = ["settings", "id", "authenticatorData", "clientDataJSON", "signature"];

        private readonly Lock _gate = new();
        private readonly TaskCompletionSource<ConfigChange> _decision = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private string? _origin;
        private byte[]? _bind;
        private OneShotResponse? _page;

        public void Open(string origin, byte[] bind, OneShotResponse page)
        {
            lock (_gate)
            {
                _origin = origin;
                _bind = bind;
                _page = page;
            }
        }

        public ConfigChange Wait(TimeSpan timeout)
        {
            if (!_decision.Task.Wait(timeout))
            {
                lock (_gate)
                {
                    _decision.TrySetResult(Denied("no answer before the time limit; nothing was saved"));
                }
            }

            return _decision.Task.Result;
        }

        public void Close()
        {
            lock (_gate)
            {
                _decision.TrySetResult(Denied("the settings page ended; nothing was saved"));
            }
        }

        public OneShotResponse Handle(string verb, string suffix, string body)
        {
            lock (_gate)
            {
                if (_origin is null || _bind is null || _page is null || _decision.Task.IsCompleted)
                {
                    return NotFound;
                }

                switch (verb, suffix)
                {
                    case ("GET", ""):
                        return _page;
                    case ("POST", "deny"):
                        return _decision.TrySetResult(Denied("cancelled on the page; nothing was saved")) ? Ok : NotFound;
                    case ("POST", "save"):
                        try
                        {
                            return Save(_origin, _bind, body);
                        }
                        catch (Exception)
                        {
                            _decision.TrySetResult(Denied("the settings page failed; nothing was saved"));

                            return Failed;
                        }

                    default:
                        return NotFound;
                }
            }
        }

        /// <summary>Called with the lock held. Every way out sets the outcome, so a proof is used once.</summary>
        private OneShotResponse Save(string origin, byte[] bind, string body)
        {
            Dictionary<string, string>? members = StringMembers(body);
            if (members is null || Fields.Any(field => !members.ContainsKey(field)))
            {
                _decision.TrySetResult(Denied("the page sent a request that is not valid; nothing was saved"));

                return Invalid;
            }

            // The admin passkey signed SHA-256(bind || SHA-256(manifest)), the manifest being the current one with these settings
            // and the next version: the proof covers exactly these values, on this page, from this state.
            string text = members["settings"];
            string signed = manifest.WithSettings(current).SettingsPrefix() + text + "}";
            string assertion = JsonSerializer.Serialize(new Dictionary<string, string>
            {
                ["id"] = members["id"],
                ["authenticatorData"] = members["authenticatorData"],
                ["clientDataJSON"] = members["clientDataJSON"],
                ["signature"] = members["signature"],
            });
            ProofResult result;
            try
            {
                result = method.Verify(new ProofContext(Manifest.Challenge(bind, signed), origin), assertion);
            }
            catch (Exception)
            {
                result = new ProofResult(false, "the proof could not be checked");
            }

            if (!result.Ok)
            {
                _decision.TrySetResult(Denied("the proof was not accepted: " + result.Detail + "; nothing was saved"));

                return Refused;
            }

            ToolSettings? next = ToolSettings.FromCanonical(text, out string? problem);
            if (next is null)
            {
                _decision.TrySetResult(Denied("the settings are not valid (" + problem + "); nothing was saved"));

                return Invalid;
            }

            IReadOnlyList<SettingChange> changes = current.Changes(next);
            if (changes.Count == 0)
            {
                _decision.TrySetResult(new ConfigChange(0, "No setting changed; nothing was saved."));

                return new OneShotResponse(200, "application/json", "{\"ok\":true,\"changed\":[]}");
            }

            string? conflict;
            try
            {
                SignedManifest stored = new(manifest.WithSettings(next).Canonical(), bind, assertion);
                conflict = stored.Text != signed ? "the settings are not in canonical form; nothing was saved" : db.Write((connection, transaction) =>
                {
                    if (db.TryReplace(connection, transaction, manifest.Version, stored) is not null)
                    {
                        return "the settings changed while the page was open; nothing was saved";
                    }

                    AuditLog.Append(connection, transaction, AuditLog.SettingsRow("settings-changed", changes, AuditLog.KeyName(result.Detail)));

                    return null;
                });
            }
            catch (StateDatabaseException failure)
            {
                _decision.TrySetResult(new ConfigChange(RunCommand.StoreError, "the settings could not be saved (" + failure.Message + "); nothing was saved"));

                return Failed;
            }

            if (conflict is not null)
            {
                _decision.TrySetResult(Denied(conflict));

                return Conflict;
            }

            string summary = string.Join("; ", changes.Select(change => $"{change.Name} {change.Old} -> {change.New}"));
            _decision.TrySetResult(new ConfigChange(0, "Saved the settings: " + summary + "."));

            return new OneShotResponse(200, "application/json", JsonSerializer.Serialize(new { ok = true, changed = changes.Select(change => change.Name) }));
        }
    }
}

/// <summary>The settings page: a form with every setting, its current value and its limits. All text is HTML-encoded.</summary>
internal static class ConfigPageHtml
{
    /// <summary>
    /// The one inline script. It keeps the change summary up to date, and on Save builds the canonical JSON of the form (the
    /// same text as <see cref="ToolSettings.Canonical" />). Flow "assert": the admin passkey signs the new manifest, the given
    /// prefix, those settings and "}". Flow "register" (the first run): a new passkey is created over the settings, then the
    /// server sends the first manifest and the new passkey signs it (a second prompt); then the page shows the code to type
    /// in the terminal. There is no keyboard shortcut.
    /// </summary>
    private const string Script = """
        (function () {
            "use strict";
            var start = JSON.parse(document.getElementById("start").textContent);
            var save = document.getElementById("save");
            var cancel = document.getElementById("deny");
            var status = document.getElementById("status");
            var changes = document.getElementById("changes");
            var code = document.getElementById("code");
            var fields = Array.prototype.slice.call(document.querySelectorAll("[data-setting]"));
            var order = ["reuseMinutes", "reuseMaxMinutes", "method", "baseUrl", "port", "timeoutMinutes"];
            var register = start.flow === "register";
            var base = location.pathname.replace(/\/+$/, "");
            var encoder = new TextEncoder();
            var busy = false;
            var finished = false;

            function show(text) {
                status.textContent = text;
            }

            function finish(text) {
                finished = true;
                save.disabled = true;
                cancel.disabled = true;
                fields.forEach(function (field) {
                    field.disabled = true;
                });
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

            function field(name) {
                for (var i = 0; i < fields.length; i++) {
                    if (fields[i].getAttribute("data-setting") === name) {
                        return fields[i];
                    }
                }
                return null;
            }

            function read() {
                var values = {};
                order.forEach(function (name) {
                    var input = field(name);
                    var text = input.value.trim();
                    var kind = input.getAttribute("data-kind");
                    if (kind === "number") {
                        var min = Number(input.getAttribute("data-min"));
                        var max = Number(input.getAttribute("data-max"));
                        if (!/^[0-9]{1,5}$/.test(text) || Number(text) < min || Number(text) > max) {
                            throw new Error(name + " must be a whole number from " + min + " to " + max + ".");
                        }
                        values[name] = Number(text);
                    } else if (kind === "url") {
                        values[name] = text.length === 0 ? null : text;
                    } else {
                        values[name] = text;
                    }
                });
                if (values.reuseMinutes > values.reuseMaxMinutes) {
                    throw new Error("reuseMinutes must not be more than reuseMaxMinutes.");
                }
                return values;
            }

            function canonical(values) {
                var text = JSON.stringify({
                    reuseMinutes: values.reuseMinutes,
                    reuseMaxMinutes: values.reuseMaxMinutes,
                    method: values.method,
                    baseUrl: values.baseUrl,
                    port: values.port,
                    timeoutMinutes: values.timeoutMinutes
                });
                return text.replace(/[\u007f-\uffff]/g, function (c) {
                    return "\\u" + ("0000" + c.charCodeAt(0).toString(16)).slice(-4);
                });
            }

            function describe(value) {
                return value === null ? "none" : String(value);
            }

            function summary() {
                var values;
                try {
                    values = read();
                } catch (error) {
                    changes.textContent = error.message;
                    return null;
                }
                var lines = [];
                order.forEach(function (name) {
                    if (values[name] !== start.current[name]) {
                        lines.push(name + ": " + describe(start.current[name]) + " -> " + describe(values[name]));
                    }
                });
                changes.textContent = lines.length > 0 ? lines.join("\n")
                    : register ? "No changes. These values will be saved with the passkey." : "No changes.";
                return values;
            }

            function creation(challenge) {
                var options = start.options;
                return {
                    challenge: challenge,
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

            function assertion(challenge) {
                var payload = JSON.parse(start.payload);
                return {
                    challenge: challenge,
                    rpId: payload.rpId,
                    allowCredentials: payload.allowCredentials.map(function (item) {
                        return { id: fromBase64Url(item.id), type: item.type };
                    }),
                    timeout: payload.timeout,
                    userVerification: "required"
                };
            }

            // The first run's second prompt: the new passkey signs the first manifest; the reply then has the code.
            function confirm(step) {
                show("Confirm with your new passkey...");
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
                }).then(function (reply) {
                    if (!reply.ok) {
                        throw new Error("refused");
                    }
                    return reply.json();
                }).then(function (data) {
                    busy = false;
                    if (typeof data.code !== "string") {
                        throw new Error("no code");
                    }
                    finish("Type this code in the terminal to finish. Nothing is saved until you do." + (typeof data.admin === "string" ? " " + data.admin + ". Note this fingerprint down: every page shows it, and if it ever changes, the state was replaced." : ""));
                    code.textContent = data.code;
                });
            }

            cancel.addEventListener("click", function () {
                if (finished) {
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
                if (finished || busy) {
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
                var values = summary();
                if (values === null) {
                    show("Fix the values first. Nothing was saved.");
                    return;
                }
                var text = canonical(values);
                var seed;
                var request;
                try {
                    seed = fromBase64Url(register ? start.options.challenge : start.bind);
                    request = register ? creation(seed) : assertion(seed);
                } catch (error) {
                    show("The page data is not valid. Nothing was saved.");
                    return;
                }
                busy = true;
                save.disabled = true;
                // The first run hashes the settings into the registration; a save signs the whole new manifest.
                window.crypto.subtle.digest("SHA-256", encoder.encode(register ? text : start.prefix + text + "}")).then(function (hash) {
                    return window.crypto.subtle.digest("SHA-256", join(seed, new Uint8Array(hash)));
                }).then(function (challenge) {
                    request.challenge = new Uint8Array(challenge);
                    show("Waiting for your passkey...");
                    return register ? navigator.credentials.create({ publicKey: request }) : navigator.credentials.get({ publicKey: request });
                }).then(function (credential) {
                    var response = credential.response;
                    var body = {
                        settings: text,
                        id: toBase64Url(credential.rawId),
                        clientDataJSON: toBase64Url(response.clientDataJSON)
                    };
                    if (register) {
                        body.attestationObject = toBase64Url(response.attestationObject);
                    } else {
                        body.authenticatorData = toBase64Url(response.authenticatorData);
                        body.signature = toBase64Url(response.signature);
                    }
                    return JSON.stringify(body);
                }).then(function (body) {
                    if (finished) {
                        busy = false;
                        return;
                    }
                    show(register ? "Checking your passkey..." : "Saving...");
                    return post(register ? "create" : "save", body).then(function (reply) {
                        if (!reply.ok) {
                            busy = false;
                            finish((reply.status === 403 ? "Your passkey was not accepted. Nothing was saved." : "Nothing was saved. The terminal says why.")
                                + (register ? " If the terminal asks for a code, press Ctrl+C." : ""));
                            return;
                        }
                        return reply.json().then(function (data) {
                            if (register && data.sign && typeof data.sign.manifest === "string") {
                                return confirm(data.sign);
                            }
                            busy = false;
                            if (register) {
                                if (typeof data.code !== "string") {
                                    throw new Error("no code");
                                }
                                finish("Type this code in the terminal to finish. Nothing is saved until you do." + (typeof data.admin === "string" ? " " + data.admin + ". Note this fingerprint down: every page shows it, and if it ever changes, the state was replaced." : ""));
                                code.textContent = data.code;
                            } else {
                                if (!data.ok) {
                                    throw new Error("not saved");
                                }
                                finish("Saved. You can close this page.");
                            }
                        });
                    }).then(null, function () {
                        busy = false;
                        finish("Nothing was saved, or the answer could not be read. The terminal says what was saved.");
                        if (register) {
                            post("deny", "").then(null, function () { });
                        }
                    });
                }, function () {
                    busy = false;
                    if (!finished) {
                        save.disabled = false;
                        show("No passkey was used. Nothing was saved. You can try again or cancel.");
                    }
                });
            });

            fields.forEach(function (input) {
                input.addEventListener("input", summary);
                input.addEventListener("change", summary);
            });
            summary();
            cancel.focus();
        })();
        """;

    private const string FormStyle = """
        .field { margin: 1rem 0; }
        .field label { display: block; font-weight: bold; margin-bottom: 0.3rem; }
        .field input, .field select { font-size: 1rem; padding: 0.5rem; width: 100%; max-width: 30rem; box-sizing: border-box; }
        .hint { margin: 0.3rem 0 0; color: #333; }
        """;

    private static readonly IReadOnlyDictionary<string, string> Meaning = new Dictionary<string, string>
    {
        ["reuseMinutes"] = "The time the \"Approve for\" list on the approval page starts on.",
        ["reuseMaxMinutes"] = "The longest time one approval may cover the same run again (the ceiling).",
        ["method"] = "How approval is proved.",
        ["baseUrl"] = "The address of the page, such as https://secrets.example.net.",
        ["port"] = "The port the page listens on.",
        ["timeoutMinutes"] = "How long the program waits for an answer on a page.",
    };

    /// <summary>
    /// Builds the page. Script and style line endings become LF before hashing and output, so the CSP hashes match what is
    /// served. <paramref name="start" /> is the JSON for the data block, made with the default encoder (which escapes &lt;,
    /// &gt; and &amp;, so it cannot end the block).
    /// </summary>
    public static OneShotResponse Build(bool firstRun, ToolSettings current, string start, string adminLine)
    {
        string script = Script.ReplaceLineEndings("\n");
        string style = (ApprovalPage.Style + PasskeyRegistration.CodeStyle + FormStyle).ReplaceLineEndings("\n");
        string policy = ApprovalPage.Policy(script, style);

        StringBuilder page = new();
        page.Append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
        page.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
        page.Append("<meta name=\"referrer\" content=\"no-referrer\">\n");
        page.Append("<title>with-secrets settings</title>\n");
        page.Append("<style>").Append(style).Append("</style>\n</head>\n<body>\n<main>\n");
        page.Append("<h1>").Append(firstRun ? "Set up with-secrets" : "Change the with-secrets settings").Append("</h1>\n");
        page.Append(firstRun
            ? "<p>Nothing is enrolled yet. Choose the settings, then create the first passkey. It will work on this page's host and it is the admin passkey: only it can change the settings or the passkeys later. Your browser asks for it twice: to create it, then to confirm the settings with it. Nothing is saved until you type the code this page then shows into your terminal.</p>\n"
            : "<p>Change any value, check the changes, then save. Your admin passkey approves exactly these values.</p>\n");
        page.Append("<pre id=\"admin\">").Append(Encode(adminLine + (firstRun ? " (the passkey you create here becomes the admin key)" : ""))).Append("</pre>\n");
        foreach (string name in ToolSettings.Names)
        {
            string id = "f-" + name;
            string value = name == "baseUrl" ? current.BaseUrl ?? "" : current.Text(name);
            page.Append("<div class=\"field\"><label for=\"").Append(id).Append("\">").Append(name).Append("</label>");
            switch (name)
            {
                case "method":
                    page.Append("<select id=\"").Append(id).Append("\" data-setting=\"method\" data-kind=\"choice\">");
                    page.Append("<option value=\"").Append(ApprovalSettings.DefaultMethod).Append("\" selected>").Append(ApprovalSettings.DefaultMethod).Append("</option></select>");
                    break;
                case "baseUrl":
                    page.Append("<input id=\"").Append(id).Append("\" data-setting=\"baseUrl\" data-kind=\"url\" type=\"text\" inputmode=\"url\" autocomplete=\"off\" autocapitalize=\"off\" spellcheck=\"false\" maxlength=\"")
                        .Append(ToolSettings.MaxBaseUrlLength.ToString(CultureInfo.InvariantCulture)).Append("\" value=\"").Append(Encode(value)).Append("\">");
                    break;
                default:
                    (int min, int max) = name switch
                    {
                        "reuseMinutes" => (0, ReuseSettings.MaxMinutes),
                        "reuseMaxMinutes" => (ReuseSettings.MinMaxMinutes, ReuseSettings.MaxMinutes),
                        "port" => (0, ToolSettings.MaxPort),
                        _ => (ToolSettings.MinTimeoutMinutes, ApprovalSettings.MaxTimeoutMinutes),
                    };
                    string low = min.ToString(CultureInfo.InvariantCulture);
                    string high = max.ToString(CultureInfo.InvariantCulture);
                    page.Append("<input id=\"").Append(id).Append("\" data-setting=\"").Append(name).Append("\" data-kind=\"number\" type=\"number\" inputmode=\"numeric\" step=\"1\" min=\"")
                        .Append(low).Append("\" max=\"").Append(high).Append("\" data-min=\"").Append(low).Append("\" data-max=\"").Append(high)
                        .Append("\" value=\"").Append(Encode(value)).Append("\">");
                    break;
            }

            page.Append("<p class=\"hint\">").Append(Encode(Meaning[name] + " " + ToolSettings.Limits(name) + " Current: " + current.Text(name) + ".")).Append("</p></div>\n");
        }

        page.Append("<h2>Changes</h2>\n<pre id=\"changes\">No changes.</pre>\n");
        page.Append("<div class=\"buttons\">");
        page.Append("<button id=\"deny\" type=\"button\" autofocus>Cancel</button>");
        page.Append("<button id=\"save\" type=\"button\">").Append(firstRun ? "Save and create passkey" : "Save").Append("</button>");
        page.Append("</div>\n<p id=\"status\" role=\"status\"></p>\n<p id=\"code\"></p>\n</main>\n");
        page.Append("<script type=\"application/json\" id=\"start\">").Append(start).Append("</script>\n");
        page.Append("<script>").Append(script).Append("</script>\n</body>\n</html>\n");

        return new OneShotResponse(200, "text/html; charset=utf-8", page.ToString(), policy);
    }

    private static string Encode(string text) => WebUtility.HtmlEncode(ApprovalSummary.Clean(text));
}

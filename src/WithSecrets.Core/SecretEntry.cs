using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WithSecrets;

/// <summary>How a change to the secret store ended: 0 when it was made, else a <see cref="RunCommand" /> exit code and why.</summary>
public sealed record SecretChange(int Code, string Detail)
{
    public bool Done => Code == 0;
}

/// <summary>
/// Stores and removes secrets through a web page, never through the terminal. The terminal gets only the link and the names.
/// The page is served at the first of the two targets where the admin passkey works, and only when something is enrolled;
/// only the admin passkey can approve.
/// <see cref="Set" />: the person types the values on the page; the page encrypts them (see <see cref="SecretCrypto" />) and
/// signs the ciphertext with a passkey. The server checks the proof, then decrypts, then checks every name and value, then
/// writes the audit line, then stores. <see cref="Remove" />: the person approves on the approval page; then the secrets are
/// deleted. Any doubt or error changes nothing.
/// </summary>
public sealed class SecretEntry(EnrollmentTarget primaryTarget, EnrollmentTarget localTarget, ISecretStore store, AuditLog audit, Action<string> announce)
{
    // Only the admin key may change the secret store.
    private readonly EnrollmentTarget primary = primaryTarget.Admin();
    private readonly EnrollmentTarget local = localTarget.Admin();

    public const int MaxNames = 20;
    public const int MaxValueLength = 4096;
    public const string AnnouncePrefix = "To store the secrets, open this link: ";

    private const string RemoveHeading = "Check this change to your secrets.";

    private static readonly OneShotResponse NotFound = new(404, "text/plain; charset=utf-8", "Not found.");

    /// <summary>
    /// Opens the set page for these names and waits for the person, the time limit or an error. A refusal or failure is
    /// recorded in the audit log (event change-denied, names only).
    /// </summary>
    public SecretChange Set(IReadOnlyList<string> names) => Logged("--set", names, SetCore(names));

    /// <summary>Asks on the approval page, then deletes. Every name must be in the store. A refusal is recorded like Set's.</summary>
    public SecretChange Remove(IReadOnlyList<string> names) => Logged("--remove", names, RemoveCore(names));

    private SecretChange Logged(string commandName, IReadOnlyList<string> names, SecretChange change)
    {
        if (!change.Done)
        {
            // Only valid names go into the log: the others came from the command line as typed.
            audit.TryWriteDenied(commandName, [.. names.Where(SecretNames.IsValid)], change.Detail);
        }

        return change;
    }

    private SecretChange SetCore(IReadOnlyList<string> names)
    {
        SecretChange? refused = CheckNames(names);
        if (refused is not null)
        {
            return refused;
        }

        try
        {
            EnrollmentTarget? target = Target(out SecretChange? problem);
            if (target is null)
            {
                return problem!;
            }

            HashSet<string> stored;
            try
            {
                stored = [.. store.ListNames()];
            }
            catch (Exception)
            {
                return new SecretChange(RunCommand.StoreError, "cannot read the secret store");
            }

            return Serve(target, [.. names], stored);
        }
        catch (ProofUnavailableException failure)
        {
            return Denied(failure.Message);
        }
        catch (Exception)
        {
            return Denied("the set page failed; nothing was stored");
        }
    }

    private SecretChange RemoveCore(IReadOnlyList<string> names)
    {
        SecretChange? refused = CheckNames(names);
        if (refused is not null)
        {
            return refused;
        }

        try
        {
            EnrollmentTarget? target = Target(out SecretChange? problem);
            if (target is null)
            {
                return problem!;
            }

            HashSet<string> stored;
            try
            {
                stored = [.. store.ListNames()];
            }
            catch (Exception)
            {
                return new SecretChange(RunCommand.StoreError, "cannot read the secret store");
            }

            List<string> unknown = [.. names.Where(name => !stored.Contains(name))];
            if (unknown.Count > 0)
            {
                return Denied("Unknown secret: " + string.Join(", ", unknown));
            }

            string list = string.Join(", ", names);
            ApprovalDecision asked = target.Approver.Ask(new ApprovalPrompt(RemoveHeading, $"Remove these secrets: {list}. They will be deleted."));
            if (!asked.Approved)
            {
                return Denied(asked.Detail);
            }

            if (!audit.TryWriteChange("secrets-removed", [.. names], asked.Detail))
            {
                return new SecretChange(RunCommand.AuditError, "the audit log could not be written; nothing was removed");
            }

            List<string> removed = [];
            foreach (string name in names)
            {
                bool gone;
                try
                {
                    gone = store.Remove(name);
                }
                catch (Exception)
                {
                    gone = false;
                }

                if (!gone)
                {
                    return new SecretChange(RunCommand.StoreError, removed.Count == 0
                        ? $"could not remove {name}; nothing was removed"
                        : $"could not remove {name}; removed only {string.Join(", ", removed)}");
                }

                removed.Add(name);
            }

            return new SecretChange(0, $"Removed {list}.");
        }
        catch (ProofUnavailableException failure)
        {
            return Denied(failure.Message);
        }
        catch (Exception)
        {
            return Denied("the removal failed; nothing was removed");
        }
    }

    private static SecretChange Denied(string detail)
    {
        return new SecretChange(RunCommand.Denied, detail);
    }

    /// <summary>Null when the names may be used: 1 to <see cref="MaxNames" /> different names, each valid.</summary>
    private static SecretChange? CheckNames(IReadOnlyList<string> names)
    {
        if (names.Count == 0)
        {
            return Denied("no secret names were given");
        }

        if (names.Count > MaxNames)
        {
            return Denied($"at most {MaxNames} secret names at a time");
        }

        if (names.Any(name => !SecretNames.IsValid(name)))
        {
            return Denied("Use UPPER_SNAKE_CASE for the names (letters, digits, underscores). Names that start with DOTENV_ are reserved.");
        }

        if (names.Distinct(StringComparer.Ordinal).Count() != names.Count)
        {
            return Denied("a secret name is given twice");
        }

        return null;
    }

    /// <summary>
    /// The first of primary and local where an enrolled entry works. Null and why not when nothing is enrolled, when the
    /// store of enrolled entries cannot be read (that throws <see cref="ProofUnavailableException" />), or when nothing works.
    /// </summary>
    private EnrollmentTarget? Target(out SecretChange? problem)
    {
        IProofMethod method = primary.Method;
        if (method.Enrolled().Count == 0)
        {
            problem = Denied($"No {method.Id} is enrolled. Set up the first one with: with-secrets --config (with-secrets --enroll adds more).");

            return null;
        }

        EnrollmentTarget? target = EnrollmentTarget.FirstThatCanProve(primary, local);
        problem = target is null ? Denied(Enrollment.NoTargetMessage(method.Id, primary.Host, local.Host)) : null;

        return target;
    }

    /// <summary>Serves the set page at the target until the first outcome or the time limit. The server key lives only here.</summary>
    private SecretChange Serve(EnrollmentTarget target, List<string> names, HashSet<string> stored)
    {
        IProofMethod method = target.Method;
        ApprovalSettings settings = target.Approver.Settings;

        // A page that takes values must be https or localhost; this throws before anything listens. The host does not
        // depend on the port. The passkey method checks this again in Start.
        PasskeyMethod.RpIdOf(settings.PageOrigin(settings.Port));

        (byte[] serverKey, string publicKey) = SecretCrypto.NewServerKey();
        Session session = new(method, store, audit, names, serverKey);
        try
        {
            using OneShotServer server = new("s", settings.Port, session.Handle);
            string origin = settings.PageOrigin(server.Port);
            List<(string Name, bool Replace)> fields = [.. names.Select(name => (name, stored.Contains(name)))];
            string text = "Store these secrets: " + string.Join(", ", fields.Select(field => field.Name + (field.Replace ? " (replace)" : " (new)"))) + ".";
            if (method.AdminLine() is { } adminLine)
            {
                text += "\n" + adminLine;
            }
            string nonce = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16));
            byte[] bind = RequestBinding.Compute(nonce, text);
            ProofStart start = method.Start(new ProofContext(bind, origin));

            session.Open(origin, bind, SetPage.Build(text, fields, start, nonce, bind, publicKey));
            announce(AnnouncePrefix + origin + "/s/" + server.Token);

            return session.Wait(settings.Timeout);
        }
        finally
        {
            session.Close();
        }
    }

    /// <summary>
    /// The state of one set page. Requests are handled one at a time under one lock; the first outcome is final, and after
    /// it every request is 404. The store is written inside the lock, so the time limit cannot cut a write in half.
    /// </summary>
    private sealed class Session(IProofMethod method, ISecretStore store, AuditLog audit, List<string> names, byte[] serverKey)
    {
        private static readonly OneShotResponse Ok = new(200, "application/json", "{\"ok\":true}");
        private static readonly OneShotResponse Refused = new(403, "application/json", "{\"ok\":false}");
        private static readonly OneShotResponse Invalid = new(400, "application/json", "{\"ok\":false}");
        private static readonly OneShotResponse Failed = new(500, "application/json", "{\"ok\":false}");

        private static readonly string[] Fields = ["epk", "iv", "ct", "id", "authenticatorData", "clientDataJSON", "signature"];

        private readonly Lock _gate = new();
        private readonly TaskCompletionSource<SecretChange> _decision = new(TaskCreationOptions.RunContinuationsAsynchronously);
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

        public SecretChange Wait(TimeSpan timeout)
        {
            if (!_decision.Task.Wait(timeout))
            {
                End(Denied("no answer before the time limit; nothing was stored"));
            }

            return _decision.Task.Result;
        }

        /// <summary>Ends the page if it has not ended and forgets the server key.</summary>
        public void Close()
        {
            lock (_gate)
            {
                _decision.TrySetResult(Denied("the set page ended; nothing was stored"));
                CryptographicOperations.ZeroMemory(serverKey);
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
                        return _decision.TrySetResult(Denied("cancelled on the page; nothing was stored")) ? Ok : NotFound;
                    case ("POST", "save"):
                        try
                        {
                            return Save(_origin, _bind, body);
                        }
                        catch (Exception)
                        {
                            _decision.TrySetResult(Denied("the set page failed; nothing was stored"));

                            return Failed;
                        }

                    default:
                        return NotFound;
                }
            }
        }

        private void End(SecretChange change)
        {
            lock (_gate)
            {
                _decision.TrySetResult(change);
            }
        }

        /// <summary>Called with the lock held. Every way out sets the outcome, so a proof is used once.</summary>
        private OneShotResponse Save(string origin, byte[] bind, string body)
        {
            Dictionary<string, string>? members = StringMembers(body);
            if (members is null || Fields.Any(field => !members.ContainsKey(field)))
            {
                _decision.TrySetResult(Denied("the page sent a request that is not valid; nothing was stored"));

                return Invalid;
            }

            byte[] ct;
            try
            {
                ct = Base64Url.DecodeFromChars(members["ct"]);
            }
            catch (FormatException)
            {
                _decision.TrySetResult(Denied("the page sent a request that is not valid; nothing was stored"));

                return Invalid;
            }

            // The passkey signed SHA-256(bind + SHA-256(ct)): the proof covers exactly this ciphertext on this page.
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
                result = method.Verify(new ProofContext(SecretCrypto.Challenge(bind, ct), origin), assertion);
            }
            catch (Exception)
            {
                result = new ProofResult(false, "the proof could not be checked");
            }

            if (!result.Ok)
            {
                _decision.TrySetResult(Denied("the proof was not accepted: " + result.Detail + "; nothing was stored"));

                return Refused;
            }

            string plaintext;
            try
            {
                plaintext = SecretCrypto.Decrypt(serverKey, bind, members["epk"], members["iv"], members["ct"]);
            }
            catch (CryptographicException)
            {
                _decision.TrySetResult(Denied("the secrets could not be decrypted; nothing was stored"));

                return Invalid;
            }

            // Every entry is checked before the first write: all or nothing.
            Dictionary<string, string>? values = StringMembers(plaintext);
            string? problem = Problem(values);
            if (values is null || problem is not null)
            {
                _decision.TrySetResult(Denied((problem ?? "the secrets are not valid") + "; nothing was stored"));

                return Invalid;
            }

            if (!audit.TryWriteChange("secrets-set", names, result.Detail))
            {
                _decision.TrySetResult(new SecretChange(RunCommand.AuditError, "the audit log could not be written; nothing was stored"));

                return Failed;
            }

            List<string> done = [];
            foreach (string name in names)
            {
                try
                {
                    store.Set(name, values[name]);
                }
                catch (Exception)
                {
                    _decision.TrySetResult(new SecretChange(RunCommand.StoreError, done.Count == 0
                        ? $"the store could not save {name}; nothing was stored"
                        : $"the store could not save {name}; stored only {string.Join(", ", done)}"));

                    return Failed;
                }

                done.Add(name);
            }

            _decision.TrySetResult(new SecretChange(0, $"Stored {string.Join(", ", names)}."));

            return new OneShotResponse(200, "application/json", JsonSerializer.Serialize(new { ok = true, stored = names }));
        }

        /// <summary>Null when the values may be stored, else why not. Names only in the message, never a value.</summary>
        private string? Problem(Dictionary<string, string>? values)
        {
            if (values is null)
            {
                return "the secrets are not a JSON object of names and text values, each name once";
            }

            if (values.Count != names.Count || names.Any(name => !values.ContainsKey(name)))
            {
                return "the names sent are not the names asked for";
            }

            foreach (string name in names)
            {
                string value = values[name];
                if (!SecretNames.IsValid(name))
                {
                    return "a name is not valid";
                }

                if (value.Length < SecretNames.MinValueLength)
                {
                    return $"the value for {name} is shorter than {SecretNames.MinValueLength} characters";
                }

                if (value.Length > MaxValueLength)
                {
                    return $"the value for {name} is longer than {MaxValueLength} characters";
                }

                if (value.Any(char.IsControl))
                {
                    return $"the value for {name} has a control character";
                }
            }

            return null;
        }

        /// <summary>The members of a JSON object whose values are all strings. Null for anything else or a name that appears twice.</summary>
        private static Dictionary<string, string>? StringMembers(string json)
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
}

/// <summary>The set page: one password input per name, Save and Cancel. Names are HTML-encoded; no value is ever in it.</summary>
internal static class SetPage
{
    /// <summary>
    /// The one inline script. On Save it reads the inputs, encrypts them with Web Crypto to the server key, asks the passkey
    /// to sign SHA-256(bind + SHA-256(ct)), and posts the result. The values leave the page only inside the ciphertext.
    /// </summary>
    private const string Script = """
        (function () {
            "use strict";
            var start = JSON.parse(document.getElementById("start").textContent);
            var save = document.getElementById("save");
            var cancel = document.getElementById("deny");
            var status = document.getElementById("status");
            var inputs = Array.prototype.slice.call(document.querySelectorAll("input[data-name]"));
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
                inputs.forEach(function (input) {
                    input.value = "";
                    input.disabled = true;
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

            function hasControl(value) {
                for (var i = 0; i < value.length; i++) {
                    var code = value.charCodeAt(i);
                    if (code < 32 || (code >= 127 && code < 160)) {
                        return true;
                    }
                }
                return false;
            }

            function values() {
                var result = {};
                for (var i = 0; i < inputs.length; i++) {
                    var input = inputs[i];
                    var value = input.value;
                    if (value.length < Number(input.getAttribute("data-min"))) {
                        throw new Error("Each value needs at least " + input.getAttribute("data-min") + " characters.");
                    }
                    if (value.length > Number(input.getAttribute("data-max"))) {
                        throw new Error("Each value can have at most " + input.getAttribute("data-max") + " characters.");
                    }
                    if (hasControl(value)) {
                        throw new Error("A value has a control character, such as a tab.");
                    }
                    result[input.getAttribute("data-name")] = value;
                }
                return result;
            }

            function seal(plain, bind, serverKey) {
                var subtle = window.crypto.subtle;
                var curve = { name: "ECDH", namedCurve: "P-256" };
                var iv = window.crypto.getRandomValues(new Uint8Array(12));
                var mine;
                var ct;
                return subtle.generateKey(curve, false, ["deriveBits"]).then(function (pair) {
                    mine = pair;
                    return subtle.importKey("raw", serverKey, curve, false, []);
                }).then(function (server) {
                    return subtle.deriveBits({ name: "ECDH", public: server }, mine.privateKey, 256);
                }).then(function (shared) {
                    return subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
                }).then(function (material) {
                    return subtle.deriveKey(
                        { name: "HKDF", hash: "SHA-256", salt: bind, info: encoder.encode("with-secrets/v1 secrets") },
                        material, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
                }).then(function (key) {
                    return subtle.encrypt({ name: "AES-GCM", iv: iv, additionalData: bind, tagLength: 128 }, key, plain);
                }).then(function (sealed) {
                    ct = new Uint8Array(sealed);
                    return subtle.exportKey("raw", mine.publicKey);
                }).then(function (epk) {
                    return { epk: new Uint8Array(epk), iv: iv, ct: ct };
                });
            }

            cancel.addEventListener("click", function () {
                if (finished) {
                    return;
                }
                finish("Sending cancel...");
                post("deny", "").then(function (reply) {
                    show(reply.ok ? "Cancelled. Nothing was stored. You can close this page." : "This request had already ended.");
                }, function () {
                    show("Could not reach the program. With no answer it stores nothing at its time limit.");
                });
            });

            save.addEventListener("click", function () {
                if (finished || busy) {
                    return;
                }
                if (start.mode !== "webauthn") {
                    show("This page cannot run this kind of proof. Nothing was stored.");
                    return;
                }
                if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
                    show("This page needs an https address or localhost. Nothing was stored.");
                    return;
                }
                if (!window.PublicKeyCredential || !navigator.credentials) {
                    show("This browser does not support passkeys. Nothing was stored.");
                    return;
                }
                var plain;
                var payload;
                var bind;
                var serverKey;
                try {
                    plain = encoder.encode(JSON.stringify(values()));
                } catch (error) {
                    show(error.message + " Nothing was stored.");
                    return;
                }
                try {
                    payload = JSON.parse(start.payload);
                    bind = fromBase64Url(start.bind);
                    serverKey = fromBase64Url(start.serverKey);
                } catch (error) {
                    show("The page data is not valid. Nothing was stored.");
                    return;
                }
                busy = true;
                save.disabled = true;
                show("Encrypting...");
                var sent;
                seal(plain, bind, serverKey).then(function (sealed) {
                    sent = sealed;
                    return window.crypto.subtle.digest("SHA-256", sent.ct);
                }).then(function (ctHash) {
                    return window.crypto.subtle.digest("SHA-256", join(bind, new Uint8Array(ctHash)));
                }).then(function (challenge) {
                    show("Waiting for your passkey...");
                    return navigator.credentials.get({
                        publicKey: {
                            challenge: challenge,
                            rpId: payload.rpId,
                            allowCredentials: payload.allowCredentials.map(function (item) {
                                return { id: fromBase64Url(item.id), type: item.type };
                            }),
                            timeout: payload.timeout,
                            userVerification: "required"
                        }
                    });
                }).then(function (credential) {
                    var response = credential.response;
                    return JSON.stringify({
                        epk: toBase64Url(sent.epk),
                        iv: toBase64Url(sent.iv),
                        ct: toBase64Url(sent.ct),
                        id: toBase64Url(credential.rawId),
                        authenticatorData: toBase64Url(response.authenticatorData),
                        clientDataJSON: toBase64Url(response.clientDataJSON),
                        signature: toBase64Url(response.signature)
                    });
                }).then(function (body) {
                    if (finished) {
                        busy = false;
                        return;
                    }
                    show("Saving...");
                    return post("save", body).then(function (reply) {
                        if (!reply.ok) {
                            busy = false;
                            finish(reply.status === 403
                                ? "Your passkey was not accepted. Nothing was stored."
                                : "Nothing was stored. The terminal says why.");
                            return;
                        }
                        return reply.json().then(function (data) {
                            busy = false;
                            if (!data.ok || !Array.isArray(data.stored)) {
                                throw new Error("no names");
                            }
                            finish("Stored " + data.stored.join(", ") + ". You can close this page.");
                        });
                    }).then(null, function () {
                        busy = false;
                        finish("Could not read the answer. The terminal says what was stored.");
                    });
                }, function () {
                    busy = false;
                    if (!finished) {
                        save.disabled = false;
                        show("No passkey was used. Nothing was stored. You can try again or cancel.");
                    }
                });
            });
            if (inputs.length > 0) {
                inputs[0].focus();
            }
        })();
        """;

    private const string FieldStyle = """
        .field { margin: 1rem 0; }
        .field label { display: block; font-weight: bold; margin-bottom: 0.3rem; }
        .field input { font-size: 1rem; padding: 0.5rem; width: 100%; max-width: 30rem; box-sizing: border-box; }
        """;

    /// <summary>
    /// Builds the page. Script and style line endings become LF before hashing and output, so the CSP hashes match what is
    /// served. The start JSON is the normal mode, payload, bind and nonce, plus the server's public key.
    /// </summary>
    public static OneShotResponse Build(string text, IReadOnlyList<(string Name, bool Replace)> fields, ProofStart start, string nonce, byte[] bind, string serverKey)
    {
        string script = Script.ReplaceLineEndings("\n");
        string style = (ApprovalPage.Style + FieldStyle).ReplaceLineEndings("\n");
        string policy = ApprovalPage.Policy(script, style);

        // The default encoder escapes < > & ' and non-ASCII, so the JSON cannot end the data block.
        string json = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["mode"] = start.Mode,
            ["payload"] = start.Payload,
            ["bind"] = Base64Url.EncodeToString(bind),
            ["nonce"] = nonce,
            ["serverKey"] = serverKey,
        });

        StringBuilder page = new();
        page.Append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
        page.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
        page.Append("<meta name=\"referrer\" content=\"no-referrer\">\n");
        page.Append("<title>Store secrets</title>\n");
        page.Append("<style>").Append(style).Append("</style>\n</head>\n<body>\n<main>\n");
        page.Append("<h1>Store secrets for with-secrets</h1>\n");
        page.Append("<pre id=\"request\">").Append(WebUtility.HtmlEncode(string.Join('\n', text.Split('\n').Select(ApprovalSummary.Clean)))).Append("</pre>\n");
        page.Append("<p>Type each value. This page encrypts the values before it sends them, and your passkey approves.</p>\n");
        for (int index = 0; index < fields.Count; index++)
        {
            string name = WebUtility.HtmlEncode(ApprovalSummary.Clean(fields[index].Name));
            string id = "v" + index.ToString(System.Globalization.CultureInfo.InvariantCulture);
            page.Append("<div class=\"field\"><label for=\"").Append(id).Append("\">").Append(name)
                .Append(fields[index].Replace ? " (replace)" : " (new)").Append("</label>");
            page.Append("<input id=\"").Append(id).Append("\" type=\"password\" autocomplete=\"off\" autocapitalize=\"off\" spellcheck=\"false\" data-name=\"")
                .Append(name).Append("\" data-min=\"").Append(SecretNames.MinValueLength.ToString(System.Globalization.CultureInfo.InvariantCulture))
                .Append("\" data-max=\"").Append(SecretEntry.MaxValueLength.ToString(System.Globalization.CultureInfo.InvariantCulture)).Append("\"></div>\n");
        }

        page.Append("<div class=\"buttons\">");
        page.Append("<button id=\"deny\" type=\"button\">Cancel</button>");
        page.Append("<button id=\"save\" type=\"button\">Save</button>");
        page.Append("</div>\n<p id=\"status\" role=\"status\"></p>\n</main>\n");
        page.Append("<script type=\"application/json\" id=\"start\">").Append(json).Append("</script>\n");
        page.Append("<script>").Append(script).Append("</script>\n</body>\n</html>\n");

        return new OneShotResponse(200, "text/html; charset=utf-8", page.ToString(), policy);
    }
}

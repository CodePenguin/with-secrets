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
/// The page is served at the first of the two targets where an admin passkey works, and only when something is enrolled;
/// only an admin passkey can approve. Both write the rows and a new signed manifest (with the ciphertexts' hashes, see
/// <see cref="SecretStore" />) in one transaction, with the audit row.
/// <para>
/// <see cref="Set" />: the person types the values on the page; the page encrypts them to the page's server key (see
/// <see cref="SecretCrypto" />) and sends them to <c>/seal</c> as they are typed. The program decrypts them, checks every
/// name and value, encrypts each value to the store's public key and answers with the next manifest. The Save tap then asks
/// the passkey for one assertion over SHA-256(bind || SHA-256(ct) || SHA-256(manifest)) (see <see cref="SecretCrypto.ManifestBind" />),
/// which covers both the values sent and the hashes of the new rows, and posts it to <c>/save</c>. The program checks the
/// proof, then stores. One assertion is one passkey prompt per tap, which iOS needs.
/// </para>
/// <para>
/// <see cref="Remove" />: the person approves the next manifest (without the removed hashes) on the approval page; then the
/// rows are deleted with it. Any doubt or error changes nothing.
/// </para>
/// </summary>
public sealed class SecretEntry(EnrollmentTarget primaryTarget, EnrollmentTarget localTarget, SecretStore store, AdminAudit audit, Action<string> announce)
{
    // Only admin keys may change the secret store.
    private readonly EnrollmentTarget primary = primaryTarget.Admin();
    private readonly EnrollmentTarget local = localTarget.Admin();

    public const int MaxNames = 20;
    public const int MaxValueLength = 4096;
    public const string AnnouncePrefix = "To store the secrets, open this link: ";

    /// <summary>How many times one set page may send values to /seal before it ends.</summary>
    internal const int MaxSeals = 500;

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

            if (!TryCurrent(out Manifest? manifest, out HashSet<string> stored, out SecretChange? failed))
            {
                return failed!;
            }

            return Serve(target, [.. names], stored, manifest!);
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

            if (!TryCurrent(out Manifest? manifest, out HashSet<string> stored, out SecretChange? failed))
            {
                return failed!;
            }

            List<string> unknown = [.. names.Where(name => !stored.Contains(name))];
            if (unknown.Count > 0)
            {
                return Denied("Unknown secret: " + string.Join(", ", unknown));
            }

            // The admin signs the next state without these hashes; the rows go with it in one transaction.
            string list = string.Join(", ", names);
            Manifest next = SecretStore.Next(manifest!, manifest!.Store, new Dictionary<string, string>(), names);
            ManifestApproval asked = target.Approver.AskManifest(new ApprovalPrompt(RemoveHeading, $"Remove these secrets: {list}. They will be deleted."), next.Canonical());
            if (!asked.Decision.Approved || asked.Signed is null)
            {
                return Denied(asked.Decision.Detail);
            }

            string detail = asked.Decision.Detail;
            string? written = store.TryApply(manifest.Version, asked.Signed, new Dictionary<string, string>(), names, AdminEvent.Secrets("secrets-removed", [.. names], detail, AdminAudit.KeyName(detail)));

            return written is null ? new SecretChange(0, $"Removed {list}.") : new SecretChange(RunCommand.StoreError, written);
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

    /// <summary>
    /// The verified manifest and the stored names, after every row matched its signed hash. False with a store error (exit 4)
    /// when the store fails verification or cannot be read.
    /// </summary>
    private bool TryCurrent(out Manifest? manifest, out HashSet<string> stored, out SecretChange? failed)
    {
        stored = [];
        manifest = null;
        try
        {
            (manifest, IReadOnlyList<string> names) = store.Current();
            stored = [.. names];
        }
        catch (SecretStoreException failure)
        {
            failed = new SecretChange(RunCommand.StoreError, "cannot use the secret store: " + failure.Message);

            return false;
        }

        failed = manifest is null ? Denied(PasskeyRegistration.NothingEnrolled) : null;

        return failed is null;
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
            return Denied(CliArgs.SecretNameRule);
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

    /// <summary>
    /// Serves the set page at the target until the first outcome or the time limit. The page's server key lives only here.
    /// The store key pair was made by the first setup (--config), so this page needs only an admin assertion over the ciphertexts
    /// and the next manifest: no PRF, no second page.
    /// </summary>
    private SecretChange Serve(EnrollmentTarget target, List<string> names, HashSet<string> stored, Manifest manifest)
    {
        IProofMethod method = target.Method;
        ApprovalSettings settings = target.Approver.Settings;

        // A page that takes values must be https or localhost; this throws before anything listens. The host does not
        // depend on the port. The passkey method checks this again in Start.
        PasskeyMethod.RpIdOf(settings.PageOrigin(settings.Port));

        // First setup (--config) made the store key, so a state without one is not usable.
        string storeKey = manifest.Store;
        if (storeKey.Length == 0)
        {
            return Denied("the state has no secret store key; set up again with: with-secrets --config");
        }

        (byte[] serverKey, string publicKey) = SecretCrypto.NewServerKey();
        Session session = new(method, store, manifest, storeKey, names, serverKey);
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
    private sealed class Session(IProofMethod method, SecretStore store, Manifest manifest, string storeKey, List<string> names, byte[] serverKey)
    {
        private static readonly OneShotResponse Ok = new(200, "application/json", "{\"ok\":true}");
        private static readonly OneShotResponse Refused = new(403, "application/json", "{\"ok\":false}");
        private static readonly OneShotResponse Invalid = new(400, "application/json", "{\"ok\":false}");
        private static readonly OneShotResponse Failed = new(500, "application/json", "{\"ok\":false}");

        private static readonly string[] SealFields = ["epk", "iv", "ct"];
        private static readonly string[] Fields = ["epk", "iv", "ct", "id", "authenticatorData", "clientDataJSON", "signature"];

        /// <summary>How many sealed payloads are kept (the newest), each waiting for its Save.</summary>
        private const int Kept = 16;

        private readonly Lock _gate = new();
        private readonly TaskCompletionSource<SecretChange> _decision = new(TaskCreationOptions.RunContinuationsAsynchronously);

        // By base64url SHA-256 of the page's ct: the next manifest and the store rows made from it. No value is kept.
        private readonly Dictionary<string, (string Manifest, Dictionary<string, string> Rows)> _sealed = new(StringComparer.Ordinal);
        private readonly Queue<string> _order = new();
        private int _seals;
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

        /// <summary>Ends the page if it has not ended and forgets the server key and what was sealed.</summary>
        public void Close()
        {
            lock (_gate)
            {
                _decision.TrySetResult(Denied("the set page ended; nothing was stored"));
                CryptographicOperations.ZeroMemory(serverKey);
                _sealed.Clear();
            }
        }

        /// <summary>Every request gets an answer. A bug that throws ends the page with "internal error" and answers 500.</summary>
        public OneShotResponse Handle(string verb, string suffix, string body)
        {
            return HandleGuard.Run(verb, suffix, () => HandleRequest(verb, suffix, body),
                () => _decision.TrySetResult(Denied(HandleGuard.Reason + "; nothing was stored")), Failed, NotFound);
        }

        private OneShotResponse HandleRequest(string verb, string suffix, string body)
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
                    case ("POST", "seal"):
                        return Seal(_bind, body);
                    case ("POST", "save"):
                        return Save(_origin, _bind, body);
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

        /// <summary>
        /// Called with the lock held, while the person types: decrypts and checks the values, encrypts each to the store key
        /// and answers with the next manifest (names, the store key and hashes: nothing secret). A refusal says why (names only)
        /// and does not end the page: the person may still be typing.
        /// </summary>
        private OneShotResponse Seal(byte[] bind, string body)
        {
            if (++_seals > MaxSeals)
            {
                _decision.TrySetResult(Denied("the page sent values too many times; nothing was stored"));

                return Invalid;
            }

            Dictionary<string, string>? members = StringMembers(body);
            if (members is null || SealFields.Any(field => !members.ContainsKey(field)))
            {
                return Refusal("the page sent a request that is not valid");
            }

            (Dictionary<string, string>? values, string? problem) = Open(bind, members);
            if (values is null)
            {
                return Refusal(problem!);
            }

            // The same ct sealed again (a retried request) gets the first answer: encryption is randomized, so a new manifest
            // would not match a challenge the page may already have made from the first one.
            string key = Key(Base64Url.DecodeFromChars(members["ct"]));
            if (_sealed.TryGetValue(key, out (string Manifest, Dictionary<string, string> Rows) earlier))
            {
                return Sealed(earlier.Manifest);
            }

            Dictionary<string, string> rows = new(StringComparer.Ordinal);
            foreach (string name in names)
            {
                rows[name] = store.Encrypt(values[name], storeKey);
            }

            string text = SecretStore.Next(manifest, storeKey, rows, []).Canonical();
            _sealed[key] = (text, rows);
            _order.Enqueue(key);
            while (_order.Count > Kept)
            {
                _sealed.Remove(_order.Dequeue());
            }

            return Sealed(text);
        }

        private static OneShotResponse Sealed(string manifestText)
        {
            return new OneShotResponse(200, "application/json", JsonSerializer.Serialize(new { ok = true, manifest = manifestText }));
        }

        private static OneShotResponse Refusal(string why) => new(400, "application/json", JsonSerializer.Serialize(new { ok = false, error = why }));

        private static string Key(byte[] ct) => Base64Url.EncodeToString(SHA256.HashData(ct));

        /// <summary>The values the page sent, decrypted and checked; or null and why not (names only, never a value).</summary>
        private (Dictionary<string, string>? Values, string? Problem) Open(byte[] bind, Dictionary<string, string> members)
        {
            string plaintext;
            try
            {
                plaintext = SecretCrypto.Decrypt(serverKey, bind, members["epk"], members["iv"], members["ct"]);
            }
            catch (CryptographicException)
            {
                return (null, "the secrets could not be decrypted");
            }

            // Every entry is checked before anything is encrypted or stored: all or nothing.
            Dictionary<string, string>? values = StringMembers(plaintext);
            string? problem = Problem(values);

            return problem is null ? (values, null) : (null, problem);
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

            // Only values that went through /seal can be saved: the manifest the passkey signed is the one made from them. Values
            // that were never sealed are checked again, so the answer says why they could not be.
            if (!_sealed.TryGetValue(Key(ct), out (string Manifest, Dictionary<string, string> Rows) prepared))
            {
                (_, string? problem) = Open(bind, members);
                _decision.TrySetResult(Denied((problem ?? "the values were not prepared on the page") + "; nothing was stored"));

                return Invalid;
            }

            // The passkey signed SHA-256(bind || SHA-256(ct) || SHA-256(manifest)): exactly these values on this page, and the
            // new state with the hashes of exactly these rows.
            byte[] manifestBind = SecretCrypto.ManifestBind(bind, ct);
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
                result = method.Verify(new ProofContext(Manifest.Challenge(manifestBind, prepared.Manifest), origin), assertion);
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

            SignedManifest signed = new(prepared.Manifest, manifestBind, assertion);
            string? problemWriting = store.TryApply(manifest.Version, signed, prepared.Rows, [], AdminEvent.Secrets("secrets-set", names, result.Detail, AdminAudit.KeyName(result.Detail)));
            if (problemWriting is not null)
            {
                _decision.TrySetResult(new SecretChange(RunCommand.StoreError, problemWriting));

                return Failed;
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
    /// The one inline script. As the values are typed it encrypts them with Web Crypto to the server key, sends the ciphertext
    /// to /seal and makes the challenge SHA-256(bind || SHA-256(ct) || SHA-256(manifest)) from the manifest it gets back; Save
    /// then asks the passkey to sign it at once (nothing awaited in the tap, which iOS WebKit needs) and posts the result. The
    /// values leave the page only inside the ciphertext.
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
            var attempt = 0;
            var promptButton = null;
            var promptLabel = "";
            var finished = false;
            var ready = null;

            function show(text) {
                status.textContent = text + (diagLine ? " " + diagLine : "");
            }

            function finish(text) {
                finished = true;
                ready = null;
                save.disabled = true;
                cancel.disabled = true;
                inputs.forEach(function (input) {
                    input.value = "";
                    input.disabled = true;
                });
                show(text);
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

            // Encrypts the values as they are typed (not in the tap) and sends them to /seal. The program answers with the next
            // manifest: the hashes of the rows it will store. The challenge is SHA-256(bind || SHA-256(ct) || SHA-256(manifest)),
            // so the one passkey signature covers both. All of this happens before the tap, so the Save tap starts the passkey
            // prompt at once: iOS WebKit refuses a prompt that follows an awaited step. Only a result for the values still in the
            // form, from the newest request, is kept.
            var waiting = "Encrypting these values. Tap Save again.";
            var sealing = 0;
            var timer = null;

            function current() {
                try {
                    return JSON.stringify(values());
                } catch (error) {
                    return null;
                }
            }

            function prepare() {
                if (finished || busy || start.mode !== "webauthn" || !window.isSecureContext || !window.crypto || !window.crypto.subtle) {
                    return;
                }
                var text = current();
                var bind;
                var serverKey;
                if (text === null || (ready !== null && ready.text === text)) {
                    return;
                }
                try {
                    bind = fromBase64Url(start.bind);
                    serverKey = fromBase64Url(start.serverKey);
                } catch (error) {
                    return;
                }
                var mine = ++sealing;
                var sent;
                var subtle = window.crypto.subtle;
                seal(encoder.encode(text), bind, serverKey).then(function (sealed) {
                    sent = sealed;
                    if (mine !== sealing || finished) {
                        throw new Error("newer values");
                    }
                    return post("seal", JSON.stringify({ epk: toBase64Url(sent.epk), iv: toBase64Url(sent.iv), ct: toBase64Url(sent.ct) }));
                }).then(function (reply) {
                    return reply.json().then(function (data) {
                        if (!reply.ok || !data || data.ok !== true || typeof data.manifest !== "string") {
                            if (mine === sealing && !finished && data && typeof data.error === "string") {
                                show(data.error + ". Nothing was stored.");
                            }
                            throw new Error("not sealed");
                        }
                        return Promise.all([subtle.digest("SHA-256", sent.ct), subtle.digest("SHA-256", encoder.encode(data.manifest))]);
                    });
                }).then(function (hashes) {
                    return subtle.digest("SHA-256", join(join(bind, new Uint8Array(hashes[0])), new Uint8Array(hashes[1])));
                }).then(function (challenge) {
                    if (!finished && !busy && mine === sealing && current() === text) {
                        ready = { text: text, sent: sent, challenge: new Uint8Array(challenge) };
                        if (status.textContent === waiting) {
                            show("Ready. Tap Save.");
                        }
                    }
                }, function (error) {
                    if (error && error.name === "AbortError" && mine === sealing && !finished) {
                        show("The program did not answer within 20 seconds. Check the terminal. Tap again to retry.");
                    }
                });
            }

            // Typing waits a moment before sending, so that not every key press is a request.
            function later() {
                if (timer !== null) {
                    clearTimeout(timer);
                }
                timer = setTimeout(prepare, 300);
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

            // While the passkey prompt is open Save stays on and reads "Cancel": a prompt that closes without ever settling must
            // not leave the page stuck. The cancel starts no prompt; it only abandons the attempt.
            function endWait() {
                if (promptButton !== null) {
                    promptButton.textContent = promptLabel;
                    promptButton = null;
                }
            }

            function cancelAttempt() {
                attempt++;
                endWait();
                busy = false;
                save.disabled = false;
                show("Cancelled. Tap again to try.");
            }

            save.addEventListener("click", function () {
                if (finished) {
                    return;
                }
                if (promptButton !== null) {
                    cancelAttempt();
                    return;
                }
                if (busy) {
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
                var text;
                var payload;
                try {
                    text = JSON.stringify(values());
                } catch (error) {
                    show(error.message + " Nothing was stored.");
                    return;
                }
                try {
                    payload = JSON.parse(start.payload);
                    fromBase64Url(start.bind);
                    fromBase64Url(start.serverKey);
                } catch (error) {
                    show("The page data is not valid. Nothing was stored.");
                    return;
                }
                if (ready === null || ready.text !== text) {
                    // These values are not encrypted yet (they just changed): encrypt them, and ask for another tap.
                    prepare();
                    show(waiting);
                    return;
                }
                var sent = ready.sent;
                var request;
                try {
                    request = {
                        challenge: ready.challenge,
                        rpId: payload.rpId,
                        timeout: payload.timeout,
                        userVerification: "required"
                    };
                } catch (error) {
                    show("The proof data is not valid (" + (error && typeof error.name === "string" ? error.name : "Error") + "). Nothing was stored.");
                    return;
                }
                var attemptNumber = ++attempt;
                busy = true;
                promptButton = save;
                promptLabel = save.textContent;
                save.textContent = "Cancel";
                save.disabled = false;
                show("Waiting for your passkey...");
                // Runs in the tap: nothing is awaited before the passkey prompt.
                navigator.credentials.get({ publicKey: request }).then(function (credential) {
                    if (attemptNumber !== attempt) {
                        return null;
                    }
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
                    if (attemptNumber !== attempt) {
                        return;
                    }
                    if (finished) {
                        busy = false;
                        return;
                    }
                    endWait();
                    save.disabled = true;
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
                    }).then(null, function (error) {
                        busy = false;
                        if (error && error.name === "AbortError") {
                            if (!finished) {
                                save.disabled = false;
                                show("The program did not answer within 20 seconds. Check the terminal. Tap again to retry.");
                            }
                            return;
                        }
                        finish("Could not read the answer. The terminal says what was stored.");
                    });
                }, function (error) {
                    if (attemptNumber !== attempt) {
                        return;
                    }
                    busy = false;
                    endWait();
                    if (!finished) {
                        save.disabled = false;
                        show("No passkey was used" + why(error) + ". Nothing was stored. You can try again or cancel.");
                    }
                });
            });

            // The browser's own error, for the status line: its name and message (cut to 120 characters). Never any value text.
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
            inputs.forEach(function (input) {
                input.addEventListener("input", later);
                input.addEventListener("change", prepare);
            });
            prepare();
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

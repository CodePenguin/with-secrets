using System.Buffers.Text;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WithSecrets;

/// <summary>
/// What <c>--recover</c> carries from the old state into the new one while the person makes the new passkey: the old store key
/// (UTF-8 hex text, in memory only; zeroed by <see cref="Dispose" />), the old ciphertext rows (already verified against the old
/// signed hashes), the old settings (the form starts from them) and the name of the database snapshot.
/// </summary>
internal sealed class RecoveryCarry(byte[] oldPrivateKey, byte[] oldReviewKey, string reviewPublicKey, IReadOnlyDictionary<string, string> oldRows, ToolSettings settings, string oldFileName, string recoveredName) : IDisposable
{
    public ToolSettings Settings => settings;

    public string OldFileName => oldFileName;

    /// <summary>The snapshot of the old database, named <c>with-secrets.db.recovered-&lt;UTC yyyyMMddHHmmss&gt;</c>.</summary>
    public string RecoveredName => recoveredName;

    /// <summary>The administrative events written in the transaction that installs the recovered store.</summary>
    internal List<AdminEvent> Pending { get; } = [];

    public int Count => oldRows.Count;

    /// <summary>What the first page of the new passkey says about this setup, where it otherwise says "Admins: not set up yet".</summary>
    public string PageNote => "Recovery: this replaces the store in " + oldFileName + " and makes new keys. The old admin keys stay in the database copy (" + recoveredName + ").";

    /// <summary>
    /// Every old row decrypted with the old store key and encrypted again for <paramref name="newPublicKey" />, one row at a
    /// time (names in order). Only ciphertext is kept. The plain value is a .NET string for the call and cannot be wiped;
    /// there is no byte copy of it.
    /// </summary>
    public IReadOnlyDictionary<string, string> Reencrypt(string newPublicKey)
    {
        string privateKey = Encoding.UTF8.GetString(oldPrivateKey);
        SortedDictionary<string, string> rows = new(StringComparer.Ordinal);
        foreach ((string name, string ciphertext) in oldRows.OrderBy(item => item.Key, StringComparer.Ordinal))
        {
            string value = JweCipher.Instance.Decrypt(privateKey, ciphertext);
            rows[name] = JweCipher.Instance.Encrypt(value, newPublicKey);
        }

        return rows;
    }

    public ReviewKey WrapReview(byte[] masterKey) => new(reviewPublicKey, KeyVault.WrapReview(oldReviewKey, masterKey, reviewPublicKey));

    public void Dispose()
    {
        SecretValues.Clear(oldPrivateKey);
        SecretValues.Clear(oldReviewKey);
    }
}

/// <summary>
/// <c>--recover</c>: for when every passkey is lost. The old state is read and verified as every command does (public keys
/// only, no passkey). Page 1 asks for the recovery code (encrypted in the browser to the page's server key, like a
/// secret value); the server derives the recovery key, opens the master key from the recovery slot and the old store key
/// from the vault. The same call then continues as a first-run setup on a new, empty state next to the old file
/// (a new passkey, new master key, new store key, vault and recovery code), holding only the old store key and the old
/// ciphertext rows in between. The new store key's public key is made first; every old row is decrypted and encrypted again
/// for it one at a time, and the new first manifest lists their hashes. The old database is copied before a transaction
/// replaces the manifest, sign counts and ciphertext and appends the recovery events in the live file. The authority
/// and audit history are preserved.
/// </summary>
public sealed class StoreRecovery(StateDatabase db, EnrollmentTarget primaryTarget, EnrollmentTarget localTarget, Action<string> announce, Func<string?>? readCode)
{
    public const string AnnouncePrefix = "To recover with your recovery code, open this link: ";

    internal const string PathPrefix = "r";

    /// <summary>For tests: the time the renamed file is named after.</summary>
    internal Func<DateTimeOffset> Clock { get; set; } = () => DateTimeOffset.UtcNow;

    /// <summary>For tests: runs after the scratch database is ready and before the live database is updated.</summary>
    internal Action? BeforeSwap { get; set; }

    public ConfigChange Run()
    {
        // One link for the whole command: the code page and the page of the new passkey share one server (see PageFlow).
        using IDisposable flow = PageFlow.Enter();
        ConfigChange change;
        try
        {
            change = RunCore();
        }
        catch (ProofUnavailableException failure)
        {
            change = Denied(failure.Message);
        }
        catch (Exception)
        {
            change = Denied("the recovery failed: " + HandleGuard.Reason + "; the old state is unchanged");
        }

        if (!change.Done)
        {
            db.Audit.TryWriteDenied("--recover", [], change.Detail);
        }

        return change;
    }

    private static ConfigChange Denied(string detail) => new(RunCommand.Denied, detail);

    private ConfigChange RunCore()
    {
        if (!db.TryManifest(out Manifest? manifest, out string? error))
        {
            return new ConfigChange(RunCommand.StoreError, error!);
        }

        if (manifest is null)
        {
            return Denied("There is nothing to recover: no secret store is set up. Set up with: with-secrets admin");
        }

        if (manifest.Recovery is null || manifest.Store.Length == 0)
        {
            return Denied("This state has no recovery code, so it cannot be recovered. Delete " + db.FileLabel + " and set up again with: with-secrets admin");
        }

        Dictionary<string, string> rows;
        try
        {
            (_, rows) = new SecretStore(db).Snapshot();
        }
        catch (SecretStoreException failure)
        {
            return new ConfigChange(RunCommand.StoreError, "cannot use the secret store: " + failure.Message);
        }

        // Both pages are served where passkeys can work: the primary page when it can, else localhost.
        EnrollmentTarget target = Usable(primaryTarget) ? primaryTarget : localTarget;
        ApprovalSettings settings = target.Approver.Settings;
        PasskeyMethod.RpIdOf(settings.PageOrigin(settings.Port));
        if (readCode is null)
        {
            return Denied("this recovery has no way to ask for the code from the page; nothing was changed");
        }

        string stamp = Clock().UtcDateTime.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture);
        string recoveredName = Path.GetFileName(db.FilePath) + ".recovered-" + stamp;
        string recoveredPath = Path.Combine(Path.GetDirectoryName(db.FilePath)!, recoveredName);
        string newPath = db.FilePath + ".recovering-" + Guid.NewGuid().ToString("N");
        if (File.Exists(recoveredPath))
        {
            return Denied(recoveredName + " exists already; move it away and try again. Nothing was changed.");
        }

        // Page 1: the recovery code. Nothing is changed by it.
        OpenedKeys? opened = AskCode(settings, manifest, out string? refused);
        if (opened is null)
        {
            return Denied(refused ?? "the recovery code was not accepted; nothing was changed");
        }

        // The carry owns both old private keys from here.
        using RecoveryCarry carry = new(opened.Store, opened.Review, manifest.Review!.PublicKey, rows, manifest.Settings, Path.GetFileName(db.FilePath), recoveredName);

        // The new state is made in a file of its own, next to the old one, and only if the whole first setup works.
        StateDatabase fresh = new(newPath);
        ConfigChange made;
        bool copied = false;
        bool replaced = false;
        try
        {
            made = new FirstRunPage(fresh, primaryTarget, localTarget, announce, readCode) { Carry = carry }.Run();
            if (!made.Done)
            {
                return made;
            }

            BeforeSwap?.Invoke();

            StateDatabase.RecoveryRows freshRows = fresh.ExportRecoveryRows();
            db.Database.CopyTo(recoveredPath);
            copied = true;
            replaced = db.ReplaceRecoveredStore(manifest, rows, freshRows, carry.Pending);
            if (!replaced)
            {
                return Denied("the old store changed while you were recovering; run --recover again. Nothing was changed.");
            }
        }
        catch (Exception)
        {
            return Denied("the recovery failed after the new state was made: " + HandleGuard.Reason + "; the old state is unchanged");
        }
        finally
        {
            if (copied && !replaced)
            {
                DeleteFiles(recoveredPath);
            }
            DeleteFiles(newPath);
        }

        return new ConfigChange(0, made.Detail + "\nRecovered " + carry.Count.ToString(CultureInfo.InvariantCulture) + (carry.Count == 1 ? " secret" : " secrets")
            + " into the new store. A copy of the old database is in " + recoveredName + ". Its admin keys are gone from the new state. The new recovery code was shown once, on the last page.");
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

    /// <summary>The files of a database path: the database and its journal files.</summary>
    private static void DeleteFiles(string path)
    {
        foreach (string file in new[] { path, path + "-wal", path + "-shm" })
        {
            try
            {
                File.Delete(file);
            }
            catch (Exception failure) when (failure is IOException or UnauthorizedAccessException)
            {
                // A stray temporary file is harmless.
            }
        }
    }

    /// <summary>
    /// Serves page 1 and waits for the code. The old store and review key bytes (the caller zeroes them), or null and why not. The master
    /// key is zeroed here.
    /// </summary>
    private OpenedKeys? AskCode(ApprovalSettings settings, Manifest manifest, out string? why)
    {
        (byte[] serverKey, string publicKey) = SecretCrypto.NewServerKey();
        // The page after this one is the new store's first setup, served at the same place; this page's reply to the right code leads to it.
        PageFlow.Plan(FirstRunPage.PathPrefix, settings);
        CodeSession session = new(manifest, serverKey, PageFlow.Current is { } flow ? flow.TakeNext : null);
        try
        {
            using PageSlot server = PageFlow.Open(PathPrefix, settings.Port, session.Handle).Keep();
            PageFlow.OnEnd(session.Forget);
            string origin = settings.PageOrigin(server.Port);
            byte[] bind = RandomNumberGenerator.GetBytes(32);
            session.Open(bind, RecoveryPage.Build(AdminKey.Line(manifest), bind, publicKey, manifest.Secrets.Count));
            server.Ready();
            announce(AdminKey.Line(manifest) + "\nIf it is not the one you noted, stop.");
            announce(AnnouncePrefix + origin + "/" + PathPrefix + "/" + server.Token);

            return session.Wait(PageFlow.Left(settings.Timeout), out why);
        }
        finally
        {
            session.Close();
        }
    }

    private sealed record OpenedKeys(byte[] Store, byte[] Review);

    /// <summary>
    /// The state of page 1. Requests are handled one at a time under one lock. At most three codes are tried; a code that does
    /// not open the store, the time limit, Cancel and any error end it without a key.
    /// </summary>
    private sealed class CodeSession(Manifest manifest, byte[] serverKey, Func<string?>? takeNext)
    {
        private const int Tries = 3;

        private static readonly OneShotResponse NotFound = new(404, "text/plain; charset=utf-8", "Not found.");
        private static readonly OneShotResponse Ok = new(200, "application/json", "{\"ok\":true}");
        private static readonly OneShotResponse Failed = new(500, "application/json", "{\"ok\":false}");

        private readonly Lock _gate = new();
        private readonly TaskCompletionSource<OpenedKeys?> _result = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private string? _why;
        private byte[]? _bind;
        private OneShotResponse? _page;
        private int _wrong;
        private OneShotResponse? _reply;
        private byte[]? _replyFor;

        public void Open(byte[] bind, OneShotResponse page)
        {
            lock (_gate)
            {
                _bind = bind;
                _page = page;
            }
        }

        public OpenedKeys? Wait(TimeSpan timeout, out string? why)
        {
            if (!_result.Task.Wait(timeout))
            {
                Fail("no answer before the time limit; nothing was changed");
            }

            OpenedKeys? keys = _result.Task.Result;
            lock (_gate)
            {
                why = _why;
            }

            return keys;
        }

        public void Close()
        {
            lock (_gate)
            {
                _result.TrySetResult(null);
                SecretValues.Clear(serverKey);
            }
        }

        private void Fail(string why)
        {
            lock (_gate)
            {
                if (_result.TrySetResult(null))
                {
                    _why = why;
                }
            }
        }

        public OneShotResponse Handle(string verb, string suffix, string body)
        {
            return HandleGuard.Run(verb, suffix, () => HandleRequest(verb, suffix, body),
                () =>
                {
                    _why = HandleGuard.Reason + "; nothing was changed";

                    return _result.TrySetResult(null);
                }, Failed, NotFound);
        }

        private OneShotResponse HandleRequest(string verb, string suffix, string body)
        {
            lock (_gate)
            {
                if (_bind is null || _page is null)
                {
                    return NotFound;
                }

                if (_result.Task.IsCompleted)
                {
                    return Again(verb, suffix, body);
                }

                switch (verb, suffix)
                {
                    case ("GET", ""):
                        return _page;
                    case ("POST", "deny"):
                        if (_result.TrySetResult(null))
                        {
                            _why = "cancelled on the page; nothing was changed";

                            return Ok;
                        }

                        return NotFound;
                    case ("POST", "code"):
                        return Code(_bind, body);
                    default:
                        return NotFound;
                }
            }
        }

        /// <summary>Called with the lock held.</summary>
        private OneShotResponse Code(byte[] bind, string body)
        {
            Dictionary<string, string>? members = FirstRunPage.StringMembers(body);
            if (members is null || members.Count != 3 || new[] { "epk", "iv", "ct" }.Any(field => !members.ContainsKey(field)))
            {
                _why = "the page sent a request that is not valid; nothing was changed";
                _result.TrySetResult(null);

                return new OneShotResponse(400, "application/json", "{\"ok\":false}");
            }

            byte[]? typed = null;
            byte[]? master = null;
            byte[]? key = null;
            byte[]? reviewKey = null;
            try
            {
                string text = SecretCrypto.Decrypt(serverKey, bind, members["epk"], members["iv"], members["ct"]);
                Dictionary<string, string>? plain = FirstRunPage.StringMembers(text);
                if (plain is null || plain.Count != 1 || !plain.TryGetValue("code", out string? code) || !RecoveryCode.TryParse(code, out typed))
                {
                    return Wrong("That is not a recovery code. It is 32 letters and digits in groups of four.");
                }

                try
                {
                    master = KeyVault.OpenRecovery(manifest, typed);
                    key = KeyVault.UnwrapVault(manifest.Vault, master, manifest.Store);
                    ReviewKey review = manifest.Review!;
                    reviewKey = KeyVault.UnwrapReview(review.Vault, master, review.PublicKey);
                }
                catch (CryptographicException)
                {
                    return Wrong("That recovery code does not open this store.");
                }

                if (JweCipher.Instance.Derive(Encoding.UTF8.GetString(key)) != manifest.Store
                    || JweCipher.Instance.Derive(Encoding.UTF8.GetString(reviewKey)) != manifest.Review!.PublicKey)
                {
                    return Wrong("That recovery code does not open this store.");
                }

                // The next step's page is made now, after the code opened the store and before the command goes on.
                string? next = takeNext?.Invoke();
                if (_result.TrySetResult(new OpenedKeys(key, reviewKey)))
                {
                    key = null;
                    reviewKey = null;
                }
                OneShotResponse reply = next is null ? Ok : new OneShotResponse(200, "application/json", JsonSerializer.Serialize(new { ok = true, next }));

                // Kept for this one body: if the reply is lost, the same sealed code sent again gets it again (and opens nothing a second time).
                _reply = reply;
                _replyFor = SHA256.HashData(Encoding.UTF8.GetBytes(body));

                return reply;
            }
            catch (CryptographicException)
            {
                // The sealed payload could not be opened: not this page's, or damaged.
                return Wrong("The code could not be read. Try again.");
            }
            finally
            {
                SecretValues.Clear(typed);
                SecretValues.Clear(master);
                SecretValues.Clear(key);
                SecretValues.Clear(reviewKey);
            }
        }

        private OneShotResponse Again(string verb, string suffix, string body)
        {
            if (verb == "POST" && suffix == "code" && _reply is not null && _replyFor is not null
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

        private OneShotResponse Wrong(string message)
        {
            if (++_wrong >= Tries)
            {
                _why = "the recovery code was wrong " + Tries.ToString(CultureInfo.InvariantCulture) + " times; nothing was changed";
                _result.TrySetResult(null);

                return new OneShotResponse(403, "application/json", JsonSerializer.Serialize(new { ok = false, error = message, final = true }));
            }

            return new OneShotResponse(400, "application/json", JsonSerializer.Serialize(new { ok = false, error = message }));
        }
    }
}

/// <summary>Page 1 of <c>--recover</c>: one input for the recovery code, Unlock and Cancel. All text is HTML-encoded; the code is never in the page.</summary>
internal static class RecoveryPage
{
    private const string Script = """
        (function () {
            "use strict";
            var start = JSON.parse(document.getElementById("start").textContent);
            var submit = document.getElementById("unlock");
            var cancel = document.getElementById("deny");
            var input = document.getElementById("recovery-code");
            var status = document.getElementById("status");
            var base = location.pathname.replace(/\/+$/, "");
            var encoder = new TextEncoder();
            var busy = false;
            var attempt = 0;
            var finished = false;

            function show(text) {
                status.textContent = text + (diagLine ? " " + diagLine : "");
            }

            //@FOLLOW@

            function finish(text) {
                finished = true;
                submit.disabled = true;
                cancel.disabled = true;
                input.value = "";
                input.disabled = true;
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

            // The code leaves the page only sealed to the program's key for this page (the scheme of the set page): a fresh ECDH
            // P-256 key, HKDF-SHA-256 (salt: the bind, info: "with-secrets/v1 secrets") and AES-256-GCM with the bind as associated data.
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
                    return { epk: toBase64Url(epk), iv: toBase64Url(iv), ct: toBase64Url(ct) };
                });
            }

            // The browser's own error, for the status line: its name and message (cut to 120 characters). Never the code.
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

            cancel.addEventListener("click", function () {
                if (finished) {
                    return;
                }
                finish("Sending cancel...");
                post("deny", "").then(function (reply) {
                    show(reply.ok ? "Cancelled. Nothing was changed. You can close this page." : "This request had already ended.");
                }, function () {
                    show("Could not reach the program. With no answer it changes nothing at its time limit.");
                });
            });

            submit.addEventListener("click", function () {
                if (finished || busy) {
                    return;
                }
                if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
                    show("This page needs an https address or localhost. Nothing was changed.");
                    return;
                }
                var text = input.value.trim();
                if (text.length === 0 || text.length > 100) {
                    show("Type the recovery code. Nothing was changed.");
                    return;
                }
                var mine = ++attempt;
                busy = true;
                submit.disabled = true;
                show("Checking the recovery code...");
                var plain = encoder.encode(JSON.stringify({ code: text }));
                seal(plain, fromBase64Url(start.bind), fromBase64Url(start.serverKey)).then(function (sealed) {
                    if (mine !== attempt || finished) {
                        throw new Error("newer");
                    }
                    return post("code", JSON.stringify(sealed));
                }).then(function (reply) {
                    busy = false;
                    return reply.json().then(function (data) {
                        if (reply.ok && data && data.ok === true) {
                            if (typeof data.next === "string") {
                                follow(data.next);
                                return;
                            }
                            finish("The recovery code was accepted, but the program gave no next step to open. Nothing was changed.");
                            return;
                        }
                        if (data && data.final === true) {
                            finish("That recovery code was wrong too many times. Nothing was changed.");
                            return;
                        }
                        submit.disabled = false;
                        show((data && typeof data.error === "string" ? data.error : "The program refused what this page sent.") + " Nothing was changed. You can try again or cancel.");
                    });
                }).then(null, function (error) {
                    busy = false;
                    if (finished) {
                        return;
                    }
                    submit.disabled = false;
                    if (error && error.name === "AbortError") {
                        show("The program did not answer within 20 seconds. Check the terminal. Tap again to retry.");
                    } else {
                        show("The code could not be sent" + why(error) + ". Nothing was changed. You can try again or cancel.");
                    }
                });
            });
            input.focus();
        })();
        """;

    private const string Style = """
        .field { margin: 1rem 0; }
        .field label { display: block; font-weight: bold; margin-bottom: 0.3rem; }
        .field input { font-size: 1.2rem; font-family: ui-monospace, monospace; padding: 0.5rem; width: 100%; max-width: 34rem; box-sizing: border-box; }
        """;

    /// <summary>Builds the page. Script and style line endings become LF before hashing and output, so the CSP hashes match what is served.</summary>
    public static OneShotResponse Build(string adminLine, byte[] bind, string serverKey, int secretCount)
    {
        string script = PageContinue.Fill(Script).ReplaceLineEndings("\n");
        string style = (ApprovalPage.Style + Style).ReplaceLineEndings("\n");
        string policy = ApprovalPage.Policy(script, style);
        string json = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["bind"] = Base64Url.EncodeToString(bind),
            ["serverKey"] = serverKey,
        });

        StringBuilder page = new();
        page.Append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
        page.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
        page.Append("<meta name=\"referrer\" content=\"no-referrer\">\n");
        page.Append("<title>Recover with-secrets</title>\n");
        page.Append("<style>").Append(style).Append("</style>\n</head>\n<body>\n<main>\n");
        page.Append("<h1>Recover the with-secrets store</h1>\n");
        page.Append("<pre id=\"request\">").Append(WebUtility.HtmlEncode(ApprovalSummary.Clean(adminLine) + "\nSecrets in the store: " + secretCount.ToString(CultureInfo.InvariantCulture))).Append("</pre>\n");
        page.Append("<p>Use this when every passkey is lost. Type the recovery code that was shown when the store was set up (lower case, spaces and dashes are fine). "
            + "The code is encrypted in this page before it is sent.</p>\n");
        page.Append("<p><strong>This replaces the store.</strong> After the code, you make a new passkey and the new keys: a new store key, a new master key and a new recovery code. "
            + "Your secrets are carried over. The old admin keys are gone: they stay only in the old file, which is renamed (never deleted). "
            + "Nothing changes until the last step is done.</p>\n");
        page.Append("<div class=\"field\"><label for=\"recovery-code\">Recovery code</label>"
            + "<input id=\"recovery-code\" type=\"text\" autocomplete=\"off\" autocapitalize=\"characters\" autocorrect=\"off\" spellcheck=\"false\" maxlength=\"100\"></div>\n");
        page.Append("<div class=\"buttons\">");
        page.Append("<button id=\"deny\" type=\"button\">Cancel</button>");
        page.Append("<button id=\"unlock\" type=\"button\">Check the recovery code</button>");
        page.Append("</div>\n<p id=\"status\" role=\"status\"></p>\n" + PageContinue.Box + "</main>\n");
        page.Append("<script type=\"application/json\" id=\"start\">").Append(json).Append("</script>\n");
        page.Append("<script>").Append(script).Append("</script>\n</body>\n</html>\n");

        return new OneShotResponse(200, "text/html; charset=utf-8", page.ToString(), policy);
    }
}

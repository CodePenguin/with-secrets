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
/// The rules and the server side of entering secret values in the admin web app (see <see cref="SecretFlows" />): the names, the text
/// the passkey signs, and the <see cref="Session" /> that takes the values the page sends sealed to the entry's key, checks them, encrypts each
/// value to the store's public key and answers with the batch to sign. The Save tap covers both the submitted values and
/// the stored ciphertext hashes. The batch, its assertion, the ciphertexts and the audit entry are committed together.
/// </summary>
public static class SecretEntry
{
    public const int MaxNames = 20;
    public const int MaxValueLength = 4096;

    /// <summary>How many times one set page may send values to /seal before it ends.</summary>
    internal const int MaxSeals = 500;

    private static readonly OneShotResponse NotFound = new(404, "text/plain; charset=utf-8", "Not found.");

    internal static SecretChange Denied(string detail)
    {
        return new SecretChange(RunCommand.Denied, detail);
    }

    /// <summary>Null when the names may be used: 1 to <see cref="MaxNames" /> different names, each valid.</summary>
    internal static SecretChange? CheckNames(IReadOnlyList<string> names)
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

    /// <summary>The text a person signs to store these names: what is new, what is replaced, and the warnings about names that are easy to confuse. Public information only.</summary>
    internal static string SetText(IReadOnlyList<string> names, HashSet<string> stored, IProofMethod method)
    {
        List<(string Name, bool Replace)> fields = [.. names.Select(name => (name, stored.Contains(name)))];
        string text = "Store these secrets: " + string.Join(", ", fields.Select(field => field.Name + (field.Replace ? " (replace)" : " (new)"))) + ".";
        if (fields.Any(field => field.Replace))
        {
            text += "\nExisting grants can use replacement values without asking again.";
        }

        return WithNameWarnings(text, names, stored, method);
    }

    internal static string EditText(string source, string destination, HashSet<string> stored, IProofMethod method)
    {
        string text = source == destination
            ? $"Replace the value of {source}. Existing grants can use replacement values without asking again."
            : $"Move {source} to {destination}. Keep its value unless a replacement is supplied.";
        return WithNameWarnings(text, [destination], stored, method);
    }

    private static string WithNameWarnings(string text, IReadOnlyList<string> names, HashSet<string> stored, IProofMethod method)
    {
        // Names are case-sensitive: a name that differs from a stored one only by case is a different secret. A warning, not a refusal;
        // it is part of the bound text, so the person signs what they were warned about. Names are public.
        foreach (string name in names)
        {
            if (SecretNames.CaseTwins(name, stored) is { Count: > 0 } twins)
            {
                text += "\nWarning: " + name + " differs only by case from the existing name" + (twins.Count > 1 ? "s" : "") + ": " + string.Join(", ", twins) + ". Names are case-sensitive, so this is a different secret.";
            }

            // Two new names of this same request that differ only by case: neither is stored yet, so the check above cannot see them.
            if (SecretNames.CaseTwins(name, names) is { Count: > 0 } together)
            {
                text += "\nWarning: " + name + " differs only by case from " + string.Join(", ", together) + ", which this request also stores. Names are case-sensitive, so these are different secrets.";
            }

            // Look-alike characters (l, I, 1 and O, 0) make two names easy to confuse as well.
            if (SecretNames.LookAlikes(name, stored.Concat(names)) is { Count: > 0 } alike)
            {
                text += "\nWarning: " + name + " looks like " + string.Join(", ", alike) + " (the characters l, I, 1 and O, 0 are easy to confuse). It is a different secret.";
            }
        }

        if (method.AdminLine() is { } adminLine)
        {
            text += "\n" + adminLine;
        }

        return text;
    }

    internal sealed record Edit(string Source, string Ciphertext);

    /// <summary>
    /// The state of one set page. Requests are handled one at a time under one lock; the first outcome is final, and after
    /// it every request is 404. The store is written inside the lock, so the time limit cannot cut a write in half.
    /// </summary>
    internal sealed class Session(IProofMethod method, SecretStore store, Manifest manifest, string storeKey, List<string> names, byte[] serverKey, Edit? edit = null)
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
        private readonly string[] _removes = edit is not null && edit.Source != names[0] ? [edit.Source] : [];
        internal VerifiedCredential? VerifiedFailure { get; private set; }

        private readonly TaskCompletionSource<SecretChange> _decision = new(TaskCreationOptions.RunContinuationsAsynchronously);

        // By base64url SHA-256 of the page's ct: the batch to sign and the store rows made from it. No plaintext is kept.
        private readonly Dictionary<string, (string Text, Dictionary<string, string> Rows)> _sealed = new(StringComparer.Ordinal);
        private readonly Queue<string> _order = new();
        private int _seals;
        private string? _origin;
        private byte[]? _bind;

        public void Open(string origin, byte[] bind)
        {
            lock (_gate)
            {
                _origin = origin;
                _bind = bind;
            }
        }

        /// <summary>True when the server key is zeroed and nothing sealed is kept (the page ended).</summary>
        internal bool IsErased
        {
            get
            {
                lock (_gate)
                {
                    return _sealed.Count == 0 && serverKey.All(value => value == 0);
                }
            }
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
                if (_origin is null || _bind is null || _decision.Task.IsCompleted)
                {
                    return NotFound;
                }

                switch (verb, suffix)
                {
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
        /// and answers with the batch to sign (names and hashes). A refusal says why (names only)
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
            if (_sealed.TryGetValue(key, out var earlier))
            {
                return Sealed(earlier.Text);
            }

            Dictionary<string, string> rows = new(StringComparer.Ordinal);
            foreach (string name in names)
            {
                rows[name] = values.Count == 0 ? edit!.Ciphertext : store.Encrypt(values[name], storeKey);
            }

            string text = _removes.Length == 0
                ? SignedSecretWrite.Prepare(manifest, rows)
                : SecretStore.Next(manifest, storeKey, rows, _removes).Canonical();
            _sealed[key] = (text, rows);
            _order.Enqueue(key);
            while (_order.Count > Kept)
            {
                _sealed.Remove(_order.Dequeue());
            }

            return Sealed(text);
        }

        private static OneShotResponse Sealed(string text)
        {
            return new OneShotResponse(200, "application/json", JsonSerializer.Serialize(new { ok = true, manifest = text }));
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

            // Only values that went through /seal can be saved: the batch the passkey signed is the one made from them. Values
            // that were never sealed are checked again, so the answer says why they could not be.
            if (!_sealed.TryGetValue(Key(ct), out var prepared))
            {
                (_, string? problem) = Open(bind, members);
                _decision.TrySetResult(Denied((problem ?? "the values were not prepared on the page") + "; nothing was stored"));

                return Invalid;
            }

            // The passkey signed SHA-256(bind || SHA-256(ct) || SHA-256(batch)): the values on this page and the ciphertext hashes.
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
                result = method.Verify(new ProofContext(Manifest.Challenge(manifestBind, prepared.Text), origin), assertion);
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

            AdminEvent change = AdminEvent.Secrets(edit is null ? SecretFlows.SetCommand : "secrets-edited", [.. _removes, .. names],
                result.Detail, result.Credential?.Name ?? AdminAudit.KeyName(result.Detail), result.Credential);
            string? problemWriting = _removes.Length == 0
                ? store.TrySet(manifest.Version, new SignedSecretWrite(prepared.Text, manifestBind, assertion), prepared.Rows, change)
                : store.TryApply(manifest.Version, new SignedManifest(prepared.Text, manifestBind, assertion), prepared.Rows, _removes, change);
            if (problemWriting is not null)
            {
                VerifiedFailure = result.Credential;
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

            if (edit is not null && values.Count == 0)
            {
                if (_removes.Length == 0)
                {
                    return "the name, path and value are unchanged";
                }

                // Moving a dotenvx private key into the ordinary namespace would let a command request its existing value.
                return SecretNames.IsPrivateKeyName(edit.Source) == SecretNames.IsPrivateKeyName(names[0])
                    ? null : "enter a new value to move a secret between private-key and ordinary paths";
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

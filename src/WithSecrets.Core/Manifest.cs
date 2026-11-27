using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WithSecrets;

/// <summary>One key in the manifest. <see cref="Id" /> and <see cref="PublicKey" /> are base64url, as <see cref="PasskeyRecord" /> keeps them.</summary>
public sealed record ManifestKey(string Id, string Name, string PublicKey, int Alg, string RpId, DateTimeOffset Created, bool Admin, KeySlot? Slot = null)
{
    public static ManifestKey From(PasskeyRecord record, bool admin) => new(record.Id, record.Name, record.PublicKey, record.Alg, record.RpId, record.Created, admin, admin ? record.Slot : null);

    public PasskeyRecord Record(uint signCount) => new(Id, PublicKey, Alg, RpId, Name, Created, signCount, Admin, Slot);
}

/// <summary>
/// The one signed description of what the tool trusts: every enrolled key (at least one of them an admin), the secret store's
/// public key and the hash of every stored secret, and every setting, with a version that goes up by one with each change. It
/// is stored as canonical JSON with an admin key's assertion over <see cref="Challenge" /> of that text (see
/// <see cref="SignedManifest" />). Verified <see cref="SignedSecretWrite" /> entries update only its effective secret hashes and version.
/// <para>
/// The canonical text is exactly
/// <c>{"v":N,"keys":[{"id":S,"name":S,"pub":S,"alg":N,"rp":S,"created":S,"admin":true|false[,"slot":{"salt":S,"wrap":S}]},...],"store":S,"vault":S[,"recovery":{"salt":S,"wrap":S}],"secrets":{NAME:HASH,...},"settings":SETTINGS}</c>:
/// this member order, no white space, keys sorted by id (ordinal), secrets sorted by name (ordinal), numbers as plain invariant
/// integers, strings written as <see cref="ToolSettings.Canonical" /> writes them (only <c>"</c> and <c>\</c> escaped, U+007F
/// and up as <c>\uXXXX</c>), <c>created</c> in the round-trip ("O") format and SETTINGS the canonical settings JSON. Sign counts
/// are not in it. <see cref="Store" /> is the store's public key (P-256 SubjectPublicKeyInfo encoded as base64url) or empty before the first
/// secret, and <see cref="Vault" /> is then the store's private key wrapped under the master key (empty exactly when the store key is); the
/// slot of an admin key is its entry of the master key (see <see cref="KeyVault" />); each HASH is <see cref="SecretStore.Hash" />
/// of that secret's stored ciphertext (64 lower-case hex digits). Anyone
/// with the public key can make a valid ciphertext, so a row is trusted only when it matches its signed hash.
/// </para>
/// </summary>
public sealed record Manifest(long Version, IReadOnlyList<ManifestKey> Keys, ToolSettings Settings, string Store, IReadOnlyDictionary<string, string> Secrets, string Vault = "", KeySlot? Recovery = null, ReviewKey? Review = null)
{
    private static readonly JsonDocumentOptions Strict = new() { AllowDuplicateProperties = false };

    private static readonly IReadOnlyDictionary<string, string> NoSecrets = new SortedDictionary<string, string>(StringComparer.Ordinal);

    /// <summary>A manifest with no store key and no secrets.</summary>
    public Manifest(long version, IReadOnlyList<ManifestKey> keys, ToolSettings settings) : this(version, keys, settings, "", NoSecrets)
    {
    }

    /// <summary>True when the key with this id is an admin key here.</summary>
    public bool IsAdmin(string id) => Keys.Any(key => key.Admin && key.Id == id);

    /// <summary>The name of the key with this id, or null.</summary>
    public string? NameOf(string id) => Keys.FirstOrDefault(key => key.Id == id)?.Name;

    /// <summary>The first manifest: the first key, which is the admin, and the settings.</summary>
    public static Manifest First(PasskeyRecord admin, ToolSettings settings) => new(1, [ManifestKey.From(admin, true)], settings);

    /// <summary>The admin keys, oldest first (then by id).</summary>
    public IReadOnlyList<ManifestKey> Admins => [.. Keys.Where(key => key.Admin).OrderBy(key => key.Created).ThenBy(key => key.Id, StringComparer.Ordinal)];

    /// <summary>The next version with <paramref name="key" /> added as an admin or a convenience passkey.</summary>
    public Manifest WithKey(PasskeyRecord key, bool admin = false) => Next([.. Keys, ManifestKey.From(key, admin)], Settings, Store, Secrets, Vault, Recovery);

    /// <summary>The next version without the key with this Id.</summary>
    public Manifest WithoutKey(string id) => Next([.. Keys.Where(key => key.Id != id)], Settings, Store, Secrets, Vault, Recovery);

    /// <summary>The next version with these settings.</summary>
    public Manifest WithSettings(ToolSettings settings) => Next(Keys, settings, Store, Secrets, Vault, Recovery);

    /// <summary>The next version with this store public key and exactly these secret hashes (by name), and this vault (the same one when null).</summary>
    public Manifest WithSecrets(string store, IReadOnlyDictionary<string, string> secrets, string? vault = null, ReviewKey? review = null)
        => Next(Keys, Settings, store, secrets, vault ?? Vault, Recovery, review);

    /// <summary>
    /// The next version after a key rotation: only <paramref name="key" /> (the admin who rotates, with its slot of the new master
    /// key), the new store key, its vault and recovery slot, and the hash of every re-encrypted secret. The settings stay.
    /// </summary>
    public Manifest Rotated(ManifestKey key, string store, string vault, KeySlot recovery, IReadOnlyDictionary<string, string> secrets, ReviewKey review)
        => Next([key], Settings, store, secrets, vault, recovery, review);

    private Manifest Next(IEnumerable<ManifestKey> keys, ToolSettings settings, string store, IReadOnlyDictionary<string, string> secrets, string vault, KeySlot? recovery, ReviewKey? review = null)
        => new(Version + 1, [.. keys.OrderBy(key => key.Id, StringComparer.Ordinal)], settings, store, new SortedDictionary<string, string>(secrets.ToDictionary(), StringComparer.Ordinal), vault, recovery, review ?? Review);

    /// <summary>What an admin key signs: SHA-256(bind || SHA-256(UTF-8 of the manifest text)).</summary>
    public static byte[] Challenge(byte[] bind, string text)
    {
        return SHA256.HashData([.. bind, .. SHA256.HashData(Encoding.UTF8.GetBytes(text))]);
    }

    public string Canonical() => SettingsPrefix() + Settings.Canonical() + "}";

    /// <summary>The canonical text up to the settings: the settings page appends the canonical settings and "}".</summary>
    public string SettingsPrefix()
    {
        StringBuilder text = new();
        text.Append("{\"v\":").Append(Version.ToString(CultureInfo.InvariantCulture)).Append(",\"keys\":[");
        bool first = true;
        foreach (ManifestKey key in Keys)
        {
            text.Append(first ? "" : ",").Append("{\"id\":");
            first = false;
            ToolSettings.Quote(text, key.Id);
            text.Append(",\"name\":");
            ToolSettings.Quote(text, key.Name);
            text.Append(",\"pub\":");
            ToolSettings.Quote(text, key.PublicKey);
            text.Append(",\"alg\":").Append(key.Alg.ToString(CultureInfo.InvariantCulture)).Append(",\"rp\":");
            ToolSettings.Quote(text, key.RpId);
            text.Append(",\"created\":");
            ToolSettings.Quote(text, key.Created.ToString("O", CultureInfo.InvariantCulture));
            text.Append(",\"admin\":").Append(key.Admin ? "true" : "false");
            if (key.Slot is { } slot)
            {
                text.Append(",\"slot\":{\"salt\":");
                ToolSettings.Quote(text, slot.Salt);
                text.Append(",\"wrap\":");
                ToolSettings.Quote(text, slot.Wrap);
                text.Append('}');
            }
            text.Append('}');
        }

        text.Append("],\"store\":");
        ToolSettings.Quote(text, Store);
        text.Append(",\"vault\":");
        ToolSettings.Quote(text, Vault);
        if (Review is { } review)
        {
            text.Append(",\"review\":{\"pub\":");
            ToolSettings.Quote(text, review.PublicKey);
            text.Append(",\"vault\":");
            ToolSettings.Quote(text, review.Vault);
            text.Append('}');
        }
        if (Recovery is not null)
        {
            // The recovery slot of the master key (see KeyVault.NewRecoverySlot): present from the first setup on, left out only by states built without one.
            text.Append(",\"recovery\":{\"salt\":");
            ToolSettings.Quote(text, Recovery.Salt);
            text.Append(",\"wrap\":");
            ToolSettings.Quote(text, Recovery.Wrap);
            text.Append('}');
        }

        text.Append(",\"secrets\":{");
        first = true;
        foreach (KeyValuePair<string, string> secret in Secrets.OrderBy(item => item.Key, StringComparer.Ordinal))
        {
            text.Append(first ? "" : ",");
            first = false;
            ToolSettings.Quote(text, secret.Key);
            text.Append(':');
            ToolSettings.Quote(text, secret.Value);
        }

        return text.Append("},\"settings\":").ToString();
    }

    /// <summary>Null when the manifest may be stored, else why not: an admin, valid unique keys, a valid store key and secret hashes, valid settings.</summary>
    public string? Problem()
    {
        if (Version < 1)
        {
            return "the version is below 1";
        }

        if (!Keys.Any(key => key.Admin))
        {
            return "the manifest has no admin key";
        }

        if (Keys.Select(key => key.Id).Distinct(StringComparer.Ordinal).Count() != Keys.Count)
        {
            return "a key id appears twice";
        }

        if (!Keys.Select(key => key.Id).SequenceEqual(Keys.Select(key => key.Id).Order(StringComparer.Ordinal)))
        {
            return "the keys are not sorted by id";
        }

        if (Keys.Select(key => key.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() != Keys.Count)
        {
            return "a key name appears twice";
        }

        foreach (ManifestKey key in Keys)
        {
            if (key.Id.Length == 0 || key.PublicKey.Length == 0 || key.RpId.Length == 0 || key.Alg is not (WebAuthn.ES256 or WebAuthn.RS256) || Enrollment.NameError(key.Name) is not null)
            {
                return "a key is not valid";
            }

            if (key.Admin && (key.Slot is null || !KeyVault.IsSalt(key.Slot.Salt) || !KeyVault.IsSlotWrap(key.Slot.Wrap)))
            {
                return "an admin key has no valid key slot";
            }

            if (!key.Admin && key.Slot is not null)
            {
                return "a key that is not an admin has a key slot";
            }
        }

        if (Store.Length > 0 && !JweCipher.IsPublicKey(Store))
        {
            return "the store key is not valid";
        }

        // The vault holds the store's private key: present exactly when there is a store key.
        if (Store.Length > 0 ? !KeyVault.IsVault(Vault) : Vault.Length > 0)
        {
            return Store.Length > 0 ? "the store key has no valid vault" : "a vault without a store key";
        }

        if (Store.Length > 0 && Review is null)
        {
            return "the store key has no review key";
        }

        if (Review is { } review)
        {
            if (Store.Length == 0)
            {
                return "a review key without a store key";
            }
            if (!JweCipher.IsPublicKey(review.PublicKey) || !KeyVault.IsVault(review.Vault))
            {
                return "the review key is not valid";
            }
            if (review.PublicKey == Store)
            {
                return "the review key is the store key";
            }
        }

        if (Recovery is not null && (Store.Length == 0 || !KeyVault.IsSalt(Recovery.Salt) || !KeyVault.IsSlotWrap(Recovery.Wrap)))
        {
            return Store.Length == 0 ? "a recovery slot without a store key" : "the recovery slot is not valid";
        }

        if (Secrets.Count > 0 && Store.Length == 0)
        {
            return "secrets without a store key";
        }

        if (!Secrets.Keys.SequenceEqual(Secrets.Keys.Order(StringComparer.Ordinal)))
        {
            return "the secrets are not sorted by name";
        }

        foreach (KeyValuePair<string, string> secret in Secrets)
        {
            if (!SecretNames.IsValid(secret.Key) || !IsHex(secret.Value, 64))
            {
                return "a secret hash is not valid";
            }
        }

        return Settings.Problem();
    }

    /// <summary>Exactly <paramref name="length" /> lower-case hex digits.</summary>
    private static bool IsHex(string value, int length) => value.Length == length && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    /// <summary>The manifest in <paramref name="text" />, or null and why not. The text must be exactly the canonical form of a valid manifest.</summary>
    public static Manifest? Parse(string text, out string? error)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(text, Strict);
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("v", out JsonElement v) || !v.TryGetInt64(out long version)
                || !root.TryGetProperty("keys", out JsonElement keys) || keys.ValueKind != JsonValueKind.Array
                || !root.TryGetProperty("settings", out JsonElement settingsJson) || settingsJson.ValueKind != JsonValueKind.Object
                || Text(root, "store") is not { } store || Text(root, "vault") is not { } vault
                || !root.TryGetProperty("secrets", out JsonElement secretsJson) || secretsJson.ValueKind != JsonValueKind.Object)
            {
                error = "the manifest does not have a version, keys, a store key, a vault, secrets and settings";

                return null;
            }

            // Kept in the order of the text, so text out of order fails the canonical check below.
            List<KeyValuePair<string, string>> secrets = [];
            foreach (JsonProperty secret in secretsJson.EnumerateObject())
            {
                if (secret.Value.ValueKind != JsonValueKind.String)
                {
                    error = "a secret hash in the manifest is not valid";

                    return null;
                }

                secrets.Add(new(secret.Name, secret.Value.GetString()!));
            }

            if (!secrets.Select(item => item.Key).SequenceEqual(secrets.Select(item => item.Key).Order(StringComparer.Ordinal)))
            {
                error = "the secrets are not sorted by name";

                return null;
            }

            List<ManifestKey> list = [];
            foreach (JsonElement item in keys.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object
                    || Text(item, "id") is not { } id || Text(item, "name") is not { } name || Text(item, "pub") is not { } pub
                    || !item.TryGetProperty("alg", out JsonElement alg) || !alg.TryGetInt32(out int algorithm)
                    || Text(item, "rp") is not { } rp || Text(item, "created") is not { } created
                    || !DateTimeOffset.TryParseExact(created, "O", CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTimeOffset when)
                    || !item.TryGetProperty("admin", out JsonElement admin) || admin.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                {
                    error = "a key in the manifest is not valid";

                    return null;
                }

                KeySlot? slot = null;
                if (item.TryGetProperty("slot", out JsonElement slotJson))
                {
                    if (slotJson.ValueKind != JsonValueKind.Object || Text(slotJson, "salt") is not { } salt
                        || Text(slotJson, "wrap") is not { } wrap)
                    {
                        error = "a key slot in the manifest is not valid";

                        return null;
                    }

                    slot = new KeySlot(salt, wrap);
                }

                list.Add(new ManifestKey(id, name, pub, algorithm, rp, when, admin.ValueKind == JsonValueKind.True, slot));
            }

            ToolSettings? settings = ToolSettings.FromCanonical(settingsJson.GetRawText(), out string? settingsError);
            if (settings is null)
            {
                error = "the settings in the manifest are not valid (" + settingsError + ")";

                return null;
            }

            KeySlot? recovery = null;
            if (root.TryGetProperty("recovery", out JsonElement recoveryJson))
            {
                if (recoveryJson.ValueKind != JsonValueKind.Object || Text(recoveryJson, "salt") is not { } recoverySalt || Text(recoveryJson, "wrap") is not { } recoveryWrap)
                {
                    error = "the recovery slot in the manifest is not valid";

                    return null;
                }

                recovery = new KeySlot(recoverySalt, recoveryWrap);
            }

            ReviewKey? review = null;
            if (root.TryGetProperty("review", out JsonElement reviewJson))
            {
                if (reviewJson.ValueKind != JsonValueKind.Object || Text(reviewJson, "pub") is not { } reviewPublicKey || Text(reviewJson, "vault") is not { } reviewVault)
                {
                    error = "the review key is not valid";
                    return null;
                }
                review = new ReviewKey(reviewPublicKey, reviewVault);
            }

            Manifest manifest = new(version, list, settings, store, new SortedDictionary<string, string>(secrets.ToDictionary(StringComparer.Ordinal), StringComparer.Ordinal), vault, recovery, review);
            error = manifest.Problem();
            if (error is not null)
            {
                return null;
            }

            if (manifest.Canonical() != text)
            {
                error = "the manifest is not in canonical form";

                return null;
            }

            return manifest;
        }
        catch (Exception failure) when (failure is JsonException or ArgumentException or InvalidOperationException or FormatException)
        {
            error = "the manifest is not JSON";

            return null;
        }
    }

    private static string? Text(JsonElement element, string name)
    {
        return element.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    }
}

/// <summary>
/// The admin keys' short fingerprints, which every page shows so that a replaced or added
/// admin key (a with-secrets.db written by someone else) is visible to the person. A fingerprint is the first 8 bytes of SHA-256 of
/// the public key bytes as the manifest stores them (the COSE key, decoded from base64url), as four groups of four lower-case
/// hex digits, for example <c>ab12 cd34 ef56 7890</c>. It is not secret.
/// </summary>
public static class AdminKey
{
    /// <summary>What every page shows before any key is enrolled.</summary>
    public const string NotSetUp = "Admins: not set up yet";

    /// <summary>The fingerprint of a public key as the manifest stores it (base64url).</summary>
    public static string Fingerprint(string publicKey)
    {
        string hex = Convert.ToHexStringLower(SHA256.HashData(System.Buffers.Text.Base64Url.DecodeFromChars(publicKey))[..8]);

        return string.Join(' ', hex[..4], hex[4..8], hex[8..12], hex[12..]);
    }

    /// <summary>"NAME ab12 cd34 ef56 7890" for one key; the name is cleaned.</summary>
    public static string Entry(string name, string publicKey) => ApprovalSummary.Clean(name) + " " + Fingerprint(publicKey);

    /// <summary>"Admins: NAME ab12 cd34 ef56 7890, NAME ...", every admin oldest first, or <see cref="NotSetUp" /> without a manifest.</summary>
    public static string Line(Manifest? manifest)
    {
        return manifest is null || manifest.Admins.Count == 0 ? NotSetUp : "Admins: " + string.Join(", ", manifest.Admins.Select(key => Entry(key.Name, key.PublicKey)));
    }

    /// <summary>The line for the verified state in <paramref name="db" />; a state that cannot be read says so.</summary>
    public static string Line(StateDatabase db)
    {
        return db.TryManifest(out Manifest? manifest, out _) ? Line(manifest) : "Admins: cannot be read (the state failed verification)";
    }
}

/// <summary>
/// A manifest text with an admin assertion over it: <paramref name="Proof" /> is the assertion JSON
/// (<c>{"id","authenticatorData","clientDataJSON","signature"}</c>, base64url), made over
/// <see cref="Manifest.Challenge" /> of <paramref name="Bind" /> and <paramref name="Text" />.
/// </summary>
public sealed record SignedManifest(string Text, byte[] Bind, string Proof)
{
    /// <summary>The credential id of the key that signed, or null when the proof has none.</summary>
    public string? SignerId
    {
        get
        {
            try
            {
                using System.Text.Json.JsonDocument document = System.Text.Json.JsonDocument.Parse(Proof);

                return document.RootElement.ValueKind == System.Text.Json.JsonValueKind.Object && document.RootElement.TryGetProperty("id", out System.Text.Json.JsonElement id)
                    && id.ValueKind == System.Text.Json.JsonValueKind.String ? id.GetString() : null;
            }
            catch (System.Text.Json.JsonException)
            {
                return null;
            }
        }
    }

    /// <summary>
    /// The check made every time the state is read: the text parses as a valid manifest, the key that signed (by the id in
    /// the assertion) is an admin key of this manifest, and the assertion verifies with that key (the signature, the challenge
    /// and type in the client data, user presence and verification). The page origin, the rpId hash and the sign count were
    /// checked when it was made and are not checked again. Null and why not when it fails.
    /// </summary>
    public Manifest? Verify(out string? error) => Verify(null, out error);

    /// <summary>
    /// The same, and with <paramref name="authority" /> (the stored manifest this one replaces) the key that signed must
    /// also be an admin key there, and the assertion must verify with the key as stored there too.
    /// </summary>
    public Manifest? Verify(Manifest? authority, out string? error)
    {
        Manifest? manifest = Manifest.Parse(Text, out error);
        if (manifest is null)
        {
            return null;
        }

        string? signer = SignerId;
        if (authority is not null && (signer is null || !authority.IsAdmin(signer)))
        {
            error = "the key that signed it is not an admin key of the current state";

            return null;
        }

        if (signer is null || !manifest.IsAdmin(signer))
        {
            error = authority is null ? "the key that signed it is not an admin key in it"
                : "the key that signed it would not be an admin key of the new state; approve with another admin key";

            return null;
        }

        foreach (Manifest by in authority is null ? [manifest] : new[] { authority, manifest })
        {
            AssertionResult result = WebAuthn.VerifyStored(by.Keys.Single(key => key.Id == signer).Record(0), Manifest.Challenge(Bind, Text), Proof);
            if (!result.Ok)
            {
                error = "the manifest signature does not verify (" + result.Detail + ")";

                return null;
            }
        }

        return manifest;
    }
}

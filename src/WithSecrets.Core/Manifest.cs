using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WithSecrets;

/// <summary>One key in the manifest. <see cref="Id" /> and <see cref="PublicKey" /> are base64url, as <see cref="PasskeyRecord" /> keeps them.</summary>
public sealed record ManifestKey(string Id, string Name, string PublicKey, int Alg, string RpId, DateTimeOffset Created, bool Admin)
{
    public static ManifestKey From(PasskeyRecord record, bool admin) => new(record.Id, record.Name, record.PublicKey, record.Alg, record.RpId, record.Created, admin);

    public PasskeyRecord Record(uint signCount) => new(Id, PublicKey, Alg, RpId, Name, Created, signCount, Admin);
}

/// <summary>
/// The one signed description of what the tool trusts: every enrolled key (exactly one of them the admin) and every setting,
/// with a version that goes up by one with each change. It is stored as its canonical JSON text with the admin key's assertion
/// over <see cref="Challenge" /> of that text (see <see cref="SignedManifest" />), and keys and settings are read only from it.
/// <para>
/// The canonical text is exactly
/// <c>{"v":N,"keys":[{"id":S,"name":S,"pub":S,"alg":N,"rp":S,"created":S,"admin":true|false},...],"settings":SETTINGS}</c>: this
/// member order, no white space, keys sorted by id (ordinal), numbers as plain invariant integers, strings written as
/// <see cref="ToolSettings.Canonical" /> writes them (only <c>"</c> and <c>\</c> escaped, U+007F and up as <c>\uXXXX</c>),
/// <c>created</c> in the round-trip ("O") format and SETTINGS the canonical settings JSON. Sign counts are not in it.
/// </para>
/// </summary>
public sealed record Manifest(long Version, IReadOnlyList<ManifestKey> Keys, ToolSettings Settings)
{
    private static readonly JsonDocumentOptions Strict = new() { AllowDuplicateProperties = false };

    /// <summary>The one admin key, or null when there is not exactly one.</summary>
    public ManifestKey? Admin => Keys.Count(key => key.Admin) == 1 ? Keys.Single(key => key.Admin) : null;

    /// <summary>The first manifest: the first key, which is the admin, and the settings.</summary>
    public static Manifest First(PasskeyRecord admin, ToolSettings settings) => new(1, [ManifestKey.From(admin, true)], settings);

    /// <summary>The next version with <paramref name="key" /> added as a key that only approves runs.</summary>
    public Manifest WithKey(PasskeyRecord key) => Next([.. Keys, ManifestKey.From(key, false)], Settings);

    /// <summary>The next version without the key with this Id.</summary>
    public Manifest WithoutKey(string id) => Next([.. Keys.Where(key => key.Id != id)], Settings);

    /// <summary>The next version with these settings.</summary>
    public Manifest WithSettings(ToolSettings settings) => Next(Keys, settings);

    private Manifest Next(IEnumerable<ManifestKey> keys, ToolSettings settings) => new(Version + 1, [.. keys.OrderBy(key => key.Id, StringComparer.Ordinal)], settings);

    /// <summary>What the admin key signs: SHA-256(bind || SHA-256(UTF-8 of the manifest text)).</summary>
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
            text.Append(",\"admin\":").Append(key.Admin ? "true" : "false").Append('}');
        }

        return text.Append("],\"settings\":").ToString();
    }

    /// <summary>Null when the manifest may be stored, else why not: one admin, valid unique keys, valid settings.</summary>
    public string? Problem()
    {
        if (Version < 1)
        {
            return "the version is below 1";
        }

        if (Keys.Count == 0 || Admin is null)
        {
            return "the manifest does not have exactly one admin key";
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
        }

        return Settings.Problem();
    }

    /// <summary>The manifest in <paramref name="text" />, or null and why not. The text must be exactly the canonical form of a valid manifest.</summary>
    public static Manifest? Parse(string text, out string? error)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(text, Strict);
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("v", out JsonElement v) || !v.TryGetInt64(out long version)
                || !root.TryGetProperty("keys", out JsonElement keys) || keys.ValueKind != JsonValueKind.Array
                || !root.TryGetProperty("settings", out JsonElement settingsJson) || settingsJson.ValueKind != JsonValueKind.Object)
            {
                error = "the manifest does not have a version, keys and settings";

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

                list.Add(new ManifestKey(id, name, pub, algorithm, rp, when, admin.ValueKind == JsonValueKind.True));
            }

            ToolSettings? settings = ToolSettings.FromCanonical(settingsJson.GetRawText(), out string? settingsError);
            if (settings is null)
            {
                error = "the settings in the manifest are not valid (" + settingsError + ")";

                return null;
            }

            Manifest manifest = new(version, list, settings);
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
/// The admin key's short fingerprint, which every page, <c>--enrolled</c> and <c>--audit</c> show so that a replaced admin key
/// (a state.db written by someone else) is visible to the person. It is the first 8 bytes of SHA-256 of the admin public key
/// bytes as the manifest stores them (the COSE key, decoded from base64url), as four groups of four lower-case hex digits,
/// for example <c>ab12 cd34 ef56 7890</c>. It is not secret.
/// </summary>
public static class AdminKey
{
    /// <summary>What every page shows before any key is enrolled.</summary>
    public const string NotSetUp = "Admin key: not set up yet";

    /// <summary>The fingerprint of a public key as the manifest stores it (base64url).</summary>
    public static string Fingerprint(string publicKey)
    {
        string hex = Convert.ToHexStringLower(SHA256.HashData(System.Buffers.Text.Base64Url.DecodeFromChars(publicKey))[..8]);

        return string.Join(' ', hex[..4], hex[4..8], hex[8..12], hex[12..]);
    }

    /// <summary>"Admin key: ab12 cd34 ef56 7890 (NAME)", or <see cref="NotSetUp" /> without a manifest.</summary>
    public static string Line(Manifest? manifest)
    {
        return manifest?.Admin is { } admin ? $"Admin key: {Fingerprint(admin.PublicKey)} ({ApprovalSummary.Clean(admin.Name)})" : NotSetUp;
    }

    /// <summary>The line for the verified state in <paramref name="db" />; a state that cannot be read says so.</summary>
    public static string Line(StateDatabase db)
    {
        return db.TryManifest(out Manifest? manifest, out _) ? Line(manifest) : "Admin key: cannot be read (the state failed verification)";
    }
}

/// <summary>
/// A manifest text with the admin assertion over it: <paramref name="Proof" /> is the assertion JSON
/// (<c>{"id","authenticatorData","clientDataJSON","signature"}</c>, base64url), made over
/// <see cref="Manifest.Challenge" /> of <paramref name="Bind" /> and <paramref name="Text" />.
/// </summary>
public sealed record SignedManifest(string Text, byte[] Bind, string Proof)
{
    /// <summary>
    /// The check made every time the state is read: the text parses as a valid manifest, and the assertion verifies with the
    /// public key of the manifest's own admin key (the signature, the challenge and type in the client data, user presence
    /// and verification). The page origin, the rpId hash and the sign count were checked when it was made and are not checked
    /// again. Null and why not when it fails.
    /// </summary>
    public Manifest? Verify(out string? error)
    {
        Manifest? manifest = Manifest.Parse(Text, out error);
        if (manifest is null)
        {
            return null;
        }

        AssertionResult result = WebAuthn.VerifyStored(manifest.Admin!.Record(0), Manifest.Challenge(Bind, Text), Proof);
        if (!result.Ok)
        {
            error = "the manifest signature does not verify (" + result.Detail + ")";

            return null;
        }

        return manifest;
    }
}

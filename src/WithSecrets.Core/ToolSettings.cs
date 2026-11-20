using System.Globalization;
using System.Text;
using System.Text.Json;

namespace WithSecrets;

/// <summary>One setting that changes: its name and the old and new values as text. None of the settings is secret.</summary>
public sealed record SettingChange(string Name, string Old, string New);

/// <summary>
/// Every setting of the tool, kept in the signed manifest in <see cref="StateDatabase" /> (see <see cref="Manifest" />). An empty
/// state uses the defaults. They change only in the admin web app, signed by an admin passkey; the first state takes the defaults (see <see cref="FirstRunPage" />).
/// A state that fails verification gives the defaults and an error.
/// </summary>
public sealed record ToolSettings(int ReuseMaxMinutes, string? BaseUrl, int Port, int TimeoutMinutes)
{
    public const int MinTimeoutMinutes = 1;
    public const int MaxPort = 65535;
    public const int MaxBaseUrlLength = 2048;

    /// <summary>The settings in their fixed order: the order of the canonical JSON, of the page and of the change lists.</summary>
    public static readonly IReadOnlyList<string> Names = ["reuseMaxMinutes", "baseUrl", "port", "timeoutMinutes"];

    public static ToolSettings Defaults { get; } = new(ReuseSettings.DefaultMaxMinutes, null, 0, ApprovalSettings.DefaultTimeoutMinutes);

    /// <summary>The settings the approval page uses.</summary>
    public ApprovalSettings Approval => new(BaseUrl, Port, TimeSpan.FromMinutes(TimeoutMinutes));

    /// <summary>The times a grant may last: the steps up to the ceiling.</summary>
    public ReuseOffer Reuse => new(ReuseMaxMinutes);

    /// <summary>The limits of a setting, as the page and the README show them.</summary>
    public static string Limits(string name) => name switch
    {
        "reuseMaxMinutes" => $"{ReuseSettings.MinMaxMinutes} to {ReuseSettings.MaxMinutes} minutes. A longer grant is neither offered nor honoured.",
        "baseUrl" => "Empty for none (the page is at http://localhost). A full http or https address, no user name or password, at most " + MaxBaseUrlLength.ToString(CultureInfo.InvariantCulture) + " characters.",
        "port" => $"0 to {MaxPort}. 0 picks a free port each time.",
        "timeoutMinutes" => $"{MinTimeoutMinutes} to {ApprovalSettings.MaxTimeoutMinutes} minutes.",
        _ => "",
    };

    /// <summary>Null when every value is within its limits, else why not, naming the setting in quotes.</summary>
    public string? Problem()
    {
        if (ReuseMaxMinutes is < ReuseSettings.MinMaxMinutes or > ReuseSettings.MaxMinutes)
        {
            return ReuseMaxProblem;
        }

        if (BaseUrl is not null && BaseUrlProblem(BaseUrl) is { } urlProblem)
        {
            return urlProblem;
        }

        if (Port is < 0 or > MaxPort)
        {
            return $"Setting 'port' must be a number from 0 to {MaxPort}.";
        }

        if (TimeoutMinutes is < MinTimeoutMinutes or > ApprovalSettings.MaxTimeoutMinutes)
        {
            return $"Setting 'timeoutMinutes' must be a number from {MinTimeoutMinutes} to {ApprovalSettings.MaxTimeoutMinutes}.";
        }

        return null;
    }

    private static string ReuseMaxProblem => $"Setting 'reuseMaxMinutes' must be a number from {ReuseSettings.MinMaxMinutes} to {ReuseSettings.MaxMinutes}.";

    /// <summary>Null when the text may be a baseUrl, else why not.</summary>
    internal static string? BaseUrlProblem(string text)
    {
        if (text.Length == 0 || text.Length > MaxBaseUrlLength || text.Any(char.IsControl)
            || !Uri.TryCreate(text, UriKind.Absolute, out Uri? uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            return $"Setting 'baseUrl' must be a full http or https address of at most {MaxBaseUrlLength} characters.";
        }

        return uri.UserInfo.Length > 0 ? "Setting 'baseUrl' must not hold a user name or password." : null;
    }

    /// <summary>
    /// The canonical JSON of these values, which the passkey signs on the first-run setup page. It is exactly
    /// <c>{"reuseMaxMinutes":N,"baseUrl":"S"|null,"port":N,"timeoutMinutes":N}</c>: this key order, no white space,
    /// numbers as plain invariant integers, strings with only <c>"</c> and <c>\</c> escaped (as <c>\"</c> and <c>\\</c>) and
    /// every character from U+007F up written as a lower-case <c>\uXXXX</c> escape (one per UTF-16 unit). Control characters
    /// are never valid in a value. The page builds the same text with <c>JSON.stringify</c> and the same escape step.
    /// </summary>
    public string Canonical()
    {
        StringBuilder text = new();
        text.Append("{\"reuseMaxMinutes\":").Append(ReuseMaxMinutes.ToString(CultureInfo.InvariantCulture));
        text.Append(",\"baseUrl\":");
        if (BaseUrl is null)
        {
            text.Append("null");
        }
        else
        {
            Quote(text, BaseUrl);
        }

        text.Append(",\"port\":").Append(Port.ToString(CultureInfo.InvariantCulture));
        text.Append(",\"timeoutMinutes\":").Append(TimeoutMinutes.ToString(CultureInfo.InvariantCulture)).Append('}');

        return text.ToString();
    }

    /// <summary>
    /// The settings in canonical JSON, or null and why not: the text must be exactly the canonical form of valid values, so
    /// what was signed is what is stored.
    /// </summary>
    public static ToolSettings? FromCanonical(string text, out string? error)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(text);
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !Int(root, "reuseMaxMinutes", out int reuseMax) || !Int(root, "port", out int port) || !Int(root, "timeoutMinutes", out int timeout)
                || !root.TryGetProperty("baseUrl", out JsonElement url) || url.ValueKind is not (JsonValueKind.String or JsonValueKind.Null))
            {
                error = "the settings are not the four settings with values of the right type";

                return null;
            }

            ToolSettings settings = new(reuseMax, url.ValueKind == JsonValueKind.Null ? null : url.GetString(), port, timeout);
            error = settings.Problem();
            if (error is not null)
            {
                return null;
            }

            if (settings.Canonical() != text)
            {
                error = "the settings are not in canonical form";

                return null;
            }

            return settings;
        }
        catch (JsonException)
        {
            error = "the settings are not JSON";

            return null;
        }
    }

    /// <summary>What differs from these settings in <paramref name="next" />, in the fixed order. A baseUrl of none is "none".</summary>
    public IReadOnlyList<SettingChange> Changes(ToolSettings next)
    {
        List<SettingChange> changes = [];
        foreach (string name in Names)
        {
            string old = Text(name);
            string now = next.Text(name);
            if (old != now)
            {
                changes.Add(new SettingChange(name, old, now));
            }
        }

        return changes;
    }

    /// <summary>The value of a setting as text: what the audit log records. No baseUrl is "none".</summary>
    public string Text(string name) => name switch
    {
        "reuseMaxMinutes" => ReuseMaxMinutes.ToString(CultureInfo.InvariantCulture),
        "baseUrl" => BaseUrl ?? "none",
        "port" => Port.ToString(CultureInfo.InvariantCulture),
        "timeoutMinutes" => TimeoutMinutes.ToString(CultureInfo.InvariantCulture),
        _ => throw new ArgumentOutOfRangeException(nameof(name)),
    };

    /// <summary>
    /// The settings in the verified manifest; the defaults for an empty state. A state that cannot be read or fails
    /// verification gives the defaults and an error.
    /// </summary>
    public static ToolSettings Load(StateDatabase db, out string? error)
    {
        if (!db.TryManifest(out Manifest? manifest, out error))
        {
            error = "cannot read the settings: " + error;

            return Defaults;
        }

        return manifest?.Settings ?? Defaults;
    }

    private static bool Int(JsonElement root, string name, out int value)
    {
        value = 0;

        return root.TryGetProperty(name, out JsonElement element) && element.ValueKind == JsonValueKind.Number && element.TryGetInt32(out value);
    }

    /// <summary>
    /// <see cref="Quote" /> for text that may hold control characters (a reason, a command line): the same escapes, and U+0000 to
    /// U+001F as a \u00XX escape, so that the result is always valid JSON. <see cref="Quote" /> itself is unchanged, because the
    /// manifest and the settings are signed over its exact output.
    /// </summary>
    internal static void QuoteJson(StringBuilder text, string value)
    {
        text.Append('"');
        foreach (char c in value)
        {
            if (c is '"' or '\\')
            {
                text.Append('\\').Append(c);
            }
            else if (c < ' ' || c >= '\u007f')
            {
                text.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
            }
            else
            {
                text.Append(c);
            }
        }

        text.Append('"');
    }

    internal static void Quote(StringBuilder text, string value)
    {
        text.Append('"');
        foreach (char c in value)
        {
            if (c is '"' or '\\')
            {
                text.Append('\\').Append(c);
            }
            else if (c >= '\u007f')
            {
                text.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
            }
            else
            {
                text.Append(c);
            }
        }

        text.Append('"');
    }
}

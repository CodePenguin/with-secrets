using System.Globalization;
using System.Text;
using System.Text.Json;

namespace WithSecrets;

/// <summary>One setting that changes: its name and the old and new values as text. None of the settings is secret.</summary>
public sealed record SettingChange(string Name, string Old, string New);

/// <summary>
/// Every setting of the tool, kept in the signed manifest in <see cref="StateDatabase" /> (see <see cref="Manifest" />). An empty
/// state uses the defaults. They change only on the <c>--config</c> page, signed by an admin passkey (see <see cref="SettingsPage" />).
/// A state that fails verification gives the defaults and an error.
/// </summary>
public sealed record ToolSettings(int ReuseMinutes, int ReuseMaxMinutes, string Method, string? BaseUrl, int Port, int TimeoutMinutes)
{
    public const int MinTimeoutMinutes = 1;
    public const int MaxPort = 65535;
    public const int MaxBaseUrlLength = 2048;

    /// <summary>The settings in their fixed order: the order of the canonical JSON, of the page and of the change lists.</summary>
    public static readonly IReadOnlyList<string> Names = ["reuseMinutes", "reuseMaxMinutes", "method", "baseUrl", "port", "timeoutMinutes"];

    public static ToolSettings Defaults { get; } = new(ReuseSettings.DefaultMinutes, ReuseSettings.DefaultMaxMinutes, ApprovalSettings.DefaultMethod, null, 0, ApprovalSettings.DefaultTimeoutMinutes);

    /// <summary>The settings the approval page uses.</summary>
    public ApprovalSettings Approval => new(Method, BaseUrl, Port, TimeSpan.FromMinutes(TimeoutMinutes));

    /// <summary>What the approval page offers besides "Approve once": the steps up to the ceiling, starting on reuseMinutes.</summary>
    public ReuseOffer Reuse => new(ReuseMaxMinutes, ReuseMinutes);

    /// <summary>The limits of a setting, as the page and the README show them.</summary>
    public static string Limits(string name) => name switch
    {
        "reuseMinutes" => $"0 to reuseMaxMinutes (at most {ReuseSettings.MaxMinutes}) minutes. The approval page starts on the longest offered time at or below it; 0 starts with no time chosen.",
        "reuseMaxMinutes" => $"{ReuseSettings.MinMaxMinutes} to {ReuseSettings.MaxMinutes} minutes. No longer reuse is offered or honoured.",
        "method" => $"Only \"{ApprovalSettings.DefaultMethod}\".",
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

        if (ReuseMinutes < 0 || ReuseMinutes > ReuseMaxMinutes)
        {
            return ReuseProblem;
        }

        if (Method != ApprovalSettings.DefaultMethod)
        {
            return $"Setting 'method' must be \"{ApprovalSettings.DefaultMethod}\".";
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

    private static string ReuseProblem => $"Setting 'reuseMinutes' must be a number from 0 to reuseMaxMinutes (at most {ReuseSettings.MaxMinutes}).";

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
    /// The canonical JSON of these values, which the passkey signs on the <c>--config</c> page. It is exactly
    /// <c>{"reuseMinutes":N,"reuseMaxMinutes":N,"method":"S","baseUrl":"S"|null,"port":N,"timeoutMinutes":N}</c>: this key order, no white space,
    /// numbers as plain invariant integers, strings with only <c>"</c> and <c>\</c> escaped (as <c>\"</c> and <c>\\</c>) and
    /// every character from U+007F up written as a lower-case <c>\uXXXX</c> escape (one per UTF-16 unit). Control characters
    /// are never valid in a value. The page builds the same text with <c>JSON.stringify</c> and the same escape step.
    /// </summary>
    public string Canonical()
    {
        StringBuilder text = new();
        text.Append("{\"reuseMinutes\":").Append(ReuseMinutes.ToString(CultureInfo.InvariantCulture));
        text.Append(",\"reuseMaxMinutes\":").Append(ReuseMaxMinutes.ToString(CultureInfo.InvariantCulture));
        text.Append(",\"method\":");
        Quote(text, Method);
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
                || !Int(root, "reuseMinutes", out int reuse) || !Int(root, "reuseMaxMinutes", out int reuseMax) || !Int(root, "port", out int port) || !Int(root, "timeoutMinutes", out int timeout)
                || !root.TryGetProperty("method", out JsonElement method) || method.ValueKind != JsonValueKind.String
                || !root.TryGetProperty("baseUrl", out JsonElement url) || url.ValueKind is not (JsonValueKind.String or JsonValueKind.Null))
            {
                error = "the settings are not the six settings with values of the right type";

                return null;
            }

            ToolSettings settings = new(reuse, reuseMax, method.GetString()!, url.ValueKind == JsonValueKind.Null ? null : url.GetString(), port, timeout);
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

    /// <summary>The value of a setting as text: what <c>--config --show</c> prints and the audit log records. No baseUrl is "none".</summary>
    public string Text(string name) => name switch
    {
        "reuseMinutes" => ReuseMinutes.ToString(CultureInfo.InvariantCulture),
        "reuseMaxMinutes" => ReuseMaxMinutes.ToString(CultureInfo.InvariantCulture),
        "method" => Method,
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

/// <summary><c>--config --show</c>: prints every setting and its value, one per line, tab-separated. Nothing in it is secret.</summary>
public static class ConfigShow
{
    public static int Run(StateDatabase db, TextWriter stdout, TextWriter stderr)
    {
        ToolSettings settings = ToolSettings.Load(db, out string? error);
        if (error is not null)
        {
            stderr.WriteLine("with-secrets: settings: " + error);

            return RunCommand.StoreError;
        }

        foreach (string name in ToolSettings.Names)
        {
            stdout.WriteLine(name + "\t" + ApprovalSummary.Clean(settings.Text(name)));
        }

        return 0;
    }
}

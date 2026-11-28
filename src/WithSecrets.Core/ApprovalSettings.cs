using System.Globalization;

namespace WithSecrets;

/// <summary>How approval works. Only the approval settings are read here; they are kept in with-secrets.db (see <see cref="ToolSettings" />).</summary>
public sealed record ApprovalSettings(string? BaseUrl, int Port, TimeSpan Timeout)
{
    public const int DefaultTimeoutMinutes = 15;
    public const int MaxTimeoutMinutes = 30;

    /// <summary>The approval settings in with-secrets.db. Settings that cannot be used: defaults and a short error that names the setting.</summary>
    public static ApprovalSettings Load(StateDatabase db, out string? error)
    {
        return ToolSettings.Load(db, out error).Approval;
    }

    /// <summary>
    /// The same settings with the page listening on <paramref name="port" /> (the --port option) instead of the setting. Null keeps
    /// the setting. Nothing is stored: the manifest still holds the setting.
    /// </summary>
    public ApprovalSettings WithPort(int? port) => port is { } value ? this with { Port = value } : this;

    /// <summary>
    /// The origin the page is served from: the scheme, host and non-default port of baseUrl, or localhost on the bound port.
    /// Built from its parts so that a user name or password in baseUrl never reaches the origin.
    /// </summary>
    public string PageOrigin(int boundPort)
    {
        if (BaseUrl == "https://" + BrowserAddress.Host)
        {
            return BrowserAddress.Origin(boundPort);
        }

        if (BaseUrl is not null && Uri.TryCreate(BaseUrl, UriKind.Absolute, out Uri? uri))
        {
            string host = uri.HostNameType == UriHostNameType.IPv6 ? uri.Host : uri.IdnHost;
            return uri.Scheme + "://" + host + (uri.IsDefaultPort ? "" : ":" + uri.Port.ToString(CultureInfo.InvariantCulture));
        }

        return $"http://localhost:{boundPort}";
    }
}

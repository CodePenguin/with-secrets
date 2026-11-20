using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;

namespace WithSecrets;

/// <summary>
/// Where a host service finds its ONE remote authority and which identity it must have (architecture 10.2): the endpoint address (routing information only) and, separately, the authority's identity
/// certificate, which is the only thing a connection is validated against. Changing the address changes no trust; changing the identity is a deliberate act (pairing). Public data only.
/// </summary>
/// <param name="Endpoint">An absolute <c>https://host:port</c> address with no user, path, query or fragment.</param>
/// <param name="AuthorityIdentityFingerprint">The authority's machine identity fingerprint (SHA-256 of its public key), 64 upper-case hex digits.</param>
/// <param name="AuthorityIdentityCertificate">The authority's self-signed identity certificate (DER, public).</param>
public sealed record RemoteAuthorityConfig(string Endpoint, string AuthorityIdentityFingerprint, byte[] AuthorityIdentityCertificate);

/// <summary>What a configured remote authority must look like.</summary>
public static class RemoteTarget
{
    /// <summary>Null when the setting is usable (the certificate is a readable one with exactly this fingerprint; its profile and dates are checked when a connection is made), else why not (no value in it).</summary>
    public static string? Problem(RemoteAuthorityConfig config)
    {
        if (Address(config.Endpoint, out _) is { } address)
        {
            return address;
        }

        if (KeyIdentity.ParseHex(config.AuthorityIdentityFingerprint, true) != config.AuthorityIdentityFingerprint)
        {
            return "the authority identity fingerprint must be 64 upper-case hex digits";
        }

        return string.Equals(MachineCertificates.FingerprintOf(config.AuthorityIdentityCertificate), config.AuthorityIdentityFingerprint, StringComparison.Ordinal) ? null : "the authority identity certificate is not the one the fingerprint names";
    }

    /// <summary>Parses an endpoint address. Null result with a problem otherwise. The address is where to connect, never who the authority is.</summary>
    public static string? Address(string url, out Uri? endpoint)
    {
        endpoint = null;
        if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? parsed) || parsed.UserInfo.Length > 0 || parsed.Query.Length > 0 || parsed.Fragment.Length > 0 || parsed.AbsolutePath != "/")
        {
            return "the authority endpoint must be an absolute https address with no user, path, query or fragment";
        }

        if (parsed.Scheme != "https")
        {
            return "the authority endpoint must be an https address: machine communication is always TLS 1.3";
        }

        endpoint = parsed;

        return null;
    }

    public static bool IsLoopback(Uri uri) => uri.IsLoopback || string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase) || IPAddress.TryParse(uri.Host.Trim('[', ']'), out IPAddress? address) && IPAddress.IsLoopback(address);
}

/// <summary>
/// A description of why a connection to the authority failed that is safe to show and log: the chain of exception TYPES, the socket or HTTP error code, the HRESULT, and for the platform's own TLS, socket and
/// I/O exceptions their message (the text the TLS stack writes, such as which handshake step failed; it holds no key, token or secret, and nothing this program put in it). Never a request or a response.
/// </summary>
public static class TransportFailure
{
    public static string Describe(Exception error)
    {
        StringBuilder text = new();
        int depth = 0;
        for (Exception? current = error; current is not null && depth < 6; current = current.InnerException, depth++)
        {
            if (depth > 0)
            {
                text.Append(" <- ");
            }

            text.Append(current.GetType().Name);
            switch (current)
            {
                case SocketException socket:
                    text.Append(" [").Append(socket.SocketErrorCode).Append(']');
                    break;
                case HttpRequestException http:
                    text.Append(" [").Append(http.HttpRequestError).Append(']');
                    break;
            }

            if (current.HResult != 0)
            {
                text.Append(" (0x").Append(current.HResult.ToString("X8", CultureInfo.InvariantCulture)).Append(')');
            }

            if (current is AuthenticationException or SocketException or IOException or PlatformNotSupportedException)
            {
                text.Append(": ").Append(current.Message.ReplaceLineEndings(" "));
            }
        }

        return text.ToString();
    }
}

/// <summary>
/// What the platform's TLS stack can do for machine-to-machine transport, which is TLS 1.3 only (never weaker). On macOS .NET's server-side <c>SslStream</c> has no TLS 1.3 at all, so a macOS machine cannot be an
/// authority (it cannot serve the machine listener); its client side can speak TLS 1.3 only with the opt-in Network.framework backend, which is switched on here before the first connection, so a macOS machine can be a host.
/// </summary>
public static class PlatformTls
{
    /// <summary>The AppContext switch that makes the client side of <c>SslStream</c> on macOS use the TLS 1.3 capable backend (.NET 10; the server side is not affected).</summary>
    private const string NetworkFrameworkSwitch = "System.Net.Security.UseNetworkFramework";

    /// <summary>Called before the first machine connection is made (idempotent): on macOS it switches on the TLS 1.3 capable client backend.</summary>
    public static void EnableClientTls13()
    {
        if (OperatingSystem.IsMacOS())
        {
            AppContext.SetSwitch(NetworkFrameworkSwitch, true);
        }
    }

    /// <summary>Why this machine cannot serve the machine listener (the authority role), or null when it can.</summary>
    public static string? ListenerUnsupported => OperatingSystem.IsMacOS()
        ? "this machine cannot be an authority: the machine listener needs TLS 1.3 on the server side, which .NET does not provide on macOS. Run the authority on Windows or Linux; this machine can still be a host (pair it with an authority elsewhere)"
        : null;
}

using System.Net;
using System.Net.Security;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace WithSecrets;

/// <summary>Where a relay is, and what a configured remote authority must look like. Plain http and ws are for a loopback relay only; anything else must be https or wss.</summary>
public static partial class RemoteTarget
{
    [GeneratedRegex("^[A-Za-z0-9_-]{1,128}\\z", RegexOptions.CultureInvariant)]
    private static partial Regex RegistrationPattern();

    public static bool IsRegistrationId(string text) => RegistrationPattern().IsMatch(text);

    /// <summary>Null when the setting is usable, else why not (no value in it).</summary>
    public static string? Problem(RemoteAuthorityConfig config)
    {
        if (!IsRegistrationId(config.RegistrationId))
        {
            return "the registration id must be 1 to 128 of letters, digits, '_' and '-'";
        }

        if (KeyIdentity.ParseHex(config.AuthorityFingerprint, true) is null)
        {
            return "the authority key fingerprint must be 64 hex digits";
        }

        if (config.TlsPin.Length > 0 && KeyIdentity.ParseHex(config.TlsPin, true) is null)
        {
            return "the TLS certificate pin must be empty or 64 hex digits";
        }

        return Base(config.RelayUrl, out _);
    }

    /// <summary>Resolves the relay URL to its WebSocket base (ws or wss). Null result with a problem otherwise.</summary>
    public static string? Base(string url, out Uri? relay)
    {
        relay = null;
        if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? parsed) || parsed.UserInfo.Length > 0 || parsed.Query.Length > 0 || parsed.Fragment.Length > 0 || parsed.AbsolutePath != "/")
        {
            return "the relay URL must be an absolute http, https, ws or wss address with no user, path, query or fragment";
        }

        bool secure = parsed.Scheme is "https" or "wss";
        if (!secure && parsed.Scheme is not ("http" or "ws"))
        {
            return "the relay URL must start with http, https, ws or wss";
        }

        if (!secure && !IsLoopback(parsed))
        {
            return "a relay beyond this machine must be reached over https (or wss): plain http is for a loopback relay only";
        }

        relay = new UriBuilder(parsed) { Scheme = secure ? "wss" : "ws" }.Uri;

        return null;
    }

    public static bool IsLoopback(Uri uri) => uri.IsLoopback || string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase) || IPAddress.TryParse(uri.Host.Trim('[', ']'), out IPAddress? address) && IPAddress.IsLoopback(address);

    public static Uri Endpoint(Uri relayBase, string path, string registration) => new(relayBase, path + "?registration=" + Uri.EscapeDataString(registration));
}

/// <summary>The certificate rule of a connection to a relay beyond this machine: the system's validation is never weakened; an optional pin can only narrow it further.</summary>
public static class RelayTls
{
    /// <summary>True only when the system found no problem with the certificate chain and name and, if a pin is set, the certificate's SHA-256 is the pinned value.</summary>
    public static bool Accept(X509Certificate? certificate, SslPolicyErrors errors, string pin)
    {
        if (certificate is null || errors != SslPolicyErrors.None)
        {
            return false;
        }

        return pin.Length == 0 || string.Equals(Convert.ToHexString(SHA256.HashData(certificate.GetRawCertData())), KeyIdentity.ParseHex(pin, true), StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>A connection that carries whole messages. The relay and the tests provide them.</summary>
internal interface IMessageChannel : IDisposable
{
    Task SendAsync(byte[] message, CancellationToken cancel);

    /// <summary>The next message, or null when the other side closed.</summary>
    Task<byte[]?> ReceiveAsync(CancellationToken cancel);
}

internal sealed class WebSocketChannel(WebSocket socket, int maxMessage = 8 * 1024 * 1024) : IMessageChannel
{
    private readonly RelaySocket _socket = new(socket, maxMessage);

    public Task SendAsync(byte[] message, CancellationToken cancel) => _socket.SendAsync(message, cancel);

    public Task<byte[]?> ReceiveAsync(CancellationToken cancel) => _socket.ReceiveAsync(cancel);

    public void Dispose()
    {
        _socket.Abort();
        socket.Dispose();
    }

    /// <summary>Connects out to the relay as the host or the authority (<paramref name="path" />). Certificate validation is the system's; the optional pin only narrows it.</summary>
    public static async Task<WebSocketChannel> ConnectAsync(RemoteAuthorityConfig config, string path, CancellationToken cancel)
    {
        if (RemoteTarget.Problem(config) is { } problem)
        {
            throw new InvalidOperationException(problem);
        }

        RemoteTarget.Base(config.RelayUrl, out Uri? relay);
        ClientWebSocket client = new();
        try
        {
            client.Options.KeepAliveInterval = TimeSpan.FromSeconds(20);
            if (RemoteTarget.IsLoopback(relay!))
            {
                client.Options.Proxy = null;
            }

            if (config.TlsPin.Length > 0)
            {
                string pin = config.TlsPin;
                client.Options.RemoteCertificateValidationCallback = (_, certificate, _, errors) => RelayTls.Accept(certificate, errors, pin);
            }

            using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(cancel);
            limit.CancelAfter(TimeSpan.FromSeconds(15));
            await client.ConnectAsync(RemoteTarget.Endpoint(relay!, path, config.RegistrationId), limit.Token);

            return new WebSocketChannel(client);
        }
        catch
        {
            client.Dispose();

            throw;
        }
    }
}

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace ArcanaGuardian.LastPass;

/// <summary>Performs a single in-memory LastPass login and read for an interactive refresh.</summary>
public static class LastPassRefreshReader
{
    // The version LastPass expects for its binary vault protocol.
    private const string VaultProtocolVersion = "1.6.2";
    private static readonly TimeSpan ReadTimeout = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan LogoutTimeout = TimeSpan.FromSeconds(5);

    /// <summary>Takes ownership of the UTF-8 password buffer and clears it even if the refresh fails.</summary>
    public static async Task<SecretValues> ReadAsync(
        string username, bool european, byte[] masterPassword, IReadOnlyCollection<string> paths, CancellationToken cancel)
    {
        using HttpClient client = new(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
        });
        return await ReadAsync(client, username, european, masterPassword, paths, cancel).ConfigureAwait(false);
    }

    internal static async Task<SecretValues> ReadAsync(
        HttpClient client, string username, bool european, byte[] masterPassword, IReadOnlyCollection<string> paths, CancellationToken cancel)
    {
        using CancellationTokenSource deadline = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        deadline.CancelAfter(ReadTimeout);
        string host = european ? "lastpass.eu" : "lastpass.com";
        byte[] vaultKey = new byte[32];
        byte[] proof = new byte[32];
        Session? session = null;
        SecretValues? values = null;
        bool closed = false;
        try
        {
            LastPassRefreshSelection selection = new(paths);
            if (!LastPassRefreshSelection.IsAccount(username) || masterPassword.Length is < 1 or > 4096
                || !ProviderBatch.IsStrictUtf8(masterPassword) || masterPassword.AsSpan().Contains((byte)0))
                throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "Enter a valid LastPass account and master password.");

            username = username.ToLowerInvariant();
            int iterations = await GetIterationsAsync(client, host, username, deadline.Token).ConfigureAwait(false);
            deadline.Token.ThrowIfCancellationRequested();
            Rfc2898DeriveBytes.Pbkdf2(masterPassword, Encoding.UTF8.GetBytes(username), vaultKey, iterations, HashAlgorithmName.SHA256);
            Rfc2898DeriveBytes.Pbkdf2(vaultKey, masterPassword, proof, 1, HashAlgorithmName.SHA256);
            CryptographicOperations.ZeroMemory(masterPassword);

            session = await LoginAsync(client, host, username, proof, iterations, deadline.Token).ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(proof);
            if (session.LogoutToken is null || !session.HasAccount) throw InvalidResponse();
            using HttpResponseMessage vault = await PostAsync(client, host, "getaccts.php",
                new() { ["mobile"] = "1", ["requestsrc"] = "cli", ["hasplugin"] = VaultProtocolVersion }, session.Id, deadline.Token).ConfigureAwait(false);
            using Stream contents = await vault.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
            values = await LastPassVaultReader.ReadAsync(contents, vaultKey, selection, deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancel.IsCancellationRequested)
        {
            throw new ProviderAdapterException(ProviderErrorKind.Unavailable, "The LastPass refresh timed out.");
        }
        catch (Exception error) when (error is HttpRequestException or IOException)
        {
            throw new ProviderAdapterException(ProviderErrorKind.Unavailable, "Could not complete the connection to LastPass.");
        }
        catch (Exception error) when (error is XmlException or CryptographicException)
        {
            throw InvalidResponse();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterPassword);
            CryptographicOperations.ZeroMemory(vaultKey);
            CryptographicOperations.ZeroMemory(proof);
            if (session is not null)
                closed = await CloseSessionAsync(client, host, session).ConfigureAwait(false);
            if (!closed || cancel.IsCancellationRequested)
                values?.Dispose();
        }

        if (cancel.IsCancellationRequested)
        {
            values?.Dispose();
            cancel.ThrowIfCancellationRequested();
        }
        if (!closed)
            throw new ProviderAdapterException(ProviderErrorKind.Unavailable, "LastPass could not confirm that the refresh session closed.");
        return values!;
    }

    private static async Task<int> GetIterationsAsync(HttpClient client, string host, string username, CancellationToken cancel)
    {
        using HttpResponseMessage response = await PostAsync(client, host, "iterations.php",
            new() { ["email"] = username }, null, cancel).ConfigureAwait(false);
        byte[] buffer = new byte[65];
        using Stream input = await response.Content.ReadAsStreamAsync(cancel).ConfigureAwait(false);
        int count = await input.ReadAtLeastAsync(buffer, buffer.Length, false, cancel).ConfigureAwait(false);
        if (count == buffer.Length || !int.TryParse(buffer.AsSpan(0, count), NumberStyles.Integer,
            CultureInfo.InvariantCulture, out int iterations) || iterations is < 2 or > 10_000_000)
            throw InvalidResponse();
        return iterations;
    }

    private static async Task<Session> LoginAsync(HttpClient client, string host, string username, byte[] proof, int iterations, CancellationToken cancel)
    {
        using HttpResponseMessage login = await PostAsync(client, host, "login.php", new()
        {
            ["xml"] = "2", ["username"] = username, ["hash"] = Convert.ToHexStringLower(proof),
            ["iterations"] = iterations.ToString(CultureInfo.InvariantCulture), ["method"] = "cli", ["outofbandsupported"] = "1",
        }, null, cancel).ConfigureAwait(false);
        XElement answer = await ReadXmlAsync(login, cancel).ConfigureAwait(false);
        XElement? ok = answer.Name == "ok" ? answer : answer.Name == "response" ? answer.Element("ok") : null;
        if (ok is null)
        {
            XElement? error = answer.Name == "error" ? answer : answer.Name == "response" ? answer.Element("error") : null;
            if (error is null) throw InvalidResponse();
            if (host == "lastpass.com" && (string?)error.Attribute("server") == "lastpass.eu")
                throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "Verify the account region and choose LastPass Europe before retrying.");
            if ((string?)error.Attribute("cause") is "outofbandrequired" or "googleauthrequired" or "otprequired"
                or "sesameotprequired" or "microsoftauthrequired" or "yubikeyrestricted" or "duorequired")
                throw new ProviderAdapterException(ProviderErrorKind.InteractionRequired, "LastPass requires an additional verification step that this refresh cannot complete.");
            throw new ProviderAdapterException(ProviderErrorKind.AuthenticationFailed, "LastPass declined the sign-in.");
        }

        string? id = (string?)ok.Attribute("sessionid");
        string? token = (string?)ok.Attribute("token");
        if (id is not { Length: > 0 and <= 512 }
            || id.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not ('-' or '_' or '.')))
            throw InvalidResponse();
        return new Session(id, token is { Length: > 0 and <= 1024 } ? token : null,
            (string?)ok.Attribute("uid") is { Length: > 0 and <= 512 });
    }

    private static async Task<bool> CloseSessionAsync(HttpClient client, string host, Session session)
    {
        using CancellationTokenSource deadline = new(LogoutTimeout);
        try
        {
            using (await PostAsync(client, host, "logout.php",
                new() { ["method"] = "cli", ["noredirect"] = "1", ["token"] = session.LogoutToken ?? "" },
                session.Id, deadline.Token, acceptError: true).ConfigureAwait(false))
            {
                // LastPass may return a redirect after ending the session. Verify directly on the same host.
            }
            using HttpResponseMessage response = await PostAsync(client, host, "login_check.php",
                new() { ["method"] = "cli" }, session.Id, deadline.Token).ConfigureAwait(false);
            XElement answer = await ReadXmlAsync(response, deadline.Token).ConfigureAwait(false);
            return answer.Name == "response" && answer.Element("ok") is null
                && (string?)answer.Element("error")?.Attribute("from") == "session is not live";
        }
        catch (Exception error) when (error is HttpRequestException or OperationCanceledException or IOException
            or XmlException or ProviderAdapterException)
        {
            return false;
        }
    }

    private static async Task<HttpResponseMessage> PostAsync(HttpClient client, string host, string path, Dictionary<string, string> fields,
        string? session, CancellationToken cancel, bool acceptError = false)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, $"https://{host}/{path}") { Content = new FormUrlEncodedContent(fields) };
        request.Headers.UserAgent.ParseAdd($"LastPass-CLI/{VaultProtocolVersion}");
        if (session is not null) request.Headers.Add("Cookie", "PHPSESSID=" + session);
        HttpResponseMessage response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancel).ConfigureAwait(false);
        if (!acceptError && !response.IsSuccessStatusCode)
        {
            response.Dispose();
            throw new ProviderAdapterException(ProviderErrorKind.Unavailable, "LastPass rejected a refresh request.");
        }
        return response;
    }

    private static async Task<XElement> ReadXmlAsync(HttpResponseMessage response, CancellationToken cancel)
    {
        using Stream input = await response.Content.ReadAsStreamAsync(cancel).ConfigureAwait(false);
        byte[] bytes = new byte[64 * 1024 + 1];
        try
        {
            int count = await input.ReadAtLeastAsync(bytes, bytes.Length, false, cancel).ConfigureAwait(false);
            if (count == bytes.Length) throw InvalidResponse();
            using MemoryStream content = new(bytes, 0, count, writable: false);
            using XmlReader reader = XmlReader.Create(content,
                new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
            return XDocument.Load(reader).Root ?? throw InvalidResponse();
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static ProviderAdapterException InvalidResponse()
        => new(ProviderErrorKind.InvalidResponse, "The LastPass control response could not be read safely.");

    private sealed record Session(string Id, string? LogoutToken, bool HasAccount);
}

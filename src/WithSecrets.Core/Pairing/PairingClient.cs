using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace WithSecrets;

/// <summary>Where a machine's pairing bundle comes from, in the order of preference. The code is never taken from a command-line argument and never from a URL.</summary>
public enum PairingSource
{
    /// <summary>A hidden interactive prompt.</summary>
    Prompt,

    /// <summary>A protected secret file (<c>WITH_SECRETS_PAIRING_FILE</c>, or the Docker secret <c>/run/secrets/with-secrets-pairing</c>).</summary>
    File,

    /// <summary>An environment variable (<c>WITH_SECRETS_PAIRING</c>): works, but a secret file is preferred because an environment is inherited and visible to more than a file is.</summary>
    Environment,
}

/// <summary>The console seam of the pairing command: a hidden read (nothing is echoed) and whether a person is there.</summary>
public interface IPairingConsole
{
    bool IsInteractive { get; }

    /// <summary>Shows <paramref name="prompt" /> and reads a line without echoing it. Null at the end of input.</summary>
    string? ReadHidden(string prompt);

    /// <summary>
    /// Asks a person at this terminal a question that only a person may answer (a deliberate, typed word). False when nobody is there: an unattended run (a file or variable supplied the invitation) can never confirm.
    /// </summary>
    bool Confirm(string question, string word);
}

/// <summary>The real terminal: characters are read without being shown (<c>Console.ReadKey(intercept: true)</c>).</summary>
public sealed class TerminalPairingConsole : IPairingConsole
{
    public bool IsInteractive => !Console.IsInputRedirected && !Console.IsOutputRedirected && !Console.IsErrorRedirected;

    public bool Confirm(string question, string word)
    {
        if (!IsInteractive)
        {
            return false;
        }

        Console.Error.WriteLine(question);
        Console.Error.Write("Type " + word + " and press Enter to confirm, anything else to stop: ");
        string? answer = Console.In.ReadLine();

        return string.Equals(answer?.Trim(), word, StringComparison.Ordinal);
    }

    public string? ReadHidden(string prompt)
    {
        Console.Error.Write(prompt);
        StringBuilder text = new();
        while (true)
        {
            ConsoleKeyInfo key = Console.ReadKey(true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.Error.WriteLine();

                return text.ToString();
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (text.Length > 0)
                {
                    text.Length--;
                }
            }
            else if (!char.IsControl(key.KeyChar))
            {
                text.Append(key.KeyChar);
            }
        }
    }
}

/// <summary>Finds the invitation bundle for the pairing command: a protected secret file first, then the environment variable, then (when a person is at a terminal) a hidden prompt.</summary>
public static class PairingInput
{
    /// <summary>The environment variable that names a file holding the bundle (a Docker secret or any protected file).</summary>
    public const string FileVariable = "WITH_SECRETS_PAIRING_FILE";

    /// <summary>The environment variable that holds the bundle itself (the weaker unattended form).</summary>
    public const string ValueVariable = "WITH_SECRETS_PAIRING";

    /// <summary>The Docker secret convention: a secret named <c>with-secrets-pairing</c> is mounted here.</summary>
    public const string DockerSecretPath = "/run/secrets/with-secrets-pairing";

    /// <summary>The names of the variables the pairing command reads. They are scrubbed from every environment passed on to a program.</summary>
    public static bool IsPairingVariable(string name) => name.StartsWith("WITH_SECRETS_PAIRING", StringComparison.OrdinalIgnoreCase);

    public sealed record Found(PairingBundle? Bundle, PairingSource Source, string? Problem);

    /// <summary>
    /// Gets the bundle. Nothing about the input is ever put in the problem text. A file that is named but cannot be read, or an input that is not a bundle, is an error: there is no fallback to a weaker source behind
    /// the person's back.
    /// </summary>
    public static Found Obtain(IPairingConsole console, Func<string, string?> environment, Func<string, string?> readFile, Func<string, bool> fileExists)
    {
        if (environment(FileVariable) is { Length: > 0 } path)
        {
            return FromFile(path, readFile);
        }

        if (fileExists(DockerSecretPath))
        {
            return FromFile(DockerSecretPath, readFile);
        }

        if (environment(ValueVariable) is { Length: > 0 } value)
        {
            return PairingBundle.TryParse(value) is { } bundle ? new Found(bundle, PairingSource.Environment, null) : new Found(null, PairingSource.Environment, ValueVariable + " does not hold a pairing invitation (create a new one in the authority's admin web app)");
        }

        if (!console.IsInteractive)
        {
            return new Found(null, PairingSource.Prompt, "no pairing invitation was supplied and there is no terminal to ask on. Give it in a secret file (" + FileVariable + " or the Docker secret with-secrets-pairing) or in " + ValueVariable);
        }

        string? typed = console.ReadHidden("Paste the pairing invitation (nothing is shown as you type) and press Enter: ");

        return PairingBundle.TryParse(typed) is { } entered ? new Found(entered, PairingSource.Prompt, null) : new Found(null, PairingSource.Prompt, "that is not a pairing invitation (create a new one in the authority's admin web app)");
    }

    private static Found FromFile(string path, Func<string, string?> readFile)
    {
        string? text;
        try
        {
            text = readFile(path);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return new Found(null, PairingSource.File, "the pairing invitation file cannot be read");
        }

        return PairingBundle.TryParse(text) is { } bundle ? new Found(bundle, PairingSource.File, null) : new Found(null, PairingSource.File, "the pairing invitation file does not hold a pairing invitation (create a new one in the authority's admin web app)");
    }
}

/// <summary>What the pairing client did, for the command's one summary line and for tests. Public data only: never the code, a proof or a key.</summary>
public sealed record PairingResult(bool Ok, string Message, string MachineFingerprint, string HostName, string AuthorityFingerprint);

/// <summary>Everything the pairing client needs. The machine's key and certificate are the persistent identity; the caller owns and disposes them.</summary>
public sealed class PairingClientOptions
{
    public required PairingBundle Bundle { get; init; }

    public required ISigningKey MachineKey { get; init; }

    public required byte[] IdentityCertificate { get; init; }

    public required string HostName { get; init; }

    public required HostConfigFile HostConfig { get; init; }

    public TimeProvider Clock { get; init; } = TimeProvider.System;

    /// <summary>For tests: told of every request just before it is sent (the step, the body and the fingerprint of the identity the TLS client certificate carries).</summary>
    public Action<string, byte[], string>? OnRequest { get; init; }

    /// <summary>For tests: how often a registration that failed in transport is sent again (same body).</summary>
    public int Retries { get; init; } = 2;

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>For tests: the machine's own TLS certificate (default: a new one made from the identity key for this run).</summary>
    public TemporaryCertificate? MachineTls { get; init; }

    /// <summary>
    /// Asked (with a description of the two identities) when this machine already trusts another authority identity (a different remote authority, or a signing key pinned in local mode) and the invitation proves a different one. Null or false
    /// refuses and changes nothing: replacing the authority this machine trusts is a deliberate act a person confirms at a terminal.
    /// </summary>
    public Func<string, bool>? ConfirmReplaceAuthority { get; init; }

    /// <summary>Told (event name, detail; public data only) when the person confirmed replacing the authority, before host.json is changed. The command writes it to the durable audit.</summary>
    public Action<string, string>? Audit { get; init; }
}

/// <summary>
/// The new machine's side of pairing (architecture 10.2). Two connections, both TLS 1.3 and HTTP/2 to the pairing route only:
/// <list type="number">
/// <item>Bootstrap. The TLS client certificate is a THROWAWAY identity made for this one connection, so the machine's real identity is not shown to a party that has not been proven yet. The body is the invitation id and a fresh
/// nonce and nothing else. The authority's TLS certificate is accepted provisionally (structure only); what it sends back is trusted only after (a) its identity certificate has the profile, (b) the TLS certificate it showed was
/// signed by that identity, (c) the identity's fingerprint is the one in that TLS certificate and (d) the HMAC-SHA-256 proof, keyed by what the pairing code derives, verifies over the invitation, that fingerprint and both nonces.</item>
/// <item>Registration, only after all of that. A NEW connection, validated against exactly the authority identity certificate just proven, with this machine's real temporary certificate. It sends the identity certificate, fingerprint,
/// host name, a fresh nonce, the signature that proves possession of the persistent key and the registration HMAC. A lost answer is repeated with the identical body (the authority answers a committed request again).</item>
/// </list>
/// The code is only key material here: it is never sent, never in a URL, and nothing this class returns or throws contains it. After success <c>host.json</c> records the authority's address and identity certificate; the authority's
/// signing key is pinned later, through the administrator's approval (the authority-key operation).
/// </summary>
public static class PairingClient
{
    private const int MaxResponseBytes = 64 * 1024;

    public static async Task<PairingResult> RunAsync(PairingClientOptions options, CancellationToken cancel = default)
    {
        string machineFingerprint = KeyIdentity.Fingerprint(options.MachineKey.PublicKey);
        PairingResult Fail(string message, string authority = "") => new(false, message, machineFingerprint, options.HostName, authority);
        if (WireText.HostNameProblem(options.HostName) is { } hostProblem)
        {
            return Fail("this machine's host name cannot be used: " + hostProblem);
        }

        byte[] key = options.Bundle.DeriveKey();
        try
        {
            // 1. Bootstrap: only the invitation id and a nonce, on a connection that carries a throwaway identity.
            byte[] clientNonce = RandomNumberGenerator.GetBytes(PairingProtocol.NonceBytes);
            BootstrapOutcome bootstrap;
            using (SoftwareSigningKey throwaway = new())
            {
                byte[] throwawayIdentity = MachineCertificates.CreateIdentity(throwaway, options.Clock.GetUtcNow());
                using TemporaryCertificate throwawayTls = new(throwaway, throwawayIdentity, options.Clock);
                bootstrap = await BootstrapAsync(options, throwawayTls, clientNonce, cancel);
            }

            if (bootstrap.Reply is null)
            {
                return Fail(bootstrap.Problem);
            }

            // 2. Verify the authority BEFORE anything about this machine is sent.
            if (Verify(options, key, clientNonce, bootstrap) is { } unproven)
            {
                return Fail(unproven);
            }

            string authorityFingerprint = MachineCertificates.FingerprintOf(bootstrap.Reply.AuthorityCertificate)!;
            byte[] authorityCertificate = bootstrap.Reply.AuthorityCertificate;

            // 2b. The authority is proven. If this machine already trusts a DIFFERENT authority identity, changing it is explicit: a person confirms at a terminal, or nothing is sent and nothing changes (the same identity keeps its pin).
            HostConfig? existing = options.HostConfig.Load().Config;
            string? existingIdentity = existing?.Remote?.AuthorityIdentityFingerprint;
            bool pinned = existing?.Authority is not null;
            bool replacing = existingIdentity is not null ? existingIdentity != authorityFingerprint : pinned;
            if (replacing)
            {
                string question = "This machine already trusts " + (existingIdentity is not null ? "the authority " + KeyIdentity.Display(existingIdentity) : "an authority signing key (" + KeyIdentity.Display(existing!.Authority!.Fingerprint) + ", pinned in local mode)")
                    + ". This invitation is from the authority " + KeyIdentity.Display(authorityFingerprint) + ". Pairing replaces the trusted authority and drops the pinned authority signing key; the new authority must then approve this machine.";
                if (options.ConfirmReplaceAuthority?.Invoke(question) != true)
                {
                    return Fail("this machine already trusts " + (existingIdentity is not null ? "another authority (" + KeyIdentity.Display(existingIdentity) + ")" : "an authority signing key") + " and this invitation is from a different one (" + KeyIdentity.Display(authorityFingerprint)
                        + "). Nothing was sent and nothing was changed. To replace it deliberately run with-secrets pair again at a terminal and confirm when asked", authorityFingerprint);
                }

                options.Audit?.Invoke("pairing-authority-replaced", "the person confirmed replacing the trusted authority " + (existingIdentity is null ? "(a pinned signing key)" : KeyIdentity.Display(existingIdentity)) + " by " + KeyIdentity.Display(authorityFingerprint));
            }

            // 3. Registration on a fresh connection pinned to the proven authority identity.
            byte[] nonce = RandomNumberGenerator.GetBytes(PairingProtocol.NonceBytes);
            PairingRegistrationRequest registration = new(options.Bundle.InvitationId, options.IdentityCertificate, machineFingerprint, options.HostName, nonce,
                options.MachineKey.Sign(PairingProtocol.PossessionMessage(options.Bundle.InvitationId, authorityFingerprint, machineFingerprint, options.HostName, nonce)),
                PairingProtocol.RegistrationProof(key, options.Bundle.InvitationId, authorityFingerprint, machineFingerprint, options.HostName, nonce));
            using TemporaryCertificate? owned = options.MachineTls is null ? new TemporaryCertificate(options.MachineKey, options.IdentityCertificate, options.Clock) : null;
            TemporaryCertificate machineTls = options.MachineTls ?? owned!;
            (string? problem, PairingRegistrationReply? reply) = await RegisterAsync(options, machineTls, authorityCertificate, authorityFingerprint, registration, cancel);
            if (reply is null)
            {
                return Fail(problem ?? "the authority did not accept the registration", authorityFingerprint);
            }

            if (reply.MachineFingerprint != machineFingerprint || reply.Status != "Pending")
            {
                return Fail("the authority answered with something other than this machine's Pending registration; nothing was saved", authorityFingerprint);
            }

            // 4. Remember the authority: where it is and which identity it must have. The signing key is pinned when an administrator approves this machine.
            options.HostConfig.SetRemote(machineFingerprint, new RemoteAuthorityConfig(options.Bundle.Authority, authorityFingerprint, authorityCertificate), dropPin: replacing);

            return new PairingResult(true, "registered; waiting for an administrator to approve this machine", machineFingerprint, options.HostName, authorityFingerprint);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    // ---- bootstrap ----

    private sealed record BootstrapOutcome(PairingBootstrapReply? Reply, string Problem, byte[]? TlsLeaf, string? TlsFingerprint, string? AuthorityFingerprint);

    private static string? Verify(PairingClientOptions options, byte[] key, byte[] clientNonce, BootstrapOutcome bootstrap)
    {
        const string Unproven = "the authority could not prove that it holds this invitation, so nothing about this machine was sent. Check the address, create a new invitation and try again";
        PairingBootstrapReply reply = bootstrap.Reply!;
        DateTimeOffset now = options.Clock.GetUtcNow();
        if (MachineCertificates.ValidateIdentity(reply.AuthorityCertificate, now) is not null || MachineCertificates.FingerprintOf(reply.AuthorityCertificate) is not { } fingerprint || bootstrap.TlsLeaf is null || fingerprint != bootstrap.TlsFingerprint)
        {
            return Unproven;
        }

        // The TLS certificate this very connection showed must belong to the identity that is being proven.
        try
        {
            using X509Certificate2 leaf = X509CertificateLoader.LoadCertificate(bootstrap.TlsLeaf);
            if (MachineCertificates.ValidateLeaf(leaf, reply.AuthorityCertificate, now, fingerprint) is not null)
            {
                return Unproven;
            }
        }
        catch (CryptographicException)
        {
            return Unproven;
        }

        byte[] expected = PairingProtocol.BootstrapProof(key, options.Bundle.InvitationId, fingerprint, clientNonce, reply.ServerNonce);

        return PairingProtocol.Same(expected, reply.Proof) ? null : Unproven;
    }

    private static async Task<BootstrapOutcome> BootstrapAsync(PairingClientOptions options, TemporaryCertificate throwaway, byte[] clientNonce, CancellationToken cancel)
    {
        byte[]? leaf = null;
        string? tlsFingerprint = null;
        string body = PairingWire.Write(new PairingBootstrapRequest(options.Bundle.InvitationId, clientNonce));
        bool Provisional(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
        {
            // Structure only: the proof decides whether this is the authority. Nothing is trusted because it passed.
            if (certificate is null)
            {
                return false;
            }

            try
            {
                using X509Certificate2 candidate = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
                if (MachineCertificates.ValidateLeafStructure(candidate, options.Clock.GetUtcNow(), out string fingerprint) is not null)
                {
                    return false;
                }

                leaf = candidate.RawData;
                tlsFingerprint = fingerprint;

                return true;
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        try
        {
            (int status, string text) = await PostAsync(options, throwaway.Current, Provisional, "bootstrap", body, cancel);
            if (status != 200 || !PairingWire.TryReadBootstrapReply(text, out PairingBootstrapReply? reply) || reply is null)
            {
                return new BootstrapOutcome(null, status == 200 ? "the authority's answer is not a pairing answer" : "the authority did not accept the invitation (it may be wrong, expired or already used); create a new one", null, null, null);
            }

            return new BootstrapOutcome(reply, "", leaf, tlsFingerprint, null);
        }
        catch (Exception error) when (error is HttpRequestException or IOException or AuthenticationException or OperationCanceledException or TimeoutException)
        {
            return new BootstrapOutcome(null, "the authority could not be reached or did not complete a TLS 1.3 handshake", null, null, null);
        }
    }

    // ---- registration ----

    private static async Task<(string? Problem, PairingRegistrationReply? Reply)> RegisterAsync(PairingClientOptions options, TemporaryCertificate machineTls, byte[] authorityCertificate, string authorityFingerprint, PairingRegistrationRequest request, CancellationToken cancel)
    {
        string body = PairingWire.Write(request);
        bool Pinned(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
        {
            if (certificate is null)
            {
                return false;
            }

            try
            {
                using X509Certificate2 candidate = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());

                return MachineCertificates.ValidateLeaf(candidate, authorityCertificate, options.Clock.GetUtcNow(), authorityFingerprint) is null;
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        for (int attempt = 0; ; attempt++)
        {
            try
            {
                (int status, string text) = await PostAsync(options, machineTls.Current, Pinned, "register", body, cancel);
                if (status == 200)
                {
                    return PairingWire.TryReadRegistrationReply(text, out PairingRegistrationReply? reply) && reply is not null ? (null, reply) : ("the authority's answer is not a pairing answer", null);
                }

                if (status == 429)
                {
                    return ("the authority is busy with pairing; wait a few minutes and try again", null);
                }

                return ("the authority refused the registration (the invitation may be used, expired or withdrawn, or this machine may already be known); ask the administrator for a new invitation", null);
            }
            catch (Exception error) when (error is HttpRequestException or IOException or AuthenticationException or OperationCanceledException or TimeoutException && !cancel.IsCancellationRequested)
            {
                if (attempt >= options.Retries)
                {
                    return ("the authority could not be reached; the registration may or may not have been recorded (the administrator's machine list shows it)", null);
                }

                await Task.Delay(TimeSpan.FromMilliseconds(200 * (attempt + 1)), options.Clock, cancel);
            }
        }
    }

    // ---- one request on one fresh connection ----

    private static async Task<(int Status, string Body)> PostAsync(PairingClientOptions options, X509Certificate2 clientCertificate, RemoteCertificateValidationCallback validate, string step, string body, CancellationToken cancel)
    {
        string clientFingerprint = MachineCertificates.SanFingerprint(clientCertificate) ?? "";
        byte[] bytes = Encoding.UTF8.GetBytes(body);
        options.OnRequest?.Invoke(step, bytes, clientFingerprint);
        using SocketsHttpHandler handler = new()
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            PooledConnectionLifetime = TimeSpan.Zero,
            SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls13,
                ClientCertificates = [clientCertificate],
                AllowTlsResume = false,
                ApplicationProtocols = [SslApplicationProtocol.Http2],
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                RemoteCertificateValidationCallback = validate,
            },
        };
        using HttpClient client = new(handler, disposeHandler: false)
        {
            DefaultRequestVersion = HttpVersion.Version20,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
            Timeout = options.Timeout,
        };
        using HttpRequestMessage request = new(HttpMethod.Post, options.Bundle.Authority + MachineApi.PairingPath) { Version = HttpVersion.Version20, VersionPolicy = HttpVersionPolicy.RequestVersionExact };
        request.Content = new ByteArrayContent(bytes);
        request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(MachineApi.JsonType);
        using HttpResponseMessage response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancel);
        using Stream stream = await response.Content.ReadAsStreamAsync(cancel);
        using MemoryStream copy = new();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = await stream.ReadAsync(buffer, cancel)) > 0)
        {
            if (copy.Length + read > MaxResponseBytes)
            {
                throw new IOException("the answer is too large");
            }

            copy.Write(buffer, 0, read);
        }

        return ((int)response.StatusCode, new UTF8Encoding(false, false).GetString(copy.ToArray()));
    }
}

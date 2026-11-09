using System.Collections;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WithSecrets;

/// <summary>
/// What the CLI knows about the service it may talk to: the machine fingerprint pinned in <c>host.json</c> (null: nothing is pinned yet,
/// because the machine was not approved), or why <c>host.json</c> cannot be used.
/// </summary>
public sealed record ServiceTrust(string? PinnedFingerprint, string? Problem = null)
{
    /// <summary>The pin in <c>host.json</c>. A file that cannot be read is a refusal, never "nothing pinned".</summary>
    public static ServiceTrust From(HostConfigFile file)
    {
        HostConfigLoad load = file.Load();

        return load.Problem is not null ? new ServiceTrust(null, load.Problem) : new ServiceTrust(load.Config?.Authority is null ? null : load.Config.MachineFingerprint);
    }
}

/// <summary>
/// The client side of a run: reads the .env files once, sends the immutable plan to the host service as a
/// <see cref="LaunchRequest" />, prints what the service streams back (the approval link, the redacted output) and ends with the
/// exit code the service reports. It never opens the secret store, never decrypts and never starts the program: the final
/// decision to launch is the service's.
/// </summary>
public static class LaunchClient
{
    /// <summary>Exit code: the host service is not running (nothing was asked, nothing ran).</summary>
    public const int ServiceNotRunning = 6;

    /// <summary>Exit code: what answers on the service port is not this machine's host service, or no identity is pinned yet (nothing was sent).</summary>
    public const int ServiceNotAuthenticated = 7;

    /// <summary>Exit code: the authority is locked (nothing was asked or run). Unlock it at the authority's admin page, whose link the line names.</summary>
    public const int AuthorityLocked = 8;

    /// <summary>How long the service has to answer the identity check.</summary>
    public static readonly TimeSpan IdentityTimeout = TimeSpan.FromSeconds(5);

    public const string NotRunningMessage = "with-secrets: the host service is not running. Start it with: with-secrets service";

    /// <summary>
    /// Runs the request through the service on 127.0.0.1:<paramref name="servicePort" />. <paramref name="environment" /> is the
    /// environment the program inherits (this process's own when null); <paramref name="pagePort" /> is the --port of the run.
    /// </summary>
    public static async Task<int> RunAsync(RunArgs args, string workingDirectory, int servicePort, int? pagePort, TextWriter stdout, TextWriter stderr, ServiceTrust trust, IReadOnlyDictionary<string, string>? environment = null, HttpMessageHandler? handler = null, CancellationToken cancel = default, bool approve = false)
    {
        environment ??= CurrentEnvironment();
        Func<string, string?> lookup = name => environment.FirstOrDefault(item => string.Equals(item.Key, name, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal)) is { Key: not null } found ? found.Value : null;

        // The .env files are read once, here. The plan goes to the service and nowhere else reads the files.
        EnvResult composed = EnvDeclarations.Compose(args.EnvFiles, workingDirectory, args.Secrets, lookup);
        if (composed.Plan is not { } plan)
        {
            return await Fail(stderr, RunCommand.Usage, composed.Error!);
        }

        foreach (string note in plan.Notes)
        {
            await stderr.WriteLineAsync("with-secrets: " + note);
        }

        if (plan.Mappings.Count == 0)
        {
            return await Fail(stderr, RunCommand.Usage, "Name the secrets with --secrets NAME[,NAME...]. There is no option for all secrets.");
        }

        string[] invalid = [.. plan.Mappings.Select(mapping => mapping.Secret).Distinct(StringComparer.Ordinal).Where(name => !SecretNames.IsValid(name))];
        if (invalid.Length > 0)
        {
            return await Fail(stderr, RunCommand.Usage, $"Invalid secret name: {string.Join(", ", invalid.Select(ApprovalSummary.Clean))}.");
        }

        DateTimeOffset created = DateTimeOffset.UtcNow;
        LaunchRequest request = new(
            LaunchProtocol.Version,
            "req-" + Base64Url(16),
            created,
            created.Add(LaunchProtocol.MaxLifetime),
            Base64Url(16),
            [.. plan.Mappings.Select(mapping => mapping.Secret).Distinct(StringComparer.Ordinal)],
            [.. plan.Mappings.Select(mapping => new LaunchMapping(mapping.Variable, mapping.Secret))],
            args.Reason,
            args.Program,
            args.Arguments,
            workingDirectory,
            plan.Files,
            [.. plan.Ordinary.Keys.Order(StringComparer.Ordinal)],
            plan.Ordinary,
            environment);

        using HttpClient client = handler is null
            ? new HttpClient(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false })
            : new HttpClient(handler, false);
        client.Timeout = Timeout.InfiniteTimeSpan;

        // Before anything is sent: is this the host service of this machine? A program that merely holds the port is refused here.
        if (await AuthenticateService(client, servicePort, trust, stderr, cancel) is { } refused)
        {
            return refused;
        }

        string url = $"http://127.0.0.1:{servicePort}/v1/{(approve ? "approve" : "launch")}" + (pagePort is { } page ? "?pagePort=" + page : "");
        using HttpRequestMessage message = new(HttpMethod.Post, url)
        {
            Content = new StringContent(request.Canonical(), new UTF8Encoding(false), new MediaTypeHeaderValue("application/json"))
        };
        message.Headers.Add(HostService.DigestHeader, request.Digest());

        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, cancel);
        }
        catch (HttpRequestException)
        {
            await stderr.WriteLineAsync(NotRunningMessage);

            return ServiceNotRunning;
        }

        using (response)
        {
            if (response.StatusCode == HttpStatusCode.Locked)
            {
                return await Fail(stderr, AuthorityLocked, await ErrorText(response));
            }

            if (response.StatusCode != HttpStatusCode.OK)
            {
                string why = await ErrorText(response);

                return await Fail(stderr, (int)response.StatusCode is >= 400 and < 500 ? RunCommand.Usage : RunCommand.StoreError, "the host service refused the request: " + why);
            }

            using StreamReader reader = new(await response.Content.ReadAsStreamAsync(cancel), new UTF8Encoding(false));
            try
            {
                while (await reader.ReadLineAsync(cancel) is { } line)
                {
                    if (!LaunchEvent.TryParse(line, out LaunchEvent? launchEvent, out string? error))
                    {
                        return await Fail(stderr, RunCommand.StoreError, "the host service sent something that is not a launch event (" + error + ")");
                    }

                    switch (launchEvent!.Kind)
                    {
                        case LaunchEvent.ApprovalKind:
                            await stderr.WriteLineAsync(WebApprover.LinkPrefix + launchEvent.Link);
                            break;
                        case LaunchEvent.OutputKind:
                            TextWriter target = launchEvent.Stream == "stdout" ? stdout : stderr;
                            await target.WriteAsync(launchEvent.Text);
                            await target.FlushAsync();
                            break;
                        default:
                            return launchEvent.ExitCode!.Value;
                    }
                }
            }
            catch (Exception failure) when (failure is HttpRequestException or IOException)
            {
                return await Fail(stderr, RunCommand.StoreError, "the connection to the host service was lost before the program finished");
            }
        }

        return await Fail(stderr, RunCommand.StoreError, "the host service closed the connection before the program finished");
    }

    /// <summary>
    /// Asks the service for a signature over a fresh random challenge and checks that it is made by the machine identity key whose fingerprint
    /// <paramref name="trust" /> pins. Null when the service is the pinned one. Otherwise the exit code, after the reason went to
    /// <paramref name="stderr" />; nothing of the request was sent. This authenticates the service to the client (a program that only holds
    /// the port cannot sign); it adds no credential of the client.
    /// </summary>
    private static async Task<int?> AuthenticateService(HttpClient client, int servicePort, ServiceTrust trust, TextWriter stderr, CancellationToken cancel)
    {
        if (trust.Problem is not null)
        {
            return await Fail(stderr, ServiceNotAuthenticated, trust.Problem);
        }

        string challenge = Base64Url(32);
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        limit.CancelAfter(IdentityTimeout);
        try
        {
            using HttpRequestMessage message = new(HttpMethod.Post, $"http://127.0.0.1:{servicePort}/v1/identity")
            {
                Content = new StringContent("{\"challenge\":\"" + challenge + "\"}", new UTF8Encoding(false), new MediaTypeHeaderValue("application/json"))
            };
            using HttpResponseMessage response = await client.SendAsync(message, HttpCompletionOption.ResponseContentRead, limit.Token);
            if (response.StatusCode != HttpStatusCode.OK)
            {
                return await Fail(stderr, ServiceNotAuthenticated, NotServiceMessage(servicePort, "it answered the identity check with HTTP " + (int)response.StatusCode));
            }

            string text = await response.Content.ReadAsStringAsync(limit.Token);
            if (text.Length > 4096 || !CanonicalJson.Open(text, out JsonDocument? doc, out _))
            {
                return await Fail(stderr, ServiceNotAuthenticated, NotServiceMessage(servicePort, "its answer to the identity check is not valid"));
            }

            string? fingerprint;
            byte[] publicKey;
            byte[] signature;
            using (doc)
            {
                ContractReader reader = new(doc!.RootElement, "protocolVersion", "fingerprint", "publicKey", "signature");
                if (reader.Problem is not null || !reader.Int("protocolVersion", out int version) || version != LaunchProtocol.Version || !reader.Text("fingerprint", out fingerprint)
                    || !reader.Text("publicKey", out string? keyText) || !reader.Text("signature", out string? signatureText))
                {
                    return await Fail(stderr, ServiceNotAuthenticated, NotServiceMessage(servicePort, "its answer to the identity check is not valid"));
                }

                try
                {
                    publicKey = Convert.FromBase64String(keyText!);
                    signature = Convert.FromBase64String(signatureText!);
                }
                catch (FormatException)
                {
                    return await Fail(stderr, ServiceNotAuthenticated, NotServiceMessage(servicePort, "its answer to the identity check is not valid"));
                }
            }

            // It must hold the private key of the fingerprint it names, for this very challenge.
            if (KeyIdentity.Fingerprint(publicKey) != fingerprint || !KeyIdentity.Verify(publicKey, WireText.Bytes(WireText.IdentityDomain, challenge), signature))
            {
                return await Fail(stderr, ServiceNotAuthenticated, NotServiceMessage(servicePort, "it could not prove the identity it claims"));
            }

            if (trust.PinnedFingerprint is null)
            {
                return await Fail(stderr, ServiceNotAuthenticated, $"this machine is not approved yet, so no identity is pinned. The service says its fingerprint is {fingerprint}. If that is the fingerprint that the service printed in its own window, ask the administrator to run: with-secrets admin approve {fingerprint} --name NAME. Nothing was sent.");
            }

            if (!string.Equals(fingerprint, trust.PinnedFingerprint, StringComparison.Ordinal))
            {
                return await Fail(stderr, ServiceNotAuthenticated, NotServiceMessage(servicePort, $"its identity {fingerprint} is not the pinned one {trust.PinnedFingerprint}"));
            }

            return null;
        }
        catch (HttpRequestException)
        {
            await stderr.WriteLineAsync(NotRunningMessage);

            return ServiceNotRunning;
        }
        catch (OperationCanceledException) when (limit.IsCancellationRequested && !cancel.IsCancellationRequested)
        {
            return await Fail(stderr, ServiceNotAuthenticated, NotServiceMessage(servicePort, "it did not answer the identity check in time"));
        }
    }

    private static string NotServiceMessage(int port, string why) =>
        $"the program that answers on port {port} is not this machine's host service ({why}). Nothing was sent. Stop that program, or start the service on another port (with-secrets service --port N, and --service-port N for a run).";

    /// <summary>The environment of this process, as a map.</summary>
    public static IReadOnlyDictionary<string, string> CurrentEnvironment()
    {
        Dictionary<string, string> map = new(StringComparer.Ordinal);
        foreach (DictionaryEntry item in Environment.GetEnvironmentVariables())
        {
            if (item.Key is string name && item.Value is string value)
            {
                map[name] = value;
            }
        }

        return map;
    }

    private static string Base64Url(int bytes) => Convert.ToBase64String(RandomNumberGenerator.GetBytes(bytes)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static async Task<int> Fail(TextWriter stderr, int code, string message)
    {
        await stderr.WriteLineAsync("with-secrets: " + message);

        return code;
    }

    private static async Task<string> ErrorText(HttpResponseMessage response)
    {
        try
        {
            using JsonDocument doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            if (doc.RootElement.TryGetProperty("error", out JsonElement error) && error.ValueKind == JsonValueKind.String)
            {
                return ApprovalSummary.Clean(error.GetString()!);
            }
        }
        catch (JsonException)
        {
            // Not our service's error body.
        }

        return "HTTP " + (int)response.StatusCode;
    }
}

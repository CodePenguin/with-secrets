using System.Collections;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ArcanaGuardian;

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
/// exit code the service reports. It can resolve dotenvx project values after approval. The service owns access to the
/// Arcana Guardian store and starts the requested program.
/// </summary>
public static class LaunchClient
{
    /// <summary>Exit code: the host service is not running (nothing was asked, nothing ran).</summary>
    public const int ServiceNotRunning = 6;

    /// <summary>Exit code: what answers on the service port is not this machine's host service, or no identity is pinned yet (nothing was sent).</summary>
    public const int ServiceNotAuthenticated = 7;

    /// <summary>Exit code: the authority is locked (nothing was asked or run). Unlock it in the administration web app, whose link the line names.</summary>
    public const int AuthorityLocked = 8;

    /// <summary>Exit code: the host service answered 503: it has not finished its startup check-in with the authority, or it is running as many launches as it allows (nothing was asked or run). Ask again in a moment.</summary>
    public const int ServiceUnavailable = 9;

    /// <summary>How long the service has to answer the identity check.</summary>
    public static readonly TimeSpan IdentityTimeout = TimeSpan.FromSeconds(5);

    public const string NotRunningMessage = "using-secrets: the host service is not running. Start it with: using-secrets service";

    /// <summary>
    /// Runs the request through the service at <paramref name="endpoint" />. <paramref name="environment" /> is the
    /// environment the program inherits (this process's own when null); <paramref name="pagePort" /> is the --port of the run.
    /// </summary>
    public static async Task<int> RunAsync(RunArgs args, string workingDirectory, LocalEndpoint endpoint, int? pagePort, TextWriter stdout, TextWriter stderr, ServiceTrust trust, IReadOnlyDictionary<string, string>? environment = null, HttpMessageHandler? handler = null, CancellationToken cancel = default, bool approve = false)
    {
        environment = (environment ?? CurrentEnvironment()).Where(pair => !DotenvxRun.IsCredential(pair.Key)).ToDictionary();
        Func<string, string?> lookup = name => environment.FirstOrDefault(item => string.Equals(item.Key, name, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal)) is { Key: not null } found ? found.Value : null;

        // The service gets the plan. The requesting client keeps the dotenvx project files local.
        EnvResult composed = EnvDeclarations.Compose(args.EnvFiles, workingDirectory, args.Secrets, lookup);
        if (composed.Plan is not { } plan)
        {
            return await Fail(stderr, RunCommand.Usage, composed.Error!);
        }

        foreach (string note in plan.Notes)
        {
            await stderr.WriteLineAsync("using-secrets: " + note);
        }

        IReadOnlyList<EncryptedValue> encrypted = plan.Encrypted ?? [];
        string? dotenvxExecutable = null;
        string? dotenvxDigest = null;
        if (plan.HasDotenvxDeclarations || DotenvxRun.HasPolicy(workingDirectory))
        {
            if (plan.Files.Count == 0)
            {
                return await Fail(stderr, RunCommand.Usage, "The dotenvx project policy requires a selected .env file.");
            }

            dotenvxExecutable = Environment.GetEnvironmentVariable(DotenvxRun.ExecutableVariable) ?? "";
            if (!Path.IsPathFullyQualified(dotenvxExecutable) || !File.Exists(dotenvxExecutable))
            {
                return await Fail(stderr, RunCommand.Usage, $"Set {DotenvxRun.ExecutableVariable} in the requesting user's environment to a trusted absolute dotenvx path.");
            }

            try
            {
                dotenvxDigest = DotenvxRun.InputDigest(workingDirectory, plan.Files, plan.FileHashes);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or DotenvxResolutionException)
            {
                return await Fail(stderr, RunCommand.Usage, "Cannot read the project inputs for dotenvx. Nothing was run.");
            }
        }

        if (plan.Mappings.Count == 0 && dotenvxDigest is null)
        {
            return await Fail(stderr, RunCommand.Usage, "Name the secrets with --secrets NAME[,NAME...]. There is no option for all secrets.");
        }

        IReadOnlyList<string> names = [.. plan.Mappings.Select(mapping => mapping.Secret).Distinct(StringComparer.Ordinal)];
        string[] invalid = [.. names.Where(name => !SecretNames.IsValid(name))];
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
            names,
            [.. plan.Mappings.Select(mapping => new LaunchMapping(mapping.Variable, mapping.Secret))],
            args.Reason,
            args.Program,
            args.Arguments,
            workingDirectory,
            plan.Files,
            [.. plan.Ordinary.Keys.Order(StringComparer.Ordinal)],
            plan.Ordinary,
            environment,
            [.. encrypted.Select(value => new LaunchEncrypted(value.Variable, value.File, value.PublicKey, value.Ciphertext))],
            dotenvxDigest, dotenvxDigest is not null && plan.DynamicNames is { Count: > 0 } ? plan.DynamicNames : null);

        using HttpClient client = handler is null
            ? new HttpClient(endpoint.CreateHandler())
            : new HttpClient(handler, false);
        client.Timeout = Timeout.InfiniteTimeSpan;

        // Before anything is sent: is this the host service of this machine? A program that merely holds the port is refused here.
        if (await AuthenticateService(client, endpoint, trust, stderr, cancel) is { } refused)
        {
            return refused;
        }

        Uri url = new(endpoint.BaseUri, "v1/" + (approve ? "approve" : "launch") + (pagePort is { } page ? "?pagePort=" + page : ""));
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
        catch (HttpRequestException unreachable) when (LocalChannelException.Find(unreachable) is { } unusable)
        {
            // The channel is there but is not safe to use or was refused: that is not "the service is not running", and nothing was sent.
            return await Fail(stderr, ServiceNotAuthenticated, "using-secrets: the channel to the host service cannot be used: " + unusable.Message);
        }
        catch (HttpRequestException)
        {
            await stderr.WriteLineAsync(NotRunningMessage + " (nothing answers on " + endpoint.Describe() + "; the service and this command must run as the same user" + (OperatingSystem.IsWindows() ? "" : ", with the same XDG_RUNTIME_DIR or TMPDIR") + ")");

            return ServiceNotRunning;
        }

        using (response)
        {
            if (response.StatusCode == HttpStatusCode.Locked)
            {
                return await Fail(stderr, AuthorityLocked, await ErrorText(response));
            }

            if (response.StatusCode == HttpStatusCode.ServiceUnavailable)
            {
                return await Fail(stderr, ServiceUnavailable, "the host service is not ready or is busy (it checks in with its authority before it accepts requests, and runs only a few launches at once); nothing was asked or run. Ask again in a moment. " + await ErrorText(response));
            }

            if (response.StatusCode != HttpStatusCode.OK)
            {
                string why = await ErrorText(response);

                return await Fail(stderr, (int)response.StatusCode is >= 400 and < 500 ? RunCommand.Usage : RunCommand.StoreError, "the host service refused the request: " + why);
            }

            using StreamReader reader = new(await response.Content.ReadAsStreamAsync(cancel), new UTF8Encoding(false));
            bool sentDotenvx = false;
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
                        case LaunchEvent.DotenvxKind:
                            if (sentDotenvx || approve || dotenvxExecutable is null || dotenvxDigest is null)
                            {
                                return await Fail(stderr, RunCommand.StoreError, "the host service sent an unexpected dotenvx request");
                            }

                            sentDotenvx = true;
                            if (!await SendDotenvxAsync(client, endpoint, request, dotenvxExecutable, launchEvent.Challenge!, stderr, cancel))
                            {
                                return await Fail(stderr, RunCommand.StoreError, "the host service refused the dotenvx response");
                            }

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

    private static async Task<bool> SendDotenvxAsync(HttpClient client, LocalEndpoint endpoint, LaunchRequest request,
        string executable, string challenge, TextWriter stderr, CancellationToken cancel)
    {
        Dictionary<string, string>? values = null;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        TimeSpan remaining = request.Expires - DateTimeOffset.UtcNow;
        if (remaining > TimeSpan.Zero)
        {
            timeout.CancelAfter(remaining);
            try
            {
                values = await DotenvxRun.ResolveAsync(executable, request.WorkingDirectory, request.EnvFiles,
                    [.. DotenvxRun.OutputNames(request)], timeout.Token, request.DotenvxInputDigest);
            }
            catch (DotenvxResolutionException error) when (error.ApprovalRequired)
            {
                await stderr.WriteLineAsync("using-secrets: " + DotenvxRun.ApprovalError);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or DotenvxResolutionException
                || error is OperationCanceledException && !cancel.IsCancellationRequested)
            {
                values = null;
            }
        }

        byte[] body = JsonSerializer.SerializeToUtf8Bytes(values);
        try
        {
            using var message = new HttpRequestMessage(HttpMethod.Post, new Uri(endpoint.BaseUri, "v1/launch/" + request.RequestId + "/dotenvx"))
            {
                Content = new ByteArrayContent(body),
            };
            message.Headers.Add("X-Dotenvx-Challenge", challenge);
            using HttpResponseMessage response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, cancel);
            return response.StatusCode == HttpStatusCode.NoContent;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(body);
        }
    }

    /// <summary>
    /// Asks the service for a signature over a fresh random challenge and checks that it is made by the machine identity key whose fingerprint
    /// <paramref name="trust" /> pins. Null when the service is the pinned one. Otherwise the exit code, after the reason went to
    /// <paramref name="stderr" />; nothing of the request was sent. This authenticates the service to the client (a program that only holds
    /// the port cannot sign); it adds no credential of the client.
    /// </summary>
    internal static async Task<int?> AuthenticateService(HttpClient client, LocalEndpoint endpoint, ServiceTrust trust, TextWriter stderr, CancellationToken cancel)
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
            using HttpRequestMessage message = new(HttpMethod.Post, new Uri(endpoint.BaseUri, "v1/identity"))
            {
                Content = new StringContent("{\"challenge\":\"" + challenge + "\"}", new UTF8Encoding(false), new MediaTypeHeaderValue("application/json"))
            };
            using HttpResponseMessage response = await client.SendAsync(message, HttpCompletionOption.ResponseContentRead, limit.Token);
            if (response.StatusCode != HttpStatusCode.OK)
            {
                return await Fail(stderr, ServiceNotAuthenticated, NotServiceMessage(endpoint, "it answered the identity check with HTTP " + (int)response.StatusCode));
            }

            string text = await response.Content.ReadAsStringAsync(limit.Token);
            if (text.Length > 4096 || !CanonicalJson.Open(text, out JsonDocument? doc, out _))
            {
                return await Fail(stderr, ServiceNotAuthenticated, NotServiceMessage(endpoint, "its answer to the identity check is not valid"));
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
                    return await Fail(stderr, ServiceNotAuthenticated, NotServiceMessage(endpoint, "its answer to the identity check is not valid"));
                }

                try
                {
                    publicKey = Convert.FromBase64String(keyText!);
                    signature = Convert.FromBase64String(signatureText!);
                }
                catch (FormatException)
                {
                    return await Fail(stderr, ServiceNotAuthenticated, NotServiceMessage(endpoint, "its answer to the identity check is not valid"));
                }
            }

            // It must hold the private key of the fingerprint it names, for this very challenge.
            if (KeyIdentity.Fingerprint(publicKey) != fingerprint || !KeyIdentity.Verify(publicKey, WireText.Bytes(WireText.IdentityDomain, challenge), signature))
            {
                return await Fail(stderr, ServiceNotAuthenticated, NotServiceMessage(endpoint, "it could not prove the identity it claims"));
            }

            if (trust.PinnedFingerprint is null)
            {
                return await Fail(stderr, ServiceNotAuthenticated, $"this machine is not approved yet, so no identity is pinned. The service says its fingerprint is {fingerprint}. If that is the fingerprint that the service printed in its own window, ask the administrator to approve that fingerprint in the authority's admin web app (using-secrets admin prints its link). Nothing was sent.");
            }

            if (!string.Equals(fingerprint, trust.PinnedFingerprint, StringComparison.Ordinal))
            {
                return await Fail(stderr, ServiceNotAuthenticated, NotServiceMessage(endpoint, $"its identity {fingerprint} is not the pinned one {trust.PinnedFingerprint}"));
            }

            return null;
        }
        catch (HttpRequestException unreachable) when (LocalChannelException.Find(unreachable) is { } unusable)
        {
            // The channel is there but is not safe to use or was refused: that is not "the service is not running", and nothing was sent.
            return await Fail(stderr, ServiceNotAuthenticated, "using-secrets: the channel to the host service cannot be used: " + unusable.Message);
        }
        catch (HttpRequestException)
        {
            await stderr.WriteLineAsync(NotRunningMessage + " (nothing answers on " + endpoint.Describe() + "; the service and this command must run as the same user" + (OperatingSystem.IsWindows() ? "" : ", with the same XDG_RUNTIME_DIR or TMPDIR") + ")");

            return ServiceNotRunning;
        }
        catch (OperationCanceledException) when (limit.IsCancellationRequested && !cancel.IsCancellationRequested)
        {
            return await Fail(stderr, ServiceNotAuthenticated, NotServiceMessage(endpoint, "it did not answer the identity check in time"));
        }
    }

    private static string NotServiceMessage(LocalEndpoint endpoint, string why) =>
        $"the program that answers at {endpoint.Describe()} is not this machine's host service ({why}). Nothing was sent. Stop that program (or remove what it made there) and start the service: using-secrets service.";

    /// <summary>The environment of this process, as a map.</summary>
    public static IReadOnlyDictionary<string, string> CurrentEnvironment()
    {
        Dictionary<string, string> map = new(StringComparer.Ordinal);
        foreach (DictionaryEntry item in Environment.GetEnvironmentVariables())
        {
            // The pairing credential is a local credential of the pairing command: never part of what a run sends on (and so never in an approval page, an audit row or a child).
            if (item.Key is string name && item.Value is string value && !PairingInput.IsPairingVariable(name))
            {
                map[name] = value;
            }
        }

        return map;
    }

    private static string Base64Url(int bytes) => Convert.ToBase64String(RandomNumberGenerator.GetBytes(bytes)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static async Task<int> Fail(TextWriter stderr, int code, string message)
    {
        await stderr.WriteLineAsync("using-secrets: " + message);

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

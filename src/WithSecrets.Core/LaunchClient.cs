using System.Collections;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WithSecrets;

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

    public const string NotRunningMessage = "with-secrets: the host service is not running. Start it with: with-secrets service";

    /// <summary>
    /// Runs the request through the service on 127.0.0.1:<paramref name="servicePort" />. <paramref name="environment" /> is the
    /// environment the program inherits (this process's own when null); <paramref name="pagePort" /> is the --port of the run.
    /// </summary>
    public static async Task<int> RunAsync(RunArgs args, string workingDirectory, int servicePort, int? pagePort, TextWriter stdout, TextWriter stderr, IReadOnlyDictionary<string, string>? environment = null, HttpMessageHandler? handler = null, CancellationToken cancel = default)
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
        string url = $"http://127.0.0.1:{servicePort}/v1/launch" + (pagePort is { } page ? "?pagePort=" + page : "");
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

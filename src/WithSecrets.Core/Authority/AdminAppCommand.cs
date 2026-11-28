using System.Net.Http.Headers;
using System.Text.Json;

namespace WithSecrets;

/// <summary>
/// <c>with-secrets admin</c> with no further words: it goes to the authority's admin web app, where all administration lives (machines, grants, audit, settings, lock and unlock). It has no
/// verbs. It prints the app's link and the service's public status (running, locked or unlocked), after checking that the program on the port is this machine's host service (the same
/// identity check as a run, so a program that merely holds the port is not reported as the service). It changes nothing, asks for nothing and needs no passkey. It opens the link in the
/// person's browser when asked to (<paramref name="open" />) and says so; it never opens anything by itself in an agent's shell.
/// </summary>
public static class AdminAppCommand
{
    public static async Task<int> RunAsync(int? chosenPort, TextWriter output, TextWriter error, ServiceTrust trust, Action<string>? open = null, LocalEndpoint? endpoint = null)
    {
        int? port = AdminPort.Resolve(chosenPort, Environment.GetEnvironmentVariable, out string? problem);
        if (port is null)
        {
            await error.WriteLineAsync("with-secrets: " + problem);

            return RunCommand.Usage;
        }

        string link = BrowserAddress.Origin(port.Value) + "/admin";
        // The service is asked through the command line's endpoint (who it is, whether it runs); the port is only where the browser finds the app.
        try
        {
            endpoint ??= LocalEndpoint.ForCommandLine();
        }
        catch (IOException channelProblem)
        {
            await error.WriteLineAsync("with-secrets: the channel to the host service cannot be used: " + channelProblem.Message);

            return RunCommand.Usage;
        }

        using HttpClient client = new(endpoint.CreateHandler()) { Timeout = TimeSpan.FromSeconds(3) };
        if (trust is { PinnedFingerprint: null, Problem: null })
        {
            // First run: this machine is not approved yet, so no identity is pinned and the program on the port cannot be checked. The link is public and carries nothing; it is offered
            // as unverified (and not opened), and the person compares the fingerprint the service printed in its own window before approving anything.
            (string firstStatus, int? firstPort) = await StatusAsync(client, endpoint);
            link = firstPort is { } reportedFirst ? BrowserAddress.Origin(reportedFirst) + "/admin" : link;
            await output.WriteLineAsync("Admin web app: " + link);
            await output.WriteLineAsync("Service: " + firstStatus);
            await output.WriteLineAsync("Not verified: this machine is not approved yet, so no identity is pinned and the program on the port cannot be checked. Open the link only if the service you started printed this port, and compare its fingerprint with the one shown in the app before you approve.");

            return 0;
        }

        StringWriter refusal = new();
        int? refused = await LaunchClient.AuthenticateService(client, endpoint, trust, refusal, CancellationToken.None);
        if (refused == LaunchClient.ServiceNotAuthenticated)
        {
            // Not this machine's service: nothing is trusted, and the link is not offered as the authority's.
            await error.WriteAsync(refusal.ToString());

            return LaunchClient.ServiceNotAuthenticated;
        }

        (string status, int? reportedPort) = refused is null ? await StatusAsync(client, endpoint) : ("not running (start it with: with-secrets service)", null);
        if (reportedPort is null && status == "running, using a remote authority")
        {
            await output.WriteLineAsync("Service: " + status + ". Open the administration app on the authority.");
            return 0;
        }

        if (reportedPort is { } servicePort)
        {
            // The port the running service says its admin web app is on wins over the one this command resolved: a wrong --port or WITH_SECRETS_PORT would print a dead link.
            link = BrowserAddress.Origin(servicePort) + "/admin";
        }

        await output.WriteLineAsync("Admin web app: " + link);
        await output.WriteLineAsync("Service: " + status);
        if (open is not null && refused is null)
        {
            open(link);
            await output.WriteLineAsync("Opened the link in your browser.");
        }

        return 0;
    }

    /// <summary>The public status line of the service at its command line endpoint: not running, or running with its lock state.</summary>
    public static async Task<(string Text, int? AdminPort)> StatusAsync(HttpClient client, LocalEndpoint endpoint)
    {
        try
        {
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            using JsonDocument doc = JsonDocument.Parse(await client.GetStringAsync(new Uri(endpoint.BaseUri, "v1/status")));
            bool locked = doc.RootElement.TryGetProperty("locked", out JsonElement value) && value.ValueKind != JsonValueKind.False;
            bool remote = doc.RootElement.TryGetProperty("remote", out JsonElement remoteValue) && remoteValue.ValueKind == JsonValueKind.True;

            int? adminPort = doc.RootElement.TryGetProperty("adminPort", out JsonElement portValue) && portValue.ValueKind == JsonValueKind.Number && portValue.TryGetInt32(out int reported) && reported is >= 1 and <= 65535 ? reported : null;

            string status = remote ? "running, using a remote authority" : locked ? "running, LOCKED (unlock it in the app)" : "running, unlocked";

            return (status, adminPort);
        }
        catch (Exception error) when (error is HttpRequestException or TaskCanceledException or JsonException or IOException)
        {
            if (LocalChannelException.Find(error) is { } unusable)
            {
                return ("not reachable: the channel cannot be used (" + unusable.Message + ")", null);
            }

            return ("not running (start it with: with-secrets service)", null);
        }
    }
}

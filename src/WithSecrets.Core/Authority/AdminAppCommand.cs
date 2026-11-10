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
    public static async Task<int> RunAsync(int? chosenPort, TextWriter output, TextWriter error, ServiceTrust trust, Action<string>? open = null)
    {
        int? port = ServiceEndpoint.Resolve(chosenPort, Environment.GetEnvironmentVariable, out string? problem);
        if (port is null)
        {
            await error.WriteLineAsync("with-secrets: " + problem);

            return RunCommand.Usage;
        }

        string link = $"http://localhost:{port}/admin";
        using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(3) };
        if (trust is { PinnedFingerprint: null, Problem: null })
        {
            // First run: this machine is not approved yet, so no identity is pinned and the program on the port cannot be checked. The link is public and carries nothing; it is offered
            // as unverified (and not opened), and the person compares the fingerprint the service printed in its own window before approving anything.
            await output.WriteLineAsync("Admin web app: " + link);
            await output.WriteLineAsync("Service: " + await StatusAsync(client, port.Value));
            await output.WriteLineAsync("Not verified: this machine is not approved yet, so no identity is pinned and the program on the port cannot be checked. Open the link only if the service you started printed this port, and compare its fingerprint with the one shown in the app before you approve.");

            return 0;
        }

        StringWriter refusal = new();
        int? refused = await LaunchClient.AuthenticateService(client, port.Value, trust, refusal, CancellationToken.None);
        if (refused == LaunchClient.ServiceNotAuthenticated)
        {
            // Not this machine's service: nothing is trusted, and the link is not offered as the authority's.
            await error.WriteAsync(refusal.ToString());

            return LaunchClient.ServiceNotAuthenticated;
        }

        string status = refused is null ? await StatusAsync(client, port.Value) : "not running (start it with: with-secrets service)";
        await output.WriteLineAsync("Admin web app: " + link);
        await output.WriteLineAsync("Service: " + status);
        if (open is not null && refused is null)
        {
            open(link);
            await output.WriteLineAsync("Opened the link in your browser.");
        }

        return 0;
    }

    /// <summary>The public status line of the service on the port: not running, or running with its lock state.</summary>
    public static async Task<string> StatusAsync(HttpClient client, int port)
    {
        try
        {
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            using JsonDocument doc = JsonDocument.Parse(await client.GetStringAsync($"http://127.0.0.1:{port}/v1/status"));
            bool locked = doc.RootElement.TryGetProperty("locked", out JsonElement value) && value.ValueKind != JsonValueKind.False;

            return locked ? "running, LOCKED (unlock it in the app)" : "running, unlocked";
        }
        catch (Exception error) when (error is HttpRequestException or TaskCanceledException or JsonException)
        {
            return "not running (start it with: with-secrets service)";
        }
    }
}

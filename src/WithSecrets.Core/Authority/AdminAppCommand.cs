using System.Net.Http.Headers;
using System.Text.Json;

namespace WithSecrets;

/// <summary>
/// <c>with-secrets admin</c> with no further words: it goes to the authority's admin web app, where all administration lives. It prints the app's link and the service's public status
/// (running, locked or unlocked). It changes nothing, asks for nothing and needs no passkey; every change is made on the app, each with its own fresh passkey tap.
/// </summary>
public static class AdminAppCommand
{
    public static async Task<int> RunAsync(int? chosenPort, TextWriter output)
    {
        int? port = ServiceEndpoint.Resolve(chosenPort, Environment.GetEnvironmentVariable, out string? error);
        if (port is null)
        {
            TerminalPrompt.Final("with-secrets: " + error);

            return RunCommand.Usage;
        }

        string link = $"http://localhost:{port}/admin";
        string status = await StatusAsync(port.Value);
        await output.WriteLineAsync("Admin web app: " + link);
        await output.WriteLineAsync("Service: " + status);

        return 0;
    }

    /// <summary>The public status line of the service on the port: not running, or running with its lock state.</summary>
    public static async Task<string> StatusAsync(int port)
    {
        try
        {
            using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(3) };
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

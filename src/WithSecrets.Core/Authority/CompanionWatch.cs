namespace WithSecrets;

/// <summary>Reports the pinned local service's status and pending request IDs to the desktop companion.</summary>
public static class CompanionWatch
{
    public static async Task<int> RunAsync(ServiceTrust trust, TextWriter output, TextWriter error, LocalEndpoint? endpoint = null)
    {
        try
        {
            endpoint ??= LocalEndpoint.ForCommandLine();
            using HttpClient client = new(endpoint.CreateHandler()) { Timeout = TimeSpan.FromSeconds(3) };
            if (await LaunchClient.AuthenticateService(client, endpoint, trust, error, CancellationToken.None) is { } refused)
            {
                return refused;
            }

            Uri snapshots = new(endpoint.BaseUri, "v1/companion");
            while (true)
            {
                await output.WriteLineAsync(await client.GetStringAsync(snapshots));
                await output.FlushAsync();
                await Task.Delay(TimeSpan.FromSeconds(2));
            }
        }
        catch (Exception problem) when (problem is HttpRequestException or IOException or OperationCanceledException)
        {
            return LaunchClient.ServiceNotRunning;
        }
    }
}

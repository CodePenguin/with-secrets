using System.Diagnostics;
using System.Text.Json;

namespace WithSecrets.Bitwarden;

internal sealed class BitwardenCli(string executablePath, string token, Uri serverUrl, CancellationToken session)
{
    private const int MaxOutput = 32 * 1024 * 1024;

    private async Task<byte[]> RunAsync(string[] arguments, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureUnlocked();
        string configPath = Path.GetTempFileName();
        try
        {
            string server = JsonSerializer.Serialize(BitwardenConfiguration.ServerArgument(serverUrl));
            File.WriteAllText(configPath, $"[profiles.default]\nserver_base = {server}\nstate_opt_out = true\n");
            return await RunWithConfigAsync(arguments, configPath, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            try
            {
                File.Delete(configPath);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                // The temporary profile contains only the server address and a policy flag.
            }
        }
    }

    private async Task<byte[]> RunWithConfigAsync(string[] arguments, string configPath, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, session);
        deadline.CancelAfter(ProviderPolicy.CommandTimeout);
        var start = new ProcessStartInfo(executablePath)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (string argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        // Use an isolated profile for both routing and state policy.
        start.ArgumentList.Add("--config-file");
        start.ArgumentList.Add(configPath);
        start.ArgumentList.Add("--profile");
        start.ArgumentList.Add("default");
        start.ArgumentList.Add("--output");
        start.ArgumentList.Add("json");

        foreach (string key in start.Environment.Keys.Where(key => key.StartsWith("BWS_", StringComparison.OrdinalIgnoreCase)).ToArray())
        {
            start.Environment.Remove(key);
        }

        start.Environment["BWS_ACCESS_TOKEN"] = token;
        using var process = new Process { StartInfo = start };
        try
        {
            EnsureUnlocked();
            process.Start();
        }
        catch (System.ComponentModel.Win32Exception)
        {
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "Could not start the configured Bitwarden Secrets Manager CLI.");
        }
        finally
        {
            start.Environment.Remove("BWS_ACCESS_TOKEN");
        }

        using var output = new MemoryStream();
        using var diagnostics = new MemoryStream();
        try
        {
            process.StandardInput.Close();
            Task stdout = CaptureAsync(process.StandardOutput.BaseStream, output, MaxOutput, deadline.Token);
            Task stderr = CaptureAsync(process.StandardError.BaseStream, diagnostics, CliFailureClassifier.MaxCapture, deadline.Token);
            await Task.WhenAll(stdout, stderr, process.WaitForExitAsync(deadline.Token)).ConfigureAwait(false);
            EnsureUnlocked();
            if (output.Length > MaxOutput)
            {
                throw InvalidResponse();
            }

            if (process.ExitCode != 0)
            {
                // The CLI does not document a machine-readable read-error taxonomy: fixed phrases only, anything else stays Unknown.
                ProviderErrorKind kind = CliFailureClassifier.Classify(diagnostics.GetBuffer().AsSpan(0, (int)diagnostics.Length), FailureRules);
                throw new ProviderAdapterException(kind, "The Bitwarden Secrets Manager CLI command failed.");
            }

            return output.ToArray();
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            EnsureUnlocked();
            throw new ProviderAdapterException(ProviderErrorKind.Unavailable, "The Bitwarden Secrets Manager CLI timed out.");
        }
        catch (IOException)
        {
            throw new ProviderAdapterException(ProviderErrorKind.Unavailable, "Could not communicate with the Bitwarden Secrets Manager CLI.");
        }
        finally
        {
            if (!process.HasExited)
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch (InvalidOperationException) when (process.HasExited)
                {
                }
            }

            System.Security.Cryptography.CryptographicOperations.ZeroMemory(output.GetBuffer().AsSpan(0, (int)output.Length));
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(diagnostics.GetBuffer().AsSpan(0, (int)diagnostics.Length));
        }
    }

    // Most specific first. stderr is matched, never logged: it can carry project metadata.
    private static readonly (string Phrase, ProviderErrorKind Kind)[] FailureRules =
    [
        ("resource not found", ProviderErrorKind.SecretNotFound),
        ("too many requests", ProviderErrorKind.RateLimited),
        ("[429", ProviderErrorKind.RateLimited),
        // Observed from bws 2.1.0: a token the server refused, and a token without a decryption key.
        ("invalid_client", ProviderErrorKind.AuthenticationFailed),
        ("doesn't contain a decryption key", ProviderErrorKind.AuthenticationFailed),
        ("unauthorized", ProviderErrorKind.AuthenticationFailed),
        ("[401", ProviderErrorKind.AuthenticationFailed),
        ("forbidden", ProviderErrorKind.AccessDenied),
        ("[403", ProviderErrorKind.AccessDenied),
        // Observed from bws 2.1.0 for a refused connection ("tcp connect error") and an unknown host ("dns error").
        ("error sending request", ProviderErrorKind.Unavailable),
        ("dns error", ProviderErrorKind.Unavailable),
        ("connection refused", ProviderErrorKind.Unavailable),
        ("timed out", ProviderErrorKind.Unavailable),
    ];

    private static async Task CaptureAsync(Stream input, MemoryStream output, int maximum, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[8192];
        try
        {
            int count;
            while ((count = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) != 0)
            {
                // Continue draining the pipe after the limit to avoid blocking the subprocess.
                int remaining = maximum + 1 - (int)output.Length;
                output.Write(buffer.AsSpan(0, Math.Min(count, remaining)));
            }
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(buffer);
        }
    }

    public async Task<T> ReadJsonAsync<T>(string[] arguments, Func<JsonElement, T> select, CancellationToken cancellationToken)
    {
        byte[] output = await RunAsync(arguments, cancellationToken).ConfigureAwait(false);
        try
        {
            using JsonDocument document = JsonDocument.Parse(output);
            return select(document.RootElement);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException)
        {
            throw InvalidResponse();
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(output);
        }
    }

    public static ProviderAdapterException InvalidResponse()
        => new(ProviderErrorKind.InvalidResponse, "The Bitwarden Secrets Manager CLI returned an invalid response.");

    public void EnsureUnlocked() => EnsureUnlocked(session);

    public static void EnsureUnlocked(CancellationToken session)
    {
        if (session.IsCancellationRequested)
        {
            throw new ProviderAdapterException(ProviderErrorKind.InteractionRequired, "Unlock the authority to access Bitwarden.");
        }
    }
}

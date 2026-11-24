using System.Diagnostics;
using System.Text.Json;

namespace WithSecrets.OnePassword;

internal sealed class OnePasswordCli(string executablePath, string token)
{
    private const int MaxOutput = 32 * 1024 * 1024;

    public async Task<byte[]> RunAsync(string[] arguments, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
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

        foreach (string key in start.Environment.Keys.Where(key => key.StartsWith("OP_", StringComparison.OrdinalIgnoreCase)).ToArray())
        {
            start.Environment.Remove(key);
        }

        start.Environment["OP_SERVICE_ACCOUNT_TOKEN"] = token;
        using var process = new Process { StartInfo = start };
        try
        {
            process.Start();
        }
        catch (System.ComponentModel.Win32Exception)
        {
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "Could not start the configured 1Password CLI.");
        }
        finally
        {
            start.Environment.Remove("OP_SERVICE_ACCOUNT_TOKEN");
        }

        using var output = new MemoryStream();
        try
        {
            process.StandardInput.Close();
            Task stdout = CaptureAsync(process.StandardOutput.BaseStream, output, deadline.Token);
            Task stderr = process.StandardError.BaseStream.CopyToAsync(Stream.Null, deadline.Token);
            await Task.WhenAll(stdout, stderr, process.WaitForExitAsync(deadline.Token)).ConfigureAwait(false);
            if (output.Length > MaxOutput)
            {
                throw InvalidResponse();
            }

            if (process.ExitCode != 0)
            {
                // The CLI does not document a machine-readable read-error taxonomy.
                throw new ProviderAdapterException(ProviderErrorKind.Unknown, "The 1Password CLI command failed.");
            }

            return output.ToArray();
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new ProviderAdapterException(ProviderErrorKind.Unavailable, "The 1Password CLI timed out.");
        }
        catch (IOException)
        {
            throw new ProviderAdapterException(ProviderErrorKind.Unavailable, "Could not communicate with the 1Password CLI.");
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
        }
    }

    private static async Task CaptureAsync(Stream input, MemoryStream output, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[8192];
        try
        {
            int count;
            while ((count = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) != 0)
            {
                // Continue draining the pipe after the limit to avoid blocking the subprocess.
                int remaining = MaxOutput + 1 - (int)output.Length;
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
        => new(ProviderErrorKind.InvalidResponse, "The 1Password CLI returned an invalid response.");
}

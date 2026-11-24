using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WithSecrets.LastPass;

/// <summary>
/// One process-shaped invocation boundary: an authority-owned executable, a private LPASS_HOME and the master password
/// on stdin. No inherited LPASS_* setting can redirect the CLI to another account, agent, pinentry or clipboard.
/// </summary>
internal sealed class LastPassCli(string executablePath, string username) : IAsyncDisposable
{
    private const int MaxOutput = 32 * 1024 * 1024;
    private const int MaxDiagnostics = 4096;
    private static readonly TimeSpan Deadline = TimeSpan.FromSeconds(10);
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly SemaphoreSlim _commandGate = new(1, 1);
    private string? _home;
    private bool _loggedIn;
    private bool _disposed;

    private enum CommandFailure { None, MissingAccount, MissingSession, Other }

    public async ValueTask DisposeAsync()
    {
        await _commandGate.WaitAsync().ConfigureAwait(false);
        try
        {
            _disposed = true;
            if (_home is not null)
            {
                try
                {
                    Directory.Delete(_home, recursive: true);
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
                _home = null;
            }
        }
        finally
        {
            _commandGate.Release();
        }
    }

    public async Task CheckConnectionAsync(string password, CancellationToken cancellationToken)
    {
        byte[] output = await ReadAsync(["ls", "--format=%ai", "--color=never", "--sync=now"], password, cancellationToken).ConfigureAwait(false);
        CryptographicOperations.ZeroMemory(output);
    }

    public async Task<T> ReadJsonAsync<T>(string[] arguments, string password, Func<JsonElement, T> select, CancellationToken cancellationToken)
    {
        byte[] output = await ReadAsync(arguments, password, cancellationToken).ConfigureAwait(false);
        try
        {
            using JsonDocument document = JsonDocument.Parse(output);
            return select(document.RootElement);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException or ArgumentException)
        {
            throw InvalidResponse();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(output);
        }
    }

    private async Task<byte[]> ReadAsync(string[] arguments, string password, CancellationToken cancellationToken)
    {
        await _commandGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_disposed)
            {
                // The configuration was replaced while this call waited: a retry reaches the new connection.
                throw new ProviderAdapterException(ProviderErrorKind.Unavailable, "The LastPass connection was replaced.");
            }
            try
            {
                _home ??= CreateHome();
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                throw new ProviderAdapterException(ProviderErrorKind.Unavailable, "Could not create the LastPass CLI's private configuration directory.");
            }
            await LoginAsync(password, cancellationToken).ConfigureAwait(false);
            (byte[] output, CommandFailure failure) = await RunAsync(arguments, password, cancellationToken).ConfigureAwait(false);
            if (failure == CommandFailure.MissingSession)
            {
                _loggedIn = false;
                await LoginAsync(password, cancellationToken).ConfigureAwait(false);
                (output, failure) = await RunAsync(arguments, password, cancellationToken).ConfigureAwait(false);
            }

            return failure switch
            {
                CommandFailure.None => output,
                CommandFailure.MissingAccount => throw new ProviderAdapterException(ProviderErrorKind.SecretNotFound, "The LastPass account item was not found."),
                _ => throw new ProviderAdapterException(ProviderErrorKind.Unknown, "The LastPass CLI command failed."),
            };
        }
        finally
        {
            _commandGate.Release();
        }
    }

    private async Task LoginAsync(string password, CancellationToken cancellationToken)
    {
        if (_loggedIn)
        {
            return;
        }

        var (output, failure) = await RunAsync(["login", "--force", "--color=never", "--", username], password, cancellationToken).ConfigureAwait(false);
        CryptographicOperations.ZeroMemory(output);
        if (failure != CommandFailure.None)
        {
            throw new ProviderAdapterException(ProviderErrorKind.AuthenticationFailed, "The LastPass CLI could not log in.");
        }
        _loggedIn = true;
    }

    private async Task<(byte[] Output, CommandFailure Failure)> RunAsync(string[] arguments, string password, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(Deadline);
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

        foreach (string key in start.Environment.Keys.Where(key => key.StartsWith("LPASS_", StringComparison.OrdinalIgnoreCase)).ToArray())
        {
            start.Environment.Remove(key);
        }

        start.Environment["LPASS_HOME"] = _home;
        start.Environment["LPASS_AGENT_DISABLE"] = "1";
        start.Environment["LPASS_DISABLE_PINENTRY"] = "1";

        byte[] input = StrictUtf8.GetBytes(password + "\n");
        using var output = new MemoryStream();
        using var diagnostics = new MemoryStream(capacity: MaxDiagnostics + 1);
        using var process = new Process { StartInfo = start };
        bool started = false;
        try
        {
            started = process.Start();
            Task stdout = CaptureAsync(process.StandardOutput.BaseStream, output, MaxOutput, deadline.Token);
            Task stderr = CaptureAsync(process.StandardError.BaseStream, diagnostics, MaxDiagnostics, deadline.Token);
            Task stdin = SendPasswordAsync(process.StandardInput.BaseStream, input, deadline.Token);
            await Task.WhenAll(stdin, stdout, stderr, process.WaitForExitAsync(deadline.Token)).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (output.Length > MaxOutput)
            {
                throw InvalidResponse();
            }

            if (process.ExitCode == 0)
            {
                return (output.ToArray(), CommandFailure.None);
            }

            return ([], ClassifyFailure(arguments[0], diagnostics.GetBuffer().AsSpan(0, (int)diagnostics.Length)));
        }
        catch (System.ComponentModel.Win32Exception) when (!started)
        {
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "Could not start the configured LastPass CLI.");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new ProviderAdapterException(ProviderErrorKind.Unavailable, "The LastPass CLI timed out.");
        }
        catch (IOException)
        {
            throw new ProviderAdapterException(ProviderErrorKind.Unavailable, "Could not communicate with the LastPass CLI.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
            if (started && !process.HasExited)
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch (InvalidOperationException) when (process.HasExited)
                {
                }
                await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
            }

            CryptographicOperations.ZeroMemory(output.GetBuffer().AsSpan(0, (int)output.Length));
            CryptographicOperations.ZeroMemory(diagnostics.GetBuffer().AsSpan(0, (int)diagnostics.Length));
        }
    }

    private static async Task SendPasswordAsync(Stream destination, byte[] input, CancellationToken cancellationToken)
    {
        try
        {
            using (destination)
            {
                await destination.WriteAsync(input, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (IOException)
        {
            // The CLI may exit before reading stdin. Its exit code decides whether the command succeeded.
        }
    }

    private static CommandFailure ClassifyFailure(string command, ReadOnlySpan<byte> diagnostics)
    {
        // Match only fixed diagnostics. stderr can also contain vault metadata and is never logged.
        if (diagnostics.Length <= MaxDiagnostics)
        {
            int end = diagnostics.Length;
            while (end > 0 && diagnostics[end - 1] is (byte)'\r' or (byte)'\n')
            {
                end--;
            }
            ReadOnlySpan<byte> line = diagnostics[(diagnostics[..end].LastIndexOf((byte)'\n') + 1)..end];
            if (command == "show" && line.SequenceEqual("Error: Could not find specified account(s)."u8))
            {
                return CommandFailure.MissingAccount;
            }
            if (command is "show" or "ls" && (line.StartsWith("Error: Could not find session."u8)
                || line.StartsWith("Error: Unable to fetch blob."u8)))
            {
                return CommandFailure.MissingSession;
            }
        }
        return CommandFailure.Other;
    }

    private static readonly object SweepGate = new();
    private static bool _swept;

    /// <summary>
    /// <c>ws-lpass-{user}-{host}-{pid}-</c>: the directory says which OS user, which host and which authority process own it, so a sweep never touches another user's directory,
    /// a directory from another host or container sharing the folder, nor a live sibling (another LastPass instance of this same authority has its own directory but the same pid).
    /// </summary>
    private static string UserStem(string user)
    {
        string safe = new([.. user.Where(char.IsAsciiLetterOrDigit).Take(12)]);

        string host = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Environment.MachineName)))[..6];

        return "ws-lpass-" + (safe.Length == 0 ? "u" : safe) + "-" + host + "-";
    }

    private static readonly string ProcessNonce = Guid.NewGuid().ToString("N")[..6];

    internal static string HomePrefix(string user, int pid, string nonce)
    {
        return UserStem(user) + pid.ToString(System.Globalization.CultureInfo.InvariantCulture) + "-" + nonce + "-";
    }

    /// <summary>
    /// Deletes this user's home directories under <paramref name="root" /> that a crash left behind: those of a process that is gone, and those of the current pid under another
    /// nonce (a restarted authority can get the same pid again, as in a container). Returns how many.
    /// </summary>
    internal static int SweepStaleHomes(string root, string user, Func<int, bool> processAlive, int ownPid, string ownNonce)
    {
        string stem = UserStem(user);
        int swept = 0;
        try
        {
            foreach (string directory in Directory.EnumerateDirectories(root, stem + "*"))
            {
                string[] parts = Path.GetFileName(directory)[stem.Length..].Split('-');
                if (parts.Length < 3 || !int.TryParse(parts[0], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int pid))
                {
                    continue;
                }

                bool stale = pid == ownPid ? parts[1] != ownNonce : !processAlive(pid);
                if (!stale)
                {
                    continue;
                }

                try
                {
                    Directory.Delete(directory, recursive: true);
                    swept++;
                }
                catch (Exception error) when (error is IOException or UnauthorizedAccessException)
                {
                    // Not ours to remove, or in use: leave it.
                }
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
        }

        return swept;
    }

    private static bool ProcessAlive(int pid)
    {
        try
        {
            using System.Diagnostics.Process process = System.Diagnostics.Process.GetProcessById(pid);

            return !process.HasExited;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return true;
        }
    }

    private static string CreateHome()
    {
        string root = OperatingSystem.IsWindows() ? Path.GetTempPath() : "/tmp";
        lock (SweepGate)
        {
            if (!_swept)
            {
                _swept = true;
                SweepStaleHomes(root, Environment.UserName, ProcessAlive, Environment.ProcessId, ProcessNonce);
            }
        }

        string prefix = HomePrefix(Environment.UserName, Environment.ProcessId, ProcessNonce);
        if (OperatingSystem.IsWindows())
        {
            return Directory.CreateTempSubdirectory(prefix).FullName;
        }

        // lpass still probes a Unix socket with its agent disabled. Keep LPASS_HOME short on macOS.
        string path = Path.Combine(root, prefix + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return path;
    }

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
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    public static ProviderAdapterException InvalidResponse()
        => new(ProviderErrorKind.InvalidResponse, "The LastPass CLI returned an invalid response.");

}

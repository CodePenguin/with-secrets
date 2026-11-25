using System.Diagnostics;
using System.Buffers;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace WithSecrets;

/// <summary>Runs dotenvx in the CLI's user context and captures its child environment through a private pipe.</summary>
public static partial class DotenvxRun
{
    public const string CaptureArgument = "--dotenvx-capture";
    internal const string ExecutableVariable = "WITH_SECRETS_DOTENVX_EXECUTABLE";
    private const string PipePrefix = "ws-dotenvx-";
    private const int MaxCaptureBytes = HostService.MaxBodyBytes;
    private static readonly string[] PolicyFiles = ["Envfile", "Dotenvxfile", "Dotenv.toml"];
    private const string ApprovalMarker = "[ACCESS_APPROVAL_REQUIRED]";
    internal const string ApprovalError = "Dotenvx requires another human approval. WithSecrets stopped the launch.";

    internal static bool ValidPublicKey(string key) => key.Length == 0 || PublicKey().IsMatch(key);

    internal static bool IsCredential(string name)
        => name.StartsWith("DOTENV_PRIVATE_KEY", StringComparison.OrdinalIgnoreCase)
            || name.Equals("DOTENVX_ARMOR_TOKEN", StringComparison.OrdinalIgnoreCase)
            || name.Equals("DOTENVX_TOKEN", StringComparison.OrdinalIgnoreCase);

    internal static bool HasPolicy(string directory) => PolicyFiles.Any(name => File.Exists(Path.Combine(directory, name)));

    [GeneratedRegex(@"\A(?:02|03)[A-Fa-f0-9]{64}\z", RegexOptions.CultureInvariant)]
    private static partial Regex PublicKey();

    [GeneratedRegex(@"\Aencrypted:[A-Za-z0-9+/]+={0,2}\z", RegexOptions.CultureInvariant)]
    internal static partial Regex Ciphertext();

    [GeneratedRegex(@"\$(?:[A-Za-z_]|\{|\()", RegexOptions.CultureInvariant)]
    internal static partial Regex Expansion();

    internal static HashSet<string> OutputNames(LaunchRequest launch)
        => new((launch.DotenvxDynamicNames ?? []).Concat(launch.Encrypted.Select(item => item.Variable))
            .Where(name => !EnvDeclarations.IsProtectedVariable(name)), NameComparer);

    private static StringComparer NameComparer => OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    internal static string InputDigest(string workingDirectory, IReadOnlyList<string> files, IReadOnlyList<string>? envHashes = null,
        Func<string, string>? inputPath = null)
    {
        using var text = new MemoryStream();
        using var writer = new BinaryWriter(text);
        for (int index = 0; index < files.Count; index++)
        {
            writer.Write(files[index]);
            string path = Path.GetFullPath(files[index], workingDirectory);
            writer.Write(envHashes?[index] ?? HashFile(inputPath?.Invoke(path) ?? path));
        }

        foreach (string filename in PolicyFiles)
        {
            string path = Path.Combine(workingDirectory, filename);
            path = inputPath?.Invoke(path) ?? path;
            writer.Write(filename);
            writer.Write(File.Exists(path) ? HashFile(path) : "");
        }

        return Convert.ToHexString(SHA256.HashData(text.GetBuffer().AsSpan(0, (int)text.Length)));
    }

    private static string HashFile(string path) => ReadInput(path, (buffer, length) => Convert.ToHexString(SHA256.HashData(buffer.AsSpan(0, length))));

    private static T ReadInput<T>(string path, Func<byte[], int, T> read)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (!stream.CanSeek || stream.Length > EnvDeclarations.MaxFileBytes)
        {
            throw new DotenvxResolutionException();
        }

        int limit = checked((int)EnvDeclarations.MaxFileBytes + 1);
        byte[] bytes = ArrayPool<byte>.Shared.Rent(limit);
        try
        {
            int length = stream.ReadAtLeast(bytes.AsSpan(0, limit), limit, throwOnEndOfStream: false);
            if (length == limit)
            {
                throw new DotenvxResolutionException();
            }

            return read(bytes, length);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(bytes, clearArray: true);
        }
    }

    internal static async Task<Dictionary<string, string>> ResolveAsync(string executable, string workingDirectory,
        IReadOnlyList<string> files, IReadOnlyList<string> names, CancellationToken cancellationToken, string? approvedDigest = null)
    {
        string? entryPoint = Environment.ProcessPath;
        if (!Path.IsPathFullyQualified(executable) || !File.Exists(executable) || entryPoint is null
            || files.Count == 0 || names.Any(EnvDeclarations.IsProtectedVariable))
        {
            throw new DotenvxResolutionException();
        }

        string pipeName = PipePrefix + Guid.NewGuid().ToString("N");
        using var pipe = new NamedPipeServerStream(pipeName, PipeDirection.In, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromMinutes(2));
        CancellationToken token = deadline.Token;
        var start = new ProcessStartInfo(executable)
        {
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add("run");
        start.ArgumentList.Add("--strict");
        start.ArgumentList.Add("--quiet");
        List<FileStream> heldInputs = [];
        int approvalRequired = 0;
        try
        {
            using ProjectSnapshot? snapshot = approvedDigest is not null && !OperatingSystem.IsWindows()
                ? ProjectSnapshot.Create(workingDirectory, files)
                : null;
            Func<string, string>? snapshotPath = snapshot is null ? null : snapshot.PathFor;
            if (snapshot is not null)
            {
                start.WorkingDirectory = snapshot.PathFor(workingDirectory);
            }

            foreach (string file in files)
            {
                start.ArgumentList.Add("-f");
                start.ArgumentList.Add(snapshot?.PathFor(Path.GetFullPath(file, workingDirectory)) ?? file);
            }

            start.ArgumentList.Add("--");
            start.ArgumentList.Add(entryPoint);
            if (string.Equals(Path.GetFileNameWithoutExtension(entryPoint), "dotnet", StringComparison.OrdinalIgnoreCase))
            {
                start.ArgumentList.Add(System.Reflection.Assembly.GetEntryAssembly()!.Location);
            }

            start.ArgumentList.Add(CaptureArgument);
            start.ArgumentList.Add(pipeName);
            foreach (string name in names)
            {
                start.ArgumentList.Add(name);
            }

            if (approvedDigest is not null && OperatingSystem.IsWindows())
            {
                // Preserve original path discovery while denying writes and deletes through Windows file sharing.
                foreach (string path in files.Select(name => Path.GetFullPath(name, workingDirectory))
                    .Concat(PolicyFiles.Select(name => Path.Combine(workingDirectory, name)).Where(File.Exists)))
                {
                    heldInputs.Add(new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read));
                }
            }

            if (approvedDigest is not null && InputDigest(workingDirectory, files, inputPath: snapshotPath) != approvedDigest)
            {
                throw new DotenvxResolutionException();
            }

            using Process process = Process.Start(start) ?? throw new DotenvxResolutionException();
            process.StandardInput.Close();
            Task<Dictionary<string, string>> capture = ReceiveAsync(pipe, names, token);
            Task stdout = process.StandardOutput.BaseStream.CopyToAsync(Stream.Null, token);
            Task stderr = WatchForApprovalAsync(process.StandardError, () =>
            {
                Interlocked.Exchange(ref approvalRequired, 1);
                deadline.Cancel();
            }, token);
            try
            {
                await process.WaitForExitAsync(token).ConfigureAwait(false);
                if (process.ExitCode != 0)
                {
                    throw new DotenvxResolutionException();
                }

                await Task.WhenAll(stdout, stderr).ConfigureAwait(false);
                if (Volatile.Read(ref approvalRequired) != 0)
                {
                    throw new DotenvxResolutionException(approvalRequired: true);
                }

                var values = await capture.WaitAsync(TimeSpan.FromSeconds(5), token).ConfigureAwait(false);
                if (approvedDigest is not null && (InputDigest(workingDirectory, files, inputPath: snapshotPath) != approvedDigest
                    || snapshot is not null && InputDigest(workingDirectory, files) != approvedDigest))
                {
                    throw new DotenvxResolutionException();
                }

                return values;
            }
            finally
            {
                await deadline.CancelAsync().ConfigureAwait(false);
                if (!process.HasExited)
                {
                    try { process.Kill(entireProcessTree: true); }
                    catch (InvalidOperationException) when (process.HasExited) { }
                }

                try { await Task.WhenAll(capture, stdout, stderr).ConfigureAwait(false); }
                catch (Exception error) when (error is IOException or OperationCanceledException or JsonException or DotenvxResolutionException) { }
            }
        }
        catch (Exception) when (Volatile.Read(ref approvalRequired) != 0 && !cancellationToken.IsCancellationRequested)
        {
            throw new DotenvxResolutionException(approvalRequired: true);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException or TimeoutException
            or System.ComponentModel.Win32Exception || error is OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            throw new DotenvxResolutionException();
        }
        finally
        {
            foreach (FileStream input in heldInputs)
            {
                input.Dispose();
            }
        }
    }

    private sealed class ProjectSnapshot(DirectoryInfo directory) : IDisposable
    {
        public string PathFor(string path) => Path.Combine(directory.FullName, Path.GetFullPath(path).TrimStart(Path.DirectorySeparatorChar));

        public static ProjectSnapshot Create(string workingDirectory, IReadOnlyList<string> files)
        {
            var snapshot = new ProjectSnapshot(Directory.CreateTempSubdirectory("ws-dotenvx-"));
            try
            {
                string[] sources = [.. files.Select(path => Path.GetFullPath(path, workingDirectory))];
                string[] policies = [.. PolicyFiles.Select(name => Path.Combine(workingDirectory, name)).Where(File.Exists)];
                foreach (string source in sources.Concat(policies).Distinct(StringComparer.Ordinal))
                {
                    string destination = snapshot.PathFor(source);
                    Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                    ReadInput(source, (bytes, length) =>
                    {
                        File.WriteAllBytes(destination, bytes.AsSpan(0, length));
                        return 0;
                    });
                    if (!OperatingSystem.IsWindows())
                    {
                        File.SetUnixFileMode(destination, UnixFileMode.UserRead);
                    }
                }

                Directory.CreateDirectory(snapshot.PathFor(workingDirectory));
                foreach (string folder in sources.Select(path => Path.GetDirectoryName(path)!).Append(workingDirectory).Distinct(StringComparer.Ordinal))
                {
                    string source = Path.Combine(folder, ".env.keys");
                    string destination = snapshot.PathFor(source);
                    if (File.Exists(source) && !File.Exists(destination))
                    {
                        File.CreateSymbolicLink(destination, source);
                    }
                }

                return snapshot;
            }
            catch
            {
                snapshot.Dispose();
                throw;
            }
        }

        public void Dispose() => directory.Delete(recursive: true);
    }

    private static async Task WatchForApprovalAsync(TextReader stderr, Action refuse, CancellationToken token)
    {
        char[] buffer = new char[1024];
        int matched = 0;
        int read;
        while ((read = await stderr.ReadAsync(buffer, token).ConfigureAwait(false)) > 0)
        {
            for (int i = 0; i < read; i++)
            {
                char current = buffer[i];
                matched = current == ApprovalMarker[matched] ? matched + 1 : current == ApprovalMarker[0] ? 1 : 0;
                if (matched == ApprovalMarker.Length)
                {
                    refuse();
                    return;
                }
            }
        }
    }

    private static async Task<Dictionary<string, string>> ReceiveAsync(NamedPipeServerStream pipe, IReadOnlyList<string> names, CancellationToken token)
    {
        await pipe.WaitForConnectionAsync(token).ConfigureAwait(false);
        byte[] bytes = new byte[MaxCaptureBytes + 1];
        try
        {
            int length = await pipe.ReadAtLeastAsync(bytes, bytes.Length, throwOnEndOfStream: false, cancellationToken: token).ConfigureAwait(false);
            if (length == bytes.Length)
            {
                throw new DotenvxResolutionException();
            }

            return ReadValues(bytes.AsMemory(0, length), names) ?? throw new DotenvxResolutionException();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    internal static Dictionary<string, string>? ReadValues(ReadOnlyMemory<byte> bytes, IReadOnlyList<string>? names)
    {
        using JsonDocument payload = JsonDocument.Parse(bytes);
        if (payload.RootElement.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (payload.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new DotenvxResolutionException();
        }

        var expected = names is null ? null : new HashSet<string>(names, NameComparer);
        var values = new Dictionary<string, string>(NameComparer);
        foreach (JsonProperty item in payload.RootElement.EnumerateObject())
        {
            if (expected?.Remove(item.Name) == false || EnvDeclarations.IsProtectedVariable(item.Name) || item.Value.ValueKind != JsonValueKind.String
                || item.Value.GetString() is not { } value || value.Length > EnvDeclarations.MaxValue || value.Contains('\0')
                || !values.TryAdd(item.Name, value))
            {
                throw new DotenvxResolutionException();
            }
        }

        return values;
    }

    /// <summary>Internal CLI command used only as the child of dotenvx.</summary>
    public static async Task<int> CaptureAsync(string pipeName, IReadOnlyList<string> names)
    {
        if (!pipeName.StartsWith(PipePrefix, StringComparison.Ordinal)
            || !Guid.TryParseExact(pipeName.AsSpan(PipePrefix.Length), "N", out _)
            || names.Count > EnvDeclarations.MaxOrdinary * 2)
        {
            return RunCommand.Usage;
        }

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.Out, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        try
        {
            string[] credentials = [.. Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>()
                .Where(entry => entry.Key is string name && IsCredential(name))
                .Select(entry => entry.Value).OfType<string>().Where(value => value.Length > 0)];
            foreach (string name in names)
            {
                if (EnvDeclarations.IsProtectedVariable(name) || name.Length is 0 or > EnvDeclarations.MaxVariableName
                    || name.Contains('=') || name.Contains('\0'))
                {
                    return RunCommand.Usage;
                }

                if (Environment.GetEnvironmentVariable(name) is { } value
                    && (value.Length > EnvDeclarations.MaxValue || credentials.Any(credential => value.Contains(credential, StringComparison.Ordinal)) || !values.TryAdd(name, value)))
                {
                    return RunCommand.Usage;
                }
            }

            await pipe.ConnectAsync(timeout.Token).ConfigureAwait(false);
            await JsonSerializer.SerializeAsync(pipe, values, cancellationToken: timeout.Token).ConfigureAwait(false);
            return 0;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or OperationCanceledException)
        {
            return RunCommand.Usage;
        }
    }
}

internal sealed class DotenvxResolutionException(bool approvalRequired = false) : Exception
{
    internal bool ApprovalRequired { get; } = approvalRequired;
}

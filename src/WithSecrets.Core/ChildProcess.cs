using System.ComponentModel;
using System.Diagnostics;
using System.Text;

namespace WithSecrets;

/// <summary>Finds the program to run. It never looks in the working directory, which an agent can write to.</summary>
public static class ProgramResolver
{
    private static readonly string[] DefaultWindowsExtensions = [".COM", ".EXE", ".BAT", ".CMD"];

    public static string? Resolve(string program, string workingDirectory, string? pathVariable = null, bool? windows = null, string? pathExt = null)
    {
        bool onWindows = windows ?? OperatingSystem.IsWindows();
        string[] extensions = [];
        if (onWindows)
        {
            extensions = (pathExt ?? Environment.GetEnvironmentVariable("PATHEXT") ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries);
            if (extensions.Length == 0)
            {
                extensions = DefaultWindowsExtensions;
            }
        }

        if (program.Contains('/', StringComparison.Ordinal) || program.Contains('\\', StringComparison.Ordinal))
        {
            return Probe(Path.GetFullPath(program, workingDirectory), extensions, onWindows);
        }

        foreach (string directory in (pathVariable ?? Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            if (!Path.IsPathRooted(directory))
            {
                continue;
            }

            string? found = Probe(Path.Combine(directory.Trim('"'), program), extensions, onWindows);
            if (found is not null)
            {
                return found;
            }
        }

        return null;
    }

    private static string? Probe(string basePath, string[] extensions, bool onWindows)
    {
        if (onWindows)
        {
            string extension = Path.GetExtension(basePath);
            if (extension.Length > 0 && extensions.Contains(extension, StringComparer.OrdinalIgnoreCase) && File.Exists(basePath))
            {
                return basePath;
            }

            return extensions.Select(candidate => basePath + candidate).FirstOrDefault(File.Exists);
        }

        return File.Exists(basePath) ? basePath : null;
    }
}

public sealed record ChildSpec(
    string ResolvedProgram,
    IReadOnlyList<string> Arguments,
    string WorkingDirectory,
    IReadOnlyDictionary<string, string> Secrets);

/// <summary>Runs the program with the secrets as environment variables and redacts what it prints.</summary>
public static class ChildRunner
{
    public static async Task<int> RunAsync(ChildSpec spec, TextWriter stdout, TextWriter stderr)
    {
        ProcessStartInfo start = new(spec.ResolvedProgram)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = new UTF8Encoding(false),
            StandardErrorEncoding = new UTF8Encoding(false),
            WorkingDirectory = spec.WorkingDirectory
        };

        foreach (string argument in spec.Arguments)
        {
            start.ArgumentList.Add(argument);
        }

        // The child never gets the dotenvx private key, even if the agent's own environment holds one.
        foreach (string name in start.Environment.Keys.Where(key => key.StartsWith("DOTENV_PRIVATE_KEY", StringComparison.OrdinalIgnoreCase)).ToList())
        {
            start.Environment.Remove(name);
        }

        foreach ((string name, string value) in spec.Secrets)
        {
            start.Environment[name] = value;
        }

        Process process;
        try
        {
            process = Process.Start(start) ?? throw new InvalidOperationException("The process did not start.");
        }
        catch (Exception error) when (error is Win32Exception or InvalidOperationException)
        {
            await stderr.WriteLineAsync($"with-secrets: cannot start '{spec.ResolvedProgram}': {error.Message}");

            return 127;
        }

        using (process)
        {
            Task output = Pump(process.StandardOutput, new StreamRedactor(spec.Secrets.Values), stdout);
            Task errors = Pump(process.StandardError, new StreamRedactor(spec.Secrets.Values), stderr);
            await process.WaitForExitAsync();
            await Task.WhenAll(output, errors);

            return process.ExitCode;
        }
    }

    private static async Task Pump(TextReader reader, StreamRedactor redactor, TextWriter writer)
    {
        char[] buffer = new char[4096];
        int count;
        while ((count = await reader.ReadAsync(buffer)) > 0)
        {
            string safe = redactor.Push(new string(buffer, 0, count));
            if (safe.Length > 0)
            {
                await writer.WriteAsync(safe);
                await writer.FlushAsync();
            }
        }

        string rest = redactor.Finish();
        if (rest.Length > 0)
        {
            await writer.WriteAsync(rest);
        }

        await writer.FlushAsync();
    }
}

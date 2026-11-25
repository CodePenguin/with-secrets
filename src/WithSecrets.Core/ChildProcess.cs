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
    IReadOnlyDictionary<string, string> Secrets,
    IReadOnlyDictionary<string, string>? Ordinary = null,
    IReadOnlyDictionary<string, string>? InheritedEnvironment = null,
    IReadOnlyList<string>? RedactAlso = null);

/// <summary>Runs the program with the secrets as environment variables and redacts what it prints.</summary>
public static class ChildRunner
{
    /// <summary>Environment variables removed before launch: each one makes an interpreter or runtime load code from somewhere.</summary>
    internal static readonly string[] CodeLoadingVariables =
    [
        "NODE_OPTIONS", "BASH_ENV", "ENV", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "PYTHONINSPECT", "PERL5OPT", "PERL5LIB",
        "RUBYOPT", "RUBYLIB", "DOTNET_STARTUP_HOOKS", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
        "PERLLIB", "ZDOTDIR", "PYTHONUSERBASE", "PYTHONWARNINGS", "NODE_PATH", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_EXEC_PATH",
        "GIT_SSH_COMMAND", "GIT_ASKPASS", "SHELLOPTS", "BASHOPTS", "PS4", "PS0", "PROMPT_COMMAND", "LD_AUDIT"
    ];

    /// <summary>Environment variable names starting with these are removed too (bash exports functions as BASH_FUNC_name%%).</summary>
    internal static readonly string[] CodeLoadingPrefixes = ["BASH_FUNC_", "DYLD_"];

    /// <summary>True when the child must not inherit this variable (see <see cref="CodeLoadingVariables" />).</summary>
    internal static bool IsCodeLoading(string name, bool caseInsensitive)
    {
        StringComparison comparison = caseInsensitive ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

        return CodeLoadingVariables.Any(item => string.Equals(item, name, comparison)) || CodeLoadingPrefixes.Any(prefix => name.StartsWith(prefix, comparison));
    }

    /// <summary>Prepares, starts and waits for the program, with no gate in between (the caller has none to pass).</summary>
    public static async Task<int> RunAsync(ChildSpec spec, TextWriter stdout, TextWriter stderr)
    {
        PreparedChild prepared = Prepare(spec);
        Process? process = prepared.Start(out string? failure);
        if (process is null)
        {
            await stderr.WriteLineAsync(failure);

            return 127;
        }

        return await prepared.WaitAsync(process, stdout, stderr);
    }

    /// <summary>
    /// Builds the child's start information and environment without starting anything: the inherited environment (the process's
    /// own when the spec has none), minus the code-loading variables, plus the ordinary .env values, plus the secrets. The
    /// result holds the secret values until it is started or discarded.
    /// </summary>
    public static PreparedChild Prepare(ChildSpec spec)
    {
        (string file, string? raw) = Launch(spec);
        ProcessStartInfo start = new(file)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            StandardOutputEncoding = new UTF8Encoding(false),
            StandardErrorEncoding = new UTF8Encoding(false),
            WorkingDirectory = spec.WorkingDirectory,

            // On Windows the child gets a console of its own instead of sharing the one of this process, so Ctrl+C in a service
            // window does not reach it; only the client's cancel ends it. No effect elsewhere.
            CreateNoWindow = true
        };

        if (raw is not null)
        {
            start.Arguments = raw;
        }
        else
        {
            foreach (string argument in spec.Arguments)
            {
                start.ArgumentList.Add(argument);
            }
        }

        // The environment is the one the sender had, when the request carries it; otherwise it is this process's own.
        if (spec.InheritedEnvironment is { } inherited)
        {
            start.Environment.Clear();
            foreach ((string name, string value) in inherited)
            {
                if (name.Length > 0 && !name.Contains('=', StringComparison.Ordinal) && !name.Contains('\0', StringComparison.Ordinal) && !value.Contains('\0', StringComparison.Ordinal))
                {
                    start.Environment[name] = value;
                }
            }
        }

        // The child never gets the pairing credential (WITH_SECRETS_PAIRING, WITH_SECRETS_PAIRING_FILE), whoever put it in the environment it is built from.
        foreach (string name in start.Environment.Keys.Where(PairingInput.IsPairingVariable).ToList())
        {
            start.Environment.Remove(name);
        }

        // The child never gets the dotenvx private key, even if the agent's own environment holds one.
        foreach (string name in start.Environment.Keys.Where(DotenvxRun.IsCredential).ToList())
        {
            start.Environment.Remove(name);
        }

        // Variables that make a program load code the approval page did not show. Names are compared without regard to case on
        // Windows, where the environment ignores it.
        foreach (string name in start.Environment.Keys.Where(key => IsCodeLoading(key, OperatingSystem.IsWindows())).ToList())
        {
            start.Environment.Remove(name);
        }

        // Ordinary .env values: all of them were shown in full on the approval page, code-loading names included, so they are passed
        // on. Only a Dotenvx private key never goes to the program. Not redacted, not secret.
        foreach ((string name, string value) in spec.Ordinary ?? new Dictionary<string, string>())
        {
            if (!DotenvxRun.IsCredential(name))
            {
                start.Environment[name] = value;
            }
        }

        foreach ((string name, string value) in spec.Secrets)
        {
            // Final filter (the run refuses before it gets here): a secret value, which the approval page cannot show, never goes to a variable that changes which code runs.
            if (EnvDeclarations.IsProtectedVariable(name))
            {
                continue;
            }

            start.Environment[name] = value;
        }

        return new PreparedChild(start, spec);
    }

    /// <summary>
    /// For cmd.exe on Windows, the argument string with the whole command after /c in one pair of quotes (without /s, cmd takes off
    /// the first and the last quote). .NET's own quoting of a path with spaces and a bracket, such as Program Files (x86), is
    /// not read back right by cmd. The words were checked to have no quote or special character. Null for any other program.
    /// </summary>
    internal static string? CmdLine(ChildSpec spec) => Launch(spec).Raw;

    private static bool IsBatch(string path) => Path.GetExtension(path) is { } extension && (extension.Equals(".cmd", StringComparison.OrdinalIgnoreCase) || extension.Equals(".bat", StringComparison.OrdinalIgnoreCase));

    // cmd reads , ; = and white space as the end of the command word, and ( ) as grouping.
    private static string QuoteForCmd(string word) => word.Any(c => char.IsWhiteSpace(c) || c is '(' or ')' or ',' or ';' or '=' or '&' or '^') ? "\"" + word + "\"" : word;

    /// <summary>
    /// The program to start and, for cmd.exe on Windows, the raw argument string (null: use the argument list). A .cmd or .bat file
    /// is started as <c>cmd.exe /d /c "path" args</c> so that the AutoRun commands of the registry are skipped. The first word
    /// after /c, when it is a batch file, is always in quotes (cmd would cut it at a comma, semicolon or equals sign).
    /// </summary>
    internal static (string File, string? Raw) Launch(ChildSpec spec)
    {
        if (!OperatingSystem.IsWindows() || spec.Arguments.Any(argument => argument.Contains('"', StringComparison.Ordinal)))
        {
            return (spec.ResolvedProgram, null);
        }

        if (IsBatch(spec.ResolvedProgram))
        {
            string args = string.Concat(spec.Arguments.Select(argument => " " + QuoteForCmd(argument)));

            return (Path.Combine(Environment.SystemDirectory, "cmd.exe"), "/d /c \"\"" + spec.ResolvedProgram + "\"" + args + "\"");
        }

        if (!Path.GetFileNameWithoutExtension(spec.ResolvedProgram).Equals("cmd", StringComparison.OrdinalIgnoreCase))
        {
            return (spec.ResolvedProgram, null);
        }

        int flag = spec.Arguments.ToList().FindIndex(argument => argument is "/c" or "/C" or "/k" or "/K" or "/r" or "/R");
        if (flag < 0 || flag + 1 >= spec.Arguments.Count)
        {
            return (spec.ResolvedProgram, null);
        }

        string[] tail = [.. spec.Arguments.Skip(flag + 1)];
        string first = IsBatch(tail[0]) ? "\"" + tail[0] + "\"" : QuoteForCmd(tail[0]);
        string rest = string.Concat(tail.Skip(1).Select(argument => " " + QuoteForCmd(argument)));

        return (spec.ResolvedProgram, string.Join(' ', spec.Arguments.Take(flag + 1)) + " \"" + first + rest + "\"");
    }

    internal static async Task Pump(TextReader reader, StreamRedactor redactor, TextWriter writer)
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

/// <summary>
/// A child that is ready to start: its environment (with the secret values) is built and nothing is running. <see cref="Start" />
/// starts it; <see cref="Discard" /> throws the environment away, for a launch that was cancelled or invalidated first.
/// </summary>
public sealed class PreparedChild
{
    private readonly ProcessStartInfo _start;
    private readonly ChildSpec _spec;

    internal PreparedChild(ProcessStartInfo start, ChildSpec spec)
    {
        _start = start;
        _spec = spec;
    }

    /// <summary>True after <see cref="Discard" />: the environment is gone and the program was not started.</summary>
    public bool IsDiscarded { get; private set; }

    /// <summary>True after a successful <see cref="Start" />.</summary>
    public bool IsStarted { get; private set; }

    /// <summary>The number of variables still held (0 after a discard or a start). For tests; never the values.</summary>
    internal int EnvironmentCount => _start.Environment.Count;

    /// <summary>Starts the program. Returns it, or null with a line to show (names the program and the system's reason, never a value). The environment is dropped from here either way.</summary>
    public Process? Start(out string? failure)
    {
        failure = null;
        if (IsDiscarded || IsStarted)
        {
            failure = "with-secrets: the program was not started (already started or discarded)";

            return null;
        }

        try
        {
            Process process = Process.Start(_start) ?? throw new InvalidOperationException("The process did not start.");
            IsStarted = true;

            return process;
        }
        catch (Exception error) when (error is Win32Exception or InvalidOperationException)
        {
            failure = $"with-secrets: cannot start '{_spec.ResolvedProgram}': {error.Message}";

            return null;
        }
        finally
        {
            // The values are in the child now, or nowhere. The strings themselves cannot be wiped (see SecretValues).
            _start.Environment.Clear();
        }
    }

    /// <summary>Drops the environment: this child will never start.</summary>
    public void Discard()
    {
        _start.Environment.Clear();
        IsDiscarded = true;
    }

    /// <summary>Waits for a started program, writing its redacted output, and returns its exit code.</summary>
    public async Task<int> WaitAsync(Process started, TextWriter stdout, TextWriter stderr)
    {
        using (started)
        {
            // The child gets no standard input (it reads end of file at once), so nothing can feed it code the page did not show.
            started.StandardInput.Close();
            Task output = ChildRunner.Pump(started.StandardOutput, new StreamRedactor(_spec.Secrets.Values.Concat(_spec.RedactAlso ?? [])), stdout);
            Task errors = ChildRunner.Pump(started.StandardError, new StreamRedactor(_spec.Secrets.Values.Concat(_spec.RedactAlso ?? [])), stderr);
            await started.WaitForExitAsync();
            await Task.WhenAll(output, errors);

            return started.ExitCode;
        }
    }
}

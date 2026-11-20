using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Microsoft.Data.Sqlite;

namespace WithSecrets;

/// <summary>What an approval covers. <see cref="Key" /> changes when anything the person approved changes.</summary>
public sealed record Fingerprint(string Key, IReadOnlyDictionary<string, string> Files);

/// <summary>
/// Identifies a request for approval reuse. The key is made of four things: the secret names, the full path of the program, the
/// working folder, and the full path and content of the script being executed. The script is the program itself
/// (<c>./check.sh</c>), or, when an interpreter runs it, the first argument that names an existing small file
/// (<c>pwsh -File run.ps1</c>, <c>node app.js</c>). Two programs with the same name in different places are different programs.
/// Flags, other arguments, and the agent's reason are not part of the key.
/// </summary>
public static class RequestFingerprint
{
    /// <summary>Larger files (programs such as dotnet.exe) are not hashed. Scripts are small.</summary>
    public const long MaxHashedFileBytes = 1024 * 1024;

    public static Fingerprint Compute(ApprovalRequest request)
    {
        SortedDictionary<string, string> files = new(StringComparer.Ordinal);
        AddHash(files, request.ResolvedProgram, request.WorkingDirectory);
        int script = PathExpander.ScriptArgumentIndex(request.Program, request.Arguments, request.WorkingDirectory);
        if (script >= 0)
        {
            AddHash(files, request.Arguments[script], request.WorkingDirectory);
        }

        StringBuilder text = new();
        text.Append(Normalize(request.ResolvedProgram)).Append('\0');
        text.Append(Normalize(request.WorkingDirectory)).Append('\0').Append('\u0001');
        foreach (string name in request.SecretNames.OrderBy(name => name, StringComparer.Ordinal))
        {
            text.Append(name).Append('\0');
        }

        text.Append('\u0001');
        // A plain --secrets run (every variable named like its secret, no .env) keeps the key it always had.
        if (request.Mappings is not null && (request.Mappings.Any(pair => pair.Variable != pair.Secret) || request.EnvFiles is { Count: > 0 } || request.EnvNames is { Count: > 0 } || request.EnvValues is { Count: > 0 } || request.Decrypts is { Count: > 0 }))
        {
            // Every pair and every file the declarations came from are part of what was approved.
            foreach (SecretMapping pair in request.Mappings.OrderBy(pair => pair.Variable, StringComparer.Ordinal))
            {
                text.Append(pair.Variable).Append('\0').Append(pair.Secret).Append('\0');
            }

            text.Append('\u0002');
            foreach (string file in (request.EnvFiles ?? []).Order(StringComparer.Ordinal))
            {
                text.Append(Normalize(file)).Append('\0');
            }

            text.Append('\u0002');
            foreach (DecryptItem item in (request.Decrypts ?? []).OrderBy(item => item.Variable, StringComparer.Ordinal))
            {
                text.Append(item.Variable).Append('\0').Append(Normalize(item.File)).Append('\0').Append(item.KeySecret).Append('\0').Append(item.CipherSha256).Append('\0');
            }

            text.Append('\u0002');
            foreach (string name in (request.EnvNames ?? []).Order(StringComparer.Ordinal))
            {
                text.Append(name).Append('\0');
            }

            text.Append('\u0002');
            foreach (KeyValuePair<string, string> variable in (request.EnvValues ?? new Dictionary<string, string>()).OrderBy(item => item.Key, StringComparer.Ordinal))
            {
                text.Append(variable.Key).Append('\0').Append(variable.Value).Append('\0');
            }

            text.Append('\u0001');
        }

        // The environment the program inherits (a request over the API) is part of what was approved. Absent: the key is unchanged.
        if (request.InheritedEnvironment is { } inherited)
        {
            text.Append((char)3).Append(EnvironmentBinding.Hash(inherited)).Append((char)3);
        }

        foreach ((string path, string hash) in files)
        {
            text.Append(Normalize(path)).Append('\0').Append(hash).Append('\0');
        }

        string key = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text.ToString())));

        return new Fingerprint(key, files);
    }

    /// <summary>A full path with no trailing separator. Windows paths ignore case, so they are compared in upper case.</summary>
    private static string Normalize(string path)
    {
        string full = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        return OperatingSystem.IsWindows() ? full.ToUpperInvariant() : full;
    }

    /// <summary>Adds the file's hash when the text names an existing file of a hashable size. Returns true when it did.</summary>
    private static bool AddHash(SortedDictionary<string, string> files, string candidate, string workingDirectory)
    {
        try
        {
            string full = Path.GetFullPath(candidate, workingDirectory);
            FileInfo info = new(full);
            if (!info.Exists || info.Length > MaxHashedFileBytes)
            {
                return false;
            }

            files[full] = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(full)));

            return true;
        }
        catch (Exception error) when (error is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return false;
        }
    }
}

/// <summary>
/// The times the administration web app offers when a grant is made: the fixed <see cref="Steps" /> up to the ceiling
/// <paramref name="MaxMinutes" /> (the <c>reuseMaxMinutes</c> setting).
/// </summary>
public sealed record ReuseOffer(int MaxMinutes)
{
    /// <summary>10 minutes, 1 hour, 4 hours, 8 hours.</summary>
    public static IReadOnlyList<int> Steps { get; } = [10, 60, 240, 480];

    /// <summary>No time is offered (no grant can be made).</summary>
    public static ReuseOffer Off { get; } = new(0);

    /// <summary>The times offered, shortest first: every step up to the ceiling.</summary>
    public IReadOnlyList<int> Choices => [.. Steps.Where(step => step <= MaxMinutes)];

    /// <summary>True when at least one time is offered.</summary>
    public bool IsOn => Choices.Count > 0;

    /// <summary>The value that stands for a grant with no end (the passkey signs it like a time: "reuse=1000000").</summary>
    public const int Always = 1_000_000;

    /// <summary>The times, then Always: what a request that makes a grant offers.</summary>
    public IReadOnlyList<int> WithAlways => [.. Choices, Always];

    /// <summary>True for every offered time and for Always. Anything else is refused.</summary>
    public bool Allows(int minutes) => minutes == Always || Choices.Contains(minutes);
}

/// <summary>
/// The grant time settings. They come from the settings in state.db in the protected store folder, never from the environment or
/// the command line, because the agent controls both of those.
/// </summary>
public static class ReuseSettings
{
    /// <summary>The default ceiling (reuseMaxMinutes).</summary>
    public const int DefaultMaxMinutes = 480;

    /// <summary>The lowest ceiling: the first step.</summary>
    public const int MinMaxMinutes = 10;

    /// <summary>The highest ceiling, and the longest grant ever honoured: 24 hours.</summary>
    public const int MaxMinutes = 1440;

    /// <summary>From state.db: the stored ceiling, the default when none is stored, and no time when the settings cannot be used.</summary>
    public static ReuseOffer Load(StateDatabase db)
    {
        ToolSettings settings = ToolSettings.Load(db, out string? error);

        return error is null ? settings.Reuse : ReuseOffer.Off;
    }
}

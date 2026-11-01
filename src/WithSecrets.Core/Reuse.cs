using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

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
        int script = PathExpander.ScriptArgumentIndex(request.Arguments, request.WorkingDirectory);
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

public sealed record GrantEntry(string Key, DateTimeOffset Approved, DateTimeOffset Expires);

/// <summary>
/// Remembers approvals for a limited time. The expiry is fixed when the person approves. Reuse never extends it, so an agent
/// cannot keep an approval alive by running the command again. A file that cannot be read means no approvals, so the person is
/// asked again.
/// </summary>
public sealed class GrantStore(string path, Func<DateTimeOffset>? clock = null)
{
    private readonly Func<DateTimeOffset> _now = clock ?? (() => DateTimeOffset.UtcNow);

    public bool TryGet(string key, out DateTimeOffset approved, out DateTimeOffset expires)
    {
        DateTimeOffset now = _now();
        GrantEntry? entry = Load().FirstOrDefault(item => item.Key == key && item.Expires > now && item.Approved <= now);
        approved = entry?.Approved ?? default;
        expires = entry?.Expires ?? default;

        return entry is not null;
    }

    /// <summary>Returns false when the grant could not be saved. The person is then asked again next time.</summary>
    public bool Add(string key, TimeSpan lifetime)
    {
        DateTimeOffset now = _now();
        List<GrantEntry> entries = [.. Load().Where(item => item.Expires > now && item.Key != key)];
        entries.Add(new GrantEntry(key, now, now + lifetime));

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
            string temp = path + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(entries));
            File.Move(temp, path, true);

            return true;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>Ends every approval now.</summary>
    public void Clear()
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            // An unreadable file is already treated as no approvals.
        }
    }

    private List<GrantEntry> Load()
    {
        try
        {
            return File.Exists(path) ? JsonSerializer.Deserialize<List<GrantEntry>>(File.ReadAllText(path)) ?? [] : [];
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException)
        {
            return [];
        }
    }
}

/// <summary>
/// How long an approval is reused. It comes from a settings file in the protected store folder, never from the environment or
/// the command line, because the agent controls both of those.
/// </summary>
public static class ReuseSettings
{
    public const int DefaultMinutes = 10;
    public const int MaxMinutes = 60;

    /// <summary>No file: the default. A file that cannot be understood: no reuse. A number is limited to 0..60 minutes.</summary>
    public static TimeSpan Load(string path)
    {
        if (!File.Exists(path))
        {
            return TimeSpan.FromMinutes(DefaultMinutes);
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(File.ReadAllText(path));
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return TimeSpan.Zero;
            }

            if (!document.RootElement.TryGetProperty("reuseMinutes", out JsonElement value))
            {
                return TimeSpan.FromMinutes(DefaultMinutes);
            }

            return value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out int minutes)
                ? TimeSpan.FromMinutes(Math.Clamp(minutes, 0, MaxMinutes))
                : TimeSpan.Zero;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException)
        {
            return TimeSpan.Zero;
        }
    }
}

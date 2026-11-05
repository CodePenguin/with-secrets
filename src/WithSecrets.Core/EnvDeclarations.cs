using System.Text;
using System.Text.RegularExpressions;

namespace WithSecrets;

/// <summary>
/// One secret handed to the program: the environment variable it is given as, and the store name it comes from. They are equal
/// for <c>--secrets NAME</c>; <c>TOKEN=secret://team/GITHUB</c> maps variable TOKEN to store name team/GITHUB.
/// </summary>
public sealed record SecretMapping(string Variable, string Secret)
{
    /// <summary>"NAME" when both are equal, else "VARIABLE &lt;- secret NAME": the form the approval page shows.</summary>
    public string Display => Variable == Secret ? Secret : Variable + " <- secret " + Secret;
}

/// <summary>
/// What the .env files and --secrets ask for, read once: the files used, the final secret pairs, and the ordinary variables
/// to pass on. The approval page, the fingerprint, the audit row and the launch all use this one object; nothing is read again.
/// </summary>
public sealed record EnvPlan(
    IReadOnlyList<string> Files,
    IReadOnlyList<SecretMapping> Mappings,
    IReadOnlyDictionary<string, string> Ordinary,
    IReadOnlyList<string> Notes,
    IReadOnlyList<string>? Links = null);

/// <summary>An <see cref="EnvPlan" />, or why not (a message with names and file:line, never a value).</summary>
public sealed record EnvResult(EnvPlan? Plan, string? Error);

/// <summary>
/// Reads project .env files (Dotenvx style, no expansion, no multiline) and composes them with the environment and --secrets.
/// An error names the file and line or the variable, never the value, because terminal output is public.
/// </summary>
public static partial class EnvDeclarations
{
    public const long MaxFileBytes = 256 * 1024;

    /// <summary>The most secret pairs one run may ask for.</summary>
    public const int MaxPairs = 50;

    /// <summary>The most -f files, ordinary variables, characters of a variable name and of an ordinary value: over is an error, never cut.</summary>
    public const int MaxFiles = 8;
    public const int MaxOrdinary = 50;
    public const int MaxVariableName = 64;
    public const int MaxValue = 512;

    public const string ReferencePrefix = "secret://";

    private const string EncryptedPrefix = "encrypted:";

    [GeneratedRegex("^[A-Za-z_][A-Za-z0-9_]*\\z", RegexOptions.CultureInvariant)]
    private static partial Regex VariableName();

    /// <summary>Variables a reference may not set, besides the code-loading ones: they decide which program or library is loaded.</summary>
    private static readonly string[] ProtectedVariables = ["PATH", "PATHEXT", "COMSPEC", "SystemRoot", "windir"];

    /// <summary>True when a secret reference may not be given to this variable.</summary>
    public static bool IsProtectedVariable(string name)
    {
        return IsSink(name) || ChildRunner.IsCodeLoading(name, true) || name.StartsWith("DOTENV_PRIVATE_KEY", StringComparison.OrdinalIgnoreCase)
            || ProtectedVariables.Any(item => string.Equals(item, name, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Variables a secret must not be steered into: proxies (the value becomes a host), and git commit identity (it lands in public metadata).</summary>
    private static bool IsSink(string name)
    {
        string[] starts = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "GIT_AUTHOR_", "GIT_COMMITTER_"];

        return name.EndsWith("_PROXY", StringComparison.OrdinalIgnoreCase) || starts.Any(item => name.StartsWith(item, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>One declaration read from a file: the name, the value and its line.</summary>
    public sealed record Entry(string Name, string Value, int Line);

    /// <summary>
    /// The declarations of one file, in order (a name repeated in a file: the last line wins), or an error. Dotenvx style:
    /// <c>NAME=value</c>, <c>#</c> comment lines, optional <c>export </c>, blank lines, and single, double or no quotes (double
    /// quotes allow \n, \r, \t, \" and \\). A comment may follow a value after a space. Nothing is expanded.
    /// </summary>
    public static (IReadOnlyList<Entry>? Entries, string? Error) Parse(string path, string text)
    {
        Dictionary<string, Entry> byName = new(StringComparer.Ordinal);
        List<string> order = [];
        string[] lines = text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        for (int index = 0; index < lines.Length; index++)
        {
            int number = index + 1;
            string line = lines[index].TrimStart();
            if (line.Length == 0 || line[0] == '#')
            {
                continue;
            }

            if (line.StartsWith("export", StringComparison.Ordinal) && line.Length > 6 && char.IsWhiteSpace(line[6]))
            {
                line = line[7..].TrimStart();
            }

            int equals = line.IndexOf('=', StringComparison.Ordinal);
            if (equals <= 0)
            {
                return (null, Where(path, number, "expected NAME=value"));
            }

            string name = line[..equals].TrimEnd();
            if (!VariableName().IsMatch(name))
            {
                return (null, Where(path, number, "the variable name is not valid (letters, digits and _, not starting with a digit)"));
            }

            string? value = ParseValue(line[(equals + 1)..], out string? problem);
            if (value is null)
            {
                return (null, Where(path, number, problem!));
            }

            if (value.Contains('\0', StringComparison.Ordinal))
            {
                return (null, Where(path, number, "the value contains a NUL character"));
            }

            if (!byName.ContainsKey(name))
            {
                order.Add(name);
            }

            byName[name] = new Entry(name, value, number);
        }

        return ([.. order.Select(name => byName[name])], null);
    }

    private static string Where(string path, int line, string message) => ApprovalSummary.Clean(path) + ":" + line + ": " + message;

    private static string? ParseValue(string raw, out string? problem)
    {
        problem = null;
        string text = raw.TrimStart();
        if (text.Length > 0 && text[0] is '"' or '\'')
        {
            char quote = text[0];
            StringBuilder value = new();
            int index = 1;
            for (; index < text.Length; index++)
            {
                char character = text[index];
                if (character == quote)
                {
                    break;
                }

                if (quote == '"' && character == '\\' && index + 1 < text.Length)
                {
                    char next = text[index + 1];
                    string? replaced = next switch { 'n' => "\n", 'r' => "\r", 't' => "\t", '"' => "\"", '\\' => "\\", _ => null };
                    if (replaced is not null)
                    {
                        value.Append(replaced);
                        index++;

                        continue;
                    }
                }

                value.Append(character);
            }

            if (index >= text.Length)
            {
                problem = "the quote is not closed (a value must be on one line)";

                return null;
            }

            string rest = text[(index + 1)..].Trim();
            if (rest.Length > 0 && rest[0] != '#')
            {
                problem = "unexpected text after the closing quote";

                return null;
            }

            return value.ToString();
        }

        // No quotes: up to a " #" comment, white space trimmed at both ends.
        int comment = -1;
        for (int index = 0; index < text.Length; index++)
        {
            if (text[index] == '#' && index > 0 && char.IsWhiteSpace(text[index - 1]))
            {
                comment = index;

                break;
            }
        }

        return (comment >= 0 ? text[..comment] : text).Trim();
    }

    /// <summary>
    /// The store name of a <c>secret://[folder/]*NAME</c> value, or null with the reason. The rest after the prefix must be a
    /// name <see cref="SecretNames.IsValid" /> accepts; anything else (empty, '//', a query, a fragment, spaces, '%', '..') is refused.
    /// </summary>
    public static string? ParseReference(string value, out string? problem)
    {
        problem = null;
        if (!value.StartsWith(ReferencePrefix, StringComparison.OrdinalIgnoreCase))
        {
            problem = "not a secret reference";

            return null;
        }

        string name = value[ReferencePrefix.Length..];
        if (!SecretNames.IsValid(name))
        {
            problem = "not a valid secret reference. Use secret://NAME or secret://folder/NAME (up to 3 folders; folders use letters, digits, _ . -; NAME is UPPER_SNAKE_CASE)";

            return null;
        }

        return name;
    }

    /// <summary>
    /// Reads the files once and composes them. <paramref name="files" /> null or empty: the default <c>.env</c> in
    /// <paramref name="workingDirectory" /> (no search upward; absent is no declarations). Files given: exactly those, each must exist.
    /// First file wins per name. An existing variable of <paramref name="environment" /> beats an ordinary value (or an
    /// encrypted one). A <c>secret://</c> reference beats it, and is added to the <paramref name="secrets" /> of --secrets.
    /// </summary>
    public static EnvResult Compose(IReadOnlyList<string>? files, string workingDirectory, IEnumerable<string> secrets, Func<string, string?> environment)
    {
        StringComparer names = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        bool explicitFiles = files is { Count: > 0 };
        List<string> paths = [];
        foreach (string file in explicitFiles ? files! : [".env"])
        {
            string full;
            try
            {
                full = Path.GetFullPath(file, workingDirectory);
            }
            catch (Exception error) when (error is ArgumentException or NotSupportedException or PathTooLongException)
            {
                return Failure("the env file name is not valid: " + ApprovalSummary.Clean(file));
            }

            if (!paths.Contains(full, names))
            {
                paths.Add(full);
            }
        }

        if (paths.Count > MaxFiles)
        {
            return Failure("at most " + MaxFiles + " env files at a time (" + paths.Count + " given)");
        }

        List<string> links = [];
        List<string> used = [];
        Dictionary<string, (Entry Entry, string File)> final = new(names);
        List<string> finalOrder = [];
        foreach (string path in paths)
        {
            if (!File.Exists(path))
            {
                if (explicitFiles)
                {
                    return Failure("the env file " + ApprovalSummary.Clean(path) + " does not exist");
                }

                continue;
            }

            string text;
            try
            {
                // One open, shared for reading only; the cap is enforced while reading, so a file swapped or endless (a device) cannot exhaust memory.
                if ((File.GetAttributes(path) & (FileAttributes.Directory | FileAttributes.Device)) != 0)
                {
                    return Failure("the env file " + ApprovalSummary.Clean(path) + " is not a regular file");
                }

                using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                if (!stream.CanSeek)
                {
                    return Failure("the env file " + ApprovalSummary.Clean(path) + " is not a regular file");
                }

                byte[] buffer = new byte[MaxFileBytes + 1];
                int length = 0;
                int read;
                while (length < buffer.Length && (read = stream.Read(buffer, length, buffer.Length - length)) > 0)
                {
                    length += read;
                }

                if (length > MaxFileBytes)
                {
                    return Failure("the env file " + ApprovalSummary.Clean(path) + " is larger than " + MaxFileBytes / 1024 + " KB");
                }

                text = new UTF8Encoding(false, true).GetString(buffer, 0, length).TrimStart((char)0xFEFF);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or DecoderFallbackException)
            {
                return Failure("cannot read the env file " + ApprovalSummary.Clean(path) + " as UTF-8 text (" + error.GetType().Name + ")");
            }

            used.Add(path);
            if (FileMark(path, workingDirectory) is { } mark)
            {
                links.Add(mark);
            }

            (IReadOnlyList<Entry>? entries, string? parseError) = Parse(path, text);
            if (entries is null)
            {
                return Failure(parseError!);
            }

            foreach (Entry entry in entries)
            {
                if (final.TryAdd(entry.Name, (entry, path)))
                {
                    finalOrder.Add(entry.Name);
                }
            }
        }

        // --secrets first: the variable is the name, the secret the same name. A name with a folder has no variable name.
        List<SecretMapping> mappings = [];
        Dictionary<string, SecretMapping> byVariable = new(names);
        foreach (string secret in secrets)
        {
            if (secret.Contains('/', StringComparison.Ordinal))
            {
                return Failure("--secrets cannot name " + ApprovalSummary.Clean(secret) + ": a name with a folder is not an environment variable name. Use a .env reference instead: VARIABLE=secret://" + ApprovalSummary.Clean(secret));
            }

            if (byVariable.TryAdd(secret, new SecretMapping(secret, secret)))
            {
                mappings.Add(byVariable[secret]);
            }
        }

        Dictionary<string, string> ordinary = new(names);
        List<string> notes = [];
        foreach (string name in finalOrder)
        {
            (Entry entry, string file) = final[name];
            string where = ApprovalSummary.Clean(file) + ":" + entry.Line;
            if (name.Length > MaxVariableName)
            {
                return Failure("variable name longer than " + MaxVariableName + " characters (" + where + ")");
            }

            if (entry.Value.StartsWith(ReferencePrefix, StringComparison.OrdinalIgnoreCase))
            {
                string? store = ParseReference(entry.Value, out string? problem);
                if (store is null)
                {
                    return Failure("variable " + name + " (" + where + "): " + problem);
                }

                if (IsProtectedVariable(name))
                {
                    return Failure("variable " + name + " (" + where + "): a secret cannot be given to this variable, because it changes which code runs");
                }

                if (byVariable.TryGetValue(name, out SecretMapping? existing))
                {
                    if (existing.Secret != store)
                    {
                        return Failure("variable " + name + " is given by --secrets and by a different reference in " + where);
                    }

                    continue;
                }

                SecretMapping mapping = new(name, store);
                byVariable[name] = mapping;
                mappings.Add(mapping);

                continue;
            }

            // --secrets is explicit: it beats an ordinary value of the same name; an environment variable beats a .env value.
            if (byVariable.ContainsKey(name) || environment(name) is not null)
            {
                continue;
            }

            if (entry.Value.StartsWith(EncryptedPrefix, StringComparison.Ordinal))
            {
                return Failure("variable " + name + " (" + where + "): Dotenvx encrypted values in .env are not supported yet");
            }

            if (ChildRunner.IsCodeLoading(name, OperatingSystem.IsWindows()) || name.StartsWith("DOTENV_PRIVATE_KEY", StringComparison.OrdinalIgnoreCase))
            {
                notes.Add("the .env variable " + name + " was left out of the program's environment (it is a code-loading variable). A program that reads the .env itself may still load it");

                continue;
            }

            if (entry.Value.Length > MaxValue)
            {
                return Failure("variable " + name + " (" + where + "): the value is longer than " + MaxValue + " characters");
            }

            ordinary[name] = entry.Value;
        }

        if (ordinary.Count > MaxOrdinary)
        {
            return Failure("at most " + MaxOrdinary + " ordinary variables from .env at a time (" + ordinary.Count + " given)");
        }

        if (mappings.Count > MaxPairs)
        {
            return Failure("at most " + MaxPairs + " secrets at a time (" + mappings.Count + " asked for)");
        }

        return new EnvResult(new EnvPlan(used, mappings, ordinary, notes, links), null);
    }

    /// <summary>A Link:-style mark when the file is outside the working directory or is a link (symlink, junction, reparse point), else null.</summary>
    private static string? FileMark(string path, string workingDirectory)
    {
        try
        {
            string relative = Path.GetRelativePath(workingDirectory, path);
            bool outside = relative == ".." || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) || Path.IsPathRooted(relative);
            FileInfo info = new(path);
            FileSystemInfo? target = info.ResolveLinkTarget(true);
            bool reparse = info.Attributes.HasFlag(FileAttributes.ReparsePoint);
            string text = ApprovalSummary.Clean(path);
            if (target is not null)
            {
                return $"Env file {text} -> {ApprovalSummary.Clean(target.FullName)} (a link)" + (outside ? "; outside the working directory" : "");
            }

            if (reparse)
            {
                return $"Env file {text} is a reparse point (a junction or link)" + (outside ? "; outside the working directory" : "");
            }

            return outside ? $"Env file {text} is outside the working directory" : null;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException)
        {
            return null;
        }
    }

    private static EnvResult Failure(string message) => new(null, message);
}

/// <summary>--needs: what the current project would ask for. Names only. No approval, no passkey, no value.</summary>
public static class NeedsCommand
{
    public static int Run(ISecretSource store, IReadOnlyList<string>? files, string workingDirectory, TextWriter stdout, TextWriter stderr, Func<string, string?>? environment = null)
    {
        EnvResult composed = EnvDeclarations.Compose(files, workingDirectory, [], environment ?? Environment.GetEnvironmentVariable);
        if (composed.Plan is not { } plan)
        {
            stderr.WriteLine("with-secrets: " + composed.Error);

            return RunCommand.Usage;
        }

        IReadOnlyList<string> inStore;
        try
        {
            inStore = store.ListNames();
        }
        catch (Exception error)
        {
            stderr.WriteLine("with-secrets: cannot read the secret store: " + error.Message);

            return RunCommand.StoreError;
        }

        foreach (string note in plan.Notes)
        {
            stderr.WriteLine("with-secrets: " + note);
        }

        if (plan.Files.Count == 0)
        {
            stdout.WriteLine("Env files: none (no .env in the working directory)");
        }

        foreach (string file in plan.Files)
        {
            stdout.WriteLine("Env file: " + ApprovalSummary.Clean(file));
        }

        foreach (string name in plan.Ordinary.Keys.Order(StringComparer.Ordinal))
        {
            stdout.WriteLine("Variable: " + name);
        }

        foreach (SecretMapping mapping in plan.Mappings)
        {
            stdout.WriteLine("Secret: " + mapping.Variable + " <- secret " + mapping.Secret + "  " + (inStore.Contains(mapping.Secret, StringComparer.Ordinal) ? "in store" : "NOT IN STORE"));
        }

        return 0;
    }
}

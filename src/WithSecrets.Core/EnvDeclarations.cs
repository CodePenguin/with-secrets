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
    IReadOnlyList<string>? Links = null,
    IReadOnlyList<EncryptedValue>? Encrypted = null);

/// <summary>
/// A Dotenvx <c>encrypted:</c> value that is the final declaration of <see cref="Variable" />, with the store secret that holds its
/// private key. The ciphertext stays in the plan (read once) and is never printed: <see cref="ToString" /> has names only.
/// </summary>
public sealed record EncryptedValue(string Variable, string File, string KeySecret, string Ciphertext)
{
    public override string ToString() => "encrypted " + Variable + " (" + File + ") key " + KeySecret;

    /// <summary>The upper-case hex SHA-256 of the ciphertext text (UTF-8). A hash of a ciphertext is not a secret; it ties an approval to exactly this ciphertext.</summary>
    public string Sha256 => DecryptItem.HashOf(Ciphertext);

    /// <summary>What the page, the fingerprint and the audit row get: no ciphertext.</summary>
    public DecryptItem ToItem() => new(Variable, File, KeySecret, Sha256);
}

/// <summary>
/// What the approval page, the fingerprint and the audit row know of an encrypted value: names, the file, and the SHA-256 of the
/// ciphertext (<see cref="CipherSha256" />, full upper-case hex), never the ciphertext itself.
/// </summary>
public sealed record DecryptItem(string Variable, string File, string KeySecret, string CipherSha256)
{
    /// <summary>The characters of <see cref="CipherSha256" /> the page and the audit row show: enough to compare with the committed file, short enough to read.</summary>
    public const int ShortLength = 12;

    public string Short => CipherSha256.Length >= ShortLength ? CipherSha256[..ShortLength] : CipherSha256;

    public static string HashOf(string ciphertext) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(ciphertext)));
}

/// <summary>An <see cref="EnvPlan" />, or why not (a message with names and file:line, never a value).</summary>
public sealed record EnvResult(EnvPlan? Plan, string? Error);

/// <summary>
/// Reads project .env files (Dotenvx style, no expansion, no multiline) and composes them with the environment and --secrets.
/// An error names the file and line or the variable, never the value, because terminal output is public.
/// </summary>
public static partial class EnvDeclarations
{
    public const long MaxFileBytes = 1024 * 1024;

    /// <summary>The most secret pairs one run may ask for.</summary>
    public const int MaxPairs = 200;

    /// <summary>The most -f files, ordinary variables, characters of a variable name and of an ordinary value: over is an error, never cut.</summary>
    public const int MaxFiles = 16;
    public const int MaxOrdinary = 200;
    public const int MaxVariableName = 128;
    public const int MaxValue = 4096;

    /// <summary>The most distinct variables one file may declare (every kind counts): parsing stops there.</summary>
    public const int MaxEntriesPerFile = MaxPairs + MaxOrdinary;

    /// <summary>The longest <c>encrypted:</c> text: base64 of a Dotenvx ciphertext (key, nonce, tag, overhead) of a value of <see cref="MaxValue" /> characters, with room for multi-byte characters.</summary>
    public const int MaxEncrypted = 4 * (MaxValue * 3 + 200) / 3 + 16;

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
            if (order.Count > MaxEntriesPerFile)
            {
                // Stop here: a file of a million tiny lines must not be built up in memory before a limit is looked at.
                return (null, Where(path, number, "more than " + MaxEntriesPerFile + " variables in one file"));
            }
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
            problem = "not a valid secret reference. Use secret://NAME or secret://folder/NAME (up to 3 folders; folders use letters, digits, _ . -; NAME is letters, digits and _ starting with a letter)";

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

            if (SecretNames.IsPrivateKeyName(secret))
            {
                return Failure("--secrets cannot name " + ApprovalSummary.Clean(secret) + ": a Dotenvx private key is used only to decrypt .env values and is never given to a program");
            }

            if (byVariable.TryAdd(secret, new SecretMapping(secret, secret)))
            {
                mappings.Add(byVariable[secret]);
            }
        }

        Dictionary<string, string> ordinary = new(names);
        List<EncryptedValue> encrypted = [];
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

                if (SecretNames.IsPrivateKeyName(store))
                {
                    return Failure("variable " + name + " (" + where + "): " + ApprovalSummary.Clean(store) + " is a Dotenvx private key: it is used only to decrypt .env values and is never given to a program");
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

            // An encrypted value is one the page cannot show, so it may not go where a reference may not go. This is decided by the name alone,
            // before any override: PATH and the like must not be safe only because the operating system happens to have them.
            if (entry.Value.StartsWith(EncryptedPrefix, StringComparison.Ordinal) && IsProtectedVariable(name) && !name.StartsWith("DOTENV_PRIVATE_KEY", StringComparison.OrdinalIgnoreCase))
            {
                return Failure("variable " + name + " (" + where + "): an encrypted value cannot be given to this variable, because it changes which code runs");
            }

            // --secrets is explicit: it beats an ordinary value of the same name; an environment variable beats a .env value.
            if (byVariable.ContainsKey(name) || environment(name) is not null)
            {
                continue;
            }

            // The program never gets a Dotenvx private key, whatever the .env says.
            if (name.StartsWith("DOTENV_PRIVATE_KEY", StringComparison.OrdinalIgnoreCase))
            {
                notes.Add("the .env variable " + name + " was left out of the program's environment (a Dotenvx private key is never given to a program)");

                continue;
            }

            if (entry.Value.StartsWith(EncryptedPrefix, StringComparison.Ordinal))
            {
                string? keySecret = KeySecretFor(file);
                if (keySecret is null)
                {
                    return Failure("variable " + name + " (" + where + "): the Dotenvx key name for this file is not a valid secret name");
                }

                if (entry.Value.Length > MaxEncrypted)
                {
                    return Failure("variable " + name + " (" + where + "): the encrypted value is longer than " + MaxEncrypted + " characters");
                }

                encrypted.Add(new EncryptedValue(name, file, keySecret, entry.Value));

                continue;
            }

            if (entry.Value.Length > MaxValue)
            {
                return Failure("variable " + name + " (" + where + "): the value is longer than " + MaxValue + " characters");
            }

            ordinary[name] = entry.Value;
        }

        if (ordinary.Count + encrypted.Count > MaxOrdinary)
        {
            return Failure("at most " + MaxOrdinary + " ordinary variables from .env at a time (" + (ordinary.Count + encrypted.Count) + " given)");
        }

        if (mappings.Count > MaxPairs)
        {
            return Failure("at most " + MaxPairs + " secrets at a time (" + mappings.Count + " asked for)");
        }

        return new EnvResult(new EnvPlan(used, mappings, ordinary, notes, links, encrypted), null);
    }

    /// <summary>
    /// The store secret that holds the Dotenvx private key for values read from <paramref name="file" />, by Dotenvx convention:
    /// <c>DOTENV_PRIVATE_KEY</c> for <c>.env</c>, <c>DOTENV_PRIVATE_KEY_SUFFIX</c> for <c>.env.suffix</c> (suffix in upper case, '-'
    /// and '.' become '_'); any other file name uses <c>DOTENV_PRIVATE_KEY</c>. The suffix must be ASCII letters, digits, '.', '-', '_'
    /// (checked before upper-casing, so no other character is folded onto a letter); otherwise, or when the result is not a valid
    /// secret name, null.
    /// </summary>
    public static string? KeySecretFor(string file)
    {
        const string Base = "DOTENV_PRIVATE_KEY";
        string name = Path.GetFileName(file);
        string key = Base;
        if (name.StartsWith(".env.", StringComparison.OrdinalIgnoreCase) && name.Length > 5)
        {
            string suffix = name[5..];
            if (suffix.Any(c => !(c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-' or '.' or '_')))
            {
                return null;
            }

            key = Base + "_" + new string([.. suffix.Select(c => c is '-' or '.' ? '_' : c is >= 'a' and <= 'z' ? (char)(c - 32) : c)]);
        }

        return SecretNames.IsValid(key) ? key : null;
    }

    /// <summary>
    /// The plan of a launch request that came over the API, checked again with the rules that built it (the sender is not trusted
    /// to have applied them): at most <see cref="MaxFiles" /> files, at most <see cref="MaxPairs" /> pairs, variable names of
    /// the grammar and length, no secret given to a protected variable, ordinary variables without NUL, within the value limit and
    /// no variable twice, encrypted values checked like references (see below), and the listed ordinary names equal to the names of the values. The .env files are
    /// not read again: the plan is what the sender read once. The link marks of the files (outside the working directory, a link)
    /// are made here, from the paths, because the person must see them. An error names a variable or a limit, never a value.
    /// </summary>
    public static EnvResult FromRequest(LaunchRequest request)
    {
        StringComparer names = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        if (request.EnvFiles.Count > MaxFiles)
        {
            return Failure("at most " + MaxFiles + " env files at a time (" + request.EnvFiles.Count + " given)");
        }

        foreach (string file in request.EnvFiles)
        {
            if (file.Length == 0 || file.Contains('\0', StringComparison.Ordinal) || !Path.IsPathFullyQualified(file))
            {
                return Failure("an env file name is not a full path: " + ApprovalSummary.Clean(file));
            }
        }

        if (request.Mappings.Count > MaxPairs)
        {
            return Failure("at most " + MaxPairs + " secrets at a time (" + request.Mappings.Count + " asked for)");
        }

        HashSet<string> variables = new(names);
        List<SecretMapping> mappings = [];
        foreach (LaunchMapping mapping in request.Mappings)
        {
            if (!VariableName().IsMatch(mapping.Variable) || mapping.Variable.Length > MaxVariableName)
            {
                return Failure("variable " + ApprovalSummary.Clean(mapping.Variable) + " is not a valid variable name (letters, digits and _, not starting with a digit, at most " + MaxVariableName + " characters)");
            }

            if (IsProtectedVariable(mapping.Variable))
            {
                return Failure("variable " + mapping.Variable + ": a secret cannot be given to this variable, because it changes which code runs");
            }

            if (!SecretNames.IsValid(mapping.Secret))
            {
                return Failure("variable " + mapping.Variable + ": " + "invalid secret name " + ApprovalSummary.Clean(mapping.Secret));
            }

            if (!variables.Add(mapping.Variable))
            {
                return Failure("variable " + mapping.Variable + " is given twice");
            }

            mappings.Add(new SecretMapping(mapping.Variable, mapping.Secret));
        }

        if (request.EnvVariables.Count + request.Encrypted.Count > MaxOrdinary)
        {
            return Failure("at most " + MaxOrdinary + " ordinary variables from .env at a time (" + (request.EnvVariables.Count + request.Encrypted.Count) + " given)");
        }

        foreach ((string name, string value) in request.EnvVariables)
        {
            if (!VariableName().IsMatch(name) || name.Length > MaxVariableName)
            {
                return Failure("variable " + ApprovalSummary.Clean(name) + " is not a valid variable name");
            }

            // A code-loading name is passed when it is an ordinary value: the page shows every ordinary value in full. Only a private key never goes on.
            if (name.StartsWith("DOTENV_PRIVATE_KEY", StringComparison.OrdinalIgnoreCase))
            {
                return Failure("variable " + name + " is a Dotenvx private key name and cannot be passed");
            }

            if (value.Length > MaxValue || value.Contains('\0', StringComparison.Ordinal))
            {
                return Failure("variable " + name + ": the value is longer than " + MaxValue + " characters or contains NUL");
            }

            if (!variables.Add(name))
            {
                return Failure("variable " + name + " is both a secret and an ordinary value");
            }
        }

        if (!request.EnvNames.SequenceEqual(request.EnvVariables.Keys.Order(StringComparer.Ordinal), StringComparer.Ordinal))
        {
            return Failure("the listed ordinary variable names are not the names of the ordinary values");
        }

        // Encrypted values: the sender is not trusted to have applied the rules either. The page cannot show what they decrypt to, so the name
        // rule is the one of a secret reference (nothing that changes which code runs), the key secret is the one the file name gives, and
        // the file is one of the listed .env files.
        List<EncryptedValue> encrypted = [];
        foreach (LaunchEncrypted item in request.Encrypted)
        {
            if (!VariableName().IsMatch(item.Variable) || item.Variable.Length > MaxVariableName)
            {
                return Failure("variable " + ApprovalSummary.Clean(item.Variable) + " is not a valid variable name");
            }

            if (IsProtectedVariable(item.Variable))
            {
                return Failure("variable " + item.Variable + ": an encrypted value cannot be given to this variable, because it changes which code runs");
            }

            if (!request.EnvFiles.Contains(item.File, StringComparer.Ordinal))
            {
                return Failure("variable " + item.Variable + ": the encrypted value names a file that is not one of the env files");
            }

            if (KeySecretFor(item.File) is not { } keySecret || keySecret != item.KeySecret)
            {
                return Failure("variable " + item.Variable + ": the key secret is not the one the file name gives");
            }

            if (!item.Ciphertext.StartsWith(EncryptedPrefix, StringComparison.Ordinal) || item.Ciphertext.Length > MaxEncrypted || item.Ciphertext.Contains(' ', StringComparison.Ordinal))
            {
                return Failure("variable " + item.Variable + ": the encrypted value is not an encrypted: text of at most " + MaxEncrypted + " characters");
            }

            if (!request.SecretNames.Contains(item.KeySecret, StringComparer.Ordinal))
            {
                return Failure("variable " + item.Variable + ": the key secret " + ApprovalSummary.Clean(item.KeySecret) + " is not among the requested secrets");
            }

            if (!variables.Add(item.Variable))
            {
                return Failure("variable " + item.Variable + " is given twice");
            }

            encrypted.Add(new EncryptedValue(item.Variable, item.File, item.KeySecret, item.Ciphertext));
        }

        List<string> links = [];
        foreach (string file in request.EnvFiles)
        {
            if (FileMark(file, request.WorkingDirectory) is { } mark)
            {
                links.Add(mark);
            }
        }

        return new EnvResult(new EnvPlan(request.EnvFiles, mappings, new Dictionary<string, string>(request.EnvVariables, names), [], links, encrypted), null);
    }

    /// <summary>A Link:-style mark when the file is outside the working directory or is a link (symlink, junction, reparse point), else null.</summary>
    internal static string? FileMark(string path, string workingDirectory)
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
            stdout.WriteLine("Secret: " + mapping.Variable + " <- secret " + mapping.Secret + "  " + (inStore.Contains(mapping.Secret, StringComparer.Ordinal) ? "in store" : "NOT IN STORE") + CaseNote(mapping.Secret, inStore));
        }

        foreach (EncryptedValue value in plan.Encrypted ?? [])
        {
            stdout.WriteLine("Encrypted: " + value.Variable + " (encrypted, file " + ApprovalSummary.Clean(value.File) + ") key " + value.KeySecret + " " + (inStore.Contains(value.KeySecret, StringComparer.Ordinal) ? "in store" : "NOT IN STORE") + CaseNote(value.KeySecret, inStore));
        }

        return 0;
    }

    /// <summary>"; differs only by case from: X" when another stored name equals the name but for case (names are case-sensitive), else "".</summary>
    private static string CaseNote(string name, IReadOnlyList<string> inStore)
    {
        IReadOnlyList<string> twins = SecretNames.CaseTwins(name, inStore);
        IReadOnlyList<string> alike = SecretNames.LookAlikes(name, inStore);

        return (twins.Count == 0 ? "" : "; differs only by case from: " + string.Join(", ", twins.Select(ApprovalSummary.Clean))) + (alike.Count == 0 ? "" : "; looks like: " + string.Join(", ", alike.Select(ApprovalSummary.Clean)));
    }
}

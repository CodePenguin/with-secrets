using System.Globalization;
using System.Text;

namespace WithSecrets;

/// <summary>
/// A script file as the approval text shows it: the SHA-256 (upper-case hex) and the size of its bytes, and its text when the
/// bytes are valid UTF-8 without NUL; null <see cref="Text" /> means "binary file". Read once, from the same bytes that are hashed.
/// </summary>
public sealed record ScriptView(string Sha256, long Length, string? Text, string Path = "", bool Guessed = false, bool Bom = false, bool NonAscii = false)
{
    /// <summary>Reads the file. Throws <see cref="IOException" /> or <see cref="UnauthorizedAccessException" /> when it cannot be read.</summary>
    public static ScriptView Read(string path) => FromBytes(File.ReadAllBytes(path), path);

    /// <summary>The view of these bytes (the contents of the file at <paramref name="path" />).</summary>
    public static ScriptView FromBytes(byte[] bytes, string path)
    {
        string hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes));
        if (Array.IndexOf(bytes, (byte)0) >= 0)
        {
            return new ScriptView(hash, bytes.Length, null, path);
        }

        try
        {
            ReadOnlySpan<byte> content = bytes.AsSpan();
            if (content.StartsWith(Encoding.UTF8.Preamble))
            {
                content = content[Encoding.UTF8.Preamble.Length..];
            }

            return new ScriptView(hash, bytes.Length, new UTF8Encoding(false, true).GetString(content), path, Bom: content.Length != bytes.Length, NonAscii: content.IndexOfAnyExceptInRange((byte)0, (byte)127) >= 0);
        }
        catch (DecoderFallbackException)
        {
            return new ScriptView(hash, bytes.Length, null, path);
        }
    }
}

/// <summary>
/// Builds the text the person reads before approving. The agent controls the command, the directory and the reason, so
/// every one of them is stripped of line breaks and control characters. Otherwise an agent could fake a line such as
/// "Secrets: none".
/// </summary>
public static class ApprovalSummary
{
    public const int MaxReasonLength = 200;

    /// <summary>The start of the line that names the request (its fingerprint key) in the text the person signs.</summary>
    public const string RequestIdPrefix = "Request id: ";

    /// <summary>The start of the line with the time the page was made (server UTC, round-trip format) in the text the person signs.</summary>
    public const string IssuedPrefix = "Page issued: ";

    /// <summary>The page issued line for <paramref name="time" />, in UTC.</summary>
    public static string IssuedLine(DateTimeOffset time) => IssuedPrefix + time.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

    /// <summary>
    /// The text the person reads on the approval page. Every line the agent controls starts with a fixed label and has its
    /// line breaks marked, so the agent cannot add a line of its own (such as a request id line).
    /// </summary>
    public static string BuildMessage(ApprovalRequest request, bool showValues = true)
    {
        StringBuilder text = new();
        text.Append("Allow an agent to use secrets?").Append('\n');
        // Each name with its source, such as "DB_URL (global)", when the request says where it comes from.
        text.Append("Secrets: ").Append(string.Join(", ", request.SecretNames.Select(name =>
            request.Sources is not null && request.Sources.TryGetValue(name, out string? source) ? name + " (" + Clean(source) + ")" : name))).Append('\n');
        text.Append("Run: ").Append(Clean(CommandLine(request.ResolvedProgram, request.Arguments))).Append('\n');
        foreach (string link in request.Links ?? [])
        {
            text.Append("Link: ").Append(Clean(link)).Append('\n');
        }

        text.Append("In: ").Append(Clean(request.WorkingDirectory)).Append('\n');
        text.Append("Agent says: ").Append(Truncate(Clean(request.Reason), MaxReasonLength));
        if (Policy.InlineCode(request.Program, request.Arguments) is { } inline)
        {
            text.Append('\n').Append(InlineBlock(inline));
        }

        // Every file that will be read as code: a program that is itself a text file, then the script it is given.
        if (request.ProgramFile is { } programFile)
        {
            text.Append('\n').Append(ScriptBlock(programFile));
        }

        if (request.Script is { } script)
        {
            text.Append('\n').Append(ScriptBlock(script));
        }

        // Ordinary variables that change which code runs, where data is sent or how git behaves: one block, before the long .env lists. The approval
        // page shows it as its own section above the text and the approve control (the program gets these values as written; the page is the only control).
        AppendCodeChanges(text, request, showValues);

        // The .env block comes after the command and the code, so a long .env cannot push them out of sight. Every pair is on its own
        // line; every ordinary value is shown (the page is the control for variables the program may treat as code); the terminal
        // echo (showValues false) lists names only.
        if (request.EnvFiles is { Count: > 0 } || request.Decrypts is { Count: > 0 } || request.Mappings is { } mapped && mapped.Any(pair => pair.Variable != pair.Secret))
        {
            foreach (string file in request.EnvFiles ?? [])
            {
                text.Append('\n').Append("Env file: ").Append(Clean(file));
            }

            foreach (SecretMapping pair in request.Mappings ?? [])
            {
                text.Append('\n').Append("Pair: ").Append(Clean(pair.Display)).Append(pair.Variable != pair.Secret ? " (renamed)" : "");
            }

            AppendDecrypts(text, request);
        }

        if (request.InheritedEnvironment is { } inherited)
        {
            text.Append((char)10).Append(EnvironmentBinding.Line(inherited));
        }

        // The variables of the warning block above are not listed again.
        HashSet<string> warned = [.. CodeChanges(request).Select(item => item.Name)];
        if (showValues && request.EnvValues?.Where(item => !warned.Contains(item.Key)).OrderBy(item => item.Key, StringComparer.Ordinal).ToList() is { Count: > 0 } values)
        {
            text.Append('\n').Append("Other variables from .env (values shown):");
            foreach ((string name, string value) in values)
            {
                text.Append('\n').Append(CodeMarker).Append(Clean(name + "=" + value));
            }
        }
        else if (request.EnvNames?.Where(name => !warned.Contains(name)).ToList() is { Count: > 0 } others)
        {
            text.Append('\n').Append("Other variables from .env (names only): ").Append(string.Join(", ", others.Select(Clean)));
        }

        if (request.Reuse is { IsOn: true } reuse && request.Heading is null)
        {
            text.Append('\n').Append($"Approve for a time (up to {reuse.Choices[^1]} min) also covers the same program, script, folder, and secrets until it ends, whatever the other arguments. Approve once covers only this run.");
        }

        foreach (string extra in request.ExtraLines ?? [])
        {
            text.Append((char)10).Append(Clean(extra));
        }

        if (request.RequestId is { Length: > 0 } id)
        {
            text.Append('\n').Append(RequestIdPrefix).Append(Clean(id));
        }

        return text.ToString();
    }

    /// <summary>The most inline code characters the text shows.</summary>
    public const int MaxInlineCharacters = 4000;

    /// <summary>The most script lines the text shows.</summary>
    public const int MaxScriptLines = 200;

    /// <summary>The most script bytes (UTF-8) the text shows.</summary>
    public const int MaxScriptBytes = 16 * 1024;

    /// <summary>The heading of the warning block (the page shows the block, from its "Warning:" line to <see cref="CodeChangesCover" />, as its own section).</summary>
    public const string CodeChangesHeading = "This run changes how the program loads code or where it sends data";

    /// <summary>The last line of the warning block.</summary>
    public const string CodeChangesCover = "Your approval covers exactly these values.";

    /// <summary>The start of the line that gives the reason for the variable above it in the warning block.</summary>
    public const string CodeChangesWhy = "  Why: ";

    private const string LoadsCodeReason = "loads code: the program, or a tool it starts, loads or runs code that the variable names.";
    private const string LibraryPathReason = "changes the library path: the program may load libraries or modules from the places the variable names.";
    private const string NetworkReason = "routes network traffic: requests may go through the address the variable names.";
    private const string GitReason = "changes git behaviour: it can change which settings or program git uses, or who a commit is by.";

    /// <summary>
    /// The ordinary variables of the request that change which code runs, where data is sent or how git behaves, by name (ordinal order), with
    /// the one-line reason for the class of each. A Dotenvx private key is never given to the program, so it is not listed.
    /// </summary>
    public static IReadOnlyList<(string Name, string Reason)> CodeChanges(ApprovalRequest request)
    {
        return [.. (request.EnvValues?.Keys ?? request.EnvNames ?? []).Where(name => !name.StartsWith("DOTENV_PRIVATE_KEY", StringComparison.OrdinalIgnoreCase) && EnvDeclarations.IsProtectedVariable(name))
            .Order(StringComparer.Ordinal).Select(name => (name, ReasonFor(name)))];
    }

    private static string ReasonFor(string name)
    {
        string upper = name.ToUpperInvariant();
        if (upper.StartsWith("GIT_", StringComparison.Ordinal))
        {
            return GitReason;
        }

        if (upper.EndsWith("_PROXY", StringComparison.Ordinal))
        {
            return NetworkReason;
        }

        if (upper is "LD_LIBRARY_PATH" or "NODE_PATH" or "PYTHONPATH" or "PYTHONHOME" or "PYTHONUSERBASE" or "PERL5LIB" or "PERLLIB" or "RUBYLIB"
            || upper.StartsWith("DYLD_", StringComparison.Ordinal) && upper != "DYLD_INSERT_LIBRARIES")
        {
            return LibraryPathReason;
        }

        return LoadsCodeReason;
    }

    private static void AppendCodeChanges(StringBuilder text, ApprovalRequest request, bool showValues)
    {
        IReadOnlyList<(string Name, string Reason)> changes = CodeChanges(request);
        if (changes.Count == 0)
        {
            return;
        }

        text.Append('\n').Append("Warning: ").Append(CodeChangesHeading).Append('.');
        foreach ((string name, string reason) in changes)
        {
            string shown = showValues && request.EnvValues is { } values && values.TryGetValue(name, out string? value) ? name + "=" + value : name;
            text.Append('\n').Append(CodeMarker).Append(Clean(shown));
            text.Append('\n').Append(CodeChangesWhy).Append(reason);
        }

        text.Append('\n').Append(CodeChangesCover);
    }

    /// <summary>
    /// Starts every line of agent-written code in the text. No line the agent writes can start a page line (such as
    /// "Request id: ") because each one starts with this. The notices of this program never do.
    /// </summary>
    public const string CodeMarker = "  | ";

    internal static string InlineBlock(string code)
    {
        StringBuilder text = new("Inline code:");
        string shown = code;
        int more = 0;
        if (code.Length > MaxInlineCharacters)
        {
            int length = char.IsHighSurrogate(code[MaxInlineCharacters - 1]) ? MaxInlineCharacters - 1 : MaxInlineCharacters;
            shown = code[..length];
            more = code.Length - length;
        }

        foreach (string line in Lines(shown))
        {
            text.Append('\n').Append(CodeMarker).Append(Clean(line));
        }

        if (more > 0)
        {
            text.Append('\n').Append($"...cut ({more} more characters)");
        }

        return text.ToString();
    }

    /// <summary>
    /// The encrypted values: names, the key secret and a short fingerprint of each ciphertext, never a value or a ciphertext. The key comes first and the
    /// file (whose folders the agent chooses) last, so a path cannot pose as the rest of the line. The page also says that anyone with the public key can
    /// write such a value, and warns for each value whose file is not the project's own.
    /// </summary>
    private static void AppendDecrypts(StringBuilder text, ApprovalRequest request)
    {
        if (request.Decrypts is not { Count: > 0 } decrypts)
        {
            return;
        }

        foreach (DecryptItem item in decrypts)
        {
            text.Append('\n').Append("decrypt with secret ").Append(Clean(item.KeySecret)).Append(": ").Append(Clean(item.Variable)).Append(" (cipher sha256 ").Append(Clean(item.Short)).Append(") from ").Append(Clean(item.File));
        }

        text.Append('\n').Append("Encrypted values are not shown. Anyone who has the public key in a .env file can write one, so a value is not proof that you made it: compare each cipher fingerprint with the committed file.");
        foreach (DecryptItem item in decrypts)
        {
            if (!IsProjectsOwnEnvFile(item.File, request.WorkingDirectory))
            {
                text.Append('\n').Append("Warning: ").Append(Clean(item.Variable)).Append(" is decrypted from a file that is not this project's own .env file (a .env or .env.NAME directly in the working folder): ").Append(Clean(item.File)).Append(". A value copied from another file or project decrypts with the same key.");
            }
        }
    }

    /// <summary>True when the file is a <c>.env</c> or <c>.env.NAME</c> directly in the working folder.</summary>
    internal static bool IsProjectsOwnEnvFile(string file, string workingDirectory)
    {
        try
        {
            string name = Path.GetFileName(file);
            string folder = Path.GetDirectoryName(Path.GetFullPath(file)) ?? "";
            string work = Path.GetFullPath(workingDirectory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            StringComparison comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

            return (name.Equals(".env", comparison) || name.StartsWith(".env.", comparison) && name.Length > 5) && string.Equals(folder.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), work, comparison);
        }
        catch (Exception error) when (error is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    internal static string ScriptBlock(ScriptView script)
    {
        StringBuilder text = new();
        if (script.Path.Length > 0)
        {
            text.Append("Script file: ").Append(Clean(script.Path)).Append(script.Guessed ? " (guessed from the arguments, not verified)" : "").Append('\n');
        }

        text.Append("Script SHA-256: ").Append(script.Sha256).Append('\n');
        if (script.Text is null)
        {
            return text.Append($"Script contents: binary file, {script.Length} bytes (not shown)").ToString();
        }

        List<string> lines = Lines(script.Text);
        if (lines.Count == 0)
        {
            return text.Append("Script contents: empty file").ToString();
        }

        text.Append("Script contents:");
        int bytes = 0;
        int shown = 0;
        bool partial = false;
        foreach (string line in lines.Take(MaxScriptLines))
        {
            int size = Encoding.UTF8.GetByteCount(line) + 1;
            string piece = line;
            if (bytes + size > MaxScriptBytes)
            {
                piece = FitBytes(line, MaxScriptBytes - bytes - 1);
                partial = true;
            }

            if (piece.Length > 0 || !partial)
            {
                text.Append('\n').Append(CodeMarker).Append(Clean(piece));
                shown++;
            }

            if (partial)
            {
                break;
            }

            bytes += size;
        }

        if (partial || shown < lines.Count)
        {
            text.Append('\n').Append($"...cut: showing {shown} of {lines.Count} lines").Append(partial && shown > 0 ? " (last line cut)" : "");
        }

        return text.ToString();
    }

    /// <summary>The longest start of the line that is at most <paramref name="bytes" /> in UTF-8, never splitting a character.</summary>
    private static string FitBytes(string line, int bytes)
    {
        int used = 0;
        int end = 0;
        foreach (System.Text.Rune rune in line.EnumerateRunes())
        {
            used += rune.Utf8SequenceLength;
            if (used > bytes)
            {
                break;
            }

            end += rune.Utf16SequenceLength;
        }

        return line[..end];
    }

    /// <summary>Tabs become 4 spaces; line breaks (LF, CRLF, CR) split lines; one final line break does not add an empty line.</summary>
    private static List<string> Lines(string value)
    {
        List<string> lines = [.. value.Replace("\t", "    ", StringComparison.Ordinal).Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n').Split('\n')];
        if (lines.Count > 0 && lines[^1].Length == 0)
        {
            lines.RemoveAt(lines.Count - 1);
        }

        return lines;
    }

    /// <summary>The command line with quotes around any argument that needs them.</summary>
    public static string CommandLine(string program, IReadOnlyList<string> arguments)
    {
        return string.Join(' ', new[] { Quote(program) }.Concat(arguments.Select(Quote)));
    }

    internal static string Quote(string argument)
    {
        if (argument.Length > 0 && argument.All(character => !char.IsWhiteSpace(character) && character != '"'))
        {
            return argument;
        }

        // The rules of CommandLineToArgvW: backslashes are doubled when a quote (or the closing quote) follows them.
        StringBuilder quoted = new("\"");
        int slashes = 0;
        foreach (char character in argument)
        {
            if (character == '\\')
            {
                slashes++;
                continue;
            }

            quoted.Append('\\', character == '"' ? slashes * 2 + 1 : slashes).Append(character);
            slashes = 0;
        }

        return quoted.Append('\\', slashes * 2).Append('"').ToString();
    }

    /// <summary>
    /// Replaces characters that can change what the person sees with a visible mark: control characters and line or paragraph
    /// separators (line breaks), and format characters such as bidi overrides and zero-width characters (they can reorder or hide text).
    /// </summary>
    public static string Clean(string value)
    {
        StringBuilder text = new(value.Length);
        foreach (char character in value)
        {
            text.Append(Mark(character) ?? character);
        }

        return text.ToString();
    }

    private static char? Mark(char character)
    {
        return char.GetUnicodeCategory(character) switch
        {
            UnicodeCategory.Control or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator => '⏎',
            UnicodeCategory.Format => '□',
            _ => null
        };
    }

    private static string Truncate(string value, int length)
    {
        return value.Length <= length ? value : value[..length] + "…";
    }
}

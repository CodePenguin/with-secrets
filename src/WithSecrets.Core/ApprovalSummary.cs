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

        // The .env block comes after the command and the code, so a long .env cannot push them out of sight. Every pair is on its own
        // line; every ordinary value is shown (the page is the control for variables the program may treat as code); the terminal
        // echo (showValues false) lists names only.
        if (request.EnvFiles is { Count: > 0 } || request.Mappings is { } mapped && mapped.Any(pair => pair.Variable != pair.Secret))
        {
            foreach (string file in request.EnvFiles ?? [])
            {
                text.Append('\n').Append("Env file: ").Append(Clean(file));
            }

            foreach (SecretMapping pair in request.Mappings ?? [])
            {
                text.Append('\n').Append("Pair: ").Append(Clean(pair.Display)).Append(pair.Variable != pair.Secret ? " (renamed)" : "");
            }
        }

        if (request.InheritedEnvironment is { } inherited)
        {
            text.Append((char)10).Append(EnvironmentBinding.Line(inherited));
        }

        if (showValues && request.EnvValues is { Count: > 0 } values)
        {
            text.Append('\n').Append("Other variables from .env (values shown):");
            foreach ((string name, string value) in values.OrderBy(item => item.Key, StringComparer.Ordinal))
            {
                text.Append('\n').Append(CodeMarker).Append(Clean(name + "=" + value));
            }
        }
        else if (request.EnvNames is { Count: > 0 } others)
        {
            text.Append('\n').Append("Other variables from .env (names only): ").Append(string.Join(", ", others.Select(Clean)));
        }

        if (request.Reuse is { IsOn: true } reuse)
        {
            text.Append('\n').Append($"Approve for a time (up to {reuse.Choices[^1]} min) also covers the same program, script, folder, and secrets until it ends, whatever the other arguments. Approve once covers only this run.");
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

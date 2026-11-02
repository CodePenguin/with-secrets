using System.Globalization;
using System.Text;

namespace WithSecrets;

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
    public static string BuildMessage(ApprovalRequest request)
    {
        StringBuilder text = new();
        text.Append("Allow an agent to use secrets?").Append('\n');
        text.Append("Secrets: ").Append(string.Join(", ", request.SecretNames)).Append('\n');
        text.Append("Run: ").Append(Clean(CommandLine(request.ResolvedProgram, request.Arguments))).Append('\n');
        foreach (string link in request.Links ?? [])
        {
            text.Append("Link: ").Append(Clean(link)).Append('\n');
        }

        text.Append("In: ").Append(Clean(request.WorkingDirectory)).Append('\n');
        text.Append("Agent says: ").Append(Truncate(Clean(request.Reason), MaxReasonLength));
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

    /// <summary>The command line with quotes around any argument that needs them.</summary>
    public static string CommandLine(string program, IReadOnlyList<string> arguments)
    {
        return string.Join(' ', new[] { Quote(program) }.Concat(arguments.Select(Quote)));
    }

    private static string Quote(string argument)
    {
        if (argument.Length > 0 && argument.All(character => !char.IsWhiteSpace(character) && character != '"'))
        {
            return argument;
        }

        return "\"" + argument.Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";
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

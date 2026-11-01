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

    /// <summary>The text of the Windows Hello prompt.</summary>
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
        if (request.ReuseMinutes > 0)
        {
            text.Append('\n').Append($"Approving also covers the same program, script, folder, and secrets for {request.ReuseMinutes} min, whatever the other arguments.");
        }

        return text.ToString();
    }

    /// <summary>
    /// The short text for the confirmation step that follows the approval window. The window already showed everything, so this
    /// only names the secrets. It is short on purpose: a short text cannot be cut off by the Windows dialog.
    /// </summary>
    public static string BuildConfirmMessage(ApprovalRequest request)
    {
        return "Confirm the request you just read in the approval window.\nSecrets: " + string.Join(", ", request.SecretNames);
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

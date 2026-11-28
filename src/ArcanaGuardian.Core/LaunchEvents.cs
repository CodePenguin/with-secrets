using System.Globalization;
using System.Text;
using System.Text.Json;

namespace ArcanaGuardian;

/// <summary>
/// One line of the answer to a launch: newline-delimited JSON, one object per line. The only members are the ones named here
/// (event, link, stream, text, outcome, exitCode, challenge); the stream carries no secret values. <c>text</c> is output that
/// the service already redacted, or a message of the service.
/// </summary>
public sealed record LaunchEvent(string Kind, string? Link = null, string? Stream = null, string? Text = null, LaunchOutcome? Outcome = null, int? ExitCode = null, string? Challenge = null)
{
    public const string ApprovalKind = "approval";
    public const string OutputKind = "output";
    public const string ResultKind = "result";
    internal const string DotenvxKind = "dotenvx";

    internal static string Dotenvx(string challenge) => JsonSerializer.Serialize(new { @event = DotenvxKind, challenge });

    /// <summary>The approval page link, public: the person opens it.</summary>
    public static string Approval(string link)
    {
        StringBuilder text = new("{\"event\":\"approval\",\"link\":");
        ToolSettings.QuoteJson(text, link);

        return text.Append('}').ToString();
    }

    /// <summary>Redacted output of the program, or a message of the service. <paramref name="stream" /> is stdout or stderr.</summary>
    public static string Output(string stream, string content)
    {
        StringBuilder text = new("{\"event\":\"output\",\"stream\":");
        ToolSettings.QuoteJson(text, stream);
        text.Append(",\"text\":");
        ToolSettings.QuoteJson(text, content);

        return text.Append('}').ToString();
    }

    /// <summary>The last line: how the launch ended and the exit code the client ends with.</summary>
    public static string Result(LaunchOutcome outcome, int exitCode)
    {
        StringBuilder text = new("{\"event\":\"result\",\"outcome\":");
        ToolSettings.QuoteJson(text, outcome.ToString().ToLowerInvariant());

        return text.Append(",\"exitCode\":").Append(exitCode.ToString(CultureInfo.InvariantCulture)).Append('}').ToString();
    }

    /// <summary>Reads one line. Strict about the members it knows; false for anything else.</summary>
    public static bool TryParse(string line, out LaunchEvent? launchEvent, out string? error)
    {
        launchEvent = null;
        if (!CanonicalJson.Open(line, out JsonDocument? doc, out error))
        {
            return false;
        }

        using (doc)
        {
            JsonElement root = doc!.RootElement;
            if (!root.TryGetProperty("event", out JsonElement kind) || kind.ValueKind != JsonValueKind.String)
            {
                error = "missing event";

                return false;
            }

            string name = kind.GetString()!;
            string[] known = name switch
            {
                ApprovalKind => ["event", "link"],
                OutputKind => ["event", "stream", "text"],
                ResultKind => ["event", "outcome", "exitCode"],
                DotenvxKind => ["event", "challenge"],
                _ => [],
            };
            if (known.Length == 0)
            {
                error = "unknown event " + ApprovalSummary.Clean(name);

                return false;
            }

            ContractReader reader = new(root, known);
            if (reader.Problem is not null)
            {
                error = reader.Problem;

                return false;
            }

            switch (name)
            {
                case ApprovalKind when reader.Text("link", out string? link):
                    launchEvent = new LaunchEvent(name, Link: link);
                    break;
                case OutputKind when reader.Text("stream", out string? stream) && reader.Text("text", out string? text) && stream is "stdout" or "stderr":
                    launchEvent = new LaunchEvent(name, Stream: stream, Text: text);
                    break;
                case DotenvxKind when reader.Text("challenge", out string? challenge) && LaunchProtocol.NoncePattern().IsMatch(challenge!):
                    launchEvent = new LaunchEvent(name, Challenge: challenge);
                    break;
                case ResultKind when reader.Text("outcome", out string? outcomeName) && reader.Int("exitCode", out int code) && Enum.TryParse(outcomeName, true, out LaunchOutcome outcome) && Enum.IsDefined(outcome) && outcomeName == outcomeName!.ToLowerInvariant():
                    launchEvent = new LaunchEvent(name, Outcome: outcome, ExitCode: code);
                    break;
            }

            error = launchEvent is null ? reader.Problem ?? "the event has a value that is not allowed" : null;

            return launchEvent is not null;
        }
    }
}

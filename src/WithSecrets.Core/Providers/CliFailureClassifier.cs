using System.Text;

namespace WithSecrets;

/// <summary>
/// Maps a provider CLI's stderr to a common error kind by fixed phrases. The text is only matched, never logged or returned: stderr can carry vault metadata.
/// The phrases are best effort (the CLIs document no machine-readable error taxonomy): anything that matches no rule stays <see cref="ProviderErrorKind.Unknown" />.
/// Rules are tried in order, so the more specific one goes first.
/// </summary>
internal static class CliFailureClassifier
{
    internal const int MaxDiagnostics = 4096;

    /// <summary>How much of a CLI's stderr an adapter keeps for classification; the rest is drained and dropped.</summary>
    internal const int MaxCapture = 64 * 1024;

    /// <summary>Text longer than <see cref="MaxDiagnostics" /> is read by its head and its tail, so a banner before the error line or a trailer after it does not hide the phrase.</summary>
    internal static ProviderErrorKind Classify(ReadOnlySpan<byte> diagnostics, IReadOnlyList<(string Phrase, ProviderErrorKind Kind)> rules)
    {
        if (diagnostics.Length == 0)
        {
            return ProviderErrorKind.Unknown;
        }

        int half = MaxDiagnostics / 2;
        string text = diagnostics.Length <= MaxDiagnostics
            ? Encoding.UTF8.GetString(diagnostics)
            : Encoding.UTF8.GetString(diagnostics[..half]) + "\n" + Encoding.UTF8.GetString(diagnostics[^half..]);
        foreach ((string phrase, ProviderErrorKind kind) in rules)
        {
            if (text.Contains(phrase, StringComparison.OrdinalIgnoreCase))
            {
                return kind;
            }
        }

        return ProviderErrorKind.Unknown;
    }
}

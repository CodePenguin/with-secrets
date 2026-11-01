using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace WithSecrets;

/// <summary>The other forms a secret takes when a program re-encodes it.</summary>
public static class RedactionVariants
{
    private const int MinFragmentLength = 8;

    /// <summary>The secret itself plus its base64, base64url, hex, URL-escaped and JSON-escaped forms.</summary>
    public static IReadOnlyList<string> Expand(string secret)
    {
        HashSet<string> needles = new(StringComparer.Ordinal) { secret };
        byte[] bytes = Encoding.UTF8.GetBytes(secret);

        foreach (string fragment in Base64Fragments(bytes))
        {
            needles.Add(fragment);
            string urlSafe = fragment.Replace('+', '-').Replace('/', '_');
            needles.Add(urlSafe);
        }

        needles.Add(Convert.ToHexString(bytes));
        needles.Add(Convert.ToHexString(bytes).ToLowerInvariant());
        needles.Add(Uri.EscapeDataString(secret));
        needles.Add(JsonEncodedText.Encode(secret).ToString());
        needles.Add(JsonEncodedText.Encode(secret, JavaScriptEncoder.UnsafeRelaxedJsonEscaping).ToString());

        // longest first, so a long form wins over a short form it contains
        return needles.Where(needle => needle.Length > 0).OrderByDescending(needle => needle.Length).ToList();
    }

    /// <summary>
    /// A base64 string that contains the secret depends on the byte offset of the secret. This yields the part of each of
    /// the three alignments that the secret alone decides: the leading characters that mix in unknown earlier bytes and the
    /// trailing characters that mix in unknown later bytes are dropped.
    /// </summary>
    private static IEnumerable<string> Base64Fragments(byte[] secret)
    {
        for (int offset = 0; offset < 3; offset++)
        {
            byte[] padded = new byte[offset + secret.Length];
            Array.Copy(secret, 0, padded, offset, secret.Length);
            string encoded = Convert.ToBase64String(padded);
            int start = offset switch { 1 => 2, 2 => 3, _ => 0 };
            int end = padded.Length / 3 * 4;

            if (end - start >= MinFragmentLength)
            {
                yield return encoded.Substring(start, end - start);
            }
        }
    }
}

/// <summary>
/// Replaces secrets in a stream of text. A chunk may end in the middle of a secret, so the end of each chunk is held back
/// while it could still grow into a secret. At the end of the stream, a held-back start of a secret is masked, not released.
/// </summary>
public sealed class StreamRedactor
{
    public const string Mask = "[REDACTED]";

    private readonly string[] _needles;
    private readonly int _longest;
    private string _pending = "";

    public StreamRedactor(IEnumerable<string> secrets)
    {
        _needles = [.. secrets.Where(secret => secret.Length > 0).SelectMany(RedactionVariants.Expand).Distinct(StringComparer.Ordinal).OrderByDescending(needle => needle.Length)];
        _longest = _needles.Length == 0 ? 0 : _needles[0].Length;
    }

    /// <summary>Takes the next piece of text and returns what is safe to show now.</summary>
    public string Push(string chunk)
    {
        if (_needles.Length == 0)
        {
            return chunk;
        }

        _pending += chunk;
        StringBuilder output = new();
        int position = 0;

        while (true)
        {
            int bestIndex = -1;
            string? best = null;
            foreach (string needle in _needles)
            {
                int index = _pending.IndexOf(needle, position, StringComparison.Ordinal);
                if (index >= 0 && (bestIndex < 0 || index < bestIndex || (index == bestIndex && needle.Length > best!.Length)))
                {
                    bestIndex = index;
                    best = needle;
                }
            }

            if (best is null)
            {
                break;
            }

            output.Append(_pending, position, bestIndex - position).Append(Mask);
            position = bestIndex + best.Length;
        }

        string tail = _pending[position..];
        int hold = PartialSuffixLength(tail);
        output.Append(tail, 0, tail.Length - hold);
        _pending = tail[(tail.Length - hold)..];

        return output.ToString();
    }

    /// <summary>Call once at the end of the stream.</summary>
    public string Finish()
    {
        string output = _pending.Length > 0 ? Mask : "";
        _pending = "";

        return output;
    }

    private int PartialSuffixLength(string text)
    {
        for (int length = Math.Min(text.Length, _longest - 1); length > 0; length--)
        {
            string suffix = text[^length..];
            if (_needles.Any(needle => needle.StartsWith(suffix, StringComparison.Ordinal)))
            {
                return length;
            }
        }

        return 0;
    }
}

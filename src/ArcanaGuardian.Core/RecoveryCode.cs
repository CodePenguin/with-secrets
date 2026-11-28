namespace ArcanaGuardian;

/// <summary>
/// The recovery code as the person sees and types it: <see cref="KeyVault.RecoveryCodeBytes" /> (20) random bytes written in
/// the RFC 4648 base32 alphabet (A to Z, 2 to 7; 20 bytes are exactly 32 characters, so there is no padding) in 8 groups of 4
/// joined by dashes, for example <c>ABCD-EFGH-JKLM-NPQR-STUV-WXYZ-2345-6723</c>. Typing accepts lower case, spaces and
/// dashes anywhere. The code is never printed to the terminal, logged, audited or stored: it appears only on a page of the
/// browser and is typed only into a page.
/// </summary>
internal static class RecoveryCode
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private const int Characters = KeyVault.RecoveryCodeBytes * 8 / 5;
    private const int GroupLength = 4;

    /// <summary>The text of a code, such as <c>ABCD-EFGH-...</c> (8 groups of 4).</summary>
    public static string Format(byte[] code)
    {
        if (code.Length != KeyVault.RecoveryCodeBytes)
        {
            throw new ArgumentException("A recovery code is " + KeyVault.RecoveryCodeBytes + " bytes.", nameof(code));
        }

        char[] letters = new char[Characters];
        int bits = 0;
        int buffer = 0;
        int next = 0;
        foreach (byte value in code)
        {
            buffer = (buffer << 8) | value;
            bits += 8;
            while (bits >= 5)
            {
                letters[next++] = Alphabet[(buffer >> (bits - 5)) & 31];
                bits -= 5;
            }

            buffer &= (1 << bits) - 1;
        }

        List<string> groups = [];
        for (int at = 0; at < letters.Length; at += GroupLength)
        {
            groups.Add(new string(letters, at, GroupLength));
        }

        return string.Join('-', groups);
    }

    /// <summary>
    /// The code bytes in what the person typed: upper or lower case, with spaces and dashes anywhere. False for anything else,
    /// including a wrong length or a character outside the alphabet. The caller zeroes the result.
    /// </summary>
    public static bool TryParse(string? text, out byte[] code)
    {
        code = [];
        if (text is null)
        {
            return false;
        }

        List<int> values = [];
        foreach (char c in text)
        {
            if (c is ' ' or '-')
            {
                continue;
            }

            int index = Alphabet.IndexOf(char.ToUpperInvariant(c), StringComparison.Ordinal);
            if (index < 0 || c > 127)
            {
                return false;
            }

            values.Add(index);
        }

        if (values.Count != Characters)
        {
            return false;
        }

        byte[] bytes = new byte[KeyVault.RecoveryCodeBytes];
        int bits = 0;
        int buffer = 0;
        int next = 0;
        foreach (int value in values)
        {
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8)
            {
                bytes[next++] = (byte)((buffer >> (bits - 8)) & 0xFF);
                bits -= 8;
                buffer &= (1 << bits) - 1;
            }
        }

        code = bytes;

        return true;
    }
}

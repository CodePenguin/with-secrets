using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;

namespace WithSecrets;

internal static class AuthenticatorCode
{
    internal const int SeedSize = 20;
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    internal static string SetupKey(ReadOnlySpan<byte> seed)
    {
        Span<char> encoded = stackalloc char[SeedSize * 8 / 5];
        for (int index = 0; index < encoded.Length; index++)
        {
            int bit = index * 5;
            int offset = bit / 8;
            int pair = seed[offset] << 8;
            if (offset + 1 < seed.Length) pair |= seed[offset + 1];
            encoded[index] = Alphabet[(pair >> (11 - bit % 8)) & 31];
        }

        return new string(encoded);
    }

    internal static long? Match(ReadOnlySpan<byte> seed, string code, DateTimeOffset now)
    {
        if (code.Length != 6 || code.Any(character => !char.IsAsciiDigit(character))) return null;
        long current = now.ToUnixTimeSeconds() / 30;
        Span<byte> entered = stackalloc byte[6];
        System.Text.Encoding.ASCII.GetBytes(code, entered);

        ReadOnlySpan<long> steps = [current, current - 1, current + 1];
        Span<byte> expected = stackalloc byte[6];
        foreach (long step in steps)
        {
            System.Text.Encoding.ASCII.GetBytes(ForStep(seed, step), expected);
            if (CryptographicOperations.FixedTimeEquals(entered, expected)) return step;
        }

        return null;
    }

    internal static string ForStep(ReadOnlySpan<byte> seed, long step)
    {
        Span<byte> counter = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counter, step);
        Span<byte> digest = stackalloc byte[20];
        HMACSHA1.HashData(seed, counter, digest);
        int offset = digest[^1] & 15;
        uint truncated = BinaryPrimitives.ReadUInt32BigEndian(digest[offset..]) & 0x7FFFFFFF;
        return (truncated % 1_000_000).ToString("D6", CultureInfo.InvariantCulture);
    }
}

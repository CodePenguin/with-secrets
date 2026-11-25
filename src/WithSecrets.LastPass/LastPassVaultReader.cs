using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace WithSecrets.LastPass;

/// <summary>Reads selected fields from the binary vault response. Unselected accounts are skipped without decryption.</summary>
internal static class LastPassVaultReader
{
    private const int SkipBufferSize = 32 * 1024;
    private const int MaxSelectedRecord = 1024 * 1024;
    private const long MaxResponse = 128 * 1024 * 1024;
    private const int MaxValue = SecretEntry.MaxValueLength;

    public static async Task<SecretValues> ReadAsync(Stream input, ReadOnlyMemory<byte> vaultKey, LastPassRefreshSelection selection, CancellationToken cancel)
    {
        Dictionary<string, byte[]> values = new(StringComparer.Ordinal);
        HashSet<string> seen = new(StringComparer.Ordinal);
        byte[] header = new byte[8];
        byte[] buffer = new byte[SkipBufferSize];
        long bytes = 0;
        bool shared = false;
        bool hasVersion = false;
        bool complete = false;
        using Aes aes = Aes.Create();
        aes.SetKey(vaultKey.Span);
        try
        {
            while (await ReadHeaderAsync(input, header, cancel).ConfigureAwait(false))
            {
                uint size = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(4));
                bytes += header.Length + (long)size;
                if (bytes > MaxResponse) throw InvalidResponse();

                if (header.AsSpan(0, 4).SequenceEqual("LPAV"u8))
                {
                    if (hasVersion || size is < 1 or > 20) throw InvalidResponse();
                    await input.ReadExactlyAsync(buffer.AsMemory(0, (int)size), cancel).ConfigureAwait(false);
                    if (!ulong.TryParse(buffer.AsSpan(0, (int)size), System.Globalization.NumberStyles.None,
                        System.Globalization.CultureInfo.InvariantCulture, out _)) throw InvalidResponse();
                    hasVersion = true;
                    continue;
                }
                if (!hasVersion) throw InvalidResponse();

                shared |= header.AsSpan(0, 4).SequenceEqual("SHAR"u8);
                bool account = header.AsSpan(0, 4).SequenceEqual("ACCT"u8);
                bool application = header.AsSpan(0, 4).SequenceEqual("AACT"u8);
                if (!account && !application)
                {
                    await SkipAsync(input, buffer, size, cancel).ConfigureAwait(false);
                    continue;
                }

                if (size < 4) throw InvalidResponse();
                await input.ReadExactlyAsync(buffer.AsMemory(0, 4), cancel).ConfigureAwait(false);
                uint idSize = BinaryPrimitives.ReadUInt32BigEndian(buffer);
                uint remaining = size - 4;
                if (idSize > remaining) throw InvalidResponse();
                if (idSize is < 1 or > 32)
                {
                    await SkipAsync(input, buffer, remaining, cancel).ConfigureAwait(false);
                    continue;
                }

                await input.ReadExactlyAsync(buffer.AsMemory(0, (int)idSize), cancel).ConfigureAwait(false);
                remaining -= idSize;
                string id = Encoding.ASCII.GetString(buffer, 0, (int)idSize);
                if (selection.Find(id) is not { } fields)
                {
                    await SkipAsync(input, buffer, remaining, cancel).ConfigureAwait(false);
                    continue;
                }
                if (application || shared)
                    throw new ProviderAdapterException(ProviderErrorKind.InteractionRequired, "This LastPass refresh supports personal login items only.");
                if (!seen.Add(id) || remaining > MaxSelectedRecord) throw InvalidResponse();

                byte[] record = new byte[(int)remaining];
                try
                {
                    await input.ReadExactlyAsync(record, cancel).ConfigureAwait(false);
                    Decode(record, aes, fields, values);
                }
                finally { CryptographicOperations.ZeroMemory(record); }
            }

            cancel.ThrowIfCancellationRequested();
            if (!hasVersion) throw InvalidResponse();
            if (values.Count != selection.Count)
                throw new ProviderAdapterException(ProviderErrorKind.SecretNotFound, "The LastPass vault did not contain every selected item and field.");
            SecretValues result = new(values);
            complete = true;
            return result;
        }
        catch (Exception error) when (error is EndOfStreamException or CryptographicException or FormatException)
        {
            throw InvalidResponse();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            if (!complete)
            {
                foreach (byte[] value in values.Values) CryptographicOperations.ZeroMemory(value);
            }
        }
    }

    private static void Decode(ReadOnlySpan<byte> record, Aes aes, IReadOnlyList<LastPassRefreshSelection.Field> fields, Dictionary<string, byte[]> values)
    {
        ReadItem(ref record); // Display name
        ReadItem(ref record); // Group
        ReadOnlySpan<byte> url = ReadItem(ref record);
        ReadOnlySpan<byte> note = ReadItem(ref record);
        ReadItem(ref record); // Favorite flag
        ReadItem(ref record); // Source account ID
        ReadOnlySpan<byte> username = ReadItem(ref record);
        ReadOnlySpan<byte> password = ReadItem(ref record);
        ReadOnlySpan<byte> protectedFlag = ReadItem(ref record);
        if (protectedFlag.SequenceEqual("1"u8))
            throw new ProviderAdapterException(ProviderErrorKind.InteractionRequired, "A selected LastPass item requires a separate protected-item prompt.");
        if (!protectedFlag.SequenceEqual("0"u8)) throw InvalidResponse();

        foreach (LastPassRefreshSelection.Field field in fields)
        {
            byte[] value = field.Name switch
            {
                "url" when !url.StartsWith("!"u8) && url.Length <= MaxValue * 2 => Convert.FromHexString(Encoding.ASCII.GetString(url)),
                "url" when !url.StartsWith("!"u8) => throw InvalidResponse(),
                "url" => Decrypt(aes, url),
                "note" => Decrypt(aes, note),
                "username" => Decrypt(aes, username),
                "password" => Decrypt(aes, password),
                _ => throw InvalidResponse(),
            };
            if (value.Length > MaxValue || value.AsSpan().Contains((byte)0) || !ProviderBatch.IsStrictUtf8(value))
            {
                CryptographicOperations.ZeroMemory(value);
                throw InvalidResponse();
            }
            values.Add(field.Path, value);
        }
    }

    private static ReadOnlySpan<byte> ReadItem(ref ReadOnlySpan<byte> record)
    {
        if (record.Length < 4) throw InvalidResponse();
        uint size = BinaryPrimitives.ReadUInt32BigEndian(record);
        record = record[4..];
        if (size > record.Length) throw InvalidResponse();
        ReadOnlySpan<byte> field = record[..(int)size];
        record = record[(int)size..];
        return field;
    }

    private static byte[] Decrypt(Aes aes, ReadOnlySpan<byte> field)
    {
        if (field.IsEmpty) return [];
        if (field.Length > MaxValue + 33) throw InvalidResponse();
        return field is [(byte)'!', ..] && field.Length >= 33 && field.Length % 16 == 1
            ? aes.DecryptCbc(field[17..], field.Slice(1, 16), PaddingMode.PKCS7)
            : aes.DecryptEcb(field, PaddingMode.PKCS7);
    }

    private static async Task<bool> ReadHeaderAsync(Stream stream, byte[] header, CancellationToken cancel)
    {
        int count = await stream.ReadAtLeastAsync(header, header.Length, false, cancel).ConfigureAwait(false);
        return count == 0 ? false : count == header.Length ? true : throw InvalidResponse();
    }

    private static async Task SkipAsync(Stream input, byte[] scratch, uint remaining, CancellationToken cancel)
    {
        while (remaining > 0)
        {
            int count = (int)Math.Min(remaining, (uint)scratch.Length);
            await input.ReadExactlyAsync(scratch.AsMemory(0, count), cancel).ConfigureAwait(false);
            remaining -= (uint)count;
        }
    }

    private static ProviderAdapterException InvalidResponse()
        => new(ProviderErrorKind.InvalidResponse, "The LastPass vault response could not be read safely.");
}

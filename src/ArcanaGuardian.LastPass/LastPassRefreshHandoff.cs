using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;

namespace ArcanaGuardian.LastPass;

public sealed record LastPassRefreshMapping(string Path, string LocalName);

/// <summary>The signed scope of a refresh. The authority supplies the requester from the authenticated admin session.</summary>
public sealed record LastPassRefreshRequest(Guid RefreshId, Guid InstanceId, string RequestedBy, string ProviderName,
    string Username, bool European, DateTimeOffset Expires, string StorePublicKey, LastPassRefreshMapping[] Mappings);

/// <summary>A one-use authority-side handoff over a private connection to the installed helper.</summary>
public sealed class LastPassRefreshHandoff : IDisposable
{
    private const int MaxRequestBytes = 64 * 1024;
    // Allow for JSON escaping and compact JWE encoding of 100 maximum-size fields.
    private const int MaxStageBytes = 5 * 1024 * 1024;
    private const int KeyBytes = 91; // canonical P-256 SubjectPublicKeyInfo
    private const int SignatureBytes = 64;
    private const int NonceBytes = 12;
    private const int TagBytes = 16;
    private const string CodeAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    private static readonly TimeSpan MaxLifetime = TimeSpan.FromMinutes(5);
    private readonly LastPassRefreshRequest _request;
    private byte[]? _stageKey;

    private LastPassRefreshHandoff(LastPassRefreshRequest request, byte[] stageKey, string matchingCode)
    {
        _request = request;
        _stageKey = stageKey;
        MatchingCode = matchingCode;
    }

    public string MatchingCode { get; }

    public static async Task<LastPassRefreshHandoff> SendAsync(Stream fromHelper, Stream toHelper,
        LastPassRefreshRequest request, ISigningKey authority, CancellationToken cancel)
    {
        // Freeze the selection before deriving the code or signing.
        if (request.Mappings is not { Length: > 0 and <= 100 } mappings) throw InvalidHandoff();
        request = Validate(request with { Mappings = [.. mappings] });
        byte[] helperKey = await ReadFrameAsync(fromHelper, KeyBytes, cancel).ConfigureAwait(false);
        using ECDiffieHellman exchange = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        byte[] senderKey = exchange.ExportSubjectPublicKeyInfo();
        byte[] shared = Derive(exchange, helperKey, helperKey, senderKey);
        byte[] launchKey = Expand(shared, "LastPass refresh launch v1"u8);
        try
        {
            byte[] signed = SignedBody(helperKey, JsonSerializer.SerializeToUtf8Bytes(request));
            byte[] signature = authority.Sign(signed);
            byte[] authorityKey = authority.PublicKey;
            if (signature.Length != SignatureBytes || !KeyIdentity.IsCanonicalP256(authorityKey)) throw InvalidHandoff();
            byte[] payload = [.. authorityKey, .. signature, .. signed];
            try
            {
                byte[] frame = [.. senderKey, .. Seal(payload, launchKey)];
                await WriteFrameAsync(toHelper, frame, MaxRequestBytes, cancel).ConfigureAwait(false);
                return new LastPassRefreshHandoff(request, Expand(shared, "LastPass refresh stage v1"u8), MatchingCodeFor(shared));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(payload);
                CryptographicOperations.ZeroMemory(signed);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(shared);
            CryptographicOperations.ZeroMemory(launchKey);
        }
    }

    /// <summary>Accepts sealed values for exactly the signed selection once. A separate approval is needed before writing them.</summary>
    public async Task<IReadOnlyDictionary<string, string>> ReceiveStageAsync(Stream fromHelper, CancellationToken cancel)
    {
        byte[] stageKey = TakeStageKey();
        try
        {
            byte[] frame = await ReadFrameAsync(fromHelper, MaxStageBytes, cancel).ConfigureAwait(false);
            byte[] payload = Open(frame, stageKey);
            try
            {
                Validate(_request);
                Stage? stage = JsonSerializer.Deserialize<Stage>(payload);
                string[] paths = Paths(_request);
                if (stage?.Values is not { } values || stage.RefreshId != _request.RefreshId || values.Count != paths.Length
                    || paths.Any(path => !values.TryGetValue(path, out string? value)
                        || value is null || !JweCipher.IsCiphertext(value)))
                    throw InvalidHandoff();
                return new System.Collections.ObjectModel.ReadOnlyDictionary<string, string>(values);
            }
            finally { CryptographicOperations.ZeroMemory(payload); }
        }
        catch (Exception error) when (error is JsonException or CryptographicException)
        {
            throw InvalidHandoff();
        }
        finally { CryptographicOperations.ZeroMemory(stageKey); }
    }

    public void Dispose() => SecretValues.Clear(Interlocked.Exchange(ref _stageKey, null));

    internal static async Task<LastPassRefreshHandoff> AcceptAsync(Stream fromAuthority, Stream toAuthority,
        string pinnedAuthorityFingerprint, CancellationToken cancel)
    {
        if (KeyIdentity.ParseHex(pinnedAuthorityFingerprint, full: true) != pinnedAuthorityFingerprint) throw InvalidHandoff();
        using ECDiffieHellman exchange = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        byte[] helperKey = exchange.ExportSubjectPublicKeyInfo();
        await WriteFrameAsync(toAuthority, helperKey, KeyBytes, cancel).ConfigureAwait(false);
        byte[] frame = await ReadFrameAsync(fromAuthority, MaxRequestBytes, cancel).ConfigureAwait(false);
        if (frame.Length <= KeyBytes) throw InvalidHandoff();
        byte[] senderKey = frame[..KeyBytes];
        byte[] shared = Derive(exchange, senderKey, helperKey, senderKey);
        byte[] launchKey = Expand(shared, "LastPass refresh launch v1"u8);
        try
        {
            byte[] payload = Open(frame.AsSpan(KeyBytes), launchKey);
            try
            {
                const int bodyOffset = KeyBytes + SignatureBytes;
                byte[] prefix = SignedBody(helperKey, []);
                if (payload.Length <= bodyOffset + prefix.Length) throw InvalidHandoff();
                byte[] authority = payload[..KeyBytes];
                byte[] signature = payload[KeyBytes..bodyOffset];
                byte[] signed = payload[bodyOffset..];
                try
                {
                    if (KeyIdentity.Fingerprint(authority) != pinnedAuthorityFingerprint
                        || !signed.AsSpan().StartsWith(prefix) || !KeyIdentity.Verify(authority, signed, signature))
                        throw InvalidHandoff();
                    LastPassRefreshRequest request = Validate(JsonSerializer.Deserialize<LastPassRefreshRequest>(signed.AsSpan(prefix.Length)));
                    return new LastPassRefreshHandoff(request, Expand(shared, "LastPass refresh stage v1"u8), MatchingCodeFor(shared));
                }
                finally { CryptographicOperations.ZeroMemory(signed); }
            }
            finally { CryptographicOperations.ZeroMemory(payload); }
        }
        catch (Exception error) when (error is JsonException or CryptographicException)
        {
            throw InvalidHandoff();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(shared);
            CryptographicOperations.ZeroMemory(launchKey);
        }
    }

    internal LastPassRefreshRequest Request => _request;

    internal async Task SendStageAsync(Stream toAuthority, SecretValues selected, CancellationToken cancel)
    {
        byte[] stageKey = TakeStageKey();
        try
        {
            Validate(_request);
            string[] paths = Paths(_request);
            if (selected.Names.Count != paths.Length
                || paths.Any(path => !selected.Names.Contains(path, StringComparer.Ordinal)))
                throw InvalidHandoff();
            Dictionary<string, string> ciphertexts = new(StringComparer.Ordinal);
            foreach (string path in paths)
            {
                cancel.ThrowIfCancellationRequested();
                if (selected.Bytes(path).Length == 0)
                    throw new ProviderAdapterException(ProviderErrorKind.SecretNotFound, "A selected LastPass field is empty.");
                ciphertexts.Add(path, JweCipher.Instance.Encrypt(selected.Text(path), _request.StorePublicKey));
            }
            byte[] payload = JsonSerializer.SerializeToUtf8Bytes(new Stage(_request.RefreshId, ciphertexts));
            await WriteFrameAsync(toAuthority, Seal(payload, stageKey), MaxStageBytes, cancel).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(stageKey); }
    }

    private byte[] TakeStageKey() => Interlocked.Exchange(ref _stageKey, null) ?? throw InvalidHandoff();

    internal static void CheckExpiry(LastPassRefreshRequest request) => Validate(request);

    private static LastPassRefreshRequest Validate(LastPassRefreshRequest? request)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (request is null || request.RefreshId == Guid.Empty || request.InstanceId == Guid.Empty
            || request.Expires <= now || request.Expires > now + MaxLifetime
            || !DisplayText(request.RequestedBy) || !DisplayText(request.ProviderName)
            || !LastPassRefreshSelection.IsAccount(request.Username)
            || request.StorePublicKey is not { } key || !JweCipher.IsPublicKey(key)
            || request.Mappings is not { Length: > 0 and <= 100 } mappings
            || mappings.Any(mapping => mapping?.LocalName is not { } name || !SecretNames.IsValid(name))
            || mappings.Select(mapping => mapping.LocalName).Distinct(StringComparer.Ordinal).Count() != mappings.Length)
            throw InvalidHandoff();
        _ = new LastPassRefreshSelection(Paths(request));
        return request;
    }

    internal static string[] Paths(LastPassRefreshRequest request)
        => [.. request.Mappings.Select(mapping => mapping.Path).Distinct(StringComparer.Ordinal)];

    private static bool DisplayText(string? value)
        => value is { Length: > 0 and <= 256 } && value == value.Trim()
            && !value.Any(character => char.IsControl(character) || char.GetUnicodeCategory(character)
                is System.Globalization.UnicodeCategory.Format or System.Globalization.UnicodeCategory.LineSeparator
                or System.Globalization.UnicodeCategory.ParagraphSeparator);

    private static byte[] Derive(ECDiffieHellman ours, byte[] peerKey, byte[] helperKey, byte[] senderKey)
    {
        if (peerKey.Length != KeyBytes || !KeyIdentity.IsCanonicalP256(peerKey)) throw InvalidHandoff();
        using ECDiffieHellman peer = ECDiffieHellman.Create();
        peer.ImportSubjectPublicKeyInfo(peerKey, out _);
        return ours.DeriveKeyFromHash(peer.PublicKey, HashAlgorithmName.SHA256, helperKey, senderKey);
    }

    private static byte[] Expand(byte[] shared, ReadOnlySpan<byte> context)
    {
        byte[] key = new byte[32];
        HKDF.Expand(HashAlgorithmName.SHA256, shared, key, context);
        return key;
    }

    private static string MatchingCodeFor(byte[] shared)
    {
        byte[] code = Expand(shared, "LastPass refresh matching code v1"u8);
        try { return new string([CodeAlphabet[code[0] & 31], CodeAlphabet[code[1] & 31],
            CodeAlphabet[code[2] & 31], CodeAlphabet[code[3] & 31]]); }
        finally { CryptographicOperations.ZeroMemory(code); }
    }

    private static byte[] SignedBody(byte[] helperKey, byte[] request)
        => [.. "arcana-guardian LastPass refresh request v1\0"u8, .. helperKey, .. request];

    private static byte[] Seal(ReadOnlySpan<byte> plaintext, byte[] key)
    {
        byte[] frame = new byte[NonceBytes + TagBytes + plaintext.Length];
        RandomNumberGenerator.Fill(frame.AsSpan(0, NonceBytes));
        using AesGcm aes = new(key, TagBytes);
        aes.Encrypt(frame.AsSpan(0, NonceBytes), plaintext, frame.AsSpan(NonceBytes + TagBytes), frame.AsSpan(NonceBytes, TagBytes));
        return frame;
    }

    private static byte[] Open(ReadOnlySpan<byte> frame, byte[] key)
    {
        if (frame.Length <= NonceBytes + TagBytes) throw InvalidHandoff();
        byte[] plaintext = new byte[frame.Length - NonceBytes - TagBytes];
        using AesGcm aes = new(key, TagBytes);
        try { aes.Decrypt(frame[..NonceBytes], frame[(NonceBytes + TagBytes)..], frame.Slice(NonceBytes, TagBytes), plaintext); }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw;
        }
        return plaintext;
    }

    private static async Task<byte[]> ReadFrameAsync(Stream source, int max, CancellationToken cancel)
    {
        byte[] header = new byte[sizeof(int)];
        await source.ReadExactlyAsync(header, cancel).ConfigureAwait(false);
        int size = BinaryPrimitives.ReadInt32BigEndian(header);
        if (size is < 1 || size > max) throw InvalidHandoff();
        byte[] frame = new byte[size];
        await source.ReadExactlyAsync(frame, cancel).ConfigureAwait(false);
        return frame;
    }

    private static async Task WriteFrameAsync(Stream target, byte[] frame, int max, CancellationToken cancel)
    {
        if (frame.Length is < 1 || frame.Length > max) throw InvalidHandoff();
        byte[] header = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(header, frame.Length);
        await target.WriteAsync(header, cancel).ConfigureAwait(false);
        await target.WriteAsync(frame, cancel).ConfigureAwait(false);
        await target.FlushAsync(cancel).ConfigureAwait(false);
    }

    private static ProviderAdapterException InvalidHandoff()
        => new(ProviderErrorKind.AccessDenied, "The Arcana Guardian LastPass refresh request could not be verified.");

    private sealed record Stage(Guid RefreshId, Dictionary<string, string> Values);
}

using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace WithSecrets;

/// <summary>Why a handshake or an encrypted frame was refused. A short code for logs; never key material, a value or a payload.</summary>
public sealed class SecureChannelException(string message) : Exception(message);

/// <summary>
/// The authority key a host trusts for a connection: its fingerprint, and its full public key when the host has it pinned (needed to follow a routine rotation).
/// A host that has only the fingerprint (the out-of-band value in <c>host.json</c>, before the first approval) accepts exactly the key with that fingerprint.
/// </summary>
public sealed record TrustedAuthority(string Fingerprint, byte[]? PublicKey);

/// <summary>The frame types and sizes of the end-to-end protocol (architecture 10.2, "Authority authentication and cryptographic protocol"). All numbers are big-endian.</summary>
internal static class ChannelFormat
{
    /// <summary>The protocol version of the handshake and of the data frames. It is in the transcript and in every frame's associated data.</summary>
    public const int Version = 1;

    public const byte HelloType = 1;
    public const byte ServerHelloType = 2;
    public const byte AuthType = 3;
    public const byte DataType = 4;

    /// <summary>An unauthenticated refusal (a code the sender chose, for example "locked"). It proves nothing; a receiver only ends the attempt.</summary>
    public const byte ErrorType = 5;

    public const int EphemeralLength = 91;
    public const int NonceLength = 32;
    public const int FingerprintBytes = 32;
    public const int SignatureLength = 64;
    public const int TagLength = 16;
    public const int SessionIdLength = 16;
    public const int MaxChain = 8;

    /// <summary>The longest application message (plaintext) a session carries.</summary>
    public const int MaxPlaintext = 4 * 1024 * 1024;

    public const byte HostToAuthority = 1;
    public const byte AuthorityToHost = 2;

    public const string AuthoritySignatureDomain = "with-secrets relay authority signature v1\n";
    public const string MachineSignatureDomain = "with-secrets relay machine signature v1\n";
    private const string Label = "with-secrets remote session v1";

    /// <summary>SHA-256 over the label, the role and each part with its length: what the identity signatures bind (both ephemeral keys, both nonces, the identities and the version are in the parts).</summary>
    public static byte[] Transcript(string role, params byte[][] parts)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, Encoding.ASCII.GetBytes(Label));
        Append(hash, Encoding.ASCII.GetBytes(role));
        foreach (byte[] part in parts)
        {
            Append(hash, part);
        }

        return hash.GetHashAndReset();
    }

    private static void Append(IncrementalHash hash, byte[] data)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, (uint)data.Length);
        hash.AppendData(length);
        hash.AppendData(data);
    }

    public static byte[] Signed(string domain, byte[] transcript) => [.. Encoding.ASCII.GetBytes(domain), .. transcript];

    public static byte[] ReadyText(byte[] machineTranscript) => [.. Encoding.ASCII.GetBytes("with-secrets session ready v1\n"), .. machineTranscript];

    public static byte[] ErrorFrame(string code) => [ErrorType, .. Encoding.ASCII.GetBytes(code.Length > 40 ? code[..40] : code)];

    public static string? ErrorCode(byte[] frame) => frame.Length is >= 1 and <= 64 && frame[0] == ErrorType ? new string([.. frame.Skip(1).Select(item => item is >= 0x20 and < 0x7F ? (char)item : '?')]) : null;

    /// <summary>The ephemeral public key of an ECDH key pair, which must be a P-256 key (any other curve or a point off the curve is refused).</summary>
    public static ECDiffieHellman ImportEphemeral(byte[] spki)
    {
        ECDiffieHellman peer = ECDiffieHellman.Create();
        try
        {
            peer.ImportSubjectPublicKeyInfo(spki, out int read);
            ECParameters parameters = peer.ExportParameters(false);
            if (read != spki.Length || parameters.Curve.Oid.Value != "1.2.840.10045.3.1.7" || !peer.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(spki))
            {
                throw new SecureChannelException("the ephemeral key is not a canonical P-256 key");
            }

            return peer;
        }
        catch (Exception error) when (error is CryptographicException or ArgumentException)
        {
            peer.Dispose();
            throw new SecureChannelException("the ephemeral key is not valid");
        }
        catch (SecureChannelException)
        {
            peer.Dispose();

            throw;
        }
    }

    /// <summary>The keys of one session: separate keys and nonce prefixes for each direction, and the session id, all from HKDF-SHA-256 over the ECDH secret with the machine transcript as salt.</summary>
    public static SecureSession Derive(byte[] sharedSecret, byte[] machineTranscript, bool initiator)
    {
        byte[] material = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, 32 + 32 + 4 + 4 + SessionIdLength, machineTranscript, Encoding.ASCII.GetBytes("with-secrets remote session keys v1"));
        try
        {
            byte[] hostToAuthorityKey = material[..32];
            byte[] authorityToHostKey = material[32..64];
            byte[] hostToAuthorityIv = material[64..68];
            byte[] authorityToHostIv = material[68..72];
            byte[] sessionId = material[72..(72 + SessionIdLength)];

            return initiator
                ? new SecureSession(sessionId, HostToAuthority, hostToAuthorityKey, hostToAuthorityIv, authorityToHostKey, authorityToHostIv)
                : new SecureSession(sessionId, AuthorityToHost, authorityToHostKey, authorityToHostIv, hostToAuthorityKey, hostToAuthorityIv);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(material);
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }
}

/// <summary>Reads a handshake message strictly: every length is checked and the message must end exactly where it should.</summary>
internal sealed class FrameReader(byte[] data)
{
    private int _position;

    public byte Byte() => Take(1)[0];

    public ushort U16() => BinaryPrimitives.ReadUInt16BigEndian(Take(2));

    public uint U32() => BinaryPrimitives.ReadUInt32BigEndian(Take(4));

    public long I64() => BinaryPrimitives.ReadInt64BigEndian(Take(8));

    public byte[] Bytes(int count) => Take(count).ToArray();

    public int Position => _position;

    public void End()
    {
        if (_position != data.Length)
        {
            throw new SecureChannelException("the message has trailing bytes");
        }
    }

    private ReadOnlySpan<byte> Take(int count)
    {
        if (count < 0 || data.Length - _position < count)
        {
            throw new SecureChannelException("the message is too short");
        }

        ReadOnlySpan<byte> slice = data.AsSpan(_position, count);
        _position += count;

        return slice;
    }
}

internal sealed class FrameWriter
{
    private readonly MemoryStream _stream = new();

    public FrameWriter Byte(byte value)
    {
        _stream.WriteByte(value);

        return this;
    }

    public FrameWriter U16(int value)
    {
        Span<byte> bytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, checked((ushort)value));
        _stream.Write(bytes);

        return this;
    }

    public FrameWriter U32(uint value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        _stream.Write(bytes);

        return this;
    }

    public FrameWriter I64(long value)
    {
        Span<byte> bytes = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(bytes, value);
        _stream.Write(bytes);

        return this;
    }

    public FrameWriter Bytes(byte[] value)
    {
        _stream.Write(value);

        return this;
    }

    public byte[] ToArray() => _stream.ToArray();
}

/// <summary>
/// The host's side of the handshake. The host sends a hello (fresh ephemeral ECDH P-256 key, a nonce, and the fingerprint of the authority key it trusts), verifies
/// that the authority's answer is signed by that key (or by a key the trusted one handed over through signed transitions) over the transcript, and answers with its
/// machine key and a signature over the transcript that includes both ephemeral keys and the authority's identity. Nothing it learns before the signature
/// verifies is used, and an unknown authority key is never accepted.
/// </summary>
internal sealed class InitiatorHandshake(ISigningKey machineKey, TrustedAuthority trust) : IDisposable
{
    private readonly ECDiffieHellman _ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
    private byte[]? _hello;

    public byte[] Hello()
    {
        _hello = new FrameWriter().Byte(ChannelFormat.HelloType).U32(ChannelFormat.Version).Bytes(_ephemeral.ExportSubjectPublicKeyInfo())
            .Bytes(RandomNumberGenerator.GetBytes(ChannelFormat.NonceLength)).Bytes(Convert.FromHexString(trust.Fingerprint)).ToArray();

        return _hello;
    }

    /// <summary>Checks the authority's hello and returns the host's authentication message, the session (not yet confirmed: the first frame from the authority must open to <c>ExpectedReady</c>) and the authority key that signed.</summary>
    public (byte[] Auth, SecureSession Session, byte[] AuthorityPublicKey, byte[] ExpectedReady) Complete(byte[] serverHello)
    {
        byte[] hello = _hello ?? throw new SecureChannelException("no hello was sent");
        FrameReader reader = new(serverHello);
        if (reader.Byte() != ChannelFormat.ServerHelloType || reader.U32() != ChannelFormat.Version)
        {
            throw new SecureChannelException("not a server hello of this version");
        }

        byte[] ephemeral = reader.Bytes(ChannelFormat.EphemeralLength);
        reader.Bytes(ChannelFormat.NonceLength);
        byte[] authorityKey = reader.Bytes(reader.U16());
        int count = reader.Byte();
        if (count > ChannelFormat.MaxChain)
        {
            throw new SecureChannelException("the key chain is too long");
        }

        List<KeyTransition> chain = [];
        for (int index = 0; index < count; index++)
        {
            byte[] oldFingerprint = reader.Bytes(ChannelFormat.FingerprintBytes);
            byte[] newFingerprint = reader.Bytes(ChannelFormat.FingerprintBytes);
            byte[] newKey = reader.Bytes(reader.U16());
            long ticks = reader.I64();
            byte[] signature = reader.Bytes(ChannelFormat.SignatureLength);
            if (ticks is < 0 or > 3_155_378_975_999_999_999)
            {
                throw new SecureChannelException("a transition has no valid time");
            }

            chain.Add(new KeyTransition(Convert.ToHexString(oldFingerprint), Convert.ToHexString(newFingerprint), newKey, new DateTimeOffset(ticks, TimeSpan.Zero), signature));
        }

        int bodyLength = reader.Position;
        byte[] authoritySignature = reader.Bytes(ChannelFormat.SignatureLength);
        reader.End();
        byte[] body = serverHello[..bodyLength];

        if (!KeyIdentity.IsCanonicalP256(authorityKey))
        {
            throw new SecureChannelException("the authority key is not a canonical P-256 key");
        }

        if (!AuthorityTrusted(authorityKey, chain))
        {
            throw new SecureChannelException("the authority key is not the one this host trusts");
        }

        byte[] authorityTranscript = ChannelFormat.Transcript("authority", hello, body);
        if (!KeyIdentity.Verify(authorityKey, ChannelFormat.Signed(ChannelFormat.AuthoritySignatureDomain, authorityTranscript), authoritySignature))
        {
            throw new SecureChannelException("the authority's handshake signature does not verify");
        }

        byte[] machinePublicKey = machineKey.PublicKey;
        byte[] machineTranscript = ChannelFormat.Transcript("machine", hello, serverHello, machinePublicKey);
        byte[] machineSignature = machineKey.Sign(ChannelFormat.Signed(ChannelFormat.MachineSignatureDomain, machineTranscript));
        byte[] auth = new FrameWriter().Byte(ChannelFormat.AuthType).U16(machinePublicKey.Length).Bytes(machinePublicKey).Bytes(machineSignature).ToArray();

        using ECDiffieHellman peer = ChannelFormat.ImportEphemeral(ephemeral);
        byte[] secret = _ephemeral.DeriveRawSecretAgreement(peer.PublicKey);

        return (auth, ChannelFormat.Derive(secret, machineTranscript, initiator: true), authorityKey, ChannelFormat.ReadyText(machineTranscript));
    }

    private bool AuthorityTrusted(byte[] authorityKey, List<KeyTransition> chain)
    {
        string fingerprint = KeyIdentity.Fingerprint(authorityKey);
        if (string.Equals(fingerprint, trust.Fingerprint, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // A rotated key is accepted only through transitions, each signed by the key before it, starting from the key this host has pinned.
        if (trust.PublicKey is not { } current || !KeyIdentity.IsCanonicalP256(current) || !string.Equals(KeyIdentity.Fingerprint(current), trust.Fingerprint, StringComparison.OrdinalIgnoreCase) || chain.Count == 0)
        {
            return false;
        }

        foreach (KeyTransition transition in chain)
        {
            if (!transition.Verify(current))
            {
                return false;
            }

            current = transition.NewPublicKey;
        }

        return current.AsSpan().SequenceEqual(authorityKey);
    }

    public void Dispose() => _ephemeral.Dispose();
}

/// <summary>The authority's side of the handshake: signs with its own key, verifies the machine's signature over the transcript, and ends in a session whose first frame confirms the keys.</summary>
internal sealed class ResponderHandshake(ISigningKey authorityKey, Func<string, IReadOnlyList<KeyTransition>> transitionsFrom) : IDisposable
{
    private readonly ECDiffieHellman _ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
    private byte[]? _hello;
    private byte[]? _serverHello;
    private byte[]? _clientEphemeral;

    public byte[] Respond(byte[] clientHello)
    {
        FrameReader reader = new(clientHello);
        if (reader.Byte() != ChannelFormat.HelloType || reader.U32() != ChannelFormat.Version)
        {
            throw new SecureChannelException("not a hello of this version");
        }

        _clientEphemeral = reader.Bytes(ChannelFormat.EphemeralLength);
        reader.Bytes(ChannelFormat.NonceLength);
        string anchor = Convert.ToHexString(reader.Bytes(ChannelFormat.FingerprintBytes));
        reader.End();
        using (ChannelFormat.ImportEphemeral(_clientEphemeral))
        {
        }

        _hello = clientHello;
        byte[] publicKey = authorityKey.PublicKey;
        List<KeyTransition> chain = [];
        if (!string.Equals(KeyIdentity.Fingerprint(publicKey), anchor, StringComparison.Ordinal))
        {
            try
            {
                chain = [.. transitionsFrom(anchor)];
            }
            catch (Exception error) when (error is not OutOfMemoryException)
            {
                chain = [];
            }

            if (chain.Count > ChannelFormat.MaxChain)
            {
                chain = [];
            }
        }

        FrameWriter body = new FrameWriter().Byte(ChannelFormat.ServerHelloType).U32(ChannelFormat.Version).Bytes(_ephemeral.ExportSubjectPublicKeyInfo())
            .Bytes(RandomNumberGenerator.GetBytes(ChannelFormat.NonceLength)).U16(publicKey.Length).Bytes(publicKey).Byte((byte)chain.Count);
        foreach (KeyTransition transition in chain)
        {
            body.Bytes(Convert.FromHexString(transition.OldFingerprint)).Bytes(Convert.FromHexString(transition.NewFingerprint)).U16(transition.NewPublicKey.Length).Bytes(transition.NewPublicKey)
                .I64(transition.Created.UtcTicks).Bytes(transition.Signature);
        }

        byte[] bodyBytes = body.ToArray();
        byte[] signature = authorityKey.Sign(ChannelFormat.Signed(ChannelFormat.AuthoritySignatureDomain, ChannelFormat.Transcript("authority", clientHello, bodyBytes)));
        _serverHello = [.. bodyBytes, .. signature];

        return _serverHello;
    }

    /// <summary>Verifies the machine's proof of possession over the transcript and returns the session, who it authenticated, and the first frame to send (it confirms the keys to the host).</summary>
    public (SecureSession Session, string MachineFingerprint, byte[] MachinePublicKey, byte[] ReadyFrame) Complete(byte[] auth)
    {
        if (_hello is null || _serverHello is null || _clientEphemeral is null)
        {
            throw new SecureChannelException("no hello was answered");
        }

        FrameReader reader = new(auth);
        if (reader.Byte() != ChannelFormat.AuthType)
        {
            throw new SecureChannelException("not an authentication message");
        }

        byte[] machineKey = reader.Bytes(reader.U16());
        byte[] signature = reader.Bytes(ChannelFormat.SignatureLength);
        reader.End();
        if (!KeyIdentity.IsCanonicalP256(machineKey))
        {
            throw new SecureChannelException("the machine key is not a canonical P-256 key");
        }

        byte[] transcript = ChannelFormat.Transcript("machine", _hello, _serverHello, machineKey);
        if (!KeyIdentity.Verify(machineKey, ChannelFormat.Signed(ChannelFormat.MachineSignatureDomain, transcript), signature))
        {
            throw new SecureChannelException("the machine's handshake signature does not verify");
        }

        using ECDiffieHellman peer = ChannelFormat.ImportEphemeral(_clientEphemeral);
        byte[] secret = _ephemeral.DeriveRawSecretAgreement(peer.PublicKey);
        SecureSession session = ChannelFormat.Derive(secret, transcript, initiator: false);

        return (session, KeyIdentity.Fingerprint(machineKey), machineKey, session.Seal(ChannelFormat.ReadyText(transcript)));
    }

    public void Dispose() => _ephemeral.Dispose();
}

/// <summary>
/// One session's AES-256-GCM, with a key and a nonce prefix for each direction. A frame is <c>type | sequence (8) | ciphertext | tag (16)</c>. The nonce is the direction's 4-byte prefix and the sequence;
/// the associated data binds the protocol version, the session id, the direction and the sequence. A receiver accepts exactly the next sequence number: a repeated, skipped, reordered,
/// reflected or foreign frame, or one with any bit changed, ends the session for good (it never recovers; the peer reconnects with a new handshake and new keys).
/// </summary>
internal sealed class SecureSession : IDisposable
{
    private readonly Lock _lock = new();
    private readonly AesGcm _send;
    private readonly AesGcm _receive;
    private readonly byte[] _sendIv;
    private readonly byte[] _receiveIv;
    private readonly byte _sendDirection;
    private ulong _sendSequence;
    private ulong _receiveSequence;

    public SecureSession(byte[] sessionId, byte sendDirection, byte[] sendKey, byte[] sendIv, byte[] receiveKey, byte[] receiveIv)
    {
        SessionId = sessionId;
        _sendDirection = sendDirection;
        _send = new AesGcm(sendKey, ChannelFormat.TagLength);
        _receive = new AesGcm(receiveKey, ChannelFormat.TagLength);
        _sendIv = sendIv;
        _receiveIv = receiveIv;
    }

    public byte[] SessionId { get; }

    public bool Broken { get; private set; }

    /// <summary>The session id in hex: public (it is in no secret), shown in logs and tests.</summary>
    public string Id => Convert.ToHexString(SessionId);

    public byte[] Seal(ReadOnlySpan<byte> plaintext)
    {
        if (plaintext.Length > ChannelFormat.MaxPlaintext)
        {
            throw new SecureChannelException("the message is too long");
        }

        lock (_lock)
        {
            if (Broken || _sendSequence >= int.MaxValue)
            {
                throw new SecureChannelException("the session is closed");
            }

            ulong sequence = _sendSequence;
            byte[] frame = new byte[1 + 8 + plaintext.Length + ChannelFormat.TagLength];
            frame[0] = ChannelFormat.DataType;
            BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(1, 8), sequence);
            _send.Encrypt(Nonce(_sendIv, sequence), plaintext, frame.AsSpan(9, plaintext.Length), frame.AsSpan(9 + plaintext.Length, ChannelFormat.TagLength), Aad(_sendDirection, sequence));
            _sendSequence++;

            return frame;
        }
    }

    public byte[] Open(byte[] frame)
    {
        lock (_lock)
        {
            if (Broken)
            {
                throw new SecureChannelException("the session is closed");
            }

            try
            {
                if (frame.Length < 1 + 8 + ChannelFormat.TagLength || frame.Length > ChannelFormat.MaxPlaintext + 1 + 8 + ChannelFormat.TagLength || frame[0] != ChannelFormat.DataType)
                {
                    throw new SecureChannelException("not a data frame");
                }

                ulong sequence = BinaryPrimitives.ReadUInt64BigEndian(frame.AsSpan(1, 8));
                if (sequence != _receiveSequence)
                {
                    throw new SecureChannelException("the frame is not the next in sequence");
                }

                int length = frame.Length - 9 - ChannelFormat.TagLength;
                byte[] plaintext = new byte[length];
                byte receiveDirection = _sendDirection == ChannelFormat.HostToAuthority ? ChannelFormat.AuthorityToHost : ChannelFormat.HostToAuthority;
                try
                {
                    _receive.Decrypt(Nonce(_receiveIv, sequence), frame.AsSpan(9, length), frame.AsSpan(9 + length, ChannelFormat.TagLength), plaintext, Aad(receiveDirection, sequence));
                }
                catch (CryptographicException)
                {
                    throw new SecureChannelException("the frame does not authenticate");
                }

                _receiveSequence++;

                return plaintext;
            }
            catch (SecureChannelException)
            {
                Broken = true;

                throw;
            }
        }
    }

    private static byte[] Nonce(byte[] prefix, ulong sequence)
    {
        byte[] nonce = new byte[12];
        prefix.CopyTo(nonce, 0);
        BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4, 8), sequence);

        return nonce;
    }

    private byte[] Aad(byte direction, ulong sequence)
    {
        byte[] aad = new byte[4 + 4 + ChannelFormat.SessionIdLength + 1 + 8];
        "WSR1"u8.CopyTo(aad);
        BinaryPrimitives.WriteUInt32BigEndian(aad.AsSpan(4, 4), ChannelFormat.Version);
        SessionId.CopyTo(aad, 8);
        aad[8 + ChannelFormat.SessionIdLength] = direction;
        BinaryPrimitives.WriteUInt64BigEndian(aad.AsSpan(9 + ChannelFormat.SessionIdLength, 8), sequence);

        return aad;
    }

    public void Dispose()
    {
        _send.Dispose();
        _receive.Dispose();
    }
}

using System.Buffers.Text;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace WithSecrets;

/// <summary>
/// The server side of the encryption on the set page. The server makes a P-256 key pair for one page. The browser makes its
/// own key pair, derives a key with ECDH and HKDF-SHA-256 (salt: the page's bind, info: <see cref="Info" />), and encrypts the
/// JSON of names and values with AES-256-GCM (12-byte iv, associated data: the bind, the 16-byte tag after the ciphertext).
/// Every failure is a <see cref="CryptographicException" /> with a message that says nothing about why.
/// </summary>
internal static class SecretCrypto
{
    public const string Info = "with-secrets/v1 secrets";

    /// <summary>The HKDF info of the PRF output's transport (not the secret entry key, so one cannot be opened as the other).</summary>
    public const string PrfInfo = "with-secrets/v1 prf";


    private const int PointLength = 65;
    private const int CoordinateLength = 32;
    private const int IvLength = 12;
    private const int TagLength = 16;

    // P-256: y^2 = x^3 - 3x + b over the prime field p.
    private static readonly BigInteger P = BigInteger.Parse("0FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);
    private static readonly BigInteger B = BigInteger.Parse("05AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>A new key pair: the private key (keep it in memory for this page only; zero it after) and the public point to send.</summary>
    public static (byte[] PrivateState, string PublicKeyBase64Url) NewServerKey()
    {
        using ECDiffieHellman key = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        ECParameters open = key.ExportParameters(false);
        byte[] point = [0x04, .. open.Q.X!, .. open.Q.Y!];

        return (key.ExportECPrivateKey(), Base64Url.EncodeToString(point));
    }

    /// <summary>The passkey challenge for a ciphertext: SHA-256(bind + SHA-256(ct)), ct being the ciphertext with its tag.</summary>
    public static byte[] Challenge(byte[] bind, byte[] ct)
    {
        return SHA256.HashData([.. bind, .. SHA256.HashData(ct)]);
    }

    /// <summary>
    /// The bind of the manifest the set page signs: the page's bind followed by SHA-256(ct). The one passkey assertion is over
    /// <see cref="Manifest.Challenge" /> of this and the manifest text, that is SHA-256(bind || SHA-256(ct) || SHA-256(manifest)),
    /// so it covers both the values the page sent and the hashes of the ciphertexts the program made from them. The manifest
    /// is stored with this bind, so it verifies at every read like any other.
    /// </summary>
    public static byte[] ManifestBind(byte[] bind, byte[] ct)
    {
        return [.. bind, .. SHA256.HashData(ct)];
    }

    /// <summary>
    /// Decrypts what the page sent and returns the plaintext (UTF-8 JSON). Throws <see cref="CryptographicException" /> on any
    /// failure: bad base64url, an epk that is not a 65-byte uncompressed P-256 point, a wrong iv length, a wrong key or tag.
    /// </summary>
    public static string Decrypt(byte[] privateState, byte[] bind, string epk, string iv, string ct)
    {
        byte[] plain = DecryptBytes(privateState, bind, epk, iv, ct, Info);
        try
        {
            return new UTF8Encoding(false, true).GetString(plain);
        }
        catch (Exception)
        {
            throw Failed();
        }
        finally
        {
            Clear(plain);
        }
    }

    /// <summary>
    /// The same scheme, returning the plaintext bytes (the caller zeroes them) under the HKDF info <paramref name="info" />
    /// (<see cref="Info" /> for the secret values, <see cref="PrfInfo" /> for a PRF output). Every failure is a
    /// <see cref="CryptographicException" /> with the same message.
    /// </summary>
    public static byte[] DecryptBytes(byte[] privateState, byte[] bind, string epk, string iv, string ct, string info)
    {
        byte[]? secret = null;
        byte[]? key = null;
        byte[]? plain = null;
        try
        {
            byte[] point = Decode(epk);
            byte[] nonce = Decode(iv);
            byte[] sealedBytes = Decode(ct);
            if (point.Length != PointLength || point[0] != 0x04 || nonce.Length != IvLength || sealedBytes.Length < TagLength)
            {
                throw Failed();
            }

            byte[] x = point[1..(1 + CoordinateLength)];
            byte[] y = point[(1 + CoordinateLength)..];
            if (!OnCurve(x, y))
            {
                throw Failed();
            }

            using ECDiffieHellman server = ECDiffieHellman.Create();
            server.ImportECPrivateKey(privateState, out _);
            using ECDiffieHellman peer = ECDiffieHellman.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y },
            });
            secret = server.DeriveRawSecretAgreement(peer.PublicKey);
            key = HKDF.DeriveKey(HashAlgorithmName.SHA256, secret, 32, bind, Encoding.UTF8.GetBytes(info));

            int length = sealedBytes.Length - TagLength;
            byte[] opened = new byte[length];
            plain = opened;
            using AesGcm aes = new(key, TagLength);
            aes.Decrypt(nonce, sealedBytes.AsSpan(0, length), sealedBytes.AsSpan(length), opened, bind);
            plain = null;

            return opened;
        }
        catch (Exception)
        {
            // One message for every failure, so the reply says nothing about what was wrong.
            throw Failed();
        }
        finally
        {
            Clear(secret);
            Clear(key);
            Clear(plain);
        }
    }

    private static CryptographicException Failed()
    {
        return new CryptographicException("The secrets could not be decrypted.");
    }

    private static byte[] Decode(string text)
    {
        return Base64Url.DecodeFromChars(text);
    }

    /// <summary>Both coordinates are below p and the point is on the curve. The platform checks too; this does not depend on it.</summary>
    private static bool OnCurve(byte[] xBytes, byte[] yBytes)
    {
        BigInteger x = new(xBytes, isUnsigned: true, isBigEndian: true);
        BigInteger y = new(yBytes, isUnsigned: true, isBigEndian: true);
        if (x >= P || y >= P)
        {
            return false;
        }

        BigInteger left = BigInteger.ModPow(y, 2, P);
        BigInteger right = (((BigInteger.ModPow(x, 3, P) - (3 * x) + B) % P) + P) % P;

        return left == right;
    }

    private static void Clear(byte[]? buffer)
    {
        if (buffer is not null)
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }
}

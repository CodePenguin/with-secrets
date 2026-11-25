using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Json;

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace WithSecrets;

/// <summary>One compact JWE suite for the store and review keys. Signing and passkey wrapping are separate.</summary>
public sealed class JweCipher : ISecretCipher
{
    public static readonly JweCipher Instance = new();
    public const string Prefix = "jwe:v1:";
    private const string Algorithm = "ECDH-ES+A256KW";
    private const string Encryption = "A256CBC-HS512";
    // Grant review text can include the entire launch request, and JWE adds encoding overhead.
    private const int MaxEnvelope = 8 * HostService.MaxBodyBytes;

    static JweCipher()
    {
        // IdentityModel 8 emits the RFC 7518 ephemeral public key only when this switch is set.
        AppContext.SetSwitch("Switch.Microsoft.IdentityModel.UseRfcDefinitionOfEpkAndKid", true);
    }

    private JweCipher() { }

    public (string PublicKey, string PrivateKey) NewKeyPair()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] privateKey = key.ExportPkcs8PrivateKey();
        try
        {
            return (Base64Url.EncodeToString(key.ExportSubjectPublicKeyInfo()), Base64Url.EncodeToString(privateKey));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }
    }

    public string Encrypt(string value, string publicKey)
    {
        using ECDsa recipient = ECDsa.Create();
        ImportPublicKey(recipient, publicKey);
        using ECDsa ephemeral = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var credentials = new EncryptingCredentials(new ECDsaSecurityKey(ephemeral), Algorithm, Encryption)
        {
            KeyExchangePublicKey = new ECDsaSecurityKey(recipient),
        };

        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        return Prefix + handler.CreateToken(JsonSerializer.Serialize(new { value }), credentials);
    }

    public string Decrypt(string privateKey, string ciphertext)
    {
        if (!IsCiphertext(ciphertext))
        {
            throw new CryptographicException("Invalid sealed value.");
        }

        var handler = new JsonWebTokenHandler { MaximumTokenSizeInBytes = MaxEnvelope };
        JsonWebToken envelope = handler.ReadJsonWebToken(ciphertext[Prefix.Length..]);
        if (envelope.Alg != Algorithm || envelope.Enc != Encryption || !string.IsNullOrEmpty(envelope.Zip))
        {
            throw new CryptographicException("Unsupported sealed value.");
        }

        using ECDsa key = ECDsa.Create();
        ImportPrivateKey(key, privateKey);
        string inner = handler.DecryptToken(envelope, new TokenValidationParameters { TokenDecryptionKey = new ECDsaSecurityKey(key) });
        byte[] payload = Base64Url.DecodeFromChars(handler.ReadJsonWebToken(inner).EncodedPayload);
        try
        {
            using JsonDocument document = JsonDocument.Parse(payload);
            return document.RootElement.GetProperty("value").GetString() ?? throw new CryptographicException("Invalid sealed value.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    public string Derive(string privateKey)
    {
        using ECDsa key = ECDsa.Create();
        ImportPrivateKey(key, privateKey);
        return Base64Url.EncodeToString(key.ExportSubjectPublicKeyInfo());
    }

    public static bool IsCiphertext(string text)
        => text.Length <= MaxEnvelope && text.StartsWith(Prefix, StringComparison.Ordinal)
            && text[Prefix.Length..].Split('.') is { Length: 5 } parts
            && parts.All(part => part.Length > 0 && Base64Url.IsValid(part));

    public static bool IsPublicKey(string text)
    {
        if (text.Length != 122 || !Base64Url.IsValid(text))
        {
            return false;
        }

        try
        {
            using ECDsa key = ECDsa.Create();
            ImportPublicKey(key, text);
            return Base64Url.EncodeToString(key.ExportSubjectPublicKeyInfo()) == text;
        }
        catch (Exception error) when (error is CryptographicException or FormatException or ArgumentException)
        {
            return false;
        }
    }

    private static void ImportPublicKey(ECDsa key, string text)
    {
        byte[] data = Base64Url.DecodeFromChars(text);
        key.ImportSubjectPublicKeyInfo(data, out int read);
        RequireP256(key, read, data.Length);
    }

    private static void ImportPrivateKey(ECDsa key, string text)
    {
        byte[] data = Base64Url.DecodeFromChars(text);
        try
        {
            key.ImportPkcs8PrivateKey(data, out int read);
            RequireP256(key, read, data.Length);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data);
        }
    }

    private static void RequireP256(ECDsa key, int read, int length)
    {
        if (read != length || key.ExportParameters(false).Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value)
        {
            throw new CryptographicException("Invalid P-256 key.");
        }
    }
}

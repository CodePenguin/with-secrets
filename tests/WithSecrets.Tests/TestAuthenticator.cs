using System.Buffers.Binary;
using System.Buffers.Text;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WithSecrets.Tests;

/// <summary>
/// A software passkey for tests. It builds the same messages a browser sends: an assertion for sign-in and a registration
/// with "none" attestation. ES256 signatures are DER, as browsers send them.
/// </summary>
internal sealed class TestAuthenticator : IDisposable
{
    private readonly ECDsa? _ec;
    private readonly RSA? _rsa;

    private TestAuthenticator(ECDsa? ec, RSA? rsa, int alg)
    {
        _ec = ec;
        _rsa = rsa;
        Alg = alg;
        CredentialId = RandomNumberGenerator.GetBytes(16);
        Known[Encode(CredentialId)] = this;
    }

    /// <summary>Every authenticator made in this process, by credential id, so test helpers can sign as the admin key.</summary>
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, TestAuthenticator> Known = new(StringComparer.Ordinal);

    public static TestAuthenticator? ById(string id) => Known.TryGetValue(id, out TestAuthenticator? found) ? found : null;

    public int Alg { get; }

    /// <summary>The authenticator's PRF secret (what a real one keeps inside: the per-credential hmac-secret).</summary>
    public byte[] PrfSecret { get; } = RandomNumberGenerator.GetBytes(32);

    /// <summary>False plays an authenticator without the PRF extension: it returns no PRF result at create or at get.</summary>
    public bool SupportsPrf { get; set; } = true;

    /// <summary>
    /// What the PRF extension returns for <paramref name="salt" />: HMAC-SHA256(secret, "WebAuthn PRF" || 0x00 || salt), or
    /// null when this authenticator has no PRF. The same value comes at create and at get.
    /// </summary>
    public byte[]? Prf(byte[] salt)
    {
        return SupportsPrf ? HMACSHA256.HashData(PrfSecret, (byte[])[.. Encoding.ASCII.GetBytes("WebAuthn PRF"), 0, .. salt]) : null;
    }

    public byte[] CredentialId { get; }

    public static TestAuthenticator ES256(bool prf = true) => new(ECDsa.Create(ECCurve.NamedCurves.nistP256), null, -7) { SupportsPrf = prf };

    public static TestAuthenticator RS256(bool prf = true) => new(null, RSA.Create(2048), -257) { SupportsPrf = prf };

    public static string Encode(byte[] bytes) => Base64Url.EncodeToString(bytes);

    /// <summary>The COSE_Key for the public key, as an authenticator puts it in its attested credential data.</summary>
    public byte[] CoseKey()
    {
        if (_ec is not null)
        {
            ECParameters parameters = _ec.ExportParameters(false);

            return EcCose(Alg, 1, parameters.Q.X!, parameters.Q.Y!);
        }

        RSAParameters rsa = _rsa!.ExportParameters(false);

        return RsaCose(Alg, rsa.Modulus!, rsa.Exponent!);
    }

    /// <summary>An EC2 COSE_Key built from the given parts, so tests can make keys that are wrong in one way. A null alg leaves label 3 out.</summary>
    public static byte[] EcCose(int? alg, long curve, byte[] x, byte[] y)
    {
        CborWriter writer = new(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(alg is null ? 4 : 5);
        writer.WriteInt32(1);
        writer.WriteInt32(2);
        if (alg is not null)
        {
            writer.WriteInt32(3);
            writer.WriteInt32(alg.Value);
        }

        writer.WriteInt32(-1);
        writer.WriteInt64(curve);
        writer.WriteInt32(-2);
        writer.WriteByteString(x);
        writer.WriteInt32(-3);
        writer.WriteByteString(y);
        writer.WriteEndMap();

        return writer.Encode();
    }

    /// <summary>An RSA COSE_Key built from the given parts. A null alg leaves label 3 out.</summary>
    public static byte[] RsaCose(int? alg, byte[] modulus, byte[] exponent)
    {
        CborWriter writer = new(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(alg is null ? 3 : 4);
        writer.WriteInt32(1);
        writer.WriteInt32(3);
        if (alg is not null)
        {
            writer.WriteInt32(3);
            writer.WriteInt32(alg.Value);
        }

        writer.WriteInt32(-1);
        writer.WriteByteString(modulus);
        writer.WriteInt32(-2);
        writer.WriteByteString(exponent);
        writer.WriteEndMap();

        return writer.Encode();
    }

    /// <summary>The x and y of the EC public key (ES256 authenticators only).</summary>
    public (byte[] X, byte[] Y) EcPoint()
    {
        ECParameters parameters = _ec!.ExportParameters(false);

        return (parameters.Q.X!, parameters.Q.Y!);
    }

    public PasskeyRecord Record(string rpId, string name, byte[]? masterKey = null)
    {
        return new PasskeyRecord(Encode(CredentialId), Encode(CoseKey()), Alg, rpId, name, DateTimeOffset.UtcNow, 0, false, Slot(masterKey ?? KeyVault.NewMasterKey()));
    }

    /// <summary>A slot of <paramref name="masterKey" /> for this credential, as enrollment makes it; null for an authenticator without PRF.</summary>
    public KeySlot? Slot(byte[] masterKey)
    {
        byte[] salt = KeyVault.NewSalt();
        byte[]? output = Prf(salt);

        return output is null ? null : new KeySlot(Encode(salt), KeyVault.WrapSlot(masterKey, output, CredentialId, salt));
    }

    /// <summary>Returns the JSON the page posts after navigator.credentials.get: id, authenticatorData, clientDataJSON, signature.</summary>
    public string Assert(
        byte[] challenge,
        string origin,
        string rpId,
        uint signCount,
        bool userVerified = true,
        string type = "webauthn.get",
        bool userPresent = true)
    {
        byte flags = (byte)((userPresent ? 0x01 : 0) | (userVerified ? 0x04 : 0));
        byte[] authenticatorData = AuthenticatorData(rpId, flags, signCount, []);
        byte[] clientDataJson = ClientData(type, challenge, origin);
        byte[] signature = Sign([.. authenticatorData, .. SHA256.HashData(clientDataJson)]);

        return JsonSerializer.Serialize(
            new Dictionary<string, string>
            {
                ["id"] = Encode(CredentialId),
                ["authenticatorData"] = Encode(authenticatorData),
                ["clientDataJSON"] = Encode(clientDataJson),
                ["signature"] = Encode(signature),
            });
    }

    /// <summary>
    /// Returns the JSON the page posts after navigator.credentials.create: id, clientDataJSON, attestationObject. The
    /// attestation is "none"; authData has flags UP|UV|AT (0x45), a zero AAGUID, the credential id and the COSE key.
    /// </summary>
    public string Attest(
        byte[] challenge,
        string origin,
        string rpId,
        string name,
        string fmt = "none",
        string type = "webauthn.create",
        byte flags = 0x45,
        string? authDataRpId = null,
        byte[]? coseKey = null,
        int? authDataLength = null,
        byte[]? clientDataJson = null)
    {
        _ = name; // The name is the person's label for the key; the authenticator never sees it.
        byte[] credentialIdLength = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(credentialIdLength, (ushort)CredentialId.Length);
        byte[] attested = [.. new byte[16], .. credentialIdLength, .. CredentialId, .. coseKey ?? CoseKey()];
        byte[] authData = AuthenticatorData(authDataRpId ?? rpId, flags, 0, attested);
        if (authDataLength is not null)
        {
            authData = authData[..authDataLength.Value];
        }

        CborWriter writer = new(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(3);
        writer.WriteTextString("fmt");
        writer.WriteTextString(fmt);
        writer.WriteTextString("attStmt");
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteTextString("authData");
        writer.WriteByteString(authData);
        writer.WriteEndMap();

        return AttestationJson(Encode(CredentialId), clientDataJson ?? ClientData(type, challenge, origin), writer.Encode());
    }

    /// <summary>The registration JSON for an attestationObject the caller built, for malformed-CBOR cases.</summary>
    public static string AttestationJson(string id, byte[] clientDataJson, byte[] attestationObject)
    {
        return JsonSerializer.Serialize(
            new Dictionary<string, string>
            {
                ["id"] = id,
                ["clientDataJSON"] = Encode(clientDataJson),
                ["attestationObject"] = Encode(attestationObject),
            });
    }

    public void Dispose()
    {
        _ec?.Dispose();
        _rsa?.Dispose();
    }

    private static byte[] AuthenticatorData(string rpId, byte flags, uint signCount, byte[] rest)
    {
        byte[] count = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(count, signCount);

        return [.. SHA256.HashData(Encoding.UTF8.GetBytes(rpId)), flags, .. count, .. rest];
    }

    private static byte[] ClientData(string type, byte[] challenge, string origin)
    {
        // Same member order as browsers: type, challenge, origin, crossOrigin.
        string json = "{\"type\":" + JsonSerializer.Serialize(type)
            + ",\"challenge\":" + JsonSerializer.Serialize(Encode(challenge))
            + ",\"origin\":" + JsonSerializer.Serialize(origin)
            + ",\"crossOrigin\":false}";

        return Encoding.UTF8.GetBytes(json);
    }

    private byte[] Sign(byte[] data)
    {
        return _ec is not null
            ? _ec.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)
            : _rsa!.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
}

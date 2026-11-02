using System.Buffers.Binary;
using System.Buffers.Text;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WithSecrets;

/// <summary>The outcome of checking a passkey sign-in. <see cref="NewSignCount" /> is to be stored only when Ok; it is 0 otherwise.</summary>
public sealed record AssertionResult(bool Ok, string Detail, uint NewSignCount);

/// <summary>The outcome of checking a passkey registration. <see cref="Key" /> is the passkey to store when Ok; it is null otherwise.</summary>
public sealed record RegistrationResult(bool Ok, string Detail, PasskeyRecord? Key);

/// <summary>
/// Checks what the browser sends after a passkey prompt. Everything fails closed: a message that cannot be read, or that
/// fails any check, gives Ok=false with a short reason. Nothing here throws for bad input.
/// </summary>
public static class WebAuthn
{
    /// <summary>COSE algorithm ES256: ECDSA with P-256 and SHA-256.</summary>
    public const int ES256 = -7;

    /// <summary>COSE algorithm RS256: RSASSA-PKCS1-v1_5 with SHA-256.</summary>
    public const int RS256 = -257;

    private const byte UserPresent = 0x01;
    private const byte UserVerified = 0x04;
    private const byte AttestedCredentialData = 0x40;
    private const byte ExtensionData = 0x80;

    // rpIdHash(32) | flags(1) | signCount(4)
    private const int AuthDataMinimum = 37;

    private static readonly JsonDocumentOptions Strict = new() { AllowDuplicateProperties = false };

    /// <summary>
    /// Checks a sign-in (navigator.credentials.get) made with <paramref name="key" />. <paramref name="responseJson" /> is
    /// {"id","authenticatorData","clientDataJSON","signature"}, each base64url.
    /// </summary>
    public static AssertionResult VerifyAssertion(PasskeyRecord key, byte[] expectedChallenge, string expectedOrigin, string rpId, string responseJson)
    {
        try
        {
            return Check(key, expectedChallenge, expectedOrigin, rpId, responseJson, true);
        }
        catch (Exception error) when (error is JsonException or FormatException or CborContentException or InvalidOperationException
            or CryptographicException or ArgumentException or OverflowException or NotSupportedException)
        {
            // Each expected failure is handled where it happens; this is the backstop that keeps the check closed.
            return Fail("response could not be checked");
        }
    }

    /// <summary>
    /// Checks an assertion that was checked in full when it was made and is now read back from storage (the signed manifest):
    /// the credential id, the signature with <paramref name="key" />, the type and challenge in the client data, and user
    /// presence and verification. The origin, the rpId hash and the sign count are not checked again.
    /// </summary>
    public static AssertionResult VerifyStored(PasskeyRecord key, byte[] expectedChallenge, string responseJson)
    {
        try
        {
            return Check(key, expectedChallenge, null, null, responseJson, false);
        }
        catch (Exception error) when (error is JsonException or FormatException or CborContentException or InvalidOperationException
            or CryptographicException or ArgumentException or OverflowException or NotSupportedException)
        {
            return Fail("response could not be checked");
        }
    }

    /// <summary>
    /// Checks a registration (navigator.credentials.create) with "none" attestation and, when it is right, returns the passkey
    /// to store. <paramref name="responseJson" /> is {"id","clientDataJSON","attestationObject"}, each base64url. The key must
    /// meet the same rules sign-in applies, so every stored key can verify later.
    /// </summary>
    public static RegistrationResult VerifyRegistration(byte[] expectedChallenge, string expectedOrigin, string rpId, string name, string responseJson)
    {
        try
        {
            return CheckRegistration(expectedChallenge, expectedOrigin, rpId, name, responseJson);
        }
        catch (Exception error) when (error is JsonException or FormatException or CborContentException or InvalidOperationException
            or CryptographicException or ArgumentException or OverflowException or NotSupportedException)
        {
            return RegistrationFail("response could not be checked");
        }
    }

    private static RegistrationResult CheckRegistration(byte[] expectedChallenge, string expectedOrigin, string rpId, string name, string responseJson)
    {
        if (expectedChallenge is null || expectedOrigin is null || rpId is null || name is null || responseJson is null)
        {
            return RegistrationFail("missing input");
        }

        if (expectedChallenge.Length == 0)
        {
            return RegistrationFail("no expected challenge");
        }

        if (string.IsNullOrWhiteSpace(name))
        {
            return RegistrationFail("no passkey name");
        }

        using JsonDocument? response = ParseObject(responseJson);
        if (response is null)
        {
            return RegistrationFail("response is not a JSON object");
        }

        string? id = Text(response.RootElement, "id");
        string? clientDataText = Text(response.RootElement, "clientDataJSON");
        string? attestationText = Text(response.RootElement, "attestationObject");
        if (id is null || clientDataText is null || attestationText is null)
        {
            return RegistrationFail("response is missing a field");
        }

        byte[]? clientDataJson = Decode(clientDataText);
        byte[]? attestation = Decode(attestationText);
        if (clientDataJson is null || attestation is null)
        {
            return RegistrationFail("response field is not base64url");
        }

        string? clientDataError = CheckClientData(clientDataJson, "webauthn.create", expectedChallenge, expectedOrigin);
        if (clientDataError is not null)
        {
            return RegistrationFail(clientDataError);
        }

        string? attestationError = ReadAttestation(attestation, out string? format, out byte[]? authData);
        if (attestationError is not null || authData is null)
        {
            return RegistrationFail(attestationError ?? "attestationObject is not valid");
        }

        if (format != "none")
        {
            return RegistrationFail("attestation format is not none");
        }

        if (authData.Length < AuthDataMinimum)
        {
            return RegistrationFail("authData is too short");
        }

        if (!CryptographicOperations.FixedTimeEquals(authData.AsSpan(0, 32), SHA256.HashData(Encoding.UTF8.GetBytes(rpId))))
        {
            return RegistrationFail("rpId hash does not match");
        }

        byte flags = authData[32];
        if ((flags & UserPresent) == 0)
        {
            return RegistrationFail("user not present");
        }

        if ((flags & UserVerified) == 0)
        {
            return RegistrationFail("user not verified");
        }

        if ((flags & AttestedCredentialData) == 0)
        {
            return RegistrationFail("no attested credential data");
        }

        // After the 37 bytes: aaguid(16), credIdLen(2), credId, then the COSE key.
        const int CredentialIdLengthAt = AuthDataMinimum + 16;
        const int CredentialIdAt = CredentialIdLengthAt + 2;
        if (authData.Length < CredentialIdAt)
        {
            return RegistrationFail("attested credential data is truncated");
        }

        int credentialIdLength = BinaryPrimitives.ReadUInt16BigEndian(authData.AsSpan(CredentialIdLengthAt, 2));
        if (credentialIdLength is 0 or > 1023)
        {
            return RegistrationFail("credential id length is not valid");
        }

        int keyAt = CredentialIdAt + credentialIdLength;
        if (authData.Length <= keyAt)
        {
            return RegistrationFail("attested credential data is truncated");
        }

        string credentialId = Base64Url.EncodeToString(authData.AsSpan(CredentialIdAt, credentialIdLength));
        if (!string.Equals(id, credentialId, StringComparison.Ordinal))
        {
            return RegistrationFail("credential id does not match");
        }

        Dictionary<long, object>? cose = ReadCoseKey(authData.AsMemory(keyAt), out int keyLength);
        if (cose is null)
        {
            return RegistrationFail("public key is not valid");
        }

        // Anything after the key must be extension data, which the authenticator flags.
        if (keyAt + keyLength != authData.Length && (flags & ExtensionData) == 0)
        {
            return RegistrationFail("authData has bytes after the public key");
        }

        if (Number(cose, 3) is not long alg || alg is not (ES256 or RS256))
        {
            return RegistrationFail("unsupported algorithm");
        }

        using AsymmetricAlgorithm? publicKey = ImportKey(cose, (int)alg, out string? keyError);
        if (publicKey is null)
        {
            return RegistrationFail(keyError ?? "public key is not valid");
        }

        PasskeyRecord record = new(credentialId, Base64Url.EncodeToString(authData.AsSpan(keyAt, keyLength)), (int)alg, rpId, name, DateTimeOffset.UtcNow, 0);

        return new RegistrationResult(true, "ok", record);
    }

    /// <summary>Reads the attestationObject map: fmt, attStmt (an empty map, as "none" has) and authData. Returns null when it is right, else the reason.</summary>
    private static string? ReadAttestation(byte[] bytes, out string? format, out byte[]? authData)
    {
        format = null;
        authData = null;
        const string Invalid = "attestationObject is not valid";
        try
        {
            CborReader reader = new(bytes, CborConformanceMode.Strict);
            int? count = reader.ReadStartMap();
            bool statement = false;
            for (int index = 0; count is null ? reader.PeekState() != CborReaderState.EndMap : index < count; index++)
            {
                if (reader.PeekState() != CborReaderState.TextString)
                {
                    return Invalid;
                }

                switch (reader.ReadTextString())
                {
                    case "fmt" when format is null && reader.PeekState() == CborReaderState.TextString:
                        format = reader.ReadTextString();
                        break;
                    case "attStmt" when !statement && reader.PeekState() == CborReaderState.StartMap:
                        if (reader.ReadStartMap() != 0)
                        {
                            return Invalid;
                        }

                        reader.ReadEndMap();
                        statement = true;
                        break;
                    case "authData" when authData is null && reader.PeekState() == CborReaderState.ByteString:
                        authData = reader.ReadByteString();
                        break;
                    default:
                        return Invalid; // Unknown, repeated or mistyped member.
                }
            }

            reader.ReadEndMap();

            return format is null || authData is null || !statement || reader.BytesRemaining != 0 ? Invalid : null;
        }
        catch (Exception error) when (error is CborContentException or InvalidOperationException or OverflowException)
        {
            return Invalid;
        }
    }

    /// <summary>With <paramref name="live" /> false (a stored assertion), origin and rpId are null and are not checked, nor is the sign count.</summary>
    private static AssertionResult Check(PasskeyRecord key, byte[] expectedChallenge, string? expectedOrigin, string? rpId, string responseJson, bool live)
    {
        if (key is null || expectedChallenge is null || responseJson is null || (live && (expectedOrigin is null || rpId is null)))
        {
            return Fail("missing input");
        }

        if (expectedChallenge.Length == 0)
        {
            return Fail("no expected challenge");
        }

        if (live && key.RpId != rpId)
        {
            return Fail("passkey is for another rpId");
        }

        if (key.Alg is not (ES256 or RS256))
        {
            return Fail("unsupported algorithm");
        }

        using JsonDocument? response = ParseObject(responseJson);
        if (response is null)
        {
            return Fail("response is not a JSON object");
        }

        string? id = Text(response.RootElement, "id");
        string? authDataText = Text(response.RootElement, "authenticatorData");
        string? clientDataText = Text(response.RootElement, "clientDataJSON");
        string? signatureText = Text(response.RootElement, "signature");
        if (id is null || authDataText is null || clientDataText is null || signatureText is null)
        {
            return Fail("response is missing a field");
        }

        if (!string.Equals(id, key.Id, StringComparison.Ordinal))
        {
            return Fail("credential id does not match");
        }

        byte[]? authData = Decode(authDataText);
        byte[]? clientDataJson = Decode(clientDataText);
        byte[]? signature = Decode(signatureText);
        if (authData is null || clientDataJson is null || signature is null)
        {
            return Fail("response field is not base64url");
        }

        string? clientDataError = CheckClientData(clientDataJson, "webauthn.get", expectedChallenge, expectedOrigin);
        if (clientDataError is not null)
        {
            return Fail(clientDataError);
        }

        if (authData.Length < AuthDataMinimum)
        {
            return Fail("authenticatorData is too short");
        }

        if (live && !CryptographicOperations.FixedTimeEquals(authData.AsSpan(0, 32), SHA256.HashData(Encoding.UTF8.GetBytes(rpId!))))
        {
            return Fail("rpId hash does not match");
        }

        byte flags = authData[32];
        if ((flags & UserPresent) == 0)
        {
            return Fail("user not present");
        }

        if ((flags & UserVerified) == 0)
        {
            return Fail("user not verified");
        }

        uint signCount = BinaryPrimitives.ReadUInt32BigEndian(authData.AsSpan(33, 4));

        string? keyError = VerifySignature(key, [.. authData, .. SHA256.HashData(clientDataJson)], signature);
        if (keyError is not null)
        {
            return Fail(keyError);
        }

        // Synced passkeys always report 0. Otherwise the count must go up, or the key may have been copied.
        if (live && !(signCount == 0 && key.SignCount == 0) && signCount <= key.SignCount)
        {
            return Fail("sign count did not increase");
        }

        return new AssertionResult(true, "ok", signCount);
    }

    /// <summary>Returns null when the client data is right, else the reason.</summary>
    /// <summary>A null <paramref name="expectedOrigin" /> is not checked (a stored assertion).</summary>
    private static string? CheckClientData(byte[] clientDataJson, string type, byte[] expectedChallenge, string? expectedOrigin)
    {
        string text;
        try
        {
            text = new UTF8Encoding(false, true).GetString(clientDataJson);
        }
        catch (ArgumentException)
        {
            return "clientDataJSON is not UTF-8";
        }

        using JsonDocument? clientData = ParseObject(text);
        if (clientData is null)
        {
            return "clientDataJSON is not a JSON object";
        }

        JsonElement root = clientData.RootElement;
        if (Text(root, "type") != type)
        {
            return "clientData type is not " + type;
        }

        if (!string.Equals(Text(root, "challenge"), Base64Url.EncodeToString(expectedChallenge), StringComparison.Ordinal))
        {
            return "challenge does not match";
        }

        if (expectedOrigin is not null && !string.Equals(Text(root, "origin"), expectedOrigin, StringComparison.Ordinal))
        {
            return "origin does not match";
        }

        // Only an explicit false (or no member) is accepted; a page framed by another site sets crossOrigin and topOrigin.
        bool crossOrigin = root.TryGetProperty("crossOrigin", out JsonElement cross) && cross.ValueKind != JsonValueKind.False;
        if (crossOrigin || root.TryGetProperty("topOrigin", out _))
        {
            return "cross-origin request";
        }

        return null;
    }

    /// <summary>Returns null when <paramref name="signature" /> over <paramref name="data" /> verifies with the key, else the reason.</summary>
    private static string? VerifySignature(PasskeyRecord key, byte[] data, byte[] signature)
    {
        byte[]? coseBytes = Decode(key.PublicKey);
        Dictionary<long, object>? cose = null;
        if (coseBytes is not null)
        {
            cose = ReadCoseKey(coseBytes, out int length);
            if (length != coseBytes.Length)
            {
                cose = null; // Bytes after the key: not what was stored at registration.
            }
        }

        if (cose is null)
        {
            return "public key is not valid";
        }

        using AsymmetricAlgorithm? publicKey = ImportKey(cose, key.Alg, out string? keyError);
        if (publicKey is null)
        {
            return keyError ?? "public key is not valid";
        }

        bool verified;
        try
        {
            verified = publicKey is ECDsa ecdsa
                ? ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)
                : ((RSA)publicKey).VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (Exception error) when (error is CryptographicException or ArgumentException)
        {
            verified = false; // A signature that is not DER, or of the wrong size.
        }

        return verified ? null : "signature does not verify";
    }

    /// <summary>
    /// The one place a COSE key is accepted, for registration and for sign-in alike: it must be the key type of
    /// <paramref name="alg" /> and meet the rules below. Returns null, with the reason in <paramref name="error" />, when it does not.
    /// </summary>
    private static AsymmetricAlgorithm? ImportKey(Dictionary<long, object> cose, int alg, out string? error)
    {
        error = null;
        if (Number(cose, 1) != (alg == ES256 ? 2 : 3) || Number(cose, 3) != alg)
        {
            error = "public key does not match its algorithm";

            return null;
        }

        return alg == ES256 ? ImportEc2(cose, out error) : ImportRsa(cose, out error);
    }

    /// <summary>COSE EC2 key on P-256: crv (-1) is 1, x (-2) and y (-3) are 32 bytes each and the point is on the curve.</summary>
    private static ECDsa? ImportEc2(Dictionary<long, object> cose, out string? error)
    {
        error = null;
        if (Number(cose, -1) != 1)
        {
            error = "EC key is not on P-256";

            return null;
        }

        if (Bytes(cose, -2) is not { Length: 32 } x || Bytes(cose, -3) is not { Length: 32 } y)
        {
            error = "EC key coordinates are not 32 bytes";

            return null;
        }

        try
        {
            return ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } });
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException or NotSupportedException)
        {
            error = "EC key point is not on the curve";

            return null;
        }
    }

    /// <summary>COSE RSA key: n (-1) of at least 2048 bits (leading zero bytes not counted), e (-2) odd and at least 3.</summary>
    private static RSA? ImportRsa(Dictionary<long, object> cose, out string? error)
    {
        error = null;
        if (Bytes(cose, -1) is not { } n || Bytes(cose, -2) is not { } e)
        {
            error = "RSA key is missing n or e";

            return null;
        }

        byte[] modulus = [.. n.SkipWhile(item => item == 0)];
        if (modulus.Length == 0 || ((modulus.Length - 1) * 8) + (8 - byte.LeadingZeroCount(modulus[0])) < 2048)
        {
            error = "RSA modulus is under 2048 bits";

            return null;
        }

        byte[] exponent = [.. e.SkipWhile(item => item == 0)];
        if (exponent.Length is 0 or > 8 || (exponent[^1] & 1) == 0 || (exponent.Length == 1 && exponent[0] < 3))
        {
            error = "RSA exponent is not odd and at least 3";

            return null;
        }

        try
        {
            return RSA.Create(new RSAParameters { Modulus = modulus, Exponent = exponent });
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException or NotSupportedException)
        {
            error = "RSA key is not valid";

            return null;
        }
    }

    /// <summary>
    /// Reads one COSE_Key (a CBOR map with integer labels) from the start of <paramref name="data" />. Returns null when it is
    /// not one. <paramref name="length" /> is how many bytes the key took. Integer values are long, byte strings byte[];
    /// other values are skipped.
    /// </summary>
    internal static Dictionary<long, object>? ReadCoseKey(ReadOnlyMemory<byte> data, out int length)
    {
        length = 0;
        try
        {
            CborReader reader = new(data, CborConformanceMode.Strict);
            Dictionary<long, object> fields = [];
            int? count = reader.ReadStartMap();
            for (int index = 0; count is null ? reader.PeekState() != CborReaderState.EndMap : index < count; index++)
            {
                if (reader.PeekState() is not (CborReaderState.UnsignedInteger or CborReaderState.NegativeInteger))
                {
                    return null;
                }

                long label = reader.ReadInt64();
                if (fields.ContainsKey(label))
                {
                    return null;
                }

                switch (reader.PeekState())
                {
                    case CborReaderState.UnsignedInteger or CborReaderState.NegativeInteger:
                        fields[label] = reader.ReadInt64();
                        break;
                    case CborReaderState.ByteString:
                        fields[label] = reader.ReadByteString();
                        break;
                    default:
                        reader.SkipValue();
                        break;
                }
            }

            reader.ReadEndMap();
            length = data.Length - reader.BytesRemaining;

            return fields;
        }
        catch (Exception error) when (error is CborContentException or InvalidOperationException or OverflowException)
        {
            return null;
        }
    }

    private static long? Number(Dictionary<long, object> cose, long label) => cose.TryGetValue(label, out object? value) && value is long number ? number : null;

    private static byte[]? Bytes(Dictionary<long, object> cose, long label) => cose.TryGetValue(label, out object? value) ? value as byte[] : null;

    private static AssertionResult Fail(string detail) => new(false, detail, 0);

    private static RegistrationResult RegistrationFail(string detail) => new(false, detail, null);

    private static JsonDocument? ParseObject(string json)
    {
        try
        {
            JsonDocument document = JsonDocument.Parse(json, Strict);
            if (document.RootElement.ValueKind == JsonValueKind.Object)
            {
                return document;
            }

            document.Dispose();

            return null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? Text(JsonElement element, string name)
    {
        return element.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    }

    /// <summary>Strict base64url: no padding, no whitespace. Returns null for anything else.</summary>
    private static byte[]? Decode(string? text)
    {
        if (string.IsNullOrEmpty(text) || !Base64Url.IsValid(text) || text.AsSpan().ContainsAny("= \t\r\n"))
        {
            return null;
        }

        try
        {
            return Base64Url.DecodeFromChars(text);
        }
        catch (FormatException)
        {
            return null;
        }
    }
}

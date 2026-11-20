using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace WithSecrets;

/// <summary>
/// An ECDSA P-256 key that signs and whose private part is never handed out. <see cref="PublicKey" /> is the canonical
/// SubjectPublicKeyInfo (DER). Signatures are SHA-256 with the fixed-size r||s form (64 bytes).
/// </summary>
public interface ISigningKey : IDisposable
{
    byte[] PublicKey { get; }

    byte[] Sign(byte[] data);
}

/// <summary>Fingerprints and signature checks over canonical public keys.</summary>
public static class KeyIdentity
{
    public const int FingerprintLength = 64;

    private static readonly Oid P256 = new("1.2.840.10045.3.1.7");

    /// <summary>The fingerprint: SHA-256 of the canonical SubjectPublicKeyInfo, upper-case hex (64 characters).</summary>
    public static string Fingerprint(ReadOnlySpan<byte> publicKey) => Convert.ToHexString(SHA256.HashData(publicKey));

    /// <summary>Hex groups of four for a person to read and compare: <c>8214 BFB0 18F0 ...</c>.</summary>
    public static string Display(string fingerprint)
    {
        StringBuilder text = new();
        for (int index = 0; index < fingerprint.Length; index += 4)
        {
            text.Append(index == 0 ? "" : " ").Append(fingerprint, index, Math.Min(4, fingerprint.Length - index));
        }

        return text.ToString();
    }

    /// <summary>
    /// Reads typed hex (spaces, colons and dashes are ignored, case does not matter). With <paramref name="full" /> exactly 64 digits;
    /// otherwise at least 12, a prefix. Returns upper-case hex without separators, or null.
    /// </summary>
    public static string? ParseHex(string text, bool full)
    {
        string hex = new([.. text.Where(letter => letter is not (' ' or ':' or '-'))]);
        if (hex.Length > FingerprintLength || hex.Length < (full ? FingerprintLength : 12) || !hex.All(Uri.IsHexDigit))
        {
            return null;
        }

        return hex.ToUpperInvariant();
    }

    /// <summary>True when <paramref name="publicKey" /> is a P-256 SubjectPublicKeyInfo in exactly its canonical encoding.</summary>
    public static bool IsCanonicalP256(byte[] publicKey)
    {
        try
        {
            using ECDsa key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(publicKey, out int read);
            ECParameters parameters = key.ExportParameters(false);

            return read == publicKey.Length && parameters.Curve.Oid.Value == P256.Value && key.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(publicKey);
        }
        catch (Exception error) when (error is CryptographicException or ArgumentException)
        {
            return false;
        }
    }

    /// <summary>True when <paramref name="signature" /> (r||s) is a valid SHA-256 ECDSA signature of <paramref name="data" /> by <paramref name="publicKey" />.</summary>
    public static bool Verify(byte[] publicKey, byte[] data, byte[] signature)
    {
        if (signature.Length != 64 || !IsCanonicalP256(publicKey))
        {
            return false;
        }

        try
        {
            using ECDsa key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(publicKey, out _);

            return key.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception error) when (error is CryptographicException or ArgumentException)
        {
            return false;
        }
    }
}

/// <summary>
/// A key held in memory only, for tests, tools and a second identity in one process. It is not what a host service uses: that
/// is <see cref="CngSigningKey" />, whose private part the operating system keeps.
/// </summary>
public sealed class SoftwareSigningKey : ISigningKey
{
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly Lock _lock = new();

    public byte[] PublicKey => _key.ExportSubjectPublicKeyInfo();

    public byte[] Sign(byte[] data)
    {
        lock (_lock)
        {
            return _key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
    }

    public void Dispose() => _key.Dispose();
}

/// <summary>The fixed names of the keys that Windows CNG keeps for this program.</summary>
public static class KeyNames
{
    /// <summary>The name of the host service's machine identity key.</summary>
    public const string Machine = "with-secrets machine identity v1";

    /// <summary>The name of the (first) authority signing key; later generations add " g2", " g3"...</summary>
    public const string Authority = "with-secrets authority signing key v1";
}

/// <summary>
/// An ECDSA P-256 key kept by Windows CNG: persisted under a fixed name in the user's key store, created non-exportable, so the
/// private part cannot be read by this process or anything else (<c>ExportParameters(true)</c> fails). The Microsoft Platform
/// Crypto Provider (the TPM) is tried first; without a TPM the Microsoft Software Key Storage Provider is used, without a message.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class CngSigningKey : ISigningKey
{
    public static readonly CngProvider PlatformProvider = new("Microsoft Platform Crypto Provider");

    private readonly CngKey _key;
    private readonly ECDsaCng _ecdsa;
    private readonly Lock _lock = new();

    private CngSigningKey(CngKey key)
    {
        _key = key;
        _ecdsa = new ECDsaCng(key);
    }

    /// <summary>The provider that holds the key.</summary>
    public string Provider => _key.Provider?.Provider ?? "";

    public bool Exportable => _key.ExportPolicy != CngExportPolicies.None;

    public byte[] PublicKey => _ecdsa.ExportSubjectPublicKeyInfo();

    public byte[] Sign(byte[] data)
    {
        lock (_lock)
        {
            return _ecdsa.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
    }

    /// <summary>
    /// The key named <paramref name="name" />, made when it does not exist. An existing key is used only when it looks like what this
    /// program makes (ECDSA P-256, signing, non-exportable): a key that someone planted under the name, with its private part
    /// exportable, is refused, never adopted.
    /// </summary>
    public static CngSigningKey OpenOrCreate(string name, out bool created)
    {
        created = false;
        if (TryOpen(name) is { } existing)
        {
            if (existing.Problem() is { } problem)
            {
                existing.Dispose();
                throw new CryptographicException($"the key named \"{name}\" is not one this program made ({problem}); it was not used");
            }

            return existing;
        }

        CngSigningKey made = Create(name);
        created = true;

        return made;
    }

    /// <summary>
    /// A new key under <paramref name="name" />. A key that already has the name is deleted first: used for a generation that
    /// authority.db does not record yet, so whatever holds the name is a leftover or a planted key, never one in use.
    /// </summary>
    public static CngSigningKey CreateFresh(string name)
    {
        while (TryOpen(name) is { } leftover)
        {
            leftover.Delete();
            leftover.Dispose();
        }

        return Create(name);
    }

    /// <summary>Null when the key is what this program makes; otherwise what is different.</summary>
    internal string? Problem()
    {
        if (_key.AlgorithmGroup != CngAlgorithmGroup.ECDsa || _key.KeySize != 256)
        {
            return "not ECDSA P-256";
        }

        if (Exportable)
        {
            return "its private part is exportable";
        }

        return (_key.KeyUsage & CngKeyUsages.Signing) == 0 ? "not for signing" : null;
    }

    private static CngSigningKey Create(string name)
    {
        foreach (CngProvider provider in new[] { PlatformProvider, CngProvider.MicrosoftSoftwareKeyStorageProvider })
        {
            try
            {
                CngKeyCreationParameters parameters = new()
                {
                    Provider = provider,
                    ExportPolicy = CngExportPolicies.None,
                    KeyUsage = CngKeyUsages.Signing,
                };

                return new CngSigningKey(CngKey.Create(CngAlgorithm.ECDsaP256, name, parameters));
            }
            catch (CryptographicException) when (provider == PlatformProvider)
            {
                // No TPM, or it refused: the software provider is the fallback.
            }
        }

        throw new CryptographicException("the signing key could not be created");
    }

    /// <summary>The existing key named <paramref name="name" />, or null. Creates nothing.</summary>
    public static CngSigningKey? TryOpen(string name)
    {
        foreach (CngProvider provider in new[] { PlatformProvider, CngProvider.MicrosoftSoftwareKeyStorageProvider })
        {
            try
            {
                if (CngKey.Exists(name, provider))
                {
                    return new CngSigningKey(CngKey.Open(name, provider));
                }
            }
            catch (CryptographicException)
            {
                // The provider is not available here.
            }
        }

        return null;
    }

    /// <summary>Deletes the key from the key store. For tests that made a key of their own; the program never deletes an identity.</summary>
    public void Delete() => _key.Delete();

    public void Dispose()
    {
        _ecdsa.Dispose();
        _key.Dispose();
    }
}

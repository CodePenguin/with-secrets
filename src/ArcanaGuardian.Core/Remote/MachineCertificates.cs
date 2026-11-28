using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ArcanaGuardian;

/// <summary>
/// The X.509 profile of machine-to-machine TLS (architecture 10.2): a persistent, self-signed machine identity certificate made from the existing ECDSA P-256 identity key (a CA-capable trust anchor,
/// <c>CA=true pathLen=0</c>, <c>DigitalSignature</c> and <c>KeyCertSign</c>, ten years), and a temporary leaf (24 hours, not a CA, <c>DigitalSignature</c>, <c>serverAuth</c> and <c>clientAuth</c>, a SAN URI
/// <c>urn:arcana-guardian:machine:FINGERPRINT</c>) for a separate in-memory TLS key, signed by the identity key. Everything here is public data: the identity private key is only ever asked to sign (it stays in CNG),
/// and validation is done against one named identity certificate, never against a trust store.
/// </summary>
public static class MachineCertificates
{
    public const string SanPrefix = "urn:arcana-guardian:machine:";

    /// <summary>The identity certificate's validity, a little over ten years of notBefore skew at most.</summary>
    public static readonly TimeSpan IdentityValidity = TimeSpan.FromDays(3652);

    /// <summary>The longest identity certificate validity accepted (the cap on a certificate someone else made).</summary>
    public static readonly TimeSpan MaxIdentityValidity = TimeSpan.FromDays(3660);

    public static readonly TimeSpan TemporaryValidity = TimeSpan.FromHours(24);

    /// <summary>The longest temporary leaf validity accepted.</summary>
    public static readonly TimeSpan MaxTemporaryValidity = TimeSpan.FromHours(25);

    /// <summary>A temporary certificate is replaced this long before it expires.</summary>
    public static readonly TimeSpan RotateBefore = TimeSpan.FromHours(1);

    /// <summary>
    /// Clock skew tolerated between two machines, fixed: a certificate is accepted from this long before its notBefore until this long after its notAfter, and new certificates are backdated by the same amount, so two machines whose
    /// clocks differ by less than this still accept each other's fresh certificates.
    /// </summary>
    public static readonly TimeSpan Skew = TimeSpan.FromMinutes(5);

    public const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";
    public const string ClientAuthOid = "1.3.6.1.5.5.7.3.2";
    private const string EcdsaSha256Oid = "1.2.840.10045.4.3.2";
    private const string EcPublicKeyOid = "1.2.840.10045.2.1";
    private const string BasicConstraintsOid = "2.5.29.19";
    private const string KeyUsageOid = "2.5.29.15";
    private const string ExtendedKeyUsageOid = "2.5.29.37";
    private const string SubjectAltNameOid = "2.5.29.17";
    private const string SubjectKeyIdentifierOid = "2.5.29.14";
    private const string AuthorityKeyIdentifierOid = "2.5.29.35";

    public static string SanUri(string fingerprint) => SanPrefix + fingerprint;

    /// <summary>The fingerprint of an identity certificate (SHA-256 of its public key, as everywhere), or null when it is not a certificate.</summary>
    public static string? FingerprintOf(byte[] identityCertificate)
    {
        try
        {
            using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(identityCertificate);

            return KeyIdentity.Fingerprint(certificate.PublicKey.ExportSubjectPublicKeyInfo());
        }
        catch (Exception error) when (error is CryptographicException or ArgumentException)
        {
            return null;
        }
    }

    // ---- signing with a key that never leaves its holder ----

    /// <summary>Lets <see cref="CertificateRequest" /> have a certificate signed by an <see cref="ISigningKey" /> (the CNG identity key): only <see cref="ISigningKey.Sign" /> is used.</summary>
    private sealed class KeySignatureGenerator(ISigningKey key) : X509SignatureGenerator
    {
        protected override PublicKey BuildPublicKey() => PublicKey.CreateFromSubjectPublicKeyInfo(key.PublicKey, out _);

        public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm)
        {
            if (hashAlgorithm != HashAlgorithmName.SHA256)
            {
                throw new CryptographicException("only SHA-256 is used");
            }

            AsnWriter writer = new(AsnEncodingRules.DER);
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(EcdsaSha256Oid);
            }

            return writer.Encode();
        }

        /// <summary>A big-endian unsigned integer without redundant leading zero bytes (what DER requires; an r or s below 2^248 is shorter than 32 bytes).</summary>
        private static ReadOnlySpan<byte> Minimal(ReadOnlySpan<byte> value)
        {
            int skip = 0;
            while (skip < value.Length - 1 && value[skip] == 0)
            {
                skip++;
            }

            return value[skip..];
        }

        public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm)
        {
            byte[] raw = key.Sign(data);
            AsnWriter writer = new(AsnEncodingRules.DER);
            using (writer.PushSequence())
            {
                writer.WriteIntegerUnsigned(Minimal(raw.AsSpan(0, 32)));
                writer.WriteIntegerUnsigned(Minimal(raw.AsSpan(32, 32)));
            }

            return writer.Encode();
        }
    }

    private static byte[] Serial()
    {
        byte[] serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F;
        serial[0] |= 0x01;

        return serial;
    }

    private static DateTimeOffset Whole(DateTimeOffset time) => new(time.UtcDateTime.Ticks / TimeSpan.TicksPerSecond * TimeSpan.TicksPerSecond, TimeSpan.Zero);

    private static X500DistinguishedName IdentityName(string fingerprint) => new("CN=arcana-guardian machine " + fingerprint[..16]);

    // ---- the persistent identity certificate ----

    /// <summary>The self-signed identity certificate of <paramref name="identityKey" />, DER, public data only.</summary>
    public static byte[] CreateIdentity(ISigningKey identityKey, DateTimeOffset now)
    {
        byte[] spki = identityKey.PublicKey;
        string fingerprint = KeyIdentity.Fingerprint(spki);
        PublicKey publicKey = PublicKey.CreateFromSubjectPublicKeyInfo(spki, out _);
        X500DistinguishedName name = IdentityName(fingerprint);
        CertificateRequest request = new(name, publicKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(publicKey, false));
        DateTimeOffset notBefore = Whole(now - Skew);
        using X509Certificate2 certificate = request.Create(name, new KeySignatureGenerator(identityKey), notBefore, notBefore + IdentityValidity, Serial());

        return certificate.RawData;
    }

    /// <summary>Null when <paramref name="der" /> is an acceptable machine identity certificate at <paramref name="now" /> (and, when given, for exactly <paramref name="expectedPublicKey" />), else why not (no value in it).</summary>
    public static string? ValidateIdentity(byte[] der, DateTimeOffset now, byte[]? expectedPublicKey = null)
    {
        X509Certificate2 certificate;
        try
        {
            certificate = X509CertificateLoader.LoadCertificate(der);
        }
        catch (Exception error) when (error is CryptographicException or ArgumentException)
        {
            return "the identity certificate cannot be read";
        }

        using (certificate)
        {
            if (!certificate.RawData.AsSpan().SequenceEqual(der))
            {
                return "the identity certificate is not in its exact DER form";
            }

            byte[] spki = certificate.PublicKey.ExportSubjectPublicKeyInfo();
            if (certificate.Version != 3 || certificate.PublicKey.Oid.Value != EcPublicKeyOid || !KeyIdentity.IsCanonicalP256(spki))
            {
                return "the identity certificate's key is not an ECDSA P-256 key";
            }

            if (expectedPublicKey is not null && !spki.AsSpan().SequenceEqual(expectedPublicKey))
            {
                return "the identity certificate is for another key";
            }

            if (!certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData))
            {
                return "the identity certificate is not self-issued";
            }

            if (CheckSignature(certificate, spki) is { } signature)
            {
                return signature;
            }

            if (UnknownCritical(certificate) is { } unknown)
            {
                return unknown;
            }

            X509BasicConstraintsExtension? constraints = certificate.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault();
            if (constraints is null || !constraints.Critical || !constraints.CertificateAuthority || !constraints.HasPathLengthConstraint || constraints.PathLengthConstraint != 0)
            {
                return "the identity certificate must be a CA with path length 0";
            }

            X509KeyUsageExtension? usage = certificate.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
            if (usage is null || !usage.Critical || usage.KeyUsages != (X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign))
            {
                return "the identity certificate's key usage must be exactly DigitalSignature and KeyCertSign";
            }

            if (certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().Any())
            {
                return "the identity certificate must not limit or grant extended key usage";
            }

            DateTimeOffset notBefore = certificate.NotBefore.ToUniversalTime();
            DateTimeOffset notAfter = certificate.NotAfter.ToUniversalTime();
            if (now < notBefore - Skew)
            {
                return "the identity certificate is not valid yet";
            }

            if (now > notAfter + Skew)
            {
                return "the identity certificate has expired";
            }

            return notAfter - notBefore > MaxIdentityValidity ? "the identity certificate's validity is longer than ten years" : null;
        }
    }

    // ---- the temporary leaf ----

    /// <summary>
    /// The temporary leaf for <paramref name="tlsPublicKey" /> (a SubjectPublicKeyInfo of the in-memory TLS key), signed by <paramref name="identityKey" /> and issued under the name of <paramref name="identityCertificate" />:
    /// 24 hours, not a CA, <c>DigitalSignature</c>, both EKUs, the machine's SAN URI. Public data only (no private key).
    /// </summary>
    public static byte[] CreateTemporary(ISigningKey identityKey, byte[] identityCertificate, byte[] tlsPublicKey, DateTimeOffset now)
    {
        using X509Certificate2 identity = X509CertificateLoader.LoadCertificate(identityCertificate);
        string fingerprint = KeyIdentity.Fingerprint(identityKey.PublicKey);
        PublicKey publicKey = PublicKey.CreateFromSubjectPublicKeyInfo(tlsPublicKey, out _);
        CertificateRequest request = new(new X500DistinguishedName("CN=arcana-guardian temporary " + fingerprint[..16]), publicKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(ServerAuthOid), new Oid(ClientAuthOid)], false));
        SubjectAlternativeNameBuilder names = new();
        names.AddUri(new Uri(SanUri(fingerprint)));
        request.CertificateExtensions.Add(names.Build(true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(publicKey, false));
        if (identity.Extensions.OfType<X509SubjectKeyIdentifierExtension>().SingleOrDefault() is { } issuerKeyId)
        {
            request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(issuerKeyId));
        }

        DateTimeOffset notBefore = Whole(now - Skew);
        using X509Certificate2 leaf = request.Create(identity.SubjectName, new KeySignatureGenerator(identityKey), notBefore, notBefore + TemporaryValidity, Serial());

        return leaf.RawData;
    }

    /// <summary>
    /// The structure of a temporary leaf that does not depend on who issued it: ECDSA P-256 key, not a CA, <c>DigitalSignature</c>, both EKUs, exactly one SAN that is a machine URI, valid now for at most 25 hours.
    /// Null when sound, else why not. <paramref name="fingerprint" /> is the identity the SAN names.
    /// </summary>
    public static string? ValidateLeafStructure(X509Certificate2 leaf, DateTimeOffset now, out string fingerprint)
    {
        fingerprint = "";
        byte[] spki = leaf.PublicKey.ExportSubjectPublicKeyInfo();
        if (leaf.Version != 3 || leaf.PublicKey.Oid.Value != EcPublicKeyOid || !KeyIdentity.IsCanonicalP256(spki))
        {
            return "the certificate's key is not an ECDSA P-256 key";
        }

        if (leaf.SignatureAlgorithm.Value != EcdsaSha256Oid)
        {
            return "the certificate is not signed with ECDSA and SHA-256";
        }

        if (UnknownCritical(leaf) is { } unknown)
        {
            return unknown;
        }

        X509BasicConstraintsExtension? constraints = leaf.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault();
        if (constraints is null || constraints.CertificateAuthority)
        {
            return "the certificate must not be a CA";
        }

        X509KeyUsageExtension? usage = leaf.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
        if (usage is null || usage.KeyUsages != X509KeyUsageFlags.DigitalSignature)
        {
            return "the certificate's key usage must be exactly DigitalSignature";
        }

        X509EnhancedKeyUsageExtension? extended = leaf.Extensions.OfType<X509EnhancedKeyUsageExtension>().SingleOrDefault();
        if (extended is null)
        {
            return "the certificate needs both serverAuth and clientAuth";
        }

        string[] usages = [.. extended.EnhancedKeyUsages.Cast<Oid>().Select(oid => oid.Value ?? "").Order(StringComparer.Ordinal)];
        if (!usages.SequenceEqual([ServerAuthOid, ClientAuthOid]))
        {
            return "the certificate needs exactly the serverAuth and clientAuth key purposes";
        }

        if (SanFingerprint(leaf) is not { } named)
        {
            return "the certificate has no single, well-formed machine identity SAN";
        }

        DateTimeOffset notBefore = leaf.NotBefore.ToUniversalTime();
        DateTimeOffset notAfter = leaf.NotAfter.ToUniversalTime();
        if (now < notBefore - Skew)
        {
            return "the certificate is not valid yet";
        }

        if (now > notAfter + Skew)
        {
            return "the certificate has expired";
        }

        if (notAfter - notBefore > MaxTemporaryValidity)
        {
            return "the certificate is valid for longer than a temporary certificate may be";
        }

        fingerprint = named;

        return null;
    }

    /// <summary>
    /// Validates <paramref name="leaf" /> against the ONE identity certificate <paramref name="identityCertificate" /> (the custom root): the identity certificate is acceptable and valid, the leaf's structure is sound,
    /// its SAN names exactly this identity, it is issued under the identity's name and its signature verifies with the identity's public key. Null when valid, else why not. Nothing else is trusted: no store, no other root.
    /// </summary>
    public static string? ValidateLeaf(X509Certificate2 leaf, byte[] identityCertificate, DateTimeOffset now, string? expectedFingerprint = null)
    {
        if (ValidateIdentity(identityCertificate, now) is { } identityProblem)
        {
            return identityProblem;
        }

        using X509Certificate2 identity = X509CertificateLoader.LoadCertificate(identityCertificate);
        byte[] identityKey = identity.PublicKey.ExportSubjectPublicKeyInfo();
        string identityFingerprint = KeyIdentity.Fingerprint(identityKey);
        if (expectedFingerprint is not null && !string.Equals(expectedFingerprint, identityFingerprint, StringComparison.Ordinal))
        {
            return "the identity certificate is not the expected one";
        }

        if (ValidateLeafStructure(leaf, now, out string named) is { } structure)
        {
            return structure;
        }

        if (!string.Equals(named, identityFingerprint, StringComparison.Ordinal))
        {
            return "the certificate names another identity";
        }

        if (!leaf.IssuerName.RawData.AsSpan().SequenceEqual(identity.SubjectName.RawData))
        {
            return "the certificate was not issued under this identity";
        }

        if (CheckSignature(leaf, identityKey) is { } signature)
        {
            return signature;
        }

        // The leaf is no longer than its issuer: a leaf cannot outlive the identity that signed it.
        return leaf.NotAfter.ToUniversalTime() > identity.NotAfter.ToUniversalTime() ? "the certificate outlives its identity certificate" : null;
    }

    /// <summary>The identity fingerprint a leaf's SAN names (exactly one general name, a URI of this program's form, 64 upper-case hex digits), or null.</summary>
    public static string? SanFingerprint(X509Certificate2 leaf)
    {
        X509Extension? extension = leaf.Extensions.Cast<X509Extension>().SingleOrDefault(item => item.Oid?.Value == SubjectAltNameOid);
        if (extension is null || leaf.Extensions.Cast<X509Extension>().Count(item => item.Oid?.Value == SubjectAltNameOid) != 1)
        {
            return null;
        }

        try
        {
            AsnReader outer = new(extension.RawData, AsnEncodingRules.DER);
            AsnReader names = outer.ReadSequence();
            outer.ThrowIfNotEmpty();
            if (!names.HasData)
            {
                return null;
            }

            Asn1Tag uri = new(TagClass.ContextSpecific, 6);
            if (names.PeekTag() != uri)
            {
                return null;
            }

            string text = names.ReadCharacterString(UniversalTagNumber.IA5String, uri);
            if (names.HasData || !text.StartsWith(SanPrefix, StringComparison.Ordinal))
            {
                return null;
            }

            string fingerprint = text[SanPrefix.Length..];

            return fingerprint.Length == KeyIdentity.FingerprintLength && fingerprint.All(letter => letter is >= '0' and <= '9' or >= 'A' and <= 'F') ? fingerprint : null;
        }
        catch (Exception error) when (error is AsnContentException or InvalidOperationException)
        {
            return null;
        }
    }

    private static string? UnknownCritical(X509Certificate2 certificate)
    {
        string[] known = [BasicConstraintsOid, KeyUsageOid, ExtendedKeyUsageOid, SubjectAltNameOid, SubjectKeyIdentifierOid, AuthorityKeyIdentifierOid];

        return certificate.Extensions.Cast<X509Extension>().Any(item => item.Critical && !known.Contains(item.Oid?.Value)) ? "the certificate has a critical extension this program does not know" : null;
    }

    /// <summary>Verifies the certificate's own signature with <paramref name="issuerPublicKey" /> (a SubjectPublicKeyInfo): ECDSA with SHA-256 over the TBS bytes.</summary>
    private static string? CheckSignature(X509Certificate2 certificate, byte[] issuerPublicKey)
    {
        try
        {
            AsnReader reader = new(certificate.RawData, AsnEncodingRules.DER);
            AsnReader body = reader.ReadSequence();
            ReadOnlyMemory<byte> tbs = body.ReadEncodedValue();
            AsnReader algorithm = body.ReadSequence();
            if (algorithm.ReadObjectIdentifier() != EcdsaSha256Oid)
            {
                return "the certificate is not signed with ECDSA and SHA-256";
            }

            byte[] signature = body.ReadBitString(out int unused);
            if (unused != 0 || body.HasData || reader.HasData)
            {
                return "the certificate's signature is malformed";
            }

            using ECDsa key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(issuerPublicKey, out _);

            return key.VerifyData(tbs.Span, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence) ? null : "the certificate's signature does not verify";
        }
        catch (Exception error) when (error is AsnContentException or CryptographicException or InvalidOperationException or ArgumentException)
        {
            return "the certificate's signature cannot be checked";
        }
    }

    /// <summary>The DER of a temporary leaf as an <see cref="X509Certificate2" /> (public only).</summary>
    public static X509Certificate2 Load(byte[] der) => X509CertificateLoader.LoadCertificate(der);

}

/// <summary>The machine identity certificate file (<c>machine-identity.cer</c>, DER, public data) in the store folder beside <c>host.json</c>: made from the identity key on first need, kept, and renewed with the SAME key when it is no longer valid.</summary>
public static class MachineIdentityFile
{
    public const string FileName = "machine-identity.cer";

    /// <summary>A certificate is renewed when this little validity is left (renewed before it expires, not after).</summary>
    public static readonly TimeSpan RenewalWindow = TimeSpan.FromDays(30);

    /// <summary>True when the certificate has less than <see cref="RenewalWindow" /> left (or cannot be read).</summary>
    public static bool RenewalDue(byte[] certificate, DateTimeOffset now)
    {
        try
        {
            using X509Certificate2 parsed = X509CertificateLoader.LoadCertificate(certificate);

            return new DateTimeOffset(parsed.NotAfter.ToUniversalTime()) - now < RenewalWindow;
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return true;
        }
    }

    /// <summary>A new certificate for the same key (the caller tells the authority before storing it).</summary>
    public static byte[] Renewed(ISigningKey identityKey, TimeProvider clock) => MachineCertificates.CreateIdentity(identityKey, clock.GetUtcNow());

    /// <summary>Replaces the certificate file atomically.</summary>
    public static void Store(string folder, byte[] certificate)
    {
        Directory.CreateDirectory(folder);
        string path = Path.Combine(folder, FileName);
        string temp = path + "." + Guid.NewGuid().ToString("N") + ".new";
        try
        {
            File.WriteAllBytes(temp, certificate);
            File.Move(temp, path, true);
        }
        finally
        {
            if (File.Exists(temp))
            {
                File.Delete(temp);
            }
        }
    }

    public static byte[] LoadOrCreate(string folder, ISigningKey identityKey, TimeProvider clock)
    {
        string path = Path.Combine(folder, FileName);
        DateTimeOffset now = clock.GetUtcNow();
        if (File.Exists(path))
        {
            try
            {
                byte[] existing = File.ReadAllBytes(path);
                if (MachineCertificates.ValidateIdentity(existing, now, identityKey.PublicKey) is null)
                {
                    return existing;
                }
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                // Made again below.
            }
        }

        byte[] made = MachineCertificates.CreateIdentity(identityKey, now);
        Directory.CreateDirectory(folder);
        string temp = path + "." + Guid.NewGuid().ToString("N") + ".new";
        try
        {
            File.WriteAllBytes(temp, made);
            File.Move(temp, path, true);
        }
        finally
        {
            if (File.Exists(temp))
            {
                File.Delete(temp);
            }
        }

        return made;
    }
}

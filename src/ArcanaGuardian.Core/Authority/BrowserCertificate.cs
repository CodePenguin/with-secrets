using System.Formats.Asn1;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ArcanaGuardian;

public static class BrowserAddress
{
    public const string Host = "arcana-guardian.localhost";
    public static string Origin(int port) => "https://" + Host +
        (port == 443 ? "" : ":" + port.ToString(CultureInfo.InvariantCulture));
}

/// <summary>The exact, dedicated browser server certificate profile. Machine certificate validation uses its own profile.</summary>
internal static class BrowserCertificate
{
    private const string ServerAuth = "1.3.6.1.5.5.7.3.1";

    internal static X509Certificate2 Create(ECDsa key, DateTimeOffset now, Guid generation)
    {
        // NSS distinguishes trust entries by subject as well as nickname when active and pending leaves coexist.
        var subject = $"CN={BrowserAddress.Host}, SERIALNUMBER={generation:N}";
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(BrowserAddress.Host);
        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new(ServerAuth) }, true));
        DateTimeOffset start = DateTimeOffset.FromUnixTimeSeconds(now.AddMinutes(-5).ToUnixTimeSeconds());
        using var withKey = request.CreateSelfSigned(start, start.AddYears(10));
        return X509CertificateLoader.LoadCertificate(withKey.RawData);
    }

    internal static string Digest(X509Certificate2 certificate) => certificate.GetCertHashString(HashAlgorithmName.SHA256);

    internal static void Validate(X509Certificate2 certificate, DateTimeOffset now, bool checkTime = true)
    {
        if (checkTime && (certificate.NotBefore.ToUniversalTime() > now.UtcDateTime ||
            certificate.NotAfter.ToUniversalTime() <= now.UtcDateTime))
        {
            throw new CryptographicException("the browser certificate is expired or not yet valid");
        }

        using ECDsa? key = certificate.GetECDsaPublicKey();
        var constraints = certificate.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault();
        var usage = certificate.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
        var purpose = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().SingleOrDefault();
        if (certificate.Extensions.Count != 4 || constraints is not { Critical: true, CertificateAuthority: false, HasPathLengthConstraint: false } ||
            usage is not { Critical: true, KeyUsages: X509KeyUsageFlags.DigitalSignature } ||
            purpose is null || purpose.EnhancedKeyUsages.Count != 1 || purpose.EnhancedKeyUsages[0].Value != ServerAuth ||
            key?.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7" ||
            certificate.NotBefore.ToUniversalTime().AddYears(10) != certificate.NotAfter.ToUniversalTime() ||
            !certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData) ||
            !OnlyRequiredName(certificate) || !SelfSigned(certificate, key))
        {
            throw new CryptographicException("the certificate does not match the browser HTTPS leaf profile");
        }
    }

    private static bool OnlyRequiredName(X509Certificate2 certificate)
    {
        var extension = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().SingleOrDefault();
        if (extension is null)
        {
            return false;
        }

        var reader = new AsnReader(extension.RawData, AsnEncodingRules.DER);
        var names = reader.ReadSequence();
        return names.ReadCharacterString(UniversalTagNumber.IA5String, new Asn1Tag(TagClass.ContextSpecific, 2)) ==
            BrowserAddress.Host && !names.HasData && !reader.HasData;
    }

    private static bool SelfSigned(X509Certificate2 certificate, ECDsa key)
    {
        var reader = new AsnReader(certificate.RawData, AsnEncodingRules.DER);
        var fields = reader.ReadSequence();
        var body = fields.ReadEncodedValue();
        var algorithm = fields.ReadSequence();
        string oid = algorithm.ReadObjectIdentifier();
        byte[] signature = fields.ReadBitString(out int unused);
        return oid == "1.2.840.10045.4.3.2" && !algorithm.HasData && unused == 0 && !fields.HasData &&
            !reader.HasData && key.VerifyData(body.Span, signature, HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
    }
}

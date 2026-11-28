using System.Formats.Asn1;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LocalHttpsLeaf;

internal sealed class SpikeCertificates : IDisposable
{
    public const string Host = "with-secrets.localhost";
    public const int LeafPort = 18765;
    public const int ChildPort = 18766;
    public const int OtherKeyPort = 18767;
    public const int OtherSanPort = 18768;
    public const int HttpPort = 18769;
    public const int ReissuedPort = 18770;
    private const string ServerAuth = "1.3.6.1.5.5.7.3.1";
    private readonly List<X509Certificate2> owned = [];
    private readonly List<(string Name, CngProvider Provider)> windowsKeys = [];

    public SpikeCertificates()
    {
        try
        {
            DateTimeOffset start = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.AddMinutes(-5).ToUnixTimeSeconds());
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var childKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            Leaf = LoadForTls(Request(Host, Host, key).CreateSelfSigned(start, start.AddYears(10)));
            using var child = Request("localhost", "localhost", childKey).Create(
                Leaf.SubjectName, X509SignatureGenerator.CreateForECDsa(key), start, start.AddDays(1),
                RandomNumberGenerator.GetBytes(16));
            Child = LoadForTls(child.CopyWithPrivateKey(childKey));
            OtherKey = LoadForTls(Request(Host, Host, otherKey).CreateSelfSigned(start, start.AddYears(10)));
            OtherSan = LoadForTls(Request(Host, "localhost", key).CreateSelfSigned(start, start.AddYears(10)));

            Reissued = LoadForTls(Request(Host, Host, key).CreateSelfSigned(start, start.AddYears(10)));

            // Same issuer name and key, with CA extensions. Used only by an in-memory custom chain engine.
            var ca = new CertificateRequest(Leaf.SubjectName, key, HashAlgorithmName.SHA256);
            ca.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            ca.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
            using var caWithKey = ca.CreateSelfSigned(start, start.AddDays(2));
            ControlCa = X509CertificateLoader.LoadCertificate(caWithKey.RawData);
            owned.Add(ControlCa);
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    public X509Certificate2 Leaf { get; }
    public X509Certificate2 Child { get; }
    public X509Certificate2 OtherKey { get; }
    public X509Certificate2 OtherSan { get; }
    public X509Certificate2 Reissued { get; }
    private X509Certificate2 ControlCa { get; }

    public async Task VerifyAsync(CancellationToken stop)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stop);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        using var wireLeaf = await ReadPresentedAsync(LeafPort, Host, Leaf, timeout.Token);
        using var wireChild = await ReadPresentedAsync(ChildPort, "localhost", Child, timeout.Token);
        using var wireOtherKey = await ReadPresentedAsync(OtherKeyPort, Host, OtherKey, timeout.Token);
        using var wireOtherSan = await ReadPresentedAsync(OtherSanPort, "localhost", OtherSan, timeout.Token);

        using var wireReissued = await ReadPresentedAsync(ReissuedPort, Host, Reissued, timeout.Token);

        VerifyLeafProfile(wireLeaf);
        VerifyLeafProfile(wireReissued);
        Require(SameKey(wireLeaf, wireReissued) &&
            wireReissued.SubjectName.RawData.AsSpan().SequenceEqual(wireLeaf.SubjectName.RawData) &&
            wireReissued.SerialNumber != wireLeaf.SerialNumber &&
            wireReissued.NotBefore == wireLeaf.NotBefore && wireReissued.NotAfter == wireLeaf.NotAfter,
            "reissued leaf keeps the key, names and validity and has a distinct serial number");
        using var publicKey = wireLeaf.GetECDsaPublicKey()!;

        Require(San(wireChild) == "localhost" && wireChild.MatchesHostname("localhost"), "child matches localhost on the wire");
        Require(wireChild.NotBefore.ToUniversalTime() <= DateTime.UtcNow && wireChild.NotAfter.ToUniversalTime() > DateTime.UtcNow, "child dates are current");
        Require(wireChild.IssuerName.RawData.AsSpan().SequenceEqual(wireLeaf.SubjectName.RawData), "child issuer matches leaf subject");
        Require(VerifySignature(wireChild, publicKey), "child signature verifies independently using the leaf's public key");
        Require(wireOtherKey.SubjectName.RawData.AsSpan().SequenceEqual(wireLeaf.SubjectName.RawData) &&
            San(wireOtherKey) == Host && !SameKey(wireLeaf, wireOtherKey), "different-key control keeps subject and SAN");
        Require(wireOtherSan.SubjectName.RawData.AsSpan().SequenceEqual(wireLeaf.SubjectName.RawData) &&
            San(wireOtherSan) == "localhost" && SameKey(wireLeaf, wireOtherSan), "different-SAN control keeps subject and key");
        Require(SameKey(wireLeaf, ControlCa), "in-memory CA control has the exact issuer key");
        Require(BuildChain(wireChild, ControlCa), "child validates when the same issuer name and key have CA authorization");
        BuildChain(wireChild, wireLeaf);
    }

    public static void VerifyLeafProfile(X509Certificate2 leaf)
    {
        using var publicKey = leaf.GetECDsaPublicKey() ?? throw new InvalidOperationException("Leaf is not ECDSA.");
        var constraints = leaf.Extensions.OfType<X509BasicConstraintsExtension>().Single();
        var usage = leaf.Extensions.OfType<X509KeyUsageExtension>().Single();
        var eku = leaf.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single();
        Require(leaf.NotBefore.ToUniversalTime().AddYears(10) == leaf.NotAfter.ToUniversalTime(), "exactly ten calendar years");
        Require(leaf.NotBefore.ToUniversalTime() <= DateTime.UtcNow &&
            leaf.NotAfter.ToUniversalTime() > DateTime.UtcNow, "leaf dates are current");
        Require(publicKey.ExportParameters(false).Curve.Oid.Value == "1.2.840.10045.3.1.7", "ECDSA P-256");
        Require(San(leaf) == Host, "sole SAN is with-secrets.localhost");
        Require(constraints.Critical && !constraints.CertificateAuthority && !constraints.HasPathLengthConstraint, "critical CA=false");
        Require(usage.Critical && usage.KeyUsages == X509KeyUsageFlags.DigitalSignature, "critical Digital Signature only");
        Require(eku.EnhancedKeyUsages.Cast<Oid>().Single().Value == ServerAuth, "sole EKU is Server Authentication");
        Require(leaf.SubjectName.RawData.AsSpan().SequenceEqual(leaf.IssuerName.RawData) &&
            VerifySignature(leaf, publicKey), "leaf self-signature and issuer name");
        Console.WriteLine($"Leaf SHA256 {leaf.GetCertHashString(HashAlgorithmName.SHA256)}; SHA1 {leaf.Thumbprint}; UTC {leaf.NotBefore.ToUniversalTime():O} through {leaf.NotAfter.ToUniversalTime():O}");
    }

    public void Dispose()
    {
        foreach (var certificate in owned)
        {
            certificate.Dispose();
        }

        if (OperatingSystem.IsWindows())
        {
            foreach (var (name, provider) in windowsKeys)
            {
                if (CngKey.Exists(name, provider))
                {
                    using var key = CngKey.Open(name, provider);
                    key.Delete();
                }

                if (CngKey.Exists(name, provider))
                {
                    throw new InvalidOperationException("Temporary Windows TLS key remains after cleanup.");
                }
            }

            Console.WriteLine($"Cleanup verified: {windowsKeys.Count} temporary Windows TLS key containers absent.");
        }
    }

    private static CertificateRequest Request(string subject, string dnsName, ECDsa key)
    {
        var request = new CertificateRequest("CN=" + subject, key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(dnsName);
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new(ServerAuth) }, true));
        return request;
    }

    private X509Certificate2 LoadForTls(X509Certificate2 certificate)
    {
        if (OperatingSystem.IsWindows())
        {
            // Schannel needs a user-backed key. Default lifetime removes it when the certificate is released.
            using (var original = certificate)
            {
                byte[] pfx = original.Export(X509ContentType.Pfx);
                try
                {
                    certificate = X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.UserKeySet);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(pfx);
                }
            }
        }

        owned.Add(certificate);
        if (OperatingSystem.IsWindows())
        {
            using var privateKey = certificate.GetECDsaPrivateKey();
            if (privateKey is ECDsaCng cng && cng.Key.KeyName is string name && cng.Key.Provider is CngProvider provider)
            {
                windowsKeys.Add((name, provider));
            }
        }

        return certificate;
    }

    public static async Task<X509Certificate2> ReadPresentedAsync(
        int port, string host, X509Certificate2 expected, CancellationToken stop)
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, port, stop);
        X509Certificate2? presented = null;
        using var tls = new SslStream(tcp.GetStream(), false, (_, certificate, _, _) =>
        {
            presented = certificate is null ? null : X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
            return false;
        });

        try
        {
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = host }, stop);
        }
        catch (AuthenticationException) when (presented is not null)
        {
            if (presented.RawData.AsSpan().SequenceEqual(expected.RawData))
            {
                return presented;
            }

            presented.Dispose();
            throw new InvalidOperationException($"Unexpected certificate on port {port}.");
        }

        throw new InvalidOperationException($"Certificate capture failed on port {port}.");
    }

    private static string San(X509Certificate2 certificate)
    {
        var extension = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().Single();
        var reader = new AsnReader(extension.RawData, AsnEncodingRules.DER);
        var sequence = reader.ReadSequence();
        string name = sequence.ReadCharacterString(UniversalTagNumber.IA5String, new Asn1Tag(TagClass.ContextSpecific, 2));
        sequence.ThrowIfNotEmpty();
        reader.ThrowIfNotEmpty();
        return name;
    }

    private static bool VerifySignature(X509Certificate2 certificate, ECDsa issuer)
    {
        var reader = new AsnReader(certificate.RawData, AsnEncodingRules.DER);
        var sequence = reader.ReadSequence();
        var body = sequence.ReadEncodedValue();
        var algorithm = sequence.ReadSequence();
        string oid = algorithm.ReadObjectIdentifier();
        algorithm.ThrowIfNotEmpty();
        var signature = sequence.ReadBitString(out int unusedBits);
        sequence.ThrowIfNotEmpty();
        reader.ThrowIfNotEmpty();
        return oid == "1.2.840.10045.4.3.2" && unusedBits == 0 &&
            issuer.VerifyData(body.Span, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
    }

    private static bool SameKey(X509Certificate2 a, X509Certificate2 b) =>
        a.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(b.PublicKey.ExportSubjectPublicKeyInfo());

    private static bool BuildChain(X509Certificate2 child, X509Certificate2 anchor)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(anchor);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(ServerAuth));
        bool valid = chain.Build(child);
        Console.WriteLine($"Custom chain {anchor.Thumbprint}: {valid}; {string.Join(", ", chain.ChainStatus.Select(status => status.Status))}");
        return valid;
    }

    private static void Require(bool condition, string description)
    {
        if (!condition)
        {
            throw new InvalidOperationException("Diagnostic failed: " + description);
        }

        Console.WriteLine("PASS diagnostic: " + description);
    }
}

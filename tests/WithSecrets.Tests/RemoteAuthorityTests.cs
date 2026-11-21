using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WithSecrets.Tests;

/// <summary>
/// Task M1: the machine transport. Direct HTTPS with mutual TLS 1.3 and HTTP/2 between a host service and the authority, replacing the relay, the custom handshake and the application-level encryption. The suite checks the
/// certificate profiles (identity and temporary), rotation, the custom-root validation in both directions, the downgrade and fallback refusals, mutual TLS on every route, the transport policy (no caching, no compression, JSON only,
/// bounded, safe errors), revocation that closes live connections, idempotent retries, the long poll and the client's refusal of redirects, proxies and unreadable answers. Real Kestrel, real TLS, real clients.
/// </summary>
internal static partial class RemoteAuthorityTests
{
    private static readonly TimeSpan Fast = TimeSpan.FromMilliseconds(100);

    // ---------- fixtures ----------

    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset _now;

        public TestClock(TimeSpan? offset = null)
        {
            _now = DateTimeOffset.UtcNow + (offset ?? TimeSpan.Zero);
        }

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }

    /// <summary>A signing key whose ECDsa the test holds, so it can forge certificates around it.</summary>
    private sealed class EcKey : ISigningKey
    {
        public ECDsa Key { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public byte[] PublicKey => Key.ExportSubjectPublicKeyInfo();

        public byte[] Sign(byte[] data) => Key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        public void Dispose() => Key.Dispose();
    }

    private sealed record Spec
    {
        public required X500DistinguishedName Issuer { get; init; }

        public required ECDsa Signer { get; init; }

        public required string Fingerprint { get; init; }

        public string[] Usages { get; init; } = [MachineCertificates.ServerAuthOid, MachineCertificates.ClientAuthOid];

        public bool Ca { get; init; }

        public X509KeyUsageFlags KeyUsage { get; init; } = X509KeyUsageFlags.DigitalSignature;

        public string[]? San { get; init; }

        public TimeSpan Start { get; init; } = TimeSpan.FromMinutes(-1);

        public TimeSpan Length { get; init; } = TimeSpan.FromHours(24);
    }

    /// <summary>A forged (or, with the defaults, a correct) leaf with a usable private key: for handshakes and for the validator.</summary>
    private sealed class Forged : IDisposable
    {
        private readonly TlsKey _key = new();

        public Forged(Spec spec, DateTimeOffset now)
        {
            CertificateRequest request = new(new X500DistinguishedName("CN=forged"), _key.Key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(spec.Ca, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(spec.KeyUsage, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([.. spec.Usages.Select(value => new Oid(value))], false));
            SubjectAlternativeNameBuilder names = new();
            foreach (string san in spec.San ?? [MachineCertificates.SanUri(spec.Fingerprint)])
            {
                names.AddUri(new Uri(san));
            }

            request.CertificateExtensions.Add(names.Build(true));
            DateTimeOffset start = now + spec.Start;
            using X509Certificate2 bare = request.Create(spec.Issuer, X509SignatureGenerator.CreateForECDsa(spec.Signer), start, start + spec.Length, RandomNumberGenerator.GetBytes(16));
            Certificate = bare.CopyWithPrivateKey(_key.Key);
        }

        public X509Certificate2 Certificate { get; }

        public void Dispose()
        {
            Certificate.Dispose();
            _key.Dispose();
        }
    }

    private sealed class Peer : IDisposable
    {
        public required TestMachine Machine { get; init; }

        public required RemoteAuthority Remote { get; init; }

        public string Fingerprint => Machine.Fingerprint;

        public TemporaryCertificate Tls => Machine.Deployment.Tls;

        public void Dispose()
        {
            Remote.Dispose();
            Machine.Deployment.Dispose();
        }
    }

    private sealed class Net : IDisposable
    {
        private readonly List<Peer> _peers = [];
        private readonly string _root;

        private Net(string root)
        {
            _root = root;
        }

        public TestMachine Authority { get; private set; } = null!;

        public MachineListener Listener { get; set; } = null!;

        public TestClock? Clock { get; private set; }

        public IRemoteLaunchHandler? Launches { get; private set; }

        public string Url => "https://127.0.0.1:" + Listener.Port;

        public byte[] Identity => Authority.Deployment.IdentityCertificate;

        public RemoteAuthorityConfig Config => new(Url, MachineCertificates.FingerprintOf(Identity)!, Identity);

        public static Net Start(string root, MachineListenerOptions? options = null, IRemoteLaunchHandler? launches = null, TestClock? clock = null)
        {
            Net net = new(root) { Clock = clock, Launches = launches };
            net.Authority = new TestMachine(Path.Combine(root, "auth-" + Guid.NewGuid().ToString("N")[..6]), trusted: true, hostName: "the-authority", clock: clock);
            LocalDeployment deployment = net.Authority.Deployment;
            net.Listener = MachineListener.Start(deployment.Authority, deployment.Keys, deployment.Store, deployment.Tls, options ?? new MachineListenerOptions { Port = 0, Clock = clock ?? TimeProvider.System }, launches);

            return net;
        }

        /// <summary>Restarts the listener on the same port over the same store (the authority service restarts).</summary>
        public void RestartListener()
        {
            int port = Listener.Port;
            Listener.Dispose();
            LocalDeployment deployment = Authority.Deployment;
            Listener = MachineListener.Start(deployment.Authority, deployment.Keys, deployment.Store, deployment.Tls, new MachineListenerOptions { Port = port, CloseGrace = TimeSpan.FromMilliseconds(300) }, Launches);
        }

        /// <summary>A host machine of its own, known to this authority (registered with its identity certificate; pairing is task M2) and approved unless told not to.</summary>
        public Peer Host(string name, bool approve = true, bool register = true)
        {
            TestMachine machine = new(Path.Combine(_root, "host-" + Guid.NewGuid().ToString("N")[..6]), trusted: false, hostName: name, clock: Clock);
            machine.Deployment.HostConfig.SetRemote(machine.Fingerprint, Config);
            if (register)
            {
                Authority.Deployment.Store.Register(machine.MachineKey.PublicKey, name, "test pairing", machine.Deployment.IdentityCertificate);
                if (approve)
                {
                    Authority.Deployment.Store.Approve(machine.Fingerprint, name, "test admin");
                }
            }

            RemoteAuthority remote = new(Config, machine.Deployment.Tls, machine.Deployment.HostConfig, Clock) { RetryPause = Fast, Retries = 3, DrainTimeout = TimeSpan.FromSeconds(2) };
            Peer peer = new() { Machine = machine, Remote = remote };
            _peers.Add(peer);

            return peer;
        }

        public void Dispose()
        {
            foreach (Peer peer in _peers)
            {
                peer.Dispose();
            }

            Listener.Dispose();
            Authority.Deployment.Dispose();
        }
    }

    /// <summary>A bare HTTP client for the machine API with a client certificate and protocol settings the real client never uses, so the tests can send what it never would.</summary>
    private sealed class Raw : IDisposable
    {
        private readonly HttpClient _client;
        private readonly SocketsHttpHandler _handler;
        private readonly Version _version;

        public Raw(string url, byte[] authorityIdentity, X509Certificate2? client, SslProtocols protocols = SslProtocols.Tls13, bool http2 = true, TimeProvider? clock = null)
        {
            Url = url;
            _version = http2 ? HttpVersion.Version20 : HttpVersion.Version11;
            _handler = new SocketsHttpHandler
            {
                UseProxy = false,
                AllowAutoRedirect = false,
                AutomaticDecompression = DecompressionMethods.None,
                SslOptions = new SslClientAuthenticationOptions
                {
                    EnabledSslProtocols = protocols,
                    ClientCertificates = client is null ? null : [client],
                    ApplicationProtocols = http2 ? [SslApplicationProtocol.Http2] : [SslApplicationProtocol.Http11],
                    RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                    {
                        if (certificate is null)
                        {
                            return false;
                        }

                        Seen.Add(certificate.GetCertHashString());
                        using X509Certificate2 leaf = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());

                        return MachineCertificates.ValidateLeaf(leaf, authorityIdentity, (clock ?? TimeProvider.System).GetUtcNow()) is null;
                    },
                },
            };
            _client = new HttpClient(_handler) { Timeout = TimeSpan.FromSeconds(20), DefaultRequestVersion = http2 ? HttpVersion.Version20 : HttpVersion.Version11, DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact };
        }

        public string Url { get; }

        /// <summary>The thumbprints of the server certificates this client was shown, one per handshake.</summary>
        public List<string> Seen { get; } = [];

        public async Task<(int Status, HttpResponseMessage Response, string Body)> Send(HttpMethod method, string path, string? body, string? contentType = "application/json", Action<HttpRequestMessage>? tweak = null)
        {
            using HttpRequestMessage request = new(method, Url + path) { Version = _version, VersionPolicy = HttpVersionPolicy.RequestVersionExact };
            if (body is not null)
            {
                request.Content = new StringContent(body, Encoding.UTF8);
                request.Content.Headers.ContentType = contentType is null ? null : MediaTypeHeaderValue.Parse(contentType);
            }

            tweak?.Invoke(request);
            HttpResponseMessage response = await _client.SendAsync(request);
            string text = await response.Content.ReadAsStringAsync();

            return ((int)response.StatusCode, response, text);
        }

        public async Task<(int Status, WireMessage? Message, string Body, HttpResponseMessage Response)> Call(string op, string id, string body)
        {
            (int status, HttpResponseMessage response, string text) = await Send(HttpMethod.Post, MachineApi.OpPath(op), RemoteWire.Request(id, op, body));
            RemoteWire.TryReadMessage(Encoding.UTF8.GetBytes(text), out WireMessage? message);

            return (status, message, text, response);
        }

        public void Dispose()
        {
            _client.Dispose();
            _handler.Dispose();
        }
    }

    /// <summary>A server that answers as a hostile or broken authority would: the client under test is configured with this server's own genuine identity, so only what the server SAYS is wrong.</summary>
    private sealed class Hostile : IDisposable
    {
        private readonly TestMachine _machine;
        private readonly WebApplication _app;
        private int _hits;

        public Hostile(string root, Func<HttpContext, Task> answer)
        {
            _machine = new TestMachine(Path.Combine(root, "hostile-" + Guid.NewGuid().ToString("N")[..6]), trusted: true, hostName: "hostile");
            WebApplicationBuilder builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [], ContentRootPath = AppContext.BaseDirectory, EnvironmentName = Environments.Production });
            builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(IPAddress.Loopback, 0, listen =>
            {
                listen.Protocols = HttpProtocols.Http2;
                listen.UseHttps(new HttpsConnectionAdapterOptions
                {
                    SslProtocols = SslProtocols.Tls13,
                    ClientCertificateMode = ClientCertificateMode.AllowCertificate,
                    ClientCertificateValidation = (_, _, _) => true,
                    ServerCertificateSelector = (_, _) => _machine.Deployment.Tls.Current,
                });
            }));
            _app = builder.Build();
            _app.Run(async context =>
            {
                Interlocked.Increment(ref _hits);
                await answer(context);
            });
            _app.StartAsync().GetAwaiter().GetResult();
            Url = _app.Urls.First().Replace("http://", "https://", StringComparison.Ordinal);
        }

        public string Url { get; }

        public int Hits => Volatile.Read(ref _hits);

        public byte[] Identity => _machine.Deployment.IdentityCertificate;

        public RemoteAuthorityConfig Config => new(Url, MachineCertificates.FingerprintOf(Identity)!, Identity);

        public void Dispose()
        {
            _app.StopAsync().GetAwaiter().GetResult();
            _app.DisposeAsync().AsTask().GetAwaiter().GetResult();
            _machine.Deployment.Dispose();
        }
    }

    private static LaunchRequest Request(string id)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;

        return new LaunchRequest(LaunchProtocol.Version, id, now, now.AddMinutes(5), "bm9uY2UtMDAwMDAwMDE" + Guid.NewGuid().ToString("N")[..6], ["TOKEN"], [new LaunchMapping("TOKEN", "TOKEN")], "remote test", "/work/tool.sh", [], "/work", [], [], new Dictionary<string, string>(), new Dictionary<string, string>(), []);
    }

    private static async Task<bool> Until(Func<bool> condition, int seconds = 10)
    {
        DateTime end = DateTime.UtcNow.AddSeconds(seconds);
        while (DateTime.UtcNow < end)
        {
            if (condition())
            {
                return true;
            }

            await Task.Delay(30);
        }

        return condition();
    }

    private static async Task<T?> Thrown<T>(Func<Task> action) where T : Exception
    {
        try
        {
            await action();
        }
        catch (T error)
        {
            return error;
        }

        return null;
    }

    private static byte[] AuthorityKey(Net net) => net.Authority.Deployment.Keys.CurrentRecord().PublicKey;

    private static string Other => new('C', 64);

    // ---------- the suite ----------

    public static async Task Run(Action<bool, string> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "ws-transport-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);
        try
        {
            IdentityCertificates(check);
            TemporaryCertificates(check);
            // The failure text names the chain of types and the platform's own TLS text, and nothing a program put in another exception's message.
            string described = TransportFailure.Describe(new HttpRequestException(HttpRequestError.SecureConnectionError, "token=SECRET-VALUE", new System.Security.Authentication.AuthenticationException("Authentication failed", new PlatformNotSupportedException("The requested security protocol is not supported."))));
            check(described.Contains("HttpRequestException [SecureConnectionError]", StringComparison.Ordinal) && described.Contains("AuthenticationException", StringComparison.Ordinal) && described.Contains("PlatformNotSupportedException", StringComparison.Ordinal)
                && described.Contains("security protocol is not supported", StringComparison.Ordinal) && !described.Contains("SECRET-VALUE", StringComparison.Ordinal), "transport failure: the text names the exception chain and the platform's TLS message, never another exception's message (" + described + ")");

            if (PlatformSkip.NoServerTls13("remote transport (rotation, operations, downgrades, revocation, long poll)"))
            {
                return;
            }

            await Rotation(check, root);
            await Operations(check, root);
            await CustomRoot(check, root);
            await Downgrades(check, root);
            await EveryRoute(check, root);
            await Policy(check, root);
            await Bounds(check, root);
            await Revocation(check, root);
            await Idempotence(check, root);
            await Recovery(check, root);
            await LongPoll(check, root);
            await FixRound1(check, root);
            await HostileAuthority(check, root);
        }
        finally
        {
            try
            {
                Directory.Delete(root, true);
            }
            catch (IOException)
            {
                // A stray temp file is harmless.
            }
        }
    }

    // ---------- certificates ----------

    private static void IdentityCertificates(Action<bool, string> check)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using EcKey key = new();
        byte[] der = MachineCertificates.CreateIdentity(key, now);
        using X509Certificate2 identity = X509CertificateLoader.LoadCertificate(der);
        X509BasicConstraintsExtension constraints = identity.Extensions.OfType<X509BasicConstraintsExtension>().Single();
        X509KeyUsageExtension usage = identity.Extensions.OfType<X509KeyUsageExtension>().Single();
        check(MachineCertificates.ValidateIdentity(der, now, key.PublicKey) is null && identity.Version == 3 && identity.PublicKey.Oid.Value == "1.2.840.10045.2.1" && identity.SignatureAlgorithm.Value == "1.2.840.10045.4.3.2", "identity certificate: self-signed X.509 v3, ECDSA P-256 key, ECDSA with SHA-256, valid for the machine's own key");
        check(constraints.Critical && constraints.CertificateAuthority && constraints.HasPathLengthConstraint && constraints.PathLengthConstraint == 0 && usage.Critical && usage.KeyUsages == (X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign)
            && !identity.Extensions.OfType<X509EnhancedKeyUsageExtension>().Any(), "identity certificate: the architecture 10.2 profile: CA with path length 0 (a trust anchor for its own temporary leaves), critical key usage DigitalSignature and KeyCertSign, no extended key usage");
        TimeSpan lifetime = identity.NotAfter.ToUniversalTime() - identity.NotBefore.ToUniversalTime();
        check(lifetime >= TimeSpan.FromDays(3650) && lifetime <= MachineCertificates.MaxIdentityValidity && MachineCertificates.FingerprintOf(der) == KeyIdentity.Fingerprint(key.PublicKey), "identity certificate: valid ten years, and its fingerprint is the machine identity fingerprint of its key");

        byte[] tampered = (byte[])der.Clone();
        tampered[^1] ^= 0x01;
        byte[] renamed = (byte[])der.Clone();
        int at = renamed.AsSpan().IndexOf("with-secrets machine"u8);
        renamed[at] ^= 0x20;
        check(MachineCertificates.ValidateIdentity(tampered, now) is not null && MachineCertificates.ValidateIdentity(renamed, now) is not null && MachineCertificates.ValidateIdentity([.. der, 0], now) is not null, "identity certificate: a changed signature, a changed name and trailing bytes are each refused");

        using RSA rsa = RSA.Create(2048);
        CertificateRequest rsaRequest = new("CN=with-secrets machine rsa", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rsaRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        rsaRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign, true));
        using X509Certificate2 rsaCertificate = rsaRequest.CreateSelfSigned(now.AddDays(-1), now.AddDays(300));
        check(MachineCertificates.ValidateIdentity(rsaCertificate.RawData, now) is { } rsaProblem && rsaProblem.Contains("P-256", StringComparison.Ordinal), "identity certificate: an RSA key is refused (ECDSA P-256 only)");

        using ECDsa other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 Self(Action<CertificateRequest> shape, DateTimeOffset notBefore, DateTimeOffset notAfter)
        {
            CertificateRequest request = new("CN=with-secrets machine other", other, HashAlgorithmName.SHA256);
            shape(request);

            return request.CreateSelfSigned(notBefore, notAfter);
        }

        void CaWith(CertificateRequest request, bool ca, X509KeyUsageFlags flags)
        {
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(ca, ca, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(flags, true));
        }

        X509KeyUsageFlags both = X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign;
        using X509Certificate2 positive = Self(request => CaWith(request, true, both), now.AddDays(-1), now.AddDays(300));
        using X509Certificate2 notCa = Self(request => CaWith(request, false, both), now.AddDays(-1), now.AddDays(300));
        using X509Certificate2 wrongUsage = Self(request => CaWith(request, true, X509KeyUsageFlags.DigitalSignature), now.AddDays(-1), now.AddDays(300));
        using X509Certificate2 withEku = Self(request =>
        {
            CaWith(request, true, both);
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(MachineCertificates.ClientAuthOid)], false));
        }, now.AddDays(-1), now.AddDays(300));
        using X509Certificate2 tooLong = Self(request => CaWith(request, true, both), now.AddDays(-1), now.AddDays(4000));
        check(MachineCertificates.ValidateIdentity(positive.RawData, now) is null, "identity certificate: the harness's own correctly shaped certificate validates (so the refusals below are about the one thing changed)");
        check(MachineCertificates.ValidateIdentity(notCa.RawData, now) is not null && MachineCertificates.ValidateIdentity(wrongUsage.RawData, now) is not null && MachineCertificates.ValidateIdentity(withEku.RawData, now) is not null && MachineCertificates.ValidateIdentity(tooLong.RawData, now) is not null,
            "identity certificate: CA=false, key usage other than DigitalSignature and KeyCertSign, an extended key usage, and a validity beyond ten years are each refused");
        check(MachineCertificates.ValidateIdentity(der, now.AddYears(11)) is { } expired && expired.Contains("expired", StringComparison.Ordinal) && MachineCertificates.ValidateIdentity(der, now.AddYears(-1)) is { } early && early.Contains("not valid yet", StringComparison.Ordinal), "identity certificate: expired and not yet valid are refused");
        using SoftwareSigningKey someoneElse = new();
        check(MachineCertificates.ValidateIdentity(der, now, someoneElse.PublicKey) is not null, "identity certificate: a certificate for another key than the one expected is refused");
    }

    private static void TemporaryCertificates(Action<bool, string> check)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using EcKey identityKey = new();
        string fingerprint = KeyIdentity.Fingerprint(identityKey.PublicKey);
        byte[] identityDer = MachineCertificates.CreateIdentity(identityKey, now);
        using X509Certificate2 identity = X509CertificateLoader.LoadCertificate(identityDer);
        TestClock clock = new();
        using TemporaryCertificate temporary = new(identityKey, identityDer, clock);
        X509Certificate2 leaf = temporary.Current;
        check(MachineCertificates.ValidateLeaf(leaf, identityDer, clock.GetUtcNow(), fingerprint) is null && leaf.HasPrivateKey, "temporary certificate: the generated leaf validates against the identity certificate it was signed under");
        X509EnhancedKeyUsageExtension eku = leaf.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single();
        X509BasicConstraintsExtension constraints = leaf.Extensions.OfType<X509BasicConstraintsExtension>().Single();
        check(!constraints.CertificateAuthority && leaf.Extensions.OfType<X509KeyUsageExtension>().Single().KeyUsages == X509KeyUsageFlags.DigitalSignature, "temporary certificate: not a CA, DigitalSignature only");
        check(eku.EnhancedKeyUsages.Cast<Oid>().Select(item => item.Value).Order(StringComparer.Ordinal).SequenceEqual([MachineCertificates.ServerAuthOid, MachineCertificates.ClientAuthOid]), "temporary certificate: serverAuth and clientAuth");
        check(MachineCertificates.SanFingerprint(leaf) == fingerprint, "temporary certificate: SAN urn:with-secrets:machine:<fingerprint>");
        check(leaf.RawData.AsSpan().SequenceEqual(temporary.CurrentPublic) && !leaf.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(identityKey.PublicKey), "temporary certificate: the TLS key is its own key, not the identity key");
        TimeSpan until = temporary.NextRotation - clock.GetUtcNow();
        check(leaf.NotAfter.ToUniversalTime() - leaf.NotBefore.ToUniversalTime() <= MachineCertificates.MaxTemporaryValidity && until > TimeSpan.FromHours(20) && until < TimeSpan.FromHours(24), "temporary certificate: valid for 24 hours, replaced about an hour before it expires");

        // The profile checks, each with one thing wrong in an otherwise correct leaf (the correct one must pass first).
        Spec Good() => new() { Issuer = identity.SubjectName, Signer = identityKey.Key, Fingerprint = fingerprint };
        bool Refuses(Spec spec, string word, DateTimeOffset? at = null)
        {
            using Forged forged = new(spec, now);

            return MachineCertificates.ValidateLeaf(forged.Certificate, identityDer, at ?? now, fingerprint) is { } problem && problem.Contains(word, StringComparison.OrdinalIgnoreCase);
        }

        using (Forged control = new(Good(), now))
        {
            check(MachineCertificates.ValidateLeaf(control.Certificate, identityDer, now, fingerprint) is null, "temporary certificate: the forging harness's correct leaf validates");
        }

        check(Refuses(Good() with { Ca = true }, "CA") && Refuses(Good() with { KeyUsage = X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign }, "key usage"), "temporary certificate: a leaf that is a CA, or may sign certificates, is refused");
        check(Refuses(Good() with { Usages = [MachineCertificates.ServerAuthOid] }, "exactly") && Refuses(Good() with { Usages = [MachineCertificates.ClientAuthOid] }, "exactly") && Refuses(Good() with { Usages = [MachineCertificates.ServerAuthOid, MachineCertificates.ClientAuthOid, "1.3.6.1.5.5.7.3.3"] }, "exactly"), "temporary certificate: wrong or missing extended key usage is refused (serverAuth AND clientAuth, nothing more)");
        check(Refuses(Good() with { Start = TimeSpan.FromDays(-3), Length = TimeSpan.FromDays(1) }, "expired") && Refuses(Good(), "not valid yet", now.AddHours(-2)), "temporary certificate: an expired leaf and a not-yet-valid leaf are refused");
        check(Refuses(Good() with { Length = TimeSpan.FromDays(30) }, "longer") && Refuses(Good() with { San = [MachineCertificates.SanUri(fingerprint), MachineCertificates.SanUri(new string('B', 64))] }, "SAN") && Refuses(Good() with { San = ["https://example.org/x"] }, "SAN") && Refuses(Good() with { Fingerprint = new string('B', 64) }, "another identity"), "temporary certificate: a long-lived leaf, two names, a name that is not a machine URI and a name for another machine are refused");
        using EcKey attacker = new();
        check(Refuses(Good() with { Signer = attacker.Key }, "signature") && Refuses(Good() with { Issuer = new X500DistinguishedName("CN=somebody else") }, "issued"), "temporary certificate: a leaf signed by another key, or issued under another name, is refused");
        using ECDsa p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        CertificateRequest p384Request = new(new X500DistinguishedName("CN=wrong key type"), p384, HashAlgorithmName.SHA256);
        p384Request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        using X509Certificate2 p384Leaf = p384Request.Create(identity.SubjectName, X509SignatureGenerator.CreateForECDsa(identityKey.Key), now.AddMinutes(-1), now.AddHours(24), RandomNumberGenerator.GetBytes(16));
        check(MachineCertificates.ValidateLeaf(p384Leaf, identityDer, now, fingerprint) is { } curve && curve.Contains("P-256", StringComparison.Ordinal), "temporary certificate: a key that is not ECDSA P-256 is refused");
    }

    private static async Task Rotation(Action<bool, string> check, string root)
    {
        // Starts 23.5 hours ago so that, after the clock has moved on to the rotation, the new certificates are valid by the real clock too (the operating system looks at certificate dates as well).
        TestClock clock = new(TimeSpan.FromHours(-23.5));
        using Net net = Net.Start(root, clock: clock);
        Peer host = net.Host("rotating");
        ReconcileResponse answer = await host.Remote.ReconcileAsync(ReconcileEnvelope.Create("rc-rot-1", "rotating", clock.GetUtcNow(), host.Machine.MachineKey));
        string serverBefore = net.Authority.Deployment.Tls.Current.Thumbprint;
        string clientBefore = host.Tls.Current.Thumbprint;
        int connections = host.Remote.Connections;
        int pools = host.Remote.Pools;
        check(answer.Status == "Trusted" && connections == 1 && pools == 1 && net.Authority.Deployment.Tls.Rotations == 0, "rotation: a first request makes one connection");

        // Time passes but less than the rotation point: nothing changes, the healthy connection is kept.
        clock.Advance(TimeSpan.FromHours(20));
        await host.Remote.ReconcileAsync(ReconcileEnvelope.Create("rc-rot-2", "rotating", clock.GetUtcNow(), host.Machine.MachineKey));
        check(host.Remote.Connections == connections && host.Remote.Pools == pools && host.Tls.Current.Thumbprint == clientBefore && net.Authority.Deployment.Tls.Current.Thumbprint == serverBefore, "rotation: 20 hours in, no certificate has changed and the one connection is still the same");

        // Past the rotation point (an hour before expiry): the connection that is open is not interrupted, a new connection gets the new certificate.
        clock.Advance(TimeSpan.FromHours(3));
        string serverAfter = net.Authority.Deployment.Tls.Current.Thumbprint;
        check(serverAfter != serverBefore && net.Authority.Deployment.Tls.Rotations == 1, "rotation: the authority replaces its temporary certificate before it expires");
        using Raw fresh = new(net.Url, net.Identity, host.Tls.Current, clock: clock);
        (int status, _, _) = await fresh.Send(HttpMethod.Post, MachineApi.OpPath(RemoteOps.KeyTransitions), RemoteWire.Request("kt-rot", RemoteOps.KeyTransitions, RemoteWire.WriteAfter(Other)));
        check(status == 200 && fresh.Seen.Count == 1 && fresh.Seen[0] != serverBefore && host.Tls.Rotations == 1, "rotation: a new connection (with the host's new certificate) is shown the authority's new certificate and validates it (status " + status + ")");

        // The host's next request uses a new pool with the new certificate; the old pool drains.
        ReconcileResponse after = await host.Remote.ReconcileAsync(ReconcileEnvelope.Create("rc-rot-3", "rotating", clock.GetUtcNow(), host.Machine.MachineKey));
        check(after.Status == "Trusted" && host.Tls.Current.Thumbprint != clientBefore && host.Remote.Pools == pools + 1 && host.Remote.Connections == connections + 1, "rotation: the host's certificate was replaced and its next request used a new pool and connection (pools " + host.Remote.Pools + ", connections " + host.Remote.Connections + ")");
        ReconcileResponse again = await host.Remote.ReconcileAsync(ReconcileEnvelope.Create("rc-rot-4", "rotating", clock.GetUtcNow(), host.Machine.MachineKey));
        check(again.Status == "Trusted" && host.Remote.Connections == connections + 1, "rotation: after the rotation the new connection is simply reused");
    }

    // ---------- operations over HTTPS ----------

    private static async Task Operations(Action<bool, string> check, string root)
    {
        using Net net = Net.Start(root);
        Peer host = net.Host("ops-host");
        TestMachine machine = host.Machine;
        RemoteAuthority remote = host.Remote;

        ReconcileResponse answer = await remote.ReconcileAsync(ReconcileEnvelope.Create("rc-1", machine.HostName, DateTimeOffset.UtcNow, machine.MachineKey));
        check(answer.Verify(AuthorityKey(net)) && answer.Status == "Trusted" && answer.HostNameBound && answer.RequestId == "rc-1", "remote: a check-in over mutual TLS returns the authority's signed answer (verifies under the authority key)");

        LaunchRequest request = Request("req-decide-1");
        int presented = 0;
        using IDisposable offer = net.Authority.Deployment.Authority.Offer(request.RequestId, request.Digest(), () => { Interlocked.Increment(ref presented); return ApprovalDecision.Allow(); });
        MachineRequestEnvelope envelope = MachineRequestEnvelope.Create(request, machine.HostName, machine.MachineKey);
        AuthorityResponse decided = await remote.DecideAsync(envelope);
        check(decided.Decision == AuthorityDecision.Approved && decided.Verify(AuthorityKey(net)) && decided.RequestDigest == request.Digest() && presented == 1, "remote: a decision is the local authority's own signed, request-bound answer (the signed contracts are unchanged)");
        check(net.Authority.Deployment.Store.GetProcessed(request.RequestId) is not null, "remote: the same persistence is used (the decision is in authority.db processed_requests)");

        GrantResponse grant = await remote.GrantAsync(GrantEnvelope.Create(GrantOps.Use, Request("req-grant-1"), new string('A', 64), machine.HostName, machine.MachineKey));
        check(grant.Verify(AuthorityKey(net)) && grant.Outcome == GrantOps.None, "remote: a grant query returns the authority's signed answer");
        check((await remote.KeyTransitionsAsync(Other)).Count == 0 && (await remote.PendingInvalidationsAsync(machine.Fingerprint)).Count == 0 && (await remote.PendingGrantEventsAsync(machine.Fingerprint)).Count == 0, "remote: reads (transitions, pending lists) work");

        HostAuditOutbox outbox = HostAuditOutbox.InFolder(Path.Combine(root, "outbox-" + Guid.NewGuid().ToString("N")[..6]), machine.MachineKey);
        outbox.Append(new AuditFacts(AuditEventTypes.Authorization, "approved", "approved", "req-audit", "/work", "/work/tool.sh", ["a"]));
        AuditBatch batch = new("batch-1", machine.Fingerprint, outbox.Pending(10));
        AuditAck ack = await remote.UploadAsync(batch);
        AuditAck again = await remote.UploadAsync(batch with { BatchId = "batch-2" });
        check(ack.Verify(AuthorityKey(net)) && ack.Entries.Count == 1 && ack.Entries[0].Status == AuditStatus.Accepted && ack.RequestDigest == batch.Digest() && again.Entries[0].Status == AuditStatus.Duplicate, "remote: a machine-signed audit batch is acknowledged by the authority's signed, batch-bound ack, and the same events again are a duplicate");
        check(net.Authority.Deployment.Store.AuditHistory(new AuditQuery(Limit: 10)).Any(item => item.Event.ToJson().Contains("req-audit", StringComparison.Ordinal)), "remote: the machine-signed audit event is stored at the authority");

        check(await remote.EnsureAuthorityKeyPinnedAsync(CancellationToken.None) && machine.Deployment.HostConfig.Load().Config?.Authority?.Fingerprint == KeyIdentity.Fingerprint(AuthorityKey(net)), "remote: a Trusted host with no authority key pinned learns it over the identity-pinned connection and pins it in host.json");

        // The machine-signed envelopes still carry the signatures the authority verifies; a changed field breaks them.
        check(RemoteWire.TryRead(RemoteWire.Write(envelope), out MachineRequestEnvelope? roundTrip) && roundTrip!.Verify(machine.MachineKey.PublicKey) && roundTrip.Request.Digest() == request.Digest(), "wire: a machine envelope round-trips through its canonical JSON and still verifies");
        check(!RemoteWire.TryRead(RemoteWire.Write(envelope).Replace("\"hostName\":\"" + machine.HostName + "\"", "\"hostName\":\"x\"", StringComparison.Ordinal), out MachineRequestEnvelope? changed) || !changed!.Verify(machine.MachineKey.PublicKey), "wire: a changed field breaks the machine's signature");
        check(!RemoteWire.TryRead(RemoteWire.Write(envelope).Replace("}", ",\"extra\":1}", StringComparison.Ordinal), out MachineRequestEnvelope? _) && !RemoteWire.TryReadMessage(Encoding.UTF8.GetBytes("{\"v\":2,\"id\":\"a\",\"op\":\"x\",\"body\":{}}"), out _), "wire: an unknown member and another message version are refused");

        // The old application-level layer is gone: no session, handshake or signature wraps an ordinary request.
        using Raw raw = new(net.Url, net.Identity, host.Tls.Current);
        (int status, WireMessage? message, string text, _) = await raw.Call(RemoteOps.KeyTransitions, "kt-1", RemoteWire.WriteAfter(Other));
        check(status == 200 && message is { Ok: true } && !text.Contains("signature", StringComparison.OrdinalIgnoreCase) && text.StartsWith("{\"v\":1,", StringComparison.Ordinal), "wire: an ordinary request is plain JSON over TLS: no per-message envelope signature or encryption around it");
    }

    // ---------- the custom root, inbound and outbound ----------

    private static async Task CustomRoot(Action<bool, string> check, string root)
    {
        using Net net = Net.Start(root);
        Peer host = net.Host("root-host");
        await host.Remote.KeyTransitionsAsync(Other);
        check(host.Remote.Connections == 1, "custom root: the host connected to the authority at 127.0.0.1 although the operating system trusts neither certificate (validation is against the one configured identity)");

        // Hostname mismatch: the address is routing only. The same authority reached under another name still validates, because the identity is the certificate's.
        using RemoteAuthority named = new(new RemoteAuthorityConfig("https://localhost:" + net.Listener.Port, net.Config.AuthorityIdentityFingerprint, net.Identity), host.Tls, host.Machine.Deployment.HostConfig) { RetryPause = Fast, Retries = 3 };
        check((await named.KeyTransitionsAsync(Other)).Count == 0, "custom root: reaching the authority under another host name (localhost) works: the name is not the identity");

        // Outbound: another authority's identity configured, the real authority answering: refused.
        using Net impostorSide = Net.Start(root);
        using RemoteAuthority wrongIdentity = new(new RemoteAuthorityConfig(net.Url, impostorSide.Config.AuthorityIdentityFingerprint, impostorSide.Identity), host.Tls, host.Machine.Deployment.HostConfig) { RetryPause = Fast, Retries = 0 };
        int requests = net.Listener.Requests;
        RemoteTransportException? wrong = await Thrown<RemoteTransportException>(() => wrongIdentity.KeyTransitionsAsync(Other));
        check(wrong is not null && net.Listener.Requests == requests, "custom root: an authority that presents a certificate of another identity than the configured one is refused before any request is sent");

        // A substituted authority: a server with a perfectly valid certificate of its own identity in the real authority's place.
        using Hostile stand = new(root, context => context.Response.WriteAsync("{}"));
        using RemoteAuthority substituted = new(new RemoteAuthorityConfig(stand.Url, net.Config.AuthorityIdentityFingerprint, net.Identity), host.Tls, host.Machine.Deployment.HostConfig) { RetryPause = Fast, Retries = 0 };
        RemoteTransportException? swap = await Thrown<RemoteTransportException>(() => substituted.KeyTransitionsAsync(Other));
        check(swap is not null && stand.Hits == 0, "custom root: a server that stands in for the authority with a valid certificate of its own identity is refused (no request reached it)");

        // An authority leaf with the right name but signed by another key.
        using EcKey attacker = new();
        using X509Certificate2 identity = X509CertificateLoader.LoadCertificate(net.Identity);
        using Forged forged = new(new Spec { Issuer = identity.SubjectName, Signer = attacker.Key, Fingerprint = net.Config.AuthorityIdentityFingerprint }, DateTimeOffset.UtcNow);
        check(MachineCertificates.ValidateLeaf(forged.Certificate, net.Identity, DateTimeOffset.UtcNow) is not null, "custom root: a leaf that names the right identity but was signed by another key does not validate");

        // Inbound: the identity comes from the certificate. The peers classifier reads the SAN, looks up THAT enrolled identity and nothing else.
        MachinePeers peers = new(net.Authority.Deployment.Store, TimeProvider.System);
        PeerIdentity enrolled = peers.Classify(host.Tls.Current);
        using TestMachine unknown = new(Path.Combine(root, "unk-" + Guid.NewGuid().ToString("N")[..6]), trusted: false, hostName: "unknown");
        PeerIdentity stranger = peers.Classify(unknown.Deployment.Tls.Current);
        check(enrolled is { Kind: PeerKind.Enrolled } && enrolled.Fingerprint == host.Fingerprint && stranger is { Kind: PeerKind.Provisional } && stranger.Fingerprint == unknown.Fingerprint, "inbound: the SAN names the machine; an enrolled machine's certificate chains to its enrolled identity, an unenrolled one is only provisional (pairing route)");
        using X509Certificate2 hostIdentity = X509CertificateLoader.LoadCertificate(host.Machine.Deployment.IdentityCertificate);
        using ECDsa thief = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using Forged asHost = new(new Spec { Issuer = hostIdentity.SubjectName, Signer = thief, Fingerprint = host.Fingerprint }, DateTimeOffset.UtcNow);
        check(peers.Classify(asHost.Certificate) is { Kind: PeerKind.Rejected }, "inbound: a certificate that names an enrolled machine but was not signed by that machine's identity key is rejected, not merely 'unknown' (substitution)");
        using Raw rejected = new(net.Url, net.Identity, asHost.Certificate);
        int before = net.Listener.HandshakeRejections;
        HttpRequestException? failed = await Thrown<HttpRequestException>(() => rejected.Send(HttpMethod.Post, MachineApi.OpPath(RemoteOps.KeyTransitions), "{}"));
        check(failed is not null && await Until(() => net.Listener.HandshakeRejections > before, 5), "inbound: the TLS handshake is refused when the client certificate does not validate (no request is ever read)");
    }

    // ---------- downgrades ----------

    private static async Task Downgrades(Action<bool, string> check, string root)
    {
        using Net net = Net.Start(root);
        Peer host = net.Host("down-host");
        X509Certificate2 cert = host.Tls.Current;
        string path = MachineApi.OpPath(RemoteOps.KeyTransitions);
        string body = RemoteWire.Request("kt-down", RemoteOps.KeyTransitions, RemoteWire.WriteAfter(Other));

        using Raw good = new(net.Url, net.Identity, cert);
        check((await good.Send(HttpMethod.Post, path, body)).Status == 200, "downgrade: the control request (TLS 1.3, HTTP/2, a valid certificate) is served");
        using Raw tls12 = new(net.Url, net.Identity, cert, SslProtocols.Tls12);
        check(await Thrown<Exception>(() => tls12.Send(HttpMethod.Post, path, body)) is not null, "downgrade: a TLS 1.2 client cannot connect");
        using Raw http11 = new(net.Url, net.Identity, cert, http2: false);
        check(await Thrown<Exception>(() => http11.Send(HttpMethod.Post, path, body)) is not null, "downgrade: a client that offers only HTTP/1.1 cannot connect (no fallback)");
        using Raw tls12and13 = new(net.Url, net.Identity, cert, SslProtocols.Tls12 | SslProtocols.Tls13);
        (int negotiated, _, _) = await tls12and13.Send(HttpMethod.Post, path, body);
        check(negotiated == 200, "downgrade: a client that offers both versions is served (the server offers TLS 1.3 only)");
        using Raw anonymous = new(net.Url, net.Identity, null);
        check(await Thrown<Exception>(() => anonymous.Send(HttpMethod.Post, path, body)) is not null, "downgrade: a client with no certificate cannot make a request (mutual TLS is required)");
        using Raw plain = new(net.Url.Replace("https://", "http://", StringComparison.Ordinal), net.Identity, cert);
        check(await Thrown<Exception>(() => plain.Send(HttpMethod.Post, path, body)) is not null, "downgrade: plain HTTP to the machine port gets nothing");

        // The client library itself refuses an http address and a config without an identity.
        check(RemoteTarget.Problem(new RemoteAuthorityConfig("http://127.0.0.1:1", net.Config.AuthorityIdentityFingerprint, net.Identity)) is not null && RemoteTarget.Problem(new RemoteAuthorityConfig(net.Url, new string('A', 64), net.Identity)) is not null && RemoteTarget.Problem(net.Config) is null, "client: an http address, or an identity certificate that is not the one the fingerprint names, is not a usable configuration");
    }

    // ---------- every route ----------

    private static async Task EveryRoute(Action<bool, string> check, string root)
    {
        using Net net = Net.Start(root);
        Peer host = net.Host("route-host");
        using TestMachine unknown = new(Path.Combine(root, "route-unk-" + Guid.NewGuid().ToString("N")[..6]), trusted: false, hostName: "unknown");
        IReadOnlyList<string> routes = MachineApi.Routes;
        check(routes.Count == RemoteOps.Requests.Length + 1 && routes.Contains(MachineApi.PairingPath) && routes.Distinct().Count() == routes.Count, "routes: the machine API is exactly the operations plus the pairing route (" + routes.Count + " routes)");

        using Raw anonymous = new(net.Url, net.Identity, null);
        using Raw stranger = new(net.Url, net.Identity, unknown.Deployment.Tls.Current);
        using Raw member = new(net.Url, net.Identity, host.Tls.Current);
        int noCertificate = 0;
        int strangerRefused = 0;
        int strangerPairing = 0;
        int memberServed = 0;
        foreach (string route in routes)
        {
            bool pairing = route == MachineApi.PairingPath;
            if (await Thrown<Exception>(() => anonymous.Send(HttpMethod.Post, route, "{}")) is not null)
            {
                noCertificate++;
            }

            (int strangerStatus, _, string strangerBody) = await stranger.Send(HttpMethod.Post, route, "{}");
            if (pairing && strangerStatus == 501 && strangerBody.Contains("not-implemented", StringComparison.Ordinal))
            {
                strangerPairing++;
            }
            else if (!pairing && strangerStatus == 403 && strangerBody.Contains("unknown-machine", StringComparison.Ordinal))
            {
                strangerRefused++;
            }

            (int memberStatus, _, _) = await member.Send(HttpMethod.Post, route, "{\"v\":1}");
            if (pairing ? memberStatus == 501 : memberStatus is not 403 and < 500)
            {
                memberServed++;
            }
        }

        check(noCertificate == routes.Count, "routes: with no client certificate not one of the " + routes.Count + " routes (pairing included) can be reached");
        check(strangerRefused == routes.Count - 1 && strangerPairing == 1, "routes: a well-formed certificate of an unenrolled machine reaches the pairing route only (501 not-implemented) and is refused 403 unknown-machine everywhere else (" + strangerRefused + " refused, " + strangerPairing + " pairing)");
        check(memberServed == routes.Count, "routes: an enrolled Trusted machine's certificate is served on every route (operations answer or reject the body; pairing is the 501 stub)");

        List<string> odd = [];
        foreach (string path in new[] { "/", "/admin", "/api/v1/status", "/api/v1/machine", MachineApi.OpsPrefix, MachineApi.OpsPrefix + "nonsense", "/relay/v1/host" })
        {
            (int status, _, _) = await member.Send(HttpMethod.Post, path, "{}");
            (int stranged, _, _) = await stranger.Send(HttpMethod.Post, path, "{}");
            if (status != 404 || stranged != 403)
            {
                odd.Add(path + " " + status + "/" + stranged);
            }
        }

        check(odd.Count == 0, "routes: any other path answers 404 to a member and 403 to a stranger (" + string.Join(", ", odd) + ")");
        (int get, _, _) = await member.Send(HttpMethod.Get, MachineApi.OpPath(RemoteOps.KeyTransitions), null);
        (int put, _, _) = await member.Send(HttpMethod.Put, MachineApi.OpPath(RemoteOps.KeyTransitions), "{}");
        check(get == 405 && put == 405, "routes: only POST is accepted (405 for GET and PUT)");

        // The identity is the certificate's: a header or a field that names another machine changes nothing.
        using TestMachine other = new(Path.Combine(root, "route-other-" + Guid.NewGuid().ToString("N")[..6]), trusted: false, hostName: "other");
        net.Authority.Deployment.Store.Register(other.MachineKey.PublicKey, "other", "test", other.Deployment.IdentityCertificate);
        net.Authority.Deployment.Store.Approve(other.Fingerprint, "other", "test admin");
        (int asOther, WireMessage? asOtherMessage, _, _) = await member.Call(RemoteOps.PendingInvalidations, "who-1", RemoteWire.WriteFingerprint(other.Fingerprint));
        (int withHeaders, _, _) = await member.Send(HttpMethod.Post, MachineApi.OpPath(RemoteOps.PendingInvalidations), RemoteWire.Request("who-2", RemoteOps.PendingInvalidations, RemoteWire.WriteFingerprint(other.Fingerprint)), tweak: request => { request.Headers.Add("X-Machine", other.Fingerprint); request.Headers.Add("X-Forwarded-Client-Cert", other.Fingerprint); });
        check(asOther == 403 && asOtherMessage is { Ok: false, Error: "wrong-machine" } && withHeaders == 403, "routes: a request for another machine's data is refused whatever header or field says so (wrong-machine)");
    }

    // ---------- transport policy ----------

    private static async Task Policy(Action<bool, string> check, string root)
    {
        using Net net = Net.Start(root);
        Peer host = net.Host("policy-host");
        using Raw raw = new(net.Url, net.Identity, host.Tls.Current);
        string path = MachineApi.OpPath(RemoteOps.KeyTransitions);
        string body = RemoteWire.Request("kt-policy", RemoteOps.KeyTransitions, RemoteWire.WriteAfter(Other));

        (int status, HttpResponseMessage response, string text) = await raw.Send(HttpMethod.Post, path, body, tweak: request =>
        {
            request.Headers.AcceptEncoding.ParseAdd("gzip, deflate, br");
            request.Headers.TryAddWithoutValidation("If-None-Match", "*");
            request.Headers.IfModifiedSince = DateTimeOffset.UtcNow;
        });
        check(status == 200 && response.Headers.CacheControl?.NoStore == true && !response.Headers.Contains("ETag") && !response.Content.Headers.Contains("Last-Modified") && !response.Content.Headers.ContentEncoding.Any() && response.Content.Headers.ContentType?.MediaType == "application/json" && response.Content.Headers.ContentType.CharSet == "utf-8",
            "policy: the answer is Cache-Control no-store with no validators, is not compressed although the client asked, and is application/json in UTF-8");
        check(response.Headers.Contains("X-Correlation-Id") && response.Headers.TryGetValues("X-Content-Type-Options", out IEnumerable<string>? sniff) && sniff.Contains("nosniff") && !response.Headers.Contains("Server") && !response.Headers.Contains("Location"), "policy: a correlation id, nosniff, no server banner, no redirect");
        check(text.Contains("\"ok\":true", StringComparison.Ordinal), "policy: the answer is a frame");

        // Content type and coding.
        (int plainText, _, _) = await raw.Send(HttpMethod.Post, path, body, "text/plain");
        (int form, _, _) = await raw.Send(HttpMethod.Post, path, body, "application/x-www-form-urlencoded");
        (int none, _, _) = await raw.Send(HttpMethod.Post, path, body, null);
        (int utf16, _, _) = await raw.Send(HttpMethod.Post, path, body, "application/json; charset=utf-16");
        (int utf8, _, _) = await raw.Send(HttpMethod.Post, path, body, "application/json; charset=utf-8");
        (int gzipped, _, _) = await raw.Send(HttpMethod.Post, path, body, tweak: request => request.Content!.Headers.ContentEncoding.Add("gzip"));
        check(plainText == 415 && form == 415 && none == 415 && utf16 == 415 && gzipped == 415 && utf8 == 200, "policy: only UTF-8 application/json is accepted: text, form, no type, UTF-16 and a content coding get 415 (" + plainText + " " + form + " " + none + " " + utf16 + " " + gzipped + " " + utf8 + ")");

        // Safe errors: a code, a correlation id, nothing about the inside.
        (int garbage, HttpResponseMessage errorResponse, string errorText) = await raw.Send(HttpMethod.Post, path, "this is not json");
        (int wrongOp, _, string wrongText) = await raw.Send(HttpMethod.Post, path, RemoteWire.Request("x", RemoteOps.Decide, "{}"));
        (int mismatch, WireMessage? mismatchMessage, _, _) = await raw.Call(RemoteOps.Decide, "d-bad", "{\"nonsense\":true}");
        check(garbage == 400 && errorText.Contains("\"ok\":false", StringComparison.Ordinal) && errorText.Contains("bad-request", StringComparison.Ordinal) && errorResponse.Headers.Contains("X-Correlation-Id") && wrongOp == 400 && wrongText.Contains("bad-request", StringComparison.Ordinal)
            && mismatch == 400 && mismatchMessage is { Ok: false, Error: "bad-request" }, "policy: malformed JSON, an operation that is not the route's and a body that is not the operation's get a short code and a correlation id");
        check(!errorText.Contains("Exception", StringComparison.Ordinal) && !errorText.Contains(" at ", StringComparison.Ordinal) && !errorText.Contains(root, StringComparison.Ordinal) && !errorText.Contains("Kestrel", StringComparison.OrdinalIgnoreCase) && errorText.Length < 300, "policy: an error carries no exception text, stack, path or product name");

        // A proxy variable is not used by the client: the request goes straight to the authority.
        string? saved = Environment.GetEnvironmentVariable("HTTPS_PROXY");
        Environment.SetEnvironmentVariable("HTTPS_PROXY", "http://127.0.0.1:1");
        try
        {
            Peer viaProxyVariable = net.Host("proxy-host");
            check((await viaProxyVariable.Remote.KeyTransitionsAsync(Other)).Count == 0, "proxy: with HTTPS_PROXY set to a dead address the client still connects directly (no proxy is ever used)");
        }
        finally
        {
            Environment.SetEnvironmentVariable("HTTPS_PROXY", saved);
        }
    }

    private static async Task Bounds(Action<bool, string> check, string root)
    {
        MachineListenerOptions narrow = new() { Port = 0, MaxBodyBytes = 2048, MaxConcurrentPerMachine = 1 };
        using Net net = Net.Start(root, narrow);
        Peer host = net.Host("bounds-host");
        using Raw raw = new(net.Url, net.Identity, host.Tls.Current);
        string path = MachineApi.OpPath(RemoteOps.KeyTransitions);
        (int big, _, string bigText) = await raw.Send(HttpMethod.Post, path, RemoteWire.Request("big", RemoteOps.KeyTransitions, "{\"after\":\"" + new string('a', 5000) + "\"}"));
        check(big == 413 && bigText.Contains("too-large", StringComparison.Ordinal), "bounds: a body over the limit is refused with 413 (no reading it all)");
        (int ok, _, _) = await raw.Send(HttpMethod.Post, path, RemoteWire.Request("small", RemoteOps.KeyTransitions, RemoteWire.WriteAfter(Other)));
        check(ok == 200, "bounds: and a body within it is served");

        // One poll in flight holds the machine's only slot: a second request is refused (429), not queued.
        using CancellationTokenSource stop = new();
        Task<AuthorityNotices> poll = host.Remote.PollAsync(host.Fingerprint, stop.Token);
        await Until(() => net.Listener.InFlight >= 1, 5);
        System.Diagnostics.Stopwatch watch = System.Diagnostics.Stopwatch.StartNew();
        (int busy, _, string busyText) = await raw.Send(HttpMethod.Post, path, RemoteWire.Request("busy", RemoteOps.KeyTransitions, RemoteWire.WriteAfter(Other)));
        check(busy == 429 && busyText.Contains("too-busy", StringComparison.Ordinal) && watch.Elapsed < TimeSpan.FromSeconds(3), "bounds: over the per-machine concurrency limit a request is refused at once with 429, not queued (" + busy + " after " + watch.ElapsedMilliseconds + " ms)");
        await stop.CancelAsync();
        await Thrown<OperationCanceledException>(() => poll);
        check(await Until(() => net.Listener.InFlight == 0, 5), "bounds: the slot is free again once the poll ends");

        MachineListenerOptions production = new();
        check(production.MaxBodyBytes <= 8 * 1024 * 1024 && production.MaxConcurrent <= 256 && production.MaxConcurrentPerMachine <= 16 && production.OperationTimeout <= TimeSpan.FromMinutes(1) && production.MaxPairingBodyBytes < production.MaxBodyBytes, "bounds: the production limits are fixed and finite (body, pairing body, concurrency, time)");
    }

    // ---------- revocation ----------

    private static async Task Revocation(Action<bool, string> check, string root)
    {
        MachineListenerOptions options = new() { Port = 0, CloseGrace = TimeSpan.FromMilliseconds(400) };
        using Net net = Net.Start(root, options);
        Peer host = net.Host("revoked-host");
        Peer other = net.Host("bystander");
        await host.Remote.KeyTransitionsAsync(Other);
        await other.Remote.KeyTransitionsAsync(Other);
        using Raw idle = new(net.Url, net.Identity, host.Tls.Current);
        string path = MachineApi.OpPath(RemoteOps.KeyTransitions);
        (int first, _, _) = await idle.Send(HttpMethod.Post, path, RemoteWire.Request("idle-1", RemoteOps.KeyTransitions, RemoteWire.WriteAfter(Other)));
        using CancellationTokenSource stop = new();
        Task<AuthorityNotices> poll = host.Remote.PollAsync(host.Fingerprint, stop.Token);
        await Until(() => net.Listener.InFlight >= 1, 5);
        int connectionsBefore = net.Listener.Connections;

        net.Authority.Deployment.Store.Disable(host.Fingerprint, "test admin");
        RemoteRefusedException? ended = null;
        try
        {
            await poll.WaitAsync(TimeSpan.FromSeconds(10));
        }
        catch (RemoteRefusedException error)
        {
            ended = error;
        }
        catch (RemoteTransportException)
        {
            // The connection went away first: also an end.
        }

        check(first == 200 && connectionsBefore >= 3 && poll.IsCompleted && (ended is null || ended.Code == "machine-not-trusted"), "revocation: disabling a machine ends its waiting poll (machine-not-trusted or a closed connection), not after a timeout");
        check(await Until(() => net.Listener.ClosedByRevocation >= 1 && net.Listener.Connections <= connectionsBefore - 2, 10), "revocation: its connections are closed (GOAWAY, then closed after the grace): " + net.Listener.Connections + " remain of " + connectionsBefore);
        int reuseStatus = 0;
        try
        {
            (reuseStatus, _, _) = await idle.Send(HttpMethod.Post, path, RemoteWire.Request("idle-2", RemoteOps.KeyTransitions, RemoteWire.WriteAfter(Other)));
        }
        catch (HttpRequestException)
        {
            reuseStatus = -1;
        }

        RemoteRefusedException? refused = await Thrown<RemoteRefusedException>(() => host.Remote.KeyTransitionsAsync(Other));
        check(refused is { Code: "machine-not-trusted" } && reuseStatus is -1 or 403, "revocation: the next request of the revoked machine (on the old connection or a new one) is refused, per request, whatever its certificate says (reuse " + reuseStatus + ")");
        check((await other.Remote.KeyTransitionsAsync(Other)).Count == 0, "revocation: another machine's connection is untouched");

        // Untrusted, and a certificate for a machine that is Pending.
        net.Authority.Deployment.Store.Enable(host.Fingerprint, "test admin");
        check((await host.Remote.KeyTransitionsAsync(Other)).Count == 0, "revocation: re-enabled, the machine is served again on a new connection");
        net.Authority.Deployment.Store.Untrust(host.Fingerprint, "test admin");
        check(await Thrown<RemoteRefusedException>(() => host.Remote.KeyTransitionsAsync(Other)) is { Code: "machine-not-trusted" }, "revocation: an Untrusted machine is refused too");
        Peer pending = net.Host("pending-host", approve: false);
        check(await Thrown<RemoteRefusedException>(() => pending.Remote.KeyTransitionsAsync(Other)) is { Code: "machine-not-trusted" }, "revocation: a Pending machine (enrolled, not approved) is refused on every route");

        // A lock ends everything at once.
        AuthorityLock gate = AuthorityLock.UnlockedForTests();
        using Net locked = Net.Start(root);
        locked.Authority.Deployment.Keys.LockState = gate;
        Peer lockedHost = locked.Host("locked-host");
        await lockedHost.Remote.KeyTransitionsAsync(Other);
        gate.Lock("test");
        check(await Thrown<RemoteRefusedException>(() => lockedHost.Remote.KeyTransitionsAsync(Other)) is { Code: "locked" }, "lock: a locked authority answers nothing (locked)");
        gate.Unlock(UnlockMethod.Seam);
        check((await lockedHost.Remote.KeyTransitionsAsync(Other)).Count == 0, "lock: unlocked, the host is served again");
    }

    // ---------- duplicates and retries ----------

    private static async Task Idempotence(Action<bool, string> check, string root)
    {
        using Net net = Net.Start(root);
        Peer host = net.Host("dup-host");
        TestMachine machine = host.Machine;
        LaunchRequest request = Request("req-dup-1");
        int presented = 0;
        using IDisposable offer = net.Authority.Deployment.Authority.Offer(request.RequestId, request.Digest(), () => { Interlocked.Increment(ref presented); return ApprovalDecision.Allow(); });
        MachineRequestEnvelope envelope = MachineRequestEnvelope.Create(request, machine.HostName, machine.MachineKey);
        AuthorityResponse[] both = await Task.WhenAll(host.Remote.DecideAsync(envelope), host.Remote.DecideAsync(envelope));
        using RemoteAuthority other = new(net.Config, host.Tls, machine.Deployment.HostConfig);
        AuthorityResponse viaNewConnection = await other.DecideAsync(envelope);
        check(presented == 1 && both[0].ToJson() == both[1].ToJson() && viaNewConnection.ToJson() == both[0].ToJson(), "duplicate: the same request id (in flight twice, or from a new connection) returns the committed answer and asks nobody twice");

        using Raw raw = new(net.Url, net.Identity, host.Tls.Current);
        string body = RemoteWire.Write(ReconcileEnvelope.Create("rc-dup", machine.HostName, DateTimeOffset.UtcNow, machine.MachineKey));
        (_, WireMessage? one, _, _) = await raw.Call(RemoteOps.Reconcile, "same-id", body);
        (_, WireMessage? same, _, _) = await raw.Call(RemoteOps.Reconcile, "same-id", body);
        (int different, WireMessage? changed, _, _) = await raw.Call(RemoteOps.Reconcile, "same-id", RemoteWire.Write(ReconcileEnvelope.Create("rc-dup-2", machine.HostName, DateTimeOffset.UtcNow, machine.MachineKey)));
        check(one is { Ok: true } && same is { Ok: true } && same.Body == one.Body && changed is { Ok: false, Error: "request-id-reused" } && different == 409, "duplicate: one request id returns the same result for the same content and is refused (409) for other content");

        // A request is retried (same id) when the connection breaks: here the authority is down for the first attempts and back later.
        using Net restartable = Net.Start(root);
        Peer retrying = restartable.Host("retry-host");
        await retrying.Remote.KeyTransitionsAsync(Other);
        restartable.Listener.Dispose();
        Task<IReadOnlyList<KeyTransition>> pendingCall = retrying.Remote.KeyTransitionsAsync(Other);
        await Task.Delay(150);
        restartable.RestartListener();
        check((await pendingCall.WaitAsync(TimeSpan.FromSeconds(30))).Count == 0, "retry: an ordinary request that finds the authority down is retried with backoff and succeeds when it is back");
    }

    private sealed class SlowRelease : IRemoteLaunchHandler
    {
        private int _calls;

        public int Calls => Volatile.Read(ref _calls);

        public async Task<LaunchAnswer> AuthorizeAsync(string machineFingerprint, LaunchAuthorize message, Action<string> announceLink, CancellationToken cancel)
        {
            Interlocked.Increment(ref _calls);
            await Task.Delay(TimeSpan.FromSeconds(20), cancel);

            throw new InvalidOperationException("never answers in time");
        }

        public void Sent(string machineFingerprint, string requestId, bool sent)
        {
        }
    }

    private static async Task Recovery(Action<bool, string> check, string root)
    {
        using Net net = Net.Start(root);
        Peer host = net.Host("recover-host");
        ReconcileResponse first = await host.Remote.ReconcileAsync(ReconcileEnvelope.Create("rc-rec-1", "recover-host", DateTimeOffset.UtcNow, host.Machine.MachineKey));
        int connections = host.Remote.Connections;
        host.Remote.Disconnect();
        ReconcileResponse next = await host.Remote.ReconcileAsync(ReconcileEnvelope.Create("rc-rec-2", "recover-host", DateTimeOffset.UtcNow, host.Machine.MachineKey));
        check(first.Status == "Trusted" && next.Status == "Trusted" && host.Remote.Connections == connections + 1, "recovery: after a dropped connection the next call connects again by itself (a new TLS connection with the same certificate)");

        // A decision interrupted by a lost connection is repeated under its id and answered once.
        LaunchRequest request = Request("req-recover-1");
        int presented = 0;
        using IDisposable offer = net.Authority.Deployment.Authority.Offer(request.RequestId, request.Digest(), () => { Interlocked.Increment(ref presented); Thread.Sleep(600); return ApprovalDecision.Allow(); });
        MachineRequestEnvelope envelope = MachineRequestEnvelope.Create(request, "recover-host", host.Machine.MachineKey);
        int requestsBefore = net.Listener.Requests;
        int connectionsBefore = host.Remote.Connections;
        Task<AuthorityResponse> pending = host.Remote.DecideAsync(envelope);
        await Task.Delay(250);
        host.Remote.Disconnect();
        AuthorityResponse decided = await pending.WaitAsync(TimeSpan.FromSeconds(30));
        check(decided.Decision == AuthorityDecision.Approved && presented == 1 && host.Remote.Connections == connectionsBefore + 1 && net.Listener.Requests - requestsBefore == 2, "recovery: a decision interrupted by a lost connection is repeated on a new connection under the same id (two requests, one new connection) and the approval is not asked twice (asked " + presented + ", requests " + (net.Listener.Requests - requestsBefore) + ")");

        // A release whose answer is lost is NOT retried: the values may already have left the authority.
        SlowRelease handler = new();
        using Net releasing = Net.Start(root, launches: handler);
        Peer releaseHost = releasing.Host("rel-host");
        using RemoteAuthority client = new(releasing.Config, releaseHost.Tls, releaseHost.Machine.Deployment.HostConfig) { RetryPause = Fast, Retries = 5, RequestTimeout = TimeSpan.FromMilliseconds(500) };
        LaunchRequest launch = Request("req-release-1");
        PageContext context = new("/work/tool.sh", [], [], null, null, new string('A', 64));
        LaunchAuthorize message = LaunchAuthorize.Create(launch, GrantEvidence.Scope(releaseHost.Fingerprint, context.FingerprintKey, context.Arguments), context, "rel-host", releaseHost.Machine.MachineKey);
        RemoteTransportException? lost = await Thrown<RemoteTransportException>(() => client.AuthorizeLaunchAsync(message, _ => { }, CancellationToken.None));
        await Task.Delay(1200);
        check(lost is not null && handler.Calls == 1, "recovery: a launch whose answer is lost (here: it does not come in time) fails and is NOT sent again, although retries are allowed (handler calls " + handler.Calls + ")");
    }

    // ---------- the long poll ----------

    private static async Task LongPoll(Action<bool, string> check, string root)
    {
        MachineListenerOptions options = new() { Port = 0, CloseGrace = TimeSpan.FromMilliseconds(300) };
        using Net net = Net.Start(root, options);
        Peer host = net.Host("poll-host");
        string fingerprint = host.Machine.Fingerprint;

        // Nothing pending: the poll waits (no periodic empty answers, no heartbeat).
        int requestsBefore = net.Listener.Requests;
        Task<AuthorityNotices> waiting = host.Remote.PollAsync(fingerprint, CancellationToken.None);
        await Task.Delay(1500);
        check(!waiting.IsCompleted && net.Listener.Requests == requestsBefore + 1, "long poll: with nothing to deliver one poll is simply outstanding (one request in 1.5 s, no empty answers, no heartbeat)");

        // The revocation ends it (a Disabled machine cannot poll), and the invalidation it leaves is pending.
        net.Authority.Deployment.Store.Disable(fingerprint, "test admin");
        await Thrown<Exception>(() => waiting.WaitAsync(TimeSpan.FromSeconds(10)));
        check(waiting.IsCompleted && net.Authority.Deployment.Store.PendingInvalidations(fingerprint).Count == 1, "long poll: disabling the machine ends the wait and leaves one durable invalidation pending");

        // Re-enabled: the pending invalidation is delivered at once, repeated until acknowledged.
        net.Authority.Deployment.Store.Enable(fingerprint, "test admin");
        AuthorityNotices notices = await host.Remote.PollAsync(fingerprint, CancellationToken.None);
        AuthorityNotices again = await host.Remote.PollAsync(fingerprint, CancellationToken.None);
        check(notices.Invalidations.Count == 1 && notices.Invalidations[0].Revision == 2 && again.Invalidations.Count == 1 && again.Invalidations[0].Revision == 2, "long poll: the pending invalidation is delivered by the poll, and again until it is acknowledged");
        await host.Remote.AcknowledgeInvalidationAsync(fingerprint, 2);
        check(net.Authority.Deployment.Store.PendingInvalidations(fingerprint).Count == 0, "long poll: the acknowledgement is durable at the authority (and a delivered invalidation is not sent again)");

        // Unacknowledged across an authority restart: delivered to the reconnecting host.
        net.Authority.Deployment.Store.Disable(fingerprint, "test admin");
        net.Authority.Deployment.Store.Enable(fingerprint, "test admin");
        net.RestartListener();
        AuthorityNotices afterRestart = new([], []);
        bool delivered = false;
        for (int attempt = 0; attempt < 20 && !delivered; attempt++)
        {
            try
            {
                afterRestart = await host.Remote.PollAsync(fingerprint, CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5));
                delivered = true;
            }
            catch (Exception error) when (error is RemoteTransportException or TimeoutException)
            {
                await Task.Delay(100);
            }
        }

        check(delivered && afterRestart.Invalidations.Count == 1 && afterRestart.Invalidations[0].Revision == 3, "long poll: an invalidation that was not acknowledged survives an authority restart and is delivered after the host reconnects (durable pending_invalidations)");
        await host.Remote.AcknowledgeInvalidationAsync(fingerprint, 3);

        // A waiting poll when the authority goes away: it ends with a transport failure (the host's loop reconnects).
        Task<AuthorityNotices> cut = host.Remote.PollAsync(fingerprint, CancellationToken.None);
        await Task.Delay(300);
        net.Listener.Dispose();
        RemoteTransportException? broken = await Thrown<RemoteTransportException>(() => cut.WaitAsync(TimeSpan.FromSeconds(15)));
        check(broken is not null, "long poll: a poll that is waiting when the authority goes away ends with a transport failure the host reconnects from");
        net.RestartListener();
    }

    // ---------- a hostile or broken authority ----------

    private static async Task HostileAuthority(Action<bool, string> check, string root)
    {
        using TestMachine hostMachine = new(Path.Combine(root, "client-host"), trusted: false, hostName: "client-host");

        async Task<(Exception? Error, int Hits)> Against(Func<HttpContext, Task> answer, int retries = 0)
        {
            using Hostile server = new(root, answer);
            hostMachine.Deployment.HostConfig.SetRemote(hostMachine.Fingerprint, server.Config);
            using RemoteAuthority client = new(server.Config, hostMachine.Deployment.Tls, hostMachine.Deployment.HostConfig) { RetryPause = Fast, Retries = retries, ConnectTimeout = TimeSpan.FromSeconds(5) };
            Exception? error = null;
            try
            {
                await client.KeyTransitionsAsync(Other);
            }
            catch (Exception caught) when (caught is RemoteTransportException or RemoteRefusedException)
            {
                error = caught;
            }

            return (error, server.Hits);
        }

        (Exception? redirect, int redirectHits) = await Against(context =>
        {
            context.Response.StatusCode = 307;
            context.Response.Headers.Location = "/elsewhere";

            return Task.CompletedTask;
        });
        check(redirect is RemoteTransportException && redirectHits == 1, "client: a redirect is an error and is never followed (one request reached the server)");
        (Exception? html, _) = await Against(context =>
        {
            context.Response.ContentType = "text/html";

            return context.Response.WriteAsync("<html>sign in</html>");
        });
        (Exception? encoded, _) = await Against(context =>
        {
            context.Response.ContentType = "application/json; charset=utf-8";
            context.Response.Headers.ContentEncoding = "gzip";

            return context.Response.WriteAsync("{}");
        });
        (Exception? utf16, _) = await Against(context =>
        {
            context.Response.ContentType = "application/json; charset=utf-16";

            return context.Response.WriteAsync("{}");
        });
        (Exception? junk, _) = await Against(context =>
        {
            context.Response.ContentType = "application/json; charset=utf-8";

            return context.Response.WriteAsync("not json at all");
        });
        (Exception? wrongId, _) = await Against(context =>
        {
            context.Response.ContentType = "application/json; charset=utf-8";

            return context.Response.WriteAsync("{\"v\":1,\"id\":\"some-other-request\",\"ok\":true,\"body\":{\"transitions\":[]}}");
        });
        check(html is RemoteTransportException && encoded is RemoteTransportException && utf16 is RemoteTransportException && junk is RemoteTransportException && wrongId is RemoteTransportException, "client: an answer that is not UTF-8 application/json, is compressed, is unreadable or is for another request is refused (" + string.Join(" | ", new[] { html, encoded, utf16, junk, wrongId }.Select(item => item?.GetType().Name + ":" + item?.Message)) + ")");
        (Exception? serverError, int errorHits) = await Against(context =>
        {
            context.Response.StatusCode = 500;
            context.Response.ContentType = "application/json; charset=utf-8";

            return context.Response.WriteAsync("{\"v\":1,\"id\":\"x\",\"ok\":false,\"error\":\"internal-error\"}");
        }, retries: 2);
        check(serverError is not null && errorHits >= 1, "client: a server error is an error (it is not mistaken for an answer)");
    }
}

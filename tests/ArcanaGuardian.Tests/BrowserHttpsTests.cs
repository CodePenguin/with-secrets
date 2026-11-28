using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ArcanaGuardian.Tests;

internal static class BrowserHttpsTests
{
    internal static async Task Run(Action<bool, string> check)
    {
        string folder = Directory.CreateTempSubdirectory("ws-browser-https-test-").FullName;
        var trust = new TestTrust();
        var certificates = new BrowserCertificates(folder, trust);
        void Run(string action, TextWriter? output = null) =>
            certificates.Run(action, false, OperatingSystem.IsLinux() ? folder : null, null, output ?? TextWriter.Null);

        try
        {
            check(Refused(() => Open(certificates)), "browser HTTPS: missing configuration fails closed");
            Run("prepare");
            check(trust.Installed.Count == 0 && Refused(() => Open(certificates)),
                "browser HTTPS: preparation never installs trust or makes the listener usable");
            Run("setup");
            using var original = certificates.Open();
            BrowserCertificate.Validate(original, DateTimeOffset.UtcNow);
            string originalId = BrowserCertificate.Digest(original);
            check(original.HasPrivateKey && original.MatchesHostname(BrowserAddress.Host) &&
                !original.MatchesHostname("localhost"), "browser HTTPS: exact hostname and private key");
            if (OperatingSystem.IsWindows())
            {
                using var key = original.GetECDsaPrivateKey() as ECDsaCng;
                check(key?.Key.ExportPolicy == CngExportPolicies.None && key.Key.KeyName is not null,
                    "browser HTTPS: Windows private key is named and non-exportable");
            }
            else
            {
                string file = Directory.GetFiles(Path.Combine(folder, "browser-https"), "*.key").Single();
                check(File.GetUnixFileMode(file) == (UnixFileMode.UserRead | UnixFileMode.UserWrite),
                    "browser HTTPS: Unix private key is owner-only");
            }

            Run("setup");
            using var same = new BrowserCertificates(folder, trust).Open();
            check(BrowserCertificate.Digest(same) == originalId && trust.Installed.SetEquals([originalId]),
                "browser HTTPS: idempotent setup and persisted identity");
            using var status = new StringWriter();
            Run("status", status);
            check(status.ToString().Contains(originalId, StringComparison.Ordinal) &&
                status.ToString().Contains("trusted", StringComparison.Ordinal), "browser HTTPS: reports exact trust state");

            using (certificates.OpenListener())
            {
                check(Refused(() => Run("replace")), "browser HTTPS: running authority prevents trust replacement");
            }

            trust.FailInstall = true;
            check(Refused(() => Run("replace")), "browser HTTPS: interrupted installation is reported");
            using var stillOriginal = certificates.Open();
            check(BrowserCertificate.Digest(stillOriginal) == originalId, "browser HTTPS: failed install keeps original active");

            trust.FailInstall = false;
            trust.FailRemove = true;
            check(Refused(() => Run("replace")), "browser HTTPS: interrupted obsolete-trust removal is reported");
            using var replacement = certificates.Open();
            string replacementId = BrowserCertificate.Digest(replacement);
            check(replacementId != originalId &&
                !replacement.PublicKey.ExportSubjectPublicKeyInfo().SequenceEqual(original.PublicKey.ExportSubjectPublicKeyInfo()) &&
                !replacement.SubjectName.RawData.SequenceEqual(original.SubjectName.RawData) &&
                trust.Installed.SetEquals([originalId, replacementId]),
                "browser HTTPS: replacement uses a fresh key, with original pending cleanup");
            trust.FailRemove = false;
            trust.Installed.Add("unrelated");
            Run("setup");
            check(trust.Installed.SetEquals([replacementId, "unrelated"]),
                "browser HTTPS: retry removes only recorded obsolete trust without replacing the active leaf");

            string path = Directory.GetFiles(Path.Combine(folder, "browser-https"), "*.cer").Single();
            File.WriteAllBytes(path, original.RawData);
            check(Refused(() => Open(certificates)), "browser HTTPS: a substituted valid certificate is refused");
            File.WriteAllText(path, "invalid certificate");
            check(Refused(() => Open(certificates)), "browser HTTPS: malformed certificate refused");
            File.Delete(path);
            check(Refused(() => Open(certificates)), "browser HTTPS: missing recorded certificate refused");
            Run("setup");
            check(File.ReadAllBytes(path).SequenceEqual(replacement.RawData), "browser HTTPS: setup restores exact missing public DER");
            check(Refused(() => BrowserCertificate.Validate(replacement, DateTimeOffset.UtcNow.AddYears(11))),
                "browser HTTPS: expired certificate rejected");

            await ListenerAsync(folder, replacement, original, check);
            Run("remove");
            Run("remove");
            check(trust.Installed.SetEquals(["unrelated"]) && Refused(() => Open(certificates)),
                "browser HTTPS: idempotent removal leaves unrelated trust alone and disables startup");
        }
        finally
        {
            trust.FailInstall = trust.FailRemove = false;
            Run("remove");
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(folder, true);
        }
    }

    private static async Task ListenerAsync(string folder, X509Certificate2 leaf, X509Certificate2 old, Action<bool, string> check)
    {
        using var machine = new SoftwareSigningKey();
        using var authority = new SoftwareSigningKey();
        var state = StateDatabase.InFolder(folder);
        using var deployment = LocalDeployment.Create(folder, machine, _ => authority, "browser-https-test");
        using var identity = X509CertificateLoader.LoadCertificate(deployment.IdentityCertificate);
        check(Refused(() => BrowserCertificate.Validate(identity, DateTimeOffset.UtcNow)),
            "browser HTTPS: a machine identity certificate is not a browser certificate");
        check(MachineCertificates.ValidateIdentity(leaf.RawData, DateTimeOffset.UtcNow) is not null &&
            MachineCertificates.ValidateLeaf(leaf, identity.RawData, DateTimeOffset.UtcNow) is not null,
            "browser HTTPS: machine mTLS rejects the browser certificate as an identity or a leaf");

        // The ordinary host startup opens the persisted browser certificate and leases its state.
        using var service = HostService.Start(new HostServiceOptions { State = state, Store = new SecretStore(state), Deployment = deployment, Port = 0 });
        check(service.BrowserListenerAddresses.All(address => new Uri(address).IsLoopback &&
            new Uri(address).Scheme == "https") && service.BrowserListenerAddresses.Count > 0,
            "browser HTTPS: production listener is TLS-only on loopback");
        using var current = X509CertificateLoader.LoadCertificate(leaf.RawData);
        using var previous = X509CertificateLoader.LoadCertificate(old.RawData);
        using var trusted = SelfCheck.BrowserProbe(current, service.Port);
        using var stale = SelfCheck.BrowserProbe(previous, service.Port);
        using var status = await trusted.GetAsync("/api/v1/status");
        check(status.IsSuccessStatusCode, "browser HTTPS: SPA API serves TLS under the exact configured leaf");
        using var foreign = new HttpRequestMessage(HttpMethod.Get, "/api/v1/status");
        foreign.Headers.TryAddWithoutValidation("Origin", "https://localhost");
        using var forbidden = await trusted.SendAsync(foreign);
        check(forbidden.StatusCode == HttpStatusCode.Forbidden, "browser HTTPS: foreign Origin is refused");
        using var plain = new HttpClient(new SocketsHttpHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(5) };
        try
        {
            using var reply = await plain.GetAsync($"http://127.0.0.1:{service.Port}/api/v1/status");
            check(!reply.IsSuccessStatusCode, "browser HTTPS: the production port does not serve plaintext");
        }
        catch (HttpRequestException)
        {
            check(true, "browser HTTPS: the production port refused a plaintext connection");
        }

        using var cli = await trusted.GetAsync("/v1/status");
        check(cli.StatusCode == HttpStatusCode.NotFound, "browser HTTPS: CLI routes are not exposed on the browser listener");
        try
        {
            using var refused = await stale.GetAsync("/api/v1/status");
            check(false, "browser HTTPS: the TLS client must reject the replacement when it trusts the old certificate");
        }
        catch (HttpRequestException)
        {
            check(true, "browser HTTPS: old exact trust rejects replacement without changing TLS validation");
        }
    }

    private static void Open(BrowserCertificates certificates)
    {
        using var leaf = certificates.Open();
    }

    private static bool Refused(Action operation)
    {
        try
        {
            operation();
            return false;
        }
        catch (Exception error) when (BrowserCertificates.IsLifecycleError(error))
        {
            return true;
        }
    }

    private sealed class TestTrust : IBrowserTrust
    {
        public HashSet<string> Installed { get; } = [];
        public bool FailInstall { get; set; }
        public bool FailRemove { get; set; }

        public bool Contains(TrustTarget target, X509Certificate2 certificate, string path) =>
            Installed.Contains(BrowserCertificate.Digest(certificate));

        public void Install(TrustTarget target, X509Certificate2 certificate, string path, bool permitPrompt, TextWriter output)
        {
            if (FailInstall) throw new IOException("simulated interrupted trust installation");
            Installed.Add(BrowserCertificate.Digest(certificate));
        }

        public void Remove(TrustTarget target, X509Certificate2 certificate, string path, bool permitPrompt, TextWriter output)
        {
            if (FailRemove) throw new IOException("simulated interrupted trust cleanup");
            Installed.Remove(BrowserCertificate.Digest(certificate));
        }
    }
}

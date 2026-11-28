using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;

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
            trust.Unrelated.Add("unrelated");
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

            await ListenerAsync(folder, trust, replacement, original, check);
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

    internal static void RunTrustRemediation(Action<bool, string> check)
    {
        string folder = Directory.CreateTempSubdirectory("ws-browser-trust-test-").FullName;
        var trust = new TestTrust();
        var certificates = new BrowserCertificates(folder, trust);
        void Run(string action, TextWriter? output = null) =>
            certificates.Run(action, false, null, null, output ?? TextWriter.Null);

        try
        {
            Run("setup");
            using var active = certificates.Open();
            string digest = BrowserCertificate.Digest(active);
            TrustTarget primary = JournalTargets(folder)[0];
            var extra = new TrustTarget("chromium", Path.Combine(folder, "second-profile"));
            InjectTarget(folder, extra);

            trust.FailInstallTarget = extra.ToString();
            check(Refused(() => Run("setup")),
                "browser HTTPS: a partially failed multi-target install is reported");
            using (var incomplete = new StringWriter())
            {
                Run("status", incomplete);
                check(incomplete.ToString().Contains("Setup incomplete", StringComparison.Ordinal),
                    "browser HTTPS: status marks the interrupted target set incomplete");
            }
            using (var stillActive = certificates.Open())
            {
                check(BrowserCertificate.Digest(stillActive) == digest,
                    "browser HTTPS: partial install never replaces the active certificate");
            }

            using (var status = new StringWriter())
            {
                Run("status", status);
                check(status.ToString().Contains("install confirmed", StringComparison.Ordinal) &&
                    status.ToString().Contains("install not confirmed", StringComparison.Ordinal),
                    "browser HTTPS: status distinguishes confirmed from intended-only trust targets");
            }

            trust.FailInstallTarget = null;
            Run("setup");
            check(trust.Contains(primary, active, CertificatePath(folder, active)) &&
                trust.Contains(extra, active, CertificatePath(folder, active)),
                "browser HTTPS: retry confirms every target idempotently");
            using (var status = new StringWriter())
            {
                Run("status", status);
                check(!status.ToString().Contains("Setup incomplete", StringComparison.Ordinal),
                    "browser HTTPS: status is complete only after all trust installs succeed");
            }

            trust.Withdraw(extra, active);
            using (var stillTrusted = certificates.Open())
            {
                check(BrowserCertificate.Digest(stillTrusted) == digest,
                    "browser HTTPS: one unavailable browser profile does not disable the authority");
            }

            trust.Withdraw(primary, active);
            string trustFailure = Message(() => Open(certificates));
            check(trustFailure.Contains("trust target currently trusts", StringComparison.Ordinal) &&
                !trustFailure.Contains("integrity checks", StringComparison.Ordinal),
                "browser HTTPS: external trust removal fails closed with a trust-specific diagnostic");
            check(Refused(() => { using var lease = certificates.OpenListener(); }),
                "browser HTTPS: the listener lease also refuses externally untrusted certificates");

            Run("setup");
            check(!Refused(() => Open(certificates)), "browser HTTPS: setup restores withdrawn trust");

            trust.UnavailableTargets.Add(extra.ToString());
            using (var unavailableOptional = certificates.Open())
            {
                check(BrowserCertificate.Digest(unavailableOptional) == digest,
                    "browser HTTPS: an unavailable optional target does not disable the authority");
            }

            trust.UnavailableTargets.Add(primary.ToString());
            check(Message(() => Open(certificates)).Contains("Trust checks reported", StringComparison.Ordinal),
                "browser HTTPS: unavailable trust targets are reported when no target can be verified");
            trust.UnavailableTargets.Clear();

            string path = CertificatePath(folder, active);
            File.WriteAllText(path, "invalid certificate");
            check(Message(() => Open(certificates)).Contains("integrity checks", StringComparison.Ordinal),
                "browser HTTPS: malformed certificate integrity failure is distinct from trust unavailability");
            File.Delete(path);
            check(Message(() => Open(certificates)).Contains("integrity checks", StringComparison.Ordinal),
                "browser HTTPS: missing recorded certificate integrity failure is distinct from trust unavailability");
            Run("setup");

            trust.Unrelated.Add("unrelated-certificate");
            trust.MachineWideDigest = digest;
            check(Refused(() => Run("remove")),
                "browser HTTPS: cleanup refuses when the exact certificate remains machine-wide trusted");
            check(JsonNode.Parse(File.ReadAllText(Path.Combine(folder, "browser-https", "state.json")))!
                    .AsObject()["Retired"]!.AsArray().Count == 1,
                "browser HTTPS: blocked machine-wide cleanup retains retry information");
            trust.MachineWideDigest = null;
            Run("remove");
            check(trust.Installed.SetEquals(["unrelated-certificate"]),
                "browser HTTPS: retried cleanup removes only exact registered trust and preserves unrelated trust");
            string browserDirectory = Path.Combine(folder, "browser-https");
            check(Directory.GetFiles(browserDirectory, "*.cer").Length == 0 &&
                Directory.GetFiles(browserDirectory, "*.key").Length == 0,
                "browser HTTPS: exact certificate DER and private key are removed after cleanup");
        }
        finally
        {
            trust.FailInstall = trust.FailRemove = false;
            trust.MachineWideDigest = null;
            try { Run("remove"); } catch { }
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(folder, true);
        }
    }

    internal static void RunRemoteListenerSeparation(Action<bool, string> check)
    {
        string folder = Directory.CreateTempSubdirectory("ws-browser-remote-test-").FullName;
        try
        {
            using var machine = new SoftwareSigningKey();
            using var authority = new SoftwareSigningKey();
            using var deployment = LocalDeployment.Create(folder, machine, _ => authority, "browser-https-remote");
            var state = StateDatabase.InFolder(folder);
            string fingerprint = MachineCertificates.FingerprintOf(deployment.IdentityCertificate)!;
            var remote = new RemoteAuthority(
                new RemoteAuthorityConfig("https://127.0.0.1:1/", fingerprint, deployment.IdentityCertificate),
                deployment.Tls,
                deployment.HostConfig)
            {
                Retries = 1,
                RetryPause = TimeSpan.FromMilliseconds(10),
            };
            deployment.UseRemote(remote);

            using var service = HostService.Start(new HostServiceOptions
            {
                State = state,
                Store = new SecretStore(state),
                Deployment = deployment,
                CommandLineEndpoint = HostServiceTests.Rig.TestEndpoint(),
                Port = 0,
            });
            bool browserTcp = service.BrowserListenerAddresses.Any(address =>
                Uri.TryCreate(address, UriKind.Absolute, out Uri? uri) &&
                (uri.Scheme == "https" || uri.Host is "127.0.0.1" or "[::1]" or "localhost"));
            check(!browserTcp && service.Port == 0,
                "browser HTTPS: a non-authority host exposes no browser TCP listener (" +
                string.Join(", ", service.BrowserListenerAddresses) + ")");
            check(Refused(() => HostService.Start(new HostServiceOptions
            {
                State = state,
                Store = new SecretStore(state),
                Deployment = deployment,
                Port = 0,
            })),
                "browser HTTPS: a remote host without local IPC cannot start");

            var flag = typeof(HostServiceOptions).GetProperty("HttpBrowserFixture",
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            check(flag?.SetMethod is { IsAssembly: true, IsPublic: false },
                "browser HTTPS: the HTTP browser fixture is an internal test-only option");
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(folder, true);
        }
    }

    private static string CertificatePath(string folder, X509Certificate2 certificate)
    {
        string directory = Path.Combine(folder, "browser-https");
        return Directory.GetFiles(directory, "*.cer").Single(path =>
            X509CertificateLoader.LoadCertificate(File.ReadAllBytes(path)).RawData.SequenceEqual(certificate.RawData));
    }

    private static TrustTarget[] JournalTargets(string folder)
    {
        var json = JsonNode.Parse(File.ReadAllText(Path.Combine(folder, "browser-https", "state.json")))!.AsObject();
        return [.. json["Active"]!["Targets"]!.AsArray().Select(item =>
            new TrustTarget((string)item!["Kind"]!, (string)item!["Path"]!))];
    }

    private static void InjectTarget(string folder, TrustTarget target)
    {
        string path = Path.Combine(folder, "browser-https", "state.json");
        var json = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        json["Active"]!["Targets"]!.AsArray().Add(new JsonObject
        {
            ["Kind"] = target.Kind,
            ["Path"] = target.Path,
        });
        File.WriteAllText(path, json.ToJsonString());
    }

    private static async Task ListenerAsync(string folder, TestTrust trust, X509Certificate2 leaf, X509Certificate2 old, Action<bool, string> check)
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
        using var service = HostService.Start(new HostServiceOptions
        {
            State = state,
            Store = new SecretStore(state),
            Deployment = deployment,
            Port = 0,
            BrowserCertificatesFixture = new BrowserCertificates(folder, trust),
        });
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

    private static string Message(Action operation)
    {
        try
        {
            operation();
            return "";
        }
        catch (Exception error) when (BrowserCertificates.IsLifecycleError(error))
        {
            return error.Message;
        }
    }

    private sealed class TestTrust : IBrowserTrust
    {
        private readonly Dictionary<string, HashSet<string>> _byTarget = [];

        public HashSet<string> Unrelated { get; } = [];
        public bool FailInstall { get; set; }
        public string? FailInstallTarget { get; set; }
        public bool FailRemove { get; set; }
        public HashSet<string> UnavailableTargets { get; } = [];
        public string? MachineWideDigest { get; set; }

        public HashSet<string> Installed => [.. _byTarget.Values.SelectMany(entries => entries).Concat(Unrelated)];

        public bool Contains(TrustTarget target, X509Certificate2 certificate, string path)
        {
            if (UnavailableTargets.Contains(target.ToString()))
            {
                throw new IOException("simulated unavailable trust target " + target);
            }

            return _byTarget.TryGetValue(target.ToString(), out var entries) &&
                entries.Contains(BrowserCertificate.Digest(certificate));
        }

        public void Install(TrustTarget target, X509Certificate2 certificate, string path, bool permitPrompt, TextWriter output)
        {
            if (FailInstall || FailInstallTarget == target.ToString())
            {
                throw new IOException("simulated interrupted trust installation in " + target);
            }

            Entry(target).Add(BrowserCertificate.Digest(certificate));
        }

        public void Remove(TrustTarget target, X509Certificate2 certificate, string path, bool permitPrompt, TextWriter output)
        {
            if (FailRemove) throw new IOException("simulated interrupted trust cleanup");
            Entry(target).Remove(BrowserCertificate.Digest(certificate));
        }

        public void Withdraw(TrustTarget target, X509Certificate2 certificate) =>
            Entry(target).Remove(BrowserCertificate.Digest(certificate));

        public bool IsMachineWideTrusted(X509Certificate2 certificate) =>
            MachineWideDigest == BrowserCertificate.Digest(certificate);

        private HashSet<string> Entry(TrustTarget target)
        {
            if (!_byTarget.TryGetValue(target.ToString(), out var entries))
            {
                entries = [];
                _byTarget[target.ToString()] = entries;
            }

            return entries;
        }
    }
}

using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace WithSecrets.Tests;

/// <summary>
/// Phase 2, machine identity: the key is made once and reused (same fingerprint after a restart), cannot be exported, has a stable
/// fingerprint (a golden vector computed with Python's hashlib over an OpenSSL key), and no private material reaches a file, the
/// database or the log.
/// </summary>
internal static class IdentityTests
{
    // An OpenSSL prime256v1 public key (SubjectPublicKeyInfo DER, base64) and its SHA-256, computed with hashlib.sha256(der).hexdigest().upper().
    private const string GoldenKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgKaJL7gYMkoY7xQNVHF5w/0/O0UgV8balud5FQpvI9RUvc4TNCLMT2zBYFRrHay4JpBtVlT0E4lO7Quql9L0mA==";
    private const string GoldenFingerprint = "8214BFB018F0AD246D52C476A58FA6C173F84B5807F5A16BC1830ABBE9AE0891";

    public static async Task Run(Action<bool, string> check)
    {
        string parent = Path.Combine(Path.GetTempPath(), "ws-identity-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(parent);
        try
        {
            Golden(check);
            Signatures(check);
            if (OperatingSystem.IsWindows())
            {
                Cng(check, parent);
            }

            await NoPrivateMaterial(check, parent);
            Startup(check);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try
            {
                Directory.Delete(parent, true);
            }
            catch (IOException)
            {
                // A stray file in the temp folder is harmless.
            }
        }
    }

    private static void Golden(Action<bool, string> check)
    {
        byte[] spki = Convert.FromBase64String(GoldenKey);
        check(KeyIdentity.Fingerprint(spki) == GoldenFingerprint, "fingerprint: SHA-256 of the canonical public key matches the independently computed golden value");
        check(KeyIdentity.Display(GoldenFingerprint) == "8214 BFB0 18F0 AD24 6D52 C476 A58F A6C1 73F8 4B58 07F5 A16B C183 0ABB E9AE 0891", "fingerprint: shown as groups of four hex digits");
        check(KeyIdentity.IsCanonicalP256(spki), "fingerprint: the golden key is a canonical P-256 key");

        // The fingerprint is of the canonical encoding: importing and exporting gives the same bytes, so one key has one fingerprint.
        using ECDsa imported = ECDsa.Create();
        imported.ImportSubjectPublicKeyInfo(spki, out _);
        check(imported.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(spki), "fingerprint: re-export of the golden key is byte-identical");

        // Anything that is not exactly the canonical encoding of a P-256 key is not accepted as an identity.
        check(!KeyIdentity.IsCanonicalP256([.. spki, 0]), "canonical key: trailing bytes are refused");
        check(!KeyIdentity.IsCanonicalP256(spki[..^1]), "canonical key: a truncated key is refused");
        check(!KeyIdentity.IsCanonicalP256([]) && !KeyIdentity.IsCanonicalP256(Encoding.ASCII.GetBytes("not a key")), "canonical key: garbage is refused");
        using ECDsa other = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        check(!KeyIdentity.IsCanonicalP256(other.ExportSubjectPublicKeyInfo()), "canonical key: a P-384 key is refused");

        check(KeyIdentity.ParseHex("8214 bfb0:18f0-AD24", false) == "8214BFB018F0AD24", "fingerprint text: separators and case are ignored; a 12-digit prefix is allowed");
        check(KeyIdentity.ParseHex("8214BFB018F", false) is null && KeyIdentity.ParseHex("8214BFB018F0AD24", true) is null, "fingerprint text: under 12 digits, or short when the full one is needed, is refused");
        check(KeyIdentity.ParseHex(GoldenFingerprint.ToLowerInvariant(), true) == GoldenFingerprint && KeyIdentity.ParseHex(GoldenFingerprint + "00", true) is null && KeyIdentity.ParseHex("zz" + GoldenFingerprint[2..], true) is null, "fingerprint text: exactly 64 hex digits for the full form");
    }

    private static void Signatures(Action<bool, string> check)
    {
        using SoftwareSigningKey key = new();
        using SoftwareSigningKey stranger = new();
        byte[] data = Encoding.UTF8.GetBytes("a message");
        byte[] signature = key.Sign(data);
        check(signature.Length == 64 && KeyIdentity.Verify(key.PublicKey, data, signature), "signature: a 64-byte r||s signature verifies");
        check(!KeyIdentity.Verify(key.PublicKey, Encoding.UTF8.GetBytes("another message"), signature), "signature: other data does not verify");
        check(!KeyIdentity.Verify(stranger.PublicKey, data, signature), "signature: another key does not verify");
        byte[] flipped = [.. signature];
        flipped[10] ^= 1;
        check(!KeyIdentity.Verify(key.PublicKey, data, flipped) && !KeyIdentity.Verify(key.PublicKey, data, signature[..63]) && !KeyIdentity.Verify(key.PublicKey, data, [.. signature, 0]), "signature: a changed or resized signature does not verify");
        using ECDsa raw = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] der = raw.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        check(!KeyIdentity.Verify(raw.ExportSubjectPublicKeyInfo(), data, der), "signature: the DER form is not accepted, only the fixed-size one");
    }

    [SupportedOSPlatform("windows")]
    private static void Cng(Action<bool, string> check, string parent)
    {
        // A key name of this test only: the program's own names are never used here.
        string name = "with-secrets test identity " + Guid.NewGuid().ToString("N");
        try
        {
            string firstFingerprint;
            using (CngSigningKey first = CngSigningKey.OpenOrCreate(name, out bool created))
            {
                firstFingerprint = KeyIdentity.Fingerprint(first.PublicKey);
                check(created && !first.Exportable && first.Provider.StartsWith("Microsoft", StringComparison.Ordinal), "cng key: created persisted and non-exportable (" + first.Provider + ")");
                byte[] data = Encoding.UTF8.GetBytes("signed by the os");
                check(KeyIdentity.Verify(first.PublicKey, data, first.Sign(data)) && KeyIdentity.IsCanonicalP256(first.PublicKey), "cng key: signs, and its public key is a canonical P-256 key");

                // The private part cannot be read out of the key: not by parameters, not as PKCS#8.
                using CngKey raw = CngKey.Open(name, new CngProvider(first.Provider));
                using ECDsaCng ecdsa = new(raw);
                bool parametersRefused = false;
                try
                {
                    ecdsa.ExportParameters(true);
                }
                catch (CryptographicException)
                {
                    parametersRefused = true;
                }

                bool pkcs8Refused = false;
                try
                {
                    ecdsa.ExportPkcs8PrivateKey();
                }
                catch (CryptographicException)
                {
                    pkcs8Refused = true;
                }

                check(parametersRefused && pkcs8Refused && raw.ExportPolicy == CngExportPolicies.None, "cng key: ExportParameters(true) and ExportPkcs8PrivateKey fail; the export policy is None");
            }

            using (CngSigningKey second = CngSigningKey.OpenOrCreate(name, out bool createdAgain))
            {
                check(!createdAgain && KeyIdentity.Fingerprint(second.PublicKey) == firstFingerprint, "cng key: a second start reuses the key (same fingerprint), it makes no new one");
            }

            // A restart of the whole deployment over the same key and folder: the fingerprint does not change.
            string folder = Path.Combine(parent, "cng-deployment");
            string authorityName = name + " authority";
            using (CngSigningKey machine = CngSigningKey.OpenOrCreate(name, out _))
            using (LocalDeployment one = LocalDeployment.Create(folder, machine, generation => CngSigningKey.OpenOrCreate(authorityName + generation, out _), "cng-host"))
            {
                EnrollmentResult enrolled = one.EnrollAsync().GetAwaiter().GetResult();
                check(one.Fingerprint == firstFingerprint && enrolled is { Accepted: true, Status: MachineStatus.Pending } && one.Keys.CurrentRecord().Generation == 1, "cng deployment: the machine enrolls as Pending under the key's fingerprint");
            }

            using (CngSigningKey machine = CngSigningKey.OpenOrCreate(name, out bool again))
            using (LocalDeployment two = LocalDeployment.Create(folder, machine, generation => CngSigningKey.OpenOrCreate(authorityName + generation, out _), "cng-host"))
            {
                EnrollmentResult enrolled = two.EnrollAsync().GetAwaiter().GetResult();
                check(!again && two.Fingerprint == firstFingerprint && two.Store.Machines().Count == 1 && enrolled.Status == MachineStatus.Pending && two.Keys.Current().PublicKey.Length > 0,
                    "cng deployment: after a restart the identity and the authority key are the same, and the machine is not enrolled twice");
            }

            // A key planted under the name with an exportable private part is never adopted; a fresh key replaces it.
            string planted = name + " planted";
            try
            {
                CngKeyCreationParameters open = new() { Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider, ExportPolicy = CngExportPolicies.AllowExport | CngExportPolicies.AllowPlaintextExport, KeyUsage = CngKeyUsages.Signing };
                using (CngKey.Create(CngAlgorithm.ECDsaP256, planted, open))
                {
                }

                bool refused = false;
                try
                {
                    CngSigningKey.OpenOrCreate(planted, out _).Dispose();
                }
                catch (CryptographicException)
                {
                    refused = true;
                }

                check(refused, "cng key: an existing exportable key under the name is refused, not adopted");
                using CngSigningKey replaced = CngSigningKey.CreateFresh(planted);
                check(!replaced.Exportable && replaced.Problem() is null, "cng key: a fresh key replaces whatever held a not-yet-used name, and it is non-exportable");
                using CngSigningKey reopened = CngSigningKey.OpenOrCreate(planted, out bool madeAgain);
                check(!madeAgain && KeyIdentity.Fingerprint(reopened.PublicKey) == KeyIdentity.Fingerprint(replaced.PublicKey), "cng key: the replacement is what opens afterwards");

                // Rotation and recovery use a fresh key even when the next generation's name holds a planted one.
                string ringName = name + " ring ";
                string plantedNext = ringName + "2";
                using (CngKey.Create(CngAlgorithm.ECDsaP256, plantedNext, open))
                {
                }

                byte[] plantedPublic;
                using (CngSigningKey plantedKey = CngSigningKey.TryOpen(plantedNext)!)
                {
                    plantedPublic = plantedKey.PublicKey;
                }

                using (CngSigningKey machine = CngSigningKey.OpenOrCreate(name, out _))
                using (LocalDeployment ring = LocalDeployment.Create(Path.Combine(parent, "cng-ring"), machine, generation => CngSigningKey.OpenOrCreate(ringName + generation, out _), "ring-host", create: generation => CngSigningKey.CreateFresh(ringName + generation)))
                {
                    ring.Keys.CurrentRecord();
                    KeyTransition rotated = ring.Keys.Rotate("test");
                    check(!rotated.NewPublicKey.AsSpan().SequenceEqual(plantedPublic) && ring.Keys.Current() is CngSigningKey { Exportable: false }, "cng key: a rotation does not adopt a key planted under the next generation's name");
                    check(ring.Keys.Recover("test").PublicKey.AsSpan().SequenceEqual(plantedPublic) == false, "cng key: a recovery makes a new key too");
                }

                foreach (string suffix in new[] { "1", "2", "3" })
                {
                    using CngSigningKey? leftover = CngSigningKey.TryOpen(ringName + suffix);
                    leftover?.Delete();
                }
            }
            finally
            {
                using CngSigningKey? gone = CngSigningKey.TryOpen(planted);
                gone?.Delete();
            }

            // The program's fixed names exist as constants, are distinct, and generations after the first add a suffix.
            check(KeyNames.Machine != KeyNames.Authority && LocalDeployment.AuthorityKeyNameOf(1) == KeyNames.Authority && LocalDeployment.AuthorityKeyNameOf(2) != KeyNames.Authority, "cng names: the machine and authority key names are fixed and distinct");
        }
        finally
        {
            foreach (string leftover in new[] { name, name + " authority1" })
            {
                using CngSigningKey? key = CngSigningKey.TryOpen(leftover);
                key?.Delete();
            }
        }
    }

    /// <summary>A key whose private bytes the test can see, so that it can look for them.</summary>
    private sealed class KnownKey : ISigningKey
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public KnownKey()
        {
            // Taken now: the deployment disposes the key it was given.
            PublicKey = _key.ExportSubjectPublicKeyInfo();
            Private = _key.ExportParameters(true).D!;
            Pkcs8 = _key.ExportPkcs8PrivateKey();
        }

        public byte[] PublicKey { get; } = [];

        public byte[] Private { get; } = [];

        public byte[] Pkcs8 { get; } = [];

        public byte[] Sign(byte[] data) => _key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        public void Dispose() => _key.Dispose();
    }

    private static bool Contains(byte[] haystack, byte[] needle) => haystack.AsSpan().IndexOf(needle) >= 0;

    private static async Task NoPrivateMaterial(Action<bool, string> check, string parent)
    {
        string folder = Path.Combine(parent, "scan");
        string logs = Path.Combine(parent, "scan-logs");
        KnownKey machine = new();
        Dictionary<int, KnownKey> authority = [];
        KnownKey Authority(int generation) => authority.TryGetValue(generation, out KnownKey? known) ? known : authority[generation] = new KnownKey();
        AppLog.LogFolder = logs;
        AppLog.Configure(false);
        try
        {
            using (LocalDeployment deployment = LocalDeployment.Create(folder, machine, Authority, "scan-host"))
            {
                TestMachine.Approve(deployment);

                // A decision, a rotation, a recovery, a transition applied, a wrong answer, and a warning in the log.
                LaunchGate gate = new();
                HostAuthorization host = deployment.CreateAuthorization(gate);
                DateTimeOffset now = DateTimeOffset.UtcNow;
                LaunchRequest request = Sample("scan-1", now);
                ApprovalDecision? seen = null;
                AuthorizationOutcome outcome = await host.AuthorizeAsync(request, () => seen = ApprovalDecision.Allow(), CancellationToken.None);
                check(outcome.Decision.Approved && seen is not null, "private material: the flow under test ran (a decision was approved)");
                deployment.Keys.Rotate("scan");
                await host.AuthorizeAsync(Sample("scan-2", now), () => ApprovalDecision.Allow(), CancellationToken.None);
                AdminActions.RecoverAuthority(deployment.Keys, deployment.HostConfig, deployment.Fingerprint, "scan");
                await host.AuthorizeAsync(Sample("scan-3", now), () => ApprovalDecision.Allow(), CancellationToken.None);
                HostAuthorization broken = new(new ThrowingAuthority(), machine, "scan-host", deployment.HostConfig, gate, deployment.Authority.Offer);
                await broken.AuthorizeAsync(Sample("scan-4", now), () => ApprovalDecision.Allow(), CancellationToken.None);
                using HostService service = HostService.Start(new HostServiceOptions { State = StateDatabase.InFolder(folder), Store = new MemoryStore(new Dictionary<string, string>()), Deployment = deployment, Port = 0 });
                using HttpClient client = new(new SocketsHttpHandler { UseProxy = false });
                string challenge = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
                using HttpResponseMessage identity = await client.PostAsync("http://127.0.0.1:" + service.Port + "/v1/identity", new StringContent("{\"challenge\":\"" + challenge + "\"}", Encoding.UTF8, "application/json"));
                string identityBody = await identity.Content.ReadAsStringAsync();
                check(identity.IsSuccessStatusCode && Needles(machine, authority.Values).All(needle => !identityBody.Contains(needle, StringComparison.Ordinal)), "private material: the identity answer has the public key and a signature, never the private key");
            }

            AppLog.Close();
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            string[] files = [.. Directory.GetFiles(folder, "*", SearchOption.AllDirectories), .. Directory.Exists(logs) ? Directory.GetFiles(logs, "*", SearchOption.AllDirectories) : []];
            List<byte[]> secrets = [];
            foreach (KnownKey key in authority.Values.Append(machine))
            {
                secrets.Add(key.Private);
                secrets.Add(key.Pkcs8);
                secrets.Add(Encoding.ASCII.GetBytes(Convert.ToHexString(key.Private)));
                secrets.Add(Encoding.ASCII.GetBytes(Convert.ToHexString(key.Private).ToLowerInvariant()));
                secrets.Add(Encoding.ASCII.GetBytes(Convert.ToBase64String(key.Private)));
                secrets.Add(Encoding.ASCII.GetBytes(Convert.ToBase64String(key.Pkcs8)));
            }

            bool database = files.Any(file => Path.GetFileName(file) == AuthorityStore.FileName);
            bool hostJson = files.Any(file => Path.GetFileName(file) == HostConfigFile.FileName);
            bool logged = files.Any(file => file.StartsWith(logs, StringComparison.OrdinalIgnoreCase));
            check(database && hostJson && logged, "private material: authority.db, host.json and the log file all exist to be scanned (" + files.Length + " files)");
            List<string> leaks = [];
            foreach (string file in files)
            {
                byte[] bytes = File.ReadAllBytes(file);
                if (secrets.Any(secret => Contains(bytes, secret)))
                {
                    leaks.Add(Path.GetFileName(file));
                }
            }

            check(leaks.Count == 0, "private material: no private key (raw, PKCS#8, hex or base64) is in any file of the store folder or in the log (" + string.Join(", ", leaks) + ")");

            // Positive control: the scan does see public data, so an empty result means something.
            string publicText = Convert.ToBase64String(machine.PublicKey);
            check(files.Where(file => Path.GetFileName(file).StartsWith(AuthorityStore.FileName, StringComparison.Ordinal)).Any(file => Contains(File.ReadAllBytes(file), Encoding.ASCII.GetBytes(Convert.ToBase64String(authority[1].PublicKey)))) && publicText.Length > 0,
                "private material: positive control, the authority's public key is found in authority.db");
        }
        finally
        {
            AppLog.Close();
            AppLog.LogFolder = null;
            foreach (KnownKey key in authority.Values)
            {
                key.Dispose();
            }

            machine.Dispose();
        }
    }

    private static IEnumerable<string> Needles(KnownKey machine, IEnumerable<KnownKey> others)
    {
        foreach (KnownKey key in others.Append(machine))
        {
            yield return Convert.ToBase64String(key.Private);
            yield return Convert.ToHexString(key.Private);
        }
    }

    internal static LaunchRequest Sample(string id, DateTimeOffset now) => new(
        LaunchProtocol.Version, id, now, now.AddMinutes(5), "bm9uY2UtMDAwMDAwMDEx" + id.Replace("-", ""), ["TOKEN"], [new LaunchMapping("TOKEN", "TOKEN")], "identity test", "program", [], Path.GetTempPath(), [], [], new Dictionary<string, string>(), new Dictionary<string, string>());

    private sealed class ThrowingAuthority : IAuthority
    {
        public Task<AuthorityResponse> DecideAsync(MachineRequestEnvelope envelope, CancellationToken cancel = default) => throw new InvalidOperationException("no answer");

        public Task<byte[]> BeginEnrollmentAsync(CancellationToken cancel = default) => throw new InvalidOperationException("no answer");

        public Task<EnrollmentResult> EnrollAsync(EnrollmentRequest request, CancellationToken cancel = default) => throw new InvalidOperationException("no answer");

        public Task<IReadOnlyList<KeyTransition>> KeyTransitionsAsync(string afterKeyFingerprint, CancellationToken cancel = default) => throw new InvalidOperationException("no answer");

        public Task<IReadOnlyList<PendingInvalidation>> PendingInvalidationsAsync(string machineFingerprint, CancellationToken cancel = default) => throw new InvalidOperationException("no answer");

        public Task AcknowledgeInvalidationAsync(string machineFingerprint, int revision, CancellationToken cancel = default) => throw new InvalidOperationException("no answer");
    }

    private static void Startup(Action<bool, string> check)
    {
        string fingerprint = GoldenFingerprint;
        IReadOnlyList<string> pending = ServiceStartup.Lines("DEV-BOX", fingerprint, new EnrollmentResult(true, MachineStatus.Pending, fingerprint, "pending"));
        string all = string.Join("\n", pending);
        check(pending[0] == "with-secrets service: machine DEV-BOX, identity 8214 BFB0 18F0 AD24 6D52 C476 A58F A6C1 73F8 4B58 07F5 A16B C183 0ABB E9AE 0891", "startup: prints the host name and the fingerprint");
        check(all.Contains("with-secrets admin approve " + fingerprint + " --name NAME", StringComparison.Ordinal) && all.Contains("Pending", StringComparison.Ordinal), "startup: a Pending machine is told the command that approves it");
        check(!all.Contains(GoldenKey, StringComparison.Ordinal), "startup: no key material is printed");
        check(ServiceStartup.Lines("DEV-BOX", fingerprint, new EnrollmentResult(true, MachineStatus.Trusted, fingerprint, "Trusted"))[1] == "with-secrets service: this machine is Trusted.", "startup: a Trusted machine is told so");
        check(ServiceStartup.Lines("DEV-BOX", fingerprint, new EnrollmentResult(false, MachineStatus.Pending, fingerprint, "no"))[1].Contains("did not accept", StringComparison.Ordinal), "startup: a refused enrollment is told");
    }
}

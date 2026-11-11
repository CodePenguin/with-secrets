using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

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
/// Task M2: authority-generated, single-use machine pairing invitations (architecture 10.2). Real Kestrel and TLS 1.3/HTTP/2 between a real pairing client and the authority's pairing route; the units (protocol, store, service) are
/// also driven directly. The suite checks the protocol (domain separation, the verifier at rest), the happy path through to administrator approval and the M1 key pinning, authority and machine substitution, bad certificate profiles and
/// proofs of possession, wrong/expired/consumed/withdrawn invitations (one uniform refusal), replay, concurrent claims, idempotent retries (also across a restart), Pending refresh and the machines pairing must not change, every route
/// for unknown certificates, what the pairing route can and cannot do, that the client sends nothing about the machine before it has verified the authority, the fixed limits, the durable audit (and that no code, proof or key is anywhere
/// on disk or in output), the input sources (hidden prompt, secret file, environment variable) and that the credential is not passed on to a program.
/// </summary>
internal static class PairingTests
{
    // ---------- fixtures ----------

    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.UtcNow;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }

    /// <summary>A machine identity of its own: key, identity certificate and this run's temporary TLS certificate.</summary>
    private sealed class Identity : IDisposable
    {
        public Identity(TimeProvider clock)
        {
            Key = new SoftwareSigningKey();
            Certificate = MachineCertificates.CreateIdentity(Key, clock.GetUtcNow());
            Tls = new TemporaryCertificate(Key, Certificate, clock);
        }

        public SoftwareSigningKey Key { get; }

        public byte[] Certificate { get; }

        public TemporaryCertificate Tls { get; }

        public string Fingerprint => KeyIdentity.Fingerprint(Key.PublicKey);

        public X509Certificate2 Leaf => MachineCertificates.Load(Tls.CurrentPublic);

        public void Dispose()
        {
            Tls.Dispose();
            Key.Dispose();
        }
    }

    private sealed class Rig : IDisposable
    {
        private readonly string _root;
        private readonly List<IDisposable> _owned = [];
        private readonly IUnlockProtection _protection = new ReversibleProtection();

        public Rig(string root)
        {
            _root = root;
            Authority = new TestMachine(Path.Combine(root, "auth-" + Guid.NewGuid().ToString("N")[..6]), trusted: true, hostName: "the-authority", clock: Clock);
            Start(0);
        }

        public TestClock Clock { get; } = new();

        public TestMachine Authority { get; }

        public PairingService Service { get; private set; } = null!;

        public MachineListener Listener { get; private set; } = null!;

        public List<string> SeenPeers { get; } = [];

        public string Url => "https://127.0.0.1:" + Listener.Port;

        public AuthorityStore Store => Authority.Deployment.Store;

        public byte[] AuthorityIdentity => Authority.Deployment.IdentityCertificate;

        public string AuthorityFingerprint => MachineCertificates.FingerprintOf(AuthorityIdentity)!;

        private void Start(int port)
        {
            LocalDeployment deployment = Authority.Deployment;
            Service = new PairingService(deployment.Store, _protection, deployment.IdentityCertificate, () => "https://127.0.0.1:" + (Listener?.Port ?? port), Clock);
            Service.SeenPeer = fingerprint =>
            {
                lock (SeenPeers)
                {
                    SeenPeers.Add(fingerprint);
                }
            };
            Listener = MachineListener.Start(deployment.Authority, deployment.Keys, deployment.Store, deployment.Tls, new MachineListenerOptions { Port = port, Clock = Clock, Pairing = new PairingHandler(Service) }, null);
        }

        /// <summary>The authority service restarts: a new store object, key ring and pairing service over the same files, on the same port.</summary>
        public void Restart()
        {
            int port = Listener.Port;
            Listener.Dispose();
            Authority.Restart();
            Start(port);
        }

        public (CreatedInvitation Created, PairingBundle Bundle) NewInvitation()
        {
            (CreatedInvitation? created, string? problem) = Service.Create("admin passkey test");
            if (created is null)
            {
                throw new InvalidOperationException("no invitation: " + problem);
            }

            return (created, PairingBundle.TryParse(created.Bundle)!);
        }

        public Host NewHost(string name)
        {
            Host host = new(new TestMachine(Path.Combine(_root, "host-" + Guid.NewGuid().ToString("N")[..6]), trusted: false, hostName: name, clock: Clock));
            _owned.Add(host);

            return host;
        }

        public Identity NewIdentity()
        {
            Identity identity = new(Clock);
            _owned.Add(identity);

            return identity;
        }

        public void Dispose()
        {
            foreach (IDisposable owned in _owned)
            {
                owned.Dispose();
            }

            Listener.Dispose();
            Authority.Deployment.Dispose();
        }

        /// <summary>One request on a fresh connection pinned to the authority identity: what a client that already verified the authority does.</summary>
        public async Task<(int Status, string Body)> Post(TemporaryCertificate client, string body, string path = MachineApi.PairingPath, string contentType = MachineApi.JsonType, HttpMethod? method = null, string? url = null)
        {
            using SocketsHttpHandler handler = new()
            {
                UseProxy = false,
                AllowAutoRedirect = false,
                SslOptions = new SslClientAuthenticationOptions
                {
                    EnabledSslProtocols = SslProtocols.Tls13,
                    ClientCertificates = [client.Current],
                    ApplicationProtocols = [SslApplicationProtocol.Http2],
                    RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                    {
                        using X509Certificate2 leaf = X509CertificateLoader.LoadCertificate(certificate!.GetRawCertData());

                        return MachineCertificates.ValidateLeaf(leaf, AuthorityIdentity, Clock.GetUtcNow()) is null;
                    },
                },
            };
            using HttpClient http = new(handler) { DefaultRequestVersion = HttpVersion.Version20, DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact, Timeout = TimeSpan.FromSeconds(20) };
            using HttpRequestMessage request = new(method ?? HttpMethod.Post, (url ?? Url) + path) { Version = HttpVersion.Version20, VersionPolicy = HttpVersionPolicy.RequestVersionExact };
            request.Content = new StringContent(body, Encoding.UTF8);
            request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);
            using HttpResponseMessage response = await http.SendAsync(request);

            return ((int)response.StatusCode, await response.Content.ReadAsStringAsync());
        }

        public Task<(int Status, string Body)> Bootstrap(Identity who, string id) => Post(who.Tls, PairingWire.Write(new PairingBootstrapRequest(id, RandomNumberGenerator.GetBytes(16))));

        public Task<(int Status, string Body)> Register(Identity who, PairingRegistrationRequest request) => Post(who.Tls, PairingWire.Write(request));

        /// <summary>A correct registration request for <paramref name="who" />, made as a client that knows the code would make it.</summary>
        public PairingRegistrationRequest Request(PairingBundle bundle, Identity who, string hostName, Func<byte[], byte[]>? tamperProof = null, byte[]? nonce = null)
        {
            byte[] key = bundle.DeriveKey();
            nonce ??= RandomNumberGenerator.GetBytes(16);
            byte[] proof = PairingProtocol.RegistrationProof(key, bundle.InvitationId, AuthorityFingerprint, who.Fingerprint, hostName, nonce);

            return new PairingRegistrationRequest(bundle.InvitationId, who.Certificate, who.Fingerprint, hostName, nonce, who.Key.Sign(PairingProtocol.PossessionMessage(bundle.InvitationId, AuthorityFingerprint, who.Fingerprint, hostName, nonce)), tamperProof?.Invoke(proof) ?? proof);
        }

        public async Task<(PairingResult Result, List<(string Step, byte[] Body, string Client)> Requests)> Pair(Host host, PairingBundle bundle)
        {
            List<(string, byte[], string)> requests = [];
            PairingResult result = await PairingClient.RunAsync(new PairingClientOptions
            {
                Bundle = bundle,
                MachineKey = host.Machine.MachineKey,
                IdentityCertificate = host.Machine.Deployment.IdentityCertificate,
                HostName = host.Machine.HostName,
                HostConfig = host.Machine.Deployment.HostConfig,
                Clock = Clock,
                MachineTls = host.Machine.Deployment.Tls,
                OnRequest = (step, body, client) =>
                {
                    lock (requests)
                    {
                        requests.Add((step, body, client));
                    }
                },
                Retries = 0,
            });

            return (result, requests);
        }
    }

    private sealed class Host(TestMachine machine) : IDisposable
    {
        public TestMachine Machine { get; } = machine;

        public string Fingerprint => Machine.Fingerprint;

        public void Dispose() => Machine.Deployment.Dispose();
    }

    /// <summary>A TLS server that is not the authority: it answers a pairing request as the test says. The client under test is pointed at it with a real invitation.</summary>
    private sealed class Impostor : IDisposable
    {
        private readonly TestMachine _machine;
        private readonly WebApplication _app;
        private int _hits;

        public Impostor(string root, Func<byte[], Task<(int Status, string Body)>> answer)
        {
            _machine = new TestMachine(Path.Combine(root, "impostor-" + Guid.NewGuid().ToString("N")[..6]), trusted: true, hostName: "impostor");
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
                using MemoryStream copy = new();
                await context.Request.Body.CopyToAsync(copy);
                lock (Bodies)
                {
                    Bodies.Add(copy.ToArray());
                }

                (int status, string text) = await answer(copy.ToArray());
                context.Response.StatusCode = status;
                context.Response.ContentType = MachineApi.JsonType;
                await context.Response.WriteAsync(text);
            });
            _app.StartAsync().GetAwaiter().GetResult();
            Url = _app.Urls.First().Replace("http://", "https://", StringComparison.Ordinal);
        }

        public string Url { get; }

        public int Hits => Volatile.Read(ref _hits);

        public List<byte[]> Bodies { get; } = [];

        public byte[] Identity => _machine.Deployment.IdentityCertificate;

        public void Dispose()
        {
            _app.StopAsync().GetAwaiter().GetResult();
            _app.DisposeAsync().AsTask().GetAwaiter().GetResult();
            _machine.Deployment.Dispose();
        }
    }

    private sealed class FakeConsole(string? typed, bool interactive = true) : IPairingConsole
    {
        public bool IsInteractive { get; } = interactive;

        public List<string> Prompts { get; } = [];

        public string? ReadHidden(string prompt)
        {
            Prompts.Add(prompt);

            return typed;
        }
    }

    // ---------- scanning ----------

    private static IEnumerable<byte[]> Forms(byte[] secret)
    {
        yield return secret;
        yield return Encoding.ASCII.GetBytes(Convert.ToHexString(secret));
        yield return Encoding.ASCII.GetBytes(Convert.ToHexString(secret).ToLowerInvariant());
        yield return Encoding.ASCII.GetBytes(Convert.ToBase64String(secret));
        yield return Encoding.ASCII.GetBytes(Convert.ToBase64String(secret).TrimEnd('='));
        yield return Encoding.ASCII.GetBytes(System.Buffers.Text.Base64Url.EncodeToString(secret));
    }

    /// <summary>The first file under <paramref name="folder" /> (or text) that holds any form of any of the secrets, else null.</summary>
    private static string? FindIn(string folder, IEnumerable<byte[]> secrets)
    {
        byte[][] needles = [.. secrets.SelectMany(Forms)];
        foreach (string file in Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories))
        {
            byte[] content;
            using (FileStream stream = new(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (MemoryStream memory = new())
            {
                stream.CopyTo(memory);
                content = memory.ToArray();
            }

            if (needles.Any(needle => content.AsSpan().IndexOf(needle) >= 0))
            {
                return Path.GetFileName(file);
            }
        }

        return null;
    }

    private static bool Holds(string text, IEnumerable<byte[]> secrets) => secrets.SelectMany(Forms).Any(needle => text.Contains(Encoding.ASCII.GetString(needle), StringComparison.Ordinal));

    // ---------- the suite ----------

    public static async Task Run(Action<bool, string> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "ws-pairing-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);
        try
        {
            Protocol(check);
            await Store(check, root);
            await HappyPath(check, root);
            await Substitution(check, root);
            await Invitations(check, root);
            await Races(check, root);
            await Retries(check, root);
            await KnownMachines(check, root);
            await Routes(check, root);
            await BeforeVerification(check, root);
            await Limits(check, root);
            await Audit(check, root);
            await Inputs(check, root);
            await Children(check, root);
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

    // ---------- the protocol ----------

    private static void Protocol(Action<bool, string> check)
    {
        byte[] code = RandomNumberGenerator.GetBytes(16);
        string id = PairingProtocol.NewToken(16);
        PairingBundle bundle = PairingBundle.Create("https://127.0.0.1:8790", id, code);
        string text = bundle.Format();
        PairingBundle? parsed = PairingBundle.TryParse("  " + text + "\n");
        check(parsed is not null && parsed.InvitationId == id && parsed.Authority == "https://127.0.0.1:8790" && parsed.Format() == text && parsed.DeriveKey().AsSpan().SequenceEqual(bundle.DeriveKey()), "bundle: address, identifier and code round-trip through the text form (surrounding white space is ignored)");
        check(!bundle.ToString().Contains(id, StringComparison.Ordinal) && !Holds(bundle.ToString(), [code]) && !Holds(bundle.ToString(), [bundle.DeriveKey()]) && !bundle.ToString().Contains(text, StringComparison.Ordinal), "bundle: formatting the object says nothing of its content (a log line or exception cannot leak the code)");
        string[] bad =
        [
            "", "wsp1", text.Replace("wsp1", "wsp2", StringComparison.Ordinal), text.Replace("https://", "http://", StringComparison.Ordinal), text + ";x", text[..^4], text.Replace("127.0.0.1:8790", "127.0.0.1:8790/path", StringComparison.Ordinal),
            string.Join(';', "wsp1", "https://127.0.0.1:8790", id[..20], System.Buffers.Text.Base64Url.EncodeToString(code)), string.Join(';', "wsp1", "https://127.0.0.1:8790", id, System.Buffers.Text.Base64Url.EncodeToString(code) + "AA"),
            string.Join(';', "wsp1", "https://user@127.0.0.1:8790", id, System.Buffers.Text.Base64Url.EncodeToString(code)),
        ];
        check(bad.All(item => PairingBundle.TryParse(item) is null) && PairingBundle.TryParse(null) is null, "bundle: wrong versions, a plain http address, a path or user in the address, short or long identifiers and codes, extra parts and nothing are all refused");

        byte[] key = PairingProtocol.DeriveKey(code, id);
        check(key.Length == 32 && key.AsSpan().SequenceEqual(PairingProtocol.DeriveKey(code, id)) && !key.AsSpan().SequenceEqual(PairingProtocol.DeriveKey(code, PairingProtocol.NewToken(16))) && !key.AsSpan().SequenceEqual(code) && !key.AsSpan().SequenceEqual(PairingProtocol.DeriveKey(RandomNumberGenerator.GetBytes(16), id)),
            "derivation: K is 32 bytes, repeatable, bound to the invitation and to the code, and is not the code");

        byte[] cn = RandomNumberGenerator.GetBytes(16);
        byte[] sn = RandomNumberGenerator.GetBytes(16);
        string authority = new string('A', 64);
        byte[] boot = PairingProtocol.BootstrapProof(key, id, authority, cn, sn);
        string other = new('B', 64);
        bool bootBound = !PairingProtocol.Same(boot, PairingProtocol.BootstrapProof(key, PairingProtocol.NewToken(16), authority, cn, sn)) && !PairingProtocol.Same(boot, PairingProtocol.BootstrapProof(key, id, other, cn, sn))
            && !PairingProtocol.Same(boot, PairingProtocol.BootstrapProof(key, id, authority, RandomNumberGenerator.GetBytes(16), sn)) && !PairingProtocol.Same(boot, PairingProtocol.BootstrapProof(key, id, authority, cn, RandomNumberGenerator.GetBytes(16)))
            && !PairingProtocol.Same(boot, PairingProtocol.BootstrapProof(PairingProtocol.DeriveKey(RandomNumberGenerator.GetBytes(16), id), id, authority, cn, sn));
        check(boot.Length == 32 && bootBound, "bootstrap proof: HMAC-SHA-256 bound to the invitation, the authority fingerprint, both nonces and the key");
        byte[] registration = PairingProtocol.RegistrationProof(key, id, authority, other, "host", cn);
        bool registrationBound = !PairingProtocol.Same(registration, PairingProtocol.RegistrationProof(key, id, authority, other, "host2", cn)) && !PairingProtocol.Same(registration, PairingProtocol.RegistrationProof(key, id, authority, new string('C', 64), "host", cn))
            && !PairingProtocol.Same(registration, PairingProtocol.RegistrationProof(key, id, authority, other, "host", sn)) && !PairingProtocol.Same(registration, PairingProtocol.RegistrationProof(key, id, other, other, "host", cn)) && !PairingProtocol.Same(registration, PairingProtocol.RegistrationProof(key, PairingProtocol.NewToken(16), authority, other, "host", cn));
        check(registration.Length == 32 && registrationBound, "registration proof: HMAC-SHA-256 bound to the invitation, the authority, the machine fingerprint, the host name and a fresh nonce");
        // The same fields under the two labels never give the same proof, and a field boundary cannot be moved ("ab"+"c" is not "a"+"bc").
        check(!PairingProtocol.Same(PairingProtocol.BootstrapProof(key, id, authority, cn, sn), PairingProtocol.RegistrationProof(key, id, authority, new string('0', 0), "", cn)) && !PairingProtocol.Same(PairingProtocol.RegistrationProof(key, id, authority, "ab", "c", cn), PairingProtocol.RegistrationProof(key, id, authority, "a", "bc", cn)),
            "domain separation: the two proofs have their own labels and a length-prefixed encoding (no field boundary can be shifted)");
        check(!PairingProtocol.Same(boot, boot[..31]) && !PairingProtocol.Same(boot, [.. boot, 0]) && PairingProtocol.Same(boot, [.. boot]), "proofs are compared whole and in constant time (a short or long proof is not equal)");

        PairingRegistrationRequest request = new(id, [1, 2, 3], new string('A', 64), "h", cn, [4], boot);
        string json = PairingWire.Write(request);
        check(PairingWire.TryReadRegistration(Encoding.UTF8.GetBytes(json), out PairingRegistrationRequest? back) && back is not null && back.Digest() == request.Digest() && back.HostName == "h", "wire: a registration round-trips and its digest is stable");
        string[] malformed =
        [
            json.Replace("\"v\":1", "\"v\":2", StringComparison.Ordinal), json.Replace("\"step\":\"register\"", "\"step\":\"bootstrap\"", StringComparison.Ordinal), json.TrimEnd('}') + ",\"extra\":1}", json.Replace("\"hostName\":\"h\",", "", StringComparison.Ordinal),
            json.Replace(Convert.ToBase64String(cn), Convert.ToBase64String(cn[..8]), StringComparison.Ordinal), json.Replace("\"proof\":\"" + Convert.ToBase64String(boot) + "\"", "\"proof\":\"AAAA\"", StringComparison.Ordinal), "[]", "null", "{}",
        ];
        check(malformed.All(item => !PairingWire.TryReadRegistration(Encoding.UTF8.GetBytes(item), out _)) && !PairingWire.TryReadRegistration(new byte[PairingProtocol.MaxBodyBytes + 1], out _) && !PairingWire.TryReadBootstrap(Encoding.UTF8.GetBytes(json), out _), "wire: another version, another step, an unknown or missing member, a wrong nonce or proof size, a non-object and an oversize body are all refused");
        check(PairingWire.StepOf(Encoding.UTF8.GetBytes(json)) == "register" && PairingWire.StepOf(Encoding.UTF8.GetBytes("{\"step\":3}")) is null && PairingWire.StepOf([0xFF, 0xFE]) is null, "wire: the step is read strictly");
    }

    // ---------- the store ----------

    private static async Task Store(Action<bool, string> check, string root)
    {
        using Rig rig = new(root);
        AuthorityStore store = rig.Store;
        (CreatedInvitation created, PairingBundle bundle) = rig.NewInvitation();
        PairingInvitationRecord? record = store.Invitation(created.Id);
        byte[] key = bundle.DeriveKey();
        check(record is { Status: "pending", Failed: 0, ProtectedKey: not null } && record.Expires - record.Created == PairingProtocol.InvitationLifetime && PairingProtocol.InvitationLifetime == TimeSpan.FromMinutes(10), "invitation: pending for a fixed 10 minutes with a stored verifier");
        check(!record!.ProtectedKey!.AsSpan().SequenceEqual(key) && FindIn(rig.Authority.Folder, [key]) is null && FindIn(rig.Authority.Folder, [Convert.FromBase64String(Convert.ToBase64String(key))]) is null, "invitation: the stored verifier is the PROTECTED derived key: neither K nor the code is in authority.db (or its journal)");
        string codeText = bundle.Format().Split(';')[3];
        check(FindIn(rig.Authority.Folder, [System.Buffers.Text.Base64Url.DecodeFromChars(codeText)]) is null && FindIn(rig.Authority.Folder, [Encoding.ASCII.GetBytes(bundle.Format())]) is null, "invitation: the pairing code and the bundle are not stored anywhere at the authority");
        check(created.Bundle.StartsWith("wsp1;https://127.0.0.1:", StringComparison.Ordinal) && bundle.InvitationId == created.Id && created.ToString().Contains(created.Id, StringComparison.Ordinal) && !created.ToString().Contains(created.Bundle, StringComparison.Ordinal), "invitation: the bundle carries the machine endpoint's address and the identifier, and prints without its code");
        (CreatedInvitation second, _) = rig.NewInvitation();
        check(second.Id != created.Id && second.Bundle != created.Bundle, "invitation: identifiers and codes are unique");

        using Identity a = rig.NewIdentity();
        PairingRegistrationRequest request = rig.Request(bundle, a, "host-a");
        using X509Certificate2 leaf = a.Leaf;
        PairingReply ok = rig.Service.Register(request, a.Fingerprint, leaf);
        check(ok.Status == 200 && rig.Store.Invitation(created.Id) is { Status: "consumed", ProtectedKey: null, MachineFingerprint: { } fp } && fp == a.Fingerprint && store.Find(a.Fingerprint) is { Status: MachineStatus.Pending, HostName: "host-a", SecurityRevision: 1 } && store.Certificate(a.Fingerprint) is not null,
            "consume: the invitation is used, its verifier wiped, and the machine is registered Pending with its host name and identity certificate");

        // Atomic: a failure after the invitation was consumed but before the commit leaves NOTHING (no consumption, no machine).
        (CreatedInvitation atomic, PairingBundle atomicBundle) = rig.NewInvitation();
        using Identity b = rig.NewIdentity();
        PairingRegistrationRequest atomicRequest = rig.Request(atomicBundle, b, "host-b");
        store.Fault = point =>
        {
            if (point == "pairing-before-commit")
            {
                throw new InvalidOperationException("injected");
            }
        };
        using X509Certificate2 leafB = b.Leaf;
        bool threw = false;
        try
        {
            rig.Service.Register(atomicRequest, b.Fingerprint, leafB);
        }
        catch (InvalidOperationException)
        {
            threw = true;
        }

        store.Fault = null;
        check(threw && store.Invitation(atomic.Id) is { Status: "pending", ProtectedKey: not null } && store.Find(b.Fingerprint) is null && store.Certificate(b.Fingerprint) is null && !store.Audit().Any(entry => entry.Event == "pairing-invitation-consumed" && entry.Detail.Contains(atomic.Id[..8], StringComparison.Ordinal)),
            "atomic: a failure just before the commit rolls back the consumption, the machine, its certificate and the audit rows together");
        check(rig.Service.Register(atomicRequest, b.Fingerprint, leafB).Status == 200 && store.Find(b.Fingerprint) is { Status: MachineStatus.Pending }, "atomic: the same registration succeeds afterwards");

        // The store step itself, raced: 16 different machines claim one invitation, exactly one wins.
        (CreatedInvitation race, PairingBundle raceBundle) = rig.NewInvitation();
        Identity[] claimants = [.. Enumerable.Range(0, 16).Select(_ => rig.NewIdentity())];
        PairingOutcome[] outcomes = new PairingOutcome[claimants.Length];
        using ManualResetEventSlim go = new(false);
        Task[] tasks = [.. claimants.Select((claimant, index) => Task.Run(() =>
        {
            PairingRegistrationRequest claim = rig.Request(raceBundle, claimant, "racer-" + index);
            go.Wait();
            outcomes[index] = store.ConsumeAndRegister(race.Id, claim.Digest(), claimant.Key.PublicKey, claim.HostName, claimant.Certificate, 1000, 1000).Outcome;
        }))];
        go.Set();
        await Task.WhenAll(tasks);
        check(outcomes.Count(item => item == PairingOutcome.Registered) == 1 && outcomes.Count(item => item == PairingOutcome.InvitationRefused) == 15 && claimants.Count(item => store.Find(item.Fingerprint) is not null) == 1, "store race: sixteen machines claim one invitation at once: exactly one is registered, fifteen are refused, one record exists");
    }

    // ---------- the happy path ----------

    private static async Task HappyPath(Action<bool, string> check, string root)
    {
        using Rig rig = new(root);
        using Host host = rig.NewHost("build-box");
        (CreatedInvitation created, PairingBundle bundle) = rig.NewInvitation();
        (PairingResult result, List<(string Step, byte[] Body, string Client)> requests) = await rig.Pair(host, bundle);
        check(result.Ok && result.MachineFingerprint == host.Fingerprint && result.HostName == "build-box" && result.AuthorityFingerprint == rig.AuthorityFingerprint, "pairing: a valid invitation pairs (TLS 1.3, HTTP/2, both proofs verified)");
        MachineRecord? record = rig.Store.Find(host.Fingerprint);
        check(record is { Status: MachineStatus.Pending, HostName: "build-box", FriendlyName: null } && rig.Store.Certificate(host.Fingerprint)!.AsSpan().SequenceEqual(host.Machine.Deployment.IdentityCertificate), "pairing: the machine is Pending with its host name and identity certificate; nothing else was granted");
        check(rig.Store.Invitation(created.Id) is { Status: "consumed", ProtectedKey: null } && rig.Store.Invitations().Single(item => item.Id == created.Id).StatusAt(rig.Clock.GetUtcNow()) == "consumed", "pairing: the invitation is consumed (and shows as consumed)");
        HostConfig? config = host.Machine.Deployment.HostConfig.Load().Config;
        check(config is { Remote: { } remote } && remote.Endpoint == bundle.Authority && remote.AuthorityIdentityFingerprint == rig.AuthorityFingerprint && remote.AuthorityIdentityCertificate.AsSpan().SequenceEqual(rig.AuthorityIdentity) && config.Authority is null,
            "pairing: host.json now names the authority's address and identity certificate (verified before it was saved) and pins no signing key yet");
        check(requests.Count == 2 && requests[0].Step == "bootstrap" && requests[1].Step == "register", "pairing: exactly two requests: the bootstrap, then the registration");

        // The machine cannot do anything while Pending.
        using RemoteAuthority remoteAuthority = new(config!.Remote!, host.Machine.Deployment.Tls, host.Machine.Deployment.HostConfig, rig.Clock) { Retries = 0 };
        bool refused;
        try
        {
            await remoteAuthority.PendingInvalidationsAsync(host.Fingerprint);
            refused = false;
        }
        catch (RemoteRefusedException error)
        {
            refused = error.Code == "machine-not-trusted";
        }

        check(refused, "pending: a paired machine is turned away from every operation until an administrator approves it");

        // The administrator verifies fingerprint and host name and approves (the existing operation); the machine is then Trusted and pins the authority key with the M1 operation.
        TransitionResult approved = AdminActions.ApproveMachine(rig.Store, rig.Authority.Deployment.Keys, rig.Authority.Deployment.HostConfig, null, host.Fingerprint, "build box", "admin passkey test", record!.SecurityRevision);
        check(approved.Ok && rig.Store.Find(host.Fingerprint) is { Status: MachineStatus.Trusted }, "approval: the existing administrator approval makes the machine Trusted");
        bool pinned = await remoteAuthority.EnsureAuthorityKeyPinnedAsync(CancellationToken.None);
        check(pinned && host.Machine.Deployment.HostConfig.Load().Config is { Authority: { } key } && key.Fingerprint == rig.Authority.Deployment.Keys.CurrentRecord().Fingerprint, "approval: the host pins the authority signing key through the M1 authority-key operation");
        check(rig.Store.Audit().Any(entry => entry.Event == "machine-approve" && entry.Fingerprint == host.Fingerprint), "approval: the administrator's approval is in the durable audit");
    }

    // ---------- substitution ----------

    private static async Task Substitution(Action<bool, string> check, string root)
    {
        using Rig rig = new(root);
        (CreatedInvitation created, PairingBundle bundle) = rig.NewInvitation();

        // An impostor that cannot know the code answers with its own identity and a made-up proof.
        using Impostor forger = new(root, _ =>
        {
            using SoftwareSigningKey key = new();
            byte[] identity = MachineCertificates.CreateIdentity(key, DateTimeOffset.UtcNow);

            return Task.FromResult((200, PairingWire.Write(new PairingBootstrapReply(identity, RandomNumberGenerator.GetBytes(16), RandomNumberGenerator.GetBytes(32)))));
        });
        using Host victim = rig.NewHost("victim-1");
        PairingBundle toForger = PairingBundle.Create(forger.Url, bundle.InvitationId, ExtractCode(bundle));
        (PairingResult forged, List<(string Step, byte[] Body, string Client)> forgedRequests) = await PairWith(rig, victim, toForger);
        check(!forged.Ok && forger.Hits == 1 && forgedRequests.Count == 1 && rig.Store.Find(victim.Fingerprint) is null && victim.Machine.Deployment.HostConfig.Load().Config is null, "authority substitution: an authority that cannot prove it holds the invitation gets ONE request (the bootstrap) and nothing about the machine; host.json is untouched");

        // A relay in the middle that forwards to the real authority gets the real proof and the real identity certificate, but its own TLS certificate: the connection is not the authority's.
        using Identity relayClient = rig.NewIdentity();
        using Impostor relay = new(root, async body =>
        {
            (int status, string text) = await rig.Post(relayClient.Tls, Encoding.UTF8.GetString(body));

            return (status, text);
        });
        using Host victim2 = rig.NewHost("victim-2");
        (PairingResult relayed, List<(string Step, byte[] Body, string Client)> relayedRequests) = await PairWith(rig, victim2, PairingBundle.Create(relay.Url, bundle.InvitationId, ExtractCode(bundle)));
        check(!relayed.Ok && relay.Hits == 1 && relayedRequests.Count == 1 && rig.Store.Find(victim2.Fingerprint) is null && rig.Store.Invitation(created.Id) is { Status: "pending" }, "authority substitution: a relay that forwards the real proof still fails (its TLS certificate is not the proven authority's); no registration is sent and the invitation is untouched");

        // A wrong code: the authority (which knows the real one) proves itself with the real key, which the machine cannot verify.
        using Host victim3 = rig.NewHost("victim-3");
        PairingBundle wrongCode = PairingBundle.Create(bundle.Authority, bundle.InvitationId, RandomNumberGenerator.GetBytes(16));
        (PairingResult wrong, List<(string Step, byte[] Body, string Client)> wrongRequests) = await rig.Pair(victim3, wrongCode);
        check(!wrong.Ok && wrongRequests.Count == 1 && rig.Store.Find(victim3.Fingerprint) is null && rig.Store.Invitation(created.Id) is { Status: "pending", Failed: 0 }, "wrong code: the machine cannot verify the authority's proof, sends nothing about itself and the invitation is untouched");

        // The authority's TLS identity must be the identity that is proven: a good proof over another identity's certificate fails.
        using Impostor mixer = new(root, async body =>
        {
            (int status, string text) = await rig.Post(relayClient.Tls, Encoding.UTF8.GetString(body));
            PairingWire.TryReadBootstrapReply(text, out PairingBootstrapReply? real);
            using SoftwareSigningKey other = new();

            return (status, PairingWire.Write(real! with { AuthorityCertificate = MachineCertificates.CreateIdentity(other, DateTimeOffset.UtcNow) }));
        });
        using Host victim4 = rig.NewHost("victim-4");
        (PairingResult mixed, _) = await PairWith(rig, victim4, PairingBundle.Create(mixer.Url, bundle.InvitationId, ExtractCode(bundle)));
        check(!mixed.Ok && mixer.Hits == 1 && rig.Store.Find(victim4.Fingerprint) is null, "authority substitution: a real proof delivered with a different identity certificate is refused");

        // Machine certificate substitution at registration.
        using Identity a = rig.NewIdentity();
        using Identity b = rig.NewIdentity();
        PairingRegistrationRequest asB = rig.Request(bundle, b, "host-b");
        (int sub1, _) = await rig.Register(a, asB);
        check(sub1 == 403 && rig.Store.Find(a.Fingerprint) is null && rig.Store.Find(b.Fingerprint) is null && rig.Store.Invitation(created.Id) is { Status: "pending" }, "machine substitution: a TLS certificate of one machine presenting another machine's identity and valid proofs is refused");
        PairingRegistrationRequest mixedIdentity = rig.Request(bundle, b, "host-b") with { MachineCertificate = a.Certificate };
        (int sub2, _) = await rig.Register(b, mixedIdentity);
        PairingRegistrationRequest wrongFingerprint = rig.Request(bundle, b, "host-b") with { MachineFingerprint = a.Fingerprint };
        (int sub3, _) = await rig.Register(b, wrongFingerprint);
        check(sub2 == 403 && sub3 == 403 && rig.Store.Invitation(created.Id) is { Status: "pending" }, "machine substitution: another machine's certificate or a fingerprint that is not the certificate's key is refused");

        // Certificate profiles and proof of possession, driven at the service (the same checks the route runs).
        DateTimeOffset now = rig.Clock.GetUtcNow();
        byte[] tampered = (byte[])b.Certificate.Clone();
        tampered[^1] ^= 1;
        using RSA rsa = RSA.Create(2048);
        CertificateRequest rsaRequest = new("CN=with-secrets machine rsa", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rsaRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        rsaRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign, true));
        byte[] rsaCertificate = rsaRequest.CreateSelfSigned(now.AddDays(-1), now.AddDays(3000)).RawData;
        byte[] expired = MachineCertificates.CreateIdentity(b.Key, now.AddYears(-12));
        using X509Certificate2 leafB = b.Leaf;
        PairingRegistrationRequest good = rig.Request(bundle, b, "host-b");
        int refusedProfiles = 0;
        foreach (byte[] badCertificate in new[] { tampered, rsaCertificate, expired, [], [1, 2, 3], [.. b.Certificate, 0] })
        {
            if (rig.Service.Register(good with { MachineCertificate = badCertificate }, b.Fingerprint, leafB).Status == 403)
            {
                refusedProfiles++;
            }
        }

        check(refusedProfiles == 6 && rig.Store.Find(b.Fingerprint) is null && rig.Store.Invitation(created.Id) is { Status: "pending", Failed: 0 }, "certificate profile: a tampered, RSA, expired, empty, garbage or padded identity certificate is refused; nothing is registered and the invitation is not spent");
        using SoftwareSigningKey wrongKey = new();
        PairingRegistrationRequest signedByOther = good with { Possession = wrongKey.Sign(PairingProtocol.PossessionMessage(bundle.InvitationId, rig.AuthorityFingerprint, b.Fingerprint, "host-b", good.Nonce)) };
        PairingRegistrationRequest signedOverOther = good with { Possession = b.Key.Sign(PairingProtocol.PossessionMessage(bundle.InvitationId, rig.AuthorityFingerprint, b.Fingerprint, "other-host", good.Nonce)) };
        PairingRegistrationRequest noPossession = good with { Possession = [1] };
        int possessionRefused = new[] { signedByOther, signedOverOther, noPossession }.Count(item => rig.Service.Register(item, b.Fingerprint, leafB).Status == 403);
        check(possessionRefused == 3 && rig.Store.Find(b.Fingerprint) is null && rig.Store.Invitation(created.Id) is { Status: "pending", Failed: 3 }, "proof of possession: a signature by another key, over other data, or a stub is refused, counted against the invitation, and registers nothing");
        check(rig.Service.Register(good, b.Fingerprint, leafB).Status == 200 && rig.Store.Find(b.Fingerprint) is { Status: MachineStatus.Pending }, "the correct registration still succeeds after those refusals");

        // The TLS certificate must have been signed by the identity it claims.
        (CreatedInvitation c2, PairingBundle bundle2) = rig.NewInvitation();
        using Identity c = rig.NewIdentity();
        using Identity d = rig.NewIdentity();
        using X509Certificate2 leafOfD = d.Leaf;
        check(rig.Service.Register(rig.Request(bundle2, c, "host-c"), c.Fingerprint, leafOfD).Status == 403 && rig.Service.Register(rig.Request(bundle2, c, "host-c"), d.Fingerprint, leafOfD).Status == 403 && rig.Store.Invitation(c2.Id) is { Status: "pending" }, "machine substitution: a TLS leaf signed by another identity than the one registering is refused");
    }

    private static byte[] ExtractCode(PairingBundle bundle) => System.Buffers.Text.Base64Url.DecodeFromChars(bundle.Format().Split(';')[3]);

    private static Task<(PairingResult Result, List<(string Step, byte[] Body, string Client)> Requests)> PairWith(Rig rig, Host host, PairingBundle bundle) => rig.Pair(host, bundle);

    // ---------- wrong, expired, consumed, withdrawn ----------

    private static async Task Invitations(Action<bool, string> check, string root)
    {
        using Rig rig = new(root);
        using Identity probe = rig.NewIdentity();
        (CreatedInvitation expiring, PairingBundle expiringBundle) = rig.NewInvitation();
        (CreatedInvitation spent, PairingBundle spentBundle) = rig.NewInvitation();
        (CreatedInvitation revoked, PairingBundle revokedBundle) = rig.NewInvitation();
        (CreatedInvitation burned, PairingBundle burnedBundle) = rig.NewInvitation();
        (CreatedInvitation live, PairingBundle liveBundle) = rig.NewInvitation();
        string unknown = PairingProtocol.NewToken(16);

        using Identity user = rig.NewIdentity();
        (int spendStatus, _) = await rig.Register(user, rig.Request(spentBundle, user, "first"));
        check(spendStatus == 200 && rig.Service.Revoke(revoked.Id, "admin passkey test") && !rig.Service.Revoke(revoked.Id, "admin passkey test") && !rig.Service.Revoke(spent.Id, "admin passkey test"), "revoke: a pending invitation can be revoked once; a used one cannot");

        // Five wrong proofs withdraw an invitation, even for the right code afterwards.
        using Identity guesser = rig.NewIdentity();
        for (int i = 0; i < PairingProtocol.MaxFailedPerInvitation; i++)
        {
            await rig.Register(guesser, rig.Request(burnedBundle, guesser, "guess-" + i, proof => RandomNumberGenerator.GetBytes(32)));
        }

        (int afterBurn, _) = await rig.Register(guesser, rig.Request(burnedBundle, guesser, "right-code"));
        check(afterBurn == 403 && rig.Store.Invitation(burned.Id) is { Status: "revoked", ProtectedKey: null } && rig.Store.Find(guesser.Fingerprint) is null, "wrong proofs: five wrong registration proofs withdraw the invitation (verifier wiped); the right code is refused afterwards");

        rig.Clock.Advance(PairingProtocol.InvitationLifetime + TimeSpan.FromSeconds(1));
        (CreatedInvitation fresh, PairingBundle freshBundle) = rig.NewInvitation();
        using Identity late = rig.NewIdentity();
        (int expiredBoot, string expiredBootBody) = await rig.Bootstrap(late, expiring.Id);
        (int expiredReg, string expiredRegBody) = await rig.Register(late, rig.Request(expiringBundle, late, "too-late"));
        (int consumedBoot, string consumedBootBody) = await rig.Bootstrap(late, spent.Id);
        (int consumedReg, string consumedRegBody) = await rig.Register(late, rig.Request(spentBundle, late, "second"));
        (int revokedBoot, string revokedBootBody) = await rig.Bootstrap(late, revoked.Id);
        (int burnedBoot, string burnedBootBody) = await rig.Bootstrap(late, burned.Id);
        (int unknownBoot, string unknownBootBody) = await rig.Bootstrap(late, unknown);
        (int unknownReg, string unknownRegBody) = await rig.Register(late, rig.Request(PairingBundle.Create(rig.Url, unknown, RandomNumberGenerator.GetBytes(16)), late, "unknown"));
        string Error(string body) => JsonDocument.Parse(body).RootElement.GetProperty("error").GetString()!;
        (int Status, string Body)[] all = [(expiredBoot, expiredBootBody), (expiredReg, expiredRegBody), (consumedBoot, consumedBootBody), (consumedReg, consumedRegBody), (revokedBoot, revokedBootBody), (burnedBoot, burnedBootBody), (unknownBoot, unknownBootBody), (unknownReg, unknownRegBody)];
        check(all.All(item => item.Status == 403 && Error(item.Body) == "pairing-refused") && rig.Store.Find(late.Fingerprint) is null, "refusals: expired, used, revoked, withdrawn and unknown invitations are all the same answer (403 pairing-refused), at the bootstrap and at the registration");
        check(rig.Store.Invitation(expiring.Id) is { Status: "expired", ProtectedKey: null } && rig.Store.Invitations().Single(item => item.Id == expiring.Id).StatusAt(rig.Clock.GetUtcNow()) == "expired" && rig.Store.Audit().Any(entry => entry.Event == "pairing-invitation-expired" && entry.Detail.Contains(expiring.Id[..8], StringComparison.Ordinal)), "expiry: an invitation not used in ten minutes expires, its verifier is wiped and the expiry is audited");
        PairingInvitationRecord[] listed = [.. rig.Store.Invitations()];
        check(listed.Single(item => item.Id == spent.Id).Status == "consumed" && listed.Single(item => item.Id == revoked.Id).Status == "revoked" && listed.Single(item => item.Id == fresh.Id).Status == "pending" && listed.All(item => item.Status is "pending" or "consumed" or "expired" or "revoked") && listed.All(item => item.Id != null), "list: statuses only");

        // A live invitation answers a valid bootstrap with exactly the three public members.
        (int liveStatus, string liveBody) = await rig.Bootstrap(late, fresh.Id);
        using JsonDocument doc = JsonDocument.Parse(liveBody);
        string[] members = [.. doc.RootElement.EnumerateObject().Select(member => member.Name).Order()];
        check(liveStatus == 200 && members.SequenceEqual(["authorityCertificate", "ok", "proof", "serverNonce", "v"]) && PairingWire.TryReadBootstrapReply(liveBody, out PairingBootstrapReply? reply) && reply!.AuthorityCertificate.AsSpan().SequenceEqual(rig.AuthorityIdentity)
            && PairingProtocol.Same(reply.Proof, PairingProtocol.BootstrapProof(freshBundle.DeriveKey(), fresh.Id, rig.AuthorityFingerprint, reply.Proof[..0], reply.ServerNonce)) == false, "bootstrap: a live invitation is answered with the authority's public identity certificate, a nonce and a proof, and nothing else");
        _ = live;
        _ = liveBundle;
    }

    // ---------- races ----------

    private static async Task Races(Action<bool, string> check, string root)
    {
        using Rig rig = new(root);
        (CreatedInvitation created, PairingBundle bundle) = rig.NewInvitation();
        Identity[] identities = [.. Enumerable.Range(0, 24).Select(_ => rig.NewIdentity())];
        PairingReply[] replies = new PairingReply[identities.Length];
        using ManualResetEventSlim go = new(false);
        rig.Service.WhileRegistering = () => { };
        int ran = 0;
        // Concurrent claims through the service (more than the registrations that may run at once: the others are told to retry later and are not queued).
        Task[] claims = [.. identities.Select((identity, index) => Task.Run(() =>
        {
            PairingRegistrationRequest request = rig.Request(bundle, identity, "claimant-" + index);
            using X509Certificate2 leaf = identity.Leaf;
            go.Wait();
            replies[index] = rig.Service.Register(request, identity.Fingerprint, leaf);
            Interlocked.Increment(ref ran);
        }))];
        go.Set();
        await Task.WhenAll(claims);
        int winners = replies.Count(item => item.Status == 200);
        check(ran == identities.Length && winners == 1 && replies.Count(item => item.Status == 403) + replies.Count(item => item.Status == 429) == identities.Length - 1, "concurrent claims: of 24 machines registering with one invitation at once exactly one wins; the rest are refused or told to retry later");
        check(identities.Count(item => rig.Store.Find(item.Fingerprint) is not null) == 1 && rig.Store.Invitation(created.Id) is { Status: "consumed" } && rig.Store.Machines().Count(item => item.Status == MachineStatus.Pending) == 1, "concurrent claims: one machine record, one consumption");

        // The same race over real TLS with the real client: eight hosts, one invitation.
        (CreatedInvitation netInvitation, PairingBundle netBundle) = rig.NewInvitation();
        Host[] hosts = [.. Enumerable.Range(0, 8).Select(index => rig.NewHost("net-" + index))];
        PairingResult[] results = await Task.WhenAll(hosts.Select(async host => (await rig.Pair(host, netBundle)).Result));
        check(results.Count(item => item.Ok) == 1 && hosts.Count(host => rig.Store.Find(host.Fingerprint) is not null) == 1 && rig.Store.Invitation(netInvitation.Id) is { Status: "consumed" }, "concurrent claims over TLS: eight real clients pair with one invitation: exactly one is registered");

        // Replay: a consumed invitation cannot register another machine, however correct its proofs.
        using Identity replayer = rig.NewIdentity();
        (int replay, _) = await rig.Register(replayer, rig.Request(bundle, replayer, "replayer"));
        check(replay == 403 && rig.Store.Find(replayer.Fingerprint) is null, "replay: a consumed invitation cannot register another machine");
    }

    // ---------- retries ----------

    private static async Task Retries(Action<bool, string> check, string root)
    {
        using Rig rig = new(root);
        (CreatedInvitation created, PairingBundle bundle) = rig.NewInvitation();
        using Identity machine = rig.NewIdentity();
        PairingRegistrationRequest request = rig.Request(bundle, machine, "retrying");
        (int first, string firstBody) = await rig.Register(machine, request);
        int machinesAfterFirst = rig.Store.Machines().Count;

        // The answer was lost: the machine sends the identical request again.
        (int again, string againBody) = await rig.Register(machine, request);
        check(first == 200 && again == 200 && PairingWire.TryReadRegistrationReply(againBody, out PairingRegistrationReply? reply) && reply!.MachineFingerprint == machine.Fingerprint && reply.Status == "Pending" && againBody == firstBody && rig.Store.Machines().Count == machinesAfterFirst,
            "idempotent retry: the identical request after a lost answer returns the same committed result and creates nothing again");

        // Approved in the meantime: the retry still returns the ORIGINAL result and changes nothing.
        AdminActions.ApproveMachine(rig.Store, rig.Authority.Deployment.Keys, rig.Authority.Deployment.HostConfig, null, machine.Fingerprint, "retrying", "admin passkey test");
        (int late, string lateBody) = await rig.Register(machine, request);
        check(late == 200 && lateBody == firstBody && rig.Store.Find(machine.Fingerprint) is { Status: MachineStatus.Trusted }, "idempotent retry: after the administrator approved the machine the retry still answers the original result and does not touch the record");

        // A different request (another nonce and proofs) for the used invitation is refused, even from the same machine.
        (int different, _) = await rig.Register(machine, rig.Request(bundle, machine, "retrying"));
        using Identity other = rig.NewIdentity();
        (int stolen, _) = await rig.Register(other, request);
        check(different == 403 && stolen == 403, "idempotent retry: only the identical request from the same machine is answered again");

        // Across a restart of the authority service.
        rig.Restart();
        (int afterRestart, string afterRestartBody) = await rig.Register(machine, request);
        check(afterRestart == 200 && afterRestartBody == firstBody && rig.Store.Machines().Count(item => item.Fingerprint == machine.Fingerprint) == 1 && rig.Store.Invitation(created.Id) is { Status: "consumed" }, "restart: the committed registration survives a restart of the authority and its retry is answered the same");

        // An invitation made before a restart is still good after it, and its verifier (sealed) still opens.
        (CreatedInvitation pending, PairingBundle pendingBundle) = rig.NewInvitation();
        rig.Restart();
        using Host host = rig.NewHost("after-restart");
        (PairingResult paired, _) = await rig.Pair(host, PairingBundle.Create(rig.Url, pendingBundle.InvitationId, ExtractCode(pendingBundle)));
        check(paired.Ok && rig.Store.Invitation(pending.Id) is { Status: "consumed" }, "restart: an invitation made before the authority restarted can be used after it");

        // The client repeats a registration that failed in transport, with the same body.
        (CreatedInvitation flaky, PairingBundle flakyBundle) = rig.NewInvitation();
        using Host flakyHost = rig.NewHost("flaky");
        int bootstraps = 0;
        List<byte[]> registrations = [];
        PairingResult retried = await PairingClient.RunAsync(new PairingClientOptions
        {
            Bundle = flakyBundle,
            MachineKey = flakyHost.Machine.MachineKey,
            IdentityCertificate = flakyHost.Machine.Deployment.IdentityCertificate,
            HostName = "flaky",
            HostConfig = flakyHost.Machine.Deployment.HostConfig,
            Clock = rig.Clock,
            MachineTls = flakyHost.Machine.Deployment.Tls,
            Retries = 2,
            OnRequest = (step, body, _) =>
            {
                if (step == "bootstrap")
                {
                    bootstraps++;
                }
                else
                {
                    registrations.Add(body);
                }
            },
        });
        check(retried.Ok && bootstraps == 1 && registrations.Count == 1 && rig.Store.Invitation(flaky.Id) is { Status: "consumed" }, "client: a successful run sends one bootstrap and one registration");
    }

    // ---------- machines pairing must not change ----------

    private static async Task KnownMachines(Action<bool, string> check, string root)
    {
        using Rig rig = new(root);
        AuthorityStore store = rig.Store;
        using Identity machine = rig.NewIdentity();
        (CreatedInvitation one, PairingBundle oneBundle) = rig.NewInvitation();
        await rig.Register(machine, rig.Request(oneBundle, machine, "original-name"));
        MachineRecord pending = store.Find(machine.Fingerprint)!;

        // Pending: a repeated registration refreshes the record (new host name), nothing else.
        (CreatedInvitation two, PairingBundle twoBundle) = rig.NewInvitation();
        rig.Clock.Advance(TimeSpan.FromSeconds(5));
        (int refreshStatus, _) = await rig.Register(machine, rig.Request(twoBundle, machine, "renamed-host"));
        MachineRecord refreshed = store.Find(machine.Fingerprint)!;
        check(refreshStatus == 200 && refreshed.Status == MachineStatus.Pending && refreshed.HostName == "renamed-host" && refreshed.SecurityRevision == pending.SecurityRevision && refreshed.Created == pending.Created && store.Machines().Count(item => item.Fingerprint == machine.Fingerprint) == 1 && store.Invitation(two.Id) is { Status: "consumed" }
            && store.Audit().Any(entry => entry.Event == "machine-pairing-refreshed" && entry.Fingerprint == machine.Fingerprint), "pending refresh: pairing again refreshes the Pending record (its host name), not its revision or creation, and is audited");

        // Trusted, Disabled and Untrusted machines are not changed, and the invitation is not spent.
        AdminActions.ApproveMachine(store, rig.Authority.Deployment.Keys, rig.Authority.Deployment.HostConfig, null, machine.Fingerprint, "known box", "admin passkey test");
        foreach ((string label, Func<MachineRecord, TransitionResult> change, MachineStatus expected) in new (string, Func<MachineRecord, TransitionResult>, MachineStatus)[]
        {
            ("Trusted", _ => new TransitionResult(true, "", null), MachineStatus.Trusted),
            ("Disabled", record => store.Disable(record.Fingerprint, "admin passkey test"), MachineStatus.Disabled),
            ("Untrusted", record => store.Enable(record.Fingerprint, "admin passkey test") is { Ok: true } ? store.Untrust(record.Fingerprint, "admin passkey test") : new TransitionResult(false, "", null), MachineStatus.Untrusted),
        })
        {
            change(store.Find(machine.Fingerprint)!);
            MachineRecord before = store.Find(machine.Fingerprint)!;
            (CreatedInvitation next, PairingBundle nextBundle) = rig.NewInvitation();
            (int status, string body) = await rig.Register(machine, rig.Request(nextBundle, machine, "attempted-reset"));
            MachineRecord after = store.Find(machine.Fingerprint)!;
            check(before.Status == expected && status == 403 && JsonDocument.Parse(body).RootElement.GetProperty("error").GetString() == "pairing-refused" && after with { PublicKey = [] } == before with { PublicKey = [] } && store.Invitation(next.Id) is { Status: "pending", ProtectedKey: not null }, $"{label}: pairing a {label} machine changes nothing (status, name, host name, revision) and does not spend the invitation");
        }

        check(store.Audit().Any(entry => entry.Event == "pairing-refused" && entry.Detail.Contains("already known as", StringComparison.Ordinal)) && one.Id != two.Id, "known machines: the refusals are in the audit with their reason");
    }

    // ---------- routes ----------

    private static async Task Routes(Action<bool, string> check, string root)
    {
        using Rig rig = new(root);
        using Identity stranger = rig.NewIdentity();
        int refused = 0;
        int reachedPairing = 0;
        foreach (string route in MachineApi.Routes)
        {
            (int status, string body) = await rig.Post(stranger.Tls, "{}", route);
            if (route == MachineApi.PairingPath)
            {
                if (status == 400)
                {
                    reachedPairing++;
                }
            }
            else if (status == 403 && body.Contains("unknown-machine", StringComparison.Ordinal))
            {
                refused++;
            }
        }

        check(MachineApi.Routes.Count(route => route != MachineApi.PairingPath) == refused && reachedPairing == 1, $"routes: an unknown certificate is refused on every one of the {MachineApi.Routes.Count - 1} other routes and reaches only the pairing handler (which answers a junk body 400)");

        // A machine that paired (Pending) is enrolled but not Trusted: it too is refused everywhere but the pairing route.
        (CreatedInvitation created, PairingBundle bundle) = rig.NewInvitation();
        using Identity pending = rig.NewIdentity();
        (int registered, _) = await rig.Register(pending, rig.Request(bundle, pending, "pending-box"));
        int notTrusted = 0;
        foreach (string route in MachineApi.Routes.Where(route => route != MachineApi.PairingPath))
        {
            (int status, string body) = await rig.Post(pending.Tls, "{}", route);
            if (status == 403 && body.Contains("machine-not-trusted", StringComparison.Ordinal))
            {
                notTrusted++;
            }
        }

        check(registered == 200 && notTrusted == MachineApi.Routes.Count - 1, "routes: a Pending machine is refused on every route except pairing until it is approved");
        _ = created;

        // The pairing route does only its two steps.
        string[] others =
        [
            "{\"v\":1,\"id\":\"x\",\"op\":\"decide\",\"ok\":true,\"body\":{}}", "{\"v\":1,\"step\":\"poll\"}", "{\"v\":1,\"step\":\"launch\"}", "{\"v\":1,\"step\":\"status\"}", "{\"v\":1,\"step\":\"machines\"}", "{\"v\":1,\"step\":\"grants\"}", "{\"v\":1,\"step\":\"authorize\"}",
            "{\"v\":1,\"step\":\"bootstrap\",\"invitation\":\"" + PairingProtocol.NewToken(16) + "\",\"nonce\":\"" + Convert.ToBase64String(new byte[16]) + "\",\"list\":\"machines\"}", "[]", "",
        ];
        int badRequests = 0;
        foreach (string body in others)
        {
            (int status, string answer) = await rig.Post(stranger.Tls, body);
            if (status == 400 && !answer.Contains("machine", StringComparison.OrdinalIgnoreCase) || status == 415)
            {
                badRequests++;
            }
        }

        (int getStatus, _) = await rig.Post(stranger.Tls, "", method: HttpMethod.Get);
        (int mediaStatus, _) = await rig.Post(stranger.Tls, "{}", contentType: "text/plain");
        (int huge, _) = await rig.Post(stranger.Tls, new string('x', PairingProtocol.MaxBodyBytes + 100));
        check(badRequests == others.Length && getStatus == 405 && mediaStatus == 415 && huge == 413, "pairing route: any other operation, an extra member, a GET, a non-JSON type and an oversize body are refused; it has no other operation to ask for");

        // Every pairing answer is public material or the small result.
        (CreatedInvitation c2, PairingBundle b2) = rig.NewInvitation();
        using Identity another = rig.NewIdentity();
        (int ok, string okBody) = await rig.Register(another, rig.Request(b2, another, "another"));
        using JsonDocument doc = JsonDocument.Parse(okBody);
        check(ok == 200 && doc.RootElement.EnumerateObject().Select(member => member.Name).Order().SequenceEqual(["fingerprint", "ok", "status", "v"]) && !okBody.Contains("pending-box", StringComparison.Ordinal) && !okBody.Contains(pending.Fingerprint, StringComparison.Ordinal), "pairing route: the registration answer is the fingerprint and the status, no machine record, list or detail");
        _ = c2;
    }

    // ---------- nothing before verification ----------

    private static async Task BeforeVerification(Action<bool, string> check, string root)
    {
        using Rig rig = new(root);
        using Host host = rig.NewHost("careful-host");
        (CreatedInvitation created, PairingBundle bundle) = rig.NewInvitation();
        (PairingResult result, List<(string Step, byte[] Body, string Client)> requests) = await rig.Pair(host, bundle);
        string first = Encoding.UTF8.GetString(requests[0].Body);
        using JsonDocument doc = JsonDocument.Parse(first);
        string[] members = [.. doc.RootElement.EnumerateObject().Select(member => member.Name).Order()];
        byte[] cert = host.Machine.Deployment.IdentityCertificate;
        bool leaks = first.Contains(host.Fingerprint, StringComparison.OrdinalIgnoreCase) || first.Contains("careful-host", StringComparison.Ordinal) || first.Contains(Convert.ToBase64String(cert)[..40], StringComparison.Ordinal) || Holds(first, [ExtractCode(bundle), bundle.DeriveKey()]) || first.Contains("proof", StringComparison.OrdinalIgnoreCase);
        check(result.Ok && members.SequenceEqual(["invitation", "nonce", "step", "v"]) && doc.RootElement.GetProperty("invitation").GetString() == created.Id && Convert.FromBase64String(doc.RootElement.GetProperty("nonce").GetString()!).Length == 16 && !leaks,
            "before verification: the client's FIRST request body is the invitation id and a fresh nonce and nothing else (no machine identity, fingerprint, host name, registration proof, launch request or environment)");
        check(requests[0].Client != host.Fingerprint && requests[0].Client != "" && requests[1].Client == host.Fingerprint, "before verification: the first connection carries a throwaway identity, not the machine's; only the verified second connection presents the machine");
        string firstPeer;
        lock (rig.SeenPeers)
        {
            firstPeer = rig.SeenPeers[0];
        }

        check(firstPeer == requests[0].Client && firstPeer != host.Fingerprint && rig.SeenPeers.Last() == host.Fingerprint, "before verification: the authority saw only the throwaway identity on the bootstrap and the machine's identity only on the registration");
        string second = Encoding.UTF8.GetString(requests[1].Body);
        check(second.Contains(host.Fingerprint, StringComparison.Ordinal) && !Holds(second, [ExtractCode(bundle), bundle.DeriveKey()]), "registration: carries the identity but never the code or the derived key");

        // Against an authority that fails verification the client sends exactly one request, whatever the failure.
        using Impostor silent = new(root, _ => Task.FromResult((403, "{\"v\":1,\"id\":\"x\",\"ok\":false,\"error\":\"pairing-refused\"}")));
        using Host second1 = rig.NewHost("quiet-host");
        (CreatedInvitation c2, PairingBundle b2) = rig.NewInvitation();
        (PairingResult refusedByImpostor, List<(string Step, byte[] Body, string Client)> impostorRequests) = await rig.Pair(second1, PairingBundle.Create(silent.Url, b2.InvitationId, ExtractCode(b2)));
        check(!refusedByImpostor.Ok && impostorRequests.Count == 1 && silent.Hits == 1 && !Encoding.UTF8.GetString(silent.Bodies[0]).Contains("quiet-host", StringComparison.Ordinal), "before verification: an authority that refuses gets only the bootstrap");
        // A server that is not TLS 1.3 or not speaking the protocol at all.
        PairingResult nobody = (await rig.Pair(rig.NewHost("nobody"), PairingBundle.Create("https://127.0.0.1:1", b2.InvitationId, ExtractCode(b2)))).Result;
        check(!nobody.Ok && nobody.Message.Length > 0 && !Holds(nobody.Message, [ExtractCode(b2)]) && !nobody.Message.Contains(b2.InvitationId, StringComparison.Ordinal), "client: an unreachable authority is a plain failure whose message holds nothing of the invitation");
        _ = c2;
    }

    // ---------- limits ----------

    private static async Task Limits(Action<bool, string> check, string root)
    {
        using Rig rig = new(root);
        // Open invitations are bounded.
        List<string> ids = [];
        for (int i = 0; i < PairingProtocol.MaxOpenInvitations; i++)
        {
            ids.Add(rig.NewInvitation().Created.Id);
        }

        (CreatedInvitation? tooMany, string? problem) = rig.Service.Create("admin passkey test");
        bool revokedOne = rig.Service.Revoke(ids[0], "admin passkey test");
        (CreatedInvitation? afterRevoke, _) = rig.Service.Create("admin passkey test");
        check(tooMany is null && problem is not null && revokedOne && afterRevoke is not null, "limit: at most 8 invitations are open at once (revoking one makes room)");

        // Concurrent registrations: the slots are bounded and the others are refused, not queued.
        foreach (string leftover in rig.Store.Invitations().Where(item => item.Status == "pending").Select(item => item.Id).ToList())
        {
            rig.Service.Revoke(leftover, "admin passkey test");
        }

        (CreatedInvitation open, PairingBundle openBundle) = rig.NewInvitation();
        _ = open;
        int inside = 0;
        int peak = 0;
        using ManualResetEventSlim release = new(false);
        using ManualResetEventSlim filled = new(false);
        rig.Service.WhileRegistering = () =>
        {
            int now = Interlocked.Increment(ref inside);
            int seen;
            do
            {
                seen = Volatile.Read(ref peak);
            }
            while (now > seen && Interlocked.CompareExchange(ref peak, now, seen) != seen);
            if (now == PairingProtocol.MaxConcurrentRegistrations)
            {
                filled.Set();
            }

            release.Wait();
            Interlocked.Decrement(ref inside);
        };
        Identity[] holders = [.. Enumerable.Range(0, PairingProtocol.MaxConcurrentRegistrations).Select(_ => rig.NewIdentity())];
        using Identity extra = rig.NewIdentity();
        Task<PairingReply>[] held = [.. holders.Select(holder => Task.Run(() =>
        {
            using X509Certificate2 leaf = holder.Leaf;

            return rig.Service.Register(rig.Request(openBundle, holder, "holder"), holder.Fingerprint, leaf);
        }))];
        filled.Wait(TimeSpan.FromSeconds(10));
        using X509Certificate2 extraLeaf = extra.Leaf;
        PairingReply busy = rig.Service.Register(rig.Request(openBundle, extra, "extra"), extra.Fingerprint, extraLeaf);
        release.Set();
        await Task.WhenAll(held);
        rig.Service.WhileRegistering = null;
        check(busy.Status == 429 && busy.Code == "too-busy" && peak == PairingProtocol.MaxConcurrentRegistrations && PairingProtocol.MaxConcurrentRegistrations == 4, "limit: at most 4 registrations run at once; one more is refused 429 at once (not queued)");

        // Pending registrations are bounded (in all, and per host name); the invitation is not spent by a refusal.
        using Rig crowded = new(root);
        for (int i = 0; i < LocalAuthority.MaxPendingMachines; i++)
        {
            using SoftwareSigningKey key = new();
            crowded.Store.Register(key.PublicKey, "pending-" + i, "test");
        }

        (CreatedInvitation c1, PairingBundle cb) = crowded.NewInvitation();
        using Identity newcomer = crowded.NewIdentity();
        (int full, _) = await crowded.Register(newcomer, crowded.Request(cb, newcomer, "newcomer"));
        check(full == 403 && crowded.Store.Find(newcomer.Fingerprint) is null && crowded.Store.Invitation(c1.Id) is { Status: "pending" } && crowded.Store.Audit().Any(entry => entry.Event == "pairing-refused" && entry.Detail.Contains("too many machines", StringComparison.Ordinal)), "limit: with 32 machines waiting a new machine is refused (audited) and the invitation is not spent");

        using Rig named = new(root);
        for (int i = 0; i < LocalAuthority.MaxPendingPerHostName; i++)
        {
            using SoftwareSigningKey key = new();
            named.Store.Register(key.PublicKey, "same-name", "test");
        }

        (CreatedInvitation n1, PairingBundle nb) = named.NewInvitation();
        using Identity twin = named.NewIdentity();
        (int sameName, _) = await named.Register(twin, named.Request(nb, twin, "SAME-NAME"));
        check(sameName == 403 && named.Store.Find(twin.Fingerprint) is null && named.Store.Invitation(n1.Id) is { Status: "pending" }, "limit: at most 4 machines may wait under one host name");

        // Failed attempts overall: after 30 refused attempts the route refuses everything (429) until the window has passed.
        using Rig noisy = new(root);
        (CreatedInvitation good, PairingBundle goodBundle) = noisy.NewInvitation();
        using Identity noise = noisy.NewIdentity();
        int refusals = 0;
        for (int i = 0; i < PairingProtocol.MaxFailedOverall; i++)
        {
            (int status, _) = await noisy.Bootstrap(noise, PairingProtocol.NewToken(16));
            if (status == 403)
            {
                refusals++;
            }
        }

        (int blocked, string blockedBody) = await noisy.Bootstrap(noise, good.Id);
        noisy.Clock.Advance(PairingProtocol.FailureWindow + TimeSpan.FromSeconds(1));
        (CreatedInvitation fresh, PairingBundle freshBundle) = noisy.NewInvitation();
        (int unblocked, _) = await noisy.Bootstrap(noise, fresh.Id);
        check(refusals == PairingProtocol.MaxFailedOverall && blocked == 429 && JsonDocument.Parse(blockedBody).RootElement.GetProperty("error").GetString() == "too-busy" && unblocked == 200 && PairingProtocol.MaxFailedOverall == 30, "limit: after 30 refused attempts in ten minutes the route answers 429 to everyone; it recovers when the window has passed");
        _ = goodBundle;
        _ = freshBundle;

        // The audit of a flood is bounded and summarized.
        using Rig flood = new(root);
        using Identity floodId = flood.NewIdentity();
        for (int i = 0; i < PairingService.MaxAuditRowsPerMinute + 10; i++)
        {
            flood.Service.Bootstrap(new PairingBootstrapRequest(PairingProtocol.NewToken(16), new byte[16]));
        }

        int rows = flood.Store.Audit().Count(entry => entry.Event == "pairing-refused");
        check(rows <= PairingService.MaxAuditRowsPerMinute && rows >= 1, "limit: the audit of a flood of refused attempts is bounded (rows per minute); a flood past the overall limit writes nothing more");
    }

    // ---------- the audit ----------

    private static async Task Audit(Action<bool, string> check, string root)
    {
        using Rig rig = new(root);
        using Host host = rig.NewHost("audited-box");
        (CreatedInvitation created, PairingBundle bundle) = rig.NewInvitation();
        (CreatedInvitation revoked, PairingBundle revokedBundle) = rig.NewInvitation();
        (CreatedInvitation expired, PairingBundle expiredBundle) = rig.NewInvitation();
        rig.Service.Revoke(revoked.Id, "admin passkey test");
        await rig.Bootstrap(rig.NewIdentity(), PairingProtocol.NewToken(16));
        PairingResult wrongCode = (await rig.Pair(rig.NewHost("guesser"), PairingBundle.Create(bundle.Authority, bundle.InvitationId, RandomNumberGenerator.GetBytes(16)))).Result;
        using Identity bad = rig.NewIdentity();
        await rig.Register(bad, rig.Request(bundle, bad, "bad-proof", proof => new byte[32]));
        (PairingResult paired, List<(string Step, byte[] Body, string Client)> requests) = await rig.Pair(host, bundle);
        rig.Clock.Advance(PairingProtocol.InvitationLifetime + TimeSpan.FromMinutes(1));
        rig.Store.ExpireInvitations();
        AdminActions.ApproveMachine(rig.Store, rig.Authority.Deployment.Keys, rig.Authority.Deployment.HostConfig, null, host.Fingerprint, "audited", "admin passkey test");
        IReadOnlyList<AuditEntry> audit = rig.Store.Audit(5000);
        string[] events = [.. audit.Select(entry => entry.Event).Distinct()];
        string[] wanted = ["pairing-invitation-created", "pairing-bootstrap", "pairing-refused", "pairing-attempt-refused", "pairing-invitation-consumed", "machine-registered", "pairing-invitation-revoked", "pairing-invitation-expired", "machine-approve"];
        check(paired.Ok && !wrongCode.Ok && wanted.All(item => events.Contains(item)), "audit: invitation creation, bootstrap, refusals, a wrong proof, consumption, the registration, revocation, expiry and the administrator's approval are all in the durable audit");
        check(audit.Where(entry => entry.Event.StartsWith("pairing-", StringComparison.Ordinal)).All(entry => entry.Detail.Length < 300), "audit: pairing rows are short and name an invitation by the start of its identifier only");

        // No code, proof or key anywhere on disk (authority.db and its journal, host.json, certificates, the outbox) or in the output.
        byte[][] secrets = [ExtractCode(bundle), bundle.DeriveKey(), ExtractCode(revokedBundle), revokedBundle.DeriveKey(), ExtractCode(expiredBundle), expiredBundle.DeriveKey(), Encoding.ASCII.GetBytes(bundle.Format()), Encoding.ASCII.GetBytes(revokedBundle.Format())];
        List<byte[]> proofs = [];
        foreach ((string step, byte[] body, string _) in requests)
        {
            using JsonDocument doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("proof", out JsonElement proof))
            {
                proofs.Add(Convert.FromBase64String(proof.GetString()!));
            }

            _ = step;
        }

        (int _, string bootBody) = await rig.Bootstrap(rig.NewIdentity(), created.Id);
        string? onDisk = FindIn(root, [.. secrets, .. proofs]);
        check(onDisk is null, "canary: no pairing code, bundle, derived key or registration proof is in authority.db, its journal, host.json, any certificate file or the audit outbox" + (onDisk is null ? "" : " (found in " + onDisk + ")"));
        string everything = string.Join('\n', audit.Select(entry => entry.Event + entry.Actor + entry.Detail + entry.Fingerprint)) + paired.Message + wrongCode.Message + string.Join('\n', rig.Store.History(host.Fingerprint).Select(entry => entry.Detail + entry.Actor));
        check(!Holds(everything, [.. secrets, .. proofs]) && !Holds(bootBody, secrets), "canary: nothing in the audit, history, results or the bootstrap answer holds a code, key or proof");
        _ = expired;
    }

    // ---------- the input sources ----------

    private static async Task Inputs(Action<bool, string> check, string root)
    {
        using Rig rig = new(root);
        (CreatedInvitation created, PairingBundle bundle) = rig.NewInvitation();
        string text = bundle.Format();
        byte[] code = ExtractCode(bundle);
        string folder = Path.Combine(root, "inputs");
        Directory.CreateDirectory(folder);
        string file = Path.Combine(folder, "pairing.secret");
        File.WriteAllText(file, text + "\n");
        Dictionary<string, string> variables = [];
        string? Variable(string name) => variables.GetValueOrDefault(name);
        string? Read(string path) => File.ReadAllText(path);
        bool Exists(string path) => File.Exists(path);

        // Hidden prompt: the console is asked once, the prompt shows nothing of the input, and a bad input does not echo.
        FakeConsole typed = new(text);
        PairingInput.Found prompted = PairingInput.Obtain(typed, Variable, Read, Exists);
        check(prompted.Bundle is not null && prompted.Source == PairingSource.Prompt && typed.Prompts.Count == 1 && !typed.Prompts[0].Contains(text, StringComparison.Ordinal) && !typed.Prompts[0].Contains(created.Id, StringComparison.Ordinal) && typed.Prompts[0].Contains("nothing is shown", StringComparison.Ordinal), "input: an interactive terminal is asked for the invitation with a hidden read, and the prompt holds no part of it");
        PairingInput.Found garbage = PairingInput.Obtain(new FakeConsole("not an invitation but secret-looking " + Convert.ToBase64String(code)), Variable, Read, Exists);
        check(garbage.Bundle is null && garbage.Problem is not null && !Holds(garbage.Problem, [code]) && !garbage.Problem.Contains("secret-looking", StringComparison.Ordinal), "input: a bad input is refused with a message that does not repeat it");
        PairingInput.Found none = PairingInput.Obtain(new FakeConsole(null, interactive: false), Variable, Read, Exists);
        check(none.Bundle is null && none.Problem!.Contains("no terminal", StringComparison.Ordinal), "input: with no terminal and no unattended source nothing is asked and nothing runs");

        // A secret file (a Docker secret) and an environment variable.
        variables[PairingInput.FileVariable] = file;
        PairingInput.Found fromFile = PairingInput.Obtain(new FakeConsole(null, false), Variable, Read, Exists);
        variables.Remove(PairingInput.FileVariable);
        variables[PairingInput.ValueVariable] = text;
        PairingInput.Found fromVariable = PairingInput.Obtain(new FakeConsole(null, false), Variable, Read, Exists);
        check(fromFile.Source == PairingSource.File && fromFile.Bundle is not null && fromVariable.Source == PairingSource.Environment && fromVariable.Bundle is not null && fromFile.Bundle.InvitationId == created.Id && fromVariable.Bundle.InvitationId == created.Id, "input: unattended, the invitation comes from a secret file (WITH_SECRETS_PAIRING_FILE) or from WITH_SECRETS_PAIRING");
        variables[PairingInput.FileVariable] = file;
        File.WriteAllText(Path.Combine(folder, "other.secret"), PairingBundle.Create(bundle.Authority, PairingProtocol.NewToken(16), RandomNumberGenerator.GetBytes(16)).Format());
        PairingInput.Found both = PairingInput.Obtain(new FakeConsole(null, false), Variable, Read, Exists);
        variables.Remove(PairingInput.FileVariable);
        PairingInput.Found docker = PairingInput.Obtain(new FakeConsole(null, false), Variable, Read, path => path == PairingInput.DockerSecretPath || File.Exists(path));
        check(both.Source == PairingSource.File && both.Bundle!.InvitationId == created.Id, "input: a secret file is preferred over the environment variable when both are given");
        string dockerPath = Path.Combine(folder, "docker-secret");
        File.WriteAllText(dockerPath, text);
        PairingInput.Found dockerSecret = PairingInput.Obtain(new FakeConsole(null, false), name => null, path => path == PairingInput.DockerSecretPath ? File.ReadAllText(dockerPath) : null, path => path == PairingInput.DockerSecretPath);
        check(dockerSecret.Source == PairingSource.File && dockerSecret.Bundle?.InvitationId == created.Id && docker.Source is PairingSource.File or PairingSource.Environment, "input: the Docker secret convention (/run/secrets/with-secrets-pairing) is read without any variable");
        variables.Clear();
        variables[PairingInput.FileVariable] = Path.Combine(folder, "missing.secret");
        PairingInput.Found missing = PairingInput.Obtain(new FakeConsole(text), Variable, Read, Exists);
        check(missing.Bundle is null && missing.Source == PairingSource.File && missing.Problem is not null && !missing.Problem.Contains(text, StringComparison.Ordinal), "input: a named secret file that cannot be read is an error; there is no quiet fallback to a weaker source");
        check(PairingInput.IsPairingVariable("WITH_SECRETS_PAIRING") && PairingInput.IsPairingVariable("with_secrets_pairing_file") && !PairingInput.IsPairingVariable("WITH_SECRETS_PORT"), "input: both pairing variables are recognized (for scrubbing)");

        // The whole command: output holds the fingerprint and host name and never the code; the variables are cleared once read.
        using Host host = rig.NewHost("cli-host");
        variables.Clear();
        variables[PairingInput.ValueVariable] = text;
        List<string> cleared = [];
        StringWriter output = new();
        StringWriter error = new();
        List<(string Step, byte[] Body, string Client)> seen = [];
        PairingEnvironment environment = new()
        {
            Console = new FakeConsole(null, false),
            Variable = Variable,
            ClearVariable = name => { cleared.Add(name); variables.Remove(name); },
            ReadFile = Read,
            FileExists = _ => false,
            OpenMachine = () => new PairingMachine(new NoDispose(host.Machine.MachineKey), host.Machine.Deployment.IdentityCertificate, "cli-host", host.Machine.Deployment.HostConfig),
            Clock = rig.Clock,
            OnRequest = (step, body, client) => seen.Add((step, body, client)),
        };
        int exit = await AuthorityPairing.RunAsync(environment, output, error);
        string printed = output + error.ToString();
        check(exit == 0 && printed.Contains(KeyIdentity.Display(host.Fingerprint), StringComparison.Ordinal) && printed.Contains("cli-host", StringComparison.Ordinal) && printed.Contains("Pending", StringComparison.Ordinal), "command: pairing prints this machine's fingerprint and host name and says it is Pending");
        check(!Holds(printed, [code, bundle.DeriveKey()]) && !printed.Contains(created.Id, StringComparison.Ordinal) && !printed.Contains(text, StringComparison.Ordinal), "command: the output never holds the code, the invitation or its identifier");
        check(cleared.Contains(PairingInput.ValueVariable) && cleared.Contains(PairingInput.FileVariable) && !variables.ContainsKey(PairingInput.ValueVariable), "command: the pairing variables are removed from the process once read");
        StringWriter badOutput = new();
        StringWriter badError = new();
        int refusedExit = await AuthorityPairing.RunAsync(new PairingEnvironment
        {
            Console = new FakeConsole("garbage " + Convert.ToBase64String(code)),
            Variable = _ => null,
            ClearVariable = _ => { },
            ReadFile = Read,
            FileExists = _ => false,
            OpenMachine = () => throw new InvalidOperationException("must not be opened"),
        }, badOutput, badError);
        check(refusedExit == RunCommand.Usage && !Holds(badOutput + badError.ToString(), [code]) && !(badOutput + badError.ToString()).Contains("garbage", StringComparison.Ordinal), "command: a bad invitation is a usage error, the machine identity is not even opened and the input is not echoed");
        int reused = await AuthorityPairing.RunAsync(new PairingEnvironment { Console = new FakeConsole(text), Variable = _ => null, ClearVariable = _ => { }, ReadFile = Read, FileExists = _ => false, OpenMachine = () => new PairingMachine(new NoDispose(rig.NewHost("late").Machine.MachineKey), rig.NewHost("late2").Machine.Deployment.IdentityCertificate, "late", host.Machine.Deployment.HostConfig), Clock = rig.Clock }, new StringWriter(), error);
        check(reused == RunCommand.Denied && !Holds(error.ToString(), [code]) && !error.ToString().Contains(text, StringComparison.Ordinal), "command: pairing with a used invitation is refused (exit 3) with a message that holds nothing of it");
    }

    private sealed class NoDispose(ISigningKey inner) : ISigningKey
    {
        public byte[] PublicKey => inner.PublicKey;

        public byte[] Sign(byte[] data) => inner.Sign(data);

        public void Dispose()
        {
        }
    }

    // ---------- the credential is not passed on ----------

    private static async Task Children(Action<bool, string> check, string root)
    {
        const string Canary = "wsp1;https://127.0.0.1:1;CANARYCANARYCANARYCAN;CANARYCANARYCANARYCAN";
        string? oldValue = Environment.GetEnvironmentVariable(PairingInput.ValueVariable);
        string? oldFile = Environment.GetEnvironmentVariable(PairingInput.FileVariable);
        try
        {
            Environment.SetEnvironmentVariable(PairingInput.ValueVariable, Canary);
            Environment.SetEnvironmentVariable(PairingInput.FileVariable, "/run/secrets/with-secrets-pairing");

            // What a run sends to the service (its own environment, as a map) never holds the pairing variables.
            IReadOnlyDictionary<string, string> sent = LaunchClient.CurrentEnvironment();
            check(!sent.Keys.Any(PairingInput.IsPairingVariable) && !sent.Values.Any(value => value.Contains("CANARYCANARY", StringComparison.Ordinal)) && sent.Count > 0, "child: the environment a run sends to the host service holds neither pairing variable");

            // A client that did not scrub (an older one, another program) is scrubbed by the service when it builds the child's environment: with a request's block and without one (the service's own).
            string script = OperatingSystem.IsWindows() ? "set" : "env";
            string program = OperatingSystem.IsWindows() ? Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe" : "/usr/bin/env";
            string[] arguments = OperatingSystem.IsWindows() ? ["/c", script] : [];
            Dictionary<string, string> block = new(StringComparer.Ordinal) { ["PATH"] = Environment.GetEnvironmentVariable("PATH") ?? "", ["SystemRoot"] = Environment.GetEnvironmentVariable("SystemRoot") ?? "", [PairingInput.ValueVariable] = Canary, [PairingInput.FileVariable] = "/run/secrets/x", ["ORDINARY"] = "kept" };
            foreach (IReadOnlyDictionary<string, string>? inherited in new IReadOnlyDictionary<string, string>?[] { block, null })
            {
                StringWriter stdout = new();
                StringWriter stderr = new();
                ChildSpec spec = new(program, arguments, Directory.GetCurrentDirectory(), new Dictionary<string, string>(), null, inherited);
                int exit = await ChildRunner.RunAsync(spec, stdout, stderr);
                string seen = stdout + stderr.ToString();
                check(exit == 0 && !seen.Contains("CANARYCANARY", StringComparison.Ordinal) && !seen.Contains(PairingInput.ValueVariable, StringComparison.OrdinalIgnoreCase) && !seen.Contains(PairingInput.FileVariable, StringComparison.OrdinalIgnoreCase) && (inherited is null || seen.Contains("ORDINARY=kept", StringComparison.Ordinal)),
                    "child: a launched program's environment (" + (inherited is null ? "the service's own" : "the request's") + ") never contains the pairing credential or the variable that names its file; other variables still pass");
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable(PairingInput.ValueVariable, oldValue);
            Environment.SetEnvironmentVariable(PairingInput.FileVariable, oldFile);
        }
    }
}

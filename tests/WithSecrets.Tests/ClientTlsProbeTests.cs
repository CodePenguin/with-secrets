using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace WithSecrets.Tests;

/// <summary>
/// The client half of machine transport against a server this program did not write: <c>tls-probe/server.mjs</c> (Node: TLS 1.3 only, HTTP/2 only, a client certificate required and verified against one root). It exists for macOS,
/// where .NET cannot serve TLS 1.3 so no machine listener can answer a handshake (see <see cref="PlatformTls" />), but it runs on every platform. The real <see cref="RemoteAuthority" /> connects with the machine certificates this
/// program makes. What is shown: TLS 1.3 and h2 were negotiated, the client certificate (SAN = the machine's identity) was presented and verified, a request arrived; and that the client still refuses an authority that is not
/// the one it was configured with, and a server that does not trust its certificate. Nothing is weakened for the test: the same validation code runs.
/// </summary>
internal static class ClientTlsProbeTests
{
    private sealed class Probe : IDisposable
    {
        private readonly Process _node;

        public Probe(string root, byte[] serverLeaf, ECDsa serverKey, byte[] clientRootIdentity)
        {
            string folder = Path.Combine(root, "probe-" + Guid.NewGuid().ToString("N")[..6]);
            Directory.CreateDirectory(folder);
            string cert = Path.Combine(folder, "server.pem");
            string key = Path.Combine(folder, "server.key");
            string ca = Path.Combine(folder, "ca.pem");
            using (X509Certificate2 leaf = X509CertificateLoader.LoadCertificate(serverLeaf))
            {
                File.WriteAllText(cert, leaf.ExportCertificatePem());
            }

            File.WriteAllText(key, serverKey.ExportPkcs8PrivateKeyPem());
            using (X509Certificate2 clientRoot = X509CertificateLoader.LoadCertificate(clientRootIdentity))
            {
                File.WriteAllText(ca, clientRoot.ExportCertificatePem());
            }

            ProcessStartInfo start = new("node") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
            start.ArgumentList.Add(ScriptPath());
            start.ArgumentList.Add(cert);
            start.ArgumentList.Add(key);
            start.ArgumentList.Add(ca);
            _node = Process.Start(start)!;
            _node.OutputDataReceived += (_, e) =>
            {
                if (e.Data is { Length: > 0 } line)
                {
                    Events.Enqueue(JsonDocument.Parse(line).RootElement.Clone());
                }
            };
            _node.ErrorDataReceived += (_, e) =>
            {
                if (e.Data is { Length: > 0 } line)
                {
                    Errors.Enqueue(line);
                }
            };
            _node.BeginOutputReadLine();
            _node.BeginErrorReadLine();
        }

        public ConcurrentQueue<JsonElement> Events { get; } = new();

        public ConcurrentQueue<string> Errors { get; } = new();

        public int Port { get; private set; }

        public async Task<bool> WaitListeningAsync()
        {
            bool up = await HostServiceTests.WaitFor(() => Events.Any(item => Kind(item) == "listening"), 20);
            if (up)
            {
                Port = Events.First(item => Kind(item) == "listening").GetProperty("port").GetInt32();
            }

            return up;
        }

        public IEnumerable<JsonElement> Of(string kind) => Events.Where(item => Kind(item) == kind);

        public void Dispose()
        {
            try
            {
                _node.Kill(true);
            }
            catch (InvalidOperationException)
            {
                // Already gone.
            }

            _node.Dispose();
        }
    }

    private static string Kind(JsonElement item) => item.GetProperty("event").GetString() ?? "";

    private static string ScriptPath()
    {
        for (DirectoryInfo? directory = new(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            string candidate = Path.Combine(directory.FullName, "tests", "WithSecrets.Tests", "tls-probe", "server.mjs");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new FileNotFoundException("tests/WithSecrets.Tests/tls-probe/server.mjs was not found above " + AppContext.BaseDirectory);
    }

    private static async Task<bool> NodeWorks()
    {
        try
        {
            using Process node = Process.Start(new ProcessStartInfo("node", "--version") { RedirectStandardOutput = true, UseShellExecute = false })!;
            await node.WaitForExitAsync();

            return node.ExitCode == 0;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }

    /// <summary>An authority identity and a TLS leaf for a fresh exportable key, signed under it: what a machine listener would present.</summary>
    private static (byte[] Identity, byte[] Leaf, ECDsa Key) Server(DateTimeOffset now)
    {
        using SoftwareSigningKey identityKey = new();
        byte[] identity = MachineCertificates.CreateIdentity(identityKey, now);
        ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] leaf = MachineCertificates.CreateTemporary(identityKey, identity, key.ExportSubjectPublicKeyInfo(), now);

        return (identity, leaf, key);
    }

    private static RemoteAuthority Client(TestMachine host, int port, byte[] pinnedIdentity)
    {
        RemoteAuthorityConfig config = new("https://127.0.0.1:" + port, MachineCertificates.FingerprintOf(pinnedIdentity)!, pinnedIdentity);
        host.Deployment.HostConfig.SetRemote(host.Fingerprint, config);

        return new RemoteAuthority(config, host.Deployment.Tls, host.Deployment.HostConfig) { RetryPause = TimeSpan.FromMilliseconds(10), Retries = 1, DrainTimeout = TimeSpan.FromSeconds(2) };
    }

    private static async Task<RemoteTransportException?> Reconcile(RemoteAuthority remote, TestMachine host, string id)
    {
        try
        {
            await remote.ReconcileAsync(ReconcileEnvelope.Create(id, host.HostName, DateTimeOffset.UtcNow, host.MachineKey)).WaitAsync(TimeSpan.FromSeconds(60));

            return null;
        }
        catch (RemoteTransportException error)
        {
            return error;
        }
    }

    public static async Task Run(Action<bool, string> check)
    {
        if (!await NodeWorks())
        {
            Console.WriteLine("  SKIP client TLS 1.3 against a Node server: node is not available here, not run");

            return;
        }

        string root = Path.Combine(Path.GetTempPath(), "ws-tlsprobe-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);
        try
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            using TestMachine host = new(Path.Combine(root, "host"), trusted: false, hostName: "probe-host");
            (byte[] authorityIdentity, byte[] authorityLeaf, ECDsa authorityKey) = Server(now);
            using (authorityKey)
            {
                // The configured authority serves a TLS 1.3 + h2 endpoint that requires, and verifies, this machine's certificate.
                using (Probe probe = new(root, authorityLeaf, authorityKey, host.Deployment.IdentityCertificate))
                {
                    check(await probe.WaitListeningAsync(), "client tls probe: the Node server is listening (" + string.Join(" | ", probe.Errors) + ")");
                    using RemoteAuthority remote = Client(host, probe.Port, authorityIdentity);
                    RemoteTransportException? error = await Reconcile(remote, host, "probe-ok");
                    bool arrived = await HostServiceTests.WaitFor(() => probe.Of("request").Any(), 10);
                    JsonElement connection = probe.Of("connection").FirstOrDefault();
                    bool seen = connection.ValueKind == JsonValueKind.Object;
                    string san = seen ? connection.GetProperty("san").GetString() ?? "" : "";
                    check(seen && connection.GetProperty("protocol").GetString() == "TLSv1.3" && connection.GetProperty("alpn").GetString() == "h2", "client tls probe: the client negotiated TLS 1.3 and HTTP/2 (" + connection + ")");
                    check(seen && connection.GetProperty("authorized").GetBoolean() && san.Contains(MachineCertificates.SanUri(host.Fingerprint), StringComparison.Ordinal), "client tls probe: the client presented its machine certificate and the server verified it against the machine identity (" + san + ")");

                    // The server answers with an empty object, which is not a protocol answer: getting that far means TLS and the request itself went through, and it is the protocol layer that refuses.
                    check(arrived && error is not null && error.Message.Contains("could not be read", StringComparison.Ordinal), "client tls probe: the request reached the server over that connection and only the protocol layer refused the empty answer (" + error?.Message + ")");
                }

                // Another authority's certificate: the client is configured for a different identity and must not connect.
                (byte[] otherIdentity, _, ECDsa otherKey) = Server(now);
                using (otherKey)
                using (Probe impostor = new(root, authorityLeaf, authorityKey, host.Deployment.IdentityCertificate))
                {
                    check(await impostor.WaitListeningAsync(), "client tls probe: the second Node server is listening");
                    using RemoteAuthority remote = Client(host, impostor.Port, otherIdentity);
                    RemoteTransportException? error = await Reconcile(remote, host, "probe-impostor");
                    await Task.Delay(200);
                    check(error is not null && error.Message.Contains("could not be reached", StringComparison.Ordinal) && !impostor.Of("request").Any(), "client tls probe: a server that is not the configured authority is refused and receives no request (" + error?.Message + ")");
                }

                // A server that does not trust this machine's identity: the handshake fails and no request is served.
                (byte[] strangerRoot, _, ECDsa strangerKey) = Server(now);
                using (strangerKey)
                using (Probe closed = new(root, authorityLeaf, authorityKey, strangerRoot))
                {
                    check(await closed.WaitListeningAsync(), "client tls probe: the third Node server is listening");
                    using RemoteAuthority remote = Client(host, closed.Port, authorityIdentity);
                    RemoteTransportException? error = await Reconcile(remote, host, "probe-untrusted");
                    await Task.Delay(200);
                    check(error is not null && !closed.Of("request").Any(), "client tls probe: a server that does not trust this machine's identity serves nothing (" + error?.Message + ")");
                }
            }
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
}

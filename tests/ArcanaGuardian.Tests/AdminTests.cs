using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

using Microsoft.Data.Sqlite;

namespace ArcanaGuardian.Tests;

/// <summary>
/// Phase 2, the admin commands: the command line, that every change needs an admin passkey tap on a page that shows the action and the
/// full fingerprint, that nothing changes without it, the terminal-only gate, and that the CLI refuses a service that is not this
/// machine's (an impostor on the port gets nothing).
/// </summary>
internal static class AdminTests
{
    public static async Task Run(Action<bool, string> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "ws-admin-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);
        try
        {
            await Impostors(check, root);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
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

    // ---- the CLI refuses a service that is not this machine's ----

    /// <summary>A listener that answers the identity check with what <c>identity</c> returns (null is a 404) and counts launch requests.</summary>
    private sealed class Impostor : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();
        private readonly Task _loop;
        private int _launches;

        public Impostor(Func<string, string?> identity, bool hang = false)
        {
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _loop = Task.Run(async () =>
            {
                while (!_stop.IsCancellationRequested)
                {
                    TcpClient client;
                    try
                    {
                        client = await _listener.AcceptTcpClientAsync(_stop.Token);
                    }
                    catch (Exception error) when (error is OperationCanceledException or SocketException or ObjectDisposedException)
                    {
                        return;
                    }

                    _ = Serve(client, identity, hang);
                }
            });
        }

        public int Port { get; }

        public int LaunchesSeen => Volatile.Read(ref _launches);

        private async Task Serve(TcpClient client, Func<string, string?> identity, bool hang)
        {
            using (client)
            {
                try
                {
                    NetworkStream stream = client.GetStream();
                    byte[] buffer = new byte[8192];
                    string head = "";
                    while (!head.Contains("\r\n\r\n", StringComparison.Ordinal))
                    {
                        int read = await stream.ReadAsync(buffer, _stop.Token);
                        if (read == 0)
                        {
                            return;
                        }

                        head += Encoding.UTF8.GetString(buffer, 0, read);
                    }

                    if (head.Contains("/v1/launch", StringComparison.Ordinal))
                    {
                        Interlocked.Increment(ref _launches);

                        return;
                    }

                    if (hang)
                    {
                        await Task.Delay(Timeout.Infinite, _stop.Token);
                    }

                    int body = head.IndexOf("\r\n\r\n", StringComparison.Ordinal) + 4;
                    while (Encoding.UTF8.GetByteCount(head[body..]) < ContentLength(head))
                    {
                        int read = await stream.ReadAsync(buffer, _stop.Token);
                        if (read == 0)
                        {
                            break;
                        }

                        head += Encoding.UTF8.GetString(buffer, 0, read);
                    }

                    string? answer = identity(head[body..]);
                    byte[] payload = Encoding.UTF8.GetBytes(answer ?? "");
                    byte[] header = Encoding.ASCII.GetBytes($"HTTP/1.1 {(answer is null ? 404 : 200)} X\r\nContent-Type: application/json\r\nContent-Length: {payload.Length}\r\nConnection: close\r\n\r\n");
                    await stream.WriteAsync(header, _stop.Token);
                    await stream.WriteAsync(payload, _stop.Token);
                }
                catch (Exception error) when (error is IOException or OperationCanceledException or SocketException or ObjectDisposedException or JsonException or KeyNotFoundException)
                {
                    // The client went away, or the test's reply could not be made.
                }
            }
        }

        private static int ContentLength(string head)
        {
            int at = head.IndexOf("Content-Length:", StringComparison.OrdinalIgnoreCase);

            return at < 0 ? 0 : int.Parse(head[(at + 15)..head.IndexOf('\r', at)].Trim(), CultureInfo.InvariantCulture);
        }

        public void Dispose()
        {
            _stop.Cancel();
            _listener.Stop();
            try
            {
                _loop.Wait(TimeSpan.FromSeconds(2));
            }
            catch (AggregateException)
            {
                // Stopping.
            }
        }
    }

    private static string Challenge(string body) => JsonDocument.Parse(body).RootElement.GetProperty("challenge").GetString()!;

    private static string Answer(ISigningKey key, string challenge, string? fingerprint = null, byte[]? publicKey = null)
        => "{\"protocolVersion\":1,\"fingerprint\":\"" + (fingerprint ?? KeyIdentity.Fingerprint(key.PublicKey)) + "\",\"publicKey\":\"" + Convert.ToBase64String(publicKey ?? key.PublicKey) + "\",\"signature\":\"" + Convert.ToBase64String(key.Sign(WireText.Bytes(WireText.IdentityDomain, challenge))) + "\"}";

    private static async Task<(int Code, string Err)> ClientRun(int port, ServiceTrust trust, string work)
    {
        StringWriter err = new();
        RunArgs args = CliArgs.ParseRun(["--secrets", "TOKEN", "--reason", "impostor test", "--", "anything"], out _)!;
        int code = await LaunchClient.RunAsync(args, work, LocalEndpoint.Loopback(port), null, new StringWriter(), err, trust);

        return (code, err.ToString());
    }

    private static async Task Impostors(Action<bool, string> check, string root)
    {
        string work = Path.Combine(root, "work");
        Directory.CreateDirectory(work);
        using SoftwareSigningKey real = new();
        using SoftwareSigningKey fake = new();
        ServiceTrust pinned = new(KeyIdentity.Fingerprint(real.PublicKey));

        using (Impostor genuine = new(body => Answer(real, Challenge(body))))
        {
            _ = await ClientRun(genuine.Port, pinned, work);
            check(genuine.LaunchesSeen == 1, "impostor control: a service that proves the pinned key is sent the launch");
        }

        // L5: `using-secrets admin` checks the service's identity like a run does; an impostor on the port is not reported as the service and its answer is not trusted.
        using (Impostor genuine = new(body => Answer(real, Challenge(body))))
        {
            StringWriter outText = new();
            StringWriter errText = new();
            int ok = await AdminAppCommand.RunAsync(genuine.Port, outText, errText, pinned, endpoint: LocalEndpoint.Loopback(genuine.Port));
            check(ok == 0 && outText.ToString().Contains(BrowserAddress.Origin(genuine.Port) + "/admin", StringComparison.Ordinal) && errText.ToString().Length == 0, "admin: a service that proves the pinned key gets its link printed (" + outText.ToString().Trim().Replace('\n', ' ') + ")");
        }

        using (Impostor imposter = new(body => Answer(fake, Challenge(body))))
        {
            StringWriter outText = new();
            StringWriter errText = new();
            string? opened = null;
            int code = await AdminAppCommand.RunAsync(imposter.Port, outText, errText, pinned, link => opened = link, endpoint: LocalEndpoint.Loopback(imposter.Port));
            check(code == LaunchClient.ServiceNotAuthenticated && outText.ToString().Length == 0 && opened is null && errText.ToString().Length > 0, "admin: a program that merely holds the port is refused (exit 7): no link, no status, nothing opened (" + errText.ToString().Trim() + ")");
        }

        using (Impostor garbage = new(_ => "{\"locked\":false}"))
        {
            StringWriter outText = new();
            int code = await AdminAppCommand.RunAsync(garbage.Port, outText, new StringWriter(), pinned, endpoint: LocalEndpoint.Loopback(garbage.Port));
            check(code == 7 && !outText.ToString().Contains("unlocked", StringComparison.Ordinal), "admin: an impostor's own status answer is not reported");
        }

        // M2: on the first run nothing is pinned yet. `admin` must not send the person back to itself (exit 7 with "admin prints its link"): it prints the link, marked as not verified, and opens nothing.
        using (Impostor firstRun = new(body => Answer(real, Challenge(body))))
        {
            StringWriter outText = new();
            StringWriter errText = new();
            string? opened = null;
            int code = await AdminAppCommand.RunAsync(firstRun.Port, outText, errText, new ServiceTrust(null), link => opened = link, endpoint: LocalEndpoint.Loopback(firstRun.Port));
            string printed = outText.ToString();
            check(code == 0 && printed.Contains(BrowserAddress.Origin(firstRun.Port) + "/admin", StringComparison.Ordinal) && printed.Contains("Not verified", StringComparison.Ordinal) && opened is null && errText.ToString().Length == 0, "admin: with no identity pinned yet (first run) it prints the link, says it is not verified, opens nothing and exits 0 (" + printed.Trim().Replace((char)10, ' ') + ")");
            StringWriter unreadable = new();
            int broken = await AdminAppCommand.RunAsync(firstRun.Port, new StringWriter(), unreadable, new ServiceTrust(null, "host.json cannot be read"), endpoint: LocalEndpoint.Loopback(firstRun.Port));
            check(broken == 7 && unreadable.ToString().Contains("host.json cannot be read", StringComparison.Ordinal), "admin: an unreadable host.json is still a refusal, never 'nothing pinned'");
        }

        string replayed = Answer(real, "an old challenge");
        (string Name, Func<string, string?> Reply)[] cases =
        [
            ("garbage", _ => "this is not json"),
            ("an empty answer", _ => ""),
            ("a 404", _ => null),
            ("a valid answer of another key", body => Answer(fake, Challenge(body))),
            ("the real fingerprint with the wrong key", body => Answer(fake, Challenge(body), fingerprint: KeyIdentity.Fingerprint(real.PublicKey))),
            ("the real key and fingerprint with a signature of the wrong key", body => Answer(fake, Challenge(body), fingerprint: KeyIdentity.Fingerprint(real.PublicKey), publicKey: real.PublicKey)),
            ("a replayed answer (the real key, an old challenge)", _ => replayed),
            ("an answer with a missing member", _ => "{\"protocolVersion\":1,\"fingerprint\":\"" + KeyIdentity.Fingerprint(real.PublicKey) + "\"}"),
            ("an oversize answer", _ => new string('x', 10_000)),
        ];
        foreach ((string name, Func<string, string?> reply) in cases)
        {
            using Impostor impostor = new(reply);
            (int code, string err) = await ClientRun(impostor.Port, pinned, work);
            check(code == LaunchClient.ServiceNotAuthenticated && code == 7 && impostor.LaunchesSeen == 0, "impostor: " + name + " gets exit 7 and no launch request (" + err.Trim() + ")");
        }

        using (Impostor hanging = new(_ => "", hang: true))
        {
            System.Diagnostics.Stopwatch clock = System.Diagnostics.Stopwatch.StartNew();
            (int code, string err) = await ClientRun(hanging.Port, pinned, work);
            check(code == 7 && hanging.LaunchesSeen == 0 && clock.Elapsed < TimeSpan.FromSeconds(30), "impostor: a service that never answers is refused (exit 7) after the time-out, nothing sent (" + err.Trim() + ")");
        }

        using (Impostor unpinnedService = new(body => Answer(real, Challenge(body))))
        {
            (int code, string err) = await ClientRun(unpinnedService.Port, new ServiceTrust(null), work);
            check(code == 7 && unpinnedService.LaunchesSeen == 0 && err.Contains(KeyIdentity.Fingerprint(real.PublicKey), StringComparison.Ordinal) && err.Contains("admin web app", StringComparison.Ordinal), "client: with no pin it prints the service's fingerprint, names the admin web app and refuses (" + err.Trim() + ")");
        }

        (int damaged, string damagedErr) = await ClientRun(1, new ServiceTrust(null, "host.json is damaged"), work);
        check(damaged == 7 && damagedErr.Contains("host.json is damaged", StringComparison.Ordinal), "client: an unreadable host.json is exit 7, not 'nothing pinned'");
        TcpListener free = new(IPAddress.Loopback, 0);
        free.Start();
        int closed = ((IPEndPoint)free.LocalEndpoint).Port;
        free.Stop();
        (int refused, _) = await ClientRun(closed, pinned, work);
        check(refused == LaunchClient.ServiceNotRunning, "client: a refused connection is still exit 6 (the service is not running)");
    }
}

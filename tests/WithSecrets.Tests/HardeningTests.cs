using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Text.Json;

using Serilog.Core;
using Serilog.Events;

namespace WithSecrets.Tests;

/// <summary>
/// Task M7. The Linux key file checks (links, owner, group/other-writable parents, exclusive and atomic creation; they run on Linux and are skipped on Windows), the process hardening (non-dumpable, best-effort mlock),
/// the copied-identity warning, the machine listener that starts when the first approval makes the authority key (no restart), and its canary scan: nothing key-like in any message or event made here.
/// </summary>
internal static class HardeningTests
{
    private const UnixFileMode Owner = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode OwnerDir = Owner | UnixFileMode.UserExecute;

    public static async Task Run(Action<bool, string> check)
    {
        string parent = Path.Combine(Path.GetTempPath(), "ws-harden-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(parent);
        try
        {
            if (OperatingSystem.IsWindows())
            {
                check(LinuxHardening.MakeNonDumpable() is null && !LinuxHardening.IsDumpable() && LinuxHardening.CurrentUserId() is null, "key file checks and process hardening: skipped on Windows (CNG keys; no prctl or mlock), nothing is attempted");
                using IDisposable none = LinuxHardening.TryLock(new byte[16]);
            }
            else
            {
                UnixKeyChecks(check, parent);
                await ProcessHardening(check, parent);
            }

            CopyWatch(check, parent);
            await ListenerWithoutRestart(check, parent);
            await CopiedIdentityEndToEnd(check, parent);
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

    // ---------- Linux key file checks ----------

    private static string? Refusal(Func<IDisposable?> action)
    {
        try
        {
            action()?.Dispose();
        }
        catch (KeyFileException error)
        {
            return error.Message;
        }

        return null;
    }

    private static bool OneClearLine(string? message, string path, string fix) => message is not null && !message.Contains('\n') && !message.Contains("   at ", StringComparison.Ordinal) && message.Contains(path, StringComparison.Ordinal) && message.Contains(fix, StringComparison.Ordinal);

    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private static string NewStore(string parent, string name)
    {
        string store = Path.Combine(parent, name);
        Directory.CreateDirectory(store);
        File.SetUnixFileMode(store, OwnerDir);

        return store;
    }

    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private static void UnixKeyChecks(Action<bool, string> check, string parent)
    {
        uint uid = LinuxHardening.CurrentUserId()!.Value;

        // The normal case: made with 0600 in a 0700 folder, found again, not changed.
        string store = NewStore(parent, "normal");
        string file = FileSigningKey.FileOf(MachineKeyStore.KeyFolder(store), KeyNames.Machine);
        string fingerprint;
        using (ISigningKey made = MachineKeyStore.OpenOrCreate(store, KeyNames.Machine, out bool created))
        {
            fingerprint = KeyIdentity.Fingerprint(made.PublicKey);
            check(created && File.GetUnixFileMode(file) == Owner && File.GetUnixFileMode(MachineKeyStore.KeyFolder(store)) == OwnerDir, "hardening: a new key is a 0600 file in a 0700 folder");
        }

        using (ISigningKey again = MachineKeyStore.OpenOrCreate(store, KeyNames.Machine, out bool createdAgain))
        {
            check(!createdAgain && KeyIdentity.Fingerprint(again.PublicKey) == fingerprint, "hardening: a key that passes every check is used again (same fingerprint)");
        }

        string tail = Convert.ToHexString(File.ReadAllBytes(file)[^24..]);
        List<string> messages = [];

        // A link in place of the key folder (the folder it points to is a perfectly good key folder).
        string linkStore = NewStore(parent, "link-folder");
        string realKeys = Path.Combine(NewStore(parent, "link-folder-real"), "keys");
        using (FileSigningKey.OpenOrCreate(FileSigningKey.FileOf(realKeys, KeyNames.Machine), out _))
        {
        }

        Directory.CreateSymbolicLink(MachineKeyStore.KeyFolder(linkStore), realKeys);
        string? folderLink = Refusal(() => MachineKeyStore.TryOpen(linkStore, KeyNames.Machine));
        messages.Add(folderLink ?? "");
        check(OneClearLine(folderLink, MachineKeyStore.KeyFolder(linkStore), "is a link") && Refusal(() => MachineKeyStore.OpenOrCreate(linkStore, KeyNames.Machine, out _)) is not null, "hardening: a link in place of the key folder is refused (with the path), for opening and for creating");

        // A link in place of the key file.
        string fileLinkStore = NewStore(parent, "link-file");
        string fileLinkKeys = MachineKeyStore.KeyFolder(fileLinkStore);
        Directory.CreateDirectory(fileLinkKeys, OwnerDir);
        string fileLink = FileSigningKey.FileOf(fileLinkKeys, KeyNames.Machine);
        File.CreateSymbolicLink(fileLink, file);
        string? linked = Refusal(() => MachineKeyStore.TryOpen(fileLinkStore, KeyNames.Machine));
        messages.Add(linked ?? "");
        check(OneClearLine(linked, fileLink, "is a link") && Refusal(() => MachineKeyStore.OpenOrCreate(fileLinkStore, KeyNames.Machine, out _)) is not null, "hardening: a link in place of the key file is refused, never followed");

        // Another owner (reported by the seam, as a user who cannot chown has no other way to make one): file and folder are refused with the path and the fix.
        string keyFolder = MachineKeyStore.KeyFolder(store);
        try
        {
            LinuxHardening.OwnerOverride = path => path == file ? uid + 1 : null;
            string? fileOwner = Refusal(() => FileSigningKey.TryOpen(file, store));
            messages.Add(fileOwner ?? "");
            check(OneClearLine(fileOwner, file, "chown " + uid) && fileOwner!.Contains("owned by user " + (uid + 1), StringComparison.Ordinal), "hardening: a key file of another owner is refused with one line naming the path and the chown fix (no stack trace)");
            LinuxHardening.OwnerOverride = path => path == keyFolder ? uid + 1 : null;
            string? folderOwner = Refusal(() => FileSigningKey.OpenOrCreate(file, out _, store));
            messages.Add(folderOwner ?? "");
            check(OneClearLine(folderOwner, keyFolder, "chown " + uid) && Refusal(() => MachineKeyStore.TryOpen(store, KeyNames.Machine)) is not null, "hardening: a key folder of another owner is refused with one line naming the folder and the fix, for opening and creating");
        }
        finally
        {
            LinuxHardening.OwnerOverride = null;
        }

        // A parent (up to the store folder) that group or other can write.
        string parentStore = NewStore(parent, "writable-parent");
        using (MachineKeyStore.OpenOrCreate(parentStore, KeyNames.Machine, out _))
        {
        }

        File.SetUnixFileMode(parentStore, OwnerDir | UnixFileMode.GroupWrite);
        string? groupWritable = Refusal(() => MachineKeyStore.TryOpen(parentStore, KeyNames.Machine));
        messages.Add(groupWritable ?? "");
        check(OneClearLine(groupWritable, parentStore, "chmod go-w") && Refusal(() => MachineKeyStore.OpenOrCreate(parentStore, KeyNames.Machine, out _)) is not null, "hardening: a store folder that group can write is refused with the fix (the key folder could be replaced)");
        File.SetUnixFileMode(parentStore, OwnerDir | UnixFileMode.OtherWrite);
        check(Refusal(() => MachineKeyStore.TryOpen(parentStore, KeyNames.Machine)) is not null, "hardening: a store folder that other can write is refused");
        File.SetUnixFileMode(parentStore, OwnerDir | UnixFileMode.OtherWrite | UnixFileMode.StickyBit);
        check(Refusal(() => MachineKeyStore.TryOpen(parentStore, KeyNames.Machine)) is null, "hardening: the same folder with the sticky bit (how a shared temporary folder is made safe) is accepted");
        File.SetUnixFileMode(parentStore, OwnerDir);

        // Above the store folder nothing is checked (a home folder is the user's own business).
        string outer = NewStore(parent, "outer");
        File.SetUnixFileMode(outer, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupWrite | UnixFileMode.GroupRead | UnixFileMode.GroupExecute);
        string inner = Path.Combine(outer, "store");
        Directory.CreateDirectory(inner, OwnerDir);
        using (ISigningKey above = MachineKeyStore.OpenOrCreate(inner, KeyNames.Machine, out _))
        {
            check(above.PublicKey.Length > 0, "hardening: a group-writable folder above the store folder is not the key store's business");
        }

        File.SetUnixFileMode(outer, OwnerDir);

        // Exclusive creation: eight racers make one key and all use it; no temporary file stays.
        string raceStore = NewStore(parent, "race");
        string racePath = FileSigningKey.FileOf(MachineKeyStore.KeyFolder(raceStore), KeyNames.Machine);
        ConcurrentBag<(bool Created, string Fingerprint)> results = [];
        Parallel.For(0, 8, _ =>
        {
            using FileSigningKey key = FileSigningKey.OpenOrCreate(racePath, out bool made, raceStore);
            results.Add((made, KeyIdentity.Fingerprint(key.PublicKey)));
        });
        check(results.Count == 8 && results.Count(item => item.Created) == 1 && results.Select(item => item.Fingerprint).Distinct().Count() == 1 && Directory.GetFiles(MachineKeyStore.KeyFolder(raceStore)).Length == 1, "hardening: eight racing creators make exactly one key, all of them use it, and no temporary file is left");

        // A file that is there is not replaced by a plain create; CreateFresh replaces it atomically, with mode 0600.
        string freshStore = NewStore(parent, "fresh");
        string freshPath = FileSigningKey.FileOf(MachineKeyStore.KeyFolder(freshStore), KeyNames.Machine);
        string before;
        using (FileSigningKey first = FileSigningKey.OpenOrCreate(freshPath, out _, freshStore))
        {
            before = KeyIdentity.Fingerprint(first.PublicKey);
        }

        using (FileSigningKey second = FileSigningKey.CreateFresh(freshPath, freshStore))
        {
            check(KeyIdentity.Fingerprint(second.PublicKey) != before && File.GetUnixFileMode(freshPath) == Owner && Directory.GetFiles(MachineKeyStore.KeyFolder(freshStore)).Length == 1, "hardening: CreateFresh replaces the key in one rename (new key, mode 0600, no temporary file left)");
        }

        // Every refusal is a KeyFileException, one line, and none holds key material.
        check(messages.All(message => message.Length > 0 && !message.Contains(tail, StringComparison.OrdinalIgnoreCase) && !message.Contains("PRIVATE", StringComparison.Ordinal)), "hardening: no refusal message holds key material (canary: the key's own bytes)");
    }

    // ---------- process hardening ----------

    [DllImport("libc", EntryPoint = "getrlimit")]
    private static extern int GetRlimit(int resource, out RLimit limit);

    [DllImport("libc", EntryPoint = "setrlimit")]
    private static extern int SetRlimit(int resource, ref RLimit limit);

    [StructLayout(LayoutKind.Sequential)]
    private struct RLimit
    {
        public ulong Current;
        public ulong Maximum;
    }

    private sealed class Capture : ILogEventSink
    {
        public ConcurrentQueue<LogEvent> Events { get; } = new();

        public void Emit(LogEvent logEvent) => Events.Enqueue(logEvent);
    }

    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private static Task ProcessHardening(Action<bool, string> check, string parent)
    {
        Capture log = new();
        AppLog.LogFolder = Path.Combine(parent, "logs");
        AppLog.Tap = log;
        AppLog.Configure(false);
        try
        {
            LinuxHardening.HardenProcess();
            check(!LinuxHardening.IsDumpable() && LinuxHardening.MakeNonDumpable() is null, "hardening: the process is non-dumpable after HardenProcess (prctl PR_SET_DUMPABLE 0)");
            check(!log.Events.Any(item => item.Level >= LogEventLevel.Warning), "hardening: making the process non-dumpable logs no warning when it works");

            // Memory that holds key material is locked and wiped by its owner; the lock is released with it.
            byte[] material = [.. Enumerable.Repeat((byte)0x5A, 64)];
            IDisposable pages = LinuxHardening.TryLock(material);
            LinuxHardening.Wipe(material, pages);
            check(material.All(item => item == 0), "hardening: locked key material is wiped, then unlocked");
            byte[] output = [.. Enumerable.Repeat((byte)0x77, 32)];
            Unlock unlock = new("credential", output);
            unlock.Dispose();
            check(output.All(item => item == 0), "hardening: the PRF output of an Unlock is zeroed when it is disposed (locked while it lives)");

            // mlock refused (the limit is 0 for this check): no exception, one warning, no content in it, the data intact.
            _ = GetRlimit(8, out RLimit saved);
            RLimit none = saved with { Current = 0 };
            byte[] canary = [.. Enumerable.Repeat((byte)0x42, 4096)];
            bool threw = false;
            int warnings;
            try
            {
                _ = SetRlimit(8, ref none);
                try
                {
                    using IDisposable refused = LinuxHardening.TryLock(canary);
                }
                catch (Exception)
                {
                    threw = true;
                }
            }
            finally
            {
                _ = SetRlimit(8, ref saved);
            }

            warnings = log.Events.Count(item => item.Level == LogEventLevel.Warning);
            string text = string.Join('\n', log.Events.Select(item => item.RenderMessage() + string.Join(",", item.Properties.Select(pair => pair.Value.ToString()))));
            check(!threw && canary.All(item => item == 0x42), "hardening: an mlock the system refuses (limit 0) does not throw and leaves the data alone");
            check(warnings == 1 || (warnings == 0 && Environment.UserName == "root"), $"hardening: a refused mlock logs one warning (as root the limit does not apply): {warnings}");
            check(!text.Contains("BBBB", StringComparison.Ordinal) && !text.Contains("4242", StringComparison.Ordinal), "hardening: the mlock warning holds no content of the memory");
        }
        finally
        {
            AppLog.Close();
            AppLog.LogFolder = null;
            AppLog.Tap = null;
        }

        return Task.CompletedTask;
    }

    // ---------- the copied-identity watch ----------

    private sealed class Events : IHostAudit
    {
        public List<AuditFacts> Recorded { get; } = [];

        public bool TryRecord(AuditFacts facts)
        {
            lock (Recorded)
            {
                Recorded.Add(facts);
            }

            return true;
        }
    }

    private static void CopyWatch(Action<bool, string> check, string parent)
    {
        AppClock clock = new();
        using TestMachine machine = new(Path.Combine(parent, "watch"), clock: clock);
        AuthorityStore store = machine.Deployment.Store;
        Events audit = new();
        CopiedIdentityWatch watch = new(store, () => audit, clock);
        string other = new string('B', 64);
        string machineFingerprint = new('A', 64);

        for (int index = 0; index < 10; index++)
        {
            watch.Superseded(machineFingerprint, "10.0.0.1", "10.0.0.1");
        }

        watch.Superseded(machineFingerprint, "", "10.0.0.9");
        check(store.CopyWarningOf(machineFingerprint) is null && audit.Recorded.Count == 0, "copy watch: a poll superseded from the SAME address (or an unknown one) counts for nothing, however often");

        watch.Superseded(machineFingerprint, "10.0.0.1", "10.0.0.2");
        watch.Superseded(machineFingerprint, "10.0.0.2", "10.0.0.1");
        check(store.CopyWarningOf(machineFingerprint) is null && audit.Recorded.Count == 0, "copy watch: two supersedes from different addresses are below the threshold (3 within 10 minutes)");

        watch.Superseded(machineFingerprint, "10.0.0.1", "10.0.0.2");
        CopyWarning? warning = store.CopyWarningOf(machineFingerprint);
        AuditFacts? first = audit.Recorded.FirstOrDefault();
        check(warning is { Count: 3, FirstAddress: "10.0.0.1", LastAddress: "10.0.0.2" } && audit.Recorded.Count == 1 && first!.Type == AuditEventTypes.Admin && first.Outcome == CopiedIdentityWatch.EventName, "copy watch: the third supersede from different addresses records the warning and one signed-type audit event (type admin)");
        check(first!.Metadata is { } meta && meta["machine"] == machineFingerprint && meta["older-address"] == "10.0.0.1" && meta["newer-address"] == "10.0.0.2" && meta["count"] == "3" && AuditMetadata.Problem(meta) is null && first.Reason.Length <= 200, "copy watch: the event carries the machine fingerprint, both addresses and the count, within the audit limits");

        watch.Superseded(machineFingerprint, "10.0.0.2", "10.0.0.1");
        check(audit.Recorded.Count == 1 && store.CopyWarningOf(machineFingerprint)!.Count == 4, "copy watch: further supersedes refresh the warning and write no second event within the window");

        clock.Advance(CopiedIdentityWatch.Window + TimeSpan.FromMinutes(1));
        for (int index = 0; index < 3; index++)
        {
            watch.Superseded(machineFingerprint, "10.0.0.1", "10.0.0.2");
        }

        check(audit.Recorded.Count == 2, "copy watch: after the window a renewed pattern writes a new event");

        // Slow alternation never reaches the threshold: one a 6 minutes is at most 2 in 10.
        for (int index = 0; index < 8; index++)
        {
            clock.Advance(TimeSpan.FromMinutes(6));
            watch.Superseded(other, "10.0.0.1", "10.0.0.2");
        }

        check(store.CopyWarningOf(other) is null, "copy watch: supersedes spread over time (one every 6 minutes) do not make a warning");
        check(CopiedIdentityWatch.Threshold == 3 && CopiedIdentityWatch.Window == TimeSpan.FromMinutes(10), "copy watch: the thresholds are fixed and built in (3 within 10 minutes)");
        check(CopiedIdentityWatch.AddressText(IPAddress.Parse("::ffff:10.1.2.3")) == "10.1.2.3" && CopiedIdentityWatch.AddressText(IPAddress.Parse("10.1.2.3")) == "10.1.2.3" && CopiedIdentityWatch.AddressText(null) == "", "copy watch: an IPv4 address mapped into IPv6 is the same address");
    }

    // ---------- the listener starts when the key appears ----------

    private static async Task<bool> UntilAsync(Func<bool> condition, int seconds = 20)
    {
        DateTime end = DateTime.UtcNow.AddSeconds(seconds);
        while (DateTime.UtcNow < end)
        {
            if (condition())
            {
                return true;
            }

            await Task.Delay(25);
        }

        return condition();
    }

    private static async Task<int> StatusWithoutCertificate(int port)
    {
        using SocketsHttpHandler handler = new()
        {
            UseProxy = false,
            SslOptions = new SslClientAuthenticationOptions { EnabledSslProtocols = SslProtocols.Tls13, RemoteCertificateValidationCallback = (_, _, _, _) => true },
        };
        using HttpClient client = new(handler) { DefaultRequestVersion = HttpVersion.Version20, DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact, Timeout = TimeSpan.FromSeconds(10) };
        try
        {
            using HttpResponseMessage response = await client.PostAsync($"https://127.0.0.1:{port}/api/v1/machine/ops/poll", new StringContent("{}"));

            return (int)response.StatusCode;
        }
        catch (Exception error) when (error is HttpRequestException or TaskCanceledException or IOException)
        {
            return 0;
        }
    }

    private static async Task ListenerWithoutRestart(Action<bool, string> check, string parent)
    {
        string root = Path.Combine(parent, "listener");
        Directory.CreateDirectory(root);
        using AdminApp app = new(root, trusted: false, machineEndpoint: true);
        bool noKey = app.Store.ActiveKey() is null;
        check(noKey && app.Service.MachinePort is null && app.Service.MachineListener is null, "listener: before the authority signing key exists the service serves no machine listener");

        // The first approval makes the key (the same operation the admin app runs after the tap); the listener comes up by itself.
        TestMachine.Approve(app.Machine.Deployment);
        bool started = await UntilAsync(() => app.Service.MachinePort is not null);
        check(started && app.Store.ActiveKey() is not null, "listener: the listener starts by itself as soon as the first approval makes the key (no restart)");
        int port = app.Service.MachinePort ?? 0;
        if (port != 0)
        {
            using System.Net.Sockets.TcpClient tcp = new();
            await tcp.ConnectAsync(IPAddress.Loopback, port);
            check(tcp.Connected, "listener: the new listener accepts connections on its address");
            int status = await StatusWithoutCertificate(port);
            check(status is 0 or >= 400, $"listener: who may connect is unchanged: a client without a machine identity is refused ({status})");
        }

        // A service without the endpoint never grows one, whatever is approved.
        string rootTwo = Path.Combine(parent, "listener-none");
        Directory.CreateDirectory(rootTwo);
        using AdminApp plain = new(rootTwo, trusted: false, machineEndpoint: false);
        TestMachine.Approve(plain.Machine.Deployment);
        await Task.Delay(300);
        check(plain.Service.MachinePort is null, "listener: a service that was not asked for a machine endpoint serves none after an approval");

        // A key that is there at the start: the listener is there at the start (unchanged).
        string rootThree = Path.Combine(parent, "listener-key");
        Directory.CreateDirectory(rootThree);
        using AdminApp keyed = new(rootThree, trusted: true, machineEndpoint: true);
        check(keyed.Service.MachinePort is not null, "listener: a key that exists at the start gives a listener at the start (as before)");

        // The service ends while a late start could be pending: no exception, no listener left.
        string rootFour = Path.Combine(parent, "listener-stop");
        Directory.CreateDirectory(rootFour);
        AdminApp stopping = new(rootFour, trusted: false, machineEndpoint: true);
        TestMachine.Approve(stopping.Machine.Deployment);
        stopping.Dispose();
        check(true, "listener: stopping the service right after the key appears is clean");
    }

    // ---------- the warning end to end ----------

    private static async Task CopiedIdentityEndToEnd(Action<bool, string> check, string parent)
    {
        string root = Path.Combine(parent, "copied");
        Directory.CreateDirectory(root);
        using AdminApp app = new(root, machineEndpoint: true);
        int port = app.Service.MachinePort ?? throw new InvalidOperationException("no machine listener");
        byte[] identity = app.Machine.Deployment.IdentityCertificate;
        RemoteAuthorityConfig config = new("https://127.0.0.1:" + port, MachineCertificates.FingerprintOf(identity)!, identity);
        using TestMachine copied = new(Path.Combine(root, "copy"), trusted: false, hostName: "copy-host");
        copied.Deployment.HostConfig.SetRemote(copied.Fingerprint, config);
        app.Store.Register(copied.MachineKey.PublicKey, "copy-host", "test pairing", copied.Deployment.IdentityCertificate);
        app.Store.Approve(copied.Fingerprint, "copy-host", "test admin");
        using RemoteAuthority here = new(config, copied.Deployment.Tls, copied.Deployment.HostConfig) { RetryPause = TimeSpan.FromMilliseconds(20), Retries = 1 };
        using RemoteAuthority there = new(config, copied.Deployment.Tls, copied.Deployment.HostConfig) { RetryPause = TimeSpan.FromMilliseconds(20), Retries = 1, TestLocalAddress = IPAddress.Parse("127.0.0.2") };
        MachineListener listener = app.Service.MachineListener!;
        using CancellationTokenSource stop = new();

        async Task<Task> Poll(RemoteAuthority client)
        {
            int before = listener.Requests;
            Task poll = Task.Run(async () =>
            {
                try
                {
                    await client.PollAsync(copied.Fingerprint, stop.Token);
                }
                catch (Exception)
                {
                    // Superseded by the other address, or ended by the test.
                }
            });
            await UntilAsync(() => listener.Requests > before, 10);
            await Task.Delay(150);

            return poll;
        }

        // The same address twice is an ordinary reconnect: no warning. Then the two addresses alternate, as in the M3b test with two services.
        _ = await Poll(here);
        _ = await Poll(here);
        check(app.Store.CopyWarningOf(copied.Fingerprint) is null, "copied identity: a reconnect from the same address makes no warning");
        _ = await Poll(there);
        _ = await Poll(here);
        check(app.Store.CopyWarningOf(copied.Fingerprint) is null, "copied identity: two supersedes from different addresses are below the threshold");
        _ = await Poll(there);
        CopyWarning? warning = app.Store.CopyWarningOf(copied.Fingerprint);
        check(warning is { Count: >= 3 } && warning.FirstAddress != warning.LastAddress && new[] { "127.0.0.1", "127.0.0.2" }.Contains(warning.LastAddress), $"copied identity: the third alternation from another address makes the warning (count {warning?.Count}, {warning?.FirstAddress} and {warning?.LastAddress})");
        check(app.Store.Find(copied.Fingerprint)?.Status == MachineStatus.Trusted, "copied identity: nothing is disabled by itself: the machine is still Trusted");

        // The signed event reaches the authority's audit (the service signs it with its machine key and uploads it like any event).
        bool arrived = await UntilAsync(() => app.Store.AuditHistory(new AuditQuery(Type: AuditEventTypes.Admin, Outcome: CopiedIdentityWatch.EventName)).Count > 0, 30);
        AuditHistoryRecord? record = app.Store.AuditHistory(new AuditQuery(Type: AuditEventTypes.Admin, Outcome: CopiedIdentityWatch.EventName)).FirstOrDefault();
        check(arrived && record is not null && record.Event.Metadata is { } metadata && metadata["machine"] == copied.Fingerprint && metadata["count"] == "3" && metadata["older-address"] != metadata["newer-address"], "copied identity: one signed admin audit event names the machine, both addresses and the count");
        string text = string.Join('\n', app.Store.AuditHistory(new AuditQuery(Limit: 1000)).Select(item => item.Event.ToJson()));
        check(!text.Contains("PRIVATE", StringComparison.Ordinal) && !text.Contains(Convert.ToBase64String(copied.MachineKey.PublicKey) + "private", StringComparison.Ordinal), "copied identity: canary: the event holds public data only (fingerprint, addresses, count)");

        // The admin app shows it on the Machines screen, and only on that machine.
        AdminBrowser browser = await app.SignedIn();
        (int status, string body, _) = await browser.GetAsync("/api/v1/machines");
        using JsonDocument machines = JsonDocument.Parse(body);
        JsonElement[] items = [.. machines.RootElement.GetProperty("items").EnumerateArray()];
        JsonElement flagged = items.First(item => item.GetProperty("fingerprint").GetString() == copied.Fingerprint);
        JsonElement clean = items.First(item => item.GetProperty("fingerprint").GetString() == app.Fingerprint);
        check(status == 200 && flagged.GetProperty("copyWarning").ValueKind == JsonValueKind.Object && flagged.GetProperty("copyWarning").GetProperty("count").GetInt32() >= 3 && clean.GetProperty("copyWarning").ValueKind == JsonValueKind.Null, "copied identity: the Machines API carries the warning for that machine only");
        check(!body.Contains("PRIVATE", StringComparison.Ordinal), "copied identity: the API shows addresses and counts, nothing secret");

        // A disabled machine is already dealt with: the warning goes quiet.
        app.Store.Disable(copied.Fingerprint, "test admin");
        (_, string afterBody, _) = await browser.GetAsync("/api/v1/machines");
        using JsonDocument after = JsonDocument.Parse(afterBody);
        JsonElement disabled = after.RootElement.GetProperty("items").EnumerateArray().First(item => item.GetProperty("fingerprint").GetString() == copied.Fingerprint);
        check(disabled.GetProperty("copyWarning").ValueKind == JsonValueKind.Null, "copied identity: once the administrator disabled the machine the warning is no longer shown");
        stop.Cancel();
    }
}

using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

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
            Parsing(check);
            await Page(check, root);
            await Sensitive(check, root);
            await KeyCommands(check, root);
            await ReviewFixes(check, root);
            Listing(check, root);
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

    private static CliCommand.Admin? Admin(params string[] args) => CliArgs.Parse(["admin", .. args], out _) as CliCommand.Admin;

    private static void Parsing(Action<bool, string> check)
    {
        string fp = new('A', 64);
        string prefix = fp[..12];
        check(Admin("machines") is { Action: AdminAction.Machines }, "admin parse: machines");
        check(Admin("machines", "--port", "5") is null, "admin parse: machines takes no --port");
        check(Admin("approve", prefix, "--name", "dev box") is { Action: AdminAction.Approve, Name: "dev box", Fingerprint: not null }, "admin parse: approve FINGERPRINT --name NAME");
        check(Admin("approve", prefix) is null && Admin("approve", "--name", "x") is null, "admin parse: approve needs both a fingerprint and --name");
        check(Admin("approve", "AB", "--name", "x") is null, "admin parse: a fingerprint of fewer than 12 digits is refused");
        check(Admin("approve", "ZZZZZZZZZZZZ", "--name", "x") is null, "admin parse: a fingerprint that is not hex is refused");
        check(Admin("disable", prefix) is { Action: AdminAction.Disable } && Admin("enable", prefix) is { Action: AdminAction.Enable } && Admin("untrust", prefix) is { Action: AdminAction.Untrust } && Admin("approve-host-change", prefix) is { Action: AdminAction.ApproveHostChange }, "admin parse: disable, enable, untrust and approve-host-change take a fingerprint");
        check(Admin("trust", prefix) is null && Admin("trust", fp) is { Action: AdminAction.Trust }, "admin parse: trust takes the full 64-digit fingerprint, not a prefix");
        check(Admin("rename", prefix, "new name") is { Action: AdminAction.Rename, Name: "new name" } && Admin("rename", prefix) is null, "admin parse: rename FINGERPRINT NAME");
        check(Admin("disable") is null && Admin("disable", prefix, "extra") is null && Admin("frobnicate", prefix) is null && Admin("disable", prefix, "--name", "x") is null, "admin parse: missing, extra or unknown arguments are refused");
        check(Admin("disable", prefix, "--port", "4000", "--debug") is { Port: 4000, Debug: true }, "admin parse: --port and --debug are accepted");

        string[][] all = [["machines"], ["approve", prefix, "--name", "x"], ["disable", prefix], ["enable", prefix], ["untrust", prefix], ["trust", fp], ["rename", prefix, "n"], ["approve-host-change", prefix]];
        check(all.All(args => Admin(args) is { } command && CliArgs.NeedsTerminal(command)), "admin gate: every admin command, the listing included, needs a real terminal (it is for people, not agents)");
    }

    private sealed class PageResult
    {
        public (int Code, string Detail)? Result { get; set; }

        public int Status { get; set; }

        public int Announced { get; set; }

        public string Html { get; set; } = "";

        public string Url { get; set; } = "";

        public string Proof { get; set; } = "";
    }

    private static async Task<PageResult> RunAdmin(TestMachine machine, StateDatabase db, CliCommand.Admin command, TestAuthenticator? signer, bool userVerified = true, Func<byte[], byte[]>? changeChallenge = null)
    {
        using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(20) };
        TaskCompletionSource<string> line = new(TaskCreationOptions.RunContinuationsAsynchronously);
        PageResult page = new();
        int announced = 0;
        ApprovalSettings settings = new("passkey", null, 0, TimeSpan.FromSeconds(signer is null ? 1 : 20));
        PasskeyMethod method = new(new PasskeyStore(db), settings);
        EnrollmentTarget target = EnrollmentTarget.For(method, new WebApprover(method, settings, text =>
        {
            Interlocked.Increment(ref announced);
            line.TrySetResult(text);
        }, TimeSpan.Zero));
        AdminContext context = new(machine.Deployment.Store, machine.Deployment.Keys, machine.Deployment.HostConfig, machine.Fingerprint, target, target, new AuditLog(db), new StringWriter());
        Task<(int, string)> task = Task.Run(() => AdminCommand.Run(command, context));
        if (await Task.WhenAny(line.Task, task, Task.Delay(TimeSpan.FromSeconds(20))) == line.Task && signer is not null)
        {
            Uri link = new(line.Task.Result[line.Task.Result.IndexOf("http", StringComparison.Ordinal)..]);
            string url = "http://127.0.0.1:" + link.Port + link.AbsolutePath;
            (_, page.Html) = TestState.Get(client, url);
            (page.Status, _) = TestState.Approve(client, url, "http://localhost:" + link.Port, "localhost", signer, userVerified: userVerified, changeChallenge: changeChallenge);
            page.Url = url;
            page.Proof = TestState.LastProofBody;
        }

        Task done = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(20)));
        page.Result = done == task ? task.Result : null;
        page.Announced = Volatile.Read(ref announced);

        return page;
    }

    private static string Decoded(string html) => WebUtility.HtmlDecode(html);

    private static async Task Page(Action<bool, string> check, string root)
    {
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.ES256();
        StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "state"));
        DateTimeOffset created = new(2026, 11, 1, 10, 0, 0, TimeSpan.Zero);
        TestState.Add(db, laptop.Record("localhost", "laptop") with { Created = created });
        TestState.Add(db, phone.Record("localhost", "phone") with { Created = created });
        using TestMachine machine = new(Path.Combine(root, "machine"), trusted: false);
        machine.Deployment.EnrollAsync().GetAwaiter().GetResult();
        AuthorityStore store = machine.Deployment.Store;
        string fp = machine.Fingerprint;
        string display = KeyIdentity.Display(fp);
        CliCommand.Admin Cmd(AdminAction action, string? fingerprint = null, string? name = null) => new(action, fingerprint ?? fp, name);

        PageResult none = await RunAdmin(machine, db, Cmd(AdminAction.Approve, fp[..16], "dev laptop"), null);
        check(none.Result is { Code: RunCommand.Denied } && store.Find(fp)!.Status == MachineStatus.Pending && !File.Exists(machine.Deployment.HostConfig.FilePath), "admin approve: with no passkey answer nothing changes and nothing is pinned (" + none.Result?.Detail + ")");
        PageResult wrong = await RunAdmin(machine, db, Cmd(AdminAction.Approve, fp[..16], "dev laptop"), phone);
        check(wrong.Result is { Code: RunCommand.Denied } && wrong.Status == 403 && store.Find(fp)!.Status == MachineStatus.Pending && !File.Exists(machine.Deployment.HostConfig.FilePath), "admin approve: a key that is not an admin key is refused (403), nothing changes");
        PageResult approved = await RunAdmin(machine, db, Cmd(AdminAction.Approve, fp[..16], "dev laptop"), laptop);
        string page = Decoded(approved.Html);
        check(approved.Result is { Code: 0 } && approved.Status == 200 && approved.Announced == 1 && store.Find(fp) is { Status: MachineStatus.Trusted, FriendlyName: "dev laptop" }, "admin approve: the admin key's tap approves the machine (" + approved.Result?.Detail + ")");
        check(page.Contains(display, StringComparison.Ordinal) && page.Contains("approve this machine", StringComparison.Ordinal) && page.Contains("dev laptop", StringComparison.Ordinal), "admin approve: the page shows the action, the full fingerprint and the name");
        check(machine.Deployment.HostConfig.Load().Config is { Authority: not null } config && config.MachineFingerprint == fp, "admin approve: the authority key is pinned in host.json");
        check(store.Audit().Any(entry => entry.Event == "machine-approve" && entry.Actor == "admin passkey laptop"), "admin approve: the audit history names the admin key that tapped");

        (AdminAction Action, string? Name, string Phrase, MachineStatus After)[] steps =
        [
            (AdminAction.Rename, "renamed", "rename this machine", MachineStatus.Trusted),
            (AdminAction.Disable, null, "disable this machine", MachineStatus.Disabled),
            (AdminAction.Enable, null, "enable this machine", MachineStatus.Trusted),
            (AdminAction.Untrust, null, "withdraw trust", MachineStatus.Untrusted),
            (AdminAction.Trust, null, "trust this machine again", MachineStatus.Trusted),
        ];
        foreach ((AdminAction action, string? name, string phrase, MachineStatus after) in steps)
        {
            MachineRecord before = store.Find(fp)!;
            string typed = action == AdminAction.Trust ? fp : fp[..20];
            PageResult denied = await RunAdmin(machine, db, Cmd(action, typed, name), phone);
            MachineRecord unchanged = store.Find(fp)!;
            check(denied.Result is { Code: RunCommand.Denied } && unchanged.Status == before.Status && unchanged.FriendlyName == before.FriendlyName && unchanged.SecurityRevision == before.SecurityRevision, "admin " + action + ": a non-admin key changes nothing");
            PageResult ok = await RunAdmin(machine, db, Cmd(action, typed, name), laptop);
            string text = Decoded(ok.Html);
            check(ok.Result is { Code: 0 } && store.Find(fp)!.Status == after && text.Contains(phrase, StringComparison.Ordinal) && text.Contains(display, StringComparison.Ordinal), "admin " + action + ": the admin tap applies it, and the page named the action and the full fingerprint (" + ok.Result?.Detail + ")");
        }

        check(store.Find(fp)!.FriendlyName == "renamed" && store.Find(fp)!.SecurityRevision == 3, "admin: rename kept the revision; disable and untrust raised it to 3");

        PageResult badState = await RunAdmin(machine, db, Cmd(AdminAction.Enable), laptop);
        check(badState.Result is { Code: RunCommand.Denied } && badState.Announced == 0, "admin enable: a machine that is not Disabled is refused before any page (" + badState.Result?.Detail + ")");
        PageResult unknown = await RunAdmin(machine, db, Cmd(AdminAction.Disable, "00" + fp[2..]), laptop);
        check(unknown.Result is { Code: RunCommand.Denied } && unknown.Announced == 0, "admin disable: an unknown fingerprint is refused before any page");
        store.Disable(fp, "test");
        store.Untrust(fp, "test");
        PageResult prefixTrust = await RunAdmin(machine, db, Cmd(AdminAction.Trust, fp[..20]), laptop);
        check(prefixTrust.Result is { Code: RunCommand.Denied } && prefixTrust.Announced == 0, "admin trust: a fingerprint prefix is not the confirmation; refused before any page");
        store.Trust(fp, fp, "test");

        PageResult disable = await RunAdmin(machine, db, Cmd(AdminAction.Disable), laptop);
        string disableText = Decoded(disable.Html);
        check(disable.Result is { Code: 0 } && disableText.Contains("disable this machine", StringComparison.Ordinal) && !disableText.Contains("enable this machine", StringComparison.Ordinal), "admin: the page text (which the passkey signs) names exactly the requested action");

        store.Enable(fp, "test");
        store.RecordHostMismatch(fp, "other-host");
        PageResult host = await RunAdmin(machine, db, Cmd(AdminAction.ApproveHostChange), laptop);
        check(host.Result is { Code: 0 } && Decoded(host.Html).Contains("other-host", StringComparison.Ordinal) && store.Find(fp) is { HostName: "other-host", PendingHostName: null }, "admin approve-host-change: the page shows the new name; the tap binds it");

        // A state that changed while the page was open: the stale tap changes nothing.
        using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(20) };
        TaskCompletionSource<string> line = new(TaskCreationOptions.RunContinuationsAsynchronously);
        ApprovalSettings settings = new("passkey", null, 0, TimeSpan.FromSeconds(20));
        PasskeyMethod method = new(new PasskeyStore(db), settings);
        EnrollmentTarget target = EnrollmentTarget.For(method, new WebApprover(method, settings, text => line.TrySetResult(text), TimeSpan.Zero));
        AdminContext context = new(store, machine.Deployment.Keys, machine.Deployment.HostConfig, fp, target, target, new AuditLog(db), new StringWriter());
        Task<(int Code, string Detail)> pending = Task.Run(() => AdminCommand.Run(Cmd(AdminAction.Disable), context));
        await line.Task;
        store.Disable(fp, "someone else");
        int revisionBefore = store.Find(fp)!.SecurityRevision;
        Uri link = new(line.Task.Result[line.Task.Result.IndexOf("http", StringComparison.Ordinal)..]);
        TestState.Approve(client, "http://127.0.0.1:" + link.Port + link.AbsolutePath, "http://localhost:" + link.Port, "localhost", laptop);
        (int code, string detail) = await pending;
        check(code == RunCommand.Denied && store.Find(fp) is { Status: MachineStatus.Disabled } stale && stale.SecurityRevision == revisionBefore, "admin: a machine that changed while the page was open is not changed again by the stale tap (" + detail + ")");
    }

    /// <summary>What an administrator change could touch: machine state and the active authority key.</summary>
    private static string Snapshot(AuthorityStore store, string fp)
    {
        MachineRecord m = store.Find(fp)!;

        return string.Join('|', m.Status, m.SecurityRevision, m.FriendlyName, m.HostName, m.PendingHostName, store.ActiveKey()?.Fingerprint, store.Machines().Count);
    }

    /// <summary>
    /// Every machine and key operation of the admin commands is a sensitive administrator operation: a fresh single-use passkey tap with user verification on a page whose
    /// signed text is the operation and its parameters. For each: a key that is not an admin key, an assertion without user verification, a signature over another challenge,
    /// no passkey answer at all, and a replay of an earlier proof each leave the authority exactly as it was (fail closed, no fallback); the genuine tap applies it.
    /// </summary>
    private static async Task Sensitive(Action<bool, string> check, string root)
    {
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.ES256();
        StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "sens-state"));
        DateTimeOffset created = new(2026, 11, 1, 10, 0, 0, TimeSpan.Zero);
        TestState.Add(db, laptop.Record("localhost", "laptop") with { Created = created });
        TestState.Add(db, phone.Record("localhost", "phone") with { Created = created });
        using TestMachine machine = new(Path.Combine(root, "sens-machine"), trusted: false);
        machine.Deployment.EnrollAsync().GetAwaiter().GetResult();
        AuthorityStore store = machine.Deployment.Store;
        string fp = machine.Fingerprint;
        CliCommand.Admin Cmd(AdminAction action, string? fingerprint = null, string? name = null) => new(action, fingerprint ?? fp, name);
        int refusals = 0;

        async Task Operation(string label, CliCommand.Admin command)
        {
            string before = Snapshot(store, fp);
            (string Name, TestAuthenticator? Who, bool Uv, Func<byte[], byte[]>? Change)[] variants =
            [
                ("a key that is not an admin key", phone, true, null),
                ("an assertion without user verification", laptop, false, null),
                ("a signature over another challenge", laptop, true, challenge => System.Security.Cryptography.SHA256.HashData(challenge)),
                ("no passkey answer", null, true, null),
            ];
            foreach ((string name, TestAuthenticator? who, bool uv, Func<byte[], byte[]>? change) in variants)
            {
                PageResult denied = await RunAdmin(machine, db, command, who, uv, change);
                refusals++;
                check(denied.Result is { Code: RunCommand.Denied } && Snapshot(store, fp) == before, $"sensitive {label}: {name} changes nothing and is refused (fail closed)");
            }

            PageResult done = await RunAdmin(machine, db, command, laptop);
            check(done.Result is { Code: 0 } && Snapshot(store, fp) != before, $"sensitive {label}: the genuine fresh tap applies it");

            // The proof of that tap, sent again to its page, changes nothing.
            string settled = Snapshot(store, fp);
            if (done.Url.Length > 0)
            {
                using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(20) };
                TestState.Post(client, done.Url + "/proof", done.Proof);
            }

            check(Snapshot(store, fp) == settled, $"sensitive {label}: replaying the proof changes nothing");
        }

        await Operation("approve", Cmd(AdminAction.Approve, fp[..16], "sens machine"));
        await Operation("rename", Cmd(AdminAction.Rename, fp[..20], "renamed again"));
        await Operation("disable", Cmd(AdminAction.Disable, fp[..20]));
        await Operation("enable", Cmd(AdminAction.Enable, fp[..20]));
        await Operation("untrust", Cmd(AdminAction.Untrust, fp[..20]));
        await Operation("trust", Cmd(AdminAction.Trust, fp));
        store.RecordHostMismatch(fp, "moved-host");
        await Operation("approve-host-change", Cmd(AdminAction.ApproveHostChange, fp[..20]));
        await Operation("rotate-authority-key", new CliCommand.Admin(AdminAction.RotateAuthorityKey));
        await Operation("recover-authority", new CliCommand.Admin(AdminAction.RecoverAuthority));
        check(refusals == 36, "sensitive: nine operations, four refusals each (" + refusals + ")");
    }

    private static async Task KeyCommands(Action<bool, string> check, string root)
    {
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.ES256();
        StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "keys-state"));
        DateTimeOffset created = new(2026, 11, 1, 10, 0, 0, TimeSpan.Zero);
        TestState.Add(db, laptop.Record("localhost", "laptop") with { Created = created });
        TestState.Add(db, phone.Record("localhost", "phone") with { Created = created });
        using TestMachine machine = new(Path.Combine(root, "keys-machine"));
        string first = machine.Deployment.Keys.CurrentRecord().Fingerprint;
        check(Admin("rotate-authority-key") is { Action: AdminAction.RotateAuthorityKey } && Admin("recover-authority") is { Action: AdminAction.RecoverAuthority } && Admin("rotate-authority-key", "ABCDEF123456") is null, "admin parse: rotate-authority-key and recover-authority take no fingerprint");

        PageResult wrong = await RunAdmin(machine, db, new CliCommand.Admin(AdminAction.RotateAuthorityKey, null, null), phone);
        check(wrong.Result is { Code: RunCommand.Denied } && machine.Deployment.Keys.CurrentRecord().Fingerprint == first, "admin rotate-authority-key: a non-admin key changes nothing");
        PageResult rotated = await RunAdmin(machine, db, new CliCommand.Admin(AdminAction.RotateAuthorityKey, null, null), laptop);
        string second = machine.Deployment.Keys.CurrentRecord().Fingerprint;
        check(rotated.Result is { Code: 0 } && second != first && Decoded(rotated.Html).Contains("rotate the authority signing key", StringComparison.Ordinal) && machine.Deployment.Store.TransitionsFrom(first).Count == 1, "admin rotate-authority-key: the admin tap rotates the key with a signed transition");

        PageResult recovered = await RunAdmin(machine, db, new CliCommand.Admin(AdminAction.RecoverAuthority, null, null), laptop);
        string third = machine.Deployment.Keys.CurrentRecord().Fingerprint;
        check(recovered.Result is { Code: 0 } && third != second && machine.Deployment.HostConfig.Load().Config!.Authority!.Fingerprint == third && machine.Deployment.Store.TransitionsFrom(second).Count == 0, "admin recover-authority: the admin tap makes a new key with no transition and pins it for this machine (" + recovered.Result?.Detail + ")");
    }

    private static async Task ReviewFixes(Action<bool, string> check, string root)
    {
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.ES256();
        StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "review-state"));
        DateTimeOffset created = new(2026, 11, 1, 10, 0, 0, TimeSpan.Zero);
        TestState.Add(db, laptop.Record("localhost", "laptop") with { Created = created });
        TestState.Add(db, phone.Record("localhost", "phone") with { Created = created });

        // L6: the rotate and recover pages create no authority key before the tap.
        using (TestMachine fresh = new(Path.Combine(root, "review-fresh"), trusted: false))
        {
            fresh.Deployment.EnrollAsync().GetAwaiter().GetResult();
            PageResult none = await RunAdmin(fresh, db, new CliCommand.Admin(AdminAction.RotateAuthorityKey, null, null), phone);
            check(none.Result is { Code: RunCommand.Denied } && fresh.Deployment.Store.ActiveKey() is null, "admin rotate-authority-key: a refused page created no authority key");
        }

        // L2: approve on a machine that is already Trusted says so on the page.
        using TestMachine machine = new(Path.Combine(root, "review-machine"));
        PageResult repin = await RunAdmin(machine, db, new CliCommand.Admin(AdminAction.Approve, machine.Fingerprint, "ignored name"), laptop);
        check(repin.Result is { Code: 0 } && Decoded(repin.Html).Contains("re-pin the authority key", StringComparison.Ordinal) && Decoded(repin.Html).Contains("already Trusted", StringComparison.Ordinal) && machine.Deployment.Store.Find(machine.Fingerprint)!.FriendlyName == "test machine", "admin approve: on a Trusted machine the page says it re-pins the key and the name is not changed");

        // L1: a different host name arriving while the page is open is not applied by the tap.
        machine.Deployment.Store.RecordHostMismatch(machine.Fingerprint, "shown-name");
        using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(20) };
        TaskCompletionSource<string> line = new(TaskCreationOptions.RunContinuationsAsynchronously);
        ApprovalSettings settings = new("passkey", null, 0, TimeSpan.FromSeconds(20));
        PasskeyMethod method = new(new PasskeyStore(db), settings);
        EnrollmentTarget target = EnrollmentTarget.For(method, new WebApprover(method, settings, text => line.TrySetResult(text), TimeSpan.Zero));
        AdminContext context = new(machine.Deployment.Store, machine.Deployment.Keys, machine.Deployment.HostConfig, machine.Fingerprint, target, target, new AuditLog(db), new StringWriter());
        Task<(int Code, string Detail)> pending = Task.Run(() => AdminCommand.Run(new CliCommand.Admin(AdminAction.ApproveHostChange, machine.Fingerprint, null), context));
        await line.Task;
        machine.Deployment.Store.RecordHostMismatch(machine.Fingerprint, "other-name");
        Uri link = new(line.Task.Result[line.Task.Result.IndexOf("http", StringComparison.Ordinal)..]);
        TestState.Approve(client, "http://127.0.0.1:" + link.Port + link.AbsolutePath, "http://localhost:" + link.Port, "localhost", laptop);
        (int code, string detail) = await pending;
        check(code == RunCommand.Denied && machine.Deployment.Store.Find(machine.Fingerprint) is { HostName: "test-host", PendingHostName: "other-name" }, "admin approve-host-change: a host name that replaced the shown one is not applied by the tap (" + detail + ")");
    }

    private static void Listing(Action<bool, string> check, string root)
    {
        using TestMachine machine = new(Path.Combine(root, "listing"));
        StringWriter output = new();
        StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "listing-state"));
        int code = CommandWiring.Admin(new CliCommand.Admin(AdminAction.Machines, null, null), db, machine.Folder, null, output);
        string text = output.ToString();
        check(code == 0 && text.Contains(machine.Fingerprint, StringComparison.Ordinal) && text.Contains("Trusted", StringComparison.Ordinal) && text.Contains("rev 1", StringComparison.Ordinal) && text.Contains("test machine", StringComparison.Ordinal), "admin machines: lists fingerprint, status, revision, host name and friendly name, with no passkey (" + text.Trim() + ")");
        StringWriter empty = new();
        int emptyCode = CommandWiring.Admin(new CliCommand.Admin(AdminAction.Machines, null, null), db, Path.Combine(root, "nothing-here"), null, empty);
        check(emptyCode == 0 && empty.ToString().Contains("No machine has contacted", StringComparison.Ordinal) && !Directory.Exists(Path.Combine(root, "nothing-here")), "admin machines: an empty authority says how to enroll and creates nothing");
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
        int code = await LaunchClient.RunAsync(args, work, port, null, new StringWriter(), err, trust);

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
            check(code == 7 && unpinnedService.LaunchesSeen == 0 && err.Contains(KeyIdentity.Fingerprint(real.PublicKey), StringComparison.Ordinal) && err.Contains("admin approve", StringComparison.Ordinal), "client: with no pin it prints the service's fingerprint, names admin approve and refuses (" + err.Trim() + ")");
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

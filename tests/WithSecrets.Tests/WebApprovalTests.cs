using System.Buffers.Text;
using System.Formats.Cbor;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WithSecrets.Tests;

internal sealed class FakeProofMethod : IProofMethod
{
    public const string Payload = "{\"rpId\":\"localhost\",\"note\":\"</script><b>\"}";
    /// <summary>The proof the fake accepts, as Verify gets it.</summary>
    public const string Inner = "{\"proof\":\"good\"}";

    /// <summary>What the page posts for it: approve once (0 minutes) and the proof.</summary>
    public const string Good = "{\"reuse\":0,\"proof\":" + Inner + "}";

    private int _verified;

    public Exception? StartThrows { get; init; }

    public bool VerifyThrows { get; init; }

    public ProofContext? Started { get; private set; }

    public ProofContext? Checked { get; private set; }

    public string? Response { get; private set; }

    public int Verified => Volatile.Read(ref _verified);

    public string Id => "fake";

    public ProofStart Start(ProofContext context)
    {
        Started = context;
        if (StartThrows is not null)
        {
            throw StartThrows;
        }

        return new ProofStart("webauthn", Payload);
    }

    public ProofResult Verify(ProofContext context, string response)
    {
        Interlocked.Increment(ref _verified);
        Checked = context;
        Response = response;
        if (VerifyThrows)
        {
            throw new InvalidOperationException("verify broke");
        }

        return response == Inner ? new ProofResult(true, "ok") : new ProofResult(false, "the fake said no");
    }

    public IReadOnlyList<EnrolledEntry> Enrolled() => [];

    public bool CanProve(string rpId) => false;

    public ApprovalDecision Enroll(string name, Action<string> announce, Func<string, ManifestApproval>? askAdmin = null, Unlock? approval = null) => ApprovalDecision.Deny("not in the fake");

    public ApprovalDecision Unenroll(string name, Func<string, ManifestApproval> askAdmin) => ApprovalDecision.Deny("not in the fake");
}

/// <summary>A proof method that records what <see cref="Enrollment" /> asks of it. Start is logged as "ask".</summary>
internal sealed class FakeEnrollMethod : IProofMethod
{
    private readonly List<string> _log = [];

    public List<EnrolledEntry> Entries { get; init; } = [];

    public bool UnenrollResult { get; init; } = true;

    public string Id => "fake";

    public string[] Calls()
    {
        lock (_log)
        {
            return [.. _log];
        }
    }

    public ProofStart Start(ProofContext context)
    {
        Add("ask");

        return new ProofStart("webauthn", "{}");
    }

    public ProofResult Verify(ProofContext context, string response)
    {
        return response == FakeProofMethod.Inner ? new ProofResult(true, "ok") : new ProofResult(false, "the fake said no");
    }

    public IReadOnlyList<EnrolledEntry> Enrolled() => Entries;

    public bool CanProve(string rpId) => Entries.Any(item => item.Detail == rpId);

    public ApprovalDecision Enroll(string name, Action<string> announce, Func<string, ManifestApproval>? askAdmin = null, Unlock? approval = null)
    {
        Add("enroll:" + name);

        return ApprovalDecision.Allow("enrolled " + name);
    }

    /// <summary>Asks the admin to sign a stand-in state (logged as "ask"), then removes (logged as "unenroll:NAME").</summary>
    public ApprovalDecision Unenroll(string name, Func<string, ManifestApproval> askAdmin)
    {
        ManifestApproval approval = askAdmin("fake-state");
        if (!approval.Decision.Approved)
        {
            return approval.Decision;
        }

        Add("unenroll:" + name);

        return UnenrollResult ? ApprovalDecision.Allow("removed " + name) : ApprovalDecision.Deny("nothing was removed");
    }

    private void Add(string call)
    {
        lock (_log)
        {
            _log.Add(call);
        }
    }
}

internal static partial class WebApprovalTests
{
    public static async Task Run(Action<bool, string> check)
    {
        byte[] expected = SHA256.HashData(Encoding.UTF8.GetBytes("n\nt"));
        check(RequestBinding.Compute("n", "t").AsSpan().SequenceEqual(expected), "binding: SHA256 of nonce, newline, text");
        check(!RequestBinding.Compute("n", "t").AsSpan().SequenceEqual(RequestBinding.Compute("m", "t")), "binding: nonce changes it");
        check(!RequestBinding.Compute("n", "t").AsSpan().SequenceEqual(RequestBinding.Compute("n", "u")), "binding: text changes it");

        ApprovalSettings set = new("https://ws.example.com/path", 8123, TimeSpan.FromMinutes(30));
        check(set.PageOrigin(1) == "https://ws.example.com", "approval settings: origin from baseUrl");
        check(new ApprovalSettings(null, 0, TimeSpan.FromMinutes(5)).PageOrigin(5123) == "http://localhost:5123", "approval settings: localhost origin");

        string passkeyFolder = Path.Combine(Path.GetTempPath(), "ws-pk-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(passkeyFolder);
        try
        {
            string path = Path.Combine(passkeyFolder, "sub", "passkeys.db");
            PasskeyStore store = new(path);
            check(store.All().Count == 0, "passkeys: missing file gives empty list");

            DateTimeOffset created = new(2026, 11, 1, 10, 0, 0, TimeSpan.Zero);
            using TestAuthenticator one = TestAuthenticator.ES256();
            using TestAuthenticator two = TestAuthenticator.RS256();
            PasskeyRecord first = one.Record("localhost", "laptop") with { Created = created, Admin = true };
            PasskeyRecord second = two.Record("ws.example.com", "phone") with { Created = created.AddMinutes(1) };
            check(store.Add(first) && store.Add(second), "passkeys: add two records");
            IReadOnlyList<PasskeyRecord> loaded = new PasskeyStore(path).All();
            check(loaded.Count == 2 && loaded[0] == first with { Slot = loaded[0].Slot } && loaded[1] == second with { Slot = loaded[1].Slot } && loaded.All(item => item.Slot is not null), "passkeys: records survive a new store (with a key slot, which the state re-wraps for its own master key); the first is the admin");
            check(store.ForRp("localhost").Select(item => item.Id).SequenceEqual([first.Id]), "passkeys: ForRp filters");
            check(store.ForRp("other").Count == 0, "passkeys: ForRp with no match is empty");
            check(!store.Add(first with { Name = "again" }) && store.All().Count == 2, "passkeys: duplicate Id refused");

            check(store.UpdateSignCount(first.Id, 4000000000u) && !store.UpdateSignCount(first.Id, 7) && new PasskeyStore(path).All()[0].SignCount == 4000000000u, "passkeys: a lower sign count is not saved");
            check(store.UpdateSignCount(first.Id, 4000000007u) && new PasskeyStore(path).All()[0].SignCount == 4000000007u, "passkeys: sign count persists");
            check(!store.UpdateSignCount("nope", 1), "passkeys: update of unknown id is false");
            check(!store.RemoveById("nope"), "passkeys: remove of an absent Id is false");
            check(!store.RemoveById(first.Id) && store.All().Count == 2, "passkeys: the admin key is not removed");
            check(store.RemoveById(second.Id) && new PasskeyStore(path).All().Select(item => item.Id).SequenceEqual([first.Id]), "passkeys: remove by Id");
            check(store.TryAll(out IReadOnlyList<PasskeyRecord> strict) && strict.Select(item => item.Id).SequenceEqual([first.Id]), "passkeys: TryAll reads a good file");
            check(new PasskeyStore(Path.Combine(passkeyFolder, "none.json")).TryAll(out IReadOnlyList<PasskeyRecord> none) && none.Count == 0, "passkeys: TryAll of a missing file is true and empty");
            check(store.UnreadableMessage == "cannot read passkeys.db; fix or delete it", "passkeys: the unreadable message names the file");

            foreach (string content in new[] { "", "not json", "{\"a\":1}", "[null]", "null", "[{\"Id\":\"x\"}]" })
            {
                File.WriteAllText(path, content);
                check(new PasskeyStore(path).All().Count == 0, $"passkeys: bad file '{content}' gives empty list");
                check(!new PasskeyStore(path).TryAll(out IReadOnlyList<PasskeyRecord> bad) && bad.Count == 0, $"passkeys: TryAll of bad file '{content}' is false, not empty");
                check(!new PasskeyStore(path).Add(first) && File.ReadAllText(path) == content, $"passkeys: Add to bad file '{content}' is refused and leaves it alone");
                check(!new PasskeyStore(path).UpdateSignCount(first.Id, 4000000099u) && File.ReadAllText(path) == content, $"passkeys: UpdateSignCount on bad file '{content}' is refused");
            }

            File.WriteAllText(path, "[]");
            using (new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                check(!new PasskeyStore(path).TryAll(out _), "passkeys: TryAll of a locked file is false");
            }

            string blocked = Path.Combine(passkeyFolder, "file.txt");
            File.WriteAllText(blocked, "x");
            check(!new PasskeyStore(Path.Combine(blocked, "passkeys.db")).Add(first), "passkeys: add returns false on IO error");
        }
        finally
        {
            Directory.Delete(passkeyFolder, true);
        }

        AssertionTests(check);
        RegistrationTests(check);
        OriginTests(check);
        await ServerTests(check);
        await PasskeyMethodTests(check);

        // Enrollment: the commands, the generic flow, and the passkey page.
        RemovedCliTests(check);
        await EnrollmentTests(check);
        await PasskeyEnrollTests(check);

        // Where enroll and unenroll are approved and made: --local and the two targets.
        await FakeTargetTests(check);
        await PasskeyTargetTests(check);

        // Setting and removing secrets through the web page.
        SecretCryptoTests(check);
        SecretEntryTests(check);
        SecretFlowsTests(check);
        SecretFlowsExpiryTests(check);
        PageSettingsFlowTests(check);

        // A run through the real chain with a real child process.
        await RunChainTests(check);
    }

    /// <summary>The commands that moved into the admin web app are gone from the command line: they are refused, and the help does not list them.</summary>
    private static void RemovedCliTests(Action<bool, string> check)
    {
        string[][] gone =
        [
            ["--set", "A"], ["--remove", "A"], ["--list"], ["-List"], ["--enroll"], ["--enrolled"], ["--unenroll", "a"], ["--rotate-key"], ["--local"], ["--config"], ["--revoke"],
            ["--enroll", "--local"], ["--set", "A", "--port", "9000"],
        ];
        foreach (string[] args in gone)
        {
            check(CliArgs.Parse(args, out string error) is null && error.Length > 0, "cli: " + string.Join(' ', args) + " is refused (" + error + ")");
        }

        check(CliArgs.Parse(["--help"], out _) is CliCommand.Help { Text: var help }
            && new[] { "--set", "--remove", "--list", "--enroll", "--unenroll", "--rotate-key", "--local", "--config", "--revoke" }.All(word => !help.Contains(word, StringComparison.Ordinal))
            && help.Contains("--recover", StringComparison.Ordinal) && help.Contains("--needs", StringComparison.Ordinal) && help.Contains("admin web app", StringComparison.Ordinal), "cli: --help names only what is left, and sends the rest to the admin web app");
        check(CliArgs.Parse(["--secrets", ""], out string nothing) is null && nothing.StartsWith("Nothing to do.", StringComparison.Ordinal) && nothing.Contains("--recover", StringComparison.Ordinal) && !nothing.Contains("--enroll", StringComparison.Ordinal), "cli: 'Nothing to do' names what is left");
        check(CliArgs.Parse(["--recover", "--needs"], out string two) is null && two.Contains("one command at a time", StringComparison.Ordinal), "cli: two commands are one too many");
        check(CliArgs.Parse(["--recover", "--port", "9000"], out _) is CliCommand.Recover { Port: 9000 } && CliArgs.Parse(["--needs", "--port", "9000"], out _) is null, "cli: --port goes with --recover and a run, not with --needs");
    }

    /// <summary>The generic Enrollment with fake targets: no passkeys, only host names and CanProve.</summary>
    private static async Task FakeTargetTests(Action<bool, string> check)
    {
        using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
        client.Timeout = TimeSpan.FromSeconds(20);
        DateTimeOffset when = new(2026, 11, 1, 10, 0, 0, TimeSpan.Zero);
        List<EnrolledEntry> entries = [new("laptop", "b.example", when)];

        // The command target is A; only B has an entry that works. The ask goes to B, the change to A.
        {
            FakeEnrollMethod a = new() { Entries = entries };
            FakeEnrollMethod b = new() { Entries = entries };
            (ApprovalDecision? decision, string page, int announced) = await TargetRun(client, a, b, "a.example", "b.example", item => item.Enroll(), FakeProofMethod.Good);
            check(decision is { Approved: true, Detail: "enrolled passkey" } && b.Calls().SequenceEqual(["ask"]) && a.Calls().SequenceEqual(["enroll:passkey"]) && announced == 1, "targets: Enroll asks at the other target and enrolls at the command target (" + string.Join(",", a.Calls()) + "|" + string.Join(",", b.Calls()) + ")");
            check(page.Contains(">Add a fake for http://localhost. Its name is chosen on the next page.\n" + ApprovalSummary.IssuedPrefix, StringComparison.Ordinal), "targets: the ask text names the command target's origin");
        }

        {
            FakeEnrollMethod a = new() { Entries = entries };
            FakeEnrollMethod b = new() { Entries = entries };
            (ApprovalDecision? decision, _, _) = await TargetRun(client, a, b, "a.example", "b.example", item => item.Unenroll("laptop"), FakeProofMethod.Good);
            check(decision is { Approved: true } && b.Calls().SequenceEqual(["ask"]) && a.Calls().SequenceEqual(["unenroll:laptop"]), "targets: Unenroll asks at the other target and removes at the command target (" + string.Join(",", a.Calls()) + "|" + string.Join(",", b.Calls()) + ")");
        }

        // The command target works itself: it asks.
        {
            FakeEnrollMethod a = new() { Entries = entries };
            FakeEnrollMethod b = new() { Entries = entries };
            (ApprovalDecision? decision, _, _) = await TargetRun(client, a, b, "b.example", "a.example", item => item.Enroll(), FakeProofMethod.Good);
            check(decision is { Approved: true } && a.Calls().SequenceEqual(["ask", "enroll:passkey"]) && b.Calls().Length == 0, "targets: the command target asks when it can prove (" + string.Join(",", a.Calls()) + "|" + string.Join(",", b.Calls()) + ")");
        }

        // Nothing works at either host: deny, name both, start nothing.
        foreach (bool unenroll in new[] { false, true })
        {
            FakeEnrollMethod a = new() { Entries = entries };
            FakeEnrollMethod b = new() { Entries = entries };
            (ApprovalDecision? decision, _, int announced) = await TargetRun(client, a, b, "c.example", "d.example", item => unenroll ? item.Unenroll("laptop") : item.Enroll());
            check(decision is { Approved: false } && decision.Detail.Contains("c.example", StringComparison.Ordinal) && decision.Detail.Contains("d.example", StringComparison.Ordinal) && announced == 0 && a.Calls().Length == 0 && b.Calls().Length == 0, "targets: no working entry denies and names both hosts, " + (unenroll ? "Unenroll" : "Enroll") + " (" + decision?.Detail + ")");
        }

        // Nothing enrolled at all: Enroll is refused; the first entry comes with the settings (--config).
        {
            FakeEnrollMethod a = new();
            FakeEnrollMethod b = new();
            (ApprovalDecision? decision, _, int announced) = await TargetRun(client, a, b, "a.example", "b.example", item => item.Enroll());
            check(decision is { Approved: false } && decision.Detail.Contains("with-secrets admin", StringComparison.Ordinal) && announced == 0 && a.Calls().Length == 0, "targets: with nothing enrolled, Enroll is refused and points to --config (" + decision?.Detail + ")");
        }
    }

    /// <summary>Runs one call on an Enrollment whose command target is A and other target is B, both with real approvers at localhost.</summary>
    private static async Task<(ApprovalDecision? Decision, string Page, int Announced)> TargetRun(HttpClient client, FakeEnrollMethod a, FakeEnrollMethod b, string hostA, string hostB, Func<Enrollment, ApprovalDecision> call, string? answer = null)
    {
        TaskCompletionSource<string> line = new(TaskCreationOptions.RunContinuationsAsynchronously);
        int announced = 0;
        ApprovalSettings settings = new(null, 0, TimeSpan.FromSeconds(20));
        void Announce(string text)
        {
            Interlocked.Increment(ref announced);
            line.TrySetResult(text);
        }

        Enrollment enrollment = new(
            new EnrollmentTarget(a, new WebApprover(a, settings, Announce, TimeSpan.Zero), hostA),
            new EnrollmentTarget(b, new WebApprover(b, settings, Announce, TimeSpan.Zero), hostB),
            _ => { });
        Task<ApprovalDecision> task = Task.Run(() => call(enrollment));
        Task first = await Task.WhenAny(line.Task, task, Task.Delay(TimeSpan.FromSeconds(20)));
        string page = "";
        if (first == line.Task)
        {
            Uri link = new(line.Task.Result[AnnouncePrefix.Length..]);
            string baseUrl = "http://127.0.0.1:" + link.Port + link.AbsolutePath;
            page = Text(Send(client, HttpMethod.Get, baseUrl));
            Send(client, HttpMethod.Post, baseUrl + "/proof", answer ?? "")?.Dispose();
        }

        Task done = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(20)));

        return (done == task ? task.Result : null, page, Volatile.Read(ref announced));
    }

    private static int FreePort()
    {
        using TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start();

        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }


    /// <summary>
    /// Real passkeys with an https baseUrl on a fixed port. The servers listen on 127.0.0.1 only, but the links, the rpId and
    /// the origin in what the authenticator signs follow baseUrl, so the whole flow runs without TLS.
    /// </summary>
    private static async Task PasskeyTargetTests(Action<bool, string> check)
    {
        string folder = Path.Combine(Path.GetTempPath(), "ws-target-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
            client.Timeout = TimeSpan.FromSeconds(20);
            int port = FreePort();
            ApprovalSettings remote = new("https://ws.example.com:" + port, port, TimeSpan.FromSeconds(20));
            ApprovalSettings localOnly = remote with { BaseUrl = null };

            // Keys only for localhost, baseUrl set. --enroll: approved at localhost, enrolled at the baseUrl host.
            {
                PasskeyStore store = new(Path.Combine(folder, "a.json"));
                using TestAuthenticator laptop = TestAuthenticator.ES256();
                using TestAuthenticator phone = TestAuthenticator.RS256();
                check(store.Add(laptop.Record("localhost", "laptop")), "targets passkey: localhost key stored (the admin)");
                (ApprovalDecision? decision, List<string> lines) = await PasskeyTargetRun(client, store, remote, localOnly, false, item => item.Enroll(), laptop, phone);
                check(decision is { Approved: true } && lines.Count == 1 && lines[0].StartsWith(AnnouncePrefix + "http://localhost:", StringComparison.Ordinal), "targets passkey: --enroll prints one link (approved at localhost); the page leads on to the baseUrl host, then to the admin signature at localhost (" + decision?.Detail + "; " + string.Join(" | ", lines) + ")");
                check(store.All().Select(item => (item.Name, item.RpId, item.Admin)).SequenceEqual([("laptop", "localhost", true), ("phone", "ws.example.com", false)]), "targets passkey: the new key is for the baseUrl host and not admin");

                // The admin key does not work at the baseUrl host, so the phone key cannot approve its removal there.
                (decision, lines) = await PasskeyTargetRun(client, store, remote, localOnly, false, item => item.Unenroll("phone"), phone, null);
                check(decision is { Approved: false } && lines.Count == 1 && lines[0].StartsWith(AnnouncePrefix + "http://localhost:", StringComparison.Ordinal) && store.All().Count == 2, "targets passkey: --unenroll asks the admin key at localhost; the phone key cannot approve it (" + decision?.Detail + ")");
                (decision, lines) = await PasskeyTargetRun(client, store, remote, localOnly, false, item => item.Unenroll("phone"), laptop, null);
                check(decision is { Approved: true } && lines.Count == 1 && lines[0].StartsWith(AnnouncePrefix + "http://localhost:", StringComparison.Ordinal) && store.All().Select(item => item.Name).SequenceEqual(["laptop"]), "targets passkey: --unenroll is approved by the admin key at localhost (" + decision?.Detail + ")");

                // The last admin key is never removed.
                (decision, lines) = await PasskeyTargetRun(client, store, remote, localOnly, false, item => item.Unenroll("laptop"), laptop, null);
                check(decision is { Approved: false, Detail: Enrollment.LastAdmin } && lines.Count == 0 && store.All().Count == 1, "targets passkey: --unenroll of the last admin key is refused before anything opens (" + decision?.Detail + ")");
            }

            // The cross-host third link carries the "Also make this key an admin" box: its text says so and its manifest makes the key an admin.
            {
                PasskeyStore store = new(Path.Combine(folder, "a-admin.json"));
                using TestAuthenticator laptop = TestAuthenticator.ES256();
                using TestAuthenticator phone = TestAuthenticator.RS256();
                check(store.Add(laptop.Record("localhost", "laptop")), "targets passkey admin: localhost key stored (the admin)");
                List<string> pages = [];
                (ApprovalDecision? decision, List<string> lines) = await PasskeyTargetRun(client, store, remote, localOnly, false, item => item.Enroll(), laptop, phone, true, pages);
                string third = pages.Count == 4 ? pages[3] : "";
                check(decision is { Approved: true } && lines.Count == 1 && store.All().Select(item => (item.Name, item.Admin)).SequenceEqual([("laptop", true), ("phone", true)]), "targets passkey admin: ticked on the enroll page, the new key is an admin after the third link (" + decision?.Detail + "; " + pages.Count + " pages)");
                check(pages.Count == 4 && pages[2].Contains("\"next\":\"http", StringComparison.Ordinal) && !pages[2].Contains("\"code\"", StringComparison.Ordinal), "targets passkey admin: the code reply says the choice (" + (pages.Count > 2 ? pages[2] : "") + ")");
                check(third.Contains("The new passkey will be an admin", StringComparison.Ordinal) && third.Contains("\\u0022admin\\u0022:true", StringComparison.Ordinal) && third.Split("\\u0022admin\\u0022:true").Length == 3,
                    "targets passkey admin: the third link's text says the new key will be an admin, and the manifest it signs has two admins");
                (decision, lines) = await PasskeyTargetRun(client, store, remote, localOnly, false, item => item.Unenroll("laptop"), phone, null);
                check(decision is { Approved: true } && store.All().Select(item => item.Name).SequenceEqual(["phone"]), "targets passkey admin: the new admin removes the first one at its own host (" + decision?.Detail + "; " + string.Join(" | ", lines) + ")");
            }

            // Not ticked: the third link says the key only approves runs.
            {
                PasskeyStore store = new(Path.Combine(folder, "a-plain.json"));
                using TestAuthenticator laptop = TestAuthenticator.ES256();
                using TestAuthenticator phone = TestAuthenticator.RS256();
                store.Add(laptop.Record("localhost", "laptop"));
                List<string> pages = [];
                (ApprovalDecision? decision, _) = await PasskeyTargetRun(client, store, remote, localOnly, false, item => item.Enroll(), laptop, phone, false, pages);
                check(decision is { Approved: true } && pages.Count == 4 && pages[3].Contains("The new passkey will only approve runs (not an admin)", StringComparison.Ordinal) && !store.All().Single(item => item.Name == "phone").Admin,
                    "targets passkey admin: not ticked, the third link says the new key only approves runs (" + decision?.Detail + ")");
            }

            // Only a baseUrl key. --enroll --local: approved at the baseUrl host, enrolled at localhost.
            {
                PasskeyStore store = new(Path.Combine(folder, "b.json"));
                using TestAuthenticator remoteKey = TestAuthenticator.ES256();
                using TestAuthenticator localKey = TestAuthenticator.RS256();
                check(store.Add(remoteKey.Record("ws.example.com", "remote")), "targets passkey: baseUrl key stored");
                (ApprovalDecision? decision, List<string> lines) = await PasskeyTargetRun(client, store, remote, localOnly, true, item => item.Enroll(), remoteKey, localKey, newName: "here");
                check(decision is { Approved: true } && lines.Count == 1 && lines[0].StartsWith(AnnouncePrefix + "https://ws.example.com:" + port + "/a/", StringComparison.Ordinal), "targets passkey: --enroll --local is approved at the baseUrl host, enrolled at localhost, signed at the baseUrl host (" + decision?.Detail + "; " + string.Join(" | ", lines) + ")");
                check(store.All().Select(item => (item.Name, item.RpId)).SequenceEqual([("remote", "ws.example.com"), ("here", "localhost")]), "targets passkey: the new key is for localhost");
            }

            // No key works at either host: deny, name both, open nothing.
            foreach (bool useLocal in new[] { false, true })
            {
                PasskeyStore store = new(Path.Combine(folder, "c" + useLocal + ".json"));
                using TestAuthenticator stranger = TestAuthenticator.ES256();
                using TestAuthenticator second = TestAuthenticator.ES256();
                check(store.Add(stranger.Record("other.example.com", "stranger")) && store.Add(second.Record("other.example.com", "second")), "targets passkey: unrelated keys stored");
                (ApprovalDecision? decision, List<string> lines) = await PasskeyTargetRun(client, store, remote, localOnly, useLocal, item => item.Enroll(), stranger, null);
                check(decision is { Approved: false } && decision.Detail.Contains("localhost", StringComparison.Ordinal) && decision.Detail.Contains("ws.example.com", StringComparison.Ordinal) && lines.Count == 0 && store.All().Count == 2, "targets passkey: no working key denies and names both hosts, local=" + useLocal + " (" + decision?.Detail + ")");
                (decision, lines) = await PasskeyTargetRun(client, store, remote, localOnly, useLocal, item => item.Unenroll("second"), stranger, null);
                check(decision is { Approved: false } && decision.Detail.Contains("localhost", StringComparison.Ordinal) && decision.Detail.Contains("ws.example.com", StringComparison.Ordinal) && lines.Count == 0 && store.All().Count == 2, "targets passkey: Unenroll with no working key denies and names both hosts, local=" + useLocal);
            }

            // CanProve: by host name, false for an unreadable store.
            {
                PasskeyStore store = new(Path.Combine(folder, "d.json"));
                using TestAuthenticator key = TestAuthenticator.ES256();
                PasskeyMethod method = new(store, localOnly);
                check(!method.CanProve("localhost"), "targets passkey: CanProve is false with no keys");
                check(store.Add(key.Record("localhost", "k")) && method.CanProve("localhost") && !method.CanProve("ws.example.com"), "targets passkey: CanProve follows the host name");
                File.WriteAllText(Path.Combine(folder, "bad.json"), "not json");
                check(!new PasskeyMethod(new PasskeyStore(Path.Combine(folder, "bad.json")), localOnly).CanProve("localhost"), "targets passkey: CanProve is false for an unreadable store");
            }
        }
        finally
        {
            Directory.Delete(folder, true);
        }
    }

    /// <summary>
    /// Runs one call on an Enrollment built like Program.cs builds it. Answers the approval link with <paramref name="approver" />
    /// and the enrollment link with <paramref name="creator" />. Returns the decision and every announced line.
    /// </summary>
    private static async Task<(ApprovalDecision? Decision, List<string> Lines)> PasskeyTargetRun(HttpClient client, PasskeyStore store, ApprovalSettings primarySettings, ApprovalSettings localSettings, bool local, Func<Enrollment, ApprovalDecision> call, TestAuthenticator approver, TestAuthenticator? creator, bool makeAdmin = false, List<string>? pages = null, string newName = "phone", PrfMode approval = PrfMode.Normal)
    {
        System.Collections.Concurrent.BlockingCollection<string> queue = [];
        TypedCodes codes = new();
        Action<string> announce = text => queue.Add(text);
        EnrollmentTarget Target(ApprovalSettings forPage)
        {
            PasskeyMethod method = new(store, forPage, codes.Read);

            return EnrollmentTarget.For(method, new WebApprover(method, forPage, announce, TimeSpan.Zero));
        }

        EnrollmentTarget primary = Target(primarySettings);
        EnrollmentTarget other = Target(localSettings);
        Enrollment enrollment = local ? new(other, primary, announce) : new(primary, other, announce);
        Task<ApprovalDecision> task = Task.Run(() => call(enrollment));
        List<string> lines = [];
        DateTime stop = DateTime.UtcNow.AddSeconds(25);
        while (!task.IsCompleted && DateTime.UtcNow < stop)
        {
            if (!queue.TryTake(out string? text, 200))
            {
                continue;
            }

            lines.Add(text);
            if (!text.StartsWith(AnnouncePrefix, StringComparison.Ordinal))
            {
                continue;
            }

            // One link: every later page is reached from the reply of the step before (its next).
            string? current = text[AnnouncePrefix.Length..];
            while (current is not null)
            {
                Uri link = new(current);
                string baseUrl = "http://127.0.0.1:" + link.Port + link.AbsolutePath;
                string origin = link.GetLeftPart(UriPartial.Authority);
                current = null;
                if (link.AbsolutePath.StartsWith("/a/", StringComparison.Ordinal))
                {
                    // An approval page: a run approval (once) or a new state the admin signs (which shows the code last).
                    pages?.Add(Text(Send(client, HttpMethod.Get, baseUrl)));
                    (_, string answer) = TestState.Approve(client, baseUrl, origin, link.IdnHost, approver, approval);
                    current = RecoveryTests.Member(answer, "next");
                    if (RecoveryTests.Member(answer, "code") is { } shown)
                    {
                        codes.Type(shown);
                    }
                }
                else if (link.AbsolutePath.StartsWith("/e/", StringComparison.Ordinal) && creator is not null)
                {
                    // The registration (with the "Also make this key an admin" box), the admin's assertion when the page asks for it, then the code.
                    string page = Text(Send(client, HttpMethod.Get, baseUrl));
                    pages?.Add(page);
                    byte[] challenge = Bytes(Options(page), "challenge");
                    string registration = TestState.Register(creator, challenge, origin, link.IdnHost, "key");
                    registration = registration[..^1] + ",\"name\":" + JsonSerializer.Serialize(newName) + (makeAdmin ? ",\"admin\":true}" : "}");

                    string reply = Text(Send(client, HttpMethod.Post, baseUrl + "/create", registration));
                    pages?.Add(reply);
                    current = RecoveryTests.Member(reply, "next");
                    if (current is null)
                    {
                        codes.Type(CodeOf(TestState.SignStep(client, baseUrl, origin, reply)));
                    }
                }
            }
        }

        Task done = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(20)));

        return (done == task ? task.Result : null, lines);
    }

    private const string EnrollPrefix = "To add the passkey, open this link: ";

    /// <summary>
    /// Runs one <see cref="Enrollment" /> call with the fake. When it asks, the page is read and <paramref name="answer" /> is
    /// posted: "deny", or a proof for /proof. Returns the decision, the approval page and how many links were announced.
    /// </summary>
    private static async Task<(ApprovalDecision? Decision, string Page, int Announced)> EnrollRun(HttpClient client, FakeEnrollMethod method, Func<Enrollment, ApprovalDecision> call, string answer = "deny")
    {
        TaskCompletionSource<string> line = new(TaskCreationOptions.RunContinuationsAsynchronously);
        int announced = 0;
        ApprovalSettings settings = new(null, 0, TimeSpan.FromSeconds(20));
        WebApprover approver = new(method, settings, text =>
        {
            Interlocked.Increment(ref announced);
            line.TrySetResult(text);
        }, TimeSpan.Zero);
        Enrollment enrollment = TestState.Enrollment(method, approver, _ => { });
        Task<ApprovalDecision> task = Task.Run(() => call(enrollment));
        Task first = await Task.WhenAny(line.Task, task, Task.Delay(TimeSpan.FromSeconds(20)));
        string page = "";
        if (first == line.Task)
        {
            Uri link = new(line.Task.Result[AnnouncePrefix.Length..]);
            string baseUrl = "http://127.0.0.1:" + link.Port + link.AbsolutePath;
            page = Text(Send(client, HttpMethod.Get, baseUrl));
            Send(client, HttpMethod.Post, baseUrl + (answer == "deny" ? "/deny" : "/proof"), answer == "deny" ? "" : answer)?.Dispose();
        }

        Task done = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(20)));

        return (done == task ? task.Result : null, page, Volatile.Read(ref announced));
    }

    private static async Task EnrollmentTests(Action<bool, string> check)
    {
        using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
        client.Timeout = TimeSpan.FromSeconds(20);
        DateTimeOffset when = new(2026, 11, 1, 10, 0, 0, TimeSpan.Zero);
        static List<EnrolledEntry> Two(DateTimeOffset at) => [new("laptop", "localhost", at), new("phone", "localhost", at)];

        check(Enrollment.DefaultName == "passkey" && Enrollment.MaxNameLength == 40, "enrollment: default name passkey, at most 40 characters");

        // Nothing enrolled: refused without asking. The first entry (the admin) comes with the settings: with-secrets --config.
        FakeEnrollMethod empty = new();
        (ApprovalDecision? decision, string page, int announced) = await EnrollRun(client, empty, item => item.Enroll());
        check(decision is { Approved: false } && decision.Detail.Contains("with-secrets admin", StringComparison.Ordinal) && announced == 0 && empty.Calls().Length == 0, "enrollment: with nothing enrolled, Enroll is refused and points to --config (" + decision?.Detail + ")");

        // Something enrolled: ask first; approval then enrolls. The name is chosen on the method's page; it suggests one not taken.
        FakeEnrollMethod one = new() { Entries = Two(when) };
        (decision, page, announced) = await EnrollRun(client, one, item => item.Enroll(), FakeProofMethod.Good);
        check(decision is { Approved: true, Detail: "enrolled passkey" } && announced == 1 && one.Calls().SequenceEqual(["ask", "enroll:passkey"]), "enrollment: with something enrolled, Enroll asks first, then enrolls with the suggested name (" + string.Join(",", one.Calls()) + ")");
        check(page.Contains(">Add a fake for http://localhost. Its name is chosen on the next page.\n" + ApprovalSummary.IssuedPrefix, StringComparison.Ordinal), "enrollment: the ask text says what is added and for which site");
        FakeEnrollMethod taken = new() { Entries = [new("laptop", "localhost", when), new("PassKey", "localhost", when), new("passkey 2", "localhost", when)] };
        (decision, _, _) = await EnrollRun(client, taken, item => item.Enroll(), FakeProofMethod.Good);
        check(decision is { Approved: true } && taken.Calls().SequenceEqual(["ask", "enroll:passkey 3"]), "enrollment: the suggested name is one not taken, without regard to case (" + string.Join(",", taken.Calls()) + ")");
        check(Enrollment.Suggest([]) == "passkey" && Enrollment.Suggest(["laptop"]) == "passkey" && Enrollment.Suggest(["PASSKEY"]) == "passkey 2", "enrollment: Suggest gives passkey, else passkey 2, 3, ...");

        FakeEnrollMethod refused = new() { Entries = Two(when) };
        (decision, _, _) = await EnrollRun(client, refused, item => item.Enroll());
        check(decision is { Approved: false } && refused.Calls().SequenceEqual(["ask"]), "enrollment: a denied ask enrolls nothing (" + decision?.Detail + ")");

        FakeEnrollMethod badProof = new() { Entries = Two(when) };
        (decision, _, _) = await EnrollRun(client, badProof, item => item.Enroll(), "{\"proof\":\"bad\"}");
        check(decision is { Approved: false } && badProof.Calls().SequenceEqual(["ask"]), "enrollment: a failed proof enrolls nothing");

        // Names that are not allowed: denied before anything starts, for Unenroll. (Enroll names are checked on the page; see the passkey tests.)
        string[] badNames =
        [
            "", "   ", new string('a', 41), "a" + (char)1 + "b", "a\nb", "a\tb", "a" + (char)0x7F + "b", "a" + (char)0x200B + "b",
            "a" + (char)0x202E + "b", "a" + (char)0x2028 + "b", "a" + (char)0xD800 + "b",
        ];
        foreach (string bad in badNames)
        {
            string shown = string.Concat(bad.Select(item => ((int)item).ToString("x", System.Globalization.CultureInfo.InvariantCulture) + " "));
            FakeEnrollMethod named = new() { Entries = Two(when) };
            check(Enrollment.NameError(bad) is not null, "enrollment: name [" + shown + "] breaks the name rules");
            (decision, _, announced) = await EnrollRun(client, named, item => item.Unenroll(bad));
            check(decision is { Approved: false } && announced == 0 && named.Calls().Length == 0, "enrollment: Unenroll with name [" + shown + "] is denied before anything starts");
        }

        check(Enrollment.NameError("  my laptop  ") is null && Enrollment.NameError(new string('a', 40)) is null, "enrollment: a name may have spaces around it (trimmed), and 40 characters are allowed");

        // Unenroll: always ask; remove only on approval.
        FakeEnrollMethod removing = new() { Entries = Two(when) };
        (decision, page, _) = await EnrollRun(client, removing, item => item.Unenroll("LAPTOP"), FakeProofMethod.Good);
        check(decision is { Approved: true } && removing.Calls().SequenceEqual(["ask", "unenroll:laptop"]), "enrollment: Unenroll asks, then removes the stored name (any case) (" + string.Join(",", removing.Calls()) + ")");
        check(page.Contains(">Remove the fake named &quot;laptop&quot;\n" + ApprovalSummary.IssuedPrefix, StringComparison.Ordinal), "enrollment: the remove text names the entry");

        FakeEnrollMethod kept = new() { Entries = Two(when) };
        (decision, _, _) = await EnrollRun(client, kept, item => item.Unenroll("laptop"));
        check(decision is { Approved: false } && kept.Calls().SequenceEqual(["ask"]), "enrollment: a denied Unenroll removes nothing");

        FakeEnrollMethod unknown = new() { Entries = Two(when) };
        (decision, _, announced) = await EnrollRun(client, unknown, item => item.Unenroll("tablet"));
        check(decision is { Approved: false, Detail: "nothing enrolled with that name" } && announced == 0 && unknown.Calls().Length == 0, "enrollment: Unenroll of an unknown name is denied (" + decision?.Detail + ")");

        FakeEnrollMethod admin = new() { Entries = [new("laptop", "localhost", when, true), new("phone", "localhost", when)] };
        (decision, _, announced) = await EnrollRun(client, admin, item => item.Unenroll("LAPTOP"), FakeProofMethod.Good);
        check(decision is { Approved: false, Detail: Enrollment.LastAdmin } && announced == 0 && admin.Calls().Length == 0, "enrollment: the last admin entry is never removed, and nothing is asked (" + decision?.Detail + ")");
        check(Enrollment.LastAdmin.Contains("delete with-secrets.db", StringComparison.Ordinal) && Enrollment.LastAdmin.Contains("with-secrets admin", StringComparison.Ordinal) && Enrollment.LastAdmin.Contains("Also make this key an admin", StringComparison.Ordinal), "enrollment: the message says how to add another admin or start over");
        FakeEnrollMethod twoAdmins = new() { Entries = [new("laptop", "localhost", when, true), new("phone", "localhost", when, true)] };
        (decision, page, _) = await EnrollRun(client, twoAdmins, item => item.Unenroll("laptop"), FakeProofMethod.Good);
        check(decision is { Approved: true } && twoAdmins.Calls().SequenceEqual(["ask", "unenroll:laptop"]), "enrollment: an admin entry is removed when another admin stays (" + decision?.Detail + "; " + string.Join(",", twoAdmins.Calls()) + ")");
        (decision, page, _) = await EnrollRun(client, admin, item => item.Unenroll("phone"), FakeProofMethod.Good);
        check(decision is { Approved: true } && admin.Calls().SequenceEqual(["ask", "unenroll:phone"]) && page.Contains("fake-state", StringComparison.Ordinal), "enrollment: another entry is removed on an approval page that signs the new state (" + string.Join(",", admin.Calls()) + ")");

        FakeEnrollMethod stuck = new() { Entries = Two(when), UnenrollResult = false };
        (decision, _, _) = await EnrollRun(client, stuck, item => item.Unenroll("phone"), FakeProofMethod.Good);
        check(decision is { Approved: false } && stuck.Calls().SequenceEqual(["ask", "unenroll:phone"]), "enrollment: a method that removes nothing is a denial (" + decision?.Detail + ")");

        FakeEnrollMethod twins = new() { Entries = [new("laptop", "localhost", when), new("laptop", "ws.example.com", when)] };
        (decision, _, announced) = await EnrollRun(client, twins, item => item.Unenroll("laptop"), FakeProofMethod.Good);
        check(decision is { Approved: false, Detail: "more than one fake has that name" } && announced == 0 && twins.Calls().Length == 0, "enrollment: two entries with the exact name remove nothing (" + decision?.Detail + ")");

        FakeEnrollMethod listed = new() { Entries = Two(when) };
        (decision, _, _) = await EnrollRun(client, listed, item =>
        {
            IReadOnlyList<EnrolledEntry> entries = item.List();
            return entries.SequenceEqual(Two(when)) ? ApprovalDecision.Allow() : ApprovalDecision.Deny("wrong list");
        });
        check(decision is { Approved: true } && listed.Calls().Length == 0, "enrollment: List gives the method's entries and asks nothing");
    }

    /// <summary>The codes a test "types" in the terminal. A read waits up to 30 s for one, then gives null.</summary>
    private sealed class TypedCodes
    {
        private readonly System.Collections.Concurrent.BlockingCollection<string?> _queue = [];
        private int _reads;

        public int Reads => Volatile.Read(ref _reads);

        public void Type(string? code) => _queue.Add(code);

        public string? Read()
        {
            Interlocked.Increment(ref _reads);

            return _queue.TryTake(out string? code, TimeSpan.FromSeconds(30)) ? code : null;
        }
    }

    /// <summary>
    /// Reads the enrollment page, posts a good registration from <paramref name="who" />, has the admin key sign the new
    /// manifest when the page asks, and returns the code it got, or "".
    /// </summary>
    private static string PostRegistration(HttpClient client, Uri? link, TestAuthenticator who, string name)
    {
        string baseUrl = "http://127.0.0.1:" + link?.Port + link?.AbsolutePath;
        string origin = "http://localhost:" + link?.Port;
        byte[] challenge = Bytes(Options(Text(Send(client, HttpMethod.Get, baseUrl))), "challenge");
        string reply = Text(Send(client, HttpMethod.Post, baseUrl + "/create", TestState.Register(who, challenge, origin, "localhost", name)));

        return CodeOf(TestState.SignStep(client, baseUrl, origin, reply));
    }

    /// <summary>The code in the body of an accepted registration, or "".</summary>
    private static string CodeOf(string body)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(body);

            return document.RootElement.TryGetProperty("code", out JsonElement code) && code.ValueKind == JsonValueKind.String ? code.GetString() ?? "" : "";
        }
        catch (JsonException)
        {
            return "";
        }
    }

    /// <summary>What the admin passkey released at the approval before an enrollment (the master key opens its slot); set by the tests that enroll.</summary>
    private static Func<Unlock?>? _enrollApproval;

    /// <summary>Starts PasskeyMethod.Enroll on its own task and waits for the link it announces. Every announced line goes to <paramref name="lines" />.</summary>
    private static async Task<(Task<ApprovalDecision> Decision, Uri? Link, string Line, int Announced)> StartEnroll(PasskeyMethod method, string name, List<string>? lines = null)
    {
        TaskCompletionSource<string> line = new(TaskCreationOptions.RunContinuationsAsynchronously);
        int announced = 0;
        Unlock? approval = _enrollApproval?.Invoke();
        Task<ApprovalDecision> decision = Task.Run(() => method.Enroll(name, text =>
        {
            Interlocked.Increment(ref announced);
            if (lines is not null)
            {
                lock (lines)
                {
                    lines.Add(text);
                }
            }

            line.TrySetResult(text);
        }, null, approval));
        Task first = await Task.WhenAny(line.Task, decision, Task.Delay(TimeSpan.FromSeconds(20)));
        if (first != line.Task)
        {
            return (decision, null, "", Volatile.Read(ref announced));
        }

        string text = line.Task.Result;
        Uri? link = text.StartsWith(EnrollPrefix, StringComparison.Ordinal) ? new Uri(text[EnrollPrefix.Length..]) : null;

        return (decision, link, text, Volatile.Read(ref announced));
    }

    private static async Task<ApprovalDecision?> Within(Task<ApprovalDecision> task)
    {
        Task first = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(20)));

        return first == task ? task.Result : null;
    }

    /// <summary>The creation options in the enrollment page's data block.</summary>
    private static JsonElement Options(string page)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(Between(page, "<script type=\"application/json\" id=\"options\">", "</script>"));

            TestState.Note(document.RootElement);

            return document.RootElement.Clone();
        }
        catch (JsonException)
        {
            return default;
        }
    }

    private static byte[] Bytes(JsonElement element, string name)
    {
        try
        {
            return element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String
                ? Base64Url.DecodeFromChars(value.GetString()!)
                : [];
        }
        catch (FormatException)
        {
            return [];
        }
    }

    private static async Task PasskeyEnrollTests(Action<bool, string> check)
    {
        string folder = Path.Combine(Path.GetTempPath(), "ws-enroll-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
            client.Timeout = TimeSpan.FromSeconds(20);
            using TestAuthenticator laptop = TestAuthenticator.ES256();
            using TestAuthenticator phone = TestAuthenticator.RS256();
            using HttpClient other = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
            other.Timeout = TimeSpan.FromSeconds(20);
            PasskeyStore store = new(Path.Combine(folder, "passkeys.db"));
            ApprovalSettings settings = new(null, 0, TimeSpan.FromSeconds(20));
            TypedCodes codes = new();
            PasskeyMethod method = new(store, settings, codes.Read);
            using TestAuthenticator admin = TestAuthenticator.ES256();

            // The plain enrollment page needs an admin key: the first key comes with the settings (--config).
            {
                (Task<ApprovalDecision> task, Uri? link, _, int announced) = await StartEnroll(method, "laptop");
                ApprovalDecision? decision = await Within(task);
                check(link is null && announced == 0 && decision is { Approved: false } && decision.Detail.Contains("with-secrets admin", StringComparison.Ordinal), "enroll: with nothing enrolled the page does not open and points to --config (" + decision?.Detail + ")");
            }

            check(store.Add(admin.Record("localhost", "admin")), "enroll: the admin key is enrolled first");
            _enrollApproval = () => TestVault.Unlock(store.Database, admin);

            check(new PasskeyMethod(store, settings).Enroll("laptop", _ => { }) is { Approved: false }, "enroll: without a code reader nothing starts");

            // A good registration is stored with the name, after the code from the page is typed.
            {
                List<string> lines = [];
                (Task<ApprovalDecision> task, Uri? link, string line, int announced) = await StartEnroll(method, "laptop", lines);
                check(link is not null && link.Scheme == "http" && link.Host == "localhost" && link.Port > 0, "enroll: announce gives the link (" + line + ")");
                string token = link?.AbsolutePath.Split('/')[^1] ?? "";
                check(link is not null && link.AbsolutePath == "/e/" + token && token.Length == 22 && line == EnrollPrefix + "http://localhost:" + link.Port + "/e/" + token && announced == 1, "enroll: link is http://localhost:<port>/e/<token>, announced once");
                string baseUrl = "http://127.0.0.1:" + link?.Port + "/e/" + token;
                string origin = "http://localhost:" + link?.Port;

                using HttpResponseMessage? page = Send(client, HttpMethod.Get, baseUrl);
                string body = Text(page);
                check(page?.StatusCode == HttpStatusCode.OK && page.Content.Headers.ContentType?.MediaType == "text/html", "enroll: GET page is 200 text/html");
                string? Header(string name) => page is not null && page.Headers.TryGetValues(name, out IEnumerable<string>? values) ? string.Join(",", values) : null;
                check(Header("Cache-Control") == "no-store" && Header("X-Content-Type-Options") == "nosniff" && Header("Referrer-Policy") == "no-referrer" && Header("X-Frame-Options") == "DENY", "enroll: page has the security headers");
                string csp = Header("Content-Security-Policy") ?? "";
                string script = Between(body, "<script>", "</script>");
                string style = Between(body, "<style>", "</style>");
                static string Hash(string text) => "'sha256-" + Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(text))) + "'";
                check(script.Length > 0 && csp.Contains("script-src " + Hash(script) + ";", StringComparison.Ordinal) && style.Length > 0 && csp.Contains("style-src " + Hash(style) + ";", StringComparison.Ordinal), "enroll: CSP allows the one script and the style by hash");
                check(!script.Contains('\r') && csp.Contains("default-src 'none'", StringComparison.Ordinal) && csp.Contains("frame-ancestors 'none'", StringComparison.Ordinal) && csp.Contains("connect-src 'self'", StringComparison.Ordinal) && !csp.Contains("unsafe", StringComparison.Ordinal), "enroll: CSP is strict and the script has LF line ends");
                check(body.Split("<script").Length - 1 == 2, "enroll: page has one data block and one inline script");
                check(script.Contains("navigator.credentials.create", StringComparison.Ordinal) && body.Contains("id=\"deny\"", StringComparison.Ordinal) && body.Contains("id=\"create\"", StringComparison.Ordinal), "enroll: page creates a passkey and can cancel");
                check(body.Contains("Works on: localhost", StringComparison.Ordinal) && body.Contains("<label for=\"f-key-name\">Passkey name</label>", StringComparison.Ordinal)
                    && body.Contains("maxlength=\"40\" value=\"laptop\" data-default=\"laptop\" data-taken=\"[&quot;admin&quot;]\"", StringComparison.Ordinal), "enroll: page shows the site and the name field, prefilled, with the names already enrolled (" + Between(body, "<input id=\"f-key-name\"", ">") + ")");
                check(!System.Text.RegularExpressions.Regex.IsMatch(body, "\\son[a-z]+=", System.Text.RegularExpressions.RegexOptions.IgnoreCase), "enroll: no inline event attributes");
                check(body.Contains("<input id=\"make-admin\" type=\"checkbox\">", StringComparison.Ordinal) && body.Contains("<label for=\"make-admin\">Also make this key an admin</label>", StringComparison.Ordinal)
                    && !System.Text.RegularExpressions.Regex.IsMatch(body, "id=\"make-admin\"[^>]*checked"), "enroll: the page has the \"Also make this key an admin\" box, not ticked");
                check(script.Contains("admin: makeAdmin.checked", StringComparison.Ordinal), "enroll: the script sends the box with the registration");

                JsonElement options = Options(body);
                byte[] challenge = Bytes(options, "challenge");
                check(challenge.Length == 32, "enroll: challenge is 32 bytes");
                check(options.ValueKind == JsonValueKind.Object && options.EnumerateObject().Select(item => item.Name).SequenceEqual(["challenge", "rp", "user", "pubKeyCredParams", "authenticatorSelection", "attestation", "excludeCredentials", "timeout", "prf"]), "enroll: options have exactly the members of the brief");
                if (options.ValueKind == JsonValueKind.Object)
                {
                    check(options.GetProperty("rp").GetRawText() == "{\"id\":\"localhost\",\"name\":\"with-secrets\"}", "enroll: rp is localhost, with-secrets (" + options.GetProperty("rp").GetRawText() + ")");
                    JsonElement user = options.GetProperty("user");
                    string guid = user.GetProperty("name").GetString() ?? "";
                    check(Bytes(user, "id").Length == 16 && user.GetProperty("displayName").GetString() == guid && user.EnumerateObject().Count() == 3, "enroll: user is 16 random bytes, name and displayName the same id");
                    check(Guid.TryParseExact(guid, "D", out Guid id) && id.ToString() == guid, "enroll: the id is a lowercase GUID");
                    string label = PasskeyLabel.Compose(guid, "laptop");
                    string longLabel = PasskeyLabel.Compose(guid, new string('x', 40));
                    check(label == "with-secrets laptop " + guid && label.StartsWith("with-secrets ", StringComparison.Ordinal) && label.EndsWith(guid, StringComparison.Ordinal), "label: with-secrets, the name, the GUID");
                    check(longLabel.Length == PasskeyLabel.MaxLength && longLabel.StartsWith("with-secrets xxxx", StringComparison.Ordinal) && longLabel.EndsWith(guid, StringComparison.Ordinal)
                        && PasskeyLabel.Compose(guid, "").Equals("with-secrets " + guid, StringComparison.Ordinal), "label: a long name is cut first; prefix and GUID stay; length is at most 64");
                    check(PasskeyLabel.NewId() != PasskeyLabel.NewId(), "label: two creates get different ids");
                    check(script.Contains("passkeyLabel(options.user.name, name)", StringComparison.Ordinal) && script.Contains("function passkeyLabel(guid, name)", StringComparison.Ordinal), "enroll: the page builds the label with the name");
                    check(options.GetProperty("pubKeyCredParams").GetRawText() == "[{\"type\":\"public-key\",\"alg\":-7},{\"type\":\"public-key\",\"alg\":-257}]", "enroll: algorithms -7 and -257 (" + options.GetProperty("pubKeyCredParams").GetRawText() + ")");
                    check(options.GetProperty("authenticatorSelection").GetRawText() == "{\"residentKey\":\"required\",\"requireResidentKey\":true,\"userVerification\":\"required\"}", "enroll: discoverable credential required, user verification required");
                    check(options.GetProperty("attestation").GetString() == "none" && options.GetProperty("excludeCredentials").GetRawText() == "[{\"id\":\"" + Encode(admin.CredentialId) + "\",\"type\":\"public-key\"}]" && options.GetProperty("timeout").GetInt64() == 20000, "enroll: attestation none, the enrolled admin key excluded, timeout from settings");
                }

                using HttpResponseMessage? wrong = Send(client, HttpMethod.Get, "http://127.0.0.1:" + link?.Port + "/e/" + Encode(new byte[16]));
                check(wrong?.StatusCode == HttpStatusCode.NotFound, "enroll: wrong token is 404");
                using HttpResponseMessage? getCreate = Send(client, HttpMethod.Get, baseUrl + "/create");
                check(getCreate?.StatusCode == HttpStatusCode.NotFound && store.All().Count == 1 && !task.IsCompleted, "enroll: GET /create is 404 and stores nothing");
                check(Gone(Send(client, HttpMethod.Post, baseUrl + "/sign", "{}")) && !task.IsCompleted, "enroll: /sign before a registration is 404");

                Manifest before = TestState.Current(store.Database)!;
                using HttpResponseMessage? created = Send(client, HttpMethod.Post, baseUrl + "/create", TestState.Register(laptop, challenge, origin, "localhost", "laptop"));
                string first = Text(created);
                using (JsonDocument step = JsonDocument.Parse(first))
                {
                    JsonElement sign = step.RootElement.GetProperty("sign");
                    Manifest next = Manifest.Parse(sign.GetProperty("manifest").GetString()!, out _)!;
                    check(created?.StatusCode == HttpStatusCode.OK && CodeOf(first) == "" && next is not null && next.Version == before.Version + 1
                        && next.Keys.Single(item => item.Id == Encode(laptop.CredentialId)) is { Admin: false, Name: "laptop" } && next.Admins.Single().Id == Encode(admin.CredentialId)
                        && sign.GetProperty("makeAdmin").ValueKind == JsonValueKind.False,
                        "enroll: a good registration is 200 and asks the admin key to sign the new manifest, with the new key not admin (" + first + ")");
                    check(!sign.TryGetProperty("allowCredentials", out _) && sign.GetProperty("rpId").GetString() == "localhost" && Bytes(sign, "bind").Length == 32,
                        "enroll: no allowCredentials is sent (the server checks the signer is an admin), for this host, over a fresh bind");
                }

                check(Gone(Send(other, HttpMethod.Post, baseUrl + "/create", TestState.Register(phone, challenge, origin, "localhost", "laptop"))), "enroll: a second registration while the sign step is open is 404");
                string reply = TestState.SignStep(client, baseUrl, origin, first);
                string code = CodeOf(reply);
                check(code.Length == 6 && code.All(char.IsAsciiDigit) && reply == JsonSerializer.Serialize(new { ok = true, code, admin = "Admins: " + before.Admins.Single().Name + " " + GrantTests.Expected(admin) }), "enroll: the admin's assertion over the manifest gets the 6-digit code and the admin keys' fingerprints (" + reply + ")");
                await Task.Delay(200);
                check(store.All().Count == 1 && !task.IsCompleted, "enroll: nothing is stored before the code is typed");
                using HttpResponseMessage? second = Send(other, HttpMethod.Post, baseUrl + "/create", TestState.Register(phone, challenge, origin, "localhost", "laptop"));
                check(second?.StatusCode == HttpStatusCode.NotFound && CodeOf(Text(second)) == "", "enroll: a registration from a second client after the first is 404 with no code");
                check(Gone(Send(other, HttpMethod.Get, baseUrl)), "enroll: the page is no longer served once a code is out");
                check(Gone(Send(client, HttpMethod.Post, baseUrl + "/sign", "{}")) && !task.IsCompleted, "enroll: a second Step 2 (/sign) after the code is out is 404 and ends nothing");
                codes.Type(code);
                ApprovalDecision? decision = await Within(task);
                check(decision is { Approved: true } && decision.Detail == "Added the passkey named \"laptop\" for localhost." && codes.Reads == 1, "enroll: the right code stores the key (" + decision?.Detail + ")");
                check(TestState.Current(store.Database)!.Version == before.Version + 1 && store.All().Single(item => item.Admin).Id == Encode(admin.CredentialId), "enroll: the new manifest is stored; the admin is unchanged");
                check(lines.Count == 1 && !lines.Any(item => item.Contains(code, StringComparison.Ordinal)) && !(decision?.Detail ?? "").Contains(code, StringComparison.Ordinal), "enroll: the code is not in anything announced or in the result");
                IReadOnlyList<PasskeyRecord> keys = store.All();
                PasskeyRecord? added = keys.FirstOrDefault(item => item.Name == "laptop");
                check(keys.Count == 2 && added is { Admin: false, RpId: "localhost", Alg: -7 } && added.Id == Encode(laptop.CredentialId) && added.PublicKey == Encode(laptop.CoseKey()), "enroll: the key lands in the store with the name, not admin");
                byte[] bind = RequestBinding.Compute("n", "t");
                check(method.Verify(new ProofContext(bind, "http://localhost:5123"), laptop.Assert(bind, "http://localhost:5123", "localhost", 1)).Ok, "enroll: the stored key then approves a request");
                check(Gone(Send(client, HttpMethod.Get, baseUrl)) && link is not null && RefusesBoth(link.Port), "enroll: page is gone and the port released after enrolling");
            }

            // A registration made for another challenge stores nothing, and ends the enrollment.
            {
                (Task<ApprovalDecision> task, Uri? link, _, _) = await StartEnroll(method, "phone");
                string baseUrl = "http://127.0.0.1:" + link?.Port + link?.AbsolutePath;
                string origin = "http://localhost:" + link?.Port;
                string body = Text(Send(client, HttpMethod.Get, baseUrl));
                JsonElement options = Options(body);
                string excluded = options.ValueKind == JsonValueKind.Object ? options.GetProperty("excludeCredentials").GetRawText() : "";
                check(excluded.Contains(Encode(laptop.CredentialId), StringComparison.Ordinal) && excluded.Contains(Encode(admin.CredentialId), StringComparison.Ordinal), "enroll: excludeCredentials lists the keys already stored for this host");
                byte[] challenge = Bytes(options, "challenge");
                using HttpResponseMessage? bad = Send(client, HttpMethod.Post, baseUrl + "/create", TestState.Register(phone, RandomNumberGenerator.GetBytes(32), origin, "localhost", "phone"));
                check(bad?.StatusCode == HttpStatusCode.Forbidden, "enroll: a registration for another challenge is 403");
                ApprovalDecision? decision = await Within(task);
                check(decision is { Approved: false } && decision.Detail.Contains("challenge does not match", StringComparison.Ordinal), "enroll: wrong challenge denies (" + decision?.Detail + ")");
                check(store.All().Count == 2, "enroll: wrong challenge stores nothing");
                check(Gone(Send(client, HttpMethod.Post, baseUrl + "/create", TestState.Register(phone, challenge, origin, "localhost", "phone"))) && store.All().Count == 2, "enroll: a good registration after a bad one is not taken");
            }

            // A registration for another origin stores nothing.
            {
                (Task<ApprovalDecision> task, Uri? link, _, _) = await StartEnroll(method, "phone");
                string baseUrl = "http://127.0.0.1:" + link?.Port + link?.AbsolutePath;
                byte[] challenge = Bytes(Options(Text(Send(client, HttpMethod.Get, baseUrl))), "challenge");
                using HttpResponseMessage? bad = Send(client, HttpMethod.Post, baseUrl + "/create", TestState.Register(phone, challenge, "http://localhost:1", "localhost", "phone"));
                ApprovalDecision? decision = await Within(task);
                check(bad?.StatusCode == HttpStatusCode.Forbidden && decision is { Approved: false } && store.All().Count == 2, "enroll: a registration for another origin is denied (" + decision?.Detail + ")");
            }

            // The new manifest signed by a key other than the admin (the new key itself, or another enrolled key): nothing is added.
            foreach ((string what, Func<TestAuthenticator> signer) in new (string, Func<TestAuthenticator>)[] { ("the new key", () => phone), ("a non-admin enrolled key", () => laptop) })
            {
                (Task<ApprovalDecision> task, Uri? link, _, _) = await StartEnroll(method, "phone");
                string baseUrl = "http://127.0.0.1:" + link?.Port + link?.AbsolutePath;
                string origin = "http://localhost:" + link?.Port;
                byte[] challenge = Bytes(Options(Text(Send(client, HttpMethod.Get, baseUrl))), "challenge");
                string first = Text(Send(client, HttpMethod.Post, baseUrl + "/create", TestState.Register(phone, challenge, origin, "localhost", "phone")));
                string reply = TestState.SignStep(client, baseUrl, origin, first, signer());
                ApprovalDecision? decision = await Within(task);
                check(CodeOf(reply) == "" && decision is { Approved: false } && decision.Detail.Contains("admin passkey did not sign", StringComparison.Ordinal) && store.All().Count == 2, "enroll: the new manifest signed by " + what + " adds nothing (" + decision?.Detail + ")");
            }

            // The admin signs other text (another manifest): nothing is added.
            {
                (Task<ApprovalDecision> task, Uri? link, _, _) = await StartEnroll(method, "phone");
                string baseUrl = "http://127.0.0.1:" + link?.Port + link?.AbsolutePath;
                string origin = "http://localhost:" + link?.Port;
                byte[] challenge = Bytes(Options(Text(Send(client, HttpMethod.Get, baseUrl))), "challenge");
                string first = Text(Send(client, HttpMethod.Post, baseUrl + "/create", TestState.Register(phone, challenge, origin, "localhost", "phone")));
                string reply = TestState.SignStep(client, baseUrl, origin, first, null, (bind, text) => Manifest.Challenge(bind, text.Replace("\"admin\":false", "\"admin\":true", StringComparison.Ordinal)));
                ApprovalDecision? decision = await Within(task);
                check(CodeOf(reply) == "" && decision is { Approved: false } && store.All().Count == 2, "enroll: an admin assertion over other text adds nothing (" + decision?.Detail + ")");
            }

            // A key that is already stored is not added again.
            {
                (Task<ApprovalDecision> task, Uri? link, _, _) = await StartEnroll(method, "again");
                string baseUrl = "http://127.0.0.1:" + link?.Port + link?.AbsolutePath;
                byte[] challenge = Bytes(Options(Text(Send(client, HttpMethod.Get, baseUrl))), "challenge");
                using HttpResponseMessage? again = Send(client, HttpMethod.Post, baseUrl + "/create", TestState.Register(laptop, challenge, "http://localhost:" + link?.Port, "localhost", "again"));
                ApprovalDecision? decision = await Within(task);
                check(again?.StatusCode == HttpStatusCode.Forbidden && decision is { Approved: false, Detail: "that passkey is already enrolled" } && store.All().Count == 2, "enroll: a key already in the store is refused (" + decision?.Detail + ")");
            }

            // Three wrong codes store nothing.
            {
                TypedCodes wrongCodes = new();
                (Task<ApprovalDecision> task, Uri? link, _, _) = await StartEnroll(new PasskeyMethod(store, settings, wrongCodes.Read), "phone");
                string code = PostRegistration(client, link, phone, "phone");
                string wrong = code.Length == 6 ? code[..5] + (code[5] == '9' ? "0" : ((char)(code[5] + 1)).ToString()) : "x";
                wrongCodes.Type(wrong);
                wrongCodes.Type(" " + wrong + " ");
                wrongCodes.Type(code + "0");
                ApprovalDecision? decision = await Within(task);
                check(code.Length == 6 && decision is { Approved: false, Detail: "the code was wrong three times; nothing was added" } && wrongCodes.Reads == 3 && store.All().Count == 2, "enroll: three wrong codes deny and store nothing (" + decision?.Detail + ")");
            }

            // No code (end of input) stores nothing.
            {
                TypedCodes noCode = new();
                (Task<ApprovalDecision> task, Uri? link, _, _) = await StartEnroll(new PasskeyMethod(store, settings, noCode.Read), "phone");
                string code = PostRegistration(client, link, phone, "phone");
                noCode.Type(null);
                ApprovalDecision? decision = await Within(task);
                check(code.Length == 6 && decision is { Approved: false, Detail: "no code was typed; nothing was added" } && store.All().Count == 2, "enroll: no code typed denies and stores nothing (" + decision?.Detail + ")");
            }

            // The time limit runs out while the terminal waits for the code.
            {
                TypedCodes slow = new();
                PasskeyMethod quick = new(store, new ApprovalSettings(null, 0, TimeSpan.FromSeconds(3)), slow.Read);
                (Task<ApprovalDecision> task, Uri? link, _, _) = await StartEnroll(quick, "phone");
                string code = PostRegistration(client, link, phone, "phone");
                ApprovalDecision? decision = await Within(task);
                check(code.Length == 6 && decision is { Approved: false, Detail: "no answer before the time limit" } && store.All().Count == 2, "enroll: no code before the time limit denies and stores nothing (" + decision?.Detail + ")");
                slow.Type(code);
                await Task.Delay(300);
                check(store.All().Count == 2, "enroll: the right code after the time limit stores nothing");
            }

            // Cancel on the page while the terminal waits for the code.
            {
                TypedCodes waiting = new();
                (Task<ApprovalDecision> task, Uri? link, _, _) = await StartEnroll(new PasskeyMethod(store, settings, waiting.Read), "phone");
                string code = PostRegistration(client, link, phone, "phone");
                using HttpResponseMessage? cancel = Send(client, HttpMethod.Post, "http://127.0.0.1:" + link?.Port + link?.AbsolutePath + "/deny", "");
                ApprovalDecision? decision = await Within(task);
                waiting.Type(code);
                check(code.Length == 6 && cancel?.StatusCode == HttpStatusCode.OK && decision is { Approved: false, Detail: "cancelled on the page" } && store.All().Count == 2, "enroll: Cancel after the code was shown stores nothing (" + decision?.Detail + ")");
            }

            // The store gains a key after the enrollment started.
            {
                using TestAuthenticator tablet = TestAuthenticator.ES256();
                (Task<ApprovalDecision> task, Uri? link, _, _) = await StartEnroll(method, "phone");
                string baseUrl = "http://127.0.0.1:" + link?.Port + link?.AbsolutePath;
                byte[] challenge = Bytes(Options(Text(Send(client, HttpMethod.Get, baseUrl))), "challenge");
                check(store.Add(tablet.Record("localhost", "tablet")), "enroll: another key added while the page is open");
                using HttpResponseMessage? late = Send(client, HttpMethod.Post, baseUrl + "/create", TestState.Register(phone, challenge, "http://localhost:" + link?.Port, "localhost", "phone"));
                ApprovalDecision? decision = await Within(task);
                check(late?.StatusCode == HttpStatusCode.Forbidden && CodeOf(Text(late)) == "" && decision is { Approved: false, Detail: "the passkeys changed while you enrolled; nothing was added" }, "enroll: a store that changed since the start is refused (" + decision?.Detail + ")");
                check(store.All().Select(item => item.Name).Order().SequenceEqual(["admin", "laptop", "tablet"]) && store.RemoveById(Encode(tablet.CredentialId)), "enroll: only the other key was added");
            }

            // Three enrollments on an empty store: the first to store wins; the others are refused, before or after their code.
            {
                PasskeyStore race = new(Path.Combine(folder, "race.json"));
                check(race.Add(admin.Record("localhost", "admin")), "enroll race: an admin key first");
                _enrollApproval = () => TestVault.Unlock(race.Database, admin);
                TypedCodes codesA = new();
                TypedCodes codesB = new();
                TypedCodes codesC = new();
                using TestAuthenticator a = TestAuthenticator.ES256();
                using TestAuthenticator b = TestAuthenticator.ES256();
                using TestAuthenticator c = TestAuthenticator.ES256();
                (Task<ApprovalDecision> taskA, Uri? linkA, _, _) = await StartEnroll(new PasskeyMethod(race, settings, codesA.Read), "one");
                (Task<ApprovalDecision> taskB, Uri? linkB, _, _) = await StartEnroll(new PasskeyMethod(race, settings, codesB.Read), "two");
                (Task<ApprovalDecision> taskC, Uri? linkC, _, _) = await StartEnroll(new PasskeyMethod(race, settings, codesC.Read), "three");

                string codeC = PostRegistration(client, linkC, c, "three");
                string codeA = PostRegistration(client, linkA, a, "one");
                codesA.Type(codeA);
                ApprovalDecision? first = await Within(taskA);
                check(first is { Approved: true } && race.All().Select(item => item.Name).SequenceEqual(["admin", "one"]), "enroll race: the first to type its code is stored (" + first?.Detail + ")");
                string codeB = PostRegistration(client, linkB, b, "two");
                ApprovalDecision? secondDecision = await Within(taskB);
                check(codeB == "" && secondDecision is { Approved: false, Detail: "the passkeys changed while you enrolled; nothing was added" }, "enroll race: a registration answered after the first was stored is refused (" + secondDecision?.Detail + ")");
                codesC.Type(codeC);
                ApprovalDecision? third = await Within(taskC);
                check(codeC.Length == 6 && third is { Approved: false, Detail: "the passkeys changed while you enrolled; nothing was added" }, "enroll race: a code typed after another key was stored is refused (" + third?.Detail + ")");
                check(race.All().Select(item => item.Name).SequenceEqual(["admin", "one"]), "enroll race: only the first key is stored");
                _enrollApproval = () => TestVault.Unlock(store.Database, admin);
            }

            // A store that exists but cannot be read is never "nothing enrolled".
            {
                string lockedPath = Path.Combine(folder, "locked.json");
                File.WriteAllText(lockedPath, "[]");
                PasskeyStore locked = new(lockedPath);
                TypedCodes lockedCodes = new();
                PasskeyMethod lockedMethod = new(locked, settings, lockedCodes.Read);
                int approvals = 0;
                Enrollment lockedEnrollment = TestState.Enrollment(lockedMethod, new WebApprover(lockedMethod, settings, _ => approvals++), _ => approvals++);
                using (new FileStream(lockedPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                {
                    (Task<ApprovalDecision> task, Uri? link, _, int announced) = await StartEnroll(lockedMethod, "laptop");
                    ApprovalDecision? decision = await Within(task);
                    check(link is null && announced == 0 && decision is { Approved: false, Detail: "cannot read locked.json; fix or delete it" }, "enroll: a locked store at the start is refused (" + decision?.Detail + ")");
                    ApprovalDecision viaEnrollment = lockedEnrollment.Enroll();
                    check(viaEnrollment is { Approved: false, Detail: "cannot read locked.json; fix or delete it" } && approvals == 0, "enrollment: a locked store is not empty: Enroll is refused without asking (" + viaEnrollment.Detail + ")");
                    ApprovalDecision removal = lockedEnrollment.Unenroll("laptop");
                    check(removal is { Approved: false, Detail: "cannot read locked.json; fix or delete it" } && approvals == 0, "enrollment: a locked store: Unenroll is refused (" + removal.Detail + ")");
                    check(Throws<ProofUnavailableException>(() => lockedEnrollment.List()) is not null, "enrollment: a locked store: List throws, not empty");
                }

                check(File.ReadAllText(lockedPath) == "[]", "enroll: a locked store is left alone");
                File.WriteAllText(lockedPath, "");
                ApprovalDecision empty = lockedEnrollment.Enroll();
                check(empty is { Approved: false, Detail: "cannot read locked.json; fix or delete it" } && approvals == 0 && File.ReadAllText(lockedPath) == "", "enrollment: a zero-byte store is refused (" + empty.Detail + ")");
            }

            // Cancel on the page.
            {
                (Task<ApprovalDecision> task, Uri? link, _, _) = await StartEnroll(method, "phone");
                string baseUrl = "http://127.0.0.1:" + link?.Port + link?.AbsolutePath;
                using HttpResponseMessage? cancel = Send(client, HttpMethod.Post, baseUrl + "/deny", "");
                ApprovalDecision? decision = await Within(task);
                check(cancel?.StatusCode == HttpStatusCode.OK && decision is { Approved: false, Detail: "cancelled on the page" } && store.All().Count == 2, "enroll: Cancel on the page stores nothing (" + decision?.Detail + ")");
                check(link is not null && RefusesBoth(link.Port), "enroll: port released after Cancel");
            }

            // No answer.
            {
                PasskeyMethod quick = new(store, new ApprovalSettings(null, 0, TimeSpan.FromMilliseconds(300)), codes.Read);
                (Task<ApprovalDecision> task, Uri? link, _, _) = await StartEnroll(quick, "phone");
                ApprovalDecision? decision = await Within(task);
                check(link is not null && decision is { Approved: false, Detail: "no answer before the time limit" } && RefusesBoth(link.Port), "enroll: no answer denies and releases the port (" + decision?.Detail + ")");
            }

            // The name on the page: a suggestion that is taken is replaced by one that is not; the program checks the name sent
            // with the registration again: one in use (any case), too long or with bad characters ends the page, and nothing is added.
            {
                (Task<ApprovalDecision> task, Uri? link, _, int announced) = await StartEnroll(method, "LAPTOP");
                string body = Text(Send(client, HttpMethod.Get, "http://127.0.0.1:" + link?.Port + link?.AbsolutePath));
                Send(client, HttpMethod.Post, "http://127.0.0.1:" + link?.Port + link?.AbsolutePath + "/deny", "")?.Dispose();
                await Within(task);
                check(link is not null && body.Contains("value=\"passkey\"", StringComparison.Ordinal), "enroll: a suggestion already enrolled (any case) becomes one that is not (" + Between(body, "<input id=\"f-key-name\"", ">") + ")");

                foreach ((string what, string sent) in new[] { ("a name in use, in another case", "\"LapTop\""), ("a name of 41 characters", "\"" + new string('a', 41) + "\""), ("a control character", "\"a\\u0001b\""),
                    ("a bidi override", "\"a\\u202Eb\""), ("a line break", "\"a\\nb\""), ("a name that is not text", "7") })
                {
                    using TestAuthenticator fresh = TestAuthenticator.ES256();
                    (task, link, _, _) = await StartEnroll(method, "phone");
                    string baseUrl = "http://127.0.0.1:" + link?.Port + link?.AbsolutePath;
                    byte[] challenge = Bytes(Options(Text(Send(client, HttpMethod.Get, baseUrl))), "challenge");
                    string registration = TestState.Register(fresh, challenge, "http://localhost:" + link?.Port, "localhost", "phone");
                    using HttpResponseMessage? reply = Send(client, HttpMethod.Post, baseUrl + "/create", registration[..^1] + ",\"name\":" + sent + "}");
                    ApprovalDecision? refused = await Within(task);
                    check(reply?.StatusCode == HttpStatusCode.BadRequest && !Text(reply).Contains("\"sign\"", StringComparison.Ordinal) && refused is { Approved: false } && store.All().Count == 2,
                        "enroll: " + what + " is refused and nothing is added (" + refused?.Detail + ")");
                }

                // The page checks the same rules before its prompt; the script reads the name at tap time.
                string script = Between(body, "<script>", "</script>");
                check(script.Contains("p{Cc}", StringComparison.Ordinal) && script.Contains("data-taken", StringComparison.Ordinal) && script.Contains("toUpperCase", StringComparison.Ordinal)
                    && script.IndexOf("chosen = chosenName();", StringComparison.Ordinal) is > 0 and var at && at < script.IndexOf("navigator.credentials.create", StringComparison.Ordinal),
                    "enroll: the script checks the name (length, characters, names in use) in the tap, before the prompt");

                ApprovalDecision? decision;

                foreach (string url in new[] { "http://ws.example.com", "http://localhost.evil.example", "http://127.0.0.1:8080" })
                {
                    PasskeyMethod insecure = new(store, new ApprovalSettings(url, 0, TimeSpan.FromSeconds(20)), codes.Read);
                    (task, link, _, announced) = await StartEnroll(insecure, "phone");
                    decision = await Within(task);
                    check(link is null && announced == 0 && decision is { Approved: false } && decision.Detail.Contains("https", StringComparison.Ordinal), "enroll: baseUrl " + url + " is refused before the page opens (" + decision?.Detail + ")");
                }

                check(store.All().Count == 2, "enroll: refusals store nothing");
            }

            // Unenroll removes the record with that name, matched without regard to case, with the admin's signature over the
            // new manifest. Names are unique without regard to case in the manifest, and the admin key is never removed.
            {
                PasskeyStore names = new(Path.Combine(folder, "names.json"));
                PasskeyMethod named = new(names, settings);
                using TestAuthenticator third = TestAuthenticator.ES256();
                int asked = 0;
                ManifestApproval Sign(string text)
                {
                    asked++;
                    return new ManifestApproval(ApprovalDecision.Allow("admin passkey admin verified"), TestState.Sign(admin, text));
                }

                check(names.Add(admin.Record("localhost", "admin")) && names.Add(laptop.Record("localhost", "Work")) && names.Add(phone.Record("localhost", "Phone")) && names.Add(third.Record("localhost", "Home")), "unenroll: records added");
                check(!names.Add(TestAuthenticator.ES256().Record("localhost", "WORK")), "unenroll: a second name that differs only in case is refused by the manifest");
                check(named.Unenroll("nope", Sign) is { Approved: false } && names.All().Count == 4 && asked == 0, "unenroll: an unknown name is refused without asking");
                check(named.Unenroll("Work", Sign) is { Approved: true } && names.All().Select(item => item.Name).SequenceEqual(["admin", "Phone", "Home"]) && asked == 1, "unenroll: the exact name is removed after the admin signs");
                check(named.Unenroll("HOME", Sign) is { Approved: true } && names.All().Select(item => item.Name).SequenceEqual(["admin", "Phone"]), "unenroll: a name in another case removes that record");
                check(named.Unenroll("admin", Sign) is { Approved: false, Detail: Enrollment.LastAdmin } && names.All().Count == 2 && asked == 2, "unenroll: the last admin key is never removed (" + string.Join(",", names.All().Select(item => item.Name)) + ")");
                check(named.Unenroll("Phone", _ => new ManifestApproval(ApprovalDecision.Deny("denied on the page"), null)) is { Approved: false, Detail: "denied on the page" } && names.All().Count == 2, "unenroll: a denied approval removes nothing");
                check(named.Unenroll("Phone", text => new ManifestApproval(ApprovalDecision.Allow(), TestState.Sign(phone, text))) is { Approved: false } && names.All().Count == 2, "unenroll: a new manifest signed by a key other than the admin removes nothing");
                check(named.Unenroll("Phone", text => new ManifestApproval(ApprovalDecision.Allow(), TestState.Sign(admin, text.Replace("\"v\":", "\"v\": ", StringComparison.Ordinal)))) is { Approved: false } && names.All().Count == 2, "unenroll: an approval of another text removes nothing");
                check(names.RemoveById(Encode(phone.CredentialId)) && names.All().Select(item => item.Name).SequenceEqual(["admin"]), "unenroll: removal is by Id, so only that record goes");
            }

            // Through Enrollment: asking with the admin passkey, and the exact texts.
            {
                PasskeyStore single = new(Path.Combine(folder, "single.json"));
                PasskeyMethod lone = new(single, settings);
                check(single.Add(admin.Record("localhost", "admin")) && single.Add(laptop.Record("localhost", "laptop")), "enrollment passkey: the admin and one more key stored");
                TaskCompletionSource<string> line = new(TaskCreationOptions.RunContinuationsAsynchronously);
                WebApprover approver = new(lone, settings, text => line.TrySetResult(text), TimeSpan.Zero);
                Enrollment enrollment = TestState.Enrollment(lone, approver, _ => { });

                ApprovalDecision adminStays = enrollment.Unenroll("ADMIN");
                check(adminStays is { Approved: false, Detail: Enrollment.LastAdmin } && !line.Task.IsCompleted, "enrollment passkey: the last admin key cannot be removed, and nothing is asked");

                foreach ((string what, TestAuthenticator signer, bool removed) in new[] { ("a non-admin key", laptop, false), ("the admin key", admin, true) })
                {
                    line = new(TaskCreationOptions.RunContinuationsAsynchronously);
                    approver = new(lone, settings, text => line.TrySetResult(text), TimeSpan.Zero);
                    enrollment = TestState.Enrollment(lone, approver, _ => { });
                    Task<ApprovalDecision> task = Task.Run(() => enrollment.Unenroll("laptop"));
                    Task first = await Task.WhenAny(line.Task, task, Task.Delay(TimeSpan.FromSeconds(20)));
                    int status = 0;
                    string body = "";
                    if (first == line.Task)
                    {
                        Uri link = new(line.Task.Result[AnnouncePrefix.Length..]);
                        string baseUrl = "http://127.0.0.1:" + link.Port + link.AbsolutePath;
                        body = Text(Send(client, HttpMethod.Get, baseUrl));
                        (status, _) = TestState.Approve(client, baseUrl, "http://localhost:" + link.Port, "localhost", signer);
                    }

                    ApprovalDecision? decision = await Within(task);
                    check(body.Contains(">Remove the passkey named &quot;laptop&quot;\nAdmins: ", StringComparison.Ordinal) && body.Contains("\"manifest\":", StringComparison.Ordinal), "enrollment passkey: the removal page names the key and carries the new manifest");
                    check(removed
                        ? decision is { Approved: true } && status == 200 && single.All().Select(item => item.Name).SequenceEqual(["admin"])
                        : decision is { Approved: false } && status == 403 && single.All().Count == 2,
                        "enrollment passkey: removal approved by " + what + ": " + (removed ? "removed" : "denied, nothing removed") + " (" + decision?.Detail + ")");
                }

                // --enroll: the first approval must come from the admin key; a second key that only approves runs is refused.
                {
                    check(single.Add(laptop.Record("localhost", "laptop")), "enrollment passkey: the second key again");
                    TypedCodes none = new();
                    PasskeyMethod coded = new(single, settings, none.Read);
                    line = new(TaskCreationOptions.RunContinuationsAsynchronously);
                    List<string> announced = [];
                    enrollment = TestState.Enrollment(coded, new WebApprover(coded, settings, text => line.TrySetResult(text), TimeSpan.Zero), text => announced.Add(text));
                    Task<ApprovalDecision> task = Task.Run(() => enrollment.Enroll());
                    Task first = await Task.WhenAny(line.Task, task, Task.Delay(TimeSpan.FromSeconds(20)));
                    int status = 0;
                    if (first == line.Task)
                    {
                        Uri link = new(line.Task.Result[AnnouncePrefix.Length..]);
                        (status, _) = TestState.Approve(client, "http://127.0.0.1:" + link.Port + link.AbsolutePath, "http://localhost:" + link.Port, "localhost", laptop);
                    }

                    ApprovalDecision? decision = await Within(task);
                    check(decision is { Approved: false } && status == 403 && announced.Count == 0 && single.All().Count == 2, "enrollment passkey: --enroll approved by a non-admin key is denied and opens no enrollment page (" + decision?.Detail + ")");
                }
            }
        }
        finally
        {
            Directory.Delete(folder, true);
        }
    }

    /// <summary>
    /// Runs WebApprover.Ask with a PasskeyMethod; <paramref name="respond" /> gets the challenge for "approve once" (the page's
    /// bind with reuse=0) and returns the assertion, which is posted for once.
    /// </summary>
    private static async Task<(ApprovalDecision? Decision, int Status)> PasskeyRun(HttpClient client, PasskeyStore store, Func<byte[], string, string> respond)
    {
        TaskCompletionSource<string> line = new(TaskCreationOptions.RunContinuationsAsynchronously);
        ApprovalSettings settings = new(null, 0, TimeSpan.FromSeconds(20));
        WebApprover approver = new(new PasskeyMethod(store, settings), settings, text => line.TrySetResult(text));
        Task<ApprovalDecision> ask = Task.Run(() => approver.Ask(new ApprovalPrompt("h", "t")));
        Task first = await Task.WhenAny(line.Task, ask, Task.Delay(TimeSpan.FromSeconds(20)));
        if (first != line.Task)
        {
            return (first == ask ? ask.Result : null, 0);
        }

        Uri link = new(line.Task.Result[AnnouncePrefix.Length..]);
        string baseUrl = "http://127.0.0.1:" + link.Port + link.AbsolutePath;
        string body = Text(Send(client, HttpMethod.Get, baseUrl));
        Dictionary<string, string> start = JsonSerializer.Deserialize<Dictionary<string, string>>(Between(body, "<script type=\"application/json\" id=\"start\">", "</script>"))!;
        using HttpResponseMessage? posted = Send(client, HttpMethod.Post, baseUrl + "/proof", ReuseTests.Body(0, respond(ReuseBinding.Challenge(Base64Url.DecodeFromChars(start["bind"]), 0), "http://localhost:" + link.Port)));
        Task done = await Task.WhenAny(ask, Task.Delay(TimeSpan.FromSeconds(20)));

        return (done == ask ? ask.Result : null, (int?)posted?.StatusCode ?? 0);
    }

    private static T? Throws<T>(Action action)
        where T : Exception
    {
        try
        {
            action();
        }
        catch (T error)
        {
            return error;
        }

        return null;
    }

    private static async Task PasskeyMethodTests(Action<bool, string> check)
    {
        string folder = Path.Combine(Path.GetTempPath(), "ws-pkm-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
            client.Timeout = TimeSpan.FromSeconds(20);
            ApprovalSettings settings = new(null, 0, TimeSpan.FromSeconds(90));
            byte[] bind = RequestBinding.Compute("n", "t");
            using TestAuthenticator laptop = TestAuthenticator.ES256();
            using TestAuthenticator other = TestAuthenticator.RS256();

            // Start: nothing enrolled, an insecure origin.
            PasskeyStore empty = new(Path.Combine(folder, "empty.json"));
            PasskeyMethod none = new(empty, settings);
            check(none.Id == "passkey", "passkey: Id is passkey");
            ProofUnavailableException? noKey = Throws<ProofUnavailableException>(() => none.Start(new ProofContext(bind, "http://localhost:5123")));
            check(noKey is not null && noKey.Message.Contains("with-secrets admin (more are added in the admin web app)", StringComparison.Ordinal), "passkey: Start with no key names --config (" + noKey?.Message + ")");

            PasskeyStore store = new(Path.Combine(folder, "passkeys.db"));
            PasskeyRecord key = laptop.Record("localhost", "laptop");
            PasskeyRecord remote = other.Record("ws.example.com", "phone");
            check(store.Add(key) && store.Add(remote), "passkey: records added");
            PasskeyMethod method = new(store, settings);

            ProofStart started = method.Start(new ProofContext(bind, "http://localhost:5123"));
            string expectedPayload = "{\"bind\":\"" + Encode(bind) + "\",\"rpId\":\"localhost\",\"timeout\":90000,\"salt\":\"" + store.ForRp("localhost").Single().Slot!.Salt + "\"}";
            check(started.Mode == "webauthn" && started.Payload == expectedPayload, "passkey: Start payload is exact (" + started.Payload + ")");
            check(method.Start(new ProofContext(bind, "https://ws.example.com")).Payload.Contains("\"rpId\":\"ws.example.com\"", StringComparison.Ordinal), "passkey: https origin uses the keys of its host");
            check(Throws<ProofUnavailableException>(() => method.Start(new ProofContext(bind, "http://ws.example.com"))) is not null, "passkey: Start refuses http on a host other than localhost");
            check(Throws<ProofUnavailableException>(() => method.Start(new ProofContext(bind, "http://localhost.evil.example"))) is not null, "passkey: Start refuses http on a look-alike host");
            check(Throws<ProofUnavailableException>(() => method.Start(new ProofContext(bind, "not a url"))) is not null, "passkey: Start refuses an origin that is not a URL");
            check(Throws<ProofUnavailableException>(() => method.Start(new ProofContext(bind, "https://nokey.example.com"))) is not null, "passkey: Start refuses a host with no key");

            List<EnrolledEntry> enrolled = [.. method.Enrolled()];
            check(enrolled.Count == 2 && enrolled[0] == new EnrolledEntry("laptop", "localhost", key.Created, true) && !enrolled[1].Admin && enrolled[1].Name == "phone" && enrolled[1].Detail == "ws.example.com", "passkey: Enrolled lists every key with its rpId");

            // Verify directly.
            ProofContext context = new(bind, "http://localhost:5123");
            ProofResult good = method.Verify(context, laptop.Assert(bind, context.Origin, "localhost", 3));
            check(good is { Ok: true, Detail: "admin passkey laptop verified" } && store.All()[0].SignCount == 3, "passkey: Verify accepts and stores the sign count (" + good.Detail + ")");
            check(!method.Verify(context, laptop.Assert(bind, context.Origin, "localhost", 3)).Ok, "passkey: a replayed sign count is refused");
            ProofResult unknown = method.Verify(context, other.Assert(bind, context.Origin, "localhost", 1));
            check(unknown is { Ok: false, Detail: "unknown passkey" }, "passkey: a key of another host name is refused (" + unknown.Detail + ")");

            // For changes only the admin key (the first one) may prove; for runs every enrolled key may.
            PasskeyMethod adminOnly = method.ForAdmin();
            check(adminOnly.AdminOnly && !method.AdminOnly && adminOnly.Start(new ProofContext(bind, "http://localhost:5123")).Payload.Contains("\"rpId\":\"localhost\"", StringComparison.Ordinal), "passkey admin: the admin key can start a change");
            ProofUnavailableException? notAdmin = Throws<ProofUnavailableException>(() => adminOnly.Start(new ProofContext(bind, "https://ws.example.com")));
            check(notAdmin is not null && notAdmin.Message.Contains("Only an admin passkey", StringComparison.Ordinal) && notAdmin.Message.Contains("\"laptop\"", StringComparison.Ordinal), "passkey admin: a host with only a non-admin key cannot start a change, and the message names the admin keys (" + notAdmin?.Message + ")");
            check(adminOnly.CanProve("localhost") && !adminOnly.CanProve("ws.example.com") && method.CanProve("ws.example.com"), "passkey admin: CanProve follows the admin key for changes, every key for runs");
            ProofContext remoteContext = new(bind, "https://ws.example.com");
            check(adminOnly.Verify(remoteContext, other.Assert(bind, remoteContext.Origin, "ws.example.com", 1)) is { Ok: false, Detail: "unknown passkey" }, "passkey admin: a non-admin key cannot approve a change");
            check(method.Verify(remoteContext, other.Assert(bind, remoteContext.Origin, "ws.example.com", 2)) is { Ok: true, Detail: "passkey phone verified" }, "passkey admin: a non-admin key approves a run, and the detail has no admin marker");
            check(!method.Verify(context, laptop.Assert(RequestBinding.Compute("n", "other"), context.Origin, "localhost", 9)).Ok, "passkey: another challenge is refused");
            check(!method.Verify(context, laptop.Assert(bind, "http://localhost:6000", "localhost", 9)).Ok, "passkey: another origin is refused");
            foreach (string junk in new[] { "", "not json", "[]", "null", "{}", "{\"id\":5}", "{\"id\":null}", "{\"id\":\"" + key.Id + "\"}" })
            {
                ProofResult result = method.Verify(context, junk);
                check(!result.Ok && result.Detail.Length > 0, "passkey: junk response '" + junk + "' is refused");
            }

            check(store.All()[0].SignCount == 3, "passkey: refused proofs leave the sign count alone");

            // End to end over HTTP.
            PasskeyStore web = new(Path.Combine(folder, "web.json"));
            check(web.Add(laptop.Record("localhost", "laptop")), "passkey: web store seeded");
            (ApprovalDecision? decision, int status) = await PasskeyRun(client, web, (challenge, origin) => laptop.Assert(challenge, origin, "localhost", 7));
            check(status == 200 && decision is { Approved: true } && decision.Detail.Contains("passkey laptop verified", StringComparison.Ordinal), "passkey: web approval by the enrolled key (" + decision?.Detail + ")");
            check(web.All()[0].SignCount == 7, "passkey: web approval stores the sign count");

            (decision, status) = await PasskeyRun(client, web, (challenge, origin) => other.Assert(challenge, origin, "localhost", 1));
            check(status == 403 && decision is { Approved: false }, "passkey: web proof from a key that is not enrolled is denied (" + decision?.Detail + ")");

            (decision, status) = await PasskeyRun(client, web, (challenge, _) => laptop.Assert(challenge, "http://localhost:1", "localhost", 8));
            check(status == 403 && decision is { Approved: false }, "passkey: web proof signed for another origin is denied (" + decision?.Detail + ")");

            (decision, status) = await PasskeyRun(client, web, (_, origin) => laptop.Assert(RequestBinding.Compute("x", "y"), origin, "localhost", 9));
            check(status == 403 && decision is { Approved: false }, "passkey: web proof signed with another challenge is denied (" + decision?.Detail + ")");
            check(web.All()[0].SignCount == 7, "passkey: denied web proofs leave the sign count alone");

            (decision, _) = await PasskeyRun(client, new PasskeyStore(Path.Combine(folder, "nothing.json")), (_, _) => "");
            check(decision is { Approved: false } && decision.Detail.Contains("with-secrets admin (more are added in the admin web app)", StringComparison.Ordinal), "passkey: web request with no key is denied and says how to enroll (" + decision?.Detail + ")");
        }
        finally
        {
            Directory.Delete(folder, true);
        }
    }

    private static void OriginTests(Action<bool, string> check)
    {
        foreach (string url in new[] { "https://user:pw@ws.example.com/", "https://user@ws.example.com/", "http://:pw@ws.example.com/" })
        {
            string? error = (ToolSettings.Defaults with { BaseUrl = url }).Problem();
            check(error is not null && error.Contains("baseUrl", StringComparison.Ordinal), "approval settings: baseUrl with userinfo '" + url + "' is refused");
        }

        static string Origin(string url) => new ApprovalSettings(url, 0, TimeSpan.FromMinutes(5)).PageOrigin(1);

        check(Origin("https://user:pw@ws.example.com/x") == "https://ws.example.com", "approval settings: origin drops userinfo");
        check(Origin("https://ws.example.com:8443/x?y#z") == "https://ws.example.com:8443", "approval settings: origin keeps a non-default port");
        check(Origin("https://ws.example.com:443/") == "https://ws.example.com", "approval settings: origin drops the default https port");
        check(Origin("http://ws.example.com:80/") == "http://ws.example.com", "approval settings: origin drops the default http port");
        check(Origin("http://WS.Example.COM:8080") == "http://ws.example.com:8080", "approval settings: origin host is lower case");
        check(Origin("http://[::1]:8080/") == "http://[::1]:8080", "approval settings: IPv6 origin keeps the brackets");
    }

    /// <summary>
    /// A run through the real chain over real HTTP: RunCommand, WebApprover, PasskeyMethod, PasskeyStore, an audit file and a
    /// real child process (a small .cmd file on Windows, a shell script elsewhere) that prints the secret from its environment.
    /// </summary>
    private static async Task RunChainTests(Action<bool, string> check)
    {
        const string Secret = "Chain-Secret-4711";
        string folder = Path.Combine(Path.GetTempPath(), "ws-chain-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            string name = OperatingSystem.IsWindows() ? "show.cmd" : "show.sh";
            string marker = Path.Combine(folder, "ran.txt");
            if (OperatingSystem.IsWindows())
            {
                File.WriteAllText(Path.Combine(folder, name), "@echo off\r\necho %MY_SECRET%\r\necho ran> \"%~dp0ran.txt\"\r\n");
            }
            else
            {
                string path = Path.Combine(folder, name);
                File.WriteAllText(path, "#!/bin/sh\necho \"$MY_SECRET\"\necho ran > \"" + marker + "\"\n");
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }

            using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
            client.Timeout = TimeSpan.FromSeconds(20);
            ApprovalSettings settings = new(null, 0, TimeSpan.FromSeconds(20));

            async Task<(int Code, string Out, string Err, int Announced, string Audit)> Drive(PasskeyStore passkeys, string auditName, Func<string, byte[], string, (string Verb, string Body)>? answer)
            {
                File.Delete(marker);
                string auditPath = Path.Combine(folder, auditName);
                TaskCompletionSource<string> link = new(TaskCreationOptions.RunContinuationsAsynchronously);
                StringWriter stdout = new();
                StringWriter stderr = new();
                TextWriter errors = TextWriter.Synchronized(stderr);
                int announced = 0;
                WebApprover approver = new(new PasskeyMethod(passkeys, settings), settings, line =>
                {
                    announced++;
                    errors.WriteLine(line);
                    link.TrySetResult(line);
                });
                RunCommand run = new(new MemoryStore(new Dictionary<string, string> { ["MY_SECRET"] = Secret }), approver, TextWriter.Synchronized(stdout), errors);
                RunArgs args = CliArgs.ParseRun(["--secrets", "MY_SECRET", "--reason", "chain test", "--", "./" + name], out _)!;
                Task<int> running = Task.Run(() => run.ExecuteAsync(args, folder, TestAudit.Sink(new StateDatabase(auditPath))));
                if (answer is not null)
                {
                    Task first = await Task.WhenAny(link.Task, running, Task.Delay(TimeSpan.FromSeconds(20)));
                    if (first == link.Task)
                    {
                        Uri uri = new(link.Task.Result[AnnouncePrefix.Length..]);
                        string baseUrl = "http://127.0.0.1:" + uri.Port + uri.AbsolutePath;
                        string body = Text(Send(client, HttpMethod.Get, baseUrl));
                        Dictionary<string, string> start = JsonSerializer.Deserialize<Dictionary<string, string>>(Between(body, "<script type=\"application/json\" id=\"start\">", "</script>"))!;
                        (string verb, string payload) = answer(baseUrl, Base64Url.DecodeFromChars(start["bind"]), "http://localhost:" + uri.Port);
                        using HttpResponseMessage? posted = Send(client, HttpMethod.Post, baseUrl + "/" + verb, payload);
                    }
                }

                Task done = await Task.WhenAny(running, Task.Delay(TimeSpan.FromSeconds(30)));
                int code = done == running ? running.Result : -1;
                string audit = StateDatabaseTests.AuditText(auditPath);

                return (code, stdout.ToString(), stderr.ToString(), announced, audit);
            }

            // (1) approve with the enrolled passkey: runs, redacted, audited with the key name
            PasskeyStore enrolled = new(Path.Combine(folder, "passkeys.db"));
            using TestAuthenticator key = TestAuthenticator.ES256();
            check(enrolled.Add(key.Record("localhost", "chain-key")), "run chain: key stored");
            (int code, string stdout, string stderr, int announced, string audit) = await Drive(enrolled, "audit-approve.log", (_, bind, origin) => ("proof", ReuseTests.Body(0, key.Assert(ReuseBinding.Challenge(bind, 0), origin, "localhost", 1))));
            check(code == 0, "run chain: approved with a passkey, exit code 0 (" + code + "; " + stderr + ")");
            check(stdout.Contains("[REDACTED]", StringComparison.Ordinal) && !stdout.Contains(Secret, StringComparison.Ordinal) && !stderr.Contains(Secret, StringComparison.Ordinal), "run chain: the child printed the secret and the output is redacted");
            check(File.Exists(marker) && announced == 1 && stderr.Contains(AnnouncePrefix, StringComparison.Ordinal), "run chain: the child ran and one link was announced on stderr");
            check(audit.Contains("\"outcome\":\"approved\"", StringComparison.Ordinal) && !audit.Contains(Secret, StringComparison.Ordinal), "run chain: the signed audit has the approval and no value");

            // (2) Deny on the page: exit 3, the child never ran
            (code, stdout, stderr, announced, audit) = await Drive(enrolled, "audit-deny.log", (_, _, _) => ("deny", ""));
            check(code == RunCommand.Denied && !File.Exists(marker) && !stdout.Contains(Secret, StringComparison.Ordinal) && audit.Contains("\"outcome\":\"denied\"", StringComparison.Ordinal), "run chain: Deny on the page exits 3 and the child never ran (" + code + ")");

            // (3) nothing enrolled: exit 3, a message that names --enroll, no link, the child never ran
            (code, stdout, stderr, announced, audit) = await Drive(new PasskeyStore(Path.Combine(folder, "empty.json")), "audit-none.log", null);
            check(code == RunCommand.Denied && stderr.Contains("with-secrets admin (more are added in the admin web app)", StringComparison.Ordinal) && announced == 0 && !File.Exists(marker), "run chain: no passkey enrolled exits 3, names --config, announces no link, the child never ran (" + code + "; " + stderr + ")");
        }
        finally
        {
            Directory.Delete(folder, true);
        }
    }

    private const string AnnouncePrefix = "Approval needed. Ask the person to open: ";

    /// <summary>One <see cref="WebApprover" /> call running on its own task, with the link it announced.</summary>
    private sealed class WebRun
    {
        public WebRun(FakeProofMethod fake, Func<WebApprover, ApprovalDecision> ask, TimeSpan? timeout = null, TimeSpan? approveDelay = null)
        {
            Fake = fake;
            ApprovalSettings settings = new(null, 0, timeout ?? TimeSpan.FromSeconds(20));
            WebApprover approver = new(fake, settings, line =>
            {
                Announced++;
                _line.TrySetResult(line);
            }, approveDelay);
            Decision = Task.Run(() => ask(approver));
        }

        private readonly TaskCompletionSource<string> _line = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public FakeProofMethod Fake { get; }

        public Task<ApprovalDecision> Decision { get; }

        public int Announced { get; private set; }

        public string Line { get; private set; } = "";

        /// <summary>The announced link, as given. Null when the call ended first.</summary>
        public Uri? Link { get; private set; }

        /// <summary>The link with 127.0.0.1 for localhost: the server listens on IPv4 loopback only.</summary>
        public string Base { get; private set; } = "";

        public async Task<bool> Opened()
        {
            Task first = await Task.WhenAny(_line.Task, Decision, Task.Delay(TimeSpan.FromSeconds(20)));
            if (first != _line.Task)
            {
                return false;
            }

            Line = _line.Task.Result;
            if (!Line.StartsWith(AnnouncePrefix, StringComparison.Ordinal))
            {
                return false;
            }

            Link = new Uri(Line[AnnouncePrefix.Length..]);
            Base = "http://127.0.0.1:" + Link.Port + Link.AbsolutePath;

            return true;
        }

        public string Token => Link?.AbsolutePath.Split('/')[^1] ?? "";

        public async Task<ApprovalDecision?> Finished()
        {
            Task first = await Task.WhenAny(Decision, Task.Delay(TimeSpan.FromSeconds(20)));

            return first == Decision ? Decision.Result : null;
        }
    }

    private static HttpResponseMessage? Send(HttpClient client, HttpMethod method, string url, string? body = null)
    {
        try
        {
            using HttpRequestMessage message = new(method, url);
            if (body is not null)
            {
                message.Content = new StringContent(body, Encoding.UTF8, "application/json");
            }

            return client.Send(message);
        }
        catch (HttpRequestException)
        {
            return null;
        }
    }

    private static string Text(HttpResponseMessage? response) => response?.Content.ReadAsStringAsync().GetAwaiter().GetResult() ?? "";

    /// <summary>The server is gone or no longer serves the link.</summary>
    private static bool Gone(HttpResponseMessage? response) => response is null || response.StatusCode == HttpStatusCode.NotFound;

    private static bool Refuses(int port, IPAddress? address = null)
    {
        address ??= IPAddress.Loopback;
        try
        {
            using TcpClient client = new(address.AddressFamily);
            client.Connect(address, port);

            return false;
        }
        catch (SocketException)
        {
            return true;
        }
    }

    /// <summary>Both loopback addresses refuse; [::1] counts only where this machine has it.</summary>
    private static bool RefusesBoth(int port) => Refuses(port) && (!HasIpv6Loopback || Refuses(port, IPAddress.IPv6Loopback));

    /// <summary>Whether this machine can listen on [::1]. Without it a browser cannot reach [::1] either.</summary>
    private static readonly bool HasIpv6Loopback = CanListenIpv6();

    private static bool CanListenIpv6()
    {
        try
        {
            using TcpListener listener = new(IPAddress.IPv6Loopback, 0);
            listener.Start();

            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    /// <summary>Whether another socket could bind the address with SO_REUSEADDR, as a program taking over the port would.</summary>
    private static bool CanTake(IPAddress address, int port)
    {
        try
        {
            using Socket socket = new(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            socket.Bind(new IPEndPoint(address, port));

            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    private static string Between(string text, string start, string end)
    {
        int from = text.IndexOf(start, StringComparison.Ordinal);
        if (from < 0)
        {
            return "";
        }

        from += start.Length;
        int to = text.IndexOf(end, from, StringComparison.Ordinal);

        return to < 0 ? "" : text[from..to];
    }

    private static ApprovalRequest Sample(params string[] arguments)
    {
        return new ApprovalRequest("tool", "/bin/tool", arguments, "/work", "testing", ["API_KEY"]);
    }

    private static async Task ServerTests(Action<bool, string> check)
    {
        using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
        client.Timeout = TimeSpan.FromSeconds(20);

        // The page, its headers, and the binding the proof is tied to.
        {
            WebRun run = new(new FakeProofMethod(), approver => approver.Ask(new ApprovalPrompt("Check this <b>", "line one\nline <two> & \"three\"")));
            check(await run.Opened(), "web: announce gives one line with the link (" + run.Line + ")");
            check(run.Link is not null && run.Link.Scheme == "http" && run.Link.Host == "localhost" && run.Link.AbsolutePath == "/a/" + run.Token, "web: link is http://localhost:<port>/a/<token>");
            check(run.Link is not null && run.Link.Port > 0 && run.Line == AnnouncePrefix + "http://localhost:" + run.Link.Port + "/a/" + run.Token, "web: announce text is exact");
            byte[]? tokenBytes = null;
            try
            {
                tokenBytes = Base64Url.DecodeFromChars(run.Token);
            }
            catch (FormatException)
            {
            }

            check(tokenBytes is { Length: 16 } && run.Token.Length == 22, "web: token is 16 bytes in base64url");
            check(run.Announced == 1, "web: announce is called once");

            using HttpResponseMessage? page = Send(client, HttpMethod.Get, run.Base);
            string body = Text(page);
            check(page?.StatusCode == HttpStatusCode.OK, "web: GET page is 200");
            check(page?.Content.Headers.ContentType?.MediaType == "text/html" && page.Content.Headers.ContentType.CharSet == "utf-8", "web: page is text/html utf-8");
            check(body.Contains("Check this &lt;b&gt;", StringComparison.Ordinal), "web: page has the heading, encoded");
            check(body.Contains("line one\nline &lt;two&gt; &amp; &quot;three&quot;", StringComparison.Ordinal), "web: page has the text, encoded");
            check(body.Contains("<button id=\"deny\" type=\"button\" autofocus>Deny</button>", StringComparison.Ordinal), "web: Deny button has the default focus");
            check(body.Contains("<button id=\"approve\" type=\"button\" disabled data-delay=\"2000\">Approve once</button>", StringComparison.Ordinal), "web: Approve once starts disabled with a 2 s delay");
            check(body.IndexOf("id=\"request\"", StringComparison.Ordinal) < body.IndexOf("id=\"deny\"", StringComparison.Ordinal), "web: buttons come after the text");

            string? Header(string name) => page is not null && page.Headers.TryGetValues(name, out IEnumerable<string>? values) ? string.Join(",", values) : null;
            check(Header("Cache-Control") == "no-store", "web: Cache-Control no-store");
            check(Header("X-Content-Type-Options") == "nosniff", "web: X-Content-Type-Options nosniff");
            check(Header("Referrer-Policy") == "no-referrer", "web: Referrer-Policy no-referrer");
            string csp = Header("Content-Security-Policy") ?? "";
            string script = Between(body, "<script>", "</script>");
            string scriptHash = "'sha256-" + Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(script))) + "'";
            string style = Between(body, "<style>", "</style>");
            string styleHash = "'sha256-" + Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(style))) + "'";
            check(script.Length > 0 && csp.Contains("script-src " + scriptHash, StringComparison.Ordinal), "web: CSP allows the one inline script by its hash");
            check(style.Length > 0 && csp.Contains("style-src " + styleHash, StringComparison.Ordinal), "web: CSP allows the inline style by its hash");
            check(csp.Contains("default-src 'none'", StringComparison.Ordinal) && csp.Contains("frame-ancestors 'none'", StringComparison.Ordinal) && csp.Contains("connect-src 'self'", StringComparison.Ordinal), "web: CSP has default-src none, frame-ancestors none, connect-src self");
            check(!csp.Contains("unsafe", StringComparison.Ordinal), "web: CSP has no unsafe- source");
            int scripts = body.Split("<script").Length - 1;
            check(scripts == 2, "web: page has one data block and one inline script (" + scripts + ")");
            check(script.Contains("fromBase64Url(start.bind)", StringComparison.Ordinal) && !script.Contains("payload.bind", StringComparison.Ordinal), "web: script takes the challenge seed from the server's start.bind, not the payload");

            string json = Between(body, "<script type=\"application/json\" id=\"start\">", "</script>");
            Dictionary<string, string>? start = null;
            try
            {
                start = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
            }
            catch (JsonException)
            {
            }

            FakeProofMethod fake = run.Fake;
            check(start is not null && start.Keys.SequenceEqual(["mode", "payload", "bind", "nonce"]), "web: start JSON has mode, payload, bind, nonce");
            check(start is not null && start["mode"] == "webauthn" && start["payload"] == FakeProofMethod.Payload, "web: start JSON carries the mode and payload as given");
            check(!json.Contains('<') && json.Contains("\\u003C", StringComparison.Ordinal), "web: start JSON escapes <");
            string nonce = start?.GetValueOrDefault("nonce") ?? "";
            string issued = ApprovalSummary.IssuedPrefix + Between(body, ApprovalSummary.IssuedPrefix, "</pre>");
            check(DateTimeOffset.TryParseExact(issued[ApprovalSummary.IssuedPrefix.Length..], "O", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out DateTimeOffset issuedAt) && Math.Abs((DateTimeOffset.UtcNow - issuedAt).TotalSeconds) < 60, "web: the text ends with the page issued time, server UTC (" + issued + ")");
            byte[] expected = RequestBinding.Compute(nonce, "line one\nline <two> & \"three\"\n" + issued);
            check(fake.Started is not null && fake.Started.Bind.AsSpan().SequenceEqual(expected), "web: Start got Bind == RequestBinding.Compute(nonce, text)");
            check(start is not null && start["bind"] == Encode(expected), "web: start JSON bind is the binding in base64url");
            check(Base64Url.DecodeFromChars(nonce).Length == 16, "web: nonce is 16 bytes in base64url");
            check(fake.Started is not null && run.Link is not null && fake.Started.Origin == "http://localhost:" + run.Link.Port, "web: Start got the page origin");

            // The link says localhost, which browsers try on [::1] first: the real server must hold it too.
            if (HasIpv6Loopback)
            {
                using HttpResponseMessage? six = Send(client, HttpMethod.Get, "http://[::1]:" + run.Link?.Port + "/a/" + run.Token);
                check(six?.StatusCode == HttpStatusCode.OK && Text(six) == body, "web: [::1] on the same port serves the real page");
            }
            else
            {
                Console.WriteLine("NOTE: no IPv6 loopback on this machine; the [::1] page check is skipped.");
            }

            int livePort = run.Link?.Port ?? 0;
            check(!CanTake(IPAddress.Loopback, livePort) && (!HasIpv6Loopback || !CanTake(IPAddress.IPv6Loopback, livePort)), "web: another socket cannot bind the server's addresses, even with SO_REUSEADDR");

            using HttpResponseMessage? wrong = Send(client, HttpMethod.Get, "http://127.0.0.1:" + run.Link?.Port + "/a/" + Encode(new byte[16]));
            check(wrong?.StatusCode == HttpStatusCode.NotFound, "web: wrong token is 404");
            check(wrong is not null && wrong.Headers.TryGetValues("X-Content-Type-Options", out IEnumerable<string>? sniff) && sniff.Single() == "nosniff", "web: 404 has the headers too");
            foreach (string path in new[] { "/", "/a", "/a/", "/b/" + run.Token, "/a/" + run.Token + "x", "/a/" + run.Token + "/other", "/a/" + run.Token[..^1] })
            {
                using HttpResponseMessage? other = Send(client, HttpMethod.Get, "http://127.0.0.1:" + run.Link?.Port + path);
                check(other?.StatusCode == HttpStatusCode.NotFound, "web: GET " + path + " is 404");
            }

            using HttpResponseMessage? getProof = Send(client, HttpMethod.Get, run.Base + "/proof");
            check(getProof?.StatusCode == HttpStatusCode.NotFound && fake.Verified == 0, "web: GET /proof is 404 and checks nothing");
            using HttpResponseMessage? postPage = Send(client, HttpMethod.Post, run.Base, FakeProofMethod.Good);
            check(postPage?.StatusCode == HttpStatusCode.NotFound && fake.Verified == 0, "web: POST to the page is 404 and checks nothing");

            using HttpResponseMessage? large = Send(client, HttpMethod.Post, run.Base + "/proof", new string('x', 1_100_000));
            check(large?.StatusCode != HttpStatusCode.OK && fake.Verified == 0, "web: proof body over 1 MB is refused and not checked");
            check(!run.Decision.IsCompleted, "web: 404s and refused bodies do not end the request");

            using HttpResponseMessage? proof = Send(client, HttpMethod.Post, run.Base + "/proof", FakeProofMethod.Good);
            check(proof?.StatusCode == HttpStatusCode.OK && Text(proof) == "{\"ok\":true}", "web: accepted proof returns {\"ok\":true}");
            ApprovalDecision? decision = await run.Finished();
            check(decision is { Approved: true }, "web: accepted proof approves (" + decision?.Detail + ")");
            check(fake.Verified == 1 && fake.Response == FakeProofMethod.Inner, "web: Verify got the proof unchanged");
            check(fake.Checked is not null && fake.Started is not null && fake.Checked.Bind.AsSpan().SequenceEqual(ReuseBinding.Challenge(fake.Started.Bind, 0)) && fake.Checked.Origin == fake.Started.Origin, "web: Verify got Start's bind with reuse=0 and the same origin");

            using HttpResponseMessage? again = Send(client, HttpMethod.Post, run.Base + "/proof", FakeProofMethod.Good);
            check(again?.StatusCode != HttpStatusCode.OK && fake.Verified == 1, "web: proof after approve is not 200 and not checked");
            check(Gone(Send(client, HttpMethod.Get, run.Base)), "web: page is gone after approve");
            check(run.Link is not null && RefusesBoth(run.Link.Port), "web: port is released on 127.0.0.1 and [::1] after approve");
        }

        // A rejected proof is a denial, and it ends the request.
        {
            WebRun run = new(new FakeProofMethod(), approver => approver.Ask(new ApprovalPrompt("h", "t")));
            check(await run.Opened(), "web: rejected proof run opens");
            using HttpResponseMessage? proof = Send(client, HttpMethod.Post, run.Base + "/proof", ReuseTests.Body(0, "{\"proof\":\"bad\"}"));
            check(proof?.StatusCode == HttpStatusCode.Forbidden, "web: rejected proof is 403");
            ApprovalDecision? decision = await run.Finished();
            check(decision is { Approved: false } && decision.Detail.Contains("the fake said no", StringComparison.Ordinal), "web: rejected proof denies with the detail (" + decision?.Detail + ")");
            check(Gone(Send(client, HttpMethod.Get, run.Base)), "web: page is gone after a rejected proof");
            check(Gone(Send(client, HttpMethod.Post, run.Base + "/proof", FakeProofMethod.Good)) && run.Fake.Verified == 1, "web: a good proof after a rejected one is not checked");
        }

        // Verify throwing is a denial.
        {
            WebRun run = new(new FakeProofMethod { VerifyThrows = true }, approver => approver.Ask(new ApprovalPrompt("h", "t")));
            check(await run.Opened(), "web: throwing Verify run opens");
            using HttpResponseMessage? proof = Send(client, HttpMethod.Post, run.Base + "/proof", FakeProofMethod.Good);
            check(proof?.StatusCode == HttpStatusCode.Forbidden, "web: throwing Verify is 403");
            ApprovalDecision? decision = await run.Finished();
            check(decision is { Approved: false }, "web: throwing Verify denies (" + decision?.Detail + ")");
        }

        // Deny on the page.
        {
            WebRun run = new(new FakeProofMethod(), approver => approver.Ask(new ApprovalPrompt("h", "t")));
            check(await run.Opened(), "web: deny run opens");
            using HttpResponseMessage? deny = Send(client, HttpMethod.Post, run.Base + "/deny", "");
            check(deny?.StatusCode == HttpStatusCode.OK, "web: POST /deny is 200");
            ApprovalDecision? decision = await run.Finished();
            check(decision is { Approved: false, Detail: "denied on the page" }, "web: POST /deny denies 'denied on the page' (" + decision?.Detail + ")");
            check(Gone(Send(client, HttpMethod.Post, run.Base + "/proof", FakeProofMethod.Good)) && run.Fake.Verified == 0, "web: proof after deny is not checked");
        }

        // Review Focus 3: no answer.
        {
            WebRun run = new(new FakeProofMethod(), approver => approver.Ask(new ApprovalPrompt("h", "t")), TimeSpan.FromMilliseconds(300));
            check(await run.Opened(), "web: timeout run opens");
            ApprovalDecision? decision = await run.Finished();
            check(decision is { Approved: false, Detail: "no answer before the time limit" }, "web: no answer denies 'no answer before the time limit' (" + decision?.Detail + ")");
            check(run.Link is not null && RefusesBoth(run.Link.Port), "web: port refuses a new connection on 127.0.0.1 and [::1] after the timeout");
        }

        // Start failures: denied, never announced.
        {
            WebRun run = new(new FakeProofMethod { StartThrows = new ProofUnavailableException("x") }, approver => approver.Ask(new ApprovalPrompt("h", "t")));
            ApprovalDecision? decision = await run.Finished();
            check(decision is { Approved: false, Detail: "x" }, "web: Start throwing ProofUnavailableException denies with its message (" + decision?.Detail + ")");
            check(run.Announced == 0, "web: announce is not called when Start fails");

            run = new(new FakeProofMethod { StartThrows = new InvalidOperationException("boom") }, approver => approver.Ask(new ApprovalPrompt("h", "t")));
            decision = await run.Finished();
            check(decision is { Approved: false } && run.Announced == 0, "web: Start throwing any exception denies, not announced (" + decision?.Detail + ")");
        }

        // A port that is taken: denied, never announced.
        {
            using TcpListener taken = new(IPAddress.Loopback, 0);
            taken.Start();
            int port = ((IPEndPoint)taken.LocalEndpoint).Port;
            FakeProofMethod fake = new();
            int announced = 0;
            WebApprover approver = new(fake, new ApprovalSettings(null, port, TimeSpan.FromSeconds(5)), _ => announced++);
            ApprovalDecision decision = approver.Ask(new ApprovalPrompt("h", "t"));
            check(!decision.Approved && announced == 0 && fake.Started is null, "web: a port in use denies before Start (" + decision.Detail + ")");
        }

        // Someone else holds [::1] on the port: they could serve their own page at the link's origin, so this is a denial.
        if (HasIpv6Loopback)
        {
            using TcpListener taken = new(IPAddress.IPv6Loopback, 0);
            taken.Start();
            int port = ((IPEndPoint)taken.LocalEndpoint).Port;
            FakeProofMethod fake = new();
            int announced = 0;
            WebApprover approver = new(fake, new ApprovalSettings(null, port, TimeSpan.FromSeconds(5)), _ => announced++);
            ApprovalDecision decision = approver.Ask(new ApprovalPrompt("h", "t"));
            check(!decision.Approved && announced == 0 && fake.Started is null, "web: [::1] held by another program denies before Start, not announced (" + decision.Detail + ")");
            check(Refuses(port), "web: 127.0.0.1 is released after the [::1] bind failed");
        }
        else
        {
            Console.WriteLine("NOTE: no IPv6 loopback on this machine; the held-[::1] check is skipped.");
        }

        // The CSP hashes cover exactly what is served, whatever line endings the source had.
        {
            OneShotResponse built = ApprovalPage.BuildWith(new ApprovalPrompt("h", "t"), new ProofStart("webauthn", "{}"), "n", [1], TimeSpan.Zero, "var a = 1;\r\nvar b = 2;\r\n", "p { }\r\nh1 { }\r\n");
            string served = Between(built.Body, "<script>", "</script>");
            string servedStyle = Between(built.Body, "<style>", "</style>");
            string csp = built.ContentSecurityPolicy ?? "";
            static string Hash(string text) => "'sha256-" + Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(text))) + "'";
            check(served == "var a = 1;\nvar b = 2;\n" && servedStyle == "p { }\nh1 { }\n", "web: CRLF script and style are served with LF");
            check(csp.Contains("script-src " + Hash(served) + ";", StringComparison.Ordinal) && csp.Contains("style-src " + Hash(servedStyle) + ";", StringComparison.Ordinal), "web: CSP hashes match the LF text served from CRLF source");

            OneShotResponse runPrompt = ApprovalPage.Build(
                new ApprovalPrompt("Run this program", "Program: example"),
                new ProofStart("webauthn", "{}"), "n", [1], TimeSpan.Zero);
            Dictionary<string, string> runData = JsonSerializer.Deserialize<Dictionary<string, string>>(Between(runPrompt.Body, "<script type=" + (char)34 + "application/json" + (char)34 + " id=" + (char)34 + "start" + (char)34 + ">", "</script>"))!;
            check(runPrompt.Body.Contains(">Approve once</button>", StringComparison.Ordinal)
                && !runData.ContainsKey("confirmedMessage")
                && Between(runPrompt.Body, "<script>", "</script>").Contains("Approved once. You can close this page.", StringComparison.Ordinal),
                "web: ordinary agent approval retains its original action and completion wording");

            OneShotResponse adminPrompt = ApprovalPage.BuildWith(
                new ApprovalPrompt("Check this change", "Action: change a setting", "Confirm this change", "Change confirmed. The change was made."),
                new ProofStart("webauthn", "{}"), "n", [1], TimeSpan.Zero, "var a = 1;", "p { }");
            Dictionary<string, string> adminData = JsonSerializer.Deserialize<Dictionary<string, string>>(Between(adminPrompt.Body, "<script type=" + (char)34 + "application/json" + (char)34 + " id=" + (char)34 + "start" + (char)34 + ">", "</script>"))!;
            check(adminPrompt.Body.Contains(">Confirm this change</button>", StringComparison.Ordinal)
                && adminData.GetValueOrDefault("confirmedMessage") == "Change confirmed. The change was made.",
                "web: administrator passkey prompt has its own confirm action and completion wording");
        }

        // Ask cleans what it shows, line by line, and binds the proof to that text.
        {
            string heading = "Head" + (char)0x202E + "ing";
            string text = "first" + (char)0x202E + "line\nsecond" + (char)0x200B + "line\nthird";
            WebRun run = new(new FakeProofMethod(), approver => approver.Ask(new ApprovalPrompt(heading, text)));
            check(await run.Opened(), "web: Ask clean run opens");
            string body = Text(Send(client, HttpMethod.Get, run.Base));
            check(body.Contains("<h1>Head□ing</h1>", StringComparison.Ordinal), "web: Ask marks a bidi override in the heading");
            check(body.Contains(">first□line\nsecond□line\nthird\n" + ApprovalSummary.IssuedPrefix, StringComparison.Ordinal), "web: Ask marks bidi and zero-width characters and keeps line breaks");
            check(!body.Contains((char)0x202E) && !body.Contains((char)0x200B), "web: Ask page has no raw bidi or zero-width character");
            string nonce = JsonSerializer.Deserialize<Dictionary<string, string>>(Between(body, "<script type=\"application/json\" id=\"start\">", "</script>"))?["nonce"] ?? "";
            check(run.Fake.Started is not null && run.Fake.Started.Bind.AsSpan().SequenceEqual(RequestBinding.Compute(nonce, "first□line\nsecond□line\nthird\n" + ApprovalSummary.IssuedPrefix + Between(body, ApprovalSummary.IssuedPrefix, "</pre>"))), "web: Ask binds the proof to the cleaned text the page shows");
            Send(client, HttpMethod.Post, run.Base + "/deny", "")?.Dispose();
            check(await run.Finished() is { Approved: false }, "web: Ask clean run denied");
        }

        // Review Focus 1: the request text cannot become markup or hide characters.
        {
            string evil = "<script>alert(1)</script> \"><img src=x onerror=y>";
            ApprovalRequest request = Sample(evil) with { Reason = "ok" + (char)0x202E + "lpd" + (char)0x200B + "end" };
            WebRun run = new(new FakeProofMethod(), approver => approver.Request(request), approveDelay: TimeSpan.FromMilliseconds(1500));
            check(await run.Opened(), "web: Request run opens");
            string body = Text(Send(client, HttpMethod.Get, run.Base));
            string message = ApprovalSummary.BuildMessage(request);
            check(body.Contains("An agent wants to run a program with these secrets.", StringComparison.Ordinal), "web: Request uses the request heading");
            check(body.Contains(WebUtility.HtmlEncode(message), StringComparison.Ordinal), "web: Request shows BuildMessage, encoded");
            check(body.Contains("&lt;script&gt;alert(1)&lt;/script&gt; \\&quot;&gt;&lt;img src=x onerror=y&gt;", StringComparison.Ordinal), "web: script and img in the command are encoded");
            check(!body.Contains("<script>alert", StringComparison.Ordinal) && !body.Contains("<img", StringComparison.Ordinal), "web: raw <script>alert and <img are absent");
            check(body.Contains("ok□lpd□end", StringComparison.Ordinal) && !body.Contains((char)0x202E) && !body.Contains((char)0x200B), "web: bidi and zero-width characters are marked");
            check(body.Contains("data-delay=\"1500\"", StringComparison.Ordinal), "web: approveDelay sets the page delay");
            Send(client, HttpMethod.Post, run.Base + "/deny", "")?.Dispose();
            check(await run.Finished() is { Approved: false }, "web: Request run denied");
        }

        // Review Focus 5: a long command is shown in full.
        {
            string longArgument = new('a', 16_000);
            ApprovalRequest request = Sample(longArgument);
            WebRun run = new(new FakeProofMethod(), approver => approver.Request(request));
            check(await run.Opened(), "web: long run opens");
            string body = Text(Send(client, HttpMethod.Get, run.Base));
            check(body.Contains("Run: /bin/tool " + longArgument + "\n", StringComparison.Ordinal), "web: a 16,000-character command is in the page in full");
            Send(client, HttpMethod.Post, run.Base + "/deny", "")?.Dispose();
            check(await run.Finished() is { Approved: false }, "web: long run denied");
        }

        // Two runs at once.
        {
            WebRun first = new(new FakeProofMethod(), approver => approver.Request(Sample("one")));
            WebRun second = new(new FakeProofMethod(), approver => approver.Request(Sample("two")));
            check(await first.Opened() && await second.Opened(), "web: two runs open");
            check(first.Link?.Port != second.Link?.Port && first.Token != second.Token, "web: two runs use different ports and tokens");
            using HttpResponseMessage? cross = Send(client, HttpMethod.Get, "http://127.0.0.1:" + first.Link?.Port + "/a/" + second.Token);
            check(cross?.StatusCode == HttpStatusCode.NotFound, "web: one run's token does not work on the other's port");
            Send(client, HttpMethod.Post, first.Base + "/deny", "")?.Dispose();
            using HttpResponseMessage? proof = Send(client, HttpMethod.Post, second.Base + "/proof", FakeProofMethod.Good);
            ApprovalDecision? one = await first.Finished();
            ApprovalDecision? two = await second.Finished();
            check(one is { Approved: false } && two is { Approved: true }, "web: two runs decide on their own");
        }
    }

    private static void AssertionTests(Action<bool, string> check)
    {
        const string Rp = "localhost";
        const string Origin = "http://localhost:5123";
        byte[] challenge = RequestBinding.Compute("nonce", "request");
        HashSet<string> details = [];

        // A message changed after signing must fail at the signature check, so those cases share that detail.
        string? badSignature = null;

        // A few extra cases repeat an earlier detail on purpose; they name it in shared.
        void Fails(AssertionResult result, string name, bool signature = false, string? shared = null)
        {
            check(!result.Ok && result.NewSignCount == 0 && result.Detail.Length > 0, "assertion: " + name + " fails");
            bool detailRight = signature ? result.Detail == badSignature
                : shared is not null ? result.Detail == shared && details.Contains(shared)
                : details.Add(result.Detail);
            check(detailRight, "assertion: " + name + " has the expected detail (" + result.Detail + ")");
        }

        using TestAuthenticator es = TestAuthenticator.ES256();
        using TestAuthenticator rs = TestAuthenticator.RS256();
        PasskeyRecord esKey = es.Record(Rp, "laptop");
        PasskeyRecord rsKey = rs.Record(Rp, "hello");

        AssertionResult good = WebAuthn.VerifyAssertion(esKey, challenge, Origin, Rp, es.Assert(challenge, Origin, Rp, 0));
        check(good.Ok && good.NewSignCount == 0, "assertion: good ES256 passes (" + good.Detail + ")");
        good = WebAuthn.VerifyAssertion(rsKey, challenge, Origin, Rp, rs.Assert(challenge, Origin, Rp, 0));
        check(good.Ok && good.NewSignCount == 0, "assertion: good RS256 passes (" + good.Detail + ")");

        string esGood = es.Assert(challenge, Origin, Rp, 0);
        Fails(WebAuthn.VerifyAssertion(esKey, RequestBinding.Compute("other", "request"), Origin, Rp, esGood), "wrong challenge");
        Fails(WebAuthn.VerifyAssertion(esKey, challenge, "http://localhost:5124", Rp, esGood), "wrong origin");
        Fails(WebAuthn.VerifyAssertion(esKey, challenge, Origin, Rp, es.Assert(challenge, Origin, "evil.example", 0)), "wrong rpId hash");
        Fails(WebAuthn.VerifyAssertion(esKey, challenge, Origin, Rp, es.Assert(challenge, Origin, Rp, 0, type: "webauthn.create")), "type webauthn.create");
        Fails(WebAuthn.VerifyAssertion(esKey, challenge, Origin, Rp, es.Assert(challenge, Origin, Rp, 0, userVerified: false)), "user-verified flag off");
        Fails(WebAuthn.VerifyAssertion(esKey, challenge, Origin, Rp, es.Assert(challenge, Origin, Rp, 0, userPresent: false)), "user-present flag off");
        AssertionResult flipped = WebAuthn.VerifyAssertion(esKey, challenge, Origin, Rp, Tamper(esGood, "signature", bytes => bytes[^1] ^= 0x01));
        badSignature = flipped.Detail;
        Fails(flipped, "flipped signature byte");
        string rsGood = rs.Assert(challenge, Origin, Rp, 0);
        Fails(WebAuthn.VerifyAssertion(rsKey, challenge, Origin, Rp, Tamper(rsGood, "signature", bytes => bytes[^1] ^= 0x01)), "flipped RS256 signature byte", signature: true);
        Fails(WebAuthn.VerifyAssertion(esKey with { Alg = -8 }, challenge, Origin, Rp, esGood), "unknown alg");

        // Not in the brief's list, but each is a way in.
        Fails(WebAuthn.VerifyAssertion(esKey, challenge, Origin, Rp, Tamper(esGood, "id", bytes => bytes[0] ^= 0x01)), "other credential id");
        Fails(WebAuthn.VerifyAssertion(esKey, challenge, Origin, Rp, Rewrite(esGood, "clientDataJSON", text => text.Replace("\"crossOrigin\":false", "\"crossOrigin\":true", StringComparison.Ordinal))), "crossOrigin true");
        Fails(WebAuthn.VerifyAssertion(esKey, challenge, Origin, Rp, Rewrite(esGood, "clientDataJSON", text => text.Replace("{", "{ ", StringComparison.Ordinal))), "clientDataJSON changed after signing", signature: true);
        Fails(WebAuthn.VerifyAssertion(esKey, challenge, Origin, Rp, Tamper(esGood, "authenticatorData", bytes => bytes[^1] ^= 0x01)), "authenticatorData changed after signing", signature: true);
        Fails(WebAuthn.VerifyAssertion(esKey, challenge, Origin, Rp, Tamper(esGood, "authenticatorData", bytes => bytes[..36])), "authenticatorData too short");
        Fails(WebAuthn.VerifyAssertion(rsKey, challenge, Origin, Rp, es.Assert(challenge, Origin, Rp, 0).Replace(Encode(es.CredentialId), rsKey.Id, StringComparison.Ordinal)), "signature from another key", signature: true);
        Fails(WebAuthn.VerifyAssertion(esKey with { Alg = -257 }, challenge, Origin, Rp, esGood), "alg does not match the COSE key");
        Fails(WebAuthn.VerifyAssertion(esKey with { PublicKey = "AAAA" }, challenge, Origin, Rp, esGood), "damaged public key");
        Fails(WebAuthn.VerifyAssertion(esKey, challenge, Origin, Rp, "not json"), "response not JSON");
        Fails(WebAuthn.VerifyAssertion(esKey, challenge, Origin, Rp, "{\"id\":\"" + esKey.Id + "\"}"), "response missing fields");
        Fails(WebAuthn.VerifyAssertion(esKey, challenge, Origin, Rp, Rewrite(esGood, "signature", _ => "*", decode: false)), "signature not base64url");
        Fails(WebAuthn.VerifyAssertion(esKey, challenge, Origin, Rp, Rewrite(esGood, "clientDataJSON", _ => "[1]")), "clientDataJSON not an object");
        Fails(WebAuthn.VerifyAssertion(esKey, [], Origin, Rp, esGood), "empty expected challenge");
        Fails(WebAuthn.VerifyAssertion(esKey with { RpId = "other.example" }, challenge, Origin, Rp, esGood), "passkey stored for another rpId");
        Fails(WebAuthn.VerifyAssertion(esKey, challenge, Origin, Rp, Rewrite(esGood, "clientDataJSON", text => text.Replace("\"crossOrigin\":false", "\"crossOrigin\":false,\"topOrigin\":\"https://evil.example\"", StringComparison.Ordinal))), "topOrigin present", shared: "cross-origin request");
        Fails(WebAuthn.VerifyAssertion(esKey, challenge, Origin, Rp, Rewrite(esGood, "clientDataJSON", text => text.Replace("\"origin\"", "\"origin\":\"" + Origin + "\",\"origin\"", StringComparison.Ordinal))), "duplicate member in clientDataJSON", shared: "clientDataJSON is not a JSON object");
        Fails(WebAuthn.VerifyAssertion(esKey, challenge, Origin, Rp, Rewrite(esGood, "signature", text => text + "=", decode: false)), "padded base64url", shared: "response field is not base64url");
        Fails(WebAuthn.VerifyAssertion(esKey, challenge, Origin, Rp, Tamper(esGood, "signature", bytes => bytes[..10])), "truncated DER signature", signature: true);
        Fails(WebAuthn.VerifyAssertion(esKey with { PublicKey = Encode([.. Base64Url.DecodeFromChars(esKey.PublicKey), 0]) }, challenge, Origin, Rp, esGood), "public key with trailing bytes", shared: "public key is not valid");

        Fails(WebAuthn.VerifyAssertion(esKey with { PublicKey = null! }, challenge, Origin, Rp, esGood), "null public key", shared: "public key is not valid");
        Fails(WebAuthn.VerifyAssertion(null!, challenge, Origin, Rp, esGood), "null passkey");

        PasskeyRecord counted = esKey with { SignCount = 5 };
        AssertionResult same = WebAuthn.VerifyAssertion(counted, challenge, Origin, Rp, es.Assert(challenge, Origin, Rp, 5));
        check(!same.Ok, "assertion: stored 5 and new 5 fails");
        check(details.Add(same.Detail), "assertion: sign count has its own detail (" + same.Detail + ")");
        check(!WebAuthn.VerifyAssertion(counted, challenge, Origin, Rp, es.Assert(challenge, Origin, Rp, 0)).Ok, "assertion: stored 5 and new 0 fails");
        AssertionResult next = WebAuthn.VerifyAssertion(counted, challenge, Origin, Rp, es.Assert(challenge, Origin, Rp, 6));
        check(next.Ok && next.NewSignCount == 6, "assertion: stored 5 and new 6 passes with NewSignCount 6");
        check(WebAuthn.VerifyAssertion(esKey, challenge, Origin, Rp, es.Assert(challenge, Origin, Rp, 0)).Ok, "assertion: stored 0 and new 0 passes (synced passkey)");
    }

    private static void RegistrationTests(Action<bool, string> check)
    {
        const string Rp = "localhost";
        const string Origin = "http://localhost:5123";
        byte[] challenge = RequestBinding.Compute("nonce", "register");

        // Every rejection names its exact Detail, so a test cannot pass for a different reason than it states.
        void Fails(RegistrationResult result, string name, string detail)
        {
            check(!result.Ok && result.Key is null && result.Detail == detail, "registration: " + name + " fails with '" + detail + "' (got '" + result.Detail + "')");
        }

        using TestAuthenticator es = TestAuthenticator.ES256();
        using TestAuthenticator rs = TestAuthenticator.RS256();

        foreach (TestAuthenticator who in new[] { es, rs })
        {
            string label = who.Alg == -7 ? "ES256" : "RS256";
            RegistrationResult result = WebAuthn.VerifyRegistration(challenge, Origin, Rp, "laptop", who.Attest(challenge, Origin, Rp, "laptop"));
            PasskeyRecord? key = result.Key;
            check(result.Ok && key is not null && result.Detail == "ok", "registration: good " + label + " passes (" + result.Detail + ")");
            check(key is not null && key.Id == Encode(who.CredentialId) && key.PublicKey == Encode(who.CoseKey()) && key.Alg == who.Alg, "registration: " + label + " record has the credential id, exact COSE bytes and alg");
            check(key is not null && key.RpId == Rp && key.Name == "laptop" && key.SignCount == 0 && DateTimeOffset.UtcNow - key.Created < TimeSpan.FromMinutes(1), "registration: " + label + " record has rpId, name, SignCount 0 and Created now");
            AssertionResult signIn = key is null ? new AssertionResult(false, "no key", 0) : WebAuthn.VerifyAssertion(key, challenge, Origin, Rp, who.Assert(challenge, Origin, Rp, 0));
            check(signIn.Ok, "registration: " + label + " record then passes VerifyAssertion (" + signIn.Detail + ")");
        }

        RegistrationResult Register(string json) => WebAuthn.VerifyRegistration(challenge, Origin, Rp, "laptop", json);
        string esGood = es.Attest(challenge, Origin, Rp, "laptop");

        Fails(Register(es.Attest(challenge, Origin, Rp, "laptop", fmt: "packed")), "fmt packed", "attestation format is not none");
        Fails(Register(es.Attest(challenge, Origin, Rp, "laptop", type: "webauthn.get")), "type webauthn.get", "clientData type is not webauthn.create");
        Fails(WebAuthn.VerifyRegistration(RequestBinding.Compute("other", "register"), Origin, Rp, "laptop", esGood), "wrong challenge", "challenge does not match");
        Fails(WebAuthn.VerifyRegistration(challenge, "http://localhost:5124", Rp, "laptop", esGood), "wrong origin", "origin does not match");
        Fails(Register(es.Attest(challenge, Origin, Rp, "laptop", authDataRpId: "evil.example")), "wrong rpId hash", "rpId hash does not match");
        Fails(WebAuthn.VerifyRegistration(challenge, Origin, "other.example", "laptop", esGood), "rpId argument differs from the hash", "rpId hash does not match");
        Fails(Register(es.Attest(challenge, Origin, Rp, "laptop", flags: 0x41)), "user-verified flag off", "user not verified");
        Fails(Register(es.Attest(challenge, Origin, Rp, "laptop", flags: 0x44)), "user-present flag off", "user not present");
        Fails(Register(es.Attest(challenge, Origin, Rp, "laptop", flags: 0x05)), "attested-credential-data flag off", "no attested credential data");
        Fails(Register(es.Attest(challenge, Origin, Rp, "laptop", authDataLength: 36)), "authData shorter than 37 bytes", "authData is too short");
        Fails(Register(es.Attest(challenge, Origin, Rp, "laptop", authDataLength: 60)), "authData cut inside the credential id", "attested credential data is truncated");
        Fails(Register(es.Attest(challenge, Origin, Rp, "laptop", authDataLength: 40)), "authData cut before the credential id length", "attested credential data is truncated");

        // Keys: the same rules sign-in applies.
        (byte[] x, byte[] y) = es.EcPoint();
        Fails(Register(es.Attest(challenge, Origin, Rp, "laptop", coseKey: TestAuthenticator.EcCose(-8, 1, x, y))), "alg -8", "unsupported algorithm");
        Fails(Register(es.Attest(challenge, Origin, Rp, "laptop", coseKey: TestAuthenticator.EcCose(null, 1, x, y))), "alg missing", "unsupported algorithm");
        Fails(Register(es.Attest(challenge, Origin, Rp, "laptop", coseKey: [0xA0])), "empty COSE map", "unsupported algorithm");
        Fails(Register(es.Attest(challenge, Origin, Rp, "laptop", coseKey: [0xFF])), "COSE key not CBOR", "public key is not valid");
        Fails(Register(es.Attest(challenge, Origin, Rp, "laptop", coseKey: TestAuthenticator.EcCose(-257, 1, x, y))), "EC key labelled RS256", "public key does not match its algorithm");
        Fails(Register(es.Attest(challenge, Origin, Rp, "laptop", coseKey: TestAuthenticator.EcCose(-7, 2, x, y))), "EC crv 2", "EC key is not on P-256");
        Fails(Register(es.Attest(challenge, Origin, Rp, "laptop", coseKey: TestAuthenticator.EcCose(-7, 1, x[1..], y))), "EC x of 31 bytes", "EC key coordinates are not 32 bytes");
        byte[] offCurve = [.. y];
        offCurve[^1] ^= 0x01;
        Fails(Register(es.Attest(challenge, Origin, Rp, "laptop", coseKey: TestAuthenticator.EcCose(-7, 1, x, offCurve))), "EC point off the curve", "EC key point is not on the curve");

        byte[] modulus2048 = RandomNumberGenerator.GetBytes(256);
        modulus2048[0] |= 0x80;
        byte[] modulus2041 = RandomNumberGenerator.GetBytes(256);
        modulus2041[0] = 0x01; // 256 bytes, but only 2041 bits.
        byte[] paddedModulus2041 = [0, .. modulus2041];
        byte[] exponent = [0x01, 0x00, 0x01];
        Fails(Register(rs.Attest(challenge, Origin, Rp, "laptop", coseKey: TestAuthenticator.RsaCose(-257, modulus2041, exponent))), "RSA modulus of 2041 bits", "RSA modulus is under 2048 bits");
        Fails(Register(rs.Attest(challenge, Origin, Rp, "laptop", coseKey: TestAuthenticator.RsaCose(-257, paddedModulus2041, exponent))), "RSA modulus of 2041 bits behind a zero byte", "RSA modulus is under 2048 bits");
        Fails(Register(rs.Attest(challenge, Origin, Rp, "laptop", coseKey: TestAuthenticator.RsaCose(-257, modulus2048[1..], exponent))), "RSA modulus of 2040 bits", "RSA modulus is under 2048 bits");
        Fails(Register(rs.Attest(challenge, Origin, Rp, "laptop", coseKey: TestAuthenticator.RsaCose(-257, modulus2048, [0x01]))), "RSA e=1", "RSA exponent is not odd and at least 3");
        Fails(Register(rs.Attest(challenge, Origin, Rp, "laptop", coseKey: TestAuthenticator.RsaCose(-257, modulus2048, [0x02]))), "RSA e=2", "RSA exponent is not odd and at least 3");
        Fails(Register(rs.Attest(challenge, Origin, Rp, "laptop", coseKey: TestAuthenticator.RsaCose(-257, modulus2048, [0x01, 0x00, 0x00]))), "RSA even e", "RSA exponent is not odd and at least 3");
        Fails(Register(rs.Attest(challenge, Origin, Rp, "laptop", coseKey: TestAuthenticator.RsaCose(-257, modulus2048, [0x00, 0x00, 0x01]))), "RSA e=1 behind zero bytes", "RSA exponent is not odd and at least 3");
        Fails(Register(rs.Attest(challenge, Origin, Rp, "laptop", coseKey: TestAuthenticator.RsaCose(-257, modulus2048, []))), "RSA empty e", "RSA exponent is not odd and at least 3");
        Fails(Register(rs.Attest(challenge, Origin, Rp, "laptop", coseKey: TestAuthenticator.RsaCose(-7, modulus2048, exponent))), "RSA key labelled ES256", "public key does not match its algorithm");

        // Bytes after the key are refused unless the authenticator flags extension data.
        Fails(Register(es.Attest(challenge, Origin, Rp, "laptop", coseKey: [.. es.CoseKey(), 0x00])), "byte after the COSE key", "authData has bytes after the public key");
        RegistrationResult withExtensions = Register(es.Attest(challenge, Origin, Rp, "laptop", flags: 0xC5, coseKey: [.. es.CoseKey(), 0xA0]));
        check(withExtensions.Ok && withExtensions.Key!.PublicKey == Encode(es.CoseKey()), "registration: extension data after the key is allowed and not stored in the key");

        // The message itself.
        Fails(Register("not json"), "response not JSON", "response is not a JSON object");
        Fails(Register("{\"id\":\"x\"}"), "response missing fields", "response is missing a field");
        Fails(Register(Rewrite(esGood, "attestationObject", _ => "*", decode: false)), "attestationObject not base64url", "response field is not base64url");
        Fails(Register(Rewrite(esGood, "id", text => text + "=", decode: false)), "id with padding", "credential id does not match");
        Fails(Register(Tamper(esGood, "id", bytes => bytes[0] ^= 0x01)), "id of another credential", "credential id does not match");
        Fails(Register(Rewrite(esGood, "clientDataJSON", _ => "[1]")), "clientDataJSON not an object", "clientDataJSON is not a JSON object");
        Fails(Register(TestAuthenticator.AttestationJson(Encode(es.CredentialId), [0xFF, 0xFE, 0x7B], [0xA0])), "clientDataJSON not UTF-8", "clientDataJSON is not UTF-8");
        Fails(Register(Rewrite(esGood, "clientDataJSON", text => text.Replace("\"crossOrigin\":false", "\"crossOrigin\":true", StringComparison.Ordinal))), "crossOrigin true", "cross-origin request");
        Fails(Register(Rewrite(esGood, "clientDataJSON", text => text.Replace("\"crossOrigin\":false", "\"crossOrigin\":false,\"topOrigin\":\"https://evil.example\"", StringComparison.Ordinal))), "topOrigin present", "cross-origin request");
        Fails(Register(Rewrite(esGood, "clientDataJSON", text => text.Replace("\"origin\"", "\"origin\":\"" + Origin + "\",\"origin\"", StringComparison.Ordinal))), "duplicate clientDataJSON member", "clientDataJSON is not a JSON object");
        Fails(WebAuthn.VerifyRegistration([], Origin, Rp, "laptop", esGood), "empty challenge", "no expected challenge");
        Fails(WebAuthn.VerifyRegistration(challenge, Origin, Rp, "  ", esGood), "blank name", "no passkey name");
        Fails(WebAuthn.VerifyRegistration(challenge, Origin, Rp, "laptop", null!), "null response", "missing input");
        Fails(WebAuthn.VerifyRegistration(null!, Origin, Rp, "laptop", esGood), "null challenge", "missing input");

        // attestationObject shapes that are not what "none" produces.
        byte[] authData = AuthDataOf(esGood);
        byte[] clientData = Base64Url.DecodeFromChars(JsonSerializer.Deserialize<Dictionary<string, string>>(esGood)!["clientDataJSON"]);
        string Object(Action<CborWriter> build, byte[]? trailing = null)
        {
            CborWriter writer = new(CborConformanceMode.Lax);
            build(writer);

            return TestAuthenticator.AttestationJson(Encode(es.CredentialId), clientData, [.. writer.Encode(), .. trailing ?? []]);
        }

        void Fmt(CborWriter writer)
        {
            writer.WriteTextString("fmt");
            writer.WriteTextString("none");
        }

        void Stmt(CborWriter writer)
        {
            writer.WriteTextString("attStmt");
            writer.WriteStartMap(0);
            writer.WriteEndMap();
        }

        void Auth(CborWriter writer)
        {
            writer.WriteTextString("authData");
            writer.WriteByteString(authData);
        }

        const string Invalid = "attestationObject is not valid";

        Fails(Register(TestAuthenticator.AttestationJson(Encode(es.CredentialId), clientData, [0xFF])), "attestationObject not CBOR", Invalid);
        Fails(Register(Object(w => w.WriteTextString("none"))), "attestationObject not a map", Invalid);
        Fails(Register(Object(w =>
        {
            w.WriteStartMap(2);
            Fmt(w);
            Auth(w);
            w.WriteEndMap();
        })), "attestationObject without attStmt", Invalid);
        Fails(Register(Object(w =>
        {
            w.WriteStartMap(3);
            Fmt(w);
            Stmt(w);
            w.WriteTextString("x");
            w.WriteInt32(1);
            w.WriteEndMap();
        })), "attestationObject with an unknown member and no authData", Invalid);
        Fails(Register(Object(w =>
        {
            w.WriteStartMap(4);
            Fmt(w);
            Stmt(w);
            Auth(w);
            Auth(w);
            w.WriteEndMap();
        })), "attestationObject with authData twice", Invalid);
        Fails(Register(Object(w =>
        {
            w.WriteStartMap(3);
            Fmt(w);
            w.WriteTextString("attStmt");
            w.WriteStartMap(1);
            w.WriteTextString("sig");
            w.WriteByteString([1]);
            w.WriteEndMap();
            Auth(w);
            w.WriteEndMap();
        })), "attestationObject with a non-empty attStmt", Invalid);
        Fails(Register(Object(w =>
        {
            w.WriteStartMap(3);
            Fmt(w);
            Stmt(w);
            w.WriteTextString("authData");
            w.WriteTextString("text");
            w.WriteEndMap();
        })), "attestationObject with authData as text", Invalid);
        Fails(Register(Object(w =>
        {
            w.WriteStartMap(3);
            Fmt(w);
            Stmt(w);
            Auth(w);
            w.WriteEndMap();
        }, [0x00])), "attestationObject with bytes after the map", Invalid);

        // The same key rules reach sign-in too, for keys stored before they were checked at registration.
        PasskeyRecord esKey = es.Record(Rp, "laptop");
        PasskeyRecord rsKey = rs.Record(Rp, "hello");
        void KeyFails(PasskeyRecord key, TestAuthenticator who, string name, string detail)
        {
            AssertionResult result = WebAuthn.VerifyAssertion(key, challenge, Origin, Rp, who.Assert(challenge, Origin, Rp, 0));
            check(!result.Ok && result.NewSignCount == 0 && result.Detail == detail, "assertion: stored key with " + name + " fails with '" + detail + "' (got '" + result.Detail + "')");
        }

        KeyFails(rsKey with { PublicKey = Encode(TestAuthenticator.RsaCose(-257, modulus2041, exponent)) }, rs, "RSA modulus of 2041 bits", "RSA modulus is under 2048 bits");
        KeyFails(rsKey with { PublicKey = Encode(TestAuthenticator.RsaCose(-257, modulus2048, [0x01])) }, rs, "RSA e=1", "RSA exponent is not odd and at least 3");
        KeyFails(rsKey with { PublicKey = Encode(TestAuthenticator.RsaCose(-257, modulus2048, [0x01, 0x00, 0x00])) }, rs, "RSA even e", "RSA exponent is not odd and at least 3");
        KeyFails(esKey with { PublicKey = Encode(TestAuthenticator.EcCose(-7, 2, x, y)) }, es, "EC crv 2", "EC key is not on P-256");
        KeyFails(esKey with { PublicKey = Encode(TestAuthenticator.EcCose(-7, 1, x, offCurve)) }, es, "EC point off the curve", "EC key point is not on the curve");
    }

    private static byte[] AuthDataOf(string registrationJson)
    {
        byte[] attestation = Base64Url.DecodeFromChars(JsonSerializer.Deserialize<Dictionary<string, string>>(registrationJson)!["attestationObject"]);
        CborReader reader = new(attestation);
        reader.ReadStartMap();
        while (reader.ReadTextString() != "authData")
        {
            reader.SkipValue();
        }

        return reader.ReadByteString();
    }

    private static string Encode(byte[] bytes) => TestAuthenticator.Encode(bytes);

    /// <summary>Decodes one base64url field of the response JSON, changes the bytes, and encodes them again.</summary>
    private static string Tamper(string json, string field, Action<byte[]> change)
    {
        Dictionary<string, string> values = JsonSerializer.Deserialize<Dictionary<string, string>>(json)!;
        byte[] bytes = Base64Url.DecodeFromChars(values[field]);
        change(bytes);
        values[field] = Encode(bytes);

        return JsonSerializer.Serialize(values);
    }

    private static string Tamper(string json, string field, Func<byte[], byte[]> change)
    {
        Dictionary<string, string> values = JsonSerializer.Deserialize<Dictionary<string, string>>(json)!;
        values[field] = Encode(change(Base64Url.DecodeFromChars(values[field])));

        return JsonSerializer.Serialize(values);
    }

    /// <summary>Changes one field as text: the decoded UTF-8 text when decode is true, else the raw field value.</summary>
    private static string Rewrite(string json, string field, Func<string, string> change, bool decode = true)
    {
        Dictionary<string, string> values = JsonSerializer.Deserialize<Dictionary<string, string>>(json)!;
        values[field] = decode
            ? Encode(Encoding.UTF8.GetBytes(change(Encoding.UTF8.GetString(Base64Url.DecodeFromChars(values[field])))))
            : change(values[field]);

        return JsonSerializer.Serialize(values);
    }

    // ---- Setting and removing secrets in the admin app (SecretFlows, SecretEntry.Session, SecretCrypto).

    /// <summary>The browser's side of the encryption, with .NET crypto: ECDH P-256, HKDF-SHA-256, AES-256-GCM with the tag appended.</summary>
    private static (byte[] Epk, byte[] Ct) BrowserEncrypt(byte[] serverKey, byte[] bind, byte[] iv, byte[] associated, byte[] plaintext)
    {
        using ECDiffieHellman mine = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        ECParameters theirs = new()
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = serverKey[1..33], Y = serverKey[33..65] },
        };
        using ECDiffieHellman server = ECDiffieHellman.Create(theirs);
        byte[] shared = mine.DeriveRawSecretAgreement(server.PublicKey);
        byte[] key = HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 32, bind, Encoding.UTF8.GetBytes("with-secrets/v1 secrets"));
        byte[] ct = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        using AesGcm aes = new(key, 16);
        aes.Encrypt(iv, plaintext, ct, tag, associated);
        ECParameters own = mine.ExportParameters(false);

        return ([0x04, .. own.Q.X!, .. own.Q.Y!], [.. ct, .. tag]);
    }

    /// <summary>True only when the call throws a CryptographicException. Success or any other exception is false.</summary>
    private static bool CryptoFails(Func<string> call)
    {
        try
        {
            call();

            return false;
        }
        catch (CryptographicException)
        {
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static void SecretCryptoTests(Action<bool, string> check)
    {
        (byte[] state, string publicKey) = SecretCrypto.NewServerKey();
        byte[] point = Base64Url.DecodeFromChars(publicKey);
        check(point.Length == 65 && point[0] == 0x04, "crypto: the server key is a 65-byte uncompressed point");
        check(SecretCrypto.NewServerKey().PublicKeyBase64Url != publicKey, "crypto: each page gets a new server key");

        byte[] bind = RandomNumberGenerator.GetBytes(32);
        byte[] iv = RandomNumberGenerator.GetBytes(12);
        const string Plain = "{\"A_NAME\":\"value-one\"}";
        (byte[] epk, byte[] ct) = BrowserEncrypt(point, bind, iv, bind, Encoding.UTF8.GetBytes(Plain));
        string Run(byte[] withBind, byte[] withEpk, byte[] withIv, byte[] withCt, byte[]? withState = null)
            => SecretCrypto.Decrypt(withState ?? state, withBind, Encode(withEpk), Encode(withIv), Encode(withCt));

        check(Run(bind, epk, iv, ct) == Plain, "crypto: what the browser encrypts is decrypted");
        check(SecretCrypto.Challenge(bind, ct).AsSpan().SequenceEqual(SHA256.HashData([.. bind, .. SHA256.HashData(ct)])), "crypto: the challenge is SHA-256(bind + SHA-256(ct))");

        byte[] tampered = [.. ct];
        tampered[0] ^= 1;
        byte[] tagTampered = [.. ct];
        tagTampered[^1] ^= 1;
        byte[] offCurve = [0x04, .. Enumerable.Repeat((byte)1, 32), .. Enumerable.Repeat((byte)2, 32)];
        byte[] compressed = [0x02, .. epk[1..]];
        byte[] tooBig = [0x04, .. Enumerable.Repeat((byte)0xFF, 64)];
        (byte[] otherState, _) = SecretCrypto.NewServerKey();
        (byte[] badTextEpk, byte[] badTextCt) = BrowserEncrypt(point, bind, iv, bind, [0xC3, 0x28]);
        (byte[] otherAadEpk, byte[] otherAadCt) = BrowserEncrypt(point, bind, iv, RandomNumberGenerator.GetBytes(32), Encoding.UTF8.GetBytes(Plain));
        (string Label, Func<string> Call)[] failures =
        [
            ("another bind", () => Run(RandomNumberGenerator.GetBytes(32), epk, iv, ct)),
            ("other associated data", () => Run(bind, otherAadEpk, iv, otherAadCt)),
            ("a tampered ct", () => Run(bind, epk, iv, tampered)),
            ("a tampered tag", () => Run(bind, epk, iv, tagTampered)),
            ("a wrong iv", () => Run(bind, epk, RandomNumberGenerator.GetBytes(12), ct)),
            ("an iv of 11 bytes", () => Run(bind, epk, iv[..11], ct)),
            ("a ct shorter than the tag", () => Run(bind, epk, iv, ct[..15])),
            ("an epk of 64 bytes", () => Run(bind, epk[..64], iv, ct)),
            ("an epk of 66 bytes", () => Run(bind, [.. epk, 0], iv, ct)),
            ("an epk that does not start with 4", () => Run(bind, compressed, iv, ct)),
            ("an epk that is not on the curve", () => Run(bind, offCurve, iv, ct)),
            ("an epk with coordinates past the field", () => Run(bind, tooBig, iv, ct)),
            ("another server key", () => Run(bind, epk, iv, ct, otherState)),
            ("plaintext that is not UTF-8", () => Run(bind, badTextEpk, iv, badTextCt)),
            ("an epk that is not base64url", () => SecretCrypto.Decrypt(state, bind, "!!", Encode(iv), Encode(ct))),
            ("a ct that is not base64url", () => SecretCrypto.Decrypt(state, bind, Encode(epk), Encode(iv), "a b")),
        ];
        foreach ((string label, Func<string> call) in failures)
        {
            check(CryptoFails(call), "crypto: " + label + " throws CryptographicException");
        }
    }

    internal enum Twist
    {
        None,
        TamperCt,
        WrongIv,
        WrongAad,
        SignOtherCt,
        SignOtherManifest,
        SealTwice,
        NoSeal,
        PointOffCurve,
        ShortEpk,
        NoSignature,
        NoCt,
        Cancel,
    }

    /// <summary>What one entry or removal did in the web app's secret flow, as the test browser saw it.</summary>
    internal sealed class EntryRun
    {
        public SecretChange? Result { get; set; }

        /// <summary>Every text the flow showed or answered: where a value must never be.</summary>
        public List<string> Seen { get; } = [];

        public SecretEntryDto? Entry { get; set; }

        public SecretRemovalDto? Removal { get; set; }

        /// <summary>The entry or removal was cancelled (the person pressed Cancel, or did not use the passkey).</summary>
        public bool Cancelled { get; set; }

        public int SealStatus { get; set; }

        public string SealReply { get; set; } = "";

        /// <summary>The reply to the same values sealed a second time (<see cref="Twist.SealTwice" />).</summary>
        public string SecondSealReply { get; set; } = "";

        public int SaveStatus { get; set; }

        public string SaveReply { get; set; } = "";

        /// <summary>A GET of the page and a second POST after the outcome were both 404 (or found no server).</summary>
        public bool AgainGone { get; set; }
    }

    /// <summary>The address the test browser is "at" in the web app's secret flows (the passkey signs for it).</summary>
    private const string FlowOrigin = "http://localhost:1";

    private static SecretFlows NewFlows(PasskeyStore passkeys, SecretStore store)
    {
        return new SecretFlows(store, store.Database.Audit, () => new PasskeyMethod(passkeys, new ApprovalSettings(null, 0, TimeSpan.FromSeconds(20))), new FlowClock());
    }

    /// <summary>
    /// Plays the browser against the web app's entry of values, as its script does: encrypt the values to the entry's key, post them to
    /// seal (as they are typed), take the manifest it returns, then sign SHA-256(bind || SHA-256(ct) || SHA-256(manifest)) and post the
    /// save. One thing is wrong when asked. <paramref name="between" /> runs after the entry started and before anything is sent.
    /// </summary>
    internal static EntryRun SetRun(PasskeyStore passkeys, SecretStore store, IReadOnlyList<string> names, TestAuthenticator key, string plaintext, Twist twist = Twist.None, Action? between = null)
    {
        EntryRun run = new();
        SecretFlows flows = NewFlows(passkeys, store);
        (SecretEntryDto? entry, string? problem) = flows.StartSet(names, "s1", FlowOrigin);
        if (entry is null)
        {
            run.Result = new SecretChange(problem!.Contains("failed verification", StringComparison.Ordinal) || problem.StartsWith("cannot use the secret store", StringComparison.Ordinal) ? RunCommand.StoreError : RunCommand.Denied, problem);
            run.Seen.Add(problem);

            return run;
        }

        run.Entry = entry;
        run.Seen.Add(entry.Text);
        run.Seen.Add(entry.Payload.GetRawText());
        between?.Invoke();
        if (twist == Twist.Cancel)
        {
            run.Cancelled = flows.Cancel(entry.Id, "s1");
            run.AgainGone = flows.Seal(entry.Id, "s1", "{}") is null && flows.SaveSet(entry.Id, "s1", "{}") is null;
            run.Result = new SecretChange(RunCommand.Denied, "cancelled; nothing was stored");

            return run;
        }

        byte[] bind = Base64Url.DecodeFromChars(entry.Payload.GetProperty("bind").GetString()!);
        byte[] serverKey = Base64Url.DecodeFromChars(entry.PublicKey);
        byte[] iv = RandomNumberGenerator.GetBytes(12);
        (byte[] epk, byte[] ct) = BrowserEncrypt(serverKey, bind, iv, twist == Twist.WrongAad ? RandomNumberGenerator.GetBytes(32) : bind, Encoding.UTF8.GetBytes(plaintext));
        if (twist == Twist.TamperCt)
        {
            ct[0] ^= 1;
        }

        epk = twist switch
        {
            Twist.PointOffCurve => [0x04, .. Enumerable.Repeat((byte)1, 32), .. Enumerable.Repeat((byte)2, 32)],
            Twist.ShortEpk => epk[..64],
            _ => epk,
        };
        if (twist == Twist.WrongIv)
        {
            iv = RandomNumberGenerator.GetBytes(12);
        }

        Dictionary<string, string> sealedBody = new() { ["epk"] = Encode(epk), ["iv"] = Encode(iv), ["ct"] = Encode(ct) };
        string manifest = "";
        if (twist != Twist.NoSeal)
        {
            (int Status, string Body)? sealedReply = flows.Seal(entry.Id, "s1", JsonSerializer.Serialize(sealedBody));
            run.SealStatus = sealedReply?.Status ?? 0;
            run.SealReply = sealedReply?.Body ?? "";
            run.Seen.Add(run.SealReply);
            if (run.SealStatus == 200)
            {
                using JsonDocument reply = JsonDocument.Parse(run.SealReply);
                manifest = reply.RootElement.GetProperty("manifest").GetString() ?? "";
            }

            if (twist == Twist.SealTwice)
            {
                // The same ct again (a retried request): the program must answer with the first manifest, which is signed below.
                run.SecondSealReply = flows.Seal(entry.Id, "s1", JsonSerializer.Serialize(sealedBody))?.Body ?? "";
            }
        }

        byte[] signedCt = twist == Twist.SignOtherCt ? [.. ct, 0] : ct;
        string signedManifest = twist == Twist.SignOtherManifest ? manifest.Replace("\"v\":", "\"v\":1", StringComparison.Ordinal) : manifest;
        byte[] challenge = Manifest.Challenge([.. bind, .. SHA256.HashData(signedCt)], signedManifest);
        Dictionary<string, string> body = JsonSerializer.Deserialize<Dictionary<string, string>>(key.Assert(challenge, FlowOrigin, "localhost", TestState.NextCount()))!;
        foreach ((string name, string value) in sealedBody)
        {
            body[name] = value;
        }

        if (twist == Twist.NoSignature)
        {
            body.Remove("signature");
        }

        if (twist == Twist.NoCt)
        {
            body.Remove("ct");
        }

        string json = JsonSerializer.Serialize(body);
        (int Status, string Body)? saved = flows.SaveSet(entry.Id, "s1", json);
        run.SaveStatus = saved?.Status ?? 0;
        run.SaveReply = saved?.Body ?? "";
        run.Seen.Add(run.SaveReply);
        run.AgainGone = flows.SaveSet(entry.Id, "s1", json) is null && flows.Seal(entry.Id, "s1", JsonSerializer.Serialize(sealedBody)) is null;
        run.Result = run.SaveStatus == 200
            ? new SecretChange(0, "Stored " + string.Join(", ", names) + ".")
            : new SecretChange(run.SaveStatus == 500 ? RunCommand.StoreError : RunCommand.Denied, run.SaveReply);

        return run;
    }

    /// <summary>Starts the removal in the web app's flow and answers as the person does: the passkey signs the new manifest, or the removal is cancelled.</summary>
    private static EntryRun RemoveRun(PasskeyStore passkeys, SecretStore store, IReadOnlyList<string> names, TestAuthenticator key, bool approve)
    {
        EntryRun run = new();
        SecretFlows flows = NewFlows(passkeys, store);
        (SecretRemovalDto? removal, string? problem) = flows.StartRemove(names, "s1", FlowOrigin);
        if (removal is null)
        {
            run.Result = new SecretChange(problem!.Contains("failed verification", StringComparison.Ordinal) || problem.StartsWith("cannot use the secret store", StringComparison.Ordinal) ? RunCommand.StoreError : RunCommand.Denied, problem);
            run.Seen.Add(problem);

            return run;
        }

        run.Removal = removal;
        run.Seen.Add(removal.Text);
        if (!approve)
        {
            run.Cancelled = flows.Cancel(removal.Id, "s1");
            run.Result = new SecretChange(RunCommand.Denied, "cancelled; nothing was removed");

            return run;
        }

        byte[] bind = Base64Url.DecodeFromChars(removal.Payload.GetProperty("bind").GetString()!);
        string proof = key.Assert(Manifest.Challenge(bind, removal.Manifest), FlowOrigin, "localhost", TestState.NextCount());
        (int Status, string Detail)? saved = flows.SaveRemove(removal.Id, "s1", proof);
        run.SaveStatus = saved?.Status ?? 0;
        run.SaveReply = saved?.Detail ?? "";
        run.Seen.Add(run.SaveReply);
        run.Result = run.SaveStatus == 200
            ? new SecretChange(0, "Removed " + string.Join(", ", names) + ".")
            : new SecretChange(run.SaveStatus == 500 ? RunCommand.StoreError : RunCommand.Denied, run.SaveReply);

        return run;
    }


    private static string Values(params (string Name, string Value)[] items)
    {
        return JsonSerializer.Serialize(items.ToDictionary(item => item.Name, item => item.Value));
    }

    /// <summary>The audit rows of an event in the store's with-secrets.db.</summary>
    private static int AuditCount(SecretStore store, string eventName)
    {
        return TestAudit.TryRead(store.Database, 1000, null, out IReadOnlyList<AuditRow> rows, out _) ? rows.Count(row => row.Event == eventName) : -1;
    }

    /// <summary>The values in the store, read back (and verified) the way a run reads them.</summary>
    private static Dictionary<string, string> Stored(SecretStore store)
    {
        IReadOnlyList<string> names = store.ListNames();
        if (names.Count == 0)
        {
            return [];
        }

        using SecretValues values = SecretStoreTests.Read(store, names);

        return names.ToDictionary(name => name, values.Text);
    }

    private sealed class FlowClock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 11, 1, 10, 0, 0, TimeSpan.Zero);

        public List<FlowTimer> Timers { get; } = [];

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            FlowTimer timer = new(callback, state, period);
            Timers.Add(timer);

            return timer;
        }

        /// <summary>Runs every timer that is still on, as its period would.</summary>
        public void Tick()
        {
            foreach (FlowTimer timer in Timers.Where(item => !item.Disposed).ToList())
            {
                timer.Callback(timer.State);
            }
        }
    }

    private sealed class FlowTimer(TimerCallback callback, object? state, TimeSpan period) : ITimer
    {
        public TimerCallback Callback { get; } = callback;

        public object? State { get; } = state;

        public TimeSpan Period { get; } = period;

        public bool Disposed { get; private set; }

        public bool Change(TimeSpan dueTime, TimeSpan period) => true;

        public void Dispose() => Disposed = true;

        public ValueTask DisposeAsync()
        {
            Dispose();

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>The web app's secret flows: who may continue an entry, how many may be open, and that nothing is stored by starting one.</summary>
    private static void SecretFlowsTests(Action<bool, string> check)
    {
        string folder = Path.Combine(Path.GetTempPath(), "ws-flows-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            using TestAuthenticator laptop = TestAuthenticator.ES256();
            StateDatabase db = StateDatabase.InFolder(folder);
            TestState.Add(db, laptop.Record("localhost", "laptop"), withStore: true);
            SecretStore store = new(db);
            ApprovalSettings settings = new(null, 0, TimeSpan.FromSeconds(20));
            FlowClock clock = new();
            SecretFlows flows = new(store, db.Audit, () => new PasskeyMethod(new PasskeyStore(db), settings), clock);
            const string Origin = "http://localhost:1";

            check(flows.List() is { Names: { Count: 0 }, Problem: null }, "secret flows: an empty store lists no names");
            check(flows.StartSet(["bad-name"], "s1", Origin).Entry is null, "secret flows: a name that is not valid starts nothing");
            check(flows.StartSet([], "s1", Origin).Entry is null, "secret flows: no names start nothing");
            check(flows.StartRemove(["NOT_STORED"], "s1", Origin) is { Removal: null, Problem: var unknown } && unknown!.Contains("Unknown secret", StringComparison.Ordinal), "secret flows: removing a name that is not stored is refused");

            (SecretEntryDto? entry, _) = flows.StartSet(["A_NEW"], "s1", Origin);
            check(entry is { Fields: [{ Name: "A_NEW", Replace: false }] } && entry.Text.Contains("A_NEW", StringComparison.Ordinal), "secret flows: an entry names the secret and says it is new");
            check(store.ListNames().Count == 0, "secret flows: starting an entry stores nothing");
            check(flows.Seal(entry!.Id, "s2", "{}") is null && flows.SaveSet(entry.Id, "s2", "{}") is null && !flows.Cancel(entry.Id, "s2"), "secret flows: another session cannot continue, save or cancel the entry");
            check(flows.Seal(entry.Id, "s1", "{}") is { Status: 400 }, "secret flows: a malformed seal is refused and the entry stays open");
            check(flows.Cancel(entry.Id, "s1") && flows.Seal(entry.Id, "s1", "{}") is null, "secret flows: cancelling ends the entry");

            List<string> ids = [];
            for (int index = 0; index < SecretFlows.MaxOpen; index++)
            {
                ids.Add(flows.StartSet(["N" + index], "s1", Origin).Entry!.Id);
            }

            check(flows.StartSet(["ONE_MORE"], "s1", Origin).Entry is null, "secret flows: only a few entries are open at once");
            clock.Advance(SecretFlows.Lifetime + TimeSpan.FromSeconds(1));
            check(flows.Seal(ids[0], "s1", "{}") is null, "secret flows: an entry ends after its lifetime");
            check(flows.StartSet(["ONE_MORE"], "s1", Origin).Entry is not null, "secret flows: expired entries free their place");
            flows.CancelAll();
            check(flows.Cancel(ids[1], "s1") == false, "secret flows: cancelling all ends every entry");
            check(store.ListNames().Count == 0, "secret flows: nothing was stored by any of it");
        }
        finally
        {
            try
            {
                Directory.Delete(folder, true);
            }
            catch (IOException)
            {
            }
        }
    }

    /// <summary>An entry that nobody finishes loses its server key and sealed values on its own: the sweep, the session ending, the lock and the shutdown all close it, once.</summary>
    private static void SecretFlowsExpiryTests(Action<bool, string> check)
    {
        string folder = Path.Combine(Path.GetTempPath(), "ws-flows-expiry-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            using TestAuthenticator laptop = TestAuthenticator.ES256();
            StateDatabase db = StateDatabase.InFolder(folder);
            TestState.Add(db, laptop.Record("localhost", "laptop"), withStore: true);
            SecretStore store = new(db);
            ApprovalSettings settings = new(null, 0, TimeSpan.FromSeconds(20));
            FlowClock clock = new();
            SecretFlows flows = new(store, db.Audit, () => new PasskeyMethod(new PasskeyStore(db), settings), clock);
            const string Origin = "http://localhost:1";

            // Seals real values, so that there is something to clear.
            SecretEntryDto Start(string name, string session)
            {
                SecretEntryDto entry = flows.StartSet([name], session, Origin).Entry!;
                byte[] bind = Base64Url.DecodeFromChars(entry.Payload.GetProperty("bind").GetString()!);
                byte[] iv = RandomNumberGenerator.GetBytes(12);
                (byte[] epk, byte[] ct) = BrowserEncrypt(Base64Url.DecodeFromChars(entry.PublicKey), bind, iv, bind, Encoding.UTF8.GetBytes(Values((name, "a-long-enough-secret-value"))));
                Dictionary<string, string> body = new() { ["epk"] = Encode(epk), ["iv"] = Encode(iv), ["ct"] = Encode(ct) };
                (int Status, string Body)? sealedReply = flows.Seal(entry.Id, session, JsonSerializer.Serialize(body));
                check(sealedReply is { Status: 200 }, "secret flow expiry: the values of " + name + " are sealed (" + sealedReply?.Status + ")");

                return entry;
            }

            check(clock.Timers.Count == 0, "secret flow expiry: with nothing open there is no timer");
            SecretEntryDto abandoned = Start("ABANDONED", "s1");
            SecretEntry.Session abandonedPage = flows.SessionOf(abandoned.Id)!;
            check(clock.Timers.Count == 1 && clock.Timers[0].Period == SecretFlows.SweepEvery, "secret flow expiry: the first entry starts one sweep, every " + SecretFlows.SweepEvery.TotalSeconds + " seconds");
            check(!abandonedPage.IsErased, "secret flow expiry: an open entry holds its key and sealed values");

            // A tick before the lifetime ends closes nothing.
            clock.Advance(SecretFlows.Lifetime - TimeSpan.FromSeconds(1));
            clock.Tick();
            check(flows.OpenCount == 1 && !abandonedPage.IsErased, "secret flow expiry: an entry that is still in its time is not closed by the sweep");

            // Nobody calls the service again: the timer alone ends it.
            clock.Advance(TimeSpan.FromSeconds(1));
            clock.Tick();
            check(flows.OpenCount == 0 && abandonedPage.IsErased, "secret flow expiry: the sweep closes an expired entry with no request, zeroing its key and clearing what was sealed");
            check(flows.Seal(abandoned.Id, "s1", "{}") is null && flows.SaveSet(abandoned.Id, "s1", "{}") is null, "secret flow expiry: a closed entry answers nothing");
            flows.Sweep();
            clock.Tick();
            check(flows.OpenCount == 0, "secret flow expiry: sweeping again is harmless");

            // The session that made an entry ends: its entries end, another session's stay.
            SecretEntryDto mine = Start("MINE", "s1");
            SecretEntryDto theirs = Start("THEIRS", "s2");
            SecretEntry.Session minePage = flows.SessionOf(mine.Id)!;
            SecretEntry.Session theirsPage = flows.SessionOf(theirs.Id)!;
            flows.CancelSession("s1");
            check(minePage.IsErased && flows.SessionOf(mine.Id) is null && !theirsPage.IsErased && flows.OpenCount == 1, "secret flow expiry: when a session ends, its entries are closed and another session's are not");

            // The shutdown closes everything that is left.
            SecretEntryDto third = Start("THIRD", "s2");
            SecretEntry.Session thirdPage = flows.SessionOf(third.Id)!;
            flows.Dispose();
            check(flows.OpenCount == 0 && theirsPage.IsErased && thirdPage.IsErased && clock.Timers.All(timer => timer.Disposed), "secret flow expiry: shutting down closes every remaining entry and stops the sweep");
            flows.Dispose();
            check(flows.OpenCount == 0, "secret flow expiry: shutting down twice is harmless");

            // A sweep racing with requests on the same entry: nothing throws, nothing is stored, the key is gone at the end.
            SecretFlows racing = new(store, db.Audit, () => new PasskeyMethod(new PasskeyStore(db), settings), clock);
            int faults = 0;
            void Guard(Action call)
            {
                try
                {
                    call();
                }
                catch (Exception)
                {
                    Interlocked.Increment(ref faults);
                }
            }

            for (int round = 0; round < 40; round++)
            {
                SecretEntryDto entry = racing.StartSet(["RACE" + round], "s1", Origin).Entry!;
                SecretEntry.Session page = racing.SessionOf(entry.Id)!;
                clock.Advance(SecretFlows.Lifetime);
                Task[] callers =
                [
                    Task.Run(() => Guard(() => racing.Seal(entry.Id, "s1", "{}"))),
                    Task.Run(() => Guard(() => racing.SaveSet(entry.Id, "s1", "{}"))),
                    Task.Run(() => Guard(() => racing.Sweep())),
                    Task.Run(() => Guard(() => racing.Cancel(entry.Id, "s1"))),
                ];
                Task.WaitAll(callers);
                if (!page.IsErased || racing.OpenCount != 0)
                {
                    Interlocked.Increment(ref faults);
                }
            }

            racing.Dispose();
            check(faults == 0 && store.ListNames().Count == 0, "secret flow expiry: a sweep racing a seal, a save and a cancel leaves no open entry, no kept key and nothing stored (" + faults + " faults)");
        }
        finally
        {
            try
            {
                Directory.Delete(folder, true);
            }
            catch (IOException)
            {
            }
        }
    }

    private static void PageSettingsFlowTests(Action<bool, string> check)
    {
        string folder = Path.Combine(Path.GetTempPath(), "ws-pageset-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            using TestAuthenticator laptop = TestAuthenticator.ES256();
            using TestAuthenticator stranger = TestAuthenticator.ES256();
            StateDatabase db = StateDatabase.InFolder(folder);
            TestState.Add(db, laptop.Record("localhost", "laptop"), withStore: true);
            SecretStore store = new(db);
            ApprovalSettings settings = new(null, 0, TimeSpan.FromSeconds(20));
            FlowClock clock = new();
            SecretFlows flows = new(store, db.Audit, () => new PasskeyMethod(new PasskeyStore(db), settings), clock);
            const string Origin = "http://localhost:1";
            ToolSettings wanted = ToolSettings.Defaults with { Port = 8765, BaseUrl = "https://ws.example.com", TimeoutMinutes = 12 };

            string Proof(SettingsChangeDto change, TestAuthenticator key)
            {
                byte[] bind = Base64Url.DecodeFromChars(change.Payload.GetProperty("bind").GetString()!);

                return key.Assert(Manifest.Challenge(bind, change.Manifest), Origin, "localhost", TestState.NextCount());
            }

            check(flows.PageSettings() is { Settings: { } read, Problem: null } && read == ToolSettings.Defaults, "page settings: the stored settings are read (the defaults at first)");
            check(flows.StartSettings(ToolSettings.Defaults, "s1", Origin) is { Change: null, Problem: "Nothing is changed." }, "page settings: a change to the same values starts nothing");
            check(flows.StartSettings(ToolSettings.Defaults with { TimeoutMinutes = 99 }, "s1", Origin) is { Change: null, Problem: var invalid } && invalid!.Contains("'timeoutMinutes'", StringComparison.Ordinal), "page settings: a value out of its limits starts nothing");

            long version = TestState.Current(db)!.Version;
            (SettingsChangeDto? change, _) = flows.StartSettings(wanted, "s1", Origin);
            check(change is not null && change.Text.Contains("port 0 -> 8765", StringComparison.Ordinal) && change.Text.Contains("baseUrl none -> https://ws.example.com", StringComparison.Ordinal), "page settings: the text names every change");
            check(Manifest.Parse(change!.Manifest, out _) is { } next && next.Settings == wanted && next.Version == version + 1, "page settings: the state to sign has the new values and the next version");
            check(ToolSettings.Load(db, out _) == ToolSettings.Defaults, "page settings: starting a change stores nothing");
            check(flows.SaveSettings(change.Id, "s2", Proof(change, laptop)) is null && flows.Cancel(change.Id, "s2") == false, "page settings: another session cannot save or cancel the change");
            check(flows.SaveSettings(change.Id, "s1", Proof(change, stranger)) is { Status: 403 } && ToolSettings.Load(db, out _) == ToolSettings.Defaults, "page settings: a key that is not enrolled changes nothing");
            check(flows.SaveSettings(change.Id, "s1", Proof(change, laptop)) is null, "page settings: a refused proof ends the change");

            (SettingsChangeDto? again, _) = flows.StartSettings(wanted, "s1", Origin);
            check(flows.SaveSettings(again!.Id, "s1", Proof(again, laptop)) is { Status: 200 }, "page settings: an admin passkey over the next state saves it");
            check(ToolSettings.Load(db, out _) == wanted && TestState.Current(db)!.Version == version + 1 && db.TryCheck(out _), "page settings: the new values are in the signed state (version + 1)");
            check(TestAudit.Rows(db).Any(row => row.Event == SecretFlows.SettingsCommand && row.KeyName == "laptop" && row.Detail.Contains("port 0 -> 8765", StringComparison.Ordinal)), "page settings: one audit event names the changes and the key");
            check(flows.SaveSettings(again.Id, "s1", Proof(again, laptop)) is null, "page settings: a saved change cannot be saved again");

            // A removal and a settings change are different flows: neither id works at the other's save.
            (SettingsChangeDto? mixed, _) = flows.StartSettings(ToolSettings.Defaults with { Port = 7000 }, "s1", Origin);
            check(mixed is not null && flows.SaveRemove(mixed.Id, "s1", Proof(mixed, laptop)) is null && flows.SaveSettings(mixed.Id, "s1", Proof(mixed, laptop)) is { Status: 200 }, "page settings: a settings change cannot be saved as a removal");
            (SecretRemovalDto? removal, _) = flows.StartRemove(["ANY"], "s1", Origin);
            if (removal is not null)
            {
                byte[] bindRemoval = Base64Url.DecodeFromChars(removal.Payload.GetProperty("bind").GetString()!);
                string proofRemoval = laptop.Assert(Manifest.Challenge(bindRemoval, removal.Manifest), Origin, "localhost", TestState.NextCount());
                check(flows.SaveSettings(removal.Id, "s1", proofRemoval) is null, "page settings: a removal cannot be saved as a settings change");
            }

            (SettingsChangeDto? stale, _) = flows.StartSettings(ToolSettings.Defaults, "s1", Origin);
            TestState.Setting(db, "port", "5555");
            check(flows.SaveSettings(stale!.Id, "s1", Proof(stale, laptop)) is { Status: 500 } && ToolSettings.Load(db, out _).Port == 5555, "page settings: a state that changed meanwhile is not overwritten");
        }
        finally
        {
            try
            {
                Directory.Delete(folder, true);
            }
            catch (IOException)
            {
            }
        }
    }

    /// <summary>Entering and removing secrets in the web app's flows: the values are sealed in the browser, one passkey assertion covers them and the new state, and any doubt stores nothing.</summary>
    private static void SecretEntryTests(Action<bool, string> check)
    {
        string folder = Path.Combine(Path.GetTempPath(), "ws-secrets-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            using TestAuthenticator laptop = TestAuthenticator.ES256();
            int stores = 0;

            // A with-secrets.db as the first-time setup leaves it (the laptop as the admin, the store key and vault in the first manifest), and these secrets stored (signed by the laptop).
            (PasskeyStore Passkeys, SecretStore Store) Fresh(IReadOnlyDictionary<string, string>? data = null)
            {
                StateDatabase db = StateDatabase.InFolder(Path.Combine(folder, "state-" + Interlocked.Increment(ref stores)));
                PasskeyStore passkeys = new(db);
                TestState.Add(db, laptop.Record("localhost", "laptop"), withStore: true);
                SecretStore store = new(db);
                if (data is { Count: > 0 } && SecretStoreTests.Put(store, data) is { } problem)
                {
                    throw new InvalidOperationException(problem);
                }

                return (passkeys, store);
            }

            // Values that must never show up anywhere the test can see. Short values are not listed: they could match a port.
            const string ValueA = "Alpha-Secret-Value-1";
            const string ValueB = "Bravo-Secret-Value-2";
            const string OldB = "Old-Bravo-Value-0";
            string longest = "L" + new string('q', 4094) + "Z";
            List<string> seen = [];
            string[] good = ["A_NEW", "B_OLD"];
            string goodValues = Values(("A_NEW", ValueA), ("B_OLD", ValueB));
            Dictionary<string, string> oldData = new() { ["B_OLD"] = OldB };

            // The first set ever: the first-time setup already made the store key, so the first set is one assertion from an admin passkey
            // (no PRF); the store key and vault stay as they were and the hash of the value is added.
            {
                (PasskeyStore passkeys, SecretStore store) = Fresh();
                Manifest before = TestState.Current(store.Database)!;
                EntryRun run = SetRun(passkeys, store, ["A_NEW"], laptop, Values(("A_NEW", ValueA)));
                seen.AddRange(run.Seen);
                Manifest? after = TestState.Current(store.Database);
                check(run.Result is { Code: 0, Detail: "Stored A_NEW." } && after is { Version: 2 } && after.Store == before.Store && after.Vault == before.Vault && Stored(store)["A_NEW"] == ValueA, "secrets: the first set is one assertion; the store key and vault stay (" + run.Result?.Detail + ")");

                (passkeys, store) = Fresh();
                run = SetRun(passkeys, store, ["A_NEW"], laptop, Values(("A_NEW", ValueA)), Twist.Cancel);
                check(run.Cancelled && run.AgainGone && run.Result is { Code: RunCommand.Denied } && TestState.Current(store.Database) is { Version: 1, Secrets.Count: 0 } && store.ListNames().Count == 0, "secrets: a cancelled first set changes nothing (" + run.Result?.Detail + ")");

                // A state without a store key (not made by the first-time setup) cannot take a set.
                StateDatabase bare = StateDatabase.InFolder(Path.Combine(folder, "state-bare"));
                PasskeyStore barePasskeys = new(bare);
                barePasskeys.Add(laptop.Record("localhost", "laptop"));
                run = SetRun(barePasskeys, new SecretStore(bare), ["A_NEW"], laptop, Values(("A_NEW", ValueA)));
                check(run.Result is { Code: RunCommand.Denied } && run.Entry is null && TestState.Current(bare) is { Version: 1, Store: "" }, "secrets: a state without a store key is refused before any entry (" + run.Result?.Detail + ")");
            }

            // The same values sealed twice: the second answer is the first one (same manifest), and signing it stores them.
            {
                (PasskeyStore passkeys, SecretStore store) = Fresh(oldData);
                EntryRun run = SetRun(passkeys, store, good, laptop, goodValues, Twist.SealTwice);
                check(run.SealStatus == 200 && run.SecondSealReply == run.SealReply, "secrets: sealing the same values twice returns the first manifest again");
                check(run.Result is { Code: 0 } && Stored(store)["A_NEW"] == ValueA, "secrets: the first manifest, signed after a second seal, is stored (" + run.Result?.Detail + ")");
            }

            // A first set whose write fails changes nothing: the manifest stays as the first-time setup left it.
            {
                (PasskeyStore passkeys, SecretStore store) = Fresh();
                store.BeforeCommit = () => throw new IOException("the test write failed");
                EntryRun run = SetRun(passkeys, store, ["A_NEW"], laptop, Values(("A_NEW", ValueA)));
                store.BeforeCommit = null;
                check(run.Result is { Code: not 0 } && TestState.Current(store.Database) is { Version: 1, Secrets.Count: 0 } && store.ListNames().Count == 0, "secrets: a failed first set leaves the manifest and the rows as they were (" + run.Result?.Detail + ")");
            }

            // A good set of two: one new, one replaced.
            {
                (PasskeyStore passkeys, SecretStore store) = Fresh(oldData);
                Manifest before = TestState.Current(store.Database)!;
                EntryRun run = SetRun(passkeys, store, good, laptop, goodValues);
                seen.AddRange(run.Seen);
                check(run.Result is { Code: 0, Detail: "Stored A_NEW, B_OLD." }, "secrets: a good set stores both (" + run.Result?.Detail + ")");
                Dictionary<string, string> data = Stored(store);
                check(data.Count == 2 && data["A_NEW"] == ValueA && data["B_OLD"] == ValueB, "secrets: the values read back from the store, verified against the signed hashes");
                Manifest after = TestState.Current(store.Database)!;
                check(after.Version == before.Version + 1 && after.Store == before.Store && after.Vault == before.Vault && after.Secrets.Keys.SequenceEqual(good) && after.Secrets["B_OLD"] != before.Secrets["B_OLD"], "secrets: one new manifest (v+1) with the same store key and vault, both hashes, the replaced one changed");
                check(run.SealStatus == 200 && JsonDocument.Parse(run.SealReply).RootElement.GetProperty("manifest").GetString() == TestState.Current(store.Database)!.Canonical(), "secrets: the manifest /seal answered is the one that is stored");
                check(run.SaveStatus == 200 && run.SaveReply == "{\"ok\":true,\"stored\":[\"A_NEW\",\"B_OLD\"]}", "secrets: the save reply has only the names (" + run.SaveReply + ")");
                check(run.Entry is { Fields: [{ Name: "A_NEW", Replace: false }, { Name: "B_OLD", Replace: true }] } && run.Entry.Text.Contains("A_NEW (new)", StringComparison.Ordinal) && run.Entry.Text.Contains("B_OLD (replace)", StringComparison.Ordinal), "secrets: the entry says new and replace");
                check(run.Entry is not null && Base64Url.DecodeFromChars(run.Entry.PublicKey) is { Length: 65 } point && point[0] == 0x04, "secrets: the entry's key is a 65-byte uncompressed point");
                check(TestAudit.TryRead(store.Database, 100, null, out IReadOnlyList<AuditRow> rows, out _) && rows.Count(row => row.Event == "secrets-set") == 1
                    && rows.Single(row => row.Event == "secrets-set") is { } line && line.Secrets.SequenceEqual(good) && line.Detail == "admin passkey laptop verified" && line.KeyName == "laptop", "secrets: one audit row with the names, the detail and the key");
                check(run.AgainGone, "secrets: after the outcome, /seal and a second /save find no entry");
            }

            // Boundaries: 6 and 4096 characters are accepted.
            {
                (PasskeyStore passkeys, SecretStore store) = Fresh();
                EntryRun run = SetRun(passkeys, store, good, laptop, Values(("A_NEW", "abcdef"), ("B_OLD", longest)));
                seen.AddRange(run.Seen);
                Dictionary<string, string> data = Stored(store);
                check(run.Result is { Code: 0 } && data["A_NEW"] == "abcdef" && data["B_OLD"] == longest, "secrets: values of 6 and 4096 characters are stored (" + run.Result?.Detail + ")");
            }

            // Anything wrong with the crypto or the proof: nothing stored, nothing audited as stored, the entry is gone.
            (Twist Twist, string Label, int Status)[] twists =
            [
                (Twist.TamperCt, "a tampered ct", 400), (Twist.WrongIv, "a wrong iv", 400),
                (Twist.WrongAad, "wrong associated data", 400), (Twist.SignOtherCt, "an assertion signed over another ct", 403),
                (Twist.SignOtherManifest, "an assertion signed over another manifest", 403),
                (Twist.NoSeal, "a save of values never sealed", 400),
                (Twist.PointOffCurve, "an epk that is not a valid point", 400), (Twist.ShortEpk, "an epk of the wrong length", 400),
                (Twist.NoSignature, "a body without a signature", 400), (Twist.NoCt, "a body without ct", 400),
            ];
            foreach ((Twist twist, string label, int status) in twists)
            {
                (PasskeyStore passkeys, SecretStore store) = Fresh(oldData);
                long version = TestState.Current(store.Database)!.Version;
                EntryRun run = SetRun(passkeys, store, good, laptop, goodValues, twist);
                seen.AddRange(run.Seen);
                Dictionary<string, string> data = Stored(store);
                check(run.Result is { Code: RunCommand.Denied } && data.Count == 1 && data["B_OLD"] == OldB && TestState.Current(store.Database)!.Version == version && AuditCount(store, "secrets-set") == 0, "secrets: " + label + " is denied and stores nothing (" + run.SaveStatus + " " + run.SaveReply + ")");
                check(run.SaveStatus == status && run.SaveReply == "{\"ok\":false}" && run.AgainGone, "secrets: " + label + " gets a generic failure, then no entry (" + run.SaveStatus + " " + run.SaveReply + ")");
            }

            // A valid proof with a bad payload: /seal refuses it with the reason (names only); the save is denied, nothing stored.
            (string[] Names, string Plain, string Label, string Why)[] payloads =
            [
                (good, Values(("A_NEW", ValueA), ("B_OLD", ValueB), ("C_EXTRA", "Extra-Value-3")), "an extra name", "not the names asked for"),
                (good, Values(("A_NEW", ValueA)), "a missing name", "not the names asked for"),
                (["A_NEW"], "{\"A_NEW\":\"" + ValueA + "\",\"A_NEW\":\"" + ValueB + "\"}", "a name twice in the JSON", "each name once"),
                (good, Values(("A_NEW", ValueA), ("B_OLD", "12345")), "a value of 5 characters", "B_OLD is shorter than 6"),
                (good, Values(("A_NEW", ValueA), ("B_OLD", longest + "x")), "a value of 4097 characters", "B_OLD is longer than 4096"),
                (["A_NEW"], "[\"" + ValueA + "\"]", "JSON that is not an object", "not a JSON object"),
                (["A_NEW"], "{\"A_NEW\":123456}", "a value that is not text", "not a JSON object"),
                (["A_NEW"], "{\"A_NEW\":\"tab\\there-1\"}", "a value with a control character", "control character"),
                (["A_NEW"], "not json " + ValueA, "text that is not JSON", "not a JSON object"),
            ];
            foreach ((string[] names, string plain, string label, string why) in payloads)
            {
                (PasskeyStore passkeys, SecretStore store) = Fresh(oldData);
                EntryRun run = SetRun(passkeys, store, names, laptop, plain);
                seen.AddRange(run.Seen);
                Dictionary<string, string> data = Stored(store);
                check(run.SealStatus == 400 && run.SealReply.Contains(why, StringComparison.Ordinal), "secrets: " + label + ": /seal refuses it and says why (" + run.SealReply + ")");
                check(run.Result is { Code: RunCommand.Denied } && data.Count == 1 && data["B_OLD"] == OldB && AuditCount(store, "secrets-set") == 0, "secrets: " + label + " is refused before anything is stored (" + run.Result?.Detail + ")");
                check(run.SaveStatus == 400 && run.SaveReply == "{\"ok\":false}" && run.AgainGone, "secrets: " + label + " gets a generic failure, then no entry (" + run.SaveStatus + ")");
            }

            // Names that cannot be stored: refused before any entry starts.
            string[] tooMany = [.. Enumerable.Range(0, 21).Select(index => "N" + index)];
            foreach (string[] names in new[] { new[] { "1bad" }, ["DOTENV_X"], ["A_NEW", "DOTENV_PUBLIC_KEY"], ["A_NEW", "A_NEW"], [], tooMany, ["A-B"] })
            {
                (PasskeyStore passkeys, SecretStore store) = Fresh(oldData);
                long version = TestState.Current(store.Database)!.Version;
                EntryRun set = SetRun(passkeys, store, names, laptop, "{}");
                EntryRun removed = RemoveRun(passkeys, store, names, laptop, true);
                check(set.Result is { Code: RunCommand.Denied } && set.Entry is null && removed.Result is { Code: RunCommand.Denied } && removed.Removal is null && Stored(store).Count == 1 && TestState.Current(store.Database)!.Version == version, "secrets: the names " + string.Join(",", names.Take(3)) + " are refused before anything starts (" + set.Result?.Detail + ")");
            }

            // Cancel in the app.
            {
                (PasskeyStore passkeys, SecretStore store) = Fresh();
                EntryRun run = SetRun(passkeys, store, good, laptop, goodValues, Twist.Cancel);
                check(run.Cancelled && run.AgainGone && Stored(store).Count == 0 && AuditCount(store, "secrets-set") == 0, "secrets: cancelling the entry stores nothing and ends it");
            }

            // The write fails inside its transaction (rows, manifest and audit row are one transaction): nothing is stored.
            {
                (PasskeyStore passkeys, SecretStore store) = Fresh(oldData);
                long version = TestState.Current(store.Database)!.Version;
                store.BeforeCommit = () => throw new IOException("the test write failed");
                EntryRun run = SetRun(passkeys, store, good, laptop, goodValues);
                store.BeforeCommit = null;
                seen.AddRange(run.Seen);
                Dictionary<string, string> data = Stored(store);
                check(run.Result is { Code: not 0 } && data.Count == 1 && data["B_OLD"] == OldB && TestState.Current(store.Database)!.Version == version && AuditCount(store, "secrets-set") == 0, "secrets: a write that fails stores nothing and changes no state (" + run.Result?.Detail + ")");
            }

            // The state changes while the entry is open (another change signed in between): nothing is stored.
            {
                (PasskeyStore passkeys, SecretStore store) = Fresh(oldData);
                EntryRun run = SetRun(passkeys, store, good, laptop, goodValues, Twist.None, () => TestState.Settings(store.Database, ToolSettings.Defaults with { Port = 8766 }));
                check(run.Result is { Code: not 0 } && Stored(store)["B_OLD"] == OldB && !Stored(store).ContainsKey("A_NEW"), "secrets: a state that changed while the entry was open stores nothing (" + run.Result?.Detail + ")");
            }

            // A key that is not an admin cannot store or remove secrets.
            {
                using TestAuthenticator tablet = TestAuthenticator.ES256();
                (PasskeyStore two, SecretStore store) = Fresh(new Dictionary<string, string> { ["A_NEW"] = ValueA });
                check(two.Add(tablet.Record("localhost", "tablet")), "secrets: an admin and a second key are enrolled");
                long version = TestState.Current(store.Database)!.Version;
                EntryRun set = SetRun(two, store, good, tablet, goodValues);
                check(set.Result is { Code: RunCommand.Denied } && set.SaveStatus == 403 && TestState.Current(store.Database)!.Version == version, "secrets: a set approved by a non-admin key is denied and stores nothing (" + set.Result?.Detail + ")");
                check(set.Entry is not null && !set.Entry.Payload.GetRawText().Contains("allowCredentials", StringComparison.Ordinal) && !set.Entry.Payload.GetRawText().Contains(TestAuthenticator.Encode(tablet.CredentialId), StringComparison.Ordinal), "secrets: the entry names no credential (the server decides who may sign)");
                using TestAuthenticator stranger = TestAuthenticator.ES256();
                EntryRun unknownSet = SetRun(two, store, good, stranger, goodValues);
                check(unknownSet.Result is { Code: RunCommand.Denied } && unknownSet.SaveStatus == 403 && TestState.Current(store.Database)!.Version == version, "secrets: a set signed by a credential that is not in the manifest is denied and stores nothing (" + unknownSet.Result?.Detail + ")");
                EntryRun removed = RemoveRun(two, store, ["A_NEW"], tablet, true);
                check(removed.Result is { Code: RunCommand.Denied } && removed.SaveStatus == 403 && Stored(store).ContainsKey("A_NEW") && TestState.Current(store.Database)!.Version == version, "secrets: a removal approved by a non-admin key is denied and removes nothing (" + removed.Result?.Detail + ")");
            }

            // Nothing enrolled, or a with-secrets.db that cannot be read: refused before anything starts.
            {
                StateDatabase emptyDb = StateDatabase.InFolder(Path.Combine(folder, "none"));
                PasskeyStore none = new(emptyDb);
                SecretStore store = new(emptyDb);
                EntryRun set = SetRun(none, store, good, laptop, goodValues);
                EntryRun removed = RemoveRun(none, store, ["A_NEW"], laptop, true);
                check(set.Result is { Code: RunCommand.Denied } && set.Result.Detail.Contains("with-secrets admin", StringComparison.Ordinal) && set.Entry is null && !File.Exists(emptyDb.FilePath), "secrets: a set with nothing enrolled says to run admin (" + set.Result?.Detail + ")");
                check(removed.Result is { Code: RunCommand.Denied } && removed.Result.Detail.Contains("with-secrets admin", StringComparison.Ordinal) && removed.Removal is null, "secrets: a removal with nothing enrolled says to run admin (" + removed.Result?.Detail + ")");

                string badPath = Path.Combine(folder, "bad", "passkeys.db");
                Directory.CreateDirectory(Path.GetDirectoryName(badPath)!);
                File.WriteAllText(badPath, "not json");
                StateDatabase badDb = new(badPath);
                PasskeyStore unreadable = new(badDb);
                SecretStore badStore = new(badDb);
                set = SetRun(unreadable, badStore, good, laptop, goodValues);
                removed = RemoveRun(unreadable, badStore, ["A_NEW"], laptop, true);
                check(set.Result is { Code: not 0 } && set.Entry is null && removed.Result is { Code: not 0 } && removed.Removal is null, "secrets: an unreadable with-secrets.db is a denial before anything starts (" + set.Result?.Detail + ")");
            }

            // A store that fails verification (a row swapped for another valid ciphertext): a set and a removal refuse, exit 4.
            {
                (PasskeyStore passkeys, SecretStore store) = Fresh(new Dictionary<string, string> { ["A_NEW"] = ValueA });
                StateDatabase db = store.Database;
                db.Write((connection, transaction) => WithSecretsDatabase.Execute(connection, transaction, "UPDATE secrets SET ciphertext = $c WHERE name = 'A_NEW'", ("$c", JweCipher.Instance.Encrypt("Attacker-Value-1", TestState.Current(db)!.Store))));
                EntryRun set = SetRun(passkeys, store, ["B_OLD"], laptop, Values(("B_OLD", ValueB)));
                EntryRun removed = RemoveRun(passkeys, store, ["A_NEW"], laptop, true);
                check(set.Result is { Code: RunCommand.StoreError } && set.Entry is null && removed.Result is { Code: RunCommand.StoreError } && removed.Removal is null && set.Result.Detail.Contains("failed verification", StringComparison.Ordinal), "secrets: a store that fails verification refuses a set and a removal (" + set.Result?.Detail + ")");
            }

            // Remove: asks with a new manifest to sign, deletes only on approval, re-signed in the same transaction.
            {
                (PasskeyStore passkeys, SecretStore store) = Fresh(new Dictionary<string, string> { ["A_NEW"] = ValueA, ["B_OLD"] = ValueB, ["C_KEEP"] = "Charlie-Keep-Value" });
                Manifest before = TestState.Current(store.Database)!;
                EntryRun run = RemoveRun(passkeys, store, good, laptop, false);
                seen.AddRange(run.Seen);
                check(run.Cancelled && run.Result is { Code: RunCommand.Denied } && Stored(store).Count == 3 && TestState.Current(store.Database)!.Version == before.Version && AuditCount(store, "secrets-removed") == 0, "secrets: a cancelled removal deletes nothing (" + run.Result?.Detail + ")");
                check(run.Removal is not null && run.Removal.Text.StartsWith("Remove these secrets: A_NEW, B_OLD. They will be deleted.", StringComparison.Ordinal), "secrets: the removal asks with the names in the text");
                check(run.Removal is not null && Manifest.Parse(run.Removal.Manifest, out _) is { } next && next.Version == before.Version + 1 && next.Secrets.Keys.SequenceEqual(["C_KEEP"]), "secrets: the removal signs a new manifest without the removed hashes");

                run = RemoveRun(passkeys, store, good, laptop, true);
                seen.AddRange(run.Seen);
                Manifest after = TestState.Current(store.Database)!;
                check(run.Result is { Code: 0, Detail: "Removed A_NEW, B_OLD." } && Stored(store).Keys.SequenceEqual(["C_KEEP"]), "secrets: an approved removal deletes the names (" + run.Result?.Detail + ")");
                check(after.Version == before.Version + 1 && after.Secrets.Keys.SequenceEqual(["C_KEEP"]) && after.Secrets["C_KEEP"] == before.Secrets["C_KEEP"] && after.Store == before.Store, "secrets: a removal re-signs: v+1 with only the kept hash");
                check(TestAudit.TryRead(store.Database, 100, null, out IReadOnlyList<AuditRow> rows, out _) && rows.SingleOrDefault(row => row.Event == "secrets-removed") is { } line
                    && line.Secrets.SequenceEqual(good) && line.Detail.Contains("admin passkey laptop verified", StringComparison.Ordinal), "secrets: the removal is audited with names only");

                run = RemoveRun(passkeys, store, ["C_KEEP", "NOPE"], laptop, true);
                check(run.Result is { Code: RunCommand.Denied, Detail: "Unknown secret: NOPE" } && run.Removal is null && Stored(store).ContainsKey("C_KEEP"), "secrets: a removal of an unknown name is refused before asking (" + run.Result?.Detail + ")");

                store.BeforeCommit = () => throw new IOException("the test write failed");
                run = RemoveRun(passkeys, store, ["C_KEEP"], laptop, true);
                store.BeforeCommit = null;
                check(run.Result is { Code: not 0 } && Stored(store).ContainsKey("C_KEEP") && TestState.Current(store.Database)!.Version == after.Version && AuditCount(store, "secrets-removed") == 1, "secrets: a removal whose write fails deletes nothing (" + run.Result?.Detail + ")");
            }

            // No value anywhere: not in any text the flow showed or answered, not in any result, not in any with-secrets.db.
            foreach (string file in Directory.GetFiles(folder, WithSecretsDatabase.FileName, SearchOption.AllDirectories))
            {
                seen.Add(StateDatabaseTests.AuditText(file));
                seen.Add(Encoding.UTF8.GetString(File.ReadAllBytes(file)));
            }

            foreach (string value in new[] { ValueA, ValueB, OldB, longest, "Extra-Value-3" })
            {
                check(seen.Count > 20 && !seen.Any(item => item.Contains(value, StringComparison.Ordinal)), "secrets: the value " + value[..5] + "... appears in no text, answer, result or with-secrets.db");
            }
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(folder, true);
        }
    }
}

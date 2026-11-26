using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>
/// Phase 4b: the authority's startup lock, unlock and lock on the admin web app (each a fresh, operation-bound passkey tap), a locked restart, the one authorizer
/// for sensitive administrator operations, that grant use is not administrative, and that the key purposes stay separate. The ceremonies run over real pages with a software
/// passkey, as the admin command tests do.
/// </summary>
internal static class AuthorityLockTests
{
    public static async Task Run(Action<bool, string> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "ws-lock-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);
        try
        {
            await Startup(check, root);
            await Ceremonies(check, root);
            await Review(check, root);
            await RestartStaysLocked(check, root);
            await Origins(check, root);
            Store(check, root);
            Authorizer(check, root);
            await GrantUseIsNotAdministrative(check, root);
            await LockWhileApproving(check, root);
            KeySeparation(check, root);
            await Recovery(check, root);
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

    // ---- helpers ----

    private sealed class CountingAsker(IAdminAsker inner, Action count) : IAdminAsker
    {
        public EnrollmentTarget? InlineTarget() => inner.InlineTarget();

        public EnrollmentTarget? ApprovalTarget() => inner.ApprovalTarget();

        public ApprovalDecision Ask(ApprovalPrompt prompt)
        {
            count();

            return inner.Ask(prompt);
        }

        public ApprovalDecision AskWithKeyRelease(ApprovalPrompt prompt, CancellationToken cancel)
        {
            count();

            return inner.AskWithKeyRelease(prompt, cancel);
        }
    }

    private sealed class Asks
    {
        public int Count;

        /// <summary>Passkey pages on the state, with a time limit; each ask is counted.</summary>
        public Func<Action<string>, IAdminAsker> Factory(StateDatabase db, TimeSpan timeout) => announce =>
        {
            ApprovalSettings settings = new(null, 0, timeout);
            PasskeyMethod method = new(new PasskeyStore(db), settings);
            EnrollmentTarget target = EnrollmentTarget.For(method, new WebApprover(method, settings, announce, TimeSpan.Zero));

            return new CountingAsker(new TargetAdminAsker(target, target), () => Interlocked.Increment(ref Count));
        };
    }

    private static int Attempts(AuthorityStore store, string operation, string outcome) =>
        store.Audit(1000).Count(entry => entry.Event == "admin-operation" && entry.Detail.StartsWith(operation + "; " + outcome, StringComparison.Ordinal));

    /// <summary>The admin key of the state under test (the sign-in tap of the browsers that <see cref="TapOn" /> drives).</summary>
    private static TestAuthenticator? s_admin;

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<HostService, AdminBrowser> s_browsers = [];

    private static AdminBrowser BrowserOf(HostService service, HttpClient http) => s_browsers.GetValue(service, key => new AdminBrowser(key, http));

    /// <summary>Signs the service's browser in with the admin key (one tap); the sessions end on lock.</summary>
    private static async Task<AdminBrowser> Login(HostService service, HttpClient http)
    {
        AdminBrowser browser = BrowserOf(service, http);
        if (!await browser.StillSignedIn())
        {
            await browser.SignInAsync(s_admin!);
        }

        return browser;
    }

    private static (TestAuthenticator Laptop, TestAuthenticator Phone) Keys(StateDatabase db)
    {
        TestAuthenticator laptop = TestAuthenticator.ES256();
        s_admin = laptop;
        TestAuthenticator phone = TestAuthenticator.ES256();
        DateTimeOffset created = new(2026, 11, 1, 10, 0, 0, TimeSpan.Zero);
        TestState.Add(db, laptop.Record("localhost", "laptop") with { Created = created }, withStore: true);
        TestState.Add(db, phone.Record("localhost", "phone") with { Created = created });

        return (laptop, phone);
    }

    // ---- the startup lock ----

    /// <summary>The PRF output a tap sends in <paramref name="mode" /> (see <see cref="InlineTap" />).</summary>
    private static byte[] PrfFor(PrfMode mode, TestAuthenticator who, TestAuthenticator? other, byte[]? otherSalt, byte[] salt)
    {
        if (mode == PrfMode.OtherOwnSalt)
        {
            return other!.Prf(otherSalt!)!;
        }

        byte[] output = (mode == PrfMode.OtherCredential ? other! : who).Prf(salt)!;

        return mode == PrfMode.ShortOutput ? output[..16] : output;
    }

    /// <summary>
    /// One inline tap on the admin app (as its page does): the authorization, the assertion by <paramref name="who" /> and, unless <paramref name="prf" /> is <see cref="PrfMode.Missing" />, the PRF
    /// output sealed to the authorization's key (<see cref="PrfMode.Garbled" />: the sealed box altered; <see cref="PrfMode.OtherCredential" />: a well-sealed output of another passkey; <see cref="PrfMode.OtherOwnSalt" />: another passkey's output for the salt of its own slot in the manifest;
    /// <see cref="PrfMode.WrongBind" />: sealed for another page; <see cref="PrfMode.ShortOutput" />: an output of the wrong size). Then the mutation.
    /// </summary>
    internal static async Task<(int Proof, int Mutation, string State)> InlineTap(AdminBrowser browser, string op, string route, TestAuthenticator who, PrfMode prf, TestAuthenticator? other = null, byte[]? otherSalt = null)
    {
        await browser.LoadAsync();
        (int prepared, string json) = await browser.PostAsync("/api/v1/authorizations/inline", AdminBrowser.AuthorizationBody(op));
        if (prepared != 201)
        {
            return (0, prepared, json);
        }

        using JsonDocument created = JsonDocument.Parse(json);
        JsonElement item = created.RootElement;
        using JsonDocument options = JsonDocument.Parse(item.GetProperty("proof").GetProperty("payload").GetString()!);
        JsonElement payload = options.RootElement;
        byte[] bind = Base64Url.DecodeFromChars(payload.GetProperty("bind").GetString()!);
        string proof = who.Assert(bind, browser.Origin, payload.GetProperty("rpId").GetString()!, TestState.NextCount());
        string body = JsonSerializer.Serialize(new { proof });
        if (prf != PrfMode.Missing)
        {
            byte[] output = PrfFor(prf, who, other, otherSalt, Base64Url.DecodeFromChars(payload.GetProperty("salt").GetString()!));
            try
            {
                (string epk, string iv, string ct) = PrfBrowser.Seal(item.GetProperty("prfKey").GetString()!, prf == PrfMode.WrongBind ? SHA256.HashData(bind) : bind, output);
                if (prf == PrfMode.Garbled)
                {
                    byte[] bytes = Base64Url.DecodeFromChars(ct);
                    bytes[0] ^= 1;
                    ct = Base64Url.EncodeToString(bytes);
                }

                body = JsonSerializer.Serialize(new { proof, prf = new { epk, iv, ct } });
            }
            finally
            {
                CryptographicOperations.ZeroMemory(output);
            }
        }

        string id = item.GetProperty("id").GetString()!;
        (int accepted, _) = await browser.PostAsync("/api/v1/authorizations/" + id + "/proof", body);
        if (accepted != 200)
        {
            return (accepted, 0, "");
        }

        (int result, _) = await browser.PostAsync(route, JsonSerializer.Serialize(new { authorization = id }));
        (_, string state, _) = await browser.GetAsync("/api/v1/authorizations/" + id);
        return (accepted, result, state);
    }

    private static async Task<bool> StatusOpen(AdminApp app)
    {
        using JsonDocument status = JsonDocument.Parse(await app.Http.GetStringAsync(app.Browser().Base + "/api/v1/status"));
        return status.RootElement.GetProperty("reviewOpen").GetBoolean();
    }

    private static bool Closed(UnlockedKeys keys) => !keys.IsOpen && keys.OpenedBy is null && keys.HeldForTests == (null, null);

    /// <summary>Follows the rotation pages a started store key rotation links to: tap 1 (with the PRF output) and tap 2 (the signature), both by <paramref name="who" />.</summary>
    private static (int First, int Second) RotationPages(HttpClient http, string link, TestAuthenticator who)
    {
        Uri uri = new(link);
        (int first, string reply) = TestState.Approve(http, "http://127.0.0.1:" + uri.Port + uri.AbsolutePath, "http://localhost:" + uri.Port, "localhost", who);
        (string Url, string Origin)? next = RecoveryTests.NextLink(reply);

        return (first, next is { } two ? TestState.Approve(http, two.Url, two.Origin, "localhost", who).Status : 0);
    }

    // ---- the unlocked keys ----

    private static async Task Review(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root, unlocked: false);
        UnlockedKeys keys = app.Service.Keys!;
        string laptopId = TestAuthenticator.Encode(app.Laptop.CredentialId);

        check(Closed(keys) && !await StatusOpen(app), "unlock keys: a new service starts locked with no key open");
        // A second admin key: its own PRF output opens its own slot, so it is the output a store that tried every slot would accept for the laptop's assertion.
        using TestAuthenticator desk = TestAuthenticator.ES256();
        TestState.Add(app.State, desk.Record("localhost", "desk") with { Created = new DateTimeOffset(2026, 11, 1, 11, 0, 0, TimeSpan.Zero) }, admin: true);
        string deskId = TestAuthenticator.Encode(desk.CredentialId);
        byte[] deskSalt = Base64Url.DecodeFromChars(TestState.Current(app.State)!.Keys.First(key => key.Id == deskId).Slot!.Salt);
        foreach ((PrfMode mode, string what, TestAuthenticator other) in new[]
        {
            (PrfMode.Missing, "no PRF output", app.Phone), (PrfMode.Garbled, "a garbled PRF output", app.Phone), (PrfMode.OtherCredential, "another passkey's PRF output", app.Phone),
            (PrfMode.WrongBind, "a PRF output sealed for another page", app.Phone), (PrfMode.ShortOutput, "a PRF output of the wrong size", app.Phone),
            (PrfMode.OtherOwnSalt, "another admin's valid PRF output for its own slot", desk),
        })
        {
            (int proof, int mutation, string state) = await InlineTap(app.Browser(), AdminService.OpUnlock, "/api/v1/unlock", app.Laptop, mode, other, deskSalt);
            check(proof == 200 && mutation == 409 && app.Service.Lock.IsLocked && Closed(keys) && !await StatusOpen(app)
                && state.Contains("the passkey did not release the secret store key (use an admin passkey with PRF); the authority stays locked", StringComparison.Ordinal),
                "unlock keys: an admin tap with " + what + " is refused, the authority stays locked and holds nothing (" + proof + " " + mutation + ")");
        }

        check((await InlineTap(app.Browser(), AdminService.OpUnlock, "/api/v1/unlock", app.Phone, PrfMode.Normal)).Proof == 409 && app.Service.Lock.IsLocked && Closed(keys),
            "unlock keys: a passkey that is not an admin cannot unlock, even with its PRF output");
        check(Attempts(app.Store, "unlock-authority", "failed: the passkey did not release the secret store key") == 6, "unlock keys: each refused unlock is audited as failed");

        check((await InlineTap(app.Browser(), AdminService.OpUnlock, "/api/v1/unlock", app.Laptop, PrfMode.Normal)).Mutation == 200
            && !app.Service.Lock.IsLocked && keys.IsOpen && keys.OpenedBy?.Id == laptopId && await StatusOpen(app), "unlock keys: an admin tap with its PRF output unlocks and opens the keys and review");
        (byte[]? store, byte[]? review) = keys.HeldForTests;
        check(store is { Length: > 0 } && review is { Length: > 0 }, "unlock keys: the store key and the review key are both held");

        AdminBrowser session = await app.SignedIn();
        (int reviewRoute, _) = await session.PostAsync("/api/v1/review/unlock", "{\"authorization\":\"AAAAAAAAAAAA\"}");
        check(reviewRoute == 404, "unlock keys: there is no separate review unlock (" + reviewRoute + ")");

        check((await InlineTap(session, AdminService.OpLock, "/api/v1/lock", app.Laptop, PrfMode.Missing)).Proof == 200 && await HostServiceTests.WaitFor(() => app.Service.Lock.IsLocked), "unlock keys: an admin tap locks");
        check(Closed(keys) && store?.All(item => item == 0) == true && review?.All(item => item == 0) == true && !await StatusOpen(app), "unlock keys: the lock zeroes and drops both keys");

        check((await InlineTap(app.Browser(), AdminService.OpUnlock, "/api/v1/unlock", app.Laptop, PrfMode.Normal)).Mutation == 200 && keys.IsOpen, "unlock keys: the authority unlocks again after a lock");
        app.Start(unlocked: false);
        check(app.Service.Lock.IsLocked && Closed(app.Service.Keys!) && !await StatusOpen(app), "unlock keys: a restart leaves the authority locked and no key open");

        await RotationLocks(check, root);
        await RemovingTheUnlockingKeyLocks(check, root);
        LockDuringUnlock(check, root);
    }

    private static async Task RotationLocks(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root, unlocked: false);
        UnlockedKeys keys = app.Service.Keys!;
        check((await InlineTap(app.Browser(), AdminService.OpUnlock, "/api/v1/unlock", app.Laptop, PrfMode.Normal)).Mutation == 200 && keys.IsOpen, "rotation lock: unlocked with the keys open");
        (byte[]? store, byte[]? review) = keys.HeldForTests;
        Manifest before = TestState.Current(app.State)!;
        AdminBrowser session = await app.SignedIn();
        Tapped rotate = await session.OpAsync("store-key-rotate", app.Laptop);
        string? link = RecoveryTests.Member(rotate.MutationBody, "link");
        (int first, int second) = link is null ? (0, 0) : RotationPages(app.Http, link, app.Laptop);
        check(rotate.MutationStatus == 202 && first == 200 && second == 200 && await HostServiceTests.WaitFor(() => app.Service.Lock.IsLocked)
            && TestState.Current(app.State)!.Store != before.Store, "rotation lock: a committed store key rotation locks the authority (" + rotate.MutationStatus + " " + first + " " + second + ")");
        check(Closed(keys) && store?.All(item => item == 0) == true && review?.All(item => item == 0) == true && !await StatusOpen(app), "rotation lock: the old keys are zeroed and nothing is open");
        check(await HostServiceTests.WaitFor(() => Attempts(app.Store, "rotate-store-key", "applied") == 1), "rotation lock: the rotation is audited as applied");
        Manifest after = TestState.Current(app.State)!;
        check((await InlineTap(app.Browser(), AdminService.OpUnlock, "/api/v1/unlock", app.Laptop, PrfMode.Normal)).Mutation == 200 && keys.IsOpen
            && keys.UseStoreKey(after, key => JweCipher.Instance.Derive(key)) == after.Store, "rotation lock: the kept admin passkey unlocks again and opens the new store key");
    }

    private static async Task RemovingTheUnlockingKeyLocks(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root, unlocked: false);
        using TestAuthenticator desk = TestAuthenticator.ES256();
        TestState.Add(app.State, desk.Record("localhost", "desk") with { Created = new DateTimeOffset(2026, 11, 1, 10, 0, 0, TimeSpan.Zero) }, admin: true);
        UnlockedKeys keys = app.Service.Keys!;
        check((await InlineTap(app.Browser(), AdminService.OpUnlock, "/api/v1/unlock", desk, PrfMode.Normal)).Mutation == 200 && keys.OpenedBy?.Id == TestAuthenticator.Encode(desk.CredentialId),
            "removal lock: a second admin passkey unlocks and is named as the one that opened the keys");
        AdminBrowser session = await app.SignedIn();

        async Task<bool> Remove(string name)
        {
            Tapped remove = await session.OpAsync("passkey-unenroll", app.Laptop, true, null, true, ("name", name));
            string? link = RecoveryTests.Member(remove.MutationBody, "link");
            if (remove.MutationStatus != 202 || link is null)
            {
                return false;
            }

            Uri uri = new(link);
            return TestState.Approve(app.Http, "http://127.0.0.1:" + uri.Port + uri.AbsolutePath, "http://localhost:" + uri.Port, "localhost", app.Laptop).Status == 200
                && await HostServiceTests.WaitFor(() => !TestState.Current(app.State)!.Keys.Any(key => key.Name == name));
        }

        check(await Remove("phone") && !app.Service.Lock.IsLocked && keys.IsOpen, "removal lock: removing another passkey leaves the authority unlocked");
        (byte[]? store, _) = keys.HeldForTests;
        check(await Remove("desk") && await HostServiceTests.WaitFor(() => app.Service.Lock.IsLocked) && Closed(keys) && store?.All(item => item == 0) == true,
            "removal lock: removing the admin passkey that unlocked locks the authority and zeroes the keys");
    }

    private static void LockDuringUnlock(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root, unlocked: false);
        UnlockedKeys keys = app.Service.Keys!;
        Manifest manifest = TestState.Current(app.State)!;
        using Unlock unlock = TestVault.Unlock(app.State, app.Laptop)!;
        AuthorityLock authority = app.Service.Lock;
        Task? locking = null;
        bool waited = false;
        UnlockOutcome outcome = authority.UnlockWith(UnlockMethod.Manual, () =>
        {
            locking = Task.Run(() => authority.Lock("test: a lock while the keys open"));
            bool opened = keys.TryOpen(manifest, unlock);
            waited = !locking.Wait(200);

            return opened;
        });
        locking!.Wait(TimeSpan.FromSeconds(10));
        check(outcome == UnlockOutcome.Unlocked && waited && authority.IsLocked && Closed(keys), "lock during unlock: a lock that comes while the keys open waits, and it ends locked with nothing held");

        using ManualResetEventSlim discarding = new();
        using ManualResetEventSlim release = new();
        authority.OnLock(_ =>
        {
            discarding.Set();
            release.Wait(TimeSpan.FromSeconds(10));
        });
        Task slowLock = Task.Run(() => authority.Lock("test: a slow discard"));
        discarding.Wait(TimeSpan.FromSeconds(10));
        UnlockOutcome during = authority.UnlockWith(UnlockMethod.Manual, () => keys.TryOpen(manifest, unlock));
        release.Set();
        slowLock.Wait(TimeSpan.FromSeconds(10));
        check(during == UnlockOutcome.Locking && authority.IsLocked && Closed(keys), "lock during unlock: while a lock is still discarding, an unlock opens nothing");
    }

    private static async Task Startup(Action<bool, string> check, string root)
    {
        using HostServiceTests.Rig rig = new(root, startLocked: true);
        HostService service = rig.Service;
        string status = await rig.Http.GetStringAsync(rig.Url("/v1/status"));
        check(service.Lock.IsLocked && status == "{\"protocolVersion\":1,\"running\":true,\"locked\":true,\"remote\":false,\"adminPort\":" + service.Port + "}", "lock: a service starts LOCKED and /v1/status says running and locked, nothing else (" + status + ")");

        HostServiceTests.Raw refused = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, rig.Script("never", "echo never", "echo never")));
        check(refused.Status == HttpStatusCode.Locked && refused.Body.Contains("/admin", StringComparison.Ordinal) && refused.Body.Contains("locked", StringComparison.Ordinal) && rig.Store.Reads == 0 && rig.Approvers.IsEmpty, "lock: a run while locked is refused (423) with one line naming the admin page; nothing is asked or decrypted (" + refused.Body + ")");
        HostServiceTests.Raw approve = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, rig.Script("never2", "echo never", "echo never")), path: "/v1/approve");
        check(approve.Status == HttpStatusCode.Locked && rig.Approvers.IsEmpty && rig.Machine.Deployment.Store.Grants().Count == 0, "lock: approve while locked is refused too and makes no grant");

        StringWriter errText = new();
        int exit = await LaunchClient.RunAsync(CliArgs.ParseRun(["--secrets", "TOKEN", "--reason", "locked", "--", "anything"], out _)!, rig.Work, service.Endpoint, null, new StringWriter(), errText, rig.Machine.Trust);
        string[] lines = errText.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        check(exit == LaunchClient.AuthorityLocked && LaunchClient.AuthorityLocked == 8 && lines.Length == 1 && lines[0].StartsWith("with-secrets: the authority is locked", StringComparison.Ordinal) && lines[0].Contains(service.Admin.PageUrl, StringComparison.Ordinal),
            "lock: the client prints one clear line with the admin page link and exits 8 (" + exit + ": " + errText + ")");

        AuthorityKeyRing keys = rig.Machine.Deployment.Keys;
        check(Throws<AuthorityLockedException>(() => keys.Current()) && Throws<AuthorityLockedException>(() => keys.Rotate("x")) && Throws<AuthorityLockedException>(() => keys.Recover("x")), "lock: while locked the authority signing key is not used, rotated or recovered");
        LocalAuthority authority = rig.Machine.Deployment.Authority;
        bool reconcileRefused = false;
        try
        {
            await authority.ReconcileAsync(ReconcileEnvelope.Create("rc-x", "test-host", DateTimeOffset.UtcNow, rig.Machine.MachineKey));
        }
        catch (AuthorityLockedException)
        {
            reconcileRefused = true;
        }

        check(reconcileRefused && !service.Ready && service.Authorization.SyncedGrants.Count == 0 && !service.Authorization.Vouched, "lock: a locked authority answers no check-in and nothing vouches for the host, it holds no grant");

        // The test seam unlocks (never a production path): the same service logic works afterwards.
        service.Lock.Unlock(UnlockMethod.Seam);
        check(!keys.Current().PublicKey.SequenceEqual([]) && !service.Lock.IsLocked, "lock: once unlocked the key is used again");
    }

    private static void ExecuteSql(string file, string sql)
    {
        using SqliteConnection connection = new($"Data Source={file};Pooling=False");
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static object? Scalar(string file, string sql)
    {
        using SqliteConnection connection = new($"Data Source={file};Pooling=False");
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;

        return command.ExecuteScalar();
    }

    private static bool Throws<T>(Action action) where T : Exception
    {
        try
        {
            action();
        }
        catch (T)
        {
            return true;
        }

        return false;
    }

    // ---- unlock, lock and discard, each a fresh tap ----

    private static async Task Ceremonies(Action<bool, string> check, string root)
    {
        Asks asks = new();
        using HostServiceTests.Rig rig = new(root, startLocked: true);
        // Rebuild the service with the asker (the rig's StateDatabase is the one the passkeys live in).
        rig.Service.Dispose();
        (TestAuthenticator laptop, TestAuthenticator phone) = Keys(rig.State);
        using HostService service = HostService.Start(new HostServiceOptions
        {
            CommandLineEndpoint = HostServiceTests.Rig.TestEndpoint(),
            State = rig.State,
            Store = rig.Store,
            Deployment = rig.Machine.Restart(),
            Port = 0,
            AdminAskerFactory = asks.Factory(rig.State, TimeSpan.FromSeconds(3)),
        });
        using HttpClient http = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(60) };
        AuthorityStore store = rig.Machine.Deployment.Store;

        // Not an enrolled admin key: refused, still locked.
        Tapped outsider = await TapOn(service, http, AdminService.OpUnlock, phone);
        check(outsider.ApproveStatus == 403 && service.Lock.IsLocked && await HostServiceTests.WaitFor(() => Attempts(store, "unlock-authority", "refused") >= 1), "unlock: a key that is not an admin key cannot unlock; the attempt is audited as refused");

        // No user verification: the proof is not accepted.
        Tapped noUv = await TapOn(service, http, AdminService.OpUnlock, laptop, userVerified: false);
        check(noUv.ApproveStatus == 403 && service.Lock.IsLocked, "unlock: an assertion without user verification is refused; still locked");

        // A signature over another page's challenge (other operation or other parameters) is not accepted.
        Tapped wrongParams = await TapOn(service, http, AdminService.OpUnlock, laptop, change: challenge => SHA256.HashData(challenge));
        check(wrongParams.ApproveStatus is 403 or 400 && service.Lock.IsLocked, "unlock: a signature over a different challenge (other operation or parameters) is refused; still locked (" + wrongParams.ApproveStatus + ")");

        // A page that is never tapped times out: fail closed. (Short limit on a second asker.)
        Asks quick = new();
        using (HostService timed = HostService.Start(new HostServiceOptions { CommandLineEndpoint = HostServiceTests.Rig.TestEndpoint(), State = rig.State, Store = rig.Store, Deployment = rig.Machine.Restart(), Port = 0, AdminAskerFactory = quick.Factory(rig.State, TimeSpan.FromSeconds(1)) }))
        {
            Tapped silent = await TapOn(timed, http, AdminService.OpUnlock, null);
            await Task.Delay(TimeSpan.FromSeconds(3));
            check(silent.Link is not null && timed.Lock.IsLocked, "unlock: a passkey page nobody taps ends at its time limit and the authority stays locked");
        }

        service.Dispose();
        using HostService live = HostService.Start(new HostServiceOptions { CommandLineEndpoint = HostServiceTests.Rig.TestEndpoint(), State = rig.State, Store = rig.Store, Deployment = rig.Machine.Restart(), Port = 0, AdminAskerFactory = asks.Factory(rig.State, TimeSpan.FromSeconds(3)) });
        store = rig.Machine.Deployment.Store;
        check(live.Lock.IsLocked, "unlock: a new service is locked again");
        Tapped unlock = await TapOn(live, http, AdminService.OpUnlock, laptop);
        check(unlock.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => !live.Lock.IsLocked) && live.Lock.How == UnlockMethod.Manual, "unlock: the admin key's fresh tap unlocks (manual)");
        check(await HostServiceTests.WaitFor(() => live.Ready), "unlock: after the unlock the host checks in with the authority and serves runs");
        check(Attempts(store, "unlock-authority", "requested") >= 4 && Attempts(store, "unlock-authority", "authorized") == 1 && Attempts(store, "unlock-authority", "applied") == 1 && Attempts(store, "unlock-authority", "refused") >= 3, "unlock: every attempt and its outcome is in the authority's audit history");
        string auditText = string.Join("\n", store.Audit(1000).Where(entry => entry.Event == "admin-operation").Select(entry => entry.Detail + entry.Actor));
        check(!auditText.Contains("authenticatorData", StringComparison.Ordinal) && !auditText.Contains("signature", StringComparison.Ordinal) && !auditText.Contains(unlock.ProofBody[..Math.Min(20, unlock.ProofBody.Length)], StringComparison.Ordinal), "unlock: the audit holds no proof");

        // Unlock creates no grant and widens none.
        check(store.Grants().Count == 0 && live.Authorization.SyncedGrants.Count == 0, "unlock: it creates no grant");

        // What a lock discards: the keys the unlock opened, the vouching state and the synchronized grants.
        (byte[]? heldStore, byte[]? heldReview) = live.Keys!.HeldForTests;
        check(live.Authorization.Vouched && live.Keys.IsOpen && heldStore is { Length: > 0 } && heldStore.Any(b => b != 0) && heldReview is { Length: > 0 } && heldReview.Any(b => b != 0), "lock: before locking the host is vouched for and the unlock's store key and review key are open");

        Tapped lockTap = await TapOn(live, http, AdminService.OpLock, laptop);
        check(lockTap.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => live.Lock.IsLocked), "lock: the admin key's fresh tap locks at once");
        check(!live.Keys.IsOpen && heldStore is { Length: > 0 } && heldStore.All(b => b == 0) && heldReview is { Length: > 0 } && heldReview.All(b => b == 0) && !live.Authorization.Vouched && live.Authorization.SyncedGrants.Count == 0 && !live.Ready, "lock: the keys are zeroed and closed, the vouching state and grants are discarded, the host is not ready");
        (int replayStatus, _) = TestState.Post(http, unlock.PageUrl + "/proof", unlock.ProofBody);
        await Task.Delay(300);
        check(live.Lock.IsLocked && replayStatus != 200, "replay: sending the unlock proof again to its page unlocks nothing");

        // Earlier unlock does not authorize a later lock (and a lock needs its own tap): an unlocked authority taps for the lock too.
        Tapped unlockAgain = await TapOn(live, http, AdminService.OpUnlock, laptop);
        await HostServiceTests.WaitFor(() => !live.Lock.IsLocked);
        await Login(live, http);
        int before = asks.Count;
        Tapped lockSilent = await TapOn(live, http, AdminService.OpLock, null);
        await Task.Delay(500);
        check(unlockAgain.ApproveStatus == 200 && asks.Count == before + 1 && !live.Lock.IsLocked && lockSilent.Link is not null, "lock: an unlocked authority still needs its own tap to lock (the earlier unlock authorizes nothing) (" + unlockAgain.ApproveStatus + " " + asks.Count + "/" + before + " " + live.Lock.IsLocked + " " + lockSilent.PostStatus + " " + lockSilent.Error + ")");

        Tapped unavailable = await TapOn(live, http, "no-such-op", laptop);
        check(unavailable.PostStatus == 400, "admin: an unknown operation is refused (" + unavailable.PostStatus + " " + unavailable.Error + ")");

        // Unavailable passkeys: no admin key enrolled means no page and no change.
        using HostServiceTests.Rig empty = new(root, startLocked: true);
        empty.Service.Dispose();
        Asks emptyAsks = new();
        using HostService noKeys = HostService.Start(new HostServiceOptions { CommandLineEndpoint = HostServiceTests.Rig.TestEndpoint(), State = empty.State, Store = empty.Store, Deployment = empty.Machine.Restart(), Port = 0, AdminAskerFactory = emptyAsks.Factory(empty.State, TimeSpan.FromSeconds(5)) });
        Tapped none = await TapOn(noKeys, http, AdminService.OpUnlock, laptop);
        check(none.Link is null && none.Error is not null && noKeys.Lock.IsLocked, "fail closed: with no admin passkey enrolled the unlock gets no page and the authority stays locked (" + none.Error + ")");
    }

    private static async Task<Tapped> TapOn(HostService service, HttpClient http, string op, TestAuthenticator? signer, bool userVerified = true, Func<byte[], byte[]>? change = null)
    {
        // Unlock needs no session; every other operation is asked for from a signed-in browser (that sign-in is its own tap).
        AdminBrowser browser = op == AdminService.OpUnlock ? BrowserOf(service, http) : await Login(service, http);

        return await browser.OpAsync(op, signer, userVerified, change);
    }

    // ---- a restart is locked ----

    private static async Task RestartStaysLocked(Action<bool, string> check, string root)
    {
        Asks asks = new();
        using HostServiceTests.Rig rig = new(root, startLocked: true);
        rig.Service.Dispose();
        (TestAuthenticator laptop, _) = Keys(rig.State);
        HostService Start() => HostService.Start(new HostServiceOptions { CommandLineEndpoint = HostServiceTests.Rig.TestEndpoint(), State = rig.State, Store = rig.Store, Deployment = rig.Machine.Restart(), Port = 0, AdminAskerFactory = asks.Factory(rig.State, TimeSpan.FromSeconds(3)) });
        using HttpClient http = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(60) };

        HostService first = Start();
        Tapped unlock = await TapOn(first, http, AdminService.OpUnlock, laptop);
        check(unlock.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => !first.Lock.IsLocked), "restart: the admin key's tap unlocks before the restart");
        first.Dispose();

        using HostService second = Start();
        check(second.Lock.IsLocked && second.Lock.How is null && !second.Ready && !second.Keys!.IsOpen, "restart: the service starts locked again, holding no key");
        StringWriter errText = new();
        int exit = await LaunchClient.RunAsync(CliArgs.ParseRun(["--secrets", "TOKEN", "--reason", "restart", "--", "anything"], out _)!, rig.Work, second.Endpoint, null, new StringWriter(), errText, rig.Machine.Trust);
        check(exit == LaunchClient.AuthorityLocked && LaunchClient.AuthorityLocked == 8 && rig.Store.Reads == 0, "restart: a run is refused with exit 8 until an administrator taps (" + exit + ": " + errText + ")");

        AdminBrowser browser = BrowserOf(second, http);
        await browser.LoadAsync();
        (int policyStatus, _) = await browser.SendAsync(HttpMethod.Put, "/api/v1/settings/unlock-policy", "{\"authorization\":\"AAAAAAAAAAAA\",\"policy\":\"unattended\"}");
        check(policyStatus == 404 && second.Lock.IsLocked, "restart: there is no route that could let a start unlock itself (" + policyStatus + ")");
    }

    // ---- the admin app's origin rules ----

    private static async Task Origins(Action<bool, string> check, string root)
    {
        using HostServiceTests.Rig rig = new(root, startLocked: true);
        // The browser surface is on the loopback port.
        using HttpClient http = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
        string baseUrl = "http://127.0.0.1:" + rig.Service.Port;
        HttpStatusCode Send(HttpMethod method, string path, string? origin, string? body = null, string contentType = "application/json")
        {
            using HttpRequestMessage message = new(method, baseUrl + path);
            if (origin is not null)
            {
                message.Headers.Add("Origin", origin);
            }

            if (body is not null)
            {
                message.Content = new StringContent(body, Encoding.UTF8, contentType);
            }

            using HttpResponseMessage response = http.Send(message);

            return response.StatusCode;
        }

        string good = "http://localhost:" + rig.Service.Port;
        string unlock = "{\"authorization\":\"AAAAAAAAAAAA\"}";
        check(Send(HttpMethod.Post, "/api/v1/unlock", null, unlock) == HttpStatusCode.Forbidden, "api: a change from a program (no Origin) is refused");
        check(Send(HttpMethod.Post, "/api/v1/unlock", "http://evil.example", unlock) == HttpStatusCode.Forbidden, "api: a change from another site is refused");
        check(Send(HttpMethod.Get, "/api/v1/status", "http://evil.example") == HttpStatusCode.Forbidden, "api: a read from another site is refused (no CORS)");
        check(Send(HttpMethod.Post, "/api/v1/unlock", good, unlock) == HttpStatusCode.Forbidden, "api: a well-formed change without the page's anti-forgery value is refused");
        AdminBrowser page = new(rig.Service, http);
        await page.LoadAsync();
        check((await page.PostAsync("/api/v1/unlock", "op=unlock", contentType: "text/plain")).Status == 415, "api: a body that is not JSON is refused");
        check((await page.PostAsync("/api/v1/unlock", "[1]")).Status == 400 && (await page.PostAsync("/api/v1/unlock", "{\"authorization\":\"AAAAAAAAAAAA\",\"x\":1}")).Status == 400, "api: a body that is not an object, or has a member the route does not take, is refused");
        check((await page.PostAsync("/api/v1/unlock", unlock)).Status == 403, "api: a change with an authorization that was never made is refused (403)");
        check(Send(HttpMethod.Get, "/api/v1/unlock", null) == HttpStatusCode.MethodNotAllowed, "api: a change is not a GET");
        check(Send(HttpMethod.Get, "/api/v1/unknown", null) == HttpStatusCode.NotFound, "api: an unknown route is 404");
        check(Send(HttpMethod.Post, "/v1/launch", "http://localhost:1", "{}") == HttpStatusCode.NotFound, "api: the run API is not on this port at all (404, whatever the Origin); on its own endpoint it still refuses any request with an Origin");

        string status = await http.GetStringAsync(baseUrl + "/api/v1/status");
        using HttpResponseMessage head = await http.GetAsync(baseUrl + "/api/v1/status");
        check(status.Contains("\"locked\":true", StringComparison.Ordinal) && head.Headers.Contains("X-Frame-Options") && head.Headers.Contains("Content-Security-Policy"), "api: the public status shows running/locked, and the answer cannot be framed or run as script");
        using HttpResponseMessage auditResponse = await http.GetAsync(baseUrl + "/api/v1/audit/changes");
        string audit = await auditResponse.Content.ReadAsStringAsync();
        check(auditResponse.StatusCode == HttpStatusCode.Unauthorized && !audit.Contains("admin-operation", StringComparison.Ordinal), "api: the audit history is served to a signed-in session only (401 without one, M2)");
    }

    // ---- store-level guards ----

    private static void Store(Action<bool, string> check, string root)
    {
        using TestMachine machine = new(Path.Combine(root, "store"), trusted: false);
        AuthorityStore store = machine.Deployment.Store;
        VerifiedAdmin For(string op, string parameters) => VerifiedAdmin.ForTests(op, parameters);

        (string retentionOp, IReadOnlyList<(string Name, string Value)> retentionParams) = AuthorityStore.RetentionOperation(7);
        check(Throws<UnauthorizedAccessException>(() => store.SetAuditRetentionDays(7, For(retentionOp, "days=8"))) && store.AuditRetentionDays() == AuthorityStore.DefaultAuditRetentionDays, "setting guard: the audit retention (a security setting) needs a tap for exactly that many days");
        check(Throws<UnauthorizedAccessException>(() => store.SetAuditRetentionDays(7, For("unlock-authority", AdminAuthorizer.Canonical(retentionParams)))), "setting guard: a tap for another operation cannot change it");
        VerifiedAdmin ok = For(retentionOp, AdminAuthorizer.Canonical(retentionParams));
        store.SetAuditRetentionDays(7, ok);
        check(store.AuditRetentionDays() == 7, "setting guard: the matching tap sets the retention");
        check(Throws<UnauthorizedAccessException>(() => store.SetAuditRetentionDays(7, ok)), "setting guard: a tap is single use");
    }

    // ---- the authorizer in isolation ----

    private sealed class StubVerifier(bool ok = true, bool admin = true) : IApprovalVerifier
    {
        public ApprovalCheck Verify(ApprovalEvidence evidence, int minutes) => new(ok, "stub-key", admin, ok ? "" : "bad signature");
        public ApprovalCheck Signer(string proof) => new(ok, "stub-key", admin, "");
    }

    private sealed class StubAsker(Func<ApprovalPrompt, ApprovalDecision> answer) : IAdminAsker
    {
        public ApprovalDecision Ask(ApprovalPrompt prompt) => answer(prompt);
    }

    private static ApprovalDecision Signed(ApprovalPrompt prompt, string nonce, DateTimeOffset? issued = null, Func<string, string>? edit = null)
    {
        string text = prompt.Text + "\n" + ApprovalSummary.IssuedLine(issued ?? DateTimeOffset.UtcNow);
        text = edit is null ? text : edit(text);

        return ApprovalDecision.Allow("approved", 0, new ApprovalEvidence(nonce, text, "{}"));
    }

    private static void Authorizer(Action<bool, string> check, string root)
    {
        using TestMachine machine = new(Path.Combine(root, "authz"), trusted: false);
        AuthorityStore store = machine.Deployment.Store;
        (string, string)[] parameters = [("authority-key", "AAAA")];
        const string Op = "unlock-authority";
        AdminAuthorizer Make(bool ok = true, bool admin = true) => new(store, new StubVerifier(ok, admin));
        AdminAuthorization Try(AdminAuthorizer authorizer, IAdminAsker asker) => authorizer.Authorize(asker, "h", "do it", Op, parameters);

        AdminAuthorizer fine = Make();
        check(Try(fine, new StubAsker(prompt => Signed(prompt, "n1"))).Ok, "authorizer: a fresh admin-signed page for exactly this operation and these parameters authorizes");
        check(!Try(fine, new StubAsker(prompt => Signed(prompt, "n1"))).Ok, "authorizer: the same proof a second time is refused (single use)");
        check(!Try(fine, new StubAsker(prompt => Signed(prompt, "n2", edit: text => text.Replace("Operation: unlock-authority", "Operation: lock-authority", StringComparison.Ordinal)))).Ok, "authorizer: a page signed for another operation is refused");
        check(!Try(fine, new StubAsker(prompt => Signed(prompt, "n3", edit: text => text.Replace("AAAA", "BBBB", StringComparison.Ordinal)))).Ok, "authorizer: a page signed for other parameters is refused");
        check(!Try(fine, new StubAsker(prompt => Signed(prompt, "n4", edit: text => text + "\nParameter extra: 1"))).Ok, "authorizer: a page with an extra parameter is refused");
        check(!Try(fine, new StubAsker(prompt => Signed(prompt, "n5", DateTimeOffset.UtcNow.AddHours(-2)))).Ok, "authorizer: a page issued long ago is refused (not fresh)");
        check(!Try(fine, new StubAsker(prompt => Signed(prompt, "n6", DateTimeOffset.UtcNow.AddHours(2)))).Ok, "authorizer: a page issued in the future is refused");
        check(!Try(Make(admin: false), new StubAsker(prompt => Signed(prompt, "n7"))).Ok, "authorizer: a signature of a key that is not an admin key is refused");
        check(!Try(Make(ok: false), new StubAsker(prompt => Signed(prompt, "n8"))).Ok, "authorizer: a signature that does not verify is refused");
        check(!Try(fine, new StubAsker(_ => ApprovalDecision.Deny("denied on the page"))).Ok, "authorizer: a denied page is a refusal");
        check(!Try(fine, new StubAsker(_ => ApprovalDecision.Allow("approved"))).Ok, "authorizer: an approval that carries no signed evidence is a refusal");
        check(!Try(fine, new StubAsker(_ => throw new InvalidOperationException("no browser"))).Ok, "authorizer: an asker that fails (passkey unavailable) is a refusal");
        check(!Try(fine, new StubAsker(_ => ApprovalDecision.Allow("approved", 0, null, new Unlock("x", [1])))).Ok, "authorizer: unlock material in place of evidence authorizes nothing");

        // L4: the page's own ticket must be the one in the signed text, and a spent proof stays spent across a restart.
        check(!Try(Make(), new StubAsker(prompt => Signed(prompt, "n1"))).Ok, "authorizer: a nonce spent before a restart (a new authorizer over the same with-secrets.db) is still spent");
        check(!Try(fine, new StubAsker(prompt => Signed(prompt, "n9", edit: text => System.Text.RegularExpressions.Regex.Replace(text, "Ticket: [0-9A-Fa-f]+", "Ticket: 0000")))).Ok, "authorizer: a signed text that carries another page's ticket is refused");
        check(!Try(fine, new StubAsker(prompt => Signed(prompt, "n10", edit: text => System.Text.RegularExpressions.Regex.Replace(text, "\nTicket: [0-9A-Fa-f]+", "")))).Ok, "authorizer: a signed text with no ticket line is refused");
        string? earlier = null;
        Try(fine, new StubAsker(prompt =>
        {
            earlier = prompt.Text;

            return ApprovalDecision.Deny("capture the first page's text");
        }));
        check(!Try(fine, new StubAsker(prompt => ApprovalDecision.Allow("approved", 0, new ApprovalEvidence("n11", earlier + "\n" + ApprovalSummary.IssuedLine(DateTimeOffset.UtcNow), "{}")))).Ok, "authorizer: a proof made on an earlier page (its text, its ticket) does not authorize a later one");
        check(Convert.ToInt32(Scalar(store.FilePath, "SELECT COUNT(*) FROM admin_spent_nonces")) >= 1, "authorizer: spent nonces are kept in with-secrets.db");

        check(Attempts(store, Op, "requested") >= 13 && Attempts(store, Op, "authorized") == 1 && Attempts(store, Op, "refused") >= 11, "authorizer: every attempt and refusal is audited");
        check(store.Audit(1000).Where(entry => entry.Event == "admin-operation").All(entry => !entry.Detail.Contains("{}", StringComparison.Ordinal) && !entry.Detail.Contains("n1", StringComparison.Ordinal)), "authorizer: the audit carries no proof or nonce");
    }

    // ---- grant use is not administrative ----

    private static async Task GrantUseIsNotAdministrative(Action<bool, string> check, string root)
    {
        using TestAuthenticator svcKey = TestAuthenticator.ES256();
        GrantAuthorityTests.Chooser tapper = new(60, signer: svcKey);
        Asks asks = new();
        HostServiceTests.Rig rig = new(root, approver: () => tapper, enrolled: svcKey, adminAskers: null);
        try
        {
            string program = GrantAuthorityTests.Show(rig);
            await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program), path: "/v1/approve");
            tapper.Minutes = 0;
            GrantRecord grant = rig.Machine.Deployment.Store.Grants()[0];
            HostServiceTests.Raw first = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            HostAuthorization host = rig.Service.Authorization;
            int taps = tapper.Requests.Count;
            HostServiceTests.Raw second = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            check(first.Result is { Outcome: LaunchOutcome.Exited } && second.Result is { Outcome: LaunchOutcome.Exited } && tapper.Requests.Count == taps && tapper.Requests.Count == 1 && asks.Count == 0, "grant use: a valid grant needs no new approval, no passkey tap and no administrator ceremony per use");

            // Locking refuses the use and discards what the host held for it: the keys the unlock opened, the vouching and the synchronized grants.
            check(SecretStoreTests.OpenKeys(rig.Service, rig.State), "grant use: the admin's unlock opened the keys");
            (byte[]? openStore, byte[]? openReview) = rig.Service.Keys!.HeldForTests;
            rig.Service.Lock.Lock("test");
            HostServiceTests.Raw locked = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            check(locked.Status == HttpStatusCode.Locked && host.SyncedGrants.Count == 0 && !host.Vouched && !rig.Service.Keys.IsOpen && openStore is { Length: > 0 } && openStore.All(b => b == 0) && openReview is { Length: > 0 } && openReview.All(b => b == 0),
                "grant use: a locked service refuses the use of a grant; it has zeroed and closed the keys and discarded the vouching and the synchronized grants");

            // Unlocking restores nothing and widens nothing: the grant is as it was.
            rig.Service.Lock.Unlock(UnlockMethod.Seam);
            await HostServiceTests.WaitFor(() => rig.Service.Ready || true);
            rig.Service.Authorization.ReconcileAsync().GetAwaiter().GetResult();
            await rig.Service.Authorization.PumpAsync();
            GrantRecord after = rig.Machine.Deployment.Store.Grants()[0];
            check(after.Id == grant.Id && after.Revision == grant.Revision && after.Expires == grant.Expires && after.ScopeKey == grant.ScopeKey && rig.Machine.Deployment.Store.Grants().Count == 1, "grant use: unlocking creates no grant and extends none");
        }
        finally
        {
            rig.Dispose();
        }
    }

    // ---- a lock during an approval (M1, L3) ----

    private sealed class LockingApprover(Action onAsk) : IApprover
    {
        public ApprovalDecision Request(ApprovalRequest request)
        {
            onAsk();

            return ApprovalDecision.Allow("approved");
        }
    }

    private static async Task LockWhileApproving(Action<bool, string> check, string root)
    {
        HostServiceTests.Rig? holder = null;
        using HostServiceTests.Rig rig = new(root, approver: () => new LockingApprover(() => holder!.Service.Lock.Lock("locked while the page was open")));
        holder = rig;
        string ran = rig.Script("ran", "echo ran > \"%~dpn0.marker.txt\"", "echo ran > \"$0.marker.txt\"");
        HostServiceTests.Raw result = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, ran, [], [("TOKEN", "TOKEN")]));
        check(rig.Store.Reads == 0 && Directory.GetFiles(rig.Work, "*.marker.txt").Length == 0 && result.Result is not { Outcome: LaunchOutcome.Exited }, "lock: a lock while the approval page was open stops the run; no secret was decrypted and the program never started (" + result.Status + " " + result.Result + ")");
        check(rig.Service.Lock.IsLocked && rig.Service.Authorization.SyncedGrants.Count == 0, "lock: the lock stays in force and no grant came of that approval");
    }

    // ---- key separation ----

    private static void KeySeparation(Action<bool, string> check, string root)
    {
        check(KeyNames.Machine != KeyNames.Authority && AuthorityDeploymentNames(), "key separation: the machine identity key, the authority signing key (and its generations) have different key-store names");

        using TestMachine machine = new(Path.Combine(root, "sep"), trusted: true);
        byte[] machinePublic = machine.MachineKey.PublicKey;
        byte[] authorityPublic = machine.Deployment.Keys.Current().PublicKey;
        check(!machinePublic.AsSpan().SequenceEqual(authorityPublic) && KeyIdentity.Fingerprint(machinePublic) != KeyIdentity.Fingerprint(authorityPublic), "key separation: the machine key and the authority key are different keys");

        // A message signed by one key under its domain does not verify as the other's: each signing domain has one key.
        byte[] challenge = RandomNumberGenerator.GetBytes(32);
        byte[] machineSignature = machine.MachineKey.Sign(WireText.Bytes(WireText.IdentityDomain, Convert.ToBase64String(challenge)));
        check(!KeyIdentity.Verify(authorityPublic, WireText.Bytes(WireText.IdentityDomain, Convert.ToBase64String(challenge)), machineSignature), "key separation: a machine-key signature is not valid under the authority key");
        byte[] authoritySignature = machine.Deployment.Keys.Current().Sign(WireText.Bytes(WireText.IdentityDomain, Convert.ToBase64String(challenge)));
        check(!KeyIdentity.Verify(machinePublic, WireText.Bytes(WireText.IdentityDomain, Convert.ToBase64String(challenge)), authoritySignature), "key separation: an authority-key signature is not valid under the machine key");
        check(!KeyIdentity.Verify(machinePublic, WireText.Bytes(WireText.IdentityDomain, Convert.ToBase64String(challenge)), authoritySignature) && !machine.Deployment.Keys.CurrentRecord().PublicKey.AsSpan().SequenceEqual(machinePublic), "key separation: the pinned authority key is not the machine key");

        // The secret-data key material (the store key and review key the unlock opened) is neither: it is not a signing key and not derived from either, and no file of the authority holds it.
        using TestAuthenticator admin = TestAuthenticator.ES256();
        using HostServiceTests.Rig rig = new(root, startLocked: false, enrolled: admin);
        using (Unlock release = TestVault.Unlock(rig.State, admin)!)
        {
            rig.Service.Keys!.TryOpen(TestState.Current(rig.State)!, release);
        }

        (byte[]? openStore, byte[]? openReview) = rig.Service.Keys.HeldForTests;
        byte[][] material = [[.. openStore ?? []], [.. openReview ?? []]];
        rig.Service.Lock.Lock("test");
        // Stop the background audit worker before reading the durable files directly.
        rig.Service.Dispose();
        bool leaked = Directory.EnumerateFiles(rig.Machine.Folder).Where(file => !file.EndsWith("-shm", StringComparison.Ordinal)).Any(file =>
        {
            using FileStream stream = new(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using StreamReader reader = new(stream, Encoding.Latin1);
            string content = reader.ReadToEnd();

            return material.Any(key => content.Contains(Encoding.Latin1.GetString(key), StringComparison.OrdinalIgnoreCase) || content.Contains(Convert.ToHexString(key), StringComparison.OrdinalIgnoreCase) || content.Contains(Convert.ToBase64String(key), StringComparison.Ordinal));
        });
        check(material.All(key => key.Length > 0) && !leaked, "key separation: the unlocked store key and review key are in no file of the authority or the host (database, outbox, host.json)");
        check(material.All(key => !key.AsSpan().SequenceEqual(machinePublic) && !key.AsSpan().SequenceEqual(authorityPublic)), "key separation: the secret-data key material is not a signing key");
    }

    private static bool AuthorityDeploymentNames() => LocalDeployment.AuthorityKeyNameOf(1) != LocalDeployment.AuthorityKeyNameOf(2) && LocalDeployment.AuthorityKeyNameOf(1) == KeyNames.Authority && !LocalDeployment.AuthorityKeyNameOf(2).StartsWith(KeyNames.Machine, StringComparison.Ordinal);

    // ---- the recovery exercise that exists ----

    private static async Task Recovery(Action<bool, string> check, string root)
    {
        // Rotation: the pinned host accepts the new key through the transition the old key signed; recovery: no transition, an explicit pin. Both need the authority unlocked.
        AuthorityLock lockState = new();
        using TestMachine machine = new(Path.Combine(root, "recover"), trusted: true);
        machine.Deployment.Keys.LockState = lockState;
        check(Throws<AuthorityLockedException>(() => machine.Deployment.Keys.Rotate("test")), "recovery: key rotation is refused while the authority is locked");
        lockState.Unlock(UnlockMethod.Manual);
        string before = machine.Deployment.Keys.CurrentRecord().Fingerprint;
        KeyTransition transition = machine.Deployment.Keys.Rotate("test admin");
        check(transition.OldFingerprint == before && machine.Deployment.Keys.CurrentRecord().Fingerprint == transition.NewFingerprint, "recovery: after unlocking, rotation introduces the new key by a transition the old key signed");
        AuthorityKeyRecord recovered = AdminActions.RecoverAuthority(machine.Deployment.Keys, machine.Deployment.HostConfig, machine.Fingerprint, "test admin");
        check(recovered.Fingerprint != transition.NewFingerprint && machine.Deployment.HostConfig.Load().Config?.Authority?.Fingerprint == recovered.Fingerprint, "recovery: recovery makes a new key with no transition and pins it for this machine only by that explicit action");

        await Task.CompletedTask;
    }
}

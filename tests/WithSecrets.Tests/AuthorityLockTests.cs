using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>
/// Phase 4b: the authority's startup lock, unlock and lock on the admin web app (each a fresh, operation-bound passkey tap), the unattended-unlock opt-in, the one authorizer
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
            await Unattended(check, root);
            Origins(check, root);
            Store(check, root);
            Authorizer(check, root);
            await GrantUseIsNotAdministrative(check, root);
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
        public ApprovalDecision Ask(ApprovalPrompt prompt)
        {
            count();

            return inner.Ask(prompt);
        }
    }

    private sealed class Asks
    {
        public int Count;

        /// <summary>Passkey pages on the state, with a time limit; each ask is counted.</summary>
        public Func<Action<string>, IAdminAsker> Factory(StateDatabase db, TimeSpan timeout) => announce =>
        {
            ApprovalSettings settings = new("passkey", null, 0, timeout);
            PasskeyMethod method = new(new PasskeyStore(db), settings);
            EnrollmentTarget target = EnrollmentTarget.For(method, new WebApprover(method, settings, announce, TimeSpan.Zero));

            return new CountingAsker(new TargetAdminAsker(target, target), () => Interlocked.Increment(ref Count));
        };
    }

    /// <summary>Reversible protection for tests that can be made to fail in each way the platform can.</summary>
    private sealed class FakeProtection : IUnlockProtection
    {
        public bool Broken { get; set; }

        public bool Wrong { get; set; }

        public string? Gone { get; set; }

        public string Name => "test protection";

        public string? Unavailable => Gone;

        public byte[] Seal(byte[] material) => [0x46, .. material.Select(item => (byte)(item ^ 0x5A))];

        public byte[]? Open(byte[] sealedBlob)
        {
            if (Broken)
            {
                return null;
            }

            byte[] opened = [.. sealedBlob.Skip(1).Select(item => (byte)(item ^ 0x5A))];
            if (Wrong)
            {
                opened[0] ^= 1;
            }

            return opened;
        }
    }

    private sealed record Tapped(int PostStatus, string? Link, string? Error, int ApproveStatus, string PageUrl, string ProofBody);

    private static int Attempts(AuthorityStore store, string operation, string outcome) =>
        store.Audit(1000).Count(entry => entry.Event == "admin-operation" && entry.Detail.StartsWith(operation + "; " + outcome, StringComparison.Ordinal));

    private static (TestAuthenticator Laptop, TestAuthenticator Phone) Keys(StateDatabase db)
    {
        TestAuthenticator laptop = TestAuthenticator.ES256();
        TestAuthenticator phone = TestAuthenticator.ES256();
        DateTimeOffset created = new(2026, 11, 1, 10, 0, 0, TimeSpan.Zero);
        TestState.Add(db, laptop.Record("localhost", "laptop") with { Created = created });
        TestState.Add(db, phone.Record("localhost", "phone") with { Created = created });

        return (laptop, phone);
    }

    // ---- the startup lock ----

    private static async Task Startup(Action<bool, string> check, string root)
    {
        using HostServiceTests.Rig rig = new(root, startLocked: true);
        HostService service = rig.Service;
        string status = await rig.Http.GetStringAsync(rig.Url("/v1/status"));
        check(service.Lock.IsLocked && status == "{\"protocolVersion\":1,\"running\":true,\"locked\":true}", "lock: a service starts LOCKED and /v1/status says running and locked, nothing else (" + status + ")");

        HostServiceTests.Raw refused = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, rig.Script("never", "echo never", "echo never")));
        check(refused.Status == HttpStatusCode.Locked && refused.Body.Contains("/admin", StringComparison.Ordinal) && refused.Body.Contains("locked", StringComparison.Ordinal) && rig.Store.Reads == 0 && rig.Approvers.IsEmpty, "lock: a run while locked is refused (423) with one line naming the admin page; nothing is asked or decrypted (" + refused.Body + ")");
        HostServiceTests.Raw approve = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, rig.Script("never2", "echo never", "echo never")), path: "/v1/approve");
        check(approve.Status == HttpStatusCode.Locked && rig.Approvers.IsEmpty && rig.Machine.Deployment.Store.Grants().Count == 0, "lock: approve while locked is refused too and makes no grant");

        StringWriter errText = new();
        int exit = await LaunchClient.RunAsync(CliArgs.ParseRun(["--secrets", "TOKEN", "--reason", "locked", "--", "anything"], out _)!, rig.Work, service.Port, null, new StringWriter(), errText, rig.Machine.Trust);
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

        check(reconcileRefused && !service.Ready && service.Authorization.SyncedGrants.Count == 0 && !service.Authorization.Lease.IsValid, "lock: a locked authority answers no check-in and the host holds no lease or grant");

        // The test seam unlocks (never a production path): the same service logic works afterwards.
        service.Lock.Unlock(UnlockMethod.Seam);
        check(!keys.Current().PublicKey.SequenceEqual([]) && !service.Lock.IsLocked, "lock: once unlocked the key is used again");
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
        using (HostService timed = HostService.Start(new HostServiceOptions { State = rig.State, Store = rig.Store, Deployment = rig.Machine.Restart(), Port = 0, AdminAskerFactory = quick.Factory(rig.State, TimeSpan.FromSeconds(1)) }))
        {
            Tapped silent = await TapOn(timed, http, AdminService.OpUnlock, null);
            await Task.Delay(TimeSpan.FromSeconds(3));
            check(silent.Link is not null && timed.Lock.IsLocked, "unlock: a passkey page nobody taps ends at its time limit and the authority stays locked");
        }

        service.Dispose();
        using HostService live = HostService.Start(new HostServiceOptions { State = rig.State, Store = rig.Store, Deployment = rig.Machine.Restart(), Port = 0, AdminAskerFactory = asks.Factory(rig.State, TimeSpan.FromSeconds(3)) });
        store = rig.Machine.Deployment.Store;
        check(live.Lock.IsLocked, "unlock: a new service is locked again");
        Tapped unlock = await TapOn(live, http, AdminService.OpUnlock, laptop);
        check(unlock.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => !live.Lock.IsLocked) && live.Lock.How == UnlockMethod.Manual, "unlock: the admin key's fresh tap unlocks (manual)");
        check(await HostServiceTests.WaitFor(() => live.Ready), "unlock: after the unlock the host checks in with the authority and serves runs");
        check(Attempts(store, "unlock-authority", "requested") >= 4 && Attempts(store, "unlock-authority", "authorized") == 1 && Attempts(store, "unlock-authority", "applied") == 1 && Attempts(store, "unlock-authority", "refused") >= 3, "unlock: every attempt and its outcome is in the authority's audit history");
        string auditText = string.Join("\n", store.Audit(1000).Where(entry => entry.Event == "admin-operation").Select(entry => entry.Detail + entry.Actor));
        check(!auditText.Contains("authenticatorData", StringComparison.Ordinal) && !auditText.Contains("signature", StringComparison.Ordinal) && !auditText.Contains(unlock.ProofBody[..Math.Min(20, unlock.ProofBody.Length)], StringComparison.Ordinal), "unlock: the audit holds no proof");

        // Unlock creates no grant and widens none.
        check(store.Grants().Count == 0 && live.Authorization.SyncedGrants.Count == 0 && !live.Authorization.Keys.IsHeld, "unlock: it creates no grant and holds no key");

        // Hold something to discard: a store key for a grant, the lease and a synchronized grant.
        live.Authorization.Keys.Hold(new Unlock("test-credential", [.. Enumerable.Range(1, 32).Select(item => (byte)item)]), new HeldKeyBinding("g1", "s1", 1, null));
        byte[]? held = live.Authorization.Keys.HeldBytes;
        check(live.Authorization.Lease.IsValid && held is not null && held.Any(b => b != 0), "lock: before locking the host holds a lease and a key");

        Tapped lockTap = await TapOn(live, http, AdminService.OpLock, laptop);
        check(lockTap.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => live.Lock.IsLocked), "lock: the admin key's fresh tap locks at once");
        check(!live.Authorization.Keys.IsHeld && held!.All(b => b == 0) && !live.Authorization.Lease.IsValid && live.Authorization.SyncedGrants.Count == 0 && !live.Ready, "lock: the held key is zeroed and dropped, the lease and grants are discarded, the host is not ready");
        (int replayStatus, _) = TestState.Post(http, unlock.PageUrl + "/proof", unlock.ProofBody);
        await Task.Delay(300);
        check(live.Lock.IsLocked && replayStatus != 200, "replay: sending the unlock proof again to its page unlocks nothing");

        // Earlier unlock does not authorize a later lock (and a lock needs its own tap): an unlocked authority taps for the lock too.
        Tapped unlockAgain = await TapOn(live, http, AdminService.OpUnlock, laptop);
        await HostServiceTests.WaitFor(() => !live.Lock.IsLocked);
        int before = asks.Count;
        Tapped lockSilent = await TapOn(live, http, AdminService.OpLock, null);
        await Task.Delay(500);
        check(unlockAgain.ApproveStatus == 200 && asks.Count == before + 1 && !live.Lock.IsLocked && lockSilent.Link is not null, "lock: an unlocked authority still needs its own tap to lock (the earlier unlock authorizes nothing)");

        Tapped unavailable = await TapOn(live, http, "no-such-op", laptop);
        check(unavailable.PostStatus == 400, "admin: an unknown operation is refused");

        // Unavailable passkeys: no admin key enrolled means no page and no change.
        using HostServiceTests.Rig empty = new(root, startLocked: true);
        empty.Service.Dispose();
        Asks emptyAsks = new();
        using HostService noKeys = HostService.Start(new HostServiceOptions { State = empty.State, Store = empty.Store, Deployment = empty.Machine.Restart(), Port = 0, AdminAskerFactory = emptyAsks.Factory(empty.State, TimeSpan.FromSeconds(5)) });
        Tapped none = await TapOn(noKeys, http, AdminService.OpUnlock, laptop);
        check(none.Link is null && none.Error is not null && noKeys.Lock.IsLocked, "fail closed: with no admin passkey enrolled the unlock gets no page and the authority stays locked (" + none.Error + ")");
    }

    private static async Task<Tapped> TapOn(HostService service, HttpClient http, string op, TestAuthenticator? signer, bool userVerified = true, Func<byte[], byte[]>? change = null)
    {
        using HttpRequestMessage post = new(HttpMethod.Post, "http://127.0.0.1:" + service.Port + "/admin/op") { Content = new StringContent("{\"op\":\"" + op + "\"}", Encoding.UTF8, "application/json") };
        post.Headers.Add("Origin", "http://localhost:" + service.Port);
        using HttpResponseMessage response = await http.SendAsync(post);
        using JsonDocument doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        string? link = doc.RootElement.TryGetProperty("link", out JsonElement l) ? l.GetString() : null;
        string? error = doc.RootElement.TryGetProperty("error", out JsonElement e) ? e.GetString() : null;
        if (link is null || signer is null)
        {
            return new Tapped((int)response.StatusCode, link, error, 0, link is null ? "" : "http://127.0.0.1:" + new Uri(link).Port + new Uri(link).AbsolutePath, "");
        }

        Uri uri = new(link);
        string url = "http://127.0.0.1:" + uri.Port + uri.AbsolutePath;
        (int status, _) = TestState.Approve(http, url, "http://localhost:" + uri.Port, "localhost", signer, userVerified: userVerified, changeChallenge: change);

        return new Tapped((int)response.StatusCode, link, null, status, url, TestState.LastProofBody);
    }

    // ---- unattended unlock ----

    private static async Task Unattended(Action<bool, string> check, string root)
    {
        FakeProtection protection = new();
        Asks asks = new();
        using HostServiceTests.Rig rig = new(root, startLocked: true);
        rig.Service.Dispose();
        (TestAuthenticator laptop, TestAuthenticator phone) = Keys(rig.State);
        HostService Start(IUnlockProtection use) => HostService.Start(new HostServiceOptions { State = rig.State, Store = rig.Store, Deployment = rig.Machine.Restart(), Port = 0, UnlockProtection = use, AdminAskerFactory = asks.Factory(rig.State, TimeSpan.FromSeconds(3)) });
        using HttpClient http = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(60) };

        HostService first = Start(protection);
        AuthorityStore store = rig.Machine.Deployment.Store;
        check(store.GetUnlockPolicy() == UnlockPolicy.Manual && first.Lock.IsLocked && first.StartupUnlockNote is null, "policy: the default is manual and a start is locked");

        // The change needs a fresh tap of an admin key for exactly this policy.
        Tapped outsider = await TapOn(first, http, AdminService.OpPolicyUnattended, phone);
        check(outsider.ApproveStatus == 403 && store.GetUnlockPolicy() == UnlockPolicy.Manual && store.UnattendedMaterial() is null, "policy: a non-admin key cannot allow unattended unlock");
        Tapped noUv = await TapOn(first, http, AdminService.OpPolicyUnattended, laptop, userVerified: false);
        check(noUv.ApproveStatus == 403 && store.GetUnlockPolicy() == UnlockPolicy.Manual, "policy: an assertion without user verification does not change it");
        Tapped otherOperation = await TapOn(first, http, AdminService.OpPolicyUnattended, laptop, change: challenge => SHA256.HashData(challenge));
        check(otherOperation.ApproveStatus is 403 or 400 && store.GetUnlockPolicy() == UnlockPolicy.Manual, "policy: a signature for other parameters does not change it");

        // Unlocking (manual) is not authority to change the policy: the policy tap is its own.
        Tapped unlock = await TapOn(first, http, AdminService.OpUnlock, laptop);
        await HostServiceTests.WaitFor(() => !first.Lock.IsLocked);
        int asked = asks.Count;
        Tapped silent = await TapOn(first, http, AdminService.OpPolicyUnattended, null);
        await Task.Delay(300);
        check(unlock.ApproveStatus == 200 && silent.Link is not null && asks.Count == asked + 1 && store.GetUnlockPolicy() == UnlockPolicy.Manual, "policy: an unlocked authority still needs a fresh tap to change the policy");

        Tapped allow = await TapOn(first, http, AdminService.OpPolicyUnattended, laptop);
        check(allow.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => store.GetUnlockPolicy() == UnlockPolicy.Unattended) && store.UnattendedMaterial() is { Sealed.Length: > 0 }, "policy: the admin key's tap allows unattended unlock");
        check(store.Audit(1000).Any(entry => entry.Event == "unlock-policy-changed" && entry.Detail.Contains("manual to unattended", StringComparison.Ordinal) && entry.Actor.Contains("laptop", StringComparison.Ordinal)), "policy: the change is in the audit history with the key that tapped");
        string root1 = await http.GetStringAsync("http://127.0.0.1:" + first.Port + "/admin");
        check(root1.Contains("WEAKER", StringComparison.Ordinal) && root1.Contains("unattended", StringComparison.Ordinal), "policy: the admin page shows the weaker mode visibly");
        check(ServiceStartup.LockLines(true, UnlockPolicy.Unattended, null, first.Admin.PageUrl).Any(line => line.Contains("WEAKER", StringComparison.Ordinal)) && ServiceStartup.LockLines(true, UnlockPolicy.Manual, null, first.Admin.PageUrl).Any(line => line.Contains("manual", StringComparison.Ordinal) && line.Contains("unlock mode", StringComparison.Ordinal)), "policy: the service startup lines report the unlock mode, the weaker one by name");

        // A restart unlocks itself; nothing else changes.
        first.Dispose();
        int grantsBefore = store.Grants().Count;
        using HostService second = Start(protection);
        check(!second.Lock.IsLocked && second.Lock.How == UnlockMethod.Unattended && second.StartupUnlockNote is { } note && note.Contains("unattended", StringComparison.Ordinal) && await HostServiceTests.WaitFor(() => second.Ready), "unattended: a restart under the policy unlocks and checks in (" + second.StartupUnlockNote + ")");
        check(store.Grants().Count == grantsBefore && second.Authorization.SyncedGrants.Count == 0 && !second.Authorization.Keys.IsHeld, "unattended: unlocking creates no grant, widens none and holds no key");
        string status = await http.GetStringAsync("http://127.0.0.1:" + second.Port + "/v1/status");
        check(status == "{\"protocolVersion\":1,\"running\":true,\"locked\":false}", "unattended: status reports unlocked and nothing else");

        // It never replaces a passkey: a sensitive operation still taps, with the service unlocked unattended.
        int beforeLock = asks.Count;
        Tapped lockNeedsTap = await TapOn(second, http, AdminService.OpLock, null);
        await Task.Delay(400);
        check(lockNeedsTap.Link is not null && asks.Count == beforeLock + 1 && !second.Lock.IsLocked, "unattended: an unattended unlock does not authorize a sensitive operation; the tap is still asked for");
        Tapped lockedByTap = await TapOn(second, http, AdminService.OpLock, phone);
        check(lockedByTap.ApproveStatus == 403 && !second.Lock.IsLocked, "unattended: and a non-admin key does not authorize it either");

        // Anything in doubt leaves it locked.
        second.Dispose();
        foreach ((string label, Action<FakeProtection> twist) in new (string, Action<FakeProtection>)[] { ("the platform will not open the material", p => p.Broken = true), ("the material is not the recorded one", p => p.Wrong = true), ("the platform has no mechanism", p => p.Gone = "unattended unlock has no platform-protection adapter on this operating system") })
        {
            FakeProtection twisted = new();
            twist(twisted);
            using HostService stays = Start(twisted);
            check(stays.Lock.IsLocked && stays.StartupUnlockNote is { } why && why.Contains("stays locked", StringComparison.Ordinal), "unattended: " + label + " -> the authority stays locked and says why");
        }

        // A platform with no adapter is refused when the administrator asks for the option.
        {
            FakeProtection none = new() { Gone = "unattended unlock has no platform-protection adapter on this operating system" };
            using HostServiceTests.Rig other = new(root, startLocked: true);
            other.Service.Dispose();
            (TestAuthenticator otherLaptop, _) = Keys(other.State);
            Asks otherAsks = new();
            using HostService refusing = HostService.Start(new HostServiceOptions { State = other.State, Store = other.Store, Deployment = other.Machine.Restart(), Port = 0, UnlockProtection = none, AdminAskerFactory = otherAsks.Factory(other.State, TimeSpan.FromSeconds(5)) });
            Tapped refused = await TapOn(refusing, http, AdminService.OpPolicyUnattended, otherLaptop);
            check(refused.Link is null && refused.Error is not null && refused.Error.Contains("no platform-protection adapter", StringComparison.Ordinal) && otherAsks.Count == 0 && other.Machine.Deployment.Store.GetUnlockPolicy() == UnlockPolicy.Manual, "unattended: a platform without an adapter refuses the option with a clear message and asks nothing");
        }

        // Back to manual: the material is deleted and a restart is locked.
        using HostService manualAgain = Start(protection);
        manualAgain.Lock.Unlock(UnlockMethod.Seam);
        Tapped toManual = await TapOn(manualAgain, http, AdminService.OpPolicyManual, laptop);
        check(toManual.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => store.GetUnlockPolicy() == UnlockPolicy.Manual) && store.UnattendedMaterial() is null, "policy: the admin key's tap makes unlock manual again and the material is deleted");
        manualAgain.Dispose();
        using HostService afterManual = Start(protection);
        check(afterManual.Lock.IsLocked, "policy: after going back to manual a restart is locked");

        // The real platform mechanism (Windows DPAPI) round-trips and refuses another blob.
        if (OperatingSystem.IsWindows())
        {
            IUnlockProtection real = UnlockProtections.ForThisPlatform();
            byte[] material = RandomNumberGenerator.GetBytes(32);
            byte[] sealedBlob = real.Seal(material);
            check(real.Unavailable is null && !sealedBlob.AsSpan().SequenceEqual(material) && real.Open(sealedBlob)!.AsSpan().SequenceEqual(material) && real.Open([1, 2, 3]) is null, "dpapi: the platform mechanism seals and opens the material and refuses a blob it did not make");
        }
        else
        {
            check(UnlockProtections.ForThisPlatform().Unavailable is not null, "no adapter: this platform has no unlock protection and says so");
        }
    }

    // ---- the admin app's origin rules ----

    private static void Origins(Action<bool, string> check, string root)
    {
        using HostServiceTests.Rig rig = new(root, startLocked: true);
        HttpClient http = rig.Http;
        string baseUrl = rig.Url("");
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
        check(Send(HttpMethod.Post, "/admin/op", null, "{\"op\":\"unlock\"}") == HttpStatusCode.Forbidden, "admin app: an operation from a program (no Origin) is refused");
        check(Send(HttpMethod.Post, "/admin/op", "http://evil.example", "{\"op\":\"unlock\"}") == HttpStatusCode.Forbidden, "admin app: an operation from another site is refused");
        check(Send(HttpMethod.Get, "/admin", "http://evil.example") == HttpStatusCode.Forbidden, "admin app: a page request from another site is refused");
        check(Send(HttpMethod.Post, "/admin/op", good, "op=unlock", "text/plain") == HttpStatusCode.UnsupportedMediaType, "admin app: a body that is not JSON is refused");
        check(Send(HttpMethod.Post, "/admin/op", good, "{\"op\":7}") == HttpStatusCode.BadRequest, "admin app: a body with a wrong member is refused");
        check(Send(HttpMethod.Get, "/admin/op", null) == HttpStatusCode.MethodNotAllowed || Send(HttpMethod.Get, "/admin/op", null) == HttpStatusCode.NotFound, "admin app: an operation is not a GET");
        check(Send(HttpMethod.Get, "/admin/unknown", null) == HttpStatusCode.NotFound, "admin app: an unknown route is 404");
        check(Send(HttpMethod.Post, "/v1/launch", "http://localhost:1", "{}") == HttpStatusCode.Forbidden, "admin app: the run API still refuses any request with an Origin");

        string page = http.GetStringAsync(baseUrl + "/admin").GetAwaiter().GetResult();
        using HttpResponseMessage head = http.GetAsync(baseUrl + "/admin").GetAwaiter().GetResult();
        check(page.Contains("LOCKED", StringComparison.Ordinal) && page.Contains("Unlock", StringComparison.Ordinal) && page.Contains("manual", StringComparison.Ordinal) && head.Headers.Contains("X-Frame-Options") && head.Headers.Contains("Content-Security-Policy"), "admin app: the root page shows running/locked and the unlock mode, and is protected against framing and inline script");
        string audit = http.GetStringAsync(baseUrl + "/admin/audit").GetAwaiter().GetResult();
        check(audit.Contains("Read-only", StringComparison.Ordinal) && !audit.Contains("<button", StringComparison.Ordinal), "admin app: the audit view is read-only (no buttons)");
    }

    // ---- store-level guards ----

    private static void Store(Action<bool, string> check, string root)
    {
        using TestMachine machine = new(Path.Combine(root, "store"), trusted: false);
        AuthorityStore store = machine.Deployment.Store;
        string Canon(UnlockPolicy policy) => AdminAuthorizer.Canonical(AuthorityStore.PolicyOperation(policy).Parameters);
        VerifiedAdmin For(string op, string parameters) => VerifiedAdmin.ForTests(op, parameters);

        check(Throws<UnauthorizedAccessException>(() => store.SetUnlockPolicy(UnlockPolicy.Unattended, [1], "AA", For("unlock-authority", Canon(UnlockPolicy.Unattended)))), "setting guard: a tap for another operation cannot change the unlock policy");
        check(Throws<UnauthorizedAccessException>(() => store.SetUnlockPolicy(UnlockPolicy.Unattended, [1], "AA", For("set-unlock-policy", Canon(UnlockPolicy.Manual)))), "setting guard: a tap for other parameters cannot change it");
        check(store.GetUnlockPolicy() == UnlockPolicy.Manual, "setting guard: nothing changed");
        VerifiedAdmin ok = For("set-unlock-policy", Canon(UnlockPolicy.Unattended));
        store.SetUnlockPolicy(UnlockPolicy.Unattended, [1, 2], "AA", ok);
        check(store.GetUnlockPolicy() == UnlockPolicy.Unattended, "setting guard: the matching tap changes it");
        check(Throws<UnauthorizedAccessException>(() => store.SetUnlockPolicy(UnlockPolicy.Unattended, [1], "AA", ok)), "setting guard: a tap is single use");
        check(Throws<ArgumentException>(() => store.SetUnlockPolicy(UnlockPolicy.Unattended, null, null, For("set-unlock-policy", Canon(UnlockPolicy.Unattended)))), "setting guard: unattended needs its material");
        (string retentionOp, IReadOnlyList<(string Name, string Value)> retentionParams) = AuthorityStore.RetentionOperation(7);
        check(Throws<UnauthorizedAccessException>(() => store.SetAuditRetentionDays(7, For(retentionOp, "days=8"))) && store.AuditRetentionDays() == AuthorityStore.DefaultAuditRetentionDays, "setting guard: the audit retention (a security setting) needs a tap for exactly that many days");
        store.SetAuditRetentionDays(7, For(retentionOp, AdminAuthorizer.Canonical(retentionParams)));
        check(store.AuditRetentionDays() == 7, "setting guard: the matching tap sets the retention");

        // A setting that cannot be read is the safe default.
        using (SqliteConnection connection = new($"Data Source={store.FilePath};Pooling=False"))
        {
            connection.Open();
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "UPDATE authority_settings SET value = 'bogus' WHERE name = 'unlock_policy'";
            command.ExecuteNonQuery();
        }

        check(store.GetUnlockPolicy() == UnlockPolicy.Manual && store.UnattendedMaterial() is null, "setting guard: a damaged policy value counts as manual, with no material");
    }

    // ---- the authorizer in isolation ----

    private sealed class StubVerifier(bool ok = true, bool admin = true) : IApprovalVerifier
    {
        public ApprovalCheck Verify(ApprovalEvidence evidence, int minutes) => new(ok, "stub-key", admin, ok ? "" : "bad signature");
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

        check(Attempts(store, Op, "requested") >= 13 && Attempts(store, Op, "authorized") == 1 && Attempts(store, Op, "refused") >= 11, "authorizer: every attempt and refusal is audited");
        check(store.Audit(1000).Where(entry => entry.Event == "admin-operation").All(entry => !entry.Detail.Contains("{}", StringComparison.Ordinal) && !entry.Detail.Contains("n1", StringComparison.Ordinal)), "authorizer: the audit carries no proof or nonce");
    }

    // ---- grant use is not administrative ----

    private static async Task GrantUseIsNotAdministrative(Action<bool, string> check, string root)
    {
        using TestAuthenticator svcKey = TestAuthenticator.ES256();
        GrantAuthorityTests.Chooser tapper = new(60, unlock: true, signer: svcKey);
        Asks asks = new();
        HostServiceTests.Rig rig = new(root, approver: () => tapper, needsUnlock: true, enrolled: svcKey, adminAskers: null);
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
            check(first.Result is { Outcome: LaunchOutcome.Exited } && second.Result is { Outcome: LaunchOutcome.Exited } && tapper.Requests.Count == taps && host.Keys.IsHeld && asks.Count == 0, "grant use: a valid grant needs no new approval, no passkey tap and no administrator ceremony per use");

            // Locking refuses the use and discards what the host held for it.
            byte[] held = host.Keys.HeldBytes!;
            rig.Service.Lock.Lock("test");
            HostServiceTests.Raw locked = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            check(locked.Status == HttpStatusCode.Locked && !host.Keys.IsHeld && held.All(b => b == 0) && host.SyncedGrants.Count == 0, "grant use: a locked service refuses the use of a grant and has discarded its key and synchronized grants");

            // Unlocking restores nothing and widens nothing: the grant is as it was and the key must be tapped for again.
            rig.Service.Lock.Unlock(UnlockMethod.Seam);
            await HostServiceTests.WaitFor(() => rig.Service.Ready || true);
            rig.Service.Authorization.ReconcileAsync().GetAwaiter().GetResult();
            await rig.Service.Authorization.PumpAsync();
            GrantRecord after = rig.Machine.Deployment.Store.Grants()[0];
            check(after.Id == grant.Id && after.Revision == grant.Revision && after.Expires == grant.Expires && after.ScopeKey == grant.ScopeKey && rig.Machine.Deployment.Store.Grants().Count == 1 && !host.Keys.IsHeld, "grant use: unlocking creates no grant, extends none, and holds no key");
        }
        finally
        {
            rig.Dispose();
        }
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

        // The secret-data key material (the held PRF output) is neither: it is not a signing key and not derived from either, and no file of the authority holds it.
        byte[] prf = [.. Enumerable.Range(1, 32).Select(item => (byte)(item * 7))];
        using HostServiceTests.Rig rig = new(root, startLocked: false);
        rig.Service.Authorization.Keys.Hold(new Unlock("test-credential", prf), new HeldKeyBinding("g", "s", 1, null));
        rig.Service.Lock.Lock("test");
        string prfText = Convert.ToHexString(prf);
        bool leaked = Directory.EnumerateFiles(rig.Machine.Folder).Where(file => !file.EndsWith("-shm", StringComparison.Ordinal)).Any(file =>
        {
            using FileStream stream = new(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using StreamReader reader = new(stream, Encoding.Latin1);
            string content = reader.ReadToEnd();

            return content.Contains(prfText, StringComparison.OrdinalIgnoreCase) || content.Contains(Convert.ToBase64String(prf), StringComparison.Ordinal) || content.Contains(Encoding.Latin1.GetString(prf), StringComparison.Ordinal);
        });
        check(!leaked, "key separation: the held secret-data key material is in no file of the authority or the host (database, outbox, host.json)");
        check(!prf.AsSpan().SequenceEqual(machinePublic.AsSpan(0, Math.Min(32, machinePublic.Length))), "key separation: the secret-data key material is not a signing key");
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

        // A lost unattended-unlock blob falls back to manual unlock (the passkey path), never to open.
        FakeProtection protection = new();
        VerifiedAdmin admin = VerifiedAdmin.ForTests("set-unlock-policy", AdminAuthorizer.Canonical(AuthorityStore.PolicyOperation(UnlockPolicy.Unattended).Parameters));
        byte[] material = RandomNumberGenerator.GetBytes(32);
        machine.Deployment.Store.SetUnlockPolicy(UnlockPolicy.Unattended, protection.Seal(material), Convert.ToHexString(SHA256.HashData(material)), admin);
        protection.Broken = true;
        AuthorityLock fresh = new();
        string? note = UnattendedUnlock.TryUnlock(machine.Deployment.Store, fresh, protection);
        check(fresh.IsLocked && note is not null && note.Contains("stays locked", StringComparison.Ordinal), "recovery: lost unattended material leaves the authority locked for a manual passkey unlock");
        await Task.CompletedTask;
    }
}

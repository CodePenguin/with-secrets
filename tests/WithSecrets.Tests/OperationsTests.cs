using System.Net;
using System.Security.Cryptography;
using System.Text;

using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>
/// Phase 6c, the operational procedures exercised rather than described: a backup restored on a second machine (the secret store and with-secrets.db only; no key
/// travels, so the restored authority fails closed until an administrator recovers its key with a fresh tap), the authority signing-key chain across rotations and
/// a recovery, lock, unlock and restart cycles, a host name change approved end to end through the API, and a Docker client launched through the host service.
/// </summary>
internal static class OperationsTests
{
    private const string Value = "Canary-Value-48151623";

    public static async Task Run(Action<bool, string> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "ws-operations-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);
        try
        {
            await SecondMachine(check, root);
            await RotationAndRecovery(check, root);
            await KeyStoreLost(check, root);
            await LockCycles(check, root);
            await HostNameChange(check, root);
            await DockerThroughTheService(check, root);
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

    private static string Tap(Tapped tapped) => tapped.PostStatus + " " + tapped.Error + " " + tapped.ApproveStatus + " " + tapped.MutationStatus + " " + tapped.MutationBody;

    /// <summary>True when every rotated key was introduced by a transition that the key before it signed, and a recovered key by none (the chain stops there, by design).</summary>
    private static (bool Verifies, int Hops, int Recoveries) Chain(AuthorityStore store)
    {
        IReadOnlyList<AuthorityKeyRecord> keys = store.AuthorityKeys();
        bool ok = keys.Count > 0;
        int recoveries = 0;
        int expected = 0;
        for (int index = 1; index < keys.Count; index++)
        {
            IReadOnlyList<KeyTransition> before = store.TransitionsFrom(keys[index - 1].Fingerprint);
            if (keys[index].How == "recovered")
            {
                recoveries++;
                ok &= before.All(item => item.NewFingerprint != keys[index].Fingerprint);

                continue;
            }

            expected++;
            ok &= before.Count > 0 && before[0].Verify(keys[index - 1].PublicKey) && before[0].OldFingerprint == keys[index - 1].Fingerprint && before[0].NewFingerprint == keys[index].Fingerprint && before[0].NewPublicKey.AsSpan().SequenceEqual(keys[index].PublicKey);
        }

        IReadOnlyList<KeyTransition> all = keys.Count == 0 ? [] : store.TransitionsFrom(keys[0].Fingerprint);

        return (ok && all.Count > 0 == expected > 0, all.Count, recoveries);
    }

    private static string Show(AdminApp app) => GrantAuthorityTests.Show(app.Rig);

    private static bool Contains(string path, params string[] needles)
    {
        string content;
        try
        {
            using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using StreamReader reader = new(stream, Encoding.Latin1);
            content = reader.ReadToEnd();
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            // Gone between the listing and the read (SQLite removes -wal/-shm and temporary files as connections close). Windows reports a file that is
            // being deleted as access denied, not as missing.
            return false;
        }

        return needles.Any(needle => needle.Length > 0 && content.Contains(needle, StringComparison.OrdinalIgnoreCase));
    }

    // ---- backup and restore on a second machine ----

    private static async Task SecondMachine(Action<bool, string> check, string root)
    {
        AdminApp? holder = null;
        int minutes = 60;
        using AdminApp primary = new(root, approver: () => new GrantAuthorityTests.Chooser(minutes, signer: holder!.Laptop));
        holder = primary;
        string program = Show(primary);

        // The first machine: a grant made by a tap, the key rotated twice and the machine renamed, each by an administrator's tap.
        await HostServiceTests.Post(primary.Rig, HostServiceTests.Req(primary.Rig, program), path: "/v1/approve");
        minutes = 0;
        GrantRecord grant = primary.Store.Grants().Single();
        check(primary.Store.Sealer!.Problem(grant) is null, "backup fixture: the grant is backed by a passkey assertion that verifies");
        AdminBrowser admin = await primary.SignedIn();
        string firstKey = primary.Store.ActiveKey()!.Fingerprint;
        Tapped one = await admin.OpAsync("authority-key-rotate", primary.Laptop);
        Tapped two = await admin.OpAsync("authority-key-rotate", primary.Laptop);
        Tapped renamed = await admin.OpAsync("machine-rename", primary.Laptop, true, null, true, ("fingerprint", primary.Fingerprint[..20]), ("name", "first machine"));
        check(one.MutationStatus == 200 && two.MutationStatus == 200 && renamed.MutationStatus == 200 && primary.Store.AuthorityKeys().Count == 3, "backup fixture: two rotations and a rename, each by its own tap (" + Tap(one) + " / " + Tap(two) + " / " + Tap(renamed) + ")");
        grant = primary.Store.Grants().Single();
        HostServiceTests.Raw ran = await HostServiceTests.Post(primary.Rig, HostServiceTests.Req(primary.Rig, program));
        check(ran.Result is { Outcome: LaunchOutcome.Exited }, "backup fixture: the first machine still runs a command after the rotations (the host followed the signed transitions)");

        IReadOnlyList<MachineRecord> machinesBefore = primary.Store.Machines();
        IReadOnlyList<AuditEntry> auditBefore = primary.Store.Audit(1000);
        IReadOnlyList<AuthorityKeyRecord> keysBefore = primary.Store.AuthorityKeys();
        IReadOnlyList<HistoryEntry> historyBefore = primary.Store.History(primary.Fingerprint);
        string manifestBefore = TestState.Current(primary.State)!.Canonical();

        // Backup: the service is stopped and the two files are copied (a copy of a live database is not a backup).
        string stateFile = primary.State.FilePath;
        byte[] master = TestVault.Master(primary.State);
        string recoveryCode = Convert.ToHexString(TestVault.RecoveryCode(primary.State));
        primary.Service.Dispose();
        SqliteConnection.ClearAllPools();
        string backup = Path.Combine(root, "backup");
        Directory.CreateDirectory(backup);
        File.Copy(stateFile, Path.Combine(backup, "with-secrets.db"));
        long Wal(string file) => File.Exists(file + "-wal") ? new FileInfo(file + "-wal").Length : 0;
        check(Wal(stateFile) == 0 && stateFile == primary.Store.FilePath, "backup: a stopped service leaves nothing in the write-ahead logs, so one file is the whole backup (" + Wal(stateFile) + " bytes)");

        // What the backup holds: no key (the signing keys are not in any file) and nothing secret.
        string[] artifacts = [Path.Combine(backup, "with-secrets.db")];
        bool plainKeys = artifacts.Any(file => Contains(file, Value, "PRIVATE KEY", Convert.ToHexString(master), Convert.ToBase64String(master), Encoding.Latin1.GetString(master), Convert.ToBase64String(Convert.FromHexString(recoveryCode)), recoveryCode));
        string planted = Path.Combine(root, "planted.db");
        File.Copy(artifacts[0], planted);
        File.AppendAllText(planted, "xx" + recoveryCode + "xx");
        check(Contains(planted, recoveryCode), "backup: the scan finds a recovery code when one is there (control)");
        check(!plainKeys, "backup: no secret value, private key, master key or recovery code is in the backup artifacts");
        check(!File.Exists(Path.Combine(backup, "host.json")), "backup: host.json (the per-machine pin) is not part of it");

        // The second machine: new machine identity key, new key store, no host.json; the artifacts are copied in and the service starts.
        using AdminApp second = new(root, unlocked: false, restoreFrom: primary, approver: () => new FakeApprover(true));
        check(second.Service.Lock.IsLocked && second.Machine.Fingerprint != primary.Fingerprint && !File.Exists(second.Machine.Deployment.HostConfig.FilePath), "restore: the second machine starts locked, with an identity of its own and no host.json");
        check(second.State.TryCheck(out _) && TestState.Current(second.State)!.Canonical() == manifestBefore, "restore: the secret store opens and its signed manifest (admin and approving keys) is the one that was backed up");
        IReadOnlyList<MachineRecord> machinesAfter = second.Store.Machines();
        check(machinesAfter.Count == machinesBefore.Count && machinesAfter.Zip(machinesBefore).All(pair => pair.First with { PublicKey = [] } == pair.Second with { PublicKey = [] } && pair.First.PublicKey.AsSpan().SequenceEqual(pair.Second.PublicKey)) && second.Store.Find(primary.Fingerprint) is { FriendlyName: "first machine", Status: MachineStatus.Trusted }, "restore: the machine records (status, revision, names) are as they were (" + string.Join(" | ", machinesAfter.Select(m => m.FriendlyName + m.Status + m.SecurityRevision)) + " vs " + string.Join(" | ", machinesBefore.Select(m => m.FriendlyName + m.Status + m.SecurityRevision)) + ")");
        check(second.Store.History(primary.Fingerprint).SequenceEqual(historyBefore), "restore: the machine's status history is as it was");
        check(GrantAuthorityTests.SameGrant(second.Store.Grants().Single(), grant) && GrantSeals.Verifies(grant, second.Store.ActiveKey()!.PublicKey), "restore: the grant is there and its seal verifies against the backed-up authority public key");
        check(second.Store.Audit(1000).Take(auditBefore.Count).SequenceEqual(auditBefore), "restore: the authority's audit history is as it was");
        (bool verifies, int transitions, int recoveries) = Chain(second.Store);
        check(verifies && transitions == 2 && recoveries == 0 && second.Store.AuthorityKeys().Zip(keysBefore).All(pair => pair.First.Fingerprint == pair.Second.Fingerprint && pair.First.How == pair.Second.How && pair.First.Status == pair.Second.Status && pair.First.PublicKey.AsSpan().SequenceEqual(pair.Second.PublicKey)), "restore: the key history is as it was and every transition (" + transitions + ") verifies against the key before it (" + verifies + " " + recoveries + " " + second.Store.AuthorityKeys().Count + " vs " + keysBefore.Count + ")");

        // A host pinned to the first key follows the restored chain, one signed hop at a time.
        HostConfigFile oldHost = HostConfigFile.InFolder(Path.Combine(root, "old-host-" + Guid.NewGuid().ToString("N")[..6]));
        Directory.CreateDirectory(Path.GetDirectoryName(oldHost.FilePath)!);
        oldHost.Pin(primary.Fingerprint, new PinnedAuthorityKey(keysBefore[0].Fingerprint, keysBefore[0].PublicKey, DateTimeOffset.UtcNow));
        string?[] hops = [.. second.Store.TransitionsFrom(keysBefore[0].Fingerprint).Select(oldHost.TryApplyTransition)];
        check(hops.Length == 2 && hops.All(item => item is null) && oldHost.Load().Config!.Authority!.Fingerprint == keysBefore[2].Fingerprint, "restore: a host pinned to the first key follows the restored transitions to the active key");

        // No key came with the backup: the authority cannot sign, and everything fails closed.
        check(Throws<AuthorityLockedException>(() => second.Machine.Deployment.Keys.Current()), "restore: locked, the authority uses no key");
        AdminBrowser b = second.Browser();
        await b.LoadAsync();
        (int signIn, string signInBody) = await b.PostAsync("/api/v1/session", "{}");
        check(signIn == 423 && second.Asked == 0, "restore: a locked authority starts no session and asks for no passkey (" + signIn + " " + signInBody + ")");
        Tapped stranger = await b.OpAsync(AdminService.OpUnlock, second.Phone);
        check(stranger.ApproveStatus == 403 && second.Service.Lock.IsLocked, "restore: a key that is not an admin cannot unlock the restored authority");
        Tapped unlock = await b.OpAsync(AdminService.OpUnlock, second.Laptop);
        check(unlock.MutationStatus == 200 && !second.Service.Lock.IsLocked, "restore: an admin key from the backup unlocks it with a fresh tap (" + Tap(unlock) + ")");
        AuthorityDatabaseException? missing = null;
        try
        {
            second.Machine.Deployment.Keys.Current();
        }
        catch (AuthorityDatabaseException error)
        {
            missing = error;
        }

        check(missing is not null && missing.Message.Contains("Recover the authority key", StringComparison.Ordinal), "restore: unlocked, the key store still has no key the database names, so it is an error that says to recover (" + missing?.Message + ")");
        int audits = second.Store.Audit(1000).Count;
        HostServiceTests.Raw refused = await HostServiceTests.Post(second.Rig, HostServiceTests.Req(second.Rig, Show(second)));
        check(refused.Result is not { Outcome: LaunchOutcome.Exited } && second.Secrets.Reads == 0 && !File.Exists(HostServiceTests.Marker(second.Rig)), "restore: without the key nothing is approved, decrypted or started (" + refused.Status + " " + refused.Result + ")");

        // Recovery: one fresh tap makes a new key with no transition and pins it for this machine only. The machine is then enrolled and approved by its own tap.
        AdminBrowser session = await second.SignedIn();
        Tapped recovery = await session.OpAsync("authority-key-recover", second.Laptop);
        AuthorityKeyRecord recovered = second.Store.ActiveKey()!;
        check(recovery.MutationStatus == 200 && recovered.How == "recovered" && recovered.Generation == 4 && second.Store.TransitionsFrom(keysBefore[2].Fingerprint).Count == 0, "restore: recovery by a tap makes a new key with no transition, so no other host can follow it by itself (" + Tap(recovery) + ")");
        check(second.Machine.Deployment.HostConfig.Load().Config is { } pinned && pinned.MachineFingerprint == second.Fingerprint && pinned.Authority!.Fingerprint == recovered.Fingerprint, "restore: the new key is pinned by that action, for this machine only");
        (bool verifiesAfter, int hopsAfter, int recoveriesAfter) = Chain(second.Store);
        check(verifiesAfter && hopsAfter == 2 && recoveriesAfter == 1, "restore: after the recovery the earlier transitions still verify and the recovery is a recorded break in the chain");
        check(oldHost.TryApplyTransition(second.Store.TransitionsFrom(keysBefore[2].Fingerprint).FirstOrDefault() ?? new KeyTransition("", "", [], DateTimeOffset.UtcNow, [])) is not null && oldHost.Load().Config!.Authority!.Fingerprint == keysBefore[2].Fingerprint, "restore: a host pinned before the recovery does not follow it; it must be pinned again by an administrator");
        await second.Machine.Deployment.EnrollAsync();
        check(second.Store.Find(second.Fingerprint) is { Status: MachineStatus.Pending }, "restore: the second machine enrolls as Pending, not Trusted (a copied database does not trust a new identity)");
        HostServiceTests.Raw pending = await HostServiceTests.Post(second.Rig, HostServiceTests.Req(second.Rig, Show(second)));
        check(pending.Result is not { Outcome: LaunchOutcome.Exited } && second.Secrets.Reads == 0, "restore: a Pending machine runs nothing");
        Tapped approve = await session.OpAsync("machine-approve", second.Laptop, true, null, true, ("fingerprint", second.Fingerprint), ("name", "second machine"));
        check(approve.MutationStatus == 200 && second.Store.Find(second.Fingerprint) is { Status: MachineStatus.Trusted, FriendlyName: "second machine" }, "restore: an administrator's tap approves the second machine (" + Tap(approve) + ")");
        HostServiceTests.Raw working = await HostServiceTests.Post(second.Rig, HostServiceTests.Req(second.Rig, Show(second)));
        check(working.Result is { Outcome: LaunchOutcome.Exited } && second.Secrets.Reads == 1 && working.Stdout.Contains("[REDACTED]", StringComparison.Ordinal), "restore: after the recovery and the approval the second machine runs a command (" + working.Status + " " + working.Result + ")");
        IReadOnlyList<AuditEntry> auditAfter = second.Store.Audit(1000);
        check(auditAfter.Count > audits && auditAfter.Take(auditBefore.Count).SequenceEqual(auditBefore) && auditAfter.Any(entry => entry.Event == "authority-key-recovered") && auditAfter.Select(entry => entry.Id).SequenceEqual(auditAfter.Select(entry => entry.Id).Order()), "restore: the audit history continues after the restore (the old rows unchanged, new ones after them, ids rising)");
        check(second.Store.Find(primary.Fingerprint) is { Status: MachineStatus.Trusted }, "restore: the first machine's record is still Trusted at the authority until an administrator disables it (disable it if the first machine is gone)");
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

    // ---- the authority key through rotations and a recovery ----

    private static async Task RotationAndRecovery(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root, approver: () => new FakeApprover(true));
        string program = Show(app);
        AdminBrowser b = await app.SignedIn();
        string first = app.Store.ActiveKey()?.Fingerprint ?? app.Machine.Deployment.Keys.CurrentRecord().Fingerprint;
        string pinned() => app.Machine.Deployment.HostConfig.Load().Config?.Authority?.Fingerprint ?? "";
        check(pinned() == first, "rotation: the host is pinned to the first key");

        int asked = app.Asked;
        Tapped rotate1 = await b.OpAsync("authority-key-rotate", app.Laptop);
        Tapped rotate2 = await b.OpAsync("authority-key-rotate", app.Laptop);
        check(rotate1.MutationStatus == 200 && rotate2.MutationStatus == 200 && app.Asked == asked + 2 && pinned() == first, "rotation: each rotation needs its own tap; the host has not moved yet");
        HostServiceTests.Raw afterRotations = await HostServiceTests.Post(app.Rig, HostServiceTests.Req(app.Rig, program));
        check(afterRotations.Result is { Outcome: LaunchOutcome.Exited } && pinned() == app.Store.ActiveKey()!.Fingerprint && pinned() != first, "rotation: the host follows both signed transitions on its next request and runs the command (no tap for the run)");
        (bool verifies, int hops, _) = Chain(app.Store);
        check(verifies && hops == 2, "rotation: the transition chain verifies end to end");

        // A key the pinned key never signed for does not move the host.
        using SoftwareSigningKey stranger = new();
        KeyTransition forged = KeyTransition.Create(stranger, stranger.PublicKey, DateTimeOffset.UtcNow);
        check(app.Machine.Deployment.HostConfig.TryApplyTransition(forged) is { } why && why.Contains("not signed by the pinned", StringComparison.Ordinal) && pinned() == app.Store.ActiveKey()!.Fingerprint, "rotation: a transition that the pinned key did not sign moves nothing");

        // Recovery: a tap, a new key with no transition, an explicit pin in the same action; the earlier chain still verifies.
        string beforeRecovery = app.Store.ActiveKey()!.Fingerprint;
        Tapped denied = await b.OpAsync("authority-key-recover", app.Phone);
        check(denied.ApproveStatus == 403 && app.Store.ActiveKey()!.Fingerprint == beforeRecovery, "recovery: a key that is not an admin cannot recover the authority key");
        Tapped recover = await b.OpAsync("authority-key-recover", app.Laptop);
        check(recover.MutationStatus == 200 && app.Store.ActiveKey() is { How: "recovered" } && pinned() == app.Store.ActiveKey()!.Fingerprint && app.Store.TransitionsFrom(beforeRecovery).Count == 0, "recovery: a tap makes the new key, with no transition, and pins it for this machine (" + Tap(recover) + ")");
        HostServiceTests.Raw afterRecovery = await HostServiceTests.Post(app.Rig, HostServiceTests.Req(app.Rig, program));
        check(afterRecovery.Result is { Outcome: LaunchOutcome.Exited }, "recovery: the host runs commands again under the recovered key");

        // A host that was not re-pinned does not follow, and refuses an answer signed by the recovered key; nothing is decrypted.
        app.Machine.Deployment.HostConfig.Pin(app.Fingerprint, new PinnedAuthorityKey(beforeRecovery, app.Store.AuthorityKeys().Single(key => key.Fingerprint == beforeRecovery).PublicKey, DateTimeOffset.UtcNow));
        int reads = app.Secrets.Reads;
        HostServiceTests.Raw stale = await HostServiceTests.Post(app.Rig, HostServiceTests.Req(app.Rig, program));
        check(stale.Result is not { Outcome: LaunchOutcome.Exited } && app.Secrets.Reads == reads && pinned() == beforeRecovery, "recovery: a host still pinned to the key before the recovery refuses the new key and decrypts nothing until an administrator pins it again");
        (bool verifiesAfter, _, int recoveries) = Chain(app.Store);
        check(verifiesAfter && recoveries == 1 && app.Store.Audit(1000).Count(entry => entry.Event is "authority-key-rotated" or "authority-key-recovered") == 3, "recovery: the history keeps both rotations and the recovery as audited events");
    }

    // ---- the key store loses the authority key while the machine stays Trusted ----

    private static async Task KeyStoreLost(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root, approver: () => new FakeApprover(true));
        string program = Show(app);
        HostServiceTests.Raw working = await HostServiceTests.Post(app.Rig, HostServiceTests.Req(app.Rig, program));
        check(working.Result is { Outcome: LaunchOutcome.Exited } && app.Secrets.Reads == 1, "key store lost: a Trusted machine runs a command");

        // The key store no longer has the key with-secrets.db names (a wiped profile, a replaced disk).
        app.Machine.LoseAuthorityKeys();
        app.Start(true);
        AuthorityDatabaseException? error = null;
        try
        {
            app.Machine.Deployment.Keys.Current();
        }
        catch (AuthorityDatabaseException failure)
        {
            error = failure;
        }

        HostServiceTests.Raw refused = await HostServiceTests.Post(app.Rig, HostServiceTests.Req(app.Rig, program));
        check(error is not null && refused.Result is not { Outcome: LaunchOutcome.Exited } && app.Secrets.Reads == 1, "key store lost: the authority will not sign with another key, so a Trusted machine is refused, nothing is decrypted (" + refused.Status + " " + refused.Result + ")");
        int reads = app.Secrets.Reads;
        AdminBrowser b = await app.SignedIn();
        Tapped recover = await b.OpAsync("authority-key-recover", app.Laptop);
        check(recover.MutationStatus == 200 && app.Store.ActiveKey() is { How: "recovered" }, "key store lost: Recover by an administrator's tap makes a new key (" + Tap(recover) + ")");
        bool ready = await HostServiceTests.WaitFor(() => app.Service.Ready, 40);
        HostServiceTests.Raw after = await HostServiceTests.Post(app.Rig, HostServiceTests.Req(app.Rig, program));
        check(ready && after.Result is { Outcome: LaunchOutcome.Exited } && app.Secrets.Reads == reads + 1, "key store lost: after the recovery the service checks in with its authority again and the machine runs (" + after.Status + " " + after.Result + " " + after.Stderr.Trim() + " " + app.Machine.Deployment.HostConfig.Load().Config?.Authority?.Fingerprint[..8] + " " + app.Store.ActiveKey()?.Fingerprint[..8] + ")");
    }

    // ---- lock, unlock and restart cycles ----

    private static async Task LockCycles(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root, approver: () => new FakeApprover(true));
        string program = Show(app);
        byte[] material = [.. Enumerable.Range(1, 32).Select(item => (byte)(item * 11))];
        for (int cycle = 1; cycle <= 3; cycle++)
        {
            string label = "cycle " + cycle;
            AdminBrowser b = await app.SignedIn();
            HostAuthorization host = app.Service.Authorization;
            host.Keys.Hold(new Unlock("test-credential", material), new HeldKeyBinding("g" + cycle, "s", 1, null));
            byte[] held = host.Keys.HeldBytes!;
            int audits = app.Store.Audit(1000).Count;
            Tapped locked = await b.OpAsync(AdminService.OpLock, app.Laptop);
            check(locked.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => app.Service.Lock.IsLocked && !host.Keys.IsHeld) && held.All(value => value == 0), label + ": a lock by tap drops the held key and zeroes its bytes");
            HostServiceTests.Raw whileLocked = await HostServiceTests.Post(app.Rig, HostServiceTests.Req(app.Rig, program));
            check(whileLocked.Status == HttpStatusCode.Locked && app.Secrets.Reads == cycle - 1, label + ": while locked a run is refused (423) and nothing is decrypted");

            // A restart is a lock too: memory only, so the service comes back locked with nothing held and no session.
            app.Start(false);
            check(app.Service.Lock.IsLocked && app.Service.Admin.Sessions.Count == 0 && !app.Service.Authorization.Keys.IsHeld, label + ": after a restart the service is locked, holds no key and has no session");
            AdminBrowser again = app.Browser();
            Tapped stranger = await again.OpAsync(AdminService.OpUnlock, app.Phone);
            check(stranger.ApproveStatus == 403 && app.Service.Lock.IsLocked, label + ": a key that is not an admin does not unlock");
            Tapped unlock = await again.OpAsync(AdminService.OpUnlock, app.Laptop);
            check(unlock.MutationStatus == 200 && !app.Service.Lock.IsLocked && !app.Service.Authorization.Keys.IsHeld, label + ": an admin's fresh tap unlocks, and the unlock holds no key");
            HostServiceTests.Raw runs = await HostServiceTests.Post(app.Rig, HostServiceTests.Req(app.Rig, program));
            check(runs.Result is { Outcome: LaunchOutcome.Exited } && app.Secrets.Reads == cycle, label + ": after the unlock a run works");
            check(app.Store.Audit(1000).Count >= audits + 2 && app.Store.Audit(1000).Count(entry => entry.Event == "admin-operation") >= cycle * 2, label + ": the lock and the unlock are in the audit history");
            Array.Clear(material);
            material = [.. Enumerable.Range(1, 32).Select(item => (byte)(item * 11))];
        }

        // Stopping the service zeroes what it holds.
        HostAuthorization last = app.Service.Authorization;
        last.Keys.Hold(new Unlock("test-credential", material), new HeldKeyBinding("g-stop", "s", 1, null));
        byte[] stopping = last.Keys.HeldBytes!;
        app.Service.Dispose();
        check(stopping.All(value => value == 0), "stop: stopping the service zeroes the key it held");
    }

    // ---- a host name change, end to end ----

    private static async Task HostNameChange(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root, approver: () => new FakeApprover(true));
        string program = Show(app);
        HostServiceTests.Raw before = await HostServiceTests.Post(app.Rig, HostServiceTests.Req(app.Rig, program));
        int revision = app.Store.Find(app.Fingerprint)!.SecurityRevision;
        check(before.Result is { Outcome: LaunchOutcome.Exited } && app.Secrets.Reads == 1, "host name: the machine runs under its enrolled host name");

        // The machine is renamed (the operating system's name changes): the authority records the new name as waiting and the run is refused.
        app.Machine.Restart("renamed-host");
        app.Start(true);
        HostServiceTests.Raw refused = await HostServiceTests.Post(app.Rig, HostServiceTests.Req(app.Rig, program));
        MachineRecord waiting = app.Store.Find(app.Fingerprint)!;
        check(refused.Result is not { Outcome: LaunchOutcome.Exited } && app.Secrets.Reads == 1 && waiting is { HostName: "test-host", PendingHostName: "renamed-host", Status: MachineStatus.Trusted } && waiting.SecurityRevision == revision, "host name: a changed host name is not accepted by itself; the run is refused, nothing decrypted, the new name waits (" + refused.Result + ")");
        check(app.Store.History(app.Fingerprint).Any(entry => entry.Kind == "host-name-mismatch"), "host name: the mismatch is in the machine's history");

        AdminBrowser b = await app.SignedIn();
        string view = (await b.GetAsync("/api/v1/machines/" + app.Fingerprint[..20])).Html;
        check(view.Contains("renamed-host", StringComparison.Ordinal) && view.Contains("approve-host-change", StringComparison.Ordinal), "host name: the admin API shows the waiting name and its action");
        Tapped phone = await b.OpAsync("machine-host-change", app.Phone, true, null, true, ("fingerprint", app.Fingerprint[..20]));
        check(phone.ApproveStatus == 403 && app.Store.Find(app.Fingerprint)!.HostName == "test-host", "host name: a key that is not an admin cannot approve the change");
        Tapped approve = await b.OpAsync("machine-host-change", app.Laptop, true, null, true, ("fingerprint", app.Fingerprint[..20]));
        check(approve.MutationStatus == 200 && approve.Page.Contains("renamed-host", StringComparison.Ordinal) && app.Store.Find(app.Fingerprint) is { HostName: "renamed-host", PendingHostName: null } changed && changed.SecurityRevision == revision, "host name: an administrator's tap binds exactly the name the page showed, with no change of the security revision (" + Tap(approve) + ")");
        HostServiceTests.Raw after = await HostServiceTests.Post(app.Rig, HostServiceTests.Req(app.Rig, program));
        check(after.Result is { Outcome: LaunchOutcome.Exited } && app.Secrets.Reads == 2, "host name: after the approval the machine runs again under the new name");
        check(app.Store.Audit(1000).Any(entry => entry.Event == "machine-host-name-approved" || entry.Event.Contains("host", StringComparison.Ordinal) && entry.Detail.Contains("renamed-host", StringComparison.Ordinal)), "host name: the approval is audited with the new name");
    }

    // ---- Docker through the host service ----

    private static async Task DockerThroughTheService(Action<bool, string> check, string root)
    {
        using HostServiceTests.Rig rig = new(root, new Dictionary<string, string> { ["API_TOKEN"] = Value });
        string bin = Path.Combine(rig.Work, "bin");
        Directory.CreateDirectory(bin);
        string docker = Path.Combine(bin, OperatingSystem.IsWindows() ? "docker.cmd" : "docker");
        string log = Path.Combine(bin, "docker.log");
        if (OperatingSystem.IsWindows())
        {
            File.WriteAllText(docker, "@echo off\r\necho ARGS=%* > \"%~dp0docker.log\"\r\nset >> \"%~dp0docker.log\"\r\nexit /b 0\r\n");
        }
        else
        {
            File.WriteAllText(docker, "#!/bin/sh\necho \"ARGS=$*\" > \"" + log + "\"\nenv >> \"" + log + "\"\n");
            File.SetUnixFileMode(docker, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        string pathName = LaunchClient.CurrentEnvironment().Keys.FirstOrDefault(key => key.Equals("PATH", StringComparison.OrdinalIgnoreCase)) ?? "PATH";
        IReadOnlyDictionary<string, string> env = HostServiceTests.Env((pathName, bin + Path.PathSeparator + LaunchClient.CurrentEnvironment().GetValueOrDefault(pathName, "")));
        string[] args = ["run", "--rm", "-e", "API_TOKEN", "alpine", "printenv", "API_TOKEN"];
        HostServiceTests.Raw run = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, "docker", args, [("API_TOKEN", "API_TOKEN")], env));
        string seen = File.Exists(log) ? File.ReadAllText(log) : "";
        string[] lines = seen.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        string argsLine = lines.FirstOrDefault(line => line.StartsWith("ARGS=", StringComparison.Ordinal)) ?? "";
        check(run.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 0 }, "docker: launched through the host service like any other program (" + run.Result + ")");
        check(argsLine == "ARGS=" + string.Join(' ', args), "docker: the arguments are exactly the ones asked for (names only; the service adds no volume, no env-file, no container option) (" + argsLine + ")");
        check(lines.Count(line => line.Contains(Value, StringComparison.Ordinal)) == 1 && lines.Any(line => line == "API_TOKEN=" + Value), "docker: the value is in exactly one place the client can see, its environment variable API_TOKEN");
        string[] names = [.. lines.Where(line => line.Contains('=') && !line.StartsWith("ARGS=", StringComparison.Ordinal)).Select(line => line[..line.IndexOf('=')])];
        HashSet<string> allowed = new(env.Keys.Append("API_TOKEN"), StringComparer.OrdinalIgnoreCase);
        string[] extra = [.. names.Where(name => !allowed.Contains(name) && !name.StartsWith('_') && name is not ("PROMPT" or "CD" or "ERRORLEVEL" or "SHLVL" or "PWD" or "OLDPWD") && !name.StartsWith("=", StringComparison.Ordinal))];
        check(extra.Length == 0 && !names.Any(name => name.StartsWith("WITH_SECRETS", StringComparison.OrdinalIgnoreCase) || name.Contains("CONTAINER", StringComparison.OrdinalIgnoreCase)), "docker: the client's environment is the request's environment and the value, nothing else (no service state, no container identity) (" + string.Join(",", extra) + ")");
        check(!run.Lines.Any(line => line.Contains(Value, StringComparison.Ordinal)), "docker: the value is in no event the service sent");
        string[] services = [Path.GetDirectoryName(rig.State.FilePath)!, rig.Machine.Folder];
        bool onDisk = services.Distinct().SelectMany(folder => Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories)).Any(file => Contains(file, Value));
        check(!onDisk, "docker: the value is in no file of the service's own folders (no secret volume, no env file)");

        // A container client cannot reach the service as it stands: the service answers only for loopback names, so host.docker.internal and a bridge address are refused.
        int asked = rig.Approvers.Count;
        HostServiceTests.Raw dockerHost = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, "docker", args, [("API_TOKEN", "API_TOKEN")], env), tweak: message => message.Headers.Host = "host.docker.internal:" + rig.Service.Port);
        HostServiceTests.Raw bridge = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, "docker", args, [("API_TOKEN", "API_TOKEN")], env), tweak: message => message.Headers.Host = "172.17.0.1:" + rig.Service.Port);
        check((int)dockerHost.Status == 421 && (int)bridge.Status == 421 && rig.Approvers.Count == asked, "docker: a request that names host.docker.internal or a bridge address is refused (421) and nothing is asked; a container client is not supported until that is decided");
    }
}

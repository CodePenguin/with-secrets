using System.Security.Cryptography;

using Microsoft.Data.Sqlite;

using Authority = WithSecrets.Tests.ConvenienceKeyTests.Authority;

namespace WithSecrets.Tests;

/// <summary>
/// Every audit entry of an action a person took names the passkey: its id, its name and whether it was an admin key, in the host's signed event and in the authority's history wherever
/// each exists. A sign-in, an approval once, a grant approval, the four grant changes, an unlock, a lock and an admin change name the key that tapped; a denial and a sign-out the key that
/// signed the session in; a run under a grant (local and remote) the key that approved the grant and the one that changed it last, and no tapping key; every delivery the admin key that
/// unlocked. A refused operation names a key that verified; a signature that did not verify, a timeout, an expiry and a restart name none. A reused name is told apart by the id, and a
/// grant row whose approver columns were edited covers nothing.
/// </summary>
internal static class AuditKeyTests
{
    private static readonly string[] Roles = ["key", "sessionKey", "grantApproved", "grantChanged", "unlock"];

    /// <summary>The real time moved by <see cref="Offset" />, so a grant can end without waiting while signed requests stay fresh.</summary>
    private sealed class ShiftedClock : TimeProvider
    {
        public TimeSpan Offset { get; set; }

        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UtcNow + Offset;
    }

    public static async Task Run(Action<bool, string> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "ws-auditkey-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);
        try
        {
            await LocalRuns(check, root);
            await RemoteRuns(check, root);
            await RemoteDenial(check, root);
            await NoPerson(check, root);
            await ReusedName(check, root);
            await EditedGrant(check, root);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            try
            {
                Directory.Delete(root, true);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
            }
        }
    }

    private static VerifiedCredential Of(TestAuthenticator who, string name, bool admin) => new(TestAuthenticator.Encode(who.CredentialId), name, admin);

    private static bool Names(IReadOnlyDictionary<string, string>? metadata, string role, VerifiedCredential key) =>
        metadata is not null && metadata.TryGetValue(role + "Id", out string? id) && id == key.Id && metadata.TryGetValue(role + "Name", out string? name) && name == key.Name
        && metadata.TryGetValue(role + "Admin", out string? admin) && admin == (key.Admin ? "true" : "false");

    private static bool Lacks(IReadOnlyDictionary<string, string>? metadata, string role) => metadata is null || !(metadata.ContainsKey(role + "Id") || metadata.ContainsKey(role + "Name") || metadata.ContainsKey(role + "Admin"));

    /// <summary>No role names a key, and there is no bare key name either.</summary>
    private static bool NoKeys(IReadOnlyDictionary<string, string>? metadata) => Roles.All(role => Lacks(metadata, role)) && (metadata is null || !metadata.ContainsKey("key"));

    private static string Show(IReadOnlyDictionary<string, string>? metadata) => metadata is null ? "(no metadata)" : string.Join(",", metadata.Where(item => Roles.Any(role => item.Key.StartsWith(role, StringComparison.Ordinal))).Select(item => item.Key + "=" + item.Value));

    private static string Show(AuditEntry? entry) => entry is null ? "(no entry)" : entry.Event + " [" + entry.Detail + "] key " + (entry.Key is { } key ? key.Id[..6] + "/" + key.Name + "/" + key.Admin : "none") + " " + Show(entry.Metadata);

    private static string Show(AuditEvent? item) => item is null ? "(no event)" : item.Type + "/" + item.Outcome + " " + Show(item.Metadata);

    /// <summary>Every signed event of <paramref name="service" />'s machine (its outbox) and every one an authority over <paramref name="store" /> holds.</summary>
    private static List<AuditEvent> HostEvents(HostService service, AuthorityStore store)
    {
        Dictionary<string, AuditEvent> all = new(StringComparer.Ordinal);
        foreach (AuditEvent item in service.Audit.Outbox.Pending(10000).Concat(store.AuditHistory(new AuditQuery(Limit: AuditQuery.MaxLimit)).Select(record => record.Event)))
        {
            all[item.EventId] = item;
        }

        return [.. all.Values.OrderBy(item => item.Sequence)];
    }

    /// <summary>The authority's history entries written after <paramref name="mark" />.</summary>
    private static List<AuditEntry> Since(AuthorityStore store, long mark) => [.. store.Audit(1000).Where(entry => entry.Id > mark).OrderBy(entry => entry.Id)];

    private static long Mark(AuthorityStore store) => store.Audit(1000).Select(entry => entry.Id).DefaultIfEmpty(0).Max();

    /// <summary>The events of one run after the secrets were decrypted (started, and how it ended).</summary>
    private static List<AuditEvent> Deliveries(IEnumerable<AuditEvent> events, string requestId) => [.. events.Where(item => item.RequestId == requestId && (item.Type == AuditEventTypes.Execution || item is { Type: AuditEventTypes.Launch, Outcome: "started" }))];

    private static async Task<(int Status, string Body)> Unlock(Authority auth, HttpClient pages)
    {
        auth.Service.Lock.Lock("test: unlocked again through the admin app");
        (_, int mutation, string state) = await AuthorityLockTests.InlineTap(new AdminBrowser(auth.Service, pages), AdminService.OpUnlock, "/api/v1/unlock", auth.Admin, PrfMode.Normal);

        return (mutation, state);
    }

    // ---------- the local runs, the grant changes, the session, unlock, lock and an admin change ----------

    private static async Task LocalRuns(Action<bool, string> check, string root)
    {
        ShiftedClock clock = new();
        using Authority auth = new(root, queue: true, clock: clock);
        AuthorityStore store = auth.Machine.Deployment.Store;
        VerifiedCredential laptop = Of(auth.Admin, "laptop", true);
        VerifiedCredential phone = Of(auth.Phone, "phone", false);
        using HttpClient pages = ConvenienceKeyTests.Pages();

        long mark = Mark(store);
        (int unlocked, string unlockState) = await Unlock(auth, pages);
        List<AuditEntry> unlockEntries = Since(store, mark);
        check(unlocked == 200 && auth.Service.Keys!.OpenedBy == laptop, "audit key: the laptop unlocks the authority through the admin app (" + unlocked + " " + unlockState + ")");
        check(unlockEntries.Any(entry => entry.Detail.StartsWith("unlock-authority; applied", StringComparison.Ordinal) && entry.Key == laptop),
            "audit key: unlock: the authority's history names the admin key that tapped (" + string.Join(" | ", unlockEntries.Select(Show)) + ")");

        AdminBrowser phoneApp = new(auth.Service, pages);
        mark = Mark(store);
        check(await phoneApp.SignInAsync(auth.Phone), "audit key: the phone signs in");
        List<AuditEntry> signIn = Since(store, mark);
        check(signIn.Any(entry => entry.Detail.StartsWith("admin-session; started", StringComparison.Ordinal) && entry.Key == phone) && signIn.Where(entry => entry.Key is not null).All(entry => entry.Key == phone),
            "audit key: sign-in: the authority's history names the phone, by id, name and kind (" + string.Join(" | ", signIn.Select(Show)) + ")");

        (string program, string valueFile) = ConvenienceKeyTests.ValueScript(auth.Work, "audit-local");
        LaunchRequest once = auth.Request(program);
        (HostServiceTests.Raw onceRaw, _) = await ConvenienceKeyTests.PostQueued(auth, once, auth.Phone);
        await Task.Delay(700);
        List<AuditEvent> events = HostEvents(auth.Service, store);
        AuditEvent? approved = events.FirstOrDefault(item => item.RequestId == once.RequestId && item.Outcome == "approved");
        check(onceRaw.Result is { ExitCode: 4 } && approved is not null && Names(approved.Metadata, "key", phone) && Roles.Skip(1).All(role => Lacks(approved.Metadata, role)),
            "audit key: approve once: the host's signed event names the phone that tapped, and no other role (" + Show(approved) + ")");
        List<AuditEntry> onceEntries = [.. store.Audit(1000).Where(entry => entry.RequestId == once.RequestId)];
        check(onceEntries.Any(entry => entry.Key == phone) && onceEntries.All(entry => entry.Key is null || entry.Key == phone),
            "audit key: approve once: the authority's history names the phone (" + string.Join(" | ", onceEntries.Select(Show)) + ")");
        List<AuditEvent> onceDelivered = Deliveries(events, once.RequestId);
        check(onceDelivered.Count >= 2 && onceDelivered.All(item => Names(item.Metadata, "unlock", laptop)),
            "audit key: delivery: each event after the decryption of a run approved once names the admin key that unlocked (" + string.Join(" | ", onceDelivered.Select(Show)) + ")");

        LaunchRequest grantAsk = auth.Request(program);
        mark = Mark(store);
        (HostServiceTests.Raw made, _) = await ConvenienceKeyTests.PostQueued(auth, grantAsk, auth.Phone, 60, "v1/approve");
        GrantRecord? grant = store.Grants().FirstOrDefault(row => row.Usage == GrantUsage.Reusable && row.Status == "active");
        await Task.Delay(700);
        AuditEvent? grantApproved = HostEvents(auth.Service, store).FirstOrDefault(item => item.RequestId == grantAsk.RequestId && item.Outcome == "grant-approved");
        AuditEntry? created = Since(store, mark).FirstOrDefault(entry => entry.Event == "grant-created");
        check(made.Result is { ExitCode: 0 } && grant is not null && grant.ApprovedKey == phone, "audit key: approve grant: the grant row keeps the phone as the key that approved it (" + grant?.ApprovedKey + ")");
        check(grantApproved is not null && Names(grantApproved.Metadata, "key", phone), "audit key: approve grant: the host's signed event names the phone that tapped (" + Show(grantApproved) + ")");
        check(created is not null && created.Key == phone, "audit key: approve grant: the authority's history names the phone that tapped (" + Show(created) + ")");
        if (grant is null)
        {
            return;
        }

        AdminBrowser laptopApp = new(auth.Service, pages);
        check(await laptopApp.SignInAsync(auth.Admin), "audit key: the laptop signs in");
        mark = Mark(store);
        Tapped byLaptop = await laptopApp.OpAsync("grant-extend", auth.Admin, true, null, true, ("id", grant.Id), ("minutes", "30"));
        bool extended = byLaptop.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => store.FindGrant(grant.Id) is { Revision: 2 });
        AuditEntry? laptopExtend = Since(store, mark).FirstOrDefault(entry => entry.Event == "grant-extended");
        check(extended && laptopExtend?.Key == laptop && store.FindGrant(grant.Id)!.ChangedKey == laptop, "audit key: grant extend by a second key: the history and the grant row name the laptop (" + Show(laptopExtend) + ")");

        LaunchRequest covered = auth.Request(program);
        mark = Mark(store);
        (HostServiceTests.Raw coveredRaw, List<ConvenienceKeyTests.Queued> coveredTaps) = await ConvenienceKeyTests.PostQueued(auth, covered, auth.Phone);
        await Task.Delay(700);
        events = HostEvents(auth.Service, store);
        AuditEvent? granted = events.FirstOrDefault(item => item.RequestId == covered.RequestId && item.Outcome == "granted");
        check(coveredRaw.Result is { ExitCode: 4 } && coveredTaps.Count == 0 && granted is not null && Names(granted.Metadata, "grantApproved", phone) && Names(granted.Metadata, "grantChanged", laptop) && Lacks(granted.Metadata, "key") && !granted.Metadata!.ContainsKey("key"),
            "audit key: grant-covered local run: the host's signed event names the phone as the grant's approver and the laptop as its last changer, and no tapping key (" + Show(granted) + ")");
        AuditEntry? used = Since(store, mark).FirstOrDefault(entry => entry.Event == "grant-use");
        check(used is not null && used.Key is null && Names(used.Metadata, "grantApproved", phone) && Names(used.Metadata, "grantChanged", laptop),
            "audit key: grant-covered local run: the authority's history names the grant's approver and last changer, and no tapping key (" + Show(used) + ")");
        List<AuditEvent> coveredDelivered = Deliveries(events, covered.RequestId);
        check(coveredDelivered.Count >= 2 && coveredDelivered.All(item => Names(item.Metadata, "unlock", laptop)),
            "audit key: delivery: each event after the decryption of a grant-covered run names the admin key that unlocked (" + string.Join(" | ", coveredDelivered.Select(Show)) + ")");

        mark = Mark(store);
        Tapped phoneExtend = await phoneApp.OpAsync("grant-extend", auth.Phone, true, null, true, ("id", grant.Id), ("minutes", "30"));
        bool again = phoneExtend.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => store.FindGrant(grant.Id) is { Revision: 3 });
        AuditEntry? extendEntry = Since(store, mark).FirstOrDefault(entry => entry.Event == "grant-extended");
        check(again && extendEntry?.Key == phone, "audit key: grant extend: the authority's history names the phone that tapped (" + Show(extendEntry) + ")");

        Tapped stale = await phoneApp.OpAsync("grant-revoke", null, true, null, true, ("id", grant.Id));
        Tapped moved = await laptopApp.OpAsync("grant-extend", auth.Admin, true, null, true, ("id", grant.Id), ("minutes", "15"));
        bool movedOn = moved.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => store.FindGrant(grant.Id) is { Revision: 4 });
        mark = Mark(store);
        (int staleTap, _) = stale.Link is null ? (0, "") : TestState.Approve(pages, stale.PageUrl, "http://localhost:" + new Uri(stale.Link).Port, "localhost", auth.Phone);
        string staleState = stale.AuthorizationId is null ? "" : await phoneApp.WaitAuthorizationAsync(stale.AuthorizationId);
        List<AuditEntry> staleEntries = [.. Since(store, mark).Where(entry => entry.Detail.Contains("; failed", StringComparison.Ordinal) || entry.Detail.Contains("; refused", StringComparison.Ordinal))];
        check(movedOn && staleTap != 0 && store.FindGrant(grant.Id) is { Status: "active", Revision: 4 } && staleEntries.Count > 0 && staleEntries.All(entry => entry.Key == phone),
            "audit key: a valid key whose operation is refused (a revoke of a grant that changed after its page was made): the refused entry names that key (" + staleTap + " " + staleState + ": " + string.Join(" | ", staleEntries.Select(Show)) + ")");

        mark = Mark(store);
        Tapped revoke = await phoneApp.OpAsync("grant-revoke", auth.Phone, true, null, true, ("id", grant.Id));
        bool revoked = revoke.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => store.FindGrant(grant.Id) is { Status: "revoked" });
        AuditEntry? revokeEntry = Since(store, mark).FirstOrDefault(entry => entry.Event == "grant-revoked");
        check(revoked && revokeEntry?.Key == phone, "audit key: grant revoke: the authority's history names the phone that tapped (" + Show(revokeEntry) + ")");

        GrantRecord? used0 = store.Grants().FirstOrDefault(row => row.Usage == GrantUsage.Once && row.Status == "consumed");
        mark = Mark(store);
        Tapped replace = used0 is null ? new Tapped(0, null, null, 0, "", "") : await phoneApp.OpAsync("grant-replace", auth.Phone, true, null, true, ("id", used0.Id), ("minutes", "10"));
        GrantRecord? replacement = await HostServiceTests.WaitFor(() => store.Grants().Any(row => row.Replaces == used0!.Id)) ? store.Grants().First(row => row.Replaces == used0!.Id) : null;
        AuditEntry? replaceEntry = Since(store, mark).FirstOrDefault(entry => entry.Event == "grant-replaced");
        check(replace.ApproveStatus == 200 && replacement is { Status: "active" } && replaceEntry?.Key == phone, "audit key: grant replace: the authority's history names the phone that tapped (" + Show(replaceEntry) + ")");

        LaunchRequest deniedRun = auth.Request(ConvenienceKeyTests.ValueScript(auth.Work, "audit-denied").Program);
        Task<HostServiceTests.Raw> waiting = auth.Post(deniedRun);
        bool pending = await HostServiceTests.WaitFor(() => auth.Service.Approvals.ListPending(10, null, out _).Any());
        string pendingId = auth.Service.Approvals.ListPending(10, null, out _).FirstOrDefault()?.RequestId ?? "none";
        mark = Mark(store);
        (int deny, string denyBody) = await phoneApp.SendAsync(HttpMethod.Post, AdminApi.Prefix + "/approvals/" + pendingId + "/deny", null);
        HostServiceTests.Raw deniedRaw = await waiting;
        await Task.Delay(700);
        AuditEvent? denied = HostEvents(auth.Service, store).FirstOrDefault(item => item.RequestId == deniedRun.RequestId && item.Outcome == "denied");
        check(pending && deny == 200 && deniedRaw.Result is not { Outcome: LaunchOutcome.Exited } && denied is not null && Names(denied.Metadata, "sessionKey", phone) && Lacks(denied.Metadata, "key") && !denied.Metadata!.ContainsKey("key"),
            "audit key: deny: the host's signed event names the phone that signed the session in, as the session key, and no tapping key (" + deny + " " + denyBody + " " + Show(denied) + ")");
        List<AuditEntry> denyEntries = [.. Since(store, mark).Where(entry => entry.RequestId == deniedRun.RequestId)];
        check(denyEntries.Any(entry => Names(entry.Metadata, "sessionKey", phone)) && denyEntries.All(entry => entry.Key is null && Lacks(entry.Metadata, "key")),
            "audit key: deny: the authority's history names the session's key and no tapping key (" + string.Join(" | ", denyEntries.Select(Show)) + ")");

        clock.Offset = TimeSpan.FromMinutes(11);
        mark = Mark(store);
        Tapped renew = replacement is null ? new Tapped(0, null, null, 0, "", "") : await phoneApp.OpAsync("grant-renew", auth.Phone, true, null, true, ("id", replacement.Id), ("minutes", "10"));
        bool renewed = renew.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => store.FindGrant(replacement!.Id) is { Revision: 2 });
        AuditEntry? renewEntry = Since(store, mark).FirstOrDefault(entry => entry.Event == "grant-renewed");
        check(renewed && renewEntry?.Key == phone, "audit key: grant renew: the authority's history names the phone that tapped (" + renew.ApproveStatus + " " + renew.Error + " " + Show(renewEntry) + ")");

        mark = Mark(store);
        (int signedOut, _) = await phoneApp.SendAsync(HttpMethod.Delete, AdminApi.Prefix + "/session", null);
        AuditEntry? signOut = Since(store, mark).FirstOrDefault(entry => entry.Detail.StartsWith("admin-session; ended: sign out", StringComparison.Ordinal));
        check(signedOut == 200 && signOut is not null && signOut.Key is null && Names(signOut.Metadata, "sessionKey", phone) && Lacks(signOut.Metadata, "key"),
            "audit key: sign-out: the authority's history names the session's key and no tapping key (" + Show(signOut) + ")");

        check(await laptopApp.StillSignedIn() || await laptopApp.SignInAsync(auth.Admin), "audit key: the laptop is signed in for its changes");
        (string Op, string Event, (string Name, string Value)[] Args)[] changes =
        [
            ("machine-rename", "machine-rename", [("fingerprint", auth.Machine.Fingerprint[..20]), ("name", "audited name")]),
            ("set-audit-retention", "audit-retention-changed", [("days", "30")]),
            ("set-session-timeouts", "session-timeouts-changed", [("idle", "20"), ("absolute", "600")]),
            ("authority-key-rotate", "authority-key-rotated", []),
        ];
        foreach ((string op, string eventName, (string Name, string Value)[] args) in changes)
        {
            mark = Mark(store);
            Tapped changed = await laptopApp.OpAsync(op, auth.Admin, true, null, true, args);
            await HostServiceTests.WaitFor(() => store.Audit(1000).Any(entry => entry.Id > mark && entry.Event == eventName));
            List<AuditEntry> changeEntries = [.. Since(store, mark).Where(entry => entry.Event == eventName || entry.Detail.Contains("; applied", StringComparison.Ordinal))];
            check(changed.ApproveStatus == 200 && changeEntries.Any(entry => entry.Event == eventName) && changeEntries.Any(entry => entry.Event == "admin-operation") && changeEntries.All(entry => entry.Key == laptop),
                "audit key: an admin change (" + op + "): the history entries of the change and of its outcome name the laptop that tapped (" + string.Join(" | ", changeEntries.Select(Show)) + ")");
        }

        mark = Mark(store);
        (int lockProof, _, _) = await AuthorityLockTests.InlineTap(laptopApp, AdminService.OpLock, "/api/v1/lock", auth.Admin, PrfMode.Missing);
        bool lockedNow = await HostServiceTests.WaitFor(() => auth.Service.Lock.IsLocked);
        List<AuditEntry> lockEntries = Since(store, mark);
        check(lockProof == 200 && lockedNow && lockEntries.Any(entry => entry.Detail.StartsWith("lock-authority; applied", StringComparison.Ordinal) && entry.Key == laptop),
            "audit key: lock: the authority's history names the admin key that tapped (" + string.Join(" | ", lockEntries.Select(Show)) + ")");
    }

    // ---------- through a remote authority ----------

    private static async Task RemoteRuns(Action<bool, string> check, string root)
    {
        using Authority auth = new(root, machineEndpoint: true);
        AuthorityStore store = auth.Machine.Deployment.Store;
        VerifiedCredential laptop = Of(auth.Admin, "laptop", true);
        VerifiedCredential phone = Of(auth.Phone, "phone", false);
        using HttpClient pages = ConvenienceKeyTests.Pages();
        (int unlocked, string unlockState) = await Unlock(auth, pages);
        check(unlocked == 200 && auth.Service.Keys!.OpenedBy == laptop, "audit key remote: the laptop unlocks the authority (" + unlocked + " " + unlockState + ")");
        using ConvenienceKeyTests.RemoteHost host = await ConvenienceKeyTests.Pair(root, auth, "wsl-audit");
        string program = host.Rig.Script("audit-remote", "echo %TOKEN%>\"%~dpn0.val\"\nexit /b 4", "printf '%s' \"$TOKEN\" > \"$0.val\"\nexit 4");
        void TapOnce(LaunchEvent item)
        {
            if (item.Kind == LaunchEvent.ApprovalKind && ApprovalLinkNotice.IsSafe(item.Link ?? ""))
            {
                ConvenienceKeyTests.Tap(auth.Browser, item.Link!, auth.Phone);
            }
        }

        LaunchRequest once = HostServiceTests.Req(host.Rig, program);
        HostServiceTests.Raw onceRaw = await HostServiceTests.Post(host.Rig, once, TapOnce);
        await Task.Delay(900);
        List<AuditEvent> events = HostEvents(host.Rig.Service, store);
        AuditEvent? approved = events.FirstOrDefault(item => item.RequestId == once.RequestId && item.Outcome == "approved");
        check(onceRaw.Result is { ExitCode: 4 } && approved is not null && Names(approved.Metadata, "key", phone),
            "audit key remote: approve once: the remote host's signed event names the phone that tapped at the authority (" + onceRaw.Result + " " + Show(approved) + ")");
        List<AuditEntry> onceEntries = [.. store.Audit(1000).Where(entry => entry.RequestId == once.RequestId)];
        AuditEntry? prepared = onceEntries.FirstOrDefault(entry => entry.Event == "delivery-prepared");
        check(onceEntries.Any(entry => entry.Key == phone) && prepared is not null && Names(prepared.Metadata, "unlock", laptop),
            "audit key remote: approve once: the authority's history names the phone, and its delivery the admin key that unlocked (" + string.Join(" | ", onceEntries.Select(Show)) + ")");
        List<AuditEvent> delivered = Deliveries(events, once.RequestId);
        check(delivered.Count >= 2 && delivered.All(item => Names(item.Metadata, "unlock", laptop)),
            "audit key remote: delivery: each event after the remote host received the values names the admin key that unlocked the authority (" + string.Join(" | ", delivered.Select(Show)) + ")");

        GrantRecord? used = store.Grants().FirstOrDefault(row => row.Fingerprint == host.Machine.Fingerprint && row.Usage == GrantUsage.Once && row.Status == "consumed");
        AdminBrowser phoneApp = new(auth.Service, pages);
        AdminBrowser laptopApp = new(auth.Service, pages);
        check(used is not null && await phoneApp.SignInAsync(auth.Phone) && await laptopApp.SignInAsync(auth.Admin), "audit key remote: the run left a used once-only grant; the phone and the laptop sign in");
        if (used is null)
        {
            return;
        }

        Tapped replace = await phoneApp.OpAsync("grant-replace", auth.Phone, true, null, true, ("id", used.Id), ("minutes", "60"));
        GrantRecord? grant = await HostServiceTests.WaitFor(() => store.Grants().Any(row => row.Replaces == used.Id)) ? store.Grants().First(row => row.Replaces == used.Id) : null;
        Tapped extend = grant is null ? new Tapped(0, null, null, 0, "", "") : await laptopApp.OpAsync("grant-extend", auth.Admin, true, null, true, ("id", grant.Id), ("minutes", "30"));
        bool changed = grant is not null && extend.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => store.FindGrant(grant.Id) is { Revision: 2 });
        check(replace.ApproveStatus == 200 && changed, "audit key remote: the phone makes a grant for the remote host's command (replace) and the laptop extends it");

        LaunchRequest covered = HostServiceTests.Req(host.Rig, program);
        HostServiceTests.Raw coveredRaw = await HostServiceTests.Post(host.Rig, covered, _ => { });
        await Task.Delay(900);
        events = HostEvents(host.Rig.Service, store);
        AuditEvent? granted = events.FirstOrDefault(item => item.RequestId == covered.RequestId && item.Outcome == "granted");
        check(coveredRaw.Result is { ExitCode: 4 } && granted is not null && Names(granted.Metadata, "grantApproved", phone) && Names(granted.Metadata, "grantChanged", laptop) && Lacks(granted.Metadata, "key") && !granted.Metadata!.ContainsKey("key"),
            "audit key remote: grant-covered run: the remote host's signed event names the phone as the grant's approver and the laptop as its last changer, and no tapping key (" + coveredRaw.Result + " " + Show(granted) + ")");
        List<AuditEntry> coveredEntries = [.. store.Audit(1000).Where(entry => entry.RequestId == covered.RequestId)];
        AuditEntry? coveredDelivery = coveredEntries.FirstOrDefault(entry => entry.Event == "delivery-prepared");
        check(coveredDelivery is not null && coveredDelivery.Key is null && Names(coveredDelivery.Metadata, "grantApproved", phone) && Names(coveredDelivery.Metadata, "grantChanged", laptop) && Names(coveredDelivery.Metadata, "unlock", laptop),
            "audit key remote: grant-covered run: the authority's delivery entry names the grant's approver, its last changer and the admin key that unlocked, and no tapping key (" + string.Join(" | ", coveredEntries.Select(Show)) + ")");
        List<AuditEvent> coveredDelivered = Deliveries(events, covered.RequestId);
        check(coveredDelivered.Count >= 2 && coveredDelivered.All(item => Names(item.Metadata, "unlock", laptop)),
            "audit key remote: delivery: each event after a grant-covered remote delivery names the admin key that unlocked (" + string.Join(" | ", coveredDelivered.Select(Show)) + ")");
    }

    private static async Task RemoteDenial(Action<bool, string> check, string root)
    {
        using Authority auth = new(root, queue: true, machineEndpoint: true);
        AuthorityStore store = auth.Machine.Deployment.Store;
        VerifiedCredential phone = Of(auth.Phone, "phone", false);
        using HttpClient pages = ConvenienceKeyTests.Pages();
        (int unlocked, _) = await Unlock(auth, pages);
        AdminBrowser phoneApp = new(auth.Service, pages);
        bool signedIn = await phoneApp.SignInAsync(auth.Phone);
        check(unlocked == 200 && signedIn, "audit key remote denial: the authority was unlocked and the convenience key signed in");

        using ConvenienceKeyTests.RemoteHost host = await ConvenienceKeyTests.Pair(root, auth, "remote-denial");
        string program = host.Rig.Script("remote-denial", "exit /b 0", "exit 0");
        LaunchRequest request = HostServiceTests.Req(host.Rig, program);
        Task<HostServiceTests.Raw> waiting = HostServiceTests.Post(host.Rig, request);
        bool pending = await HostServiceTests.WaitFor(() => auth.Service.Approvals.ListPending(10, null, out _).Any(item => item.RequestId == request.RequestId));
        (int status, _) = await phoneApp.SendAsync(HttpMethod.Post, AdminApi.Prefix + "/approvals/" + request.RequestId + "/deny", null);
        HostServiceTests.Raw refused = await waiting;
        AuditEvent? denied = HostEvents(host.Rig.Service, store).FirstOrDefault(item => item.RequestId == request.RequestId && item.Outcome == "denied");
        check(pending && status == 200 && refused.Result is not { Outcome: LaunchOutcome.Exited } && denied is not null
            && Names(denied.Metadata, "sessionKey", phone) && Lacks(denied.Metadata, "key"),
            "audit key remote denial: the remote host records the convenience session key without a tapping key (pending " + pending + ", status " + status + ", " + Show(denied) + ")");
        check(store.Audit(1000).Any(entry => entry.RequestId == request.RequestId && entry.Key is null && Names(entry.Metadata, "sessionKey", phone)),
            "audit key remote denial: the authority records the same session key");
    }

    // ---------- entries with no person behind them ----------

    private static async Task NoPerson(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root, askSeconds: 2, machineEndpoint: true);
        AuthorityStore store = app.Store;
        AdminBrowser laptop = await app.SignedIn();
        string machine = app.Fingerprint[..20];

        long mark = Mark(store);
        app.Clock.Advance(TimeSpan.FromSeconds(13));
        Tapped forged = await laptop.OpAsync("machine-disable", app.Laptop, true, challenge => SHA256.HashData(challenge), true, ("fingerprint", machine));
        app.Clock.Advance(TimeSpan.FromSeconds(13));
        Tapped forgedPhone = await laptop.OpAsync("machine-rename", app.Phone, true, challenge => SHA256.HashData(challenge), true, ("fingerprint", machine), ("name", "forged"));
        List<AuditEntry> forgedEntries = Since(store, mark);
        check(forged.Link is not null && forged.ApproveStatus is 403 or 400 && forgedPhone.ApproveStatus is 403 or 400 && forgedEntries.Count > 0 && forgedEntries.All(entry => entry.Key is null && NoKeys(entry.Metadata)),
            "audit key: a bad signature that claims a real key's id (the laptop's, the phone's) is recorded with no key (" + string.Join(" | ", forgedEntries.Select(Show)) + ")");

        mark = Mark(store);
        app.Clock.Advance(TimeSpan.FromSeconds(13));
        Tapped silent = await laptop.OpAsync("machine-disable", null, true, null, true, ("fingerprint", machine));
        await Task.Delay(TimeSpan.FromSeconds(3.5));
        List<AuditEntry> timedOut = Since(store, mark);
        check(silent.Link is not null && timedOut.Any(entry => entry.Detail.Contains("refused", StringComparison.Ordinal)) && timedOut.All(entry => entry.Key is null && NoKeys(entry.Metadata)),
            "audit key: a passkey page nobody taps ends at its time limit with no key recorded (" + string.Join(" | ", timedOut.Select(Show)) + ")");

        AdminBrowser phone = app.Browser();
        check(await phone.SignInAsync(app.Phone), "audit key: the phone signs in");
        mark = Mark(store);
        app.Clock.Advance(TimeSpan.FromMinutes(16));
        check(!await phone.StillSignedIn(), "audit key: sixteen minutes without use end the phone's session");
        await laptop.GetAsync(AdminApi.Prefix + "/status");
        List<AuditEntry> expired = Since(store, mark);
        check(expired.Any(entry => entry.Detail.StartsWith("admin-session; ended: idle timeout", StringComparison.Ordinal)) && expired.All(entry => entry.Key is null && NoKeys(entry.Metadata)),
            "audit key: a session that expires is recorded with no key (" + string.Join(" | ", expired.Select(Show)) + ")");

        laptop = await app.SignedIn();
        app.Clock.Advance(TimeSpan.FromSeconds(13));
        mark = Mark(store);
        Tapped invitation = await laptop.OpAsync("pairing-create", app.Laptop, true, null, true);
        List<AuditEntry> created = [.. Since(store, mark).Where(entry => entry.Event == "pairing-invitation-created" || entry.Detail.Contains("; applied", StringComparison.Ordinal))];
        check(invitation.MutationStatus == 200 && store.Invitations().Any(item => item.Status == "pending") && created.Any(entry => entry.Event == "pairing-invitation-created") && created.All(entry => entry.Key == Of(app.Laptop, "laptop", true)),
            "audit key: an admin change (pairing-create): the history entries of the change and of its outcome name the laptop that tapped (" + string.Join(" | ", created.Select(Show)) + ")");
        mark = Mark(store);
        app.Start(true);
        await HostServiceTests.WaitFor(() => store.Audit(1000).Any(entry => entry.Id > mark && entry.Event == "pairing-invitation-expired"));
        List<AuditEntry> restarted = Since(store, mark);
        check(restarted.Any(entry => entry.Event == "pairing-invitation-expired") && restarted.All(entry => entry.Key is null && NoKeys(entry.Metadata)),
            "audit key: what a restart ends is recorded with no key (" + string.Join(" | ", restarted.Select(Show)) + ")");
    }

    // ---------- a name used again ----------

    private static async Task ReusedName(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root);
        AuthorityStore store = app.Store;
        long mark = Mark(store);
        check(await app.Browser().SignInAsync(app.Phone), "audit key: the first phone signs in");
        AuditEntry? first = Since(store, mark).FirstOrDefault(entry => entry.Detail.StartsWith("admin-session; started", StringComparison.Ordinal));
        string oldId = TestAuthenticator.Encode(app.Phone.CredentialId);
        check(new PasskeyStore(app.State).RemoveById(oldId), "audit key: the first phone is removed");

        using TestAuthenticator second = TestAuthenticator.ES256(prf: false);
        TestState.Add(app.State, second.Record("localhost", "phone") with { Created = new DateTimeOffset(2026, 11, 2, 10, 0, 0, TimeSpan.Zero) });
        mark = Mark(store);
        check(await app.Browser().SignInAsync(second), "audit key: a new passkey enrolled under the same name signs in");
        AuditEntry? next = Since(store, mark).FirstOrDefault(entry => entry.Detail.StartsWith("admin-session; started", StringComparison.Ordinal));
        AuditEntry? firstNow = first is null ? null : store.Audit(1000).FirstOrDefault(entry => entry.Id == first.Id);
        check(first?.Key is { Name: "phone" } a && next?.Key is { Name: "phone" } b && a.Id == oldId && b.Id == TestAuthenticator.Encode(second.CredentialId) && a.Id != b.Id,
            "audit key: two keys named phone have two different ids in the history (" + Show(first) + " / " + Show(next) + ")");
        check(firstNow is not null && firstNow.Key == first!.Key && firstNow.Detail == first.Detail && firstNow.Actor == first.Actor, "audit key: the first phone's entry is unchanged after its removal and the new enrolment");
    }

    // ---------- a grant row whose approver columns were edited ----------

    private static void Execute(AuthorityStore store, string sql, params (string Name, object Value)[] parameters)
    {
        using SqliteConnection connection = new("Data Source=" + store.FilePath + ";Pooling=False");
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        foreach ((string name, object value) in parameters)
        {
            command.Parameters.AddWithValue(name, value);
        }

        command.ExecuteNonQuery();
    }

    private static async Task EditedGrant(Action<bool, string> check, string root)
    {
        using Authority auth = new(root, queue: true);
        auth.OpenKeys();
        AuthorityStore store = auth.Machine.Deployment.Store;
        string laptopId = TestAuthenticator.Encode(auth.Admin.CredentialId);
        (string Name, string Sql, object Value)[] edits =
        [
            ("approved_key_id", "UPDATE grants SET approved_key_id = $v WHERE id = $id", laptopId),
            ("approved_key_name", "UPDATE grants SET approved_key_name = $v WHERE id = $id", "laptop"),
            ("approved_key_admin", "UPDATE grants SET approved_key_admin = $v WHERE id = $id", 1),
            ("changed_key_id", "UPDATE grants SET changed_key_id = $v WHERE id = $id", TestAuthenticator.Encode(auth.Phone.CredentialId)),
            ("changed_key_name", "UPDATE grants SET changed_key_name = $v WHERE id = $id", "phone"),
            ("changed_key_admin", "UPDATE grants SET changed_key_admin = $v WHERE id = $id", 0),
            ("changed_key (all three)", "UPDATE grants SET changed_key_id = $v, changed_key_name = 'laptop', changed_key_admin = 1 WHERE id = $id", laptopId),
        ];
        foreach ((string column, string sql, object value) in edits)
        {
            (string program, string valueFile) = ConvenienceKeyTests.ValueScript(auth.Work, "edited-" + new string([.. column.Where(char.IsAsciiLetter)]));
            (HostServiceTests.Raw made, _) = await ConvenienceKeyTests.PostQueued(auth, auth.Request(program), auth.Phone, ReuseOffer.Always, "v1/approve");
            GrantRecord? grant = store.Grants().LastOrDefault(row => row.Usage == GrantUsage.Reusable && row.Status == "active" && row.Program.Contains("edited-" + new string([.. column.Where(char.IsAsciiLetter)]), StringComparison.Ordinal));
            if (grant is null || made.Result is not { ExitCode: 0 })
            {
                check(false, "audit key edit: a grant for " + column + " was made (" + made.Result + " " + made.Stderr.Trim() + ")");

                continue;
            }

            File.Delete(valueFile);
            (HostServiceTests.Raw before, List<ConvenienceKeyTests.Queued> beforeTaps) = await ConvenienceKeyTests.PostQueued(auth, auth.Request(program), auth.Phone);
            Execute(store, sql, ("$v", value), ("$id", grant.Id));
            File.Delete(valueFile);
            int decrypts = auth.Cipher.Decrypts;
            (HostServiceTests.Raw after, List<ConvenienceKeyTests.Queued> afterTaps) = await ConvenienceKeyTests.PostQueued(auth, auth.Request(program), auth.Phone);
            check(before.Result is { ExitCode: 4 } && beforeTaps.Count == 0 && after.Result is { ExitCode: 4 } && afterTaps.Count == 1 && auth.Cipher.Decrypts == decrypts + 1,
                "audit key edit: with " + column + " edited in the database the grant is ignored: the run needs its own tap (" + beforeTaps.Count + " then " + afterTaps.Count + " taps, " + after.Result + ")");
        }
    }
}

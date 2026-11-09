using System.Net;
using System.Security.Cryptography;
using System.Text;

using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>
/// Phase 3, grants as authority operations, the offline lease and reconciliation: a grant is made by a human approval, used without a page
/// decision for exactly its scope while it is unexpired and unrevoked, extended, renewed and revoked by the authority (signed, idempotent, atomic),
/// and the host may use a synchronized grant while the authority cannot be reached only within a finite lease that a monotonic clock measures,
/// that nothing but a verified check-in can set, that a restart destroys, and that no grant (indefinite or not) lengthens.
/// </summary>
internal static class GrantAuthorityTests
{
    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.UtcNow;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }

    private sealed class FakeMonotonic : IMonotonicClock
    {
        private long _ms = 1_000;

        public long Milliseconds => Interlocked.Read(ref _ms);

        public void Advance(TimeSpan by) => Interlocked.Add(ref _ms, (long)by.TotalMilliseconds);
    }

    /// <summary>The authority as the host sees it, with a switch for "cannot be reached" and hooks that change or delay what comes back.</summary>
    private sealed class FlakyAuthority(LocalAuthority inner) : IAuthority
    {
        private int _reconciles;

        public bool Offline { get; set; }

        public bool BreakReconcile { get; set; }

        public Func<GrantResponse, GrantResponse>? TamperGrant { get; set; }

        public Func<ReconcileResponse, ReconcileResponse>? TamperReconcile { get; set; }

        public Action? AfterGrant { get; set; }

        public GrantResponse? LastGrant { get; private set; }

        public int Reconciles => Volatile.Read(ref _reconciles);

        private void Gate()
        {
            if (Offline)
            {
                throw new IOException("the authority cannot be reached (test)");
            }
        }

        public Task<AuthorityResponse> DecideAsync(MachineRequestEnvelope envelope, CancellationToken cancel = default)
        {
            Gate();

            return inner.DecideAsync(envelope, cancel);
        }

        public Task<byte[]> BeginEnrollmentAsync(CancellationToken cancel = default)
        {
            Gate();

            return inner.BeginEnrollmentAsync(cancel);
        }

        public Task<EnrollmentResult> EnrollAsync(EnrollmentRequest request, CancellationToken cancel = default)
        {
            Gate();

            return inner.EnrollAsync(request, cancel);
        }

        public Task<IReadOnlyList<KeyTransition>> KeyTransitionsAsync(string afterKeyFingerprint, CancellationToken cancel = default)
        {
            Gate();

            return inner.KeyTransitionsAsync(afterKeyFingerprint, cancel);
        }

        public Task<IReadOnlyList<PendingInvalidation>> PendingInvalidationsAsync(string machineFingerprint, CancellationToken cancel = default)
        {
            Gate();

            return inner.PendingInvalidationsAsync(machineFingerprint, cancel);
        }

        public Task AcknowledgeInvalidationAsync(string machineFingerprint, int revision, CancellationToken cancel = default)
        {
            Gate();

            return inner.AcknowledgeInvalidationAsync(machineFingerprint, revision, cancel);
        }

        public async Task<GrantResponse> GrantAsync(GrantEnvelope envelope, CancellationToken cancel = default)
        {
            Gate();
            GrantResponse response = await inner.GrantAsync(envelope, cancel);
            LastGrant = response;
            AfterGrant?.Invoke();

            return TamperGrant?.Invoke(response) ?? response;
        }

        public async Task<ReconcileResponse> ReconcileAsync(ReconcileEnvelope envelope, CancellationToken cancel = default)
        {
            Gate();
            if (BreakReconcile)
            {
                throw new IOException("the check-in cannot be answered (test)");
            }

            ReconcileResponse response = await inner.ReconcileAsync(envelope, cancel);
            Interlocked.Increment(ref _reconciles);

            return TamperReconcile?.Invoke(response) ?? response;
        }

        public Task<IReadOnlyList<PendingGrantEvent>> PendingGrantEventsAsync(string machineFingerprint, CancellationToken cancel = default)
        {
            Gate();

            return inner.PendingGrantEventsAsync(machineFingerprint, cancel);
        }

        public Task AcknowledgeGrantEventAsync(string machineFingerprint, long sequence, CancellationToken cancel = default)
        {
            Gate();

            return inner.AcknowledgeGrantEventAsync(machineFingerprint, sequence, cancel);
        }
    }

    /// <summary>A trusted machine, its authority behind a link that can fail, and a host with a fake monotonic clock.</summary>
    private sealed class Fixture : IDisposable
    {
        private int _ids;
        private readonly TimeSpan _lease;

        public Fixture(string parent, TimeSpan? lease = null)
        {
            _lease = lease ?? TimeSpan.FromMinutes(10);
            Clock = new TestClock();
            Machine = new TestMachine(Path.Combine(parent, "gx-" + Guid.NewGuid().ToString("N")[..8]), true, clock: Clock);
            Mono = new FakeMonotonic();

            // The state the authority checks assertions against: an admin key (the first one enrolled) and an ordinary key.
            AdminKey = TestAuthenticator.ES256();
            UserKey = TestAuthenticator.ES256();
            Db = StateDatabase.InFolder(Path.Combine(parent, "st-" + Guid.NewGuid().ToString("N")[..8]));
            TestState.Add(Db, AdminKey.Record("localhost", "admin-key") with { Created = DateTimeOffset.UtcNow });
            TestState.Add(Db, UserKey.Record("localhost", "user-key") with { Created = DateTimeOffset.UtcNow });
            Wire();
        }

        public TestAuthenticator AdminKey { get; }

        public TestAuthenticator UserKey { get; }

        public StateDatabase Db { get; }

        public TestClock Clock { get; }

        public FakeMonotonic Mono { get; }

        public TestMachine Machine { get; }

        public FlakyAuthority Link { get; private set; } = null!;

        public LaunchGate Gate { get; private set; } = null!;

        public HostAuthorization Host { get; private set; } = null!;

        public LocalAuthority Authority => Machine.Deployment.Authority;

        public AuthorityStore Store => Machine.Deployment.Store;

        public string Fingerprint => Machine.Fingerprint;

        private void Wire()
        {
            Machine.Deployment.Authority.LeaseDuration = _lease;
            Machine.Deployment.Authority.Verifier = new ManifestApprovalVerifier(Db);
            Link = new FlakyAuthority(Machine.Deployment.Authority);
            Gate = new LaunchGate();
            Host = new HostAuthorization(Link, Machine.Deployment.MachineKey, Machine.HostName, Machine.Deployment.HostConfig, Gate, Machine.Deployment.Authority.Offer, Clock, null, Mono);
        }

        /// <summary>A service restart: the same files and keys, a new authority object, a new host with nothing in memory.</summary>
        public void Restart()
        {
            Machine.Restart();
            Gate = new LaunchGate();
            Wire();
        }

        public LaunchRequest Req(string? id = null) => IdentityTests.Sample(id ?? "gr-" + Interlocked.Increment(ref _ids), Clock.GetUtcNow());

        /// <summary>A passkey assertion over <paramref name="text" /> (plus the page-issued line, as the page adds it) for the reuse <paramref name="minutes" />.</summary>
        public ApprovalEvidence Sign(TestAuthenticator who, string text, int minutes)
        {
            string nonce = "nonce-" + Guid.NewGuid().ToString("N")[..8];
            string full = text + "\n" + ApprovalSummary.IssuedLine(Clock.GetUtcNow());

            return new ApprovalEvidence(nonce, full, who.Assert(ReuseBinding.Challenge(RequestBinding.Compute(nonce, full), minutes), TestState.Origin, "localhost", TestState.NextCount()));
        }

        /// <summary>The text an approve page carries for this scope and security revision, as the program builds it.</summary>
        public static string ApproveText(string scope, int revision) => string.Join('\n', GrantEvidence.ApproveLines(revision, scope)) + "\n" + ApprovalSummary.RequestIdPrefix + scope;

        public Task<GrantApproval> Approve(string scope, int minutes, bool approve = true, LaunchRequest? request = null, TestAuthenticator? who = null, string? textScope = null, int? textRevision = null, bool noEvidence = false)
            => Host.ApproveGrantAsync(request ?? Req(), scope, () => approve
                ? ApprovalDecision.Allow("approved with passkey key-one", minutes, minutes > 0 && !noEvidence ? Sign(who ?? UserKey, ApproveText(textScope ?? scope, textRevision ?? Host.KnownRevision ?? 1), minutes) : null)
                : ApprovalDecision.Deny("test denied"), CancellationToken.None);

        public Task<GrantUse> Use(string scope, LaunchRequest? request = null) => Host.TryUseGrantAsync(request ?? Req(), scope, CancellationToken.None);

        /// <summary>An admin change as the admin command makes it: the new end fixed up front, the page text signed by an admin key.</summary>
        public GrantResponse Admin(string operation, string grantId, int? minutes = null, bool indefinite = false, string? requestId = null, TestAuthenticator? who = null, int? expectedRevision = null)
            => Authority.AdminGrant(Command(operation, grantId, minutes, indefinite, requestId, who, expectedRevision));

        public GrantAdminCommand Command(string operation, string grantId, int? minutes = null, bool indefinite = false, string? requestId = null, TestAuthenticator? who = null, int? expectedRevision = null, DateTimeOffset? endOverride = null)
        {
            GrantRecord? grant = Store.FindGrant(grantId);
            DateTimeOffset now = Clock.GetUtcNow();
            DateTimeOffset? newEnd = operation == GrantOps.Revoke || indefinite || minutes is not >= 1 or > 1440 || grant is null ? null
                : operation == GrantOps.Extend ? grant.Expires?.AddMinutes(minutes.Value) : now.AddMinutes(minutes.Value);
            newEnd = endOverride ?? newEnd;
            ApprovalEvidence? evidence = grant is null ? null : Sign(who ?? AdminKey, "Admin change to a grant\n" + GrantEvidence.AdminLines(operation, grant, grant.Revision + 1, newEnd), 0);

            return new GrantAdminCommand(requestId ?? "adm-" + Interlocked.Increment(ref _ids), operation, grantId, minutes, indefinite, expectedRevision, "test admin", newEnd, evidence);
        }

        public async Task<HostAuthorization.Reconciliation> Start() => await Host.ReconcileAsync();

        public void Dispose() => Machine.Dispose();
    }

    private static string Scope(string name) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("scope " + name)));

    private static readonly string S1 = Scope("one");
    private static readonly string S2 = Scope("two");

    public static async Task Run(Action<bool, string> check)
    {
        string parent = Path.Combine(Path.GetTempPath(), "ws-grants-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(parent);
        try
        {
            Parsing(check);
            await Lifecycle(check, parent);
            await Leases(check, parent);
            await Reconnection(check, parent);
            await Tampering(check, parent);
            await Evidence(check, parent);
            await Atomicity(check, parent);
            await AdminGate(check, parent);
            await LockDuringApproval(check, parent);
            await KeyHolding(check, parent);
            await ThroughTheService(check, parent);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            try
            {
                Directory.Delete(parent, true);
            }
            catch (IOException)
            {
                // A stray temp file is harmless.
            }
        }
    }

    // ---- command line ----

    private static void Parsing(Action<bool, string> check)
    {
        CliCommand? Parse(params string[] args) => CliArgs.Parse(args, out _);
        CliCommand.Approve? approve = Parse("approve", "--secrets", "A,B", "--reason", "why", "--", "node", "x.js") as CliCommand.Approve;
        check(approve is { Args: { Program: "node", Reason: "why" } } && approve.Args.Secrets.SequenceEqual(["A", "B"]) && approve.Args.Arguments.SequenceEqual(["x.js"]), "approve parse: the grammar of a run (secrets, reason, -- program and arguments)");
        check(Parse("approve", "--service-port", "9000", "--port", "8000", "--secrets", "A", "--reason", "r", "--", "p") is CliCommand.Approve { ServicePort: 9000, Port: 8000 }, "approve parse: --service-port and --port are accepted as for a run");
        check(CliArgs.Parse(["approve", "--secrets", "A", "--", "p"], out string noReason) is null && noReason.Contains("--reason", StringComparison.Ordinal), "approve parse: --reason is required as for a run (" + noReason + ")");
        check(CliArgs.Parse(["approve", "--list"], out string notRun) is null && notRun.Contains("approve takes", StringComparison.Ordinal), "approve parse: only the arguments of a run (" + notRun + ")");
        check(Parse("approve") is CliCommand.Help && Parse("approve", "--help") is CliCommand.Help, "approve parse: nothing to approve shows the help; --help still works");
        check(Parse("approve", "-f", "a.env", "--secrets", "A", "--reason", "r", "--", "p") is CliCommand.Approve { Args.EnvFiles.Count: 1 }, "approve parse: -f works as for a run");
        check(!CliArgs.NeedsTerminal(approve!), "approve: needs no terminal of its own (the approval is on the page, as for a run)");
    }

    // ---- grant lifecycle ----

    private static async Task Lifecycle(Action<bool, string> check, string parent)
    {
        using Fixture fx = new(parent);
        check(await fx.Start() == HostAuthorization.Reconciliation.Reconciled && fx.Host.Lease.IsValid && fx.Host.Lease.Remaining == TimeSpan.FromMinutes(10), "startup: the host checks in with the authority and gets the lease the authority set (10 minutes)");
        DateTimeOffset t0 = fx.Clock.GetUtcNow();
        int machineRevision = fx.Store.Find(fx.Fingerprint)!.SecurityRevision;

        // Creation by a human approval.
        GrantApproval none = await fx.Approve(S1, 0);
        check(!none.Granted && fx.Store.Grants().Count == 0 && none.Message.Contains("no grant time", StringComparison.Ordinal), "create: an approval without a chosen time makes no grant (" + none.Message + ")");
        GrantApproval refused = await fx.Approve(S1, 60, approve: false);
        check(!refused.Granted && fx.Store.Grants().Count == 0 && refused.Message.Contains("did not approve", StringComparison.Ordinal) && fx.Host.SyncedGrants.Count == 0, "create: a refused approval makes no grant (" + refused.Message + ")");
        GrantApproval made = await fx.Approve(S1, 60);
        GrantRecord grant = fx.Store.FindGrant(made.GrantId ?? "")!;
        check(made.Granted && made.Expires == t0.AddMinutes(60) && grant is { Status: "active", Revision: 1, ScopeKey: var key } && key == S1 && grant.Expires == t0.AddMinutes(60) && grant.Fingerprint == fx.Fingerprint, "create: the approval makes a grant for the scope, ending 60 minutes later");
        check(fx.Store.Find(fx.Fingerprint)!.SecurityRevision == machineRevision && fx.Store.PendingInvalidations(fx.Fingerprint).Count == 0, "create: the machine's security revision is untouched");
        check(fx.Store.Audit().Any(entry => entry.Event == "grant-created" && entry.Detail.Contains(grant.Id, StringComparison.Ordinal) && entry.Detail.Contains("60 min", StringComparison.Ordinal)), "create: the authority audit records who made it and for how long");
        check(fx.Host.SyncedGrants.Count == 1 && fx.Host.SyncedGrants[0].GrantId == grant.Id, "create: the host remembers the grant as synchronized");
        check(fx.Store.GetProcessedGrant(fx.Host.SyncedGrants[0].GrantId) is null && fx.Store.Grants().Count == 1, "create: the grant id is not a request id; one grant exists");

        // Use: exact scope only.
        GrantUse use = await fx.Use(S1);
        check(use is { Kind: GrantUseKind.Granted, Offline: false } && use.GrantId == grant.Id, "use: a request in the scope of the grant is covered (online, answered by the authority)");
        check((await fx.Use(S2)).Kind == GrantUseKind.NoGrant && (await fx.Use(Scope("three"))).Kind == GrantUseKind.NoGrant, "scope mismatch: another scope is not covered");
        check(fx.Store.Audit().Count(entry => entry.Event == "grant-use") == 1, "use: the authority audit records the use of the grant (and not the questions that found none)");

        // The same scope approved again updates the grant (one grant, a new end and revision).
        GrantApproval again = await fx.Approve(S1, 10);
        GrantRecord updated = fx.Store.FindGrant(grant.Id)!;
        check(again.Granted && again.GrantId == grant.Id && updated is { Revision: 2 } && updated.Expires == t0.AddMinutes(10) && fx.Store.Grants().Count == 1 && fx.Store.Audit().Any(entry => entry.Event == "grant-updated"), "update: approving the same scope again updates the one grant (new end, revision 2)");

        // Expiry: the grant ends by itself; the request then needs the ordinary approval.
        fx.Clock.Advance(TimeSpan.FromMinutes(11));
        check((await fx.Use(S1)).Kind == GrantUseKind.NoGrant && fx.Host.SyncedGrants.Count == 0, "expiry: after its end the grant covers nothing and the host forgets it");
        GrantResponse extendExpired = fx.Admin(GrantOps.Extend, grant.Id, 30);
        check(extendExpired is { Outcome: GrantOps.Denied, ReasonCode: GrantReasons.Expired }, "extend: an ended grant cannot be extended (renew it)");
        GrantResponse renewed = fx.Admin(GrantOps.Renew, grant.Id, 20);
        GrantRecord afterRenew = fx.Store.FindGrant(grant.Id)!;
        check(renewed is { Outcome: GrantOps.Renewed } && renewed.Verify(fx.Machine.Deployment.Keys.CurrentRecord().PublicKey) && afterRenew.Expires == fx.Clock.GetUtcNow().AddMinutes(20) && afterRenew.Revision == 3, "renew: an ended grant gets a new end counted from now (signed answer, revision 3)");
        check((await fx.Use(S1)).Kind == GrantUseKind.Granted, "renew: the renewed grant covers the scope again");
        check(fx.Admin(GrantOps.Renew, grant.Id, 5) is { Outcome: GrantOps.Denied, ReasonCode: GrantReasons.NotExpired }, "renew: a grant that has not ended is not renewed (extend it)");

        // Extension: counted from the present end; no revision of the machine, no lease.
        TimeSpan leaseBefore = fx.Host.Lease.Remaining;
        DateTimeOffset endBefore = afterRenew.Expires!.Value;
        GrantResponse extended = fx.Admin(GrantOps.Extend, grant.Id, 30);
        check(extended is { Outcome: GrantOps.Extended } && fx.Store.FindGrant(grant.Id) is { Revision: 4 } now4 && now4.Expires == endBefore.AddMinutes(30), "extend: an active grant ends 30 minutes later than it did (revision 4)");
        check(fx.Store.Find(fx.Fingerprint)!.SecurityRevision == machineRevision && fx.Host.Lease.Remaining == leaseBefore && fx.Host.Lease.Duration == TimeSpan.FromMinutes(10), "extend: neither the machine's revision nor the offline lease changed");
        check(fx.Admin(GrantOps.Extend, grant.Id, null, false) is { Outcome: GrantOps.Denied, ReasonCode: GrantReasons.NoTime } && fx.Admin(GrantOps.Extend, grant.Id, 5000) is { ReasonCode: GrantReasons.NoTime } && fx.Admin(GrantOps.Extend, "g-nothere", 5) is { ReasonCode: GrantReasons.NotFound }, "extend: a time from 1 to 1440 minutes is required and the grant must exist");
        check(fx.Authority.AdminGrant(new GrantAdminCommand("adm-stale", GrantOps.Extend, grant.Id, 5, false, 1, "test admin")) is { ReasonCode: GrantReasons.RevisionChanged }, "extend: a grant that changed since the page showed it is refused");

        // Revocation: the authority ends it at once; a connected host applies it at once.
        int gateBefore = fx.Gate.Revision;
        GrantResponse revoked = fx.Admin(GrantOps.Revoke, grant.Id, requestId: "adm-revoke-1");
        check(revoked is { Outcome: GrantOps.Revoked } && fx.Store.FindGrant(grant.Id) is { Status: "revoked", Revoked: not null }, "revoke: the grant is revoked (signed answer)");
        check((await fx.Use(S1)).Kind == GrantUseKind.NoGrant && fx.Store.PendingGrantEvents(fx.Fingerprint).Count == 1, "revoke: nothing is covered any more, and the notice for the host is queued");
        await fx.Host.PumpAsync();
        check(fx.Host.SyncedGrants.Count == 0 && fx.Gate.Revision > gateBefore && fx.Store.PendingGrantEvents(fx.Fingerprint).Count == 0 && fx.Store.Audit().Any(entry => entry.Event == "grant-revocation-acknowledged"), "revoke: the connected host drops the grant, invalidates the gate (a launch that has not committed is cancelled) and acknowledges after cleaning up");
        GrantResponse retried = fx.Admin(GrantOps.Revoke, grant.Id, requestId: "adm-revoke-1");
        check(retried.ToJson() == revoked.ToJson() && fx.Store.Audit().Count(entry => entry.Event == "grant-revoked") == 1 && fx.Store.FindGrant(grant.Id)!.Revision == 5, "idempotent: a retry of the same request id returns the committed answer and does nothing twice");
        check(fx.Admin(GrantOps.Revoke, grant.Id, requestId: "adm-revoke-1") is { Outcome: GrantOps.Revoked } && fx.Authority.AdminGrant(new GrantAdminCommand("adm-revoke-1", GrantOps.Extend, grant.Id, 5, false, null, "test admin")) is { ReasonCode: ReasonCodes.RequestIdReused }, "idempotent: the same request id for another change is refused");
        check(fx.Admin(GrantOps.Revoke, grant.Id) is { ReasonCode: GrantReasons.NotActive } && fx.Admin(GrantOps.Renew, grant.Id, 5) is { ReasonCode: GrantReasons.NotActive }, "revoke: a revoked grant cannot be changed or renewed; a new approval makes a new grant");
        GrantApproval fresh = await fx.Approve(S1, 10);
        check(fresh.Granted && fresh.GrantId != grant.Id, "revoke: approving again after a revocation makes a new grant");

        // A machine that is no longer Trusted: its grants end with the revision, and nothing is covered.
        fx.Store.Disable(fx.Fingerprint, "test");
        GrantUse afterDisable = await fx.Use(S1);
        check(afterDisable.Kind != GrantUseKind.Granted && fx.Store.FindGrant(fresh.GrantId!)!.Status == "invalidated", "disable (" + afterDisable.Kind + "): the grants end with the security revision and a disabled machine is covered by nothing");
    }

    // ---- the offline lease ----

    private static async Task Leases(Action<bool, string> check, string parent)
    {
        // Within the lease an offline host uses a synchronized grant; after it, nothing.
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            GrantApproval made = await fx.Approve(S1, 600);
            fx.Link.Offline = true;
            fx.Mono.Advance(TimeSpan.FromMinutes(9));
            GrantUse within = await fx.Use(S1);
            check(within is { Kind: GrantUseKind.Granted, Offline: true } && within.GrantId == made.GrantId, "lease: while the authority cannot be reached, a synchronized grant counts within the lease (9 of 10 minutes)");
            check((await fx.Use(S2)).Kind == GrantUseKind.NoGrant, "lease: offline, a scope with no synchronized grant is not covered");
            fx.Mono.Advance(TimeSpan.FromMinutes(2));
            check((await fx.Use(S1)).Kind == GrantUseKind.NoGrant && !fx.Host.Lease.IsValid && fx.Host.Lease.Remaining == TimeSpan.Zero, "lease expiry: after the lease the same grant (still unexpired) covers nothing; fails closed");
            GrantApproval offlineApproval = await fx.Approve(Scope("new"), 10);
            check(!offlineApproval.Granted && offlineApproval.Message.Contains("authority", StringComparison.Ordinal) && fx.Store.Grants().Count == 1, "offline: no new approval is made while disconnected (" + offlineApproval.Message + ")");
            fx.Link.Offline = false;
            check((await fx.Use(S1)).Kind == GrantUseKind.Granted && fx.Host.Lease.IsValid && fx.Host.Lease.Remaining == TimeSpan.FromMinutes(10), "lease: reconnected, the authority answers again and a new lease starts (the same code path as local mode)");
        }

        // The wall clock does not move the lease.
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            GrantApproval made = await fx.Approve(S1, 600);
            fx.Admin(GrantOps.Extend, made.GrantId!, null, true);
            await fx.Use(S1);
            fx.Link.Offline = true;
            fx.Clock.Advance(TimeSpan.FromDays(30));
            fx.Mono.Advance(TimeSpan.FromMinutes(1));
            check((await fx.Use(S1)) is { Kind: GrantUseKind.Granted, Offline: true }, "wall clock: a date 30 days ahead does not end the lease (the monotonic clock says 1 minute) for an indefinite grant");
            fx.Clock.Advance(TimeSpan.FromDays(-40));
            fx.Mono.Advance(TimeSpan.FromMinutes(10));
            check((await fx.Use(S1)).Kind == GrantUseKind.NoGrant, "wall clock: a date set back does not bring the expired lease back");
        }

        using (Fixture fx = new(parent))
        {
            await fx.Start();
            await fx.Approve(S1, 30);
            fx.Link.Offline = true;
            fx.Clock.Advance(TimeSpan.FromMinutes(40));
            check((await fx.Use(S1)).Kind == GrantUseKind.NoGrant, "grant expiry offline: a grant past its own end is not used even inside the lease");
            fx.Clock.Advance(TimeSpan.FromDays(-5));
            fx.Mono.Advance(TimeSpan.FromMinutes(1));
            check((await fx.Use(S1)).Kind == GrantUseKind.Granted, "grant expiry offline: a date set back can make a grant look current, but only inside the lease (bounded by it)");
            fx.Mono.Advance(TimeSpan.FromMinutes(10));
            check((await fx.Use(S1)).Kind == GrantUseKind.NoGrant, "grant expiry offline: and the lease ends that, whatever the date says");
        }

        // An indefinite grant never makes the lease longer.
        using (Fixture fx = new(parent, TimeSpan.FromMinutes(10)))
        {
            await fx.Start();
            GrantApproval made = await fx.Approve(S1, 10);
            TimeSpan before = fx.Host.Lease.Remaining;
            GrantResponse forever = fx.Admin(GrantOps.Extend, made.GrantId!, null, true);
            check(forever is { Outcome: GrantOps.Extended, Indefinite: true, GrantExpires: null } && fx.Store.FindGrant(made.GrantId!)!.Expires is null, "indefinite: a grant can be extended to have no end (signed answer says so)");
            GrantUse online = await fx.Use(S1);
            check(online.Kind == GrantUseKind.Granted && fx.Host.SyncedGrants[0].Expires is null && fx.Host.Lease.Remaining == before && fx.Host.Lease.Duration == TimeSpan.FromMinutes(10), "indefinite: using it online leaves the lease exactly as it was (10 minutes, not longer)");
            fx.Link.Offline = true;
            fx.Mono.Advance(TimeSpan.FromMinutes(9));
            check((await fx.Use(S1)).Offline, "indefinite: offline it works within the lease");
            fx.Mono.Advance(TimeSpan.FromMinutes(2));
            check((await fx.Use(S1)).Kind == GrantUseKind.NoGrant, "indefinite: and not one minute beyond it; an indefinite grant does not make an indefinite lease");
        }

        // No valid lease, no use of secrets.
        using (Fixture fx = new(parent))
        {
            fx.Link.BreakReconcile = true;
            await fx.Approve(S1, 60);
            GrantUse noLease = await fx.Use(S1);
            check(noLease.Kind == GrantUseKind.Denied && noLease.Message.Contains("lease", StringComparison.Ordinal) && !fx.Host.Lease.IsValid, "no lease: the authority answers the grant question but cannot give a lease: the host refuses the use (" + noLease.Message + ")");
            int asked = 0;
            AuthorizationOutcome approved = await fx.Host.AuthorizeAsync(fx.Req(), () =>
            {
                asked++;

                return ApprovalDecision.Allow();
            }, CancellationToken.None);
            check(!approved.Decision.Approved && approved.Code == "no-lease" && asked == 1 && approved.AuthorityMessage!.Contains("lease", StringComparison.Ordinal), "no lease: even an approval by the person does not release anything without a lease (" + approved.AuthorityMessage + ")");
            fx.Link.BreakReconcile = false;
            AuthorizationOutcome ok = await fx.Host.AuthorizeAsync(fx.Req(), () => ApprovalDecision.Allow(), CancellationToken.None);
            check(ok.Decision.Approved && fx.Host.Lease.IsValid, "no lease: once the authority gives one, the approval stands");
        }

        // A restart destroys the lease and what was synchronized.
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            await fx.Approve(S1, 600);
            check(fx.Host.Lease.IsValid && fx.Host.SyncedGrants.Count == 1, "restart: before it, a lease and a synchronized grant");
            fx.Restart();
            check(!fx.Host.Lease.IsValid && fx.Host.SyncedGrants.Count == 0 && fx.Host.KnownRevision is null, "restart: the new service has no lease, no synchronized grant and has applied no revision");
            fx.Link.Offline = true;
            check((await fx.Use(S1)).Kind == GrantUseKind.NoGrant, "restart: offline after a restart nothing is covered (fresh reconciliation is needed first)");
            fx.Link.Offline = false;
            check(await fx.Start() == HostAuthorization.Reconciliation.Reconciled && fx.Host.Lease.IsValid && (await fx.Use(S1)).Kind == GrantUseKind.Granted, "restart: after reconciling, the grant (kept by the authority) is usable again");
        }

        // The authority is the only source of the lease: a changed answer is not accepted.
        using (Fixture fx = new(parent))
        {
            fx.Link.TamperReconcile = r => r with { LeaseSeconds = 100_000 };
            check(await fx.Start() == HostAuthorization.Reconciliation.Unverified && !fx.Host.Lease.IsValid, "lease: a check-in answer whose lease was changed on the way does not verify and gives no lease");
            fx.Link.TamperReconcile = null;
            await fx.Start();
            ReconcileResponse? captured = null;
            fx.Link.TamperReconcile = r =>
            {
                captured = r;

                return r;
            };
            await fx.Host.ReconcileAsync();
            fx.Mono.Advance(TimeSpan.FromMinutes(11));
            check(!fx.Host.Lease.IsValid, "lease: it runs out on the monotonic clock while nobody renews it");
            fx.Link.TamperReconcile = _ => captured!;
            check(await fx.Host.ReconcileAsync() == HostAuthorization.Reconciliation.Unverified && !fx.Host.Lease.IsValid, "lease: an old check-in answer replayed later gives no lease (another request id)");
        }

        // A machine that is not Trusted gets no lease.
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            fx.Store.Disable(fx.Fingerprint, "test");
            await fx.Host.PumpAsync();
            check(!fx.Host.Lease.IsValid && fx.Host.KnownRevision == 2, "disable: the connected host applies it at once: the lease is destroyed and the revision applied");
            fx.Store.Enable(fx.Fingerprint, "test");
            await fx.Host.ReconcileAsync();
            check(fx.Host.Lease.IsValid && fx.Host.SyncedGrants.Count == 0, "enable: it starts clean: a new lease, no grants");
        }
    }

    // ---- reconnection ----

    private static async Task Reconnection(Action<bool, string> check, string parent)
    {
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            GrantApproval made = await fx.Approve(S1, 600);
            fx.Link.Offline = true;

            // The authority acts while the host cannot hear it.
            fx.Store.Disable(fx.Fingerprint, "test");
            fx.Store.Enable(fx.Fingerprint, "test");
            check((await fx.Use(S1)) is { Kind: GrantUseKind.Granted, Offline: true }, "offline: a host cannot benefit from, or be stopped by, a change it has not received: within its lease it still uses what it had");

            fx.Link.Offline = false;
            int gate = fx.Gate.Revision;
            await fx.Host.PumpAsync();
            check(fx.Host.KnownRevision == 2 && fx.Gate.Revision > gate && fx.Host.SyncedGrants.Count == 0 && fx.Host.Lease.IsValid, "reconnect: the host applies the missed revision (cleans up, invalidates the gate) and then holds a new lease");
            check((await fx.Use(S1)).Kind == GrantUseKind.NoGrant && fx.Store.FindGrant(made.GrantId!)!.Status == "invalidated", "reconnect: the old grant was invalidated by the revision and is not restored");
        }

        using (Fixture fx = new(parent))
        {
            await fx.Start();
            GrantApproval made = await fx.Approve(S1, 10);
            fx.Link.Offline = true;
            fx.Admin(GrantOps.Extend, made.GrantId!, 120);
            fx.Clock.Advance(TimeSpan.FromMinutes(11));
            check((await fx.Use(S1)).Kind == GrantUseKind.NoGrant, "extension offline: the host cannot use an extension it has not received: its synchronized grant ends where it ended");
            fx.Link.Offline = false;
            check((await fx.Use(S1)).Kind == GrantUseKind.Granted && fx.Host.SyncedGrants[0].Revision == 2, "extension: once reconnected the host gets the extension (the authority answers; revision 2)");
        }

        // Revocation reaches a connected host at once, and a launch that has not committed is cancelled.
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            GrantApproval made = await fx.Approve(S1, 60);
            int begun = fx.Gate.Revision;
            fx.Admin(GrantOps.Revoke, made.GrantId!);
            await fx.Host.PumpAsync();
            bool committed = fx.Gate.TryCommit(begun, CancellationToken.None, () => { });
            check(!committed, "revoke: a launch that began before the revocation does not commit (the gate was invalidated)");
        }

        // Startup: the host that cannot reach its authority holds no lease; one that can, does.
        using (Fixture fx = new(parent))
        {
            fx.Link.Offline = true;
            check(await fx.Start() == HostAuthorization.Reconciliation.Unreachable && !fx.Host.Lease.IsValid && fx.Host.KnownRevision is null, "startup: an unreachable authority leaves the host with no lease and no applied revision");
            check((await fx.Use(S1)).Kind == GrantUseKind.NoGrant, "startup: nothing is covered before the first reconciliation");
            fx.Link.Offline = false;
            check(await fx.Start() == HostAuthorization.Reconciliation.Reconciled && fx.Host.KnownRevision == 1 && fx.Host.Lease.IsValid, "startup: once the authority answers the host knows the machine status and revision and holds a lease");
        }

        using (Fixture fx = new(parent))
        {
            fx.Store.Disable(fx.Fingerprint, "test");
            check(await fx.Start() == HostAuthorization.Reconciliation.Reconciled && !fx.Host.Lease.IsValid && fx.Host.KnownRevision == 2, "startup: a Disabled machine learns its revision and gets no lease");
        }
    }

    // ---- tampering and replay ----

    private static async Task Tampering(Action<bool, string> check, string parent)
    {
        using Fixture fx = new(parent);
        await fx.Start();
        GrantApproval made = await fx.Approve(S1, 60);
        string fingerprint = fx.Fingerprint;
        ISigningKey machineKey = fx.Machine.Deployment.MachineKey;

        // Envelopes (host to authority).
        LaunchRequest request = fx.Req("tamper-env");
        GrantEnvelope envelope = GrantEnvelope.Create(GrantOps.Use, request, S1, fx.Machine.HostName, machineKey);
        check(envelope.Verify(machineKey.PublicKey) && !(envelope with { ScopeKey = S2 }).Verify(machineKey.PublicKey) && !(envelope with { Operation = GrantOps.Approve }).Verify(machineKey.PublicKey) && !(envelope with { HostName = "other" }).Verify(machineKey.PublicKey)
            && !(envelope with { RequestDigest = new string('A', 64) }).Verify(machineKey.PublicKey) && !(envelope with { Request = request with { Reason = "changed" } }).Verify(machineKey.PublicKey) && !(envelope with { MachineFingerprint = new string('B', 64) }).Verify(machineKey.PublicKey),
            "envelope: the signature covers the operation, scope key, host name, digest, request and fingerprint");
        byte[] flipped = [.. envelope.Signature];
        flipped[3] ^= 1;
        check((await fx.Authority.GrantAsync(envelope with { Signature = flipped })) is { Outcome: GrantOps.Denied, ReasonCode: ReasonCodes.BadSignature }, "authority: a damaged envelope signature is refused");
        check((await fx.Authority.GrantAsync(envelope with { ScopeKey = S2 })) is { Outcome: GrantOps.Denied, ReasonCode: ReasonCodes.BadSignature }, "authority: a scope key changed on the way is refused (signature)");
        using SoftwareSigningKey stranger = new();
        check((await fx.Authority.GrantAsync(GrantEnvelope.Create(GrantOps.Use, fx.Req("tamper-stranger"), S1, fx.Machine.HostName, stranger))) is { Outcome: GrantOps.Denied, ReasonCode: ReasonCodes.UnknownMachine }, "authority: an envelope from a machine it does not know gets nothing");
        check((await fx.Authority.GrantAsync(GrantEnvelope.Create(GrantOps.Use, fx.Req("tamper-bad-scope"), "nothex", fx.Machine.HostName, machineKey))) is { ReasonCode: GrantReasons.BadScope } && (await fx.Authority.GrantAsync(GrantEnvelope.Create("delete", fx.Req("tamper-op"), S1, fx.Machine.HostName, machineKey))) is { ReasonCode: GrantReasons.BadOperation }, "authority: a scope key that is not 64 hex digits and an unknown operation are refused");
        check((await fx.Authority.GrantAsync(GrantEnvelope.Create(GrantOps.Use, fx.Req("tamper-host"), S1, "another-host", machineKey))) is { ReasonCode: ReasonCodes.HostNameMismatch }, "authority: a host name that is not the bound one gets nothing");
        LaunchRequest expired = fx.Req("tamper-expired") with { Created = fx.Clock.GetUtcNow().AddHours(-2), Expires = fx.Clock.GetUtcNow().AddHours(-1) };
        check((await fx.Authority.GrantAsync(GrantEnvelope.Create(GrantOps.Use, expired, S1, fx.Machine.HostName, machineKey))) is { ReasonCode: ReasonCodes.InvalidRequest }, "authority: an expired request gets nothing");

        // A use is a read of the present state: evaluated each time, never stored, so a replay cannot outlive a revocation (L2) and nothing grows with use (L6).
        GrantApproval replayGrant = await fx.Approve(Scope("replay"), 60);
        GrantEnvelope first = GrantEnvelope.Create(GrantOps.Use, fx.Req("replay-1"), Scope("replay"), fx.Machine.HostName, machineKey);
        GrantResponse one = await fx.Authority.GrantAsync(first);
        GrantResponse two = await fx.Authority.GrantAsync(first);
        check(one.Outcome == GrantOps.Granted && two.Outcome == GrantOps.Granted && fx.Store.Audit().Count(entry => entry.Event == "grant-use" && entry.RequestId == "replay-1") >= 1 && fx.Store.GetProcessedGrant("replay-1") is null, "replay: a use is evaluated each time (audited, never stored)");
        fx.Admin(GrantOps.Revoke, replayGrant.GrantId!);
        GrantResponse replayed = await fx.Authority.GrantAsync(first);
        check(replayed.Outcome == GrantOps.None && fx.Store.GetProcessedGrant("replay-1") is null, "replay: the same envelope after a revocation is not granted (no stored answer is replayed)");

        // Responses (authority to host).
        fx.Link.TamperGrant = r => r with { Signature = [.. r.Signature.Select((b, i) => i == 0 ? (byte)(b ^ 0x80) : b)] };
        check((await fx.Use(S1)) is { Kind: GrantUseKind.Denied }, "response: a damaged signature is refused");
        fx.Link.TamperGrant = r => r with { Outcome = GrantOps.Granted, GrantId = "g-forged", ScopeKey = S2, ReasonCode = GrantReasons.Ok };
        GrantUse forged = await fx.Use(S2);
        check(forged.Kind == GrantUseKind.Denied && fx.Host.SyncedGrants.All(item => item.GrantId != "g-forged"), "response: 'no grant' changed into 'granted' on the way is refused and remembers nothing");
        fx.Link.TamperGrant = null;
        GrantUse genuine = await fx.Use(S1);
        GrantResponse captured = fx.Link.LastGrant!;
        fx.Link.TamperGrant = _ => captured;
        check((await fx.Use(S1)).Kind == GrantUseKind.Denied, "response: a genuine answer replayed for another request is refused (request id)");
        fx.Link.TamperGrant = null;

        using SoftwareSigningKey other2 = new();
        fx.Link.TamperGrant = r => GrantResponse.Create(r.RequestId, r.RequestDigest, r.MachineFingerprint, r.Operation, r.Outcome, r.ReasonCode, new GrantInfo(r.GrantId, r.ScopeKey, r.GrantRevision, r.GrantExpires), r.SecurityRevision, r.Issued, r.Expires, other2);
        check((await fx.Use(S1)).Kind == GrantUseKind.Denied, "response: an answer signed by a key that is not the pinned one is refused");
        fx.Link.TamperGrant = null;

        fx.Link.AfterGrant = () => fx.Clock.Advance(TimeSpan.FromMinutes(2));
        check((await fx.Use(S1)).Kind == GrantUseKind.Denied, "response: an answer that arrives after its validity (60 s) is refused");
        fx.Link.AfterGrant = null;

        fx.Link.TamperGrant = r => r with { Operation = GrantOps.Approve };
        check((await fx.Use(S1)).Kind == GrantUseKind.Denied, "response: an answer for another operation is refused");
        fx.Link.TamperGrant = null;

        // An approval answer that does not verify makes nothing on the host.
        fx.Link.TamperGrant = r => r with { GrantId = "g-other" };
        GrantApproval badApproval = await fx.Approve(Scope("tampered approval"), 10);
        check(!badApproval.Granted && fx.Host.SyncedGrants.All(item => item.GrantId != "g-other"), "response: an approval answer that was changed on the way is not accepted by the host");
        fx.Link.TamperGrant = null;
        check(genuine.Kind == GrantUseKind.Granted && made.Granted && fingerprint == fx.Fingerprint, "response: and the untouched answers worked throughout");

        // A grant is only for its machine: another machine's use of the same scope is not covered.
        string folder = Path.Combine(parent, "second-" + Guid.NewGuid().ToString("N")[..6]);
        using TestMachine second = new(folder, clock: fx.Clock);
        GrantResponse foreign = await second.Deployment.Authority.GrantAsync(GrantEnvelope.Create(GrantOps.Use, fx.Req("second-1"), S1, second.HostName, second.MachineKey));
        check(foreign.Outcome == GrantOps.Denied || foreign.Outcome == GrantOps.None, "machines: a grant of one machine does not cover another (no grant)");
    }

    // ---- atomic operations ----

    private static async Task Atomicity(Action<bool, string> check, string parent)
    {
        using Fixture fx = new(parent);
        await fx.Start();
        AuthorityStore store = fx.Store;
        (int Grants, int Audit, int Processed, int Events) Snapshot() => (store.Grants().Count, store.Audit().Count, CountProcessed(store, "p-"), store.PendingGrantEvents(fx.Fingerprint).Count);

        // Creation.
        foreach (string point in new[] { "after-grant", "after-result", "before-commit" })
        {
            (int, int, int, int) before = Snapshot();
            store.Fault = name =>
            {
                if (name == point)
                {
                    throw new InvalidOperationException("fault at " + point);
                }
            };
            GrantApproval result = await fx.Approve(S1, 30, request: fx.Req("p-" + point));
            store.Fault = null;
            check(!result.Granted && Snapshot() == before, "atomic: a fault at " + point + " while a grant is made leaves no grant, no stored answer and no audit row");
        }

        GrantApproval made = await fx.Approve(S1, 30, request: fx.Req("p-ok"));
        check(made.Granted && store.GetProcessedGrant("p-ok") is not null, "atomic: the same operations work once the fault is gone");

        // Revocation.
        foreach (string point in new[] { "after-grant", "after-event", "after-result", "before-commit" })
        {
            GrantRecord beforeGrant = store.FindGrant(made.GrantId!)!;
            int audits = store.Audit().Count;
            int events = store.PendingGrantEvents(fx.Fingerprint).Count;
            store.Fault = name =>
            {
                if (name == point)
                {
                    throw new InvalidOperationException("fault at " + point);
                }
            };
            bool threw = false;
            try
            {
                fx.Admin(GrantOps.Revoke, made.GrantId!, requestId: "adm-fault-" + point);
            }
            catch (Exception)
            {
                threw = true;
            }

            store.Fault = null;
            check(threw && store.FindGrant(made.GrantId!) == beforeGrant && store.Audit().Count == audits && store.PendingGrantEvents(fx.Fingerprint).Count == events && store.GetProcessedGrant("adm-fault-" + point) is null, "atomic: a fault at " + point + " during a revocation leaves the grant active, no notice, no audit row and no stored answer");
        }

        // Concurrency: two approvals of the same scope at once leave one grant.
        Fixture other = fx;
        GrantApproval[] both = await Task.WhenAll(other.Approve(Scope("race"), 10), other.Approve(Scope("race"), 10));
        check(both.All(item => item.Granted) && store.Grants().Count(grant => grant.ScopeKey == Scope("race")) == 1, "atomic: two approvals of one scope at the same time leave exactly one grant");

        // The schema migration from Phase 2 (grants were never written there).
        string folder = Path.Combine(parent, "migrate-" + Guid.NewGuid().ToString("N")[..6]);
        using (TestMachine machine = new(folder))
        {
            string path = machine.Deployment.Store.FilePath;
            SqliteConnection.ClearAllPools();
            using (SqliteConnection connection = new("Data Source=" + path + ";Pooling=False"))
            {
                connection.Open();
                using SqliteCommand command = connection.CreateCommand();
                command.CommandText = "DROP TABLE grants; DROP TABLE grant_events; DROP TABLE processed_grant_requests;"
                    + "CREATE TABLE grants (id TEXT PRIMARY KEY NOT NULL, fingerprint TEXT NOT NULL, scope_digest TEXT NOT NULL, created TEXT NOT NULL, expires TEXT, security_revision INTEGER NOT NULL, status TEXT NOT NULL);"
                    + "UPDATE schema_version SET version = 1;";
                command.ExecuteNonQuery();
            }

            AuthorityStore migrated = AuthorityStore.InFolder(folder);
            check(migrated.Machines().Count == 1 && migrated.Grants().Count == 0 && migrated.PendingGrantEvents(machine.Fingerprint).Count == 0, "migration: a Phase 2 authority.db is migrated (machines kept, the empty grants table replaced)");
            check(Version(path) == AuthorityStore.SchemaVersion, "migration: the schema version is now " + AuthorityStore.SchemaVersion);
            migrated.AddGrant("m1", machine.Fingerprint, S1, null);
            check(migrated.Grants().Count == 1 && migrated.ActiveGrants(machine.Fingerprint).SequenceEqual(["m1"]), "migration: the new grants table works");
        }

        // Schema 2 (grants without approval evidence) is migrated too: its rows are dropped, as they would be ignored anyway.
        string folder2 = Path.Combine(parent, "migrate2-" + Guid.NewGuid().ToString("N")[..6]);
        using (TestMachine machine = new(folder2))
        {
            string path = machine.Deployment.Store.FilePath;
            SqliteConnection.ClearAllPools();
            using (SqliteConnection connection = new("Data Source=" + path + ";Pooling=False"))
            {
                connection.Open();
                using SqliteCommand command = connection.CreateCommand();
                command.CommandText = "DROP TABLE grants;"
                    + "CREATE TABLE grants (id TEXT PRIMARY KEY NOT NULL, fingerprint TEXT NOT NULL, scope_key TEXT NOT NULL, program TEXT NOT NULL, working_directory TEXT NOT NULL, secret_names TEXT NOT NULL, created TEXT NOT NULL, updated TEXT NOT NULL, expires TEXT, grant_revision INTEGER NOT NULL, security_revision INTEGER NOT NULL, status TEXT NOT NULL, approved_by TEXT NOT NULL, revoked TEXT);"
                    + "INSERT INTO grants VALUES ('old', '" + machine.Fingerprint + "', '" + S1 + "', 'p', 'd', 'N', '2026-01-01T00:00:00.0000000Z', '2026-01-01T00:00:00.0000000Z', NULL, 1, 1, 'active', 'x', NULL);"
                    + "UPDATE schema_version SET version = 2;";
                command.ExecuteNonQuery();
            }

            AuthorityStore migrated = AuthorityStore.InFolder(folder2);
            check(migrated.Grants().Count == 0 && Version(path) == AuthorityStore.SchemaVersion && migrated.Machines().Count == 1, "migration: a schema 2 authority.db is migrated (machines kept, grants without evidence dropped)");
        }
    }

    private static long Version(string path)
    {
        SqliteConnection.ClearAllPools();
        using SqliteConnection connection = new("Data Source=" + path + ";Pooling=False");
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT version FROM schema_version";

        return Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
    }

    private static int CountProcessed(AuthorityStore store, string prefix)
    {
        int count = 0;
        foreach (string suffix in new[] { "after-grant", "after-result", "before-commit", "ok" })
        {
            count += store.GetProcessedGrant(prefix + suffix) is null ? 0 : 1;
        }

        return count;
    }

    // ---- grant scope, evidence and the held key's binding (security review H1, H2, L1, L5, L6) ----

    /// <summary>Writes authority.db behind the program's back, as another process of the same user could.</summary>
    private static void Sql(Fixture fx, string text, params (string Name, object? Value)[] args)
    {
        SqliteConnection.ClearAllPools();
        using SqliteConnection connection = new("Data Source=" + fx.Store.FilePath + ";Pooling=False");
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = text;
        foreach ((string name, object? value) in args)
        {
            command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }

        command.ExecuteNonQuery();
        SqliteConnection.ClearAllPools();
    }

    private static async Task Evidence(Action<bool, string> check, string parent)
    {
        // H1: the scope of a grant covers every argument (inline code too), the machine and the request fingerprint; not the reason.
        string fp = new('A', 64);
        string key = new('B', 64);
        string baseScope = GrantEvidence.Scope(fp, key, ["-c", "print(1)"]);
        check(GrantOps.IsScopeKey(baseScope) && baseScope == GrantEvidence.Scope(fp, key, ["-c", "print(1)"]), "scope: a grant scope is a 64-digit key and the same inputs give the same key");
        check(baseScope != GrantEvidence.Scope(fp, key, ["-c", "print(2)"]) && baseScope != GrantEvidence.Scope(fp, key, ["-c"]) && baseScope != GrantEvidence.Scope(fp, key, ["-c", "print(1)", "x"]), "scope: other inline code (python -c, bash -c, node -e) or other arguments are another scope");
        check(GrantEvidence.Scope(fp, key, ["a b"]) != GrantEvidence.Scope(fp, key, ["a", "b"]) && GrantEvidence.Scope(fp, key, ["ab", ""]) != GrantEvidence.Scope(fp, key, ["a", "b"]), "scope: the argument boundaries count (no two lists give one key)");
        check(baseScope != GrantEvidence.Scope(new string('C', 64), key, ["-c", "print(1)"]) && baseScope != GrantEvidence.Scope(fp, new string('D', 64), ["-c", "print(1)"]), "scope: another machine or another request fingerprint is another scope");

        // H2: the authority believes a grant only when a person's assertion backs its present state.
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            string machine = fx.Fingerprint;

            // A planted row (no evidence) is no grant.
            fx.Store.AddGrant("planted", machine, Scope("planted"), null);
            check((await fx.Use(Scope("planted"))).Kind == GrantUseKind.NoGrant && fx.Store.Audit().Any(entry => entry.Event == "grant-ignored" && entry.Detail.Contains("planted", StringComparison.Ordinal)), "evidence: a row written by anything but an approval (no assertion) is ignored, and says so in the audit");

            // A row re-scoped behind the program's back.
            GrantApproval made = await fx.Approve(S1, 60);
            check((await fx.Use(S1)).Kind == GrantUseKind.Granted, "evidence: a grant made by a person's approval is used");
            Sql(fx, "UPDATE grants SET scope_key = $scope WHERE id = $id", ("$scope", S2), ("$id", made.GrantId));
            check((await fx.Use(S2)).Kind == GrantUseKind.NoGrant && (await fx.Use(S1)).Kind == GrantUseKind.NoGrant, "evidence: a grant whose scope was changed in the database covers neither scope");
            Sql(fx, "UPDATE grants SET scope_key = $scope WHERE id = $id", ("$scope", S1), ("$id", made.GrantId));
            check((await fx.Use(S1)).Kind == GrantUseKind.Granted, "evidence: put back as it was, the row verifies again (the evidence is the only thing that counts)");

            // Stretched without the admin passkey.
            Sql(fx, "UPDATE grants SET expires = NULL WHERE id = $id", ("$id", made.GrantId));
            check((await fx.Use(S1)).Kind == GrantUseKind.NoGrant, "evidence: an end removed in the database (an extension with no admin passkey) makes the grant void");
            Sql(fx, "UPDATE grants SET expires = $end WHERE id = $id", ("$end", CanonicalJson.Time(fx.Clock.GetUtcNow().AddDays(30))), ("$id", made.GrantId));
            check((await fx.Use(S1)).Kind == GrantUseKind.NoGrant, "evidence: a later end written in the database makes the grant void");
        }

        // Revoked and revived.
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            GrantApproval made = await fx.Approve(S1, 60);
            fx.Admin(GrantOps.Revoke, made.GrantId!);
            Sql(fx, "UPDATE grants SET status = 'active' WHERE id = $id", ("$id", made.GrantId));
            check((await fx.Use(S1)).Kind == GrantUseKind.NoGrant, "evidence: a revoked grant set active again in the database stays void (a revocation takes its evidence with it)");
        }

        // Machine revision bump, then a row revived by hand.
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            GrantApproval made = await fx.Approve(S1, 60);
            fx.Store.Disable(fx.Fingerprint, "test");
            fx.Store.Enable(fx.Fingerprint, "test");
            Sql(fx, "UPDATE grants SET status = 'active', security_revision = $rev WHERE id = $id", ("$rev", fx.Store.Find(fx.Fingerprint)!.SecurityRevision), ("$id", made.GrantId));
            await fx.Host.PumpAsync();
            check((await fx.Use(S1)).Kind == GrantUseKind.NoGrant, "evidence: a grant invalidated by a revision change and revived in the database stays void (its assertion names the old revision)");
        }

        // Evidence moved between rows.
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            GrantApproval a = await fx.Approve(S1, 60);
            GrantApproval b = await fx.Approve(S2, 60);
            GrantRecord rowA = fx.Store.FindGrant(a.GrantId!)!;
            Sql(fx, "UPDATE grants SET evidence_nonce = $n, evidence_text = $t, evidence_proof = $p WHERE id = $id", ("$n", rowA.Evidence!.Nonce), ("$t", rowA.Evidence.Text), ("$p", rowA.Evidence.Proof), ("$id", b.GrantId));
            check((await fx.Use(S2)).Kind == GrantUseKind.NoGrant && (await fx.Use(S1)).Kind == GrantUseKind.Granted, "evidence: the assertion of one grant does not back another scope");
        }

        // Approvals that do not carry a valid assertion make no grant.
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            using TestAuthenticator stranger = TestAuthenticator.ES256();
            GrantApproval wrongScope = await fx.Approve(S1, 10, textScope: S2);
            GrantApproval wrongRevision = await fx.Approve(S1, 10, textRevision: 99);
            GrantApproval none = await fx.Approve(S1, 10, noEvidence: true);
            GrantApproval unknownKey = await fx.Approve(S1, 10, who: stranger);
            check(!wrongScope.Granted && !wrongRevision.Granted && !none.Granted && !unknownKey.Granted && fx.Store.Grants().Count == 0, "evidence: an approval whose signed text names another scope or revision, has no assertion, or is signed by a key that is not enrolled makes no grant");
            check(fx.Store.Audit().Count(entry => entry.Event == "grant-denied") >= 4, "evidence: each refusal is audited");
        }

        // Extensions, renewals and revocations need an admin assertion that says exactly this change.
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            GrantApproval made = await fx.Approve(S1, 60);
            string id = made.GrantId!;
            GrantRecord before = fx.Store.FindGrant(id)!;
            check(fx.Admin(GrantOps.Extend, id, 30, who: fx.UserKey) is { Outcome: GrantOps.Denied, ReasonCode: GrantReasons.BadEvidence } && fx.Store.FindGrant(id) == before, "admin evidence: a change signed by a key that is not an admin key is refused and changes nothing");
            GrantAdminCommand good = fx.Command(GrantOps.Extend, id, 30);
            check(fx.Authority.AdminGrant(good with { NewEnd = good.NewEnd!.Value.AddDays(1) }) is { ReasonCode: GrantReasons.BadEvidence } && fx.Authority.AdminGrant(good with { Evidence = null, RequestId = "adm-none" }) is { ReasonCode: GrantReasons.NoEvidence } && fx.Store.FindGrant(id) == before,
                "admin evidence: an end other than the one the signed page showed, or no assertion, is refused");
            GrantApproval other = await fx.Approve(S2, 60);
            GrantAdminCommand forOther = fx.Command(GrantOps.Extend, other.GrantId!, 30);
            check(fx.Authority.AdminGrant(forOther with { GrantId = id, RequestId = "adm-swap" }) is { ReasonCode: GrantReasons.BadEvidence } && fx.Store.FindGrant(id) == before, "admin evidence: an admin assertion for one grant does not change another");
            GrantResponse applied = fx.Authority.AdminGrant(good);
            check(applied is { Outcome: GrantOps.Extended } && fx.Store.FindGrant(id) is { Revision: 2, Evidence.Kind: GrantEvidence.AdminKind } && (await fx.Use(S1)).Kind == GrantUseKind.Granted, "admin evidence: the right assertion extends the grant, the row then carries the admin evidence, and it verifies on use");
            check(applied.SecurityRevision == fx.Store.Find(fx.Fingerprint)!.SecurityRevision, "admin answer: the security revision in it is the machine's, read where the change was applied");
            check(fx.Admin(GrantOps.Revoke, id, who: fx.UserKey) is { ReasonCode: GrantReasons.BadEvidence } && fx.Store.FindGrant(id) is { Status: "active" }, "admin evidence: a revocation needs the admin assertion too");
        }

        // The held key is bound to what was true at the tap.
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            byte[] held = await Holding(fx, S1);
            string id = fx.Host.Keys.GrantId!;
            check(fx.Host.Keys.Binding is { } bound && bound.ScopeKey == S1 && bound.Revision == 1 && bound.Expires is not null && fx.Host.BorrowKey(id, S2) is null && fx.Host.Keys.IsHeld, "key binding: the key is bound to the grant's scope, revision and end at the tap, and is lent to no other scope");
            check(GC.GetGeneration(held) == GC.MaxGeneration && fx.Host.BorrowKey(id, S1) is { } lent && GC.GetGeneration(lent.Output) == GC.MaxGeneration, "key memory: the held bytes and each copy lent to a run are in the pinned object heap (the collector never moves them)");
            fx.Admin(GrantOps.Extend, id, 30);
            check(fx.Host.Keys.IsHeld, "key binding: an extension the host has not seen yet changes nothing about the held key");
            check((await fx.Use(S1)).Kind == GrantUseKind.Granted && !fx.Host.Keys.IsHeld && held.All(b => b == 0) && fx.Host.Keys.LastDropReason == "grant changed", "key binding: once the host learns that the grant changed (even by an admin) the key is dropped and zeroed, and the next run taps again");
        }

        // L1: an error of the authority is not "offline".
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            await fx.Approve(S1, 60);
            HostAuthorization direct = new(fx.Authority, fx.Machine.Deployment.MachineKey, fx.Machine.HostName, fx.Machine.Deployment.HostConfig, new LaunchGate(), fx.Authority.Offer, fx.Clock, null, fx.Mono);
            await direct.ReconcileAsync();
            check((await direct.TryUseGrantAsync(fx.Req(), S1, CancellationToken.None)).Kind == GrantUseKind.Granted, "local errors: against the local authority a synchronized grant is used online");
            fx.Store.Fault = name =>
            {
                if (name == "before-commit")
                {
                    throw new IOException("the database failed (test)");
                }
            };
            GrantUse failing = await direct.TryUseGrantAsync(fx.Req(), S1, CancellationToken.None);
            fx.Store.Fault = name =>
            {
                if (name == "before-commit")
                {
                    throw new InvalidOperationException("an error that is not a transport failure (test)");
                }
            };
            GrantUse flaky = await fx.Use(S1);
            fx.Store.Fault = null;
            check(failing.Kind == GrantUseKind.Denied && failing.Message.Contains("failed to answer", StringComparison.Ordinal), "local errors: a database error of the local authority is a refusal, never 'offline' (no use of an earlier answer) (" + failing.Kind + ")");
            check(flaky.Kind == GrantUseKind.Denied, "local errors: nor is a non-transport error of any authority (" + flaky.Kind + ")");
        }

        // L3: a check-in that cannot be checked takes the lease and the key.
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            byte[] held = await Holding(fx, S1);
            fx.Link.TamperReconcile = r => r with { Signature = null! };
            await fx.Host.ReconcileAsync();
            check(!fx.Host.Lease.IsValid && !fx.Host.Keys.IsHeld && held.All(b => b == 0), "check-in: an answer that cannot be checked destroys the lease and the held key");
        }

        // L6: stored answers are pruned.
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            await fx.Approve(Scope("old"), 10, request: fx.Req("keep-old"));
            check(fx.Store.GetProcessedGrant("keep-old") is not null, "prune: the answer of a durable request is kept for retries");
            fx.Clock.Advance(AuthorityStore.ProcessedGrantRetention + TimeSpan.FromMinutes(5));
            await fx.Approve(Scope("new"), 10, request: fx.Req("keep-new"));
            check(fx.Store.GetProcessedGrant("keep-old") is null && fx.Store.GetProcessedGrant("keep-new") is not null, "prune: answers older than the retention are removed when a new one is stored");
            for (int i = 0; i < 5; i++)
            {
                await fx.Use(Scope("new"));
            }

            check(fx.Store.GetProcessedGrant("keep-new") is not null, "prune: uses store nothing, so the table does not grow with use");
        }
    }

    // ---- a lock while an approval page is open (M1) ----

    private static async Task LockDuringApproval(Action<bool, string> check, string parent)
    {
        using Fixture fx = new(parent);
        AuthorityLock lockState = AuthorityLock.UnlockedForTests();
        fx.Machine.Deployment.Keys.LockState = lockState;
        await fx.Start();
        string outcome;
        try
        {
            GrantApproval made = await fx.Host.ApproveGrantAsync(fx.Req(), S1, () =>
            {
                lockState.Lock("locked while the page was open");

                return ApprovalDecision.Allow("approved with passkey key-one", 60, fx.Sign(fx.UserKey, Fixture.ApproveText(S1, fx.Host.KnownRevision ?? 1), 60));
            }, CancellationToken.None);
            outcome = made.GrantId is null ? "no grant" : "grant " + made.GrantId;
        }
        catch (AuthorityLockedException)
        {
            outcome = "locked";
        }

        check(outcome != "grant " && !outcome.StartsWith("grant ", StringComparison.Ordinal) && fx.Store.Grants().Count == 0, "lock: a grant approved on a page that was open when the authority locked is not made (" + outcome + ")");
    }

    // ---- the admin gate (the admin web app's grant functions: each a fresh, bound passkey tap behind a signed-in session) ----

    private static string Snap(Fixture fx, string id) => fx.Store.FindGrant(id) is { } grant ? grant.Status + "|" + grant.Revision + "|" + grant.Expires?.ToString("O") : "none";

    private static async Task AdminGate(Action<bool, string> check, string parent)
    {
        using Fixture fx = new(parent);
        TestAuthenticator laptop = fx.AdminKey;
        TestAuthenticator phone = fx.UserKey;
        await fx.Start();
        GrantApproval made = await fx.Approve(S1, 60);
        string id = made.GrantId!;
        using HostService service = HostService.Start(new HostServiceOptions
        {
            Lock = AuthorityLock.UnlockedForTests(),
            State = fx.Db,
            Store = new HostServiceTests.CountingStore(new Dictionary<string, string> { ["TOKEN"] = "x" }),
            Deployment = fx.Machine.Deployment,
            Port = 0,
            AdminAskerFactory = announce =>
            {
                ApprovalSettings settings = new("passkey", null, 0, TimeSpan.FromSeconds(4));
                PasskeyMethod method = new(new PasskeyStore(fx.Db), settings);
                EnrollmentTarget target = EnrollmentTarget.For(method, new WebApprover(method, settings, announce, TimeSpan.Zero));

                return new TargetAdminAsker(target, target);
            },
        });
        using HttpClient http = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(30) };
        AdminBrowser browser = new(service, http);
        check(await browser.SignInAsync(laptop), "admin grants: the administrator signs in to the app with one tap");

        // The grants view lists each grant (no scope key), with its state and end; it needs the session.
        (int listStatus, string listHtml, _) = await browser.GetAsync("/admin/grants");
        check(listStatus == 200 && listHtml.Contains(id, StringComparison.Ordinal) && listHtml.Contains("active", StringComparison.Ordinal) && !listHtml.Contains(S1, StringComparison.Ordinal), "admin grants: the grants view shows the grant and its state, and not the scope key");
        AdminBrowser stranger = new(service, http);
        check((await stranger.GetAsync("/admin/grants")).Status == 401, "admin grants: without a session the view is refused");

        string before = Snap(fx, id);
        async Task<Tapped> Op(string op, TestAuthenticator? who, bool uv = true, Func<byte[], byte[]>? change = null, params (string, string)[] args) => await browser.OpAsync(op, who, uv, change, true, args);

        Tapped none = await Op("grant-extend", null, true, null, ("id", id), ("minutes", "30"));
        await Task.Delay(TimeSpan.FromSeconds(5));
        check(none.Link is not null && Snap(fx, id) == before, "admin grants extend: with no passkey answer nothing changes");
        Tapped wrong = await Op("grant-extend", phone, true, null, ("id", id), ("minutes", "30"));
        check(wrong.ApproveStatus == 403 && Snap(fx, id) == before, "admin grants extend: a key that is not an admin key is refused (403), nothing changes");
        Tapped noUv = await Op("grant-extend", laptop, false, null, ("id", id), ("minutes", "30"));
        Tapped otherChallenge = await Op("grant-extend", laptop, true, challenge => SHA256.HashData(challenge), ("id", id), ("minutes", "30"));
        check(noUv.ApproveStatus == 403 && otherChallenge.ApproveStatus is 403 or 400 && Snap(fx, id) == before, "admin grants extend: no user verification, or a signature over another challenge, changes nothing");
        Tapped noUvRevoke = await Op("grant-revoke", laptop, false, null, ("id", id));
        Tapped wrongRevoke = await Op("grant-revoke", phone, true, null, ("id", id));
        check(noUvRevoke.ApproveStatus == 403 && wrongRevoke.ApproveStatus == 403 && Snap(fx, id) == before, "admin grants revoke: no user verification, or a key that is not an admin key, revokes nothing");

        // The session alone changes nothing: every request so far had a session and no genuine tap.
        check(Snap(fx, id) == before && fx.Store.FindGrant(id) is { Revision: 1 }, "admin grants: a signed-in session without a genuine tap changes no grant");

        Tapped ok = await Op("grant-extend", laptop, true, null, ("id", id[..6]), ("minutes", "30"));
        string text = ok.Page;
        check(ok.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => fx.Store.FindGrant(id) is { Revision: 2 } extended && extended.Expires == fx.Clock.GetUtcNow().AddMinutes(90)), "admin grants extend: the admin key's tap extends it (found by a prefix of its id)");
        string settled = Snap(fx, id);
        TestState.Post(http, ok.PageUrl + "/proof", ok.ProofBody);
        await Task.Delay(300);
        check(Snap(fx, id) == settled, "admin grants extend: replaying the proof does not extend it again");
        check(text.Contains("extend this grant by 30 minutes", StringComparison.Ordinal) && text.Contains(id, StringComparison.Ordinal) && text.Contains(KeyIdentity.Display(fx.Fingerprint), StringComparison.Ordinal) && text.Contains(fx.Machine.HostName, StringComparison.Ordinal), "admin grants extend: the page (which the passkey signs) shows the action, the grant, the machine's fingerprint and host name");
        check(fx.Store.Audit().Any(entry => entry.Event == "grant-extended" && entry.Detail.Contains("admin passkey admin-key", StringComparison.Ordinal)), "admin grants extend: the authority audit names the admin key that tapped");

        Tapped notYet = await Op("grant-renew", laptop, true, null, ("id", id), ("minutes", "30"));
        check(notYet.Link is null && notYet.PostStatus == 409, "admin grants renew: a grant that has not ended is refused before any page (" + notYet.Error + ")");
        Tapped unknown = await Op("grant-revoke", laptop, true, null, ("id", "g-none"));
        Tapped tooShort = await Op("grant-revoke", laptop, true, null, ("id", "g-"));
        check(unknown.Link is null && tooShort.Link is null, "admin grants: an unknown grant, or an id of fewer than 4 characters, is refused before any page");
        Tapped badTime = await Op("grant-extend", laptop, true, null, ("id", id), ("minutes", "0"));
        Tapped bothTimes = await Op("grant-extend", laptop, true, null, ("id", id), ("minutes", "5"), ("indefinite", "true"));
        check(badTime.Link is null && bothTimes.Link is null, "admin grants: a time of 0, or a time and no-end together, is refused before any page");

        // A grant that changed while the page was open: the tap changes nothing.
        Tapped stalePage = await browser.OpAsync("grant-revoke", null, true, null, true, ("id", id));
        fx.Admin(GrantOps.Extend, id, 1);
        (int staleStatus, _) = TestState.Approve(http, "http://127.0.0.1:" + new Uri(stalePage.Link!).Port + new Uri(stalePage.Link!).AbsolutePath, "http://localhost:" + new Uri(stalePage.Link!).Port, "localhost", laptop);
        await Task.Delay(500);
        check(fx.Store.FindGrant(id) is { Status: "active" } && staleStatus != 0, "admin grants revoke: a grant that changed while the page was open is not revoked by the stale tap");

        Tapped revoke = await Op("grant-revoke", laptop, true, null, ("id", id));
        check(revoke.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => fx.Store.FindGrant(id) is { Status: "revoked" }) && revoke.Page.Contains("revoke this grant", StringComparison.Ordinal), "admin grants revoke: the tap revokes it and the page named exactly that action");

        GrantApproval short1 = await fx.Approve(Scope("short"), 10);
        fx.Clock.Advance(TimeSpan.FromMinutes(11));
        Tapped renew = await Op("grant-renew", laptop, true, null, ("id", short1.GrantId!), ("minutes", "15"));
        check(renew.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => fx.Store.FindGrant(short1.GrantId!) is { } renewed && renewed.Expires == fx.Clock.GetUtcNow().AddMinutes(15)) && renew.Page.Contains("renew this ended grant for 15 minutes from now", StringComparison.Ordinal), "admin grants renew: an ended grant is renewed from now after the tap");
        Tapped indefinite = await Op("grant-extend", laptop, true, null, ("id", short1.GrantId!), ("indefinite", "true"));
        check(indefinite.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => fx.Store.FindGrant(short1.GrantId!) is { Expires: null }), "admin grants extend (no end): gives the grant no end after the tap");

        (_, string again, _) = await browser.GetAsync("/admin/grants");
        check(again.Contains(id, StringComparison.Ordinal) && again.Contains("revoked", StringComparison.Ordinal) && again.Contains(short1.GrantId!, StringComparison.Ordinal) && again.Contains("no end", StringComparison.Ordinal) && !again.Contains(S1, StringComparison.Ordinal), "admin grants list: one row per grant with its state and end; the scope key (a hash of the request) is not shown");
    }

    // ---- the held store key: dropped on every end of its grant ----

    private static async Task<byte[]> Holding(Fixture fx, string scope, int minutes = 600)
    {
        GrantApproval made = await fx.Approve(scope, minutes);
        await fx.Use(scope);
        using Unlock tapped = new("test-credential", [.. Enumerable.Range(1, 32).Select(i => (byte)(i * 5))]);
        fx.Host.HoldKey(made.GrantId!, scope, tapped);

        return fx.Host.Keys.HeldBytes!;
    }

    private static async Task KeyHolding(Action<bool, string> check, string parent)
    {
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            check(!fx.Host.Keys.IsHeld, "key: nothing is held before a tap");
            fx.Host.HoldKey("g-unknown", S1, new Unlock("c", [1, 2, 3]));
            check(!fx.Host.Keys.IsHeld, "key: a key is not held for a grant the host does not vouch for");
            byte[] held = await Holding(fx, S1);
            string id = fx.Host.Keys.GrantId!;
            check(fx.Host.Keys.IsHeld && id == fx.Host.SyncedGrants[0].GrantId, "key: after a tap under a valid grant the host holds the key for that grant");
            using (Unlock lent = fx.Host.BorrowKey(id, S1)!)
            {
                check(lent.Output.SequenceEqual(held) && !ReferenceEquals(lent.Output, held), "key: a run is lent a copy");
            }

            check(held.Any(b => b != 0) && fx.Host.BorrowKey("g-other", S1) is null && fx.Host.BorrowKey(id, S2) is null && fx.Host.Keys.IsHeld, "key: disposing the copy leaves the held key intact; another grant's run is lent nothing");
            fx.Host.DropKey("test");
            check(!fx.Host.Keys.IsHeld && held.All(b => b == 0), "key: dropping zeroes the held bytes");
        }

        // Grant expiry.
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            byte[] held = await Holding(fx, S1, 30);
            string id = fx.Host.Keys.GrantId!;
            fx.Clock.Advance(TimeSpan.FromMinutes(31));
            check(fx.Host.BorrowKey(id, S1) is null && !fx.Host.Keys.IsHeld && held.All(b => b == 0) && fx.Host.Keys.LastDropReason == "grant expired", "drop: when the grant ends the key is dropped and zeroed (and a stale key is never lent)");
        }

        using (Fixture fx = new(parent))
        {
            await fx.Start();
            byte[] held = await Holding(fx, S1, 30);
            fx.Clock.Advance(TimeSpan.FromMinutes(31));
            await fx.Host.PumpAsync();
            check(!fx.Host.Keys.IsHeld && held.All(b => b == 0), "drop: the service's periodic check drops it when the grant has ended, with no run to notice");
        }

        // Revoke.
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            byte[] held = await Holding(fx, S1);
            fx.Admin(GrantOps.Revoke, fx.Host.Keys.GrantId!);
            check(fx.Host.Keys.IsHeld, "revoke: the host has not been told yet (so the drop below is the notice's doing)");
            await fx.Host.PumpAsync();
            check(!fx.Host.Keys.IsHeld && held.All(b => b == 0) && fx.Host.Keys.LastDropReason == "grant revoked", "drop: revoking the grant drops and zeroes the key as soon as the host is told");
        }

        // Disable, and the security revision that goes with it.
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            byte[] held = await Holding(fx, S1);
            fx.Store.Disable(fx.Fingerprint, "test");
            await fx.Host.PumpAsync();
            check(!fx.Host.Keys.IsHeld && held.All(b => b == 0) && fx.Host.KnownRevision == 2, "drop: disabling the machine (its security revision changes) drops and zeroes the key");
        }

        using (Fixture fx = new(parent))
        {
            await fx.Start();
            byte[] held = await Holding(fx, S1);
            fx.Store.Disable(fx.Fingerprint, "test");
            fx.Store.Enable(fx.Fingerprint, "test");
            await fx.Host.PumpAsync();
            check(!fx.Host.Keys.IsHeld && held.All(b => b == 0), "drop: a machine disabled and enabled again (a new revision, no grants) holds no key");
        }

        // The machine is no longer trusted and the host finds out only at its next check-in.
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            byte[] held = await Holding(fx, S1);
            fx.Store.Disable(fx.Fingerprint, "test");
            await fx.Host.ReconcileAsync();
            check(!fx.Host.Keys.IsHeld && held.All(b => b == 0), "drop: a check-in that finds the machine untrusted drops and zeroes the key");
        }

        // The lease ends (the authority cannot be reached for longer than the lease).
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            byte[] held = await Holding(fx, S1);
            fx.Link.Offline = true;
            fx.Mono.Advance(TimeSpan.FromMinutes(9));
            check(fx.Host.BorrowKey(fx.Host.Keys.GrantId!, S1) is { } within && within.Output.Length == 32, "lease: within the lease the held key is still lent while the authority cannot be reached");
            fx.Mono.Advance(TimeSpan.FromMinutes(2));
            check(fx.Host.BorrowKey(fx.Host.Keys.GrantId ?? "", S1) is null && !fx.Host.Keys.IsHeld && held.All(b => b == 0) && fx.Host.Keys.LastDropReason == "lease ended", "drop: when the lease ends the key is dropped and zeroed");
        }

        // A restart holds nothing (the key lives only in the service's memory).
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            await Holding(fx, S1);
            fx.Restart();
            check(!fx.Host.Keys.IsHeld && fx.Host.Keys.HeldBytes is null, "restart: the new service holds no key");
            await fx.Start();
            check(!fx.Host.Keys.IsHeld, "restart: nor after it reconciles; a tap is needed again");
        }

        // The key provider is told when a run failed.
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            byte[] held = await Holding(fx, S1);
            IStoreKeyProvider provider = new HeldStoreKeyProvider(new Chooser(0), fx.Host);
            provider.Discard();
            check(!fx.Host.Keys.IsHeld && held.All(b => b == 0) && fx.Host.Keys.LastDropReason == "run failed", "drop: a failed run (the provider is told) drops and zeroes the key");
        }
    }

    // ---- through the real service ----

    internal static string Show(HostServiceTests.Rig rig) => rig.Script("show", "echo ran > \"%~dpn0.marker.txt\"\necho t=%TOKEN%", "echo ran > \"$0.marker.txt\"\necho \"t=$TOKEN\"");

    private static string Marker(HostServiceTests.Rig rig) => HostServiceTests.Marker(rig);

    /// <summary>Approves; chooses a grant time only while <see cref="Minutes" /> is set (as a person would on the approve page), and counts the asks.</summary>
    internal sealed class Chooser(int minutes, bool approve = true, bool unlock = false, TestAuthenticator? signer = null) : IApprover
    {
        public int Minutes { get; set; } = minutes;

        public List<ApprovalRequest> Requests { get; } = [];

        public ApprovalDecision Request(ApprovalRequest request)
        {
            lock (Requests)
            {
                Requests.Add(request);
            }

            // A tap that releases the store key (PRF) hands over 32 bytes the test can recognise; no real secret is involved.
            Unlock? released = unlock && request.Unlock ? new Unlock("test-credential", [.. Enumerable.Range(1, 32).Select(i => (byte)(i * 7))]) : null;

            // A grant is backed by the assertion the person made over the page text (as the page makes it).
            ApprovalEvidence? evidence = null;
            if (approve && Minutes > 0 && signer is not null)
            {
                string text = ApprovalSummary.BuildMessage(request) + "\n" + ApprovalSummary.IssuedLine(DateTimeOffset.UtcNow);
                string nonce = "svc-nonce-" + Guid.NewGuid().ToString("N")[..8];
                evidence = new ApprovalEvidence(nonce, text, signer.Assert(ReuseBinding.Challenge(RequestBinding.Compute(nonce, text), Minutes), TestState.Origin, "localhost", TestState.NextCount()));
            }

            return approve ? ApprovalDecision.Allow("approved", Minutes, evidence, released) : ApprovalDecision.Deny("test denied");
        }
    }

    private sealed class CountingProvider(IApprover approver, bool refuse = false) : IStoreKeyProvider
    {
        private readonly TapStoreKeyProvider _tap = new(approver);

        public int Calls;

        public KeyRelease Obtain(ISecretSource store, ApprovalRequest request, CancellationToken cancel, Action<string> note, string? grantId = null, string? scopeKey = null)
        {
            Interlocked.Increment(ref Calls);

            return refuse ? KeyRelease.Refused("test refusal") : _tap.Obtain(store, request, cancel, note, grantId, scopeKey);
        }
    }

    /// <summary>An admin revoke as the admin command makes it, signed by <paramref name="who" /> (an admin key of the rig's state).</summary>
    private static GrantResponse ServiceRevoke(HostServiceTests.Rig rig, TestAuthenticator who, string grantId, string requestId)
    {
        AuthorityStore store = rig.Machine.Deployment.Store;
        GrantRecord grant = store.FindGrant(grantId)!;
        string text = "Admin change to a grant\n" + GrantEvidence.AdminLines(GrantOps.Revoke, grant, grant.Revision + 1, null) + "\n" + ApprovalSummary.IssuedLine(DateTimeOffset.UtcNow);
        string nonce = "svc-admin-" + Guid.NewGuid().ToString("N")[..8];
        ApprovalEvidence evidence = new(nonce, text, who.Assert(ReuseBinding.Challenge(RequestBinding.Compute(nonce, text), 0), TestState.Origin, "localhost", TestState.NextCount()));

        return rig.Machine.Deployment.Authority.AdminGrant(new GrantAdminCommand(requestId, GrantOps.Revoke, grantId, null, false, null, "test admin", null, evidence));
    }

    private static async Task ThroughTheService(Action<bool, string> check, string parent)
    {
        using TestAuthenticator svcKey = TestAuthenticator.ES256();
        // approve makes a grant and launches nothing; run then needs no page decision for the same request.
        Chooser approver = new(60, signer: svcKey);
        using (HostServiceTests.Rig rig = new(parent, approver: () => approver, enrolled: svcKey))
        {
            string program = Show(rig);
            HostServiceTests.Raw approved = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program), path: "/v1/approve");
            check(approved.Result is { Outcome: LaunchOutcome.Approved, ExitCode: 0 } && rig.Store.Reads == 0 && !File.Exists(Marker(rig)) && approver.Requests.Count == 1 && approved.Stdout.Contains("approved until", StringComparison.Ordinal) && approved.Stdout.Contains("Nothing was run", StringComparison.Ordinal),
                "service approve: the approval page makes a grant and launches nothing (no decryption, no program) (" + approved.Stdout.Trim() + approved.Stderr.Trim() + ")");
            check(approver.Requests[0].Reuse is { IsOn: true } && !approver.Requests[0].Unlock, "service approve: the page offers the times and asks for no unlock");
            check(rig.Machine.Deployment.Store.Grants() is [{ Status: "active" } granted] && granted.Program == program && granted.SecretNames == "TOKEN" && granted.Fingerprint == rig.Machine.Fingerprint, "service approve: the authority holds one grant with what it covers (program, secret names, folder)");
            check(rig.Machine.Deployment.Store.Audit().Any(entry => entry.Event == "grant-created") && new AuditLog(rig.State).TryRead(20, null, out IReadOnlyList<AuditRecord> rows, out _) && rows.Any(row => row.Event == "grant-approved"), "service approve: audited by the authority and in the local audit log");

            approver.Minutes = 0;
            HostServiceTests.Raw run = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            check(run.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 0 } && approver.Requests.Count == 1 && rig.Store.Reads == 1 && File.Exists(Marker(rig)) && run.Stderr.Contains("a grant covers this request", StringComparison.Ordinal) && !run.Stdout.Contains("Canary", StringComparison.Ordinal),
                "service run: a request in the scope of the grant runs with no approval page decision (the approver was asked once, for approve) (" + run.Stderr.Trim() + string.Join(" | ", rig.Machine.Deployment.Store.Audit().Where(e => e.Event.StartsWith("grant", StringComparison.Ordinal)).Select(e => e.Event + ":" + e.Detail)) + ")");
            check(new AuditLog(rig.State).TryRead(20, null, out rows, out _) && rows.Any(row => row.Event == "granted") && rig.Machine.Deployment.Store.Audit().Any(entry => entry.Event == "grant-use"), "service run: the use of the grant is audited by the host and by the authority");

            // A grant covers exactly one command line: another argument (a different target, or inline code after -c / -e) is another command.
            File.Delete(Marker(rig));
            HostServiceTests.Raw flagged = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program, ["--extra"]));
            check(flagged.Result is { Outcome: LaunchOutcome.Exited } && approver.Requests.Count == 2, "service run: another argument of the same program, secrets and folder is not covered: the approval page decides (" + approver.Requests.Count + ")");
            HostServiceTests.Raw otherSecret = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program, pairs: [("TOKEN", "TOKEN"), ("OTHER_KEY", "OTHER_KEY")]));
            check(approver.Requests.Count == 3 && otherSecret.Result is { Outcome: LaunchOutcome.Exited }, "service run: a request with another set of secrets is not covered: the approval page decides (" + approver.Requests.Count + " " + otherSecret.Result?.Outcome + " " + otherSecret.Stderr.Trim() + ")");
            string second = rig.Script("second", "echo two", "echo two");
            HostServiceTests.Raw otherProgram = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, second));
            check(approver.Requests.Count == 4 && otherProgram.Result is { Outcome: LaunchOutcome.Exited }, "service run: another program is not covered: the approval page decides");
            File.AppendAllText(rig.FileOf(Path.GetFileName(program)), OperatingSystem.IsWindows() ? "rem edited\r\n" : "# edited\n");
            HostServiceTests.Raw edited = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            check(approver.Requests.Count == 5 && edited.Result is { Outcome: LaunchOutcome.Exited }, "service run: the same script with other contents is not covered: the approval page decides");

            // Revocation: the next run asks again.
            string grantId = rig.Machine.Deployment.Store.Grants().First(grant => grant.Program == program).Id;
            ServiceRevoke(rig, svcKey, grantId, "adm-svc-1");
            await rig.Service.Authorization.PumpAsync();
            int asked = approver.Requests.Count;
            File.WriteAllText(rig.FileOf(Path.GetFileName(program)), File.ReadAllText(rig.FileOf(Path.GetFileName(program))).Replace("rem edited\r\n", "", StringComparison.Ordinal).Replace("# edited\n", "", StringComparison.Ordinal));
            HostServiceTests.Raw afterRevoke = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            check(approver.Requests.Count == asked + 1 && afterRevoke.Result is { Outcome: LaunchOutcome.Exited }, "service run: after a revocation the same request goes through the approval page again (" + approver.Requests.Count + "/" + asked + " " + afterRevoke.Result?.Outcome + " " + afterRevoke.Stderr.Trim() + ")");
        }

        // A denied approval and an approval with no time make nothing.
        foreach (bool noTime in new[] { false, true })
        {
            FakeApprover refusing = noTime ? new FakeApprover(true, reuseMinutes: 0) : new FakeApprover(false);
            using HostServiceTests.Rig rig = new(parent, approver: () => refusing);
            HostServiceTests.Raw refused = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, Show(rig)), path: "/v1/approve");
            check(refused.Result is { Outcome: LaunchOutcome.Denied, ExitCode: RunCommand.Denied } && rig.Machine.Deployment.Store.Grants().Count == 0 && rig.Store.Reads == 0, "service approve: " + (noTime ? "an approval with no time chosen" : "a refused approval") + " makes no grant (" + refused.Stderr.Trim() + ")");
        }

        // approve validates the request like a run (unknown secret).
        using (HostServiceTests.Rig rig = new(parent, approver: () => new FakeApprover(true, reuseMinutes: 60)))
        {
            HostServiceTests.Raw unknown = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, Show(rig), pairs: [("TOKEN", "NO_SUCH")]), path: "/v1/approve");
            check(unknown.Result is { ExitCode: RunCommand.Usage } && rig.Machine.Deployment.Store.Grants().Count == 0 && unknown.Stderr.Contains("Unknown secret", StringComparison.Ordinal), "service approve: the same validation as a run (an unknown secret is refused, no grant)");
        }

        // A store whose key needs a tap. The first run under a grant gets the key from one passkey tap (the page the person taps) and the service
        // holds it for that grant; every later run under it needs no tap and no page. It is dropped on every end of the grant and on a failed run.
        {
            Chooser tapper = new(60, unlock: true, signer: svcKey);
            HostServiceTests.Rig rig = new(parent, approver: () => tapper, needsUnlock: true, enrolled: svcKey);
            try
            {
                string program = Show(rig);
                await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program), path: "/v1/approve");
                tapper.Minutes = 0;
                HostAuthorization host = rig.Service.Authorization;
                check(rig.Machine.Deployment.Store.Grants().Count == 1 && tapper.Requests.Count == 1 && !host.Keys.IsHeld && rig.Store.Reads == 0, "tap store: approve works for a store that needs a passkey tap, releases nothing and holds nothing");
                string grantId = rig.Machine.Deployment.Store.Grants()[0].Id;

                HostServiceTests.Raw first = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
                check(first.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 0 } && tapper.Requests.Count == 2 && rig.Store.KeyedReads == 1 && tapper.Requests[1].Unlock && tapper.Requests[1].Reuse is null, "held key: the first run under the grant gets the key from one tap (the page asks for the unlock, offers no reuse) (" + first.Stderr.Trim() + ")");
                check(first.Stderr.Contains("keep the secret store key", StringComparison.Ordinal) && !first.Stderr.Contains("does not replace that tap", StringComparison.Ordinal) && host.Keys.IsHeld && host.Keys.GrantId == grantId, "held key: it says in one line that this run needs a tap that makes the service keep the key, and the service now holds the key for that grant");
                check(tapper.Requests[1].Heading == HeldStoreKeyProvider.KeepHeading && tapper.Requests[1].ExtraLines is { } keepLines && keepLines.Any(line => line.StartsWith("KEY HELD:", StringComparison.Ordinal) && line.Contains(grantId, StringComparison.Ordinal) && line.Contains("until 20", StringComparison.Ordinal) && line.Contains("ALL your secrets", StringComparison.Ordinal)),
                    "held key: the page of the key-holding tap says plainly (in the text the passkey signs) that the service keeps the key for this grant until its end");
                byte[] heldBytes = host.Keys.HeldBytes!;

                File.Delete(Marker(rig));
                HostServiceTests.Raw second = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
                check(second.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 0 } && tapper.Requests.Count == 2 && rig.Store.KeyedReads == 2 && File.Exists(Marker(rig)) && second.Stderr.Contains(HeldStoreKeyProvider.HeldNote, StringComparison.Ordinal) && !second.Stderr.Contains("needs a passkey tap", StringComparison.Ordinal),
                    "held key: a later run under the grant needs no tap and no page, and still opens the store with the key (" + second.Stderr.Trim() + ")");
                check(heldBytes.Any(b => b != 0) && ReferenceEquals(heldBytes, host.Keys.HeldBytes), "held key: running does not use up or zero the held copy (each run gets its own copy)");
                check(!second.Stdout.Contains("test-credential", StringComparison.Ordinal) && !second.Stderr.Contains(Convert.ToHexString(heldBytes), StringComparison.OrdinalIgnoreCase) && !second.Stderr.Contains(Convert.ToBase64String(heldBytes), StringComparison.Ordinal), "held key: nothing printed shows the key");

                // Another request (no grant covers it) is decided on the page and neither uses nor replaces the held key.
                HostServiceTests.Raw other = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, rig.Script("other-k", "echo k", "echo k")));
                check(other.Result is { Outcome: LaunchOutcome.Exited } && tapper.Requests.Count == 3 && host.Keys.IsHeld && host.Keys.GrantId == grantId && ReferenceEquals(heldBytes, host.Keys.HeldBytes), "held key: a request outside the grant gets its own page and tap, and leaves the held key as it was");

                // A run under the grant that fails drops the key (and zeroes it); the next run taps again.
                rig.Store.Fail = true;
                HostServiceTests.Raw failed = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
                check(failed.Result is { Outcome: LaunchOutcome.Failed } && !host.Keys.IsHeld && host.Keys.LastDropReason == "run failed" && heldBytes.All(b => b == 0), "held key: a run that fails drops the key and zeroes it");
                rig.Store.Fail = false;
                int taps = tapper.Requests.Count;
                HostServiceTests.Raw again = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
                check(again.Result is { Outcome: LaunchOutcome.Exited } && tapper.Requests.Count == taps + 1 && host.Keys.IsHeld, "held key: after a drop the next run under the grant taps again and holds a new key");

                // Revoking the grant drops the key at once.
                byte[] before = host.Keys.HeldBytes!;
                ServiceRevoke(rig, svcKey, grantId, "adm-key-1");
                await host.PumpAsync();
                check(!host.Keys.IsHeld && before.All(b => b == 0) && host.Keys.LastDropReason == "grant revoked", "held key: revoking the grant drops and zeroes the key");
                int tapsAfter = tapper.Requests.Count;
                HostServiceTests.Raw revokedRun = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
                check(revokedRun.Result is { Outcome: LaunchOutcome.Exited } && tapper.Requests.Count == tapsAfter + 1 && !host.Keys.IsHeld, "held key: after the revocation a run goes through the page and its tap, and holds nothing");

                // A new grant, a new tap, and the service stopping zeroes the key.
                tapper.Minutes = 60;
                await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program), path: "/v1/approve");
                tapper.Minutes = 0;
                await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
                byte[]? stopping = host.Keys.HeldBytes;
                check(stopping is not null && stopping.Any(b => b != 0), "held key: a new grant holds a new key after its first run");
                rig.Dispose();
                check(stopping!.All(b => b == 0) && !host.Keys.IsHeld, "held key: stopping the service zeroes the key");
            }
            finally
            {
                rig.Dispose();
            }
        }

        // The provider's refusal stops the run before anything is decrypted.
        Chooser plain = new(60, signer: svcKey);
        using (HostServiceTests.Rig rig = new(parent, approver: () => plain, enrolled: svcKey, keyProvider: approver => new CountingProvider(approver, refuse: true)))
        {
            string program = Show(rig);
            await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program), path: "/v1/approve");
            plain.Minutes = 0;
            HostServiceTests.Raw run = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            check(run.Result is { Outcome: LaunchOutcome.Denied, ExitCode: RunCommand.Denied } && rig.Store.Reads == 0 && !File.Exists(Marker(rig)) && run.Stderr.Contains("test refusal", StringComparison.Ordinal), "seam: a key provider that refuses stops the run before decryption and before the program starts (" + run.Stderr.Trim() + ")");
        }

        // Revocation applied by a connected host cancels a launch that waits for the tap and has not committed.
        HostServiceTests.CancelAwareApprover waiting = new();
        Chooser maker = new(60, signer: svcKey);
        int phase = 0;
        using (HostServiceTests.Rig rig = new(parent, approver: () => Interlocked.Increment(ref phase) == 1 ? maker : waiting, needsUnlock: true, enrolled: svcKey))
        {
            string program = Show(rig);
            await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program), path: "/v1/approve");
            Task<HostServiceTests.Raw> pending = HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            check(await HostServiceTests.WaitFor(() => waiting.Asked.IsSet), "revoke while waiting: the launch under the grant reached the tap");
            string grantId = rig.Machine.Deployment.Store.Grants()[0].Id;
            ServiceRevoke(rig, svcKey, grantId, "adm-svc-2");
            await rig.Service.Authorization.PumpAsync();
            waiting.Release.Set();
            HostServiceTests.Raw result = await pending;
            check(result.Result is { Outcome: LaunchOutcome.Denied or LaunchOutcome.Cancelled } && rig.Store.Reads == 0 && !File.Exists(Marker(rig)), "revoke while waiting: the revocation invalidated the gate; nothing was decrypted and nothing started (" + result.Result?.Outcome + ")");
        }

        // Startup reconciliation: until the host has checked in with its authority it accepts no request.
        {
            string folder = Path.Combine(parent, "startup-" + Guid.NewGuid().ToString("N")[..6]);
            using TestMachine machine = new(folder);
            FlakyAuthority link = new(machine.Deployment.Authority) { Offline = true };
            machine.Deployment.Link = link;
            using HostServiceTests.Rig rig = new(parent, approver: () => new FakeApprover(true), machine: machine);
            check(!rig.Service.Ready, "startup: an unreachable authority leaves the service not ready");
            HostServiceTests.Raw refused = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, Show(rig)));
            HostServiceTests.Raw refusedApprove = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, Show(rig)), path: "/v1/approve");
            check(refused.Status == HttpStatusCode.ServiceUnavailable && refusedApprove.Status == HttpStatusCode.ServiceUnavailable && rig.Store.Reads == 0 && !File.Exists(Marker(rig)), "startup: until it has reconciled the service refuses runs and approvals with 503 and decrypts nothing");
            link.Offline = false;
            check(await HostServiceTests.WaitFor(() => rig.Service.Ready, 30), "startup: it keeps trying and becomes ready when the authority answers");
            HostServiceTests.Raw ready = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, Show(rig)));
            check(ready.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 0 } && rig.Service.Authorization.Lease.IsValid, "startup: once reconciled the run goes through and the host holds a lease");
        }

        // Lease expiry in the running service: an authority that cannot be reached for longer than the lease means no secret use.
        {
            string folder = Path.Combine(parent, "lease-" + Guid.NewGuid().ToString("N")[..6]);
            using TestMachine machine = new(folder);
            machine.Deployment.Authority.LeaseDuration = TimeSpan.FromMinutes(10);
            FlakyAuthority link = new(machine.Deployment.Authority);
            machine.Deployment.Link = link;
            FakeMonotonic mono = new();
            Chooser tap = new(60, signer: svcKey);
            using HostServiceTests.Rig rig = new(parent, approver: () => tap, machine: machine, monotonic: mono, enrolled: svcKey);
            string program = Show(rig);
            await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program), path: "/v1/approve");
            tap.Minutes = 0;
            link.Offline = true;
            mono.Advance(TimeSpan.FromMinutes(9));
            HostServiceTests.Raw within = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            check(within.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 0 } && within.Stderr.Contains("offline, within the lease", StringComparison.Ordinal) && tap.Requests.Count == 1, "service lease: offline, within the lease, a synchronized grant still lets the run through with no page decision (" + within.Stderr.Trim() + ")");
            mono.Advance(TimeSpan.FromMinutes(2));
            int reads = rig.Store.Reads;
            File.Delete(Marker(rig));
            HostServiceTests.Raw expired = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            check(expired.Result is { Outcome: LaunchOutcome.Denied } && rig.Store.Reads == reads && !File.Exists(Marker(rig)), "service lease: after the lease, offline, the run is refused and nothing is decrypted (" + expired.Stderr.Trim() + ")");
        }
    }
}

using System.Net;
using System.Security.Cryptography;
using System.Text;

using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>
/// Phase 3, grants as authority operations and reconciliation: a grant is made by a human approval, used without a page
/// decision for exactly its scope while it is unexpired and unrevoked, extended, renewed and revoked by the authority (signed, idempotent, atomic),
/// and a host whose authority cannot be reached uses nothing (it fails closed): what vouches for the host is only a verified, Trusted check-in, which
/// nothing but the authority can give, which a restart destroys, and which no grant (indefinite or not) changes.
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

        public Action<GrantEnvelope>? BeforeGrant { get; set; }

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
            BeforeGrant?.Invoke(envelope);
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

        public Fixture(string parent, bool withStore = true)
        {
            Clock = new TestClock();
            Machine = new TestMachine(Path.Combine(parent, "gx-" + Guid.NewGuid().ToString("N")[..8]), true, clock: Clock);
            Mono = new FakeMonotonic();

            // The state the authority checks assertions against: an admin key (the first one enrolled) and an ordinary key.
            AdminKey = TestAuthenticator.ES256();
            UserKey = TestAuthenticator.ES256(prf: false);
            Db = new StateDatabase(Store.Database);
            TestState.Add(Db, AdminKey.Record("localhost", "admin-key") with { Created = DateTimeOffset.UtcNow }, withStore: withStore);
            TestState.AddConvenience(Db, UserKey, "user-key");
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
            Machine.Deployment.Authority.Verifier = new ManifestApprovalVerifier(Db);
            Link = new FlakyAuthority(Machine.Deployment.Authority);
            Gate = new LaunchGate();
            Host = new HostAuthorization(Link, Machine.Deployment.MachineKey, Machine.HostName, Machine.Deployment.HostConfig, Gate, (requestId, digest, present) => Machine.Deployment.Authority.Offer(requestId, digest, present), Clock, Mono);
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
        public static string ApproveText(string scope, int revision, LaunchRequest? request = null)
        {
            LaunchRequest basis = request ?? IdentityTests.Sample("contents", DateTimeOffset.UtcNow);

            return string.Join((char)10, GrantEvidence.ApproveLines(revision, scope, contents: GrantEvidence.ContentsKey(basis.SecretNames, basis.Program, basis.WorkingDirectory))) + (char)10 + ApprovalSummary.RequestIdPrefix + scope;
        }

        public Task<GrantApproval> Approve(string scope, int minutes, bool approve = true, LaunchRequest? request = null, TestAuthenticator? who = null, string? textScope = null, int? textRevision = null, bool noEvidence = false)
            => Host.ApproveGrantAsync(request ?? Req(), scope, () => approve
                ? ApprovalDecision.Allow("approved with passkey key-one", minutes, minutes > 0 && !noEvidence ? Sign(who ?? UserKey, ApproveText(textScope ?? scope, textRevision ?? Host.KnownRevision ?? 1, request), minutes) : null)
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

        /// <summary>A replace as the admin app makes it: the new grant's id and end fixed up front, the replace lines signed by an admin key.</summary>
        public GrantAdminCommand ReplaceCommand(string originalId, int? minutes = 1440, bool indefinite = false, string? requestId = null, TestAuthenticator? who = null, string? newId = null)
        {
            GrantRecord? original = Store.FindGrant(originalId);
            string id = newId ?? "g-" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(9)).Replace('+', '-').Replace('/', '_');
            DateTimeOffset? newEnd = indefinite || minutes is null ? null : Clock.GetUtcNow().AddMinutes(minutes.Value);
            ApprovalEvidence? evidence = original is null ? null : Sign(who ?? AdminKey, "Admin change to a grant\n" + GrantEvidence.ReplaceLines(original, id, newEnd), 0);

            return new GrantAdminCommand(requestId ?? "adm-" + Interlocked.Increment(ref _ids), GrantOps.Replace, originalId, minutes, indefinite, null, "test admin", newEnd, evidence, id);
        }

        /// <summary>A consumed once-only grant for <paramref name="scope" />, recorded as "Approve once" records it (the person's assertion, made for once).</summary>
        public async Task<GrantRecord?> Once(string scope)
        {
            ApprovalDecision decision = ApprovalDecision.Allow("approved with passkey key-one", 0, Sign(UserKey, ApproveText(scope, Host.KnownRevision ?? 1), 0));
            GrantApproval made = await Host.RecordOnceGrantAsync(Req(), scope, decision, CancellationToken.None);

            return made.GrantId is null ? null : Store.FindGrant(made.GrantId);
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
            await FailClosed(check, parent);
            await Reconnection(check, parent);
            await Tampering(check, parent);
            await Evidence(check, parent);
            await Seals(check, parent);
            await SealFailures(check, parent);
            await Atomicity(check, parent);
            await UsageColumns(check, parent);
            await AdminGate(check, parent);
            await LockDuringApproval(check, parent);
            await OnceGrants(check, parent);
            await LifetimePolicy(check, parent);
            await ExtendOnceGrants(check, parent);
            await ReplaceGrants(check, parent);
            await GrantEnds(check, parent);
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
        static CliCommand? Parse(params string[] args) => CliArgs.Parse(args, out _);
        CliCommand.Approve? approve = Parse("approve", "--secrets", "A,B", "--reason", "why", "--", "node", "x.js") as CliCommand.Approve;
        check(approve is { Args: { Program: "node", Reason: "why" } } && approve.Args.Secrets.SequenceEqual(["A", "B"]) && approve.Args.Arguments.SequenceEqual(["x.js"]), "approve parse: the grammar of a run (secrets, reason, -- program and arguments)");
        check(Parse("approve", "--port", "8000", "--secrets", "A", "--reason", "r", "--", "p") is CliCommand.Approve { Port: 8000 } && Parse("approve", "--service-port", "9000", "--secrets", "A", "--reason", "r", "--", "p") is null, "approve parse: --port (the approval page) is accepted as for a run; there is no service port option");
        check(CliArgs.Parse(["approve", "--secrets", "A", "--", "p"], out string noReason) is null && noReason.Contains("--reason", StringComparison.Ordinal), "approve parse: --reason is required as for a run (" + noReason + ")");
        check(CliArgs.Parse(["approve", "--needs"], out string notRun) is null && notRun.Contains("approve takes", StringComparison.Ordinal), "approve parse: only the arguments of a run (" + notRun + ")");
        check(Parse("approve") is CliCommand.Help && Parse("approve", "--help") is CliCommand.Help, "approve parse: nothing to approve shows the help; --help still works");
        check(Parse("approve", "-f", "a.env", "--secrets", "A", "--reason", "r", "--", "p") is CliCommand.Approve { Args.EnvFiles.Count: 1 }, "approve parse: -f works as for a run");
        check(!CliArgs.NeedsTerminal(approve!), "approve: needs no terminal of its own (the approval is on the page, as for a run)");
    }

    // ---- grant lifecycle ----

    private static async Task Lifecycle(Action<bool, string> check, string parent)
    {
        using Fixture fx = new(parent);
        check(await fx.Start() == HostAuthorization.Reconciliation.Reconciled && fx.Host.Vouched, "startup: the host checks in with the authority and is vouched for");
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
        check(use is { Kind: GrantUseKind.Granted } && use.GrantId == grant.Id, "use: a request in the scope of the grant is covered (online, answered by the authority)");
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

        // Extension: counted from the present end; no revision of the machine.
        DateTimeOffset endBefore = afterRenew.Expires!.Value;
        GrantResponse extended = fx.Admin(GrantOps.Extend, grant.Id, 30);
        check(extended is { Outcome: GrantOps.Extended } && fx.Store.FindGrant(grant.Id) is { Revision: 4 } now4 && now4.Expires == endBefore.AddMinutes(30), "extend: an active grant ends 30 minutes later than it did (revision 4)");
        check(fx.Store.Find(fx.Fingerprint)!.SecurityRevision == machineRevision && fx.Host.Vouched, "extend: the machine's revision did not change and the host is still vouched for");
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

    // ---- fail closed: the authority is the only thing that vouches for a host ----

    private static async Task FailClosed(Action<bool, string> check, string parent)
    {
        // Always: a grant with no end, backed by the same kind of passkey assertion (the signed time is the Always value).
        using (Fixture always = new(parent))
        {
            await always.Start();
            GrantApproval forever = await always.Approve(S1, ReuseOffer.Always);
            check(forever.Granted && forever.Expires is null && always.Store.Grants() is [{ Expires: null }] && (await always.Use(S1)).Kind == GrantUseKind.Granted, "always: the approval makes a grant with no end, and it covers its scope");
        }

        // An authority that cannot be reached means no use of a grant, even one this host synchronized and that has not ended.
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            GrantApproval made = await fx.Approve(S1, 600);
            check((await fx.Use(S1)).Kind == GrantUseKind.Granted && fx.Host.SyncedGrants.Count == 1, "fail closed: online the grant covers its scope");
            fx.Link.Offline = true;
            GrantUse offline = await fx.Use(S1);
            check(offline.Kind == GrantUseKind.Denied && offline.GrantId.Length == 0 && offline.Message.Contains("Nothing was run", StringComparison.Ordinal), "fail closed: while the authority cannot be reached a synchronized grant is NOT used (" + offline.Message + ")");
            fx.Mono.Advance(TimeSpan.FromMinutes(1));
            check((await fx.Use(S1)).Kind == GrantUseKind.Denied && (await fx.Use(S2)).Kind == GrantUseKind.Denied, "fail closed: and no time makes it so, for any scope");
            GrantApproval offlineApproval = await fx.Approve(Scope("new"), 10);
            check(!offlineApproval.Granted && offlineApproval.Message.Contains("authority", StringComparison.Ordinal) && fx.Store.Grants().Count == 1, "fail closed: no new approval is made while disconnected (" + offlineApproval.Message + ")");
            fx.Link.Offline = false;
            check((await fx.Use(S1)) is { Kind: GrantUseKind.Granted } back && back.GrantId == made.GrantId, "fail closed: reconnected, the authority answers again and the grant covers its scope");
        }

        // The wall clock does not matter: with the authority out of reach a date change does not bring a grant back.
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            GrantApproval made = await fx.Approve(S1, 30);
            fx.Link.Offline = true;
            fx.Clock.Advance(TimeSpan.FromMinutes(40));
            check((await fx.Use(S1)).Kind == GrantUseKind.Denied, "fail closed: a grant past its own end is not used");
            fx.Clock.Advance(TimeSpan.FromDays(-5));
            check((await fx.Use(S1)).Kind == GrantUseKind.Denied, "fail closed: a date set back does not make a grant look current while the authority is out of reach");
            fx.Admin(GrantOps.Extend, made.GrantId!, null, true);
            check((await fx.Use(S1)).Kind == GrantUseKind.Denied, "fail closed: an indefinite grant is no more usable offline");
        }

        // Not vouched for, no use of secrets.
        using (Fixture fx = new(parent))
        {
            fx.Link.BreakReconcile = true;
            await fx.Approve(S1, 60);
            GrantUse notVouched = await fx.Use(S1);
            check(notVouched.Kind == GrantUseKind.Denied && notVouched.Message.Contains("trusted", StringComparison.Ordinal) && !fx.Host.Vouched, "not vouched: the authority answers the grant question but cannot vouch for the host: the host refuses the use (" + notVouched.Message + ")");
            int asked = 0;
            AuthorizationOutcome approved = await fx.Host.AuthorizeAsync(fx.Req(), () =>
            {
                asked++;

                return ApprovalDecision.Allow();
            }, CancellationToken.None);
            check(!approved.Decision.Approved && approved.Code == "not-vouched" && asked == 1 && approved.AuthorityMessage!.Contains("trusted", StringComparison.Ordinal), "not vouched: even an approval by the person releases nothing (" + approved.AuthorityMessage + ")");
            fx.Link.BreakReconcile = false;
            AuthorizationOutcome ok = await fx.Host.AuthorizeAsync(fx.Req(), () => ApprovalDecision.Allow(), CancellationToken.None);
            check(ok.Decision.Approved && fx.Host.Vouched, "not vouched: once the authority vouches, the approval stands");
        }

        // A restart destroys what vouched for the host and what was synchronized.
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            await fx.Approve(S1, 600);
            check(fx.Host.Vouched && fx.Host.SyncedGrants.Count == 1, "restart: before it, the host is vouched for and holds a synchronized grant");
            fx.Restart();
            check(!fx.Host.Vouched && fx.Host.SyncedGrants.Count == 0 && fx.Host.KnownRevision is null, "restart: the new service is not vouched for, holds no synchronized grant and has applied no revision");
            fx.Link.Offline = true;
            check((await fx.Use(S1)).Kind == GrantUseKind.Denied, "restart: offline after a restart nothing is covered");
            fx.Link.Offline = false;
            check(await fx.Start() == HostAuthorization.Reconciliation.Reconciled && fx.Host.Vouched && (await fx.Use(S1)).Kind == GrantUseKind.Granted, "restart: after reconciling, the grant (kept by the authority) is usable again");
        }

        // Only a verified answer vouches: a changed one is not accepted, and neither is an old one replayed.
        using (Fixture fx = new(parent))
        {
            fx.Link.TamperReconcile = r => r with { Status = "Trusted", SecurityRevision = r.SecurityRevision + 7 };
            check(await fx.Start() == HostAuthorization.Reconciliation.Unverified && !fx.Host.Vouched, "not vouched: a check-in answer that was changed on the way does not verify and vouches for nothing");
            fx.Link.TamperReconcile = null;
            await fx.Start();
            ReconcileResponse? captured = null;
            fx.Link.TamperReconcile = r =>
            {
                captured = r;

                return r;
            };
            await fx.Host.ReconcileAsync();
            fx.Link.TamperReconcile = _ => captured!;
            check(await fx.Host.ReconcileAsync() == HostAuthorization.Reconciliation.Unverified && !fx.Host.Vouched, "not vouched: an old check-in answer replayed later vouches for nothing (another request id)");
        }

        // A machine that is not Trusted is not vouched for.
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            fx.Store.Disable(fx.Fingerprint, "test");
            await fx.Host.PumpAsync();
            check(!fx.Host.Vouched && fx.Host.KnownRevision == 2, "disable: the connected host applies it at once: nothing vouches for it and the revision is applied");
            fx.Store.Enable(fx.Fingerprint, "test");
            await fx.Host.ReconcileAsync();
            check(fx.Host.Vouched && fx.Host.SyncedGrants.Count == 0, "enable: it starts clean: vouched for again, no grants");
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
            check((await fx.Use(S1)).Kind == GrantUseKind.Denied, "offline: a host that cannot hear its authority uses nothing, whatever it had");

            fx.Link.Offline = false;
            int gate = fx.Gate.Revision;
            await fx.Host.PumpAsync();
            check(fx.Host.KnownRevision == 2 && fx.Gate.Revision > gate && fx.Host.SyncedGrants.Count == 0, "reconnect: the host applies the missed revision (cleans up, invalidates the gate)");
            check((await fx.Use(S1)).Kind == GrantUseKind.NoGrant && fx.Store.FindGrant(made.GrantId!)!.Status == "invalidated", "reconnect: the old grant was invalidated by the revision and is not restored");
        }

        using (Fixture fx = new(parent))
        {
            await fx.Start();
            GrantApproval made = await fx.Approve(S1, 10);
            fx.Link.Offline = true;
            fx.Admin(GrantOps.Extend, made.GrantId!, 120);
            fx.Clock.Advance(TimeSpan.FromMinutes(11));
            check((await fx.Use(S1)).Kind == GrantUseKind.Denied, "extension offline: nothing is used while the authority cannot be reached");
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

        // Startup: the host that cannot reach its authority is not vouched for; one that can, is.
        using (Fixture fx = new(parent))
        {
            fx.Link.Offline = true;
            check(await fx.Start() == HostAuthorization.Reconciliation.Unreachable && !fx.Host.Vouched && fx.Host.KnownRevision is null, "startup: an unreachable authority leaves the host not vouched for, with no applied revision");
            check((await fx.Use(S1)).Kind == GrantUseKind.Denied, "startup: nothing is covered before the first reconciliation");
            fx.Link.Offline = false;
            check(await fx.Start() == HostAuthorization.Reconciliation.Reconciled && fx.Host.KnownRevision == 1 && fx.Host.Vouched, "startup: once the authority answers the host knows the machine status and revision and is vouched for");
        }

        using (Fixture fx = new(parent))
        {
            fx.Store.Disable(fx.Fingerprint, "test");
            check(await fx.Start() == HostAuthorization.Reconciliation.Reconciled && !fx.Host.Vouched && fx.Host.KnownRevision == 2, "startup: a Disabled machine learns its revision and is not vouched for");
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
            check(threw && SameGrant(store.FindGrant(made.GrantId!), beforeGrant) && store.Audit().Count == audits && store.PendingGrantEvents(fx.Fingerprint).Count == events && store.GetProcessedGrant("adm-fault-" + point) is null, "atomic: a fault at " + point + " during a revocation leaves the grant active, no notice, no audit row and no stored answer");
        }

        // Concurrency: two approvals of the same scope at once leave one grant.
        Fixture other = fx;
        GrantApproval[] both = await Task.WhenAll(other.Approve(Scope("race"), 10), other.Approve(Scope("race"), 10));
        check(both.All(item => item.Granted) && store.Grants().Count(grant => grant.ScopeKey == Scope("race")) == 1, "atomic: two approvals of one scope at the same time leave exactly one grant");

    }

    // ---- usage, consumption and replacement columns ----

    private static async Task UsageColumns(Action<bool, string> check, string parent)
    {
        using Fixture fx = new(parent);
        AuthorityStore store = fx.Store;
        string path = store.FilePath;
        SqliteConnection.ClearAllPools();
        using (SqliteConnection connection = new("Data Source=" + path + ";Pooling=False"))
        {
            connection.Open();
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "SELECT group_concat(name) FROM pragma_table_info('grants') WHERE name IN ('usage', 'consumed', 'replaces')";
            string columns = (string)command.ExecuteScalar()!;
            check(WithSecretsDatabase.SchemaVersion == 4 && Version(path) == 4 && columns.Split(',').Order().SequenceEqual(["consumed", "replaces", "usage"]), "usage columns: a new with-secrets.db is schema 4 with the grants columns usage, consumed and replaces (" + columns + ")");
        }

        await fx.Start();
        DateTimeOffset at = fx.Clock.GetUtcNow();
        int revision = store.Find(fx.Fingerprint)!.SecurityRevision;
        GrantResponse Dummy() => new(1, "r", "d", fx.Fingerprint, "x", "x", "x", "", "", 0, false, null, revision, at, at, "k", []);
        GrantRecord once = (await fx.Once(S1))!;
        GrantRecord plain = store.FindGrant((await fx.Approve(S2, 60)).GrantId!)!;
        check(once is { Status: "consumed", Usage: "once" } && once.Consumed == at && !once.IsUsable(at), "usage columns: a consumed once-only grant reads back as consumed, once, with the time it was consumed, and is not usable");
        check(plain is { Status: "active", Usage: "reusable", Consumed: null, Replaces: null } && plain.IsUsable(at), "usage columns: a grant made with no usage is active and reusable");
        store.ApplyGrant("usage-2", "digest", fx.Fingerprint, (tx, _) =>
        {
            check(tx.FindByScope(fx.Fingerprint, S1) is null && tx.FindByScope(fx.Fingerprint, S2)?.Id == plain!.Id, "usage columns: a consumed grant is not found by scope");

            return new AuthorityStore.GrantPlan(Dummy(), null, "", false);
        });
        string newId = GrantOps.NewGrantId();
        GrantResponse replaced = fx.Authority.AdminGrant(fx.ReplaceCommand(once.Id, newId: newId));
        check(replaced.GrantId == newId && store.FindGrant(newId)?.Replaces == once.Id, "usage columns: a given id is used verbatim and the replacement link is kept");
        check(SameGrant(store.FindGrant(once.Id), once), "usage columns: the original record stays the same");

        // Any other schema version (5 included) is refused; nothing is migrated.
        Sql(fx, "UPDATE schema_version SET version = 5");
        AuthorityDatabaseException? old = null;
        try
        {
            AuthorityStore.InFolder(fx.Machine.Folder).Grants();
        }
        catch (AuthorityDatabaseException error)
        {
            old = error;
        }

        check(old is not null && old.Message.Contains("schema version 4", StringComparison.Ordinal), "usage columns: a schema 5 with-secrets.db is refused (" + old?.Message + ")");
    }

    private static async Task Seals(Action<bool, string> check, string parent)
    {
        using Fixture fx = new(parent);
        await fx.Start();
        const string canary = "--token-canary-7f3a";
        LaunchRequest request = fx.Req();
        int revision = fx.Host.KnownRevision!.Value;
        ApprovalEvidence evidence = fx.Sign(fx.UserKey, Fixture.ApproveText(S1, revision, request) + "\nCommand: test " + canary, 60);
        GrantApproval approved = await fx.Host.ApproveGrantAsync(request, S1, () => ApprovalDecision.Allow("approved", 60, evidence), CancellationToken.None);
        GrantRecord row = fx.Store.FindGrant(approved.GrantId!)!;
        AuthorityKeyRing keys = fx.Machine.Deployment.Keys;
        string path = fx.Store.FilePath;
        string raw = string.Concat(new[] { path, path + "-wal", path + "-shm" }
            .Where(File.Exists).Select(file => Encoding.Latin1.GetString(File.ReadAllBytes(file))));
        check(row.Evidence?.Ciphertext.StartsWith(JweCipher.Prefix, StringComparison.Ordinal) == true
            && row.ReviewKey == TestState.Current(fx.Db)!.Review!.PublicKey
            && row.SealKey == KeyIdentity.Fingerprint(keys.ActivePublicKey()!)
            && !raw.Contains(canary, StringComparison.Ordinal)
            && TestVault.ReviewText(fx.Db, row) == evidence.Text, "seal: the row authenticates evidence encrypted to the review key and the database contains no plaintext command arguments");
        check((await fx.Use(S1)).Kind == GrantUseKind.Granted, "seal: ordinary grant use needs no private review key");

        GrantRecord other = fx.Store.FindGrant((await fx.Approve(S2, 60)).GrantId!)!;
        Sql(fx, "UPDATE grants SET seal = $seal WHERE id = $id", ("$seal", row.Seal), ("$id", other.Id));
        check((await fx.Use(S2)).Kind == GrantUseKind.NoGrant && fx.Store.Audit().Last(entry => entry.Event == "grant-ignored").Detail.Contains("the seal does not verify", StringComparison.Ordinal),
            "seal: a seal copied from another grant fails verification");
        keys.Rotate("test");
        check((await fx.Use(S1)).Kind == GrantUseKind.Granted && fx.Store.FindGrant(row.Id)!.SealKey == KeyIdentity.Fingerprint(keys.ActivePublicKey()!)
            && fx.Store.FindGrant(other.Id) is { Seal: null }, "seal: routine rotation reseals valid grants and clears invalid seals");

        check(new PasskeyStore(fx.Db).RemoveById(TestAuthenticator.Encode(fx.UserKey.CredentialId))
            && (await fx.Use(S1)).Kind == GrantUseKind.NoGrant
            && fx.Store.Audit().Last(entry => entry.Event == "grant-ignored").Detail.Contains("a passkey that approved or changed the grant is no longer enrolled", StringComparison.Ordinal),
            "seal: removing the signing passkey ends grant use");
        keys.Recover("test");
        check(fx.Store.Sealer!.Problem(fx.Store.FindGrant(row.Id)!) == "the grant is sealed by a key that is not the active authority key", "seal: authority recovery does not reseal old grants");
        check(fx.Admin(GrantOps.Revoke, row.Id).Outcome == GrantOps.Revoked
            && fx.Store.FindGrant(row.Id) is { Evidence: null, Seal: null, SealKey: null, ReviewKey: null }, "seal: revocation clears the evidence and seal together");
    }

    /// <summary>Answers the first check as the inner verifier does and refuses every later one, as if the passkey went away between the check and the seal.</summary>
    private sealed class FirstOnlyVerifier(IApprovalVerifier inner) : IApprovalVerifier
    {
        private int _calls;

        public ApprovalCheck Verify(ApprovalEvidence evidence, int minutes)
            => Interlocked.Increment(ref _calls) == 1 ? inner.Verify(evidence, minutes) : new ApprovalCheck(false, "", false, "seal-failure-canary passkey gone");

        public ApprovalCheck Signer(string proof) => inner.Signer(proof);
    }

    private const string SealRefused = LocalAuthority.SealRefusedDetail;

    private static async Task SealFailures(Action<bool, string> check, string parent)
    {
        bool Audited(Fixture fx, int before) => fx.Store.Audit().Skip(before).Count(entry => entry.Event == "grant-denied") == 1
            && fx.Store.Audit().Skip(before).Single(entry => entry.Event == "grant-denied") is { } row
            && row.Detail.Contains(SealRefused, StringComparison.Ordinal) && !row.Detail.Contains("canary", StringComparison.Ordinal) && !row.Detail.Contains("review key", StringComparison.Ordinal);
        bool Signed(Fixture fx, GrantResponse? response) => response is { Outcome: GrantOps.Denied, ReasonCode: GrantReasons.BadEvidence } && response.Verify(fx.Machine.Deployment.Keys.CurrentRecord().PublicKey);

        // No review key: passkeys are enrolled but no store (and so no review key) is set up yet, so the evidence cannot be kept encrypted.
        using (Fixture fx = new(parent, withStore: false))
        {
            await fx.Start();
            int audits = fx.Store.Audit().Count;
            GrantApproval made = await fx.Approve(S1, 60);
            check(!made.Granted && Signed(fx, fx.Link.LastGrant) && fx.Store.Grants().Count == 0 && Audited(fx, audits),
                "seal failure (no review key): the approval is a signed refusal, no grant row, one grant-denied audit row with a constant reason (" + made.Message + ")");
            audits = fx.Store.Audit().Count;
            GrantRecord? once = await fx.Once(S2);
            check(once is null && Signed(fx, fx.Link.LastGrant) && fx.Store.Grants().Count == 0 && Audited(fx, audits), "seal failure (no review key): approve once is a signed refusal and records nothing");
        }

        // The evidence check at the seal fails (the passkey went away between the first check and the seal).
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            IApprovalVerifier verifier = fx.Authority.Verifier!;
            fx.Authority.Verifier = new FirstOnlyVerifier(verifier);
            int audits = fx.Store.Audit().Count;
            GrantApproval made = await fx.Approve(S1, 60);
            check(!made.Granted && Signed(fx, fx.Link.LastGrant) && fx.Store.Grants().Count == 0 && Audited(fx, audits),
                "seal failure (evidence): the approval is a signed refusal, no grant row, one grant-denied audit row without the evidence problem text");

            fx.Authority.Verifier = new FirstOnlyVerifier(verifier);
            audits = fx.Store.Audit().Count;
            check(await fx.Once(S2) is null && Signed(fx, fx.Link.LastGrant) && fx.Store.Grants().Count == 0 && Audited(fx, audits), "seal failure (evidence): approve once is a signed refusal and records nothing");

            fx.Authority.Verifier = verifier;
            GrantApproval good = await fx.Approve(S1, 60);
            GrantRecord before = fx.Store.FindGrant(good.GrantId!)!;
            fx.Authority.Verifier = new FirstOnlyVerifier(verifier);
            audits = fx.Store.Audit().Count;
            GrantResponse extended = fx.Admin(GrantOps.Extend, before.Id, 30);
            check(Signed(fx, extended) && SameGrant(fx.Store.FindGrant(before.Id), before) && Audited(fx, audits), "seal failure (evidence): an admin extend is a signed refusal, the grant is unchanged, one grant-denied audit row");

            fx.Authority.Verifier = verifier;
            GrantApproval ending = await fx.Approve(Scope("seal-renew"), 5);
            fx.Clock.Advance(TimeSpan.FromMinutes(6));
            GrantRecord ended = fx.Store.FindGrant(ending.GrantId!)!;
            fx.Authority.Verifier = new FirstOnlyVerifier(verifier);
            audits = fx.Store.Audit().Count;
            GrantResponse renewed = fx.Admin(GrantOps.Renew, ended.Id, 30);
            check(Signed(fx, renewed) && SameGrant(fx.Store.FindGrant(ended.Id), ended) && Audited(fx, audits), "seal failure (evidence): an admin renew is a signed refusal, the ended grant is unchanged, one grant-denied audit row");

            fx.Authority.Verifier = verifier;
            GrantRecord original = (await fx.Once(Scope("seal-once")))!;
            GrantRecord originalBefore = fx.Store.FindGrant(original.Id)!;
            int rows = fx.Store.Grants().Count;
            fx.Authority.Verifier = new FirstOnlyVerifier(verifier);
            audits = fx.Store.Audit().Count;
            GrantResponse replaced = fx.Authority.AdminGrant(fx.ReplaceCommand(original.Id));
            check(Signed(fx, replaced) && fx.Store.Grants().Count == rows && SameGrant(fx.Store.FindGrant(original.Id), originalBefore) && Audited(fx, audits),
                "seal failure (evidence): an admin replace is a signed refusal, no new row, the original grant unchanged, one grant-denied audit row");
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

    // ---- grant scope and evidence (security review H1, H2, L1, L5, L6) ----

    /// <summary>Writes with-secrets.db behind the program's back, as another process of the same user could.</summary>
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
            Sql(fx, "UPDATE grants SET evidence_nonce = $n, evidence_ciphertext = $t, evidence_proof = $p WHERE id = $id", ("$n", rowA.Evidence!.Nonce), ("$t", rowA.Evidence.Ciphertext), ("$p", rowA.Evidence.Proof), ("$id", b.GrantId));
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
            check(fx.Admin(GrantOps.Extend, id, 30, who: TestAuthenticator.ES256()) is { Outcome: GrantOps.Denied, ReasonCode: GrantReasons.BadEvidence } && SameGrant(fx.Store.FindGrant(id), before), "grant evidence: a change signed by an unenrolled key changes nothing");
            GrantAdminCommand good = fx.Command(GrantOps.Extend, id, 30);
            check(fx.Authority.AdminGrant(good with { NewEnd = good.NewEnd!.Value.AddDays(1) }) is { ReasonCode: GrantReasons.BadEvidence } && fx.Authority.AdminGrant(good with { Evidence = null, RequestId = "adm-none" }) is { ReasonCode: GrantReasons.NoEvidence } && SameGrant(fx.Store.FindGrant(id), before),
                "admin evidence: an end other than the one the signed page showed, or no assertion, is refused");
            GrantApproval other = await fx.Approve(S2, 60);
            GrantAdminCommand forOther = fx.Command(GrantOps.Extend, other.GrantId!, 30);
            check(fx.Authority.AdminGrant(forOther with { GrantId = id, RequestId = "adm-swap" }) is { ReasonCode: GrantReasons.BadEvidence } && SameGrant(fx.Store.FindGrant(id), before), "admin evidence: an admin assertion for one grant does not change another");
            GrantResponse applied = fx.Authority.AdminGrant(good);
            check(applied is { Outcome: GrantOps.Extended } && fx.Store.FindGrant(id) is { Revision: 2, Evidence.Kind: GrantEvidence.AdminKind } && (await fx.Use(S1)).Kind == GrantUseKind.Granted, "admin evidence: the right assertion extends the grant, the row then carries the admin evidence, and it verifies on use");
            check(applied.SecurityRevision == fx.Store.Find(fx.Fingerprint)!.SecurityRevision, "admin answer: the security revision in it is the machine's, read where the change was applied");
            check(fx.Admin(GrantOps.Revoke, id, who: TestAuthenticator.ES256()) is { ReasonCode: GrantReasons.BadEvidence } && fx.Store.FindGrant(id) is { Status: "active" }, "grant evidence: revocation also requires an enrolled passkey");
        }

        // L1: an error of the authority is not "offline".
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            await fx.Approve(S1, 60);
            HostAuthorization direct = new(fx.Authority, fx.Machine.Deployment.MachineKey, fx.Machine.HostName, fx.Machine.Deployment.HostConfig, new LaunchGate(), (requestId, digest, present) => fx.Authority.Offer(requestId, digest, present), fx.Clock, fx.Mono);
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
            check(failing.Kind == GrantUseKind.Denied && failing.Message.Contains("could not be asked", StringComparison.Ordinal), "local errors: a database error of the local authority is a refusal, never 'offline' (no use of an earlier answer) (" + failing.Kind + ")");
            check(flaky.Kind == GrantUseKind.Denied, "local errors: nor is a non-transport error of any authority (" + flaky.Kind + ")");
        }

        // L3: a check-in that cannot be checked takes the vouching.
        using (Fixture fx = new(parent))
        {
            await fx.Start();
            await fx.Approve(S1, 600);
            fx.Link.TamperReconcile = r => r with { Signature = null! };
            await fx.Host.ReconcileAsync();
            check(!fx.Host.Vouched, "check-in: an answer that cannot be checked ends the vouching");
            check((await fx.Use(S1)).Kind != GrantUseKind.Granted && !fx.Host.Vouched, "check-in: after a check-in that cannot be checked the grant covers nothing (no run under it is authorized)");
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

    // ---- every approval is a grant: "Approve once" records a consumed once-only grant ----

    private static async Task OnceGrants(Action<bool, string> check, string parent)
    {
        using TestAuthenticator key = TestAuthenticator.ES256();

        // (a) A run approved once on the page leaves one consumed once-only grant for its scope; it covers nothing.
        Chooser once = new(0, signer: key);
        using (HostServiceTests.Rig rig = new(parent, approver: () => once, enrolled: key))
        {
            string program = Show(rig);
            AuthorityStore store = rig.Machine.Deployment.Store;
            HostServiceTests.Raw first = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            check(first.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 0 } && File.Exists(Marker(rig)) && once.Requests.Count == 1, "once: a run approved once on the page runs (" + first.Stderr.Trim() + ")");
            IReadOnlyList<GrantRecord> rows = store.Grants();
            check(rows is [{ Usage: GrantUsage.Once, Status: "consumed", Expires: null, Consumed: not null, Evidence: { Kind: GrantEvidence.ApproveKind, Minutes: 0 } }] && rows[0].Fingerprint == rig.Machine.Fingerprint && rows[0].Program == program && rows[0].SecretNames == "TOKEN",
                "once: the approval leaves exactly one grant row for its scope: usage once, status consumed, no end, consumed now, evidence kind approve with minutes 0 (" + string.Join(" | ", rows.Select(row => row.Usage + "/" + row.Status)) + ")");
            check(rows.Count == 1 && rig.Machine.Deployment.Store.Sealer!.Problem(rows[0]) is null, "once: the consumed row's seal verifies");
            check(rows.Count == 1 && store.Audit().Any(entry => entry.Event == "grant-once-recorded" && entry.Detail.Contains("grant " + rows[0].Id + ", once, by ", StringComparison.Ordinal)), "once: the authority audit records grant-once-recorded with the grant id and who approved");
            check(rig.Service.Authorization.SyncedGrants.Count == 0, "once: the host never syncs the once-only grant");
            if (rows.Count == 1)
            {
                LaunchRequest again = HostServiceTests.Req(rig, program);
                GrantResponse use = await rig.Machine.Deployment.Authority.GrantAsync(GrantEnvelope.Create(GrantOps.Use, again, rows[0].ScopeKey, rig.Machine.HostName, rig.Machine.Deployment.MachineKey));
                check(use is { Outcome: GrantOps.None } && !use.HasGrant, "once: a use for the same scope answers none (a consumed grant covers no run) (" + use.Outcome + ")");
            }

            // (b) The same command approved once again adds a second consumed row; nothing is updated in place.
            File.Delete(Marker(rig));
            HostServiceTests.Raw second = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            IReadOnlyList<GrantRecord> both = store.Grants();
            check(second.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 0 } && once.Requests.Count == 2 && both.Count == 2 && both.All(row => row is { Usage: GrantUsage.Once, Status: "consumed", Revision: 1 }) && both[0].Id != both[1].Id && both[0].ScopeKey == both[1].ScopeKey,
                "once: a second approve once of the same command asks again and adds a second consumed row (" + both.Count + ")");
        }

        // (c) A run approved with a time still makes one reusable, active grant.
        Chooser timed = new(60, signer: key, offersTime: true);
        using (HostServiceTests.Rig rig = new(parent, approver: () => timed, enrolled: key))
        {
            string program = Show(rig);
            HostServiceTests.Raw run = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            IReadOnlyList<GrantRecord> rows = rig.Machine.Deployment.Store.Grants();
            check(run.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 0 } && rows is [{ Usage: GrantUsage.Reusable, Status: "active", Expires: not null, Consumed: null, Evidence.Minutes: 60 }],
                "timed: a run approved with a time makes one reusable, active grant (" + run.Stderr.Trim() + " " + string.Join(" | ", rows.Select(row => row.Usage + "/" + row.Status)) + ")");
            File.Delete(Marker(rig));
            HostServiceTests.Raw covered = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            check(covered.Result is { Outcome: LaunchOutcome.Exited } && timed.Requests.Count == 1 && rig.Machine.Deployment.Store.Grants().Count == 1 && covered.Stderr.Contains("a grant covers this request", StringComparison.Ordinal), "timed: the next run of the same command is covered by that grant (no page)");
        }

        // (d) The authority locks between the tap and the record: nothing runs, the launch is audited grant-not-made, no row.
        {
            string folder = Path.Combine(parent, "once-lock-" + Guid.NewGuid().ToString("N")[..6]);
            using TestMachine machine = new(folder);
            FlakyAuthority link = new(machine.Deployment.Authority);
            machine.Deployment.Link = link;
            Chooser tap = new(0, signer: key);
            using HostServiceTests.Rig rig = new(parent, approver: () => tap, machine: machine, enrolled: key);
            // The run was approved (the tap and the authority's decision are done); the authority locks as the once-only grant is about to be recorded.
            link.BeforeGrant = envelope =>
            {
                if (envelope.Operation == GrantOps.Approve)
                {
                    machine.Deployment.Keys.LockState?.Lock("locked between the tap and the record (test)");
                }
            };
            string program = Show(rig);
            HostServiceTests.Raw run = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            check(run.Result is { ExitCode: RunCommand.Denied } && tap.Requests.Count == 1 && !File.Exists(Marker(rig)) && rig.Store.Reads == 0, "once lock: a lock between the tap and the record refuses the run with exit 3; no child started, nothing decrypted (" + run.Result?.ExitCode + " " + run.Stderr.Trim() + ")");
            check(machine.Deployment.Store.Grants().Count == 0, "once lock: no grant row is written");
            // The uploader is woken by every recorded event, so an event may already have reached the authority (before the lock) or still be in the
            // host's outbox. Read the outbox first, then the authority's history: an event acknowledged in between is in the history, so none is missed.
            IEnumerable<AuditEvent> pending = rig.Service.Audit.Outbox.Pending(1000);
            IEnumerable<AuditEvent> uploaded = machine.Deployment.Store.AuditHistory(new AuditQuery(Limit: AuditQuery.MaxLimit)).Select(record => record.Event);
            string audit = string.Join((char)10, pending.Concat(uploaded).Select(item => item.ToJson()));
            check(audit.Contains("\"outcome\":\"approved\"", StringComparison.Ordinal) && audit.Contains("grant-not-made", StringComparison.Ordinal), "once lock: the run was approved, and the launch is audited as failed, grant-not-made (" + audit.Length + " bytes of events)");
        }
    }

    // ---- lifetime policy: extend and renew keep the existing bounds (1 to 1440 minutes, or no end) ----

    private static async Task LifetimePolicy(Action<bool, string> check, string parent)
    {
        using Fixture fx = new(parent);
        await fx.Start();
        DateTimeOffset t0 = fx.Clock.GetUtcNow();

        // A 1-hour grant extended by 1380 minutes ends exactly 24 hours after its creation; each applied change raises the revision by 1 and is audited with the grant id.
        string id = (await fx.Approve(S1, 60)).GrantId!;
        GrantResponse day = fx.Admin(GrantOps.Extend, id, 1380);
        check(day is { Outcome: GrantOps.Extended } && fx.Store.FindGrant(id) is { Revision: 2 } dayGrant && dayGrant.Expires == t0.AddHours(24), "lifetime: a 60-minute grant extended by 1380 minutes ends exactly 24 hours after its creation (revision 2)");
        check(fx.Store.Audit().Any(entry => entry.Event == "grant-extended" && entry.Detail.Contains(id, StringComparison.Ordinal)), "lifetime: grant-extended names the grant id");

        // Extended to no end.
        check(fx.Admin(GrantOps.Extend, id, null, true) is { Outcome: GrantOps.Extended } && fx.Store.FindGrant(id) is { Revision: 3, Expires: null }, "lifetime: extended indefinite the grant has no end (revision 3)");

        // The bounds of the time: 0 and 1441 minutes are refused with no time chosen, and nothing changes.
        string bounded = (await fx.Approve(S2, 60)).GrantId!;
        check(fx.Admin(GrantOps.Extend, bounded, 0) is { Outcome: GrantOps.Denied, ReasonCode: GrantReasons.NoTime } && fx.Admin(GrantOps.Extend, bounded, 1441) is { Outcome: GrantOps.Denied, ReasonCode: GrantReasons.NoTime } && fx.Store.FindGrant(bounded) is { Revision: 1 } untouched && untouched.Expires == t0.AddMinutes(60), "lifetime: extend by 0 or by 1441 minutes is refused no-time-chosen and changes nothing");
        check(fx.Admin(GrantOps.Renew, bounded, 0) is { ReasonCode: GrantReasons.NoTime } && fx.Admin(GrantOps.Renew, bounded, 1441) is { ReasonCode: GrantReasons.NoTime }, "lifetime: renew by 0 or by 1441 minutes is refused no-time-chosen");

        // Renew: only an ended grant; the new end is counted from now.
        check(fx.Admin(GrantOps.Renew, bounded, 60) is { Outcome: GrantOps.Denied, ReasonCode: GrantReasons.NotExpired } && fx.Store.FindGrant(bounded)!.Revision == 1, "lifetime: renew of an active unexpired grant is refused grant-not-expired");
        fx.Clock.Advance(TimeSpan.FromMinutes(61));
        GrantResponse renewed = fx.Admin(GrantOps.Renew, bounded, 60);
        check(renewed is { Outcome: GrantOps.Renewed } && fx.Store.FindGrant(bounded) is { Revision: 2 } renewedGrant && renewedGrant.Expires == fx.Clock.GetUtcNow().AddMinutes(60), "lifetime: renew of an expired grant by 60 ends 60 minutes from now (revision 2)");
        check(fx.Store.Audit().Any(entry => entry.Event == "grant-renewed" && entry.Detail.Contains(bounded, StringComparison.Ordinal)), "lifetime: grant-renewed names the grant id");

        // A revoked grant is neither extended nor renewed (replace is checked with replace itself).
        check(fx.Admin(GrantOps.Revoke, bounded) is { Outcome: GrantOps.Revoked }, "lifetime: the grant is revoked");
        check(fx.Admin(GrantOps.Extend, bounded, 5) is { ReasonCode: GrantReasons.NotActive } && fx.Admin(GrantOps.Renew, bounded, 5) is { ReasonCode: GrantReasons.NotActive }, "lifetime: extend and renew of a revoked grant are refused grant-not-active");

        // A consumed once-only grant cannot be extended when an existing grant already covers the scope.
        int revision = fx.Host.KnownRevision ?? 1;
        ApprovalDecision decision = ApprovalDecision.Allow("approved with passkey key-one", 0, fx.Sign(fx.UserKey, Fixture.ApproveText(S1, revision), 0));
        GrantApproval onceMade = await fx.Host.RecordOnceGrantAsync(fx.Req(), S1, decision, CancellationToken.None);
        GrantRecord? once = onceMade.GrantId is null ? null : fx.Store.FindGrant(onceMade.GrantId);
        check(once is { Usage: GrantUsage.Once, Status: "consumed" }, "lifetime: a consumed once-only grant exists (" + onceMade.Message + ")");
        if (once is not null)
        {
            DateTimeOffset now = fx.Clock.GetUtcNow();
            check(fx.Admin(GrantOps.Extend, once.Id, 60) is { Outcome: GrantOps.Denied, ReasonCode: GrantReasons.Exists } && fx.Admin(GrantOps.Renew, once.Id, 5) is { Outcome: GrantOps.Denied, ReasonCode: GrantReasons.NotActive } && fx.Store.FindGrant(once.Id)!.Revision == once.Revision, "lifetime: another grant blocks extending a used approval, and it cannot be renewed");
            check(AdminService.GrantProblem("extend", once, now) is not null && AdminService.GrantProblem("renew", once, now) == "this grant was used once; extend it to allow repeat runs", "lifetime: the app requires verified evidence to extend an existing consumed grant and guides renewal toward extension");
        }
    }

    private static async Task ExtendOnceGrants(Action<bool, string> check, string parent)
    {
        using Fixture fx = new(parent);
        await fx.Start();
        GrantRecord once = (await fx.Once(S1))!;
        DateTimeOffset now = fx.Clock.GetUtcNow();
        GrantAdminCommand command = fx.Command(GrantOps.Extend, once.Id, 43200, endOverride: now.AddDays(30));
        check(fx.Authority.AdminGrant(command with { Evidence = null }) is { ReasonCode: GrantReasons.NoEvidence }
            && SameGrant(fx.Store.FindGrant(once.Id), once), "extending a used grant requires a signed assertion");
        check(fx.Authority.AdminGrant(command with { Minutes = 1440 }) is { ReasonCode: GrantReasons.NoTime }
            && SameGrant(fx.Store.FindGrant(once.Id), once), "the signed end cannot exceed the selected duration");
        GrantResponse extended = fx.Authority.AdminGrant(command);
        GrantRecord? current = fx.Store.FindGrant(once.Id);
        check(extended is { Outcome: GrantOps.Extended } && current is { Usage: GrantUsage.Reusable, Status: "active", Revision: 2 }
            && current.Expires == now.AddDays(30) && current.ScopeKey == once.ScopeKey && fx.Store.Grants().Count == 1
            && fx.Store.Sealer!.Problem(current) is null, "a 30-day extension seals the original grant with the same id and scope");
        GrantRecord other = (await fx.Once(S2))!;
        check(fx.Admin(GrantOps.Extend, other.Id, indefinite: true) is { Outcome: GrantOps.Extended }
            && fx.Store.FindGrant(other.Id) is { Usage: GrantUsage.Reusable, Expires: null, Revision: 2 },
            "Always extends the existing grant with no end");
    }

    // ---- replace: a consumed once-only grant becomes a new reusable grant for exactly its scope (an admin's tap; the original is kept as it was) ----

    internal static bool SameGrant(GrantRecord? row, GrantRecord expected)
        => row is not null && (row with { Seal = expected.Seal }) == expected
            && (row.Seal is null ? expected.Seal is null : expected.Seal is not null && row.Seal.AsSpan().SequenceEqual(expected.Seal));

    private static int Replacements(Fixture fx, string originalId) => fx.Store.Grants().Count(row => row.Replaces == originalId);

    private static async Task ReplaceGrants(Action<bool, string> check, string parent)
    {
        using Fixture fx = new(parent);
        await fx.Start();
        GrantRecord? original = await fx.Once(S1);
        check(original is { Usage: GrantUsage.Once, Status: "consumed", Revision: 1 }, "replace: a consumed once-only grant exists");
        if (original is null)
        {
            return;
        }

        DateTimeOffset now = fx.Clock.GetUtcNow();
        check(AdminService.GrantProblem("replace", original, now, fx.Store) is null, "replace: the admin app offers replace for a consumed once-only grant whose evidence verifies");

        // Replace by 1440 minutes: a new active reusable grant that copies the scope exactly and is linked to the original.
        GrantAdminCommand replace = fx.ReplaceCommand(original.Id, 1440, requestId: "adm-replace-1");
        GrantResponse replaced = fx.Authority.AdminGrant(replace);
        GrantRecord? fresh = fx.Store.FindGrant(replace.NewGrantId!);
        check(replaced is { Outcome: GrantOps.Replaced, ReasonCode: GrantReasons.Ok, Operation: GrantOps.Replace } && replaced.GrantId == replace.NewGrantId && replaced.Verify(fx.Machine.Deployment.Keys.CurrentRecord().PublicKey),
            "replace: the authority answers replaced (signed) with the new grant's id (" + replaced.Outcome + " " + replaced.ReasonCode + ")");
        check(fresh is { Status: "active", Usage: GrantUsage.Reusable, Revision: 1, Consumed: null, Evidence.Kind: GrantEvidence.AdminKind } && fresh.Replaces == original.Id && fresh.Expires == now.AddMinutes(1440),
            "replace: the new row is active, reusable, revision 1, ends 1440 minutes from now, carries admin evidence and names the original it replaces");
        check(fresh is not null && fresh.ScopeKey == original.ScopeKey && fresh.Fingerprint == original.Fingerprint && fresh.Program == original.Program && fresh.WorkingDirectory == original.WorkingDirectory && fresh.SecretNames == original.SecretNames && fresh.SecurityRevision == original.SecurityRevision,
            "replace: scope key, machine, program, folder, secret names and security revision are copied from the original exactly");
        check(fresh is not null && fx.Store.Sealer!.Problem(fresh) is null, "replace: the new row is sealed");
        check(SameGrant(fx.Store.FindGrant(original.Id), original), "replace: the original row is not modified (still consumed)");
        GrantResponse use = await fx.Authority.GrantAsync(GrantEnvelope.Create(GrantOps.Use, fx.Req(), S1, fx.Machine.HostName, fx.Machine.Deployment.MachineKey));
        check(use is { Outcome: GrantOps.Granted } && use.GrantId == replace.NewGrantId, "replace: a use for the scope is granted by the new grant, with no tap (" + use.Outcome + ")");
        check(fx.Store.Audit().Any(entry => entry.Event == "grant-replaced" && entry.Detail.Contains($"grant {replace.NewGrantId} replaces {original.Id} by test admin; 1440 min", StringComparison.Ordinal)), "replace: audited grant-replaced with the new and the original id, who, and the time");

        // Idempotent: the same request id gets the stored answer; the evidence under another request id is refused (its grant id exists).
        GrantResponse again = fx.Authority.AdminGrant(replace);
        check(again.Signature.SequenceEqual(replaced.Signature) && Replacements(fx, original.Id) == 1, "replace: the same request id retried returns the stored answer and makes no second row");
        check(fx.Authority.AdminGrant(replace with { RequestId = "adm-replace-replay" }) is { Outcome: GrantOps.Denied, ReasonCode: GrantReasons.BadEvidence } && Replacements(fx, original.Id) == 1, "replace: the evidence replayed under another request id is refused bad-evidence (the grant id it names exists)");

        // An active grant for the scope already: another consumed once row of it is not replaced.
        GrantRecord? second = await fx.Once(S1);
        check(second is not null && fx.Authority.AdminGrant(fx.ReplaceCommand(second.Id, 60)) is { Outcome: GrantOps.Denied, ReasonCode: GrantReasons.Exists } && Replacements(fx, second.Id) == 0, "replace: refused while an active grant covers the scope (grant-exists)");

        // Only a consumed once row: an active reusable grant, and a revoked one, are refused.
        check(AdminService.GrantProblem("replace", fresh!, now, fx.Store) is not null && fx.Authority.AdminGrant(fx.ReplaceCommand(fresh!.Id, 60)) is { ReasonCode: GrantReasons.NotActive }, "replace: an active reusable grant is not replaced");
        check(fx.Admin(GrantOps.Revoke, fresh!.Id) is { Outcome: GrantOps.Revoked } && fx.Store.FindGrant(fresh.Id) is { Status: "revoked" } revoked
            && AdminService.GrantProblem("replace", revoked, now, fx.Store) is not null && fx.Authority.AdminGrant(fx.ReplaceCommand(fresh.Id, 60)) is { ReasonCode: GrantReasons.NotActive } && Replacements(fx, fresh.Id) == 0, "replace: a revoked grant is not replaced (grant-not-active)");

        // A planted consumed once row (no person's assertion backs it) is offered nothing and not replaced.
        GrantRecord? other = await fx.Once(S2);
        Sql(fx, $"INSERT INTO grants (id, fingerprint, scope_key, program, working_directory, secret_names, created, updated, expires, grant_revision, security_revision, status, approved_by, revoked, evidence_kind, evidence_nonce, evidence_ciphertext, evidence_proof, evidence_minutes, usage, consumed, replaces) "
            + "SELECT 'g-planted0001', fingerprint, scope_key, program, working_directory, secret_names, created, updated, expires, grant_revision, security_revision, status, approved_by, revoked, NULL, NULL, NULL, NULL, NULL, usage, consumed, replaces FROM grants WHERE id = $id", ("$id", other!.Id));
        GrantRecord? planted = fx.Store.FindGrant("g-planted0001");
        check(planted is { Status: "consumed", Usage: GrantUsage.Once, Evidence: null } && AdminService.GrantProblem("replace", planted, now, fx.Store) is not null, "replace: the admin app does not offer replace for a planted consumed row");
        check(fx.Authority.AdminGrant(fx.ReplaceCommand("g-planted0001", 60)) is { Outcome: GrantOps.Denied, ReasonCode: GrantReasons.NotActive } && Replacements(fx, "g-planted0001") == 0, "replace: a planted consumed row is not replaced (no person's assertion backs it)");
        check(AdminService.GrantProblem("replace", other, now) is not null, "replace: with no verifier nothing is offered (fails closed)");

        // The evidence: an ordinary key, none, another end, another new id, or another original's page is refused, and nothing is made.
        GrantAdminCommand good = fx.ReplaceCommand(other.Id, null, true);
        check(fx.Authority.AdminGrant(fx.ReplaceCommand(other.Id, 60, who: TestAuthenticator.ES256())) is { ReasonCode: GrantReasons.BadEvidence }, "replace: a page signed by an unenrolled key is refused bad-evidence");
        check(fx.Authority.AdminGrant(good with { RequestId = "adm-rp-none", Evidence = null }) is { ReasonCode: GrantReasons.NoEvidence }, "replace: no evidence is refused no-evidence");
        check(fx.Authority.AdminGrant(good with { RequestId = "adm-rp-end", Indefinite = false, Minutes = 60, NewEnd = fx.Clock.GetUtcNow().AddMinutes(60) }) is { ReasonCode: GrantReasons.BadEvidence }, "replace: another end than the page said is refused bad-evidence");
        check(fx.Authority.AdminGrant(good with { RequestId = "adm-rp-id", NewGrantId = "g-AAAAAAAAAAAA" }) is { ReasonCode: GrantReasons.BadEvidence }, "replace: another new grant id than the page said is refused bad-evidence");
        check(fx.Authority.AdminGrant(good with { RequestId = "adm-rp-swap", GrantId = second!.Id }) is { ReasonCode: GrantReasons.BadEvidence }, "replace: the page of one original does not replace another");
        check(Replacements(fx, other.Id) == 0 && fx.Store.FindGrant("g-AAAAAAAAAAAA") is null, "replace: none of those made a row");
        GrantResponse forever = fx.Authority.AdminGrant(good);
        check(forever is { Outcome: GrantOps.Replaced } && fx.Store.FindGrant(good.NewGrantId!) is { Expires: null, Status: "active" } noEnd && fx.Store.Sealer!.Problem(noEnd) is null
            && fx.Store.Audit().Any(entry => entry.Event == "grant-replaced" && entry.Detail.Contains($"grant {good.NewGrantId} replaces {other.Id} by test admin; indefinite", StringComparison.Ordinal)), "replace: indefinite makes a grant with no end (audited indefinite)");

        // The machine's security revision changed since the once grant: refused authorization-changed; the grants it ended are not replaced either.
        GrantRecord? third = await fx.Once(Scope("three"));
        check(fx.Store.Disable(fx.Fingerprint, "test").Ok && fx.Store.Enable(fx.Fingerprint, "test").Ok && fx.Store.Find(fx.Fingerprint)!.SecurityRevision > third!.SecurityRevision, "replace: the machine's security revision changes (disabled and enabled)");
        check(fx.Authority.AdminGrant(fx.ReplaceCommand(third!.Id, 60)) is { Outcome: GrantOps.Denied, ReasonCode: ReasonCodes.AuthorizationChanged } && Replacements(fx, third.Id) == 0, "replace: refused authorization-changed when the security revision changed");
        check(fx.Store.FindGrant(good.NewGrantId!) is { Status: "invalidated" } invalidated && AdminService.GrantProblem("replace", invalidated, now, fx.Store) is not null && fx.Authority.AdminGrant(fx.ReplaceCommand(invalidated.Id, 60)) is { ReasonCode: GrantReasons.NotActive }, "replace: an invalidated grant is not replaced");
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
            HttpBrowserFixture = true,
            CommandLineEndpoint = HostServiceTests.Rig.TestEndpoint(),
            Lock = AuthorityLock.UnlockedForTests(),
            State = fx.Db,
            Store = new HostServiceTests.CountingStore(new Dictionary<string, string> { ["TOKEN"] = "x" }),
            Deployment = fx.Machine.Deployment,
            Port = 0,
            AdminAskerFactory = announce =>
            {
                ApprovalSettings settings = new(null, 0, TimeSpan.FromSeconds(4));
                PasskeyMethod method = new(new PasskeyStore(fx.Db), settings);
                EnrollmentTarget target = EnrollmentTarget.For(method, new WebApprover(method, settings, announce, TimeSpan.Zero));

                return new TargetAdminAsker(target, target);
            },
        });
        using HttpClient http = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(30) };
        AdminBrowser browser = new(service, http);
        check(await browser.SignInAsync(phone), "grant management: the convenience key signs in with one tap");
        TestAuthenticator unenrolled = TestAuthenticator.ES256();

        // The grants view lists each grant (no scope key), with its state and end; it needs the session.
        (int listStatus, string listHtml, _) = await browser.GetAsync("/api/v1/grants");
        check(listStatus == 200 && listHtml.Contains(id, StringComparison.Ordinal) && listHtml.Contains("active", StringComparison.Ordinal) && !listHtml.Contains(S1, StringComparison.Ordinal), "admin grants: the grants view shows the grant and its state, and not the scope key");
        AdminBrowser stranger = new(service, http);
        check((await stranger.GetAsync("/api/v1/grants")).Status == 200, "admin grants: metadata is available without a session");

        string before = Snap(fx, id);
        async Task<Tapped> Op(string op, TestAuthenticator? who, bool uv = true, Func<byte[], byte[]>? change = null, params (string, string)[] args) => await browser.OpAsync(op, who, uv, change, true, args);

        Tapped none = await Op("grant-extend", null, true, null, ("id", id), ("minutes", "30"));
        await Task.Delay(TimeSpan.FromSeconds(5));
        check(none.Link is not null && Snap(fx, id) == before, "admin grants extend: with no passkey answer nothing changes");
        Tapped wrong = await Op("grant-extend", unenrolled, true, null, ("id", id), ("minutes", "30"));
        check(wrong.ApproveStatus == 403 && Snap(fx, id) == before, "grant extend: an unenrolled key changes nothing");
        Tapped noUv = await Op("grant-extend", laptop, false, null, ("id", id), ("minutes", "30"));
        Tapped otherChallenge = await Op("grant-extend", laptop, true, challenge => SHA256.HashData(challenge), ("id", id), ("minutes", "30"));
        check(noUv.ApproveStatus == 403 && otherChallenge.ApproveStatus is 403 or 400 && Snap(fx, id) == before, "admin grants extend: no user verification, or a signature over another challenge, changes nothing");
        Tapped noUvRevoke = await Op("grant-revoke", laptop, false, null, ("id", id));
        Tapped wrongRevoke = await Op("grant-revoke", unenrolled, true, null, ("id", id));
        check(noUvRevoke.ApproveStatus == 403 && wrongRevoke.ApproveStatus == 403 && Snap(fx, id) == before, "admin grants revoke: no user verification, or an unenrolled key, revokes nothing");

        // The session alone changes nothing: every request so far had a session and no genuine tap.
        check(Snap(fx, id) == before && fx.Store.FindGrant(id) is { Revision: 1 }, "admin grants: a signed-in session without a genuine tap changes no grant");

        Tapped ok = await Op("grant-extend", phone, true, null, ("id", id[..6]), ("minutes", "30"));
        string text = ok.Page;
        check(ok.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => fx.Store.FindGrant(id) is { Revision: 2 } extended && extended.Expires == fx.Clock.GetUtcNow().AddMinutes(90)), "grant extend: a convenience key extends a grant found by an id prefix");
        check((await fx.Use(S1)).Kind == GrantUseKind.Granted, "grant extend: a grant signed by a convenience key still covers the run");
        string settled = Snap(fx, id);
        TestState.Post(http, ok.PageUrl + "/proof", ok.ProofBody);
        await Task.Delay(300);
        check(Snap(fx, id) == settled, "admin grants extend: replaying the proof does not extend it again");
        check(text.Contains("extend this grant by 30 minutes", StringComparison.Ordinal) && text.Contains(id, StringComparison.Ordinal) && text.Contains(KeyIdentity.Display(fx.Fingerprint), StringComparison.Ordinal) && text.Contains(fx.Machine.HostName, StringComparison.Ordinal), "admin grants extend: the page (which the passkey signs) shows the action, the grant, the machine's fingerprint and host name");
        check(fx.Store.Audit().Any(entry => entry.Event == "grant-extended" && entry.Detail.Contains("user-key", StringComparison.Ordinal)), "grant extend: the authority audit names the convenience key that tapped");

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
        string staleState = await browser.WaitAuthorizationAsync(stalePage.AuthorizationId!);
        (HttpMethod staleMethod, string stalePath, string staleBody) = browser.MutationRequest("grant-revoke", stalePage.AuthorizationId, ("id", id));
        (int staleMutation, _) = await browser.SendAsync(staleMethod, stalePath, staleBody);
        check(fx.Store.FindGrant(id) is { Status: "active" } && staleStatus != 0 && staleState == "consumed" && staleMutation == 409, "admin grants revoke: a grant that changed between the authorization and the tap is not revoked by the tap (failed, 409)");

        Tapped revoke = await Op("grant-revoke", phone, true, null, ("id", id));
        check(revoke.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => fx.Store.FindGrant(id) is { Status: "revoked" }) && revoke.Page.Contains("revoke this grant", StringComparison.Ordinal) && (await fx.Use(S1)).Kind == GrantUseKind.NoGrant, "admin grants revoke: the tap revokes it and the page named exactly that action");

        GrantApproval short1 = await fx.Approve(Scope("short"), 10);
        fx.Clock.Advance(TimeSpan.FromMinutes(11));
        Tapped renew = await Op("grant-renew", phone, true, null, ("id", short1.GrantId!), ("minutes", "15"));
        check(renew.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => fx.Store.FindGrant(short1.GrantId!) is { } renewed && renewed.Expires == fx.Clock.GetUtcNow().AddMinutes(15)) && renew.Page.Contains("renew this ended grant for 15 minutes from now", StringComparison.Ordinal) && (await fx.Use(Scope("short"))).Kind == GrantUseKind.Granted, "admin grants renew: an ended grant is renewed from now after the tap");
        Tapped indefinite = await Op("grant-extend", laptop, true, null, ("id", short1.GrantId!), ("indefinite", "true"));
        check(indefinite.ApproveStatus == 200 && await HostServiceTests.WaitFor(() => fx.Store.FindGrant(short1.GrantId!) is { Expires: null }), "admin grants extend (no end): gives the grant no end after the tap");

        (_, string again, _) = await browser.GetAsync("/api/v1/grants");
        check(again.Contains(id, StringComparison.Ordinal) && again.Contains("revoked", StringComparison.Ordinal) && again.Contains(short1.GrantId!, StringComparison.Ordinal) && again.Contains("no end", StringComparison.Ordinal) && !again.Contains(S1, StringComparison.Ordinal), "admin grants list: one row per grant with its state and end; the scope key (a hash of the request) is not shown");

        string changedScope = Scope("removed-changer");
        string approvedScope = Scope("removed-approver");
        GrantApproval changedGrant = await fx.Approve(changedScope, 60, who: laptop);
        GrantApproval approvedGrant = await fx.Approve(approvedScope, 60, who: phone);
        check(fx.Admin(GrantOps.Extend, changedGrant.GrantId!, 15, who: phone).Outcome == GrantOps.Extended
            && fx.Admin(GrantOps.Extend, approvedGrant.GrantId!, 15, who: laptop).Outcome == GrantOps.Extended
            && (await fx.Use(changedScope)).Kind == GrantUseKind.Granted && (await fx.Use(approvedScope)).Kind == GrantUseKind.Granted,
            "grant removal: each grant covers runs before the convenience signer is removed");
        check(new PasskeyStore(fx.Db).RemoveById(TestAuthenticator.Encode(phone.CredentialId))
            && (await fx.Use(changedScope)).Kind == GrantUseKind.NoGrant && (await fx.Use(approvedScope)).Kind == GrantUseKind.NoGrant,
            "grant removal: removing a convenience key ends coverage for grants it approved and grants it last changed");
    }

    // ---- every end of a grant ends its use (what held the store key for a grant before is gone; the grant itself still has to end) ----

    private static async Task GrantEnds(Action<bool, string> check, string parent)
    {
        foreach (string end in new[] { "expired", "revoked", "disabled", "disabled and enabled", "untrusted at check-in" })
        {
            using Fixture fx = new(parent);
            await fx.Start();
            GrantApproval made = await fx.Approve(S1, 30);
            check((await fx.Use(S1)).Kind == GrantUseKind.Granted, "grant end (" + end + "): the grant covers its scope before");
            switch (end)
            {
                case "expired":
                    fx.Clock.Advance(TimeSpan.FromMinutes(31));
                    break;
                case "revoked":
                    fx.Admin(GrantOps.Revoke, made.GrantId!);
                    await fx.Host.PumpAsync();
                    break;
                case "disabled":
                    fx.Store.Disable(fx.Fingerprint, "test");
                    await fx.Host.PumpAsync();
                    break;
                case "disabled and enabled":
                    fx.Store.Disable(fx.Fingerprint, "test");
                    fx.Store.Enable(fx.Fingerprint, "test");
                    await fx.Host.PumpAsync();
                    break;
                default:
                    fx.Store.Disable(fx.Fingerprint, "test");
                    await fx.Host.ReconcileAsync();
                    break;
            }

            GrantUse after = await fx.Use(S1);
            check(after.Kind != GrantUseKind.Granted && !fx.Host.SyncedGrants.Any(item => item.GrantId == made.GrantId && end != "expired"), "grant end (" + end + "): afterwards the grant covers no run (" + after.Kind + " " + after.Message + ")");
        }
    }

    // ---- through the real service ----

    internal static string Show(HostServiceTests.Rig rig) => rig.Script("show", "echo ran > \"%~dpn0.marker.txt\"\necho t=%TOKEN%", "echo ran > \"$0.marker.txt\"\necho \"t=$TOKEN\"");

    private static string Marker(HostServiceTests.Rig rig) => HostServiceTests.Marker(rig);

    /// <summary>Approves; chooses a grant time only while <see cref="Minutes" /> is set (as a person would on the approve page), and counts the asks.</summary>
    internal sealed class Chooser(int minutes, bool approve = true, TestAuthenticator? signer = null, bool offersTime = false) : IApprover
    {
        public int Minutes { get; set; } = minutes;

        public bool OffersTime => offersTime;

        public List<ApprovalRequest> Requests { get; } = [];

        public ApprovalDecision Request(ApprovalRequest request)
        {
            lock (Requests)
            {
                Requests.Add(request);
            }

            // Every approval is a grant (once: a consumed once-only grant), backed by the assertion the person made over the page text (as the page makes it).
            ApprovalEvidence? evidence = null;
            if (approve && (signer is not null || Minutes == 0))
            {
                string text = ApprovalSummary.BuildMessage(request) + "\n" + ApprovalSummary.IssuedLine(DateTimeOffset.UtcNow);
                string nonce = "svc-nonce-" + Guid.NewGuid().ToString("N")[..8];
                evidence = new ApprovalEvidence(nonce, text, (signer ?? TestSigner.Default).Assert(ReuseBinding.Challenge(RequestBinding.Compute(nonce, text), Minutes), TestState.Origin, "localhost", TestState.NextCount()));
            }

            return approve ? ApprovalDecision.Allow("approved", Minutes, evidence) : ApprovalDecision.Deny("test denied");
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
            check(approver.Requests[0].Reuse is { IsOn: true }, "service approve: the page offers the times");
            check(rig.Machine.Deployment.Store.Grants() is [{ Status: "active" } granted] && granted.Program == program && granted.SecretNames == "TOKEN" && granted.Fingerprint == rig.Machine.Fingerprint, "service approve: the authority holds one grant with what it covers (program, secret names, folder)");
            check(rig.Machine.Deployment.Store.Audit().Any(entry => entry.Event == "grant-created") && (StateDatabaseTests.AuditText(rig.State.FilePath).Contains("\"outcome\":\"grant-approved\"", StringComparison.Ordinal) || rig.Machine.Deployment.Store.AuditHistory(new AuditQuery(Limit: 1000)).Any(item => item.Event.Outcome == "grant-approved")), "service approve: audited by the authority and in the signed host audit");

            approver.Minutes = 0;
            HostServiceTests.Raw run = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            check(run.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 0 } && approver.Requests.Count == 1 && rig.Store.Reads == 1 && File.Exists(Marker(rig)) && run.Stderr.Contains("a grant covers this request", StringComparison.Ordinal) && !run.Stdout.Contains("Canary", StringComparison.Ordinal),
                "service run: a request in the scope of the grant runs with no approval page decision (the approver was asked once, for approve) (" + run.Stderr.Trim() + string.Join(" | ", rig.Machine.Deployment.Store.Audit().Where(e => e.Event.StartsWith("grant", StringComparison.Ordinal)).Select(e => e.Event + ":" + e.Detail)) + ")");
            check((StateDatabaseTests.AuditText(rig.State.FilePath).Contains("\"outcome\":\"granted\"", StringComparison.Ordinal) || rig.Machine.Deployment.Store.AuditHistory(new AuditQuery(Limit: 1000)).Any(item => item.Event.Outcome == "granted")) && rig.Machine.Deployment.Store.Audit().Count(entry => entry.Event == "grant-use") == 1, "service run: the use of the grant is audited by the host and by the authority, once for the one run (the check again before the decryption records no second use) (" + string.Join("|", HostServiceTests.AuditOf(rig).Split((char)10).Select(line => line.Length)) + "; " + string.Join("|", rig.Machine.Deployment.Store.Audit().Select(entry => entry.Event)) + ")");

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

        // Revocation applied by a connected host cancels a launch under the grant that has not committed: here it lands after the grant check and before the decryption.
        Chooser maker = new(60, signer: svcKey);
        using (HostServiceTests.Rig rig = new(parent, approver: () => maker, enrolled: svcKey))
        {
            string program = Show(rig);
            await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program), path: "/v1/approve");
            maker.Minutes = 0;
            string grantId = rig.Machine.Deployment.Store.Grants()[0].Id;
            bool revoked = false;
            RunCommand.AfterHold = () =>
            {
                revoked = ServiceRevoke(rig, svcKey, grantId, "adm-svc-2").Outcome == GrantOps.Revoked;
                rig.Service.Authorization.PumpAsync().GetAwaiter().GetResult();
            };
            HostServiceTests.Raw result;
            try
            {
                result = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            }
            finally
            {
                RunCommand.AfterHold = null;
            }

            check(revoked && maker.Requests.Count == 1 && result.Result is { Outcome: LaunchOutcome.Denied or LaunchOutcome.Cancelled } && rig.Store.Reads == 0 && !File.Exists(Marker(rig)), "revoke before the decryption: a revocation applied after the grant check invalidated the gate; nothing was decrypted and nothing started (" + result.Result?.Outcome + ")");
        }

        // A revocation the host has not heard of yet, made after the hold and the stale check: the grant is asked about again just before the decryption, so nothing is decrypted.
        Chooser late = new(60, signer: svcKey);
        using (HostServiceTests.Rig rig = new(parent, approver: () => late, enrolled: svcKey))
        {
            string program = Show(rig);
            await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program), path: "/v1/approve");
            late.Minutes = 0;
            string grantId = rig.Machine.Deployment.Store.Grants()[0].Id;
            bool revoked = false;
            RunCommand.BeforeGrantRecheck = () => revoked = ServiceRevoke(rig, svcKey, grantId, "adm-svc-3").Outcome == GrantOps.Revoked;
            HostServiceTests.Raw result;
            try
            {
                result = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            }
            finally
            {
                RunCommand.BeforeGrantRecheck = null;
            }

            check(revoked && late.Requests.Count == 1 && result.Result is { Outcome: LaunchOutcome.Denied or LaunchOutcome.Cancelled } && rig.Store.Reads == 0 && !File.Exists(Marker(rig)),
                "revoke just before the decryption: the grant is checked again with the authority just before the values are read; nothing was decrypted and nothing started (" + result.Result?.Outcome + " " + result.Stderr.Trim() + ")");
        }

        // The authorization is invalidated while the grant is being checked again (the last await before the decryption): the stale check after it stops the run.
        {
            string folder = Path.Combine(parent, "recheck-" + Guid.NewGuid().ToString("N")[..6]);
            using TestMachine machine = new(folder);
            FlakyAuthority link = new(machine.Deployment.Authority);
            machine.Deployment.Link = link;
            Chooser rechecker = new(60, signer: svcKey);
            using HostServiceTests.Rig rig = new(parent, approver: () => rechecker, machine: machine, enrolled: svcKey);
            string program = Show(rig);
            await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program), path: "/v1/approve");
            rechecker.Minutes = 0;
            int checks = 0;
            link.BeforeGrant = envelope =>
            {
                if (envelope.Operation != GrantOps.Approve && Interlocked.Increment(ref checks) == 2)
                {
                    rig.Service.Gate.Invalidate();
                }
            };
            HostServiceTests.Raw result = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            link.BeforeGrant = null;
            check(checks == 2 && rechecker.Requests.Count == 1 && result.Result is { Outcome: LaunchOutcome.Cancelled } && rig.Store.Reads == 0 && !File.Exists(Marker(rig)),
                "stale after the grant check again: an invalidation while the grant is asked about again just before the decryption stops the run; nothing was decrypted and nothing started (" + checks + " " + result.Result?.Outcome + " " + result.Stderr.Trim() + ")");
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
            StringWriter notReadyErr = new();
            int notReady = await LaunchClient.RunAsync(CliArgs.ParseRun(["--secrets", "TOKEN", "--reason", "early", "--", Show(rig)], out _)!, rig.Work, rig.Service.Endpoint, null, new StringWriter(), notReadyErr, rig.Machine.Trust);
            check(notReady == LaunchClient.ServiceUnavailable && notReadyErr.ToString().Contains("not ready", StringComparison.Ordinal), "startup: a client told 503 exits " + LaunchClient.ServiceUnavailable + " with a line that says to ask again, not 4 (store error) (" + notReady + ")");
            link.Offline = false;
            check(await HostServiceTests.WaitFor(() => rig.Service.Ready, 30), "startup: it keeps trying and becomes ready when the authority answers");
            HostServiceTests.Raw ready = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, Show(rig)));
            check(ready.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 0 } && rig.Service.Authorization.Vouched, "startup: once reconciled the run goes through and the host is vouched for");
        }

        // Fail closed in the running service: an authority that cannot be reached means no secret use, even under a grant this host synchronized.
        {
            string folder = Path.Combine(parent, "closed-" + Guid.NewGuid().ToString("N")[..6]);
            using TestMachine machine = new(folder);
            FlakyAuthority link = new(machine.Deployment.Authority);
            machine.Deployment.Link = link;
            FakeMonotonic mono = new();
            Chooser tap = new(60, signer: svcKey);
            using HostServiceTests.Rig rig = new(parent, approver: () => tap, machine: machine, monotonic: mono, enrolled: svcKey);
            string program = Show(rig);
            await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program), path: "/v1/approve");
            tap.Minutes = 0;
            HostServiceTests.Raw online = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            check(online.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 0 } && tap.Requests.Count == 1, "service fail closed: online, the grant lets the run through with no page decision (" + online.Stderr.Trim() + ")");
            link.Offline = true;
            int reads = rig.Store.Reads;
            File.Delete(Marker(rig));
            HostServiceTests.Raw offline = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            check(offline.Result is { Outcome: LaunchOutcome.Denied } && rig.Store.Reads == reads && !File.Exists(Marker(rig)) && !offline.Stderr.Contains("offline", StringComparison.Ordinal), "service fail closed: with the authority out of reach the run is refused at once and nothing is decrypted (" + offline.Stderr.Trim() + ")");
        }
    }
}

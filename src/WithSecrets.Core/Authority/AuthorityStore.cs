using System.Globalization;

using Microsoft.Data.Sqlite;

namespace WithSecrets;

/// <summary>An authority database that cannot be used: unreadable, locked past the timeout, damaged or of another schema version.</summary>
public sealed class AuthorityDatabaseException(string message, Exception? inner = null) : Exception(message, inner);

public enum MachineStatus
{
    Pending,
    Trusted,
    Disabled,
    Untrusted,
}

/// <summary>
/// One machine the authority knows. <see cref="Fingerprint" /> is the identity (SHA-256 of the canonical public key);
/// <see cref="FriendlyName" /> is display text only. <see cref="SecurityRevision" /> is per machine and grows when an
/// administrative action invalidates its authorization. <see cref="PendingHostName" /> is a host name the machine presented that
/// differs from <see cref="HostName" />, waiting for an administrator.
/// </summary>
public sealed record MachineRecord(string Fingerprint, byte[] PublicKey, string HostName, string? FriendlyName, MachineStatus Status, int SecurityRevision, string? PendingHostName, DateTimeOffset Created, DateTimeOffset Updated);

public sealed record TransitionResult(bool Ok, string Message, MachineRecord? Machine);

public sealed record ProcessedRequest(string RequestId, string Fingerprint, string RequestDigest, AuthorityResponse Response);

public sealed record ProcessedGrant(string RequestId, string Fingerprint, string RequestDigest, GrantResponse Response);

/// <summary>An authority signing key's public part and where it stands. <see cref="Status" /> is Active or Retired; <see cref="How" /> is created, rotated or recovered.</summary>
public sealed record AuthorityKeyRecord(int Generation, string Fingerprint, byte[] PublicKey, string Status, DateTimeOffset Created, string? PreviousFingerprint, byte[]? TransitionSignature, string How);

public sealed record AuditEntry(long Id, DateTimeOffset Time, string Event, string? Fingerprint, string? RequestId, string Actor, string Detail);

public sealed record HistoryEntry(long Id, string Fingerprint, DateTimeOffset Time, string Kind, string? FromStatus, string? ToStatus, int SecurityRevision, string Actor, string Detail);

/// <summary>What <see cref="AuthorityStore.RecordDecision" /> stores: the signed answer, a host name to record as pending review, and the audit text.</summary>
public sealed record DecisionPlan(AuthorityResponse Response, string? HostMismatch, string AuditDetail, bool Store = true);

/// <summary>
/// <c>authority.db</c> in the store folder: the authority's durable state in SQLite (WAL, schema version 2): machines and their
/// status history, grants (scoped, with their expiry, revision and revocation) with the revocation notices for hosts and the stored
/// results of grant requests, the public part of the authority signing keys and
/// their rotation history, the authority-side audit history, processed request ids with their signed results (idempotency),
/// and pending invalidation notifications. The authority signing private key is not here (see <see cref="CngSigningKey" />),
/// and no secret value is. Every operation is one transaction that takes the write lock first, so it commits whole or leaves
/// nothing; a database of another schema version is never migrated, except version 1 (Phase 2), whose grants table was never written
/// by the program and is replaced by the Phase 3 tables: any other version: delete it and start over (machines then enroll again).
/// </summary>
public sealed class AuthorityStore
{
    public const string FileName = "authority.db";
    public const int SchemaVersion = 2;

    private const string Schema = """
        CREATE TABLE schema_version (version INTEGER NOT NULL);
        CREATE TABLE machines (
            fingerprint TEXT PRIMARY KEY NOT NULL, public_key TEXT NOT NULL, host_name TEXT NOT NULL, friendly_name TEXT,
            status TEXT NOT NULL, security_revision INTEGER NOT NULL, pending_host_name TEXT, created TEXT NOT NULL, updated TEXT NOT NULL);
        CREATE TABLE machine_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT NOT NULL, time TEXT NOT NULL, kind TEXT NOT NULL,
            from_status TEXT, to_status TEXT, security_revision INTEGER NOT NULL, actor TEXT NOT NULL, detail TEXT NOT NULL);
        CREATE TABLE grants (
            id TEXT PRIMARY KEY NOT NULL, fingerprint TEXT NOT NULL, scope_key TEXT NOT NULL, program TEXT NOT NULL, working_directory TEXT NOT NULL,
            secret_names TEXT NOT NULL, created TEXT NOT NULL, updated TEXT NOT NULL, expires TEXT, grant_revision INTEGER NOT NULL,
            security_revision INTEGER NOT NULL, status TEXT NOT NULL, approved_by TEXT NOT NULL, revoked TEXT);
        CREATE TABLE grant_events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT NOT NULL, grant_id TEXT NOT NULL, scope_key TEXT NOT NULL, kind TEXT NOT NULL,
            grant_revision INTEGER NOT NULL, state TEXT NOT NULL, created TEXT NOT NULL, acknowledged TEXT);
        CREATE TABLE processed_grant_requests (
            request_id TEXT PRIMARY KEY NOT NULL, fingerprint TEXT NOT NULL, request_digest TEXT NOT NULL, response TEXT NOT NULL, created TEXT NOT NULL);
        CREATE TABLE authority_keys (
            generation INTEGER PRIMARY KEY NOT NULL, fingerprint TEXT NOT NULL UNIQUE, public_key TEXT NOT NULL, status TEXT NOT NULL,
            created TEXT NOT NULL, retired TEXT, previous_fingerprint TEXT, transition_signature TEXT, how TEXT NOT NULL);
        CREATE TABLE audit_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT NOT NULL, event TEXT NOT NULL, fingerprint TEXT, request_id TEXT,
            actor TEXT NOT NULL, detail TEXT NOT NULL);
        CREATE TABLE processed_requests (
            request_id TEXT PRIMARY KEY NOT NULL, fingerprint TEXT NOT NULL, request_digest TEXT NOT NULL, response TEXT NOT NULL,
            created TEXT NOT NULL);
        CREATE TABLE pending_invalidations (
            fingerprint TEXT NOT NULL, security_revision INTEGER NOT NULL, state TEXT NOT NULL, created TEXT NOT NULL,
            acknowledged TEXT, PRIMARY KEY (fingerprint, security_revision));
        """;

    public static readonly TimeSpan BusyTimeout = TimeSpan.FromSeconds(5);

    private readonly TimeProvider _clock;
    private int _checked;

    public AuthorityStore(string path, TimeProvider? clock = null)
    {
        FilePath = Path.GetFullPath(path);
        _clock = clock ?? TimeProvider.System;
    }

    public string FilePath { get; }

    public string FileLabel => Path.GetFileName(FilePath);

    public static AuthorityStore InFolder(string folder, TimeProvider? clock = null) => new(Path.Combine(folder, FileName), clock);

    /// <summary>For tests: called inside a write transaction at named points; throwing from it must leave no partial effect.</summary>
    internal Action<string>? Fault { get; set; }

    private DateTimeOffset Now => _clock.GetUtcNow();

    private static string Time(DateTimeOffset time) => CanonicalJson.Time(time);

    private static DateTimeOffset ParseTime(string text) => DateTimeOffset.ParseExact(text, "O", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

    // ---- machines ----

    public IReadOnlyList<MachineRecord> Machines()
    {
        return Read(connection => connection is null ? [] : Query(connection, null, "SELECT * FROM machines ORDER BY created, fingerprint", Machine));
    }

    public MachineRecord? Find(string fingerprint)
    {
        return Read(connection => connection is null ? null : Query(connection, null, "SELECT * FROM machines WHERE fingerprint = $fp", Machine, ("$fp", fingerprint)).FirstOrDefault());
    }

    /// <summary>The machines whose fingerprint starts with the given (upper-case hex) prefix.</summary>
    public IReadOnlyList<MachineRecord> FindByPrefix(string prefix)
    {
        return [.. Machines().Where(machine => machine.Fingerprint.StartsWith(prefix, StringComparison.Ordinal))];
    }

    public IReadOnlyList<HistoryEntry> History(string fingerprint)
    {
        return Read(connection => connection is null ? [] : Query(connection, null, "SELECT * FROM machine_history WHERE fingerprint = $fp ORDER BY id", reader => new HistoryEntry(
            reader.GetInt64(0), reader.GetString(1), ParseTime(reader.GetString(2)), reader.GetString(3), reader.IsDBNull(4) ? null : reader.GetString(4), reader.IsDBNull(5) ? null : reader.GetString(5),
            reader.GetInt32(6), reader.GetString(7), reader.GetString(8)), ("$fp", fingerprint)));
    }

    public IReadOnlyList<AuditEntry> Audit(int limit = 1000)
    {
        return Read(connection => connection is null ? [] : Query(connection, null, "SELECT * FROM audit_history ORDER BY id LIMIT $limit", reader => new AuditEntry(
            reader.GetInt64(0), ParseTime(reader.GetString(1)), reader.GetString(2), reader.IsDBNull(3) ? null : reader.GetString(3), reader.IsDBNull(4) ? null : reader.GetString(4),
            reader.GetString(5), reader.GetString(6)), ("$limit", limit)));
    }

    /// <summary>
    /// First contact: records the machine as Pending (with its host name) and returns the record. A machine that is already known
    /// is returned as it is; nothing changes. The caller has checked the proof of possession.
    /// </summary>
    public MachineRecord Register(byte[] publicKey, string hostName, string actor)
    {
        string fingerprint = KeyIdentity.Fingerprint(publicKey);

        return Write((connection, transaction) =>
        {
            if (Query(connection, transaction, "SELECT * FROM machines WHERE fingerprint = $fp", Machine, ("$fp", fingerprint)).FirstOrDefault() is { } known)
            {
                return known;
            }

            string now = Time(Now);
            StateDatabase.Execute(connection, transaction, "INSERT INTO machines (fingerprint, public_key, host_name, friendly_name, status, security_revision, pending_host_name, created, updated) VALUES ($fp, $key, $host, NULL, 'Pending', 1, NULL, $now, $now)",
                ("$fp", fingerprint), ("$key", Convert.ToBase64String(publicKey)), ("$host", hostName), ("$now", now));
            Fault?.Invoke("after-update");
            History(connection, transaction, fingerprint, "registered", null, MachineStatus.Pending, 1, actor, "first contact, proof of possession verified; host name " + hostName);
            Audit(connection, transaction, "machine-registered", fingerprint, null, actor, "Pending; host name " + hostName);
            Fault?.Invoke("before-commit");

            return Query(connection, transaction, "SELECT * FROM machines WHERE fingerprint = $fp", Machine, ("$fp", fingerprint)).Single();
        });
    }

    /// <summary>Null when the action (approve, disable, enable, untrust, trust, rename, approve-host-change) may be applied to the machine as it is now, else why not. The rules of the status table.</summary>
    public static string? TransitionProblem(string kind, MachineRecord machine) => kind switch
    {
        "approve" => machine.Status == MachineStatus.Pending ? null : $"the machine is {machine.Status}; only a Pending machine is approved",
        "disable" => machine.Status == MachineStatus.Trusted ? null : $"the machine is {machine.Status}; only a Trusted machine is disabled",
        "untrust" => machine.Status == MachineStatus.Untrusted ? "the machine is already Untrusted" : null,
        "enable" => machine.Status == MachineStatus.Disabled ? null : $"the machine is {machine.Status}; only a Disabled machine is enabled",
        "trust" => machine.Status == MachineStatus.Untrusted ? null : $"the machine is {machine.Status}; only an Untrusted machine is trusted again",
        "rename" => null,
        "approve-host-change" => machine.PendingHostName is null ? "no host name change is waiting for approval" : null,
        _ => "unknown action",
    };

    /// <summary>Pending to Trusted: needs a friendly name. No revision change: there is no earlier authorization to end.</summary>
    public TransitionResult Approve(string fingerprint, string friendlyName, string actor, int? expectedRevision = null)
    {
        if (Enrollment.NameError(friendlyName) is { } nameProblem)
        {
            return new TransitionResult(false, "the friendly name is not usable: " + nameProblem, null);
        }

        return Change(fingerprint, "approve", actor, expectedRevision, machine => TransitionProblem("approve", machine) is { } problem ? Plan.Refuse(problem)
            : new Plan(null, MachineStatus.Trusted, friendlyName.Trim(), false, null, "approved with friendly name " + friendlyName.Trim()));
    }

    /// <summary>Trusted to Disabled. Increments the security revision, invalidates the machine's grants and records the invalidation to deliver.</summary>
    public TransitionResult Disable(string fingerprint, string actor, int? expectedRevision = null)
    {
        return Change(fingerprint, "disable", actor, expectedRevision, machine => TransitionProblem("disable", machine) is { } problem ? Plan.Refuse(problem)
            : new Plan(null, MachineStatus.Disabled, machine.FriendlyName, true, null, "disabled"));
    }

    /// <summary>
    /// Trusted, Disabled or Pending to Untrusted. From Trusted it increments the security revision and invalidates grants like
    /// <see cref="Disable" />; from the others there is no authorization to end, so the revision stays.
    /// </summary>
    public TransitionResult Untrust(string fingerprint, string actor, int? expectedRevision = null)
    {
        return Change(fingerprint, "untrust", actor, expectedRevision, machine => TransitionProblem("untrust", machine) is { } problem ? Plan.Refuse(problem)
            : new Plan(null, MachineStatus.Untrusted, machine.FriendlyName, machine.Status == MachineStatus.Trusted, null, "trust withdrawn"));
    }

    /// <summary>Disabled to Trusted. Starts clean: grants that existed before were invalidated when it was disabled and stay invalid.</summary>
    public TransitionResult Enable(string fingerprint, string actor, int? expectedRevision = null)
    {
        return Change(fingerprint, "enable", actor, expectedRevision, machine => TransitionProblem("enable", machine) is { } problem ? Plan.Refuse(problem)
            : new Plan(null, MachineStatus.Trusted, machine.FriendlyName, false, null, "re-enabled; starts clean"));
    }

    /// <summary>Untrusted to Trusted. <paramref name="confirmedFingerprint" /> is what the administrator typed; it is compared with the machine's real fingerprint <paramref name="fingerprint" /> (taken from the record, not from the typed text). Starts clean.</summary>
    public TransitionResult Trust(string fingerprint, string confirmedFingerprint, string actor, int? expectedRevision = null)
    {
        if (!string.Equals(KeyIdentity.ParseHex(confirmedFingerprint, true), fingerprint, StringComparison.Ordinal))
        {
            return new TransitionResult(false, "the confirmation is not this machine's full fingerprint", null);
        }

        return Change(fingerprint, "trust", actor, expectedRevision, machine => TransitionProblem("trust", machine) is { } problem ? Plan.Refuse(problem)
            : new Plan(null, MachineStatus.Trusted, machine.FriendlyName, false, null, "trusted again after explicit confirmation of the fingerprint; starts clean"));
    }

    /// <summary>Display only: audited, no revision change, grants and cache stay.</summary>
    public TransitionResult Rename(string fingerprint, string friendlyName, string actor, int? expectedRevision = null)
    {
        if (Enrollment.NameError(friendlyName) is { } nameProblem)
        {
            return new TransitionResult(false, "the friendly name is not usable: " + nameProblem, null);
        }

        return Change(fingerprint, "rename", actor, expectedRevision, machine => new Plan(null, machine.Status, friendlyName.Trim(), false, null, $"friendly name changed from {machine.FriendlyName ?? "(none)"} to {friendlyName.Trim()}"));
    }

    /// <summary>An administrator accepts the host name the machine presented: it becomes the bound name. No revision change.</summary>
    public TransitionResult ApproveHostChange(string fingerprint, string actor, int? expectedRevision = null, string? expectedHostName = null)
    {
        return Change(fingerprint, "approve-host-change", actor, expectedRevision, machine => TransitionProblem("approve-host-change", machine) is { } problem ? Plan.Refuse(problem)
            : expectedHostName is not null && expectedHostName != machine.PendingHostName ? Plan.Refuse("the host name waiting for approval is not the one that was shown; nothing was done")
            : new Plan(null, machine.Status, machine.FriendlyName, false, machine.PendingHostName, $"host name changed from {machine.HostName} to {machine.PendingHostName}"));
    }

    /// <summary>Records that a machine presented a host name other than the bound one. The binding stays; the name waits for an administrator.</summary>
    public void RecordHostMismatch(string fingerprint, string presentedHostName)
    {
        Write((connection, transaction) =>
        {
            RecordMismatch(connection, transaction, fingerprint, presentedHostName);

            return 0;
        });
    }

    private void RecordMismatch(SqliteConnection connection, SqliteTransaction transaction, string fingerprint, string presented)
    {
        MachineRecord? machine = Query(connection, transaction, "SELECT * FROM machines WHERE fingerprint = $fp", Machine, ("$fp", fingerprint)).FirstOrDefault();
        if (machine is null || machine.HostName == presented || machine.PendingHostName == presented)
        {
            return;
        }

        StateDatabase.Execute(connection, transaction, "UPDATE machines SET pending_host_name = $host, updated = $now WHERE fingerprint = $fp", ("$host", presented), ("$now", Time(Now)), ("$fp", fingerprint));
        History(connection, transaction, fingerprint, "host-name-mismatch", machine.Status, machine.Status, machine.SecurityRevision, "authority", $"presented host name {presented}; bound name {machine.HostName} unchanged; pending administrator review");
        Audit(connection, transaction, "host-name-mismatch", fingerprint, null, "authority", $"presented {presented}, bound {machine.HostName}; pending review");
    }

    private sealed record Plan(string? Error, MachineStatus Status, string? FriendlyName, bool Bump, string? NewHostName, string Detail)
    {
        public static Plan Refuse(string error) => new(error, MachineStatus.Pending, null, false, null, "");
    }

    private TransitionResult Change(string fingerprint, string kind, string actor, int? expectedRevision, Func<MachineRecord, Plan> plan)
    {
        return Write((connection, transaction) =>
        {
            MachineRecord? machine = Query(connection, transaction, "SELECT * FROM machines WHERE fingerprint = $fp", Machine, ("$fp", fingerprint)).FirstOrDefault();
            if (machine is null)
            {
                return new TransitionResult(false, "no such machine", null);
            }

            if (expectedRevision is { } expected && expected != machine.SecurityRevision)
            {
                return new TransitionResult(false, "the machine changed while the page was open; nothing was done", machine);
            }

            Plan chosen = plan(machine);
            if (chosen.Error is not null)
            {
                return new TransitionResult(false, chosen.Error, machine);
            }

            int revision = machine.SecurityRevision + (chosen.Bump ? 1 : 0);
            string now = Time(Now);
            StateDatabase.Execute(connection, transaction, "UPDATE machines SET status = $status, friendly_name = $name, security_revision = $revision, host_name = $host, pending_host_name = $pending, updated = $now WHERE fingerprint = $fp",
                ("$status", chosen.Status.ToString()), ("$name", chosen.FriendlyName), ("$revision", revision), ("$host", chosen.NewHostName ?? machine.HostName),
                ("$pending", chosen.NewHostName is null ? machine.PendingHostName : null), ("$now", now), ("$fp", fingerprint));
            Fault?.Invoke("after-update");
            string detail = chosen.Detail;
            if (chosen.Bump)
            {
                int ended = StateDatabase.Execute(connection, transaction, "UPDATE grants SET status = 'invalidated' WHERE fingerprint = $fp AND status = 'active'", ("$fp", fingerprint));
                Fault?.Invoke("after-grants");
                StateDatabase.Execute(connection, transaction, "INSERT INTO pending_invalidations (fingerprint, security_revision, state, created, acknowledged) VALUES ($fp, $revision, 'Pending', $now, NULL)",
                    ("$fp", fingerprint), ("$revision", revision), ("$now", now));
                Fault?.Invoke("after-invalidation");
                detail += $"; security revision {machine.SecurityRevision} to {revision}; {ended} grant(s) invalidated; pending work is cancelled when the host applies revision {revision}";
            }

            History(connection, transaction, fingerprint, kind, machine.Status, chosen.Status, revision, actor, detail);
            Fault?.Invoke("after-history");
            Audit(connection, transaction, "machine-" + kind, fingerprint, null, actor, detail);
            Fault?.Invoke("before-commit");

            return new TransitionResult(true, detail, Query(connection, transaction, "SELECT * FROM machines WHERE fingerprint = $fp", Machine, ("$fp", fingerprint)).Single());
        });
    }

    // ---- requests (idempotency) ----

    /// <summary>The stored result of a request id, or null.</summary>
    public ProcessedRequest? GetProcessed(string requestId)
    {
        return Read(connection => connection is null ? null : Query(connection, null, "SELECT request_id, fingerprint, request_digest, response FROM processed_requests WHERE request_id = $id", ReadProcessed, ("$id", requestId)).FirstOrDefault());
    }

    /// <summary>
    /// The one durable decision of a request, in one transaction: the stored result when the id was decided before (the new
    /// decision is not made); otherwise the plan that <paramref name="produce" /> builds from the machine's current record is stored
    /// with its audit row and a host name mismatch it names, and returned. The machine row is read inside the transaction, so the
    /// status and revision the answer states are the ones that were committed with it.
    /// </summary>
    public AuthorityResponse RecordDecision(string requestId, string requestDigest, string fingerprint, Func<MachineRecord?, DecisionPlan> produce)
    {
        return Write((connection, transaction) =>
        {
            if (Query(connection, transaction, "SELECT request_id, fingerprint, request_digest, response FROM processed_requests WHERE request_id = $id", ReadProcessed, ("$id", requestId)).FirstOrDefault() is { } stored)
            {
                return stored.Response;
            }

            MachineRecord? machine = Query(connection, transaction, "SELECT * FROM machines WHERE fingerprint = $fp", Machine, ("$fp", fingerprint)).FirstOrDefault();
            DecisionPlan plan = produce(machine);
            if (plan.HostMismatch is { } presented)
            {
                RecordMismatch(connection, transaction, fingerprint, presented);
            }

            if (plan.Store)
            {
                StateDatabase.Execute(connection, transaction, "INSERT INTO processed_requests (request_id, fingerprint, request_digest, response, created) VALUES ($id, $fp, $digest, $response, $now)",
                    ("$id", requestId), ("$fp", fingerprint), ("$digest", requestDigest), ("$response", plan.Response.ToJson()), ("$now", Time(Now)));
                Fault?.Invoke("after-result");
                Audit(connection, transaction, "decision-" + plan.Response.Decision.ToString().ToLowerInvariant(), fingerprint, requestId, "authority", plan.Response.ReasonCode + (plan.AuditDetail.Length > 0 ? "; " + plan.AuditDetail : "") + "; request " + requestDigest[..12]);
            }

            Fault?.Invoke("before-commit");

            return plan.Response;
        });
    }

    private static ProcessedRequest ReadProcessed(SqliteDataReader reader)
    {
        if (!AuthorityResponse.TryParse(reader.GetString(3), out AuthorityResponse? response, out string? problem))
        {
            throw new AuthorityDatabaseException("a stored result cannot be read (" + problem + "); delete authority.db to start over");
        }

        return new ProcessedRequest(reader.GetString(0), reader.GetString(1), reader.GetString(2), response!);
    }

    // ---- authority keys ----

    public IReadOnlyList<AuthorityKeyRecord> AuthorityKeys()
    {
        return Read(connection => connection is null ? [] : Query(connection, null, "SELECT generation, fingerprint, public_key, status, created, previous_fingerprint, transition_signature, how FROM authority_keys ORDER BY generation", ReadKey));
    }

    public AuthorityKeyRecord? ActiveKey() => AuthorityKeys().LastOrDefault(key => key.Status == "Active");

    /// <summary>Records the first authority key as generation 1. When another process did it first, that record stays.</summary>
    public AuthorityKeyRecord RecordFirstKey(byte[] publicKey, string actor)
    {
        return Write((connection, transaction) =>
        {
            if (Query(connection, transaction, "SELECT generation, fingerprint, public_key, status, created, previous_fingerprint, transition_signature, how FROM authority_keys ORDER BY generation", ReadKey).LastOrDefault(key => key.Status == "Active") is { } existing)
            {
                return existing;
            }

            string fingerprint = KeyIdentity.Fingerprint(publicKey);
            int generation = (int)(Convert.ToInt64(StateDatabase.Scalar(connection, transaction, "SELECT COALESCE(MAX(generation), 0) FROM authority_keys"), CultureInfo.InvariantCulture) + 1);
            string now = Time(Now);
            StateDatabase.Execute(connection, transaction, "INSERT INTO authority_keys (generation, fingerprint, public_key, status, created, retired, previous_fingerprint, transition_signature, how) VALUES ($gen, $fp, $key, 'Active', $now, NULL, NULL, NULL, 'created')",
                ("$gen", generation), ("$fp", fingerprint), ("$key", Convert.ToBase64String(publicKey)), ("$now", now));
            Audit(connection, transaction, "authority-key-created", null, null, actor, $"generation {generation}, fingerprint {fingerprint}");

            return new AuthorityKeyRecord(generation, fingerprint, publicKey, "Active", ParseTime(now), null, null, "created");
        });
    }

    /// <summary>
    /// Routine rotation, atomically: the current key is retired and the new one becomes active with the transition the current key
    /// signed. Refused when <paramref name="transition" /> does not name the active key.
    /// </summary>
    public AuthorityKeyRecord RecordRotation(KeyTransition transition, string actor)
    {
        return Write((connection, transaction) =>
        {
            AuthorityKeyRecord active = ActiveIn(connection, transaction) ?? throw new AuthorityDatabaseException("there is no active authority key");
            if (active.Fingerprint != transition.OldFingerprint)
            {
                throw new AuthorityDatabaseException("the transition does not start from the active authority key");
            }

            return Replace(connection, transaction, active, transition.NewPublicKey, transition.Signature, "rotated", actor, transition.Created);
        });
    }

    /// <summary>Recovery: the active key is retired without a transition (it is lost or not trusted), and the new key becomes active. Hosts pin it only through an explicit administrator action.</summary>
    public AuthorityKeyRecord RecordRecovery(byte[] newPublicKey, string actor)
    {
        return Write((connection, transaction) =>
        {
            AuthorityKeyRecord active = ActiveIn(connection, transaction) ?? throw new AuthorityDatabaseException("there is no active authority key");

            return Replace(connection, transaction, active, newPublicKey, null, "recovered", actor);
        });
    }

    private AuthorityKeyRecord Replace(SqliteConnection connection, SqliteTransaction transaction, AuthorityKeyRecord active, byte[] newPublicKey, byte[]? signature, string how, string actor, DateTimeOffset? created = null)
    {
        // A transition is signed over its creation time, so the stored time must be that one.
        string now = Time(created ?? Now);
        string fingerprint = KeyIdentity.Fingerprint(newPublicKey);
        int generation = active.Generation + 1;
        StateDatabase.Execute(connection, transaction, "UPDATE authority_keys SET status = 'Retired', retired = $now WHERE generation = $gen", ("$now", now), ("$gen", active.Generation));
        Fault?.Invoke("after-retire");
        StateDatabase.Execute(connection, transaction, "INSERT INTO authority_keys (generation, fingerprint, public_key, status, created, retired, previous_fingerprint, transition_signature, how) VALUES ($gen, $fp, $key, 'Active', $now, NULL, $previous, $signature, $how)",
            ("$gen", generation), ("$fp", fingerprint), ("$key", Convert.ToBase64String(newPublicKey)), ("$now", now), ("$previous", active.Fingerprint),
            ("$signature", signature is null ? null : Convert.ToBase64String(signature)), ("$how", how));
        Audit(connection, transaction, "authority-key-" + how, null, null, actor, $"generation {active.Generation} to {generation}; {active.Fingerprint} to {fingerprint}");
        Fault?.Invoke("before-commit");

        return new AuthorityKeyRecord(generation, fingerprint, newPublicKey, "Active", ParseTime(now), active.Fingerprint, signature, how);
    }

    private static AuthorityKeyRecord? ActiveIn(SqliteConnection connection, SqliteTransaction transaction)
    {
        return Query(connection, transaction, "SELECT generation, fingerprint, public_key, status, created, previous_fingerprint, transition_signature, how FROM authority_keys WHERE status = 'Active' ORDER BY generation DESC", ReadKey).FirstOrDefault();
    }

    /// <summary>The signed transitions from the key with fingerprint <paramref name="fromFingerprint" /> forward, in order; the chain stops at a key reached by recovery.</summary>
    public IReadOnlyList<KeyTransition> TransitionsFrom(string fromFingerprint)
    {
        IReadOnlyList<AuthorityKeyRecord> keys = AuthorityKeys();
        List<KeyTransition> chain = [];
        string current = fromFingerprint;
        while (keys.FirstOrDefault(key => key.PreviousFingerprint == current && key.TransitionSignature is not null) is { } next)
        {
            chain.Add(new KeyTransition(current, next.Fingerprint, next.PublicKey, next.Created, next.TransitionSignature!));
            current = next.Fingerprint;
        }

        return chain;
    }

    // ---- grants ----

    private const string GrantColumns = "id, fingerprint, scope_key, program, working_directory, secret_names, created, updated, expires, grant_revision, security_revision, status, approved_by, revoked";

    private static GrantRecord ReadGrant(SqliteDataReader reader)
    {
        return new GrantRecord(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetString(4), reader.GetString(5), ParseTime(reader.GetString(6)), ParseTime(reader.GetString(7)),
            reader.IsDBNull(8) ? null : ParseTime(reader.GetString(8)), reader.GetInt32(9), reader.GetInt32(10), reader.GetString(11), reader.GetString(12), reader.IsDBNull(13) ? null : ParseTime(reader.GetString(13)));
    }

    /// <summary>Every grant (of one machine when <paramref name="fingerprint" /> is given), oldest first.</summary>
    public IReadOnlyList<GrantRecord> Grants(string? fingerprint = null)
    {
        return Read(connection => connection is null ? [] : Query(connection, null, $"SELECT {GrantColumns} FROM grants WHERE $fp IS NULL OR fingerprint = $fp ORDER BY created, id", ReadGrant, ("$fp", fingerprint)));
    }

    public GrantRecord? FindGrant(string id)
    {
        return Read(connection => connection is null ? null : Query(connection, null, $"SELECT {GrantColumns} FROM grants WHERE id = $id", ReadGrant, ("$id", id)).FirstOrDefault());
    }

    /// <summary>The grants whose id starts with the given text.</summary>
    public IReadOnlyList<GrantRecord> FindGrantsByPrefix(string prefix)
    {
        return [.. Grants().Where(grant => grant.Id.StartsWith(prefix, StringComparison.Ordinal))];
    }

    /// <summary>For tests: puts a grant (as an approval makes it) with a scope key only.</summary>
    internal void AddGrant(string id, string fingerprint, string scopeDigest, DateTimeOffset? expires)
    {
        Write((connection, transaction) =>
        {
            int revision = Query(connection, transaction, "SELECT * FROM machines WHERE fingerprint = $fp", Machine, ("$fp", fingerprint)).Single().SecurityRevision;
            string now = Time(Now);
            StateDatabase.Execute(connection, transaction, $"INSERT INTO grants ({GrantColumns}) VALUES ($id, $fp, $scope, 'test', 'test', 'TEST', $now, $now, $expires, 1, $revision, 'active', 'test', NULL)",
                ("$id", id), ("$fp", fingerprint), ("$scope", scopeDigest), ("$now", now), ("$expires", expires is { } at ? Time(at) : null), ("$revision", revision));

            return 0;
        });
    }

    /// <summary>What a grant operation works with inside its transaction.</summary>
    public sealed class GrantTx
    {
        private readonly AuthorityStore _store;
        private readonly SqliteConnection _connection;
        private readonly SqliteTransaction _transaction;

        internal GrantTx(AuthorityStore store, SqliteConnection connection, SqliteTransaction transaction)
        {
            _store = store;
            _connection = connection;
            _transaction = transaction;
        }

        public GrantRecord? Find(string id) => Query(_connection, _transaction, $"SELECT {GrantColumns} FROM grants WHERE id = $id", ReadGrant, ("$id", id)).FirstOrDefault();

        /// <summary>The newest grant of the machine for the scope that is active (it may be past its end: it is then renewed, not made again).</summary>
        public GrantRecord? FindByScope(string fingerprint, string scopeKey)
        {
            return Query(_connection, _transaction, $"SELECT {GrantColumns} FROM grants WHERE fingerprint = $fp AND scope_key = $scope AND status = 'active' ORDER BY created DESC, id LIMIT 1", ReadGrant, ("$fp", fingerprint), ("$scope", scopeKey)).FirstOrDefault();
        }

        public GrantRecord Create(string fingerprint, string scopeKey, string program, string workingDirectory, string secretNames, DateTimeOffset? expires, int securityRevision, string approvedBy)
        {
            string id = "g-" + Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(9)).Replace('+', '-').Replace('/', '_');
            string now = Time(_store.Now);
            StateDatabase.Execute(_connection, _transaction, $"INSERT INTO grants ({GrantColumns}) VALUES ($id, $fp, $scope, $program, $dir, $names, $now, $now, $expires, 1, $revision, 'active', $by, NULL)",
                ("$id", id), ("$fp", fingerprint), ("$scope", scopeKey), ("$program", program), ("$dir", workingDirectory), ("$names", secretNames), ("$now", now), ("$expires", expires is { } at ? Time(at) : null), ("$revision", securityRevision), ("$by", approvedBy));
            _store.Fault?.Invoke("after-grant");

            return Find(id)!;
        }

        /// <summary>Sets the end of an active grant (null: indefinite), raises the grant's revision and records who. Returns the grant as it is now.</summary>
        public GrantRecord SetExpiry(string id, DateTimeOffset? expires, string approvedBy)
        {
            StateDatabase.Execute(_connection, _transaction, "UPDATE grants SET expires = $expires, updated = $now, grant_revision = grant_revision + 1, approved_by = $by WHERE id = $id AND status = 'active'",
                ("$expires", expires is { } at ? Time(at) : null), ("$now", Time(_store.Now)), ("$by", approvedBy), ("$id", id));
            _store.Fault?.Invoke("after-grant");

            return Find(id)!;
        }

        /// <summary>Ends the grant for good and queues the notice for its machine.</summary>
        public GrantRecord Revoke(string id)
        {
            GrantRecord grant = Find(id)!;
            string now = Time(_store.Now);
            StateDatabase.Execute(_connection, _transaction, "UPDATE grants SET status = 'revoked', revoked = $now, updated = $now, grant_revision = grant_revision + 1 WHERE id = $id AND status = 'active'", ("$now", now), ("$id", id));
            _store.Fault?.Invoke("after-grant");
            StateDatabase.Execute(_connection, _transaction, "INSERT INTO grant_events (fingerprint, grant_id, scope_key, kind, grant_revision, state, created, acknowledged) VALUES ($fp, $id, $scope, 'revoked', $revision, 'Pending', $now, NULL)",
                ("$fp", grant.Fingerprint), ("$id", id), ("$scope", grant.ScopeKey), ("$revision", grant.Revision + 1), ("$now", now));
            _store.Fault?.Invoke("after-event");

            return Find(id)!;
        }
    }

    /// <summary>What a grant operation decided: the signed answer, the audit event and text (when it should be recorded), and whether the answer is stored for retries.</summary>
    public sealed record GrantPlan(GrantResponse Response, string? AuditEvent, string AuditDetail, bool Store = true);

    /// <summary>
    /// One durable grant operation, atomically: the stored answer when the request id was done before (nothing is done again; the
    /// caller compares the digest first); otherwise <paramref name="produce" /> works on the grants in this transaction, with the machine's
    /// current record, and returns the signed answer, which is stored with its audit row. A throw anywhere leaves no change.
    /// </summary>
    public GrantResponse ApplyGrant(string requestId, string requestDigest, string fingerprint, Func<GrantTx, MachineRecord?, GrantPlan> produce)
    {
        return Write((connection, transaction) =>
        {
            if (Query(connection, transaction, "SELECT request_id, fingerprint, request_digest, response FROM processed_grant_requests WHERE request_id = $id", ReadProcessedGrant, ("$id", requestId)).FirstOrDefault() is { } stored)
            {
                return stored.Response;
            }

            MachineRecord? machine = Query(connection, transaction, "SELECT * FROM machines WHERE fingerprint = $fp", Machine, ("$fp", fingerprint)).FirstOrDefault();
            GrantPlan plan = produce(new GrantTx(this, connection, transaction), machine);
            if (plan.Store)
            {
                StateDatabase.Execute(connection, transaction, "INSERT INTO processed_grant_requests (request_id, fingerprint, request_digest, response, created) VALUES ($id, $fp, $digest, $response, $now)",
                    ("$id", requestId), ("$fp", fingerprint), ("$digest", requestDigest), ("$response", plan.Response.ToJson()), ("$now", Time(Now)));
                Fault?.Invoke("after-result");
                if (plan.AuditEvent is { } auditEvent)
                {
                    Audit(connection, transaction, auditEvent, fingerprint, requestId, "authority", plan.Response.ReasonCode + (plan.AuditDetail.Length > 0 ? "; " + plan.AuditDetail : "") + "; request " + requestDigest[..Math.Min(12, requestDigest.Length)]);
                }
            }

            Fault?.Invoke("before-commit");

            return plan.Response;
        });
    }

    /// <summary>The stored answer of a grant request id, with the machine and digest it was made for, or null.</summary>
    public ProcessedGrant? GetProcessedGrant(string requestId)
    {
        return Read(connection => connection is null ? null : Query(connection, null, "SELECT request_id, fingerprint, request_digest, response FROM processed_grant_requests WHERE request_id = $id", ReadProcessedGrant, ("$id", requestId)).FirstOrDefault());
    }

    private static ProcessedGrant ReadProcessedGrant(SqliteDataReader reader)
    {
        if (!GrantResponse.TryParse(reader.GetString(3), out GrantResponse? response, out string? problem))
        {
            throw new AuthorityDatabaseException("a stored grant result cannot be read (" + problem + "); delete authority.db to start over");
        }

        return new ProcessedGrant(reader.GetString(0), reader.GetString(1), reader.GetString(2), response!);
    }

    public IReadOnlyList<PendingGrantEvent> PendingGrantEvents(string fingerprint)
    {
        return Read(connection => connection is null ? [] : Query(connection, null, "SELECT seq, fingerprint, grant_id, scope_key, kind, grant_revision FROM grant_events WHERE fingerprint = $fp AND state = 'Pending' ORDER BY seq",
            reader => new PendingGrantEvent(reader.GetInt64(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetString(4), reader.GetInt32(5)), ("$fp", fingerprint)));
    }

    /// <summary>Marks the notice delivered and applied. Idempotent.</summary>
    public void AcknowledgeGrantEvent(string fingerprint, long sequence)
    {
        Write((connection, transaction) =>
        {
            int changed = StateDatabase.Execute(connection, transaction, "UPDATE grant_events SET state = 'Acknowledged', acknowledged = $now WHERE fingerprint = $fp AND seq = $seq AND state = 'Pending'", ("$now", Time(Now)), ("$fp", fingerprint), ("$seq", sequence));
            if (changed > 0)
            {
                Audit(connection, transaction, "grant-revocation-acknowledged", fingerprint, null, fingerprint, $"notice {sequence} applied by the host");
            }

            return 0;
        });
    }

    /// <summary>The ids of the machine's grants that are active.</summary>
    public IReadOnlyList<string> ActiveGrants(string fingerprint)
    {
        return Read(connection => connection is null ? [] : Query(connection, null, "SELECT id FROM grants WHERE fingerprint = $fp AND status = 'active' ORDER BY id", reader => reader.GetString(0), ("$fp", fingerprint)));
    }

    public IReadOnlyList<PendingInvalidation> PendingInvalidations(string fingerprint)
    {
        return Read(connection => connection is null ? [] : Query(connection, null, "SELECT fingerprint, security_revision FROM pending_invalidations WHERE fingerprint = $fp AND state = 'Pending' ORDER BY security_revision",
            reader => new PendingInvalidation(reader.GetString(0), reader.GetInt32(1)), ("$fp", fingerprint)));
    }

    /// <summary>Marks the notification delivered and applied. Idempotent.</summary>
    public void Acknowledge(string fingerprint, int revision)
    {
        Write((connection, transaction) =>
        {
            int changed = StateDatabase.Execute(connection, transaction, "UPDATE pending_invalidations SET state = 'Acknowledged', acknowledged = $now WHERE fingerprint = $fp AND security_revision <= $revision AND state = 'Pending'",
                ("$now", Time(Now)), ("$fp", fingerprint), ("$revision", revision));
            if (changed > 0)
            {
                Audit(connection, transaction, "invalidation-acknowledged", fingerprint, null, fingerprint, $"revision {revision} applied by the host");
            }

            return 0;
        });
    }

    // ---- plumbing ----

    private void History(SqliteConnection connection, SqliteTransaction transaction, string fingerprint, string kind, MachineStatus? from, MachineStatus? to, int revision, string actor, string detail)
    {
        StateDatabase.Execute(connection, transaction, "INSERT INTO machine_history (fingerprint, time, kind, from_status, to_status, security_revision, actor, detail) VALUES ($fp, $now, $kind, $from, $to, $revision, $actor, $detail)",
            ("$fp", fingerprint), ("$now", Time(Now)), ("$kind", kind), ("$from", from?.ToString()), ("$to", to?.ToString()), ("$revision", revision), ("$actor", actor), ("$detail", detail));
    }

    private void Audit(SqliteConnection connection, SqliteTransaction transaction, string eventName, string? fingerprint, string? requestId, string actor, string detail)
    {
        StateDatabase.Execute(connection, transaction, "INSERT INTO audit_history (time, event, fingerprint, request_id, actor, detail) VALUES ($now, $event, $fp, $id, $actor, $detail)",
            ("$now", Time(Now)), ("$event", eventName), ("$fp", fingerprint), ("$id", requestId), ("$actor", actor), ("$detail", detail));
    }

    private static MachineRecord Machine(SqliteDataReader reader)
    {
        return new MachineRecord(reader.GetString(0), Convert.FromBase64String(reader.GetString(1)), reader.GetString(2), reader.IsDBNull(3) ? null : reader.GetString(3),
            Enum.Parse<MachineStatus>(reader.GetString(4)), reader.GetInt32(5), reader.IsDBNull(6) ? null : reader.GetString(6), ParseTime(reader.GetString(7)), ParseTime(reader.GetString(8)));
    }

    private static AuthorityKeyRecord ReadKey(SqliteDataReader reader)
    {
        return new AuthorityKeyRecord(reader.GetInt32(0), reader.GetString(1), Convert.FromBase64String(reader.GetString(2)), reader.GetString(3), ParseTime(reader.GetString(4)),
            reader.IsDBNull(5) ? null : reader.GetString(5), reader.IsDBNull(6) ? null : Convert.FromBase64String(reader.GetString(6)), reader.GetString(7));
    }

    private static List<T> Query<T>(SqliteConnection connection, SqliteTransaction? transaction, string sql, Func<SqliteDataReader, T> read, params (string Name, object? Value)[] parameters)
    {
        using SqliteCommand command = StateDatabase.Command(connection, transaction, sql, parameters);
        using SqliteDataReader reader = command.ExecuteReader();
        List<T> rows = [];
        while (reader.Read())
        {
            rows.Add(read(reader));
        }

        return rows;
    }

    /// <summary>One write transaction, committed when <paramref name="work" /> returns and rolled back when it throws. Creates the database when it is missing.</summary>
    private T Write<T>(Func<SqliteConnection, SqliteTransaction, T> work)
    {
        return Use(true, connection =>
        {
            using SqliteTransaction transaction = connection!.BeginTransaction(deferred: false);
            T result = work(connection, transaction);
            transaction.Commit();

            return result;
        });
    }

    private T Read<T>(Func<SqliteConnection?, T> work) => Use(false, work);

    private T Use<T>(bool create, Func<SqliteConnection?, T> work)
    {
        try
        {
            using SqliteConnection? connection = Open(create);

            return work(connection);
        }
        catch (SqliteException failure)
        {
            throw new AuthorityDatabaseException(failure.SqliteErrorCode is 5 or 6 ? $"{FileLabel} is locked by another process; try again" : $"cannot read {FileLabel}: {failure.Message}", failure);
        }
        catch (Exception failure) when (failure is IOException or UnauthorizedAccessException)
        {
            throw new AuthorityDatabaseException($"cannot read {FileLabel}: {failure.Message}", failure);
        }
    }

    private SqliteConnection? Open(bool create)
    {
        if (!File.Exists(FilePath))
        {
            if (!create)
            {
                return null;
            }

            Create();
        }

        SqliteConnection connection = Connect(FilePath, SqliteOpenMode.ReadWrite);
        try
        {
            connection.Open();
            StateDatabase.Execute(connection, null, "PRAGMA busy_timeout = " + (int)BusyTimeout.TotalMilliseconds);
            if (Volatile.Read(ref _checked) == 0 && StateDatabase.Scalar(connection, null, "PRAGMA quick_check") is not "ok")
            {
                throw new AuthorityDatabaseException($"{FileLabel} is damaged; delete {FileLabel} to start over (machines then enroll again)");
            }

            long found;
            try
            {
                found = Convert.ToInt64(StateDatabase.Scalar(connection, null, "SELECT version FROM schema_version"), CultureInfo.InvariantCulture);
            }
            catch (SqliteException)
            {
                found = -1;
            }

            if (found == 1)
            {
                Migrate(connection);
                found = SchemaVersion;
            }

            if (found != SchemaVersion)
            {
                throw new AuthorityDatabaseException($"{FileLabel} is not of schema version {SchemaVersion}; delete {FileLabel} to start over (machines then enroll again)");
            }

            Volatile.Write(ref _checked, 1);

            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    /// <summary>Schema 1 (Phase 2) to 2: its grants table only had the structure (nothing wrote it); it is replaced and the new tables are made, in one transaction.</summary>
    private static void Migrate(SqliteConnection connection)
    {
        using SqliteTransaction transaction = connection.BeginTransaction(deferred: false);
        if (Convert.ToInt64(StateDatabase.Scalar(connection, transaction, "SELECT version FROM schema_version"), CultureInfo.InvariantCulture) != 1)
        {
            // Another process migrated first.
            return;
        }

        StateDatabase.Execute(connection, transaction, "DROP TABLE grants");
        StateDatabase.Execute(connection, transaction, Schema[Schema.IndexOf("CREATE TABLE grants (", StringComparison.Ordinal)..Schema.IndexOf("CREATE TABLE authority_keys (", StringComparison.Ordinal)]);
        StateDatabase.Execute(connection, transaction, "UPDATE schema_version SET version = $version", ("$version", SchemaVersion));
        transaction.Commit();
    }

    private void Create()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        string temp = FilePath + "." + Guid.NewGuid().ToString("N") + ".new";
        try
        {
            using (SqliteConnection connection = Connect(temp, SqliteOpenMode.ReadWriteCreate))
            {
                connection.Open();
                StateDatabase.Execute(connection, null, "PRAGMA journal_mode = WAL");
                using SqliteTransaction transaction = connection.BeginTransaction(deferred: false);
                StateDatabase.Execute(connection, transaction, Schema);
                StateDatabase.Execute(connection, transaction, "INSERT INTO schema_version (version) VALUES ($version)", ("$version", SchemaVersion));
                transaction.Commit();
            }

            try
            {
                File.Move(temp, FilePath, false);
            }
            catch (IOException) when (File.Exists(FilePath))
            {
                // Another process created it first: use that one.
            }
        }
        finally
        {
            foreach (string leftover in new[] { temp, temp + "-wal", temp + "-shm" })
            {
                try
                {
                    File.Delete(leftover);
                }
                catch (Exception failure) when (failure is IOException or UnauthorizedAccessException)
                {
                    // A stray temporary file is harmless.
                }
            }
        }
    }

    private static SqliteConnection Connect(string path, SqliteOpenMode mode)
    {
        return new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = mode,
            Pooling = false,
            DefaultTimeout = Math.Max(1, (int)Math.Ceiling(BusyTimeout.TotalSeconds)),
        }.ToString());
    }
}

using System.Reflection;
using System.Text;

using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>
/// Phase 2, the authority: signed envelopes and responses (every field, wrong keys, expiry, digest, replay), enrollment with proof of
/// possession, the status table with its revision rules, durable and idempotent operations across simulated restarts, authority key
/// rotation and recovery, and, through the real host service, that a machine that is not Trusted gets nothing and decrypts nothing.
/// </summary>
internal static class AuthorityTests
{
    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 11, 8, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }

    /// <summary>The authority of a test, with a hook that changes what the host service receives.</summary>
    private sealed class ScriptedAuthority(LocalAuthority inner) : IAuthority
    {
        public Func<AuthorityResponse, AuthorityResponse>? Tamper { get; set; }

        public Func<string, IReadOnlyList<KeyTransition>>? Transitions { get; set; }

        public async Task<AuthorityResponse> DecideAsync(MachineRequestEnvelope envelope, CancellationToken cancel = default)
        {
            AuthorityResponse response = await inner.DecideAsync(envelope, cancel);

            return Tamper?.Invoke(response) ?? response;
        }

        public Task<byte[]> BeginEnrollmentAsync(CancellationToken cancel = default) => inner.BeginEnrollmentAsync(cancel);

        public Task<EnrollmentResult> EnrollAsync(EnrollmentRequest request, CancellationToken cancel = default) => inner.EnrollAsync(request, cancel);

        public Task<IReadOnlyList<KeyTransition>> KeyTransitionsAsync(string afterKeyFingerprint, CancellationToken cancel = default)
            => Transitions is null ? inner.KeyTransitionsAsync(afterKeyFingerprint, cancel) : Task.FromResult(Transitions(afterKeyFingerprint));

        public Task<IReadOnlyList<PendingInvalidation>> PendingInvalidationsAsync(string machineFingerprint, CancellationToken cancel = default) => inner.PendingInvalidationsAsync(machineFingerprint, cancel);

        public Task AcknowledgeInvalidationAsync(string machineFingerprint, int revision, CancellationToken cancel = default) => inner.AcknowledgeInvalidationAsync(machineFingerprint, revision, cancel);

        public Task<GrantResponse> GrantAsync(GrantEnvelope envelope, CancellationToken cancel = default) => inner.GrantAsync(envelope, cancel);

        public Task<ReconcileResponse> ReconcileAsync(ReconcileEnvelope envelope, CancellationToken cancel = default) => inner.ReconcileAsync(envelope, cancel);

        public Task<IReadOnlyList<PendingGrantEvent>> PendingGrantEventsAsync(string machineFingerprint, CancellationToken cancel = default) => inner.PendingGrantEventsAsync(machineFingerprint, cancel);

        public Task AcknowledgeGrantEventAsync(string machineFingerprint, long sequence, CancellationToken cancel = default) => inner.AcknowledgeGrantEventAsync(machineFingerprint, sequence, cancel);
    }

    /// <summary>A machine, its authority and a host, in a folder of their own.</summary>
    private sealed class Fixture : IDisposable
    {
        public Fixture(string parent, bool trusted = true, TestClock? clock = null)
        {
            Clock = clock;
            Machine = new TestMachine(Path.Combine(parent, "fx-" + Guid.NewGuid().ToString("N")[..8]), trusted, clock: clock);
            Gate = new LaunchGate();
            Scripted = new ScriptedAuthority(Machine.Deployment.Authority);
            Host = new HostAuthorization(Scripted, Machine.Deployment.MachineKey, Machine.HostName, Machine.Deployment.HostConfig, Gate, Machine.Deployment.Authority.Offer, clock);
        }

        public TestClock? Clock { get; }

        public TestMachine Machine { get; }

        public LaunchGate Gate { get; }

        public ScriptedAuthority Scripted { get; }

        public HostAuthorization Host { get; }

        public int Asked;

        public AuthorityStore Store => Machine.Deployment.Store;

        public string Fingerprint => Machine.Fingerprint;

        public DateTimeOffset Now => Clock?.GetUtcNow() ?? DateTimeOffset.UtcNow;

        public Task<AuthorizationOutcome> Ask(string id, bool approve = true, LaunchRequest? request = null)
            => Host.AuthorizeAsync(request ?? IdentityTests.Sample(id, Now), () =>
            {
                Interlocked.Increment(ref Asked);

                return approve ? ApprovalDecision.Allow() : ApprovalDecision.Deny("test denied");
            }, CancellationToken.None);

        public void Dispose() => Machine.Dispose();
    }

    public static async Task Run(Action<bool, string> check)
    {
        string parent = Path.Combine(Path.GetTempPath(), "ws-authority-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(parent);
        try
        {
            Tampering(check);
            await HostVerification(check, parent);
            await Enrollment(check, parent);
            Transitions(check, parent);
            await Idempotency(check, parent);
            Durability(check, parent);
            await KeyRotation(check, parent);
            await ThroughTheService(check, parent);
            await ReviewFixes(check, parent);
            await Throttle(check, parent);
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
                // A stray file in the temp folder is harmless.
            }
        }
    }

    // ---- signatures: every field ----

    private static void Tampering(Action<bool, string> check)
    {
        using SoftwareSigningKey machine = new();
        using SoftwareSigningKey stranger = new();
        using SoftwareSigningKey authority = new();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        LaunchRequest request = IdentityTests.Sample("tamper-1", now) with { EnvVariables = new Dictionary<string, string> { ["A"] = "b" }, EnvNames = ["A"], Arguments = ["one"] };
        MachineRequestEnvelope envelope = MachineRequestEnvelope.Create(request, "host-a", machine);
        check(envelope.Verify(machine.PublicKey) && envelope.MachineFingerprint == KeyIdentity.Fingerprint(machine.PublicKey) && envelope.RequestDigest == request.Digest(), "envelope: signed by the machine key over the canonical bytes, with its fingerprint and the request digest");
        check(!envelope.Verify(stranger.PublicKey), "envelope: another machine's key does not verify it");
        check(envelope.Canonical().StartsWith("{\"protocolVersion\":1,\"machineFingerprint\":\"", StringComparison.Ordinal) && envelope.Canonical().Contains("\"request\":{\"protocolVersion\":1,", StringComparison.Ordinal), "envelope: canonical JSON with the fields in a fixed order");

        byte[] flipped = [.. envelope.Signature];
        flipped[5] ^= 1;
        (string Field, MachineRequestEnvelope Changed)[] changed =
        [
            ("protocol version", envelope with { ProtocolVersion = 2 }),
            ("machine fingerprint", envelope with { MachineFingerprint = KeyIdentity.Fingerprint(stranger.PublicKey) }),
            ("host name", envelope with { HostName = "host-b" }),
            ("request digest", envelope with { RequestDigest = new string('A', 64) }),
            ("signature", envelope with { Signature = flipped }),
            ("signature length", envelope with { Signature = envelope.Signature[..63] }),
        ];
        foreach ((string field, MachineRequestEnvelope other) in changed)
        {
            check(!other.Verify(machine.PublicKey), "envelope: a changed " + field + " is rejected");
        }

        // Every field of the request: changed with the old digest (digest mismatch), and changed with a fresh digest (signature mismatch).
        Dictionary<string, LaunchRequest> variants = new()
        {
            ["ProtocolVersion"] = request with { ProtocolVersion = 2 },
            ["RequestId"] = request with { RequestId = request.RequestId + "x" },
            ["Created"] = request with { Created = request.Created.AddSeconds(1) },
            ["Expires"] = request with { Expires = request.Expires.AddSeconds(1) },
            ["ClientNonce"] = request with { ClientNonce = request.ClientNonce + "x" },
            ["SecretNames"] = request with { SecretNames = [.. request.SecretNames, "OTHER"] },
            ["Mappings"] = request with { Mappings = [.. request.Mappings, new LaunchMapping("X", "TOKEN")] },
            ["Reason"] = request with { Reason = request.Reason + "x" },
            ["Program"] = request with { Program = request.Program + "x" },
            ["Arguments"] = request with { Arguments = [.. request.Arguments, "two"] },
            ["WorkingDirectory"] = request with { WorkingDirectory = request.WorkingDirectory + "x" },
            ["EnvFiles"] = request with { EnvFiles = [.. request.EnvFiles, "x.env"] },
            ["EnvNames"] = request with { EnvNames = [.. request.EnvNames, "B"] },
            ["EnvVariables"] = request with { EnvVariables = new Dictionary<string, string> { ["A"] = "c" } },
            ["InheritedEnvironment"] = request with { InheritedEnvironment = new Dictionary<string, string> { ["PATH"] = "x" } },
            ["Encrypted"] = request with { Encrypted = [.. request.Encrypted, new LaunchEncrypted("V", "x.env", "DOTENV_PRIVATE_KEY", "encrypted:AAAA")] },
        };
        string[] properties = [.. typeof(LaunchRequest).GetProperties(BindingFlags.Public | BindingFlags.Instance).Where(property => property.Name != "EqualityContract").Select(property => property.Name).Order(StringComparer.Ordinal)];
        check(properties.SequenceEqual(variants.Keys.Order(StringComparer.Ordinal)), "envelope: every field of the launch request is tested (a new field must be added here)");
        foreach ((string field, LaunchRequest other) in variants)
        {
            check(!(envelope with { Request = other }).Verify(machine.PublicKey) && !(envelope with { Request = other, RequestDigest = other.Digest() }).Verify(machine.PublicKey), "envelope: a changed request " + field + " is rejected, with the old digest or a new one");
        }

        // The response.
        DateTimeOffset issued = now;
        AuthorityResponse response = AuthorityResponse.Create("tamper-1", request.Digest(), envelope.MachineFingerprint, AuthorityDecision.Approved, ReasonCodes.Approved, 3, issued, issued.AddMinutes(1), authority);
        check(response.Verify(authority.PublicKey) && response.AuthorityKeyId == KeyIdentity.Fingerprint(authority.PublicKey) && response.Canonical().StartsWith("{\"protocolVersion\":1,\"requestId\":\"tamper-1\",\"requestDigest\":", StringComparison.Ordinal), "response: signed by the authority key over canonical JSON");
        check(!response.Verify(stranger.PublicKey), "response: another key does not verify it");
        byte[] badSignature = [.. response.Signature];
        badSignature[0] ^= 0x80;
        Dictionary<string, AuthorityResponse> responses = new()
        {
            ["ProtocolVersion"] = response with { ProtocolVersion = 2 },
            ["RequestId"] = response with { RequestId = "tamper-2" },
            ["RequestDigest"] = response with { RequestDigest = new string('B', 64) },
            ["MachineFingerprint"] = response with { MachineFingerprint = KeyIdentity.Fingerprint(stranger.PublicKey) },
            ["Decision"] = response with { Decision = AuthorityDecision.Denied },
            ["ReasonCode"] = response with { ReasonCode = ReasonCodes.UserDenied },
            ["SecurityRevision"] = response with { SecurityRevision = 4 },
            ["Issued"] = response with { Issued = issued.AddSeconds(1) },
            ["Expires"] = response with { Expires = issued.AddMinutes(10) },
            ["AuthorityKeyId"] = response with { AuthorityKeyId = KeyIdentity.Fingerprint(stranger.PublicKey) },
            ["Signature"] = response with { Signature = badSignature },
        };
        string[] responseProperties = [.. typeof(AuthorityResponse).GetProperties(BindingFlags.Public | BindingFlags.Instance).Where(property => property.Name != "EqualityContract").Select(property => property.Name).Order(StringComparer.Ordinal)];
        check(responseProperties.SequenceEqual(responses.Keys.Order(StringComparer.Ordinal)), "response: every field is tested (a new field must be added here)");
        foreach ((string field, AuthorityResponse other) in responses)
        {
            check(!other.Verify(authority.PublicKey), "response: a changed " + field + " is rejected");
        }

        // Nothing that looks like a value.
        check(!responseProperties.Concat(properties).Any(name => name.Contains("Value", StringComparison.Ordinal) && name != "EnvVariables" || name.Contains("Plaintext", StringComparison.Ordinal) || name.Contains("Password", StringComparison.Ordinal)), "response: no member is named like a secret value");

        // Text form: round trip and strict parsing.
        string json = response.ToJson();
        check(AuthorityResponse.TryParse(json, out AuthorityResponse? parsed, out _) && parsed!.Verify(authority.PublicKey) && parsed.RequestId == "tamper-1" && parsed.SecurityRevision == 3 && parsed.Expires == response.Expires, "response: its JSON reads back and still verifies");
        string[] badJson =
        [
            json.Replace("\"reasonCode\":\"approved\",", "", StringComparison.Ordinal),
            json.Replace("\"decision\":\"approved\"", "\"decision\":\"maybe\"", StringComparison.Ordinal),
            json.Replace("\"securityRevision\":3", "\"securityRevision\":\"3\"", StringComparison.Ordinal),
            json[..^1] + ",\"extra\":1}",
            json.Replace("\"requestId\":\"tamper-1\"", "\"requestId\":\"tamper-1\",\"requestId\":\"tamper-2\"", StringComparison.Ordinal),
            json.Replace("\"signature\":\"", "\"signature\":\"AAAA", StringComparison.Ordinal),
            json + " trailing",
            "[]",
        ];
        check(badJson.All(text => !AuthorityResponse.TryParse(text, out _, out _)), "response: a missing, unknown, repeated or wrongly typed member, a bad decision or signature length, trailing text are all refused");
    }

    // ---- the host verifies before anything is decrypted ----

    private static bool Rejected(AuthorizationOutcome outcome, string part)
        => !outcome.Decision.Approved && outcome.Code == "response-invalid" && outcome.AuthorityMessage!.Contains(part, StringComparison.Ordinal) && outcome.AuthorityMessage.Contains("Nothing was run", StringComparison.Ordinal);

    private static AuthorityResponse Resign(AuthorityResponse response, ISigningKey key, string? requestId = null, string? digest = null, int? revision = null, DateTimeOffset? issued = null, DateTimeOffset? expires = null)
        => AuthorityResponse.Create(requestId ?? response.RequestId, digest ?? response.RequestDigest, response.MachineFingerprint, response.Decision, response.ReasonCode, revision ?? response.SecurityRevision, issued ?? response.Issued, expires ?? response.Expires, key);

    private static async Task HostVerification(Action<bool, string> check, string parent)
    {
        using Fixture fx = new(parent);
        using SoftwareSigningKey stranger = new();
        ISigningKey real = fx.Machine.AuthorityKey(1);

        AuthorizationOutcome good = await fx.Ask("host-1");
        check(good.Decision.Approved && good.Code == ReasonCodes.Approved && fx.Asked == 1 && fx.Host.KnownRevision == 1, "host: a response signed by the pinned key for exactly this request is accepted (revision 1)");

        // A tampered field of an otherwise genuine response: the signature no longer matches.
        (string Name, Func<AuthorityResponse, AuthorityResponse> Change)[] tampers =
        [
            ("reason code", r => r with { ReasonCode = "approved-by-someone" }),
            ("decision", r => r with { Decision = r.Decision == AuthorityDecision.Approved ? AuthorityDecision.Denied : AuthorityDecision.Approved }),
            ("request id", r => r with { RequestId = r.RequestId + "x" }),
            ("request digest", r => r with { RequestDigest = new string('C', 64) }),
            ("machine fingerprint", r => r with { MachineFingerprint = KeyIdentity.Fingerprint(stranger.PublicKey) }),
            ("security revision", r => r with { SecurityRevision = r.SecurityRevision + 1 }),
            ("issue time", r => r with { Issued = r.Issued.AddSeconds(-1) }),
            ("expiry", r => r with { Expires = r.Expires.AddMinutes(1) }),
            ("signature", r => r with { Signature = [.. r.Signature.Select(value => (byte)(value ^ 1))] }),
        ];
        int number = 0;
        foreach ((string name, Func<AuthorityResponse, AuthorityResponse> change) in tampers)
        {
            fx.Scripted.Tamper = change;
            AuthorizationOutcome outcome = await fx.Ask("host-t" + number++);
            check(Rejected(outcome, "signature does not verify") || Rejected(outcome, "not pinned"), "host: a changed " + name + " in the authority's answer is rejected before anything is decrypted (" + outcome.AuthorityMessage + ")");
        }

        // Signed by a key that is not the pinned one, or for another request, or not issued sensibly.
        fx.Scripted.Tamper = r => Resign(r, stranger);
        check(Rejected(await fx.Ask("host-w1"), "not pinned"), "host: an answer signed by any other key is rejected");
        fx.Scripted.Tamper = r => Resign(r, real, requestId: "another-request");
        check(Rejected(await fx.Ask("host-w2"), "another request id"), "host: a genuine answer for another request id is rejected");
        fx.Scripted.Tamper = r => Resign(r, real, digest: new string('D', 64));
        check(Rejected(await fx.Ask("host-w3"), "another request digest"), "host: a genuine answer for another request digest is rejected");
        fx.Scripted.Tamper = r => Resign(r, real, issued: r.Issued.AddMinutes(10), expires: r.Expires.AddMinutes(10));
        check(Rejected(await fx.Ask("host-w4"), "issued in the future"), "host: an answer issued in the future is rejected");
        fx.Scripted.Tamper = r => Resign(r, real, expires: r.Issued.AddMinutes(30));
        check(Rejected(await fx.Ask("host-w5"), "valid for too long"), "host: an answer that stays valid for too long is rejected");
        fx.Scripted.Tamper = r => Resign(r, real, revision: 0);
        check(!(await fx.Ask("host-w6")).Decision.Approved && fx.Host.KnownRevision == 1, "host: an answer for an older security revision than the host applied is rejected");
        fx.Scripted.Tamper = null;
        check((await fx.Ask("host-ok")).Decision.Approved, "host: after all those refusals a genuine answer is still accepted");

        // Expiry, with a clock: a stored answer that is retried after its time is rejected, not honoured.
        TestClock clock = new();
        using Fixture timed = new(parent, clock: clock);
        check((await timed.Ask("timed-1")).Decision.Approved, "expiry: a fresh answer is accepted");
        clock.Advance(LocalAuthority.ResponseLifetime + TimeSpan.FromSeconds(1));
        LaunchRequest retried = IdentityTests.Sample("timed-1", clock.GetUtcNow().AddSeconds(-61)) with { Expires = clock.GetUtcNow().AddMinutes(5) };
        AuthorizationOutcome late = await timed.Ask("timed-1", request: retried with { Created = clock.GetUtcNow().AddSeconds(-61) });
        check(!late.Decision.Approved, "expiry: a retry after the answer's lifetime does not launch (" + late.Code + ")");
        TestClock clock2 = new();
        using Fixture second = new(parent, clock: clock2);
        LaunchRequest same = IdentityTests.Sample("timed-2", clock2.GetUtcNow());
        AuthorizationOutcome first = await second.Ask("timed-2", request: same);
        clock2.Advance(TimeSpan.FromMinutes(2));
        second.Scripted.Tamper = null;
        AuthorizationOutcome replay = await second.Ask("timed-2", request: same);
        check(first.Decision.Approved && Rejected(replay, "expired"), "expiry: the stored approved answer, returned again after its expiry, is rejected as expired (" + replay.AuthorityMessage + ")");

        // A replayed request id returns the committed answer and asks nobody again; with no approval of its own, the host does not launch.
        using Fixture replayed = new(parent);
        LaunchRequest sameRequest = IdentityTests.Sample("replay-1", replayed.Now);
        AuthorizationOutcome one = await replayed.Ask("replay-1", request: sameRequest);
        AuthorizationOutcome two = await replayed.Ask("replay-1", request: sameRequest);
        check(one.Decision.Approved && !two.Decision.Approved && two.Code == "no-approval" && replayed.Asked == 1, "replay: the same request id is not approved twice; the approval is asked once (" + two.Code + ")");

        // The pin: no host.json, a damaged one, another machine's.
        using Fixture unpinned = new(parent, trusted: false);
        AuthorizationOutcome pending = await unpinned.Ask("pin-1");
        check(!pending.Decision.Approved && pending.Code == ReasonCodes.MachinePending && pending.AuthorityMessage!.Contains(unpinned.Fingerprint, StringComparison.Ordinal) && pending.AuthorityMessage.Contains("admin web app", StringComparison.Ordinal) && unpinned.Asked == 0, "pin: with nothing pinned the host refuses and names the admin approve command, and asks nobody");
        File.WriteAllText(fx.Machine.Deployment.HostConfig.FilePath, "{ not json");
        AuthorizationOutcome damaged = await fx.Ask("pin-2");
        check(!damaged.Decision.Approved && damaged.AuthorityMessage!.Contains("host.json", StringComparison.Ordinal), "pin: a damaged host.json is a refusal, not 'nothing pinned' (" + damaged.AuthorityMessage + ")");
        fx.Machine.Deployment.HostConfig.Pin(KeyIdentity.Fingerprint(stranger.PublicKey), new PinnedAuthorityKey(fx.Machine.Deployment.Keys.CurrentRecord().Fingerprint, fx.Machine.Deployment.Keys.CurrentRecord().PublicKey, DateTimeOffset.UtcNow));
        check(!(await fx.Ask("pin-3")).Decision.Approved, "pin: a host.json that belongs to another machine identity is a refusal");
        AdminActions.PinLocal(fx.Machine.Deployment.Keys, fx.Machine.Deployment.HostConfig, fx.Fingerprint);
        check((await fx.Ask("pin-4")).Decision.Approved, "pin: repinned, the host works again");

        // A revision that moved on: the host clears its authorization state and refuses this launch; the next one is fine.
        using Fixture moved = new(parent);
        check((await moved.Ask("rev-1")).Decision.Approved && moved.Host.KnownRevision == 1, "revision: first answer sets the host's revision to 1");
        moved.Store.Disable(moved.Fingerprint, "test");
        moved.Store.Enable(moved.Fingerprint, "test");
        int gateBefore = moved.Gate.Revision;
        AuthorizationOutcome stale = await moved.Ask("rev-2");
        check(!stale.Decision.Approved && stale.Code == ReasonCodes.AuthorizationChanged && moved.Gate.Revision == gateBefore + 1 && moved.Host.KnownRevision == 2, "revision: a newer revision than the host knew clears the host's state and refuses that launch (" + stale.Code + ")");
        check((await moved.Ask("rev-3")).Decision.Approved, "revision: the next launch starts from the new revision");
    }

    // ---- enrollment ----

    private static async Task Enrollment(Action<bool, string> check, string parent)
    {
        TestClock clock = new();
        using Fixture fx = new(parent, trusted: false, clock: clock);
        LocalAuthority authority = fx.Machine.Deployment.Authority;
        using SoftwareSigningKey newcomer = new();
        string fingerprint = KeyIdentity.Fingerprint(newcomer.PublicKey);

        byte[] challenge = await authority.BeginEnrollmentAsync();
        EnrollmentRequest request = EnrollmentRequest.Create("newcomer", challenge, newcomer);
        EnrollmentResult result = await authority.EnrollAsync(request);
        MachineRecord? record = fx.Store.Find(fingerprint);
        check(result is { Accepted: true, Status: MachineStatus.Pending } && record is { Status: MachineStatus.Pending, SecurityRevision: 1, HostName: "newcomer", FriendlyName: null }, "enroll: first contact with proof of possession records the machine as Pending");
        check(fx.Store.History(fingerprint).Single().Kind == "registered" && fx.Store.Audit().Any(entry => entry.Event == "machine-registered" && entry.Fingerprint == fingerprint), "enroll: recorded in the machine history and the audit history");

        check(!(await authority.EnrollAsync(request)).Accepted, "enroll: the challenge is single use (replaying the same proof is refused)");
        byte[] second = await authority.BeginEnrollmentAsync();
        check(!(await authority.EnrollAsync(EnrollmentRequest.Create("newcomer", RandomBytes(32), newcomer))).Accepted, "enroll: a challenge the authority did not issue is refused");
        using SoftwareSigningKey thief = new();
        EnrollmentRequest forged = EnrollmentRequest.Create("newcomer", second, newcomer);
        check(!(await authority.EnrollAsync(forged with { Signature = thief.Sign(forged.SigningBytes()) })).Accepted, "enroll: a signature by another key is refused (no proof of possession)");
        byte[] third = await authority.BeginEnrollmentAsync();
        EnrollmentRequest changedHost = EnrollmentRequest.Create("newcomer", third, newcomer);
        check(!(await authority.EnrollAsync(changedHost with { HostName = "elsewhere" })).Accepted, "enroll: the host name is covered by the proof");
        byte[] fourth = await authority.BeginEnrollmentAsync();
        EnrollmentRequest claimed = EnrollmentRequest.Create("claimer", fourth, thief);
        check(!(await authority.EnrollAsync(claimed with { Fingerprint = fingerprint })).Accepted && !(await authority.EnrollAsync(claimed with { PublicKey = [.. claimed.PublicKey, 0] })).Accepted, "enroll: a fingerprint that is not the key's, or a key that is not canonical, is refused");
        check(!(await authority.EnrollAsync(EnrollmentRequest.Create("bad\nname", await authority.BeginEnrollmentAsync(), thief))).Accepted && !(await authority.EnrollAsync(EnrollmentRequest.Create("", await authority.BeginEnrollmentAsync(), thief))).Accepted, "enroll: a host name with a control character, or empty, is refused");
        check(fx.Store.Find(KeyIdentity.Fingerprint(thief.PublicKey)) is null, "enroll: nothing was recorded for the refused attempts");

        byte[] stale = await authority.BeginEnrollmentAsync();
        EnrollmentRequest late = EnrollmentRequest.Create("late", stale, thief);
        clock.Advance(TimeSpan.FromMinutes(3));
        check(!(await authority.EnrollAsync(late)).Accepted, "enroll: an expired challenge is refused");

        // Known machine: nothing changes; a different host name is recorded as pending review, not applied.
        EnrollmentResult again = await authority.EnrollAsync(EnrollmentRequest.Create("newcomer", await authority.BeginEnrollmentAsync(), newcomer));
        check(again is { Accepted: true, Status: MachineStatus.Pending } && fx.Store.Machines().Count(machine => machine.Fingerprint == fingerprint) == 1 && fx.Store.History(fingerprint).Count == 1, "enroll: a second start does not enroll twice or change anything");
        AdminActions.ApproveMachine(fx.Store, fx.Machine.Deployment.Keys, fx.Machine.Deployment.HostConfig, null, fingerprint, "newcomer box", "test");
        EnrollmentResult renamed = await authority.EnrollAsync(EnrollmentRequest.Create("newcomer-renamed", await authority.BeginEnrollmentAsync(), newcomer));
        record = fx.Store.Find(fingerprint);
        check(renamed.Status == MachineStatus.Trusted && record is { HostName: "newcomer", PendingHostName: "newcomer-renamed", Status: MachineStatus.Trusted, SecurityRevision: 1 }, "enroll: a Trusted machine that comes back under another host name keeps its binding and status; the name waits for review");

        // The challenges are capped.
        bool refusedAtCap = false;
        try
        {
            for (int index = 0; index < 100; index++)
            {
                await authority.BeginEnrollmentAsync();
            }
        }
        catch (InvalidOperationException)
        {
            refusedAtCap = true;
        }

        check(refusedAtCap, "enroll: unanswered challenges are capped");
    }

    private static byte[] RandomBytes(int count) => System.Security.Cryptography.RandomNumberGenerator.GetBytes(count);

    // ---- the status table ----

    private static MachineRecord Machine(AuthorityStore store, string fingerprint) => store.Find(fingerprint)!;

    private static void Transitions(Action<bool, string> check, string parent)
    {
        using Fixture fx = new(parent, trusted: false);
        AuthorityStore store = fx.Store;
        string fp = fx.Fingerprint;
        // A different fingerprint that cannot accidentally equal fp (which a random key would make possible with "00" + fp[2..]).
        string unknownFp = (fp[0] == '0' ? '1' : '0') + fp[1..];
        fx.Machine.Deployment.EnrollAsync().GetAwaiter().GetResult();
        int Histories() => store.History(fp).Count;
        int Audits() => store.Audit().Count;

        // Pending
        check(!store.Disable(fp, "a").Ok && !store.Enable(fp, "a").Ok && !store.Trust(fp, fp, "a").Ok && Machine(store, fp).Status == MachineStatus.Pending && Histories() == 1, "table: a Pending machine cannot be disabled, enabled or trusted (only approved)");
        int before = Audits();
        check(!store.Approve(fp, "", "a").Ok && !store.Approve(fp, "bad\nname", "a").Ok && !store.Approve(fp, new string('x', 41), "a").Ok && Machine(store, fp).Status == MachineStatus.Pending && Audits() == before, "table: approval needs a usable friendly name; a refusal records nothing");
        check(!store.Approve(unknownFp, "name", "a").Ok && store.Approve(unknownFp, "name", "a").Message == "no such machine", "table: an unknown fingerprint is refused");
        check(!store.Approve(fp, "name", "a", expectedRevision: 99).Ok && Machine(store, fp).Status == MachineStatus.Pending, "table: a change made against a revision that moved on is refused");

        TransitionResult approved = store.Approve(fp, "dev laptop", "admin passkey laptop");
        check(approved.Ok && approved.Machine is { Status: MachineStatus.Trusted, FriendlyName: "dev laptop", SecurityRevision: 1 } && Histories() == 2, "table: Pending to Trusted with a friendly name, no revision change");
        check(!store.Approve(fp, "again", "a").Ok && !store.Enable(fp, "a").Ok && !store.Trust(fp, fp, "a").Ok, "table: a Trusted machine cannot be approved, enabled or trusted again");
        check(store.Audit().Any(entry => entry.Event == "machine-approve" && entry.Actor == "admin passkey laptop" && entry.Fingerprint == fp), "table: the audit history names the administrator's key");

        // Friendly name: display only.
        store.AddGrant("g1", fp, "scope-1", null);
        store.AddGrant("g2", fp, "scope-2", DateTimeOffset.UtcNow.AddHours(1));
        int histories = Histories();
        TransitionResult renamed = store.Rename(fp, "renamed laptop", "admin passkey laptop");
        check(renamed.Ok && renamed.Machine is { FriendlyName: "renamed laptop", SecurityRevision: 1, Status: MachineStatus.Trusted } && store.ActiveGrants(fp).Count == 2 && store.PendingInvalidations(fp).Count == 0 && Histories() == histories + 1
            && store.Audit().Any(entry => entry.Event == "machine-rename" && entry.Detail.Contains("dev laptop", StringComparison.Ordinal)), "table: a friendly-name change is audited, keeps the revision, the grants and invalidates nothing");
        check(!store.Rename(fp, "", "a").Ok && !store.Rename(fp, "x\ty\u0007", "a").Ok, "table: a bad friendly name is refused");

        // Trusted to Disabled: the revision goes up, the grants end, the invalidation is queued.
        TransitionResult disabled = store.Disable(fp, "admin passkey laptop");
        check(disabled.Ok && disabled.Machine is { Status: MachineStatus.Disabled, SecurityRevision: 2 } && store.ActiveGrants(fp).Count == 0 && store.PendingInvalidations(fp).SequenceEqual([new PendingInvalidation(fp, 2)]), "table: Trusted to Disabled raises the revision to 2, invalidates every grant and queues the invalidation for revision 2");
        check(store.Audit().Any(entry => entry.Event == "machine-disable" && entry.Detail.Contains("security revision 1 to 2", StringComparison.Ordinal) && entry.Detail.Contains("2 grant(s) invalidated", StringComparison.Ordinal)), "table: the audit records the status change, the revision, the grants ended and the pending work");
        check(!store.Disable(fp, "a").Ok && !store.Approve(fp, "x", "a").Ok && !store.Trust(fp, fp, "a").Ok, "table: a Disabled machine cannot be disabled again, approved or trusted (only enabled)");

        // Disabled to Trusted starts clean.
        TransitionResult enabled = store.Enable(fp, "admin passkey laptop");
        check(enabled.Ok && enabled.Machine is { Status: MachineStatus.Trusted, SecurityRevision: 2 } && store.ActiveGrants(fp).Count == 0, "table: Disabled to Trusted keeps revision 2 and restores no old grant (starts clean)");
        store.AddGrant("g3", fp, "scope-3", null);
        check(store.ActiveGrants(fp).SequenceEqual(["g3"]), "table: only grants made after the re-enable exist");

        // Trusted to Untrusted.
        TransitionResult untrusted = store.Untrust(fp, "admin passkey laptop");
        check(untrusted.Ok && untrusted.Machine is { Status: MachineStatus.Untrusted, SecurityRevision: 3 } && store.ActiveGrants(fp).Count == 0 && store.PendingInvalidations(fp).Select(item => item.Revision).SequenceEqual([2, 3]), "table: Trusted to Untrusted raises the revision to 3 and invalidates the grants");
        check(!store.Untrust(fp, "a").Ok && !store.Disable(fp, "a").Ok && !store.Enable(fp, "a").Ok && !store.Approve(fp, "x", "a").Ok, "table: an Untrusted machine can only be trusted again");

        // Untrusted to Trusted needs the full fingerprint.
        check(!store.Trust(fp, fp[..12], "a").Ok && !store.Trust(fp, unknownFp, "a").Ok && !store.Trust(fp, "", "a").Ok && Machine(store, fp).Status == MachineStatus.Untrusted, "table: Untrusted to Trusted refuses a prefix, another fingerprint or nothing as the confirmation");
        TransitionResult trusted = store.Trust(fp, KeyIdentity.Display(fp).ToLowerInvariant(), "admin passkey laptop");
        check(trusted.Ok && trusted.Machine is { Status: MachineStatus.Trusted, SecurityRevision: 3 } && store.ActiveGrants(fp).Count == 0 && trusted.Message.Contains("explicit confirmation", StringComparison.Ordinal), "table: with the full fingerprint confirmed, Untrusted to Trusted keeps revision 3 and starts clean");

        // Disabled to Untrusted does not raise the revision again; Pending can be rejected.
        store.Disable(fp, "a");
        check(Machine(store, fp).SecurityRevision == 4, "table: a second disable raises the revision to 4");
        TransitionResult both = store.Untrust(fp, "a");
        check(both.Ok && both.Machine is { Status: MachineStatus.Untrusted, SecurityRevision: 4 } && store.PendingInvalidations(fp).Select(item => item.Revision).SequenceEqual([2, 3, 4]), "table: Disabled to Untrusted ends nothing more, so the revision stays 4");
        using SoftwareSigningKey other = new();
        string otherFp = fx.Machine.Deployment.Store.Register(other.PublicKey, "other-host", "test").Fingerprint;
        check(store.Untrust(otherFp, "a").Ok && Machine(store, otherFp) is { Status: MachineStatus.Untrusted, SecurityRevision: 1 }, "table: a Pending machine can be rejected (Untrusted) without a revision change");

        // Host name changes.
        check(!store.ApproveHostChange(fp, "a").Ok, "table: with no host name waiting, approving a host name change is refused");
        store.RecordHostMismatch(fp, "renamed-host");
        MachineRecord withPending = Machine(store, fp);
        check(withPending is { HostName: "test-host", PendingHostName: "renamed-host", Status: MachineStatus.Untrusted } && store.History(fp).Last().Kind == "host-name-mismatch", "table: a different host name is recorded as pending and the binding is unchanged");
        TransitionResult hostApproved = store.ApproveHostChange(fp, "admin passkey laptop");
        check(hostApproved.Ok && hostApproved.Machine is { HostName: "renamed-host", PendingHostName: null, SecurityRevision: 4 }, "table: approving the change binds the new host name, with no revision change");

        // Every history row has an audit row; failed operations left neither.
        check(store.History(fp).All(entry => entry.Actor.Length > 0) && store.Audit().Count >= store.History(fp).Count, "table: every status change is in the history and the audit history");
        check(store.FindByPrefix(fp[..12]).Single().Fingerprint == fp && store.FindByPrefix("FFFFFFFFFFFF").Count == 0, "table: a prefix finds the machine");
    }

    // ---- idempotency ----

    private static async Task Idempotency(Action<bool, string> check, string parent)
    {
        using Fixture fx = new(parent);
        LocalAuthority authority = fx.Machine.Deployment.Authority;
        DateTimeOffset now = DateTimeOffset.UtcNow;
        LaunchRequest request = IdentityTests.Sample("idem-1", now);
        MachineRequestEnvelope envelope = MachineRequestEnvelope.Create(request, fx.Machine.HostName, fx.Machine.MachineKey);
        int asked = 0;
        using (authority.Offer(request.RequestId, request.Digest(), () =>
        {
            Interlocked.Increment(ref asked);

            return ApprovalDecision.Allow();
        }))
        {
            AuthorityResponse first = await authority.DecideAsync(envelope);
            AuthorityResponse retry = await authority.DecideAsync(envelope);
            check(first.Decision == AuthorityDecision.Approved && retry.ToJson() == first.ToJson() && asked == 1, "idempotent: a retry of the request id returns the committed answer (same bytes, same signature), no second page");
            check(fx.Store.GetProcessed("idem-1") is { Response: { } stored } && stored.ToJson() == first.ToJson() && fx.Store.Audit().Count(entry => entry.Event == "decision-approved" && entry.RequestId == "idem-1") == 1, "idempotent: the result is in processed_requests and audited once");

            // A simulated restart: new objects over the same files. The answer comes from the database; nobody is asked.
            LocalDeployment restarted = fx.Machine.Restart();
            AuthorityResponse afterRestart = await restarted.Authority.DecideAsync(envelope);
            check(afterRestart.ToJson() == first.ToJson() && asked == 1, "idempotent: after a restart (database reopened) the same request id returns the same committed answer");
            AuthorityStore reopened = AuthorityStore.InFolder(fx.Machine.Folder);
            check(reopened.GetProcessed("idem-1")!.Response.ToJson() == first.ToJson(), "idempotent: a fresh store object reads the committed result");
        }

        // Another request under a used id is refused and changes nothing.
        LaunchRequest other = request with { Reason = "something else" };
        AuthorityResponse reused = await fx.Machine.Deployment.Authority.DecideAsync(MachineRequestEnvelope.Create(other, fx.Machine.HostName, fx.Machine.MachineKey));
        check(reused.Decision == AuthorityDecision.Denied && reused.ReasonCode == ReasonCodes.RequestIdReused && fx.Store.GetProcessed("idem-1")!.RequestDigest == request.Digest(), "idempotent: a different request under a used id is denied and the stored result is untouched");

        // A denial is a committed result too.
        LaunchRequest denied = IdentityTests.Sample("idem-2", now);
        int deniedAsked = 0;
        MachineRequestEnvelope deniedEnvelope = MachineRequestEnvelope.Create(denied, fx.Machine.HostName, fx.Machine.MachineKey);
        using (fx.Machine.Deployment.Authority.Offer(denied.RequestId, denied.Digest(), () =>
        {
            deniedAsked++;

            return ApprovalDecision.Deny("no thanks");
        }))
        {
            AuthorityResponse no = await fx.Machine.Deployment.Authority.DecideAsync(deniedEnvelope);
            AuthorityResponse noAgain = await fx.Machine.Deployment.Authority.DecideAsync(deniedEnvelope);
            check(no.ReasonCode == ReasonCodes.UserDenied && noAgain.ToJson() == no.ToJson() && deniedAsked == 1, "idempotent: a denial is committed and returned again, not asked again");
        }

        // Two callers at once with the same id share one decision.
        LaunchRequest raced = IdentityTests.Sample("idem-3", now);
        MachineRequestEnvelope racedEnvelope = MachineRequestEnvelope.Create(raced, fx.Machine.HostName, fx.Machine.MachineKey);
        int racedAsked = 0;
        using (fx.Machine.Deployment.Authority.Offer(raced.RequestId, raced.Digest(), () =>
        {
            Interlocked.Increment(ref racedAsked);
            Thread.Sleep(300);

            return ApprovalDecision.Allow();
        }))
        {
            AuthorityResponse[] both = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => fx.Machine.Deployment.Authority.DecideAsync(racedEnvelope)));
            check(racedAsked == 1 && both.All(answer => answer.ToJson() == both[0].ToJson()), "idempotent: concurrent retries share one decision (asked once)");
        }

        // A request that nobody offered an approval for, a different digest than offered, an approver that throws.
        LaunchRequest unoffered = IdentityTests.Sample("idem-4", now);
        AuthorityResponse none = await fx.Machine.Deployment.Authority.DecideAsync(MachineRequestEnvelope.Create(unoffered, fx.Machine.HostName, fx.Machine.MachineKey));
        check(none.Decision == AuthorityDecision.Denied && none.ReasonCode == ReasonCodes.NoApprovalChannel, "decide: with no approval offered the answer is a denial");
        LaunchRequest mismatched = IdentityTests.Sample("idem-5", now);
        using (fx.Machine.Deployment.Authority.Offer(mismatched.RequestId, new string('E', 64), () => ApprovalDecision.Allow()))
        {
            AuthorityResponse wrong = await fx.Machine.Deployment.Authority.DecideAsync(MachineRequestEnvelope.Create(mismatched, fx.Machine.HostName, fx.Machine.MachineKey));
            check(wrong.ReasonCode == ReasonCodes.DigestMismatch, "decide: an approval offered for another digest is not shown for this request");
        }

        LaunchRequest thrown = IdentityTests.Sample("idem-6", now);
        using (fx.Machine.Deployment.Authority.Offer(thrown.RequestId, thrown.Digest(), () => throw new InvalidOperationException("page failed")))
        {
            AuthorityResponse failed = await fx.Machine.Deployment.Authority.DecideAsync(MachineRequestEnvelope.Create(thrown, fx.Machine.HostName, fx.Machine.MachineKey));
            check(failed.Decision == AuthorityDecision.Denied && failed.ReasonCode == ReasonCodes.UserDenied, "decide: an approval that fails is a denial");
        }

        // A stranger and a forged signature are answered with a denial and recorded nowhere.
        using SoftwareSigningKey stranger = new();
        LaunchRequest strange = IdentityTests.Sample("idem-7", now);
        AuthorityResponse unknown = await fx.Machine.Deployment.Authority.DecideAsync(MachineRequestEnvelope.Create(strange, "host", stranger));
        MachineRequestEnvelope forged = MachineRequestEnvelope.Create(strange, fx.Machine.HostName, fx.Machine.MachineKey) with { Signature = stranger.Sign([1, 2, 3]) };
        AuthorityResponse bad = await fx.Machine.Deployment.Authority.DecideAsync(forged);
        check(unknown.ReasonCode == ReasonCodes.UnknownMachine && bad.ReasonCode == ReasonCodes.BadSignature && fx.Store.GetProcessed("idem-7") is null && fx.Store.Machines().Count == 1, "decide: an unknown machine or a bad signature is denied and nothing is stored for it");
        LaunchRequest expired = IdentityTests.Sample("idem-8", now.AddHours(-1));
        AuthorityResponse old = await fx.Machine.Deployment.Authority.DecideAsync(MachineRequestEnvelope.Create(expired, fx.Machine.HostName, fx.Machine.MachineKey));
        check(old.ReasonCode == ReasonCodes.InvalidRequest, "decide: an expired request is denied as invalid");
    }

    // ---- durability ----

    private static void Durability(Action<bool, string> check, string parent)
    {
        using Fixture fx = new(parent);
        AuthorityStore store = fx.Store;
        string fp = fx.Fingerprint;
        store.AddGrant("d1", fp, "scope", null);

        (int History, int Audit, int Invalidations, int Grants, MachineStatus Status, int Revision) Snapshot() => (store.History(fp).Count, store.Audit().Count, store.PendingInvalidations(fp).Count, store.ActiveGrants(fp).Count, Machine(store, fp).Status, Machine(store, fp).SecurityRevision);

        // A fault inside the transaction, at every step of a disable: nothing at all is left.
        foreach (string point in new[] { "after-update", "after-grants", "after-invalidation", "after-history", "before-commit" })
        {
            var before = Snapshot();
            store.Fault = reached =>
            {
                if (reached == point)
                {
                    throw new InvalidOperationException("injected fault");
                }
            };
            bool threw = false;
            try
            {
                store.Disable(fp, "test");
            }
            catch (InvalidOperationException)
            {
                threw = true;
            }

            store.Fault = null;
            check(threw && Snapshot() == before, "atomic: a fault at " + point + " during a disable leaves no partial effect (status, revision, grants, invalidations, history, audit)");
        }

        var committed = Snapshot();
        check(store.Disable(fp, "test").Ok, "atomic: the same disable then succeeds");
        var after = Snapshot();
        check(after.Status == MachineStatus.Disabled && after.Revision == committed.Revision + 1 && after.Grants == 0 && after.Invalidations == committed.Invalidations + 1 && after.History == committed.History + 1 && after.Audit == committed.Audit + 1, "atomic: one disable is one revision step, one history row, one audit row, one invalidation");

        // A committed operation remains committed when everything is dropped and reopened.
        SqliteConnection.ClearAllPools();
        AuthorityStore reopened = AuthorityStore.InFolder(fx.Machine.Folder);
        check(reopened.Find(fp) is { Status: MachineStatus.Disabled, SecurityRevision: 2 } && reopened.PendingInvalidations(fp).Count == 1 && reopened.ActiveGrants(fp).Count == 0, "durable: a committed disable is still there after a reopen");

        // Registration and a decision are atomic too.
        using SoftwareSigningKey newcomer = new();
        foreach (string point in new[] { "after-update", "before-commit" })
        {
            store.Fault = reached =>
            {
                if (reached == point)
                {
                    throw new InvalidOperationException("injected fault");
                }
            };
            try
            {
                store.Register(newcomer.PublicKey, "newcomer", "test");
            }
            catch (InvalidOperationException)
            {
                // Expected.
            }

            store.Fault = null;
            check(store.Find(KeyIdentity.Fingerprint(newcomer.PublicKey)) is null && store.Machines().Count == 1, "atomic: a fault at " + point + " during registration records no machine");
        }

        store.Enable(fp, "test");
        DateTimeOffset now = DateTimeOffset.UtcNow;
        LaunchRequest request = IdentityTests.Sample("dur-1", now);
        foreach (string point in new[] { "after-result", "before-commit" })
        {
            int audits = store.Audit().Count;
            store.Fault = reached =>
            {
                if (reached == point)
                {
                    throw new InvalidOperationException("injected fault");
                }
            };
            try
            {
                store.RecordDecision(request.RequestId, request.Digest(), fp, machine => new DecisionPlan(AuthorityResponse.Create(request.RequestId, request.Digest(), fp, AuthorityDecision.Approved, ReasonCodes.Approved, machine!.SecurityRevision, now, now.AddMinutes(1), fx.Machine.AuthorityKey(1)), null, "x"));
            }
            catch (InvalidOperationException)
            {
                // Expected.
            }

            store.Fault = null;
            check(store.GetProcessed("dur-1") is null && store.Audit().Count == audits, "atomic: a fault at " + point + " while recording a decision stores no result and no audit row, so a retry decides afresh");
        }

        // Key rotation is atomic.
        foreach (string point in new[] { "after-retire", "before-commit" })
        {
            fx.Machine.Deployment.Keys.CurrentRecord();
            int generation = store.ActiveKey()!.Generation;
            store.Fault = reached =>
            {
                if (reached == point)
                {
                    throw new InvalidOperationException("injected fault");
                }
            };
            try
            {
                fx.Machine.Deployment.Keys.Rotate("test");
            }
            catch (InvalidOperationException)
            {
                // Expected.
            }

            store.Fault = null;
            check(store.ActiveKey()!.Generation == generation && store.AuthorityKeys().Count == generation && store.AuthorityKeys().Count(key => key.Status == "Active") == 1, "atomic: a fault at " + point + " during a key rotation leaves the old key active and no new one");
        }

        // Parallel disables: exactly one wins; the revision goes up once.
        store.Enable(fp, "test");
        int revision = Machine(store, fp).SecurityRevision;
        TransitionResult[] results = Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() => AuthorityStore.InFolder(fx.Machine.Folder).Disable(fp, "racer")))).GetAwaiter().GetResult();
        check(results.Count(result => result.Ok) == 1 && Machine(store, fp).SecurityRevision == revision + 1, "atomic: eight parallel disables (separate connections) make one revision step");

        // Schema version, damage, and a missing file.
        string folder = Path.Combine(parent, "schema");
        AuthorityStore missing = AuthorityStore.InFolder(folder);
        check(missing.Machines().Count == 0 && missing.Find("X") is null && !File.Exists(missing.FilePath) && !Directory.Exists(folder), "schema: reading a missing authority.db is empty and creates nothing");
        AuthorityStore created = AuthorityStore.InFolder(folder);
        created.Register(newcomer.PublicKey, "newcomer", "test");
        check(File.Exists(created.FilePath) && new FileInfo(created.FilePath).Length > 0 && created.Machines().Count == 1, "schema: the first write creates authority.db");
        using (SqliteConnection connection = new("Data Source=" + created.FilePath + ";Pooling=False"))
        {
            connection.Open();
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "PRAGMA journal_mode";
            string mode = command.ExecuteScalar()!.ToString()!;
            check(mode.Equals("wal", StringComparison.OrdinalIgnoreCase), "schema: the database uses WAL");
            command.CommandText = "UPDATE schema_version SET version = 99";
            command.ExecuteNonQuery();
        }

        AuthorityDatabaseException? mismatch = null;
        try
        {
            AuthorityStore.InFolder(folder).Machines();
        }
        catch (AuthorityDatabaseException error)
        {
            mismatch = error;
        }

        check(mismatch is not null && mismatch.Message == "authority.db is not of schema version 5; delete authority.db to start over (machines then enroll again)", "schema: another schema version is refused with the delete-it message (" + mismatch?.Message + ")");
        AuthorityDatabaseException? writing = null;
        try
        {
            AuthorityStore.InFolder(folder).Register(newcomer.PublicKey, "newcomer", "test");
        }
        catch (AuthorityDatabaseException error)
        {
            writing = error;
        }

        check(writing is not null, "schema: a write to a database of another version is refused too");

        string damaged = Path.Combine(parent, "damaged");
        Directory.CreateDirectory(damaged);
        File.WriteAllText(Path.Combine(damaged, AuthorityStore.FileName), "this is not a database, it is text that is long enough to look like a file");
        AuthorityDatabaseException? junk = null;
        try
        {
            AuthorityStore.InFolder(damaged).Machines();
        }
        catch (AuthorityDatabaseException error)
        {
            junk = error;
        }

        check(junk is not null, "schema: a file that is not a database is refused, never read as empty (" + junk?.Message + ")");
    }

    // ---- authority key rotation and recovery ----

    private static async Task KeyRotation(Action<bool, string> check, string parent)
    {
        using Fixture fx = new(parent);
        AuthorityKeyRing ring = fx.Machine.Deployment.Keys;
        HostConfigFile hostFile = fx.Machine.Deployment.HostConfig;
        AuthorityKeyRecord first = ring.CurrentRecord();
        check(first.Generation == 1 && hostFile.Load().Config!.Authority!.Fingerprint == first.Fingerprint && hostFile.Load().Config!.MachineFingerprint == fx.Fingerprint, "pin: approving the machine pinned the authority's public key and the machine's fingerprint in host.json");
        string json = File.ReadAllText(hostFile.FilePath);
        check(json.Contains(first.Fingerprint, StringComparison.Ordinal) && !json.Contains("private", StringComparison.OrdinalIgnoreCase), "pin: host.json holds public data (fingerprints and a public key)");

        // Routine rotation: the new key is introduced by a transition that the current key signed.
        KeyTransition transition = ring.Rotate("admin passkey laptop");
        check(transition.Verify(first.PublicKey) && transition.OldFingerprint == first.Fingerprint && ring.CurrentRecord().Generation == 2 && ring.CurrentRecord().Fingerprint == transition.NewFingerprint, "rotation: the new key comes with a transition signed by the current key, and becomes active");
        check(fx.Store.AuthorityKeys().Select(key => key.Status).SequenceEqual(["Retired", "Active"]) && fx.Store.Audit().Any(entry => entry.Event == "authority-key-rotated"), "rotation: recorded in the key history and the audit history");
        using SoftwareSigningKey stranger = new();
        check(!(transition with { Signature = [.. transition.Signature.Select(value => (byte)(value ^ 1))] }).Verify(first.PublicKey) && !(transition with { NewPublicKey = stranger.PublicKey }).Verify(first.PublicKey) && !(transition with { NewFingerprint = KeyIdentity.Fingerprint(stranger.PublicKey) }).Verify(first.PublicKey)
            && !(transition with { OldFingerprint = KeyIdentity.Fingerprint(stranger.PublicKey) }).Verify(first.PublicKey) && !transition.Verify(stranger.PublicKey), "rotation: a changed transition (signature, new key, either fingerprint) or the wrong old key does not verify");
        check(fx.Store.TransitionsFrom(first.Fingerprint).Single().Verify(first.PublicKey) && fx.Store.TransitionsFrom(transition.NewFingerprint).Count == 0, "rotation: the host can fetch the signed chain from the key it pinned");

        // The host accepts the new key only through the transition; the pin moves.
        AuthorizationOutcome rotated = await fx.Ask("rot-1");
        check(rotated.Decision.Approved && hostFile.Load().Config!.Authority!.Fingerprint == transition.NewFingerprint, "rotation: an answer signed by the new key is accepted through the transition and the pin moves");
        AuthorityResponse oldKeyAnswer = AuthorityResponse.Create("rot-2", IdentityTests.Sample("rot-2", DateTimeOffset.UtcNow).Digest(), fx.Fingerprint, AuthorityDecision.Approved, ReasonCodes.Approved, 1, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(1), fx.Machine.AuthorityKey(1));
        fx.Scripted.Tamper = _ => oldKeyAnswer;
        check(Rejected(await fx.Ask("rot-2"), "not pinned"), "rotation: after the move, an answer signed by the retired key is rejected");
        fx.Scripted.Tamper = null;

        // A transition from a key that was never pinned, or a forged one, moves nothing.
        using Fixture forged = new(parent);
        forged.Machine.Deployment.Keys.Rotate("admin");
        string pinnedBefore = forged.Machine.Deployment.HostConfig.Load().Config!.Authority!.Fingerprint;
        KeyTransition foreign = KeyTransition.Create(stranger, stranger.PublicKey, DateTimeOffset.UtcNow);
        forged.Scripted.Transitions = _ => [foreign];
        AuthorizationOutcome refused = await forged.Ask("rot-3");
        check(refused.Decision.Approved == false && forged.Machine.Deployment.HostConfig.Load().Config!.Authority!.Fingerprint == pinnedBefore, "rotation: a transition that the pinned key did not sign moves nothing, and the answer is rejected");
        string? why = forged.Machine.Deployment.HostConfig.TryApplyTransition(foreign);
        check(why is not null && why.Contains("not signed by the pinned", StringComparison.Ordinal), "rotation: TryApplyTransition names why (" + why + ")");

        // Recovery: a new key with no transition. The host does not take it by itself; an explicit admin action pins it.
        using Fixture lost = new(parent);
        string keyBefore = lost.Machine.Deployment.Keys.CurrentRecord().Fingerprint;
        AuthorityKeyRecord recovered = lost.Machine.Deployment.Keys.Recover("admin passkey laptop");
        check(recovered.How == "recovered" && lost.Store.TransitionsFrom(keyBefore).Count == 0 && lost.Store.Audit().Any(entry => entry.Event == "authority-key-recovered"), "recovery: the new key has no transition, so no host can follow it by itself");
        check(Rejected(await lost.Ask("rec-1"), "not pinned") && lost.Machine.Deployment.HostConfig.Load().Config!.Authority!.Fingerprint == keyBefore, "recovery: the host rejects the unpinned key until an administrator pins it");
        AdminActions.RecoverAuthority(lost.Machine.Deployment.Keys, lost.Machine.Deployment.HostConfig, lost.Fingerprint, "admin passkey laptop");
        check((await lost.Ask("rec-2")).Decision.Approved, "recovery: after the explicit admin recovery (pin) the host accepts the new key");

        // A key that authority.db names but the key store lost is an error, never another key.
        using Fixture missing = new(parent);
        missing.Machine.Deployment.Keys.CurrentRecord();
        AuthorityKeyRing wrong = new(missing.Store, _ => new SoftwareSigningKey());
        AuthorityDatabaseException? mismatch = null;
        try
        {
            wrong.Current();
        }
        catch (AuthorityDatabaseException error)
        {
            mismatch = error;
        }

        check(mismatch is not null && mismatch.Message.Contains("recover", StringComparison.OrdinalIgnoreCase) && mismatch.Message.Contains("admin web app", StringComparison.Ordinal), "keys: a key store whose key is not the one authority.db names is an error that names the recovery command");
    }


    // ---- review round: saved approvals, host name binding, pinning, cleanup, throttle ----

    private static async Task ReviewFixes(Action<bool, string> check, string parent)
    {
        // H1: a saved approval made before the machine was disabled is not honoured after it is enabled again.
        using (TestAuthenticator signer = TestAuthenticator.ES256())
        {
            FakeApprover approver = new(true, 10, signer);
            using HostServiceTests.Rig rig = new(parent, approver: () => approver, savedApprovalSigner: signer);
            string program = Show(rig);
            HostServiceTests.Raw first = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            check(first.Result is { Outcome: LaunchOutcome.Exited } && approver.Requests.Count == 1 && new GrantStore(rig.State).Entries().Count == 1, "saved approval: the first run asks and saves an approval (" + first.Result?.Outcome + ")");
            HostServiceTests.Raw reused = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            check(reused.Result is { Outcome: LaunchOutcome.Exited } && approver.Requests.Count == 1, "saved approval: the same request is reused while the machine's revision is the same (no new page)");

            AuthorityStore store = rig.Machine.Deployment.Store;
            string fp = rig.Machine.Fingerprint;
            store.Disable(fp, "test");
            store.Enable(fp, "test");
            HostServiceTests.Raw after = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            check(approver.Requests.Count == 2 && after.Result is { Outcome: LaunchOutcome.Exited }, "saved approval: disable then enable, and the next run shows a fresh page (an old approval is not honoured) (" + approver.Requests.Count + " page(s))");
            check(new GrantStore(rig.State).Entries().Count == 1 && !rig.Service.Authorization.SavedStillValid("not-a-key"), "saved approval: only the approval made after the change is kept");
            HostServiceTests.Raw again = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            check(approver.Requests.Count == 2 && again.Result is { Outcome: LaunchOutcome.Exited }, "saved approval: the new approval is reused under the new revision");

            // Untrust and trust: the same.
            store.Untrust(fp, "test");
            store.Trust(fp, fp, "test");
            HostServiceTests.Raw afterTrust = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            check(approver.Requests.Count == 3 && afterTrust.Result is { Outcome: LaunchOutcome.Exited }, "saved approval: untrust then trust also needs a fresh page");
        }

        // A saved approval does not survive a service restart (the host keeps no authorization state).
        using (TestAuthenticator signer = TestAuthenticator.ES256())
        {
            FakeApprover approver = new(true, 10, signer);
            using HostServiceTests.Rig rig = new(parent, approver: () => approver, savedApprovalSigner: signer);
            string program = Show(rig);
            await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            HostAuthorization restarted = rig.Machine.Restart().CreateAuthorization(new LaunchGate());
            check(!restarted.SavedStillValid(new GrantStore(rig.State).Entries().Single().Key), "saved approval: a restarted host does not honour a saved approval (nothing is remembered)");
        }

        // L1: the host name that is approved is the one that was shown.
        using (Fixture fx = new(parent))
        {
            fx.Store.RecordHostMismatch(fx.Fingerprint, "name-one");
            TransitionResult wrong = fx.Store.ApproveHostChange(fx.Fingerprint, "test", null, "name-two");
            check(!wrong.Ok && fx.Store.Find(fx.Fingerprint) is { HostName: "test-host", PendingHostName: "name-one" }, "host change: a host name other than the one shown is not applied");
            fx.Store.RecordHostMismatch(fx.Fingerprint, "name-three");
            check(!fx.Store.ApproveHostChange(fx.Fingerprint, "test", null, "name-one").Ok && fx.Store.ApproveHostChange(fx.Fingerprint, "test", null, "name-three").Ok && fx.Store.Find(fx.Fingerprint)!.HostName == "name-three", "host change: a name that replaced the shown one is refused; the current shown one is applied");
        }

        // L2: nothing is pinned on the strength of a database row alone.
        using (Fixture fx = new(parent))
        {
            AuthorityKeyRing wrongRing = new(fx.Store, _ => new SoftwareSigningKey());
            string pinnedBefore = fx.Machine.Deployment.HostConfig.Load().Config!.Authority!.Fingerprint;
            File.Delete(fx.Machine.Deployment.HostConfig.FilePath);
            bool threw = false;
            try
            {
                AdminActions.PinLocal(wrongRing, fx.Machine.Deployment.HostConfig, fx.Fingerprint);
            }
            catch (AuthorityDatabaseException)
            {
                threw = true;
            }

            check(threw && !File.Exists(fx.Machine.Deployment.HostConfig.FilePath) && pinnedBefore.Length > 0, "pin: a key store that does not hold the key authority.db names pins nothing");
        }

        // L4: a failure while checking the answer is a denial, and what the page released is zeroed.
        using (Fixture fx = new(parent))
        {
            using SoftwareSigningKey stranger = new();
            fx.Scripted.Tamper = r => Resign(r, stranger);
            fx.Scripted.Transitions = _ => throw new IOException("disk");
            byte[] released = [1, 2, 3, 4];
            Unlock unlock = new("cred", released);
            AuthorizationOutcome outcome = await fx.Host.AuthorizeAsync(IdentityTests.Sample("l4-1", fx.Now), () => ApprovalDecision.Allow("ok", 0, null, unlock), CancellationToken.None);
            check(!outcome.Decision.Approved && outcome.Code == "response-invalid" && released.All(value => value == 0), "cleanup: an exception while verifying denies and zeroes the unlock material");
        }
    }

    private static async Task Throttle(Action<bool, string> check, string parent)
    {
        FakeApprover approver = new(true);
        using HostServiceTests.Rig rig = new(parent, approver: () => approver);
        string body = "{\"challenge\":\"" + Convert.ToBase64String(RandomBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_') + "\"}";
        HttpResponseMessage[] answers = await Task.WhenAll(Enumerable.Range(0, 40).Select(_ => rig.Http.PostAsync(rig.Url("/v1/identity"), new StringContent(body, Encoding.UTF8, "application/json"))));
        int ok = answers.Count(answer => (int)answer.StatusCode == 200);
        int busy = answers.Count(answer => (int)answer.StatusCode == 429);
        check(ok >= 1 && ok + busy == 40, "identity: 40 parallel checks are answered or told to retry (" + ok + " answered, " + busy + " busy), never anything else");
    }

    // ---- through the real host service ----

    private static string Show(HostServiceTests.Rig rig) => rig.Script("show", "echo ran > \"%~dpn0.marker.txt\"\necho t=%TOKEN%", "echo ran > \"$0.marker.txt\"\necho \"t=$TOKEN\"");

    private static async Task ThroughTheService(Action<bool, string> check, string parent)
    {
        // A Trusted machine runs; the same machine in each other state gets nothing and decrypts nothing.
        FakeApprover approver = new(true);
        using (HostServiceTests.Rig rig = new(parent, approver: () => approver))
        {
            string program = Show(rig);
            HostServiceTests.Raw ok = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            check(ok.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 0 } && rig.Store.Reads == 1 && approver.Requests.Count == 1 && !ok.Stdout.Contains("Canary", StringComparison.Ordinal), "service: a Trusted machine runs (one approval, one decryption, redacted output)");

            string fp = rig.Machine.Fingerprint;
            AuthorityStore store = rig.Machine.Deployment.Store;
            (string Name, Action Put, string Wants)[] states =
            [
                ("Disabled", () => store.Disable(fp, "test"), "with-secrets admin enable " + fp),
                ("Untrusted", () => { store.Enable(fp, "test"); store.Untrust(fp, "test"); }, "with-secrets admin trust " + fp),
            ];
            foreach ((string name, Action put, string wants) in states)
            {
                put();
                int reads = rig.Store.Reads;
                int asked = approver.Requests.Count;
                HostServiceTests.Raw denied = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
                check(denied.Result is { Outcome: LaunchOutcome.Denied, ExitCode: RunCommand.Denied } && rig.Store.Reads == reads && approver.Requests.Count == asked && denied.Stderr.Contains(wants, StringComparison.Ordinal) && HostServiceTests.Marker(rig).Length == 0 || File.Exists(HostServiceTests.Marker(rig)) && rig.Store.Reads == reads,
                    "service: a " + name + " machine is denied with the command that fixes it, nobody is asked, and nothing is decrypted (" + denied.Stderr.Trim() + ")");
            }

            // Re-enabled: starts clean and works again.
            store.Trust(fp, fp, "test");
            await rig.Service.Authorization.PumpAsync();
            File.Delete(HostServiceTests.Marker(rig));
            HostServiceTests.Raw back = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            check(back.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 0 } && store.Find(fp)!.SecurityRevision == 3 && rig.Service.Authorization.KnownRevision == 3, "service: after the machine is trusted again it runs; the host has applied revision 3");
        }

        // Pending without a pin, and Pending with a pin (the authority says no).
        foreach (bool pinned in new[] { false, true })
        {
            FakeApprover never = new(true);
            string folder = Path.Combine(parent, "pending-" + pinned + "-" + Guid.NewGuid().ToString("N")[..6]);
            using TestMachine machine = new(folder, trusted: false);
            machine.Deployment.EnrollAsync().GetAwaiter().GetResult();
            if (pinned)
            {
                AdminActions.PinLocal(machine.Deployment.Keys, machine.Deployment.HostConfig, machine.Fingerprint);
            }

            using HostServiceTests.Rig rig = new(parent, approver: () => never, machine: machine);
            HostServiceTests.Raw denied = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, Show(rig)));
            check(denied.Result is { Outcome: LaunchOutcome.Denied, ExitCode: RunCommand.Denied } && rig.Store.Reads == 0 && never.Requests.Count == 0 && denied.Stderr.Contains(machine.Fingerprint, StringComparison.Ordinal) && denied.Stderr.Contains("admin web app", StringComparison.Ordinal) && HostServiceTests.Marker(rig).Length == 0,
                "service: a Pending machine (" + (pinned ? "pinned" : "not pinned") + ") is denied with the approve command, nobody is asked, nothing is decrypted (" + denied.Stderr.Trim() + ")");
        }

        // A changed host name is rejected and recorded; the binding stays until an administrator approves it.
        {
            string folder = Path.Combine(parent, "hostname-" + Guid.NewGuid().ToString("N")[..6]);
            using TestMachine machine = new(folder, hostName: "host-a");
            machine.Restart("host-b");
            FakeApprover never = new(true);
            using HostServiceTests.Rig rig = new(parent, approver: () => never, machine: machine);
            HostServiceTests.Raw denied = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, Show(rig)));
            MachineRecord record = machine.Deployment.Store.Find(machine.Fingerprint)!;
            check(denied.Result is { Outcome: LaunchOutcome.Denied } && rig.Store.Reads == 0 && never.Requests.Count == 0 && denied.Stderr.Contains(machine.Fingerprint, StringComparison.Ordinal) && denied.Stderr.Contains("admin web app", StringComparison.Ordinal)
                && record is { HostName: "host-a", PendingHostName: "host-b", Status: MachineStatus.Trusted, SecurityRevision: 1 }, "service: a host name that is not the bound one is rejected and recorded pending; the binding and status are unchanged (" + denied.Stderr.Trim() + ")");
            machine.Deployment.Store.ApproveHostChange(machine.Fingerprint, "test");
            HostServiceTests.Raw allowed = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, Show(rig)));
            check(allowed.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 0 } && rig.Store.Reads == 1, "service: once the administrator approves the host name change the machine runs");
        }

        // An invalidation while the page is open: the launch does not decrypt.
        {
            HostServiceTests.CancelAwareApprover waiting = new();
            using HostServiceTests.Rig rig = new(parent, approver: () => waiting);
            string program = Show(rig);
            Task<HostServiceTests.Raw> pending = HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            check(await HostServiceTests.WaitFor(() => waiting.Asked.IsSet), "invalidation: the launch reached the approval page");
            rig.Machine.Deployment.Store.Disable(rig.Machine.Fingerprint, "test");
            await rig.Service.Authorization.PumpAsync();
            check(rig.Machine.Deployment.Store.PendingInvalidations(rig.Machine.Fingerprint).Count == 0 && rig.Machine.Deployment.Store.Audit().Any(entry => entry.Event == "invalidation-acknowledged"), "invalidation: the host applied the notification and acknowledged it, which is recorded");
            waiting.Release.Set();
            HostServiceTests.Raw result = await pending;
            check(result.Result is { Outcome: LaunchOutcome.Denied or LaunchOutcome.Cancelled } && rig.Store.Reads == 0 && HostServiceTests.Marker(rig).Length == 0, "invalidation: a machine disabled while the page was open decrypts nothing and starts nothing (" + result.Result?.Outcome + ")");
        }

        // A service that was started on its own (no pump call) still learns of an invalidation by polling.
        {
            using HostServiceTests.Rig rig = new(parent, approver: () => new FakeApprover(true));
            int before = rig.Service.Gate.Revision;
            rig.Machine.Deployment.Store.Disable(rig.Machine.Fingerprint, "test");
            bool polled = await HostServiceTests.WaitFor(() => rig.Service.Gate.Revision > before && rig.Machine.Deployment.Store.PendingInvalidations(rig.Machine.Fingerprint).Count == 0, 30);
            check(polled && rig.Machine.Deployment.Store.PendingInvalidations(rig.Machine.Fingerprint).Count == 0, "invalidation: the running service applies and acknowledges a new invalidation by itself (polling; polled " + polled + ", pending " + rig.Machine.Deployment.Store.PendingInvalidations(rig.Machine.Fingerprint).Count + ", gate " + rig.Service.Gate.Revision + " from " + before + ")");
        }
    }
}

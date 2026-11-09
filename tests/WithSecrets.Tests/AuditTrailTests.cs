using System.Text;

using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>
/// Phase 4, the durable audit trail: signed events (authorization decision, launch outcome and execution outcome as distinct facts) with a per-machine sequence,
/// committed to the host's SQLite outbox BEFORE a secret-bearing run decrypts anything, uploaded asynchronously and retried until the authority durably
/// acknowledges them; at the authority they are verified, deduplicated, checked for sequence gaps, kept for the authority's retention and searchable.
/// No secret value, environment value or OS user is ever recorded.
/// </summary>
internal static class AuditTrailTests
{
    /// <summary>A token as a fresh passkey tap for exactly this retention change would give (the authorizer itself is tested in AuthorityLockTests).</summary>
    private static VerifiedAdmin RetentionAdmin(int days)
    {
        (string operation, IReadOnlyList<(string Name, string Value)> parameters) = AuthorityStore.RetentionOperation(days);

        return VerifiedAdmin.ForTests(operation, AdminAuthorizer.Canonical(parameters), "test admin");
    }

    private static readonly TimeSpan Fast = TimeSpan.FromMilliseconds(40);

    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 11, 9, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }

    /// <summary>The authority as the host's audit uploader sees it: it can be unreachable, hang, or answer with something altered.</summary>
    private sealed class FlakySink(IAuditSink inner) : IAuditSink
    {
        private int _calls;

        public bool Offline { get; set; }

        public bool Hang { get; set; }

        public Func<AuditBatch, AuditAck, AuditAck>? Tamper { get; set; }

        public List<AuditBatch> Batches { get; } = [];

        public int Calls => Volatile.Read(ref _calls);

        public async Task<AuditAck> UploadAsync(AuditBatch batch, CancellationToken cancel = default)
        {
            Interlocked.Increment(ref _calls);
            lock (Batches)
            {
                Batches.Add(batch);
            }

            if (Hang)
            {
                await Task.Delay(Timeout.Infinite, cancel);
            }

            if (Offline)
            {
                throw new IOException("the authority cannot be reached (test)");
            }

            AuditAck ack = await inner.UploadAsync(batch, cancel);

            return Tamper?.Invoke(batch, ack) ?? ack;
        }
    }

    private static AuditFacts Facts(string type = AuditEventTypes.Authorization, string outcome = "approved", string reason = "approved", string grant = "", int? exit = null, string folder = "/work", string program = "/work/show.sh", params string[] arguments)
        => new(type, outcome, reason, "req-1", folder, program, arguments, grant, exit);

    private static Func<AuditAck, string, string, CancellationToken, Task<string?>> Verifier(byte[] authorityKey)
        => (ack, id, digest, _) => Task.FromResult<string?>(ack.RequestId != id ? "another batch" : ack.RequestDigest != digest ? "another digest" : !ack.Verify(authorityKey) ? "bad signature" : null);

    private static byte[] AuthorityKey(TestMachine machine) => machine.Deployment.Keys.CurrentRecord().PublicKey;

    private static AuditBatch Batch(TestMachine machine, params AuditEvent[] events) => new("b-" + Guid.NewGuid().ToString("N")[..8], machine.Fingerprint, events);

    private static void Sql(string file, string sql)
    {
        using SqliteConnection connection = new("Data Source=" + file + ";Pooling=False");
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static object? Scalar(string file, string sql)
    {
        using SqliteConnection connection = new("Data Source=" + file + ";Pooling=False");
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;

        return command.ExecuteScalar();
    }

    public static async Task Run(Action<bool, string> check)
    {
        string parent = Path.Combine(Path.GetTempPath(), "ws-audit-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(parent);
        try
        {
            Signing(check);
            Redaction(check);
            Outbox(check, parent);
            await Authority(check, parent);
            await Retention(check, parent);
            await History(check, parent);
            await Uploading(check, parent);
            Schema(check, parent);
            Cli(check, parent);
            await AdminAuditView(check, parent);
            await ThroughTheService(check, parent);
            await Review(check, parent);
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

    // ---- signed events ----

    private static void Signing(Action<bool, string> check)
    {
        using SoftwareSigningKey key = new();
        using SoftwareSigningKey other = new();
        string fingerprint = KeyIdentity.Fingerprint(key.PublicKey);
        DateTimeOffset time = new(2026, 11, 9, 12, 0, 0, TimeSpan.Zero);
        AuditEvent e = AuditEvent.Create(Facts(exit: 0, arguments: ["a", "b"]), "11111111-1111-1111-1111-111111111111", 7, time, key);

        check(e.Verify(key.PublicKey) && !e.Verify(other.PublicKey) && e.MachineFingerprint == fingerprint, "event signing: the machine key's signature verifies; another key's does not");
        string expected = "{\"protocolVersion\":1,\"eventId\":\"11111111-1111-1111-1111-111111111111\",\"sequence\":7,\"time\":\"2026-11-09T12:00:00.0000000Z\",\"machineFingerprint\":\"" + fingerprint
            + "\",\"epoch\":\"default\",\"type\":\"authorization\",\"outcome\":\"approved\",\"reason\":\"approved\",\"requestId\":\"req-1\",\"folder\":\"/work\",\"program\":\"/work/show.sh\",\"arguments\":[\"a\",\"b\"],\"grantId\":\"\",\"exitCode\":0}";
        check(e.Canonical() == expected, "event signing: the canonical text is fixed (member order, no white space) (" + e.Canonical() + ")");
        check(e.Signature.Length == 64 && e.ToJson().StartsWith(expected[..^1], StringComparison.Ordinal) && e.ToJson().Contains(",\"signature\":\"", StringComparison.Ordinal), "event signing: the signature is 64 bytes (r||s) and is the last member of the stored form");

        (string Name, AuditEvent Changed)[] tampered =
        [
            ("event id", e with { EventId = "11111111-1111-1111-1111-111111111112" }),
            ("sequence", e with { Sequence = 8 }),
            ("time", e with { Time = time.AddSeconds(1) }),
            ("machine", e with { MachineFingerprint = KeyIdentity.Fingerprint(other.PublicKey) }),
            ("type", e with { Type = AuditEventTypes.Launch }),
            ("outcome", e with { Outcome = "denied" }),
            ("reason", e with { Reason = "user-denied" }),
            ("request id", e with { RequestId = "req-2" }),
            ("folder", e with { Folder = "/elsewhere" }),
            ("program", e with { Program = "/work/evil.sh" }),
            ("an argument", e with { Arguments = ["a", "c"] }),
            ("argument order", e with { Arguments = ["b", "a"] }),
            ("an extra argument", e with { Arguments = ["a", "b", "c"] }),
            ("grant id", e with { GrantId = "g-1" }),
            ("exit code", e with { ExitCode = 1 }),
            ("a removed exit code", e with { ExitCode = null }),
            ("protocol version", e with { ProtocolVersion = 2 }),
        ];
        foreach ((string name, AuditEvent changed) in tampered)
        {
            check(!changed.Verify(key.PublicKey), "event tamper: changing the " + name + " breaks the signature");
        }

        byte[] flipped = [.. e.Signature];
        flipped[10] ^= 1;
        check(!(e with { Signature = flipped }).Verify(key.PublicKey) && !(e with { Signature = e.Signature[..63] }).Verify(key.PublicKey) && !(e with { Signature = [] }).Verify(key.PublicKey), "event tamper: a flipped, short or missing signature does not verify");
        check(!(e with { Signature = key.Sign(WireText.Bytes("with-secrets machine request v1\n", e.Canonical())) }).Verify(key.PublicKey), "event signing: the signature is bound to the audit domain (the same text signed for another message does not verify)");

        check(AuditEvent.TryParse(e.ToJson(), out AuditEvent? parsed, out _) && parsed!.Canonical() == e.Canonical() && parsed.Verify(key.PublicKey) && parsed.Arguments.SequenceEqual(["a", "b"]), "event parse: the stored form reads back to the same signed event");
        string json = e.ToJson();
        check(!AuditEvent.TryParse(json.Replace("\"signature\"", "\"extra\":1,\"signature\"", StringComparison.Ordinal), out _, out string? unknown) && unknown!.Contains("unknown field", StringComparison.Ordinal), "event parse: an unknown member is refused (" + unknown + ")");
        check(!AuditEvent.TryParse(json.Replace("\"grantId\":\"\",", "", StringComparison.Ordinal), out _, out string? missing) && missing!.Contains("missing field", StringComparison.Ordinal), "event parse: a missing member is refused (" + missing + ")");
        check(!AuditEvent.TryParse(json.Replace("\"sequence\":7", "\"sequence\":\"7\"", StringComparison.Ordinal), out _, out _) && !AuditEvent.TryParse(json + " ", out _, out _) is false, "event parse: a wrong type is refused and trailing white space is harmless");
        check(!AuditEvent.TryParse(json.Replace("\"eventId\"", "\"eventId\":\"x\",\"eventId\"", StringComparison.Ordinal), out _, out _), "event parse: a repeated member is refused");
        check(!AuditEvent.TryParse(json.Replace(Convert.ToBase64String(e.Signature), "AAAA", StringComparison.Ordinal), out _, out _) && !AuditEvent.TryParse("[]", out _, out _) && !AuditEvent.TryParse("not json", out _, out _), "event parse: a short signature, a non-object and text that is not JSON are refused");

        check(e.Problem() is null && (e with { Sequence = 0 }).Problem() is not null && (e with { Type = "other" }).Problem() is not null && (e with { Outcome = "" }).Problem() is not null && (e with { Program = new string('x', 5000) }).Problem() is not null
            && (e with { Arguments = [.. Enumerable.Repeat("a", 300)] }).Problem() is not null && (e with { EventId = "bad id" }).Problem() is not null && (e with { ProtocolVersion = 9 }).Problem() is not null, "event shape: a number below 1, an unknown type, an empty outcome, a long field, too many arguments or a bad id are refused");

        string[] fields = [.. typeof(AuditEvent).GetProperties().Where(p => p.DeclaringType == typeof(AuditEvent) && p.Name != "EqualityContract").Select(p => p.Name).Order(StringComparer.Ordinal)];
        string[] allowed = ["Arguments", "ExitCode", "EventId", "Epoch", "Folder", "GrantId", "MachineFingerprint", "Outcome", "Program", "ProtocolVersion", "Reason", "RequestId", "Sequence", "Signature", "Time", "Type"];
        check(fields.SequenceEqual(allowed.Order(StringComparer.Ordinal)), "event content: exactly the agreed fields; none names an OS user, a secret value or an environment value (a new field must be decided here) (" + string.Join(",", fields) + ")");
    }

    // ---- redaction ----

    private static void Redaction(Action<bool, string> check)
    {
        IReadOnlyList<string> Redact(params string[] arguments) => AuditRedaction.Arguments(arguments);

        check(Redact("--token=abc123XYZ")[0] == "--token=[REDACTED]" && Redact("API_KEY=sk-live-1234")[0] == "API_KEY=[REDACTED]" && Redact("password: hunter22")[0] == "password: [REDACTED]" && Redact("--client-secret=zzz")[0] == "--client-secret=[REDACTED]", "redaction: a value after a name like token, key, password or secret is masked");
        check(Redact("--token", "abc123", "--verbose").SequenceEqual(["--token", "[REDACTED]", "--verbose"]) && Redact("--password", "--other").SequenceEqual(["--password", "--other"]) && Redact("--token=abc", "next").SequenceEqual(["--token=[REDACTED]", "next"]), "redaction: the value after a secret-named flag is masked, an option after it is not, and a name=value pair does not mask the next argument");
        check(Redact("https://bob:pa55w0rd@example.com/x")[0] == "https://[REDACTED]@example.com/x", "redaction: the password of a URL is masked");
        string header = Redact("Authorization: Bearer abcdefghij123")[0];
        check(!header.Contains("abcdefghij123", StringComparison.Ordinal) && header.Contains("[REDACTED]", StringComparison.Ordinal) && !Redact("-H", "Bearer abcdefghij123")[1].Contains("abcdefghij123", StringComparison.Ordinal), "redaction: an Authorization or Bearer value is masked (" + header + ")");
        check(Redact("build", "--verbose", "src/main.cs", "--name=value", "--keyboard=us", "-c", "Release").SequenceEqual(["build", "--verbose", "src/main.cs", "--name=value", "--keyboard=us", "-c", "Release"]), "redaction: ordinary arguments are left as they are");
        string longText = Redact(new string('x', 2000))[0];
        check(longText.Length < 600 && longText.Contains("more characters omitted", StringComparison.Ordinal) && Redact("a\nb‮c")[0].All(letter => !char.IsControl(letter) && letter != '‮'), "redaction: a long argument is cut and control or bidi characters are marked");
        IReadOnlyList<string> many = Redact([.. Enumerable.Range(0, 400).Select(i => "a" + i)]);
        check(many.Count == AuditEvent.MaxArguments && many[^1].Contains("more arguments omitted", StringComparison.Ordinal), "redaction: more than 256 arguments are cut with a count");
    }

    // ---- outbox ----

    private static void Outbox(Action<bool, string> check, string parent)
    {
        string dir = Path.Combine(parent, "ob-" + Guid.NewGuid().ToString("N")[..6]);
        using SoftwareSigningKey key = new();
        TestClock clock = new();
        HostAuditOutbox outbox = HostAuditOutbox.InFolder(dir, key, clock);
        check(outbox.LastSequence() == 0 && outbox.Count("pending") == 0 && outbox.Pending(10).Count == 0 && !File.Exists(outbox.FilePath), "outbox: reading an outbox that does not exist creates nothing");

        AuditEvent first = outbox.Append(Facts());
        AuditEvent second = outbox.Append(Facts(AuditEventTypes.Launch, "started", ""));
        AuditEvent third = outbox.Append(Facts(AuditEventTypes.Execution, "exited", "", exit: 0));
        IReadOnlyList<AuditEvent> pending = outbox.Pending(10);
        check(new[] { first.Sequence, second.Sequence, third.Sequence }.SequenceEqual([1L, 2L, 3L]) && pending.Select(item => item.EventId).SequenceEqual([first.EventId, second.EventId, third.EventId]) && pending.All(item => item.Verify(key.PublicKey)), "outbox: events are numbered 1, 2, 3, kept in order, and stored signed");
        check(Scalar(outbox.FilePath, "PRAGMA journal_mode") as string == "wal" && Convert.ToInt32(Scalar(outbox.FilePath, "SELECT version FROM schema_version")) == 2 && Path.GetFileName(outbox.FilePath) == "audit-outbox.db", "outbox: a file of its own in the store folder, WAL, schema version 2");

        outbox.Acknowledge([first.EventId]);
        check(outbox.Count("pending") == 2 && outbox.LastSequence() == 3 && outbox.Append(Facts()).Sequence == 4, "outbox: an acknowledged event is removed, and its number is not used again");
        outbox.Acknowledge(["no-such-id", first.EventId]);
        check(outbox.Count("pending") == 3, "outbox: acknowledging an id that is not there (or twice) changes nothing");

        HostAuditOutbox again = HostAuditOutbox.InFolder(dir, key, clock);
        check(again.LastSequence() == 4 && again.Pending(10).Count == 3 && again.Append(Facts()).Sequence == 5, "outbox restart: a new object over the same file resumes at the next number and still holds the unacknowledged events");

        // Many writers at once: monotonic and gapless.
        string busyDir = Path.Combine(parent, "ob-busy-" + Guid.NewGuid().ToString("N")[..6]);
        HostAuditOutbox busy = HostAuditOutbox.InFolder(busyDir, key, clock);
        List<long> numbers = [];
        Task[] writers = [.. Enumerable.Range(0, 8).Select(_ => Task.Run(() =>
        {
            for (int index = 0; index < 25; index++)
            {
                long sequence = busy.Append(Facts()).Sequence;
                lock (numbers)
                {
                    numbers.Add(sequence);
                }
            }
        }))];
        Task.WaitAll(writers);
        IReadOnlyList<AuditEvent> all = busy.Pending(500);
        check(numbers.Order().SequenceEqual(Enumerable.Range(1, 200).Select(i => (long)i)) && all.Select(item => item.Sequence).SequenceEqual(Enumerable.Range(1, 200).Select(i => (long)i)) && all.Select(item => item.EventId).Distinct().Count() == 200 && all.All(item => item.Verify(key.PublicKey)),
            "outbox concurrency: 8 writers x 25 events get exactly the numbers 1 to 200, once each, in order, all signed");

        // A failed commit consumes no number.
        string failDir = Path.Combine(parent, "ob-fail-" + Guid.NewGuid().ToString("N")[..6]);
        HostAuditOutbox failing = HostAuditOutbox.InFolder(failDir, key, clock);
        failing.Append(Facts());
        failing.Fault = point => throw new IOException("the disk went away (test)");
        AuditOutboxException? failure = Catch<AuditOutboxException>(() => failing.Append(Facts()));
        check(failure is not null && failing.LastSequence() == 1 && failing.Count("pending") == 1, "outbox failure: a commit that fails throws, stores nothing and uses no number");
        failing.Fault = point => throw new SqliteException("database or disk is full (test)", 13);
        check(Catch<AuditOutboxException>(() => failing.Append(Facts()))?.Message.Contains("disk is full", StringComparison.Ordinal) == true, "outbox failure: a full disk is reported as one");
        failing.Fault = point =>
        {
            if (point == "before-sign")
            {
                throw new InvalidOperationException("signing failed (test)");
            }
        };
        check(Catch<InvalidOperationException>(() => failing.Append(Facts())) is not null && failing.LastSequence() == 1, "outbox failure: a signing failure stores nothing and uses no number");
        failing.Fault = null;
        check(failing.Append(Facts()).Sequence == 2 && failing.Count("pending") == 2, "outbox failure: afterwards the next event gets the next number (no gap)");
        HostAudit audit = new(failing, new AuditUploader(failing, () => throw new InvalidOperationException(), (_, _, _, _) => Task.FromResult<string?>(null), "fp"));
        failing.Fault = point => throw new IOException("the disk went away (test)");
        check(!audit.TryRecord(Facts()) && failing.LastSequence() == 2, "outbox failure: TryRecord says false and never throws");

        // Damaged, other schema, not a file.
        string damagedDir = Path.Combine(parent, "ob-damaged-" + Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(damagedDir);
        File.WriteAllText(Path.Combine(damagedDir, HostAuditOutbox.FileName), "this is not a database");
        HostAuditOutbox damaged = HostAuditOutbox.InFolder(damagedDir, key, clock);
        check(Catch<AuditOutboxException>(() => damaged.Append(Facts())) is not null && Catch<AuditOutboxException>(() => damaged.Pending(5)) is not null && !new HostAudit(damaged, audit.Uploader).TryRecord(Facts()), "outbox failure: a damaged file cannot be used: appending and reading throw, TryRecord is false");

        Sql(outbox.FilePath, "UPDATE schema_version SET version = 99");
        AuditOutboxException? mismatch = Catch<AuditOutboxException>(() => HostAuditOutbox.InFolder(dir, key, clock).Append(Facts()));
        check(mismatch?.Message == "audit-outbox.db is not of schema version 2; delete audit-outbox.db to start over", "outbox schema: another schema version is refused with the delete-it message (" + mismatch?.Message + ")");

        string blockedDir = Path.Combine(parent, "ob-blocked-" + Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(Path.Combine(blockedDir, HostAuditOutbox.FileName));
        check(Catch<AuditOutboxException>(() => HostAuditOutbox.InFolder(blockedDir, key, clock).Append(Facts())) is not null, "outbox failure: a folder where the file should be is an error, not a crash");
    }

    private static T? Catch<T>(Action action)
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

    // ---- the authority's side ----

    private static async Task Authority(Action<bool, string> check, string parent)
    {
        TestClock clock = new();
        using TestMachine machine = new(Path.Combine(parent, "au-" + Guid.NewGuid().ToString("N")[..6]), true, clock: clock);
        LocalAuthority authority = machine.Deployment.Authority;
        AuthorityStore store = machine.Deployment.Store;
        HostAuditOutbox outbox = HostAuditOutbox.InFolder(machine.Folder, machine.MachineKey, clock);
        byte[] authorityKey = AuthorityKey(machine);

        AuditEvent e1 = outbox.Append(Facts());
        AuditEvent e2 = outbox.Append(Facts(AuditEventTypes.Launch, "started", ""));
        AuditEvent e3 = outbox.Append(Facts(AuditEventTypes.Execution, "exited", "", exit: 0));
        AuditBatch batch = Batch(machine, e1, e2, e3);
        AuditAck ack = await authority.UploadAsync(batch);
        check(ack.Verify(authorityKey) && ack.RequestId == batch.BatchId && ack.RequestDigest == batch.Digest() && ack.MachineFingerprint == machine.Fingerprint && ack.Entries.Select(entry => entry.Status).All(status => status == AuditStatus.Accepted) && ack.Entries.Select(entry => entry.EventId).SequenceEqual([e1.EventId, e2.EventId, e3.EventId]),
            "authority: an upload is acknowledged with an answer signed by the authority key that names the batch, its digest, the machine and every event as accepted");
        IReadOnlyList<AuditHistoryRecord> stored = store.AuditHistory(new AuditQuery());
        check(stored.Count == 3 && stored.All(record => record.Event.Verify(machine.MachineKey.PublicKey)) && store.AuditHighestSequence(machine.Fingerprint) == 3 && store.AuditGaps().Count == 0, "authority: the events are stored signed, the machine's sequence is at 3 and there is no gap");
        check(store.Audit().Any(entry => entry.Event == "audit-events-received" && entry.Detail.Contains("3 event(s), sequence 1 to 3", StringComparison.Ordinal)), "authority: the receipt is in the authority's own audit history");
        check(ack.Expires - ack.Issued == LocalAuthority.AuditAckLifetime, "authority: the acknowledgement is valid for a short time (60 s)");

        // Duplicate delivery.
        AuditAck duplicate = await authority.UploadAsync(Batch(machine, e1, e2, e3, e2));
        check(duplicate.Entries.All(entry => entry.Status == AuditStatus.Duplicate) && duplicate.Entries.Count == 4 && store.AuditHistory(new AuditQuery()).Count == 3 && duplicate.Verify(authorityKey), "duplicate delivery: events stored already are acknowledged as duplicates and stored once (also inside one batch)");
        AuditEvent e4 = outbox.Append(Facts());
        AuditAck mixed = await authority.UploadAsync(Batch(machine, e3, e4, e4));
        check(mixed.Entries.Select(entry => entry.Status).SequenceEqual([AuditStatus.Duplicate, AuditStatus.Accepted, AuditStatus.Duplicate]) && store.AuditHistory(new AuditQuery()).Count == 4, "duplicate delivery: a batch of one old and new events keeps the new, once");

        // Verification.
        AuditEvent e5 = outbox.Append(Facts());
        AuditEvent forged = e5 with { Outcome = "denied" };
        AuditEvent e6 = outbox.Append(Facts());
        AuditAck refused = await authority.UploadAsync(Batch(machine, forged, e6));
        check(refused.Entries[0] is { Status: AuditStatus.Rejected, Detail: "bad-signature" } && refused.Entries[1].Status == AuditStatus.Accepted && store.AuditHistory(new AuditQuery()).Count == 5, "verification: an event whose content was altered is rejected (bad-signature) and does not stop the others");
        using SoftwareSigningKey stranger = new();
        AuditEvent claimed = AuditEvent.Create(Facts(), Guid.NewGuid().ToString("D"), 50, clock.GetUtcNow(), stranger) with { MachineFingerprint = machine.Fingerprint };
        AuditEvent strangers = AuditEvent.Create(Facts(), Guid.NewGuid().ToString("D"), 51, clock.GetUtcNow(), stranger);
        AuditAck strange = await authority.UploadAsync(Batch(machine, claimed, strangers));
        check(strange.Entries[0].Detail == "bad-signature" && strange.Entries[1].Detail == "other-machine" && store.AuditHighestSequence(machine.Fingerprint) == 6, "verification: an event signed by another key (claiming this machine, or its own) is rejected and moves no sequence");
        AuditAck unknown = await authority.UploadAsync(new AuditBatch("b-x", KeyIdentity.Fingerprint(stranger.PublicKey), [strangers]));
        check(unknown.Entries[0] is { Status: AuditStatus.Rejected, Detail: "unknown-machine" } && store.AuditHistory(new AuditQuery()).Count == 5, "verification: an upload from a machine the authority does not know is rejected");
        AuditEvent reused = AuditEvent.Create(Facts(outcome: "different"), e1.EventId, 60, clock.GetUtcNow(), machine.MachineKey);
        AuditEvent shape = AuditEvent.Create(Facts(), Guid.NewGuid().ToString("D"), 0, clock.GetUtcNow(), machine.MachineKey);
        AuditAck odd = await authority.UploadAsync(Batch(machine, reused, shape));
        check(odd.Entries[0].Detail == "event-id-reused" && odd.Entries[1].Detail.StartsWith("invalid-event", StringComparison.Ordinal) && store.AuditHistory(new AuditQuery()).Count == 5, "verification: a known id with other content, and an event of an invalid shape, are rejected");
        check(odd.Entries.All(entry => !AuditStatus.Done(entry.Status)) && refused.Entries.Count(entry => AuditStatus.Done(entry.Status)) == 1, "verification: only accepted, duplicate and expired events end the host's duty to keep them");

        // Atomic: a failure while storing acknowledges nothing and stores nothing.
        using TestMachine second = new(Path.Combine(parent, "au2-" + Guid.NewGuid().ToString("N")[..6]), true, clock: clock);
        HostAuditOutbox outbox2 = HostAuditOutbox.InFolder(second.Folder, second.MachineKey, clock);
        AuditEvent a1 = outbox2.Append(Facts());
        AuditEvent a2 = outbox2.Append(Facts());
        second.Deployment.Store.Fault = point =>
        {
            if (point == "after-audit-events")
            {
                throw new InvalidOperationException("the commit failed (test)");
            }
        };
        check(Catch<InvalidOperationException>(() => second.Deployment.Authority.UploadAsync(Batch(second, a1, a2)).GetAwaiter().GetResult()) is not null && second.Deployment.Store.AuditHistory(new AuditQuery()).Count == 0 && second.Deployment.Store.AuditHighestSequence(second.Fingerprint) == 0 && second.Deployment.Store.AuditGaps().Count == 0,
            "atomic: a failure before the commit stores nothing, moves no sequence state and returns no acknowledgement");
        second.Deployment.Store.Fault = null;
        check((await second.Deployment.Authority.UploadAsync(Batch(second, a1, a2))).Entries.All(entry => entry.Status == AuditStatus.Accepted), "atomic: the retry is accepted");

        // Sequence gaps.
        using TestMachine gapped = new(Path.Combine(parent, "au3-" + Guid.NewGuid().ToString("N")[..6]), true, clock: clock);
        AuditEvent At(long sequence, string? id = null) => AuditEvent.Create(Facts(), id ?? Guid.NewGuid().ToString("D"), sequence, clock.GetUtcNow(), gapped.MachineKey);
        AuditStore g = new(gapped.Deployment.Store);
        await gapped.Deployment.Authority.UploadAsync(Batch(gapped, At(1), At(2)));
        check(g.Gaps().Count == 0 && g.Highest(gapped) == 2, "sequence: 1 and 2 arrive in order: no gap");
        AuditAck jump = await gapped.Deployment.Authority.UploadAsync(Batch(gapped, At(5)));
        check(jump.Entries[0].Status == AuditStatus.Accepted && g.Gaps().Count == 1 && g.Gaps()[0] is { Kind: "missing", From: 3, To: 4 } && g.Highest(gapped) == 5, "sequence: 5 after 2 is accepted (never rejected) and records the missing 3 to 4");
        await gapped.Deployment.Authority.UploadAsync(Batch(gapped, At(4)));
        check(g.Gaps() is [{ Kind: "missing", From: 3, To: 3 }], "sequence: the late 4 shrinks the gap to 3");
        await gapped.Deployment.Authority.UploadAsync(Batch(gapped, At(3)));
        check(g.Gaps().Count == 0 && gapped.Deployment.Store.AuditGaps(openOnly: false) is [{ Resolved: not null }], "sequence: the late 3 closes it (kept as resolved)");
        await gapped.Deployment.Authority.UploadAsync(Batch(gapped, At(20)));
        await gapped.Deployment.Authority.UploadAsync(Batch(gapped, At(10)));
        check(g.Gaps().Select(gap => (gap.From, gap.To)).SequenceEqual([(6L, 9L), (11L, 19L)]), "sequence: a number inside a gap splits it (6-9 and 11-19)");
        AuditAck again = await gapped.Deployment.Authority.UploadAsync(Batch(gapped, At(2)));
        check(again.Entries[0].Status == AuditStatus.Accepted && g.Gaps().Any(gap => gap.Kind == "reused" && gap.From == 2) && gapped.Deployment.Store.AuditHistory(new AuditQuery()).Count(record => record.Event.Sequence == 2) == 2, "sequence: a number used twice by different events is accepted and recorded as reused");
        check(g.Highest(gapped) == 20 && gapped.Deployment.Store.AuditGaps(gapped.Fingerprint[..12]).Count == g.Gaps().Count && gapped.Deployment.Store.AuditGaps("0000").Count == 0, "sequence: the highest number seen is kept per machine, and gaps can be listed for a machine prefix");
    }

    /// <summary>Short reads over the gap list of one store.</summary>
    private sealed class AuditStore(AuthorityStore store)
    {
        public IReadOnlyList<AuditGap> Gaps() => store.AuditGaps();

        public long Highest(TestMachine machine) => store.AuditHighestSequence(machine.Fingerprint);
    }

    // ---- retention ----

    private static async Task Retention(Action<bool, string> check, string parent)
    {
        TestClock clock = new();
        using TestMachine machine = new(Path.Combine(parent, "re-" + Guid.NewGuid().ToString("N")[..6]), true, clock: clock);
        AuthorityStore store = machine.Deployment.Store;
        HostAuditOutbox outbox = HostAuditOutbox.InFolder(machine.Folder, machine.MachineKey, clock);
        check(store.AuditRetentionDays() == AuthorityStore.DefaultAuditRetentionDays && AuthorityStore.DefaultAuditRetentionDays == 365, "retention: the authority keeps a year of events unless it is told otherwise");
        store.SetAuditRetentionDays(30, RetentionAdmin(30));
        check(store.AuditRetentionDays() == 30 && store.Audit().Any(entry => entry.Event == "audit-retention-changed" && entry.Detail.Contains("365 to 30", StringComparison.Ordinal)), "retention: the authority sets it, and the change is in its audit history");
        check(Catch<ArgumentOutOfRangeException>(() => store.SetAuditRetentionDays(-1, RetentionAdmin(-1))) is not null && Catch<ArgumentOutOfRangeException>(() => store.SetAuditRetentionDays(AuthorityStore.MaxAuditRetentionDays + 1, RetentionAdmin(AuthorityStore.MaxAuditRetentionDays + 1))) is not null && store.AuditRetentionDays() == 30, "retention: a negative or absurd value is refused");

        AuditEvent old = outbox.Append(Facts());
        clock.Advance(TimeSpan.FromDays(40));
        AuditEvent recent = outbox.Append(Facts(AuditEventTypes.Launch, "started", ""));
        AuditAck ack = await machine.Deployment.Authority.UploadAsync(Batch(machine, old, recent));
        check(ack.Entries[0] is { Status: AuditStatus.Expired } && ack.Entries[1].Status == AuditStatus.Accepted && AuditStatus.Done(AuditStatus.Expired) && store.AuditHistory(new AuditQuery()).Count == 1, "retention: an event older than the retention is acknowledged but not stored; a recent one is stored");
        check(Convert.ToInt32(Scalar(store.FilePath, "SELECT COUNT(*) FROM audit_events WHERE acknowledged IS NULL")) == 0, "retention: everything the authority stores is already acknowledged (only acknowledged events can be pruned)");

        clock.Advance(TimeSpan.FromDays(29));
        check(store.PruneAuditEvents() == 0 && store.AuditHistory(new AuditQuery()).Count == 1, "retention: nothing is pruned before the retention has passed (29 of 30 days)");
        clock.Advance(TimeSpan.FromDays(2));
        check(store.PruneAuditEvents() == 1 && store.AuditHistory(new AuditQuery()).Count == 0 && store.Audit().Any(entry => entry.Event == "audit-pruned"), "retention: after the retention the event is pruned, and the pruning is recorded");
        check(store.AuditHighestSequence(machine.Fingerprint) == 2, "retention: pruning keeps the machine's sequence state (a gap is still a gap)");

        // Pruning happens with the next upload, too.
        AuditEvent next = outbox.Append(Facts());
        await machine.Deployment.Authority.UploadAsync(Batch(machine, next));
        clock.Advance(TimeSpan.FromDays(31));
        AuditEvent later = outbox.Append(Facts());
        await machine.Deployment.Authority.UploadAsync(Batch(machine, later));
        check(store.AuditHistory(new AuditQuery()) is [{ } only] && only.Event.EventId == later.EventId, "retention: an upload prunes what the retention no longer keeps");

        // 0 keeps everything; the outbox never prunes on its own.
        store.SetAuditRetentionDays(0, RetentionAdmin(0));
        clock.Advance(TimeSpan.FromDays(5000));
        check(store.PruneAuditEvents() == 0 && store.AuditHistory(new AuditQuery()).Count == 1, "retention: 0 keeps everything");
        int waiting = outbox.Count("pending");
        outbox.Append(Facts());
        clock.Advance(TimeSpan.FromDays(5000));
        check(outbox.Count("pending") == waiting + 1, "retention: an event that is not acknowledged stays in the outbox however old it is");
    }

    // ---- history queries ----

    private static async Task History(Action<bool, string> check, string parent)
    {
        TestClock clock = new();
        using TestMachine machine = new(Path.Combine(parent, "hi-" + Guid.NewGuid().ToString("N")[..6]), true, clock: clock);
        using TestMachine other = new(Path.Combine(parent, "hi2-" + Guid.NewGuid().ToString("N")[..6]), true, clock: clock);
        AuthorityStore store = machine.Deployment.Store;
        HostAuditOutbox outbox = HostAuditOutbox.InFolder(machine.Folder, machine.MachineKey, clock);
        DateTimeOffset t0 = clock.GetUtcNow();
        List<AuditEvent> events = [];
        void Add(AuditFacts facts)
        {
            events.Add(outbox.Append(facts));
            clock.Advance(TimeSpan.FromMinutes(10));
        }

        Add(Facts(program: "/work/build.sh", folder: "/work/alpha", arguments: ["--target", "release"]));
        Add(Facts(AuditEventTypes.Launch, "started", "", "g-aaaa1111", folder: "/work/alpha", program: "/work/build.sh"));
        Add(Facts(AuditEventTypes.Execution, "exited", "", "g-aaaa1111", 0, "/work/alpha", "/work/build.sh"));
        Add(Facts(outcome: "denied", reason: "user-denied", folder: "/work/beta", program: "/work/deploy.sh", arguments: ["100% done", "a_b"]));
        Add(Facts(AuditEventTypes.Authorization, "granted", "online", "g-bbbb2222", folder: "/work/beta", program: "/work/deploy.sh"));
        await machine.Deployment.Authority.UploadAsync(Batch(machine, [.. events]));

        AuditEvent foreign = AuditEvent.Create(Facts(program: "/work/other.sh"), Guid.NewGuid().ToString("D"), 1, clock.GetUtcNow(), other.MachineKey);
        await machine.Deployment.Authority.UploadAsync(new AuditBatch("b-foreign", other.Fingerprint, [foreign]));

        IReadOnlyList<AuditHistoryRecord> Query(AuditQuery query) => store.AuditHistory(query);
        check(Query(new AuditQuery()).Count == 5, "history: no filter lists every event (the unknown machine's upload was refused)");
        check(Query(new AuditQuery()).Select(record => record.Event.Sequence).SequenceEqual([5L, 4L, 3L, 2L, 1L]), "history: newest first");
        check(Query(new AuditQuery(Type: AuditEventTypes.Launch)) is [{ } launch] && launch.Event.Outcome == "started", "history: filter by event type");
        check(Query(new AuditQuery(Outcome: "denied")) is [{ } denied] && denied.Event.Reason == "user-denied", "history: filter by outcome");
        check(Query(new AuditQuery(GrantId: "g-aaaa")).Count == 2 && Query(new AuditQuery(GrantId: "g-bbbb2222")).Count == 1 && Query(new AuditQuery(GrantId: "g-zzzz")).Count == 0, "history: filter by grant id (the whole id or the first characters)");
        check(Query(new AuditQuery(Folder: "beta")).Count == 2 && Query(new AuditQuery(Folder: "/work/alpha")).Count == 3, "history: filter by project/working directory");
        check(Query(new AuditQuery(Text: "deploy")).Count == 2 && Query(new AuditQuery(Text: "RELEASE")).Count == 1 && Query(new AuditQuery(Text: "user-denied")).Count == 1, "history: text search over program, arguments and reason, without regard to case");
        check(Query(new AuditQuery(Text: "100%")).Count == 1 && Query(new AuditQuery(Text: "a_b")).Count == 1 && Query(new AuditQuery(Text: "%")).Count == 1 && Query(new AuditQuery(Text: "_")).Count == 1, "history: % and _ in the search text are literal characters");
        check(Query(new AuditQuery(From: t0.AddMinutes(10), To: t0.AddMinutes(30))).Select(record => record.Event.Sequence).Order().SequenceEqual([2L, 3L, 4L]), "history: filter by time range (inclusive)");
        check(Query(new AuditQuery(MachinePrefix: machine.Fingerprint[..12])).Count == 5 && Query(new AuditQuery(MachinePrefix: KeyIdentity.Display(machine.Fingerprint)[..14])).Count == 5 && Query(new AuditQuery(MachinePrefix: machine.Fingerprint[..12].ToLowerInvariant())).Count == 5 && Query(new AuditQuery(MachinePrefix: "0000FFFF0000")).Count == 0, "history: filter by machine (a fingerprint prefix, as typed in groups or in either case)");
        check(Query(new AuditQuery(Type: AuditEventTypes.Authorization, Folder: "beta", Text: "deploy", GrantId: "g-bbbb")).Count == 1 && Query(new AuditQuery(Type: AuditEventTypes.Launch, Folder: "beta")).Count == 0, "history: filters combine (all must match)");
        check(Query(new AuditQuery(Limit: 2)).Count == 2 && Query(new AuditQuery(Limit: 0)).Count == 1 && Query(new AuditQuery(Limit: 100000)).Count == 5, "history: the limit is clamped to 1 to 1000");
        check(Query(new AuditQuery(Text: "x' OR '1'='1")).Count == 0 && Query(new AuditQuery(Text: "\\")).Count == 0, "history: text with quotes or a backslash is data, not SQL");
    }

    // ---- uploading ----

    private static async Task Uploading(Action<bool, string> check, string parent)
    {
        // Retry until acknowledged, in batches.
        using (TestMachine machine = new(Path.Combine(parent, "up-" + Guid.NewGuid().ToString("N")[..6])))
        {
            AuthorityStore store = machine.Deployment.Store;
            HostAuditOutbox outbox = HostAuditOutbox.InFolder(machine.Folder, machine.MachineKey);
            FlakySink sink = new(machine.Deployment.Authority);
            AuditUploader uploader = new(outbox, () => sink, Verifier(AuthorityKey(machine)), machine.Fingerprint, 2);
            for (int index = 0; index < 5; index++)
            {
                outbox.Append(Facts());
            }

            sink.Offline = true;
            AuditUploadResult down = await uploader.DrainAsync();
            check(down.Failed && down.Acknowledged == 0 && outbox.Count("pending") == 5 && sink.Calls == 1 && store.AuditHistory(new AuditQuery()).Count == 0, "retry: while the authority cannot be reached nothing is removed from the outbox");
            down = await uploader.DrainAsync();
            check(down.Failed && outbox.Count("pending") == 5 && sink.Calls == 2, "retry: the next drain tries again");
            sink.Offline = false;
            AuditUploadResult up = await uploader.DrainAsync();
            check(!up.Failed && up.Acknowledged == 5 && outbox.Count("pending") == 0 && sink.Batches.Skip(2).Select(batch => batch.Events.Count).SequenceEqual([2, 2, 1]) && store.AuditHistory(new AuditQuery()).Count == 5 && store.AuditGaps().Count == 0, "acknowledgement: once reachable the outbox is sent in batches of 2, 2, 1, and each event leaves the outbox only after the authority acknowledged it");

            // The authority's commit fails: no acknowledgement, the events stay and are sent again.
            outbox.Append(Facts());
            outbox.Append(Facts());
            store.Fault = point =>
            {
                if (point == "after-audit-events")
                {
                    throw new InvalidOperationException("the commit failed (test)");
                }
            };
            AuditUploadResult broken = await uploader.DrainAsync();
            store.Fault = null;
            check(broken.Failed && outbox.Count("pending") == 2 && store.AuditHistory(new AuditQuery()).Count == 5, "acknowledgement: an authority that could not commit sends no acknowledgement; the events stay in the outbox");
            check((await uploader.DrainAsync()).Acknowledged == 2 && outbox.Count("pending") == 0 && store.AuditHistory(new AuditQuery()).Count == 7 && store.AuditGaps().Count == 0, "acknowledgement: the retry is stored and acknowledged, with no gap and no duplicate");

            // An acknowledgement that is altered, replayed or signed by another key removes nothing.
            outbox.Append(Facts());
            AuditAck? replay = null;
            sink.Tamper = (batch, ack) =>
            {
                replay ??= ack;

                return ack with { Entries = [] };
            };
            check((await uploader.DrainAsync()).Failed && outbox.Count("pending") == 1, "acknowledgement: an altered answer (the signature no longer fits) removes nothing");
            sink.Tamper = (batch, ack) => replay!;
            check((await uploader.DrainAsync()).Failed && outbox.Count("pending") == 1, "acknowledgement: an answer replayed from another batch removes nothing");
            using SoftwareSigningKey rogue = new();
            sink.Tamper = (batch, ack) => AuditAck.Create(batch, ack.Entries, ack.Issued, TimeSpan.FromSeconds(60), rogue);
            check((await uploader.DrainAsync()).Failed && outbox.Count("pending") == 1, "acknowledgement: an answer signed by a key that is not the authority's removes nothing");
            sink.Tamper = (batch, ack) => AuditAck.Create(batch, [new AuditAckEntry("not-one-of-ours", AuditStatus.Accepted, "")], ack.Issued, TimeSpan.FromSeconds(60), machine.Deployment.Keys.Current());
            check((await uploader.DrainAsync()).Failed && outbox.Count("pending") == 1, "acknowledgement: an answer that names only other events removes nothing");
            sink.Tamper = null;
            check((await uploader.DrainAsync()).Acknowledged == 1 && outbox.Count("pending") == 0, "acknowledgement: the genuine answer is accepted");

            // Rejected for good: kept, never sent again.
            AuditEvent keep = outbox.Append(Facts());
            AuditEvent drop = outbox.Append(Facts());
            sink.Tamper = (batch, ack) => AuditAck.Create(batch, [new AuditAckEntry(keep.EventId, AuditStatus.Rejected, "bad-signature"), new AuditAckEntry(drop.EventId, AuditStatus.Accepted, "")], ack.Issued, TimeSpan.FromSeconds(60), machine.Deployment.Keys.Current());
            AuditUploadResult mixed = await uploader.DrainAsync();
            int calls = sink.Calls;
            check(!mixed.Failed && mixed.Rejected == 1 && mixed.Acknowledged == 1 && outbox.Count("pending") == 0 && outbox.Count("rejected") == 1, "rejection: an event the authority refuses is kept apart (rejected), not pending");
            await uploader.DrainAsync();
            check(sink.Calls == calls, "rejection: a rejected event is not sent again");
            sink.Tamper = null;
        }

        // The loop: never blocks a record, retries by itself, stops with the service.
        using (TestMachine machine = new(Path.Combine(parent, "lp-" + Guid.NewGuid().ToString("N")[..6])))
        {
            AuthorityStore store = machine.Deployment.Store;
            HostAuditOutbox outbox = HostAuditOutbox.InFolder(machine.Folder, machine.MachineKey);
            FlakySink sink = new(machine.Deployment.Authority) { Offline = true };
            HostAudit audit = new(outbox, new AuditUploader(outbox, () => sink, Verifier(AuthorityKey(machine)), machine.Fingerprint));
            using CancellationTokenSource stop = new();
            Task loop = audit.RunAsync(Fast, TimeSpan.FromMilliseconds(160), stop.Token);
            bool recorded = audit.TryRecord(Facts()) && audit.TryRecord(Facts()) && audit.TryRecord(Facts());
            check(recorded && outbox.Count("pending") + store.AuditHistory(new AuditQuery()).Count == 3, "loop: events are recorded whatever the authority does");
            check(await HostServiceTests.WaitFor(() => sink.Calls >= 3, 10) && outbox.Count("pending") == 3, "loop: while the authority is down it keeps trying (with a growing pause) and keeps the events");
            sink.Offline = false;
            check(await HostServiceTests.WaitFor(() => outbox.Count("pending") == 0 && store.AuditHistory(new AuditQuery()).Count == 3, 10), "loop: when it is back every event is delivered and acknowledged without anyone asking");
            audit.TryRecord(Facts());
            check(await HostServiceTests.WaitFor(() => store.AuditHistory(new AuditQuery()).Count == 4, 10), "loop: a new event wakes the uploader at once");
            stop.Cancel();
            check(await Task.WhenAny(loop, Task.Delay(5000)) == loop, "loop: it ends when the service stops");
        }

        using (TestMachine machine = new(Path.Combine(parent, "hg-" + Guid.NewGuid().ToString("N")[..6])))
        {
            HostAuditOutbox outbox = HostAuditOutbox.InFolder(machine.Folder, machine.MachineKey);
            FlakySink sink = new(machine.Deployment.Authority) { Hang = true };
            HostAudit audit = new(outbox, new AuditUploader(outbox, () => sink, Verifier(AuthorityKey(machine)), machine.Fingerprint));
            using CancellationTokenSource stop = new();
            Task loop = audit.RunAsync(Fast, TimeSpan.FromMilliseconds(160), stop.Token);
            System.Diagnostics.Stopwatch watch = System.Diagnostics.Stopwatch.StartNew();
            bool all = Enumerable.Range(0, 10).All(_ => audit.TryRecord(Facts()));
            check(all && watch.Elapsed < TimeSpan.FromSeconds(3) && outbox.Count("pending") == 10, "never blocks: with an authority that never answers, ten events are recorded at once (" + watch.ElapsedMilliseconds + " ms)");
            stop.Cancel();
            check(await Task.WhenAny(loop, Task.Delay(5000)) == loop, "never blocks: a hanging upload is cancelled when the service stops");
        }

        // Restart: the unacknowledged events and the numbering survive.
        using (TestMachine machine = new(Path.Combine(parent, "rs-" + Guid.NewGuid().ToString("N")[..6])))
        {
            AuthorityStore store = machine.Deployment.Store;
            HostAuditOutbox before = HostAuditOutbox.InFolder(machine.Folder, machine.MachineKey);
            for (int index = 0; index < 3; index++)
            {
                before.Append(Facts());
            }

            HostAuditOutbox after = HostAuditOutbox.InFolder(machine.Folder, machine.MachineKey);
            AuditUploader uploader = new(after, () => machine.Deployment.AuditSink, Verifier(AuthorityKey(machine)), machine.Fingerprint);
            check((await uploader.DrainAsync()).Acknowledged == 3 && after.Append(Facts()).Sequence == 4 && store.AuditHistory(new AuditQuery()).Select(record => record.Event.Sequence).Order().SequenceEqual([1L, 2L, 3L]) && store.AuditGaps().Count == 0, "restart: a new process uploads what the old one left and goes on numbering from where it stopped");
        }
    }

    // ---- schema ----

    private static void Schema(Action<bool, string> check, string parent)
    {
        using TestMachine machine = new(Path.Combine(parent, "sc-" + Guid.NewGuid().ToString("N")[..6]));
        string file = machine.Deployment.Store.FilePath;
        check(AuthorityStore.SchemaVersion == 5 && Convert.ToInt32(Scalar(file, "SELECT version FROM schema_version")) == 5 && Convert.ToInt32(Scalar(file, "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('audit_events','audit_machine_state','audit_gaps','authority_settings')")) == 4, "schema: a new authority.db is version 5 with the audit tables");
        Sql(file, "DROP TABLE audit_events; DROP TABLE audit_machine_state; DROP TABLE audit_gaps; DROP TABLE authority_settings; UPDATE schema_version SET version = 3;");
        AuthorityStore migrated = AuthorityStore.InFolder(machine.Folder);
        check(migrated.AuditHistory(new AuditQuery()).Count == 0 && Convert.ToInt32(Scalar(file, "SELECT version FROM schema_version")) == 5 && migrated.Machines().Count == 1 && migrated.AuditRetentionDays() == 365, "schema: a version 3 authority.db gains the audit tables in place (machines are kept)");
        Sql(file, "UPDATE schema_version SET version = 6");
        check(Catch<AuthorityDatabaseException>(() => AuthorityStore.InFolder(machine.Folder).AuditHistory(new AuditQuery())) is not null, "schema: another version is still refused");
    }

    // ---- the command ----

    private static void Cli(Action<bool, string> check, string parent)
    {
        // The audit search of the admin web app (the old `admin audit` verb is gone): its query parsing and the data it reads.
        (AuditQuery? Query, string? Error) Parse(params (string Name, string Value)[] args) => AdminService.ParseAuditQuery(name => args.Where(item => item.Name == name).Select(item => item.Value).FirstOrDefault());
        check(Parse() is { Error: null, Query: { Limit: 100, MachinePrefix: null, Text: null } }, "audit search parse: no filters lists the newest 100");
        var full = Parse(("machine", "AB12"), ("since", "2026-11-01"), ("until", "2026-11-02T10:00:00Z"), ("type", "launch"), ("outcome", "started"), ("grant", "g-12"), ("folder", "alpha"), ("text", "build"), ("last", "7"));
        check(full.Query is { MachinePrefix: "AB12", Type: "launch", Outcome: "started", GrantId: "g-12", Folder: "alpha", Text: "build", Limit: 7 } && full.Query.From == new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero) && full.Query.To == new DateTimeOffset(2026, 11, 2, 10, 0, 0, TimeSpan.Zero), "audit search parse: every filter (a time without a zone is UTC)");
        check(Parse(("machine", "AB12")) is { Error: null } && Parse(("type", "nope")).Error is not null && Parse(("since", "yesterday-ish")).Error is not null && Parse(("last", "0")).Error is not null && Parse(("last", "1001")).Error is not null && Parse(("last", "-3")).Error is not null, "audit search parse: bad values are refused with a reason");

        using TestMachine machine = new(Path.Combine(parent, "cl-" + Guid.NewGuid().ToString("N")[..6]));
        HostAuditOutbox outbox = HostAuditOutbox.InFolder(machine.Folder, machine.MachineKey);
        check(machine.Deployment.Store.AuditHistory(new AuditQuery()).Count == 0, "audit search: nothing recorded yet finds nothing");
        AuditEvent a = outbox.Append(Facts(program: "/work/build.sh", arguments: ["--token=[REDACTED]"]));
        AuditEvent b = outbox.Append(Facts(AuditEventTypes.Execution, "exited", "", "g-1", 3, "/work", "/work/build.sh"));
        AuditEvent skipped = AuditEvent.Create(Facts(), Guid.NewGuid().ToString("D"), 9, DateTimeOffset.UtcNow, machine.MachineKey, (string)Scalar(outbox.FilePath, "SELECT epoch FROM counter")!);
        machine.Deployment.Authority.UploadAsync(Batch(machine, a, b, skipped)).GetAwaiter().GetResult();
        check(machine.Deployment.Store.AuditHistory(Parse().Query!).Count == 3, "audit search: all three stored events are found, newest first");
        check(machine.Deployment.Store.AuditHistory(Parse(("grant", "g-1")).Query!) is { Count: 1 } one && one[0].Event.Outcome == "exited", "audit search: the grant filter applies");
        check(machine.Deployment.Store.AuditGaps(null, openOnly: true) is { Count: > 0 } gaps && gaps.Any(gap => gap.From == 3 && gap.To == 8), "audit search: the gap view lists the missing range 3-8");
        check(CliArgs.Parse(["--help"], out _) is CliCommand.Help { Text: var help } && help.Contains("admin web app", StringComparison.Ordinal) && !help.Contains("admin audit", StringComparison.Ordinal), "help: it describes the admin web app and no longer an admin audit command");
    }

    // ---- the audit view of the admin web app ----

    private static async Task AdminAuditView(Action<bool, string> check, string parent)
    {
        using AdminApp app = new(parent);
        TestMachine machine = app.Machine;
        app.Service.Dispose();
        HostAuditOutbox outbox = HostAuditOutbox.InFolder(machine.Folder, machine.MachineKey);
        AuditEvent a = outbox.Append(Facts(program: "/work/build.sh", arguments: ["--token=[REDACTED]"]));
        AuditEvent b = outbox.Append(Facts(AuditEventTypes.Execution, "exited", "", "g-1", 3, "/other/dir", "/work/test.sh"));
        AuditEvent skipped = AuditEvent.Create(Facts(), Guid.NewGuid().ToString("D"), 9, DateTimeOffset.UtcNow, machine.MachineKey, EpochOf(outbox));
        machine.Deployment.Authority.UploadAsync(Batch(machine, a, b, skipped)).GetAwaiter().GetResult();
        app.Start(true);
        AdminBrowser anon = app.Browser();
        check((await anon.GetAsync("/api/v1/audit/events?text=build")).Status == 401 && (await anon.GetAsync("/api/v1/audit/changes")).Status == 401 && (await anon.GetAsync("/api/v1/audit/gaps")).Status == 401, "audit view: without a session nothing of the history is served");
        AdminBrowser browser = await app.SignedIn();
        async Task<string> View(string query, string kind = "events") => (await browser.GetAsync("/api/v1/audit/" + kind + query)).Html;
        string all = await View("");
        check(all.Contains("build.sh", StringComparison.Ordinal) && all.Contains("test.sh", StringComparison.Ordinal) && all.Contains("exited", StringComparison.Ordinal) && all.Contains("g-1", StringComparison.Ordinal) && all.Contains("--token=[REDACTED]", StringComparison.Ordinal), "audit view: every event with its outcome, grant, exit code and the redacted command");
        string changes = await View("", "changes");
        check(changes.Contains("admin-session", StringComparison.Ordinal) && changes.Contains("\"actor\"", StringComparison.Ordinal), "audit view: the authority's own changes (the session start) are served too");
        string byGrant = await View("?grant=g-1");
        check(byGrant.Contains("test.sh", StringComparison.Ordinal) && !byGrant.Contains("build.sh", StringComparison.Ordinal), "audit view: the grant filter applies");
        string byMachine = await View("?machine=" + KeyIdentity.Display(machine.Fingerprint).Replace(" ", "")[..8]);
        string otherMachine = await View("?machine=ffffffff");
        check(byMachine.Contains("build.sh", StringComparison.Ordinal) && !otherMachine.Contains("build.sh", StringComparison.Ordinal) && otherMachine == "{\"items\":[]}", "audit view: the machine filter applies");
        check((await View("?type=execution")).Contains("test.sh", StringComparison.Ordinal) && !(await View("?type=execution")).Contains("build.sh", StringComparison.Ordinal), "audit view: the type (launch or execution) filter applies");
        check((await View("?outcome=exited")).Contains("test.sh", StringComparison.Ordinal) && !(await View("?outcome=exited")).Contains("build.sh", StringComparison.Ordinal), "audit view: the outcome filter applies");
        check((await View("?folder=other")).Contains("test.sh", StringComparison.Ordinal) && !(await View("?folder=other")).Contains("build.sh", StringComparison.Ordinal), "audit view: the project (working directory) filter applies");
        check((await View("?text=build")).Contains("build.sh", StringComparison.Ordinal) && !(await View("?text=build")).Contains("test.sh", StringComparison.Ordinal), "audit view: the text search applies");
        check((await View("?since=2999-01-01")) == "{\"items\":[]}" && (await View("?until=2000-01-01")) == "{\"items\":[]}" && (await View("?since=2000-01-01")).Contains("build.sh", StringComparison.Ordinal), "audit view: the time range applies");
        string gaps = await View("", "gaps");
        check(gaps.Contains("\"from\":3", StringComparison.Ordinal) && gaps.Contains("\"to\":8", StringComparison.Ordinal) && gaps.Contains("missing", StringComparison.OrdinalIgnoreCase), "audit view: the gap list has the missing range 3-8");
        (int badStatus, string bad, HttpResponseMessage badResponse) = await browser.GetAsync("/api/v1/audit/events?last=0&since=nonsense");
        check(badStatus == 400 && badResponse.Content.Headers.ContentType?.MediaType == "application/problem+json" && bad.Contains("invalid-request", StringComparison.Ordinal) && !bad.Contains("build.sh", StringComparison.Ordinal), "audit view: a bad filter is a problem document and shows nothing");
        (int unknownStatus, _, _) = await browser.GetAsync("/api/v1/audit/events?nope=1");
        check(unknownStatus == 400, "audit view: a query parameter the route does not take is refused");
        (int xssStatus, string xss, HttpResponseMessage xssResponse) = await browser.GetAsync("/api/v1/audit/changes?text=" + Uri.EscapeDataString("<script>alert(1)</script>"));
        check(xssStatus == 200 && !xss.Contains("<script>", StringComparison.Ordinal) && xssResponse.Content.Headers.ContentType?.MediaType == "application/json" && xssResponse.Headers.GetValues("X-Content-Type-Options").Contains("nosniff"), "audit view: a search text never comes back as markup (JSON, nosniff)");
        check(!all.Contains("authenticatorData", StringComparison.Ordinal) && !all.Contains(browser.Cookies[AdminSessions.SessionCookie], StringComparison.Ordinal) && !changes.Contains(browser.Cookies[AdminSessions.SessionCookie], StringComparison.Ordinal), "audit view: no proof and no session token in the answers");

        // L2: a locked authority stores nothing that a host uploads.
        using TestMachine lockedMachine = new(Path.Combine(parent, "l2-" + Guid.NewGuid().ToString("N")[..6]));
        lockedMachine.Deployment.Keys.LockState = new AuthorityLock();
        HostAuditOutbox lockedOutbox = HostAuditOutbox.InFolder(lockedMachine.Folder, lockedMachine.MachineKey);
        AuditEvent held = lockedOutbox.Append(Facts());
        bool refused = false;
        try
        {
            await lockedMachine.Deployment.Authority.UploadAsync(Batch(lockedMachine, held));
        }
        catch (AuthorityLockedException)
        {
            refused = true;
        }

        check(refused && lockedMachine.Deployment.Store.AuditHistory(new AuditQuery()).Count == 0, "audit upload: a locked authority refuses an upload and stores (and prunes) nothing (L2)");
    }

    // ---- through the running service ----

    private static List<AuditEvent> Events(HostServiceTests.Rig rig) => [.. rig.Machine.Deployment.Store.AuditHistory(new AuditQuery(Limit: 1000)).Select(record => record.Event).OrderBy(item => item.Sequence)];

    private static async Task ThroughTheService(Action<bool, string> check, string parent)
    {
        // A run approved on the page: three distinct signed events, in order.
        using (HostServiceTests.Rig rig = new(parent, approver: () => new FakeApprover(true), auditInterval: Fast))
        {
            string program = GrantAuthorityTests.Show(rig);
            HostServiceTests.Raw run = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program, ["--build"]));
            bool drained = await HostServiceTests.WaitFor(() => Events(rig).Count == 3 && rig.Service.Audit.Outbox.Count("pending") == 0);
            List<AuditEvent> events = Events(rig);
            check(run.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 0 } && drained, "service audit: an approved run produced events that reached the authority and left the outbox (" + events.Count + ")");
            check(events.Select(item => item.Type).SequenceEqual([AuditEventTypes.Authorization, AuditEventTypes.Launch, AuditEventTypes.Execution]) && events.Select(item => item.Outcome).SequenceEqual(["approved", "started", "exited"]) && events.Select(item => item.Sequence).SequenceEqual([1L, 2L, 3L]),
                "service audit: the authorization decision, the launch outcome and the execution outcome are distinct events, numbered 1, 2, 3 (" + string.Join(",", events.Select(item => item.Type + ":" + item.Outcome)) + ")");
            check(events.All(item => item.Verify(rig.Machine.MachineKey.PublicKey) && item.MachineFingerprint == rig.Machine.Fingerprint && item.Folder == rig.Work && Path.GetFileName(item.Program) == Path.GetFileName(program) && item.Arguments.SequenceEqual(["--build"]) && item.GrantId == "" && item.RequestId.StartsWith("req-", StringComparison.Ordinal)) && events.Select(item => item.EventId).Distinct().Count() == 3,
                "service audit: each event is signed by the machine key and carries the machine, the working folder, the program, the (redacted) arguments and the request id");
            check(events.Select(item => item.ExitCode).SequenceEqual([null, null, 0]) && events.All(item => item.Reason is "approved" or ""), "service audit: the exit code is on the execution event only");
            check(rig.Machine.Deployment.Store.AuditGaps().Count == 0, "service audit: no sequence gap");
        }

        // A denial is an authorization event and nothing else; nothing is decrypted.
        using (HostServiceTests.Rig rig = new(parent, approver: () => new FakeApprover(false), auditInterval: Fast))
        {
            HostServiceTests.Raw run = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, GrantAuthorityTests.Show(rig)));
            await HostServiceTests.WaitFor(() => Events(rig).Count == 1 && rig.Service.Audit.Outbox.Count("pending") == 0);
            List<AuditEvent> events = Events(rig);
            check(run.Result is { Outcome: LaunchOutcome.Denied } && rig.Store.Reads == 0 && events is [{ Type: AuditEventTypes.Authorization, Outcome: "denied", Reason: "user-denied" }], "service audit: a refused approval is one authorization event (denied, user-denied), no launch and no execution, and nothing was decrypted");
        }

        // A machine that is not trusted: the denial is audited with the authority's code.
        using (HostServiceTests.Rig rig = new(parent, approver: () => new FakeApprover(true), trusted: false, auditInterval: Fast))
        {
            HostServiceTests.Raw run = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, GrantAuthorityTests.Show(rig)));
            check(run.Result is { Outcome: LaunchOutcome.Denied } && rig.Store.Reads == 0 && rig.Service.Audit.Outbox.Pending(10) is [{ Type: AuditEventTypes.Authorization, Outcome: "denied" } denied] && denied.Reason.StartsWith("machine-", StringComparison.Ordinal), "service audit: a denied attempt of a machine that is not trusted is audited too (" + string.Join(",", rig.Service.Audit.Outbox.Pending(10).Select(item => item.Reason)) + ")");
        }

        // A grant: approve, then run under it.
        using (TestAuthenticator signer = TestAuthenticator.ES256())
        {
            GrantAuthorityTests.Chooser chooser = new(60, signer: signer);
            using HostServiceTests.Rig rig = new(parent, approver: () => chooser, enrolled: signer, auditInterval: Fast);
            string program = GrantAuthorityTests.Show(rig);
            await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program), path: "/v1/approve");
            chooser.Minutes = 0;
            HostServiceTests.Raw run = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            await HostServiceTests.WaitFor(() => Events(rig).Count == 5 && rig.Service.Audit.Outbox.Count("pending") == 0);
            List<AuditEvent> events = Events(rig);
            string grantId = rig.Machine.Deployment.Store.Grants()[0].Id;
            check(run.Result is { Outcome: LaunchOutcome.Exited } && events.Select(item => item.Outcome).SequenceEqual(["approval-requested", "grant-approved", "granted", "started", "exited"]) && events[1].GrantId == grantId, "service audit: approve is audited (approval-requested before the tap, then grant-approved with the grant id) and a run under the grant is audited as granted, started, exited (" + string.Join(",", events.Select(item => item.Outcome)) + ")");
            check(events.Skip(1).All(item => item.GrantId == grantId) && events[2].Reason == "online" && events[2].Type == AuditEventTypes.Authorization, "service audit: every event of a grant use carries the grant id, and the authorization says it was checked online");
            check(rig.Machine.Deployment.Store.AuditHistory(new AuditQuery(GrantId: grantId)).Count == 4, "service audit: the history can be filtered by the grant id");

            // A grant use whose event cannot be committed does not run.
            int reads = rig.Store.Reads;
            File.Delete(HostServiceTests.Marker(rig));
            rig.Service.Audit.Outbox.Fault = point => throw new IOException("the disk is full (test)");
            HostServiceTests.Raw blocked = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            rig.Service.Audit.Outbox.Fault = null;
            check(blocked.Result is { Outcome: LaunchOutcome.Failed, ExitCode: RunCommand.AuditError } && rig.Store.Reads == reads && !File.Exists(HostServiceTests.Marker(rig)), "durable before launch: a grant-covered run whose event cannot be committed is refused (exit 5); nothing was decrypted and nothing started (" + blocked.Stderr.Trim() + ")");
        }

        // Durable before launch: the order, with an authority that cannot be reached so that the outbox is not drained under our feet.
        {
            using TestMachine machine = new(Path.Combine(parent, "ord-" + Guid.NewGuid().ToString("N")[..6]));
            FlakySink sink = new(machine.Deployment.Authority) { Offline = true };
            machine.Deployment.AuditSink = sink;
            List<AuditEvent>? atRead = null;
            List<AuditEvent>? atStart = null;
            HostAuditOutbox? watched = null;
            using HostServiceTests.Rig rig = new(parent, approver: () => new FakeApprover(true), machine: machine, auditInterval: Fast, afterCommit: () => atStart = [.. watched!.Pending(50)]);
            watched = rig.Service.Audit.Outbox;
            rig.Store.OnRead = () => atRead = [.. watched.Pending(50)];
            HostServiceTests.Raw run = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, GrantAuthorityTests.Show(rig)));
            check(run.Result is { Outcome: LaunchOutcome.Exited } && atRead is [{ Type: AuditEventTypes.Authorization, Outcome: "approved" } committed] && committed.Verify(machine.MachineKey.PublicKey), "durable before launch: when the secrets are decrypted the signed authorization event is already committed in the outbox, and it is the only event");
            check(atStart is [{ Type: AuditEventTypes.Authorization }, { Type: AuditEventTypes.Launch, Outcome: "started" }], "durable before launch: the launch event follows once the program has started; the execution event only after it ended");
            check(rig.Service.Audit.Outbox.Pending(10).Select(item => item.Type).SequenceEqual([AuditEventTypes.Authorization, AuditEventTypes.Launch, AuditEventTypes.Execution]) && await HostServiceTests.WaitFor(() => sink.Calls >= 1), "durable before launch: with the authority unreachable the run was not held up, and all three events wait in the outbox");
        }

        // Fault injection: the commit fails, so the run fails closed.
        using (HostServiceTests.Rig rig = new(parent, approver: () => new FakeApprover(true), auditInterval: Fast))
        {
            string program = GrantAuthorityTests.Show(rig);
            rig.Service.Audit.Outbox.Fault = point => throw new IOException("the disk is full (test)");
            HostServiceTests.Raw run = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            check(run.Result is { Outcome: LaunchOutcome.Failed, ExitCode: RunCommand.AuditError } && rig.Store.Reads == 0 && !File.Exists(HostServiceTests.Marker(rig)) && rig.Service.Audit.Outbox.LastSequence() == 0, "durable before launch: if the authorization event cannot be committed the run fails closed (exit 5): the canary decrypt count is 0, nothing started, no number used (" + run.Stderr.Trim() + ")");
            rig.Service.Audit.Outbox.Fault = null;
            HostServiceTests.Raw next = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            await HostServiceTests.WaitFor(() => Events(rig).Count == 3 && rig.Service.Audit.Outbox.Count("pending") == 0);
            check(next.Result is { Outcome: LaunchOutcome.Exited } && rig.Store.Reads == 1 && Events(rig).Select(item => item.Sequence).SequenceEqual([1L, 2L, 3L]), "durable before launch: once the outbox works again the next run goes through, numbered from 1 (the failed attempt used no number)");

            // The later events are not a condition of a launch that already happened.
            int appends = 0;
            rig.Service.Audit.Outbox.Fault = point =>
            {
                if (point == "before-commit" && Interlocked.Increment(ref appends) == 2)
                {
                    throw new IOException("the disk is full (test)");
                }
            };
            File.Delete(HostServiceTests.Marker(rig));
            HostServiceTests.Raw partial = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            rig.Service.Audit.Outbox.Fault = null;
            await HostServiceTests.WaitFor(() => Events(rig).Count == 5 && rig.Service.Audit.Outbox.Count("pending") == 0);
            check(partial.Result is { Outcome: LaunchOutcome.Exited, ExitCode: 0 } && File.Exists(HostServiceTests.Marker(rig)) && Events(rig).Skip(3).Select(item => item.Type).SequenceEqual([AuditEventTypes.Authorization, AuditEventTypes.Execution]) && rig.Machine.Deployment.Store.AuditGaps().Count == 0,
                "durable before launch: if only the launch event cannot be committed the program still runs (it is after the fact), the other events are recorded and the numbers stay gapless");
        }

        // Real failures of the outbox file: damaged, and a folder in its place.
        foreach (bool asFolder in new[] { false, true })
        {
            using TestMachine machine = new(Path.Combine(parent, "bad-" + Guid.NewGuid().ToString("N")[..6]));
            string file = Path.Combine(machine.Folder, HostAuditOutbox.FileName);
            if (asFolder)
            {
                Directory.CreateDirectory(file);
            }
            else
            {
                File.WriteAllText(file, "this is not a database");
            }

            using HostServiceTests.Rig rig = new(parent, approver: () => new FakeApprover(true), machine: machine, auditInterval: Fast);
            HostServiceTests.Raw run = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, GrantAuthorityTests.Show(rig)));
            check(run.Result is { Outcome: LaunchOutcome.Failed, ExitCode: RunCommand.AuditError } && rig.Store.Reads == 0 && !File.Exists(HostServiceTests.Marker(rig)), "outbox failure: " + (asFolder ? "a folder where the outbox file belongs" : "a damaged outbox file") + " fails the secret-bearing run closed; nothing is decrypted or started (" + run.Stderr.Trim() + ")");
        }

        // Redaction: no secret value, argument canary or environment value is in the authority's database or the outbox.
        {
            const string Value = "Canary-Value-48151623";
            const string Other = "Canary-Other-9001337";
            using TestMachine machine = new(Path.Combine(parent, "red-" + Guid.NewGuid().ToString("N")[..6]));
            using HostServiceTests.Rig rig = new(parent, approver: () => new FakeApprover(true), machine: machine, auditInterval: Fast);
            string[] canaries = ["ArgCanary-111", "ArgCanary-222", "ArgCanary-333", "ArgCanary-444x", "EnvCanary-555"];
            HostServiceTests.Raw run = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, GrantAuthorityTests.Show(rig), ["--token=ArgCanary-111", "--password", "ArgCanary-222", "https://bob:ArgCanary-333@host/p", "Authorization: Bearer ArgCanary-444x", "--ok"], environment: HostServiceTests.Env(("WS_ENV_CANARY", "EnvCanary-555"))));
            await HostServiceTests.WaitFor(() => Events(rig).Count == 3 && rig.Service.Audit.Outbox.Count("pending") == 0);
            List<AuditEvent> events = Events(rig);
            string[] expected = ["--token=[REDACTED]", "--password", "[REDACTED]", "https://[REDACTED]@host/p", "Authorization: [REDACTED] [REDACTED]", "--ok"];
            check(run.Result is { Outcome: LaunchOutcome.Exited } && events.Count == 3 && events.All(item => item.Arguments.SequenceEqual(expected)), "redaction: the arguments in every event are the redacted ones (" + string.Join(" | ", events.FirstOrDefault()?.Arguments ?? []) + ")");

            StringBuilder everything = new();
            foreach (string file in Directory.GetFiles(machine.Folder).Where(name => Path.GetFileName(name).StartsWith("authority.db", StringComparison.Ordinal) || Path.GetFileName(name).StartsWith("audit-outbox.db", StringComparison.Ordinal)))
            {
                using FileStream stream = new(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using MemoryStream copy = new();
                stream.CopyTo(copy);
                everything.Append(Encoding.UTF8.GetString(copy.ToArray()));
            }

            string text = everything.ToString();
            check(text.Contains("authorization", StringComparison.Ordinal) && text.Contains("[REDACTED]", StringComparison.Ordinal), "redaction: the database files were read (the events are in them)");
            check(!text.Contains(Value, StringComparison.Ordinal) && !text.Contains(Other, StringComparison.Ordinal) && canaries.All(canary => !text.Contains(canary, StringComparison.Ordinal)), "redaction: no secret value, no argument canary and no environment value is in authority.db or audit-outbox.db (and their logs)");
            check(!run.Stdout.Contains(Value, StringComparison.Ordinal) && !(run.Stdout + run.Stderr).Contains("EnvCanary-555", StringComparison.Ordinal), "redaction: the secret value is not in what the run printed either");
        }

        // Concurrent runs: gapless numbers.
        {
            GrantAuthorityTests.Chooser chooser = new(0);
            using HostServiceTests.Rig rig = new(parent, approver: () => chooser, auditInterval: Fast);
            string program = GrantAuthorityTests.Show(rig);
            HostServiceTests.Raw[] runs = await Task.WhenAll(Enumerable.Range(0, 4).Select(index => HostServiceTests.Post(rig, HostServiceTests.Req(rig, program, [index.ToString()]))));
            await HostServiceTests.WaitFor(() => Events(rig).Count == 12 && rig.Service.Audit.Outbox.Count("pending") == 0);
            check(runs.All(run => run.Result is { Outcome: LaunchOutcome.Exited }) && Events(rig).Select(item => item.Sequence).SequenceEqual(Enumerable.Range(1, 12).Select(i => (long)i)) && rig.Machine.Deployment.Store.AuditGaps().Count == 0, "concurrency: four runs at once produce the numbers 1 to 12, once each, and the authority sees no gap");
        }

        // The authority cannot be reached: runs go on, events wait, and a restart delivers them.
        {
            using TestMachine machine = new(Path.Combine(parent, "rs-" + Guid.NewGuid().ToString("N")[..6]));
            FlakySink sink = new(machine.Deployment.Authority) { Offline = true };
            machine.Deployment.AuditSink = sink;
            using (HostServiceTests.Rig rig = new(parent, approver: () => new FakeApprover(true), machine: machine, auditInterval: Fast))
            {
                string program = GrantAuthorityTests.Show(rig);
                HostServiceTests.Raw one = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
                HostServiceTests.Raw two = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
                check(one.Result is { Outcome: LaunchOutcome.Exited } && two.Result is { Outcome: LaunchOutcome.Exited } && rig.Service.Audit.Outbox.Count("pending") == 6 && machine.Deployment.Store.AuditHistory(new AuditQuery()).Count == 0, "unreachable authority: runs are not held up; six events wait in the outbox");
                check(await HostServiceTests.WaitFor(() => sink.Calls >= 3, 10), "unreachable authority: the uploader keeps retrying while it is down (" + sink.Calls + " tries)");
            }

            machine.Restart();
            using HostServiceTests.Rig second = new(parent, approver: () => new FakeApprover(true), machine: machine, auditInterval: Fast);
            check(await HostServiceTests.WaitFor(() => machine.Deployment.Store.AuditHistory(new AuditQuery()).Count == 6 && second.Service.Audit.Outbox.Count("pending") == 0), "restart: a new service delivers the events the old one left, and the outbox empties");
            HostServiceTests.Raw three = await HostServiceTests.Post(second, HostServiceTests.Req(second, GrantAuthorityTests.Show(second)));
            await HostServiceTests.WaitFor(() => machine.Deployment.Store.AuditHistory(new AuditQuery()).Count == 9);
            check(three.Result is { Outcome: LaunchOutcome.Exited } && Events(second).Select(item => item.Sequence).SequenceEqual(Enumerable.Range(1, 9).Select(i => (long)i)) && machine.Deployment.Store.AuditGaps().Count == 0, "restart: numbering goes on across the restart (1 to 9), no gap");
        }

        // A lost event shows up as a gap at the authority.
        {
            using TestMachine machine = new(Path.Combine(parent, "lost-" + Guid.NewGuid().ToString("N")[..6]));
            FlakySink sink = new(machine.Deployment.Authority) { Offline = true };
            machine.Deployment.AuditSink = sink;
            using HostServiceTests.Rig rig = new(parent, approver: () => new FakeApprover(true), machine: machine, auditInterval: Fast);
            string program = GrantAuthorityTests.Show(rig);
            await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program));
            Sql(rig.Service.Audit.Outbox.FilePath, "DELETE FROM events WHERE sequence = 3");
            sink.Offline = false;
            rig.Service.Audit.Wake();
            check(await HostServiceTests.WaitFor(() => machine.Deployment.Store.AuditHistory(new AuditQuery()).Count == 5 && rig.Service.Audit.Outbox.Count("pending") == 0), "sequence gap: the remaining events are delivered and acknowledged");
            check(machine.Deployment.Store.AuditGaps() is [{ Kind: "missing", From: 3, To: 3 }], "sequence gap: the authority recorded the lost event 3 as a gap (it did not reject anything)");
        }

        // An acknowledgement the host cannot verify keeps the events; the genuine one removes them.
        {
            using TestMachine machine = new(Path.Combine(parent, "ack-" + Guid.NewGuid().ToString("N")[..6]));
            FlakySink sink = new(machine.Deployment.Authority);
            using SoftwareSigningKey rogue = new();
            sink.Tamper = (batch, ack) => AuditAck.Create(batch, ack.Entries, ack.Issued, TimeSpan.FromSeconds(60), rogue);
            machine.Deployment.AuditSink = sink;
            using HostServiceTests.Rig rig = new(parent, approver: () => new FakeApprover(true), machine: machine, auditInterval: Fast);
            await HostServiceTests.Post(rig, HostServiceTests.Req(rig, GrantAuthorityTests.Show(rig)));
            check(await HostServiceTests.WaitFor(() => sink.Calls >= 2, 10) && rig.Service.Audit.Outbox.Count("pending") == 3, "service acknowledgement: an answer signed by another key than the pinned authority key is not believed: the events stay in the outbox");
            sink.Tamper = null;
            check(await HostServiceTests.WaitFor(() => rig.Service.Audit.Outbox.Count("pending") == 0 && machine.Deployment.Store.AuditHistory(new AuditQuery()).Count == 3), "service acknowledgement: with a genuine answer they are removed, and the authority has each exactly once");
        }

        // An authority that never answers does not hold up a run.
        {
            using TestMachine machine = new(Path.Combine(parent, "hang-" + Guid.NewGuid().ToString("N")[..6]));
            machine.Deployment.AuditSink = new FlakySink(machine.Deployment.Authority) { Hang = true };
            using HostServiceTests.Rig rig = new(parent, approver: () => new FakeApprover(true), machine: machine, auditInterval: Fast);
            System.Diagnostics.Stopwatch watch = System.Diagnostics.Stopwatch.StartNew();
            HostServiceTests.Raw run = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, GrantAuthorityTests.Show(rig)));
            check(run.Result is { Outcome: LaunchOutcome.Exited } && rig.Service.Audit.Outbox.Count("pending") == 3 && watch.Elapsed < TimeSpan.FromSeconds(20), "never blocks: a run completes while the audit upload hangs (" + watch.ElapsedMilliseconds + " ms)");
        }
    }

    // ---- review fixes (M1, M2, L1 to L7) ----

    private static string EpochOf(HostAuditOutbox outbox) => (string)Scalar(outbox.FilePath, "SELECT epoch FROM counter")!;

    private static async Task Review(Action<bool, string> check, string parent)
    {
        // M1: the host cuts what the authority would refuse, so a run's events always reach it.
        {
            TestClock clock = new();
            using TestMachine machine = new(Path.Combine(parent, "m1-" + Guid.NewGuid().ToString("N")[..6]), true, clock: clock);
            HostAuditOutbox outbox = HostAuditOutbox.InFolder(machine.Folder, machine.MachineKey, clock);
            string deep = "/" + string.Join("/", Enumerable.Repeat("directory", 700));
            AuditEvent a = outbox.Append(Facts(folder: deep, program: deep + "/" + new string('p', 12000) + ".sh"));
            AuditEvent b = outbox.Append(Facts(AuditEventTypes.Launch, "started", "", folder: deep, program: new string('p', 16000)));
            AuditEvent emoji = outbox.Append(Facts(folder: string.Concat(Enumerable.Repeat("\U0001F600", 3000)), program: "/work/x.sh"));
            AuditEvent many = outbox.Append(Facts(reason: new string('r', 900), arguments: [.. Enumerable.Range(0, 400).Select(index => new string('a', 6000))]));
            check(new[] { a, b, emoji, many }.All(item => item.Problem() is null && item.Verify(machine.MachineKey.PublicKey)) && a.Folder.Length <= AuditEvent.MaxText && a.Program.Length <= AuditEvent.MaxText && b.Program.Length <= AuditEvent.MaxText, "long folder or program: the signed event is cut to what the authority accepts (4096 characters), and still verifies");
            check(a.Folder.EndsWith("characters omitted]", StringComparison.Ordinal) && a.Folder.StartsWith("/directory/directory", StringComparison.Ordinal) && Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(emoji.Folder)) == emoji.Folder && many.Arguments.Count == AuditEvent.MaxArguments && many.Arguments.All(argument => argument.Length <= AuditEvent.MaxText) && many.Reason.Length <= 200 && many.Reason.EndsWith("characters omitted]", StringComparison.Ordinal), "long folder or program: a cut says how much is gone, never splits a character, and the arguments and reason are bounded too");
            AuditAck ack = await machine.Deployment.Authority.UploadAsync(Batch(machine, a, b, emoji, many));
            check(ack.Entries.All(entry => entry.Status == AuditStatus.Accepted) && machine.Deployment.Store.AuditHistory(new AuditQuery()).Count == 4 && machine.Deployment.Store.AuditGaps().Count == 0, "long folder or program: the authority accepts all of them (nothing is rejected, no gap)");
            long before = outbox.LastSequence();
            check(Catch<AuditOutboxException>(() => outbox.Append(Facts(outcome: ""))) is { } invalid && invalid.Message.Contains("not valid", StringComparison.Ordinal) && outbox.LastSequence() == before, "long folder or program: an event that is still invalid is never signed (the append fails closed and uses no number)");
        }

        // M2: a recreated outbox is a new epoch, and its numbers cannot close a hole the old one left.
        {
            TestClock clock = new();
            using TestMachine machine = new(Path.Combine(parent, "m2-" + Guid.NewGuid().ToString("N")[..6]), true, clock: clock);
            AuthorityStore store = machine.Deployment.Store;
            HostAuditOutbox first = HostAuditOutbox.InFolder(machine.Folder, machine.MachineKey, clock);
            AuditEvent e1 = first.Append(Facts());
            string epoch1 = EpochOf(first);
            first.Append(Facts());
            AuditEvent lateOne = AuditEvent.Create(Facts(), Guid.NewGuid().ToString("D"), 6, clock.GetUtcNow(), machine.MachineKey, epoch1);
            await machine.Deployment.Authority.UploadAsync(Batch(machine, [.. first.Pending(10), lateOne]));
            check(e1.Epoch == epoch1 && store.AuditGaps() is [{ Kind: "missing", From: 3, To: 5 } hole] && hole.Epoch == epoch1, "epoch: every event carries its outbox's epoch; the authority tracks 3 to 5 as missing in that epoch");

            foreach (string leftover in Directory.GetFiles(machine.Folder, HostAuditOutbox.FileName + "*"))
            {
                File.Delete(leftover);
            }

            HostAuditOutbox second = HostAuditOutbox.InFolder(machine.Folder, machine.MachineKey, clock);
            for (int index = 0; index < 6; index++)
            {
                second.Append(Facts());
            }

            string epoch2 = EpochOf(second);
            await machine.Deployment.Authority.UploadAsync(Batch(machine, [.. second.Pending(10)]));
            IReadOnlyList<AuditGap> gaps = store.AuditGaps();
            check(epoch2 != epoch1 && gaps.Any(gap => gap.Kind == "missing" && gap.From == 3 && gap.To == 5 && gap.Epoch == epoch1 && gap.Resolved is null), "epoch: the new outbox's numbers 3 to 5 do not close the hole its predecessor left");
            check(gaps.Any(gap => gap.Kind == "epoch" && gap.Epoch == epoch2 && gap.From == 1) && !gaps.Any(gap => gap.Kind == "reused"), "epoch: the new epoch is recorded as its own gap kind, and its numbers 1 to 6 are not reuse");
            AuditEvent again = AuditEvent.Create(Facts(), Guid.NewGuid().ToString("D"), 2, clock.GetUtcNow(), machine.MachineKey, epoch2);
            await machine.Deployment.Authority.UploadAsync(Batch(machine, again));
            check(store.AuditGaps().Any(gap => gap.Kind == "reused" && gap.From == 2 && gap.Epoch == epoch2) && store.AuditHistory(new AuditQuery()).Count == 10, "epoch: a number used twice within one epoch is still recorded as reused");
            HostAuditOutbox reopened = HostAuditOutbox.InFolder(machine.Folder, machine.MachineKey, clock);
            check(EpochOf(reopened) == epoch2 && reopened.Append(Facts()).Epoch == epoch2, "epoch: it is kept across a restart of the same outbox");
            check(e1 with { Epoch = "" } is { } noEpoch && noEpoch.Problem() is not null && !AuditEvent.TryParse(e1.ToJson().Replace("\"epoch\":\"" + epoch1 + "\",", "", StringComparison.Ordinal), out _, out _), "epoch: an event without one is refused");
            check(!(e1 with { Epoch = "other" }).Verify(machine.MachineKey.PublicKey), "epoch: changing the epoch breaks the signature (it is part of what is signed)");
        }

        // L1: the upload loop survives anything.
        {
            using TestMachine machine = new(Path.Combine(parent, "l1-" + Guid.NewGuid().ToString("N")[..6]));
            HostAuditOutbox outbox = HostAuditOutbox.InFolder(machine.Folder, machine.MachineKey);
            AuditUploader uploader = new(outbox, () => machine.Deployment.AuditSink, Verifier(AuthorityKey(machine)), machine.Fingerprint);
            outbox.Append(Facts());
            int throws = 0;
            outbox.Fault = point =>
            {
                if (point == "pending" && Interlocked.Increment(ref throws) <= 3)
                {
                    throw new InvalidOperationException("an unexpected error while reading a row (test)");
                }
            };
            AuditUploadResult broken = await uploader.DrainAsync();
            check(broken.Failed && outbox.Count("pending") == 1, "upload loop: an unexpected error reading the outbox is a failed drain, not an exception");
            HostAudit audit = new(outbox, uploader);
            using CancellationTokenSource stop = new();
            Task loop = audit.RunAsync(Fast, TimeSpan.FromMilliseconds(160), stop.Token);
            check(await HostServiceTests.WaitFor(() => outbox.Count("pending") == 0 && machine.Deployment.Store.AuditHistory(new AuditQuery()).Count == 1, 10) && !loop.IsCompleted, "upload loop: it kept going through the errors and delivered the event (the loop is still running)");
            stop.Cancel();
            check(await Task.WhenAny(loop, Task.Delay(5000)) == loop && loop.Status == TaskStatus.RanToCompletion, "upload loop: it still ends cleanly when the service stops");
        }

        // L2: an event dropped as expired leaves a trace at the authority.
        {
            TestClock clock = new();
            using TestMachine machine = new(Path.Combine(parent, "l2-" + Guid.NewGuid().ToString("N")[..6]), true, clock: clock);
            AuthorityStore store = machine.Deployment.Store;
            HostAuditOutbox outbox = HostAuditOutbox.InFolder(machine.Folder, machine.MachineKey, clock);
            store.SetAuditRetentionDays(30, RetentionAdmin(30));
            AuditEvent stale = outbox.Append(Facts());
            AuditEvent stale2 = outbox.Append(Facts());
            clock.Advance(TimeSpan.FromDays(40));
            AuditAck ack = await machine.Deployment.Authority.UploadAsync(Batch(machine, stale, stale2));
            check(ack.Entries.All(entry => entry.Status == AuditStatus.Expired) && store.AuditHistory(new AuditQuery()).Count == 0 && store.Audit().Any(entry => entry.Event == "audit-events-expired" && entry.Detail.Contains("2 event(s)", StringComparison.Ordinal) && entry.Detail.Contains("sequence 1 to 2", StringComparison.Ordinal)), "expired: events acknowledged without being stored are counted in the authority's own history (a machine with a wrong clock shows)");
        }

        // L3: approve fails closed.
        using (TestAuthenticator signer = TestAuthenticator.ES256())
        {
            GrantAuthorityTests.Chooser chooser = new(60, signer: signer);
            using HostServiceTests.Rig rig = new(parent, approver: () => chooser, enrolled: signer, auditInterval: Fast);
            string program = GrantAuthorityTests.Show(rig);
            rig.Service.Audit.Outbox.Fault = point => throw new IOException("the disk is full (test)");
            HostServiceTests.Raw blocked = await HostServiceTests.Post(rig, HostServiceTests.Req(rig, program), path: "/v1/approve");
            rig.Service.Audit.Outbox.Fault = null;
            check(blocked.Result is { Outcome: LaunchOutcome.Failed, ExitCode: RunCommand.AuditError } && chooser.Requests.Count == 0 && rig.Machine.Deployment.Store.Grants().Count == 0 && rig.Store.Reads == 0, "approve: if the request for a grant cannot be committed there is no tap, no grant and nothing is decrypted (exit 5)");
        }

        // L4: a refusal that can pass is retried; a final one is parked.
        {
            using TestMachine machine = new(Path.Combine(parent, "l4-" + Guid.NewGuid().ToString("N")[..6]));
            HostAuditOutbox outbox = HostAuditOutbox.InFolder(machine.Folder, machine.MachineKey);
            FlakySink sink = new(machine.Deployment.Authority);
            AuditUploader uploader = new(outbox, () => sink, Verifier(AuthorityKey(machine)), machine.Fingerprint);
            AuditEvent held = outbox.Append(Facts());
            foreach ((string status, string detail) in new[] { (AuditStatus.Rejected, AuditStatus.UnknownMachine), (AuditStatus.Rejected, AuditStatus.MachinePending), ("some-future-status", "") })
            {
                sink.Tamper = (batch, ack) => AuditAck.Create(batch, [new AuditAckEntry(held.EventId, status, detail)], ack.Issued, TimeSpan.FromSeconds(60), machine.Deployment.Keys.Current());
                AuditUploadResult result = await uploader.DrainAsync();
                check(result.Failed && result.Rejected == 0 && outbox.Count("pending") == 1 && outbox.Count("rejected") == 0, "retryable refusal: '" + status + " " + detail + "' leaves the event pending to be tried again");
            }

            sink.Tamper = null;
            check((await uploader.DrainAsync()).Acknowledged == 1 && outbox.Count("pending") == 0 && machine.Deployment.Store.AuditHistory(new AuditQuery()).Count == 1, "retryable refusal: when the authority takes it the event is delivered");
            AuditEvent bad = outbox.Append(Facts());
            sink.Tamper = (batch, ack) => AuditAck.Create(batch, [new AuditAckEntry(bad.EventId, AuditStatus.Rejected, "event-id-reused")], ack.Issued, TimeSpan.FromSeconds(60), machine.Deployment.Keys.Current());
            AuditUploadResult parked = await uploader.DrainAsync();
            check(parked.Rejected == 1 && outbox.Count("rejected") == 1 && outbox.Count("pending") == 0, "final refusal: an event the authority can never use is still parked");
        }

        // L5: more forms of secret in the arguments.
        {
            string[] redacted = [.. AuditRedaction.Arguments(["{\"password\":\"JsonCanary1\",\"name\":\"x\"}", "--data", "{\"api_key\": \"JsonCanary2\", \"token\":\"JsonCanary3\"}", "-u", "bob:CurlCanary4", "--user=amy:CurlCanary5", "--proxy-user", "p:CurlCanary6", "-pMysqlCanary7", "--password=EqCanary8", "-u", "1000", "-pthread", "-p", "8080", "--port=80"])];
            string all = string.Join("\n", redacted);
            check(!all.Contains("Canary", StringComparison.Ordinal), "redaction forms: JSON bodies, curl -u/--user/--proxy-user NAME:PASSWORD, mysql -pSECRET and --password=VALUE are all masked (" + string.Join(" | ", redacted) + ")");
            check(redacted[0].Contains("\"password\"", StringComparison.Ordinal) && redacted[0].Contains("\"name\":\"x\"", StringComparison.Ordinal) && redacted[4] == "bob:[REDACTED]" && redacted[5] == "--user=amy:[REDACTED]" && redacted[9] == "--password=[REDACTED]", "redaction forms: the name stays, only the value goes");
            check(redacted[11] == "1000" && redacted[12] == "-pthread" && redacted[13] == "-p" && redacted[14] == "8080" && redacted[15] == "--port=80", "redaction forms: a user id, a compiler flag, a port and ordinary flags are left alone");
        }

        // L6 and L7 at the authority.
        {
            TestClock clock = new();
            using TestMachine machine = new(Path.Combine(parent, "l6-" + Guid.NewGuid().ToString("N")[..6]), true, clock: clock);
            AuthorityStore store = machine.Deployment.Store;
            HostAuditOutbox outbox = HostAuditOutbox.InFolder(machine.Folder, machine.MachineKey, clock);
            AuditEvent hard = outbox.Append(Facts(program: "C:\\proj\\build.exe", arguments: ["C:\\proj\\data\\x.txt", "say \"hello there\"", "caf\u00e9 \u00fcber", "plain 100%"]));
            await machine.Deployment.Authority.UploadAsync(Batch(machine, hard));
            int Count(string text) => store.AuditHistory(new AuditQuery(Text: text)).Count;
            check(Count("C:\\proj\\data") == 1 && Count("say \"hello") == 1 && Count("caf\u00e9") == 1 && Count("\u00fcber") == 1 && Count("100%") == 1 && Count("C:\\proj\\build.exe") == 1 && Count("C:\\other") == 0, "text search: backslashes, quotes and non-ASCII letters in the arguments are found");

            // The same event id from another machine is not this machine's problem.
            string otherEvent = Guid.NewGuid().ToString("D");
            Sql(store.FilePath, "INSERT INTO audit_events (fingerprint, event_id, epoch, sequence, time, type, outcome, reason, request_id, folder, program, arguments, grant_id, exit_code, event_json, received, acknowledged) VALUES ('OTHERMACHINE', '" + otherEvent + "', 'e', 1, '2026-01-01T00:00:00.0000000Z', 'authorization', 'approved', '', '', '', '', '[]', '', NULL, '{}', '2026-01-01T00:00:00.0000000Z', '2026-01-01T00:00:00.0000000Z')");
            AuditEvent same = AuditEvent.Create(Facts(), otherEvent, 2, clock.GetUtcNow(), machine.MachineKey, EpochOf(outbox));
            AuditAck ack = await machine.Deployment.Authority.UploadAsync(Batch(machine, same));
            check(ack.Entries[0].Status == AuditStatus.Accepted && (await machine.Deployment.Authority.UploadAsync(Batch(machine, same))).Entries[0].Status == AuditStatus.Duplicate, "duplicate check: an event id another machine already used does not block this machine's event, and its own repeat is a duplicate");
            AuditEvent clash = AuditEvent.Create(Facts(outcome: "different"), otherEvent, 9, clock.GetUtcNow(), machine.MachineKey, EpochOf(outbox));
            check((await machine.Deployment.Authority.UploadAsync(Batch(machine, clash))).Entries[0].Detail == "event-id-reused", "duplicate check: the same id with other content from the same machine is still refused");
        }

        // Migration from the first cut (schema 4).
        {
            using TestMachine machine = new(Path.Combine(parent, "mg-" + Guid.NewGuid().ToString("N")[..6]));
            string file = machine.Deployment.Store.FilePath;
            Sql(file, "DROP TABLE audit_events; DROP TABLE audit_machine_state; DROP TABLE audit_gaps; CREATE TABLE audit_events (event_id TEXT PRIMARY KEY NOT NULL, fingerprint TEXT NOT NULL); CREATE TABLE audit_machine_state (fingerprint TEXT PRIMARY KEY NOT NULL, highest INTEGER NOT NULL, updated TEXT NOT NULL); CREATE TABLE audit_gaps (id INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL); UPDATE schema_version SET version = 4;");
            AuthorityStore migrated = AuthorityStore.InFolder(machine.Folder);
            check(migrated.AuditHistory(new AuditQuery()).Count == 0 && Convert.ToInt32(Scalar(file, "SELECT version FROM schema_version")) == 5 && migrated.Machines().Count == 1 && Convert.ToInt32(Scalar(file, "SELECT COUNT(*) FROM pragma_table_info('audit_machine_state') WHERE name = 'epoch'")) == 1, "schema: a version 4 authority.db is migrated to 5 (the audit tables of the first cut are replaced, machines are kept)");
        }
    }
}

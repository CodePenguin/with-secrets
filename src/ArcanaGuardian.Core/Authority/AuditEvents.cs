using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ArcanaGuardian;

/// <summary>The kinds of fact the audit records: three for a run (each is its own event: a decision is not an outcome, and a started program is not a finished one) and the administrative events.</summary>
public sealed record AuditKeys(VerifiedCredential? Key = null, VerifiedCredential? SessionKey = null, VerifiedCredential? GrantApproved = null,
    VerifiedCredential? GrantChanged = null, VerifiedCredential? Unlock = null)
{
    internal string Wire() => System.Text.Json.JsonSerializer.Serialize(this);

    internal static bool TryRead(string? text, out AuditKeys? keys)
    {
        keys = null;
        if (text is null || text.Length > 32000)
        {
            return false;
        }

        try
        {
            keys = System.Text.Json.JsonSerializer.Deserialize<AuditKeys>(text);
            return true;
        }
        catch (System.Text.Json.JsonException)
        {
            return false;
        }
    }

    internal Dictionary<string, string> Metadata(Dictionary<string, string>? metadata = null)
    {
        metadata ??= new(StringComparer.Ordinal);
        Key?.AddTo(metadata, "key");
        SessionKey?.AddTo(metadata, "sessionKey");
        GrantApproved?.AddTo(metadata, "grantApproved");
        if (GrantChanged is { } changed && changed.Id != GrantApproved?.Id)
        {
            changed.AddTo(metadata, "grantChanged");
        }

        Unlock?.AddTo(metadata, "unlock");

        return metadata;
    }
}

public static class AuditEventTypes
{
    /// <summary>Whether the run may use secrets: the person's approval, a grant, or a denial (with its code).</summary>
    public const string Authorization = "authorization";

    /// <summary>What happened when the launch was attempted: started, or why not.</summary>
    public const string Launch = "launch";

    /// <summary>How the program ended: its exit code, or an internal failure after it started.</summary>
    public const string Execution = "execution";

    /// <summary>An administrative event: a change to the secret store, to the passkeys or the settings, or a change that was refused. The outcome is the event name; the arguments are names only (see <see cref="AdminEvent" />).</summary>
    public const string Admin = "admin";

    public static readonly IReadOnlyList<string> All = [Authorization, Launch, Execution, Admin];
}

/// <summary>
/// The optional metadata of an event: a small JSON object of text values (names and fingerprints: secret names, an approving key name, reuse minutes, variable mapping,
/// .env file paths and file fingerprints; never a value, a code, a key or PRF output). It is part of the signed canonical text (members sorted by name) and is left out of it when empty,
/// so an event without metadata has exactly the text it always had. The limits are built in: <see cref="MaxMembers" /> members, names of letters, digits, dot, dash and underscore,
/// <see cref="MaxValue" /> characters per value, <see cref="MaxBytes" /> bytes of UTF-8 in all, and valid Unicode only.
/// </summary>
public static class AuditMetadata
{
    public const int MaxMembers = 24;
    public const int MaxName = 32;
    public const int MaxValue = 2048;
    public const int MaxBytes = 8192;

    public static readonly IReadOnlyDictionary<string, string> None = new Dictionary<string, string>(StringComparer.Ordinal);

    private static bool ValidName(string name) => name.Length is > 0 and <= MaxName && char.IsAsciiLetter(name[0]) && name.All(letter => char.IsAsciiLetterOrDigit(letter) || letter is '.' or '-' or '_');

    private static bool ValidText(string text)
    {
        try
        {
            _ = new UTF8Encoding(false, true).GetBytes(text);

            return true;
        }
        catch (EncoderFallbackException)
        {
            return false;
        }
    }

    /// <summary>The canonical JSON object (members sorted by name, no white space).</summary>
    public static string Canonical(IReadOnlyDictionary<string, string> metadata)
    {
        StringBuilder text = new();
        CanonicalJson.Map(text, metadata);

        return text.ToString();
    }

    /// <summary>Null when the metadata is within the limits, else what is wrong (naming the limit, never a value).</summary>
    public static string? Problem(IReadOnlyDictionary<string, string> metadata)
    {
        if (metadata.Count > MaxMembers)
        {
            return "too many metadata members";
        }

        foreach ((string name, string value) in metadata)
        {
            if (!ValidName(name))
            {
                return "a metadata name is not 1 to 32 letters, digits, dots, dashes or underscores starting with a letter";
            }

            if (value.Length > MaxValue)
            {
                return "a metadata value is too long";
            }

            if (!ValidText(name) || !ValidText(value))
            {
                return "metadata is not valid UTF-8 text";
            }
        }

        return Encoding.UTF8.GetByteCount(Canonical(metadata)) > MaxBytes ? "the metadata is too large" : null;
    }

    /// <summary>The metadata cut to the limits, so that no event this host signs can be refused for it: a member with an invalid name is dropped, a long value is cut, invalid Unicode is removed, and members past the size are left out.</summary>
    public static IReadOnlyDictionary<string, string> Bound(IReadOnlyDictionary<string, string>? metadata)
    {
        if (metadata is null || metadata.Count == 0)
        {
            return None;
        }

        SortedDictionary<string, string> result = new(StringComparer.Ordinal);
        foreach ((string name, string value) in metadata.OrderBy(entry => entry.Key, StringComparer.Ordinal))
        {
            if (!ValidName(name) || result.Count >= MaxMembers)
            {
                continue;
            }

            string clean = AuditRedaction.Cut(ApprovalSummary.Clean(value), MaxValue);
            result[name] = ValidText(clean) ? clean : new string([.. clean.Where(letter => !char.IsSurrogate(letter))]);
        }

        while (result.Count > 0 && Encoding.UTF8.GetByteCount(Canonical(result)) > MaxBytes)
        {
            result.Remove(result.Keys.Last());
        }

        return result;
    }
}

/// <summary>
/// What the host knows when it records an event, before it is numbered and signed. <see cref="Outcome" /> and <see cref="Reason" /> are words and codes, never
/// free text from a person, a program or the store. <see cref="Arguments" /> must already be redacted (<see cref="AuditRedaction" />). No OS user, no secret
/// value and no environment value belongs here.
/// </summary>
public sealed record AuditFacts(string Type, string Outcome, string Reason, string RequestId, string Folder, string Program, IReadOnlyList<string> Arguments, string GrantId = "", int? ExitCode = null, IReadOnlyDictionary<string, string>? Metadata = null);

/// <summary>
/// One signed audit event. The host numbers it (a per-machine sequence, monotonic and gapless) and signs it with the machine identity key before it is committed to
/// the outbox; the authority verifies that signature, deduplicates by <see cref="EventId" /> and watches the sequence. The signed text is
/// <c>"arcana-guardian audit event v1" LF</c> followed by <see cref="Canonical" /> (fixed member order, no white space), the same signature format as the other machine messages
/// (ECDSA P-256 over SHA-256, r||s). There is no hash chain: integrity comes from the signature, the unique id, the sequence and the authority's acknowledgement.
/// </summary>
public sealed record AuditEvent(
    int ProtocolVersion,
    string EventId,
    long Sequence,
    DateTimeOffset Time,
    string MachineFingerprint,
    string Epoch,
    string Type,
    string Outcome,
    string Reason,
    string RequestId,
    string Folder,
    string Program,
    IReadOnlyList<string> Arguments,
    string GrantId,
    int? ExitCode,
    byte[] Signature,
    IReadOnlyDictionary<string, string>? Metadata = null)
{
    public const string Domain = "arcana-guardian audit event v1\n";

    public const int MaxText = 4096;
    public const int MaxArguments = 256;

    public string Canonical()
    {
        StringBuilder text = new();
        Body(text);

        return text.Append('}').ToString();
    }

    private void Body(StringBuilder text)
    {
        text.Append("{\"protocolVersion\":").Append(ProtocolVersion.ToString(CultureInfo.InvariantCulture)).Append(",\"eventId\":");
        ToolSettings.QuoteJson(text, EventId);
        text.Append(",\"sequence\":").Append(Sequence.ToString(CultureInfo.InvariantCulture)).Append(",\"time\":");
        ToolSettings.QuoteJson(text, CanonicalJson.Time(Time));
        text.Append(",\"machineFingerprint\":");
        ToolSettings.QuoteJson(text, MachineFingerprint);
        text.Append(",\"epoch\":");
        ToolSettings.QuoteJson(text, Epoch);
        text.Append(",\"type\":");
        ToolSettings.QuoteJson(text, Type);
        text.Append(",\"outcome\":");
        ToolSettings.QuoteJson(text, Outcome);
        text.Append(",\"reason\":");
        ToolSettings.QuoteJson(text, Reason);
        text.Append(",\"requestId\":");
        ToolSettings.QuoteJson(text, RequestId);
        text.Append(",\"folder\":");
        ToolSettings.QuoteJson(text, Folder);
        text.Append(",\"program\":");
        ToolSettings.QuoteJson(text, Program);
        text.Append(",\"arguments\":");
        CanonicalJson.Strings(text, Arguments);
        text.Append(",\"grantId\":");
        ToolSettings.QuoteJson(text, GrantId);
        text.Append(",\"exitCode\":").Append(ExitCode is { } code ? code.ToString(CultureInfo.InvariantCulture) : "null");
        if (Metadata is { Count: > 0 })
        {
            text.Append(",\"metadata\":");
            CanonicalJson.Map(text, Metadata);
        }
    }

    /// <summary>The metadata of the event (empty when it has none).</summary>
    public IReadOnlyDictionary<string, string> Meta => Metadata ?? AuditMetadata.None;

    /// <summary>The event with its signature (base64) as the last member: as stored in the outbox and at the authority.</summary>
    public string ToJson()
    {
        StringBuilder text = new();
        Body(text);
        text.Append(",\"signature\":");
        ToolSettings.QuoteJson(text, Convert.ToBase64String(Signature));

        return text.Append('}').ToString();
    }

    internal static byte[] SigningBytes(string canonical) => WireText.Bytes(Domain, canonical);

    public static AuditEvent Create(AuditFacts facts, string eventId, long sequence, DateTimeOffset time, ISigningKey machineKey, string epoch = "default")
    {
        AuditEvent unsigned = new(1, eventId, sequence, time, KeyIdentity.Fingerprint(machineKey.PublicKey), epoch, facts.Type, facts.Outcome, facts.Reason, facts.RequestId, facts.Folder, facts.Program, [.. facts.Arguments], facts.GrantId, facts.ExitCode, [], AuditMetadata.Bound(facts.Metadata) is { Count: > 0 } meta ? meta : null);

        return unsigned with { Signature = machineKey.Sign(SigningBytes(unsigned.Canonical())) };
    }

    /// <summary>True when the machine key signed exactly these fields and the fingerprint is that key's.</summary>
    public bool Verify(byte[] machinePublicKey)
    {
        return string.Equals(MachineFingerprint, KeyIdentity.Fingerprint(machinePublicKey), StringComparison.Ordinal)
            && KeyIdentity.Verify(machinePublicKey, SigningBytes(Canonical()), Signature);
    }

    /// <summary>Null when the event has the shape the authority accepts (sizes, known type, version), else the first thing wrong (naming a field, never a value).</summary>
    public string? Problem()
    {
        if (ProtocolVersion != 1)
        {
            return "another protocol version";
        }

        if (EventId.Length is 0 or > 64 || !EventId.All(letter => char.IsAsciiLetterOrDigit(letter) || letter == '-'))
        {
            return "the event id is not 1 to 64 letters, digits or dashes";
        }

        if (Epoch.Length is 0 or > 64 || !Epoch.All(letter => char.IsAsciiLetterOrDigit(letter) || letter == '-'))
        {
            return "the epoch is not 1 to 64 letters, digits or dashes";
        }

        if (Sequence < 1)
        {
            return "the sequence number starts at 1";
        }

        if (!AuditEventTypes.All.Contains(Type))
        {
            return "unknown event type";
        }

        if (Outcome.Length is 0 or > 64 || Reason.Length > 200 || RequestId.Length > 128 || GrantId.Length > 128 || Folder.Length > MaxText || Program.Length > MaxText)
        {
            return "a field is empty or too long";
        }

        if (Arguments.Count > MaxArguments || Arguments.Any(argument => argument.Length > MaxText))
        {
            return "too many arguments, or one is too long";
        }

        return AuditMetadata.Problem(Meta);
    }

    /// <summary>Reads a stored event, strictly (every member, none unknown or repeated, each of its type).</summary>
    public static bool TryParse(string json, out AuditEvent? parsed, out string? error)
    {
        parsed = null;
        if (!CanonicalJson.Open(json, out JsonDocument? doc, out error))
        {
            return false;
        }

        using (doc)
        {
            // The metadata member is optional: an event without it has the text it always had.
            bool hasMetadata = doc!.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.TryGetProperty("metadata", out _);
            string[] names = ["protocolVersion", "eventId", "sequence", "time", "machineFingerprint", "epoch", "type", "outcome", "reason", "requestId", "folder", "program", "arguments", "grantId", "exitCode", "signature", .. hasMetadata ? new[] { "metadata" } : []];
            ContractReader reader = new(doc.RootElement, names);
            if (reader.Problem is not null || !reader.Int("protocolVersion", out int version) || !reader.Text("eventId", out string? id) || !reader.Long("sequence", out long sequence)
                || !reader.Time("time", out DateTimeOffset time) || !reader.Text("machineFingerprint", out string? machine) || !reader.Text("epoch", out string? epoch) || !reader.Text("type", out string? type) || !reader.Text("outcome", out string? outcome)
                || !reader.Text("reason", out string? reason) || !reader.Text("requestId", out string? requestId) || !reader.Text("folder", out string? folder) || !reader.Text("program", out string? program)
                || !reader.Strings("arguments", out List<string>? arguments) || !reader.Text("grantId", out string? grantId) || !reader.OptionalInt("exitCode", out int? exitCode) || !reader.Text("signature", out string? signature))
            {
                error = reader.Problem;

                return false;
            }

            Dictionary<string, string>? metadata = null;
            if (hasMetadata && !reader.Map("metadata", out metadata))
            {
                error = reader.Problem;

                return false;
            }

            byte[] bytes = new byte[64];
            if (!Convert.TryFromBase64String(signature!, bytes, out int written) || written != 64)
            {
                error = "the signature is not 64 bytes of base64";

                return false;
            }

            error = null;
            parsed = new AuditEvent(version, id!, sequence, time, machine!, epoch!, type!, outcome!, reason!, requestId!, folder!, program!, arguments!, grantId!, exitCode, bytes, metadata is { Count: > 0 } ? metadata : null);

            return true;
        }
    }
}

/// <summary>Events the host sends in one upload: its fingerprint and the events (oldest first). The batch itself is not signed; every event is.</summary>
public sealed record AuditBatch(string BatchId, string MachineFingerprint, IReadOnlyList<AuditEvent> Events)
{
    /// <summary>What an acknowledgement is bound to: the batch id, the machine and each event's id, sequence number and signature.</summary>
    public string Digest()
    {
        StringBuilder text = new("arcana-guardian audit batch v1\n");
        text.Append(BatchId).Append('\n').Append(MachineFingerprint).Append('\n');
        foreach (AuditEvent item in Events)
        {
            text.Append(item.EventId).Append(':').Append(item.Sequence.ToString(CultureInfo.InvariantCulture)).Append(':').Append(Convert.ToBase64String(item.Signature)).Append('\n');
        }

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text.ToString())));
    }
}

/// <summary>What the authority did with one uploaded event. <see cref="AuditStatus.Accepted" />, <see cref="AuditStatus.Duplicate" /> and <see cref="AuditStatus.Expired" /> end the host's duty to keep it; <see cref="AuditStatus.Rejected" /> does not (it needs attention).</summary>
public static class AuditStatus
{
    public const string Accepted = "accepted";
    public const string Duplicate = "duplicate";
    public const string Expired = "expired";
    public const string Rejected = "rejected";

    public static bool Done(string status) => status is Accepted or Duplicate or Expired;

    /// <summary>Details of a refusal that can pass: the authority does not know (or has not yet approved) the machine, so a later upload may be taken.</summary>
    public const string UnknownMachine = "unknown-machine";

    public const string MachinePending = "machine-pending";

    /// <summary>True for a refusal that is final (a bad signature, an event it cannot use). Anything else (an unknown machine, a status this host does not know) is tried again later.</summary>
    public static bool Permanent(AuditAckEntry entry) => entry.Status == Rejected && entry.Detail is not (UnknownMachine or MachinePending);
}

public sealed record AuditAckEntry(string EventId, string Status, string Detail);

/// <summary>
/// The authority's durable acknowledgement of an upload, signed by the authority key and sent only after the events were committed. The host checks it like any other
/// answer (pinned key, signature, batch id and digest, machine, validity) before it removes anything from its outbox.
/// </summary>
public sealed record AuditAck(int ProtocolVersion, string RequestId, string RequestDigest, string MachineFingerprint, IReadOnlyList<AuditAckEntry> Entries, DateTimeOffset Issued, DateTimeOffset Expires, string AuthorityKeyId, byte[] Signature) : ISignedAnswer
{
    public const string Domain = "arcana-guardian audit acknowledgement v1\n";

    public string Canonical()
    {
        StringBuilder text = new();
        text.Append("{\"protocolVersion\":").Append(ProtocolVersion.ToString(CultureInfo.InvariantCulture)).Append(",\"requestId\":");
        ToolSettings.QuoteJson(text, RequestId);
        text.Append(",\"requestDigest\":");
        ToolSettings.QuoteJson(text, RequestDigest);
        text.Append(",\"machineFingerprint\":");
        ToolSettings.QuoteJson(text, MachineFingerprint);
        text.Append(",\"entries\":[");
        for (int index = 0; index < Entries.Count; index++)
        {
            text.Append(index == 0 ? "" : ",").Append("{\"eventId\":");
            ToolSettings.QuoteJson(text, Entries[index].EventId);
            text.Append(",\"status\":");
            ToolSettings.QuoteJson(text, Entries[index].Status);
            text.Append(",\"detail\":");
            ToolSettings.QuoteJson(text, Entries[index].Detail);
            text.Append('}');
        }

        text.Append("],\"issued\":");
        ToolSettings.QuoteJson(text, CanonicalJson.Time(Issued));
        text.Append(",\"expires\":");
        ToolSettings.QuoteJson(text, CanonicalJson.Time(Expires));
        text.Append(",\"authorityKeyId\":");
        ToolSettings.QuoteJson(text, AuthorityKeyId);

        return text.Append('}').ToString();
    }

    public static AuditAck Create(AuditBatch batch, IReadOnlyList<AuditAckEntry> entries, DateTimeOffset issued, TimeSpan lifetime, ISigningKey key)
    {
        AuditAck unsigned = new(LaunchProtocol.Version, batch.BatchId, batch.Digest(), batch.MachineFingerprint, entries, issued, issued + lifetime, KeyIdentity.Fingerprint(key.PublicKey), []);

        return unsigned with { Signature = key.Sign(WireText.Bytes(Domain, unsigned.Canonical())) };
    }

    public bool Verify(byte[] authorityPublicKey)
    {
        return string.Equals(AuthorityKeyId, KeyIdentity.Fingerprint(authorityPublicKey), StringComparison.Ordinal)
            && KeyIdentity.Verify(authorityPublicKey, WireText.Bytes(Domain, Canonical()), Signature);
    }
}

/// <summary>
/// Where the host sends its events: the authority. The local authority and the remote one of a later phase implement the same contract. The call returns only after the
/// authority committed what it accepted (the acknowledgement is that promise).
/// </summary>
public interface IAuditSink
{
    Task<AuditAck> UploadAsync(AuditBatch batch, CancellationToken cancel = default);
}

/// <summary>Filters for the history. All optional; the text filter matches the program, folder, arguments, outcome, reason and request id (case-insensitively).</summary>
public sealed record AuditQuery(string? MachinePrefix = null, DateTimeOffset? From = null, DateTimeOffset? To = null, string? Type = null, string? Outcome = null, string? GrantId = null, string? Folder = null, string? Text = null, int Limit = 100)
{
    public const int MaxLimit = 1000;
}

/// <summary>A stored event with when the authority received (and so acknowledged) it.</summary>
public sealed record AuditHistoryRecord(AuditEvent Event, DateTimeOffset Received);

/// <summary>A hole in a machine's sequence within one outbox epoch (<see cref="Kind" /> missing: events from <see cref="From" /> to <see cref="To" /> have not arrived), a number used twice (reused), or a new epoch (epoch: the machine's outbox was recreated, its first number is <see cref="From" />). Recorded, never a reason to reject.</summary>
public sealed record AuditGap(long Id, string Fingerprint, string Kind, long From, long To, DateTimeOffset Detected, DateTimeOffset? Resolved, string Epoch = "");

/// <summary>
/// Redaction of the arguments before they go into an event. The host records the arguments before anything is decrypted, so it cannot mask the exact values: what it masks
/// is what looks like one (a value after a name such as password, token, key or secret, an Authorization or Bearer value, the password of a URL) and anything very long is cut.
/// A secret typed bare into an argument is not recognizable and is the agent's own doing (it is not given the values); the approval page shows the person the same arguments.
/// </summary>
public static partial class AuditRedaction
{
    public const string Mask = "[REDACTED]";

    public const int MaxArgumentLength = 512;

    private const string SecretWord = "pass(?:word|wd|phrase)?|pwd|secret|token|api[-_]?key|apikey|access[-_]?key|private[-_]?key|auth(?:orization)?|credential|bearer|cookie|session[-_]?id|signature";

    // The name may be quoted (a JSON body: {"password":"x"}); the quote stays, the value goes.
    [GeneratedRegex(@"(?<name>[\w.-]*(?:" + SecretWord + @")[\w.-]*)(?<quote>[""']?)(?<sep>\s*[=:]\s*)(?<value>""[^""]*""|'[^']*'|[^\s,}\]]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Pair();

    [GeneratedRegex("(?<scheme>bearer|basic|token)\\s+[A-Za-z0-9._~+/=-]{6,}", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Scheme();

    [GeneratedRegex("(?<start>[a-z][a-z0-9+.-]*://)[^/\\s:@]*:[^/\\s@]*@", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UrlUser();

    // --user=name:password and --proxy-user=name:password.
    [GeneratedRegex(@"(?<name>--(?:proxy-)?user=)(?<user>[^:\s]*):\S+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UserPair();

    // curl -u / --user / -U / --proxy-user NAME:PASSWORD (as the next argument).
    [GeneratedRegex(@"^(?:-u|-U|--user|--proxy-user)$", RegexOptions.CultureInvariant)]
    private static partial Regex UserFlag();

    // mysql -pSECRET (the value is attached to the flag). A few compiler flags that start with -p are left alone.
    [GeneratedRegex(@"^-p(?!thread$|ipe$|edantic$|g$|rofile$)(?<value>[^-\s].*)$", RegexOptions.CultureInvariant)]
    private static partial Regex AttachedPassword();

    [GeneratedRegex("^-{1,2}[\\w.-]*(?:" + SecretWord + ")[\\w.-]*$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SecretFlag();

    // sshpass -p PASSWORD inside one string (bash -c "sshpass -p X ssh host").
    [GeneratedRegex(@"(?<start>\bsshpass\s+-p\s*)(?<value>""[^""]*""|'[^']*'|\S+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SshpassText();

    // Programs whose -p takes the password as the next argument: sshpass -p X, and mysql -p X (mysql would read X as the database, but a password typed that way is still a password).
    private static readonly string[] PasswordAfterP = ["sshpass", "mysql", "mysqldump", "mysqladmin", "mysqlimport", "mariadb", "mariadb-dump", "mariadb-admin"];

    public static IReadOnlyList<string> Arguments(IEnumerable<string> arguments, string program = "")
    {
        string name = Path.GetFileNameWithoutExtension(program.Replace('\\', '/')).ToLowerInvariant();
        bool pTakesPassword = PasswordAfterP.Contains(name, StringComparer.Ordinal);
        List<string> result = [];
        bool nextIsValue = false;
        bool nextIsUser = false;
        foreach (string argument in arguments)
        {
            // A value that follows a flag named like a secret (--token VALUE), or the NAME:PASSWORD after -u.
            string text;
            if (nextIsValue && !argument.StartsWith('-'))
            {
                text = Mask;
            }
            else if (nextIsUser && !argument.StartsWith('-') && argument.Contains(':'))
            {
                text = argument[..argument.IndexOf(':')] + ":" + Mask;
            }
            else if (AttachedPassword().Match(argument) is { Success: true })
            {
                text = "-p" + Mask;
            }
            else
            {
                text = Text(argument);
            }

            nextIsValue = !argument.Contains('=') && !argument.Contains(':') && (SecretFlag().IsMatch(argument) || (pTakesPassword && argument == "-p"));
            nextIsUser = UserFlag().IsMatch(argument);
            result.Add(text);
        }

        return result.Count <= AuditEvent.MaxArguments ? result : [.. result.Take(AuditEvent.MaxArguments - 1), "[" + (result.Count - AuditEvent.MaxArguments + 1) + " more arguments omitted]"];
    }

    /// <summary>
    /// The facts cut to what the authority accepts, so that no event this host signs can be refused for its size (the run it records went ahead): the folder and the program path
    /// (a deep folder tree or a long path is allowed to a program), the codes, and the arguments (count and length). A cut text ends with a marker that says how much is gone.
    /// </summary>
    public static AuditFacts Bound(AuditFacts facts)
    {
        return facts with
        {
            Outcome = Cut(facts.Outcome, 64),
            Reason = Cut(facts.Reason, 200),
            RequestId = Cut(facts.RequestId, 128),
            Folder = Cut(facts.Folder, AuditEvent.MaxText),
            Program = Cut(facts.Program, AuditEvent.MaxText),
            GrantId = Cut(facts.GrantId, 128),
            Arguments = [.. facts.Arguments.Take(AuditEvent.MaxArguments).Select(argument => Cut(argument, AuditEvent.MaxText))],
            Metadata = AuditMetadata.Bound(facts.Metadata),
        };
    }

    /// <summary>The text itself when it fits, else its beginning and "[N more characters omitted]", at most <paramref name="limit" /> characters in all.</summary>
    public static string Cut(string value, int limit)
    {
        if (value.Length <= limit)
        {
            return value;
        }

        int keep = Math.Max(0, limit - 40);
        if (keep > 0 && char.IsHighSurrogate(value[keep - 1]))
        {
            keep--;
        }

        string marker = "[" + (value.Length - keep) + " more characters omitted]";

        return limit <= marker.Length ? marker[..limit] : value[..keep] + marker;
    }

    public static string Text(string value)
    {
        // The scheme first: in "Authorization: Bearer VALUE" the pair rule would otherwise take "Bearer" for the value and leave VALUE.
        string text = SshpassText().Replace(value, match => match.Groups["start"].Value + Mask);
        text = Scheme().Replace(text, match => match.Groups["scheme"].Value + " " + Mask);
        text = Pair().Replace(text, match => match.Groups["name"].Value + match.Groups["quote"].Value + match.Groups["sep"].Value + Mask);
        text = UserPair().Replace(text, match => match.Groups["name"].Value + match.Groups["user"].Value + ":" + Mask);
        text = UrlUser().Replace(text, match => match.Groups["start"].Value + Mask + "@");
        text = ApprovalSummary.Clean(text);

        return text.Length <= MaxArgumentLength ? text : text[..MaxArgumentLength] + "[" + (text.Length - MaxArgumentLength) + " more characters omitted]";
    }
}

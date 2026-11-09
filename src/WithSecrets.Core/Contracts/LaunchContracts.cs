using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace WithSecrets;

/// <summary>The version and the limits of the launch protocol.</summary>
public static partial class LaunchProtocol
{
    /// <summary>The one protocol version this build speaks. A message with another version is refused, never guessed at.</summary>
    public const int Version = 1;

    /// <summary>The longest a request may live between <see cref="LaunchRequest.Created" /> and <see cref="LaunchRequest.Expires" />.</summary>
    public static readonly TimeSpan MaxLifetime = TimeSpan.FromMinutes(10);

    /// <summary>How far in the future a request's creation time may be (clock difference between the two sides).</summary>
    public static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(1);

    [GeneratedRegex("^[A-Za-z0-9_-]{1,64}\\z", RegexOptions.CultureInvariant)]
    internal static partial Regex IdPattern();

    [GeneratedRegex("^[A-Za-z0-9_-]{16,128}\\z", RegexOptions.CultureInvariant)]
    internal static partial Regex NoncePattern();
}

/// <summary>One secret handed to the program: the environment variable it appears as, and the store name it comes from. Names only.</summary>
public sealed record LaunchMapping(string Variable, string Secret);

/// <summary>
/// Everything that defines a run, as the CLI sends it and a person approves it. It names secrets and never carries one: the
/// values stay with whoever launches the program. <see cref="Arguments" /> are the arguments as typed; <see cref="EnvVariables" />
/// are the ordinary (non-secret) variables from the .env files and <see cref="EnvNames" /> the ordinary names taken from the
/// environment; <see cref="EnvFiles" /> are the .env files the declarations came from. <see cref="RequestId" /> is unique per
/// request, <see cref="ClientNonce" /> is chosen by the sender, and the digest (see <see cref="Digest" />) covers all of it.
/// The type says nothing about where the request is handled.
/// <para>
/// The canonical text is exactly <c>{"protocolVersion":N,"requestId":S,"created":S,"expires":S,"clientNonce":S,"secretNames":[S,...],
/// "mappings":[{"variable":S,"secret":S},...],"reason":S,"program":S,"arguments":[S,...],"workingDirectory":S,"envFiles":[S,...],
/// "envNames":[S,...],"envVariables":{NAME:S,...},"inheritedEnvironment":{NAME:S,...}}</c>: this member order, no white space, both maps sorted by name
/// (ordinal), lists in the order given, times in UTC in the round-trip ("O") format, numbers as plain integers, and strings as
/// <see cref="ToolSettings.QuoteJson" /> writes them (the escaping <see cref="Manifest.Canonical" /> uses, plus control
/// characters). The digest is <see cref="Digest" />: SHA-256 of the UTF-8 bytes of that text, in upper-case hex.
/// </para>
/// </summary>
public sealed record LaunchRequest(
    int ProtocolVersion,
    string RequestId,
    DateTimeOffset Created,
    DateTimeOffset Expires,
    string ClientNonce,
    IReadOnlyList<string> SecretNames,
    IReadOnlyList<LaunchMapping> Mappings,
    string Reason,
    string Program,
    IReadOnlyList<string> Arguments,
    string WorkingDirectory,
    IReadOnlyList<string> EnvFiles,
    IReadOnlyList<string> EnvNames,
    IReadOnlyDictionary<string, string> EnvVariables,
    IReadOnlyDictionary<string, string> InheritedEnvironment)
{
    /// <summary>The canonical JSON text of the request. Equal requests give equal text, whatever the order they were read in.</summary>
    public string Canonical()
    {
        StringBuilder text = new();
        text.Append("{\"protocolVersion\":").Append(ProtocolVersion.ToString(CultureInfo.InvariantCulture));
        text.Append(",\"requestId\":");
        ToolSettings.QuoteJson(text, RequestId);
        text.Append(",\"created\":");
        ToolSettings.QuoteJson(text, CanonicalJson.Time(Created));
        text.Append(",\"expires\":");
        ToolSettings.QuoteJson(text, CanonicalJson.Time(Expires));
        text.Append(",\"clientNonce\":");
        ToolSettings.QuoteJson(text, ClientNonce);
        text.Append(",\"secretNames\":");
        CanonicalJson.Strings(text, SecretNames);
        text.Append(",\"mappings\":[");
        bool first = true;
        foreach (LaunchMapping mapping in Mappings)
        {
            text.Append(first ? "" : ",").Append("{\"variable\":");
            first = false;
            ToolSettings.QuoteJson(text, mapping.Variable);
            text.Append(",\"secret\":");
            ToolSettings.QuoteJson(text, mapping.Secret);
            text.Append('}');
        }

        text.Append("],\"reason\":");
        ToolSettings.QuoteJson(text, Reason);
        text.Append(",\"program\":");
        ToolSettings.QuoteJson(text, Program);
        text.Append(",\"arguments\":");
        CanonicalJson.Strings(text, Arguments);
        text.Append(",\"workingDirectory\":");
        ToolSettings.QuoteJson(text, WorkingDirectory);
        text.Append(",\"envFiles\":");
        CanonicalJson.Strings(text, EnvFiles);
        text.Append(",\"envNames\":");
        CanonicalJson.Strings(text, EnvNames);
        text.Append(",\"envVariables\":");
        CanonicalJson.Map(text, EnvVariables);
        text.Append(",\"inheritedEnvironment\":");
        CanonicalJson.Map(text, InheritedEnvironment);

        return text.Append('}').ToString();
    }

    /// <summary>The request digest: SHA-256 of the UTF-8 bytes of <see cref="Canonical" />, upper-case hex. It changes when any field changes.</summary>
    public string Digest() => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Canonical())));

    /// <summary>
    /// Null when the request may be acted on at <paramref name="now" />, else why not (a message with no values in it): the
    /// protocol version, well-formed ids, valid secret names, pairs that name only listed secrets, a program and a folder, and a
    /// life that has begun, has not ended and is no longer than <see cref="LaunchProtocol.MaxLifetime" />.
    /// </summary>
    public string? Validate(DateTimeOffset now)
    {
        if (ProtocolVersion != LaunchProtocol.Version)
        {
            return $"unsupported protocol version {ProtocolVersion.ToString(CultureInfo.InvariantCulture)} (this build speaks {LaunchProtocol.Version.ToString(CultureInfo.InvariantCulture)})";
        }

        if (!LaunchProtocol.IdPattern().IsMatch(RequestId))
        {
            return "the request id must be 1 to 64 of letters, digits, '_' and '-'";
        }

        if (!LaunchProtocol.NoncePattern().IsMatch(ClientNonce))
        {
            return "the client nonce must be 16 to 128 of letters, digits, '_' and '-'";
        }

        if (Expires <= Created)
        {
            return "the request expires before it was created";
        }

        if (Expires - Created > LaunchProtocol.MaxLifetime)
        {
            return "the request lifetime is longer than " + ((int)LaunchProtocol.MaxLifetime.TotalMinutes).ToString(CultureInfo.InvariantCulture) + " minutes";
        }

        if (Created > now + LaunchProtocol.ClockSkew)
        {
            return "the request was created in the future";
        }

        if (now >= Expires)
        {
            return "the request expired at " + CanonicalJson.Time(Expires);
        }

        if (SecretNames.Count is 0 or > EnvDeclarations.MaxPairs)
        {
            return "the request must name between 1 and " + EnvDeclarations.MaxPairs.ToString(CultureInfo.InvariantCulture) + " secrets";
        }

        if (SecretNames.FirstOrDefault(name => !WithSecrets.SecretNames.IsValid(name)) is { } bad)
        {
            return "invalid secret name: " + ApprovalSummary.Clean(bad);
        }

        if (Mappings.Count == 0)
        {
            return "the request has no secret-to-variable pairs";
        }

        foreach (LaunchMapping mapping in Mappings)
        {
            if (mapping.Variable.Length == 0 || mapping.Variable.Contains('=', StringComparison.Ordinal) || mapping.Variable.Contains('\0', StringComparison.Ordinal))
            {
                return "invalid variable name: " + ApprovalSummary.Clean(mapping.Variable);
            }

            if (!SecretNames.Contains(mapping.Secret, StringComparer.Ordinal))
            {
                return "the pair for variable " + ApprovalSummary.Clean(mapping.Variable) + " names a secret that the request does not list";
            }
        }

        if (Program.Length == 0)
        {
            return "the request has no program";
        }

        if (WorkingDirectory.Length == 0)
        {
            return "the request has no working directory";
        }

        return null;
    }

    /// <summary>
    /// Reads a request from JSON. Strict: every member must be present, none may repeat or be unknown, and each must have its
    /// type; the order of members does not matter. The protocol version is read as it is and judged by <see cref="Validate" />.
    /// </summary>
    public static bool TryParse(string json, out LaunchRequest? request, out string? error)
    {
        request = null;
        if (!CanonicalJson.Open(json, out JsonDocument? doc, out error))
        {
            return false;
        }

        using (doc)
        {
            ContractReader reader = new(doc!.RootElement, "protocolVersion", "requestId", "created", "expires", "clientNonce", "secretNames", "mappings", "reason", "program", "arguments", "workingDirectory", "envFiles", "envNames", "envVariables", "inheritedEnvironment");
            if (reader.Problem is not null)
            {
                error = reader.Problem;

                return false;
            }

            List<LaunchMapping> mappings = [];
            if (!reader.Int("protocolVersion", out int version) || !reader.Text("requestId", out string? id) || !reader.Time("created", out DateTimeOffset created) || !reader.Time("expires", out DateTimeOffset expires)
                || !reader.Text("clientNonce", out string? nonce) || !reader.Strings("secretNames", out List<string>? names) || !reader.Text("reason", out string? reason) || !reader.Text("program", out string? program)
                || !reader.Strings("arguments", out List<string>? arguments) || !reader.Text("workingDirectory", out string? folder) || !reader.Strings("envFiles", out List<string>? files)
                || !reader.Strings("envNames", out List<string>? envNames) || !reader.Map("envVariables", out Dictionary<string, string>? variables) || !reader.Map("inheritedEnvironment", out Dictionary<string, string>? inherited) || !ReadMappings(reader, mappings))
            {
                error = reader.Problem;

                return false;
            }

            error = null;
            request = new LaunchRequest(version, id!, created, expires, nonce!, names!, mappings, reason!, program!, arguments!, folder!, files!, envNames!, variables!, inherited!);

            return true;
        }
    }

    private static bool ReadMappings(ContractReader reader, List<LaunchMapping> mappings)
    {
        if (!reader.Array("mappings", out JsonElement array))
        {
            return false;
        }

        foreach (JsonElement item in array.EnumerateArray())
        {
            ContractReader pair = new(item, "variable", "secret") { Where = "mappings" };
            if (pair.Problem is not null || !pair.Text("variable", out string? variable) || !pair.Text("secret", out string? secret))
            {
                reader.Fail(pair.Problem!);

                return false;
            }

            mappings.Add(new LaunchMapping(variable!, secret!));
        }

        return true;
    }
}

/// <summary>How a run ended, as far as the sender can tell.</summary>
public enum LaunchOutcome
{
    /// <summary>The person refused the request, or a policy did.</summary>
    Denied,

    /// <summary>The request was withdrawn or timed out before it was decided.</summary>
    Cancelled,

    /// <summary>Approved, but the run could not be set up (store, audit, program not found, ...). <see cref="LaunchResult.Detail" /> says why, without values.</summary>
    Failed,

    /// <summary>The program was started and has not finished (for a result sent before the exit).</summary>
    Launched,

    /// <summary>The program ran and ended: <see cref="LaunchResult.ExitCode" /> is its status.</summary>
    Exited,

    /// <summary>An approval that makes a grant (<c>approve</c>) was given: nothing was launched.</summary>
    Approved,
}

/// <summary>
/// The answer to a <see cref="LaunchRequest" />: the outcome, the program's exit status when it ended, and the public output
/// (what the terminal would show, already redacted) as text. Nothing else: no secret value, key or code travels back to the
/// sender. <see cref="Detail" /> is a short reason, never a value.
/// </summary>
public sealed record LaunchResult(int ProtocolVersion, string RequestId, LaunchOutcome Outcome, int? ExitCode, string Output, string Detail)
{
    public static LaunchResult Exited(string requestId, int exitCode, string output) => new(LaunchProtocol.Version, requestId, LaunchOutcome.Exited, exitCode, output, "");

    public static LaunchResult Launched(string requestId, string output = "") => new(LaunchProtocol.Version, requestId, LaunchOutcome.Launched, null, output, "");

    public static LaunchResult Denied(string requestId, string detail) => new(LaunchProtocol.Version, requestId, LaunchOutcome.Denied, null, "", detail);

    public static LaunchResult Cancelled(string requestId, string detail) => new(LaunchProtocol.Version, requestId, LaunchOutcome.Cancelled, null, "", detail);

    public static LaunchResult Failed(string requestId, string detail) => new(LaunchProtocol.Version, requestId, LaunchOutcome.Failed, null, "", detail);

    /// <summary>The canonical JSON text: <c>{"protocolVersion":N,"requestId":S,"outcome":S,"exitCode":N|null,"output":S,"detail":S}</c>.</summary>
    public string Canonical()
    {
        StringBuilder text = new();
        text.Append("{\"protocolVersion\":").Append(ProtocolVersion.ToString(CultureInfo.InvariantCulture)).Append(",\"requestId\":");
        ToolSettings.QuoteJson(text, RequestId);
        text.Append(",\"outcome\":");
        ToolSettings.QuoteJson(text, Outcome.ToString().ToLowerInvariant());
        text.Append(",\"exitCode\":").Append(ExitCode is { } code ? code.ToString(CultureInfo.InvariantCulture) : "null").Append(",\"output\":");
        ToolSettings.QuoteJson(text, Output);
        text.Append(",\"detail\":");
        ToolSettings.QuoteJson(text, Detail);

        return text.Append('}').ToString();
    }

    /// <summary>Reads a result from JSON, as strictly as <see cref="LaunchRequest.TryParse" />, and refuses another protocol version.</summary>
    public static bool TryParse(string json, out LaunchResult? result, out string? error)
    {
        result = null;
        if (!CanonicalJson.Open(json, out JsonDocument? doc, out error))
        {
            return false;
        }

        using (doc)
        {
            ContractReader reader = new(doc!.RootElement, "protocolVersion", "requestId", "outcome", "exitCode", "output", "detail");
            if (reader.Problem is not null || !reader.Int("protocolVersion", out int version) || !reader.Text("requestId", out string? id) || !reader.Text("outcome", out string? outcomeName)
                || !reader.OptionalInt("exitCode", out int? exit) || !reader.Text("output", out string? output) || !reader.Text("detail", out string? detail))
            {
                error = reader.Problem;

                return false;
            }

            if (version != LaunchProtocol.Version)
            {
                error = $"unsupported protocol version {version.ToString(CultureInfo.InvariantCulture)} (this build speaks {LaunchProtocol.Version.ToString(CultureInfo.InvariantCulture)})";

                return false;
            }

            if (!Enum.TryParse(outcomeName, true, out LaunchOutcome outcome) || !Enum.IsDefined(outcome) || outcomeName != outcomeName!.ToLowerInvariant())
            {
                error = "unknown outcome";

                return false;
            }

            error = null;
            result = new LaunchResult(version, id!, outcome, exit, output!, detail!);

            return true;
        }
    }
}

/// <summary>What was approved, tied to the request that is run: the request digest, the existing approval fingerprint, and one value (BoundDigest) over both.</summary>
public sealed record LaunchBinding(string RequestDigest, string FingerprintKey, string BoundDigest);

/// <summary>
/// Ties the launch request to the approval the person saw. The approval fingerprint (see <see cref="RequestFingerprint" />: names,
/// program path, folder, script content) is computed exactly as before and keeps its values; the request digest covers every
/// field of the request. <see cref="Bind" /> refuses a request that is not the approved one and returns both and one value over
/// them: <c>SHA-256("with-secrets launch binding v1" LF digest LF fingerprint)</c>, upper-case hex.
/// </summary>
public static class LaunchRequestBinding
{
    /// <summary>The request for an approval: the command as typed, the pairs by name, the .env plan and the reason.</summary>
    public static LaunchRequest From(ApprovalRequest approval, string requestId, string clientNonce, DateTimeOffset created, DateTimeOffset expires, IReadOnlyDictionary<string, string>? inheritedEnvironment = null)
        => new(
            LaunchProtocol.Version,
            requestId,
            created,
            expires,
            clientNonce,
            approval.SecretNames,
            [.. (approval.Mappings ?? [.. approval.SecretNames.Select(name => new SecretMapping(name, name))]).Select(mapping => new LaunchMapping(mapping.Variable, mapping.Secret))],
            approval.Reason,
            approval.Program,
            approval.TypedArguments ?? approval.Arguments,
            approval.WorkingDirectory,
            approval.EnvFiles ?? [],
            approval.EnvNames ?? [],
            approval.EnvValues ?? new Dictionary<string, string>(),
            inheritedEnvironment ?? approval.InheritedEnvironment ?? new Dictionary<string, string>());

    /// <summary>Null when the request is the approved one, else which part differs (names the part, never a value).</summary>
    public static string? Mismatch(LaunchRequest request, ApprovalRequest approval)
    {
        LaunchRequest expected = From(approval, request.RequestId, request.ClientNonce, request.Created, request.Expires, request.InheritedEnvironment);
        if (request.Program != expected.Program)
        {
            return "program differs from the approval";
        }

        if (approval.InheritedEnvironment is { } approvedEnvironment && EnvironmentBinding.Hash(request.InheritedEnvironment) != EnvironmentBinding.Hash(approvedEnvironment))
        {
            return "inherited environment differs from the approval";
        }

        if (!request.Arguments.SequenceEqual(expected.Arguments, StringComparer.Ordinal))
        {
            return "arguments differ from the approval";
        }

        if (request.WorkingDirectory != expected.WorkingDirectory)
        {
            return "folder differs from the approval";
        }

        if (!request.SecretNames.SequenceEqual(expected.SecretNames, StringComparer.Ordinal))
        {
            return "secret names differ from the approval";
        }

        if (!request.Mappings.SequenceEqual(expected.Mappings))
        {
            return "mappings differ from the approval";
        }

        if (request.Reason != expected.Reason)
        {
            return "reason differs from the approval";
        }

        if (!request.EnvFiles.SequenceEqual(expected.EnvFiles, StringComparer.Ordinal))
        {
            return "env files differ from the approval";
        }

        if (!request.EnvNames.SequenceEqual(expected.EnvNames, StringComparer.Ordinal))
        {
            return "env names differ from the approval";
        }

        if (request.EnvVariables.Count != expected.EnvVariables.Count || request.EnvVariables.Any(item => !expected.EnvVariables.TryGetValue(item.Key, out string? value) || value != item.Value))
        {
            return "env values differ from the approval";
        }

        return null;
    }

    /// <summary>Binds the request to the approval. Throws <see cref="InvalidOperationException" /> when the request is not the approved one.</summary>
    public static LaunchBinding Bind(LaunchRequest request, ApprovalRequest approval)
    {
        if (Mismatch(request, approval) is { } why)
        {
            throw new InvalidOperationException("the launch request is not the approved request: " + why);
        }

        string digest = request.Digest();
        string fingerprint = RequestFingerprint.Compute(approval).Key;
        string value = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("with-secrets launch binding v1\n" + digest + "\n" + fingerprint)));

        return new LaunchBinding(digest, fingerprint, value);
    }
}

/// <summary>Helpers shared by the contract types.</summary>
internal static class CanonicalJson
{
    private static readonly JsonDocumentOptions Strict = new() { AllowDuplicateProperties = false };

    public static string Time(DateTimeOffset time) => time.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);

    public static void Strings(StringBuilder text, IReadOnlyList<string> items)
    {
        text.Append('[');
        for (int index = 0; index < items.Count; index++)
        {
            text.Append(index == 0 ? "" : ",");
            ToolSettings.QuoteJson(text, items[index]);
        }

        text.Append(']');
    }

    /// <summary>A JSON object of strings, members sorted by name (ordinal).</summary>
    public static void Map(StringBuilder text, IReadOnlyDictionary<string, string> map)
    {
        text.Append('{');
        bool first = true;
        foreach (KeyValuePair<string, string> item in map.OrderBy(entry => entry.Key, StringComparer.Ordinal))
        {
            text.Append(first ? "" : ",");
            first = false;
            ToolSettings.QuoteJson(text, item.Key);
            text.Append(':');
            ToolSettings.QuoteJson(text, item.Value);
        }

        text.Append('}');
    }

    public static bool Open(string json, out JsonDocument? doc, out string? error)
    {
        doc = null;
        try
        {
            doc = JsonDocument.Parse(json, Strict);
        }
        catch (Exception problem) when (problem is JsonException or ArgumentException)
        {
            error = "not valid JSON";

            return false;
        }

        if (doc.RootElement.ValueKind != JsonValueKind.Object)
        {
            doc.Dispose();
            doc = null;
            error = "not a JSON object";

            return false;
        }

        error = null;

        return true;
    }
}

/// <summary>Reads the members of one JSON object by name, strictly. <see cref="Problem" /> is the first thing wrong, naming a member and never a value.</summary>
internal sealed class ContractReader
{
    private readonly Dictionary<string, JsonElement> _members = new(StringComparer.Ordinal);

    public ContractReader(JsonElement element, params string[] names)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            Problem = "expected an object";

            return;
        }

        foreach (JsonProperty property in element.EnumerateObject())
        {
            if (!names.Contains(property.Name, StringComparer.Ordinal))
            {
                Problem = "unknown field " + ApprovalSummary.Clean(property.Name);

                return;
            }

            _members[property.Name] = property.Value;
        }

        foreach (string name in names)
        {
            if (!_members.ContainsKey(name))
            {
                Problem = "missing field " + name;

                return;
            }
        }
    }

    public string? Where { get; init; }

    public string? Problem { get; private set; }

    public void Fail(string problem) => Problem ??= problem;

    private bool Bad(string name, string expected)
    {
        Problem ??= "field " + (Where is null ? "" : Where + ".") + name + " must be " + expected;

        return false;
    }

    public bool Int(string name, out int value)
    {
        value = 0;

        return _members[name] is { ValueKind: JsonValueKind.Number } element && element.TryGetInt32(out value) || Bad(name, "an integer");
    }

    public bool Long(string name, out long value)
    {
        value = 0;

        return _members[name] is { ValueKind: JsonValueKind.Number } element && element.TryGetInt64(out value) || Bad(name, "an integer");
    }

    public bool OptionalInt(string name, out int? value)
    {
        value = null;
        if (_members[name].ValueKind == JsonValueKind.Null)
        {
            return true;
        }

        if (!Int(name, out int number))
        {
            return false;
        }

        value = number;

        return true;
    }

    public bool Text(string name, out string? value)
    {
        value = null;
        if (_members[name].ValueKind != JsonValueKind.String)
        {
            return Bad(name, "a string");
        }

        try
        {
            value = _members[name].GetString();
        }
        catch (InvalidOperationException)
        {
            return Bad(name, "valid text");
        }

        return true;
    }

    public bool Time(string name, out DateTimeOffset value)
    {
        value = default;

        return Text(name, out string? text) && DateTimeOffset.TryParseExact(text, "O", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out value) || Bad(name, "a time in the round-trip (O) format");
    }

    public bool Array(string name, out JsonElement array)
    {
        array = _members[name];

        return array.ValueKind == JsonValueKind.Array || Bad(name, "an array");
    }

    public bool Strings(string name, out List<string>? items)
    {
        items = null;
        if (!Array(name, out JsonElement array))
        {
            return false;
        }

        List<string> list = [];
        foreach (JsonElement item in array.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String)
            {
                return Bad(name, "an array of strings");
            }

            list.Add(item.GetString()!);
        }

        items = list;

        return true;
    }

    public bool Map(string name, out Dictionary<string, string>? map)
    {
        map = null;
        if (_members[name].ValueKind != JsonValueKind.Object)
        {
            return Bad(name, "an object of strings");
        }

        Dictionary<string, string> result = new(StringComparer.Ordinal);
        foreach (JsonProperty property in _members[name].EnumerateObject())
        {
            if (property.Value.ValueKind != JsonValueKind.String)
            {
                return Bad(name, "an object of strings");
            }

            result[property.Name] = property.Value.GetString()!;
        }

        map = result;

        return true;
    }
}

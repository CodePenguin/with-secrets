using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace WithSecrets.Tests;

/// <summary>
/// Phase 0 contracts: the launch request and result that sit between the CLI and a host service. Stable canonical text (golden
/// vectors), a digest that covers every field, strict parsing, version and expiry checks, the binding to the existing approval
/// fingerprint, and the guarantee that no contract type can carry a secret value.
/// </summary>
internal static class LaunchContractTests
{
    private static readonly DateTimeOffset Created = new(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);

    private const string GoldenCanonical = "{\"protocolVersion\":1,\"requestId\":\"req-0001\",\"created\":\"2026-11-01T12:00:00.0000000Z\",\"expires\":\"2026-11-01T12:05:00.0000000Z\",\"clientNonce\":\"bm9uY2UtMDAwMDAwMDE\",\"secretNames\":[\"API_KEY\",\"team/DB_PASS\"],\"mappings\":[{\"variable\":\"API_KEY\",\"secret\":\"API_KEY\"},{\"variable\":\"DB\",\"secret\":\"team/DB_PASS\"}],\"reason\":\"deploy \\\"v2\\\"\\u000a\",\"program\":\"dotnet\",\"arguments\":[\"test\",\"--filter\",\"\\u00e9\"],\"workingDirectory\":\"C:\\\\work\\\\app\",\"envFiles\":[\".env\"],\"envNames\":[\"MODE\"],\"envVariables\":{\"MODE\":\"ci\"},\"inheritedEnvironment\":{\"LANG\":\"en\",\"PATH\":\"C:\\\\bin\"}}";

    // Computed independently (Python hashlib) over the exact bytes of GoldenCanonical.
    private const string GoldenDigest = "CB6CEE83EFA8D50D5754870AE0C47A0C0CB93BAFA7E294BA6EF02A0EF550211B";

    private const string GoldenResult = "{\"protocolVersion\":1,\"requestId\":\"req-0001\",\"outcome\":\"exited\",\"exitCode\":3,\"output\":\"hello [REDACTED]\\u000a\",\"detail\":\"\"}";

    private static LaunchRequest Sample() => new(
        LaunchProtocol.Version,
        "req-0001",
        Created,
        Created.AddMinutes(5),
        "bm9uY2UtMDAwMDAwMDE",
        ["API_KEY", "team/DB_PASS"],
        [new LaunchMapping("API_KEY", "API_KEY"), new LaunchMapping("DB", "team/DB_PASS")],
        "deploy \"v2\"\n",
        "dotnet",
        ["test", "--filter", "\u00e9"],
        "C:\\work\\app",
        [".env"],
        ["MODE"],
        new Dictionary<string, string> { ["MODE"] = "ci" },
        new Dictionary<string, string> { ["PATH"] = "C:\\bin", ["LANG"] = "en" });

    public static Task Run(Action<bool, string> check)
    {
        Golden(check);
        OrderIndependence(check);
        EveryFieldChangesTheDigest(check);
        Validation(check);
        Parsing(check);
        NoSecretValues(check);
        Binding(check);
        Result(check);

        return Task.CompletedTask;
    }

    private static void Golden(Action<bool, string> check)
    {
        LaunchRequest request = Sample();
        check(request.Canonical() == GoldenCanonical, "launch contract: canonical text matches the golden vector (" + request.Canonical() + ")");
        check(request.Digest() == GoldenDigest, "launch contract: the request digest is SHA-256 of the canonical text, upper-case hex (" + request.Digest() + ")");
        check(LaunchRequest.TryParse(GoldenCanonical, out LaunchRequest? back, out string? error) && error is null && back!.Canonical() == GoldenCanonical && back.Digest() == GoldenDigest, "launch contract: the canonical text parses and canonicalises to itself (" + error + ")");
        check(Sample().Canonical() == Sample().Canonical(), "launch contract: serialization is deterministic");

        LaunchRequest unsorted = Sample() with { EnvVariables = new Dictionary<string, string> { ["ZED"] = "1", ["ALPHA"] = "2" } };
        check(unsorted.Canonical().Contains("\"envVariables\":{\"ALPHA\":\"2\",\"ZED\":\"1\"}", StringComparison.Ordinal), "launch contract: environment variables are written sorted by name (ordinal)");
        LaunchRequest offset = Sample() with { Created = new DateTimeOffset(2026, 11, 1, 14, 0, 0, TimeSpan.FromHours(2)) };
        check(offset.Canonical() == GoldenCanonical, "launch contract: times are written as UTC whatever offset they were given");
    }

    private static void OrderIndependence(Action<bool, string> check)
    {
        // The same members in reverse order, with white space, parse to the same canonical text and digest.
        using JsonDocument doc = JsonDocument.Parse(GoldenCanonical);
        List<string> members = [.. doc.RootElement.EnumerateObject().Select(property => JsonSerializer.Serialize(property.Name) + " : " + property.Value.GetRawText())];
        members.Reverse();
        string shuffled = "{\n  " + string.Join(",\n  ", members) + "\n}";
        check(LaunchRequest.TryParse(shuffled, out LaunchRequest? request, out string? error) && request!.Canonical() == GoldenCanonical && request.Digest() == GoldenDigest, "launch contract: member order and white space do not change the canonical form (" + error + ")");

        string nested = GoldenCanonical.Replace("{\"variable\":\"DB\",\"secret\":\"team/DB_PASS\"}", "{\"secret\":\"team/DB_PASS\",\"variable\":\"DB\"}", StringComparison.Ordinal);
        check(nested != GoldenCanonical && LaunchRequest.TryParse(nested, out LaunchRequest? swapped, out _) && swapped!.Canonical() == GoldenCanonical, "launch contract: member order inside a mapping does not matter");

        string escaped = GoldenCanonical.Replace("\"dotnet\"", "\"\\u0064otnet\"", StringComparison.Ordinal);
        check(LaunchRequest.TryParse(escaped, out LaunchRequest? viaEscape, out _) && viaEscape!.Digest() == GoldenDigest, "launch contract: an escaped spelling of the same text has the same digest");
    }

    private static void EveryFieldChangesTheDigest(Action<bool, string> check)
    {
        ConstructorInfo constructor = typeof(LaunchRequest).GetConstructors().Single();
        ParameterInfo[] parameters = constructor.GetParameters();
        LaunchRequest baseline = Sample();
        check(parameters.Length == 15, "launch contract: the request has 15 fields (a new field needs a golden vector and a binding decision): " + parameters.Length);
        foreach (ParameterInfo parameter in parameters)
        {
            PropertyInfo property = typeof(LaunchRequest).GetProperty(parameter.Name!)!;
            object?[] values = [.. parameters.Select(other => typeof(LaunchRequest).GetProperty(other.Name!)!.GetValue(baseline))];
            values[parameter.Position] = Mutate(property.GetValue(baseline)!, property.PropertyType);
            LaunchRequest changed = (LaunchRequest)constructor.Invoke(values);
            check(changed.Digest() != baseline.Digest(), "request digest: changing " + parameter.Name + " changes the digest");
            check(changed.Canonical() != baseline.Canonical(), "request digest: changing " + parameter.Name + " changes the canonical text");
        }

        check(Sample().Digest() != (Sample() with { EnvVariables = new Dictionary<string, string> { ["MODE"] = "cj" } }).Digest(), "request digest: a changed environment value changes the digest");
        check(Sample().Digest() != (Sample() with { InheritedEnvironment = new Dictionary<string, string> { ["PATH"] = "C:\\other", ["LANG"] = "en" } }).Digest(), "request digest: a changed inherited environment value changes the digest");
        check(Sample().Digest() == (Sample() with { InheritedEnvironment = new Dictionary<string, string> { ["LANG"] = "en", ["PATH"] = "C:\\bin" } }).Digest(), "request digest: the inherited environment is sorted by name, so its order does not matter");
        check(Sample().Digest() != (Sample() with { Arguments = ["--filter", "test", "\u00e9"] }).Digest(), "request digest: argument order matters");
        check(Sample().Digest() != (Sample() with { Arguments = ["test", "--filter\u00e9"] }).Digest(), "request digest: argument boundaries matter");
    }

    private static object Mutate(object value, Type type) => value switch
    {
        string text => text + "x",
        int number => number + 1,
        DateTimeOffset time => time.AddSeconds(1),
        IReadOnlyList<string> list => (IReadOnlyList<string>)[.. list, "x"],
        IReadOnlyList<LaunchMapping> list => (IReadOnlyList<LaunchMapping>)[.. list, new LaunchMapping("X", "X")],
        IReadOnlyDictionary<string, string> map => new Dictionary<string, string>(map) { ["X"] = "x" },
        _ => throw new InvalidOperationException("no mutation for " + type),
    };

    private static void Validation(Action<bool, string> check)
    {
        DateTimeOffset now = Created.AddMinutes(1);
        check(Sample().Validate(now) is null, "launch validation: the sample is valid (" + Sample().Validate(now) + ")");

        check(Sample().Validate(Created.AddMinutes(5)) is { } expired && expired.Contains("expired", StringComparison.Ordinal), "launch validation: a request is expired at its expiry time");
        check(Sample().Validate(Created.AddMinutes(60)) is { } late && late.Contains("expired", StringComparison.Ordinal), "launch validation: a request long past its expiry is expired");
        check(Sample().Validate(Created.AddMinutes(5).AddTicks(-1)) is null, "launch validation: a request is valid until its expiry");
        check((Sample() with { Created = Created.AddMinutes(10), Expires = Created.AddMinutes(15) }).Validate(now) is { } future && future.Contains("future", StringComparison.Ordinal), "launch validation: a request created in the future is refused");
        check((Sample() with { Expires = Created }).Validate(Created.AddSeconds(-1)) is { } nolife && nolife.Contains("expires", StringComparison.Ordinal), "launch validation: expiry must be after creation");
        check((Sample() with { Expires = Created.Add(LaunchProtocol.MaxLifetime).AddSeconds(1) }).Validate(now) is { } longLife && longLife.Contains("lifetime", StringComparison.Ordinal), "launch validation: a lifetime over the maximum is refused");

        check((Sample() with { ProtocolVersion = 2 }).Validate(now) is { } v2 && v2.Contains("protocol version 2", StringComparison.Ordinal), "launch validation: a newer protocol version is rejected");
        check((Sample() with { ProtocolVersion = 0 }).Validate(now) is { } v0 && v0.Contains("protocol version 0", StringComparison.Ordinal), "launch validation: protocol version 0 is rejected");

        check((Sample() with { RequestId = "" }).Validate(now) is not null, "launch validation: an empty request id is refused");
        check((Sample() with { RequestId = "has space" }).Validate(now) is not null, "launch validation: a request id with a space is refused");
        check((Sample() with { ClientNonce = "" }).Validate(now) is not null, "launch validation: an empty client nonce is refused");
        check((Sample() with { ClientNonce = "short" }).Validate(now) is not null, "launch validation: a short client nonce is refused");
        check((Sample() with { SecretNames = [] }).Validate(now) is not null, "launch validation: no secret names is refused");
        check((Sample() with { SecretNames = ["lower_case", "API_KEY"] }).Validate(now) is not null, "launch validation: an invalid secret name is refused");
        check((Sample() with { Mappings = [new LaunchMapping("DB", "NOT_LISTED")] }).Validate(now) is not null, "launch validation: a mapping to a secret that was not named is refused");
        check((Sample() with { Mappings = [] }).Validate(now) is not null, "launch validation: no mappings is refused");
        check((Sample() with { Program = "" }).Validate(now) is not null, "launch validation: an empty program is refused");
        check((Sample() with { WorkingDirectory = "" }).Validate(now) is not null, "launch validation: an empty working directory is refused");
        check((Sample() with { Mappings = [new LaunchMapping("", "API_KEY")] }).Validate(now) is not null, "launch validation: an empty variable name is refused");
    }

    private static void Parsing(Action<bool, string> check)
    {
        static bool Fails(string json, string expect, out string? error)
        {
            bool parsed = LaunchRequest.TryParse(json, out LaunchRequest? request, out error);

            return !parsed && request is null && error is not null && error.Contains(expect, StringComparison.Ordinal);
        }

        check(Fails(GoldenCanonical.Replace("\"envNames\"", "\"extra\":1,\"envNames\"", StringComparison.Ordinal), "unknown field extra", out string? error), "launch parse: an unknown field is rejected (" + error + ")");
        check(Fails(GoldenCanonical.Replace("\"variable\":\"DB\"", "\"variable\":\"DB\",\"note\":\"x\"", StringComparison.Ordinal), "unknown field note", out error), "launch parse: an unknown field in a mapping is rejected (" + error + ")");
        check(Fails(GoldenCanonical.Replace("\"requestId\":\"req-0001\",", "\"requestId\":\"req-0001\",\"requestId\":\"req-0002\",", StringComparison.Ordinal), "", out error), "launch parse: a duplicate field is rejected (" + error + ")");
        check(Fails("", "", out error) && Fails("not json", "", out error) && Fails("[]", "", out error) && Fails("{}", "missing field", out error), "launch parse: empty, malformed, non-object and empty-object input are rejected");
        check(Fails(GoldenCanonical + " x", "", out error), "launch parse: trailing text is rejected");

        using JsonDocument doc = JsonDocument.Parse(GoldenCanonical);
        foreach (JsonProperty property in doc.RootElement.EnumerateObject())
        {
            string without = "{" + string.Join(",", doc.RootElement.EnumerateObject().Where(other => other.Name != property.Name).Select(other => JsonSerializer.Serialize(other.Name) + ":" + other.Value.GetRawText())) + "}";
            check(Fails(without, "missing field " + property.Name, out error), "launch parse: missing " + property.Name + " is rejected (" + error + ")");
        }

        check(Fails(GoldenCanonical.Replace("\"protocolVersion\":1", "\"protocolVersion\":\"1\"", StringComparison.Ordinal), "protocolVersion", out error), "launch parse: a string where a number belongs is rejected (" + error + ")");
        check(Fails(GoldenCanonical.Replace("\"protocolVersion\":1", "\"protocolVersion\":1.5", StringComparison.Ordinal), "protocolVersion", out error), "launch parse: a fraction where an integer belongs is rejected");
        check(Fails(GoldenCanonical.Replace("\"arguments\":[\"test\",\"--filter\",\"\\u00e9\"]", "\"arguments\":[\"test\",3]", StringComparison.Ordinal), "arguments", out error), "launch parse: a number inside a string list is rejected");
        check(Fails(GoldenCanonical.Replace("\"MODE\":\"ci\"", "\"MODE\":5", StringComparison.Ordinal), "envVariables", out error), "launch parse: a non-string environment value is rejected");
        check(Fails(GoldenCanonical.Replace("2026-11-01T12:00:00.0000000Z", "yesterday", StringComparison.Ordinal), "created", out error), "launch parse: a bad time is rejected");
        check(Fails(GoldenCanonical.Replace("\"secretNames\":[\"API_KEY\",\"team/DB_PASS\"]", "\"secretNames\":null", StringComparison.Ordinal), "secretNames", out error), "launch parse: null where a list belongs is rejected");

        // Parsing does not judge the version: that is Validate's job, so a version-2 message is still readable for its error.
        string v2 = GoldenCanonical.Replace("\"protocolVersion\":1", "\"protocolVersion\":2", StringComparison.Ordinal);
        check(LaunchRequest.TryParse(v2, out LaunchRequest? parsed, out _) && parsed!.Validate(Created.AddMinutes(1)) is { } problem && problem.Contains("protocol version 2", StringComparison.Ordinal), "launch parse: a version mismatch parses and is then rejected by validation");
    }

    private static void NoSecretValues(Action<bool, string> check)
    {
        Regex forbidden = new("secretvalue|plaintext|password|privatekey|storekey|^key$|unlock|decrypted|^values?$|secretbytes|secrettext|^payload$|^secrets$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        Type[] contracts = [typeof(LaunchRequest), typeof(LaunchMapping), typeof(LaunchResult), typeof(LaunchBinding)];
        HashSet<Type> seen = [];
        Queue<Type> queue = new(contracts);
        while (queue.Count > 0)
        {
            Type type = queue.Dequeue();
            if (!seen.Add(type) || type.IsEnum)
            {
                continue;
            }

            foreach (PropertyInfo property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.NonPublic))
            {
                if (property.Name == "EqualityContract")
                {
                    continue;
                }

                check(!forbidden.IsMatch(property.Name), "contracts hold no secret value: " + type.Name + "." + property.Name + " is not named like a secret value");
                bool allowed = property.PropertyType != typeof(byte[]) && property.PropertyType != typeof(Unlock) && property.PropertyType != typeof(SecretValues) && !property.PropertyType.Name.Contains("Secure", StringComparison.Ordinal) && property.PropertyType != typeof(ReadOnlyMemory<byte>) && property.PropertyType != typeof(Memory<byte>);
                check(allowed, "contracts hold no secret value: " + type.Name + "." + property.Name + " is not a byte buffer or a key holder (" + property.PropertyType.Name + ")");
                foreach (Type argument in property.PropertyType.GetGenericArguments().Append(property.PropertyType))
                {
                    if (argument.Namespace == typeof(LaunchRequest).Namespace && argument.Name.StartsWith("Launch", StringComparison.Ordinal))
                    {
                        queue.Enqueue(argument);
                    }
                }
            }

            foreach (FieldInfo field in type.GetFields(BindingFlags.Public | BindingFlags.Instance))
            {
                check(false, "contracts hold no secret value: " + type.Name + "." + field.Name + " is a public field");
            }
        }

        check(seen.Count == contracts.Length + 1 && seen.Contains(typeof(LaunchOutcome)), "contracts hold no secret value: every contract type was inspected (" + seen.Count + ")");

        // The result is exactly an outcome, an exit status and public text: no second payload.
        string[] resultFields = [.. typeof(LaunchResult).GetProperties().Where(property => property.Name != "EqualityContract").Select(property => property.Name).Order(StringComparer.Ordinal)];
        check(resultFields.SequenceEqual(["Detail", "ExitCode", "Outcome", "Output", "ProtocolVersion", "RequestId"]), "launch result: carries only the outcome, exit status and public text (" + string.Join(",", resultFields) + ")");
        check(typeof(LaunchResult).GetProperty("Output")!.PropertyType == typeof(string) && typeof(LaunchResult).GetProperty("Detail")!.PropertyType == typeof(string), "launch result: the output is text, the same text the terminal shows");
        check(!typeof(LaunchResult).GetMethods().Any(method => method.ReturnType == typeof(SecretValues)), "launch result: no method hands secret values to the caller");

        // The redactor is what makes the output public: a secret in the child's output never reaches the result text.
        const string secret = "Contract-Secret-5521";
        StreamRedactor redactor = new([secret]);
        string text = redactor.Push("token=" + secret + "\n") + redactor.Finish();
        LaunchResult result = LaunchResult.Exited(Sample().RequestId, 0, text);
        check(!result.Canonical().Contains(secret, StringComparison.Ordinal) && result.Output.Contains(StreamRedactor.Mask, StringComparison.Ordinal), "launch result: redacted output holds no secret value");
    }

    private static void Binding(Action<bool, string> check)
    {
        string folder = Path.Combine(Path.GetTempPath(), "ws-launch-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            string script = Path.Combine(folder, "run.sh");
            File.WriteAllText(script, "#!/bin/sh\necho hi\n");
            ApprovalRequest approval = new(
                "sh",
                OperatingSystem.IsWindows() ? "C:\\Windows\\System32\\cmd.exe" : "/bin/sh",
                [script, "--flag"],
                folder,
                "run the tests",
                ["API_KEY", "team/DB_PASS"],
                TypedArguments: ["./run.sh", "--flag"],
                Mappings: [new SecretMapping("API_KEY", "API_KEY"), new SecretMapping("DB", "team/DB_PASS")],
                EnvFiles: [Path.Combine(folder, ".env")],
                EnvNames: ["MODE"],
                EnvValues: new Dictionary<string, string> { ["MODE"] = "ci" });

            string before = RequestFingerprint.Compute(approval).Key;
            LaunchRequest request = LaunchRequestBinding.From(approval, "req-0002", "bm9uY2UtMDAwMDAwMDE", Created, Created.AddMinutes(5));
            check(request.Program == "sh" && request.Arguments.SequenceEqual(["./run.sh", "--flag"]) && request.WorkingDirectory == folder && request.Reason == "run the tests", "launch binding: the request carries the command as typed, the folder and the reason");
            check(request.SecretNames.SequenceEqual(["API_KEY", "team/DB_PASS"]) && request.Mappings.Select(mapping => mapping.Variable + "=" + mapping.Secret).SequenceEqual(["API_KEY=API_KEY", "DB=team/DB_PASS"]), "launch binding: the secret names and pairs are carried by name only");
            check(request.EnvVariables["MODE"] == "ci" && request.EnvNames.SequenceEqual(["MODE"]) && request.EnvFiles.Count == 1, "launch binding: the ordinary environment and the .env files are carried");
            check(LaunchRequestBinding.Mismatch(request, approval) is null, "launch binding: a request built from an approval matches it");

            LaunchBinding binding = LaunchRequestBinding.Bind(request, approval);
            check(binding.FingerprintKey == before && binding.FingerprintKey == RequestFingerprint.Compute(approval).Key, "launch binding: the approval fingerprint value is unchanged");
            check(binding.RequestDigest == request.Digest(), "launch binding: carries the request digest");
            check(binding.BoundDigest.Length == 64 && binding.BoundDigest != binding.RequestDigest && binding.BoundDigest != binding.FingerprintKey, "launch binding: the bound value is neither input alone");
            check(LaunchRequestBinding.Bind(request, approval).BoundDigest == binding.BoundDigest, "launch binding: deterministic");
            check(LaunchRequestBinding.Bind(request with { RequestId = "req-0003" }, approval).BoundDigest != binding.BoundDigest, "launch binding: a different request id (same fingerprint) is a different binding");
            check(LaunchRequestBinding.Bind(request with { ClientNonce = "ZGlmZmVyZW50LW5vbmNlLTAx" }, approval).BoundDigest != binding.BoundDigest, "launch binding: a different client nonce is a different binding");
            check(LaunchRequestBinding.Bind(request with { Expires = request.Expires.AddMinutes(1) }, approval).BoundDigest != binding.BoundDigest, "launch binding: a different expiry is a different binding");
            check(LaunchRequestBinding.Bind(request with { Reason = "another reason" }, approval with { Reason = "another reason" }).FingerprintKey == before, "launch binding: the reason is in the digest but not in the fingerprint, as before");

            // What was approved and what is asked must be the same request.
            foreach ((string name, LaunchRequest other) in new (string, LaunchRequest)[]
            {
                ("program", request with { Program = "bash" }),
                ("arguments", request with { Arguments = ["./run.sh"] }),
                ("folder", request with { WorkingDirectory = folder + "x" }),
                ("secret names", request with { SecretNames = ["API_KEY"] }),
                ("mappings", request with { Mappings = [new LaunchMapping("OTHER", "API_KEY")] }),
                ("reason", request with { Reason = "other" }),
                ("env values", request with { EnvVariables = new Dictionary<string, string> { ["MODE"] = "prod" } }),
                ("env names", request with { EnvNames = [] }),
                ("env files", request with { EnvFiles = [] }),
            })
            {
                check(LaunchRequestBinding.Mismatch(other, approval) is { } why && why.Contains(name, StringComparison.Ordinal), "launch binding: a request that differs in " + name + " does not match the approval");
                check(Throws(() => LaunchRequestBinding.Bind(other, approval)), "launch binding: binding a request that differs in " + name + " throws");
            }

            // A plain --secrets run (no Mappings on the approval) gets identical pairs, and keeps the fingerprint it always had.
            ApprovalRequest plain = new("sh", approval.ResolvedProgram, [script], folder, "r", ["API_KEY"]);
            LaunchRequest plainRequest = LaunchRequestBinding.From(plain, "req-0004", "bm9uY2UtMDAwMDAwMDE", Created, Created.AddMinutes(5));
            check(plainRequest.Mappings.Count == 1 && plainRequest.Mappings[0] == new LaunchMapping("API_KEY", "API_KEY") && LaunchRequestBinding.Bind(plainRequest, plain).FingerprintKey == RequestFingerprint.Compute(plain).Key, "launch binding: a plain secrets run maps each name to itself and keeps its fingerprint");
        }
        finally
        {
            Directory.Delete(folder, true);
        }
    }

    private static bool Throws(Action action)
    {
        try
        {
            action();

            return false;
        }
        catch (InvalidOperationException)
        {
            return true;
        }
    }

    private static void Result(Action<bool, string> check)
    {
        LaunchResult result = LaunchResult.Exited("req-0001", 3, "hello [REDACTED]\n");
        check(result.Canonical() == GoldenResult, "launch result: canonical text matches the golden vector (" + result.Canonical() + ")");
        check(LaunchResult.TryParse(GoldenResult, out LaunchResult? back, out string? error) && back == result, "launch result: parses back to the same result (" + error + ")");
        check(Enum.GetNames<LaunchOutcome>().Order().SequenceEqual(["Approved", "Cancelled", "Denied", "Exited", "Failed", "Launched"]), "launch result: the outcomes are denied, cancelled, failed, launched and exited, and approved (a grant made by approve; Phase 3)");
        check(LaunchResult.Denied("req-0001", "the user said no").Canonical().Contains("\"outcome\":\"denied\",\"exitCode\":null", StringComparison.Ordinal), "launch result: a denial has no exit status");
        check(!LaunchResult.TryParse(GoldenResult.Replace("\"exited\"", "\"vanished\"", StringComparison.Ordinal), out _, out error) && error is not null, "launch result: an unknown outcome is rejected");
        check(!LaunchResult.TryParse(GoldenResult.Replace("\"detail\":\"\"", "\"detail\":\"\",\"secret\":\"x\"", StringComparison.Ordinal), out _, out error) && error is not null && error.Contains("unknown field secret", StringComparison.Ordinal), "launch result: an unknown field (a smuggled payload) is rejected");
        check(!LaunchResult.TryParse(GoldenResult.Replace("\"protocolVersion\":1", "\"protocolVersion\":2", StringComparison.Ordinal), out _, out error) && error is not null && error.Contains("protocol version 2", StringComparison.Ordinal), "launch result: a version mismatch is rejected");
        check(!LaunchResult.TryParse(GoldenResult.Replace(",\"detail\":\"\"", "", StringComparison.Ordinal), out _, out error) && error is not null && error.Contains("missing field detail", StringComparison.Ordinal), "launch result: a missing field is rejected");
    }
}

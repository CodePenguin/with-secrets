using System.Globalization;
using System.Text;
using System.Text.Json;

namespace WithSecrets;

/// <summary>The operations of the authority protocol, one word each. They travel only inside the encrypted session: the relay never sees them.</summary>
internal static class RemoteOps
{
    public const string BeginEnrollment = "begin-enrollment";
    public const string Enroll = "enroll";
    public const string Decide = "decide";
    public const string KeyTransitions = "key-transitions";
    public const string PendingInvalidations = "pending-invalidations";
    public const string AcknowledgeInvalidation = "ack-invalidation";
    public const string Grant = "grant";
    public const string Reconcile = "reconcile";
    public const string PendingGrantEvents = "pending-grant-events";
    public const string AcknowledgeGrantEvent = "ack-grant-event";
    public const string AuditUpload = "audit-upload";

    /// <summary>Host to authority: authorize one launch at the authority (approval, decryption there), answered with a <see cref="LaunchAnswer" />. Never repeated under the same id.</summary>
    public const string LaunchAuthorize = "launch-authorize";

    /// <summary>Authority to host: where the approval page for a waiting launch is (a notification).</summary>
    public const string ApprovalLink = "approval-link";

    /// <summary>Authority to host: an invalidation has not been acknowledged yet (a notification; the pending list is the source of truth).</summary>
    public const string PushInvalidation = "push-invalidation";

    public static readonly string[] Requests =
    [
        BeginEnrollment, Enroll, Decide, KeyTransitions, PendingInvalidations, AcknowledgeInvalidation, Grant, Reconcile, PendingGrantEvents, AcknowledgeGrantEvent, AuditUpload, LaunchAuthorize,
    ];
}

/// <summary>One application message (a request, a push, or a response) after decryption.</summary>
internal sealed record WireMessage(string Id, string? Op, bool Ok, string Body, string Error)
{
    public bool IsRequest => Op is not null;
}

/// <summary>
/// The canonical, versioned application messages. A request is <c>{"v":1,"id":S,"op":S,"body":{...}}</c>, a response <c>{"v":1,"id":S,"ok":true,"body":{...}}</c> or
/// <c>{"v":1,"id":S,"ok":false,"error":S}</c> (a code, never a value). The id names the logical operation: a retry reuses it. The bodies are the existing signed contract
/// types (machine envelopes in, authority answers out), each in its own canonical JSON with its signature as the last member; reading is strict (every member, none unknown or repeated).
/// </summary>
internal static class RemoteWire
{
    public const int Version = 1;
    public const int MaxId = 200;

    private static string Q(string text)
    {
        StringBuilder builder = new();
        ToolSettings.QuoteJson(builder, text);

        return builder.ToString();
    }

    public static string Request(string id, string op, string body) => "{\"v\":1,\"id\":" + Q(id) + ",\"op\":" + Q(op) + ",\"body\":" + body + "}";

    public static string Response(string id, string body) => "{\"v\":1,\"id\":" + Q(id) + ",\"ok\":true,\"body\":" + body + "}";

    public static string Failure(string id, string error) => "{\"v\":1,\"id\":" + Q(id) + ",\"ok\":false,\"error\":" + Q(error) + "}";

    public static bool TryReadMessage(byte[] plaintext, out WireMessage? message)
    {
        message = null;
        string json;
        try
        {
            json = new UTF8Encoding(false, true).GetString(plaintext);
        }
        catch (DecoderFallbackException)
        {
            return false;
        }

        if (!CanonicalJson.Open(json, out JsonDocument? doc, out _))
        {
            return false;
        }

        using (doc)
        {
            JsonElement root = doc!.RootElement;
            bool request = root.TryGetProperty("op", out _);
            ContractReader reader = request ? new(root, "v", "id", "op", "body") : root.TryGetProperty("ok", out JsonElement okElement) && okElement.ValueKind == JsonValueKind.False ? new(root, "v", "id", "ok", "error") : new(root, "v", "id", "ok", "body");
            if (reader.Problem is not null || !reader.Int("v", out int version) || version != Version || !reader.Text("id", out string? id) || id is null || id.Length is 0 or > MaxId)
            {
                return false;
            }

            if (request)
            {
                if (!reader.Text("op", out string? op) || !reader.Object("body", out JsonElement body))
                {
                    return false;
                }

                message = new WireMessage(id, op, true, body.GetRawText(), "");

                return true;
            }

            if (!reader.Bool("ok", out bool ok))
            {
                return false;
            }

            if (!ok)
            {
                if (!reader.Text("error", out string? error))
                {
                    return false;
                }

                message = new WireMessage(id, null, false, "", error!);

                return true;
            }

            if (!reader.Object("body", out JsonElement answer))
            {
                return false;
            }

            message = new WireMessage(id, null, true, answer.GetRawText(), "");

            return true;
        }
    }

    // ---- helpers ----

    private static string WithSignature(string canonical, byte[] signature) => canonical[..^1] + ",\"signature\":" + Q(Convert.ToBase64String(signature)) + "}";

    private static bool Signature(string text, out byte[] bytes)
    {
        bytes = new byte[64];

        return Convert.TryFromBase64String(text, bytes, out int written) && written == 64;
    }

    private static bool Base64(string text, int maximum, out byte[] bytes)
    {
        bytes = new byte[maximum];
        if (!Convert.TryFromBase64String(text, bytes, out int written))
        {
            return false;
        }

        bytes = bytes[..written];

        return true;
    }

    private static bool Open(string json, out JsonDocument? doc) => CanonicalJson.Open(json, out doc, out _);

    // ---- launch authorization ----

    public static string Write(LaunchAuthorize message) => "{\"decide\":" + Write(message.Decide) + ",\"use\":" + Write(message.Use) + ",\"context\":" + message.Context.Canonical() + ",\"contextSignature\":" + Q(Convert.ToBase64String(message.ContextSignature)) + "}";

    public static bool TryRead(string json, out LaunchAuthorize? message)
    {
        message = null;
        if (!Open(json, out JsonDocument? doc))
        {
            return false;
        }

        using (doc)
        {
            ContractReader reader = new(doc!.RootElement, "decide", "use", "context", "contextSignature");
            if (reader.Problem is not null || !reader.Object("decide", out JsonElement decideElement) || !reader.Object("use", out JsonElement useElement) || !reader.Object("context", out JsonElement contextElement) || !reader.Text("contextSignature", out string? signatureText)
                || !Signature(signatureText!, out byte[] signature) || !TryRead(decideElement.GetRawText(), out MachineRequestEnvelope? decide) || !TryRead(useElement.GetRawText(), out GrantEnvelope? use) || !PageContext.TryRead(contextElement, out PageContext? context))
            {
                return false;
            }

            message = new LaunchAuthorize(decide!, use!, context!, signature);

            return true;
        }
    }

    // ---- machine messages ----

    public static string Write(MachineRequestEnvelope envelope) => WithSignature(envelope.Canonical(), envelope.Signature);

    public static bool TryRead(string json, out MachineRequestEnvelope? envelope)
    {
        envelope = null;
        if (!Open(json, out JsonDocument? doc))
        {
            return false;
        }

        using (doc)
        {
            ContractReader reader = new(doc!.RootElement, "protocolVersion", "machineFingerprint", "hostName", "requestDigest", "request", "signature");
            if (reader.Problem is not null || !reader.Int("protocolVersion", out int version) || !reader.Text("machineFingerprint", out string? machine) || !reader.Text("hostName", out string? host) || !reader.Text("requestDigest", out string? digest)
                || !reader.Object("request", out JsonElement requestElement) || !reader.Text("signature", out string? signatureText) || !Signature(signatureText!, out byte[] signature) || !LaunchRequest.TryParse(requestElement.GetRawText(), out LaunchRequest? request, out _))
            {
                return false;
            }

            envelope = new MachineRequestEnvelope(version, machine!, host!, digest!, request!, signature);

            return true;
        }
    }

    public static string Write(GrantEnvelope envelope) => WithSignature(envelope.Canonical(), envelope.Signature);

    public static bool TryRead(string json, out GrantEnvelope? envelope)
    {
        envelope = null;
        if (!Open(json, out JsonDocument? doc))
        {
            return false;
        }

        using (doc)
        {
            ContractReader reader = new(doc!.RootElement, "protocolVersion", "operation", "machineFingerprint", "hostName", "requestDigest", "scopeKey", "request", "signature");
            if (reader.Problem is not null || !reader.Int("protocolVersion", out int version) || !reader.Text("operation", out string? operation) || !reader.Text("machineFingerprint", out string? machine) || !reader.Text("hostName", out string? host)
                || !reader.Text("requestDigest", out string? digest) || !reader.Text("scopeKey", out string? scope) || !reader.Object("request", out JsonElement requestElement) || !reader.Text("signature", out string? signatureText)
                || !Signature(signatureText!, out byte[] signature) || !LaunchRequest.TryParse(requestElement.GetRawText(), out LaunchRequest? request, out _))
            {
                return false;
            }

            envelope = new GrantEnvelope(version, operation!, machine!, host!, digest!, scope!, request!, signature);

            return true;
        }
    }

    public static string Write(ReconcileEnvelope envelope) => WithSignature(envelope.Canonical(), envelope.Signature);

    public static bool TryRead(string json, out ReconcileEnvelope? envelope)
    {
        envelope = null;
        if (!Open(json, out JsonDocument? doc))
        {
            return false;
        }

        using (doc)
        {
            ContractReader reader = new(doc!.RootElement, "protocolVersion", "requestId", "machineFingerprint", "hostName", "created", "signature");
            if (reader.Problem is not null || !reader.Int("protocolVersion", out int version) || !reader.Text("requestId", out string? id) || !reader.Text("machineFingerprint", out string? machine) || !reader.Text("hostName", out string? host)
                || !reader.Time("created", out DateTimeOffset created) || !reader.Text("signature", out string? signatureText) || !Signature(signatureText!, out byte[] signature))
            {
                return false;
            }

            envelope = new ReconcileEnvelope(version, id!, machine!, host!, created, signature);

            return true;
        }
    }

    public static string Write(ReconcileResponse response) => WithSignature(response.Canonical(), response.Signature);

    public static bool TryRead(string json, out ReconcileResponse? response)
    {
        response = null;
        if (!Open(json, out JsonDocument? doc))
        {
            return false;
        }

        using (doc)
        {
            ContractReader reader = new(doc!.RootElement, "protocolVersion", "requestId", "requestDigest", "machineFingerprint", "status", "hostName", "securityRevision", "leaseSeconds", "issued", "expires", "authorityKeyId", "signature");
            if (reader.Problem is not null || !reader.Int("protocolVersion", out int version) || !reader.Text("requestId", out string? id) || !reader.Text("requestDigest", out string? digest) || !reader.Text("machineFingerprint", out string? machine)
                || !reader.Text("status", out string? status) || !reader.Text("hostName", out string? bound) || bound is not ("bound" or "mismatch") || !reader.Int("securityRevision", out int revision) || !reader.Int("leaseSeconds", out int lease)
                || !reader.Time("issued", out DateTimeOffset issued) || !reader.Time("expires", out DateTimeOffset expires) || !reader.Text("authorityKeyId", out string? keyId) || !reader.Text("signature", out string? signatureText) || !Signature(signatureText!, out byte[] signature))
            {
                return false;
            }

            response = new ReconcileResponse(version, id!, digest!, machine!, status!, bound == "bound", revision, lease, issued, expires, keyId!, signature);

            return true;
        }
    }

    public static string Write(AuditBatch batch)
    {
        StringBuilder text = new("{\"batchId\":");
        ToolSettings.QuoteJson(text, batch.BatchId);
        text.Append(",\"machineFingerprint\":");
        ToolSettings.QuoteJson(text, batch.MachineFingerprint);
        text.Append(",\"events\":[");
        for (int index = 0; index < batch.Events.Count; index++)
        {
            text.Append(index == 0 ? "" : ",").Append(batch.Events[index].ToJson());
        }

        return text.Append("]}").ToString();
    }

    public static bool TryRead(string json, out AuditBatch? batch)
    {
        batch = null;
        if (!Open(json, out JsonDocument? doc))
        {
            return false;
        }

        using (doc)
        {
            ContractReader reader = new(doc!.RootElement, "batchId", "machineFingerprint", "events");
            if (reader.Problem is not null || !reader.Text("batchId", out string? id) || !reader.Text("machineFingerprint", out string? machine) || !reader.Array("events", out JsonElement array))
            {
                return false;
            }

            List<AuditEvent> events = [];
            foreach (JsonElement item in array.EnumerateArray())
            {
                if (!AuditEvent.TryParse(item.GetRawText(), out AuditEvent? parsed, out _))
                {
                    return false;
                }

                events.Add(parsed!);
            }

            batch = new AuditBatch(id!, machine!, events);

            return true;
        }
    }

    public static string Write(AuditAck ack) => WithSignature(ack.Canonical(), ack.Signature);

    public static bool TryRead(string json, out AuditAck? ack)
    {
        ack = null;
        if (!Open(json, out JsonDocument? doc))
        {
            return false;
        }

        using (doc)
        {
            ContractReader reader = new(doc!.RootElement, "protocolVersion", "requestId", "requestDigest", "machineFingerprint", "entries", "issued", "expires", "authorityKeyId", "signature");
            if (reader.Problem is not null || !reader.Int("protocolVersion", out int version) || !reader.Text("requestId", out string? id) || !reader.Text("requestDigest", out string? digest) || !reader.Text("machineFingerprint", out string? machine)
                || !reader.Array("entries", out JsonElement array) || !reader.Time("issued", out DateTimeOffset issued) || !reader.Time("expires", out DateTimeOffset expires) || !reader.Text("authorityKeyId", out string? keyId)
                || !reader.Text("signature", out string? signatureText) || !Signature(signatureText!, out byte[] signature))
            {
                return false;
            }

            List<AuditAckEntry> entries = [];
            foreach (JsonElement item in array.EnumerateArray())
            {
                ContractReader entry = new(item, "eventId", "status", "detail") { Where = "entries" };
                if (entry.Problem is not null || !entry.Text("eventId", out string? eventId) || !entry.Text("status", out string? status) || !entry.Text("detail", out string? detail))
                {
                    return false;
                }

                entries.Add(new AuditAckEntry(eventId!, status!, detail!));
            }

            ack = new AuditAck(version, id!, digest!, machine!, entries, issued, expires, keyId!, signature);

            return true;
        }
    }

    // ---- enrollment ----

    public static string Write(EnrollmentRequest request)
    {
        StringBuilder text = new("{\"fingerprint\":");
        ToolSettings.QuoteJson(text, request.Fingerprint);
        text.Append(",\"publicKey\":");
        ToolSettings.QuoteJson(text, Convert.ToBase64String(request.PublicKey));
        text.Append(",\"hostName\":");
        ToolSettings.QuoteJson(text, request.HostName);
        text.Append(",\"challenge\":");
        ToolSettings.QuoteJson(text, Convert.ToBase64String(request.Challenge));
        text.Append(",\"signature\":");
        ToolSettings.QuoteJson(text, Convert.ToBase64String(request.Signature));

        return text.Append('}').ToString();
    }

    public static bool TryRead(string json, out EnrollmentRequest? request)
    {
        request = null;
        if (!Open(json, out JsonDocument? doc))
        {
            return false;
        }

        using (doc)
        {
            ContractReader reader = new(doc!.RootElement, "fingerprint", "publicKey", "hostName", "challenge", "signature");
            if (reader.Problem is not null || !reader.Text("fingerprint", out string? fingerprint) || !reader.Text("publicKey", out string? keyText) || !Base64(keyText!, 256, out byte[] key) || !reader.Text("hostName", out string? host)
                || !reader.Text("challenge", out string? challengeText) || !Base64(challengeText!, 256, out byte[] challenge) || !reader.Text("signature", out string? signatureText) || !Signature(signatureText!, out byte[] signature))
            {
                return false;
            }

            request = new EnrollmentRequest(fingerprint!, key, host!, challenge, signature);

            return true;
        }
    }

    public static string Write(EnrollmentResult result)
    {
        StringBuilder text = new("{\"accepted\":");
        text.Append(result.Accepted ? "true" : "false").Append(",\"status\":");
        ToolSettings.QuoteJson(text, result.Status.ToString());
        text.Append(",\"fingerprint\":");
        ToolSettings.QuoteJson(text, result.Fingerprint);
        text.Append(",\"message\":");
        ToolSettings.QuoteJson(text, result.Message);

        return text.Append('}').ToString();
    }

    public static bool TryRead(string json, out EnrollmentResult? result)
    {
        result = null;
        if (!Open(json, out JsonDocument? doc))
        {
            return false;
        }

        using (doc)
        {
            ContractReader reader = new(doc!.RootElement, "accepted", "status", "fingerprint", "message");
            if (reader.Problem is not null || !reader.Bool("accepted", out bool accepted) || !reader.Text("status", out string? statusText) || !Enum.TryParse(statusText, false, out MachineStatus status) || !Enum.IsDefined(status)
                || !reader.Text("fingerprint", out string? fingerprint) || !reader.Text("message", out string? message))
            {
                return false;
            }

            result = new EnrollmentResult(accepted, status, fingerprint!, message!);

            return true;
        }
    }

    public static string WriteChallenge(byte[] challenge) => "{\"challenge\":" + Q(Convert.ToBase64String(challenge)) + "}";

    public static bool TryReadChallenge(string json, out byte[] challenge)
    {
        challenge = [];
        if (!Open(json, out JsonDocument? doc))
        {
            return false;
        }

        using (doc)
        {
            ContractReader reader = new(doc!.RootElement, "challenge");

            return reader.Problem is null && reader.Text("challenge", out string? text) && Base64(text!, 256, out challenge) && challenge.Length > 0;
        }
    }

    // ---- small bodies ----

    public static string WriteAfter(string fingerprint) => "{\"after\":" + Q(fingerprint) + "}";

    public static string WriteFingerprint(string fingerprint) => "{\"fingerprint\":" + Q(fingerprint) + "}";

    public static string WriteAck(string fingerprint, long number, bool revision) => "{\"fingerprint\":" + Q(fingerprint) + ",\"" + (revision ? "revision" : "sequence") + "\":" + number.ToString(CultureInfo.InvariantCulture) + "}";

    public static bool TryReadText(string json, string name, out string value)
    {
        value = "";
        if (!Open(json, out JsonDocument? doc))
        {
            return false;
        }

        using (doc)
        {
            ContractReader reader = new(doc!.RootElement, name);
            if (reader.Problem is not null || !reader.Text(name, out string? text))
            {
                return false;
            }

            value = text!;

            return true;
        }
    }

    public static bool TryReadAck(string json, bool revision, out string fingerprint, out long number)
    {
        fingerprint = "";
        number = 0;
        if (!Open(json, out JsonDocument? doc))
        {
            return false;
        }

        using (doc)
        {
            string name = revision ? "revision" : "sequence";
            ContractReader reader = new(doc!.RootElement, "fingerprint", name);
            if (reader.Problem is not null || !reader.Text("fingerprint", out string? text) || !reader.Long(name, out number))
            {
                return false;
            }

            fingerprint = text!;

            return true;
        }
    }

    public static string Empty => "{}";

    public static string Write(IReadOnlyList<KeyTransition> transitions)
    {
        StringBuilder text = new("{\"transitions\":[");
        for (int index = 0; index < transitions.Count; index++)
        {
            KeyTransition item = transitions[index];
            text.Append(index == 0 ? "" : ",").Append("{\"oldFingerprint\":");
            ToolSettings.QuoteJson(text, item.OldFingerprint);
            text.Append(",\"newFingerprint\":");
            ToolSettings.QuoteJson(text, item.NewFingerprint);
            text.Append(",\"newPublicKey\":");
            ToolSettings.QuoteJson(text, Convert.ToBase64String(item.NewPublicKey));
            text.Append(",\"created\":");
            ToolSettings.QuoteJson(text, CanonicalJson.Time(item.Created));
            text.Append(",\"signature\":");
            ToolSettings.QuoteJson(text, Convert.ToBase64String(item.Signature));
            text.Append('}');
        }

        return text.Append("]}").ToString();
    }

    public static bool TryReadTransitions(string json, out List<KeyTransition> transitions)
    {
        transitions = [];
        if (!Open(json, out JsonDocument? doc))
        {
            return false;
        }

        using (doc)
        {
            ContractReader reader = new(doc!.RootElement, "transitions");
            if (reader.Problem is not null || !reader.Array("transitions", out JsonElement array) || array.GetArrayLength() > 64)
            {
                return false;
            }

            foreach (JsonElement item in array.EnumerateArray())
            {
                ContractReader entry = new(item, "oldFingerprint", "newFingerprint", "newPublicKey", "created", "signature") { Where = "transitions" };
                if (entry.Problem is not null || !entry.Text("oldFingerprint", out string? old) || !entry.Text("newFingerprint", out string? current) || !entry.Text("newPublicKey", out string? keyText) || !Base64(keyText!, 256, out byte[] key)
                    || !entry.Time("created", out DateTimeOffset created) || !entry.Text("signature", out string? signatureText) || !Signature(signatureText!, out byte[] signature))
                {
                    return false;
                }

                transitions.Add(new KeyTransition(old!, current!, key, created, signature));
            }

            return true;
        }
    }

    public static string Write(IReadOnlyList<PendingInvalidation> items)
    {
        StringBuilder text = new("{\"items\":[");
        for (int index = 0; index < items.Count; index++)
        {
            text.Append(index == 0 ? "" : ",").Append("{\"fingerprint\":");
            ToolSettings.QuoteJson(text, items[index].Fingerprint);
            text.Append(",\"revision\":").Append(items[index].Revision.ToString(CultureInfo.InvariantCulture)).Append('}');
        }

        return text.Append("]}").ToString();
    }

    public static bool TryReadInvalidations(string json, out List<PendingInvalidation> items)
    {
        items = [];
        if (!Open(json, out JsonDocument? doc))
        {
            return false;
        }

        using (doc)
        {
            ContractReader reader = new(doc!.RootElement, "items");
            if (reader.Problem is not null || !reader.Array("items", out JsonElement array) || array.GetArrayLength() > 1000)
            {
                return false;
            }

            foreach (JsonElement item in array.EnumerateArray())
            {
                ContractReader entry = new(item, "fingerprint", "revision") { Where = "items" };
                if (entry.Problem is not null || !entry.Text("fingerprint", out string? fingerprint) || !entry.Int("revision", out int revision))
                {
                    return false;
                }

                items.Add(new PendingInvalidation(fingerprint!, revision));
            }

            return true;
        }
    }

    public static string Write(IReadOnlyList<PendingGrantEvent> items)
    {
        StringBuilder text = new("{\"items\":[");
        for (int index = 0; index < items.Count; index++)
        {
            PendingGrantEvent item = items[index];
            text.Append(index == 0 ? "" : ",").Append("{\"sequence\":").Append(item.Sequence.ToString(CultureInfo.InvariantCulture)).Append(",\"fingerprint\":");
            ToolSettings.QuoteJson(text, item.Fingerprint);
            text.Append(",\"grantId\":");
            ToolSettings.QuoteJson(text, item.GrantId);
            text.Append(",\"scopeKey\":");
            ToolSettings.QuoteJson(text, item.ScopeKey);
            text.Append(",\"kind\":");
            ToolSettings.QuoteJson(text, item.Kind);
            text.Append(",\"grantRevision\":").Append(item.GrantRevision.ToString(CultureInfo.InvariantCulture)).Append('}');
        }

        return text.Append("]}").ToString();
    }

    public static bool TryReadGrantEvents(string json, out List<PendingGrantEvent> items)
    {
        items = [];
        if (!Open(json, out JsonDocument? doc))
        {
            return false;
        }

        using (doc)
        {
            ContractReader reader = new(doc!.RootElement, "items");
            if (reader.Problem is not null || !reader.Array("items", out JsonElement array) || array.GetArrayLength() > 1000)
            {
                return false;
            }

            foreach (JsonElement item in array.EnumerateArray())
            {
                ContractReader entry = new(item, "sequence", "fingerprint", "grantId", "scopeKey", "kind", "grantRevision") { Where = "items" };
                if (entry.Problem is not null || !entry.Long("sequence", out long sequence) || !entry.Text("fingerprint", out string? fingerprint) || !entry.Text("grantId", out string? grantId) || !entry.Text("scopeKey", out string? scope)
                    || !entry.Text("kind", out string? kind) || !entry.Int("grantRevision", out int revision))
                {
                    return false;
                }

                items.Add(new PendingGrantEvent(sequence, fingerprint!, grantId!, scope!, kind!, revision));
            }

            return true;
        }
    }

    public static string Digest(string body) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(body)));
}

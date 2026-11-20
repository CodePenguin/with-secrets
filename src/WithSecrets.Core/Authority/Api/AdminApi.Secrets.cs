using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace WithSecrets;

/// <summary>Entering and removing secrets in the administration app (see <see cref="SecretFlows" />).</summary>
internal sealed partial class AdminApi
{
    /// <summary>A sealed value of one secret is at most 4096 characters; the sealed payload and its assertion fit in this.</summary>
    private const int SecretBodyLimit = 49152;

    private static JsonObject SecretNamesBody() => S.Obj([("names", S.Arr(S.Str(max: 80)))]);

    private static JsonObject SecretSealBody() => S.Obj(
    [
        ("epk", S.Str(max: 200)),
        ("iv", S.Str(max: 64)),
        ("ct", S.Str(max: SecretBodyLimit)),
    ]);

    private static JsonObject SecretSaveBody() => S.Obj(
    [
        ("epk", S.Str(max: 200)),
        ("iv", S.Str(max: 64)),
        ("ct", S.Str(max: SecretBodyLimit)),
        ("id", S.Str(max: 2048)),
        ("authenticatorData", S.Str(max: 4096)),
        ("clientDataJSON", S.Str(max: 4096)),
        ("signature", S.Str(max: 4096)),
    ]);

    private static JsonObject SecretRemovalSaveBody() => S.Obj([("proof", ApprovalAssertionSchema())]);

    private bool SecretsReady(ApiCall call, out SecretFlows flows, out string sessionId, out ApiResult? refusal)
    {
        flows = admin.Secrets!;
        sessionId = call.Session?.Id ?? "";
        refusal = null;
        if (call.Session is null)
        {
            refusal = new ApiResult(401, new ApiProblem(401, "session-required", "this needs an administrator session; sign in with a passkey"));

            return false;
        }

        if (admin.Secrets is null)
        {
            refusal = new ApiResult(503, new ApiProblem(503, "internal-error", "the secret store cannot be changed from this service"));

            return false;
        }

        return true;
    }

    private static ApiResult SecretProblem(int status, string detail)
    {
        string code = status switch { 400 => "invalid-request", 403 => "proof-invalid", 404 => "request-unavailable", _ => "internal-error" };

        return new ApiResult(status, new ApiProblem(status, code, detail));
    }

    /// <summary>The set page's answer (a JSON body with ok and, for a refusal, error) as an API answer.</summary>
    private static ApiResult SecretAnswer((int Status, string Body) answer)
    {
        using JsonDocument document = JsonDocument.Parse(answer.Body);
        if (answer.Status == 200)
        {
            return new ApiResult(200, document.RootElement.Clone());
        }

        string detail = document.RootElement.ValueKind == JsonValueKind.Object && document.RootElement.TryGetProperty("error", out JsonElement error) && error.ValueKind == JsonValueKind.String
            ? error.GetString()!
            : answer.Status == 403 ? "the passkey proof was not accepted; nothing was stored" : "the values could not be used; nothing was stored";

        return SecretProblem(answer.Status, detail);
    }

    private static bool ValidEntryId(string id) => Regex.IsMatch(id, "^[A-Za-z0-9_-]{8,64}$");

    private Task<ApiResult> ListSecretsAsync(ApiCall call)
    {
        if (admin.Secrets is not { } flows)
        {
            return Task.FromResult(new ApiResult(200, new { items = Array.Empty<string>() }));
        }

        (IReadOnlyList<string>? names, string? problem) = flows.List();

        return Task.FromResult(names is not null ? new ApiResult(200, new { items = names }) : SecretProblem(500, problem!));
    }

    private static List<string> NamesOf(JsonElement body)
    {
        List<string> names = [];
        foreach (JsonElement item in body.GetProperty("names").EnumerateArray())
        {
            names.Add(item.ValueKind == JsonValueKind.String ? item.GetString()! : "");
        }

        return names;
    }

    private Task<ApiResult> StartSecretEntryAsync(ApiCall call)
    {
        if (!SecretsReady(call, out SecretFlows flows, out string sessionId, out ApiResult? refusal))
        {
            return Task.FromResult(refusal!);
        }

        (SecretEntryDto? entry, string? problem) = flows.StartSet(NamesOf(call.Body!.Value), sessionId, call.Context.Request.Headers.Origin.ToString());

        return Task.FromResult(entry is not null ? new ApiResult(201, entry) : SecretProblem(400, problem!));
    }

    private Task<ApiResult> SealSecretEntryAsync(ApiCall call)
    {
        if (!SecretsReady(call, out SecretFlows flows, out string sessionId, out ApiResult? refusal))
        {
            return Task.FromResult(refusal!);
        }

        string id = call.Path["id"];
        (int Status, string Body)? answer = ValidEntryId(id) ? flows.Seal(id, sessionId, call.Body!.Value.GetRawText()) : null;

        return Task.FromResult(answer is { } sealedAnswer ? SecretAnswer(sealedAnswer) : SecretProblem(404, "no such entry is open"));
    }

    private Task<ApiResult> SaveSecretEntryAsync(ApiCall call)
    {
        if (!SecretsReady(call, out SecretFlows flows, out string sessionId, out ApiResult? refusal))
        {
            return Task.FromResult(refusal!);
        }

        string id = call.Path["id"];
        (int Status, string Body)? answer = ValidEntryId(id) ? flows.SaveSet(id, sessionId, call.Body!.Value.GetRawText()) : null;

        return Task.FromResult(answer is { } saved ? SecretAnswer(saved) : SecretProblem(404, "no such entry is open"));
    }

    private Task<ApiResult> CancelSecretEntryAsync(ApiCall call)
    {
        if (!SecretsReady(call, out SecretFlows flows, out string sessionId, out ApiResult? refusal))
        {
            return Task.FromResult(refusal!);
        }

        string id = call.Path["id"];

        return Task.FromResult(ValidEntryId(id) && flows.Cancel(id, sessionId) ? new ApiResult(200, new { ok = true }) : SecretProblem(404, "no such entry is open"));
    }

    private Task<ApiResult> StartSecretRemovalAsync(ApiCall call)
    {
        if (!SecretsReady(call, out SecretFlows flows, out string sessionId, out ApiResult? refusal))
        {
            return Task.FromResult(refusal!);
        }

        (SecretRemovalDto? removal, string? problem) = flows.StartRemove(NamesOf(call.Body!.Value), sessionId, call.Context.Request.Headers.Origin.ToString());

        return Task.FromResult(removal is not null ? new ApiResult(201, removal) : SecretProblem(400, problem!));
    }

    private Task<ApiResult> SaveSecretRemovalAsync(ApiCall call)
    {
        if (!SecretsReady(call, out SecretFlows flows, out string sessionId, out ApiResult? refusal))
        {
            return Task.FromResult(refusal!);
        }

        string id = call.Path["id"];
        (int Status, string Detail)? answer = ValidEntryId(id) ? flows.SaveRemove(id, sessionId, call.Body!.Value.GetProperty("proof").GetRawText()) : null;

        return Task.FromResult(answer switch
        {
            null => SecretProblem(404, "no such removal is open"),
            { Status: 200 } => new ApiResult(200, new { ok = true }),
            { } failed => SecretProblem(failed.Status, failed.Detail),
        });
    }
}

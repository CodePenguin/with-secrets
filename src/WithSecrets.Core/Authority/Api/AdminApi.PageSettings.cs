using System.Text.Json;
using System.Text.Json.Nodes;

namespace WithSecrets;

/// <summary>Reading and changing the settings of the pages this machine serves, in the administration app (see <see cref="SecretFlows" />).</summary>
internal sealed partial class AdminApi
{
    private static JsonObject PageSettingsBody() => S.Obj(
    [
        ("reuseMaxMinutes", S.Int(ReuseSettings.MinMaxMinutes, ReuseSettings.MaxMinutes, description: "The longest time a grant may be made for.")),
        ("baseUrl", S.Str(max: ToolSettings.MaxBaseUrlLength, nullable: true, description: "Reserved. Use null when the authority serves its canonical HTTPS origin.")),
        ("port", S.Int(0, ToolSettings.MaxPort, description: "Reserved for browser HTTPS. Use 0; the service determines its browser port.")),
        ("timeoutMinutes", S.Int(ToolSettings.MinTimeoutMinutes, ApprovalSettings.MaxTimeoutMinutes, description: "How long the program waits for an answer on a page.")),
    ]);

    private static object PageSettingsView(ToolSettings settings) => new { reuseMaxMinutes = settings.ReuseMaxMinutes, baseUrl = settings.BaseUrl, port = settings.Port, timeoutMinutes = settings.TimeoutMinutes };

    private Task<ApiResult> GetPageSettingsAsync(ApiCall call)
    {
        if (admin.Secrets is not { } flows)
        {
            // No local state to hold them (a service without the secret store): the pages use the defaults.
            return Task.FromResult(new ApiResult(200, PageSettingsView(ToolSettings.Defaults)));
        }

        (ToolSettings? settings, string? problem) = flows.PageSettings();

        return Task.FromResult(settings is not null ? new ApiResult(200, PageSettingsView(settings)) : SecretProblem(500, problem!));
    }

    private Task<ApiResult> StartPageSettingsChangeAsync(ApiCall call)
    {
        if (!SecretsReady(call, out SecretFlows flows, out string sessionId, out ApiResult? refusal))
        {
            return Task.FromResult(refusal!);
        }

        JsonElement body = call.Body!.Value;
        JsonElement url = body.GetProperty("baseUrl");
        ToolSettings requested = new(
            body.GetProperty("reuseMaxMinutes").GetInt32(),
            url.ValueKind == JsonValueKind.Null ? null : url.GetString(),
            body.GetProperty("port").GetInt32(),
            body.GetProperty("timeoutMinutes").GetInt32());
        if (HttpsOnly && (requested.BaseUrl is not null || requested.Port != 0))
        {
            return Task.FromResult(SecretProblem(400, "set the browser port when starting the authority. The HTTPS hostname is fixed."));
        }

        (SettingsChangeDto? change, string? problem) = flows.StartSettings(requested, sessionId, call.Context.Request.Headers.Origin.ToString());

        return Task.FromResult(change is not null ? new ApiResult(201, change) : SecretProblem(400, problem!));
    }

    private Task<ApiResult> SavePageSettingsChangeAsync(ApiCall call)
    {
        if (!SecretsReady(call, out SecretFlows flows, out string sessionId, out ApiResult? refusal))
        {
            return Task.FromResult(refusal!);
        }

        string id = call.Path["id"];
        (int Status, string Detail)? answer = ValidEntryId(id) ? flows.SaveSettings(id, sessionId, call.Body!.Value.GetProperty("proof").GetRawText()) : null;

        return Task.FromResult(answer switch
        {
            null => SecretProblem(404, "no such change is open"),
            { Status: 200 } => new ApiResult(200, new { ok = true }),
            { } failed => SecretProblem(failed.Status, failed.Detail),
        });
    }
}

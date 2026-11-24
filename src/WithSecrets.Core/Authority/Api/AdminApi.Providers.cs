using System.Text.Json;
using System.Text.Json.Nodes;

namespace WithSecrets;

internal sealed partial class AdminApi
{
    private IReadOnlyList<ApiRoute> ProviderRoutes() =>
    [
        new("GET", Prefix + "/providers", "listProviders", "List configured provider instances.", "providers", ApiAccess.Read, 200, "ProviderList", null, [], null,
            _ => Task.FromResult(new ApiResult(200, admin.Providers?.Providers() ?? []))),
        new("GET", Prefix + "/providers/{id}", "getProvider", "Read one provider instance by id.", "providers", ApiAccess.Read, 200, "Provider", null, [], null, GetProviderAsync),
        // The dispatcher uses the last match, so the literal path must follow the id route.
        new("GET", Prefix + "/providers/types", "listProviderTypes", "List registered provider types.", "providers", ApiAccess.Read, 200, "ProviderTypeList", null, [], null,
            _ => Task.FromResult(new ApiResult(200, admin.Providers?.Types() ?? []))),
        new("GET", Prefix + "/providers/{id}/mounts", "listProviderMounts", "List mounts of a provider instance.", "providers", ApiAccess.Read, 200, "MountList", null, [], null,
            call => Task.FromResult(ProviderRead(call, (providers, id) => providers.Mounts(id)))),
        new("GET", Prefix + "/mounts", "listMounts", "List all provider mounts.", "providers", ApiAccess.Read, 200, "MountList", null, [], null,
            _ => Task.FromResult(new ApiResult(200, admin.Providers?.Mounts() ?? []))),
        new("GET", Prefix + "/mounts/{id}/entries", "listMountEntries", "List namespace entry metadata for a mount.", "providers", ApiAccess.Read, 200, "NamespaceEntryList", null, [], null,
            call => Task.FromResult(ProviderRead(call, (providers, id) => providers.Entries(id)))),
        new("POST", Prefix + "/providers/validate", "validateProvider", "Validate a proposed provider configuration or mount path.", "providers", ApiAccess.Authorize, 200,
            "ProviderValidation", ProviderValidationBody(), [], null, ValidateProviderAsync, BodyLimit: ConfigurationBodyLimit),
        new("POST", Prefix + "/mounts/{id}/refresh", "refreshMount", "Refresh the namespace entries of a mount from its provider.", "providers", ApiAccess.Authorize, 200,
            "MountRefresh", null, [], null, RefreshMountAsync),
        Mutation("POST", "/providers", "provider-add", "addProvider", "Add a provider instance.", "providers", "name", "type", "config", "max-stale-seconds", "confirm-warnings"),
        Mutation("PUT", "/providers/{id}/config", "provider-config", "changeProviderConfig", "Change a provider instance configuration.", "providers", "revision", "config", "confirm-warnings"),
        Mutation("PUT", "/providers/{id}/max-stale", "provider-max-stale", "changeProviderMaxStale", "Change the provider instance cache policy.", "providers", "revision", "max-stale-seconds"),
        Mutation("DELETE", "/providers/{id}", "provider-remove", "removeProvider", "Remove a provider instance with no mounts.", "providers", "revision"),
        Mutation("POST", "/mounts", "mount-add", "addMount", "Add a provider mount and end grants whose source changes.", "providers", "instance", "kind", "path", "base", "confirm-warnings"),
        Mutation("DELETE", "/mounts/{id}", "mount-remove", "removeMount", "Remove a provider mount and end grants whose source changes.", "providers"),
    ];

    private static JsonObject ProviderValidationBody() => new()
    {
        ["oneOf"] = new JsonArray(
            S.Obj([("type", ParameterSchema("type")), ("config", ParameterSchema("config")), ("mountBase", ParameterSchema("base"))], ["mountBase"]),
            S.Obj([("instance", ParameterSchema("instance")), ("config", ParameterSchema("config")), ("mountBase", ParameterSchema("base"))], ["config"])),
    };

    // One item is never an empty list: where there is no provider authority there is no item to answer with.
    private Task<ApiResult> GetProviderAsync(ApiCall call) => Task.FromResult(admin.Providers is null ? ProvidersUnavailable() : ProviderRead(call, (providers, id) => providers.Provider(id)));

    private ApiResult ProviderRead(ApiCall call, Func<ProviderAdmin, Guid, object?> read)
    {
        if (admin.Providers is not { } providers)
        {
            return new ApiResult(200, Array.Empty<object>());
        }

        return Guid.TryParseExact(call.Path["id"], "D", out Guid id) && read(providers, id) is { } item
            ? new ApiResult(200, item)
            : ProviderProblem(404, "not-found", "no provider instance or mount has that id");
    }

    private ApiResult? ProviderRequestProblem(AdminSession? session)
    {
        if (session is null)
        {
            return ProviderProblem(401, "session-required", "this needs an administrator session; sign in with a passkey");
        }

        if (admin.Providers is null)
        {
            return ProvidersUnavailable();
        }

        if (admin.Status().Locked)
        {
            return ProviderProblem(423, "authority-locked", "the authority is locked");
        }

        return admin.TakeStart(AdminService.CallerOf(session))
            ? null
            : ProviderProblem(429, "too-many-requests", "too many requests; wait a minute");
    }

    private async Task<ApiResult> ValidateProviderAsync(ApiCall call)
    {
        if (ProviderRequestProblem(call.Session) is { } refusal)
        {
            return refusal;
        }

        JsonElement body = call.Body!.Value;
        string? config = body.TryGetProperty("config", out JsonElement proposed) ? proposed.GetString() : null;
        string? mountBase = body.TryGetProperty("mountBase", out JsonElement path) ? path.GetString() : null;
        if (config is not null && ProviderAdmin.ConfigurationScreen(config) is { } problem)
        {
            return new ApiResult(200, new ValidationDto(false, [new ValidationIssueDto(problem, "error", "config", null)]));
        }

        CancellationToken cancel = call.Context.RequestAborted;
        ProviderAdmin providers = admin.Providers!;
        if (body.TryGetProperty("type", out JsonElement type))
        {
            return new ApiResult(200, await providers.ValidateConfigurationAsync(type.GetString()!, config!, cancel, mountBase));
        }

        if (!Guid.TryParseExact(body.GetProperty("instance").GetString(), "D", out Guid id))
        {
            return ProviderProblem(400, "invalid-request", "give the provider instance id");
        }

        return new ApiResult(200, await providers.ValidateMountAsync(id, config, mountBase!, cancel));
    }

    private async Task<ApiResult> RefreshMountAsync(ApiCall call)
    {
        if (ProviderRequestProblem(call.Session) is { } refusal)
        {
            return refusal;
        }

        ProviderAdmin providers = admin.Providers!;
        if (!Guid.TryParseExact(call.Path["id"], "D", out Guid id) || !providers.Store.Mounts().Any(mount => mount.Id == id))
        {
            return ProviderProblem(404, "not-found", "no mount has that id");
        }

        try
        {
            return new ApiResult(200, await providers.RefreshAsync(id, call.Session!.Identity, call.Context.RequestAborted));
        }
        catch (ProviderConfigurationException error)
        {
            return ProviderProblem(409, "operation-refused", error.Message);
        }
    }

    private static ApiResult ProvidersUnavailable() => ProviderProblem(503, "internal-error", "providers cannot be changed from this service");

    private static ApiResult ProviderProblem(int status, string code, string detail) => new(status, new ApiProblem(status, code, detail));
}

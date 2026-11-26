using System.Buffers.Text;
using System.Security.Cryptography;
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
        new("POST", Prefix + "/providers/onepassword/seal", "sealOnePasswordConfiguration", "Seal a write-only 1Password token for provider configuration.", "providers",
            ApiAccess.Authorize, 200, "SealedProviderConfiguration", S.Obj([("serviceAccountToken", S.Str(min: 1, max: 2000))]), [], null, SealOnePasswordConfigurationAsync),
        new("POST", Prefix + "/providers/vault/seal", "sealVaultConfiguration", "Seal a write-only HashiCorp Vault token for provider configuration.", "providers",
            ApiAccess.Authorize, 200, "SealedProviderConfiguration", S.Obj([("token", S.Str(min: 1, max: 2000))]), [], null, SealVaultConfigurationAsync),
        new("POST", Prefix + "/providers/validate", "validateProvider", "Validate a proposed provider configuration or mount path.", "providers", ApiAccess.Authorize, 200,
            "ProviderValidation", ProviderValidationBody(), [], null, ValidateProviderAsync, BodyLimit: ConfigurationBodyLimit),
        new("POST", Prefix + "/mounts/{id}/refresh", "refreshMount", "Refresh the namespace entries of a mount from its provider.", "providers", ApiAccess.Authorize, 200,
            "MountRefresh", null, [], null, RefreshMountAsync),
        new("POST", Prefix + "/providers/{id}/value-refreshes", "startProviderValueRefresh", "Open the local terminal and begin an interactive provider refresh.", "providers",
            ApiAccess.Authorize, 201, "ProviderValueRefreshLaunched", S.Obj([("browserKey", S.Str(min: 300, max: 512))]), [], null, StartProviderValueRefreshAsync),
        new("GET", Prefix + "/provider-value-refreshes/{id}", "getProviderValueRefresh", "Read the matching code and staging status for this session's refresh.", "providers",
            ApiAccess.Read, 200, "ProviderValueRefresh", null, [], null, GetProviderValueRefreshAsync),
        new("DELETE", Prefix + "/provider-value-refreshes/{id}", "cancelProviderValueRefresh", "End this session's refresh and discard its staged ciphertext.", "providers",
            ApiAccess.Authorize, 200, "Done", null, [], null, CancelProviderValueRefreshAsync),
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
            S.Obj([("type", ParameterSchema("type")), ("config", ParameterSchema("config")), ("mountBase", ParameterSchema("base")), ("mountKind", ParameterSchema("kind"))], ["mountBase", "mountKind"]),
            S.Obj([("instance", ParameterSchema("instance")), ("config", ParameterSchema("config")), ("mountBase", ParameterSchema("base")), ("mountKind", ParameterSchema("kind"))], ["config", "mountKind"])),
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

    private Task<ApiResult> SealOnePasswordConfigurationAsync(ApiCall call)
        => SealProviderTokenAsync(call, "serviceAccountToken", "1Password", (providers, token) => providers.SealOnePasswordConfiguration(token));

    private Task<ApiResult> SealVaultConfigurationAsync(ApiCall call)
        => SealProviderTokenAsync(call, "token", "Vault", (providers, token) => providers.SealVaultConfiguration(token));

    private Task<ApiResult> SealProviderTokenAsync(ApiCall call, string field, string providerName, Func<ProviderAdmin, string, string?> seal)
    {
        if (ProviderRequestProblem(call.Session) is { } refusal)
        {
            return Task.FromResult(refusal);
        }

        try
        {
            string token = call.Body!.Value.GetProperty(field).GetString()!;
            string? config = seal(admin.Providers!, token);
            if (config is not null && ProviderAdmin.ConfigurationScreen(config) is null)
            {
                return Task.FromResult(new ApiResult(200, new { config }));
            }
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            // The request contains a credential. Never include provider exception details.
        }

        return Task.FromResult(ProviderProblem(400, "configuration-not-sealed",
            $"The {providerName} configuration could not be sealed. Check the token and authority setup."));
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
        MountKind? mountKind = body.TryGetProperty("mountKind", out JsonElement kind) ? kind.GetString() switch
        {
            "tree" => MountKind.Tree,
            "single" => MountKind.Single,
            _ => null,
        } : null;
        if (config is not null && ProviderAdmin.ConfigurationScreen(config) is { } problem)
        {
            return new ApiResult(200, new ValidationDto(false, [new ValidationIssueDto(problem, "error", "config", null)]));
        }

        CancellationToken cancel = call.Context.RequestAborted;
        ProviderAdmin providers = admin.Providers!;
        if (body.TryGetProperty("type", out JsonElement type))
        {
            return new ApiResult(200, await providers.ValidateConfigurationAsync(type.GetString()!, config!, cancel, mountBase, mountKind));
        }

        if (!Guid.TryParseExact(body.GetProperty("instance").GetString(), "D", out Guid id))
        {
            return ProviderProblem(400, "invalid-request", "give the provider instance id");
        }

        return new ApiResult(200, await providers.ValidateMountAsync(id, config, mountBase!, cancel, mountKind));
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
            return new ApiResult(200, await providers.RefreshAsync(id, call.Session!.Identity, call.Context.RequestAborted, call.Session.Key, fromSession: true));
        }
        catch (ProviderConfigurationException error)
        {
            return ProviderProblem(409, "operation-refused", error.Message);
        }
    }

    private static ApiResult ProvidersUnavailable() => ProviderProblem(503, "internal-error", "providers cannot be changed from this service");

    private async Task<ApiResult> StartProviderValueRefreshAsync(ApiCall call)
    {
        if (ProviderRequestProblem(call.Session) is { } refusal) return refusal;
        if (admin.InteractiveRefreshes is not { } refreshes) return ProvidersUnavailable();
        if (!Guid.TryParseExact(call.Path["id"], "D", out Guid instance) || admin.Providers!.Store.Instance(instance) is null)
            return ProviderProblem(404, "not-found", "no provider instance has that id");

        using RSA browserKey = RSA.Create();
        try
        {
            byte[] der = Base64Url.DecodeFromChars(call.Body!.Value.GetProperty("browserKey").GetString()!);
            browserKey.ImportSubjectPublicKeyInfo(der, out int read);
            if (read != der.Length || browserKey.KeySize != 2048 || !der.AsSpan().SequenceEqual(browserKey.ExportSubjectPublicKeyInfo()))
                return ProviderProblem(400, "invalid-request", "the browser refresh key must be an RSA 2048 public key");
        }
        catch (Exception error) when (error is FormatException or CryptographicException or ArgumentException)
        {
            return ProviderProblem(400, "invalid-request", "the browser refresh key is invalid");
        }

        try
        {
            return new ApiResult(201, await refreshes.StartAsync(instance, call.Session!, browserKey, call.Context.RequestAborted));
        }
        catch (ProviderConfigurationException problem)
        {
            return ProviderProblem(409, "operation-refused", problem.Message);
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            return ProviderProblem(409, "operation-refused", "The WithSecrets terminal could not open a verified refresh on this desktop.");
        }
    }

    private Task<ApiResult> GetProviderValueRefreshAsync(ApiCall call)
        => Task.FromResult(Guid.TryParseExact(call.Path["id"], "D", out Guid id) && call.Session is { } owner
            && admin.InteractiveRefreshes?.View(id, owner) is { } view
            ? new ApiResult(200, view)
            : ProviderProblem(404, "not-found", "this refresh is unavailable or expired"));

    private Task<ApiResult> CancelProviderValueRefreshAsync(ApiCall call)
        => Task.FromResult(Guid.TryParseExact(call.Path["id"], "D", out Guid id) && call.Session is { } owner
            && admin.InteractiveRefreshes?.Cancel(id, owner) == true
            ? new ApiResult(200, new { ok = true })
            : ProviderProblem(404, "not-found", "this refresh is unavailable or expired"));

    private static ApiResult ProviderProblem(int status, string code, string detail) => new(status, new ApiProblem(status, code, detail));
}

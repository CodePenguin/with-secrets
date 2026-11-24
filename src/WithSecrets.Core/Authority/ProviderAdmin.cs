using System.Text.Json;
using System.Text.RegularExpressions;

using Microsoft.Extensions.Logging.Abstractions;

namespace WithSecrets;

/// <summary>
/// Provider and mount administration over the authority's provider side (10.3.1, 10.5): the views the admin app shows, validation of a proposed configuration or
/// mount through a temporary adapter, the screen that keeps a credential out of the stored configuration, and the namespace refresh. A change itself is an admin
/// operation (tap-bound) that writes through <see cref="ProviderStore" /> with <see cref="AdminAudit" />'s event committed in the same transaction. All text here is
/// constant, a stored non-secret value or an adapter's own validation message; never configuration text or provider response text taken from an exception.
/// </summary>
internal sealed class ProviderAdmin(ProviderAuthority providers, AdminAudit audit, Func<string, string?>? sealOnePasswordConfiguration = null,
    Func<string, string, string?>? sealLastPassConfiguration = null)
{
    /// <summary>The longest configuration text accepted (it is signed into the page text, so it is bounded).</summary>
    internal const int MaxConfigurationLength = 2000;

    /// <summary>The names an environment-variable field may hold: the NAME of a variable that holds the credential, never the credential.</summary>
    private static readonly Regex EnvironmentName = new(@"^[A-Z][A-Z0-9_]{0,63}\z", RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly string[] EnvironmentSuffixes = ["env", "envvar"];

    private static readonly string[] CredentialMarks = ["token", "password", "secret", "apikey", "api_key", "credential", "privatekey"];

    public string? SealOnePasswordConfiguration(string token) => sealOnePasswordConfiguration?.Invoke(token);

    public string? SealLastPassConfiguration(string username, string masterPassword) => sealLastPassConfiguration?.Invoke(username, masterPassword);


    public IReadOnlyList<ProviderTypeDto> Types() => [.. providers.Registry.Types().Select(item => new ProviderTypeDto(item.Type, item.AdapterVersion))];

    public IReadOnlyList<ProviderDto> Providers()
    {
        IReadOnlyList<Mount> mounts = providers.Store.Mounts();

        return [.. providers.Store.Instances().Select(instance => View(instance, mounts))];
    }

    public ProviderDto? Provider(Guid id) => providers.Store.Instance(id) is { } instance ? View(instance, providers.Store.Mounts()) : null;

    public IReadOnlyList<MountDto> Mounts(Guid? instanceId = null)
    {
        Dictionary<Guid, string> names = providers.Store.Instances().ToDictionary(instance => instance.Id, instance => instance.Name);
        Dictionary<Guid, int> counts = providers.Store.Entries().GroupBy(entry => entry.MountId).ToDictionary(group => group.Key, group => group.Count());

        return [.. providers.Store.Mounts()
            .Where(mount => instanceId is null || mount.InstanceId == instanceId)
            .Select(mount => new MountDto(mount.Id, mount.InstanceId, names.GetValueOrDefault(mount.InstanceId, ""), KindName(mount.Kind), mount.LogicalPath, mount.BasePath, counts.GetValueOrDefault(mount.Id), MountActions(mount)))];
    }

    public IReadOnlyList<NamespaceEntryDto> Entries(Guid mountId)
    {
        return [.. providers.Store.Entries(mountId).Select(entry => new NamespaceEntryDto(entry.LogicalPath, entry.ProviderPath, entry.ExternalId, entry.Description, entry.DescriptionSource == DescriptionSource.Local ? "local" : "provider"))];
    }

    /// <summary>The changes the admin app may offer for an instance: the removal only while it has no mounts.</summary>
    public IReadOnlyList<string> ProviderActions(ProviderInstance instance) => ProviderActions(instance, providers.Store.Mounts());

    /// <summary>A mount can be removed; it can be refreshed while its instance is registered (running).</summary>
    public IReadOnlyList<string> MountActions(Mount mount) => IsRegistered(mount.InstanceId) ? ["remove", "refresh"] : ["remove"];

    /// <summary>Validates a configuration that is not stored yet through a temporary adapter of the type. Errors block saving; warnings need confirming.</summary>
    public async Task<ValidationDto> ValidateConfigurationAsync(string type, string configuration, CancellationToken cancellationToken, string? mountBase = null)
    {
        return Issues(await providers.Registry.ValidateProposedAsync(type, configuration, mountBase, NullLogger.Instance, cancellationToken).ConfigureAwait(false));
    }

    /// <summary>Validates a mount's provider path against an instance, with the proposed configuration when one is given (a configuration change planned together with the mount), else the stored one.</summary>
    public async Task<ValidationDto> ValidateMountAsync(Guid instanceId, string? proposedConfiguration, string basePath, CancellationToken cancellationToken)
    {
        if (providers.Store.Instance(instanceId) is not { } instance)
        {
            return Issues([new ProviderValidationIssue("The provider instance does not exist.", ValidationSeverity.Error)]);
        }

        return Issues(await providers.Registry.ValidateProposedAsync(instance.ProviderType, proposedConfiguration ?? instance.Configuration, basePath, NullLogger.Instance, cancellationToken).ConfigureAwait(false));
    }

    /// <summary>
    /// Null when the configuration may be stored; else a refusal naming only the offending field NAME (or a constant message). The configuration is stored
    /// unencrypted in with-secrets.db and shown in the signed page text, so it must be a JSON object of at most <see cref="MaxConfigurationLength" /> characters in which
    /// no property name, at any depth, contains (case-insensitively) token, password, secret, apikey, api_key, credential or privatekey. Values are not examined,
    /// with one exception: a property of such a name that ends in Env or EnvVar (case-insensitive, so also _ENV) holds the NAME of an environment variable and is accepted
    /// only when its value is a JSON string matching <c>^[A-Z][A-Z0-9_]{0,63}$</c>; any other value is refused (naming only the property).
    /// </summary>
    public static string? ConfigurationScreen(string configurationJson)
    {
        if (configurationJson is null || configurationJson.Length > MaxConfigurationLength)
        {
            return $"The configuration must be at most {MaxConfigurationLength} characters.";
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(configurationJson);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return "The configuration must be a JSON object.";
            }

            return FirstCredentialName(document.RootElement) is { } name
                ? $"The configuration has a field named '{name}', which looks like a credential. Credentials are not accepted here."
                : null;
        }
        catch (JsonException)
        {
            return "The configuration is not valid JSON.";
        }
    }

    /// <summary>
    /// Refreshes one mount's namespace entries from its provider (no tap: it only syncs with provider truth) and audits it with counts. A mount that does not exist, or whose
    /// instance is not running, is refused with a constant message and nothing is audited. A provider failure propagates as the reconciler throws it.
    /// </summary>
    public async Task<ReconcileResult> RefreshAsync(Guid mountId, string actor, CancellationToken cancellationToken)
    {
        Mount mount = providers.Store.Mounts().FirstOrDefault(item => item.Id == mountId) ?? throw new ProviderConfigurationException("The mount does not exist.");
        try
        {
            providers.Registry.Adapter(mount.InstanceId);
        }
        catch (Exception error) when (error is KeyNotFoundException or InvalidOperationException)
        {
            throw new ProviderConfigurationException("The provider instance is not running, so its namespace cannot be refreshed.");
        }

        ReconcileResult result;
        try
        {
            result = await providers.Reconciler.ReconcileWithinAsync(mount, RefreshDeadline, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
        }
        catch (TimeoutException)
        {
            throw new ProviderConfigurationException("The provider listing timed out, so the namespace was not refreshed.");
        }
        catch (Exception error) when (error is not (OperationCanceledException or OutOfMemoryException))
        {
            // The text of a provider or adapter failure can quote its response: the kind goes to the log, the administrator gets a constant.
            AppLog.Warn("refreshing the namespace of a mount failed ({Type})", error.GetType().Name);

            throw new ProviderConfigurationException("The provider could not be listed, so the namespace was not refreshed.");
        }

        string detail = result.Complete ? $"added {result.Added}, removed {result.Removed}, changed {result.Changed}" : "the provider listing was incomplete; nothing changed";

        // Best effort, like the refresh itself: the entries already follow the provider.
        audit.TryRecord(AdminEvent.Provider("namespace-refreshed", [mount.LogicalPath], detail, actor));

        return result;
    }

    // ---- the changes (each called by an admin operation after its verified tap) ----

    /// <summary>The store under this administration: what the plans of the admin operations read.</summary>
    internal ProviderStore Store => providers.Store;

    internal bool HasType(string type) => providers.Registry.Types().Any(item => item.Type == type);

    /// <summary>The most one post-commit namespace refresh of a mount takes (an adapter whose listing ignores its token included); after it the change's outcome says the namespace was not listed. For tests: shortened.</summary>
    internal TimeSpan RefreshDeadline { get; set; } = ProviderPolicy.Deadline;

    /// <summary>The refusal when the grants a mount change ends are not the ones its signed sentence counted (one was approved, or ended, in between).</summary>
    internal const string GrantsChanged = "the active grants this change ends are not the ones shown (one was approved or ended since); nothing was changed, ask again";

    /// <summary>Adds an instance; its provider-added event commits in the same transaction (a failed audit write rolls the change back).</summary>
    internal ProviderInstance AddInstance(string name, string type, string configuration, TimeSpan maxStale, string key)
    {
        return providers.Store.AddInstance(name, type, configuration, maxStale,
            (connection, transaction) => audit.Append(connection, transaction, AdminEvent.Provider("provider-added", [name], $"type {type}; fields {Fields(configuration)}; max stale {Seconds(maxStale)} s", key)));
    }

    internal ProviderInstance Reconfigure(ProviderInstance current, string configuration, string key)
    {
        return providers.Store.UpdateConfiguration(current.Id, configuration,
            (connection, transaction) => audit.Append(connection, transaction, AdminEvent.Provider("provider-config-changed", [current.Name], $"revision {current.Revision} -> {current.Revision + 1}; fields {Fields(configuration)}", key)));
    }

    /// <summary>Policy only: the revision stays (<see cref="ProviderStore.SetMaxStale" />).</summary>
    internal ProviderInstance SetMaxStale(ProviderInstance current, TimeSpan maxStale, string key)
    {
        return providers.Store.SetMaxStale(current.Id, maxStale,
            (connection, transaction) => audit.Append(connection, transaction, AdminEvent.Provider("provider-max-stale-changed", [current.Name], $"max stale {Seconds(current.MaxStale)} s -> {Seconds(maxStale)} s", key)));
    }

    /// <summary>Removes an instance that has no mounts and its cache rows; returns how many rows were deleted.</summary>
    internal int RemoveInstance(ProviderInstance current, string key)
    {
        return providers.Store.RemoveInstance(current.Id,
            (connection, transaction, rows) => audit.Append(connection, transaction, AdminEvent.Provider("provider-removed", [current.Name], $"type {current.ProviderType}; {rows} cache rows deleted", key)));
    }

    /// <summary>
    /// Adds a mount. <paramref name="expectedEnded" /> is the number of active grants the signed sentence said would end: inside the transaction, when the change would end
    /// another number, it is rolled back (<see cref="GrantsChanged" />), so no grant ends that the administrator was not shown.
    /// </summary>
    internal Mount AddMount(ProviderInstance instance, MountKind kind, string logicalPath, string basePath, int expectedEnded, string key)
    {
        return providers.Store.AddMount(instance.Id, kind, logicalPath, basePath, (connection, transaction, ended) =>
        {
            RequireEnded(ended, expectedEnded);
            audit.Append(connection, transaction, AdminEvent.Provider("mount-added", [logicalPath], $"{KindName(kind)} mount of {instance.Name}; {ended} active grants ended", key));
        });
    }

    /// <summary>Removes a mount; as <see cref="AddMount" />, rolled back when it would end another number of grants than <paramref name="expectedEnded" />.</summary>
    internal void RemoveMount(Mount mount, string instanceName, int expectedEnded, string key)
    {
        providers.Store.RemoveMount(mount.Id, (connection, transaction, ended) =>
        {
            RequireEnded(ended, expectedEnded);
            audit.Append(connection, transaction, AdminEvent.Provider("mount-removed", [mount.LogicalPath], $"{KindName(mount.Kind)} mount of {instanceName}; {ended} active grants ended", key));
        });
    }

    private static void RequireEnded(int ended, int expected)
    {
        if (ended != expected)
        {
            throw new ProviderConfigurationException(GrantsChanged);
        }
    }

    /// <summary>After an instance was committed: adds it to the registry. Null when that worked, else one constant line for the outcome (the configuration stays committed).</summary>
    internal async Task<string?> StartAsync(ProviderInstance instance)
    {
        return await Quietly(() => providers.StartInstanceAsync(instance), "the instance was saved, but it could not be started; see its status").ConfigureAwait(false);
    }

    /// <summary>After a configuration change was committed: the running adapter takes it. Null when it did, else one constant line (the configuration stays committed).</summary>
    internal async Task<string?> ApplyAsync(ProviderInstance instance)
    {
        return await Quietly(() => providers.ReconfigureInstanceAsync(instance), "the configuration was saved, but the running provider did not take it; see its status").ConfigureAwait(false);
    }

    /// <summary>After an instance was removed: its running adapter is shut down. Null when that worked, else one constant line.</summary>
    internal async Task<string?> StopAsync(Guid instanceId)
    {
        return await Quietly(() => providers.StopInstanceAsync(instanceId), "the instance was removed, but its running adapter did not shut down cleanly").ConfigureAwait(false);
    }

    /// <summary>
    /// After a mount or configuration change was committed: refreshes the namespaces of <paramref name="mounts" /> within one deadline.
    /// Returns null when all were listed, or a summary of how many still need refreshing.
    /// </summary>
    internal async Task<string?> RefreshAfterChangeAsync(IReadOnlyList<Mount> mounts, string key)
    {
        int failed = 0;
        using CancellationTokenSource deadline = new(RefreshDeadline);
        foreach (Mount mount in mounts)
        {
            if (deadline.IsCancellationRequested)
            {
                failed++;
                continue;
            }

            try
            {
                if (!(await RefreshAsync(mount.Id, key, deadline.Token).ConfigureAwait(false)).Complete)
                {
                    failed++;
                }
            }
            catch (Exception error) when (error is not OutOfMemoryException)
            {
                // RefreshAsync turns provider failures into constants; anything else is logged by type only.
                AppLog.Debug("a namespace refresh after an administrator change did not complete ({Type})", error.GetType().Name);
                failed++;
            }
        }

        return failed == 0 ? null : mounts.Count == 1 ? "the namespace could not be listed yet; refresh it later" : $"{failed} of {mounts.Count} namespaces could not be listed yet; refresh them later";
    }

    private static async Task<string?> Quietly(Func<Task> work, string failure)
    {
        try
        {
            await work().ConfigureAwait(false);

            return null;
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            // Committed already; the kind only goes to the log (the text of an adapter failure can quote the provider).
            AppLog.Warn("a provider registry change after an administrator change failed ({Type})", error.GetType().Name);

            return failure;
        }
    }

    /// <summary>The top-level field NAMES of a configuration (the audit carries names, never values).</summary>
    private static string Fields(string configuration)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(configuration);

            return document.RootElement.ValueKind == JsonValueKind.Object ? string.Join(",", document.RootElement.EnumerateObject().Select(property => property.Name)) : "";
        }
        catch (JsonException)
        {
            return "";
        }
    }

    private static string Seconds(TimeSpan value) => ((long)value.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture);

    internal static string KindName(MountKind kind) => kind == MountKind.Tree ? "tree" : "single";

    private ProviderDto View(ProviderInstance instance, IReadOnlyList<Mount> mounts)
    {
        return new ProviderDto(instance.Id, instance.Name, instance.ProviderType, instance.Configuration, (int)instance.MaxStale.TotalSeconds, instance.Revision,
            mounts.Count(mount => mount.InstanceId == instance.Id), StatusOf(instance.Id), ProviderActions(instance, mounts));
    }

    internal bool IsRegistered(Guid id)
    {
        try
        {
            providers.Registry.Status(id);

            return true;
        }
        catch (KeyNotFoundException)
        {
            return false;
        }
    }

    private ProviderStatusDto? StatusOf(Guid id)
    {
        try
        {
            InstanceStatus status = providers.Registry.Status(id);

            return new ProviderStatusDto(Name(status.Lifecycle), status.LifecycleMessage, status.LifecycleAt, Name(status.Health), status.HealthMessage, status.HealthAt);
        }
        catch (KeyNotFoundException)
        {
            return null;
        }
    }

    private static IReadOnlyList<string> ProviderActions(ProviderInstance instance, IReadOnlyList<Mount> mounts)
    {
        return mounts.Any(mount => mount.InstanceId == instance.Id) ? ["config", "max-stale", "add-mount"] : ["config", "max-stale", "remove", "add-mount"];
    }

    private static ValidationDto Issues(IReadOnlyList<ProviderValidationIssue> issues)
    {
        return new ValidationDto(issues.All(issue => issue.Severity != ValidationSeverity.Error),
            [.. issues.Select(issue => new ValidationIssueDto(issue.Message, Name(issue.Severity), issue.Target, issue.ProviderCode))]);
    }

    private static string? FirstCredentialName(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (JsonProperty property in element.EnumerateObject())
                {
                    if (CredentialMarks.Any(mark => property.Name.Contains(mark, StringComparison.OrdinalIgnoreCase)))
                    {
                        if (EnvironmentSuffixes.Any(suffix => property.Name.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                            && property.Value.ValueKind == JsonValueKind.String && EnvironmentName.IsMatch(property.Value.GetString()!))
                        {
                            continue;
                        }

                        return property.Name;
                    }

                    if (FirstCredentialName(property.Value) is { } nested)
                    {
                        return nested;
                    }
                }

                break;
            case JsonValueKind.Array:
                foreach (JsonElement item in element.EnumerateArray())
                {
                    if (FirstCredentialName(item) is { } nested)
                    {
                        return nested;
                    }
                }

                break;
        }

        return null;
    }

    private static string Name<T>(T value) where T : struct, Enum => value.ToString().ToLowerInvariant();
}

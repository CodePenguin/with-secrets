using System.Globalization;
using System.Runtime.CompilerServices;

using ProviderPlanResult = (ArcanaGuardian.AdminPlan? Plan, string? Refusal, int Status);

namespace ArcanaGuardian;

/// <summary>
/// The provider and mount operations (10.3.1, 10.5) as plans. Each is refused before any page when it does not apply (the same checks that decide the actions the views
/// offer), validates a proposed configuration or mount through a temporary adapter (errors refuse; warnings only with <c>confirm-warnings=yes</c>, which is then signed), and
/// signs a sentence of constants, names, ids, counts and the configuration itself (non-secret by rule; it is screened for credential-looking fields), never an adapter's
/// text. At the tap the state is checked again (revision, existence, mounts, the grants that would end) and the change commits with its audit event; only then is the
/// running registry updated and the affected namespaces listed again. What fails after the commit does not undo it: it is one constant line in the outcome.
/// </summary>
public sealed partial class AdminService
{
    private const int MaxInstanceName = 64;

    private static readonly int MaxStaleSeconds = (int)ProviderPolicy.MaxStaleCap.TotalSeconds;

    /// <summary>One provider or mount change at a time: what a change re-checks at its tap stays so until it is applied (instances and mounts have no other writer, ruling 5).</summary>
    private readonly Lock _providerChanges = new();

    internal static bool IsProviderOperation(string op) => op is "provider-add" or "provider-config" or "provider-max-stale" or "provider-remove" or "mount-add" or "mount-remove";

    private static ProviderPlanResult Refuse(string refusal, int status = 409) => (null, refusal, status);

    private async Task<ProviderPlanResult> ProviderPlanAsync(string op, IReadOnlyDictionary<string, string> args, CancellationToken cancel)
    {
        if (Providers is not { } providers)
        {
            return Refuse("providers and mounts cannot be changed from this service", 503);
        }

        return op switch
        {
            "provider-add" => await AddProviderPlanAsync(providers, args, cancel),
            "provider-config" => await ConfigurationPlanAsync(providers, args, cancel),
            "provider-max-stale" => MaxStalePlan(providers, args),
            "provider-remove" => RemoveProviderPlan(providers, args),
            "mount-add" => await AddMountPlanAsync(providers, args, cancel),
            _ => RemoveMountPlan(providers, args),
        };
    }

    private async Task<ProviderPlanResult> AddProviderPlanAsync(ProviderAdmin providers, IReadOnlyDictionary<string, string> args, CancellationToken cancel)
    {
        string name = Arg(args, "name")?.Trim() ?? "";
        if (name.Length is 0 or > MaxInstanceName || !OneLine(name))
        {
            return Refuse($"give the instance a name of 1 to {MaxInstanceName} characters on one line", 400);
        }

        string type = Arg(args, "type") ?? "";
        if (!providers.HasType(type))
        {
            return Refuse("no provider type of that name is available in this service", 400);
        }

        string? configuration = Arg(args, "config");
        if (ConfigurationProblem(configuration) is { } problem)
        {
            return Refuse(problem, 400);
        }

        bool interactive = providers.IsInteractiveType(type);
        string? cachePolicy = Arg(args, "max-stale-seconds");
        int seconds = 3600;
        if ((cachePolicy is not null || !interactive) && !TryNumber(cachePolicy, 0, MaxStaleSeconds, out seconds))
        {
            return Refuse($"the maximum staleness is 0 to {MaxStaleSeconds} seconds (24 hours)", 400);
        }

        if (seconds == 0 && interactive)
            return Refuse("Set a positive cache duration for a provider that refreshes through a terminal.", 400);

        if (!TryConfirm(args, out bool confirmed))
        {
            return Refuse("confirm-warnings takes only yes", 400);
        }

        if (providers.Store.Instances().Any(instance => instance.Name == name))
        {
            return Refuse($"a provider instance named \"{name}\" already exists");
        }

        ValidationDto validation = await providers.ValidateConfigurationAsync(type, configuration!, cancel);
        if (ValidationProblem(validation, confirmed, "configuration") is { } refused)
        {
            return Refuse(refused);
        }

        string config = configuration!;
        string sentence = $"add the provider instance \"{name}\" of type {type}, with the settings listed below; mounted secrets of this instance are served only while it runs";
        List<(string Name, string Value)> parameters = [("name", name), ("type", type), ("config", config)];
        if (cachePolicy is not null)
        {
            sentence += "\n" + CachePolicySummary(seconds, interactive);
            parameters.Add(("max-stale-seconds", seconds.ToString(CultureInfo.InvariantCulture)));
        }
        sentence += "\n" + ValidationLine(validation);
        AddConfirmation(parameters, confirmed);
        StrongBox<string?> remark = new();

        return (new AdminPlan("provider-add", sentence, parameters, a => ProviderChange(() =>
        {
            if (providers.Store.Instances().Any(instance => instance.Name == name))
            {
                return $"a provider instance named \"{name}\" exists now; nothing was added";
            }

            if (AppliedValidationProblem(Wait(providers.ValidateConfigurationAsync(type, config, CancellationToken.None)), confirmed, Warnings(validation), "configuration") is { } late)
            {
                return "nothing was added: " + late;
            }

            ProviderInstance added = providers.AddInstance(name, type, config, TimeSpan.FromSeconds(seconds), a.Admin!.Key);
            remark.Value = Wait(providers.StartAsync(added));

            return null;
        }), Remark: remark), null, 200);
    }

    private async Task<ProviderPlanResult> ConfigurationPlanAsync(ProviderAdmin providers, IReadOnlyDictionary<string, string> args, CancellationToken cancel)
    {
        if (CurrentInstance(providers, args) is not { } current)
        {
            return InstanceRefusal(providers, args);
        }

        string? configuration = Arg(args, "config");
        if (ConfigurationProblem(configuration) is { } problem)
        {
            return Refuse(problem, 400);
        }

        bool configChanged = configuration != current.Configuration;
        int before = (int)current.MaxStale.TotalSeconds;
        int? seconds = null;
        if (Arg(args, "max-stale-seconds") is { } requested)
        {
            if (!TryNumber(requested, 0, MaxStaleSeconds, out int value))
                return Refuse($"the maximum staleness is 0 to {MaxStaleSeconds} seconds (24 hours)", 400);
            if (value == 0 && providers.IsInteractiveType(current.ProviderType))
                return Refuse("Set a positive cache duration for a provider that refreshes through a terminal.", 400);
            seconds = value;
        }

        if (!configChanged && (seconds is null || seconds == before))
        {
            return Refuse("the configuration is unchanged");
        }

        if (!TryConfirm(args, out bool confirmed))
        {
            return Refuse("confirm-warnings takes only yes", 400);
        }

        ValidationDto? validation = configChanged ? await providers.ValidateConfigurationAsync(current.ProviderType, configuration!, cancel) : null;
        if (validation is not null && ValidationProblem(validation, confirmed, "configuration") is { } refused)
        {
            return Refuse(refused);
        }

        string config = configuration!;
        Guid id = current.Id;
        int revision = current.Revision;
        int mounts = providers.Store.Mounts().Count(mount => mount.InstanceId == id);
        string sentence = $"Update provider \"{ApprovalSummary.Clean(current.Name)}\".\nInstance: {id:D}, revision {revision.ToString(CultureInfo.InvariantCulture)}";
        if (validation is not null)
            sentence += "\nApply the connection settings" + (mounts > 0 ? $" and refresh {Plural(mounts, "mount")}" : "") + ".\n" + ValidationLine(validation);
        if (seconds is { } duration)
            sentence += "\n" + CachePolicySummary(duration, providers.IsInteractiveType(current.ProviderType));
        List<(string Name, string Value)> parameters = [("id", id.ToString("D")), ("revision", revision.ToString(CultureInfo.InvariantCulture)), ("config", config)];
        if (seconds is { } proposed) parameters.Add(("max-stale-seconds", proposed.ToString(CultureInfo.InvariantCulture)));
        AddConfirmation(parameters, confirmed);
        StrongBox<string?> remark = new();

        return (new AdminPlan("provider-config", sentence, parameters, a => ProviderChange(() =>
        {
            if (Drifted(providers, id, revision) is { } drift)
            {
                return drift;
            }

            ProviderInstance now = providers.Store.Instance(id)!;
            if (seconds is not null && (int)now.MaxStale.TotalSeconds != before)
                return "the cache freshness changed after this was authorized; nothing was changed";

            if (validation is null)
            {
                providers.SetMaxStale(now, TimeSpan.FromSeconds(seconds!.Value), a.Admin!.Key);
                return null;
            }

            if (AppliedValidationProblem(Wait(providers.ValidateConfigurationAsync(now.ProviderType, config, CancellationToken.None)), confirmed, Warnings(validation), "configuration") is { } late)
            {
                return "nothing was changed: " + late;
            }

            ProviderInstance changed = providers.Reconfigure(now, config, a.Admin!.Key, seconds is { } value ? TimeSpan.FromSeconds(value) : null);
            string? applied = Wait(providers.ApplyAsync(changed));
            remark.Value = applied ?? Wait(providers.RefreshAfterChangeAsync([.. providers.Store.Mounts().Where(mount => mount.InstanceId == id)], a.Admin.Key));

            return null;
        }), Remark: remark), null, 200);
    }

    private static string CachePolicySummary(int seconds, bool interactive = false) => interactive
        ? $"Values approved after a manual refresh are cached in encrypted form for up to {seconds.ToString(CultureInfo.InvariantCulture)} seconds."
        : seconds == 0
        ? "Every run fetches live values. Arcana Guardian caches no provider values."
        : $"The authority caches encrypted provider values on disk and can serve them during a provider outage for up to {seconds.ToString(CultureInfo.InvariantCulture)} seconds after retrieval.";

    private ProviderPlanResult MaxStalePlan(ProviderAdmin providers, IReadOnlyDictionary<string, string> args)
    {
        if (CurrentInstance(providers, args) is not { } current)
        {
            return InstanceRefusal(providers, args);
        }

        if (!TryNumber(Arg(args, "max-stale-seconds"), 0, MaxStaleSeconds, out int seconds))
        {
            return Refuse($"the maximum staleness is 0 to {MaxStaleSeconds} seconds (24 hours)", 400);
        }

        int before = (int)current.MaxStale.TotalSeconds;
        bool interactive = providers.IsInteractiveType(current.ProviderType);
        if (seconds == 0 && interactive)
            return Refuse("Set a positive cache duration for a provider that refreshes through a terminal.", 400);

        if (seconds == before)
        {
            return Refuse("the maximum staleness is unchanged");
        }

        Guid id = current.Id;
        int revision = current.Revision;
        string sentence = $"set the maximum staleness of the provider instance \"{ApprovalSummary.Clean(current.Name)}\" from {before.ToString(CultureInfo.InvariantCulture)} to {seconds.ToString(CultureInfo.InvariantCulture)} seconds. "
            + (seconds == 0 ? "Existing cached values are removed. " : "")
            + CachePolicySummary(seconds, interactive) + "\n"
            + $"Instance: {id:D}, revision {revision.ToString(CultureInfo.InvariantCulture)}";
        List<(string Name, string Value)> parameters = [("id", id.ToString("D")), ("revision", revision.ToString(CultureInfo.InvariantCulture)), ("max-stale-seconds", seconds.ToString(CultureInfo.InvariantCulture))];

        // ProviderStore.SetMaxStale leaves the revision as it is (policy only), so the signed revision still detects a configuration change between page and tap.
        return (new AdminPlan("provider-max-stale", sentence, parameters, a => ProviderChange(() =>
        {
            if (Drifted(providers, id, revision) is { } drift)
            {
                return drift;
            }

            ProviderInstance now = providers.Store.Instance(id)!;
            if ((int)now.MaxStale.TotalSeconds != before)
            {
                return $"the maximum staleness changed after this was authorized (it is {((int)now.MaxStale.TotalSeconds).ToString(CultureInfo.InvariantCulture)} seconds now); nothing was changed";
            }

            providers.SetMaxStale(now, TimeSpan.FromSeconds(seconds), a.Admin!.Key);

            return null;
        })), null, 200);
    }

    private ProviderPlanResult RemoveProviderPlan(ProviderAdmin providers, IReadOnlyDictionary<string, string> args)
    {
        if (CurrentInstance(providers, args) is not { } current)
        {
            return InstanceRefusal(providers, args);
        }

        int mounts = providers.Store.Mounts().Count(mount => mount.InstanceId == current.Id);
        if (mounts > 0)
        {
            return Refuse($"the provider instance still has {Plural(mounts, "mount")}; remove them first");
        }

        Guid id = current.Id;
        int revision = current.Revision;
        int rows = providers.Store.CacheRowCount(id);
        string sentence = $"remove the provider instance \"{ApprovalSummary.Clean(current.Name)}\" (type {ApprovalSummary.Clean(current.ProviderType)}): its configuration and its {Plural(rows, "cached value")} are deleted "
            + "and its running adapter is shut down. It has no mounts, so no grant ends\n"
            + $"Instance: {id:D}, revision {revision.ToString(CultureInfo.InvariantCulture)}\nConfiguration: {ApprovalSummary.Clean(current.Configuration)}";
        StrongBox<string?> remark = new();

        return (new AdminPlan("provider-remove", sentence, [("id", id.ToString("D")), ("revision", revision.ToString(CultureInfo.InvariantCulture))], a => ProviderChange(() =>
        {
            if (Drifted(providers, id, revision) is { } drift)
            {
                return drift;
            }

            if (providers.Store.Mounts().Any(mount => mount.InstanceId == id))
            {
                return "the provider instance has mounts now; nothing was removed";
            }

            providers.RemoveInstance(providers.Store.Instance(id)!, a.Admin!.Key);
            remark.Value = Wait(providers.StopAsync(id));

            return null;
        }), Remark: remark), null, 200);
    }

    private async Task<ProviderPlanResult> AddMountPlanAsync(ProviderAdmin providers, IReadOnlyDictionary<string, string> args, CancellationToken cancel)
    {
        if (ParseId(Arg(args, "instance")) is not { } instanceId)
        {
            return Refuse("give the provider instance's id", 400);
        }

        MountKind? kind = Arg(args, "kind") switch
        {
            "tree" => MountKind.Tree,
            "single" => MountKind.Single,
            _ => null,
        };
        if (kind is not { } mountKind)
        {
            return Refuse("the kind of a mount is tree or single", 400);
        }

        string? path = Arg(args, "path");
        string? basePath = Arg(args, "base");
        if (path is null || basePath is null || !OneLine(path) || !OneLine(basePath))
        {
            return Refuse("give the mount's path and its provider path, each on one line", 400);
        }

        if (ProviderStore.MountProblem(mountKind, path, basePath) is { } problem)
        {
            return Refuse(problem, 400);
        }

        if (providers.Store.Instance(instanceId) is not { } instance)
        {
            return Refuse("no provider instance has that id", 404);
        }

        if (!TryConfirm(args, out bool confirmed))
        {
            return Refuse("confirm-warnings takes only yes", 400);
        }

        string kindName = ProviderAdmin.KindName(mountKind);
        if (providers.Store.Mounts().Any(mount => mount.Kind == mountKind && mount.LogicalPath == path))
        {
            return Refuse($"a {kindName} mount at \"{path}\" already exists");
        }

        ValidationDto validation = await providers.ValidateMountAsync(instanceId, null, basePath, cancel, mountKind);
        if (ValidationProblem(validation, confirmed, "mount") is { } refused)
        {
            return Refuse(refused);
        }

        int ending = providers.Store.GrantsEndingOnAdd(instanceId, mountKind, path);
        string selected = mountKind == MountKind.Tree ? $"The secret names under \"{path}/\" are" : $"The secret name \"{path}\" is";
        string sentence = $"add a {kindName} mount at \"{path}\" for the provider instance \"{ApprovalSummary.Clean(instance.Name)}\" (type {ApprovalSummary.Clean(instance.ProviderType)}), over the provider path \"{basePath}\". "
            + $"{selected} then served by this provider instead of the native store or another mount: {Plural(ending, "active grant")} will end (they named a secret this mount now selects). "
            + $"Its namespace is listed from the provider after the change\n{ValidationLine(validation)}";
        List<(string Name, string Value)> parameters = [("instance", instanceId.ToString("D")), ("kind", kindName), ("path", path), ("base", basePath)];
        AddConfirmation(parameters, confirmed);
        StrongBox<string?> remark = new();

        return (new AdminPlan("mount-add", sentence, parameters, a => ProviderChange(() =>
        {
            if (Drifted(providers, instanceId, instance.Revision) is { } drift)
            {
                return drift;
            }

            if (providers.Store.Mounts().Any(mount => mount.Kind == mountKind && mount.LogicalPath == path))
            {
                return $"a {kindName} mount at \"{path}\" exists now; nothing was added";
            }

            if (AppliedValidationProblem(Wait(providers.ValidateMountAsync(instanceId, null, basePath, CancellationToken.None, mountKind)), confirmed, Warnings(validation), "mount") is { } late)
            {
                return "nothing was added: " + late;
            }

            // The grants the mount ends are counted again inside its transaction; another number than the signed one rolls it back.
            Mount added = providers.AddMount(providers.Store.Instance(instanceId)!, mountKind, path, basePath, ending, a.Admin!.Key);
            remark.Value = providers.IsRegistered(instanceId)
                ? Wait(providers.RefreshAfterChangeAsync([added], a.Admin.Key))
                : "the provider instance is not running, so the namespace was not listed; refresh it once the instance runs";

            return null;
        }), Remark: remark), null, 200);
    }

    private ProviderPlanResult RemoveMountPlan(ProviderAdmin providers, IReadOnlyDictionary<string, string> args)
    {
        if (ParseId(Arg(args, "id")) is not { } id)
        {
            return Refuse("give the mount's id", 400);
        }

        if (providers.Store.Mounts().FirstOrDefault(mount => mount.Id == id) is not { } mount)
        {
            return Refuse("no mount has that id", 404);
        }

        string instanceName = providers.Store.Instance(mount.InstanceId)?.Name ?? "(unknown)";
        int ending = providers.Store.GrantsEndingOnRemove(id);
        int entries = providers.Store.Entries(id).Count;
        string sentence = $"remove the {ProviderAdmin.KindName(mount.Kind)} mount at \"{ApprovalSummary.Clean(mount.LogicalPath)}\" (provider instance \"{ApprovalSummary.Clean(instanceName)}\", provider path \"{ApprovalSummary.Clean(mount.BasePath)}\"): "
            + $"its {Plural(entries, "namespace entry", "namespace entries")} are dropped and {Plural(ending, "active grant")} will end; the names under it fall back to the native store or a broader mount. "
            + "Cached values that no entry uses any more are deleted later";

        return (new AdminPlan("mount-remove", sentence, [("id", id.ToString("D"))], a => ProviderChange(() =>
        {
            if (!providers.Store.Mounts().Any(item => item.Id == id))
            {
                return "the mount no longer exists; nothing was changed";
            }

            // Counted again inside the transaction, as for mount-add.
            providers.RemoveMount(mount, instanceName, ending, a.Admin!.Key);

            return null;
        })), null, 200);
    }

    // ---- helpers ----

    /// <summary>Runs one provider or mount change alone. A refusal of the store (its messages carry names, never configuration content) is the outcome's line.</summary>
    private string? ProviderChange(Func<string?> change)
    {
        lock (_providerChanges)
        {
            try
            {
                return change();
            }
            catch (ProviderConfigurationException refused)
            {
                return refused.Message;
            }
        }
    }

    /// <summary>
    /// Waits for a provider call from inside an operation's Apply. Apply runs on the passkey page's worker thread or a request thread, neither of which has a
    /// synchronization context, so the wait cannot deadlock; every call waited on here is bounded (validation and registry deadlines).
    /// </summary>
    private static T Wait<T>(Task<T> task) => task.GetAwaiter().GetResult();

    private static bool OneLine(string value) => ApprovalSummary.Clean(value) == value;

    private static Guid? ParseId(string? text) => text is not null && Guid.TryParseExact(text, "D", out Guid id) ? id : null;

    /// <summary>The instance <c>id</c> names when its <c>revision</c> is the current one; null otherwise (<see cref="InstanceRefusal" /> says why).</summary>
    private static ProviderInstance? CurrentInstance(ProviderAdmin providers, IReadOnlyDictionary<string, string> args)
    {
        return ParseId(Arg(args, "id")) is { } id && Revision(args) is { } revision && providers.Store.Instance(id) is { } instance && instance.Revision == revision ? instance : null;
    }

    private static ProviderPlanResult InstanceRefusal(ProviderAdmin providers, IReadOnlyDictionary<string, string> args)
    {
        if (ParseId(Arg(args, "id")) is not { } id)
        {
            return Refuse("give the provider instance's id", 400);
        }

        if (Revision(args) is null)
        {
            return Refuse("give the revision of the provider instance as it was shown", 400);
        }

        return providers.Store.Instance(id) is { } instance
            ? Refuse($"the provider instance changed since it was shown (it is at revision {instance.Revision.ToString(CultureInfo.InvariantCulture)} now); reload it")
            : Refuse("no provider instance has that id", 404);
    }

    private static int? Revision(IReadOnlyDictionary<string, string> args)
    {
        return Arg(args, "revision") is { Length: > 0 and <= 10 } text && int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out int revision) && revision >= 1 ? revision : null;
    }

    /// <summary>Null when the instance still exists at the signed revision, else why the change is refused at its tap.</summary>
    private static string? Drifted(ProviderAdmin providers, Guid id, int revision)
    {
        return providers.Store.Instance(id) switch
        {
            null => "the provider instance no longer exists; nothing was changed",
            { } instance when instance.Revision != revision => $"the provider instance changed after this was authorized (it is at revision {instance.Revision.ToString(CultureInfo.InvariantCulture)} now); nothing was changed",
            _ => null,
        };
    }

    private static string? ConfigurationProblem(string? configuration)
    {
        return configuration is null ? "give the configuration (a JSON object)"
            : !OneLine(configuration) ? "The configuration must be on one line (compact JSON, without line breaks or control characters)."
            : ProviderAdmin.ConfigurationScreen(configuration);
    }

    /// <summary>False when <c>confirm-warnings</c> is given with any value but yes.</summary>
    private static bool TryConfirm(IReadOnlyDictionary<string, string> args, out bool confirmed)
    {
        string? text = Arg(args, "confirm-warnings");
        confirmed = text == "yes";

        return text is null || confirmed;
    }

    private static void AddConfirmation(List<(string Name, string Value)> parameters, bool confirmed)
    {
        if (confirmed)
        {
            parameters.Add(("confirm-warnings", "yes"));
        }
    }

    /// <summary>Why a validation result stops the change (counts only: the adapter's messages are shown by the validation, never in a refusal, the audit or the signed text), or null.</summary>
    private static string? ValidationProblem(ValidationDto result, bool confirmed, string what)
    {
        int errors = result.Issues.Count(issue => issue.Severity == "error");
        int warnings = Warnings(result);
        if (errors > 0)
        {
            return $"the provider found {Plural(errors, "error")} in this {what}; check it with the validation";
        }

        return warnings > 0 && !confirmed ? $"the provider reported {Plural(warnings, "warning")} about this {what}; check them, then confirm with confirm-warnings=yes" : null;
    }

    /// <summary>
    /// At the tap: as <see cref="ValidationProblem" />, and when warnings were confirmed, their number must be the one the signed sentence showed (a confirmation covers
    /// the warnings that were shown, not new ones).
    /// </summary>
    private static string? AppliedValidationProblem(ValidationDto result, bool confirmed, int signedWarnings, string what)
    {
        if (ValidationProblem(result, confirmed, what) is { } problem)
        {
            return problem;
        }

        int warnings = Warnings(result);
        return confirmed && warnings != signedWarnings
            ? $"the provider now reports {Plural(warnings, "warning")} about this {what}; check them again"
            : null;
    }

    private static int Warnings(ValidationDto result) => result.Issues.Count(issue => issue.Severity == "warning");

    private static string ValidationLine(ValidationDto result)
    {
        int warnings = Warnings(result);

        return warnings == 0 ? "Validation: no issues" : $"Validation: {Plural(warnings, "warning")}, confirmed";
    }

    private static string Plural(int count, string one, string? many = null) => count.ToString(CultureInfo.InvariantCulture) + " " + (count == 1 ? one : many ?? one + "s");
}

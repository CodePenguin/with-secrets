namespace WithSecrets;

// What the admin app sees of provider instances, mounts and namespace entries. Strings are constants or stored non-secret values; nothing here carries a credential.

internal sealed record ProviderTypeDto(string Type, string AdapterVersion);

/// <summary>Lifecycle and health as lower-case enum names, each with the adapter's already sanitised message and the registry's time of receipt.</summary>
internal sealed record ProviderStatusDto(string Lifecycle, string? LifecycleMessage, DateTimeOffset LifecycleAt, string Health, string? HealthMessage, DateTimeOffset HealthAt);

/// <summary><see cref="Status" /> is null when the instance is not registered (it did not start). <see cref="Configuration" /> is the stored, non-secret configuration text.</summary>
internal sealed record ProviderDto(Guid Id, string Name, string Type, string Configuration, int MaxStaleSeconds, int Revision, int Mounts, ProviderStatusDto? Status, IReadOnlyList<string> Actions);

/// <summary><see cref="Kind" /> is "tree" or "single".</summary>
internal sealed record MountDto(Guid Id, Guid InstanceId, string InstanceName, string Kind, string LogicalPath, string BasePath, int Entries, IReadOnlyList<string> Actions);

/// <summary><see cref="DescriptionSource" /> is "provider" or "local".</summary>
internal sealed record NamespaceEntryDto(string LogicalPath, string ProviderPath, string ExternalId, string? Description, string DescriptionSource);

/// <summary><see cref="Severity" /> is "error" or "warning".</summary>
internal sealed record ValidationIssueDto(string Message, string Severity, string? Target, string? ProviderCode);

/// <summary><see cref="Ok" /> is true when no issue is an error (warnings are for the administrator to confirm).</summary>
internal sealed record ValidationDto(bool Ok, IReadOnlyList<ValidationIssueDto> Issues);

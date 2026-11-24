using System.Globalization;
using Microsoft.Data.Sqlite;

namespace WithSecrets;

/// <summary>
/// Applies an adapter's <see cref="InvalidateProviderDataEvent" /> in one transaction: drops the affected cache rows, ends the active grants that name the affected
/// logical paths, bumps the instance generation (first, so an in-flight retrieval can tell it raced), then writes one audit record of identifiers and counts, never values.
/// </summary>
public sealed class ProviderInvalidation(ProviderStore store, Action<string, IReadOnlyDictionary<string, string>>? observe)
{
    private const int MaxListText = 1500;
    private const string EventName = "provider-data-invalidated";
    private IHostAudit? _audit;

    internal ProviderInvalidation(ProviderStore store, IHostAudit audit) : this(store, (Action<string, IReadOnlyDictionary<string, string>>?)null)
    {
        _audit = audit;
    }

    public long Generation(Guid instanceId) => store.Generation(instanceId);

    public void Apply(Guid instanceId, InvalidateProviderDataEvent evt)
    {
        var result = store.ApplyInvalidation(instanceId, evt, _audit is null ? null : Append);
        observe?.Invoke(EventName, Metadata(instanceId, evt, result));

        void Append(SqliteConnection connection, SqliteTransaction transaction, (string Scope, IReadOnlyList<string> Paths, int CacheRows, int Grants) change)
        {
            AuditFacts facts = new(AuditEventTypes.Admin, EventName, $"instance {instanceId:D}, scope {change.Scope}", "", "", "", [], Metadata: Metadata(instanceId, evt, change));
            HostAudit.TryRecordIn(_audit!, connection, transaction, facts);
        }
    }

    private static Dictionary<string, string> Metadata(Guid instanceId, InvalidateProviderDataEvent evt,
        (string Scope, IReadOnlyList<string> Paths, int CacheRows, int Grants) change) => new()
    {
        ["instance"] = instanceId.ToString("D"),
        ["scope"] = change.Scope,
        ["mounts"] = Bounded((evt.MountIds ?? []).Select(id => id.ToString("D"))),
        ["externalIds"] = Bounded(evt.ExternalSecretIds ?? []),
        ["paths"] = Bounded(change.Paths),
        ["entries"] = change.Paths.Count.ToString(CultureInfo.InvariantCulture),
        ["cacheRows"] = change.CacheRows.ToString(CultureInfo.InvariantCulture),
        ["grants"] = change.Grants.ToString(CultureInfo.InvariantCulture),
    };

    /// <summary>Identifiers joined by commas, cut to a bounded length with a count of what was left out.</summary>
    internal static string Bounded(IEnumerable<string> items)
    {
        List<string> all = [.. items];
        List<string> kept = [];
        int length = 0;
        foreach (string item in all)
        {
            if (length + item.Length + 1 > MaxListText)
            {
                break;
            }

            kept.Add(item);
            length += item.Length + 1;
        }

        string text = string.Join(",", kept);

        return kept.Count < all.Count ? text + $" (+{(all.Count - kept.Count).ToString(CultureInfo.InvariantCulture)} more)" : text;
    }
}

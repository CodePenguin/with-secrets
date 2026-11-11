using System.Globalization;
using System.Net;

namespace WithSecrets;

/// <summary>
/// Watches for a machine identity that may have been copied. The authority lets one long poll per machine supersede the previous one (a dead connection must not block the machine); when the connection that supersedes
/// comes from a DIFFERENT remote address, that is a sign that two processes hold the same identity (a copied key file, or a cloned container). The rule is fixed, not a setting: <see cref="Threshold" /> supersedes from
/// different addresses within <see cref="Window" /> (so two services alternating, as seen in testing, reach it at the third) record a warning for the machine and one signed audit event (at most one per window).
/// Nothing is disabled: the administrator decides. Only public data is used and recorded: the machine fingerprint, two addresses, a count.
/// </summary>
internal sealed class CopiedIdentityWatch(AuthorityStore store, Func<IHostAudit?> audit, TimeProvider clock)
{
    /// <summary>Supersedes from a different address that make the warning.</summary>
    public const int Threshold = 3;

    /// <summary>The window those supersedes must fall in; also the least time between two audit events of one machine.</summary>
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(10);

    /// <summary>The audit event name (type admin).</summary>
    public const string EventName = "machine-identity-possibly-copied";

    private readonly Lock _lock = new();
    private readonly Dictionary<string, Queue<DateTimeOffset>> _seen = new(StringComparer.Ordinal);

    /// <summary>The text of an address for comparing and recording (an IPv4 address that arrived mapped into IPv6 is the IPv4 one).</summary>
    public static string AddressText(IPAddress? address) => address is null ? "" : (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString();

    /// <summary>A poll of <paramref name="fingerprint" /> was superseded: the older came from <paramref name="olderAddress" />, the newer from <paramref name="newerAddress" />. The same address (or an unknown one) counts for nothing.</summary>
    public void Superseded(string fingerprint, string olderAddress, string newerAddress)
    {
        if (olderAddress.Length == 0 || newerAddress.Length == 0 || string.Equals(olderAddress, newerAddress, StringComparison.Ordinal))
        {
            return;
        }

        DateTimeOffset now = clock.GetUtcNow();
        int count;
        lock (_lock)
        {
            if (!_seen.TryGetValue(fingerprint, out Queue<DateTimeOffset>? times))
            {
                times = _seen[fingerprint] = new Queue<DateTimeOffset>();
            }

            while (times.Count > 0 && now - times.Peek() > Window)
            {
                times.Dequeue();
            }

            times.Enqueue(now);
            count = times.Count;
        }

        if (count < Threshold)
        {
            return;
        }

        try
        {
            if (store.RecordCopyWarning(fingerprint, olderAddress, newerAddress, count, Window))
            {
                Dictionary<string, string> metadata = new(StringComparer.Ordinal)
                {
                    ["machine"] = fingerprint,
                    ["older-address"] = olderAddress,
                    ["newer-address"] = newerAddress,
                    ["count"] = count.ToString(CultureInfo.InvariantCulture),
                    ["window-minutes"] = ((int)Window.TotalMinutes).ToString(CultureInfo.InvariantCulture),
                };
                string reason = $"the connection of machine {KeyIdentity.Display(fingerprint)[..19]} was superseded from a different address {count} times within {(int)Window.TotalMinutes} minutes; its identity may have been copied (not disabled)";
                if (audit()?.TryRecord(new AuditFacts(AuditEventTypes.Admin, EventName, reason, "", "", "", [], Metadata: metadata)) != true)
                {
                    AppLog.Warn("the copied-identity audit event could not be committed");
                }
            }
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            AppLog.Warn("a copied-identity warning could not be recorded ({Type})", error.GetType().Name);
        }
    }
}

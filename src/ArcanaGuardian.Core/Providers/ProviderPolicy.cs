namespace ArcanaGuardian;

/// <summary>
/// The system-wide provider retry and freshness constants and the pure decisions built on them (10.3.3, 10.3.4). None of these is an administrator setting except
/// MaxStaleDuration, which is validated here and never clamped.
/// </summary>
public static class ProviderPolicy
{
    /// <summary>Provider invocations per request (the first try plus two retries).</summary>
    public const int MaxAttempts = 3;

    /// <summary>The hard upper bound of MaxStaleDuration.</summary>
    public static readonly TimeSpan MaxStaleCap = TimeSpan.FromHours(24);

    /// <summary>A provider-supplied RetryAfter is honored but never waited longer than this.</summary>
    public static readonly TimeSpan RetryAfterCap = TimeSpan.FromSeconds(2);

    /// <summary>The overall retrieval deadline for one provider instance batch.</summary>
    public static readonly TimeSpan Deadline = TimeSpan.FromSeconds(10);

    /// <summary>The most one provider CLI invocation takes. Shorter than <see cref="Deadline" />, so a batch can retry a timed-out command.</summary>
    public static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(5);

    /// <summary>The most provider CLI invocations an adapter runs at once for one batch.</summary>
    public const int CommandConcurrency = 4;

    /// <summary>The wait before the second and third invocation.</summary>
    public static readonly TimeSpan[] Backoff = [TimeSpan.FromMilliseconds(200), TimeSpan.FromMilliseconds(400)];

    /// <summary>Null when <paramref name="value" /> is 0 through 24 hours inclusive; otherwise a message. A larger value is rejected, never clamped.</summary>
    public static string? ValidateMaxStale(TimeSpan value)
    {
        if (value < TimeSpan.Zero)
        {
            return "MaxStaleDuration must not be negative.";
        }

        if (value > MaxStaleCap)
        {
            return "MaxStaleDuration must not exceed 24 hours.";
        }

        return null;
    }

    /// <summary>The health a failed provider call says the provider is in.</summary>
    public static AdapterHealthState HealthFor(ProviderErrorKind kind) => kind switch
    {
        ProviderErrorKind.Unavailable => AdapterHealthState.Unavailable,
        ProviderErrorKind.InvalidConfiguration or ProviderErrorKind.AuthenticationFailed or ProviderErrorKind.AccessDenied => AdapterHealthState.Misconfigured,
        _ => AdapterHealthState.Degraded,
    };

    /// <summary>False for a failure that says nothing about the provider: a locked authority, or a secret that is simply gone.</summary>
    public static bool SaysAboutProvider(ProviderErrorKind kind) => kind is not (ProviderErrorKind.InteractionRequired or ProviderErrorKind.SecretNotFound);

    public static bool IsRetryable(ProviderErrorKind kind) => kind is ProviderErrorKind.Unavailable or ProviderErrorKind.RateLimited;

    /// <summary>Only a final temporary availability failure may be answered with a stale cached value.</summary>
    public static bool StaleEligible(ProviderErrorKind kind) => kind is ProviderErrorKind.Unavailable or ProviderErrorKind.RateLimited;

    /// <summary>A cached value is served without calling the provider only while younger than 75% of MaxStaleDuration (and MaxStaleDuration is above zero).</summary>
    public static bool IsFreshEnough(TimeSpan age, TimeSpan maxStale) => maxStale > TimeSpan.Zero && age < RefreshDue(maxStale);

    /// <summary>A value may be served stale while its age is at most MaxStaleDuration (and MaxStaleDuration is above zero).</summary>
    public static bool WithinStaleWindow(TimeSpan age, TimeSpan maxStale) => maxStale > TimeSpan.Zero && age <= maxStale;

    /// <summary>The age at which a proactive refresh is due.</summary>
    public static TimeSpan RefreshDue(TimeSpan maxStale) => maxStale * 0.75;
}

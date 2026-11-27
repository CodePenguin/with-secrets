using System.Text.Json;

using Microsoft.Data.Sqlite;

namespace WithSecrets;

/// <summary>
/// The authority's security settings (<c>authority_settings</c>). Changing one needs an administrator's fresh passkey authorization (<see cref="VerifiedAdmin" />) for exactly that
/// change; a setting that cannot be read counts as the safe default.
/// </summary>
public sealed partial class AuthorityStore
{
    private const string IdleSetting = "session_idle_minutes";
    private const string AbsoluteSetting = "session_absolute_minutes";

    /// <summary>The admin session defaults: 15 minutes idle, 8 hours in all (changed only by an administrator's fresh tap, <see cref="SetSessionTimeouts" />).</summary>
    public const int DefaultSessionIdleMinutes = 15;

    public const int DefaultSessionAbsoluteMinutes = 480;

    public const int MaxSessionIdleMinutes = 120;

    public const int MaxSessionAbsoluteMinutes = 1440;

    private static void Put(SqliteConnection connection, SqliteTransaction transaction, string name, string value)
    {
        WithSecretsDatabase.Execute(connection, transaction, "INSERT INTO authority_settings (name, value) VALUES ($name, $value) ON CONFLICT(name) DO UPDATE SET value = $value", ("$name", name), ("$value", value));
    }

    // ---- admin session timeouts ----

    /// <summary>The idle and absolute admin session timeouts, in minutes (the defaults when unset or unreadable).</summary>
    public (int Idle, int Absolute) SessionTimeouts()
    {
        return Read(connection =>
        {
            if (connection is null)
            {
                return (DefaultSessionIdleMinutes, DefaultSessionAbsoluteMinutes);
            }

            int idle = ReadMinutes(connection, IdleSetting, DefaultSessionIdleMinutes, MaxSessionIdleMinutes, min: 0);
            int absolute = ReadMinutes(connection, AbsoluteSetting, DefaultSessionAbsoluteMinutes, MaxSessionAbsoluteMinutes);

            return idle <= absolute ? (idle, absolute) : (DefaultSessionIdleMinutes, DefaultSessionAbsoluteMinutes);
        });
    }

    private static int ReadMinutes(SqliteConnection connection, string name, int fallback, int max, int min = 1)
    {
        object? stored = WithSecretsDatabase.Scalar(connection, null, "SELECT value FROM authority_settings WHERE name = $name", ("$name", name));

        return stored is string text && int.TryParse(text, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int minutes) && minutes >= min && minutes <= max ? minutes : fallback;
    }

    /// <summary>The problem with these timeouts, or null when they may be set.</summary>
    public static string? SessionTimeoutsProblem(int idle, int absolute)
    {
        if (idle < 0 || idle > MaxSessionIdleMinutes)
        {
            return "the editing idle timeout is 0 (Never) or 1 to " + MaxSessionIdleMinutes + " minutes";
        }

        if (absolute < 1 || absolute > MaxSessionAbsoluteMinutes)
        {
            return "the absolute timeout is 1 to " + MaxSessionAbsoluteMinutes + " minutes";
        }

        return idle > absolute ? "the idle timeout cannot be longer than the absolute one" : null;
    }

    public static (string Operation, IReadOnlyList<(string Name, string Value)> Parameters) SessionTimeoutsOperation(int idle, int absolute) => ("set-session-timeouts",
        [("idle-minutes", idle.ToString(System.Globalization.CultureInfo.InvariantCulture)), ("absolute-minutes", absolute.ToString(System.Globalization.CultureInfo.InvariantCulture))]);

    /// <summary>Sets the admin session timeouts. A security setting: it needs the administrator's fresh passkey authorization of exactly these values. Recorded in the authority's audit history.</summary>
    public void SetSessionTimeouts(int idle, int absolute, VerifiedAdmin admin)
    {
        if (SessionTimeoutsProblem(idle, absolute) is { } problem)
        {
            throw new ArgumentOutOfRangeException(nameof(idle), problem);
        }

        (string operation, IReadOnlyList<(string Name, string Value)> parameters) = SessionTimeoutsOperation(idle, absolute);
        if (!admin.Consume(operation, AdminAuthorizer.Canonical(parameters)))
        {
            throw new UnauthorizedAccessException("the session timeout change was not authorized by a fresh administrator passkey tap for exactly these values");
        }

        string actor = admin.Actor;
        Write((connection, transaction) =>
        {
            Put(connection, transaction, IdleSetting, idle.ToString(System.Globalization.CultureInfo.InvariantCulture));
            Put(connection, transaction, AbsoluteSetting, absolute.ToString(System.Globalization.CultureInfo.InvariantCulture));
            Audit(connection, transaction, "session-timeouts-changed", null, null, actor, $"admin session timeouts: idle {idle} min, absolute {absolute} min", admin.Key);

            return 0;
        });
    }

    internal const string SetMachineLogLevelOperation = "machine-log-level";

    internal DiagnosticSettings DiagnosticsSettings(string fingerprint) => Read(connection =>
    {
        if (connection is null) return DiagnosticSettings.Default;
        object? stored = WithSecretsDatabase.Scalar(connection, null, "SELECT value FROM authority_settings WHERE name = $name",
            ("$name", "diagnostics:" + fingerprint));
        if (stored is not string json) return DiagnosticSettings.Default;
        try
        {
            DiagnosticSettings? settings = JsonSerializer.Deserialize<DiagnosticSettings>(json, DiagnosticWire.Json);
            return settings is not null && settings.Valid() ? settings : DiagnosticSettings.Default;
        }
        catch (JsonException)
        {
            return DiagnosticSettings.Default;
        }
    });

    internal static IReadOnlyList<(string Name, string Value)> DiagnosticsSettingsParameters(string fingerprint, DiagnosticSettings settings) =>
        [("machine", fingerprint), ("level", settings.Level)];

    internal void SetDiagnosticsSettings(string fingerprint, DiagnosticSettings settings, VerifiedAdmin admin)
    {
        if (!settings.Valid()) throw new ArgumentException("invalid machine log level", nameof(settings));
        if (!admin.Consume(SetMachineLogLevelOperation, AdminAuthorizer.Canonical(DiagnosticsSettingsParameters(fingerprint, settings))))
            throw new UnauthorizedAccessException("changing the machine log level requires a fresh administrator passkey tap");

        Write((connection, transaction) =>
        {
            Put(connection, transaction, "diagnostics:" + fingerprint, JsonSerializer.Serialize(settings, DiagnosticWire.Json));
            Audit(connection, transaction, "machine-log-level-changed", fingerprint, null, admin.Actor, $"log level {settings.Level}", admin.Key);
            return 0;
        });
    }

    // ---- spent administrator proofs ----

    /// <summary>True the first time a proof nonce is seen; false when it was spent already. The record lives in this database, so a restart does not forget it, until <paramref name="expires" /> passes.</summary>
    public bool TrySpendAdminNonce(string nonce, DateTimeOffset expires)
    {
        return Write((connection, transaction) =>
        {
            WithSecretsDatabase.Execute(connection, transaction, "DELETE FROM admin_spent_nonces WHERE expires < $now", ("$now", Time(Now)));
            int added = WithSecretsDatabase.Execute(connection, transaction, "INSERT OR IGNORE INTO admin_spent_nonces (nonce, expires) VALUES ($nonce, $expires)", ("$nonce", nonce), ("$expires", Time(expires)));

            return added == 1;
        });
    }

    /// <summary>
    /// Durable record of an attempt at a sensitive administrator operation and how it went: the operation, the outcome and its security-relevant parameters, the admin key's name when
    /// there was a tap. Never a proof, a code, a key or a secret.
    /// </summary>
    public void RecordAdminAttempt(string operation, string outcome, string actor, string parameters, VerifiedCredential? key = null, IReadOnlyDictionary<string, string>? metadata = null)
    {
        Write((connection, transaction) =>
        {
            Audit(connection, transaction, "admin-operation", null, null, actor.Length > 0 ? actor : "(none)", $"{operation}; {outcome}; {parameters.Replace('\n', ' ')}", key, metadata);

            return 0;
        });
    }
}

using Microsoft.Data.Sqlite;

namespace WithSecrets;

/// <summary>
/// The authority's security settings (<c>authority_settings</c>): the unlock policy and, only when the policy is unattended, the platform-sealed unlock material and a hash of it.
/// Changing the policy needs an administrator's fresh passkey authorization (<see cref="VerifiedAdmin" />) for exactly that change; a setting that cannot be read
/// counts as the safe default (manual unlock). The sealed blob is useless without the platform mechanism; the hash only recognizes the material, it opens nothing.
/// </summary>
public sealed partial class AuthorityStore
{
    private const string PolicySetting = "unlock_policy";
    private const string SealedSetting = "unlock_sealed";
    private const string VerifierSetting = "unlock_verifier";
    private const string SignatureSetting = "unlock_signature";
    private const string IdleSetting = "session_idle_minutes";
    private const string AbsoluteSetting = "session_absolute_minutes";

    /// <summary>The admin session defaults: 15 minutes idle, 8 hours in all (changed only by an administrator's fresh tap, <see cref="SetSessionTimeouts" />).</summary>
    public const int DefaultSessionIdleMinutes = 15;

    public const int DefaultSessionAbsoluteMinutes = 480;

    public const int MaxSessionIdleMinutes = 120;

    public const int MaxSessionAbsoluteMinutes = 1440;

    private const string PolicyDomain = "with-secrets unlock policy v1\n";

    /// <summary>What the authority signing key signs when the unattended policy is set: the policy row, the sealed blob and its hash, so that a plain write to with-secrets.db cannot turn unattended unlock on.</summary>
    public static byte[] PolicySigningBytes(UnlockPolicy policy, byte[] sealedMaterial, string verifier) => System.Text.Encoding.UTF8.GetBytes(PolicyDomain + UnlockPolicies.Name(policy) + "\n" + Convert.ToBase64String(sealedMaterial) + "\n" + verifier);

    /// <summary>The operation name and parameters an authorization for <see cref="SetUnlockPolicy" /> must carry.</summary>
    public static (string Operation, IReadOnlyList<(string Name, string Value)> Parameters) PolicyOperation(UnlockPolicy policy) => ("set-unlock-policy", [("policy", UnlockPolicies.Name(policy))]);

    public UnlockPolicy GetUnlockPolicy()
    {
        return Read(connection =>
        {
            if (connection is null)
            {
                return UnlockPolicy.Manual;
            }

            return ReadPolicy(connection, null);
        });
    }

    private static UnlockPolicy ReadPolicy(SqliteConnection connection, SqliteTransaction? transaction)
    {
        object? stored = WithSecretsDatabase.Scalar(connection, transaction, "SELECT value FROM authority_settings WHERE name = $name", ("$name", PolicySetting));

        return UnlockPolicies.TryParse(stored as string, out UnlockPolicy policy) ? policy : UnlockPolicy.Manual;
    }

    /// <summary>The sealed unattended-unlock material and its hash, or null when the policy is not unattended or they are missing.</summary>
    public (byte[] Sealed, string Verifier, byte[]? Signature)? UnattendedMaterial()
    {
        return Read(connection =>
        {
            if (connection is null || ReadPolicy(connection, null) != UnlockPolicy.Unattended)
            {
                return ((byte[], string, byte[]?)?)null;
            }

            object? blob = WithSecretsDatabase.Scalar(connection, null, "SELECT value FROM authority_settings WHERE name = $name", ("$name", SealedSetting));
            object? verifier = WithSecretsDatabase.Scalar(connection, null, "SELECT value FROM authority_settings WHERE name = $name", ("$name", VerifierSetting));
            if (blob is not string blobText || verifier is not string verifierText)
            {
                return null;
            }

            object? signature = WithSecretsDatabase.Scalar(connection, null, "SELECT value FROM authority_settings WHERE name = $name", ("$name", SignatureSetting));
            try
            {
                return (Convert.FromBase64String(blobText), verifierText, signature is string signatureText ? Convert.FromBase64String(signatureText) : null);
            }
            catch (FormatException)
            {
                return null;
            }
        });
    }

    /// <summary>
    /// Sets the unlock policy. Unattended carries the sealed material and its hash; manual removes them. Recorded in the authority's audit history in the same transaction.
    /// Refused unless <paramref name="admin" /> authorizes exactly this change.
    /// </summary>
    public void SetUnlockPolicy(UnlockPolicy policy, byte[]? sealedMaterial, string? verifier, VerifiedAdmin admin, ISigningKey? signer = null)
    {
        (string operation, IReadOnlyList<(string Name, string Value)> parameters) = PolicyOperation(policy);
        if (!admin.Consume(operation, AdminAuthorizer.Canonical(parameters)))
        {
            throw new UnauthorizedAccessException("the unlock policy change was not authorized by a fresh administrator passkey tap for exactly this change");
        }

        if (policy == UnlockPolicy.Unattended && (sealedMaterial is null || verifier is null))
        {
            throw new ArgumentException("unattended unlock needs its sealed material");
        }

        // The authority key signs the unattended policy: a start unlocks itself only for a policy row that key vouches for (a plain write to this file cannot make one).
        string? signature = policy == UnlockPolicy.Unattended && signer is not null ? Convert.ToBase64String(signer.Sign(PolicySigningBytes(policy, sealedMaterial!, verifier!))) : null;

        Write((connection, transaction) =>
        {
            UnlockPolicy before = ReadPolicy(connection, transaction);
            Put(connection, transaction, PolicySetting, UnlockPolicies.Name(policy));
            if (policy == UnlockPolicy.Unattended)
            {
                Put(connection, transaction, SealedSetting, Convert.ToBase64String(sealedMaterial!));
                Put(connection, transaction, VerifierSetting, verifier!);
                if (signature is not null)
                {
                    Put(connection, transaction, SignatureSetting, signature);
                }
                else
                {
                    WithSecretsDatabase.Execute(connection, transaction, "DELETE FROM authority_settings WHERE name = $a", ("$a", SignatureSetting));
                }
            }
            else
            {
                WithSecretsDatabase.Execute(connection, transaction, "DELETE FROM authority_settings WHERE name IN ($a, $b, $c)", ("$a", SealedSetting), ("$b", VerifierSetting), ("$c", SignatureSetting));
            }

            Audit(connection, transaction, "unlock-policy-changed", null, null, admin.Actor, $"unlock policy {UnlockPolicies.Name(before)} to {UnlockPolicies.Name(policy)}");

            return 0;
        });
    }

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

            int idle = ReadMinutes(connection, IdleSetting, DefaultSessionIdleMinutes, MaxSessionIdleMinutes);
            int absolute = ReadMinutes(connection, AbsoluteSetting, DefaultSessionAbsoluteMinutes, MaxSessionAbsoluteMinutes);

            return idle <= absolute ? (idle, absolute) : (DefaultSessionIdleMinutes, DefaultSessionAbsoluteMinutes);
        });
    }

    private static int ReadMinutes(SqliteConnection connection, string name, int fallback, int max)
    {
        object? stored = WithSecretsDatabase.Scalar(connection, null, "SELECT value FROM authority_settings WHERE name = $name", ("$name", name));

        return stored is string text && int.TryParse(text, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int minutes) && minutes >= 1 && minutes <= max ? minutes : fallback;
    }

    /// <summary>The problem with these timeouts, or null when they may be set.</summary>
    public static string? SessionTimeoutsProblem(int idle, int absolute)
    {
        if (idle < 1 || idle > MaxSessionIdleMinutes)
        {
            return "the idle timeout is 1 to " + MaxSessionIdleMinutes + " minutes";
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
            Audit(connection, transaction, "session-timeouts-changed", null, null, actor, $"admin session timeouts: idle {idle} min, absolute {absolute} min");

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
    public void RecordAdminAttempt(string operation, string outcome, string actor, string parameters)
    {
        Write((connection, transaction) =>
        {
            Audit(connection, transaction, "admin-operation", null, null, actor.Length > 0 ? actor : "(none)", $"{operation}; {outcome}; {parameters.Replace('\n', ' ')}");

            return 0;
        });
    }
}

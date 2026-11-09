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
        object? stored = StateDatabase.Scalar(connection, transaction, "SELECT value FROM authority_settings WHERE name = $name", ("$name", PolicySetting));

        return UnlockPolicies.TryParse(stored as string, out UnlockPolicy policy) ? policy : UnlockPolicy.Manual;
    }

    /// <summary>The sealed unattended-unlock material and its hash, or null when the policy is not unattended or they are missing.</summary>
    public (byte[] Sealed, string Verifier)? UnattendedMaterial()
    {
        return Read(connection =>
        {
            if (connection is null || ReadPolicy(connection, null) != UnlockPolicy.Unattended)
            {
                return ((byte[], string)?)null;
            }

            object? blob = StateDatabase.Scalar(connection, null, "SELECT value FROM authority_settings WHERE name = $name", ("$name", SealedSetting));
            object? verifier = StateDatabase.Scalar(connection, null, "SELECT value FROM authority_settings WHERE name = $name", ("$name", VerifierSetting));
            if (blob is not string blobText || verifier is not string verifierText)
            {
                return null;
            }

            try
            {
                return (Convert.FromBase64String(blobText), verifierText);
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
    public void SetUnlockPolicy(UnlockPolicy policy, byte[]? sealedMaterial, string? verifier, VerifiedAdmin admin)
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

        Write((connection, transaction) =>
        {
            UnlockPolicy before = ReadPolicy(connection, transaction);
            Put(connection, transaction, PolicySetting, UnlockPolicies.Name(policy));
            if (policy == UnlockPolicy.Unattended)
            {
                Put(connection, transaction, SealedSetting, Convert.ToBase64String(sealedMaterial!));
                Put(connection, transaction, VerifierSetting, verifier!);
            }
            else
            {
                StateDatabase.Execute(connection, transaction, "DELETE FROM authority_settings WHERE name IN ($a, $b)", ("$a", SealedSetting), ("$b", VerifierSetting));
            }

            Audit(connection, transaction, "unlock-policy-changed", null, null, admin.Actor, $"unlock policy {UnlockPolicies.Name(before)} to {UnlockPolicies.Name(policy)}");

            return 0;
        });
    }

    private static void Put(SqliteConnection connection, SqliteTransaction transaction, string name, string value)
    {
        StateDatabase.Execute(connection, transaction, "INSERT INTO authority_settings (name, value) VALUES ($name, $value) ON CONFLICT(name) DO UPDATE SET value = $value", ("$name", name), ("$value", value));
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

using System.Text.Json;

using Microsoft.Data.Sqlite;

namespace WithSecrets;

internal sealed record AuthenticatorCredential(string Id, string Name, string ReviewKey, string SealedSeed, long LastStep);

public sealed partial class AuthorityStore
{
    private const string AuthenticatorPrefix = "access-totp:";

    private static AuthenticatorCredential? ReadAuthenticator(string? value)
    {
        if (value is null) return null;
        try
        {
            return JsonSerializer.Deserialize<AuthenticatorCredential>(value);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static IReadOnlyList<AuthenticatorCredential> Authenticators(SqliteConnection connection, SqliteTransaction? transaction, string reviewKey) =>
        [.. Query(connection, transaction, "SELECT value FROM authority_settings WHERE name GLOB $pattern",
            row => ReadAuthenticator(row.GetString(0)), ("$pattern", AuthenticatorPrefix + "*"))
            .OfType<AuthenticatorCredential>().Where(item => item.ReviewKey == reviewKey).OrderBy(item => item.Name, StringComparer.OrdinalIgnoreCase)];

    internal IReadOnlyList<AuthenticatorCredential> Authenticators(string reviewKey) => Read(connection =>
        connection is null ? [] : Authenticators(connection, null, reviewKey));

    private static AuthenticatorCredential? Authenticator(SqliteConnection connection, SqliteTransaction? transaction, string id) =>
        ReadAuthenticator(WithSecretsDatabase.Scalar(connection, transaction, "SELECT value FROM authority_settings WHERE name = $name", ("$name", AuthenticatorPrefix + id)) as string);

    internal AuthenticatorCredential? Authenticator(string id) => Read(connection =>
        connection is null ? null : Authenticator(connection, null, id));

    internal static IReadOnlyList<(string, string)> AuthenticatorAddParameters(string name) => [("name", name)];

    internal static IReadOnlyList<(string, string)> AuthenticatorRemoveParameters(AuthenticatorCredential credential) => [("id", credential.Id), ("name", credential.Name)];

    internal bool AddAuthenticator(AuthenticatorCredential credential, VerifiedAdmin approver)
    {
        if (!approver.Key.Admin || !approver.Consume("authenticator-add", AdminAuthorizer.Canonical(AuthenticatorAddParameters(credential.Name))))
            throw new UnauthorizedAccessException("adding an authenticator app requires its own admin passkey authorization");
        return Write((connection, transaction) =>
        {
            if (Authenticators(connection, transaction, credential.ReviewKey).Any(item => string.Equals(item.Name, credential.Name, StringComparison.OrdinalIgnoreCase))) return false;
            Put(connection, transaction, AuthenticatorPrefix + credential.Id, JsonSerializer.Serialize(credential));
            Audit(connection, transaction, "authenticator-app-added", null, null, approver.Actor, credential.Name, approver.Key);
            return true;
        });
    }

    internal bool RemoveAuthenticator(AuthenticatorCredential credential, VerifiedAdmin approver)
    {
        if (!approver.Key.Admin || !approver.Consume("authenticator-remove", AdminAuthorizer.Canonical(AuthenticatorRemoveParameters(credential))))
            throw new UnauthorizedAccessException("removing an authenticator app requires its own admin passkey authorization");
        return Write((connection, transaction) =>
        {
            if (Authenticator(connection, transaction, credential.Id) is not { } current || current.ReviewKey != credential.ReviewKey || current.SealedSeed != credential.SealedSeed)
                return false;
            WithSecretsDatabase.Execute(connection, transaction, "DELETE FROM authority_settings WHERE name = $name", ("$name", AuthenticatorPrefix + credential.Id));
            Audit(connection, transaction, "authenticator-app-removed", null, null, approver.Actor, credential.Name, approver.Key);
            return true;
        });
    }

    internal bool SpendAuthenticatorCode(AuthenticatorCredential credential, long step, AdminSession session) => Write((connection, transaction) =>
    {
        if (Authenticator(connection, transaction, credential.Id) is not { } current || current.ReviewKey != credential.ReviewKey
            || current.SealedSeed != credential.SealedSeed || step <= current.LastStep) return false;
        Put(connection, transaction, AuthenticatorPrefix + credential.Id, JsonSerializer.Serialize(current with { LastStep = step }));
        Audit(connection, transaction, "admin-editing-resumed", null, null, "session of " + session.Identity, "authenticator app " + current.Name, session.Key);
        return true;
    });

    internal static void ClearAuthenticators(SqliteConnection connection, SqliteTransaction transaction) =>
        WithSecretsDatabase.Execute(connection, transaction, "DELETE FROM authority_settings WHERE name GLOB $pattern", ("$pattern", AuthenticatorPrefix + "*"));
}

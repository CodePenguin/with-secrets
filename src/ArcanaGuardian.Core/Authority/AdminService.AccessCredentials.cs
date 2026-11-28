using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace ArcanaGuardian;

public sealed record AuthenticatorSetupDto(string Name, string SetupKey);
internal sealed record AuthenticatorDto(string Id, string Name);

public sealed partial class AdminService
{
    private readonly Lock _authenticatorAttemptsGate = new();
    private readonly Queue<long> _authenticatorAttempts = new();

    internal IReadOnlyList<AuthenticatorDto> AuthenticatorViews() => !IsRemote && CurrentManifest()?.Review is { } review
        ? [.. _p.Store.Authenticators(review.PublicKey).Select(item => new AuthenticatorDto(item.Id, ApprovalSummary.Clean(item.Name)))]
        : [];

    private (AdminPlan? Plan, string? Refusal, int Status)? PlanAuthenticator(string op, IReadOnlyDictionary<string, string> args)
    {
        if (op is not ("authenticator-add" or "authenticator-remove")) return null;
        if (CurrentManifest()?.Review is not { } review || _p.Unlocked is not { IsOpen: true } keys)
            return (null, "open the authority with an admin passkey before managing authenticator apps", 423);

        if (op == "authenticator-remove")
        {
            if (Arg(args, "id") is not { } id || !Guid.TryParseExact(id, "D", out _)
                || _p.Store.Authenticator(id) is not { } credential || credential.ReviewKey != review.PublicKey)
                return (null, "no authenticator app has that identifier", 404);
            return (new AdminPlan(op, "remove authenticator app " + ApprovalSummary.Clean(credential.Name),
                AuthorityStore.AuthenticatorRemoveParameters(credential), a => _p.Lock.UseWhileUnlocked(() =>
                    _p.Store.RemoveAuthenticator(credential, a.Admin!) ? null : "the authenticator app was already removed")), null, 200);
        }

        string? name = Arg(args, "name")?.Trim();
        if (Enrollment.NameError(name) is { } problem) return (null, problem, 400);
        string credentialName = name!;
        StrongBox<AuthenticatorSetupDto?> setup = new();

        return (new AdminPlan(op, "add authenticator app " + ApprovalSummary.Clean(credentialName) + " to resume existing admin sessions",
            AuthorityStore.AuthenticatorAddParameters(credentialName), a => _p.Lock.UseWhileUnlocked(() =>
            {
                string id = Guid.NewGuid().ToString("D");
                Span<byte> seed = stackalloc byte[AuthenticatorCode.SeedSize];
                RandomNumberGenerator.Fill(seed);
                try
                {
                    string? sealedSeed = keys.SealAuthenticatorSeed(review.PublicKey, id, credentialName, seed);
                    if (sealedSeed is null) return "the authority keys changed; prepare the enrollment again";
                    if (!_p.Store.AddAuthenticator(new AuthenticatorCredential(id, credentialName, review.PublicKey, sealedSeed, -1), a.Admin!))
                        return "an authenticator app already has that name";
                    setup.Value = new AuthenticatorSetupDto(credentialName, AuthenticatorCode.SetupKey(seed));
                    return null;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(seed);
                }
            }), AuthenticatorSetup: setup), null, 200);
    }

    private bool TakeAuthenticatorAttempt()
    {
        lock (_authenticatorAttemptsGate)
        {
            long now = _clock.GetTimestamp();
            while (_authenticatorAttempts.TryPeek(out long first) && _clock.GetElapsedTime(first, now) >= TimeSpan.FromSeconds(30))
                _authenticatorAttempts.Dequeue();
            if (_authenticatorAttempts.Count >= 5) return false;
            _authenticatorAttempts.Enqueue(now);
            return true;
        }
    }

    internal int ResumeEditingWithAuthenticator(AdminSession session, string id, string code)
    {
        lock (session.EditingGate)
        {
            if (IsRemote || _p.Lock.IsLocked || Sessions.LockedEditing(session) is not { } generation) return 409;
            if (!TakeAuthenticatorAttempt()) return 429;

            try
            {
                return _p.Lock.UseWhileUnlocked(() =>
                {
                    if (_p.Store.Authenticator(id) is not { } credential || credential.Id != id
                        || _p.Unlocked?.MatchAuthenticatorCode(credential, code, _clock.GetUtcNow()) is not { } step
                        || !_p.Store.SpendAuthenticatorCode(credential, step, session)) return 403;
                    return Sessions.ResumeEditing(session, generation) ? 200 : 409;
                });
            }
            catch (AuthorityLockedException)
            {
                return 409;
            }
        }
    }
}

using System.Globalization;

namespace ArcanaGuardian;

/// <summary>A service-owned sign-in challenge; the browser receives only its passkey options.</summary>
internal sealed record InlineLoginView(ProofStart Proof);

public sealed partial class AdminService
{
    private sealed record InlineLogin(string Browser, string Code, InlineAdminProof Proof, DateTimeOffset Expires);

    private readonly Lock _inlineLoginGate = new();
    private readonly Dictionary<string, InlineLogin> _inlineLogins = new(StringComparer.Ordinal);
    private readonly HashSet<string> _checkingInlineLogins = new(StringComparer.Ordinal);

    private void ClearInlineLogins()
    {
        lock (_inlineLoginGate)
        {
            _inlineLogins.Clear();
            _checkingInlineLogins.Clear();
        }
    }

    internal Task<(InlineLoginView? View, AdminStart Start, string? Ticket)> BeginInlineLoginAsync(string browserId, string origin, CancellationToken cancel)
    {
        string caller = AdminSessions.BrowserCaller(browserId);
        if (IsRemote)
        {
            Refused(OpLogin, RemoteAdminRefusal, caller);

            return Task.FromResult<(InlineLoginView?, AdminStart, string?)>((null, new AdminStart(null, RemoteAdminRefusal, 409), null));
        }

        if (!TakeStart(caller)) return Task.FromResult<(InlineLoginView?, AdminStart, string?)>((null, new AdminStart(null, "too many requests; wait a minute", 429), null));
        if (_p.Lock.IsLocked) return Task.FromResult<(InlineLoginView?, AdminStart, string?)>((null, new AdminStart(null, "the authority is locked: unlock it first", 423), null));

        if (Sessions.BeginLogin(browserId) is not { } begun) return Task.FromResult<(InlineLoginView?, AdminStart, string?)>((null, new AdminStart(null, "too many sign-ins are waiting; wait for them to end", 429), null));
        (string ticket, string code) = begun;
        AfterPlanForTests?.Invoke();
        (int idle, int absolute) = _p.Store.SessionTimeouts();
        string sentence = "start a browser session on the administration app. An admin passkey allows routine changes. An approval passkey opens an approvals session. The session lasts up to "
            + absolute.ToString(CultureInfo.InvariantCulture) + " minutes. " + (idle == 0 ? "Inactivity does not lock editing" : "Editing locks after " + idle.ToString(CultureInfo.InvariantCulture) + " idle minutes");

        try
        {
            IAdminAsker asker = _p.Askers(_ => { });
            if (asker.ApprovalTarget() is not { } target) throw new ProofUnavailableException("no enrolled passkey can prove at this address");
            InlineAdminProof prepared = _p.Authorizer.PrepareInline(sentence, OpLogin, [("login", code)], target, origin);
            lock (_inlineLoginGate)
            {
                foreach (string previous in _inlineLogins.Where(item => item.Value.Browser == browserId).Select(item => item.Key).ToArray()) _inlineLogins.Remove(previous);
                _inlineLogins[ticket] = new InlineLogin(browserId, code, prepared, _clock.GetUtcNow() + AdminSessions.LoginLifetime);
            }

            return Task.FromResult<(InlineLoginView?, AdminStart, string?)>((new InlineLoginView(prepared.Start), new AdminStart(null, null), ticket));
        }
        catch (ProofUnavailableException error)
        {
            Sessions.Forget(ticket, browserId);
            _p.Authorizer.RecordRefusal(OpLogin, error.Message, code);
            return Task.FromResult<(InlineLoginView?, AdminStart, string?)>((null, new AdminStart(null, error.Message, 409), null));
        }
    }

    internal bool? SubmitInlineLoginProof(string browserId, string? ticket, string proof)
    {
        InlineLogin? login;
        lock (_inlineLoginGate)
        {
            if (ticket is null || !_inlineLogins.TryGetValue(ticket, out login) || login.Browser != browserId) return null;
            if (_checkingInlineLogins.Contains(ticket)) return false;
            if (_clock.GetUtcNow() > login.Expires)
            {
                _inlineLogins.Remove(ticket);
                Sessions.Forget(ticket, browserId);
                return false;
            }
            _checkingInlineLogins.Add(ticket);
        }

        AdminAuthorization result = _p.Authorizer.AcceptInline(login.Proof, OpLogin, [("login", login.Code)], proof);
        lock (_inlineLoginGate)
        {
            _checkingInlineLogins.Remove(ticket!);
            if (!_inlineLogins.Remove(ticket!, out InlineLogin? current) || !ReferenceEquals(login, current)) return false;
        }
        VerifiedCredential? credential = result.Credential;
        Sessions.CompleteLogin(login.Code, result.Ok ? credential?.Name ?? result.Admin?.Signer ?? "(unnamed)" : null,
            result.Ok ? null : result.Detail, credential is null ? SessionScope.Approval : SessionCapabilities.FromAdminFlag(credential.Admin), credential);
        return result.Ok;
    }

    internal bool CancelInlineLogin(string browserId, string? ticket)
    {
        if (ticket is null) return false;
        lock (_inlineLoginGate)
        {
            if (!_inlineLogins.TryGetValue(ticket, out InlineLogin? login) || login.Browser != browserId || _checkingInlineLogins.Contains(ticket)) return false;
            _inlineLogins.Remove(ticket);
        }
        Sessions.Forget(ticket, browserId);
        return true;
    }
}

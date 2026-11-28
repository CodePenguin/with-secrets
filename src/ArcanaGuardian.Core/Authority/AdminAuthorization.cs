using System.Globalization;
using System.Text;

namespace ArcanaGuardian;

/// <summary>Shows one operation-bound passkey page. <see cref="Ask(ApprovalPrompt)" /> is the admin-only mutation path; <see cref="ApprovalTarget" /> exposes the authority's enrolled credentials for sign-in and run approval.</summary>
public interface IAdminAsker
{
    ApprovalDecision Ask(ApprovalPrompt prompt);

    /// <summary>The target used by the same authority to prepare a passkey challenge inside its SPA, when supported.</summary>
    EnrollmentTarget? InlineTarget() => null;

    /// <summary>The first target that can verify any enrolled passkey, for sign-in and run approval rather than admin-only changes.</summary>
    EnrollmentTarget? ApprovalTarget() => InlineTarget();

    /// <summary>As <see cref="Ask(ApprovalPrompt)" />; an asker that waits for a person closes its page and refuses when <paramref name="cancel" /> is set.</summary>
    ApprovalDecision Ask(ApprovalPrompt prompt, CancellationToken cancel) => Ask(prompt);

    /// <summary>As <see cref="Ask(ApprovalPrompt, CancellationToken)" />, and the page also asks the passkey for its PRF output (<see cref="ApprovalDecision.Unlock" />). An asker without pages releases nothing.</summary>
    ApprovalDecision AskWithKeyRelease(ApprovalPrompt prompt, CancellationToken cancel) => Ask(prompt, cancel);
}

/// <summary>An <see cref="IAdminAsker" /> over page targets. Administrative changes use admin credentials; sign-in and run approval may use any enrolled credential.</summary>
public sealed class TargetAdminAsker(EnrollmentTarget primary, EnrollmentTarget local) : IAdminAsker
{
    public EnrollmentTarget? InlineTarget() => EnrollmentTarget.FirstThatCanProve(primary.Admin(), local.Admin());

    public EnrollmentTarget? ApprovalTarget() => EnrollmentTarget.FirstThatCanProve(primary, local);

    public ApprovalDecision Ask(ApprovalPrompt prompt) => Ask(prompt, CancellationToken.None);

    public ApprovalDecision Ask(ApprovalPrompt prompt, CancellationToken cancel) => Ask(prompt, false, cancel);

    public ApprovalDecision AskWithKeyRelease(ApprovalPrompt prompt, CancellationToken cancel) => Ask(prompt, true, cancel);

    private ApprovalDecision Ask(ApprovalPrompt prompt, bool unlock, CancellationToken cancel)
    {
        EnrollmentTarget? target = EnrollmentTarget.FirstThatCanProve(primary.Admin(), local.Admin());

        return target is null
            ? ApprovalDecision.Deny(Enrollment.NoTargetMessage(primary.Admin().Method.Id, primary.Admin().Host, local.Admin().Host))
            : target.Approver.Ask(prompt, unlock, cancel);
    }
}

/// <summary>Service-owned input retained until an inline SPA passkey assertion is judged.</summary>
internal sealed record InlineAdminProof(string Ticket, ApprovalEvidence Evidence, ProofContext Context, IProofMethod Method, ProofStart Start, DateTimeOffset Issued,
    byte[]? PrfState, string? PrfKey) : IDisposable
{
    public void Dispose()
    {
        if (PrfState is not null)
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(PrfState);
        }
    }
}

/// <summary>
/// Proof that an administrator's fresh passkey tap authorized exactly one operation with exactly these parameters. Only <see cref="AdminAuthorizer" /> makes one; a store
/// method that changes a security setting takes one and spends it (<see cref="Consume" />), so an operation cannot run on the strength of an earlier tap, of an unlock, or of
/// a tap for another operation or other parameters.
/// </summary>
public sealed class VerifiedAdmin
{
    private int _spent;

    internal VerifiedAdmin(string operation, string parameters, VerifiedCredential key)
    {
        Operation = operation;
        Parameters = parameters;
        Key = key;
    }

    public string Operation { get; }

    public string Parameters { get; }

    public VerifiedCredential Key { get; }

    public string Signer => Key.Name;

    public string Actor => (Key.Admin && Operation != AdminService.OpLogin ? "admin passkey " : "passkey ") + (Signer.Length > 0 ? Signer : "(unnamed)");

    /// <summary>True once, and only for the operation and parameters that were authorized.</summary>
    public bool Consume(string operation, string parameters)
    {
        return Operation == operation && Parameters == parameters && Interlocked.Exchange(ref _spent, 1) == 0;
    }

    /// <summary>For tests of a store method in isolation: a token as the authorizer would issue it. It exists in the library, as the lock's test seam does; no command or setting reaches it.</summary>
    internal static VerifiedAdmin ForTests(string operation, string parameters, string signer = "test admin")  => new(operation, parameters, new VerifiedCredential("test-admin", signer, true));
}

/// <summary>What <see cref="AdminAuthorizer.Authorize" /> came to. <see cref="Evidence" /> is the verified signed page, for an operation whose own authority re-checks it (a grant change).</summary>
public sealed record AdminAuthorization(VerifiedAdmin? Admin, string Detail, ApprovalEvidence? Evidence = null, VerifiedCredential? Credential = null, Unlock? Unlock = null)
{
    public bool Ok => Admin is not null || Credential is not null;
}

/// <summary>
/// The one way a sensitive administrator operation of the authority is authorized: a fresh passkey tap with user verification (the page and the proof check refuse an
/// assertion without it) on a one-use page whose signed text names the operation and its security-relevant parameters, checked again here against the enrolled admin keys. Nothing
/// is reused: every call makes a page; the evidence is accepted once (its nonce is remembered) and only while the page it came from could still be open. A failed, denied,
/// timed-out or unavailable passkey is a refusal; there is no other way in. Each attempt and its outcome is written to the authority's audit history (no proof, no code, no key).
/// </summary>
public sealed class AdminAuthorizer(AuthorityStore store, IApprovalVerifier verifier, TimeProvider? clock = null)
{
    public const string OperationPrefix = "Operation: ";
    public const string ParameterPrefix = "Parameter ";

    public const string TicketPrefix = "Ticket: ";

    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    /// <summary>The canonical form of the parameters a token is bound to: <c>name=value</c> lines in the given order.</summary>
    public static string Canonical(IReadOnlyList<(string Name, string Value)> parameters) => string.Join('\n', parameters.Select(parameter => parameter.Name + "=" + parameter.Value));

    /// <summary>The text the page shows and the passkey signs for an operation: the sentence for the person, the operation name, and one line per parameter.</summary>
    public static string PageText(string sentence, string operation, IReadOnlyList<(string Name, string Value)> parameters)
    {
        StringBuilder text = new("Action: ");
        text.Append(sentence).Append('\n').Append(OperationPrefix).Append(operation);
        foreach ((string name, string value) in parameters)
        {
            text.Append('\n').Append(ParameterPrefix).Append(name).Append(": ").Append(value);
        }

        return text.ToString();
    }

    internal InlineAdminProof PrepareInline(string sentence, string operation, IReadOnlyList<(string Name, string Value)> parameters, EnrollmentTarget target, string origin, bool wantsPrf = false)
    {
        string parameterText = Canonical(parameters);
        if (!Record(operation, "requested", "", parameterText))
        {
            throw new ProofUnavailableException("the audit history cannot be written, so nothing was started");
        }

        string ticket = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(8));
        DateTimeOffset issued = _clock.GetUtcNow();
        List<string> lines = [.. (PageText(sentence, operation, parameters) + "\n" + TicketPrefix + ticket).Split('\n').Select(ApprovalSummary.Clean)];
        if (target.Method.AdminLine() is { } admin) lines.Add(admin);
        lines.Add(ApprovalSummary.IssuedLine(issued));
        string text = string.Join('\n', lines);
        string nonce = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        byte[] bind = RequestBinding.Compute(nonce, text);
        ProofContext context = new(ReuseBinding.Challenge(bind, 0), origin);
        ProofStart start = target.Method.Start(context);
        if (start.Mode != "webauthn") throw new ProofUnavailableException("this proof method cannot be used inside the administration page");

        (byte[]? state, string? key) = wantsPrf ? SecretCrypto.NewServerKey() : (null, null);
        return new InlineAdminProof(ticket, new ApprovalEvidence(nonce, text, ""), context, target.Method, start, issued, state, key);
    }

    internal AdminAuthorization AcceptInline(InlineAdminProof prepared, string operation, IReadOnlyList<(string Name, string Value)> parameters, string proof)
    {
        string parameterText = Canonical(parameters);
        ApprovalEvidence evidence = prepared.Evidence with { Proof = proof };
        DateTimeOffset now = _clock.GetUtcNow();
        if (GrantEvidence.Line(evidence.Text, TicketPrefix) != prepared.Ticket
            || Check(evidence, now, operation, parameters) is { } problem)
        {
            return Refuse(operation, "the signed page is not the page this call prepared", parameterText);
        }

        ProofResult full = prepared.Method.Verify(prepared.Context, proof);
        if (!full.Ok)
        {
            return Refuse(operation, full.Detail, parameterText);
        }

        if (operation == AdminService.OpLogin)
        {
            if (full.Credential is null)
            {
                return Refuse(operation, "the passkey did not identify an enrolled credential", parameterText);
            }

            bool firstLogin;
            try { firstLogin = store.TrySpendAdminNonce(evidence.Nonce, now.AddMinutes(ApprovalSettings.MaxTimeoutMinutes + 5)); }
            catch (AuthorityDatabaseException) { return Refuse(operation, "the spent-proof record cannot be written, so no session was started", parameterText); }
            if (!firstLogin) return Refuse(operation, "this sign-in proof was already used", parameterText);

            VerifiedAdmin login = new(operation, parameterText, full.Credential);
            Record(operation, "authorized", login.Actor, parameterText, login.Key);
            return new AdminAuthorization(login, "authorized", evidence, full.Credential);
        }

        ApprovalCheck check = verifier.Verify(evidence, 0);
        if (!check.Ok || (!check.Admin && !OperationPolicy.AnyKey(operation)))
        {
            return Refuse(operation, "the approval was not signed by an enrolled " + (OperationPolicy.AnyKey(operation) ? "passkey" : "admin key") + " (" + check.Detail + ")", parameterText, check.Credential);
        }

        bool first;
        try { first = store.TrySpendAdminNonce(evidence.Nonce, now.AddMinutes(ApprovalSettings.MaxTimeoutMinutes + 5)); }
        catch (AuthorityDatabaseException) { return Refuse(operation, "the spent-proof record cannot be written, so nothing was applied", parameterText); }
        if (!first) return Refuse(operation, "this approval was already used", parameterText, check.Credential);

        VerifiedAdmin admin = new(operation, parameterText, check.Credential ?? new VerifiedCredential("", check.SignerName, check.Admin));
        Record(operation, "authorized", admin.Actor, parameterText, admin.Key);
        return new AdminAuthorization(admin, "authorized", evidence, full.Credential);
    }

    /// <summary>
    /// With <paramref name="wantsPrf" /> the page also asks the passkey for its PRF output; an authorization that is granted carries it (<see cref="AdminAuthorization.Unlock" />, for the caller to
    /// dispose), and every refusal disposes it here.
    /// </summary>
    public AdminAuthorization Authorize(IAdminAsker asker, string heading, string sentence, string operation, IReadOnlyList<(string Name, string Value)> parameters, CancellationToken cancel = default, bool wantsPrf = false)
    {
        string parameterText = Canonical(parameters);
        if (!Record(operation, "requested", "", parameterText))
        {
            // An operation that cannot be audited is not started.
            return new AdminAuthorization(null, "the audit history cannot be written, so nothing was started");
        }

        // A value only this call knows is part of the signed text, so a proof made for another call (an earlier one, or one relayed from elsewhere) is not this call's answer.
        string ticket = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(8));
        ApprovalDecision asked;
        try
        {
            ApprovalPrompt prompt = new(heading, PageText(sentence, operation, parameters) + "\n" + TicketPrefix + ticket, "Confirm this change", "Change confirmed. The change was made.");
            asked = OperationPolicy.AnyKey(operation)
                ? asker.ApprovalTarget()?.Approver.Ask(prompt, cancel) ?? ApprovalDecision.Deny("no enrolled passkey can prove at this address")
                : wantsPrf ? asker.AskWithKeyRelease(prompt, cancel) : asker.Ask(prompt, cancel);
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            // An asker that fails is a refusal, whatever it throws.
            return Refuse(operation, "the passkey page could not be shown", parameterText);
        }

        AdminAuthorization judged = Judge(asked, ticket, operation, parameters, parameterText);
        if (judged.Ok && operation != AdminService.OpLogin && asked.Unlock is { } released)
        {
            return judged with { Unlock = released };
        }

        asked.Unlock?.Dispose();

        return judged;
    }

    private AdminAuthorization Judge(ApprovalDecision asked, string ticket, string operation, IReadOnlyList<(string Name, string Value)> parameters, string parameterText)
    {
        if (!asked.Approved)
        {
            return Refuse(operation, asked.Detail, parameterText);
        }

        if (asked.Evidence is not { } evidence)
        {
            return Refuse(operation, "the passkey did not produce a signed approval", parameterText);
        }

        DateTimeOffset now = _clock.GetUtcNow();
        if (GrantEvidence.Line(evidence.Text, TicketPrefix) != ticket)
        {
            return Refuse(operation, "the signed page is not the page this call showed", parameterText);
        }

        if (Check(evidence, now, operation, parameters) is { } problem)
        {
            return Refuse(operation, problem, parameterText);
        }

        if (operation == AdminService.OpLogin)
        {
            if (asked.Credential is null)
                return Refuse(operation, "the passkey did not identify an enrolled credential", parameterText);

            bool firstLogin;
            try { firstLogin = store.TrySpendAdminNonce(evidence.Nonce, now.AddMinutes(ApprovalSettings.MaxTimeoutMinutes + 5)); }
            catch (AuthorityDatabaseException) { return Refuse(operation, "the spent-proof record cannot be written, so no session was started", parameterText); }
            if (!firstLogin) return Refuse(operation, "this sign-in proof was already used", parameterText);

            VerifiedAdmin login = new(operation, parameterText, asked.Credential);
            Record(operation, "authorized", login.Actor, parameterText, login.Key);
            return new AdminAuthorization(login, "authorized", evidence, asked.Credential);
        }

        ApprovalCheck check = verifier.Verify(evidence, 0);
        if (!check.Ok || (!check.Admin && !OperationPolicy.AnyKey(operation)))
        {
            return Refuse(operation, "the approval was not signed by an enrolled " + (OperationPolicy.AnyKey(operation) ? "passkey" : "admin key") + " (" + check.Detail + ")", parameterText, check.Credential);
        }

        // A proof is accepted once, and the record outlives a restart (it is kept in arcana-guardian.db until the proof could no longer be fresh).
        bool first;
        try
        {
            first = store.TrySpendAdminNonce(evidence.Nonce, now.AddMinutes(ApprovalSettings.MaxTimeoutMinutes + 5));
        }
        catch (AuthorityDatabaseException)
        {
            return Refuse(operation, "the spent-proof record cannot be written, so nothing was applied", parameterText);
        }

        if (!first)
        {
            return Refuse(operation, "this approval was already used", parameterText, check.Credential);
        }

        VerifiedAdmin admin = new(operation, parameterText, check.Credential ?? new VerifiedCredential("", check.SignerName, check.Admin));
        Record(operation, "authorized", admin.Actor, parameterText, admin.Key);

        return new AdminAuthorization(admin, "authorized", evidence);
    }

    /// <summary>Records a request that was refused before any passkey page was made (no session, no anti-forgery value, an operation that does not apply). Best effort: a refusal needs no audit to stay a refusal.</summary>
    public void RecordRefusal(string operation, string reason, string parameters = "") => Record(operation, "refused: " + ApprovalSummary.Clean(reason), "", parameters);

    /// <summary>Records how an authorized operation ended (applied, or failed after the tap).</summary>
    public void Outcome(VerifiedAdmin admin, string outcome) => Record(admin.Operation, outcome, admin.Actor, admin.Parameters, admin.Key);

    private string? Check(ApprovalEvidence evidence, DateTimeOffset now, string operation, IReadOnlyList<(string Name, string Value)> parameters)
    {
        if (GrantEvidence.Line(evidence.Text, OperationPrefix) != operation)
        {
            return "the signed page is not for this operation";
        }

        foreach ((string name, string value) in parameters)
        {
            if (GrantEvidence.Line(evidence.Text, ParameterPrefix + name + ": ") != value)
            {
                return "the signed page does not carry these parameters";
            }
        }

        // No parameter line may be present that was not asked for (a page for other parameters).
        int signedParameters = evidence.Text.Split('\n').Count(line => line.StartsWith(ParameterPrefix, StringComparison.Ordinal));
        if (signedParameters != parameters.Count)
        {
            return "the signed page carries other parameters";
        }

        if (GrantEvidence.Line(evidence.Text, ApprovalSummary.IssuedPrefix) is not { } issuedText
            || !DateTimeOffset.TryParseExact(issuedText, "O", CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTimeOffset issued)
            || now < issued - GrantEvidence.Skew || now > issued.AddMinutes(ApprovalSettings.MaxTimeoutMinutes))
        {
            return "the signed page is not fresh";
        }

        return null;
    }

    private AdminAuthorization Refuse(string operation, string reason, string parameters, VerifiedCredential? key = null)
    {
        Record(operation, "refused: " + ApprovalSummary.Clean(reason), "", parameters, key);

        return new AdminAuthorization(null, reason);
    }

    /// <summary>Writes one row of the authority's audit history for an administrator operation (an attempt, an outcome). False when it cannot be written.</summary>
    public bool Record(string operation, string outcome, string actor, string parameters, VerifiedCredential? key = null, IReadOnlyDictionary<string, string>? metadata = null)
    {
        try
        {
            store.RecordAdminAttempt(operation, outcome, actor, parameters, key, metadata);

            return true;
        }
        catch (AuthorityDatabaseException)
        {
            AppLog.Warn("the audit of an administrator operation could not be written");

            return false;
        }
    }
}

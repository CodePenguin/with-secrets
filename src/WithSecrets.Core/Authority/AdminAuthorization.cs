using System.Globalization;
using System.Text;

namespace WithSecrets;

/// <summary>Shows the person one operation-bound passkey page and returns their answer. The production implementation is a <see cref="WebApprover" /> that accepts admin keys only.</summary>
public interface IAdminAsker
{
    ApprovalDecision Ask(ApprovalPrompt prompt);
}

/// <summary>An <see cref="IAdminAsker" /> over a page target: the first target where an enrolled admin passkey can prove (as the admin commands do).</summary>
public sealed class TargetAdminAsker(EnrollmentTarget primary, EnrollmentTarget local) : IAdminAsker
{
    public ApprovalDecision Ask(ApprovalPrompt prompt)
    {
        EnrollmentTarget? target = EnrollmentTarget.FirstThatCanProve(primary.Admin(), local.Admin());

        return target is null
            ? ApprovalDecision.Deny(Enrollment.NoTargetMessage(primary.Admin().Method.Id, primary.Admin().Host, local.Admin().Host))
            : target.Approver.Ask(prompt);
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

    internal VerifiedAdmin(string operation, string parameters, string signer)
    {
        Operation = operation;
        Parameters = parameters;
        Signer = signer;
    }

    public string Operation { get; }

    public string Parameters { get; }

    public string Signer { get; }

    public string Actor => "admin passkey " + (Signer.Length > 0 ? Signer : "(unnamed)");

    /// <summary>True once, and only for the operation and parameters that were authorized.</summary>
    public bool Consume(string operation, string parameters)
    {
        return Operation == operation && Parameters == parameters && Interlocked.Exchange(ref _spent, 1) == 0;
    }

    /// <summary>For tests of a store method in isolation: a token as the authorizer would issue it. It exists in the library, as the lock's test seam does; no command or setting reaches it.</summary>
    public static VerifiedAdmin ForTests(string operation, string parameters, string signer = "test admin") => new(operation, parameters, signer);
}

/// <summary>What <see cref="AdminAuthorizer.Authorize" /> came to.</summary>
public sealed record AdminAuthorization(VerifiedAdmin? Admin, string Detail)
{
    public bool Ok => Admin is not null;
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

    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly Lock _lock = new();
    private readonly Dictionary<string, DateTimeOffset> _spentNonces = new(StringComparer.Ordinal);

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

    public AdminAuthorization Authorize(IAdminAsker asker, string heading, string sentence, string operation, IReadOnlyList<(string Name, string Value)> parameters)
    {
        string parameterText = Canonical(parameters);
        if (!Record(operation, "requested", "", parameterText))
        {
            // An operation that cannot be audited is not started.
            return new AdminAuthorization(null, "the audit history cannot be written, so nothing was started");
        }

        ApprovalDecision asked;
        try
        {
            asked = asker.Ask(new ApprovalPrompt(heading, PageText(sentence, operation, parameters)));
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            // An asker that fails is a refusal, whatever it throws.
            return Refuse(operation, "the passkey page could not be shown (" + error.GetType().Name + ")", parameterText);
        }

        if (!asked.Approved)
        {
            return Refuse(operation, asked.Detail, parameterText);
        }

        if (asked.Evidence is not { } evidence)
        {
            return Refuse(operation, "the passkey did not produce a signed approval", parameterText);
        }

        DateTimeOffset now = _clock.GetUtcNow();
        if (Check(evidence, now, operation, parameters) is { } problem)
        {
            return Refuse(operation, problem, parameterText);
        }

        ApprovalCheck check = verifier.Verify(evidence, 0);
        if (!check.Ok || !check.Admin)
        {
            return Refuse(operation, "the approval was not signed by an enrolled admin key (" + check.Detail + ")", parameterText);
        }

        lock (_lock)
        {
            foreach (string old in _spentNonces.Where(item => item.Value < now).Select(item => item.Key).ToList())
            {
                _spentNonces.Remove(old);
            }

            // A proof is accepted once.
            if (!_spentNonces.TryAdd(evidence.Nonce, now.AddMinutes(ApprovalSettings.MaxTimeoutMinutes + 5)))
            {
                return Refuse(operation, "this approval was already used", parameterText);
            }
        }

        VerifiedAdmin admin = new(operation, parameterText, check.SignerName);
        Record(operation, "authorized", admin.Actor, parameterText);

        return new AdminAuthorization(admin, "authorized");
    }

    /// <summary>Records how an authorized operation ended (applied, or failed after the tap).</summary>
    public void Outcome(VerifiedAdmin admin, string outcome) => Record(admin.Operation, outcome, admin.Actor, admin.Parameters);

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

    private AdminAuthorization Refuse(string operation, string reason, string parameters)
    {
        Record(operation, "refused: " + ApprovalSummary.Clean(reason), "", parameters);

        return new AdminAuthorization(null, reason);
    }

    private bool Record(string operation, string outcome, string actor, string parameters)
    {
        try
        {
            store.RecordAdminAttempt(operation, outcome, actor, parameters);

            return true;
        }
        catch (AuthorityDatabaseException)
        {
            AppLog.Warn("the audit of an administrator operation could not be written");

            return false;
        }
    }
}

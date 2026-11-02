using System.Buffers;
using System.Globalization;
using System.Text;

namespace WithSecrets;

/// <summary>
/// <c>--enrolled</c>: a header line with the admin key's fingerprint (see <see cref="AdminKey" />), then one line per entry:
/// name, host, date, and "admin" for the admin entry, separated by tabs. Never key bytes.
/// </summary>
public static class EnrolledListing
{
    public static void Write(StateDatabase db, IReadOnlyList<EnrolledEntry> entries, TextWriter stdout, TextWriter stderr)
    {
        stdout.WriteLine(AdminKey.Line(db));
        foreach (EnrolledEntry entry in entries)
        {
            stdout.WriteLine(ApprovalSummary.Clean(entry.Name) + "\t" + ApprovalSummary.Clean(entry.Detail) + "\t"
                + entry.Created.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) + (entry.Admin ? "\tadmin" : ""));
        }

        if (entries.Count == 0)
        {
            stderr.WriteLine("Nothing is enrolled. Set up the first passkey with: with-secrets --config (with-secrets --enroll adds more).");
        }
    }
}

/// <summary>
/// Adds and removes what a proof method trusts, the same way for every method. The first entry comes with the settings
/// (<c>--config</c>) and is the admin. Every change needs the admin: adding asks the admin first, then the method's own setup
/// has the admin sign the new manifest; removing has the admin sign the new manifest on the approval page. The admin entry
/// cannot be removed. Names are unique without regard to case. Any doubt or error denies. The change happens at the command
/// target; the approval happens at the first of the command target and the other target where the targets' methods can
/// prove (Program gives both targets admin-only methods).
/// </summary>
public sealed class Enrollment(EnrollmentTarget commandTarget, EnrollmentTarget otherTarget, Action<string> announce, AuditLog? audit = null)
{
    // Every change is approved by the admin key.
    private readonly EnrollmentTarget command = commandTarget.Admin();
    private readonly EnrollmentTarget other = otherTarget.Admin();

    public const string DefaultName = "passkey";
    public const int MaxNameLength = 40;

    private const string Heading = "Check this change to what can approve runs.";

    /// <summary>Why the admin entry cannot be removed, and the way to replace it.</summary>
    public const string AdminStays = "The admin passkey cannot be removed. To replace it, delete state.db and run with-secrets --config again.";

    private IProofMethod Method => command.Method;

    /// <summary>
    /// Asks first with what is enrolled, when anything is. Then the method's own setup runs. A refusal or failure is recorded in
    /// the audit log (event change-denied) when one is given.
    /// </summary>
    public ApprovalDecision Enroll(string name)
    {
        return Logged("--enroll", EnrollCore(name));
    }

    /// <summary>A refused or failed change goes into the audit log; the decision is returned as it is.</summary>
    private ApprovalDecision Logged(string commandName, ApprovalDecision decision)
    {
        if (!decision.Approved)
        {
            audit?.TryWriteDenied(commandName, [], decision.Detail);
        }

        return decision;
    }

    private ApprovalDecision EnrollCore(string name)
    {
        string? error = NameError(name);
        if (error is not null)
        {
            return ApprovalDecision.Deny(error);
        }

        name = name.Trim();
        try
        {
            IReadOnlyList<EnrolledEntry> entries = Method.Enrolled();
            if (entries.Any(item => string.Equals(item.Name, name, StringComparison.OrdinalIgnoreCase)))
            {
                return ApprovalDecision.Deny($"a {Method.Id} with that name is already enrolled");
            }

            if (entries.Count == 0)
            {
                return ApprovalDecision.Deny(PasskeyRegistration.NothingEnrolled);
            }

            EnrollmentTarget? approval = ApprovalTarget();
            if (approval is null)
            {
                return NoTarget();
            }

            string text = $"Add a {Method.Id} named \"{name}\" for {command.Approver.Origin}.";
            ApprovalDecision asked = approval.Approver.Ask(new ApprovalPrompt(Heading, text));
            if (!asked.Approved)
            {
                return asked;
            }

            return Method.Enroll(name, announce, manifest => approval.Approver.AskManifest(new ApprovalPrompt(Heading, text + "\nConfirm the new state with the admin " + Method.Id + "."), manifest));
        }
        catch (ProofUnavailableException failure)
        {
            // For example, the method's store exists but cannot be read: that is never "nothing enrolled".
            return ApprovalDecision.Deny(failure.Message);
        }
        catch (Exception failure)
        {
            return ApprovalDecision.Deny("the enrollment failed: " + failure.Message);
        }
    }

    /// <summary>The first of the command target and the other target where an enrolled entry works, else null.</summary>
    private EnrollmentTarget? ApprovalTarget()
    {
        return command.Method.CanProve(command.Host) ? command
            : other.Method.CanProve(other.Host) ? other
            : null;
    }

    private ApprovalDecision NoTarget()
    {
        return ApprovalDecision.Deny(NoTargetMessage(Method.Id, command.Host, other.Host));
    }

    /// <summary>Why no approval can be asked: no enrolled entry works at either host. Names both, or one when they are the same.</summary>
    internal static string NoTargetMessage(string methodId, string first, string second)
    {
        string where = string.Equals(first, second, StringComparison.OrdinalIgnoreCase) ? first : $"{first} or {second}";

        return $"No enrolled {methodId} works at {where}. Run it where a {methodId} is enrolled.";
    }

    public IReadOnlyList<EnrolledEntry> List()
    {
        return Method.Enrolled();
    }

    /// <summary>Always asks the admin, who signs the new manifest. The admin entry cannot be removed. A refusal is recorded like Enroll's.</summary>
    public ApprovalDecision Unenroll(string name)
    {
        return Logged("--unenroll", UnenrollCore(name));
    }

    private ApprovalDecision UnenrollCore(string name)
    {
        string? error = NameError(name);
        if (error is not null)
        {
            return ApprovalDecision.Deny(error);
        }

        name = name.Trim();
        try
        {
            IReadOnlyList<EnrolledEntry> entries = Method.Enrolled();
            if (!entries.Any(item => string.Equals(item.Name, name, StringComparison.OrdinalIgnoreCase)))
            {
                return ApprovalDecision.Deny("nothing enrolled with that name");
            }

            string? stored = Match(entries, name);
            if (stored is null)
            {
                return ApprovalDecision.Deny("more than one name differs from this only in case; give the exact name");
            }

            if (entries.Count(item => item.Name == stored) > 1)
            {
                return ApprovalDecision.Deny($"more than one {Method.Id} has that name");
            }

            if (entries.Any(item => item.Name == stored && item.Admin))
            {
                return ApprovalDecision.Deny(AdminStays);
            }

            EnrollmentTarget? approval = ApprovalTarget();
            if (approval is null)
            {
                return NoTarget();
            }

            string text = $"Remove the {Method.Id} named \"{stored}\"";

            return Method.Unenroll(stored, manifest => approval.Approver.AskManifest(new ApprovalPrompt(Heading, text), manifest));
        }
        catch (ProofUnavailableException failure)
        {
            // For example, the method's store exists but cannot be read: that is never "nothing enrolled".
            return ApprovalDecision.Deny(failure.Message);
        }
        catch (Exception failure)
        {
            return ApprovalDecision.Deny("the removal failed: " + failure.Message);
        }
    }

    /// <summary>
    /// Null when the name may be used, else why not. It must not be empty after trimming, may have at most
    /// <see cref="MaxNameLength" /> characters, and must not hold control, format or line-break characters or broken text.
    /// </summary>
    public static string? NameError(string? name)
    {
        string trimmed = name?.Trim() ?? "";
        if (trimmed.Length == 0)
        {
            return "the name is empty";
        }

        if (trimmed.Length > MaxNameLength)
        {
            return $"the name is longer than {MaxNameLength} characters";
        }

        ReadOnlySpan<char> rest = trimmed;
        while (!rest.IsEmpty)
        {
            if (Rune.DecodeFromUtf16(rest, out Rune rune, out int used) != OperationStatus.Done)
            {
                return "the name is not valid text";
            }

            if (Rune.GetUnicodeCategory(rune) is UnicodeCategory.Control or UnicodeCategory.Format
                or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator)
            {
                return "the name has a control or hidden character";
            }

            rest = rest[used..];
        }

        return null;
    }

    /// <summary>The stored name: the exact one, else the only one that matches without regard to case. Null for none or two.</summary>
    internal static string? Match(IEnumerable<EnrolledEntry> entries, string name)
    {
        List<string> names = [.. entries.Select(item => item.Name)];
        if (names.Contains(name, StringComparer.Ordinal))
        {
            return name;
        }

        List<string> matches = [.. names.Where(item => string.Equals(item, name, StringComparison.OrdinalIgnoreCase)).Distinct(StringComparer.Ordinal)];

        return matches.Count == 1 ? matches[0] : null;
    }
}

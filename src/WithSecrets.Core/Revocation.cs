namespace WithSecrets;

/// <summary>
/// <c>--revoke</c>: ends every saved approval, after the admin passkey approves on the approval page (served at the first of
/// the two targets where the admin key works). With nothing enrolled there can be no saved approval, so nothing is asked.
/// It does not change the manifest. It stops further reuse only; a program that already ran has seen its secrets.
/// </summary>
public static class Revocation
{
    private const string Heading = "Check this change to your saved approvals.";

    /// <summary>0 and what happened, else a <see cref="RunCommand" /> exit code and why.</summary>
    public static (int Code, string Detail) Run(StateDatabase db, EnrollmentTarget primary, EnrollmentTarget local, GrantStore grants)
    {
        const string Ended = "Every saved approval has ended.";
        if (!db.TryManifest(out Manifest? manifest, out string? error))
        {
            return (RunCommand.StoreError, error!);
        }

        // With nothing enrolled there is no saved approval and nothing to record.
        if (manifest is null)
        {
            return grants.TryClear() ? (0, Ended) : (RunCommand.StoreError, $"cannot clear the saved approvals in {db.FileLabel}.");
        }

        AuditLog audit = new(db);
        EnrollmentTarget adminPrimary = primary.Admin();
        EnrollmentTarget adminLocal = local.Admin();
        EnrollmentTarget? target = EnrollmentTarget.FirstThatCanProve(adminPrimary, adminLocal);
        if (target is null)
        {
            string why = Enrollment.NoTargetMessage(adminPrimary.Method.Id, adminPrimary.Host, adminLocal.Host);
            audit.TryWriteDenied("--revoke", [], why);

            return (RunCommand.Denied, why);
        }

        ApprovalDecision asked = target.Approver.Ask(new ApprovalPrompt(Heading, "End every saved approval now. Every run then asks again."));
        if (!asked.Approved)
        {
            audit.TryWriteDenied("--revoke", [], asked.Detail);

            return (RunCommand.Denied, asked.Detail);
        }

        // The grants are cleared and the audit row written in one transaction.
        try
        {
            db.Write((connection, transaction) =>
            {
                int count = StateDatabase.Execute(connection, transaction, "DELETE FROM grants");
                AuditLog.Append(connection, transaction, AuditLog.ChangeRow("approvals-revoked",
                    $"{count} saved approval(s) cleared; {asked.Detail}", AuditLog.KeyName(asked.Detail)));

                return count;
            });

            return (0, Ended);
        }
        catch (StateDatabaseException)
        {
            audit.TryWriteDenied("--revoke", [], "the saved approvals could not be cleared");

            return (RunCommand.StoreError, $"cannot clear the saved approvals in {db.FileLabel}.");
        }
    }
}

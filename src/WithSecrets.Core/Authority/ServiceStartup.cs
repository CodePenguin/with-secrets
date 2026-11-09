namespace WithSecrets;

/// <summary>What <c>with-secrets service</c> prints when it starts: the machine's host name and identity fingerprint (public data), what the authority says about the machine, and the port. Never key material.</summary>
public static class ServiceStartup
{
    public static IReadOnlyList<string> Lines(string hostName, string fingerprint, EnrollmentResult enrolled)
    {
        string state = !enrolled.Accepted
            ? $"with-secrets service: the authority did not accept this machine ({enrolled.Message}); launches are denied."
            : enrolled.Status == MachineStatus.Trusted
                ? "with-secrets service: this machine is Trusted."
                : $"with-secrets service: this machine is {enrolled.Status}; launches are denied. Ask the administrator to approve fingerprint {fingerprint} in the authority's admin web app (with-secrets admin prints its link)";

        return [$"with-secrets service: machine {ApprovalSummary.Clean(hostName)}, identity {KeyIdentity.Display(fingerprint)}", state];
    }

    /// <summary>
    /// The lines about the authority's lock: whether it is locked, the unlock mode (the weaker unattended mode is always named), what an unattended start came to, and where
    /// to unlock. The admin page link is public and carries nothing.
    /// </summary>
    public static IReadOnlyList<string> LockLines(bool locked, UnlockPolicy policy, string? unattendedNote, string adminPageUrl)
    {
        List<string> lines = ["with-secrets service: unlock mode: " + UnlockPolicies.Describe(policy)];
        if (unattendedNote is not null)
        {
            lines.Add("with-secrets service: " + unattendedNote + ".");
        }

        lines.Add(locked
            ? "with-secrets service: the authority is LOCKED; runs are refused until an administrator unlocks it. Unlock at: " + adminPageUrl
            : "with-secrets service: the authority is unlocked. Admin page: " + adminPageUrl);

        return lines;
    }
}

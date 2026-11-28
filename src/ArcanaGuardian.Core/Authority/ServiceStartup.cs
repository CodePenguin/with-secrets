namespace ArcanaGuardian;

/// <summary>What <c>using-secrets service</c> prints when it starts: the machine's host name and identity fingerprint (public data), what the authority says about the machine, and the port. Never key material.</summary>
public static class ServiceStartup
{
    public static IReadOnlyList<string> Lines(string hostName, string fingerprint, EnrollmentResult enrolled, bool remote = false)
    {
        string identity = $"using-secrets service: machine {ApprovalSummary.Clean(hostName)}, identity {KeyIdentity.Display(fingerprint)}";
        if (remote)
        {
            return [identity, "using-secrets service: the remote authority checks this machine's trust before serving launches."];
        }

        string state = !enrolled.Accepted
            ? $"using-secrets service: the authority did not accept this machine ({enrolled.Message}); launches are denied."
            : enrolled.Status == MachineStatus.Trusted
                ? "using-secrets service: this machine is Trusted."
                : $"using-secrets service: this machine is {enrolled.Status}; launches are denied. Ask the administrator to approve fingerprint {fingerprint} in the authority's admin web app (using-secrets admin prints its link)";

        return [identity, state];
    }

    /// <summary>The lines about the authority's lock: whether it is locked and where to unlock. The admin page link is public and carries nothing.</summary>
    public static IReadOnlyList<string> LockLines(bool locked, string adminPageUrl)
    {
        return
        [
            locked
                ? "using-secrets service: the authority is LOCKED; runs are refused until an administrator unlocks it. Unlock it in the administration web app (one passkey tap, no sign-in needed): " + adminPageUrl
                : "using-secrets service: the authority is unlocked. Administration web app: " + adminPageUrl,
        ];
    }
}

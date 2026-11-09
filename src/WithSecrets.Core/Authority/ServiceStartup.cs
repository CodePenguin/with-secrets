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
                : $"with-secrets service: this machine is {enrolled.Status}; launches are denied. Ask the administrator to run: with-secrets admin approve {fingerprint} --name NAME";

        return [$"with-secrets service: machine {ApprovalSummary.Clean(hostName)}, identity {KeyIdentity.Display(fingerprint)}", state];
    }
}

namespace WithSecrets;

/// <summary>
/// <c>with-secrets admin ADDRESS --authority-fingerprint HEX</c>: points this machine's host service at an authority and enrolls this machine there. It records public data only in host.json (the
/// address, the public registration label and the authority key fingerprint this machine will trust; the key itself is pinned at the first handshake that matches the fingerprint), asks the authority to
/// register this machine (Pending until an administrator approves it in the authority's admin web app), and prints this machine's fingerprint and where to approve it. It never takes a secret, never
/// opens the authority's administration (which is not reachable from here by design) and changes nothing at the authority except the one Pending registration.
/// </summary>
public static class AuthorityPairing
{
    public static async Task<int> RunAsync(CliCommand.AdminPair command, LocalDeployment deployment, TextWriter output, TextWriter error, CancellationToken cancel = default)
    {
        RemoteAuthorityConfig config = new(command.Url, MachineEndpointOptions.RegistrationId, command.AuthorityFingerprint ?? "");
        if (RemoteTarget.Problem(config) is { } problem)
        {
            await error.WriteLineAsync("with-secrets: " + problem);

            return RunCommand.Usage;
        }

        try
        {
            deployment.HostConfig.SetRemote(deployment.Fingerprint, config);
        }
        catch (Exception failure) when (failure is ArgumentException or IOException or UnauthorizedAccessException)
        {
            await error.WriteLineAsync("with-secrets: host.json cannot be written (" + failure.GetType().Name + ").");

            return RunCommand.StoreError;
        }

        await output.WriteLineAsync($"This machine now asks the authority at {ApprovalSummary.Clean(command.Url)} (it will trust only the key with fingerprint {KeyIdentity.Display(KeyIdentity.ParseHex(command.AuthorityFingerprint!, true)!)}).");
        EnrollmentResult? enrolled = null;
        try
        {
            deployment.UseRemote(new RemoteAuthority(config with { AuthorityFingerprint = KeyIdentity.ParseHex(command.AuthorityFingerprint!, true)! }, deployment.MachineKey, deployment.HostConfig));
            enrolled = await deployment.EnrollAsync(cancel);
        }
        catch (Exception failure) when (failure is RemoteTransportException or RemoteRefusedException)
        {
            await output.WriteLineAsync("The authority could not be reached now (" + ApprovalSummary.Clean(failure.Message) + "). The setting is saved; start the service and it enrolls this machine when the authority answers.");
        }

        foreach (string line in ServiceStartup.Lines(deployment.HostName, deployment.Fingerprint, enrolled ?? new EnrollmentResult(false, MachineStatus.Pending, deployment.Fingerprint, "not enrolled yet")))
        {
            await output.WriteLineAsync(line);
        }

        await output.WriteLineAsync("Approve this machine where the authority runs: open its admin web app there (run `with-secrets admin` on that machine; it prints the link) and approve fingerprint " + KeyIdentity.Display(deployment.Fingerprint) + " under Machines.");

        return 0;
    }
}

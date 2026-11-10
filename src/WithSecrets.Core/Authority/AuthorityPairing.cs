namespace WithSecrets;

/// <summary>
/// <c>with-secrets admin ADDRESS</c>: pairing a machine with an authority. A stub until the pairing task: the machine listener's pairing route (<see cref="MachineApi.PairingPath" />) answers 501 and nothing here
/// contacts it, writes <c>host.json</c> or enrolls anything. It only says so, so the command line is stable and nothing is half-done.
/// </summary>
public static class AuthorityPairing
{
    public static async Task<int> RunAsync(CliCommand.AdminPair command, TextWriter output, TextWriter error)
    {
        await error.WriteLineAsync("with-secrets: pairing with an authority is not available in this build yet (ADDRESS " + ApprovalSummary.Clean(command.Url) + "). Nothing was contacted and nothing was changed.");
        await output.WriteLineAsync("A machine becomes known to an authority through the authority's one-time pairing invitation; that flow arrives in the next change.");

        return RunCommand.Usage;
    }
}

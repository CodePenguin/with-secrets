namespace WithSecrets;

/// <summary>This machine's identity as the pairing command needs it (the caller owns and disposes the key).</summary>
public sealed record PairingMachine(ISigningKey Key, byte[] IdentityCertificate, string HostName, HostConfigFile HostConfig, Action<string, string>? Audit = null);

/// <summary>Everything the pairing command touches outside itself, so a test can drive it without a terminal, a real environment or a real key store.</summary>
public sealed class PairingEnvironment
{
    public required IPairingConsole Console { get; init; }

    public required Func<string, string?> Variable { get; init; }

    /// <summary>Removes a variable from this process (the pairing variables are cleared once read, so nothing this process starts can inherit them).</summary>
    public required Action<string> ClearVariable { get; init; }

    public required Func<string, string?> ReadFile { get; init; }

    public required Func<string, bool> FileExists { get; init; }

    /// <summary>Opens this machine's identity (only after the invitation was read).</summary>
    public required Func<PairingMachine> OpenMachine { get; init; }

    public TimeProvider Clock { get; init; } = TimeProvider.System;

    /// <summary>For tests: told of every request just before it is sent (see <see cref="PairingClientOptions.OnRequest" />).</summary>
    public Action<string, byte[], string>? OnRequest { get; init; }

    /// <summary>The real thing: the real console and environment.</summary>
    public static PairingEnvironment ForThisProcess(Func<PairingMachine> openMachine) => new()
    {
        Console = new TerminalPairingConsole(),
        Variable = Environment.GetEnvironmentVariable,
        ClearVariable = name => Environment.SetEnvironmentVariable(name, null),
        ReadFile = path => File.ReadAllText(path),
        FileExists = File.Exists,
        OpenMachine = openMachine,
    };
}

/// <summary>
/// <c>with-secrets pair</c>: pairing this machine with an authority (architecture 10.2). It takes the one-time invitation an administrator made in the admin web app (a hidden prompt, or unattended from a secret file or an environment
/// variable, see <see cref="PairingInput" />), runs <see cref="PairingClient" /> and prints ONLY this machine's fingerprint and host name and what to do next. The code is never printed, never put in a message, and the variables that held it are
/// removed from this process once read.
/// </summary>
public static class AuthorityPairing
{
    public static async Task<int> RunAsync(PairingEnvironment environment, TextWriter output, TextWriter error, CancellationToken cancel = default)
    {
        PairingInput.Found found = PairingInput.Obtain(environment.Console, environment.Variable, environment.ReadFile, environment.FileExists);

        // Whatever the source, this process stops carrying the pairing variables: nothing it starts can inherit them.
        environment.ClearVariable(PairingInput.ValueVariable);
        environment.ClearVariable(PairingInput.FileVariable);
        if (found.Bundle is not { } bundle)
        {
            await error.WriteLineAsync("with-secrets: " + found.Problem);

            return RunCommand.Usage;
        }

        PairingMachine machine;
        try
        {
            machine = environment.OpenMachine();
        }
        catch (Exception failure) when (failure is System.Security.Cryptography.CryptographicException or IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            await error.WriteLineAsync("with-secrets: this machine's identity cannot be used (" + failure.GetType().Name + "); nothing was sent");

            return RunCommand.StoreError;
        }

        using (machine.Key)
        {
            PairingResult result;
            try
            {
                result = await PairingClient.RunAsync(new PairingClientOptions
                {
                    Bundle = bundle,
                    MachineKey = machine.Key,
                    IdentityCertificate = machine.IdentityCertificate,
                    HostName = machine.HostName,
                    HostConfig = machine.HostConfig,
                    Clock = environment.Clock,
                    OnRequest = environment.OnRequest,
                    ConfirmReplaceAuthority = question => environment.Console.Confirm(question, "replace"),
                    Audit = machine.Audit,
                }, cancel);
            }
            catch (Exception failure) when (failure is IOException or UnauthorizedAccessException or ArgumentException)
            {
                await error.WriteLineAsync("with-secrets: pairing could not be finished on this machine (" + failure.GetType().Name + "); host.json was not changed");

                return RunCommand.StoreError;
            }

            if (!result.Ok)
            {
                await error.WriteLineAsync("with-secrets: " + result.Message);

                return RunCommand.Denied;
            }

            await output.WriteLineAsync("Paired with the authority at " + ApprovalSummary.Clean(bundle.Authority) + " (its identity: " + KeyIdentity.Display(result.AuthorityFingerprint) + ").");
            await output.WriteLineAsync("This machine is Pending. Give the administrator these two facts to check before approving it in the authority's admin web app:");
            await output.WriteLineAsync("  Fingerprint: " + KeyIdentity.Display(result.MachineFingerprint));
            await output.WriteLineAsync("  Host name:   " + ApprovalSummary.Clean(result.HostName));
            await output.WriteLineAsync("Until it is approved this machine cannot get secrets. Then start the service here: with-secrets service");

            return 0;
        }
    }
}

namespace WithSecrets.E2E;

/// <summary>
/// A machine identity and local authority for the browser tests, over software keys that live as long as the rig. The machine is made
/// Trusted through <see cref="AdminActions.ApproveMachine" />, the operation the admin web app runs after the passkey tap, never by a
/// shortcut in the program.
/// </summary>
internal sealed class E2EMachine : IDisposable
{
    private readonly Dictionary<int, SoftwareSigningKey> _authorityKeys = [];
    private readonly SoftwareSigningKey _machineKey;
    private readonly Lock _lock = new();

    public E2EMachine(string folder)
    {
        // The same key signs the events the commands write (see E2EAudit) and the ones the service writes: one machine, one key.
        _machineKey = E2EAudit.KeyFor(folder);
        Deployment = LocalDeployment.Create(folder, _machineKey, AuthorityKey, "e2e-host");
        Deployment.EnrollAsync().GetAwaiter().GetResult();
        TransitionResult result = AdminActions.ApproveMachine(Deployment.Store, Deployment.Keys, Deployment.HostConfig, Deployment.Fingerprint, Deployment.Fingerprint, "e2e machine", "e2e admin");
        if (!result.Ok)
        {
            throw new InvalidOperationException("the e2e machine could not be trusted: " + result.Message);
        }
    }

    public LocalDeployment Deployment { get; }

    public ServiceTrust Trust => new(Deployment.Fingerprint);

    private ISigningKey AuthorityKey(int generation)
    {
        lock (_lock)
        {
            if (!_authorityKeys.TryGetValue(generation, out SoftwareSigningKey? key))
            {
                _authorityKeys[generation] = key = new SoftwareSigningKey();
            }

            return key;
        }
    }

    public void Dispose()
    {
    }
}

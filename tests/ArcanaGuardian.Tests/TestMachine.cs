namespace ArcanaGuardian.Tests;

/// <summary>
/// A machine identity and a local authority for tests, over software keys that live as long as this object (as CNG keys outlive a
/// process). <see cref="Open" /> builds a deployment over the same folder and keys again: a service restart. A machine is made Trusted
/// through <see cref="AdminActions.ApproveMachine" />, the operation the admin command runs after the passkey tap, never by a
/// shortcut in the program.
/// </summary>
internal sealed class TestMachine : IDisposable
{
    private readonly Dictionary<int, SoftwareSigningKey> _authorityKeys = [];
    private readonly Lock _lock = new();
    private int _lostUpTo;

    public TestMachine(string folder, bool trusted = true, string hostName = "test-host", TimeProvider? clock = null)
    {
        Folder = folder;
        HostName = hostName;
        Clock = clock;
        MachineKey = new SoftwareSigningKey();
        Deployment = Open();
        if (trusted)
        {
            Approve(Deployment);
        }
    }

    public string Folder { get; }

    public string HostName { get; private set; }

    public TimeProvider? Clock { get; }

    public SoftwareSigningKey MachineKey { get; }

    public LocalDeployment Deployment { get; private set; }

    public string Fingerprint => KeyIdentity.Fingerprint(MachineKey.PublicKey);

    public ServiceTrust Trust => new(Fingerprint);

    /// <summary>The persisted authority key of a generation (made on first use).</summary>
    public ISigningKey AuthorityKey(int generation)
    {
        lock (_lock)
        {
            if (generation <= _lostUpTo)
            {
                // A generation the key store lost: whatever is asked for is a different key each time (as a wiped store would make).
                return new SoftwareSigningKey();
            }

            if (!_authorityKeys.TryGetValue(generation, out SoftwareSigningKey? key))
            {
                _authorityKeys[generation] = key = new SoftwareSigningKey();
            }

            return key;
        }
    }

    /// <summary>The key store loses the authority signing keys (a wiped or replaced machine): the next use of a generation makes a new, different key.</summary>
    public void LoseAuthorityKeys()
    {
        lock (_lock)
        {
            _lostUpTo = _authorityKeys.Count == 0 ? 1 : _authorityKeys.Keys.Max();
            _authorityKeys.Clear();
        }
    }

    /// <summary>A deployment over this folder and these keys. The machine key is shared and is not disposed with the deployment.</summary>
    public LocalDeployment Open() => LocalDeployment.Create(Folder, new Shared(MachineKey), AuthorityKey, HostName, Clock);

    /// <summary>A service restart: a new deployment (new store object, new ring, new authority) over the same files and keys.</summary>
    public LocalDeployment Restart(string? hostName = null)
    {
        HostName = hostName ?? HostName;
        Deployment = Open();

        return Deployment;
    }

    /// <summary>Enrolls the machine (Pending) and approves it as the admin command does, pinning the authority key.</summary>
    public static void Approve(LocalDeployment deployment)
    {
        deployment.EnrollAsync().GetAwaiter().GetResult();
        TransitionResult result = AdminActions.ApproveMachine(deployment.Store, deployment.Keys, deployment.HostConfig, deployment.Fingerprint, deployment.Fingerprint, "test machine", "test admin");
        if (!result.Ok)
        {
            throw new InvalidOperationException("the test machine could not be trusted: " + result.Message);
        }
    }

    public void Dispose() => MachineKey.Dispose();

    /// <summary>The same key, whose disposal does nothing.</summary>
    private sealed class Shared(ISigningKey inner) : ISigningKey
    {
        public byte[] PublicKey => inner.PublicKey;

        public byte[] Sign(byte[] data) => inner.Sign(data);

        public void Dispose()
        {
        }
    }
}

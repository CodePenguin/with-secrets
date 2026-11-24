namespace WithSecrets.Tests;

/// <summary>A time source the tests move by hand (the admin app's session timeouts, grant ends).</summary>
internal sealed class AppClock : TimeProvider
{
    private DateTimeOffset _now = DateTimeOffset.UtcNow;

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;
}

/// <summary>Passkey administration for tests: records what the admin app asked of it (the real one runs the enrollment pages, which taps on their own pages).</summary>
internal sealed class FakePasskeys : IPasskeyAdmin
{
    public List<string> Calls { get; } = [];

    public IReadOnlyList<EnrolledEntry> List() => [];

    public ApprovalDecision Enroll(Action<string> announce, Func<string?> stopReason)
    {
        Calls.Add("enroll");
        announce("open http://127.0.0.1:1/enroll-page to add the passkey");

        return ApprovalDecision.Allow("passkey added");
    }

    public ApprovalDecision Unenroll(string name, Action<string> announce, Func<string?> stopReason)
    {
        Calls.Add("unenroll " + name);
        announce("open http://127.0.0.1:1/unenroll-page to remove the passkey");

        return ApprovalDecision.Allow("passkey removed");
    }

    public ApprovalDecision RotateStoreKey(Action<string> announce, Func<string?> stopReason)
    {
        Calls.Add("rotate-store-key");
        announce("open http://127.0.0.1:1/rotate-page to rotate the store key");

        return ApprovalDecision.Allow("keys rotated");
    }
}

/// <summary>A passkey administration whose pages wait until the service says the change must stop (the request was cancelled, the authority locked), as real pages wait for their taps.</summary>
internal sealed class StoppablePasskeys : IPasskeyAdmin
{
    private readonly TaskCompletionSource<string> _stopped = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public Task<string> Stopped => _stopped.Task;

    public IReadOnlyList<EnrolledEntry> List() => [];

    public ApprovalDecision Enroll(Action<string> announce, Func<string?> stopReason)
    {
        announce("open http://127.0.0.1:1/enroll-page to add the passkey");
        for (int i = 0; i < 300; i++)
        {
            if (stopReason() is { } reason)
            {
                _stopped.TrySetResult(reason);

                return ApprovalDecision.Deny("nothing was changed: " + reason);
            }

            Thread.Sleep(20);
        }

        return ApprovalDecision.Allow("passkey added");
    }

    public ApprovalDecision Unenroll(string name, Action<string> announce, Func<string?> stopReason) => Enroll(announce, stopReason);

    public ApprovalDecision RotateStoreKey(Action<string> announce, Func<string?> stopReason) => Enroll(announce, stopReason);
}

/// <summary>Reversible protection for the unattended-unlock tests.</summary>
internal sealed class ReversibleProtection : IUnlockProtection
{
    public string Name => "test protection";

    public string? Unavailable => null;

    public byte[] Seal(byte[] material) => [0x46, .. material.Select(item => (byte)(item ^ 0x5A))];

    public byte[]? Open(byte[] sealedBlob) => [.. sealedBlob.Skip(1).Select(item => (byte)(item ^ 0x5A))];
}

/// <summary>
/// A host service with an admin app for tests: one machine (a fake clock), a state with an admin key (laptop) and an ordinary key (phone), passkey pages with a time limit, and browsers.
/// <see cref="Start" /> makes the service again over the same files (a restart).
/// </summary>
internal sealed class AdminApp : IDisposable
{
    private readonly HostServiceTests.Rig _rig;
    private readonly Func<Action<string>, IAdminAsker> _askers;
    private readonly IPasskeyAdmin? _passkeys;
    private readonly IUnlockProtection? _protection;
    private readonly AdminWebAssets? _web;
    private readonly Func<IApprover>? _approver;
    private readonly bool _machineEndpoint;
    private readonly ProviderRegistry? _providers;
    private SecretStore? _native;

    private readonly Func<string, string?>? _sealOnePasswordConfiguration;
    private readonly Func<string, string, string?>? _sealLastPassConfiguration;
    private readonly Func<string, string?>? _sealVaultConfiguration;

    /// <summary>With <paramref name="providers" />, the service runs over a native secret store (not the counting one) and composes its provider side over that registry.</summary>
    public AdminApp(string root, bool trusted = true, bool unlocked = true, int askSeconds = 4, IPasskeyAdmin? passkeys = null, bool protection = false, AdminWebAssets? web = null, AdminApp? restoreFrom = null, Func<IApprover>? approver = null, bool machineEndpoint = false,
        ProviderRegistry? providers = null, Func<string, string?>? sealOnePasswordConfiguration = null,
        Func<string, string, string?>? sealLastPassConfiguration = null, Func<string, string?>? sealVaultConfiguration = null)
    {
        _providers = providers;
        _sealOnePasswordConfiguration = sealOnePasswordConfiguration;
        _sealLastPassConfiguration = sealLastPassConfiguration;
        _sealVaultConfiguration = sealVaultConfiguration;
        _web = web;
        _approver = approver;
        _machineEndpoint = machineEndpoint;
        Clock = new AppClock();
        string machineFolder = Path.Combine(root, "app-" + Guid.NewGuid().ToString("N")[..8]);
        if (restoreFrom is not null)
        {
            // A second machine: only the backup artifacts (the secret store and with-secrets.db) come over, never host.json or a key; it has keys of its own.
            Directory.CreateDirectory(machineFolder);
            File.Copy(restoreFrom.Store.FilePath, Path.Combine(machineFolder, WithSecretsDatabase.FileName));
            trusted = false;
        }

        Machine = new TestMachine(machineFolder, trusted, clock: Clock);
        if (!trusted && restoreFrom is null)
        {
            Machine.Deployment.EnrollAsync().GetAwaiter().GetResult();
        }

        _rig = new HostServiceTests.Rig(root, startLocked: true, machine: Machine);
        _rig.Service.Dispose();
        Laptop = restoreFrom?.Laptop ?? TestAuthenticator.ES256();
        Phone = restoreFrom?.Phone ?? TestAuthenticator.ES256();
        if (restoreFrom is null)
        {
            DateTimeOffset created = new(2026, 11, 1, 10, 0, 0, TimeSpan.Zero);
            TestState.Add(State, Laptop.Record("localhost", "laptop") with { Created = created }, withStore: true);
            TestState.Add(State, Phone.Record("localhost", "phone") with { Created = created });
        }
        Http = new HttpClient(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false, UseCookies = false }) { Timeout = TimeSpan.FromSeconds(60) };
        _passkeys = passkeys;
        _protection = protection || !OperatingSystem.IsWindows() ? new ReversibleProtection() : null;
        _askers = announce =>
        {
            ApprovalSettings settings = new(null, 0, TimeSpan.FromSeconds(askSeconds));
            PasskeyMethod method = new(new PasskeyStore(State), settings);
            EnrollmentTarget target = EnrollmentTarget.For(method, new WebApprover(method, settings, announce, TimeSpan.Zero));

            return new CountingAsker(new TargetAdminAsker(target, target), () => Interlocked.Increment(ref Asked));
        };
        Start(unlocked);
    }

    private sealed class CountingAsker(IAdminAsker inner, Action count) : IAdminAsker
    {
        public EnrollmentTarget? InlineTarget() => inner.InlineTarget();

        public EnrollmentTarget? ApprovalTarget() => inner.ApprovalTarget();

        public ApprovalDecision Ask(ApprovalPrompt prompt)
        {
            count();

            return inner.Ask(prompt);
        }

        public ApprovalDecision Ask(ApprovalPrompt prompt, CancellationToken cancel)
        {
            count();

            return inner.Ask(prompt, cancel);
        }
    }

    /// <summary>How many passkey pages were asked for.</summary>
    public int Asked;

    public AppClock Clock { get; }

    public TestMachine Machine { get; }

    public TestAuthenticator Laptop { get; }

    public TestAuthenticator Phone { get; }

    public HttpClient Http { get; }

    public StateDatabase State => _rig.State;

    public HostService Service { get; private set; } = null!;

    public AuthorityStore Store => Machine.Deployment.Store;

    public string Fingerprint => Machine.Fingerprint;

    public HostServiceTests.CountingStore Secrets => _rig.Store;

    /// <summary>The rig that holds the work folder and the helpers (a request is posted to <see cref="Service" />, which the rig follows).</summary>
    public HostServiceTests.Rig Rig => _rig;

    public AdminBrowser Browser() => new(Service, Http);

    /// <summary>A browser that has signed in with the admin key.</summary>
    public async Task<AdminBrowser> SignedIn()
    {
        AdminBrowser browser = Browser();
        if (!await browser.SignInAsync(Laptop))
        {
            throw new InvalidOperationException("the test browser could not sign in");
        }

        return browser;
    }

    public void Start(bool unlocked)
    {
        Service?.Dispose();
        Service = HostService.Start(new HostServiceOptions
        {
            CommandLineEndpoint = HostServiceTests.Rig.TestEndpoint(),
            Lock = unlocked ? AuthorityLock.UnlockedForTests() : null,
            State = State,
            Store = _providers is null ? _rig.Store : _native ??= new SecretStore(State),
            ProviderRegistry = _providers,
            SealOnePasswordConfiguration = _sealOnePasswordConfiguration,
            SealVaultConfiguration = _sealVaultConfiguration,
            SealLastPassConfiguration = _sealLastPassConfiguration,
            Deployment = Machine.Restart(),
            Port = 0,
            UnlockProtection = _protection,
            AdminAskerFactory = _askers,
            PasskeyAdminFactory = _passkeys is null ? null : () => _passkeys,
            WebAssets = _web,
            MachineEndpoint = _machineEndpoint ? new MachineListenerOptions { Port = 0 } : null,
            ApproverFactory = _approver is null ? null : (_, _) =>
            {
                // Every approval is a grant: the key test approvers sign with when a test names none (see TestSigner), after the keys of this state.
                TestSigner.Enroll(State);

                return _approver();
            },
        });
        _rig.Service = Service;
    }

    public void Dispose()
    {
        Service.Dispose();
        _rig.Dispose();
        Http.Dispose();
    }
}

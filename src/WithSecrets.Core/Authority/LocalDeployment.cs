namespace WithSecrets;

/// <summary>
/// The parts of a local-authority deployment that belong together: this machine's identity key, the authority (store, keys, the
/// <see cref="LocalAuthority" /> itself) and <c>host.json</c>. The host service takes one of these and talks to the authority only
/// through <see cref="IAuthority" /> and signed messages.
/// </summary>
public sealed class LocalDeployment(AuthorityStore store, AuthorityKeyRing keys, LocalAuthority authority, ISigningKey machineKey, string hostName, HostConfigFile hostConfig, TimeProvider clock) : IDisposable
{
    public AuthorityStore Store => store;

    public AuthorityKeyRing Keys => keys;

    public LocalAuthority Authority => authority;

    /// <summary>What the host service talks to: the local authority itself. Tests put a link in its place that can go offline or alter answers.</summary>
    public IAuthority Link { get; set; } = authority;

    /// <summary>Where the host sends its audit events: the local authority itself. Tests put a sink in its place that can fail, delay or answer wrongly.</summary>
    public IAuditSink AuditSink { get; set; } = authority;

    /// <summary>
    /// Remote-authority mode: the host talks to the authority through <paramref name="remote" /> (HTTPS: TLS 1.3 mutual authentication, HTTP/2) for decisions, grants, check-ins, invalidations
    /// and audit upload. The signed contracts and the host's checks are unchanged. Disposed with the deployment.
    /// </summary>
    public void UseRemote(RemoteAuthority remote)
    {
        Link = remote;
        AuditSink = remote;
        _remote = remote;
    }

    private RemoteAuthority? _remote;

    /// <summary>The remote authority client when the host is in remote mode, else null.</summary>
    public RemoteAuthority? Remote => _remote;

    public ISigningKey MachineKey => machineKey;

    public string HostName => hostName;

    public HostConfigFile HostConfig => hostConfig;

    public TimeProvider Clock => clock;

    public string Fingerprint => KeyIdentity.Fingerprint(machineKey.PublicKey);

    private byte[]? _identityCertificate;

    /// <summary>This machine's self-signed identity certificate (DER, public data), made from the identity key on first need and kept beside host.json; it is what enrollment presents and what peers validate temporary TLS certificates against.</summary>
    public byte[] IdentityCertificate => _identityCertificate ??= MachineIdentityFile.LoadOrCreate(Path.GetDirectoryName(hostConfig.FilePath)!, machineKey, clock);

    /// <summary>
    /// Renews this machine's identity certificate before it expires (same key, so the same fingerprint): in remote mode the authority is told first, over the authenticated connection, and only when it accepted the new certificate
    /// is the file replaced (so the authority never holds a certificate older than the one this machine presents). Returns true when a renewal happened. Nothing changes on any failure; it is tried again at the next check.
    /// </summary>
    public async Task<bool> RenewIdentityIfDueAsync(CancellationToken cancel = default)
    {
        byte[] current = IdentityCertificate;
        if (_remote is null || !MachineIdentityFile.RenewalDue(current, clock.GetUtcNow()))
        {
            return false;
        }

        byte[] renewed = MachineIdentityFile.Renewed(machineKey, clock);
        if (!await _remote.RenewIdentityAsync(renewed, cancel))
        {
            return false;
        }

        MachineIdentityFile.Store(Path.GetDirectoryName(hostConfig.FilePath)!, renewed);
        _identityCertificate = renewed;

        return true;
    }

    /// <summary>A deployment over any keys (tests, tools). <paramref name="authorityKey" /> opens the authority key of a generation.</summary>
    public static LocalDeployment Create(string folder, ISigningKey machineKey, Func<int, ISigningKey> authorityKey, string hostName, TimeProvider? clock = null, Func<int, ISigningKey>? create = null, WithSecretsDatabase? database = null)
    {
        clock ??= TimeProvider.System;
        AuthorityStore store = new(database ?? WithSecretsDatabase.InFolder(folder), clock);
        AuthorityKeyRing keys = new(store, authorityKey, clock, create);

        return new LocalDeployment(store, keys, new LocalAuthority(store, keys, clock), machineKey, hostName, HostConfigFile.InFolder(folder), clock);
    }

    /// <summary>
    /// The deployment of this user's machine: the machine identity and the authority signing key are persistent keys under their fixed names (<see cref="MachineKeyStore" />: non-exportable CNG keys on Windows, owner-only
    /// key files under <c>keys</c> in the store folder elsewhere), made on first use; the rest is in the store folder.
    /// </summary>
    public static LocalDeployment OpenProduction(string folder, WithSecretsDatabase? database = null)
    {
        ISigningKey machine = MachineKeyStore.OpenOrCreate(folder, KeyNames.Machine, out _);
        LocalDeployment deployment = Create(folder, machine, generation => MachineKeyStore.OpenOrCreate(folder, AuthorityKeyNameOf(generation), out _), Environment.MachineName,
            create: generation => MachineKeyStore.CreateFresh(folder, AuthorityKeyNameOf(generation)), database: database);

        return deployment;
    }

    /// <summary>The authority key ring of this user's machine over a store (the keys are in the platform key store, see <see cref="OpenProduction" />).</summary>
    public static AuthorityKeyRing ProductionKeyRing(AuthorityStore store)
    {
        string folder = Path.GetDirectoryName(store.FilePath)!;

        return new(store, generation => MachineKeyStore.OpenOrCreate(folder, AuthorityKeyNameOf(generation), out _), null, generation => MachineKeyStore.CreateFresh(folder, AuthorityKeyNameOf(generation)));
    }

    /// <summary>The fingerprint of this user's machine identity if the key exists already (nothing is created), else null.</summary>
    public static string? ExistingMachineFingerprint(string folder)
    {
        using ISigningKey? key = MachineKeyStore.TryOpen(folder, KeyNames.Machine);

        return key is null ? null : KeyIdentity.Fingerprint(key.PublicKey);
    }

    /// <summary>The CNG name of an authority key generation: the fixed name, with " gN" from generation 2.</summary>
    public static string AuthorityKeyNameOf(int generation) => generation <= 1 ? KeyNames.Authority : KeyNames.Authority + " g" + generation;

    /// <summary>First contact with the authority: proves possession of the machine key and records the machine (Pending when new). Idempotent.</summary>
    public async Task<EnrollmentResult> EnrollAsync(CancellationToken cancel = default)
    {
        byte[] challenge = await Link.BeginEnrollmentAsync(cancel);

        return await Link.EnrollAsync(EnrollmentRequest.Create(hostName, challenge, machineKey, IdentityCertificate), cancel);
    }

    public HostAuthorization CreateAuthorization(LaunchGate gate, IMonotonicClock? monotonic = null) => new(Link, machineKey, hostName, hostConfig, gate, (requestId, digest, present) => authority.Offer(requestId, digest, present), clock, monotonic);

    private TemporaryCertificate? _tls;

    /// <summary>This running instance's temporary TLS certificate (a fresh in-memory key, a 24-hour leaf signed by the machine identity key, replaced one hour before it expires): the client certificate of a host talking to a remote authority and the server certificate of the machine listener of an authority. Made on first use, gone with this deployment.</summary>
    public TemporaryCertificate Tls => _tls ??= new TemporaryCertificate(machineKey, IdentityCertificate, clock);

    public void Dispose()
    {
        _remote?.Dispose();
        _tls?.Dispose();
        machineKey.Dispose();
    }
}

using System.Runtime.Versioning;

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

    public ISigningKey MachineKey => machineKey;

    public string HostName => hostName;

    public HostConfigFile HostConfig => hostConfig;

    public TimeProvider Clock => clock;

    public string Fingerprint => KeyIdentity.Fingerprint(machineKey.PublicKey);

    /// <summary>A deployment over any keys (tests, tools). <paramref name="authorityKey" /> opens the authority key of a generation.</summary>
    public static LocalDeployment Create(string folder, ISigningKey machineKey, Func<int, ISigningKey> authorityKey, string hostName, TimeProvider? clock = null)
    {
        clock ??= TimeProvider.System;
        AuthorityStore store = AuthorityStore.InFolder(folder, clock);
        AuthorityKeyRing keys = new(store, authorityKey, clock);

        return new LocalDeployment(store, keys, new LocalAuthority(store, keys, clock), machineKey, hostName, HostConfigFile.InFolder(folder), clock);
    }

    /// <summary>
    /// The deployment of this user's machine: the machine identity and the authority signing key are CNG keys under their fixed names
    /// (made non-exportable on first use), the rest is in the store folder.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static LocalDeployment OpenProduction(string folder)
    {
        CngSigningKey machine = CngSigningKey.OpenOrCreate(KeyNames.Machine, out _);
        LocalDeployment deployment = Create(folder, machine, generation => CngSigningKey.OpenOrCreate(AuthorityKeyNameOf(generation), out _), Environment.MachineName);

        return deployment;
    }

    /// <summary>The authority key ring of this user's machine over a store (the keys are CNG keys, see <see cref="OpenProduction" />).</summary>
    [SupportedOSPlatform("windows")]
    public static AuthorityKeyRing ProductionKeyRing(AuthorityStore store) => new(store, generation => CngSigningKey.OpenOrCreate(AuthorityKeyNameOf(generation), out _));

    /// <summary>The fingerprint of this user's machine identity if the key exists already (nothing is created), else null.</summary>
    [SupportedOSPlatform("windows")]
    public static string? ExistingMachineFingerprint()
    {
        using CngSigningKey? key = CngSigningKey.TryOpen(KeyNames.Machine);

        return key is null ? null : KeyIdentity.Fingerprint(key.PublicKey);
    }

    /// <summary>The CNG name of an authority key generation: the fixed name, with " gN" from generation 2.</summary>
    public static string AuthorityKeyNameOf(int generation) => generation <= 1 ? KeyNames.Authority : KeyNames.Authority + " g" + generation;

    /// <summary>First contact with the authority: proves possession of the machine key and records the machine (Pending when new). Idempotent.</summary>
    public async Task<EnrollmentResult> EnrollAsync(CancellationToken cancel = default)
    {
        byte[] challenge = await authority.BeginEnrollmentAsync(cancel);

        return await authority.EnrollAsync(EnrollmentRequest.Create(hostName, challenge, machineKey), cancel);
    }

    public HostAuthorization CreateAuthorization(LaunchGate gate) => new(authority, machineKey, hostName, hostConfig, gate, authority.Offer, clock);

    public void Dispose() => machineKey.Dispose();
}

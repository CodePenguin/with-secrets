namespace WithSecrets;

/// <summary>
/// The operations behind the admin web app, without any page: what runs after an administrator's fresh passkey tap approved. The same
/// functions are what tests call to put a machine into a state without going through a production shortcut.
/// </summary>
public static class AdminActions
{
    /// <summary>
    /// Approves a machine and, for this host's own machine, pins the authority's public key in <c>host.json</c> (public data) before the
    /// status changes, so a failure in between leaves a pin and a Pending machine (denied), never a Trusted machine that no key vouches for.
    /// A machine that is already Trusted is only pinned again (repair).
    /// </summary>
    public static TransitionResult ApproveMachine(AuthorityStore store, AuthorityKeyRing keys, HostConfigFile host, string? localFingerprint, string fingerprint, string friendlyName, string actor, int? expectedRevision = null, VerifiedCredential? key = null)
    {
        MachineRecord? machine = store.Find(fingerprint);
        if (machine is null)
        {
            return new TransitionResult(false, "no such machine", null);
        }

        if (machine.Status == MachineStatus.Trusted)
        {
            if (fingerprint == localFingerprint)
            {
                PinLocal(keys, host, fingerprint);
            }

            return new TransitionResult(true, "the machine is already Trusted; the authority key is pinned for it", machine);
        }

        if (AuthorityStore.TransitionProblem("approve", machine) is { } problem)
        {
            return new TransitionResult(false, problem, machine);
        }

        if (Enrollment.NameError(friendlyName) is { } nameProblem)
        {
            return new TransitionResult(false, "the friendly name is not usable: " + nameProblem, machine);
        }

        if (fingerprint == localFingerprint)
        {
            PinLocal(keys, host, fingerprint);
        }

        return store.Approve(fingerprint, friendlyName, actor, expectedRevision, key);
    }

    /// <summary>Pins the authority's current public key for this machine.</summary>
    public static void PinLocal(AuthorityKeyRing keys, HostConfigFile host, string machineFingerprint)
    {
        // The key store must hold the key with-secrets.db names: nothing is pinned on the strength of a database row alone.
        keys.Current();
        AuthorityKeyRecord key = keys.CurrentRecord();
        host.Pin(machineFingerprint, new PinnedAuthorityKey(key.Fingerprint, key.PublicKey, DateTimeOffset.UtcNow));
    }

    /// <summary>Recovery: a new authority key with no transition, pinned for this machine by this explicit action. Hosts of other machines must be re-enrolled.</summary>
    public static AuthorityKeyRecord RecoverAuthority(AuthorityKeyRing keys, HostConfigFile host, string? localFingerprint, string actor, VerifiedCredential? key = null)
    {
        AuthorityKeyRecord recovered = keys.Recover(actor, key);
        if (localFingerprint is not null)
        {
            host.Pin(localFingerprint, new PinnedAuthorityKey(recovered.Fingerprint, recovered.PublicKey, DateTimeOffset.UtcNow));
        }

        return recovered;
    }
}

using System.Globalization;

namespace WithSecrets;

/// <summary>What an administrator can ask of the authority: <c>with-secrets admin ACTION</c>.</summary>
public enum AdminAction
{
    Machines,
    Approve,
    Disable,
    Enable,
    Untrust,
    Trust,
    Rename,
    ApproveHostChange,
    RotateAuthorityKey,
    RecoverAuthority,
}

/// <summary>
/// The operations behind the admin commands, without any page: what runs after an administrator's passkey approved. The same
/// functions are what tests call to put a machine into a state without going through a production shortcut.
/// </summary>
public static class AdminActions
{
    /// <summary>
    /// Approves a machine and, for this host's own machine, pins the authority's public key in <c>host.json</c> (public data) before the
    /// status changes, so a failure in between leaves a pin and a Pending machine (denied), never a Trusted machine that no key vouches for.
    /// A machine that is already Trusted is only pinned again (repair).
    /// </summary>
    public static TransitionResult ApproveMachine(AuthorityStore store, AuthorityKeyRing keys, HostConfigFile host, string? localFingerprint, string fingerprint, string friendlyName, string actor, int? expectedRevision = null)
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

        return store.Approve(fingerprint, friendlyName, actor, expectedRevision);
    }

    /// <summary>Pins the authority's current public key for this machine.</summary>
    public static void PinLocal(AuthorityKeyRing keys, HostConfigFile host, string machineFingerprint)
    {
        // The key store must hold the key authority.db names: nothing is pinned on the strength of a database row alone.
        keys.Current();
        AuthorityKeyRecord key = keys.CurrentRecord();
        host.Pin(machineFingerprint, new PinnedAuthorityKey(key.Fingerprint, key.PublicKey, DateTimeOffset.UtcNow));
    }

    /// <summary>Recovery: a new authority key with no transition, pinned for this machine by this explicit action. Hosts of other machines must be re-enrolled.</summary>
    public static AuthorityKeyRecord RecoverAuthority(AuthorityKeyRing keys, HostConfigFile host, string? localFingerprint, string actor)
    {
        AuthorityKeyRecord recovered = keys.Recover(actor);
        if (localFingerprint is not null)
        {
            host.Pin(localFingerprint, new PinnedAuthorityKey(recovered.Fingerprint, recovered.PublicKey, DateTimeOffset.UtcNow));
        }

        return recovered;
    }
}

/// <summary>What the admin commands work with.</summary>
public sealed record AdminContext(AuthorityStore Store, AuthorityKeyRing Keys, HostConfigFile Host, string? LocalFingerprint, EnrollmentTarget Primary, EnrollmentTarget Local, AuditLog Audit, TextWriter Stdout);

/// <summary>
/// <c>with-secrets admin ...</c>: for a person in a terminal. <c>machines</c> lists what the authority knows. Every other action is shown on
/// the one-use approval page with the action, the machine's full fingerprint, host name and state, and applies only after an admin
/// passkey signed that page (the page text, so the action and the fingerprint, is bound into the signed challenge). Nothing changes on a
/// refusal, a time-out or a state that changed while the page was open.
/// </summary>
public static class AdminCommand
{
    private const string Heading = "Check this change to the machines that may use secrets.";

    public static (int Code, string Detail) Run(CliCommand.Admin command, AdminContext context)
    {
        AuthorityStore store = context.Store;
        try
        {
            if (command.Action == AdminAction.Machines)
            {
                return List(store, context.Stdout);
            }

            string name = "admin " + Verb(command.Action);
            MachineRecord? machine = null;
            if (command.Action is not (AdminAction.RotateAuthorityKey or AdminAction.RecoverAuthority))
            {
                (machine, string? problem) = Resolve(store, command);
                if (machine is null)
                {
                    return Deny(context, name, problem!);
                }

                string kind = Verb(command.Action);
                bool repin = command.Action == AdminAction.Approve && machine.Status == MachineStatus.Trusted && machine.Fingerprint == context.LocalFingerprint;
                if (!repin && AuthorityStore.TransitionProblem(kind, machine) is { } refusal)
                {
                    return Deny(context, name, refusal);
                }

                if (command.Action is AdminAction.Approve or AdminAction.Rename && Enrollment.NameError(command.Name) is { } nameProblem)
                {
                    return Deny(context, name, "the friendly name is not usable: " + nameProblem);
                }
            }

            EnrollmentTarget? target = EnrollmentTarget.FirstThatCanProve(context.Primary.Admin(), context.Local.Admin());
            if (target is null)
            {
                return Deny(context, name, Enrollment.NoTargetMessage(context.Primary.Admin().Method.Id, context.Primary.Admin().Host, context.Local.Admin().Host));
            }

            ApprovalDecision asked = target.Approver.Ask(new ApprovalPrompt(Heading, PageText(command, machine, context)));
            if (!asked.Approved)
            {
                return Deny(context, name, asked.Detail);
            }

            string actor = "admin passkey " + (AuditLog.KeyName(asked.Detail) is { Length: > 0 } key ? key : "(unnamed)");

            return Apply(command, machine, context, actor);
        }
        catch (AuthorityDatabaseException failure)
        {
            return (RunCommand.StoreError, failure.Message);
        }
    }

    private static (int Code, string Detail) Apply(CliCommand.Admin command, MachineRecord? machine, AdminContext context, string actor)
    {
        AuthorityStore store = context.Store;
        string fingerprint = machine?.Fingerprint ?? "";
        int? revision = machine?.SecurityRevision;
        TransitionResult result;
        switch (command.Action)
        {
            case AdminAction.Approve:
                result = AdminActions.ApproveMachine(store, context.Keys, context.Host, context.LocalFingerprint, fingerprint, command.Name!, actor, revision);
                break;
            case AdminAction.Disable:
                result = store.Disable(fingerprint, actor, revision);
                break;
            case AdminAction.Enable:
                result = store.Enable(fingerprint, actor, revision);
                break;
            case AdminAction.Untrust:
                result = store.Untrust(fingerprint, actor, revision);
                break;
            case AdminAction.Trust:
                result = store.Trust(fingerprint, command.Fingerprint!, actor, revision);
                break;
            case AdminAction.Rename:
                result = store.Rename(fingerprint, command.Name!, actor, revision);
                break;
            case AdminAction.ApproveHostChange:
                result = store.ApproveHostChange(fingerprint, actor, revision, machine?.PendingHostName);
                break;
            case AdminAction.RotateAuthorityKey:
                KeyTransition transition = context.Keys.Rotate(actor);

                return (0, $"The authority signing key was replaced: {KeyIdentity.Display(transition.OldFingerprint)} to {KeyIdentity.Display(transition.NewFingerprint)}. The host service accepts the new key through the transition the old key signed.");
            case AdminAction.RecoverAuthority:
                AuthorityKeyRecord recovered = AdminActions.RecoverAuthority(context.Keys, context.Host, context.LocalFingerprint, actor);

                return (0, $"The authority signing key was recovered: new key {KeyIdentity.Display(recovered.Fingerprint)}, pinned for this machine." + (context.LocalFingerprint is null ? " This machine has no identity yet, so nothing was pinned; run the service and approve it." : ""));
            default:
                return (RunCommand.Usage, "unknown admin action");
        }

        return result.Ok ? (0, $"{Verb(command.Action)}: {KeyIdentity.Display(fingerprint)} ({result.Message})") : Deny(context, "admin " + Verb(command.Action), result.Message);
    }

    private static (int Code, string Detail) Deny(AdminContext context, string command, string reason)
    {
        context.Audit.TryWriteDenied(command, [], reason);

        return (RunCommand.Denied, reason);
    }

    public static (int Code, string Detail) List(AuthorityStore store, TextWriter output)
    {
        IReadOnlyList<MachineRecord> machines = store.Machines();
        foreach (MachineRecord machine in machines)
        {
            output.WriteLine(string.Join('\t', machine.Fingerprint, machine.Status, "rev " + machine.SecurityRevision.ToString(CultureInfo.InvariantCulture), ApprovalSummary.Clean(machine.HostName),
                machine.FriendlyName is null ? "(no name)" : ApprovalSummary.Clean(machine.FriendlyName), machine.PendingHostName is null ? "" : "host name change waiting: " + ApprovalSummary.Clean(machine.PendingHostName)));
        }

        if (machines.Count == 0)
        {
            output.WriteLine("No machine has contacted the authority yet. Start the host service (with-secrets service); it enrolls this machine as Pending.");
        }

        return (0, "");
    }

    /// <summary>The machine the command names: a full fingerprint (a prefix of 12 or more digits for every action but trust) that matches exactly one.</summary>
    private static (MachineRecord? Machine, string? Problem) Resolve(AuthorityStore store, CliCommand.Admin command)
    {
        bool full = command.Action == AdminAction.Trust;
        string? typed = command.Fingerprint is null ? null : KeyIdentity.ParseHex(command.Fingerprint, full);
        if (typed is null)
        {
            return (null, full ? "trust needs the machine's full fingerprint (64 hex digits), typed as the confirmation" : "give the machine's fingerprint (at least 12 hex digits, see: with-secrets admin machines)");
        }

        IReadOnlyList<MachineRecord> found = store.FindByPrefix(typed);

        return found.Count switch
        {
            0 => (null, "no machine has that fingerprint (see: with-secrets admin machines)"),
            1 => (found[0], null),
            _ => (null, "more than one machine starts with that; type more of the fingerprint"),
        };
    }

    private static string Verb(AdminAction action) => action switch
    {
        AdminAction.Approve => "approve",
        AdminAction.Disable => "disable",
        AdminAction.Enable => "enable",
        AdminAction.Untrust => "untrust",
        AdminAction.Trust => "trust",
        AdminAction.Rename => "rename",
        AdminAction.ApproveHostChange => "approve-host-change",
        AdminAction.RotateAuthorityKey => "rotate-authority-key",
        AdminAction.RecoverAuthority => "recover-authority",
        _ => "machines",
    };

    /// <summary>The text the page shows and the passkey signs: the action, the machine's full fingerprint, host name, name and state.</summary>
    internal static string PageText(CliCommand.Admin command, MachineRecord? machine, AdminContext context)
    {
        if (command.Action is AdminAction.RotateAuthorityKey or AdminAction.RecoverAuthority)
        {
            string current = context.Store.ActiveKey()?.Fingerprint ?? "(none yet)";

            return command.Action == AdminAction.RotateAuthorityKey
                ? $"Action: rotate the authority signing key\nCurrent key: {KeyIdentity.Display(current)}\nThe new key is introduced by a transition that the current key signs; hosts that pinned the current key accept it."
                : $"Action: recover the authority signing key (the current key is lost or not trusted)\nCurrent key: {KeyIdentity.Display(current)}\nA new key is made with no transition and pinned for this machine. Every other host must be enrolled again.";
        }

        MachineRecord shown = machine!;
        string what = command.Action switch
        {
            AdminAction.Approve when shown.Status == MachineStatus.Trusted => $"re-pin the authority key for this machine, which is already Trusted (nothing else changes; the friendly name is not changed). The key to pin: {KeyIdentity.Display(context.Store.ActiveKey()?.Fingerprint ?? "")}",
            AdminAction.Approve => $"approve this machine (it may then ask for secrets) with the friendly name \"{ApprovalSummary.Clean(command.Name ?? "")}\"",
            AdminAction.Disable => "disable this machine (it is denied until enabled; its grants end)",
            AdminAction.Enable => "enable this machine (it starts clean: no earlier grants or cache)",
            AdminAction.Untrust => "withdraw trust from this machine (it is denied; its grants end)",
            AdminAction.Trust => "trust this machine again (it starts clean). You confirmed its full fingerprint",
            AdminAction.Rename => $"rename this machine to \"{ApprovalSummary.Clean(command.Name ?? "")}\" (display only)",
            _ => $"accept the host name \"{ApprovalSummary.Clean(shown.PendingHostName ?? "")}\" for this machine, in place of \"{ApprovalSummary.Clean(shown.HostName)}\"",
        };

        return $"Action: {what}\nFingerprint: {KeyIdentity.Display(shown.Fingerprint)}\nHost name: {ApprovalSummary.Clean(shown.HostName)}\nFriendly name: {(shown.FriendlyName is null ? "(none)" : ApprovalSummary.Clean(shown.FriendlyName))}\nStatus: {shown.Status}, security revision {shown.SecurityRevision.ToString(CultureInfo.InvariantCulture)}";
    }
}

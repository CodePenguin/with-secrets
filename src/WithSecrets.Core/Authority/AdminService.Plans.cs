using System.Globalization;
using System.Security.Cryptography;

namespace WithSecrets;

/// <summary>Adding and removing the passkeys that can approve and administer. The production implementation runs the same enrollment pages as <c>--enroll</c> and <c>--unenroll</c> (admin approval, the new passkey, the admin's signature over the new state).</summary>
public interface IPasskeyAdmin
{
    IReadOnlyList<EnrolledEntry> List();

    /// <summary>
    /// Adds a passkey: the pages announce their link through <paramref name="announce" />. Approved only after the admin passkey's taps on those pages. <paramref name="stopReason" /> answers null while
    /// the change may go on and a short reason once it must not (the request was cancelled or the authority was locked): the change is then not made, however far the pages got.
    /// </summary>
    ApprovalDecision Enroll(Action<string> announce, Func<string?> stopReason);

    ApprovalDecision Unenroll(string name, Action<string> announce, Func<string?> stopReason);
}

/// <summary>Every operation of the admin app, as a plan: what is asked of the person (the sentence and the parameters the passkey signs) and what runs after the verified tap. A plan is made, and refused, before any page exists.</summary>
public sealed partial class AdminService
{
    private string CurrentKey() => _p.Store.ActiveKey()?.Fingerprint is { } fingerprint ? KeyIdentity.Display(fingerprint) : "(none yet)";

    /// <summary>
    /// The authority key was part of what the administrator signed ("Current key: K1"). When the key is another one by the time the change is applied (a rotation or recovery in between), it is refused:
    /// the tap was for the other key.
    /// </summary>
    private string? KeyMoved(string signed) => CurrentKey() == signed ? null : "the authority key changed after this was authorized (it was " + signed + "); ask again";

    private static string? Arg(IReadOnlyDictionary<string, string> args, string name) => args.TryGetValue(name, out string? value) ? value : null;

    private static bool TryNumber(string? text, int min, int max, out int value)
    {
        value = 0;

        return text is { Length: > 0 and <= 6 } && int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value) && value >= min && value <= max;
    }

    private AdminPlan? Plan(string op, IReadOnlyDictionary<string, string> args, out string? refusal, out int status)
    {
        refusal = null;
        status = 409;
        if (op != OpUnlock && _p.Lock.IsLocked)
        {
            refusal = "the authority is locked; unlock it first";
            status = 423;

            return null;
        }

        string key = CurrentKey();
        switch (op)
        {
            case OpUnlock:
                if (!_p.Lock.IsLocked)
                {
                    refusal = "the authority is already unlocked";

                    return null;
                }

                return new AdminPlan("unlock-authority",
                    "unlock the authority so that it serves secret requests again. It creates no grant and widens none; every sensitive change still needs its own passkey tap",
                    [("authority-key", key)],
                    _ =>
                    {
                        if (KeyMoved(key) is { } moved)
                        {
                            return moved;
                        }

                        _p.Lock.Unlock(UnlockMethod.Manual);
                        _p.OnUnlocked();

                        return null;
                    });

            case OpLock:
                return new AdminPlan("lock-authority",
                    "lock the authority now: secret requests stop, the held keys and the synchronized grants are discarded, and every administrator session ends",
                    [("authority-key", key)],
                    _ =>
                    {
                        if (KeyMoved(key) is { } moved)
                        {
                            return moved;
                        }

                        _p.Lock.Lock("locked by an administrator");

                        return null;
                    });

            case OpPolicyManual:
                if (_p.Store.GetUnlockPolicy() == UnlockPolicy.Manual)
                {
                    refusal = "unlock is manual already";

                    return null;
                }

                return PolicyPlan(UnlockPolicy.Manual, "make unlock manual again: after a start an administrator unlocks with a passkey tap, and the unattended-unlock material is deleted", null, null, null);

            case OpPolicyUnattended:
                if (_p.Store.GetUnlockPolicy() == UnlockPolicy.Unattended)
                {
                    refusal = "unlock is unattended already";

                    return null;
                }

                if (_p.Protection.Unavailable is { } unavailable)
                {
                    refusal = unavailable;

                    return null;
                }

                byte[] material = RandomNumberGenerator.GetBytes(32);
                try
                {
                    byte[] sealedBlob = _p.Protection.Seal(material);

                    return PolicyPlan(UnlockPolicy.Unattended,
                        "let the authority unlock itself after it starts, using material that " + _p.Protection.Name + " protects for this user. This is WEAKER than manual unlock: anything that can run as this user can unlock the service the same way. It does not remove the passkey tap for sensitive changes and creates no grant",
                        sealedBlob, Convert.ToHexString(SHA256.HashData(material)), material);
                }
                catch (Exception error) when (error is CryptographicException or InvalidOperationException)
                {
                    CryptographicOperations.ZeroMemory(material);
                    refusal = "the platform could not protect the unlock material";

                    return null;
                }

            case "authority-key-rotate":
                return new AdminPlan("rotate-authority-key",
                    "rotate the authority signing key. The new key is introduced by a transition that the current key signs; hosts that pinned the current key accept it.\nCurrent key: " + key,
                    [("authority-key", key)],
                    a =>
                    {
                        if (KeyMoved(key) is { } moved)
                        {
                            return moved;
                        }

                        _p.Keys.Rotate(a.Admin!.Actor);

                        return null;
                    });

            case "authority-key-recover":
                return new AdminPlan("recover-authority-key",
                    "recover the authority signing key (the current key is lost or not trusted). A new key is made with no transition and pinned for this machine; every other host must be enrolled again.\nCurrent key: " + key,
                    [("authority-key", key)],
                    a =>
                    {
                        if (KeyMoved(key) is { } moved)
                        {
                            return moved;
                        }

                        AdminActions.RecoverAuthority(_p.Keys, _p.HostConfig, _p.LocalFingerprint, a.Admin!.Actor);

                        return null;
                    });

            case "set-audit-retention":
                if (!TryNumber(Arg(args, "days"), 0, AuthorityStore.MaxAuditRetentionDays, out int days))
                {
                    refusal = "retention is 0 to " + AuthorityStore.MaxAuditRetentionDays + " days (0 keeps everything)";
                    status = 400;

                    return null;
                }

                (string retentionOperation, IReadOnlyList<(string, string)> retentionParameters) = AuthorityStore.RetentionOperation(days);

                return new AdminPlan(retentionOperation, "keep the audit events the hosts uploaded for " + (days == 0 ? "ever (no pruning)" : days.ToString(CultureInfo.InvariantCulture) + " days; older events are removed"), retentionParameters,
                    a =>
                    {
                        _p.Store.SetAuditRetentionDays(days, a.Admin!);

                        return null;
                    });

            case "set-session-timeouts":
                if (!TryNumber(Arg(args, "idle"), 1, AuthorityStore.MaxSessionIdleMinutes, out int idle) || !TryNumber(Arg(args, "absolute"), 1, AuthorityStore.MaxSessionAbsoluteMinutes, out int absolute)
                    || AuthorityStore.SessionTimeoutsProblem(idle, absolute) is { } timeoutProblem)
                {
                    refusal = AuthorityStore.SessionTimeoutsProblem(TryNumber(Arg(args, "idle"), 0, 100000, out int shownIdle) ? shownIdle : 0, TryNumber(Arg(args, "absolute"), 0, 100000, out int shownAbsolute) ? shownAbsolute : 0) ?? "give both timeouts in minutes";
                    status = 400;

                    return null;
                }

                (string timeoutOperation, IReadOnlyList<(string, string)> timeoutParameters) = AuthorityStore.SessionTimeoutsOperation(idle, absolute);

                return new AdminPlan(timeoutOperation, $"set the administrator session timeouts: a session ends after {idle} minutes without use, and at most {absolute} minutes after it started. Sessions already open keep working until they reach the new limits", timeoutParameters,
                    a =>
                    {
                        _p.Store.SetSessionTimeouts(idle, absolute, a.Admin!);

                        return null;
                    });

            case "passkey-enroll":
                if (_p.Passkeys is not { } enrolling)
                {
                    refusal = "passkey administration is not available in this service";

                    return null;
                }

                return new AdminPlan("enroll-passkey", "add a passkey that can approve runs (and, if you choose on its page, administer). The next pages ask an admin passkey for approval, make the new passkey and have an admin sign the new state", [],
                    _ => null, null, (announce, stop) =>
                    {
                        ApprovalDecision decision = enrolling.Enroll(announce, stop);

                        return (decision.Approved, decision.Detail, "admin passkey");
                    });

            case "passkey-unenroll":
                if (_p.Passkeys is not { } removing)
                {
                    refusal = "passkey administration is not available in this service";

                    return null;
                }

                string? name = Arg(args, "name");
                if (Enrollment.NameError(name) is { } nameProblem)
                {
                    refusal = nameProblem;
                    status = 400;

                    return null;
                }

                string removeName = name!.Trim();

                return new AdminPlan("remove-passkey", $"remove the passkey named \"{ApprovalSummary.Clean(removeName)}\" (any key but the last admin key). Its page asks an admin passkey to sign the new state", [("name", removeName)],
                    _ => null, null, (announce, stop) =>
                    {
                        ApprovalDecision decision = removing.Unenroll(removeName, announce, stop);

                        return (decision.Approved, decision.Detail, "admin passkey");
                    });

            case "pairing-create":
                if (_p.Pairing is not { } creating)
                {
                    refusal = "pairing is not available in this service";

                    return null;
                }

                if (creating.Unavailable is { } cannot)
                {
                    refusal = cannot;

                    return null;
                }

                string authorityUrl = creating.AuthorityUrl!;
                int lifetime = (int)PairingProtocol.InvitationLifetime.TotalMinutes;
                System.Runtime.CompilerServices.StrongBox<InvitationCreatedDto?> box = new();

                return new AdminPlan("create-pairing-invitation",
                    $"create a one-time pairing invitation for a new machine. It can register ONE machine and is valid for {lifetime} minutes. The invitation (an address, an identifier and a random pairing code) is shown once on this page after your tap and can never be shown again. "
                    + "A machine that pairs with it only becomes Pending: you still check its fingerprint and host name here and approve it with another passkey tap.\nAuthority address: " + authorityUrl,
                    [("authority", authorityUrl), ("valid-minutes", lifetime.ToString(CultureInfo.InvariantCulture))],
                    a =>
                    {
                        (CreatedInvitation? created, string? problem) = creating.Create(a.Admin!.Actor);
                        if (created is null)
                        {
                            return problem ?? "the invitation could not be made";
                        }

                        box.Value = new InvitationCreatedDto(created.Id, created.Expires, created.Bundle);

                        return null;
                    }, Output: box);

            case "pairing-revoke":
                if (_p.Pairing is not { } revoking)
                {
                    refusal = "pairing is not available in this service";

                    return null;
                }

                string? typedId = Arg(args, "id");
                if (typedId is null || !PairingProtocol.IsToken(typedId, PairingProtocol.IdBytes))
                {
                    refusal = "give the invitation's identifier";
                    status = 400;

                    return null;
                }

                _p.Store.ExpireInvitations();
                if (_p.Store.Invitation(typedId) is not { } invitation)
                {
                    refusal = "no invitation has that identifier";
                    status = 404;

                    return null;
                }

                if (invitation.StatusAt(_clock.GetUtcNow()) != "pending")
                {
                    refusal = "the invitation is " + invitation.StatusAt(_clock.GetUtcNow()) + "; only a pending one can be revoked";

                    return null;
                }

                return new AdminPlan("revoke-pairing-invitation", $"revoke the pairing invitation {typedId} (created {CanonicalJson.Time(invitation.Created)}). It can no longer be used. A machine that already paired with it is not affected",
                    [("invitation", typedId)],
                    a => revoking.Revoke(typedId, a.Admin!.Actor) ? null : "the invitation is no longer pending");
        }

        if (op.StartsWith("machine-", StringComparison.Ordinal))
        {
            return MachinePlan(op["machine-".Length..], args, out refusal, out status);
        }

        if (op.StartsWith("grant-", StringComparison.Ordinal))
        {
            return GrantPlan(op["grant-".Length..], args, out refusal, out status);
        }

        refusal = "unknown operation";
        status = 400;

        return null;
    }

    private AdminPlan? PolicyPlan(UnlockPolicy policy, string sentence, byte[]? sealedBlob, string? verifier, byte[]? material)
    {
        (string operation, IReadOnlyList<(string Name, string Value)> parameters) = AuthorityStore.PolicyOperation(policy);

        return new AdminPlan(operation, sentence, parameters, a =>
        {
            // The authority key signs the unattended policy, so that only an administrator's tap (and not a plain write to authority.db) can make one.
            _p.Store.SetUnlockPolicy(policy, sealedBlob, verifier, a.Admin!, policy == UnlockPolicy.Unattended ? _p.Keys.Current() : null);

            return null;
        }, material);
    }

    // ---- machines ----

    private (MachineRecord? Machine, string? Problem) ResolveMachine(string? typed)
    {
        string? hex = typed is null ? null : KeyIdentity.ParseHex(typed, false);
        if (hex is null)
        {
            return (null, "give the machine's fingerprint (at least 12 hex digits)");
        }

        IReadOnlyList<MachineRecord> found = _p.Store.FindByPrefix(hex);

        return found.Count switch
        {
            0 => (null, "no machine has that fingerprint"),
            1 => (found[0], null),
            _ => (null, "more than one machine starts with that; give more of the fingerprint"),
        };
    }

    private AdminPlan? MachinePlan(string verb, IReadOnlyDictionary<string, string> args, out string? refusal, out int status)
    {
        refusal = null;
        status = 409;
        string kind = verb == "host-change" ? "approve-host-change" : verb;
        if (kind is not ("approve" or "disable" or "enable" or "untrust" or "trust" or "rename" or "approve-host-change"))
        {
            refusal = "unknown operation";
            status = 400;

            return null;
        }

        (MachineRecord? machine, string? problem) = ResolveMachine(Arg(args, "fingerprint"));
        if (machine is null)
        {
            refusal = problem;
            status = 400;

            return null;
        }

        bool repin = kind == "approve" && machine.Status == MachineStatus.Trusted && machine.Fingerprint == _p.LocalFingerprint;
        if (!repin && AuthorityStore.TransitionProblem(kind, machine) is { } transition)
        {
            refusal = transition;

            return null;
        }

        string? name = Arg(args, "name");
        if (kind is "approve" or "rename" && !repin && Enrollment.NameError(name) is { } nameProblem)
        {
            refusal = "the friendly name is not usable: " + nameProblem;
            status = 400;

            return null;
        }

        string? confirmation = null;
        if (kind == "trust")
        {
            confirmation = KeyIdentity.ParseHex(Arg(args, "confirm") ?? "", true);
            if (confirmation is null || confirmation != machine.Fingerprint)
            {
                refusal = "trust needs the machine's full fingerprint (64 hex digits) typed as the confirmation, and it must be this machine's";
                status = 400;

                return null;
            }
        }

        string fingerprint = machine.Fingerprint;
        int revision = machine.SecurityRevision;
        string display = KeyIdentity.Display(fingerprint);
        string pinKey = CurrentKey();
        string trimmed = name?.Trim() ?? "";
        string what = kind switch
        {
            "approve" when repin => $"re-pin the authority key for this machine, which is already Trusted (nothing else changes; the friendly name is not changed). The key to pin: {pinKey}",
            "approve" => $"approve this machine (it may then ask for secrets) with the friendly name \"{ApprovalSummary.Clean(trimmed)}\"",
            "disable" => "disable this machine (it is denied until enabled; its grants end)",
            "enable" => "enable this machine (it starts clean: no earlier grants or cache)",
            "untrust" => "withdraw trust from this machine (it is denied; its grants end)",
            "trust" => "trust this machine again (it starts clean). You confirmed its full fingerprint",
            "rename" => $"rename this machine to \"{ApprovalSummary.Clean(trimmed)}\" (display only)",
            _ => $"accept the host name \"{ApprovalSummary.Clean(machine.PendingHostName ?? "")}\" for this machine, in place of \"{ApprovalSummary.Clean(machine.HostName)}\"",
        };
        string sentence = $"{what}\nFingerprint: {display}\nHost name: {ApprovalSummary.Clean(machine.HostName)}\nFriendly name: {(machine.FriendlyName is null ? "(none)" : ApprovalSummary.Clean(machine.FriendlyName))}\nStatus: {machine.Status}, security revision {revision.ToString(CultureInfo.InvariantCulture)}";
        List<(string Name, string Value)> parameters = [("machine", fingerprint), ("revision", revision.ToString(CultureInfo.InvariantCulture))];
        if (kind is "approve" or "rename")
        {
            parameters.Add(("friendly-name", repin ? "(unchanged)" : trimmed));
        }

        if (kind == "approve-host-change")
        {
            parameters.Add(("host-name", machine.PendingHostName ?? ""));
        }

        string? pending = machine.PendingHostName;

        return new AdminPlan(kind + "-machine", sentence, parameters, a =>
        {
            if (kind == "approve" && repin && KeyMoved(pinKey) is { } moved)
            {
                return moved;
            }

            string actor = a.Admin!.Actor;
            TransitionResult result = kind switch
            {
                "approve" => AdminActions.ApproveMachine(_p.Store, _p.Keys, _p.HostConfig, _p.LocalFingerprint, fingerprint, trimmed, actor, revision),
                "disable" => _p.Store.Disable(fingerprint, actor, revision),
                "enable" => _p.Store.Enable(fingerprint, actor, revision),
                "untrust" => _p.Store.Untrust(fingerprint, actor, revision),
                "trust" => _p.Store.Trust(fingerprint, confirmation!, actor, revision),
                "rename" => _p.Store.Rename(fingerprint, trimmed, actor, revision),
                _ => _p.Store.ApproveHostChange(fingerprint, actor, revision, pending),
            };

            return result.Ok ? null : result.Message;
        });
    }

    // ---- grants ----

    internal static string GrantState(GrantRecord grant, DateTimeOffset now) => grant.Status != "active" ? grant.Status : grant.IsExpired(now) ? "expired" : "active";

    internal static string GrantEnds(GrantRecord grant, DateTimeOffset now) => grant.Expires is { } at ? (grant.IsExpired(now) ? "ended " : "ends ") + CanonicalJson.Time(at) : "no end";

    /// <summary>Null when the change may be applied to the grant as it is now, else why not (checked before the page, and again by the authority).</summary>
    internal static string? GrantProblem(string verb, GrantRecord grant, DateTimeOffset now)
    {
        if (grant.Status != "active")
        {
            return $"the grant is {grant.Status}; it cannot be changed (a person makes a new one with: with-secrets approve ...)";
        }

        return verb switch
        {
            "extend" when grant.IsExpired(now) => "the grant has ended; renew it instead",
            "extend" when grant.Expires is null => "the grant has no end already",
            "renew" when !grant.IsExpired(now) => "the grant has not ended; extend it instead",
            _ => null,
        };
    }

    private AdminPlan? GrantPlan(string verb, IReadOnlyDictionary<string, string> args, out string? refusal, out int status)
    {
        refusal = null;
        status = 409;
        if (verb is not ("extend" or "renew" or "revoke"))
        {
            refusal = "unknown operation";
            status = 400;

            return null;
        }

        string? typed = Arg(args, "id");
        GrantRecord? grant = typed is { Length: >= 4 } ? _p.Store.FindGrant(typed) : null;
        if (grant is null && typed is { Length: >= 4 })
        {
            IReadOnlyList<GrantRecord> found = _p.Store.FindGrantsByPrefix(typed);
            grant = found.Count == 1 ? found[0] : null;
            if (found.Count > 1)
            {
                refusal = "more than one grant starts with that; give more of the id";
                status = 400;

                return null;
            }
        }

        if (grant is null)
        {
            refusal = "no grant has that id";
            status = 400;

            return null;
        }

        DateTimeOffset now = _clock.GetUtcNow();
        if (GrantProblem(verb, grant, now) is { } problem)
        {
            refusal = problem;

            return null;
        }

        bool timed = verb is "extend" or "renew";
        bool indefinite = Arg(args, "indefinite") == "true";
        int? minutes = null;
        if (timed)
        {
            if (indefinite == (Arg(args, "minutes") is { Length: > 0 }) || (!indefinite && !TryNumber(Arg(args, "minutes"), 1, ReuseSettings.MaxMinutes, out int parsedMinutes)))
            {
                refusal = $"give a time (1 to {ReuseSettings.MaxMinutes} minutes) or no end, not both";
                status = 400;

                return null;
            }

            if (!indefinite)
            {
                minutes = int.Parse(Arg(args, "minutes")!, CultureInfo.InvariantCulture);
            }
        }

        // What the page shows is exact: the new end is fixed here (counted from the present end, or from now) and is what the authority applies.
        DateTimeOffset? newEnd = verb == "revoke" || indefinite ? null : verb == "extend" ? grant.Expires!.Value.AddMinutes(minutes!.Value) : now.AddMinutes(minutes!.Value);
        MachineRecord? machine = _p.Store.Find(grant.Fingerprint);
        string change = verb switch
        {
            "extend" => indefinite ? "extend this grant so that it has no end" : $"extend this grant by {minutes} minutes from its present end",
            "renew" => indefinite ? "renew this ended grant so that it has no end" : $"renew this ended grant for {minutes} minutes from now",
            _ => "revoke this grant (it ends now and its machine is told)",
        };
        string sentence = $"{change}\nGrant: {grant.Id} (revision {grant.Revision.ToString(CultureInfo.InvariantCulture)}), {GrantState(grant, now)}, {GrantEnds(grant, now)}\nMachine: {KeyIdentity.Display(grant.Fingerprint)}, host {(machine is null ? "(unknown)" : ApprovalSummary.Clean(machine.HostName))}\nSecrets: {ApprovalSummary.Clean(grant.SecretNames)}\nProgram: {ApprovalSummary.Clean(grant.Program)}\nFolder: {ApprovalSummary.Clean(grant.WorkingDirectory)}\nIt ends: {GrantEvidence.EndText(newEnd)}\n{GrantEvidence.AdminLines(verb, grant, grant.Revision + 1, newEnd)}";
        string grantId = grant.Id;
        int grantRevision = grant.Revision;

        return new AdminPlan(verb + "-grant", sentence, [("grant", grantId), ("revision", grantRevision.ToString(CultureInfo.InvariantCulture)), ("new-end", GrantEvidence.EndText(newEnd))], a =>
        {
            GrantAdminCommand command = new("adm-" + Guid.NewGuid().ToString("N"), verb, grantId, minutes, indefinite, grantRevision, a.Admin!.Actor, newEnd, a.Evidence);
            GrantResponse response = _p.Authority.AdminGrant(command);

            // The answer is signed by the authority key; it is checked here too, as a host checks one (key, signature, this request, this change).
            if (!response.Verify(_p.Keys.CurrentRecord().PublicKey) || response.RequestId != command.RequestId || response.RequestDigest != command.Digest())
            {
                return "the authority's answer did not verify; check the grant in the list";
            }

            return !response.HasGrant && response.Outcome != GrantOps.Revoked ? GrantReason(response.ReasonCode) : null;
        });
    }

    private static string GrantReason(string code) => code switch
    {
        GrantReasons.RevisionChanged => "the grant changed while the page was open; nothing was done",
        GrantReasons.NotActive => "the grant is not active; nothing was done",
        GrantReasons.Expired => "the grant has ended; renew it instead",
        GrantReasons.NotExpired => "that change does not apply to this grant as it is now; nothing was done",
        GrantReasons.NotFound => "no such grant",
        GrantReasons.NoTime => "give a time (1 to 1440 minutes) or no end",
        _ => "the authority refused the change (" + code + ")",
    };
}

/// <summary>The passkey administration over this user's state: the same enrollment pages as <c>--enroll</c> and <c>--unenroll</c>. The confirmation code that a new passkey's page shows is typed in the terminal that runs the service.</summary>
public sealed class StatePasskeyAdmin(StateDatabase state) : IPasskeyAdmin
{
    private Enrollment Make(Action<string> announce, Func<string?>? stopReason = null)
    {
        ApprovalSettings settings = ApprovalSettings.Load(state, out _);
        Func<string?> reader = CommandWiring.CodeReader("If the page says nothing was added, press Ctrl+C.");
        // A code typed after the request ended (or the authority locked) counts as no code, so the new passkey is not stored.
        Func<string?> guarded = () => stopReason?.Invoke() is not null ? null : reader() is { } code && stopReason?.Invoke() is null ? code : null;
        (EnrollmentTarget primary, EnrollmentTarget local) = CommandWiring.Targets(state, settings, announce, guarded);

        return new Enrollment(primary, local, announce, state.Audit) { StopReason = stopReason };
    }

    /// <summary>
    /// Runs a flow that cannot be interrupted from inside (its pages wait for their own taps) so that the request is free to end when <paramref name="stopReason" /> says so. What the flow does after that
    /// changes nothing: <see cref="Enrollment.StopReason" /> is asked before the new state is made.
    /// </summary>
    private static ApprovalDecision Watch(Func<ApprovalDecision> flow, Func<string?> stopReason)
    {
        Task<ApprovalDecision> task = Task.Run(flow);
        while (!task.Wait(TimeSpan.FromMilliseconds(200)))
        {
            if (stopReason() is { } reason)
            {
                return ApprovalDecision.Deny("nothing was changed: " + reason);
            }
        }

        return task.Result;
    }

    public IReadOnlyList<EnrolledEntry> List() => Make(_ => { }).List();

    public ApprovalDecision Enroll(Action<string> announce, Func<string?> stopReason) => Watch(() => Make(announce, stopReason).Enroll(), stopReason);

    public ApprovalDecision Unenroll(string name, Action<string> announce, Func<string?> stopReason) => Watch(() => Make(announce, stopReason).Unenroll(name), stopReason);
}

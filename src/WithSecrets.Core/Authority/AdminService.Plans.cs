using System.Globalization;

namespace WithSecrets;

/// <summary>Adding and removing the passkeys that can approve and administer. The production implementation runs the enrollment pages (admin approval, the new passkey, the admin's signature over the new state).</summary>
public interface IPasskeyAdmin
{
    IReadOnlyList<EnrolledEntry> List();

    /// <summary>
    /// Adds a passkey: the pages announce their link through <paramref name="announce" />. Approved only after the admin passkey's taps on those pages. <paramref name="stopReason" /> answers null while
    /// the change may go on and a short reason once it must not (the request was cancelled or the authority was locked): the change is then not made, however far the pages got.
    /// </summary>
    ApprovalDecision Enroll(Action<string> announce, Func<string?> stopReason);

    ApprovalDecision Unenroll(string name, Action<string> announce, Func<string?> stopReason);

    /// <summary>Rotates the secret store key and the master key, with every secret encrypted again: two taps of an admin key on pages the announced link leads to. Only the tapped key stays; a new recovery code is shown once on the last page.</summary>
    ApprovalDecision RotateStoreKey(Action<string> announce, Func<string?> stopReason);
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

    /// <summary>Why the unlock was refused when the tap released nothing that opens the keys.</summary>
    internal const string NoKeyRelease = "the passkey did not release the secret store key (use an admin passkey with PRF); the authority stays locked";

    internal const string RemoteLockRefusal = "this host has no lock: unlock the authority";

    internal const string RemoteAdminRefusal = "manage access and secrets at the authority";

    /// <summary>The current signed state, or null when it cannot be read.</summary>
    private Manifest? CurrentManifest()
    {
        try
        {
            StateDatabase state = new(_p.Store.Database);
            return state.Read(connection => state.CurrentManifest(connection, null));
        }
        catch (Exception error) when (error is StateDatabaseException or WithSecretsDatabaseException)
        {
            return null;
        }
    }

    /// <summary>
    /// Unlocks. Where the authority holds keys (not on a host whose authority is remote), the keys are opened with what the tap released first and the unlock happens only if they opened, both inside the
    /// lock's gate: a refused or failed unlock holds nothing, and a lock that comes meanwhile never leaves keys held.
    /// </summary>
    private string? UnlockWithKeys(Unlock? unlock)
    {
        if (_p.Unlocked is not { } keys)
        {
            _p.Lock.Unlock(UnlockMethod.Manual);

            return null;
        }

        if (unlock is null || CurrentManifest() is not { } manifest)
        {
            return NoKeyRelease;
        }

        return _p.Lock.UnlockWith(UnlockMethod.Manual, () => keys.TryOpen(manifest, unlock)) switch
        {
            UnlockOutcome.Unlocked => null,
            UnlockOutcome.AlreadyUnlocked => "the authority is already unlocked",
            UnlockOutcome.Locking => "the authority is locking; unlock it again",
            _ => NoKeyRelease,
        };
    }

    /// <summary>Locks when the passkey whose unlock opened the keys is no longer an admin key of the current state (it was just removed).</summary>
    private void LockIfUnlockingKeyRemoved()
    {
        if (_p.Unlocked?.OpenedBy is { } opener && CurrentManifest()?.IsAdmin(opener.Id) != true)
        {
            _p.Lock.Lock("the admin passkey that unlocked the authority was removed");
        }
    }

    /// <summary>
    /// The plan of an operation, or why there is none. The provider and mount operations are planned asynchronously: their plan validates the proposed configuration or
    /// mount through the provider's adapter before any page exists.
    /// </summary>
    private async Task<(AdminPlan? Plan, string? Refusal, int Status)> PlanAsync(object owner, string op, IReadOnlyDictionary<string, string> args, CancellationToken cancel)
    {
        if (!IsRemote && op == "provider-refresh-values" && !_p.Lock.IsLocked)
        {
            if (owner is not AdminSession session || InteractiveRefreshes is not { } refreshes
                || !Guid.TryParseExact(Arg(args, "id"), "D", out Guid id)
                || !refreshes.TryDescribe(id, session, out string sentence, out (string, string)[] parameters))
                return (null, "The terminal has not returned an active staged refresh for this session.", 409);

            string digest = parameters[2].Item2;
            return (new AdminPlan(op, sentence, parameters, authorization => ProviderChange(() =>
            {
                string? refusal = null;
                return _p.Lock.WhileUnlocked(() =>
                {
                    refusal = refreshes.Commit(id, session, digest, authorization.Admin!.Key);
                    return true;
                }) ? refusal : "The authority is locked.";
            })), null, 200);
        }

        if (!IsRemote && IsProviderOperation(op) && !_p.Lock.IsLocked)
        {
            return await ProviderPlanAsync(op, args, cancel);
        }

        AdminPlan? plan = Plan(op, args, out string? refusal, out int status);

        return (plan, refusal, status);
    }

    private AdminPlan? Plan(string op, IReadOnlyDictionary<string, string> args, out string? refusal, out int status)
    {
        refusal = null;
        status = 409;
        if (IsRemote)
        {
            refusal = NeedsNoSession(op) ? RemoteLockRefusal : RemoteAdminRefusal;

            return null;
        }

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
                    "unlock the authority so that it serves secret requests again: the secret store key and the review key are opened in its memory until it locks. It creates no grant and widens none; every sensitive change still needs its own passkey tap",
                    [("authority-key", key)],
                    authorization =>
                    {
                        if (KeyMoved(key) is { } moved)
                        {
                            return moved;
                        }

                        if (UnlockWithKeys(authorization.Unlock) is { } refused)
                        {
                            return refused;
                        }

                        _p.OnUnlocked();

                        return null;
                    }, WantsPrf: _p.Unlocked is not null);

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

                        _p.Keys.Rotate(a.Admin!.Actor, a.Admin.Key);

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

                        AdminActions.RecoverAuthority(_p.Keys, _p.HostConfig, _p.LocalFingerprint, a.Admin!.Actor, a.Admin.Key);

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
                    _ => null, (announce, stop) =>
                    {
                        ApprovalDecision decision = enrolling.Enroll(announce, stop);

                        return (decision.Approved, decision.Detail, "admin passkey");
                    });

            case "store-key-rotate":
                if (_p.Passkeys is not { } rotating)
                {
                    refusal = "key rotation is not available in this service";

                    return null;
                }

                return new AdminPlan("rotate-store-key", "rotate the secret store key and the master key: every secret is encrypted again and only the passkey you tap stays (the others must be added again). The next pages ask an admin passkey twice and show a new code for recovery once; the old one stops working", [],
                    _ => null, (announce, stop) =>
                    {
                        ApprovalDecision decision = rotating.RotateStoreKey(announce, stop);
                        if (decision.Approved)
                        {
                            _p.Lock.Lock("the secret store key was rotated");
                        }

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
                    _ => null, (announce, stop) =>
                    {
                        ApprovalDecision decision = removing.Unenroll(removeName, announce, stop);
                        if (decision.Approved)
                        {
                            LockIfUnlockingKeyRemoved();
                        }

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
                    $"create a one-time pairing invitation for a new machine. It can register ONE machine and is valid for {lifetime} minutes, or until this service restarts. The invitation (an address, an identifier and a random pairing code) is shown once on this page after your tap and can never be shown again. "
                    + "A machine that pairs with it only becomes Pending: you still check its fingerprint and host name here and approve it with another passkey tap.\nAuthority address: " + authorityUrl,
                    [("authority", authorityUrl), ("valid-minutes", lifetime.ToString(CultureInfo.InvariantCulture))],
                    a =>
                    {
                        (CreatedInvitation? created, string? problem) = creating.Create(a.Admin!.Actor, a.Admin.Key);
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
                    a => revoking.Revoke(typedId, a.Admin!.Actor, a.Admin.Key) ? null : "the invitation is no longer pending");
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
            VerifiedCredential key = a.Admin.Key;
            TransitionResult result = kind switch
            {
                "approve" => AdminActions.ApproveMachine(_p.Store, _p.Keys, _p.HostConfig, _p.LocalFingerprint, fingerprint, trimmed, actor, revision, key),
                "disable" => _p.Store.Disable(fingerprint, actor, revision, key),
                "enable" => _p.Store.Enable(fingerprint, actor, revision, key),
                "untrust" => _p.Store.Untrust(fingerprint, actor, revision, key),
                "trust" => _p.Store.Trust(fingerprint, confirmation!, actor, revision, key),
                "rename" => _p.Store.Rename(fingerprint, trimmed, actor, revision, key),
                _ => _p.Store.ApproveHostChange(fingerprint, actor, revision, pending, key),
            };

            return result.Ok ? null : result.Message;
        });
    }

    // ---- grants ----

    internal static string GrantState(GrantRecord grant, DateTimeOffset now) => grant.Status != "active" ? grant.Status : grant.IsExpired(now) ? "expired" : "active";

    internal static string GrantEnds(GrantRecord grant, DateTimeOffset now) => grant.Status == "consumed" && grant.Consumed is { } used ? "used " + CanonicalJson.Time(used)
        : grant.Expires is { } at ? (grant.IsExpired(now) ? "ended " : "ends ") + CanonicalJson.Time(at) : "no end";

    /// <summary>
    /// Null when the change may be applied to the grant as it is now, else why not (checked before the page, and again by the authority). Replace applies only to a consumed once-only grant
    /// that a person's assertion backs (<paramref name="verifier" /> checks it; with none, nothing is replaced), of a machine still Trusted at the grant's security revision, while no active
    /// grant covers its scope (<paramref name="store" /> is read for both; with none, nothing is replaced): the authority's own refusals, so the app does not offer a replace that must fail.
    /// </summary>
    internal static string? GrantProblem(string verb, GrantRecord grant, DateTimeOffset now, AuthorityStore? store = null)
    {
        if (verb == "replace")
        {
            if (grant.Status != "consumed" || grant.Usage != GrantUsage.Once)
            {
                return grant.Status == "active" ? "only a once-only grant that was used can be replaced; extend or renew this one instead" : $"the grant is {grant.Status}; only a once-only grant that was used can be replaced";
            }

            if (store?.Sealer is not { } sealer || sealer.Problem(grant) is not null)
            {
                return "no person's approval backs this grant, so it cannot be replaced";
            }

            if (store.Find(grant.Fingerprint) is not { Status: MachineStatus.Trusted } machine || machine.SecurityRevision != grant.SecurityRevision)
            {
                return "the machine's authorization changed since this grant was approved, so it cannot be replaced";
            }

            return store.ActiveGrantForScope(grant.Fingerprint, grant.ScopeKey) is { } active ? $"an active grant ({active.Id}) already covers this command; extend or renew that one instead" : null;
        }

        if (grant.Status == "consumed" && verb is "extend" or "renew")
        {
            return "this grant was used once; make a new grant from it instead";
        }

        if (grant.Status != "active")
        {
            return $"the grant is {grant.Status}; it cannot be changed (a person makes a new one with: with-secrets approve ...)";
        }

        if (verb is "extend" or "renew" && (store?.Sealer is not { } activeSealer || activeSealer.Problem(grant) is not null))
        {
            return "no valid approval backs this grant";
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
        if (verb is not ("extend" or "renew" or "revoke" or "replace"))
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
        if (GrantProblem(verb, grant, now, _p.Store) is { } problem)
        {
            refusal = problem;

            return null;
        }

        bool timed = verb is "extend" or "renew" or "replace";
        bool indefinite = Arg(args, "indefinite") == "true";
        int? minutes = null;
        if (timed)
        {
            if (indefinite == (Arg(args, "minutes") is { Length: > 0 }) || (!indefinite && !TryNumber(Arg(args, "minutes"), 1, ReuseSettings.MaxAdminMinutes, out int parsedMinutes)))
            {
                refusal = $"give a time (1 to {ReuseSettings.MaxAdminMinutes} minutes) or no end, not both";
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
        bool replace = verb == "replace";
        // A replacement's id is fixed here, so the page (which the passkey signs) names exactly the grant that will exist, and the authority makes no other.
        string? newGrantId = replace ? GrantOps.NewGrantId() : null;
        string change = verb switch
        {
            "extend" => indefinite ? "extend this grant so that it has no end" : $"extend this grant by {minutes} minutes from its present end",
            "renew" => indefinite ? "renew this ended grant so that it has no end" : $"renew this ended grant for {minutes} minutes from now",
            "replace" => (indefinite ? "make a new grant with no end" : $"make a new grant for {minutes} minutes from now") + $" ({newGrantId}) in place of this once-only grant that was used: the same machine, program, folder and secrets; it covers every run of that command, with no tap, until it ends",
            _ => "revoke this grant (it ends now and its machine is told)",
        };
        string lines = replace ? GrantEvidence.ReplaceLines(grant, newGrantId!, newEnd) : GrantEvidence.AdminLines(verb, grant, grant.Revision + 1, newEnd);
        string sentence = $"{change}\nGrant: {grant.Id} (revision {grant.Revision.ToString(CultureInfo.InvariantCulture)}), {GrantState(grant, now)}, {GrantEnds(grant, now)}\nMachine: {KeyIdentity.Display(grant.Fingerprint)}, host {(machine is null ? "(unknown)" : ApprovalSummary.Clean(machine.HostName))}\nSecrets: {ApprovalSummary.Clean(grant.SecretNames)}\nProgram: {ApprovalSummary.Clean(grant.Program)}\nFolder: {ApprovalSummary.Clean(grant.WorkingDirectory)}\nIt ends: {GrantEvidence.EndText(newEnd)}\n{lines}";
        string grantId = grant.Id;
        int grantRevision = grant.Revision;
        IReadOnlyList<(string Name, string Value)> parameters = replace
            ? [("grant", grantId), ("new-grant", newGrantId!), ("new-end", GrantEvidence.EndText(newEnd))]
            : [("grant", grantId), ("revision", grantRevision.ToString(CultureInfo.InvariantCulture)), ("new-end", GrantEvidence.EndText(newEnd))];

        return new AdminPlan("grant-" + verb, sentence, parameters, a =>
        {
            GrantAdminCommand command = new("adm-" + Guid.NewGuid().ToString("N"), verb, grantId, minutes, indefinite, grantRevision, a.Admin!.Actor, newEnd, a.Evidence, newGrantId);
            GrantResponse response = _p.Authority.AdminGrant(command);

            // The answer is signed by the authority key; it is checked here too, as a host checks one (key, signature, this request, this change).
            if (!response.Verify(_p.Keys.CurrentRecord().PublicKey) || response.RequestId != command.RequestId || response.RequestDigest != command.Digest())
            {
                return "the authority's answer did not verify; check the grant in the list";
            }

            return !response.HasGrant && response.Outcome is not (GrantOps.Revoked or GrantOps.Replaced) ? GrantReason(response.ReasonCode) : null;
        });
    }

    private static string GrantReason(string code) => code switch
    {
        GrantReasons.Exists => "an active grant already covers this command; extend or renew that one instead. Nothing was done",
        ReasonCodes.AuthorizationChanged => "the machine's authorization changed since this grant was approved; nothing was done",
        GrantReasons.RevisionChanged => "the grant changed while the page was open; nothing was done",
        GrantReasons.NotActive => "the grant is not active; nothing was done",
        GrantReasons.Expired => "the grant has ended; renew it instead",
        GrantReasons.NotExpired => "that change does not apply to this grant as it is now; nothing was done",
        GrantReasons.NotFound => "no such grant",
        GrantReasons.NoTime => "give a time (1 to 1440 minutes) or no end",
        _ => "the authority refused the change (" + code + ")",
    };
}

/// <summary>The passkey administration over this user's state: the enrollment pages. The confirmation code that a new passkey's page shows is typed in the terminal that runs the service.</summary>
public sealed class StatePasskeyAdmin(StateDatabase state) : IPasskeyAdmin
{
    internal Func<Microsoft.Data.Sqlite.SqliteConnection, Microsoft.Data.Sqlite.SqliteTransaction, string, string, string?>? RekeyReview { get; init; }

    internal Action? AfterStoreChange { get; init; }

    private Enrollment Make(Action<string> announce, Func<string?>? stopReason = null)
    {
        ApprovalSettings settings = ApprovalSettings.Load(state, out _);
        Func<string?> reader = CommandWiring.CodeReader("Press Ctrl+C to cancel.");
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

    // The worker can finish after Watch returns. Reconcile the held keys from the worker so a late commit is covered too.
    private ApprovalDecision WatchStoreChange(Func<ApprovalDecision> flow, Func<string?> stopReason) => Watch(() =>
    {
        try
        {
            return flow();
        }
        finally
        {
            AfterStoreChange?.Invoke();
        }
    }, stopReason);

    public ApprovalDecision Unenroll(string name, Action<string> announce, Func<string?> stopReason) =>
        WatchStoreChange(() => Make(announce, stopReason).Unenroll(name), stopReason);

    public ApprovalDecision RotateStoreKey(Action<string> announce, Func<string?> stopReason) => WatchStoreChange(() =>
    {
        ApprovalSettings settings = ApprovalSettings.Load(state, out _);
        (EnrollmentTarget primary, EnrollmentTarget local) = CommandWiring.Targets(state, settings, announce, null);
        ConfigChange change = new KeyRotation(state, new SecretStore(state), primary, local, announce) { StopReason = stopReason, RekeyReview = RekeyReview }.Run();

        return change.Done ? ApprovalDecision.Allow(change.Detail) : ApprovalDecision.Deny(change.Detail);
    }, stopReason);
}

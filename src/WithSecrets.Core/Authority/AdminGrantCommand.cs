using System.Globalization;

namespace WithSecrets;

/// <summary>What an administrator can do to a grant: <c>with-secrets admin grant ACTION</c>.</summary>
public enum GrantAdminAction
{
    List,
    Extend,
    Renew,
    Revoke,
}

/// <summary>
/// <c>with-secrets admin grant list|extend|renew|revoke ID</c>: for a person in a terminal. <c>list</c> prints the grants. The other three are
/// shown on the one-use page (the grant, its machine, what it covers and what will change) and are applied by the authority only after an admin
/// passkey signed that page, as the machine commands are. A grant that changed meanwhile (its revision) is refused. None of them changes a machine's
/// security revision or lengthens an offline lease.
/// </summary>
public static class AdminGrantCommand
{
    private const string Heading = "Check this change to a grant that lets one command use secrets without asking each time.";

    public static (int Code, string Detail) Run(CliCommand.GrantAdmin command, AdminContext context)
    {
        AuthorityStore store = context.Store;
        try
        {
            TimeProvider clock = context.Clock ?? TimeProvider.System;
            if (command.Action == GrantAdminAction.List)
            {
                return List(store, context.Stdout, clock.GetUtcNow());
            }

            string name = "admin grant " + Verb(command.Action);
            (GrantRecord? grant, string? problem) = Resolve(store, command.Id);
            if (grant is null)
            {
                return Deny(context, name, problem!);
            }

            if (Problem(command, grant, clock.GetUtcNow()) is { } refusal)
            {
                return Deny(context, name, refusal);
            }

            EnrollmentTarget? target = EnrollmentTarget.FirstThatCanProve(context.Primary.Admin(), context.Local.Admin());
            if (target is null)
            {
                return Deny(context, name, Enrollment.NoTargetMessage(context.Primary.Admin().Method.Id, context.Primary.Admin().Host, context.Local.Admin().Host));
            }

            ApprovalDecision asked = target.Approver.Ask(new ApprovalPrompt(Heading, PageText(command, grant, store, clock.GetUtcNow())));
            if (!asked.Approved)
            {
                return Deny(context, name, asked.Detail);
            }

            string actor = "admin passkey " + (AuditLog.KeyName(asked.Detail) is { Length: > 0 } key ? key : "(unnamed)");
            GrantAdminCommand change = new("adm-" + Guid.NewGuid().ToString("N"), Operation(command.Action), grant.Id, command.Minutes, command.Indefinite, grant.Revision, actor);
            GrantResponse response = new LocalAuthority(store, context.Keys, clock).AdminGrant(change);
            if (!response.HasGrant && response.Outcome != GrantOps.Revoked)
            {
                return Deny(context, name, Reason(response.ReasonCode));
            }

            string result = response.Outcome == GrantOps.Revoked ? "revoked" : response.Indefinite ? "now has no end" : $"now ends {CanonicalJson.Time(response.GrantExpires!.Value)}";

            return (0, $"grant {grant.Id}: {Verb(command.Action)} done; it {result}.");
        }
        catch (AuthorityDatabaseException failure)
        {
            return (RunCommand.StoreError, failure.Message);
        }
    }

    private static (int Code, string Detail) Deny(AdminContext context, string command, string reason)
    {
        context.Audit.TryWriteDenied(command, [], reason);

        return (RunCommand.Denied, reason);
    }

    public static (int Code, string Detail) List(AuthorityStore store, TextWriter output, DateTimeOffset now)
    {
        IReadOnlyList<GrantRecord> grants = store.Grants();
        foreach (GrantRecord grant in grants)
        {
            MachineRecord? machine = store.Find(grant.Fingerprint);
            output.WriteLine(string.Join('\t', grant.Id, State(grant, now), "rev " + grant.Revision.ToString(CultureInfo.InvariantCulture), Ends(grant, now), KeyIdentity.Display(grant.Fingerprint)[..19], machine?.FriendlyName is { } friendly ? ApprovalSummary.Clean(friendly) : "(machine)",
                grant.SecretNames, grant.Program, grant.WorkingDirectory));
        }

        if (grants.Count == 0)
        {
            output.WriteLine("No grants. A person makes one with: with-secrets approve --secrets NAME --reason TEXT -- PROGRAM [ARGS...]");
        }

        return (0, "");
    }

    /// <summary>The grant the text names: its full id, or the first 4 or more characters of one.</summary>
    private static (GrantRecord? Grant, string? Problem) Resolve(AuthorityStore store, string? typed)
    {
        if (typed is null || typed.Length < 4)
        {
            return (null, "give the grant's id (at least 4 characters, see: with-secrets admin grant list)");
        }

        if (store.FindGrant(typed) is { } exact)
        {
            return (exact, null);
        }

        IReadOnlyList<GrantRecord> found = store.FindGrantsByPrefix(typed);

        return found.Count switch
        {
            0 => (null, "no grant has that id (see: with-secrets admin grant list)"),
            1 => (found[0], null),
            _ => (null, "more than one grant starts with that; type more of the id"),
        };
    }

    /// <summary>Null when the change may be applied to the grant as it is now, else why not (checked before the page, and again by the authority).</summary>
    private static string? Problem(CliCommand.GrantAdmin command, GrantRecord grant, DateTimeOffset now)
    {
        if (grant.Status != "active")
        {
            return $"the grant is {grant.Status}; it cannot be changed (make a new one with: with-secrets approve ...)";
        }

        return command.Action switch
        {
            GrantAdminAction.Extend when grant.IsExpired(now) => "the grant has ended; renew it instead (admin grant renew)",
            GrantAdminAction.Extend when grant.Expires is null => "the grant has no end already",
            GrantAdminAction.Renew when !grant.IsExpired(now) => "the grant has not ended; extend it instead (admin grant extend)",
            _ => null,
        };
    }

    private static string Reason(string code) => code switch
    {
        GrantReasons.RevisionChanged => "the grant changed while the page was open; nothing was done",
        GrantReasons.NotActive => "the grant is not active; nothing was done",
        GrantReasons.Expired => "the grant has ended; renew it instead",
        GrantReasons.NotExpired => "that change does not apply to this grant as it is now; nothing was done",
        GrantReasons.NotFound => "no such grant",
        GrantReasons.NoTime => "give a time (--minutes N, 1 to 1440) or --indefinite",
        _ => "the authority refused the change (" + code + ")",
    };

    private static string Operation(GrantAdminAction action) => action switch
    {
        GrantAdminAction.Extend => GrantOps.Extend,
        GrantAdminAction.Renew => GrantOps.Renew,
        _ => GrantOps.Revoke,
    };

    private static string Verb(GrantAdminAction action) => action switch
    {
        GrantAdminAction.List => "list",
        GrantAdminAction.Extend => "extend",
        GrantAdminAction.Renew => "renew",
        _ => "revoke",
    };

    private static string State(GrantRecord grant, DateTimeOffset now) => grant.Status != "active" ? grant.Status : grant.IsExpired(now) ? "expired" : "active";

    private static string Ends(GrantRecord grant, DateTimeOffset now) => grant.Expires is { } at ? (grant.IsExpired(now) ? "ended " : "ends ") + CanonicalJson.Time(at) : "no end";

    /// <summary>The text the page shows and the passkey signs: the action, the grant, its machine, what it covers, and the new end.</summary>
    internal static string PageText(CliCommand.GrantAdmin command, GrantRecord grant, AuthorityStore store, DateTimeOffset now)
    {
        MachineRecord? machine = store.Find(grant.Fingerprint);
        string change = command.Action switch
        {
            GrantAdminAction.Extend => command.Indefinite ? "extend this grant so that it has no end" : $"extend this grant by {command.Minutes} minutes from its present end",
            GrantAdminAction.Renew => command.Indefinite ? "renew this ended grant so that it has no end" : $"renew this ended grant for {command.Minutes} minutes from now",
            _ => "revoke this grant (it ends now and its machine is told)",
        };

        return $"Action: {change}\nGrant: {grant.Id} (revision {grant.Revision.ToString(CultureInfo.InvariantCulture)}), {State(grant, now)}, {Ends(grant, now)}\nMachine: {KeyIdentity.Display(grant.Fingerprint)}, host {(machine is null ? "(unknown)" : ApprovalSummary.Clean(machine.HostName))}\nSecrets: {ApprovalSummary.Clean(grant.SecretNames)}\nProgram: {ApprovalSummary.Clean(grant.Program)}\nFolder: {ApprovalSummary.Clean(grant.WorkingDirectory)}";
    }
}

using System.Globalization;

namespace WithSecrets;

// The read models of the administration API (what a session may look at). Metadata only: no secret value, proof, key or credential is part of any of them, and every text that came from
// elsewhere (a host name, a program, a folder) is passed through ApprovalSummary.Clean so that control characters never reach a client.

/// <summary>The public status: running, locked or not, the unlock mode and the versions. Nothing here is sensitive.</summary>
public sealed record StatusDto(bool Running, bool Locked, string UnlockMode, string? UnlockedHow, string ApiVersion, string Version, int ProtocolVersion);

public sealed record LoginDto(string State, string? Problem);

public sealed record SessionDto(bool Authenticated, string? Admin, DateTimeOffset? Started, DateTimeOffset? IdleExpires, DateTimeOffset? AbsoluteExpires, LoginDto? Login, IReadOnlyList<string> Recent);

public sealed record BrowserDto(string AntiForgery);

public sealed record ClaimDto(string AntiForgery, SessionDto Session);

public sealed record MachineDto(string Fingerprint, string Display, string Status, int Revision, string HostName, string? PendingHostName, string? FriendlyName, DateTimeOffset Created, DateTimeOffset Updated, bool ThisMachine, IReadOnlyList<string> Actions);

public sealed record GrantDto(string Id, string Fingerprint, string? MachineName, string State, string Status, int Revision, DateTimeOffset Created, DateTimeOffset Updated, DateTimeOffset? Expires, string Ends, string SecretNames, string Program, string WorkingDirectory,
    string ApprovedBy, DateTimeOffset? Revoked, IReadOnlyList<string> Actions);

public sealed record AuditEventDto(string EventId, long Sequence, DateTimeOffset Time, DateTimeOffset Received, string Machine, string Type, string Outcome, string Reason, string RequestId, string Folder, string Program, IReadOnlyList<string> Arguments, string GrantId, int? ExitCode, IReadOnlyDictionary<string, string> Metadata);

public sealed record AuditChangeDto(long Id, DateTimeOffset Time, string Event, string? Machine, string Actor, string Detail);

public sealed record AuditGapDto(long Id, string Machine, string Kind, long From, long To, DateTimeOffset Detected, DateTimeOffset? Resolved, string Epoch);

public sealed record SettingsDto(string UnlockMode, string UnlockModeDescription, int AuditRetentionDays, int SessionIdleMinutes, int SessionAbsoluteMinutes, string AuthorityKey, int MaxAuditRetentionDays, int MaxSessionIdleMinutes, int MaxSessionAbsoluteMinutes);

public sealed record PasskeyDto(string Name, string Detail, DateTimeOffset Created, bool Admin);

public sealed record PasskeysDto(bool Available, string? Problem, IReadOnlyList<PasskeyDto> Items);

/// <summary>An invitation's standing: status only (pending, consumed, expired or revoked). Never a code, a verifier or a bundle.</summary>
public sealed record InvitationDto(string Id, string Status, DateTimeOffset Created, DateTimeOffset Expires, DateTimeOffset? Ended, string? Machine, bool CanRevoke);

/// <summary>What creating an invitation answers, once: the credential bundle (it holds the code). It is not stored and cannot be read again.</summary>
public sealed record InvitationCreatedDto(string Id, DateTimeOffset Expires, string Bundle);

public sealed partial class AdminService
{
    internal static string Version { get; } = typeof(AdminService).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false) is [System.Reflection.AssemblyInformationalVersionAttribute info, ..]
        ? info.InformationalVersion.Split('+')[0]
        : "0.0.0";

    private static string C(string? text) => ApprovalSummary.Clean(text ?? "");

    internal StatusDto StatusView()
    {
        AuthorityStatus status = Status();

        return new StatusDto(true, status.Locked, UnlockPolicies.Name(status.Policy), status.How?.ToString().ToLowerInvariant(), "v1", Version, LaunchProtocol.Version);
    }

    /// <summary>When a session ends: the idle end (renewed by each use) and the absolute end.</summary>
    internal (DateTimeOffset Idle, DateTimeOffset Absolute) SessionEnds(AdminSession session)
    {
        (int idle, int absolute) = _p.Store.SessionTimeouts();

        return (session.LastSeen.AddMinutes(idle), session.Started.AddMinutes(absolute));
    }

    private List<string> MachineActions(MachineRecord machine)
    {
        List<string> actions = [];
        bool repin = machine.Status == MachineStatus.Trusted && machine.Fingerprint == _p.LocalFingerprint;
        if (machine.Status == MachineStatus.Pending || repin)
        {
            actions.Add("approve");
        }

        foreach (string verb in new[] { "disable", "enable", "untrust" })
        {
            if (AuthorityStore.TransitionProblem(verb, machine) is null)
            {
                actions.Add(verb);
            }
        }

        if (machine.Status == MachineStatus.Untrusted)
        {
            actions.Add("trust");
        }

        if (machine.PendingHostName is not null)
        {
            actions.Add("approve-host-change");
        }

        actions.Add("rename");

        return actions;
    }

    internal MachineDto MachineView(MachineRecord machine) => new(machine.Fingerprint, KeyIdentity.Display(machine.Fingerprint), machine.Status.ToString().ToLowerInvariant(), machine.SecurityRevision, C(machine.HostName),
        machine.PendingHostName is null ? null : C(machine.PendingHostName), machine.FriendlyName is null ? null : C(machine.FriendlyName), machine.Created, machine.Updated, machine.Fingerprint == _p.LocalFingerprint, MachineActions(machine));

    internal IReadOnlyList<MachineDto> MachinesView() => [.. _p.Store.Machines().Select(MachineView)];

    /// <summary>One machine by its fingerprint or an unambiguous start of it (12 hex digits or more); null with a reason when none or several.</summary>
    internal (MachineDto? Machine, string? Problem, int Status) FindMachineView(string typed)
    {
        (MachineRecord? machine, string? problem) = ResolveMachine(typed);

        return machine is null ? (null, problem, problem is not null && problem.StartsWith("no machine", StringComparison.Ordinal) ? 404 : 400) : (MachineView(machine), null, 200);
    }

    internal GrantDto GrantView(GrantRecord grant, DateTimeOffset now)
    {
        MachineRecord? machine = _p.Store.Find(grant.Fingerprint);
        List<string> actions = [];
        foreach (string verb in new[] { "extend", "renew", "revoke" })
        {
            if (GrantProblem(verb, grant, now) is null)
            {
                actions.Add(verb);
            }
        }

        return new GrantDto(grant.Id, grant.Fingerprint, machine?.FriendlyName is { } name ? C(name) : null, GrantState(grant, now), grant.Status, grant.Revision, grant.Created, grant.Updated, grant.Expires, GrantEnds(grant, now), C(grant.SecretNames), C(grant.Program),
            C(grant.WorkingDirectory), C(grant.ApprovedBy), grant.Revoked, actions);
    }

    internal IReadOnlyList<GrantDto> GrantsView()
    {
        DateTimeOffset now = _clock.GetUtcNow();

        return [.. _p.Store.Grants().Select(grant => GrantView(grant, now))];
    }

    internal (GrantDto? Grant, string? Problem, int Status) FindGrantView(string typed)
    {
        GrantRecord? grant = typed.Length >= 4 ? _p.Store.FindGrant(typed) : null;
        if (grant is null && typed.Length >= 4)
        {
            IReadOnlyList<GrantRecord> found = _p.Store.FindGrantsByPrefix(typed);
            if (found.Count > 1)
            {
                return (null, "more than one grant starts with that; give more of the id", 400);
            }

            grant = found.Count == 1 ? found[0] : null;
        }

        return grant is null ? (null, "no grant has that id", 404) : (GrantView(grant, _clock.GetUtcNow()), null, 200);
    }

    /// <summary>The audit filters of a request, or why not. All optional. <c>last</c> is 1 to 1000 (default 100). A time is ISO 8601 (UTC when no zone is given).</summary>
    internal static (AuditQuery? Query, string? Error) ParseAuditQuery(Func<string, string?> get)
    {
        static string? Text(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
        DateTimeOffset? since = null;
        DateTimeOffset? until = null;
        foreach (string name in new[] { "since", "until" })
        {
            if (Text(get(name)) is { } value)
            {
                if (!DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTimeOffset parsed))
                {
                    return (null, name + " takes a time in ISO 8601 form, for example 2026-11-01 or 2026-11-01T09:30:00Z");
                }

                if (name == "since")
                {
                    since = parsed;
                }
                else
                {
                    until = parsed;
                }
            }
        }

        int last = 100;
        if (Text(get("last")) is { } lastText && (!int.TryParse(lastText, NumberStyles.None, CultureInfo.InvariantCulture, out last) || last < 1 || last > AuditQuery.MaxLimit))
        {
            return (null, "last takes a number from 1 to " + AuditQuery.MaxLimit);
        }

        string? type = Text(get("type"));
        if (type is not null && !AuditEventTypes.All.Contains(type))
        {
            return (null, "type is authorization, launch, execution or admin");
        }

        return (new AuditQuery(Text(get("machine")), since, until, type, Text(get("outcome")), Text(get("grant")), Text(get("folder")), Text(get("text")), last), null);
    }

    internal IReadOnlyList<AuditEventDto> AuditEventsView(AuditQuery query) => [.. _p.Store.AuditHistory(query).Select(record => new AuditEventDto(record.Event.EventId, record.Event.Sequence, record.Event.Time, record.Received, record.Event.MachineFingerprint, record.Event.Type,
        C(record.Event.Outcome), C(record.Event.Reason), C(record.Event.RequestId), C(record.Event.Folder), C(record.Event.Program), [.. record.Event.Arguments.Select(C)], C(record.Event.GrantId), record.Event.ExitCode, record.Event.Meta.ToDictionary(item => C(item.Key), item => C(item.Value), StringComparer.Ordinal)))];

    internal IReadOnlyList<AuditChangeDto> AuditChangesView(AuditQuery query)
    {
        string? needle = query.Text;

        return [.. _p.Store.Audit(1000)
            .Where(entry => (needle is null || (entry.Event + " " + entry.Actor + " " + entry.Detail).Contains(needle, StringComparison.OrdinalIgnoreCase)) && (query.From is null || entry.Time >= query.From) && (query.To is null || entry.Time <= query.To)
                && (query.MachinePrefix is null || (entry.Fingerprint ?? "").StartsWith(query.MachinePrefix, StringComparison.OrdinalIgnoreCase)))
            .Take(query.Limit)
            .Select(entry => new AuditChangeDto(entry.Id, entry.Time, C(entry.Event), entry.Fingerprint, C(entry.Actor), C(entry.Detail)))];
    }

    internal IReadOnlyList<AuditGapDto> AuditGapsView(string? machinePrefix) => [.. _p.Store.AuditGaps(machinePrefix, openOnly: true).Select(gap => new AuditGapDto(gap.Id, gap.Fingerprint, C(gap.Kind), gap.From, gap.To, gap.Detected, gap.Resolved, C(gap.Epoch)))];

    internal SettingsDto SettingsView()
    {
        AuthorityStatus status = Status();
        (int idle, int absolute) = _p.Store.SessionTimeouts();

        return new SettingsDto(UnlockPolicies.Name(status.Policy), UnlockPolicies.Describe(status.Policy), _p.Store.AuditRetentionDays(), idle, absolute, CurrentKey(), AuthorityStore.MaxAuditRetentionDays, AuthorityStore.MaxSessionIdleMinutes, AuthorityStore.MaxSessionAbsoluteMinutes);
    }

    internal PasskeysDto PasskeysView()
    {
        if (_p.Passkeys is not { } passkeys)
        {
            return new PasskeysDto(false, "passkey administration is not available in this service", []);
        }

        try
        {
            return new PasskeysDto(true, null, [.. passkeys.List().Select(entry => new PasskeyDto(C(entry.Name), C(entry.Detail), entry.Created, entry.Admin))]);
        }
        catch (ProofUnavailableException failure)
        {
            return new PasskeysDto(false, C(failure.Message), []);
        }
    }
}

public sealed partial class AdminService
{
    /// <summary>The invitations by status only (expired ones are ended first, audited).</summary>
    internal IReadOnlyList<InvitationDto> InvitationsView()
    {
        DateTimeOffset now = _clock.GetUtcNow();

        return [.. _p.Store.Invitations().Select(item => new InvitationDto(item.Id, item.StatusAt(now), item.Created, item.Expires, item.Ended, item.MachineFingerprint is null ? null : KeyIdentity.Display(item.MachineFingerprint), item.StatusAt(now) == "pending"))];
    }
}

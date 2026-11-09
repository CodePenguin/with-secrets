using System.Text.Json.Nodes;

namespace WithSecrets;

/// <summary>What a route needs from its caller before its handler runs.</summary>
internal enum ApiAccess
{
    /// <summary>Anyone on this machine's loopback: no session, nothing sensitive in the answer.</summary>
    Public,

    /// <summary>
    /// Makes this browser's pre-session cookie and gives its anti-forgery value, once: a same-origin request (an Origin) and nothing else. It changes nothing in the authority and a program may make as many
    /// identities as it likes; each is its own caller with its own limits.
    /// </summary>
    Open,

    /// <summary>A read: needs a session (its cookie and its own secret).</summary>
    Read,

    /// <summary>Only for the caller a thing was made for (its session, or for the unlock its browser, each with its secret): an authorization's state, or the session's own state. Needs no session itself, because the unlock is asked for without one, and never changes anything.</summary>
    Owner,

    /// <summary>Start a sign-in: a same-origin request with the anti-forgery value of the browser (its pre-session cookie); no session yet.</summary>
    Login,

    /// <summary>Claim the session of a sign-in whose tap was verified: a same-origin request with the anti-forgery value of the browser that began it and its login cookie. The answer carries the session's own secret, once.</summary>
    Claim,

    /// <summary>Sign out: a session (its cookie and its own secret).</summary>
    Logout,

    /// <summary>Ask for an authorization: a session (but for the unlock), the anti-forgery value, a body. Authorizes nothing by itself.</summary>
    Authorize,

    /// <summary>A change: a session (but for the unlock), the anti-forgery value, and a verified, unspent, fresh authorization for exactly this operation and these parameters.</summary>
    Mutation,
}

internal sealed record ApiQuery(string Name, JsonObject Schema, string Description);

/// <summary>One route of the API: what the dispatcher matches and enforces and what the OpenAPI document says, from this one record.</summary>
internal sealed record ApiRoute(string Method, string Template, string OperationId, string Summary, string Tag, ApiAccess Access, int Success, string? Response, JsonObject? Request, IReadOnlyList<ApiQuery> Query, string? Operation, Func<ApiCall, Task<ApiResult>> Handle,
    string[]? AlsoSuccess = null);

internal sealed record ApiResult(int Status, object? Body = null);

internal sealed record ApiProblem(int Status, string Code, string Detail, string[]? SupportedVersions = null);

internal sealed partial class AdminApi
{
    public const string Version = "v1";
    public const string Prefix = "/api/v1";
    public const int MaxBody = 4096;

    /// <summary>Every administrative operation, with the parameter names it takes. Both the authorization request and the mutation that spends it are checked against this one list.</summary>
    internal static readonly (string Operation, string[] Parameters)[] Operations =
    [
        (AdminService.OpUnlock, []),
        (AdminService.OpLock, []),
        (AdminService.OpPolicyManual, []),
        (AdminService.OpPolicyUnattended, []),
        ("set-audit-retention", ["days"]),
        ("set-session-timeouts", ["idle", "absolute"]),
        ("authority-key-rotate", []),
        ("authority-key-recover", []),
        ("machine-approve", ["fingerprint", "name"]),
        ("machine-disable", ["fingerprint"]),
        ("machine-enable", ["fingerprint"]),
        ("machine-untrust", ["fingerprint"]),
        ("machine-trust", ["fingerprint", "confirm"]),
        ("machine-rename", ["fingerprint", "name"]),
        ("machine-host-change", ["fingerprint"]),
        ("grant-extend", ["id", "minutes", "indefinite"]),
        ("grant-renew", ["id", "minutes", "indefinite"]),
        ("grant-revoke", ["id"]),
        ("passkey-enroll", []),
        ("passkey-unenroll", ["name"]),
    ];

    private static readonly string[] AuditFilters = ["machine", "since", "until", "type", "outcome", "grant", "folder", "text", "last"];

    private static JsonObject ParameterSchema(string name) => name switch
    {
        "fingerprint" => S.Str(max: 80, min: 12, description: "The machine's fingerprint, or an unambiguous start of it (12 hex digits or more)."),
        "id" => S.Str(max: 80, min: 4, description: "The grant's id, or an unambiguous start of it."),
        "name" => S.Str(max: 40, min: 1, description: "A friendly name (a passkey's or a machine's)."),
        "confirm" => S.Str(max: 80, description: "The machine's full fingerprint, typed again to confirm."),
        "days" => S.Int(0, AuthorityStore.MaxAuditRetentionDays, description: "How many days audit events are kept; 0 keeps everything."),
        "idle" => S.Int(1, AuthorityStore.MaxSessionIdleMinutes, description: "Minutes without use that end a session."),
        "absolute" => S.Int(1, AuthorityStore.MaxSessionAbsoluteMinutes, description: "Minutes after which a session ends however busy."),
        "minutes" => S.Int(1, ReuseSettings.MaxMinutes, description: "Minutes to add to (extend) or to grant from now (renew)."),
        "indefinite" => S.Bool("True for a grant with no end (instead of minutes)."),
        "policy" => S.Str(values: [UnlockPolicies.Manual, UnlockPolicies.Unattended], description: "The unlock mode."),
        _ => throw new InvalidOperationException("unknown parameter " + name),
    };

    private static readonly string[] RequiredParameters = ["days", "idle", "absolute", "confirm", "policy"];

    /// <summary>A mutation route: the body names the parameters of the operation (those not in the path) and carries the authorization id.</summary>
    private ApiRoute Mutation(string method, string template, string operation, string id, string summary, string tag, params string[] body)
    {
        string[] pathParams = [.. template.Split('/').Where(part => part.StartsWith('{')).Select(part => part.Trim('{', '}'))];
        string[] required = [.. body.Where(name => RequiredParameters.Contains(name) || (operation == "machine-rename" && name == "name"))];
        List<(string, JsonObject)> members = [("authorization", S.Str(max: 64, min: 8, description: "The id of the authorization made for exactly this operation and these parameters (POST /api/v1/authorizations), after its passkey tap."))];
        members.AddRange(body.Select(name => (name, ParameterSchema(name))));
        JsonObject request = S.Obj(members, members.Select(item => item.Item1).Where(name => name != "authorization" && !required.Contains(name)));

        return new ApiRoute(method, Prefix + template, id, summary, tag, ApiAccess.Mutation, 200, "MutationResponse", request, [], operation == "" ? null : operation,
            call => MutateAsync(call, operation, pathParams), operation is "passkey-enroll" or "passkey-unenroll" ? ["202"] : null);
    }

    private IReadOnlyList<ApiRoute> BuildRoutes()
    {
        List<ApiRoute> routes =
        [
            new("GET", Prefix + "/openapi.json", "getOpenApi", "The OpenAPI 3.1 document of this API (public; it carries no secret).", "meta", ApiAccess.Public, 200, null, null, [], null, _ => Task.FromResult(new ApiResult(200, null))),
            new("GET", Prefix + "/status", "getStatus", "Whether the service is running, locked or unlocked, the unlock mode and the versions (public).", "status", ApiAccess.Public, 200, "Status", null, [], null, _ => Task.FromResult(new ApiResult(200, admin.StatusView()))),
            new("POST", Prefix + "/browser", "startBrowser", "Make this browser's pre-session cookie and give its anti-forgery value (once, in this answer: keep it in the page and send it as X-Admin-Token). Needed before a sign-in or an unlock. Changes nothing in the authority.", "session", ApiAccess.Open, 201, "Browser", S.Obj([]), [], null, StartBrowserAsync),
            new("GET", Prefix + "/session", "getSession", "Who is signed in (a read-only session) and how a sign-in in progress stands. Read-only: it claims nothing and sets no cookie; a session is recognized only with its cookie AND its own secret (X-Admin-Token).", "session", ApiAccess.Owner, 200, "Session", null, [], null, GetSessionAsync),
            new("POST", Prefix + "/session", "startSession", "Start a sign-in: answers the link of the one-use passkey page whose tap (user verification) starts a read-only session for this browser. Then GET /session until the login is ready, then POST /session/claim.", "session", ApiAccess.Login, 202, "LoginStarted", S.Obj([]), [], null, StartSessionAsync),
            new("POST", Prefix + "/session/claim", "claimSession", "Claim the session of the sign-in this browser began, once its tap was verified. The answer carries the session's own secret (antiForgery), once: keep it in the page and send it as X-Admin-Token with every request.", "session", ApiAccess.Claim, 201, "Claim", S.Obj([]), [], null, ClaimSessionAsync),
            new("DELETE", Prefix + "/session", "endSession", "Sign out: ends the session now.", "session", ApiAccess.Logout, 200, "Done", null, [], null, EndSessionAsync),
            new("GET", Prefix + "/machines", "listMachines", "The machines and where each stands (read-only session).", "machines", ApiAccess.Read, 200, "MachineList", null, [], null, _ => Task.FromResult(new ApiResult(200, new { items = admin.MachinesView() }))),
            new("GET", Prefix + "/machines/{fingerprint}", "getMachine", "One machine, by its fingerprint or an unambiguous start of it (read-only session).", "machines", ApiAccess.Read, 200, "Machine", null, [], null, GetMachineAsync),
            new("GET", Prefix + "/grants", "listGrants", "The grants and what can be done to each (read-only session).", "grants", ApiAccess.Read, 200, "GrantList", null, [], null, _ => Task.FromResult(new ApiResult(200, new { items = admin.GrantsView() }))),
            new("GET", Prefix + "/grants/{id}", "getGrant", "One grant, by its id or an unambiguous start of it (read-only session).", "grants", ApiAccess.Read, 200, "Grant", null, [], null, GetGrantAsync),
            new("GET", Prefix + "/audit/events", "searchAuditEvents", "Search the host events the authority holds (authorization, launch and execution outcomes). Every filter is optional.", "audit", ApiAccess.Read, 200, "AuditEventList", null, AuditQueries(), null, AuditEventsAsync),
            new("GET", Prefix + "/audit/changes", "searchAuditChanges", "Search the authority's own audit history (administrator operations, machine and grant changes). Filters: machine, since, until, text, last.", "audit", ApiAccess.Read, 200, "AuditChangeList", null, AuditQueries(), null, AuditChangesAsync),
            new("GET", Prefix + "/audit/gaps", "listAuditGaps", "The open holes in a machine's audit numbering. Filter: machine.", "audit", ApiAccess.Read, 200, "AuditGapList", null, [new ApiQuery("machine", S.Str(max: 80), "A machine's fingerprint or the start of it.")], null, AuditGapsAsync),
            new("GET", Prefix + "/settings", "getSettings", "Audit retention, the unlock mode, the session timeouts and the authority key in use (read-only session).", "settings", ApiAccess.Read, 200, "Settings", null, [], null, _ => Task.FromResult(new ApiResult(200, admin.SettingsView()))),
            new("GET", Prefix + "/passkeys", "listPasskeys", "The enrolled passkeys (names and kinds; no key material).", "passkeys", ApiAccess.Read, 200, "Passkeys", null, [], null, _ => Task.FromResult(new ApiResult(200, admin.PasskeysView()))),
            new("POST", Prefix + "/authorizations", "createAuthorization", "Ask to authorize one change: answers the link of a one-use passkey page whose signed text names the operation and every security-relevant parameter, and the text to show. The tap (user verification) makes the authorization usable once, for exactly that operation and those parameters, for " + AdminService.LifetimeText + " seconds. It changes nothing by itself.", "authorizations", ApiAccess.Authorize, 201, "Authorization", AuthorizationRequest(), [], null, CreateAuthorizationAsync),
            new("GET", Prefix + "/authorizations/{id}", "getAuthorization", "Where an authorization stands (pending, verified, refused, consumed or expired). Only for the caller it was made for (its session, or for the unlock its browser).", "authorizations", ApiAccess.Owner, 200, "Authorization", null, [], null, GetAuthorizationAsync),
            Mutation("POST", "/unlock", AdminService.OpUnlock, "unlockAuthority", "Unlock the authority (needs no session, but its own authorization).", "authority"),
            Mutation("POST", "/lock", AdminService.OpLock, "lockAuthority", "Lock the authority now: secret requests stop, held keys are discarded and every session and authorization ends.", "authority"),
            Mutation("PUT", "/settings/unlock-policy", "", "setUnlockPolicy", "Set the unlock mode (manual, or the weaker unattended mode).", "settings", "policy"),
            Mutation("PUT", "/settings/audit-retention", "set-audit-retention", "setAuditRetention", "Set how many days audit events are kept (0 keeps everything).", "settings", "days"),
            Mutation("PUT", "/settings/session-timeouts", "set-session-timeouts", "setSessionTimeouts", "Set the idle and absolute timeouts of administrator sessions.", "settings", "idle", "absolute"),
            Mutation("POST", "/authority-key/rotate", "authority-key-rotate", "rotateAuthorityKey", "Rotate the authority signing key (a transition the current key signs).", "authority"),
            Mutation("POST", "/authority-key/recover", "authority-key-recover", "recoverAuthorityKey", "Recover the authority signing key (no transition; other hosts must enroll again).", "authority"),
            Mutation("POST", "/machines/{fingerprint}/approve", "machine-approve", "approveMachine", "Approve a pending machine with a friendly name (or re-pin the authority key for this machine).", "machines", "name"),
            Mutation("POST", "/machines/{fingerprint}/disable", "machine-disable", "disableMachine", "Disable a machine (it is denied until enabled; its grants end).", "machines"),
            Mutation("POST", "/machines/{fingerprint}/enable", "machine-enable", "enableMachine", "Enable a disabled machine (it starts clean).", "machines"),
            Mutation("POST", "/machines/{fingerprint}/untrust", "machine-untrust", "untrustMachine", "Withdraw trust from a machine.", "machines"),
            Mutation("POST", "/machines/{fingerprint}/trust", "machine-trust", "trustMachine", "Trust an untrusted machine again, confirmed by typing its full fingerprint.", "machines", "confirm"),
            Mutation("POST", "/machines/{fingerprint}/rename", "machine-rename", "renameMachine", "Rename a machine (display only).", "machines", "name"),
            Mutation("POST", "/machines/{fingerprint}/approve-host-change", "machine-host-change", "approveMachineHostChange", "Accept the new host name a machine reported.", "machines"),
            Mutation("POST", "/grants/{id}/extend", "grant-extend", "extendGrant", "Extend a grant by minutes, or to no end.", "grants", "minutes", "indefinite"),
            Mutation("POST", "/grants/{id}/renew", "grant-renew", "renewGrant", "Renew an ended grant for minutes from now, or to no end.", "grants", "minutes", "indefinite"),
            Mutation("POST", "/grants/{id}/revoke", "grant-revoke", "revokeGrant", "Revoke a grant (it ends now and its machine is told).", "grants"),
            Mutation("POST", "/passkeys", "passkey-enroll", "addPasskey", "Add a passkey: after its authorization the enrollment pages (their own passkey taps) are started; the answer is the link of the first.", "passkeys"),
            Mutation("POST", "/passkeys/{name}/remove", "passkey-unenroll", "removePasskey", "Remove a passkey (any key but the last admin key).", "passkeys"),
        ];

        return routes;
    }

    private static IReadOnlyList<ApiQuery> AuditQueries() =>
    [
        new("machine", S.Str(max: 80), "A machine's fingerprint, or the start of it."),
        new("since", S.Str(max: 40), "Only events at or after this time (ISO 8601, UTC when no zone is given)."),
        new("until", S.Str(max: 40), "Only events at or before this time."),
        new("type", S.Str(values: [.. AuditEventTypes.All]), "authorization, launch or execution."),
        new("outcome", S.Str(max: 64), "The outcome, for example approved, denied, started or exited."),
        new("grant", S.Str(max: 128), "Events that used this grant."),
        new("folder", S.Str(max: 300), "The working directory contains this text."),
        new("text", S.Str(max: 300), "Any of the event's text contains this."),
        new("last", S.Str(max: 4), "The most to return, 1 to 1000 (default 100)."),
    ];

    private static JsonObject AuthorizationRequest() => S.Obj(
    [
        ("operation", S.Str(values: [.. Operations.Select(item => item.Operation)], description: "The operation to authorize.")),
        ("parameters", S.Params(8, 300)),
    ], ["parameters"], "The operation and every parameter that the passkey will sign. The mutation that follows must repeat exactly these.");
}

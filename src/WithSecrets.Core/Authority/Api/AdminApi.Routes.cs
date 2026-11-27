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

    /// <summary>A read: needs a session (its cookie and its own secret) with admin.read.</summary>
    Read,

    /// <summary>A read limited to the Approvals capability.</summary>
    ApprovalsRead,

    /// <summary>A decision limited to the Approvals capability, with same-origin and anti-forgery checks.</summary>
    ApprovalsDecide,

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
    string[]? AlsoSuccess = null, int BodyLimit = 0);

internal sealed record ApiResult(int Status, object? Body = null);

internal sealed record ApiProblem(int Status, string Code, string Detail, string[]? SupportedVersions = null);

internal sealed partial class AdminApi
{
    public const string Version = "v1";
    public const string Prefix = "/api/v1";
    public const int MaxBody = 4096;
    // A JSON string can use six bytes per UTF-16 code unit, plus the operation's other fields.
    private const int ConfigurationBodyLimit = MaxBody + 6 * ProviderAdmin.MaxConfigurationLength;

    /// <summary>Every administrative operation, with the parameter names it takes. Both the authorization request and the mutation that spends it are checked against this one list.</summary>
    internal static readonly (string Operation, string[] Parameters)[] Operations =
    [
        (AdminService.OpUnlock, []),
        (AdminService.OpLock, []),
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
        (AuthorityStore.SetDiagnosticsOperation, ["fingerprint", "level", "queue-kib", "retention-hours"]),
        ("machine-host-change", ["fingerprint"]),
        ("grant-extend", ["id", "minutes", "indefinite"]),
        ("grant-renew", ["id", "minutes", "indefinite"]),
        ("grant-replace", ["id", "minutes", "indefinite"]),
        ("grant-revoke", ["id"]),
        ("passkey-enroll", []),
        ("store-key-rotate", []),
        ("passkey-unenroll", ["name"]),
        ("pairing-create", []),
        ("pairing-revoke", ["id"]),
        ("provider-add", ["name", "type", "config", "max-stale-seconds", "confirm-warnings"]),
        ("provider-config", ["id", "revision", "config", "max-stale-seconds", "confirm-warnings"]),
        ("provider-max-stale", ["id", "revision", "max-stale-seconds"]),
        ("provider-refresh-values", ["id"]),
        ("provider-remove", ["id", "revision"]),
        ("mount-add", ["instance", "kind", "path", "base", "confirm-warnings"]),
        ("mount-remove", ["id"]),
    ];

    /// <summary>The parameters whose values may be longer than <see cref="MaxParameterLength" />, with their own limit.</summary>
    private static readonly Dictionary<string, int> LongParameters = new(StringComparer.Ordinal) { ["config"] = ProviderAdmin.MaxConfigurationLength };

    private const int MaxParameterLength = 300;

    private static readonly string[] AuditFilters = ["machine", "since", "until", "type", "outcome", "grant", "folder", "text", "last"];

    private static JsonObject ParameterSchema(string name, string? operation = null) => name switch
    {
        "fingerprint" => S.Str(max: 80, min: 12, description: "The machine's fingerprint, or an unambiguous start of it (12 hex digits or more)."),
        "id" => S.Str(max: 80, min: 4, description: "The id of what the operation changes: a grant's id (or an unambiguous start of it), a pairing invitation's, or a provider instance's or mount's (its full id)."),
        "name" => S.Str(max: 64, min: 1, description: "A name: a passkey's or a machine's friendly name (at most 40 characters), or a provider instance's (at most 64; leading and trailing spaces are dropped)."),
        "type" => S.Str(max: 64, min: 1, description: "The provider type of the instance (one the service offers)."),
        "config" => S.Str(max: ProviderAdmin.MaxConfigurationLength, min: 2, description: "The instance's configuration as a JSON object on one line. Use the provider's sealing endpoint for credentials."),
        "max-stale-seconds" => S.Str(max: 5, min: 1, description: "Whole seconds as text, 0 to 86400. Zero fetches live values without a cache. A positive value enables the encrypted authority cache and sets the maximum age for outage fallback."),
        "revision" => S.Str(max: 10, min: 1, description: "The revision of the provider instance as it was shown (whole number as text); the change is refused when it has moved."),
        "instance" => S.Str(max: 36, min: 36, description: "The id of the provider instance the mount reads from."),
        "kind" => S.Str(values: ["tree", "single"], description: "A tree mount (a folder of secret names) or a single secret name."),
        "path" => S.Str(max: 200, min: 1, description: "The mount's logical path: the folder (tree) or the secret name (single)."),
        "base" => S.Str(max: MaxParameterLength, description: "The provider path the mount reads (for a tree mount it may be empty: the provider's root)."),
        "confirm-warnings" => S.Str(values: ["yes"], description: "Go on although the provider's validation reported warnings (it is signed)."),
        "confirm" => S.Str(max: 80, description: "The machine's full fingerprint, typed again to confirm."),
        "days" => S.Int(0, AuthorityStore.MaxAuditRetentionDays, description: "How many days audit events are kept; 0 keeps everything."),
        "level" => S.Str(values: DiagnosticSettings.Levels, description: "The minimum severity forwarded by this machine."),
        "queue-kib" => S.Int(DiagnosticSettings.MinQueueKiB, DiagnosticSettings.MaxQueueKiB, description: "Maximum size of the unsent diagnostics queue in KiB."),
        "retention-hours" => S.Int(1, DiagnosticSettings.MaxRetentionHours, description: "How long unsent diagnostics can wait for delivery."),
        "idle" => S.Int(1, AuthorityStore.MaxSessionIdleMinutes, description: "Minutes without use that end a session."),
        "absolute" => S.Int(1, AuthorityStore.MaxSessionAbsoluteMinutes, description: "Minutes after which a session ends however busy."),
        "minutes" => S.Int(1, operation == "grant-extend" ? ReuseSettings.MaxMinutes : ReuseSettings.MaxAdminMinutes, description: "Minutes to add to an active grant or to grant from now."),
        "indefinite" => S.Bool("True for a grant with no end (instead of minutes)."),
        _ => throw new InvalidOperationException("unknown parameter " + name),
    };

    private static readonly string[] RequiredParameters = ["days", "idle", "absolute", "confirm", "type", "config", "max-stale-seconds", "revision", "instance", "kind", "path", "base", "level", "queue-kib", "retention-hours"];

    /// <summary>A mutation route: the body names the parameters of the operation (those not in the path) and carries the authorization id.</summary>
    private ApiRoute Mutation(string method, string template, string operation, string id, string summary, string tag, params string[] body)
    {
        string[] pathParams = [.. template.Split('/').Where(part => part.StartsWith('{')).Select(part => part.Trim('{', '}'))];
        string[] required = [.. body.Where(name => !((operation is "provider-add" or "provider-config") && name == "max-stale-seconds") &&
            (RequiredParameters.Contains(name) || (operation is "machine-rename" or "provider-add" && name == "name")))];
        List<(string, JsonObject)> members = [("authorization", S.Str(max: 64, min: 8, description: "The id of the authorization made for exactly this operation and these parameters (POST /api/v1/authorizations), after its passkey tap."))];
        members.AddRange(body.Select(name => (name, ParameterSchema(name, operation))));
        JsonObject request = S.Obj(members, members.Select(item => item.Item1).Where(name => name != "authorization" && !required.Contains(name)));

        return new ApiRoute(method, Prefix + template, id, summary, tag, ApiAccess.Mutation, 200, "MutationResponse", request, [], operation,
            call => AdminService.IsProviderOperation(operation) && admin.Providers is null ? Task.FromResult(ProvidersUnavailable()) : MutateAsync(call, operation, pathParams),
            operation is "passkey-enroll" or "passkey-unenroll" or "store-key-rotate" ? ["202"] : null,
            BodyLimit: body.Contains("config") ? ConfigurationBodyLimit : 0);
    }

    private static IReadOnlyList<ApiQuery> ApprovalQueries() =>
    [
        new("limit", S.Int(1, ApprovalQueue.MaxPending), "The maximum number of pending requests to return (default 50)."),
        new("cursor", S.Str(max: 128, min: 1), "An opaque cursor from the previous page."),
    ];

    private static JsonObject ApprovalAssertionSchema() => S.Obj(
    [
        ("id", S.Str(max: 2048)),
        ("authenticatorData", S.Str(max: 4096)),
        ("clientDataJSON", S.Str(max: 4096)),
        ("signature", S.Str(max: 4096)),
    ]);

    private static JsonObject ApprovalPrfSchema() => S.Obj(
    [
        ("epk", S.Str(max: 256)),
        ("iv", S.Str(max: 128)),
        ("ct", S.Str(max: 256)),
    ]);

    private static JsonObject ApprovalDecisionBody() => S.Obj(
    [
        ("flowId", S.Str(max: 64, min: 8)),
        ("proof", ApprovalAssertionSchema()),
        ("minutes", S.Int(min: 0, max: ReuseOffer.Always)),
    ], ["minutes"]);

    private IReadOnlyList<ApiRoute> BuildRoutes()
    {
        List<ApiRoute> routes =
        [
            new("GET", Prefix + "/openapi.json", "getOpenApi", "The OpenAPI 3.1 document of this API (public; it carries no secret).", "meta", ApiAccess.Public, 200, null, null, [], null, _ => Task.FromResult(new ApiResult(200, null))),
            new("GET", Prefix + "/status", "getStatus", "Whether the service is running, whether it uses a remote authority, the local authority's lock state and the versions (public).", "status", ApiAccess.Public, 200, "Status", null, [], null, _ => Task.FromResult(new ApiResult(200, admin.StatusView()))),
            new("POST", Prefix + "/browser", "startBrowser", "Make this browser's pre-session cookie and give its anti-forgery value (once, in this answer: keep it in the page and send it as X-Admin-Token). Needed before a sign-in or an unlock. Changes nothing in the authority.", "session", ApiAccess.Open, 201, "Browser", S.Obj([]), [], null, StartBrowserAsync),
            new("GET", Prefix + "/session", "getSession", "Who is signed in (a read-only session) and how a sign-in in progress stands. Read-only: it claims nothing and sets no cookie; a session is recognized only with its cookie AND its own secret (X-Admin-Token).", "session", ApiAccess.Owner, 200, "Session", null, [], null, GetSessionAsync),
            new("POST", Prefix + "/session", "startSession", "Start a sign-in: answers the link of the one-use passkey page whose tap (user verification) starts a read-only session for this browser. Then GET /session until the login is ready, then POST /session/claim.", "session", ApiAccess.Login, 202, "LoginStarted", S.Obj([]), [], null, StartSessionAsync),
            new("POST", Prefix + "/session/inline", "startInlineSession", "Prepare a service-owned WebAuthn challenge for sign-in inside the SPA.", "session", ApiAccess.Login, 201, "InlineLoginStarted", S.Obj([]), [], null, StartInlineSessionAsync),
            new("POST", Prefix + "/session/inline/proof", "submitInlineSessionProof", "Verify the service-prepared sign-in assertion for this browser.", "session", ApiAccess.Login, 200, "Done", S.Obj([("proof", S.Str(max: 12000))]), [], null, SubmitInlineSessionProofAsync),
            new("DELETE", Prefix + "/session/inline", "cancelInlineSession", "Cancel a prepared sign-in challenge.", "session", ApiAccess.Login, 200, "Done", null, [], null, CancelInlineSession),
            new("POST", Prefix + "/session/claim", "claimSession", "Claim the session of the sign-in this browser began, once its tap was verified. The answer carries the session's own secret (antiForgery), once: keep it in the page and send it as X-Admin-Token with every request.", "session", ApiAccess.Claim, 201, "Claim", S.Obj([]), [], null, ClaimSessionAsync),
            new("DELETE", Prefix + "/session", "endSession", "Sign out: ends the session now.", "session", ApiAccess.Logout, 200, "Done", null, [], null, EndSessionAsync),
            new("GET", Prefix + "/approvals", "listApprovals", "List pending run requests for an Approvals-capable session.", "approvals", ApiAccess.ApprovalsRead, 200, "ApprovalQueue", null, ApprovalQueries(), null, ListApprovalsAsync),
            new("GET", Prefix + "/approvals/{requestId}", "getApproval", "Read the current decision state and bounded review projection for one run request.", "approvals", ApiAccess.ApprovalsRead, 200, "ApprovalDetail", null, [], null, GetApprovalAsync),
            new("POST", Prefix + "/approvals/{requestId}/challenge", "createApprovalChallenge", "Prepare a short-lived passkey challenge for Approve once. The SPA remains on the request route.", "approvals", ApiAccess.ApprovalsDecide, 201, "ApprovalChallenge", null, [], null, CreateApprovalChallengeAsync),
            new("POST", Prefix + "/approvals/{requestId}/approve", "approveOnce", "Verify the prepared passkey assertion and approve this request once.", "approvals", ApiAccess.ApprovalsDecide, 200, "ApprovalDetail", ApprovalDecisionBody(), [], null, ApproveOnceAsync),
            new("POST", Prefix + "/approvals/{requestId}/deny", "denyApproval", "Refuse this pending run request without a passkey; no secrets are released.", "approvals", ApiAccess.ApprovalsDecide, 200, "ApprovalDetail", null, [], null, DenyApprovalAsync),
            new("GET", Prefix + "/secrets", "listSecrets", "The names of the stored secrets (names only; a value is never readable).", "secrets", ApiAccess.Read, 200, "SecretList", null, [], null, ListSecretsAsync),
            new("POST", Prefix + "/secrets/entries", "startSecretEntry", "Start a batch of up to 20 values or edit a single stored secret. Requires secrets.write. Moving a secret between names requires an admin passkey and can keep the value by sealing an empty object.", "secrets", ApiAccess.Authorize, 201, "SecretEntry", SecretEntryBody(), [], SecretFlows.SetCommand, StartSecretEntryAsync, BodyLimit: SecretNamesBodyLimit),
            new("POST", Prefix + "/secrets/entries/{id}/seal", "sealSecretEntry", "Check the sealed values and return the batch the passkey will sign. Requires a session with secrets.write.", "secrets", ApiAccess.Authorize, 200, "SecretSealed", SecretSealBody(), [], SecretFlows.SetCommand, SealSecretEntryAsync, BodyLimit: SecretBodyLimit),
            new("POST", Prefix + "/secrets/entries/{id}/save", "saveSecretEntry", "Store the batch with one enrolled passkey assertion, or move a secret with an admin assertion. Requires a session with secrets.write.", "secrets", ApiAccess.Authorize, 200, "Done", SecretSaveBody(), [], SecretFlows.SetCommand, SaveSecretEntryAsync, BodyLimit: SecretBodyLimit),
            new("DELETE", Prefix + "/secrets/entries/{id}", "cancelSecretEntry", "Cancel an entry before saving. Requires a session with secrets.write.", "secrets", ApiAccess.Authorize, 200, "Done", null, [], SecretFlows.SetCommand, CancelSecretEntryAsync),
            new("POST", Prefix + "/secrets/removals", "startSecretRemoval", "Start removing these stored secrets: answers the text and the next state the passkey will sign. Removes nothing.", "secrets", ApiAccess.Authorize, 201, "SecretRemoval", SecretNamesBody(), [], null, StartSecretRemovalAsync),
            new("POST", Prefix + "/secrets/removals/{id}/save", "saveSecretRemoval", "Remove the secrets with one admin passkey assertion over the next state.", "secrets", ApiAccess.Authorize, 200, "Done", SecretRemovalSaveBody(), [], null, SaveSecretRemovalAsync),
            new("GET", Prefix + "/page-settings", "getPageSettings", "The settings of the pages this machine serves: the longest grant time, the address, the port and the time limit (read-only session).", "settings", ApiAccess.Read, 200, "PageSettings", null, [], null, GetPageSettingsAsync),
            new("POST", Prefix + "/page-settings/changes", "startPageSettingsChange", "Start changing the page settings: answers the text and the next state the passkey will sign. Changes nothing.", "settings", ApiAccess.Authorize, 201, "PageSettingsChange", PageSettingsBody(), [], null, StartPageSettingsChangeAsync),
            new("POST", Prefix + "/page-settings/changes/{id}/save", "savePageSettingsChange", "Change the page settings with one admin passkey assertion over the next state.", "settings", ApiAccess.Authorize, 200, "Done", SecretRemovalSaveBody(), [], null, SavePageSettingsChangeAsync),
            new("DELETE", Prefix + "/page-settings/changes/{id}", "cancelPageSettingsChange", "Cancel a change that has not been saved.", "settings", ApiAccess.Authorize, 200, "Done", null, [], null, CancelSecretEntryAsync),
            new("GET", Prefix + "/machines", "listMachines", "The machines and where each stands (read-only session).", "machines", ApiAccess.Read, 200, "MachineList", null, [], null, _ => Task.FromResult(new ApiResult(200, new { items = admin.MachinesView() }))),
            new("GET", Prefix + "/machines/{fingerprint}", "getMachine", "One machine, by its fingerprint or an unambiguous start of it (read-only session).", "machines", ApiAccess.Read, 200, "Machine", null, [], null, GetMachineAsync),
            new("GET", Prefix + "/machines/{fingerprint}/diagnostics", "getMachineDiagnostics", "Recent diagnostics and forwarding settings for one machine.", "machines", ApiAccess.Read, 200, "MachineDiagnostics", null, [], null, GetMachineDiagnosticsAsync),
            new("GET", Prefix + "/grants", "listGrants", "The grants and what can be done to each (read-only session).", "grants", ApiAccess.Read, 200, "GrantList", null, [], null, _ => Task.FromResult(new ApiResult(200, new { items = admin.GrantsView() }))),
            new("GET", Prefix + "/grants/{id}", "getGrant", "One grant, by its id or an unambiguous start of it (read-only session).", "grants", ApiAccess.Read, 200, "Grant", null, [], null, GetGrantAsync),
            new("GET", Prefix + "/grants/{id}/review", "getGrantReview", "The signed approval text of a grant, available while the authority is unlocked, which opens review (state open, locked or none).", "grants", ApiAccess.Read, 200, "GrantReview", null, [], null, GetGrantReviewAsync),
            new("GET", Prefix + "/audit/events", "searchAuditEvents", "Search the host events the authority holds (authorization, launch and execution outcomes). Every filter is optional.", "audit", ApiAccess.Read, 200, "AuditEventList", null, AuditQueries(), null, AuditEventsAsync),
            new("GET", Prefix + "/audit/changes", "searchAuditChanges", "Search the authority's own audit history (administrator operations, machine and grant changes). Filters: machine, since, until, text, last.", "audit", ApiAccess.Read, 200, "AuditChangeList", null, AuditQueries(), null, AuditChangesAsync),
            new("GET", Prefix + "/audit/gaps", "listAuditGaps", "The open holes in a machine's audit numbering. Filter: machine.", "audit", ApiAccess.Read, 200, "AuditGapList", null, [new ApiQuery("machine", S.Str(max: 80), "A machine's fingerprint or the start of it.")], null, AuditGapsAsync),
            new("GET", Prefix + "/settings", "getSettings", "Audit retention, the session timeouts and the authority key in use (read-only session).", "settings", ApiAccess.Read, 200, "Settings", null, [], null, _ => Task.FromResult(new ApiResult(200, admin.SettingsView()))),
            new("GET", Prefix + "/pairing/invitations", "listPairingInvitations", "The pairing invitations by status only (pending, consumed, expired or revoked); never a code or a bundle (read-only session).", "pairing", ApiAccess.Read, 200, "InvitationList", null, [], null, _ => Task.FromResult(new ApiResult(200, new { items = admin.InvitationsView() }))),
            new("GET", Prefix + "/passkeys", "listPasskeys", "The enrolled passkeys (names and kinds; no key material).", "passkeys", ApiAccess.Read, 200, "Passkeys", null, [], null, _ => Task.FromResult(new ApiResult(200, admin.PasskeysView()))),
            .. ProviderRoutes(),
            new("POST", Prefix + "/authorizations", "createAuthorization", "Ask to authorize one change: answers the link of a one-use passkey page whose signed text names the operation and every security-relevant parameter, and the text to show. The tap (user verification) makes the authorization usable once, for exactly that operation and those parameters, for " + AdminService.LifetimeText + " seconds. It changes nothing by itself.", "authorizations", ApiAccess.Authorize, 201, "Authorization", AuthorizationRequest(), [], null, CreateAuthorizationAsync, BodyLimit: ConfigurationBodyLimit),
            new("POST", Prefix + "/authorizations/inline", "createInlineAuthorization", "Prepare an operation-bound WebAuthn challenge for the SPA. This makes no change; submit its assertion to /authorizations/{id}/proof.", "authorizations", ApiAccess.Authorize, 201, "InlineAuthorization", AuthorizationRequest(), [], null, CreateInlineAuthorizationAsync, BodyLimit: ConfigurationBodyLimit),
            new("POST", Prefix + "/authorizations/{id}/proof", "submitInlineAuthorizationProof", "Verify the assertion for this exact pending operation and apply it once when valid.", "authorizations", ApiAccess.Authorize, 200, "Done", S.Obj([("proof", S.Str(max: 12000)), ("prf", ApprovalPrfSchema())], ["prf"]), [], null, SubmitInlineAuthorizationProofAsync),
            new("GET", Prefix + "/authorizations/{id}", "getAuthorization", "Where an authorization stands (pending, verified, refused, consumed or expired) and, once its tap was verified, how the change it authorized came out (`result`: the service applies it at the tap, so this is readable after a reload or from another tab; a new invitation's bundle is given once, when collect=invitation is asked for or by the first retry of the mutation). Only for the caller it was made for (its session, or for the unlock its browser).", "authorizations", ApiAccess.Owner, 200, "Authorization", null, [new ApiQuery("collect", S.Str(values: ["invitation"]), "Give the bundle of a new invitation in this answer (once; it is never given again).")], null, GetAuthorizationAsync),
            new("DELETE", Prefix + "/authorizations/{id}", "cancelAuthorization", "Cancel an authorization whose passkey tap has not been made: a tap on its page afterwards changes nothing. Only for the caller it was made for. 409 when the tap was already judged (its change was made or refused and cannot be taken back).", "authorizations", ApiAccess.Owner, 200, "Done", null, [], null, CancelAuthorizationAsync),
            Mutation("POST", "/unlock", AdminService.OpUnlock, "unlockAuthority", "Unlock the local authority (needs no session, but its own authorization). Remote hosts refuse this operation.", "authority"),
            Mutation("POST", "/lock", AdminService.OpLock, "lockAuthority", "Lock the local authority: secret requests stop, held keys are discarded and every session and authorization ends. Remote hosts refuse this operation.", "authority"),
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
            Mutation("PUT", "/machines/{fingerprint}/diagnostics/settings", AuthorityStore.SetDiagnosticsOperation, "setMachineDiagnosticsSettings", "Set the machine's diagnostic forwarding level, queue budget and retention.", "machines", "level", "queue-kib", "retention-hours"),
            Mutation("POST", "/machines/{fingerprint}/approve-host-change", "machine-host-change", "approveMachineHostChange", "Accept the new host name a machine reported.", "machines"),
            Mutation("POST", "/grants/{id}/extend", "grant-extend", "extendGrant", "Extend a grant by minutes, or to no end.", "grants", "minutes", "indefinite"),
            Mutation("POST", "/grants/{id}/renew", "grant-renew", "renewGrant", "Renew an ended grant for minutes from now, or to no end.", "grants", "minutes", "indefinite"),
            Mutation("POST", "/grants/{id}/replace", "grant-replace", "replaceGrant", "Make a new grant with the same scope as a used once-only grant.", "grants", "minutes", "indefinite"),
            Mutation("POST", "/grants/{id}/revoke", "grant-revoke", "revokeGrant", "Revoke a grant (it ends now and its machine is told).", "grants"),
            Mutation("POST", "/pairing/invitations", "pairing-create", "createPairingInvitation", "Create a one-time pairing invitation for a new machine. The answer carries the invitation bundle (address, identifier and pairing code) ONCE; it is never stored in readable form, never logged and cannot be read again.", "pairing"),
            Mutation("POST", "/pairing/invitations/{id}/revoke", "pairing-revoke", "revokePairingInvitation", "Revoke a pending pairing invitation (it can no longer be used).", "pairing"),
            Mutation("POST", "/passkeys", "passkey-enroll", "addPasskey", "Add a passkey: after its authorization the enrollment pages (their own passkey taps) are started; the answer is the link of the first.", "passkeys"),
            Mutation("POST", "/secrets/store-key/rotate", "store-key-rotate", "rotateStoreKey", "Rotate the secret store key and the master key: after its authorization the rotation pages (two admin passkey taps) are started; the answer is the link of the first. Only the tapped passkey stays and a new code for recovery is shown once.", "secrets"),
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
        ("parameters", S.Params(8, MaxParameterLength, LongParameters)),
    ], ["parameters"], "The operation and every parameter that the passkey will sign. The mutation that follows must repeat exactly these.");
}

using System.Text.Json.Nodes;

namespace WithSecrets;

/// <summary>
/// The OpenAPI 3.1 document, generated from the route table (<see cref="BuildRoutes" />) and the schemas below: the dispatcher and the document are made from the same records, so a route cannot be served
/// without being documented. The checked-in copy (<c>docs/api/openapi.json</c>, the input of the TypeScript client) is compared with this by a test; the schemas of the answers are checked against real answers by tests.
/// </summary>
internal sealed partial class AdminApi
{
    private static JsonObject Components()
    {
        string[] machineActions = ["approve", "disable", "enable", "untrust", "trust", "approve-host-change", "rename"];
        string[] grantActions = ["extend", "renew", "revoke"];
        JsonObject schemas = new()
        {
            ["Problem"] = S.Obj(
            [
                ("type", S.Str(description: "A URI naming the kind of problem (urn:with-secrets:problem:CODE).")),
                ("title", S.Str()),
                ("status", S.Int()),
                ("detail", S.Str(description: "One safe sentence. Never a secret, a credential, a key or an internal detail.")),
                ("code", S.Str(description: "A stable machine-readable code.")),
                ("supportedVersions", S.Arr(S.Str())),
            ], ["supportedVersions"], "An RFC 9457 problem document (application/problem+json)."),
            ["Done"] = S.Obj([("ok", S.Bool())]),
            ["Status"] = S.Obj(
            [
                ("running", S.Bool()),
                ("locked", S.Bool()),
                ("unlockMode", S.Str(values: [UnlockPolicies.Manual, UnlockPolicies.Unattended])),
                ("unlockedHow", S.Str(nullable: true, description: "How it was unlocked (manual, unattended), when it is unlocked.")),
                ("apiVersion", S.Str()),
                ("version", S.Str()),
                ("protocolVersion", S.Int()),
            ]),
            ["Login"] = S.Obj([("state", S.Str(values: ["waiting", "ready", "failed"])), ("problem", S.Str(nullable: true))]),
            ["Session"] = S.Obj(
            [
                ("authenticated", S.Bool()),
                ("identity", S.Str(nullable: true, description: "The trusted enrolled passkey identity that signed in.")),
                ("scope", S.Str(values: ["admin", "approval"], nullable: true)),
                ("capabilities", S.Arr(S.Str(values: [SessionCapabilities.ApprovalsRead, SessionCapabilities.ApprovalsDecide, SessionCapabilities.AdminRead, SessionCapabilities.AdminDecide]))),
                ("started", S.Time(nullable: true)),
                ("idleExpires", S.Time(nullable: true)),
                ("absoluteExpires", S.Time(nullable: true)),
                ("login", new JsonObject { ["oneOf"] = new JsonArray(S.Ref("Login"), new JsonObject { ["type"] = "null" }) }),
                ("recent", S.Arr(S.Str())),
            ]),
            ["Browser"] = S.Obj([("antiForgery", S.Str(description: "Keep this in the page (not in a cookie) and send it as the X-Admin-Token header with every request. It is given once, here, and never again."))]),
            ["Claim"] = S.Obj([("antiForgery", S.Str(description: "The session's own secret, given once, here. Send it as the X-Admin-Token header with every request: the session cookie alone is not enough.")), ("session", S.Ref("Session"))]),
            ["LoginStarted"] = S.Obj([("link", S.Str(description: "The one-use passkey page to open. The tap there starts the session."))]),
            ["InlineLoginStarted"] = S.Obj([("proof", S.Ref("ProofStart"))]),
            ["ApprovalMachine"] = S.Obj(
            [
                ("fingerprint", S.Str()),
                ("friendlyName", S.Str(nullable: true)),
                ("hostName", S.Str()),
            ]),
            ["ApprovalQueueItem"] = S.Obj(
            [
                ("requestId", S.Str()),
                ("status", S.Str(values: ["pending"])),
                ("submittedAt", S.Time()),
                ("expiresAt", S.Time()),
                ("machine", S.Ref("ApprovalMachine")),
                ("program", S.Str()),
                ("reason", S.Str()),
                ("secretNames", S.Arr(S.Str())),
            ]),
            ["ApprovalQueue"] = S.Obj(
            [
                ("items", S.Arr(S.Ref("ApprovalQueueItem"))),
                ("nextCursor", S.Str(nullable: true)),
                ("serverTime", S.Time()),
            ]),
            ["ApprovalScript"] = S.Obj(
            [
                ("path", S.Str(nullable: true)),
                ("sha256", S.Str()),
                ("length", S.Int()),
                ("text", S.Str(nullable: true)),
                ("guessed", S.Bool()),
                ("binary", S.Bool()),
            ]),
            ["ApprovalDecrypt"] = S.Obj(
            [
                ("variable", S.Str()),
                ("file", S.Str()),
                ("keySecret", S.Str()),
                ("cipherShort", S.Str()),
            ]),
            ["ApprovalNameValue"] = S.Obj([("name", S.Str()), ("value", S.Str())]),
            ["ApprovalCodeWarning"] = S.Obj([("name", S.Str()), ("why", S.Str())]),
            ["ApprovalReview"] = S.Obj(
            [
                ("requestId", S.Str()),
                ("fingerprintKey", S.Str()),
                ("requestDigest", S.Str()),
                ("submittedAt", S.Time()),
                ("expiresAt", S.Time()),
                ("machine", S.Ref("ApprovalMachine")),
                ("program", S.Str()),
                ("resolvedProgram", S.Str()),
                ("arguments", S.Arr(S.Str())),
                ("workingDirectory", S.Str()),
                ("reason", S.Str()),
                ("secretNames", S.Arr(S.Str())),
                ("secretSources", new JsonObject { ["type"] = "object", ["additionalProperties"] = S.Str() }),
                ("inlineCode", S.Str(nullable: true)),
                ("script", new JsonObject { ["oneOf"] = new JsonArray(S.Ref("ApprovalScript"), new JsonObject { ["type"] = "null" }) }),
                ("programFile", new JsonObject { ["oneOf"] = new JsonArray(S.Ref("ApprovalScript"), new JsonObject { ["type"] = "null" }) }),
                ("envFiles", S.Arr(S.Str())),
                ("envPairs", S.Arr(S.Str())),
                ("shownEnvValues", S.Arr(S.Ref("ApprovalNameValue"))),
                ("codeChangeWarnings", S.Arr(S.Ref("ApprovalCodeWarning"))),
                ("decrypts", S.Arr(S.Ref("ApprovalDecrypt"))),
                ("inheritedEnvironmentLine", S.Str(nullable: true)),
                ("extraLines", S.Arr(S.Str())),
                ("canonicalText", S.Str()),
                ("requiresUnlock", S.Bool()),
            ]),
            ["ApprovalDetail"] = S.Obj(
            [
                ("requestId", S.Str()),
                ("status", S.Str(values: ["pending", "approved", "denied", "expired", "cancelled"])),
                ("submittedAt", S.Time()),
                ("expiresAt", S.Time()),
                ("decidedAt", S.Time(nullable: true)),
                ("machine", new JsonObject { ["oneOf"] = new JsonArray(S.Ref("ApprovalMachine"), new JsonObject { ["type"] = "null" }) }),
                ("program", S.Str(nullable: true)),
                ("reason", S.Str(nullable: true)),
                ("secretNames", S.Arr(S.Str(), nullable: true)),
                ("review", new JsonObject { ["oneOf"] = new JsonArray(S.Ref("ApprovalReview"), new JsonObject { ["type"] = "null" }) }),
                ("decisionInProgress", S.Bool()),
                ("actions", S.Arr(S.Str())),
            ]),
            ["ApprovalChallenge"] = S.Obj(
            [
                ("flowId", S.Str()),
                ("mode", S.Str(values: ["webauthn"])),
                ("payload", new JsonObject { ["type"] = "object", ["additionalProperties"] = true }),
                ("expiresAt", S.Time()),
                ("prfKey", S.Str(nullable: true)),
            ]),
            ["CopyWarning"] = S.Obj(
            [
                ("count", S.Int(description: "The most supersedes from another address seen within one watch window.")),
                ("firstAddress", S.Str(description: "The address of the older connection when the warning was first recorded.")),
                ("lastAddress", S.Str(description: "The address of the newest connection that superseded another.")),
                ("firstSeen", S.Time()),
                ("lastSeen", S.Time()),
            ], description: "A warning (never a decision) that this machine's identity may have been copied: its connection was repeatedly superseded by a connection from a different address."),
            ["Machine"] = S.Obj(
            [
                ("fingerprint", S.Str()),
                ("display", S.Str()),
                ("status", S.Str(values: ["pending", "trusted", "disabled", "untrusted"])),
                ("revision", S.Int()),
                ("hostName", S.Str()),
                ("pendingHostName", S.Str(nullable: true)),
                ("friendlyName", S.Str(nullable: true)),
                ("created", S.Time()),
                ("updated", S.Time()),
                ("thisMachine", S.Bool()),
                ("actions", S.Arr(S.Str(values: machineActions))),
                ("copyWarning", new JsonObject { ["oneOf"] = new JsonArray(S.Ref("CopyWarning"), new JsonObject { ["type"] = "null" }) }),
            ]),
            ["MachineList"] = S.Obj([("items", S.Arr(S.Ref("Machine")))]),
            ["Grant"] = S.Obj(
            [
                ("id", S.Str()),
                ("fingerprint", S.Str()),
                ("machineName", S.Str(nullable: true)),
                ("state", S.Str()),
                ("status", S.Str()),
                ("revision", S.Int()),
                ("created", S.Time()),
                ("updated", S.Time()),
                ("expires", S.Time(nullable: true)),
                ("ends", S.Str()),
                ("secretNames", S.Str(description: "The NAMES of the secrets the grant covers (never a value).")),
                ("program", S.Str()),
                ("workingDirectory", S.Str()),
                ("approvedBy", S.Str()),
                ("revoked", S.Time(nullable: true)),
                ("actions", S.Arr(S.Str(values: grantActions))),
            ]),
            ["GrantList"] = S.Obj([("items", S.Arr(S.Ref("Grant")))]),
            ["AuditEvent"] = S.Obj(
            [
                ("eventId", S.Str()),
                ("sequence", S.Int()),
                ("time", S.Time()),
                ("received", S.Time()),
                ("machine", S.Str()),
                ("type", S.Str(values: [.. AuditEventTypes.All])),
                ("outcome", S.Str()),
                ("reason", S.Str()),
                ("requestId", S.Str()),
                ("folder", S.Str()),
                ("program", S.Str()),
                ("arguments", S.Arr(S.Str())),
                ("grantId", S.Str()),
                ("exitCode", S.Int(nullable: true)),
                ("metadata", S.TextMap(AuditMetadata.MaxMembers, AuditMetadata.MaxValue, "Names and fingerprints the host signed with the event (secret names, key name, reuse minutes, variable mapping, .env files, file fingerprints). Read-only data, never values.")),
            ]),
            ["AuditEventList"] = S.Obj([("items", S.Arr(S.Ref("AuditEvent")))]),
            ["AuditChange"] = S.Obj([("id", S.Int()), ("time", S.Time()), ("event", S.Str()), ("machine", S.Str(nullable: true)), ("actor", S.Str()), ("detail", S.Str())]),
            ["AuditChangeList"] = S.Obj([("items", S.Arr(S.Ref("AuditChange")))]),
            ["AuditGap"] = S.Obj([("id", S.Int()), ("machine", S.Str()), ("kind", S.Str()), ("from", S.Int()), ("to", S.Int()), ("detected", S.Time()), ("resolved", S.Time(nullable: true)), ("epoch", S.Str())]),
            ["AuditGapList"] = S.Obj([("items", S.Arr(S.Ref("AuditGap")))]),
            ["Settings"] = S.Obj(
            [
                ("unlockMode", S.Str(values: [UnlockPolicies.Manual, UnlockPolicies.Unattended])),
                ("unlockModeDescription", S.Str()),
                ("auditRetentionDays", S.Int()),
                ("sessionIdleMinutes", S.Int()),
                ("sessionAbsoluteMinutes", S.Int()),
                ("authorityKey", S.Str(description: "The public fingerprint of the authority key in use.")),
                ("maxAuditRetentionDays", S.Int()),
                ("maxSessionIdleMinutes", S.Int()),
                ("maxSessionAbsoluteMinutes", S.Int()),
            ]),
            ["Passkey"] = S.Obj([("name", S.Str()), ("detail", S.Str()), ("created", S.Time()), ("admin", S.Bool())]),
            ["Passkeys"] = S.Obj([("available", S.Bool()), ("problem", S.Str(nullable: true)), ("items", S.Arr(S.Ref("Passkey")))]),
            ["NameValue"] = S.Obj([("name", S.Str()), ("value", S.Str())]),
            ["Authorization"] = S.Obj(
            [
                ("id", S.Str(description: "Carry this in the `authorization` member of the one mutation it was made for.")),
                ("operation", S.Str(values: [.. Operations.Select(item => item.Operation)])),
                ("state", S.Str(values: ["pending", "verified", "refused", "consumed", "expired"])),
                ("detail", S.Str(nullable: true)),
                ("link", S.Str(nullable: true, description: "The one-use passkey page to open (while pending). The tap there is the authorization.")),
                ("sentence", S.Str(description: "Exactly what the passkey signs: show it to the person.")),
                ("parameters", S.Arr(S.Ref("NameValue"))),
                ("created", S.Time()),
                ("expires", S.Time()),
                ("lifetimeSeconds", S.Int(description: "How long a verified authorization may wait for its mutation.")),
                ("result", new JsonObject { ["oneOf"] = new JsonArray(S.Ref("AuthorizationResult"), new JsonObject { ["type"] = "null" }) }),
                ("proof", new JsonObject { ["oneOf"] = new JsonArray(S.Ref("ProofStart"), new JsonObject { ["type"] = "null" }) }),
            ]),
            ["ProofStart"] = S.Obj([("mode", S.Str(values: ["webauthn"])), ("payload", S.Str(description: "Service-generated WebAuthn request data; the service retains the operation, nonce, origin and RP ID context."))]),
            ["InlineAuthorization"] = S.Obj(
            [
                ("id", S.Str()), ("operation", S.Str(values: [.. Operations.Select(item => item.Operation)])), ("state", S.Str(values: ["pending"])),
                ("detail", S.Str(nullable: true)), ("link", S.Str(nullable: true)), ("sentence", S.Str()), ("parameters", S.Arr(S.Ref("NameValue"))),
                ("created", S.Time()), ("expires", S.Time()), ("lifetimeSeconds", S.Int()), ("result", new JsonObject { ["oneOf"] = new JsonArray(S.Ref("AuthorizationResult"), new JsonObject { ["type"] = "null" }) }),
                ("proof", S.Ref("ProofStart")),
            ]),
            ["AuthorizationResult"] = S.Obj(
            [
                ("outcome", S.Str(values: ["applied", "started", "failed"], description: "applied: the service made the change when the tap was verified. started: the operation's own passkey pages continue at `link`. failed: the tap was good but the change was refused or could not be made (see `code` and `detail`); nothing was changed.")),
                ("code", S.Str(nullable: true)),
                ("detail", S.Str(nullable: true)),
                ("link", S.Str(nullable: true)),
                ("invitation", new JsonObject { ["oneOf"] = new JsonArray(S.Ref("InvitationCreated"), new JsonObject { ["type"] = "null" }) }),
                ("invitationGone", S.Bool("True when a new invitation's bundle was already given (or held for " + AdminService.BundleHold.TotalMinutes + " minutes without being collected): it is never given again.")),
            ]),
            ["AuthorizationRequest"] = AuthorizationRequest(),
            ["Invitation"] = S.Obj(
            [
                ("id", S.Str(description: "The invitation's identifier (not secret on its own: it is useless without the pairing code, which is never listed).")),
                ("status", S.Str(values: ["pending", "consumed", "expired", "revoked"])),
                ("created", S.Time()),
                ("expires", S.Time()),
                ("ended", S.Time(nullable: true)),
                ("machine", S.Str(nullable: true, description: "The fingerprint of the machine that used it, once consumed.")),
                ("canRevoke", S.Bool()),
            ]),
            ["InvitationList"] = S.Obj([("items", S.Arr(S.Ref("Invitation")))]),
            ["InvitationCreated"] = S.Obj(
            [
                ("id", S.Str()),
                ("expires", S.Time()),
                ("bundle", S.Str(description: "The credential bundle: address, identifier and pairing code. Shown ONCE, in this answer. It is not stored in readable form, not logged and cannot be fetched again; give it to the new machine's pairing command (hidden prompt, an environment variable or, preferably, a secret file).")),
            ]),
            ["MutationResponse"] = S.Obj(
            [
                ("operation", S.Str()),
                ("outcome", S.Str(values: ["applied", "started", "already-applied", "already-started"], description: "applied: done (the service made the change when the tap was verified). started: the first passkey page of an operation with pages of its own is at `link`. already-applied and already-started: a retry for an authorization that was already answered; nothing was applied again.")),
                ("link", S.Str(nullable: true)),
                ("invitation", new JsonObject { ["oneOf"] = new JsonArray(S.Ref("InvitationCreated"), new JsonObject { ["type"] = "null" }) }),
            ]),
        };

        return schemas;
    }

    private static JsonObject ProblemResponse(string description) => new()
    {
        ["description"] = description,
        ["content"] = new JsonObject { ["application/problem+json"] = new JsonObject { ["schema"] = S.Ref("Problem") } },
    };

    private static JsonObject Document0(IReadOnlyList<ApiRoute> routes)
    {
        JsonObject paths = [];
        foreach (ApiRoute route in routes)
        {
            string key = route.Template;
            if (paths[key] is not JsonObject item)
            {
                item = [];
                paths[key] = item;
            }

            JsonObject operation = new() { ["operationId"] = route.OperationId, ["summary"] = route.Summary, ["tags"] = new JsonArray(route.Tag) };
            JsonArray parameters = [];
            foreach (string name in route.Template.Split('/').Where(part => part.StartsWith('{')).Select(part => part.Trim('{', '}')))
            {
                parameters.Add(new JsonObject { ["name"] = name, ["in"] = "path", ["required"] = true, ["schema"] = name is "fingerprint" or "id" or "name" ? ParameterSchema(name) : S.Str(max: 80) });
            }

            foreach (ApiQuery query in route.Query)
            {
                parameters.Add(new JsonObject { ["name"] = query.Name, ["in"] = "query", ["required"] = false, ["description"] = query.Description, ["schema"] = query.Schema.DeepClone() });
            }

            if (parameters.Count > 0)
            {
                operation["parameters"] = parameters;
            }

            if (route.Request is not null)
            {
                operation["requestBody"] = new JsonObject
                {
                    ["required"] = true,
                    ["content"] = new JsonObject { ["application/json"] = new JsonObject { ["schema"] = route.OperationId is "createAuthorization" or "createInlineAuthorization" ? S.Ref("AuthorizationRequest") : route.Request.DeepClone() } },
                };
            }

            string access = route.Access switch
            {
                ApiAccess.Public => "public",
                ApiAccess.Owner => "caller",
                ApiAccess.Read or ApiAccess.ApprovalsRead or ApiAccess.ApprovalsDecide => "session",
                ApiAccess.Login => "browser",
                ApiAccess.Logout => "session",
                ApiAccess.Authorize => "session",
                _ => "authorization",
            };
            operation["x-access"] = access;
            if (route.Access == ApiAccess.ApprovalsDecide)
            {
                operation["description"] = route.Summary + " Requires a session with approvals.decide, the anti-forgery header and a same-origin request. Denial releases no secrets and does not require WebAuthn; approval requires a fresh request-bound, user-verified WebAuthn assertion.";
            }
            if (route.Access == ApiAccess.Mutation)
            {
                operation["x-operation"] = route.Operation ?? "policy-manual | policy-unattended";
                operation["description"] = route.Summary + " Needs a session (the unlock needs none), the anti-forgery header, a same-origin request and an authorization that was made for exactly this operation and these parameters, tapped with user verification, unspent and not older than " + AdminService.LifetimeText + " seconds. Any other authorization, a repeated one or a session alone is refused with 403.";
            }

            JsonObject responses = [];
            if (route.OperationId == "getOpenApi")
            {
                responses["200"] = new JsonObject { ["description"] = "The OpenAPI document.", ["content"] = new JsonObject { ["application/json"] = new JsonObject { ["schema"] = new JsonObject { ["type"] = "object" } } } };
            }
            else
            {
                responses[route.Success.ToString(System.Globalization.CultureInfo.InvariantCulture)] = new JsonObject
                {
                    ["description"] = "Success.",
                    ["content"] = new JsonObject { ["application/json"] = new JsonObject { ["schema"] = S.Ref(route.Response!) } },
                };
                foreach (string also in route.AlsoSuccess ?? [])
                {
                    responses[also] = new JsonObject { ["description"] = "Started: the first passkey page of the operation is at `link`.", ["content"] = new JsonObject { ["application/json"] = new JsonObject { ["schema"] = S.Ref(route.Response!) } } };
                }
            }

            if (route.Request is not null || route.Query.Count > 0 || route.Template.Contains('{', StringComparison.Ordinal))
            {
                responses["400"] = ProblemResponse("The request is not valid (invalid-request, invalid-json).");
            }

            responses["403"] = ProblemResponse("Another origin is refused (origin-not-allowed); for a change also no Origin, no anti-forgery value, or no valid authorization (origin-required, anti-forgery, authorization-invalid, authorization-pending, authorization-refused, authorization-used, authorization-expired, authorization-mismatch).");
            if (route.Access is not (ApiAccess.Public or ApiAccess.Owner or ApiAccess.Open or ApiAccess.Login or ApiAccess.Claim))
            {
                responses["401"] = ProblemResponse("No browser session (session-required).");
            }

            if (route.Template.Contains('{', StringComparison.Ordinal) || route.Access == ApiAccess.Authorize)
            {
                responses["404"] = ProblemResponse("No such resource (not-found).");
            }

            if (route.Access is ApiAccess.Authorize or ApiAccess.Mutation)
            {
                responses["409"] = ProblemResponse("The operation does not apply, or the change failed (operation-refused, operation-failed).");
                responses["423"] = ProblemResponse("The authority is locked (authority-locked).");
            }

            if (route.Request is not null)
            {
                responses["413"] = ProblemResponse("The body is too large (payload-too-large).");
                responses["415"] = ProblemResponse("The body is not application/json (unsupported-media-type).");
            }

            responses["421"] = ProblemResponse("The Host is not a loopback name (host-not-allowed).");
            if (route.Access is ApiAccess.Authorize or ApiAccess.Mutation or ApiAccess.Login)
            {
                responses["429"] = ProblemResponse("Too many requests (too-many-requests).");
            }

            responses["500"] = ProblemResponse("The request failed (internal-error). Nothing the response does not say was changed.");
            operation["responses"] = responses;
            if (route.Access is not (ApiAccess.Public or ApiAccess.Owner or ApiAccess.Open))
            {
                JsonObject session = new() { ["sessionCookie"] = new JsonArray(), ["antiForgery"] = new JsonArray() };
                JsonObject browser = new() { ["browserCookie"] = new JsonArray(), ["antiForgery"] = new JsonArray() };
                operation["security"] = route.Access is ApiAccess.Read or ApiAccess.Logout ? new JsonArray(session)
                    : route.Access is ApiAccess.Login or ApiAccess.Claim ? new JsonArray(browser)
                    : new JsonArray(session, browser);
            }

            item[route.Method.ToLowerInvariant()] = operation;
        }

        return paths;
    }

    private static JsonObject BuildDocument(IReadOnlyList<ApiRoute> routes, int port)
    {
        _ = port;

        return new JsonObject
        {
            ["openapi"] = "3.1.0",
            ["info"] = new JsonObject
            {
                ["title"] = "with-secrets authority administration API",
                ["version"] = "1.0.0",
                ["description"] = "The administration API of the with-secrets authority on the Windows host service's loopback port (same origin as the administration web application). JSON only. "
                    + "A browser session is READ-ONLY (an HttpOnly, SameSite=Strict cookie plus a secret given once, in service memory only). Every administrative change needs its own fresh passkey authorization; the narrow exception is Deny request in Approvals, which releases no secrets. Approve once requires a fresh request-bound passkey assertion (POST /api/v1/authorizations, then the tap, then the mutation carrying the authorization id), "
                    + "bound to the operation and its parameters, single use and time limited. There is no CORS. Changes within v1 are additive; a breaking change is a new major version. Another version number (/api/v2/...) is answered with 400 and the problem code "
                    + "unsupported-api-version listing supportedVersions; an unknown path under /api is 404 route-not-found; /api never falls through to the web application. Every response carries X-Api-Version; a request may carry it too (X-Api-Version: 1) and another value is refused with unsupported-api-version. No answer contains a secret value, a credential, a private key or recovery material.",
            },
            ["servers"] = new JsonArray(new JsonObject { ["url"] = "/", ["description"] = "The service's own origin (http://localhost:PORT)." }),
            ["tags"] = new JsonArray([.. routes.Select(route => route.Tag).Distinct().Select(tag => (JsonNode?)new JsonObject { ["name"] = tag })]),
            ["paths"] = Document0(routes),
            ["components"] = new JsonObject
            {
                ["securitySchemes"] = new JsonObject
                {
                    ["sessionCookie"] = new JsonObject { ["type"] = "apiKey", ["in"] = "cookie", ["name"] = AdminSessions.SessionCookie, ["description"] = "A read-only browser session (admin or approval scope; HttpOnly, SameSite=Strict, path " + Prefix + "). The value is bound to the service port. Alone it is not enough: the request must also carry the session's own secret (antiForgery)." },
                    ["browserCookie"] = new JsonObject { ["type"] = "apiKey", ["in"] = "cookie", ["name"] = AdminSessions.BrowserCookie, ["description"] = "The browser's pre-session cookie (HttpOnly, SameSite=Strict, path " + Prefix + "), made by POST /browser; with it, the anti-forgery value of POST /browser." },
                    ["antiForgery"] = new JsonObject { ["type"] = "apiKey", ["in"] = "header", ["name"] = TokenHeader, ["description"] = "A secret given once, in the answer that made the cookie it belongs to: POST /browser (before a session) or POST /session/claim (the session). Kept in the page, never in a cookie; the page's origin (with its port) is what keeps it from other programs that are sent the cookies." },
                },
                ["schemas"] = Components(),
            },
            ["x-versioning"] = new JsonObject { ["current"] = Version, ["supported"] = new JsonArray(Version), ["unsupportedVersionProblem"] = "unsupported-api-version" },
        };
    }
}

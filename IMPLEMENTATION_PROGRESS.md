# Implementation progress

Worktree `C:\Users\codep\Projects\with-secrets-impl`, branch `impl/host-service` (based on origin/main 03be52b). Plan: `docs/implementation-plan.md`. Architecture (`docs/architecture.md`) is authoritative.

## Current phase

Phase 0 (extract contracts, preserve behaviour): done, reviewed. Phase 1 (local host service and shared API): done, pending review. Phase 2 (machine identity and local authority): done, pending review. Phase 3 (the independent parts: grants, offline lease, startup reconciliation, plus the maintainer's decision to hold the store key in service memory for a grant's life): done, reviewed (fix round 1 applied). Phase 4 (durable audit trail): done, pending review. Phase 4b (authority lock, admin web app, sensitive operations): done, pending review. Next: Phase 5 onward.

## Commands

- Build: `dotnet build with-secrets.slnx --no-incremental` (warnings are errors; must be 0)
- Tests (console runner, about 5 min): `dotnet run --project tests\WithSecrets.Tests`
- One suite: `$env:WS_ONLY = "LaunchContract"; dotnet run --project tests\WithSecrets.Tests` (names: see `Wants("...")` in `tests\WithSecrets.Tests\Program.cs`)
- E2E (real browser): `dotnet run --project tests\WithSecrets.E2E`
- Tests use temp folders only; never touch `~/.with-secrets`.

## Phase 0: completed work

1. Reconnaissance (below).
2. Contracts in `src\WithSecrets.Core\Contracts\LaunchContracts.cs`: `LaunchProtocol` (Version = 1, MaxLifetime 10 min, ClockSkew 1 min), `LaunchMapping`, `LaunchRequest`, `LaunchOutcome`, `LaunchResult`, `LaunchBinding`, `LaunchRequestBinding`, plus internal `CanonicalJson` / `ContractReader` helpers. No type carries a secret value; no local-vs-remote branching.
3. Canonical JSON: fixed member order, no white space, `envVariables` sorted ordinal, lists in given order, UTC "O" times, strings via `ToolSettings.QuoteJson` (new; same escapes as the `ToolSettings.Quote` that `Manifest.Canonical()` uses, plus U+0000-U+001F as `\u00XX`, because reasons and arguments may contain control characters and `Quote` would emit invalid JSON). `Quote` is untouched (manifest signatures depend on it).
4. `RequestDigest` = `LaunchRequest.Digest()` = upper-case hex SHA-256 of the canonical UTF-8 text, over all 14 fields.
5. `LaunchRequestBinding`: `From(ApprovalRequest, ...)` builds the request; `Mismatch` / `Bind` refuse a request that is not the approved one and return `LaunchBinding(RequestDigest, FingerprintKey, BoundDigest)`. `BoundDigest` = SHA-256("with-secrets launch binding v1\n" + digest + "\n" + fingerprint). `RequestFingerprint.Compute` is unchanged, so all fingerprint values and existing tests are unchanged.
6. Tests: `tests\WithSecrets.Tests\LaunchContractTests.cs` (suite `LaunchContract`, 283 checks): golden vectors (canonical text and digest, the digest computed independently with Python hashlib), member-order and escape independence, one digest-change test per field via reflection (plus a field-count guard so a new field forces a decision), validation (version, expiry, future creation, lifetime, ids, names, pairs), strict parsing (unknown, missing per field, duplicate, wrong types, trailing text), no-secret-value reflection test, binding tests, result golden vector and strict parse.
7. Mutation evidence (each applied then reverted): (a) removing `workingDirectory` from `Canonical()` failed golden canonical, digest, round trip, order tests; (b) disabling the version check in `Validate` failed "newer protocol version is rejected", "protocol version 0 is rejected", "version mismatch parses then rejected"; (c) adding `string? PlaintextValue` to `LaunchResult` failed "not named like a secret value" and "carries only the outcome, exit status and public text".

No production code path calls the contracts yet; Phase 0 only adds them (no behaviour change). Existing tests are unchanged apart from registering the new suite in `Program.cs`.

## Phase 1: local host service and shared API (done, pending review)

Baseline (step 0, LF checkout, before any change): full suite 3105 passed, 0 failed; E2E ALL PASSED (12 scenarios, 57 s). The Phase 0 CRLF failures are gone.

Result: build `dotnet build with-secrets.slnx --no-incremental` 0 warnings, 0 errors; full suite 3218 passed, 0 failed; E2E ALL PASSED (12 scenarios, 57 s, now through the service). Real exe: a run with no service prints the one-line message and exits 6; `service --port 0` exits 2.

### What was built

- `HostService.cs`: `HostService.Start(HostServiceOptions)`, a Kestrel front on 127.0.0.1 and [::1] (port 0 for tests; IPv4 only where IPv6 cannot be held). Routes: `GET /v1/status` (`{"protocolVersion":1}`), `POST /v1/launch` (body: canonical `LaunchRequest` JSON; header `X-Request-Digest`; optional query `pagePort`), `POST /v1/launch/{id}/cancel`. Checks: Host must be localhost/127.0.0.1/[::1] (421), no Origin header (403), content type application/json (415), body at most 1 MB (413) and read within 15 s (408, a race against a timer because a stalled stream may ignore its token), strict parse (400), digest equals the digest of the parsed request (400), `Validate` (version, expiry, ids; 400), request id not used before (409). Response: NDJSON events.
- `LaunchEvents.cs`: `approval {link}`, `output {stream,text}` (redacted by the service), `result {outcome,exitCode}`; strict reader.
- `LaunchGate.cs`: lock plus integer revision, `Invalidate()`, `TryCommit(expectedRevision, cancelToken, commit)`. A launch reads the revision when it is accepted.
- `ChildProcess.cs`: `ChildRunner.Prepare` builds the environment without starting (inherited block of the request, denylist, ordinary values, secrets) and returns a `PreparedChild` with `Start`, `Discard`, `WaitAsync`. `RunAsync` is now Prepare/Start/Wait (same behaviour).
- `RunCommand.cs`: the middle of the old run is one body (`RunPlan`) used by the old in-process entry (`ExecuteAsync(RunArgs, dir)`, still used by the existing tests) and by the new service entry `ExecuteAsync(LaunchRequest, LaunchContext)`. The service entry re-validates the request (`LaunchRequest.Validate`, `EnvDeclarations.FromRequest`), resolves the program against the PATH carried in the request, checks `LaunchRequestBinding.Mismatch` against the approval, decrypts only if the launch is not cancelled, prepares the child, then commits through the gate. The loser of the race discards the prepared environment, writes audit `finished` ("cancelled before the program started") and ends `Cancelled` (exit 3). `RunCommand.Outcome` tells denied, failed, cancelled or exited, because a child may exit with any code.
- `EnvDeclarations.FromRequest`: service-side re-validation of the plan (file count and full paths, pair count, variable grammar and length, protected variables for every pair, ordinary count, length, NUL and code-loading, no variable twice, listed ordinary names equal to the values) and recomputation of the file link marks.
- `LaunchClient.cs`: the CLI side. The .env is read once (same `Compose`, same messages); it sends the request, prints the link line `Approval needed. Ask the person to open: <link>` (`WebApprover.LinkPrefix`), writes output to stdout and stderr, and ends with the reported exit code. No service: `ServiceNotRunning` = 6 and the one-line message.
- CLI: `with-secrets service [--port N] [--debug]` (foreground, Ctrl+C stops), `--service-port N` for a run, `WITH_SECRETS_PORT`; a run no longer opens state.db or the store. `CommandWiring.Run` was replaced by `CommandWiring.RunApprover` (used by the service).
- Contract change: `LaunchRequest` has a 15th field `InheritedEnvironment` (`inheritedEnvironment` in JSON, last member, sorted by name) bound into the digest. Golden canonical text and digest updated in `LaunchContractTests` (digest computed with Python hashlib over the exact text).
- Tests: `tests\WithSecrets.Tests\HostServiceTests.cs` (suite `HostService`, alone with `WS_ONLY=HostService`); E2E `Flows.Run` starts an in-process `HostService` per run and uses `LaunchClient` (the page port is the harness port, sent as `pagePort`).

### Decisions made (inside the accepted design)

1. Default port 8765; `--port` for `service`, `--service-port` for a run, `WITH_SECRETS_PORT` for both. No stored setting: a new setting would change the signed manifest and schema, which the task forbids.
2. New exit code 6 "host service not running" (2, 3, 4, 5, 127 were taken). Documented in README and architecture section 9.
3. The digest travels in the header `X-Request-Digest` (the body stays exactly the canonical `LaunchRequest`). The `--port` of a run (the approval page port) travels as `?pagePort=N` (the only query accepted), so `--port` on a run keeps working.
4. The inherited environment is a request field (non-secret by assumption, in the digest). The child gets exactly that block (minus the denylist) plus ordinary values plus secrets; nothing of the service's own environment. The program is resolved against the PATH and PATHEXT in the block.
5. The service applies the protected-variable rule to every pair, including `--secrets NAME` pairs whose variable equals the name (the old CLI path applied it only to `.env` references). The result is stricter only for a secret named like a code-loading, PATH or proxy variable.
6. Ordinary variables that are code-loading in a request are refused, not dropped (the CLI already drops them with a note before sending).
7. A request id may be used once; seen ids are kept until their expiry. The request lifetime is checked on receipt, not at the commit (the approval wait can exceed it).
8. Client disconnect or the cancel route sets the cancellation token. An open page stays open until its time limit (the approver has no cancel token); a later approval then ends as cancelled with nothing decrypted. After the commit a disconnect does not touch the child; the service drops output it can no longer send.
9. The service re-reads settings (`ApprovalSettings.Load`) per launch; a damaged settings row is exit 4 with the usual hint.
10. The final audit row of a cancelled launch is `finished` with detail "cancelled before the program started".
11. Docker: nothing added. A program named `docker` is launched like any other; the test uses a stand-in `docker.cmd` that records its arguments and its environment.

### Tests added (HostService suite)

Gate unit checks and a 3000-race stress (commit first or invalidation first, never a mix); request rejection (bad and missing digest, body changed after the digest, version 2, expired, unknown field, over 1 MB, Host `evil.example` and `127.0.0.1.evil.example`, content type, Origin header, reused id, unknown query, GET on launch, no secrets route, slow body over a raw socket) and that no refused request reached the approver; child environment (value only in the child env and never in events or arguments, request block inherited, service-only variable absent, code-loading and dotenvx key dropped, pair mapping, PATH from the request); redacted streaming (a secret split over two writes, output streamed while running); exit pass-through (7), unknown secret (2), not found (127), policy (2), protected names, ordinary code-loading, names mismatch, relative env file, too many pairs; denial and approver exception decrypt nothing and start nothing; cancellation (client disconnect, explicit cancel, cancel after prepare discards the environment, audit row); invalidation (before the commit: cancelled and discarded; after the commit: the child runs to its exit code 5; a 25-launch stress loop with random invalidation timing); canary scan of every body and event (plain, base64, hex, URL forms); two clients at once (approvals open together via a barrier); Docker stand-in; approval over real HTTP with `TestAuthenticator` through the service (page shows names only, approve gives exit 4 with redacted output and one decrypt, a stranger key is denied with zero decrypts); client (not running gives exit 6 and the exact line, output and exit pass-through, unknown secret, no secrets named) and command line (service, --service-port, port resolution).

### Mutation evidence (each applied, suite run, reverted)

1. `LaunchGate.TryCommit` without the revision check: failed "gate: a launch that began before an invalidation does not commit", "gate stress ... (1002 wrong ...)", "invalidation: an invalidation before the commit cancels the launch and discards the prepared environment".
2. The digest comparison in `HostService` made always true: failed "request rejection: a digest that is not the digest of the body is refused", "... a body changed after its digest was made is refused", "... no refused request reached the approver".
3. The Host header check removed: failed "a Host that is not a loopback name (DNS rebinding) is refused", "a name that only starts like a loopback address is refused", "no refused request reached the approver".

### Fix round 1 (security review of Phase 1)

- H1: the inherited environment is bound into the approval fingerprint (hash of sorted name=value, `EnvironmentBinding`), into `LaunchRequestBinding.Mismatch`, shown on the page as one line (count plus NAMES on the protected/code-loading lists, proxies, CA bundles, HOME, PSModulePath, npm_config_*, GIT_CONFIG_*, JDK_JAVA_OPTIONS, CORECLR_*, COR_*), and recorded in the audit row as a 12-character hash prefix only. The service computes it itself. The extra names are shown, not stripped (they were not stripped before this phase); the existing strip is unchanged. A request without an environment (the legacy path) has an unchanged fingerprint.
- H2: no code change; stated in README and architecture 10.2. **Phase 3 requirement:** grants/saved approvals must be unusable by other OS users (the API has no caller identity).
- M1: not changed. **Phase 2 requirement:** the CLI must authenticate the service (and the service the CLI) with the machine identity; until then the CLI sends its environment to whatever holds the port (the client still sends the whole environment; stripping `DOTENV_PRIVATE_KEY*` client-side was not done because the child strip already covers it and the block is bound into the approval).
- M2: after the commit, the client's own cancel (disconnect or cancel route) kills the program and its process tree (`Process.Kill(true)`); authorization invalidation does not. The child is started with `CreateNoWindow` so on Windows it has its own console and Ctrl+C in the service window does not reach it (not testable here; no effect on other platforms, where it is documented only). Test: a 40 s stand-in is gone within seconds after a disconnect or a cancel.
- Lows: expiry, revision and cancellation are re-checked before decryption and inside the gate commit (`LaunchContext.StaleReason`, `TryCommit(..., stillValid)`); client request lifetime is now 10 minutes; a cancel after approval writes `finished`/`denied` rows; try/finally Discard between prepare and commit; an exception after the start is reported as failed (exit 4, "may have run"), audited, and kills the child; a start failure is outcome failed; at most 8 concurrent launches (503); `IApprover.Request(request, CancellationToken)` (default interface method) and the page approver closes its page when cancelled; PATH and Path together refused on Windows; the working directory must be a full path to an existing folder; the service stops accepting and cancels in-flight launches on shutdown.
- Tests: `FixRound1` in `HostServiceTests` (suite HostService, 233 checks).

### Later work (not in this phase)

- The human commands (`--config`, `--set`, `--remove`, `--enroll`, `--unenroll`, `--recover`, `--rotate-key`, `--revoke`, `--audit`, `--list`, `--enrolled`, `--needs`) still open state.db in the CLI process; their pages are served by the CLI today. Moving them behind the service is later work.
- Windows service/SCM installation, start at logon, service account (Phase 6, Task 16). The service runs in the foreground console.
- Production callers of `LaunchGate.Invalidate()` (Phase 2 and 3): the gate has the method and tests; nothing calls it in production yet.
- Cancelling an open approval page when the client leaves (needs a cancellation token in `IApprover`).

### Concerns

- The service listens on a fixed local port with no caller authentication (accepted design): any local process that can reach loopback can submit a request, which still needs a passkey approval; it can also hold approval pages open until their time limit.
- The CLI's environment block travels to the service and is bound into the digest; it is shown nowhere and not recorded in the audit row (the audit row is unchanged). It is treated as non-secret.
- If the service is stopped while a launch runs, the child is not stopped (nothing touches the child after the commit); its output is lost.

## Phase 2: machine identity and local authority (done, pending review)

Result: `dotnet build with-secrets.slnx --no-incremental` 0 warnings, 0 errors; full suite 3499 passed, 0 failed; E2E ALL PASSED (57.7 s). New suites (alone with `WS_ONLY=Identity`, `WS_ONLY=Authority`, `WS_ONLY=Admin`): `IdentityTests.cs`, `AuthorityTests.cs`, `AdminTests.cs`; shared fixture `TestMachine.cs` (software keys; a machine is made Trusted through `AdminActions.ApproveMachine`, the code the admin command runs after the passkey tap, never through a shortcut in the program; E2E uses `E2EMachine.cs` the same way).

### What was built (`src/WithSecrets.Core/Authority/`)

- `Keys.cs`: `ISigningKey`, `KeyIdentity` (fingerprint = upper-case hex SHA-256 of the canonical SPKI, display in groups of 4, strict hex parsing, canonical P-256 check, verify), `SoftwareSigningKey` (tests), `CngSigningKey` (non-exportable, Platform Crypto Provider first then Software KSP, fixed key names).
- `AuthorityProtocol.cs`: `MachineRequestEnvelope` (launch request + fingerprint + host name, signed by the machine key), `AuthorityResponse` (canonical JSON, signed by the authority key, strict `TryParse`), `EnrollmentRequest/Result`, `KeyTransition`, `PendingInvalidation`, `IAuthority`. Domain-separation prefixes on every signed message.
- `AuthorityStore.cs`: `authority.db` (schema 1, WAL, one transaction per operation, fault-injection points, "delete authority.db" on another schema), the status table, history and audit rows, `processed_requests`, key history, pending invalidations.
- `LocalAuthority.cs`: `AuthorityKeyRing`, `LocalAuthority` (decision, in-flight sharing, enrollment challenges, transitions, invalidations). `HostAuthorization.cs`: verification before any decryption. `HostConfig.cs`: `host.json`. `LocalDeployment.cs`, `ServiceStartup.cs`, `AdminCommand.cs`.
- Edited: `RunCommand.cs` (the page and saved-approval branches go through `HostAuthorization`), `HostService.cs` (`/v1/identity`, invalidation pump, deployment option), `LaunchClient.cs` (identity check, exit 7), `CommandLine.cs`, `CommandWiring.cs`, `src/WithSecrets/Program.cs`.

### Phase 2 fix round 1 (security review `task-p2-review.md`)

Fixed: **H1** a saved approval is tied to the machine's security revision: the host remembers (in memory only) the revision under which each saved approval was made, honours it only while that revision is current, and clears the host's notes and the `GrantStore` when a newer revision is learned or an invalidation is applied (before the acknowledgement); after a service restart no saved approval is honoured (nothing is persisted, as 10.2 says). **M1** `CngSigningKey.OpenOrCreate` refuses an existing key that is exportable, not signing or not P-256; rotation and recovery make a fresh key (`CreateFresh`, which first deletes whatever holds the not-yet-recorded generation name). **L1** `approve-host-change` applies only the host name that the page showed. **L2** `admin approve` on a Trusted machine says on the page that it only re-pins the authority key, and `PinLocal` first opens the key store's key (it must be the one authority.db names). **L3** the typed full fingerprint was already compared with the machine's real fingerprint (the selector is the record's fingerprint); documented in the code. **L4** an exception while verifying an answer is a denial and the unlock material is zeroed. **L5** `/v1/identity` answers at most 4 at a time, otherwise 429. **L6** the rotate/recover pages read the active key from authority.db and create nothing before the tap.

Documented only: **L7** a running service learns of an invalidation through the 1 s poll (and before each launch); a launch whose Approved answer was committed just before `admin disable` may still commit within that window. **L8** two service instances on one `authority.db` can both show a page for the same request id (the first committed answer wins, the result stays correct); one service per store is assumed. `authority.db` has no integrity protection and keeps no copy of the admin assertion (same-user trust limit); a remote authority must store and verify the admin assertion with each transition.

**OPEN item for the maintainer (M2, not fixed on purpose): relay of `/v1/identity`.** The CLI's service check is not bound to the launch request: an impostor that holds the configured port can forward `/v1/identity` to the real service (on another port), then read the full launch request and environment on `/v1/launch` and answer with its own link and output. Options: a channel-bound handshake (ephemeral ECDH, the service's identity signature over the transcript, then an AEAD launch body, i.e. request encryption to the identity key), or at least a service signature over `challenge || H(launch body)` returned before anything is printed. Until decided, exit 7 does not defend against an active relay.

### Decisions made (inside the accepted design)

1. One process, one interface: the host and the local authority talk only through `IAuthority` and signatures, as a remote authority will. The approval page is offered to the authority through `LocalAuthority.Offer(requestId, digest, present)`, local only; the unlock material the page releases goes from page to host, never in a response.
2. Bumps: only Trusted to Disabled and Trusted to Untrusted raise the revision (as the architecture table says); Untrust from Pending or Disabled is allowed and changes nothing else; a rename and a host-name approval keep the revision.
3. The authority decision, the machine status and revision it saw, the `processed_requests` row and the audit row are committed in one `BEGIN IMMEDIATE` transaction; the status is re-read inside it.
4. Response lifetime 60 s (host rejects more than 5 min, an issue time in the future beyond 1 min skew, an expiry, a stale revision). A newer revision than the host knew clears the `LaunchGate` and refuses that launch once ("authorization changed, ask again"), the next starts from the new revision.
5. Key rotation: signed `KeyTransition` chain; the host applies it by itself only if the pinned key signed it. Recovery: no transition; `admin recover-authority` (page + admin tap) pins the new key for this machine; other hosts re-enroll. A bug found by the rotation test and fixed: the transition's signed creation time was not the stored one (stored chain never verified); the store now keeps the signed time.
6. Admin commands are terminal-only (`NeedsTerminal` includes every admin action, `machines` too); `machines` needs no passkey, every other action needs the page and an admin passkey tap; `trust` needs the full 64-digit fingerprint; others accept a prefix of 12 or more digits. The page text (signed by the passkey) names the action, the full fingerprint, host name, name and state; a change against a machine that changed meanwhile is refused (expected revision).
7. The CLI authenticates the service (POST `/v1/identity`: signature over a fresh challenge by the machine key; fingerprint must equal the one in `host.json`), before the launch request is sent. New exit code **7** (`LaunchClient.ServiceNotAuthenticated`); a refused connection is still 6. `LaunchClient.RunAsync` now takes a required `ServiceTrust`. No client credential.
8. `with-secrets service` and `admin` (except `machines`) refuse on non-Windows (CNG).

### Residual risks and limits (also in README and architecture 10.2)

- The identity check is not channel-bound: an impostor that relays to the real service could still read the request the CLI sends.
- `host.json` and the key store are within the same-user trust limit.
- An exact request replayed after a service restart within 60 s gets the stored Approved answer, but the host has no approval of its own, so it denies (fails closed).
- Remote mode will need approval-page content (script contents) that is not in `LaunchRequest` (Phase 5). The envelope has no `TryParse` yet (Phase 5).
- Retired authority private keys are not deleted. The real `with-secrets service` was not run in this session, to avoid creating the production-named CNG key; CNG tests use their own key names and delete them.

### Mutation evidence (applied, run, reverted)

(a) Host skips the response signature check: the `Authority` suite fails 9 of the tamper checks. (b) Authority treats a Pending machine as allowed: "a Pending machine (pinned) is denied..." fails. (c) Disable no longer raises the revision: 10+ checks fail (revision stays 1, grants and invalidations, "a newer revision clears the host's state").

## Phase 3: grants, offline lease, startup reconciliation (done, pending review)

Result: `dotnet build with-secrets.slnx --no-incremental` 0 warnings, 0 errors; full suite 3696 passed, 0 failed (one check, the list of launch outcomes, needed `Approved` added; rerun of LaunchContract and GrantAuthority: 467 passed, 0 failed); E2E ALL PASSED (55.5 s). New suite `GrantAuthorityTests.cs` (alone with `WS_ONLY=GrantAuthority`). Brief: `.superpowers/sdd/2026-11-01-web-approval-passkey/task-p3-brief.md`.

### What was built

- `Authority/GrantProtocol.cs`: `GrantOps`, `GrantReasons`, `GrantEnvelope` (machine-signed use/approve request, domain "with-secrets grant request v1"), `GrantResponse` (authority-signed canonical JSON, strict `TryParse`, domain "grant response v1"), `GrantRecord`, `GrantAdminCommand`, `ReconcileEnvelope`/`ReconcileResponse` (the only carrier of the lease), `IMonotonicClock`/`SystemMonotonicClock`, `OfflineLease`.
- `AuthorityStore.cs`: schema 2 (grants rebuilt, `grant_events`, `processed_grant_requests`; schema 1 migrated in place); `ApplyGrant` runs one `BEGIN IMMEDIATE` transaction per operation (grant row, revocation notice, stored answer, audit row) with fault points; idempotent by request id.
- `LocalAuthority.cs`: `GrantAsync` (use, approve through the existing page via `Offer`), `AdminGrant` (extend, renew, revoke; expected revision), `ReconcileAsync`, notices. No operation bumps the machine's security revision.
- `Authority/AdminGrantCommand.cs`, `CommandLine.cs`, `CommandWiring.cs`, `src/WithSecrets/Program.cs`: `approve COMMAND`, `admin grant list|extend|renew|revoke ID` (terminal-only; page and admin tap like the machine commands; list needs no tap).
- `HostAuthorization.cs`: synchronized grants, the lease (`no-lease` deny code, same path in local mode), startup `ReconcileAsync`, revocation notices (drop, `gate.Invalidate()`, acknowledge), `TryUseGrantAsync`, `ApproveGrantAsync`, held-key sweep. `HostService.cs`: `/v1/approve`, 503 until reconciled, default `HeldStoreKeyProvider`. `RunCommand.cs`: grant branch and `ApproveGrantOnly`. `StoreKeyProvider.cs`: `IStoreKeyProvider`, `TapStoreKeyProvider`, `StoreKeyHolder`, `HeldStoreKeyProvider`.

### Decisions (inside the design; 10.2 is silent unless stated)

1. **Scope key** is the host's request fingerprint key (names, resolved program, folder, `.env` plan, script hash, environment hash); opaque 64-hex to the authority, which also stores a description. Stricter than the brief's fallback; other arguments and the reason are not part of it (as for saved approvals).
2. **Lease** is issued only by a signed reconcile answer, default 15 minutes (`LocalAuthority.LeaseDuration`, provisional), measured on a monotonic clock from receipt, in memory only. Grant answers carry no lease. Offline use needs a synchronized grant, a valid lease and the grant's own wall-clock end not passed.
3. **Approve** needs the reuse setting on; the expiry is chosen on the page (10, 60, 240, 480 minutes, up to 1440); indefinite only by `admin grant extend|renew --indefinite`. Approve asks for no unlock (nothing is decrypted).
4. **Revoke** invalidates the gate for every unlaunched launch (the gate does not know which grant a launch used). Extend and renew have no push event; the host sees them on its next online use.
5. **Startup**: the service reconciles before listening; an unreachable authority gives 503 on `/v1/launch` and `/v1/approve` until the pump succeeds. An unpinned authority counts as ready (the run gets the normal denial).
6. **Maintainer decision on the blocker (see below):** the service holds the key after the first approving tap. What is held is the PRF output (a byte array that can be zeroed) that opens K; K is opened from it per run and zeroed there.

### Blockers requiring maintainer input: RESOLVED, one item open

The Phase 3 blocker ("how does a grant-based `run` obtain the store key K without a tap?") was decided by the maintainer: **the service holds the key in memory after the approving passkey tap for the grant's lifetime; runs under a valid grant need no further tap or approval.** Implemented as above (the seam `IStoreKeyProvider` stays; `HeldStoreKeyProvider` is the default). The held key is dropped and zeroed on: grant expiry, revoke, machine disable or untrust, security revision change, lease end, service restart (memory only), service stop, and every failed or refused run under a grant. It is never written to disk or logged; nothing else is cached. Options 2 to 4 of the earlier analysis (hold only the granted values, taps for every run, authority-held keys) were not chosen.

**Open item: cleaner mitigation, REVISIT later.** Holding the key weakens "K never rests in memory" (README, architecture 4 and 6): while a grant lives, a same-user process that can read the service's memory (or a debugger, a crash dump) gets the key material for the whole store, not only the granted secrets, and an indefinite grant makes that lifetime unbounded up to the lease/restart limits. Candidates for later: hold only the granted values re-encrypted under a random in-memory key (option 2), cap the held time shorter than the grant, require a re-tap after N minutes or N runs, or move the key to an OS-protected region.

### Other risks and limits

- `authority.db` has no integrity protection: a same-user process can insert a grant row (saved approvals self-verify with the passkey assertion; grants do not).
- The Phase 1 requirement "grants unusable by other OS users" is **not** implemented: the API has no caller identity. Idea for later: a Windows TCP-table owner-PID same-user check behind a seam.
- The grant scope excludes non-script arguments. A revocation cancels all pending launches. The lease default is provisional. The host persists no revision and fetches grants on demand, so a restart restores none.
- The held key is a PRF output: anything that can read the service's memory has it (same-user trust limit, as for secret values during a run).
- M2 (relay of `/v1/identity`) remains open, unchanged.

### Tests (suite `GrantAuthority`)

Parsing of `approve` and `admin grant` and `NeedsTerminal`; grant creation, no-time and refused approvals, use, scope mismatch, update, expiry, extend, renew, revoke (notice, pump, gate, acknowledge), idempotent retries, request id reuse; lease expiry, wall-clock jumps both ways, restart destroying the lease and synchronized grants, no lease means no secret use (even after a person's approval), an indefinite grant not extending the lease, extension not seen offline, reconnect reconciliation after disable and enable, startup 503 and ready; tamper and replay at the authority (signature, scope, operation, stranger key, host name, expired request, replayed envelope, reused id) and at the host (damaged signature, forged outcome, replayed answer, wrong key, late answer, wrong operation, changed lease); atomic faults (grant creation, revocation), concurrent approvals, v1 to v2 migration; the admin page flow (no answer, non-admin 403, tap applies, stale grant refused, prefix ids, list); service level through `Rig` (approve then run without a decision, scope variations, revoke, denied approve, seam refusal, offline lease). **Held key:** the first run taps, later runs under the grant need no tap and use the key, a failed run drops and zeroes it, revoke, expiry, disable, a revision bump, an untrusted check-in, lease end, restart and service stop each drop and zero it, a run is lent a copy and the held bytes are never zeroed by a run, a request outside the grant does not touch the held key.

### Mutation evidence (applied, suite run, reverted)

(a) `OfflineUse` ignores the lease: 5 checks fail (lease expiry fails closed, wall clock set back, indefinite grant beyond the lease, grant expiry offline, service lease). (b) The authority's `UseGrant` ignores the grant's end: "expiry: after its end the grant covers nothing" fails. (c) `SweepKey` no longer drops the key when the lease ends: "drop: when the lease ends the key is dropped and zeroed" fails.

### Phase 3 fix round 1 (review of 552dd9f)

- H1: grant scope key `GrantEvidence.Scope(machine, request fingerprint, full argument list)` (length-prefixed, domain "with-secrets grant scope v1"); the old saved-approval key is no longer used for grants. Test that asserted "other arguments do not change it" now asserts they do.
- H2: the held key is bound (`HeldKeyBinding`: grant id, scope, revision, end) at the tap and lent only to that scope; the host drops it when the synced grant differs. Grant rows carry the approver's passkey assertion (`StoredEvidence`, schema 3; schema 1 and 2 grants are discarded on migration), verified at each use by `GrantEvidence.RowProblem` against the manifest (`IApprovalVerifier`); extend, renew and revoke need an admin assertion over the new end (`AdminProblem`), checked in the transaction; a revoked row loses its evidence. Residual: whole-file rollback of authority.db; wall-clock based page-time windows (1 minute skew).
- M1: the key-holding tap page now has its own heading and a "KEY HELD" line (until the end, or restart for indefinite); the contradicting note is gone. L1: only a transport failure is "offline"; database errors deny. L2: use is evaluated every time, never stored or replayed. L3: an exception in check-in drops the lease and key. L4: pinned arrays, zeroed on drop (the array from the page's tap is the caller's and zeroed on dispose). L5: admin answers are verified (signature, id, digest), revision read inside the transaction. L6: processed answers pruned after 1 hour. L7: approve page headed "Create a GRANT".
- Mutation evidence (applied, GrantAuthority run, reverted): UseGrant skipping `RowProblem`: 7 checks fail; `Scope` ignoring arguments past the first: 1 fails; `Borrow` ignoring the scope key: 2 fail.

## Phase 4: durable audit trail (done, pending review)

Brief: `.superpowers/sdd/2026-11-01-web-approval-passkey/task-p4-brief.md`. New suite `AuditTrailTests.cs` (`WS_ONLY=AuditTrail`, 262 checks). Results are in the report `task-p4-report.md` (same folder) and under "Final verification" at the end of this file.

### What was built

- `Authority/AuditEvents.cs`: `AuditEventTypes` (authorization, launch, execution), `AuditFacts`, `AuditEvent` (canonical JSON, domain "with-secrets audit event v1", ECDSA P-256 by the machine key, P1363 like Phase 2; strict `TryParse`; `Problem()` shape checks), `AuditBatch` (+digest), `AuditAck` (authority-signed, an `ISignedAnswer`, valid 60 s), `AuditStatus`, `IAuditSink`, `AuditQuery`, `AuditHistoryRecord`, `AuditGap`, `AuditRedaction`.
- `Authority/HostAudit.cs`: `HostAuditOutbox` (`audit-outbox.db`, WAL, `synchronous=FULL`, schema 1, mismatch or damage = error naming the delete-it remedy; one write transaction = read counter, sign, insert, bump counter, so the sequence is monotonic and gapless and a failed commit uses no number), `AuditUploader` (batches of 50, removes an event only after a verified ack names it accepted/duplicate/expired; rejected ones are parked), `HostAudit` (`TryRecord` never throws and never waits for the upload; loop with a doubling pause up to 60 s, woken by each new event), `IHostAudit`.
- `AuthorityStore` is now `partial`; `AuthorityStore.AuditEvents.cs` adds schema 4 tables (schema 5 after fix round 1) (`audit_events`, `audit_machine_state`, `audit_gaps`, `authority_settings`; version 1 to 3 files are migrated in place, `IF NOT EXISTS`), `RecordAuditEvents` (one transaction: machine signature, shape, dedup by id, expiry, sequence tracking), gap shrink/split/reused, retention (`AuditRetentionDays`, `SetAuditRetentionDays`, `PruneAuditEvents`), `AuditHistory(AuditQuery)`, `AuditGaps`, `AuditHighestSequence`.
- `LocalAuthority` implements `IAuditSink` (acknowledgement signed only after the commit); `LocalDeployment.AuditSink` (tests can swap it, like `Link`); `HostAuthorization.VerifyAnswerAsync` reuses the pinned-key/transition/validity checks for the ack.
- `HostService`: creates the outbox beside `authority.db`, runs the upload loop (`AuditUploadInterval` 2 s, `AuditMaxBackoff` 60 s), passes `Audit` in the `LaunchContext`, waits briefly for the loop on dispose.
- `RunCommand` (service path only, `context.Audit != null`): authorization event (approved, granted + online/offline-lease + grant id, reused, denied with the authority's code, grant-approved for `approve`) is REQUIRED to commit before the store is opened: failure = exit 5 (`AuditError`), no decryption, no launch. Launch events (started; failed/cancelled with codes: files-changed, files-not-held, decrypt-failed, key-not-released, start-failed, not-committed, authorization-invalidated, cancelled, request-expired) and execution events (exited + exit code, or failed/internal-error) are best effort after the fact.
- CLI: `admin audit [--machine PREFIX] [--since T] [--until T] [--type T] [--outcome W] [--grant ID] [--folder S] [--text S] [--last N]` and `admin audit --gaps` (terminal-only, read-only, no passkey); help text; `CliCommand.AuditAdmin`, `CommandWiring.AdminAudit`.
- `ContractReader.Long` added. Test support: `HostServiceTests.Rig(auditInterval)`, `CountingStore.OnRead`, `GrantAuthorityTests.Chooser`/`Show` made internal, the Phase 2 schema message test now says version 4.

### Decisions (10.2 is silent unless stated)

1. **Old and new audit coexist (provisional).** The existing `AuditLog` (rows and hash chain in `state.db`) is unchanged and still written by every run (including runs through the service) and by the human commands; `--audit` is unchanged. The new signed host/authority trail is written in addition, only for runs through the service, with no hash chain and no export (10.2). The two are not merged or cross-checked. Why: 10.2 says nothing about retiring the old log, the human commands still open `state.db` in the CLI, and removing it would change a prototype security property (the exit 5 rule and `--audit`) outside this phase. Open for the maintainer: when the service owns all commands, whether the old log should be dropped.
2. **Which events gate a launch.** Only the authorization event must be committed before the launch (before any decryption). The launch and execution events happen after the fact (a launch outcome cannot be known before it); a failure to commit them is logged (exception type only) and the launch is not undone. Their numbers are not consumed when the commit fails, so the sequence stays gapless.
3. **Non-secret commands.** None exist on this path: `RunPlan` refuses a run without secret names (exit 2). So every run through the service is secret-bearing and fails closed; nothing was relaxed. A denial or a failure to record a denial is best effort (nothing runs either way).
4. **Argument redaction is a heuristic.** The host records the authorization event before it decrypts, so it cannot mask exact secret values; it masks values after secret-like names/flags, Authorization/Bearer/Basic/token values and URL passwords, cuts long arguments (512 chars, 256 arguments) and marks control characters. A secret typed bare into an argument is not recognizable (the agent is not given values). The old `state.db` rows still hold raw arguments (unchanged behaviour).
5. **Reason and outcome words** are codes (authorization: approved, granted, reused, denied, grant-approved; reasons: the authority's reason codes, online, offline-lease, saved-approval, grant-check-failed, cancelled, reuse-not-offered). Free text from a person, a program or the store is never recorded.
6. **Acknowledgement is signed** by the authority key (like every answer) so a forged ack cannot make the host drop its events; entries: accepted, duplicate, expired (older than the retention, acknowledged but not stored), rejected (kept apart in the outbox, never resent).
7. **Sequence handling at the authority:** the next number advances; a skipped range is a `missing` gap (shrunk, split or closed by late events); a number used by a second, different event is accepted and recorded as `reused`; nothing is ever rejected for a sequence reason. Expired events move the sequence but never record `reused` (they may be events the authority already pruned). A deleted outbox restarts the numbering at 1: the authority sees `reused` numbers.
8. **Retention** (authority setting, default 365 days, 0 keeps everything) removes only acknowledged events (all stored events are), on every upload and by `PruneAuditEvents`. Setting it needs a command with an admin tap: that is Phase 6 together with the admin web view; for now it is `AuthorityStore.SetAuditRetentionDays` (service-level API, audited in `audit_history`). The host's outbox has no pruning of its own: an unacknowledged event stays however old.
9. **Event time** is the host's clock when the event is made. The batch is not signed (each event is); the ack binds the batch id and a digest over event ids, sequences and signatures.
10. **Local authority mode and the sink:** the same `IAuditSink` interface a remote authority will implement; the local one is called in process. The uploader does not block launches.
11. **Timing choices (not security properties):** batch 50 sent / 200 processed, ack valid 60 s, loop interval 2 s with doubling to 60 s.

### Fix round 1 (review of fa93cbc: 0 High, 2 Medium, 7 Low)

- **M1** `AuditRedaction.Bound` (called by `HostAuditOutbox.Append`) cuts folder and program to 4096 characters with an "[N more characters omitted]" marker (no split surrogate pair) and bounds outcome, reason, request id, grant id and the arguments (256, 4096 each). `Append` also checks `Problem()` after signing and throws `AuditOutboxException` (fail closed, no number used) if an event would still be refused.
- **M2** Signed `epoch` member (random id in the outbox's `counter` table; outbox schema 2). The authority tracks `audit_machine_state` and gaps per (machine, epoch); an event can only fill a hole of its own epoch; the first event of a new epoch of a known machine records a gap of kind `epoch`; reuse inside one epoch is still `reused`. Authority schema 5; a schema 4 file is migrated by replacing the three first-cut audit tables (their events lack the epoch and cannot be verified in the new format; the feature was never released). Decision: the `epoch` gap stays open (visible in `admin audit --gaps`) because an outbox reset is something an administrator should see.
- **L1** `DrainAsync` catches every exception around `Pending`; `RunAsync` wraps each iteration (logs the type, backs off, continues).
- **L2** Expired events are still acknowledged without being stored (judged by the host's signed time), but the authority writes `audit-events-expired` (count, sequence range, machine) to its `audit_history`. Not done: rejecting or flagging event times far from the receipt time (decision for the maintainer).
- **L3** `approve` records an `approval-requested` authorization event BEFORE the tap and fails closed (exit 5); the result (`grant-approved` / `denied`) stays best effort. Decision: this adds one event per approve.
- **L4** Only final refusals are parked. `unknown-machine`, `machine-pending` and any status the host does not know leave the event pending (the drain reports failure so the loop backs off). The service logs a warning at start when refused events are kept in the outbox. Not done: showing the count in a CLI command.
- **L5** Redaction: quoted names (`{"password":"x"}`), `--user=NAME:PASS`, the value after `-u/-U/--user/--proxy-user` when it has `NAME:PASS`, and an attached `-pSECRET` (a few compiler flags starting with `-p` are left alone; `-p VALUE` and a bare `-u 1000` are not masked). Still heuristic.
- **L6** `--text` escapes the search text like the stored JSON arguments.
- **L7** `audit_events` is keyed by (fingerprint, event id); the duplicate check is per machine.
- Tests: `AuditTrailTests.Review` (the suite is now 290 checks). Mutation evidence: M1 (no `Bound`, no backstop): 4 failures; M2 (epoch ignored in `TrackSequence`): 4 failures.

### Known limits

- The outbox and `authority.db` have no integrity protection against a same-user writer; a compromised host can report untruthfully (10.2 says the protocol does not claim otherwise).
- Pending (not yet approved) machines produce denial events that cannot be acknowledged until the machine is approved and the authority key is pinned (the host cannot verify an ack without a pin); they wait in the outbox.
- `admin audit` reads `authority.db` directly (local authority); a remote authority will need the Phase 6 web view.
- Logs: warnings in the new code name only exception types; no test reads the rolling log file.

### Mutation evidence (applied, `WS_ONLY=AuditTrail`, reverted)

(a) The page path no longer fails the run when the authorization event cannot be committed: 4 failures ("fails closed ... canary decrypt count is 0", "next run ... numbered from 1", damaged outbox file, folder in place of the file). (b) The uploader ignores the result of the acknowledgement verification: 5 failures (replayed, wrong-key, other-events acknowledgements; the genuine one; the service-level wrong-key ack). (c) The authority no longer records a missing range: 6 failures (gap records, shrink/split/close, `admin audit --gaps`, end-to-end lost event).

## Phase 4b: authority lock, admin web app, sensitive operations (done, pending review)

Merged origin/main (e40d969, clean: its accepted text is kept verbatim; our boundary notes follow it). Maintainer corrections applied: lock, unlock and the unlock policy are NOT CLI verbs; they are done on the authority's admin web app, and `with-secrets admin` has no new subcommands (bare `admin` prints the app link and the public status).

### What was built

- `Authority/AuthorityLock.cs`: `AuthorityLock` (starts locked; `OnLock` discards), `UnlockPolicy`, `IUnlockProtection` with `DpapiUnlockProtection` (Windows, current user) and `NoUnlockProtection` (other platforms: the option is refused with a message), `UnattendedUnlock.TryUnlock`.
- Gates: `AuthorityKeyRing.LockState` (Current/Rotate/Recover refuse), `HostService` (423 on run/approve, `/v1/status` running+locked, pump idle, unlock then re-check-in), `HostAuthorization.LockState`/`Discard` (key zeroed, lease, grants, saved approvals, gate invalidated).
- `Authority/AdminAuthorization.cs`: `AdminAuthorizer` (one-use page with `Operation:`/`Parameter` lines; re-verifies admin signature, exact text, freshness, single use of the nonce; audits attempts and outcomes; fails closed, including when the audit cannot be written), `VerifiedAdmin` (single-use token required by `SetUnlockPolicy` and `SetAuditRetentionDays`), `IAdminAsker`/`TargetAdminAsker`.
- `Authority/AdminService.cs`: admin web app on the service port: `GET /admin` (status, mode), `GET /admin/audit` (read-only), `POST /admin/op` (unlock, lock, policy-manual, policy-unattended; same-origin only, CSP with nonce, no framing). Route table `AdminService.Pages` is the Phase 6 extension point.
- `AuthorityStore.Settings.cs`: unlock policy, sealed material and hash in `authority_settings`; `RecordAdminAttempt` (`admin-operation` audit rows).
- CLI: bare `admin` (`AdminAppCommand`), exit code 8 for a locked authority, service start prints the unlock mode (weaker one by name), the lock state and the admin page link.
- Docs: README (section "The authority lock and the admin web app"), architecture 10.2 current-implementation notes (lock, app, authorizer, audit table of sensitive operations, unlock mode, key hierarchy, backup and recovery procedure), exit code 8, file map.

### Decisions (the design leaves them open)

1. The lock is a process-level gate, not encryption: the authority key stays CNG-protected. Simplest mechanism that gates every secret path (the signing key is needed by every authority answer).
2. Lock itself needs a passkey tap (maintainer: each a fresh operation-bound tap). Killing the process also locks.
3. Unattended material is random 32 bytes sealed with DPAPI plus its SHA-256; it decides only whether to unlock. Weaker, documented.
4. Exit code 8 (7 was taken). Locked status is 423.
5. Test seam: `HostServiceOptions.Lock = AuthorityLock.UnlockedForTests()` (a library object; no command, setting or variable reaches it); `VerifiedAdmin.ForTests` for store-guard tests. E2E and the suites use the first.
6. `SetAuditRetentionDays` took an actor string with no proof (a gap): it now needs a `VerifiedAdmin`.

### Open items / limits

- The existing CLI admin verbs run in their own process, verify their tap there, and are not gated by the service lock; they move into the app later (then under `AdminAuthorizer`).
- Zeroing is best effort. Phase 4 audit is merged in this branch, so the authority audit history is the durable record.
- Key wrapping/backup of the authority key (non-exportable CNG) and a restore test on a second machine remain; the written procedure covers what exists.
- BLOCKER: none. Ambiguity noted: whether `Lock` should need a tap (implemented as the maintainer said).

### Tests and mutation evidence

Suite `AuthorityLock` (196 checks; `WS_ONLY=AuthorityLock`), plus new checks in `Admin` (every machine/key operation x non-admin key, no UV, other challenge, no answer, replay) and `GrantAuthority` (grant extend/revoke: no UV, other challenge, replay). Mutations applied, suite run, reverted: (a) `if (false && Lock.IsLocked)` in the run route: 4 failures (runs, approve, client exit 8, grant use while locked); (b) user-verified check removed in `WebAuthn.VerifyAssertion`: 7 failures; (c) unattended unlock applies lock/policy operations without a tap: 2 failures.

## Reconnaissance: who owns what today

| Responsibility | Owner today (file / type) | Notes |
|---|---|---|
| CLI parse, wiring, state/store open, grants | `src\WithSecrets\Program.cs`, `CommandLine.cs`, `CommandWiring.Run` | Builds `RunArgs` (secrets, reason, program, args, -f files), `WebApprover`, `GrantStore`, `RunCommand`. Stays in the CLI. |
| Request validation | `RunCommand.ExecuteAsync` (names valid/present, `Policy.Check`, `CheckExpanded`, `CheckBatchFile`, `CheckLength`, script exists/size/ASCII/BOM), `Policy.cs`, `SecretNames.IsValid` (Contracts.cs), `EnvDeclarations.Compose` | Interleaved with I/O (reads store names, .env files, script files). Service-side checks must repeat these on the received request. New `LaunchRequest.Validate` covers only the wire-level shape (version, ids, expiry, names, pairs). |
| Program resolution | `ProgramResolver`, `PathExpander` (ChildProcess.cs, Paths.cs) | Resolved path and expanded script are what the fingerprint covers; request carries the command as typed, service resolves. |
| Approval summary | `ApprovalSummary.BuildMessage`, `ScriptView` (ApprovalSummary.cs); `ApprovalRequest` (Contracts.cs) | Text the person reads and signs. Built from `ApprovalRequest`. |
| Fingerprint | `RequestFingerprint.Compute` (Reuse.cs); `RequestBinding` / `ReuseBinding` (Proof.cs) | Fingerprint = names, resolved program, folder, pairs/.env plan, script content. Challenge binds nonce + approval text (+ reuse minutes). |
| Approval UI and proof | `WebApprover.cs`, `OneShotServer.cs`, `PageFlow.cs`, `WebAuthn.cs`, `Proof.cs` | `IApprover.Request(ApprovalRequest)` returns `ApprovalDecision` (with `Unlock` = PRF release). |
| Grants (saved approvals) | `GrantStore` / `Reuse.cs` | Re-verifies the stored passkey assertion at every use. Not used when the store needs unlock (PRF stores). |
| Secret resolution / decryption | `ISecretSource.GetValues(names, Unlock?)` -> `SecretValues` (SecretStore.cs); `SecretCrypto`, `KeyVault` | Key K only from a passkey PRF release inside an approved run; bytes zeroed on dispose. |
| Environment construction | `RunCommand` (`injected` from `Mappings`) + `ChildSpec` (ChildProcess.cs) + `ChildRunner` (denylist vars, ordinary .env vars) | |
| Process launch | `ChildRunner.RunAsync` (ChildProcess.cs), `HeldFiles` (hold script open) | |
| Redaction | `StreamRedactor`, `RedactionVariants` (Redaction.cs); applied inside `ChildRunner` to stdout/stderr | Output is written straight to the CLI's stdout/stderr (`TextWriter`). |
| Audit | `AuditLog.TryWrite` (AuditLog.cs): rows approved/denied/reused/finished; failure to write = exit 5, nothing runs | Per-run rows in state.db; the target design (signed events, outbox, sequence numbers) is not built. |
| Exit status | `RunCommand` constants (2 usage, 3 denied, 4 store, 5 audit, 127 not found), else the child's code | |

### Extraction boundaries (not done in Phase 0)

- Future service interface, e.g. `ILaunchService.LaunchAsync(LaunchRequest, IOutputSink?) -> LaunchResult`. Behind it (moves out of the CLI): the validation block, `ProgramResolver`/`PathExpander` resolution, `ScriptView` reads, `RequestFingerprint`, `ApprovalSummary`, `IApprover`, `GrantStore` use, `ISecretSource`/`SecretValues`, `ChildRunner`, `StreamRedactor`, `AuditLog`.
- Stays in the CLI: argument parsing, `.env` composition into the request (`EnvDeclarations.Compose` produces the pairs/ordinary variables the request carries), printing `LaunchResult.Output`, mapping `LaunchOutcome`/`ExitCode` to the process exit code (Denied 3, Failed per `Detail`/code, Exited child code).
- `RunCommand.ExecuteAsync` is the seam: its middle (from "Policy.Check" to `ChildRunner.RunAsync`) is the service body; its head (store names, `.env` composition) and tail (exit code) are CLI. Output currently goes to `TextWriter`s; the service must return public redacted output as a stream or text in `LaunchResult` (`Output` is text for now; a streaming variant can be added without changing the digest, since the digest covers only the request).
- Redaction must run in the service (it holds the values); the CLI only ever sees redacted text. This is already true in structure (`ChildRunner` redacts before writing).
- The client chooses `RequestId`, `ClientNonce`, `Created`, `Expires`; they are inside the digest and the approval binding.

## Decisions made within the accepted design

- Request carries the command as typed (`Program`, typed `Arguments`), not the resolved path; the service resolves it, and the approval fingerprint (resolved path + script content hashes) is bound next to the digest by `LaunchRequestBinding`. Why: the fingerprint is the existing approval identity and must not change; the digest then covers what the sender asked for.
- `LaunchRequest.TryParse` does not judge the protocol version (so an unsupported version can be reported); `Validate` rejects it. `LaunchResult.TryParse` rejects another version directly.
- Lists keep the sender's order in the digest (argument order matters); only `envVariables` is sorted. Secret names order is therefore part of the digest although the fingerprint sorts them.
- `MaxLifetime` 10 min and `ClockSkew` 1 min are implementation choices (plan: values are not a security property); request id and nonce are `[A-Za-z0-9_-]` of length 1-64 / 16-128.
- Result carries one `Output` text (public, redacted) and a `Detail` reason; no streaming API yet.
- `ToolSettings.QuoteJson` added next to `Quote` rather than changing `Quote` (manifest/settings signatures).
- No IPC authentication, hash chain, broker or privilege separation (plan "Implementation notes").

## Code/doc differences found

- architecture.md 10.2 audit: signed per-machine events, outbox, sequence numbers. Code today: `AuditLog` rows in state.db without those. Not changed; target is for a later phase.
- README/architecture describe current behaviour; no conflict found that needed a doc change. The main working copy has uncommitted edits to docs and `src\WithSecrets.Core` (env declarations) that this branch does not contain; `EnvDeclarations.cs`, `SecretMapping` etc. here are the origin/main versions.

## Tests run and outcomes

- `LaunchContract` suite alone: 283 passed, 0 failed.
- Full suite and E2E: see "Final verification" below.

## Remaining work

- Phase 5 onward per `docs/implementation-plan.md` (Phases 1 to 4 are done, see above). Phase 6 owns the admin web view of the audit history and an administrator command (with a passkey tap) to set the audit retention. Open: the cleaner mitigation for the held key (REVISIT later), the same-user check for grants, the M2 relay. Phase 2 leftovers: wire the `service` startup of the real CNG key on a Windows machine by hand once; decide whether retired authority keys should be deleted.

## Blockers requiring maintainer input (Phase 3): resolved, see the Phase 3 section

(Kept for history; the maintainer chose option 1, with the cleaner mitigation left as an open item.)

**How does a grant-based `run` obtain the store key K without a passkey tap?**

- `docs/architecture.md` section 10.2 "Cache, grants, startup, and reconnection" says `run` "uses an applicable, unexpired grant without prompting", and secret values are "fetched on demand and cached in memory" (memory-only, destroyed on restart).
- Current behaviour (`docs/architecture.md` sections 4 and 6.3; `RunCommand.ExecuteAsync`, `ReuseOffer` is off when `store.NeedsUnlock`): K is released only by a passkey tap (WebAuthn PRF) inside an approved run, opened inside `GetValues`, zeroed, and never rests in memory between runs. A saved approval has no PRF output, so today a PRF store never offers or uses saved approvals.
- Undefined: where plaintext or K comes from for a run under a grant that has no tap. Options:
  1. The service keeps K (or the master key MK) in memory after the approving tap for the grant's lifetime. Simple; weakens "K never rests in memory"; the lifetime of K equals the grant (possibly indefinite) unless capped.
  2. At the approving tap, decrypt the granted secrets and keep the values in service memory (re-encrypted under a random service-memory key, or plain) for the grant's lifetime. Narrower than K (only granted secrets), still memory-resident; matches "values cached in service memory"; a restart destroys them and the next run needs a tap.
  3. Runs under a grant still need a tap (grants only skip the approval page/review, not the PRF release). Keeps the current key hygiene but then `run` is not prompt-free.
  4. Authority-held keys in remote mode (values fetched from the authority per run); does not answer the local-authority case.
- Phases 1 and 2 do not depend on this.

## Final verification

- `dotnet build with-secrets.slnx --no-incremental`: 0 warnings, 0 errors.
- Full unit suite: 3103 passed, 2 failed: "enroll: CSP is strict and the script has LF line ends" and "reuse page: the CSP hash is of the LF script as served". Both fail identically on the untouched base (checked with `git stash -u`, suites WebApproval and Reuse: 884 passed, 2 failed). Cause: this checkout has `core.autocrlf=true`, so page scripts embedded in the `.cs` sources have CRLF and the served script / CSP hash differ. Not related to Phase 0.
- E2E (`tests\WithSecrets.E2E`, real browser available): 12 FAILED in 245 s, all with the same browser console error "Executing inline script violates ... script-src 'sha256-...'" (CSP hash mismatch from the same CRLF cause). Not compared against the base run; same root cause as the two unit failures. Suggested fix for the environment: `git config core.autocrlf false` (or `input`) in this worktree and re-checkout, then rerun both. Not done here (config change outside the task).

### Phase 4 verification

- `dotnet build with-secrets.slnx --no-incremental`: 0 warnings, 0 errors.
- Full unit suite: 3890 passed, 0 failed (AuditTrail 262 checks). The CSP/CRLF failures noted above no longer occur in this run.
- E2E (`tests\WithSecrets.E2E`): ALL PASSED in 56.6 s.

### Phase 4 fix round 1 verification

- `dotnet build with-secrets.slnx --no-incremental`: 0 warnings, 0 errors. Full unit suite: 4069 passed, 0 failed. E2E: ALL PASSED.

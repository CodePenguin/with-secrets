# with-secrets implementation plan

This plan turns the accepted target design in [architecture.md](architecture.md#10-planned-not-built) into incremental, testable work. It is a build sequence, not a second architecture specification. If implementation exposes a genuine design conflict, update the architecture before coding around it.

## Starting point

- The current CLI prototype remains the behavioral reference for existing secret parsing, approval display, secret resolution, and child-process behavior.
- Section 10.1 describes accepted `.env` and Dotenvx integration work; it is related CLI work but does not block the host-service foundation.
- Section 10.2 is the accepted target for the host service, authority, machine identity, direct HTTPS/mTLS communication, grants, offline use, and audit.
- Task 16 (running the service under a separate OS account / privilege separation) remains explicitly out of scope for this plan.
- Keep each phase buildable and testable. Complete the local service boundary and shared protocol before implementing direct remote-authority communication.

## Phase 0 — Extract contracts and preserve current behavior

**Goal:** Make the current behavior reusable behind a service boundary without changing user-visible semantics.

- Identify the core request validation, approval summary, secret resolution, redaction, and child-launch responsibilities currently owned by the CLI.
- Define shared request/response contracts for a launch request and its result. Keep the protocol backend-agnostic; do not put local-vs-remote branching in the CLI contract.
- Define canonical serialization and request-digest inputs used to bind approval to the exact launch request.
- Add contract and regression tests around existing behavior before moving ownership.

**Exit criteria:**
- Existing CLI tests pass.
- Contract tests prove stable serialization, request binding, validation failures, and redaction behavior.
- No secret value is returned to the CLI as a separate API response.

## Phase 1 — Local host service and shared API

**Goal:** Move the trusted execution boundary into a Windows host service and make the CLI a client.

- Implement the loopback HTTP host-service API using the shared contracts.
- Move final request validation, approval coordination, secret resolution/decryption, environment preparation, process creation, output redaction, and exit-status handling behind the service boundary.
- Serialize final launch commit against local authorization invalidation. A launch cancelled before commit must discard its prepared environment; a child launched before a later invalidation continues unaffected.
- Keep secret values in service memory and the prepared child environment only.
- Have the CLI submit requests and stream/receive public, redacted output and the final result.
- Exercise Docker launches through the same host-side CLI/service path; do not add a container identity or secret volume.

**Exit criteria:**
- Windows CLI launches through the service and cannot independently retrieve secret values or make the final launch decision.
- Tests cover request rejection, approval, child environment construction, redacted output, cancellation-before-launch, launch-vs-invalidation ordering, and child continuation after launch.
- Local API access alone does not authorize secret use.

## Phase 2 — Machine identity and local authority

**Goal:** Establish the same authority and machine-identity model in a local deployment before adding networking.

- Generate and OS-protect the host service's ECDSA P-256 machine identity.
- Implement canonical public-key fingerprints and explicit enrollment/status transitions.
- Implement authority-created, single-use pairing invitations containing the authority URL, invitation identifier, 128-bit random code, and fixed expiration. Store only protected derived key material needed for HMAC proofs, never the plaintext code.
- Support the same pairing credential through a hidden interactive prompt or unattended protected input (environment variable or secret store, including Docker secrets). Never accept the code as a command-line argument or transmit it as part of the URL; never log it, expose it to agents, or inherit it into child processes.
- Implement local-authority mode with SQLite persistence for machine records, grants, security revisions, authority signing-key metadata, pairing invitations and their protected verifier material, audit history, idempotency records, and pending invalidations.
- Protect the authority signing private key and secret-data encryption/wrapping keys outside plaintext SQLite; keep protocol-signing and secret-encryption key purposes separate.
- Implement authority startup in a locked state by default. Require an explicit administrator unlock before serving secret-related requests; keep unattended startup unlock as a separate, explicit opt-in and do not let it bypass administrator authentication.
- Define and implement the authority's protected key hierarchy and platform-protection abstraction using the existing vault design as a reference. Validate the manual unlock ceremony, key wrapping, backup/recovery, and platform-specific limitations before treating any deployment mode as production-ready.
- Implement fresh, operation-bound passkey authentication with user verification for sensitive administrative operations, including administrator credential management, machine trust/status transitions, grant changes, secret/provider credential changes, security-setting changes, and authority key recovery/rotation.
- Ensure sensitive administrative operations fail closed when passkey authentication is unavailable or invalid; an unlocked authority or unattended-unlock mechanism is not an authentication substitute.
- Implement the admin approval path for pending machines and the authority-controlled grant decision path.
- Implement authority-issued signed responses and verify them at the host service.

**Exit criteria:**
- New machines are Pending and cannot access secrets until explicitly trusted.
- Pairing invitations are short-lived, single-use, atomically consumed, and idempotent across a lost response/retry; wrong, expired, consumed, and concurrent claims are rejected.
- Pairing invitation creation, refusal, expiration, consumption, and administrator approval are durably audited without codes or proof material.
- Disabled and Untrusted machines are denied; re-enabling starts clean.
- Machine identity and authority message signatures are verified by automated tests.
- Durable authority operations are atomic and idempotent across retries and simulated restarts.

## Phase 3 — Grants, approvals, and offline authorization

**Goal:** Complete the grant lifecycle and make online/offline behavior predictable.

- Implement `with-secrets approve COMMAND` as the normal request validation and human approval flow that creates or updates a scoped grant without launching the command.
- Implement `with-secrets run COMMAND` as normal validation plus use of an applicable, unexpired grant without interactive approval.
- Implement grant extension, renewal, and revocation as authority-controlled operations, each requiring fresh operation-bound administrator passkey authentication.
- Ensure ordinary use of an applicable, unexpired grant does not prompt for another approval or passkey authentication. Enforce grant scope and expiration independently from the finite offline-authorization lease.
- Implement authority-issued lease duration/expiration, monotonic-clock enforcement, and destruction of the in-memory lease on service restart. **[Superseded by task M4: the offline lease and offline grant use were removed; a host whose authority cannot be reached fails closed. Not built.]**
- Implement startup reconciliation and security-revision checks before accepting requests.
- Permit offline use only for already synchronized grants and locally available encrypted material; no new authority-dependent retrieval, approval, extension, or renewal while disconnected. **[Superseded by task M4: the offline lease and offline grant use were removed; a host whose authority cannot be reached fails closed. Not built.]**
- Ensure connected hosts apply authority changes immediately and offline hosts cannot benefit from changes they have not received.

**Exit criteria:**
- Tests cover grant creation, scope mismatch, expiry, extension, renewal, revocation, offline lease expiry, wall-clock changes, service restart, and reconnect reconciliation.
- An indefinite grant never extends an offline lease. **[Superseded by task M4: the offline lease and offline grant use were removed; a host whose authority cannot be reached fails closed. Not built.]**
- A host with no valid lease fails closed for secret use. **[Superseded by task M4: the offline lease and offline grant use were removed; a host whose authority cannot be reached fails closed. Not built.]**

## Phase 4 — Durable audit trail

**Goal:** Make every authorization attempt and grant use durably auditable without blocking normal operation on network upload.

- Add the host-local SQLite audit outbox.
- Persist a signed event before launching a secret-bearing child process.
- Record authorization decision, launch outcome, and execution outcome as distinct facts.
- Include event ID, per-machine sequence number, timestamp, machine identity, project/working directory, executable and redacted arguments, and grant ID when applicable. Do not record OS user identity or secret values.
- Upload asynchronously; retry until the authority durably acknowledges receipt.
- Verify signatures, deduplicate event IDs, and detect per-machine sequence gaps at the authority.
- Apply authority-controlled retention and expose searchable/filterable history in the admin web interface.
- Fail closed for secret-bearing launches if the local event cannot be durably committed. Non-secret commands may continue.
- Do not add a hash chain or audit export in this phase.

**Exit criteria:**
- Tests cover event signing, durable-before-launch ordering, duplicate delivery, retries, acknowledgements, sequence gaps, retention, redaction, and local outbox failure.
- A command cannot launch with secrets if its audit event was not durably committed.

## Phase 5 — Direct remote authority communication

**Goal:** Make remote-authority mode work without changing the CLI or shared local API.

- Implement direct host-to-authority HTTPS communication using TLS 1.3 mutual authentication and HTTP/2. Do not implement an application-level encrypted channel, relay, reverse tunnel, or multi-hop routing.
- Generate the persistent self-signed machine identity certificate from the existing ECDSA P-256 identity key, and include it in machine registration. Validate its public key, self-signature, CA constraints, key usage, and 10-year validity.
- Implement the authority-created, one-time pairing invitation flow. The invitation contains the authority URL, invitation identifier, and 128-bit random code as a local credential bundle; the code is never sent in the URL, command line, HTTP request, or logs. Support hidden interactive entry and unattended environment-variable/secret-store input, including Docker secrets, without exposing the credential to agents or child processes.
- Implement the pairing-only bootstrap: over TLS 1.3/HTTP/2, the client initially sends only the invitation identifier and fresh nonce. The authority returns its public identity certificate and a domain-separated HMAC-SHA-256 proof bound to the invitation, authority fingerprint, and fresh nonces. The client verifies the proof and certificate profile before sending any machine identity or registration data, then opens a new TLS connection pinned to that authority identity.
- Implement machine registration on the same single pairing route using the pinned authority connection, machine certificate structural validation, persistent-key proof of possession, and a domain-separated HMAC-SHA-256 proof bound to the invitation, machine fingerprint, host name, and fresh nonce. Consume the invitation atomically with Pending registration; make committed registration retries idempotent.
- Generate a separate in-memory ECDSA P-256 TLS key/certificate per running host-service instance. Sign the 24-hour temporary leaf with the persistent machine identity key; include the machine identity SAN URI; use the same leaf for client and server authentication; rotate one hour before expiry.
- Implement narrowly scoped custom-root certificate validation against the exact enrolled machine identity certificate or configured authority identity. Validate machine identity independently of endpoint hostname/IP. Do not disable certificate validation globally.
- Require TLS 1.3 and HTTP/2 with no downgrade. Disable TLS 0-RTT and session resumption initially. Keep healthy HTTP/2 connections persistent; do not impose maximum connection age or idle timeouts.
- Implement temporary certificate rotation without interrupting healthy connections. New handshakes use the new certificate; client connection pools rotate and old pools drain. Close active connections when machine trust is revoked.
- Enforce the machine API transport policy: no redirects or ambient proxies; no HTTP caching or conditional requests; no compression; UTF-8 JSON only; exactly one pairing-route exception to enrolled-client-certificate authentication; structured safe errors; fixed built-in request/concurrency/time limits appropriate for a development tool.
- Derive the authenticated caller identity only from the validated TLS client certificate. Authorize every request independently and perform the final current-state authorization checkpoint immediately before secret release.
- Implement direct reconnect to the one configured authority with bounded exponential backoff and jitter. Do not add authority fallback or automatic endpoint switching.
- Preserve canonical, versioned API contracts, request IDs, idempotent durable operations, and the existing durable invalidation delivery/acknowledgement protocol. Carry its existing messages over authenticated HTTP/2 long polling; do not redesign their payloads, sequencing, acknowledgements, retry/retention, duplicate handling, security-revision behavior, or host processing. Do not persist secret values to make release retries replayable; an interrupted release is not automatically retried.
- Retain signatures for durable authority-issued records and machine-signed audit events. Do not add signatures or custom encryption to every ordinary HTTP message. Keep machine identity, authority signing, and secret-data encryption keys separate.
- Reuse the same authority contracts and persistence model as local-authority mode.

**Exit criteria:**
- A host connects directly to its one configured authority using TLS 1.3 mTLS and HTTP/2; no relay is required.
- Tests cover identity certificate registration/validation, temporary certificate generation/rotation, SAN identity lookup, custom-root validation, hostname mismatch handling, TLS downgrade rejection, and mTLS enforcement on every route except the single narrowly scoped pairing route.
- Pairing tests cover authority-certificate substitution and machine-certificate substitution, wrong/expired/consumed codes, invitation replay and concurrent claims, idempotent retry after a lost registration response, Pending-record refresh, refusal to reset Disabled/Untrusted identities, fixed abuse limits, durable audit without codes, and rejection of every non-pairing request from an unknown certificate.
- Tests prove that the client sends no machine identity, host name, registration proof, launch request, environment, or other machine data before verifying the authority's certificate proof; test both interactive and unattended credential supply, including Docker secret input and non-inheritance into child processes.
- Tests cover persistent connection recovery, duplicate durable requests, interrupted secret releases, redirect/proxy rejection, no-cache/no-compression behavior, JSON/content-type enforcement, safe errors, and fixed resource bounds.
- Durable grants, authority trust transitions, pairing-invitation consumption, audit events, and idempotency state remain valid across connection loss and service restart.

**Progress (task M1, transport foundation; branch `impl/mtls-pairing`):**
- [x] Direct HTTPS, TLS 1.3 mutual authentication, HTTP/2 only; the relay, the custom handshake, AES-GCM sessions, relay wire layer and the 5b `--authority-fingerprint` pairing are removed.
- [x] Persistent self-signed identity certificate (profile per architecture 10.2: CA with path length 0, DigitalSignature and KeyCertSign, ten years) and strict validator; machine registration carries it (`machine_certificates`, additive table).
- [x] Per-instance in-memory TLS key, 24-hour temporary leaf signed by the identity key, rotation one hour before expiry, per-handshake selection, client pool rotation with a bounded drain.
- [x] Narrow custom-root validation in both directions (identity independent of address); unknown-but-valid certificates reach only the pairing route, which serves the pairing protocol (task M2).
- [x] Transport policy (no redirects or proxy, no-store, no compression, UTF-8 JSON, safe errors with correlation id, fixed bounds), GOAWAY then close on revocation, per-request authorization, final checkpoint before release.
- [x] Direct reconnect with bounded exponential backoff and jitter; idempotent retries under the same id; a release with a lost answer is not retried.
- [x] Existing invalidation and grant-event delivery carried by HTTP/2 long polling (one outstanding poll, no heartbeat); reconnect checks status and revision.
- [x] Tests: suites `Remote` (transport) and `RemoteLaunch` (CLI-level launches through the new transport); see `IMPLEMENTATION_PROGRESS.md`, "Task M1".
- [x] Pairing invitation flow, pairing-only bootstrap and proof, registration on the pairing route, credential supply (hidden prompt, environment variable, secret file, Docker secret), Pending refresh and abuse limits: **task M2** (branch `impl/mtls-pairing`).
- [x] Pairing tests and the "no machine data before the authority's proof is verified" tests: task M2 (suite `Pairing`, the pairing checks of `Api`, SPA tests, E2E `k1-spa-pair-machine`).
## Phase 6 — Admin experience, hardening, and platform integration

**Goal:** Complete the operational experience and validate real deployments.

- Implement the accepted administration SPA and API from architecture Section 10.5: React/TypeScript/Vite, responsive feature-based UI, OpenAPI-generated TypeScript client, same-origin `/api/v1/`, and WCAG 2.2 AA.
- Complete admin web views for machine management, provider instances and mounts, grant management, authority settings, locked/unlocked status, explicit manual unlock, opt-in unattended-unlock configuration, and searchable audit history.
- Enforce read-only browser sessions and fresh operation-bound passkey authorization for every administrative mutation at the API boundary; test direct API calls, replay, expiry, and parameter binding independently of the UI.
- Implement write-only provider credential entry and atomic replacement without exposing credentials in responses, logs, diagnostics, or telemetry.
- Integrate the Vite build into the .NET publish pipeline so the Windows host service serves the SPA and API from one origin and the release is one self-contained EXE with embedded frontend assets. Verify the artifact and matching frontend/backend versions.
- Validate that every sensitive administrative operation requires fresh operation-bound passkey authentication in both manual and unattended startup modes; validate that normal grant use requires no repeated passkey prompt.
- Exercise lock/unlock, restart, key zeroization best-effort behavior, key backup/recovery, and fail-closed behavior when authentication or protected key access fails.
- Validate machine rename/host-name change approval and authority signing-key rotation/recovery.
- Test Windows and WSL as independently enrolled host-service identities.
- Test Docker-launched commands through the host service.
- Add end-to-end tests with real browser/passkey flows and a direct remote-authority deployment.
- Document installation, enrollment, recovery, backup, offline behavior, and operational troubleshooting.

**Exit criteria:**
- The local-authority and remote-authority deployment paths both pass the end-to-end acceptance suite.
- Recovery and key-rotation procedures are exercised, not merely documented.
- Security-sensitive failure paths fail closed and produce auditable outcomes.

## Implementation notes

- Exact HTTP routes, DTO names, SQLite schema details, UI layout, concrete offline-lease policy values, and the specific platform key-protection adapters are implementation choices unless they change an accepted security property. Keep them simple and testable. Machine transport limits and timeout defaults are fixed built-in implementation constants, not user-facing settings or environment-variable overrides. Manual unlock is the default; unattended unlock is explicit opt-in. Sensitive administrator operations always require fresh passkey authentication, while routine use of a valid grant does not.
- Do not add caller-process identity, separate local IPC authentication, a hash chain, audit export, a message broker, or Task 16 privilege separation as prerequisites for the initial build.
- Prefer completing Phase 1 as a working vertical slice before broadening into remote networking. The local-authority path then provides a practical test harness for the same contracts used remotely.

### Task M4: retire the old AuditLog, remove the offline lease

- [x] The hash-chained `AuditLog` (state.db `audit` table, `--audit`) is deleted; every event it recorded is a signed audit event (type `admin` for administrative events; the run events were already signed). No migration, no hash chain.
- [x] Administrative changes commit their signed event inside the change's own `state.db` transaction, so a change whose event cannot be committed is not made.
- [x] `OfflineLease`, `ReconcileResponse.LeaseSeconds`, `LocalAuthority.LeaseDuration`, `HostAuthorization.OfflineUse` and the lease loop are removed; hosts fail closed when the authority is unreachable (`HostAuthorization.Vouched`).

### Task M7: Linux key file hardening, the listener without a restart, the blocked-run outcome

- [x] Linux key file checks: no links (file or folder), owner equals the running user, no group or other write on any folder from the key folder up to the store folder (sticky-bit folders accepted), exclusive (`O_EXCL`, `link`) and atomic (temporary file, `fsync`, rename) creation; a refusal is one line with the path and the fix, no stack trace, exit 4.
- [x] Linux process hardening: non-dumpable (`prctl`), best-effort `mlock` of key and PRF material (a refusal is one warning line), libc only, skipped on Windows; the key folder is to be excluded from backups (documented).
- [x] Copied-identity warning: 3 supersedes from different addresses within 10 minutes (fixed) record a warning in `authority.db`, one signed `admin` audit event and a Machines screen warning; nothing is disabled.
- [x] The machine listener starts when the first approval makes the authority signing key (no restart).
- [x] A run blocked on approval ends as approved, refused or timed out with a distinct outcome (exit 3 for both refusals, per the exit-code table; own sentence and reason code `approval-timeout` for a timeout).

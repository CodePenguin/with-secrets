# with-secrets implementation plan

This plan turns the accepted target design in [architecture.md](architecture.md#10-planned-not-built) into incremental, testable work. It is a build sequence, not a second architecture specification. If implementation exposes a genuine design conflict, update the architecture before coding around it.

## Starting point

- The current CLI prototype remains the behavioral reference for existing secret parsing, approval display, secret resolution, and child-process behavior.
- Section 10.1 describes accepted `.env` and Dotenvx integration work; it is related CLI work but does not block the host-service foundation.
- Section 10.2 is the accepted target for the host service, authority, machine identity, relay, grants, offline use, and audit.
- Task 16 (running the service under a separate OS account / privilege separation) remains explicitly out of scope for this plan.
- Keep each phase buildable and testable. Do not implement the remote relay before the local service boundary and shared protocol work.

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
- Implement local-authority mode with SQLite persistence for machine records, grants, security revisions, authority signing-key metadata, audit history, idempotency records, and pending invalidations.
- Protect the authority signing private key and secret-data encryption/wrapping keys outside plaintext SQLite; keep protocol-signing and secret-encryption key purposes separate.
- Implement authority startup in a locked state by default. Require an explicit administrator unlock before serving secret-related requests; keep unattended startup unlock as a separate, explicit opt-in and do not let it bypass administrator authentication.
- Define and implement the authority's protected key hierarchy and platform-protection abstraction using the existing vault design as a reference. Validate the manual unlock ceremony, key wrapping, backup/recovery, and platform-specific limitations before treating any deployment mode as production-ready.
- Implement fresh, operation-bound passkey authentication with user verification for sensitive administrative operations, including administrator credential management, machine trust/status transitions, grant changes, secret/provider credential changes, security-setting changes, and authority key recovery/rotation.
- Ensure sensitive administrative operations fail closed when passkey authentication is unavailable or invalid; an unlocked authority or unattended-unlock mechanism is not an authentication substitute.
- Implement the admin approval path for pending machines and the authority-controlled grant decision path.
- Implement authority-issued signed responses and verify them at the host service.

**Exit criteria:**
- New machines are Pending and cannot access secrets until explicitly trusted.
- Disabled and Untrusted machines are denied; re-enabling starts clean.
- Machine identity and authority message signatures are verified by automated tests.
- Durable authority operations are atomic and idempotent across retries and simulated restarts.

## Phase 3 — Grants, approvals, and offline authorization

**Goal:** Complete the grant lifecycle and make online/offline behavior predictable.

- Implement `with-secrets approve COMMAND` as the normal request validation and human approval flow that creates or updates a scoped grant without launching the command.
- Implement `with-secrets run COMMAND` as normal validation plus use of an applicable, unexpired grant without interactive approval.
- Implement grant extension, renewal, and revocation as authority-controlled operations, each requiring fresh operation-bound administrator passkey authentication.
- Ensure ordinary use of an applicable, unexpired grant does not prompt for another approval or passkey authentication. Enforce grant scope and expiration independently from the finite offline-authorization lease.
- Implement authority-issued lease duration/expiration, monotonic-clock enforcement, and destruction of the in-memory lease on service restart.
- Implement startup reconciliation and security-revision checks before accepting requests.
- Permit offline use only for already synchronized grants and locally available encrypted material; no new authority-dependent retrieval, approval, extension, or renewal while disconnected.
- Ensure connected hosts apply authority changes immediately and offline hosts cannot benefit from changes they have not received.

**Exit criteria:**
- Tests cover grant creation, scope mismatch, expiry, extension, renewal, revocation, offline lease expiry, wall-clock changes, service restart, and reconnect reconciliation.
- An indefinite grant never extends an offline lease.
- A host with no valid lease fails closed for secret use.

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

## Phase 5 — Remote authority protocol and relay

**Goal:** Make remote-authority mode work without changing the CLI or shared local API.

- Implement the mutually authenticated ECDH P-256 handshake, transcript-bound identity signatures, HKDF-SHA-256 session keys, and AES-256-GCM directional encryption using built-in .NET cryptography.
- Implement canonical, versioned application messages, session/sequence replay protection, unique request IDs, idempotent operations, and authenticated authority responses.
- Require HTTPS as an additional layer for externally hosted authorities.
- Implement the relay as an opaque in-memory router only; it must not inspect message types or payloads, store sessions, or make authorization decisions.
- Implement reconnect with fresh session keys and durable invalidation delivery/acknowledgement.
- Reuse the same authority contracts and persistence model as local-authority mode.

**Exit criteria:**
- Local host service can use a remote authority through the relay with no CLI protocol changes.
- Tests cover mutual authentication, key substitution, tampering, replay, out-of-order messages, reconnect, relay restart, duplicate requests, and invalidation delivery.
- Relay inspection reveals routing metadata only, never application message contents.

## Phase 6 — Admin experience, hardening, and platform integration

**Goal:** Complete the operational experience and validate real deployments.

- Complete admin web views for machine management, grant management, authority settings, locked/unlocked status, explicit manual unlock, opt-in unattended-unlock configuration, and searchable audit history.
- Validate that every sensitive administrative operation requires fresh operation-bound passkey authentication in both manual and unattended startup modes; validate that normal grant use requires no repeated passkey prompt.
- Exercise lock/unlock, restart, key zeroization best-effort behavior, key backup/recovery, and fail-closed behavior when authentication or protected key access fails.
- Validate machine rename/host-name change approval and authority signing-key rotation/recovery.
- Test Windows and WSL as independently enrolled host-service identities.
- Test Docker-launched commands through the host service.
- Add end-to-end tests with real browser/passkey flows and a real remote relay/authority deployment.
- Document installation, enrollment, recovery, backup, offline behavior, and operational troubleshooting.

**Exit criteria:**
- The local-authority and remote-authority deployment paths both pass the end-to-end acceptance suite.
- Recovery and key-rotation procedures are exercised, not merely documented.
- Security-sensitive failure paths fail closed and produce auditable outcomes.

## Implementation notes

- Exact HTTP routes, DTO names, SQLite schema details, UI layout, concrete offline-lease policy values, and the specific platform key-protection adapters are implementation choices unless they change an accepted security property. Keep them simple and testable. Manual unlock is the default; unattended unlock is explicit opt-in. Sensitive administrator operations always require fresh passkey authentication, while routine use of a valid grant does not.
- Do not add caller-process identity, separate local IPC authentication, a hash chain, audit export, a message broker, or Task 16 privilege separation as prerequisites for the initial build.
- Prefer completing Phase 1 as a working vertical slice before broadening into remote networking. The local-authority path then provides a practical test harness for the same contracts used remotely.

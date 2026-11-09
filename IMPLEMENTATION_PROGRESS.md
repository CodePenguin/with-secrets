# Implementation progress

Worktree `C:\Users\codep\Projects\with-secrets-impl`, branch `impl/host-service` (based on origin/main 03be52b). Plan: `docs/implementation-plan.md`. Architecture (`docs/architecture.md`) is authoritative.

## Current phase

Phase 0 (extract contracts, preserve behaviour): done, reviewed. Phase 1 (local host service and shared API): done, pending review. Next: Phase 2 (machine identity and local authority).

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

### Later work (not in this phase)

- The human commands (`--config`, `--set`, `--remove`, `--enroll`, `--unenroll`, `--recover`, `--rotate-key`, `--revoke`, `--audit`, `--list`, `--enrolled`, `--needs`) still open state.db in the CLI process; their pages are served by the CLI today. Moving them behind the service is later work.
- Windows service/SCM installation, start at logon, service account (Phase 6, Task 16). The service runs in the foreground console.
- Production callers of `LaunchGate.Invalidate()` (Phase 2 and 3): the gate has the method and tests; nothing calls it in production yet.
- Cancelling an open approval page when the client leaves (needs a cancellation token in `IApprover`).

### Concerns

- The service listens on a fixed local port with no caller authentication (accepted design): any local process that can reach loopback can submit a request, which still needs a passkey approval; it can also hold approval pages open until their time limit.
- The CLI's environment block travels to the service and is bound into the digest; it is shown nowhere and not recorded in the audit row (the audit row is unchanged). It is treated as non-secret.
- If the service is stopped while a launch runs, the child is not stopped (nothing touches the child after the commit); its output is lost.

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

- Phase 2 onward per `docs/implementation-plan.md` (Phase 1 is done, see above).

## Blockers requiring maintainer input (Phase 3)

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

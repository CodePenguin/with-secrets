# Implementation progress

Worktree `C:\Users\codep\Projects\with-secrets-impl`, branch `impl/host-service` (based on origin/main 03be52b). Plan: `docs/implementation-plan.md`. Architecture (`docs/architecture.md`) is authoritative.

## Current phase

Phase 0 (extract contracts, preserve behaviour): done, pending review. Next: Phase 1 (local host service vertical slice).

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

- Phase 1 onward per `docs/implementation-plan.md`. First step suggestion: add `ILaunchService` and an in-process local implementation wrapping the middle of `RunCommand`, driven by `LaunchRequest`, with the CLI calling it, behind tests that assert identical outputs and exit codes.

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

# Task M2 report (branch impl/mtls-pairing, worktree with-secrets-impl)

## 1. Implemented
Authority-generated single-use pairing invitations: admin API + SPA (create shown once, list status only, revoke; each with operation-bound passkey tap), `with-secrets pair` (hidden prompt, WITH_SECRETS_PAIRING_FILE, Docker secret path, WITH_SECRETS_PAIRING), bootstrap with authority HMAC proof verified before any machine data is sent, registration on a fresh pinned connection (possession proof + registration HMAC), atomic idempotent consume+register, Pending refresh, no reset of Trusted/Disabled/Untrusted, fixed limits, durable audit without codes, scrubbing of pairing variables from child environments. Docs: README, operations.md, architecture CURRENT text, progress, plan marks.

## 2. Files changed
New: Core/Pairing/{PairingProtocol,PairingClient}.cs, Core/Authority/{PairingService,AuthorityStore.Pairing}.cs, Core/Remote/PairingHandler.cs, tests PairingTests.cs, PairingAdminTests.cs, E2E ScenariosPairing.cs, SPA features/pairing/*.
Modified: AuthorityPairing.cs, Program.cs, CommandLine.cs, MachineListener.cs, HostService.cs, AdminService*.cs, AdminViews.cs, Api/*, LaunchClient.cs, ChildProcess.cs, AuthorityStore.cs, openapi.json, schema.ts, SPA operations/queries/App/Shell/MachinesPage/OperationDialog, test rigs, docs.

## 3. Tests
Pairing 198 pass; Api 602 pass; vitest 43 pass; E2E k1 pass; verify-all.ps1 all 5 stages passed (dotnet suite, frontend, publish, E2E rebuilt, no -nologo); build --no-incremental 0 warnings.
Mutation evidence: (a) client skips authority proof check: 5 FAIL; (b) known non-Pending machine not refused: 4 FAIL; (c) registration proof unchecked: 2 FAIL. All reverted.

## 4. Remaining gaps
E2E: the SPA-tap virtual authenticator clone has no PRF secret, so the E2E paired host reaches the authority's approval page and is denied there; a run that opens the secret is covered by RemoteLaunch (hosts now pair for real). No real WSL/two-machine run.

## 5. Deviations / provisional decisions (need maintainer confirmation)
`admin ADDRESS` replaced by top-level `pair`; known non-Pending machine refused without consuming the invitation; registration proof also binds authority fingerprint; extra list status `revoked`; throwaway client identity for bootstrap; creation requires a machine endpoint.

---

# Fix round 1 (M1/M2 review, task-m-review.md)

Commits on impl/mtls-pairing: 6a9e3f7 (M1 re-pairing), 2d50d12 (M2 per-peer limits), 07832ab (M3, M4, L1-L4 listener hardening and tests), 296317f (L5 secret-file permissions), 39ff0d9 (L6 renewal, L7 Reconnected removed), 7f83159 (L7 docs).

## 1. Implemented
- M1: `pair` against a different authority than the one the host trusts (remote identity, or a signing key pinned in local mode) is refused naming both identities, nothing sent, nothing changed; a person may confirm by typing `replace` at a terminal (unattended always refuses). Confirmed replacement drops the stale signing-key pin (host then pins the new authority's key) and writes the host audit event `pairing-authority-replaced`. Same authority keeps its pin.
- M2: global failure counter replaced by per-invitation limits plus a bounded per-peer-address limit (20 per 10 min, 256 addresses). It only turns away requests for unknown/ended invitations; a pending invitation is never locked out; the identical retry of a committed registration returns the committed result before any limit.
- M3: HTTP/2 keep-alive (30 s / 20 s), 256-connection cap, exactly one outstanding poll per machine (new supersedes old, old answered 409 superseded).
- M4: launch ids pruned by request expiry (+1 min), ceiling kept, live ids never reusable.
- L1: fixed 5 min skew on identity and leaf validity (leaves backdated 5 min); an established healthy connection is not cut at leaf expiry, a new handshake is refused.
- L2 connection table pruned on close. L3 transient failures (locked, internal-error) not remembered under an id. L4 grant re-checked at the final release checkpoint (authorization-changed; authority told not sent).
- L5: pairing secret file refused when other accounts can read it (Unix mode bits; Windows ACL: anyone but current user, SYSTEM, Administrators); Docker secret mount not checked; file is left in place and the command says so.
- L6: `renew-identity` operation: a Trusted host with under 30 days of identity-certificate validity makes a new certificate with the same key and sends it over the authenticated connection; authority validates against the key it holds, replaces the stored certificate, audits `machine-identity-renewed`; the host replaces its file only after acceptance. Checked at start and each reconnect. **Flag:** 10.2 does not say how the authority learns a renewed certificate; this mechanism is provisional.
- L7: README 501 text and architecture "64 KiB" (now 16 KiB) fixed; unused `RemoteAuthority.Reconnected` event removed (the host loop tracks reconnects itself); docs for limits, keep-alive, one poll, skew, re-pair confirmation, renewal, secret files.
- L8: new tests (below); recovery test strengthened (two requests, one new connection, one approval).

## 2. Files changed
src/WithSecrets.Core: Pairing/PairingClient.cs, PairingProtocol.cs; Authority/PairingService.cs, AuthorityPairing.cs, AuthorityStore.cs, HostConfig.cs, LocalDeployment.cs; Remote/MachineListener.cs, MachineCertificates.cs, PairingHandler.cs, RemoteAuthority.cs, RemoteWire.cs; HostService.cs; src/WithSecrets/Program.cs. Tests: PairingTests.cs, PairingRepairTests.cs (new), RemoteAuthorityTests.cs, RemoteFixTests.cs (new). Docs: README.md, docs/architecture.md, docs/operations.md, docs/implementation-plan.md, IMPLEMENTATION_PROGRESS.md.

## 3. Tests added / results
Pairing suite 216, Remote suite 225 (new: one poll, abandoned connection via black-hole proxy, launch-id pruning, skew and connection outliving its leaf, release checkpoint, transient failure, identity renewal, connection table), RemoteLaunch 215, whole .NET suite 4926+ passed. Mutation evidence (applied, suite run, reverted): poll supersede removed: hang/timeout; keep-alive off: 3 FAIL; launch-id pruning off: 1; live id reusable: 2; skew 0: 3 + crash; reclassify each request: 1; grant re-check off: 2; connection pruning off: 3; transient caching on: 1; renewal without same-key check: 3; secret-file check off: 2 (M1/M2 mutation evidence is from the earlier round and in IMPLEMENTATION_PROGRESS.md).
verify-all: see final line below.

## 4. Remaining gaps
- Unattended pairing by the host service is NOT BUILT (10.2 says the service consumes the credential at startup; the separate `pair` command does, also unattended).
- The authority's own identity certificate is not renewed or propagated to hosts.
- A host that runs ten years without reconnecting would not renew (checked at start and reconnect only).
- E2E does not cover remote secret release (virtual authenticator has no PRF secret); covered in-process by RemoteLaunch.
- Timing-sensitive tests under load: RemoteLaunch "two hosts ... shows the page" failed twice in one verify run and in two solo runs right after, then passed 12 of 12 times; E2E i4 and j1 failed once under verify-all and pass alone. No code cause found.

## 5. Deviations from the architecture
Unattended pairing by the service (above); renewal mechanism is provisional (10.2 silent); per-peer limits, 5 min skew, keep-alive values are fixed built-ins chosen by the implementer.

verify-all final: ALL STAGES PASSED (5): build 0 warnings, dotnet-tests, frontend, publish, e2e (E2E rebuilt, no -nologo). Last commit: "E2E: wait for the narrowed audit list itself" (i4-spa-audit-search had a status-line race that failed under load in two earlier verify runs; j1 dark-contrast failed once and passed alone and in the final run, cause not found).

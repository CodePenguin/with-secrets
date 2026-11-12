# Task M7 report

Worktree C:\Users\codep\Projects\with-secrets-impl, branch impl/mtls-pairing, base 56deebb. Local commits only:
e33910c (core and CLI), 24eca73 (Machines API, OpenAPI, Machines page), 21c79ed (tests), d04b707 (docs).
Note: e33910c alone does not compile (it uses MachineDto.CopyWarning, which is in 24eca73); the branch tip builds.

## 1. Implemented
- Linux key file hardening (FileSigningKey, LinuxHardening): key stays a 0600 file. Refuses (one line, path plus fix, no key material, exit 4) a key file or folder that is a symlink or not a regular file/dir, not owned by the running user, with group/other bits (file not 0600, folder not 0700), or any folder from the key folder's parent up to the store root that is group/other-writable without the sticky bit. Creation is O_EXCL temp file, fsync, link(2) no-clobber publish (race loser reads the winner's key), directory fsync. CreateFresh uses rename.
- Process hardening: PR_SET_DUMPABLE 0 in service and pair commands before key load; key and PRF buffers pinned and mlocked best effort, wiped after use; mlock refusal is one log warning, never a failure.
- Copied identity warning (CopiedIdentityWatch): 3 supersedes of a machine's poll from different addresses within 10 min record a warning (additive table copy_warnings, no schema version change) and one signed audit event admin / machine-identity-possibly-copied (max one per 10 min). Nothing is disabled. Shown on the Machines API (copyWarning) and as a notice on the Machines page; hidden once the machine is Disabled.
- Listener without restart: AuthorityKeyRing.KeyRecorded starts the machine listener when the first key is recorded; the CLI prints a line.
- Blocked-run outcome: approval timeout has its own reason code approval-timeout, own sentence ("Nobody answered before the approval time limit ... run again."), own audit reason, distinct from user-denied.
- Docs: README, docs/operations.md (Linux host hardening, exit codes), docs/architecture.md (new "Task M7 current implementation" paragraph; design text untouched), IMPLEMENTATION_PROGRESS.md, docs/implementation-plan.md.

## 2. Files changed
Core: Authority/FileSigningKey.cs, Authority/LinuxHardening.cs (new), Authority/AuthorityStore.cs, AuthorityStore.CopyWarnings.cs (new), AuthorityPairing.cs, AuthorityProtocol.cs, AdminViews.cs, Api/AdminApi.OpenApi.cs, HostAuthorization.cs, LocalAuthority.cs; Remote/CopiedIdentityWatch.cs (new), MachineListener.cs, RemoteAuthority.cs, AuthorityLaunchHandler.cs; Contracts.cs, HostService.cs, KeyVault.cs, RunCommand.cs, WebApprover.cs; src/WithSecrets/Program.cs. Frontend: api/schema.ts, MachinesPage.tsx, test/fakeApi.ts, views.test.tsx. docs/api/openapi.json. Docs as above. Tests: HardeningTests.cs, BlockedRunTests.cs (new), Program.cs.

## 3. Tests
- New: suite Hardening (26 checks: owner, mode, symlink file/folder, writable parent, sticky exception, ignored above store root, 8-way create race, atomic CreateFresh, canary no key material, non-dumpable, Unlock zeroing, mlock refusal warning, copy-watch rules, late listener start, end-to-end copied identity with two clients at 127.0.0.1/127.0.0.2) and suite BlockedRun (9 checks: approved, denied, timed out, audit codes, no secret values). Vitest for the copy notice.
- Windows: build --no-incremental 0 warnings; scripts/verify-all.ps1 ALL STAGES PASSED (build, dotnet-tests 4981 passed/0 failed, frontend, publish, e2e). npm run verify: 45 tests.
- WSL Ubuntu (non-root): 5014 passed, 1 failed. The one failure is the environmental "built without the frontend" (suite run with BuildAdminWeb=false).
- Mutation evidence (reverted): owner check off -> 3 FAIL; parent-writable check off -> 3 FAIL; folder symlink check off -> 1 FAIL; copy-watch same-address ignore removed -> 7 FAIL; KeyRecorded not raised -> 1 FAIL; timeout treated as denial -> 2 FAIL.
- Canary: no key material, code or value in any new message, event or log (asserted).
- Fixed a pre-existing Linux-only failure present at 56deebb: e2e audit assertion expected "./script.sh" but the event records the full path; now matches "script.sh".

## 4. Gaps and limits
- A file key is still exportable by anyone who can read it as the owning user (or root); the checks and non-dumpable only narrow exposure.
- mlock covers only arrays we own; runtime or crypto-library copies are not covered. Needs RLIMIT_MEMLOCK headroom, else warning.
- Copy detection is heuristic: NAT or a single bridge hides copies; thresholds are fixed, not settings.
- Late listener start failure is logged only; restart then needed.
- statx needs glibc 2.28 or newer, else the key is refused. macOS only partly checked (no owner info).

## 5. Deviations / architecture conflicts
- No deviations from the accepted design. Section 10.2 design text says nothing on key-file hardening, mlock, copied-key detection, listener start timing or timeout exit code, so the M7 paragraph is additive. The M3 paragraph's "no-overwrite move" is superseded by link(2) publish.
- Interpretation to confirm: timeout keeps exit code 3 (the existing table assigns 3 to Deny/time limit); no new exit code. Distinction is by sentence and audit reason.
- New reason code approval-timeout is wire-visible; older hosts show "the authority refused the request (approval-timeout)".

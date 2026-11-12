# Task M5 report: Dotenvx encrypted .env values on the service, review findings fixed

Worktree `C:\Users\codep\Projects\with-secrets-impl`, branch `impl/mtls-pairing` (base 117b5f0). Local commits only, no attribution, nothing pushed.

Commits (oldest first):
1. `38076fd` Dotenvx encrypted .env values on the service (feature, review fixes, tests, README, operations.md)
2. `6dab146` Remote parity test for encrypted .env values
3. `9b2ab96` Progress notes and current-implementation text in docs/architecture.md
4. `bf85841` Envelope, contract-inspection and service tests updated for the new field and passed-on code-loading values
5. `31e8fc6` E2E pairing scenario builds the 16-member launch request

## 1. Implemented

- Encrypted `NAME=encrypted:...` values (the effective declaration) are decrypted after approval with the private key read from the store (`DOTENV_PRIVATE_KEY` or `DOTENV_PRIVATE_KEY_SUFFIX` for `.env.suffix`). The key secret is part of the approval, is never given to the child, and is masked in output (`ChildSpec.RedactAlso`).
- Crypto: only the project's `DotenvxCipher` wrapper (Dotenvx.Primitives 3.3.1, already used by the store and key rotation). No direct secp256k1/ECIES/AES calls. Note: the maintainer rule names "Dotenvx.Core"; the project references Dotenvx.Primitives, so I used the existing wrapper over it. No library call was missing.
- Protocol: `LaunchRequest` has a 16th member `encrypted` (`LaunchEncrypted(variable, file, keySecret, ciphertext)`), canonical, strictly parsed, validated; digest and `LaunchRequestBinding` compare ciphertexts by SHA-256. Protocol version still 1; golden vectors changed.
- Remote parity: the host service decrypts with the key delivered by the authority; the authority page lists the decrypt items (`ApprovalRequest.Decrypts`). Test `EncryptedEnvValues` in RemoteLaunchTests.
- Approval page: `decrypt with secret KEY: VARIABLE (cipher sha256 FP12) from FILE`, statement that anyone with the public key can write an encrypted value, warning for a file that is not the project's own (`.env` or `.env.NAME` directly in the working folder), first-in-block warning naming code-loading ordinary variables.
- Decision 4 followed: ordinary visible code-loading values (`NODE_OPTIONS` etc.) are passed on and bound in the fingerprint, no stripping or refusal; the service `FromRequest` no longer refuses them. Only values the page cannot show (encrypted, secret-injected) are refused for protected names.
- Audit: signed event metadata `decrypts` = `VARIABLE=KEY:FP12` (names and fingerprints only); a failed decrypt is a signed launch/failed row with reason `env-decrypt-failed`.
- Limits raised: file 1 MB, 16 files, 200 ordinary/200 pairs, 400 entries per file (parse stops early), name 128, value 4096. Secret names accept any case; `DOTENV_PRIVATE_KEY...` allowed as a store name.
- `--set` page and `--needs` warn about case twins and look-alikes (I/l/1, O/0), within the store and within one request.
- Unchanged: remote mode, grants, lock, audit-before-launch, exit codes.

## 2. Files changed

Core (`src/WithSecrets.Core`): ApprovalSummary.cs, ChildProcess.cs, CommandLine.cs, Contracts.cs, Contracts/LaunchContracts.cs, EnvDeclarations.cs, Remote/AuthorityLaunchHandler.cs, Reuse.cs, RunCommand.cs, SecretEntry.cs (plus LaunchClient and call sites).
Tests (`tests/WithSecrets.Tests`): EnvDeclarationTests.cs, EnvEncryptedHttpTests.cs (new), LaunchContractTests.cs, RemoteLaunchTests.cs, HostServiceTests.cs, IdentityTests.cs, RemoteAuthorityTests.cs, AuthorityTests.cs, WebApprovalTests.cs, Program.cs, TestState.cs; `tests/WithSecrets.E2E/ScenariosPairing.cs`.
Docs: README.md, docs/operations.md, IMPLEMENTATION_PROGRESS.md, docs/architecture.md (current-implementation text only).

## 3. Tests added and results

- EnvDeclarations suite (incl. new `ReviewFixes`): 545 checks, 0 failed. It covers 28 protected names at compose and override, runs, request validation, ChildRunner last filter, saved-approval swap, transplant warnings, forged path, key-name folding, control-character table, length bounds, same message for every failure cause, flooding warning, parse limit, RedactAlso, look-alikes, audit canary.
- `EnvEncryptedHttpTests.cs`: real HTTP with a test authenticator; canary scans of page, audit, logs, output.
- LaunchContract (golden vectors recomputed independently with Python hashlib), RemoteLaunch (222 passed, 0 failed, with remote parity test), HostService 233/0, Authority 283/0.
- Mutation evidence (each reverted, git clean afterwards):
  1. Remove `CipherSha256` from the fingerprint in Reuse.cs: 3 tests fail (swapped ciphertext is another fingerprint; item carries the SHA-256; hash is part of the fingerprint).
  2. Drop the control-character check in `UsablePlaintext`: 8 checks fail (NUL, line break, bell, DEL: exit 2 and the signed failed-launch row).
  3. Disable the transplant warning: 4 checks fail (sub folder, non-.env name, other folder, warning names the variable).
- Gates: `dotnet build with-secrets.slnx --no-incremental` 0 warnings, 0 errors. `scripts/verify-all.ps1`: ALL STAGES PASSED (build, dotnet-tests, frontend, publish, e2e). An earlier run failed 4 tests and an E2E compile error from the new field; fixed in commits bf85841 and 31e8fc6.

## 4. Remaining gaps and limitations, each review finding

- H1 fixed: protected-name decision by name alone in compose (before the override check), `FromRequest`, early refusal in `RunPlan` before any page (also `--secrets NODE_OPTIONS`), final filter after approval in RunCommand and in `ChildRunner.Prepare`. All 28 listed names tested.
- H2 fixed: SHA-256 of each ciphertext in the fingerprint, the request digest and the binding; saved approval and grant tests.
- M3 fixed: short ciphertext fingerprint on the decrypt line, own-file warning, public-key statement. Not done (optional): folder-scoped key names.
- M4 fixed: NUL and all control characters except tab refused (multi-line plaintext is refused).
- Finding 5 fixed: code-loading warning first in the block (also in terminal echo); no byte cap added.
- Finding 6 fixed: key first, file last on the decrypt line.
- Finding 7 fixed: ASCII-only key suffix. The Dotenvx convention (`.`/`-`/`_` become `_`) is kept, so two files may map to one key name; the key name is displayed.
- Finding 8 fixed: key strings passed to the redactor.
- Finding 9 fixed: same-request twins and look-alikes warn. Unicode homoglyphs cannot occur (ASCII names).
- Finding 10 NOT fixed: the 6-character plaintext minimum is kept. Redaction steering through an agent-chosen plaintext is accepted; it leaks nothing.
- Finding 11 fixed: 400-entry per-file parse cap.
- Finding 12 fixed: `env-decrypt-failed` signed audit row, one message for every cause.
- Limits: audit `decrypts` metadata may be cut at 2048 characters with very many items; a decrypted value is limited to 4096 characters.

## 5. Deviations from the architecture

- Dotenvx.Primitives via `DotenvxCipher` rather than "Dotenvx.Core" (see section 1).
- `LaunchRequest` gained a 16th member; the golden vectors changed with protocol version still 1.
- Ordinary code-loading values are now passed instead of refused by the service (maintainer decision 4). The review's H1 wording was followed by its technical intent (values the page cannot show).
- docs/architecture.md: accepted design text untouched. I edited only current-implementation statements (Section 10 table row "Task 19", 10.1 status paragraph, the "current Phase A parser rejects encrypted" bullet and the Dotenvx.Core table row). Conflict with proposed wording: the 10.1 text still says integration is "through existing Dotenvx.Core" while the built code uses Dotenvx.Primitives; the parked patch's "Confirmed choices/phase B built" hunk did not apply and was not hand-ported. Maintainer to decide.
- Housekeeping: `C:\Users\codep\.claude\scratch\` is shared; my earlier ed3-ed6.py there may have been overwritten (likely mine). A stale test process of mine (PID 39732) was killed with taskkill.

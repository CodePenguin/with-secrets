# Browser HTTPS verification

The earlier spike covers the browser trust matrix, including rejection of a child certificate issued by the trusted leaf. The production runs below exercise the authority and its server-side passkey verification. [HTTPS spike results at 86254c24](https://github.com/CodePenguin/arcana-guardian/blob/86254c24/spikes/LocalHttpsLeaf/results.md)

| Environment or check | Result | Evidence |
| --- | --- | --- |
| Windows 11 25H2 build 26200.9974, SDK 10.0.404 | PASS | Focused browser HTTPS checks cover Windows CNG persistence and export restrictions, exact trust lifecycle with simulated interruptions, real Kestrel HTTPS, certificate and hostname rejection, loopback binding, browser and machine identity separation, startup trust verification, partial multi-target installation and machine-wide cleanup refusal. |
| Ubuntu 26.04.1 LTS, WSL2 kernel 6.18.58.1, Chromium 156.0.8078.4 | PASS | Production Kestrel HTTPS using a disposable NSS database, with ordinary certificate validation. Quick Start verified the administrator's WebAuthn registration and authentication on the server. A separate approval-only passkey enrolled at the same HTTPS origin. The administrator unlocked and signed in after a service restart and after replacing the leaf. The existing approval-only passkey signed in and authorized a real launch after replacement. Offline recovery used browser-validated HTTPS, enrolled a replacement administrator passkey, and preserved the stored test secret. |
| Automated machine and transport regressions | PASS | Windows passed 216 pairing and transport checks and 97 machine diagnostics checks. Ubuntu WSL passed a combined run of 309 checks covering certificate lifecycle, Unix socket, pairing, diagnostics and transport invariants. |
| Windows client against a WSL authority | PASS (machine mTLS) | A separate Windows process enrolled over a loopback-only machine listener in Ubuntu WSL NAT mode. It became Pending, received approval through the existing administrative backend, then pinned the authority signing key over authenticated machine TLS. The disposable processes and state were removed. WSL client to Windows authority and physical two-machine pairing remain unverified. |
| Windows installed Edge 158.0.4370.45 | PASS | Disposable production HTTPS scenario passed 58 checks. A human manually verified the exact initial and replacement SHA-1 fingerprints in CurrentUser Root before the scenario continued and before cleanup. Both exact leaves were absent from CurrentUser Root afterward, no `arcana-guardian-browser` CNG keys remained, and no Arcana Guardian leaf appeared in LocalMachine Root. |
| Windows installed Chrome 158.0.8127.38 | PASS | Disposable production HTTPS scenario passed 58 checks with the same manual fingerprint confirmations. Both exact leaves were absent from CurrentUser Root afterward, no `arcana-guardian-browser` CNG keys remained, and no Arcana Guardian leaf appeared in LocalMachine Root. |
| Windows installed Firefox | NOT TESTED | Firefox was not found in the standard Windows install locations. The Playwright Firefox TLS and WSL rows above describe separate environments. Production Firefox WebAuthn remains unverified. |
| Ubuntu/WSL Firefox 157.0, Playwright build 1555 | PASS (TLS) | A new Firefox process loaded the production SPA as a secure context after NSS installation and again after leaf replacement. The disposable NSS database was empty after cleanup. Production Firefox WebAuthn remains unverified. |
| Windows browser against a WSL authority | NOT TESTED | Windows browser trust and loopback forwarding in this topology remain unverified. |
| macOS Safari and Chromium | NOT TESTED | No macOS environment was available. Treat the documented login-keychain steps as unverified. |
| Hardware and synchronized passkeys, managed browser policy | NOT TESTED | Production Chromium verification used disposable virtual authenticators. |

On this Windows session the direct `CurrentUser Root` write did not display an OS confirmation dialog. The production scenario therefore uses `--wait-for-confirmation`: it prints the exact SHA-1, waits for a human to check the user certificate store, and only then continues. Cleanup uses the same gate before removing the exact initial and replacement leaves. No validation bypass or machine-wide trust change was used.

The production leaf has a ten-calendar-year validity period, ECDSA P-256, the sole DNS SAN `arcana-guardian.localhost`, critical basic constraints with CA=false, critical Digital Signature-only usage, and Server Authentication as the sole EKU. Trust and cleanup match the exact DER. Each generation has a distinct subject so NSS can distinguish active and pending leaves while replacement is in progress. The origin and relying-party ID stay fixed across rotation when the authority port is unchanged.

An early Chromium rotation run produced `An NSS entry has the expected nickname but different certificate bytes. It was left alone.` The application conservatively preserved lifecycle state. After the subject change, replacement and cleanup succeeded. The early run's exact leaves were removed from its disposable NSS database after checking their full DER fingerprints. The final cleanup check independently found both disposable NSS databases empty, the isolated key directories absent, and the last HTTPS test port no longer listening. No production passkeys, keys or machine-wide trust were used.

## Repository verification

`scripts/verify-all.ps1 -KeepGoing` passed all five stages: solution build, 6,482 .NET checks, frontend checks (161 tests), Windows single-file publication and self-check, and all 35 Windows Playwright regression scenarios (662 checks). These regression scenarios use the repository's in-process HTTP fixture. Native browser trust evidence is reported separately above. The Windows desktop companion Go checks are NOT TESTED here because the Go toolchain is not installed in this environment.

The initial .NET suite run reported a transient Windows backup assertion (49,472 bytes remained in the SQLite write-ahead log after shutdown). The backup suite passed in isolation on both this branch and unchanged `main`. The same full run aborted when a convenience-key test tried to open a WAL file that SQLite had already removed. The test now handles a missing WAL sidecar while continuing to scan the database and other files. A focused rerun passed all 266 checks. The final complete Windows .NET run passed 6,482 checks with zero failures, including the backup and convenience-key checks. The repository stages therefore passed across the acceptance script and the complete .NET rerun.

## Reproduction

From the repository root, run `scripts/verify-all.ps1 -KeepGoing`. The disposable production HTTPS scenario is opt-in:

- On an interactive Windows desktop with Edge installed, run `dotnet run --project tests/ArcanaGuardian.E2E -- --browser-https --wait-for-confirmation msedge`. Verify the displayed SHA-1 in `Cert:\CurrentUser\Root` and write it to the printed `confirm-install.txt` path. The scenario gates cleanup the same way with a `confirm-cleanup.txt` path. Use `chrome` for installed Chrome.
- On Linux or WSL with NSS tooling and Playwright Chromium available, create an isolated browser user environment and SQL NSS database, then run `dotnet run --project tests/ArcanaGuardian.E2E -- --browser-https /absolute/path/to/nssdb`. Use the NSS directory the launched Chromium actually reads. The runner checks production HTTPS and uses disposable browser contexts.
- On Linux or WSL with Playwright Firefox available, initialize an isolated Firefox profile as a SQL NSS database and run `dotnet run --project tests/ArcanaGuardian.E2E -- --browser-https firefox /absolute/path/to/profile`. This verifies HTTPS after setup and replacement.

## Review boundaries

### Browser surfaces and ceremony inventory

Ordinary sign-in, unlock, administration and launch approval already run inside the embedded React SPA at `/admin` and its JSON API at `/api/v1` on the one HTTPS origin. The remaining standalone browser ceremonies are generated HTML served on the same authority HTTPS origin under one-use random paths:

| Route | Purpose | Security boundary |
| --- | --- | --- |
| `/admin/quick-start/<token>` | Quick Start device verification, first administrator passkey, first manifest signature, trust and unlock, recovery code display. | 24-byte random path, exact origin and `Origin`, one-use route, challenge bound to route and fingerprint, server-side WebAuthn verification. |
| `/c/<token>` | Terminal first setup and the recovery continuation that creates the replacement administrator passkey. | Random token, server-owned challenge, PRF-backed sign, terminal confirmation code before commit. |
| `/e/<token>` | Delegated passkey enrollment. | Server-owned challenge, exact origin and RP ID, verified admin manifest signature, sealed PRF output, first outcome wins. |
| `/a/<token>` | Delegated approval, manifest signature, PRF release, key-rotation confirmation and non-inline authorization fallback. | Exact proof body, challenge binding to manifest, one-use replay guard, strict CSP. |
| `/r/<token>` | Recovery code entry at the start of `--recover`. | Browser-side sealing of the recovery code, three-try limit, no store write until the whole flow succeeds. |

Each command prints one tokenized link; later steps reserve new tokenized pages and navigate the same tab. These pages are not additional ordinary authorization tabs. The terminal-assisted `--recover` operation uses the same browser-trusted leaf on its own temporary loopback HTTPS listener because it may run without the normal service while WebAuthn still needs the fixed `arcana-guardian.localhost` RP origin.

Consolidating these ceremonies into the React SPA is a separate implementation task: add SPA rendering for the token routes, replace suffix posts with versioned JSON endpoints while keeping token, origin and one-use checks authoritative, port the four inline scripts into React components, replace inline JSON bootstrap with framework-safe API state, deliberately allow `publickey-credentials-create` only on ceremony routes, keep the recovery listener serving the same SPA assets, and preserve terminal confirmation, PRF sealing, atomic commits, retry limits and first-outcome-wins sessions. Security properties must be re-verified by tests before removing the current pages. Substantial SPA consolidation is therefore recorded as outstanding architectural work, not expanded into this remediation.

### Trust and key boundaries

The key stays separate from machine enrollment and mTLS. Browser trust is scoped to the selected user or NSS database. The spike characterized the issuer checks in specific browser verifiers. Other software, enterprise policies, OS releases and macOS trust may evaluate that trust differently. Unix file permissions protect the private key from other ordinary users. Code running as the same user or root can read the Unix private key. Cleanup requires access to the original trust target. Keep lifecycle state until cleanup succeeds.

# Browser HTTPS verification

The earlier spike covers the browser trust matrix, including rejection of a child certificate issued by the trusted leaf. The production runs below exercise the authority and its server-side passkey verification. [HTTPS spike results at 86254c24](https://github.com/CodePenguin/with-secrets/blob/86254c24/spikes/LocalHttpsLeaf/results.md)

| Environment or check | Result | Evidence |
| --- | --- | --- |
| Windows 11 25H2 build 26200.9974, SDK 10.0.404 | PASS | 115 focused checks. Windows CNG persistence and export restrictions, exact trust lifecycle with simulated interruptions, real Kestrel HTTPS, certificate and hostname rejection, loopback binding, and browser and machine identity separation. |
| Ubuntu 26.04.1 LTS, WSL2 kernel 6.18.58.1, Chromium 156.0.8078.4 | PASS | Production Kestrel HTTPS using a disposable NSS database, with ordinary certificate validation. Quick Start verified the administrator's WebAuthn registration and authentication on the server. A separate approval-only passkey enrolled at the same HTTPS origin. The administrator unlocked and signed in after a service restart and after replacing the leaf. The existing approval-only passkey signed in and authorized a real launch after replacement. Offline recovery used browser-validated HTTPS, enrolled a replacement administrator passkey, and preserved the stored test secret. |
| Windows automated machine and transport regressions | PASS | 216 checks across pairing and transport invariants. A separate machine-diagnostics run passed 97 checks. Physical two-machine pairing and live WSL-to-Windows mTLS remain unverified. |
| Windows installed Edge | BLOCKED | A disposable production scenario requested a Windows CurrentUser Root confirmation. The prompt was not approved during the run. The test was stopped. The exact certificate was absent from CurrentUser Root and TrustedPeople after cleanup, and its CNG key and temporary state were gone. |
| Windows installed Chrome and Firefox | NOT TESTED | The spike tested installed Chrome and Playwright Firefox with the same trust store. Production WebAuthn and same-origin rotation on these browsers remain unverified. |
| Ubuntu/WSL Firefox 157.0, Playwright build 1555 | PASS (TLS) | A new Firefox process loaded the production SPA as a secure context after NSS installation and again after leaf replacement. The disposable NSS database was empty after cleanup. Production Firefox WebAuthn remains unverified. |
| Windows browser against a WSL authority | NOT TESTED | Windows browser trust and loopback forwarding in this topology remain unverified. |
| macOS Safari and Chromium | NOT TESTED | No macOS environment was available. Treat the documented login-keychain steps as unverified. |
| Hardware and synchronized passkeys, managed browser policy | NOT TESTED | Production Chromium verification used disposable virtual authenticators. |

The production leaf has a ten-calendar-year validity period, ECDSA P-256, the sole DNS SAN `with-secrets.localhost`, critical basic constraints with CA=false, critical Digital Signature-only usage, and Server Authentication as the sole EKU. Trust and cleanup match the exact DER. Each generation has a distinct subject so NSS can distinguish active and pending leaves while replacement is in progress. The origin and relying-party ID stay fixed across rotation when the authority port is unchanged.

An early Chromium rotation run produced `An NSS entry has the expected nickname but different certificate bytes. It was left alone.` The application conservatively preserved lifecycle state. After the subject change, replacement and cleanup succeeded. The early run's exact leaves were removed from its disposable NSS database after checking their full DER fingerprints. The final cleanup check independently found both disposable NSS databases empty, the isolated key directories absent, and the last HTTPS test port no longer listening. No production passkeys, keys or machine-wide trust were used.

## Reproduction

From the repository root, run `scripts/verify-all.ps1 -KeepGoing`. The disposable production HTTPS scenario is opt-in:

- On an interactive Windows desktop with Edge installed, run `dotnet run --project tests/WithSecrets.E2E -- --browser-https msedge`. Verify the displayed SHA-1 before confirming a Windows trust prompt. Use `chrome` for installed Chrome.
- On Linux or WSL with NSS tooling and Playwright Chromium available, create an isolated browser user environment and SQL NSS database, then run `dotnet run --project tests/WithSecrets.E2E -- --browser-https /absolute/path/to/nssdb`. Use the NSS directory the launched Chromium actually reads. The runner checks production HTTPS and uses disposable browser contexts.
- On Linux or WSL with Playwright Firefox available, initialize an isolated Firefox profile as a SQL NSS database and run `dotnet run --project tests/WithSecrets.E2E -- --browser-https firefox /absolute/path/to/profile`. This verifies HTTPS after setup and replacement.

## Review boundaries

The React SPA handles ordinary sign-in, unlock, administration and launch approvals. Quick Start and delegated passkey operations still use the existing HTML ceremony pages on the authority's HTTPS origin. The terminal-assisted `--recover` operation uses the same leaf on a separate, temporary loopback HTTPS listener. Moving those existing ceremony pages into the React SPA remains open.

The key stays separate from machine enrollment and mTLS. Browser trust is scoped to the selected user or NSS database. The spike characterized the issuer checks in specific browser verifiers. Other software, enterprise policies, OS releases and macOS trust may evaluate that trust differently. Unix file permissions protect the private key from other ordinary users. Code running as the same user or root can read the Unix private key. Cleanup requires access to the original trust target. Keep lifecycle state until cleanup succeeds.

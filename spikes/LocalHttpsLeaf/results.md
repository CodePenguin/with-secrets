# Ten-year self-signed HTTPS leaf results

**Recommendation: keep the leaf as the preferred candidate and defer production adoption.** The measured Windows and Linux configurations rejected certificates signed by the trusted leaf. Windows CurrentUser Root and Linux NSS accepted the ten-year leaf with browser-specific settings. CurrentUser TrustedPeople failed in every Windows browser. A production decision still depends on release-channel and platform coverage, verification of browser-specific enrollment, and a tested response to loss or compromise of the long-lived key.

## Environment

| Environment | Browser | Version |
| --- | --- | --- |
| Windows 11 25H2, build 26200.9974 | Installed Microsoft Edge | 158.0.4370.45 |
| Same Windows host | Installed Google Chrome | 158.0.8127.38 |
| Same Windows host | Playwright Firefox, patched build 1555 | 157.0 |
| Ubuntu 26.04.1 LTS in WSL2, kernel 6.18.58.1-microsoft-standard-WSL2 | Playwright Chromium, build 1248 | 156.0.8078.4 |
| Same Ubuntu WSL2 environment | Playwright Firefox, patched build 1555 | 157.0 |

Runs started November 27, 2026 Eastern time. SDK 10.0.404, runtime 10.0.15 and Playwright 1.64.1. Browser runs used disposable profiles. Windows trust changes applied to the current Windows account across its profiles. The Windows test process ran without an administrator token.

## Certificate and diagnostic controls

All wire checks passed on Windows and Ubuntu. The Windows Edge/Chrome leaf was valid from 2026-11-28 00:20:10 UTC through 2036-11-28 00:20:10 UTC. Its SHA-256 was `ED6F3B5D7DF13C7108EAA45220917F2061795FAF92F79C565A92E3EE288F30E1`. The runner validated the exact DER served by Kestrel, the self-signature, ECDSA P-256, sole DNS SAN `with-secrets.localhost`, critical basic constraints `CA=false` with no path length, critical Digital Signature-only key usage, and sole EKU Server Authentication. The validity is exactly ten calendar years, including the five-minute clock-skew allowance at generation.

The child at `https://localhost:18766/` had the sole matching SAN `localhost`, current dates, a matching issuer DN, and a valid ECDSA-SHA256 signature over the certificate body under the trusted leaf's key. The exact wire certificate passed server-auth chain building against an in-memory CA certificate with the same issuer name and signing key. When the original non-CA leaf was the anchor, the Windows engine returned `NotValidForUsage, InvalidBasicConstraints` and the Linux engine returned `InvalidBasicConstraints`. Windows system chain building with the exact leaf in CurrentUser Root independently gave the same Windows errors for the child and accepted the leaf itself. The positive CA control was never installed or served. The browser results below are from real TLS navigations. The wire check always rejected the connection after capturing the certificate.

## Windows matrix

`E` = Edge, `C` = Chrome, `F` = Firefox. PASS means the expected outcome occurred. BLOCKED means a missing prerequisite prevented a conclusion. A rejection under TrustedPeople alone cannot establish that a specific second certificate is rejected under working trust.

| Test | TrustedPeople E | TrustedPeople C | TrustedPeople F | Root E | Root C | Root F |
| --- | --- | --- | --- | --- | --- | --- |
| Reject before trust | PASS A | PASS A | PASS F | PASS A | PASS A | PASS F |
| Accept HTTPS after installation | FAIL A | FAIL A | FAIL F | PASS | PASS | PASS after restart |
| Accept ten-year validity | BLOCKED | BLOCKED | BLOCKED | PASS | PASS | PASS |
| Reject incorrect hostname | BLOCKED A | BLOCKED A | BLOCKED F | PASS N | PASS N | PASS H |
| Reject leaf-issued child | BLOCKED A | BLOCKED A | BLOCKED I | PASS V | PASS V | PASS K |
| Reject same subject and SAN, different key | BLOCKED A | BLOCKED A | BLOCKED F | PASS A | PASS A | PASS F |
| Reject same key and subject, different matching SAN | BLOCKED A | BLOCKED A | BLOCKED F | PASS V | PASS V | PASS F |
| Secure context and WebAuthn API available | BLOCKED | BLOCKED | BLOCKED | PASS | PASS | PASS |
| WebAuthn registration verified by server | BLOCKED | BLOCKED | BLOCKED | PASS | PASS | BLOCKED |
| WebAuthn authentication verified by server | BLOCKED | BLOCKED | BLOCKED | PASS | PASS | BLOCKED |
| Reject HTTPS after removing leaf | PASS A | PASS A | PASS F | PASS A | PASS A | PASS F |

| Code | Exact error emitted by Playwright | Explanation |
| --- | --- | --- |
| A | `net::ERR_CERT_AUTHORITY_INVALID` | Chromium found no acceptable trust path. |
| F | `SSL_ERROR_UNKNOWN` | Exact Playwright Firefox identifier for these navigations. It gives less detail than the other Firefox errors below. |
| I | `SEC_ERROR_UNKNOWN_ISSUER` | Firefox found no issuer under TrustedPeople. |
| N | `net::ERR_CERT_COMMON_NAME_INVALID` | Chromium rejected `localhost` against the sole `with-secrets.localhost` SAN. |
| H | `SSL_ERROR_BAD_CERT_DOMAIN` | Firefox rejected the same hostname mismatch. |
| V | `net::ERR_CERT_INVALID` | Chromium rejected the candidate chain. For the child, the unchanged child passed the separate authorized-issuer control and Windows identified issuer key usage and basic constraints. |
| K | `SEC_ERROR_INADEQUATE_KEY_USAGE` | Firefox flagged the leaf issuer's key usage for the child. |

Both CurrentUser installs succeeded without elevation. TrustedPeople installed and removed silently, and none of the browsers accepted the leaf from it. Windows default chain building in that phase returned `UntrustedRoot` for the leaf and `PartialChain` for the child. The Root API prompted for user confirmation. Windows described the leaf as a CA in the install dialog and warned about certificate issuance. Edge and Chrome picked up Root installation in the already-running process on a fresh navigation. Firefox still returned `SSL_ERROR_UNKNOWN` in that process and accepted in a new one. After removal, all three browsers returned a certificate error in the same and fresh processes in the harness. The same-process Firefox probe reused the process that had rejected the leaf before install, while the fresh after-removal probe confirmed current trust.

## Linux and other platforms

| Test | Ubuntu WSL Chromium, NSS `P,,` | Ubuntu WSL Firefox, NSS `P,,` | Ubuntu WSL Firefox, NSS `C,,` | macOS Safari, Chrome, Firefox |
| --- | --- | --- | --- | --- |
| Reject before trust | PASS A | PASS F | PASS F | NOT TESTED |
| Accept HTTPS after installation | PASS | FAIL F | PASS | NOT TESTED |
| Accept ten-year validity | PASS | BLOCKED | PASS | NOT TESTED |
| Reject incorrect hostname | PASS N | BLOCKED F | PASS H | NOT TESTED |
| Reject leaf-issued child | PASS A | BLOCKED U | PASS K | NOT TESTED |
| Reject same subject and SAN, different key | PASS A | BLOCKED U | PASS F | NOT TESTED |
| Reject same key and subject, different matching SAN | PASS A | BLOCKED F | PASS F | NOT TESTED |
| Secure context and WebAuthn API available | PASS | BLOCKED | PASS | NOT TESTED |
| WebAuthn registration verified by server | PASS | BLOCKED | PASS | NOT TESTED |
| WebAuthn authentication verified by server | PASS | BLOCKED | PASS | NOT TESTED |
| Reject after removing leaf | PASS A | PASS F | PASS F | NOT TESTED |

U is `SEC_ERROR_UNTRUSTED_ISSUER`. Firefox did not accept the exact leaf with SSL peer trust.

Linux used an isolated NSS database per browser. NSS `P,,` grants SSL peer trust, so Chromium's `ERR_CERT_AUTHORITY_INVALID` for the child is consistent with the trusted peer being unavailable as a CA. Firefox accepted the leaf when explicitly marked as an SSL trust anchor in its disposable profile with `C,,`. The child was rejected for issuer key usage under that configuration. The test restarted the Linux browser across trust transitions. No macOS environment was available.

## Windows browsers with WSL-hosted Kestrel

The Windows client captured the exact WSL leaf over loopback forwarding and matched the public DER before changing trust. Windows Edge, Chrome and Firefox rejected the HTTPS leaf before trust and completed the server-verified HTTP localhost control through the same forwarded app.

| Test | Edge | Chrome | Firefox |
| --- | --- | --- | --- |
| Reject before trust | PASS A | PASS A | PASS F |
| Complete localhost registration and authentication | PASS | PASS | PASS |
| Install leaf in CurrentUser Root | BLOCKED | BLOCKED | BLOCKED |
| Accept HTTPS and ten-year validity | BLOCKED | BLOCKED | BLOCKED |
| Reject incorrect hostname, child and substitute leaves under working trust | BLOCKED | BLOCKED | BLOCKED |
| Secure context, registration and authentication over trusted HTTPS | BLOCKED | BLOCKED | BLOCKED |
| Reject HTTPS after trust removal | BLOCKED | BLOCKED | BLOCKED |

Windows requested user confirmation for the Root import. The client was stopped while the confirmation was pending, and the exact WSL leaf was verified absent from both Windows CurrentUser stores. The Windows-local Firefox Root test established HTTPS and secure-context results. Its server-verified HTTPS ceremony remains blocked because the retry was part of the forwarded Root phase.

## WebAuthn and trust scope

The original spike only observed browser API completion. This run uses the with-secrets verification code to check a server-generated challenge, the exact browser origin, the RP ID hash, user presence and user verification, the enrolled public key and the assertion signature. It retains only the disposable ceremony state in memory. Firefox uses GeckoDriver 0.37.1 with only its virtual authenticator enabled in the disposable profile. A control that left the USB authenticator enabled returned `NotAllowedError: The request is not allowed by the user agent or the platform in the current context, possibly because the user denied permission.` Mozilla declares its virtual and USB test paths mutually exclusive. [Firefox authenticator preferences](https://raw.githubusercontent.com/mozilla-firefox/firefox/refs/heads/main/modules/libpref/init/StaticPrefList.yaml) It does not exercise production enrollment, persisted sign counters, hardware authenticators or synced passkeys.

Windows Edge, Chrome and Firefox and Ubuntu Chromium also completed server-verified registration and authentication on `http://localhost:18769` with RP ID `localhost`. In Chromium, calling WebAuthn from that origin with RP ID `with-secrets.localhost` returned `SecurityError: The relying party ID is not a registrable domain suffix of, nor equal to the current domain. Subsequently, an attempt to fetch the .well-known/webauthn resource of the claimed RP ID failed.` Both origins can support a passkey, and changing the RP ID requires a migration or new enrollment. Localhost was an HTTP comparison control, so the test does not independently isolate host from scheme or port.

The leaf-issued child was rejected across accepted configurations, and two independently valid self-signed substitutes also failed. The same-key control had a new SAN that matched the connection and shared the trusted subject, so its rejection cannot be explained by using an incorrect URL hostname or mismatched subject DN. The tests establish that trusting the leaf does not grant general-purpose signing authority in these verifiers and configurations. Chromium Windows source compares the complete DER before recognizing a certificate as directly trusted. That is source evidence for exact-certificate matching in Chromium, and the tests leave same-name, same-key, same-SAN renewal and exact matching by other applications unresolved. [Chromium Windows trust lookup](https://chromium.googlesource.com/chromium/src/net/%2B/341eaef1195c6b238354e9f65cd9fa6fc05cd663/cert/internal/trust_store_win.cc#326)

## Documentation and architecture implications

- The Chromium Windows verifier source lists CurrentUser Root and restricts TrustedPeople for server-side trust to machine locations. In the referenced implementation, Root may provide trust-anchor or self-signed leaf trust while enforcing anchor expiry and constraints. This accounts for the measured store difference without requiring any machine-wide import. Root is a shared trust decision and other verifiers can have different trust-anchor semantics. [Chromium Windows store implementation](https://chromium.googlesource.com/chromium/src/net/%2B/341eaef1195c6b238354e9f65cd9fa6fc05cd663/cert/internal/trust_store_win.cc) · [RFC 5280 section 6.1](https://datatracker.ietf.org/doc/html/rfc5280#section-6.1)
- Chromium documents `P,,` as explicit self-signed server trust in Linux NSS. Mozilla documents its enterprise-root integration on Windows. Acceptance can vary with policy or profile. [Chromium Linux certificate management](https://chromium.googlesource.com/chromium/src/%2B/main/docs/linux/cert_management.md) · [Mozilla enterprise certificate configuration](https://support.mozilla.org/en-US/kb/setting-certificate-authorities-firefox)
- Chrome scopes public Web PKI lifetime enforcement to publicly trusted certificates. Apple documents a lifetime exemption for certificates issued by user- or administrator-added Root CAs. That wording leaves the long-lived directly trusted non-CA leaf in Safari unresolved. [Chromium lifetime policy](https://chromium.googlesource.com/chromium/src/%2Bshow/main/net/docs/certificate_lifetimes.md) · [Apple trusted certificate lifetime limits](https://support.apple.com/en-us/102028) · [Apple Keychain certificate trust settings](https://support.apple.com/en-euro/guide/keychain-access/kyca11871/mac)

Prefer explicit peer trust where supported. On Windows, weigh the Root import and removal prompts, Firefox restart, and shared trust-store scope against the benefit of eliminating an online CA signing key. A shorter-lived directly trusted leaf reduces the exposure window and requires re-enrollment at rotation if trust matches only the exact certificate. If the leaf cannot meet required platform or enrollment gates, evaluate a private CA with a separate offline, tightly controlled signer and short-lived server certificates. That architecture retains a CA signing capability and needs testing of name constraints and removal in each target verifier. A publicly trusted certificate for an organization-controlled DNS name could avoid local trust changes, but changes the naming and issuance model. Keep an explicit uninstall and trust-replacement path in any design. Measure hardware and synced passkey behavior, managed browser policy, normal browser release builds, same-SAN key reuse, macOS trust and key recovery before adopting a production architecture.

## Cleanup

The Windows browser runs verified the exact leaf absent from both CurrentUser stores before each phase and again after removal. No LocalMachine store was modified. The Windows diagnostic run also confirmed all four temporary TLS key containers were absent after shutdown. Chromium and Firefox virtual authenticators were explicitly removed and their disposable profiles closed. The Linux runner removed each exact NSS certificate and its temporary profile and database. The WSL Kestrel process stopped and removed its public DER file. A final check found none of the test leaves in either Windows CurrentUser store and no listeners on ports 18765 through 18769 on Windows or WSL. No test CA was installed.

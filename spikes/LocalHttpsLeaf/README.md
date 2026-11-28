# Disposable local HTTPS leaf spike

Run with .NET 10: `dotnet run --project spikes/LocalHttpsLeaf`. No production state or automatic trust changes. Each run generates a new certificate. Use a disposable OS account/browser profile or VM; do not use production passkeys. Keep the process running throughout the test.

1. Before trust, open https://with-secrets.localhost:18765/ and confirm certificate rejection. Never bypass warnings.
2. Import only the printed public leaf into the browser's applicable trust store. Windows: try CurrentUser TrustedPeople first, then (if unsupported) CurrentUser Root in the disposable account. Record which store works. Linux Firefox/NSS and macOS: use native explicit certificate trust UI; record exact trust settings. Do not enable arbitrary CA trust without recording it.
3. Open the correct URL again; require normal trusted connection, secure context, and no warning.
4. Open https://localhost:18765/; require hostname rejection.
5. Open https://localhost:18766/; require rejection of the child signed by the trusted non-CA leaf. This endpoint has a matching SAN and is intentionally invalid as a chain. If accepted, the trust configuration fails the security requirement.
6. On the correct URL register and authenticate a disposable passkey. This tests browser API behavior only, not server-side assertion verification.
7. Remove the exact imported certificate (printed SHA1/SHA256), remove the disposable passkey, restart browser if needed, and verify correct URL is rejected again before stopping the process.

Windows cleanup example for Root: `Remove-Item Cert:\CurrentUser\Root\<printed SHA1>` (substitute actual thumbprint); use TrustedPeople instead if that was the store used. Never remove unrelated certificates.

Record OS, browser/version, trust store, each result, and error codes. Test Edge/Chrome/Firefox on Windows, Chrome/Firefox on Linux, Safari/Chrome/Firefox on macOS. No certificate warning overrides or browser flags disabling validation. WSL browser trust belongs to the browser host.

Spike only: Windows uses temporary user key storage for Schannel compatibility, not production nonexportable CNG storage. No production code changes. Remove this directory before merging any eventual implementation.

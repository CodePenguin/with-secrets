# Disposable local HTTPS leaf spike

Run from the repository root with .NET 10.

```powershell
dotnet run --project spikes/LocalHttpsLeaf
```

Each run creates a fresh ECDSA P-256 leaf, starts loopback-only listeners and prints the public DER file path and fingerprints after the wire checks pass. Keep the server running while comparing trust stores. Stop it with Ctrl+C to remove the public file and release the temporary TLS keys. The server does not install trust by default. Use a disposable account or VM for OS-level trust changes and a disposable browser profile and authenticator.

| URL | Purpose |
| --- | --- |
| `https://with-secrets.localhost:18765/` | Exact ten-year leaf |
| `https://localhost:18765/` | Same leaf, incorrect hostname |
| `https://localhost:18766/` | Valid localhost certificate signed by the non-CA leaf |
| `https://with-secrets.localhost:18767/` | Same subject and SAN, different key |
| `https://localhost:18768/` | Same subject and key, different SAN that matches this URL |
| `http://localhost:18769/` | Localhost WebAuthn comparison |
| `https://with-secrets.localhost:18770/` | Reissued leaf with the same key, names and validity and a distinct serial number |

The wire probe captures the certificate presented by each listener and rejects the connection. It verifies the child's signature independently and compares the exact child against an in-memory CA control with the same issuer name and signing key. The control CA never enters a browser or OS trust store. The page verifies registration and authentication in memory using the repository's WebAuthn verifier and one-use server challenges. No production state or passkeys are involved.

## Windows browser runner

```powershell
dotnet build spikes/LocalHttpsLeaf -p:BuildAdminWeb=false
pwsh -File spikes/LocalHttpsLeaf/bin/Debug/net10.0/playwright.ps1 install firefox
dotnet run --no-build --project spikes/LocalHttpsLeaf -- --browser-tests
```

The runner uses the installed Edge and Chrome channels and Playwright's Firefox. Optionally specify browser names `msedge chrome firefox` and `--store=TrustedPeople` or `--store=Root`. For Firefox registration and authentication, set `SPIKE_GECKODRIVER` to the path to GeckoDriver 0.37 or later and `SPIKE_FIREFOX_BINARY` to the full path to Firefox 152 or later. The runner checks TLS through Playwright and uses a separate GeckoDriver session with a virtual authenticator to verify Firefox's ceremony. Only the disposable GeckoDriver profile selects Firefox's software authenticator. Without GeckoDriver it records that ceremony as blocked.

The runner installs only the public leaf into CurrentUser TrustedPeople and then CurrentUser Root. Each phase verifies absence from both stores before moving on. Approve Windows Root confirmation dialogs only after verifying the SHA-1 fingerprint printed by the runner. Never click through a browser certificate warning. After unexpected termination, inspect both stores and remove only the exact printed leaf. A browser profile does not isolate CurrentUser trust.

Pass `--replace-trust` to explicitly trust the reissued certificate after the original is removed. This asks Windows to confirm a second Root import and checks that only the replacement is accepted, then removes it and checks rejection again. These tests use separate loopback ports to compare the two TLS certificates. Passkey continuity across an in-place server rotation is outside this test.

```powershell
Remove-Item -LiteralPath "Cert:\CurrentUser\Root\<printed SHA-1>"
```

## Linux and WSL

Use NSS `certutil` from `libnss3-tools` or your distribution's equivalent and install Playwright Chromium and Firefox. Pass the NSS tool's path, optionally followed by `chromium` and/or `firefox`. Use `firefox-anchor` to separately test explicit profile-local SSL anchor trust (`C,,`) for the same non-CA leaf. The runner uses per-browser temporary profiles and NSS databases, imports the leaf as an SSL peer with `P,,`, removes it and checks browser rejection again. For Firefox WebAuthn, set the same GeckoDriver environment variables as on Windows.

```sh
dotnet run --project spikes/LocalHttpsLeaf -p:BuildAdminWeb=false -- --linux-browser-tests /usr/bin/certutil
```

To reuse an already running server from Linux, pass `--linux-client <absolute-public-DER-path> <NSS-certutil-path>` and any browser modes.

For WSL-hosted Kestrel with a Windows browser, start the server with the default command in WSL and make the printed public DER file available to Windows. With native Windows listeners stopped, run the Windows client against that file. It verifies the forwarded listener presents the exact certificate and checks the required leaf profile before modifying CurrentUser trust.

```powershell
dotnet run --no-build --project spikes/LocalHttpsLeaf -- --windows-client <absolute-public-DER-path> msedge chrome firefox
```

Use `--diagnostics-only` to verify the wire certificate profile and child controls without changing a trust store. Browser runs print each outcome and the exact error reported by browser automation. A recorded FAIL is an experimental result, so the CLI can complete successfully while reporting failures in the acceptance criteria.

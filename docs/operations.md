# Operations guide

Installation, first run, enrollment, backup and recovery, offline behaviour, Docker and WSL, and troubleshooting for the Windows host service and its authority. The design is in [architecture.md](architecture.md) (10.2 and 10.5); every command and screen is in the [README](../README.md). Everything here that says "tested" is exercised by the suites named in brackets (`dotnet run --project tests\WithSecrets.Tests` with `WS_ONLY=<suite>`), not only described.

Terminal output is public: nothing in this guide asks you to copy a code, key or value into a terminal that an agent can read.

## 1. Install

Building needs the .NET 10 SDK and **Node.js 22 or newer** on the PATH (the administration web application is built by the .NET build; a release build fails rather than ship without it). Running the published program needs neither.

1. `scripts\publish-win-x64.ps1` makes `artifacts\publish\win-x64\with-secrets.exe`: one self-contained file with the web application embedded, and verifies it (`scripts\verify-publish.ps1`: exactly one file, the application served from the same origin as the API, frontend version equal to backend version equal to `Directory.Build.props`). Re-run the verification alone with `scripts\verify-publish.ps1 -Folder <folder>`; the program also checks itself with `with-secrets.exe --self-check` (a throwaway service, software keys, no user state).
2. Put the EXE where you like and call it by name (`with-secrets`). The service is started by hand for now (`with-secrets service`); a Windows service that starts at logon is not built.
3. `scripts\verify-all.ps1` runs the whole acceptance sequence (build with warnings as errors, the .NET suite, frontend checks, the single-EXE publish and its verification, the browser tests) and prints only pass or fail lines.

## 2. First run

Do these in your own terminal, not the agent's.

1. **Create the secret store and the first passkey:** `with-secrets --config` (README "First-time setup"). The first passkey must support PRF and becomes the first admin key. The page shows a **recovery code once**; write it down offline (see section 5).
2. **Start the host service:** `with-secrets service`. It enrolls this machine as **Pending**, starts **locked** and prints its fingerprint and the link of the admin web app. It listens on `127.0.0.1` and `[::1]`, port 8765 (`--port N` or `WITH_SECRETS_PORT`).
3. **Open the admin web app:** `with-secrets admin` prints and opens `http://localhost:8765/admin`. Unlock (one passkey tap), sign in (a second tap, a read-only session) and open **Machines**.
4. **Approve this machine:** compare the fingerprint with the one the service printed, type a friendly name, press **Approve** and tap an admin passkey. This also pins the authority signing key in `host.json`. Until then a run exits 7 (no identity pinned) or is refused (Pending).
5. **Store secrets:** `with-secrets --set NAME`. Give the agent the run command and the secret names.

Every later change in the app is its own request, its own one-use passkey page and one tap; a session alone changes nothing. Normal use of a valid grant needs no tap.

### More passkeys

`with-secrets --enroll` adds a passkey (name it, choose whether it is also an admin key; an admin key approves and signs the change). `--unenroll NAME` removes one (never the last admin key). Keep at least two admin keys on different devices: a second admin key is the only other way to open the store besides the recovery code.

### More machines

A second machine (for example WSL) is a separate identity with its own enrollment. On the authority's machine run `with-secrets service --machine-port 8790` (loopback by default; beyond loopback it needs `--machine-cert`). On the other machine run `with-secrets admin https://HOST:8790 --authority-fingerprint HEX`, where the fingerprint is the authority's (shown in the app; it is required, there is no trust on first use). That enrolls the machine as Pending and pins the authority; an administrator then approves it in the app **Machines** view after comparing its fingerprint. See section 8 for WSL.

## 3. Day to day

- **Lock and unlock:** the service starts locked and again after every restart; **Lock** and **Unlock** are in the app, each a fresh tap. Locking drops and zeroes the key held for a grant, ends saved approvals and the offline lease, and cancels launches that have not started. [suites AuthorityLock, Operations]
- **Unlock mode:** manual (a tap) is the default. Unattended unlock is an explicit opt-in in **Settings**; it only decides how the key hierarchy becomes available at start, never replaces a tap for a sensitive change.
- **Machines:** Approve, Disable/Enable, Untrust/Trust again, Rename, Accept host name (section 7).
- **Grants:** created with `with-secrets approve ...` on the page; Extend, Renew, Revoke in the app.
- **Audit:** the **Audit** view searches the signed events (machine, project, time, outcome).

## 4. Backup and restore

**What to back up.** Stop the service (Ctrl+C), then copy two files from `%USERPROFILE%\.with-secrets`:

| File | What it holds |
| --- | --- |
| `state.db` | The secret store: secrets as ciphertext (names are readable, as `--list` shows), the signed manifest (passkeys with their key slots, settings), the store's vault and recovery slot, the human-command audit log |
| `authority.db` | Machine records and history, grants (secret names, program, folder, the approving passkey assertion), the audit events hosts uploaded, the authority's public keys and the signed key transitions, settings (the unattended-unlock policy and its sealed blob) |

Not backed up, on purpose: **the keys.** The machine identity key and the authority signing keys are Windows CNG keys created non-exportable; no file holds them, so no backup can. `host.json` is this machine's pin (public data, per machine). `audit-outbox.db` is this host's not yet uploaded events (signed by this machine's key). Logs are diagnostics. The recovery code and the passkeys are not in any file in usable form.

**What an attacker with the backup gets.** Ciphertext they cannot open without a passkey's PRF output (the authenticator) or the recovery code; the names of your secrets, the names of programs and folders that asked for them, machine names and fingerprints, and public keys. No secret value, no private key, no master or store key, no recovery code, no PRF output. [Operations: a scan of the backup files for the master key, the recovery code and a secret value finds none, and finds a planted recovery code as a control.] The protection of the backup is therefore the protection of the recovery code: **keep the recovery code and the backup apart**, because together they open every secret. The unattended-unlock blob in `authority.db` is sealed with the Windows user's DPAPI key; it does not open on another account or machine. Treat the backup as private metadata (who asked for what, when) anyway.

**What a restore does and does not do.** Rolling back to an older backup also rolls back things that happened since: a machine disabled, a grant revoked or an audit row written after the backup comes back as it was. After any restore, open **Machines** and **Grants** and re-apply what is missing.

**Restore on a second machine.** [suite Operations, "restore:" checks, on a fresh folder with fresh keys]

1. Install the program there. Create no store: copy `state.db` and `authority.db` into `%USERPROFILE%\.with-secrets` while no service is running.
2. `with-secrets service`. It starts **locked**. The store opens and its manifest verifies; the admin passkeys from the backup still work (the authenticator is the same).
3. Unlock in the app with an admin passkey tap. The authority still **cannot sign**: the key store of this machine does not hold the key `authority.db` names, and the program never uses another key. Runs are refused and nothing is decrypted; the error says to recover the key.
4. In **Settings** press **Recover** and tap. A new authority key is made with no transition and pinned for this machine only. The earlier rotation chain still verifies; the recovery is a recorded break in it, so no host follows it by itself.
5. This machine's identity is new, so it enrolled as **Pending**: approve it in **Machines** (a tap). The old machine's record is still Trusted until you **Disable** it (do that if it is gone). Other hosts that pinned the old authority key must be enrolled again.
6. Run a command. The audit history continues after the restored rows.

## 5. Recovery

| Situation | What to do |
| --- | --- |
| Every passkey lost, recovery code known | `with-secrets --recover`: type the code on the page, make a new passkey and new keys; the old `state.db` is renamed, never deleted. Then `--rotate-key` to get a new recovery code |
| Suspect a passkey or the store key | `with-secrets --rotate-key` (admin): new store and master keys, every secret encrypted again, only the tapped admin key stays. This does not recall values already exposed: rotate the secrets at their source |
| Authority signing key: routine change | **Rotate** in the app **Settings** (a tap). The new key is introduced by a transition the current key signs; a host that pinned the current key follows it by itself, one signed hop at a time, and runs without another tap. [Operations, AuthorityTests] |
| Authority signing key lost (new machine, wiped key store) or not trusted | **Recover** in the app **Settings** (a tap). No transition: the new key is pinned for this machine by that action; every other host must be enrolled again. A key that is not an admin cannot do either [Operations] |
| Authority key store disagrees with `authority.db` | Fail closed: nothing is signed, decrypted or run, until Recover |
| Unattended-unlock blob lost or unreadable | Nothing to restore: the authority stays locked; unlock manually with a tap |
| A machine is lost or distrusted | **Disable** or **Untrust** it (its grants end, the revision goes up) and revoke its grants |
| `authority.db` damaged or of another schema | Restore it from a backup (section 4). Deleting it starts over: machines enroll again and grants and uploaded audit are lost |

No path skips a fresh tap: unlock, lock, rotate, recover, approve, disable and every other sensitive operation need an admin passkey with user verification for that operation, with or without unattended unlock.

## 6. Offline behaviour

While the authority answers, a grant is checked with it on every run. A host that already synchronized a grant may keep using it while the authority cannot be reached, but only inside a **lease** the authority issues (15 minutes by default). The lease is held in memory, measured with a monotonic clock (changing the system date does not lengthen it, an indefinite grant does not lengthen it), and a restart destroys it. With no valid lease nothing is decrypted (`this host has no valid offline-authorization lease ...`; ask again in a moment, the service reconnects). Offline a host makes no new approval, extension or renewal. A revocation or a disable is applied at once while connected. After a restart the service checks in before it accepts requests (503 until then). Audit events wait in `audit-outbox.db` and are uploaded when the authority answers; a run that needs a secret does not start if its audit event cannot be committed locally (exit 5). [suites GrantAuthority, AuditTrail]

## 7. Host name changes

A machine that starts reporting another host name is **not** accepted by itself: the run is refused, nothing is decrypted, the new name is recorded as waiting and shown in **Machines** ("New host name reported"). **Accept host name** binds exactly the name the dialog showed, after a fresh admin tap; the security revision does not change. A different name arriving after the tap is not applied. [suites Operations and Api, browser scenario i8]

## 8. Docker and WSL

**Docker.** A program called `docker` is launched through the host service like any other: the service runs on the host and starts the Docker client there. Values reach the client only as environment variables (`-e API_TOKEN` in the arguments names the variable; the value is never in arguments), the service adds no volume, no env-file and no container identity, and nothing is written to disk by it. [suite Operations "docker:" checks with a stand-in `docker`] A client **inside a container** cannot talk to the service as it stands: the service answers only for loopback host names and addresses (`localhost`, `127.0.0.1`, `[::1]`), so a request that names `host.docker.internal` or a bridge address is refused with 421. Reaching the service from a container would need a deliberate decision to listen beyond loopback (an attack-surface change); it is not made here, and no system or firewall setting is changed by this program.

**WSL.** The protocol, configuration and topology are tested by simulation (two independently enrolled host identities against one authority, the relay, the machine endpoint). A real WSL run is not possible yet: the Linux machine key store does not exist (Windows CNG only), so a WSL host service cannot start. That is a recorded security decision, not an oversight. Checklist for when it is decided:

1. Build for `linux-x64` and start the WSL service.
2. Windows: `with-secrets service --machine-port 8790` (mirrored networking: loopback works; NAT mode: bind the vEthernet(WSL) address with `--machine-bind` and `--machine-cert`, and add the firewall rule yourself).
3. WSL: `with-secrets admin https://HOST:8790 --authority-fingerprint HEX`.
4. Windows admin app: approve the pending machine after comparing its fingerprint.
5. WSL: run a command that needs a secret; open the authority link printed on Windows and tap the passkey.
6. Confirm the child saw the value and the Windows audit history shows the signed events.
7. Lock the authority; confirm a run is refused and nothing starts.
8. Confirm no secret value is in the WSL home folder, `host.json` or the logs.

## 9. Troubleshooting

### Exit codes

| Code | Meaning | What to do |
| --- | --- | --- |
| 0 | Success (the child exited 0, a grant was made, a command did its change) | |
| 2 | Usage: bad arguments or secret name, policy refusal, script missing or changed, unknown secret | Read the line printed; `--needs` shows what the project asks for |
| 3 | Denied: Deny on the page, wrong proof, time limit, nothing enrolled, refused change | Ask again; for "nothing enrolled" run `--config` |
| 4 | Store error: `state.db` damaged, locked over 5 seconds, other schema, failed signature, cannot decrypt; also the service could not listen on its port | See below |
| 5 | Audit error: the audit row or the signed audit event could not be committed, so nothing ran | Check disk space and the `audit-outbox.db` file; see "Outbox" |
| 6 | Host service not running | `with-secrets service`, or give `--service-port N` |
| 7 | Service not authenticated: what answers on the port is not this machine's service, or no identity is pinned yet | Check the port; for a new machine approve its fingerprint in the app |
| 8 | Authority locked | Unlock in the app (`with-secrets admin` prints the link) |
| 127 | Program not found or cannot be started | Check PATH and the App Execution Alias |
| other | The child's own exit code, passed through | |

### Common problems

- **Locked.** A run prints `the authority is locked ... Unlock it at the authority: http://localhost:8765/admin` and exits 8. Unlock with a tap. The service starts locked after every restart by design.
- **Pending machine.** The run is refused with the machine's fingerprint and the instruction to approve it in the admin app. Compare the fingerprint with the one the service printed.
- **Port conflict.** `the host service cannot listen on port N (...). Is it already running?` (exit 4): another service or program holds the port; use `--port N` for the service and the same `--service-port N` (or `WITH_SECRETS_PORT`) for runs. An approval page port in use fails with `port N is already in use; choose another with --port N`.
- **Expired lease.** `this host has no valid offline-authorization lease`: the authority has not been reached lately or the machine is not Trusted. Ask again in a moment; check the authority is running, unlocked and the machine Trusted.
- **Outbox or authority schema mismatch.** `audit-outbox.db is not of schema version N; delete audit-outbox.db to start over` and `authority.db is not of schema version N; delete authority.db to start over (machines then enroll again)`. The outbox holds only events not yet uploaded: deleting it loses those. For `authority.db` restore a backup first; delete only if you accept losing machines, grants and audit.
- **The authority signing key in the key store is not the one authority.db names.** Restore on a new machine or a wiped key store: **Recover** in the app (section 4).
- **A host refuses the authority's answers ("not pinned").** The authority key was recovered (no transition): pin it by approving the machine again in the app, or enroll the host again.
- **A page sits on "Checking your passkey...".** Run with `--debug` and read the terminal and the log (README "Logging" and "Troubleshooting").
- **Publish verification fails.** `scripts\verify-publish.ps1` prints one line per failure (loose file, missing embedded asset, version mismatch). Rebuild with `scripts\publish-win-x64.ps1` after `npm ci` in `src\WithSecrets.Admin.Web`; Node 22 or newer is required.
- **The whole acceptance sequence.** `scripts\verify-all.ps1` stops at the first failing stage and says which.

## 10. Limits to remember

Same-OS-user processes can reach the loopback API and the service's memory; a restored or rolled-back `authority.db` can bring back an older state (review machines and grants); the Linux key store, grant creation from a remote host, and a Windows service that starts at logon are not built. The full list is in README "Known limits" and `IMPLEMENTATION_PROGRESS.md`.

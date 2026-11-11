# Operations guide

Installation, first run, enrollment, backup and recovery, behaviour when the authority is unreachable, Docker and WSL, and troubleshooting for the Windows host service and its authority. The design is in [architecture.md](architecture.md) (10.2 and 10.5); every command and screen is in the [README](../README.md). Everything here that says "tested" is exercised by the suites named in brackets (`dotnet run --project tests\WithSecrets.Tests` with `WS_ONLY=<suite>`), not only described.

Terminal output is public: nothing in this guide asks you to copy a code, key or value into a terminal that an agent can read.

## 1. Install

Building needs the .NET 10 SDK and **Node.js 22 or newer** on the PATH (the administration web application is built by the .NET build; a release build fails rather than ship without it). Running the published program needs neither.

1. `scripts\publish-win-x64.ps1` makes `artifacts\publish\win-x64\with-secrets.exe`: one self-contained file with the web application embedded, and verifies it (`scripts\verify-publish.ps1`: exactly one file, the application served from the same origin as the API, frontend version equal to backend version equal to `Directory.Build.props`). Re-run the verification alone with `scripts\verify-publish.ps1 -Folder <folder>`; the program also checks itself with `with-secrets.exe --self-check` (a throwaway service, software keys, no user state).
2. Put the EXE where you like and call it by name (`with-secrets`). The service is started by hand for now (`with-secrets service`); a Windows service that starts at logon is not built.
3. `scripts\verify-all.ps1` runs the whole acceptance sequence (build with warnings as errors, the .NET suite, frontend checks, the single-EXE publish and its verification, the browser tests) and prints only pass or fail lines.

## 2. First run

**Read this before the first real start.** The first `with-secrets service` on a real profile creates two non-exportable Windows CNG keys under fixed names: `with-secrets machine identity v1` (this machine's identity) and `with-secrets authority signing key v1` (the authority's), in the TPM when there is one. There is no way to export or copy them, and removing them by hand (or a wiped profile) means **Recover** (section 5) and approving the machine again. That sequence on the real profile (start locked, unlock, sign in, approve, run) has been exercised only with test key names and software keys (`--self-check`), never end to end on `%USERPROFILE%\.with-secrets`; a Linux or WSL machine keeps its identity key as an owner-only file instead (weaker, section 8); the WSL path and a real two-machine deployment over mutual TLS (each running service also creates, and deletes at exit, short-lived named CNG keys for its temporary TLS certificate) have not been run at all (section 8 and `IMPLEMENTATION_PROGRESS.md` "Exit criteria status"). Treat the first run as a test drive and do it in this order:

1. `with-secrets --config` (creates the passkey and the secret store; no CNG key)
2. `with-secrets service` (**creates the two CNG keys**; starts locked)
3. open the link it printed; Unlock (tap); Sign in (tap); Machines, Approve (tap)
4. `with-secrets --set NAME`; run a command

The numbered steps below explain each.

Do these in your own terminal, not the agent's.

1. **Create the secret store and the first passkey:** `with-secrets --config` (README "First-time setup"). The first passkey must support PRF and becomes the first admin key. The page shows a **recovery code once**; write it down offline (see section 5).
2. **Start the host service:** `with-secrets service`. It enrolls this machine as **Pending**, starts **locked** and prints its fingerprint and the link of the admin web app. It listens on `127.0.0.1` and `[::1]`, port 8765 (`--port N` or `WITH_SECRETS_PORT`).
3. **Open the admin web app:** open the link the service printed in its own window. (`with-secrets admin` also prints the link, but until this machine is approved nothing is pinned, so it marks the link as not verified, exits 0 and does not open a browser; after the approval it checks the service's identity first, opens the link in a terminal on Windows, and exits 7 if what answers is not this machine's service.) Unlock (one passkey tap), sign in (a second tap, a read-only session) and open **Machines**.
4. **Approve this machine:** compare the fingerprint with the one the service printed, type a friendly name, press **Approve** and tap an admin passkey. This also pins the authority signing key in `host.json`. Until then a run exits 7 (no identity pinned) or is refused (Pending).
5. **Store secrets:** `with-secrets --set NAME`. Give the agent the run command and the secret names.

Every later change in the app is its own request, its own one-use passkey page and one tap; a session alone changes nothing. Normal use of a valid grant needs no tap.

### More passkeys

`with-secrets --enroll` adds a passkey (name it, choose whether it is also an admin key; an admin key approves and signs the change). `--unenroll NAME` removes one (never the last admin key). Keep at least two admin keys on different devices: a second admin key is the only other way to open the store besides the recovery code.

### More machines

A second machine (for example WSL) is a separate identity. On the authority's machine run `with-secrets service --machine-port 8790` (loopback by default; `--machine-bind ADDRESS` for one other address; the machine port is separate from the browser and client port and speaks only TLS 1.3 with a certificate on both sides, HTTP/2). The other machine is introduced to the authority by **pairing** (below).

#### Pairing procedure

1. On the authority: admin app, **Pairing**, **Create an invitation**, tap the passkey on the page that opens and **copy the bundle** shown once (`wsp1;https://HOST:8790;ID;CODE`). It is valid 10 minutes and registers one machine. It cannot be shown again: if it is lost, revoke the invitation (or let it expire) and create another.
2. On the new machine: `with-secrets pair`, paste the bundle at the hidden prompt. The machine prints its fingerprint and host name and says it is Pending.
3. On the authority: **Machines**, find the Pending machine, compare the fingerprint and host name with what the machine printed, **Approve** with a tap. Host then pins the authority key by itself on its first run.
4. Check: run a command on the new machine that needs a secret; the authority's approval page opens on the authority.

#### Unattended pairing and Docker secrets

For a container or a provisioning script put the bundle in a file and let `with-secrets pair` read it, so it is never in a command line, an image layer or `docker inspect`:

```
# docker compose
services:
  host:
    secrets: [with-secrets-pairing]
secrets:
  with-secrets-pairing:
    file: ./pairing.bundle     # one line: the bundle; delete the file after pairing
```

`pair` refuses a secret file that other accounts can read (Unix: any group or other permission bit; Windows: an ACL entry allowing read to anyone but you, SYSTEM and Administrators) and says so without reading it; the Docker secret mount is not checked. After pairing the file is left where it is; it is spent, delete it (or let your Docker secret lifecycle do it). The host service does not pair by itself at startup: run `with-secrets pair` first (unattended is fine).

Pairing a host that already trusts another authority is refused unless a person types `replace` at a terminal (it prints both identities); an unattended run always refuses. Pairing attempts are limited per invitation and per peer address; a pending invitation is never locked out by other people's failed attempts. A host renews its machine identity certificate by itself (same key) when under 30 days remain, checked at start and reconnect.

A Docker secret appears as `/run/secrets/with-secrets-pairing`, which `with-secrets pair` reads with no variable. Any other file: set `WITH_SECRETS_PAIRING_FILE=/path/to/file`. `WITH_SECRETS_PAIRING` holds the bundle itself and is the weakest form (an environment is visible to the process's owner and often to tooling); prefer a file. A file is preferred over the variable when both are set. The command clears both variables from its own environment after reading, and neither is passed to any program a host service launches. Delete the file after pairing: the invitation is useless once used or expired, but the file is a credential until then. With no terminal and no unattended source `pair` asks for nothing and exits 2.

#### Pairing troubleshooting

- **"the authority could not prove that it holds this invitation" (exit 3).** The bundle is wrong or for another authority, the address in it is not the authority that created it, or something sits in between. Nothing about this machine was sent. Create a new invitation and copy the whole bundle again.
- **"pairing was refused" (exit 3).** One answer for a wrong, expired, used, revoked or withdrawn invitation, and for a machine the authority already knows as Trusted, Disabled or Untrusted (those are never changed by pairing). The authority's audit says which (Audit view, events starting `pairing-`). Create a new invitation; for a known machine use the Machines view instead.
- **"too busy".** Fixed limits: 30 refused attempts in 10 minutes in all, 4 registrations at once, 32 machines waiting. Wait ten minutes or approve/remove waiting machines.
- **The Create button says no address.** The authority service has no machine endpoint: start it with `--machine-port`.
- **Cannot connect.** The address in the bundle must be reachable from the new machine (firewall; with WSL NAT use `--machine-bind` on the vEthernet address).
- **The machine stays Pending after pairing.** That is intended: approve it under Machines.

## 3. Day to day

- **Lock and unlock:** the service starts locked and again after every restart; **Lock** and **Unlock** are in the app, each a fresh tap. Locking drops and zeroes the key held for a grant, ends saved approvals and the offline lease, and cancels launches that have not started. [suites AuthorityLock, Operations]
- **Unlock mode:** manual (a tap) is the default. Unattended unlock is an explicit opt-in in **Settings**; it only decides how the key hierarchy becomes available at start, never replaces a tap for a sensitive change.
- **Machines:** Approve, Disable/Enable, Untrust/Trust again, Rename, Accept host name (section 7).
- **Grants:** created with `with-secrets approve ...` on the page; Extend, Renew, Revoke in the app.
- **Audit:** the **Audit** view searches the signed events (machine, project, time, type, outcome). This is the only audit log: run events (authorization, launch, execution) and administrative events (type `admin`: store changes, key rotation, enrollment, recovery, revocation, settings, passkey changes, refused changes; names only). Each event may carry signed **metadata** (names and fingerprints only: secret names, variable mapping, `.env` files, file fingerprints, approving key, reuse minutes), shown read-only in the event list. There is no hash chain; integrity comes from the machine signature, the unique id, the per-machine sequence and the authority's acknowledgement. The `--audit` command is gone.

## 4. Backup and restore

**What to back up.** Stop the service (Ctrl+C), then copy two files from `%USERPROFILE%\.with-secrets`:

| File | What it holds |
| --- | --- |
| `state.db` | The secret store: secrets as ciphertext (names are readable, as `--list` shows), the signed manifest (passkeys with their key slots, settings), the store's vault and recovery slot. No audit table: the audit is the signed event outbox, `audit-outbox.db`, below |
| `authority.db` | Machine records and history, grants (secret names, program, folder, and the approving passkey assertion **with the page text the passkey signed, which contains the full arguments of the command and the ordinary `.env` values the page showed, unredacted**), the audit events hosts uploaded, the authority's public keys and the signed key transitions, settings (the unattended-unlock policy and its sealed blob) |

Not backed up, on purpose: **the keys.** The machine identity key and the authority signing keys are Windows CNG keys created non-exportable; no file holds them, so no backup can. `host.json` is this machine's pin (public data, per machine). `audit-outbox.db` is this host's not yet uploaded events (signed by this machine's key). Logs are diagnostics. The recovery code and the passkeys are not in any file in usable form.

**What an attacker with the backup gets.** Ciphertext they cannot open without a passkey's PRF output (the authenticator) or the recovery code; the names of your secrets, the names of programs and folders that asked for them, machine names and fingerprints, and public keys. No secret value, no private key, no master or store key, no recovery code, no PRF output. [Operations: a scan of the backup files for the master key, the recovery code and a secret value finds none, and finds a planted recovery code as a control.] The protection of the backup is therefore the protection of the recovery code: **keep the recovery code and the backup apart**, because together they open every secret. The unattended-unlock blob in `authority.db` is sealed with the Windows user's DPAPI key; it does not open on another account or machine. Treat the backup as private metadata (who asked for what, when) anyway. In particular the grant rows keep the signed page text as evidence, so command arguments (for example a `--token xyz` that was not a secret reference) and ordinary `.env` values are in `authority.db` in clear text; the signed audit trail masks secret-like arguments, the grant rows do not. Do not put secrets in arguments or ordinary `.env` values. Keeping only a hash of that text would need a change to how grant evidence is verified and is not done.

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
| Suspect a passkey or the store key | `with-secrets --rotate-key` (admin): new store and master keys, every secret encrypted again, only the tapped admin key stays. This does not recall values already exposed: rotate the secrets at their source. **Then lock the service in the app (or stop it) and start it again**: `--rotate-key` runs in the CLI process and does not tell the service, so key material the service holds in memory for a grant is not dropped by it. A restart or a lock drops and zeroes it (telling the service would need a design change) |
| Authority signing key: routine change | **Rotate** in the app **Settings** (a tap). The new key is introduced by a transition the current key signs; a host that pinned the current key follows it by itself, one signed hop at a time, and runs without another tap. [Operations, AuthorityTests] |
| Authority signing key lost (new machine, wiped key store) or not trusted | **Recover** in the app **Settings** (a tap). No transition: the new key is pinned for this machine by that action; every other host must be enrolled again. A key that is not an admin cannot do either [Operations] |
| Authority key store disagrees with `authority.db` | Fail closed: nothing is signed, decrypted or run, until Recover |
| Unattended-unlock blob lost or unreadable | Nothing to restore: the authority stays locked; unlock manually with a tap |
| A machine is lost or distrusted | **Disable** or **Untrust** it (its grants end, the revision goes up) and revoke its grants |
| `authority.db` damaged or of another schema | Restore it from a backup (section 4). Deleting it starts over: machines enroll again and grants and uploaded audit are lost |

No path skips a fresh tap: unlock, lock, rotate, recover, approve, disable and every other sensitive operation need an admin passkey with user verification for that operation, with or without unattended unlock.

## 6. When the authority is unreachable (fail closed)

**Stated exactly: a host whose authority cannot be reached fails closed. There is no offline lease and no offline use of a grant, in either mode.**

- **Local mode:** the authority is in the same process as the host, so a failure is a denial, never "offline". Nothing runs while the authority is locked or unreachable inside the process.
- **Remote mode (WSL path):** the host has no store; every value comes from the authority. When the authority is stopped or the connection is gone, runs are refused at once, whatever grant the host synchronized earlier, and the key the host was holding for a grant is dropped and zeroed. Do not expect a grace period.

The rules: a grant is checked with the authority on every run. The authority vouches for a host only through a verified check-in that says the machine is Trusted and its host name is the bound one; that is held in memory, a restart destroys it, a changed or replayed answer vouches for nothing, and the system date does not matter; without it nothing is decrypted (`the authority has not confirmed this machine as trusted ...`). A host makes no new approval, extension or renewal while the authority cannot be reached; a revocation or a disable is applied at once while connected. After a restart the service checks in before it accepts requests (503 until then, exit 9 for a run). Audit events (the run events and the administrative events) wait in `audit-outbox.db` and are uploaded when the authority answers; a run that needs a secret does not start if its audit event cannot be committed locally (exit 5; in remote mode that includes the host's "requested" record, committed before the authority is asked), and an administrative change is not made if its audit event cannot be committed. [suites GrantAuthority, AuditTrail, RemoteLaunch, StateDatabase]

## 7. Host name changes

A machine that starts reporting another host name is **not** accepted by itself: the run is refused, nothing is decrypted, the new name is recorded as waiting and shown in **Machines** ("New host name reported"). **Accept host name** binds exactly the name the dialog showed, after a fresh admin tap; the security revision does not change. A different name arriving after the tap is not applied. [suites Operations and Api, browser scenario i8]

## 8. Docker and WSL

**Docker.** A program called `docker` is launched through the host service like any other: the service runs on the host and starts the Docker client there. Values reach the client only as environment variables (`-e API_TOKEN` in the arguments names the variable; the value is never in arguments), the service adds no volume, no env-file and no container identity, and nothing is written to disk by it. [suite Operations "docker:" checks with a stand-in `docker`] A client **inside a container** cannot talk to the service as it stands: the service answers only for loopback host names and addresses (`localhost`, `127.0.0.1`, `[::1]`), so a request that names `host.docker.internal` or a bridge address is refused with 421. Reaching the service from a container would need a deliberate decision to listen beyond loopback (an attack-surface change); it is not made here, and no system or firewall setting is changed by this program.

**Linux and WSL host: the machine key is a file.** On Linux (WSL included) the machine identity key (and the authority signing key, if that machine is an authority) is an ECDSA P-256 key in a FILE under `~/.with-secrets/keys/` (`with-secrets-machine-identity-v1.key`): created with mode 0600 in a directory with mode 0700, never replaced once it exists. **This is weaker than Windows CNG, and the limit is stated plainly: the key is not non-exportable. Anything that runs as the same user (and root) can read and copy the file, and a copy is a complete copy of the machine's identity; no TPM, keyring or secret service is used.** The program refuses a key file or key folder that group or other can access (the message says to run `chmod 600` on the file or `chmod 700` on the folder), a link in place of the file, and a file that is not exactly an ECDSA P-256 PKCS#8 private key; it never prints, logs or reports key material. Keep the folder out of backups and images you share. The short-lived TLS key of a running instance is an ordinary in-memory key on Linux (OpenSSL accepts that); it is never written. [suite KeyStore; the mode checks run on Linux and are skipped on Windows]

**A container is a separate machine.** It pairs as a host over the authority's mTLS machine listener with its own identity (section 2, "Unattended pairing and Docker secrets"); there is no other listener and no identity shared with the host. Its key file must survive restarts: mount a persistent volume at the key folder (for example `-v ws-keys:/root/.with-secrets/keys`, or the path under the container user's home). A container started without that volume makes a NEW identity each time, which the authority sees as a different, Pending machine. The volume holds a plain key file (the weaker model above); give it to that one container only.

**WSL.** The protocol, configuration and topology are tested by simulation (two independently enrolled host identities against one authority over real mutual TLS 1.3 / HTTP/2 on loopback). The Linux key store exists and its unit suite runs in WSL. The real Windows-authority / WSL-host run needs steps only the administrator can do (a passkey tap and typing the pairing code) and, in NAT mode, an inbound firewall rule: in this build's test environment (WSL2, NAT) a Windows listener on the vEthernet(WSL) address was NOT reachable from WSL, so the machine port must be allowed for the WSL network by the administrator first (this program changes no firewall setting). Checklist:

1. Build for `linux-x64`; in WSL `with-secrets pair` makes the key file on first use (a Linux host service starts with `with-secrets service`).
2. Windows: `with-secrets service --machine-port 8790` (mirrored networking: loopback works; NAT mode: bind the vEthernet(WSL) address with `--machine-bind`, which from WSL is the default gateway in `ip route show default`, and add the firewall rule yourself; the certificate is the machine's own, there is no certificate file to supply).
3. Windows admin app: **Pairing**, create an invitation (tap) and copy the bundle. WSL: `with-secrets pair` and paste it (see section 2, "Pairing procedure").
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
| 4 | Store error: `state.db` damaged, locked over 5 seconds, other schema, failed signature, cannot decrypt; also the service could not start | Read the line: it says whether the port is in use or names another reason (then run with `--debug`) |
| 5 | Audit error: the signed audit event could not be committed, so nothing ran | Check disk space and the `audit-outbox.db` file; see "Outbox" |
| 6 | Host service not running | `with-secrets service`, or give `--service-port N` |
| 7 | Service not authenticated: what answers on the port is not this machine's service, or no identity is pinned yet | Check the port; for a new machine approve its fingerprint in the app |
| 8 | Authority locked | Unlock in the app (`with-secrets admin` prints the link) |
| 9 | Service not ready or busy: the host service answered 503 (it has not finished its check-in with its authority, or it already runs 8 launches) | Ask again in a moment; the service keeps trying by itself. If it stays, check the authority is running, unlocked and the key is not lost (section 5) |
| 127 | Program not found or cannot be started | Check PATH and the App Execution Alias |
| other | The child's own exit code, passed through | |

### Common problems

- **Locked.** A run prints `the authority is locked ... Unlock it in the administration web app: http://localhost:8765/admin (one passkey tap; no sign-in is needed to unlock)` (the line the service sends) and exits 8. Unlock with a tap. The service starts locked after every restart by design.
- **Pending machine.** The run is refused with the machine's fingerprint and the instruction to approve it in the admin app. Compare the fingerprint with the one the service printed.
- **Port conflict.** `the host service cannot listen on port N: the port is in use. Is it already running?` (exit 4). Any other start failure is reported as `the host service could not start (<type>)` with a hint to use `--debug`. For the port: another service or program holds it; use `--port N` for the service and the same `--service-port N` (or `WITH_SECRETS_PORT`) for runs. An approval page port in use fails with `port N is already in use; choose another with --port N`.
- **Not vouched for.** `the authority has not confirmed this machine as trusted`: the authority cannot be reached or the machine is not Trusted. Ask again in a moment; check the authority is running, unlocked and the machine Trusted.
- **Outbox or authority schema mismatch.** `audit-outbox.db is not of schema version N; delete audit-outbox.db to start over` and `authority.db is not of schema version N; delete authority.db to start over (machines then enroll again)`. The outbox holds only events not yet uploaded: deleting it loses those. For `authority.db` restore a backup first; delete only if you accept losing machines, grants and audit.
- **The authority signing key in the key store is not the one authority.db names.** Restore on a new machine or a wiped key store: **Recover** in the app (section 4).
- **A host refuses the authority's answers ("not pinned").** The authority key was recovered (no transition): pin it by approving the machine again in the app, or enroll the host again.
- **A page sits on "Checking your passkey...".** Run with `--debug` and read the terminal and the log (README "Logging" and "Troubleshooting").
- **Publish verification fails.** `scripts\verify-publish.ps1` prints one line per failure (loose file, missing embedded asset, version mismatch). Rebuild with `scripts\publish-win-x64.ps1` after `npm ci` in `src\WithSecrets.Admin.Web`; Node 22 or newer is required.
- **The whole acceptance sequence.** `scripts\verify-all.ps1` stops at the first failing stage and says which.

## 10. Limits to remember

Same-OS-user processes can reach the loopback API and the service's memory; a restored or rolled-back `authority.db` can bring back an older state (review machines and grants); the Linux key store, grant creation from a remote host, and a Windows service that starts at logon are not built. The full list is in README "Known limits" and `IMPLEMENTATION_PROGRESS.md`.

### Test-only isolation (never for real use)

For an end-to-end test of a real Windows authority that must not touch your own keys or store: set both `WITH_SECRETS_TEST_STORE` (an absolute folder, not `~/.with-secrets` and not inside it) and `WITH_SECRETS_TEST_KEY_PREFIX` (3 to 12 lower-case letters or digits) before `with-secrets service`/`pair`. The store, its logs and every CNG key name (machine identity, authority signing keys, the temporary TLS key) then move to the folder and carry the prefix; the keys are still real, non-exportable CNG keys. The program refuses to start with one variable only, a malformed prefix, or the default store.

Cleanup deletes only the prefixed keys. In PowerShell, list with `certutil -user -csp "Microsoft Software Key Storage Provider" -key | Select-String '<prefix> '`, then for each exact name `certutil -user -csp "Microsoft Software Key Storage Provider" -delkey "<prefix> with-secrets machine identity v1"` (likewise `<prefix> with-secrets authority signing key v1`, ` g2`...). Never delete a name that does not start with your prefix. Remove the test store folder afterwards.

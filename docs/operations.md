# Operations guide

Installation, first run, enrollment, backup and recovery, behaviour when the authority is unreachable, Docker and WSL, and troubleshooting for the Windows host service and its authority. The design is in [architecture.md](architecture.md) (10.2 and 10.5); every command and screen is in the [reference.md](reference.md). Everything here that says "tested" is exercised by the suites named in brackets (`dotnet run --project tests\ArcanaGuardian.Tests` with `ARCANA_GUARDIAN_ONLY=<suite>`), not only described.

Terminal output is public: nothing in this guide asks you to copy a code, key or value into a terminal that an agent can read.

## 1. Install

Building needs the .NET 10 SDK and **Node.js 22 or newer** on the PATH (the administration web application is built by the .NET build; a release build fails rather than ship without it). Running the published program needs neither.

1. `scripts\publish.ps1` makes `artifacts\publish\<runtime>\Arcana Guardian` (`using-secrets.exe` for win-x64; `-Runtime` picks linux-x64 or osx-arm64): one self-contained file with the web application embedded, and verifies it (`scripts\verify-publish.ps1`: exactly one file, the application served from the same origin as the API, frontend version equal to backend version equal to `Directory.Build.props`). Re-run the verification alone with `scripts\verify-publish.ps1 -Folder <folder>`; the program also checks itself with `using-secrets.exe --self-check` (a throwaway service, software keys, no user state).
2. Put the EXE where you like and call it by name (`using-secrets`). The service is started by hand for now (`using-secrets service`); a Windows service that starts at logon is not built.
3. `scripts\verify-all.ps1` runs the whole acceptance sequence (build with warnings as errors, the .NET suite, frontend checks, the single-EXE publish and its verification, the browser tests) and prints only pass or fail lines.

## 2. First run

Use your own terminal to run `using-secrets admin`. With no passkey enrolled, it starts the local service in the background and opens Quick Start on Windows. Open the printed link if your browser did not open.

1. **Verify device.** Enter the six-digit code in your terminal. Compare the full fingerprint on both screens and select **Fingerprint matches**.
2. **Create passkey.** Name and create a PRF-capable admin passkey.
3. **Finish setup.** Select **Confirm setup and unlock** to trust the local device, pin the authority, and sign in. Save the recovery code shown on this screen. Expand **See how a secret is used** for an example, or select **Open Arcana Guardian** to go straight to Overview.

The service stays running after Quick Start. After a service restart, use the normal passkey unlock. A second machine still needs an invitation and a separate trust decision. Changes such as saving secrets and revoking grants each require their own passkey.

New installations allow 15 minutes for a pending approval. Change this in **Settings**, under **Approval pages** (1 to 30 minutes). The number beside **Access** shows waiting requests while the signed-in app is open.

### More passkeys

The **Passkeys** page of the admin web app adds a passkey (name it, choose whether it is also an admin key; an admin key approves and signs the change) and removes one (never the last admin key). Keep at least two admin keys on different devices: a second admin key is the only other way to open the store besides the recovery code.

### More machines

A second machine (for example WSL) is a separate identity. On the authority's machine run `using-secrets service --machine-port 8790` (loopback by default; `--machine-bind ADDRESS` for one other address; the machine port is separate from the browser and client port and speaks only TLS 1.3 with a certificate on both sides, HTTP/2). The other machine is introduced to the authority by **pairing** (below).

#### Pairing procedure

1. On the authority: admin app, **Machines**, **Add a machine**, **Continue to passkey**, tap the passkey on the page that opens and **copy the bundle** shown once (`wsp1;https://HOST:8790;ID;CODE`). It is valid 10 minutes and registers one machine. It cannot be shown again: if it is lost, revoke the invitation (or let it expire) and create another.
2. On the new machine: `using-secrets pair`, paste the bundle at the hidden prompt. The machine prints its fingerprint and host name and says it is Pending.
3. On the authority: **Machines**, find the Pending machine, compare the fingerprint and host name with what the machine printed, **Approve** with a tap. Host then pins the authority key by itself on its first run.
4. Check: run a command on the new machine that needs a secret; the authority's approval page opens on the authority.

#### Unattended pairing and Docker secrets

For a container or a provisioning script put the bundle in a file and let `using-secrets pair` read it, so it is never in a command line, an image layer or `docker inspect`:

```
# docker compose
services:
  host:
    secrets: [arcana-guardian-pairing]
secrets:
  arcana-guardian-pairing:
    file: ./pairing.bundle     # one line: the bundle; delete the file after pairing
```

`pair` refuses a secret file that other accounts can read (Unix: any group or other permission bit; Windows: an ACL entry allowing read to anyone but you, SYSTEM and Administrators) and says so without reading it; the Docker secret mount is not checked. After pairing the file is left where it is; it is spent, delete it (or let your Docker secret lifecycle do it). The host service does not pair by itself at startup: run `using-secrets pair` first (unattended is fine).

Pairing a host that already trusts another authority is refused unless a person types `replace` at a terminal (it prints both identities); an unattended run always refuses. Pairing attempts are limited per invitation and per peer address; a pending invitation is never locked out by other people's failed attempts. A host renews its machine identity certificate by itself (same key) when under 30 days remain, checked at start and reconnect.

A Docker secret appears as `/run/secrets/arcana-guardian-pairing`, which `using-secrets pair` reads with no variable. Any other file: set `ARCANA_GUARDIAN_PAIRING_FILE=/path/to/file`. `ARCANA_GUARDIAN_PAIRING` holds the bundle itself and is the weakest form (an environment is visible to the process's owner and often to tooling); prefer a file. A file is preferred over the variable when both are set. The command clears both variables from its own environment after reading, and neither is passed to any program a host service launches. Delete the file after pairing: the invitation is useless once used or expired, but the file is a credential until then. With no terminal and no unattended source `pair` asks for nothing and exits 2.

#### Pairing troubleshooting

- **"the authority could not prove that it holds this invitation" (exit 3).** The bundle is wrong or for another authority, the address in it is not the authority that created it, or something sits in between. Nothing about this machine was sent. Create a new invitation and copy the whole bundle again.
- **"pairing was refused" (exit 3).** One answer for a wrong, expired, used, revoked or withdrawn invitation, and for a machine the authority already knows as Trusted, Disabled or Untrusted (those are never changed by pairing). The authority's audit says which (Audit view, events starting `pairing-`). Create a new invitation; for a known machine use the Machines view instead.
- **"too busy".** Fixed limits: 30 refused attempts in 10 minutes in all, 4 registrations at once, 32 machines waiting. Wait ten minutes or approve/remove waiting machines.
- **The Create button says no address.** The authority service has no machine endpoint: start it with `--machine-port`. (Started before the first approval, it prints that the listener starts by itself when the first approval makes the signing key; no restart is needed.)
- **Cannot connect.** The address in the bundle must be reachable from the new machine (firewall; with WSL NAT use `--machine-bind` on the vEthernet address).
- **The authority restarted before the host paired.** Any pending invitation expired at restart. Create and copy a new bundle.
- **The machine stays Pending after pairing.** That is intended: approve it under Machines.

## 3. Day to day

- **Lock and unlock:** the authority starts locked after every restart. Unlock with an admin passkey that supports PRF. Locking wipes the in-memory store and Review keys and cancels launches that have yet to start. Paired hosts reconnect after their own restart without an unlock and require an unlocked, reachable authority for every delivery.
- **Machines:** Approve, Disable/Enable, Untrust/Trust again, Rename, Accept host name (section 7).
- **Grants:** created with `using-secrets approve ...` on the page; Extend, Renew, Revoke in the app.
- **Audit:** the **Audit** view searches the signed events (machine, project, time, type, outcome). This is the only audit log: run events (authorization, launch, execution) and administrative events (type `admin`: store changes, key rotation, enrollment, recovery, revocation, settings, passkey changes, refused changes; names only). Each event may carry signed **metadata** (names and fingerprints only: secret names, variable mapping, `.env` files, `decrypts` as `VARIABLE=KEY:FINGERPRINT` for Dotenvx encrypted values (the key secret's name and the first 12 hex characters of the SHA-256 of the ciphertext, never a value, a ciphertext or a key), file fingerprints, approving key, reuse minutes), shown read-only in the event list. There is no hash chain; integrity comes from the machine signature, the unique id, the per-machine sequence and the authority's acknowledgement. The `--audit` command is gone.

### Interactive LastPass refresh

On the authority desktop, open **Providers** and choose **Refresh values**. Finish the terminal and browser steps within four minutes in the initiating browser session. Start a fresh refresh if the provider or its mounts changed, the previous refresh expired, or the authority locked during the flow. See [Providers and mounts](reference.md#providers-and-mounts) for prerequisites and the approval steps.

### HashiCorp Vault

Configure these settings in the authority service environment before starting it.

| Variable | Value |
| --- | --- |
| `ARCANA_GUARDIAN_VAULT_ADDR` | Trusted HTTPS Vault address, for example `https://vault.example.com:8200`. Use an endpoint that serves requests directly and a certificate trusted by the authority host. |
| `ARCANA_GUARDIAN_VAULT_MOUNT` | KV v2 engine mount path. Defaults to `secret`. |
| `ARCANA_GUARDIAN_VAULT_NAMESPACE` | Optional Vault namespace, for example `teams/payments`. |

In **Admin → Providers**, add **HashiCorp Vault** and enter a Vault token in the password field. The authority seals it to its review key. Use the provider's **Change configuration** action to replace the token before it expires. Vault instances use the same server, namespace, and KV engine settings on a given authority.

The token needs `read` on `auth/token/lookup-self` and on the engine's `data/<document>` and `subkeys/<document>` paths for the documents you expose. Folder trees also need `list` on the engine's `metadata/<folder>` paths. Use a Vault version with the [KV v2 subkeys endpoint](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#read-secret-subkeys). Discovery uses field names from that endpoint, and retrieval reads the latest version.

Provider paths are relative to the Vault engine mount. Given a document at `apps/db` with a field named `PASSWORD`:

| Mount kind | Provider path | Example logical name |
| --- | --- | --- |
| Single secret at `DB_PASSWORD` | `apps/db/PASSWORD` | `DB_PASSWORD` |
| Document tree at `db` | `apps/db` | `db/PASSWORD` |
| Folder tree at `services` | `apps/` | `services/db/PASSWORD` |

Leave the provider path blank for a tree over the KV engine root. Document and field segments may use ASCII letters, digits, underscores, dots, and hyphens. Tree entries also follow the logical secret-name rules. String values are returned as UTF-8 text, and other values as JSON text.

## 4. Backup and restore

**What to back up.** Stop the service and any other Arcana Guardian commands, then copy `arcana-guardian.db` from `%USERPROFILE%\.ArcanaGuardian`. The file holds the encrypted store and signed manifest, authority state, provider data, uploaded audit history, and pending signed audit events. Keep the backup private and store the recovery code separately.

Keep `host.json`, logs, and the platform key store out of a database backup. A restored machine uses its own identity and starts its own audit sequence. Pending events signed by a different machine cannot be uploaded from this one: the next upload marks them rejected (reason `signed by another machine`). They stay in the restored file, are never sent and are not pending. Only the machine that signed them (its own identity key) can upload them, from its own copy of the backup.

**What an attacker with the backup gets.** Ciphertext they cannot open without a passkey's PRF output (the authenticator) or the recovery code; the names of your secrets, the names of programs and folders that asked for them, machine names and fingerprints, and public keys. No secret value, no private key, no master or store key, no recovery code, no PRF output. [Operations: a scan of the backup files for the master key, the recovery code and a secret value finds none, and finds a planted recovery code as a control.] The protection of the backup is therefore the protection of the recovery code: **keep the recovery code and the backup apart**, because together they open every secret. Treat the backup as private metadata (who asked for what, when) anyway. The grant rows keep the signed page text as evidence **encrypted to the review key `R`** (its private key is wrapped by the master key, like the store key), so the full command lines and ordinary `.env` values that a person approved are not in the backup in clear text; the grant's program, folder and secret names are, as are the audit trail's arguments after secret-like values are masked. Do not put secrets in arguments or ordinary `.env` values: the audit trail does not catch a secret typed bare into an argument.

**What a restore does and does not do.** Rolling back to an older backup also rolls back things that happened since: a machine disabled, a grant revoked or an audit row written after the backup comes back as it was. After any restore, open **Machines** and **Grants** and re-apply what is missing.

**Restore on a second machine.** [suite Operations, "restore:" checks, on a fresh folder with fresh keys]

1. Install the program there. Create no store: copy `arcana-guardian.db` into `%USERPROFILE%\.ArcanaGuardian` while no service is running.
2. `using-secrets service`. It starts **locked**. The store opens and its manifest verifies; the admin passkeys from the backup still work (the authenticator is the same).
3. Unlock in the app with an admin passkey tap. The authority still **cannot sign**: the key store of this machine does not hold the key `arcana-guardian.db` names, and the program never uses another key. Runs are refused and nothing is decrypted; the error says to recover the key.
4. In **Settings** press **Recover** and tap. A new authority key is made with no transition and pinned for this machine only. The earlier rotation chain still verifies; the recovery is a recorded break in it, so no host follows it by itself.
5. This machine's identity is new, so it enrolled as **Pending**: approve it in **Machines** (a tap). The old machine's record is still Trusted until you **Disable** it (do that if it is gone). Other hosts that pinned the old authority key must be enrolled again.
6. Run a command. The audit history continues after the restored rows.

## 5. Recovery

| Situation | What to do |
| --- | --- |
| Every passkey lost, recovery code known | `using-secrets --recover`: type the code on the page, make a new passkey and new keys; a snapshot named `arcana-guardian.db.recovered-<time>` keeps the old database; the review key `R` is carried over, so grant review text stays readable. Then rotate the secret store key in the admin web app (Settings) to get a new recovery code |
| Suspect a passkey or the store key | Settings, **Secret store key**, in the admin web app: new store and master keys, every secret encrypted again, only the tapped admin key stays. This does not recall values already exposed: rotate the secrets at their source. **Then lock the service in the app (or stop it) and start it again**: the rotation does not tell the grant cache, so key material the service holds in memory for a grant is not dropped by it. A restart or a lock drops and zeroes it (telling the service would need a design change) |
| Authority signing key: routine change | **Rotate** in the app **Settings** (a tap). The new key is introduced by a transition the current key signs; a host that pinned the current key follows it by itself, one signed hop at a time, and runs without another tap. [Operations, AuthorityTests] |
| Authority signing key lost (new machine, wiped key store) or not trusted | **Recover** in the app **Settings** (a tap). No transition: the new key is pinned for this machine by that action; every other host must be enrolled again. Grants are not resealed by a recovery: every grant shows "not verified" and is not used until a person approves again. A key that is not an admin cannot do either [Operations] |
| Authority key store disagrees with `arcana-guardian.db` | Fail closed: nothing is signed, decrypted or run, until Recover |
| A machine is lost or distrusted | **Disable** or **Untrust** it (its grants end, the revision goes up) and revoke its grants |
| `arcana-guardian.db` damaged or of another schema | Restore it from a backup (section 4). Starting over removes secrets, grants, machine records and the local audit history |

A fresh admin tap with user verification protects administrative changes. Unlock also requires PRF. Any enrolled passkey can approve runs and create, extend, renew, replace or revoke grants with its own fresh tap.

## 6. When the authority is unreachable (fail closed)

**Stated exactly: a host whose authority cannot be reached fails closed. There is no offline lease and no offline use of a grant, in either mode.**

- **Local mode:** the authority is in the same process as the host, so a failure is a denial, never "offline". Nothing runs while the authority is locked or unreachable inside the process.
- **Remote mode (WSL path):** the host has no store; every value comes from the authority. When the authority is stopped or the connection is gone, runs are refused at once, whatever grant the host synchronized earlier, and the key the host was holding for a grant is dropped and zeroed. Do not expect a grace period.

The rules: a grant is checked with the authority on every run. The authority vouches for a host only through a verified check-in that says the machine is Trusted and its host name is the bound one; that is held in memory, a restart destroys it, a changed or replayed answer vouches for nothing, and the system date does not matter; without it nothing is decrypted (`the authority has not confirmed this machine as trusted ...`). A host makes no new approval, extension or renewal while the authority cannot be reached; a revocation or a disable is applied at once while connected. After a restart the service checks in before it accepts requests (503 until then, exit 9 for a run). Audit events (the run events and the administrative events) wait in `arcana-guardian.db` and are uploaded when the authority answers; a run that needs a secret does not start if its audit event cannot be committed locally (exit 5; in remote mode that includes the host's "requested" record, committed before the authority is asked), and an administrative change is not made if its audit event cannot be committed. [suites GrantAuthority, AuditTrail, RemoteLaunch, StateDatabase]

## 7. Host name changes

A machine that starts reporting another host name is **not** accepted by itself: the run is refused, nothing is decrypted, the new name is recorded as waiting and shown in **Machines** ("New host name reported"). **Accept host name** binds exactly the name the dialog showed, after a fresh admin tap; the security revision does not change. A different name arriving after the tap is not applied. [suites Operations and Api, browser scenario i8]

## 8. Docker and WSL

**Docker.** A program called `docker` is launched through the host service like any other: the service runs on the host and starts the Docker client there. Values reach the client only as environment variables (`-e API_TOKEN` in the arguments names the variable; the value is never in arguments), the service adds no volume, no env-file and no container identity, and nothing is written to disk by it. [suite Operations "docker:" checks with a stand-in `docker`] A client **inside a container** cannot talk to the service as it stands: the service answers only for loopback host names and addresses (`localhost`, `127.0.0.1`, `[::1]`), so a request that names `host.docker.internal` or a bridge address is refused with 421. Reaching the service from a container would need a deliberate decision to listen beyond loopback (an attack-surface change); it is not made here, and no system or firewall setting is changed by this program.

**Linux and WSL host: the machine key is a file.** On Linux (WSL included) the machine identity key (and the authority signing key, if that machine is an authority) is an ECDSA P-256 key in a FILE under `~/.ArcanaGuardian/keys/` (`arcana-guardian-machine-identity-v1.key`): created with mode 0600 in a directory with mode 0700, never replaced once it exists. **This is weaker than Windows CNG, and the limit is stated plainly: the key is not non-exportable. Anything that runs as the same user (and root) can read and copy the file, and a copy is a complete copy of the machine's identity; no TPM, keyring or secret service is used.** The program refuses a key file or key folder that group or other can access (the message says to run `chmod 600` on the file or `chmod 700` on the folder), a link in place of the file, and a file that is not exactly an ECDSA P-256 PKCS#8 private key; it never prints, logs or reports key material. Keep the folder out of backups and images you share. The checks in full, the process hardening and what to do about them are in "Linux host hardening" below. The short-lived TLS key of a running instance is an ordinary in-memory key on Linux (OpenSSL accepts that); it is never written. [suite KeyStore; the mode checks run on Linux and are skipped on Windows]

**A container is a separate machine.** It pairs as a host over the authority's mTLS machine listener with its own identity (section 2, "Unattended pairing and Docker secrets"); there is no other listener and no identity shared with the host. Its key file must survive restarts: mount a persistent volume at the key folder (for example `-v ws-keys:/root/.ArcanaGuardian/keys`, or the path under the container user's home). A container started without that volume makes a NEW identity each time, which the authority sees as a different, Pending machine. The volume holds a plain key file (the weaker model above); give it to that one container only.

**WSL.** The protocol, configuration and topology are tested by simulation (two independently enrolled host identities against one authority over real mutual TLS 1.3 / HTTP/2 on loopback). The Linux key store exists and its unit suite runs in WSL. The real Windows-authority / WSL-host run needs steps only the administrator can do (a passkey tap and typing the pairing code) and, in NAT mode, an inbound firewall rule: in this build's test environment (WSL2, NAT) a Windows listener on the vEthernet(WSL) address was NOT reachable from WSL, so the machine port must be allowed for the WSL network by the administrator first (this program changes no firewall setting). Checklist:

1. Build for `linux-x64`; in WSL `using-secrets pair` makes the key file on first use (a Linux host service starts with `using-secrets service`).
2. Windows: `using-secrets service --machine-port 8790` (mirrored networking: loopback works; NAT mode: bind the vEthernet(WSL) address with `--machine-bind`, which from WSL is the default gateway in `ip route show default`, and add the firewall rule yourself; the certificate is the machine's own, there is no certificate file to supply).
3. Windows admin app: **Machines**, **Add a machine** (tap) and copy the bundle. WSL: `using-secrets pair` and paste it (see section 2, "Pairing procedure").
4. Windows admin app: approve the pending machine after comparing its fingerprint.
5. WSL: run a command that needs a secret; open the authority link printed on Windows and tap the passkey.
6. Confirm the child saw the value and the Windows audit history shows the signed events.
7. Lock the authority; confirm a run is refused and nothing starts.
8. Confirm no secret value is in the WSL home folder, `host.json` or the logs.

### Linux host hardening

The Linux key is a file (above), so the protection is the operating system's, not a key store's. Do this on a Linux or WSL host that holds a real identity:

1. **Run the service as its own user, or in its own container.** Create a dedicated service user (for example `arcana-guardian`) that owns `~/.ArcanaGuardian` and nothing else of value, and start the service as that user. In Docker, keep the key folder in a volume that is mounted **only in the service container** (never in a build container, a sidecar or a shell you open to look around), run the container as a non-root user, and give the volume to that one container. Anything that runs as the key's owner, and root, can read the file; the fewer programs that run as that user, the smaller the exposure.
2. **What the program refuses.** Before it uses a key it checks, and a failure stops the command with one line that names the path and the fix (exit code 4, no stack trace): the key file or the key folder is a link (links are never followed); the file or folder belongs to another user than the one running the program (`chown N`); the file can be read or written by group or other (`chmod 600`); the folder can be entered by group or other (`chmod 700`); the file is not exactly one ECDSA P-256 private key; or a folder from the key folder up to the store folder (`~/.ArcanaGuardian`) can be written by group or other (`chmod go-w`). A folder with the sticky bit set is accepted (that is how a shared temporary folder is made safe: only an entry's owner can rename or remove it). Folders above the store folder are not checked. A new key is created exclusively and atomically (temporary file, flushed, linked into place only when the name is free), so two processes starting together make one key and a crash leaves no half-written key.
3. **Process hardening.** The service and `pair` make the process non-dumpable (no core dump, and no reading of its memory by another process of the same user through ptrace or `/proc`), and keep the memory that holds a key file's bytes and a passkey's PRF output out of swap with `mlock` while it lives. The system may refuse `mlock` (a small `RLIMIT_MEMLOCK`, a container without the capability): the program goes on and writes one warning line (an error number, no content) to the log; raise the limit (for example `--ulimit memlock=-1` or `LimitMEMLOCK=` in a service unit) if you want it. The key objects inside the cryptography library and copies the runtime makes are not covered, and a core dump of the host by root is not prevented.
4. **Limits, stated plainly.** The file key is **exportable by its owner**: a copy is a complete copy of the machine identity, which is why the next two items exist. Backups: **exclude the key folder** (`~/.ArcanaGuardian/keys`) from backups, images and snapshots you share or keep; `arcana-guardian.db` and `host.json` hold no key (section 4). Restoring a machine means pairing it again as a new machine, not restoring a key.
5. **Copied-identity warning.** If two programs use the same identity, the authority sees the machine's connection replaced again and again from different addresses. After **3 such replacements within 10 minutes** (fixed, not a setting) it writes a signed audit event (`machine-identity-possibly-copied`, with the machine fingerprint, both addresses and the count; nothing secret) and the **Machines** screen shows "This machine's identity may have been copied" with the text **Disable this machine if you did not start both.** Nothing is disabled for you: if you started both (a second terminal, a restarted container that has not yet let go), ignore it; if you did not, **Disable** the machine and pair a new one. The warning is kept in `arcana-guardian.db` and goes quiet when the machine is Disabled. Two copies behind one address (a NAT, one Docker bridge) look like one machine and are not detected. [suite Hardening]
6. **No restart after the first approval.** A service started with `--machine-port` before the authority has a signing key (the key is made by the first approval of a machine, section 2) says so and has no machine listener; the listener starts by itself as soon as the first approval makes the key, with the same address and the same rules about who may connect, and the terminal prints one line when it does. If that late start fails (the address is taken), the log says so and a restart tries again. [suite Hardening]

### Test-only isolation (never for real use)

For an end-to-end test of a real Windows authority that must not touch your own keys or store: set both `ARCANA_GUARDIAN_TEST_STORE` (an absolute folder, not `~/.ArcanaGuardian` and not inside it) and `ARCANA_GUARDIAN_TEST_KEY_PREFIX` (3 to 12 lower-case letters or digits) before `using-secrets service`/`pair`. The store, its logs and every CNG key name (machine identity, authority signing keys, the temporary TLS key) then move to the folder and carry the prefix; the keys are still real, non-exportable CNG keys. The program refuses to start with one variable only, a malformed prefix, or the default store.

Cleanup deletes only the prefixed keys. In PowerShell, list with `certutil -user -csp "Microsoft Software Key Storage Provider" -key | Select-String '<prefix> '`, then for each exact name `certutil -user -csp "Microsoft Software Key Storage Provider" -delkey "<prefix> arcana-guardian machine identity v1"` (likewise `<prefix> arcana-guardian authority signing key v1`, ` g2`...). Never delete a name that does not start with your prefix. Remove the test store folder afterwards.

## 9. Troubleshooting

### Exit codes

| Code | Meaning | What to do |
| --- | --- | --- |
| 0 | Success (the child exited 0, a grant was made, a command did its change) | |
| 2 | Usage: bad arguments or secret name, policy refusal, script missing or changed, unknown secret | Read the line printed; `--needs` shows what the project asks for |
| 3 | Denied: Deny on the page, wrong proof, time limit, nothing enrolled, refused change. A run blocked on approval says which: "The user did not approve (denied on the page)" (a person pressed Deny; do not retry) or "Nobody answered before the approval time limit" (nobody tapped in time; nothing ran, ask the user to be ready and run again). The audit records `user-denied` or `approval-timeout` | Ask again; for "nothing enrolled" run `using-secrets admin` |
| 4 | Store error: `arcana-guardian.db` damaged, locked over 5 seconds, other schema, failed signature, cannot decrypt; a folder that still holds `state.db`, `authority.db` or `audit-outbox.db` from an earlier version; also the service could not start; a key file or key folder that Linux refuses (the line names the path and the fix, see "Linux host hardening") | Read the line: it says whether the port is in use or names another reason (then run with `--debug`) |
| 5 | Audit error: the signed audit event could not be committed to the outbox tables in `arcana-guardian.db`, so nothing ran (a change and its event commit together, so neither was written) | Check disk space and the `arcana-guardian.db` file; see reference.md "Audit trail of the host service" |
| 6 | Host service not running (nothing answers on the channel the command line uses) | `using-secrets service` (as the same user that runs the command) |
| 7 | Service not authenticated or channel refused: what answers on the channel is not this machine's service, no identity is pinned yet, or the channel cannot be used safely (another user's or not-private directory, a pipe made at another elevation level) | Stop the other program; for a new machine approve its fingerprint in the app; on Windows run the service and the command at the same elevation level (both as administrator or both not) |
| 8 | Authority locked | Unlock in the app (`using-secrets admin` prints the link) |
| 9 | Service not ready or busy: the host service answered 503 (it has not finished its check-in with its authority, or it already runs 8 launches) | Ask again in a moment; the service keeps trying by itself. If it stays, check the authority is running, unlocked and the key is not lost (section 5) |
| 127 | Program not found or cannot be started | Check PATH and the App Execution Alias |
| other | The child's own exit code, passed through | |

### Common problems

- **Locked.** A run prints `the authority is locked ... Unlock it in the administration web app: http://localhost:8765/admin (one passkey tap; no sign-in is needed to unlock)` (the line the service sends) and exits 8. Unlock with a tap. The service starts locked after every restart by design.
- **Encrypted `.env` values (Dotenvx).** Store the private key in the secret store (the Secrets page, name `DOTENV_PRIVATE_KEY`, or `DOTENV_PRIVATE_KEY_STAGING` for `.env.staging`); the approval page then shows `decrypt with secret DOTENV_PRIVATE_KEY: VARIABLE (cipher sha256 FINGERPRINT) from FILE` and the run decrypts after the tap. `Missing secret: DOTENV_PRIVATE_KEY` (exit 2) means the key is not in the store; `Cannot use the encrypted .env value of VARIABLE` (exit 2) means the value did not decrypt with that key, is damaged, or decrypts to something that is not usable (under 6 or over 4096 characters, or with a NUL, line break or other control character except a tab): the message is the same for every cause on purpose, and the signed audit has a failed launch with the reason `env-decrypt-failed`. A refusal naming a variable (`an encrypted value cannot be given to this variable`) means the name changes which code runs (`NODE_OPTIONS`, `PATH`, a proxy, a git identity): rename the variable. The page warns when the file is not a `.env` or `.env.NAME` directly in the working folder; compare the cipher fingerprint with the committed file, because anyone who has the public key can write an `encrypted:` value. A grant does not cover a changed ciphertext (its SHA-256 is in the fingerprint): the page appears again. With a remote authority the key secret is delivered like any other secret and the host service decrypts; nothing else changes. The audit events carry `decrypts` metadata (`VARIABLE=KEY:FINGERPRINT`), never a value.
- **Pending machine.** The run is refused with the machine's fingerprint and the instruction to approve it in the admin app. Compare the fingerprint with the one the service printed.
- **Port conflict (admin web app).** `the host service cannot listen on port N (the admin web app's port): the port is in use. Is it already running?` (exit 4). Any other start failure is reported as `the host service could not start (<type>)` with a hint to use `--debug`. Another service or program holds the port: use `--port N` for the service, and `--port N` with `using-secrets admin` to get the right link (or `ARCANA_GUARDIAN_PORT`). Runs do not use a port.
- **The channel cannot be made or is taken.** `the host service could not make the channel the command line uses: ...` names the reason: `a service is already running for this user` (one service per user; stop the other, or it is already what you want), `the service directory is not private to this user (mode ..., it must be 700)` or `... is a link` (fix or remove that directory yourself; it is never repaired for you, because another user could have prepared it), `the socket path is too long`. A directory that another user made (`/tmp/arcana-guardian-UID` is in a shared place) is refused with `not owned by this user`; remove it as that user or an administrator and start again. A socket path that is not a socket (a file or directory) or a socket that cannot be told to be stale is left as it is: remove it yourself when you know it is not in use. On Linux a missing `XDG_RUNTIME_DIR` (for example in a bare container or `su`) falls back to `/tmp/arcana-guardian-UID`; on macOS an unset `TMPDIR` does too. A service started as a different user (for example with `sudo`) is a different user's service: run the command as the same user.
- **Different elevation levels (Windows).** `the pipe ... was made by a process the command may not talk to ... different elevation levels` (exit 7): the service runs elevated (as administrator) and the command does not, or the other way round. A process's pipe is owned by the Administrators group when it is elevated and by the user when it is not, and the command only talks to a pipe owned the same way as itself. Start the service and the command from the same kind of terminal. Access is not widened to make it work.
- **Not vouched for.** `the authority has not confirmed this machine as trusted`: the authority cannot be reached or the machine is not Trusted. Ask again in a moment; check the authority is running, unlocked and the machine Trusted.
- **Database format mismatch.** `arcana-guardian.db is not of schema version 4; delete arcana-guardian.db to start over`, or `... still holds state.db, authority.db, audit-outbox.db from an earlier version of Arcana Guardian; delete it to start over (nothing is moved over)` (exit 4). Restore a compatible backup or keep a copy of the old files, delete them and set up a new store (`using-secrets admin`). Nothing is converted. A fresh store has its own machine, grant and audit history.
- **A grant says "This grant is not verified and is not used".** Its seal no longer verifies: the authority key was recovered (a recovery does not reseal), its approving passkey was removed, or the row was edited. It is never used; approve the command again.
- **Review is locked.** Unlock the authority with an admin passkey that supports PRF. An enrolled passkey's session can then open Review on the Grants page.
- **A key file or key folder is refused (Linux).** `using-secrets: the key file ... was not used: ...` or `the key folder ... is not protected / is owned by user N / is a link ...`, exit 4: run the `chmod` or `chown` the line names (section 8, "Linux host hardening"), as the user that runs the service. Nothing is changed or deleted by the program; a key that was made by another user is that user's identity: pair a new machine instead of taking it over.
- **The authority signing key in the key store is not the one arcana-guardian.db names.** Restore on a new machine or a wiped key store: **Recover** in the app (section 4).
- **A host refuses the authority's answers ("not pinned").** The authority key was recovered (no transition): pin it by approving the machine again in the app, or enroll the host again.
- **A page sits on "Checking your passkey...".** Run with `--debug` and read the terminal and the log (reference.md "Logging" and "Troubleshooting").
- **Publish verification fails.** `scripts\verify-publish.ps1` prints one line per failure (loose file, missing embedded asset, version mismatch). Rebuild with `scripts\publish.ps1` after `npm ci` in `src\ArcanaGuardian.Admin.Web`; Node 22 or newer is required.
- **The whole acceptance sequence.** `scripts\verify-all.ps1` stops at the first failing stage and says which.

## 10. Limits to remember

Same-OS-user processes can reach the loopback API and the service's memory; a restored or rolled-back `arcana-guardian.db` can bring back an older state (review machines and grants); grant creation from a remote host, and a Windows service that starts at logon are not built. The full list is in reference.md "Known limits".
- **Variables that change how the program loads code or where it sends data.** When a project `.env` sets an ordinary (visible) value for a name such as `NODE_OPTIONS`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_*`, `PYTHONPATH`, `PYTHONSTARTUP`, `BASH_ENV`, `RUBYOPT`, `JAVA_TOOL_OPTIONS`, `DOTNET_STARTUP_HOOKS`, `PATH`, a `*_PROXY` variable or `GIT_*`, the approval page (local, and at a remote authority) starts with one warning section above the request text and the Approve control: the name and value of each variable, one reason per class (loads code, changes the library path, routes network traffic, changes git behaviour) and the sentence that the approval covers exactly these values. Read the values before you approve. They are passed on to the program as written and are part of the request fingerprint, so a changed value is a new request that needs a new approval. A value the page cannot show (an encrypted value, or a secret reference) is refused for these names, as before. The terminal shows the names and reasons only.

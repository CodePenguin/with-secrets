# with-secrets: architecture

The code is the source of truth (`src/WithSecrets.Core`, `src/WithSecrets`); [reference](reference.md) describes each behaviour and limit in detail, and this page is the design and the threat model. Sections 10.2 and 10.5 hold the design of the machine identity, the authority and the admin application.

## 1. What it is

- A CLI runs a program with secrets in its environment. An agent starts the command; a person approves it.
- The agent supplies secret names and a reason. The CLI does not print secret values, private keys, or the recovery code to agent-visible output. Approved values are injected into the child process environment.
- The person approves on a one-use web page with a passkey (WebAuthn). The same tap releases the secret-store key (WebAuthn PRF).
- Each machine keeps one SQLite file, `with-secrets.db` (one schema, one version), for secret state, authority state, providers and audit; each state change commits in the same transaction as its audit event. The store private key K and the review private key R are persisted only wrapped by the master key. Passkey and recovery slots wrap the master key.
- Terminal output is public (the agent reads it). Values and the recovery code appear only in the browser, apart from approved secret values in the child environment. Same-user process-memory access remains a documented limit (reference.md).

## 2. Components

The diagram below is the existing single-process CLI. It is not the host-service topology accepted in Section 10.2.

```mermaid
flowchart LR
    Agent["Agent (shell)"]
    Term["Person's terminal"]
    subgraph Dev["Person's device"]
        Browser["Browser page"]
        Passkey["Passkey (PRF)"]
    end
    subgraph CLI["src/WithSecrets"]
        Prog["Program.cs"]
    end
    subgraph Core["src/WithSecrets.Core"]
        Wire["CommandWiring + CliArgs"]
        Cmds["Commands: RunCommand, SecretEntry, Enrollment, FirstRunPage, KeyRotation, StoreRecovery"]
        Pages["Pages: OneShotServer, PageFlow, WebApprover, PasskeyMethod"]
        Pol["Policy + ChildRunner"]
        Vault["SecretStore + KeyVault + Manifest"]
        Audit["AdminAudit (signed events, outbox in with-secrets.db)"]
    end
    DB[("with-secrets.db")]
    Child["Spawned program"]

    Agent -->|"argv"| Prog
    Prog --> Wire --> Cmds
    Cmds --> Pages
    Cmds --> Pol
    Cmds --> Vault
    Cmds --> Audit
    Vault --> DB
    Audit --> DB
    Pol -->|"env, no stdin"| Child
    Child -->|"stdout, stderr"| Pol
    Prog -->|"links, results (public)"| Agent
    Prog -->|"links, code prompt"| Term
    Pages <-->|"loopback HTTP"| Browser
    Browser <--> Passkey
```

- `CommandWiring.cs` lives in Core, not in the exe. `Program.cs` parses, opens `with-secrets.db`, runs the gate, then dispatches.
- Every page of one command shares one `OneShotServer` (`PageFlow`), so one port and one link per command.

## 3. Communications

The table describes the current CLI/browser/child-process flow, not the future local-service and authority protocol in Section 10.2.

| From -> to | Transport | What is sent | What protects it |
| --- | --- | --- | --- |
| Agent -> CLI | argv, process start | secret names, reason, program, args | Policy checks before any page; names are not secret |
| CLI -> host service | HTTP/1.1 carried over a **channel only the current OS user can open**: Windows, a named pipe `with-secrets-<user SID>` (access list: the user only, network clients refused; the service and the command at the same elevation level); Linux and macOS, a Unix-domain socket `service.sock` in a directory owned by the user with mode 700 (`$XDG_RUNTIME_DIR/with-secrets` on Linux, `$TMPDIR/with-secrets` on macOS, each only when it is a private per-user place, else `/tmp/with-secrets-UID`; see "Local transport" below). There is no port and no plaintext TCP listener for the command line. `POST /v1/launch` with the canonical `LaunchRequest` JSON and its digest in `X-Request-Digest`, `POST /v1/launch/{id}/cancel`, `POST /v1/identity`, `GET /v1/status` | the request (names, pairs, reason, program, arguments, folder, the `.env` plan, the inherited environment), never a secret value | The OS: another user cannot open the channel (pipe access list; socket directory 700 and socket 600; on Linux and macOS the kernel-recorded peer user of each connection is checked too). The application: the client pins the service's machine identity and the service proves it before anything is sent (`/v1/identity`); `Host` must be a local name, no `Origin` header, JSON only, body max 1 MB with a 15 s read timeout, strict parse, digest, version and expiry checked. Reaching the channel is not authority: every request still needs its approval, and secrets open only after a passkey tap. A process of the same user is outside this boundary (see "Local transport" below) |
| Host service -> CLI | the response body of `POST /v1/launch`: NDJSON, one event per line (`approval` with the page link, `output` with redacted text and the stream, `result` with the outcome and the exit code) | the public link, redacted output, the exit status | **Public by design.** No event has a member that could hold a value; output is redacted in the service before it is sent |
| CLI -> Agent / terminal | stdout, stderr | one-use link, names, admin fingerprint line, redacted child output, exit code | **Public by design.** Never values, keys, recovery code |
| Person -> CLI | terminal stdin | the 6-digit confirmation code (first-time setup, adding a passkey, new store of `--recover`) | Read only after the last tap, 3 tries, prompt is the last line (`TerminalPrompt`) |
| Host service -> browser | HTTP on 127.0.0.1 and [::1] (the admin web app's port: `service --port N`, `WITH_SECRETS_PORT`, else 8765; a one-use approval page: setting `port`, `--port N`, else free). With `baseUrl` (http or https; passkeys need https or localhost): that name pointed at the port, or `ssh -L PORT:localhost:PORT` | HTML page, inline script and style allowed by CSP hash, data block (request text, bind, challenges) | Token: 16 random bytes in the path, fixed-time compare, 404 for anything else. Headers: strict CSP (`default-src 'none'`, `connect-src 'self'`), `no-store`, `nosniff`, `X-Frame-Options: DENY`, `no-referrer`. Both loopback addresses held, `ExclusiveAddressUse` on Windows |
| Browser -> CLI | POST `proof`, `deny`, `seal`, `save`, `create`, `sign`, `code` (body max 1 MB, 15 s body timeout) | passkey assertion or attestation, reuse minutes, PRF output, typed secret values, recovery code | See rows below. First outcome of a step is final, later requests get 404 |
| Browser <-> passkey | WebAuthn in the browser | challenge, assertion, PRF eval of the slot salt | Each prompt starts in its own tap (iOS rule). RP ID is the page host, passkey ignores ports |
| PRF output, browser -> CLI | inside the proof POST | 32 bytes sealed: fresh ECDH P-256 key, HKDF-SHA-256 (salt = bind, info `with-secrets/v1 prf`), AES-256-GCM (bind as AAD) to the page's own server key | Sealed to a key that lives for that page only. A passive observer (tunnel that ends TLS) sees ciphertext. An active man in the middle who replaces the page key is not stopped (reference.md) |
| Secret values, browser -> service | `seal` POSTs while typing (max 500 per page) | each value sealed the same way (own HKDF info `with-secrets/v1 secrets`) | Page server key per page. The Save tap signs `SHA-256(bind \|\| SHA-256(ct) \|\| SHA-256(manifest))` |
| Recovery code, browser -> CLI | `--recover` code page | code sealed to the page key | Never in terminal, log, audit or `with-secrets.db`. A typed code is not origin-bound: compare the printed admin fingerprint first |
| Lost reply | page resends the same body (3 tries: 8 s, 8 s, 20 s; `deny` one try of 20 s) | same bytes | Steps that lead on (`proof`, `create`, `sign`, `code`) keep one reply per verified body (SHA-256 of body, fixed-time compare), in memory until the command ends. No second page, no second code. Other steps (`save`, `seal`, `deny`): a resend after the outcome gets 404 and the page says the program already finished |
| CLI and service <-> `with-secrets.db` | SQLite, WAL, `synchronous=FULL`, one transaction per write (a change and its audit event in the same one); inside a process every writer first takes the one writer gate of the file (`WithSecretsDatabase.Write`), so writers of one process never meet in SQLite's busy handler; between processes the 5 s busy timeout decides; the first creation of the file is serialized between processes by an operating-system lock on `with-secrets.db.lock` beside it (a persistent file that is never removed: `flock` on Linux and macOS, the share mode on Windows; released by the system when a process ends; refused, not worked around, when the file is not a private regular file of this user or the lock does not exclude) | manifest, ciphertext rows, sign counts, authority, provider and outbox rows | Manifest signature checked before use (exit 4). Writes check the version they replace |
| Host service -> spawned program | environment (the sender's inherited block, minus the denylist, plus ordinary `.env` values and the approved secrets), argv, closed stdin | only the approved secrets as env vars | Denylist, no stdin, redacted output (section 7) |
| Network diagnostics | Debug log events: terminal only with `--debug`, and the log file | method, route word, whole seconds, sizes, verdict words | No path, token, body, key or value (`NetLog` words, constant `AppLog` templates) |

### Local transport (CLI to host service)

The command line and the host service speak one application protocol (the `/v1` routes, the canonical request JSON and digest, the identity challenge, the NDJSON answer stream, cancellation by the client leaving). Only the channel that carries it differs by platform, behind one small abstraction (`LocalEndpoint`): the service listens on it, the client connects through it, and the same handlers answer on every channel. Remote machine-to-machine transport (TLS 1.3, HTTP/2, mutual authentication) is a different path and is unchanged.

| Platform | Channel | Who can open it |
| --- | --- | --- |
| Windows | named pipe `with-secrets-<user SID>` | the access list allows only the current user's SID and denies network (remote) clients; the first instance is created exclusively, so no other program can take the name first; the client asks for a pipe owned by the owner of its own token and does not let the service act as it. **Service and command run at the same elevation level** (see below) |
| Linux | Unix socket `$XDG_RUNTIME_DIR/with-secrets/service.sock` (else `/tmp/with-secrets-UID/service.sock`) | the directory must be a real directory owned by this user with mode 700 (a link, another owner or any other mode is refused, not repaired); the socket is mode 600; each connection's peer user (`SO_PEERCRED`) must be this user |
| macOS | Unix socket `$TMPDIR/with-secrets/service.sock` (else `/tmp/with-secrets-UID/service.sock`) | as Linux (`LOCAL_PEERCRED`). Machine transport to an authority is not available on macOS; this local channel is |

- **Where the directory is.** `XDG_RUNTIME_DIR` (Linux) or `TMPDIR` (macOS) is used only when it is an absolute path to a directory that this user owns and no one else can write to, and not a shared system directory (`/tmp`, `/var/tmp` and the like). When it is unset or unsuitable (macOS gives `/tmp` when `TMPDIR` is unset, which is shared) the directory is `/tmp/with-secrets-UID`, a different name for every user. In the shared `/tmp` another user can create that name first; the service and the command then find a directory that is not theirs and refuse it (the service does not start, with the reason): a denial of service at worst, never a takeover and never a connection through it. The owner, the type and the mode of the directory are read from the file system itself, not from the path.
- **One service per user.** A socket that something answers on is never replaced or removed: a second `with-secrets service` fails with that reason. A socket left by a service that is gone is replaced, and only then: it must be a socket (not a file, a directory or a link) owned by this user, and the probe connection must be *refused*, which is what a socket with no listener answers. No permission, a busy probe, an unexpected error or anything that cannot be told leaves the file alone and the start fails with the reason. The pipe's first-instance rule gives the same on Windows.
- **Windows elevation.** The service and the command run as the same user at the same elevation level. The owner of a process's token is the user for a normal process and the Administrators group for an elevated one, the pipe is owned by its creator's token owner, and the client (.NET's `CurrentUserOnly`) accepts only a pipe owned by its own token's owner; a pipe made at the other level is therefore refused (.NET source, `NamedPipeClientStream.Windows.cs`, the CurrentUserOnly check; seen on the CI runners, which are elevated). Both tokens hold the user's SID, so the access list would let each in; letting the client accept either owner would also accept a pipe that any administrator account made, so it is not done. The command says so (exit 7, "different elevation levels") instead of "not running". Start both from the same kind of terminal.
- **No fallback.** If the channel cannot be made safely (a directory that is not private or not this user's, a link in the way, a path that is not a socket, a path too long for the platform) the service does not start, and says why. The client never falls back to a port: with nothing on the channel a run exits 6.
- **Two surfaces, two listeners.** The channel serves only the command line's routes (`/v1`). The browser administration (`/api`, `/admin`) is served only on the loopback port, which serves nothing of `/v1`. Each connection is marked with the listener it came on and a request for the other surface is answered 404, so the browser administration is no way around the channel's access control and the command line's routes cannot be reached by a process that merely opens a port.
- **Threat model.** The channel keeps other OS users from the launch interface: they cannot connect, read a request or an answer (program names, arguments, working directory, environment declarations), inject or replay a request, or disturb a running launch or approval. A process that runs as the same user is outside this boundary, as before: it can already read the user's files and act as the user.
- **What the loopback port shows other local users (reviewed).** Any local user can open the admin web app's address and the one-use approval pages' ports, so what they can learn without the user's passkey was checked: before a session the API answers only the status (running, locked or unlocked, the unlock mode, versions) and the OpenAPI document; every other read needs a session, which is a cookie together with its own secret and is made only by an administrator's passkey; every change needs its own fresh tap. An approval page is a one-use address whose path holds a 128-bit random token and is given to the person through the terminal, so another user cannot guess it. Program names, arguments, working directories, environment declarations and secret names are therefore not visible to other users over the loopback port; they travel only on the user's own channel. What a local user can still learn is that the service runs and whether it is locked.

What is public: everything on stdout/stderr. What never leaves the browser: typed values (only sealed), the recovery code in plaintext (only sealed on `--recover`, shown on the page once), the passkey private key, the raw PRF output.

## 4. Key hierarchy

```mermaid
flowchart LR
    PRF["Passkey PRF output (32 bytes)"]
    KEK["Slot KEK"]
    Slot["Key slot wrap (per passkey)"]
    MK["Master key MK"]
    Vault["Vault"]
    K["Store key K (Dotenvx private key)"]
    Rows["secrets rows (ECIES secp256k1)"]
    Vals["Secret values"]
    Code["Recovery code (20 bytes)"]
    RK["Recovery key RK"]
    RSlot["Recovery slot wrap"]
    RVault["Review vault"]
    R["Review key R (Dotenvx private key)"]
    Evidence["Grant evidence rows (review text)"]

    PRF -->|"HKDF-SHA-256, salt = slot salt, info with-secrets/v1 slot"| KEK
    KEK -->|"AES-256-GCM, AAD cred id + salt"| Slot
    Slot -->|"unwrap"| MK
    Code -->|"HKDF-SHA-256, salt = recovery salt, info with-secrets/v1 recovery"| RK
    RK -->|"AES-256-GCM, AAD with-secrets/v1 recovery + store public key"| RSlot
    RSlot -->|"unwrap"| MK
    MK -->|"AES-256-GCM, AAD with-secrets/v1 vault + store public key"| Vault
    Vault -->|"unwrap"| K
    K -->|"Dotenvx decrypt, requested rows only"| Rows
    Rows --> Vals
    MK -->|"AES-256-GCM, AAD with-secrets/v1 review + review public key"| RVault
    RVault -->|"unwrap"| R
    R -->|"Dotenvx decrypt, only while review is open"| Evidence
```

| Secret | Lives | Zeroed |
| --- | --- | --- |
| PRF output | In the passkey. In the page as a plain `Uint8Array` until sealed: the page scripts never overwrite it (garbage collection only). Server: opened from the sealed payload into `Unlock` (bytes) | `Unlock.Dispose` after the run read its values (every exit path). Registration copies zeroed after the slot is wrapped |
| Slot KEK | Process memory during wrap or unwrap | `KeyVault` finally blocks |
| Master key MK | `with-secrets.db` only as slot wraps and the recovery slot. Plain in memory during a run, adding a passkey, rotating the store key, `--recover`, the first-time setup, opening R | After use (`SecretValues.Clear`) |
| Store key K | `with-secrets.db` only as the vault. Plain as bytes plus a hex string during decrypt | Bytes zeroed. The hex string cannot be wiped (.NET) |
| Review key R | `with-secrets.db` only as the review vault. In the service, `ReviewKeys` keeps a pinned byte array after a PRF tap of an admin passkey (`unlock` or `review-unlock`). Encrypts grant review text. Writing needs only its public key | The service wipes the pinned bytes on lock, shutdown and store-key rotation. Dotenvx uses .NET hex strings for the private key during generation, validation and decryption, including decryption during rotation. Those strings cannot be wiped |
| Decrypted values | Bytes in `SecretValues`, strings in the child env and the redactor | Bytes when the child ends. Strings cannot be wiped |
| Recovery code | Offline, written by the person. Server makes it at the first-time setup, `--recover`, the rotation of the store key, formats it for the page | Code bytes zeroed when the page ends (the first-time setup, `--recover`) or after the slot is built (the rotation of the store key); the formatted text is a string and cannot be wiped. `--recover` holds the old K in `RecoveryCarry` until the end |
| Slot salt | Manifest. One shared salt per store (the first key's), because the page can pass one `eval` salt. The PRF output still differs per passkey | Not secret |

Facts that follow from this: `with-secrets.db` alone cannot decrypt anything, neither secrets nor review text. A same-user agent that reads process memory during a run can get K (reference.md "The secret store"). Removing a passkey does not rotate MK or K. Rotating the store key (admin web app) does.

## 5. Signed state

The manifest is one row in `with-secrets.db`, as canonical JSON, signed by an admin passkey.

| Item | Detail |
| --- | --- |
| Contents | version `v`, `keys` (id, name, public key, alg, rp, created, admin flag, slot salt and wrap), `store` (store public key), `vault`, `review` (review public key and its MK-wrapped vault; present exactly when `store` is), optional `recovery` slot, `secrets` (name -> SHA-256 of ciphertext), `settings` |
| Not in it | sign counts (table `sign_counts`), the secret ciphertext itself (rows table, covered by the hashes) |
| Signature | admin assertion over `SHA-256(bind \|\| SHA-256(manifest text))`. Stored with its authenticator data and client data |
| Who may sign | a key that is an admin in the **stored** manifest and stays one. A key that only becomes admin in the new manifest cannot sign it. An admin cannot approve its own removal. The last admin cannot be removed |
| Verify before use | `Program.cs` runs `state.Gate` before every command. Failure prints `with-secrets: state failed verification: delete with-secrets.db to start over (only if you did not edit it)` (or the damaged or other-schema message) and exits 4. `--help` and bad arguments exit before the gate. Verified manifests are cached per process |
| Rows | every `SecretStore` read (a run, a secret change in the admin app, the rotation of the store key, `--recover`) checks every row against its signed hash (the gate checks integrity and the manifest only): a swapped row, a row with no hash or a hash with no row is exit 4 |
| Writes | one transaction: manifest, rows and the signed audit event appended to the outbox tables on the same connection (`AppendIn`); a failure anywhere rolls back both, so there is never a change without its event nor an event without its change. Refused when the stored version is not the one the page started from |
| Sign counts | stored beside the manifest, unsigned. An assertion must raise the count. An agent can inflate them (denial of service only) |
| Fingerprints | first 8 bytes of SHA-256 of each admin public key, 4x4 hex. Shown on every page (part of the signed text), and in the terminal before `--recover` and the rotation of the store key. Detects a replaced state |
| Grants | rows in `grants` hold the evidence text encrypted to R (`evidence_ciphertext`), the proof, nonce, kind and minutes in clear, and a seal (`review_key`, `seal_key`, `seal`) signed by the authority key in the transaction that writes the row. Every use checks the seal against the active authority key, the current review public key and the approving passkey's enrollment, and never decrypts. Revoked and invalidated rows keep no evidence and no seal |
| Audit | no hash chain: every administrative event is a signed event of type `admin` (machine key, per-machine sequence, unique id) in the outbox tables of `with-secrets.db`, uploaded to the authority. Integrity: the signature, the id, the sequence and the authority's acknowledgement. A same-user writer can still delete the outbox |
| Schema | `with-secrets.db` schema version 3, checked at open (`PRAGMA quick_check`, the version and the exact table layout). Other versions, and folders that still hold `state.db`, `authority.db` or `audit-outbox.db`, are refused ("delete it to start over"), never migrated |

Gaps (agent deletes `with-secrets.db` and builds its own state, restore of an older copy, rollback) are in reference.md "Admin keys" and "Known limits".

## 6. Flows

Legend: **TAP** is a passkey prompt (one per user tap). Page moves on by itself when a reply carries `next`. Participants: P person, T terminal, C with-secrets process, B browser and passkey.

### 6.1 First-run setup (`with-secrets admin`, nothing enrolled)

```mermaid
sequenceDiagram
    actor P as Person
    participant T as Terminal
    participant C as with-secrets
    participant B as Browser + passkey
    P->>T: with-secrets admin (own terminal)
    C->>T: one-use link
    P->>B: open link
    B->>C: GET page (settings form, defaults)
    P->>B: name the passkey, Save (Step 1)
    Note over B: TAP 1 create passkey with PRF
    B->>C: POST create (attestation, PRF output sealed to page key)
    C->>C: refuse before storing if no PRF
    C->>C: in memory: MK, store key pair K, vault, slot, recovery code, recovery slot, first manifest v1
    C->>B: first manifest
    P->>B: Step 2
    Note over B: TAP 2 new passkey signs the manifest (becomes first admin)
    B->>C: POST sign
    C->>B: 6-digit code, recovery code, fingerprints (page only)
    C->>T: Waiting for the code from the page
    P->>T: type the 6-digit code (3 tries)
    C->>C: one transaction: manifest, settings, audit
    C->>C: zero MK, K, PRF output
    C->>T: result and Admins fingerprint line
```

### 6.2 Store secrets (admin web app, Secrets page)

```mermaid
sequenceDiagram
    actor P as Person
    participant T as Terminal
    participant C as with-secrets
    participant B as Browser + passkey
    C->>C: gate, rows match signed hashes
    C->>T: link of the admin web app
    P->>B: open link, type values
    loop while typing
        B->>C: POST seal (values sealed to page key)
        C->>C: decrypt, check, encrypt to store public key
        C->>B: next manifest (names and hashes only)
    end
    Note over B: TAP 1 admin signs SHA-256(bind, SHA-256(ct), SHA-256(manifest))
    B->>C: POST save (assertion)
    C->>C: verify, then one transaction: rows, manifest, audit
    C->>B: Stored NAMES
```

No PRF and no master key: storing a secret only needs the store public key. Removing a secret is a tap signing the next manifest without those hashes.

### 6.3 Run approval

```mermaid
sequenceDiagram
    actor P as Person
    participant A as Agent
    participant C as with-secrets
    participant B as Browser + passkey
    participant X as Child program
    A->>C: --secrets A,B --reason R -- PROGRAM ARGS
    C->>C: gate, names in store, Policy.Check (grammar), resolve on PATH, full paths
    C->>C: read script and program file, fingerprint, hash check
    C->>A: link (stderr, public)
    A->>P: shows link
    P->>B: open link
    B->>C: GET page: full command, Inline code, Script contents, secrets, folder, reason, fingerprints
    P->>B: read it all, Approve once (after a short delay)
    Note over B: TAP 1 assertion and PRF in one prompt
    B->>C: POST proof (assertion, PRF output sealed to page key)
    C->>C: verify assertion over SHA-256(bind, reuse=0), then open PRF payload
    C->>C: audit row approved, fingerprint recheck, hold files
    C->>C: unwrap slot, MK, vault, K, decrypt ONLY requested rows
    C->>X: start (env: approved secrets, no denylist vars, stdin closed)
    X-->>C: stdout, stderr
    C->>C: zero values, audit row finished
    C->>A: redacted output, exit code
```

Deny, wrong proof, any error or the time limit gives exit 3 and the audit row `denied`. If the audit row cannot be written nothing runs (exit 5).

Since Phase 1 the participant "with-secrets" is two parts: the CLI (parses, reads the `.env` once, prints, exits with the reported code) and the host service (everything from the policy checks to the exit status). The CLI sends a `LaunchRequest` and receives the events in section 3. The service prepares the child and its environment, then commits through a `LaunchGate` (a lock and an authorization revision): the process starts only if the launch was not cancelled and the revision is unchanged since it began; otherwise the prepared environment is discarded and the launch ends `cancelled` (exit 3, audit row `finished`, nothing ran). After the start nothing touches the child; a later invalidation does not stop it.

### 6.4 Enroll a passkey (admin web app, Passkeys page)

```mermaid
sequenceDiagram
    actor P as Person
    participant T as Terminal
    participant C as with-secrets
    participant B as Browser (admin host)
    participant N as Browser (new key host)
    C->>T: one link
    P->>B: open link
    Note over B: TAP 1 admin approves and releases PRF (opens MK)
    B->>C: POST proof
    C->>B: next (enroll page, new token)
    B->>N: page moves on by itself
    P->>N: choose name, tick Also make this key an admin or not
    Note over N: TAP 2 create new passkey with PRF
    N->>C: POST create (PRF sealed)
    C->>C: new slot for MK, next manifest with the new key
    alt same host
        Note over N: TAP 3 (Step 2) admin signs the new manifest
        N->>C: POST sign
        C->>N: 6-digit code
    else base URL host differs from admin keys host
        C->>N: next (admin signing page at admin host)
        Note over B: TAP 3 admin signs the new manifest
        B->>C: POST sign
        C->>B: 6-digit code
    end
    C->>T: Waiting for the code from the page
    P->>T: type code (last step)
    C->>C: one transaction: manifest, audit. Zero MK, PRF output
```

The code is generated at registration but shown only on the last page. Nothing is stored before it is typed. Removing a passkey is a single approval page where another admin signs the manifest without that key.

### 6.5 Rotate keys (admin web app, Settings, Secret store key)

```mermaid
sequenceDiagram
    actor P as Person
    participant T as Terminal
    participant C as with-secrets
    participant B as Browser + passkey
    C->>T: Admins fingerprint line, compare with your note
    C->>T: one link
    P->>B: open link (page lists keys that will be removed)
    Note over B: TAP 1 admin key S approves and releases PRF
    B->>C: POST proof
    C->>C: open old MK, K. New K, MK. Re-encrypt every row. Only S gets a slot. New recovery slot
    C->>B: next (Step 2 page)
    Note over B: TAP 2 same key S signs the new manifest (bind covers the new rows)
    B->>C: POST sign
    C->>C: one transaction: manifest, rows, audit key-rotated
    C->>B: new recovery code (page only, once)
    C->>T: result, no key, no code
```

Failure or timeout between the taps changes nothing. The link and the fingerprint line are printed in the terminal of the service.

### 6.6 Recover (`--recover`, all passkeys lost)

```mermaid
sequenceDiagram
    actor P as Person
    participant T as Terminal
    participant C as with-secrets
    participant B as Browser + passkey
    C->>T: Admins fingerprint line, compare with your note
    C->>T: one link
    P->>B: open link, type the recovery code
    B->>C: POST code (sealed to page key)
    C->>C: recovery slot, MK, vault, old K. Three wrong codes end it
    C->>B: next (first-setup page on a new empty state)
    Note over B: TAP 1 and TAP 2 as in 6.1 (new passkey, new keys)
    C->>C: re-encrypt old rows one at a time for the new store key
    C->>B: 6-digit code, new recovery code
    C->>T: Waiting for the code from the page
    P->>T: type code
    C->>C: snapshot with-secrets.db, replace store rows and append recovery events
```

The snapshot preserves the previous database. Recovery replaces the signed manifest, sign counts and encrypted secret rows in the live file and commits the audit events with them.

## 7. Policy and child process

| Area | Rule | File |
| --- | --- | --- |
| Secret names | `NAME` or `folder/NAME` (up to 3 folders, 200 characters in all; the last segment UPPER_SNAKE_CASE, no `DOTENV_` prefix; folders `[A-Za-z0-9_.-]{1,64}`, not `.` or `..`). One validator for all commands, the whole path is the store name and is data only. Every name must be listed (no `--all`). A secret change in the admin app: 1 to 20 names | `Contracts.cs` (`SecretNames`), `SecretEntry.cs`. Values: 6 to 4096 characters |
| Program lookup | `env`, `printenv`, `set` are refused (they print the environment). PATH entries that are absolute only. Working directory not searched unless the program has a slash or backslash. Windows App Execution Aliases refused | `ChildProcess.cs` (`ProgramResolver`), `RunCommand.cs` |
| Paths | program and script are expanded to full paths. What is checked, shown and run is the expanded form. They must read the same as the typed form | `RunCommand.cs`, `Paths.cs` (`PathExpander`), `Policy.cs` |
| Command grammar | Interpreters in one strict form only: `PROG script [args]` or `PROG -c/-e CODE` (sh family, python, node, perl, ruby), PowerShell: `-NoProfile` required, then `-NonInteractive`, `-NoLogo`, `-ExecutionPolicy VALUE` (once each), then exactly `-File` or `-Command`; `cmd /d /c` (or `/k`, `/r`) with a tail of letters, digits and `. _ : \ /` `-`, first word a `.cmd`/`.bat` file or echo, dir, type, ver. Encoded commands, a bare interpreter and code starting with a dash are refused. Other programs: no analysis, `Run:` line only (a text-file program is still shown). Matches reference.md "Known limits" and `--help` | `Policy.cs` |
| Limits | command max 16,000 characters. Inline code shown: first 4,000 characters. Script max 1 MB (page shows first 200 lines or 16 KB). Script must exist, be text, and be readable. Batch files ASCII | `Policy.cs`, `RunCommand.cs`, `ApprovalSummary.cs` |
| Page text | every line of code prefixed `  \| `. Control, bidi and zero-width characters replaced by a mark. Part of the signed text | `ApprovalSummary.cs` |
| Fingerprint | covers names, every variable-to-secret pair, the `.env` paths and ordinary variable names (when a `.env` is used or a variable differs from its secret), full program path, folder, and path and hash of the script and of the program file (when 1 MB or less). Recomputed after approval. A changed file denies | `Reuse.cs`, `RunCommand.cs` |
| File lock | shown files opened `FileShare.Read` until the child ends (nobody can write, delete or rename them) and hashed again. Windows runs the file itself. Elsewhere the system cannot lock a file, so the checked bytes are written once to a private folder (owner only, outside the project, read-only, checked again) and the child is told to run that copy, under the same name; it is deleted when the child ends. The working folder, arguments and environment are unchanged. The copy's folder also holds a link to each entry of the original's folder (none above 1000 entries), made without opening or following anything, so a script that finds neighbours by its own location (`dirname "$0"`, `BASH_SOURCE`, `Path(__file__).resolve().parent`, `$PSScriptRoot`) still does; those neighbours are read as they are when used, never as shown or approved. `$0`, `__file__` and the like are the copy's path, `..` is the private folder, and a new file cannot be written beside the script. In the step that starts the child the copies are checked again by path (hash, plain files, owner-only modes, folders not links). The child opens the file a moment later by its path, so a process of the same user (which owns the folder) can still change it in that gap; that is not prevented, and that process can already read the child's environment from `/proc`. What a script loads from beside itself is not covered by the approval, and the page says so | `RunCommand.cs` (`HeldFiles`) |
| Environment | removed before launch: `DOTENV_PRIVATE_KEY*`, `NODE_OPTIONS`, `BASH_ENV`, `ENV`, `PYTHONPATH`, `PYTHONSTARTUP`, `PYTHONHOME`, `PERL5OPT`, `RUBYOPT`, `LD_PRELOAD`, `DOTNET_STARTUP_HOOKS`, `JAVA_TOOL_OPTIONS`, five `GIT_*` names (`GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM`, `GIT_EXEC_PATH`, `GIT_SSH_COMMAND`, `GIT_ASKPASS`), `SHELLOPTS`, `BASHOPTS`, `PS4`, `PS0`, `PROMPT_COMMAND`, `BASH_FUNC_*` and more (case-insensitive on Windows). Full list in `ChildRunner.CodeLoadingVariables` and reference.md. Known gaps: reference.md | `ChildProcess.cs` |
| Stdin | closed right after start: the child reads end of file | `ChildProcess.cs` |
| Launch | `.cmd` and `.bat` start as `cmd.exe /d /c "path" args` (no AutoRun). Arguments with quotes or `& \| < > ^ % !` are refused for cmd | `ChildProcess.cs`, `Policy.cs` |
| Output | read as UTF-8, redacted by `StreamRedactor` (chunk splits and common forms). Reversed, split, compressed or encrypted copies are not caught | `Redaction.cs` |
| Terminal-only commands | `--recover` and the first-time setup of `admin` (nothing enrolled) refuse when input, output or error is redirected (exit 3). `--needs` does not check | `CommandLine.cs`, `Program.cs` |

## 8. Trust boundaries

This table describes the current single-process implementation. The future local API trust model is described separately in Section 10.2. What the agent can and cannot do, and the known limits: reference.md "Known limits", "Admin keys" and "The secret store". Summary:

| Actor | Capability | What stops it |
| --- | --- | --- |
| Agent (same OS user) | start a run, read terminal output, hold links | Cannot tap the passkey. Link is one-use and shows the whole request. Enrollment codes need a human typing in a real terminal |
| Agent | read `with-secrets.db` | No key on disk: K and R are only wrapped, MK only under PRF or the recovery code. Secret rows and grant review text are ciphertext |
| Agent | edit `with-secrets.db` (keys, settings, rows, slot, vault) | Manifest signature and row hashes fail: exit 4 on every command. An edited, copied or planted grant row fails its seal and is never used |
| Agent | delete `with-secrets.db` and write its own signed state | **Not prevented.** Visible: admin fingerprints change on every page |
| Agent | restore an older `with-secrets.db`, rewrite audit and chain, inflate sign counts | Accepted limits (reference.md) |
| Agent | read process memory during a run | **Not prevented.** K, MK, PRF output and values are in memory for that moment (reference.md) |
| Agent | change the script or program after the page showed it | Fingerprint recheck, file hold (Windows) |
| Agent | pass options or env that load unshown code | Strict grammar, environment denylist, closed stdin. Gaps listed in reference.md |
| Another local process | serve a look-alike page on localhost | Server holds both loopback addresses exclusively. Passkey RP ID ignores ports, so check the printed link before tapping (reference.md) |
| Network observer (tunnel) | read page traffic | PRF output and secret values are sealed to the page key. Active man in the middle is out of scope |
| Child program | print or send secrets | Output redaction only. A program that sends its environment out is out of scope |
| Lost admin device | still opens the store with an old `with-secrets.db` copy | Rotate the store key in the admin web app (keeps one key). Removing a passkey alone does not rotate MK or K |

## 9. Exit codes and error paths

| Code | Meaning | Typical causes |
| --- | --- | --- |
| 0 | success | run: the child exited 0. approve: the grant was made. Commands: change made, `--help` |
| 2 | usage | bad arguments, two commands, invalid or unknown secret name, policy refusal, script missing, too large or not text, changed while the request was built, command too long, App Execution Alias |
| 3 | denied | Deny on the page, wrong proof, time limit, internal error in a session (`HandleGuard`, text says only `internal error`), files changed while the page was open, file hold failed, nothing enrolled, no terminal for a human command, refused change |
| 4 | store error | `with-secrets.db` damaged, locked over 5 s, other schema, a folder that still holds `state.db`, `authority.db` or `audit-outbox.db`, failed signature or row hash, unusable settings, cannot decrypt |
| 5 | audit error | the audit row could not be written, or (behind the host service) the signed audit event could not be committed to the outbox tables of `with-secrets.db`, so nothing ran (a change and its event commit together) |
| 6 | host service not running | a run could not reach the host service (`with-secrets: the host service is not running. Start it with: with-secrets service`); nothing was asked and nothing ran |
| 7 | service not authenticated | the CLI could not verify that what answers is this machine's host service (no answer to the identity check in 5 s, a wrong or replayed answer, another fingerprint than the one pinned in `host.json`, an unreadable `host.json`), or no identity is pinned yet (the fingerprint is printed; an administrator approves it in the admin web app, which pins it); nothing was sent |
| 8 | authority locked | a run or approve reached the host service while the authority is locked (the service starts locked); nothing was asked and nothing ran. The line names the admin page where an administrator unlocks it with a passkey tap |
| 9 | service not ready or busy | the host service answered 503: it has not finished its startup check-in with its authority (it keeps trying and becomes ready by itself, for example after the authority key was recovered), or it already runs 8 launches; nothing was asked or run. Ask again in a moment |
| 127 | not found | program not on PATH, or the process cannot be started |
| other | the child's own exit code | passed through on a run |

Every web session ends on the first outcome. Deny, error and silence all end in a denial, never an approval. Gate failures happen before any link is printed.

## 10. Machines, the authority and the admin application

The machine/authority and administration design in 10.2 and 10.5 is implemented except where the current-implementation notes say otherwise; 10.3 is an agreed design and provider implementations/mount configuration are not yet built. The "current implementation" paragraphs state exact behaviour; the rest of each section is the design it follows.

Not built: a Windows service that starts at logon; a macOS Keychain machine key store (macOS uses the owner-only key file, like Linux); privilege separation (the service under another OS account); Dotenvx profile selection and `--env` layering, and `${VAR}` expansion in `.env` (not planned through `Dotenvx.Core`, see 10.1); secret providers, mounts and namespaces (designed in 10.3). Hand tests with real phones, a tunnel and a screen reader are open.

### 10.1 Project environment declarations and Dotenvx

**Status:** Implemented in `EnvDeclarations.cs`. with-secrets reads project `.env` files with its own bounded parser and uses `Dotenvx.Primitives` only for the cryptography of the `encrypted:` format.

#### Ownership boundary

- `Dotenvx.Primitives` (version 3.3.1, `WithSecrets.Core.csproj`) supplies the cryptography and nothing else: key pairs, `Encrypt` and `Decrypt` of the `encrypted:` ECIES format. `DotenvxCipher` (`SecretStore.cs`) wraps it. The same `DotenvxCipher` encrypts the values in the secret store and decrypts the `encrypted:` values in project `.env` files; they are one mechanism and one format, not two.
- with-secrets owns the `.env` parser (bounded, one declaration per line, no expansion, no multiline), file selection and composition, classification of the effective declarations, `secret://` resolution, approval and request binding, audit, and the decision to launch the child.
- `Dotenvx.Core` is not used to parse project `.env` files or build the launch plan. Its parser expands `${...}` and evaluates `$(...)` commands, and its `ParseOptions` cannot turn either off, so using it for that job would execute commands while a launch plan is being built. Its provider integration is a separate concern: `Dotenvx.Core` may be used by the dedicated Dotenvx provider adapter described in 10.3, without bringing its parser or command evaluation into the with-secrets launch-planning path.
- Dotenvx's `.env` syntax is followed where the parser supports it; where Dotenvx supports more (expansion, evaluation, multiline values), with-secrets does not.

#### File selection and composition

- The default project file is `.env` in the command's working directory. Parent directories are not searched.
- Explicit repeatable `-f` / `--env-file` selection uses exactly the supplied files and replaces the default. A missing default `.env` means there are no project declarations; an explicitly selected missing file is an error.
- Dotenvx profile selection and `--env` layering are not supported. No profile is inferred from ambient variables such as `NODE_ENV`.
- Within a file, a name repeated on several lines takes the last line. Across files, the first file wins per name (`EnvDeclarations.cs`). An existing variable of the environment beats an ordinary value as documented there.
- Files are composed first; only the final effective value of each variable is classified. An overridden `secret://` reference is never requested, approved, or decrypted.
- `${VAR}` expansion is not supported (see the "Not built" list above).

#### Declarative model

Selected project environment files may contain ordinary configuration, `encrypted:` project values, and external secret references:

```dotenv
API_URL=http://localhost:5000
LOG_LEVEL=Debug
API_KEY=<encrypted: value>
GITHUB_TOKEN=secret://team/development/github/token
DATABASE_PASSWORD=secret://personal/database/password
```

- The left side is the child environment-variable name; the right side of a `secret://` declaration is a logical secret path. They may differ, for example `STRIPE_KEY=secret://team/payments/STRIPE_PRODUCTION_KEY`.
- Comments are not declarations.
- Ordinary values remain ordinary configuration. `encrypted:` values remain encrypted in project files and are decrypted by with-secrets with `DotenvxCipher`. External `secret://` values are resolved by the selected with-secrets provider adapter; a logical path does not select Dotenvx or any other provider by itself.
- An explicit `secret://` declaration must not silently be satisfied or replaced by an inherited environment variable. Inherited-environment and encrypted-value precedence are those of `EnvDeclarations.cs`.
- A missing mount, denied permission, unavailable provider, missing secret, or required credential is a hard error. No fallback, cross-provider search, silent substitution, or alternate-name prompt.

#### Discovery, approval, and launch

- Keep `--secrets NAME[,NAME...]` for explicit requests and compatibility; it composes with effective declarations from the selected project files.
- `--needs` is read-only discovery. It reports selected files, ordinary variable names, effective variable-to-secret mappings, and whether references are resolvable. It does not approve, decrypt, or display secret values.
- A `--needs` result is informational, not authorization or a trusted cached plan. The run independently recomputes and validates its plan.
- Do not scan source code for environment-variable usage; dynamic lookups make this unreliable and language-specific. The request set is selected declarations plus explicit `--secrets`.
- The approver sees selected file paths, effective secret mappings, and ordinary values; plaintext secret values are never shown. Agent/terminal-facing output shows names and paths only.
- Bind selected file paths, effective declarations, ordinary values, secret mappings, command/script, working directory, request identity, and expiry to the approval fingerprint/signature. Approval, audit, and launch use the same immutable request snapshot; changing a file while approval is pending must not change what launches.
- Preserve protected-variable rules: secret references cannot target code-loading variables, process-selection variables such as `PATH`, `PATHEXT`, or `COMSPEC`, proxy variables, or git identity variables. A denylist is not a complete security boundary; showing ordinary values to the human approver remains required.
- Do not expose the Dotenvx private key or plaintext secrets to the agent.

### 10.2 Local service, machine identity and direct authority communication

This section records the design of the service, the machine identity, the authority and its audit, and what is built of it.

#### Goals and operating model

- The CLI is backend-agnostic. It communicates only with its local host service through one shared API/protocol, whether the service fulfills requests from a local authority or connects directly to one configured remote authority.
- The host service is the trusted execution boundary: it validates requests, obtains authorization, resolves and decrypts approved secrets, prepares the child environment, and owns the final launch decision. The CLI is a client; it does not independently retrieve secret values or make the final launch decision.
- Each independently installed host service has its own machine identity. Windows and WSL installations are separate identities. Docker launched through the host-side CLI uses the host service and host identity; the host service launches the Docker client with approved values in its process environment and passes variable names, not secret values, in Docker command arguments. Values are not written to Docker volumes or secret files. The container receives them as environment variables; it does not run an independently enrolled service or hold a machine key.
- A host service operates with one authority:
  - **Local authority:** the host service also performs the authority role and owns/accesses the local provider/store and authoritative security state.
  - **Remote authority:** the host service connects directly to its one configured remote authority. That authority owns authoritative machine records, grants, provider access, and approval decisions; the local host service retains only its permitted in-memory cache and working authorization state.
- Each host has exactly one configured authority identity and endpoint. There is no authority selection, automatic fallback, alternate authority, relay, reverse tunnel, or multi-hop routing in the initial design. Changing authority requires an explicit administrative operation.
- The authority endpoint address is routing information only. The enrolled authority machine identity is the trust identity; changing DNS name or IP address does not change that identity or silently change trust.
- Remote hosts are assumed to be directly addressable at their configured endpoint. Multi-hop routing and intermediaries are deferred until a concrete requirement exists.
- Secret delivery to a child remains ordinary environment variables. The agent does not receive secret values, private keys, or recovery codes.

#### Local clients and transport

The CLI and host service use one application protocol regardless of the local carrier: the same routes, request models and canonical JSON, request digest, identity challenge, streamed NDJSON answers, cancellation, and error semantics. A small transport abstraction selects the local channel; do not create transport-specific application protocols or change child-process behavior to accommodate a transport.

| Client path | Transport and boundary |
| --- | --- |
| Windows CLI → Windows host service | Named pipe, named per user SID. The pipe ACL allows only that user's SID and denies network clients; the client also verifies that the pipe belongs to the owner of its own token. The service and CLI must run at the same elevation level. |
| Linux CLI → Linux host service | Unix-domain socket in a private per-user directory; directory mode 0700 and socket mode 0600, with kernel peer-UID verification. Prefer a safe `XDG_RUNTIME_DIR`; otherwise use a per-user directory under `/tmp`. |
| macOS CLI → macOS host service | Unix-domain socket in a private per-user directory; directory mode 0700 and socket mode 0600, with kernel peer-UID verification. Use `TMPDIR` only when it is a private per-user location; otherwise use a per-user directory under `/tmp`. |
| Browser → authority administration | Separate loopback-only HTTP listener on the authority host. It serves the browser application/API, not the CLI launch routes. Non-authority host services do not expose this listener. |
| Host service → remote authority | Separate HTTPS connection using TLS 1.3, HTTP/2, and mutual machine-certificate authentication. |

- There is no plaintext TCP fallback for CLI-to-host communication. If the named pipe or Unix socket cannot be created or verified safely, the service fails to start or the CLI refuses to connect; it must not fall back to a port.
- The CLI authenticates the host service's machine identity over the local channel before sending the launch request. The OS channel protects the request and response from other OS users; machine identity pinning protects against an unexpected service. Reaching the channel is not authorization: grants, current authority vouching, and approval policy still apply.
- WSL has its own independently enrolled WSL host service and machine identity. Its service communicates with the Windows host service over the existing authenticated HTTPS/mTLS machine protocol. Do not trust a request merely because it originates on a WSL network interface.
- The browser listener is separate from both the local CLI channel and the machine-to-machine listener. It is enabled only on the authority host, binds only to loopback, and uses the browser session, origin/CSRF protections, and fresh operation-bound passkey authorization defined in Section 10.5. Browser passkeys authorize human administrative operations; they are not machine credentials.
- The machine-to-machine listener requires TLS 1.3 and HTTP/2. Exactly one route is exempt from requiring an already-enrolled, trusted client certificate: the pairing route defined below. No other route is unauthenticated or available to an unknown, disabled, or untrusted machine. Health, status, diagnostics, and discovery remain authenticated.
- The local IPC boundary protects against processes running as other OS users, not malicious processes running as the same user. Same-user process-memory access and actions performed with the user's own privileges remain outside the threat model.
- Docker launched as a child execution target through the host-side CLI uses that host service and host machine identity. The host service starts the Docker client with approved values in its process environment and passes variable names, not secret values, in Docker command arguments. Values are not written to Docker volumes or secret files. The container receives them as environment variables; it does not need direct service access, an identity-key volume, or an independently enrolled service. A separately installed with-secrets host service inside a Docker environment is a distinct machine and must have its own identity and enrollment.
- The machine listener uses HTTP/2 only. It does not fall back to HTTP/1.1 or TLS 1.2. The browser listener remains independently compatible with ordinary browser-supported HTTP.
- The machine API uses the shared, versioned HTTP API and OpenAPI contract. Transport authentication identifies the calling machine; application authorization still evaluates every request independently.
- This is a developer-machine trust model, not isolation from malicious processes already running with the developer's privileges. Such processes may be able to interact with local services or inspect same-user process memory.
- Docker is launched through a host-side CLI request. The host service owns the launch and supplies approved values to the Docker client through its process environment. The container does not need direct service access, a separate machine identity, an identity-key volume, or secret files.

#### Machine identity and enrollment

- Each host service generates and securely retains its own ECDSA P-256 machine identity private key. The key signs; it is not used to encrypt or wrap secrets.
- The machine fingerprint is SHA-256 of the canonical public key (SubjectPublicKeyInfo) and is the stable cryptographic identity. It is not a certificate thumbprint. A friendly name is authority-managed display metadata, not identity.
- Initial machine identity creation also creates a required self-signed X.509 identity certificate using the existing persistent ECDSA P-256 identity key. It introduces no additional persistent private key. The certificate is a CA-capable trust anchor (`BasicConstraints CA=true`, `pathLen=0`) with `DigitalSignature` and `KeyCertSign` key usage and a 10-year validity period. Its public certificate is stored as machine metadata and included in enrollment.
- Enrollment verifies that the identity certificate contains exactly the public key supplied for the machine identity, verifies its self-signature and required CA/key-usage properties, and then follows the normal Pending/Trusted approval process. Possession of a valid certificate does not itself establish trust.
- Each running host-service instance creates a separate temporary ECDSA P-256 TLS key pair in memory. Its temporary leaf certificate is signed by the persistent machine identity key, is not a CA, has `DigitalSignature` key usage and both `serverAuth` and `clientAuth` EKUs, and is valid for 24 hours. The same temporary certificate/key is used for TLS server and client authentication. The temporary key is distinct from the persistent identity key and is never persisted.
- The temporary certificate's SAN contains a URI identifying the machine, in the form `urn:with-secrets:machine:<identity-fingerprint>`. The SAN is a lookup hint only; certificate signature/chain validation proves that the identified machine issued the certificate. Missing, malformed, or ambiguous identity SANs are rejected without trying other identities.
- A temporary certificate is rotated in memory one hour before expiry. New TLS handshakes use the replacement; existing connections may finish. A service restart generates a new temporary key and certificate.
- No external CA, OS trust-store installation, or separate persistent TLS private key is required. Peers validate the temporary leaf against the enrolled machine identity certificate as a custom trust anchor.
- Identity-certificate renewal uses the same persistent identity key and therefore preserves the machine fingerprint. A replacement certificate with the same public key, valid self-signature, required certificate profile, and acceptable validity is accepted without administrator re-enrollment. A different public key is a new machine identity and requires explicit enrollment/approval.
- Machine identity key replacement is a separate security-sensitive trust transition. It is never automatic; the old identity is revoked and the new identity is explicitly enrolled and approved. Existing grants do not transfer automatically. If the old key is unavailable, the replacement is treated as a new machine identity; there is no automatic recovery or hostname/IP-based continuity.
- The private key is kept outside ordinary application data. On a developer machine it is protected by the host OS. For Docker-launched workloads, the host service retains the key; no Docker volume contains it.

- A new machine is paired with a one-time invitation created by an administrator in the authority's admin web interface. The invitation contains the authority URL, a unique invitation identifier, a randomly generated 128-bit pairing code, and a fixed short expiration. The authority stores only protected derived key material needed to verify the invitation proofs; it never stores or logs the plaintext code.
- The invitation is a local credential bundle, not a network message. The CLI parses the authority URL, invitation identifier, and code locally. The code is never placed in a URL path/query/fragment, command-line argument, HTTP header/body, log, diagnostic, or agent-facing output. It may be entered through a hidden terminal prompt or supplied unattended through a dedicated environment variable or protected secret store (including a Docker secret); a protected secret store is preferred to an environment variable. The pairing credential must not be inherited by launched child processes.
- Pairing first contacts only the pairing route over TLS 1.3/HTTP/2. The server certificate is provisional at this stage: the client accepts it only for this bootstrap exchange and only after structural certificate checks. The request contains only the invitation identifier and a fresh client nonce, not the machine identity or pairing code. The authority returns its public identity certificate, a fresh server nonce, and an HMAC-SHA-256 proof keyed by the invitation code and bound to a domain separator, invitation identifier, authority identity fingerprint, and both nonces. The client verifies the authority certificate profile and fingerprint and verifies the HMAC before trusting or sending machine registration data. A substituted authority certificate cannot produce the required proof.
- After authenticating the authority, the new machine establishes a fresh TLS 1.3/HTTP/2 connection pinned to that exact authority identity certificate. It presents its self-signed machine identity certificate and submits its public identity, fingerprint, host name, a fresh registration nonce, proof of possession of its persistent identity private key, and an HMAC-SHA-256 proof keyed by the pairing code. The registration proof is domain-separated and bound to the invitation identifier, machine fingerprint, host name, and registration nonce. The code itself is never transmitted. The authority accepts an unknown machine certificate only on the pairing route and only after validating the certificate structure and registration proofs.
- The pairing route does only two things: bootstrap delivery and proof of the authority identity certificate, and machine registration that creates or refreshes a Pending record. It returns only public authority certificate material and the minimal registration result. It never returns secrets, machine records, grants, or other authority state, and never accepts launch, secret, grant, or authorization requests. All other routes require a validated client certificate belonging to a currently Trusted and enabled machine.
- Successful registration and invitation consumption are one atomic, idempotent authority operation. A consumed invitation cannot register another machine. A retry of the same committed registration request may retrieve its original non-secret result without creating another registration. Failed proofs are rejected and bounded; expired or consumed invitations cannot be used. Concurrent claims cannot both succeed. A repeated registration using the same fingerprint refreshes its existing Pending record; it does not reset Disabled or Untrusted records to Pending or bypass any existing trust transition.
- The authority invitation is single-use and short-lived, with fixed limits on failed attempts, concurrent pairing registrations, pending registrations, and request size. These are built-in limits, not user-configurable quotas or reputation controls. Expiration, refusal, failed attempts, and approval are durably audited without recording the pairing code or derived proof material.
- After registration, the machine remains Pending and cannot request secrets or create grants until an administrator verifies its fingerprint and host name in the admin web interface and approves it using fresh, operation-bound passkey authorization. The authority's public signing key remains separately pinned through this authenticated approval flow; the pairing code does not replace administrator approval or authorize secret access.
- Pairing can run interactively or unattended using the same protocol. In unattended startup, the host service consumes the supplied invitation credential without prompting; the credential remains unavailable to agents and child processes. The authority's URL and identity are pinned only after successful proof verification. An optional out-of-band authority fingerprint may be supplied as an additional check, but is not required when the pairing-code proof succeeds.
- The authority records the host name established at enrollment. Requests present both fingerprint and current host name; both must match. A mismatch is rejected and recorded as pending for administrator review. The administrator explicitly approves a legitimate host-name change in the admin web interface. A mismatch does not silently change the binding or delete the enrollment.
- Friendly-name changes are display-only, may be made at any time, and do not invalidate grants or cache. They are audited.
- Machine listing, details, status changes, friendly-name changes, host-name change approval, and audit history are managed through the admin web interface.

#### Machine status and authorization invalidation

The authority retains machine records and their history. A previously known Untrusted fingerprint is not treated as a new Pending machine.

| Status | Meaning | Secret access |
| --- | --- | --- |
| Pending | Newly discovered and not yet approved | Denied |
| Trusted | Approved and trusted | Allowed subject to grants and approval |
| Disabled | Temporarily suspended by an administrator | Denied |
| Untrusted | Administrator has explicitly withdrawn trust | Denied |

- Pending → Trusted requires explicit administrator approval and assignment of a friendly name.
- Trusted → Disabled and Trusted → Untrusted invalidate all grants and authorization state.
- Disabled → Trusted is an ordinary re-enable, but starts clean: no old grants or cache are restored.
- Untrusted → Trusted requires an explicit confirmation identifying the machine. It also starts clean.
- Disabled and Untrusted have the same access-control effect; the distinction records administrative intent.
- Every administrative action that invalidates a machine's authorization increments a monotonically increasing security revision for that machine fingerprint. The revision is per machine, not global. Display-only friendly-name changes do not increment it.
- A revision change invalidates the machine's entire cache and all grants. No selective preservation is attempted.
- Status changes, revision changes, grant invalidation, and cancellation of pending work are recorded in the authority audit history.
- Disabling or untrusting a machine also invalidates its active authenticated machine connections. The receiving host stops accepting new requests on those connections, initiates HTTP/2 `GOAWAY`, and closes remaining connections after a bounded grace period. Per-request authorization and the secret-release checkpoint remain authoritative; connection closure is defense-in-depth, not an authorization cache.

#### Cache, grants, startup, and reconnection

- The authority's native store and mounted-provider cache may persist secret values only as encrypted ciphertext. Both native entries and mounted-provider cache entries use the same Dotenvx.Primitives-based at-rest encryption mechanism and the same native store data-encryption key K, protected by the existing master key MK and passkey/recovery unlock hierarchy. Do not create a separate mounted-cache encryption key, password, or unlock path. Mounted entries remain read-only because of their ownership and lifecycle, not because they use a different cryptographic subsystem. Only a successful authority unlock that makes the existing secret-data key hierarchy available can rehydrate stored values. Locking or restarting the authority clears decrypted values and usable key material from memory; ciphertext remains stored.
- Host services do not persist secret values or usable authorization state. Their synchronized grants and working authorization state are memory-only and are rebuilt only after successful authority reconciliation. The authority's encrypted native-store and mounted-cache ciphertext is not copied to hosts and does not create an offline-use mode.
- Durable grants live at the authority. Keep indefinite grants available as an explicit, passkey-approved choice for standing workloads. Any enrolled passkey, admin or not, can approve one; extending, renewing, replacing or revoking a grant requires an admin passkey. When the same scope would otherwise need repeated renewal or reapproval, an indefinite grant avoids repeated approvals while preserving the online authority check and signed audit event for every use. The grant has no scheduled expiry. Each launch still requires the authority to verify the grant and its exact scope, fails closed if that check cannot be completed, and remains subject to central revocation. A timed grant gives the administrator a scheduled point to reconsider continued access. Revocation blocks further use of the grant and cancels pending launches when the host applies it. An already-launched process can retain credentials it received.
- The CLI exposes `with-secrets approve COMMAND` and `with-secrets run COMMAND`. `approve` performs the normal request validation and human approval flow to create or update a grant, but does not launch the command. `run` performs the same normal validation and uses an applicable, unexpired grant without prompting; it does not bypass request scope or constraints. Preapproval is limited to the approved grant scope, not blanket permission.
- An active grant may be extended, an expired grant renewed, or a grant revoked through an authority-controlled operation. The authority is the source of truth for all grant changes. A host cannot use an extension or renewal it has not received. No previously synchronized grant authorizes use while the authority is unreachable; grant validity alone is not sufficient without current authority vouching.
- An administrator may extend an active grant's expiration without repeating the original approval, but the operation requires fresh, operation-bound administrator passkey authentication. The extension preserves the grant's exact existing scope: it cannot add secret paths, commands, working directories, machines, or other permissions. The new expiration must be permitted by the authority's grant-lifetime policy.
- A once-only grant that has not yet been consumed may have its lifetime/usage policy corrected by an administrator through the same authenticated operation, without changing its scope. If it has already been consumed, the authority may issue a replacement grant with the same scope and a new lifetime; the consumed grant remains in history and is not silently reactivated. An expired grant may be renewed under the same scope-preservation rule. A revoked grant cannot be extended or renewed; it requires a new approval.
- Each extension, correction, renewal, or replacement is recorded as a distinct audited administrative action linked to the original grant. The original approval and grant history are retained. Changing the approved scope is not an extension and requires a new approval.
- At startup, the host service must authenticate to its authority and reconcile machine status, host-name binding, and security revision before accepting secret requests. If the authority is unavailable at startup, the service cannot accept new requests.
- After successful startup reconciliation, if the security revision is unchanged, the authority may restore still-valid grants into host-service memory. The authority must be unlocked before it can rehydrate encrypted native-store or mounted-provider cache values. Mounted values are refreshed from their providers as needed; host services never persist their own plaintext or encrypted secret-value cache. If the revision changed, old grants are not restored.
- If the authority becomes unreachable, every grant check fails closed immediately. The host does not continue using a previously synchronized grant or cached secret value under an offline grace period. A remote host drops and zeroes its held store key when its authority link fails; it must re-establish authenticated connectivity and successfully check in before secret use can resume. The same rule applies to local-authority mode: if the local authority cannot perform the authorization check, the request is denied. A service restart, lock, trust change, or loss of authority vouching clears the relevant in-memory authorization state and held key. There is no offline-authorization lease or offline secret-use mode.
- Losing connectivity prevents new secret use; it is not a grace period. The authority records revocations durably and distributes them to connected hosts; a host applies a received revocation immediately, clears affected grants/cache and held key, and refuses the revoked fingerprint. Reconnection requires a fresh authenticated check-in and reconciliation before secret use resumes.
- The authority invalidates grants and in-flight requests when a security transition occurs and delivers the existing invalidation messages through authenticated HTTP/2 long polling. Each host maintains one outstanding long-poll request; the authority holds it until the existing protocol has an invalidation message to deliver. The response carries the existing message payload without redefining it. The host acknowledges through the existing acknowledgment operation and immediately issues its next long poll.
- Long polling changes only the transport. Preserve the already-defined invalidation message contract, sequencing, acknowledgment semantics, retry/retention behavior, duplicate handling, security-revision rules, host-side cleanup/cancellation, and reconnect reconciliation unchanged. Do not introduce a new event schema, sequencing model, delivery guarantee, heartbeat, periodic empty polling, WebSocket, custom streaming protocol, or message broker.
- The host cancels its own affected pending work and clears the affected cache, grants, and held key before acknowledging. It never inspects, signals, suspends, terminates, or otherwise interacts with already-launched child processes.
- Invalidation events are notifications, not the source of truth. On every reconnect, the host authenticates and obtains current status and security revision before resuming requests. If the revision differs from the last successfully synchronized revision, it purges all cached secret values and authorization state even if the machine is Trusted again.
- Duplicate or older invalidation events are ignored by revision. An acknowledgment is sent only after cleanup and cancellation of pending pre-launch work completes. If cleanup fails, no acknowledgment is sent; reconnect reconciliation remains the fallback.
- Reconciliation is limited to the security state needed to establish cache validity; it does not require downloading all machine configuration.

#### Process launch and invalidation race

- The host service prepares the child process and its environment without launching it. Secret values are held only in the service's working memory and the prepared child environment; they are not returned to the CLI as a separate secret response.
- Immediately before process creation, the host service performs a final authorization check and commits the launch against its current local authorization state. The service, not the CLI, owns this launch boundary.
- Launch commit and local invalidation handling are serialized so only one wins the race.
- If invalidation wins, the pending launch is cancelled and the prepared environment is discarded.
- If launch wins, the child is considered launched. Later invalidation must not inspect, signal, suspend, terminate, or otherwise interact with it.
- Secret-bearing launches require current authority vouching at the final authorization checkpoint. If the host cannot reach its authority or has lost vouching, the launch is denied; there is no offline-cache policy. Once a child has been launched, later invalidation does not inspect, signal, suspend, terminate, or otherwise interact with it.

#### Machine-to-machine HTTPS, TLS, and certificate validation

Machine-to-machine communication uses ordinary HTTPS with TLS 1.3 mutual authentication. TLS replaces the former custom application-level ECDH handshake, transcript signatures, HKDF session-key derivation, AES-GCM message wrapping, and per-message sequence encryption. Do not implement a second encrypted channel inside HTTPS.

**TLS and HTTP requirements**

- Require TLS 1.3 and HTTP/2 for every machine-to-machine connection. Do not fall back to TLS 1.2, HTTP/1.1, or plaintext.
- Use the platform TLS implementation through .NET. Do not implement TLS, invent cipher suites, or add third-party cryptography dependencies.
- Disable TLS 0-RTT and TLS session resumption initially. A new connection performs a fresh certificate-authenticated handshake.
- Keep healthy HTTP/2 connections persistent. Do not impose maximum connection age or idle timeouts. Ordinary network failure detection still applies.
- Kestrel selects the current temporary certificate for each new server handshake. Clients use a new connection pool after their temporary certificate rotates; existing connections in the old pool may drain and finish in-flight work. Dispose the old pool after draining, with a bounded shutdown timeout. Do not interrupt healthy connections solely because the certificate used at their handshake later expires.
- Disable automatic HTTP redirects and ambient system HTTP proxy use for machine connections. A 3xx response is an unexpected protocol response, not permission to connect to another endpoint. Endpoint changes require explicit configuration/administration. Never forward machine credentials or client certificates to another destination.
- Disable all HTTP caching for the machine API, on both clients and servers. Every response uses `Cache-Control: no-store`; do not emit `ETag`, `Last-Modified`, or other cache validators, and do not support conditional requests. No intermediary/reverse-proxy caching is permitted.
- Disable HTTP compression in both directions. Do not negotiate compressed request or response bodies.
- Use `application/json` with UTF-8 for machine API requests and responses. Reject unsupported media types and content encodings. Do not support multipart, form-encoded, XML, or alternative representations.
- Use the existing canonical JSON rules wherever signatures or request digests depend on serialization. Keep the API versioned under `/api/v1/` and described by the shared OpenAPI contract.
- Every endpoint except the single pairing route requires a successfully authenticated client certificate for a currently Trusted and enabled machine before application processing. The pairing route is the only exception and is restricted to the bootstrap and registration operations described in the Machine identity and enrollment subsection. A structurally valid but unknown client certificate may complete the TLS handshake provisionally only so that the pairing route can validate it; middleware/endpoint enforcement must reject it on every other route. No health/status/diagnostics/discovery exception exists.
- Machine API errors use standard HTTP status codes and structured JSON error codes with a correlation/request ID. Never return stack traces, filesystem paths, secret values, provider credentials, private keys, or internal cryptographic details. Do not redirect to browser login pages.

**Pairing route and bootstrap trust**

- The pairing route is the sole exception to the requirement for an already-enrolled, trusted client certificate. It remains on the machine listener and still requires TLS 1.3 and HTTP/2; it is not a plaintext or general anonymous HTTP endpoint.
- During the initial bootstrap connection, the client may provisionally accept a structurally valid authority TLS certificate only for the pairing route. The client sends only the invitation identifier and a fresh nonce. The authority returns its public identity certificate and an HMAC-SHA-256 proof keyed by the invitation code, bound to a domain separator, invitation identifier, authority fingerprint, and both nonces. The client verifies the proof and certificate profile before sending machine identity, host name, or registration data. It then opens a new TLS connection and validates the authority's temporary TLS certificate against the exact authority identity certificate just authenticated.
- The pairing route may provisionally complete a TLS client-certificate handshake with a structurally valid but not-yet-enrolled machine certificate. This provisional acceptance grants access only to the pairing handler. The handler validates the self-signed identity certificate profile, verifies that the presented temporary leaf is correctly signed by that identity, verifies proof of possession of the persistent identity key, and validates the invitation-code registration HMAC. Unknown certificates are rejected on every other route, before any route-specific work.
- The pairing code is never transmitted. Both proofs use HMAC-SHA-256 with domain separation and fresh nonces; the authority retains only protected derived key material until the invitation is consumed or expires. Proofs bind the invitation identifier and the relevant authority or machine fingerprint, preventing certificate substitution and cross-protocol reuse.
- The route has fixed built-in limits for request size, concurrent registrations, pending registrations, and failed code attempts. It supports only authority-certificate bootstrap and machine registration. It does not expose machine details, grants, secrets, diagnostics, health, discovery, launch, or authorization operations.

**Machine certificate validation**

- The persistent machine identity key remains the stable identity. The 10-year self-signed identity certificate is the enrolled trust anchor; the 24-hour temporary leaf certificate is used for TLS handshakes.
- For an inbound client certificate, read the machine identity fingerprint from its SAN URI, locate that exact enrolled identity certificate, and validate the temporary leaf chain against that certificate using a narrowly scoped custom-root trust policy. Verify the leaf signature, validity, CA=false constraint, key usage, both required EKUs, and expected identity. Then check that the machine is currently trusted and enabled.
- For an outbound connection, validate the server's temporary certificate against the one configured authority identity certificate. Verify the SAN identity and chain against that exact expected identity. Do not try other enrolled identities or accept an arbitrary valid certificate.
- DNS names and IP addresses are routing information only, not machine identity. A hostname mismatch may be accepted only after the expected enrolled machine identity and certificate chain have been successfully verified. Never disable certificate validation globally.
- Endpoint address and expected authority identity are separate configuration values. Changing an address does not change trust; changing authority identity requires an explicit administrative operation.
- The authority's public signing key remains separately pinned through administrator-approved enrollment. It is not replaced by the TLS certificate or machine identity key.

**Authentication, authorization, and release**

- The server derives the caller's machine identity exclusively from the successfully validated TLS client certificate. The client cannot select or override its identity through an HTTP header, URL, or JSON field. Any machine identifier supplied as a target/resource is untrusted input and is independently authorized.
- Machine authentication identifies the calling host; it does not grant blanket access. The authority checks current machine status, grant scope/expiration, policy, and security revision independently for every API request. An established connection is never a standing authorization.
- The authority performs a final authorization checkpoint immediately before releasing a secret. This checkpoint is the linearization point for concurrent release and revocation: if revocation takes effect first, release is denied; if the checkpoint succeeds first, that release may complete. A secret already delivered cannot be recalled.
- Revocation stops new requests, closes active connections, and cancels pending work where practical. It does not inspect, signal, suspend, or terminate already-launched child processes, and cannot retract a secret already delivered.

**Connection recovery, retries, and resource limits**

- If a persistent connection fails, the client reconnects directly to the same configured authority using the current temporary certificate, with bounded exponential backoff and jitter. There is no alternate authority, insecure fallback, reverse tunnel, or relay.
- Each logical operation has a unique request ID. Retries of durable/idempotent operations reuse the same ID; the authority records processed IDs and results atomically with the operation so a committed mutation is not executed twice.
- Read-only metadata requests may be retried when safe. Administrative mutations use the existing idempotency mechanism. A secret release whose response is lost has an ambiguous outcome and is not automatically retried; the client may make a new request, which is independently authorized at the current release checkpoint. Do not persist secret values merely to replay a response.
- Use fixed, built-in resource safeguards appropriate for a development tool: modest global and per-machine concurrent-request limits, bounded request bodies, and operation-specific timeout defaults. These are implementation constants, not user settings, environment variables, or deployment configuration. Do not add request-per-second quotas, adaptive throttling, reputation scoring, or elaborate abuse detection. Reject excess concurrent work rather than queueing it without bound.
- Cancellation propagates to server work where safe. A timeout or disconnect does not prove that an operation did not complete.
- Durable authority operations remain atomic in SQLite. Machine records/statuses, security revisions, grants, signing-key metadata/rotation history, audit history, processed request IDs/results, pending invalidation state, and encrypted native-store/mounted-provider secret ciphertext are durable. Decrypted secret values, usable data-encryption keys, and host working authorization/cache state remain memory-only.
- A machine disable/untrust operation atomically updates status, increments security revision, invalidates grants, and records the audit event. Grant approval atomically records approved scope, expiration, and audit event.
- Do not add a message broker or distributed transaction system.

**Application-level signatures and key separation**

- TLS authenticates live connections and protects ordinary API traffic. Do not sign every ordinary HTTP request or response on top of TLS.
- Retain application-level signatures for durable authority-issued records whose authenticity must survive beyond a live connection, including grants and other durable authority-issued security records. Verify these signatures against the separately pinned authority public signing key.
- Continue signing durable host audit events with the machine identity signing key. The authority verifies those signatures, deduplicates event IDs, and tracks per-machine sequence numbers.
- Keep machine identity signing keys, authority signing keys, and secret-data encryption/wrapping keys cryptographically separate. The machine identity key also signs its temporary TLS leaf certificates; it is not used to encrypt or wrap secrets. The authority signing key is not the machine TLS key.
- Routine authority signing-key rotation is authorized by a transition signed by the currently trusted authority key. If that key is compromised or unavailable, replacement requires explicit authenticated administrator recovery; an unknown key is never trusted automatically.
- Dotenvx/store encryption remains separate from transport encryption. The existing store ciphertext format is unchanged.

#### Direct authority routing

- The initial design connects each host directly to its one configured authority over HTTPS/mTLS.
- No relay, opaque forwarding service, central router, HTTP CONNECT tunnel, reverse tunnel, mesh discovery, or multi-hop routing is part of the initial implementation.
- The configured endpoint is directly addressable. The host validates the expected authority machine identity independently of the endpoint address.
- A future intermediary or multi-hop route may be considered only when a concrete requirement exists. It must preserve the same end-to-end machine identity, authorization, and API contract; it must not become an authority or policy layer.

#### Request replay protection and durable authority state

- Every logical operation has a unique request ID. A retry of the same durable operation reuses that ID; the authority records processed IDs and results in the same SQLite transaction as the operation, so a committed operation is not executed twice.
- Secret-release requests are not automatically replayed after an ambiguous transport failure. The client must not infer success or failure from a timeout; a new release request requires current authorization and a new release checkpoint.
- Durable operations are idempotent. Stored results are operation metadata, not secret values or decrypted payloads.
- Machine records and statuses, host-name bindings, friendly names, public keys and identity certificates, security revisions, grants and expirations, signing-key metadata and rotation history, audit history, processed request IDs/results, and pending invalidation delivery state are durable.
- A machine disable/untrust operation atomically updates status, increments security revision, invalidates grants, and records the audit event.
- Grant approval atomically records the approved scope, expiration, and audit event.
- Authority key rotation atomically records the new key and its authenticated trust transition.
- A committed operation remains committed after a crash; an uncommitted operation has no partial effects.
- The authority signing private key is not stored in plaintext in the SQLite database. It is protected separately using an OS-protected key store or equivalent protected secret storage; SQLite contains public trust material and metadata, not the plaintext private key.

#### Audit events, delivery, and administration

- The authority is the durable source of audit history. The local host service maintains a SQLite outbox for events not yet acknowledged by the authority.
- Audit every authorization attempt, including denied attempts, and every use of a grant. Record the authorization decision separately from the launch outcome and execution outcome. Secret-bearing launches fail closed if the audit event cannot be durably committed.
- Each event contains a unique event ID, a per-machine monotonically increasing sequence number, event timestamp, machine identity, project/working directory, executable and arguments, grant ID when applicable, authorization decision, launch outcome, and execution result when available (including exit code or termination status). Do not record an OS user identity; the local API does not authenticate individual same-user callers.
- Record command arguments only after secret redaction. Never record secret values, private keys, or decrypted secret material.
- The host signs each event with its machine identity private key before committing it to the local SQLite outbox. The event must be durably committed before a secret-bearing child process is launched.
- Upload is asynchronous. The host retries unacknowledged events; the authority verifies the machine signature, deduplicates by event ID, and tracks per-machine sequence numbers so missing events or sequence gaps can be detected. The authority acknowledges durable receipt. Acknowledged events may then be removed from the local outbox.
- If the local audit database is unavailable, corrupt, or full and an event cannot be durably committed, fail closed for secret-bearing launches. Non-secret commands may continue.
- Audit retention is controlled by the authority. The admin web interface provides searchable audit history with filters for machine, project/working directory, time range, authorization outcome, and launch/execution outcome. Do not add audit export in this phase.
- Do not add a hash chain to the new host/authority audit protocol. Signed events, unique IDs, per-machine sequence numbers, and authority acknowledgements provide the required integrity and gap detection within the documented developer-machine trust boundary. A compromised same-user process or administrator-level attacker may still tamper with local state or misuse the host identity; the protocol does not claim to prove completeness or truthfulness of records produced by a compromised host.

#### Authority key protection, startup lock, and administrator authentication

The authority has two distinct security concerns: making its protected key hierarchy available to perform its work, and authenticating an administrator who authorizes sensitive administrative changes. Unlocking the authority is not blanket administrator authorization.

**Startup and unlock policy**

- The authority process may start while its protected key hierarchy remains locked. In the locked state it must not serve secret-related requests, resolve or release secrets, use grants to authorize secret-bearing launches, or perform administrative changes that require protected keys.
- **Manual unlock is the default.** An administrator must explicitly unlock the authority before it begins serving secret-related requests.
- **Unattended unlock is opt-in.** An administrator may explicitly configure the authority to unlock after startup using a platform-protected mechanism appropriate to that deployment. This option must be visibly enabled and documented as a weaker protection against an attacker who can control the running host or invoke its OS key-protection facility.
- Unattended unlock changes only how the authority's key hierarchy becomes available after startup. It does not bypass administrator authentication for sensitive operations.
- The exact cross-platform key-protection mechanism and the manual-unlock ceremony remain implementation/design details to validate against the existing passkey-PRF vault and each supported deployment platform. Do not assume DPAPI, Keychain, a Linux keyring, or a hosted KMS is universally available or equivalent. Do not claim absolute security; document the threat model and platform-specific limits.
- Locking the authority must discard usable in-memory key material, the mounted-cache encryption key, and decrypted cached secret values as far as the runtime permits. Persisted cache ciphertext remains unusable until the same authority unlock process makes its wrapping key available again. Health/status endpoints may report that the process is running but locked; they must not disclose protected material.

**Sensitive administrator operations**

- Sensitive administrative operations always require a fresh passkey authentication with user verification, regardless of whether the authority was manually or automatically unlocked.
- The authentication challenge must be bound to the specific operation and its security-relevant parameters (for example, target machine, grant scope and expiration, key identity, or settings being changed). It must be single-use, time-limited, and protected against replay. A previously authenticated web session or an earlier unlock does not satisfy this requirement.
- At minimum, sensitive operations include administrator passkey enrollment/removal/replacement; machine trust, disable, untrust, or re-trust transitions; grant creation, scope/expiration/usage-policy changes, extension, renewal, replacement of a consumed once-only grant, and revocation; secret and provider-credential creation, replacement, or removal; security-setting and unlock-policy changes; and authority-key recovery or rotation.
- Recovery is a separate, tightly controlled ceremony. A recovery code or unattended-unlock key is not a routine substitute for fresh passkey authentication on sensitive operations.
- Failed or unavailable passkey authentication fails closed. There is no fallback to an ordinary password, an unlocked authority session, or unattended-unlock material for these operations.
- Sensitive-operation attempts and outcomes are durably audited without recording passkey secrets, PRF output, recovery codes, or private key material.

**Grant use is not an administrative operation**

- A valid, applicable, unexpired grant authorizes routine use within its approved scope without another human approval or passkey prompt. Requiring a passkey for every grant use would defeat the purpose of preapproval and is not part of this design.
- Passkey authentication is required to create or change the grant, not to exercise it. Grant scope, expiration, machine status, security revision, and current authority vouching continue to be enforced on every use.
- An authority unlock, including unattended unlock, does not itself create a grant or expand any existing grant.

**Key separation**

- Keep machine identity signing keys, authority message-signing keys, and secret-data encryption/wrapping keys cryptographically separate. A key used to authenticate protocol messages must not be reused to encrypt or wrap secret data.
- Protect the authority signing private key outside plaintext SQLite, as already required above. Protect secret-data encryption keys separately; persist only ciphertext and wrapped key material. Use authenticated encryption and bind ciphertext to stable record identity/version and purpose through authenticated associated data.
- The precise authority key hierarchy, key-wrapping implementation, rotation, backup, and recovery procedure must be documented and tested before production use. Reuse sound existing vault primitives where appropriate, but do not assume the current prototype's user-interactive PRF unlock flow automatically solves unattended service startup.

#### Current implementation boundary

The paragraphs below describe what is built, in the order it was built; where a later paragraph changes an earlier one, the later one is current (every administration verb moved into the admin web app). In outline: a local **host service** (`with-secrets service`, foreground console host, loopback only; Windows service installation, start at logon and the service account are not built) and the CLI as its client for runs, over the shared HTTP API with versioned JSON (`LaunchRequest` with a digest, NDJSON events). The service owns the approval page, store access for runs, decryption, environment preparation, launch, redaction and exit status, and serializes the final launch commit against local authorization invalidation (`LaunchGate`).

Phase 2 adds the **machine identity and a local authority** (no network): an ECDSA P-256 machine key in Windows CNG (non-exportable; Platform Crypto Provider first, silent fallback to the software provider) whose fingerprint is the SHA-256 of the canonical SPKI; a separate authority signing key, pinned (public key only) in `host.json` at the first approval of the machine, with rotation by a signed transition and recovery by an explicit admin action; `authority.db` (SQLite, WAL, schema 1 as built in Phase 2: machines, machine_history, grants (structure only), authority_keys, audit_history, processed_requests, pending_invalidations) beside `state.db`, which is unchanged. Enrollment records first contact as Pending with proof of possession; the status table above is implemented exactly (the security revision goes up only on Trusted to Disabled and Trusted to Untrusted; a rename never changes it; a changed host name is recorded as pending and the binding is not changed until an administrator accepts the name in the admin web app (**Accept host name**, a fresh tap)). `IAuthority.DecideAsync` takes a machine-signed `MachineRequestEnvelope` (the launch request, fingerprint and host name), re-reads the machine's status and revision inside the transaction that commits the decision, runs the approval page for exactly that digest and returns a canonical-JSON `AuthorityResponse` signed by the authority key; the host checks the pinned key, the signature, request id, digest, machine, validity (60 s, never more than 5 min) and the revision before anything is decrypted. A retry of a request id returns the committed answer from `processed_requests`. An exact request replayed after a restart within the response's validity returns the stored answer, but the host has no approval of its own for it and denies. In Phase 2 the machine functions (approve, disable, enable, untrust, trust, rename, accept host name, rotate and recover the authority key) were terminal verbs; they are now operations of the admin web app and the verbs no longer exist. Every change needs a one-use page with an admin passkey tap (the action and the full fingerprint are in the signed page text). The CLI authenticates the service (POST `/v1/identity`: a signature over a fresh challenge by the machine key, whose fingerprint must equal the one pinned in `host.json`) before it sends anything, with exit code 7 otherwise; this adds no client credential. Grants are honoured behind the service only under the security revision they were made in, and none survives a service restart; a revision increase or an applied invalidation clears them. **Superseded open item (the old loopback port):** the concern that an impostor holding the CLI loopback port could relay `/v1/identity` to the real service no longer applies to local IPC, which no longer uses a TCP port (10.2, "Local clients and transport"). Windows uses a named pipe whose ACL allows only the current user's SID and denies network clients, and the client connects current-user-only; Linux and macOS use a Unix-domain socket in a private owner-only directory, and the service checks the peer UID before it reads the request. The CLI still sends a fresh challenge and checks the pinned machine fingerprint before it sends a launch request (`TransportInvariantTests.cs` checks that an unpinned or wrongly identified service is rejected before anything is sent). **Remaining limitation:** the identity challenge is still not cryptographically bound to the channel, and a malicious process running as the same OS user is outside the threat model; this adds no channel-binding requirement. Known limits: a running service learns of an invalidation through a 1 s poll and before each launch; two services on one `authority.db` are not supported; `authority.db` has no integrity protection and keeps no copy of the admin assertion; `host.json` and the key store are within the same-user trust limit; the approval page content that a remote authority would need (script contents) is not part of `LaunchRequest`; the envelope has no parser yet; CNG is Windows-only; retired authority private keys are not deleted. (The separate `authority.db` and `state.db` files of this phase are superseded by the one `with-secrets.db` per machine, see "One database per machine and the review key (current implementation)" below.)

**Historical Phase 3 snapshot (superseded):** This paragraph records an intermediate implementation/design state, including the then-proposed offline lease. It is retained only to explain the evolution of the grant protocol; none of its lease behavior, `no-lease` denial semantics, offline grant use, or associated cache-retention rules are current. Task M4 below records the removal, and Section 10.2 is normative. Phase 3 added **grants as authority operations**: `authority.db` schema 2 (a schema 1 file is migrated in place; the grants table of schema 1 was never written) holds grants (id, machine fingerprint, scope key, a description of what the scope covers, created, expires or NULL for indefinite, a grant revision, status active, revoked or invalidated, who approved), `grant_events` (revocation notices for a host) and `processed_grant_requests` (the committed signed answer for each request id). `IAuthority` gained `GrantAsync` (a machine-signed `GrantEnvelope`: use, or approve, which shows the ordinary page and creates or updates the one grant for the scope), `ReconcileAsync`, `PendingGrantEventsAsync` and `AcknowledgeGrantEventAsync`; every answer is canonical JSON signed by the authority key and checked by the host like a decision (pinned key, signature, request id, digest, machine, validity, operation). Extend, renew and revoke are applied by the authority after an admin passkey tap (in the admin web app **Grants** view; Phase 3 had terminal verbs that no longer exist); each is atomic with its audit row and stored answer, idempotent by request id, refuses a grant that changed meanwhile (grant revision), and never changes the machine's security revision. **Scope key (provisional; 10.2 does not say):** the scope of a grant is the host's request fingerprint key (secret names, resolved program path, working folder, `.env` plan, script content hash, inherited-environment hash), opaque to the authority, which also stores program, folder and names for display; the reason is not in it (the Phase 3 fix round added the full argument list to the scope, see below). `with-secrets approve COMMAND` (HTTP `/v1/approve`) asks for that approval and launches nothing; `run` under an applicable, unexpired, unrevoked grant for this machine and exact scope skips the page decision and otherwise falls back to the page. **Lease:** issued only inside a signed reconcile answer (default 15 minutes, provisional), held in host memory, measured by a monotonic clock from receipt, destroyed by a restart, never lengthened by a grant (indefinite included) or by the wall clock; no valid lease means no secret use (deny code `no-lease`), for local authority mode too (the same code path). Offline, only a grant the host already synchronized counts, only inside the lease and before the grant's own end; no new approval, extension or renewal is possible and an extension is seen only after the next online use. **Current implementation, stated exactly:** this offline path (`HostAuthorization.OfflineUse`) is reachable only with an `IAuthority` that can fail separately from the host, which exists in the tests (a fake transport) and nowhere else. In local mode the authority is in the same process, so a failure is a denial and never "offline"; in remote mode the host has no store and every value comes from the authority, so a run cannot be served while the authority is unreachable and the runtime path for a grant in remote mode is the authority's (`LaunchAuthorize`), not `TryUseGrantAsync`. The lease is enforced (no valid lease, no use) and the gates were not weakened, but offline grant use is **not reachable in the shipped modes**; an offline cache for remote mode does not exist and is an open design item. **Startup reconciliation:** before it accepts a request the service checks machine status and security revision with its authority; an unreachable authority leaves it returning 503 until a check-in succeeds. A connected host applies a revocation, disable or revision change at once (grants and lease dropped, `LaunchGate.Invalidate()`; a revocation invalidates every launch that has not committed, not only those that used the grant). **The store key (maintainer decision):** the first run under a grant gets the key from one passkey tap; the service then holds that key material (the PRF output, which opens K and can be zeroed) in memory for the grant and later runs under it need no tap or page. It is dropped and zeroed on grant expiry or revoke, machine disable or untrust, a security revision change, the lease ending, a service restart and every failed run; never written to disk or a log, no other caching. **Open item: a cleaner mitigation for holding the key in memory is to be revisited later**. The seam is `IStoreKeyProvider` (`StoreKeyProvider.cs`): `TapStoreKeyProvider` is the plain tap, `HeldStoreKeyProvider` the service default. Known limits: `authority.db` has no integrity protection (a same-user process can insert a grant; grants carry the passkey assertion that approved them; superseded: grant rows are now sealed by the authority key, see "One database per machine and the review key"); the Phase 1 requirement that grants be unusable by other OS users is **not** implemented (the API has no caller identity; idea: a same-user check on the loopback connection's owner process, behind a seam); the host persists no revision and fetches grants on demand, so a restart restores none.

Phase 4 adds the **durable audit trail** (10.2 "Audit events"). `AuditEvent` (`Authority/AuditEvents.cs`) is a canonical-JSON event signed by the machine key in the format of the other machine messages (domain `with-secrets audit event v1`): event id (GUID), per-machine sequence, time, machine fingerprint, type (`authorization`, `launch` or `execution`), outcome, reason code, request id, working folder, program, redacted arguments, grant id, exit code. No OS user, no secret value and no environment value; arguments pass through `AuditRedaction` (a heuristic: values after secret-like names, Authorization/Bearer values, URL passwords are masked; long ones cut; the host records them before it decrypts, so it cannot mask exact values). `HostAuditOutbox` is `audit-outbox.db` beside `authority.db` (SQLite, WAL, `synchronous=FULL`, schema 1; another version or a damaged file is never repaired: delete it): one write transaction reads the counter, signs, inserts the event and bumps the counter, so the sequence is monotonic and gapless (a failed commit uses no number) and a returned commit is on disk. `RunCommand` records the **authorization** event (approved, granted, reused, denied, grant-approved for `approve`) and, for any outcome that lets the run go on, requires it to be committed before the store is opened; if not it ends with exit 5 and decrypts nothing. The **launch** (started, or failed/cancelled with a code) and **execution** (exited with the exit code, or an internal failure) events follow; a failure to commit them is logged (type only) and does not stop a launch that happened. Every run through the service names secrets, so every one is secret-bearing; there is no non-secret path to relax. `HostAudit`/`AuditUploader` send the outbox in batches through `IAuditSink` (the local authority implements it; a remote one will) and remove an event only after an `AuditAck` signed by the pinned authority key (verified like every other answer: key or transition, signature, batch id and digest, machine, validity) names it accepted, duplicate or expired; a rejected event (bad signature, unknown machine, id reused) is kept apart and not resent. The loop wakes on each new event, retries with a doubling pause (capped at 60 s) while the authority is unreachable or an answer does not verify, resumes after a restart from the outbox, and never makes a launch wait. At the authority (`authority.db` schema 5, migrated in place from 1 to 4; the first-cut audit tables of schema 4 are replaced) one transaction per upload verifies each event against the machine's registered public key, stores each event id once (the same id with other content is rejected), keeps the machine's highest sequence, records a skipped range as a `missing` gap (shrunk or split when a late event fills it) and a number used by two events as `reused` (never a reason to reject), and only then is the acknowledgement signed. Retention is the authority's setting (`audit_retention_days`, 365 by default, 0 keeps everything; set in the admin web app Settings): events older than it are acknowledged as `expired` without being stored, and events whose receipt is older are pruned on each upload or by `PruneAuditEvents`; only acknowledged events exist at the authority, and the host never prunes an unacknowledged one. `AuthorityStore.AuditHistory(AuditQuery)` filters by machine prefix, time range, type, outcome, grant id, folder and text; the admin web app **Audit** view and `/api/v1/audit/events` show it (read-only; the `admin audit` verbs no longer exist). **(Superseded by task M4, see "Task M4 current implementation": the old `AuditLog` and `--audit` no longer exist; the human commands' events are signed events of type `admin` in this same trail.)** Review fixes: every event carries the **epoch** (a random id made with the outbox, signed) and the authority tracks the sequence per (machine, epoch), so numbers of a recreated outbox can never close a hole of an earlier one (a number repeated within one epoch is still `reused`); the host cuts folder, program path, codes and arguments to the authority's limits before signing (`AuditRedaction.Bound`) and refuses to sign an event that is still invalid; `approve` commits an `approval-requested` authorization event before the tap and fails closed (exit 5) without it; the uploader parks only final refusals (an unknown or not yet approved machine, or a status the host does not know, is retried); the upload loop survives any exception; events dropped as expired are counted in the authority's `audit_history` (`audit-events-expired`); duplicates are checked per machine; `--text` finds backslashes, quotes and non-ASCII letters in arguments; redaction also masks JSON bodies, `-u/--user/--proxy-user NAME:PASSWORD` and `-pSECRET`. Event reason and outcome words, the 60 s acknowledgement validity, the batch sizes (50 sent, 200 processed), the retry pause and the 365-day default are implementation choices. Known limits: the outbox and `authority.db` have no integrity protection against a same-user writer (a deleted outbox restarts the numbering under a new epoch, which the authority records as an `epoch` gap; the old epoch's holes stay open). Grant evidence text is stored encrypted to the review key R and each grant row is sealed by the authority key (see "One database per machine and the review key"); values injected as secrets are never stored. (The separate `audit-outbox.db` and `authority.db` files and their schema numbers in this paragraph are superseded: the outbox and the authority tables are tables of the one `with-secrets.db`, and an event is appended in the same transaction as the change it records.)

**Startup lock.** The service starts locked (`AuthorityLock`). It is a gate in the service process, not a second encryption layer: the authority signing key stays a CNG key and the lock decides when the process may use it. Locked means: `AuthorityKeyRing.Current/Rotate/Recover` throw (so the authority decides, grants, reconciles and acknowledges nothing, because every answer is signed), `HostService` answers runs and approves with 423 and one line naming the admin page (the CLI exits 8), `HostAuthorization` authorizes, uses and lends nothing, and locking runs `HostAuthorization.Discard`: the held store key (PRF-derived material) is zeroed and dropped, synchronized grants and authorization state are cleared, `LaunchGate.Invalidate` cancels launches that have not committed, and the host is no longer ready. `GET /v1/status` reports `running` and `locked` only. Unlocking checks the host in with the authority again before it serves; nothing is restored from before the lock. A program that already started is not affected.

**Admin web app and sessions.** The service serves the whole administration on its own loopback port as a JSON API under `/api/v1` (Phase 6b-1; `Authority/Api/AdminApi*.cs`, `AdminViews.cs` for the DTOs; the 6a server-rendered pages and `AdminWeb.cs` are removed and the SPA of 6b-2 is served at `/admin`). `with-secrets admin` has no verbs: it checks the service's identity (the same proof as a run), prints the app's link and the public status, and opens the link in a terminal on Windows. The verbs `machines`, `approve`, `disable`, `enable`, `untrust`, `trust`, `rename`, `approve-host-change`, `grant list|extend|renew|revoke`, `audit`, `rotate-authority-key` and `recover-authority` were removed after their function moved into the app (`AdminService.Plans.cs`); lock, unlock and the unlock policy were never verbs.

**Admin API.** One route table (`AdminApi.Routes.cs`) drives the dispatcher, the request validation and the OpenAPI 3.1 document (`AdminApi.OpenApi.cs`, served at `/api/v1/openapi.json`, snapshot in `docs/api/openapi.json`; a test fails on divergence). Check order: `X-Api-Version` (unsupported: 400 problem with `supportedVersions`), loopback `Host` (421), `Origin`, route (404 `route-not-found`, 405 with `Allow`; `/api` never falls through to a SPA route), then by access class: public, owner-of-the-login-ticket, session read, and for everything else an exact `Origin`, the `X-Admin-Token` anti-forgery value, the session (except unlock) and the body (JSON, at most 4096 bytes, no duplicate members, schema-valid). Errors are RFC 9457 problem documents (`urn:with-secrets:problem:CODE`), never echoing input, paths or exception text; unexpected errors are a 500 that logs only the exception type. Cookies (`ws_session`, `ws_login`, `ws_pre`) are `Path=/api/v1`, `HttpOnly`, `SameSite=Strict`. No CORS.

**Per-mutation authorization at the API.** `POST /api/v1/authorizations` (operation and parameters, validated against the operation's schema) starts a pending authorization and its one-use passkey page (`AdminAuthorizer`, unchanged: signed text, ticket, persisted spent nonce, lock re-check). After the tap it is `verified` for 2 minutes. The mutation request carries the authorization id; `AdminService.MutateAsync` requires state verified, the same operation, equal parameters, not expired and unused, marks it consumed, then runs the plan with the verified admin (the store still checks `VerifiedAdmin.Consume`). A mismatch burns the authorization. A session never authorizes a mutation. Lock clears all authorizations. At most 32 active, 30 starts a minute. Audited: session start, each authorization request, refusal, application and failure.

The accepted text above already allows an authenticated web session as long as it never satisfies a sensitive operation. The session model that implements it:

| | |
| --- | --- |
| Start | One fresh passkey tap with user verification by an **admin** key on a one-use page whose signed text is `Operation: admin-session` with `Parameter login: <code>`; the browser that asked claims the session on its next page load. A locked authority starts none (only unlock works without a session). |
| Token | 32 random bytes in an `HttpOnly`, `SameSite=Strict`, `Path=/api/v1` session cookie; the service keeps only a hash in memory (`AdminSessions`); never written to a file, page, log or the audit history |
| Ends | 15 minutes idle (each use renews), 8 hours absolute (both authority settings, 1 to 120 and 1 to 1440 minutes, changed by a tap), sign out, **lock**, service restart |
| Grants | Read-only views: status, machines, grants, audit history and search (filters for machine, project folder, time range, authorization/launch/execution outcome, grant, text; a gap view), settings, passkeys. Nothing else. |
| Does not grant | Any change. Every operation on the sensitive list below is its own one-use page: a fresh, time-limited tap with user verification, signed over the operation, **every** parameter (machine and its security revision, shown host name, grant and revision and the exact new end, the setting's value, the key) and a per-page ticket, checked by the authority (`AdminAuthorizer`), spent once with the proof surviving a restart (`admin_spent_nonces`). A session, an unlock, an earlier tap or unattended material never satisfies it; a failed or unavailable passkey is a refusal. |
| Request rules | Every non-read request needs an `Origin` that is exactly this service, a loopback `Host` (the service refuses any other with 421), a small JSON body, and the page's secret in `X-Admin-Token`. Reads need the secret too. The session's secret is random, given once in the answer to `POST /session/claim` and never derived or shown again; before a session the browser's secret (an HMAC under a per-start key over the pre-session cookie) is given once by `POST /browser`. Cookie values are bound to the service's port. Without a session only the unlock and the lock may be started (each needs its own fresh tap). |
| Limits | Per caller (a session, or a browser's pre-session cookie, never the cookie's value itself): 30 starts a minute and one waiting passkey page; a new request closes only the same caller's page. Callers without a session share 32 waiting pages and 16 authorizations (a further one is refused; no waiting page or sign-in is ever evicted by another caller). **Lock** has lanes of its own: a signed-in administrator's cannot be touched by anyone else; the anonymous lane (8) pushes its oldest page out instead of refusing a new request. Refusal rows: 20 a minute per caller (200 in all); what is not written is counted in a summary row. |
| Audit | Session start and end, and every sensitive attempt and outcome (requested, refused, authorized, applied, failed), are durable `admin-operation` rows (no proof, token, nonce or code). |
| Lock | Destroys every session and closes every pending admin page, run and approval page (`CancelActive`); the lock is re-checked at every commit and before every signature, so a tap that arrives after the lock changes and signs nothing. |

Known limits of the session design: **OPEN for the maintainer (inherent, cookie design not changed): cookies are shared across `localhost` ports.** A browser sends the cookies to every localhost port, so another program served there is sent them. Since the fix round of 6b-1 the cookie alone is neither a session (the secret in `X-Admin-Token`, given once to the page, is also needed) nor a way to read, claim a sign-in or start an authorization; what such a program can still do is set or clear cookies for the origin (a nuisance, not a bypass), and a program that can run script in the page's origin (an XSS, excluded by the strict CSP) could read the page's `sessionStorage`. The decision to keep the two secrets in `sessionStorage` (so that a reload stays signed in) instead of memory only (a reload signs in again with a tap) is also open. **OPEN: callers without a session can occupy the shared pages** (32 waiting sign-in or unlock pages) by making many browser identities, which blocks a new sign-in or unlock (never a signed-in administrator, a Lock, or a change) until their pages time out; a local program can start a sign-in or an operation and ask the person to tap, so the passkey page names what the tap does (the sign-in page says to tap only after choosing to sign in); **Lock** needs no session but its own fresh tap, and is not blocked by other callers; passkey add and remove reuse the existing enrollment pages (the new passkey's code is typed in the terminal that runs the service) and are tested with a fake `IPasskeyAdmin`; secrets, passkeys and the rotation of the store key are in the app, and the page settings are in the app's Settings page.

**Sensitive administrator operations.** `AdminAuthorizer` is the one way the authority's own operations (unlock, lock, unlock policy, audit retention) are authorized: it shows a one-use page whose signed text carries `Operation: ...` and one `Parameter name: value` line per security-relevant parameter, then verifies for itself that the assertion verifies against the enrolled keys and was made by an admin key (the proof check requires user verification), that the signed text is exactly this operation and these parameters (no more, no fewer), that the page was issued within the page limit and not in the future, and that its nonce was not accepted before. A `VerifiedAdmin` token results; the store methods that change a setting (`SetUnlockPolicy`, `SetAuditRetentionDays`) take one and spend it, so they cannot be reached from an unlock, an earlier tap, another operation or other parameters. Failed, denied, timed-out or unavailable passkeys fail closed; an operation whose attempt cannot be recorded in the audit history is not started. Attempts, refusals and outcomes are written to the `audit_history` table of `with-secrets.db` as `admin-operation` rows (operation, outcome, parameters, key name; never a proof, nonce or code). Audit of the existing operations:

| Operation | Where it is authorized | Fresh, bound, single-use, UV | Tests |
| --- | --- | --- | --- |
| Admin passkey enroll / unenroll / replace (admin web app), `--recover` | Admin approval page and signed manifest (`Enrollment`, `StoreRecovery`); recovery is its own ceremony with the recovery code | Page nonce, text and manifest signed; `WebAuthn` requires UV | `WebApprovalTests`, `RecoveryTests`, `ManifestTests` (non-UV manifest signature refused) |
| Machine approve, disable, enable, untrust, trust, rename, host-name change | Admin API: `AdminService.Plans` one-use page via `AdminAuthorizer`, text names action, full fingerprint, host name, status, revision | Verified again by the authority; nonce remembered across restarts | `Api` suite: for each, only a session, non-admin key, no UV, signature over another challenge, replay, proof for other parameters change nothing |
| Grant create (approve), extend, renew, replace, revoke | Approve page evidence verified by the authority; extend, renew, replace and revoke are admin-app operations (`GrantPlan`) whose page text `Change/Grant id/Scope/Machine/New revision/New end` is verified by the authority | Same; revision and the exact new end in the signed text defeat replay | `GrantAuthority` suite (web endpoints: no UV, other challenge, replay, stale revision), `Api` |
| Secret set / remove, rotation of the store key (admin web app) | Manifest or admin approval page | Same page flow | existing page suites (denied or non-admin changes nothing) |
| Authority key rotation / recovery | Admin app Settings, `AdminAuthorizer`; `AuthorityKeyRing` (refused while locked, and the refusal is audited) | Same | `Api`, `AuthorityLock` |
| Unlock, lock, unlock policy (the unattended policy is signed by the authority key), audit retention, session timeouts, admin sign-in | `AdminAuthorizer` as above | Verified again by the authority; nonce and ticket checked, nonce persisted | `AuthorityLock`, `Api` suites |

**Unlock mode.** `unlock_policy` (manual by default, unattended only by a fresh tap on the app) and, for unattended, a DPAPI-sealed random 32-byte blob and its SHA-256 are in `authority_settings`. `IUnlockProtection` has `DpapiUnlockProtection` (Windows, current user) and `NoUnlockProtection` elsewhere (the option is refused with a message); no other platform is assumed. At start, `UnattendedUnlock.TryUnlock` opens the blob, compares the hash and unlocks; any doubt leaves the service locked. It grants nothing, widens nothing and never replaces a tap. Weaker by design: any process of the same Windows user can open the blob. The service prints the mode at start, the app shows it, and reference.md documents it as weaker.

**Key hierarchy and key separation.** The machine identity key signs machine requests, reconciliation and audit events, and service identity proofs; it is never used to encrypt or wrap secret data. The authority signing key signs authority answers and key-rotation transitions; it is also never used to encrypt or wrap secret data. Secret-data keys are a separate hierarchy: the master key MK is protected by the existing passkey-PRF/recovery slots; the single native store data-encryption key K is wrapped by MK in the vault and is used by the Dotenvx.Primitives-based at-rest encryption mechanism for both native entries and mounted-provider cache values. There is no separate mounted-cache key. No machine-identity or authority-signing key participates in this hierarchy. The authority's existing unlock process is the only path that makes MK and then K available. Locking or restarting clears MK, K, and decrypted values from usable memory. The unattended-unlock material is a separate random value that only lets the service decide to unlock; it is not itself a data-encryption key. A signature by one signing key never verifies under the other.

**Backup and recovery procedure (written and exercised; full steps in `docs/operations.md`).** (a) Authority signing key: routine rotation is a transition signed by the current key (**Rotate** in the app's Settings; refused while the authority is locked); loss or distrust: **Recover** makes a new key with no transition and pins it for this machine, other hosts re-enroll. The CNG keys are not exportable, so there is no backup of the key itself and none is invented: a restored `with-secrets.db` on a machine without the key fails closed (`AuthorityDatabaseException`, nothing signed, decrypted or run) until an administrator recovers the key with a fresh tap. (b) Secret-data keys: the recovery code (`--recover`) and a second admin passkey; there is no other copy of K or MK. (c) Unattended-unlock blob: not backed up; if it will not open or the policy signature does not verify under the active key, the service stays locked and an administrator unlocks with a tap. (d) Backup set: the one file `with-secrets.db`, copied while the service is stopped (it also holds the outbox tables; after a restore onto another machine, the uploader marks events signed by another machine's key rejected, never uploaded or left pending); `host.json` (per-machine pin), logs and every key are not part of it. The backup holds ciphertext (secret rows, grant review text encrypted to R), public keys, names, sealed grants and audit, no private key, master key, review key, recovery code or secret value (scanned in the suite). **Exercised** (suite `Operations`): a restore on a second machine with new keys (store opens, manifest and admin passkeys verify, machine records, history, grants with their assertions and the audit rows are unchanged, the transition chain verifies and a host pinned to the first key follows it; locked, unlocked-without-key and Pending machines run nothing; Recover by tap, approval of the new identity, a run, the audit continuing); two rotations followed by a recovery through the admin API (each its own tap, a non-admin key refused, the host follows the signed transitions without a tap and refuses an unpinned recovered key, decrypting nothing); three lock, restart, unlock cycles (held key zeroed, locked after restart, no session survives, a non-admin key cannot unlock); a host name change from refusal to approval to the next run. A restore from an older backup also restores older state (a machine since disabled, a grant since revoked): review Machines and Grants after a restore.

**Phase 5b: the remote store model (decided by the maintainer; built for the WSL path).** The authority holds the data store (secrets, passkeys, grants, audit). In remote mode the approval page, the passkey tap and the PRF unlock happen at the authority, the authority decrypts, and the values reach the host service only inside the existing end-to-end encrypted session as a **signed delivery**; the host builds the child environment and launches (`LaunchGate` and audit-before-launch unchanged). Values never pass the relay in plaintext, never go to the CLI, are never logged and never persisted at the host. Failure, disconnect or lock before delivery means no launch. The deployment is exactly the 10.5 path: `WSL client -> WSL host service -> mutually authenticated, encrypted machine connection -> Windows host service and authority`. **Messages** (`Remote/RemoteLaunch.cs`, `AuthorityLaunchHandler.cs`): op `launch-authorize` (id `launch:<requestId>`, never resent once its send began) carries the machine-signed decide envelope, the machine-signed use envelope and a machine-signed `PageContext` (the resolved program, expanded arguments, links, script and program-file views, and the fingerprint key: the authority cannot read the host's files, so the host states what the person will approve and signs it); the authority pushes `approval-link` notices (a plain http/https link, no user info or control characters) so the CLI shows the authority's page link; the final answer is a `LaunchAnswer` with either a signed refusal (`AuthorityResponse`) or a `SecretsDelivery`. **`SecretsDelivery`** is signed by the authority key (domain-separated) over the request id, request digest, machine fingerprint, security revision, how it was authorized (page or grant), the grant id, issue and expiry (at most 120 s) and a salted SHA-256 proof per value; the values travel beside the signed text, not in it. The host accepts it only if the signature verifies under the pinned key, it is for this request id, digest and machine, it has not expired, the names are exactly the requested ones, the security revision is not older than the one applied, the host is currently vouched for by its authority, and the id was not delivered before (one-time on both sides); anything else zeroes the values and refuses. The authority handler checks the machine (Trusted, host name bound), the unknown-secret case (refused before any page), a grant (`GrantAsync(Use)`; a grant path shows no page and, for a store that needs the passkey, borrows or takes the key held for that grant, bound to grant, scope, revision and end, swept and dropped on lock, disable or change) or the page (`Offer` plus the web approver; a replayed approved decision is refused as `request-id-reused`), and decrypts only then. The delivery is not cached by the endpoint. The host shows no page and reads no store. **Pairing:** `with-secrets admin http://AUTHORITY:PORT --authority-fingerprint HEX` writes the remote setting in `host.json` (registration id `machine`) and enrolls this host's own machine identity as Pending; an administrator approves it in the authority's admin app. Bare `with-secrets admin` still opens the local app. The fingerprint of the authority key is required (trust on first use would need a new handshake mode); the key is pinned at the first matching handshake. **Endpoint:** `with-secrets service --machine-port N [--machine-bind ADDRESS] [--machine-cert FILE [--machine-cert-password-env NAME]]` serves only the machine protocol (an embedded relay whose authority registration is loopback-only, plus the `AuthorityEndpoint` over the same authority and its database, now `with-secrets.db`): no admin app, no API, no pages. It listens on loopback by default; 0.0.0.0 and [::] are refused; an address beyond loopback needs a TLS certificate. Opening a firewall rule for it is a maintainer action; the tool changes no system configuration. No request is trusted for coming from a WSL interface: the host has its own independently enrolled identity and the authority checks its signature and status. **Deferred (maintainer decision):** an administration interface reachable beyond loopback, LAN access and remote deployment of the authority (it may later serve the same frontend and API); Native AOT. **Known gaps, recorded not invented:** creating a grant (`approve`) from a host whose authority is remote is not built (grants are per machine; the protocol-level approve works and tests use it); the machine key store exists for Windows CNG only, so a Linux/WSL host service cannot start yet (a Linux key store is a security decision for the maintainer); a non-loopback plain-ws endpoint (NAT-mode WSL address) needs either a CA-valid certificate or a decision to allow plain ws on private virtual-network addresses (recommended, since the session is end-to-end encrypted); the values appear as .NET strings in the JSON of the delivery at both ends (not wipeable, as elsewhere); local mode keeps its in-process path and does not use these messages. Tests: suite `RemoteLaunch` (real HTTP and WebSocket, the approval page at the authority with a test authenticator, canary scans of relay frames, CLI events, logs, audit and host disk, tampered, replayed and duplicate deliveries, wrong digest, revision and names, locked or vanished authority, grants and the held key, two independently enrolled hosts against one authority).

**Every approval is a grant (current implementation).** An approval no longer leaves nothing behind: each one creates a grant record with the person's passkey assertion over the page text. A grant has a usage, `reusable` or `once`. "Approve once" records a once-only grant that is consumed at creation by the run it approved (it has a `consumed` time, no end, and status `consumed`); it never covers a later run, and the next run asks again. A timed approval records a reusable grant as before. **Replace** (admin app, **Make a grant from this**; plan `replace-grant`, API `POST /grants/{id}/replace`, operation `grant-replace`) makes a new reusable grant with exactly the scope of a used once-only grant (scope key, machine, program, folder, secret names, security revision), ending after 1 to 1440 minutes from the page or with no end; it needs a fresh admin passkey tap with user verification, is linked to the original by `replaces`, is audited (`grant-replaced`) and leaves the original unchanged and still consumed. It is refused while an active grant already covers the scope (`grant-exists`). The extend and renew bounds are unchanged: extend adds 1 to 1440 minutes to the present end or gives no end, renew sets 1 to 1440 minutes from now or no end. A revoked, invalidated or consumed grant cannot be extended or renewed. (The schema numbers of `authority.db` at the time are superseded: the grants table is now part of `with-secrets.db`, schema 3.)

**Task M1 current implementation: direct mutual TLS (branch `impl/mtls-pairing`).** Built from the accepted design of 10.2 (the design text is unchanged); the files are `Remote/MachineCertificates.cs`, `MachineTls.cs`, `MachineListener.cs`, `RemoteAuthority.cs`, `RemoteWire.cs`, `RemoteTransport.cs`. **Removed:** the relay, the custom handshake, the AES-GCM session, the relay wire layer, registration and the 5b `--authority-fingerprint` pairing. **Kept unchanged:** the authority logic, grants (including the H1 scope), the audit outbox and acknowledgements, lock behaviour, launch gates, the `SecretsDelivery` content rules, idempotency (`processed_requests`) and the machine states; the signatures on authority-issued records and on machine-signed request envelopes and audit events. **Identity certificate:** `MachineIdentityFile` writes `machine-identity.cer` beside `host.json` from the CNG identity key: ECDSA P-256, self-signed, ten years, the profile of 10.2 (CA with path length 0, critical key usage DigitalSignature and KeyCertSign, no extended key usage). `ValidateIdentity` is strict (exact DER, key type, self-signature, critical extensions, dates, validity length). Registration carries the certificate (`EnrollmentRequest.IdentityCertificate`, bound by the request signature; the authority stores it in the additive `machine_certificates` table, created on first open, schema version unchanged). **Temporary certificate:** `TemporaryCertificate` makes a fresh in-memory TLS key and a 24-hour leaf signed by the identity key (SAN `urn:with-secrets:machine:<fingerprint>`, serverAuth and clientAuth, not a CA, DigitalSignature), replaced one hour before expiry; `Current` is asked for each handshake (Kestrel `ServerCertificateSelector`) and for each client pool. The previous generation is kept until the next rotation. **TLS key on Windows (spike result, a recorded decision):** SChannel refuses an ephemeral key ("the platform does not support ephemeral keys"), and a PFX re-import writes key files that outlive the process. The smallest workaround is a named, non-exportable CNG key in the software provider, created per instance, used through `ECDsaCng`, and deleted when the certificate object is disposed. It is never written to disk by this program; a process that is killed leaves the named key in the user's key store (the one residue). On other platforms a plain in-memory `ECDsa` is used. **Validation:** `MachineCertificates.ValidateLeaf` checks a leaf against exactly one identity certificate (no `X509Chain`, no store, no hostname); outbound, the host validates the authority against the configured identity certificate and fingerprint; inbound, `MachinePeers` reads the SAN, looks up that machine's enrolled certificate and validates against it (Enrolled), accepts a structurally valid certificate of an unknown machine as Provisional (pairing route only) and rejects everything else at the handshake. **Listener:** `MachineListener` is a separate Kestrel endpoint (`--machine-port`, `--machine-bind`; 0.0.0.0 refused): TLS 1.3 and HTTP/2 only, client certificate required, no resumption, no 0-RTT, no HTTP/1.1. Routes are `POST /api/v1/machine/ops/{op}` carrying the existing versioned frames `{"v":1,"id","op","body"}` (a frame is a plain JSON body; there is no per-message signature or encryption around it) and `POST /api/v1/pairing`, a seam (`IPairingHandler`) that answers 501 `not-implemented` and is the only route an unknown machine may reach. Per request, in order: certificate identity, pairing exception, lock, the machine is Trusted now, method, route, content type, size and concurrency; the identity is never read from a header or field and a body that names another machine gets `wrong-machine`. Policy: no redirects or proxy, `Cache-Control: no-store`, no compression, UTF-8 `application/json` only, errors are a short code and an `X-Correlation-Id`, fixed limits (body 4 MiB, pairing body 16 KiB, 64 concurrent in all, 8 per machine, 30 s per operation) that refuse with 429 or 413 rather than queue. When a machine stops being Trusted (or the authority locks) its connections are asked to close (GOAWAY) and aborted after a grace of 5 s. Launches stream (`launch-authorize`): approval-link notices as lines, then the answer; the authorization is checked again immediately before the values leave. **Host client:** `RemoteAuthority` talks to the one configured endpoint (address and authority identity are separate settings in `host.json`: `remote.endpoint`, `authorityIdentityFingerprint`, `authorityIdentityCertificate`), `SocketsHttpHandler` with Tls13, HTTP/2 exact, no proxy, no redirects, no decompression, no resumption, persistent connections (HTTP/2 keep-alive pings detect a dead path; no maximum age), rotates its pool with the certificate and drains the old pool with a bounded timeout, retries ordinary operations under the same id with bounded exponential backoff and jitter, never retries a launch (a secret release whose answer is lost fails and nothing runs) and refuses an answer that is not UTF-8 JSON, is for another request id, or contradicts its status. **Invalidations:** the existing pending-invalidation and grant-event messages, sequencing and acknowledgements are unchanged; the op `poll` is held until one exists (woken by `AuthorityStore.Changed`, one outstanding poll per host, no heartbeat or empty polling); the host applies, acknowledges and polls again, and after every reconnect it reconciles (status and revision) and purges on a difference. A machine that is not Trusted cannot poll: the host treats `machine-not-trusted` as a loss of trust and discards what it holds. **Decisions for the maintainer (provisional):** (1) the identity certificate follows 10.2 (CA=true, path length 0) although the M1 brief text said CA=false; 10.2 needs a trust anchor for the leaves. (2) The machine-signed request envelopes (`decide`, `grant`, `reconcile`) are kept because the authority and `LocalAuthority` verify them in both modes; only the per-message session signatures were removed. (3) A host with no pinned authority signing key learns it over the identity-pinned connection with the op `authority-key` once the authority trusts it (previously the 5b pairing pinned it); pairing (M2) is expected to replace this. (4) Tests register machines at the authority store directly with their identity certificate until pairing exists. **Not built:** pairing, a Linux key store, the admin web app view of connections.

Not built: moving `--recover` into the admin app (it is still a terminal command with its own pages), a stronger passkey-add flow without the terminal code, and the Windows privilege separation of Task 16. The human commands' events are signed `admin` events in the outbox tables (Task M4); the authority also keeps its own `audit_history` table, in the same `with-secrets.db`. The loopback API has no caller identity: any local OS user can reach it, which is why grants should be unusable by other users (not yet done, see above). The inherited environment of a request is bound into the approval fingerprint and summarized on the page (count and notable names, no values). A client cancel (disconnect or the cancel route) before the commit discards the launch; after the start it ends the program and its child process tree, whereas an authorization invalidation never touches a launched child. The human commands (`--recover`, `--needs`, the first-time setup, `pair`) still open `with-secrets.db` in the CLI process (SQLite's busy timeout orders them against the service). The current prototype uses SQLite. Task 16 (service account and privilege separation) remains separate and is not expanded here. The `.env` behaviour (see the reference) is unchanged: the CLI reads the files once and the service checks the plan it receives with the same rules.

**Task M2 current implementation: pairing invitations (branch `impl/mtls-pairing`).** Built from the accepted design of 10.2 (the design text is unchanged). Files: `Pairing/PairingProtocol.cs` (bundle text, key derivation, proofs, strict wire encoding, fixed limits), `Pairing/PairingClient.cs` (the client: input sources, bootstrap, verification, registration), `Authority/PairingService.cs` (the authority side, limits and audit rate cap), `Authority/AuthorityStore.Pairing.cs` (the `pairing_invitations` table, additive, created on first open; atomic consume and register), `Remote/PairingHandler.cs` (the route's two steps), `Authority/AuthorityPairing.cs` (the `pair` command), and the admin plans `pairing-create` and `pairing-revoke` with the API routes under `/api/v1/pairing/invitations` and the SPA view `features/pairing`. What exists:

- **Invitation.** `wsp1;ADDRESS;ID;CODE` where ID and CODE are base64url of 16 random bytes. Fixed 10-minute lifetime. The authority stores `K = HKDF-SHA256(code, salt = id, info = "with-secrets pairing key v1")` in the service process's memory only, never on disk and never the code, and wipes it on consumption, expiry, revocation and withdrawal. An invitation open when the service stops is ended at the next start (audited), so it needs no operating system facility. The bundle is returned once, in the answer to the one mutation that creates it (a one-shot output of the authorized plan, not stored, not logged, not in the audit).
- **Protocol.** Bootstrap request: the invitation id and a client nonce only, on a connection that uses a throwaway client identity. Answer: the authority's identity certificate, a server nonce and `HMAC-SHA-256(K, frame("authority proof v1", invitation, authority fingerprint, client nonce, server nonce))`. The client validates the certificate profile, that the TLS leaf it saw is signed by that identity (and its SAN is that identity's fingerprint) and the proof, then sends the registration on a fresh connection pinned to that identity: the identity certificate, fingerprint, host name, a nonce, a proof of possession (identity-key signature over a domain-separated frame) and `HMAC-SHA-256(K, frame("registration proof v1", invitation, authority fingerprint, machine fingerprint, host name, nonce))`. Frames are length-prefixed, so no field boundary can be shifted. The registration proof binds the authority fingerprint as well (an addition to the design text).
- **Registration.** One transaction: the invitation must be pending and unexpired, then it is consumed and the machine is created (or, when Pending, refreshed) with the same transaction's audit rows. The digest of the whole registration request is stored with the result, so the identical retry after a lost answer returns the same result and a different request is refused. A machine already known as Trusted, Disabled or Untrusted is refused without changing it and **without using up the invitation** (provisional decision, see below).
- **Errors.** Wrong, expired, used, revoked, withdrawn and unknown invitations are one answer (403 `pairing-refused`); a malformed body is 400, over 16 KiB is 413, a busy route is 429; the reason goes only to the durable audit. Fixed limits (not configurable): 5 failed proofs per invitation (it is then withdrawn), 30 refused attempts per 10 minutes overall, 4 concurrent registrations (the others are refused, not queued), 8 open invitations, 32 Pending machines and 4 per host name (the per-host rule is the one enrollment already had), 30 audit rows a minute from the route with a summary row for the rest.
- **The route.** Still the only one reachable with an unenrolled certificate. It does bootstrap and register and nothing else; its answers are the authority's public material or the fingerprint and status of the registering machine.
- **Credential supply.** `with-secrets pair`: hidden prompt, `WITH_SECRETS_PAIRING_FILE` (a file, read first), the Docker secret path `/run/secrets/with-secrets-pairing`, or `WITH_SECRETS_PAIRING`. The variables are cleared from the command's process after reading; `LaunchClient` does not send them and `ChildRunner` removes them from every child environment.
- **Admin.** `POST /pairing/invitations` and `POST /pairing/invitations/{id}/revoke` are mutations (an operation-bound passkey tap each; since M8 the service applies them at the tap and the bundle is collected once through the authorization); `GET /pairing/invitations` lists status only. Creation needs a configured machine endpoint (the address in the bundle is the endpoint's bind address and port).
- **Tests.** Suite `Pairing` (198 checks), the pairing checks of the `Api` suite, the SPA tests (shown once, axe), the E2E scenario `k1-spa-pair-machine`, and `RemoteLaunch` now pairs its hosts for real.

**Task M3 current implementation: Linux machine key store (branch `impl/mtls-pairing`).** Built from the maintainer's decisions; the design text is unchanged. `Authority/FileSigningKey.cs` holds `FileSigningKey` (ECDSA P-256 as a PKCS#8 file, created with mode 0600 through a temporary file and a no-overwrite move, in a `keys` folder created with mode 0700; a file or folder that group or other can access, a link, a wrong curve, trailing bytes or other content is refused with a message that never contains key material) and `MachineKeyStore`, the single place that chooses the store: CNG (`CngSigningKey`, unchanged) on Windows, the key file elsewhere. `LocalDeployment.OpenProduction`, `ProductionKeyRing`, `ExistingMachineFingerprint` and the pairing command go through it, and `with-secrets service` no longer refuses to start off Windows. This is WEAKER than CNG: anything running as the same user can copy the file; no TPM, keyring or secret service is used. A container is a separate machine with its own identity over the mTLS machine listener and needs a persistent volume for its key folder; no listener or other code was added for it. The TLS key of a running instance stays an in-memory key on Linux (verified: no file is written). Tests: suite `KeyStore`.

**Task M4 historical implementation note (superseded):** the earlier grant design included an offline lease. That mechanism was subsequently removed; it is not part of the accepted architecture or current behavior. The current fail-closed rule is stated normatively in Section 10.2. This paragraph describes the earlier split-file implementation (`state.db`, `audit-outbox.db`). "One database per machine and the review key" below supersedes its files and its transaction boundaries: the reverse case it names (an event committed for a change that then failed) no longer exists. (1) **One audit.** The hash-chained `AuditLog` (the `audit` table of `state.db`, the `--audit` command, `AuditRecord`, `AuditVerification`) is gone; `state.db` is schema 10 without that table (an older file says "not of schema version 10; delete state.db", nothing is migrated: nothing was released). Every event it recorded is now a signed audit event of the new kind: the run events were already recorded by the host (`authorization`, `launch`, `execution`); the administrative events (`secrets-set`, `secrets-removed`, `setup`, `settings-changed`, `key-enrolled`, `key-removed`, `key-rotated`, `approvals-revoked`, `recovered`, `change-denied`) are type `admin` (`AuditEventTypes.Admin`): outcome = the event name, reason = a short text with the approving key's name, arguments = secret, setting or key names, metadata = the full detail, the key name and the names; no value, ciphertext, code or key. `AdminAudit` (`Authority/AdminAudit.cs`) writes them through the machine identity key into the same outbox as the run events (`audit-outbox.db` beside `state.db`), the service uploads them, and the authority's admin app shows them. `StateDatabase.Audit` holds the sink (the service installs its own at start so an event wakes the uploader). The event is committed inside the change's own `state.db` transaction just before it commits, so an event that cannot be committed fails the change (fail closed); the reverse case (the event committed, `state.db` then fails to commit) can leave a record of a change that did not happen. A refusal is recorded only when `state.db` exists. The run path writes no second record: the fields the old row had (the secret names of a run, the approving key name, the reuse minutes, the variable mapping, the `.env` file list, the file fingerprints) are carried by the optional signed `metadata` member of the run events (see (3)). There is no hash chain. (3) **Event metadata (maintainer decision, additive).** `AuditEvent` has one optional member `metadata`: a JSON object of text values, part of the signed canonical text (members sorted by name) and omitted when empty, so an event without it has exactly the text and signature it had before and still verifies and parses. Built-in limits (`AuditMetadata`): at most 24 members, names of 1 to 32 letters, digits, dot, dash or underscore starting with a letter, values of at most 2048 characters, at most 8192 bytes of UTF-8 in all, valid Unicode only; the host cuts what it signs to the limits (`AuditRedaction.Bound`), the authority refuses an event outside them (`Problem()`). Names and fingerprints only. Run events carry `secrets`, `variables` (VAR=SECRET, only when a variable is renamed), `envFiles`, `files` (path=SHA-256 of the program and script), and on the authorization event `key` (the approving key's name) and the grant; administrative events carry `detail`, `key` and `names`. The event list of the admin API (`AuditEvent.metadata`, OpenAPI and the generated client) returns it and the Audit view shows it as read-only escaped text. A metadata canary test scans every event type for values, ciphertext and codes. (2) **Fail closed.** `OfflineLease`, `ReconcileResponse.LeaseSeconds` (and its signed text), `LocalAuthority.LeaseDuration`, `HostAuthorization.OfflineUse`, `GrantUse.Offline`, the host's lease loop and the `offline-lease` reason are removed. What vouches for a host is `HostAuthorization.Vouched`: set only by a verified check-in that says Trusted and bound, cleared with every other authorization state, in memory only. An unreachable authority makes a grant check a denial (never a fall back to a synchronized grant), a remote host drops and zeroes its held key when its authority link fails, and the deny code is `not-vouched` (was `no-lease`). Kept: the in-memory grant key, its sweep on revocation, expiry, revision change and loss of vouching, and the monotonic clock (now only for the check-in back-off after a refusal).

**Task M7 current implementation: Linux key file hardening, the listener without a restart, the copied-identity warning, the blocked-run outcome (branch `impl/mtls-pairing`).** Built from the maintainer's decisions; the design text is unchanged. (1) **Key file checks (Unix).** `FileSigningKey` refuses before use: a link in place of the key file or of the key folder (not followed), anything but a regular file, a file or folder owned by another user than the one running the program (the owner is read with `statx`, `Authority/LinuxHardening.cs`; the message says `chown N`), a file with any group or other access (`chmod 600`), a folder with any group or other access (`chmod 700`), and, from the key folder's parent up to and including the store folder, a folder that group or other can write (`chmod go-w`) unless it has the sticky bit (how a shared temporary folder is made safe: only an entry's owner can rename or remove it). Folders above the store folder are not checked. A new key is written to a temporary file made with `O_EXCL` (mode 0600 from the first byte), flushed (`fsync`), and put in place with `link(2)`, which fails when the name exists (so two racing processes never replace each other's key: the loser reads the winner's), then the temporary name is removed and the folder is flushed; a replacement of a generation that nothing records yet (`CreateFresh`) is one `rename(2)`. A refusal is a `KeyFileException`: one line with the path and the fix, no stack trace, never key material; the command line prints it and exits 4 (the existing store-error code). (2) **Process hardening (Linux only, skipped on Windows, libc through P/Invoke, no package).** The service and `pair` make the process non-dumpable (`prctl(PR_SET_DUMPABLE, 0)`: no core file, no ptrace or `/proc/PID/mem` read by another process of the same user) before a key is loaded. The arrays that hold a key file's bytes (while it is read or written) and the PRF output of an unlock are pinned and `mlock`ed for their lifetime and wiped before they are unlocked; a refusal by the system (`RLIMIT_MEMLOCK`, a container without the capability) is one warning line in the log (an error number, no content) and never a failure. Not covered: the key objects inside the cryptography library, copies the runtime makes, and swap of memory that was never locked. (3) **Copied-identity warning.** The authority already lets one long poll per machine supersede the previous one. When the superseding poll comes from a different remote address, `CopiedIdentityWatch` counts it; fixed built-in rule: 3 such supersedes within 10 minutes (two services alternating, as seen in the M3b run, reach it at the third; a reconnect from the same address counts for nothing; an IPv4 address mapped into IPv6 is the IPv4 one). It records a warning in the `copy_warnings` table (now in `with-secrets.db`) (machine fingerprint, the most supersedes seen in one window, the two addresses, times; no schema version change) and one signed audit event of type `admin`, outcome `machine-identity-possibly-copied`, at most one per machine per 10 minutes; metadata `machine`, `older-address`, `newer-address`, `count`, `window-minutes`; public data only. Nothing is disabled. The Machines API carries `copyWarning` (an object or null; OpenAPI document and generated client updated) and the Machines screen shows "This machine's identity may have been copied" with the text "Disable this machine if you did not start both." until the machine is Disabled. Two copies behind the same address (a NAT, one Docker bridge) look like one and are not detected. (4) **The machine listener without a restart.** The key ring raises `KeyRecorded` when it makes the first authority signing key; the service started with a machine endpoint hands that to a background start of the listener (`HostService.TryStartMachineListener`), with the same handler, the same peer validation and the same address. No listener exists before the key does. A late start that fails is one log line and the next restart tries again; the terminal says when the listener came up. (5) **The blocked-run outcome.** A run waiting for approval ends as exactly one of: approved (the program's own exit code), refused (Deny: exit 3, "The user did not approve (denied on the page)..."), or timed out (exit 3, which the exit-code table already assigns to "time limit"; its own sentence "Nobody answered before the approval time limit, so nothing was run ... then run again", and its own reason code `approval-timeout` in the signed authorization event and in a remote authority's answer, where a refusal stays `user-denied`). No exit code was added. Tests: suites `Hardening` and `BlockedRun`.

**One database per machine and the review key (current implementation).** This supersedes the file layout and the transaction boundaries of the Phase 2 to M7 paragraphs above. Nothing was released, so nothing is migrated.

- **One file, full schema everywhere.** Every machine keeps exactly one SQLite file, `with-secrets.db` (schema version 3), with the full schema: the manifest, sign counts and secret rows; machines, grants, providers, mounts, namespace and cache rows, authority keys, settings, spent nonces, pairing invitations and the audit history; and the host's audit outbox. A remote host builds the same file; only its outbox tables (and the `audit_history` rows of its own `pair` command) ever hold rows, because secrets, grants, machines and audit history live at its authority. One schema text, one version and one creation path mean a host can be paired, unpaired or made an authority by `host.json` alone, with no second layout and no mode check in the database layer. A file of another version or table layout, and a folder that still holds `state.db`, `authority.db` or `audit-outbox.db`, are refused with a message that ends "delete it to start over"; nothing is converted, renamed or imported.
- **Connection ownership.** `WithSecretsDatabase` owns the file: its creation (a temporary file and a no-overwrite move under the cross-process creation gate `with-secrets.db.lock`), the open checks (`quick_check`, version, layout, old files; once per instance), the pragmas of every connection (`journal_mode=WAL`, `synchronous=FULL`, `foreign_keys=ON`, `busy_timeout=5000`, unpooled), and the only `BEGIN IMMEDIATE` in the program. `StateDatabase`, `AuthorityStore` (with `ProviderStore`) and `HostAuditOutbox` are facades that borrow its connections and transactions and open none of their own. Inside one process every writer takes one gate per file (`WithSecretsDatabase.Write`, a first-in, first-out queue per full path) before `BEGIN IMMEDIATE`, so writers of one process never meet in SQLite's busy handler (the cause of the macOS "database is locked" flake of the split files); opening the connection for a write (its pragmas) or its `BEGIN` failing as busy, locked or protocol is retried on a new connection with a short doubling pause until the busy deadline, and never once the work has started. The writer gate, first creation, opening and `BEGIN` use the same five-second deadline measured from before the writer gate. The creation lock receives the remaining time. The write retry loop handles lock errors from connection setup and `BEGIN` directly, with SQLite and driver lock retries disabled during acquisition. Statements run with the normal busy timeout after the transaction begins. A write inside another write on the same thread fails at once ("pass the transaction instead"). Between processes (the service, `--recover`, the first-time setup, `pair`) SQLite's busy timeout decides. Reads use their own short connection with no gate.
- **One transaction for a change and its event.** An administrative event is appended to the outbox on the change's own connection inside the change's own transaction (`AdminAudit.AppendIn`), so a failure before the commit leaves neither the change nor the event, and an outbox failure leaves the store unchanged. The same holds for provider invalidations and their audit, the copied-identity warning, and the carried pending events of `--recover`. Post-commit signals (`AuthorityStore.Changed`, waking the uploader) run only after the commit.
- **`--recover`** copies the live file, keeps it as `with-secrets.db.recovered-<UTC time>`, and replaces the secret-store tables in the live file in one transaction with its audit events; the machine, grant, provider, authority and outbox tables stay as they are.
- **The review key R.** A second Dotenvx key pair, made with the store key K at the first-time setup. The signed manifest carries its public key and its private key wrapped by MK (AES-256-GCM, AAD `with-secrets/v1 review` and the review public key), beside the vault of K. R encrypts only review text (the grant evidence text, which holds the full command line, inline code and ordinary `.env` values the person saw); K never does, and R never encrypts a secret value. Writing needs only the public half from the verified manifest. The private half is plain only in `ReviewKeys` in the service's memory (pinned, wiped like `Unlock`), opened by a PRF-bearing tap of an admin passkey with user verification: a manual unlock tap that releases PRF, or the operation `review-unlock` ("Locked: tap to review" in the Grants view; the PRF output is sealed to the inline authorization's `prfKey` as on the approval page, `SealedPrf`). Lock, restart and a store-key rotation close it; an unattended unlock never opens it; it is never given to a remote host. Reading review text (`GET /api/v1/grants/{id}/review`) needs an admin session (an approval-only session gets `403 admin-required`) and is not audited per read; the tap that opened R is. A store-key rotation makes a new R and, in the same transaction as the new manifest, decrypts every grant's evidence with the old R, encrypts it to the new one and reseals the row (a locked authority refuses the rotation; a failure changes nothing). `--recover` opens the old R with the recovery code's MK and carries it: the same public key, wrapped by the new MK, so no evidence row changes.
- **Sealed grants.** Each grant row holds `evidence_ciphertext` (the evidence text encrypted to R), the proof, nonce, kind and minutes in clear, the review public key it was encrypted to, and a seal: a signature by the active authority key (`seal_key` is its fingerprint) over the length-prefixed fields after the context `with-secrets grant seal v1`: id, machine fingerprint, scope key, program, folder, secret names, created, updated, expires, grant revision, security revision, status, usage, consumed, replaces, approved by, evidence kind, nonce and minutes, the SHA-256 of the proof and of the ciphertext, the review public key and the authority fingerprint. The authority verifies the passkey assertion over the plain text before it writes, then encrypts and seals in the transaction that writes the row (`GrantSealer`; a locked authority makes no grant). Every use, replace offer and replace checks, without decrypting, that the seal verifies against the active authority key as the key store holds it, names the current review public key, and that the approving credential is still enrolled (an admin key for admin evidence); a failing row is ignored with an audit detail `grant {id}: {problem}`. Revoke and invalidation clear the evidence and the seal. A routine authority key rotation reseals every row that verifies under the old key in the rotation's transaction; a **recovery does not reseal** (a lost or distrusted key must not vouch for anything), so every grant becomes "not verified" and a person approves again. Later item: re-verifying each row's passkey assertion while R is open and resealing it with the recovered key.
- **What stays in clear, and why.** The grant's program, folder and secret names (needed for the scope check on every use without decryption, and shown in the Grants view; no arguments). The outbox events and the authority's `audit_events.arguments`: arguments after `AuditRedaction` (secret-like values masked, long ones cut), signed by the machine key over the clear text and searchable in the Audit view; a remote host has no R. `audit_history`, `machine_history`, the processed-request answers and grant events: short reasons and signed answers, no arguments. The approval queue's review text is memory only. `state.db` no longer exists, so its old "raw arguments" limit is gone.

### 10.3 Secret providers, logical mounts, and namespaces

**Status:** Provider core built: the adapter contract and registry (10.3.1), provider instances, mounts and the logical namespace in `with-secrets.db`, retrieval with bounded retries (10.3.4), the authority-signed cache with stale serving and proactive refresh (10.3.3), and delivery of mounted secrets through the run's secret source, wired into the authority. No real provider adapter ships yet (the tests register a test adapter type). The mount and project-permission configuration formats, and the admin screens for providers and mounts, remain open until plan 3; until then no instance or mount can be made outside code.

**Built (provider core).**

- `ProviderAuthority` composes the provider side once per authority process: the local authority's service in local mode, the authority's service in remote mode (a host whose authority is remote composes none; its runs get mounted values from the authority like native ones). Runs read `ProviderSecretSource`, the native store plus every mounted secret; with no mount it serves the native store exactly as before. At start the invalidation subscription is made first (an invalidation reported during initialization is applied), then the stored instances are added to the registry all at once, and the proactive refresher runs; both stop with the service. Start is bounded at 15 s whatever the adapters do: an instance whose `InitializeAsync` has not returned after 10 s (even one that ignores its token) is removed again within the 5 s shutdown deadline; it, and one that cannot be added, stays unregistered, is logged by name and exception type, and its mounted secrets fail closed.
- The per-instance generation that lets an in-flight retrieval detect an invalidation lives in memory in the one `ProviderStore` of that process, so the authority process must be the only writer of provider data in `with-secrets.db`.
- `ISecretSource.LabelFor(name)` names each secret's source on the approval page: the provider instance name for a mounted name, `global` otherwise.
- `ISecretSource.GetValues` stays synchronous; the provider source runs its asynchronous retrieval with `Task.Run(...).GetAwaiter().GetResult()` (no synchronization-context deadlock).

with-secrets supports multiple secret sources/providers concurrently. Project declarations use logical names; the host authority maps those names to configured provider instances.

**Logical paths**

Examples:

- `secret://personal/github/token`
- `secret://team/development/github/token`
- `secret://infrastructure/aws/production/access-key`

The path is a logical name only. It does not expose provider name, account, SDK, API endpoint, or physical storage location to the project. Path segments are organizational namespaces, not implicit provider selectors.

Ruling: mounted names share the store-name syntax. A logical path is exactly a store name (`SecretNames.IsValid`), as `TOKEN=secret://team/GITHUB` already maps to the store name `team/GITHUB`. A name that a mount selects is mounted; any other name is native.

**Mount model**

- A mount maps a logical location to a configured provider instance and a provider-side location. There are two forms: a **tree mount**, which maps a provider-side folder/namespace and exposes its relative contents below a logical folder; and an **individual-secret mount**, which maps one specific provider secret to an arbitrary logical secret path.
- For a tree mount, the logical path is formed from the logical mount point plus the provider-relative path beneath the configured provider base path. For an individual-secret mount, the configured logical path names that one provider secret; its provider-side path need not resemble the logical path.
- Mounts are configured by the host authority, not checked into the project repository. Project files remain portable and contain no provider credentials or machine-specific provider configuration.
- Mount definitions are global, with project-specific permissions/allowlists. A project may use a logical path only when policy grants access.
- Multiple mounts/providers coexist. A provider tree can be mounted at multiple logical locations, and individual secrets from different providers can be mounted into the same logical namespace. The same underlying provider secret may therefore have multiple logical paths.
- Provider ACLs remain in force. with-secrets human approval is an additional release gate, not a replacement for provider authorization.
- Provider authentication and SDK/API credentials stay on the host/authority side. Windows/WSL/Docker CLIs do not receive provider credentials and do not need provider SDKs.
- Logical path resolution uses **longest-prefix matching** for tree mounts, with segment-boundary-aware prefixes. More-specific tree mounts override broader tree mounts for their subtrees. An individual-secret mount resolves its exact logical secret path. This is deterministic namespace routing, not fallback: once a logical path selects a mount, any permission, availability, authentication, or missing-secret failure is a hard error and must not fall through to another mount or provider.
- Ruling: a mount takes precedence over the native store. A name a mount selects is served by that mount only; a native secret of the same name is shadowed. Overlap at creation: two tree mounts may not share a logical path, nor two individual mounts; an individual mount may sit inside a tree mount (the exact path beats the prefix). A mounted name that has no namespace entry is not a secret of the store at all, so the run refuses it before any page (no provider audit). A name the mount selects that has no entry when the values are read (its entry vanished while the approval was open, or a native secret of that name is shadowed by a mount that has no entry for it), or whose instance row is gone, is "not available": a hard error, and the whole call is audited Failed, every mounted name of it, against the selected instances.

**Provider identity, logical identity, and shared values**

- Every listed provider secret has an external identity supplied by its adapter. The identity is opaque to the core and scoped to one provider instance; the core stores and compares it but does not parse it.
- If the provider exposes no native stable ID, its first-party adapter constructs one from provider-specific information. The adapter must return the same ID for the same underlying secret across listings and restarts, and preserve it across renames or moves when the provider can establish continuity.
- The core associates provider instance ID plus external secret ID with one underlying secret identity. Logical paths are separate references to that identity, not the identity itself.
- The same external identity may be exposed through multiple logical paths, including multiple tree mounts or a combination of tree and individual-secret mounts. These are references to the same underlying secret.
- Cache entries and freshness state are keyed by provider instance ID plus external secret ID, so the underlying value is cached once regardless of how many logical paths reference it. Grants and project permissions remain specific to the logical path through which access is requested; a grant for one logical path does not authorize another.
- Provider invalidation identifies an underlying secret by external ID. The core resolves that identity and invalidates its cached value and grants for every logical reference.

**Logical namespace reconciliation**

- The core maintains the logical folder/file structure implied by configured mounts and provider listings. Tree mounts populate and reconcile their exposed files; individual-secret mounts define one explicit logical file.
- Provider paths returned by an adapter are relative to the provider-side base path for the tree mount. The core combines that relative path with the logical mount point to form the logical path.
- A successful, complete listing reconciles the contents of the listed scope. A failed, cancelled, rate-limited, or incomplete listing never implies deletion and leaves the last known logical entries intact.
- A file is removed from the logical namespace only when the core has reliable confirmation that it is genuinely absent, such as its absence from a successful, complete listing of the relevant scope or an explicit provider deletion signal.
- Confirmed deletion removes the logical file entry and invalidates its cached value and all grants associated with that logical file. A later file created at the same provider path with a different external ID is a new underlying secret at the same logical location; it receives no previous cache value or grants and requires fresh authorization.
- Removing a provider file does not remove the configured mount or its parent logical folders. Multiple logical references to the same external identity are reconciled independently as files, while sharing the underlying cache identity.
- Ruling (listing scope): the contract has no folder marker, so the core calls `ListSecretsAsync` once per mount scope (`Path` = the mount's provider base path, `Filter` null, paging by `ContinuationToken`) and takes every returned item as a file of that scope; it does not recurse. The adapter chooses how deep the scope's items go. For an individual mount the scope is the parent of the secret's provider path with `Filter` = the secret's leaf, and the single match supplies the external id. Built in `NamespaceReconciler`; what triggers a reconciliation (admin screens) is plan 3.
**No fallback or cross-provider search**

- A missing mount, denied project permission, unavailable provider, missing secret, or provider authentication failure is a hard error.
- Do not search other mounts/providers, fall back to an environment variable, prompt for an alternate name, or silently substitute another value.
- Do not query every provider looking for a matching name. This prevents accidental cross-tenant disclosure and keeps resolution auditable.
- Approval and audit identify the logical name and selected provider/mount identity without exposing credentials or values. Built: the approval page shows the provider instance name after a mounted name (`team/dev/GITHUB (vault-one)`); the audit records the path and the instance id and name.

**First-party providers and Dotenvx integration**

with-secrets has two distinct Dotenvx-related integrations; they must not be conflated:

- **Default local provider:** The built-in local encrypted SQLite provider stores with-secrets-managed secrets in its local store. It uses `Dotenvx.Primitives` for the encrypted-value cryptography through `DotenvxCipher`. This is a storage/cryptography dependency, not the Dotenvx provider architecture, and it does not make Dotenvx the provider for those values.
- **Dotenvx provider:** A separate first-party provider adapter uses the Dotenvx provider architecture to retrieve secrets from backends supported by Dotenvx. This is the integration point for Dotenvx-supported providers such as 1Password, Bitwarden Secrets Manager, and Armor. Use `Dotenvx.Core` within this adapter where its provider architecture supplies the required functionality. Its use here does not change the with-secrets-owned project `.env` parser, launch planning, approval, logical mount, or secret-delivery boundaries.

The Dotenvx provider is one provider instance/type behind the same with-secrets adapter and logical-mount boundary as other providers. Dotenvx's backend selection and provider-specific authentication/retrieval behavior remain inside that adapter; they do not become project declaration syntax or implicit cross-provider fallback. The authority still owns logical path authorization, batching at the with-secrets adapter boundary, cache/freshness policy, and delivery. The Dotenvx adapter is responsible for mapping a with-secrets batch onto Dotenvx's supported operations and preserving per-request result identity and errors.

Direct first-party adapters for 1Password, Bitwarden Secrets Manager, Armor, HashiCorp Vault, or other backends may be considered independently; using Dotenvx to access a backend does not require or imply a separate direct adapter for that backend. These are not first-release requirements. LastPass remains an optional candidate only if its command-line client supports the required unattended service operation. For Bitwarden, the target is Secrets Manager, not the personal password-manager product.

Each mount records the provider instance UUID, the mount kind (`tree` or `single`), a logical path and the provider base path. The administration API accepts these fields as `instance`, `kind`, `path` and `base` when adding a mount. Removing and adding mounts requires separate passkey taps and ends active grants for names whose source changes. Project `.env` declarations continue to refer to logical names with `secret://`. The approval page names the provider instance.

### 10.3.1 Provider adapter contract and lifecycle

**Status:** Contract built as specified below (`Providers/ProviderContract.cs`), with batch validation (`ProviderBatch`) and the registry (`ProviderRegistry`: types, instances, lifecycle, health, invalidation). The authority bundles Bitwarden Secrets Manager and exposes its setup in the administration app.

Provider adapters isolate provider-specific access behind the authority. Adapters execute in-process with the authority; they are not separate services or plugins loaded dynamically at runtime. The authority discovers and registers the adapters bundled with its release. Adapter implementations may be independently identified/versioned, but are distributed with and tied to an authority release.

An adapter instance represents one configured provider connection. Multiple connections to the same provider type use separate instances and independent configuration. The authority assigns each instance a unique, stable instance ID and supplies it during initialization. In remote mode, adapters run at the remote authority; in local mode, they run at the local authority.

**Responsibilities and boundary**

- The adapter contains provider integration logic only. It does not provide UI, HTML, JavaScript, dynamic configuration forms, or configuration schemas for the admin UI.
- The admin UI owns provider-specific configuration screens. The adapter exposes its configuration type and validation results for the authority/UI integration.
- Adapters are read-only with respect to provider data: no create, modify, rotate, delete, or migration operations.
- The core depends only on the common adapter contract, not provider SDKs or provider-specific types. The `Dotenvx.Core` dependency belongs to the dedicated Dotenvx provider adapter, not `WithSecrets.Core`; `WithSecrets.Core` may reference `Dotenvx.Primitives` for the built-in local store's encryption.
- Every adapter implements the complete required contract. There are no optional capability flags or optional operations.
- The authority owns provider configuration persistence, configuration revisions, operation timeouts, concurrency limits, cache/freshness policy, grant lifetimes, and secret delivery. Adapters do not own the secret cache and do not write cache timestamps.
- Adapters must be thread-safe, support concurrent calls, and honor cancellation. They may declare provider-specific concurrency constraints for the authority to enforce.

**Required operations**

Every adapter provides initialization, configuration update, shutdown, configuration validation, mount validation, **batch secret retrieval**, and secret listing. Pagination is implemented internally by the adapter and exposed through opaque continuation tokens.

The authority resolves and authorizes each requested logical path, applies cache policy, and groups the remaining provider reads by the exact configured provider instance. For one launch, it invokes each affected adapter with one batch containing that instance's uncached secret requests (one request per distinct external id). It does not combine requests across provider instances or across launches. Ruling: the instances of one launch are retrieved one after another, so the worst case is N instances times the 10 s deadline; retrieving them in parallel is deferred. Cache hits are not sent to the adapter. Retries may submit only the requests that remain eligible for retry, within the existing bounded retry/deadline policy.

Batching is a provider invocation boundary, not a promise of one provider network/API request or one user prompt. An adapter may need multiple provider operations internally, but it must coordinate authentication for the batch rather than independently initiating authentication for every secret. It returns one individually attributable result for every request, preserving request identity even when paths repeat. A missing, duplicate, or unknown result identity, or a result that contains neither a value nor an error, is an InvalidResponse failure; the authority never guesses which value belongs to which request. A batch-wide failure is reported as ProviderAdapterException and applies to the outstanding batch; an item-specific failure is returned only for that request. Successful items remain independently usable, subject to the normal launch-wide fail-closed rules for any required secret that failed.

```csharp
public interface IProviderAdapter
{
    Type ConfigurationType { get; }

    Task InitializeAsync(
        IAdapterConfiguration configuration,
        AdapterInitializationContext context,
        CancellationToken cancellationToken);

    Task UpdateConfigurationAsync(
        IAdapterConfiguration configuration,
        CancellationToken cancellationToken);

    Task ShutdownAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<ProviderValidationIssue>> ValidateConfigurationAsync(
        IAdapterConfiguration configuration,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<ProviderValidationIssue>> ValidateMountAsync(
        IAdapterConfiguration configuration,
        string basePath,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<ProviderSecretResult>> RetrieveSecretsAsync(
        IReadOnlyList<ProviderSecretRequest> requests,
        CancellationToken cancellationToken);

    Task<ListSecretsResult> ListSecretsAsync(
        ListSecretsRequest request,
        CancellationToken cancellationToken);
}
```

There is deliberately no health-check or refresh operation. The adapter owns its provider connection and recovery behavior and reports health changes when it learns them; the core does not poll adapters. Retrieval occurs only when the core asks for a secret. The core decides when to retrieve again based on its cache and freshness policy.

**Configuration contract**

- Adapter configuration is a strongly typed in-process .NET object. JSON is the persistence format, not the runtime boundary.
- Each adapter defines a concrete configuration type implementing `IAdapterConfiguration`, including `Load(JsonDocument document)` to load persisted JSON.
- The adapter factory selects the adapter type, creates the matching configuration type, loads it, and passes the typed configuration to the adapter.
- A generic base class may provide typed configuration storage, type checking, and dispatch only:

```csharp
public abstract class ProviderAdapter<TConfiguration> : IProviderAdapter
    where TConfiguration : class, IAdapterConfiguration
{
    public Type ConfigurationType => typeof(TConfiguration);
    protected TConfiguration? Configuration { get; private set; }
}
```

The base class does not manage provider connections, recovery, rollback, or atomic replacement of adapter-owned resources.

The authority serializes configuration updates per adapter instance. `UpdateConfigurationAsync` receives an already committed configuration, applies it, and returns promptly; provider connection establishment/re-establishment continues asynchronously. A connection failure after the configuration has been committed does not reject or roll back that configuration. When a newer update arrives while an earlier connection attempt is running, the adapter cancels or supersedes the stale attempt and converges on the latest committed configuration. A stale attempt must not overwrite health for the newer configuration.

Configuration validation may contact the real provider using the proposed configuration. Validation issues have a message, severity, and optional UI target:

```csharp
public enum ValidationSeverity
{
    Error,
    Warning
}

public sealed record ProviderValidationIssue(
    string Message,
    ValidationSeverity Severity,
    string? Target = null,
    string? ProviderCode = null);
```

An error blocks saving. A warning permits saving after explicit admin confirmation; for example, a provider may be temporarily unavailable or rate-limited during validation. `Target` may identify a field or category for UI highlighting. `ProviderCode` is an optional provider-specific diagnostic code for display and troubleshooting; core behavior does not depend on it. Messages must be actionable and safe for administrator display and must not include credentials, secret values, or raw provider response bodies. Adapters are first-party code; normal UI output encoding applies.

Both validation methods return all reliably identifiable issues, not just the first failure. Multiple issues may target the same field or section. The core preserves the adapter's deterministic issue order and does not deduplicate issues. Validation findings are normal return values; operational failures use `ProviderAdapterException`.

`ValidateConfigurationAsync` validates a proposed provider-instance configuration, including its connection and credentials. `ValidateMountAsync` validates a provider-side base path using the supplied proposed configuration without changing the active configuration. Core validation of logical path syntax, mount overlap, and logical routing remains separate from provider-side mount validation.

Provider-specific configuration changes can affect connection state, mount access, or the identity/source of exposed secrets. The adapter determines which existing mounts are affected and reports required provider-data invalidation through the event contract below; the core does not inspect provider-specific configuration fields or classify their meaning.

A proposed configuration is validated before activation. The authority validates the proposed configuration and revalidates every affected mount using that proposed configuration. Any validation error rejects the entire change and leaves the previous configuration, provider resources, mounts, cache, grants, and operational state unchanged. Warnings require explicit administrator confirmation. Only after all required validations pass (and warnings are confirmed) does the authority commit the new configuration and call `UpdateConfigurationAsync`. The adapter then applies the committed configuration and manages its connection/recovery asynchronously. A post-commit operational connection failure does not roll back the committed configuration.

Policy-only changes take effect immediately without reconnecting or invalidating provider data. Reducing a permitted age or duration is enforced immediately against existing cache entries; it never resets `lastVerifiedAt`.

Provider settings belong to configured **provider instances**, not provider types. Two instances using the same adapter/provider type may have different credentials, connection settings, and policies.

**Initialization, lifecycle, and health**

Lifecycle and health are independent status dimensions.

```csharp
public enum AdapterLifecycleState
{
    Initializing,
    Ready,
    Unavailable,
    ShuttingDown
}

public enum AdapterHealthState
{
    Initializing,
    Healthy,
    Degraded,
    Unavailable,
    Misconfigured
}
```

The authority initializes both dimensions to `Initializing`. It owns lifecycle boundary transitions: it sets `Initializing` and `ShuttingDown`; the adapter may report `Ready` or `Unavailable`. Health remains `Initializing` until the adapter has a real provider response or other reliable health information. This avoids presenting an unknown or empty health result during startup.

`InitializeAsync` performs adapter-internal setup and starts provider connection work without waiting for provider connectivity to succeed. Once its internal setup is complete, the adapter reports lifecycle `Ready`, even if the provider connection is still being established; health can remain `Initializing`. If adapter-internal initialization fails, it reports lifecycle `Unavailable` and remains registered so it can recover. Provider connectivity failures normally affect health, not lifecycle. The adapter owns recovery and may later report `Ready` after an internal initialization failure; there is no separate `RecoverAsync` operation.

When configuration is updated, the adapter immediately reports health `Initializing`, applies the configuration, and begins reconnecting asynchronously. Lifecycle does not need to change during a configuration update; for example, it may remain `Ready` while health is `Initializing`.

Status reporting uses one reporter method and typed events:

```csharp
public interface IAdapterStatusReporter
{
    void Report(AdapterStatusEvent statusEvent);
}

public abstract record AdapterStatusEvent;

public sealed record LifecycleChangedEvent(
    AdapterLifecycleState State,
    string? Message = null) : AdapterStatusEvent;

public sealed record HealthChangedEvent(
    AdapterHealthState State,
    string? Message = null) : AdapterStatusEvent;

public sealed record InvalidateProviderDataEvent(
    IReadOnlyList<Guid>? MountIds = null,
    IReadOnlyList<string>? ExternalSecretIds = null,
    bool InvalidateEntireProviderInstance = false) : AdapterStatusEvent;
```

`InvalidateProviderDataEvent` is a separate event on the same reporter/event channel. It identifies what provider data must be invalidated, not why. The adapter may request invalidation for the entire provider instance, one or more mounts, or one or more external secret IDs. The event is scoped to the reporting provider instance, so external IDs are interpreted within that instance. The core resolves the requested scopes to affected logical references.

Every invalidation invalidates both cached values and grants for the selected scope; there are no independent cache-only or grant-only flags. Invalidating an external secret ID affects its shared cached value and every logical reference to it, including references through different mounts. Invalidating a mount affects data exposed through that logical mount; invalidating the provider instance affects all its data.

Adapters may report invalidation while active, including while initializing, ready, or unavailable. The authority rejects invalidation after shutdown begins or after the adapter instance is unregistered. Handling begins immediately but must not block unrelated provider operations; physical cleanup may complete asynchronously. Invalidation takes precedence over work already in progress: a retrieval that finishes after its target has been invalidated must be discarded and must not be cached or delivered. Unrelated in-flight operations continue normally. Ruling: the discard is coarse, per instance. Any invalidation, mount removal, or reconciliation that removes or re-identifies an entry of an instance moves its in-memory generation, and every retrieval of that instance in flight (refresh or delivery, including unrelated external ids of the same instance) is discarded and its launch fails closed; other instances are unaffected.

Each accepted invalidation produces an audit record identifying the provider instance, requested scope, affected identifiers, and timestamp, without values or credentials. The event and audit record do not carry a reason; explanatory detail belongs in structured logs.

The initialization context supplies the instance identity, provider identity/version, logger, and status reporter:

```csharp
public sealed record AdapterInitializationContext(
    Guid InstanceId,
    string ProviderType,
    string AdapterVersion,
    ILogger Logger,
    IAdapterStatusReporter StatusReporter);
```

The authority timestamps status receipt and retains the latest lifecycle and health states, each with an optional concise message and authority-assigned timestamp. It does not persist status history; detailed history belongs in logs. No operation/correlation ID is required in status events because instance identity and structured logs provide correlation. Status messages are suitable for the admin UI and must not contain secret values, credentials, or sensitive provider responses.

Invalid or stale lifecycle reports (for example, a delayed `Ready` after shutdown has started) are ignored and logged at Debug/Warning level; they are not thrown back to the adapter. Health updates are accepted until shutdown begins. After shutdown begins, further health updates are ignored and the last health value is retained.

**Shutdown and removal**

- The authority stops accepting new operations for the adapter and transitions lifecycle to `ShuttingDown`.
- It cancels ongoing initialization and background connection attempts.
- In-flight provider operations are cancelled or allowed to finish within a bounded shutdown deadline enforced by the authority.
- The authority invokes `ShutdownAsync(CancellationToken)`; the adapter releases its connections and other resources.
- The status reporter remains available during shutdown for any permitted final reporting, but lifecycle remains authority-controlled. Once shutdown completes, the authority stops accepting status updates.
- Deleting an adapter instance is blocked while mounts reference it. After references are removed and deletion is committed, the authority stops new operations, drains/cancels in-flight work within the shutdown deadline, shuts down and disposes the adapter, then removes it from the registry. Provider-side data is never modified or deleted.

**Retrieval and listing data contracts**

A retrieval returns UTF-8 bytes only; provider metadata is not returned with the value. Batch requests and results use an opaque per-request correlation ID so results cannot be mis-associated when a batch contains repeated paths:

```csharp
public sealed record ProviderSecretRequest(
    Guid RequestId,
    string Path);

public sealed record RetrieveSecretResult(byte[] Value);

public sealed record ProviderSecretResult(
    Guid RequestId,
    RetrieveSecretResult? Secret,
    ProviderErrorKind? ErrorKind = null,
    string? ProviderCode = null,
    TimeSpan? RetryAfter = null);
```

Each request ID must be unique within the batch. Each result must contain exactly one of Secret or ErrorKind. The adapter returns exactly one result for every request ID and no others. The core validates this contract before using any result; malformed or incomplete batches fail as InvalidResponse and no ambiguous value is delivered. A batch-wide failure uses ProviderAdapterException; an item-specific failure uses that item's ErrorKind, ProviderCode, and RetryAfter. ProviderCode remains diagnostic only, and RetryAfter is subject to the core's existing limits.

The core validates strict UTF-8 before updating its cache and preserves the exact bytes without normalization or re-encoding. The CLI later converts to the target process encoding; if the value cannot be represented, the operation fails rather than silently corrupting it. Host-service responses use UTF-8. An empty provider value is treated as unset: the core reports it as `SecretNotFound`, a hard error for delivery, never stale-served. A missing path or provider error is a hard failure; there is no fallback.

Listing returns one page of immediate children (nonrecursive), names and optional descriptions only, never values:

```csharp
public sealed record ListSecretsRequest(
    string Path,
    string? Filter,
    string? ContinuationToken);

public sealed record ListSecretsResult(
    IReadOnlyList<ProviderSecretInfo> Secrets,
    string? NextContinuationToken,
    bool IsComplete);

public sealed record ProviderSecretInfo(
    string Path,
    string ExternalSecretId,
    string? Description);
```

`IsComplete` is true only when the adapter has successfully enumerated the entire requested scope; intermediate pages are false, and the final page is true only when no results remain for that scope. A failed or cancelled enumeration is an operational failure, not a complete empty result. The core reconciles deletions only after the complete scope has been successfully enumerated.

`Path` is relative to the provider-side base path selected by the mount. `ExternalSecretId` is required and opaque to the core; it is stable for the same underlying provider secret across listings and adapter restarts, and unique within the provider instance. The adapter must supply it even when the provider has no native identifier, constructing a stable provider-specific identifier when necessary. The core stores the external ID and associates it with the underlying secret identity; adapters do not need to know logical secret IDs.

The adapter owns provider pagination. The authority passes the opaque continuation token through unchanged. Listing returns immediate children only (nonrecursive); the UI navigates by requesting subpaths. Provider listing may supply descriptions. Description ownership is explicit:

```csharp
public enum DescriptionSource
{
    Provider,
    Local
}
```

When the source is `Provider`, each provider listing refreshes the effective description, including setting it to null when the provider has no description. When the source is `Local`, provider listings do not overwrite it. There is one effective description and one source marker, not separate competing local/provider descriptions.

**Provider authentication and user interaction**

Provider authentication is distinct from with-secrets approval. The person must still approve the complete requested secret set through the normal with-secrets flow; a provider login, desktop authorization, OS permission dialog, or service-account credential does not grant a with-secrets permission or bypass a grant.

Authentication mode, credential handling, session reuse, refresh, and provider-specific authentication mechanics belong to the adapter and its configured provider instance. The common architecture does not prescribe how an individual provider performs authentication or detects completion; those details are implemented and tested with each first-party adapter.

When user interaction is required, it is initiated explicitly by the person through the local administration web app. The host service owns the authentication lifecycle and provider session. The adapter initiates the provider-supported authentication mechanism when requested by the service; the provider's own UI handles the interaction (for example, a browser flow, native desktop prompt, or OS authentication UI). The administration web app does not implement or impersonate that provider UI. It displays the pending state and refreshes to reflect the resulting provider authentication status.

A launch must not trigger a separate authentication attempt for every secret in a batch. The adapter coordinates authentication for the batch and reuses an established provider session according to that provider's documented behavior. It must not weaken provider verification, disable required OS security prompts, or silently substitute another credential or provider.

The background service must not independently launch interactive authentication or block indefinitely waiting for a person. A required interaction is represented as a pending authentication state that the person can initiate from the administration web app; the service and adapter manage its lifecycle without relying on an agent terminal or a service-owned desktop dialog. A pending secret request may resume after authentication succeeds, but secrets are delivered only after provider authentication and the normal with-secrets authorization both succeed. If authentication is cancelled, fails, or cannot be completed, the affected launch fails closed. There is no prompt-on-the-agent, automatic fallback, or silent substitution. Authentication failures are not eligible for stale-cache serving.

Provider credentials and provider session material remain on the authority side. Secret values are not persisted as part of provider authentication state or in a cross-launch plaintext cache. A provider may retain its own authenticated session/token only as required by its supported authentication mechanism and the authority's credential-protection design.

**Logging and diagnostics**

Adapters use the existing `Microsoft.Extensions.Logging.ILogger` abstraction, which can be backed by the application's existing Serilog setup. There is no separate adapter logging framework or metrics interface. Detailed diagnostics go to structured logs; status messages remain concise and safe for display. Never log secret values, credentials, or decrypted provider responses.

**Implementation notes**

- The adapter contract is a design boundary, not a promise that a provider is already implemented.
- Provider-specific connection setup, authentication, retry/backoff strategy, and recovery are adapter responsibilities; global timeouts, cancellation, concurrency enforcement, cache policy, and status retention remain authority responsibilities.
- Batch retrieval is mandatory for every adapter. The authority groups uncached reads by provider instance for each launch; adapters must preserve per-request result identity and coordinate authentication across the batch.
- Registration is `ProviderRegistry.RegisterType(providerType, adapterVersion, factory, newConfiguration)` for each bundled adapter. The local authority adds each stored instance at start. Bitwarden resolves `bws` from the authority service's PATH and reads the machine-account credential from the named service environment variable. The same environment binds the credential to its server before any CLI invocation. Locking the authority cancels calls from the retired unlock session.
- Provider listing, mount validation, and retrieval must all resolve against the exact configured adapter instance selected by the mount. They must not search other providers or mounts.
- The cache is keyed by provider instance ID plus opaque external secret ID, never by logical path. Grants and project permissions are evaluated against the requested logical path.
- The core owns the association between provider external identity and logical references. Adapters supply external IDs and provider-relative paths; they never need to know core logical IDs.
- Tree-mount listing reconciliation updates the logical file/folder structure. Individual-secret mounts identify one explicit provider secret. Multiple logical references to one external identity share a cache entry but retain independent logical-path authorization.
- A confirmed provider-side deletion removes the affected logical file references and invalidates their grants and the shared cached value. Recreating a secret at the same provider path with a different external ID creates a new underlying identity and does not inherit grants or cached values.

### 10.3.2 Provider versioning and secret rotation

**Status:** Agreed architecture decision.

Logical secret paths resolve to the provider's **current active value**; project declarations and grants do not pin a provider-specific version.

- The adapter retrieves the provider's current active value when the core requests retrieval. Provider version identifiers, version history, and rotation metadata remain internal to the adapter and are not exposed through logical paths, project declarations, grants, or the common retrieval result.
- The core owns cache freshness and determines when another retrieval occurs. A provider-side rotation becomes visible to with-secrets when the core next retrieves the value; it does not bypass the core's cache policy.
- Provider rotation does not change the logical secret identity or require grant changes. Grants authorize the logical secret, not a particular provider version.
- If the provider deletes, retires, or otherwise makes the current secret unavailable, retrieval fails. The adapter must not silently return an older version as a fallback.
- Provider-specific version selection, rollback, and historical-version retrieval are outside the common adapter contract unless explicitly introduced as a future, separately designed feature.

This keeps project declarations and authorization independent of provider-specific versioning models while preserving the core's single cache/freshness policy.

### 10.3.3 Cache freshness, provider outages, and stale serving

**Status:** Agreed architecture decision; built (`ProviderPolicy`, `ProviderCache`, `ProviderSecretSource`, `ProviderRefresher`).

The core owns cache freshness and stale-serving policy. Stale serving is an availability safeguard for temporary provider outages, not an alternate source of truth.

The provider cache is authority-owned and persisted as encrypted ciphertext, using the same Dotenvx.Primitives-based at-rest encryption and native store key K as native entries. Built: the rows are in `with-secrets.db` (`provider_cache`, keyed by instance id and external id), each value encrypted to K's public key from the verified native manifest (writing needs no tap; reading needs K, released by the run's passkey tap), and sealed by the authority signing key over the instance id, the external id, `lastVerifiedAt` (UTC ticks), the SHA-256 of the ciphertext, the store public key and the signing key's fingerprint. A row whose seal does not verify against the ACTIVE authority key, or that names another store public key, is a miss and is refetched; an authority key rotation therefore turns every row into a miss (ruling). The active key is the public part the key store holds (`AuthorityKeyRing.ActivePublicKey`), never the `authority_keys` row alone, so a planted key row with a row it sealed is a miss. Ruling 7, configuration integrity: provider configuration rows (instances, mounts, namespace entries) are not sealed, like machines (grants are sealed since "One database per machine and the review key"). A writer of `with-secrets.db` therefore cannot inject plaintext of its choosing (the cache seals), but it can redirect an approved logical path to another secret the provider instance can read: (a) change `namespace_entries.external_id` of the path to another external id of the same instance; (b) change `mounts.instance_id` or `mounts.base_path` to send the path to another instance or provider location; (c) change only `namespace_entries.provider_path`, so the next fetch stores secret B under A's external id and poisons the cache row for every path that references A. Plan 3's admin-tap binding of configuration changes must cover all three tables, `provider_path` included. While the authority is locked nothing is signed, no row is served and no refresh runs. The existing MK/passkey-recovery unlock hierarchy protects K; no separate cache key or unlock mechanism exists. K and decrypted values remain memory-only and are cleared on lock or restart. The cache's stale-serving behavior is governed by the rules in this section. It does not authorize offline secret use, create an offline authorization lease, or allow secret retrieval while the authority is unavailable (10.2).

- Stale serving is configured per provider instance through MaxStaleDuration. It is not a provider-type setting and is not configured per secret or mount. The same setting remains the single stale-serving limit; do not introduce a second stale-duration or cache-lifetime setting.
- The default is zero (live retrieval with no provider-value caching). A configured value may be from zero through a hard system-wide maximum of 24 hours. Values above the cap are rejected, not silently clamped. The cap is a system constant initially, not another administrator setting.
- The maximum age is measured from the cached value's lastVerifiedAt timestamp: the last successful retrieval that proved the value current. It is not measured from when an outage begins. A value already 20 hours old has at most 4 hours remaining under the 24-hour maximum.
- A cached value may be served stale only after the core's bounded retry policy is exhausted for an eligible temporary availability failure (Unavailable or RateLimited), and only while its age remains within that provider instance's configured MaxStaleDuration.
- Stale fallback does not apply to authentication or authorization failures, missing/deleted secrets, invalid configuration, invalid provider responses, unknown errors, or cancellation. If no cached value exists, retrieval fails.
- When caching is enabled, a successful provider retrieval replaces the encrypted cached value and updates lastVerifiedAt. A failed refresh leaves both the existing cached value and its original lastVerifiedAt unchanged. A failure must never extend the stale-serving window. Locking, restarting, decrypting, or reading a cached value does not update lastVerifiedAt.
- When MaxStaleDuration is greater than zero, the authority schedules a proactive batch refresh when a cached value reaches 75% of that duration (for example, at 18 hours for a 24-hour setting), leaving a refresh margin before the stale boundary. Due values are grouped by provider instance and refreshed through the existing batch retrieval contract; do not add a separate per-secret refresh API or another freshness setting. A successful refresh replaces the ciphertext and resets lastVerifiedAt. A failed refresh leaves both unchanged and is retried only under the core's bounded retry/backoff policy; it must not create a tight retry loop. The authority also attempts refresh for stale or missing values when a request requires them and the provider is available. With MaxStaleDuration set to zero, retrieval is live and on demand with no cache reads, writes, or refreshes.
- Proactive refresh does not require or create a with-secrets grant, does not extend any grant, and does not make a value deliverable to a caller. It updates only the provider cache. Secret delivery still requires an unlocked authority, current authority authorization, a valid grant or normal approval, and a value that meets the freshness rules.
- Background refresh must not launch provider authentication UI or wait indefinitely. If provider authentication is required, the existing web-initiated provider-authentication flow applies. A failed or interrupted refresh preserves the previous ciphertext and lastVerifiedAt; if that value exceeds the stale limit, it cannot be delivered until a successful refresh.
- Once the maximum permitted age is reached, retrieval fails closed. When the provider recovers, the next retrieval attempt fetches the current provider value and replaces the stale cache entry; there is no special stale-first recovery mode.
- MaxStaleDuration is stored in whole seconds (`max_stale_seconds`): a value with a fraction of a second is refused, like one above 24 hours, never rounded.
- A fresh value that cannot be written to the cache fails the delivery closed, unless the write failed only because the authority locked during the call (the value is then delivered and not persisted). A call that names a mounted secret while the authority is locked fails closed before anything is read or retrieved. A failed delivery discards held grant keys, so after a provider outage the next run needs a new passkey tap: in local mode the grant key this host held; in remote mode every machine's held grant key at the authority, not only the requesting host's (`AuthorityLaunchHandler.DropKeys` drops them all on a failed grant decrypt). Keeping the key across a transient Unavailable is a plan 3 follow-up.
- Ruling (final review): adding or removing a mount ends the active grants of the names whose source changes, in the same transaction, with grant events so hosts drop them: RemoveMount ends every active grant naming a name the mount selected (it now falls to the native store or a broader mount); AddMount ends every active grant naming a name the new mount now selects (a shadowed native name, or a name a broader mount served), so adding a shadowing mount costs a re-approval. Both move the affected instances' generations inside and after the transaction. RemoveInstance deletes the instance's cache rows in its transaction; each refresh pass first deletes cache rows that no namespace entry references.
- Changing MaxStaleDuration is a policy-only provider-instance configuration change. It applies immediately to existing cache entries without reconnecting or reinitializing the adapter and without changing cached values or timestamps. Reducing the duration immediately enforces the shorter limit.

Rulings of the provider core:

- Freshness: a cached value is Cached (served without calling the provider) only while its age is below 75% of MaxStaleDuration and MaxStaleDuration is above zero. At or beyond that, or with MaxStaleDuration zero, a request retrieves from the provider; on a final Unavailable or RateLimited it serves the row stale only while its age is at most MaxStaleDuration. A row whose `lastVerifiedAt` lies in the future (a clock that went back) is neither fresh nor stale-servable.
- Rows are persisted only when MaxStaleDuration is positive. Setting it to zero removes existing rows in the same transaction. A policy change advances the provider generation, and a write checks the current policy in its transaction. The one-time database upgrade clears legacy rows and resets existing providers to zero because the previous UI prefilled a positive duration.
- Superseded writes: a retrieval that started earlier but commits later never overwrites a row with a newer `lastVerifiedAt`; it still delivers its own value as Fresh.
- Stale fallback serves the row read before the retrieval only if it still verifies unchanged afterwards; a row rewritten or deleted meanwhile by a concurrent run fails closed.
- The background refresher halts, until a NEWER `lastVerifiedAt` (an on-demand success) lifts it, a row whose refresh ended in AuthenticationFailed, InteractionRequired or AccessDenied (AccessDenied too, stricter than the spec's retry rule: it needs a policy change). Other failures back off per row from one minute, doubling to at most 15 minutes, reset by a success. A row that does not exist is never created by a refresh. Its state is in memory.

Audit history records the retrieval outcome without recording secret values or credentials:

| Outcome | Meaning |
| --- | --- |
| Fresh | Value retrieved successfully from the provider for this request |
| Cached | Value served from cache within the normal freshness policy |
| Stale | Expired cache value served under the provider instance's outage allowance |
| Failed | Retrieval failed and no value was delivered |

Each audit event identifies the logical secret path and selected provider instance, with its timestamp. A Cached outcome does not imply an outage; it means the cached value was still within normal freshness policy.

Built: one signed host audit event per mounted name of a call, type `admin` (the type of the service's events that are not a run's own), outcome `provider-fresh`, `provider-cached`, `provider-stale` or `provider-failed`, the path as the argument, metadata `path`, `instance` (id), `instanceName`, `outcome` and `errorKind` (when there is one); never a value, ciphertext, credential or external id. The events of one call are built in full and committed in ONE outbox transaction after the outcome is known; if that commit fails, the call fails and every value is zeroed, so no record names a value that was not delivered. A failed call records every mounted name Failed: with its error kind when its retrieval failed, without one when it succeeded but is held back, or was never retrieved. An accepted invalidation is the event `provider-data-invalidated` (type `admin`) with the instance, scope, mount and external ids, paths and counts.

### 10.3.4 Provider errors, cancellation, and retries

**Status:** Agreed architecture decision; built (`ProviderRetriever`, `ProviderPolicy`). The system-wide constants: at most 3 provider invocations per request, waits of 200 ms then 400 ms between them, a `RetryAfter` honoured up to 2 s, and an overall deadline of 10 s per provider instance batch. None is configurable.

Adapters translate provider-specific failures into a common typed exception. Core behavior depends only on the common error category, never on provider-specific exception types or message parsing.

~~~csharp
public enum ProviderErrorKind
{
    Unavailable,
    RateLimited,
    AuthenticationFailed,
    InteractionRequired,
    AccessDenied,
    SecretNotFound,
    InvalidConfiguration,
    InvalidResponse,
    Unknown
}

public sealed class ProviderAdapterException : Exception
{
    public ProviderErrorKind Kind { get; }
    public string? ProviderCode { get; }
    public TimeSpan? RetryAfter { get; }

    public ProviderAdapterException(
        ProviderErrorKind kind,
        string message,
        string? providerCode = null,
        TimeSpan? retryAfter = null,
        Exception? innerException = null)
        : base(message, innerException)
    {
        Kind = kind;
        ProviderCode = providerCode;
        RetryAfter = retryAfter;
    }
}
~~~

- ProviderCode is optional provider-specific diagnostic metadata for structured logs and troubleshooting only. It must not contain credentials, secret values, or sensitive provider response data. Core behavior is determined exclusively by Kind.
- RetryAfter is optional provider-supplied retry guidance, principally for rate limiting. The core owns retry scheduling, limits, and backoff; adapters do not run independent retry loops.
- Only Unavailable and RateLimited are retryable. Authentication failures, interaction-required failures, access denial, missing secrets, invalid configuration, invalid responses, and Unknown fail immediately and are never retried. InteractionRequired means the provider needs a human or interactive desktop action that the authority cannot complete in the current execution context; it is not a request for the agent to collect credentials.
- Item-level errors returned in ProviderSecretResult follow the same categories and retry rules as ProviderAdapterException. An item-level Unavailable or RateLimited result may be retried as part of a smaller batch; other item-level errors are final. A batch-wide ProviderAdapterException applies to all requests still outstanding in that invocation.
- The core applies a small, bounded number of automatic retries with a bounded overall retrieval deadline. System-wide defaults and limits govern retries; provider instances and adapters cannot expand them. A supplied RetryAfter is respected only within those core-enforced limits.
- Retries apply only to the provider operation. Mount resolution, authorization, and cache-policy evaluation occur once per request, and the selected provider instance remains fixed throughout the request.
- Caller or authority cancellation propagates as cancellation and does not qualify for stale fallback. A provider-side timeout is translated to ProviderAdapterException(Unavailable). If the authority's provider-operation deadline expires while the caller remains active, the operation is treated as Unavailable and may qualify for stale fallback after retries, subject to the normal stale policy.
- After retry exhaustion, stale-cache eligibility is determined by the final common error category and the provider instance's MaxStaleDuration. Unexpected exceptions are treated as Unknown and fail closed.

### Shared database

`WithSecretsDatabase` owns the full schema and opens every connection with WAL, FULL synchronous writes, foreign keys and a five-second busy timeout. A per-path writer gate prevents concurrent writers within a process from contending inside SQLite. The creation lock protects first creation across processes. An unknown schema or a previous split file is refused without migration.

The state, authority and outbox facades use the same database. Administrative changes append their signed outbox events in the transaction that writes the change. The uploader wakes after commit. A restored machine starts a new epoch and uploads events signed by its own identity. Pending events signed by another machine can never be uploaded from it (the upload session authenticates only this machine), so the uploader marks them rejected (`signed by another machine`) the next time it runs: they stay in the outbox tables for the person to see and are never sent or left pending. The backup keeps them as they were.

### 10.5 Administration web application and API

The Providers view is available when the local authority advertises `capabilities.providers` and the signed-in session has `admin.read`. It shows instance health and lifecycle, cache policy, mounts and namespace metadata. The six instance and mount mutations use the existing inline passkey flow. Validation and manual namespace refresh use `admin.decide` with same-origin and anti-forgery checks. Provider credential entry is deferred. See [Providers and mounts](reference.md#providers-and-mounts).

**Status:** Accepted target design. This defines the canonical human administration interface for the host service and authority. It does not change the security or deployment boundaries in Section 10.2.

#### Frontend application

- Use React, TypeScript, and Vite.
- Build one cohesive, fully responsive single-page application (SPA), not separate websites for individual workflows. Desktop, tablet, and mobile are first-class layouts.
- Use standard HTML, CSS, and TypeScript. Use CSS Modules and CSS custom properties for shared styling/design tokens, with CSS Grid and Flexbox for responsive layouts. Prefer native HTML controls where practical.
- Do not introduce a large UI component framework initially; build small reusable accessible components.
- Organize the UI by feature, including machines, providers, mounts, grants, approvals, policies, authority status/settings, and audit.
- Keep presentation separate from API communication. Generate the TypeScript API client from the OpenAPI contract.
- Use URL-based navigation for primary application views and dialogs for contextual operations. Use React state for local UI state and a small server-state/query library (TanStack Query) for fetching, caching, mutations, and invalidation. Do not introduce a global Redux-style state store initially.
- The SPA is the canonical human interface. Native applications may be added as optional clients later; they are not required components and do not form a security boundary.

#### Optional native tray application

The tray application is an optional desktop integration for platforms where a native tray is useful. It is not part of the authority, the host service's authorization boundary, or the canonical administration UI.

- It may show OS notifications and concise host-service/authority status, and launch the system browser at the exact relevant administration page.
- It does not embed a browser, duplicate the administration SPA, display secret values, approve or deny requests, authorize operations, or hold independent policy state.
- It communicates with the local host service through the same authenticated local transport and application protocol used by other local clients. It does not receive a special privileged endpoint or bypass authorization.
- It is not required for headless operation or for Docker/WSL deployments. The service and browser administration remain fully usable without it.

#### Accessibility

Target WCAG 2.2 AA throughout the application, including every security-sensitive workflow.

- Support keyboard-only operation, visible focus, logical tab order, semantic HTML, and accessible names, labels, and descriptions.
- Manage focus correctly in dialogs and announce validation errors and asynchronous status changes accessibly.
- Meet contrast requirements; do not use color as the only indicator.
- Support text scaling and 200% zoom. Ordinary workflows must remain usable on small screens without horizontal scrolling.
- Provide adequate touch targets, respect reduced-motion preferences, and avoid flashing content.
- Passkey enrollment, authorization, unlock, and recovery flows must be accessible and must not impose unnecessary time limits.
- Include automated accessibility checks and manual keyboard-only and screen-reader testing.

#### API contract and browser security

- OpenAPI is the authoritative, documented API contract. Generate the frontend TypeScript client from it.
- Initial API namespace is `/api/v1/`. Changes within v1 are additive and backwards-compatible; breaking changes require a new major version. Unsupported versions return a documented error.
- Treat every client as untrusted. The server validates every request and enforces authentication, authorization, and operation-specific security. UI restrictions, hidden controls, and obscure endpoints are not security controls.
- Validate request schemas and bound request sizes. Return safe errors without leaking secrets, credentials, private keys, recovery material, or internal security details.
- Never include secret values, provider credentials, private keys, or recovery material in API responses, logs, diagnostics, telemetry, or errors.
- Serve the frontend and API from the same origin. Do not enable general CORS. Validate browser origins and protect browser state-changing requests against CSRF.
- API routes under `/api/v1/` must never fall through to the SPA fallback. Application routes should resolve to the SPA.

#### Read-only browser session and per-operation administration authorization

A browser session and administrative authorization are separate security concepts.

**Browser session**
- Use a server-managed `HttpOnly`, `SameSite` cookie with expiration, CSRF protection, explicit logout, and revocation.
- The browser session is read-only: it permits navigation and inspection of authorized metadata.
- Browser session credentials cannot authorize state changes and cannot be elevated into a generally privileged session.

**Administrative authorization**
- Every administrative mutation requires a fresh passkey authorization with user verification.
- Bind authorization to the exact operation and its security-relevant parameters.
- Make authorization time-limited, single-use, and replay-protected.
- Completing one operation does not authorize a subsequent operation. Each mutation requires its own fresh authorization.
- Enforce this at the API/server boundary, regardless of frontend behavior.
- Routine use of an existing applicable grant does not require fresh administrative passkey authorization; creating or changing grants does.
- Grant management provides an administrator action to extend an active grant's expiration without repeating the original approval. The administrator reviews the existing scope and selects the new permitted expiration before completing a fresh passkey authorization. The operation cannot broaden the grant.
- A once-only grant that has not been used may have its lifetime/usage policy corrected. If it has already been consumed, the UI offers a same-scope replacement grant rather than reactivating the consumed record. Expired grants may be renewed under the same scope; revoked grants cannot be restored. The original grant and every administrative extension, correction, renewal, or replacement remain separately visible in audit history.

#### Administration UI secret boundary

The administration UI manages metadata, not secret values.

It may manage provider configurations, logical mounts and paths, machine identities and trust, grants, policies, authority settings, and audit records. It must not retrieve or display existing secret values, provider credentials, private keys, or recovery material.

The only credential-entry exception is when an administrator explicitly creates or replaces a provider credential:

- Use a dedicated credential-submission endpoint and request model.
- Treat the input as write-only: never return, prepopulate, reveal, or offer to copy the credential.
- Exclude request bodies from logs and telemetry.
- After saving, display metadata only (for example provider identity, credential status, and last-updated time).
- Replacement is atomic: validate and securely store the proposed credential before activating it; preserve the existing credential if validation or storage fails.
- Provider-specific credential semantics remain adapter-owned. The adapter reports standardized validation and provider-data invalidation results; core logic does not inspect credentials or infer provider-specific authentication semantics.

Secret retrieval remains exclusively part of authorized child-process launches.

#### Hosting, packaging, and deployment scope

- Kestrel serves the SPA and API from the same origin.
- The Windows host service serves the frontend and `/api/v1/`.
- Vite builds static frontend assets ahead of time. Bundle those assets into the .NET application and publish one self-contained Windows EXE. There must be no loose frontend files, Node runtime, separate frontend server, or runtime asset downloads.
- Frontend and backend versions always match. The build/publish pipeline must verify that the final artifact is genuinely a single EXE containing the required frontend assets.
- A future remote authority may serve the same frontend build and API contract from its own Kestrel server.

Initial release scope:
- Local Windows host service and local authority.
- The local Windows browser connects to the service over loopback HTTP.
- Support WSL and Docker clients.
- No LAN-facing administration interface, remote browser access, or remote-authority deployment in the initial release.

The browser's loopback interface and WSL service-to-service connection are distinct access paths. WSL does not need the browser application exposed to it. For the WSL client path, use the existing independently enrolled machine identities and authenticated protocol:

`WSL client → WSL host service → mutually authenticated and encrypted machine connection → Windows host service → local authority`

The WSL and Windows host services each have independent machine identities and private keys. The WSL host service authenticates to the Windows host service using the existing machine-to-machine mutual-authentication and encrypted-communication protocol. The Windows service verifies trust and authorization before accepting requests. Do not introduce WSL-specific credentials or trust a request merely because it originates on a WSL network interface. Make the necessary local virtual-network connectivity available to WSL without enabling general LAN administration access.

The web application is a human interface, not an authority or execution boundary. The authority remains responsible for authoritative state and authorization. Preserve the backend-agnostic shared API/protocol and authority abstraction so local and future remote-authority deployments use the same contract.

#### Implementation and verification

- Build and test the frontend independently, then integrate its generated assets into the .NET build/publish pipeline.
- Test API security independently of the UI, including direct API attempts to bypass approval, passkey authorization, and machine/grant authorization.
- Test same-origin behavior, CSRF and origin validation, route fallback separation, and API version handling.
- Test the read-only browser session and operation-bound passkey authorization, including replay, expiry, parameter substitution, and attempts to reuse one authorization for another mutation.
- Test credential write-only handling, request-body logging exclusion, and atomic replacement failure behavior.
- Include automated accessibility tests and manual keyboard/screen-reader checks.
- Verify the published Windows artifact is one self-contained EXE with matching frontend/backend versions and no runtime frontend dependencies.

**Current implementation.** The SPA is `src/WithSecrets.Admin.Web` (feature folders status, machines, grants, audit, settings, passkeys; CSS Modules over custom properties; TanStack Query; React Router with basename `/admin`). The TypeScript types are generated from `docs/api/openapi.json` (`npm run api:generate`; `api:check` fails a build when they are stale). The session is read-only. **Browser storage (a documented exception, stated exactly):** the page keeps the two random secrets of the API (the session secret given once by the claim, and the pre-session browser secret) in this tab's `sessionStorage` (per origin and port, never `localStorage`) and sends the session secret as `X-Admin-Token`; since task M8 it also keeps in `sessionStorage` one record of the authorization it is waiting for (`ws.pending-authorization`: the authorization id, the operation name, the dialog title and the one-sentence summary, a time; never the passkey link, a parameter, a bundle or a secret), so a tab that is reloaded or restored between the tap and the result can ask the service what became of it; the record is removed when the result is seen or the request is cancelled and is ignored after 40 minutes. Nothing else is kept in browser storage. **Administrative changes.** One dialog and one step: a form (or, for a change without input, the operation and its parameters) and one button, **Continue to passkey**, which asks the service for the authorization (`POST /authorizations`, changes nothing) and opens the service's one-use passkey page in a new tab (`noopener`; if the browser blocks that, the dialog offers the same link). The dialog then shows the operation and the parameters the service returned (what the passkey signs) once, and refuses to wait if the operation differs. **The service makes the change when the tap is verified** (single use, bound to the operation and parameters, fresh, user verification), not when the page asks for it: the page makes no mutation call, it reads the outcome with `GET /authorizations/{id}` (`result`: applied, started or failed, with the service's sentence), also after a reload; a retry of a mutation endpoint is answered with the stored outcome and applies nothing again (`already-applied`). A new pairing invitation's bundle is given once to the first reader that asks with `?collect=invitation` and is held at most 5 minutes; `DELETE /authorizations/{id}` cancels a request that has not been tapped yet. A lock ends every session and authorization, so the page then reads the authority's status; the outcome of a request whose session ended (idle timeout) cannot be read, and the change, if the tap happened, is in the audit history. Passkey enrolment and removal start on the service's own further passkey pages after the tap (outcome `started`). **Machines and pairing share one view:** Machines has Add a machine (the invitation, its own fresh tap, the bundle shown once and kept nowhere), a card for a machine that has paired (fingerprint and host name to check, its friendly name pre-filled from the host name, Approve), the other machines, and the invitations by status; the separate Pairing entry is gone (`/admin/pairing` leads to Machines). The exe serves the embedded files at `/admin` (`AdminWebAssets`): an extension-less path gets `index.html`, a path with an extension is served only if it exists, GET and HEAD only, `/api` is never a fallback target, and every answer carries a CSP without inline script or style (`default-src 'none'; script-src 'self'; ...; frame-ancestors 'none'`), `nosniff`, `no-store` and no referrer. Accessibility: automated axe-core checks run in the component tests and in the browser scenarios (viewports to 320 px, dark scheme, reduced motion, keyboard path); the manual keyboard and screen-reader pass is a hand test that has not been done.

## 11. Where is it in the code

| Concept | File (`src/WithSecrets.Core` unless noted) |
| --- | --- |
| Entry, gate, dispatch | `src/WithSecrets/Program.cs` |
| Command wiring, targets, code reader | `CommandWiring.cs` |
| Argument parsing, `NeedsTerminal` | `CommandLine.cs` |
| Remote authority over mutual TLS: certificates, temporary-certificate rotation, machine listener, host client, wire messages | `Remote/MachineCertificates.cs`, `MachineTls.cs`, `MachineListener.cs`, `RemoteAuthority.cs`, `RemoteWire.cs`, `RemoteTransport.cs` |
| Run pipeline, exit codes | `RunCommand.cs` |
| Host service: loopback API (`/v1/launch`, `/v1/approve`), request checks, event stream, cancel, `/v1/identity`, invalidation pump, startup reconcile (503 until done) | `HostService.cs` |
| Machine and authority keys (CNG, software, fingerprint, signatures) | `Authority/Keys.cs` |
| Signed envelope and response, enrollment, key transition, `IAuthority` | `Authority/AuthorityProtocol.cs` |
| Shared SQLite file, schema, connection settings and writer gate | `WithSecretsDatabase.cs`, `WithSecretsDatabase.Schema.cs` |
| Authority tables in `with-secrets.db`: machines, history, decisions, keys, invalidations, grants and providers | `Authority/AuthorityStore.cs` |
| Uploaded events, sequence state and gaps, audit retention and history queries | `Authority/AuthorityStore.AuditEvents.cs` |
| Signed audit event, batch, acknowledgement, `IAuditSink`, argument redaction | `Authority/AuditEvents.cs` |
| Host audit outbox (tables in `with-secrets.db`, `AppendIn` in the caller's transaction), uploader and its loop | `Authority/HostAudit.cs` |
| Grant seals: encrypt evidence to R, sign and check each grant row, reseal on authority key rotation, rekey on store key rotation | `Authority/GrantSeals.cs` |
| Review key R held in memory while review is open; review text of a grant | `Authority/ReviewKeys.cs`, `Authority/AdminService.cs` (`GrantReview`) |
| PRF output sealed by the browser and opened by the service (approval and admin operations) | `SealedPrf.cs` |
| Local authority (also the `IAuditSink`), authority key ring | `Authority/LocalAuthority.cs` |
| Host side: verify answers before decrypting, revision, pump, synchronized grants, the vouching state (no lease), startup reconcile, held key sweep | `Authority/HostAuthorization.cs` |
| Grants: signed grant envelope and answer, reconcile (no lease), monotonic clock for the check-in back-off | `Authority/GrantProtocol.cs` |
| Grant extend, renew, replace, revoke in the admin app | `Authority/AdminService.Plans.cs` (`GrantPlan`) |
| Where the store key comes from for a grant run; the held key | `StoreKeyProvider.cs` |
| Grant scope key, assertion evidence stored with each grant row and its verification (`IApprovalVerifier`) | `Authority/GrantEvidence.cs` |
| `host.json` (pinned authority key) | `Authority/HostConfig.cs` |
| Deployment of identity, store and authority; startup lines | `Authority/LocalDeployment.cs`, `Authority/ServiceStartup.cs` |
| Admin operations that stay as functions (approve a machine and pin, recover the key) | `Authority/AdminActions.cs` |
| Authority lock, unattended-unlock policy and platform protection (`IUnlockProtection`, DPAPI) | `Authority/AuthorityLock.cs` |
| Sensitive administrator operations (`AdminAuthorizer`, `VerifiedAdmin`) and the authority settings | `Authority/AdminAuthorization.cs`, `Authority/AuthorityStore.Settings.cs` |
| Admin API (`/api/v1`): sessions, operations as plans, views, HTTP side; `with-secrets admin` (link and status) | `Authority/AdminSessions.cs`, `Authority/AdminService.cs`, `Authority/AdminService.Plans.cs`, `Authority/AdminViews.cs`, `Authority/AdminService.Authorizations.cs`, `Authority/Api/AdminApi*.cs`, `Authority/Api/ApiSchema.cs`, `Authority/AdminAppCommand.cs`, `HostService.cs` |
| Administration web app (React, TypeScript, Vite; generated API client; per-operation authorization dialog) | `src/WithSecrets.Admin.Web/` (`src/api`, `src/features/*`, `src/components`) |
| Embedded web app assets, SPA fallback for application routes, strict CSP | `Authority/AdminWebAssets.cs` |
| Build integration (Node check, `npm ci`, `npm run build`, embed `dist` as `admin-web/*`) | `WithSecrets.Core.csproj` (targets `AdminWeb*`) |
| `with-secrets --self-check` (versions, embedded files, from a throwaway service) | `SelfCheck.cs` |
| Single-file publish and its verification | `scripts/publish.ps1`, `scripts/verify-publish.ps1` |
| Final launch commit against invalidation | `LaunchGate.cs` |
| CLI client of a run (reads `.env`, sends the request, prints events, exit code 6 without a service) | `LaunchClient.cs` |
| Launch events (NDJSON: approval, output, result) | `LaunchEvents.cs` |
| Launch request, result, digest, binding | `Contracts/LaunchContracts.cs` |
| Project `.env`: parser, composition, `secret://` grammar, `--needs` | `EnvDeclarations.cs` |
| Command grammar, length limits | `Policy.cs` |
| Approval text, request fingerprint, script view | `ApprovalSummary.cs`, `Reuse.cs` |
| Child process (prepare, start, discard), PATH lookup, env denylist | `ChildProcess.cs` |
| Output redaction | `Redaction.cs` |
| Loopback server, tokens, headers, `HandleGuard`, `NetLog` | `OneShotServer.cs` |
| One link per command, `next`, time budget | `PageFlow.cs` |
| Approval page and session, proof handling, CSP | `WebApprover.cs` |
| Passkey proof, RP ID, sign counts | `PasskeyMethod.cs`, `WebAuthn.cs`, `PasskeyStore.cs`, `Proof.cs` |
| PRF page code, label, sealed payload | `PrfClient.cs`, `SecretCrypto.cs` |
| First setup and registration pages | `FirstRunPage.cs`, `PasskeyRegistration.cs` |
| Settings and limits | `ToolSettings.cs`, `ApprovalSettings.cs` |
| Enroll, unenroll, names | `Enrollment.cs`, `EnrollmentTarget.cs` |
| Secret entry and removal in the admin app | `Authority/SecretFlows.cs`, `SecretEntry.cs` |
| Secret rows, hashes, decrypt only requested | `SecretStore.cs` |
| Slots, vault, recovery slot | `KeyVault.cs`, `RecoveryCode.cs` |
| Signed manifest | `Manifest.cs` |
| Store facade over `with-secrets.db`: manifest, sign counts, secret rows, gate | `StateDatabase.cs` |
| Rotate keys, recover | `KeyRotation.cs`, `StoreRecovery.cs` |
| Administrative audit events (type `admin`, also the provider retrieval and invalidation events), outbox and signing (one transaction for several events: `AppendAll`) | `Authority/AdminAudit.cs`, `Authority/HostAudit.cs`, `Authority/AuditEvents.cs` |
| Terminal prompt (lines are written at once; nothing is held or dropped) | `TerminalPrompt.cs` |
| Logging: Serilog setup, file rules, `--debug` terminal sink | `AppLog.cs` |
| Saved approvals (inactive with this store) | `Reuse.cs` |
| Provider core (10.3): adapter contract, batch validation, registry; instances, mounts, namespace and cache rows (in `with-secrets.db`); mount resolution, reconciliation, invalidation; retrieval and retry policy; sealed cache; mounted-secret delivery; proactive refresh; the authority's composition of them | `Providers/ProviderContract.cs`, `ProviderBatch.cs`, `ProviderRegistry.cs`, `ProviderStore.cs`, `MountResolver.cs`, `NamespaceReconciler.cs`, `ProviderInvalidation.cs`, `ProviderRetriever.cs`, `ProviderPolicy.cs`, `ProviderCache.cs`, `ProviderSecretSource.cs`, `ProviderRefresher.cs`, `ProviderAuthority.cs` |
| Remote launch: signed secret delivery over the encrypted session, authority-side launch handler, pairing with `pair` | `Remote/RemoteLaunch.cs`, `Authority/AuthorityLaunchHandler.cs`, `Authority/AuthorityPairing.cs` |
| Operational procedures exercised (backup and restore on a second machine, key chain, recovery, lock cycles, host name change, Docker) | `tests/WithSecrets.Tests/OperationsTests.cs`; guide `docs/operations.md` |
| Acceptance sequence (build, suite, frontend, publish, browser tests) | `scripts/verify-all.ps1` |
| Tests | `tests/WithSecrets.Tests`, browser tests `tests/WithSecrets.E2E` |

The reference.md path spelling is correct (`%USERPROFILE%\.with-secrets\with-secrets.db`).

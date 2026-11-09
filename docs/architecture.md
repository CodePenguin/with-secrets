# with-secrets: architecture

The code and README describe the current single-process prototype. Sections 10.1 and 10.2 describe later work; Section 10.2 is the accepted target design, not implemented behavior. For current behavior, the source of truth is the code (`src/WithSecrets.Core`, `src/WithSecrets`), then `README.md`. For the accepted service/authority/relay design, use Section 10.2 and the decisions recorded there. This page links to the README for current implementation limits instead of repeating them.

## 1. What it is (current prototype)

- A CLI runs a program with secrets in its environment. An agent starts the command; a person approves it.
- The agent supplies secret names and a reason. The CLI does not print secret values, private keys, or the recovery code to agent-visible output. Approved values are injected into the child process environment.
- The person approves on a one-use web page with a passkey (WebAuthn). The same tap releases the secret-store key (WebAuthn PRF).
- The current prototype keeps its signed manifest, wrapped key material, Dotenvx ciphertext rows, settings, and audit chain in one SQLite file, `state.db`. The store private key is persisted only wrapped in the vault; the master key is persisted only in wrapped passkey/recovery slots. No plaintext store or master key is persisted.
- Terminal output is public (the agent reads it). Values and the recovery code appear only in the browser, apart from approved secret values in the child environment. Same-user process-memory access remains a documented limit (README).

## 2. Components (current prototype)

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
        Cmds["Commands: RunCommand, SecretEntry, Enrollment, SettingsPage, KeyRotation, StoreRecovery, Revocation"]
        Pages["Pages: OneShotServer, PageFlow, WebApprover, PasskeyMethod"]
        Pol["Policy + ChildRunner"]
        Vault["SecretStore + KeyVault + Manifest"]
        Audit["AuditLog"]
    end
    DB[("state.db")]
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

- `CommandWiring.cs` lives in Core, not in the exe. `Program.cs` parses, opens `state.db`, runs the gate, then dispatches.
- Every page of one command shares one `OneShotServer` (`PageFlow`), so one port and one link per command.

## 3. Communications (current prototype)

The table describes the current CLI/browser/child-process flow, not the future local-service and authority protocol in Section 10.2.

| From -> to | Transport | What is sent | What protects it |
| --- | --- | --- | --- |
| Agent -> CLI | argv, process start | secret names, reason, program, args | Policy checks before any page; names are not secret |
| CLI -> host service | HTTP on 127.0.0.1 and [::1] (port 8765, `--service-port N` / `--port N` of `service`, `WITH_SECRETS_PORT`); `POST /v1/launch` with the canonical `LaunchRequest` JSON and its digest in `X-Request-Digest`, `POST /v1/launch/{id}/cancel`, `GET /v1/status` | the request (names, pairs, reason, program, arguments, folder, the `.env` plan, the inherited environment), never a secret value | Loopback bind only; `Host` must be a loopback name (DNS rebinding), no `Origin` header, JSON only, body max 1 MB with a 15 s read timeout, strict parse, digest, version and expiry checked, one use per request id. No caller identity: the API alone authorizes nothing, because secrets open only after a passkey approved the page |
| Host service -> CLI | the response body of `POST /v1/launch`: NDJSON, one event per line (`approval` with the page link, `output` with redacted text and the stream, `result` with the outcome and the exit code) | the public link, redacted output, the exit status | **Public by design.** No event has a member that could hold a value; output is redacted in the service before it is sent |
| CLI -> Agent / terminal | stdout, stderr | one-use link, names, admin fingerprint line, redacted child output, exit code | **Public by design.** Never values, keys, recovery code |
| Person -> CLI | terminal stdin | the 6-digit confirmation code (first `--config`, `--enroll`, new store of `--recover`) | Read only after the last tap, 3 tries, prompt is the last line (`TerminalPrompt`) |
| Host service -> browser | HTTP on 127.0.0.1 and [::1], same port (setting `port`, `--port N`, else free). With `baseUrl` (http or https; passkeys need https or localhost): that name pointed at the port, or `ssh -L PORT:localhost:PORT` | HTML page, inline script and style allowed by CSP hash, data block (request text, bind, challenges) | Token: 16 random bytes in the path, fixed-time compare, 404 for anything else. Headers: strict CSP (`default-src 'none'`, `connect-src 'self'`), `no-store`, `nosniff`, `X-Frame-Options: DENY`, `no-referrer`. Both loopback addresses held, `ExclusiveAddressUse` on Windows |
| Browser -> CLI | POST `proof`, `deny`, `seal`, `save`, `create`, `sign`, `code` (body max 1 MB, 15 s body timeout) | passkey assertion or attestation, reuse minutes, PRF output, typed `--set` values, recovery code | See rows below. First outcome of a step is final, later requests get 404 |
| Browser <-> passkey | WebAuthn in the browser | challenge, assertion, PRF eval of the slot salt | Each prompt starts in its own tap (iOS rule). RP ID is the page host, passkey ignores ports |
| PRF output, browser -> CLI | inside the proof POST | 32 bytes sealed: fresh ECDH P-256 key, HKDF-SHA-256 (salt = bind, info `with-secrets/v1 prf`), AES-256-GCM (bind as AAD) to the page's own server key | Sealed to a key that lives for that page only. A passive observer (tunnel that ends TLS) sees ciphertext. An active man in the middle who replaces the page key is not stopped (README) |
| `--set` values, browser -> CLI | `seal` POSTs while typing (max 500 per page) | each value sealed the same way (own HKDF info `with-secrets/v1 secrets`) | Page server key per page. The Save tap signs `SHA-256(bind \|\| SHA-256(ct) \|\| SHA-256(manifest))` |
| Recovery code, browser -> CLI | `--recover` code page | code sealed to the page key | Never in terminal, log, audit or `state.db`. A typed code is not origin-bound: compare the printed admin fingerprint first |
| Lost reply | page resends the same body (3 tries: 8 s, 8 s, 20 s; `deny` one try of 20 s) | same bytes | Steps that lead on (`proof`, `create`, `sign`, `code`) keep one reply per verified body (SHA-256 of body, fixed-time compare), in memory until the command ends. No second page, no second code. Other steps (`save`, `seal`, `deny`): a resend after the outcome gets 404 and the page says the program already finished |
| CLI <-> `state.db` | SQLite, WAL, one transaction per write | manifest, ciphertext rows, sign counts, audit rows | Manifest signature checked before use (exit 4). Writes check the version they replace |
| Host service -> spawned program | environment (the sender's inherited block, minus the denylist, plus ordinary `.env` values and the approved secrets), argv, closed stdin | only the approved secrets as env vars | Denylist, no stdin, redacted output (section 7) |
| Network diagnostics | Debug log events: terminal only with `--debug`, and the log file | method, route word, whole seconds, sizes, verdict words | No path, token, body, key or value (`NetLog` words, constant `AppLog` templates) |

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
```

| Secret | Lives | Zeroed |
| --- | --- | --- |
| PRF output | In the passkey. In the page as a plain `Uint8Array` until sealed: the page scripts never overwrite it (garbage collection only). Server: opened from the sealed payload into `Unlock` (bytes) | `Unlock.Dispose` after the run read its values (every exit path). Registration copies zeroed after the slot is wrapped |
| Slot KEK | Process memory during wrap or unwrap | `KeyVault` finally blocks |
| Master key MK | `state.db` only as slot wraps and the recovery slot. Plain in memory during a run, `--enroll`, `--rotate-key`, `--recover`, first `--config` | After use (`SecretValues.Clear`) |
| Store key K | `state.db` only as the vault. Plain as bytes plus a hex string during decrypt | Bytes zeroed. The hex string cannot be wiped (.NET) |
| Decrypted values | Bytes in `SecretValues`, strings in the child env and the redactor | Bytes when the child ends. Strings cannot be wiped |
| Recovery code | Offline, written by the person. Server makes it at first `--config`, `--recover`, `--rotate-key`, formats it for the page | Code bytes zeroed when the page ends (first `--config`, `--recover`) or after the slot is built (`--rotate-key`); the formatted text is a string and cannot be wiped. `--recover` holds the old K in `RecoveryCarry` until the end |
| Slot salt | Manifest. One shared salt per store (the first key's), because the page can pass one `eval` salt. The PRF output still differs per passkey | Not secret |

Facts that follow from this: `state.db` alone cannot decrypt anything. A same-user agent that reads process memory during a run can get K (README "The secret store"). `--unenroll` does not rotate MK or K. `--rotate-key` does.

## 5. Signed state

The manifest is one row in `state.db`, as canonical JSON, signed by an admin passkey.

| Item | Detail |
| --- | --- |
| Contents | version `v`, `keys` (id, name, public key, alg, rp, created, admin flag, slot salt and wrap), `store` (store public key), `vault`, optional `recovery` slot, `secrets` (name -> SHA-256 of ciphertext), `settings` |
| Not in it | sign counts (table `sign_counts`), saved approvals, audit rows, the secret ciphertext itself (rows table, covered by the hashes) |
| Signature | admin assertion over `SHA-256(bind \|\| SHA-256(manifest text))`. Stored with its authenticator data and client data |
| Who may sign | a key that is an admin in the **stored** manifest and stays one. A key that only becomes admin in the new manifest cannot sign it. An admin cannot approve its own removal. The last admin cannot be removed |
| Verify before use | `Program.cs` runs `state.Gate` before every command, including `--list` and `--audit`. Failure prints `with-secrets: state failed verification: delete state.db to start over (only if you did not edit it)` (or the damaged or other-schema message) and exits 4. `--help` and bad arguments exit before the gate. Verified manifests are cached per process |
| Rows | every `SecretStore` read (`--list`, a run, `--set`, `--rotate-key`, `--recover`) checks every row against its signed hash (the gate checks integrity and the manifest only): a swapped row, a row with no hash or a hash with no row is exit 4 |
| Writes | one transaction: manifest, rows, audit row. Refused when the stored version is not the one the page started from |
| Sign counts | stored beside the manifest, unsigned. An assertion must raise the count. An agent can inflate them (denial of service only) |
| Fingerprints | first 8 bytes of SHA-256 of each admin public key, 4x4 hex. Shown on every page (part of the signed text), in `--enrolled`, `--audit`, and in the terminal before `--recover` and `--rotate-key`. Detects a replaced state |
| Grants (saved approvals) | **Inactive with the PRF store.** `SecretStore.NeedsUnlock` is true, so `RunCommand` uses `ReuseOffer.Off`: no list on the page, none saved or used. Code, table and tests remain (`Reuse.cs`) |
| Audit hash chain | each row holds `prev_hash` and `hash` over its entry, first row chains to 64 zeros. `--audit --verify` names the first broken link (exit 4). Finds edits and deleted middle rows, not removed tail rows. Not signed: a same-user writer can recompute it |
| Schema | version 9, checked at open (`PRAGMA integrity_check`). Other versions are never migrated |

Gaps (agent deletes `state.db` and builds its own state, restore of an older copy, rollback) are in README "Admin keys" and "Known limits".

## 6. Flows

Legend: **TAP** is a passkey prompt (one per user tap). Page moves on by itself when a reply carries `next`. Participants: P person, T terminal, C with-secrets process, B browser and passkey.

### 6.1 First-run setup (`--config`, nothing enrolled)

```mermaid
sequenceDiagram
    actor P as Person
    participant T as Terminal
    participant C as with-secrets
    participant B as Browser + passkey
    P->>T: with-secrets --config (own terminal)
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

### 6.2 Store secrets (`--set NAME`)

```mermaid
sequenceDiagram
    actor P as Person
    participant T as Terminal
    participant C as with-secrets
    participant B as Browser + passkey
    C->>C: gate, rows match signed hashes
    C->>T: link (admin passkey must work at this host)
    P->>B: open link, type values
    loop while typing
        B->>C: POST seal (values sealed to page key)
        C->>C: decrypt, check, encrypt to store public key
        C->>B: next manifest (names and hashes only)
    end
    Note over B: TAP 1 admin signs SHA-256(bind, SHA-256(ct), SHA-256(manifest))
    B->>C: POST save (assertion)
    C->>C: verify, then one transaction: rows, manifest, audit
    C->>T: Stored NAMES
```

No PRF and no master key: `--set` only needs the store public key. `--remove` is the plain approval page signing the next manifest without those hashes.

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

### 6.4 Enroll a passkey (`--enroll`)

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

The code is generated at registration but shown only on the last page. Nothing is stored before it is typed. `--unenroll NAME` is a single approval page where another admin signs the manifest without that key.

### 6.5 Rotate keys (`--rotate-key`)

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

Failure or timeout between the taps changes nothing.

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
    C->>C: write new state.db, rename old to state.db.recovered-UTC, audit recovered
```

The old file is never deleted. Old admin keys are gone from the new state. Any failure leaves the old `state.db` as it was.

## 7. Policy and child process

| Area | Rule | File |
| --- | --- | --- |
| Secret names | `NAME` or `folder/NAME` (up to 3 folders, 200 characters in all; the last segment UPPER_SNAKE_CASE, no `DOTENV_` prefix; folders `[A-Za-z0-9_.-]{1,64}`, not `.` or `..`). One validator for all commands, the whole path is the store name and is data only. Every name must be listed (no `--all`). `--set` and `--remove`: 1 to 20 names | `Contracts.cs` (`SecretNames`), `SecretEntry.cs`. Values: 6 to 4096 characters |
| Program lookup | `env`, `printenv`, `set` are refused (they print the environment). PATH entries that are absolute only. Working directory not searched unless the program has a slash or backslash. Windows App Execution Aliases refused | `ChildProcess.cs` (`ProgramResolver`), `RunCommand.cs` |
| Paths | program and script are expanded to full paths. What is checked, shown and run is the expanded form. They must read the same as the typed form | `RunCommand.cs`, `Paths.cs` (`PathExpander`), `Policy.cs` |
| Command grammar | Interpreters in one strict form only: `PROG script [args]` or `PROG -c/-e CODE` (sh family, python, node, perl, ruby), PowerShell: `-NoProfile` required, then `-NonInteractive`, `-NoLogo`, `-ExecutionPolicy VALUE` (once each), then exactly `-File` or `-Command`; `cmd /d /c` (or `/k`, `/r`) with a tail of letters, digits and `. _ : \ /` `-`, first word a `.cmd`/`.bat` file or echo, dir, type, ver. Encoded commands, a bare interpreter and code starting with a dash are refused. Other programs: no analysis, `Run:` line only (a text-file program is still shown). Matches README "Known limits" and `--help` | `Policy.cs` |
| Limits | command max 16,000 characters. Inline code shown: first 4,000 characters. Script max 1 MB (page shows first 200 lines or 16 KB). Script must exist, be text, and be readable. Batch files ASCII | `Policy.cs`, `RunCommand.cs`, `ApprovalSummary.cs` |
| Page text | every line of code prefixed `  \| `. Control, bidi and zero-width characters replaced by a mark. Part of the signed text | `ApprovalSummary.cs` |
| Fingerprint | covers names, every variable-to-secret pair, the `.env` paths and ordinary variable names (when a `.env` is used or a variable differs from its secret), full program path, folder, and path and hash of the script and of the program file (when 1 MB or less). Recomputed after approval. A changed file denies | `Reuse.cs`, `RunCommand.cs` |
| File lock | shown files opened `FileShare.Read` until the child ends, hashed again. Windows only. Elsewhere only the last check before launch | `RunCommand.cs` (`HeldFiles`) |
| Environment | removed before launch: `DOTENV_PRIVATE_KEY*`, `NODE_OPTIONS`, `BASH_ENV`, `ENV`, `PYTHONPATH`, `PYTHONSTARTUP`, `PYTHONHOME`, `PERL5OPT`, `RUBYOPT`, `LD_PRELOAD`, `DOTNET_STARTUP_HOOKS`, `JAVA_TOOL_OPTIONS`, five `GIT_*` names (`GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM`, `GIT_EXEC_PATH`, `GIT_SSH_COMMAND`, `GIT_ASKPASS`), `SHELLOPTS`, `BASHOPTS`, `PS4`, `PS0`, `PROMPT_COMMAND`, `BASH_FUNC_*` and more (case-insensitive on Windows). Full list in `ChildRunner.CodeLoadingVariables` and README. Known gaps: README | `ChildProcess.cs` |
| Stdin | closed right after start: the child reads end of file | `ChildProcess.cs` |
| Launch | `.cmd` and `.bat` start as `cmd.exe /d /c "path" args` (no AutoRun). Arguments with quotes or `& \| < > ^ % !` are refused for cmd | `ChildProcess.cs`, `Policy.cs` |
| Output | read as UTF-8, redacted by `StreamRedactor` (chunk splits and common forms). Reversed, split, compressed or encrypted copies are not caught | `Redaction.cs` |
| Terminal-only commands | `--revoke --enroll --enrolled --unenroll --config` (not `--config --show`) `--recover --rotate-key` refuse when input, output or error is redirected (exit 3). `--set`, `--remove`, `--list`, `--audit` do not check | `CommandLine.cs`, `Program.cs` |

## 8. Trust boundaries (current prototype)

This table describes the current single-process implementation. The future local API trust model is described separately in Section 10.2. What the agent can and cannot do, and the known limits: README "Known limits", "Admin keys" and "The secret store". Summary:

| Actor | Capability | What stops it |
| --- | --- | --- |
| Agent (same OS user) | start a run, read terminal output, hold links | Cannot tap the passkey. Link is one-use and shows the whole request. Enrollment codes need a human typing in a real terminal |
| Agent | read `state.db` | No key on disk: K is only wrapped, MK only under PRF or the recovery code. Rows are ciphertext |
| Agent | edit `state.db` (keys, settings, rows, slot, vault) | Manifest signature and row hashes fail: exit 4 on every command |
| Agent | delete `state.db` and write its own signed state | **Not prevented.** Visible: admin fingerprints change on every page, `--enrolled`, `--audit` |
| Agent | restore an older `state.db`, rewrite audit and chain, inflate sign counts | Accepted limits (README) |
| Agent | read process memory during a run | **Not prevented.** K, MK, PRF output and values are in memory for that moment (README) |
| Agent | change the script or program after the page showed it | Fingerprint recheck, file hold (Windows) |
| Agent | pass options or env that load unshown code | Strict grammar, environment denylist, closed stdin. Gaps listed in README |
| Another local process | serve a look-alike page on localhost | Server holds both loopback addresses exclusively. Passkey RP ID ignores ports, so check the printed link before tapping (README) |
| Network observer (tunnel) | read page traffic | PRF output and `--set` values are sealed to the page key. Active man in the middle is out of scope |
| Child program | print or send secrets | Output redaction only. A program that sends its environment out is out of scope |
| Lost admin device | still opens the store with an old `state.db` copy | `--rotate-key` (keeps one key). `--unenroll` alone does not rotate MK or K |

## 9. Exit codes and error paths

| Code | Meaning | Typical causes |
| --- | --- | --- |
| 0 | success | run: the child exited 0. approve: the grant was made. Commands: change made, `--help`, `--list`, `--audit` |
| 2 | usage | bad arguments, two commands, invalid or unknown secret name, policy refusal, script missing, too large or not text, changed while the request was built, command too long, App Execution Alias |
| 3 | denied | Deny on the page, wrong proof, time limit, internal error in a session (`HandleGuard`, text says only `internal error`), files changed while the page was open, file hold failed, nothing enrolled, no terminal for a human command, refused change |
| 4 | store error | `state.db` damaged, locked over 5 s, other schema, failed signature or row hash, unusable settings, cannot decrypt, `--audit --verify` finds a broken link |
| 5 | audit error | the audit row could not be written, or (behind the host service) the signed audit event could not be committed to `audit-outbox.db`, so nothing ran |
| 6 | host service not running | a run could not reach the host service (`with-secrets: the host service is not running. Start it with: with-secrets service`); nothing was asked and nothing ran |
| 7 | service not authenticated | the CLI could not verify that what answers is this machine's host service (no answer to the identity check in 5 s, a wrong or replayed answer, another fingerprint than the one pinned in `host.json`, an unreadable `host.json`), or no identity is pinned yet (the fingerprint is printed; `with-secrets admin approve FP --name NAME` pins it); nothing was sent |
| 8 | authority locked | a run or approve reached the host service while the authority is locked (the service starts locked); nothing was asked and nothing ran. The line names the admin page where an administrator unlocks it with a passkey tap |
| 127 | not found | program not on PATH, or the process cannot be started |
| other | the child's own exit code | passed through on a run |

Every web session ends on the first outcome. Deny, error and silence all end in a denial, never an approval. Gate failures happen before any link is printed.

## 10. Planned, not built

| Item | State |
| --- | --- |
| Task 20: remote mode for sandboxes (relay, pairing, end-to-end encrypted values) | Accepted target design in 10.2; implementation remains future work |
| Task 19: project `.env` declarations and invocation environment overrides | **Phase A built**; accepted `--env` layering and Dotenvx encrypted-value integration remain implementation work (see 10.1) |
| Local service, machine identity, end-to-end encrypted relay (10.2) | Accepted target design; implementation not started. Task 16 (privilege separation) remains separate |
| Task 16: privilege separation (service or daemon under another OS account) | Future, priority not decided |
| Serilog logging (normal run quiet, `--debug` verbose, warnings and errors to a rolling file under `~/.with-secrets/logs`) | **Built** (`AppLog.cs`): Debug events to the terminal and file only with `--debug` or `WITH_SECRETS_DEBUG=1`; warnings and above always to the file (daily, 1 MB roll, 7 files); call sites use constant templates with route words, sizes and type names only |
| Hand tests (real browsers, phones, tunnel) | Open, see README "Checks" |

### 10.1 Project environment declarations and Dotenvx

**Status:** Phase A project declarations are implemented in `EnvDeclarations.cs`. Host service and remote authority are design-only. Integration with the existing Dotenvx loading/evaluation behavior, including encrypted project `.env` values and profile selection, remains follow-up work.

**Ownership boundary**

- Use the existing `Dotenvx.Core` NuGet package unchanged. The maintainer owns the C# port, not Dotenvx core; do not propose modifying either to accommodate with-secrets.
- Dotenvx remains responsible for its existing parsing/loading, interpolation/evaluation, encrypted `.env` value handling, and standard environment construction/injection behavior.
- with-secrets owns project-file selection/composition policy, classification of effective declarations, `secret://` resolution, provider mounts, approval, audit/request binding, and launching the child.
- The current Phase A parser is a deliberately limited implementation and rejects an effective encrypted declaration. That is current state, not the desired long-term parser boundary. Integrate with the existing package rather than reimplementing Dotenvx semantics.

**File selection**

- Default selection is the project's `.env` in the current working directory. Do not search parent directories.
- If the caller selects a Dotenvx profile (for example `local` or `development`), follow Dotenvx's existing profile/file-selection convention. Do not invent a second convention or infer profiles from ambient variables such as `NODE_ENV`.
- Explicit file selection through the existing repeatable `-f` / `--env-file` interface selects exactly the supplied files and replaces default selection.
- File ordering and profile expansion must match the actual Dotenvx implementation. The with-secrets composition rule is **first file wins**. Verify exact Dotenvx ordering and repeated-key semantics with tests before documenting specific profile filename patterns or precedence examples.
- A missing default `.env` means there are no project declarations. An explicitly selected missing file is an error; never silently skip it.

**Declarative model**

Selected project environment files may contain ordinary configuration, Dotenvx-encrypted project values, and external secret references:

```dotenv
# Ordinary configuration
API_URL=http://localhost:5000
LOG_LEVEL=Debug

# Dotenvx-encrypted project value
API_KEY=<encrypted Dotenvx value>

# External secret resolved by with-secrets
GITHUB_TOKEN=secret://team/development/github/token
DATABASE_PASSWORD=secret://personal/database/password
```

- The left side is the child environment-variable name; the right side is a logical secret path. They may differ, e.g. `STRIPE_KEY=secret://team/payments/STRIPE_PRODUCTION_KEY`.
- Dotenvx comments and syntax remain Dotenvx's responsibility. Comments are not declarations.
- Ordinary values are not secret-store references. Dotenvx-encrypted values remain encrypted in source control and are decrypted through the existing Dotenvx mechanism. External `secret://` values are resolved by with-secrets.
- Compose selected files first, using the ordered first-file-wins rule, then classify only the final effective value of each variable. An overridden reference must never be requested, approved, or decrypted.
- Validate every effective reference before approval. A missing mount, permission, provider, secret, or required credential is a hard error. No fallback, cross-provider search, silent substitution, or alternate-name prompt.
- An explicit `secret://` declaration must not silently be satisfied or replaced by an inherited environment variable. Ordinary inherited-environment behavior and encrypted-value precedence must remain compatible with Dotenvx and be covered by tests.

**Discovery and CLI behavior**

- Keep `--secrets NAME[,NAME...]` for explicit requests and compatibility; it composes with effective declarations from selected project files.
- `--needs` is read-only discovery. It reports selected files, ordinary variable names, effective variable-to-secret mappings, and whether references are resolvable. It does not approve, decrypt, or display secret values.
- A `--needs` result is informational, not an authorization or trusted cached plan. The run command independently recomputes and validates its plan.
- Do not scan source code for environment-variable usage; dynamic lookups make this unreliable and language-specific. The request set is selected declarations plus explicit `--secrets`.
- Additional `--env NAME` layering is deferred.

**Approval and trust**

- The human approval page is the control point because an agent can modify project environment files.
- Show the human approver every selected file path, every effective secret mapping, and every effective ordinary variable/value. Never show plaintext secret values. Agent/terminal-facing output shows names and paths only.
- Bind selected file paths, effective declarations, ordinary values, secret mappings, command/script, working directory, request identity, and expiry to the approval fingerprint/signature. Read files once per request; approval, audit, and launch use the same immutable snapshot. A file changed while approval is pending must not change what launches.
- Preserve protected-variable rules: secret references cannot target code-loading variables, process-selection variables such as `PATH`, `PATHEXT`, or `COMSPEC`, proxy variables, or git identity variables. Continue stripping the existing child code-loading variables. A denylist is not a complete security boundary; showing ordinary values is still required.
- Do not expose the Dotenvx decryption key or plaintext secrets to the agent.

**Implementation status**

| Capability | State |
| --- | --- |
| Default `.env` in working directory; no parent traversal | Implemented |
| Explicit repeatable `-f` / `--env-file` selection | Implemented |
| Phase A comments, optional `export`, basic quoted/unquoted values | Implemented in current parser |
| First-file-wins composition and effective-reference-only resolution | Implemented and tested |
| `secret://` references and renamed environment mapping | Implemented and tested |
| `--secrets` additions and read-only `--needs` | Implemented and tested |
| Approval display of paths, secret mappings, and ordinary values | Implemented in Phase A |
| Dotenvx encrypted project values through existing `Dotenvx.Core` | Follow-up integration; current Phase A parser rejects effective encrypted values |
| Dotenvx profile selection | Open pending verification against current Dotenvx behavior |
| Additional `--env NAME` layering | Deferred |

### 10.2 Local service, machine identity and end-to-end encrypted relay (planned)

Status: design only. This section records the accepted design. It supersedes the earlier proposal and review notes; it does not change the Phase A \`.env\` model. Task 16 (privilege separation) remains a separate future decision.

#### Goals and operating model

- The CLI is backend-agnostic. It communicates only with its local host service through one shared API/protocol, whether the service uses a local authority/store or connects to a remote authority through the relay.
- The host service is the trusted execution boundary: it validates the request, obtains authorization, resolves and decrypts approved secrets, prepares the child environment, and owns the final launch decision. The CLI is a client; it does not independently retrieve secret values or make the final launch decision.
- Each independently installed host service has its own machine identity. Windows and WSL installations are separate identities. Docker launched through the host-side CLI uses the host service and host identity; the host service launches the Docker client with approved values in its environment and passes variable names, not secret values, in Docker command arguments. Values are not written to Docker volumes or secret files. The container receives them as environment variables; it does not run an independently enrolled service or hold a machine key.
- A host service operates in one of two modes:
  - **Local authority:** the host service also performs the authority role, owns/accesses the local encrypted store, and handles approval and resolution.
  - **Remote authority:** the host service authenticates to a remote authority and communicates with it through the relay. The remote authority owns the authoritative store, grants, machine records, and approval decisions; the local host service retains only its permitted in-memory cache and working authorization state.
- The relay is a minimal message router between the host service and remote authority. It does not understand application messages, store session state or payloads, or make authorization decisions.
- Secret delivery to a child remains ordinary environment variables. The agent does not receive secret values, private keys, or recovery codes.

#### Local clients and transport

All local clients use the same HTTP API and application protocol. The CLI sends launch requests to the host service; the service prepares and launches the requested child process and returns its exit status and redacted output. Do not introduce separate named-pipe, Unix-socket, or Docker-specific authentication protocols.

- The local service binds to loopback interfaces only. Localhost alone is not treated as client authentication.
- Do not embed a client signing key or shared authentication secret in the executable. An executable cannot keep an embedded private key secret.
- Secret disclosure remains controlled by request validation, a human approval page that displays the trustworthy request context, and grant rules. Local API access does not itself grant access to secrets.
- This is a developer-machine trust model, not isolation from malicious processes already running with the developer's privileges. Such processes may be able to interact with the local service or inspect same-user process memory.
- Docker is launched through a host-side CLI request, but the host service owns the launch and supplies approved values to the Docker client through its process environment. The container does not need direct service access, a separate machine identity, an identity-key volume, or secret files.

#### Machine identity and enrollment

- Each host service generates and securely retains its own ECDSA P-256 machine identity private key. The key signs; it is not used to encrypt or wrap secrets.
- The machine fingerprint is SHA-256 of the canonical public key and is the cryptographic identity. A friendly name is authority-managed display metadata, not identity.
- The private key is kept outside ordinary application data. On a developer machine it is protected by the host OS. For Docker-launched workloads, the host service retains the key; no Docker volume contains it.
- Losing or regenerating the key creates a new fingerprint and requires fresh enrollment. There is no silent identity transfer or recovery.
- Enrollment uses the existing CLI \`admin\` verb. A newly discovered fingerprint is **Pending** and cannot request secrets or create grants until an administrator approves it and assigns a friendly name through the authority's admin web interface.
- First contact presents a newly generated machine public key, its fingerprint, and host name, with proof of possession of the private key. The authority may record that identity as Pending, but it grants no secret access. An administrator explicitly approves the pending identity and pins the authority's public signing key through the authenticated enrollment flow; the host must not accept an untrusted authority key merely because it was presented by the network.
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

#### Cache, grants, startup, and reconnection

- Secret values and the host service's working authorization/grant state are memory-only. The host service does not persist secret cache values or authorization state locally. A host-service restart destroys them.
- Durable grants live at the authority. The approver chooses the grant expiration at approval time, including an indefinite grant where offered. Do not impose a new fixed lifetime.
- The CLI exposes `with-secrets approve COMMAND` and `with-secrets run COMMAND`. `approve` performs the normal request validation and human approval flow to create or update a grant, but does not launch the command. `run` performs the same normal validation and uses an applicable, unexpired grant without prompting; it does not bypass request scope or constraints. Preapproval is limited to the approved grant scope, not blanket permission.
- An active grant may be extended, an expired grant renewed, or a grant revoked through an authority-controlled operation. The authority is the source of truth for all grant changes. Connected hosts apply updates immediately. An offline host cannot use an extension or renewal it has not received; its previously synchronized grant remains subject to its existing expiration and the separate offline-authorization lease. A grant change never extends the offline lease.
- At startup, the host service must authenticate to its authority and reconcile machine status, host-name binding, and security revision before accepting secret requests. If the authority is unavailable at startup, the service cannot accept new requests.
- After successful startup reconciliation, if the security revision is unchanged, the authority may restore still-valid grants into host-service memory. Secret values are fetched on demand and cached in memory. If the revision changed, old grants are not restored.
- If the authority becomes temporarily unavailable while the service is already running, existing in-memory cache and grants may continue to be used only within a finite offline-authorization lease. The authority is the sole source of policy and sets the lease duration; hosts cannot choose, extend, or override it. A connected host applies an authority policy change immediately. An offline host remains bound by its already-issued lease and must reconnect and reconcile before obtaining a new lease or continuing after expiry. In local-authority mode, the local authority sets the policy. The authority issues each offline lease with an explicit duration/expiration. The host measures elapsed lease time with a monotonic clock, never the wall clock, so changing the system date or time cannot extend offline access. A service restart destroys the in-memory lease and requires fresh authority reconciliation before secret requests are accepted. An indefinite durable grant does not create an indefinite offline lease. When the lease expires, the host must fail closed for secret use until it can reconnect and reconcile with the authority. New retrievals or approvals that require authority participation cannot proceed while disconnected.
- Losing connectivity alone does not immediately invalidate the cache. However, the authority records revocations durably and distributes them to every host; a host must apply a received revocation immediately, clear affected grants/cache, and refuse the revoked fingerprint. An offline host that has not received the event is still bounded by its finite offline-authorization lease and must reconcile before resuming use.
- The authority invalidates grants and in-flight requests when a security transition occurs, sends an authenticated, end-to-end protected invalidation event, and retries unacknowledged events while the connection is active.
- The host cancels its own affected pending work and clears the affected cache and authorization state before acknowledging. It never inspects, signals, suspends, terminates, or otherwise interacts with already-launched child processes.
- Invalidation events are notifications, not the source of truth. On every reconnect, the host authenticates and obtains current status and security revision before resuming requests. If the revision differs from the last successfully synchronized revision, it purges all cached secret values and authorization state even if the machine is Trusted again.
- Duplicate or older invalidation events are ignored by revision. An acknowledgment is sent only after cleanup and cancellation of pending pre-launch work completes. If cleanup fails, no acknowledgment is sent; reconnect reconciliation remains the fallback.
- Reconciliation is limited to the security state needed to establish cache validity; it does not require downloading all machine configuration.

#### Process launch and invalidation race

- The host service prepares the child process and its environment without launching it. Secret values are held only in the service's working memory and the prepared child environment; they are not returned to the CLI as a separate secret response.
- Immediately before process creation, the host service performs a final authorization check and commits the launch against its current local authorization state. The service, not the CLI, owns this launch boundary.
- Launch commit and local invalidation handling are serialized so only one wins the race.
- If invalidation wins, the pending launch is cancelled and the prepared environment is discarded.
- If launch wins, the child is considered launched. Later invalidation must not inspect, signal, suspend, terminate, or otherwise interact with it.
- An authority cannot prevent a launch that occurs while the host is disconnected and has not yet received an invalidation. This is consistent with the offline-cache policy. In remote-authority mode, the host service's offline freshness and expiration policy remains the limit on cached use; a new retrieval or new approval requiring the authority cannot proceed.

#### Authority authentication and cryptographic protocol

Application-level authenticated encryption is mandatory for authority communication. HTTPS is an additional transport layer, not a substitute for the application protocol.

- Local developer deployments may use HTTP; they do not require developers to create or install self-signed HTTPS certificates.
- Connections to externally hosted authorities require HTTPS in addition to application-level authenticated encryption.
- Machine identity private keys authenticate the machine. Authority signing keys authenticate authority-issued messages and responses. The authority public key is pinned during the administrator-approved enrollment flow. The host rejects unknown authority keys and does not treat TLS server identity alone as authority-message authorization.
- The host accepts authority messages only when signed by a pinned, trusted authority key. Routine key rotation is authorized by a transition signed by the currently trusted key. If the current key is compromised or unavailable, replacement requires an explicit authenticated administrator recovery/re-enrollment process; an unknown key is never trusted automatically.
- Each connection performs a fresh mutually authenticated handshake. Both parties prove possession of their identity private keys.
- The handshake uses fresh ephemeral ECDH P-256 key pairs. Identity signatures bind the ephemeral public keys and handshake transcript to the authenticated identities, preventing key substitution and active man-in-the-middle attacks.
- Derive fresh session keys using HKDF-SHA-256 over the ephemeral shared secret and transcript context. Use an established AEAD construction (AES-256-GCM) with separate directional keys.
- Use built-in .NET cryptographic primitives and standard formats. Do not add a third-party cryptography dependency or invent cryptographic algorithms.
- Every encrypted message is bound to its session and sequence number. Reject duplicate, out-of-order, invalid, or wrong-session messages. Reconnection always creates a new session with new keys. Application-level authority messages that affect trust, grants, revisions, or secret release are also authenticated as authority-issued data; the relay cannot forge them.
- The authority-facing application protocol uses canonical JSON and includes a protocol version. The request digest binds the exact request approved by the human. The host service verifies authority signatures and request binding before releasing approved values to the local child-launch path.
- Dotenvx/store encryption and transport encryption are separate layers. Existing store ciphertext format is not changed by this protocol.
- Application encryption protects message contents, not all traffic metadata. Network addresses, connection times, message sizes, and traffic timing may remain visible.

#### Relay privacy and behavior

The relay forwards end-to-end encrypted application messages and does not possess endpoint private keys or session keys.

The relay can see:
- Connected machine fingerprints and routing destinations.
- Network addresses of connected machines.
- Connection times, message sizes, and traffic timing.
- Whether a machine is connected.

The relay cannot see:
- Secret names or values.
- Reasons, commands, approval details, or grant contents.
- Application message types or payload contents.
- Machine or authority private keys.

The relay keeps registrations in memory only, replaces stale registrations on reconnect, and does not persist or log message payloads. It does not make authorization decisions.

#### Replay protection, retries, and durable authority state

- Every connection has fresh session keys and per-session monotonically increasing message sequence numbers. Old-session messages are never accepted in a new session.
- Every logical operation has a unique request ID. A retry of the same operation reuses that ID.
- Durable operations are idempotent. The authority records processed request IDs and their results in the same SQLite transaction as the operation, so a retry returns the committed result rather than executing it twice. These stored results are operation metadata, not secret values or decrypted payloads.
- If a connection drops and the outcome is unknown, the client retries with the same request ID. It does not create a new logical operation.
- Invalidation notifications and their acknowledgment state are durable at the authority. Unacknowledged notifications are retried after authority restart; reconnect revision reconciliation remains the source of truth.
- SQLite is the authority's durable store. Ordinary database transactions provide atomicity for security-sensitive operations; no distributed transaction system or message broker is required.
- Machine records and statuses, host-name bindings, friendly names, public keys, security revisions, grants and expirations, signing-key metadata and rotation history, audit history, processed request IDs/results, and pending invalidation delivery state are durable.
- A machine disable/untrust operation atomically updates status, increments security revision, invalidates grants, and records the audit event.
- Grant approval atomically records the approved scope, expiration, and audit event.
- Authority key rotation atomically records the new key and its authenticated trust transition.
- A committed operation remains committed after a crash; an uncommitted operation has no partial effects.
- The authority signing private key is not stored in plaintext in the SQLite database. It is protected separately using an OS-protected key store or equivalent protected secret storage; SQLite contains public trust material and metadata, not the plaintext private key.

#### Audit events, delivery, and administration

- The authority is the durable source of audit history. The local host service maintains a SQLite outbox for events not yet acknowledged by the authority.
- Audit an authorization attempt, including denied attempts, and every use of a grant, whether online or under a valid offline lease. Record the authorization decision separately from the launch outcome and execution outcome.
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
- Locking the authority must discard usable in-memory key material and decrypted working material as far as the runtime permits. Health/status endpoints may report that the process is running but locked; they must not disclose protected material.

**Sensitive administrator operations**

- Sensitive administrative operations always require a fresh passkey authentication with user verification, regardless of whether the authority was manually or automatically unlocked.
- The authentication challenge must be bound to the specific operation and its security-relevant parameters (for example, target machine, grant scope and expiration, key identity, or settings being changed). It must be single-use, time-limited, and protected against replay. A previously authenticated web session or an earlier unlock does not satisfy this requirement.
- At minimum, sensitive operations include administrator passkey enrollment/removal/replacement; machine trust, disable, untrust, or re-trust transitions; grant creation, scope/expiration changes, extension, renewal, and revocation; secret and provider-credential creation, replacement, or removal; security-setting and unlock-policy changes; and authority-key recovery or rotation.
- Recovery is a separate, tightly controlled ceremony. A recovery code or unattended-unlock key is not a routine substitute for fresh passkey authentication on sensitive operations.
- Failed or unavailable passkey authentication fails closed. There is no fallback to an ordinary password, an unlocked authority session, or unattended-unlock material for these operations.
- Sensitive-operation attempts and outcomes are durably audited without recording passkey secrets, PRF output, recovery codes, or private key material.

**Grant use is not an administrative operation**

- A valid, applicable, unexpired grant authorizes routine use within its approved scope without another human approval or passkey prompt. Requiring a passkey for every grant use would defeat the purpose of preapproval and is not part of this design.
- Passkey authentication is required to create or change the grant, not to exercise it. Grant scope, expiration, machine status, security revision, and offline-authorization lease continue to be enforced on every use.
- An authority unlock, including unattended unlock, does not itself create a grant or expand any existing grant.

**Key separation**

- Keep machine identity signing keys, authority message-signing keys, and secret-data encryption/wrapping keys cryptographically separate. A key used to authenticate protocol messages must not be reused to encrypt or wrap secret data.
- Protect the authority signing private key outside plaintext SQLite, as already required above. Protect secret-data encryption keys separately; persist only ciphertext and wrapped key material. Use authenticated encryption and bind ciphertext to stable record identity/version and purpose through authenticated associated data.
- The precise authority key hierarchy, key-wrapping implementation, rotation, backup, and recovery procedure must be documented and tested before production use. Reuse sound existing vault primitives where appropriate, but do not assume the current prototype's user-interactive PRF unlock flow automatically solves unattended service startup.

#### Current implementation boundary

This section is the accepted target design. What exists today (Phases 1 and 2): a local **host service** (`with-secrets service`, foreground console host, loopback only; Windows service installation, start at logon and the service account are not built) and the CLI as its client for runs, over the shared HTTP API with versioned JSON (`LaunchRequest` with a digest, NDJSON events). The service owns the approval page, store access for runs, decryption, environment preparation, launch, redaction and exit status, and serializes the final launch commit against local authorization invalidation (`LaunchGate`).

Phase 2 adds the **machine identity and a local authority** (no network): an ECDSA P-256 machine key in Windows CNG (non-exportable; Platform Crypto Provider first, silent fallback to the software provider) whose fingerprint is the SHA-256 of the canonical SPKI; a separate authority signing key, pinned (public key only) in `host.json` at the first approval of the machine, with rotation by a signed transition and recovery by an explicit admin action; `authority.db` (SQLite, WAL, schema 1 as built in Phase 2: machines, machine_history, grants (structure only), authority_keys, audit_history, processed_requests, pending_invalidations) beside `state.db`, which is unchanged. Enrollment records first contact as Pending with proof of possession; the status table above is implemented exactly (the security revision goes up only on Trusted to Disabled and Trusted to Untrusted; a rename never changes it; a changed host name is recorded as pending and the binding is not changed until `admin approve-host-change`). `IAuthority.DecideAsync` takes a machine-signed `MachineRequestEnvelope` (the launch request, fingerprint and host name), re-reads the machine's status and revision inside the transaction that commits the decision, runs the approval page for exactly that digest and returns a canonical-JSON `AuthorityResponse` signed by the authority key; the host checks the pinned key, the signature, request id, digest, machine, validity (60 s, never more than 5 min) and the revision before anything is decrypted. A retry of a request id returns the committed answer from `processed_requests`. An exact request replayed after a restart within the response's validity returns the stored answer, but the host has no approval of its own for it and denies. The admin commands (`admin machines|approve|disable|enable|untrust|trust|rename|approve-host-change|rotate-authority-key|recover-authority`) are terminal-only and every change needs a one-use page with an admin passkey tap (the action and the full fingerprint are in the signed page text). The CLI authenticates the service (POST `/v1/identity`: a signature over a fresh challenge by the machine key, whose fingerprint must equal the one pinned in `host.json`) before it sends anything, with exit code 7 otherwise; this adds no client credential. Saved approvals (Phase 1 `GrantStore`) are honoured behind the service only under the security revision they were made in, and none survives a service restart; a revision increase or an applied invalidation clears them. **Open item for the maintainer:** the identity check is not channel-bound, so an impostor that holds the port and relays `/v1/identity` to the real service could still read the launch request and environment (a fix needs a channel-bound handshake or encryption of the request to the identity key; not decided). Known limits: a running service learns of an invalidation through a 1 s poll and before each launch; two services on one `authority.db` are not supported; `authority.db` has no integrity protection and keeps no copy of the admin assertion; `host.json` and the key store are within the same-user trust limit; the approval page content that a remote authority would need (script contents) is not part of `LaunchRequest` (Phase 5); the envelope has no parser yet (Phase 5); CNG is Windows-only; retired authority private keys are not deleted.

Phase 3 (the independent parts) adds **grants as authority operations and the offline lease**: `authority.db` schema 2 (a schema 1 file is migrated in place; the grants table of schema 1 was never written) holds grants (id, machine fingerprint, scope key, a description of what the scope covers, created, expires or NULL for indefinite, a grant revision, status active, revoked or invalidated, who approved), `grant_events` (revocation notices for a host) and `processed_grant_requests` (the committed signed answer for each request id). `IAuthority` gained `GrantAsync` (a machine-signed `GrantEnvelope`: use, or approve, which shows the ordinary page and creates or updates the one grant for the scope), `ReconcileAsync`, `PendingGrantEventsAsync` and `AcknowledgeGrantEventAsync`; every answer is canonical JSON signed by the authority key and checked by the host like a decision (pinned key, signature, request id, digest, machine, validity, operation). Extend, renew and revoke are applied by the authority after an admin passkey tap (`admin grant list|extend|renew|revoke ID`, terminal-only); each is atomic with its audit row and stored answer, idempotent by request id, refuses a grant that changed meanwhile (grant revision), and never changes the machine's security revision. **Scope key (provisional; 10.2 does not say):** the scope of a grant is the host's request fingerprint key (secret names, resolved program path, working folder, `.env` plan, script content hash, inherited-environment hash), opaque to the authority, which also stores program, folder and names for display; other arguments and the reason are not in it. `with-secrets approve COMMAND` (HTTP `/v1/approve`) asks for that approval and launches nothing; `run` under an applicable, unexpired, unrevoked grant for this machine and exact scope skips the page decision and otherwise falls back to the page. **Lease:** issued only inside a signed reconcile answer (default 15 minutes, provisional), held in host memory, measured by a monotonic clock from receipt, destroyed by a restart, never lengthened by a grant (indefinite included) or by the wall clock; no valid lease means no secret use (deny code `no-lease`), for local authority mode too (the same code path). Offline, only a grant the host already synchronized counts, only inside the lease and before the grant's own end; no new approval, extension or renewal is possible and an extension is seen only after the next online use. **Startup reconciliation:** before it accepts a request the service checks machine status and security revision with its authority; an unreachable authority leaves it returning 503 until a check-in succeeds. A connected host applies a revocation, disable or revision change at once (grants and lease dropped, `LaunchGate.Invalidate()`; a revocation invalidates every launch that has not committed, not only those that used the grant). **The store key (maintainer decision):** the first run under a grant gets the key from one passkey tap; the service then holds that key material (the PRF output, which opens K and can be zeroed) in memory for the grant and later runs under it need no tap or page. It is dropped and zeroed on grant expiry or revoke, machine disable or untrust, a security revision change, the lease ending, a service restart and every failed run; never written to disk or a log, no other caching. **Open item: a cleaner mitigation for holding the key in memory is to be revisited later** (see the blocker section of `IMPLEMENTATION_PROGRESS.md`). The seam is `IStoreKeyProvider` (`StoreKeyProvider.cs`): `TapStoreKeyProvider` is the plain tap, `HeldStoreKeyProvider` the service default. Known limits: `authority.db` has no integrity protection (a same-user process can insert a grant; saved approvals self-verify with the passkey assertion, grants do not); the Phase 1 requirement that grants be unusable by other OS users is **not** implemented (the API has no caller identity; idea: a same-user check on the loopback connection's owner process, behind a seam); the host persists no revision and fetches grants on demand, so a restart restores none.

Phase 3 fix round 1: the grant scope key covers the full argument list (`GrantEvidence.Scope`); `authority.db` is schema 3 and each grant row stores the approver's passkey assertion (over scope, security revision, minutes), verified at every use against the signed manifest, and extend/renew/revoke need an admin assertion over the new end; rows without valid evidence are ignored. The held key is bound to grant, scope, revision and end at the tap, lent only to that scope, kept in pinned memory, and the key-holding tap page says it is kept for the grant's duration (until restart when indefinite). Residual: rollback of the whole `authority.db` file.

Phase 4 adds the **durable audit trail** (10.2 "Audit events"). `AuditEvent` (`Authority/AuditEvents.cs`) is a canonical-JSON event signed by the machine key in the format of the other machine messages (domain `with-secrets audit event v1`): event id (GUID), per-machine sequence, time, machine fingerprint, type (`authorization`, `launch` or `execution`), outcome, reason code, request id, working folder, program, redacted arguments, grant id, exit code. No OS user, no secret value and no environment value; arguments pass through `AuditRedaction` (a heuristic: values after secret-like names, Authorization/Bearer values, URL passwords are masked; long ones cut; the host records them before it decrypts, so it cannot mask exact values). `HostAuditOutbox` is `audit-outbox.db` beside `authority.db` (SQLite, WAL, `synchronous=FULL`, schema 1; another version or a damaged file is never repaired: delete it): one write transaction reads the counter, signs, inserts the event and bumps the counter, so the sequence is monotonic and gapless (a failed commit uses no number) and a returned commit is on disk. `RunCommand` records the **authorization** event (approved, granted, reused, denied, grant-approved for `approve`) and, for any outcome that lets the run go on, requires it to be committed before the store is opened; if not it ends with exit 5 and decrypts nothing. The **launch** (started, or failed/cancelled with a code) and **execution** (exited with the exit code, or an internal failure) events follow; a failure to commit them is logged (type only) and does not stop a launch that happened. Every run through the service names secrets, so every one is secret-bearing; there is no non-secret path to relax. `HostAudit`/`AuditUploader` send the outbox in batches through `IAuditSink` (the local authority implements it; a remote one will) and remove an event only after an `AuditAck` signed by the pinned authority key (verified like every other answer: key or transition, signature, batch id and digest, machine, validity) names it accepted, duplicate or expired; a rejected event (bad signature, unknown machine, id reused) is kept apart and not resent. The loop wakes on each new event, retries with a doubling pause (capped at 60 s) while the authority is unreachable or an answer does not verify, resumes after a restart from the outbox, and never makes a launch wait. At the authority (`authority.db` schema 5, migrated in place from 1 to 4; the first-cut audit tables of schema 4 are replaced) one transaction per upload verifies each event against the machine's registered public key, stores each event id once (the same id with other content is rejected), keeps the machine's highest sequence, records a skipped range as a `missing` gap (shrunk or split when a late event fills it) and a number used by two events as `reused` (never a reason to reject), and only then is the acknowledgement signed. Retention is the authority's setting (`audit_retention_days`, 365 by default, 0 keeps everything; set through `AuthorityStore.SetAuditRetentionDays`, no command yet): events older than it are acknowledged as `expired` without being stored, and events whose receipt is older are pruned on each upload or by `PruneAuditEvents`; only acknowledged events exist at the authority, and the host never prunes an unacknowledged one. `AuthorityStore.AuditHistory(AuditQuery)` filters by machine prefix, time range, type, outcome, grant id, folder and text; `with-secrets admin audit [filters]` and `admin audit --gaps` print it (terminal only, read-only). **Provisional (10.2 is silent):** the old `AuditLog` rows in `state.db` and their hash chain stay unchanged for the human commands and still record the service's runs as before (`--audit` unchanged), and the new signed trail is added beside it for runs through the service; they are not merged or cross-checked. Review fixes: every event carries the **epoch** (a random id made with the outbox, signed) and the authority tracks the sequence per (machine, epoch), so numbers of a recreated outbox can never close a hole of an earlier one (a number repeated within one epoch is still `reused`); the host cuts folder, program path, codes and arguments to the authority's limits before signing (`AuditRedaction.Bound`) and refuses to sign an event that is still invalid; `approve` commits an `approval-requested` authorization event before the tap and fails closed (exit 5) without it; the uploader parks only final refusals (an unknown or not yet approved machine, or a status the host does not know, is retried); the upload loop survives any exception; events dropped as expired are counted in the authority's `audit_history` (`audit-events-expired`); duplicates are checked per machine; `--text` finds backslashes, quotes and non-ASCII letters in arguments; redaction also masks JSON bodies, `-u/--user/--proxy-user NAME:PASSWORD` and `-pSECRET`. Event reason and outcome words, the 60 s acknowledgement validity, the batch sizes (50 sent, 200 processed), the retry pause and the 365-day default are implementation choices. Known limits: the outbox and `authority.db` have no integrity protection against a same-user writer (a deleted outbox restarts the numbering under a new epoch, which the authority records as an `epoch` gap; the old epoch's holes stay open); the service's own `state.db` rows still hold raw arguments (as before).

Phase 4b reconciles the implementation with "Authority key protection, startup lock, and administrator authentication" above.

**Startup lock.** The service starts locked (`AuthorityLock`). It is a gate in the service process, not a second encryption layer: the authority signing key stays a CNG key and the lock decides when the process may use it. Locked means: `AuthorityKeyRing.Current/Rotate/Recover` throw (so the authority decides, grants, reconciles and acknowledges nothing, because every answer is signed), `HostService` answers runs and approves with 423 and one line naming the admin page (the CLI exits 8), `HostAuthorization` authorizes, uses and lends nothing, and locking runs `HostAuthorization.Discard`: the held store key (PRF-derived material) is zeroed and dropped, the offline lease and synchronized grants are cleared, saved approvals end, `LaunchGate.Invalidate` cancels launches that have not committed, and the host is no longer ready. `GET /v1/status` reports `running` and `locked` only. Unlocking checks the host in with the authority again before it serves; nothing is restored from before the lock. A program that already started is not affected.

**Admin web app (root).** The service serves, on its own loopback port, `GET /admin` (status: running, locked or unlocked and how, the unlock mode shown visibly), `GET /admin/audit` (the authority's audit history, read-only) and `POST /admin/op` (start an operation; only from the page's own origin). The route table (`AdminService.Pages`) is the extension point for Phase 6 (machines, grants, settings, audit search): each state-changing action there starts a one-use passkey page the same way. There are no `admin lock`, `unlock`, `unlock-policy` or `status` verbs; `with-secrets admin` with no words prints the app's link and the public status. The existing admin verbs (machines, approve, grant, audit, ...) are unchanged and move into the app later; until then they run in their own process, need their own fresh tap, and are not gated by the service's lock.

**Sensitive administrator operations.** `AdminAuthorizer` is the one way the authority's own operations (unlock, lock, unlock policy, audit retention) are authorized: it shows a one-use page whose signed text carries `Operation: ...` and one `Parameter name: value` line per security-relevant parameter, then verifies for itself that the assertion verifies against the enrolled keys and was made by an admin key (the proof check requires user verification), that the signed text is exactly this operation and these parameters (no more, no fewer), that the page was issued within the page limit and not in the future, and that its nonce was not accepted before. A `VerifiedAdmin` token results; the store methods that change a setting (`SetUnlockPolicy`, `SetAuditRetentionDays`) take one and spend it, so they cannot be reached from an unlock, an earlier tap, another operation or other parameters. Failed, denied, timed-out or unavailable passkeys fail closed; an operation whose attempt cannot be recorded in the audit history is not started. Attempts, refusals and outcomes are written to `authority.db` `audit_history` as `admin-operation` rows (operation, outcome, parameters, key name; never a proof, nonce or code). Audit of the existing operations:

| Operation | Where it is authorized | Fresh, bound, single-use, UV | Tests |
| --- | --- | --- | --- |
| Admin passkey enroll / unenroll / replace (`--enroll`, `--unenroll`), `--recover` | Admin approval page and signed manifest (`Enrollment`, `StoreRecovery`); recovery is its own ceremony with the recovery code | Page nonce, text and manifest signed; `WebAuthn` requires UV | `WebApprovalTests`, `RecoveryTests`, `ManifestTests` (non-UV manifest signature refused) |
| Machine approve, disable, enable, untrust, trust, rename, host-name change | `AdminCommand` one-use page, text names action, full fingerprint, state | Same page flow | `AdminTests` suite: for each, non-admin key, no UV, signature over another challenge, no answer, replay change nothing |
| Grant create (approve), extend, renew, revoke | Approve page evidence verified by the authority; admin grant text `Change/Grant id/Scope/Machine/New revision/New end` verified by the authority | Same; revision in the signed text defeats replay | `GrantAuthority` suite (adds no UV, other challenge, replay) |
| Secret and credential set / remove (`--set`, `--remove`), settings (`--config`), `--revoke`, `--rotate-key` | Manifest or admin approval page | Same page flow | existing page suites (denied or non-admin changes nothing) |
| Authority key rotation / recovery | `AdminCommand` page, `AuthorityKeyRing` (refused while locked) | Same | `AdminTests`, `AuthorityLock` |
| Unlock, lock, unlock policy, audit retention | `AdminAuthorizer` as above | Verified again by the authority; nonce remembered | `AuthorityLock` suite |

Gap found and closed: `SetAuditRetentionDays` took an actor string with no proof; it now needs a `VerifiedAdmin` for exactly that change (no command or page exposes it yet). Remaining limit: the CLI admin verbs and the settings pages verify the tap in the process that runs them rather than through the authority's `AdminAuthorizer`; moving them into the app brings them under it.

**Unlock mode.** `unlock_policy` (manual by default, unattended only by a fresh tap on the app) and, for unattended, a DPAPI-sealed random 32-byte blob and its SHA-256 are in `authority_settings`. `IUnlockProtection` has `DpapiUnlockProtection` (Windows, current user) and `NoUnlockProtection` elsewhere (the option is refused with a message); no other platform is assumed. At start, `UnattendedUnlock.TryUnlock` opens the blob, compares the hash and unlocks; any doubt leaves the service locked. It grants nothing, widens nothing and never replaces a tap. Weaker by design: any process of the same Windows user can open the blob. The service prints the mode at start, the app shows it, and README documents it as weaker.

**Key hierarchy (what exists).** Three purposes with no shared key: (1) the machine identity key (CNG key `with-secrets machine identity v1`, signs machine requests, reconcile and audit events and the service identity proof; domain-separated signed messages); (2) the authority signing key (CNG key `with-secrets authority signing key v1`, then `... g2`, `... g3`, signs the authority's answers and rotation transitions; public part pinned in `host.json`; used only while unlocked); (3) secret-data keys: the store key K and master key MK, kept only as ciphertext in the signed vault of `state.db` wrapped by each passkey's PRF output, never by (1) or (2). The held PRF-derived material (secret-data only) lives in service memory for one grant (Phase 3 maintainer decision) and is zeroed at lock, grant end or service stop. The unattended-unlock material is a fourth, unrelated random value that unlocks nothing cryptographic: it only lets the service decide to unlock. A signature by one signing key never verifies under the other (tested), and no file of the authority or host contains the held material (tested).

**Backup and recovery procedure (written; exercised in tests as far as it exists).** (a) Authority signing key: routine rotation is a transition signed by the current key (`admin rotate-authority-key`, unlocked service not required for the CLI but required for the service's key ring); loss or distrust: `admin recover-authority` makes a new key with no transition and pins it for this machine, other hosts re-enroll. The CNG keys are not exportable, so there is no backup of the key itself: recovery replaces it. (b) Secret-data keys: the recovery code (`--recover`) and a second admin passkey; there is no other copy of K or MK. (c) Unattended-unlock blob: not backed up; if it will not open, the service stays locked and an administrator unlocks with a tap. (d) `authority.db` backup: copy the file while the service is stopped; it holds public keys, grants and audit, no private key or secret. The exercise in the suites covers rotation, recovery, a lost unattended blob falling back to manual unlock, and the locked state refusing rotation. Wrapping the authority key for backup, the machine-to-machine procedure and a restore test on a second machine remain to be written and tested before production.

Phase 5 adds the **remote authority protocol and the relay** (`Remote/`). **Handshake** (`SecureChannel.cs`): the host sends a hello (type, version, a fresh ephemeral ECDH P-256 key as SPKI, a 32-byte nonce, the fingerprint of the authority key it trusts); the authority answers with a server hello (its ephemeral key, nonce, its signing public key, the signed key transitions from the host's trusted key to its current one, at most 8) and an ECDSA signature by its key over `H("authority", hello, server hello body)`; the host accepts only the trusted key (or one reached by transitions signed link by link from its pinned key), checks the signature, and answers with its machine public key and a signature over `H("machine", hello, server hello, machine key)`, so both ephemeral keys, both nonces and both identities are bound and key substitution or a man in the middle fails. Keys: HKDF-SHA-256 over the ECDH secret, salt = the machine transcript, one expansion into two AES-256 keys, two 4-byte nonce prefixes and a 16-byte session id. **Frames**: `0x04 | sequence (u64) | ciphertext | 16-byte tag`; nonce = direction prefix + sequence; AAD = `"WSR1"`, version, session id, direction, sequence. A receiver accepts exactly the next sequence number; a repeat, gap, reorder, reflection, foreign-session frame or any changed bit ends the session for good (a reconnect makes a new handshake and new keys). The authority's first frame confirms the keys. Handshake messages are fixed-layout binary; an error before authentication is an unauthenticated `0x05 | code` that only ends the attempt. **Application messages** (`RemoteWire.cs`, inside the session): `{"v":1,"id":S,"op":S,"body":{...}}` and `{"v":1,"id":S,"ok":true,"body":{...}}` or `{"v":1,"id":S,"ok":false,"error":CODE}`; bodies are the existing signed contracts (machine envelopes in; authority responses, grant, reconcile and audit answers out, each with its own signature, read strictly); operations: begin-enrollment, enroll, decide, grant, reconcile, key-transitions, pending-invalidations, ack-invalidation, pending-grant-events, ack-grant-event, audit-upload, and the authority-to-host push-invalidation. `RemoteAuthority` (host side, `IAuthority` and `IAuditSink`) reconnects and repeats an operation under the same id (up to 2 times); `AuthorityEndpoint` (authority side) wraps the same `LocalAuthority`, `AuthorityKeyRing` and `AuthorityStore`: it runs one operation per id per session (same id and content: the same answer; other content: `request-id-reused`), binds the session to the machine that proved its key (a request, acknowledgement or enrollment naming another machine is refused with `wrong-machine`), leaves idempotency across sessions to `processed_requests`, refuses everything while the authority is locked, and pushes a connected machine's unacknowledged invalidations every 2 s until acknowledged (the pending list in `authority.db` stays the source of truth; the host's 1 s poll also fetches it). **Relay** (`Relay.cs`): WebSocket endpoints `/relay/v1/authority` and `/relay/v1/host` (query `registration=ID`); between relay and authority a frame is `kind | connection id (16) | payload`, between host and relay the payload itself; a newer authority connection replaces the stale one (and ends the hosts paired through it), a host with no authority gets 503, frames are limited to 8 MiB; it parses nothing inside a payload. **Config**: `host.json` gained an optional `remote` member (`relayUrl`, `registrationId`, `authorityFingerprint`, `tlsPin`); `LocalDeployment.UseRemote` swaps `Link` and `AuditSink` for the `RemoteAuthority`; `with-secrets relay` runs the relay. **Provisional (10.2 is silent):** the key fingerprint in `host.json` is the transport trust anchor before approval, and the first handshake pins the whole key in `host.json` when none is pinned (equality of the SHA-256 with the out-of-band value; no other key is ever pinned automatically); a plain http/ws relay is allowed for loopback only; the relay registration id is not a secret and not authenticated (anyone who knows it can register as that authority and so deny service or replace the real endpoint, never read or forge anything because every host checks the authority key); the push interval, retry count (2), 15 s handshake limit and message limits are implementation choices. **Open items for the maintainer:** (1) the approval page, the passkeys and the secret store are still on the host (`HostAuthorization` still hands the approval to the local `LocalAuthority.Offer`), so a truly separate remote authority cannot yet show the approval page or hold the store: where the page is shown and how approved secret values or ciphertext reach the host in remote mode is not specified in 10.2 and is not decided here; the end-to-end tests run the host and authority roles in one process over the real relay; (2) no command starts `AuthorityEndpoint` yet (its production hosting belongs with the answer to (1) and Phase 6); (3) in remote mode the host service still starts locked by its own `AuthorityLock` and needs its local unlock; the remote authority's lock is enforced at the endpoint. Known limits: a restart of the relay or authority ends sessions (reconnect on the next call, at most a 1 s poll later); sizes are bounded, not rate limited; the relay does not authenticate registrations; the endpoint's per-session result memory holds the last 512 operations.

Not built: the full admin web app (machines, grants, settings and searchable audit history; this version has the status, lock, unlock, unlock policy and a read-only audit list) and an administrator page to change the retention (Phase 6), and the Windows privilege separation of Task 16. The per-run rows in `state.db` (with their hash chain) stay for the human commands (see Phase 4 above); `authority.db` also has its own `audit_history` table. The loopback API has no caller identity: any local OS user can reach it, which is why grants should be unusable by other users (not yet done, see above). The inherited environment of a request is bound into the approval fingerprint and summarized on the page (count and notable names, no values). A client cancel (disconnect or the cancel route) before the commit discards the launch; after the start it ends the program and its child process tree, whereas an authorization invalidation never touches a launched child. The human commands (`--config`, `--set`, `--remove`, `--enroll`, `--unenroll`, `--recover`, `--rotate-key`, `--revoke`, `--audit`, `--list`, `--enrolled`, `--needs`) still open `state.db` in the CLI process. The current prototype uses SQLite. Task 16 (service account and privilege separation) remains separate and is not expanded here. The existing Phase A `.env` behavior in Section 10.1 remains unchanged: the CLI reads the files once and the service checks the plan it receives with the same rules.

### 10.3 Secret providers, logical mounts, and namespaces

**Status:** Agreed architecture direction; provider implementations and mount configuration are not yet built.

with-secrets supports multiple secret sources/providers concurrently. Project declarations use logical names; the host authority maps those names to configured provider instances.

**Logical paths**

Examples:

- `secret://personal/github/token`
- `secret://team/development/github/token`
- `secret://infrastructure/aws/production/access-key`

The path is a logical name only. It does not expose provider name, account, SDK, API endpoint, or physical storage location to the project. Path segments are organizational namespaces, not implicit provider selectors.

**Mount model**

- A mount maps a logical location to a configured provider instance and a provider-side location. There are two forms: a **tree mount**, which maps a provider-side folder/namespace and exposes its relative contents below a logical folder; and an **individual-secret mount**, which maps one specific provider secret to an arbitrary logical secret path.
- For a tree mount, the logical path is formed from the logical mount point plus the provider-relative path beneath the configured provider base path. For an individual-secret mount, the configured logical path names that one provider secret; its provider-side path need not resemble the logical path.
- Mounts are configured by the host authority, not checked into the project repository. Project files remain portable and contain no provider credentials or machine-specific provider configuration.
- Mount definitions are global, with project-specific permissions/allowlists. A project may use a logical path only when policy grants access.
- Multiple mounts/providers coexist. A provider tree can be mounted at multiple logical locations, and individual secrets from different providers can be mounted into the same logical namespace. The same underlying provider secret may therefore have multiple logical paths.
- Provider ACLs remain in force. with-secrets human approval is an additional release gate, not a replacement for provider authorization.
- Provider authentication and SDK/API credentials stay on the host/authority side. Windows/WSL/Docker CLIs do not receive provider credentials and do not need provider SDKs.
- Logical path resolution uses **longest-prefix matching** for tree mounts, with segment-boundary-aware prefixes. More-specific tree mounts override broader tree mounts for their subtrees. An individual-secret mount resolves its exact logical secret path. This is deterministic namespace routing, not fallback: once a logical path selects a mount, any permission, availability, authentication, or missing-secret failure is a hard error and must not fall through to another mount or provider.

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
**No fallback or cross-provider search**

- A missing mount, denied project permission, unavailable provider, missing secret, or provider authentication failure is a hard error.
- Do not search other mounts/providers, fall back to an environment variable, prompt for an alternate name, or silently substitute another value.
- Do not query every provider looking for a matching name. This prevents accidental cross-tenant disclosure and keeps resolution auditable.
- Approval and audit identify the logical name and selected provider/mount identity without exposing credentials or values.

**Provider candidates**

1Password and Bitwarden Secrets Manager are optional provider candidates behind the host/authority adapter boundary. For Bitwarden, the target is Secrets Manager, not the personal password-manager product. These are not first-release requirements. The local encrypted SQLite store remains a first-party provider.

Mount configuration and project permission formats, and provider metadata shown to approvers, remain open. Mount resolution, provider identity/reconciliation, provider version/rotation semantics, provider outage behavior, and retrieval error handling are specified below. Provider-specific syntax must not leak into project `.env` declarations.

### 10.3.1 Provider adapter contract and lifecycle

**Status:** Architecture decisions agreed; common interface and provider implementations are not yet implemented.

Provider adapters isolate provider-specific access behind the authority. Adapters execute in-process with the authority; they are not separate services or plugins loaded dynamically at runtime. The authority discovers and registers the adapters bundled with its release. Adapter implementations may be independently identified/versioned, but are distributed with and tied to an authority release.

An adapter instance represents one configured provider connection. Multiple connections to the same provider type use separate instances and independent configuration. The authority assigns each instance a unique, stable instance ID and supplies it during initialization. In remote mode, adapters run at the remote authority; in local mode, they run at the local authority.

**Responsibilities and boundary**

- The adapter contains provider integration logic only. It does not provide UI, HTML, JavaScript, dynamic configuration forms, or configuration schemas for the admin UI.
- The admin UI owns provider-specific configuration screens. The adapter exposes its configuration type and validation results for the authority/UI integration.
- Adapters are read-only with respect to provider data: no create, modify, rotate, delete, or migration operations.
- The core depends only on the common adapter contract, not provider SDKs or provider-specific types.
- Every adapter implements the complete required contract. There are no optional capability flags or optional operations.
- The authority owns provider configuration persistence, configuration revisions, operation timeouts, concurrency limits, cache/freshness policy, grant lifetimes, and secret delivery. Adapters do not own the secret cache and do not write cache timestamps.
- Adapters must be thread-safe, support concurrent calls, and honor cancellation. They may declare provider-specific concurrency constraints for the authority to enforce.

**Required operations**

Every adapter provides initialization, configuration update, shutdown, configuration validation, mount validation, secret retrieval, and secret listing. Pagination is implemented internally by the adapter and exposed through opaque continuation tokens.

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

    Task<RetrieveSecretResult> RetrieveSecretAsync(
        string path,
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

Adapters may report invalidation while active, including while initializing, ready, or unavailable. The authority rejects invalidation after shutdown begins or after the adapter instance is unregistered. Handling begins immediately but must not block unrelated provider operations; physical cleanup may complete asynchronously. Invalidation takes precedence over work already in progress: a retrieval that finishes after its target has been invalidated must be discarded and must not be cached or delivered. Unrelated in-flight operations continue normally.

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

A retrieval returns UTF-8 bytes only; provider metadata is not returned with the value:

```csharp
public sealed record RetrieveSecretResult(byte[] Value);
```

The core validates strict UTF-8 before updating its cache and preserves the exact bytes without normalization or re-encoding. The CLI later converts to the target process encoding; if the value cannot be represented, the operation fails rather than silently corrupting it. Host-service responses use UTF-8. An empty provider value is treated as unset. A missing path or provider error is a hard failure; there is no fallback.

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

**Logging and diagnostics**

Adapters use the existing `Microsoft.Extensions.Logging.ILogger` abstraction, which can be backed by the application's existing Serilog setup. There is no separate adapter logging framework or metrics interface. Detailed diagnostics go to structured logs; status messages remain concise and safe for display. Never log secret values, credentials, or decrypted provider responses.

**Implementation notes**

- The adapter contract is a design boundary, not a promise that a provider is already implemented.
- Provider-specific connection setup, authentication, retry/backoff strategy, and recovery are adapter responsibilities; global timeouts, cancellation, concurrency enforcement, cache policy, and status retention remain authority responsibilities.
- The precise public API for declaring adapter concurrency constraints and the exact configuration factory/registration mechanism remain implementation details to settle while implementing the common contract.
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

**Status:** Agreed architecture decision.

The core owns cache freshness and stale-serving policy. Stale serving is an availability safeguard for temporary provider outages, not an alternate source of truth.

- Stale serving is configured per provider instance through MaxStaleDuration. It is not a provider-type setting and is not configured per secret or mount.
- The default is zero (disabled). A configured value may be from zero through a hard system-wide maximum of 24 hours. Values above the cap are rejected, not silently clamped. The cap is a system constant initially, not another administrator setting.
- The maximum age is measured from the cached value's lastVerifiedAt timestamp: the last successful retrieval that proved the value current. It is not measured from when an outage begins. A value already 20 hours old has at most 4 hours remaining under the 24-hour maximum.
- A cached value may be served stale only after the core's bounded retry policy is exhausted for an eligible temporary availability failure (Unavailable or RateLimited), and only while its age remains within that provider instance's configured MaxStaleDuration.
- Stale fallback does not apply to authentication or authorization failures, missing/deleted secrets, invalid configuration, invalid provider responses, unknown errors, or cancellation. If no cached value exists, retrieval fails.
- A successful provider retrieval replaces the cached value and updates lastVerifiedAt. A failed refresh leaves both the existing cached value and its original lastVerifiedAt unchanged. A failure must never extend the stale-serving window.
- Once the maximum permitted age is reached, retrieval fails closed. When the provider recovers, the next retrieval attempt fetches the current provider value and replaces the stale cache entry; there is no special stale-first recovery mode.
- Changing MaxStaleDuration is a policy-only provider-instance configuration change. It applies immediately to existing cache entries without reconnecting or reinitializing the adapter and without changing cached values or timestamps. Reducing the duration immediately enforces the shorter limit.

Audit history records the retrieval outcome without recording secret values or credentials:

| Outcome | Meaning |
| --- | --- |
| Fresh | Value retrieved successfully from the provider for this request |
| Cached | Value served from cache within the normal freshness policy |
| Stale | Expired cache value served under the provider instance's outage allowance |
| Failed | Retrieval failed and no value was delivered |

Each audit event identifies the logical secret path and selected provider instance, with its timestamp. A Cached outcome does not imply an outage; it means the cached value was still within normal freshness policy.

### 10.3.4 Provider errors, cancellation, and retries

**Status:** Agreed architecture decision.

Adapters translate provider-specific failures into a common typed exception. Core behavior depends only on the common error category, never on provider-specific exception types or message parsing.

~~~csharp
public enum ProviderErrorKind
{
    Unavailable,
    RateLimited,
    AuthenticationFailed,
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
- Only Unavailable and RateLimited are retryable. Authentication failures, access denial, missing secrets, invalid configuration, invalid responses, and Unknown fail immediately and are never retried.
- The core applies a small, bounded number of automatic retries with a bounded overall retrieval deadline. System-wide defaults and limits govern retries; provider instances and adapters cannot expand them. A supplied RetryAfter is respected only within those core-enforced limits.
- Retries apply only to the provider operation. Mount resolution, authorization, and cache-policy evaluation occur once per request, and the selected provider instance remains fixed throughout the request.
- Caller or authority cancellation propagates as cancellation and does not qualify for stale fallback. A provider-side timeout is translated to ProviderAdapterException(Unavailable). If the authority's provider-operation deadline expires while the caller remains active, the operation is treated as Unavailable and may qualify for stale fallback after retries, subject to the normal stale policy.
- After retry exhaustion, stale-cache eligibility is determined by the final common error category and the provider instance's MaxStaleDuration. Unexpected exceptions are treated as Unknown and fail closed.

### 10.4 Application-specific request declarations (curl add-on)

**Status:** Complementary design proposal accepted for documentation; adapter behavior and security review remain open. This extends the declarative `.env` model; it does not replace ordinary environment variables or `secret://` mappings.

Initial curl-oriented naming proposal:

```dotenv
# Header name is ordinary configuration.
curl_api.github.com_authorization_key=Authorization

# Header value is resolved by with-secrets.
curl_api.github.com_authorization_value=secret://team/development/github/token
```

- The `curl_` prefix identifies the intended application adapter. The host portion identifies the exact destination domain; `_key` names the header and `_value` provides its literal or secret-reference value.
- These are with-secrets curl-adapter declarations, not ordinary variables passed through to the child environment.
- Compose declarations first. Only the effective surviving declaration is considered. A secret-valued `_value` uses the same mount and approval model as any other `secret://` reference.
- Exact-host matching is the initial proposal. Do not send a credential to a different host. HTTPS-only use, redirect behavior, conflicting headers, duplicate declarations, and interactions with curl configuration files require explicit security review.
- The adapter must not place the secret in command-line arguments, shell history, terminal output, logs, or persistent temporary files. The concrete interception/injection mechanism is open; do not claim it is implemented.
- Unknown application prefixes must not silently become ordinary environment variables. Behavior when an adapter is unavailable (clear error versus unused declaration) remains open.
- This is curl-specific initially. Do not generalize it into a broad command/network authorization broker; with-secrets remains focused on secret exposure.

## 11. Where is it in the code

| Concept | File (`src/WithSecrets.Core` unless noted) |
| --- | --- |
| Entry, gate, dispatch | `src/WithSecrets/Program.cs` |
| Command wiring, targets, code reader | `CommandWiring.cs` |
| Argument parsing, `NeedsTerminal` | `CommandLine.cs` |
| Remote authority: handshake and encrypted session, wire messages, relay, authority endpoint, host client | `Remote/SecureChannel.cs`, `RemoteWire.cs`, `Relay.cs`, `RemoteTransport.cs`, `AuthorityEndpoint.cs`, `RemoteAuthority.cs` |
| Run pipeline, exit codes | `RunCommand.cs` |
| Host service: loopback API (`/v1/launch`, `/v1/approve`), request checks, event stream, cancel, `/v1/identity`, invalidation pump, startup reconcile (503 until done) | `HostService.cs` |
| Machine and authority keys (CNG, software, fingerprint, signatures) | `Authority/Keys.cs` |
| Signed envelope and response, enrollment, key transition, `IAuthority` | `Authority/AuthorityProtocol.cs` |
| `authority.db`: machines, history, decisions, keys, invalidations, grants | `Authority/AuthorityStore.cs` |
| `authority.db`, audit side (schema 5): uploaded events, sequence state and gaps, retention, history query | `Authority/AuthorityStore.AuditEvents.cs` |
| Signed audit event, batch, acknowledgement, `IAuditSink`, argument redaction | `Authority/AuditEvents.cs` |
| Host audit outbox (`audit-outbox.db`), uploader and its loop | `Authority/HostAudit.cs` |
| Local authority (also the `IAuditSink`), authority key ring | `Authority/LocalAuthority.cs` |
| Host side: verify answers before decrypting, revision, pump, synchronized grants, offline lease, startup reconcile, held key sweep | `Authority/HostAuthorization.cs` |
| Grants: signed grant envelope and answer, reconcile, offline lease, monotonic clock | `Authority/GrantProtocol.cs` |
| `admin grant list/extend/renew/revoke` | `Authority/AdminGrantCommand.cs` |
| Where the store key comes from for a grant run; the held key | `StoreKeyProvider.cs` |
| Grant scope key, assertion evidence stored with each grant row and its verification (`IApprovalVerifier`) | `Authority/GrantEvidence.cs` |
| `host.json` (pinned authority key) | `Authority/HostConfig.cs` |
| Deployment of identity, store and authority; startup lines | `Authority/LocalDeployment.cs`, `Authority/ServiceStartup.cs` |
| `admin` commands | `Authority/AdminCommand.cs`, `CommandWiring.cs`, `CommandLine.cs` |
| Authority lock, unattended-unlock policy and platform protection (`IUnlockProtection`, DPAPI) | `Authority/AuthorityLock.cs` |
| Sensitive administrator operations (`AdminAuthorizer`, `VerifiedAdmin`) and the authority settings | `Authority/AdminAuthorization.cs`, `Authority/AuthorityStore.Settings.cs` |
| Admin web app (status, unlock, lock, unlock policy, read-only audit) and `with-secrets admin` | `Authority/AdminService.cs`, `Authority/AdminAppCommand.cs`, `HostService.cs` |
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
| First setup and registration pages | `SettingsPage.cs`, `PasskeyRegistration.cs` |
| Settings and limits | `ToolSettings.cs`, `ApprovalSettings.cs` |
| Enroll, unenroll, names | `Enrollment.cs`, `EnrollmentTarget.cs` |
| `--set`, `--remove` | `SecretEntry.cs` |
| Secret rows, hashes, decrypt only requested | `SecretStore.cs` |
| Slots, vault, recovery slot | `KeyVault.cs`, `RecoveryCode.cs` |
| Signed manifest | `Manifest.cs` |
| SQLite, schema 9, gate, integrity | `StateDatabase.cs` |
| Rotate keys, recover | `KeyRotation.cs`, `StoreRecovery.cs` |
| Revoke | `Revocation.cs` |
| Audit log, hash chain, `--audit` | `AuditLog.cs` |
| Terminal prompt (lines are written at once; nothing is held or dropped) | `TerminalPrompt.cs` |
| Logging: Serilog setup, file rules, `--debug` terminal sink | `AppLog.cs` |
| Saved approvals (inactive with this store) | `Reuse.cs` |
| Tests | `tests/WithSecrets.Tests`, browser tests `tests/WithSecrets.E2E` |

## Remaining implementation checks and maintainer choices

These are not unresolved questions about the accepted Section 10.2 architecture. They are current-prototype validation or product-maintenance items.

1. **Cross-host `--enroll` browser test:** the server-side flow is implemented and traced in `Enrollment.cs` and `PasskeyRegistration.cs`, but the real cross-host HTTPS flow still needs a manual browser test. The existing E2E test cannot complete it because its test server has no HTTPS host.
2. **PRF output cleanup:** page scripts currently do not overwrite the browser-side PRF `Uint8Array` after sealing. Calling `fill(0)` after successful sealing may reduce its lifetime, but cannot erase browser/WebAuthn or other copies. Decide whether to add this best-effort cleanup as implementation hardening.
3. **`--revoke` command:** the current passkey-PRF store does not create or use saved approvals, but `--revoke` remains implemented and can clear any rows in the grants table. Decide whether to retain this dormant compatibility/admin command or remove it.

The README path spelling is already correct (`%USERPROFILE%\\.with-secrets\\state.db`); the previous note about missing backslashes was stale and has been removed.

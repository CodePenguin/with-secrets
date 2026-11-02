# with-secrets

An agent runs a program that needs secrets. A person approves each request on a web page with a passkey. The agent never sees a value.

```
with-secrets --secrets DB_URL,API_KEY --reason "run the migration" -- dotnet ef database update
```

## How approval works

1. The agent runs the command. The program checks the names against the store in `state.db` (and checks every stored ciphertext against its signed hash) and decrypts nothing.
2. It prints a **one-use link** to the terminal (stderr). The agent shows the link to you.
3. You open the link on any device that can reach it. The page shows the whole request: the program and the script as **full paths** (no `./`, no `..`), the secret names, the folder, and the agent's reason. The full path is also what runs, so what you approve is exactly what executes. If the program or script is a symbolic link, the page adds a `Link:` line that shows where it leads.
4. You read all of it, then press **Approve once** (or Ctrl+Enter, Cmd+Enter on a Mac), or pick a time in the **Approve for** list (10 minutes, 1 hour, 4 hours, 8 hours, up to the `reuseMaxMinutes` setting) and press **Approve for selected time** (the list starts on the `reuseMinutes` setting; when it is 0, no time is preselected). The approve controls stay off for a moment so they cannot be pressed by accident. Enter on the focused Deny button denies.
5. You prove it with a **passkey**. The passkey signs the request and the time you chose, so nothing can change the time afterwards. The program checks the proof itself, and accepts only a time the page offered. The page cannot approve anything alone.
6. If the proof is good, the program decrypts **only the named secrets** (with the Dotenvx crypto library), passes them to the program as environment variables, and redacts them from the output. Give a comma-separated list (`--secrets DB_URL,API_KEY`) to inject several secrets in one run. There is no `--all`: every name must be written out.
7. It writes an audit line (names, command, result, and a hash of any script file in the command; never values).

Deny, a wrong proof, an error, or no answer before the time limit all deny the run (exit code 3). The link works once.

## Install

Requires the .NET 10 SDK.

```
dotnet tool install -g WithSecrets
dotnet tool update -g WithSecrets
```

Not yet published to nuget.org. Until it is, pack it and install from a local feed: `dotnet pack src/WithSecrets -c Release -o <feed>`, then `dotnet tool install -g WithSecrets --add-source <feed>`.

## First-time setup

Do steps 1 and 2 in **your own terminal** (an ssh session or a separate window), never in the agent's.

1. `with-secrets --config`. Open the link, check the settings (the defaults are fine to start), give the passkey a name in **Name for this passkey** (for example `laptop`; empty means `passkey`), then press **Step 1 of 2: save and create passkey** and create the passkey. A second button then appears: press **Step 2 of 2: confirm with your new passkey** and confirm with it (the new passkey signs the settings and itself as the first **admin** key). Each passkey prompt has its own tap, because iOS refuses a second prompt in the same tap. Then type the code the page shows into the terminal (only a code shown on the page you opened yourself; if it shows none, press Ctrl+C). Nothing is saved until you do: the settings and the passkey are written together. The passkey works on the page's host, normally `localhost`. The first passkey is trusted on first use, so make sure you are the one at the keyboard. It is an admin key: only admin keys can change the settings, the passkeys and the secrets. Add more passkeys later with `with-secrets --enroll`; a new one only approves runs unless you tick **Also make this key an admin** on its page. **We recommend two admin keys** (for example your laptop and your phone), so that a lost device does not lock you out (see [Admin keys](#admin-keys)). When the setup is done, the page and the terminal show the admin keys' fingerprints, such as `Admins: laptop ab12 cd34 ef56 7890`. **Write them down** (outside this machine). Every page the tool serves shows them again; check them each time you approve (see [Admin keys](#admin-keys)).
2. `with-secrets --set DB_URL`. Open the link, type the value in the browser, and approve with your passkey. The terminal never sees the value. The first `--set` makes the store's key pair: its private key goes to **Windows Credential Manager** (as Dotenvx keeps it, target `dotenvx:<public key>`), its public key into the signed state. Nothing is asked in the terminal, and no key file is written. The secrets are stored in `%USERPROFILE%\.with-secrets\state.db` (see [The secret store](#the-secret-store)).
3. Give the agent the run command (see above) and tell it which secret names it may use.

## Commands

| Command | What it does | Who |
| --- | --- | --- |
| `with-secrets --secrets A,B --reason TEXT -- PROGRAM [ARGS...]` | Run a program with the named secrets after approval | Agent |
| `--list` | Print the secret names (never values); exit 4 when the store fails verification | Anyone |
| `--set NAME[,NAME...]` | Store secrets: you type the values on a web page and approve with an admin passkey | Person |
| `--remove NAME[,NAME...]` | Delete secrets after approval with an admin passkey on a web page (the passkey signs the new state without them) | Person |
| `--revoke` | Clear every saved approval now, after approval with an admin passkey on a web page. Best effort: it stops reuse by the tool, not by a same-user agent that kept a copy of a saved approval (see [Approval reuse](#approval-reuse)). Exit 4 if the saved approvals cannot be cleared (they may still be in force) | Person, in a terminal you own |
| `--config` | Change the settings on a web page, approved with an admin passkey. With nothing enrolled, it is the first-time setup and also creates the first passkey (named on the page), the first admin | Person, in a terminal you own |
| `--config --show` | Print the settings and their values (none is secret) | Anyone |
| `--enroll [--local]` | Add a passkey on a web page. You type its name there (**Name for this passkey**: unique without regard to case, at most 40 characters, no control or hidden characters; the page suggests a free one) and choose **Also make this key an admin** (off by default: the key then only approves runs). An admin passkey approves first, then signs the change, which holds the name and the choice: on the same page, with a second button (**Step 2 of 2: confirm with your admin passkey**) when an admin passkey works there, else on a third page after the code, whose text says `New key: NAME` and whether it will be an admin | Person, in a terminal you own |
| `--enrolled` | Print the admin keys' fingerprints (first line), then the passkeys that can approve (name, host, date, and `admin` for each admin key) | Person, in a terminal you own |
| `--unenroll NAME [--local]` | Remove a passkey, approved with an admin passkey. Any key can be removed, an admin key too, except the last admin key. An admin key cannot approve its own removal: another admin key does | Person, in a terminal you own |
| `--audit [--last N] [--secret NAME] [--verify]` | Print the admin keys' fingerprints (first line), then the newest audit entries (default 20, N from 1 to 1000), one per line: time, event, secret names, program, outcome, key name. Never values. `--verify` checks the hash chain and names the first broken entry (exit 4) | Anyone (read-only) |

`--local` uses the page at `http://localhost:<port>` and ignores `baseUrl`. A run picks the page by itself: the first of the `baseUrl` page and the localhost page where an enrolled passkey works. `--set`, `--remove`, `--revoke`, `--config` and the approvals of `--enroll` and `--unenroll` do the same with the admin passkeys. `--config`, `--enroll`, `--enrolled`, `--unenroll` and `--revoke` refuse to run when input or output is redirected, as in an agent's shell.

## State and audit

Passkeys, saved approvals, the audit log and the settings are kept in `%USERPROFILE%\.with-secrets\state.db`, a SQLite database (WAL mode). The passkeys and the settings are one signed manifest (canonical JSON with a version that goes up with each change), signed by an admin passkey over `SHA-256(bind || SHA-256(manifest))`. The key that signed must be an admin key in that manifest. Every command verifies it first; if it fails (the file was edited outside the tool, a key or setting added, a signature swapped), every command stops with exit 4, `state failed verification: delete state.db to start over (only if you did not edit it)`, and nothing runs. Sign counts are kept beside it, outside the signature. A change is written only if the manifest is still the version the page started from, and only when it is signed by a key that is an admin key in the stored manifest (not one that the new manifest makes an admin) and stays one. **Verification only catches edits that keep your admin keys.** An agent that can write `state.db` can still delete it and write a whole new state signed by its own software key, with no page and no terminal. That state has other admin keys, so it shows **other fingerprints** on every page, in `--enrolled` and in `--audit` (see [Admin keys](#admin-keys)). Each saved approval keeps the passkey assertion that approved it and is checked again every time it is used (see [Approval reuse](#approval-reuse)). Every write is one transaction, so two runs at once cannot lose an update; a run waits up to 5 seconds for another one to finish writing. The database holds names and Dotenvx ciphertext, never secret values in plain text. A missing database is empty (nothing enrolled). A database that cannot be read, is damaged (checked with `PRAGMA integrity_check` at open), or stays locked longer than 5 seconds stops the command with exit 4; nothing is asked and nothing runs. If the audit entry cannot be written, nothing runs (exit 5).

The audit log records runs (`approved`, `denied`, `reused`, `finished`), changes (`secrets-set`, `secrets-removed`, `settings-changed`, `settings-setup`, `key-enrolled`, `key-removed`, `approvals-revoked`, each with the approving admin key; `key-enrolled` also says whether the new key is an admin; `approvals-revoked` says how many were cleared) and refused or failed changes (`change-denied`, with the command, the secret names and why). It holds names, never values. A change to `state.db` and its audit entry are written in one transaction; for `--set` and `--remove` that transaction also holds the secret rows and the new signed manifest. A refused change is recorded only when `state.db` already exists.

Each audit entry carries the SHA-256 hash of the entry before it. `with-secrets --audit --verify` reports the first entry whose link does not hold. This finds an edited or deleted entry, but not entries removed from the end.

The schema version is 7 (the signed manifest, with any number of admin keys, holds the passkeys, the settings, the store's public key and the hash of every secret; the `secrets` table holds one Dotenvx ciphertext per secret; each saved approval holds its signed approval). A database of another schema version (an older or newer one) is never moved forward: the command stops with exit 4 and says to delete `state.db` to start over. There is no import from the `.env.local` file of earlier versions. The program reads no other file in the store folder.

### The secret store

- **Rows.** Each secret is one row of the `secrets` table in `state.db`: its name and its value encrypted by Dotenvx (the `encrypted:` format, ECIES on secp256k1). Dotenvx is the crypto library here, not the file store: there is no `.env.local` and no `.env.keys`.
- **Signed hashes.** Anyone with the public key can make a valid ciphertext, so a row alone proves nothing. The signed manifest therefore holds the store's public key and, for every secret, the SHA-256 of its ciphertext. Every read (`--list`, a run, `--set`, `--remove`) checks every row against its hash first. A row whose ciphertext is not the signed one (another valid ciphertext, or another row's), a row without a hash and a hash without a row all stop the command with exit 4 (`the secret store failed verification`), before anything is asked or decrypted. A changed hash or store key in the manifest fails the manifest's own signature, so every command stops.
- **One tap for `--set`.** As you type, the page sends the encrypted values to the program, which checks them, encrypts each to the store key and answers with the next manifest (names and hashes, nothing secret). Your Save tap then signs `SHA-256(bind || SHA-256(ct) || SHA-256(manifest))` once: it covers both the values the page sent and the hashes of the rows the program will write. The rows, the new manifest and the audit entry are one transaction that is written only if the state is still the version the page started from.
- **`--remove`** asks you to sign the next manifest, without the removed hashes; the rows go in the same transaction.
- **Only the requested rows are decrypted**, with the private key passed as a parameter (never an environment variable or a file). A run with `--secrets A` decrypts `A` and no other secret.
- **The private key** is in Windows Credential Manager, as Dotenvx keeps it (target `dotenvx:<public key>`), and is read through Dotenvx's native provider. It is saved there only when the first `--set` is approved, just before the write; if that write then fails, the key this `--set` added is removed again (a key that was already there is never touched), and a cancelled first `--set` saves none. If the removal itself fails, the result says so.
- **Windows only, for now.** The secrets need Windows (Credential Manager keeps the store key) until the store key is wrapped by passkey PRF key slots (planned as Task 18). Elsewhere a first `--set` stops with exit 4 before any page opens: the key custody is Windows-only for now.
- **Memory.** Decrypted values are kept as bytes and zeroed when the program ends. Some copies cannot be wiped: the string Dotenvx's decrypt returns, the strings the redactor and the child's environment need, the child's environment block itself, and the private key (a .NET string). .NET strings stay in memory until the garbage collector reuses it.

## Admin keys

Any number of passkeys can be **admin keys**; at least one always is. The first passkey (from the first-time setup) is an admin key. A passkey added with `--enroll` becomes one only when you tick **Also make this key an admin** on its page; that choice is part of the new state the approving admin key signs, and the page says it. Only admin keys can change the settings, the passkeys and the secrets, and `--revoke`; every passkey can approve runs. Each page that changes the state offers all admin keys that work at its host.

- **Use two admin keys**, for example your laptop and your phone. Then a lost or broken device is no emergency: the other admin key removes it with `with-secrets --unenroll NAME`.
- **To replace an admin key** (a new device): `with-secrets --enroll` with the new key, tick **Also make this key an admin**, then `with-secrets --unenroll OLD-NAME`, approved with the new key (an admin key cannot approve its own removal).
- **The last admin key cannot be removed.** With a single admin key and that device lost, nothing can change the state any more: delete `state.db` and run `with-secrets --config` again (your passkeys, settings and secrets start over: the secrets are in `state.db` too, so store them again with `--set`).

### The fingerprints

An admin key's fingerprint is the first 8 bytes of SHA-256 of its public key (as stored in the manifest), written as four groups of four hex digits. Every admin key is listed, oldest first: `Admins: laptop ab12 cd34 ef56 7890, phone 1234 5678 9abc def0`. It is not secret. The line is shown:

- on every page the tool serves: run approvals, `--enroll`, `--unenroll`, `--set`, `--remove`, `--revoke` and `--config` (on an approval page it is part of the text your passkey signs);
- as the first line of `--enrolled` and of `--audit`;
- once when the first-time setup finishes, and when `--enroll` shows its code, on the page and in the terminal.

Note the fingerprints down when you first see them, and check the line on each page before you approve. **If it ever changes without you adding or removing an admin key, the state was replaced**: someone deleted `state.db` and set up their own admin key, or an admin key was added that you did not add. Do not approve anything; find out what happened, then delete `state.db` and set up again with `with-secrets --config`. The fingerprints do not stop a same-user agent from resetting the database; they make the reset visible to you. Restoring an older copy of `state.db` (with your own admin keys) is not detected: it can bring back passkeys you removed (an admin key you removed too) and settings you changed, saved approvals that have not yet ended, and old secret values, including one you replaced after it leaked (so rotate a leaked value at its source, not only here). `--revoke` is not a recall: it clears the saved approvals on a best-effort basis, it does not take back a secret a program already saw, and an agent that kept a copy of a saved approval can put it back until it ends. Keep reuse times short, and rotate any value that may have leaked.

## Where the page can be reached

By default the page is at `http://localhost:<port>` on the machine that runs the program, with a free port picked each time. When that machine is remote, forward the port with ssh and open the link on your own computer:

```
ssh -L PORT:localhost:PORT user@host
```

Set `port` with `with-secrets --config` to a fixed number so the forward can be set up once. To use an HTTPS name (a Cloudflare or Tailscale name, for example), set `baseUrl` and `port`, and point that name at the port. Browsers allow passkeys only on `https` or `localhost`, so plain `http` to another name does not work. A passkey is tied to the host name it was created for. Changing `baseUrl` removes no passkey: a passkey made for `localhost` keeps working on the localhost page (a run picks it by itself, see `--local` above). Add a passkey for the new name with `with-secrets --enroll` (it is approved with a passkey you already have).

## Settings

The settings are kept in `state.db` in the protected folder, not in an environment variable or flag, because the agent controls those. They change only on the `--config` page:

- `with-secrets --config` prints only a one-use link. The page shows every setting with its current value and its limits as a form, and a summary of your changes. **Save** is approved with your admin passkey, which signs exactly the new state: the challenge is `SHA-256(bind || SHA-256(manifest))`, the manifest being the current one with the new values and the next version. The program checks the passkey, then checks every value, then writes the new manifest and an audit entry (the names of the settings that changed, old -> new, and the key; none of the settings is secret) in one transaction. Cancel, a wrong passkey, a value out of its limits or the time limit saves nothing.
- With nothing enrolled, the same page is the first-time setup (see above). There is no way to save settings without a passkey.
- `with-secrets --config --show` prints the current values. It works anywhere.

With nothing enrolled every setting has its default. A manifest with a value that cannot be used never verifies, so it stops every command with exit 4.

| Setting | Default | Meaning and limits |
| --- | --- | --- |
| `reuseMinutes` | `10` | The time the **Approve for** list starts on: the longest offered time at or below it. 0 to `reuseMaxMinutes`. 0 starts with no time chosen (the list still works) |
| `reuseMaxMinutes` | `480` | The ceiling: the longest time one approval may cover. 10 to 1440. Longer times are not offered, and a saved approval longer than the current ceiling is not used |
| `method` | `passkey` | How approval is proved. Only `passkey` exists |
| `baseUrl` | none | The address of the page, such as `https://secrets.example.net`. Empty for none. A full `http` or `https` address, no user name or password, at most 2048 characters |
| `port` | `0` | The port the page listens on. 0 picks a free one. 0 to 65535 |
| `timeoutMinutes` | `5` | How long the program waits for an answer on a page. 1 to 30 |

## Approval reuse

You choose on the approval page, each time, whether an approval is reused. **Approve once** runs the program once and saves nothing. **Approve for selected time** saves the approval for that time, so a test loop does not prompt every run: it covers the **same secret names, program, script, and folder** until it ends.

- **The time is signed.** The passkey signs `SHA-256(bind || "reuse=" || minutes)` (0 for once). The program refuses a time the page did not offer or above `reuseMaxMinutes`, and saves exactly the signed time.
- **A saved approval is signed, and checked at every use.** It keeps the passkey assertion, the page nonce and the exact text you approved, which names the request (`Request id: ...`) and the time the page was made (`Page issued: ...`). Each time it would be used, the program checks: the key is in the verified manifest; the assertion verifies over `SHA-256(bind || "reuse=" || minutes)` with `bind = SHA-256(nonce + "\n" + text)`; the text names this request; the minutes are 1 to 1440; it was saved no earlier than the page was made and at most 30 minutes after; it ends exactly that many minutes after it was saved. A saved approval that fails is not used, the agent's run prints `a saved approval failed verification and was ignored`, and you are asked again (the run is not refused). Sign counts are not checked again. An expired one, or one longer than the current ceiling, is simply not used.
- **A longer approval means the agent can run the same command again, without asking you, until it ends**, with other arguments. Choose the shortest time that does the job; use **Approve once** for anything you would not run again unseen.

- **What is matched:** the secret names, the full path of the program, the working folder, and the full path and hash of the script being executed. Two programs with the same name in different folders are approved one by one, even when their bytes are identical. The script is the program itself (`./check.sh`). When an interpreter runs it, the script is the **first argument that names an existing file up to 1 MB** (`pwsh -File run.ps1`, `node app.js`, `sh check.sh`).
- **Not matched:** flags, other arguments, later files (a data file, for example), and the agent's reason.
- **The clock starts at approval and never extends.** Running the command again does not renew it.
- **A changed script asks again.** A script edited while the page is open is not run.
- **A denial is never remembered.**
- **Clear all approvals now:** `with-secrets --revoke`. This is best effort, not a security boundary: it stops reuse by the tool and by an agent that plays fair, but a same-user agent that copied a saved approval row before `--revoke` can put it back afterwards, and it still verifies until it ends (its signature is still good). Keep reuse times short. A secret a program already saw is not recalled; rotate a value that may have leaked.
- **The start can be moved later, within limits.** The program records when an approval was saved, and only the page time is signed. An agent that edits `state.db` can move the start of a saved approval later, up to 30 minutes after the page was made (less the time you took to approve). So a saved approval can last at most until the page time + 30 minutes + the time you chose, never longer.
- **Removing a passkey ends its saved approvals.** `--unenroll` deletes them in the same change.
- **A lower ceiling applies at once.** A saved approval longer than the current `reuseMaxMinutes` is not used.
- The audit entry records the time you chose (`approved once` or `approved for N min`) and the approving key; a reused approval records the key that approved it.

## Rules

- **Terminal output is public.** The agent reads it. Nothing the program prints is secret: it shows links, names, and results, never values or key bytes.
- Run `--config`, `--enroll`, `--unenroll` and `--revoke` only in a terminal you own. Values are typed in the browser, never in a terminal. The confirmation code of a new passkey is shown only on the page and typed by you in that terminal.
- **Only type a confirmation code that a page you opened yourself shows.** If the page has already ended or shows no code, press Ctrl+C. (An agent that holds the link could register its own key and pass you its code.)

## Parts

| Path | What it is |
| --- | --- |
| `src/WithSecrets.Core` | Logic: command line (System.CommandLine), policy, approval text, redaction, child process, audit log, the web approval page (Kestrel), passkey checks, enrollment |
| `src/WithSecrets` | The `with-secrets` exe: the store key custody (Windows Credential Manager), wiring of `--set`, `--remove`, `--enroll` and the rest |
| `tests/WithSecrets.Tests` | Console test runner (no test framework package). `dotnet run --project tests/WithSecrets.Tests` |

## Build

```
dotnet build with-secrets.slnx
```

It needs .NET 10 and the NuGet packages `Dotenvx.Primitives` (3.3.1), `Dotenvx.Providers` (0.3.11), `Microsoft.Data.Sqlite` (10.0.14) and `SQLitePCLRaw.bundle_e_sqlite3` (2.1.14, which carries its own native SQLite build).

## Checks

| Check | Status |
| --- | --- |
| Per-approval reuse: the page controls (Approve once, the times up to the ceiling, the starting entry, reuse off), the challenge for once and for a time differ, a signature for one time is refused for another, times not offered or above the ceiling and malformed bodies deny, a grant lasts exactly the signed time, once saves nothing, an expired grant or one longer than the current ceiling is not used, the audit entry records the time | **Tested** in code (the `reuse` checks, through `RunCommand`, `WebApprover` and `PasskeyMethod` over real HTTP). The page script (the select, Ctrl+Enter, the challenge hash in the browser) is **not tested** in a browser |
| Core logic: reuse (fingerprint, expiry, changed script, denial, settings), redaction (forms, chunk splits), policy, approval text, command line, program lookup, audit, exit codes | **Tested.** All checks pass (`dotnet run --project tests/WithSecrets.Tests`) |
| Web approval, server side, with a test authenticator that signs like a passkey: the one-use page and its headers, deny, time limit, a wrong proof (assertion checks: signature, origin, challenge, sign count), enroll and unenroll, `--set` and `--remove` (the encryption is checked in code, not in a browser) | **Tested** in code (the web approval, passkey, enrollment and secret entry test groups) |
| A run through the real chain: `RunCommand`, `WebApprover`, `PasskeyMethod`, a passkey store, an audit log (both SQLite) and a real child process, over real HTTP. Approve (exit 0, output redacted, audit names the key), Deny on the page (exit 3, child never ran), nothing enrolled (exit 3, names `--config`, no link) | **Tested** in code (the `run chain` checks) |
| The signed manifest: canonical text and round trip; each edit fails verification (exit 4, no run, no saved approval used): edited text, settings or signature, a manifest signed by another key, a key flipped to admin, zero admins, a manifest signed by a key in it that is not an admin, a table or sign count added by hand, the manifest deleted while keys or approvals exist; a stale version is refused; sign counts only go up; parallel writers lose nothing; only admin keys can `--config`, `--enroll`, `--unenroll`, `--set`, `--remove` and `--revoke`; a second admin key can do all of it, including removing the first; a key that is an admin only in the new manifest cannot sign it; the last admin key cannot be removed; the **Also make this key an admin** box (ticked: an admin in the signed manifest and in the fingerprint line; not ticked: not), also on the three-link `--enroll`; the name chosen on the page (a name in use in any case, too long or with bad characters is refused and adds nothing; empty is the suggestion); a key that is not an admin approves runs | **Tested** in code (the `manifest` checks and the admin checks in the other groups). The second passkey prompt of the first run and of `--enroll` is **not tested** in a browser |
| Signed saved approvals and the fingerprint: a good grant is reused without a page; each of these is ignored, reported once, and the run asks again and works: no or an invalid assertion, a key not in the manifest, a signature for once with the minutes edited, minutes or the end edited, the start moved past the page time, the text or nonce edited, the request id moved to another request, the credential swapped to another enrolled key; an expired grant or one over a lowered ceiling is not used; the fingerprint is the 4x4 hex form, every admin key is listed, it changes with the admin keys, and it is on every page type and the first line of `--enrolled` and `--audit` | **Tested** in code (the `grant` and `fingerprint` checks, through `RunCommand`, `WebApprover` and `PasskeyMethod` over real HTTP). The fingerprint in the page scripts' final messages is **not tested** in a browser |
| `state.db`: round trips of passkeys, saved approvals and audit entries; two writers at once (no lost update); a garbage or damaged file and a lock past the timeout are errors, not an empty store; a database of another schema version is an error; the hash chain finds an edited or deleted entry; `--audit` output has names and never a value | **Tested** in code (the `db`, `chain` and `audit output` checks). `--audit` on an empty store in the installed tool was **tested by hand** |
| Settings and `--config`: the limits of every setting, the round trip through the signed manifest, an edited setting (the state fails verification, so every command stops with exit 4, `--config --show` too), a save signed by an admin passkey (a key that is not an admin is refused), refusals that save nothing (an assertion over other values or another page, a value changed after the assertion, a value out of its limits, a key that is not enrolled, cancel, the time limit, settings changed meanwhile), a second POST is 404, the first-run setup (settings and key stored together only after the code; nothing in `state.db` before it; three wrong codes or no code store nothing), the audit entry, `--config --show` | **Tested** in code (the `settings`, `db settings`, `db schema`, `config` and `config first run` checks). The page script (the form, the summary, the canonical JSON) is **not tested** in a browser; its canonical JSON was compared with the program's by hand in Node |
| Command line: the parsing of every option (`--list`, `--set`, `--remove`, `--revoke`, `--enroll`, `--local`, `--enrolled`, `--unenroll`, `--audit`, `--last`, `--secret`, `--verify`, a run), bad options (also `--name`, which no longer exists) and two commands at once, and that `--help` lists the options | **Tested** in code (the `cli:` checks). The exit codes of `--help` and of an unknown secret in the real exe were **tested by hand** only |
| The secret store in `state.db`: round trips with the real Dotenvx crypto; only the requested rows are decrypted (counted); a row replaced by another valid ciphertext made with the public key, a row swapped with another, a row without a hash, a hash without a row, a hash or the store key edited in the manifest: exit 4, nothing asked or decrypted (also when the row is swapped while the approval page is open); `--set` of a new and an existing name; `--remove` re-signs; a stale version, rows that do not match the signed hashes, or a failure inside the transaction write nothing (no row, no manifest, no audit entry); the audit has names only; the zeroing of decrypted bytes | **Tested** in code (the `store` and `secrets` checks) |
| The passkey flow in a real browser (create and use a passkey) and on a phone, over `ssh -L` and over an HTTPS name | **Not tested.** Must be tried by hand |
| Safari and iOS (WebKit, also Chrome on iOS) refuse a passkey prompt that does not start in its own tap. Every page now starts each prompt synchronously in a click (or Ctrl+Enter) handler, with the challenge made before the tap: the approval page makes the challenges for Approve once and every offered time before its buttons turn on; the settings and `--set` pages make theirs as the form changes (the `--set` page after the program answered its values with the next manifest); the first-run `--config` and `--enroll` pages have a separate **Step 2 of 2** button for the second prompt | A text check of the served scripts is **tested** in code (the `tap rule` and `step 2` checks: every `credentials.get(`/`create(` is in a click or keydown handler or a function only called from one, with no `await` before it). The pages on an iPhone are **not tested**: hand test on Safari (macOS) and on an iPhone (Safari and Chrome): the first run in two taps, `--enroll` in two taps, a run approval, and **Approve for** with a time chosen |
| `--enroll` with three links: when `baseUrl`'s host differs from the admin keys' hosts, the approval page (where an admin key works), then the enrollment page at the new host (name and admin box), then, after the code, a third page where an admin key signs the new state | **Not tested** in a browser (the server side is tested). Hand test |
| The first-run `--config` in two taps (Step 1 creates the passkey; Step 2 confirms with the new passkey) | **Not tested** in a browser. Hand test |
| The store key kept in Windows Credential Manager (written by the tool's own CredWriteW call, read back through Dotenvx's native provider), and a run that reads it | **Not tested** (the tests use an in-memory key custody). Hand test: the first `--set`, then a run, then `cmdkey /list` shows `dotenvx:<public key>` |
| The page scripts (buttons, the Approve delay, messages, encryption of `--set` values in the browser) | **Not tested** in a browser. Only the server side is tested. Check by hand |
| `.cmd` and `.bat` programs | **Tested.** A quote in an argument ran another command through `cmd.exe`; such arguments are now refused (see Known limits). `npm` resolves to `npm.CMD` |

## Known limits

- **The page shows the command line, not the contents of a script.** An agent can write a script that prints `$DB_URL` in a form that is not redacted. Approve only commands you recognize.
- **Redaction does not catch** reversed, split, compressed, or encrypted copies.
- **A program that sends its environment over the network is out of scope.**
- **No length limit on the command** except a technical one of 16,000 characters. The program refuses a longer command instead of cutting it short.
- **Only file symbolic links are shown.** A link in a parent folder (a junction, for example) is not.
- **A script can load other files.** Only the program and the first file argument are hashed. A second script or module that the first one loads is not.
- **Same OS user.** An agent that runs as you can write `state.db` in the store folder and read the store's private key from Credential Manager (so it can decrypt every secret). An edit to your passkeys, settings or secret rows fails verification and stops everything, and an edited or forged saved approval is ignored. But the agent can still delete `state.db` and write a whole new state signed by its own software key, with no page and no terminal; that key then approves its runs. The admin keys' fingerprints make that visible to you: they change on every page and in `--enrolled` and `--audit`. The agent can also restore an older copy (accepted, see [Admin keys](#admin-keys)), put back a saved approval it copied before `--revoke` (it works until it ends, so `--revoke` is not a boundary against it), move a saved approval's start up to 30 minutes past its page time, or rewrite the audit log (and recompute the hash chain). The hook and file permissions must protect that folder, like the store itself.
- **Sign counts are not signed.** They sit outside the manifest signature. An agent can set the admin keys' counts very high, and then every admin assertion fails ("sign count did not increase"), which also blocks `--revoke`. This is denial of service only: deleting `state.db` does the same.
- **The first passkey is trust on first use.** Whoever finishes the first `--config` becomes the first admin. Do it yourself, in your own terminal.
- **An agent that owns your terminal** can read the link and the confirmation code. Use a terminal the agent cannot read.
- **Plain `http` is not accepted for passkeys** except on localhost. Use `https` for any other name.
- **`.cmd` and `.bat` programs** run through `cmd.exe`, which reads quotes and `& | < > ^ % !` in arguments as commands. Arguments that contain them are refused.
- **Output is read as UTF-8.** Binary output and output in another code page (the console's OEM page, UTF-16) are garbled, and UTF-16 copies of a secret are not redacted.

## References

- [Agent Secret](https://kovyrin.net/2026/06/04/agent-secret/) (Kovyrin, 2026-06-04). Where several of the ideas come from: the approval request shows the command, the folder, the secrets, and the agent's reason, and an approval can be reused for a limited time. It is macOS only and uses 1Password; this project applies those ideas with Dotenvx and passkeys.
- [dotenvx](https://dotenvx.com/): its encryption format (and its Credential Manager key entry) is what the store uses.
- [dotnet-dotenvx](https://github.com/CodePenguin/dotnet-dotenvx) is the .NET port (`Dotenvx.Primitives` and `Dotenvx.Providers`) that this project calls, and the source of the command-line style.

## License

BSD 3-Clause. See `LICENSE`. The released exe contains third-party components, listed with their licenses in `THIRD-PARTY-NOTICES.md`. Ship that file with the exe.

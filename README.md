# Arcana Guardian

[![ci](https://github.com/CodePenguin/arcana-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/CodePenguin/arcana-guardian/actions/workflows/ci.yml)

*Trusted execution. Protected secrets.*

Arcana: secrets, mysteries, or knowledge known only to a select few.

Arcana Guardian is an open-source, self-hosted secrets broker that gives humans explicit control over when agents, applications and commands can access sensitive information across machines and secret providers.

The agent runs a command and names the secrets it wants. A person reads the exact request on a web page and approves it with a passkey. Only then does `using-secrets` decrypt those secrets, put them in the program's environment and start it. The agent sees the program's output with the values redacted, and never sees a value, a key or a password.

```
using-secrets --secrets PGDATABASE --reason "list tables in the staging database" -- psql -c '\dt'
```

> **Status: early (0.1.0), pre-release software.** Hand-tested on Windows. The unit suite and the single-file build run on Linux (including WSL); macOS builds in CI and runs the unit suite, but it has not been tried by hand and it takes no part in machine transport: it cannot be an authority or pair with one (a .NET 10 TLS 1.3 limit on macOS; see the reference). Local use works. Read [What it does not protect against](#what-it-does-not-protect-against) before you rely on it.

## How a run works

1. The agent runs `using-secrets --secrets NAME --reason "..." -- program args`. Nothing is decrypted yet.
2. The command prints a one-use link. The agent shows it to you.
3. You open the page. It shows the whole request: the full program path and arguments, the folder, the secret names, the agent's reason, and the full text of every script or inline command the program will read. Warnings appear for things that change which code runs or where data goes.
4. You approve with an enrolled passkey that signs the exact request you reviewed. An admin passkey with PRF unlocks the authority after startup. Once unlocked, a convenience passkey can approve runs without PRF.
5. The program decrypts only the named secrets, starts the child with them as environment variables, redacts them from the output, and writes a signed audit entry (names and a hash, never values).

Deny, a wrong proof, an error or no answer before the time limit all end the run with exit code 3, and nothing is decrypted.

## What you get

- **Secrets the agent cannot read.** Values are typed in the admin web app, sealed with [JSON Web Encryption](https://www.rfc-editor.org/rfc/rfc7516.html), and stored in a SQLite database. The key that opens them is wrapped by your passkeys and is never kept on disk.
- **Approval of the exact command.** What you approve is what runs: the page shows the script's contents and hash, and the program runs a private snapshot of that file (on Linux and macOS) or holds it against changes (on Windows).
- **A small, strict command grammar.** Interpreters are allowed in one reviewable form (`sh script.sh`, `python -c CODE`, `pwsh -NoProfile -File x.ps1`); forms that load unshown code are refused, and variables that change which code loads are removed from the child's environment.
- **Pre-approvals.** A grant lets one exact command run again for a chosen time without another page.
- **An admin web app** for secrets, passkeys, machines, grants and a searchable, signed audit history, served by the program itself.
- **Machines.** One machine can be the authority for others over mutual TLS.

## Install

You need an admin passkey with WebAuthn PRF for setup and unlock. You can then enroll a convenience passkey for approvals, grant changes, and adding or replacing secret values. The Secrets page saves up to 20 values with one tap.

**From a release.** Download the asset for your platform from the [releases page](https://github.com/CodePenguin/arcana-guardian/releases) and verify it against `SHA256SUMS`.

| Platform | Desktop companion and CLI | CLI only |
| --- | --- | --- |
| Windows x64 | `arcana-guardian-desktop-win-x64.zip` | `using-secrets-win-x64.exe` |
| Linux x64 | `arcana-guardian-desktop-linux-x64.tar.gz` | `using-secrets-linux-x64.tar.gz` |
| macOS Apple silicon | `arcana-guardian-desktop-osx-arm64.tar.gz` | `using-secrets-osx-arm64.tar.gz` |

Extract the entire desktop bundle and keep its contents together. Open `arcana-guardian-desktop.exe` on Windows, run `./arcana-guardian-desktop` on Linux, or open `Arcana Guardian.app` on macOS. The macOS app is ad hoc signed. The CLI includes the admin web app and can also run on its own.

**From source.** You need the .NET 10 SDK and Node.js 22 or newer.

```
git clone https://github.com/CodePenguin/arcana-guardian.git arcana-guardian
cd arcana-guardian
pwsh scripts/publish.ps1        # builds and verifies artifacts/publish/<platform>/
```

It is not on NuGet yet.

## First run

Do these in your own terminal, never in the agent's.

1. **Open Quick Start.** Run `using-secrets admin`. It starts the local service in the background and prints the setup link and this device’s fingerprint.
2. **Verify device.** Type the code from the page in your terminal, compare the full fingerprint on both screens, then choose **Fingerprint matches. Continue**.
3. **Create passkey and finish setup.** Name and create the passkey. Choose **Confirm setup and unlock** to trust the device and sign in. Save the recovery code from the **Finish setup** screen.

Finish setup includes an optional example of how a command requests a secret. Select **Open Arcana Guardian** to go to Overview. To start using Arcana Guardian from an agent, see [Using Arcana Guardian safely from an agent](docs/agent-usage.md).

The full walk-through, with backup, recovery, Docker, WSL and every exit code, is in the [operations guide](docs/operations.md).

## Using it

```
using-secrets --needs                                   # what this project would ask for (names only, no approval)
using-secrets --secrets DB_URL --reason "migrate" -- sh ./scripts/migrate.sh
using-secrets --reason "deploy" -- ./deploy.sh          # secrets declared in the project's .env
using-secrets approve --secrets DB_URL --reason "nightly" -- sh ./report.sh   # make a grant; nothing runs
```

A project can declare what it needs in its `.env`, so the agent does not list names:

```
LOG_LEVEL=info
STRIPE_KEY=secret://team/payments/STRIPE_PRODUCTION_KEY
GITHUB_TOKEN=secret://GITHUB_TOKEN
```

The program receives `STRIPE_KEY` and `GITHUB_TOKEN` as environment variables, and `LOG_LEVEL` as an ordinary value. A requesting client configured with the dotenvx executable can also resolve dotenvx `encrypted:` values. Details: [Project `.env` declarations](docs/reference.md#project-env-declarations).

| Command | What it does |
| --- | --- |
| `using-secrets [--secrets A,B] --reason TEXT -- PROGRAM [ARGS]` | Run a program with the named secrets, after approval |
| `using-secrets approve ...` | Same arguments; on approval make a grant instead of running |
| `using-secrets --needs` | Show what the project asks for; names only |
| `using-secrets admin` | First-time setup, then print the admin app's link |
| `using-secrets service` | Run the host service |
| `using-secrets pair` | Pair this machine with a remote authority |
| `using-secrets --recover` | Rebuild after every passkey is lost, with the recovery code |

Exit codes: `3` not approved, `4` the state failed verification, `5` the audit could not be written, `6` the service is not running, `7` the service is not this machine's, `8` the authority is locked, `9` the authority cannot be reached; anything else is the program's own code. A list is in [operations](docs/operations.md#exit-codes).

## What it protects against

- An agent that asks for a secret you did not expect: the page names every secret, and nothing is decrypted before you tap.
- An agent that changes a script or the `.env` after you read it: the bytes you saw are the bytes that run, and the request fingerprint covers the script, the arguments, the folder and the `.env` pairs.
- Secrets in the agent's context: terminal output is public by design, values and keys appear only in the browser, and the child's output is redacted.
- A stolen `arcana-guardian.db`: it holds ciphertext and a signed manifest, and the keys are wrapped by your passkeys. The approved command lines kept with each grant are encrypted too (to a separate review key), and every grant row is sealed by the authority key, so an edited or planted grant is never used.
- Tampered state: every command verifies the signed manifest and every ciphertext's hash first, and stops (exit 4) if anything was edited.

## What it does not protect against

- **A program that sends its secret somewhere.** The tool limits what the program is given, shows you what will run, and redacts the output. Your reading of the request is the control; write requests that are easy to read.
- **Code a script loads.** Approval covers the files shown. Files a script sources, imports or reads from beside itself are read as they are when it runs, and the page says so.
- **A process running as you.** Anything running as your user can read the program's memory and environment while a run is open, and can change files you own. On Linux and macOS the private copy of a script closes the swap-after-approval attack, not a same-user process that races the interpreter.
- **A look-alike page.** Passkeys ignore the port, so another local program serving a page on `localhost` can ask for the same tap. Check the link the terminal printed.
- **A weaker machine key off Windows.** On Windows the machine identity is a non-exportable key in the TPM or CNG; on Linux, WSL and macOS it is an owner-only file.

The full lists are in [Known limits](docs/reference.md#known-limits) and the [threat model](docs/architecture.md).

## Documentation

| Document | What is in it |
| --- | --- |
| [Using Arcana Guardian safely from an agent](docs/agent-usage.md) | Rules and Bash and PowerShell examples for an agent's author |
| [Operations guide](docs/operations.md) | Install, first run, machines, backup, recovery, Docker and WSL, troubleshooting, exit codes |
| [Reference](docs/reference.md) | Every behaviour in detail: approval, the store, `.env`, grants, the admin API, audit, mutual TLS, known limits |
| [Architecture](docs/architecture.md) | Design, trust boundaries and threat model |
| [Repository rename cutover](docs/repository-rename.md) | Exact substitutions for the final GitHub repository rename |
| [OpenAPI contract](docs/api/openapi.json) | The admin API |

## Development

```
dotnet build arcana-guardian.slnx                          # warnings are errors; also builds the admin web app (needs Node.js 22+)
dotnet run --project tests/ArcanaGuardian.Tests            # the .NET suite; ARCANA_GUARDIAN_ONLY=Name,Name runs groups
cd src/ArcanaGuardian.Admin.Web && npm run verify          # API client freshness, typecheck, lint, component and accessibility tests
pwsh scripts/publish.ps1                                # the single-file release for this platform, verified
pwsh scripts/verify-all.ps1                             # all of the above plus the browser tests
```

- **CI** (`.github/workflows/ci.yml`) builds and runs the .NET suite on Windows, Linux and macOS, runs the frontend checks, publishes and verifies the single file on each, and runs the browser tests on each.
- **Browser tests** (`tests/ArcanaGuardian.E2E`) drive the real pages in headless Chromium with a virtual passkey authenticator (including PRF). See [Browser tests](docs/reference.md#browser-tests).
- **Releases** are made by pushing a tag `vX.Y.Z` that equals `Version` in `Directory.Build.props`. The release workflow publishes standalone CLI assets and desktop bundles for all three platforms with checksums.

Layout: `src/ArcanaGuardian.Core` (logic, the approval page, the host and the authority), `src/ArcanaGuardian` (the executable), `src/ArcanaGuardian.Admin.Web` (the React admin app), `tests/`, `scripts/`, `docs/`.

## Credits

Several of the ideas come from [Agent Secret](https://kovyrin.net/2026/06/04/agent-secret/) (Kovyrin, 2026). The internal store uses [JWE](https://www.rfc-editor.org/rfc/rfc7516.html). Projects can optionally resolve encrypted .env values with the [dotenvx CLI](https://dotenvx.com/).

## License

BSD 3-Clause. See [LICENSE](LICENSE). The released program contains third-party components, listed with their licenses in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md); ship that file with it.

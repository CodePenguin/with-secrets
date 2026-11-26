# Using with-secrets safely from an agent

This page is for an agent's author and for the agent's instructions. The rules come from how the tool works: the program gets a secret as an **environment variable**, the person approves the **exact command**, and the output is redacted.

## The rules

1. **Never write a secret value anywhere.** Not in the command line, a script, an inline `-c` string, a `.env` file or the `--reason`. The agent is not given the values and has no need of them.
2. **Name secrets, do not pass them.** Use `--secrets NAME` or a `secret://NAME` reference in `.env`. The program reads the value from its environment.
3. **Keep the shell from expanding the variable.** The variable exists in the program's environment, not in the agent's shell. Use single quotes (Bash) so the shell leaves `$NAME` for the program, or let a script file read it.
4. **Put the logic in a script file** when it is more than a line. The person reads the whole file on the approval page; a long one-liner is harder to judge.
5. **Always give a `--reason`** that says what the run is for in a sentence a person can check against the command.
6. **Run `--needs` first** to see what the project asks for and whether each secret is in the store. It prints names only and starts nothing.
7. **Expect to wait.** The run blocks until the person approves. Deny, a wrong proof, no answer in time or an error ends it with a nonzero exit (3 for a refusal). Do not retry in a loop: each try is another request to the person.

## Bash

`--secrets` names the secret; the program reads `$DB_URL`. Single quotes keep your shell from expanding it:

```bash
with-secrets --secrets DB_URL --reason "list tables in the staging database" -- \
  sh -c 'psql "$DB_URL" -c "\dt"'
```

A script file, which the approval page shows in full:

```bash
with-secrets --secrets DB_URL --reason "run the nightly report" -- sh ./scripts/report.sh
# report.sh uses $DB_URL; it contains no value
```

A `.env` in the project with references, no `--secrets` needed:

```bash
# .env
DB_URL=secret://DB_URL
LOG_LEVEL=info
```

```bash
with-secrets --needs
with-secrets --reason "apply migrations" -- sh ./scripts/migrate.sh
```

## PowerShell

`pwsh` is allowed in one form: `-NoProfile`, then `-File` or `-Command`. Single quotes keep your own shell from expanding `$env:DB_URL`:

```powershell
with-secrets --secrets DB_URL --reason "list tables in the staging database" -- `
  pwsh -NoProfile -Command 'psql $env:DB_URL -c "\dt"'
```

```powershell
with-secrets --secrets DB_URL --reason "run the nightly report" -- `
  pwsh -NoProfile -File .\scripts\report.ps1
# report.ps1 uses $env:DB_URL; it contains no value
```

```powershell
with-secrets --needs
with-secrets --reason "apply migrations" -- pwsh -NoProfile -File .\scripts\migrate.ps1
```

## What not to do

| Do not | Why | Do instead |
| --- | --- | --- |
| `PGPASSWORD=hunter2 psql ...` | The value is in the command, on the approval page, and in your history. The page warns, and the audit masks it, but it has already left the store | `--secrets PGPASSWORD`, then `psql` reads it |
| `sshpass -p hunter2 ssh host` | Same, and `-p VALUE` shows in the process list | Use a key, or `--secrets SSHPASS` with `sshpass -e` |
| `curl -H "Authorization: Bearer abc..."` | The token is in the command | `--secrets API_TOKEN`, then `sh -c 'curl -H "Authorization: Bearer $API_TOKEN" ...'` |
| `echo $DB_URL` in your own shell | It is empty there, and the program's environment is where it lives | Let the program read it |
| Print the value to see it | The output is redacted, and a value you build or transform may not match the redaction | Do not print secrets |
| A plaintext `DB_PASSWORD=...` in `.env` | The page shows a warning, names only, but the file holds the value | `DB_PASSWORD=secret://DB_PASSWORD` |
| Retry a denied or timed-out run | Each try asks the person again | Report that the run was not approved |

## What the person sees

The whole command line, the inline code, every file read as code with its hash and contents (only those files: what a script sources, imports or reads from beside itself is not approved, and the page says so), the secret names and `.env` pairs, and warnings for what looks like a credential written in the command, a script or a plaintext `.env` value. A value that looks like a credential in an ordinary `.env` variable is shown as `[hidden]`; the approval still covers the real value.

## Choosing passkeys

Use an approval credential that requires an action the agent cannot perform. An unlocked software passkey manager in a browser the agent controls is risky. Consider a Windows Hello PIN or biometric, a hardware security key that requires your interaction, or a passkey on a separate phone. An authenticator's physical touch does not show what it is approving. Read the operation and command on the trusted page before providing the touch.

Once an admin unlocks the authority, a convenience key can approve any command the service accepts, including a grant with no end. Choose a credential whose approval requires something the agent cannot do or obtain. An unlocked software passkey manager is risky if the agent can drive it. Windows Hello with a PIN or biometric, a physical security key, or a phone you control can require your participation. Read the approval page before tapping. A touch confirms presence but does not tell you what you approved.

## Limits

The tool cannot stop a script from sending a secret somewhere. It limits what the program is given, shows the person what will run, and redacts the output, so the person's reading of the command is the control. Write commands that are easy to read.

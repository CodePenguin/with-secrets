# with-secrets

An agent runs a program that needs secrets. A person approves each request in a Windows Hello prompt. The agent never sees a value.

```
with-secrets --secrets DB_URL,API_KEY --reason "run the migration" -- dotnet ef database update
```

1. The program checks the names against the store. It reads the store file as text and decrypts nothing.
2. It opens an **approval window** (scrollable, shows everything), then a short **Windows Hello** confirmation. Both must approve. The window cannot be the only step, because a program in the same session could click it. The window text has the program and the script as **full paths** (no `./`, no `..`), the secret names, the folder, and the agent's reason. The full path is also what runs, so what you approve is exactly what executes. If the program or script is a symbolic link, the prompt adds a `Link:` line that shows where it leads.
3. If you approve, it decrypts the store with the Dotenvx library, passes **only the named secrets** to the program as environment variables, and redacts them from the output. Give a comma-separated list (`--secrets DB_URL,API_KEY`) to inject several secrets in one run. There is no `--all`: every name must be written out.
4. It writes an audit line (names, command, result, and a hash of any script file in the command; never values).

## Approval reuse

One approval covers the **same secret names, program, script, and folder** for a limited time, so a test loop does not prompt every run.

- **What is matched:** the secret names, the full path of the program, the working folder, and the full path and hash of the script being executed. Two programs with the same name in different folders are approved one by one, even when their bytes are identical. The script is the program itself (`./check.sh`). When an interpreter runs it, the script is the **first argument that names an existing file up to 1 MB** (`pwsh -File run.ps1`, `node app.js`, `sh check.sh`).
- **Not matched:** flags, other arguments, later files (a data file, for example), and the agent's reason.
- **The clock starts at approval and never extends.** Running the command again does not renew it.
- **A changed script asks again.** A script edited while the prompt is open is not run.
- **A denial is never remembered.**
- **Length:** `%USERPROFILE%\.with-secrets\settings.json` holds `{"reuseMinutes": 10}`. The default is 10, the maximum is 60, and 0 turns reuse off. A broken file turns reuse off. The setting is a file in the protected folder, not an environment variable or flag, because the agent controls those.
- **End all approvals now:** `with-secrets --revoke` (a person, in a terminal).
- The prompt tells you how long the approval is reused.

## Parts

| Path | What it is |
| --- | --- |
| `src/WithSecrets.Core` | Logic: command line (System.CommandLine), policy, approval text, redaction, child process, audit log |
| `src/WithSecrets` | The `with-secrets` exe: Dotenvx store, `--set` and `--remove`, wiring |
| `src/WithSecrets.Windows` | The approval window (WinForms) and the Windows Hello approver, both in-process |
| `tests/WithSecrets.Tests` | Console test runner (no test framework package). `dotnet run` |

## Build

```
dotnet publish src/WithSecrets -c Release -r win-x64 -o out
```

This makes one self-contained `with-secrets.exe` (about 140 MB, no .NET runtime and no PowerShell needed on the machine). It needs the `Dotenvx.Core` NuGet package (version 2.38.2 in the project file; change it to the version you publish).

## First use (a person, in a real terminal)

```
with-secrets --set DB_URL
```

On the first write, Dotenvx asks where to keep the private key. Choose **Windows Credential Manager**. No `.env.keys` file is written. The store is `%USERPROFILE%\.with-secrets\.env.local`.

## Checks

| Check | Status |
| --- | --- |
| Core logic: reuse (fingerprint, expiry, changed script, denial, settings), redaction (forms, chunk splits), policy, prompt text, command line, program lookup, approve/deny/refuse flows, audit, exit codes | **Tested.** All checks pass on Windows (`dotnet run --project tests/WithSecrets.Tests`) |
| Command line: `--help`, bad options, two commands at once, `--list`, `--set` without a terminal | **Tested** by hand on Windows with the Release exe |
| Real `Dotenvx.Core`: set, get, list, remove, wrong name | **Tested** in a temporary folder with no terminal. The key was written to `.env.keys` there |
| Key kept in Windows Credential Manager (`--set` in a real terminal, no `.env.keys`) | **Not tested.** |
| `.cmd` and `.bat` programs | **Tested.** A quote in an argument ran another command through `cmd.exe`; such arguments are now refused (see Known limits). `npm` resolves to `npm.CMD` |
| Approval window (WinForms, in the exe) | **Tested in code:** the tests open the real window and drive it. Approve is off at first and then on; Enter and Escape deny; a long command shows in full and scrolls; closing denies; the time limit denies. **Not tested:** how it looks and that it opens in front while you are working |
| Windows Hello prompt (in the exe) | **Not tested.** Hello is available on the development machine, and the code compiles against the documented API. It asks for a small owner window that it shows in front, so the prompt should not open behind other windows. Check that the prompt appears in front and shows both lines |

## Known limits

- **The prompt shows the command line, not the contents of a script.** An agent can write a script that prints `$DB_URL` in a form that is not redacted. Approve only commands you recognize.
- **Redaction does not catch** reversed, split, compressed, or encrypted copies.
- **A program that sends its environment over the network is out of scope.**
- **No length limit on the command** except a technical one of 16,000 characters. The program refuses a longer command instead of cutting it short.
- **Only file symbolic links are shown.** A link in a parent folder (a junction, for example) is not.
- **A script can load other files.** Only the program and the first file argument are hashed. A second script or module that the first one loads is not.
- **Reuse lives in a file** in the store folder (`grants.json`). An agent that can write there can forge an approval. The hook protects that folder, like the store itself.
- **Same OS user.** An agent that can edit the exe, the store folder, or the Hello setup can defeat this. The hook and file permissions cover that.
- **`.cmd` and `.bat` programs** run through `cmd.exe`, which reads quotes and `& | < > ^ % !` in arguments as commands. Arguments that contain them are refused.
- **Output is read as UTF-8.** Binary output and output in another code page (the console's OEM page, UTF-16) are garbled, and UTF-16 copies of a secret are not redacted.
- **Windows 10 (19041) or later only.** The exe is built for Windows. It needs nothing else installed: no .NET runtime and no PowerShell.

## References

- [Agent Secret](https://kovyrin.net/2026/06/04/agent-secret/) (Kovyrin, 2026-06-04). Where several of the ideas come from: the approval request shows the command, the folder, the secrets, and the agent's reason, and an approval can be reused for a limited time. It is macOS only and uses 1Password; this project applies those ideas on Windows with Dotenvx.
- [dotenvx](https://dotenvx.com/) stores the encrypted values and the keys.
- [dotnet-dotenvx](https://github.com/CodePenguin/dotnet-dotenvx) is the .NET port (`Dotenvx.Core`) that this project calls, and the source of the command-line style.
- [UserConsentVerifier](https://learn.microsoft.com/en-us/uwp/api/windows.security.credentials.ui.userconsentverifier) is the Windows Hello consent API used for the second approval.

## License

BSD 3-Clause. See `LICENSE`. The released exe contains third-party components, listed with their licenses in `THIRD-PARTY-NOTICES.md`. Ship that file with the exe.

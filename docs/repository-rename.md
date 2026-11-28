# Repository rename cutover

The product, code, CLI, runtime, and environment identities are renamed to Arcana Guardian. The GitHub repository itself still uses `CodePenguin/with-secrets` so existing links keep working during review. Do not change the references below until the repository rename is complete.

## Remaining substitutions

| Current | Replace after the GitHub rename |
| --- | --- |
| `https://github.com/CodePenguin/with-secrets` | `https://github.com/CodePenguin/arcana-guardian` |
| `github.com/CodePenguin/with-secrets/desktop` | `github.com/CodePenguin/arcana-guardian/desktop` |
| `git clone https://github.com/CodePenguin/with-secrets.git arcana-guardian` | `git clone https://github.com/CodePenguin/arcana-guardian.git arcana-guardian` |

These references are in the README badge, documentation links, release and clone instructions, and `src/ArcanaGuardian.Desktop/go.mod`. The local clone directory is already named `arcana-guardian` and does not need to change.

## After the rename

1. Rename the GitHub repository to `arcana-guardian`.
2. Apply the substitutions above across tracked files.
3. Rescan tracked files for legacy identities and run `pwsh scripts/verify-all.ps1`.
4. Update or remove this document once the cutover is complete.

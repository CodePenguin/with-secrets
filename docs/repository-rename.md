# Repository rename cutover

The product, code, CLI, runtime, environment, and hosting identities now use Arcana Guardian and `CodePenguin/arcana-guardian`. The GitHub repository rename itself is still pending, so links and module paths below point at the future repository and will not resolve until that rename is complete.

## Applied references

- Web URL: `https://github.com/CodePenguin/arcana-guardian`
- Go module path: `github.com/CodePenguin/arcana-guardian/desktop`
- Clone command: `git clone https://github.com/CodePenguin/arcana-guardian.git arcana-guardian`

These references are used by the README badge, documentation links, release and clone instructions, and `src/ArcanaGuardian.Desktop/go.mod`. The local clone directory is already named `arcana-guardian` and does not need to change.

## After the GitHub rename

1. Rename the GitHub repository to `arcana-guardian`.
2. Confirm that the README badge, workflow links, releases link, and clone command resolve.
3. Confirm that `github.com/CodePenguin/arcana-guardian/desktop` resolves as a Go module.
4. Rescan tracked files for legacy identities and run `pwsh scripts/verify-all.ps1`.
5. Remove this document once the cutover is complete.

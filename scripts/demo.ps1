<#
.SYNOPSIS
    Runs every Playwright end-to-end scenario and records a demo of each.

.DESCRIPTION
    Builds in this checkout, then replaces this branch's demo in the shared library.
    The main branch uses artifacts\demo\latest. Linked worktrees use their worktree name.
    An explicit OutputDirectory preserves the previous run and must be empty.
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$demoArgs = @('--demo')
if (-not [string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $demoArgs += $OutputDirectory
}

Push-Location $repo
try {
    dotnet build tests/ArcanaGuardian.E2E
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    dotnet run --no-build --project tests/ArcanaGuardian.E2E -- @demoArgs
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}

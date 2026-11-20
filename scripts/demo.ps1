<#
.SYNOPSIS
    Runs every Playwright end-to-end scenario and records a browser video for each scenario.

.DESCRIPTION
    Uses the same isolated test rigs and real browser scenarios as the ordinary E2E runner.
    Videos, failure evidence and an HTML index are written under artifacts\demo by default.
    The default output is artifacts\demo\latest, which each run replaces: only the last demo is kept.
    An explicit output directory must be under artifacts\demo and empty: the script never overwrites
    one and never writes demo output elsewhere in the repository.

    This is deliberately separate from verify-all.ps1 and does not change the normal
    verification pipeline. A failed build or scenario exits with a nonzero code.
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$demoRoot = [System.IO.Path]::GetFullPath((Join-Path $repo 'artifacts\demo'))
$replaceLatest = [string]::IsNullOrWhiteSpace($OutputDirectory)
if ($replaceLatest) {
    $OutputDirectory = Join-Path $demoRoot 'latest'
}
elseif (-not [System.IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory = Join-Path $repo $OutputDirectory
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)

# Demo output can contain failure screenshots and page state. Keep every run inside the
# ignored artifacts\demo tree, and never reuse an explicit directory that already holds recordings.
$demoRootWithSeparator = $demoRoot.TrimEnd('\') + '\'
if (-not $OutputDirectory.StartsWith($demoRootWithSeparator, [StringComparison]::OrdinalIgnoreCase)) {
    Write-Host "ERROR: The demo output directory must be under $demoRoot." -ForegroundColor Red
    exit 1
}

$exitCode = 0
Push-Location $repo
try {
    # Only the last demo is kept, so the build must succeed before the old one goes.
    dotnet build tests\WithSecrets.E2E
    if ($LASTEXITCODE -ne 0) { throw "E2E build failed with exit code $LASTEXITCODE" }

    if ($replaceLatest -and (Test-Path -LiteralPath $OutputDirectory)) {
        Remove-Item -LiteralPath $OutputDirectory -Recurse -Force
    }

    if (Test-Path -LiteralPath $OutputDirectory) {
        $existing = @(Get-ChildItem -LiteralPath $OutputDirectory -Force -ErrorAction Stop)
        if ($existing.Count -gt 0) {
            throw "Output directory '$OutputDirectory' already contains files. Previous recordings are never overwritten; choose a new directory."
        }
    }

    New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
    dotnet run --no-build --project tests\WithSecrets.E2E -- --demo $OutputDirectory
    if ($LASTEXITCODE -ne 0) { throw "UX demo run failed with exit code $LASTEXITCODE. See the scenario output above." }

    Write-Host ""
    Write-Host "UX demo ready:"
    Write-Host "  $OutputDirectory\index.html"
    Write-Host "Open the index in a browser to review the scenario recordings."
}
catch {
    Write-Host ("ERROR: " + $_.Exception.Message) -ForegroundColor Red
    $exitCode = 1
}
finally {
    Pop-Location
}

exit $exitCode

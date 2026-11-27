[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Output
)

$ErrorActionPreference = 'Stop'
$Output = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Output)
$windows = $PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows
$linkerFlags = if ($windows) { '-s -w -H windowsgui' } else { '-s -w' }
$binary = if ($windows) { 'with-secrets-desktop.exe' } else { 'with-secrets-desktop' }
$previousCgo = $env:CGO_ENABLED

Push-Location (Join-Path $PSScriptRoot '../src/WithSecrets.Desktop')
try {
    $env:CGO_ENABLED = if ($IsMacOS) { '1' } else { '0' }
    $binary = Join-Path $Output $binary
    if ($IsMacOS) {
        $bundle = Join-Path $Output 'With Secrets.app'
        $binary = Join-Path $bundle 'Contents/MacOS/with-secrets-desktop'
        New-Item -ItemType Directory -Path (Split-Path $binary) -Force | Out-Null
        Copy-Item Info.plist (Join-Path $bundle 'Contents/Info.plist')
    } else {
        New-Item -ItemType Directory -Path $Output -Force | Out-Null
    }

    go build -trimpath -ldflags $linkerFlags -o $binary .
    if ($LASTEXITCODE -ne 0) { throw "Desktop build failed (exit $LASTEXITCODE)" }

    if ($IsMacOS) {
        codesign --force --sign - $bundle
        if ($LASTEXITCODE -ne 0) { throw 'Could not sign the macOS app for local use' }
        codesign --verify --strict $bundle
        if ($LASTEXITCODE -ne 0) { throw 'Could not verify the macOS app signature' }
    }

    Copy-Item README.md, THIRD-PARTY-NOTICES.txt $Output
} finally {
    $env:CGO_ENABLED = $previousCgo
    Pop-Location
}

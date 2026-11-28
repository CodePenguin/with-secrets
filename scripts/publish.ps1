<#
.SYNOPSIS
    Publishes the release for one platform: one self-contained, single-file program with the administration web application embedded, then verifies it.

.DESCRIPTION
    Needs the .NET 10 SDK and Node.js 22 or newer on the PATH. The frontend (src/ArcanaGuardian.Admin.Web) is built by the .NET build itself
    (npm ci when package-lock.json changed, then npm run build) because -p:AdminWebRequired=true makes a missing Node.js or a failed frontend build
    an error: a release never lacks the application. Nothing is written outside -Output (default: artifacts/publish/<runtime>, which git ignores).

    -Runtime is a .NET runtime identifier: win-x64, linux-x64, osx-arm64 or osx-x64. The default is the platform this runs on. The program is
    run by the verification (--self-check), so a runtime that this machine cannot run cannot be verified here.

    The result is checked by scripts/verify-publish.ps1: exactly one file (using-secrets, using-secrets.exe on Windows), no loose frontend file, the web
    application embedded and served by the program itself from the one origin, and the frontend version equal to the backend version at /api/v1/status.
#>
[CmdletBinding()]
param(
    [string]$Runtime = '',
    [string]$Output = ''
)

$ErrorActionPreference = 'Stop'
$repo = Resolve-Path (Join-Path $PSScriptRoot '..')

if ($Runtime -eq '') {
    # Windows PowerShell 5.1 has no $IsWindows; it only runs on Windows.
    $onWindows = $PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows
    $arm = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq [System.Runtime.InteropServices.Architecture]::Arm64
    $Runtime = if ($onWindows) { 'win-x64' } elseif ($IsLinux) { 'linux-x64' } elseif ($arm) { 'osx-arm64' } else { 'osx-x64' }
}

if ($Runtime -notin 'win-x64', 'linux-x64', 'osx-arm64', 'osx-x64') { throw "unsupported runtime '$Runtime'" }
if ($Output -eq '') { $Output = Join-Path $repo "artifacts/publish/$Runtime" }
$Output = [System.IO.Path]::GetFullPath($Output)

if (Test-Path $Output) { Remove-Item -Recurse -Force $Output }
New-Item -ItemType Directory -Force $Output | Out-Null

& dotnet publish (Join-Path $repo 'src/ArcanaGuardian/ArcanaGuardian.csproj') -c Release -r $Runtime --self-contained true `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=none -p:DebugSymbols=false `
    -p:AdminWebRequired=true -o $Output
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed (exit $LASTEXITCODE)" }

& (Join-Path $PSScriptRoot 'verify-publish.ps1') -Folder $Output -Runtime $Runtime
if ($LASTEXITCODE -ne 0) { throw "the published artifact failed verification" }
Write-Host "Published and verified: $Output"

<#
.SYNOPSIS
    Publishes the Windows release: one self-contained win-x64 EXE with the administration web application embedded, then verifies it.

.DESCRIPTION
    Needs the .NET 10 SDK and Node.js 22 or newer on the PATH. The frontend (src/WithSecrets.Admin.Web) is built by the .NET build itself
    (npm ci when package-lock.json changed, then npm run build) because -p:AdminWebRequired=true makes a missing Node.js or a failed frontend build
    an error: a release never lacks the application. Nothing is written outside -Output (default: artifacts\publish\win-x64, which git ignores).

    The result is checked by scripts\verify-publish.ps1: exactly one file (with-secrets.exe), no loose frontend file, the web application embedded and served by the
    program itself from the one origin, and the frontend version equal to the backend version at /api/v1/status.
#>
[CmdletBinding()]
param(
    [string]$Output = (Join-Path $PSScriptRoot '..\artifacts\publish\win-x64')
)

$ErrorActionPreference = 'Stop'
$repo = Resolve-Path (Join-Path $PSScriptRoot '..')
$Output = [System.IO.Path]::GetFullPath($Output)

if (Test-Path $Output) { Remove-Item -Recurse -Force $Output }
New-Item -ItemType Directory -Force $Output | Out-Null

& dotnet publish (Join-Path $repo 'src\WithSecrets\WithSecrets.csproj') -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=none -p:DebugSymbols=false `
    -p:AdminWebRequired=true -o $Output
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed (exit $LASTEXITCODE)" }

& (Join-Path $PSScriptRoot 'verify-publish.ps1') -Folder $Output
if ($LASTEXITCODE -ne 0) { throw "the published artifact failed verification" }
Write-Host "Published and verified: $Output"

<#
.SYNOPSIS
    Serves all recorded Playwright UX demo runs on every network interface with HTTP byte-range support.

.DESCRIPTION
    Shows a landing page listing every completed run under artifacts\demo.
    Select a run to open its scenario index. New runs appear when the page is refreshed.
    The server listens on 0.0.0.0, allowing access from other devices on the LAN.
    Keep this running only on a trusted network. Press Ctrl+C to stop.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 65535)]
    [int]$Port = 4173
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$primary = git -C $repo worktree list --porcelain | Select-Object -First 1
$libraryCheckout = if ($primary -like 'worktree *') { $primary.Substring('worktree '.Length) } else { $repo }
$demoRoot = [System.IO.Path]::GetFullPath((Join-Path $libraryCheckout 'artifacts\demo'))

if (-not (Test-Path -LiteralPath $demoRoot -PathType Container)) {
    throw "No demo runs folder found. Run .\scripts\demo.ps1 first."
}

$url = "http://0.0.0.0:$Port"

Write-Host "Serving demo library: $demoRoot"
Write-Host "Listening on all network interfaces (0.0.0.0:$Port)."
Write-Host "On this computer: http://127.0.0.1:$Port/"
# The addresses of other devices' view of this computer: real adapters only (no loopback, link-local or virtual switches).
$addresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notmatch '^(127|169\.254)\.' -and $_.InterfaceAlias -notmatch 'vEthernet|WSL|Loopback' })
foreach ($address in $addresses) {
    Write-Host "From another device: http://$($address.IPAddress):$Port/"
}
Write-Host "Only use this on a trusted network; the recordings are available to anyone who can reach this port."
Write-Host "Press Ctrl+C to stop."
dotnet run (Join-Path $PSScriptRoot 'serve-demo.cs') -- --root $demoRoot --url $url
exit $LASTEXITCODE

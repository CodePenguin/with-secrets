<#
.SYNOPSIS
    Verifies a published release folder (architecture 10.5: one self-contained program with the frontend embedded, matching versions).

.DESCRIPTION
    Checks, and exits 1 with one line per failure:
      1. the folder holds exactly one file, using-secrets (using-secrets.exe on Windows; no loose frontend files, no pdb, no runtime files, no Node);
      2. no file or folder named like frontend output exists (nothing to serve from disk);
      3. the program itself, run with --self-check (a throwaway service: software keys, a temporary folder, a free loopback port; no user state, no system key, no secret),
         serves the embedded web application and the API from one origin and reports its versions;
      4. the frontend version embedded in the EXE equals the backend version at /api/v1/status, and both equal the version of the source tree (Directory.Build.props),
         and the frontend build on disk (src\ArcanaGuardian.Admin.Web\dist\version.json) is that version too.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Folder,
    [Parameter(Mandatory = $true)][string]$Runtime
)

$ErrorActionPreference = 'Stop'
$repo = Resolve-Path (Join-Path $PSScriptRoot '..')
$Folder = [System.IO.Path]::GetFullPath($Folder)
$problems = New-Object System.Collections.Generic.List[string]

if (-not (Test-Path $Folder)) { Write-Host "FAIL: $Folder does not exist"; exit 1 }

# 1. Exactly one file, the program.
$files = @(Get-ChildItem -Path $Folder -Recurse -Force)
$onlyFiles = @($files | Where-Object { -not $_.PSIsContainer })
if ($onlyFiles.Count -ne 1) { $problems.Add("expected exactly one file, found $($onlyFiles.Count): " + (($onlyFiles | ForEach-Object { $_.FullName.Substring($Folder.Length + 1) }) -join ', ')) }
if (@($files | Where-Object { $_.PSIsContainer }).Count -ne 0) { $problems.Add('the folder contains sub-folders') }
$name = if ($Runtime -like 'win-*') { 'using-secrets.exe' } else { 'using-secrets' }
$exe = Join-Path $Folder $name
if (-not (Test-Path $exe)) { $problems.Add("$name is missing") }

# 2. No loose frontend files.
$loose = @($files | Where-Object { $_.Extension -in '.js', '.css', '.html', '.map', '.woff2' -or $_.Name -in 'index.html', 'version.json', 'node.exe', 'node' -or $_.FullName -match '[\\/](assets|dist|node_modules|wwwroot)([\\/]|$)' })
foreach ($item in $loose) { $problems.Add("a loose frontend file: " + $item.FullName.Substring($Folder.Length + 1)) }

$result = $null
if (Test-Path $exe) {
    # 3. The program checks itself.
    $line = & $exe '--self-check' | Select-Object -Last 1
    if ($LASTEXITCODE -ne 0) { $problems.Add("$name --self-check failed (exit $LASTEXITCODE): $line") }
    try { $result = $line | ConvertFrom-Json } catch { $problems.Add("--self-check did not print JSON: $line") }
}

if ($null -ne $result) {
    foreach ($p in @($result.problems)) { if ($p) { $problems.Add("self-check: $p") } }
    if (-not $result.oneOrigin) { $problems.Add('the web application and the API were not both served from one origin') }
    foreach ($needed in 'index.html', 'version.json') { if ($result.embeddedFiles -notcontains $needed) { $problems.Add("$needed is not embedded") } }
    if (@($result.embeddedFiles | Where-Object { $_ -like 'assets/*.js' }).Count -lt 1) { $problems.Add('no script is embedded') }
    if (@($result.embeddedFiles | Where-Object { $_ -like 'assets/*.css' }).Count -lt 1) { $problems.Add('no stylesheet is embedded') }

    # 4. Versions.
    $props = [xml](Get-Content (Join-Path $repo 'Directory.Build.props') -Raw)
    $source = ($props.Project.PropertyGroup | ForEach-Object { $_.Version } | Where-Object { $_ } | Select-Object -First 1)
    $dist = Join-Path $repo 'src/ArcanaGuardian.Admin.Web/dist/version.json'
    $built = if (Test-Path $dist) { (Get-Content $dist -Raw | ConvertFrom-Json).version } else { $null }
    if ($result.backendVersion -ne $source) { $problems.Add("backend version $($result.backendVersion) is not the source version $source") }
    if ($result.frontendVersion -ne $result.backendVersion) { $problems.Add("frontend version $($result.frontendVersion) is not the backend version $($result.backendVersion)") }
    if ($built -and $built -ne $result.frontendVersion) { $problems.Add("the embedded frontend version $($result.frontendVersion) is not the one last built on disk ($built)") }
}

if ($problems.Count -gt 0) {
    foreach ($p in $problems) { Write-Host "FAIL: $p" }
    exit 1
}

$size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
Write-Host "OK: one file ($name, $size MB), $($result.embeddedFileCount) embedded frontend files, backend $($result.backendVersion) = frontend $($result.frontendVersion), web application and API served from one origin."
exit 0

<#
.SYNOPSIS
    Runs the whole acceptance sequence in order and reports pass or fail per stage.

.DESCRIPTION
    Stages, in order:
      1. build        dotnet build with-secrets.slnx --no-incremental; must end with 0 warnings and 0 errors (warnings are errors in this repository)
      2. dotnet-tests the whole .NET suite (tests\WithSecrets.Tests); must report 0 failed
      3. frontend     npm run verify in src\WithSecrets.Admin.Web (client is current, typecheck, lint, unit and accessibility tests)
      4. publish      scripts\publish-win-x64.ps1 (single self-contained EXE) and scripts\verify-publish.ps1
      5. e2e          rebuilds tests\WithSecrets.E2E, then runs the real-browser scenarios; must end with ALL PASSED

    Each stage's full output goes to artifacts\verify-all\<stage>.log (git ignores artifacts); the console shows one result line per stage and, for a
    failed stage, the lines that start with FAIL (test names and public detail only; the tests print no secret, key, code or value). The script stops at the
    first failed stage unless -KeepGoing is given, and exits 0 only when every stage that ran passed.

    Needs the .NET 10 SDK and Node.js 22 or newer. It changes nothing outside the repository (tests use temporary folders, never ~/.with-secrets).
#>
[CmdletBinding()]
param(
    [switch]$KeepGoing,
    [string[]]$Skip = @()
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$logs = Join-Path $repo 'artifacts\verify-all'
New-Item -ItemType Directory -Force $logs | Out-Null
$results = New-Object System.Collections.Generic.List[object]

function Invoke-Stage {
    param([string]$Name, [scriptblock]$Command, [scriptblock]$Judge)
    if ($Skip -contains $Name) { Write-Host ("SKIP  {0}" -f $Name); return $true }
    $log = Join-Path $logs "$Name.log"
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $global:LASTEXITCODE = 0
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & $Command *> $log
    $ErrorActionPreference = $previous
    $exit = $LASTEXITCODE
    $text = if (Test-Path $log) { Get-Content $log -Raw } else { '' }
    $verdict = & $Judge $exit $text
    $clock.Stop()
    $ok = ($verdict -eq 'ok')
    $label = if ($ok) { 'PASS' } else { 'FAIL' }
    $detail = if ($ok) { '' } else { " ($verdict)" }
    Write-Host ("{0}  {1}  {2:N0}s{3}" -f $label, $Name, $clock.Elapsed.TotalSeconds, $detail)
    if (-not $ok) {
        $failing = @(Select-String -Path $log -Pattern '^(FAIL|error )' -SimpleMatch:$false | Select-Object -First 20 | ForEach-Object { $_.Line })
        foreach ($line in $failing) { Write-Host ("      " + $line) }
        Write-Host ("      full output: " + $log)
    }
    $results.Add([pscustomobject]@{ Stage = $Name; Passed = $ok })
    return $ok
}

Push-Location $repo
try {
    $stages = @(
        @{ Name = 'build'
           Command = { dotnet build with-secrets.slnx --no-incremental }
           Judge = { param($exit, $text)
               if ($exit -ne 0) { return "exit $exit" }
               if ($text -notmatch '\b0 Warning\(s\)') { return 'warnings are not 0' }
               if ($text -notmatch '\b0 Error\(s\)') { return 'errors are not 0' }
               'ok' } },
        @{ Name = 'dotnet-tests'
           Command = { dotnet run --project tests\WithSecrets.Tests }
           Judge = { param($exit, $text)
               $m = [regex]::Matches($text, '(\d+) passed, (\d+) failed')
               if ($m.Count -eq 0) { return 'no result line' }
               $last = $m[$m.Count - 1]
               if ([int]$last.Groups[2].Value -ne 0) { return "$($last.Groups[2].Value) failed" }
               if ($exit -ne 0) { return "exit $exit" }
               'ok' } },
        @{ Name = 'frontend'
           Command = { Push-Location (Join-Path $repo 'src\WithSecrets.Admin.Web'); try { npm run verify } finally { Pop-Location } }
           Judge = { param($exit, $text) if ($exit -ne 0) { "exit $exit" } else { 'ok' } } },
        @{ Name = 'publish'
           Command = { & (Join-Path $repo 'scripts\publish-win-x64.ps1') }
           Judge = { param($exit, $text)
               if ($exit -ne 0) { return "exit $exit" }
               if ($text -notmatch 'Published and verified') { return 'the artifact was not verified' }
               'ok' } },
        @{ Name = 'e2e'
           Command = { dotnet build tests\WithSecrets.E2E; if ($LASTEXITCODE -eq 0) { dotnet run --project tests\WithSecrets.E2E } }
           Judge = { param($exit, $text)
               if ($exit -ne 0) { return "exit $exit" }
               if ($text -notmatch 'ALL PASSED') { return 'not all scenarios passed' }
               'ok' } }
    )

    foreach ($stage in $stages) {
        $ok = Invoke-Stage -Name $stage.Name -Command $stage.Command -Judge $stage.Judge
        if (-not $ok -and -not $KeepGoing) { break }
    }
}
finally {
    Pop-Location
}

$failed = @($results | Where-Object { -not $_.Passed })
$ran = $results.Count
if ($failed.Count -eq 0 -and $ran -gt 0) { Write-Host ("ALL STAGES PASSED ({0})" -f $ran); exit 0 }
Write-Host ("NOT PASSED: {0} of {1} stages failed" -f $failed.Count, $ran)
exit 1

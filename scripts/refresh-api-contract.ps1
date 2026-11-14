<#
.SYNOPSIS
    Regenerates the checked-in OpenAPI document and TypeScript API types from the current backend routes.

.DESCRIPTION
    Runs the .NET test harness with WS_UPDATE_OPENAPI=1 so ApiTests writes docs/api/openapi.json,
    then runs the frontend API generator to refresh src/WithSecrets.Admin.Web/src/api/schema.ts,
    and finishes with the full repository verification script.
#>
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$previousOpenApi = $env:WS_UPDATE_OPENAPI
$previousOnly = $env:WS_ONLY

Push-Location $repo
try {
    $env:WS_UPDATE_OPENAPI = '1'
    $env:WS_ONLY = 'Api'
    dotnet run --project tests\WithSecrets.Tests
    if ($LASTEXITCODE -ne 0) {
        throw "The .NET test harness failed while regenerating docs/api/openapi.json (exit $LASTEXITCODE)."
    }

    if ($null -eq $previousOnly) {
        Remove-Item Env:\WS_ONLY -ErrorAction SilentlyContinue
    }
    else {
        $env:WS_ONLY = $previousOnly
    }

    if ($null -eq $previousOpenApi) {
        Remove-Item Env:\WS_UPDATE_OPENAPI -ErrorAction SilentlyContinue
    }
    else {
        $env:WS_UPDATE_OPENAPI = $previousOpenApi
    }

    Push-Location (Join-Path $repo 'src\WithSecrets.Admin.Web')
    try {
        npm run api:generate
        if ($LASTEXITCODE -ne 0) {
            throw "The frontend API type generator failed (exit $LASTEXITCODE)."
        }
    }
    finally {
        Pop-Location
    }

    & (Join-Path $PSScriptRoot 'verify-all.ps1')
    if ($LASTEXITCODE -ne 0) {
        throw "Full repository verification failed (exit $LASTEXITCODE)."
    }

    Write-Host 'OpenAPI document and TypeScript API types regenerated; full verification passed.'
}
finally {
    if ($null -eq $previousOnly) {
        Remove-Item Env:\WS_ONLY -ErrorAction SilentlyContinue
    }
    else {
        $env:WS_ONLY = $previousOnly
    }
    if ($null -eq $previousOpenApi) {
        Remove-Item Env:\WS_UPDATE_OPENAPI -ErrorAction SilentlyContinue
    }
    else {
        $env:WS_UPDATE_OPENAPI = $previousOpenApi
    }
    Pop-Location
}

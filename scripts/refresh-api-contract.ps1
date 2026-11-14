<#
.SYNOPSIS
    Regenerates the checked-in OpenAPI document and TypeScript API types from the current backend routes.

.DESCRIPTION
    Runs the .NET test harness with WS_UPDATE_OPENAPI=1 so ApiTests writes docs/api/openapi.json,
    then runs the frontend API generator to refresh src/WithSecrets.Admin.Web/src/api/schema.ts.
    Run this after changing AdminApi routes or schemas, then run scripts/verify-all.ps1.
#>
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$previousOpenApi = $env:WS_UPDATE_OPENAPI

Push-Location $repo
try {
    $env:WS_UPDATE_OPENAPI = '1'
    dotnet run --project tests\WithSecrets.Tests
    if ($LASTEXITCODE -ne 0) {
        throw "The .NET test harness failed while regenerating docs/api/openapi.json (exit $LASTEXITCODE)."
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

    Write-Host 'OpenAPI document and TypeScript API types regenerated.'
}
finally {
    if ($null -eq $previousOpenApi) {
        Remove-Item Env:\WS_UPDATE_OPENAPI -ErrorAction SilentlyContinue
    }
    else {
        $env:WS_UPDATE_OPENAPI = $previousOpenApi
    }
    Pop-Location
}

<#
.SYNOPSIS
    Regenerates the checked-in OpenAPI document and TypeScript API types from the current backend routes.

.DESCRIPTION
    Runs the .NET test harness with WS_UPDATE_OPENAPI=1 so ApiTests writes docs/api/openapi.json,
    then runs the frontend API generator to refresh src/WithSecrets.Admin.Web/src/api/schema.ts.
    Run scripts/verify-all.ps1 after this script succeeds.
#>
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$previousOpenApi = $env:WS_UPDATE_OPENAPI
$previousOnly = $env:WS_ONLY

Push-Location $repo
try {
    $env:WS_UPDATE_OPENAPI = '1'
    $env:WS_ONLY = 'Api'
    dotnet run --project tests\WithSecrets.Tests --property:BuildAdminWeb=false
    if ($LASTEXITCODE -ne 0) {
        throw "The .NET test harness failed while regenerating docs/api/openapi.json (exit $LASTEXITCODE)."
    }

    $openApiPath = Join-Path $repo 'docs\api\openapi.json'
    $openApi = Get-Content $openApiPath -Raw | ConvertFrom-Json
    $schemas = $openApi.components.schemas
    $requiredSchemas = @('ApprovalQueue', 'ApprovalQueueItem', 'ApprovalDetail', 'ApprovalChallenge', 'ApprovalReview')
    $missingSchemas = @($requiredSchemas | Where-Object { $null -eq $schemas.$_ })
    if ($missingSchemas.Count -gt 0) {
        throw "The API tests did not regenerate the approval schemas in docs/api/openapi.json: $($missingSchemas -join ', ')."
    }
    if ($null -eq $openApi.paths.'/api/v1/approvals' -or $null -eq $openApi.paths.'/api/v1/approvals/{requestId}') {
        throw 'The API tests did not regenerate the approval routes in docs/api/openapi.json.'
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

    Write-Host 'OpenAPI document and TypeScript API types regenerated. Run scripts/verify-all.ps1 next.'
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

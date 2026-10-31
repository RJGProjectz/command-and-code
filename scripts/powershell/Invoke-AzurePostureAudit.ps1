<#
.SYNOPSIS
    Read-only Azure / Entra ID identity posture audit. Grades the tenant against a posture catalog
    where every check carries CIS Microsoft Azure Foundations Benchmark and MCSB crosswalk entries.

.DESCRIPTION
    Script Name   : Invoke-AzurePostureAudit.ps1
    Purpose       : Audits the connected Azure / Entra ID tenant (security defaults, conditional
                    access policies, user settings, guest access, global administrator assignments,
                    and PIM role settings) against the Azure identity posture catalog. Each result
                    records a per-framework verdict (CIS / MCSB / best practice) and an overall
                    Pass/Fail decided by -Bar. This is Phase 1 (Identity and Access Management);
                    future phases cover subscriptions, storage/network/key vault and logging.
    Inputs        : Azure identity posture catalog JSON (default scripts/cis/catalogs/azure/
                    azure-identity-posture-v1.json) and the live tenant, read through the az CLI
                    and Microsoft Graph v1.0.
    Outputs       : Result objects on the pipeline; optional JSON, NDJSON (one line per check,
                    SIEM-ready) and CSV reports. Reports default to the script's own folder so there
                    are no write-permission issues wherever it is run from.
    Security      : Security Domain: Compliance / Hardening. Read-only in Test and Prod: no Azure
                    resource or Entra ID object is changed. Requires az login with a user or service
                    principal that holds the Global Reader or Security Reader Entra ID built-in role.
                    PIM checks require Azure AD P2 and PrivilegedAccess.Read.AzureAD permission.
    Author        : RJGProjectz
    Version       : 1.0.0
    Created       : 2026-10-29T00:00:00Z
    Last Modified : 2026-10-29T00:00:00Z
    KB Article    : docs/tasks/assurance/azure-posture-audit.md
    API Standards : Status values Pass | Fail | NotApplicable | Error. Catalog schema
                    cc.azposture.catalog/1; report schema cc.azposture.report/1.

.PARAMETER TargetEnvironment
    'Test' (default) or 'Prod'. The audit is read-only and behaves the same in both; the value is
    recorded in the report.

.PARAMETER Bar
    Overall pass bar: 'BestPractice' (default) passes a check when its best-practice expectation is
    met (the minimum bar); 'Strictest' passes only when every framework on the check is met.

.PARAMETER CatalogPath
    Azure identity posture catalog JSON. Default: ..\cis\catalogs\azure\azure-identity-posture-v1.json
    next to this script.

.PARAMETER TenantId
    Optional Entra ID tenant ID to target. Omit to use the signed-in account's default tenant.

.PARAMETER OutputPath
    Folder for report files. Default: this script's own folder ($PSScriptRoot). Use '' to skip files.

.PARAMETER Format
    Report formats written to -OutputPath: Json, Ndjson, Csv (default: all three).

.PARAMETER FailOn
    Exit code policy: None (default, always exit 0), Fail (exit 1 on any Fail) or FailOrError (also
    exit 2 when any check could not be evaluated).

.PARAMETER Quiet
    No console summary; results still go to the pipeline and files.

.EXAMPLE
    .\Invoke-AzurePostureAudit.ps1
.EXAMPLE
    .\Invoke-AzurePostureAudit.ps1 -Bar Strictest -OutputPath D:\Evidence
.EXAMPLE
    .\Invoke-AzurePostureAudit.ps1 -TenantId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' | Where-Object Status -ne 'Pass'
.EXAMPLE
    # Fail the script when findings exist (for CI / automated attestation)
    .\Invoke-AzurePostureAudit.ps1 -FailOn FailOrError -Quiet
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Test', 'Prod')]
    [string]$TargetEnvironment = 'Test',

    [Parameter(Mandatory = $false)]
    [ValidateSet('BestPractice', 'Strictest')]
    [string]$Bar = 'BestPractice',

    [Parameter(Mandatory = $false)]
    [string]$CatalogPath,

    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = $PSScriptRoot,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Json', 'Ndjson', 'Csv')]
    [string[]]$Format = @('Json', 'Ndjson', 'Csv'),

    [Parameter(Mandatory = $false)]
    [ValidateSet('None', 'Fail', 'FailOrError')]
    [string]$FailOn = 'None',

    [Parameter(Mandatory = $false)]
    [switch]$Quiet
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$ToolName = 'Invoke-AzurePostureAudit'
$ToolVersion = '1.0.0'
$script:QuietMode = $Quiet.IsPresent

function Write-AuditLog {
    # Console logging helper (the only place Write-Host is used, GOLDEN_STANDARDS section 5.1).
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR', 'PASS', 'FAIL')][string]$Level = 'INFO')
    if ($script:QuietMode) { return }
    $colors = @{ INFO = 'Cyan'; WARN = 'Yellow'; ERROR = 'Red'; PASS = 'Green'; FAIL = 'Red' }
    Write-Host "[$Level] $Message" -ForegroundColor $colors[$Level]
}

Import-Module (Join-Path $PSScriptRoot 'AzurePosture\AzurePosture.psm1') -Force

$executionId = [guid]::NewGuid().ToString()
$startedUtc = (Get-Date).ToUniversalTime()
$timestamp = $startedUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')

if (-not $CatalogPath) {
    $CatalogPath = Join-Path $PSScriptRoot '..\cis\catalogs\azure\azure-identity-posture-v1.json'
}
if (-not (Test-Path -LiteralPath $CatalogPath)) {
    throw "Azure posture catalog not found: $CatalogPath"
}

Write-Verbose "Mode: $TargetEnvironment (read-only; no Azure resource is changed)"
Write-AuditLog "Azure identity posture audit — $TargetEnvironment (bar: $Bar)"
Write-AuditLog "Catalog: $CatalogPath" 'INFO'

# Load catalog.
$catalog = Import-AzurePostureCatalog -Path $CatalogPath
Write-AuditLog "Checks: $(@($catalog.checks).Count) from $($catalog.name) v$($catalog.version)" 'INFO'

# Collect context.
Write-AuditLog "Collecting Azure / Entra ID facts via Microsoft Graph..." 'INFO'
$collectArgs = @{}
if ($TenantId) { $collectArgs['TenantId'] = $TenantId }
$context = Get-AzurePostureContext @collectArgs

$tenantLabel = if ($context.Meta.TenantName -and $context.Meta.TenantName -ne 'unknown') {
    "$($context.Meta.TenantName) ($($context.Meta.TenantId))"
} else { $context.Meta.TenantId }
Write-AuditLog "Tenant: $tenantLabel" 'INFO'

# Evaluate checks.
$rows = @(foreach ($check in $catalog.checks) {
    Invoke-AzurePostureCheck -Check $check -Context $context -Bar $Bar
})

# Summary.
$summary = [ordered]@{
    total         = $rows.Count
    pass          = @($rows | Where-Object Status -eq 'Pass').Count
    fail          = @($rows | Where-Object Status -eq 'Fail').Count
    error         = @($rows | Where-Object Status -eq 'Error').Count
    notApplicable = @($rows | Where-Object Status -eq 'NotApplicable').Count
}
$scored = $summary.pass + $summary.fail
$summary.scorePct = if ($scored -gt 0) { [math]::Round(100 * $summary.pass / $scored, 1) } else { 0 }

foreach ($r in $rows | Where-Object Status -ne 'Pass') {
    $logLevel = if ($r.Status -eq 'Fail') { 'FAIL' } elseif ($r.Status -eq 'Error') { 'ERROR' } else { 'INFO' }
    Write-AuditLog "$($r.Id) $($r.Title) | expected: $($r.Expected) | actual: $($r.Actual)" $logLevel
}
Write-AuditLog ("Summary: {0} checks, {1} pass, {2} fail, {3} error, {4} n/a — score {5}%" -f
    $summary.total, $summary.pass, $summary.fail, $summary.error, $summary.notApplicable, $summary.scorePct)

$report = [ordered]@{
    schema       = 'cc.azposture.report/1'
    tool         = $ToolName
    version      = $ToolVersion
    execution_id = $executionId
    timestamp    = $timestamp
    tenant       = $tenantLabel
    environment  = $TargetEnvironment
    bar          = $Bar
    catalog      = (Split-Path -Leaf $CatalogPath)
    failOn       = $FailOn
    summary      = $summary
    results      = $rows
}

$written = @()
if ($OutputPath -ne '') {
    $null = New-Item -ItemType Directory -Path $OutputPath -Force
    $base = Join-Path $OutputPath ("azposture-" + $startedUtc.ToString('yyyyMMdd-HHmmss'))
    if ($Format -contains 'Json') {
        $p = "$base.json"
        $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $p -Encoding UTF8
        $written += $p
    }
    if ($Format -contains 'Ndjson') {
        $p = "$base.ndjson"
        $rows | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 3 } |
            Set-Content -LiteralPath $p -Encoding UTF8
        $written += $p
    }
    if ($Format -contains 'Csv') {
        $p = "$base.csv"
        $rows | Export-Csv -LiteralPath $p -NoTypeInformation -Encoding UTF8
        $written += $p
    }
    if ($written.Count -gt 0) {
        Write-AuditLog "Reports written: $($written -join ', ')" 'INFO'
    }
}

$rows | Write-Output

switch ($FailOn) {
    'Fail' {
        if (@($rows | Where-Object Status -eq 'Fail').Count -gt 0) { exit 1 }
    }
    'FailOrError' {
        if (@($rows | Where-Object Status -eq 'Fail').Count -gt 0) { exit 1 }
        if (@($rows | Where-Object Status -eq 'Error').Count -gt 0) { exit 2 }
    }
}

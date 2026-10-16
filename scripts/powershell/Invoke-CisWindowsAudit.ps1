<#
.SYNOPSIS
    Read-only CIS Microsoft Windows 11 Enterprise Benchmark audit (Level 1 / Level 2), data-driven.

.DESCRIPTION
    Script Name   : Invoke-CisWindowsAudit.ps1
    Purpose       : Audits the local host against every automatable recommendation in a CIS check
                    catalog (default: CIS Microsoft Windows 11 Enterprise v5.1.0, 486 checks) and
                    writes one result per recommendation: CIS ID, title, level, expected, actual,
                    Pass / Fail / NotApplicable / Error. Use it for hardening baselines, before/after
                    comparisons and compliance evidence.
    Inputs        : Catalog JSON (scripts/cis/catalogs/), profile level, optional ID/section filters.
    Outputs       : Result objects on the pipeline; optional JSON report, NDJSON (GOLDEN_STANDARDS
                    section 4.7, one line per check, SIEM-ready) and CSV in -OutputPath.
    Security      : Security Domain: Compliance / Hardening. Read-only in Test and Prod: reads the
                    registry, secedit /export (temporary .inf, deleted), auditpol /get and service
                    state. Run elevated: secedit and auditpol need administrator rights; without
                    them account, user-rights and audit-policy checks report Error.
    Author        : RJGProjectz
    Version       : 2.0.0
    Created       : 2026-10-08T12:30:00Z
    Last Modified : 2026-10-16T15:00:00Z
    KB Article    : docs/tasks/hardening/windows-11-cis-audit-tool.md
    Source Repo   : https://www.cisecurity.org/benchmark/microsoft_windows_desktop
    API Standards : Status values Pass | Fail | NotApplicable | Error. Recommendation IDs and titles
                    only; CIS benchmark text is licensed and not reproduced.

.PARAMETER TargetEnvironment
    'Test' (default) or 'Prod'. The audit is read-only and behaves the same in both; the value is
    recorded in the report.

.PARAMETER Level
    CIS profile: L1 (default) or L2. L2 includes all L1 recommendations.

.PARAMETER Id
    Recommendation ID filter, wildcards allowed (e.g. '2.3.*', '18.10.43.*'). Default: all.

.PARAMETER Section
    Top-level section numbers to audit (1, 2, 5, 9, 17, 18, 19). Default: all.

.PARAMETER CatalogPath
    Catalog JSON. Default: ..\cis\catalogs\windows11-enterprise-v5.1.0.json next to this script.

.PARAMETER OutputPath
    Folder for report files. Nothing is written when omitted.

.PARAMETER Format
    Report formats written to -OutputPath: Json, Ndjson, Csv (default: all three).

.PARAMETER OutputJson
    Legacy: path of a single JSON report file (same content as Format Json).

.PARAMETER SkipApplicabilityCheck
    Audit even when the host is not Windows 11 client (results are then indicative only).

.PARAMETER Quiet
    No console summary; results still go to the pipeline and files.

.EXAMPLE
    .\Invoke-CisWindowsAudit.ps1 -Level L1 -OutputPath C:\Reports\CIS
.EXAMPLE
    .\Invoke-CisWindowsAudit.ps1 -Level L2 -Section 17 | Where-Object Status -ne 'Pass'
.EXAMPLE
    .\Invoke-CisWindowsAudit.ps1 -Id '2.3.*','18.9.*' -Format Csv -OutputPath .\out -Quiet
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Test', 'Prod')]
    [string]$TargetEnvironment = 'Test',

    [Parameter(Mandatory = $false)]
    [ValidateSet('L1', 'L2')]
    [string]$Level = 'L1',

    [Parameter(Mandatory = $false)]
    [string[]]$Id = @('*'),

    [Parameter(Mandatory = $false)]
    [string[]]$Section = @(),

    [Parameter(Mandatory = $false)]
    [string]$CatalogPath = (Join-Path $PSScriptRoot '..\cis\catalogs\windows11-enterprise-v5.1.0.json'),

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Json', 'Ndjson', 'Csv')]
    [string[]]$Format = @('Json', 'Ndjson', 'Csv'),

    [Parameter(Mandatory = $false)]
    [string]$OutputJson,

    [Parameter(Mandatory = $false)]
    [switch]$SkipApplicabilityCheck,

    [Parameter(Mandatory = $false)]
    [switch]$Quiet
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$ToolName = 'Invoke-CisWindowsAudit'
$ToolVersion = '2.0.0'

function Write-AuditLog {
    # Console logging helper (the only place Write-Host is used, GOLDEN_STANDARDS section 5.1).
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR', 'PASS', 'FAIL')][string]$Level = 'INFO')
    if ($Quiet) { return }
    $colors = @{ INFO = 'Cyan'; WARN = 'Yellow'; ERROR = 'Red'; PASS = 'Green'; FAIL = 'Red' }
    Write-Host "[$Level] $Message" -ForegroundColor $colors[$Level]
}

Import-Module (Join-Path $PSScriptRoot 'CisAudit\CisAudit.psm1') -Force

$executionId = [guid]::NewGuid().ToString()
$startedUtc = (Get-Date).ToUniversalTime()
$timestamp = $startedUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
$hostName = [Environment]::MachineName
$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Verbose "Mode: $TargetEnvironment (read-only; no changes are made in either mode)"
$catalog = Import-CisCatalog -Path $CatalogPath
Write-AuditLog "$($catalog.benchmark) v$($catalog.version) - profile $Level - host $hostName - $TargetEnvironment"
if (-not $isElevated) {
    Write-AuditLog 'Not elevated: account policy, user rights and audit policy checks will report Error. Run as administrator for a full audit.' 'WARN'
}

$context = Get-CisLiveContext

# Applicability: the catalog says which OS it is written for (Windows 11 client builds).
$applicable = $true
foreach ($test in @($catalog.applicability)) {
    if ((Invoke-CisTest -Test $test -Context $context).Status -ne 'Pass') { $applicable = $false }
}
if (-not $applicable) {
    if (-not $SkipApplicabilityCheck) {
        throw "Host is not covered by '$($catalog.benchmark)' (build/installation type check failed). Use -SkipApplicabilityCheck to audit anyway."
    }
    Write-AuditLog 'Host is outside the benchmark scope; results are indicative only.' 'WARN'
}

$checks = Select-CisCheck -Catalog $catalog -Level $Level -Id $Id -Section $Section
$results = foreach ($check in $checks) { Invoke-CisCheck -Check $check -Context $context }
$results = @($results)

$summary = [ordered]@{
    total         = $results.Count
    pass          = @($results | Where-Object Status -eq 'Pass').Count
    fail          = @($results | Where-Object Status -eq 'Fail').Count
    error         = @($results | Where-Object Status -eq 'Error').Count
    notApplicable = @($results | Where-Object Status -eq 'NotApplicable').Count
}
$scored = $summary.pass + $summary.fail
$summary.scorePct = if ($scored -gt 0) { [math]::Round(100 * $summary.pass / $scored, 1) } else { 0 }

foreach ($r in $results | Where-Object Status -ne 'Pass') {
    $logLevel = if ($r.Status -eq 'Fail') { 'FAIL' } elseif ($r.Status -eq 'Error') { 'ERROR' } else { 'INFO' }
    Write-AuditLog "$($r.Id) $($r.Title) | expected: $($r.Expected) | actual: $($r.Actual)" $logLevel
}
Write-AuditLog ("Summary: {0} checks, {1} pass, {2} fail, {3} error, {4} n/a - score {5}% (pass / (pass + fail))" -f
    $summary.total, $summary.pass, $summary.fail, $summary.error, $summary.notApplicable, $summary.scorePct)

$report = [ordered]@{
    schema           = 'cc.cis.report/1'
    tool             = $ToolName
    version          = $ToolVersion
    execution_id     = $executionId
    timestamp        = $timestamp
    host             = $hostName
    environment      = $TargetEnvironment
    elevated         = $isElevated
    benchmark        = $catalog.benchmark
    benchmarkVersion = $catalog.version
    profile          = $Level
    filters          = [ordered]@{ id = $Id; section = $Section }
    summary          = $summary
    results          = $results
}

$written = @()
if ($OutputJson) {
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputJson -Encoding UTF8
    $written += $OutputJson
}
if ($OutputPath) {
    if (-not (Test-Path -LiteralPath $OutputPath)) { $null = New-Item -ItemType Directory -Path $OutputPath }
    $base = Join-Path $OutputPath ("cis-{0}-{1}-{2}" -f $hostName, $Level, $startedUtc.ToString('yyyyMMddTHHmmssZ'))
    if ($Format -contains 'Json') {
        $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath "$base.json" -Encoding UTF8
        $written += "$base.json"
    }
    if ($Format -contains 'Ndjson') {
        $lines = foreach ($r in $results) {
            $eventLevel = switch ($r.Status) { 'Fail' { 'WARN' } 'Error' { 'ERROR' } default { 'INFO' } }
            [ordered]@{
                timestamp         = $timestamp
                host              = $hostName
                tool              = $ToolName
                version           = $ToolVersion
                execution_id      = $executionId
                level             = $eventLevel
                message           = "CIS $($r.Id) $($r.Status)"
                environment       = $TargetEnvironment
                action            = 'cis.check'
                target            = $r.Id
                result            = $r.Status
                benchmark         = $catalog.benchmark
                benchmark_version = $catalog.version
                profile           = $r.Level
                cis_id            = $r.Id
                title             = $r.Title
                section           = $r.Section
                expected          = $r.Expected
                actual            = $r.Actual
                source            = $r.Source
                detail            = $r.Detail
            } | ConvertTo-Json -Compress -Depth 3
        }
        [IO.File]::WriteAllLines("$base.ndjson", [string[]]@($lines), [Text.UTF8Encoding]::new($false))
        $written += "$base.ndjson"
    }
    if ($Format -contains 'Csv') {
        $results | Export-Csv -LiteralPath "$base.csv" -NoTypeInformation -Encoding UTF8
        $written += "$base.csv"
    }
}
foreach ($file in $written) { Write-AuditLog "Report written: $file" }

$results
# auditpol leaves a non-zero native exit code when it is denied; the audit itself succeeded.
exit 0

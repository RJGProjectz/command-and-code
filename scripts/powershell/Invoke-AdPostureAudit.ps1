<#
.SYNOPSIS
    Read-only Active Directory environment posture audit. Grades the domain against a posture
    catalog where every check carries a DISA STIG, CIS (DC profile) and best-practice expectation.

.DESCRIPTION
    Script Name   : Invoke-AdPostureAudit.ps1
    Purpose       : Audits the current Active Directory domain (password and lockout policy, krbtgt
                    age, privileged-group membership, delegation, Kerberoasting exposure, stale
                    accounts, built-in accounts, LAPS coverage, trusts, recycle bin and more) against
                    ad-posture catalog checks. Each result records a per-framework verdict (STIG /
                    CIS / best practice) and an overall Pass/Fail decided by -Bar.
    Inputs        : AD posture catalog JSON (default scripts/cis/catalogs/ad-posture-v1.json) and the
                    live domain, read through the RSAT ActiveDirectory module.
    Outputs       : Result objects on the pipeline; optional JSON report, NDJSON (one line per check,
                    SIEM-ready) and CSV. Reports default to the script's own folder so there are no
                    write-permission issues wherever it is run from.
    Security      : Security Domain: Compliance / Hardening. Read-only in Test and Prod: no directory
                    object is changed. Run as a domain user that can read the directory (a standard
                    user can read most; some fields benefit from Domain Admin read).
    Author        : RJGProjectz
    Version       : 1.0.0
    Created       : 2026-10-26T00:00:00Z
    Last Modified : 2026-10-26T00:00:00Z
    KB Article    : docs/tasks/assurance/ad-environment-posture-audit.md
    API Standards : Status values Pass | Fail | NotApplicable | Error. Catalog schema
                    cc.adposture.catalog/1; report schema cc.adposture.report/1.

.PARAMETER TargetEnvironment
    'Test' (default) or 'Prod'. The audit is read-only and behaves the same in both; the value is
    recorded in the report.

.PARAMETER Bar
    Overall pass bar: 'BestPractice' (default) passes a check when its best-practice expectation is
    met (the minimum bar); 'Strictest' passes only when every framework on the check is met.

.PARAMETER CatalogPath
    AD posture catalog JSON. Default: ..\cis\catalogs\ad-posture-v1.json next to this script.

.PARAMETER StaleDays
    Inactivity window (days) for the stale-account checks. Default 90.

.PARAMETER Server
    Optional domain controller / domain to target (passed to the ActiveDirectory cmdlets).

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
    .\Invoke-AdPostureAudit.ps1
.EXAMPLE
    .\Invoke-AdPostureAudit.ps1 -Bar Strictest -OutputPath D:\Evidence
.EXAMPLE
    .\Invoke-AdPostureAudit.ps1 -Server dc01.contoso.com -StaleDays 60 | Where-Object Status -ne 'Pass'
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
    [int]$StaleDays = 90,

    [Parameter(Mandatory = $false)]
    [string]$Server,

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

$ToolName = 'Invoke-AdPostureAudit'
$ToolVersion = '1.0.0'
$script:QuietMode = $Quiet.IsPresent

function Write-AuditLog {
    # Console logging helper (the only place Write-Host is used, GOLDEN_STANDARDS section 5.1).
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR', 'PASS', 'FAIL')][string]$Level = 'INFO')
    if ($script:QuietMode) { return }
    $colors = @{ INFO = 'Cyan'; WARN = 'Yellow'; ERROR = 'Red'; PASS = 'Green'; FAIL = 'Red' }
    Write-Host "[$Level] $Message" -ForegroundColor $colors[$Level]
}

Import-Module (Join-Path $PSScriptRoot 'AdPosture\AdPosture.psm1') -Force

$executionId = [guid]::NewGuid().ToString()
$startedUtc = (Get-Date).ToUniversalTime()
$timestamp = $startedUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
$hostName = [Environment]::MachineName

Write-Verbose "Mode: $TargetEnvironment (read-only; no directory object is changed in either mode)"

if (-not $CatalogPath) { $CatalogPath = Join-Path $PSScriptRoot '..\cis\catalogs\adposture\ad-posture-v1.json' }
if (-not (Test-Path -LiteralPath $CatalogPath)) {
    throw "AD posture catalog not found: $CatalogPath"
}
$catalog = Import-AdPostureCatalog -Path $CatalogPath
$catalogSha256 = (Get-FileHash -LiteralPath $CatalogPath -Algorithm SHA256).Hash.ToLowerInvariant()

$contextArgs = @{ StaleDays = $StaleDays }
if ($Server) { $contextArgs['Server'] = $Server }
$context = Get-AdPostureContext @contextArgs
Write-AuditLog "$($catalog.name) v$($catalog.version) - domain $($context.Meta.Domain) - bar $Bar - $TargetEnvironment"

$results = foreach ($check in $catalog.checks) { Invoke-AdPostureCheck -Check $check -Context $context -Bar $Bar }
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
    schema         = 'cc.adposture.report/1'
    tool           = $ToolName
    version        = $ToolVersion
    execution_id   = $executionId
    timestamp      = $timestamp
    host           = $hostName
    environment    = $TargetEnvironment
    domain         = $context.Meta.Domain
    forest         = $context.Meta.Forest
    bar            = $Bar
    staleDays      = $StaleDays
    catalog        = [ordered]@{ path = (Split-Path -Leaf $CatalogPath); sha256 = $catalogSha256 }
    name           = $catalog.name
    catalogVersion = $catalog.version
    failOn         = $FailOn
    summary        = $summary
    results        = $results
}

$written = @()
if ($OutputPath) {
    if (-not (Test-Path -LiteralPath $OutputPath)) { $null = New-Item -ItemType Directory -Path $OutputPath }
    $base = Join-Path $OutputPath ("adposture-{0}-{1}" -f $hostName, $startedUtc.ToString('yyyyMMddTHHmmssZ'))
    if ($Format -contains 'Json') {
        $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath "$base.json" -Encoding UTF8
        $written += "$base.json"
    }
    if ($Format -contains 'Ndjson') {
        $lines = foreach ($r in $results) {
            $eventLevel = switch ($r.Status) { 'Fail' { 'WARN' } 'Error' { 'ERROR' } default { 'INFO' } }
            [ordered]@{
                timestamp     = $timestamp
                host          = $hostName
                tool          = $ToolName
                version       = $ToolVersion
                execution_id  = $executionId
                level         = $eventLevel
                message       = "ADPOSTURE $($r.Id) $($r.Status)"
                environment   = $TargetEnvironment
                action        = 'adposture.check'
                target        = $r.Id
                result        = $r.Status
                domain        = $context.Meta.Domain
                catalog_sha256 = $catalogSha256
                bar           = $Bar
                check_id      = $r.Id
                title         = $r.Title
                category      = $r.Category
                expected      = $r.Expected
                actual        = $r.Actual
                stig          = $r.Stig
                cis           = $r.Cis
                best_practice = $r.BestPractice
                source        = $r.Source
                detail        = $r.Detail
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
exit (Get-CisExitCode -Results $results -FailOn $FailOn)

<#
.SYNOPSIS
    One-command, read-only configuration posture audit. Auto-detects the host role and runs the CIS
    OS audit for a Windows 10/11 workstation, a member server or a domain controller, and on a domain
    controller (or on request) also runs the Active Directory environment posture audit, then writes
    one merged posture report wherever the script is run from.

.DESCRIPTION
    Script Name   : Invoke-PostureAudit.ps1
    Purpose       : The easy-run umbrella over the CIS audit engine (CisAudit.psm1 / the Windows CIS
                    catalogs) and the AD posture engine (AdPosture.psm1 / ad-posture-v1.json). It
                    picks the right OS catalog by Win32_OperatingSystem.ProductType, evaluates every
                    applicable check read-only, adds the AD posture checks on a domain controller, and
                    reports combined totals. Use it when you want current config posture in one run
                    without choosing a catalog or a role.
    Inputs        : CIS OS catalog (by role) and the AD posture catalog, under scripts/cis/catalogs.
    Outputs       : Unified result objects on the pipeline; JSON, NDJSON (one line per check) and CSV
                    reports. Reports default to the script's OWN folder ($PSScriptRoot) so there are
                    no write-permission issues wherever it runs from. Override with -OutputPath.
    Security      : Security Domain: Compliance / Hardening. Read-only in Test and Prod: it reads the
                    registry, secedit /export, auditpol /get and the directory; nothing is changed.
                    Run from an elevated PowerShell so the OS account/user-rights/audit-policy checks
                    can read their sources.
    Author        : RJGProjectz
    Version       : 1.0.0
    Created       : 2026-10-26T00:00:00Z
    Last Modified : 2026-10-26T00:00:00Z
    KB Article    : docs/tasks/assurance/posture-audit.md
    API Standards : Status values Pass | Fail | NotApplicable | Error. Report schema
                    cc.posture.report/1.

.PARAMETER TargetEnvironment
    'Test' (default) or 'Prod'. The audit is read-only and behaves the same in both; recorded in the
    report.

.PARAMETER Level
    CIS OS profile for the OS audit: L1 (default) or L2.

.PARAMETER IncludeAd
    Also run the AD posture audit. Automatic on a domain controller; use this to run it elsewhere
    (e.g. from a management workstation with the RSAT ActiveDirectory module).

.PARAMETER SkipOs
    Skip the CIS OS audit and run only the AD posture audit.

.PARAMETER Bar
    AD overall pass bar: 'BestPractice' (default) or 'Strictest'. See Invoke-AdPostureAudit.

.PARAMETER OutputPath
    Folder for report files. Default: this script's own folder ($PSScriptRoot). Use '' to skip files.

.PARAMETER Format
    Report formats written to -OutputPath: Json, Ndjson, Csv (default: all three).

.PARAMETER FailOn
    Exit code policy: None (default), Fail (exit 1 on any Fail) or FailOrError (also exit 2 on any
    check that could not be evaluated).

.PARAMETER Quiet
    No console summary; results still go to the pipeline and files.

.EXAMPLE
    .\Invoke-PostureAudit.ps1
.EXAMPLE
    # Workstation or server, Level 2, report written next to the script
    .\Invoke-PostureAudit.ps1 -Level L2
.EXAMPLE
    # From a management workstation: AD posture only
    .\Invoke-PostureAudit.ps1 -SkipOs -IncludeAd -OutputPath D:\Evidence
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
    [switch]$IncludeAd,

    [Parameter(Mandatory = $false)]
    [switch]$SkipOs,

    [Parameter(Mandatory = $false)]
    [ValidateSet('BestPractice', 'Strictest')]
    [string]$Bar = 'BestPractice',

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

$ToolName = 'Invoke-PostureAudit'
$ToolVersion = '1.0.0'
$script:QuietMode = $Quiet.IsPresent

function Write-AuditLog {
    # Console logging helper (the only place Write-Host is used, GOLDEN_STANDARDS section 5.1).
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR', 'PASS', 'FAIL')][string]$Level = 'INFO')
    if ($script:QuietMode) { return }
    $colors = @{ INFO = 'Cyan'; WARN = 'Yellow'; ERROR = 'Red'; PASS = 'Green'; FAIL = 'Red' }
    Write-Host "[$Level] $Message" -ForegroundColor $colors[$Level]
}

function ConvertTo-PostureRow {
    # Projects a CIS result or an AD posture result onto the unified posture row.
    param([Parameter(Mandatory = $true)]$Result, [Parameter(Mandatory = $true)][ValidateSet('OS', 'AD')][string]$Scope)
    $hasFramework = { param($n) @($Result.PSObject.Properties.Name) -contains $n }
    [PSCustomObject]@{
        Scope        = $Scope
        Id           = $Result.Id
        Title        = $Result.Title
        Category     = if ($Scope -eq 'AD') { $Result.Category } else { $Result.Section }
        Status       = $Result.Status
        Expected     = $Result.Expected
        Actual       = $Result.Actual
        Bar          = if ($Scope -eq 'AD') { $Result.Bar } else { '' }
        Stig         = if (& $hasFramework 'Stig') { $Result.Stig } else { 'n/a' }
        Cis          = if ($Scope -eq 'OS') { $Result.Status } elseif (& $hasFramework 'Cis') { $Result.Cis } else { 'n/a' }
        BestPractice = if (& $hasFramework 'BestPractice') { $Result.BestPractice } else { 'n/a' }
        Source       = $Result.Source
        Detail       = $Result.Detail
    }
}

Import-Module (Join-Path $PSScriptRoot 'CisAudit\CisAudit.psm1') -Force

$executionId = [guid]::NewGuid().ToString()
$startedUtc = (Get-Date).ToUniversalTime()
$timestamp = $startedUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
$hostName = [Environment]::MachineName
$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
$hostRole = ConvertTo-CisHostRole -ProductType (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType
$catalogDir = Join-Path $PSScriptRoot '..\cis\catalogs'

Write-Verbose "Mode: $TargetEnvironment (read-only; no change is made in either mode)"
Write-AuditLog "Posture audit - host $hostName ($hostRole) - $TargetEnvironment"
if (-not $isElevated -and -not $SkipOs) {
    Write-AuditLog 'Not elevated: OS account/user-rights/audit-policy checks will report Error. Run as administrator for a full OS audit.' 'WARN'
}

$rows = @()
$osInfo = [ordered]@{ ran = $false; catalog = $null; benchmark = $null; reason = $null }

# ----------------------------------------------------------------- OS CIS audit (by role)
if (-not $SkipOs) {
    $pattern = switch ($hostRole) {
        'MemberServer' { 'windows-server-*-ms-*.json' }
        'DomainController' { 'windows-server-*-dc-*.json' }
        default { 'windows11-enterprise-v5.1.0.json' }
    }
    $found = @(Get-ChildItem -Path $catalogDir -Filter $pattern -File -ErrorAction SilentlyContinue | Sort-Object Name)
    if ($found.Count -eq 0) {
        $osInfo.reason = "OS catalog '$pattern' not found in $catalogDir - skipping OS audit (build or add the catalog for role $hostRole)."
        Write-AuditLog $osInfo.reason 'WARN'
    }
    else {
        $osCatalogPath = $found[-1].FullName
        $catalog = Import-CisCatalog -Path $osCatalogPath
        $context = Get-CisLiveContext
        $checks = Select-CisCheck -Catalog $catalog -Level $Level
        $osResults = @(foreach ($check in $checks) { Invoke-CisCheck -Check $check -Context $context })
        foreach ($r in $osResults) { $rows += ConvertTo-PostureRow -Result $r -Scope 'OS' }
        $osInfo.ran = $true
        $osInfo.catalog = (Split-Path -Leaf $osCatalogPath)
        $osInfo.benchmark = "$($catalog.benchmark) v$($catalog.version)"
        Write-AuditLog "OS audit: $($catalog.benchmark) v$($catalog.version) ($Level) - $($osResults.Count) checks"
    }
}

# ----------------------------------------------------------------- AD posture audit
$adInfo = [ordered]@{ ran = $false; domain = $null; reason = $null }
$runAd = $IncludeAd.IsPresent -or ($hostRole -eq 'DomainController')
if ($runAd) {
    try {
        Import-Module (Join-Path $PSScriptRoot 'AdPosture\AdPosture.psm1') -Force
        $adCatalogPath = Join-Path $catalogDir 'adposture\ad-posture-v1.json'
        $adCatalog = Import-AdPostureCatalog -Path $adCatalogPath
        $adContext = Get-AdPostureContext
        $adResults = @(foreach ($check in $adCatalog.checks) { Invoke-AdPostureCheck -Check $check -Context $adContext -Bar $Bar })
        foreach ($r in $adResults) { $rows += ConvertTo-PostureRow -Result $r -Scope 'AD' }
        $adInfo.ran = $true
        $adInfo.domain = $adContext.Meta.Domain
        Write-AuditLog "AD posture: domain $($adContext.Meta.Domain) (bar $Bar) - $($adResults.Count) checks"
    }
    catch {
        $adInfo.reason = "AD posture audit could not run: $($_.Exception.Message) (RSAT ActiveDirectory module and a reachable domain are required)."
        Write-AuditLog $adInfo.reason 'WARN'
    }
}

$rows = @($rows)

$summary = [ordered]@{
    total         = $rows.Count
    pass          = @($rows | Where-Object Status -eq 'Pass').Count
    fail          = @($rows | Where-Object Status -eq 'Fail').Count
    error         = @($rows | Where-Object Status -eq 'Error').Count
    notApplicable = @($rows | Where-Object Status -eq 'NotApplicable').Count
    os            = @($rows | Where-Object Scope -eq 'OS').Count
    ad            = @($rows | Where-Object Scope -eq 'AD').Count
}
$scored = $summary.pass + $summary.fail
$summary.scorePct = if ($scored -gt 0) { [math]::Round(100 * $summary.pass / $scored, 1) } else { 0 }

foreach ($r in $rows | Where-Object Status -ne 'Pass') {
    $logLevel = if ($r.Status -eq 'Fail') { 'FAIL' } elseif ($r.Status -eq 'Error') { 'ERROR' } else { 'INFO' }
    Write-AuditLog "[$($r.Scope)] $($r.Id) $($r.Title) | expected: $($r.Expected) | actual: $($r.Actual)" $logLevel
}
Write-AuditLog ("Summary: {0} checks ({1} OS, {2} AD), {3} pass, {4} fail, {5} error, {6} n/a - score {7}%" -f
    $summary.total, $summary.os, $summary.ad, $summary.pass, $summary.fail, $summary.error, $summary.notApplicable, $summary.scorePct)

$report = [ordered]@{
    schema       = 'cc.posture.report/1'
    tool         = $ToolName
    version      = $ToolVersion
    execution_id = $executionId
    timestamp    = $timestamp
    host         = $hostName
    hostRole     = $hostRole
    environment  = $TargetEnvironment
    elevated     = $isElevated
    level        = $Level
    bar          = $Bar
    os           = $osInfo
    ad           = $adInfo
    failOn       = $FailOn
    summary      = $summary
    results      = $rows
}

$written = @()
if ($OutputPath) {
    if (-not (Test-Path -LiteralPath $OutputPath)) { $null = New-Item -ItemType Directory -Path $OutputPath }
    $base = Join-Path $OutputPath ("posture-{0}-{1}" -f $hostName, $startedUtc.ToString('yyyyMMddTHHmmssZ'))
    if ($Format -contains 'Json') {
        $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath "$base.json" -Encoding UTF8
        $written += "$base.json"
    }
    if ($Format -contains 'Ndjson') {
        $lines = foreach ($r in $rows) {
            $eventLevel = switch ($r.Status) { 'Fail' { 'WARN' } 'Error' { 'ERROR' } default { 'INFO' } }
            [ordered]@{
                timestamp     = $timestamp
                host          = $hostName
                tool          = $ToolName
                version       = $ToolVersion
                execution_id  = $executionId
                level         = $eventLevel
                message       = "POSTURE $($r.Scope) $($r.Id) $($r.Status)"
                environment   = $TargetEnvironment
                action        = 'posture.check'
                scope         = $r.Scope
                target        = $r.Id
                result        = $r.Status
                host_role     = $hostRole
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
        $rows | Export-Csv -LiteralPath "$base.csv" -NoTypeInformation -Encoding UTF8
        $written += "$base.csv"
    }
}
foreach ($file in $written) { Write-AuditLog "Report written: $file" }

$rows
exit (Get-CisExitCode -Results $rows -FailOn $FailOn)

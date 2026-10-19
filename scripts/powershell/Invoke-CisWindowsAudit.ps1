<#
.SYNOPSIS
    Read-only CIS Benchmark audit for Windows 11 Enterprise and Windows Server (Member Server and
    Domain Controller profiles), Level 1 / Level 2, data-driven.

.DESCRIPTION
    Script Name   : Invoke-CisWindowsAudit.ps1
    Purpose       : Audits the local host against every automatable recommendation in a CIS check
                    catalog (Windows 11 Enterprise v5.1.0, 486 checks, or a Windows Server MS / DC
                    catalog the operator builds) and
                    writes one result per recommendation: CIS ID, title, level, expected, actual,
                    Pass / Fail / NotApplicable / Error. Use it for hardening baselines, before/after
                    comparisons and compliance evidence.
    Inputs        : Catalog JSON (scripts/cis/catalogs/, built from Tenable CIS audit files with
                    tools/build_cis_catalog.py), profile level, optional ID/section filters.
    Outputs       : Result objects on the pipeline; optional JSON report, NDJSON (GOLDEN_STANDARDS
                    section 4.7, one line per check, SIEM-ready) and CSV in -OutputPath.
    Security      : Security Domain: Compliance / Hardening. Read-only in Test and Prod: reads the
                    registry, secedit /export (temporary .inf, deleted), auditpol /get and service
                    state. Run elevated: secedit and auditpol need administrator rights; without
                    them account, user-rights and audit-policy checks report Error.
    Author        : RJGProjectz
    Version       : 2.2.0
    Created       : 2026-10-08T12:30:00Z
    Last Modified : 2026-10-19T03:35:00Z
    KB Article    : docs/tasks/hardening/windows-11-cis-audit-tool.md
                    docs/tasks/hardening/windows-server-cis-audit-tool.md
    Source Repo   : https://www.cisecurity.org/benchmark/microsoft_windows_desktop
                    https://www.cisecurity.org/benchmark/microsoft_windows_server
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
    Catalog JSON. Default, by host role (Win32_OperatingSystem.ProductType): work station ->
    ..\cis\catalogs\windows11-enterprise-v5.1.0.json; member or standalone server -> the last
    windows-server-*-ms-*.json by name; domain controller -> the last windows-server-*-dc-*.json.

.PARAMETER OutputPath
    Folder for report files. Nothing is written when omitted.

.PARAMETER Format
    Report formats written to -OutputPath: Json, Ndjson, Csv (default: all three).

.PARAMETER OutputJson
    Legacy: path of a single JSON report file (same content as Format Json).

.PARAMETER SkipApplicabilityCheck
    Audit even when the host is outside the catalog's scope: another OS build or installation type,
    or a server role that does not match the catalog profile (MS vs DC). Results are then indicative
    only.

.PARAMETER FailOn
    Exit code policy for automation: None (default, always exit 0), Fail (exit 1 when any check
    fails) or FailOrError (also exit 2 when any check could not be evaluated, e.g. not elevated).

.PARAMETER Quiet
    No console summary; results still go to the pipeline and files.

.EXAMPLE
    .\Invoke-CisWindowsAudit.ps1 -Level L1 -OutputPath C:\Reports\CIS
.EXAMPLE
    .\Invoke-CisWindowsAudit.ps1 -Level L2 -Section 17 | Where-Object Status -ne 'Pass'
.EXAMPLE
    .\Invoke-CisWindowsAudit.ps1 -Id '2.3.*','18.9.*' -Format Csv -OutputPath .\out -Quiet
.EXAMPLE
    # Domain controller, Level 1, with a DC catalog built from the operator's own audit files
    .\Invoke-CisWindowsAudit.ps1 -CatalogPath ..\cis\catalogs\windows-server-2025-dc-v2.1.0.json -OutputPath D:\Evidence
.EXAMPLE
    # Scheduled compliance gate: exit 1 on drift, 2 when the audit was incomplete
    .\Invoke-CisWindowsAudit.ps1 -Level L1 -OutputPath D:\Evidence -Quiet -FailOn FailOrError
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
    [string]$CatalogPath,

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
    [ValidateSet('None', 'Fail', 'FailOrError')]
    [string]$FailOn = 'None',

    [Parameter(Mandatory = $false)]
    [switch]$Quiet
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$ToolName = 'Invoke-CisWindowsAudit'
$ToolVersion = '2.2.0'
$script:QuietMode = $Quiet.IsPresent

function Write-AuditLog {
    # Console logging helper (the only place Write-Host is used, GOLDEN_STANDARDS section 5.1).
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR', 'PASS', 'FAIL')][string]$Level = 'INFO')
    if ($script:QuietMode) { return }
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
# ProductType: 1 = work station, 2 = domain controller, 3 = server (Win32_OperatingSystem).
$hostRole = ConvertTo-CisHostRole -ProductType (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType
$catalogDir = Join-Path $PSScriptRoot '..\cis\catalogs'
if (-not $CatalogPath) {
    $pattern = switch ($hostRole) {
        'MemberServer' { 'windows-server-*-ms-*.json' }
        'DomainController' { 'windows-server-*-dc-*.json' }
        default { 'windows11-enterprise-v5.1.0.json' }
    }
    $found = @(Get-ChildItem -Path $catalogDir -Filter $pattern -File -ErrorAction SilentlyContinue | Sort-Object Name)
    $CatalogPath = if ($found.Count -gt 0) { $found[-1].FullName } else { Join-Path $catalogDir $pattern }
}
if (-not (Test-Path -LiteralPath $CatalogPath)) {
    # Server catalogs are never shipped: the operator builds them from their own audit files.
    throw ("CIS catalog not found: $CatalogPath (host role: $hostRole)`n" +
        "Generate it from your own audit files (docs/tasks/hardening/windows-11-cis-audit-tool.md, " +
        "docs/tasks/hardening/windows-server-cis-audit-tool.md), e.g.:`n" +
        "  python tools/build_cis_catalog.py --benchmark `"CIS Microsoft Windows Server 2025`" --version 2.1.0 " +
        "--out scripts/cis/catalogs/windows-server-2025-ms-v2.1.0.json <..._L1_MS.audit> <..._L2_MS.audit>")
}
$catalog = Import-CisCatalog -Path $CatalogPath
$catalogProfile = if ($catalog.PSObject.Properties.Name -contains 'profile') { [string]$catalog.profile } else { '' }
$catalogSha256 = (Get-FileHash -LiteralPath $CatalogPath -Algorithm SHA256).Hash.ToLowerInvariant()
$osKey = 'HKLM\Software\Microsoft\Windows NT\CurrentVersion'
$osEdition = [string](Read-CisRegistryValue -Key $osKey -Name 'EditionID')
$osBuild = '{0}.{1}' -f (Read-CisRegistryValue -Key $osKey -Name 'CurrentBuild'), (Read-CisRegistryValue -Key $osKey -Name 'UBR')
$psInfo = '{0} {1}' -f $PSVersionTable.PSEdition, $PSVersionTable.PSVersion
Write-AuditLog "$($catalog.benchmark) v$($catalog.version) - profile $Level $catalogProfile - host $hostName ($hostRole) - $TargetEnvironment"
if (-not (Test-CisSupportedEdition -EditionId $osEdition)) {
    Write-AuditLog "Edition '$osEdition': the client benchmark targets Enterprise/Education. Home and Pro ignore many Section 18 policies, so a Pass there may not be enforced." 'WARN'
}
if (-not $isElevated) {
    Write-AuditLog 'Not elevated: account policy, user rights and audit policy checks will report Error. Run as administrator for a full audit.' 'WARN'
}

$context = Get-CisLiveContext

# Applicability: the catalog says which OS it is written for (build, installation type), and a
# server catalog's profile must match the role: MS rules on a DC (or the reverse) give wrong results.
$applicable = $true
if (-not (Test-CisCatalogRole -Catalog $catalog -HostRole $hostRole)) {
    $applicable = $false
    Write-AuditLog "Catalog profile '$catalogProfile' does not match host role '$hostRole'." 'WARN'
}
foreach ($test in @($catalog.applicability)) {
    if ((Invoke-CisTest -Test $test -Context $context).Status -ne 'Pass') { $applicable = $false }
}
if (-not $applicable) {
    if (-not $SkipApplicabilityCheck) {
        throw "Host is not covered by '$($catalog.benchmark)' $catalogProfile (build, installation type or role check failed). Use -SkipApplicabilityCheck to audit anyway."
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
    powershell       = $psInfo
    osEdition        = $osEdition
    osBuild          = $osBuild
    hostRole         = $hostRole
    auditPolicySource = $context.AuditPolicySource
    catalog          = [ordered]@{ path = (Split-Path -Leaf $CatalogPath); sha256 = $catalogSha256 }
    failOn           = $FailOn
    benchmark        = $catalog.benchmark
    benchmarkVersion = $catalog.version
    profile          = $Level
    benchmarkProfile = $catalogProfile
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
                catalog_sha256    = $catalogSha256
                os_edition        = $osEdition
                os_build          = $osBuild
                host_role         = $hostRole
                benchmark_profile = $catalogProfile
                elevated          = $isElevated
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
# Exit code is decided by -FailOn only (auditpol leaves a non-zero native exit code when denied).
exit (Get-CisExitCode -Results $results -FailOn $FailOn)

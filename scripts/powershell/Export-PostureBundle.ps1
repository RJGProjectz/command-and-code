<#
.SYNOPSIS
    Bundles the local posture-audit report files on an endpoint into one zip plus a small manifest,
    so the evidence can be carried back to a worker over SMB, SSH/SCP or physical media. Runs
    entirely LOCALLY on the endpoint: no PowerShell remoting, WinRM or network calls of any kind.

.DESCRIPTION
    Script Name   : Export-PostureBundle.ps1
    Purpose       : The endpoint-side half of the WP-97 posture-audit retrieval flow. The audit
                    scripts (Invoke-PostureAudit.ps1 / Invoke-AdPostureAudit.ps1 / the standalone
                    CIS tool) each write their report files next to themselves on the audited asset.
                    This script collects those files (posture-*, adposture-*, cis-*) into a single
                    posture-bundle-<HOST>-<UTC>.zip and writes a posture-bundle-<HOST>-<UTC>.manifest.json
                    beside it, giving the operator one artifact per host to retrieve and verify.
    Inputs        : Report files produced by the posture audits, found in -SourcePath.
    Outputs       : posture-bundle-<HOST>-<UTC>.zip and posture-bundle-<HOST>-<UTC>.manifest.json in
                    -OutputPath (both default to the script's own folder). The manifest lists host,
                    UTC, the bundled files and the pass/fail/score pulled from the newest posture or
                    AD-posture JSON summary when one is present.
    Security      : Security Domain: Compliance / Hardening. Read-only with respect to the audited
                    host's configuration: it only reads existing report files and writes a zip and a
                    manifest. It makes NO network connection and uses NO remoting (no Invoke-Command,
                    New-PSSession or WinRM). Nothing else on the host is changed.
    Author        : RJGProjectz
    Version       : 1.0.0
    Created       : 2026-10-26T00:00:00Z
    Last Modified : 2026-10-26T00:00:00Z
    KB Article    : docs/tasks/assurance/posture-audit-lab-test.md
    API Standards : Manifest schema cc.posture.bundle/1.

.PARAMETER TargetEnvironment
    'Test' (default) or 'Prod'. The script is read-only and behaves the same in both; recorded in the
    manifest.

.PARAMETER SourcePath
    Folder to collect report files from. Default: this script's own folder ($PSScriptRoot), which is
    where the audit scripts write their reports.

.PARAMETER OutputPath
    Folder to write the bundle zip and manifest into. Default: this script's own folder ($PSScriptRoot).

.PARAMETER Latest
    Bundle only the newest set per report type (newest posture-*, newest adposture-*, newest cis-*)
    instead of every matching file. A "set" is the json/ndjson/csv that share one run's base name.

.PARAMETER RunAudit
    If Invoke-PostureAudit.ps1 exists in -SourcePath, run it first (read-only) so a fresh report is
    bundled. Tolerates its absence (warns and bundles whatever reports already exist).

.PARAMETER Quiet
    No console log; the bundle and manifest are still written.

.EXAMPLE
    .\Export-PostureBundle.ps1
.EXAMPLE
    # Run the audit first, then bundle only the newest report set
    .\Export-PostureBundle.ps1 -RunAudit -Latest
.EXAMPLE
    # Collect reports from a staging folder and drop the bundle on a USB drive
    .\Export-PostureBundle.ps1 -SourcePath D:\Evidence -OutputPath E:\
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Test', 'Prod')]
    [string]$TargetEnvironment = 'Test',

    [Parameter(Mandatory = $false)]
    [string]$SourcePath = $PSScriptRoot,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = $PSScriptRoot,

    [Parameter(Mandatory = $false)]
    [switch]$Latest,

    [Parameter(Mandatory = $false)]
    [switch]$RunAudit,

    [Parameter(Mandatory = $false)]
    [switch]$Quiet
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$ToolName = 'Export-PostureBundle'
$ToolVersion = '1.0.0'
$script:QuietMode = $Quiet.IsPresent

function Write-BundleLog {
    # Console logging helper (the only place Write-Host is used, GOLDEN_STANDARDS section 5.1).
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO')
    if ($script:QuietMode) { return }
    $colors = @{ INFO = 'Cyan'; WARN = 'Yellow'; ERROR = 'Red' }
    Write-Host "[$Level] $Message" -ForegroundColor $colors[$Level]
}

function Get-SummaryFromReport {
    # Reads pass/fail/score from a posture or AD-posture JSON report, StrictMode-safe. Returns $null
    # when the file cannot be read or carries no recognisable summary.
    param([string]$Path)
    try {
        $json = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    }
    catch {
        return $null
    }
    if (@($json.PSObject.Properties.Name) -notcontains 'summary' -or $null -eq $json.summary) { return $null }
    $s = $json.summary
    $names = @($s.PSObject.Properties.Name)
    [ordered]@{
        source   = (Split-Path -Leaf $Path)
        pass     = if ($names -contains 'pass') { $s.pass } else { $null }
        fail     = if ($names -contains 'fail') { $s.fail } else { $null }
        error    = if ($names -contains 'error') { $s.error } else { $null }
        total    = if ($names -contains 'total') { $s.total } else { $null }
        scorePct = if ($names -contains 'scorePct') { $s.scorePct } else { $null }
    }
}

Write-Verbose "Mode: $TargetEnvironment (read-only; no remoting, no network, no change to host config)"
$hostName = [Environment]::MachineName
$startedUtc = (Get-Date).ToUniversalTime()
$stamp = $startedUtc.ToString('yyyyMMddTHHmmssZ')
$timestamp = $startedUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
Write-BundleLog "Posture bundle - host $hostName - $TargetEnvironment - source $SourcePath"

# ----------------------------------------------------------------- optionally run the audit first
if ($RunAudit) {
    $auditScript = Join-Path $SourcePath 'Invoke-PostureAudit.ps1'
    if (Test-Path -LiteralPath $auditScript) {
        Write-BundleLog "Running Invoke-PostureAudit.ps1 (read-only) before bundling"
        & $auditScript -TargetEnvironment $TargetEnvironment -OutputPath $SourcePath -Quiet:$script:QuietMode | Out-Null
    }
    else {
        Write-BundleLog "Invoke-PostureAudit.ps1 not found in $SourcePath - bundling existing reports only" 'WARN'
    }
}

# ----------------------------------------------------------------- gather report files
if (-not (Test-Path -LiteralPath $SourcePath)) {
    throw "SourcePath '$SourcePath' does not exist."
}
# posture-*, adposture-* and cis-* reports, but never a previous bundle or its manifest.
$reportPatterns = @('posture-*', 'adposture-*', 'cis-*')
$allFiles = foreach ($pattern in $reportPatterns) {
    Get-ChildItem -LiteralPath $SourcePath -Filter $pattern -File -ErrorAction SilentlyContinue
}
$allFiles = @($allFiles | Where-Object { $_.Name -notlike 'posture-bundle-*' } | Sort-Object FullName -Unique)

$selected = if ($Latest) {
    $prefixes = @('posture', 'adposture', 'cis')
    $perType = foreach ($prefix in $prefixes) {
        $ofType = @($allFiles | Where-Object { $_.Name -like "$prefix-*" })
        if ($ofType.Count -eq 0) { continue }
        $newestBase = (@($ofType | Sort-Object LastWriteTimeUtc -Descending)[0]).BaseName
        $ofType | Where-Object { $_.BaseName -eq $newestBase }
    }
    @($perType)
}
else {
    $allFiles
}
$selected = @($selected)

if ($selected.Count -eq 0) {
    Write-BundleLog "No posture report files (posture-*, adposture-*, cis-*) found in $SourcePath - nothing to bundle." 'WARN'
}

# ----------------------------------------------------------------- summary for the manifest
$summaryFile = @($allFiles | Where-Object { $_.Name -like 'posture-*.json' } | Sort-Object LastWriteTimeUtc -Descending)
if ($summaryFile.Count -eq 0) {
    $summaryFile = @($allFiles | Where-Object { $_.Name -like 'adposture-*.json' } | Sort-Object LastWriteTimeUtc -Descending)
}
$summary = if ($summaryFile.Count -gt 0) { Get-SummaryFromReport -Path $summaryFile[0].FullName } else { $null }

# ----------------------------------------------------------------- write the bundle and manifest
if (-not (Test-Path -LiteralPath $OutputPath)) { $null = New-Item -ItemType Directory -Path $OutputPath }
$bundleBase = "posture-bundle-{0}-{1}" -f $hostName, $stamp
$zipPath = Join-Path $OutputPath "$bundleBase.zip"
$manifestPath = Join-Path $OutputPath "$bundleBase.manifest.json"

if ($selected.Count -gt 0) {
    Compress-Archive -LiteralPath @($selected.FullName) -DestinationPath $zipPath -Force
    Write-BundleLog "Bundle written: $zipPath ($($selected.Count) file(s))"
}

$manifest = [ordered]@{
    schema      = 'cc.posture.bundle/1'
    tool        = $ToolName
    version     = $ToolVersion
    timestamp   = $timestamp
    host        = $hostName
    environment = $TargetEnvironment
    latestOnly  = $Latest.IsPresent
    zip         = if ($selected.Count -gt 0) { (Split-Path -Leaf $zipPath) } else { $null }
    fileCount   = $selected.Count
    files       = @($selected | ForEach-Object { $_.Name })
    summary     = $summary
}
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
Write-BundleLog "Manifest written: $manifestPath"
if ($summary) {
    Write-BundleLog ("Newest summary ({0}): {1} pass, {2} fail - score {3}%" -f $summary.source, $summary.pass, $summary.fail, $summary.scorePct)
}

[PSCustomObject]@{
    Host     = $hostName
    Zip      = if ($selected.Count -gt 0) { $zipPath } else { $null }
    Manifest = $manifestPath
    Files    = $selected.Count
}

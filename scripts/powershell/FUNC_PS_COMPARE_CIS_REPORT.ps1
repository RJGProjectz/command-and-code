<#
.SYNOPSIS
    Before/after diff of two CIS audit reports: what a hardening change fixed, what it broke, what it left failing.

.DESCRIPTION
    Script Name: FUNC_PS_COMPARE_CIS_REPORT
    Compares a baseline and a current report from the CIS audit tools, which share one result schema:
    Invoke-CisWindowsAudit.ps1 (Windows 11 / Server) and audit_cis_linux.sh (Ubuntu 24.04 / RHEL 9).
    Accepted inputs, detected from the content:

      JSON    cc.cis.report/1 report (results[] with Id, Title, Status, Expected, Actual)
      NDJSON  one cis.check event per line (cis_id, title, result, expected, actual), e.g. Linux stdout
      CSV     Id,Title,Level,Section,Status,Expected,Actual,Source,Detail

    Each recommendation in either report gets one change class:

      Fixed          Fail or Error -> Pass
      Regressed      Pass -> Fail or Error
      StatusChanged  any other status change (NotApplicable <-> Pass/Fail, Fail <-> Error)
      ActualChanged  same status, different actual value (e.g. still failing, but closer)
      Unchanged      same status and actual value (reported only with -IncludeUnchanged)
      Added          only in the current report
      Removed        only in the baseline

    Read-only: the two reports are only read; the diff goes to the pipeline, the NDJSON log and, with
    -OutputPath, to JSON and CSV files. A warning is logged when host, benchmark or profile differ.

.PARAMETER TargetEnvironment
    'Test' or 'Prod'. Defaults to 'Test'. Recorded in each event; nothing differs between the two.

.PARAMETER BaselinePath
    Report taken before the change (JSON, NDJSON or CSV).

.PARAMETER CurrentPath
    Report taken after the change.

.PARAMETER IncludeUnchanged
    Also emit Unchanged recommendations.

.PARAMETER OutputPath
    Directory for cis-diff-<UTC time>.json (summary + changes) and .csv. Optional.

.PARAMETER FailOn
    None (default) or Regression: exit code 1 when at least one recommendation regressed (CI or change gate).

.PARAMETER LogPath
    Directory for the text log and NDJSON event log. Defaults to .\Logs beside the script.

.EXAMPLE
    .\FUNC_PS_COMPARE_CIS_REPORT.ps1 -BaselinePath .\before\cis-pc01-L1.json -CurrentPath .\after\cis-pc01-L1.json |
        Format-Table cis_id, change, before, after, actual_after

.EXAMPLE
    pwsh ./FUNC_PS_COMPARE_CIS_REPORT.ps1 -BaselinePath before.ndjson -CurrentPath after.ndjson -FailOn Regression -OutputPath ./diff
    Linux reports (NDJSON from audit_cis_linux.sh); exit 1 when the change made any recommendation fail.

.OUTPUTS
    PSCustomObject per changed recommendation; summary and changes as NDJSON in <LogPath>\FUNC_PS_COMPARE_CIS_REPORT.ndjson.

.NOTES
    Purpose: Prove what a hardening rollout changed, and catch regressions from later changes (drift).
    Security Context: a recommendation that silently returns to Fail after a GPO, image or package change
        reopens the exposure the benchmark closed; the diff makes that visible per change window.
    Security Domain: Governance / Compliance
    Author: RJGProjectz
    Version: 1.0.0
    Created: 2026-10-20T02:15:00Z
    Last Modified: 2026-10-20T02:15:00Z
    KB Article: [CIS hardening lab test](../../docs/tasks/hardening/cis-hardening-lab-test.md)
    Source Repo: [Invoke-CisWindowsAudit.ps1](Invoke-CisWindowsAudit.ps1), [audit_cis_linux.sh](../bash/audit_cis_linux.sh)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Test', 'Prod')]
    [string]$TargetEnvironment = 'Test',

    [Parameter(Mandatory = $true)]
    [string]$BaselinePath,

    [Parameter(Mandatory = $true)]
    [string]$CurrentPath,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeUnchanged,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [ValidateSet('None', 'Regression')]
    [string]$FailOn = 'None',

    [Parameter(Mandatory = $false)]
    [string]$LogPath = (Join-Path $PSScriptRoot 'Logs')
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$ScriptName = 'FUNC_PS_COMPARE_CIS_REPORT'
$ScriptVersion = '1.0.0'
$ExecutionId = [guid]::NewGuid().ToString()
$HostName = [Environment]::MachineName
if (-not (Test-Path -LiteralPath $LogPath)) { $null = New-Item -ItemType Directory -Path $LogPath -Force }

# --- Logging Helper ---
function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )
    $timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $colors = @{ INFO = 'Cyan'; WARN = 'Yellow'; ERROR = 'Red' }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $colors[$Level]
    Write-Event -Entry ([ordered]@{ level = $Level; action = 'log'; message = $Message })
    Add-Content -LiteralPath (Join-Path $LogPath 'ScriptLog.log') -Value "[$timestamp] [$Level] $Message"
}

function Write-Event {
    param([Parameter(Mandatory = $true)][System.Collections.Specialized.OrderedDictionary]$Entry)
    if (-not (Test-Path -LiteralPath $LogPath)) { $null = New-Item -ItemType Directory -Path $LogPath -Force }
    $line = [ordered]@{
        timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); host = $HostName; tool = $ScriptName
        version = $ScriptVersion; execution_id = $ExecutionId; environment = $TargetEnvironment
    }
    foreach ($key in $Entry.Keys) { $line[$key] = $Entry[$key] }
    Add-Content -LiteralPath (Join-Path $LogPath "$ScriptName.ndjson") -Value ($line | ConvertTo-Json -Compress -Depth 4)
}

function Get-PropertyValue {
    param($Object, [string[]]$Names)
    foreach ($name in $Names) {
        $property = $Object.PSObject.Properties[$name]
        if ($null -ne $property -and $null -ne $property.Value) { return [string]$property.Value }
    }
    return ''
}

function Import-CisReport {
    <#
    .SYNOPSIS
        Reads a CIS report (JSON, NDJSON or CSV) into metadata and a hashtable of results keyed by recommendation ID.
    .EXAMPLE
        Import-CisReport -Path .\cis-pc01-L1.json
    #>
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Report not found: $Path" }
    $text = (Get-Content -LiteralPath $Path -Raw -Encoding UTF8).TrimStart([char]0xFEFF).Trim()
    $meta = [ordered]@{ path = $Path; format = ''; host = ''; benchmark = ''; profile = ''; timestamp = '' }
    $rows = @()
    $report = $null
    if ($text.StartsWith('{')) {
        # A whole-file parse succeeds for the JSON report and fails on NDJSON (several top-level objects).
        try { $report = $text | ConvertFrom-Json } catch [System.Exception] { $report = $null }
        if ($null -ne $report -and $null -eq $report.PSObject.Properties['results']) { $report = $null }
    }
    if ($null -ne $report) {
        $meta.format = 'json'; $meta.host = Get-PropertyValue $report @('host')
        $meta.benchmark = Get-PropertyValue $report @('benchmark'); $meta.profile = Get-PropertyValue $report @('profile')
        $meta.timestamp = Get-PropertyValue $report @('timestamp')
        $rows = @($report.results)
    } elseif ($text.StartsWith('{')) {
        $meta.format = 'ndjson'
        $rows = @(foreach ($line in ($text -split "`r?`n")) {
                if (-not $line.Trim()) { continue }
                $item = $line | ConvertFrom-Json
                if ((Get-PropertyValue $item @('action')) -ne 'cis.check') { continue }
                if (-not $meta.host) {
                    $meta.host = Get-PropertyValue $item @('host'); $meta.benchmark = Get-PropertyValue $item @('benchmark')
                    $meta.profile = Get-PropertyValue $item @('profile'); $meta.timestamp = Get-PropertyValue $item @('timestamp')
                }
                $item
            })
    } else {
        $meta.format = 'csv'
        $rows = @($text | ConvertFrom-Csv)
    }
    $results = @{}
    foreach ($row in $rows) {
        $id = Get-PropertyValue $row @('Id', 'cis_id')
        if (-not $id) { continue }
        $results[$id] = [PSCustomObject]@{
            Id       = $id
            Title    = Get-PropertyValue $row @('Title', 'title')
            Status   = Get-PropertyValue $row @('Status', 'result')
            Expected = Get-PropertyValue $row @('Expected', 'expected')
            Actual   = Get-PropertyValue $row @('Actual', 'actual')
        }
    }
    if ($results.Count -eq 0) { throw "No CIS results found in $Path (expected cc.cis.report/1 JSON, cis.check NDJSON or the audit CSV)." }
    return [PSCustomObject]@{ Meta = $meta; Results = $results }
}

function Get-CisChangeClass {
    <#
    .SYNOPSIS
        Change class for one recommendation from its baseline and current result (either may be $null).
    .EXAMPLE
        Get-CisChangeClass -Before $baseline.Results['1.1.1'] -After $current.Results['1.1.1']
    #>
    param($Before, $After)
    if ($null -eq $Before) { return 'Added' }
    if ($null -eq $After) { return 'Removed' }
    $bad = @('Fail', 'Error')
    if ($Before.Status -eq $After.Status) {
        if ($Before.Actual -eq $After.Actual) { return 'Unchanged' }
        return 'ActualChanged'
    }
    if ($After.Status -eq 'Pass' -and $bad -contains $Before.Status) { return 'Fixed' }
    if ($Before.Status -eq 'Pass' -and $bad -contains $After.Status) { return 'Regressed' }
    return 'StatusChanged'
}

function Get-CisScore {
    param([hashtable]$Results)
    $pass = @($Results.Values | Where-Object { $_.Status -eq 'Pass' }).Count
    $fail = @($Results.Values | Where-Object { $_.Status -eq 'Fail' }).Count
    if (($pass + $fail) -eq 0) { return 0 }
    return [math]::Round(100 * $pass / ($pass + $fail), 1)
}

# --- Begin ---
Write-Log "Starting $ScriptName $ScriptVersion in [$TargetEnvironment] mode (read-only)."
$baseline = Import-CisReport -Path $BaselinePath
$current = Import-CisReport -Path $CurrentPath
Write-Log "Baseline: $($baseline.Results.Count) results ($($baseline.Meta.format)); current: $($current.Results.Count) results ($($current.Meta.format))."
foreach ($field in 'host', 'benchmark', 'profile') {
    $before = $baseline.Meta[$field]; $after = $current.Meta[$field]
    if ($before -and $after -and $before -ne $after) {
        Write-Log "Reports differ in $field ('$before' vs '$after'): the diff compares recommendation IDs only." 'WARN'
    }
}

$order = @{ Regressed = 0; Fixed = 1; StatusChanged = 2; ActualChanged = 3; Added = 4; Removed = 5; Unchanged = 6 }
$ids = @($baseline.Results.Keys) + @($current.Results.Keys) | Sort-Object -Unique
$changes = @(foreach ($id in $ids) {
        $before = $baseline.Results[$id]; $after = $current.Results[$id]
        $class = Get-CisChangeClass -Before $before -After $after
        if ($class -eq 'Unchanged' -and -not $IncludeUnchanged) { continue }
        $known = if ($null -ne $after) { $after } else { $before }
        [PSCustomObject][ordered]@{
            cis_id        = $id
            title         = $known.Title
            change        = $class
            before        = if ($null -ne $before) { $before.Status } else { '' }
            after         = if ($null -ne $after) { $after.Status } else { '' }
            expected      = $known.Expected
            actual_before = if ($null -ne $before) { $before.Actual } else { '' }
            actual_after  = if ($null -ne $after) { $after.Actual } else { '' }
        }
    }) | Sort-Object @{ Expression = { $order[$_.change] } }, @{ Expression = { $_.cis_id } }
$changes = @($changes)

$allClasses = @(foreach ($id in $ids) { Get-CisChangeClass -Before $baseline.Results[$id] -After $current.Results[$id] })
$summary = [ordered]@{
    baseline_score = Get-CisScore -Results $baseline.Results
    current_score  = Get-CisScore -Results $current.Results
}
foreach ($class in $order.Keys | Sort-Object { $order[$_] }) {
    $summary[$class.ToLowerInvariant()] = @($allClasses | Where-Object { $_ -eq $class }).Count
}

foreach ($change in $changes) {
    $level = switch ($change.change) { 'Regressed' { 'WARN' } 'Removed' { 'WARN' } default { 'INFO' } }
    $entry = [ordered]@{
        level = $level; action = 'cis.diff'; message = "CIS $($change.cis_id) $($change.change) ($($change.before) -> $($change.after))"
        target = $change.cis_id; result = $change.change
    }
    foreach ($property in $change.PSObject.Properties) { $entry[$property.Name] = $property.Value }
    Write-Event -Entry $entry
    $change
}

$regressed = $summary.regressed
$summaryEntry = [ordered]@{
    level = if ($regressed -gt 0) { 'WARN' } else { 'INFO' }; action = 'cis.diff.summary'
    message = ("Score {0}% -> {1}%: {2} fixed, {3} regressed, {4} status changed, {5} actual changed, {6} added, {7} removed" -f
        $summary.baseline_score, $summary.current_score, $summary.fixed, $summary.regressed, $summary.statuschanged,
        $summary.actualchanged, $summary.added, $summary.removed)
    result = if ($regressed -gt 0) { 'Regressed' } else { 'NoRegression' }
    summary = $summary
}
Write-Event -Entry $summaryEntry
Write-Log $summaryEntry.message $summaryEntry.level

if ($OutputPath) {
    if (-not (Test-Path -LiteralPath $OutputPath)) { $null = New-Item -ItemType Directory -Path $OutputPath -Force }
    $base = Join-Path $OutputPath ('cis-diff-{0}' -f (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))
    [ordered]@{
        schema = 'cc.cis.diff/1'; tool = $ScriptName; version = $ScriptVersion; execution_id = $ExecutionId
        timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); environment = $TargetEnvironment
        baseline = $baseline.Meta; current = $current.Meta; summary = $summary; changes = $changes
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath "$base.json" -Encoding UTF8
    $changes | Export-Csv -LiteralPath "$base.csv" -NoTypeInformation -Encoding UTF8
    Write-Log "Diff written: $base.json, $base.csv"
}

# --- End ---
Write-Log "Script completed."
if ($FailOn -eq 'Regression' -and $regressed -gt 0) { exit 1 }

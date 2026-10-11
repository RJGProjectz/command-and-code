<#
.SYNOPSIS
    Runs PSScriptAnalyzer over the repository and fails on findings not in the baseline.

.DESCRIPTION
    Lints scripts/powershell and tests/powershell with templates/PSScriptAnalyzerSettings.psd1.
    Each finding is keyed by file, rule and the first line of the offending code (not the line
    number, so unrelated edits do not churn the baseline). A key that occurs more often than the
    baseline allows fails the run. Keys that occur less often are reported so the baseline can
    be tightened with -UpdateBaseline.

.PARAMETER UpdateBaseline
    Rewrite the baseline file from the current findings instead of gating.

.EXAMPLE
    pwsh tests/lint/Invoke-PSScriptAnalyzerGate.ps1

.NOTES
    security_domain: Code Quality
    Author: RJGProjectz
    Created: 2026-10-11T19:00:00Z
    Last Modified: 2026-10-11T19:00:00Z
#>
[CmdletBinding()]
param(
    [switch]$UpdateBaseline
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$settings = Join-Path $repoRoot 'templates/PSScriptAnalyzerSettings.psd1'
$baselinePath = Join-Path $PSScriptRoot 'pssa-baseline.json'
$targets = @('scripts/powershell', 'tests/powershell', 'tests/lint')

Import-Module PSScriptAnalyzer

$findings = foreach ($target in $targets) {
    Invoke-ScriptAnalyzer -Path (Join-Path $repoRoot $target) -Recurse -Settings $settings
}
# Write-Log is the logging helper GOLDEN_STANDARDS mandates in every script; PSScriptAnalyzer
# reports it as overriding a PowerShell 6.1 cmdlet. Ignore only that case of the rule.
$findings = @($findings | Where-Object {
    -not ($_.RuleName -eq 'PSAvoidOverwritingBuiltInCmdlets' -and $_.Message -like "'Write-Log'*")
})

$current = @{}
$sample = @{}
foreach ($f in $findings) {
    $relative = [IO.Path]::GetRelativePath($repoRoot, $f.ScriptPath).Replace('\', '/')
    $code = if ($f.Extent -and $f.Extent.Text) { ($f.Extent.Text -split "`r?`n")[0].Trim() } else { '' }
    $key = "$relative|$($f.RuleName)|$code"
    $current[$key] = 1 + $(if ($current.ContainsKey($key)) { $current[$key] } else { 0 })
    if (-not $sample.ContainsKey($key)) { $sample[$key] = $f }
}

if ($UpdateBaseline) {
    $ordered = [ordered]@{}
    foreach ($key in ($current.Keys | Sort-Object)) { $ordered[$key] = $current[$key] }
    $ordered | ConvertTo-Json | Set-Content -Path $baselinePath -Encoding utf8NoBOM
    Write-Output "Baseline written: $($current.Count) keys, $(@($findings).Count) findings."
    return
}

$baseline = @{}
if (Test-Path $baselinePath) {
    (Get-Content -Raw $baselinePath | ConvertFrom-Json).PSObject.Properties |
        ForEach-Object { $baseline[$_.Name] = [int]$_.Value }
}

$new = foreach ($key in $current.Keys) {
    $allowed = if ($baseline.ContainsKey($key)) { $baseline[$key] } else { 0 }
    if ($current[$key] -gt $allowed) { $key }
}
$fixed = foreach ($key in $baseline.Keys) {
    $now = if ($current.ContainsKey($key)) { $current[$key] } else { 0 }
    if ($now -lt $baseline[$key]) { $key }
}

foreach ($key in $fixed) { Write-Output "FIXED (tighten baseline with -UpdateBaseline): $key" }
foreach ($key in $new) {
    $detail = $sample[$key]
    Write-Output "NEW: $($key.Split('|')[0]):$($detail.Line) [$($detail.RuleName)] $($detail.Message)"
}

Write-Output "PSScriptAnalyzer: $(@($findings).Count) findings, $(@($new).Count) new, baseline $($baseline.Count) keys."
if (@($new).Count -gt 0) { exit 1 }

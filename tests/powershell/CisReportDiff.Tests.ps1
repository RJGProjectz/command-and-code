# CIS report diff tests (Pester v5)
# Runs scripts/powershell/FUNC_PS_COMPARE_CIS_REPORT.ps1 on the synthetic before/after reports in fixtures/cisdiff/
# (the same results as Windows JSON, Linux-style NDJSON and CSV), so the suite runs on the Linux CI runner.
# security_domain: Governance
# Author: RJGProjectz
# Created: 2026-10-20T02:20:00Z
# Last Modified: 2026-10-20T02:20:00Z

BeforeAll {
    $script:diffScript = Join-Path $PSScriptRoot '../../scripts/powershell/FUNC_PS_COMPARE_CIS_REPORT.ps1'
    $script:fixtures = Join-Path $PSScriptRoot 'fixtures/cisdiff'

    function Invoke-Diff {
        param([string]$Before = 'before.json', [string]$After = 'after.json', [hashtable]$Extra = @{})
        $logDir = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        $arguments = @{
            BaselinePath = (Join-Path $script:fixtures $Before)
            CurrentPath  = (Join-Path $script:fixtures $After)
            LogPath      = $logDir
        }
        foreach ($key in $Extra.Keys) { $arguments[$key] = $Extra[$key] }
        $changes = @(& $script:diffScript @arguments 6> $null)
        $events = @(Get-Content -LiteralPath (Join-Path $logDir 'FUNC_PS_COMPARE_CIS_REPORT.ndjson') | ForEach-Object { $_ | ConvertFrom-Json })
        [PSCustomObject]@{ Changes = $changes; Events = $events; LogDir = $logDir }
    }

    function Get-Change {
        param($Changes, [string]$Id)
        @($Changes | Where-Object { $_.cis_id -eq $Id })[0]
    }

    $script:json = Invoke-Diff
}

Describe 'FUNC_PS_COMPARE_CIS_REPORT: change classes' {
    It 'classifies every kind of change' {
        (Get-Change $script:json.Changes '1.1.2').change | Should -Be 'Fixed'
        (Get-Change $script:json.Changes '2.3.1').change | Should -Be 'Regressed'
        (Get-Change $script:json.Changes '9.1.1').change | Should -Be 'StatusChanged'
        (Get-Change $script:json.Changes '2.3.2').change | Should -Be 'ActualChanged'
        (Get-Change $script:json.Changes '18.2.1').change | Should -Be 'Added'
        (Get-Change $script:json.Changes '18.1.1').change | Should -Be 'Removed'
    }

    It 'omits unchanged results unless asked' {
        Get-Change $script:json.Changes '1.1.1' | Should -BeNullOrEmpty
        $all = Invoke-Diff -Extra @{ IncludeUnchanged = $true }
        (Get-Change $all.Changes '1.1.1').change | Should -Be 'Unchanged'
    }

    It 'lists regressions first' {
        $script:json.Changes[0].change | Should -Be 'Regressed'
    }

    It 'keeps both actual values' {
        $change = Get-Change $script:json.Changes '2.3.2'
        $change.actual_before | Should -Be '60'
        $change.actual_after | Should -Be '30'
        $change.expected | Should -Be '1..15'
    }
}

Describe 'FUNC_PS_COMPARE_CIS_REPORT: formats and summary' {
    It 'gives the same diff for NDJSON and CSV inputs' {
        $mixed = Invoke-Diff -Before 'before.ndjson' -After 'after.csv'
        $left = @($script:json.Changes | ForEach-Object { "$($_.cis_id)=$($_.change)" })
        $right = @($mixed.Changes | ForEach-Object { "$($_.cis_id)=$($_.change)" })
        $right | Should -Be $left
    }

    It 'writes a summary event with both scores' {
        $summary = @($script:json.Events | Where-Object { $_.action -eq 'cis.diff.summary' })[0]
        $summary.summary.baseline_score | Should -Be 40
        $summary.summary.current_score | Should -Be 66.7
        $summary.summary.fixed | Should -Be 1
        $summary.summary.regressed | Should -Be 1
        $summary.result | Should -Be 'Regressed'
        $summary.level | Should -Be 'WARN'
    }

    It 'writes one cis.diff event per change with the mandatory fields' {
        $diffEvents = @($script:json.Events | Where-Object { $_.action -eq 'cis.diff' })
        $diffEvents.Count | Should -Be $script:json.Changes.Count
        foreach ($item in $diffEvents) {
            foreach ($field in 'timestamp', 'host', 'tool', 'version', 'execution_id', 'level', 'action', 'result', 'environment') {
                $item.PSObject.Properties.Name | Should -Contain $field
            }
        }
    }

    It 'writes JSON and CSV files with -OutputPath' {
        $out = Join-Path $TestDrive 'diff-out'
        $null = Invoke-Diff -Extra @{ OutputPath = $out }
        $report = Get-Content -LiteralPath (Get-ChildItem -Path $out -Filter '*.json')[0].FullName -Raw | ConvertFrom-Json
        $report.schema | Should -Be 'cc.cis.diff/1'
        @($report.changes).Count | Should -Be 6
        @(Import-Csv -LiteralPath (Get-ChildItem -Path $out -Filter '*.csv')[0].FullName).Count | Should -Be 6
    }

    It 'refuses a file without CIS results' {
        $empty = Join-Path $TestDrive 'empty.csv'
        Set-Content -LiteralPath $empty -Value 'Name,Value'
        { & $script:diffScript -BaselinePath $empty -CurrentPath (Join-Path $script:fixtures 'after.json') -LogPath (Join-Path $TestDrive 'e') 6> $null } |
            Should -Throw '*No CIS results*'
    }
}

Describe 'FUNC_PS_COMPARE_CIS_REPORT: exit code' {
    It 'exits 1 on a regression with -FailOn Regression and 0 without one' {
        $pwsh = (Get-Process -Id $PID).Path
        $log = Join-Path $TestDrive 'exit'
        & $pwsh -NoProfile -File $script:diffScript -BaselinePath (Join-Path $script:fixtures 'before.json') `
            -CurrentPath (Join-Path $script:fixtures 'after.json') -FailOn Regression -LogPath $log *> $null
        $LASTEXITCODE | Should -Be 1
        & $pwsh -NoProfile -File $script:diffScript -BaselinePath (Join-Path $script:fixtures 'after.json') `
            -CurrentPath (Join-Path $script:fixtures 'after.json') -FailOn Regression -LogPath $log *> $null
        $LASTEXITCODE | Should -Be 0
    }
}

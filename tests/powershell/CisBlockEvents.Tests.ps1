# CIS block monitor tests (Pester v5)
# Runs scripts/powershell/FUNC_PS_GET_CIS_BLOCK_EVENTS.ps1 with -InputPath against the synthetic exported events
# in fixtures/cisblock/, so no event log is read and the suite runs on the Linux CI runner.
# security_domain: Compliance / Detection
# Author: RJGProjectz
# Created: 2026-10-19T17:45:00Z
# Last Modified: 2026-10-19T17:45:00Z

BeforeAll {
    $script:monitor = Join-Path $PSScriptRoot '../../scripts/powershell/FUNC_PS_GET_CIS_BLOCK_EVENTS.ps1'
    $script:events = Join-Path $PSScriptRoot 'fixtures/cisblock/events-sample.xml'
    $script:catalog = Join-Path $PSScriptRoot 'fixtures/cisblock/catalog-asr.json'

    function Invoke-Monitor {
        param([hashtable]$Extra = @{})
        $logDir = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        $arguments = @{ InputPath = $script:events; CatalogPath = $script:catalog; LogPath = $logDir }
        foreach ($key in $Extra.Keys) { $arguments[$key] = $Extra[$key] }
        $records = @(& $script:monitor @arguments 6> $null)
        [PSCustomObject]@{ Records = $records; LogDir = $logDir }
    }

    function Get-Record {
        param($Records, [int]$EventId)
        @($Records | Where-Object { $_.event_id -eq $EventId })
    }

    $script:blocks = Invoke-Monitor
    $script:all = Invoke-Monitor -Extra @{ IncludeAudit = $true }
}

Describe 'FUNC_PS_GET_CIS_BLOCK_EVENTS: event selection' {
    It 'reports blocks only by default' {
        $script:blocks.Records.Count | Should -Be 5
        @($script:blocks.Records | Where-Object { $_.result -ne 'Blocked' }).Count | Should -Be 0
    }

    It 'adds audit-mode events with -IncludeAudit' {
        $script:all.Records.Count | Should -Be 7
        @(Get-Record $script:all.Records 8003)[0].result | Should -Be 'Audited'
        @(Get-Record $script:all.Records 1122)[0].result | Should -Be 'Audited'
    }

    It 'ignores events that are not block events' {
        Get-Record $script:all.Records 11707 | Should -BeNullOrEmpty
        Get-Record $script:all.Records 4624 | Should -BeNullOrEmpty
    }

    It 'matches Windows Installer IDs only for the MsiInstaller provider' {
        $msi = @(Get-Record $script:all.Records 1008)
        $msi.Count | Should -Be 1
        $msi[0].control | Should -Be 'WindowsInstaller'
        $msi[0].path | Should -Be 'C:\Users\erin\Downloads\setup.msi'
    }
}

Describe 'FUNC_PS_GET_CIS_BLOCK_EVENTS: fields' {
    It 'reads AppLocker UserData' {
        $record = (Get-Record $script:blocks.Records 8004)[0]
        $record.control | Should -Be 'AppLocker'
        $record.path | Should -Be 'C:\Users\alice\Downloads\tool.exe'
        $record.user | Should -Be 'S-1-5-21-1-2-3-1001'
        $record.rule | Should -Be 'EXE'
        $record.event_time | Should -Be '2026-10-19T08:00:00.0000000Z'
    }

    It 'reads App Control EventData' {
        $record = (Get-Record $script:blocks.Records 3077)[0]
        $record.control | Should -Be 'AppControl'
        $record.path | Should -Be '\Device\HarddiskVolume3\Users\bob\evil.dll'
        $record.process | Should -Match 'rundll32\.exe$'
        $record.rule | Should -Be 'Fixture base policy'
    }

    It 'names the ASR rule from its GUID and maps it to the CIS recommendation by title' {
        $record = (Get-Record $script:blocks.Records 1121)[0]
        $record.rule | Should -Be 'Block all Office applications from creating child processes (d4f940ab-401b-4efc-aadc-ad5f3c50688a)'
        $record.process | Should -Match 'WINWORD\.EXE$'
        $record.user | Should -Be 'FIXTURE\carol'
        $record.cis_id | Should -Be '9.2.1'
        $record.cis_title | Should -Match 'Attack Surface Reduction'
    }

    It 'leaves cis_id empty for controls without a CIS recommendation' {
        foreach ($id in 8004, 3077, 1123, 1008) {
            (Get-Record $script:blocks.Records $id)[0].cis_id | Should -BeNullOrEmpty
        }
    }
}

Describe 'FUNC_PS_GET_CIS_BLOCK_EVENTS: NDJSON log' {
    It 'writes one cis.block event per record with the mandatory fields' {
        $lines = @(Get-Content -LiteralPath (Join-Path $script:all.LogDir 'FUNC_PS_GET_CIS_BLOCK_EVENTS.ndjson') |
                ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.action -eq 'cis.block' })
        $lines.Count | Should -Be 7
        foreach ($line in $lines) {
            foreach ($field in 'timestamp', 'host', 'tool', 'version', 'execution_id', 'level', 'action', 'result', 'environment') {
                $line.PSObject.Properties.Name | Should -Contain $field
            }
            $line.environment | Should -Be 'Test'
            $expected = if ($line.result -eq 'Audited') { 'INFO' } else { 'WARN' }
            $line.level | Should -Be $expected
        }
    }

    It 'runs without a catalog and leaves cis_id empty' {
        $run = Invoke-Monitor -Extra @{ CatalogPath = (Join-Path $TestDrive 'missing.json') }
        @($run.Records | Where-Object { $_.cis_id }).Count | Should -Be 0
    }
}

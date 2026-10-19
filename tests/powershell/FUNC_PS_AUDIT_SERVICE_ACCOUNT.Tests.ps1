# Service account audit tests (Pester v5)
# Runs scripts/powershell/FUNC_PS_AUDIT_SERVICE_ACCOUNT.ps1 against the JSON snapshot in fixtures/serviceaccount/,
# so no host, AD or RSAT is needed and the suite runs on the Linux CI runner.
# security_domain: Identity
# Author: RJGProjectz
# Created: 2026-10-18T23:00:00Z
# Last Modified: 2026-10-18T23:00:00Z

BeforeAll {
    $script:auditScript = Join-Path $PSScriptRoot '../../scripts/powershell/FUNC_PS_AUDIT_SERVICE_ACCOUNT.ps1'
    $script:fixture = Join-Path $PSScriptRoot 'fixtures/serviceaccount/snapshot-sample.json'

    function Invoke-Audit {
        param([string]$InputPath = $script:fixture, [hashtable]$Extra = @{})
        $logDir = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        $arguments = @{ InputPath = $InputPath; LogPath = $logDir } + $Extra
        $findings = @(& $script:auditScript @arguments 6> $null)
        [PSCustomObject]@{ Findings = $findings; LogDir = $logDir }
    }

    function Get-Check {
        param($Findings, [string]$Check, [string]$Account)
        @($Findings | Where-Object { $_.check -eq $Check -and (-not $Account -or $_.account -eq $Account) })
    }

    $script:run = Invoke-Audit
    $script:findings = $script:run.Findings
}

Describe 'FUNC_PS_AUDIT_SERVICE_ACCOUNT: service and task identities' {

    It 'inventories every service with its identity type' {
        $inventory = Get-Check $script:findings 'SA-SERVICE-INVENTORY'
        $inventory.Count | Should -Be 7
        ($inventory | Where-Object target -eq 'AppSvc').details.identity_type | Should -Be 'VirtualAccount'
        ($inventory | Where-Object target -eq 'WebApi').details.identity_type | Should -Be 'ManagedServiceAccount'
        ($inventory | Where-Object target -eq 'Dnscache').details.identity_type | Should -Be 'NetworkService'
    }

    It 'flags typed passwords only for named users, not gMSA, virtual or built-in accounts' {
        $typed = Get-Check $script:findings 'SA-TYPED-PASSWORD'
        @($typed.target | Sort-Object) | Should -Be @('BackupSvc', 'LegacySvc', 'ReportSvc')
    }

    It 'rates tasks by logon type and skips group tasks' {
        $tasks = Get-Check $script:findings 'SA-TASK-NAMED-USER'
        $tasks.Count | Should -Be 2
        ($tasks | Where-Object target -eq '\Example\Nightly').severity | Should -Be 'medium'
        ($tasks | Where-Object target -eq '\Example\Cleanup').severity | Should -Be 'low'
    }

    It 'reports an identity it cannot resolve as NeedsReview' {
        $missing = Get-Check $script:findings 'SA-ACCOUNT-NOT-FOUND'
        $missing.Count | Should -Be 1
        $missing[0].account | Should -Be 'svc-missing@example.test'
        $missing[0].result | Should -Be 'NeedsReview'
    }
}

Describe 'FUNC_PS_AUDIT_SERVICE_ACCOUNT: account checks' {

    It 'flags SPN user accounts, high when privileged or stale, and skips krbtgt' {
        $spn = Get-Check $script:findings 'SA-SPN-USER'
        @($spn.account | Sort-Object) | Should -Be @('svc-report', 'svc-sql')
        (Get-Check $script:findings 'SA-SPN-USER' -Account 'svc-report')[0].severity | Should -Be 'high'
        (Get-Check $script:findings 'SA-SPN-USER' -Account 'svc-sql')[0].severity | Should -Be 'medium'
    }

    It 'measures password age from the snapshot time, not the test run time' {
        $stale = Get-Check $script:findings 'SA-STALE-PASSWORD'
        @($stale.account) | Should -Be @('svc-report')
        $stale[0].details.password_age_days | Should -Be 2771
    }

    It 'honours -StalePasswordDays' {
        $strict = (Invoke-Audit -Extra @{ StalePasswordDays = 90 }).Findings
        @((Get-Check $strict 'SA-STALE-PASSWORD').account | Sort-Object) | Should -Be @('svc-batch', 'svc-report')
    }

    It 'finds privilege through adminCount, tokenGroups and local Administrators' {
        $privileged = Get-Check $script:findings 'SA-PRIVILEGED'
        @($privileged.account | Sort-Object) | Should -Be @('legacyadmin', 'svc-report')
        (Get-Check $script:findings 'SA-PRIVILEGED' -Account 'svc-report')[0].details.privileged_groups | Should -Contain 'Domain Admins'
        (Get-Check $script:findings 'SA-PRIVILEGED' -Account 'legacyadmin')[0].details.privileged_groups | Should -Contain 'local Administrators on APP01'
    }

    It 'flags host-used accounts not denied interactive logon' {
        $interactive = Get-Check $script:findings 'SA-INTERACTIVE-ALLOWED'
        @($interactive.account | Sort-Object) | Should -Be @('svc-batch', 'svc-report')
    }

    It 'returns NeedsReview for interactive logon when user rights were not collected' {
        $snapshot = Get-Content -LiteralPath $script:fixture -Raw | ConvertFrom-Json
        $snapshot.UserRights = $null
        $snapshot.CollectionErrors = @([PSCustomObject]@{ Step = 'UserRights'; Message = 'secedit exited with code 5 (run elevated).' })
        $noRights = Join-Path $TestDrive 'no-rights.json'
        $snapshot | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $noRights
        $result = (Invoke-Audit -InputPath $noRights).Findings
        @((Get-Check $result 'SA-INTERACTIVE-ALLOWED').result | Sort-Object -Unique) | Should -Be @('NeedsReview')
        (Get-Check $result 'SA-COLLECTION').target | Should -Be 'UserRights'
    }

    It 'flags a gMSA whose password any domain computer can retrieve' {
        $retrievers = Get-Check $script:findings 'SA-GMSA-RETRIEVERS'
        (Get-Check $retrievers 'SA-GMSA-RETRIEVERS' -Account 'gmsa-broad$')[0].severity | Should -Be 'high'
        (Get-Check $retrievers 'SA-GMSA-RETRIEVERS' -Account 'gmsa-web$')[0].result | Should -Be 'Info'
    }
}

Describe 'FUNC_PS_AUDIT_SERVICE_ACCOUNT: NDJSON output and safety' {

    It 'writes one NDJSON event per finding with the GOLDEN 4.7 mandatory fields' {
        $ndjson = Join-Path $script:run.LogDir 'FUNC_PS_AUDIT_SERVICE_ACCOUNT.ndjson'
        $events = @(Get-Content -LiteralPath $ndjson | ForEach-Object { $_ | ConvertFrom-Json })
        $audit = @($events | Where-Object action -eq 'audit')
        $audit.Count | Should -Be $script:findings.Count
        foreach ($auditEvent in $events) {
            foreach ($field in 'timestamp', 'host', 'tool', 'version', 'execution_id') {
                $auditEvent.PSObject.Properties.Name | Should -Contain $field
            }
        }
        @($events.execution_id | Sort-Object -Unique).Count | Should -Be 1
        $audit[0].host | Should -Be 'APP01'
        $audit[0].environment | Should -Be 'Test'
    }

    It 'emits timestamps as ISO 8601 UTC' {
        $line = Get-Content -LiteralPath (Join-Path $script:run.LogDir 'FUNC_PS_AUDIT_SERVICE_ACCOUNT.ndjson') -TotalCount 1
        $line | Should -Match '"timestamp":"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"'
    }

    It 'runs Prod with -Force without prompting and labels the events Prod' {
        $prod = Invoke-Audit -Extra @{ TargetEnvironment = 'Prod'; Force = $true }
        $prod.Findings.Count | Should -Be $script:findings.Count
        $events = @(Get-Content -LiteralPath (Join-Path $prod.LogDir 'FUNC_PS_AUDIT_SERVICE_ACCOUNT.ndjson') | ForEach-Object { $_ | ConvertFrom-Json })
        @($events.environment | Sort-Object -Unique) | Should -Be @('Prod')
    }

    It 'reads nothing and emits no findings under -WhatIf' {
        $logDir = Join-Path $TestDrive 'whatif'
        $result = @(& $script:auditScript -WhatIf -SkipActiveDirectory -LogPath $logDir 6> $null)
        $result.Count | Should -Be 0
    }

    It 'contains no state-changing cmdlets' {
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $script:auditScript).Path, [ref]$tokens, [ref]$parseErrors)
        $commands = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) |
                ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
        $writers = @($commands | Where-Object { $_ -match '^(Set|Remove|Disable|Enable|Add|New|Install|Uninstall|Reset|Stop|Start|Restart)-AD|^(Set-Service|Stop-Service|Set-LocalUser|Remove-LocalUser|Set-ScheduledTask|Unregister-ScheduledTask)$' })
        $writers | Should -BeNullOrEmpty
    }
}

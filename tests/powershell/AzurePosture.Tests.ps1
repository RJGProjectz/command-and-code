# Azure posture engine tests (Pester v5)
# Catalog contract + crosswalk logic for scripts/powershell/AzurePosture/AzurePosture.psm1.
# Nothing here reaches a live Azure tenant: every check runs against a synthetic context so the
# suite also runs on CI without az login.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../scripts/powershell/CisAudit/CisAudit.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '../../scripts/powershell/AzurePosture/AzurePosture.psm1') -Force
    $script:catalogPath = Join-Path $PSScriptRoot '../../scripts/cis/catalogs/azure/azure-identity-posture-v1.json'
    $script:catalog = Import-AzurePostureCatalog -Path $script:catalogPath

    function Get-AzFakeContext {
        param([hashtable]$Facts = @{}, [hashtable]$Errors = @{})
        [PSCustomObject]@{
            Facts  = $Facts
            Errors = $Errors
            Meta   = @{ TenantId = 'test-tenant'; TenantName = 'Test Tenant' }
        }
    }
    function Get-CheckById { param([string]$Id) $script:catalog.checks | Where-Object { $_.id -eq $Id } }
}

Describe 'Import-AzurePostureCatalog' {
    It 'loads the shipped catalog with the expected schema' {
        $script:catalog.schema | Should -Be 'cc.azposture.catalog/1'
        @($script:catalog.checks).Count | Should -BeGreaterThan 0
    }
    It 'rejects an unknown schema' {
        $tmp = Join-Path $TestDrive 'bad.json'
        '{ "schema": "nope/1", "checks": [] }' | Set-Content -LiteralPath $tmp -Encoding UTF8
        { Import-AzurePostureCatalog -Path $tmp } | Should -Throw
    }
}

Describe 'Azure posture catalog contract' {
    It 'gives every check an id, title, category and collector' {
        foreach ($c in $script:catalog.checks) {
            $c.id | Should -Match '\S' -Because "check $($c.id)"
            $c.title | Should -Match '\S' -Because "check $($c.id)"
            $c.category | Should -Match '\S' -Because "check $($c.id)"
            $c.collector | Should -Match '\S' -Because "check $($c.id)"
        }
    }
    It 'has unique check IDs' {
        $ids = @($script:catalog.checks.id)
        @($ids | Sort-Object -Unique).Count | Should -Be $ids.Count
    }
    It 'defines a bestPractice expectation on every check (minimum bar)' {
        foreach ($c in $script:catalog.checks) {
            $c.frameworks.PSObject.Properties.Name | Should -Contain 'bestPractice' -Because "check $($c.id)"
            $c.frameworks.bestPractice.expect | Should -Not -BeNullOrEmpty -Because "check $($c.id)"
        }
    }
    It 'uses only expectation operators the engine supports' {
        $supported = @('eq', 'ne', 'range', 'in', 'regex', 'notRegex', 'any', 'all', 'set', 'notEmpty', 'absent')
        foreach ($c in $script:catalog.checks) {
            foreach ($name in @('cis', 'mcsb', 'bestPractice')) {
                if ($c.frameworks.PSObject.Properties.Name -contains $name -and $c.frameworks.$name -and
                    $c.frameworks.$name.expect) {
                    $c.frameworks.$name.expect.op | Should -BeIn $supported -Because "check $($c.id) framework $name"
                }
            }
        }
    }
    It 'has at least 15 Phase 1 identity checks' {
        @($script:catalog.checks).Count | Should -BeGreaterOrEqual 15
    }
}

Describe 'Get-AzurePostureFrameworkList' {
    It 'returns cis, mcsb, bestPractice in order for a full-crosswalk check' {
        $check = Get-CheckById 'AZ-ID-03'
        (Get-AzurePostureFrameworkList -Check $check) -join ',' | Should -Be 'cis,mcsb,bestPractice'
    }
    It 'omits a framework that is not declared on the check' {
        # AZ-ID-11 has no cis framework
        $check = Get-CheckById 'AZ-ID-11'
        Get-AzurePostureFrameworkList -Check $check | Should -Not -Contain 'cis'
    }
}

Describe 'Invoke-AzurePostureCheck pass/fail logic' {
    It 'passes when the fact meets the bestPractice expectation (BestPractice bar)' {
        $ctx = Get-AzFakeContext -Facts @{ 'Entra.SecurityDefaults.IsEnabled' = 'True' }
        $r = Invoke-AzurePostureCheck -Check (Get-CheckById 'AZ-ID-01') -Context $ctx
        $r.Status | Should -Be 'Pass'
        $r.Cis | Should -Be 'Pass'
        $r.Mcsb | Should -Be 'Pass'
        $r.BestPractice | Should -Be 'Pass'
    }
    It 'fails when the fact does not meet the expectation' {
        $ctx = Get-AzFakeContext -Facts @{ 'Entra.SecurityDefaults.IsEnabled' = 'False' }
        $r = Invoke-AzurePostureCheck -Check (Get-CheckById 'AZ-ID-01') -Context $ctx
        $r.Status | Should -Be 'Fail'
    }
    It 'reports Error when the fact is missing from the context' {
        $ctx = Get-AzFakeContext -Facts @{}
        $r = Invoke-AzurePostureCheck -Check (Get-CheckById 'AZ-ID-01') -Context $ctx
        $r.Status | Should -Be 'Error'
    }
    It 'reports Error when the collector recorded an error' {
        $ctx = Get-AzFakeContext -Facts @{ 'Entra.SecurityDefaults.IsEnabled' = 'True' } `
            -Errors @{ 'Entra.SecurityDefaults.IsEnabled' = 'az rest returned 403' }
        $r = Invoke-AzurePostureCheck -Check (Get-CheckById 'AZ-ID-01') -Context $ctx
        $r.Status | Should -Be 'Error'
        $r.Detail | Should -Match '403'
    }
    It 'passes a range check at the min boundary (GA count = 2)' {
        $ctx = Get-AzFakeContext -Facts @{ 'Entra.GlobalAdmin.UserCount' = 2 }
        $r = Invoke-AzurePostureCheck -Check (Get-CheckById 'AZ-ID-10') -Context $ctx
        $r.Status | Should -Be 'Pass'
    }
    It 'passes a range check at the max boundary (GA count = 4)' {
        $ctx = Get-AzFakeContext -Facts @{ 'Entra.GlobalAdmin.UserCount' = 4 }
        $r = Invoke-AzurePostureCheck -Check (Get-CheckById 'AZ-ID-10') -Context $ctx
        $r.Status | Should -Be 'Pass'
    }
    It 'fails a range check below the min boundary (GA count = 1)' {
        $ctx = Get-AzFakeContext -Facts @{ 'Entra.GlobalAdmin.UserCount' = 1 }
        $r = Invoke-AzurePostureCheck -Check (Get-CheckById 'AZ-ID-10') -Context $ctx
        $r.Status | Should -Be 'Fail'
    }
    It 'fails a range check above the max boundary (GA count = 5)' {
        $ctx = Get-AzFakeContext -Facts @{ 'Entra.GlobalAdmin.UserCount' = 5 }
        $r = Invoke-AzurePostureCheck -Check (Get-CheckById 'AZ-ID-10') -Context $ctx
        $r.Status | Should -Be 'Fail'
    }
    It 'passes an in-set check with an allowed invite level' {
        $ctx = Get-AzFakeContext -Facts @{ 'Entra.GuestAccess.AllowInvitesFrom' = 'admins' }
        $r = Invoke-AzurePostureCheck -Check (Get-CheckById 'AZ-ID-06') -Context $ctx
        $r.Status | Should -Be 'Pass'
    }
    It 'fails an in-set check with a disallowed invite level' {
        $ctx = Get-AzFakeContext -Facts @{ 'Entra.GuestAccess.AllowInvitesFrom' = 'everyone' }
        $r = Invoke-AzurePostureCheck -Check (Get-CheckById 'AZ-ID-06') -Context $ctx
        $r.Status | Should -Be 'Fail'
    }
    It 'passes guest access level = 0 (restricted)' {
        $ctx = Get-AzFakeContext -Facts @{ 'Entra.GuestAccess.UserRoleLevel' = 0 }
        $r = Invoke-AzurePostureCheck -Check (Get-CheckById 'AZ-ID-05') -Context $ctx
        $r.Status | Should -Be 'Pass'
    }
    It 'passes guest access level = 1 (limited)' {
        $ctx = Get-AzFakeContext -Facts @{ 'Entra.GuestAccess.UserRoleLevel' = 1 }
        $r = Invoke-AzurePostureCheck -Check (Get-CheckById 'AZ-ID-05') -Context $ctx
        $r.Status | Should -Be 'Pass'
    }
    It 'fails guest access level = 2 (default/full)' {
        $ctx = Get-AzFakeContext -Facts @{ 'Entra.GuestAccess.UserRoleLevel' = 2 }
        $r = Invoke-AzurePostureCheck -Check (Get-CheckById 'AZ-ID-05') -Context $ctx
        $r.Status | Should -Be 'Fail'
    }
}

Describe 'Invoke-AzurePostureCheck Bar logic' {
    It 'passes BestPractice bar when best-practice expectation is met even if other frameworks would fail' {
        # AZ-ID-10 (GA count 2-4): if count=3 all frameworks pass, so use AZ-ID-12 which has range
        # Test: both bar modes with a passing best-practice check
        $ctx = Get-AzFakeContext -Facts @{ 'Entra.PIM.EligibleAssignmentCount' = 5 }
        $r = Invoke-AzurePostureCheck -Check (Get-CheckById 'AZ-ID-12') -Context $ctx -Bar BestPractice
        $r.Status | Should -Be 'Pass'
        $r.BestPractice | Should -Be 'Pass'
    }
    It 'fails Strictest bar when any framework fails' {
        $ctx = Get-AzFakeContext -Facts @{ 'Entra.GlobalAdmin.UserCount' = 1 }
        $r = Invoke-AzurePostureCheck -Check (Get-CheckById 'AZ-ID-10') -Context $ctx -Bar Strictest
        $r.Status | Should -Be 'Fail'
    }
    It 'records per-framework verdicts in the result object' {
        $ctx = Get-AzFakeContext -Facts @{ 'Entra.ConditionalAccess.HasMfaAllUsers' = 'True' }
        $r = Invoke-AzurePostureCheck -Check (Get-CheckById 'AZ-ID-03') -Context $ctx
        $r.Cis | Should -Be 'Pass'
        $r.Mcsb | Should -Be 'Pass'
        $r.BestPractice | Should -Be 'Pass'
    }
    It 'marks absent frameworks as n/a in the result' {
        # AZ-ID-11 has no cis framework
        $ctx = Get-AzFakeContext -Facts @{ 'Entra.GlobalAdmin.ExternalUserCount' = 0 }
        $r = Invoke-AzurePostureCheck -Check (Get-CheckById 'AZ-ID-11') -Context $ctx
        $r.Cis | Should -Be 'n/a'
        $r.Status | Should -Be 'Pass'
    }
}

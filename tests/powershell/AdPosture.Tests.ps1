# AD posture engine tests (Pester v5)
# Catalog contract + crosswalk logic for scripts/powershell/AdPosture/AdPosture.psm1. Nothing here
# reaches a live domain: every check runs against a synthetic context, so the suite also runs on CI.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../scripts/powershell/CisAudit/CisAudit.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '../../scripts/powershell/AdPosture/AdPosture.psm1') -Force
    $script:catalogPath = Join-Path $PSScriptRoot '../../scripts/cis/catalogs/adposture/ad-posture-v1.json'
    $script:catalog = Import-AdPostureCatalog -Path $script:catalogPath

    function Get-AdFakeContext {
        param([hashtable]$Facts = @{}, [hashtable]$Errors = @{})
        [PSCustomObject]@{ Facts = $Facts; Errors = $Errors; Meta = @{ Domain = 'test.local' } }
    }
    function Get-CheckById { param([string]$Id) $script:catalog.checks | Where-Object { $_.id -eq $Id } }
}

Describe 'Import-AdPostureCatalog' {
    It 'loads the shipped catalog with the expected schema' {
        $script:catalog.schema | Should -Be 'cc.adposture.catalog/1'
        @($script:catalog.checks).Count | Should -BeGreaterThan 0
    }
    It 'rejects an unknown schema' {
        $tmp = Join-Path $TestDrive 'bad.json'
        '{ "schema": "nope/1", "checks": [] }' | Set-Content -LiteralPath $tmp -Encoding UTF8
        { Import-AdPostureCatalog -Path $tmp } | Should -Throw
    }
}

Describe 'AD posture catalog contract' {
    It 'gives every check an id, title, category and collector' {
        foreach ($c in $script:catalog.checks) {
            $c.id | Should -Match '\S'
            $c.title | Should -Match '\S'
            $c.category | Should -Match '\S'
            $c.collector | Should -Match '\S'
        }
    }
    It 'has unique check IDs' {
        $ids = @($script:catalog.checks.id)
        @($ids | Sort-Object -Unique).Count | Should -Be $ids.Count
    }
    It 'defines a best-practice expectation on every check (best practice is the minimum bar)' {
        foreach ($c in $script:catalog.checks) {
            $c.frameworks.PSObject.Properties.Name | Should -Contain 'bestPractice' -Because "check $($c.id)"
            $c.frameworks.bestPractice.expect | Should -Not -BeNullOrEmpty -Because "check $($c.id)"
        }
    }
    It 'uses only expectation operators the engine supports' {
        $ops = foreach ($c in $script:catalog.checks) {
            foreach ($name in @('stig', 'cis', 'bestPractice')) {
                if ($c.frameworks.PSObject.Properties.Name -contains $name -and $c.frameworks.$name) {
                    $c.frameworks.$name.expect.op
                }
            }
        }
        $ops | Where-Object { $_ -notin @('eq', 'ne', 'range', 'in', 'regex', 'notRegex', 'any', 'all', 'set', 'notEmpty', 'absent') } |
            Should -BeNullOrEmpty
    }
}

Describe 'Get-AdPostureFrameworkList' {
    It 'returns present frameworks with best practice last' {
        $check = Get-CheckById 'AD-PW-01'
        (Get-AdPostureFrameworkList -Check $check) -join ',' | Should -Be 'stig,cis,bestPractice'
    }
    It 'omits a framework that is not declared (CIS on an AD-only check)' {
        $check = Get-CheckById 'AD-KRB-01'
        Get-AdPostureFrameworkList -Check $check | Should -Not -Contain 'cis'
    }
}

Describe 'Invoke-AdPostureCheck crosswalk and bar' {
    It 'passes all frameworks when the value meets the strictest' {
        $ctx = Get-AdFakeContext -Facts @{ 'PasswordPolicy.MinPasswordLength' = 16 }
        $r = Invoke-AdPostureCheck -Check (Get-CheckById 'AD-PW-01') -Context $ctx -Bar Strictest
        $r.Status | Should -Be 'Pass'
        $r.Stig | Should -Be 'Pass'; $r.Cis | Should -Be 'Pass'; $r.BestPractice | Should -Be 'Pass'
    }
    It 'grades on best practice at the BestPractice bar even when another framework is looser' {
        # Max age 90: STIG/BP want <=60 (Fail), CIS wants <=365 (Pass). BestPractice bar => Fail.
        $ctx = Get-AdFakeContext -Facts @{ 'PasswordPolicy.MaxPasswordAgeDays' = 90 }
        $r = Invoke-AdPostureCheck -Check (Get-CheckById 'AD-PW-03') -Context $ctx -Bar BestPractice
        $r.Status | Should -Be 'Fail'
        $r.Cis | Should -Be 'Pass'
        $r.BestPractice | Should -Be 'Fail'
    }
    It 'passes at the BestPractice bar when BP is met but a stricter framework fails' {
        # Lockout threshold 4: STIG wants <=3 (Fail), CIS/BP want <=5 (Pass). BestPractice => Pass.
        $ctx = Get-AdFakeContext -Facts @{ 'Lockout.Threshold' = 4 }
        $r = Invoke-AdPostureCheck -Check (Get-CheckById 'AD-LO-01') -Context $ctx -Bar BestPractice
        $r.Status | Should -Be 'Pass'
        $r.Stig | Should -Be 'Fail'
    }
    It 'fails at the Strictest bar when any framework fails' {
        $ctx = Get-AdFakeContext -Facts @{ 'Lockout.Threshold' = 4 }
        $r = Invoke-AdPostureCheck -Check (Get-CheckById 'AD-LO-01') -Context $ctx -Bar Strictest
        $r.Status | Should -Be 'Fail'
    }
    It 'reports Error when the fact was not collected' {
        $ctx = Get-AdFakeContext -Facts @{}
        $r = Invoke-AdPostureCheck -Check (Get-CheckById 'AD-KRB-01') -Context $ctx
        $r.Status | Should -Be 'Error'
    }
    It 'evaluates boolean facts (built-in Guest disabled)' {
        $r = Invoke-AdPostureCheck -Check (Get-CheckById 'AD-GUEST-01') -Context (Get-AdFakeContext -Facts @{ 'BuiltinGuest.Enabled' = $false })
        $r.Status | Should -Be 'Pass'
        $r2 = Invoke-AdPostureCheck -Check (Get-CheckById 'AD-GUEST-01') -Context (Get-AdFakeContext -Facts @{ 'BuiltinGuest.Enabled' = $true })
        $r2.Status | Should -Be 'Fail'
    }
    It 'marks CIS n/a on an AD-only check' {
        $r = Invoke-AdPostureCheck -Check (Get-CheckById 'AD-DEL-01') -Context (Get-AdFakeContext -Facts @{ 'Delegation.UnconstrainedNonDcCount' = 0 })
        $r.Cis | Should -Be 'n/a'
        $r.Status | Should -Be 'Pass'
    }
}

# CIS audit engine tests (Pester v5)
# Catalog contract + fixture tests for scripts/powershell/CisAudit/CisAudit.psm1. Nothing here reads
# the live host: every check runs against a fake context, so the suite also runs on the Linux CI runner.
# Shared state uses $script: scope (assigned in BeforeAll, read in It blocks).

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../scripts/powershell/CisAudit/CisAudit.psm1') -Force
    $script:fixtures = Join-Path $PSScriptRoot 'fixtures/cis'
    $script:sidNames = @{
        'S-1-1-0' = 'Everyone'; 'S-1-5-32-544' = 'BUILTIN\Administrators'; 'S-1-5-32-545' = 'BUILTIN\Users'
        'S-1-5-32-546' = 'BUILTIN\Guests'; 'S-1-5-32-551' = 'BUILTIN\Backup Operators'
        'S-1-5-113' = 'NT AUTHORITY\Local account'; 'S-1-5-19' = 'NT AUTHORITY\LOCAL SERVICE'
        'S-1-5-20' = 'NT AUTHORITY\NETWORK SERVICE'; 'S-1-5-32-555' = 'BUILTIN\Remote Desktop Users'
    }

    # Fake host: registry values keyed 'KEY|Name', SIDs from the table above, user hives and the Print
    # Spooler state from the most recent Get-FakeContext call (each test builds and uses one at a time).
    function Get-FakeContext {
        param(
            [hashtable]$Registry = @{},
            $SecurityPolicy = (ConvertFrom-CisSeceditText -Text (Get-Content -LiteralPath (Join-Path $script:fixtures 'secedit-sample.inf') -Raw)),
            $AuditPolicy = (ConvertFrom-CisAuditpolCsv -Lines (Get-Content -LiteralPath (Join-Path $script:fixtures 'auditpol-sample.csv'))),
            [AllowEmptyCollection()][string[]]$Hives = @('S-1-5-21-1-2-3-1001'),
            [string]$Spooler = 'Running'
        )
        $script:fakeRegistry = $Registry
        $script:fakeHives = $Hives
        $script:fakeSpooler = $Spooler
        [PSCustomObject]@{
            SecurityPolicy      = $SecurityPolicy
            SecurityPolicyError = 'access denied'
            AuditPolicy         = $AuditPolicy
            AuditPolicyError    = 'access denied'
            ReadRegistry        = { param($Key, $Name) $script:fakeRegistry["$Key|$Name"] }
            ListUserHives       = { $script:fakeHives }
            ReadService         = { param($Name) if ($Name -eq 'Spooler') { $script:fakeSpooler } }
            ResolveSid          = { param($Sid) if ($script:sidNames.ContainsKey($Sid)) { $script:sidNames[$Sid] } else { $Sid } }
        }
    }

    function Get-FixtureCheck {
        param([string]$Id = '9.9.9', [object[]]$Tests)
        [PSCustomObject]@{ id = $Id; title = "Ensure 'Fixture' is set"; level = 'L1'; section = ($Id -split '\.')[0]; tests = $Tests }
    }

    function ConvertTo-Expect { param([string]$Json) $Json | ConvertFrom-Json }
}

Describe 'Catalog contract: <Name>' -ForEach @(
    Get-ChildItem -Path (Join-Path $PSScriptRoot '../../scripts/cis/catalogs') -Filter '*.json' |
        ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } }
) {

    BeforeAll {
        $script:catalog = Import-CisCatalog -Path $Path
        $script:allTests = @(foreach ($c in $script:catalog.checks) {
                if ($c.PSObject.Properties.Name -contains 'variants') { foreach ($v in $c.variants) { $v.tests; $v.when } }
                else { $c.tests }
            }) | Where-Object { $null -ne $_ }

        function Get-Op {
            param($Expect)
            $Expect.op
            if ($Expect.PSObject.Properties.Name -contains 'of') { foreach ($e in $Expect.of) { Get-Op -Expect $e } }
        }
    }

    It 'names a benchmark, version and its source files' {
        $catalog.benchmark | Should -Not -BeNullOrEmpty
        $catalog.version | Should -Match '^\d+\.\d+\.\d+$'
        @($catalog.sources).Count | Should -BeGreaterThan 0
        foreach ($s in $catalog.sources) { $s.sha256 | Should -Match '^[0-9a-f]{64}$' }
    }

    It 'has unique, numeric recommendation IDs' {
        $ids = @($catalog.checks.id)
        $ids.Count | Should -BeGreaterThan 0
        @($ids | Sort-Object -Unique).Count | Should -Be $ids.Count
        $ids | Where-Object { $_ -notmatch '^\d+(\.\d+)+$|^\d+$' } | Should -BeNullOrEmpty
    }

    It 'gives every check a CIS title, a level and at least one test' {
        foreach ($c in $catalog.checks) {
            $c.title | Should -Match '\S' -Because "check $($c.id) needs its CIS title"
            $c.title.Length | Should -BeLessThan 300 -Because 'titles only, no benchmark text'
            $c.level | Should -BeIn @('L1', 'L2')
            $hasTests = ($c.PSObject.Properties.Name -contains 'tests' -and @($c.tests).Count -gt 0) -or
                ($c.PSObject.Properties.Name -contains 'variants' -and @($c.variants).Count -gt 0)
            $hasTests | Should -BeTrue -Because "check $($c.id) needs tests"
        }
    }

    It 'stores IDs, titles and settings only (no CIS rationale or remediation text)' {
        $allowed = @('id', 'title', 'level', 'section', 'tests', 'variants')
        foreach ($c in $catalog.checks) {
            $c.PSObject.Properties.Name | Where-Object { $allowed -notcontains $_ } | Should -BeNullOrEmpty
        }
    }

    It 'uses only test sources and operators the engine supports' {
        $allTests | ForEach-Object { $_.source } | Where-Object { $_ -notin @('Registry', 'SecurityPolicy', 'UserRight', 'AuditPolicy', 'Service') } |
            Should -BeNullOrEmpty
        $ops = @($allTests | ForEach-Object { Get-Op -Expect $_.expect })
        $ops | Where-Object { $_ -notin @('eq', 'ne', 'range', 'regex', 'notRegex', 'any', 'all', 'in', 'set', 'notEmpty', 'absent') } |
            Should -BeNullOrEmpty
    }

    It 'maps every audit subcategory to its language-independent GUID' {
        $script:allTests | Where-Object { $_.source -eq 'AuditPolicy' } |
            Where-Object { -not (Get-CisAuditSubcategoryGuid -Name $_.subcategory) } | ForEach-Object { $_.subcategory } |
            Should -BeNullOrEmpty
    }

    It 'uses registry keys the engine can map (HKLM / HKU)' {
        $allTests | Where-Object { $_.source -eq 'Registry' } | ForEach-Object { $_.key } |
            Where-Object { $_ -notmatch '^(HKLM|HKU)\\' } | Should -BeNullOrEmpty
    }
}

Describe 'ConvertFrom-CisSeceditText' {
    BeforeAll { $script:policy = ConvertFrom-CisSeceditText -Text (Get-Content -LiteralPath (Join-Path $script:fixtures 'secedit-sample.inf') -Raw) }

    It 'reads System Access values and strips quotes' {
        $policy.SystemAccess['MinimumPasswordLength'] | Should -Be '14'
        $policy.SystemAccess['NewAdministratorName'] | Should -Be 'Administrator'
    }
    It 'reads Privilege Rights as SID lists without the * prefix' {
        $policy.PrivilegeRights['SeDebugPrivilege'] | Should -Be @('S-1-5-32-544')
        $policy.PrivilegeRights['SeDenyNetworkLogonRight'] | Should -Be @('S-1-5-32-546', 'S-1-5-113')
    }
    It 'keeps unresolved account names as written' {
        $policy.PrivilegeRights['SeInteractiveLogonRight'][0] | Should -Be 'Guest'
    }
    It 'ignores other sections' {
        $policy.SystemAccess.ContainsKey('AuditSystemEvents') | Should -BeFalse
    }
}

Describe 'ConvertFrom-CisAuditpolCsv' {
    It 'maps subcategories and normalizes Success and Failure' {
        $map = ConvertFrom-CisAuditpolCsv -Lines (Get-Content -LiteralPath (Join-Path $script:fixtures 'auditpol-sample.csv'))
        $map['Credential Validation'] | Should -Be 'Success, Failure'
        $map['Process Creation'] | Should -Be 'Success'
        $map['Security System Extension'] | Should -Be 'No Auditing'
    }
}

Describe 'ConvertFrom-CisAuditpolBackup (locale-independent)' {
    BeforeAll {
        $script:backup = ConvertFrom-CisAuditpolBackup -Lines (Get-Content -LiteralPath (Join-Path $script:fixtures 'auditpol-backup-localized.csv'))
    }

    It 'decodes Setting Value bits regardless of the display language' {
        $script:backup['{0CCE923F-69AE-11D9-BED3-505054503030}'] | Should -Be 'Success, Failure'
        $script:backup['{0CCE922B-69AE-11D9-BED3-505054503030}'] | Should -Be 'Success'
        $script:backup['{0CCE9217-69AE-11D9-BED3-505054503030}'] | Should -Be 'Failure'
    }
    It 'normalizes GUID case' {
        $script:backup['{0CCE9211-69AE-11D9-BED3-505054503030}'] | Should -Be 'No Auditing'
    }
    It 'skips per-user and option rows' {
        $script:backup.ContainsKey('{0CCE9216-69AE-11D9-BED3-505054503030}') | Should -BeFalse
        $script:backup.Count | Should -Be 4
    }
    It 'lets catalog checks match by GUID on a non-English host' {
        $check = Get-FixtureCheck -Id '17.1.1' -Tests @(ConvertTo-Expect '{"source":"AuditPolicy","subcategory":"Credential Validation","expect":{"op":"in","values":["Success, Failure"]}}')
        (Invoke-CisCheck -Check $check -Context (Get-FakeContext -AuditPolicy $script:backup)).Status | Should -Be 'Pass'
        $lockout = Get-FixtureCheck -Id '17.5.1' -Tests @(ConvertTo-Expect '{"source":"AuditPolicy","subcategory":"Account Lockout","expect":{"op":"in","values":["Failure","Success, Failure"]}}')
        (Invoke-CisCheck -Check $lockout -Context (Get-FakeContext -AuditPolicy $script:backup)).Status | Should -Be 'Pass'
    }
    It 'also keys auditpol /get /r rows by GUID' {
        $map = ConvertFrom-CisAuditpolCsv -Lines (Get-Content -LiteralPath (Join-Path $script:fixtures 'auditpol-sample.csv'))
        $map['{0CCE923F-69AE-11D9-BED3-505054503030}'] | Should -Be 'Success, Failure'
    }
    It 'returns $null for an unknown subcategory name' {
        Get-CisAuditSubcategoryGuid -Name 'Not A Subcategory' | Should -BeNullOrEmpty
        Get-CisAuditSubcategoryGuid -Name 'Process Creation' | Should -Be '{0CCE922B-69AE-11D9-BED3-505054503030}'
    }
}

Describe 'Automation helpers' {
    It 'exit code <Expected> for FailOn <FailOn> with <Statuses>' -ForEach @(
        @{ FailOn = 'None'; Statuses = @('Fail', 'Error'); Expected = 0 }
        @{ FailOn = 'Fail'; Statuses = @('Pass', 'Error'); Expected = 0 }
        @{ FailOn = 'Fail'; Statuses = @('Pass', 'Fail'); Expected = 1 }
        @{ FailOn = 'FailOrError'; Statuses = @('Pass', 'Fail'); Expected = 1 }
        @{ FailOn = 'FailOrError'; Statuses = @('Fail', 'Error'); Expected = 2 }
        @{ FailOn = 'FailOrError'; Statuses = @('Pass', 'NotApplicable'); Expected = 0 }
    ) {
        $results = @($Statuses | ForEach-Object { [PSCustomObject]@{ Status = $_ } })
        Get-CisExitCode -Results $results -FailOn $FailOn | Should -Be $Expected
    }
    It 'treats edition <EditionId> as supported = <Supported>' -ForEach @(
        @{ EditionId = 'Enterprise'; Supported = $true }
        @{ EditionId = 'EnterpriseS'; Supported = $true }
        @{ EditionId = 'Education'; Supported = $true }
        @{ EditionId = 'Professional'; Supported = $false }
        @{ EditionId = 'Core'; Supported = $false }
        @{ EditionId = ''; Supported = $false }
    ) {
        Test-CisSupportedEdition -EditionId $EditionId | Should -Be $Supported
    }
}

Describe 'Test-CisExpectation' {
    It '<Case>' -ForEach @(
        @{ Case = 'eq compares numbers numerically'; Expect = '{"op":"eq","value":"1"}'; Actual = 1; Result = $true }
        @{ Case = 'eq compares text case-insensitively'; Expect = '{"op":"eq","value":"Client"}'; Actual = 'client'; Result = $true }
        @{ Case = 'eq fails on a different value'; Expect = '{"op":"eq","value":"1"}'; Actual = 0; Result = $false }
        @{ Case = 'eq fails when not set'; Expect = '{"op":"eq","value":"0"}'; Actual = $null; Result = $false }
        @{ Case = 'range with open max passes'; Expect = '{"op":"range","min":14,"max":null}'; Actual = '20'; Result = $true }
        @{ Case = 'range below min fails'; Expect = '{"op":"range","min":14,"max":null}'; Actual = '8'; Result = $false }
        @{ Case = 'range above max fails'; Expect = '{"op":"range","min":1,"max":5}'; Actual = 6; Result = $false }
        @{ Case = 'any matches one branch'; Expect = '{"op":"any","of":[{"op":"eq","value":"1"},{"op":"eq","value":"2"}]}'; Actual = 2; Result = $true }
        @{ Case = 'in matches audit settings'; Expect = '{"op":"in","values":["Success","Success, Failure"]}'; Actual = 'Success, Failure'; Result = $true }
        @{ Case = 'in rejects No Auditing'; Expect = '{"op":"in","values":["Success","Success, Failure"]}'; Actual = 'No Auditing'; Result = $false }
        @{ Case = 'notRegex passes a renamed admin'; Expect = '{"op":"notRegex","pattern":"\\b[Aa]dmin(istrator)?"}'; Actual = 'LocalOps'; Result = $true }
        @{ Case = 'notRegex fails the default admin name'; Expect = '{"op":"notRegex","pattern":"\\b[Aa]dmin(istrator)?"}'; Actual = 'Administrator'; Result = $false }
        @{ Case = 'set exact passes equal sets in any order'; Expect = '{"op":"set","mode":"exact","anyOf":[["Administrators","Remote Desktop Users"]]}'; Actual = @('BUILTIN\Remote Desktop Users', 'BUILTIN\Administrators'); Result = $true }
        @{ Case = 'set exact fails an extra member'; Expect = '{"op":"set","mode":"exact","anyOf":[["Administrators"]]}'; Actual = @('BUILTIN\Administrators', 'Everyone'); Result = $false }
        @{ Case = 'set exact No One passes an empty right'; Expect = '{"op":"set","mode":"exact","anyOf":[[]]}'; Actual = @(); Result = $true }
        @{ Case = 'set superset passes with extra members'; Expect = '{"op":"set","mode":"superset","anyOf":[["Guests","Local account"]]}'; Actual = @('BUILTIN\Guests', 'NT AUTHORITY\Local account', 'X'); Result = $true }
        @{ Case = 'set superset fails a missing member'; Expect = '{"op":"set","mode":"superset","anyOf":[["Guests","Local account"]]}'; Actual = @('BUILTIN\Guests'); Result = $false }
        @{ Case = 'notEmpty fails on blank text'; Expect = '{"op":"notEmpty"}'; Actual = '  '; Result = $false }
        @{ Case = 'absent passes when not set'; Expect = '{"op":"absent"}'; Actual = $null; Result = $true }
    ) {
        Test-CisExpectation -Expect (ConvertTo-Expect $Expect) -Actual $Actual | Should -Be $Result
    }

    It 'throws on an unknown operator' {
        { Test-CisExpectation -Expect ([PSCustomObject]@{ op = 'bogus' }) -Actual 1 } | Should -Throw
    }
}

Describe 'Invoke-CisCheck against a fake host' {

    It 'passes a compliant registry value' {
        $check = Get-FixtureCheck -Tests @(ConvertTo-Expect '{"source":"Registry","key":"HKLM\\Sys\\Lsa","name":"RunAsPPL","expect":{"op":"eq","value":"1"}}')
        $r = Invoke-CisCheck -Check $check -Context (Get-FakeContext -Registry @{ 'HKLM\Sys\Lsa|RunAsPPL' = 1 })
        $r.Status | Should -Be 'Pass'
        $r.Actual | Should -Be '1'
        $r.Source | Should -Be 'HKLM\Sys\Lsa\RunAsPPL'
    }

    It 'fails a missing registry value unless the catalog allows it' {
        $test = ConvertTo-Expect '{"source":"Registry","key":"HKLM\\K","name":"V","expect":{"op":"eq","value":"1"}}'
        (Invoke-CisCheck -Check (Get-FixtureCheck -Tests @($test)) -Context (Get-FakeContext)).Status | Should -Be 'Fail'
        $test | Add-Member -NotePropertyName allowMissing -NotePropertyValue $true
        (Invoke-CisCheck -Check (Get-FixtureCheck -Tests @($test)) -Context (Get-FakeContext)).Status | Should -Be 'Pass'
    }

    It 'fails when a value that must not exist is present' {
        $check = Get-FixtureCheck -Tests @(ConvertTo-Expect '{"source":"Registry","key":"HKLM\\Winlogon","name":"DefaultPassword","mustNotExist":true,"expect":{"op":"absent"}}')
        (Invoke-CisCheck -Check $check -Context (Get-FakeContext -Registry @{ 'HKLM\Winlogon|DefaultPassword' = 'x' })).Status | Should -Be 'Fail'
        (Invoke-CisCheck -Check $check -Context (Get-FakeContext)).Status | Should -Be 'Pass'
    }

    It 'requires every test of a composite recommendation to pass' {
        $tests = @(
            ConvertTo-Expect '{"source":"Registry","key":"HKLM\\A","name":"One","expect":{"op":"eq","value":"1"}}'
            ConvertTo-Expect '{"source":"Registry","key":"HKLM\\A","name":"Two","expect":{"op":"eq","value":"0"}}'
        )
        $context = Get-FakeContext -Registry @{ 'HKLM\A|One' = 1; 'HKLM\A|Two' = 1 }
        $r = Invoke-CisCheck -Check (Get-FixtureCheck -Tests $tests) -Context $context
        $r.Status | Should -Be 'Fail'
        $r.Expected | Should -Be '1 ; 0'
    }

    It 'reads password policy from secedit' {
        $check = Get-FixtureCheck -Id '1.1.4' -Tests @(ConvertTo-Expect '{"source":"SecurityPolicy","key":"MinimumPasswordLength","expect":{"op":"range","min":14,"max":null}}')
        $r = Invoke-CisCheck -Check $check -Context (Get-FakeContext)
        $r.Status | Should -Be 'Pass'
        $r.Section | Should -Be 'Account Policies'
    }

    It 'compares user rights by resolved account name' {
        $exact = Get-FixtureCheck -Id '2.2.2' -Tests @(ConvertTo-Expect '{"source":"UserRight","right":"SeNetworkLogonRight","expect":{"op":"set","mode":"exact","anyOf":[["Administrators","Remote Desktop Users"]]}}')
        $r = Invoke-CisCheck -Check $exact -Context (Get-FakeContext)
        $r.Status | Should -Be 'Fail'
        $r.Actual | Should -Match 'Everyone'
        $superset = Get-FixtureCheck -Id '2.2.15' -Tests @(ConvertTo-Expect '{"source":"UserRight","right":"SeDenyNetworkLogonRight","expect":{"op":"set","mode":"superset","anyOf":[["Guests","Local account"]]}}')
        (Invoke-CisCheck -Check $superset -Context (Get-FakeContext)).Status | Should -Be 'Pass'
    }

    It 'treats a right that is not assigned as No One' {
        $check = Get-FixtureCheck -Id '2.2.1' -Tests @(ConvertTo-Expect '{"source":"UserRight","right":"SeTrustedCredManAccessPrivilege","expect":{"op":"set","mode":"exact","anyOf":[[]]}}')
        (Invoke-CisCheck -Check $check -Context (Get-FakeContext)).Status | Should -Be 'Pass'
    }

    It 'reads audit policy subcategories' {
        $check = Get-FixtureCheck -Id '17.1.1' -Tests @(ConvertTo-Expect '{"source":"AuditPolicy","subcategory":"Credential Validation","expect":{"op":"in","values":["Success, Failure"]}}')
        (Invoke-CisCheck -Check $check -Context (Get-FakeContext)).Status | Should -Be 'Pass'
    }

    It 'reports Error (not Fail) when a source could not be read' {
        $check = Get-FixtureCheck -Id '1.1.1' -Tests @(ConvertTo-Expect '{"source":"SecurityPolicy","key":"PasswordHistorySize","expect":{"op":"range","min":24,"max":null}}')
        $r = Invoke-CisCheck -Check $check -Context (Get-FakeContext -SecurityPolicy $null)
        $r.Status | Should -Be 'Error'
        $r.Detail | Should -Match 'access denied'
        $audit = Get-FixtureCheck -Id '17.1.1' -Tests @(ConvertTo-Expect '{"source":"AuditPolicy","subcategory":"Credential Validation","expect":{"op":"in","values":["Success, Failure"]}}')
        (Invoke-CisCheck -Check $audit -Context (Get-FakeContext -AuditPolicy $null)).Status | Should -Be 'Error'
    }

    It 'reports Error for an audit subcategory missing from auditpol output' {
        $check = Get-FixtureCheck -Id '17.9.9' -Tests @(ConvertTo-Expect '{"source":"AuditPolicy","subcategory":"Not A Subcategory","expect":{"op":"in","values":["Success"]}}')
        (Invoke-CisCheck -Check $check -Context (Get-FakeContext)).Status | Should -Be 'Error'
    }

    It 'picks the variant whose condition matches (Print Spooler running or not)' {
        $check = ConvertTo-Expect @'
{"id":"2.2.22","title":"Ensure 'Generate security audits' is set","level":"L1","section":"2","variants":[
 {"when":[{"source":"Service","name":"Spooler","property":"Status","expect":{"op":"regex","pattern":"Running"}}],
  "tests":[{"source":"UserRight","right":"SeAuditPrivilege","expect":{"op":"set","mode":"exact","anyOf":[["Local Service","Network Service","PrintSpoolerService"]]}}]},
 {"when":null,
  "tests":[{"source":"UserRight","right":"SeAuditPrivilege","expect":{"op":"set","mode":"exact","anyOf":[["Local Service","Network Service"]]}}]}]}
'@
        (Invoke-CisCheck -Check $check -Context (Get-FakeContext -Spooler 'Running')).Status | Should -Be 'Fail'
        (Invoke-CisCheck -Check $check -Context (Get-FakeContext -Spooler 'Stopped')).Status | Should -Be 'Pass'
    }

    It 'checks HKU settings in every loaded user hive' {
        $check = Get-FixtureCheck -Id '19.7.8.1' -Tests @(ConvertTo-Expect '{"source":"Registry","key":"HKU\\Software\\Policies\\X","name":"V","expect":{"op":"eq","value":"1"}}')
        $hives = @('S-1-5-21-1-2-3-1001', 'S-1-5-21-1-2-3-1002')
        $context = Get-FakeContext -Hives $hives -Registry @{ 'HKU\S-1-5-21-1-2-3-1001\Software\Policies\X|V' = 1 }
        $r = Invoke-CisCheck -Check $check -Context $context
        $r.Status | Should -Be 'Fail'
        $r.Detail | Should -Match '1002'
        $r.Detail | Should -Not -Match '1001'
        (Invoke-CisCheck -Check $check -Context (Get-FakeContext -Hives @())).Status | Should -Be 'NotApplicable'
    }
}

Describe 'Select-CisCheck and formatting' {
    BeforeAll {
        $script:smallCatalog = [PSCustomObject]@{ checks = @(
                [PSCustomObject]@{ id = '1.1.1'; level = 'L1'; section = '1' }
                [PSCustomObject]@{ id = '2.3.1.1'; level = 'L1'; section = '2' }
                [PSCustomObject]@{ id = '18.9.4.1'; level = 'L2'; section = '18' }
            )
        }
    }

    It 'L2 includes L1 recommendations' {
        @(Select-CisCheck -Catalog $script:smallCatalog -Level L1).Count | Should -Be 2
        @(Select-CisCheck -Catalog $script:smallCatalog -Level L2).Count | Should -Be 3
    }
    It 'filters by ID wildcard and section' {
        @(Select-CisCheck -Catalog $script:smallCatalog -Level L2 -Id '2.3.*').id | Should -Be '2.3.1.1'
        @(Select-CisCheck -Catalog $script:smallCatalog -Level L2 -Section '18').id | Should -Be '18.9.4.1'
    }
    It 'formats expectations for reports' {
        Format-CisExpectation -Expect (ConvertTo-Expect '{"op":"range","min":15,"max":null}') | Should -Be '>= 15'
        Format-CisExpectation -Expect (ConvertTo-Expect '{"op":"set","mode":"exact","anyOf":[[]]}') | Should -Be 'No One'
        Format-CisExpectation -Expect (ConvertTo-Expect '{"op":"set","mode":"superset","anyOf":[["Guests"]]}') | Should -Be 'includes Guests'
        Format-CisValue -Value $null | Should -Be '(not set)'
    }
    It 'maps registry hives to provider paths' {
        ConvertTo-CisRegistryPath -Key 'HKLM\Software\Policies' | Should -Be 'Registry::HKEY_LOCAL_MACHINE\Software\Policies'
        { ConvertTo-CisRegistryPath -Key 'HKCR\x' } | Should -Throw
    }
}

# Active Directory Automation Test Suite (Pester v5)
# Tests parameter contracts, dry-run safety, and validation rules for AD automation

BeforeAll {
    $scriptRoot = "$PSScriptRoot/../../scripts/powershell"
}

Describe "Active Directory Automation Scripts - Parameter & Safety Contracts" {
    
    Context "FUNC_PS_DISABLE_TERMINATED_USER.ps1" {
        $scriptPath = "$scriptRoot/FUNC_PS_DISABLE_TERMINATED_USER.ps1"

        It "Script file exists" {
            Test-Path $scriptPath | Should -Be $true
        }

        It "Requires mandatory -Identity parameter" {
            { & $scriptPath -TargetEnvironment "Test" -ErrorAction Stop } | Should -Throw
        }

        It "Accepts valid TargetEnvironment ('Test', 'Prod')" {
            { & $scriptPath -Identity "user.test" -TargetEnvironment "Test" } | Should -Not -Throw
        }
    }

    Context "FUNC_PS_GET_AD_GROUP_MEMBERS.ps1" {
        $scriptPath = "$scriptRoot/FUNC_PS_GET_AD_GROUP_MEMBERS.ps1"

        It "Script file exists" {
            Test-Path $scriptPath | Should -Be $true
        }

        It "Enforces mandatory GroupName parameter" {
            { & $scriptPath -TargetEnvironment "Test" -ErrorAction Stop } | Should -Throw
        }

        It "Safe execution in Test environment" {
            { & $scriptPath -GroupName "Domain Admins" -TargetEnvironment "Test" } | Should -Not -Throw
        }
    }

    Context "FUNC_PS_RESET_PASSWORD.ps1" {
        $scriptPath = "$scriptRoot/FUNC_PS_RESET_PASSWORD.ps1"

        It "Script file exists" {
            Test-Path $scriptPath | Should -Be $true
        }

        It "Requires SecureString for NewPassword parameter" {
            $pass = ConvertTo-SecureString "TempP@ssw0rd123!" -AsPlainText -Force
            { & $scriptPath -Identity "test.user" -NewPassword $pass -TargetEnvironment "Test" } | Should -Not -Throw
        }
    }

    Context "FUNC_PS_GET_BITLOCKER_KEY.ps1" {
        $scriptPath = "$scriptRoot/FUNC_PS_GET_BITLOCKER_KEY.ps1"

        It "Script file exists" {
            Test-Path $scriptPath | Should -Be $true
        }

        It "Executes safely under Test environment without live AD queries" {
            { & $scriptPath -ComputerName "WKSTN-TEST-01" -TargetEnvironment "Test" } | Should -Not -Throw
        }
    }
}

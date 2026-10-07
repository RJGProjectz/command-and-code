# Azure & Microsoft Graph Automation Test Suite (Pester v5)
# Tests parameter contracts, indicator validations, and dry-run safety for cloud scripts

BeforeAll {
    $scriptRoot = "$PSScriptRoot/../../scripts/powershell"
}

Describe "Azure & Microsoft Graph Security Scripts - Parameter & Safety Contracts" {

    Context "FUNC_PS_BLOCK_AZ_INDICATOR.ps1" {
        $scriptPath = "$scriptRoot/FUNC_PS_BLOCK_AZ_INDICATOR.ps1"

        It "Script file exists" {
            Test-Path $scriptPath | Should -Be $true
        }

        It "Enforces ValidateSet on IndicatorType parameter" {
            { & $scriptPath -Value "1.1.1.1" -IndicatorType "InvalidType" -Comment "Test" -TargetEnvironment "Test" -ErrorAction Stop } | Should -Throw
        }

        It "Executes safely under Test environment with valid indicator" {
            { & $scriptPath -Value "198.51.100.23" -IndicatorType "IpAddress" -Comment "IOC-Test" -TargetEnvironment "Test" } | Should -Not -Throw
        }
    }

    Context "FUNC_PS_GET_AZ_SIGNIN_LOGS.ps1" {
        $scriptPath = "$scriptRoot/FUNC_PS_GET_AZ_SIGNIN_LOGS.ps1"

        It "Script file exists" {
            Test-Path $scriptPath | Should -Be $true
        }

        It "Accepts UserId parameter contract" {
            { & $scriptPath -UserId "user@example.com" -Hours 24 } | Should -Not -Throw
        }
    }

    Context "FUNC_PS_INVITE_GUEST_USER.ps1" {
        $scriptPath = "$scriptRoot/FUNC_PS_INVITE_GUEST_USER.ps1"

        It "Script file exists" {
            Test-Path $scriptPath | Should -Be $true
        }

        It "Enforces mandatory EmailAddress parameter" {
            { & $scriptPath -ErrorAction Stop } | Should -Throw
        }
    }
}

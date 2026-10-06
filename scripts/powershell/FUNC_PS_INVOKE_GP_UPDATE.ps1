<#
.SYNOPSIS
    Forces a Group Policy update on a local or remote computer.

.DESCRIPTION
    1. Triggers 'gpupdate /force' on the target machine.
    2. Uses Invoke-Command for remote execution.
    3. Logs the output of the command to the console.

.PARAMETER ComputerName
    The name of the computer to update. Defaults to localhost.

.PARAMETER TargetEnvironment
    Mandatory standard parameter. Use 'Test' or 'Prod'.

.EXAMPLE
    .\Invoke-GPUpdate.ps1 -ComputerName "Server01" -TargetEnvironment Prod

.NOTES
    Security Domain: Operations
    Created: 2026-01-16T16:20:00
    Last Modified: 2026-01-16T16:20:00
    Author: Antigravity
    KB Article: [KB-OnPrem-008-GPUpdate.md](../../HowTo/Scripts/KB-OnPrem-008-GPUpdate.md)
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerName = "localhost",

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment
)

Write-Host "--- Remote GPUpdate ---" -ForegroundColor Cyan
Write-Host "Target: $ComputerName ($TargetEnvironment)"

$ScriptBlock = {
    gpupdate /force
}

try {
    if ($ComputerName -eq "localhost") {
        Invoke-Command -ScriptBlock $ScriptBlock
    } else {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock -ErrorAction Stop
    }
    Write-Host "[OK] GPUpdate triggered successfully on $ComputerName." -ForegroundColor Green
} catch {
    Write-Host "[FAIL] Failed to trigger GPUpdate on $ComputerName. Error: $($_.Exception.Message)" -ForegroundColor Red
}

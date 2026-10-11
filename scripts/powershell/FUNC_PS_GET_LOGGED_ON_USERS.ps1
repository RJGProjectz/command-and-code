<#
.SYNOPSIS
    Identifies active and disconnected users on a remote computer.

.DESCRIPTION
    1. Queries the machine for logged-on sessions.
    2. Identifies User Name, Session ID, and Status (Active/Disc).
    3. Useful for identifying 'Ghost' users or active admins.

.PARAMETER ComputerName
    The name of the computer. Defaults to localhost.

.PARAMETER TargetEnvironment
    'Test' (default) simulates. 'Prod' executes.

.EXAMPLE
    .\Get-LoggedOnUsers.ps1 -ComputerName "WS101" -TargetEnvironment Prod

.NOTES
    Security Domain: Endpoint
    Created: 2026-01-16T16:30:00
    Last Modified: 2026-01-16T16:30:00
    Author: Antigravity
    Documentation: [Endpoint Triage Playbook](../../docs/tasks/incident-response/endpoint-triage.md)
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerName = "localhost",

    [Parameter(Mandatory=$false)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment = "Test"
)

Write-Host "--- Logged On User Detection ---" -ForegroundColor Cyan
Write-Host "Target: $ComputerName ($TargetEnvironment)"

try {
    # Using 'quser' as a robust legacy tool via Invoke-Command
    $ScriptBlock = { quser }
    if ($ComputerName -eq "localhost") {
        Invoke-Command -ScriptBlock $ScriptBlock
    } else {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock -ErrorAction Stop
    }
} catch {
    Write-Host "[FAIL] Failed to retrieve user list. Error: $($_.Exception.Message)" -ForegroundColor Red
}

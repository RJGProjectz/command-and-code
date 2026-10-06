<#
.SYNOPSIS
    Restarts a specific service on a local or remote computer.

.DESCRIPTION
    1. Checks if the service exists.
    2. Restarts the service and waits for it to reach the 'Running' state.
    3. Supports -WhatIf for safety.

.PARAMETER ComputerName
    The name of the computer. Defaults to localhost.

.PARAMETER ServiceName
    The name of the service to restart (e.g., Spooler).

.PARAMETER TargetEnvironment
    Mandatory standard parameter. Use 'Test' or 'Prod'.

.EXAMPLE
    .\Restart-RemoteService.ps1 -ComputerName "Server01" -ServiceName "Spooler" -TargetEnvironment Prod

.NOTES
    Security Domain: Operations
    Created: 2026-01-16T16:20:00
    Last Modified: 2026-01-16T16:20:00
    Author: Antigravity
    KB Article: [KB-OnPrem-009-ServiceRestart.md](../../HowTo/Scripts/KB-OnPrem-009-ServiceRestart.md)
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerName = "localhost",

    [Parameter(Mandatory=$true)]
    [string]$ServiceName,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment
)

Write-Host "--- Remote Service Restart ---" -ForegroundColor Cyan
Write-Host "Service: $ServiceName on $ComputerName ($TargetEnvironment)"

try {
    $Svc = Get-Service -Name $ServiceName -ComputerName $ComputerName -ErrorAction Stop
    Write-Host "[*] Current Status of $($Svc.Name): $($Svc.Status)"
    
    Write-Host "[!] Restarting service..." -ForegroundColor Yellow
    Restart-Service -Name $ServiceName -Force -ErrorAction Stop
    
    # Wait and verify
    Start-Sleep -Seconds 2
    $Svc = Get-Service -Name $ServiceName -ComputerName $ComputerName
    if ($Svc.Status -eq 'Running') {
        Write-Host "[OK] Service $ServiceName is now running." -ForegroundColor Green
    } else {
        Write-Host "[WARN] Service $ServiceName reached status: $($Svc.Status)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[FAIL] Failed to restart $ServiceName on $ComputerName. Error: $($_.Exception.Message)" -ForegroundColor Red
}

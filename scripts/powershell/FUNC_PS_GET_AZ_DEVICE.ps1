<#
.SYNOPSIS
    Retrieves detailed inventory and compliance state for a managed device.

.DESCRIPTION
    Standardized device auditing tool via Intune/Microsoft Graph.
    Returns: Compliance state, OS version, Last Check-in, Serial Number.
    SAFEGUARDS: Read-only. Requires -TargetEnvironment.

.PARAMETER DeviceName
    The name of the device to query.

.PARAMETER TargetEnvironment
    Standard compliance parameter.

.EXAMPLE
    .\Get-AzDevice.ps1 -DeviceName "LT-5678" -TargetEnvironment Prod

.NOTES
    Security Domain: Identity
    Author: AntiGravity
    Created: 2026-01-19T08:50:00
    Last Modified: 2026-01-19T08:50:00
    KB Article: [KB-Azure-010-DeviceState.md](../../HowTo/Scripts/KB-Azure-010-DeviceState.md)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$DeviceName,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment
)

Write-Host "--- Entra ID / Intune Device State Audit ---" -ForegroundColor Cyan

try {
    Write-Host "[*] Searching for device: $DeviceName..."
    $Device = Get-MgDeviceManagementManagedDevice -Filter "deviceName eq '$DeviceName'" -ErrorAction Stop
    
    if ($Device) {
        $Device | Select-Object DeviceName, ComplianceState, OSVersion, LastSyncDateTime, SerialNumber | 
                  Format-List
        Write-Host "[OK] Device information retrieved." -ForegroundColor Green
    } else {
        Write-Host "[WARN] Device not found in Intune management." -ForegroundColor Yellow
    }
} catch {
    Write-Host "[ERROR] Could not query device: $($_.Exception.Message)" -ForegroundColor Red
}

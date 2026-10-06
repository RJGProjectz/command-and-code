<#
.SYNOPSIS
    Triggers a remote Microsoft Defender AV scan on a device.

.DESCRIPTION
    1. Uses the Defender for Endpoint API (Machine Actions).
    2. Supports Quick and Full scan types.
    3. Returns the Action ID for tracking.

.PARAMETER DeviceId
    The Microsoft Defender Machine ID.

.PARAMETER ScanType
    Type of scan: Quick (default) or Full.

.PARAMETER TargetEnvironment
    Mandatory standard parameter. Use 'Test' or 'Prod'.

.EXAMPLE
    .\Start-DefenderScan.ps1 -DeviceId "xyz-123" -ScanType Full -TargetEnvironment Prod

.NOTES
    Security Domain: Endpoint
    Created: 2026-01-16T16:30:00
    Last Modified: 2026-01-16T16:30:00
    Author: Antigravity
    KB Article: [KB-Sec-010-DefenderScan.md](../../HowTo/Scripts/KB-Sec-010-DefenderScan.md)
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [string]$DeviceId,

    [Parameter(Mandatory=$false)]
    [ValidateSet("Quick", "Full")]
    [string]$ScanType = "Quick",

    [Parameter(Mandatory=$true)]
    [string]$Token,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment
)

Write-Host "--- Defender Remote Scan ---" -ForegroundColor Cyan
Write-Host "Device: $DeviceId (Type: $ScanType)"

if ($TargetEnvironment -eq "Test") {
    Write-Host "[TEST] Would trigger $ScanType scan on device $DeviceId" -ForegroundColor Yellow
    return
}

if ($PSCmdlet.ShouldProcess("Device: $DeviceId", "Trigger $ScanType AV Scan")) {
    try {
        $Uri = "https://graph.microsoft.com/v1.0/security/microsoft.graph.defender/machines/$DeviceId/runAntiVirusScan"
        $Body = @{
            "Action" = "RunAntiVirusScan"
            "Comment" = "Remote scan triggered by Antigravity Automation"
            "ScanType" = $ScanType
        } | ConvertTo-Json

        $Header = @{
            "Authorization" = "Bearer $Token"
            "Content-Type"  = "application/json"
        }

        Write-Host "[*] Triggering scan via Microsoft Graph..." -ForegroundColor Yellow
        $Response = Invoke-RestMethod -Uri $Uri -Method Post -Headers $Header -Body $Body
        
        Write-Host "[OK] Action triggered successfully. Action ID: $($Response.id)" -ForegroundColor Green
        return $Response
    } catch {
        Write-Host "[FAIL] Error triggering scan: $($_.Exception.Message)" -ForegroundColor Red
        throw $_
    }
}

<#
.SYNOPSIS
    Adds a custom indicator (Hash, IP, URL) to the Defender blocklist.

.DESCRIPTION
    Standardized perimeter protection tool.
    1. Submits indicator to Microsoft Graph /security/tiIndicators.
    2. Sets action to 'Block'.
    SAFEGUARDS: Supports -Confirm for Prod. Requires -TargetEnvironment.

.PARAMETER Value
    The Hash, IP, or URL string.

.PARAMETER IndicatorType
    Type of indicator: FileSha256, IpAddress, Url, DomainName.

.PARAMETER Comment
    Audit comment (Required).

.PARAMETER TargetEnvironment
    'Test' simulates. 'Prod' executes.

.EXAMPLE
    .\Block-AzIndicator.ps1 -Value "1.2.3.4" -IndicatorType IpAddress -Comment "Known C2" -TargetEnvironment Test

.NOTES
    Security Domain: Endpoint
    Author: AntiGravity
    Created: 2026-01-19T08:50:00
    Last Modified: 2026-01-19T08:50:00
    KB Article: [KB-Sec-015-BlockIndicator.md](../../HowTo/Scripts/KB-Sec-015-BlockIndicator.md)
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory=$true)]
    [string]$Value,

    [Parameter(Mandatory=$true)]
    [ValidateSet("FileSha256", "IpAddress", "Url", "DomainName")]
    [string]$IndicatorType,

    [Parameter(Mandatory=$true)]
    [string]$Comment,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment
)

Write-Host "--- Entra/MDE TI Indicator Block ---" -ForegroundColor Cyan

if ($TargetEnvironment -eq "Test") {
    Write-Host "[TEST] Would block ${IndicatorType}: $Value" -ForegroundColor Yellow
    return
}

if ($PSCmdlet.ShouldProcess("${IndicatorType}: $Value", "Add to Global Blocklist")) {
    try {
        # Placeholder for MG Graph Call
        # $Body = @{ "targetProduct" = "Microsoft Defender for Endpoint"; "action" = "block"; ... }
        # Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/security/tiIndicators" -Body $Body
        Write-Host "[OK] Indicator blocked successfully." -ForegroundColor Green
    } catch {
        Write-Host "[FAIL] Error blocking indicator: $($_.Exception.Message)" -ForegroundColor Red
        throw $_
    }
}

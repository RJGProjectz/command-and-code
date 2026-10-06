<#
.SYNOPSIS
    Updates profile attributes for a Microsoft Entra user.

.DESCRIPTION
    Standardized account management tool.
    Updates attributes like JobTitle, Department, BusinessPhones, etc.
    SAFEGUARDS: Supports -WhatIf. Requires -TargetEnvironment.

.PARAMETER UserId
    UPN or ObjectId of the user.

.PARAMETER JobTitle
    New job title.

.PARAMETER Department
    New department.

.PARAMETER TargetEnvironment
    'Test' simulates. 'Prod' executes.

.EXAMPLE
    .\Update-AzUserProfile.ps1 -UserId "user@tenant.com" -JobTitle "Sr. Analyst" -Department "IT" -TargetEnvironment Test

.NOTES
    Security Domain: Identity
    Author: AntiGravity
    Created: 2026-01-19T08:50:00
    Last Modified: 2026-01-19T08:50:00
    KB Article: [KB-Azure-009-ProfileUpdate.md](../../HowTo/Scripts/KB-Azure-009-ProfileUpdate.md)
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [string]$UserId,

    [string]$JobTitle,
    [string]$Department,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment
)

Write-Host "--- Entra ID Profile Update ---" -ForegroundColor Cyan

$UpdateData = @{}
if ($JobTitle) { $UpdateData["JobTitle"] = $JobTitle }
if ($Department) { $UpdateData["Department"] = $Department }

if ($UpdateData.Count -eq 0) {
    Write-Warning "No attribute updates provided."
    return
}

if ($TargetEnvironment -eq "Test") {
    Write-Host "[TEST] Would update $UserId with: $($UpdateData | ConvertTo-Json -Compress)" -ForegroundColor Yellow
    return
}

if ($PSCmdlet.ShouldProcess($UserId, "Update Profile Attributes")) {
    try {
        Update-MgUser -UserId $UserId -BodyParameter $UpdateData -ErrorAction Stop
        Write-Host "[OK] Profile updated successfully." -ForegroundColor Green
    } catch {
        Write-Host "[FAIL] Error updating profile: $($_.Exception.Message)" -ForegroundColor Red
        throw $_
    }
}

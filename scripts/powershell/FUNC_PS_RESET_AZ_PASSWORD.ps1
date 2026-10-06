<#
.SYNOPSIS
    Resets the password for a cloud-only Microsoft Entra user.

.DESCRIPTION
    Standardized identity remediation tool.
    1. Resets password via Microsoft Graph.
    2. Optionally requires password change on next sign-in.
    SAFEGUARDS: Supports -Confirm for Prod. Requires -TargetEnvironment.

.PARAMETER UserId
    UPN or ObjectId of the user.

.PARAMETER NewPassword
    The new password to set.

.PARAMETER TargetEnvironment
    'Test' simulates. 'Prod' executes.

.EXAMPLE
    .\Reset-AzPassword.ps1 -UserId "user@tenant.com" -NewPassword "ComplexPass123!" -TargetEnvironment Test

.NOTES
    Security Domain: Identity
    Author: AntiGravity
    Created: 2026-01-19T08:50:00
    Last Modified: 2026-01-19T08:50:00
    KB Article: [KB-Azure-008-PassReset.md](../../HowTo/Scripts/KB-Azure-008-PassReset.md)
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true)]
    [string]$UserId,

    [Parameter(Mandatory=$true)]
    [string]$NewPassword,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment
)

Write-Host "--- Entra ID Password Reset ---" -ForegroundColor Cyan

if ($TargetEnvironment -eq "Test") {
    Write-Host "[TEST] Would reset password for $UserId" -ForegroundColor Yellow
    return
}

if ($PSCmdlet.ShouldProcess($UserId, "Reset Password")) {
    try {
        $Profile = @{
            "PasswordProfile" = @{
                "Password" = $NewPassword
                "ForceChangePasswordNextSignIn" = $true
            }
        }
        Update-MgUser -UserId $UserId -BodyParameter $Profile -ErrorAction Stop
        Write-Host "[OK] Password reset completed." -ForegroundColor Green
    } catch {
        Write-Host "[FAIL] Error during reset: $($_.Exception.Message)" -ForegroundColor Red
        throw $_
    }
}

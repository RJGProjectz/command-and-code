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
    The new password to set, as a SecureString (e.g. from Read-Host -AsSecureString).
    It is only converted to plain text for the Graph request body.

.PARAMETER TargetEnvironment
    'Test' simulates. 'Prod' executes.

.EXAMPLE
    .\Reset-AzPassword.ps1 -UserId "user@tenant.com" -NewPassword (Read-Host -AsSecureString "New password") -TargetEnvironment Test

.NOTES
    Security Domain: Identity
    Author: AntiGravity
    Created: 2026-01-19T08:50:00
    Last Modified: 2026-10-11T18:40:00Z
    Documentation: [User Lifecycle Management](../../docs/tasks/administration/user-lifecycle-management.md)
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true)]
    [string]$UserId,

    [Parameter(Mandatory=$true)]
    [securestring]$NewPassword,

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
        $Body = @{
            "PasswordProfile" = @{
                "Password" = [System.Net.NetworkCredential]::new('', $NewPassword).Password
                "ForceChangePasswordNextSignIn" = $true
            }
        }
        Update-MgUser -UserId $UserId -BodyParameter $Body -ErrorAction Stop
        Write-Host "[OK] Password reset completed." -ForegroundColor Green
    } catch {
        Write-Host "[FAIL] Error during reset: $($_.Exception.Message)" -ForegroundColor Red
        throw $_
    }
}

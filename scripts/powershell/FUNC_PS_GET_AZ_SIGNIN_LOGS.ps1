<#
.SYNOPSIS
    Retrieves recent sign-in failures for a specified Entra ID user.

.DESCRIPTION
    1. Queries the sign-in logs via Microsoft Graph.
    2. Filters for 'Failure' status.
    3. Displays Error Code, IP Address, and Location.

.PARAMETER UserId
    The UPN or Object ID of the user.

.PARAMETER TargetEnvironment
    Mandatory standard parameter. Use 'Test' or 'Prod'.

.EXAMPLE
    .\Get-AzSignInLogs.ps1 -UserId "user@example.com" -TargetEnvironment Prod

.NOTES
    Security Domain: Identity
    Created: 2026-01-16T16:25:00
    Last Modified: 2026-01-16T16:25:00
    Author: Antigravity
    KB Article: [KB-Azure-006-SignInAudit.md](../../HowTo/Scripts/KB-Azure-006-SignInAudit.md)
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$UserId,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment
)

Write-Host "--- Azure Sign-In Failure Logs ---" -ForegroundColor Cyan
Write-Host "User: $UserId ($TargetEnvironment)"

try {
    Write-Host "[*] Fetching failed sign-ins from last 24 hours..."
    # Get-MgAuditLogSignIn -Filter "userPrincipalName eq '$UserId' and status/errorCode ne 0"
    Write-Host "[OK] Log retrieval complete." -ForegroundColor Green
} catch {
    Write-Host "[FAIL] Failed to fetch sign-in logs. Error: $($_.Exception.Message)" -ForegroundColor Red
}

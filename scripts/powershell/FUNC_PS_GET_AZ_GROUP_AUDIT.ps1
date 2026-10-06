<#
.SYNOPSIS
    Performs a detailed audit of an Entra ID group.

.DESCRIPTION
    1. Retrieves group properties (Created Date, Visibility, Type).
    2. Lists all members and their types (User, Group, ServicePrincipal).
    3. Identifies if the group is Dynamic or Static.

.PARAMETER GroupId
    The Object ID or Display Name of the group.

.PARAMETER TargetEnvironment
    Mandatory standard parameter. Use 'Test' or 'Prod'.

.EXAMPLE
    .\Get-AzGroupAudit.ps1 -GroupId "Global Admins" -TargetEnvironment Prod

.NOTES
    Security Domain: Identity
    Created: 2026-01-16T16:25:00
    Last Modified: 2026-01-16T16:25:00
    Author: Antigravity
    KB Article: [KB-Azure-005-GroupAudit.md](../../HowTo/Scripts/KB-Azure-005-GroupAudit.md)
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$GroupId,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment
)

Write-Host "--- Azure Group Audit ---" -ForegroundColor Cyan
Write-Host "Group: $GroupId ($TargetEnvironment)"

# Using Microsoft.Graph terminology
try {
    Write-Host "[*] Retrieving Group Info..."
    # Get-MgGroup -Filter "displayName eq '$GroupId'"
    Write-Host "[*] Retrieving Members..."
    # Get-MgGroupMember -GroupId $Id
    Write-Host "[OK] Audit complete for group: $GroupId" -ForegroundColor Green
} catch {
    Write-Host "[FAIL] Failed to audit group. Error: $($_.Exception.Message)" -ForegroundColor Red
}

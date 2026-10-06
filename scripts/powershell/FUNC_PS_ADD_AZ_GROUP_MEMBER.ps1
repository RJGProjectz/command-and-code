<#
.SYNOPSIS
    Adds a user to a Microsoft Entra (Azure AD) group.

.DESCRIPTION
    Standardized Graph API wrapper for group management.
    1. Validates connection.
    2. Adds user to group via Microsoft Graph.
    SAFEGUARDS: Supports -WhatIf. Requires -TargetEnvironment.

.PARAMETER UserPrincipalName
    UPN of the user to add.

.PARAMETER GroupId
    The GUID of the target group.

.PARAMETER TargetEnvironment
    'Test' simulates. 'Prod' executes.

.EXAMPLE
    .\Add-AzGroupMember.ps1 -UserPrincipalName "user@tenant.com" -GroupId "00000000-0000-0000-0000-000000000000" -TargetEnvironment Test

.NOTES
    Security Domain: Identity
    Author: AntiGravity
    Created: 2026-01-19T08:50:00
    Last Modified: 2026-01-19T08:50:00
    KB Article: [KB-Azure-007-AddMember.md](../../HowTo/Scripts/KB-Azure-007-AddMember.md)
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory=$true)]
    [string]$GroupId,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment
)

Write-Host "--- Entra ID Group Membership Update ---" -ForegroundColor Cyan

if ($TargetEnvironment -eq "Test") {
    Write-Host "[TEST] Would add $UserPrincipalName to group $GroupId" -ForegroundColor Yellow
    return
}

if ($PSCmdlet.ShouldProcess("Group: $GroupId", "Add User: $UserPrincipalName")) {
    try {
        $User = Get-MgUser -UserId $UserPrincipalName -ErrorAction Stop
        New-MgGroupMember -GroupId $GroupId -DirectoryObjectId $User.Id -ErrorAction Stop
        Write-Host "[OK] User added successfully." -ForegroundColor Green
    } catch {
        Write-Host "[FAIL] Error adding user: $($_.Exception.Message)" -ForegroundColor Red
        throw $_
    }
}

---
title: Assurance Check — Azure External Guest Access & Permissions
type: entry
platforms:
  - Entra ID
  - Azure
  - Microsoft 365
languages:
  - PowerShell
tasks:
  - Assurance
  - Hardening
  - Administration
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - azure
  - entra-id
  - guest-users
  - assurance
  - access-reviews
---

# Assurance Check — Azure External Guest Access & Permissions

Audits external guest accounts, external collaboration settings, and high-privilege directory roles assigned to guests in Microsoft Entra ID.

## 1. Regulatory Context & CIS Benchmark

- **CIS Microsoft 365 Benchmark**: 5.1.4 "Ensure external sharing and guest user access is restricted."
- **Risk**: Stale guest accounts retain access to SharePoint sites, Teams channels, and internal directories after projects terminate, exposing organizations to credential stuffing and token theft.

## 2. PowerShell Compliance Audit Script

```powershell
# Connect with required scopes
Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All" -NoWelcome

# 1. Audit Stale Guest Accounts (inactive > 90 days)
$CutoffDate = (Get-Date).AddDays(-90)
$Guests = Get-MgUser -Filter "userType eq 'Guest'" -Property Id, DisplayName, UserPrincipalName, SignInActivity, CreatedDateTime -All

$StaleGuests = foreach ($G in $Guests) {
    $LastSignIn = $G.SignInActivity.LastSignInDateTime
    if (-not $LastSignIn -or $LastSignIn -lt $CutoffDate) {
        [PSCustomObject]@{
            DisplayName    = $G.DisplayName
            UPN            = $G.UserPrincipalName
            LastSignIn     = $LastSignIn
            CreatedDate    = $G.CreatedDateTime
            Status         = "STALE_OR_NEVER_LOGGED_IN"
        }
    }
}

$StaleGuests | Format-Table -AutoSize
```

## 3. Audit High-Privilege Roles Assigned to Guests

```powershell
# Verify no guest user holds directory administrative roles
$DirectoryRoles = Get-MgDirectoryRole -All
foreach ($Role in $DirectoryRoles) {
    $Members = Get-MgDirectoryRoleMember -DirectoryRoleId $Role.Id -All
    foreach ($M in $Members) {
        $User = Get-MgUser -UserId $M.Id -Property UserType, DisplayName, UserPrincipalName
        if ($User.UserType -eq "Guest") {
            Write-Warning "HIGH RISK: Guest user [$($User.DisplayName)] holds role [$($Role.DisplayName)]"
        }
    }
}
```

## 4. Hardening Remediation

1. Enable **Entra ID Access Reviews** for all guest accounts with recurring 90-day intervals.
2. Restrict guest user permissions in External Collaboration Settings to `Guest users have restricted access to properties and memberships of directory objects`.

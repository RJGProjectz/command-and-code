---
title: User Lifecycle Management
type: workflow
platforms: [Windows, Windows Server, Entra ID, Microsoft 365]
languages: [PowerShell]
tasks: [Administration, Hardening]
category: Identity
tags: [user management, onboarding, offboarding, active directory, entra id, session revocation, credentials]
aliases: [create user, disable user, offboard employee, onboard user, password reset, ad user lifecycle]
difficulty: intermediate
verified: true
last_verified: 2026-10-06
search:
  boost: 3
---

# User Lifecycle Management

> **Created**: 2026-10-06T18:45:00Z  
> **Last Modified**: 2026-10-06T18:45:00Z  
> **Author**: RJGProjectz  

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> Account lifecycle changes modify authentication, authorization, and cloud sessions.
> 1. Ensure a verified HR or ticket authorization exists before creating or disabling accounts.
> 2. Always test offboarding against the targeted identity object with `-WhatIf` where applicable.
> 3. Document ticket IDs and timestamp in the change ledger.

**Trigger:** New hire onboarding, department transfer, or emergency/scheduled employee separation.

**Goal:** Execute complete identity lifecycle actions across Active Directory and Microsoft Entra ID with zero leftover privileges or stale sessions.

---

## 1. Onboarding: Standard User Provisioning

### Active Directory (On-Premises)

Create a standardized user with forced password reset on initial logon:

```powershell
$Params = @{
    Name                  = "Alex Mercer"
    GivenName             = "Alex"
    Surname               = "Mercer"
    SamAccountName        = "amercer"
    UserPrincipalName     = "amercer@<DOMAIN>"
    Path                  = "OU=Users,OU=Corporate,DC=domain,DC=local"
    AccountPassword       = (ConvertTo-SecureString -String 'InitPass123!Secure' -AsPlainText -Force)
    Enabled               = $true
    ChangePasswordAtLogon = $true
}
New-ADUser @Params
```

Assign baseline organizational security group:

```powershell
Add-ADGroupMember -Identity 'Corp-Standard-Users' -Members 'amercer'
```

### Entra ID / Microsoft 365 (Cloud-Only)

For organizations managing cloud identities with the Microsoft Graph PowerShell SDK:

```powershell
$PasswordProfile = @{
    ForceChangePasswordNextSignIn = $true
    Password                      = 'InitPass123!Secure'
}

New-MgUser -DisplayName "Alex Mercer" `
           -UserPrincipalName "amercer@<DOMAIN>" `
           -MailNickName "amercer" `
           -AccountEnabled `
           -PasswordProfile $PasswordProfile
```

---

## 2. Role Assignment & Elevation

Verify existing group membership before granting elevated roles:

```powershell
# Review existing AD groups
Get-ADPrincipalGroupMembership -Identity 'amercer' | Select-Object Name

# Add to role group
Add-ADGroupMember -Identity 'Tier1-Helpdesk' -Members 'amercer'
```

For Entra ID administrative roles, prefer Privileged Identity Management (PIM) or assign through administrative units rather than persistent Global Administrator roles.

---

## 3. Emergency Account Offboarding & Separation

When an employee departs, follow this sequence: **Disable → Revoke Sessions → Move to Disabled OU → Strip Groups**.

### Step 1: Revoke Active Cloud Sessions (Immediate)

```powershell
# Revoke all Entra ID refresh tokens immediately
Revoke-MgUserSignOut -UserId 'amercer@<DOMAIN>'
```

### Step 2: Disable the On-Premises Active Directory Account

```powershell
# Disable account and clear manager/description
Set-ADUser -Identity 'amercer' -Enabled $false -Description "Offboarded $(Get-Date -Format 'yyyy-MM-dd') per Ticket-9821"

# Invalidate Kerberos TGT tickets by resetting password
Set-ADAccountPassword -Identity 'amercer' -NewPassword (ConvertTo-SecureString -String ([Guid]::NewGuid().ToString()) -AsPlainText -Force) -Reset
```

### Step 3: Remove from Sensitive Groups and Quarantine

```powershell
# Move to Disabled Accounts Organizational Unit
Get-ADUser -Identity 'amercer' | Move-ADObject -TargetPath "OU=Disabled,DC=domain,DC=local"

# Remove all secondary group memberships (leaving primary Domain Users)
$Groups = Get-ADPrincipalGroupMembership -Identity 'amercer' | Where-Object { $_.Name -ne 'Domain Users' }
foreach ($Group in $Groups) {
    Remove-ADGroupMember -Identity $Group -Members 'amercer' -Confirm:$false
}
```

---

## 4. Mailbox & Data Preservation

Convert departing user mailbox to a shared mailbox to release licenses while preserving email for legal/compliance hold:

```powershell
# Exchange Online: Convert to shared mailbox
Set-Mailbox -Identity 'amercer@<DOMAIN>' -Type Shared

# Hide from Global Address List (GAL)
Set-Mailbox -Identity 'amercer@<DOMAIN>' -HiddenFromAddressListsEnabled $true
```

---

## Related

- [Windows Users and Groups](../../platforms/windows/users-groups.md)
- [Entra ID Management](../../platforms/microsoft-365/entra.md)
- [Exchange Online Operations](../../platforms/microsoft-365/exchange.md)
- [Account Compromise Investigation](../incident-response/account-compromise.md)

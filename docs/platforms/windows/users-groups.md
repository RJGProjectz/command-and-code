---
title: Windows Users and Groups
platforms: [Windows, Windows Server]
languages: [PowerShell, Windows CLI]
tasks: [Incident Response, Investigation, Administration, Hardening]
category: Identity
tags: [users, groups, local administrators, active directory, account lockout, sessions]
aliases: [local admins, who is logged on, domain admins members, disable account, locked out account, net user]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Windows Users and Groups

## Local users

```powershell
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, Description
```

## Local Administrators members

```powershell
Get-LocalGroupMember -Group 'Administrators' | Select-Object Name, ObjectClass, PrincipalSource
```

!!! note "Known failure"
    `Get-LocalGroupMember` throws an error when the group contains a member whose SID cannot be resolved (for example a deleted domain account). Fall back to `net localgroup administrators`.

**What to look for:** individual user accounts (rather than groups) in Administrators, recently added members, unknown local accounts.

## Who is logged on

```text
query user        (quser) — interactive and RDP sessions
qwinsta           all session states
```

```powershell
Get-CimInstance Win32_LoggedOnUser | Select-Object Antecedent -Unique
```

For historical logons use the [Security log](event-logs.md) or [`Get-RecentLogons.ps1`](../../toolbox/powershell.md#get-recentlogons).

## Disable a local account

```powershell
Disable-LocalUser -Name 'suspect'
```

**Windows CLI:** `net user suspect /active:no`

## Active Directory (RSAT ActiveDirectory module)

```powershell
Get-ADUser -Identity '<USER>' -Properties Enabled, LastLogonDate, PasswordLastSet, LockedOut, MemberOf, whenCreated
Get-ADGroupMember -Identity 'Domain Admins' -Recursive | Select-Object Name, SamAccountName, objectClass
Search-ADAccount -LockedOut | Select-Object Name, SamAccountName, LastLogonDate
Get-ADUser -Filter 'Enabled -eq $true' -Properties LastLogonDate |
    Where-Object LastLogonDate -lt (Get-Date).AddDays(-90) |
    Select-Object SamAccountName, LastLogonDate
```

!!! note "`-Filter` syntax"
    `Get-ADUser -Filter` uses its own PowerShell-like syntax inside a string. `'Enabled -eq $true'` works because the AD module expands the variable. `LastLogonDate` is replicated with up to ~14 days of lag by design — it is for stale-account checks, not precise timelines.

Recently created accounts:

```powershell
$since = (Get-Date).AddDays(-7)
Get-ADUser -Filter 'whenCreated -ge $since' -Properties whenCreated | Select-Object SamAccountName, whenCreated
```

Disable and contain:

```powershell
Disable-ADAccount -Identity '<USER>'
Unlock-ADAccount -Identity '<USER>'
```

**Windows CLI:** `net user <USER> /domain`, `net group "Domain Admins" /domain`.

## Account-management events

| Event | Meaning |
| --- | --- |
| 4720 | User account created |
| 4722 / 4725 | Account enabled / disabled |
| 4724 | Password reset attempt |
| 4726 | Account deleted |
| 4728 / 4732 / 4756 | Member added to global / local / universal security group |
| 4740 | Account locked out (on the PDC emulator) |

## Related

- [Account Compromise workflow](../../tasks/incident-response/account-compromise.md)
- [Entra ID](../microsoft-365/entra.md)
- [Linux users and permissions](../linux/users-permissions.md)

## Sources

- [Microsoft.PowerShell.LocalAccounts](https://learn.microsoft.com/powershell/module/microsoft.powershell.localaccounts/)
- [ActiveDirectory module](https://learn.microsoft.com/powershell/module/activedirectory/)

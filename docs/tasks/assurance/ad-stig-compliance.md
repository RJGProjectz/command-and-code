---
title: Assurance Check — Active Directory STIG Compliance
type: entry
platforms:
  - Windows Server
  - Active Directory
languages:
  - PowerShell
tasks:
  - Assurance
  - Hardening
verified: true
last_verified: 2026-10-12
difficulty: intermediate
tags:
  - assurance
  - active-directory
  - stig
  - compliance
---

# Assurance Check — Active Directory STIG Compliance

Audits Active Directory Domain Controller configurations against DISA STIG baselines, focusing on privileged group membership, the domain password and lockout policy, and `krbtgt` rotation.

**Run as:** a domain user with the RSAT `ActiveDirectory` module (read-only; no change is made). **Frequency:** monthly, and after any change to privileged groups.

## What the STIG expects

Values from the DISA *Windows Server* STIG (account policies) and *Active Directory Domain* STIG. Always check the exact rule IDs in the STIG version your organisation is assessed against.

| Setting | STIG requirement |
| --- | --- |
| Minimum password length | 14 characters or more |
| Password complexity | Enabled |
| Password history | 24 passwords remembered |
| Maximum password age | 60 days or less (not 0) |
| Minimum password age | 1 day or more |
| Reversible encryption | Disabled |
| Account lockout threshold | 3 invalid attempts or fewer (not 0) |
| Lockout duration | 15 minutes or more, or 0 (admin must unlock) |
| Reset lockout counter after | 15 minutes or more |
| `krbtgt` password | Reset at least every 180 days |
| Enterprise Admins, Schema Admins | Only accounts that need it; normally empty until used |
| Domain Admins | Only accounts that administer domain controllers; not used for daily work or on workstations |

## PowerShell compliance audit

```powershell
Import-Module ActiveDirectory

# 1. Default domain password and lockout policy
$policy = Get-ADDefaultDomainPasswordPolicy
$checks = @(
    @{ Name = 'MinPasswordLength >= 14';      Pass = $policy.MinPasswordLength -ge 14 }
    @{ Name = 'ComplexityEnabled';            Pass = $policy.ComplexityEnabled }
    @{ Name = 'PasswordHistoryCount >= 24';   Pass = $policy.PasswordHistoryCount -ge 24 }
    @{ Name = 'MaxPasswordAge 1-60 days';     Pass = $policy.MaxPasswordAge.TotalDays -gt 0 -and $policy.MaxPasswordAge.TotalDays -le 60 }
    @{ Name = 'MinPasswordAge >= 1 day';      Pass = $policy.MinPasswordAge.TotalDays -ge 1 }
    @{ Name = 'ReversibleEncryption off';     Pass = -not $policy.ReversibleEncryptionEnabled }
    @{ Name = 'LockoutThreshold 1-3';         Pass = $policy.LockoutThreshold -ge 1 -and $policy.LockoutThreshold -le 3 }
    @{ Name = 'LockoutDuration >= 15 or 0';   Pass = $policy.LockoutDuration.TotalMinutes -ge 15 -or $policy.LockoutDuration.TotalMinutes -eq 0 }
    @{ Name = 'LockoutObservation >= 15 min'; Pass = $policy.LockoutObservationWindow.TotalMinutes -ge 15 }
)
foreach ($check in $checks) {
    '{0,-6} {1}' -f $(if ($check.Pass) { 'PASS' } else { 'FAIL' }), $check.Name
}

# 2. krbtgt password age (STIG: reset at least every 180 days)
$krbtgt = Get-ADUser -Identity krbtgt -Properties PasswordLastSet
$age = ((Get-Date) - $krbtgt.PasswordLastSet).Days
'{0,-6} krbtgt password age {1} days' -f $(if ($age -le 180) { 'PASS' } else { 'FAIL' }), $age

# 3. Privileged group membership (recursive) for review
foreach ($group in 'Enterprise Admins', 'Schema Admins', 'Domain Admins', 'Administrators') {
    $members = @(Get-ADGroupMember -Identity $group -Recursive)
    '{0}: {1} member(s)' -f $group, $members.Count
    $members | ForEach-Object { '    ' + $_.SamAccountName }
}
```

Fine-grained password policies override the default policy for the users they apply to; list them too:

```powershell
Get-ADFineGrainedPasswordPolicy -Filter * |
    Select-Object Name, Precedence, MinPasswordLength, LockoutThreshold, AppliesTo
```

## Interpreting the results

- **Too many Domain Admins** is not a STIG number, but every extra account is another path to the domain. Many teams set a local target (for example 5 or fewer) and require a named owner for each account.
- Members of Enterprise Admins or Schema Admins outside a change window should be removed.
- A `krbtgt` password older than 180 days: reset it twice, at least 10 hours apart (longer than the maximum ticket lifetime), using Microsoft's documented procedure.
- Service accounts in Domain Admins are a common finding; replace them with delegated rights or group Managed Service Accounts.

## Related

- [Active Directory Domain Management](../administration/active-directory-domain-management.md)
- [Kerberoasting and AS-REP Roasting Hunting](../threat-hunting/kerberoasting-asreproast-hunting.md)
- [CISA SCuBA Compliance](cisa-scuba-compliance.md)

## Sources

- [DISA STIG Library (Windows Server, Active Directory Domain)](https://public.cyber.mil/stigs/downloads/)
- [Microsoft Learn — Get-ADDefaultDomainPasswordPolicy](https://learn.microsoft.com/powershell/module/activedirectory/get-addefaultdomainpasswordpolicy)
- [Microsoft Learn — AD forest recovery: reset the krbtgt password](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)

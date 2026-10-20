---
title: Deploy Windows LAPS and Admin Tiering (Tier 0/1/2)
type: workflow
platforms: [Windows, Windows Server]
languages: [PowerShell]
tasks: [Hardening, Administration]
category: Workflow
security_domain: Identity
author: RJGProjectz
date_created: 2026-10-20
last_updated: 2026-10-20
tags: [laps, windows-laps, local-administrator, tiering, privileged-access, paw, protected-users, user-rights, lateral-movement]
aliases: [windows laps deployment, Update-LapsADSchema, Set-LapsADComputerSelfPermission, Set-LapsADReadPasswordPermission, Set-LapsADResetPasswordPermission, Find-LapsADExtendedRights, Get-LapsADPassword, Reset-LapsPassword, Invoke-LapsPolicyProcessing, laps password encryption, ADPasswordEncryptionPrincipal, laps event 10018, admin tier model, tier 0 tier 1 tier 2, deny log on locally tier, privileged access workstation, paw basics, protected users group, authentication policy silo]
difficulty: advanced
verified: true
last_verified: 2026-10-20
---

# Deploy Windows LAPS and Admin Tiering (Tier 0/1/2)
> **Created**: 2026-10-20T18:30:00Z
> **Last Modified**: 2026-10-20T18:30:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> `Update-LapsADSchema` changes the forest schema (one time, cannot be undone). Deny-logon user rights
> applied to the wrong OU lock admins out of servers. Test the GPOs on a pilot OU, keep a break-glass
> account outside the deny groups, and run every `Set-*` command with `-WhatIf` first where it exists.

**Trigger:** every machine has the same local Administrator password, or domain admins log on to
workstations and servers, so one compromised PC leads to the whole domain.

**Goal:** each computer has a unique, rotated local admin password that only named groups can read,
and admin accounts can log on only to machines of their own tier.

| Control | Stops | Section |
| :--- | :--- | :--- |
| Windows LAPS | reuse of one local admin password (pass-the-hash between machines) | 1-5 |
| Tier logon restrictions | Tier 0 credentials left on Tier 1/2 machines | 6 |
| Protected Users, PAW | credential caching and theft on the admin's own machine | 7 |

## 1. Prerequisites and schema

Windows LAPS is built into Windows 11, Windows 10 (April 2023 update and later) and Windows Server
2019 and later; it is not the legacy "Microsoft LAPS" MSI. Password encryption in AD needs domain
functional level 2016 or later.

```powershell
Get-ADDomain | Select-Object DomainMode        # Windows2016Domain or later for encryption
Import-Module LAPS
Update-LapsADSchema -Verbose                   # once per forest, as Schema Admin
```

If you used legacy LAPS, plan the move: the new policy and attributes (`msLAPS-*`) are separate from
the old `ms-Mcs-AdmPwd`. Do not let both manage the same account.

## 2. Permissions on the computer OUs

```powershell
$ou = 'OU=Servers,OU=Tier1,DC=ad,DC=example,DC=com'

# The computers may write their own password
Set-LapsADComputerSelfPermission -Identity $ou

# Who may read and who may expire (force rotation) passwords
Set-LapsADReadPasswordPermission  -Identity $ou -AllowedPrincipals 'AD\T1-LAPS-Readers'
Set-LapsADResetPasswordPermission -Identity $ou -AllowedPrincipals 'AD\T1-LAPS-Resetters'

# Who else can read confidential attributes (should be SYSTEM and Domain Admins only)
Find-LapsADExtendedRights -Identity $ou
```

- Use separate reader groups per tier (`T0-`, `T1-`, `T2-LAPS-Readers`). A help desk group that reads
  Tier 2 passwords must not read Tier 1 server passwords.
- Anyone listed by `Find-LapsADExtendedRights` besides SYSTEM and Domain Admins can read every LAPS
  password in that OU. Remove those "All extended rights" grants.

## 3. Policy (GPO or Intune)

Configure under *Computer Configuration > Administrative Templates > System > LAPS* (or the LAPS CSP).

| Setting | Value | Note |
| :--- | :--- | :--- |
| Configure password backup directory (`BackupDirectory`) | Active Directory (`2`) | required |
| Password settings | complexity: large+small+numbers+specials, length 20, age 30 days | defaults are 14 chars, 30 days |
| Enable password encryption (`ADPasswordEncryptionEnabled`) | Enabled | needs DFL 2016 |
| Configure authorized password decryptors (`ADPasswordEncryptionPrincipal`) | `AD\T1-LAPS-Readers` | default is Domain Admins only |
| Name of administrator account to manage (`AdministratorAccountName`) | leave empty | empty = built-in Administrator by RID |
| Post-authentication actions | reset password and log off, delay 8 h | rotates after someone used it |

- Read permission (section 2) and decrypt permission (`ADPasswordEncryptionPrincipal`) are separate;
  a reader who is not a decryptor sees `DecryptionStatus: Unauthorized`.
- If you manage a custom account name, LAPS does not create it; create it first.

Apply and check on a pilot machine:

```powershell
Invoke-LapsPolicyProcessing
Get-WinEvent -LogName 'Microsoft-Windows-LAPS/Operational' -MaxEvents 20 |
    Select-Object TimeCreated, Id, Message          # 10018 = password updated in AD
```

## 4. Retrieve and rotate

```powershell
Get-LapsADPassword -Identity 'APP01' -AsPlainText          # Account, Password, ExpirationTimestamp, Source, DecryptionStatus
Get-LapsADPassword -Identity 'APP01' -IncludeHistory        # older passwords, if history is enabled

Set-LapsADPasswordExpirationTime -Identity 'APP01'          # expire now; device rotates at next cycle (hourly)
Reset-LapsPassword                                           # on the device itself: rotate immediately
```

Do not paste retrieved passwords into tickets or chat. After use, expire the password (or rely on the
post-authentication action).

## 5. Audit LAPS coverage

```powershell
$base = 'DC=ad,DC=example,DC=com'
Get-ADComputer -SearchBase $base -Filter 'Enabled -eq $true' -Properties msLAPS-PasswordExpirationTime, OperatingSystem |
    Select-Object Name, OperatingSystem,
        @{ Name = 'LapsExpires'; Expression = { if ($_.'msLAPS-PasswordExpirationTime') { [datetime]::FromFileTimeUtc($_.'msLAPS-PasswordExpirationTime') } } } |
    Where-Object { -not $_.LapsExpires -or $_.LapsExpires -lt (Get-Date).ToUniversalTime() } |
    Sort-Object Name                                         # machines with no or an overdue LAPS password
```

Readers of LAPS passwords belong in the [access review](../assurance/effective-permissions-access-review.md).

## 6. Admin tiering by user rights

| Tier | Holds | Admin accounts | May log on to |
| :--- | :--- | :--- | :--- |
| 0 | DCs, AD CS, AD Connect/Entra Connect, PAWs for Tier 0 | `t0-` accounts | Tier 0 only |
| 1 | member servers and apps | `t1-` accounts | Tier 1 servers |
| 2 | workstations, help desk | `t2-` accounts | workstations |

Put each tier's admin accounts in a group (`Tier0-Admins`, `Tier1-Admins`, `Tier2-Admins`) and link
deny-logon GPOs so a higher tier never logs on to a lower one:

| GPO linked to | Deny log on locally / through RDS / as batch / as service | Deny access from network |
| :--- | :--- | :--- |
| Tier 1 servers OU | `Tier0-Admins`, `Tier2-Admins` | `Tier0-Admins` |
| Workstations OU | `Tier0-Admins`, `Tier1-Admins` | `Tier0-Admins`, `Tier1-Admins` |
| Domain Controllers | `Tier1-Admins`, `Tier2-Admins` | — (keep DC network logon for Tier 0) |

User-right constants: `SeDenyInteractiveLogonRight`, `SeDenyRemoteInteractiveLogonRight`,
`SeDenyBatchLogonRight`, `SeDenyServiceLogonRight`, `SeDenyNetworkLogonRight`. See
[CIS user rights assignment](windows-cis-user-rights-assignment.md) for how to read and set them.

Check the effective rights on a member server:

```powershell
secedit /export /cfg "$Env:TEMP\rights.inf" /areas USER_RIGHTS | Out-Null
Select-String -Path "$Env:TEMP\rights.inf" -Pattern '^SeDeny' | ForEach-Object Line
Remove-Item "$Env:TEMP\rights.inf"
gpresult /scope computer /r | Select-String -Pattern 'Tier'
```

Stronger, harder to bypass option: **authentication policy silos** (`New-ADAuthenticationPolicy`,
`New-ADAuthenticationPolicySilo`) restrict where Tier 0 accounts can get Kerberos tickets. They need
DFL 2012 R2 and Kerberos armoring; pilot them after the GPO model works.

## 7. Protected Users and PAW basics

- Add Tier 0 (and Tier 1) **user** admin accounts to **Protected Users**: no NTLM, no DES/RC4, no
  delegation, no cached credentials, 4-hour TGT. Never add service accounts or computers. Details and
  commands: [AD Kerberos and LDAP hardening](ad-kerberos-ldap-hardening.md#5-step-4-deploy-the-protected-users-security-group).
- Set "Account is sensitive and cannot be delegated" on every admin account.
- A **PAW** (privileged access workstation) is the only machine where Tier 0 admins type their
  credentials: no email, no web browsing, no local admin for the user, Credential Guard on, tighter
  AppLocker/WDAC ([AppLocker rollout](applocker-deployment-rollout.md)).
- Admins use a separate daily account for email and browsing.

## 8. Verify

- [ ] Two computers have different LAPS passwords, and event 10018 appears after each rotation.
- [ ] A Tier 2 help desk user can read a workstation password and gets access denied on a server.
- [ ] `Find-LapsADExtendedRights` shows only SYSTEM and Domain Admins on each computer OU.
- [ ] A `t0-` account cannot log on to a member server or workstation (event **4625**, status
      `0xC000015B` "logon type not granted").
- [ ] The coverage report (section 5) is empty or every entry has a ticket.

ATT&CK relevance: LAPS and tiering break **T1550.002** (pass the hash) and **T1078.002/T1078.003**
(reuse of domain and local accounts) for lateral movement, and limit **T1003** credential dumping
to the tier where it happened.

## Related

- [AD Kerberos and LDAP hardening](ad-kerberos-ldap-hardening.md)
- [CIS user rights assignment](windows-cis-user-rights-assignment.md)
- [Active Directory management](../administration/active-directory-domain-management.md)
- [Delegated administration (JEA, sudo, polkit)](../administration/delegated-admin-jea-sudo-polkit.md)
- [Effective permissions and access review](../assurance/effective-permissions-access-review.md)

## Sources

- [Windows LAPS overview](https://learn.microsoft.com/windows-server/identity/laps/laps-overview)
- [Get started with Windows LAPS and Windows Server AD](https://learn.microsoft.com/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [Windows LAPS policy settings](https://learn.microsoft.com/windows-server/identity/laps/laps-management-policy-settings)
- [Securing privileged access: enterprise access model](https://learn.microsoft.com/security/privileged-access-workstations/privileged-access-access-model)
- [Protected Users security group](https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/protected-users-security-group)

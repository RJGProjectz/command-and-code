---
title: Kerberoasting
type: concept
platforms: [Active Directory, Windows Server, Microsoft Defender]
languages: [PowerShell, KQL]
tasks: [Threat Hunting, Hardening, Investigation]
category: Identity Attacks
security_domain: Identity
author: RJGProjectz
date_created: 2026-10-11
last_updated: 2026-10-11
tags: [concept, kerberos, active-directory, credential-access]
aliases: [Kerberoast, SPN roasting, service ticket cracking, AS-REP roasting]
difficulty: intermediate
verified: false
---

# Kerberoasting
> **Created**: 2026-10-11T22:00:00Z
> **Last Modified**: 2026-10-11T22:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

**In one line:** any domain user can ask for a service ticket, and part of that ticket is encrypted with the service account's password — so weak service passwords can be cracked offline.

## What it is

In Active Directory, a user account with a Service Principal Name (SPN) runs a service. When anyone requests a ticket for
that SPN, the domain controller returns a ticket encrypted with a key derived from that account's password. An attacker
with any domain login requests tickets for many SPNs, takes them away, and guesses passwords offline with no lockout and no
further network traffic. Its cousin, **AS-REP roasting**, targets accounts with Kerberos pre-authentication turned off.

## How it works

```text
[Any user] ──TGS-REQ for MSSQLSvc/db01──► [DC]
[Any user] ◄──TGS-REP (ticket encrypted with svc_sql's key, often RC4)── [DC]
[Attacker laptop] ── offline guessing against the ticket ──► svc_sql password
```

The full exchange is on the [Kerberos fundamentals](../kerberos.md) page.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) — Kerberoasting · [T1558.004](https://attack.mitre.org/techniques/T1558/004/) — AS-REP Roasting |
| **What it leads to** | a service account password — often privileged, rarely rotated, sometimes Domain Admin |
| **Where defenders meet it** | a burst of 4769 events from one user, RC4 tickets in an AES-only domain |

## Do it

```bash
cc find kerberoasting
cc view docs/tasks/threat-hunting/kerberoasting-asreproast-hunting.md
```

Check your exposure — user accounts with SPNs, and accounts without pre-authentication (needs the RSAT ActiveDirectory module):

```powershell
Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties ServicePrincipalName, PasswordLastSet, 'msDS-SupportedEncryptionTypes' |
    Select-Object -Property SamAccountName, PasswordLastSet, 'msDS-SupportedEncryptionTypes'
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' | Select-Object -Property SamAccountName
```

Old `PasswordLastSet` plus RC4 allowed = the accounts to fix first.

## See it

| Source | What you see |
| :--- | :--- |
| DC Security log 4769 | many service tickets requested by one account in minutes; `TicketEncryptionType` `0x17` (RC4) |
| DC Security log 4768 | AS-REP roasting: `PreAuthType` `0` for accounts without pre-authentication |
| Defender for Identity | "Suspected Kerberos SPN exposure" style alerts |

## Detect it

- Hunt: [Hunting Kerberoasting and AS-REP Roasting](../../tasks/threat-hunting/kerberoasting-asreproast-hunting.md) — KQL and SPL queries
- Event reference: [Windows event IDs](../../references/windows-event-ids.md)
- Harden: [AD Kerberos & LDAP hardening](../../tasks/hardening/ad-kerberos-ldap-hardening.md) — gMSA, AES-only, Protected Users
- Audit: [Advanced audit policy](../../tasks/hardening/windows-cis-advanced-audit-policy.md) — turn on Kerberos service ticket auditing

## Related concepts

- [Credential Dumping](credential-dumping.md)
- [Kerberos fundamentals](../kerberos.md)

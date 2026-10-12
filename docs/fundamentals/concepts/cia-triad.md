---
title: CIA Triad and Least Privilege
type: concept
platforms: [Windows, Linux]
languages: [PowerShell, Bash]
tasks: [Hardening, Assurance]
category: Security Principles
security_domain: Governance
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, cia-triad, least-privilege, principles]
aliases: [CIA Triad, Confidentiality, Integrity, Availability, Least Privilege Principle, Cybersecurity Fundamentals]
difficulty: basic
verified: false
---

# CIA Triad and Least Privilege
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** every security control protects confidentiality, integrity or availability of something, and least privilege limits how much any one account can damage when it is compromised.

## What it is

| Pillar | Question | Typical controls | Typical attack |
| :--- | :--- | :--- | :--- |
| **Confidentiality** | can only the right people read it? | [encryption](cryptography-fundamentals.md), [access control](access-control-models.md), DLP | data theft, [packet sniffing](packet-sniffing.md) |
| **Integrity** | is it unchanged and from the right source? | [hashes](hash-functions.md), [signatures](digital-signatures.md), change control, file-integrity monitoring | tampering, [MITM](man-in-the-middle.md) |
| **Availability** | can people use it when needed? | redundancy, backups, DDoS protection, capacity | [DoS](denial-of-service.md), [ransomware](ransomware.md) |

Often extended with **authenticity**, **non-repudiation** ([digital signatures](digital-signatures.md)) and
**accountability** (logging). Risk decisions weigh which pillar matters most for a system: a hospital's patient monitor
favours availability, a password vault confidentiality, a payment ledger integrity.

**Least privilege** gives every user, service and process only the rights it needs, only for as long as it needs them.
It pairs with **separation of duties** (no one person can complete a sensitive action alone) and **need to know**.

## How it works

1. Classify the asset and decide which pillar is critical.
2. Grant the minimum role ([RBAC](access-control-models.md)), time-bound where possible ([PAM / just-in-time](identity-access-management.md)).
3. Remove standing admin rights, local admin on workstations, and wildcard API scopes.
4. Review access regularly and log every use of privilege.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts · [T1068](https://attack.mitre.org/techniques/T1068/) Exploitation for Privilege Escalation · [T1098](https://attack.mitre.org/techniques/T1098/) Account Manipulation |
| **What it leads to** | over-privileged accounts turn one phished user into domain or tenant compromise |
| **Where defenders meet it** | audit findings, incident scoping ("what could this account reach?"), risk assessments |

## Do it

```powershell
# What can I do right now? Privileges and group memberships of the current token
whoami /priv
whoami /groups
# Who has local admin on this machine?
Get-LocalGroupMember -Group 'Administrators'
```

```bash
# Linux: sudo rights of the current user, and members of the admin groups
sudo -l
getent group sudo wheel
```

## See it

| Source | What you see |
| :--- | :--- |
| Security event 4672 | "special privileges assigned to new logon" — every admin logon |
| Security events 4728 / 4732 / 4756 | a member added to a global / local / universal security group |
| Entra `AuditLogs` | "Add member to role" — new standing admin |

## Detect it

- Assurance: [Linux sudoers integrity](../../tasks/assurance/linux-sudoers-integrity.md) · [AD STIG compliance](../../tasks/assurance/ad-stig-compliance.md)
- Harden: [Windows user rights assignment](../../tasks/hardening/windows-cis-user-rights-assignment.md)
- Investigate: [Account compromise](../../tasks/incident-response/account-compromise.md)

## Related concepts

- [Access Control Models](access-control-models.md) · [Identity and Access Management](identity-access-management.md) · [Defense in Depth](defense-in-depth.md)

---
title: Access Control Models (ACL, DAC, MAC, RBAC, ABAC)
type: concept
platforms: [Windows, Linux, Azure]
languages: [PowerShell, Bash]
tasks: [Hardening, Administration, Assurance]
category: Identity Concepts
security_domain: Identity
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, access-control, authorization, rbac, abac]
aliases: [Access Control, Access Control Lists (ACLs), Authorization, Authorization Models, Discretionary Access Control (DAC), Mandatory Access Control (MAC), Role-Based Access Control (RBAC), Attribute-Based Access Control (ABAC)]
difficulty: basic
verified: false
---

# Access Control Models (ACL, DAC, MAC, RBAC, ABAC)
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** authentication proves who you are; authorization — access control — decides what you may do, using lists, owners, labels, roles or attributes.

## What it is

| Model | Who decides | Example |
| :--- | :--- | :--- |
| **ACL** (access control list) | a list on each object: principal → allowed actions | NTFS permissions, firewall rules, S3 bucket ACLs |
| **DAC** (discretionary) | the object's owner grants access at will | Windows/Linux file ownership — owners can over-share |
| **MAC** (mandatory) | the system enforces labels; users cannot override | SELinux, AppArmor, Windows integrity levels, classified systems |
| **RBAC** (role-based) | permissions attach to roles, users get roles | Azure RBAC, Entra roles, AD groups |
| **ABAC** (attribute-based) | policy evaluates attributes of user, resource and context | Conditional Access ("compliant device + MFA + country"), AWS IAM conditions |

Most environments mix them: RBAC for administration, ACLs on files, MAC as a safety net on Linux, ABAC for cloud
sign-in policy. **Zero trust** pushes toward ABAC — every request evaluated on identity, device and risk.

## How it works

1. A subject (user, service, process) requests an action on an object.
2. The reference monitor collects the subject's identity, groups/roles and attributes.
3. Policy is evaluated — explicit deny wins over allow in most systems (NTFS, Azure, AWS).
4. The decision is logged; denies are a useful detection signal.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1222](https://attack.mitre.org/techniques/T1222/) File and Directory Permissions Modification · [T1098](https://attack.mitre.org/techniques/T1098/) Account Manipulation · [T1548](https://attack.mitre.org/techniques/T1548/) Abuse Elevation Control Mechanism |
| **What it leads to** | broken access control is the #1 OWASP web risk; over-broad ACLs expose shares and buckets |
| **Where defenders meet it** | "Everyone: Full Control" shares, public storage buckets, role sprawl in cloud subscriptions |

## Do it

```powershell
# Who can do what on a folder (ACL)
Get-Acl -Path 'D:\Shares\Finance' | Select-Object -ExpandProperty Access |
    Select-Object -Property IdentityReference, FileSystemRights, AccessControlType, IsInherited
icacls 'D:\Shares\Finance'
# Azure RBAC: role assignments on a subscription
Get-AzRoleAssignment | Select-Object -Property DisplayName, RoleDefinitionName, Scope
```

```bash
# DAC and extended ACLs on Linux
ls -l /srv/data ; getfacl /srv/data
# MAC: is SELinux enforcing, and what label does a file carry?
getenforce ; ls -Z /var/www/html
```

## See it

| Source | What you see |
| :--- | :--- |
| Security event 4670 | permissions on an object were changed |
| Security event 4663 (with SACL) | object access attempts, including denied ones |
| SELinux `audit.log` | `avc: denied` lines naming the subject and object labels |
| Azure Activity log | `Microsoft.Authorization/roleAssignments/write` |

## Detect it

- Harden: [Azure policy](../cloud/azure-policy.md) · [Conditional Access](../../platforms/microsoft-365/conditional-access.md)
- Investigate: [File & registry events (KQL)](../../detection/kql/file-registry-events.md)
- Principles: [CIA triad and least privilege](cia-triad.md)

## Related concepts

- [CIA Triad and Least Privilege](cia-triad.md) · [Authentication, MFA and SSO](authentication-mfa-sso.md) · [Identity and Access Management](identity-access-management.md)

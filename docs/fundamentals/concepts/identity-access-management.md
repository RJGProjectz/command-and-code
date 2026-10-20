---
title: Identity and Access Management (IAM, PAM, Directory Services)
type: concept
platforms: [Windows Server, Entra ID, Azure]
languages: [PowerShell, KQL]
tasks: [Administration, Hardening, Assurance]
category: Identity Concepts
security_domain: Identity
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, iam, pam, directory, governance]
aliases: [Identity and Access Management, IAM in the Cloud, IAM Policy and Governance, Identity as a Service, User Identity Management, Emerging Technologies in IAM, Directory Services, Privileged Access Management]
difficulty: intermediate
verified: false
---

# Identity and Access Management (IAM, PAM, Directory Services)
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** IAM manages the whole life of every identity — create, grant, review, revoke — and PAM puts the most powerful accounts behind extra controls.

## What it is

| Area | What it covers | Examples |
| :--- | :--- | :--- |
| **Directory services** | the authoritative store of users, groups and devices | Active Directory, [LDAP](../identity/ldap.md), Entra ID |
| **Identity lifecycle** | joiner / mover / leaver, driven from HR | provisioning (SCIM), deprovisioning on exit |
| **IAM governance** | access reviews, certifications, role design, policy | Entra ID Governance, SailPoint |
| **Identity as a Service (IDaaS)** | cloud IdP providing SSO, MFA, lifecycle | Entra ID, Okta, Ping |
| **Cloud IAM** | roles and policies for cloud resources and workloads | Azure RBAC, AWS IAM, managed identities |
| **PAM** | vaulting, rotation, just-in-time elevation, session recording for admins | Entra PIM, LAPS, CyberArk |

Emerging directions: passkeys replacing passwords, workload identities (federated credentials instead of secrets),
identity threat detection and response (ITDR), and continuous access evaluation.

## How it works

- **Joiner:** HR record → account created with role-based birthright access.
- **Mover:** role change → old access removed, not just new access added (the classic "privilege creep").
- **Leaver:** disable immediately, revoke sessions and tokens, rotate shared secrets they knew.
- **Privileged:** separate admin accounts, tiered admin model (Tier 0 = domain controllers/IdP), no standing access —
  elevate just in time with approval and MFA.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts · [T1098](https://attack.mitre.org/techniques/T1098/) Account Manipulation · [T1136](https://attack.mitre.org/techniques/T1136/) Create Account |
| **What it leads to** | orphaned accounts of leavers, privilege creep, attackers persisting by adding roles or credentials |
| **Where defenders meet it** | access reviews, stale-account reports, new Global Admin alerts |

## Do it

```powershell
# Enabled AD users who have not logged on for 90 days (leaver/orphan candidates)
Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -UsersOnly |
    Where-Object -Property Enabled -EQ -Value $true | Select-Object -Property SamAccountName, LastLogonDate
# Effective members of Domain Admins (nested groups expanded)
Get-ADGroupMember -Identity 'Domain Admins' -Recursive | Select-Object -Property SamAccountName, objectClass
# Windows LAPS: current local admin password info for one computer (needs rights)
Get-LapsADPassword -Identity 'PC-0042' | Select-Object -Property ComputerName, ExpirationTimestamp
```

```kql
// New privileged role assignments in Entra ID
AuditLogs
| where OperationName in ("Add member to role", "Add eligible member to role")
| extend Role = tostring(TargetResources[0].modifiedProperties[1].newValue)
| project TimeGenerated, InitiatedBy = tostring(InitiatedBy.user.userPrincipalName), Target = tostring(TargetResources[0].userPrincipalName), Role
```

Full LAPS rollout and admin tiers: [Deploy Windows LAPS and admin tiering](../../tasks/hardening/windows-laps-admin-tiering.md).

## See it

| Source | What you see |
| :--- | :--- |
| Entra `AuditLogs` | role assignments, PIM activations, app credential additions |
| Security events 4720 / 4726 / 4738 | account created / deleted / changed |
| Access-review reports | users who still hold access the reviewer could not justify |

## Detect it

- Harden: [AD Kerberos & LDAP hardening](../../tasks/hardening/ad-kerberos-ldap-hardening.md) · [Entra ID](../../platforms/microsoft-365/entra.md)
- Investigate: [Compromised service principal](../../tasks/incident-response/compromised-service-principal.md)
- Principles: [CIA triad and least privilege](cia-triad.md)

## Related concepts

- [Authentication, MFA and SSO](authentication-mfa-sso.md) · [Access Control Models](access-control-models.md) · [Credential Dumping](credential-dumping.md) · [Kerberoasting](kerberoasting.md)

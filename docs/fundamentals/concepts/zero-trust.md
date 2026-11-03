---
title: Zero Trust Architecture
type: concept
platforms: [Windows, Linux, Azure, AWS]
languages: [PowerShell, KQL]
tasks: [Hardening, Administration, Detection Engineering]
category: Security Operations
security_domain: Network
author: RJGProjectz
date_created: 2026-11-03
last_updated: 2026-11-03
tags: [zero-trust, ZTA, microsegmentation, never-trust-always-verify, BeyondCorp, NIST-SP-800-207, control-plane, data-plane, identity-perimeter, SASE, conditional-access]
aliases: [zero trust, ZTA, never trust always verify, microsegmentation, identity-centric security, BeyondCorp, software-defined perimeter]
difficulty: intermediate
verified: false
---

# Zero Trust Architecture
> **Created**: 2026-11-03T00:00:00Z
> **Last Modified**: 2026-11-03T00:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

**In one line:** zero trust is a security model that removes implicit trust from the network and instead requires every request — from inside or outside the perimeter — to be continuously authenticated, authorized, and inspected.

## What it is

The traditional perimeter security model assumed that traffic inside the corporate network was trustworthy. This assumption broke as remote work, cloud services, BYOD, and supply-chain compromise made the network boundary meaningless. Zero trust replaces that boundary with identity and context: the network is always treated as hostile, and no user, device, or workload is trusted by default regardless of where it connects from.

The phrase "never trust, always verify" captures the core posture. It was popularized by John Kindervag at Forrester Research around 2010 and later formalized by NIST in **Special Publication 800-207 (Zero Trust Architecture, 2020)**.

Google's internal deployment, called **BeyondCorp**, is the canonical large-scale implementation. After the 2009 Operation Aurora breach, Google rebuilt its access model so that no application relied on being inside the corporate network — every access decision was made by a central policy engine evaluating device health, user identity, and request context.

## How it works

A zero trust network is built on five assertions (from *Zero Trust Networks*, O'Reilly, 2nd ed.):

1. The network is always assumed to be hostile.
2. External and internal threats exist on the network at all times.
3. Network locality is not sufficient to decide trust.
4. Every device, user, and network flow is authenticated and authorized.
5. Policies must be dynamic and calculated from as many data sources as possible.

### Control Plane and Data Plane

Zero trust separates **policy decisions** from **traffic forwarding**:

- **Control plane** — the policy decision engine. When a user or workload requests access to a resource, the control plane evaluates identity, device posture, time, location, and risk score, then issues an allow or deny decision. Access grants are time-bound and context-dependent.
- **Data plane** — the enforcement fabric. It carries actual traffic and is dynamically configured by the control plane. Traffic only flows where the control plane has authorized it, and only for as long as the grant remains valid.

This separation means that a compromised network segment cannot be used to reach adjacent resources — the data plane will not forward unapproved traffic regardless of the attacker's network position.

### Five Pillars

CISA and NIST define zero trust implementation around five pillars:

| Pillar | What it secures | Key technologies |
| :--- | :--- | :--- |
| Identity | Users and service accounts | MFA, Entra ID Conditional Access, Privileged Identity Management |
| Device | Endpoints | MDM/UEM, compliance policies, Defender for Endpoint |
| Network | Traffic paths and segmentation | Microsegmentation, ZTNA, SASE |
| Application | App-layer access | App proxy, API gateway, per-app MFA |
| Data | Data classification and protection | DLP, AIP/MIP sensitivity labels, encryption at rest/in-transit |

## Why it matters

| | |
| :--- | :--- |
| **Framework alignment** | NIST SP 800-207, CISA Zero Trust Maturity Model, DoD ZTA Reference Architecture, Microsoft E5 ZT Blueprint |
| **What it prevents** | Lateral movement after initial compromise — an attacker who obtains one credential cannot freely traverse the internal network |
| **Where defenders meet it** | Cloud transformation programs, Conditional Access policy design, microsegmentation projects, and Zero Trust Maturity Assessments |

## Contrasting Perimeter and Zero Trust

| Dimension | Perimeter model | Zero trust model |
| :--- | :--- | :--- |
| Trust anchor | Network location (inside = trusted) | Identity + device posture + context |
| VPN | Required for remote access | Replaced by ZTNA / app proxy |
| Lateral movement | Easy once inside the perimeter | Blocked by microsegmentation and per-resource auth |
| Implicit trust | All internal traffic | No traffic, anywhere |
| Authentication | At the edge (login once, roam freely) | Continuous, per-resource |

## Do it

Check your current Conditional Access posture in Microsoft Entra ID (Azure AD):

```powershell
# Requires AzureAD or Microsoft.Graph module
Connect-MgGraph -Scopes "Policy.Read.All"
Get-MgIdentityConditionalAccessPolicy | Select-Object DisplayName, State | Format-Table
```

Enumerate devices not meeting compliance:

```kusto
// KQL — Intune non-compliant devices
DeviceComplianceOrg
| where ComplianceState != "Compliant"
| project DeviceName, OS, UserPrincipalName, LastContact
| order by LastContact asc
```

Audit privileged role assignments (Tier 0 accounts should be protected):

```powershell
# List members of high-privilege Entra ID roles
Get-MgDirectoryRoleMember -DirectoryRoleId (Get-MgDirectoryRole | Where DisplayName -eq "Global Administrator").Id |
    Select-Object AdditionalProperties
```

## See it

Zero trust controls show up in:

| Source | What you see |
| :--- | :--- |
| Conditional Access sign-in logs | Block events for non-compliant devices or risky sign-ins |
| Entra ID Identity Protection | Risk detections: unfamiliar sign-in properties, impossible travel, malware-linked IP |
| Firewall / segmentation logs | East-west traffic that is denied because no policy permits it |
| ZTNA access logs | Per-application authentication events for users who would previously have roamed freely on VPN |

## Detect it

- Detection: [Entra ID Conditional Access rules](../../detection/sigma/cloud-identity-rules.md)
- Hunt: [Threat Hunting workflow](../../tasks/threat-hunting/index.md)
- Harden: [Hardening tasks](../../tasks/hardening/index.md)

## Related concepts

- [Defense in Depth and Secure Network Design](defense-in-depth.md)
- [Threat Modeling](threat-modeling.md)
- [Authentication, MFA, SSO and Federation](authentication-mfa-sso.md)
- [Access Control Models](access-control-models.md)
- [Identity and Access Management](identity-access-management.md)
- [Security Controls](security-controls.md)

## External Resources

- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [CISA Zero Trust Maturity Model v2](https://www.cisa.gov/zero-trust-maturity-model)
- [Microsoft Zero Trust Guidance Center](https://learn.microsoft.com/en-us/security/zero-trust/)
- [Google BeyondCorp: A New Approach to Enterprise Security](https://cloud.google.com/beyondcorp)
- [Zero Trust Networks, 2nd ed. (O'Reilly) — Rais, Morillo, Gilman, Barth](https://www.oreilly.com/library/view/zero-trust-networks/9781492096597/)

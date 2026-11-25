---
title: Enterprise Security Architecture
type: concept
platforms: [Windows, Azure, AWS]
languages: [PowerShell]
tasks: [Governance, Hardening, Assurance]
category: Security Architecture
security_domain: Governance
author: RJGProjectz
date_created: 2026-11-24
last_updated: 2026-11-24
tags: [concept, enterprise-architecture, security-architecture, TOGAF, hybrid-cloud, ABB, solution-architecture, zero-trust]
aliases: [EA, enterprise architecture, security EA, TOGAF, solution architecture, hybrid cloud architecture, security framework]
difficulty: advanced
verified: false
---

# Enterprise Security Architecture
> **Created**: 2026-11-24T00:00:00Z
> **Last Modified**: 2026-11-24T00:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

**In one line:** enterprise security architecture (ESA) is a structured, organization-wide approach to aligning an organization's business objectives with its information systems and security controls through consistent design principles and reusable building blocks.

## What it is

Security architecture bridges business strategy and technical implementation. Where individual security controls (a firewall rule, an MFA policy, an IDS signature) address specific threats, enterprise architecture provides the blueprint that makes those controls coherent, non-redundant, and traceable to business requirements [Security Architecture for Hybrid Cloud, p. 63].

An enterprise architecture (EA) provides:

- A **holistic view** of the organization's information systems and their relationships
- **Architectural building blocks (ABBs)** — reusable, generic capability descriptions (e.g., "identity governance service", "network segmentation capability")
- **Guiding principles** that individual teams apply when making design decisions
- A **living framework** that evolves as business goals change and new technologies emerge

The most widely adopted EA framework is **TOGAF** (The Open Group Architecture Framework), which is vendor-neutral and published under continuous improvement by The Open Group. TOGAF defines enterprise architecture as:

> *The process of translating business vision and strategy into effective enterprise change by creating, communicating, and improving the key principles and models that describe the enterprise's future state and enabling its evolution.* [Security Architecture for Hybrid Cloud, p. 63]

For security practitioners, EA is not primarily about documentation — it is about making security decisions that are consistent, defensible, and resistant to point-solution sprawl.

## How it works

### Enterprise architecture vs. solution architecture

| Dimension | Enterprise Architecture | Solution Architecture |
| :--- | :--- | :--- |
| **Scope** | Whole organization or major program | Specific workload or system |
| **Output** | Principles, ABBs, guidelines, roadmaps | Design specification, deployment diagrams |
| **Audience** | CISOs, CIOs, program managers | Architects, engineers, DevOps teams |
| **Timeframe** | Long-term (3–5 year horizon) | Project delivery timeframe |
| **Tool** | TOGAF Architecture Continuum | Solution Architecture Document (SAD) |

A solution architecture is *derived from* the enterprise architecture — it is a specific answer to a specific problem, constrained by and consistent with the broader EA framework [Security Architecture for Hybrid Cloud, p. 64].

### Architecture building blocks (ABBs)

ABBs describe generic capabilities without committing to a specific product or vendor. This allows the enterprise architecture to remain stable even as underlying technologies change:

| ABB | Example capability | May be implemented by |
| :--- | :--- | :--- |
| Identity governance | Manage the user lifecycle, entitlements, and access reviews | Azure AD / Entra ID, SailPoint, Okta |
| Network access control | Enforce who can reach which network segment | Cisco ISE, Juniper NAC, 802.1X |
| Security event monitoring | Collect, correlate, and alert on security telemetry | Splunk, Microsoft Sentinel, Elastic SIEM |
| Data classification | Label and control data based on sensitivity | Microsoft Purview, Varonis |
| Vulnerability management | Continuously assess and remediate weaknesses | Nessus, Qualys, Rapid7 |

### Security services vs. security processes

One significant shift in modern ESA is treating security capabilities as **services** rather than processes [Security Architecture for Hybrid Cloud, p. 73]. A process has a process owner and a defined workflow; a service has a consumer, a provider, and a service-level agreement. Describing security as services:

- Aligns with cloud and DevSecOps operating models
- Enables security capabilities to be catalogued, priced, and consumed on-demand
- Supports clear accountability — the service has a named owner and an SLA

For example, "MFA enrollment" is a *service* consumed by identity governance, not a step in an IT process. This distinction matters when designing security in hybrid or multi-cloud environments where the boundary between organizational and cloud-provider responsibility is defined by service contracts.

### Key design principles

Principles guide decisions at every level of the architecture [Security Architecture for Hybrid Cloud, p. 63]:

1. **Architect for change** — assume systems will evolve; prefer modular, loosely coupled designs over monolithic ones
2. **Build, test, deploy, and operate as one** — security is embedded in the SDLC pipeline, not bolted on at release
3. **Team topology mirrors architecture** — Conway's Law predicts that your systems will reflect your organizational structure; design teams and architecture together
4. **Least privilege by default** — identities, services, and infrastructure components should start with minimal rights and elevate only when needed
5. **Secure failure modes** — when a component fails, it should fail securely (deny all) rather than fail open

### The TOGAF Architecture Development Method (ADM)

The TOGAF ADM is an iterative cycle for developing and maintaining an enterprise architecture:

```
Preliminary Phase — establish capability & governance
       ↓
Phase A — Architecture Vision
       ↓
Phase B — Business Architecture
       ↓
Phase C — Information Systems Architecture (Data + Applications)
       ↓
Phase D — Technology Architecture
       ↓
Phases E–H — Opportunities, Solutions, Migration Planning, Governance
       ↓
Requirements Management (continuous, intersects all phases)
```

For security architects, Phase D (Technology Architecture) is where network segmentation, platform security controls, and security tooling are defined. Phase C is where data classification and application security requirements are set. The ADM ensures these phases are connected to business requirements rather than driven by tool vendor proposals.

## Why it matters

| | |
| :--- | :--- |
| **What it prevents** | Security sprawl — redundant, overlapping tools with no coherent control plane; ungoverned cloud resources |
| **Regulatory drivers** | ISO/IEC 27001 Clause 4 (organizational context), NIST CSF Govern function, SOC 2 security criteria |
| **Where defenders meet it** | Architecture review boards, cloud landing zone design, M&A due diligence, audit responses |

Security decisions made without an architecture framework tend to be reactive, vendor-driven, and inconsistent across business units. An EA provides the shared vocabulary and decision criteria that allow multiple teams to make compatible choices independently [Security Architecture for Hybrid Cloud, p. 73].

## Do it

Enumerate Azure resource groups to identify unapproved architectural components:

```powershell
# List all Azure resource groups and their locations
# (requires Az.Resources module and authentication)
Connect-AzAccount -TenantId "<tenant-id>"
Get-AzResourceGroup | Select-Object ResourceGroupName, Location, Tags |
  Sort-Object ResourceGroupName |
  Format-Table -AutoSize
```

Review Active Directory organizational unit (OU) structure for alignment with architectural tiers:

```powershell
# List top-level OUs (reflects how the org has modelled its identity architecture)
Get-ADOrganizationalUnit -Filter * -SearchBase "DC=contoso,DC=com" -SearchScope OneLevel |
  Select-Object Name, DistinguishedName |
  Sort-Object Name
```

Review which security services are consuming SIEM telemetry (indicates which capabilities are actively monitored):

```powershell
# Check Splunk forwarder status on Windows hosts (shows what's sending telemetry)
Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue |
  Select-Object Name, Status, StartType
```

## See it

Evidence of an immature or absent enterprise architecture:

| Source | What you see |
| :--- | :--- |
| Cloud environment | Multiple untagged subscriptions with no naming convention or cost-centre tags |
| Active Directory | Flat OU structure with all computers in a single container |
| Security tooling | Duplicate SIEM and EDR platforms with no defined integration |
| Risk register | No formal mapping between controls and business requirements |
| Audit findings | Repeated findings across audits with no architectural remediation track |

## Detect it

- Detection: architecture review processes should include a security architecture review gate for all new systems; flag systems deployed without review
- Cross-reference: [Zero Trust](zero-trust.md), [Defense in Depth](defense-in-depth.md), [Risk Management and Governance](risk-management-governance.md), [Secure SDLC / DevSecOps](secure-sdlc-devsecops.md)

---
*Sources: Security Architecture for Hybrid Cloud (O'Reilly, 2022), p. 39–41, 63–64, 73–78.*

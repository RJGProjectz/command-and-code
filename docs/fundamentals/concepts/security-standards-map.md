---
title: Security Standards Map (ISO/IEC 27000 series, NIST SP 800)
type: concept
platforms: [Windows, Linux, Azure]
languages: [PowerShell]
tasks: [Compliance, Assurance, Hardening]
category: Governance and Law
security_domain: Governance
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, standards, iso27001, nist, frameworks]
aliases: [Security Standards and Best Practices, Cybersecurity Frameworks, Risk Management Framework, ISOIEC 27001, ISOIEC 27002, ISOIEC 27017, ISOIEC 27018, ISOIEC 27031, ISOIEC 27032, ISOIEC 27037, ISOIEC 27043, NIST Special Publication 800-34, NIST Special Publication 800-37, NIST Special Publication 800-50, NIST Special Publication 800-53, NIST Special Publication 800-63, NIST Special Publication 800-63B, NIST Special Publication 800-83, NIST Special Publication 800-86, NIST Special Publication 800-92, "NIST Special Publication 800-101, Revision 1", NIST Special Publication 800-115, NIST Special Publication 800-124, NIST Special Publication 800-144]
difficulty: intermediate
verified: false
---

# Security Standards Map (ISO/IEC 27000 series, NIST SP 800)
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** a lookup of which standard answers which question — so you cite the right document in a policy, audit or design review.

## What it is

**ISO/IEC 27000 family** (international, certifiable for 27001):

| Standard | Covers |
| :--- | :--- |
| **27001** | requirements for an information security management system (ISMS); Annex A lists 93 controls (2022) — the certifiable one |
| **27002** | guidance on implementing those controls |
| **27017** | security controls for cloud services (provider and customer) |
| **27018** | protecting personal data (PII) in public clouds |
| **27031** | ICT readiness for business continuity |
| **27032** | cybersecurity / internet security guidelines |
| **27037** | identifying, collecting, acquiring and preserving digital evidence |
| **27043** | incident investigation principles and processes |

**NIST Special Publications** (US, free, widely reused):

| SP | Topic |
| :--- | :--- |
| 800-34 | contingency planning (backup, DR, continuity) |
| **800-37** | **Risk Management Framework (RMF)**: Prepare → Categorize → Select → Implement → Assess → Authorize → Monitor |
| 800-50 | security and privacy awareness and training programmes |
| **800-53** | catalogue of security and privacy controls (Rev. 5) — basis of FISMA and FedRAMP |
| 800-63 / **63B** | digital identity; 63B = authentication: assurance levels AAL1–3, long passphrases, no forced rotation or composition rules, block breached passwords |
| 800-83 | malware incident prevention and handling |
| 800-86 | integrating forensic techniques into incident response |
| 800-92 | security log management |
| 800-101 r1 | mobile device forensics |
| 800-115 | technical guide to security testing (pentest methodology) |
| 800-124 | managing mobile devices in the enterprise |
| 800-144 | security and privacy in public cloud computing |

Frameworks that tie these together: [NIST CSF 2.0](../grc/nist-csf-2.md), [CIS Controls / Benchmarks](../grc/cis-benchmarks.md),
SOC 2, PCI DSS ([cross-walk](../grc/regulatory-frameworks.md)).

## How it works

Pick by need: **certify** an ISMS → ISO 27001; **select controls** → 800-53 or 27002; **talk to executives** → CSF 2.0;
**harden hosts** → CIS Benchmarks; **US federal** → RMF + 800-53 (FISMA, FedRAMP). Map once, reuse evidence across all of
them.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | not applicable — 800-53 controls are mapped to ATT&CK by the Center for Threat-Informed Defense |
| **What it leads to** | consistent controls, audit-ready evidence, contract and regulatory eligibility |
| **Where defenders meet it** | customer questionnaires, audits, "which control does this alert support?" |

## Do it

Tag your own evidence with the control it supports, so one collection serves several audits:

```powershell
[pscustomobject]@{
    Control     = 'NIST 800-53 AC-2 / ISO 27001 A.5.18'
    Evidence    = 'Enabled accounts inactive > 90 days'
    Count       = (Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -UsersOnly | Where-Object -Property Enabled -EQ -Value $true).Count
    CollectedAt = (Get-Date).ToUniversalTime().ToString('o')
}
```

## See it

| Source | What you see |
| :--- | :--- |
| Statement of Applicability (ISO 27001) | which Annex A controls apply and why |
| System Security Plan (RMF / FedRAMP) | 800-53 controls and how each is implemented |

## Detect it

- Frameworks: [NIST CSF 2.0](../grc/nist-csf-2.md) · [CIS benchmarks](../grc/cis-benchmarks.md) · [Regulatory cross-walk](../grc/regulatory-frameworks.md)
- Assurance tasks: [Assurance](../../tasks/assurance/index.md)
- No detection rule applies.

## Related concepts

- [Risk Management and Governance](risk-management-governance.md) · [Cyber Law](cyber-law.md) · [Privacy Laws](privacy-laws.md)

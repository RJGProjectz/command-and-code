---
title: Risk Management, Policies and Compliance Audits
type: concept
platforms: [Windows, Linux]
languages: [PowerShell]
tasks: [Assurance, Compliance]
category: Governance and Law
security_domain: Governance
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, risk, governance, policy, audit]
aliases: [Risk Management, Risk Analysis and Prioritization, How to Conduct a Risk Assessment, Security Policies and Governance, How to Develop Security Policies and Procedures, How to Perform a Compliance Audit]
difficulty: basic
verified: false
---

# Risk Management, Policies and Compliance Audits
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** risk management decides which threats to fix first and which to accept; governance writes those decisions down as policy and audits prove they are followed.

## What it is

**Risk = likelihood × impact.** A risk assessment estimates both for each threat to each important asset.

| Approach | How | Example |
| :--- | :--- | :--- |
| Qualitative | High / Medium / Low matrix | "ransomware on file servers: likely × severe = High" |
| Quantitative | money: ALE = SLE × ARO | single loss $200k × 0.3 per year = $60k annual expected loss |

**Risk treatment:** *mitigate* (add controls), *transfer* (insurance, contracts), *avoid* (stop the activity), *accept*
(documented sign-off by the risk owner). Everything goes in a **risk register** with an owner and review date.
Standards: NIST SP 800-30 (risk assessment), ISO/IEC 27005, NIST RMF ([SP 800-37](security-standards-map.md)).

**Policy hierarchy:**

| Document | Says | Example |
| :--- | :--- | :--- |
| Policy | what and why — approved by leadership | "All remote access requires MFA" |
| Standard | measurable requirement | "FIDO2 or number-matching push" |
| Procedure | step-by-step how | "Enrol a FIDO2 key" |
| Guideline | recommended, optional | "Prefer platform passkeys" |

## How it works

**Risk assessment:** list assets → threats and vulnerabilities → existing controls → likelihood and impact → rank →
treatment plan. For vulnerabilities, prioritise with exploitability (CISA KEV, EPSS) and exposure, not CVSS alone.

**Compliance audit:** define scope and criteria → map controls to requirements → collect evidence (configs, logs,
tickets) → test samples → report findings with severity → track remediation to closure.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | not applicable — governance |
| **What it leads to** | budget spent on the risks that matter; defensible decisions after an incident |
| **Where defenders meet it** | risk acceptances for unpatchable systems, policy exceptions, audit findings |

## Do it

```powershell
# Minimal risk register entry, scored and timestamped
$risk = [pscustomobject]@{
    Id = 'R-014'; Asset = 'File servers'; Threat = 'Ransomware'
    Likelihood = 4; Impact = 5; Owner = 'Head of IT'; Treatment = 'Mitigate: immutable backups, EDR, MFA on admin'
    Reviewed = (Get-Date).ToUniversalTime().ToString('o')
}
$risk | Add-Member -NotePropertyName Score -NotePropertyValue ($risk.Likelihood * $risk.Impact) -PassThru
```

## See it

| Source | What you see |
| :--- | :--- |
| Risk register | top risks, owners, overdue reviews |
| Policy exception log | who accepted what risk, until when |
| Audit report | findings mapped to controls and due dates |

## Detect it

- Frameworks: [Security standards map](security-standards-map.md) · [Regulatory cross-walk](../grc/regulatory-frameworks.md)
- Assurance tasks: [Assurance](../../tasks/assurance/index.md)
- No detection rule applies.

## Related concepts

- [Security Standards Map](security-standards-map.md) · [Defense in Depth](defense-in-depth.md) · [CIA Triad](cia-triad.md)

---
title: Cyber Law (CFAA, ECPA, FISA, PATRIOT Act, SOX, FISMA, FedRAMP)
type: concept
platforms: [Windows, Azure]
languages: [PowerShell]
tasks: [Compliance, Assurance, Incident Response]
category: Governance and Law
security_domain: Governance
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, law, cfaa, fisma, fedramp, compliance]
aliases: [Computer Fraud and Abuse Act (CFAA), Electronic Communications Privacy Act (ECPA), Foreign Intelligence Surveillance Act (FISA), USA PATRIOT Act, Cybersecurity Information Sharing Act (CISA), Sarbanes-Oxley Act (SOX), Federal Information Security Management Act (FISMA), FedRAMP, Whistleblowers, Digital Forensics Legal and Ethical Considerations]
difficulty: intermediate
verified: false
---

# Cyber Law (CFAA, ECPA, FISA, PATRIOT Act, SOX, FISMA, FedRAMP)
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** these US laws define what counts as computer crime, when communications may be monitored, and what security controls public companies and federal systems must prove.

## What it is

| Law | Year | What it does |
| :--- | :--- | :--- |
| **CFAA** (18 U.S.C. §1030) | 1986 | federal crime to access a computer *without authorisation* or *exceed authorised access*; *Van Buren* (2021) narrowed the second; DOJ policy (2022) not to charge good-faith security research |
| **ECPA** | 1986 | Wiretap Act (real-time interception), Stored Communications Act (email/cloud data), Pen Register Act (metadata) — governs employer monitoring and law-enforcement requests |
| **FISA** | 1978 | foreign-intelligence surveillance with a special court; Section 702 (2008) covers non-US persons abroad and needs periodic reauthorisation |
| **USA PATRIOT Act** | 2001 | expanded surveillance and information-sharing powers; some sections have since expired |
| **CISA** (Cybersecurity Information Sharing Act) | 2015 | liability protection for sharing cyber-threat indicators with the government and peers — check its current status, it has sunset dates |
| **SOX** | 2002 | public companies attest to internal controls over financial reporting (§404) → IT general controls: access, change management, operations |
| **FISMA** | 2002 / 2014 | federal agencies run risk-based security programmes using NIST RMF ([SP 800-37 / 800-53](security-standards-map.md)) |
| **FedRAMP** | 2011 | standard authorisation for cloud services used by federal agencies, built on SP 800-53 baselines (Low / Moderate / High) |

**Whistleblowers** reporting fraud or security failures have protection under SOX (§806), Dodd-Frank and other laws —
handle such reports through legal, not as an insider-threat case.

## How it works

For defenders the practical rules are:

- **Authorisation is everything:** testing without written permission can be a CFAA offence — see
  [ethical hacking](ethical-hacking.md).
- **Monitoring needs a basis:** banner and policy consent, monitoring only company systems, and legal review before
  reading content.
- **Evidence must hold up:** chain of custody, hashes, documented methods (ISO/IEC 27037 — see
  [digital forensics](security-standards-map.md)); preserve on legal hold.
- **Report in time:** state breach laws, SEC 8-K cyber disclosure (material incidents within four business days),
  sector rules.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | not applicable — legal framework |
| **What it leads to** | criminal liability for unauthorised testing, inadmissible evidence, audit failures, disclosure deadlines |
| **Where defenders meet it** | rules of engagement, IR legal hold, SOX ITGC audits, FedRAMP/FISMA assessments |

## Do it

SOX-style IT general control evidence (who changed what, who has access):

```powershell
# Members of privileged groups as audit evidence, with a timestamp
Get-ADGroupMember -Identity 'Domain Admins' -Recursive |
    Select-Object -Property SamAccountName, @{Name = 'CollectedUtc'; Expression = { (Get-Date).ToUniversalTime().ToString('o') } } |
    Export-Csv -Path .\evidence_domain_admins.csv -NoTypeInformation
# Logon banner configured? (consent to monitoring)
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LegalNoticeCaption, LegalNoticeText
```

## See it

| Source | What you see |
| :--- | :--- |
| Audit evidence packages | access reviews, change tickets, backup tests mapped to controls |
| Legal hold notices | which mailboxes/devices must not be wiped during an incident |
| Engagement letters | scope, dates and signatures that make a pentest legal |

## Detect it

- Frameworks: [Regulatory compliance cross-walk](../grc/regulatory-frameworks.md) · [Security standards map](security-standards-map.md)
- Forensics: [Windows disk artifacts](../../tasks/forensics/windows-disk-artifacts.md) — evidence handling
- No detection rule applies.

## Related concepts

- [Privacy Laws](privacy-laws.md) · [Ethical Hacking](ethical-hacking.md) · [Risk Management and Governance](risk-management-governance.md)

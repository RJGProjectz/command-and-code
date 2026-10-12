---
title: Privacy Laws and Data Protection (GDPR, CCPA, HIPAA)
type: concept
platforms: [Microsoft 365, Windows]
languages: [PowerShell, KQL]
tasks: [Compliance, Incident Response, Assurance]
category: Governance and Law
security_domain: Governance
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, privacy, gdpr, ccpa, hipaa, compliance]
aliases: [Privacy Laws and Regulations, General Data Protection Regulation (GDPR), California Consumer Privacy Act (CCPA), Consumer Privacy Rights, Health Insurance Portability and Accountability Act (HIPAA), How to Conduct a Data Privacy Assessment, How to Perform a Privacy Impact Assessment, Privacy-Enhancing Technologies, Cybersecurity Ethics and Privacy]
difficulty: basic
verified: false
---

# Privacy Laws and Data Protection (GDPR, CCPA, HIPAA)
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** privacy laws decide what personal data you may collect, how you must protect it, what rights people have over it, and how fast you must report a breach.

## What it is

| Law | Scope | What security teams must know |
| :--- | :--- | :--- |
| **GDPR** (EU, 2018) | anyone processing personal data of people in the EU | lawful basis, data minimisation, "appropriate technical and organisational measures" (Art. 32), **breach notice to the regulator within 72 hours** (Art. 33), DPIA for high-risk processing (Art. 35); fines up to €20 M or 4 % of global turnover |
| **CCPA / CPRA** (California, 2020/2023) | businesses above size thresholds handling Californians' data | rights to know, delete, correct, opt out of sale/sharing, limit use of sensitive data; "reasonable security" duty with a private right of action for breaches |
| **HIPAA** (US, 1996) | health providers, plans, clearing houses and their business associates | Security Rule (administrative, physical, technical safeguards for ePHI); Breach Notification Rule — individuals within 60 days, HHS and media for breaches of 500+ |
| **ECPA** (US, 1986) | interception and stored communications | limits on monitoring content — see [cyber law](cyber-law.md) |

**Consumer privacy rights** recur across laws: access, correction, deletion, portability, objection/opt-out, and not
being subject to purely automated decisions.

**Privacy-enhancing technologies (PETs)** reduce what can leak: encryption, pseudonymisation and tokenisation,
data masking, differential privacy, [homomorphic encryption and ZK proofs](zero-knowledge-homomorphic-blockchain.md),
federated learning.

## How it works

**Data privacy assessment / Privacy Impact Assessment (PIA, DPIA under GDPR):**

1. Map the data: what personal data, where it is stored, who can access it, where it flows (incl. vendors, other countries).
2. Check necessity and lawful basis; cut what is not needed.
3. Assess risks to individuals (not just to the company): breach, misuse, re-identification.
4. Choose controls — access control, encryption, retention limits, logging — and record residual risk.
5. Review when the processing changes.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1530](https://attack.mitre.org/techniques/T1530/) Data from Cloud Storage · [T1567](https://attack.mitre.org/techniques/T1567/) Exfiltration Over Web Service |
| **What it leads to** | regulatory fines, mandatory notification, lawsuits; a breach clock that starts when you *become aware* |
| **Where defenders meet it** | incident response (is personal data involved? which countries?), DLP alerts, data subject requests |

## Do it

Find where personal data lives before an incident forces you to:

```powershell
# Files on a share that look like they hold card numbers or US SSNs (sampling, not a full DLP scan)
Get-ChildItem -Path '\\fileserver\shares' -Recurse -Include *.csv, *.txt, *.xlsx -ErrorAction SilentlyContinue |
    Select-String -Pattern '\b\d{3}-\d{2}-\d{4}\b', '\b(?:\d[ -]?){13,16}\b' -List |
    Select-Object -Property Path -Unique
```

```kql
// Microsoft Purview DLP matches by policy and user (Defender XDR / Sentinel)
CloudAppEvents
| where ActionType has "DLP"
| summarize Matches = count() by AccountDisplayName, ActionType
| order by Matches desc
```

## See it

| Source | What you see |
| :--- | :--- |
| Purview DLP / sensitivity labels | where regulated data is stored and shared externally |
| Unified audit log | bulk downloads (`FileDownloaded`) of labelled files — scope for breach notification |
| Records of processing (GDPR Art. 30) | the data map assessors and regulators ask for first |

## Detect it

- Respond: [Account compromise](../../tasks/incident-response/account-compromise.md) — decide early whether notification clocks are running
- Investigate: [M365 audit log investigation](../../platforms/microsoft-365/audit-log-investigation.md)
- Frameworks: [Regulatory compliance cross-walk](../grc/regulatory-frameworks.md)

## Related concepts

- [Cyber Law](cyber-law.md) · [Security Standards Map](security-standards-map.md) · [Risk Management and Governance](risk-management-governance.md) · [CIA Triad](cia-triad.md)

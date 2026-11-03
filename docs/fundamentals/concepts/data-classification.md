---
title: Data Classification
type: concept
platforms: [Windows, Linux, Microsoft 365]
languages: [PowerShell, Bash]
tasks: [Governance, Compliance, Hardening]
category: Governance & Principles
security_domain: Governance
author: RJGProjectz
date_created: 2026-11-03
last_updated: 2026-11-03
tags: [concept, data-classification, dlp, data-governance, sensitivity-labels, compliance]
aliases: [data sensitivity, information classification, sensitivity labels, data handling policy]
difficulty: basic
verified: false
---

# Data Classification
> **Created**: 2026-11-03T00:00:00Z
> **Last Modified**: 2026-11-03T00:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

**In one line:** data classification assigns a sensitivity tier to every piece of information so the right controls — encryption, access restrictions, logging, and retention — follow the data wherever it goes.

## What it is

Security controls cannot scale if every document, database record, and email is treated identically. Classification solves this by grouping data into tiers with defined handling requirements. When a dataset has a label, the security team knows immediately which controls apply, which regulations cover it, and what a breach would cost.

Most organisations use a four-tier model:

| Tier | Typical label | Examples | Consequence of breach |
| :--- | :--- | :--- | :--- |
| 1 | **Public** | Marketing content, published documentation | Negligible |
| 2 | **Internal** | Operational procedures, org charts, internal pricing | Reputational |
| 3 | **Confidential** | Customer PII, contracts, financial forecasts | Regulatory / legal |
| 4 | **Restricted / Secret** | Source code, M&A plans, credentials, health records | Severe / existential |

Some regulated industries add a fifth tier (Top Secret in government; PHI in healthcare) or collapse tiers 1 and 2 into a single "General" category. The exact labels matter less than consistency: every employee should be able to identify the tier of what they are handling and know the rules that apply.

## How it works

```text
Data created / collected
       │
       ▼
  Label applied ──► auto-classify via DLP rules, or owner assigns manually
       │
       ▼
  Controls enforced by the label
       ├── Encryption at rest required?   (Confidential and above)
       ├── Encryption in transit required? (Internal and above)
       ├── Who can access?               (RBAC / need-to-know)
       ├── Can it leave the org?          (DLP block or alert)
       ├── Where can it be stored?        (approved storage only)
       └── How long is it retained?       (schedule by regulation)
```

**Labelling mechanisms:**

- **Manual** — the author or data owner selects a label when creating or sharing. Training-dependent; inconsistent at scale.
- **Automatic / recommended** — DLP engines scan content for patterns (SSNs, card numbers, passport formats, defined keywords) and apply or recommend a label.
- **Mandatory** — applications and storage systems refuse to save unlabelled content above a defined tier.

In Microsoft 365, sensitivity labels drive both classification and enforcement: a "Confidential" label can automatically apply encryption to the file, restrict who can open it, add a visual watermark, and prevent copying to USB or personal cloud storage. The label travels with the document even when it is emailed externally.

**Data inventory and discovery** must precede effective classification. You cannot classify what you do not know you have. Common discovery tools include:

- Microsoft Purview (formerly Azure Purview / Microsoft Information Protection) — scans M365, SharePoint, Exchange, Azure SQL, and on-premises file shares.
- AWS Macie — classifies S3 objects using ML.
- Open-source tools: `clamscan` (for known patterns), `bulk_extractor` (extracts email addresses, credit card numbers, PII from file systems or raw disk images).

**Handling rules** vary by tier but typically include:

| Control | Internal | Confidential | Restricted |
| :--- | :---: | :---: | :---: |
| Encryption at rest | Optional | Required | Required |
| Encryption in transit | Recommended | Required | Required |
| Need-to-know access | Recommended | Required | Required + logged |
| Removable media | Allowed | Prohibited / encrypted | Prohibited |
| Third-party sharing | With NDA | Security review + DPA | Prohibited or approval board |
| Retention period | Per policy | Per regulation | Per regulation |

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1530](https://attack.mitre.org/techniques/T1530/) — Data from Cloud Storage · [T1213](https://attack.mitre.org/techniques/T1213/) — Data from Information Repositories |
| **What it leads to** | without classification, DLP tools cannot distinguish a public press release from a salary spreadsheet — both generate the same alert, and neither gets the right control |
| **Where defenders meet it** | compliance audits (GDPR Art. 30 requires record of processing activities), DLP policy tuning, breach impact assessment |

## Do it

Scan a local directory for files containing common PII patterns (run on a machine you own):

```powershell
# Search for files containing SSN-like patterns (US Social Security Numbers)
Get-ChildItem -Path C:\DataReview -Recurse -Include *.txt,*.csv,*.docx |
    Select-String -Pattern '\b\d{3}-\d{2}-\d{4}\b' |
    Select-Object -Property Path, LineNumber, Line |
    Export-Csv -Path C:\Temp\ssn_hits.csv -NoTypeInformation
```

```bash
# Extract email addresses from a directory (Linux)
bulk_extractor -e email -o /tmp/be_out /path/to/datadir
cat /tmp/be_out/email.txt | sort -u | head -20
```

> [!CAUTION]
> **SECURITY WARNING:** Run data discovery tools only on storage you own or are authorised to assess. Discovery output may itself contain sensitive data — protect it accordingly and delete when no longer needed.

## See it

| Source | What you see |
| :--- | :--- |
| Microsoft Purview / DLP reports | Volume of sensitive data discovered by type and location |
| DLP policy match logs | Files copied to USB or emailed externally that matched a confidential label |
| Cloud storage audit logs | Unclassified or public S3/Azure Blob objects that contain PII patterns |

## Detect it

- Governance: [Risk Management, Policies and Compliance Audits](risk-management-governance.md)
- Governance: [Privacy Laws and Data Protection (GDPR, CCPA, HIPAA)](privacy-laws.md)
- Cloud: [Shared Responsibility Model](shared-responsibility-model.md)

## Related concepts

- [Risk Management, Policies and Compliance Audits](risk-management-governance.md)
- [Privacy Laws and Data Protection](privacy-laws.md)
- [Shared Responsibility Model](shared-responsibility-model.md)

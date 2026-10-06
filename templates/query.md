---
title: Hunt or Detect the Behaviour          # e.g. "KQL Encoded PowerShell"
platforms: [Microsoft Defender]              # data source platform
languages: [KQL]                             # KQL | SPL | S1QL | Sigma
tasks: [Threat Hunting, Detection Engineering]
category: Process Execution
security_domain: Endpoint                    # Identity | Endpoint | Network | Cloud | Application | Operations | Governance | Intelligence
author: RJGProjectz
date_created: 2026-10-06
last_updated: 2026-10-06
tags: [tag-one, tag-two]
aliases: [how people would search for this]
difficulty: intermediate
verified: false
# last_verified: 2026-10-06
---

# Hunt or Detect the Behaviour
> **Created**: 2026-10-06T02:45:00Z
> **Last Modified**: 2026-10-06T02:45:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> This query may impact SIEM/EDR performance. Before running:
> 1. Restrict the time window to a minimal test range (e.g. `1h`).
> 2. Validate field names against your environment schema.
> 3. Avoid unbounded searches in production consoles.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    State the data source, table/index/sourcetype and version assumptions. Remove when verified.

## Query

```kql
TableName
| where Timestamp > ago(7d)
| where Column has "value"
| project Timestamp, DeviceName, Column
```

**Data source / requirements:** table, index, sourcetype, audit policy or sensor feature required.

**Explanation:** what each filter does and why.

**Expected output:** what a true positive looks like.

**False positives / tuning:** known benign causes and how to exclude them.

**MITRE ATT&CK:** [T0000](https://attack.mitre.org/techniques/T0000/) — only if it genuinely applies.

## Equivalents

- SPL: link
- S1QL: link
- Sigma: link

## Related

- [Investigation workflow](../../tasks/investigation/page.md)
- [Endpoint command](../../platforms/windows/page.md)

## External Resources & White Papers

- [Table schema documentation](https://learn.microsoft.com/...)

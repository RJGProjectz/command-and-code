---
title: Hunt or Detect the Behaviour          # e.g. "KQL Encoded PowerShell"
platforms: [Microsoft Defender]              # data source platform
languages: [KQL]                             # KQL | SPL | S1QL | Sigma
tasks: [Threat Hunting, Detection Engineering]
category: Process Execution
tags: [tag-one, tag-two]
aliases: [how people would search for this]
difficulty: intermediate
verified: false
# last_verified: 2026-10-05
---

# Hunt or Detect the Behaviour

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

## Sources

- [Table schema documentation](https://learn.microsoft.com/...)

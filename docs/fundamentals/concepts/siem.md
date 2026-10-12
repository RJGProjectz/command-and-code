---
title: Security Information and Event Management (SIEM)
type: concept
platforms: [Splunk, Microsoft Defender, Azure]
languages: [SPL, KQL]
tasks: [Detection Engineering, Investigation, Threat Hunting]
category: Security Operations
security_domain: Operations
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, siem, logging, soc]
aliases: [Security Information and Event Management (SIEM), How to Implement a SIEM System, How to Perform Log Analysis for Intrusions, log analysis, Microsoft Sentinel]
difficulty: intermediate
verified: false
---

# Security Information and Event Management (SIEM)
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** a SIEM collects logs from everywhere, normalises them, and runs detections and searches across all of them in one place.

## What it is

A single host log shows one piece of an attack; the SIEM joins the pieces: the phishing click (mail), the sign-in
(identity), the new process (endpoint), the outbound connection (firewall). Splunk, Microsoft Sentinel and Elastic are
common examples. A SIEM is only as good as what you send it and the rules you maintain.

## How it works

1. **Collect** — agents and forwarders ship Windows events, syslog, cloud audit logs, EDR telemetry.
2. **Normalise** — map fields to a common model (CIM in Splunk, ASIM in Sentinel) so one query works across vendors.
3. **Detect** — scheduled correlation rules raise alerts; analysts hunt with ad-hoc queries.
4. **Respond** — alerts become incidents; playbooks (SOAR) automate enrichment and containment.

Plan in this order: use cases first, then the log sources they need, then retention and cost.

## Why it matters

| | |
| :--- | :--- |
| **Framework** | NIST CSF DE.CM / DE.AE · CIS Control 8 (audit log management) · NIST SP 800-92 (log management) |
| **What it leads to** | cross-source detection, investigation timelines, evidence for audits |
| **Where defenders meet it** | daily — it is the SOC's main console |

## Do it

```bash
cc find "splunk" ; cc find "log forwarding"
```

```spl
index=wineventlog EventCode=4625 earliest=-24h
| stats count by Account_Name, src_ip | where count > 20
```

```kql
SigninLogs
| where TimeGenerated > ago(1d) and ResultType != 0
| summarize Failures = count() by UserPrincipalName, IPAddress
| where Failures > 20
```

## See it

| Source | What you see |
| :--- | :--- |
| Ingestion dashboards | log sources that went silent (a detection gap) |
| Correlation alerts | multi-source incidents with an entity timeline |

## Detect it

- Build: [Centralised log forwarding (WEF / rsyslog)](../../tasks/administration/centralized-log-forwarding-wef-rsyslog.md), [Windows advanced audit policy](../../tasks/hardening/windows-cis-advanced-audit-policy.md)
- Search: [Splunk threat hunting](../../tasks/threat-hunting/splunk-threat-hunting.md), [Investigate a user in Splunk](../../tasks/investigation/investigate-user-splunk.md)
- Rules: [SPL brute force](../../detection/spl/brute-force.md), [KQL logon & identity](../../detection/kql/logon-identity.md)

## Related concepts

- [IDS/IPS](ids-ips.md) · [Defense in Depth](defense-in-depth.md)

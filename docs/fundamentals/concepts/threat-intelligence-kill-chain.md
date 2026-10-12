---
title: Threat Intelligence and the Cyber Kill Chain
type: concept
platforms: [Windows, Microsoft Defender]
languages: [KQL, PowerShell]
tasks: [Threat Intelligence, Threat Hunting, Detection Engineering]
category: Threat Intelligence
security_domain: Intelligence
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, threat-intel, kill-chain, attack-lifecycle]
aliases: [Introduction to Threat Intelligence, Cyber-attack Chain, Cyber Kill Chain]
difficulty: basic
verified: false
---

# Threat Intelligence and the Cyber Kill Chain
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** threat intelligence turns information about adversaries into decisions, and kill-chain models show where along an attack you can stop it.

## What it is

| Level | Audience | Example |
| :--- | :--- | :--- |
| Strategic | leadership | "ransomware groups target our sector through VPN flaws" |
| Operational | IR / hunt leads | a campaign's timing, targets and infrastructure |
| Tactical | SOC, detection engineers | TTPs mapped to ATT&CK |
| Technical | tools | IOCs: hashes, IPs, domains |

**Intelligence lifecycle:** direction (what do we need to know?) → collection → processing → analysis → dissemination →
feedback. The **Pyramid of Pain** reminds you that hashes and IPs are trivial for attackers to change; TTPs are not.

**Lockheed Martin Cyber Kill Chain:**

| Stage | Defender opportunity |
| :--- | :--- |
| 1. Reconnaissance | limit exposure ([OSINT](osint.md)), watch scanning |
| 2. Weaponisation | (attacker side) — intel on tooling |
| 3. Delivery | mail and web filtering ([social engineering](social-engineering.md)) |
| 4. Exploitation | patching ([vulnerability management](vulnerability-management.md)), exploit protection |
| 5. Installation | EDR, application control |
| 6. Command & control | egress filtering, DNS and proxy analytics |
| 7. Actions on objectives | DLP, segmentation, backups |

ATT&CK, the Unified Kill Chain and the Diamond Model (adversary – capability – infrastructure – victim) add detail
inside these stages.

## How it works

Use intel to: prioritise patching (exploited CVEs), write detections for TTPs relevant to your sector, enrich alerts with
IOC reputation, and brief leadership. Share back through ISACs and STIX/TAXII.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | the shared language for tactical intel — [ATT&CK matrix](../../references/mitre-attack-matrix.md) |
| **What it leads to** | detections that match real threats, faster triage, informed risk decisions |
| **Where defenders meet it** | IOC feeds, vendor reports, ISAC alerts, threat-actor profiles |

## Do it

```kql
// Match your telemetry against TI indicators in Sentinel (network IOCs)
ThreatIntelligenceIndicator
| where Active == true and isnotempty(NetworkIP)
| join kind=inner (DeviceNetworkEvents | where TimeGenerated > ago(1d)) on $left.NetworkIP == $right.RemoteIP
| project TimeGenerated, DeviceName, RemoteIP, Description, ThreatType, ConfidenceScore
```

## See it

| Source | What you see |
| :--- | :--- |
| TIP / Sentinel TI | indicators with confidence, source, expiry |
| Vendor and government advisories | TTPs and IOCs for current campaigns |

## Detect it

- Intel tasks: [IOC lifecycle and scoring](../../tasks/threat-intelligence/ioc-lifecycle-scoring.md) · [STIX/TAXII pipeline](../../tasks/threat-intelligence/stix-taxii-pipeline.md) · [Adversary emulation profiling](../../tasks/threat-intelligence/adversary-emulation-profiling.md)
- Reference: [Threat actor profiles](../../references/threat-actor-profiles.md)
- Automation: [Automated IOC enrichment](../../tasks/automation/automated-ioc-enrichment.md)

## Related concepts

- [OSINT](osint.md) · [Anonymity and the Dark Web](anonymity-dark-web.md) · [Penetration Testing](penetration-testing.md) · [SIEM](siem.md)

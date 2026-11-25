---
title: MITRE ATT&CK Framework
type: concept
platforms: [Windows, Linux, Azure, AWS]
languages: [PowerShell, KQL, Python]
tasks: [Threat Hunting, Detection Engineering, Threat Intelligence, Incident Response]
category: Frameworks
security_domain: Operations
author: RJGProjectz
date_created: 2026-11-24
last_updated: 2026-11-24
tags: [concept, mitre, attck, threat-intelligence, tactics, techniques, procedures, TTP, framework]
aliases: [MITRE ATT&CK, ATT&CK matrix, ATT&CK framework, TTPs, tactics techniques procedures, adversary behavior framework]
difficulty: basic
verified: false
---

# MITRE ATT&CK Framework
> **Created**: 2026-11-24T00:00:00Z
> **Last Modified**: 2026-11-24T00:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

**In one line:** a publicly maintained, structured knowledge base of real-world adversary tactics and techniques, used by defenders to map alerts to attacker goals and find detection gaps.

## What it is

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a freely available knowledge base maintained by MITRE Corporation. It documents how real threat actors actually operate: not the theoretical attack steps in a textbook, but observed behaviour drawn from incident reports, malware analysis, and threat intelligence collected over many years. Each entry describes a specific action an adversary takes, the platform it applies to, the prerequisites it requires, and the data sources a defender can use to detect it.

The framework organises adversary behaviour into a matrix where columns are **tactics** — the attacker's goals at each stage of an intrusion — and rows within each column are **techniques** — the specific methods used to achieve those goals. Many techniques have **sub-techniques** that capture distinct variants (for example, T1055 Process Injection has sub-techniques for DLL injection, portable-executable injection, and process hollowing, among others).

ATT&CK is not a kill chain or a linear model: an attacker may jump between tactics, skip some entirely, or return to earlier ones as the intrusion evolves. Its value is as a shared vocabulary — when an alert fires, security engineers can say "this looks like T1059.001 (PowerShell execution)" rather than describing the raw log event, and immediately connect it to known threat groups, expected next steps, and published mitigations.

## How it works

The ATT&CK for Enterprise matrix covers fourteen tactics in approximate attack-lifecycle order:

| # | Tactic | What the attacker is doing |
| :-- | :-- | :-- |
| 1 | Reconnaissance | Gathering information before the attack |
| 2 | Resource Development | Acquiring infrastructure, accounts, and tooling |
| 3 | Initial Access | Getting a foothold in the target environment |
| 4 | Execution | Running attacker-controlled code |
| 5 | Persistence | Maintaining access across reboots and logouts |
| 6 | Privilege Escalation | Gaining higher-privilege access |
| 7 | Defense Evasion | Avoiding or disabling detection controls |
| 8 | Credential Access | Stealing or forging authentication material |
| 9 | Discovery | Learning the shape and contents of the environment |
| 10 | Lateral Movement | Pivoting to other hosts or accounts |
| 11 | Collection | Gathering data intended for exfiltration |
| 12 | Command and Control | Maintaining a channel back to attacker infrastructure |
| 13 | Exfiltration | Moving data out of the environment |
| 14 | Impact | Destroying, encrypting, or degrading systems or data |

Separate ATT&CK matrices exist for Mobile (Android and iOS), ICS (industrial control systems), and Cloud, each with tactics and techniques specific to those environments.

## Why it matters

| | |
| :--- | :--- |
| **Framework reference** | [MITRE ATT&CK for Enterprise](https://attack.mitre.org/matrices/enterprise/) |
| **What it enables** | Purple-team exercises map simulated attacks to ATT&CK IDs; detection engineers use it to find uncovered techniques; threat-intel analysts map adversary reports to TTPs; executives use coverage heat maps to understand detection posture |
| **Where defenders meet it** | SIEM alert enrichment, EDR tactic labels, threat intelligence reports ("APT29 uses T1021.001"), security assessments |

## Do it

```bash
cc find "mitre tactics"
cc view docs/fundamentals/concepts/threat-intelligence-kill-chain.md
cc view docs/tasks/threat-hunting/index.md
```

Map a suspicious command to an ATT&CK technique:

```powershell
# A discovery command observed on a host — maps to T1016 (System Network Configuration Discovery)
# and T1069.002 (Domain Groups)
ipconfig /all
net group "Domain Admins" /domain
net group "Domain Controllers" /domain
```

Use ATT&CK Navigator (browser-based) to build a coverage heat map:

```bash
# ATT&CK Navigator is a free browser tool at https://mitre-attack.github.io/attack-navigator/
# No installation required — open in a browser and load a JSON layer file
# Example: export a layer from your SIEM's detection library to see which techniques you detect
```

## See it

ATT&CK technique IDs appear in:

| Source | Where you see them |
| :--- | :--- |
| Microsoft Defender / Sentinel alerts | Alert title and tactic column in the incident view |
| SentinelOne / CrowdStrike alerts | Tactic and technique fields on each detection |
| Threat intelligence reports | "The actor leveraged T1059.001 for execution…" |
| SIGMA rules | `tags: attack.txxxx` field |
| CISA advisories | Tabular TTP listings in joint advisories |

## Detect it

Mapping detections to ATT&CK:

- Detection: [Detection Engineering](../../tasks/detection-engineering/index.md)
- Hunt: [Threat Hunting Workflows](../../tasks/threat-hunting/index.md)
- Intel: [Threat Intelligence Tasks](../../tasks/threat-intelligence/index.md)
- Kill chain context: [Threat Intelligence and the Cyber Kill Chain](threat-intelligence-kill-chain.md)

## Using ATT&CK in practice

**Incident response enrichment:** when analysing a suspicious event, search attack.mitre.org for the technique. The page lists known threat groups that use it, the data sources that detect it, and published mitigations — a faster research path than a general web search.

**Detection gap analysis:** export your SIEM's detection rules as an ATT&CK Navigator layer. Techniques with no coverage are detection gaps. Prioritise closing gaps that appear in threat-actor reports relevant to your industry.

**Purple-team planning:** defenders and red teamers agree on a subset of techniques to simulate, then compare the resulting alerts against expected ATT&CK IDs. Where alerts are missing or mislabelled, detection rules need work.

**Vendor evaluation:** ask security vendors to show their ATT&CK coverage map. Compare coverage, not just feature lists.

## Related concepts

- [Threat Intelligence and the Cyber Kill Chain](threat-intelligence-kill-chain.md)
- [Threat Modeling](threat-modeling.md)
- Purple Teaming
- [SIEM](siem.md)

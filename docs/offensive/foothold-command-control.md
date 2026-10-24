---
title: Foothold, Command-and-Control & Defense Evasion — Awareness, Detection and Hardening
type: workflow
platforms: [Windows, Linux]
tasks: [Assessment]
category: Workflow
security_domain: Endpoint
author: RJGProjectz
date_created: 2026-10-24
last_updated: 2026-10-24
tags: [foothold, command-and-control, c2, beaconing, persistence, scheduled-task, run-key, service-persistence, defense-evasion, amsi, lolbins, red-team, stage-3, awareness, blue-team-parity]
aliases: [stage 3, foothold, command and control, c2 channels, beaconing, persistence mechanisms, scheduled task persistence, run keys, service persistence, defense evasion, amsi bypass, living off the land, lolbins, post-exploitation awareness]
difficulty: intermediate
verified: false
---

# Foothold, Command-and-Control & Defense Evasion — Awareness, Detection and Hardening
> **Created**: 2026-10-24T00:00:00Z
> **Last Modified**: 2026-10-24T00:00:00Z
> **Author**: RJGProjectz

> [!WARNING]
> **Authorized testing only — this is an awareness and defence page, not an operations page.**
> This project is **enumeration/assessment-only**. It publishes **no** Command-and-Control
> frameworks, implants, persistence installers, or defence-evasion payloads. Stage 3 is documented so
> an authorized assessor understands *what an adversary does after landing* and, above all, so a
> defender can **detect and harden** against it. Reproduce any of this only inside a lab you own, under a
> signed engagement, and keep everything inside the agreed scope — see
> [Cyber Law](../fundamentals/concepts/cyber-law.md) and
> [Ethical Hacking & Ethics](../fundamentals/concepts/ethical-hacking.md).

!!! danger "VERIFY BEFORE PRODUCTION USE"
    This page is conceptual: it links detection and hardening procedures that live on other pages rather
    than carrying runnable commands. Confirm the linked procedures against your own build and vendor docs
    before relying on them. Remove this block when `verified: true`.

**Trigger:** an adversary (or an authorized red team) has gained initial access — Stage 2 is complete —
and now works to **stay in**, **control the host remotely**, and **avoid the defender's tooling**.

**Goal:** know the three activities that define Stage 3 — **persistence**, **command-and-control**, and
**defense evasion** — and, for each, reach the Defensive page that **detects** it and the one that
**hardens** against it. Because the activity is adversary-operational, the "know it" column is theory
and the real work for this project is the **Detect it / Harden it** columns.

<!-- Rules: awareness + defensive-pointer page. Every activity links to pages we already have
     (fundamentals/concepts for theory, tasks/threat-hunting + detection for Detect it,
     tasks/hardening for Harden it). No C2 / implant / persistence / evasion tooling or payloads. -->

## 1. Persistence mechanisms (scheduled tasks, services, run keys)

**What happens:** having landed, the adversary establishes a way to survive reboots and logoffs —
a scheduled task, a new or hijacked Windows service, a `Run`/`RunOnce` registry key, a WMI event
subscription, or a Linux `cron`/`systemd` unit. The technique is low-skill and extremely common, which
is exactly why it is one of the richest detection opportunities a defender has.

- **Know it:** [Malware Types & Analysis](../fundamentals/concepts/malware-types-analysis.md) (persistence
  is how a RAT or implant earns its "persistent" label).
- **Detect it:** [Scheduled-Task Persistence Review](../tasks/threat-hunting/scheduled-task-persistence-review.md) ·
  [LOLBins Execution Hunting](../tasks/threat-hunting/lolbins-execution-hunting.md) (persistence usually
  executes *through* a trusted binary).
- **Harden it:** [AppLocker Deployment & Rollout](../tasks/hardening/applocker-deployment-rollout.md)
  (application control blocks the unsigned payload the autostart points at) ·
  [Windows CIS Attack-Surface Reduction](../tasks/hardening/windows-cis-attack-surface-reduction.md)
  (ASR rules + Credential Guard cut the common persistence and abuse paths).

## 2. Command-and-Control channels & beaconing

**What happens:** the foothold calls home to an operator-controlled server to receive tasking and return
output. Mature C2 hides in normal-looking traffic — HTTPS to a reputable-looking domain, DNS queries,
or a cloud/collaboration API — and **beacons** on an interval with jitter so the pattern is hard to spot.
This project does **not** ship C2 tooling; defenders meet the channel as anomalous egress and periodic,
low-and-slow callbacks.

- **Know it:** [Malware Types & Analysis](../fundamentals/concepts/malware-types-analysis.md) ·
  [Anonymity Networks & the Dark Web](../fundamentals/concepts/anonymity-dark-web.md) (how operators
  obscure the far end of the channel).
- **Detect it:** [LOLBins Execution Hunting](../tasks/threat-hunting/lolbins-execution-hunting.md) (the
  binary that beacons is often a signed system tool) ·
  [DNS Tunneling](../detection/spl/dns-tunneling.md) (a classic covert C2 and exfiltration carrier).
- **Harden it:** [Windows CIS Attack-Surface Reduction](../tasks/hardening/windows-cis-attack-surface-reduction.md)
  (ASR rules block the script/Office-spawned processes that launch beacons; egress control and proxy
  inspection constrain the channel).

## 3. Defense evasion (AMSI, logging tamper, living-off-the-land)

**What happens:** to keep the foothold and the C2 channel alive, the adversary blinds or bypasses
defences — attempting to disable the Antimalware Scan Interface (AMSI), clearing or stopping event
logs, unhooking EDR, or staying "living off the land" with signed built-in binaries (LOLBins) so nothing
new ever touches disk. Evasion is what turns a noisy intrusion into a quiet one.

- **Know it:** [Malware Types & Analysis](../fundamentals/concepts/malware-types-analysis.md)
  (obfuscation, packing and anti-analysis are the evasion toolkit).
- **Detect it:** [AMSI Bypass](../detection/spl/amsi-bypass.md) (Splunk detection for the common
  in-memory AMSI-patching patterns) ·
  [LOLBins Execution Hunting](../tasks/threat-hunting/lolbins-execution-hunting.md) (catches the
  trusted-binary abuse that evasion relies on).
- **Harden it:** [AppLocker Deployment & Rollout](../tasks/hardening/applocker-deployment-rollout.md) ·
  [Windows CIS Attack-Surface Reduction](../tasks/hardening/windows-cis-attack-surface-reduction.md)
  (script-control, constrained language mode and ASR raise the cost of evasion).

## Defender's view — map the stage to a counterpart

| Activity | Know it (theory) | Detect it (Defensive) | Harden it (Defensive) |
| --- | --- | --- | --- |
| Persistence | Malware Types & Analysis | Scheduled-Task Persistence Review · LOLBins Hunting | AppLocker · Windows ASR |
| Command-and-Control | Malware Types · Anonymity & Dark Web | LOLBins Hunting · DNS Tunneling | Windows ASR (egress/proxy control) |
| Defense evasion | Malware Types & Analysis | AMSI Bypass · LOLBins Hunting | AppLocker · Windows ASR |

## Related

- [Offensive Overview — the five-stage lifecycle](index.md)
- [Stage 4 — Lateral Movement & Privilege Escalation](windows-host-enumeration-privesc.md) (where the
  adversary goes next with the foothold)
- [Actions on Objectives & Reporting](actions-on-objectives-reporting.md) (Stage 5)
- **Defensive counterparts:** [Threat Hunting](../tasks/threat-hunting/index.md) ·
  [Hardening](../tasks/hardening/index.md) · [Incident Response](../tasks/incident-response/index.md)

## External Resources & White Papers

- [MITRE ATT&CK — Persistence (TA0003)](https://attack.mitre.org/tactics/TA0003/)
- [MITRE ATT&CK — Command and Control (TA0011)](https://attack.mitre.org/tactics/TA0011/)
- [MITRE ATT&CK — Defense Evasion (TA0005)](https://attack.mitre.org/tactics/TA0005/)
- [Microsoft — Antimalware Scan Interface (AMSI)](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
- [Microsoft — Attack surface reduction rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)

---
title: Penetration Testing and Red Teaming (Methodology and Detection)
type: concept
platforms: [Windows, Linux, Microsoft Defender]
languages: [PowerShell, Bash, KQL]
tasks: [Assurance, Threat Hunting, Detection Engineering]
category: Offensive Security
security_domain: Operations
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, pentest, red-team, methodology, lab]
aliases: [Penetration Testing, Penetration Testing Frameworks, Penetration Testing Methodologies, Red Teaming, Post-Exploitation Techniques, Hacking Toolkit, Kali Linux, Metasploit, "How to Develop & Test Exploits", How to Set Up a Pentesting Lab, How to Set Up a Home Lab, How to Use OWASP Juice Shop, Cybersecurity Tools and Technologies, Open Source Security Tools]
difficulty: intermediate
verified: false
---

# Penetration Testing and Red Teaming (Methodology and Detection)
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** a penetration test is an authorised, scoped attack that proves which weaknesses are exploitable; a red team tests whether detection and response catch a realistic adversary.

## What it is

| Exercise | Question it answers | Typical length |
| :--- | :--- | :--- |
| Vulnerability scan | what known weaknesses exist? ([vulnerability management](vulnerability-management.md)) | hours |
| **Penetration test** | which of them can actually be exploited, and how far does it go? | 1–3 weeks |
| **Red team** | can an objective-driven, stealthy adversary reach a crown jewel without being caught? | weeks–months |
| Purple team | red and blue together, technique by technique, to tune detections | days |

**Methodologies:** PTES (pre-engagement → intelligence gathering → threat modelling → vulnerability analysis →
exploitation → post-exploitation → reporting), NIST SP 800-115, OSSTMM, OWASP WSTG for web apps, and MITRE ATT&CK-based
adversary emulation (TIBER-EU for financial red teaming).

**Toolkits:** Kali Linux bundles open-source testing tools; frameworks such as Metasploit, Sliver or Cobalt Strike
handle exploitation and **post-exploitation** (privilege escalation, credential access, lateral movement, persistence).
Defenders should know their artefacts — attackers use the same tools. Exploit development and testing belong only in
an isolated lab against systems you own. Always work under written [authorisation](ethical-hacking.md).

## How it works

**A home / pentest lab:**

1. An isolated virtual network (host-only or private switch) — never bridged to production.
2. Snapshots so every exercise starts clean.
3. Deliberately vulnerable targets: OWASP Juice Shop (web), DVWA, Metasploitable, an AD lab such as GOAD.
4. A defender side: EDR trial, Sysmon + a SIEM (Splunk Free, Elastic, Wazuh) — watch what each technique looks like.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | the whole matrix — engagements are mapped technique by technique; e.g. [T1059](https://attack.mitre.org/techniques/T1059/), [T1021](https://attack.mitre.org/techniques/T1021/), [T1003](https://attack.mitre.org/techniques/T1003/) |
| **What it leads to** | proven attack paths with fixes; for blue teams — tested detections |
| **Where defenders meet it** | engagement alerts (deconflict with the test team), findings reports, purple-team sessions |

## Do it

Run OWASP Juice Shop locally as a training target (lab only):

```bash
docker run --rm -p 127.0.0.1:3000:3000 bkimminich/juice-shop
```

```powershell
# Private (isolated) Hyper-V switch for the lab network
New-VMSwitch -Name 'PentestLab' -SwitchType Private -WhatIf
```

Hunt for common post-exploitation tooling behaviour in your own estate:

```kql
// Default Metasploit/Meterpreter listener ports and remote service creation from cmd/PowerShell
DeviceNetworkEvents
| where RemotePort in (4444, 4445, 8443) and InitiatingProcessFileName in~ ("powershell.exe", "rundll32.exe", "regsvr32.exe", "cmd.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort
```

## See it

| Source | What you see |
| :--- | :--- |
| Security event 7045 / Sysmon 1 | random-named services, PsExec-style `ADMIN$` service binaries |
| Sysmon 17/18 | named pipes used by C2 frameworks |
| EDR | detections naming Meterpreter, Cobalt Strike Beacon, Sliver |

## Detect it

- Hunt: [Lateral movement](../../tasks/threat-hunting/lateral-movement.md) · [LOLBins execution](../../tasks/threat-hunting/lolbins-execution-hunting.md)
- Respond: [SMB lateral movement](../../tasks/incident-response/smb-lateral-movement.md)
- Intel: [Adversary emulation profiling](../../tasks/threat-intelligence/adversary-emulation-profiling.md)

## Related concepts

- [Ethical Hacking](ethical-hacking.md) · [Vulnerability Management](vulnerability-management.md) · [Port Scanning](port-scanning.md) · [Credential Dumping](credential-dumping.md)

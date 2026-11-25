---
title: Cyber Kill Chain
type: concept
platforms: [Windows, Linux]
languages: [KQL]
tasks: [Threat Hunting, Detection Engineering, Incident Response]
category: Threat Intelligence
security_domain: Intelligence
author: RJGProjectz
date_created: 2026-11-03
last_updated: 2026-11-03
tags: [concept, kill-chain, lockheed-martin, attack-lifecycle, threat-modeling]
aliases: [Lockheed Martin Kill Chain, attack lifecycle, intrusion kill chain, 7 stages of a cyberattack]
difficulty: basic
verified: false
---

# Cyber Kill Chain
> **Created**: 2026-11-03T00:00:00Z
> **Last Modified**: 2026-11-03T00:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

**In one line:** a seven-stage model that maps every intrusion from the attacker's first look at the target to their final objective, giving defenders a structured way to detect and interrupt attacks at each step.

## What it is

Lockheed Martin adapted the Kill Chain concept from military targeting doctrine and applied it to cyber intrusions. The insight is that every successful attack follows a predictable sequence: information gathering, building a weapon, getting it to the target, exploiting a weakness, installing persistence, issuing commands, and finally acting. Breaking the chain at any stage stops the attack.

Where MITRE ATT&CK catalogues hundreds of individual techniques, the Kill Chain describes the *shape* of an intrusion — why each phase matters strategically and where defenders should invest to disrupt the most attacks with the least effort.

## How it works

| Stage | Attacker goal | Defender opportunity |
| :--- | :--- | :--- |
| **1. Reconnaissance** | Learn about the target: IP ranges, email addresses, technology stack, employee names | Limit public exposure; detect scanning with network telemetry |
| **2. Weaponisation** | Build or adapt a payload: exploit code, macro-laced document, malicious link | Hunt for threat-actor tooling via intelligence feeds |
| **3. Delivery** | Get the weapon to the target: phishing email, drive-by download, USB drop | Email and web filtering; attachment sandboxing |
| **4. Exploitation** | Trigger code execution on the target: browser bug, macro, unpatched service | Patch management; exploit mitigations (ASLR, DEP, CFG) |
| **5. Installation** | Establish a foothold: drop an implant, create a scheduled task, add a registry key | EDR behavioural detection; application allowlisting |
| **6. Command & Control (C2)** | Open a channel back to attacker infrastructure for instructions and data | Egress filtering; DNS and proxy analytics; beacon detection |
| **7. Actions on Objectives** | Achieve the goal: encrypt files, exfiltrate data, move laterally, destroy records | Data loss prevention; segmentation; monitored backups |

**Reconnaisance** is the most information-rich stage for defenders. Passive reconnaissance (public WHOIS, LinkedIn, Shodan) leaves no trace; active reconnaissance (port scans, directory brute force) appears in firewall and IDS logs. Many organisations can detect active scanning but miss the passive intelligence gathering that preceded it.

**Weaponisation** is mostly invisible — it happens on attacker infrastructure. Intelligence from vendor reports and ISACs helps defenders anticipate which exploit or lure will arrive next.

**Delivery** is the highest-volume intervention point. Most intrusions still begin with phishing, making email filtering and user awareness the broadest single control. Drive-by downloads and supply-chain compromises bypass email entirely and require endpoint and web controls.

**Exploitation** is where patching pays off. Browser and document-format vulnerabilities are frequently targeted because endpoints process untrusted content constantly. Operating system mitigations (ASLR, DEP, Control Flow Guard, Safe Stack) raise the cost of exploitation even on unpatched software.

**Installation** is where behavioural detection shines. A new process writing a registry Run key, spawning `cmd.exe` from a Word macro, or dropping a DLL in a user-writable directory are all suspicious regardless of what the file is named or whether it matches a known signature.

**Command & Control** communication must traverse the network. Beaconing (periodic outbound calls to a C2 server) has a recognisable pattern — regular intervals, unusual destination, short request with a base-64 encoded payload. Encrypted channels over HTTPS are common; DNS tunnelling and domain fronting are advanced evasions.

**Actions on Objectives** vary by adversary. Ransomware actors follow lateral movement and data exfiltration with encryption. Nation-state actors may persist for months without triggering this stage at all.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | TA0043 Reconnaissance → TA0042 Resource Development → TA0001 Initial Access → TA0002 Execution → TA0003 Persistence → TA0011 C2 → TA0010 Exfiltration / TA0040 Impact |
| **What it leads to** | a detection strategy anchored to stages rather than individual techniques — harder for attackers to evade holistically |
| **Where defenders meet it** | incident reconstruction, detection engineering sprints, purple team exercise design |

## Do it

```bash
cc find "kill chain"
cc view docs/fundamentals/concepts/threat-intelligence-kill-chain.md
```

Quick check for common installation-stage persistence mechanisms on a Windows host you own:

```powershell
# Run keys (common persistence location)
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' |
    Select-Object -Property * -ExcludeProperty PS*

# Scheduled tasks not signed by Microsoft
Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '^\\Microsoft\\' } |
    Select-Object TaskName, TaskPath, State
```

> [!CAUTION]
> **SECURITY WARNING:** Run enumeration commands only on hosts you own or are authorised to assess.

## See it

| Kill chain stage | Log source | Signal |
| :--- | :--- | :--- |
| Reconnaissance | Firewall / IDS | Port scans, directory brute-force, version-string probing |
| Delivery | Email gateway | Attachment type, sender reputation, URL sandbox result |
| Exploitation | Sysmon Event 1 | Unusual parent-child process relationships |
| Installation | Sysmon Events 11, 12, 13 | New files in startup paths, registry Run key writes |
| C2 | DNS / proxy logs | High-frequency requests to newly registered domains; large DNS TXT responses |
| Actions | DLP / EDR | Bulk file reads or renames; LSASS access; large outbound transfers |

## Detect it

- Hunt: [Threat hunting index](../../tasks/threat-hunting/index.md)
- Detection: [KQL process events](../../detection/kql/process-events.md) · [KQL network events](../../detection/kql/network-events.md)
- Respond: [Incident response overview](../../tasks/incident-response/index.md)
- Intel: [Threat Intelligence and the Cyber Kill Chain](threat-intelligence-kill-chain.md)

## Related concepts

- [Threat Intelligence and the Cyber Kill Chain](threat-intelligence-kill-chain.md)
- [OSINT and Reconnaissance](osint.md)
- [Malware Types and Analysis](malware-types-analysis.md)
- [Lateral Movement](../../tasks/threat-hunting/lateral-movement.md)

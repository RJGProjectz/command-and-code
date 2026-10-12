---
title: Surveillance, Counter-Surveillance and Deception
type: concept
platforms: [Windows, Linux, Microsoft Defender]
languages: [PowerShell, KQL]
tasks: [Threat Hunting, Detection Engineering, Investigation]
category: Network Defense
security_domain: Operations
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, surveillance, deception, honeypot, honeytoken]
aliases: [Surveillance, Surveillance and Counter-Surveillance, Counter-surveillance, Decoy Operations]
difficulty: intermediate
verified: false
---

# Surveillance, Counter-Surveillance and Deception
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** surveillance collects information about people or systems; counter-surveillance detects it, and deception turns the tables by planting decoys that only an intruder would touch.

## What it is

**Surveillance** ranges from lawful mass and targeted collection ([FISA, ECPA](cyber-law.md)) to commercial tracking,
employer monitoring, and abusive stalkerware or mercenary [spyware](malware-types-analysis.md). **Counter-surveillance**
finds it: checking devices for stalkerware, reviewing account sessions and forwarding rules, unknown Bluetooth trackers,
physical bug sweeps (TSCM).

**Deception / decoy operations** are the defender's version: fake assets that have no business use, so any interaction is
a high-confidence alert.

| Decoy | Example | Alert on |
| :--- | :--- | :--- |
| Honeypot | a fake server or service (SSH, RDP, SMB) | any connection |
| Honeytoken / canary token | fake API key, AWS key, document with a beacon, DNS canary | any use |
| Honey account | a disabled-looking "svc_backup_admin" with an SPN | logon attempts, Kerberos ticket requests |
| Honey file / share | `passwords.xlsx` on a file share | file open |

## How it works

1. Place decoys where an attacker looks: AD, file shares, code repos, cloud credential files, password managers.
2. Make them believable but unused by anyone legitimate.
3. Route every touch to a high-priority alert — false-positive rates are close to zero.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [MITRE Engage](https://engage.mitre.org/) (defensive deception) · detects [T1558.003](https://attack.mitre.org/techniques/T1558/003/) Kerberoasting, [T1552](https://attack.mitre.org/techniques/T1552/) Unsecured Credentials |
| **What it leads to** | early warning of an intruder already inside; for individuals — finding stalkerware and trackers |
| **Where defenders meet it** | deception platform alerts, canary-token emails, users reporting "my phone is being watched" |

## Do it

```powershell
# A honey account: enabled, unused, strong random password; alert on ANY logon or ticket for it
New-ADUser -Name 'svc_backup_admin' -AccountPassword (ConvertTo-SecureString -String ([guid]::NewGuid().ToString() + 'aA1!') -AsPlainText -Force) -Enabled $true -WhatIf
# Check a mailbox for counter-surveillance red flags: forwarding and inbox rules
Get-InboxRule -Mailbox 'user@contoso.com' | Select-Object -Property Name, ForwardTo, RedirectTo, DeleteMessage
```

```kql
// Any authentication or Kerberos ticket request for the honey account
SecurityEvent
| where EventID in (4624, 4625, 4768, 4769) and TargetUserName =~ "svc_backup_admin"
| project TimeGenerated, EventID, Computer, IpAddress, TargetUserName
```

## See it

| Source | What you see |
| :--- | :--- |
| Security events 4624/4625/4769 | a decoy account used — near-certain malicious |
| Canary-token callbacks | the token's location, source IP, user agent |
| Mailbox audit / Entra | unknown forwarding rules or sessions — counter-surveillance finding |

## Detect it

- Hunt: [Kerberoasting and AS-REP roasting hunting](../../tasks/threat-hunting/kerberoasting-asreproast-hunting.md)
- Investigate: [Account compromise](../../tasks/incident-response/account-compromise.md)
- No dedicated honeytoken rule page yet (tracked in WP-31).

## Related concepts

- [Malware Types and Analysis](malware-types-analysis.md) · [Kerberoasting](kerberoasting.md) · [Anonymity and the Dark Web](anonymity-dark-web.md) · [IDS/IPS](ids-ips.md)

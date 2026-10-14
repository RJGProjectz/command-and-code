---
title: Detection Rule — Cryptomining (Resource Hijacking)
type: entry
platforms:
  - Windows
  - Linux
  - Microsoft Defender
languages:
  - Sigma
  - KQL
  - SPL
tasks:
  - Detection Engineering
  - Threat Hunting
verified: true
last_verified: 2026-10-13
difficulty: basic
tags:
  - cryptomining
  - xmrig
  - stratum
  - resource-hijacking
  - t1496
---

# Detection Rule — Cryptomining (Resource Hijacking)

Detects coin miners on endpoints and servers: miner command-line options, Stratum pool URLs, and connections to common
pool ports. XMRig (Monero) is by far the most common miner used by attackers, so most patterns target it.

!!! warning "Before you deploy"
    Option names were checked (2026-10-13) against the XMRig command-line documentation and the KQL columns against
    Microsoft Learn; not run against live miners. Pool ports are conventions, not rules; attackers often tunnel Stratum over 443 or use a proxy. Treat the network
    query as a hunt and the command-line rule as the alert. Sustained high CPU on a server with no workload change is
    the oldest and still useful signal.

- **ATT&CK**: [T1496 — Resource Hijacking](https://attack.mitre.org/techniques/T1496/)
- **Concept**: [Zero-Knowledge, Homomorphic & Blockchain](../../fundamentals/concepts/zero-knowledge-homomorphic-blockchain.md)

## Sigma rule

```yaml
title: Cryptominer Command Line
id: bafb0702-fdfe-439d-bd96-f708747bd08a
status: experimental
description: Detects command-line options and pool URLs used by XMRig and similar CPU/GPU miners.
references:
  - https://attack.mitre.org/techniques/T1496/
author: RJGProjectz
date: 2026-10-11
tags:
  - attack.impact
  - attack.t1496
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'stratum+tcp://'
      - 'stratum+ssl://'
      - 'stratum2+tcp://'
      - '--donate-level'
      - '--cpu-priority'
      - '--randomx-1gb-pages'
      - '--coin=monero'
      - '-a rx/0'
  selection_img:
    Image|endswith:
      - '\xmrig.exe'
      - '/xmrig'
  condition: 1 of selection*
falsepositives:
  - Sanctioned research or mining workloads (rare in business networks)
level: high
```

## KQL (Defender for Endpoint)

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("stratum+tcp://", "stratum+ssl://", "--donate-level", "--cpu-priority", "--randomx-1gb-pages")
    or FileName in~ ("xmrig.exe", "xmrig")
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, AccountName,
          InitiatingProcessFileName, SHA256
```

Hunt for pool connections:

```kql
DeviceNetworkEvents
| where RemotePort in (3333, 4444, 5555, 7777, 14433, 14444, 45700)
    or RemoteUrl has_any ("pool.", "xmr", "monero", "nanopool", "supportxmr", "moneroocean", "2miners")
| summarize Connections = count(), Urls = make_set(RemoteUrl, 10), Processes = make_set(InitiatingProcessFileName, 10)
    by DeviceName, RemoteIP, RemotePort
```

## SPL (Sysmon)

```spl
index=sysmon EventCode=1
    (CommandLine="*stratum+tcp://*" OR CommandLine="*stratum+ssl://*" OR CommandLine="*--donate-level*"
     OR CommandLine="*--cpu-priority*" OR Image="*\\xmrig.exe")
| table _time, host, User, Image, CommandLine, ParentImage, Hashes
```

## Triage

1. Find how it arrived: parent process, scheduled tasks, cron, services, and the initial access (exposed service, stolen cloud key).
2. Miners are often the visible payload of a broader compromise — check for persistence and credential theft before cleaning up.
3. In cloud, check for unexpected GPU/compute instances and the API key that created them.

## Test it

Atomic Red Team [T1496](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1496/T1496.md) has
*Windows - Simulate CPU Load with PowerShell* and *FreeBSD/macOS/Linux - Simulate CPU Load with Yes* for the CPU
signal. They start no miner, so test the command-line rule with a harmless process that carries the same strings:

```powershell
cmd.exe /c "echo stratum+tcp://pool.invalid:3333 --donate-level 1"
```

## Sources

- [XMRig — command line options](https://xmrig.com/docs/miner/command-line-options)
- [Microsoft Learn — DeviceProcessEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [MITRE ATT&CK T1496](https://attack.mitre.org/techniques/T1496/)

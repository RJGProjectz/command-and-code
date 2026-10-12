---
title: Digital Forensics and Incident Response (DFIR)
type: concept
platforms: [Windows, Linux]
languages: [PowerShell, Bash]
tasks: [Forensics, Incident Response, Investigation]
category: Forensics
security_domain: Operations
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, dfir, forensics, evidence, timeline]
aliases: [Digital Forensics and Incident Response, Digital Forensics Fundamentals, Forensic Reporting, Forensic Tools and Techniques, Data Recovery Techniques, Mobile Forensics]
difficulty: intermediate
verified: false
---

# Digital Forensics and Incident Response (DFIR)
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** forensics recovers what happened from evidence in a way others can verify; DFIR combines it with incident response so investigation and containment run together.

## What it is

**Principles:** preserve before you analyse, collect in **order of volatility** (RFC 3227: CPU/memory → network state →
running processes → disk → logs/backups), hash everything, keep a **chain of custody**, work on copies, document every
step so another examiner can reproduce it (ISO/IEC 27037, NIST SP 800-86).

| Area | Typical evidence | Tools |
| :--- | :--- | :--- |
| Memory | processes, injected code, network connections, keys | WinPMem, AVML, Volatility 3 |
| Disk / file system | MFT, prefetch, registry, event logs, browser history | FTK Imager, KAPE, Autopsy / Sleuth Kit, Eric Zimmerman tools |
| Timeline | everything on one time axis | Plaso (log2timeline), Timeline Explorer |
| Live response at scale | the same artefacts from many hosts | Velociraptor, EDR live response |
| **Mobile** | app data, messages, location, backups | logical / file-system / physical extractions; MVT; NIST SP 800-101 r1 |

**Data recovery:** deleted files stay on disk until overwritten — recover from file-system metadata or by carving
(PhotoRec, foremost); Volume Shadow Copies often hold earlier versions; SSD TRIM makes deleted-data recovery much less
likely.

## How it works

1. **Identify** scope and legal requirements (legal hold, privacy, who may see the data).
2. **Acquire** — memory first, then disk image or triage collection; hash on acquisition.
3. **Analyse** — timeline, persistence, execution, lateral movement, exfiltration; map to ATT&CK.
4. **Report** — executive summary, scope, method, findings with evidence references, timeline, IOCs, recommendations;
   facts separated from opinion.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1070](https://attack.mitre.org/techniques/T1070/) Indicator Removal · [T1485](https://attack.mitre.org/techniques/T1485/) Data Destruction · [T1490](https://attack.mitre.org/techniques/T1490/) Inhibit System Recovery |
| **What it leads to** | knowing root cause and scope — what to fix, whom to notify, whether evidence holds up legally |
| **Where defenders meet it** | every serious incident, insurance and legal investigations, HR cases |

## Do it

```powershell
# Shadow copies available for recovery / earlier file versions
vssadmin list shadows
# Hash an acquired image and record it for chain of custody
Get-FileHash -Path E:\evidence\host01.E01 -Algorithm SHA256 |
    Select-Object -Property Path, Hash, @{Name = 'TimeUtc'; Expression = { (Get-Date).ToUniversalTime().ToString('o') } }
```

```bash
# Linux live response: volatile data first, into a timestamped folder on external media
out=/mnt/usb/ir_$(hostname)_$(date -u +%Y%m%dT%H%M%SZ); mkdir -p "$out"
ss -tanp > "$out/sockets.txt"; ps auxww > "$out/processes.txt"; last -Faiw > "$out/logins.txt"
sha256sum "$out"/* > "$out/SHA256SUMS"
```

## See it

| Source | What you see |
| :--- | :--- |
| Prefetch, Amcache, ShimCache | evidence a program ran, and when |
| `$MFT` / `$UsnJrnl` | file creation, rename and deletion history |
| Event logs 1102 / 104 | audit log cleared — anti-forensics |

## Detect it

- Forensics: [Windows disk artifacts](../../tasks/forensics/windows-disk-artifacts.md) · [Memory acquisition & analysis](../../tasks/forensics/memory-acquisition-analysis.md) · [Linux live response](../../tasks/forensics/linux-live-response-forensics.md)
- Respond: [Endpoint triage](../../tasks/incident-response/endpoint-triage.md)
- Standards: [Security standards map](security-standards-map.md) — ISO/IEC 27037, 27043, NIST SP 800-86

## Related concepts

- [Malware Types and Analysis](malware-types-analysis.md) · [Hash Functions](hash-functions.md) · [Cyber Law](cyber-law.md) · [Mobile Security](mobile-security.md)

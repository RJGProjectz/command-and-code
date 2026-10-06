---
title: Splunk Detection — Suspicious SMB Administrative Share Access
type: entry
platforms:
  - Windows
  - Windows Server
  - Splunk
languages:
  - SPL
tasks:
  - Detection Engineering
  - Threat Hunting
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - splunk
  - smb
  - lateral-movement
  - admin-shares
  - 5140
---

# Splunk Detection — Suspicious SMB Administrative Share Access

Detects an internal endpoint establishing SMB connections to hidden administrative shares (`C$`, `ADMIN$`, `IPC$`) across multiple distinct internal systems within a short time threshold.

## Detection Logic

- **Log Source**: Windows Security `EventCode=5140` (A network share object was accessed)
- **ATT&CK Technique**: [T1021.002 - Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)

```spl
index=win_logs EventCode=5140 (ShareName="*\\C$" OR ShareName="*\\ADMIN$" OR ShareName="*\\IPC$")
| stats dc(ComputerName) as unique_targets values(ComputerName) as targets values(ShareName) as shares by src_ip, user
| where unique_targets > 5
| sort - unique_targets
```

## Detection Rationale

Adversaries, ransomware operators, and lateral movement frameworks (e.g. PsExec, Impacket) enumerate and write payloads to administrative shares across network segments. Standard user workstations should rarely connect to administrative shares on multiple peer workstations.

## False Positive Tuning

- **Authenticated Vulnerability Scanners**: Vulnerability management scanners (e.g. Qualys, Nessus, Rapid7) legitimately access admin shares. Exclude dedicated scanner subnets.
- **IT Deployment Systems**: SCCM, PDQ Deploy, or patch deployment distribution points.

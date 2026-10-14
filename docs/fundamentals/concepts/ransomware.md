---
title: Ransomware
type: concept
platforms: [Windows, Linux, VMware, SentinelOne]
languages: [PowerShell, S1QL]
tasks: [Incident Response, Threat Hunting, Hardening]
category: Malware
security_domain: Endpoint
author: RJGProjectz
date_created: 2026-10-11
last_updated: 2026-10-11
tags: [concept, ransomware, impact, extortion]
aliases: [crypto-ransomware, double extortion, data encrypted for impact]
difficulty: basic
verified: false
---

# Ransomware
> **Created**: 2026-10-11T22:00:00Z
> **Last Modified**: 2026-10-11T22:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

**In one line:** malware that encrypts your files and demands payment for the key — today usually the last step of a hands-on intrusion, after the data has already been stolen.

## What it is

Modern ransomware is rarely a single click. An operator gets in (phishing, exposed RDP or VPN, stolen credentials),
spends days gaining admin rights and copying data out, then removes backups and encrypts as many hosts as possible at
once — often hypervisors first. The ransom note threatens both the outage and publication of the stolen data
(*double extortion*).

## How it works

```text
initial access ─► credential theft ─► discovery & lateral movement ─► exfiltration
                                                                          │
     ransom note ◄── mass encryption ◄── delete shadow copies / backups ◄─┘
```

Most of the timeline happens **before** encryption — that is where detection pays off.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1486](https://attack.mitre.org/techniques/T1486/) — Data Encrypted for Impact · [T1490](https://attack.mitre.org/techniques/T1490/) — Inhibit System Recovery |
| **What it leads to** | business outage, data leak, legal and notification duties |
| **Where defenders meet it** | users report renamed files; EDR kills a process doing mass file writes; backup jobs fail |

## Do it

```bash
cc find ransomware
cc view docs/tasks/incident-response/ransomware-host-isolation.md
```

Check that recovery is still possible on a host you own:

```powershell
vssadmin list shadows
Get-CimInstance -ClassName Win32_ShadowCopy | Select-Object -Property InstallDate, VolumeName
# Is controlled folder access (Defender anti-ransomware) on? 1 = enabled
(Get-MpPreference).EnableControlledFolderAccess
```

## See it

| Source | What you see |
| :--- | :--- |
| Process telemetry | `vssadmin delete shadows /all`, `wmic shadowcopy delete`, `wbadmin delete catalog`, `bcdedit /set recoveryenabled no` |
| File telemetry | thousands of writes/renames per minute by one process; a new extension on every file; the same note in every folder |
| Security / System logs | event log clearing (1102, 104) shortly before impact; services for backup and databases stopped |
| Hypervisor | ESXi VMs powered off and `.vmdk` files renamed |

## Detect it

- Detection: [S1QL defense impairment — shadow copy deletion, log clearing](../../detection/s1ql/defense-evasion.md)
- Detection: [SMB admin-share lateral movement](../../detection/spl/lateral-movement-smb.md)
- Respond: [Ransomware host isolation](../../tasks/incident-response/ransomware-host-isolation.md) · [Malware triage](../../tasks/incident-response/malware-triage.md)
- Hypervisors: [ESXi forensics & hardening](../../platforms/virtualization/esxi-forensics-hardening.md)
- Recover: [Backup and recovery operations](../../tasks/administration/backup-and-recovery.md)
- Harden: [Attack Surface Reduction rules](../../tasks/hardening/windows-cis-attack-surface-reduction.md)

## Related concepts

- [Credential Dumping](credential-dumping.md)
- [Port Scanning](port-scanning.md)

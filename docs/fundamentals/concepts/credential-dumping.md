---
title: Credential Dumping
type: concept
platforms: [Windows, Microsoft Defender, Active Directory]
languages: [PowerShell, KQL]
tasks: [Incident Response, Threat Hunting, Hardening]
category: Identity Attacks
security_domain: Endpoint
author: RJGProjectz
date_created: 2026-10-11
last_updated: 2026-10-11
tags: [concept, lsass, mimikatz, credential-access]
aliases: [Mimikatz, LSASS dump, OS credential dumping, NTDS.dit extraction, pass-the-hash]
difficulty: intermediate
verified: false
---

# Credential Dumping
> **Created**: 2026-10-11T22:00:00Z
> **Last Modified**: 2026-10-11T22:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

**In one line:** pulling passwords, hashes and tickets out of a machine's memory or credential stores so the attacker can log in as someone else.

## What it is

Windows keeps secrets so users are not asked for passwords all day: the LSASS process holds logon hashes and Kerberos
tickets, the SAM and LSA secrets hold local ones, and a domain controller's `NTDS.dit` holds every domain account's hash.
With administrator rights an attacker reads these — with Mimikatz, a memory dump through Task Manager or `procdump`, or a
shadow copy of the database. The hashes are then cracked, or used directly (pass-the-hash, pass-the-ticket).

## How it works

```text
local admin / SYSTEM
   ├── open lsass.exe with read access ──► NTLM hashes, Kerberos tickets, sometimes clear text
   ├── reg save HKLM\SAM + SYSTEM ──────► local account hashes
   └── on a DC: shadow copy / replication ─► NTDS.dit = every domain hash
                         │
                         ▼
           reuse on other hosts (lateral movement)
```

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) — LSASS Memory · [T1003.003](https://attack.mitre.org/techniques/T1003/003/) — NTDS · [T1550.002](https://attack.mitre.org/techniques/T1550/002/) — Pass the Hash |
| **What it leads to** | domain-wide compromise; one admin logon on a bad host can expose the whole domain |
| **Where defenders meet it** | EDR "credential theft" alert, a `.dmp` file in a temp folder, `lsass` access from an odd process |

## Do it

```bash
cc find lsass
cc view docs/detection/kql/credential-access.md
```

Check what protects this host's credentials:

```powershell
# LSA protection (RunAsPPL) and Credential Guard state
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue
(Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard).SecurityServicesRunning
# 1 = Credential Guard running
```

## See it

| Source | What you see |
| :--- | :--- |
| Sysmon Event 10 (ProcessAccess) | `TargetImage` `lsass.exe` with `GrantedAccess` such as `0x1010` or `0x1FFFFF` from a non-system tool |
| Sysmon Event 11 / file telemetry | `lsass*.dmp` or other minidumps written to user-writable paths |
| Process telemetry | `procdump -ma lsass`, `rundll32 comsvcs.dll, MiniDump`, `ntdsutil "ac i ntds" ifm`, `vssadmin create shadow` |
| Security log 4624 afterwards | logon type 9 or NTLM logons from hosts the account never used |

## Detect it

- Detection: [KQL credential access and memory dumping](../../detection/kql/credential-access.md)
- Sensor: [Sysmon architecture](../systems/sysmon.md) · [Sysmon deployment & tuning](../../tasks/administration/sysmon-deployment-tuning.md)
- Respond: [Account compromise investigation](../../tasks/incident-response/account-compromise.md) · [Suspicious process](../../tasks/incident-response/suspicious-process.md)
- Harden: [Credential Guard & ASR](../../tasks/hardening/windows-cis-attack-surface-reduction.md) · [User rights assignment](../../tasks/hardening/windows-cis-user-rights-assignment.md)

## Related concepts

- [Kerberoasting](kerberoasting.md)
- [Ransomware](ransomware.md)

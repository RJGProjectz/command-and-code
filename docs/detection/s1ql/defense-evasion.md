---
title: S1QL Defense Evasion and Tampering Queries
type: entry
platforms:
  - SentinelOne
  - Windows
  - Linux
languages:
  - S1QL
tasks:
  - Threat Hunting
  - Incident Response
  - Detection Engineering
verified: true
last_verified: 2026-10-07
difficulty: advanced
tags:
  - s1ql
  - sentinelone
  - defense-evasion
  - tampering
  - wevtutil
  - auditpol
  - shadow-copies
---

# S1QL Defense Evasion and Tampering Queries

SentinelOne Deep Visibility telemetry captures system-level manipulation attempts where adversaries attempt to disable logging, clear Windows Event logs, delete volume shadow copies, and blind security sensors.

---

## 1. Windows Event Log Clearing (`wevtutil` / PowerShell)

Adversaries wipe event logs prior to disconnecting or launching ransomware:

```text
EventType = "Process Creation" AND (
    (TgtProcName = "wevtutil.exe" AND TgtProcCmd Contains Anycase ("cl", "clear-log")) OR
    (TgtProcName = "powershell.exe" AND TgtProcCmd Contains Anycase ("Clear-EventLog", "Remove-EventLog", "wevtutil"))
)
```

---

## 2. Mass Volume Shadow Copy Deletion (`vssadmin` / `wmic`)

Pre-ransomware impact signature ([T1490](https://attack.mitre.org/techniques/T1490/)):

```text
EventType = "Process Creation" AND (
    (TgtProcName = "vssadmin.exe" AND TgtProcCmd Contains Anycase ("delete shadows", "resize shadowstorage")) OR
    (TgtProcName = "wmic.exe" AND TgtProcCmd Contains Anycase ("shadowcopy delete")) OR
    (TgtProcName = "wbadmin.exe" AND TgtProcCmd Contains Anycase ("delete catalog", "delete systemstatebackup"))
)
```

---

## 3. Disabling Windows Defender & Security Services

Adversaries disable Real-Time Protection via PowerShell or registry tweaks:

```text
EventType = "Process Creation" AND (
    (TgtProcName = "powershell.exe" AND TgtProcCmd Contains Anycase (
        "Set-MpPreference -DisableRealtimeMonitoring $true",
        "DisableIOAVProtection $true",
        "DisableBehaviorMonitoring $true"
    )) OR
    (TgtProcName = "sc.exe" AND TgtProcCmd Contains Anycase (
        "config WinDefend start= disabled",
        "stop WinDefend",
        "stop Sense"
    ))
)
```

---

## 4. Modifying Host Audit Policy via `auditpol`

Adversaries turn off process creation and logon auditing:

```text
EventType = "Process Creation" AND 
TgtProcName = "auditpol.exe" AND 
TgtProcCmd Contains Anycase ("/set", "/subcategory", "/success:disable", "/failure:disable")
```

---

## 5. Linux Log Deletion and History Disabling

Detects Linux adversaries truncating logs or unsetting history parameters:

```text
EventType = "Process Creation" AND (
    (TgtProcCmd Contains Anycase ("rm -rf /var/log", "> /var/log/", "shred /var/log")) OR
    (TgtProcCmd Contains Anycase ("HISTFILE=/dev/null", "HISTSIZE=0", "unset HISTFILE"))
)
```

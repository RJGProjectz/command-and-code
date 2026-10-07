---
title: KQL Credential Access and Memory Dumping Queries
type: entry
platforms:
  - Microsoft Defender
  - Windows
  - Windows Server
languages:
  - KQL
tasks:
  - Threat Hunting
  - Detection Engineering
  - Incident Response
verified: true
last_verified: 2026-10-07
difficulty: advanced
tags:
  - kql
  - credential-access
  - lsass
  - minidump
  - procdump
  - mimikatz
  - ntds
---

# KQL Credential Access and Memory Dumping Queries

Adversaries dump plaintext credentials, Kerberos tickets, and NTLM password hashes by accessing Local Security Authority Subsystem Service ($LSASS$) memory or stealing Active Directory database copies ($NTDS.dit$).

---

## 1. LSASS Memory Read & Injection Detection

Detects processes requesting `PROCESS_VM_READ` or `PROCESS_ALL_ACCESS` rights to `lsass.exe` (Mimikatz, Procdump, Taskmgr, Dumpert).

```kql
// Detect unauthorized processes opening LSASS process handle
DeviceProcessEvents
| where ActionType == "OpenProcess" or ActionType == "ProcessAccess"
| where TargetProcessFileName =~ "lsass.exe"
// Filter out legitimate Windows processes and Defender
| where not(InitiatingProcessFileName in~ (
    "csrss.exe", "svchost.exe", "MsMpEng.exe", "SenseCncProxy.exe", 
    "lsass.exe", "services.exe", "dwm.exe"
))
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, 
          InitiatingProcessParentFileName, TargetProcessFileName
| order by Timestamp desc
```

---

## 2. MiniDump / Process Dump File Creation

Detects dumping process memory to `.dmp` files in user-writable directories.

```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName endswith ".dmp" or FileName endswith ".dump"
| where FolderPath has_any ("C:\\Users\\", "C:\\Temp\\", "C:\\ProgramData\\", "C:\\Windows\\Temp\\")
| where not(InitiatingProcessFileName in~ ("WerFault.exe", "devenv.exe", "visualstudio.exe"))
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 3. NTDS.dit Shadow Copy Access and Extraction

Detects adversaries executing `ntdsutil`, `vssadmin`, or `wbadmin` to copy the Active Directory database on Domain Controllers.

```kql
DeviceProcessEvents
| where FileName in~ ("ntdsutil.exe", "vssadmin.exe", "wbadmin.exe", "esentutl.exe")
| where (
    // ntdsutil database snapshot
    (FileName =~ "ntdsutil.exe" and ProcessCommandLine has_any ("ac i ntds", "ifm", "create full"))
    or
    // esentutl database copy
    (FileName =~ "esentutl.exe" and ProcessCommandLine has_any ("ntds.dit", "/y", "/vss"))
    or
    // Volume Shadow Copy creation for offline copy
    (FileName =~ "vssadmin.exe" and ProcessCommandLine has_any ("create shadow", "shadowcopy"))
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 4. DPAPI Master Key Scraping & Vault Dumping

Detects access to stored credentials, browser passwords, and Windows Vault master keys (`T1555`).

```kql
DeviceProcessEvents
| where FileName in~ ("vaultcmd.exe", "cmdkey.exe")
| where ProcessCommandLine has_any ("/list", "/export", "/show")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

---
title: Hunting Living-off-the-Land Binaries and Scripts (LOLBins)
type: workflow
platforms:
  - Windows
  - Windows Server
  - Microsoft Defender
  - Splunk
  - SentinelOne
languages:
  - PowerShell
  - KQL
  - SPL
  - S1QL
tasks:
  - Threat Hunting
  - Detection Engineering
  - Investigation
verified: true
last_verified: 2026-10-07
difficulty: advanced
tags:
  - threat-hunting
  - lolbins
  - certutil
  - mshta
  - rundll32
  - bitsadmin
  - living-off-the-land
---

# Hunting Living-off-the-Land Binaries and Scripts (LOLBins)

Living-off-the-land binaries ($LOLBins$) are trusted Microsoft-signed system utilities that adversaries abuse to bypass application allowlisting, download staging payloads, proxy code execution, and evade defense telemetry.

---

## 1. High-Priority LOLBins & Suspicious Command-Line Arguments

| Binary | Common Legitimate Path | Adversary Abuse Pattern | Suspicious Telemetry Indicators |
| :--- | :--- | :--- | :--- |
| **`certutil.exe`** | `C:\Windows\System32\` | Remote HTTP file download, Base64 decoding | `-urlcache`, `-split`, `-f`, `-decode` |
| **`mshta.exe`** | `C:\Windows\System32\` | Inline VBScript/JScript execution from URL | `http://`, `https://`, `javascript:`, `vbscript:` |
| **`rundll32.exe`** | `C:\Windows\System32\` | Proxy execution of malicious DLL or memory shellcode | Path outside System32/SysWOW64, URL target, ordinal export |
| **`regsvr32.exe`** | `C:\Windows\System32\` | "Squiblydoo" remote scriptlet execution | `/s /n /u /i:http` |
| **`bitsadmin.exe`** | `C:\Windows\System32\` | Stealthy background file download & persistence | `/transfer`, `/create`, `/addfile`, `/setnotifycmdline` |

---

## 2. Threat Hunting Queries

### Microsoft Defender XDR (KQL): Multi-LOLBin Download & Execution

```kql
DeviceProcessEvents
| where FileName in~ ("certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "bitsadmin.exe", "hh.exe", "wmic.exe")
| where (
    // CertUtil remote fetch or decode
    (FileName =~ "certutil.exe" and ProcessCommandLine has_any ("urlcache", "split", "decode"))
    or
    // Mshta inline web execution
    (FileName =~ "mshta.exe" and ProcessCommandLine has_any ("http:", "https:", "javascript:", "vbscript:"))
    or
    // Regsvr32 remote scriptlet execution
    (FileName =~ "regsvr32.exe" and ProcessCommandLine has_any ("/i:http", "/i:https", "scrobj.dll"))
    or
    // Bitsadmin payload download
    (FileName =~ "bitsadmin.exe" and ProcessCommandLine has_any ("/transfer", "/addfile"))
    or
    // Rundll32 executing from user-writable directory
    (FileName =~ "rundll32.exe" and ProcessCommandLine has_any ("C:\\Users\\", "C:\\ProgramData\\", "C:\\Temp\\", "http"))
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Splunk (SPL): CertUtil and Regsvr32 Execution Cradles

```spl
index=wineventlog EventCode=4688
| eval Process=lower(NewProcessName)
| where match(Process, "(\\\\certutil\\.exe|\\\\regsvr32\\.exe|\\\\mshta\\.exe)$")
| where match(CommandLine, "(?i)(-urlcache|-split|-decode|/i:http|javascript:|vbscript:)")
| table _time host user Process CommandLine ParentProcessName
| sort - _time
```

### SentinelOne Deep Visibility (S1QL): Suspicious Scriptlet & Binary Proxies

```text
EventType = "Process Creation" AND (
    (TgtProcName = "certutil.exe" AND TgtProcCmd Contains Anycase ("urlcache", "decode")) OR
    (TgtProcName = "mshta.exe" AND TgtProcCmd Contains Anycase ("http", "javascript")) OR
    (TgtProcName = "regsvr32.exe" AND TgtProcCmd Contains Anycase ("/i:http", "scrobj.dll"))
)
```

---

## 3. Host-Level PowerShell Triage

When investigating an endpoint alerted for suspicious LOLBin usage, correlate the executing user and parent process tree:

```powershell
# 1. Inspect recent process creation in Security Event Log (Event ID 4688)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4688
    StartTime = (Get-Date).AddDays(-2)
} | Where-Object {
    $_.Properties[5].Value -match "certutil\.exe|mshta\.exe|regsvr32\.exe|bitsadmin\.exe"
} | Select-Object TimeCreated,
    @{N='Process';E={$_.Properties[5].Value}},
    @{N='CommandLine';E={$_.Properties[8].Value}},
    @{N='Parent';E={$_.Properties[13].Value}}

# 2. Check BITS jobs queue for active persistent adversary downloads
Get-BitsTransfer -AllUsers | Select-Object JobId, DisplayName, JobState, Priority, @{N='Files';E={$_.FileList.RemoteName}}
```

---

## 4. Hardening & Mitigation Controls

1. **WDAC / AppLocker Binary Constraints**: Enforce Windows Defender Application Control ($WDAC$) to block LOLBins from executing in user-writable directories (`C:\Users\*`, `C:\ProgramData\*`).
2. **Microsoft Recommended Block Rules**: Implement the official WDAC blocklist rules which restrict high-risk LOLBins (`mshta.exe`, `wmic.exe`, `cscript.exe`) from initiating external network connections.
3. **Attack Surface Reduction (ASR)**: Enable rule `Block process creations originating from PSExec and WMI commands` and `Block executable files from running unless they meet a prevalence, age, or trusted list criterion`.

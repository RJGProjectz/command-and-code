---
title: Investigation Workflow — Compromised Host Forensics in Splunk
type: workflow
platforms:
  - Splunk
  - Windows
  - Windows Server
languages:
  - SPL
tasks:
  - Investigation
  - Forensics
  - Incident Response
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - splunk
  - host-forensics
  - sysmon
  - persistence
  - lolbins
---

# Investigation Workflow — Compromised Host Forensics in Splunk

Deep-dive forensic investigation procedure for endpoints or servers suspected of malware infection, hands-on-keyboard activity, or persistence installation.

## 1. Anomalous Process Lineage & LOLBins

Search for rare parent-child execution patterns on the target host:

```spl
index=endpoint host="<TARGET_HOST>" EventCode=4688
| stats count by ParentProcessName, NewProcessName, CommandLine
| eventstats sum(count) as total
| eval frequency = count/total
| where frequency < 0.02
| table ParentProcessName, NewProcessName, CommandLine, count
```

- **Red Flags**:
  - `WINWORD.EXE` $\rightarrow$ `powershell.exe` or `cmd.exe`
  - `w3wp.exe` $\rightarrow$ `cmd.exe` (Web shell execution)
  - `certutil.exe -urlcache -split -f` (Payload download)

## 2. Persistence via New Services & Scheduled Tasks

```spl
index=endpoint host="<TARGET_HOST>" (EventCode=7045 OR EventCode=4697 OR EventCode=4698)
| table _time, EventCode, ServiceName, ServiceFileName, TaskName, Command, AccountName
```

## 3. Registry Run Key Modifications

```spl
index=endpoint host="<TARGET_HOST>" EventCode=13 TargetObject="*\\CurrentVersion\\Run*"
| table _time, Image, TargetObject, Details
```

## 4. Anti-Forensics & Audit Log Clearing

```spl
index=endpoint host="<TARGET_HOST>" (EventCode=1102 OR EventCode=104)
| table _time, User, Message
```

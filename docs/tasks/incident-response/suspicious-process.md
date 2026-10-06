---
title: Suspicious Process Investigation
type: workflow
platforms: [Windows, Linux, Microsoft Defender]
languages: [PowerShell, Bash, KQL]
tasks: [Incident Response, Investigation]
category: Workflow
tags: [workflow, process, triage, hash, signature, parent child]
aliases: [suspicious process, unknown process, is this process malicious, investigate pid]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Suspicious Process Investigation

**Trigger:** an unknown process name, an unusual path, high resource use, or an EDR alert on a process.

## 1. Pin down the process

PID, name, full path, command line, start time, user.

→ [Windows: find a process by PID](../../platforms/windows/processes.md#find-a-process-by-pid) · [Linux: find a process by PID](../../platforms/linux/processes.md#find-a-process-by-pid)

## 2. Check the path against the name

| Red flag | Example |
| --- | --- |
| System binary name in the wrong folder | `C:\Users\Public\svchost.exe` |
| Misspelling | `scvhost.exe`, `lsasss.exe`, `explorer .exe` |
| User-writable location | `%APPDATA%`, `%TEMP%`, `C:\ProgramData`, `/tmp`, `/dev/shm` |
| Deleted binary (Linux) | `/proc/PID/exe -> /tmp/x (deleted)` |

## 3. Parent and children

→ [Windows parent](../../platforms/windows/processes.md#find-the-parent-process) · [Windows tree](../../platforms/windows/processes.md#process-tree) · [Linux tree](../../platforms/linux/processes.md#process-tree)

## 4. Hash and signature

Look the SHA256 up in your threat-intel sources and EDR.

→ [Windows hash and signature](../../platforms/windows/processes.md#check-the-binary-hash-and-signature) · [Linux inspect a file](../../platforms/linux/filesystem.md#inspect-a-file)

## 5. What is it doing?

- Network: [Windows](../../platforms/windows/processes.md#find-the-process-that-owns-a-port), [Linux](../../platforms/linux/processes.md#open-files-and-network-sockets-of-a-process)
- Loaded modules: [Windows DLLs](../../platforms/windows/processes.md#list-loaded-modules-dlls)

## 6. How did it start, and will it come back?

Persistence → [Endpoint Triage step 6](endpoint-triage.md#6-persistence)

## 7. Fleet prevalence

One host or hundreds? A binary on one device in the whole estate deserves more suspicion.

→ [KQL: every execution of a hash](../../detection/kql/process-events.md#find-every-execution-of-a-hash) · [KQL: execution from user-writable paths](../../detection/kql/process-events.md#execution-from-user-writable-paths) · [S1QL: rare processes](../../detection/s1ql/hunting.md#rare-processes-across-the-fleet)

## 8. Contain

Preserve first (hash, copy, memory if feasible), then kill/quarantine via EDR so the action is logged.

→ [Windows stop a process](../../platforms/windows/processes.md#stop-a-process) · [Linux stop/freeze a process](../../platforms/linux/processes.md#stop-a-process)

## Related

- [Malware Triage](malware-triage.md)
- [Suspicious PowerShell](suspicious-powershell.md)

---
title: DLL Injection
type: concept
platforms: [Windows]
languages: [PowerShell]
tasks: [Incident Response, Threat Hunting, Hardening, Detection Engineering]
category: Code Injection
security_domain: Endpoint
author: RJGProjectz
date_created: 2026-11-24
last_updated: 2026-11-24
tags: [concept, dll-injection, process-injection, privilege-escalation, defense-evasion, windows]
aliases: [DLL injection, process injection, remote thread injection, reflective DLL injection, LoadLibrary injection]
difficulty: intermediate
verified: false
---

# DLL Injection
> **Created**: 2026-11-24T00:00:00Z
> **Last Modified**: 2026-11-24T00:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

**In one line:** forcing a running Windows process to load an attacker-controlled DLL, so the malicious code executes inside the address space and security context of a legitimate process.

## What it is

DLL injection is a code-injection technique specific to Windows. Every Windows process loads Dynamic Link Libraries (DLLs) — shared code modules — to perform common operations like file I/O, networking, and GUI rendering. Because DLLs load directly into a process's virtual address space and run with that process's privileges, persuading a privileged process to load an attacker-controlled DLL is an effective way to run arbitrary code as a higher-integrity or SYSTEM-level identity.

This differs from DLL hijacking, which exploits the Windows DLL search order to substitute a rogue DLL before the legitimate one is found. Injection does not depend on a path misconfiguration; instead it uses Windows APIs — primarily `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, and `CreateRemoteThread` — to place code into an already-running target process and trigger its execution. Because the malicious code runs inside a trusted host process such as `explorer.exe`, `svchost.exe`, or a security tool, many endpoint products see the behaviour attributed to that trusted parent rather than to the injector.

## How it works

The classic `LoadLibrary` injection path uses four API calls:

```text
Attacker process (low/admin privilege)
  │
  ├─ OpenProcess(PROCESS_ALL_ACCESS, pid)   ─► handle to target
  ├─ VirtualAllocEx(handle, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
  │      └─► allocate RWX memory inside target's VA space
  ├─ WriteProcessMemory(handle, addr, dll_path, size)
  │      └─► write the DLL path string into that memory
  └─ CreateRemoteThread(handle, NULL, 0, LoadLibraryA, addr)
         └─► target calls LoadLibrary → DLL loads and DllMain() executes
```

Reflective DLL injection is a stealthier variant: rather than writing a file path and relying on `LoadLibrary`, the entire DLL is mapped into memory by a custom loader that never touches the filesystem and never registers the DLL in the Process Environment Block (PEB), making it invisible to standard loaded-modules enumeration.

Shellcode injection follows a similar memory-write-and-thread pattern but injects raw position-independent shellcode instead of a DLL, reducing the on-disk footprint to zero.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1055.001](https://attack.mitre.org/techniques/T1055/001/) — Dynamic-link Library Injection |
| **What it leads to** | code running as SYSTEM or as a trusted process; credential harvesting; persistence through a trusted host process; EDR bypass |
| **Where defenders meet it** | EDR "process injection" alert; unexpected `OpenProcess` + `WriteProcessMemory` + `CreateRemoteThread` sequence on a monitored host |

## Do it

```bash
cc find "process injection"
cc view docs/offensive/dll-hijacking.md
cc view docs/tasks/threat-hunting/index.md
```

Check for suspicious cross-process access on a Windows host you own:

```powershell
# List processes that have opened handles to other processes (requires Sysinternals handle.exe)
# This is read-only analysis on a host you own
Get-Process | Where-Object { $_.Handles -gt 500 } |
  Select-Object Id, ProcessName, Handles, StartTime |
  Sort-Object Handles -Descending | Select-Object -First 15
```

```powershell
# Check for unusual DLLs loaded into a process (inspect svchost as an example)
$pid = (Get-Process -Name 'explorer' | Select-Object -First 1).Id
(Get-Process -Id $pid).Modules | Where-Object { $_.FileName -notlike 'C:\Windows\*' } |
  Select-Object FileName, ModuleMemorySize
```

!!! caution "SAFETY WARNING: VALIDATE BEFORE EXECUTION"
    The read-only PowerShell commands above inspect running processes on a machine you own. Do not use injection tooling (msfvenom, Empire, manual API calls) against systems you do not own or lack explicit written authorisation to test.

## See it

Injection leaves traces across multiple telemetry sources. The injector process and the host process both emit events that together reveal the technique, even when the injected code itself is fileless.

| Source | What you see |
| :--- | :--- |
| Sysmon Event 8 (CreateRemoteThread) | Source and target process IDs, start address; a non-system process creating a thread in `lsass.exe`, `explorer.exe`, or `svchost.exe` is immediately suspicious |
| Sysmon Event 10 (ProcessAccess) | `OpenProcess` calls with `PROCESS_VM_WRITE` or `PROCESS_CREATE_THREAD` access rights from unexpected source processes |
| Sysmon Event 7 (ImageLoad) | A DLL loading from a user-writable path (`AppData`, `Temp`, network share) into a system process |
| ETW / API monitoring | `VirtualAllocEx` followed by `WriteProcessMemory` followed by `CreateRemoteThread` within seconds from the same source PID |
| Memory scanning (live forensics) | Private RWX memory regions inside a system process that contain no mapped file reference — a classic indicator of reflective injection |

## Detect it

- Detection: [Endpoint Detection](../../detection/index.md)
- Hunt: [Threat Hunting Workflows](../../tasks/threat-hunting/index.md)
- Respond: [Incident Response](../../tasks/incident-response/index.md)
- Harden: [Windows Hardening](../../tasks/hardening/index.md)

## Hardening controls

| Control | Why it helps |
| :--- | :--- |
| Protected Process Light (PPL) | LSASS and other sensitive processes cannot be opened with write access by non-PPL callers |
| Arbitrary Code Guard (ACG) | Prevents a process from mapping executable memory at runtime, breaking `WriteProcessMemory` + RWX patterns |
| Child Process Creation policy | Group Policy / Defender Attack Surface Reduction can block processes from spawning threads in other processes |
| EDR with memory scanning | Detects RWX private regions and known injection shellcode signatures at runtime |
| Sysmon Event 8 alerting | Trigger on `CreateRemoteThread` where source and target process names do not match known legitimate pairs |

## Related concepts

- DLL Hijacking
- [Privilege Escalation](../../offensive/privilege-escalation.md)
- [Malware Types and Analysis](malware-types-analysis.md)
- [Processes and Threads](processes-threads.md)

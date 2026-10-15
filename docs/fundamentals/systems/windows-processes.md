---
title: Fundamentals — Windows Process Architecture, Tokens & Handles
type: entry
platforms:
  - Windows
  - Windows Server
languages:
  - PowerShell
  - Windows CLI
tasks:
  - Investigation
  - Forensics
verified: true
last_verified: 2026-10-12
difficulty: intermediate
tags:
  - windows
  - processes
  - access-tokens
  - handles
---

# Fundamentals — Windows Process Architecture, Tokens & Handles

Every running executable in Windows operates as an isolated process with virtual address space, execution threads, open handles, and an access token.

## 1. Process Access Tokens

An access token contains the security context of the process:
- User SID (Security Identifier) and Group SIDs (e.g. Domain Admins, Everyone).
- Privileges (e.g., `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeBackupPrivilege`).
- Integrity Level: `Untrusted`, `Low`, `Medium` (Standard user), `High` (Elevated Admin), `System`.

An administrator who logs on gets **two tokens** (UAC): a filtered Medium-integrity token for normal work and a full High-integrity token used only after elevation.

```powershell
whoami /user /groups /priv     # your token: SIDs, groups (with integrity level), privileges
```

Privileges attackers look for:

| Privilege | Abuse |
| --- | --- |
| `SeDebugPrivilege` | Open any process, including `lsass.exe` (credential dumping) |
| `SeImpersonatePrivilege` | "Potato" attacks: service accounts (IIS, SQL) escalate to `SYSTEM` |
| `SeBackupPrivilege` / `SeRestorePrivilege` | Read or write any file regardless of ACLs (copy `SAM`, `NTDS.dit`) |
| `SeLoadDriverPrivilege` | Load a vulnerable driver to reach the kernel |
| `SeTakeOwnershipPrivilege` | Take over any file or registry key |

## 2. Process Lineage & Handle Tables

- **Parent Process ID (PPID)**: Defines the spawning parent. Adversaries use PPID Spoofing ([T1134.004](https://attack.mitre.org/techniques/T1134/004/)) to make malicious binaries appear as children of legitimate processes (e.g., `explorer.exe`).
- **Handles**: Pointers to system objects (files, registry keys, synchronization mutexes, ports). A handle to `lsass.exe` with read-memory access is the core of credential dumping (Sysmon Event 10).

## 3. Know normal

Most process-based detections are "this parent should never start that child" or "this system process is in the wrong place".

| Process | Normal parent | Path | Count |
| --- | --- | --- | --- |
| `smss.exe` | `System` | `C:\Windows\System32` | 1 (plus short-lived copies at boot) |
| `csrss.exe`, `wininit.exe` | `smss.exe` (which exits) | `C:\Windows\System32` | 1 per session / 1 |
| `services.exe` | `wininit.exe` | `C:\Windows\System32` | 1 |
| `lsass.exe` | `wininit.exe` | `C:\Windows\System32` | 1 |
| `svchost.exe` | `services.exe` | `C:\Windows\System32` (or `SysWOW64`) | Many, always with `-k <group>` |
| `explorer.exe` | `userinit.exe` (which exits) | `C:\Windows` | 1 per logged-on user |

Red flags: `lsass.exe` or `svchost.exe` running from another folder or with a different parent, two `lsass.exe`, `svchost.exe` without `-k`, Office or browsers starting `cmd.exe` / `powershell.exe`, and look-alike names (`scvhost.exe`, `lsas.exe`).

```powershell
# Process tree with command lines (parent PID, owner of each process)
Get-CimInstance Win32_Process |
    Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine |
    Sort-Object ParentProcessId | Format-Table -AutoSize -Wrap
```

## Related

- Concept: [Processes, threads and handles](../concepts/processes-threads.md)
- [Windows processes (platform)](../../platforms/windows/processes.md)
- [Suspicious Process](../../tasks/incident-response/suspicious-process.md)
- [Virtual memory, stack and heap](memory-internals.md)

## Sources

- [Microsoft Learn — Access tokens](https://learn.microsoft.com/windows/win32/secauthz/access-tokens)
- [Microsoft Learn — Privilege constants](https://learn.microsoft.com/windows/win32/secauthz/privilege-constants)
- [SANS — Hunt Evil poster (normal Windows processes)](https://www.sans.org/posters/hunt-evil/)

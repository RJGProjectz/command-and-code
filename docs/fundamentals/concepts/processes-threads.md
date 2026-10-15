---
title: Processes, Threads and Handles
type: concept
platforms: [Windows, Linux]
languages: [PowerShell, Bash]
tasks: [Incident Response, Investigation, Threat Hunting]
category: Operating Systems
security_domain: Endpoint
author: RJGProjectz
date_created: 2026-10-15
last_updated: 2026-10-15
tags: [concept, process, thread, pid, ppid, access-token, file-descriptor]
aliases: [Processes and threads, PID and PPID, parent-child process, access token, primary token, impersonation token, file descriptors, process handles, effective UID]
difficulty: basic
verified: true
last_verified: 2026-10-15
---

# Processes, Threads and Handles
> **Created**: 2026-10-15T03:20:00Z
> **Last Modified**: 2026-10-15T03:20:00Z
> **Author**: RJGProjectz

**In one line:** a process is a running program with its own memory, an identity it acts as, and open handles to files, keys and sockets — most malware is found by asking which process did it and who started it.

## What it is

A **process** is a container: an executable image, its memory, and one or more **threads** that actually run code.
The operating system gives each process an ID and a security identity, and tracks everything it has open.

| | Windows | Linux |
| :--- | :--- | :--- |
| ID | Process ID (PID), parent PID recorded at creation | PID from `fork()`, PPID; both kept across `execve()` |
| Identity | **access token**: user SID, group SIDs, logon SID, privileges, integrity level | **credentials**: real, effective, saved and filesystem UID/GID, supplementary groups, capabilities |
| Acting as someone else | a thread can carry an **impersonation token** on top of the process's primary token | set-user-ID programs change the effective UID; `seteuid()` switches between real and saved IDs |
| Open resources | **handles** in the process handle table (files, registry keys, mutexes, other processes) | **file descriptors** (`/proc/1234/fd`) for files, pipes and sockets |
| Tree | parent PID is a number, not a live link — the parent may have exited and the PID been reused | orphans are re-parented to PID 1 (or a subreaper) |

## How it works

```text
logon ──► token / credentials created
             │  copied to every process the user starts
             ▼
explorer.exe / login shell ──► child process ──► child thread
             │                     │
             │                     └── opens handles / fds (files, keys, sockets, other processes)
             ▼
every access check compares the caller's token (Windows) or effective/fs IDs (Linux) with the object's ACL or mode bits
```

Windows Vista and later start an administrator's desktop with a filtered (standard) token; elevation through
[UAC](users-groups-permissions.md) starts a new process with the full token. Normal parent-child pairs on Windows
(for example `services.exe` → `svchost.exe`) are listed on [Windows process internals](../systems/windows-processes.md).

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1055](https://attack.mitre.org/techniques/T1055/) Process Injection · [T1134](https://attack.mitre.org/techniques/T1134/) Access Token Manipulation · [T1134.004](https://attack.mitre.org/techniques/T1134/004/) Parent PID Spoofing · [T1036](https://attack.mitre.org/techniques/T1036/) Masquerading · [T1057](https://attack.mitre.org/techniques/T1057/) Process Discovery |
| **What it leads to** | code running inside a trusted process, stolen tokens used to act as another user, a fake `svchost.exe` in the wrong folder |
| **Where defenders meet it** | EDR alert on an odd parent (Word → PowerShell), a process running from `%TEMP%` or `/tmp`, a deleted binary still running |

## Do it

```bash
cc find "process tree" ; cc view docs/platforms/windows/processes.md
```

```powershell
# Parent, path, command line and owner of every process
Get-CimInstance -ClassName Win32_Process |
    Select-Object -Property ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine |
    Sort-Object -Property ParentProcessId
# Privileges and integrity level of the current token
whoami /priv
whoami /groups | Select-String -Pattern 'Mandatory Label'
```

```bash
# Tree with PIDs and the user each process runs as
ps -eo pid,ppid,user,etime,cmd --forest
# Real/effective/saved/filesystem UIDs and capabilities of process 1234
grep -E '^(Uid|Gid|Cap)' /proc/1234/status
# Open file descriptors (files, sockets)
ls -l /proc/1234/fd
```

## See it

| Source | What you see |
| :--- | :--- |
| Security 4688 (with command line auditing) | new process, creator process, token elevation type |
| Sysmon Event 1 | process create with hashes, parent image and parent command line |
| Sysmon Event 8 / 10 | `CreateRemoteThread` into another process / handle opened to another process (for example `lsass.exe`) |
| auditd `execve` rules | every program run, with `auid` (the original login user) and `euid` |
| `/proc/1234/exe` → `(deleted)` | a Linux process whose binary was removed from disk |

## Detect it

- Commands: [Windows processes](../../platforms/windows/processes.md) · [Linux processes](../../platforms/linux/processes.md)
- Internals: [Windows process internals](../systems/windows-processes.md) · [Memory internals and paging](../systems/memory-internals.md)
- Detection: [KQL process events](../../detection/kql/process-events.md) · [SPL Windows events](../../detection/spl/windows-events.md) · [Sigma examples](../../detection/sigma/examples.md)
- Respond: [Suspicious process](../../tasks/incident-response/suspicious-process.md) · Hunt: [LOLBins execution](../../tasks/threat-hunting/lolbins-execution-hunting.md)
- Memory: [Memory acquisition and analysis](../../tasks/forensics/memory-acquisition-analysis.md)

## Related concepts

- [Credential dumping](credential-dumping.md) · [Malware types and analysis](malware-types-analysis.md) · [Users, groups and privilege](users-groups-permissions.md) · [Services and daemons](services-daemons.md)

## Sources

- Microsoft Learn: [Access tokens](https://learn.microsoft.com/windows/win32/secauthz/access-tokens) · [How UAC works](https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/how-it-works) · [Event 4688](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688) · [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- man7.org: [credentials(7)](https://man7.org/linux/man-pages/man7/credentials.7.html) · [proc_pid_status(5)](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html) · [ps(1)](https://man7.org/linux/man-pages/man1/ps.1.html)

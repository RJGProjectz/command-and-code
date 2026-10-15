---
title: Services and Daemons (Windows SCM, systemd)
type: concept
platforms: [Windows, Linux]
languages: [PowerShell, Bash]
tasks: [Investigation, Threat Hunting, Hardening]
category: Operating Systems
security_domain: Endpoint
author: RJGProjectz
date_created: 2026-10-15
last_updated: 2026-10-15
tags: [concept, services, daemons, scm, systemd, service-accounts, persistence]
aliases: [Windows services, Service Control Manager, SCM, daemons, systemd units, service accounts, LocalSystem, NetworkService, LocalService]
difficulty: basic
verified: true
last_verified: 2026-10-15
---

# Services and Daemons (Windows SCM, systemd)
> **Created**: 2026-10-15T03:20:00Z
> **Last Modified**: 2026-10-15T03:20:00Z
> **Author**: RJGProjectz

**In one line:** services are programs the operating system starts by itself, usually before anyone signs in and often as the most powerful account on the box — which makes them a favourite place to persist.

## What it is

| | Windows | Linux |
| :--- | :--- | :--- |
| Manager | **Service Control Manager** (`services.exe`) | **systemd** as PID 1 (older: SysV init scripts) |
| Definition | registry key `HKLM\SYSTEM\CurrentControlSet\Services\<Name>` | **unit file** `<name>.service`, plus drop-ins `<name>.service.d/*.conf` |
| Where definitions live | the SYSTEM [hive](windows-registry.md) | `/etc/systemd/system/` (admin, wins), `/run/systemd/system/`, `/usr/lib/systemd/system/` (packages); user units in `~/.config/systemd/user/` |
| What it runs | `ImagePath` (an EXE, or `svchost.exe -k group` + `Parameters\ServiceDll`) | `ExecStart=` |
| When | `Start`: 0 boot, 1 system (drivers), 2 automatic, 3 manual, 4 disabled | `WantedBy=` a target (`multi-user.target`), sockets, timers, paths |
| Runs as | `ObjectName`: LocalSystem, LocalService, NetworkService, a virtual `NT SERVICE\<name>` account, a (g)MSA or a user | `User=` / `Group=`; **root if `User=` is not set**; `DynamicUser=yes` allocates a throw-away user |

## How it works

**Service accounts (Windows).** The SCM signs in as the configured account and attaches that token to the service process:

| Account | Local rights | On the network |
| :--- | :--- | :--- |
| LocalSystem (`S-1-5-18`) | everything; hidden member of Administrators | as the computer account |
| LocalService (`S-1-5-19`) | ordinary user | anonymous |
| NetworkService (`S-1-5-20`) | ordinary user | as the computer account |

**systemd sandboxing.** A unit can drop privileges and lock itself down with `NoNewPrivileges=yes` (no gain through
setuid), `ProtectSystem=strict` (file system read-only except `/dev`, `/proc`, `/sys`), `CapabilityBoundingSet=` and
`PrivateTmp=yes`. `systemd-analyze security <unit>` scores how much of this a unit uses.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) Windows Service · [T1543.002](https://attack.mitre.org/techniques/T1543/002/) Systemd Service · [T1569.002](https://attack.mitre.org/techniques/T1569/002/) Service Execution · [T1574.009](https://attack.mitre.org/techniques/T1574/009/) Path Interception by Unquoted Path · [T1489](https://attack.mitre.org/techniques/T1489/) Service Stop · [T1007](https://attack.mitre.org/techniques/T1007/) System Service Discovery |
| **What it leads to** | SYSTEM/root code execution at every boot, remote execution (PsExec-style service creation), ransomware stopping backup and database services first |
| **Where defenders meet it** | Event 7045 "a service was installed", a unit in `/etc/systemd/system` no package owns, a service binary in a user-writable folder |

## Do it

```bash
cc find "service" ; cc view docs/tasks/investigation/suspicious-service.md
```

```powershell
# Services with binary path, start mode and account; flag ones outside Windows and Program Files
Get-CimInstance -ClassName Win32_Service |
    Where-Object { $_.PathName -and $_.PathName -notmatch '(?i)\\Windows\\|\\Program Files' } |
    Select-Object -Property Name, State, StartMode, StartName, PathName
```

```bash
# Enabled units, then the full definition of one (with drop-ins) and its security score
systemctl list-unit-files --type=service --state=enabled
systemctl cat ssh.service
systemd-analyze security ssh.service
```

## See it

| Source | What you see |
| :--- | :--- |
| System 7045 (Service Control Manager) | new service: name, image path, start type, account |
| Security 4697 | a service was installed (with advanced audit policy) |
| System 7036 / 7040 | service state change / start type changed |
| Sysmon Event 13 | value set under `...\Services\<Name>\ImagePath` |
| journald / `systemctl status` | unit start, exit code, the `ExecStart` that ran |
| auditd watch on `/etc/systemd/system` | who created or edited a unit file |

## Detect it

- Commands: [Windows services](../../platforms/windows/services.md) · [Linux services with systemd](../../platforms/linux/systemd.md)
- Investigate: [Suspicious service](../../tasks/investigation/suspicious-service.md) · [Linux service failure](../../tasks/troubleshooting/linux-service-failure.md)
- Hunt: [Scheduled task persistence review](../../tasks/threat-hunting/scheduled-task-persistence-review.md) (systemd timers) · [Linux persistence](../../platforms/linux/persistence.md)
- Detection: [SPL Windows events](../../detection/spl/windows-events.md) · [SPL agent tampering](../../detection/spl/agent-tampering.md)
- Harden: [Linux CIS filesystem and services](../../tasks/hardening/linux-cis-filesystem-services.md)

## Related concepts

- [Windows registry](windows-registry.md) · [Boot and startup sequence](boot-startup-sequence.md) · [Users, groups and privilege](users-groups-permissions.md) · [Ransomware](ransomware.md)

## Sources

- Microsoft Learn: [Service user accounts](https://learn.microsoft.com/windows/win32/services/service-user-accounts) · [CreateService (start types)](https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-createservicea) · [Security identifiers](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers) · [Event 4697](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697)
- systemd: [systemd.unit(5)](https://man7.org/linux/man-pages/man5/systemd.unit.5.html) · [systemd.exec(5)](https://man7.org/linux/man-pages/man5/systemd.exec.5.html) · [systemd-analyze(1)](https://man7.org/linux/man-pages/man1/systemd-analyze.1.html)

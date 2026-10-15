---
title: Windows Registry (and the Linux /etc Equivalent)
type: concept
platforms: [Windows, Linux]
languages: [PowerShell, Bash]
tasks: [Investigation, Forensics, Threat Hunting]
category: Operating Systems
security_domain: Endpoint
author: RJGProjectz
date_created: 2026-10-15
last_updated: 2026-10-15
tags: [concept, registry, hives, run-keys, persistence, configuration]
aliases: [Windows Registry, registry hives, HKLM, HKCU, NTUSER.DAT, SAM hive, registry keys and values, Run and RunOnce keys]
difficulty: basic
verified: true
last_verified: 2026-10-15
---

# Windows Registry (and the Linux /etc Equivalent)
> **Created**: 2026-10-15T03:20:00Z
> **Last Modified**: 2026-10-15T03:20:00Z
> **Author**: RJGProjectz

**In one line:** the registry is Windows' central configuration database — services, drivers, autostarts, policies and local account hashes all live there, so attackers change it and defenders read it.

## What it is

The registry is a tree of **keys** (like folders) holding **values** (name, type, data). It is stored as **hives**:
files loaded into memory at boot or when a user signs in.

| Hive (as you see it) | File | Holds |
| :--- | :--- | :--- |
| `HKLM\SYSTEM` | `%SystemRoot%\System32\Config\System` | services and drivers, control sets, boot configuration |
| `HKLM\SOFTWARE` | `...\Config\Software` | installed software, machine-wide Run keys, Winlogon settings |
| `HKLM\SAM` | `...\Config\Sam` | local accounts and their password hashes |
| `HKLM\SECURITY` | `...\Config\Security` | LSA secrets, cached domain logons, local security policy |
| `HKU\.DEFAULT` | `...\Config\Default` | profile used before anyone signs in |
| `HKCU` (= `HKU\<user SID>`) | `NTUSER.DAT` in the user's profile | that user's settings and per-user Run keys |

`HKEY_CLASSES_ROOT` and `HKEY_CURRENT_CONFIG` are views built from these hives. Each key has a security descriptor
(ACL) and a last-write time, which is useful in a timeline.

**Linux has no registry.** The same jobs are done by plain text files: `/etc` (machine config: `passwd`, `shadow`,
`sudoers`, `systemd/system/`, `cron.d/`), per-user dot files in the home directory (`~/.bashrc`, `~/.config/`), and the
runtime view in `/proc/sys` (kernel settings, see `sysctl`). Hunting there means file hashes, owners and mtimes instead of key write times.

## How it works

```text
boot ──► kernel loads SYSTEM hive ──► SCM reads HKLM\SYSTEM\CurrentControlSet\Services (what to start)
logon ──► NTUSER.DAT loaded as HKCU ──► Explorer runs HKLM + HKCU ...\CurrentVersion\Run entries
any program ──► reads/writes keys through the registry API, checked against each key's ACL
```

Common autostart and abuse points (full list on [Windows Registry and Run keys](../../platforms/windows/registry.md)):

| Location | Effect |
| :--- | :--- |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` / `RunOnce` and the `HKCU` copies | program runs at every logon / once (`HKLM` RunOnce only when an administrator signs in) |
| `HKLM\SYSTEM\CurrentControlSet\Services\<Name>` | a [service or driver](services-daemons.md) definition: `ImagePath`, `Start`, `ObjectName` |
| `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` `Userinit`, `Shell` | programs Winlogon starts at sign-in |
| `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>` `Debugger` | another program launches instead of the named executable |

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) Registry Run Keys / Startup Folder · [T1547.004](https://attack.mitre.org/techniques/T1547/004/) Winlogon Helper DLL · [T1546.012](https://attack.mitre.org/techniques/T1546/012/) Image File Execution Options Injection · [T1112](https://attack.mitre.org/techniques/T1112/) Modify Registry · [T1012](https://attack.mitre.org/techniques/T1012/) Query Registry · [T1003.002](https://attack.mitre.org/techniques/T1003/002/) Security Account Manager |
| **What it leads to** | persistence that survives reboots, disabled security settings, local hashes taken with `reg save HKLM\SAM` |
| **Where defenders meet it** | autoruns review, an EDR "registry persistence" alert, offline hive analysis during forensics |

## Do it

```bash
cc find "run keys" ; cc view docs/tasks/investigation/registry-persistence.md
```

```powershell
# Machine and user Run keys, and the Winlogon shell values
Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' | Select-Object -Property Userinit, Shell
# Who may change the Services key
(Get-Acl -Path 'HKLM:\SYSTEM\CurrentControlSet\Services').Access | Select-Object -Property IdentityReference, RegistryRights, AccessControlType
```

```bash
# Linux equivalent: recently changed machine configuration
find /etc -xdev -type f -mtime -7 -printf '%TY-%Tm-%Td %TH:%TM %u %p\n' | sort
```

## See it

| Source | What you see |
| :--- | :--- |
| Sysmon Event 12 / 13 / 14 | registry key create-delete / value set / rename, with the process that did it |
| Security 4657 (with a SACL on the key) | an audited registry value was modified |
| Key last-write time (offline hive) | when a Run or Services key last changed |
| Process telemetry | `reg add ...\Run`, `reg save HKLM\SAM`, `Set-ItemProperty` from a script host |

## Detect it

- Commands: [Windows Registry and Run keys](../../platforms/windows/registry.md) · Linux: [persistence locations](../../platforms/linux/persistence.md)
- Investigate: [Registry persistence](../../tasks/investigation/registry-persistence.md) · [Windows disk artifacts](../../tasks/forensics/windows-disk-artifacts.md)
- Detection: [KQL file and registry events](../../detection/kql/file-registry-events.md) · [Sysmon architecture](../systems/sysmon.md)
- Credentials: [Credential dumping](credential-dumping.md)

## Related concepts

- [Services and daemons](services-daemons.md) · [Boot and startup sequence](boot-startup-sequence.md) · [Malware types and analysis](malware-types-analysis.md)

## Sources

- Microsoft Learn: [Registry hives](https://learn.microsoft.com/windows/win32/sysinfo/registry-hives) · [Run and RunOnce registry keys](https://learn.microsoft.com/windows/win32/setupapi/run-and-runonce-registry-keys) · [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) · [Event 4657](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
- MITRE ATT&CK: [T1547.004 Winlogon Helper DLL](https://attack.mitre.org/techniques/T1547/004/)
- man7.org: [hier(7)](https://man7.org/linux/man-pages/man7/hier.7.html) · [sysctl(8)](https://man7.org/linux/man-pages/man8/sysctl.8.html)

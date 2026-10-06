---
title: Windows System Information
platforms: [Windows, Windows Server]
languages: [PowerShell, Windows CLI]
tasks: [Incident Response, Administration, Troubleshooting]
category: System Information
tags: [system information, os version, uptime, hotfix, environment variables, domain]
aliases: [systeminfo, windows version, last boot time, installed updates, environment variables, PATH]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Windows System Information

The first questions in any triage: *what is this host, what OS/build, when did it last boot, is it domain-joined, is it patched?*

## OS, build and last boot

```powershell
Get-CimInstance -ClassName Win32_OperatingSystem |
    Select-Object CSName, Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime
```

Uptime:

```powershell
(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
```

PowerShell 7 has `Get-Uptime` (`Get-Uptime -Since` returns the boot time).

**Windows CLI:** `systeminfo`, `hostname`, `ver`.

`Get-ComputerInfo` returns everything at once but is slow; select only what you need:

```powershell
Get-ComputerInfo -Property CsName, CsDomain, OsName, OsVersion, OsBuildNumber, OsLastBootUpTime
```

## Domain membership

```powershell
Get-CimInstance Win32_ComputerSystem | Select-Object Name, Domain, PartOfDomain, Manufacturer, Model
```

Entra ID / hybrid join state: `dsregcmd /status` (see [Intune](../microsoft-365/intune.md#check-device-join-and-enrollment-state)).

## Installed updates

```powershell
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15 HotFixID, Description, InstalledOn
```

`Get-HotFix` only lists updates recorded by `Win32_QuickFixEngineering`; cumulative updates may show `InstalledOn` empty or only the latest LCU. Use your patch tool or Defender Vulnerability Management for authoritative patch status.

## Who am I and what can I do?

```text
whoami /all       user, SIDs, groups, privileges, integrity level
whoami /priv      privileges only
```

**Security relevance:** `SeDebugPrivilege`, `SeImpersonatePrivilege` and `SeBackupPrivilege` on unexpected accounts are privilege-escalation enablers.

## Environment variables

```powershell
Get-ChildItem Env: | Sort-Object Name
$env:PATH -split ';'
```

Process-level values are inherited; the persisted values are in the registry:

```powershell
[Environment]::GetEnvironmentVariable('Path', 'Machine')
[Environment]::GetEnvironmentVariable('Path', 'User')
```

| Scope | Registry location |
| --- | --- |
| Machine | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment` |
| User | `HKCU\Environment` |

**What to look for:** user-writable directories early in the machine `PATH` (search-order hijacking, [T1574.007](https://attack.mitre.org/techniques/T1574/007/)); unexpected `COR_ENABLE_PROFILING` / `COR_PROFILER` values ([T1574.012](https://attack.mitre.org/techniques/T1574/012/)).

## Hardware and disks

```powershell
Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors
Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, SizeRemaining, Size
```

## Related

- [Windows 10/11 version notes](windows-10-11.md)
- [Windows Server notes](windows-server.md)
- [Endpoint Triage workflow](../../tasks/incident-response/endpoint-triage.md)
- [Linux system information](../linux/system-information.md)

## Sources

- [Win32_OperatingSystem](https://learn.microsoft.com/windows/win32/cimwin32prov/win32-operatingsystem)
- [Get-HotFix](https://learn.microsoft.com/powershell/module/microsoft.powershell.management/get-hotfix)
- [whoami](https://learn.microsoft.com/windows-server/administration/windows-commands/whoami)

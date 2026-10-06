---
title: Windows Services
platforms: [Windows, Windows Server]
languages: [PowerShell, Windows CLI]
tasks: [Incident Response, Investigation, Administration, Hardening]
category: Services
tags: [services, persistence, sc.exe, 7045, unquoted service path]
aliases: [list services, service binary path, sc query, new service installed, service persistence]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Windows Services

Services run at boot, often as `LocalSystem` — which is exactly why attackers install them ([T1543.003](https://attack.mitre.org/techniques/T1543/003/)).

## List services with binary path and account

`Get-Service` in Windows PowerShell 5.1 does not show the binary path or account. Use CIM:

```powershell
Get-CimInstance -ClassName Win32_Service |
    Select-Object Name, DisplayName, State, StartMode, StartName, PathName |
    Sort-Object Name
```

PowerShell 7 adds `BinaryPathName`, `UserName` and `StartupType` to `Get-Service`.

**What to look for**

- `PathName` in `C:\Users\`, `C:\ProgramData\`, `%TEMP%`, or `C:\Windows\Temp`
- `PathName` launching `cmd.exe /c`, `powershell.exe`, `rundll32.exe` or `mshta.exe`
- Random-looking service names, or names imitating real ones (`WindowsUpdateSvc`, `MicrosoftEdgeUpdater`)
- Auto-start services that are not running

## Inspect one service

```powershell
Get-CimInstance Win32_Service -Filter "Name = 'Spooler'" | Format-List *
```

**Windows CLI:**

```text
sc.exe qc Spooler
sc.exe query state= all
sc.exe sdshow Spooler
```

!!! warning "`sc` is not `sc.exe` in PowerShell"
    In Windows PowerShell 5.1, `sc` is an alias for `Set-Content`. Always type `sc.exe`. Note the space after `state=` — it is required.

## Registry location

```text
HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>
    ImagePath    binary and arguments
    Start        2 = Automatic, 3 = Manual, 4 = Disabled
    ObjectName   account the service runs as
    Parameters\ServiceDll   DLL for svchost-hosted services
```

```powershell
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Spooler' |
    Select-Object ImagePath, Start, ObjectName
```

An attacker can hijack an existing service by changing `ImagePath` or `ServiceDll` instead of creating a new one.

## Find recently installed services

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045 } -MaxEvents 50 |
    Select-Object TimeCreated, @{ Name = 'Service'; Expression = { $_.Properties[0].Value } },
                               @{ Name = 'ImagePath'; Expression = { $_.Properties[1].Value } },
                               @{ Name = 'Account'; Expression = { $_.Properties[4].Value } }
```

| Event | Log | Meaning |
| --- | --- | --- |
| 7045 | System | A service was installed (always logged) |
| 4697 | Security | A service was installed (requires *Audit Security System Extension*) |
| 7040 | System | Start type changed |
| 7036 | System | Service entered running/stopped state |

## Find unquoted service paths

An unquoted path with spaces lets an attacker who can write to a parent folder plant an executable (privilege escalation, [T1574.009](https://attack.mitre.org/techniques/T1574/009/)).

```powershell
Get-CimInstance Win32_Service |
    Where-Object { $_.PathName -and $_.PathName -notlike '"*' -and $_.PathName -match '^[^"]*\s[^"]*\.exe' } |
    Select-Object Name, StartMode, StartName, PathName
```

Each result is only exploitable if a parent folder in the path is writable by non-admins — check with [`icacls`](files-directories.md#check-file-and-folder-permissions).

## Stop and disable a service

```powershell
Stop-Service -Name 'BadSvc' -Force
Set-Service -Name 'BadSvc' -StartupType Disabled
```

Remove (after evidence collection): `sc.exe delete BadSvc`. PowerShell 7 also has `Remove-Service`.

## Related

- [Suspicious Service workflow](../../tasks/investigation/suspicious-service.md)
- [Linux services (systemd)](../linux/systemd.md)
- [SPL: new service installs](../../detection/spl/windows-events.md#new-service-installed-7045)
- [Sigma: service installation](../../detection/sigma/examples.md#suspicious-service-installation)

## Sources

- [Win32_Service class](https://learn.microsoft.com/windows/win32/cimwin32prov/win32-service)
- [sc.exe query](https://learn.microsoft.com/windows-server/administration/windows-commands/sc-query)
- [Event 4697](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697)

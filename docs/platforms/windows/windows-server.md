---
title: Windows Server Notes
platforms: [Windows Server]
languages: [PowerShell, Windows CLI]
tasks: [Administration, Incident Response, Troubleshooting]
category: System Information
tags: [windows server, roles, features, server core, domain controller, build numbers]
aliases: [Get-WindowsFeature, installed roles, server core, sconfig, domain controller logs]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Windows Server Notes

Everything in the Windows section applies to Windows Server. This page covers what is different.

## Build reference

| Release | Build |
| --- | --- |
| Windows Server 2016 | 14393 |
| Windows Server 2019 | 17763 |
| Windows Server 2022 | 20348 |
| Windows Server 2025 | 26100 |

## Installed roles and features

```powershell
Get-WindowsFeature | Where-Object Installed | Select-Object Name, DisplayName
```

`Get-WindowsFeature` / `Install-WindowsFeature` come from the **ServerManager** module and exist only on Windows Server. On Windows client use:

```powershell
Get-WindowsOptionalFeature -Online | Where-Object State -eq 'Enabled'
```

**Why it matters:** an unexpected IIS (`Web-Server`), Remote Access or Hyper-V role changes the attack surface of the server.

## Server Core

No desktop shell. Use `sconfig` for basic configuration and PowerShell / remote management (`Enter-PSSession`, Windows Admin Center, RSAT) for everything else.

## Domain controllers

Domain controllers hold the authoritative Kerberos and account-management events (4768, 4769, 4771, 4740, 4720, 4728…). See the [Event ID reference](../../references/windows-event-ids.md#kerberos-and-ntlm-domain-controllers).

Find the PDC emulator — account lockout (4740) events are logged there:

```powershell
Get-ADDomain | Select-Object PDCEmulator
```

Requires the ActiveDirectory module (RSAT). List DCs:

```powershell
Get-ADDomainController -Filter * | Select-Object HostName, Site, IPv4Address, OperatingSystem
```

## Prefetch is usually off

Prefetch (`C:\Windows\Prefetch`) is typically disabled on Windows Server, so execution evidence common on workstations may be absent. Rely on 4688, Sysmon, EDR telemetry and Amcache instead.

## Related

- [Windows Users and Groups](users-groups.md)
- [Hyper-V](../virtualization/hyper-v.md)

## Sources

- [Windows Server release information](https://learn.microsoft.com/windows/release-health/windows-server-release-info)
- [Get-WindowsFeature](https://learn.microsoft.com/powershell/module/servermanager/get-windowsfeature)

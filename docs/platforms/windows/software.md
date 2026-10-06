---
title: Windows Installed Software
platforms: [Windows, Windows Server]
languages: [PowerShell, Windows CLI]
tasks: [Investigation, Administration, Incident Response]
category: Software
tags: [installed software, uninstall registry, drivers, appx, winget, remote access tools]
aliases: [list installed programs, what is installed, add remove programs, Win32_Product, installed drivers]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Windows Installed Software

## List installed programs (registry — preferred)

```powershell
$paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue |
    Where-Object DisplayName |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation |
    Sort-Object DisplayName
```

`InstallDate` is a `yyyyMMdd` string when present. Per-user installs (common for remote-access tools and browsers) appear only under that user's `HKCU`.

!!! danger "Avoid `Win32_Product`"
    `Get-CimInstance Win32_Product` is slow and triggers a Windows Installer consistency check on every MSI package, which can start repairs. Use the registry method above.

## Recently installed (event log)

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'MsiInstaller'; Id = 11707, 1033 } -MaxEvents 50 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message
```

## Store (Appx) apps and winget

```powershell
Get-AppxPackage -AllUsers | Select-Object Name, Version, PackageFullName
```

```text
winget list
```

## Drivers

```powershell
Get-CimInstance Win32_SystemDriver | Where-Object State -eq 'Running' | Select-Object Name, PathName, StartMode
```

**Windows CLI:** `driverquery /v /fo csv`

Vulnerable signed drivers are used to disable EDR (*bring your own vulnerable driver*, [T1068](https://attack.mitre.org/techniques/T1068/)). Unexpected kernel drivers deserve a hash lookup.

## Remote access tools to hunt for

Commercial remote-access software is routinely abused for persistence ([T1219](https://attack.mitre.org/techniques/T1219/)):

```powershell
Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue |
    Where-Object DisplayName -match 'AnyDesk|TeamViewer|ScreenConnect|Atera|Splashtop|RustDesk|NetSupport|Remote Utilities|LogMeIn|ConnectWise' |
    Select-Object DisplayName, DisplayVersion, InstallDate, InstallLocation
```

Also check running processes and services for the same names — portable versions do not install.

## Related

- [Windows services](services.md)
- [Linux packages](../linux/packages.md)

## Sources

- [Win32_Product side effects (Microsoft)](https://learn.microsoft.com/troubleshoot/windows-server/admin-development/windows-installer-reconfigured-all-applications)
- [Uninstall registry key](https://learn.microsoft.com/windows/win32/msi/uninstall-registry-key)

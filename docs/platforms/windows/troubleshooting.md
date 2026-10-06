---
title: Windows Troubleshooting Commands
platforms: [Windows, Windows Server]
languages: [PowerShell, Windows CLI]
tasks: [Troubleshooting, Administration]
category: Troubleshooting
tags: [troubleshooting, reboot, group policy, time sync, sfc, dism, pending reboot, winrm]
aliases: [why did it reboot, unexpected shutdown, gpresult, w32tm, pending reboot, repair windows]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Windows Troubleshooting Commands

## Why did the machine restart?

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 1074, 6005, 6006, 6008, 41 } -MaxEvents 30 |
    Select-Object TimeCreated, Id, ProviderName, Message
```

| Event | Meaning |
| --- | --- |
| 1074 | Planned restart/shutdown — names the process and user |
| 6006 / 6005 | Event Log service stopped / started (clean shutdown / boot) |
| 6008 | Previous shutdown was unexpected |
| 41 (Kernel-Power) | Rebooted without cleanly shutting down (crash, power loss) |

## Pending reboot

```powershell
[pscustomobject]@{
    CBS             = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    WindowsUpdate   = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    FileRename      = $null -ne (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue)
}
```

## Group Policy

```text
gpresult /r                         summary of applied GPOs (user + computer)
gpresult /scope computer /r
gpresult /h C:\Temp\gp.html /f      full HTML report (elevated for computer settings)
gpupdate /force
```

## Time synchronisation

Kerberos fails when clocks drift more than 5 minutes (default) — a common cause of sudden authentication failures.

```text
w32tm /query /status
w32tm /query /source
w32tm /resync
```

## System file and image repair

```text
DISM /Online /Cleanup-Image /RestoreHealth
sfc /scannow
```

Run DISM first so SFC has a healthy component store to repair from. Logs: `C:\Windows\Logs\CBS\CBS.log`, `C:\Windows\Logs\DISM\dism.log`.

## Disk space

```powershell
Get-Volume | Where-Object DriveLetter |
    Select-Object DriveLetter, @{ n = 'FreeGB'; e = { [math]::Round($_.SizeRemaining / 1GB, 1) } }, @{ n = 'SizeGB'; e = { [math]::Round($_.Size / 1GB, 1) } }
```

## WinRM / PowerShell remoting

```powershell
Test-WSMan -ComputerName server01
Test-NetConnection -ComputerName server01 -Port 5985
```

Enable on a target (elevated): `Enable-PSRemoting -Force`.

## Certificates

```powershell
Get-ChildItem Cert:\LocalMachine\My | Select-Object Subject, NotAfter, Thumbprint | Sort-Object NotAfter
```

## Related

- [Windows Connectivity troubleshooting workflow](../../tasks/troubleshooting/windows-connectivity.md)
- [Windows event logs](event-logs.md)
- [Linux troubleshooting](../linux/troubleshooting.md)

## Sources

- [gpresult](https://learn.microsoft.com/windows-server/administration/windows-commands/gpresult)
- [w32tm](https://learn.microsoft.com/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings)
- [Repair a Windows image](https://learn.microsoft.com/windows-hardware/manufacture/desktop/repair-a-windows-image)

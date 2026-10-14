---
title: Windows Triage Cheat Sheet (Printable)
type: reference
platforms: [Windows]
languages: [PowerShell, Windows CLI]
tasks: [Incident Response, Investigation, Forensics]
category: Reference
tags: [windows, triage, cheat sheet, printable, incident response, powershell, live response]
aliases: [windows triage cheat sheet, windows ir cheat sheet, windows live response commands, printable windows triage]
difficulty: intermediate
verified: true
last_verified: 2026-10-13
search:
  boost: 3
---

# Windows Triage Cheat Sheet (Printable)

Live-response sheet for a suspect Windows host. The **Print** button gives one landscape sheet, printed on both sides.

!!! warning "Before you run anything"
    Commands were checked against Microsoft Learn (2026-10-13) and the read-only ones were run on a lab workstation.
    Run from an **elevated** PowerShell session, and collect before you change anything. Lines marked **change**
    alter the host. Full script: [Invoke-EndpointTriage.ps1](../toolbox/powershell.md#invoke-endpointtriage).

## 1. Host and users

```powershell
Get-CimInstance Win32_OperatingSystem | Select-Object CSName, Caption, Version, LastBootUpTime
quser                                   # who is logged on (console and RDP); not on Home editions
Get-LocalGroupMember -Group Administrators
Get-LocalUser | Where-Object Enabled | Select-Object Name, LastLogon, PasswordLastSet
```

New local admins, a recently set password, or a logon you cannot explain are the first leads.

## 2. Processes

```powershell
Get-CimInstance Win32_Process |
    Select-Object ProcessId, ParentProcessId, Name, CommandLine | Sort-Object ProcessId
Get-Process | Where-Object { $_.Path -and $_.Path -notmatch '^C:\\(Windows|Program Files)' } |
    Select-Object Id, ProcessName, Path
```

Look for Office or a browser as the parent of a shell, encoded command lines, and binaries in user-writable paths.

## 3. Network

```powershell
Get-NetTCPConnection -State Established, Listen |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess,
        @{N = 'Process'; E = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName }}
Get-DnsClientCache | Select-Object Entry, Data
```

Tie every outbound connection to a process; unknown listeners and connections to bare IPs come first.

## 4. Persistence

```powershell
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
                 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ScheduledTask | Where-Object TaskPath -notlike '\Microsoft\*' | Select-Object TaskPath, TaskName, State
Get-CimInstance Win32_Service | Where-Object PathName -notmatch 'C:\\Windows\\' |
    Select-Object Name, StartMode, State, PathName
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer   # WMI persistence
```

Deep dive: [Scheduled task persistence review](../tasks/threat-hunting/scheduled-task-persistence-review.md).

## 5. Event log quick hits (last 7 days)

```powershell
$since = (Get-Date).AddDays(-7)
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 1102, 4720, 4732, 4698; StartTime = $since } -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message
Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = $since } -ErrorAction SilentlyContinue
(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddDays(-1) } -ErrorAction SilentlyContinue).Count
```

**1102** log cleared · **4720 / 4732** user created / added to a local group · **4698 / 7045** scheduled task /
service installed · **4625** failed logons, counted for the last 24 hours.

## 6. Microsoft Defender

```powershell
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, IsTamperProtected, AntivirusSignatureLastUpdated
Get-MpThreatDetection | Select-Object InitialDetectionTime, ThreatID, ActionSuccess, Resources
(Get-MpPreference).ExclusionPath        # attacker-added exclusions hide their tools
```

## 7. Recent files in user-writable paths

```powershell
Get-ChildItem C:\Users\*\AppData, C:\ProgramData, C:\Windows\Temp -Recurse -File -ErrorAction SilentlyContinue `
    -Include *.exe, *.dll, *.ps1, *.bat, *.vbs |
    Where-Object LastWriteTime -gt (Get-Date).AddDays(-7) | Select-Object LastWriteTime, FullName
Get-FileHash -Algorithm SHA256 -Path '<FILE_PATH>'
```

## 8. Collect, then contain

```powershell
$case = "C:\IR\$env:COMPUTERNAME-$(Get-Date -Format yyyyMMddTHHmm)"
New-Item -ItemType Directory -Path $case | Out-Null
Get-CimInstance Win32_Process | Export-Csv "$case\processes.csv" -NoTypeInformation
Get-NetTCPConnection | Export-Csv "$case\connections.csv" -NoTypeInformation
wevtutil epl Security "$case\Security.evtx"
wevtutil epl System "$case\System.evtx"
# change: only after collection
Disable-LocalUser -Name '<USER>'
Stop-Process -Id <PID> -Force
```

Prefer your EDR's **isolate host** action over unplugging: it keeps the EDR connected and memory intact
([Memory acquisition](../tasks/forensics/memory-acquisition-analysis.md)).

## Sources

- [Microsoft Learn — Get-NetTCPConnection](https://learn.microsoft.com/powershell/module/nettcpip/get-nettcpconnection)
- [Microsoft Learn — Get-WinEvent](https://learn.microsoft.com/powershell/module/microsoft.powershell.diagnostics/get-winevent)
- [Microsoft Learn — Get-MpComputerStatus](https://learn.microsoft.com/powershell/module/defender/get-mpcomputerstatus)
- [Microsoft Learn — wevtutil](https://learn.microsoft.com/windows-server/administration/windows-commands/wevtutil)
- [Windows Event ID reference](windows-event-ids.md)

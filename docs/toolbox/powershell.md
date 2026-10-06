---
title: PowerShell Toolbox
type: tool
platforms: [Windows, Windows Server]
languages: [PowerShell]
tasks: [Automation, Incident Response, Forensics, Investigation]
category: Tools
tags: [toolbox, scripts, triage, persistence, logons, process tree, listening ports]
aliases: [powershell scripts, triage script, persistence script, Get-ListeningPorts, Get-ProcessTree, Invoke-EndpointTriage]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
---

# PowerShell Toolbox

Reusable scripts in `scripts/powershell/`. All of them:

- are **read-only** (the triage collector writes only to its output folder)
- run on **Windows PowerShell 5.1 and PowerShell 7** on Windows
- use `Set-StrictMode -Version Latest` and `$ErrorActionPreference = 'Stop'`
- return **objects**, so you can pipe to `Export-Csv`, `ConvertTo-Json`, `Out-GridView` or `Where-Object`
- include comment-based help: `Get-Help .\Script.ps1 -Full`

Every script is syntax-checked by the PowerShell parser (`python tools/cc.py code`) and linted with PSScriptAnalyzer in CI.

!!! note "Downloaded scripts"
    Files downloaded from the web are blocked by execution policy on many systems. After reviewing a script, run `Unblock-File .\Script.ps1`, or use `powershell.exe -ExecutionPolicy Bypass -File .\Script.ps1` for a single run.

## Get-ListeningPorts

**Problem it solves:** `Get-NetTCPConnection` shows the PID but not the binary, command line or owner — you need three commands to answer "what is listening and is it legitimate?".

| | |
| --- | --- |
| Inputs | `-IncludeUdp`, `-ExcludeLoopback` |
| Output | Protocol, LocalAddress, LocalPort, ProcessId, ProcessName, Path, CommandLine, Owner |
| Requirements | NetTCPIP module (Windows 8 / Server 2012 and later). Elevated for complete owner data. |

```powershell
.\Get-ListeningPorts.ps1 -ExcludeLoopback | Format-Table -AutoSize
.\Get-ListeningPorts.ps1 -IncludeUdp | Where-Object Path -match '\\Users\\|\\Temp\\'
```

Related: [Find listening ports](../platforms/windows/networking.md#find-listening-ports) · [Network Investigation](../tasks/investigation/network-investigation.md)

[Download Get-ListeningPorts.ps1](../../scripts/powershell/Get-ListeningPorts.ps1)

??? abstract "Source"

    ```powershell
    --8<-- "powershell/Get-ListeningPorts.ps1"
    ```

## Get-ProcessTree

**Problem it solves:** Windows has no built-in process tree command, and naive parent lookups are fooled by PID reuse.

| | |
| --- | --- |
| Inputs | `-ProcessId` (required), `-AsObject` |
| Output | Indented text tree (default) or objects: Depth, Relation, ProcessId, ParentProcessId, Name, CreationDate, ExecutablePath, CommandLine |
| Requirements | None beyond CIM. Elevated to see command lines of other users' processes. |

```powershell
.\Get-ProcessTree.ps1 -ProcessId 4321
.\Get-ProcessTree.ps1 -ProcessId 4321 -AsObject | Export-Csv tree.csv -NoTypeInformation
```

A parent is accepted only if it was created **before** the child, so a recycled PID is not shown as a false parent.

Related: [Process tree](../platforms/windows/processes.md#process-tree) · [Suspicious Process](../tasks/incident-response/suspicious-process.md)

[Download Get-ProcessTree.ps1](../../scripts/powershell/Get-ProcessTree.ps1)

??? abstract "Source"

    ```powershell
    --8<-- "powershell/Get-ProcessTree.ps1"
    ```

## Get-RecentLogons

**Problem it solves:** 4624/4625 events hide the useful fields in XML; this flattens them into one object per logon and filters machine/service noise.

| | |
| --- | --- |
| Inputs | `-Hours` (default 24), `-FailedOnly`, `-IncludeSystemLogons`, `-MaxEvents` |
| Output | Time, EventId, Outcome, User, Domain, LogonType, LogonTypeName, SourceIp, Workstation, Process, AuthPackage, Status, SubStatus |
| Requirements | Elevated session (Security log access) |

```powershell
.\Get-RecentLogons.ps1 -Hours 4 | Format-Table Time, Outcome, User, LogonTypeName, SourceIp
.\Get-RecentLogons.ps1 -FailedOnly -Hours 48 | Group-Object User, SourceIp | Sort-Object Count -Descending
```

**Security considerations:** output contains usernames and IPs — handle as case data.

Related: [Windows event logs](../platforms/windows/event-logs.md#extract-event-fields) · [Failed Authentication](../tasks/investigation/failed-authentication.md)

[Download Get-RecentLogons.ps1](../../scripts/powershell/Get-RecentLogons.ps1)

??? abstract "Source"

    ```powershell
    --8<-- "powershell/Get-RecentLogons.ps1"
    ```

## Get-PersistenceSnapshot

**Problem it solves:** a single fast pass over the most-abused autostart locations, with suspicious entries flagged.

| | |
| --- | --- |
| Coverage | Run/RunOnce (HKLM, WOW6432Node, every loaded user hive), Winlogon Shell/Userinit, IFEO debuggers, startup folders (all users), non-`\Microsoft\` scheduled tasks, auto-start services, WMI event consumers |
| Inputs | `-SuspiciousOnly` |
| Output | Category, Location, Name, Value, Flags |
| Flags | `UserWritablePath`, `ScriptHost`, `Encoded`, `Network`, `NonDefault`, `Debugger`, `WmiConsumer` |
| Requirements | Elevated session |

```powershell
.\Get-PersistenceSnapshot.ps1 -SuspiciousOnly | Format-Table Category, Name, Flags, Value -Wrap
```

Not a replacement for Sysinternals Autoruns — it checks far fewer locations, by design, to stay fast and dependency-free. Expect some flagged items to be legitimate (per-user updaters, management agents).

Related: [Registry Persistence](../tasks/investigation/registry-persistence.md) · [Windows registry](../platforms/windows/registry.md)

[Download Get-PersistenceSnapshot.ps1](../../scripts/powershell/Get-PersistenceSnapshot.ps1)

??? abstract "Source"

    ```powershell
    --8<-- "powershell/Get-PersistenceSnapshot.ps1"
    ```

## Invoke-EndpointTriage

**Problem it solves:** consistent, complete first-response collection in one command, in order of volatility, with a hash manifest for chain of custody.

| | |
| --- | --- |
| Inputs | `-OutputPath` (required), `-SkipEventLogs`, `-LogonHours` (default 72) |
| Output | Folder `HOST-yyyyMMdd-HHmmss` with CSVs (system, network, DNS cache, processes, sessions, accounts, logons, persistence, services, tasks, Defender status/exclusions/detections, hotfixes, software), `evtx\` exports, `collection-transcript.txt`, `manifest-sha256.csv` |
| Dependencies | Uses `Get-RecentLogons.ps1` and `Get-PersistenceSnapshot.ps1` from the same folder when present |
| Requirements | Elevated session |

```powershell
.\Invoke-EndpointTriage.ps1 -OutputPath D:\Cases\IR-2026-001 -Verbose
```

`-Verbose` shows per-artefact progress. The script returns the collection folder as its output.

Remote use — copy the folder to the target first so the companion scripts are found:

```powershell
$s = New-PSSession -ComputerName WS01
Copy-Item -Path .\scripts\powershell -Destination C:\Windows\Temp\cc -Recurse -ToSession $s
Invoke-Command -Session $s -ScriptBlock { & C:\Windows\Temp\cc\Invoke-EndpointTriage.ps1 -OutputPath C:\Windows\Temp\triage }
```

**Security considerations:** the collection contains command lines, usernames, IPs and full event logs — store it as evidence. Write to a different volume or share where possible, so the collection does not overwrite deleted-file evidence on the system drive.

Related: [Endpoint Triage](../tasks/incident-response/endpoint-triage.md)

[Download Invoke-EndpointTriage.ps1](../../scripts/powershell/Invoke-EndpointTriage.ps1)

??? abstract "Source"

    ```powershell
    --8<-- "powershell/Invoke-EndpointTriage.ps1"
    ```

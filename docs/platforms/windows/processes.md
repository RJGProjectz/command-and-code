---
title: Windows Processes
platforms: [Windows, Windows Server]
languages: [PowerShell, Windows CLI]
tasks: [Incident Response, Investigation, Troubleshooting, Forensics]
category: Processes
tags: [process, pid, parent process, command line, process tree, triage]
aliases: [find process by PID, tasklist, kill process, process command line, parent process]
difficulty: basic
verified: true
last_verified: 2026-10-05
search:
  boost: 2
---

# Windows Processes

Process questions come up in almost every investigation: *what is this PID, who started it, what was the command line, where is the binary, is it signed?*

!!! tip "Two sources of process data"
    `Get-Process` is fast but does not expose the **parent PID** or **command line** in Windows PowerShell 5.1.
    `Get-CimInstance Win32_Process` exposes both and works in 5.1 and 7. Use CIM for investigation.

## List running processes

```powershell
Get-Process |
    Sort-Object CPU -Descending |
    Select-Object -First 20 Name, Id, CPU, WorkingSet64, Path
```

| Property | Meaning |
| --- | --- |
| `CPU` | Total processor seconds used since start (not current %) |
| `WorkingSet64` | Physical memory in bytes |
| `Path` | Executable path — empty for protected/system processes unless elevated |

Add the owner (requires an elevated session):

```powershell
Get-Process -IncludeUserName | Select-Object Name, Id, UserName, Path
```

**Windows CLI:** `tasklist /v` (with user and window title), `tasklist /svc` (services hosted in each process).

## Find a process by PID

```powershell
$TargetPid = 1234
Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $TargetPid" |
    Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate
```

!!! warning "Do not name your variable `$pid`"
    `$PID` is a read-only automatic variable (the current PowerShell process ID). Variable names are case-insensitive, so `$pid = 1234` fails. Use `$TargetPid` or `$ProcessId`.

PowerShell 7+ also exposes `Parent` and `CommandLine` on `Get-Process`:

```powershell
Get-Process -Id 1234 | Select-Object Id, Name, Path, CommandLine, @{ Name = 'ParentId'; Expression = { $_.Parent.Id } }
```

## Find the parent process

```powershell
$TargetPid = 1234
$child  = Get-CimInstance Win32_Process -Filter "ProcessId = $TargetPid"
$parent = Get-CimInstance Win32_Process -Filter "ProcessId = $($child.ParentProcessId)"
$parent | Select-Object ProcessId, Name, ExecutablePath, CommandLine, CreationDate
```

**Why it matters:** suspicious parent/child pairs are among the highest-value signals on an endpoint — for example `winword.exe → powershell.exe`, `w3wp.exe → cmd.exe`, `services.exe → cmd.exe`.

!!! note "PID reuse"
    If the parent has exited, Windows may have reused its PID for an unrelated process. Compare `CreationDate`: a real parent must be **older** than the child.

## Process tree

Show a process and every descendant:

```powershell
function Show-ProcessTree {
    param([int]$RootId, [int]$Depth = 0, [object[]]$All = (Get-CimInstance Win32_Process))
    $node = $All | Where-Object ProcessId -eq $RootId
    if ($node) { '{0}{1} ({2})  {3}' -f ('  ' * $Depth), $node.Name, $node.ProcessId, $node.CommandLine }
    foreach ($child in ($All | Where-Object { $_.ParentProcessId -eq $RootId -and $_.ProcessId -ne $RootId })) {
        Show-ProcessTree -RootId $child.ProcessId -Depth ($Depth + 1) -All $All
    }
}
Show-ProcessTree -RootId 1234
```

For a reusable version with ancestors, PID-reuse protection and object output, use [`Get-ProcessTree.ps1`](../../toolbox/powershell.md#get-processtree).

## Find processes by name with command line

```powershell
Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe' OR Name = 'pwsh.exe'" |
    Select-Object ProcessId, ParentProcessId, CreationDate, CommandLine
```

WQL `-Filter` uses `=`, `AND`, `OR` and `LIKE` with `%` wildcards — not PowerShell operators:

```powershell
Get-CimInstance Win32_Process -Filter "CommandLine LIKE '%-enc%'"
```

## Find the process that owns a port

```powershell
$port = 443
Get-NetTCPConnection -LocalPort $port -State Listen |
    ForEach-Object { Get-Process -Id $_.OwningProcess } |
    Select-Object Id, Name, Path
```

See [Windows Networking](networking.md#find-listening-ports) for full connection listings.

## Find the process owner

```powershell
$proc = Get-CimInstance Win32_Process -Filter "ProcessId = 1234"
Invoke-CimMethod -InputObject $proc -MethodName GetOwner | Select-Object Domain, User
```

## Check the binary: hash and signature

```powershell
$path = (Get-CimInstance Win32_Process -Filter "ProcessId = 1234").ExecutablePath
Get-FileHash -Path $path -Algorithm SHA256
Get-AuthenticodeSignature -FilePath $path | Select-Object Status, SignerCertificate
```

**What to look for:** `Status` other than `Valid`, unsigned binaries in `C:\Users\`, `C:\ProgramData\`, `%TEMP%`, or Microsoft-named binaries (`svchost.exe`, `lsass.exe`) running from anywhere other than `C:\Windows\System32\`.

## List loaded modules (DLLs)

```powershell
(Get-Process -Id 1234).Modules | Select-Object ModuleName, FileName
```

Look for DLLs loaded from user-writable paths — a common side-loading indicator. 32-bit processes viewed from 64-bit PowerShell show a partial list.

## Stop a process

```powershell
Stop-Process -Id 1234 -Force
```

**Windows CLI:** `taskkill /PID 1234 /F /T` — `/T` also kills child processes.

!!! danger "Collect before you kill"
    Capture the command line, parent, path, hash and network connections first. Killing the process destroys volatile evidence. In an EDR-managed fleet prefer the EDR's kill/quarantine action so the action is logged.

## Related

- [Suspicious Process workflow](../../tasks/incident-response/suspicious-process.md)
- [Suspicious PowerShell workflow](../../tasks/incident-response/suspicious-powershell.md)
- [KQL process events](../../detection/kql/process-events.md)
- [Linux processes](../linux/processes.md)

## Sources

- [Get-CimInstance](https://learn.microsoft.com/powershell/module/cimcmdlets/get-ciminstance)
- [Win32_Process class](https://learn.microsoft.com/windows/win32/cimwin32prov/win32-process)
- [about_Automatic_Variables ($PID)](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_automatic_variables)

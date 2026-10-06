---
title: Windows Event Logs
platforms: [Windows, Windows Server]
languages: [PowerShell, Windows CLI]
tasks: [Incident Response, Investigation, Forensics, Hardening]
category: Logging
tags: [event logs, get-winevent, wevtutil, audit policy, 4624, 4625, 4688, 4104, evtx]
aliases: [failed windows login, Get-WinEvent, event viewer, read evtx, audit policy, command line logging, script block logging]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
search:
  boost: 2
---

# Windows Event Logs

The Windows event logs are the primary local record of authentication, process, service and PowerShell activity — **if** the right auditing is enabled. Event ID meanings are in the [Windows Event ID reference](../../references/windows-event-ids.md).

## Query events efficiently

Always filter with `-FilterHashtable` (or `-FilterXPath`). Piping everything to `Where-Object` reads the whole log and is dramatically slower.

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625
    StartTime = (Get-Date).AddHours(-24)
} -MaxEvents 200
```

Valid hashtable keys include `LogName`, `ProviderName`, `Path`, `Id`, `Level`, `StartTime`, `EndTime`, `UserID` and `Data`. `Id` accepts an array: `Id = 4624, 4625`.

!!! note "No events found is an error"
    `Get-WinEvent` throws `No events were found that match the specified selection criteria` when nothing matches. Add `-ErrorAction SilentlyContinue` in scripts.

## Extract event fields

`Message` is text for humans. For automation, read the named `EventData` fields from the XML:

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddDays(-1) } |
    ForEach-Object {
        $data = @{}
        foreach ($d in ([xml]$_.ToXml()).Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
        [pscustomobject]@{
            Time        = $_.TimeCreated
            User        = $data.TargetUserName
            Domain      = $data.TargetDomainName
            SourceIp    = $data.IpAddress
            Workstation = $data.WorkstationName
            LogonType   = $data.LogonType
            Status      = $data.Status
            SubStatus   = $data.SubStatus
        }
    }
```

Reusable tool: [`Get-RecentLogons.ps1`](../../toolbox/powershell.md#get-recentlogons).

## Failed logons summary

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddDays(-1) } -ErrorAction SilentlyContinue |
    ForEach-Object {
        $x = [xml]$_.ToXml()
        $d = @{}; foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
        [pscustomobject]@{ User = $d.TargetUserName; SourceIp = $d.IpAddress }
    } |
    Group-Object User, SourceIp | Sort-Object Count -Descending |
    Select-Object Count, Name -First 20
```

Common 4625 `SubStatus` codes: `0xC000006A` bad password, `0xC0000064` user does not exist, `0xC0000234` account locked, `0xC0000072` account disabled, `0xC0000193` account expired.

## Filter on event data with XPath

RDP (logon type 10) successes:

```powershell
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4624)]] and *[EventData[Data[@Name='LogonType']='10']]" -MaxEvents 50
```

## Read an exported .evtx file

```powershell
Get-WinEvent -Path 'C:\Cases\HOST01\Security.evtx' -FilterXPath "*[System[(EventID=4624)]]"
```

`-FilterHashtable` also accepts `Path = 'C:\Cases\Security.evtx'`.

## Export and inspect logs (wevtutil)

```text
wevtutil el                                        list all logs
wevtutil gli Security                              size, record count, last write
wevtutil epl Security C:\Cases\HOST01-Security.evtx    export (preserves the original)
wevtutil qe Security /q:"*[System[(EventID=4624)]]" /c:10 /rd:true /f:text
wevtutil sl Security /ms:1073741824                set max size to 1 GB
```

Export **before** remediation. Copying `C:\Windows\System32\winevt\Logs\*.evtx` directly also works from an elevated prompt.

## Detect log clearing

| Event | Log | Meaning |
| --- | --- | --- |
| 1102 | Security | The audit log was cleared |
| 104 | System | An event log was cleared |

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 1102 } -ErrorAction SilentlyContinue
Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 104 } -ErrorAction SilentlyContinue
```

## Check the audit policy

```text
auditpol /get /category:*
auditpol /get /subcategory:"Process Creation"
```

If `Process Creation` shows `No Auditing`, there are no 4688 events. Advanced audit policy in GPO:
`Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration`.

## Enable command-line capture in 4688

=== "GPO"

    ```text
    Computer Configuration
    → Administrative Templates
    → System
    → Audit Process Creation
    → Include command line in process creation events = Enabled
    ```

=== "Registry"

    ```text
    HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit
        ProcessCreationIncludeCmdLine_Enabled  (DWORD) = 1
    ```

Command lines can contain secrets typed on the command line — treat 4688 data accordingly.

## Enable PowerShell script block logging

=== "GPO"

    ```text
    Computer Configuration
    → Administrative Templates
    → Windows Components
    → Windows PowerShell
    → Turn on PowerShell Script Block Logging = Enabled
    ```

=== "Registry"

    ```text
    HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
        EnableScriptBlockLogging  (DWORD) = 1
    ```

Events land in `Microsoft-Windows-PowerShell/Operational` as **4104**. PowerShell 7 logs to `PowerShellCore/Operational` and has its own policy under `Administrative Templates → PowerShell Core` (installed with PowerShell 7's ADMX).

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104 } -MaxEvents 50 |
    Select-Object TimeCreated, @{ Name = 'ScriptBlock'; Expression = { $_.Properties[2].Value } }
```

Even without the policy, PowerShell logs script blocks it considers suspicious as 4104 with level *Warning*.

## Related

- [Windows Event ID reference](../../references/windows-event-ids.md)
- [Failed Authentication workflow](../../tasks/investigation/failed-authentication.md)
- [SPL: Windows security events](../../detection/spl/windows-events.md)
- [Linux logs](../linux/logs.md)

## Sources

- [Get-WinEvent](https://learn.microsoft.com/powershell/module/microsoft.powershell.diagnostics/get-winevent)
- [Command line process auditing](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)
- [about_Logging_Windows](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows)
- [Event 4625](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)

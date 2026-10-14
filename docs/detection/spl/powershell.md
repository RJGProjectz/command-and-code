---
title: SPL PowerShell Hunting
platforms: [Splunk, Windows]
languages: [SPL]
tasks: [Threat Hunting, Detection Engineering, Incident Response]
category: Process Execution
tags: [spl, powershell, 4104, script block logging, encoded command, sysmon]
aliases: [suspicious powershell splunk, 4104 splunk, script block splunk, encoded powershell splunk]
difficulty: intermediate
verified: true
last_verified: 2026-10-13
---

# SPL PowerShell Hunting

!!! warning "Before you deploy"
    Fields were checked (2026-10-13) against Microsoft Learn (about_Logging_Windows, Sysmon) and Atomic Red Team;
    not run against a live index. Assumes `index=wineventlog` and XML-rendered events from the Splunk Add-on for Microsoft Windows. Sysmon examples assume `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"` with the Splunk Add-on for Sysmon. Confirm index, source and field names in your environment.

## Suspicious script blocks (4104)

Requires [script block logging](../../platforms/windows/event-logs.md#enable-powershell-script-block-logging).

```spl
index=wineventlog source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
    (ScriptBlockText="*FromBase64String*" OR ScriptBlockText="*DownloadString*" OR ScriptBlockText="*Invoke-Expression*"
     OR ScriptBlockText="*IEX*" OR ScriptBlockText="*Net.WebClient*" OR ScriptBlockText="*-bxor*"
     OR ScriptBlockText="*VirtualAlloc*" OR ScriptBlockText="*AmsiUtils*")
| table _time, host, Path, ScriptBlockText
```

Large scripts are split across several 4104 events sharing a `ScriptBlockId`. Reassemble them:

```spl
index=wineventlog source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 ScriptBlockId="<id>"
| sort 0 MessageNumber
| stats list(ScriptBlockText) AS script BY ScriptBlockId
| eval script = mvjoin(script, "")
```

## Encoded commands (process creation)

```spl
index=wineventlog (source="XmlWinEventLog:Security" EventCode=4688) OR (source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
| eval image = coalesce(NewProcessName, Image), cmd = coalesce(CommandLine, process)
| where match(image, "(?i)\\\\(powershell|pwsh)\.exe$") AND match(cmd, "(?i)\s[-/]e[a-z]*\s+[a-z0-9+/=]{20,}")
| table _time, host, image, cmd
```

## PowerShell with network connections (Sysmon event 3)

```spl
index=wineventlog source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
    (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| stats count, values(DestinationPort) AS ports BY host, User, DestinationIp
| sort - count
```

## Downgrade to PowerShell 2.0

Version 2.0 bypasses script block logging and AMSI. Microsoft removed it from Windows 11 24H2 and Windows Server 2025
(KB5065506, from August/September 2025), where `powershell -Version 2` starts 5.1 instead; older builds with the
optional feature still installed remain exposed. Windows PowerShell log event 400 records the engine version:

```spl
index=wineventlog source="XmlWinEventLog:Windows PowerShell" EventCode=400
| rex field=_raw "EngineVersion=(?<engine_version>[\d\.]+)"
| where like(engine_version, "2.%")
| table _time, host, engine_version
```

## Test it

| Query | Atomic Red Team test |
| --- | --- |
| Suspicious script blocks | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) *PowerShell Invoke Known Malicious Cmdlets* |
| Encoded commands | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) *ATHPowerShellCommandLineParameter -EncodedCommand parameter variations* |
| PowerShell network connections | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) *Windows - PowerShell Download* |
| Downgrade to 2.0 | [T1689](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1689/T1689.md) *PowerShell Version 2 Downgrade* (fires only where the 2.0 engine is still installed) |

## Related

- [Suspicious PowerShell workflow](../../tasks/incident-response/suspicious-powershell.md)
- [KQL process events](../kql/process-events.md#encoded-powershell)
- [Sigma: encoded PowerShell](../sigma/examples.md#encoded-powershell-command-line)

## Sources

- [about_Logging_Windows](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows)
- [Splunk Add-on for Sysmon](https://docs.splunk.com/Documentation/AddOns/released/MSSysmon/About)
- [Microsoft Support — PowerShell 2.0 removal from Windows (KB5065506)](https://support.microsoft.com/help/5065506)

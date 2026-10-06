---
title: SPL PowerShell Hunting
platforms: [Splunk, Windows]
languages: [SPL]
tasks: [Threat Hunting, Detection Engineering, Incident Response]
category: Process Execution
tags: [spl, powershell, 4104, script block logging, encoded command, sysmon]
aliases: [suspicious powershell splunk, 4104 splunk, script block splunk, encoded powershell splunk]
difficulty: intermediate
verified: false
---

# SPL PowerShell Hunting

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Assumes `index=wineventlog` and XML-rendered events from the Splunk Add-on for Microsoft Windows. Sysmon examples assume `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"` with the Splunk Add-on for Sysmon. Confirm index, source and field names in your environment.

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

Version 2.0 bypasses script block logging and AMSI. Windows PowerShell log event 400 records the engine version:

```spl
index=wineventlog source="XmlWinEventLog:Windows PowerShell" EventCode=400
| rex field=_raw "EngineVersion=(?<engine_version>[\d\.]+)"
| where like(engine_version, "2.%")
| table _time, host, engine_version
```

## Related

- [Suspicious PowerShell workflow](../../tasks/incident-response/suspicious-powershell.md)
- [KQL process events](../kql/process-events.md#encoded-powershell)
- [Sigma: encoded PowerShell](../sigma/examples.md#encoded-powershell-command-line)

## Sources

- [about_Logging_Windows](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows)
- [Splunk Add-on for Sysmon](https://docs.splunk.com/Documentation/AddOns/released/MSSysmon/About)

---
title: SPL Windows Security Events
platforms: [Splunk, Windows]
languages: [SPL]
tasks: [Threat Hunting, Detection Engineering, Investigation, Incident Response]
category: Authentication
tags: [spl, windows events, 4625, 4624, 4688, 7045, 4698, 1102, defender, authentication]
aliases: [failed windows login splunk, brute force splunk, new service splunk, scheduled task splunk, log cleared splunk]
difficulty: intermediate
verified: true
last_verified: 2026-10-13
---

# SPL Windows Security Events

!!! warning "Before you deploy"
    Event fields were checked (2026-10-13) against the Microsoft Learn event reference and the Splunk Add-on for
    Microsoft Windows; not run against a live index. SPL syntax here is standard, but **index names, sourcetypes and field names depend on your Splunk Add-on for Microsoft Windows configuration**. Examples assume `index=wineventlog`, XML rendering (`sourcetype=XmlWinEventLog`, `source=XmlWinEventLog:Security`) and XML field names such as `TargetUserName`. With classic rendering (`sourcetype=WinEventLog`) fields are named differently (e.g. `Account_Name`, `Source_Network_Address`). Run `| fieldsummary` on a sample to confirm.

## Failed logons (4625)

```spl
index=wineventlog source="XmlWinEventLog:Security" EventCode=4625 earliest=-24h
| stats count AS failures, dc(TargetUserName) AS users, values(TargetUserName) AS user_list BY IpAddress
| where failures > 20
| sort - failures
```

`users` high with one `IpAddress` = password spray; `failures` high for one user = brute force.

## Successful logon after failures

```spl
index=wineventlog source="XmlWinEventLog:Security" (EventCode=4625 OR EventCode=4624) earliest=-24h
| eval outcome = if(EventCode==4624, "success", "failure")
| stats count(eval(outcome="failure")) AS failures, count(eval(outcome="success")) AS successes,
        latest(_time) AS last_seen BY TargetUserName, IpAddress
| where failures >= 5 AND successes > 0
| convert ctime(last_seen)
```

## RDP logons (4624, LogonType 10)

```spl
index=wineventlog source="XmlWinEventLog:Security" EventCode=4624 LogonType=10
| stats count, earliest(_time) AS first, latest(_time) AS last BY host, TargetUserName, IpAddress
| convert ctime(first) ctime(last)
```

## Process creation (4688)

Requires *Audit Process Creation* and [command-line logging](../../platforms/windows/event-logs.md#enable-command-line-capture-in-4688).

```spl
index=wineventlog source="XmlWinEventLog:Security" EventCode=4688
    (NewProcessName="*\\powershell.exe" OR NewProcessName="*\\cmd.exe")
    ParentProcessName IN ("*\\winword.exe", "*\\excel.exe", "*\\outlook.exe")
| table _time, host, SubjectUserName, ParentProcessName, NewProcessName, CommandLine
```

## New service installed (7045)

```spl
index=wineventlog source="XmlWinEventLog:System" EventCode=7045
| table _time, host, ServiceName, ImagePath, ServiceType, StartType, AccountName
| search ImagePath="*\\Users\\*" OR ImagePath="*\\Temp\\*" OR ImagePath="*powershell*" OR ImagePath="*cmd.exe*"
```

Remove the final `search` line to see every new service.

## Scheduled task created (4698)

```spl
index=wineventlog source="XmlWinEventLog:Security" EventCode=4698
| rex field=TaskContent "(?:<|&lt;)Command(?:>|&gt;)(?<task_command>[^<&]+)"
| rex field=TaskContent "(?:<|&lt;)Arguments(?:>|&gt;)(?<task_args>[^<&]+)"
| table _time, host, SubjectUserName, TaskName, task_command, task_args
```

## Account and group changes

```spl
index=wineventlog source="XmlWinEventLog:Security" EventCode IN (4720, 4722, 4724, 4728, 4732, 4756)
| table _time, host, EventCode, SubjectUserName, TargetUserName, MemberName
```

## Log cleared (1102 / 104)

```spl
index=wineventlog (source="XmlWinEventLog:Security" EventCode=1102) OR (source="XmlWinEventLog:System" EventCode=104)
| table _time, host, EventCode, SubjectUserName
```

`TaskContent` is the task XML embedded in the event; depending on the add-on version it arrives with its tags
escaped (`&lt;Command&gt;`), so the patterns accept both forms.

## Microsoft Defender Antivirus events

From the Windows event log (requires the `Microsoft-Windows-Windows Defender/Operational` channel in your inputs):

```spl
index=wineventlog source="XmlWinEventLog:Microsoft-Windows-Windows Defender/Operational" EventCode IN (1116, 1117, 5001, 5007, 5013)
| table _time, host, EventCode, Threat_Name, Path, Process_Name, Detection_User
```

Defender field names in this channel vary with add-on version — inspect a raw event first.

## Test it

Each query has an Atomic Red Team test that produces the event on a lab host:

| Query | Atomic Red Team test |
| --- | --- |
| Failed logons, success after failures | [T1110.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.001/T1110.001.md) *Brute Force Credentials of single Active Directory domain users via SMB*; [T1110.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.003/T1110.003.md) *Password Spray all Domain Users* |
| RDP logons | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) *RDP to Remote Host* |
| Process creation from Office | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) *Word spawned a command shell and used an IP address in the command line* |
| New service (7045) | [T1543.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md) *Service Installation CMD* |
| Scheduled task (4698) | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) *Scheduled task Local* |
| Account and group changes | [T1136.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.001/T1136.001.md) *Create a new user in a command prompt*; [T1098](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098) *Domain Account and Group Manipulate* |
| Log cleared | [T1685.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685.005/T1685.005.md) *Clear Logs* |
| Defender events | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) *Tamper with Windows Defender Command Prompt* (5001) |

Run them in a lab domain only, and run each test's cleanup command afterwards.

## Related

- [Windows Event ID reference](../../references/windows-event-ids.md)
- [KQL logon hunting](../kql/logon-identity.md)
- [Windows event logs](../../platforms/windows/event-logs.md)

## Sources

- [Splunk Add-on for Microsoft Windows](https://docs.splunk.com/Documentation/WindowsAddOn/latest/User/AbouttheSplunkAdd-onforWindows)
- [Event 4625](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [Event 4698](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698)
- [Event 4688](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688)
- [Event 1102](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [Microsoft Defender Antivirus event IDs](https://learn.microsoft.com/defender-endpoint/troubleshoot-microsoft-defender-antivirus)

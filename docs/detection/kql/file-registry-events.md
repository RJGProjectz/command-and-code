---
title: KQL File, Registry and Persistence Hunting
platforms: [Microsoft Defender, Windows]
languages: [KQL]
tasks: [Threat Hunting, Detection Engineering, Investigation]
category: Persistence
tags: [kql, devicefileevents, deviceregistryevents, deviceevents, run keys, scheduled tasks, services]
aliases: [run key kql, registry persistence kql, scheduled task created kql, service installed kql, file dropped kql]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
---

# KQL File, Registry and Persistence Hunting

## Executables written to user-writable paths

Table: **`DeviceFileEvents`** (`ActionType`: `FileCreated`, `FileModified`, `FileRenamed`, `FileDeleted`).

```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileCreated", "FileRenamed")
| where FileName matches regex @"(?i)\.(exe|dll|ps1|hta|js|vbs)$"
| where FolderPath has_any (@"\AppData\", @"\Users\Public\", @"\ProgramData\", @"\Windows\Temp\")
| project Timestamp, DeviceName, ActionType, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## Run key modifications

Table: **`DeviceRegistryEvents`**. `RegistryKey` values start with the full hive name (`HKEY_LOCAL_MACHINE\…`, `HKEY_CURRENT_USER\…`).

```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce", @"\Policies\Explorer\Run")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

`has_any` on `\CurrentVersion\Run` also matches `RunOnce` and `RunOnceEx`. MITRE: [T1547.001](https://attack.mitre.org/techniques/T1547/001/). Endpoint view: [Windows registry](../../platforms/windows/registry.md#common-autostart-locations).

## Winlogon and IFEO tampering

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType == "RegistryValueSet"
| where (RegistryKey endswith @"\Windows NT\CurrentVersion\Winlogon" and RegistryValueName in~ ("Shell", "Userinit"))
     or (RegistryKey has @"\Image File Execution Options\" and RegistryValueName =~ "Debugger")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
```

## Scheduled task creation

```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "ScheduledTaskCreated"
| extend Fields = parse_json(AdditionalFields)
| extend TaskName = tostring(Fields.TaskName), TaskContent = tostring(Fields.TaskContent)
| project Timestamp, DeviceName, TaskName, TaskContent, InitiatingProcessFileName, InitiatingProcessAccountName
```

`TaskContent` holds the task XML — search it for `powershell`, `cmd.exe /c`, `\AppData\`, `http`. Process-based alternative (catches `schtasks /create` with arguments):

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "schtasks.exe" and ProcessCommandLine has "/create"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

MITRE: [T1053.005](https://attack.mitre.org/techniques/T1053/005/).

## Service installation

```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "ServiceInstalled"
| extend Fields = parse_json(AdditionalFields)
| project Timestamp, DeviceName, ServiceName = tostring(Fields.ServiceName), FolderPath, FileName,
          InitiatingProcessFileName, AdditionalFields
```

Check the `AdditionalFields` keys in your tenant (`take 10`) — the set of fields has changed across sensor versions. Registry-based alternative:

```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has @"\SYSTEM\ControlSet001\Services\" and RegistryValueName =~ "ImagePath"
| project Timestamp, DeviceName, RegistryKey, RegistryValueData, InitiatingProcessFileName
```

MITRE: [T1543.003](https://attack.mitre.org/techniques/T1543/003/).

## Defender exclusion added

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has @"\Windows Defender\Exclusions\"
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## Related

- [Registry Persistence workflow](../../tasks/investigation/registry-persistence.md)
- [Scheduled Task Investigation workflow](../../tasks/investigation/scheduled-task-investigation.md)
- [Suspicious Service workflow](../../tasks/investigation/suspicious-service.md)

## Sources

- [DeviceRegistryEvents table](https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceregistryevents-table)
- [DeviceFileEvents table](https://learn.microsoft.com/defender-xdr/advanced-hunting-devicefileevents-table)
- [DeviceEvents table](https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceevents-table)

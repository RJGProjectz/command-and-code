---
title: Windows Scheduled Tasks
platforms: [Windows, Windows Server]
languages: [PowerShell, Windows CLI]
tasks: [Incident Response, Investigation, Threat Hunting, Administration]
category: Persistence
tags: [scheduled tasks, schtasks, persistence, 4698, task scheduler]
aliases: [scheduled task persistence, schtasks query, list scheduled tasks, hidden scheduled task]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
---

# Windows Scheduled Tasks

Scheduled tasks are one of the most common persistence and execution mechanisms ([T1053.005](https://attack.mitre.org/techniques/T1053/005/)).

## List tasks with their actions

```powershell
Get-ScheduledTask |
    Where-Object State -ne 'Disabled' |
    ForEach-Object {
        foreach ($action in $_.Actions) {
            [pscustomobject]@{
                Task      = $_.TaskPath + $_.TaskName
                State     = $_.State
                Author    = $_.Author
                RunAs     = $_.Principal.UserId
                Execute   = $action.Execute
                Arguments = $action.Arguments
            }
        }
    } | Sort-Object Task
```

Exclude built-in Microsoft tasks to shrink the list (attackers do place tasks under `\Microsoft\`, so check that path separately when hunting):

```powershell
Get-ScheduledTask | Where-Object TaskPath -notlike '\Microsoft\*'
```

**What to look for:** actions running `powershell.exe`, `cmd.exe /c`, `mshta.exe`, `rundll32.exe`, binaries in user-writable folders, tasks running as `SYSTEM` created by non-admin authors, names imitating legitimate updaters.

## Last and next run time

```powershell
Get-ScheduledTask -TaskPath '\' | Get-ScheduledTaskInfo |
    Select-Object TaskName, LastRunTime, LastTaskResult, NextRunTime
```

`LastTaskResult` 0 = success; `267011` (0x41303) = has not yet run.

## schtasks.exe

```text
schtasks /query /fo LIST /v
schtasks /query /tn "\TaskName" /xml
schtasks /query /fo CSV /v > C:\Cases\tasks.csv
```

`/xml` output shows triggers, actions, principal and settings exactly as stored.

## Where tasks are stored

| Location | Contents |
| --- | --- |
| `C:\Windows\System32\Tasks\` | One XML file per task |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\` | Task names/paths, security descriptor (`SD`) |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{GUID}` | Actions, triggers, metadata |

!!! warning "Hidden tasks"
    Deleting the `SD` value under `TaskCache\Tree\<task>` hides a task from `schtasks` and `Get-ScheduledTask` while it keeps running (technique publicised by Microsoft as *Tarrask*, 2022). Compare the `Tree` registry keys against `Get-ScheduledTask` output when hunting.

```powershell
Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree' -Recurse |
    Where-Object { $null -eq $_.GetValue('SD') -and $_.GetValue('Id') } |
    Select-Object Name
```

## Events

| Event | Log | Meaning |
| --- | --- | --- |
| 4698 / 4699 / 4702 | Security | Task created / deleted / updated (requires *Audit Other Object Access Events*) |
| 4700 / 4701 | Security | Task enabled / disabled |
| 106 | Microsoft-Windows-TaskScheduler/Operational | Task registered |
| 140 / 141 | TaskScheduler/Operational | Task updated / deleted |
| 200 / 201 | TaskScheduler/Operational | Action started / completed |

The TaskScheduler Operational log may be disabled; enable it with `wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true`.

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4698 } -MaxEvents 20 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, @{ Name = 'Task'; Expression = { ([xml]$_.ToXml()).Event.EventData.Data | Where-Object Name -eq 'TaskName' | Select-Object -ExpandProperty '#text' } }
```

## Disable or remove a task

```powershell
Disable-ScheduledTask -TaskPath '\' -TaskName 'BadTask'
Export-ScheduledTask -TaskPath '\' -TaskName 'BadTask' | Out-File C:\Cases\BadTask.xml
Unregister-ScheduledTask -TaskPath '\' -TaskName 'BadTask' -Confirm:$false
```

Disable and export before deleting so the definition is preserved as evidence.

## Related

- [Scheduled Task Investigation workflow](../../tasks/investigation/scheduled-task-investigation.md)
- [Linux cron and timers](../linux/cron.md)
- [KQL: scheduled task creation](../../detection/kql/file-registry-events.md#scheduled-task-creation)
- [SPL: scheduled task created](../../detection/spl/windows-events.md#scheduled-task-created-4698)

## Sources

- [Get-ScheduledTask](https://learn.microsoft.com/powershell/module/scheduledtasks/get-scheduledtask)
- [schtasks query](https://learn.microsoft.com/windows-server/administration/windows-commands/schtasks-query)
- [Tarrask malware uses scheduled tasks for defense evasion (Microsoft)](https://www.microsoft.com/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/)

---
title: Scheduled Task Investigation
type: workflow
platforms: [Windows, Microsoft Defender, Splunk, SentinelOne]
languages: [PowerShell, Windows CLI, KQL, SPL, S1QL]
tasks: [Investigation, Incident Response, Threat Hunting]
category: Workflow
tags: [workflow, scheduled tasks, persistence, 4698]
aliases: [scheduled task persistence, suspicious scheduled task, malicious task, schtasks alert]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
---

# Scheduled Task Investigation

**Trigger:** event 4698/106, EDR "scheduled task created" alert, or an unfamiliar task during triage.

## 1. Get the full definition

Actions, arguments, triggers, principal (run-as account), author, creation date.

```text
schtasks /query /tn "\TaskName" /xml
```

→ [List tasks with their actions](../../platforms/windows/scheduled-tasks.md#list-tasks-with-their-actions) · [schtasks.exe](../../platforms/windows/scheduled-tasks.md#schtasksexe)

## 2. Assess the action

Script interpreters, encoded commands, user-writable paths, LOLBins, remote URLs. A task running every few minutes as `SYSTEM` with a hidden window is a strong indicator.

## 3. Check for hiding

Tasks with no `SD` value are hidden from normal tooling.

→ [Hidden tasks](../../platforms/windows/scheduled-tasks.md#where-tasks-are-stored)

## 4. Who created it, and when?

→ [Task events](../../platforms/windows/scheduled-tasks.md#events) — 4698 includes the creating account and the task XML. Remote creation shows a preceding network logon from another host.

## 5. What did it run?

TaskScheduler/Operational 200/201 show executions; correlate with process creation on those times.

## 6. Scope

→ [KQL scheduled task creation](../../detection/kql/file-registry-events.md#scheduled-task-creation) · [SPL 4698](../../detection/spl/windows-events.md#scheduled-task-created-4698) · [S1QL task registration](../../detection/s1ql/hunting.md#scheduled-task-registration)

## 7. Contain

Disable → export → remove; investigate the payload the task points at.

→ [Disable or remove a task](../../platforms/windows/scheduled-tasks.md#disable-or-remove-a-task)

## Linux equivalent

→ [Cron](../../platforms/linux/cron.md) · [systemd timers](../../platforms/linux/systemd.md#timers)

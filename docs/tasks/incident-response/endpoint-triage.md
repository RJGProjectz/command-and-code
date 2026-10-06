---
title: Endpoint Triage
type: workflow
platforms: [Windows, Linux]
languages: [PowerShell, Bash]
tasks: [Incident Response, Forensics]
category: Workflow
tags: [workflow, triage, live response, volatile data, collection]
aliases: [endpoint triage, live response checklist, what commands during triage, first responder checklist, collect volatile data]
difficulty: basic
verified: true
last_verified: 2026-10-05
search:
  boost: 3
---

# Endpoint Triage

**Trigger:** any alert that puts a single endpoint in question.

**Goal:** in 15–30 minutes, capture volatile state and answer *is this host compromised, and how urgently do we contain it?*

!!! tip "Order of volatility"
    Collect what disappears first: network connections → processes → logged-on users → DNS cache → then disk artefacts and logs. Write output to a collection folder or remote share, not over evidence on the system drive.

## Automated collection

| Platform | Tool |
| --- | --- |
| Windows | [`Invoke-EndpointTriage.ps1`](../../toolbox/powershell.md#invoke-endpointtriage) — collects every item below into one folder |
| Linux | [`linux-triage.sh`](../../toolbox/bash.md#linux-triagesh) |

Use the manual steps when you cannot run scripts (restricted live-response consoles) or need to dig deeper.

## 1. Record the context

Hostname, IP, OS/build, current time and time zone, analyst, ticket number.

→ Windows [system information](../../platforms/windows/system-information.md#os-build-and-last-boot) · Linux [system information](../../platforms/linux/system-information.md#time)

## 2. Network connections and listeners

→ Windows [listening ports](../../platforms/windows/networking.md#find-listening-ports), [established](../../platforms/windows/networking.md#list-established-connections) · Linux [listening ports](../../platforms/linux/networking.md#find-listening-ports), [established](../../platforms/linux/networking.md#list-established-connections)

## 3. Running processes with parents and command lines

→ Windows [processes](../../platforms/windows/processes.md#find-a-process-by-pid) · Linux [processes](../../platforms/linux/processes.md#list-processes), [deleted binaries](../../platforms/linux/processes.md#processes-running-from-deleted-or-temporary-binaries)

## 4. Logged-on users and recent logons

→ Windows [who is logged on](../../platforms/windows/users-groups.md#who-is-logged-on), [`Get-RecentLogons.ps1`](../../toolbox/powershell.md#get-recentlogons) · Linux [logins](../../platforms/linux/logs.md#successful-logins)

## 5. DNS cache

→ Windows [DNS client cache](../../platforms/windows/networking.md#dns-client-cache)

## 6. Persistence

→ Windows [`Get-PersistenceSnapshot.ps1`](../../toolbox/powershell.md#get-persistencesnapshot), [services](../../platforms/windows/services.md#list-services-with-binary-path-and-account), [tasks](../../platforms/windows/scheduled-tasks.md#list-tasks-with-their-actions), [Run keys](../../platforms/windows/registry.md#dump-all-run-keys-and-startup-folders) · Linux [cron](../../platforms/linux/cron.md#list-every-users-crontab), [systemd](../../platforms/linux/systemd.md#hunt-for-systemd-persistence), [SSH keys](../../platforms/linux/ssh.md#find-authorized-keys)

## 7. Recently created files

→ Windows [recent files](../../platforms/windows/files-directories.md#find-recently-created-or-modified-files) · Linux [recent files](../../platforms/linux/filesystem.md#recently-modified-files)

## 8. Security tooling health

Is the EDR/AV running, up to date, without new exclusions?

→ [Defender status and exclusions](../../platforms/windows/defender.md#health-and-protection-status)

## 9. Export logs

→ Windows [export with wevtutil](../../platforms/windows/event-logs.md#export-and-inspect-logs-wevtutil) · Linux [log locations](../../platforms/linux/logs.md#where-logs-live)

## 10. Decide

| Observation | Next step |
| --- | --- |
| Confirmed malicious process, C2 or persistence | Isolate now; continue with the specific workflow |
| Suspicious but unconfirmed | Keep collecting; scope via EDR/SIEM; consider isolation if the asset is critical |
| Benign explanation proven | Document evidence, close, tune the alert |

Specific workflows: [Suspicious Process](suspicious-process.md) · [Suspicious PowerShell](suspicious-powershell.md) · [Malware Triage](malware-triage.md) · [Network Investigation](../investigation/network-investigation.md)

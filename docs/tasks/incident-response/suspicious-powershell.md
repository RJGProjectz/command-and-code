---
title: Suspicious PowerShell Investigation
type: workflow
platforms: [Windows, Microsoft Defender, Splunk, SentinelOne]
languages: [PowerShell, KQL, SPL, S1QL]
tasks: [Incident Response, Investigation]
category: Workflow
tags: [workflow, powershell, encoded command, triage, playbook]
aliases: [suspicious powershell, powershell alert, encoded powershell alert, investigate powershell]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
search:
  boost: 3
---

# Suspicious PowerShell Investigation

**Trigger:** an alert or observation of PowerShell running encoded commands, download cradles, AMSI bypass strings, or an unusual parent.

**Goal:** decide whether the activity is malicious, what it did, and what needs containment.

## 1. Identify the process

Record host, user, time, PID and the **full command line** from the alert. If the process is still running:

```powershell
Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe' OR Name = 'pwsh.exe'" |
    Select-Object ProcessId, ParentProcessId, CreationDate, CommandLine
```

→ [Find processes by name with command line](../../platforms/windows/processes.md#find-processes-by-name-with-command-line)

## 2. Identify the parent and the full tree

Who launched PowerShell? `explorer.exe` (user), `winword.exe` (macro), `wmiprvse.exe` (WMI/remote), `services.exe` (service), `svchost.exe` hosting Task Scheduler (scheduled task), `w3wp.exe` (web shell).

→ [Find the parent process](../../platforms/windows/processes.md#find-the-parent-process) · [Process tree](../../platforms/windows/processes.md#process-tree) · [`Get-ProcessTree.ps1`](../../toolbox/powershell.md#get-processtree)

## 3. Decode the command

Extract and decode any `-EncodedCommand` payload; look for a second stage (URLs, `FromBase64String`, `-bxor`, compressed streams).

→ [`decode-powershell.py`](../../toolbox/python.md#decode-powershellpy) · [Bash decoding](../../languages/bash/text-processing.md#decode-base64-and-powershell-encoded-commands)

## 4. Identify the script or binary path and user

```powershell
Get-CimInstance Win32_Process -Filter "ProcessId = 1234" | Invoke-CimMethod -MethodName GetOwner
```

If the command references a `.ps1`, hash and preserve it. → [Hash a file](../../platforms/windows/files-directories.md#hash-a-file)

## 5. Check network connections

```powershell
Get-NetTCPConnection -OwningProcess 1234 -ErrorAction SilentlyContinue | Select-Object RemoteAddress, RemotePort, State
Get-DnsClientCache | Select-Object Entry, Data
```

→ [Established connections](../../platforms/windows/networking.md#list-established-connections) · [DNS client cache](../../platforms/windows/networking.md#dns-client-cache)

## 6. Check persistence

Look for the same command line or script path in Run keys, scheduled tasks, services and WMI.

→ [`Get-PersistenceSnapshot.ps1`](../../toolbox/powershell.md#get-persistencesnapshot) · [Run keys](../../platforms/windows/registry.md#dump-all-run-keys-and-startup-folders) · [Scheduled tasks](../../platforms/windows/scheduled-tasks.md#list-tasks-with-their-actions)

## 7. Review Windows logs on the host

- **4104** script blocks — the deobfuscated code PowerShell actually ran
- **4688** / Sysmon **1** — process creation with parent
- PSReadLine history for interactive sessions

→ [Script block logging](../../platforms/windows/event-logs.md#enable-powershell-script-block-logging) · [PowerShell history](../../platforms/windows/files-directories.md#execution-artifacts-forensics)

## 8. Search Defender telemetry (fleet-wide)

Same command line, same hash, same parent pattern on other devices.

→ [KQL encoded PowerShell](../../detection/kql/process-events.md#encoded-powershell) · [KQL download cradles](../../detection/kql/process-events.md#powershell-download-cradles)

## 9. Search SIEM telemetry

→ [SPL 4104 script blocks](../../detection/spl/powershell.md#suspicious-script-blocks-4104) · [SPL encoded commands](../../detection/spl/powershell.md#encoded-commands-process-creation)

## 10. Search EDR telemetry

→ [S1QL encoded PowerShell](../../detection/s1ql/hunting.md#encoded-or-download-cradle-powershell) · [Storyline pivot](../../detection/s1ql/fundamentals.md#storyline-pivot)

## 11. Determine scope

Answer before containing: how many hosts, which accounts, first-seen time, any successful download or second stage, any credential access (LSASS access, `sekurlsa`, `comsvcs.dll MiniDump`).

## 12. Contain and remediate

| Finding | Action |
| --- | --- |
| Confirmed malicious, single host | Isolate device via EDR; preserve memory if possible |
| Credentials exposed | Reset passwords, [revoke sessions](../../platforms/microsoft-365/entra.md#contain-a-compromised-account) |
| Persistence found | Export, then remove ([registry](../../platforms/windows/registry.md#remove-a-malicious-value), [task](../../platforms/windows/scheduled-tasks.md#disable-or-remove-a-task)) |
| C2 domain/IP | Block at proxy/firewall and as EDR indicators |
| Legitimate admin activity | Document, tune the detection, consider signing the script |

## Related

- [Suspicious Process](suspicious-process.md)
- [Endpoint Triage](endpoint-triage.md)
- [MITRE T1059.001](../../detection/mitre-attack/index.md)

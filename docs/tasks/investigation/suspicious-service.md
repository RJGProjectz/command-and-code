---
title: Suspicious Service Investigation
type: workflow
platforms: [Windows, Windows Server, Microsoft Defender, Splunk]
languages: [PowerShell, Windows CLI, KQL, SPL]
tasks: [Investigation, Incident Response]
category: Workflow
tags: [workflow, services, persistence, 7045, psexec]
aliases: [suspicious service, new service installed alert, malicious service, psexec service]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
---

# Suspicious Service Investigation

**Trigger:** event 7045/4697, an EDR "service installed" alert, or an unfamiliar service found during triage.

## 1. Get the service definition

Name, display name, binary path and arguments, start type, account.

→ [Inspect one service](../../platforms/windows/services.md#inspect-one-service) · [Registry location](../../platforms/windows/services.md#registry-location)

## 2. Recognise common attacker patterns

| Pattern | Likely cause |
| --- | --- |
| Random 4–8 character name, `ImagePath` = `%SystemRoot%\xxxxxx.exe` | Remote execution tools (PsExec-style, Impacket `smbexec`/`psexec`) |
| `ImagePath` contains `cmd.exe /c` or `powershell -enc` | Remote command execution via a temporary service |
| Service DLL changed on an existing svchost service | Service hijack |
| Binary in user-writable path | Malware persistence |

`PSEXESVC` is the legitimate Sysinternals PsExec service — legitimate tool, but check who ran it and from where.

## 3. When and by whom?

7045 gives the time; correlate with logons on the host around that time (type 3 network logons from another machine indicate remote creation).

→ [Find recently installed services](../../platforms/windows/services.md#find-recently-installed-services) · [Extract event fields](../../platforms/windows/event-logs.md#extract-event-fields)

## 4. Examine the binary

→ [Hash and signature](../../platforms/windows/processes.md#check-the-binary-hash-and-signature)

## 5. Scope

→ [KQL service installation](../../detection/kql/file-registry-events.md#service-installation) · [SPL new service installed](../../detection/spl/windows-events.md#new-service-installed-7045)

## 6. Source host

If the service was created remotely, the source machine is now your primary suspect. → [Possible Lateral Movement](../threat-hunting/lateral-movement.md)

## 7. Contain

Stop and disable, preserve the binary and registry key, then delete.

→ [Stop and disable a service](../../platforms/windows/services.md#stop-and-disable-a-service)

---
title: Possible Lateral Movement
type: workflow
platforms: [Windows, Windows Server, Microsoft Defender, Splunk]
languages: [PowerShell, KQL, SPL]
tasks: [Threat Hunting, Incident Response, Investigation]
category: Workflow
tags: [workflow, lateral movement, rdp, smb, psexec, wmi, winrm]
aliases: [lateral movement, lateral movement hunt, psexec detection, remote execution, attacker moving between hosts]
difficulty: advanced
verified: true
last_verified: 2026-10-05
---

# Possible Lateral Movement

**Trigger:** a compromised host, an admin account used from an unusual source, or a hunt hypothesis.

**Hypothesis:** an attacker with credentials is moving from host A to host B using built-in remote-administration protocols.

## Remote execution methods and their traces

| Method | Network | Destination-host evidence |
| --- | --- | --- |
| RDP | TCP 3389 | 4624 LogonType 10; `TerminalServices-*` logs |
| SMB + service (PsExec-style) | TCP 445 | 4624 LogonType 3, then 7045 new service |
| WMI | TCP 135 + dynamic RPC | `wmiprvse.exe` spawning `cmd.exe`/`powershell.exe` |
| WinRM / PowerShell remoting | TCP 5985/5986 | `wsmprovhost.exe` spawning processes |
| Scheduled task (remote) | TCP 445/135 | 4698 shortly after a type 3 logon |
| SSH (Linux) | TCP 22 | `Accepted` in auth.log |

## 1. Map logons from the suspect source

→ [KQL successful RDP logons](../../detection/kql/logon-identity.md#successful-rdp-logons) · [SPL RDP logons](../../detection/spl/windows-events.md#rdp-logons-4624-logontype-10) · [Domain authentication](../../detection/kql/logon-identity.md#domain-authentication-defender-for-identity)

## 2. Look for remote-execution children

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("wmiprvse.exe", "wsmprovhost.exe", "services.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

## 3. Services and tasks created right after network logons

→ [Suspicious Service](../investigation/suspicious-service.md) · [Scheduled Task Investigation](../investigation/scheduled-task-investigation.md)

## 4. Workstation-to-workstation SMB/RDP

Workstations rarely need to administer each other.

→ [SPL RDP/SMB between workstations](../../detection/spl/network-dns.md#rdp-smb-between-workstations) · [SMB sessions on a host](../../platforms/windows/networking.md#smb-shares-sessions-and-connections)

## 5. Build the path

Draw source → destination → account → method → time for every hop. The earliest hop points to the initial access host.

## 6. Contain

Isolate every host on the path, disable/reset the accounts used, and check for credential dumping on each hop (access to LSASS, `ntds.dit`, SAM hive saves).

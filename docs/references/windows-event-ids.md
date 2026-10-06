---
title: Windows Event ID Reference
type: reference
platforms: [Windows, Windows Server]
languages: [PowerShell, SPL, KQL]
tasks: [Investigation, Incident Response, Detection Engineering, Forensics]
category: Reference
tags: [event ids, security log, sysmon, logon types, kerberos, 4624, 4625, 4688, 7045, 4104]
aliases: [windows event id list, logon type 10, event 4624, sysmon event ids, what is event 4688, security event ids cheat sheet]
verified: true
last_verified: 2026-10-05
search:
  boost: 2
---

# Windows Event ID Reference

The events that matter most in investigations. "Requires" names the advanced-audit subcategory that must be enabled (check with `auditpol /get /category:*`).

## Logon and session

| ID | Log | Meaning | Requires |
| --- | --- | --- | --- |
| 4624 | Security | Successful logon | Audit Logon |
| 4625 | Security | Failed logon | Audit Logon |
| 4634 / 4647 | Security | Logoff / user-initiated logoff | Audit Logoff |
| 4648 | Security | Logon with explicit credentials (`runas`, many lateral-movement tools) | Audit Logon |
| 4672 | Security | Special privileges assigned to new logon (admin-equivalent session) | Audit Special Logon |
| 4778 / 4779 | Security | RDP session reconnected / disconnected | Audit Other Logon/Logoff Events |
| 21 / 24 / 25 | TerminalServices-LocalSessionManager/Operational | RDP logon / disconnect / reconnect | — |
| 1149 | TerminalServices-RemoteConnectionManager/Operational | RDP network authentication succeeded | — |

### Logon types (4624 / 4625)

| Type | Name | Typical source |
| --- | --- | --- |
| 2 | Interactive | Console keyboard logon |
| 3 | Network | SMB share, `net use`, PsExec, WMI, many remote tools |
| 4 | Batch | Scheduled task |
| 5 | Service | Service start |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | Credentials sent in clear (IIS basic auth, some PowerShell) |
| 9 | NewCredentials | `runas /netonly` — local identity, different network credentials |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | Domain logon with cached credentials (DC unreachable) |

## Kerberos and NTLM (domain controllers)

| ID | Meaning | Investigation use |
| --- | --- | --- |
| 4768 | Kerberos TGT requested | Account logon from a client IP |
| 4769 | Kerberos service ticket requested | RC4 (`0x17`) encryption for many services can indicate Kerberoasting |
| 4771 | Kerberos pre-authentication failed | Password spray / bad password against Kerberos |
| 4776 | NTLM credential validation | NTLM authentication attempts and failures |
| 4740 | Account locked out (on the PDC emulator) | `CallerComputerName` = lockout source |

## Process and PowerShell

| ID | Log | Meaning |
| --- | --- | --- |
| 4688 | Security | Process created (command line only if enabled) — *Audit Process Creation* |
| 4689 | Security | Process exited |
| 4103 | PowerShell/Operational | Module/pipeline execution logging |
| 4104 | PowerShell/Operational | Script block logging — the deobfuscated code |
| 400 / 403 | Windows PowerShell | Engine started / stopped (includes `EngineVersion` — spot v2 downgrade) |

## Services, tasks and persistence

| ID | Log | Meaning |
| --- | --- | --- |
| 7045 | System | Service installed |
| 4697 | Security | Service installed — *Audit Security System Extension* |
| 7040 | System | Service start type changed |
| 4698 / 4699 / 4702 | Security | Scheduled task created / deleted / updated — *Audit Other Object Access Events* |
| 106 / 140 / 141 | TaskScheduler/Operational | Task registered / updated / deleted |
| 5861 | WMI-Activity/Operational | Permanent WMI event subscription registered |

## Accounts and groups

| ID | Meaning |
| --- | --- |
| 4720 | User account created |
| 4722 / 4725 | Account enabled / disabled |
| 4723 / 4724 | Password change attempt / reset attempt |
| 4726 | Account deleted |
| 4728 / 4729 | Member added to / removed from a global security group |
| 4732 / 4733 | Member added to / removed from a local security group |
| 4756 / 4757 | Member added to / removed from a universal security group |

## Defence evasion and system

| ID | Log | Meaning |
| --- | --- | --- |
| 1102 | Security | Security log cleared |
| 104 | System | An event log was cleared |
| 4719 | Security | System audit policy changed |
| 1074 | System | Planned shutdown/restart, with process and user |
| 6005 / 6006 / 6008 | System | Event Log service started / stopped / previous shutdown unexpected |
| 5001 / 5007 / 5013 | Windows Defender/Operational | Real-time protection disabled / configuration changed / tamper protection blocked a change |
| 1116 / 1117 | Windows Defender/Operational | Malware detected / action taken |

## Sysmon (Microsoft-Windows-Sysmon/Operational)

| ID | Meaning |
| --- | --- |
| 1 | Process creation (with hashes, parent, command line) |
| 3 | Network connection |
| 7 | Image (DLL) loaded |
| 8 | CreateRemoteThread |
| 10 | Process accessed (e.g. LSASS access) |
| 11 | File created |
| 12 / 13 / 14 | Registry object created-deleted / value set / renamed |
| 22 | DNS query |
| 23 / 26 | File delete archived / file delete logged |

Sysmon logs only what its configuration includes.

## Related

- [Windows event logs](../platforms/windows/event-logs.md)
- [SPL Windows security events](../detection/spl/windows-events.md)

## Sources

- [Advanced security audit policy settings](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/advanced-security-audit-policy-settings)
- [Events to monitor (Microsoft)](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
- [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)

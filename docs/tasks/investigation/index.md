---
title: Investigation
type: index
---

# Investigation

Answer specific questions about a host, account or connection: what happened, when, and how.

## Workflows

<!-- cc:index tasks="Investigation" type="workflow" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Account Compromise Investigation](../incident-response/account-compromise.md) | Workflow | Entra ID, Exchange Online, Microsoft 365, Windows | PowerShell, KQL | Incident Response, Investigation |
| [Failed Authentication Investigation](failed-authentication.md) | Workflow | Windows, Windows Server, Linux, Entra ID, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Troubleshooting |
| [Network Investigation](network-investigation.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Possible Lateral Movement](../threat-hunting/lateral-movement.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk | PowerShell, KQL, SPL | Threat Hunting, Incident Response, Investigation |
| [Registry Persistence Investigation](registry-persistence.md) | Workflow | Windows, Microsoft Defender, SentinelOne | PowerShell, Windows CLI, KQL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Scheduled Task Investigation](scheduled-task-investigation.md) | Workflow | Windows, Microsoft Defender, Splunk, SentinelOne | PowerShell, Windows CLI, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Suspicious Outbound Connection](suspicious-outbound-connection.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Threat Hunting |
| [Suspicious PowerShell Investigation](../incident-response/suspicious-powershell.md) | Workflow | Windows, Microsoft Defender, Splunk, SentinelOne | PowerShell, KQL, SPL, S1QL | Incident Response, Investigation |
| [Suspicious Process Investigation](../incident-response/suspicious-process.md) | Workflow | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Incident Response, Investigation |
| [Suspicious Service Investigation](suspicious-service.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk | PowerShell, Windows CLI, KQL, SPL | Investigation, Incident Response |

<!-- /cc:index -->

## Reference entries

<!-- cc:index tasks="Investigation" type="entry|tool|reference" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Bash Text Processing](../../languages/bash/text-processing.md) | Entry | Linux | Bash | Investigation, Automation, Threat Hunting |
| [Conditional Access](../../platforms/microsoft-365/conditional-access.md) | Entry | Microsoft 365, Entra ID | PowerShell, KQL | Administration, Hardening, Investigation, Troubleshooting |
| [Entra ID](../../platforms/microsoft-365/entra.md) | Entry | Microsoft 365, Entra ID | PowerShell | Incident Response, Investigation, Administration |
| [Exchange Online](../../platforms/microsoft-365/exchange.md) | Entry | Microsoft 365, Exchange Online | PowerShell | Incident Response, Investigation, Administration |
| [KQL File, Registry and Persistence Hunting](../../detection/kql/file-registry-events.md) | Entry | Microsoft Defender, Windows | KQL | Threat Hunting, Detection Engineering, Investigation |
| [KQL Fundamentals](../../detection/kql/fundamentals.md) | Entry | Microsoft Defender, Microsoft 365 | KQL | Threat Hunting, Detection Engineering, Investigation |
| [KQL Logon and Identity Hunting](../../detection/kql/logon-identity.md) | Entry | Microsoft Defender, Entra ID, Microsoft 365, Windows | KQL | Threat Hunting, Investigation, Incident Response, Detection Engineering |
| [KQL Network Event Hunting](../../detection/kql/network-events.md) | Entry | Microsoft Defender, Windows | KQL | Threat Hunting, Investigation, Detection Engineering, Incident Response |
| [KQL Process Event Hunting](../../detection/kql/process-events.md) | Entry | Microsoft Defender, Windows | KQL | Threat Hunting, Detection Engineering, Investigation, Incident Response |
| [Linux Cron and Scheduled Jobs](../../platforms/linux/cron.md) | Entry | Linux | Bash | Incident Response, Investigation, Threat Hunting, Administration |
| [Linux Filesystem](../../platforms/linux/filesystem.md) | Entry | Linux | Bash | Incident Response, Investigation, Forensics, Troubleshooting |
| [Linux Installed Packages](../../platforms/linux/packages.md) | Entry | Linux | Bash | Investigation, Administration, Forensics |
| [Linux Logs](../../platforms/linux/logs.md) | Entry | Linux | Bash | Incident Response, Investigation, Troubleshooting, Forensics |
| [Linux Networking and DNS](../../platforms/linux/networking.md) | Entry | Linux | Bash | Incident Response, Investigation, Troubleshooting, Administration |
| [Linux Processes](../../platforms/linux/processes.md) | Entry | Linux | Bash | Incident Response, Investigation, Troubleshooting, Forensics |
| [Linux Services with systemd](../../platforms/linux/systemd.md) | Entry | Linux | Bash | Administration, Troubleshooting, Incident Response, Investigation |
| [Linux SSH](../../platforms/linux/ssh.md) | Entry | Linux | Bash | Incident Response, Investigation, Hardening, Administration |
| [Linux Users and Permissions](../../platforms/linux/users-permissions.md) | Entry | Linux | Bash | Incident Response, Investigation, Administration, Hardening |
| [PowerShell JSON and CSV](../../languages/powershell/json-csv.md) | Entry | Windows, Windows Server | PowerShell | Automation, Investigation |
| [Python JSON and CSV](../../languages/python/json-csv.md) | Entry | Linux, Windows | Python | Automation, Investigation |
| [S1QL Fundamentals](../../detection/s1ql/fundamentals.md) | Entry | SentinelOne | S1QL | Threat Hunting, Investigation, Detection Engineering |
| [S1QL Hunting Queries](../../detection/s1ql/hunting.md) | Entry | SentinelOne, Windows, Linux | S1QL | Threat Hunting, Incident Response, Investigation |
| [SPL Fundamentals and Search Optimization](../../detection/spl/fundamentals.md) | Entry | Splunk | SPL | Threat Hunting, Detection Engineering, Investigation |
| [SPL Network and DNS Hunting](../../detection/spl/network-dns.md) | Entry | Splunk | SPL | Threat Hunting, Investigation, Detection Engineering |
| [SPL Windows Security Events](../../detection/spl/windows-events.md) | Entry | Splunk, Windows | SPL | Threat Hunting, Detection Engineering, Investigation, Incident Response |
| [Windows Event Logs](../../platforms/windows/event-logs.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Forensics, Hardening |
| [Windows Files and Permissions](../../platforms/windows/files-directories.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Forensics, Hardening |
| [Windows Installed Software](../../platforms/windows/software.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Investigation, Administration, Incident Response |
| [Windows Networking and DNS](../../platforms/windows/networking.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Troubleshooting, Administration |
| [Windows Processes](../../platforms/windows/processes.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Troubleshooting, Forensics |
| [Windows Registry and Run Keys](../../platforms/windows/registry.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Forensics, Threat Hunting |
| [Windows Scheduled Tasks](../../platforms/windows/scheduled-tasks.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Threat Hunting, Administration |
| [Windows Services](../../platforms/windows/services.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Administration, Hardening |
| [Windows Users and Groups](../../platforms/windows/users-groups.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Administration, Hardening |
| [Bash Toolbox](../../toolbox/bash.md) | Tool | Linux | Bash | Automation, Incident Response, Forensics, Investigation |
| [PowerShell Toolbox](../../toolbox/powershell.md) | Tool | Windows, Windows Server | PowerShell | Automation, Incident Response, Forensics, Investigation |
| [Python Toolbox](../../toolbox/python.md) | Tool | Windows, Linux, Microsoft 365, SentinelOne | Python | Automation, Incident Response, Investigation |
| [Cross-Platform Equivalents](../../references/equivalents.md) | Reference | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting, Administration |
| [Linux Sysadmin Speed Dial Cheat Sheet](../../references/linux-cheat-sheet.md) | Reference | Linux | Bash | Administration, Troubleshooting, Investigation |
| [PowerShell Admin One-Liners Cheat Sheet](../../references/powershell-cheat-sheet.md) | Reference | Windows, Windows Server | PowerShell | Administration, Investigation, Automation |
| [Sysadmin Quick Reference Cheat Sheet](../../references/sysadmin-cheat-sheet.md) | Reference | Windows, Windows Server, Linux, Microsoft 365, Entra ID | PowerShell, Bash, Windows CLI | Administration, Troubleshooting, Investigation |
| [Windows Event ID Reference](../../references/windows-event-ids.md) | Reference | Windows, Windows Server | PowerShell, SPL, KQL | Investigation, Incident Response, Detection Engineering, Forensics |

<!-- /cc:index -->

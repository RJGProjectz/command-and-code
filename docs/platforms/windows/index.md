---
title: Windows
type: index
---

# Windows

Commands, configuration locations and investigation techniques for Windows 10/11 and Windows Server.
Most entries show **PowerShell** first, with the native **Windows CLI** equivalent where one exists.

!!! tip "PowerShell version"
    Examples run in **Windows PowerShell 5.1** (in-box) unless marked *PowerShell 7+*. See [PowerShell fundamentals and pitfalls](../../languages/powershell/fundamentals.md).

## Quick answers

| I need to… | Go to |
| --- | --- |
| Find listening ports | [Networking → Find listening ports](networking.md#find-listening-ports) |
| Find a process from a PID | [Processes → Find a process by PID](processes.md#find-a-process-by-pid) |
| See a process tree | [Processes → Process tree](processes.md#process-tree) |
| Check Run keys | [Registry → Common autostart locations](registry.md#common-autostart-locations) |
| List scheduled tasks with actions | [Scheduled tasks](scheduled-tasks.md#list-tasks-with-their-actions) |
| Read failed logons | [Event logs → Failed logons summary](event-logs.md#failed-logons-summary) |
| Check Defender exclusions | [Defender → Exclusions](defender.md#exclusions) |
| Find where a firewall setting lives | [Firewall → Where is the setting?](firewall.md#where-is-the-setting) |

## All Windows entries

<!-- cc:index platforms="Windows|Windows Server" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Account Compromise Investigation](../../tasks/incident-response/account-compromise.md) | Workflow | Entra ID, Exchange Online, Microsoft 365, Windows | PowerShell, KQL | Incident Response, Investigation |
| [Endpoint Triage](../../tasks/incident-response/endpoint-triage.md) | Workflow | Windows, Linux | PowerShell, Bash | Incident Response, Forensics |
| [Failed Authentication Investigation](../../tasks/investigation/failed-authentication.md) | Workflow | Windows, Windows Server, Linux, Entra ID, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Troubleshooting |
| [Malware Triage](../../tasks/incident-response/malware-triage.md) | Workflow | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Incident Response, Forensics |
| [Network Investigation](../../tasks/investigation/network-investigation.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Possible Lateral Movement](../../tasks/threat-hunting/lateral-movement.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk | PowerShell, KQL, SPL | Threat Hunting, Incident Response, Investigation |
| [Registry Persistence Investigation](../../tasks/investigation/registry-persistence.md) | Workflow | Windows, Microsoft Defender, SentinelOne | PowerShell, Windows CLI, KQL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Scheduled Task Investigation](../../tasks/investigation/scheduled-task-investigation.md) | Workflow | Windows, Microsoft Defender, Splunk, SentinelOne | PowerShell, Windows CLI, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Suspicious Outbound Connection](../../tasks/investigation/suspicious-outbound-connection.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Threat Hunting |
| [Suspicious PowerShell Investigation](../../tasks/incident-response/suspicious-powershell.md) | Workflow | Windows, Microsoft Defender, Splunk, SentinelOne | PowerShell, KQL, SPL, S1QL | Incident Response, Investigation |
| [Suspicious Process Investigation](../../tasks/incident-response/suspicious-process.md) | Workflow | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Incident Response, Investigation |
| [Suspicious Service Investigation](../../tasks/investigation/suspicious-service.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk | PowerShell, Windows CLI, KQL, SPL | Investigation, Incident Response |
| [Windows Connectivity Troubleshooting](../../tasks/troubleshooting/windows-connectivity.md) | Workflow | Windows, Windows Server | PowerShell, Windows CLI | Troubleshooting |
| [Hyper-V](../virtualization/hyper-v.md) | Entry | Hyper-V, Windows Server | PowerShell | Administration, Incident Response, Forensics |
| [Intune](../microsoft-365/intune.md) | Entry | Microsoft 365, Intune, Windows | PowerShell, Windows CLI | Administration, Troubleshooting, Incident Response |
| [KQL File, Registry and Persistence Hunting](../../detection/kql/file-registry-events.md) | Entry | Microsoft Defender, Windows | KQL | Threat Hunting, Detection Engineering, Investigation |
| [KQL Logon and Identity Hunting](../../detection/kql/logon-identity.md) | Entry | Microsoft Defender, Entra ID, Microsoft 365, Windows | KQL | Threat Hunting, Investigation, Incident Response, Detection Engineering |
| [KQL Network Event Hunting](../../detection/kql/network-events.md) | Entry | Microsoft Defender, Windows | KQL | Threat Hunting, Investigation, Detection Engineering, Incident Response |
| [KQL Process Event Hunting](../../detection/kql/process-events.md) | Entry | Microsoft Defender, Windows | KQL | Threat Hunting, Detection Engineering, Investigation, Incident Response |
| [Microsoft Defender Antivirus](defender.md) | Entry | Windows, Windows Server, Microsoft Defender | PowerShell, Windows CLI | Incident Response, Administration, Hardening, Troubleshooting |
| [Microsoft Defender XDR and Defender for Endpoint](../microsoft-365/defender.md) | Entry | Microsoft 365, Microsoft Defender, Windows | PowerShell, KQL | Incident Response, Threat Hunting, Administration, Automation |
| [PowerShell Automation and Remoting](../../languages/powershell/automation.md) | Entry | Windows, Windows Server | PowerShell | Automation, Incident Response, Administration |
| [PowerShell Error Handling](../../languages/powershell/error-handling.md) | Entry | Windows, Windows Server | PowerShell | Automation |
| [PowerShell Fundamentals and Pitfalls](../../languages/powershell/fundamentals.md) | Entry | Windows, Windows Server | PowerShell | Automation, Administration |
| [PowerShell JSON and CSV](../../languages/powershell/json-csv.md) | Entry | Windows, Windows Server | PowerShell | Automation, Investigation |
| [PowerShell REST APIs](../../languages/powershell/rest-apis.md) | Entry | Windows, Microsoft 365, SentinelOne, Splunk | PowerShell | Automation, Incident Response |
| [Python JSON and CSV](../../languages/python/json-csv.md) | Entry | Linux, Windows | Python | Automation, Investigation |
| [Python Logging and Automation](../../languages/python/logging-automation.md) | Entry | Linux, Windows | Python | Automation |
| [Python Subprocess and Filesystem](../../languages/python/subprocess-filesystem.md) | Entry | Linux, Windows | Python | Automation, Forensics, Incident Response |
| [S1QL Hunting Queries](../../detection/s1ql/hunting.md) | Entry | SentinelOne, Windows, Linux | S1QL | Threat Hunting, Incident Response, Investigation |
| [Sigma Rule Examples](../../detection/sigma/examples.md) | Entry | Windows | Sigma | Detection Engineering, Threat Hunting |
| [SPL PowerShell Hunting](../../detection/spl/powershell.md) | Entry | Splunk, Windows | SPL | Threat Hunting, Detection Engineering, Incident Response |
| [SPL Windows Security Events](../../detection/spl/windows-events.md) | Entry | Splunk, Windows | SPL | Threat Hunting, Detection Engineering, Investigation, Incident Response |
| [Windows 10 and 11 Version Notes](windows-10-11.md) | Entry | Windows | PowerShell | Administration, Troubleshooting |
| [Windows Event Logs](event-logs.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Forensics, Hardening |
| [Windows Files and Permissions](files-directories.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Forensics, Hardening |
| [Windows Firewall](firewall.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Administration, Hardening, Incident Response, Troubleshooting |
| [Windows Installed Software](software.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Investigation, Administration, Incident Response |
| [Windows Networking and DNS](networking.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Troubleshooting, Administration |
| [Windows Processes](processes.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Troubleshooting, Forensics |
| [Windows Registry and Run Keys](registry.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Forensics, Threat Hunting |
| [Windows Scheduled Tasks](scheduled-tasks.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Threat Hunting, Administration |
| [Windows Server Notes](windows-server.md) | Entry | Windows Server | PowerShell, Windows CLI | Administration, Incident Response, Troubleshooting |
| [Windows Services](services.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Administration, Hardening |
| [Windows System Information](system-information.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Administration, Troubleshooting |
| [Windows Troubleshooting Commands](troubleshooting.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Troubleshooting, Administration |
| [Windows Users and Groups](users-groups.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Administration, Hardening |
| [PowerShell Toolbox](../../toolbox/powershell.md) | Tool | Windows, Windows Server | PowerShell | Automation, Incident Response, Forensics, Investigation |
| [Python Toolbox](../../toolbox/python.md) | Tool | Windows, Linux, Microsoft 365, SentinelOne | Python | Automation, Incident Response, Investigation |
| [Cross-Platform Equivalents](../../references/equivalents.md) | Reference | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting, Administration |
| [MITRE ATT&CK Mapping](../../detection/mitre-attack/index.md) | Reference | Windows, Linux, Microsoft 365 | MITRE ATT&CK | Detection Engineering, Threat Hunting, Incident Response |
| [Windows Event ID Reference](../../references/windows-event-ids.md) | Reference | Windows, Windows Server | PowerShell, SPL, KQL | Investigation, Incident Response, Detection Engineering, Forensics |

<!-- /cc:index -->

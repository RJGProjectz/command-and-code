---
title: Incident Response
type: index
---

# Incident Response

Confirm, scope, contain and recover from security incidents. Start with a workflow, then drop into the linked reference entries.

## Workflows

<!-- cc:index tasks="Incident Response" type="workflow" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Account Compromise Investigation](account-compromise.md) | Workflow | Entra ID, Exchange Online, Microsoft 365, Windows | PowerShell, KQL | Incident Response, Investigation |
| [Endpoint Triage](endpoint-triage.md) | Workflow | Windows, Linux | PowerShell, Bash | Incident Response, Forensics |
| [Failed Authentication Investigation](../investigation/failed-authentication.md) | Workflow | Windows, Windows Server, Linux, Entra ID, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Troubleshooting |
| [Malware Triage](malware-triage.md) | Workflow | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Incident Response, Forensics |
| [Network Investigation](../investigation/network-investigation.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Possible Lateral Movement](../threat-hunting/lateral-movement.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk | PowerShell, KQL, SPL | Threat Hunting, Incident Response, Investigation |
| [Registry Persistence Investigation](../investigation/registry-persistence.md) | Workflow | Windows, Microsoft Defender, SentinelOne | PowerShell, Windows CLI, KQL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Scheduled Task Investigation](../investigation/scheduled-task-investigation.md) | Workflow | Windows, Microsoft Defender, Splunk, SentinelOne | PowerShell, Windows CLI, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Suspicious Outbound Connection](../investigation/suspicious-outbound-connection.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Threat Hunting |
| [Suspicious PowerShell Investigation](suspicious-powershell.md) | Workflow | Windows, Microsoft Defender, Splunk, SentinelOne | PowerShell, KQL, SPL, S1QL | Incident Response, Investigation |
| [Suspicious Process Investigation](suspicious-process.md) | Workflow | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Incident Response, Investigation |
| [Suspicious Service Investigation](../investigation/suspicious-service.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk | PowerShell, Windows CLI, KQL, SPL | Investigation, Incident Response |

<!-- /cc:index -->

## Reference entries

<!-- cc:index tasks="Incident Response" type="entry|tool|reference" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Bash Scripting and Automation](../../languages/bash/automation.md) | Entry | Linux | Bash | Automation, Administration, Incident Response |
| [Entra ID](../../platforms/microsoft-365/entra.md) | Entry | Microsoft 365, Entra ID | PowerShell | Incident Response, Investigation, Administration |
| [Exchange Online](../../platforms/microsoft-365/exchange.md) | Entry | Microsoft 365, Exchange Online | PowerShell | Incident Response, Investigation, Administration |
| [Hyper-V](../../platforms/virtualization/hyper-v.md) | Entry | Hyper-V, Windows Server | PowerShell | Administration, Incident Response, Forensics |
| [Intune](../../platforms/microsoft-365/intune.md) | Entry | Microsoft 365, Intune, Windows | PowerShell, Windows CLI | Administration, Troubleshooting, Incident Response |
| [KQL Logon and Identity Hunting](../../detection/kql/logon-identity.md) | Entry | Microsoft Defender, Entra ID, Microsoft 365, Windows | KQL | Threat Hunting, Investigation, Incident Response, Detection Engineering |
| [KQL Network Event Hunting](../../detection/kql/network-events.md) | Entry | Microsoft Defender, Windows | KQL | Threat Hunting, Investigation, Detection Engineering, Incident Response |
| [KQL Process Event Hunting](../../detection/kql/process-events.md) | Entry | Microsoft Defender, Windows | KQL | Threat Hunting, Detection Engineering, Investigation, Incident Response |
| [Linux Cron and Scheduled Jobs](../../platforms/linux/cron.md) | Entry | Linux | Bash | Incident Response, Investigation, Threat Hunting, Administration |
| [Linux Filesystem](../../platforms/linux/filesystem.md) | Entry | Linux | Bash | Incident Response, Investigation, Forensics, Troubleshooting |
| [Linux Logs](../../platforms/linux/logs.md) | Entry | Linux | Bash | Incident Response, Investigation, Troubleshooting, Forensics |
| [Linux Networking and DNS](../../platforms/linux/networking.md) | Entry | Linux | Bash | Incident Response, Investigation, Troubleshooting, Administration |
| [Linux Processes](../../platforms/linux/processes.md) | Entry | Linux | Bash | Incident Response, Investigation, Troubleshooting, Forensics |
| [Linux Services with systemd](../../platforms/linux/systemd.md) | Entry | Linux | Bash | Administration, Troubleshooting, Incident Response, Investigation |
| [Linux SSH](../../platforms/linux/ssh.md) | Entry | Linux | Bash | Incident Response, Investigation, Hardening, Administration |
| [Linux System Information](../../platforms/linux/system-information.md) | Entry | Linux | Bash | Incident Response, Administration, Troubleshooting |
| [Linux Users and Permissions](../../platforms/linux/users-permissions.md) | Entry | Linux | Bash | Incident Response, Investigation, Administration, Hardening |
| [Microsoft Defender Antivirus](../../platforms/windows/defender.md) | Entry | Windows, Windows Server, Microsoft Defender | PowerShell, Windows CLI | Incident Response, Administration, Hardening, Troubleshooting |
| [Microsoft Defender XDR and Defender for Endpoint](../../platforms/microsoft-365/defender.md) | Entry | Microsoft 365, Microsoft Defender, Windows | PowerShell, KQL | Incident Response, Threat Hunting, Administration, Automation |
| [PowerShell Automation and Remoting](../../languages/powershell/automation.md) | Entry | Windows, Windows Server | PowerShell | Automation, Incident Response, Administration |
| [PowerShell REST APIs](../../languages/powershell/rest-apis.md) | Entry | Windows, Microsoft 365, SentinelOne, Splunk | PowerShell | Automation, Incident Response |
| [Proxmox VE](../../platforms/virtualization/proxmox.md) | Entry | Proxmox, Linux | Bash | Administration, Incident Response, Forensics |
| [Python HTTP and APIs](../../languages/python/http-apis.md) | Entry | Microsoft 365, SentinelOne, Splunk | Python | Automation, Incident Response |
| [Python Subprocess and Filesystem](../../languages/python/subprocess-filesystem.md) | Entry | Linux, Windows | Python | Automation, Forensics, Incident Response |
| [S1QL Hunting Queries](../../detection/s1ql/hunting.md) | Entry | SentinelOne, Windows, Linux | S1QL | Threat Hunting, Incident Response, Investigation |
| [SPL PowerShell Hunting](../../detection/spl/powershell.md) | Entry | Splunk, Windows | SPL | Threat Hunting, Detection Engineering, Incident Response |
| [SPL Windows Security Events](../../detection/spl/windows-events.md) | Entry | Splunk, Windows | SPL | Threat Hunting, Detection Engineering, Investigation, Incident Response |
| [VMware vSphere and ESXi](../../platforms/virtualization/vmware.md) | Entry | VMware | PowerShell, Bash | Administration, Incident Response, Forensics |
| [Windows Event Logs](../../platforms/windows/event-logs.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Forensics, Hardening |
| [Windows Files and Permissions](../../platforms/windows/files-directories.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Forensics, Hardening |
| [Windows Firewall](../../platforms/windows/firewall.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Administration, Hardening, Incident Response, Troubleshooting |
| [Windows Installed Software](../../platforms/windows/software.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Investigation, Administration, Incident Response |
| [Windows Networking and DNS](../../platforms/windows/networking.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Troubleshooting, Administration |
| [Windows Processes](../../platforms/windows/processes.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Troubleshooting, Forensics |
| [Windows Registry and Run Keys](../../platforms/windows/registry.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Forensics, Threat Hunting |
| [Windows Scheduled Tasks](../../platforms/windows/scheduled-tasks.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Threat Hunting, Administration |
| [Windows Server Notes](../../platforms/windows/windows-server.md) | Entry | Windows Server | PowerShell, Windows CLI | Administration, Incident Response, Troubleshooting |
| [Windows Services](../../platforms/windows/services.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Administration, Hardening |
| [Windows System Information](../../platforms/windows/system-information.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Administration, Troubleshooting |
| [Windows Users and Groups](../../platforms/windows/users-groups.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Administration, Hardening |
| [Bash Toolbox](../../toolbox/bash.md) | Tool | Linux | Bash | Automation, Incident Response, Forensics, Investigation |
| [PowerShell Toolbox](../../toolbox/powershell.md) | Tool | Windows, Windows Server | PowerShell | Automation, Incident Response, Forensics, Investigation |
| [Python Toolbox](../../toolbox/python.md) | Tool | Windows, Linux, Microsoft 365, SentinelOne | Python | Automation, Incident Response, Investigation |
| [Cross-Platform Equivalents](../../references/equivalents.md) | Reference | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting, Administration |
| [MITRE ATT&CK Mapping](../../detection/mitre-attack/index.md) | Reference | Windows, Linux, Microsoft 365 | MITRE ATT&CK | Detection Engineering, Threat Hunting, Incident Response |
| [Windows Event ID Reference](../../references/windows-event-ids.md) | Reference | Windows, Windows Server | PowerShell, SPL, KQL | Investigation, Incident Response, Detection Engineering, Forensics |

<!-- /cc:index -->

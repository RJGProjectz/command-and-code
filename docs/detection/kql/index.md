---
title: KQL
type: index
---

# KQL — Kusto Query Language

Used by **Microsoft Defender XDR advanced hunting** and **Microsoft Sentinel**.

| Page | Covers |
| --- | --- |
| [Fundamentals](fundamentals.md) | operators, time filtering, summarize, joins, parsing, dynamic data |
| [Process events](process-events.md) | `DeviceProcessEvents` — PowerShell, LOLBins, Office children, process trees |
| [Network events](network-events.md) | `DeviceNetworkEvents` — listeners, outbound, beaconing, RDP, DNS |
| [File and registry events](file-registry-events.md) | `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceEvents` — persistence |
| [Logons and identity](logon-identity.md) | `DeviceLogonEvents`, `IdentityLogonEvents`, `SigninLogs`, `AuditLogs` |

## Everything tagged KQL

<!-- cc:index languages="KQL" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Account Compromise Investigation](../../tasks/incident-response/account-compromise.md) | Workflow | Entra ID, Exchange Online, Microsoft 365, Windows | PowerShell, KQL | Incident Response, Investigation |
| [Failed Authentication Investigation](../../tasks/investigation/failed-authentication.md) | Workflow | Windows, Windows Server, Linux, Entra ID, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Troubleshooting |
| [Investigation Playbook — Azure Resource Hijacking](../../tasks/incident-response/azure-resource-hijacking.md) | Workflow | Azure, Microsoft 365 | KQL, PowerShell | Incident Response, Investigation |
| [Investigation Playbook — Compromised Service Principal](../../tasks/incident-response/compromised-service-principal.md) | Workflow | Entra ID, Azure | KQL, PowerShell | Incident Response, Investigation |
| [Investigation Playbook — Phishing Email Triage](../../tasks/incident-response/phishing-email-triage.md) | Workflow | Microsoft 365, Exchange Online | PowerShell, KQL | Incident Response, Investigation |
| [Malware Triage](../../tasks/incident-response/malware-triage.md) | Workflow | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Incident Response, Forensics |
| [Network Investigation](../../tasks/investigation/network-investigation.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Possible Lateral Movement](../../tasks/threat-hunting/lateral-movement.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk | PowerShell, KQL, SPL | Threat Hunting, Incident Response, Investigation |
| [Registry Persistence Investigation](../../tasks/investigation/registry-persistence.md) | Workflow | Windows, Microsoft Defender, SentinelOne | PowerShell, Windows CLI, KQL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Scheduled Task Investigation](../../tasks/investigation/scheduled-task-investigation.md) | Workflow | Windows, Microsoft Defender, Splunk, SentinelOne | PowerShell, Windows CLI, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Suspicious Outbound Connection](../../tasks/investigation/suspicious-outbound-connection.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Threat Hunting |
| [Suspicious PowerShell Investigation](../../tasks/incident-response/suspicious-powershell.md) | Workflow | Windows, Microsoft Defender, Splunk, SentinelOne | PowerShell, KQL, SPL, S1QL | Incident Response, Investigation |
| [Suspicious Process Investigation](../../tasks/incident-response/suspicious-process.md) | Workflow | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Incident Response, Investigation |
| [Suspicious Service Investigation](../../tasks/investigation/suspicious-service.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk | PowerShell, Windows CLI, KQL, SPL | Investigation, Incident Response |
| [Conditional Access](../../platforms/microsoft-365/conditional-access.md) | Entry | Microsoft 365, Entra ID | PowerShell, KQL | Administration, Hardening, Investigation, Troubleshooting |
| [KQL File, Registry and Persistence Hunting](file-registry-events.md) | Entry | Microsoft Defender, Windows | KQL | Threat Hunting, Detection Engineering, Investigation |
| [KQL Fundamentals](fundamentals.md) | Entry | Microsoft Defender, Microsoft 365 | KQL | Threat Hunting, Detection Engineering, Investigation |
| [KQL Logon and Identity Hunting](logon-identity.md) | Entry | Microsoft Defender, Entra ID, Microsoft 365, Windows | KQL | Threat Hunting, Investigation, Incident Response, Detection Engineering |
| [KQL Network Event Hunting](network-events.md) | Entry | Microsoft Defender, Windows | KQL | Threat Hunting, Investigation, Detection Engineering, Incident Response |
| [KQL Process Event Hunting](process-events.md) | Entry | Microsoft Defender, Windows | KQL | Threat Hunting, Detection Engineering, Investigation, Incident Response |
| [Microsoft Defender XDR and Defender for Endpoint](../../platforms/microsoft-365/defender.md) | Entry | Microsoft 365, Microsoft Defender, Windows | PowerShell, KQL | Incident Response, Threat Hunting, Administration, Automation |
| [Cross-Platform Equivalents](../../references/equivalents.md) | Reference | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting, Administration |
| [Knowledge Graph Efficacy & Operational Coverage Matrix](../../references/coverage-matrix.md) | Reference | Windows, Windows Server, Linux, Azure, Entra ID, Microsoft Defender, SentinelOne, Splunk | PowerShell, Bash, Python, KQL, SPL, S1QL, REST API | Administration, Incident Response, Threat Hunting, Detection Engineering, Hardening, Assurance, Governance |
| [MITRE ATT&CK® Enterprise Matrix & Navigator Coverage](../../references/mitre-attack-matrix.md) | Reference | Windows, Linux, Azure, Entra ID, Microsoft Defender, SentinelOne, Splunk | KQL, SPL, S1QL, PowerShell, Bash | Detection Engineering, Incident Response, Threat Hunting, Hardening |
| [Windows Event ID Reference](../../references/windows-event-ids.md) | Reference | Windows, Windows Server | PowerShell, SPL, KQL | Investigation, Incident Response, Detection Engineering, Forensics |

<!-- /cc:index -->

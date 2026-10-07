---
title: Threat Hunting
type: index
---

# Threat Hunting

Hypothesis-driven searches for activity your detections have not alerted on.

## Workflows

<!-- cc:index tasks="Threat Hunting" type="workflow" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Investigation Playbook — SMB Lateral Movement](../incident-response/smb-lateral-movement.md) | Workflow | Windows, Windows Server | PowerShell, SPL | Incident Response, Threat Hunting |
| [Investigation Workflow — Suspicious IP Address Analysis in Splunk](../investigation/investigate-ip-splunk.md) | Workflow | Splunk, Windows, Linux | SPL | Investigation, Threat Hunting |
| [Network Investigation](../investigation/network-investigation.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Possible Lateral Movement](lateral-movement.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk | PowerShell, KQL, SPL | Threat Hunting, Incident Response, Investigation |
| [Registry Persistence Investigation](../investigation/registry-persistence.md) | Workflow | Windows, Microsoft Defender, SentinelOne | PowerShell, Windows CLI, KQL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Scheduled Task Investigation](../investigation/scheduled-task-investigation.md) | Workflow | Windows, Microsoft Defender, Splunk, SentinelOne | PowerShell, Windows CLI, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Suspicious Outbound Connection](../investigation/suspicious-outbound-connection.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Threat Hunting |
| [Threat Hunting — Hypothesis-Driven SIEM Hunting in Splunk](splunk-threat-hunting.md) | Workflow | Splunk, Windows, Linux | SPL | Threat Hunting, Detection Engineering |

<!-- /cc:index -->

## Reference entries

<!-- cc:index tasks="Threat Hunting" type="entry|tool|reference" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Bash Text Processing](../../languages/bash/text-processing.md) | Entry | Linux | Bash | Investigation, Automation, Threat Hunting |
| [Fundamentals — Sysmon Telemetry & Endpoint Monitoring](../../fundamentals/systems/sysmon.md) | Entry | Windows, Linux | PowerShell, Bash | Threat Hunting, Detection Engineering |
| [KQL File, Registry and Persistence Hunting](../../detection/kql/file-registry-events.md) | Entry | Microsoft Defender, Windows | KQL | Threat Hunting, Detection Engineering, Investigation |
| [KQL Fundamentals](../../detection/kql/fundamentals.md) | Entry | Microsoft Defender, Microsoft 365 | KQL | Threat Hunting, Detection Engineering, Investigation |
| [KQL Logon and Identity Hunting](../../detection/kql/logon-identity.md) | Entry | Microsoft Defender, Entra ID, Microsoft 365, Windows | KQL | Threat Hunting, Investigation, Incident Response, Detection Engineering |
| [KQL Network Event Hunting](../../detection/kql/network-events.md) | Entry | Microsoft Defender, Windows | KQL | Threat Hunting, Investigation, Detection Engineering, Incident Response |
| [KQL Process Event Hunting](../../detection/kql/process-events.md) | Entry | Microsoft Defender, Windows | KQL | Threat Hunting, Detection Engineering, Investigation, Incident Response |
| [Linux Cron and Scheduled Jobs](../../platforms/linux/cron.md) | Entry | Linux | Bash | Incident Response, Investigation, Threat Hunting, Administration |
| [Microsoft Defender XDR and Defender for Endpoint](../../platforms/microsoft-365/defender.md) | Entry | Microsoft 365, Microsoft Defender, Windows | PowerShell, KQL | Incident Response, Threat Hunting, Administration, Automation |
| [Microsoft Graph API — Audit Sign-In Logs](../../apis/microsoft-graph/sign-in-logs.md) | Entry | Entra ID, Microsoft 365 | PowerShell, REST API | Investigation, Threat Hunting, Incident Response |
| [S1QL Fundamentals](../../detection/s1ql/fundamentals.md) | Entry | SentinelOne | S1QL | Threat Hunting, Investigation, Detection Engineering |
| [S1QL Hunting Queries](../../detection/s1ql/hunting.md) | Entry | SentinelOne, Windows, Linux | S1QL | Threat Hunting, Incident Response, Investigation |
| [SentinelOne API — Query Threats](../../apis/sentinelone/threats.md) | Entry | SentinelOne | PowerShell, Bash, REST API | Incident Response, Threat Hunting |
| [Sigma Rule Examples](../../detection/sigma/examples.md) | Entry | Windows | Sigma | Detection Engineering, Threat Hunting |
| [SPL Fundamentals and Search Optimization](../../detection/spl/fundamentals.md) | Entry | Splunk | SPL | Threat Hunting, Detection Engineering, Investigation |
| [SPL Network and DNS Hunting](../../detection/spl/network-dns.md) | Entry | Splunk | SPL | Threat Hunting, Investigation, Detection Engineering |
| [SPL PowerShell Hunting](../../detection/spl/powershell.md) | Entry | Splunk, Windows | SPL | Threat Hunting, Detection Engineering, Incident Response |
| [SPL Windows Security Events](../../detection/spl/windows-events.md) | Entry | Splunk, Windows | SPL | Threat Hunting, Detection Engineering, Investigation, Incident Response |
| [Splunk Detection — AMSI Bypass Attempts](../../detection/spl/amsi-bypass.md) | Entry | Windows, Splunk | SPL, PowerShell | Detection Engineering, Threat Hunting |
| [Splunk Detection — Brute Force Success Correlation](../../detection/spl/brute-force.md) | Entry | Windows, Windows Server, Splunk | SPL | Detection Engineering, Threat Hunting |
| [Splunk Detection — Suspicious Azure RBAC Modification](../../detection/spl/azure-rbac-modification.md) | Entry | Azure, Splunk | SPL | Detection Engineering, Threat Hunting |
| [Splunk Detection — Suspicious DNS Tunneling Signatures](../../detection/spl/dns-tunneling.md) | Entry | Splunk | SPL | Detection Engineering, Threat Hunting |
| [Splunk Detection — Suspicious MFA Authentication Method Deletion](../../detection/spl/mfa-deletion.md) | Entry | Entra ID, Microsoft 365, Splunk | SPL | Detection Engineering, Threat Hunting |
| [Splunk Detection — Suspicious SMB Administrative Share Access](../../detection/spl/lateral-movement-smb.md) | Entry | Windows, Windows Server, Splunk | SPL | Detection Engineering, Threat Hunting |
| [Windows Registry and Run Keys](../../platforms/windows/registry.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Forensics, Threat Hunting |
| [Windows Scheduled Tasks](../../platforms/windows/scheduled-tasks.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Threat Hunting, Administration |
| [Cross-Platform Equivalents](../../references/equivalents.md) | Reference | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting, Administration |
| [Knowledge Graph Efficacy & Operational Coverage Matrix](../../references/coverage-matrix.md) | Reference | Windows, Windows Server, Linux, Azure, Entra ID, Microsoft Defender, SentinelOne, Splunk | PowerShell, Bash, Python, KQL, SPL, S1QL, REST API | Administration, Incident Response, Threat Hunting, Detection Engineering, Hardening, Assurance, Governance |
| [MITRE ATT&CK Mapping](../../detection/mitre-attack/index.md) | Reference | Windows, Linux, Microsoft 365 | MITRE ATT&CK | Detection Engineering, Threat Hunting, Incident Response |

<!-- /cc:index -->

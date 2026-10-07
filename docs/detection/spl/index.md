---
title: SPL
type: index
---

# SPL — Splunk Search Processing Language

| Page | Covers |
| --- | --- |
| [Fundamentals and optimization](fundamentals.md) | search shape, speed rules, common commands, `tstats`, first-seen |
| [Windows security events](windows-events.md) | authentication, process creation, services, tasks, account changes, log clearing, Defender |
| [PowerShell](powershell.md) | 4104 script blocks, encoded commands, downgrade |
| [Network and DNS](network-dns.md) | CIM network traffic, rare destinations, DNS, beaconing |

!!! note "Environment-specific"
    Splunk field names depend on the add-ons and rendering mode you deploy. Detection pages are marked **Unverified** until checked against your indexes — update `verified` and `last_verified` once tested.

## Everything tagged SPL

<!-- cc:index languages="SPL" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Failed Authentication Investigation](../../tasks/investigation/failed-authentication.md) | Workflow | Windows, Windows Server, Linux, Entra ID, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Troubleshooting |
| [Investigation Playbook — SMB Lateral Movement](../../tasks/incident-response/smb-lateral-movement.md) | Workflow | Windows, Windows Server | PowerShell, SPL | Incident Response, Threat Hunting |
| [Investigation Workflow — Compromised Host Forensics in Splunk](../../tasks/investigation/investigate-device-splunk.md) | Workflow | Splunk, Windows, Windows Server | SPL | Investigation, Forensics, Incident Response |
| [Investigation Workflow — Compromised User Identity Triage in Splunk](../../tasks/investigation/investigate-user-splunk.md) | Workflow | Splunk, Windows, Entra ID | SPL | Investigation, Incident Response |
| [Investigation Workflow — Suspicious IP Address Analysis in Splunk](../../tasks/investigation/investigate-ip-splunk.md) | Workflow | Splunk, Windows, Linux | SPL | Investigation, Threat Hunting |
| [Network Investigation](../../tasks/investigation/network-investigation.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Possible Lateral Movement](../../tasks/threat-hunting/lateral-movement.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk | PowerShell, KQL, SPL | Threat Hunting, Incident Response, Investigation |
| [Scheduled Task Investigation](../../tasks/investigation/scheduled-task-investigation.md) | Workflow | Windows, Microsoft Defender, Splunk, SentinelOne | PowerShell, Windows CLI, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Suspicious Outbound Connection](../../tasks/investigation/suspicious-outbound-connection.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Threat Hunting |
| [Suspicious PowerShell Investigation](../../tasks/incident-response/suspicious-powershell.md) | Workflow | Windows, Microsoft Defender, Splunk, SentinelOne | PowerShell, KQL, SPL, S1QL | Incident Response, Investigation |
| [Suspicious Service Investigation](../../tasks/investigation/suspicious-service.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk | PowerShell, Windows CLI, KQL, SPL | Investigation, Incident Response |
| [Threat Hunting — Hypothesis-Driven SIEM Hunting in Splunk](../../tasks/threat-hunting/splunk-threat-hunting.md) | Workflow | Splunk, Windows, Linux | SPL | Threat Hunting, Detection Engineering |
| [SPL Fundamentals and Search Optimization](fundamentals.md) | Entry | Splunk | SPL | Threat Hunting, Detection Engineering, Investigation |
| [SPL Network and DNS Hunting](network-dns.md) | Entry | Splunk | SPL | Threat Hunting, Investigation, Detection Engineering |
| [SPL PowerShell Hunting](powershell.md) | Entry | Splunk, Windows | SPL | Threat Hunting, Detection Engineering, Incident Response |
| [SPL Windows Security Events](windows-events.md) | Entry | Splunk, Windows | SPL | Threat Hunting, Detection Engineering, Investigation, Incident Response |
| [Splunk Detection — AMSI Bypass Attempts](amsi-bypass.md) | Entry | Windows, Splunk | SPL, PowerShell | Detection Engineering, Threat Hunting |
| [Splunk Detection — Brute Force Success Correlation](brute-force.md) | Entry | Windows, Windows Server, Splunk | SPL | Detection Engineering, Threat Hunting |
| [Splunk Detection — Security Agent Tampering & EDR Impairment](agent-tampering.md) | Entry | Windows, Linux, SentinelOne, Splunk | SPL | Detection Engineering, Incident Response |
| [Splunk Detection — Suspicious Azure RBAC Modification](azure-rbac-modification.md) | Entry | Azure, Splunk | SPL | Detection Engineering, Threat Hunting |
| [Splunk Detection — Suspicious DNS Tunneling Signatures](dns-tunneling.md) | Entry | Splunk | SPL | Detection Engineering, Threat Hunting |
| [Splunk Detection — Suspicious MFA Authentication Method Deletion](mfa-deletion.md) | Entry | Entra ID, Microsoft 365, Splunk | SPL | Detection Engineering, Threat Hunting |
| [Splunk Detection — Suspicious SMB Administrative Share Access](lateral-movement-smb.md) | Entry | Windows, Windows Server, Splunk | SPL | Detection Engineering, Threat Hunting |
| [Cross-Platform Equivalents](../../references/equivalents.md) | Reference | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting, Administration |
| [Knowledge Graph Efficacy & Operational Coverage Matrix](../../references/coverage-matrix.md) | Reference | Windows, Windows Server, Linux, Azure, Entra ID, Microsoft Defender, SentinelOne, Splunk | PowerShell, Bash, Python, KQL, SPL, S1QL, REST API | Administration, Incident Response, Threat Hunting, Detection Engineering, Hardening, Assurance, Governance |
| [Windows Event ID Reference](../../references/windows-event-ids.md) | Reference | Windows, Windows Server | PowerShell, SPL, KQL | Investigation, Incident Response, Detection Engineering, Forensics |

<!-- /cc:index -->

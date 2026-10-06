---
title: Tasks
type: index
---

# Browse by Task

Start from what you are trying to accomplish. **Workflows** are ordered field procedures that link to the reference entries — they never duplicate the commands.

<div class="grid cards" markdown>

-   :material-alarm-light-outline:{ .lg } **[Incident Response](incident-response/index.md)**

    ---

    Endpoint triage, suspicious PowerShell and processes, malware, account compromise.

-   :material-magnify:{ .lg } **[Investigation](investigation/index.md)**

    ---

    Services, scheduled tasks, registry persistence, failed authentication, network and outbound connections.

-   :material-crosshairs-gps:{ .lg } **[Threat Hunting](threat-hunting/index.md)**

    ---

    Hypothesis-driven hunts such as lateral movement.

-   :material-wrench-outline:{ .lg } **[Troubleshooting](troubleshooting/index.md)**

    ---

    Connectivity, failing services, reboots, policy and time problems.

-   :material-cog-outline:{ .lg } **[Administration](administration/index.md)**

    ---

    Accounts, services, firewall, Microsoft 365 and hypervisor administration.

-   :material-radar:{ .lg } **[Detection Engineering](detection-engineering/index.md)**

    ---

    KQL, SPL, S1QL and Sigma detection content.

-   :material-shield-lock-outline:{ .lg } **[Hardening](hardening/index.md)**

    ---

    Logging, auditing, firewall and SSH configuration.

-   :material-fingerprint:{ .lg } **[Forensics](forensics/index.md)**

    ---

    Evidence preservation and artefacts.

-   :material-robot-outline:{ .lg } **[Automation](automation/index.md)**

    ---

    Scripting patterns, APIs and toolbox scripts.

</div>

## All workflows

<!-- cc:index type="workflow" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Account Compromise Investigation](incident-response/account-compromise.md) | Workflow | Entra ID, Exchange Online, Microsoft 365, Windows | PowerShell, KQL | Incident Response, Investigation |
| [Administration — BitLocker Key Retrieval & Status Audit](administration/bitlocker-recovery.md) | Workflow | Windows, Active Directory | PowerShell | Administration, Troubleshooting |
| [Administration — Disk Space Capacity Audit & Reporting](administration/disk-space-audit.md) | Workflow | Windows Server, Windows | PowerShell | Administration, Troubleshooting |
| [Administration — Group Policy Force Refresh & Diagnostic Audit](administration/group-policy-update.md) | Workflow | Windows, Active Directory | PowerShell | Administration, Troubleshooting |
| [Administration — Remote Service Restart & Dependency Validation](administration/remote-service-restart.md) | Workflow | Windows Server, Windows | PowerShell | Administration, Troubleshooting |
| [Administration — Safe Temporary File Purging](administration/temp-file-cleanup.md) | Workflow | Windows Server, Windows | PowerShell | Administration, Troubleshooting |
| [Backup and Recovery Operations](administration/backup-and-recovery.md) | Workflow | Hyper-V, VMware, Proxmox, Windows Server, Linux | PowerShell, Bash | Administration, Forensics |
| [Certificate and PKI Management](administration/certificate-and-pki-management.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Administration, Hardening |
| [Endpoint Triage](incident-response/endpoint-triage.md) | Workflow | Windows, Linux | PowerShell, Bash | Incident Response, Forensics |
| [Failed Authentication Investigation](investigation/failed-authentication.md) | Workflow | Windows, Windows Server, Linux, Entra ID, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Troubleshooting |
| [Incident Response — Automated Multi-Vector Containment Runbook](incident-response/automated-containment.md) | Workflow | Windows, Microsoft 365, Entra ID, Microsoft Defender, SentinelOne | PowerShell | Incident Response, Automation |
| [Investigation Playbook — Azure Resource Hijacking](incident-response/azure-resource-hijacking.md) | Workflow | Azure, Microsoft 365 | KQL, PowerShell | Incident Response, Investigation |
| [Investigation Playbook — Compromised Service Principal](incident-response/compromised-service-principal.md) | Workflow | Entra ID, Azure | KQL, PowerShell | Incident Response, Investigation |
| [Investigation Playbook — Phishing Email Triage](incident-response/phishing-email-triage.md) | Workflow | Microsoft 365, Exchange Online | PowerShell, KQL | Incident Response, Investigation |
| [Investigation Playbook — Ransomware Host Isolation](incident-response/ransomware-host-isolation.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Incident Response |
| [Investigation Playbook — SMB Lateral Movement](incident-response/smb-lateral-movement.md) | Workflow | Windows, Windows Server | PowerShell, SPL | Incident Response, Threat Hunting |
| [Investigation Workflow — Compromised Host Forensics in Splunk](investigation/investigate-device-splunk.md) | Workflow | Splunk, Windows, Windows Server | SPL | Investigation, Forensics, Incident Response |
| [Investigation Workflow — Compromised User Identity Triage in Splunk](investigation/investigate-user-splunk.md) | Workflow | Splunk, Windows, Entra ID | SPL | Investigation, Incident Response |
| [Investigation Workflow — Suspicious IP Address Analysis in Splunk](investigation/investigate-ip-splunk.md) | Workflow | Splunk, Windows, Linux | SPL | Investigation, Threat Hunting |
| [Linux Service Failure Troubleshooting](troubleshooting/linux-service-failure.md) | Workflow | Linux | Bash | Troubleshooting, Administration |
| [Malware Triage](incident-response/malware-triage.md) | Workflow | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Incident Response, Forensics |
| [Network Investigation](investigation/network-investigation.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Network Services Management](administration/network-services-management.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Administration, Troubleshooting |
| [Possible Lateral Movement](threat-hunting/lateral-movement.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk | PowerShell, KQL, SPL | Threat Hunting, Incident Response, Investigation |
| [Registry Persistence Investigation](investigation/registry-persistence.md) | Workflow | Windows, Microsoft Defender, SentinelOne | PowerShell, Windows CLI, KQL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Scheduled Task Investigation](investigation/scheduled-task-investigation.md) | Workflow | Windows, Microsoft Defender, Splunk, SentinelOne | PowerShell, Windows CLI, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Suspicious Outbound Connection](investigation/suspicious-outbound-connection.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Threat Hunting |
| [Suspicious PowerShell Investigation](incident-response/suspicious-powershell.md) | Workflow | Windows, Microsoft Defender, Splunk, SentinelOne | PowerShell, KQL, SPL, S1QL | Incident Response, Investigation |
| [Suspicious Process Investigation](incident-response/suspicious-process.md) | Workflow | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Incident Response, Investigation |
| [Suspicious Service Investigation](investigation/suspicious-service.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk | PowerShell, Windows CLI, KQL, SPL | Investigation, Incident Response |
| [System Maintenance and Updates](administration/system-maintenance-updates.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Administration, Automation |
| [Threat Hunting — Hypothesis-Driven SIEM Hunting in Splunk](threat-hunting/splunk-threat-hunting.md) | Workflow | Splunk, Windows, Linux | SPL | Threat Hunting, Detection Engineering |
| [Troubleshooting — Emergency Disk Space Exhaustion & Inode Recovery](troubleshooting/disk-space-emergency.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Troubleshooting, Administration |
| [Troubleshooting — High CPU Utilization & Runaway Processes](troubleshooting/high-cpu-troubleshooting.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Troubleshooting, Administration |
| [Troubleshooting — TLS/SSL Handshake & Certificate Failures](troubleshooting/certificate-handshake-failure.md) | Workflow | Linux, Windows, Windows Server | Bash, PowerShell | Troubleshooting, Investigation |
| [User Lifecycle Management](administration/user-lifecycle-management.md) | Workflow | Windows, Windows Server, Entra ID, Microsoft 365 | PowerShell | Administration, Hardening |
| [Windows Connectivity Troubleshooting](troubleshooting/windows-connectivity.md) | Workflow | Windows, Windows Server | PowerShell, Windows CLI | Troubleshooting |

<!-- /cc:index -->

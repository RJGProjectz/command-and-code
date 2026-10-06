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
| [Backup and Recovery Operations](administration/backup-and-recovery.md) | Workflow | Hyper-V, VMware, Proxmox, Windows Server, Linux | PowerShell, Bash | Administration, Forensics |
| [Certificate and PKI Management](administration/certificate-and-pki-management.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Administration, Hardening |
| [Endpoint Triage](incident-response/endpoint-triage.md) | Workflow | Windows, Linux | PowerShell, Bash | Incident Response, Forensics |
| [Failed Authentication Investigation](investigation/failed-authentication.md) | Workflow | Windows, Windows Server, Linux, Entra ID, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Troubleshooting |
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
| [User Lifecycle Management](administration/user-lifecycle-management.md) | Workflow | Windows, Windows Server, Entra ID, Microsoft 365 | PowerShell | Administration, Hardening |
| [Windows Connectivity Troubleshooting](troubleshooting/windows-connectivity.md) | Workflow | Windows, Windows Server | PowerShell, Windows CLI | Troubleshooting |

<!-- /cc:index -->

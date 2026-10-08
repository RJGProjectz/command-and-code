---
title: PowerShell
type: index
---

# PowerShell

PowerShell knowledge appears in two places:

- **Language pages** (below) — syntax, data handling, APIs, error handling, automation patterns.
- **Platform entries** tagged *PowerShell* — the actual operational commands for Windows, Microsoft 365 and virtualization.

Start with [Fundamentals and Pitfalls](fundamentals.md) — it covers the mistakes that break most scripts.

## Language pages

- [Fundamentals and Pitfalls](fundamentals.md)
- [JSON and CSV](json-csv.md)
- [REST APIs](rest-apis.md)
- [Error Handling](error-handling.md)
- [Automation and Remoting](automation.md)
- [PowerShell toolbox scripts](../../toolbox/powershell.md)

## Everything tagged PowerShell

<!-- cc:index languages="PowerShell" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Account Compromise Investigation](../../tasks/incident-response/account-compromise.md) | Workflow | Entra ID, Exchange Online, Microsoft 365, Windows | PowerShell, KQL | Incident Response, Investigation |
| [Active Directory Domain Services Administration](../../tasks/administration/active-directory-domain-management.md) | Workflow | Windows Server, Active Directory | PowerShell, CMD | Administration |
| [Administration — BitLocker Key Retrieval & Status Audit](../../tasks/administration/bitlocker-recovery.md) | Workflow | Windows, Active Directory | PowerShell, CMD | Administration, Troubleshooting |
| [Administration — Centralized Event Forwarding Pipeline (WEF & Rsyslog TLS)](../../tasks/administration/centralized-log-forwarding-wef-rsyslog.md) | Workflow | Windows Server, Windows, Linux | PowerShell, Bash | Administration, Hardening, Assurance |
| [Administration — Disk Space Capacity Audit & Reporting](../../tasks/administration/disk-space-audit.md) | Workflow | Windows Server, Windows | PowerShell, CMD | Administration, Troubleshooting |
| [Administration — Email Authentication Deployment (SPF, DKIM & DMARC)](../../tasks/administration/email-authentication-deployment.md) | Workflow | Linux, Microsoft 365 | Bash, PowerShell | Administration, Hardening, Investigation |
| [Administration — Group Policy Force Refresh & Diagnostic Audit](../../tasks/administration/group-policy-update.md) | Workflow | Windows, Active Directory | PowerShell, CMD | Administration, Troubleshooting |
| [Administration — Remote Service Restart & Dependency Validation](../../tasks/administration/remote-service-restart.md) | Workflow | Windows Server, Windows | PowerShell, CMD | Administration, Troubleshooting |
| [Administration — Safe Temporary File Purging](../../tasks/administration/temp-file-cleanup.md) | Workflow | Windows Server, Windows | PowerShell, CMD | Administration, Troubleshooting |
| [Administration — SSH Key Generation, Deployment & Best Practices](../../tasks/administration/ssh-key-deployment.md) | Workflow | Linux, Windows, Windows Server | Bash, PowerShell | Administration, Hardening |
| [Administration — Sysmon Enterprise Deployment & Telemetry Tuning](../../tasks/administration/sysmon-deployment-tuning.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Administration, Detection Engineering, Threat Hunting |
| [Administration — TLS/SSL Certificate Deployment & Web Server Hardening](../../tasks/administration/tls-certificate-deployment.md) | Workflow | Linux, Windows, Windows Server | Bash, PowerShell | Administration, Hardening |
| [Administration — WireGuard Secure VPN Gateway & Client Deployment](../../tasks/administration/wireguard-vpn-deployment.md) | Workflow | Linux, Windows | Bash, PowerShell | Administration, Hardening, Troubleshooting |
| [Automated Active Directory and Cloud Identity Containment](../../tasks/automation/automated-account-containment.md) | Workflow | Active Directory, Entra ID, Microsoft 365, Windows Server | PowerShell, REST API | Automation, Incident Response, Administration |
| [Automated IoC Enrichment and Threat Intelligence Pipeline](../../tasks/automation/automated-ioc-enrichment.md) | Workflow | Linux, Windows | PowerShell, Python, REST API | Automation, Incident Response, Investigation |
| [Azure Cloud Infrastructure and Resource Administration](../../tasks/administration/cloud-azure-resource-management.md) | Workflow | Azure, Entra ID | PowerShell, Bash | Administration |
| [Backup and Recovery Operations](../../tasks/administration/backup-and-recovery.md) | Workflow | Hyper-V, VMware, Proxmox, Windows Server, Linux | PowerShell, Bash | Administration, Forensics |
| [Certificate and PKI Management](../../tasks/administration/certificate-and-pki-management.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Administration, Hardening |
| [CISA SCuBA Microsoft 365 and Azure Baseline Compliance](../../tasks/assurance/cisa-scuba-compliance.md) | Workflow | Microsoft 365, Azure, Entra ID | PowerShell | Assurance, Compliance, Hardening |
| [Detection Development Lifecycle (DDLC) and Testing](../../tasks/detection-engineering/detection-development-lifecycle.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | KQL, SPL, S1QL, Sigma, PowerShell | Detection Engineering, Threat Hunting, Incident Response |
| [DNS Client Resolution and Troubleshooting](../../tasks/administration/dns-resolution-troubleshooting.md) | Workflow | Windows, Linux | PowerShell, CMD, Bash | Administration, Troubleshooting |
| [Endpoint Triage](../../tasks/incident-response/endpoint-triage.md) | Workflow | Windows, Linux | PowerShell, Bash | Incident Response, Forensics |
| [Failed Authentication Investigation](../../tasks/investigation/failed-authentication.md) | Workflow | Windows, Windows Server, Linux, Entra ID, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Troubleshooting |
| [Hardening — Active Directory Kerberos & LDAP Protocol Hardening](../../tasks/hardening/ad-kerberos-ldap-hardening.md) | Workflow | Windows Server, Active Directory | PowerShell | Hardening, Administration, Assurance |
| [Hardening — AppLocker & Application Control Phased Enterprise Rollout](../../tasks/hardening/applocker-deployment-rollout.md) | Workflow | Windows, Windows Server | PowerShell | Hardening, Administration, Assurance |
| [Host Firewall and Port Management](../../tasks/administration/firewall-port-management.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Hardening |
| [Host Performance and System Resource Auditing](../../tasks/administration/performance-resource-auditing.md) | Workflow | Windows, Linux | PowerShell, Bash, Python | Administration, Troubleshooting |
| [Hunting Cloud Identity Persistence in Entra ID and Microsoft 365](../../tasks/threat-hunting/cloud-identity-persistence-hunting.md) | Workflow | Entra ID, Microsoft 365, Azure, Microsoft Defender, Splunk | PowerShell, KQL, SPL | Threat Hunting, Incident Response, Investigation |
| [Hunting Kerberoasting and AS-REP Roasting in Active Directory](../../tasks/threat-hunting/kerberoasting-asreproast-hunting.md) | Workflow | Active Directory, Windows, Windows Server, Splunk, Microsoft Defender | PowerShell, KQL, SPL | Threat Hunting, Investigation, Incident Response |
| [Hunting Living-off-the-Land Binaries and Scripts (LOLBins)](../../tasks/threat-hunting/lolbins-execution-hunting.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk, SentinelOne | PowerShell, KQL, SPL, S1QL | Threat Hunting, Detection Engineering, Investigation |
| [Incident Response — Automated Multi-Vector Containment Runbook](../../tasks/incident-response/automated-containment.md) | Workflow | Windows, Microsoft 365, Entra ID, Microsoft Defender, SentinelOne | PowerShell | Incident Response, Automation |
| [Investigation Playbook — Azure Resource Hijacking](../../tasks/incident-response/azure-resource-hijacking.md) | Workflow | Azure, Microsoft 365 | KQL, PowerShell | Incident Response, Investigation |
| [Investigation Playbook — Compromised Service Principal](../../tasks/incident-response/compromised-service-principal.md) | Workflow | Entra ID, Azure | KQL, PowerShell | Incident Response, Investigation |
| [Investigation Playbook — Phishing Email Triage](../../tasks/incident-response/phishing-email-triage.md) | Workflow | Microsoft 365, Exchange Online | PowerShell, KQL | Incident Response, Investigation |
| [Investigation Playbook — Ransomware Host Isolation](../../tasks/incident-response/ransomware-host-isolation.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Incident Response |
| [Investigation Playbook — SMB Lateral Movement](../../tasks/incident-response/smb-lateral-movement.md) | Workflow | Windows, Windows Server | PowerShell, SPL | Incident Response, Threat Hunting |
| [Live Memory Acquisition and Volatility Analysis](../../tasks/forensics/memory-acquisition-analysis.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash, Python | Forensics, Incident Response, Investigation |
| [Local User and Group Administration](../../tasks/administration/local-user-group-management.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration |
| [Malware Triage](../../tasks/incident-response/malware-triage.md) | Workflow | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Incident Response, Forensics |
| [Microsoft Purview and Unified Audit Log (UAL) Investigation](../../platforms/microsoft-365/audit-log-investigation.md) | Workflow | Microsoft 365, Entra ID, Exchange Online | PowerShell | Investigation, Incident Response, Forensics |
| [Network Adapter and IP Configuration](../../tasks/administration/network-adapter-ip-configuration.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration |
| [Network Investigation](../../tasks/investigation/network-investigation.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Network Services Management](../../tasks/administration/network-services-management.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Troubleshooting |
| [Package and Software Lifecycle Management](../../tasks/administration/package-software-management.md) | Workflow | Windows, Linux | PowerShell, Bash, CMD | Administration |
| [Possible Lateral Movement](../../tasks/threat-hunting/lateral-movement.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk | PowerShell, KQL, SPL | Threat Hunting, Incident Response, Investigation |
| [Registry Persistence Investigation](../../tasks/investigation/registry-persistence.md) | Workflow | Windows, Microsoft Defender, SentinelOne | PowerShell, Windows CLI, KQL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Scheduled Task and Cron Job Automation](../../tasks/administration/scheduled-jobs-task-scheduler.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Automation |
| [Scheduled Task Investigation](../../tasks/investigation/scheduled-task-investigation.md) | Workflow | Windows, Microsoft Defender, Splunk, SentinelOne | PowerShell, Windows CLI, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Storage Partitioning, Formatting and Filesystem Mounting](../../tasks/administration/storage-partitioning-mounting.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration |
| [Suspicious Outbound Connection](../../tasks/investigation/suspicious-outbound-connection.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Threat Hunting |
| [Suspicious PowerShell Investigation](../../tasks/incident-response/suspicious-powershell.md) | Workflow | Windows, Microsoft Defender, Splunk, SentinelOne | PowerShell, KQL, SPL, S1QL | Incident Response, Investigation |
| [Suspicious Process Investigation](../../tasks/incident-response/suspicious-process.md) | Workflow | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Incident Response, Investigation |
| [Suspicious Service Investigation](../../tasks/investigation/suspicious-service.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk | PowerShell, Windows CLI, KQL, SPL | Investigation, Incident Response |
| [System Maintenance and Updates](../../tasks/administration/system-maintenance-updates.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Automation |
| [Troubleshooting — Emergency Disk Space Exhaustion & Inode Recovery](../../tasks/troubleshooting/disk-space-emergency.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Troubleshooting, Administration |
| [Troubleshooting — High CPU Utilization & Runaway Processes](../../tasks/troubleshooting/high-cpu-troubleshooting.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Troubleshooting, Administration |
| [Troubleshooting — TLS/SSL Handshake & Certificate Failures](../../tasks/troubleshooting/certificate-handshake-failure.md) | Workflow | Linux, Windows, Windows Server | Bash, PowerShell | Troubleshooting, Investigation |
| [User Lifecycle Management](../../tasks/administration/user-lifecycle-management.md) | Workflow | Windows, Windows Server, Entra ID, Microsoft 365 | PowerShell | Administration, Hardening |
| [Windows Connectivity Troubleshooting](../../tasks/troubleshooting/windows-connectivity.md) | Workflow | Windows, Windows Server | PowerShell, Windows CLI | Troubleshooting |
| [Assurance Check — Active Directory STIG Compliance](../../tasks/assurance/ad-stig-compliance.md) | Entry | Windows Server, Active Directory | PowerShell | Assurance, Hardening |
| [Assurance Check — Azure External Guest Access & Permissions](../../tasks/assurance/azure-guest-access-audit.md) | Entry | Entra ID, Azure, Microsoft 365 | PowerShell | Assurance, Hardening, Administration |
| [Assurance Check — Azure Network Security Group Compliance](../../tasks/assurance/azure-nsg-compliance.md) | Entry | Azure | PowerShell | Assurance, Hardening |
| [Assurance Check — Endpoint EDR Agent Health Status](../../tasks/assurance/endpoint-edr-status.md) | Entry | Windows, Linux | PowerShell | Assurance, Incident Response |
| [Assurance Check — Host Firewall Default Deny Stance](../../tasks/assurance/firewall-default-deny.md) | Entry | Windows, Linux | PowerShell, Bash | Assurance, Hardening |
| [Azure & Entra ID Security Baseline — CIS Benchmark & NIST CSF 2.0](../../tasks/hardening/cloud-azure-security-baseline.md) | Entry | Azure, Entra ID, Microsoft 365 | PowerShell, Bash | Hardening, Assurance, Governance |
| [Conditional Access](../../platforms/microsoft-365/conditional-access.md) | Entry | Microsoft 365, Entra ID | PowerShell, KQL | Administration, Hardening, Investigation, Troubleshooting |
| [Entra ID](../../platforms/microsoft-365/entra.md) | Entry | Microsoft 365, Entra ID | PowerShell | Incident Response, Investigation, Administration |
| [Exchange Online](../../platforms/microsoft-365/exchange.md) | Entry | Microsoft 365, Exchange Online | PowerShell | Incident Response, Investigation, Administration |
| [Finding Files & Content Discovery](../../tasks/administration/file-search-discovery.md) | Entry | Linux, Windows, Windows Server | Bash, PowerShell, CMD | Administration, Investigation, Forensics |
| [Fundamentals — API Security & Error Handling](../../fundamentals/apis/security-error-handling.md) | Entry | Linux, Windows | REST API, PowerShell, Python | Automation, Administration, Hardening |
| [Fundamentals — AppLocker & Application Control Baselines](../../fundamentals/systems/applocker.md) | Entry | Windows, Windows Server | PowerShell | Hardening, Administration |
| [Fundamentals — Authentication & Token Lifecycles](../../fundamentals/apis/auth-tokens.md) | Entry | Linux, Windows | REST API, PowerShell, Python | Automation, Administration, Hardening |
| [Fundamentals — Azure Policy & Governance Baselines](../../fundamentals/cloud/azure-policy.md) | Entry | Azure | PowerShell | Assurance, Hardening |
| [Fundamentals — Azure Virtual Network (VNet) Security](../../fundamentals/cloud/azure-vnet-security.md) | Entry | Azure | PowerShell | Hardening, Administration |
| [Fundamentals — CIS Critical Security Controls & Benchmarks](../../fundamentals/grc/cis-benchmarks.md) | Entry | Windows, Windows Server, Linux | PowerShell, Bash | Assurance, Hardening, Administration |
| [Fundamentals — Cross-Site Request Forgery (CSRF) & State Defense](../../fundamentals/web-apps/csrf-defense.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Investigation, Detection Engineering |
| [Fundamentals — Cross-Site Scripting (XSS) & Content Security Policy](../../fundamentals/web-apps/xss-defense.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Investigation, Detection Engineering |
| [Fundamentals — DHCP Protocol Mechanics & IP Allocation](../../fundamentals/networking/dhcp.md) | Entry | Windows Server, Linux | PowerShell, Bash | Troubleshooting, Administration |
| [Fundamentals — DNS Protocol Mechanics & Security](../../fundamentals/dns.md) | Entry | Windows Server, Linux | PowerShell, Bash | Investigation, Hardening |
| [Fundamentals — HTTP Security Headers & Transport Hardening](../../fundamentals/web-apps/http-security-headers.md) | Entry | Linux, Windows | HTTP, PowerShell, Bash | Hardening, Assurance, Troubleshooting |
| [Fundamentals — HTTP/HTTPS Protocol Mechanics & Headers](../../fundamentals/networking/http-https.md) | Entry | Linux, Windows Server | Bash, PowerShell | Investigation, Troubleshooting |
| [Fundamentals — Kerberos Authentication Protocol](../../fundamentals/kerberos.md) | Entry | Windows, Active Directory | PowerShell | Investigation, Hardening |
| [Fundamentals — LDAP Protocol, Directory Trees & LDAPS](../../fundamentals/identity/ldap.md) | Entry | Windows Server, Linux, Active Directory | PowerShell, Bash | Administration, Investigation |
| [Fundamentals — Microsoft Entra ID Architecture & Hybrid Identity](../../fundamentals/cloud/entra-id-fundamentals.md) | Entry | Entra ID, Microsoft 365 | PowerShell | Administration, Hardening |
| [Fundamentals — NIST Cybersecurity Framework (CSF) 2.0](../../fundamentals/grc/nist-csf-2.md) | Entry | Windows, Linux, Microsoft 365, Azure | PowerShell, Bash, Python | Assurance, Hardening, Administration, Incident Response |
| [Fundamentals — OAuth 2.0 Authorization & OIDC Mechanics](../../fundamentals/identity/oauth2.md) | Entry | Entra ID, Microsoft 365 | PowerShell | Automation, Investigation |
| [Fundamentals — OWASP Top 10 for Web Applications](../../fundamentals/web-apps/owasp-web-top-10.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Investigation, Detection Engineering |
| [Fundamentals — Pagination & High-Volume Ingestion](../../fundamentals/apis/pagination.md) | Entry | Linux, Windows | REST API, PowerShell, Python | Automation, Administration, Investigation |
| [Fundamentals — Public Key Infrastructure (PKI), CAs & Revocation](../../fundamentals/identity/pki.md) | Entry | Windows Server, Linux | PowerShell, Bash | Hardening, Administration |
| [Fundamentals — Rate Limiting & Exponential Backoff](../../fundamentals/apis/rate-limiting-backoff.md) | Entry | Linux, Windows | REST API, PowerShell, Python | Automation, Administration, Troubleshooting |
| [Fundamentals — Regulatory Compliance & Framework Cross-Walk](../../fundamentals/grc/regulatory-frameworks.md) | Entry | Windows, Linux, Azure, Microsoft 365 | PowerShell, Bash, Python | Assurance, Hardening, Administration |
| [Fundamentals — REST Architecture & HTTP Semantics](../../fundamentals/apis/rest-architecture.md) | Entry | Linux, Windows | REST API, PowerShell, Python | Automation, Administration, Troubleshooting |
| [Fundamentals — Server-Side Request Forgery (SSRF) & Egress Defense](../../fundamentals/web-apps/ssrf-defense.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Investigation, Detection Engineering |
| [Fundamentals — Session Management & Cookie Security](../../fundamentals/web-apps/session-management.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Administration, Investigation |
| [Fundamentals — SMB Protocol & Network Share Security](../../fundamentals/smb.md) | Entry | Windows, Windows Server, Linux | PowerShell | Investigation, Hardening |
| [Fundamentals — SMTP Protocol, Relays & Email Authentication](../../fundamentals/networking/smtp.md) | Entry | Linux, Microsoft 365 | PowerShell, Bash | Investigation, Hardening |
| [Fundamentals — SQL Injection & Parameterized Defense](../../fundamentals/web-apps/sql-injection.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Investigation, Detection Engineering |
| [Fundamentals — Sysmon Telemetry & Endpoint Monitoring](../../fundamentals/systems/sysmon.md) | Entry | Windows, Linux | PowerShell, Bash | Threat Hunting, Detection Engineering |
| [Fundamentals — TLS Handshake & Cipher Suite Mechanics](../../fundamentals/networking/tls-ssl.md) | Entry | Linux, Windows Server | Bash, PowerShell | Hardening, Investigation |
| [Fundamentals — UEFI Boot Sequence & Secure Boot Mechanics](../../fundamentals/systems/uefi-secure-boot.md) | Entry | Windows, Linux | PowerShell, Bash | Hardening, Assurance |
| [Fundamentals — Virtual Memory, Paging, Stack & Heap](../../fundamentals/systems/memory-internals.md) | Entry | Windows, Linux | PowerShell, Bash | Forensics, Investigation |
| [Fundamentals — VPN Protocols (IPsec vs SSL/TLS)](../../fundamentals/networking/vpn.md) | Entry | Windows, Linux | PowerShell, Bash | Troubleshooting, Hardening |
| [Fundamentals — Webhooks & Event-Driven Architecture](../../fundamentals/apis/webhooks-events.md) | Entry | Linux, Windows | REST API, PowerShell, Python | Automation, Administration, Incident Response |
| [Fundamentals — Windows Process Architecture, Tokens & Handles](../../fundamentals/systems/windows-processes.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Investigation, Forensics |
| [Fundamentals — Zero Trust Network Microsegmentation](../../fundamentals/networking/microsegmentation.md) | Entry | Linux, Windows Server | Bash, PowerShell | Hardening, Assurance |
| [Hyper-V](../../platforms/virtualization/hyper-v.md) | Entry | Hyper-V, Windows Server | PowerShell | Administration, Incident Response, Forensics |
| [Incoming Webhooks for Slack & Microsoft Teams](../../apis/webhooks/slack-teams-webhooks.md) | Entry | Microsoft 365 | PowerShell, Bash, REST API | Automation, Incident Response |
| [Intune](../../platforms/microsoft-365/intune.md) | Entry | Microsoft 365, Intune, Windows | PowerShell, Windows CLI | Administration, Troubleshooting, Incident Response |
| [Microsoft Defender Antivirus](../../platforms/windows/defender.md) | Entry | Windows, Windows Server, Microsoft Defender | PowerShell, Windows CLI | Incident Response, Administration, Hardening, Troubleshooting |
| [Microsoft Defender API — Get Alerts](../../apis/microsoft-defender/get-alerts.md) | Entry | Microsoft Defender, Microsoft 365 | PowerShell, REST API | Incident Response, Automation |
| [Microsoft Defender API — Trigger Antivirus Scan](../../apis/microsoft-defender/antivirus-scan.md) | Entry | Microsoft Defender, Windows | PowerShell, REST API | Incident Response, Automation |
| [Microsoft Defender XDR and Defender for Endpoint](../../platforms/microsoft-365/defender.md) | Entry | Microsoft 365, Microsoft Defender, Windows | PowerShell, KQL | Incident Response, Threat Hunting, Administration, Automation |
| [Microsoft Graph API — Audit Sign-In Logs](../../apis/microsoft-graph/sign-in-logs.md) | Entry | Entra ID, Microsoft 365 | PowerShell, REST API | Investigation, Threat Hunting, Incident Response |
| [Microsoft Graph API — Conditional Access Policies](../../apis/microsoft-graph/conditional-access.md) | Entry | Entra ID, Microsoft 365 | PowerShell, REST API | Administration, Hardening, Assurance |
| [Microsoft Graph API — User Authentication Methods](../../apis/microsoft-graph/user-auth-methods.md) | Entry | Entra ID, Microsoft 365 | PowerShell, REST API | Administration, Incident Response, Hardening |
| [OAuth 2.0 Bearer Token Authentication Flow](../../apis/authentication/bearer-tokens.md) | Entry | Entra ID, Microsoft 365 | PowerShell, Bash, REST API | Automation, Administration |
| [PowerShell Automation and Remoting](automation.md) | Entry | Windows, Windows Server | PowerShell | Automation, Incident Response, Administration |
| [PowerShell Error Handling](error-handling.md) | Entry | Windows, Windows Server | PowerShell | Automation |
| [PowerShell Fundamentals and Pitfalls](fundamentals.md) | Entry | Windows, Windows Server | PowerShell | Automation, Administration |
| [PowerShell JSON and CSV](json-csv.md) | Entry | Windows, Windows Server | PowerShell | Automation, Investigation |
| [PowerShell REST APIs](rest-apis.md) | Entry | Windows, Microsoft 365, SentinelOne, Splunk | PowerShell | Automation, Incident Response |
| [Remote File Transfer — SCP, SFTP, rsync & WinRM](../../tasks/administration/remote-file-transfer.md) | Entry | Linux, Windows, Windows Server | Bash, PowerShell, CMD | Administration, Automation, Incident Response |
| [REST APIs — Jira & ServiceNow Security Incident Creation](../../apis/webhooks/jira-servicenow-incident-creation.md) | Entry | Linux, Windows | PowerShell, Python, REST API | Automation, Incident Response |
| [SentinelOne API — Network Host Isolation](../../apis/sentinelone/isolate-host.md) | Entry | SentinelOne | PowerShell, REST API | Incident Response, Automation |
| [SentinelOne API — Query Threats](../../apis/sentinelone/threats.md) | Entry | SentinelOne | PowerShell, Bash, REST API | Incident Response, Threat Hunting |
| [Splunk Detection — AMSI Bypass Attempts](../../detection/spl/amsi-bypass.md) | Entry | Windows, Splunk | SPL, PowerShell | Detection Engineering, Threat Hunting |
| [Splunk REST API — Search Jobs Management](../../apis/splunk/management-jobs.md) | Entry | Splunk | PowerShell, Bash, REST API | Administration, Automation, Troubleshooting |
| [VMware ESXi CLI Forensics and Ransomware Hardening](../../platforms/virtualization/esxi-forensics-hardening.md) | Entry | VMware, Linux | Bash, PowerShell | Hardening, Incident Response, Forensics |
| [VMware vSphere and ESXi](../../platforms/virtualization/vmware.md) | Entry | VMware | PowerShell, Bash | Administration, Incident Response, Forensics |
| [Windows 10 and 11 Version Notes](../../platforms/windows/windows-10-11.md) | Entry | Windows | PowerShell | Administration, Troubleshooting |
| [Windows Advanced Audit Policy & SACLs](../../platforms/windows/audit-policy.md) | Entry | Windows, Windows Server | PowerShell, CMD | Hardening, Administration |
| [Windows Defender Application Control (WDAC) & Exploit Guard](../../platforms/windows/wdac-exploit-guard.md) | Entry | Windows, Windows Server | PowerShell | Hardening, Administration |
| [Windows Event Logs](../../platforms/windows/event-logs.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Forensics, Hardening |
| [Windows Files and Permissions](../../platforms/windows/files-directories.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Forensics, Hardening |
| [Windows Firewall](../../platforms/windows/firewall.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Administration, Hardening, Incident Response, Troubleshooting |
| [Windows Forensic Disk Artifacts and Evidence Triage](../../tasks/forensics/windows-disk-artifacts.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI, Python | Forensics, Investigation, Incident Response |
| [Windows Installed Software](../../platforms/windows/software.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Investigation, Administration, Incident Response |
| [Windows Kernel & Network Stack Tuning](../../platforms/windows/kernel-tuning.md) | Entry | Windows, Windows Server | PowerShell, CMD | Administration, Hardening |
| [Windows Networking and DNS](../../platforms/windows/networking.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Troubleshooting, Administration |
| [Windows Processes](../../platforms/windows/processes.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Troubleshooting, Forensics |
| [Windows Registry and Run Keys](../../platforms/windows/registry.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Forensics, Threat Hunting |
| [Windows Remote Access (WinRM & OpenSSH)](../../platforms/windows/winrm-openssh.md) | Entry | Windows, Windows Server | PowerShell | Administration, Hardening |
| [Windows Scheduled Tasks](../../platforms/windows/scheduled-tasks.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Threat Hunting, Administration |
| [Windows Security Baseline — CIS Benchmark & NIST CSF 2.0](../../tasks/hardening/windows-security-baseline.md) | Entry | Windows, Windows Server | PowerShell, CMD | Hardening, Assurance, Administration |
| [Windows Server Notes](../../platforms/windows/windows-server.md) | Entry | Windows Server | PowerShell, Windows CLI | Administration, Incident Response, Troubleshooting |
| [Windows Services](../../platforms/windows/services.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Administration, Hardening |
| [Windows Storage & Disk Management](../../platforms/windows/storage-disks.md) | Entry | Windows, Windows Server | PowerShell, CMD | Administration, Troubleshooting |
| [Windows System Information](../../platforms/windows/system-information.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Administration, Troubleshooting |
| [Windows Troubleshooting Commands](../../platforms/windows/troubleshooting.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Troubleshooting, Administration |
| [Windows Users and Groups](../../platforms/windows/users-groups.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Administration, Hardening |
| [PowerShell Toolbox](../../toolbox/powershell.md) | Tool | Windows, Windows Server | PowerShell | Automation, Incident Response, Forensics, Investigation |
| [Cross-Platform Equivalents](../../references/equivalents.md) | Reference | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting, Administration |
| [Knowledge Graph Efficacy & Operational Coverage Matrix](../../references/coverage-matrix.md) | Reference | Windows, Windows Server, Linux, Azure, Entra ID, Microsoft Defender, SentinelOne, Splunk | PowerShell, Bash, Python, KQL, SPL, S1QL, REST API | Administration, Incident Response, Threat Hunting, Detection Engineering, Hardening, Assurance, Governance |
| [MITRE ATT&CK® Enterprise Matrix & Navigator Coverage](../../references/mitre-attack-matrix.md) | Reference | Windows, Linux, Azure, Entra ID, Microsoft Defender, SentinelOne, Splunk | KQL, SPL, S1QL, PowerShell, Bash | Detection Engineering, Incident Response, Threat Hunting, Hardening |
| [PowerShell Admin One-Liners Cheat Sheet](../../references/powershell-cheat-sheet.md) | Reference | Windows, Windows Server | PowerShell | Administration, Investigation, Automation |
| [Sysadmin Quick Reference Cheat Sheet](../../references/sysadmin-cheat-sheet.md) | Reference | Windows, Windows Server, Linux, Microsoft 365, Entra ID | PowerShell, Bash, Windows CLI | Administration, Troubleshooting, Investigation |
| [Windows Event ID Reference](../../references/windows-event-ids.md) | Reference | Windows, Windows Server | PowerShell, SPL, KQL | Investigation, Incident Response, Detection Engineering, Forensics |

<!-- /cc:index -->

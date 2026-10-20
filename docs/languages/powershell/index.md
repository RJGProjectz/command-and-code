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
| [Active Directory Account Lockout & Bad Password Troubleshooting](../../tasks/troubleshooting/account-lockout-troubleshooting.md) | Workflow | Windows, Windows Server, Active Directory | PowerShell, CMD, Windows CLI | Troubleshooting, Administration |
| [Active Directory Domain Services Administration](../../tasks/administration/active-directory-domain-management.md) | Workflow | Windows Server, Active Directory | PowerShell, CMD | Administration |
| [Administration — BitLocker Key Retrieval & Status Audit](../../tasks/administration/bitlocker-recovery.md) | Workflow | Windows, Active Directory | PowerShell, CMD | Administration, Troubleshooting |
| [Administration — Centralized Event Forwarding Pipeline (WEF & Rsyslog TLS)](../../tasks/administration/centralized-log-forwarding-wef-rsyslog.md) | Workflow | Windows Server, Windows, Linux | PowerShell, Bash | Administration, Detection Engineering, Hardening, Assurance |
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
| [CIS Hardening Lab Test (Before/After Diff and Run Checklist)](../../tasks/hardening/cis-hardening-lab-test.md) | Workflow | Windows, Linux | PowerShell, Bash | Hardening, Assurance |
| [CISA SCuBA Microsoft 365 and Azure Baseline Compliance](../../tasks/assurance/cisa-scuba-compliance.md) | Workflow | Microsoft 365, Azure, Entra ID | PowerShell | Assurance, Compliance, Hardening |
| [Credential Rotation After a Compromise](../../tasks/incident-response/credential-rotation-after-compromise.md) | Workflow | Active Directory, Windows Server, Linux, Entra ID, Azure | PowerShell, Bash, CMD | Incident Response, Administration |
| [Cyber Threat Intelligence — Adversary Emulation & ATT&CK Profiling](../../tasks/threat-intelligence/adversary-emulation-profiling.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | PowerShell, Bash, KQL, SPL | Threat Intelligence, Detection Engineering, Assurance |
| [Cyber Threat Intelligence — IoC Ingestion, Aging & Confidence Scoring](../../tasks/threat-intelligence/ioc-lifecycle-scoring.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | Python, PowerShell, Bash, KQL, SPL | Threat Intelligence, Detection Engineering, Investigation |
| [Cyber Threat Intelligence — STIX 2.1 & TAXII Feed Ingestion Pipeline](../../tasks/threat-intelligence/stix-taxii-pipeline.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | Python, PowerShell, Bash, KQL, SPL | Threat Intelligence, Detection Engineering, Threat Hunting |
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
| [Scheduled Task and Cron Persistence Review (Windows, Linux, macOS)](../../tasks/threat-hunting/scheduled-task-persistence-review.md) | Workflow | Windows, Windows Server, Linux, Microsoft Defender, Splunk | PowerShell, Windows CLI, Bash, KQL, SPL, MITRE ATT&CK | Threat Hunting, Investigation, Incident Response |
| [Scheduled Task Investigation](../../tasks/investigation/scheduled-task-investigation.md) | Workflow | Windows, Microsoft Defender, Splunk, SentinelOne | PowerShell, Windows CLI, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [SSH Connection Timeouts, Session Freezes & Host Sleep Drops](../../tasks/troubleshooting/ssh-connection-timeout-troubleshooting.md) | Workflow | Linux, Windows | Bash, PowerShell | Troubleshooting, Administration |
| [Storage Partitioning, Formatting and Filesystem Mounting](../../tasks/administration/storage-partitioning-mounting.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration |
| [Store Service Secrets & Keys on Windows](../../tasks/administration/windows-service-secrets-storage.md) | Workflow | Windows, Windows Server, Active Directory | PowerShell, CMD | Administration, Hardening |
| [Suspicious Outbound Connection](../../tasks/investigation/suspicious-outbound-connection.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Threat Hunting |
| [Suspicious PowerShell Investigation](../../tasks/incident-response/suspicious-powershell.md) | Workflow | Windows, Microsoft Defender, Splunk, SentinelOne | PowerShell, KQL, SPL, S1QL | Incident Response, Investigation |
| [Suspicious Process Investigation](../../tasks/incident-response/suspicious-process.md) | Workflow | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Incident Response, Investigation |
| [Suspicious Service Investigation](../../tasks/investigation/suspicious-service.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk | PowerShell, Windows CLI, KQL, SPL | Investigation, Incident Response |
| [System Maintenance and Updates](../../tasks/administration/system-maintenance-updates.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Automation |
| [Threat Hunting — Cloud Identity, OAuth Grants & Ephemeral Asset Anomalies](../../tasks/threat-hunting/cloud-infrastructure-ephemeral-asset-hunting.md) | Workflow | Entra ID, Microsoft 365, Azure, Microsoft Defender, Splunk | KQL, SPL, PowerShell | Threat Hunting, Incident Response, Investigation |
| [Threat Hunting — Cross-Platform Behavioral Telemetry (Windows & Linux)](../../tasks/threat-hunting/cross-platform-behavioral-hunting.md) | Workflow | Windows, Windows Server, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Threat Hunting, Detection Engineering, Investigation |
| [Threat Hunting — Hypothesis-Driven Methodology & Hunt Lifecycle Framework](../../tasks/threat-hunting/hypothesis-driven-hunting-framework.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Threat Hunting, Detection Engineering, Incident Response |
| [Threat Hunting — Statistical Baselining & Frequency Analysis (LFO)](../../tasks/threat-hunting/statistical-baselining-frequency-analysis.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | KQL, SPL, S1QL, PowerShell, Bash | Threat Hunting, Detection Engineering, Investigation |
| [Troubleshooting — Emergency Disk Space Exhaustion & Inode Recovery](../../tasks/troubleshooting/disk-space-emergency.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Troubleshooting, Administration |
| [Troubleshooting — High CPU Utilization & Runaway Processes](../../tasks/troubleshooting/high-cpu-troubleshooting.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Troubleshooting, Administration |
| [Troubleshooting — TLS/SSL Handshake & Certificate Failures](../../tasks/troubleshooting/certificate-handshake-failure.md) | Workflow | Linux, Windows, Windows Server | Bash, PowerShell | Troubleshooting, Investigation |
| [User Lifecycle Management](../../tasks/administration/user-lifecycle-management.md) | Workflow | Windows, Windows Server, Entra ID, Microsoft 365 | PowerShell | Administration, Hardening |
| [VPN & Remote Access Tunnel Troubleshooting](../../tasks/troubleshooting/vpn-connectivity-troubleshooting.md) | Workflow | Windows, Linux | PowerShell, Bash, Windows CLI | Troubleshooting |
| [Windows CIS Benchmark — Advanced Audit Policy Baseline](../../tasks/hardening/windows-cis-advanced-audit-policy.md) | Workflow | Windows, Windows Server, Active Directory | PowerShell, CMD | Hardening, Detection Engineering, Assurance |
| [Windows CIS Benchmark — Attack Surface Reduction (ASR) & Credential Guard](../../tasks/hardening/windows-cis-attack-surface-reduction.md) | Workflow | Windows, Windows Server | PowerShell, CMD | Hardening, Assurance, Administration |
| [Windows CIS Benchmark — User Rights Assignment & Account Policies](../../tasks/hardening/windows-cis-user-rights-assignment.md) | Workflow | Windows, Windows Server, Active Directory | PowerShell, CMD | Hardening, Assurance, Administration |
| [Windows Connectivity Troubleshooting](../../tasks/troubleshooting/windows-connectivity.md) | Workflow | Windows, Windows Server | PowerShell, Windows CLI | Troubleshooting |
| [Windows Service Accounts with Least Privilege](../../tasks/administration/windows-service-accounts-least-privilege.md) | Workflow | Windows, Windows Server, Active Directory | PowerShell, CMD | Administration, Hardening |
| [Amazon EC2 & Systems Manager (Compute)](../../platforms/aws/compute.md) | Entry | AWS | Bash, PowerShell | Administration, Investigation, Incident Response |
| [Assurance Check — Active Directory STIG Compliance](../../tasks/assurance/ad-stig-compliance.md) | Entry | Windows Server, Active Directory | PowerShell | Assurance, Hardening |
| [Assurance Check — Azure External Guest Access & Permissions](../../tasks/assurance/azure-guest-access-audit.md) | Entry | Entra ID, Azure, Microsoft 365 | PowerShell | Assurance, Hardening, Administration |
| [Assurance Check — Azure Network Security Group Compliance](../../tasks/assurance/azure-nsg-compliance.md) | Entry | Azure | PowerShell | Assurance, Hardening |
| [Assurance Check — Endpoint EDR Agent Health Status](../../tasks/assurance/endpoint-edr-status.md) | Entry | Windows, Linux | PowerShell | Assurance, Incident Response |
| [Assurance Check — Host Firewall Default Deny Stance](../../tasks/assurance/firewall-default-deny.md) | Entry | Windows, Linux | PowerShell, Bash | Assurance, Hardening |
| [AWS CLI, SDKs & Authentication](../../platforms/aws/cli-authentication.md) | Entry | AWS | Bash, PowerShell, Python | Administration, Automation, Incident Response |
| [Azure & Entra ID Security Baseline — CIS Benchmark & NIST CSF 2.0](../../tasks/hardening/cloud-azure-security-baseline.md) | Entry | Azure, Entra ID, Microsoft 365 | PowerShell, Bash | Hardening, Assurance, Governance |
| [Azure Audit Logging (Activity Log & Diagnostic Settings)](../../platforms/azure/audit-logging.md) | Entry | Azure, Entra ID | Bash, PowerShell, KQL | Investigation, Incident Response, Forensics, Hardening |
| [Azure CLI, Az PowerShell & Authentication](../../platforms/azure/cli-authentication.md) | Entry | Azure | Bash, PowerShell | Administration, Automation, Incident Response |
| [Azure Identity & Access (RBAC, PIM, Managed Identities)](../../platforms/azure/identity-access.md) | Entry | Azure, Entra ID | Bash, PowerShell, KQL | Administration, Hardening, Investigation, Assurance |
| [Azure Incident Response & Forensics](../../platforms/azure/incident-response.md) | Entry | Azure, Entra ID | Bash, PowerShell, KQL | Incident Response, Forensics, Investigation |
| [Azure Key Vault (Keys, Secrets & Certificates)](../../platforms/azure/keys-secrets.md) | Entry | Azure | Bash, PowerShell, KQL | Administration, Hardening, Investigation, Incident Response |
| [Azure Monitor & Log Analytics Queries](../../platforms/azure/monitoring-logs.md) | Entry | Azure | Bash, PowerShell, KQL | Investigation, Troubleshooting, Detection Engineering, Administration |
| [Azure Networking (VNets, NSGs, Flow Logs, Firewall)](../../platforms/azure/networking.md) | Entry | Azure | Bash, PowerShell, KQL | Administration, Troubleshooting, Investigation, Hardening |
| [Azure Persistence & Threat Hunting](../../platforms/azure/persistence-hunting.md) | Entry | Azure, Entra ID | KQL, Bash, PowerShell | Threat Hunting, Incident Response, Investigation, Detection Engineering |
| [Azure Policy, Locks & Governance](../../platforms/azure/policy-governance.md) | Entry | Azure | Bash, PowerShell, KQL | Hardening, Assurance, Administration, Governance |
| [Azure Resource Hierarchy & Inventory](../../platforms/azure/resource-hierarchy.md) | Entry | Azure | Bash, PowerShell, KQL | Administration, Investigation, Assurance |
| [Azure Storage & Data Exposure](../../platforms/azure/storage.md) | Entry | Azure | Bash, PowerShell, KQL | Administration, Hardening, Investigation, Incident Response |
| [Azure Troubleshooting](../../platforms/azure/troubleshooting.md) | Entry | Azure | Bash, PowerShell | Troubleshooting, Administration |
| [Azure Virtual Machines (Compute)](../../platforms/azure/compute.md) | Entry | Azure | Bash, PowerShell, KQL | Administration, Investigation, Incident Response |
| [Compare Files, Folders and Hashes](../../tasks/administration/compare-files-and-folders.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Investigation, Forensics |
| [Conditional Access](../../platforms/microsoft-365/conditional-access.md) | Entry | Microsoft 365, Entra ID | PowerShell, KQL | Administration, Hardening, Investigation, Troubleshooting |
| [Create and Extract Archives (zip, tar)](../../tasks/administration/create-and-extract-archives.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Investigation, Forensics |
| [Cross-platform data handling: Windows ↔ Linux, secrets, encodings and transport](../../fundamentals/systems/cross-platform-data-handling.md) | Entry | Windows, Linux, Proxmox | Python, PowerShell, Bash | Administration, Automation, Troubleshooting, Hardening |
| [Entra ID](../../platforms/microsoft-365/entra.md) | Entry | Microsoft 365, Entra ID | PowerShell | Incident Response, Investigation, Administration |
| [Environment Variables and PATH](../../tasks/administration/environment-variables-and-path.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Troubleshooting, Hardening |
| [Exchange Online](../../platforms/microsoft-365/exchange.md) | Entry | Microsoft 365, Exchange Online | PowerShell | Incident Response, Investigation, Administration |
| [File or Port in Use — Find and Stop the Holder](../../tasks/troubleshooting/file-or-port-in-use.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Troubleshooting, Administration |
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
| [GitHub Incident Response (Leaked Tokens, Compromised Accounts, Secret Purge)](../../platforms/github/incident-response.md) | Entry | GitHub | Bash, PowerShell | Incident Response, Forensics, Investigation |
| [Google Cloud CLI, SDKs & Authentication](../../platforms/gcp/cli-authentication.md) | Entry | GCP | Bash, PowerShell, Python | Administration, Automation, Incident Response |
| [Hyper-V](../../platforms/virtualization/hyper-v.md) | Entry | Hyper-V, Windows Server | PowerShell | Administration, Incident Response, Forensics |
| [Identify File Types (Not by Extension)](../../tasks/administration/identify-file-types.md) | Entry | Windows, Windows Server, Linux | PowerShell, Bash | Administration, Investigation, Forensics |
| [Incoming Webhooks for Slack & Microsoft Teams](../../apis/webhooks/slack-teams-webhooks.md) | Entry | Microsoft 365 | PowerShell, Bash, REST API | Automation, Incident Response |
| [Intune](../../platforms/microsoft-365/intune.md) | Entry | Microsoft 365, Intune, Windows | PowerShell, Windows CLI | Administration, Troubleshooting, Incident Response |
| [Microsoft Defender Antivirus](../../platforms/windows/defender.md) | Entry | Windows, Windows Server, Microsoft Defender | PowerShell, Windows CLI | Incident Response, Administration, Hardening, Troubleshooting |
| [Microsoft Defender API — Get Alerts](../../apis/microsoft-defender/get-alerts.md) | Entry | Microsoft Defender, Microsoft 365 | PowerShell, REST API | Incident Response, Automation |
| [Microsoft Defender API — Trigger Antivirus Scan](../../apis/microsoft-defender/antivirus-scan.md) | Entry | Microsoft Defender, Windows | PowerShell, REST API | Incident Response, Automation |
| [Microsoft Defender for Cloud (Posture & Alerts)](../../platforms/azure/security-posture.md) | Entry | Azure, Microsoft Defender | Bash, PowerShell, KQL | Assurance, Hardening, Investigation, Incident Response |
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
| [Search and Follow Logs by Keyword](../../tasks/administration/search-logs-by-keyword.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Troubleshooting, Investigation |
| [SentinelOne API — Network Host Isolation](../../apis/sentinelone/isolate-host.md) | Entry | SentinelOne | PowerShell, REST API | Incident Response, Automation |
| [SentinelOne API — Query Threats](../../apis/sentinelone/threats.md) | Entry | SentinelOne | PowerShell, Bash, REST API | Incident Response, Threat Hunting |
| [Shell Command History (PowerShell, CMD, Bash, Zsh)](../../tasks/administration/shell-command-history.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Investigation, Forensics, Incident Response |
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
| [Write Command Output to Files](../../tasks/administration/save-command-output-to-file.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Investigation, Automation |
| [CIS Block Monitor (Windows and Linux)](../../tasks/hardening/cis-block-monitor.md) | Tool | Windows, Linux | PowerShell, Bash | Hardening, Detection Engineering, Assurance |
| [PowerShell Toolbox](../../toolbox/powershell.md) | Tool | Windows, Windows Server | PowerShell | Automation, Incident Response, Forensics, Investigation |
| [Service Account Audit (Windows, Active Directory, Linux)](../../tasks/assurance/service-account-audit.md) | Tool | Windows, Windows Server, Active Directory, Linux | PowerShell, Bash | Assurance, Hardening, Administration |
| [Windows 11 CIS Benchmark Audit Tool (L1 / L2)](../../tasks/hardening/windows-11-cis-audit-tool.md) | Tool | Windows | PowerShell | Hardening, Assurance, Administration |
| [Windows Server CIS Benchmark Audit (Member Server / Domain Controller)](../../tasks/hardening/windows-server-cis-audit-tool.md) | Tool | Windows Server, Active Directory | PowerShell, Python | Hardening, Assurance, Administration |
| [Cloud Incident Response Cheat Sheet (Printable)](../../references/cloud-ir-cheat-sheet.md) | Reference | AWS, Azure, GCP | Bash, PowerShell | Incident Response, Investigation, Forensics |
| [Command Index — All Shells](../../references/command-index.md) | Reference | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Troubleshooting, Investigation |
| [Cross-Platform Equivalents](../../references/equivalents.md) | Reference | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting, Administration |
| [Knowledge Graph Efficacy & Operational Coverage Matrix](../../references/coverage-matrix.md) | Reference | Windows, Windows Server, Linux, Azure, Entra ID, Microsoft Defender, SentinelOne, Splunk | PowerShell, Bash, Python, KQL, SPL, S1QL, REST API | Administration, Incident Response, Threat Hunting, Detection Engineering, Hardening, Assurance, Governance |
| [MITRE ATT&CK® Enterprise Matrix & Navigator Coverage](../../references/mitre-attack-matrix.md) | Reference | Windows, Linux, Azure, Entra ID, Microsoft Defender, SentinelOne, Splunk | KQL, SPL, S1QL, PowerShell, Bash | Detection Engineering, Incident Response, Threat Hunting, Hardening |
| [PowerShell Admin One-Liners Cheat Sheet](../../references/powershell-cheat-sheet.md) | Reference | Windows, Windows Server | PowerShell | Administration, Investigation, Automation |
| [Sysadmin Quick Reference Cheat Sheet](../../references/sysadmin-cheat-sheet.md) | Reference | Windows, Windows Server, Linux, Microsoft 365, Entra ID | PowerShell, Bash, Windows CLI | Administration, Troubleshooting, Investigation |
| [Threat Actor Intelligence Profiles & TTP Reference Cards](../../references/threat-actor-profiles.md) | Reference | Windows, Linux, Azure, Entra ID, Microsoft 365 | KQL, SPL, PowerShell, Bash | Threat Intelligence, Threat Hunting, Detection Engineering |
| [Windows Event ID Reference](../../references/windows-event-ids.md) | Reference | Windows, Windows Server | PowerShell, SPL, KQL | Investigation, Incident Response, Detection Engineering, Forensics |
| [Windows Process Parent/Child Chains — Know Normal](../../references/windows-process-chains.md) | Reference | Windows, Windows Server | PowerShell, KQL, SPL | Investigation, Threat Hunting, Incident Response, Detection Engineering |
| [Windows Registry Keys That Change Behaviour — Persistence and Security Settings](../../references/windows-registry-security-keys.md) | Reference | Windows, Windows Server | PowerShell, Windows CLI, KQL, SPL | Investigation, Threat Hunting, Incident Response, Hardening, Forensics |
| [Windows Triage Cheat Sheet (Printable)](../../references/windows-triage-cheat-sheet.md) | Reference | Windows | PowerShell, Windows CLI | Incident Response, Investigation, Forensics |
| [Access Control Models (ACL, DAC, MAC, RBAC, ABAC)](../../fundamentals/concepts/access-control-models.md) | Concept | Windows, Linux, Azure | PowerShell, Bash | Hardening, Administration, Assurance |
| [Anonymity Networks and the Dark Web (Tor, I2P, Tails)](../../fundamentals/concepts/anonymity-dark-web.md) | Concept | Windows, Linux, Microsoft Defender | KQL, PowerShell, Bash | Threat Intelligence, Threat Hunting, Investigation |
| [ARP Spoofing](../../fundamentals/concepts/arp-spoofing.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Threat Hunting, Troubleshooting |
| [Authentication, MFA, SSO and Federation](../../fundamentals/concepts/authentication-mfa-sso.md) | Concept | Windows, Entra ID, Microsoft 365 | PowerShell, KQL | Investigation, Hardening, Incident Response |
| [Boot and Startup Sequence (UEFI to Logon)](../../fundamentals/concepts/boot-startup-sequence.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Threat Hunting, Troubleshooting |
| [CIA Triad and Least Privilege](../../fundamentals/concepts/cia-triad.md) | Concept | Windows, Linux | PowerShell, Bash | Hardening, Assurance |
| [Credential Dumping](../../fundamentals/concepts/credential-dumping.md) | Concept | Windows, Microsoft Defender, Active Directory | PowerShell, KQL | Incident Response, Threat Hunting, Hardening |
| [Cryptographic Attacks and Cryptanalysis](../../fundamentals/concepts/cryptographic-attacks.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Threat Hunting, Hardening, Assurance |
| [Cryptography Fundamentals (Symmetric and Asymmetric Encryption)](../../fundamentals/concepts/cryptography-fundamentals.md) | Concept | Windows, Linux | PowerShell, Bash | Hardening, Assurance, Administration |
| [Cyber Law (CFAA, ECPA, FISA, PATRIOT Act, SOX, FISMA, FedRAMP)](../../fundamentals/concepts/cyber-law.md) | Concept | Windows, Azure | PowerShell | Compliance, Assurance, Incident Response |
| [Defense in Depth and Secure Network Design](../../fundamentals/concepts/defense-in-depth.md) | Concept | Windows, Linux, Azure | PowerShell, Bash | Hardening, Assurance |
| [Denial of Service (DoS and DDoS)](../../fundamentals/concepts/denial-of-service.md) | Concept | Windows, Linux, Azure | PowerShell, Bash | Incident Response, Troubleshooting, Hardening |
| [Digital Forensics and Incident Response (DFIR)](../../fundamentals/concepts/digital-forensics.md) | Concept | Windows, Linux | PowerShell, Bash | Forensics, Incident Response, Investigation |
| [Digital Signatures and Non-repudiation (RSA, DSA, ECDSA, EdDSA, PGP)](../../fundamentals/concepts/digital-signatures.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Hardening, Forensics |
| [Ethical Hacking, Ethics and Careers](../../fundamentals/concepts/ethical-hacking.md) | Concept | Windows, Linux | PowerShell, Bash | Assurance, Hardening |
| [File Systems (NTFS, ext4, XFS)](../../fundamentals/concepts/file-systems.md) | Concept | Windows, Linux | PowerShell, Bash | Forensics, Investigation, Hardening |
| [Hash Functions (MD5, SHA-1, SHA-2, SHA-3, BLAKE2)](../../fundamentals/concepts/hash-functions.md) | Concept | Windows, Linux | PowerShell, Bash | Forensics, Investigation, Threat Intelligence |
| [Identity and Access Management (IAM, PAM, Directory Services)](../../fundamentals/concepts/identity-access-management.md) | Concept | Windows Server, Entra ID, Azure | PowerShell, KQL | Administration, Hardening, Assurance |
| [Kerberoasting](../../fundamentals/concepts/kerberoasting.md) | Concept | Active Directory, Windows Server, Microsoft Defender | PowerShell, KQL | Threat Hunting, Hardening, Investigation |
| [MAC Addresses and Spoofing](../../fundamentals/concepts/mac-address-spoofing.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Hardening, Troubleshooting |
| [Malware Types and Analysis (Spyware, RATs, Rootkits)](../../fundamentals/concepts/malware-types-analysis.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Incident Response, Forensics, Threat Intelligence |
| [Man-in-the-Middle Attacks](../../fundamentals/concepts/man-in-the-middle.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Threat Hunting, Hardening |
| [Mobile Device and Application Security](../../fundamentals/concepts/mobile-security.md) | Concept | Intune, Microsoft 365 | PowerShell, KQL | Hardening, Assurance, Investigation |
| [OSI Model and TCP](../../fundamentals/concepts/osi-model-tcp.md) | Concept | Windows, Linux | PowerShell, Bash | Troubleshooting, Investigation |
| [OSINT and Reconnaissance](../../fundamentals/concepts/osint.md) | Concept | Windows, Linux | PowerShell, Bash | Threat Intelligence, Investigation |
| [Packet Sniffing](../../fundamentals/concepts/packet-sniffing.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Troubleshooting, Threat Hunting |
| [Password Attacks and Defences (Spraying, Cracking, Wordlists)](../../fundamentals/concepts/password-attacks.md) | Concept | Windows, Entra ID, Microsoft Defender | PowerShell, KQL | Threat Hunting, Hardening, Incident Response |
| [Penetration Testing and Red Teaming (Methodology and Detection)](../../fundamentals/concepts/penetration-testing.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Assurance, Threat Hunting, Detection Engineering |
| [Port Scanning](../../fundamentals/concepts/port-scanning.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Investigation, Threat Hunting, Hardening |
| [Post-Quantum Cryptography (ML-KEM, ML-DSA, SLH-DSA)](../../fundamentals/concepts/post-quantum-cryptography.md) | Concept | Windows, Linux | PowerShell, Bash | Hardening, Assurance, Administration |
| [Privacy Laws and Data Protection (GDPR, CCPA, HIPAA)](../../fundamentals/concepts/privacy-laws.md) | Concept | Microsoft 365, Windows | PowerShell, KQL | Compliance, Incident Response, Assurance |
| [Processes, Threads and Handles](../../fundamentals/concepts/processes-threads.md) | Concept | Windows, Linux | PowerShell, Bash | Incident Response, Investigation, Threat Hunting |
| [Proxy Servers](../../fundamentals/concepts/proxy-servers.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Threat Hunting, Administration |
| [Quantum Computing and Security (Qubits, QKD)](../../fundamentals/concepts/quantum-computing-security.md) | Concept | Windows, Linux | PowerShell, Bash | Threat Intelligence, Assurance |
| [Ransomware](../../fundamentals/concepts/ransomware.md) | Concept | Windows, Linux, VMware, SentinelOne | PowerShell, S1QL | Incident Response, Threat Hunting, Hardening |
| [Risk Management, Policies and Compliance Audits](../../fundamentals/concepts/risk-management-governance.md) | Concept | Windows, Linux | PowerShell | Assurance, Compliance |
| [Secure SDLC, DevSecOps and Secure Coding](../../fundamentals/concepts/secure-sdlc-devsecops.md) | Concept | Windows, Linux | PowerShell, Bash, Python | Hardening, Assurance, Automation |
| [Security Standards Map (ISO/IEC 27000 series, NIST SP 800)](../../fundamentals/concepts/security-standards-map.md) | Concept | Windows, Linux, Azure | PowerShell | Compliance, Assurance, Hardening |
| [Services and Daemons (Windows SCM, systemd)](../../fundamentals/concepts/services-daemons.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Threat Hunting, Hardening |
| [Social Engineering (Phishing, Vishing, Pretexting, Tailgating)](../../fundamentals/concepts/social-engineering.md) | Concept | Microsoft 365, Exchange Online, Microsoft Defender | KQL, PowerShell | Incident Response, Investigation, Hardening |
| [Surveillance, Counter-Surveillance and Deception](../../fundamentals/concepts/surveillance-deception.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, KQL | Threat Hunting, Detection Engineering, Investigation |
| [Threat Intelligence and the Cyber Kill Chain](../../fundamentals/concepts/threat-intelligence-kill-chain.md) | Concept | Windows, Microsoft Defender | KQL, PowerShell | Threat Intelligence, Threat Hunting, Detection Engineering |
| [Users, Groups and Privilege (SIDs, UIDs, UAC, sudo)](../../fundamentals/concepts/users-groups-permissions.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Hardening, Incident Response |
| [Vulnerability Assessment and Patch Management](../../fundamentals/concepts/vulnerability-management.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Hardening, Assurance, Administration |
| [Wi-Fi Deauthentication and Rogue Access Points](../../fundamentals/concepts/wifi-deauth-rogue-ap.md) | Concept | Windows, Linux | PowerShell, Bash | Threat Hunting, Investigation, Hardening |
| [Wi-Fi Security (WEP, WPA, WPA2, WPA3)](../../fundamentals/concepts/wifi-security.md) | Concept | Windows, Linux | PowerShell, Bash, Windows CLI | Hardening, Investigation, Assurance |
| [Windows Registry (and the Linux /etc Equivalent)](../../fundamentals/concepts/windows-registry.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Forensics, Threat Hunting |
| [WPA/WPA2 Passphrase Attacks (Handshake Capture)](../../fundamentals/concepts/wifi-passphrase-attacks.md) | Concept | Windows, Linux | PowerShell, Bash | Hardening, Investigation, Threat Hunting |
| [Zero-Knowledge Proofs, Homomorphic Encryption and Blockchain](../../fundamentals/concepts/zero-knowledge-homomorphic-blockchain.md) | Concept | Windows, Linux | PowerShell, Bash | Threat Intelligence, Investigation |

<!-- /cc:index -->

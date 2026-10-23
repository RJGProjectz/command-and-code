---
title: Bash
type: index
---

# Bash

Bash knowledge lives in two places:

- **Language pages** — text processing and scripting patterns.
- **Linux platform entries** tagged *Bash* — processes, networking, logs, persistence and more.

## Language pages

- [Defensive Scripting](defensive-scripting.md) — Strict boilerplate, parameter checking, and error traps
- [Error Handling & Traps](error-handling-traps.md) — Signal handling, EXIT traps, and graceful recovery
- [Text Processing](text-processing.md) — grep, awk, sed, jq, pipeline stacking, and base64 decoding
- [Networking & Sockets](networking-sockets.md) — `/dev/tcp` socket manipulation, curl, netcat, and triage
- [Modern CLI Tools Ecosystem](cli-tools-ecosystem.md) — ripgrep, bat, fd, fzf, jq, and yq workflows
- [Scripting and Automation](automation.md) — Strict-mode templates, SSH loops, and cron-safe scripts
- [Bash toolbox scripts](../../toolbox/bash.md)

## Everything tagged Bash

<!-- cc:index languages="Bash" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Administration — Centralized Event Forwarding Pipeline (WEF & Rsyslog TLS)](../../tasks/administration/centralized-log-forwarding-wef-rsyslog.md) | Workflow | Windows Server, Windows, Linux | PowerShell, Bash | Administration, Detection Engineering, Hardening, Assurance |
| [Administration — Email Authentication Deployment (SPF, DKIM & DMARC)](../../tasks/administration/email-authentication-deployment.md) | Workflow | Linux, Microsoft 365 | Bash, PowerShell | Administration, Hardening, Investigation |
| [Administration — SSH Key Generation, Deployment & Best Practices](../../tasks/administration/ssh-key-deployment.md) | Workflow | Linux, Windows, Windows Server | Bash, PowerShell | Administration, Hardening |
| [Administration — Sysmon Enterprise Deployment & Telemetry Tuning](../../tasks/administration/sysmon-deployment-tuning.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Administration, Detection Engineering, Threat Hunting |
| [Administration — TLS/SSL Certificate Deployment & Web Server Hardening](../../tasks/administration/tls-certificate-deployment.md) | Workflow | Linux, Windows, Windows Server | Bash, PowerShell | Administration, Hardening |
| [Administration — WireGuard Secure VPN Gateway & Client Deployment](../../tasks/administration/wireguard-vpn-deployment.md) | Workflow | Linux, Windows | Bash, PowerShell | Administration, Hardening, Troubleshooting |
| [Apache & PHP Web Server Hardening](../../tasks/hardening/apache-php-web-server-hardening.md) | Workflow | Linux | Bash, HTTP | Hardening, Assurance, Administration |
| [Assess a Web API for Endpoints, Authorization Flaws and Abuse](../../offensive/web-api-assessment.md) | Workflow | Linux | Bash, HTTP | Assessment |
| [Assess a Wi-Fi Network's Posture — Survey, Encryption and Rogue-AP Awareness](../../offensive/wifi-wireless-assessment.md) | Workflow | Linux | Bash | Assessment |
| [Assess Credential Strength — Authorized Password Spraying and Offline Hash Cracking](../../offensive/password-attacks-credential-cracking.md) | Workflow | Linux | Bash | Assessment |
| [Auditing Services, Share Mounts and Containers — Boot Order and the Common Failures](../../tasks/troubleshooting/services-shares-containers-boot-order.md) | Workflow | Linux, Proxmox | Bash | Troubleshooting, Administration, Assurance |
| [Azure Cloud Infrastructure and Resource Administration](../../tasks/administration/cloud-azure-resource-management.md) | Workflow | Azure, Entra ID | PowerShell, Bash | Administration |
| [Backup and Recovery Operations](../../tasks/administration/backup-and-recovery.md) | Workflow | Hyper-V, VMware, Proxmox, Windows Server, Linux | PowerShell, Bash | Administration, Forensics |
| [Certificate and PKI Management](../../tasks/administration/certificate-and-pki-management.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Administration, Hardening |
| [CIS Hardening Lab Test (Before/After Diff and Run Checklist)](../../tasks/hardening/cis-hardening-lab-test.md) | Workflow | Windows, Linux | PowerShell, Bash | Hardening, Assurance |
| [Credential Rotation After a Compromise](../../tasks/incident-response/credential-rotation-after-compromise.md) | Workflow | Active Directory, Windows Server, Linux, Entra ID, Azure | PowerShell, Bash, CMD | Incident Response, Administration |
| [Cyber Threat Intelligence — Adversary Emulation & ATT&CK Profiling](../../tasks/threat-intelligence/adversary-emulation-profiling.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | PowerShell, Bash, KQL, SPL | Threat Intelligence, Detection Engineering, Assurance |
| [Cyber Threat Intelligence — IoC Ingestion, Aging & Confidence Scoring](../../tasks/threat-intelligence/ioc-lifecycle-scoring.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | Python, PowerShell, Bash, KQL, SPL | Threat Intelligence, Detection Engineering, Investigation |
| [Cyber Threat Intelligence — STIX 2.1 & TAXII Feed Ingestion Pipeline](../../tasks/threat-intelligence/stix-taxii-pipeline.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | Python, PowerShell, Bash, KQL, SPL | Threat Intelligence, Detection Engineering, Threat Hunting |
| [Delegated Administration Without Full Admin (JEA, sudo, polkit)](../../tasks/administration/delegated-admin-jea-sudo-polkit.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Administration, Hardening |
| [DNS Client Resolution and Troubleshooting](../../tasks/administration/dns-resolution-troubleshooting.md) | Workflow | Windows, Linux | PowerShell, CMD, Bash | Administration, Troubleshooting |
| [Effective Permissions and Access Review (Windows and Linux)](../../tasks/assurance/effective-permissions-access-review.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Assurance, Hardening, Administration |
| [Encrypt Linux Disks with LUKS2 (TPM2, Clevis/Tang, Key Slots, Header Backup)](../../tasks/administration/linux-luks-disk-encryption.md) | Workflow | Linux | Bash | Administration, Hardening |
| [Endpoint Triage](../../tasks/incident-response/endpoint-triage.md) | Workflow | Windows, Linux | PowerShell, Bash | Incident Response, Forensics |
| [Enumerate a Linux Host and Identify Privilege-Escalation Paths](../../offensive/linux-host-enumeration-privesc.md) | Workflow | Linux | Bash | Assessment |
| [Enumerate a Web Application for Technology, Versions and Weaknesses](../../offensive/web-application-assessment.md) | Workflow | Linux | Bash | Assessment |
| [Enumerate Active Directory for Users, Privileges and Attack Paths](../../offensive/active-directory-enumeration.md) | Workflow | Active Directory, Windows | PowerShell, Bash | Assessment |
| [Enumerate an Internal Network and its Services](../../offensive/network-infrastructure-enumeration.md) | Workflow | Linux | Bash | Assessment |
| [Enumerate Cloud Attack Surface across AWS, Azure and GCP](../../offensive/cloud-attack-surface-enumeration.md) | Workflow | AWS, Azure, GCP | Bash, Python | Assessment |
| [Failed Authentication Investigation](../../tasks/investigation/failed-authentication.md) | Workflow | Windows, Windows Server, Linux, Entra ID, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Troubleshooting |
| [File Integrity Monitoring (AIDE, SACLs, Sysmon)](../../tasks/assurance/file-integrity-monitoring.md) | Workflow | Linux, Windows, Windows Server | Bash, PowerShell | Assurance, Detection Engineering |
| [Host Firewall and Port Management](../../tasks/administration/firewall-port-management.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Hardening |
| [Host Performance and System Resource Auditing](../../tasks/administration/performance-resource-auditing.md) | Workflow | Windows, Linux | PowerShell, Bash, Python | Administration, Troubleshooting |
| [Investigation Playbook — Ransomware Host Isolation](../../tasks/incident-response/ransomware-host-isolation.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Incident Response |
| [Join Linux to Active Directory (realm, SSSD)](../../tasks/administration/linux-active-directory-join-sssd.md) | Workflow | Linux, Windows Server | Bash, PowerShell | Administration, Hardening |
| [Linux CIS Benchmark — Access Control, PAM & SSH Hardening](../../tasks/hardening/linux-cis-access-pam-ssh.md) | Workflow | Linux | Bash | Hardening, Assurance, Administration |
| [Linux CIS Benchmark — Comprehensive Auditd & Telemetry Baseline](../../tasks/hardening/linux-cis-auditd-logging.md) | Workflow | Linux | Bash | Hardening, Detection Engineering, Forensics |
| [Linux CIS Benchmark — Filesystem Integrity & Service Hardening](../../tasks/hardening/linux-cis-filesystem-services.md) | Workflow | Linux | Bash | Hardening, Assurance, Administration |
| [Linux Live Response and Forensic Artifact Extraction](../../tasks/forensics/linux-live-response-forensics.md) | Workflow | Linux | Bash, Python | Forensics, Incident Response, Investigation |
| [Linux Service Accounts with Least Privilege](../../tasks/administration/linux-service-accounts-least-privilege.md) | Workflow | Linux | Bash | Administration, Hardening |
| [Linux Service Failure Troubleshooting](../../tasks/troubleshooting/linux-service-failure.md) | Workflow | Linux | Bash | Troubleshooting, Administration |
| [Live Memory Acquisition and Volatility Analysis](../../tasks/forensics/memory-acquisition-analysis.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash, Python | Forensics, Incident Response, Investigation |
| [Local User and Group Administration](../../tasks/administration/local-user-group-management.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration |
| [Malware Triage](../../tasks/incident-response/malware-triage.md) | Workflow | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Incident Response, Forensics |
| [Map an Organization's Attack Surface with OSINT and Active Reconnaissance](../../offensive/osint-active-recon.md) | Workflow | Linux | Bash | Assessment |
| [Network Adapter and IP Configuration](../../tasks/administration/network-adapter-ip-configuration.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration |
| [Network and PCAP Forensics](../../tasks/forensics/network-pcap-forensics.md) | Workflow | Linux | Bash, Python | Forensics, Investigation, Incident Response |
| [Network Investigation](../../tasks/investigation/network-investigation.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Network Services Management](../../tasks/administration/network-services-management.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Troubleshooting |
| [NGINX Web Server Hardening](../../tasks/hardening/nginx-web-server-hardening.md) | Workflow | Linux | Bash, HTTP | Hardening, Assurance, Administration |
| [Package and Software Lifecycle Management](../../tasks/administration/package-software-management.md) | Workflow | Windows, Linux | PowerShell, Bash, CMD | Administration |
| [Restrict Outbound Traffic per Service (Windows Firewall, nftables, systemd)](../../tasks/hardening/per-service-egress-control.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Hardening, Administration |
| [Run an SSH Certificate Authority (User and Host Certificates)](../../tasks/administration/ssh-certificate-authority.md) | Workflow | Linux, Windows, Windows Server | Bash, PowerShell | Administration, Hardening |
| [Scan Linux Host Posture with Lynis, OpenSCAP and osquery](../../tasks/assurance/linux-posture-scanners.md) | Workflow | Linux | Bash | Assurance, Hardening |
| [Scheduled Task and Cron Job Automation](../../tasks/administration/scheduled-jobs-task-scheduler.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Automation |
| [Scheduled Task and Cron Persistence Review (Windows, Linux, macOS)](../../tasks/threat-hunting/scheduled-task-persistence-review.md) | Workflow | Windows, Windows Server, Linux, Microsoft Defender, Splunk | PowerShell, Windows CLI, Bash, KQL, SPL, MITRE ATT&CK | Threat Hunting, Investigation, Incident Response |
| [SSH Connection Timeouts, Session Freezes & Host Sleep Drops](../../tasks/troubleshooting/ssh-connection-timeout-troubleshooting.md) | Workflow | Linux, Windows | Bash, PowerShell | Troubleshooting, Administration |
| [Storage Partitioning, Formatting and Filesystem Mounting](../../tasks/administration/storage-partitioning-mounting.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration |
| [Store Service Secrets & Keys on Linux](../../tasks/administration/linux-service-secrets-storage.md) | Workflow | Linux | Bash | Administration, Hardening |
| [Suspicious Outbound Connection](../../tasks/investigation/suspicious-outbound-connection.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Threat Hunting |
| [Suspicious Process Investigation](../../tasks/incident-response/suspicious-process.md) | Workflow | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Incident Response, Investigation |
| [System Maintenance and Updates](../../tasks/administration/system-maintenance-updates.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Automation |
| [Threat Hunting — Cross-Platform Behavioral Telemetry (Windows & Linux)](../../tasks/threat-hunting/cross-platform-behavioral-hunting.md) | Workflow | Windows, Windows Server, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Threat Hunting, Detection Engineering, Investigation |
| [Threat Hunting — Hypothesis-Driven Methodology & Hunt Lifecycle Framework](../../tasks/threat-hunting/hypothesis-driven-hunting-framework.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Threat Hunting, Detection Engineering, Incident Response |
| [Threat Hunting — Statistical Baselining & Frequency Analysis (LFO)](../../tasks/threat-hunting/statistical-baselining-frequency-analysis.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | KQL, SPL, S1QL, PowerShell, Bash | Threat Hunting, Detection Engineering, Investigation |
| [Troubleshooting — Emergency Disk Space Exhaustion & Inode Recovery](../../tasks/troubleshooting/disk-space-emergency.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Troubleshooting, Administration |
| [Troubleshooting — High CPU Utilization & Runaway Processes](../../tasks/troubleshooting/high-cpu-troubleshooting.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Troubleshooting, Administration |
| [Troubleshooting — TLS/SSL Handshake & Certificate Failures](../../tasks/troubleshooting/certificate-handshake-failure.md) | Workflow | Linux, Windows, Windows Server | Bash, PowerShell | Troubleshooting, Investigation |
| [VPN & Remote Access Tunnel Troubleshooting](../../tasks/troubleshooting/vpn-connectivity-troubleshooting.md) | Workflow | Windows, Linux | PowerShell, Bash, Windows CLI | Troubleshooting |
| [Amazon CloudWatch, Logs Insights & Athena](../../platforms/aws/monitoring-logs.md) | Entry | AWS | Bash, Python | Investigation, Troubleshooting, Detection Engineering, Administration |
| [Amazon EC2 & Systems Manager (Compute)](../../platforms/aws/compute.md) | Entry | AWS | Bash, PowerShell | Administration, Investigation, Incident Response |
| [Amazon Elastic Kubernetes Service (EKS)](../../platforms/aws/kubernetes.md) | Entry | AWS | Bash | Administration, Hardening, Investigation, Incident Response |
| [Amazon S3 & Data Exposure](../../platforms/aws/storage.md) | Entry | AWS | Bash | Administration, Hardening, Investigation, Incident Response |
| [Assurance Check — Host Firewall Default Deny Stance](../../tasks/assurance/firewall-default-deny.md) | Entry | Windows, Linux | PowerShell, Bash | Assurance, Hardening |
| [Assurance Check — Linux Sudoers File Integrity](../../tasks/assurance/linux-sudoers-integrity.md) | Entry | Linux | Bash | Assurance, Hardening |
| [AWS CLI, SDKs & Authentication](../../platforms/aws/cli-authentication.md) | Entry | AWS | Bash, PowerShell, Python | Administration, Automation, Incident Response |
| [AWS CloudTrail (Audit Logging)](../../platforms/aws/audit-logging.md) | Entry | AWS | Bash, Python | Investigation, Incident Response, Forensics, Hardening |
| [AWS Identity & Access (IAM)](../../platforms/aws/identity-access.md) | Entry | AWS | Bash, Python | Administration, Hardening, Investigation, Assurance |
| [AWS Incident Response & Forensics](../../platforms/aws/incident-response.md) | Entry | AWS | Bash | Incident Response, Forensics, Investigation |
| [AWS KMS, Secrets Manager & Parameter Store](../../platforms/aws/keys-secrets.md) | Entry | AWS | Bash, Python | Administration, Hardening, Investigation, Incident Response |
| [AWS Networking (VPC, Security Groups, Flow Logs)](../../platforms/aws/networking.md) | Entry | AWS | Bash | Administration, Troubleshooting, Investigation, Hardening |
| [AWS Organizations, Accounts & Inventory](../../platforms/aws/resource-hierarchy.md) | Entry | AWS | Bash, Python | Administration, Investigation, Assurance |
| [AWS Persistence & Threat Hunting](../../platforms/aws/persistence-hunting.md) | Entry | AWS | Bash, Python | Threat Hunting, Incident Response, Investigation, Detection Engineering |
| [AWS SCPs, Config Rules & Governance](../../platforms/aws/policy-governance.md) | Entry | AWS | Bash | Hardening, Assurance, Administration, Governance |
| [AWS Security Hub, GuardDuty & Inspector (Posture & Alerts)](../../platforms/aws/security-posture.md) | Entry | AWS | Bash | Assurance, Hardening, Investigation, Incident Response |
| [AWS Troubleshooting](../../platforms/aws/troubleshooting.md) | Entry | AWS | Bash | Troubleshooting, Administration |
| [Azure & Entra ID Security Baseline — CIS Benchmark & NIST CSF 2.0](../../tasks/hardening/cloud-azure-security-baseline.md) | Entry | Azure, Entra ID, Microsoft 365 | PowerShell, Bash | Hardening, Assurance, Governance |
| [Azure Audit Logging (Activity Log & Diagnostic Settings)](../../platforms/azure/audit-logging.md) | Entry | Azure, Entra ID | Bash, PowerShell, KQL | Investigation, Incident Response, Forensics, Hardening |
| [Azure CLI, Az PowerShell & Authentication](../../platforms/azure/cli-authentication.md) | Entry | Azure | Bash, PowerShell | Administration, Automation, Incident Response |
| [Azure Identity & Access (RBAC, PIM, Managed Identities)](../../platforms/azure/identity-access.md) | Entry | Azure, Entra ID | Bash, PowerShell, KQL | Administration, Hardening, Investigation, Assurance |
| [Azure Incident Response & Forensics](../../platforms/azure/incident-response.md) | Entry | Azure, Entra ID | Bash, PowerShell, KQL | Incident Response, Forensics, Investigation |
| [Azure Key Vault (Keys, Secrets & Certificates)](../../platforms/azure/keys-secrets.md) | Entry | Azure | Bash, PowerShell, KQL | Administration, Hardening, Investigation, Incident Response |
| [Azure Kubernetes Service (AKS)](../../platforms/azure/kubernetes.md) | Entry | Azure | Bash, KQL | Administration, Hardening, Investigation, Incident Response |
| [Azure Monitor & Log Analytics Queries](../../platforms/azure/monitoring-logs.md) | Entry | Azure | Bash, PowerShell, KQL | Investigation, Troubleshooting, Detection Engineering, Administration |
| [Azure Networking (VNets, NSGs, Flow Logs, Firewall)](../../platforms/azure/networking.md) | Entry | Azure | Bash, PowerShell, KQL | Administration, Troubleshooting, Investigation, Hardening |
| [Azure Persistence & Threat Hunting](../../platforms/azure/persistence-hunting.md) | Entry | Azure, Entra ID | KQL, Bash, PowerShell | Threat Hunting, Incident Response, Investigation, Detection Engineering |
| [Azure Policy, Locks & Governance](../../platforms/azure/policy-governance.md) | Entry | Azure | Bash, PowerShell, KQL | Hardening, Assurance, Administration, Governance |
| [Azure Resource Hierarchy & Inventory](../../platforms/azure/resource-hierarchy.md) | Entry | Azure | Bash, PowerShell, KQL | Administration, Investigation, Assurance |
| [Azure Storage & Data Exposure](../../platforms/azure/storage.md) | Entry | Azure | Bash, PowerShell, KQL | Administration, Hardening, Investigation, Incident Response |
| [Azure Troubleshooting](../../platforms/azure/troubleshooting.md) | Entry | Azure | Bash, PowerShell | Troubleshooting, Administration |
| [Azure Virtual Machines (Compute)](../../platforms/azure/compute.md) | Entry | Azure | Bash, PowerShell, KQL | Administration, Investigation, Incident Response |
| [Bash Error Handling, Signals & Trap Handlers](error-handling-traps.md) | Entry | Linux | Bash | Automation, Troubleshooting |
| [Bash Pure Networking & /dev/tcp Socket Mechanics](networking-sockets.md) | Entry | Linux | Bash | Troubleshooting, Investigation |
| [Bash Scripting and Automation](automation.md) | Entry | Linux | Bash | Automation, Administration, Incident Response |
| [Bash Text Processing](text-processing.md) | Entry | Linux | Bash | Investigation, Automation, Threat Hunting |
| [Compare Files, Folders and Hashes](../../tasks/administration/compare-files-and-folders.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Investigation, Forensics |
| [Create and Extract Archives (zip, tar)](../../tasks/administration/create-and-extract-archives.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Investigation, Forensics |
| [Cross-platform data handling: Windows ↔ Linux, secrets, encodings and transport](../../fundamentals/systems/cross-platform-data-handling.md) | Entry | Windows, Linux, Proxmox | Python, PowerShell, Bash | Administration, Automation, Troubleshooting, Hardening |
| [Defensive Bash Scripting & Enterprise Boilerplate](defensive-scripting.md) | Entry | Linux | Bash | Automation, Hardening |
| [Environment Variables and PATH](../../tasks/administration/environment-variables-and-path.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Troubleshooting, Hardening |
| [File or Port in Use — Find and Stop the Holder](../../tasks/troubleshooting/file-or-port-in-use.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Troubleshooting, Administration |
| [Finding Files & Content Discovery](../../tasks/administration/file-search-discovery.md) | Entry | Linux, Windows, Windows Server | Bash, PowerShell, CMD | Administration, Investigation, Forensics |
| [Fundamentals — CIS Critical Security Controls & Benchmarks](../../fundamentals/grc/cis-benchmarks.md) | Entry | Windows, Windows Server, Linux | PowerShell, Bash | Assurance, Hardening, Administration |
| [Fundamentals — DHCP Protocol Mechanics & IP Allocation](../../fundamentals/networking/dhcp.md) | Entry | Windows Server, Linux | PowerShell, Bash | Troubleshooting, Administration |
| [Fundamentals — DNS Protocol Mechanics & Security](../../fundamentals/dns.md) | Entry | Windows Server, Linux | PowerShell, Bash | Investigation, Hardening |
| [Fundamentals — HTTP Security Headers & Transport Hardening](../../fundamentals/web-apps/http-security-headers.md) | Entry | Linux, Windows | HTTP, PowerShell, Bash | Hardening, Assurance, Troubleshooting |
| [Fundamentals — HTTP/HTTPS Protocol Mechanics & Headers](../../fundamentals/networking/http-https.md) | Entry | Linux, Windows Server | Bash, PowerShell | Investigation, Troubleshooting |
| [Fundamentals — LDAP Protocol, Directory Trees & LDAPS](../../fundamentals/identity/ldap.md) | Entry | Windows Server, Linux, Active Directory | PowerShell, Bash | Administration, Investigation |
| [Fundamentals — NIST Cybersecurity Framework (CSF) 2.0](../../fundamentals/grc/nist-csf-2.md) | Entry | Windows, Linux, Microsoft 365, Azure | PowerShell, Bash, Python | Assurance, Hardening, Administration, Incident Response |
| [Fundamentals — Public Key Infrastructure (PKI), CAs & Revocation](../../fundamentals/identity/pki.md) | Entry | Windows Server, Linux | PowerShell, Bash | Hardening, Administration |
| [Fundamentals — Regulatory Compliance & Framework Cross-Walk](../../fundamentals/grc/regulatory-frameworks.md) | Entry | Windows, Linux, Azure, Microsoft 365 | PowerShell, Bash, Python | Assurance, Hardening, Administration |
| [Fundamentals — Self-Hosted & Air-Gapped AI Model Runtimes](../../fundamentals/ai-systems/self-hosted-models.md) | Entry | Linux | Bash, Python | Hardening, Automation |
| [Fundamentals — SMTP Protocol, Relays & Email Authentication](../../fundamentals/networking/smtp.md) | Entry | Linux, Microsoft 365 | PowerShell, Bash | Investigation, Hardening |
| [Fundamentals — SSH Key Architecture & Cryptographic Baselines](../../fundamentals/identity/ssh-keys.md) | Entry | Linux | Bash | Hardening, Administration |
| [Fundamentals — Sysmon Telemetry & Endpoint Monitoring](../../fundamentals/systems/sysmon.md) | Entry | Windows, Linux | PowerShell, Bash | Threat Hunting, Detection Engineering |
| [Fundamentals — TLS Handshake & Cipher Suite Mechanics](../../fundamentals/networking/tls-ssl.md) | Entry | Linux, Windows Server | Bash, PowerShell | Hardening, Investigation |
| [Fundamentals — UEFI Boot Sequence & Secure Boot Mechanics](../../fundamentals/systems/uefi-secure-boot.md) | Entry | Windows, Linux | PowerShell, Bash | Hardening, Assurance |
| [Fundamentals — Virtual Memory, Paging, Stack & Heap](../../fundamentals/systems/memory-internals.md) | Entry | Windows, Linux | PowerShell, Bash | Forensics, Investigation |
| [Fundamentals — VPN Protocols (IPsec vs SSL/TLS)](../../fundamentals/networking/vpn.md) | Entry | Windows, Linux | PowerShell, Bash | Troubleshooting, Hardening |
| [Fundamentals — Zero Trust Network Microsegmentation](../../fundamentals/networking/microsegmentation.md) | Entry | Linux, Windows Server | Bash, PowerShell | Hardening, Assurance |
| [Git: Clone, Sync a Fork, Branches, Rebase & Signed Commits](../../platforms/github/repositories.md) | Entry | GitHub | Bash | Administration, Automation, Troubleshooting |
| [GitHub Actions Secrets, Environments, OIDC & Deploy Keys](../../platforms/github/keys-secrets.md) | Entry | GitHub | Bash | Administration, Hardening, Investigation, Incident Response |
| [GitHub Audit Log & Security Log](../../platforms/github/audit-logging.md) | Entry | GitHub | Bash | Investigation, Incident Response, Forensics, Hardening |
| [GitHub CLI, Tokens & Authentication](../../platforms/github/cli-authentication.md) | Entry | GitHub | Bash | Administration, Automation, Incident Response |
| [GitHub Incident Response (Leaked Tokens, Compromised Accounts, Secret Purge)](../../platforms/github/incident-response.md) | Entry | GitHub | Bash, PowerShell | Incident Response, Forensics, Investigation |
| [GitHub Organizations, Teams & Repository Access](../../platforms/github/identity-access.md) | Entry | GitHub | Bash | Administration, Hardening, Investigation, Assurance |
| [GitHub Persistence & Threat Hunting](../../platforms/github/persistence-hunting.md) | Entry | GitHub | Bash | Threat Hunting, Incident Response, Investigation, Detection Engineering |
| [GitHub Security Posture (Rulesets, Actions Policy, Dependabot, Secret & Code Scanning)](../../platforms/github/security-posture.md) | Entry | GitHub | Bash | Assurance, Hardening, Investigation, Incident Response |
| [GitHub Troubleshooting (Auth, Push, Actions & OIDC Errors)](../../platforms/github/troubleshooting.md) | Entry | GitHub | Bash | Troubleshooting, Administration |
| [Google Cloud Audit Logs](../../platforms/gcp/audit-logging.md) | Entry | GCP | Bash | Investigation, Incident Response, Forensics, Hardening |
| [Google Cloud CLI, SDKs & Authentication](../../platforms/gcp/cli-authentication.md) | Entry | GCP | Bash, PowerShell, Python | Administration, Automation, Incident Response |
| [Google Cloud IAM (Identity & Access)](../../platforms/gcp/identity-access.md) | Entry | GCP | Bash, Python | Administration, Hardening, Investigation, Incident Response |
| [Google Cloud Incident Response & Forensics](../../platforms/gcp/incident-response.md) | Entry | GCP | Bash | Incident Response, Forensics, Investigation |
| [Google Cloud KMS & Secret Manager](../../platforms/gcp/keys-secrets.md) | Entry | GCP | Bash, Python | Administration, Hardening, Investigation, Incident Response |
| [Google Cloud Logging & BigQuery Log Queries](../../platforms/gcp/monitoring-logs.md) | Entry | GCP | Bash | Investigation, Troubleshooting, Detection Engineering, Administration |
| [Google Cloud Organization Policy & Governance](../../platforms/gcp/policy-governance.md) | Entry | GCP | Bash | Hardening, Assurance, Administration, Governance |
| [Google Cloud Persistence & Threat Hunting](../../platforms/gcp/persistence-hunting.md) | Entry | GCP | Bash, Python | Threat Hunting, Incident Response, Investigation, Detection Engineering |
| [Google Cloud Resource Hierarchy & Inventory](../../platforms/gcp/resource-hierarchy.md) | Entry | GCP | Bash | Administration, Investigation, Assurance |
| [Google Cloud Storage (Buckets & Data Exposure)](../../platforms/gcp/storage.md) | Entry | GCP | Bash, Python | Administration, Hardening, Investigation, Assurance |
| [Google Cloud Troubleshooting](../../platforms/gcp/troubleshooting.md) | Entry | GCP | Bash | Troubleshooting, Administration |
| [Google Cloud VPC & Firewall Rules](../../platforms/gcp/networking.md) | Entry | GCP | Bash | Administration, Hardening, Investigation, Incident Response |
| [Google Compute Engine & OS Login](../../platforms/gcp/compute.md) | Entry | GCP | Bash | Administration, Hardening, Investigation, Incident Response |
| [Google Kubernetes Engine (GKE)](../../platforms/gcp/kubernetes.md) | Entry | GCP | Bash | Administration, Hardening, Investigation, Incident Response |
| [Identify File Types (Not by Extension)](../../tasks/administration/identify-file-types.md) | Entry | Windows, Windows Server, Linux | PowerShell, Bash | Administration, Investigation, Forensics |
| [Incoming Webhooks for Slack & Microsoft Teams](../../apis/webhooks/slack-teams-webhooks.md) | Entry | Microsoft 365 | PowerShell, Bash, REST API | Automation, Incident Response |
| [Linux Antivirus & Endpoint Detection (EDR)](../../platforms/linux/antivirus-edr.md) | Entry | Linux | Bash | Administration, Hardening, Incident Response |
| [Linux Audit Daemon (auditd) & Kernel Telemetry](../../platforms/linux/auditd.md) | Entry | Linux | Bash | Forensics, Detection Engineering |
| [Linux Cron and Scheduled Jobs](../../platforms/linux/cron.md) | Entry | Linux | Bash | Incident Response, Investigation, Threat Hunting, Administration |
| [Linux Distributions, Package Systems & Release Baselines](../../platforms/linux/distros.md) | Entry | Linux | Bash | Administration, Troubleshooting |
| [Linux Filesystem](../../platforms/linux/filesystem.md) | Entry | Linux | Bash | Incident Response, Investigation, Forensics, Troubleshooting |
| [Linux Firewalls — nftables, iptables & UFW Defense](../../platforms/linux/firewalls-nftables.md) | Entry | Linux | Bash | Hardening, Administration |
| [Linux Installed Packages](../../platforms/linux/packages.md) | Entry | Linux | Bash | Investigation, Administration, Forensics |
| [Linux Kernel Tuning & sysctl Runtime Optimization](../../platforms/linux/kernel-tuning.md) | Entry | Linux | Bash | Hardening, Troubleshooting |
| [Linux Logs](../../platforms/linux/logs.md) | Entry | Linux | Bash | Incident Response, Investigation, Troubleshooting, Forensics |
| [Linux Mandatory Access Control — SELinux & AppArmor](../../platforms/linux/selinux-apparmor.md) | Entry | Linux | Bash | Hardening, Troubleshooting |
| [Linux Networking and DNS](../../platforms/linux/networking.md) | Entry | Linux | Bash | Incident Response, Investigation, Troubleshooting, Administration |
| [Linux Processes](../../platforms/linux/processes.md) | Entry | Linux | Bash | Incident Response, Investigation, Troubleshooting, Forensics |
| [Linux Security Baseline — CIS Benchmark & NIST CSF 2.0](../../tasks/hardening/linux-security-baseline.md) | Entry | Linux | Bash | Hardening, Assurance, Administration |
| [Linux Services with systemd](../../platforms/linux/systemd.md) | Entry | Linux | Bash | Administration, Troubleshooting, Incident Response, Investigation |
| [Linux SSH](../../platforms/linux/ssh.md) | Entry | Linux | Bash | Incident Response, Investigation, Hardening, Administration |
| [Linux Startup Persistence & Autostart Architecture](../../platforms/linux/persistence.md) | Entry | Linux | Bash | Investigation, Forensics, Hardening |
| [Linux Storage, Partitioning & Logical Volume Management (LVM)](../../platforms/linux/storage-lvm.md) | Entry | Linux | Bash | Administration, Troubleshooting |
| [Linux System Information](../../platforms/linux/system-information.md) | Entry | Linux | Bash | Incident Response, Administration, Troubleshooting |
| [Linux Terminal Sessions — screen, tmux & Background Jobs](../../platforms/linux/terminal-sessions.md) | Entry | Linux | Bash | Administration, Troubleshooting, Investigation, Incident Response |
| [Linux Troubleshooting Commands](../../platforms/linux/troubleshooting.md) | Entry | Linux | Bash | Troubleshooting, Administration |
| [Linux Users and Permissions](../../platforms/linux/users-permissions.md) | Entry | Linux | Bash | Incident Response, Investigation, Administration, Hardening |
| [Microsoft Defender for Cloud (Posture & Alerts)](../../platforms/azure/security-posture.md) | Entry | Azure, Microsoft Defender | Bash, PowerShell, KQL | Assurance, Hardening, Investigation, Incident Response |
| [Modern Sysadmin CLI Toolkit — jq, yq, ripgrep & fzf](cli-tools-ecosystem.md) | Entry | Linux | Bash | Administration, Investigation |
| [OAuth 2.0 Bearer Token Authentication Flow](../../apis/authentication/bearer-tokens.md) | Entry | Entra ID, Microsoft 365 | PowerShell, Bash, REST API | Automation, Administration |
| [Proxmox VE](../../platforms/virtualization/proxmox.md) | Entry | Proxmox, Linux | Bash | Administration, Incident Response, Forensics |
| [Remote File Transfer — SCP, SFTP, rsync & WinRM](../../tasks/administration/remote-file-transfer.md) | Entry | Linux, Windows, Windows Server | Bash, PowerShell, CMD | Administration, Automation, Incident Response |
| [Search and Follow Logs by Keyword](../../tasks/administration/search-logs-by-keyword.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Troubleshooting, Investigation |
| [Security Command Center (GCP Posture & Alerts)](../../platforms/gcp/security-posture.md) | Entry | GCP | Bash | Assurance, Hardening, Investigation, Incident Response |
| [SentinelOne API — Query Threats](../../apis/sentinelone/threats.md) | Entry | SentinelOne | PowerShell, Bash, REST API | Incident Response, Threat Hunting |
| [Shell Command History (PowerShell, CMD, Bash, Zsh)](../../tasks/administration/shell-command-history.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Investigation, Forensics, Incident Response |
| [Splunk REST API — Search Jobs Management](../../apis/splunk/management-jobs.md) | Entry | Splunk | PowerShell, Bash, REST API | Administration, Automation, Troubleshooting |
| [VMware ESXi CLI Forensics and Ransomware Hardening](../../platforms/virtualization/esxi-forensics-hardening.md) | Entry | VMware, Linux | Bash, PowerShell | Hardening, Incident Response, Forensics |
| [VMware vSphere and ESXi](../../platforms/virtualization/vmware.md) | Entry | VMware | PowerShell, Bash | Administration, Incident Response, Forensics |
| [Write Command Output to Files](../../tasks/administration/save-command-output-to-file.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Investigation, Automation |
| [API Surface Recon Tool (scope- and rate-limit-aware)](../../offensive/api-surface-recon-tool.md) | Tool | Linux | Bash | Assessment |
| [Bash Toolbox](../../toolbox/bash.md) | Tool | Linux | Bash | Automation, Incident Response, Forensics, Investigation |
| [CIS Block Monitor (Windows and Linux)](../../tasks/hardening/cis-block-monitor.md) | Tool | Windows, Linux | PowerShell, Bash | Hardening, Detection Engineering, Assurance |
| [Linux CIS Benchmark Audit Tool (Ubuntu 24.04, RHEL 9)](../../tasks/hardening/linux-cis-audit-tool.md) | Tool | Linux | Bash | Hardening, Assurance, Administration |
| [Passive Web OSINT Tool (one or many targets)](../../offensive/passive-web-osint.md) | Tool | Linux | Bash | Assessment |
| [Service Account Audit (Windows, Active Directory, Linux)](../../tasks/assurance/service-account-audit.md) | Tool | Windows, Windows Server, Active Directory, Linux | PowerShell, Bash | Assurance, Hardening, Administration |
| [Cloud Incident Response Cheat Sheet (Printable)](../../references/cloud-ir-cheat-sheet.md) | Reference | AWS, Azure, GCP | Bash, PowerShell | Incident Response, Investigation, Forensics |
| [Command Index — All Shells](../../references/command-index.md) | Reference | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Troubleshooting, Investigation |
| [Cross-Platform Equivalents](../../references/equivalents.md) | Reference | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting, Administration |
| [Knowledge Graph Efficacy & Operational Coverage Matrix](../../references/coverage-matrix.md) | Reference | Windows, Windows Server, Linux, Azure, Entra ID, Microsoft Defender, SentinelOne, Splunk | PowerShell, Bash, Python, KQL, SPL, S1QL, REST API | Administration, Incident Response, Threat Hunting, Detection Engineering, Hardening, Assurance, Governance |
| [Linux Sysadmin Speed Dial Cheat Sheet](../../references/linux-cheat-sheet.md) | Reference | Linux | Bash | Administration, Troubleshooting, Investigation |
| [Linux Triage Cheat Sheet (Printable)](../../references/linux-triage-cheat-sheet.md) | Reference | Linux | Bash | Incident Response, Investigation, Forensics |
| [MITRE ATT&CK® Enterprise Matrix & Navigator Coverage](../../references/mitre-attack-matrix.md) | Reference | Windows, Linux, Azure, Entra ID, Microsoft Defender, SentinelOne, Splunk | KQL, SPL, S1QL, PowerShell, Bash | Detection Engineering, Incident Response, Threat Hunting, Hardening |
| [Sysadmin Quick Reference Cheat Sheet](../../references/sysadmin-cheat-sheet.md) | Reference | Windows, Windows Server, Linux, Microsoft 365, Entra ID | PowerShell, Bash, Windows CLI | Administration, Troubleshooting, Investigation |
| [Threat Actor Intelligence Profiles & TTP Reference Cards](../../references/threat-actor-profiles.md) | Reference | Windows, Linux, Azure, Entra ID, Microsoft 365 | KQL, SPL, PowerShell, Bash | Threat Intelligence, Threat Hunting, Detection Engineering |
| [Access Control Models (ACL, DAC, MAC, RBAC, ABAC)](../../fundamentals/concepts/access-control-models.md) | Concept | Windows, Linux, Azure | PowerShell, Bash | Hardening, Administration, Assurance |
| [Anonymity Networks and the Dark Web (Tor, I2P, Tails)](../../fundamentals/concepts/anonymity-dark-web.md) | Concept | Windows, Linux, Microsoft Defender | KQL, PowerShell, Bash | Threat Intelligence, Threat Hunting, Investigation |
| [ARP Spoofing](../../fundamentals/concepts/arp-spoofing.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Threat Hunting, Troubleshooting |
| [Boot and Startup Sequence (UEFI to Logon)](../../fundamentals/concepts/boot-startup-sequence.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Threat Hunting, Troubleshooting |
| [CIA Triad and Least Privilege](../../fundamentals/concepts/cia-triad.md) | Concept | Windows, Linux | PowerShell, Bash | Hardening, Assurance |
| [Cloud-Native Security (Containers, Kubernetes, Microservices)](../../fundamentals/concepts/cloud-native-security.md) | Concept | Linux, Azure | Bash, KQL | Hardening, Threat Hunting, Assurance |
| [Cryptographic Attacks and Cryptanalysis](../../fundamentals/concepts/cryptographic-attacks.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Threat Hunting, Hardening, Assurance |
| [Cryptography Fundamentals (Symmetric and Asymmetric Encryption)](../../fundamentals/concepts/cryptography-fundamentals.md) | Concept | Windows, Linux | PowerShell, Bash | Hardening, Assurance, Administration |
| [Defense in Depth and Secure Network Design](../../fundamentals/concepts/defense-in-depth.md) | Concept | Windows, Linux, Azure | PowerShell, Bash | Hardening, Assurance |
| [Denial of Service (DoS and DDoS)](../../fundamentals/concepts/denial-of-service.md) | Concept | Windows, Linux, Azure | PowerShell, Bash | Incident Response, Troubleshooting, Hardening |
| [Digital Forensics and Incident Response (DFIR)](../../fundamentals/concepts/digital-forensics.md) | Concept | Windows, Linux | PowerShell, Bash | Forensics, Incident Response, Investigation |
| [Digital Signatures and Non-repudiation (RSA, DSA, ECDSA, EdDSA, PGP)](../../fundamentals/concepts/digital-signatures.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Hardening, Forensics |
| [Ethical Hacking, Ethics and Careers](../../fundamentals/concepts/ethical-hacking.md) | Concept | Windows, Linux | PowerShell, Bash | Assurance, Hardening |
| [File Systems (NTFS, ext4, XFS)](../../fundamentals/concepts/file-systems.md) | Concept | Windows, Linux | PowerShell, Bash | Forensics, Investigation, Hardening |
| [Hash Functions (MD5, SHA-1, SHA-2, SHA-3, BLAKE2)](../../fundamentals/concepts/hash-functions.md) | Concept | Windows, Linux | PowerShell, Bash | Forensics, Investigation, Threat Intelligence |
| [Intrusion Detection and Prevention (IDS/IPS)](../../fundamentals/concepts/ids-ips.md) | Concept | Linux, Windows, Microsoft Defender | Bash, KQL | Detection Engineering, Threat Hunting, Hardening |
| [MAC Addresses and Spoofing](../../fundamentals/concepts/mac-address-spoofing.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Hardening, Troubleshooting |
| [Malware Types and Analysis (Spyware, RATs, Rootkits)](../../fundamentals/concepts/malware-types-analysis.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Incident Response, Forensics, Threat Intelligence |
| [Man-in-the-Middle Attacks](../../fundamentals/concepts/man-in-the-middle.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Threat Hunting, Hardening |
| [OSI Model and TCP](../../fundamentals/concepts/osi-model-tcp.md) | Concept | Windows, Linux | PowerShell, Bash | Troubleshooting, Investigation |
| [OSINT and Reconnaissance](../../fundamentals/concepts/osint.md) | Concept | Windows, Linux | PowerShell, Bash | Threat Intelligence, Investigation |
| [Packet Sniffing](../../fundamentals/concepts/packet-sniffing.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Troubleshooting, Threat Hunting |
| [Penetration Testing and Red Teaming (Methodology and Detection)](../../fundamentals/concepts/penetration-testing.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Assurance, Threat Hunting, Detection Engineering |
| [Port Scanning](../../fundamentals/concepts/port-scanning.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Investigation, Threat Hunting, Hardening |
| [Post-Quantum Cryptography (ML-KEM, ML-DSA, SLH-DSA)](../../fundamentals/concepts/post-quantum-cryptography.md) | Concept | Windows, Linux | PowerShell, Bash | Hardening, Assurance, Administration |
| [Processes, Threads and Handles](../../fundamentals/concepts/processes-threads.md) | Concept | Windows, Linux | PowerShell, Bash | Incident Response, Investigation, Threat Hunting |
| [Proxy Servers](../../fundamentals/concepts/proxy-servers.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Threat Hunting, Administration |
| [Quantum Computing and Security (Qubits, QKD)](../../fundamentals/concepts/quantum-computing-security.md) | Concept | Windows, Linux | PowerShell, Bash | Threat Intelligence, Assurance |
| [Secure SDLC, DevSecOps and Secure Coding](../../fundamentals/concepts/secure-sdlc-devsecops.md) | Concept | Windows, Linux | PowerShell, Bash, Python | Hardening, Assurance, Automation |
| [Services and Daemons (Windows SCM, systemd)](../../fundamentals/concepts/services-daemons.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Threat Hunting, Hardening |
| [Users, Groups and Privilege (SIDs, UIDs, UAC, sudo)](../../fundamentals/concepts/users-groups-permissions.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Hardening, Incident Response |
| [Vulnerability Assessment and Patch Management](../../fundamentals/concepts/vulnerability-management.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Hardening, Assurance, Administration |
| [Wi-Fi Deauthentication and Rogue Access Points](../../fundamentals/concepts/wifi-deauth-rogue-ap.md) | Concept | Windows, Linux | PowerShell, Bash | Threat Hunting, Investigation, Hardening |
| [Wi-Fi Security (WEP, WPA, WPA2, WPA3)](../../fundamentals/concepts/wifi-security.md) | Concept | Windows, Linux | PowerShell, Bash, Windows CLI | Hardening, Investigation, Assurance |
| [Windows Registry (and the Linux /etc Equivalent)](../../fundamentals/concepts/windows-registry.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Forensics, Threat Hunting |
| [WPA/WPA2 Passphrase Attacks (Handshake Capture)](../../fundamentals/concepts/wifi-passphrase-attacks.md) | Concept | Windows, Linux | PowerShell, Bash | Hardening, Investigation, Threat Hunting |
| [Zero-Knowledge Proofs, Homomorphic Encryption and Blockchain](../../fundamentals/concepts/zero-knowledge-homomorphic-blockchain.md) | Concept | Windows, Linux | PowerShell, Bash | Threat Intelligence, Investigation |

<!-- /cc:index -->

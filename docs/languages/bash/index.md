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
| [Administration — Email Authentication Deployment (SPF, DKIM & DMARC)](../../tasks/administration/email-authentication-deployment.md) | Workflow | Linux, Microsoft 365 | Bash, PowerShell | Administration, Hardening, Investigation |
| [Administration — SSH Key Generation, Deployment & Best Practices](../../tasks/administration/ssh-key-deployment.md) | Workflow | Linux, Windows, Windows Server | Bash, PowerShell | Administration, Hardening |
| [Administration — Sysmon Enterprise Deployment & Telemetry Tuning](../../tasks/administration/sysmon-deployment-tuning.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Administration, Detection Engineering, Threat Hunting |
| [Administration — TLS/SSL Certificate Deployment & Web Server Hardening](../../tasks/administration/tls-certificate-deployment.md) | Workflow | Linux, Windows, Windows Server | Bash, PowerShell | Administration, Hardening |
| [Administration — WireGuard Secure VPN Gateway & Client Deployment](../../tasks/administration/wireguard-vpn-deployment.md) | Workflow | Linux, Windows | Bash, PowerShell | Administration, Hardening, Troubleshooting |
| [Azure Cloud Infrastructure and Resource Administration](../../tasks/administration/cloud-azure-resource-management.md) | Workflow | Azure, Entra ID | PowerShell, Bash | Administration |
| [Backup and Recovery Operations](../../tasks/administration/backup-and-recovery.md) | Workflow | Hyper-V, VMware, Proxmox, Windows Server, Linux | PowerShell, Bash | Administration, Forensics |
| [Certificate and PKI Management](../../tasks/administration/certificate-and-pki-management.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Administration, Hardening |
| [DNS Client Resolution and Troubleshooting](../../tasks/administration/dns-resolution-troubleshooting.md) | Workflow | Windows, Linux | PowerShell, CMD, Bash | Administration, Troubleshooting |
| [Endpoint Triage](../../tasks/incident-response/endpoint-triage.md) | Workflow | Windows, Linux | PowerShell, Bash | Incident Response, Forensics |
| [Failed Authentication Investigation](../../tasks/investigation/failed-authentication.md) | Workflow | Windows, Windows Server, Linux, Entra ID, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Troubleshooting |
| [Host Firewall and Port Management](../../tasks/administration/firewall-port-management.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Hardening |
| [Host Performance and System Resource Auditing](../../tasks/administration/performance-resource-auditing.md) | Workflow | Windows, Linux | PowerShell, Bash, Python | Administration, Troubleshooting |
| [Investigation Playbook — Ransomware Host Isolation](../../tasks/incident-response/ransomware-host-isolation.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Incident Response |
| [Linux Live Response and Forensic Artifact Extraction](../../tasks/forensics/linux-live-response-forensics.md) | Workflow | Linux | Bash, Python | Forensics, Incident Response, Investigation |
| [Linux Service Failure Troubleshooting](../../tasks/troubleshooting/linux-service-failure.md) | Workflow | Linux | Bash | Troubleshooting, Administration |
| [Live Memory Acquisition and Volatility Analysis](../../tasks/forensics/memory-acquisition-analysis.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash, Python | Forensics, Incident Response, Investigation |
| [Local User and Group Administration](../../tasks/administration/local-user-group-management.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration |
| [Malware Triage](../../tasks/incident-response/malware-triage.md) | Workflow | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Incident Response, Forensics |
| [Network Adapter and IP Configuration](../../tasks/administration/network-adapter-ip-configuration.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration |
| [Network Investigation](../../tasks/investigation/network-investigation.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Network Services Management](../../tasks/administration/network-services-management.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Troubleshooting |
| [Package and Software Lifecycle Management](../../tasks/administration/package-software-management.md) | Workflow | Windows, Linux | PowerShell, Bash, CMD | Administration |
| [Scheduled Task and Cron Job Automation](../../tasks/administration/scheduled-jobs-task-scheduler.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Automation |
| [Storage Partitioning, Formatting and Filesystem Mounting](../../tasks/administration/storage-partitioning-mounting.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration |
| [Suspicious Outbound Connection](../../tasks/investigation/suspicious-outbound-connection.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Threat Hunting |
| [Suspicious Process Investigation](../../tasks/incident-response/suspicious-process.md) | Workflow | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Incident Response, Investigation |
| [System Maintenance and Updates](../../tasks/administration/system-maintenance-updates.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Automation |
| [Troubleshooting — Emergency Disk Space Exhaustion & Inode Recovery](../../tasks/troubleshooting/disk-space-emergency.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Troubleshooting, Administration |
| [Troubleshooting — High CPU Utilization & Runaway Processes](../../tasks/troubleshooting/high-cpu-troubleshooting.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Troubleshooting, Administration |
| [Troubleshooting — TLS/SSL Handshake & Certificate Failures](../../tasks/troubleshooting/certificate-handshake-failure.md) | Workflow | Linux, Windows, Windows Server | Bash, PowerShell | Troubleshooting, Investigation |
| [Assurance Check — Host Firewall Default Deny Stance](../../tasks/assurance/firewall-default-deny.md) | Entry | Windows, Linux | PowerShell, Bash | Assurance, Hardening |
| [Assurance Check — Linux Sudoers File Integrity](../../tasks/assurance/linux-sudoers-integrity.md) | Entry | Linux | Bash | Assurance, Hardening |
| [Azure & Entra ID Security Baseline — CIS Benchmark & NIST CSF 2.0](../../tasks/hardening/cloud-azure-security-baseline.md) | Entry | Azure, Entra ID, Microsoft 365 | PowerShell, Bash | Hardening, Assurance, Governance |
| [Bash Error Handling, Signals & Trap Handlers](error-handling-traps.md) | Entry | Linux | Bash | Automation, Troubleshooting |
| [Bash Pure Networking & /dev/tcp Socket Mechanics](networking-sockets.md) | Entry | Linux | Bash | Troubleshooting, Investigation |
| [Bash Scripting and Automation](automation.md) | Entry | Linux | Bash | Automation, Administration, Incident Response |
| [Bash Text Processing](text-processing.md) | Entry | Linux | Bash | Investigation, Automation, Threat Hunting |
| [Defensive Bash Scripting & Enterprise Boilerplate](defensive-scripting.md) | Entry | Linux | Bash | Automation, Hardening |
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
| [Linux Troubleshooting Commands](../../platforms/linux/troubleshooting.md) | Entry | Linux | Bash | Troubleshooting, Administration |
| [Linux Users and Permissions](../../platforms/linux/users-permissions.md) | Entry | Linux | Bash | Incident Response, Investigation, Administration, Hardening |
| [Modern Sysadmin CLI Toolkit — jq, yq, ripgrep & fzf](cli-tools-ecosystem.md) | Entry | Linux | Bash | Administration, Investigation |
| [OAuth 2.0 Bearer Token Authentication Flow](../../apis/authentication/bearer-tokens.md) | Entry | Entra ID, Microsoft 365 | PowerShell, Bash, REST API | Automation, Administration |
| [Proxmox VE](../../platforms/virtualization/proxmox.md) | Entry | Proxmox, Linux | Bash | Administration, Incident Response, Forensics |
| [Remote File Transfer — SCP, SFTP, rsync & WinRM](../../tasks/administration/remote-file-transfer.md) | Entry | Linux, Windows, Windows Server | Bash, PowerShell, CMD | Administration, Automation, Incident Response |
| [SentinelOne API — Query Threats](../../apis/sentinelone/threats.md) | Entry | SentinelOne | PowerShell, Bash, REST API | Incident Response, Threat Hunting |
| [Splunk REST API — Search Jobs Management](../../apis/splunk/management-jobs.md) | Entry | Splunk | PowerShell, Bash, REST API | Administration, Automation, Troubleshooting |
| [VMware ESXi CLI Forensics and Ransomware Hardening](../../platforms/virtualization/esxi-forensics-hardening.md) | Entry | VMware, Linux | Bash, PowerShell | Hardening, Incident Response, Forensics |
| [VMware vSphere and ESXi](../../platforms/virtualization/vmware.md) | Entry | VMware | PowerShell, Bash | Administration, Incident Response, Forensics |
| [Bash Toolbox](../../toolbox/bash.md) | Tool | Linux | Bash | Automation, Incident Response, Forensics, Investigation |
| [Cross-Platform Equivalents](../../references/equivalents.md) | Reference | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting, Administration |
| [Knowledge Graph Efficacy & Operational Coverage Matrix](../../references/coverage-matrix.md) | Reference | Windows, Windows Server, Linux, Azure, Entra ID, Microsoft Defender, SentinelOne, Splunk | PowerShell, Bash, Python, KQL, SPL, S1QL, REST API | Administration, Incident Response, Threat Hunting, Detection Engineering, Hardening, Assurance, Governance |
| [Linux Sysadmin Speed Dial Cheat Sheet](../../references/linux-cheat-sheet.md) | Reference | Linux | Bash | Administration, Troubleshooting, Investigation |
| [MITRE ATT&CK® Enterprise Matrix & Navigator Coverage](../../references/mitre-attack-matrix.md) | Reference | Windows, Linux, Azure, Entra ID, Microsoft Defender, SentinelOne, Splunk | KQL, SPL, S1QL, PowerShell, Bash | Detection Engineering, Incident Response, Threat Hunting, Hardening |
| [Sysadmin Quick Reference Cheat Sheet](../../references/sysadmin-cheat-sheet.md) | Reference | Windows, Windows Server, Linux, Microsoft 365, Entra ID | PowerShell, Bash, Windows CLI | Administration, Troubleshooting, Investigation |

<!-- /cc:index -->

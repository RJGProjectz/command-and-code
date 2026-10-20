---
title: Linux
type: index
---

# Linux

Commands and investigation techniques for common Linux distributions. Where Debian/Ubuntu and RHEL-family systems differ, both are shown.

## Quick answers

| I need to… | Go to |
| --- | --- |
| Find listening ports | [Networking → Find listening ports](networking.md#find-listening-ports) |
| Find a process from a PID | [Processes → Find a process by PID](processes.md#find-a-process-by-pid) |
| Find processes running from deleted binaries | [Processes](processes.md#processes-running-from-deleted-or-temporary-binaries) |
| List every user's crontab | [Cron](cron.md#list-every-users-crontab) |
| Find SSH authorized keys | [SSH](ssh.md#find-authorized-keys) |
| See failed SSH logins | [Logs](logs.md#failed-ssh-logins) |
| Hunt systemd persistence | [systemd](systemd.md#hunt-for-systemd-persistence) |
| Keep a job running after SSH drops (tmux/screen) | [Terminal sessions](terminal-sessions.md) |
| Containers see an empty NFS/SMB share after a reboot | [Shares, mounts & containers at boot](../../tasks/troubleshooting/services-shares-containers-boot-order.md) |

## All Linux entries

<!-- cc:index platforms="Linux" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Administration — Centralized Event Forwarding Pipeline (WEF & Rsyslog TLS)](../../tasks/administration/centralized-log-forwarding-wef-rsyslog.md) | Workflow | Windows Server, Windows, Linux | PowerShell, Bash | Administration, Detection Engineering, Hardening, Assurance |
| [Administration — Email Authentication Deployment (SPF, DKIM & DMARC)](../../tasks/administration/email-authentication-deployment.md) | Workflow | Linux, Microsoft 365 | Bash, PowerShell | Administration, Hardening, Investigation |
| [Administration — SSH Key Generation, Deployment & Best Practices](../../tasks/administration/ssh-key-deployment.md) | Workflow | Linux, Windows, Windows Server | Bash, PowerShell | Administration, Hardening |
| [Administration — Sysmon Enterprise Deployment & Telemetry Tuning](../../tasks/administration/sysmon-deployment-tuning.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Administration, Detection Engineering, Threat Hunting |
| [Administration — TLS/SSL Certificate Deployment & Web Server Hardening](../../tasks/administration/tls-certificate-deployment.md) | Workflow | Linux, Windows, Windows Server | Bash, PowerShell | Administration, Hardening |
| [Administration — WireGuard Secure VPN Gateway & Client Deployment](../../tasks/administration/wireguard-vpn-deployment.md) | Workflow | Linux, Windows | Bash, PowerShell | Administration, Hardening, Troubleshooting |
| [Alert Tuning and False Positive Management](../../tasks/detection-engineering/alert-tuning-false-positive-management.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | KQL, SPL, S1QL | Detection Engineering, Investigation, Incident Response |
| [Auditing Services, Share Mounts and Containers — Boot Order and the Common Failures](../../tasks/troubleshooting/services-shares-containers-boot-order.md) | Workflow | Linux, Proxmox | Bash | Troubleshooting, Administration, Assurance |
| [Automated IoC Enrichment and Threat Intelligence Pipeline](../../tasks/automation/automated-ioc-enrichment.md) | Workflow | Linux, Windows | PowerShell, Python, REST API | Automation, Incident Response, Investigation |
| [Backup and Recovery Operations](../../tasks/administration/backup-and-recovery.md) | Workflow | Hyper-V, VMware, Proxmox, Windows Server, Linux | PowerShell, Bash | Administration, Forensics |
| [Certificate and PKI Management](../../tasks/administration/certificate-and-pki-management.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Administration, Hardening |
| [CIS Hardening Lab Test (Before/After Diff and Run Checklist)](../../tasks/hardening/cis-hardening-lab-test.md) | Workflow | Windows, Linux | PowerShell, Bash | Hardening, Assurance |
| [Credential Rotation After a Compromise](../../tasks/incident-response/credential-rotation-after-compromise.md) | Workflow | Active Directory, Windows Server, Linux, Entra ID, Azure | PowerShell, Bash, CMD | Incident Response, Administration |
| [Cyber Threat Intelligence — Adversary Emulation & ATT&CK Profiling](../../tasks/threat-intelligence/adversary-emulation-profiling.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | PowerShell, Bash, KQL, SPL | Threat Intelligence, Detection Engineering, Assurance |
| [Cyber Threat Intelligence — IoC Ingestion, Aging & Confidence Scoring](../../tasks/threat-intelligence/ioc-lifecycle-scoring.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | Python, PowerShell, Bash, KQL, SPL | Threat Intelligence, Detection Engineering, Investigation |
| [Cyber Threat Intelligence — STIX 2.1 & TAXII Feed Ingestion Pipeline](../../tasks/threat-intelligence/stix-taxii-pipeline.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | Python, PowerShell, Bash, KQL, SPL | Threat Intelligence, Detection Engineering, Threat Hunting |
| [Detection Development Lifecycle (DDLC) and Testing](../../tasks/detection-engineering/detection-development-lifecycle.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | KQL, SPL, S1QL, Sigma, PowerShell | Detection Engineering, Threat Hunting, Incident Response |
| [DNS Client Resolution and Troubleshooting](../../tasks/administration/dns-resolution-troubleshooting.md) | Workflow | Windows, Linux | PowerShell, CMD, Bash | Administration, Troubleshooting |
| [Effective Permissions and Access Review (Windows and Linux)](../../tasks/assurance/effective-permissions-access-review.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Assurance, Hardening, Administration |
| [Endpoint Triage](../../tasks/incident-response/endpoint-triage.md) | Workflow | Windows, Linux | PowerShell, Bash | Incident Response, Forensics |
| [Failed Authentication Investigation](../../tasks/investigation/failed-authentication.md) | Workflow | Windows, Windows Server, Linux, Entra ID, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Troubleshooting |
| [Host Firewall and Port Management](../../tasks/administration/firewall-port-management.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Hardening |
| [Host Performance and System Resource Auditing](../../tasks/administration/performance-resource-auditing.md) | Workflow | Windows, Linux | PowerShell, Bash, Python | Administration, Troubleshooting |
| [Investigation Playbook — Ransomware Host Isolation](../../tasks/incident-response/ransomware-host-isolation.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Incident Response |
| [Investigation Workflow — Suspicious IP Address Analysis in Splunk](../../tasks/investigation/investigate-ip-splunk.md) | Workflow | Splunk, Windows, Linux | SPL | Investigation, Threat Hunting |
| [Linux CIS Benchmark — Access Control, PAM & SSH Hardening](../../tasks/hardening/linux-cis-access-pam-ssh.md) | Workflow | Linux | Bash | Hardening, Assurance, Administration |
| [Linux CIS Benchmark — Comprehensive Auditd & Telemetry Baseline](../../tasks/hardening/linux-cis-auditd-logging.md) | Workflow | Linux | Bash | Hardening, Detection Engineering, Forensics |
| [Linux CIS Benchmark — Filesystem Integrity & Service Hardening](../../tasks/hardening/linux-cis-filesystem-services.md) | Workflow | Linux | Bash | Hardening, Assurance, Administration |
| [Linux Live Response and Forensic Artifact Extraction](../../tasks/forensics/linux-live-response-forensics.md) | Workflow | Linux | Bash, Python | Forensics, Incident Response, Investigation |
| [Linux Service Accounts with Least Privilege](../../tasks/administration/linux-service-accounts-least-privilege.md) | Workflow | Linux | Bash | Administration, Hardening |
| [Linux Service Failure Troubleshooting](../../tasks/troubleshooting/linux-service-failure.md) | Workflow | Linux | Bash | Troubleshooting, Administration |
| [Live Memory Acquisition and Volatility Analysis](../../tasks/forensics/memory-acquisition-analysis.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash, Python | Forensics, Incident Response, Investigation |
| [Local User and Group Administration](../../tasks/administration/local-user-group-management.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration |
| [Malware Triage](../../tasks/incident-response/malware-triage.md) | Workflow | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Incident Response, Forensics |
| [Network Adapter and IP Configuration](../../tasks/administration/network-adapter-ip-configuration.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration |
| [Network Investigation](../../tasks/investigation/network-investigation.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Network Services Management](../../tasks/administration/network-services-management.md) | Workflow | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Troubleshooting |
| [Package and Software Lifecycle Management](../../tasks/administration/package-software-management.md) | Workflow | Windows, Linux | PowerShell, Bash, CMD | Administration |
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
| [Threat Hunting — Hypothesis-Driven SIEM Hunting in Splunk](../../tasks/threat-hunting/splunk-threat-hunting.md) | Workflow | Splunk, Windows, Linux | SPL | Threat Hunting, Detection Engineering |
| [Threat Hunting — Statistical Baselining & Frequency Analysis (LFO)](../../tasks/threat-hunting/statistical-baselining-frequency-analysis.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | KQL, SPL, S1QL, PowerShell, Bash | Threat Hunting, Detection Engineering, Investigation |
| [Troubleshooting — Emergency Disk Space Exhaustion & Inode Recovery](../../tasks/troubleshooting/disk-space-emergency.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Troubleshooting, Administration |
| [Troubleshooting — High CPU Utilization & Runaway Processes](../../tasks/troubleshooting/high-cpu-troubleshooting.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Troubleshooting, Administration |
| [Troubleshooting — TLS/SSL Handshake & Certificate Failures](../../tasks/troubleshooting/certificate-handshake-failure.md) | Workflow | Linux, Windows, Windows Server | Bash, PowerShell | Troubleshooting, Investigation |
| [VPN & Remote Access Tunnel Troubleshooting](../../tasks/troubleshooting/vpn-connectivity-troubleshooting.md) | Workflow | Windows, Linux | PowerShell, Bash, Windows CLI | Troubleshooting |
| [Assurance Check — Endpoint EDR Agent Health Status](../../tasks/assurance/endpoint-edr-status.md) | Entry | Windows, Linux | PowerShell | Assurance, Incident Response |
| [Assurance Check — Host Firewall Default Deny Stance](../../tasks/assurance/firewall-default-deny.md) | Entry | Windows, Linux | PowerShell, Bash | Assurance, Hardening |
| [Assurance Check — Linux Sudoers File Integrity](../../tasks/assurance/linux-sudoers-integrity.md) | Entry | Linux | Bash | Assurance, Hardening |
| [Bash Error Handling, Signals & Trap Handlers](../../languages/bash/error-handling-traps.md) | Entry | Linux | Bash | Automation, Troubleshooting |
| [Bash Pure Networking & /dev/tcp Socket Mechanics](../../languages/bash/networking-sockets.md) | Entry | Linux | Bash | Troubleshooting, Investigation |
| [Bash Scripting and Automation](../../languages/bash/automation.md) | Entry | Linux | Bash | Automation, Administration, Incident Response |
| [Bash Text Processing](../../languages/bash/text-processing.md) | Entry | Linux | Bash | Investigation, Automation, Threat Hunting |
| [Compare Files, Folders and Hashes](../../tasks/administration/compare-files-and-folders.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Investigation, Forensics |
| [Create and Extract Archives (zip, tar)](../../tasks/administration/create-and-extract-archives.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Investigation, Forensics |
| [Cross-platform data handling: Windows ↔ Linux, secrets, encodings and transport](../../fundamentals/systems/cross-platform-data-handling.md) | Entry | Windows, Linux, Proxmox | Python, PowerShell, Bash | Administration, Automation, Troubleshooting, Hardening |
| [Defensive Bash Scripting & Enterprise Boilerplate](../../languages/bash/defensive-scripting.md) | Entry | Linux | Bash | Automation, Hardening |
| [Detection Rule — ARP Spoofing (DAI and arpwatch)](../../detection/sigma/arp-spoofing-dai.md) | Entry | Linux, Splunk | Sigma, SPL, KQL | Detection Engineering, Threat Hunting |
| [Detection Rule — Cryptomining (Resource Hijacking)](../../detection/sigma/cryptomining.md) | Entry | Windows, Linux, Microsoft Defender | Sigma, KQL, SPL | Detection Engineering, Threat Hunting |
| [Environment Variables and PATH](../../tasks/administration/environment-variables-and-path.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Troubleshooting, Hardening |
| [File or Port in Use — Find and Stop the Holder](../../tasks/troubleshooting/file-or-port-in-use.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Troubleshooting, Administration |
| [Finding Files & Content Discovery](../../tasks/administration/file-search-discovery.md) | Entry | Linux, Windows, Windows Server | Bash, PowerShell, CMD | Administration, Investigation, Forensics |
| [Fundamentals — Agentic AI Architectures & Tool Execution](../../fundamentals/agentic-ai.md) | Entry | Linux | Python | Automation, Hardening |
| [Fundamentals — API Security & Error Handling](../../fundamentals/apis/security-error-handling.md) | Entry | Linux, Windows | REST API, PowerShell, Python | Automation, Administration, Hardening |
| [Fundamentals — Authentication & Token Lifecycles](../../fundamentals/apis/auth-tokens.md) | Entry | Linux, Windows | REST API, PowerShell, Python | Automation, Administration, Hardening |
| [Fundamentals — CIS Critical Security Controls & Benchmarks](../../fundamentals/grc/cis-benchmarks.md) | Entry | Windows, Windows Server, Linux | PowerShell, Bash | Assurance, Hardening, Administration |
| [Fundamentals — Cross-Site Request Forgery (CSRF) & State Defense](../../fundamentals/web-apps/csrf-defense.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Investigation, Detection Engineering |
| [Fundamentals — Cross-Site Scripting (XSS) & Content Security Policy](../../fundamentals/web-apps/xss-defense.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Investigation, Detection Engineering |
| [Fundamentals — DHCP Protocol Mechanics & IP Allocation](../../fundamentals/networking/dhcp.md) | Entry | Windows Server, Linux | PowerShell, Bash | Troubleshooting, Administration |
| [Fundamentals — DNS Protocol Mechanics & Security](../../fundamentals/dns.md) | Entry | Windows Server, Linux | PowerShell, Bash | Investigation, Hardening |
| [Fundamentals — Enterprise Prompt Engineering & Guardrails](../../fundamentals/ai-systems/prompt-engineering.md) | Entry | Linux | Python | Hardening, Automation |
| [Fundamentals — HTTP Security Headers & Transport Hardening](../../fundamentals/web-apps/http-security-headers.md) | Entry | Linux, Windows | HTTP, PowerShell, Bash | Hardening, Assurance, Troubleshooting |
| [Fundamentals — HTTP/HTTPS Protocol Mechanics & Headers](../../fundamentals/networking/http-https.md) | Entry | Linux, Windows Server | Bash, PowerShell | Investigation, Troubleshooting |
| [Fundamentals — LDAP Protocol, Directory Trees & LDAPS](../../fundamentals/identity/ldap.md) | Entry | Windows Server, Linux, Active Directory | PowerShell, Bash | Administration, Investigation |
| [Fundamentals — LLM Architecture & Inference Engineering](../../fundamentals/ai-llm-architecture.md) | Entry | Linux | Python | Hardening, Automation |
| [Fundamentals — NIST Cybersecurity Framework (CSF) 2.0](../../fundamentals/grc/nist-csf-2.md) | Entry | Windows, Linux, Microsoft 365, Azure | PowerShell, Bash, Python | Assurance, Hardening, Administration, Incident Response |
| [Fundamentals — OWASP Top 10 for Large Language Models](../../fundamentals/owasp-llm-top-10.md) | Entry | Linux | Python | Hardening, Assurance |
| [Fundamentals — OWASP Top 10 for Web Applications](../../fundamentals/web-apps/owasp-web-top-10.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Investigation, Detection Engineering |
| [Fundamentals — Pagination & High-Volume Ingestion](../../fundamentals/apis/pagination.md) | Entry | Linux, Windows | REST API, PowerShell, Python | Automation, Administration, Investigation |
| [Fundamentals — Public Key Infrastructure (PKI), CAs & Revocation](../../fundamentals/identity/pki.md) | Entry | Windows Server, Linux | PowerShell, Bash | Hardening, Administration |
| [Fundamentals — Rate Limiting & Exponential Backoff](../../fundamentals/apis/rate-limiting-backoff.md) | Entry | Linux, Windows | REST API, PowerShell, Python | Automation, Administration, Troubleshooting |
| [Fundamentals — Regulatory Compliance & Framework Cross-Walk](../../fundamentals/grc/regulatory-frameworks.md) | Entry | Windows, Linux, Azure, Microsoft 365 | PowerShell, Bash, Python | Assurance, Hardening, Administration |
| [Fundamentals — REST Architecture & HTTP Semantics](../../fundamentals/apis/rest-architecture.md) | Entry | Linux, Windows | REST API, PowerShell, Python | Automation, Administration, Troubleshooting |
| [Fundamentals — Retrieval-Augmented Generation (RAG) Architecture](../../fundamentals/rag-architecture.md) | Entry | Linux | Python | Automation, Investigation |
| [Fundamentals — Self-Hosted & Air-Gapped AI Model Runtimes](../../fundamentals/ai-systems/self-hosted-models.md) | Entry | Linux | Bash, Python | Hardening, Automation |
| [Fundamentals — Server-Side Request Forgery (SSRF) & Egress Defense](../../fundamentals/web-apps/ssrf-defense.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Investigation, Detection Engineering |
| [Fundamentals — Session Management & Cookie Security](../../fundamentals/web-apps/session-management.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Administration, Investigation |
| [Fundamentals — SMB Protocol & Network Share Security](../../fundamentals/smb.md) | Entry | Windows, Windows Server, Linux | PowerShell | Investigation, Hardening |
| [Fundamentals — SMTP Protocol, Relays & Email Authentication](../../fundamentals/networking/smtp.md) | Entry | Linux, Microsoft 365 | PowerShell, Bash | Investigation, Hardening |
| [Fundamentals — SQL Injection & Parameterized Defense](../../fundamentals/web-apps/sql-injection.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Investigation, Detection Engineering |
| [Fundamentals — SSH Key Architecture & Cryptographic Baselines](../../fundamentals/identity/ssh-keys.md) | Entry | Linux | Bash | Hardening, Administration |
| [Fundamentals — Sysmon Telemetry & Endpoint Monitoring](../../fundamentals/systems/sysmon.md) | Entry | Windows, Linux | PowerShell, Bash | Threat Hunting, Detection Engineering |
| [Fundamentals — TLS Handshake & Cipher Suite Mechanics](../../fundamentals/networking/tls-ssl.md) | Entry | Linux, Windows Server | Bash, PowerShell | Hardening, Investigation |
| [Fundamentals — Tokenization & Vector Embeddings in AI](../../fundamentals/ai-systems/tokenization-embeddings.md) | Entry | Linux | Python | Automation, Investigation |
| [Fundamentals — UEFI Boot Sequence & Secure Boot Mechanics](../../fundamentals/systems/uefi-secure-boot.md) | Entry | Windows, Linux | PowerShell, Bash | Hardening, Assurance |
| [Fundamentals — Vector Databases & Approximate Nearest Neighbors (ANN)](../../fundamentals/ai-systems/vector-databases.md) | Entry | Linux | Python | Automation, Investigation |
| [Fundamentals — Virtual Memory, Paging, Stack & Heap](../../fundamentals/systems/memory-internals.md) | Entry | Windows, Linux | PowerShell, Bash | Forensics, Investigation |
| [Fundamentals — VPN Protocols (IPsec vs SSL/TLS)](../../fundamentals/networking/vpn.md) | Entry | Windows, Linux | PowerShell, Bash | Troubleshooting, Hardening |
| [Fundamentals — Webhooks & Event-Driven Architecture](../../fundamentals/apis/webhooks-events.md) | Entry | Linux, Windows | REST API, PowerShell, Python | Automation, Administration, Incident Response |
| [Fundamentals — Zero Trust Network Microsegmentation](../../fundamentals/networking/microsegmentation.md) | Entry | Linux, Windows Server | Bash, PowerShell | Hardening, Assurance |
| [Identify File Types (Not by Extension)](../../tasks/administration/identify-file-types.md) | Entry | Windows, Windows Server, Linux | PowerShell, Bash | Administration, Investigation, Forensics |
| [Linux Antivirus & Endpoint Detection (EDR)](antivirus-edr.md) | Entry | Linux | Bash | Administration, Hardening, Incident Response |
| [Linux Audit Daemon (auditd) & Kernel Telemetry](auditd.md) | Entry | Linux | Bash | Forensics, Detection Engineering |
| [Linux Cron and Scheduled Jobs](cron.md) | Entry | Linux | Bash | Incident Response, Investigation, Threat Hunting, Administration |
| [Linux Distributions, Package Systems & Release Baselines](distros.md) | Entry | Linux | Bash | Administration, Troubleshooting |
| [Linux Filesystem](filesystem.md) | Entry | Linux | Bash | Incident Response, Investigation, Forensics, Troubleshooting |
| [Linux Firewalls — nftables, iptables & UFW Defense](firewalls-nftables.md) | Entry | Linux | Bash | Hardening, Administration |
| [Linux Installed Packages](packages.md) | Entry | Linux | Bash | Investigation, Administration, Forensics |
| [Linux Kernel Tuning & sysctl Runtime Optimization](kernel-tuning.md) | Entry | Linux | Bash | Hardening, Troubleshooting |
| [Linux Logs](logs.md) | Entry | Linux | Bash | Incident Response, Investigation, Troubleshooting, Forensics |
| [Linux Mandatory Access Control — SELinux & AppArmor](selinux-apparmor.md) | Entry | Linux | Bash | Hardening, Troubleshooting |
| [Linux Networking and DNS](networking.md) | Entry | Linux | Bash | Incident Response, Investigation, Troubleshooting, Administration |
| [Linux Processes](processes.md) | Entry | Linux | Bash | Incident Response, Investigation, Troubleshooting, Forensics |
| [Linux Security Baseline — CIS Benchmark & NIST CSF 2.0](../../tasks/hardening/linux-security-baseline.md) | Entry | Linux | Bash | Hardening, Assurance, Administration |
| [Linux Services with systemd](systemd.md) | Entry | Linux | Bash | Administration, Troubleshooting, Incident Response, Investigation |
| [Linux SSH](ssh.md) | Entry | Linux | Bash | Incident Response, Investigation, Hardening, Administration |
| [Linux Startup Persistence & Autostart Architecture](persistence.md) | Entry | Linux | Bash | Investigation, Forensics, Hardening |
| [Linux Storage, Partitioning & Logical Volume Management (LVM)](storage-lvm.md) | Entry | Linux | Bash | Administration, Troubleshooting |
| [Linux System Information](system-information.md) | Entry | Linux | Bash | Incident Response, Administration, Troubleshooting |
| [Linux Terminal Sessions — screen, tmux & Background Jobs](terminal-sessions.md) | Entry | Linux | Bash | Administration, Troubleshooting, Investigation, Incident Response |
| [Linux Troubleshooting Commands](troubleshooting.md) | Entry | Linux | Bash | Troubleshooting, Administration |
| [Linux Users and Permissions](users-permissions.md) | Entry | Linux | Bash | Incident Response, Investigation, Administration, Hardening |
| [Modern Sysadmin CLI Toolkit — jq, yq, ripgrep & fzf](../../languages/bash/cli-tools-ecosystem.md) | Entry | Linux | Bash | Administration, Investigation |
| [Proxmox VE](../virtualization/proxmox.md) | Entry | Proxmox, Linux | Bash | Administration, Incident Response, Forensics |
| [Python JSON and CSV](../../languages/python/json-csv.md) | Entry | Linux, Windows | Python | Automation, Investigation |
| [Python Logging and Automation](../../languages/python/logging-automation.md) | Entry | Linux, Windows | Python | Automation |
| [Python Subprocess and Filesystem](../../languages/python/subprocess-filesystem.md) | Entry | Linux, Windows | Python | Automation, Forensics, Incident Response |
| [Remote File Transfer — SCP, SFTP, rsync & WinRM](../../tasks/administration/remote-file-transfer.md) | Entry | Linux, Windows, Windows Server | Bash, PowerShell, CMD | Administration, Automation, Incident Response |
| [REST APIs — Jira & ServiceNow Security Incident Creation](../../apis/webhooks/jira-servicenow-incident-creation.md) | Entry | Linux, Windows | PowerShell, Python, REST API | Automation, Incident Response |
| [S1QL Defense Impairment and Tampering Queries](../../detection/s1ql/defense-evasion.md) | Entry | SentinelOne, Windows, Linux | S1QL | Threat Hunting, Incident Response, Detection Engineering |
| [S1QL Hunting Queries](../../detection/s1ql/hunting.md) | Entry | SentinelOne, Windows, Linux | S1QL | Threat Hunting, Incident Response, Investigation |
| [Search and Follow Logs by Keyword](../../tasks/administration/search-logs-by-keyword.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Troubleshooting, Investigation |
| [Shell Command History (PowerShell, CMD, Bash, Zsh)](../../tasks/administration/shell-command-history.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Investigation, Forensics, Incident Response |
| [Splunk Detection — Security Agent Tampering & EDR Impairment](../../detection/spl/agent-tampering.md) | Entry | Windows, Linux, SentinelOne, Splunk | SPL | Detection Engineering, Incident Response |
| [VMware ESXi CLI Forensics and Ransomware Hardening](../virtualization/esxi-forensics-hardening.md) | Entry | VMware, Linux | Bash, PowerShell | Hardening, Incident Response, Forensics |
| [Write Command Output to Files](../../tasks/administration/save-command-output-to-file.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Investigation, Automation |
| [Bash Toolbox](../../toolbox/bash.md) | Tool | Linux | Bash | Automation, Incident Response, Forensics, Investigation |
| [CIS Block Monitor (Windows and Linux)](../../tasks/hardening/cis-block-monitor.md) | Tool | Windows, Linux | PowerShell, Bash | Hardening, Detection Engineering, Assurance |
| [Command & Code CLI Lookup Utility](../../toolbox/lookup.md) | Tool | Windows, Linux | Python | Administration, Investigation |
| [Linux CIS Benchmark Audit Tool (Ubuntu 24.04, RHEL 9)](../../tasks/hardening/linux-cis-audit-tool.md) | Tool | Linux | Bash | Hardening, Assurance, Administration |
| [Python Toolbox](../../toolbox/python.md) | Tool | Windows, Linux, Microsoft 365, SentinelOne | Python | Automation, Incident Response, Investigation |
| [Service Account Audit (Windows, Active Directory, Linux)](../../tasks/assurance/service-account-audit.md) | Tool | Windows, Windows Server, Active Directory, Linux | PowerShell, Bash | Assurance, Hardening, Administration |
| [Command Index — All Shells](../../references/command-index.md) | Reference | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Troubleshooting, Investigation |
| [Cross-Platform Equivalents](../../references/equivalents.md) | Reference | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting, Administration |
| [Knowledge Graph Efficacy & Operational Coverage Matrix](../../references/coverage-matrix.md) | Reference | Windows, Windows Server, Linux, Azure, Entra ID, Microsoft Defender, SentinelOne, Splunk | PowerShell, Bash, Python, KQL, SPL, S1QL, REST API | Administration, Incident Response, Threat Hunting, Detection Engineering, Hardening, Assurance, Governance |
| [Linux Sysadmin Speed Dial Cheat Sheet](../../references/linux-cheat-sheet.md) | Reference | Linux | Bash | Administration, Troubleshooting, Investigation |
| [Linux Triage Cheat Sheet (Printable)](../../references/linux-triage-cheat-sheet.md) | Reference | Linux | Bash | Incident Response, Investigation, Forensics |
| [MITRE ATT&CK Mapping](../../detection/mitre-attack/index.md) | Reference | Windows, Linux, Microsoft 365 | MITRE ATT&CK | Detection Engineering, Threat Hunting, Incident Response |
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
| [Ransomware](../../fundamentals/concepts/ransomware.md) | Concept | Windows, Linux, VMware, SentinelOne | PowerShell, S1QL | Incident Response, Threat Hunting, Hardening |
| [Risk Management, Policies and Compliance Audits](../../fundamentals/concepts/risk-management-governance.md) | Concept | Windows, Linux | PowerShell | Assurance, Compliance |
| [Secure SDLC, DevSecOps and Secure Coding](../../fundamentals/concepts/secure-sdlc-devsecops.md) | Concept | Windows, Linux | PowerShell, Bash, Python | Hardening, Assurance, Automation |
| [Security Standards Map (ISO/IEC 27000 series, NIST SP 800)](../../fundamentals/concepts/security-standards-map.md) | Concept | Windows, Linux, Azure | PowerShell | Compliance, Assurance, Hardening |
| [Services and Daemons (Windows SCM, systemd)](../../fundamentals/concepts/services-daemons.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Threat Hunting, Hardening |
| [Surveillance, Counter-Surveillance and Deception](../../fundamentals/concepts/surveillance-deception.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, KQL | Threat Hunting, Detection Engineering, Investigation |
| [Users, Groups and Privilege (SIDs, UIDs, UAC, sudo)](../../fundamentals/concepts/users-groups-permissions.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Hardening, Incident Response |
| [Vulnerability Assessment and Patch Management](../../fundamentals/concepts/vulnerability-management.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Hardening, Assurance, Administration |
| [Wi-Fi Deauthentication and Rogue Access Points](../../fundamentals/concepts/wifi-deauth-rogue-ap.md) | Concept | Windows, Linux | PowerShell, Bash | Threat Hunting, Investigation, Hardening |
| [Wi-Fi Security (WEP, WPA, WPA2, WPA3)](../../fundamentals/concepts/wifi-security.md) | Concept | Windows, Linux | PowerShell, Bash, Windows CLI | Hardening, Investigation, Assurance |
| [Windows Registry (and the Linux /etc Equivalent)](../../fundamentals/concepts/windows-registry.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Forensics, Threat Hunting |
| [WPA/WPA2 Passphrase Attacks (Handshake Capture)](../../fundamentals/concepts/wifi-passphrase-attacks.md) | Concept | Windows, Linux | PowerShell, Bash | Hardening, Investigation, Threat Hunting |
| [Zero-Knowledge Proofs, Homomorphic Encryption and Blockchain](../../fundamentals/concepts/zero-knowledge-homomorphic-blockchain.md) | Concept | Windows, Linux | PowerShell, Bash | Threat Intelligence, Investigation |

<!-- /cc:index -->

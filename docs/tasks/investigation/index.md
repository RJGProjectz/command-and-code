---
title: Investigation
type: index
---

# Investigation

Answer specific questions about a host, account or connection: what happened, when, and how.

## Workflows

<!-- cc:index tasks="Investigation" type="workflow" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Account Compromise Investigation](../incident-response/account-compromise.md) | Workflow | Entra ID, Exchange Online, Microsoft 365, Windows | PowerShell, KQL | Incident Response, Investigation |
| [Administration — Email Authentication Deployment (SPF, DKIM & DMARC)](../administration/email-authentication-deployment.md) | Workflow | Linux, Microsoft 365 | Bash, PowerShell | Administration, Hardening, Investigation |
| [Alert Tuning and False Positive Management](../detection-engineering/alert-tuning-false-positive-management.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | KQL, SPL, S1QL | Detection Engineering, Investigation, Incident Response |
| [Automated IoC Enrichment and Threat Intelligence Pipeline](../automation/automated-ioc-enrichment.md) | Workflow | Linux, Windows | PowerShell, Python, REST API | Automation, Incident Response, Investigation |
| [Cyber Threat Intelligence — IoC Ingestion, Aging & Confidence Scoring](../threat-intelligence/ioc-lifecycle-scoring.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | Python, PowerShell, Bash, KQL, SPL | Threat Intelligence, Detection Engineering, Investigation |
| [Failed Authentication Investigation](failed-authentication.md) | Workflow | Windows, Windows Server, Linux, Entra ID, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Troubleshooting |
| [Hunting Cloud Identity Persistence in Entra ID and Microsoft 365](../threat-hunting/cloud-identity-persistence-hunting.md) | Workflow | Entra ID, Microsoft 365, Azure, Microsoft Defender, Splunk | PowerShell, KQL, SPL | Threat Hunting, Incident Response, Investigation |
| [Hunting Kerberoasting and AS-REP Roasting in Active Directory](../threat-hunting/kerberoasting-asreproast-hunting.md) | Workflow | Active Directory, Windows, Windows Server, Splunk, Microsoft Defender | PowerShell, KQL, SPL | Threat Hunting, Investigation, Incident Response |
| [Hunting Living-off-the-Land Binaries and Scripts (LOLBins)](../threat-hunting/lolbins-execution-hunting.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk, SentinelOne | PowerShell, KQL, SPL, S1QL | Threat Hunting, Detection Engineering, Investigation |
| [Investigation Playbook — Azure Resource Hijacking](../incident-response/azure-resource-hijacking.md) | Workflow | Azure, Microsoft 365 | KQL, PowerShell | Incident Response, Investigation |
| [Investigation Playbook — Compromised Service Principal](../incident-response/compromised-service-principal.md) | Workflow | Entra ID, Azure | KQL, PowerShell | Incident Response, Investigation |
| [Investigation Playbook — Phishing Email Triage](../incident-response/phishing-email-triage.md) | Workflow | Microsoft 365, Exchange Online | PowerShell, KQL | Incident Response, Investigation |
| [Investigation Workflow — Compromised Host Forensics in Splunk](investigate-device-splunk.md) | Workflow | Splunk, Windows, Windows Server | SPL | Investigation, Forensics, Incident Response |
| [Investigation Workflow — Compromised User Identity Triage in Splunk](investigate-user-splunk.md) | Workflow | Splunk, Windows, Entra ID | SPL | Investigation, Incident Response |
| [Investigation Workflow — Suspicious IP Address Analysis in Splunk](investigate-ip-splunk.md) | Workflow | Splunk, Windows, Linux | SPL | Investigation, Threat Hunting |
| [Linux Live Response and Forensic Artifact Extraction](../forensics/linux-live-response-forensics.md) | Workflow | Linux | Bash, Python | Forensics, Incident Response, Investigation |
| [Live Memory Acquisition and Volatility Analysis](../forensics/memory-acquisition-analysis.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash, Python | Forensics, Incident Response, Investigation |
| [Microsoft Purview and Unified Audit Log (UAL) Investigation](../../platforms/microsoft-365/audit-log-investigation.md) | Workflow | Microsoft 365, Entra ID, Exchange Online | PowerShell | Investigation, Incident Response, Forensics |
| [Network Investigation](network-investigation.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Possible Lateral Movement](../threat-hunting/lateral-movement.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk | PowerShell, KQL, SPL | Threat Hunting, Incident Response, Investigation |
| [Registry Persistence Investigation](registry-persistence.md) | Workflow | Windows, Microsoft Defender, SentinelOne | PowerShell, Windows CLI, KQL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Scheduled Task and Cron Persistence Review (Windows, Linux, macOS)](../threat-hunting/scheduled-task-persistence-review.md) | Workflow | Windows, Windows Server, Linux, Microsoft Defender, Splunk | PowerShell, Windows CLI, Bash, KQL, SPL, MITRE ATT&CK | Threat Hunting, Investigation, Incident Response |
| [Scheduled Task Investigation](scheduled-task-investigation.md) | Workflow | Windows, Microsoft Defender, Splunk, SentinelOne | PowerShell, Windows CLI, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Suspicious Outbound Connection](suspicious-outbound-connection.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Threat Hunting |
| [Suspicious PowerShell Investigation](../incident-response/suspicious-powershell.md) | Workflow | Windows, Microsoft Defender, Splunk, SentinelOne | PowerShell, KQL, SPL, S1QL | Incident Response, Investigation |
| [Suspicious Process Investigation](../incident-response/suspicious-process.md) | Workflow | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Incident Response, Investigation |
| [Suspicious Service Investigation](suspicious-service.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk | PowerShell, Windows CLI, KQL, SPL | Investigation, Incident Response |
| [Threat Hunting — Cloud Identity, OAuth Grants & Ephemeral Asset Anomalies](../threat-hunting/cloud-infrastructure-ephemeral-asset-hunting.md) | Workflow | Entra ID, Microsoft 365, Azure, Microsoft Defender, Splunk | KQL, SPL, PowerShell | Threat Hunting, Incident Response, Investigation |
| [Threat Hunting — Cross-Platform Behavioral Telemetry (Windows & Linux)](../threat-hunting/cross-platform-behavioral-hunting.md) | Workflow | Windows, Windows Server, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Threat Hunting, Detection Engineering, Investigation |
| [Threat Hunting — Statistical Baselining & Frequency Analysis (LFO)](../threat-hunting/statistical-baselining-frequency-analysis.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | KQL, SPL, S1QL, PowerShell, Bash | Threat Hunting, Detection Engineering, Investigation |
| [Troubleshooting — TLS/SSL Handshake & Certificate Failures](../troubleshooting/certificate-handshake-failure.md) | Workflow | Linux, Windows, Windows Server | Bash, PowerShell | Troubleshooting, Investigation |

<!-- /cc:index -->

## Reference entries

<!-- cc:index tasks="Investigation" type="entry|tool|reference" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Amazon CloudWatch, Logs Insights & Athena](../../platforms/aws/monitoring-logs.md) | Entry | AWS | Bash, Python | Investigation, Troubleshooting, Detection Engineering, Administration |
| [Amazon EC2 & Systems Manager (Compute)](../../platforms/aws/compute.md) | Entry | AWS | Bash, PowerShell | Administration, Investigation, Incident Response |
| [Amazon Elastic Kubernetes Service (EKS)](../../platforms/aws/kubernetes.md) | Entry | AWS | Bash | Administration, Hardening, Investigation, Incident Response |
| [Amazon S3 & Data Exposure](../../platforms/aws/storage.md) | Entry | AWS | Bash | Administration, Hardening, Investigation, Incident Response |
| [AWS CloudTrail (Audit Logging)](../../platforms/aws/audit-logging.md) | Entry | AWS | Bash, Python | Investigation, Incident Response, Forensics, Hardening |
| [AWS Identity & Access (IAM)](../../platforms/aws/identity-access.md) | Entry | AWS | Bash, Python | Administration, Hardening, Investigation, Assurance |
| [AWS Incident Response & Forensics](../../platforms/aws/incident-response.md) | Entry | AWS | Bash | Incident Response, Forensics, Investigation |
| [AWS KMS, Secrets Manager & Parameter Store](../../platforms/aws/keys-secrets.md) | Entry | AWS | Bash, Python | Administration, Hardening, Investigation, Incident Response |
| [AWS Networking (VPC, Security Groups, Flow Logs)](../../platforms/aws/networking.md) | Entry | AWS | Bash | Administration, Troubleshooting, Investigation, Hardening |
| [AWS Organizations, Accounts & Inventory](../../platforms/aws/resource-hierarchy.md) | Entry | AWS | Bash, Python | Administration, Investigation, Assurance |
| [AWS Persistence & Threat Hunting](../../platforms/aws/persistence-hunting.md) | Entry | AWS | Bash, Python | Threat Hunting, Incident Response, Investigation, Detection Engineering |
| [AWS Security Hub, GuardDuty & Inspector (Posture & Alerts)](../../platforms/aws/security-posture.md) | Entry | AWS | Bash | Assurance, Hardening, Investigation, Incident Response |
| [Azure Audit Logging (Activity Log & Diagnostic Settings)](../../platforms/azure/audit-logging.md) | Entry | Azure, Entra ID | Bash, PowerShell, KQL | Investigation, Incident Response, Forensics, Hardening |
| [Azure Identity & Access (RBAC, PIM, Managed Identities)](../../platforms/azure/identity-access.md) | Entry | Azure, Entra ID | Bash, PowerShell, KQL | Administration, Hardening, Investigation, Assurance |
| [Azure Incident Response & Forensics](../../platforms/azure/incident-response.md) | Entry | Azure, Entra ID | Bash, PowerShell, KQL | Incident Response, Forensics, Investigation |
| [Azure Key Vault (Keys, Secrets & Certificates)](../../platforms/azure/keys-secrets.md) | Entry | Azure | Bash, PowerShell, KQL | Administration, Hardening, Investigation, Incident Response |
| [Azure Kubernetes Service (AKS)](../../platforms/azure/kubernetes.md) | Entry | Azure | Bash, KQL | Administration, Hardening, Investigation, Incident Response |
| [Azure Monitor & Log Analytics Queries](../../platforms/azure/monitoring-logs.md) | Entry | Azure | Bash, PowerShell, KQL | Investigation, Troubleshooting, Detection Engineering, Administration |
| [Azure Networking (VNets, NSGs, Flow Logs, Firewall)](../../platforms/azure/networking.md) | Entry | Azure | Bash, PowerShell, KQL | Administration, Troubleshooting, Investigation, Hardening |
| [Azure Persistence & Threat Hunting](../../platforms/azure/persistence-hunting.md) | Entry | Azure, Entra ID | KQL, Bash, PowerShell | Threat Hunting, Incident Response, Investigation, Detection Engineering |
| [Azure Resource Hierarchy & Inventory](../../platforms/azure/resource-hierarchy.md) | Entry | Azure | Bash, PowerShell, KQL | Administration, Investigation, Assurance |
| [Azure Storage & Data Exposure](../../platforms/azure/storage.md) | Entry | Azure | Bash, PowerShell, KQL | Administration, Hardening, Investigation, Incident Response |
| [Azure Virtual Machines (Compute)](../../platforms/azure/compute.md) | Entry | Azure | Bash, PowerShell, KQL | Administration, Investigation, Incident Response |
| [Bash Pure Networking & /dev/tcp Socket Mechanics](../../languages/bash/networking-sockets.md) | Entry | Linux | Bash | Troubleshooting, Investigation |
| [Bash Text Processing](../../languages/bash/text-processing.md) | Entry | Linux | Bash | Investigation, Automation, Threat Hunting |
| [Compare Files, Folders and Hashes](../administration/compare-files-and-folders.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Investigation, Forensics |
| [Conditional Access](../../platforms/microsoft-365/conditional-access.md) | Entry | Microsoft 365, Entra ID | PowerShell, KQL | Administration, Hardening, Investigation, Troubleshooting |
| [Create and Extract Archives (zip, tar)](../administration/create-and-extract-archives.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Investigation, Forensics |
| [Detection Rules — Wi-Fi (WLAN-AutoConfig and Unknown Devices)](../../detection/sigma/wlan-events.md) | Entry | Windows, Windows Server | Sigma, KQL, SPL | Detection Engineering, Investigation |
| [Entra ID](../../platforms/microsoft-365/entra.md) | Entry | Microsoft 365, Entra ID | PowerShell | Incident Response, Investigation, Administration |
| [Exchange Online](../../platforms/microsoft-365/exchange.md) | Entry | Microsoft 365, Exchange Online | PowerShell | Incident Response, Investigation, Administration |
| [Finding Files & Content Discovery](../administration/file-search-discovery.md) | Entry | Linux, Windows, Windows Server | Bash, PowerShell, CMD | Administration, Investigation, Forensics |
| [Fundamentals — Cross-Site Request Forgery (CSRF) & State Defense](../../fundamentals/web-apps/csrf-defense.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Investigation, Detection Engineering |
| [Fundamentals — Cross-Site Scripting (XSS) & Content Security Policy](../../fundamentals/web-apps/xss-defense.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Investigation, Detection Engineering |
| [Fundamentals — DNS Protocol Mechanics & Security](../../fundamentals/dns.md) | Entry | Windows Server, Linux | PowerShell, Bash | Investigation, Hardening |
| [Fundamentals — HTTP/HTTPS Protocol Mechanics & Headers](../../fundamentals/networking/http-https.md) | Entry | Linux, Windows Server | Bash, PowerShell | Investigation, Troubleshooting |
| [Fundamentals — Kerberos Authentication Protocol](../../fundamentals/kerberos.md) | Entry | Windows, Active Directory | PowerShell | Investigation, Hardening |
| [Fundamentals — LDAP Protocol, Directory Trees & LDAPS](../../fundamentals/identity/ldap.md) | Entry | Windows Server, Linux, Active Directory | PowerShell, Bash | Administration, Investigation |
| [Fundamentals — OAuth 2.0 Authorization & OIDC Mechanics](../../fundamentals/identity/oauth2.md) | Entry | Entra ID, Microsoft 365 | PowerShell | Automation, Investigation |
| [Fundamentals — OWASP Top 10 for Web Applications](../../fundamentals/web-apps/owasp-web-top-10.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Investigation, Detection Engineering |
| [Fundamentals — Pagination & High-Volume Ingestion](../../fundamentals/apis/pagination.md) | Entry | Linux, Windows | REST API, PowerShell, Python | Automation, Administration, Investigation |
| [Fundamentals — Retrieval-Augmented Generation (RAG) Architecture](../../fundamentals/rag-architecture.md) | Entry | Linux | Python | Automation, Investigation |
| [Fundamentals — Server-Side Request Forgery (SSRF) & Egress Defense](../../fundamentals/web-apps/ssrf-defense.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Investigation, Detection Engineering |
| [Fundamentals — Session Management & Cookie Security](../../fundamentals/web-apps/session-management.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Administration, Investigation |
| [Fundamentals — SMB Protocol & Network Share Security](../../fundamentals/smb.md) | Entry | Windows, Windows Server, Linux | PowerShell | Investigation, Hardening |
| [Fundamentals — SMTP Protocol, Relays & Email Authentication](../../fundamentals/networking/smtp.md) | Entry | Linux, Microsoft 365 | PowerShell, Bash | Investigation, Hardening |
| [Fundamentals — SQL Injection & Parameterized Defense](../../fundamentals/web-apps/sql-injection.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Investigation, Detection Engineering |
| [Fundamentals — TLS Handshake & Cipher Suite Mechanics](../../fundamentals/networking/tls-ssl.md) | Entry | Linux, Windows Server | Bash, PowerShell | Hardening, Investigation |
| [Fundamentals — Tokenization & Vector Embeddings in AI](../../fundamentals/ai-systems/tokenization-embeddings.md) | Entry | Linux | Python | Automation, Investigation |
| [Fundamentals — Vector Databases & Approximate Nearest Neighbors (ANN)](../../fundamentals/ai-systems/vector-databases.md) | Entry | Linux | Python | Automation, Investigation |
| [Fundamentals — Virtual Memory, Paging, Stack & Heap](../../fundamentals/systems/memory-internals.md) | Entry | Windows, Linux | PowerShell, Bash | Forensics, Investigation |
| [Fundamentals — Windows Process Architecture, Tokens & Handles](../../fundamentals/systems/windows-processes.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Investigation, Forensics |
| [Google Cloud Audit Logs](../../platforms/gcp/audit-logging.md) | Entry | GCP | Bash | Investigation, Incident Response, Forensics, Hardening |
| [Google Cloud IAM (Identity & Access)](../../platforms/gcp/identity-access.md) | Entry | GCP | Bash, Python | Administration, Hardening, Investigation, Incident Response |
| [Google Cloud Incident Response & Forensics](../../platforms/gcp/incident-response.md) | Entry | GCP | Bash | Incident Response, Forensics, Investigation |
| [Google Cloud KMS & Secret Manager](../../platforms/gcp/keys-secrets.md) | Entry | GCP | Bash, Python | Administration, Hardening, Investigation, Incident Response |
| [Google Cloud Logging & BigQuery Log Queries](../../platforms/gcp/monitoring-logs.md) | Entry | GCP | Bash | Investigation, Troubleshooting, Detection Engineering, Administration |
| [Google Cloud Persistence & Threat Hunting](../../platforms/gcp/persistence-hunting.md) | Entry | GCP | Bash, Python | Threat Hunting, Incident Response, Investigation, Detection Engineering |
| [Google Cloud Resource Hierarchy & Inventory](../../platforms/gcp/resource-hierarchy.md) | Entry | GCP | Bash | Administration, Investigation, Assurance |
| [Google Cloud Storage (Buckets & Data Exposure)](../../platforms/gcp/storage.md) | Entry | GCP | Bash, Python | Administration, Hardening, Investigation, Assurance |
| [Google Cloud VPC & Firewall Rules](../../platforms/gcp/networking.md) | Entry | GCP | Bash | Administration, Hardening, Investigation, Incident Response |
| [Google Compute Engine & OS Login](../../platforms/gcp/compute.md) | Entry | GCP | Bash | Administration, Hardening, Investigation, Incident Response |
| [Google Kubernetes Engine (GKE)](../../platforms/gcp/kubernetes.md) | Entry | GCP | Bash | Administration, Hardening, Investigation, Incident Response |
| [Identify File Types (Not by Extension)](../administration/identify-file-types.md) | Entry | Windows, Windows Server, Linux | PowerShell, Bash | Administration, Investigation, Forensics |
| [KQL File, Registry and Persistence Hunting](../../detection/kql/file-registry-events.md) | Entry | Microsoft Defender, Windows | KQL | Threat Hunting, Detection Engineering, Investigation |
| [KQL Fundamentals](../../detection/kql/fundamentals.md) | Entry | Microsoft Defender, Microsoft 365 | KQL | Threat Hunting, Detection Engineering, Investigation |
| [KQL Logon and Identity Hunting](../../detection/kql/logon-identity.md) | Entry | Microsoft Defender, Entra ID, Microsoft 365, Windows | KQL | Threat Hunting, Investigation, Incident Response, Detection Engineering |
| [KQL Network Event Hunting](../../detection/kql/network-events.md) | Entry | Microsoft Defender, Windows | KQL | Threat Hunting, Investigation, Detection Engineering, Incident Response |
| [KQL Process Event Hunting](../../detection/kql/process-events.md) | Entry | Microsoft Defender, Windows | KQL | Threat Hunting, Detection Engineering, Investigation, Incident Response |
| [Linux Cron and Scheduled Jobs](../../platforms/linux/cron.md) | Entry | Linux | Bash | Incident Response, Investigation, Threat Hunting, Administration |
| [Linux Filesystem](../../platforms/linux/filesystem.md) | Entry | Linux | Bash | Incident Response, Investigation, Forensics, Troubleshooting |
| [Linux Installed Packages](../../platforms/linux/packages.md) | Entry | Linux | Bash | Investigation, Administration, Forensics |
| [Linux Logs](../../platforms/linux/logs.md) | Entry | Linux | Bash | Incident Response, Investigation, Troubleshooting, Forensics |
| [Linux Networking and DNS](../../platforms/linux/networking.md) | Entry | Linux | Bash | Incident Response, Investigation, Troubleshooting, Administration |
| [Linux Processes](../../platforms/linux/processes.md) | Entry | Linux | Bash | Incident Response, Investigation, Troubleshooting, Forensics |
| [Linux Services with systemd](../../platforms/linux/systemd.md) | Entry | Linux | Bash | Administration, Troubleshooting, Incident Response, Investigation |
| [Linux SSH](../../platforms/linux/ssh.md) | Entry | Linux | Bash | Incident Response, Investigation, Hardening, Administration |
| [Linux Startup Persistence & Autostart Architecture](../../platforms/linux/persistence.md) | Entry | Linux | Bash | Investigation, Forensics, Hardening |
| [Linux Terminal Sessions — screen, tmux & Background Jobs](../../platforms/linux/terminal-sessions.md) | Entry | Linux | Bash | Administration, Troubleshooting, Investigation, Incident Response |
| [Linux Users and Permissions](../../platforms/linux/users-permissions.md) | Entry | Linux | Bash | Incident Response, Investigation, Administration, Hardening |
| [Microsoft Defender for Cloud (Posture & Alerts)](../../platforms/azure/security-posture.md) | Entry | Azure, Microsoft Defender | Bash, PowerShell, KQL | Assurance, Hardening, Investigation, Incident Response |
| [Microsoft Graph API — Audit Sign-In Logs](../../apis/microsoft-graph/sign-in-logs.md) | Entry | Entra ID, Microsoft 365 | PowerShell, REST API | Investigation, Threat Hunting, Incident Response |
| [Modern Sysadmin CLI Toolkit — jq, yq, ripgrep & fzf](../../languages/bash/cli-tools-ecosystem.md) | Entry | Linux | Bash | Administration, Investigation |
| [PowerShell JSON and CSV](../../languages/powershell/json-csv.md) | Entry | Windows, Windows Server | PowerShell | Automation, Investigation |
| [Python JSON and CSV](../../languages/python/json-csv.md) | Entry | Linux, Windows | Python | Automation, Investigation |
| [S1QL Fundamentals](../../detection/s1ql/fundamentals.md) | Entry | SentinelOne | S1QL | Threat Hunting, Investigation, Detection Engineering |
| [S1QL Hunting Queries](../../detection/s1ql/hunting.md) | Entry | SentinelOne, Windows, Linux | S1QL | Threat Hunting, Incident Response, Investigation |
| [Search and Follow Logs by Keyword](../administration/search-logs-by-keyword.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Troubleshooting, Investigation |
| [Security Command Center (GCP Posture & Alerts)](../../platforms/gcp/security-posture.md) | Entry | GCP | Bash | Assurance, Hardening, Investigation, Incident Response |
| [Shell Command History (PowerShell, CMD, Bash, Zsh)](../administration/shell-command-history.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Investigation, Forensics, Incident Response |
| [SPL Fundamentals and Search Optimization](../../detection/spl/fundamentals.md) | Entry | Splunk | SPL | Threat Hunting, Detection Engineering, Investigation |
| [SPL Network and DNS Hunting](../../detection/spl/network-dns.md) | Entry | Splunk | SPL | Threat Hunting, Investigation, Detection Engineering |
| [SPL Windows Security Events](../../detection/spl/windows-events.md) | Entry | Splunk, Windows | SPL | Threat Hunting, Detection Engineering, Investigation, Incident Response |
| [System32 Native Executables Field Guide](../../languages/windows-cli/system32-toolkit.md) | Entry | Windows, Windows Server | CMD, Windows CLI | Administration, Investigation, Troubleshooting, Incident Response |
| [Text Processing & findstr](../../languages/windows-cli/text-processing.md) | Entry | Windows, Windows Server | CMD, Windows CLI | Investigation, Automation, Administration |
| [Windows Event Logs](../../platforms/windows/event-logs.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Forensics, Hardening |
| [Windows Files and Permissions](../../platforms/windows/files-directories.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Forensics, Hardening |
| [Windows Forensic Disk Artifacts and Evidence Triage](../forensics/windows-disk-artifacts.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI, Python | Forensics, Investigation, Incident Response |
| [Windows Installed Software](../../platforms/windows/software.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Investigation, Administration, Incident Response |
| [Windows Networking and DNS](../../platforms/windows/networking.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Troubleshooting, Administration |
| [Windows Processes](../../platforms/windows/processes.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Troubleshooting, Forensics |
| [Windows Registry and Run Keys](../../platforms/windows/registry.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Forensics, Threat Hunting |
| [Windows Scheduled Tasks](../../platforms/windows/scheduled-tasks.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Threat Hunting, Administration |
| [Windows Services](../../platforms/windows/services.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Administration, Hardening |
| [Windows Users and Groups](../../platforms/windows/users-groups.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Administration, Hardening |
| [Write Command Output to Files](../administration/save-command-output-to-file.md) | Entry | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Investigation, Automation |
| [Bash Toolbox](../../toolbox/bash.md) | Tool | Linux | Bash | Automation, Incident Response, Forensics, Investigation |
| [Command & Code CLI Lookup Utility](../../toolbox/lookup.md) | Tool | Windows, Linux | Python | Administration, Investigation |
| [PowerShell Toolbox](../../toolbox/powershell.md) | Tool | Windows, Windows Server | PowerShell | Automation, Incident Response, Forensics, Investigation |
| [Python Toolbox](../../toolbox/python.md) | Tool | Windows, Linux, Microsoft 365, SentinelOne | Python | Automation, Incident Response, Investigation |
| [Cloud Incident Response Cheat Sheet (Printable)](../../references/cloud-ir-cheat-sheet.md) | Reference | AWS, Azure, GCP | Bash, PowerShell | Incident Response, Investigation, Forensics |
| [Command Index — All Shells](../../references/command-index.md) | Reference | Windows, Windows Server, Linux | PowerShell, CMD, Bash | Administration, Troubleshooting, Investigation |
| [Cross-Platform Equivalents](../../references/equivalents.md) | Reference | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting, Administration |
| [Linux Sysadmin Speed Dial Cheat Sheet](../../references/linux-cheat-sheet.md) | Reference | Linux | Bash | Administration, Troubleshooting, Investigation |
| [Linux Triage Cheat Sheet (Printable)](../../references/linux-triage-cheat-sheet.md) | Reference | Linux | Bash | Incident Response, Investigation, Forensics |
| [PowerShell Admin One-Liners Cheat Sheet](../../references/powershell-cheat-sheet.md) | Reference | Windows, Windows Server | PowerShell | Administration, Investigation, Automation |
| [Sysadmin Quick Reference Cheat Sheet](../../references/sysadmin-cheat-sheet.md) | Reference | Windows, Windows Server, Linux, Microsoft 365, Entra ID | PowerShell, Bash, Windows CLI | Administration, Troubleshooting, Investigation |
| [Windows Event ID Reference](../../references/windows-event-ids.md) | Reference | Windows, Windows Server | PowerShell, SPL, KQL | Investigation, Incident Response, Detection Engineering, Forensics |
| [Windows Triage Cheat Sheet (Printable)](../../references/windows-triage-cheat-sheet.md) | Reference | Windows | PowerShell, Windows CLI | Incident Response, Investigation, Forensics |

<!-- /cc:index -->

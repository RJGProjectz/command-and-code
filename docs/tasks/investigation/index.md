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
| [Failed Authentication Investigation](failed-authentication.md) | Workflow | Windows, Windows Server, Linux, Entra ID, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Troubleshooting |
| [Investigation Playbook — Azure Resource Hijacking](../incident-response/azure-resource-hijacking.md) | Workflow | Azure, Microsoft 365 | KQL, PowerShell | Incident Response, Investigation |
| [Investigation Playbook — Compromised Service Principal](../incident-response/compromised-service-principal.md) | Workflow | Entra ID, Azure | KQL, PowerShell | Incident Response, Investigation |
| [Investigation Playbook — Phishing Email Triage](../incident-response/phishing-email-triage.md) | Workflow | Microsoft 365, Exchange Online | PowerShell, KQL | Incident Response, Investigation |
| [Investigation Workflow — Compromised Host Forensics in Splunk](investigate-device-splunk.md) | Workflow | Splunk, Windows, Windows Server | SPL | Investigation, Forensics, Incident Response |
| [Investigation Workflow — Compromised User Identity Triage in Splunk](investigate-user-splunk.md) | Workflow | Splunk, Windows, Entra ID | SPL | Investigation, Incident Response |
| [Investigation Workflow — Suspicious IP Address Analysis in Splunk](investigate-ip-splunk.md) | Workflow | Splunk, Windows, Linux | SPL | Investigation, Threat Hunting |
| [Network Investigation](network-investigation.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Possible Lateral Movement](../threat-hunting/lateral-movement.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk | PowerShell, KQL, SPL | Threat Hunting, Incident Response, Investigation |
| [Registry Persistence Investigation](registry-persistence.md) | Workflow | Windows, Microsoft Defender, SentinelOne | PowerShell, Windows CLI, KQL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Scheduled Task Investigation](scheduled-task-investigation.md) | Workflow | Windows, Microsoft Defender, Splunk, SentinelOne | PowerShell, Windows CLI, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Suspicious Outbound Connection](suspicious-outbound-connection.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Threat Hunting |
| [Suspicious PowerShell Investigation](../incident-response/suspicious-powershell.md) | Workflow | Windows, Microsoft Defender, Splunk, SentinelOne | PowerShell, KQL, SPL, S1QL | Incident Response, Investigation |
| [Suspicious Process Investigation](../incident-response/suspicious-process.md) | Workflow | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Incident Response, Investigation |
| [Suspicious Service Investigation](suspicious-service.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk | PowerShell, Windows CLI, KQL, SPL | Investigation, Incident Response |
| [Troubleshooting — TLS/SSL Handshake & Certificate Failures](../troubleshooting/certificate-handshake-failure.md) | Workflow | Linux, Windows, Windows Server | Bash, PowerShell | Troubleshooting, Investigation |

<!-- /cc:index -->

## Reference entries

<!-- cc:index tasks="Investigation" type="entry|tool|reference" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Bash Pure Networking & /dev/tcp Socket Mechanics](../../languages/bash/networking-sockets.md) | Entry | Linux | Bash | Troubleshooting, Investigation |
| [Bash Text Processing](../../languages/bash/text-processing.md) | Entry | Linux | Bash | Investigation, Automation, Threat Hunting |
| [Conditional Access](../../platforms/microsoft-365/conditional-access.md) | Entry | Microsoft 365, Entra ID | PowerShell, KQL | Administration, Hardening, Investigation, Troubleshooting |
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
| [Linux Users and Permissions](../../platforms/linux/users-permissions.md) | Entry | Linux | Bash | Incident Response, Investigation, Administration, Hardening |
| [Microsoft Graph API — Audit Sign-In Logs](../../apis/microsoft-graph/sign-in-logs.md) | Entry | Entra ID, Microsoft 365 | PowerShell, REST API | Investigation, Threat Hunting, Incident Response |
| [Modern Sysadmin CLI Toolkit — jq, yq, ripgrep & fzf](../../languages/bash/cli-tools-ecosystem.md) | Entry | Linux | Bash | Administration, Investigation |
| [PowerShell JSON and CSV](../../languages/powershell/json-csv.md) | Entry | Windows, Windows Server | PowerShell | Automation, Investigation |
| [Python JSON and CSV](../../languages/python/json-csv.md) | Entry | Linux, Windows | Python | Automation, Investigation |
| [S1QL Fundamentals](../../detection/s1ql/fundamentals.md) | Entry | SentinelOne | S1QL | Threat Hunting, Investigation, Detection Engineering |
| [S1QL Hunting Queries](../../detection/s1ql/hunting.md) | Entry | SentinelOne, Windows, Linux | S1QL | Threat Hunting, Incident Response, Investigation |
| [SPL Fundamentals and Search Optimization](../../detection/spl/fundamentals.md) | Entry | Splunk | SPL | Threat Hunting, Detection Engineering, Investigation |
| [SPL Network and DNS Hunting](../../detection/spl/network-dns.md) | Entry | Splunk | SPL | Threat Hunting, Investigation, Detection Engineering |
| [SPL Windows Security Events](../../detection/spl/windows-events.md) | Entry | Splunk, Windows | SPL | Threat Hunting, Detection Engineering, Investigation, Incident Response |
| [Windows Event Logs](../../platforms/windows/event-logs.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Forensics, Hardening |
| [Windows Files and Permissions](../../platforms/windows/files-directories.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Forensics, Hardening |
| [Windows Installed Software](../../platforms/windows/software.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Investigation, Administration, Incident Response |
| [Windows Networking and DNS](../../platforms/windows/networking.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Troubleshooting, Administration |
| [Windows Processes](../../platforms/windows/processes.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Troubleshooting, Forensics |
| [Windows Registry and Run Keys](../../platforms/windows/registry.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Forensics, Threat Hunting |
| [Windows Scheduled Tasks](../../platforms/windows/scheduled-tasks.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Threat Hunting, Administration |
| [Windows Services](../../platforms/windows/services.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Administration, Hardening |
| [Windows Users and Groups](../../platforms/windows/users-groups.md) | Entry | Windows, Windows Server | PowerShell, Windows CLI | Incident Response, Investigation, Administration, Hardening |
| [Bash Toolbox](../../toolbox/bash.md) | Tool | Linux | Bash | Automation, Incident Response, Forensics, Investigation |
| [Command & Code CLI Lookup Utility](../../toolbox/lookup.md) | Tool | Windows, Linux | Python | Administration, Investigation |
| [PowerShell Toolbox](../../toolbox/powershell.md) | Tool | Windows, Windows Server | PowerShell | Automation, Incident Response, Forensics, Investigation |
| [Python Toolbox](../../toolbox/python.md) | Tool | Windows, Linux, Microsoft 365, SentinelOne | Python | Automation, Incident Response, Investigation |
| [Cross-Platform Equivalents](../../references/equivalents.md) | Reference | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting, Administration |
| [Linux Sysadmin Speed Dial Cheat Sheet](../../references/linux-cheat-sheet.md) | Reference | Linux | Bash | Administration, Troubleshooting, Investigation |
| [PowerShell Admin One-Liners Cheat Sheet](../../references/powershell-cheat-sheet.md) | Reference | Windows, Windows Server | PowerShell | Administration, Investigation, Automation |
| [Sysadmin Quick Reference Cheat Sheet](../../references/sysadmin-cheat-sheet.md) | Reference | Windows, Windows Server, Linux, Microsoft 365, Entra ID | PowerShell, Bash, Windows CLI | Administration, Troubleshooting, Investigation |
| [Windows Event ID Reference](../../references/windows-event-ids.md) | Reference | Windows, Windows Server | PowerShell, SPL, KQL | Investigation, Incident Response, Detection Engineering, Forensics |

<!-- /cc:index -->

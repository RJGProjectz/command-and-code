---
title: Microsoft 365
type: index
---

# Microsoft 365

Security administration and investigation for Defender XDR, Entra ID, Conditional Access, Intune and Exchange Online.

!!! info "Modules"
    Use the **Microsoft Graph PowerShell SDK** (`Microsoft.Graph`) and **ExchangeOnlineManagement**. The AzureAD and MSOnline modules are retired — do not build new automation on them.

## Quick answers

| I need to… | Go to |
| --- | --- |
| Disable a user and revoke sessions | [Entra ID → Contain a compromised account](entra.md#contain-a-compromised-account) |
| Find malicious inbox rules | [Exchange → Inbox rules](exchange.md#inbox-rules-on-a-mailbox) |
| See why a sign-in was blocked | [Conditional Access](conditional-access.md#why-was-this-sign-in-blocked) |
| Run advanced hunting from a script | [Defender XDR](defender.md#run-an-advanced-hunting-query-from-powershell) |
| Check a device's join state | [Intune → dsregcmd](intune.md#check-device-join-and-enrollment-state) |

## All Microsoft 365 entries

<!-- cc:index platforms="Microsoft 365" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Account Compromise Investigation](../../tasks/incident-response/account-compromise.md) | Workflow | Entra ID, Exchange Online, Microsoft 365, Windows | PowerShell, KQL | Incident Response, Investigation |
| [Administration — Email Authentication Deployment (SPF, DKIM & DMARC)](../../tasks/administration/email-authentication-deployment.md) | Workflow | Linux, Microsoft 365 | Bash, PowerShell | Administration, Hardening, Investigation |
| [Automated Active Directory and Cloud Identity Containment](../../tasks/automation/automated-account-containment.md) | Workflow | Active Directory, Entra ID, Microsoft 365, Windows Server | PowerShell, REST API | Automation, Incident Response, Administration |
| [CISA SCuBA Microsoft 365 and Azure Baseline Compliance](../../tasks/assurance/cisa-scuba-compliance.md) | Workflow | Microsoft 365, Azure, Entra ID | PowerShell | Assurance, Compliance, Hardening |
| [Hunting Cloud Identity Persistence in Entra ID and Microsoft 365](../../tasks/threat-hunting/cloud-identity-persistence-hunting.md) | Workflow | Entra ID, Microsoft 365, Azure, Microsoft Defender, Splunk | PowerShell, KQL, SPL | Threat Hunting, Incident Response, Investigation |
| [Incident Response — Automated Multi-Vector Containment Runbook](../../tasks/incident-response/automated-containment.md) | Workflow | Windows, Microsoft 365, Entra ID, Microsoft Defender, SentinelOne | PowerShell | Incident Response, Automation |
| [Investigation Playbook — Azure Resource Hijacking](../../tasks/incident-response/azure-resource-hijacking.md) | Workflow | Azure, Microsoft 365 | KQL, PowerShell | Incident Response, Investigation |
| [Investigation Playbook — Phishing Email Triage](../../tasks/incident-response/phishing-email-triage.md) | Workflow | Microsoft 365, Exchange Online | PowerShell, KQL | Incident Response, Investigation |
| [Microsoft Purview and Unified Audit Log (UAL) Investigation](audit-log-investigation.md) | Workflow | Microsoft 365, Entra ID, Exchange Online | PowerShell | Investigation, Incident Response, Forensics |
| [User Lifecycle Management](../../tasks/administration/user-lifecycle-management.md) | Workflow | Windows, Windows Server, Entra ID, Microsoft 365 | PowerShell | Administration, Hardening |
| [Assurance Check — Azure External Guest Access & Permissions](../../tasks/assurance/azure-guest-access-audit.md) | Entry | Entra ID, Azure, Microsoft 365 | PowerShell | Assurance, Hardening, Administration |
| [Azure & Entra ID Security Baseline — CIS Benchmark & NIST CSF 2.0](../../tasks/hardening/cloud-azure-security-baseline.md) | Entry | Azure, Entra ID, Microsoft 365 | PowerShell, Bash | Hardening, Assurance, Governance |
| [Conditional Access](conditional-access.md) | Entry | Microsoft 365, Entra ID | PowerShell, KQL | Administration, Hardening, Investigation, Troubleshooting |
| [Entra ID](entra.md) | Entry | Microsoft 365, Entra ID | PowerShell | Incident Response, Investigation, Administration |
| [Exchange Online](exchange.md) | Entry | Microsoft 365, Exchange Online | PowerShell | Incident Response, Investigation, Administration |
| [Fundamentals — Microsoft Entra ID Architecture & Hybrid Identity](../../fundamentals/cloud/entra-id-fundamentals.md) | Entry | Entra ID, Microsoft 365 | PowerShell | Administration, Hardening |
| [Fundamentals — NIST Cybersecurity Framework (CSF) 2.0](../../fundamentals/grc/nist-csf-2.md) | Entry | Windows, Linux, Microsoft 365, Azure | PowerShell, Bash, Python | Assurance, Hardening, Administration, Incident Response |
| [Fundamentals — OAuth 2.0 Authorization & OIDC Mechanics](../../fundamentals/identity/oauth2.md) | Entry | Entra ID, Microsoft 365 | PowerShell | Automation, Investigation |
| [Fundamentals — Regulatory Compliance & Framework Cross-Walk](../../fundamentals/grc/regulatory-frameworks.md) | Entry | Windows, Linux, Azure, Microsoft 365 | PowerShell, Bash, Python | Assurance, Hardening, Administration |
| [Fundamentals — SMTP Protocol, Relays & Email Authentication](../../fundamentals/networking/smtp.md) | Entry | Linux, Microsoft 365 | PowerShell, Bash | Investigation, Hardening |
| [Incoming Webhooks for Slack & Microsoft Teams](../../apis/webhooks/slack-teams-webhooks.md) | Entry | Microsoft 365 | PowerShell, Bash, REST API | Automation, Incident Response |
| [Intune](intune.md) | Entry | Microsoft 365, Intune, Windows | PowerShell, Windows CLI | Administration, Troubleshooting, Incident Response |
| [KQL Fundamentals](../../detection/kql/fundamentals.md) | Entry | Microsoft Defender, Microsoft 365 | KQL | Threat Hunting, Detection Engineering, Investigation |
| [KQL Logon and Identity Hunting](../../detection/kql/logon-identity.md) | Entry | Microsoft Defender, Entra ID, Microsoft 365, Windows | KQL | Threat Hunting, Investigation, Incident Response, Detection Engineering |
| [Microsoft Defender API — Get Alerts](../../apis/microsoft-defender/get-alerts.md) | Entry | Microsoft Defender, Microsoft 365 | PowerShell, REST API | Incident Response, Automation |
| [Microsoft Defender XDR and Defender for Endpoint](defender.md) | Entry | Microsoft 365, Microsoft Defender, Windows | PowerShell, KQL | Incident Response, Threat Hunting, Administration, Automation |
| [Microsoft Graph API — Audit Sign-In Logs](../../apis/microsoft-graph/sign-in-logs.md) | Entry | Entra ID, Microsoft 365 | PowerShell, REST API | Investigation, Threat Hunting, Incident Response |
| [Microsoft Graph API — Conditional Access Policies](../../apis/microsoft-graph/conditional-access.md) | Entry | Entra ID, Microsoft 365 | PowerShell, REST API | Administration, Hardening, Assurance |
| [Microsoft Graph API — User Authentication Methods](../../apis/microsoft-graph/user-auth-methods.md) | Entry | Entra ID, Microsoft 365 | PowerShell, REST API | Administration, Incident Response, Hardening |
| [OAuth 2.0 Bearer Token Authentication Flow](../../apis/authentication/bearer-tokens.md) | Entry | Entra ID, Microsoft 365 | PowerShell, Bash, REST API | Automation, Administration |
| [PowerShell REST APIs](../../languages/powershell/rest-apis.md) | Entry | Windows, Microsoft 365, SentinelOne, Splunk | PowerShell | Automation, Incident Response |
| [Python HTTP and APIs](../../languages/python/http-apis.md) | Entry | Microsoft 365, SentinelOne, Splunk | Python | Automation, Incident Response |
| [Sigma Rules for Cloud Identity and Entra ID Attacks](../../detection/sigma/cloud-identity-rules.md) | Entry | Entra ID, Microsoft 365, Azure | Sigma | Detection Engineering, Threat Hunting |
| [Splunk Detection — Suspicious MFA Authentication Method Deletion](../../detection/spl/mfa-deletion.md) | Entry | Entra ID, Microsoft 365, Splunk | SPL | Detection Engineering, Threat Hunting |
| [Python Toolbox](../../toolbox/python.md) | Tool | Windows, Linux, Microsoft 365, SentinelOne | Python | Automation, Incident Response, Investigation |
| [MITRE ATT&CK Mapping](../../detection/mitre-attack/index.md) | Reference | Windows, Linux, Microsoft 365 | MITRE ATT&CK | Detection Engineering, Threat Hunting, Incident Response |
| [Sysadmin Quick Reference Cheat Sheet](../../references/sysadmin-cheat-sheet.md) | Reference | Windows, Windows Server, Linux, Microsoft 365, Entra ID | PowerShell, Bash, Windows CLI | Administration, Troubleshooting, Investigation |

<!-- /cc:index -->

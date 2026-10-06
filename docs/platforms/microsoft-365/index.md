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
| [Investigation Playbook — Azure Resource Hijacking](../../tasks/incident-response/azure-resource-hijacking.md) | Workflow | Azure, Microsoft 365 | KQL, PowerShell | Incident Response, Investigation |
| [Investigation Playbook — Phishing Email Triage](../../tasks/incident-response/phishing-email-triage.md) | Workflow | Microsoft 365, Exchange Online | PowerShell, KQL | Incident Response, Investigation |
| [User Lifecycle Management](../../tasks/administration/user-lifecycle-management.md) | Workflow | Windows, Windows Server, Entra ID, Microsoft 365 | PowerShell | Administration, Hardening |
| [Conditional Access](conditional-access.md) | Entry | Microsoft 365, Entra ID | PowerShell, KQL | Administration, Hardening, Investigation, Troubleshooting |
| [Entra ID](entra.md) | Entry | Microsoft 365, Entra ID | PowerShell | Incident Response, Investigation, Administration |
| [Exchange Online](exchange.md) | Entry | Microsoft 365, Exchange Online | PowerShell | Incident Response, Investigation, Administration |
| [Fundamentals — Microsoft Entra ID Architecture & Hybrid Identity](../../fundamentals/cloud/entra-id-fundamentals.md) | Entry | Entra ID, Microsoft 365 | PowerShell | Administration, Hardening |
| [Fundamentals — OAuth 2.0 Authorization & OIDC Mechanics](../../fundamentals/identity/oauth2.md) | Entry | Entra ID, Microsoft 365 | PowerShell | Automation, Investigation |
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
| [Python Toolbox](../../toolbox/python.md) | Tool | Windows, Linux, Microsoft 365, SentinelOne | Python | Automation, Incident Response, Investigation |
| [MITRE ATT&CK Mapping](../../detection/mitre-attack/index.md) | Reference | Windows, Linux, Microsoft 365 | MITRE ATT&CK | Detection Engineering, Threat Hunting, Incident Response |
| [Sysadmin Quick Reference Cheat Sheet](../../references/sysadmin-cheat-sheet.md) | Reference | Windows, Windows Server, Linux, Microsoft 365, Entra ID | PowerShell, Bash, Windows CLI | Administration, Troubleshooting, Investigation |

<!-- /cc:index -->

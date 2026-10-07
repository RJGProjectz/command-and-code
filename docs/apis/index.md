---
title: REST APIs & Platform Integration
type: index
hide:
  - toc
---

# REST APIs & Platform Integration

Practical, tested API endpoints and automation flows for core security and cloud platforms.

Every entry includes:
- Production endpoint paths and HTTP methods
- OAuth2 and API token authentication headers
- Least-privilege application permission scopes
- Copy-ready PowerShell (`Invoke-RestMethod`) and `curl` templates
- Practical incident response, auditing, and threat hunting use cases

---

## API Directories

<!-- cc:index languages="REST API" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Fundamentals — API Security & Error Handling](../fundamentals/apis/security-error-handling.md) | Entry | Linux, Windows | REST API, PowerShell, Python | Automation, Administration, Hardening |
| [Fundamentals — Authentication & Token Lifecycles](../fundamentals/apis/auth-tokens.md) | Entry | Linux, Windows | REST API, PowerShell, Python | Automation, Administration, Hardening |
| [Fundamentals — Pagination & High-Volume Ingestion](../fundamentals/apis/pagination.md) | Entry | Linux, Windows | REST API, PowerShell, Python | Automation, Administration, Investigation |
| [Fundamentals — Rate Limiting & Exponential Backoff](../fundamentals/apis/rate-limiting-backoff.md) | Entry | Linux, Windows | REST API, PowerShell, Python | Automation, Administration, Troubleshooting |
| [Fundamentals — REST Architecture & HTTP Semantics](../fundamentals/apis/rest-architecture.md) | Entry | Linux, Windows | REST API, PowerShell, Python | Automation, Administration, Troubleshooting |
| [Fundamentals — Webhooks & Event-Driven Architecture](../fundamentals/apis/webhooks-events.md) | Entry | Linux, Windows | REST API, PowerShell, Python | Automation, Administration, Incident Response |
| [Incoming Webhooks for Slack & Microsoft Teams](webhooks/slack-teams-webhooks.md) | Entry | Microsoft 365 | PowerShell, Bash, REST API | Automation, Incident Response |
| [Microsoft Defender API — Get Alerts](microsoft-defender/get-alerts.md) | Entry | Microsoft Defender, Microsoft 365 | PowerShell, REST API | Incident Response, Automation |
| [Microsoft Defender API — Trigger Antivirus Scan](microsoft-defender/antivirus-scan.md) | Entry | Microsoft Defender, Windows | PowerShell, REST API | Incident Response, Automation |
| [Microsoft Graph API — Audit Sign-In Logs](microsoft-graph/sign-in-logs.md) | Entry | Entra ID, Microsoft 365 | PowerShell, REST API | Investigation, Threat Hunting, Incident Response |
| [Microsoft Graph API — Conditional Access Policies](microsoft-graph/conditional-access.md) | Entry | Entra ID, Microsoft 365 | PowerShell, REST API | Administration, Hardening, Assurance |
| [Microsoft Graph API — User Authentication Methods](microsoft-graph/user-auth-methods.md) | Entry | Entra ID, Microsoft 365 | PowerShell, REST API | Administration, Incident Response, Hardening |
| [OAuth 2.0 Bearer Token Authentication Flow](authentication/bearer-tokens.md) | Entry | Entra ID, Microsoft 365 | PowerShell, Bash, REST API | Automation, Administration |
| [REST APIs — Jira & ServiceNow Security Incident Creation](webhooks/jira-servicenow-incident-creation.md) | Entry | Linux, Windows | PowerShell, Python, REST API | Automation, Incident Response |
| [SentinelOne API — Network Host Isolation](sentinelone/isolate-host.md) | Entry | SentinelOne | PowerShell, REST API | Incident Response, Automation |
| [SentinelOne API — Query Threats](sentinelone/threats.md) | Entry | SentinelOne | PowerShell, Bash, REST API | Incident Response, Threat Hunting |
| [Splunk REST API — Search Jobs Management](splunk/management-jobs.md) | Entry | Splunk | PowerShell, Bash, REST API | Administration, Automation, Troubleshooting |

<!-- /cc:index -->

---

## Authentication Protocols

Security API integrations require standardized authentication handling:
- **Microsoft Graph & Defender**: OAuth 2.0 client credentials grant against `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` with scoped Bearer tokens.
- **SentinelOne**: Static or service-account `ApiToken` passed via `Authorization: ApiToken {token}`.
- **Splunk Enterprise & Cloud**: Splunk REST authentication tokens (`Authorization: Bearer {token}`) or management API credentials on port `8089`.

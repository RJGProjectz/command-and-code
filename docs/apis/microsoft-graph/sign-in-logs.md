---
title: Microsoft Graph API — Audit Sign-In Logs
type: entry
platforms:
  - Entra ID
  - Microsoft 365
languages:
  - PowerShell
  - REST API
tasks:
  - Investigation
  - Threat Hunting
  - Incident Response
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - api
  - graph
  - entra
  - sign-ins
  - authentication
---

# Microsoft Graph API — Audit Sign-In Logs

Retrieves interactive and non-interactive Entra ID user sign-in logs, authentication details, conditional access results, and risk states.

## Endpoint & Permissions

- **Method**: `GET`
- **URI**: `https://graph.microsoft.com/v1.0/auditLogs/signIns`
- **Authentication**: OAuth 2.0 Bearer token
- **Required Application Permission**: `AuditLog.Read.All`

---

## Copy-Ready PowerShell

```powershell
# Query sign-ins with failed status codes (e.g. 50126 invalid password, 50074 MFA required)
$Filter = "status/errorCode ne 0 and createdDateTime ge 2026-10-01T00:00:00Z"
$Url = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$Filter&`$top=25"

$Headers = @{ "Authorization" = "Bearer $Token" }
$SignIns = Invoke-RestMethod -Method Get -Uri $Url -Headers $Headers

$SignIns.value | Select-Object userPrincipalName, ipAddress, clientAppUsed,
    @{Name="City"; Expression={$_.location.city}},
    @{Name="Country"; Expression={$_.location.countryOrRegion}},
    @{Name="ErrorCode"; Expression={$_.status.errorCode}},
    @{Name="FailureReason"; Expression={$_.status.failureReason}}
```

---

## Operational Use Cases

- **Compromised Account Triage**: Instantly pull the last 100 sign-in events for a suspicious account to identify foreign IP addresses, uncommon user-agents, or bypass attempts.
- **Brute-Force & Password Spray Detection**: Aggregate failed sign-ins by source IP over short timeframes.

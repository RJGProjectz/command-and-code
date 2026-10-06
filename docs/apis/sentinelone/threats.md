---
title: SentinelOne API — Query Threats
type: entry
platforms:
  - SentinelOne
languages:
  - PowerShell
  - Bash
  - REST API
tasks:
  - Incident Response
  - Threat Hunting
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - api
  - sentinelone
  - edr
  - threats
---

# SentinelOne API — Query Threats

Fetches unresolved detection incidents and behavioral threat details from the SentinelOne Singularity platform.

## Endpoint & Permissions

- **Method**: `GET`
- **URI**: `https://{console_url}/web/api/v2.1/threats`
- **Authentication**: `Authorization: ApiToken {token}`
- **Required Scope**: Viewer or Admin access to target site/group

---

## Copy-Ready Implementations

### PowerShell

```powershell
param(
    [Parameter(Mandatory=$true)][string]$ConsoleUrl,
    [Parameter(Mandatory=$true)][string]$ApiToken
)

$Uri = "https://$ConsoleUrl/web/api/v2.1/threats?resolved=false&limit=25"
$Headers = @{
    "Authorization" = "ApiToken $ApiToken"
    "Content-Type"  = "application/json"
}

$Response = Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers
$Response.data | Select-Object id, threatName, classification, agentRealtimeInfo, createdDate
```

### cURL

```bash
curl -s -X GET "https://${S1_CONSOLE}/web/api/v2.1/threats?resolved=false&limit=10" \
     -H "Authorization: ApiToken ${S1_TOKEN}" \
     -H "Content-Type: application/json"
```

---

## Operational Use Cases

- **SOC Threat Queuing**: Pull real-time threats directly into SOAR platforms to initiate automated forensic artifact preservation.
- **Agent Coverage Gap Analysis**: Validate that detected threats on hosts correlate with known active agent versions.

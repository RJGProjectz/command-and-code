---
title: SentinelOne API — Network Host Isolation
type: entry
platforms:
  - SentinelOne
languages:
  - PowerShell
  - REST API
tasks:
  - Incident Response
  - Automation
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - api
  - sentinelone
  - isolation
  - containment
---

# SentinelOne API — Network Host Isolation

Disconnects a compromised workstation or server from all network communications, maintaining strictly an encrypted management tunnel to the SentinelOne console.

## Endpoint & Permissions

- **Method**: `POST`
- **URI**: `https://{console_url}/web/api/v2.1/agents/actions/network-quarantine`
- **Authentication**: `Authorization: ApiToken {token}`
- **Required Permission**: `Endpoint Admin` or `SOC Admin`

---

## Copy-Ready PowerShell

```powershell
param(
    [Parameter(Mandatory=$true)][string]$ConsoleUrl,
    [Parameter(Mandatory=$true)][string]$ApiToken,
    [Parameter(Mandatory=$true)][string[]]$AgentIds
)

$Uri = "https://$ConsoleUrl/web/api/v2.1/agents/actions/network-quarantine"
$Headers = @{
    "Authorization" = "ApiToken $ApiToken"
    "Content-Type"  = "application/json"
}

$Body = @{
    filter = @{ ids = $AgentIds }
    data   = @{}
} | ConvertTo-Json

$Result = Invoke-RestMethod -Method Post -Uri $Uri -Headers $Headers -Body $Body
Write-Host "[OK] Isolation requested. Affected agents: $($Result.data.affected)"
```

---

## Reversing Containment (Un-isolate)

To abort network quarantine after forensic validation and threat eradication:

```powershell
$AbortUri = "https://$ConsoleUrl/web/api/v2.1/agents/actions/abort-network-quarantine"
Invoke-RestMethod -Method Post -Uri $AbortUri -Headers $Headers -Body $Body
```

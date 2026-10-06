---
title: Microsoft Defender API — Get Alerts
type: entry
platforms:
  - Microsoft Defender
  - Microsoft 365
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
  - defender
  - alerts
  - incident-response
---

# Microsoft Defender API — Get Alerts

Retrieves security alerts generated across endpoints and identities from Microsoft Defender for Endpoint and Defender XDR.

## Endpoint & Permissions

- **Method**: `GET`
- **URI**: `https://api.security.microsoft.com/api/alerts`
- **Authentication**: OAuth 2.0 Bearer token (`Authorization: Bearer <token>`)
- **Required Application Permission**: `Alert.Read.All`

---

## Query Parameters & Filtering

| Parameter | Purpose | Example |
| :--- | :--- | :--- |
| `$filter` | OData filter expression | `severity eq 'High' and status eq 'New'` |
| `$top` | Max records to return | `10` |
| `$orderby` | Sort ordering | `alertCreationTime desc` |

---

## Copy-Ready Implementations

### PowerShell (`Invoke-RestMethod`)

```powershell
# Prerequisites: Valid OAuth token in $Token with Alert.Read.All scope
$Filter = "severity eq 'High' and status eq 'New'"
$Url = "https://api.security.microsoft.com/api/alerts?`$filter=$Filter&`$top=10&`$orderby=alertCreationTime desc"

$Headers = @{
    "Authorization" = "Bearer $Token"
    "Accept"        = "application/json"
}

$Response = Invoke-RestMethod -Method Get -Uri $Url -Headers $Headers
$Response.value | Select-Object id, title, severity, status, category, alertCreationTime
```

### cURL

```bash
curl -s -X GET "https://api.security.microsoft.com/api/alerts?\$filter=severity%20eq%20'High'&\$top=5" \
     -H "Authorization: Bearer ${DEFENDER_TOKEN}" \
     -H "Accept: application/json"
```

---

## Operational Use Cases

1. **Automated Triage Ingestion**: Feed new high-severity Defender alerts into SIEM or internal ticketing engines without manual portal exports.
2. **Stale Alert Sweeps**: Filter alerts by `status eq 'New'` older than 30 days to review false positives or unresolved detections.
3. **Correlation with EDR Isolation**: Extract `machineId` from alert entities to invoke automated containment routines.

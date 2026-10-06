---
title: Splunk REST API — Search Jobs Management
type: entry
platforms:
  - Splunk
languages:
  - PowerShell
  - Bash
  - REST API
tasks:
  - Administration
  - Automation
  - Troubleshooting
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - api
  - splunk
  - rest
  - management
---

# Splunk REST API — Search Jobs Management

Inspects, audits, and manages active or queued search jobs on Splunk Enterprise or Cloud search heads (management port 8089).

## Endpoint & Permissions

- **Method**: `GET`
- **URI**: `https://{splunk_host}:8089/services/search/jobs?output_mode=json`
- **Authentication**: Splunk Bearer Token or Basic Auth
- **Required Capability**: `rest_apps_view`, `search`

---

## Copy-Ready Implementations

### PowerShell

```powershell
param(
    [Parameter(Mandatory=$true)][string]$SplunkHost,
    [Parameter(Mandatory=$true)][string]$SplunkToken
)

$Uri = "https://${SplunkHost}:8089/services/search/jobs?output_mode=json"
$Headers = @{ "Authorization" = "Bearer $SplunkToken" }

$Jobs = Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers
$Jobs.entry | Select-Object name,
    @{Name="User"; Expression={$_.author}},
    @{Name="Status"; Expression={$_.content.dispatchState}},
    @{Name="RunDurationSeconds"; Expression={$_.content.runDuration}},
    @{Name="ResultCount"; Expression={$_.content.resultCount}}
```

### cURL

```bash
curl -k -s -X GET "https://splunk.internal:8089/services/search/jobs?output_mode=json" \
     -H "Authorization: Bearer ${SPLUNK_TOKEN}"
```

---

## Operational Use Cases

- **Runaway Search Remediation**: Detect resource-intensive searches stuck in dispatch and issue `DELETE /services/search/jobs/{sid}` to restore search head performance.
- **Headless Telemetry Ingestion**: Programmatically export search results into JSON pipelines without web portal intervention.

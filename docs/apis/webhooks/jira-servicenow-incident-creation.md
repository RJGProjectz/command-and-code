---
title: REST APIs — Jira & ServiceNow Security Incident Creation
type: entry
platforms:
  - Linux
  - Windows
languages:
  - PowerShell
  - Python
  - REST API
tasks:
  - Automation
  - Incident Response
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - rest-api
  - servicenow
  - jira
  - itsm
  - automation
---

# REST APIs — Jira & ServiceNow Security Incident Creation

Programmatic integration patterns for dispatching automated security incident records into IT Service Management (ITSM) platforms from detection alerts and hunting scripts.

## 1. ServiceNow Incident Table API

- **Endpoint**: `POST https://{instance}.service-now.com/api/now/table/incident`
- **Headers**: `Accept: application/json`, `Content-Type: application/json`

### PowerShell Dispatch
```powershell
$Instance = "yourorg.service-now.com"
$Uri = "https://$Instance/api/now/table/incident"

$Headers = @{
    "Authorization" = "Bearer $Env:SNOW_BEARER_TOKEN"
    "Content-Type"  = "application/json"
    "Accept"        = "application/json"
}

$Body = @{
    short_description = "Security Alert: High-Frequency Brute Force Detected"
    description       = "Host WS-8092 experienced 45 failed logons followed by success from source 198.51.100.22"
    urgency           = "1"  # 1 = High, 2 = Medium, 3 = Low
    impact            = "1"
    category          = "Security"
    subcategory       = "Incident"
    correlation_id    = "DET-SPL-4625-WS8092-20261006"
} | ConvertTo-Json

$Response = Invoke-RestMethod -Uri $Uri -Method Post -Headers $Headers -Body $Body
Write-Host "ServiceNow Incident Created: $($Response.result.number) (sys_id: $($Response.result.sys_id))"
```

## 2. Jira Service Management REST API

- **Endpoint**: `POST https://{domain}.atlassian.net/rest/api/3/issue`

### Python Dispatch
```python
import os
import requests
from requests.auth import HTTPBasicAuth

domain = os.environ.get("JIRA_DOMAIN", "yourorg.atlassian.net")
url = f"https://{domain}/rest/api/3/issue"
auth = HTTPBasicAuth(os.environ["JIRA_EMAIL"], os.environ["JIRA_API_TOKEN"])

headers = {
    "Accept": "application/json",
    "Content-Type": "application/json"
}

payload = {
    "fields": {
        "project": {"key": "SEC"},
        "summary": "Security Alert: Suspicious EDR Agent Tampering",
        "description": {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [
                        {"type": "text", "text": "Endpoint SentinelOne agent was stopped on SRV-FIN-01."}
                    ]
                }
            ]
        },
        "issuetype": {"name": "Security Incident"},
        "priority": {"name": "High"}
    }
}

response = requests.post(url, json=payload, headers=headers, auth=auth)
response.raise_for_status()
print(f"Jira Issue Created: {response.json()['key']}")
```

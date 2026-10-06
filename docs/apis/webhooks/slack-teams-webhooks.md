---
title: Incoming Webhooks for Slack & Microsoft Teams
type: entry
platforms:
  - Microsoft 365
languages:
  - PowerShell
  - Bash
  - REST API
tasks:
  - Automation
  - Incident Response
verified: true
last_verified: 2026-10-06
difficulty: basic
tags:
  - api
  - webhooks
  - slack
  - teams
  - alerting
---

# Incoming Webhooks for Slack & Microsoft Teams

Reliable payloads for transmitting high-priority incident notifications, SOC escalation alerts, and system health status to Slack and Microsoft Teams channels.

---

## Slack Incoming Webhook

### Payload Schema
```json
{
  "text": "🚨 *SEV-1 Security Alert:* Suspicious process execution on DC-01",
  "blocks": [
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*Host:* `DC-01.corp.internal`\n*User:* `NT AUTHORITY\\SYSTEM`\n*Action:* Host isolated."
      }
    }
  ]
}
```

### PowerShell Implementation

```powershell
param(
    [Parameter(Mandatory=$true)][string]$WebhookUrl,
    [Parameter(Mandatory=$true)][string]$Message
)

$Payload = @{ text = $Message } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri $WebhookUrl -ContentType "application/json" -Body $Payload
```

---

## Microsoft Teams Incoming Webhook (Adaptive Card)

### Payload Schema

```json
{
  "type": "message",
  "attachments": [
    {
      "contentType": "application/vnd.microsoft.card.adaptive",
      "content": {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": [
          { "type": "TextBlock", "text": "🛡️ SOC Alert Notification", "weight": "Bolder", "size": "Medium" },
          { "type": "TextBlock", "text": "Automated triage executed successfully.", "wrap": true }
        ]
      }
    }
  ]
}
```

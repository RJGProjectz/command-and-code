---
title: Microsoft Defender XDR and Defender for Endpoint
platforms: [Microsoft 365, Microsoft Defender, Windows]
languages: [PowerShell, KQL]
tasks: [Incident Response, Threat Hunting, Administration, Automation]
category: Endpoint Protection
tags: [defender xdr, mde, advanced hunting, isolation, live response, graph api, onboarding]
aliases: [isolate device, defender portal, advanced hunting api, runHuntingQuery, sense service, mde onboarding status]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
---

# Microsoft Defender XDR and Defender for Endpoint

## Portal locations

| Need | Where (security.microsoft.com) |
| --- | --- |
| Incidents and alerts | **Incidents & alerts** |
| Advanced hunting | **Hunting → Advanced hunting** |
| Device page, timeline, response actions | **Assets → Devices** → select device |
| Isolate / restrict app execution / collect investigation package / Live Response | Device page → **…** response actions |
| Indicators (block hash/IP/URL) | **Settings → Endpoints → Indicators** |
| Action center (pending/completed actions) | **Actions & submissions → Action center** |

Microsoft renames menu items periodically — if a path has moved, use the portal search box.

## Check sensor and onboarding state on a device

```powershell
Get-Service -Name Sense | Select-Object Name, Status, StartType
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -Name OnboardingState -ErrorAction SilentlyContinue
```

`Sense` is the Defender for Endpoint sensor service. `OnboardingState = 1` means onboarded.

## Advanced hunting

Queries use KQL. Start with the [KQL section](../../detection/kql/index.md). Data is retained for 30 days in advanced hunting.

## Run an advanced hunting query from PowerShell

Uses Microsoft Graph `runHuntingQuery` (permission: `ThreatHunting.Read.All`).

```powershell
Connect-MgGraph -Scopes 'ThreatHunting.Read.All'
$query = @'
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "powershell.exe"
| summarize Count = count() by DeviceName
| top 10 by Count
'@
$body = @{ Query = $query } | ConvertTo-Json
$response = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' -Body $body -ContentType 'application/json'
$response.results | ForEach-Object { [pscustomobject]$_ }
```

## Isolate a device via API

Defender for Endpoint API (application permission `Machine.Isolate`):

```text
POST https://api.securitycenter.microsoft.com/api/machines/{machineId}/isolate
Content-Type: application/json

{ "Comment": "IR-2026-001 containment", "IsolationType": "Full" }
```

`IsolationType`: `Full` or `Selective` (Selective keeps Outlook/Teams/Skype connectivity). Release with `POST .../machines/{machineId}/unisolate`.

## Indicators

Block a file hash fleet-wide: **Settings → Endpoints → Indicators → File hashes → Add item**, action *Block and remediate*. Requires the relevant feature to be enabled under advanced features for network indicators (IP/URL).

## Related

- [Microsoft Defender Antivirus (local)](../windows/defender.md)
- [KQL process events](../../detection/kql/process-events.md)
- [PowerShell REST APIs](../../languages/powershell/rest-apis.md)

## Sources

- [runHuntingQuery (Microsoft Graph)](https://learn.microsoft.com/graph/api/security-security-runhuntingquery)
- [Isolate machine API](https://learn.microsoft.com/defender-endpoint/api/isolate-machine)
- [Advanced hunting overview](https://learn.microsoft.com/defender-xdr/advanced-hunting-overview)

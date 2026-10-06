---
title: Microsoft Defender API — Trigger Antivirus Scan
type: entry
platforms:
  - Microsoft Defender
  - Windows
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
  - remediation
  - antivirus
---

# Microsoft Defender API — Trigger Antivirus Scan

Initiates a remote Quick or Full Microsoft Defender Antivirus scan on an onboarded Windows endpoint.

## Endpoint & Permissions

- **Method**: `POST`
- **URI**: `https://api.security.microsoft.com/api/machines/{machine_id}/runAntiVirusScan`
- **Authentication**: OAuth 2.0 Bearer token (`Authorization: Bearer <token>`)
- **Required Application Permission**: `Machine.Scan`

---

## Request Body Schema

```json
{
  "Comment": "Remediation scan initiated via automated SOC playbook",
  "ScanType": "Full"
}
```

*Valid `ScanType` values*: `Quick`, `Full`.

---

## Copy-Ready Implementations

### PowerShell

```powershell
param(
    [Parameter(Mandatory=$true)][string]$MachineId,
    [ValidateSet("Quick", "Full")][string]$ScanType = "Quick",
    [Parameter(Mandatory=$true)][string]$Token
)

$Uri = "https://api.security.microsoft.com/api/machines/$MachineId/runAntiVirusScan"
$Headers = @{
    "Authorization" = "Bearer $Token"
    "Content-Type"  = "application/json"
}

$Body = @{
    Comment  = "Automated remediation sweep for alert triage"
    ScanType = $ScanType
} | ConvertTo-Json

$Action = Invoke-RestMethod -Method Post -Uri $Uri -Headers $Headers -Body $Body
Write-Host "[OK] Action ID created: $($Action.id) - Status: $($Action.status)"
```

---

## Operational Use Cases

- **Immediate Host Scrubbing**: Automatically trigger a Full Scan immediately after isolating an endpoint that fired a ransomware or credential-dumping alert.
- **Post-Remediation Verification**: Ensure no lingering persistent malware artifacts remain on disk before un-isolating a machine.

---
title: Incident Response — Automated Multi-Vector Containment Runbook
type: workflow
platforms:
  - Windows
  - Microsoft 365
  - Entra ID
  - Microsoft Defender
  - SentinelOne
languages:
  - PowerShell
tasks:
  - Incident Response
  - Automation
verified: true
last_verified: 2026-10-06
difficulty: advanced
tags:
  - incident-response
  - containment
  - isolation
  - token-revocation
  - playbook
---

# Incident Response — Automated Multi-Vector Containment Runbook

Standardized containment sequence bridging high-confidence alerts (Ransomware, Compromised Identity, Active C2) directly into multi-vector isolation actions across endpoints, cloud identities, and network perimeters.

## 1. Containment Sequence Architecture

```text
[High Severity Alert: Severity >= HIGH, Confidence >= 90]
       │
       ▼
Phase 1: Host Network Isolation (Cut C2 & Lateral Movement)
       │ ├── Defender for Endpoint API: Isolate
       │ └── SentinelOne API: Network Quarantine
       ▼
Phase 2: Identity Session Revocation (Kill Active Access Tokens)
       │ ├── Entra ID: Revoke-MgUserSignInSession
       │ └── Exchange Online: Terminate Outlook/Mobile ActiveSync
       ▼
Phase 3: Threat Indicator Perimeter Block (Stop Ingress/Egress)
       │ ├── Add SHA256 file hashes to Defender Indicators (Action: BlockAndRemediate)
       │ └── Block C2 IP / Domain at Edge Firewall / Web Proxy
       ▼
Phase 4: Forensic Memory Preservation & Notification
         ├── Trigger Live Memory Acquisition & EDR Package
         └── Post ChatOps Alert to Incident Response War Room
```

## 2. Coordinated Containment Automation Script

```powershell
<#
.SYNOPSIS
    Executes rapid multi-vector containment across Host, Identity, and Indicators.
#>
param(
    [Parameter(Mandatory=$true)] [string]$ComputerName,
    [Parameter(Mandatory=$true)] [string]$UserPrincipalName,
    [Parameter(Mandatory=$false)] [string]$MaliciousSHA256
)

Write-Host "[CONTAINMENT] Initiating emergency containment for host: $ComputerName, user: $UserPrincipalName" -ForegroundColor Red

# 1. Isolate Endpoint via Defender for Endpoint
try {
    $Device = Get-DefenderDevice -ComputerName $ComputerName
    if ($Device) {
        Invoke-DefenderHostIsolation -DeviceId $Device.id -Comment "Automated containment triggered by SOC playbook"
        Write-Host "  [OK] Host isolated from network." -ForegroundColor Green
    }
} catch {
    Write-Warning "Failed to isolate host via Defender: $_"
}

# 2. Revoke All Identity Sessions via Microsoft Graph
try {
    $User = Get-MgUser -UserId $UserPrincipalName
    if ($User) {
        Revoke-MgUserSignInSession -UserId $User.Id | Out-Null
        Update-MgUser -UserId $User.Id -AccountEnabled:$false
        Write-Host "  [OK] Identity tokens revoked and account disabled." -ForegroundColor Green
    }
} catch {
    Write-Warning "Failed to revoke user session: $_"
}

# 3. Block Malicious Hash if provided
if ($MaliciousSHA256) {
    try {
        New-DefenderIndicator -Value $MaliciousSHA256 -Type FileSha256 -Action BlockAndRemediate -Title "Emergency Block - Incident"
        Write-Host "  [OK] Hash indicator blocked fleet-wide." -ForegroundColor Green
    } catch {
        Write-Warning "Failed to push hash indicator: $_"
    }
}

Write-Host "[CONTAINMENT] Sequence complete. Proceed with forensic memory analysis." -ForegroundColor Cyan
```

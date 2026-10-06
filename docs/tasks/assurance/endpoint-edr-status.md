---
title: Assurance Check — Endpoint EDR Agent Health Status
type: entry
platforms:
  - Windows
  - Linux
languages:
  - PowerShell
tasks:
  - Assurance
  - Incident Response
verified: true
last_verified: 2026-10-06
difficulty: basic
tags:
  - assurance
  - edr
  - defender
  - sentinelone
---

# Assurance Check — Endpoint EDR Agent Health Status

Inspects local service execution, driver loading, and cloud heartbeat telemetry for endpoint detection agents (Microsoft Defender, SentinelOne).

## PowerShell Health Audit

```powershell
# Inspect Microsoft Defender for Endpoint Service & Sense Driver
$SenseService = Get-Service -Name "Sense" -ErrorAction SilentlyContinue
$MpCmd = Get-MpComputerStatus -ErrorAction SilentlyContinue

[PSCustomObject]@{
    SenseRunning       = ($SenseService.Status -eq "Running")
    RealTimeProtection = $MpCmd.RealTimeProtectionEnabled
    AntivirusSignature = $MpCmd.AntivirusSignatureVersion
    EngineVersion      = $MpCmd.AMEngineVersion
}
```

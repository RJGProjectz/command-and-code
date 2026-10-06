---
title: Administration — Disk Space Capacity Audit & Reporting
type: workflow
platforms:
  - Windows Server
  - Windows
languages:
  - PowerShell
tasks:
  - Administration
  - Troubleshooting
verified: true
last_verified: 2026-10-06
difficulty: basic
tags:
  - administration
  - disk-space
  - reporting
  - storage
---

# Administration — Disk Space Capacity Audit & Reporting

Audits fixed disk drive capacity across servers, flagging volumes below 15% free space threshold.

## 1. PowerShell Disk Capacity Report

```powershell
Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceId, VolumeName,
    @{Name="TotalSizeGB"; Expression={[math]::Round($_.Size / 1GB, 2)}},
    @{Name="FreeSpaceGB"; Expression={[math]::Round($_.FreeSpace / 1GB, 2)}},
    @{Name="PercentFree"; Expression={[math]::Round(($_.FreeSpace / $_.Size) * 100, 1)}} |
    ForEach-Object {
        $Status = if ($_.PercentFree -lt 15) { "[CRITICAL]" } else { "[OK]" }
        Write-Host "$Status Drive $($_.DeviceId) - $($_.PercentFree)% Free ($($_.FreeSpaceGB) GB)"
    }
```

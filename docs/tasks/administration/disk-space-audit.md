---
title: Administration — Disk Space Capacity Audit & Reporting
type: workflow
platforms:
  - Windows Server
  - Windows
languages:
  - PowerShell
  - CMD
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

---

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

---

## 2. Windows CMD Operations

### Quick Volume Free Space Audit (`fsutil`)
Query free space on fixed drive volumes using native filesystem utilities:

```bat
:: Query total and free bytes on drive C:
fsutil volume diskfree C:

:: Enumerate all active drive letters
fsutil fsinfo drives
```

### Table Audit via WMIC
List device ID, volume label, free space, and total size in bytes:

```bat
:: Query all fixed disks (DriveType 3 = Local Fixed Disk)
wmic logicaldisk where "DriveType=3" get DeviceID, VolumeName, FreeSpace, Size /format:table

:: Target a remote server
wmic /node:"WIN-SRV01" logicaldisk where "DriveType=3" get DeviceID, FreeSpace, Size
```

### Batch Script Disk Threshold Check
Iterate through drives and flag low storage in pure batch:

```bat
@echo off
setlocal EnableDelayedExpansion

echo ==========================================================
echo  Disk Capacity Audit (CMD / System32)
echo ==========================================================

for /f "tokens=1,2,3" %%a in ('wmic logicaldisk where "DriveType=3" get DeviceID^,FreeSpace^,Size ^| findstr /r "[A-Z]:"') do (
    set "DRIVE=%%a"
    set "FREE=%%b"
    set "SIZE=%%c"
    echo Drive !DRIVE! - Free Bytes: !FREE! ^| Total Bytes: !SIZE!
)

endlocal
```

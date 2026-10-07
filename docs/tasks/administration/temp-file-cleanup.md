---
title: Administration — Safe Temporary File Purging
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
  - cleanup
  - temp-files
  - maintenance
---

# Administration — Safe Temporary File Purging

Automated routine to safely reclaim disk capacity by purging temp files older than 24 hours from `C:\Windows\Temp`, user temp paths, and the Windows Update download cache.

---

## 1. PowerShell Temp Purge Routine

```powershell
$Cutoff = (Get-Date).AddDays(-1)
$TempPaths = @(
    "C:\Windows\Temp",
    "C:\Windows\SoftwareDistribution\Download"
)

foreach ($path in $TempPaths) {
    if (Test-Path $path) {
        Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $Cutoff } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "[OK] Temp cache purging complete." -ForegroundColor Green
```

---

## 2. Windows CMD Operations

### Age-Filtered File Purging (`forfiles.exe`)
Delete files older than 7 days without locking currently active files:

```bat
:: Purge files in system Temp older than 7 days
forfiles /p "C:\Windows\Temp" /s /m *.* /d -7 /c "cmd /c del /f /q @path 2>nul"

:: Purge files in current user Temp older than 3 days
forfiles /p "%TEMP%" /s /m *.* /d -3 /c "cmd /c del /f /q @path 2>nul"
```

### Windows Update Cache Purge
Stop the Windows Update service, clear cached downloaded patches, and restart the service:

```bat
:: Stop update service
net stop wuauserv

:: Delete cached update packages
del /f /s /q "C:\Windows\SoftwareDistribution\Download\*.*" 2>nul
rmdir /s /q "C:\Windows\SoftwareDistribution\Download" 2>nul
mkdir "C:\Windows\SoftwareDistribution\Download"

:: Restart update service
net start wuauserv
```

### Automated Windows Disk Cleanup (`cleanmgr.exe`)

```bat
:: Pre-configure cleanup preset 100 (runs once during system provisioning)
cleanmgr /sageset:100

:: Execute unattended cleanup preset without UI prompts
cleanmgr /sagerun:100
```

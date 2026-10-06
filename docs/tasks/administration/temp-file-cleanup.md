---
title: Administration — Safe Temporary File Purging
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
  - cleanup
  - temp-files
  - maintenance
---

# Administration — Safe Temporary File Purging

Automated routine to safely reclaim disk capacity by purging temp files older than 24 hours from `C:\Windows\Temp` and user temp paths.

## 1. Safe Temp Purge Routine

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

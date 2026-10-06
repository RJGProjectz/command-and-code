---
title: Troubleshooting — Emergency Disk Space Exhaustion & Inode Recovery
type: workflow
platforms:
  - Windows
  - Windows Server
  - Linux
languages:
  - PowerShell
  - Bash
tasks:
  - Troubleshooting
  - Administration
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - disk-full
  - storage
  - inodes
  - vss
  - troubleshooting
---

# Troubleshooting — Emergency Disk Space Exhaustion & Inode Recovery

Rapid response workflow for triaging zero-byte disk outages, volume write lockouts, and hidden storage leaks (inode exhaustion, shadow storage bloat, deleted open file descriptors).

## 1. Immediate Volume Capacity Inspection

### Windows
```powershell
Get-Volume | Where-Object DriveType -eq 'Fixed' |
    Select-Object DriveLetter, FileSystemLabel, FileSystem,
                  @{N="SizeGB";E={[math]::Round($_.Size / 1GB, 2)}},
                  @{N="FreeGB";E={[math]::Round($_.SizeRemaining / 1GB, 2)}},
                  @{N="PercentFree";E={[math]::Round(($_.SizeRemaining / $_.Size) * 100, 1)}} |
    Sort-Object PercentFree
```

### Linux
```bash
# Check block capacity AND inode allocation
df -hT / /var /home /tmp
df -i / /var /home /tmp
```
*Note: If `df -h` shows available gigabytes but `df -i` shows 100% inode utilization, the filesystem cannot write new files due to millions of micro-files (e.g., PHP sessions, spool queues).*

## 2. Identify Hidden Storage Consumers

### Windows: Common Culprits
1. **Shadow Storage (VSS)**:
   ```cmd
   vssadmin list shadowstorage
   :: Reclaim space by resizing max shadow storage
   vssadmin resize shadowstorage /for=C: /on=C: /maxsize=5GB
   ```
2. **Component Store & CBS Log Bloat**:
   ```cmd
   Dism.exe /Online /Cleanup-Image /AnalyzeComponentStore
   Dism.exe /Online /Cleanup-Image /StartComponentCleanup
   ```
3. **Largest Directory Tree Audit**:
   ```powershell
   Get-ChildItem -Path C:\ -Directory -ErrorAction SilentlyContinue | ForEach-Object {
       $size = (Get-ChildItem -Path $_.FullName -File -Recurse -Force -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum).Sum
       [PSCustomObject]@{
           Directory = $_.FullName
           SizeGB    = [math]::Round($size / 1GB, 2)
       }
   } | Sort-Object SizeGB -Descending
   ```

### Linux: Common Culprits
1. **Unlinked Deleted Files Held Open by Processes**:
   ```bash
   # Files deleted from filesystem while daemon holds file descriptor open
   lsof +L1 | awk '{print $1, $2, $7, $10}' | head -n 15
   # Remediation: Restart the offending daemon to release blocks without rebooting
   ```
2. **Top Directory Space Hogs**:
   ```bash
   du -ahx / 2>/dev/null | sort -rh | head -n 20
   ```
3. **Systemd Journal Vacuuming**:
   ```bash
   journalctl --disk-usage
   journalctl --vacuum-size=500M
   ```

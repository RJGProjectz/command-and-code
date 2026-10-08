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

<div class="cc-tree" data-title="Storage Emergency Triage Flow" markdown>

<div class="cc-node cc-node--root" data-id="step-capacity" markdown>

#### Step 1: Storage Exhaustion Root Cause Analysis

Determine whether the disk outage is caused by **raw block exhaustion** or **inode exhaustion** (Linux):

```bash
# Linux: Compare block usage with inode allocation
df -h / /var /tmp
df -i / /var /tmp
```
```powershell
# Windows: Inspect volume free space
Get-Volume | Where-Object DriveType -eq 'Fixed' | Select-Object DriveLetter, SizeRemaining, @{N='PercentFree';E={[math]::Round(($_.SizeRemaining / $_.Size)*100,1)}}
```

**What is the underlying condition?**

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-block-full">Block Capacity 100% Full (0 bytes free)</button>
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-inode-full">Inode 100% Full (df -i 100% but free GB exists)</button>
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-unlinked-open">Deleted Files Still Consuming Space (lsof +L1)</button>
</div>

</div>

<div class="cc-node" data-id="step-block-full" markdown>

#### Diagnostic Branch: Raw Block Space Exhaustion

A volume has run out of physical bytes. Find the largest directory trees and purge safe temporary caches:

```powershell
# Windows: Audit largest directory trees
Get-ChildItem -Path C:\ -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $sum = (Get-ChildItem -Path $_.FullName -File -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    [PSCustomObject]@{ Directory = $_.FullName; SizeGB = [math]::Round($sum / 1GB, 2) }
} | Sort-Object SizeGB -Descending | Select-Object -First 5
```
```bash
# Linux: Identify top space hogs on the root filesystem
du -ahx / 2>/dev/null | sort -rh | head -n 15
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-vss-cleanup">Check Windows VSS / Journal Bloat</button>
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-inode-full" markdown>

#### Diagnostic Branch: Inode Exhaustion (Linux)

When `df -i` shows 100%, the filesystem cannot allocate new files even if hundreds of gigabytes remain free. This is caused by millions of micro-files:

```bash
# 1. Identify which directory contains the highest file count
for d in /var/spool /var/log /tmp /var/lib/php; do
    if [ -d "$d" ]; then
        echo "$d: $(find "$d" -maxdepth 2 -type f 2>/dev/null | wc -l) files"
    fi
done

# 2. Safely purge accumulated spool or session micro-files
find /var/spool/postfix/maildrop -type f -delete
find /var/lib/php/sessions -type f -mtime +2 -delete
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-unlinked-open" markdown>

#### Diagnostic Branch: Deleted Files Held Open by Active Processes

When administrators delete huge log files with `rm`, but disk space is **not released**, a running daemon still holds the file descriptor open:

```bash
# 1. Identify unlinked files held open by running processes
sudo lsof +L1 | awk '{print $1, $2, $7, $10}' | head -n 15

# Example: rsyslogd 1240 4294967296 /var/log/messages (deleted)

# 2. Release blocks without rebooting by restarting the daemon:
sudo systemctl restart '<DAEMON_NAME>'

# 3. Or truncate file descriptor directly in /proc without restart:
# : > "/proc/<PID>/fd/<FD_NUM>"
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-vss-cleanup" markdown>

#### Immediate Emergency Space Reclamation

Execute safe zero-risk purges to bring the host back online immediately:

```cmd
:: Windows: Reclaim Volume Shadow Copy bloat
vssadmin resize shadowstorage /for=C: /on=C: /maxsize=5GB

:: Windows: Component Store cleanup
Dism.exe /Online /Cleanup-Image /StartComponentCleanup
```
```bash
# Linux: Vacuum systemd journal logs to max 500 MB
journalctl --vacuum-size=500M

# Linux: Clean package manager caches
apt-get clean || dnf clean all
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

</div>

---

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

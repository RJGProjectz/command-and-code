---
title: Finding Files & Content Discovery
type: entry
platforms:
  - Linux
  - Windows
  - Windows Server
languages:
  - Bash
  - PowerShell
  - CMD
tasks:
  - Administration
  - Investigation
  - Forensics
verified: true
last_verified: 2026-10-06
difficulty: basic
tags:
  - search
  - find
  - discovery
  - forensics
  - grep
  - powershell
  - linux
  - windows
---

# Finding Files & Content Discovery

Comprehensive operational commands for locating files, directories, executable permissions, and content patterns across Linux and Windows systems.

---

## 1. Linux File Search (`find`, `locate`, `grep`)

### Search by Name, Pattern, and Extension
```bash
# Case-insensitive name search across filesystem
find /var/log -iname "*.log" 2>/dev/null

# Find all hidden files and directories in home
find /home -name ".*" 2>/dev/null

# Locate exact executable binary path
which nginx || whereis nginx
```

### Search by Timestamp & Modification Window
```bash
# Files modified within the last 24 hours (1 day)
find /etc -type f -mtime -1

# Files modified within the last 60 minutes
find /var/www -type f -mmin -60

# Files accessed before a reference file was created
find /tmp -type f -newer /var/log/boot.log
```

### Search by File Size & Empty Artifacts
```bash
# Find files larger than 500MB (emergency disk consumption)
find / -type f -size +500M -exec ls -lh {} + 2>/dev/null

# Find empty files and directories
find /tmp -empty -type f
find /tmp -empty -type d
```

### Security & Privilege Discovery (SUID / SGID / World-Writable)
```bash
# Find all SUID root binaries (potential privilege escalation vectors)
find / -perm -4000 -user root -type f 2>/dev/null

# Find world-writable files outside /proc and /sys
find / -xdev -type f -perm -0002 2>/dev/null

# Find files owned by a specific user or group
find /home -user www-data -type f
```

### Batch Action on Discovered Files
```bash
# Safely process files with spaces using null-delimiters
find /var/log -type f -name "*.gz" -print0 | xargs -0 -r ls -l

# Search for sensitive regex inside discovered configuration files
find /etc -type f -name "*.conf" -exec grep -Hn "password" {} + 2>/dev/null
```

---

## 2. Windows PowerShell File Search

### Locate Files by Name & Extension
```powershell
# Fast recursive file search under specific path
Get-ChildItem -Path "C:\Windows" -Filter "*.dll" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 25 FullName

# Search current directory tree for configuration files
Get-ChildItem -Path . -Include "*.json","*.xml","*.yaml","*.yml" -Recurse -File
```

### Search by Size & Modification Date
```powershell
# Identify files larger than 1GB across drive C:
Get-ChildItem -Path "C:\" -File -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Length -gt 1GB } |
    Select-Object FullName, @{Name="SizeGB"; Expression={[math]::Round($_.Length / 1GB, 2)}}, LastWriteTime |
    Sort-Object SizeGB -Descending

# Locate files created or modified in the last 2 hours
$cutoff = (Get-Date).AddHours(-2)
Get-ChildItem -Path "C:\Users" -File -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -ge $cutoff } |
    Select-Object FullName, LastWriteTime, Length
```

### Search File Contents (`Select-String`)
```powershell
# Search recursively for IP addresses or tokens inside files
Select-String -Path "C:\inetpub\logs\*.log" -Pattern "401\.1|403\.1" -SimpleMatch |
    Select-Object -First 20 Path, LineNumber, Line

# Case-insensitive regex search with context lines
Get-ChildItem -Path "C:\ProgramData" -Filter "*.config" -Recurse -File -ErrorAction SilentlyContinue |
    Select-String -Pattern "connectionString|api_key" -Context 1, 1
```

### Forensic File Hash Auditing & Alternate Data Streams (ADS)
```powershell
# Compute SHA256 hash for suspicious executable
Get-FileHash -Path "C:\Windows\System32\cmd.exe" -Algorithm SHA256

# Detect hidden Alternate Data Streams on NTFS volumes
Get-Item -Path "C:\Users\Public\*" -Stream * -ErrorAction SilentlyContinue |
    Where-Object { $_.Stream -ne ':$DATA' }
```

---

## 3. Windows CMD File Search

### Fast Recursive File Listing (`dir`)
```cmd
REM Search entire drive for executable matching pattern
dir C:\nc*.exe /s /b

REM List only hidden system files in system directory
dir C:\Windows /s /b /a:h
```

### Content String Search (`findstr`)
```cmd
REM Recursive case-insensitive content match
findstr /s /i /m "password" C:\Users\*.txt

REM Search with exact line numbers
findstr /s /n /i "SELECT" C:\inetpub\wwwroot\*.asp
```

REM Locate executable in system PATH
where /R C:\Windows svchost.exe

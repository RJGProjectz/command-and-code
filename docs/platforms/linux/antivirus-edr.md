---
title: Linux Antivirus & Endpoint Detection (EDR)
type: entry
platforms:
  - Linux
languages:
  - Bash
tasks:
  - Administration
  - Hardening
  - Incident Response
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - linux
  - edr
  - clamav
  - mdatp
  - sentinelone
---

# Linux Antivirus & Endpoint Detection (EDR)

Deploying, monitoring, and validating Linux antimalware scanners (ClamAV) and enterprise EDR sensors (Microsoft Defender for Endpoint `mdatp`, SentinelOne).

## 1. Process & Service First: Antivirus & EDR Daemons

```bash
# 1. Check ClamAV daemon and update service
systemctl status clamav-daemon clamav-freshclam

# 2. Check Microsoft Defender for Endpoint daemon
systemctl status mdatp

# 3. Check SentinelOne Linux agent daemon
systemctl status sentinelone
```

## 2. ClamAV Operations & Scanning

```bash
# 1. Update virus signature database
freshclam

# 2. Run recursive on-demand scan of /tmp and /var/tmp without removing files
clamscan -r -i /tmp /var/tmp

# 3. Full system quarantine scan (move infected files to quarantine directory)
mkdir -p /var/quarantine
clamscan -r -i --move=/var/quarantine /home /var/www
```

## 3. Microsoft Defender for Endpoint on Linux (`mdatp`)

```bash
# 1. Query real-time protection, engine version, and cloud connectivity
mdatp health

# 2. Trigger on-demand quick or full scan
mdatp scan quick
mdatp scan full

# 3. Inspect detected threats and quarantine list
mdatp threat list
```

## 4. SentinelOne Linux Agent Operations

```bash
# 1. Query agent status, cloud connectivity, and management console status
/opt/sentinelone/bin/sentinelctl control status

# 2. Query endpoint policy status
/opt/sentinelone/bin/sentinelctl management status
```

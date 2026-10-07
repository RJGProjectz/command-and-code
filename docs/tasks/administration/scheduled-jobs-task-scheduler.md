---
title: Scheduled Task and Cron Job Automation
type: workflow
platforms:
  - Windows
  - Windows Server
  - Linux
languages:
  - PowerShell
  - CMD
  - Bash
tasks:
  - Administration
  - Automation
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - task-scheduler
  - cron
  - systemd-timers
  - automation
  - scheduled-jobs
---

# Scheduled Task and Cron Job Automation

Configuring, auditing, and managing recurring automated jobs using Windows Task Scheduler, Linux crontab, and modern systemd timers.

---

## 1. Windows Task Scheduler

### PowerShell `ScheduledTasks` Module

```powershell
# Enumerate custom enterprise scheduled tasks
Get-ScheduledTask -TaskPath "\Enterprise\*" | Select-Object TaskName, State, Author

# Define a task action: execute PowerShell script
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-NoProfile -WindowStyle Hidden -File C:\Scripts\DailyBackup.ps1"

# Define a task trigger: daily at 02:00 AM
$Trigger = New-ScheduledTaskTrigger -Daily -At "02:00AM"

# Configure task settings (stop after 2 hours, wake to run)
$Settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 2) -AllowStartIfOnBatteries

# Define security principal (run as SYSTEM with highest privileges)
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

# Register the task in Task Scheduler
Register-ScheduledTask -TaskName "DailyStorageBackup" -TaskPath "\Enterprise\" `
    -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal

# Manually trigger task execution
Start-ScheduledTask -TaskName "DailyStorageBackup" -TaskPath "\Enterprise\"

# Query last run result and next run time
Get-ScheduledTaskInfo -TaskName "DailyStorageBackup" -TaskPath "\Enterprise\"
```

---

## 2. Linux Cron and Systemd Timers

### User & System Crontabs

```bash
# View active crontab for current user
crontab -l

# Schedule a script to run daily at 02:00 AM
(crontab -l 2>/dev/null; echo "0 2 * * * /opt/scripts/backup.sh >> /var/log/backup.log 2>&1") | crontab -

# Create a system-wide root cron job in /etc/cron.d/
cat << 'EOF' | sudo tee /etc/cron.d/system-cleaner
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 3 * * 0 root /usr/local/bin/cleanup.sh > /dev/null 2>&1
EOF
sudo chmod 0644 /etc/cron.d/system-cleaner
```

### Modern Systemd Timer Units

Create `/etc/systemd/system/backup.service`:
```ini
[Unit]
Description=Daily Storage Backup Job

[Service]
Type=oneshot
ExecStart=/opt/scripts/backup.sh
```

Create companion `/etc/systemd/system/backup.timer`:
```ini
[Unit]
Description=Run Daily Storage Backup at 02:00

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

Enable and monitor:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now backup.timer
systemctl list-timers --all
```

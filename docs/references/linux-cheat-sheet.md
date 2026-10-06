---
title: Linux Sysadmin Speed Dial Cheat Sheet
type: reference
platforms: [Linux]
languages: [Bash]
tasks: [Administration, Troubleshooting, Investigation]
category: Reference
tags: [linux, cheat sheet, bash, systemd, journalctl, sysadmin, speed dial, commands]
aliases: [linux cheat sheet, linux admin commands, systemctl cheat sheet, journalctl cheat sheet, linux troubleshooting commands]
difficulty: intermediate
verified: true
last_verified: 2026-10-06
search:
  boost: 3
---

# Linux Sysadmin Speed Dial Cheat Sheet

Practical, high-yield commands for Linux systems administration, performance troubleshooting, process triage, and log investigation.

---

## 1. Systemd & Service Diagnostics

```bash
# Check status of a specific service with recent log tail
systemctl status <service_name> --lines=20 --no-pager

# List all failed units on the system
systemctl --failed

# Reload systemd daemon after editing unit files
sudo systemctl daemon-reload

# View active system timers (cron alternative)
systemctl list-timers --all

# Check boot-up performance and slowest loading services
systemd-analyze blame | head -n 10
systemd-analyze critical-chain
```

---

## 2. Journalctl Log Inspection

```bash
# Follow logs for a specific service in real time
journalctl -u <service_name> -f

# Show logs from the current boot only with error priority or higher
journalctl -b -p err..emerg --no-pager

# View logs from a specific time window
journalctl --since "2 hours ago" --until "10 minutes ago"

# Check disk space used by journal logs and clean older than 7 days
journalctl --disk-usage
sudo journalctl --vacuum-time=7d
```

---

## 3. Storage, Inodes & File Systems

```bash
# Human-readable filesystem disk usage (excluding virtual mounts)
df -hT -x tmpfs -x devtmpfs

# Check inode usage (prevents "No space left on device" when disk is not full)
df -i -x tmpfs -x devtmpfs

# Find the 10 largest directories under /var
sudo du -h --max-depth=1 /var 2>/dev/null | sort -hr | head -n 10

# List all block devices with filesystem UUIDs and mountpoints
lsblk -o NAME,SIZE,TYPE,FSTYPE,UUID,MOUNTPOINT

# Monitor real-time disk I/O performance
iostat -xz 1 5
```

---

## 4. Processes, Memory & Network Sockets

```bash
# Top 5 processes by memory usage
ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -n 6

# Top 5 processes by CPU utilization
ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 6

# Find which process is listening on port 80/443
sudo ss -tulpn | grep -E ':(80|443)\b'

# Find which process has an open lock on a file or directory
sudo lsof +D /var/log/nginx/

# Check memory and swap activity in real time
vmstat 1 5
```

---

## 5. User Management & Security Permissions

```bash
# List all accounts with UID >= 1000 (human interactive users)
getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 {print $1, $3, $6, $7}'

# Check group memberships for a user
id <USER>

# Lock user account and expire shell access immediately
sudo usermod -L -s /usr/sbin/nologin <USER>

# Find all files with SUID bit set (potential privilege escalation targets)
find / -perm -4000 -type f 2>/dev/null

# Review sudoers configuration syntax before saving
sudo visudo -c
```

---

## Related

- [Linux Services with systemd](../../platforms/linux/systemd.md)
- [Linux Networking and DNS](../../platforms/linux/networking.md)
- [Linux Troubleshooting Commands](../../platforms/linux/troubleshooting.md)
- [Sysadmin Quick Reference](sysadmin-cheat-sheet.md)
- [Cross-Platform Equivalents](equivalents.md)

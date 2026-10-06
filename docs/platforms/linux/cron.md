---
title: Linux Cron and Scheduled Jobs
platforms: [Linux]
languages: [Bash]
tasks: [Incident Response, Investigation, Threat Hunting, Administration]
category: Persistence
tags: [cron, crontab, at, systemd timers, persistence]
aliases: [crontab list all users, cron persistence, scheduled jobs linux, cron.d, cron service check]
difficulty: basic
verified: true
last_verified: 2026-10-06
---

# Linux Cron and Scheduled Jobs

A systematic guide to checking, inspecting, auditing, and remediating cron jobs and scheduled tasks on Linux.

---

## 1. Check Cron Daemon & Service State

Always verify whether the cron scheduling daemon is currently active and managing background execution on the system:

```bash
# Check systemd service status ('cron' on Debian/Ubuntu, 'crond' on RHEL/CentOS)
systemctl status cron --no-pager 2>/dev/null || systemctl status crond --no-pager

# Check if cron daemon process is active
pgrep -a cron || pgrep -a crond
```

---

## 2. Known Locations & Key Filesystem Paths

Cron jobs are stored in distinct system and user spool locations:

| Location | Purpose / Notes |
| :--- | :--- |
| **`/etc/crontab`** | System crontab — includes an explicit *user* field |
| **`/etc/cron.d/`** | System job drop-in files — include an explicit *user* field |
| **`/etc/cron.hourly/`, `daily/`, `weekly/`, `monthly/`** | Automated script directories executed by `run-parts` |
| **`/var/spool/cron/crontabs/<user>`** | Per-user crontabs on Debian/Ubuntu |
| **`/var/spool/cron/<user>`** | Per-user crontabs on RHEL/CentOS |
| **`/var/spool/cron/atjobs`, `/var/spool/at`** | One-time `at` job queues |
| **`/etc/cron.allow`, `/etc/cron.deny`** | Access control files controlling who can create crontabs |

---

## 3. List and Review Scheduled Jobs

Inspect all active scheduled jobs across individual user spools and system-wide configuration files:

### List Every User's Crontab

```bash
for user in $(cut -d: -f1 /etc/passwd); do
  sudo crontab -l -u "$user" 2>/dev/null | grep -v '^#' | sed "s/^/$user: /"
done
```

### Review System Cron Files

```bash
sudo cat /etc/crontab
sudo ls -la /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/
sudo find /etc/cron* /var/spool/cron -type f -mtime -14 -ls 2>/dev/null
```

### Check at Jobs and systemd Timers

```bash
sudo atq
sudo at -c JOBNUMBER          # show a job's full content
systemctl list-timers --all
```

---

## 4. Execution Logs & Recent Activity

Review cron execution history to identify which jobs have run recently:

```bash
# Query systemd journal for cron executions
journalctl -u cron --since today 2>/dev/null || journalctl -u crond --since today

# Inspect classic syslog / cron logs
grep CRON /var/log/syslog | tail 2>/dev/null
sudo grep CROND /var/log/cron | tail 2>/dev/null
```

---

## 5. Security Triage & Remediation

Cron is a classic persistence mechanism ([T1053.003](https://attack.mitre.org/techniques/T1053/003/)).

### What to Look For

- `curl`/`wget` piped directly into `sh`/`bash`
- Base64-decoded commands (`echo ... | base64 -d | bash`)
- Unusual frequency (jobs running every minute: `* * * * *`)
- References to `/tmp`, `/dev/shm`, or hidden folders (`/.x/`, `~/.cache/.y`)
- Recently modified files in cron directories within the past 14 days

### Remove a Malicious Job

```bash
# Preserve evidence first before modifying
sudo crontab -l -u www-data > /root/case/www-data.crontab

# Remove crontab for target user
sudo crontab -r -u www-data
```

---

## Related

- [Windows Scheduled Tasks](../windows/scheduled-tasks.md)
- [Linux Services with systemd](systemd.md)

## Sources

- [crontab(5)](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [MITRE ATT&CK T1053.003](https://attack.mitre.org/techniques/T1053/003/)

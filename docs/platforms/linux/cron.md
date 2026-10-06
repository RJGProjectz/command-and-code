---
title: Linux Cron and Scheduled Jobs
platforms: [Linux]
languages: [Bash]
tasks: [Incident Response, Investigation, Threat Hunting, Administration]
category: Persistence
tags: [cron, crontab, at, systemd timers, persistence]
aliases: [crontab list all users, cron persistence, scheduled jobs linux, cron.d]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Linux Cron and Scheduled Jobs

Cron is a common Linux persistence mechanism ([T1053.003](https://attack.mitre.org/techniques/T1053/003/)).

## Where cron jobs live

| Location | Notes |
| --- | --- |
| `/etc/crontab` | System crontab — has a *user* field |
| `/etc/cron.d/` | System job files — have a *user* field |
| `/etc/cron.hourly/`, `daily/`, `weekly/`, `monthly/` | Scripts run by run-parts |
| `/var/spool/cron/crontabs/<user>` | Debian/Ubuntu user crontabs |
| `/var/spool/cron/<user>` | RHEL-family user crontabs |
| `/var/spool/cron/atjobs`, `/var/spool/at` | `at` jobs (path varies) |

## List every user's crontab

```bash
for user in $(cut -d: -f1 /etc/passwd); do
  sudo crontab -l -u "$user" 2>/dev/null | grep -v '^#' | sed "s/^/$user: /"
done
```

## Review system cron

```bash
sudo cat /etc/crontab
sudo ls -la /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/
sudo find /etc/cron* /var/spool/cron -type f -mtime -14 -ls 2>/dev/null
```

## at jobs and systemd timers

```bash
sudo atq
sudo at -c JOBNUMBER          # show a job's full content
systemctl list-timers --all
```

## What to look for

- `curl`/`wget` piped to `sh`/`bash`
- base64-decoded payloads (`echo ... | base64 -d | bash`)
- jobs running every minute (`* * * * *`)
- references to `/tmp`, `/dev/shm`, hidden directories (`/.x/`, `~/.cache/.y`)
- recently modified files in the locations above

## Cron execution logs

```bash
grep CRON /var/log/syslog | tail          # Debian/Ubuntu
sudo grep CROND /var/log/cron | tail      # RHEL-family
journalctl -u cron --since today          # 'crond' on RHEL-family
```

## Remove a malicious job

```bash
sudo crontab -l -u www-data > /root/case/www-data.crontab   # preserve first
sudo crontab -r -u www-data
```

## Related

- [Windows scheduled tasks](../windows/scheduled-tasks.md)
- [systemd services and timers](systemd.md)

## Sources

- [crontab(5)](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [MITRE ATT&CK T1053.003](https://attack.mitre.org/techniques/T1053/003/)

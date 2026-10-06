---
title: Linux Services with systemd
platforms: [Linux]
languages: [Bash]
tasks: [Administration, Troubleshooting, Incident Response, Investigation]
category: Services
tags: [systemd, systemctl, services, timers, persistence, unit files]
aliases: [linux services, systemctl status, enabled services, systemd persistence, unit file location]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Linux Services with systemd

## List services

```bash
systemctl list-units --type=service --state=running
systemctl list-unit-files --type=service --state=enabled
systemctl --failed
```

## Inspect a service

```bash
systemctl status nginx
systemctl cat nginx               # the unit file(s), including drop-ins
systemctl show nginx -p ExecStart -p User -p FragmentPath
journalctl -u nginx --since "1 hour ago" --no-pager
```

`FragmentPath` shows which file defines the unit.

## Unit file locations

| Path | Purpose |
| --- | --- |
| `/etc/systemd/system/` | Administrator units and overrides — **highest priority** |
| `/run/systemd/system/` | Runtime units |
| `/usr/lib/systemd/system/` (`/lib/systemd/system/` on Debian/Ubuntu) | Package-provided units |
| `~/.config/systemd/user/` | Per-user units (`systemctl --user`) |
| `/etc/systemd/system/<unit>.d/*.conf` | Drop-in overrides |

## Hunt for systemd persistence

Malicious services and timers ([T1543.002](https://attack.mitre.org/techniques/T1543/002/), [T1053.006](https://attack.mitre.org/techniques/T1053/006/)) usually appear as recently modified unit files:

```bash
sudo find /etc/systemd /usr/lib/systemd /lib/systemd /run/systemd /home/*/.config/systemd /root/.config/systemd \
  -type f \( -name '*.service' -o -name '*.timer' -o -name '*.conf' \) -mtime -14 -ls 2>/dev/null
```

```bash
sudo grep -rhs '^ExecStart' /etc/systemd/system | sort | uniq -c | sort -n
```

**What to look for:** `ExecStart` invoking `bash -c`, `curl`/`wget` piped to a shell, binaries in `/tmp`, `/dev/shm`, `/var/tmp` or hidden directories; `Restart=always` on unknown units.

## Timers

```bash
systemctl list-timers --all
```

## Stop, disable and mask

```bash
sudo systemctl disable --now badsvc.service
sudo systemctl mask badsvc.service       # prevents any start, even as a dependency
sudo systemctl daemon-reload             # after editing or removing unit files
```

Copy the unit file to your case folder before deleting it.

## Related

- [Linux Service Failure workflow](../../tasks/troubleshooting/linux-service-failure.md)
- [Cron and timers](cron.md)
- [Windows services](../windows/services.md)

## Sources

- [systemctl(1)](https://man7.org/linux/man-pages/man1/systemctl.1.html)
- [systemd.unit(5) — load path](https://man7.org/linux/man-pages/man5/systemd.unit.5.html)

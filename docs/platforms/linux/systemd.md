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

Linux uses systemd as its default init system and service manager. For administration, troubleshooting, or persistence triage, follow the 5-stage systematic progression: start by checking live service and socket states, identify where unit files reside, verify unit definitions, audit recent logs and timers, and apply safe reload or masking operations.

## 1. Check Process, Service & Socket State

### List services

Establish whether services are actively running, enabled at boot, or in a failed state:

```bash
systemctl list-units --type=service --state=running
systemctl list-unit-files --type=service --state=enabled
systemctl --failed
```

### Inspect a service

Check the runtime state, PID, memory usage, and execution binary of a specific unit:

```bash
systemctl status nginx
systemctl show nginx -p ExecStart -p User -p FragmentPath -p MainPID
```

*(Correlate listening sockets with `sudo ss -tulpn | grep -E ':(80|443)\b'`)*

## 2. Known Locations & Unit File Hierarchy

Systemd loads unit files across multiple filesystem tiers in a strict priority order (earlier paths override later ones):

| Priority | Path | Purpose / Description |
| :--- | :--- | :--- |
| **Highest** | `/etc/systemd/system/` | Administrator-created units and full unit overrides |
| **Modular** | `/etc/systemd/system/<unit>.d/*.conf` | Drop-in override configuration snippets |
| **Runtime** | `/run/systemd/system/` | Volatile runtime units created dynamically by daemons |
| **Package** | `/usr/lib/systemd/system/` (`/lib/systemd/system/`) | Package-manager installed default units |
| **User** | `~/.config/systemd/user/` | Per-user session units (`systemctl --user`) |

`FragmentPath` in `systemctl show <unit>` indicates the exact file currently controlling the unit.

## 3. Configuration Inspection & Syntax Testing

Inspect the effective unit definition and validate syntax before reloading or activating changes:

```bash
# View complete active unit definition, including all merged drop-ins
systemctl cat nginx

# Perform pre-flight syntax check on unit files
systemd-analyze verify /etc/systemd/system/nginx.service
```

## 4. Operational Diagnostics, Timers & Persistence Auditing

### Audit service logs

```bash
journalctl -u nginx --since "1 hour ago" --no-pager
journalctl -u nginx -e --no-pager -n 50
```

### Timers

Timers trigger services on schedules or events ([T1053.006](https://attack.mitre.org/techniques/T1053/006/)):

```bash
systemctl list-timers --all
```

### Hunt for systemd persistence

Malicious services and timers ([T1543.002](https://attack.mitre.org/techniques/T1543/002/), [T1053.006](https://attack.mitre.org/techniques/T1053/006/)) usually appear as recently modified unit files:

```bash
sudo find /etc/systemd /usr/lib/systemd /lib/systemd /run/systemd /home/*/.config/systemd /root/.config/systemd \
  -type f \( -name '*.service' -o -name '*.timer' -o -name '*.conf' \) -mtime -14 -ls 2>/dev/null
```

```bash
sudo grep -rhs '^ExecStart' /etc/systemd/system | sort | uniq -c | sort -n
```

**What to look for:** `ExecStart` invoking `bash -c`, `curl`/`wget` piped to a shell, binaries in `/tmp`, `/dev/shm`, `/var/tmp` or hidden directories; `Restart=always` on unknown units.

## 5. Hardening & Safe Service Lifecycle

### Stop, disable and mask

Always copy the unit file to your evidence folder before neutralizing:

```bash
sudo systemctl disable --now badsvc.service
sudo systemctl mask badsvc.service       # prevents any start, even as a dependency
sudo systemctl daemon-reload             # after editing or removing unit files
```

### Safe reload without dropping connections

When deploying configuration updates to production daemons, use `reload` instead of `restart` to prevent connection drops:

```bash
sudo systemctl reload nginx              # reloads configuration gracefully without dropping connections
```

## Related

- [Linux Service Failure workflow](../../tasks/troubleshooting/linux-service-failure.md)
- [Cron and timers](cron.md)
- [Windows services](../windows/services.md)

## Sources

- [systemctl(1)](https://man7.org/linux/man-pages/man1/systemctl.1.html)
- [systemd.unit(5) — load path](https://man7.org/linux/man-pages/man5/systemd.unit.5.html)
- [systemd-analyze(1)](https://man7.org/linux/man-pages/man1/systemd-analyze.1.html)

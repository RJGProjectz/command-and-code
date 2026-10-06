---
title: Linux Service Failure Troubleshooting
type: workflow
platforms: [Linux]
languages: [Bash]
tasks: [Troubleshooting, Administration]
category: Workflow
tags: [workflow, troubleshooting, systemd, journalctl, service failed]
aliases: [service failed to start, systemd unit failed, service keeps restarting, troubleshoot linux service]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Linux Service Failure Troubleshooting

**Symptom:** a systemd service fails to start, stops unexpectedly, or restarts in a loop.

## 1. Status and recent logs

```bash
systemctl status SERVICE --no-pager -l
journalctl -u SERVICE -b --no-pager | tail -50
```

The status output shows the exit code and the last log lines. → [systemd](../../platforms/linux/systemd.md#inspect-a-service)

## 2. What exactly is it running?

```bash
systemctl cat SERVICE
```

Run the `ExecStart` command manually as the service's `User=` to see the real error:

```bash
sudo -u SERVICE_USER /path/to/binary --args
```

## 3. Common causes

| Symptom in logs | Check |
| --- | --- |
| `Permission denied` | file ownership/modes, SELinux/AppArmor denials → [troubleshooting](../../platforms/linux/troubleshooting.md#selinux-and-apparmor-denials) |
| `Address already in use` | another process holds the port → [process for a port](../../platforms/linux/networking.md#find-the-process-for-a-port) |
| `No space left on device` | disk or inodes → [disk full](../../platforms/linux/troubleshooting.md#disk-full) |
| `status=137` / killed | OOM killer → [OOM kills](../../platforms/linux/troubleshooting.md#out-of-memory-kills) |
| `start request repeated too quickly` | crash loop — fix the underlying error, then `systemctl reset-failed SERVICE` |

## 4. Config changes

Validate config before restarting (examples: `nginx -t`, `sshd -t`, `apachectl configtest`, `named-checkconf`). After editing unit files: `systemctl daemon-reload`.

## 5. Security angle

An unexpected failure of a security service (auditd, EDR agent, syslog forwarder) can be tampering. Check who changed it:

```bash
sudo find /etc/systemd /usr/lib/systemd -name 'SERVICE*' -newer /etc/hostname -ls
sudo grep -E 'systemctl (stop|disable|mask)' /root/.bash_history /home/*/.bash_history 2>/dev/null
```

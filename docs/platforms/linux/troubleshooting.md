---
title: Linux Troubleshooting Commands
platforms: [Linux]
languages: [Bash]
tasks: [Troubleshooting, Administration]
category: Troubleshooting
tags: [troubleshooting, oom, disk full, load, selinux, apparmor, time sync]
aliases: [disk full linux, out of memory, high load, selinux denials, chrony]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Linux Troubleshooting Commands

## Load, CPU and memory

```bash
uptime                       # load averages: 1, 5, 15 minutes
top -b -n 1 | head -20
free -h
vmstat 1 5
```

Load average above the CPU count (`nproc`) for a sustained period means work is queuing.

## Out-of-memory kills

```bash
journalctl -k | grep -iE 'out of memory|oom-kill'
dmesg -T | grep -i oom
```

## Disk full

```bash
df -h
df -i
sudo du -xh /var --max-depth=2 2>/dev/null | sort -h | tail
sudo lsof +L1                # deleted files still holding space
journalctl --disk-usage
```

## Failing services

```bash
systemctl --failed
journalctl -u SERVICE -b --no-pager | tail -50
```

See the [Linux Service Failure workflow](../../tasks/troubleshooting/linux-service-failure.md).

## Time synchronisation

```bash
timedatectl
chronyc tracking
chronyc sources -v
```

## SELinux and AppArmor denials

```bash
getenforce
sudo ausearch -m AVC -ts recent
sudo aa-status
```

A service that works with `setenforce 0` (temporary, for testing only) but not in enforcing mode has an SELinux policy problem — fix the context or policy rather than disabling SELinux.

## Related

- [Windows troubleshooting](../windows/troubleshooting.md)
- [Linux logs](logs.md)

## Sources

- [chronyc(1)](https://chrony-project.org/doc/4.5/chronyc.html)
- [Red Hat: Troubleshooting SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/troubleshooting-problems-related-to-selinux_using-selinux)

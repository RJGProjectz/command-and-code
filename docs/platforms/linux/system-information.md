---
title: Linux System Information
platforms: [Linux]
languages: [Bash]
tasks: [Incident Response, Administration, Troubleshooting]
category: System Information
tags: [os-release, uname, uptime, hostnamectl, environment variables]
aliases: [linux version, kernel version, which distro, uptime linux, environment variables linux]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Linux System Information

## OS, kernel and host

```bash
cat /etc/os-release
uname -a
hostnamectl
```

## Uptime and last boot

```bash
uptime
who -b
last -x reboot shutdown | head
```

## Time

```bash
timedatectl
date -u
```

Record the host's time zone and clock offset at the start of an investigation — every timeline depends on it.

## Hardware and resources

```bash
lscpu
free -h
lsblk
df -h
```

## Environment variables

```bash
env | sort
printenv PATH
cat /etc/environment
sudo grep -rs 'LD_PRELOAD' /etc/environment /etc/profile /etc/profile.d /etc/bash.bashrc /root/.bashrc /home/*/.bashrc
```

**What to look for:** `LD_PRELOAD`, unusual `PATH` entries (writable directories first), aliases overriding `ls`, `ps`, `sudo` in shell profiles.

## Kernel modules

```bash
lsmod
modinfo MODULE_NAME
```

Unknown kernel modules can indicate a rootkit.

## Related

- [Windows system information](../windows/system-information.md)
- [Endpoint Triage workflow](../../tasks/incident-response/endpoint-triage.md)

## Sources

- [os-release(5)](https://man7.org/linux/man-pages/man5/os-release.5.html)
- [hostnamectl(1)](https://man7.org/linux/man-pages/man1/hostnamectl.1.html)

---
title: Linux Kernel Tuning & sysctl Runtime Optimization
type: entry
platforms:
  - Linux
languages:
  - Bash
tasks:
  - Hardening
  - Troubleshooting
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - linux
  - kernel
  - sysctl
  - performance
---

# Linux Kernel Tuning & sysctl Runtime Optimization

Inspecting and tuning runtime Linux kernel parameters via `/proc/sys` and `/etc/sysctl.d/` for network performance and host hardening.

## Hardened Network sysctl Baseline (`/etc/sysctl.d/99-security.conf`)

```ini
# Disable IP forwarding (unless router / gateway host)
net.ipv4.ip_forward = 0

# Ignore ICMP broadcast echo requests (Smurf attack defense)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Enable TCP SYN Cookies (SYN flood defense)
net.ipv4.tcp_syncookies = 1

# Disable ICMP redirect acceptance (MITM defense)
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Restrict dmesg kernel logging to root only
kernel.dmesg_restrict = 1

# Restrict BPF execution to privileged accounts
kernel.unprivileged_bpf_disabled = 1
```

Apply immediately:
```bash
sudo sysctl --system
```

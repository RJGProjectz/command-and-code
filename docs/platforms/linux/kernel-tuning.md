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
last_verified: 2026-10-12
difficulty: intermediate
tags:
  - linux
  - kernel
  - sysctl
  - performance
---

# Linux Kernel Tuning & sysctl Runtime Optimization

Inspecting and tuning runtime Linux kernel parameters via `/proc/sys` and `/etc/sysctl.d/` for network performance and host hardening.

## 1. Read and change values

Every `sysctl` key maps to a file under `/proc/sys` (`net.ipv4.ip_forward` = `/proc/sys/net/ipv4/ip_forward`).

```bash
sysctl net.ipv4.ip_forward              # read one value
sysctl -a 2>/dev/null | grep rp_filter  # search all values
sysctl -w net.ipv4.ip_forward=0         # change until reboot (change)
```

Persistent settings go in `/etc/sysctl.d/*.conf`. Files load in name order and a later file wins, so `99-` files override vendor defaults in `/usr/lib/sysctl.d/`.

## 2. Hardened Network sysctl Baseline (`/etc/sysctl.d/99-security.conf`)

```ini
# Disable IP forwarding (unless router / gateway host)
net.ipv4.ip_forward = 0

# Ignore ICMP broadcast echo requests (Smurf attack defense)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Enable TCP SYN Cookies (SYN flood defense)
net.ipv4.tcp_syncookies = 1

# Disable ICMP redirect acceptance and sending (MITM defense)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Refuse source-routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Reverse-path filtering (drop spoofed source addresses); use 2 (loose) on multi-homed hosts
net.ipv4.conf.all.rp_filter = 1

# Log packets with impossible source addresses
net.ipv4.conf.all.log_martians = 1
```

## 3. Kernel hardening baseline

```ini
# Restrict dmesg kernel logging to root only
kernel.dmesg_restrict = 1

# Hide kernel pointers from unprivileged users (makes exploits harder)
kernel.kptr_restrict = 2

# Restrict BPF execution to privileged accounts
kernel.unprivileged_bpf_disabled = 1

# Only a parent process may ptrace its children (blocks credential theft from other processes)
kernel.yama.ptrace_scope = 1

# Full address space layout randomisation
kernel.randomize_va_space = 2

# Protect against link and FIFO tricks in world-writable directories
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# No core dumps from setuid programs (they can contain secrets)
fs.suid_dumpable = 0
```

Apply immediately:

```bash
sudo sysctl --system
```

`sysctl --system` prints each file as it loads; an `unknown key` line means the key does not exist on this kernel (for example `kernel.yama.ptrace_scope` without the Yama module).

## 4. Verify and investigate

```bash
# Confirm the running values match the baseline
grep -hv '^\s*#' /etc/sysctl.d/99-security.conf | grep '=' | while IFS='=' read -r key value; do
    key=$(echo "$key" | xargs); value=$(echo "$value" | xargs)
    [ "$(sysctl -n "$key" 2>/dev/null)" = "$value" ] && echo "OK   $key" || echo "DIFF $key (running: $(sysctl -n "$key" 2>/dev/null))"
done
```

During an incident, `net.ipv4.ip_forward = 1` on a host that is not a router, or `kernel.yama.ptrace_scope = 0` when your baseline sets 1, means someone changed it. Check `/etc/sysctl.d/`, `/etc/sysctl.conf` and recent root shell history.

## Related

- [Linux firewalls and nftables](firewalls-nftables.md)
- [Linux Audit Daemon (auditd)](auditd.md)

## Sources

- [Linux kernel docs — /proc/sys/kernel](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [Linux kernel docs — IP sysctl](https://docs.kernel.org/networking/ip-sysctl.html)
- [Linux kernel docs — /proc/sys/fs](https://docs.kernel.org/admin-guide/sysctl/fs.html)
- [sysctl.d(5)](https://man7.org/linux/man-pages/man5/sysctl.d.5.html)

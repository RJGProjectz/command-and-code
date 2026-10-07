---
title: Linux Startup Persistence & Autostart Architecture
type: entry
platforms:
  - Linux
languages:
  - Bash
tasks:
  - Investigation
  - Forensics
  - Hardening
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - linux
  - persistence
  - systemd
  - autostart
  - ld-preload
---

# Linux Startup Persistence & Autostart Architecture

Investigating, auditing, and defending autostart persistence mechanisms across systemd services, shell profile hooks, init scripts, and dynamic linker injection (`/etc/ld.so.preload`).

## 1. Process & Service First: Systemd Generators & Units

```bash
# 1. Inspect active user and system services enabled at boot
systemctl list-unit-files --type=service --state=enabled

# 2. Check systemd generator directories (early-boot transient units)
ls -la /run/systemd/generator/ /run/systemd/generator.early/ /run/systemd/generator.late/
```

## 2. Global & User Shell Profile Persistence

Adversaries inject backdoor commands into environment startup files executed when any interactive or login shell starts:

```bash
# 1. Global shell configuration files
ls -la /etc/profile /etc/bash.bashrc /etc/profile.d/ /etc/environment

# 2. User-specific shell configuration files
ls -la ~/.bashrc ~/.bash_profile ~/.bash_login ~/.profile ~/.bash_logout

# 3. Check for anomalous aliases or background nohup triggers
grep -E 'alias|export PATH|curl|wget|nc|python' /etc/profile.d/*.sh ~/.bashrc 2>/dev/null
```

## 3. Legacy Init Scripts & System Hooks

```bash
# 1. Audit /etc/rc.local and SysV init directories
ls -la /etc/rc.local /etc/rc*.d/ /etc/init.d/

# 2. Check XDG desktop autostart entries (GUI sessions)
ls -la /etc/xdg/autostart/ ~/.config/autostart/
```

## 4. Kernel & Shared Library Persistence (`ld.so.preload`)

Malicious rootkits inject arbitrary `.so` dynamic libraries into every spawned binary by hooking the loader:

```bash
# 1. Check for ld.so.preload existence (should NOT exist in standard baselines)
ls -la /etc/ld.so.preload
cat /etc/ld.so.preload 2>/dev/null

# 2. Check for kernel modules loaded outside package directories
lsmod | head -n 20
find /lib/modules/$(uname -r)/ -name "*.ko" -mtime -30
```

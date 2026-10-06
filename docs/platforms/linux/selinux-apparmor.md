---
title: Linux Mandatory Access Control — SELinux & AppArmor
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
  - selinux
  - apparmor
  - mac
---

# Linux Mandatory Access Control — SELinux & AppArmor

Mandatory Access Control (MAC) enforces fine-grained confinement over processes, restricting file and network access even if root privileges are compromised.

## 1. SELinux (RHEL, Fedora, Rocky, Alma)

```bash
# Check current SELinux status
sestatus

# Inspect security context labels on files
ls -lZ /var/www/html/

# Restore default security contexts recursively
restorecon -Rv /var/www/html/

# Query and toggle SELinux booleans
getsebool -a | grep httpd
setsebool -P httpd_can_network_connect on
```

## 2. AppArmor (Ubuntu, Debian, SUSE)

```bash
# Check loaded profile enforcement states
aa-status

# Put a profile into complain (monitor) mode
aa-complain /usr/sbin/nginx

# Enforce profile rules strictly
aa-enforce /usr/sbin/nginx
```

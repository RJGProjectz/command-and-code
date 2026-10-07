---
title: Linux Distributions, Package Systems & Release Baselines
type: entry
platforms:
  - Linux
languages:
  - Bash
tasks:
  - Administration
  - Troubleshooting
verified: true
last_verified: 2026-10-06
difficulty: basic
tags:
  - linux
  - distros
  - releases
  - debian
  - rhel
---

# Linux Distributions, Package Systems & Release Baselines

Operating system release discovery, distribution family standards (Debian/Ubuntu, RHEL/Rocky, Alpine), package managers (`apt`, `dnf`, `apk`), and kernel lifecycle tracking.

## 1. Process & Service First: Distribution Identification

```bash
# 1. Query standardized OS release metadata
cat /etc/os-release

# 2. Query kernel architecture, release version, and build date
uname -s -r -v -m

# 3. Enumerate system architecture via hostnamectl
hostnamectl
```

## 2. Distribution Family Comparisons

| Family | Reference Distros | Package Manager | Service Manager | Default Firewall | Default MAC |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Debian** | Debian, Ubuntu, Kali | `apt`, `dpkg` | `systemd` | `ufw` / `nftables` | AppArmor |
| **RHEL** | RHEL, Rocky, Alma, Fedora | `dnf`, `rpm` | `systemd` | `firewalld` / `nftables` | SELinux |
| **Alpine** | Alpine Linux | `apk` | `OpenRC` | `nftables` | PaX / Grsecurity |
| **SUSE** | SLES, openSUSE | `zypper`, `rpm` | `systemd` | `firewalld` | AppArmor |

## 3. Kernel Version & Module Lifecycles

```bash
# 1. Inspect loaded kernel parameters
sysctl -a | grep -E 'kernel.osrelease|kernel.version'

# 2. Check installed kernel packages (RHEL / Ubuntu)
rpm -qa | grep kernel || dpkg --list | grep linux-image

# 3. Clean obsolete kernel packages to reclaim /boot space
apt-get autoremove --purge || dnf autoremove
```

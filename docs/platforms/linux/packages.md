---
title: Linux Installed Packages
platforms: [Linux]
languages: [Bash]
tasks: [Investigation, Administration, Forensics]
category: Software
tags: [dpkg, rpm, apt, dnf, package integrity, installed software]
aliases: [list installed packages, which package owns a file, verify package files, rpm -Va, dpkg --verify]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Linux Installed Packages

| Task | Debian / Ubuntu | RHEL / Fedora / Rocky |
| --- | --- | --- |
| List installed | `dpkg -l` / `apt list --installed` | `rpm -qa` |
| Recently installed | `grep ' install ' /var/log/dpkg.log` | `rpm -qa --last` (newest first) |
| Install history | `less /var/log/apt/history.log` | `dnf history` |
| Which package owns a file | `dpkg -S /usr/bin/ssh` | `rpm -qf /usr/bin/ssh` |
| Verify package files | `dpkg --verify` | `rpm -Va` |
| Package details | `apt show openssh-server` | `rpm -qi openssh-server` |

## Verify package integrity

Detects binaries replaced by a rootkit or trojanised tool:

```bash
sudo dpkg --verify 2>/dev/null | grep -v ' c '          # Debian/Ubuntu; 'c' marks config files
sudo rpm -Va 2>/dev/null | grep -E '^..5' | grep -v ' c ' # RHEL-family; '5' = digest changed
```

A changed digest on a binary in `/usr/bin`, `/usr/sbin` or `/lib` is a strong indicator. Verification trusts the local package database — an attacker with root can tamper with it, so confirm with a known-good source.

## Files not owned by any package

```bash
for f in /usr/bin/* /usr/sbin/*; do dpkg -S "$f" >/dev/null 2>&1 || echo "unowned: $f"; done
```

(RHEL-family: replace `dpkg -S` with `rpm -qf`.)

## Other package sources

```bash
snap list
flatpak list
pip list 2>/dev/null
ls /opt /usr/local/bin
```

## Related

- [Windows installed software](../windows/software.md)
- [Linux filesystem](filesystem.md)

## Sources

- [dpkg(1)](https://man7.org/linux/man-pages/man1/dpkg.1.html)
- [rpm verify](https://rpm-software-management.github.io/rpm/man/rpm.8.html)

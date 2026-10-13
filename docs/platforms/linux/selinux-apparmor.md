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
last_verified: 2026-10-12
difficulty: intermediate
tags:
  - linux
  - selinux
  - apparmor
  - mac
---

# Linux Mandatory Access Control — SELinux & AppArmor

Mandatory Access Control (MAC) enforces fine-grained confinement over processes, restricting file and network access even if root privileges are compromised.

**Why it matters:** with MAC enforcing, a compromised web server process can only touch the files and ports its policy allows, even when the attacker gets code execution. Turning it off "to make the app work" removes that layer, so fix the policy instead. Attackers also disable it after gaining root ([T1685](https://attack.mitre.org/techniques/T1685/), formerly T1562.001), so its state is worth checking during triage.

| | SELinux | AppArmor |
| --- | --- | --- |
| Default on | RHEL, Fedora, Rocky, Alma, CentOS Stream | Ubuntu, Debian, SUSE |
| Model | Labels on every file and process | Path-based profiles per program |
| Modes | `enforcing`, `permissive` (log only), `disabled` | `enforce`, `complain` (log only), unconfined |
| Denials logged as | `type=AVC` in `/var/log/audit/audit.log` | `apparmor="DENIED"` in the kernel log |

## 1. SELinux (RHEL, Fedora, Rocky, Alma)

```bash
# Check current SELinux status
sestatus
getenforce

# Inspect security context labels on files and processes
ls -lZ /var/www/html/
ps -eZ | grep httpd

# Restore default security contexts recursively
restorecon -Rv /var/www/html/

# Query and toggle SELinux booleans
getsebool -a | grep httpd
setsebool -P httpd_can_network_connect on
```

### Fix a denial the right way

```bash
# 1. See recent denials and why they happened
ausearch -m AVC,USER_AVC -ts recent
ausearch -m AVC -ts recent | audit2why

# 2. Common fixes, in order of preference
semanage fcontext -a -t httpd_sys_content_t '/srv/www(/.*)?'   # label a custom path
restorecon -Rv /srv/www
semanage port -a -t http_port_t -p tcp 8443                   # allow a non-standard port
setsebool -P <boolean> on                                      # a boolean made for this case

# 3. Last resort: a small local module built from the denials (review it before loading)
ausearch -m AVC -ts recent | audit2allow -M mylocal
semodule -i mylocal.pp
```

`setenforce 0` switches to permissive until reboot. Use it only to confirm SELinux is the cause, then switch back with `setenforce 1`. The persistent mode is `SELINUX=` in `/etc/selinux/config`.

## 2. AppArmor (Ubuntu, Debian, SUSE)

```bash
# Check loaded profile enforcement states
aa-status

# Put a profile into complain (monitor) mode
aa-complain /usr/sbin/nginx

# Enforce profile rules strictly
aa-enforce /usr/sbin/nginx

# Recent denials
journalctl -k | grep 'apparmor="DENIED"'

# Update a profile interactively from logged events
aa-logprof
```

Profiles live in `/etc/apparmor.d/`; reload one after editing with `apparmor_parser -r /etc/apparmor.d/<profile>`. `aa-complain`, `aa-enforce` and `aa-logprof` come from the `apparmor-utils` package.

## 3. Incident triage checks

```bash
getenforce; grep '^SELINUX=' /etc/selinux/config          # SELinux hosts
aa-status | head -n 5                                       # AppArmor hosts
ausearch -m MAC_STATUS,MAC_CONFIG_CHANGE -i                 # SELinux mode or boolean changes (auditd)
```

A host that should be enforcing but is permissive or disabled, or a burst of denials for a web or database process, is a lead worth following.

## Related

- [Linux Audit Daemon (auditd)](auditd.md)
- [Linux services (systemd)](systemd.md)

## Sources

- [Red Hat — Using SELinux (RHEL 9)](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/index)
- [Ubuntu Server — AppArmor](https://documentation.ubuntu.com/server/how-to/security/apparmor/)
- [audit2allow(1)](https://man7.org/linux/man-pages/man1/audit2allow.1.html)

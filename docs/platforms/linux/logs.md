---
title: Linux Logs
platforms: [Linux]
languages: [Bash]
tasks: [Incident Response, Investigation, Troubleshooting, Forensics]
category: Logging
tags: [journalctl, auth.log, secure, auditd, failed ssh, logs]
aliases: [failed ssh logins, journalctl, auth.log, /var/log/secure, ausearch, linux login history]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
---

# Linux Logs

## Where logs live

| Content | Debian / Ubuntu | RHEL / Fedora / Rocky |
| --- | --- | --- |
| Authentication (sshd, sudo, su) | `/var/log/auth.log` | `/var/log/secure` |
| General system | `/var/log/syslog` | `/var/log/messages` |
| Kernel | `/var/log/kern.log` | `/var/log/messages` |
| Package installs | `/var/log/dpkg.log`, `/var/log/apt/history.log` | `/var/log/dnf.log`, `dnf history` |
| Audit (auditd) | `/var/log/audit/audit.log` | `/var/log/audit/audit.log` |
| Logins (binary) | `/var/log/wtmp`, `/var/log/btmp` | same |

Some minimal installs only have the systemd journal — use `journalctl`.

## journalctl essentials

```bash
journalctl -b -p err                              # errors since this boot
journalctl --since "2026-10-05 08:00" --until "2026-10-05 12:00"
journalctl -u ssh --since today                   # unit is 'sshd' on RHEL-family
journalctl _COMM=sudo --since "-2h"
journalctl -k                                     # kernel messages
journalctl -f                                     # follow
journalctl -u ssh -o json --since today > /tmp/ssh.json
journalctl --list-boots
```

## Failed SSH logins

```bash
sudo grep -E 'Failed password|Invalid user' /var/log/auth.log | tail -50
```

Top source IPs:

```bash
sudo grep 'Failed password' /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head
```

The IP is the 4th field from the end of `Failed password for [invalid user] NAME from IP port N ssh2`.

Journal-only systems:

```bash
journalctl -u ssh --since "-24h" | grep -E 'Failed password|Invalid user'
```

## Successful logins

```bash
sudo grep 'Accepted' /var/log/auth.log
last -n 30 -a          # from wtmp
sudo lastb -n 30 -a    # failed logins from btmp
lastlog | grep -v 'Never logged in'
```

`Accepted publickey` vs `Accepted password` tells you how the session authenticated.

## sudo usage

```bash
sudo grep -E 'sudo: .*COMMAND=' /var/log/auth.log | tail -50
```

## auditd

```bash
sudo ausearch -m USER_LOGIN -ts today -i
sudo ausearch -m EXECVE -ts recent -i
sudo ausearch -k KEYNAME -i
sudo aureport -au --summary
```

`-ts recent` = last 10 minutes; `-i` interprets UIDs and syscalls into names. `EXECVE` records require audit rules that watch `execve`.

## Log tampering indicators

- Gaps in timestamps or a truncated `auth.log`/`wtmp`
- `wtmp` smaller than expected, `last` shows `wtmp begins` recently
- `HISTFILE=/dev/null` or `unset HISTFILE` in shell histories or profiles

## Related

- [Failed Authentication workflow](../../tasks/investigation/failed-authentication.md)
- [Linux SSH](ssh.md)
- [Windows event logs](../windows/event-logs.md)

## Sources

- [journalctl(1)](https://man7.org/linux/man-pages/man1/journalctl.1.html)
- [ausearch(8)](https://man7.org/linux/man-pages/man8/ausearch.8.html)

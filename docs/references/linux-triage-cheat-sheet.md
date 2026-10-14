---
title: Linux Triage Cheat Sheet (Printable)
type: reference
platforms: [Linux]
languages: [Bash]
tasks: [Incident Response, Investigation, Forensics]
category: Reference
tags: [linux, triage, cheat sheet, printable, incident response, bash, live response]
aliases: [linux triage cheat sheet, linux ir cheat sheet, linux live response commands, printable linux triage]
difficulty: intermediate
verified: true
last_verified: 2026-10-13
search:
  boost: 3
---

# Linux Triage Cheat Sheet (Printable)

Live-response sheet for a suspect Linux host. The **Print** button gives one landscape sheet, printed on both sides.

!!! warning "Before you run anything"
    Commands were checked against the man pages (procps-ng, iproute2, util-linux, systemd, GNU findutils) on
    2026-10-13; this guide does not run them on your host. Run as root (`sudo -i`), prefer trusted binaries from
    read-only media on a host you think is rootkitted, and collect before you change anything. Lines marked
    **change** alter the host. Full script: [linux-triage.sh](../toolbox/bash.md#linux-triagesh).

## 1. Host and users

```bash
hostnamectl; uptime; date -u
who -a                       # current sessions
last -F -n 20                # recent logins (wtmp)
lastb -F -n 20               # recent failed logins (btmp, root only)
awk -F: '$3 == 0 {print $1}' /etc/passwd     # every UID 0 account, should be root only
getent group sudo wheel
```

## 2. Processes

```bash
ps auxwwf                                            # full command lines as a tree
ps -eo pid,ppid,user,lstart,cmd --sort=start_time | tail -n 25   # newest processes
ls -l /proc/*/exe 2>/dev/null | grep '(deleted)'     # running from a deleted binary
ls -l /proc/<PID>/cwd /proc/<PID>/exe; tr '\0' ' ' < /proc/<PID>/cmdline; echo
```

A process whose binary is deleted, or that runs from `/tmp`, `/dev/shm` or a hidden directory, is the lead.

## 3. Network

```bash
ss -tulpn                    # listeners with owning process
ss -tnp state established    # live TCP connections with process
ip -br addr; ip route
cat /etc/resolv.conf /etc/hosts
```

## 4. Persistence

```bash
cat /etc/crontab; ls -la /etc/cron.* /var/spool/cron /var/spool/cron/crontabs 2>/dev/null
systemctl list-timers --all
systemctl list-unit-files --state=enabled
find /etc/systemd/system /usr/lib/systemd/system /home/*/.config/systemd -type f -mtime -7 2>/dev/null
cat /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null
cat /etc/ld.so.preload 2>/dev/null           # should not exist on most systems
ls -la /etc/profile.d/ /etc/rc.local 2>/dev/null
```

Deep dive: [Scheduled task persistence review](../tasks/threat-hunting/scheduled-task-persistence-review.md).

## 5. Logs

```bash
journalctl --since "24 hours ago" -p warning --no-pager | tail -n 50
journalctl -u ssh -u sshd --since today --no-pager | grep -E 'Accepted|Failed'
grep -E 'Accepted|Failed|sudo' /var/log/auth.log /var/log/secure 2>/dev/null | tail -n 50
ausearch -m USER_LOGIN,USER_AUTH -ts today -i 2>/dev/null | tail -n 30    # if auditd runs
```

`auth.log` is Debian/Ubuntu, `secure` is RHEL family. The SSH unit is `ssh` on Debian and `sshd` on RHEL.

## 6. Files

```bash
find /tmp /var/tmp /dev/shm -type f -mtime -7 -ls 2>/dev/null
find / -xdev -type f -perm -4000 -mtime -30 -ls 2>/dev/null      # new SUID binaries
find / -xdev -name '.*' -type d -path '*/tmp/*' 2>/dev/null       # hidden dirs under tmp
sha256sum '<FILE_PATH>'
dpkg --verify 2>/dev/null || rpm -Va                            # changed package files
```

## 7. Collect, then contain

```bash
case_dir="/root/ir-$(hostname)-$(date -u +%Y%m%dT%H%MZ)"; mkdir -p "$case_dir"
ps auxwwf > "$case_dir/ps.txt"; ss -tunap > "$case_dir/ss.txt"; last -F > "$case_dir/last.txt"
tar czf "$case_dir/logs.tgz" /var/log 2>/dev/null
sha256sum "$case_dir"/* > "$case_dir/SHA256SUMS"
# change: only after collection
kill -STOP <PID>             # freeze, do not kill: memory and open files stay available
usermod -L <USER>            # lock the account's password
```

Copy the case folder off the host. Capture memory before a reboot ([Memory acquisition](../tasks/forensics/memory-acquisition-analysis.md)).

## Sources

- [ss(8)](https://man7.org/linux/man-pages/man8/ss.8.html) · [ps(1)](https://man7.org/linux/man-pages/man1/ps.1.html) · [last(1), util-linux](https://man7.org/linux/man-pages/man1/last.1@@util-linux.html)
- [journalctl(1)](https://man7.org/linux/man-pages/man1/journalctl.1.html) · [find(1)](https://man7.org/linux/man-pages/man1/find.1.html) · [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)
- [ausearch(8)](https://man7.org/linux/man-pages/man8/ausearch.8.html) · [usermod(8)](https://man7.org/linux/man-pages/man8/usermod.8.html)

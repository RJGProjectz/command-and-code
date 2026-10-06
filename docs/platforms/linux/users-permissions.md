---
title: Linux Users and Permissions
platforms: [Linux]
languages: [Bash]
tasks: [Incident Response, Investigation, Administration, Hardening]
category: Identity
tags: [users, groups, sudo, suid, permissions, capabilities, uid 0]
aliases: [linux users, sudoers, uid 0 accounts, suid binaries, world writable, lock linux account, chmod]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Linux Users and Permissions

## Accounts

```bash
getent passwd                                     # local + directory users
awk -F: '$3 == 0 {print $1}' /etc/passwd          # every UID-0 account (should be only root)
grep -vE '(nologin|false)$' /etc/passwd           # accounts with a login shell
id jdoe
```

## Groups and sudo rights

```bash
getent group sudo wheel                           # admin group (Debian: sudo, RHEL: wheel)
sudo cat /etc/sudoers
sudo ls -la /etc/sudoers.d/
sudo -l -U jdoe                                   # what jdoe may run
sudo visudo -c                                    # syntax-check sudoers files
```

**What to look for:** new files in `/etc/sudoers.d/`, `NOPASSWD: ALL` entries, UID-0 accounts other than `root`, new accounts with a shell.

## Who is logged in

```bash
who
w
last -n 20 -a
```

## Password and account state

```bash
sudo chage -l jdoe
sudo passwd -S jdoe
```

## Lock an account

```bash
sudo usermod -L jdoe                       # lock password
sudo usermod -s /usr/sbin/nologin jdoe     # remove shell
sudo chage -E 0 jdoe                       # expire account
```

Locking the password does **not** stop SSH key logins — also review [`authorized_keys`](ssh.md#find-authorized-keys) and existing sessions (`pkill -KILL -u jdoe`).

## Read permissions

```bash
ls -la /path
stat /path/file
getfacl /path/file
```

```text
-rwsr-xr-x  1 root root  /usr/bin/passwd
   ^ s = setuid: runs as the file owner (root)
```

## Find SUID/SGID binaries

```bash
sudo find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} + 2>/dev/null
```

Compare against a known-good baseline. Unexpected SUID copies of shells or interpreters are a privilege-escalation backdoor ([T1548.001](https://attack.mitre.org/techniques/T1548/001/)).

## Find world-writable directories without the sticky bit

```bash
sudo find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null
```

## File capabilities

```bash
sudo getcap -r / 2>/dev/null
```

`cap_setuid` on an interpreter (e.g. `python3`) is equivalent to root.

## Change permissions

```bash
chmod 640 file
chmod u+x script.sh
sudo chown root:root /etc/cron.d/job
```

## Related

- [Account Compromise workflow](../../tasks/incident-response/account-compromise.md)
- [Windows users and groups](../windows/users-groups.md)

## Sources

- [sudoers(5)](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html)

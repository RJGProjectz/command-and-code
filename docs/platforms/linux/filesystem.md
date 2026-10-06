---
title: Linux Filesystem
platforms: [Linux]
languages: [Bash]
tasks: [Incident Response, Investigation, Forensics, Troubleshooting]
category: Filesystem
tags: [find, hashes, recent files, immutable, disk usage, tmp, dev shm]
aliases: [recently modified files linux, sha256sum, find files linux, chattr immutable, disk space]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Linux Filesystem

## Recently modified files

```bash
sudo find / -xdev -type f -mmin -60 2>/dev/null | grep -vE '^/(proc|sys|run)/'
sudo find /etc /usr/bin /usr/sbin /usr/lib -xdev -type f -mtime -7 -ls 2>/dev/null
```

`-mmin -60` = modified in the last 60 minutes; `-mtime -7` = last 7 days; `-xdev` stays on one filesystem. Use `-newer /path/reference` to find files changed after a known event.

## Temporary and staging locations

```bash
sudo ls -la /tmp /var/tmp /dev/shm
sudo find /tmp /var/tmp /dev/shm -type f -exec file {} + 2>/dev/null | grep -i elf
```

ELF binaries in `/tmp` or `/dev/shm` (RAM-backed) are highly suspicious.

## Hidden files and directories

```bash
sudo find / -xdev -name '.*' -type d 2>/dev/null | grep -vE '/(\.cache|\.config|\.local|\.git|\.ssh|\.gnupg|\.mozilla)$'
```

## Inspect a file

```bash
sha256sum suspect
file suspect
stat suspect
strings -n 8 suspect | head -50
```

## Immutable attribute

Attackers set `+i` so files cannot be deleted or edited — even by root — until it is removed:

```bash
sudo lsattr -a /etc/ld.so.preload /root/.ssh/authorized_keys 2>/dev/null
sudo chattr -i /path/file
```

`/etc/ld.so.preload` should normally not exist; if present, every dynamically linked program loads the listed library ([T1574.006](https://attack.mitre.org/techniques/T1574/006/)).

## Open but deleted files

```bash
sudo lsof +L1
```

## Disk usage

```bash
df -h
df -i                                       # inode exhaustion
sudo du -xh / --max-depth=1 2>/dev/null | sort -h
findmnt
```

## Related

- [Malware Triage workflow](../../tasks/incident-response/malware-triage.md)
- [Windows files and permissions](../windows/files-directories.md)

## Sources

- [find(1)](https://man7.org/linux/man-pages/man1/find.1.html)
- [chattr(1)](https://man7.org/linux/man-pages/man1/chattr.1.html)
- [ld.so(8) — /etc/ld.so.preload](https://man7.org/linux/man-pages/man8/ld.so.8.html)

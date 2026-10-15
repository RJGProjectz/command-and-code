---
title: File Systems (NTFS, ext4, XFS)
type: concept
platforms: [Windows, Linux]
languages: [PowerShell, Bash]
tasks: [Forensics, Investigation, Hardening]
category: Operating Systems
security_domain: Endpoint
author: RJGProjectz
date_created: 2026-10-15
last_updated: 2026-10-15
tags: [concept, ntfs, ext4, xfs, mft, inode, ads, timestamps]
aliases: [NTFS, ext4, XFS, Master File Table, MFT, inode, Alternate Data Streams, ADS, MACB timestamps, hard links and symbolic links, mode bits]
difficulty: basic
verified: true
last_verified: 2026-10-15
---

# File Systems (NTFS, ext4, XFS)
> **Created**: 2026-10-15T03:20:00Z
> **Last Modified**: 2026-10-15T03:20:00Z
> **Author**: RJGProjectz

**In one line:** the file system decides where a file's bytes live, who may open it and which timestamps it keeps — the raw material of almost every investigation.

## What it is

A file system turns a disk volume into named files and folders. Windows uses **NTFS** (and ReFS on servers); Linux
distributions mostly use **ext4** or **XFS**. Both keep a metadata record per file, separate from the name you see:

| | Windows (NTFS) | Linux (ext4 / XFS) |
| :--- | :--- | :--- |
| Metadata record | an entry in the **Master File Table (MFT)**; every file, including the MFT itself, has at least one | an **inode**: type, mode, owner UID/GID, size, link count, timestamps |
| Where the name lives | the `$FILE_NAME` attribute in the MFT entry (also holds short names and hard links) | in the directory entry, which points to the inode number |
| Permissions | **ACL** in a security descriptor: owner + DACL of allow/deny entries (ACEs), inherited from the parent folder | **mode bits** `rwx` for owner / group / other, plus optional POSIX ACLs (`getfacl`) |
| Special bits | read-only, hidden, system attributes | setuid `04000`, setgid `02000`, sticky `01000` |
| Extra data | **Alternate Data Streams**: `file.txt:name:$DATA` next to the unnamed default stream | extended attributes (`security.capability`, SELinux labels) |
| Links | hard links, symbolic links, junctions (reparse points) | hard links (same inode, same file system only), symbolic links |

## How it works

**Timestamps (MACB).** Investigators speak of Modified, Accessed, Changed and Born:

| Letter | NTFS | Linux inode | Changes when |
| :--- | :--- | :--- | :--- |
| M | last write | `mtime` | content is written |
| A | last access | `atime` | content is read (often suppressed: `relatime`/`noatime` on Linux, disabled last-access updates on Windows) |
| C | MFT entry changed | `ctime` | metadata changes: owner, mode, link count, and every write |
| B | creation | `btime` | file is created; on Linux only `statx()` returns it, and not every file system keeps it |

NTFS has no per-stream times: writing to any stream of a file updates the file's times. Timestamps are metadata, so a
process with write access can set them back — compare them with other evidence (journal, logs, prefetch) before trusting them.

**Access check.** Windows walks the DACL of the object and compares each ACE with the SIDs in the caller's
[token](processes-threads.md); an explicit deny wins. Linux checks owner, then group, then other, using the process's
filesystem UID/GID, and root (or a process with the right [capability](users-groups-permissions.md)) bypasses the check.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1564.004](https://attack.mitre.org/techniques/T1564/004/) NTFS File Attributes (hiding data in ADS) · [T1070.006](https://attack.mitre.org/techniques/T1070/006/) Timestomp · [T1222](https://attack.mitre.org/techniques/T1222/) File and Directory Permissions Modification · [T1548.001](https://attack.mitre.org/techniques/T1548/001/) Setuid and Setgid · [T1083](https://attack.mitre.org/techniques/T1083/) File and Directory Discovery |
| **What it leads to** | hidden payloads, faked timelines, privilege escalation through writable or setuid files |
| **Where defenders meet it** | building a timeline, "who changed this file?", a world-writable folder in a service path, a SUID binary that should not exist |

## Do it

```bash
cc find "permissions" ; cc find "timeline"
```

```powershell
# Owner and ACL of a folder, and any alternate data streams on files in Downloads
Get-Acl -Path 'C:\ProgramData' | Format-List -Property Owner, AccessToString
Get-ChildItem -Path "$env:USERPROFILE\Downloads" -File |
    ForEach-Object { Get-Item -LiteralPath $_.FullName -Stream * } |
    Where-Object { $_.Stream -ne ':$DATA' } |
    Select-Object -Property FileName, Stream, Length
```

```bash
# Inode number, mode, owner and all four timestamps (Birth shows "-" where unsupported)
stat /etc/passwd
# POSIX ACL entries beyond the mode bits
getfacl /etc/passwd
```

A `Zone.Identifier` stream on a downloaded file is normal (Mark of the Web); other named streams deserve a look.

## See it

| Source | What you see |
| :--- | :--- |
| Sysmon Event 2 | a process changed a file creation time (timestomping) |
| Sysmon Event 15 | a named stream was created (FileCreateStreamHash), including `Zone.Identifier` |
| Security 4663 (with a SACL on the object) | who accessed or changed an audited file |
| NTFS `$MFT`, `$UsnJrnl` | full timestamp sets and the change journal, collected offline |
| auditd `-w path -p wa` | writes and attribute changes on watched Linux paths |

## Detect it

- Commands: [Windows files and permissions](../../platforms/windows/files-directories.md) · [Linux filesystem](../../platforms/linux/filesystem.md) · [Linux users and permissions](../../platforms/linux/users-permissions.md) (SUID/SGID, world-writable)
- Forensics: [Windows disk artifacts](../../tasks/forensics/windows-disk-artifacts.md) · [Linux live response](../../tasks/forensics/linux-live-response-forensics.md)
- Detection: [KQL file and registry events](../../detection/kql/file-registry-events.md) · [Sysmon architecture](../systems/sysmon.md)
- Harden: [Linux CIS filesystem and services](../../tasks/hardening/linux-cis-filesystem-services.md)
- Data handling: [Cross-platform data handling](../systems/cross-platform-data-handling.md)

## Related concepts

- [Access control models](access-control-models.md) · [Users, groups and privilege](users-groups-permissions.md) · [Digital forensics](digital-forensics.md) · [Hash functions](hash-functions.md)

## Sources

- Microsoft Learn: [Master File Table](https://learn.microsoft.com/windows/win32/fileio/master-file-table) · [File streams](https://learn.microsoft.com/windows/win32/fileio/file-streams) · [Access control lists](https://learn.microsoft.com/windows/win32/secauthz/access-control-lists) · [Sysmon events](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- man7.org: [inode(7)](https://man7.org/linux/man-pages/man7/inode.7.html) · [acl(5)](https://man7.org/linux/man-pages/man5/acl.5.html) · [statx(2)](https://man7.org/linux/man-pages/man2/statx.2.html)

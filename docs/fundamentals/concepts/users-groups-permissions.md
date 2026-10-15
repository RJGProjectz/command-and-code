---
title: Users, Groups and Privilege (SIDs, UIDs, UAC, sudo)
type: concept
platforms: [Windows, Linux]
languages: [PowerShell, Bash]
tasks: [Investigation, Hardening, Incident Response]
category: Operating Systems
security_domain: Identity
author: RJGProjectz
date_created: 2026-10-15
last_updated: 2026-10-15
tags: [concept, sid, uid, uac, sudo, root, administrator, privileges]
aliases: [Security Identifier (SID), UID and GID, root account, local Administrator, User Account Control (UAC), sudo, setuid, Linux capabilities, privilege escalation basics]
difficulty: basic
verified: true
last_verified: 2026-10-15
---

# Users, Groups and Privilege (SIDs, UIDs, UAC, sudo)
> **Created**: 2026-10-15T03:20:00Z
> **Last Modified**: 2026-10-15T03:20:00Z
> **Author**: RJGProjectz

**In one line:** the operating system knows accounts by number, not name — a SID on Windows, a UID on Linux — and "admin" is just membership in one group or holding UID 0.

## What it is

| | Windows | Linux |
| :--- | :--- | :--- |
| Account identifier | **SID**, e.g. `S-1-5-21-<domain>-1001`; never reused, even if the account is recreated with the same name | **UID** / **GID** numbers from `/etc/passwd`, `/etc/group` (or LDAP/SSSD); can be reused |
| Built-in admin | local **Administrator** (RID 500), the **Administrators** group `S-1-5-32-544`, `SYSTEM` (`S-1-5-18`) | **root** (UID 0); admins get it through `sudo` (groups `sudo` or `wheel`) |
| Where passwords live | SAM hive (local) or Active Directory `NTDS.dit` | `/etc/shadow` (hashes, readable only by root) |
| Fine-grained rights | **privileges** in the token (`SeDebugPrivilege`, `SeBackupPrivilege`, `SeImpersonatePrivilege`) and user rights assignment | **capabilities** (`CAP_NET_BIND_SERVICE`, `CAP_SYS_ADMIN`) per thread or per file |
| Elevation | **UAC**: admins run with a filtered token; consent or credential prompt starts a process with the full token | `sudo` runs one command as root (credentials cached per terminal, 5 minutes by default); setuid binaries run as their owner |

## How it works

```text
sign-in ──► LSA / PAM checks the password ──► token (SIDs + privileges) / process credentials (UID, GIDs)
                                                   │
                     ┌─────────────────────────────┴─────────────────────────────┐
     Windows admin in Admin Approval Mode:                      Linux admin:
     filtered token for Explorer and children                  normal UID for the shell
     "Run as administrator" ─► consent on the secure desktop   sudo ─► sudoers rule ─► command as UID 0
     ─► new process, full token, high integrity                (logged with the calling user)
```

Groups that are admin in practice even if not called so: Windows **Backup Operators** (read any file), **Hyper-V
Administrators**, anyone holding `SeDebugPrivilege`; Linux members of `docker`, `lxd` or `disk`, and any sudoers rule
that allows a shell, editor or interpreter.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1078.003](https://attack.mitre.org/techniques/T1078/003/) Local Accounts · [T1136](https://attack.mitre.org/techniques/T1136/) Create Account · [T1098](https://attack.mitre.org/techniques/T1098/) Account Manipulation · [T1548.002](https://attack.mitre.org/techniques/T1548/002/) Bypass User Account Control · [T1548.003](https://attack.mitre.org/techniques/T1548/003/) Sudo and Sudo Caching · [T1548.001](https://attack.mitre.org/techniques/T1548/001/) Setuid and Setgid · [T1069](https://attack.mitre.org/techniques/T1069/) Permission Groups Discovery |
| **What it leads to** | a new local admin as a backdoor, UAC bypass to high integrity without a prompt, root through a loose sudoers line |
| **Where defenders meet it** | "user added to Administrators" alert, an unknown account in `/etc/passwd` with UID 0, a sudoers change |

## Do it

```bash
cc find "local admin" ; cc view docs/tasks/assurance/linux-sudoers-integrity.md
```

```powershell
# Local users with SIDs, and who is in Administrators
Get-LocalUser | Select-Object -Property Name, Enabled, SID, LastLogon
Get-LocalGroupMember -Group 'Administrators'
# UAC on, and the admin prompt behaviour (2 = consent on secure desktop, 5 = consent for non-Windows binaries, the default)
Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' |
    Select-Object -Property EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop
```

```bash
# Every account with UID 0 (should be root only), admin group members, and my sudo rights
awk -F: '$3 == 0 { print $1 }' /etc/passwd
getent group sudo wheel
sudo -l
```

## See it

| Source | What you see |
| :--- | :--- |
| Security 4720 / 4732 / 4728 | user created / added to a local group / added to a domain global group |
| Security 4672 | special privileges assigned to a new logon (admin-equivalent sign-in) |
| Security 4688 `TokenElevationType` | `%%1937` elevated (Run as administrator), `%%1938` limited, `%%1936` full token (UAC off or built-in Administrator) |
| `/var/log/auth.log` or `/var/log/secure`, journald | `sudo: <user> : TTY=... ; USER=root ; COMMAND=...`, `useradd`, `usermod -aG` |
| auditd watch on `/etc/passwd`, `/etc/shadow`, `/etc/sudoers*` | who changed accounts or sudo rules |

## Detect it

- Commands: [Windows users and groups](../../platforms/windows/users-groups.md) · [Linux users and permissions](../../platforms/linux/users-permissions.md)
- Administer: [Local user and group management](../../tasks/administration/local-user-group-management.md) · [User lifecycle](../../tasks/administration/user-lifecycle-management.md)
- Assure and harden: [Linux sudoers integrity](../../tasks/assurance/linux-sudoers-integrity.md) · [Windows user rights assignment](../../tasks/hardening/windows-cis-user-rights-assignment.md) · [Linux CIS access, PAM and SSH](../../tasks/hardening/linux-cis-access-pam-ssh.md)
- Detection: [KQL logon and identity](../../detection/kql/logon-identity.md) · Respond: [Account compromise](../../tasks/incident-response/account-compromise.md)

## Related concepts

- [CIA triad and least privilege](cia-triad.md) · [Access control models](access-control-models.md) · [Identity and access management](identity-access-management.md) · [Processes, threads and handles](processes-threads.md)

## Sources

- Microsoft Learn: [Security identifiers](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers) · [How UAC works](https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/how-it-works) · [UAC settings and configuration](https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/settings-and-configuration) · [Event 4688](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688)
- man7.org: [credentials(7)](https://man7.org/linux/man-pages/man7/credentials.7.html) · [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html) · [sudoers(5)](https://man7.org/linux/man-pages/man5/sudoers.5.html) · [passwd(5)](https://man7.org/linux/man-pages/man5/passwd.5.html)

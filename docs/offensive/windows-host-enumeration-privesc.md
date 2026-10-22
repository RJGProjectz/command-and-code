---
title: Enumerate a Windows Host and Identify Privilege-Escalation Paths
type: workflow
platforms: [Windows]
languages: [PowerShell]
tasks: [Assessment]
category: Workflow
security_domain: Endpoint
author: RJGProjectz
date_created: 2026-10-21
last_updated: 2026-10-21
tags: [windows, privilege-escalation, privesc, enumeration, winpeas, seimpersonate, unquoted-service-path, service-misconfig, uac-bypass, credential-access, token-privileges, post-exploitation]
aliases: [windows privilege escalation, windows privesc, enumerate windows host, winpeas, seimpersonate privilege, potato attack, unquoted service path, weak service permissions, always install elevated, find credentials on windows, how to escalate on windows]
difficulty: intermediate
verified: false
---

# Enumerate a Windows Host and Identify Privilege-Escalation Paths
> **Created**: 2026-10-21T00:00:00Z
> **Last Modified**: 2026-10-21T00:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **AUTHORIZED TESTING ONLY — VALIDATE BEFORE EXECUTION**
> These commands assume you already have an authorized foothold (a shell) on the host.
> 1. Run **only** on a host you own or are explicitly authorized to test.
> 2. Enumeration is low-risk; **acting** on a finding (replacing a service binary, abusing a token)
>    changes the system and may require a reboot — stay inside scope and keep a log.
> 3. Several techniques touch EDR/AV detections; where detection is in scope, expect alerts.
> 4. Treat the output as sensitive — it exposes credentials and escalation routes.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Commands are written against documented behaviour (built-in Windows tooling, WinPEAS, PowerUp on
    supported Windows builds) but have not been lab-run for this page. Confirm cmdlets and paths on the
    target build. Remove this block when `verified: true`.

**Trigger:** you have a low-privilege shell on an authorized Windows host and need to find a path to
`SYSTEM`/local admin — or confirm there isn't one — and document the misconfiguration behind it.

**Goal:** work from host context → automated enumeration → the classic Windows vectors (token
privileges, service misconfigurations, registry/MSI policies) → credential hunting. This is
**identification**, not exploitation. The fixes live under
[Hardening → Windows CIS user rights](../tasks/hardening/windows-cis-user-rights-assignment.md) and
[Windows LAPS & admin tiering](../tasks/hardening/windows-laps-admin-tiering.md).

| Stage | Commands / tools | What you learn |
| :--- | :--- | :--- |
| Host context | `whoami /all`, `systeminfo` | Identity, privileges, patch level |
| Automated sweep | `winPEAS.exe`, PowerUp | Everything below, ranked |
| Token privileges | `whoami /priv` | `SeImpersonate`/`SeBackup` and similar high-value rights |
| Service misconfig | `sc`, PowerShell ACL checks | Weak service permissions, unquoted paths |
| Policy & credentials | registry, `cmdkey`, files | AlwaysInstallElevated, stored creds, autologon |

## 0. Host context (always first)

```powershell
whoami /all                         # user SID, group memberships, and privileges in one view
systeminfo                          # OS build and installed hotfixes -> map to missing patches
Get-LocalGroupMember -Group Administrators   # who is already local admin
```

`whoami /all` is the single most useful command: its **Privileges** section drives step 2, and group
membership (e.g. *Backup Operators*, *DnsAdmins*) can be an escalation on its own.

## 1. Automated enumeration (WinPEAS / PowerUp)

```powershell
# WinPEAS: broad, colour-ranked sweep of every vector below
.\winPEASx64.exe | Tee-Object -FilePath winpeas.txt

# PowerUp: focused privesc checks from PowerShell
powershell -ep bypass -c "Import-Module .\PowerUp.ps1; Invoke-AllChecks" | Tee-Object powerup.txt
```

Treat the ranked output as leads; confirm each manually below before reporting.

## 2. Token privileges

Certain privileges are effectively SYSTEM with the right technique:

```powershell
whoami /priv
```

| Privilege | Why it matters |
| :--- | :--- |
| `SeImpersonatePrivilege` | Service-account "Potato"-class escalation to SYSTEM |
| `SeAssignPrimaryToken` | Run a process under another token |
| `SeBackupPrivilege` | Read any file (SAM/SYSTEM hives) → offline credential extraction |
| `SeRestorePrivilege` | Write any file / registry key |
| `SeDebugPrivilege` | Open any process → inject or dump LSASS |

An **Enabled** entry here is the finding. The theory of what follows is in
[Credential Dumping](../fundamentals/concepts/credential-dumping.md).

## 3. Service misconfigurations

```powershell
# Unquoted service paths with spaces -> a planted binary earlier in the path runs as the service account
Get-CimInstance Win32_Service |
  Where-Object { $_.PathName -match '^[^"].*\s.*\.exe' -and $_.PathName -notmatch '^"' } |
  Select-Object Name, StartName, PathName

# Services whose binary or registry key a low-priv user can modify (PowerUp reports these as "AbuseFunction")
Get-CimInstance Win32_Service | Select-Object Name, StartName, State, StartMode
```

Also check **folder/file ACLs** on each service binary (`icacls "C:\Path\service.exe"`): a service that
runs as `LocalSystem` but whose binary is writable by `Users` or `Authenticated Users` is a direct
escalation. Record the service name, the account it runs as, and the weak ACL.

## 4. Policy and credential hunting

```powershell
# AlwaysInstallElevated: if BOTH keys are 1, any MSI installs as SYSTEM
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Stored credentials and autologon
cmdkey /list
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword 2>$null

# Credentials left in files, scripts and unattended-install answer files
Get-ChildItem C:\ -Recurse -Include *.config,*.xml,unattend.xml,*.ps1 -ErrorAction SilentlyContinue |
  Select-String -Pattern 'password|pwd|secret' -ErrorAction SilentlyContinue | Select-Object -First 50
```

A plaintext credential, a cached `cmdkey` entry, or both `AlwaysInstallElevated` keys set to `1` are
each reportable escalations in their own right.

## 5. Record findings

Keep `winpeas.txt`, `powerup.txt`, and the raw command output as evidence. For each path, write
**what** (the misconfig), **where** (the service/privilege/key), **evidence** (the output line),
**severity**, and **fix** — mapping to the CIS user-rights and service-hardening pages.

## Notes

- **`whoami /priv` first.** `SeImpersonate`/`SeBackup`/`SeDebug` are the fastest wins and need no
  software bug — check them before chasing missing patches.
- **EDR will see the loud steps.** WinPEAS, LSASS access, and token abuse are heavily monitored; where
  detection is in scope, expect the [Detection](../detection/index.md) queries to fire.
- **Unquoted paths need a writable directory.** The finding is only real if you can actually write to
  an earlier segment of the path — verify with `icacls` before reporting it as exploitable.
- Install notes: `winPEAS` and `PowerUp.ps1` are staged in-scope; `whoami`, `sc`, `reg`, `cmdkey`, and
  the PowerShell cmdlets are all built in.

## Related

- [Offensive — Overview](index.md)
- [Active Directory enumeration](active-directory-enumeration.md)
- [Network & infrastructure enumeration](network-infrastructure-enumeration.md)
- Reference: [Windows services](../platforms/windows/services.md) · [Scheduled tasks](../platforms/windows/scheduled-tasks.md) · [Windows registry](../platforms/windows/registry.md) · [Users & groups](../platforms/windows/users-groups.md)
- Defensive counterparts: [Windows CIS user rights assignment](../tasks/hardening/windows-cis-user-rights-assignment.md) · [Windows CIS attack surface reduction](../tasks/hardening/windows-cis-attack-surface-reduction.md) · [Windows LAPS & admin tiering](../tasks/hardening/windows-laps-admin-tiering.md)

## External Resources & White Papers

- [PEASS-ng / WinPEAS](https://github.com/peass-ng/PEASS-ng) — Windows privilege-escalation enumeration
- [PowerSploit / PowerUp](https://github.com/PowerShellMafia/PowerSploit) — `Invoke-AllChecks`
- [LOLBAS](https://lolbas-project.github.io/) — living-off-the-land Windows binaries
- [MITRE ATT&CK — Privilege Escalation (TA0004)](https://attack.mitre.org/tactics/TA0004/) and [Access Token Manipulation (T1134)](https://attack.mitre.org/techniques/T1134/)

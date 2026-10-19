---
title: Service Account Audit (Windows, Active Directory, Linux)
type: tool
platforms:
  - Windows
  - Windows Server
  - Active Directory
  - Linux
languages:
  - PowerShell
  - Bash
tasks:
  - Assurance
  - Hardening
  - Administration
verified: true
last_verified: 2026-10-18
difficulty: intermediate
category: Identity
tags:
  - service accounts
  - kerberoasting
  - gmsa
  - spn
  - sudoers
  - systemd
  - ndjson
aliases: [audit service accounts, service account inventory, find kerberoastable accounts, accounts with spn, stale service account passwords, service account in domain admins, adminCount service account, scheduled task stored password, which services run as a user account, gMSA password retrievers, system account with login shell, sudo nopasswd audit, systemd unit user audit, credstore permissions, FUNC_PS_AUDIT_SERVICE_ACCOUNT, FUNC_BASH_AUDIT_SERVICE_ACCOUNT]
---

# Service Account Audit (Windows, Active Directory, Linux)

*"Which services still run as a domain user?"* *"Is any service account in Domain Admins?"* *"Which system
accounts can still log in?"* Two read-only scripts answer these and write one NDJSON event per finding, ready for
Splunk or any SIEM:

| Script | Covers |
| --- | --- |
| `scripts/powershell/FUNC_PS_AUDIT_SERVICE_ACCOUNT.ps1` | Windows services and scheduled tasks on the host, plus gMSA/MSA, SPN users, password age and privileged groups in Active Directory |
| `scripts/bash/FUNC_BASH_AUDIT_SERVICE_ACCOUNT.sh` | Linux system accounts, shadow passwords, sudoers grants, systemd unit identities and credential stores |

Both scripts change nothing on the host or in the directory. They are the review step for
[Windows service accounts with least privilege](../administration/windows-service-accounts-least-privilege.md),
[Linux service accounts with least privilege](../administration/linux-service-accounts-least-privilege.md) and the
secret storage pages for [Windows](../administration/windows-service-secrets-storage.md) and
[Linux](../administration/linux-service-secrets-storage.md).

!!! warning "Before you run anything"
    The scripts only read, but they read sensitive data: LSA user rights, the AD group memberships of service
    accounts, `/etc/shadow` and sudoers. Run them from an admin workstation or the host itself, keep the NDJSON
    output with the same care as other audit evidence, and test against a lab host or the fixtures first. The
    checks are compared with Microsoft Learn and the Linux man pages listed under Sources; they have not been run
    against a live domain or production host.

## Why audit service accounts

A service account with a typed password is the most common way from one foothold to the whole domain:

- **Kerberoasting** ([T1558.003](https://attack.mitre.org/techniques/T1558/003/)): any domain user can ask for a
  service ticket for an account that has a servicePrincipalName (SPN) and crack its password offline. User accounts
  with SPNs and old, human-chosen passwords crack fast. gMSAs use a long random password that AD generates and
  rotates, so they do not have this problem.
- **Valid accounts** ([T1078.002](https://attack.mitre.org/techniques/T1078/002/),
  [T1078.003](https://attack.mitre.org/techniques/T1078/003/)): the password of a service that runs as a named user
  is stored in LSA secrets on every host that runs it; an administrator on that host can read it. When the account
  is in Domain Admins, or may log on interactively or by RDP, one host becomes many.
- **sudo** ([T1548.003](https://attack.mitre.org/techniques/T1548/003/)): a `NOPASSWD: ALL` rule for a service
  account means that anyone who runs code as that service is root.
- **Secrets in files** ([T1552.001](https://attack.mitre.org/techniques/T1552/001/)): a world-readable file in a
  systemd credential store gives the secret to every local user.

## Windows and Active Directory checks

| Check | Severity | Flags | Fix |
| --- | --- | --- | --- |
| `SA-SERVICE-INVENTORY` | info | Every service from `Win32_Service` with its `StartName` and identity type: LocalSystem, LocalService, NetworkService, virtual account (`NT SERVICE\...`), managed account (`...$`) or named user | — |
| `SA-TYPED-PASSWORD` | medium | Service runs as a named user, so its password is typed in and stored | Move it to a gMSA or a virtual account ([how](../administration/windows-service-accounts-least-privilege.md)) |
| `SA-TASK-NAMED-USER` | medium / low | Scheduled task runs as a named user. `Password` and `InteractiveOrPassword` logon types store the password (medium); `S4U` does not (low); group tasks are skipped | Run it as a gMSA or `NT AUTHORITY\SYSTEM` with a narrow action, or S4U |
| `SA-SPN-USER` | high / medium | User account (not a computer, gMSA or `krbtgt`) with an SPN: Kerberoasting candidate. High when it is also privileged or its password is stale | Move the SPN to a gMSA; until then a 25+ character random password and AES-only encryption ([Kerberos hardening](../hardening/ad-kerberos-ldap-hardening.md)) |
| `SA-STALE-PASSWORD` | medium | Password of a service user older than `-StalePasswordDays` (default 365), or never set; `PasswordNeverExpires` is in the details | Rotate it ([rotate a service logon password](../administration/windows-service-secrets-storage.md)) |
| `SA-PRIVILEGED` | high | `adminCount=1`, a protected group in the account's `tokenGroups` (Domain/Enterprise/Schema Admins, Administrators, Account/Server/Print/Backup Operators, Key Admins, DCs), or member of the host's local Administrators | Remove the membership; grant only the rights the service needs |
| `SA-INTERACTIVE-ALLOWED` | medium | Service user used on this host that is not in both *Deny log on locally* and *Deny log on through Remote Desktop Services* (`secedit /export /areas USER_RIGHTS`) | Add it to both deny rights ([logon rights](../administration/windows-service-accounts-least-privilege.md)) |
| `SA-GMSA-RETRIEVERS` | high / info | gMSA whose `PrincipalsAllowedToRetrieveManagedPassword` includes Domain Computers, Domain Users, Authenticated Users or Everyone (high); otherwise lists the retrievers (info) | `Set-ADServiceAccount -PrincipalsAllowedToRetrieveManagedPassword` with a group of only the hosts that run it |
| `SA-ACCOUNT-NOT-FOUND` | NeedsReview | Identity used by a service or task that is not in AD or the local accounts | Deleted account, another domain, or a collection gap: check by hand |
| `SA-COLLECTION` | NeedsReview | A collection step failed (not elevated, no RSAT, no Global Catalog for `tokenGroups`) | Rerun elevated with the ActiveDirectory module |

`adminCount=1` stays set after an account leaves a protected group, so `SA-PRIVILEGED` can also point at a past
membership: check `privileged_groups` in the details, then clear the stale flag if the account is no longer
privileged.

### Run it

```powershell
# Dry run: shows each collection step and reads nothing
.\scripts\powershell\FUNC_PS_AUDIT_SERVICE_ACCOUNT.ps1 -WhatIf

# Elevated, with RSAT ActiveDirectory: audit this host and AD, show only what needs action
.\scripts\powershell\FUNC_PS_AUDIT_SERVICE_ACCOUNT.ps1 |
    Where-Object result -ne 'Info' |
    Sort-Object severity, check | Format-Table check, severity, account, message -Wrap

# Standalone or workgroup host: local identities only
.\scripts\powershell\FUNC_PS_AUDIT_SERVICE_ACCOUNT.ps1 -SkipActiveDirectory

# Collect on one host, analyse later (or diff two snapshots after a change)
.\scripts\powershell\FUNC_PS_AUDIT_SERVICE_ACCOUNT.ps1 -ExportSnapshotPath .\app01-snapshot.json
.\scripts\powershell\FUNC_PS_AUDIT_SERVICE_ACCOUNT.ps1 -InputPath .\app01-snapshot.json -StalePasswordDays 180
```

The AD part reads every gMSA/MSA (`Get-ADServiceAccount -Filter *`), every user with an SPN
(`Get-ADUser -Filter 'servicePrincipalName -like "*"'`) and the named accounts this host's services and tasks use.
It reads `tokenGroups` only for those accounts, because `tokenGroups` is a constructed attribute that needs one
base-scope query per object and is expensive on domain controllers. Run the script on each server that hosts
services (or collect snapshots there); the AD findings repeat on every run, the host findings do not.

## Linux checks

| Check | Severity | Flags | Fix |
| --- | --- | --- | --- |
| `SA-UID0-DUPLICATE` | high | An account other than `root` with UID 0 | Remove it or give it its own UID; investigate how it got there |
| `SA-SYSTEM-SHELL` | medium | System-range account (UID below `UID_MIN` from `/etc/login.defs`, or 65534) with a real login shell; `nologin`, `false`, `sync`, `shutdown` and `halt` do not count | `usermod -s /usr/sbin/nologin <account>` |
| `SA-EMPTY-PASSWORD` | high | Any account with an empty password field in `/etc/shadow` | `passwd -l <account>` |
| `SA-SYSTEM-PASSWORD` | high / medium | System-range account with a usable hash (field does not start with `!` or `*`); high when it also has a login shell | `passwd -l <account>` |
| `SA-SUDO-NOPASSWD` | high / medium | sudoers rule with `NOPASSWD` or `!authenticate`; high when the rule grants `ALL` commands | Exact commands only, with a password ([sudo: exact commands only](../administration/linux-service-accounts-least-privilege.md)) |
| `SA-SUDO-ALL` | medium / low | Rule that grants every command (`ALL`) to anyone but `root`; low for `%sudo`, `%wheel`, `%admin` | Review the group members; replace with command lists |
| `SA-UNIT-ROOT` | low / info | systemd `.service` with no `User=` (runs as root). Low for units under `/etc/systemd/system` (added locally), info for vendor units | `User=` with its own account, or `DynamicUser=yes` |
| `SA-UNIT-USER` | info | Unit with `User=` or `DynamicUser=yes` (inventory), after drop-ins in `<unit>.service.d/*.conf` | — |
| `SA-UNIT-USER-SHELL` | medium | The `User=` account of a unit has a real login shell | `usermod -s /usr/sbin/nologin <account>` |
| `SA-CREDSTORE-READABLE` | high / medium | World-readable file in `/etc`, `/run` or `/usr/lib` `credstore` (high) or `credstore.encrypted` (medium) | `chmod 0600` (root-owned); see [systemd credentials](../administration/linux-service-secrets-storage.md) |
| `SA-COLLECTION` | NeedsReview | `/etc/passwd`, `/etc/shadow` or a sudoers file could not be read | Rerun as root |

The sudoers parser follows `sudoers(5)`: it reads `/etc/sudoers` and `/etc/sudoers.d/*`, joins lines that end in a
backslash, and skips files in `sudoers.d` whose names end in `~` or contain a `.`, as sudo does. It reports each
rule; it does not expand aliases. Run `visudo -c` and the [sudoers integrity check](linux-sudoers-integrity.md)
for syntax and file permissions.

The unit scan reads unit files from `/usr/lib`, `/lib`, `/run` and `/etc/systemd/system` in that order (a file
with the same name in a later directory replaces the earlier one), skips units masked to `/dev/null`, and applies
`User=` and `DynamicUser=` from drop-ins. On a running host, compare with what systemd itself resolved:
`systemctl show -p User,DynamicUser --value <unit>`.

### Run it

```bash
# Dry run: lists the sources and reads nothing
sudo ./scripts/bash/FUNC_BASH_AUDIT_SERVICE_ACCOUNT.sh --whatif

# Audit this host; show only what needs action (jq optional)
sudo ./scripts/bash/FUNC_BASH_AUDIT_SERVICE_ACCOUNT.sh > service-accounts.ndjson
jq -c 'select(.result != "Info") | {check, severity, account, message}' service-accounts.ndjson

# Audit a mounted disk image or another root, with a non-default UID_MIN
./scripts/bash/FUNC_BASH_AUDIT_SERVICE_ACCOUNT.sh --root /mnt/image --uid-min 500 > image.ndjson
```

Without root, `/etc/shadow` and most of `/etc/sudoers.d` are unreadable; those checks come back as `SA-COLLECTION`
NeedsReview instead of a false "clean".

## Output

Each finding is one NDJSON line with the project's NDJSON logging fields
(`timestamp`, `host`, `tool`, `version`, `execution_id`) plus `environment`, `level`, `action` (`audit` for
findings, `log` for run messages), `check`, `severity`, `result` (`Finding`, `Info` or `NeedsReview`), `target`,
`account`, `message` and `details`. Both scripts use the same schema:

```json
{"timestamp":"2026-10-18T23:00:00Z","host":"APP01","tool":"FUNC_PS_AUDIT_SERVICE_ACCOUNT","version":"1.0","execution_id":"6f1c2b9e-0d4a-4c1e-9a43-2f6d8b7e5a10","environment":"Test","level":"WARN","action":"audit","check":"SA-SPN-USER","severity":"high","result":"Finding","target":"svc-report","account":"svc-report","message":"User account 'svc-report' has 1 SPN(s): any domain user can request a ticket and crack it offline (Kerberoasting).","details":{"spns":["MSSQLSvc/sql01.example.test:1433"],"password_age_days":2771,"privileged":true}}
```

The PowerShell script returns the same findings as objects and appends them to
`Logs\FUNC_PS_AUDIT_SERVICE_ACCOUNT.ndjson` beside the script (`-LogPath` to change it). The Bash script prints
findings on stdout and writes its run log to `Logs/` (`--log-dir`). In Splunk, index the files with
`sourcetype=_json` (or a custom JSON sourcetype) and summarise:

```spl
index=assurance tool IN ("FUNC_PS_AUDIT_SERVICE_ACCOUNT", "FUNC_BASH_AUDIT_SERVICE_ACCOUNT") action=audit result!=Info earliest=-7d
| stats latest(severity) AS severity latest(message) AS message dc(host) AS hosts BY check account
| sort - severity check
```

Run the scripts weekly or after every service deployment, and compare `execution_id` runs to see what changed.
Alert on new `high` findings; the account-change and logon events that show abuse are in
[suspicious service investigation](../investigation/suspicious-service.md) and
[Kerberoasting](../../fundamentals/concepts/kerberoasting.md).

## Test without a domain or a Linux host

The test fixtures are synthetic: `tests/powershell/fixtures/serviceaccount/snapshot-sample.json` (a host snapshot
with a stale, privileged SPN user, a gMSA with domain-wide retrievers and a local admin service account) and
`tests/python/fixtures/service_account_linux/` (a small `/etc` and `/usr/lib/systemd` tree). The Pester suite
`tests/powershell/FUNC_PS_AUDIT_SERVICE_ACCOUNT.Tests.ps1` and the pytest module
`tests/python/test_service_account_audit_linux.py` run both scripts against them in CI.

## Related

- [Credential rotation after a compromise](../incident-response/credential-rotation-after-compromise.md): uses this audit as the dependency check before each rotation
- [Windows service accounts with least privilege](../administration/windows-service-accounts-least-privilege.md) · [Linux service accounts with least privilege](../administration/linux-service-accounts-least-privilege.md)
- [Windows service secrets](../administration/windows-service-secrets-storage.md) · [Linux service secrets](../administration/linux-service-secrets-storage.md)
- [AD Kerberos & LDAP hardening (gMSA rollout)](../hardening/ad-kerberos-ldap-hardening.md) · [Kerberoasting](../../fundamentals/concepts/kerberoasting.md)
- [Linux sudoers integrity](linux-sudoers-integrity.md) · [User Rights Assignment (CIS)](../hardening/windows-cis-user-rights-assignment.md)

## Sources

- Microsoft Learn — [Win32_Service class](https://learn.microsoft.com/windows/win32/cimwin32prov/win32-service) (`StartName`) · [Get-ScheduledTask](https://learn.microsoft.com/powershell/module/scheduledtasks/get-scheduledtask) · [New-ScheduledTaskPrincipal](https://learn.microsoft.com/powershell/module/scheduledtasks/new-scheduledtaskprincipal) (LogonType values) · [Principal.LogonType](https://learn.microsoft.com/windows/win32/taskschd/principal-logontype)
- Microsoft Learn — [Get-ADServiceAccount](https://learn.microsoft.com/powershell/module/activedirectory/get-adserviceaccount) · [Get-ADUser](https://learn.microsoft.com/powershell/module/activedirectory/get-aduser) · [Get-ADObject](https://learn.microsoft.com/powershell/module/activedirectory/get-adobject) · [Token-Groups attribute](https://learn.microsoft.com/windows/win32/adschema/a-tokengroups) (constructed, base-scope, Global Catalog needed)
- Microsoft Learn — [Appendix C: Protected accounts and groups in Active Directory](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory) (adminCount, SDProp) · [Well-known SIDs](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers)
- Microsoft Learn — [Group Managed Service Accounts overview](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview) · [secedit /export](https://learn.microsoft.com/windows-server/administration/windows-commands/secedit-export) · [Deny log on locally](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/deny-log-on-locally) · [Get-LocalGroupMember](https://learn.microsoft.com/powershell/module/microsoft.powershell.localaccounts/get-localgroupmember)
- Linux man pages — [shadow(5)](https://man7.org/linux/man-pages/man5/shadow.5.html) · [login.defs(5)](https://man7.org/linux/man-pages/man5/login.defs.5.html) · [sudoers(5)](https://www.sudo.ws/docs/man/sudoers.man/) (includedir file-name rule, line continuation, NOPASSWD, authenticate) · [systemd.exec(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html) (User=, DynamicUser=, LoadCredential= credstore paths) · [systemd.unit(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) (unit search path, drop-ins, masking)
- MITRE ATT&CK — [T1558.003](https://attack.mitre.org/techniques/T1558/003/) · [T1078.002](https://attack.mitre.org/techniques/T1078/002/) · [T1078.003](https://attack.mitre.org/techniques/T1078/003/) · [T1548.003](https://attack.mitre.org/techniques/T1548/003/) · [T1552.001](https://attack.mitre.org/techniques/T1552/001/)

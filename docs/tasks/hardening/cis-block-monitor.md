---
title: CIS Block Monitor (Windows and Linux)
type: tool
platforms:
  - Windows
  - Linux
languages:
  - PowerShell
  - Bash
tasks:
  - Hardening
  - Detection Engineering
  - Assurance
verified: true
last_verified: 2026-10-19
difficulty: intermediate
tags:
  - cis-benchmark
  - applocker
  - app-control
  - asr
  - selinux
  - apparmor
  - fapolicyd
  - ndjson
aliases: [cis block monitor, blocked executions, applocker 8004, wdac 3077, code integrity block, asr 1121, controlled folder access 1123, msiinstaller 1008, selinux avc denied, apparmor denied, noexec tmp blocked, fapolicyd deny, FUNC_PS_GET_CIS_BLOCK_EVENTS, FUNC_BASH_GET_CIS_BLOCK_EVENTS]
---

# CIS Block Monitor (Windows and Linux)

Two read-only scripts report what the hardening **actually stopped**: every program, script, installer
or file access that a control blocked (or, in audit mode, would have blocked), with the control, the path,
the process, the user and, where one exists, the CIS recommendation that put the control in place. Use it
after a CIS rollout ([Windows 11](windows-11-cis-audit-tool.md), [Windows Server](windows-server-cis-audit-tool.md),
[Linux](linux-cis-audit-tool.md)) to tell a needed allow-list entry from an attack.

| Script | Reads | Output |
| :--- | :--- | :--- |
| `scripts/powershell/FUNC_PS_GET_CIS_BLOCK_EVENTS.ps1` | AppLocker, App Control (Code Integrity), Defender ASR and Controlled folder access, MsiInstaller events | Objects + NDJSON (`<LogPath>\FUNC_PS_GET_CIS_BLOCK_EVENTS.ndjson`) |
| `scripts/bash/FUNC_BASH_GET_CIS_BLOCK_EVENTS.sh` | `audit.log` (SELinux AVC, AppArmor, execve EACCES, fapolicyd FANOTIFY), syslog/journal (fapolicyd, kernel AppArmor/AVC) | NDJSON on stdout |

!!! warning "Before you run anything"
    Both scripts only read logs. They need admin / root to read the Security-relevant channels and
    `/var/log/audit/audit.log`; without it they report nothing for those sources rather than failing.
    Nothing is changed in `Test` or `Prod`.

## What it reports

### Windows

| Control | Event log | Blocked | Audit mode (would block) | CIS mapping |
| :--- | :--- | :--- | :--- | :--- |
| AppLocker EXE/DLL | `Microsoft-Windows-AppLocker/EXE and DLL` | 8004 | 8003 | none (organization policy) |
| AppLocker MSI/script | `Microsoft-Windows-AppLocker/MSI and Script` | 8007 | 8006 | none |
| AppLocker packaged apps | `.../Packaged app-Execution`, `.../Packaged app-Deployment` | 8022, 8025 | 8021, 8024 | none |
| App Control for Business (WDAC) | `Microsoft-Windows-CodeIntegrity/Operational` | 3077, 3033 | 3076, 3034 | none |
| App Control script enforcement | `Microsoft-Windows-AppLocker/MSI and Script` | 8029, 8036, 8040 | 8028, 8039 | none |
| Defender ASR rules | `Microsoft-Windows-Windows Defender/Operational` | 1121 | 1122 (1129 = user override) | "Configure Attack Surface Reduction rules", found by title in the catalog |
| Controlled folder access | same | 1123, 1127 | 1124, 1128 | none |
| Windows Installer | `Application`, provider `MsiInstaller` | 1007, 1008, 1044 | — | none (software restriction / AppLocker policy) |

The ASR rule GUID in event 1121/1122 is translated to the rule name. **UAC** "Automatically deny elevation
requests" writes no documented event, so denied elevations cannot be read from the log.

### Linux

| Control | Record | Result | CIS mapping (`--profile`) |
| :--- | :--- | :--- | :--- |
| SELinux | `type=AVC ... avc: denied { ... }` | `permissive=0` Blocked, `permissive=1` Audited | RHEL 9: 1.3.1.5 enforcing (Blocked), 1.3.1.4 not disabled (Audited) |
| AppArmor | `apparmor="DENIED"` / `apparmor="ALLOWED"` (complain mode) | Blocked / Audited | Ubuntu 24.04: 1.3.1.3 profiles in enforce or complain mode |
| `noexec` mounts | execve `SYSCALL` with `exit=-13` + its `PATH` record under `/tmp`, `/dev/shm`, `/var/tmp` | Blocked | 1.1.2.1.4, 1.1.2.2.4, 1.1.2.5.4 |
| fapolicyd | `type=FANOTIFY ... resp=2` (rule decision `deny_audit`) + `SYSCALL`/`PATH`; syslog `rule=N dec=deny_*` lines (`deny_syslog`, or `deny_log` with `syslog_format`) | Blocked | none (not in the CIS server profiles) |

Kernel AppArmor and AVC lines in a syslog file (`kern.log`, `/var/log/messages`) are read too, for hosts
where auditd is not running.

The `noexec` case needs an audit rule, because a failed execve is not logged by default
(`audit.rules(7)`):

```bash
# /etc/audit/rules.d/60-cis-exec-denied.rules
-a always,exit -F arch=b64 -S execve -F exit=-EACCES -k cis_exec_denied
-a always,exit -F arch=b32 -S execve -F exit=-EACCES -k cis_exec_denied
```

Load it with `sudo augenrules --load`. `EACCES` also means plain file permissions, so the event detail says
"noexec mount or permission"; only paths under the three temporary mounts are reported.

## Run it

```powershell
# Last 72 hours, blocks only
.\scripts\powershell\FUNC_PS_GET_CIS_BLOCK_EVENTS.ps1 -Hours 72 | Format-Table event_time, control, path, rule, cis_id

# Include audit-mode events, map ASR to a locally built catalog
.\scripts\powershell\FUNC_PS_GET_CIS_BLOCK_EVENTS.ps1 -IncludeAudit -CatalogPath .\scripts\cis\catalogs\windows11-enterprise-v5.1.0.json

# Dry run: which logs and event IDs would be read
.\scripts\powershell\FUNC_PS_GET_CIS_BLOCK_EVENTS.ps1 -IncludeAudit -WhatIf

# Offline: events exported from another host as <Events><Event>...</Event></Events>
.\scripts\powershell\FUNC_PS_GET_CIS_BLOCK_EVENTS.ps1 -InputPath .\evidence\blocks.xml -IncludeAudit
```

```bash
# Live host, profile from /etc/os-release
sudo ./scripts/bash/FUNC_BASH_GET_CIS_BLOCK_EVENTS.sh --include-audit | jq -c '{control, result, path, cis_id}'

# Offline: copied logs from a RHEL 9 host
./scripts/bash/FUNC_BASH_GET_CIS_BLOCK_EVENTS.sh --audit-log ./audit.log --syslog ./messages --profile rhel9 > blocks.ndjson
```

To export events for `-InputPath`, wrap the `ToXml()` output of `Get-WinEvent` in an `<Events>` element.

## Read the results

Each block is one NDJSON line with the GOLDEN_STANDARDS §4.7 fields (`timestamp`, `host`, `tool`,
`version`, `execution_id`, `level`, `action` = `cis.block`, `result`, `environment`) plus:

| Field | Meaning |
| :--- | :--- |
| `control` | `AppLocker`, `AppControl`, `ASR`, `ControlledFolderAccess`, `WindowsInstaller`, `selinux`, `apparmor`, `noexec`, `fapolicyd` |
| `result` | `Blocked`, `Audited` (audit mode, only with `-IncludeAudit` / `--include-audit`), `UserOverride` (ASR 1129) |
| `event_time` | Time of the original event (UTC) |
| `path`, `process`, `user` | Blocked file, the process that tried, the user (SID, `DOMAIN\user` or audit `auid`) |
| `rule` (Windows) / `detail` (Linux) | Policy or ASR rule name; SELinux contexts and class, AppArmor profile and mask, fapolicyd rule number and trust |
| `cis_id`, `cis_title` | The CIS recommendation, empty when the control has none |

`level` is `WARN` for blocks and `INFO` for audit-mode events, so a SIEM rule can alert on `WARN` only.

Triage:

1. **Same path, many users, signed vendor binary** → allow-list it (AppLocker publisher rule, App Control
   supplemental policy, ASR exclusion, fapolicyd trust entry, SELinux boolean or file context).
2. **Path under a user profile, `Downloads`, `Temp`, `/tmp`, `/dev/shm`** → treat as payload delivery
   until proven otherwise ([T1204.002](https://attack.mitre.org/techniques/T1204/002/)); collect the file
   and the parent process.
3. **Office or script host as `process`** (ASR "Office child process", `wscript.exe`, `mshta.exe`) →
   phishing chain; check mail and proxy logs for the same user.
4. **Audit-mode events** before enforcement: every distinct path is a rule you need, or a block users will
   hit on enforcement day.

## Tests

- `tests/powershell/CisBlockEvents.Tests.ps1` (Pester 5) runs the Windows script with `-InputPath` on
  synthetic exported events (`tests/powershell/fixtures/cisblock/`): blocks vs audit mode, provider check
  for MsiInstaller IDs, AppLocker `UserData`, Code Integrity `EventData`, ASR GUID → rule name, CIS lookup
  by title in a fixture catalog, NDJSON fields, and a run without a catalog.
- `tests/python/test_cis_block_events_linux.py` runs the Bash script on a synthetic `audit.log` and syslog
  file (`tests/python/fixtures/cis_block_linux/`): SELinux enforcing vs permissive, AppArmor from
  `audit.log` and from a kernel line, execve EACCES paired with its `PATH` record (inside and outside the
  temporary mounts), fapolicyd `deny_audit` and `deny_syslog`, profile-specific CIS IDs, `--whatif`.

## Limits

- Doc-checked against Microsoft Learn and the man pages; not yet run on a live host. Event data field
  names vary between Windows builds: an empty `path` or `user` means the field had another name.
- A relative path passed to execve (`./x` from `/tmp`) is reported only when the `PATH` record holds the
  absolute name; the `CWD` record is not joined.
- fapolicyd syslog lines carry no time stamp of their own in the parsed fields, so `event_time` is empty
  for them; use the syslog line time.
- The shipped Windows catalog (v5.1.0 build) has no ASR recommendation, so `cis_id` stays empty for ASR
  until a catalog with it is built.

## Related

- [AppLocker phased rollout](applocker-deployment-rollout.md)
- [Windows CIS ASR & Credential Guard](windows-cis-attack-surface-reduction.md)
- [Linux CIS filesystems & services](linux-cis-filesystem-services.md) (noexec mounts)
- [Linux CIS auditd & telemetry baseline](linux-cis-auditd-logging.md)
- [Linux CIS audit tool](linux-cis-audit-tool.md)

## Sources

- [Using Event Viewer with AppLocker](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker)
- [App Control for Business event IDs](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations)
- [ASR rules: view events](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-windows-events)
- [ASR rules reference (GUIDs)](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference)
- [Windows Installer event logging](https://learn.microsoft.com/windows/win32/msi/event-logging)
- [audit.rules(7)](https://man7.org/linux/man-pages/man7/audit.rules.7.html), [ausearch(8)](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [fapolicyd.rules(5)](https://github.com/linux-application-whitelisting/fapolicyd/blob/main/doc/fapolicyd.rules.5), [fapolicyd.conf(5)](https://github.com/linux-application-whitelisting/fapolicyd/blob/main/doc/fapolicyd.conf.5)
- [apparmor(7)](https://manpages.ubuntu.com/manpages/noble/man7/apparmor.7.html)

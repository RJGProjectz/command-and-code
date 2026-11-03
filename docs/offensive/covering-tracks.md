---
title: Covering Tracks — Evidence Removal in Authorized Penetration Tests
type: workflow
platforms: [Windows, Linux]
languages: [PowerShell, Bash, Windows CLI]
tasks: [Assessment]
category: Workflow
security_domain: Endpoint
author: RJGProjectz
date_created: 2026-11-03
last_updated: 2026-11-03
tags: [covering-tracks, anti-forensics, log-clearing, event-logs, bash-history, wevtutil, timestomping, indicator-removal, T1070, post-exploitation, clean-up, penetration-testing]
aliases: [anti-forensics, evidence removal, log clearing, indicator removal, clean up after pentest, clearing logs, post-exploitation cleanup]
difficulty: advanced
verified: false
---

# Covering Tracks — Evidence Removal in Authorized Penetration Tests
> **Created**: 2026-11-03T00:00:00Z
> **Last Modified**: 2026-11-03T00:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **AUTHORIZED TESTING ONLY — ENGAGE SCOPE AND LEGAL REVIEW BEFORE PROCEEDING**
> Removing host evidence is irreversible. Before any clean-up step:
> 1. **Confirm written authorization** explicitly covers evidence removal and log clearing for each target system.
> 2. **Verify legal and ethical boundaries** — log data may belong to operational audit requirements; deleting it without explicit approval can constitute evidence tampering.
> 3. **Coordinate with the blue team** in purple-team exercises; defenders need a record to validate detection gaps. Unannounced log clearing defeats the purpose.
> 4. **Document everything you remove** in the engagement log before deleting it — clearing logs you have not recorded is a gap in your own engagement evidence.
> 5. For production systems, obtain a **change-control record** with rollback approval before any action.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Commands reference documented tool syntax but have not been lab-executed for this page. Exact flags and behavior vary by OS version and tool release — validate against `--help`, man pages, or vendor docs before running on any target. Remove this block when `verified: true`.

**Trigger:** you have completed your authorized penetration test objectives and the rules of engagement require you to restore systems to their pre-test state and remove indicators left by your tooling.

**Goal:** remove artifacts that a defender would use to trace the simulated attack path, then document what was removed in the engagement report.

---

## 1. Understand what "tracks" means

Every action on a host produces evidence across four artifact families:

| Artifact family | Examples |
| :--- | :--- |
| **Event logs** | Windows Security/System/Application logs; Sysmon; PowerShell script-block logs |
| **Shell history** | `~/.bash_history`, `~/.zsh_history`, PowerShell `$PROFILE` history |
| **Filesystem traces** | Uploaded payloads, downloaded tools, staging directories, prefetch, LNK/jump lists |
| **Registry and caches** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`; MRU keys; browser caches |

Real threat actors prioritize event logs and shell history because those are what incident responders reach for first. A thorough clean-up touches all four families in the order above, working from most-visible to least-visible.

---

## 2. Windows event log clearing

> [!CAUTION]
> Clearing the Security log generates **Event ID 1102** ("The audit log was cleared") and clearing other logs generates **Event ID 104**. Both are high-fidelity detection signals. In many organizations Event ID 1102 pages on-call immediately. Clearing logs does not make you invisible — it makes you more suspicious. In authorized tests, coordinate timing with the blue team.

Clear a single log channel by name:

```powershell
# List all log names
wevtutil el

# Clear a specific log (requires elevated privileges)
wevtutil cl Security
wevtutil cl System
wevtutil cl Application
wevtutil cl "Microsoft-Windows-PowerShell/Operational"
```

Using the PowerShell cmdlet (requires admin, Windows 7+):

```powershell
# Clear named event logs
Clear-EventLog -LogName Security, System, Application
```

To clear all event logs in a single sweep:

```powershell
# Enumerate and clear every registered log channel
Get-WinEvent -ListLog * | Where-Object {$_.RecordCount -gt 0} | ForEach-Object {
    wevtutil cl $_.LogName 2>$null
}
```

---

## 3. Windows filesystem and registry cleanup

Remove uploaded tools and payloads from staging paths:

```powershell
# Remove staged payloads — replace with your actual staging path
Remove-Item -Path "C:\Users\Public\Downloads\tool.exe" -Force
Remove-Item -Path "$env:TEMP\*.ps1" -Force

# Clear PowerShell command history
$historyPath = (Get-PSReadLineOption).HistorySavePath
if ($historyPath -and (Test-Path $historyPath)) {
    Clear-Content -Path $historyPath
}
Clear-History
```

Windows tracks recently accessed files via jump lists and MRU registry keys:

```powershell
# Clear Recent Items jump list folder (user-accessible)
Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\*" -Force -ErrorAction SilentlyContinue

# Clear specific MRU registry key (example: Run dialog history)
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name * -Force -ErrorAction SilentlyContinue
```

Prefetch files record every executable that has run:

```powershell
# Prefetch clearing requires SYSTEM and is not available on all editions
# Verify you are authorized before touching %SystemRoot%\Prefetch
Remove-Item "$env:SystemRoot\Prefetch\TOOL.EXE-*.pf" -Force -ErrorAction SilentlyContinue
```

---

## 4. Linux log and history cleanup

Remove Bash command history:

```bash
# Clear in-memory history
history -c
history -w

# Overwrite and remove the history file
shred -u ~/.bash_history 2>/dev/null || rm -f ~/.bash_history
unset HISTFILE
export HISTSIZE=0
```

On Linux, PowerShell history can also be cleared when PowerShell is present:

```powershell
# PowerShell on Linux — clear history in the current session
Clear-History
```

Remove uploaded tools and temporary working directories:

```bash
# Remove a staging directory securely
shred -uzn 3 /tmp/staging/* 2>/dev/null
rm -rf /tmp/staging/

# Remove any installed backdoors or SSH keys added during the test
sed -i "/your_key_comment/d" ~/.ssh/authorized_keys
```

Syslog-family logs (`/var/log/auth.log`, `/var/log/syslog`, `/var/log/secure`) require root and often rotate automatically. Discuss with the client before truncating rotated logs, as these may be forwarded to a SIEM already.

```bash
# Truncate (requires root) — only if authorized
> /var/log/auth.log
> /var/log/syslog
```

---

## 5. Timestomping — modifying file metadata

Timestomping sets a file's timestamps to blend in with neighboring files, making forensic timeline analysis harder. It is **always a post-exploitation action** and requires write access to the target.

```powershell
# Set all timestamps on a file to match a reference file
$ref = Get-Item "C:\Windows\System32\notepad.exe"
$target = Get-Item "C:\Users\Public\malware.exe"
$target.CreationTime   = $ref.CreationTime
$target.LastWriteTime  = $ref.LastWriteTime
$target.LastAccessTime = $ref.LastAccessTime
```

Note: NTFS maintains a second timestamp in the `$MFT` that PowerShell's `FileInfo` does not touch. Forensic tools (FTK, Autopsy) read the raw `$MFT` and will still see the original creation time. Full timestomping requires direct `$MFT` manipulation, which is out of scope here.

---

## 6. Document the clean-up

Every track removed during an authorized engagement **must be recorded** in the penetration test report. The documentation should include:

- **Artifact type** (event log, file, registry key)
- **System hostname and path**
- **Timestamp of removal**
- **Method used**
- **Original content** (where preserved before deletion)

This record serves two purposes: it proves the test ended cleanly and it gives the blue team a full audit trail to validate their detection capability against the window of activity.

---

## See it

Defenders watching for unauthorized track covering will see:

| Source | Indicator |
| :--- | :--- |
| Windows Security log | **Event ID 1102** — Security audit log cleared; correlate with non-admin accounts |
| Windows System log | **Event ID 104** — Event log service cleared a log |
| Sysmon (Event ID 11) | File creation/deletion in `%TEMP%`, `%APPDATA%`, `C:\Users\Public` |
| PowerShell (Event ID 4104) | Script-block containing `Clear-History`, `Remove-Item -Path *History*`, `wevtutil cl` |
| Linux `auditd` | `SYSCALL` records for `unlink`/`rename` on `/var/log/*` files |

---

## Detect it

- Detection: [SPL — Windows Events](../../detection/spl/windows-events.md) (Event ID 1102 / 104 query)
- Detection: [KQL — Logon & Identity](../../detection/kql/logon-identity.md)
- Hunt: [Threat Hunting Workflow](../../tasks/threat-hunting/index.md)
- Harden: [Hardening Tasks](../../tasks/hardening/index.md)
- Related offensive: [Foothold & C2](foothold-command-control.md)

## Related concepts

- [Digital Forensics](../fundamentals/concepts/digital-forensics.md)
- [DLL Hijacking](dll-hijacking.md)
- [Actions on Objectives & Reporting](actions-on-objectives-reporting.md)

## External Resources

- [MITRE ATT&CK T1070 — Indicator Removal](https://attack.mitre.org/techniques/T1070/)
- [MITRE ATT&CK T1070.001 — Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)
- [MITRE ATT&CK T1070.003 — Clear Command History](https://attack.mitre.org/techniques/T1070/003/)
- [NIST SP 800-115 — Technical Guide to Information Security Testing](https://csrc.nist.gov/publications/detail/sp/800-115/final)

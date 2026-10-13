---
title: Splunk Detection — AMSI Bypass Attempts
type: entry
platforms:
  - Windows
  - Splunk
languages:
  - SPL
  - PowerShell
tasks:
  - Detection Engineering
  - Threat Hunting
verified: true
last_verified: 2026-10-12
difficulty: intermediate
tags:
  - splunk
  - amsi
  - detection
  - evasion
---

# Splunk Detection — AMSI Bypass Attempts

Detects .NET reflection code and memory patching strings commonly used to disable or blind the Antimalware Scan Interface (AMSI) in Windows PowerShell sessions.

## Why it matters

AMSI hands every PowerShell script block, VBScript, JScript and Office VBA macro to the installed antivirus *before* it runs, after de-obfuscation. Attackers disable it first so the rest of their tooling (Mimikatz loaders, C2 stagers) is never scanned. A bypass attempt is rarely legitimate on a production host, so this rule has a high signal-to-noise ratio.

Common techniques:

| Technique | What it looks like in a script block |
| --- | --- |
| Force the init-failed flag | `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')` + `amsiInitFailed` |
| Null the AMSI context | `GetField('amsiContext', 'NonPublic, Static')` |
| Patch `AmsiScanBuffer` in memory | `AmsiScanBuffer`, `VirtualProtect`, `GetProcAddress`, byte arrays such as `0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3` |
| Downgrade to PowerShell 2.0 (no AMSI) | `powershell -version 2` |

## Detection Logic

- **Log Source**: `EventCode=4104` (PowerShell Script Block Logging, `Microsoft-Windows-PowerShell/Operational`)
- **ATT&CK Technique**: [T1562.001 - Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

```spl
index=win_logs EventCode=4104
  (ScriptBlockText="*amsiInitFailed*"
   OR ScriptBlockText="*.GetField('amsiContext', 'NonPublic, Static')*"
   OR ScriptBlockText="*[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')*")
| stats count earliest(_time) as first_seen latest(_time) as last_seen values(User) as Users by ComputerName, ScriptBlockText
```

Wider variant that also catches in-memory patching and string-split obfuscation (`'Am'+'si'`). Expect a few more false positives:

```spl
index=win_logs EventCode=4104
| eval sb=lower(replace(ScriptBlockText, "['\"+\s`]", ""))
| where like(sb, "%amsiinitfailed%") OR like(sb, "%amsicontext%") OR like(sb, "%amsiutils%")
    OR (like(sb, "%amsiscanbuffer%") AND (like(sb, "%virtualprotect%") OR like(sb, "%getprocaddress%")))
| stats count min(_time) as first_seen max(_time) as last_seen values(User) as users by ComputerName
```

Field names follow the Splunk Add-on for Microsoft Windows (`XmlWinEventLog`). Rename `ComputerName`/`User` if your add-on version uses `Computer`/`UserID`.

## Prerequisites

Script block logging must be on: Group Policy *Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging*. Without it, Windows only logs blocks that it considers suspicious itself (as warning-level 4104), and you will miss some attempts. PowerShell 2.0 does not log script blocks or use AMSI, so also alert on `powershell.exe -version 2` in process creation logs (4688 / Sysmon 1), and remove the feature where possible.

## Tuning and false positives

- Security tools, AMSI test harnesses and red-team exercises print these strings. Allowlist by host and user, not by string.
- Malware research workstations will fire constantly; exclude them by `ComputerName`.
- Long scripts are split across several 4104 events (`MessageNumber` of `MessageTotal`). A string split across two parts can be missed; rebuild them with `ScriptBlockId` if you see near misses.

## Respond

1. Pull every 4104 event with the same `ScriptBlockId` and the 30 minutes around it on that host. What ran after the bypass is the actual payload.
2. Find the parent process (4688 / Sysmon 1): Office, `wscript`, a scheduled task or a remote session (`wsmprovhost.exe`).
3. Treat the host as compromised until proved otherwise → [Suspicious PowerShell](../../tasks/incident-response/suspicious-powershell.md).

## Test it

Atomic Red Team [T1562.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md) includes *AMSI Bypass - AMSI InitFailed*. Run it in a lab only; it disables AMSI for that PowerShell session.

## Related

- [PowerShell detections (SPL)](powershell.md)
- [Suspicious PowerShell workflow](../../tasks/incident-response/suspicious-powershell.md)
- [Microsoft Defender Antivirus](../../platforms/windows/defender.md)

## Sources

- [Microsoft Learn — Antimalware Scan Interface (AMSI)](https://learn.microsoft.com/windows/win32/amsi/antimalware-scan-interface-portal)
- [Microsoft Learn — about_Logging_Windows (script block logging)](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows)
- [MITRE ATT&CK T1562.001](https://attack.mitre.org/techniques/T1562/001/)

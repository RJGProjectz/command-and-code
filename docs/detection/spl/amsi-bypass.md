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
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - splunk
  - amsi
  - detection
  - evasion
---

# Splunk Detection — AMSI Bypass Attempts

Detects .NET reflection code and memory patching strings commonly used to disable or blind the Antimalware Scan Interface (AMSI) in Windows PowerShell sessions.

## Detection Logic

- **Log Source**: `EventCode=4104` (PowerShell Script Block Logging)
- **ATT&CK Technique**: [T1562.001 - Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

```spl
index=win_logs EventCode=4104
  (ScriptBlockText="*amsiInitFailed*"
   OR ScriptBlockText="*.GetField('amsiContext', 'NonPublic, Static')*"
   OR ScriptBlockText="*[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')*")
| stats count earliest(_time) as first_seen latest(_time) as last_seen values(User) as Users by ComputerName, ScriptBlockText
```

---
title: Sigma Rule Examples
platforms: [Windows]
languages: [Sigma]
tasks: [Detection Engineering, Threat Hunting]
category: Detection Rules
tags: [sigma, detection rules, process creation, registry, services, scheduled tasks]
aliases: [sigma rules, sigma powershell rule, sigma run key, sigma service install, write a sigma rule]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
---

# Sigma Rule Examples

Each rule follows the Sigma specification and SigmaHQ field taxonomy. Test conversions against your own data and tune the filters before deploying — these are starting points, not production rules.

## Encoded PowerShell command line

```yaml
title: PowerShell Encoded Command Line
id: aba0fb38-c925-4a33-b4a0-71ba7084d1fd
status: experimental
description: Detects PowerShell started with an abbreviation of -EncodedCommand followed by a base64 payload.
references:
  - https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_pwsh
author: Command & Code
date: 2026-10-05
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense-evasion
  - attack.t1027
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith:
        - '\powershell.exe'
        - '\pwsh.exe'
    - OriginalFileName:
        - 'PowerShell.EXE'
        - 'pwsh.dll'
  selection_cli:
    CommandLine|re: '(?i)\s[-/]e[a-z]*\s+[a-z0-9+/=]{20,}'
  condition: all of selection_*
falsepositives:
  - Management and deployment tools that pass scripts as encoded commands (SCCM, some RMM agents)
level: medium
```

Equivalent hunts: [KQL](../kql/process-events.md#encoded-powershell), [SPL](../spl/powershell.md#encoded-commands-process-creation), [S1QL](../s1ql/hunting.md#encoded-or-download-cradle-powershell).

## Suspicious service installation

```yaml
title: Service Installed With Suspicious Image Path
id: ce45b031-9af5-4184-94fc-e9059ac8f2a7
status: experimental
description: Detects a new service whose binary path points to a user-writable location or a script interpreter.
author: Command & Code
date: 2026-10-05
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.t1543.003
logsource:
  product: windows
  service: system
detection:
  selection:
    Provider_Name: 'Service Control Manager'
    EventID: 7045
  suspicious_path:
    ImagePath|contains:
      - '\Users\'
      - '\ProgramData\'
      - '\Windows\Temp\'
      - '\AppData\'
      - 'powershell'
      - 'cmd.exe /c'
      - 'mshta'
      - 'rundll32'
  condition: selection and suspicious_path
falsepositives:
  - Software installers that register services from ProgramData
level: high
```

## Run key persistence

```yaml
title: Run Key Value Pointing To User-Writable Location
id: 30c4d057-99fd-4731-9e2e-ceca909fa67c
status: experimental
description: Detects Run/RunOnce values set to execute from user-writable paths or via script interpreters.
author: Command & Code
date: 2026-10-05
tags:
  - attack.persistence
  - attack.t1547.001
logsource:
  category: registry_set
  product: windows
detection:
  selection_key:
    TargetObject|contains:
      - '\Software\Microsoft\Windows\CurrentVersion\Run'
      - '\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
  selection_value:
    Details|contains:
      - '\AppData\Local\Temp\'
      - '\Users\Public\'
      - '\ProgramData\'
      - 'powershell'
      - 'mshta'
      - 'wscript'
      - 'rundll32'
  condition: all of selection_*
falsepositives:
  - Per-user application updaters installed under AppData (browsers, chat clients) — filter by known paths
level: medium
```

## Scheduled task created by command line

```yaml
title: Scheduled Task Created Via Schtasks
id: 2970f965-df7d-4df8-a8b7-6f8a1675bad4
status: experimental
description: Detects schtasks.exe creating a task that runs a script interpreter or a binary from a user-writable path.
author: Command & Code
date: 2026-10-05
tags:
  - attack.persistence
  - attack.execution
  - attack.t1053.005
logsource:
  category: process_creation
  product: windows
detection:
  selection_create:
    Image|endswith: '\schtasks.exe'
    CommandLine|contains: '/create'
  selection_payload:
    CommandLine|contains:
      - 'powershell'
      - 'cmd /c'
      - 'cmd.exe /c'
      - 'mshta'
      - '\AppData\'
      - '\Users\Public\'
      - '\Temp\'
  condition: all of selection_*
falsepositives:
  - Administrative scripts that schedule maintenance tasks
level: medium
```

## Related

- [Sigma overview and conversion](index.md)
- [MITRE ATT&CK mappings](../mitre-attack/index.md)

## Sources

- [Sigma specification](https://github.com/SigmaHQ/sigma-specification)
- [SigmaHQ rule repository](https://github.com/SigmaHQ/sigma)

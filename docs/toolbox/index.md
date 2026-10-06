---
title: Toolbox
type: index
---

# Toolbox

The **operational layer** of Command & Code: reusable scripts that live in the repository's `scripts/` folder and are documented here.

Each tool page explains purpose, the problem it solves, inputs, outputs, dependencies, usage, security considerations and related knowledge — and embeds the source so it is readable offline.

| Tool | Language | Purpose |
| --- | --- | --- |
| [Get-ListeningPorts](powershell.md#get-listeningports) | PowerShell | Listeners with process path, command line and owner |
| [Get-ProcessTree](powershell.md#get-processtree) | PowerShell | Ancestors and descendants of a PID, PID-reuse safe |
| [Get-RecentLogons](powershell.md#get-recentlogons) | PowerShell | Flattened 4624/4625 logon history |
| [Get-PersistenceSnapshot](powershell.md#get-persistencesnapshot) | PowerShell | Run keys, tasks, services, Winlogon, IFEO, startup, WMI — flagged |
| [Invoke-EndpointTriage](powershell.md#invoke-endpointtriage) | PowerShell | Full Windows first-response collection with hash manifest |
| [get-listening-ports.sh](bash.md#get-listening-portssh) | Bash | Listeners with binary path, user, deleted/tmp flags |
| [get-process-tree.sh](bash.md#get-process-treesh) | Bash | Ancestors and descendants of a PID |
| [linux-triage.sh](bash.md#linux-triagesh) | Bash | Full Linux first-response collection with hash manifest |
| [decode-powershell.py](python.md#decode-powershellpy) | Python | Decode `-EncodedCommand` payloads and nested base64 |
| [api-query.py](python.md#api-querypy) | Python | Paginated API export (Graph, SentinelOne, …) to JSONL/CSV |

## Adding a tool

1. Put the script in `scripts/<language>/` using the [PowerShell](../languages/powershell/automation.md#script-template), [Bash](../languages/bash/automation.md#script-template) or [Python](../languages/python/logging-automation.md#script-template) template.
2. Document it on the matching toolbox page: problem, inputs, outputs, dependencies, usage, security considerations, related entries.
3. Embed the source with `--8<-- "<language>/<file>"` inside a collapsible block.
4. Run `python tools/cc.py code` — the script must parse cleanly.

## All tool pages

<!-- cc:index type="tool" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Bash Toolbox](bash.md) | Tool | Linux | Bash | Automation, Incident Response, Forensics, Investigation |
| [Command & Code CLI Lookup Utility](lookup.md) | Tool | Windows, Linux | Python | Administration, Investigation |
| [PowerShell Toolbox](powershell.md) | Tool | Windows, Windows Server | PowerShell | Automation, Incident Response, Forensics, Investigation |
| [Python Toolbox](python.md) | Tool | Windows, Linux, Microsoft 365, SentinelOne | Python | Automation, Incident Response, Investigation |

<!-- /cc:index -->

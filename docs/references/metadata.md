---
title: Metadata Conventions
type: index
---

# Metadata Conventions

Every knowledge page starts with YAML front matter. Metadata drives the three browse dimensions, the chips under each title, the generated browse tables, and validation in CI.

## Schema

```yaml
---
title: Find Listening TCP Ports         # required — unique across the repository
type: entry                             # entry | workflow | tool | reference | index (default: entry; index.md → index)
platforms: [Windows, Windows Server]    # required*: values from tools/vocabulary.yml
languages: [PowerShell, Windows CLI]    # required*: values from tools/vocabulary.yml
tasks: [Incident Response, Troubleshooting]   # required: values from tools/vocabulary.yml
category: Networking                    # optional — free text, one per page
tags: [tcp, ports, triage]              # optional — free-form, feeds the Tags page
aliases: [netstat, open ports]          # optional — alternative search phrases, shown under the title
difficulty: basic                       # optional — basic | intermediate | advanced
verified: true                          # required — true | false
last_verified: 2026-10-05               # required when verified: true
search:
  boost: 2                              # optional — Material search ranking boost for key pages
---
```

\* At least one of `platforms` or `languages`.

## Required vs optional

| Field | entry / workflow / tool / reference | index |
| --- | --- | --- |
| `title` | required | recommended |
| `tasks` | required | — |
| `platforms` or `languages` | at least one required | — |
| `verified` | required | — |
| `last_verified` | required if `verified: true` | — |
| everything else | optional | — |

## Controlled vocabulary

Platform, language and task values must match `tools/vocabulary.yml` exactly — that file also maps each value to its browse page. To introduce a new value, add it there first.

| Dimension | Values |
| --- | --- |
| Platforms | Windows, Windows Server, Linux, Microsoft 365, Microsoft Defender, Entra ID, Intune, Exchange Online, Hyper-V, VMware, Proxmox, SentinelOne, Splunk |
| Languages | PowerShell, Bash, Python, Windows CLI, KQL, SPL, S1QL, Sigma, MITRE ATT&CK |
| Tasks | Incident Response, Threat Hunting, Investigation, Troubleshooting, Administration, Detection Engineering, Hardening, Forensics, Automation |

## What `verified` means

| Value | Meaning | Page must |
| --- | --- | --- |
| `verified: true` | Syntax and locations checked against vendor documentation; PowerShell, Bash, Python and YAML blocks pass `tools/cc.py code`. Still test in your environment. | set `last_verified` |
| `verified: false` | Not yet confirmed — for example vendor syntax that varies by version, or field names that depend on local configuration | state **VERIFY BEFORE PRODUCTION USE** in a visible admonition |

`python tools/cc.py check` enforces both rules.

## Generated browse tables

A page can include a table of every entry matching a filter:

```text
<!-- cc:index tasks="Incident Response" type="workflow" -->
<!-- /cc:index -->
```

Run `python tools/cc.py index` to fill or refresh the table. Filters are ANDed; use `|` for OR within one key (`platforms="Windows|Linux"`). Supported keys: `platforms`, `languages`, `tasks`, `type`, `category`. The rows are committed, so they also render on GitHub. CI fails when a table is stale.

## Headings and anchors

Write headings as the task, phrased the way you would search for it: *Find listening ports*, *Find a process by PID*. Workflows link to these headings, so renaming one breaks links — `mkdocs build --strict` will report every broken anchor.

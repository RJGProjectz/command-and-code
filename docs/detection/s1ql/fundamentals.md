---
title: S1QL Fundamentals
platforms: [SentinelOne]
languages: [S1QL]
tasks: [Threat Hunting, Investigation, Detection Engineering]
category: Query Language
tags: [s1ql, sentinelone, deep visibility, powerquery, event search, singularity data lake]
aliases: [sentinelone query, deep visibility query syntax, powerquery, s1 query language, contains anycase]
difficulty: basic
verified: false
---

# S1QL Fundamentals

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Syntax shown is **S1QL 2.0 with PowerQuery pipes**, as used in the Singularity Data Lake / Event Search experience. Older consoles use **S1QL 1.0** with different field names (e.g. `SrcProcName`, `TgtProcCmdLine`) and operators (`ContainsCIS`). Field availability depends on console version, license and agent OS. Test every query in your console and confirm field names with its autocomplete.

## Query structure

```text
<filter expression> | <pipe command> | <pipe command> ...
```

The filter selects events; pipe commands (PowerQuery) aggregate and shape them.

## Operators

| Operator | Example |
| --- | --- |
| `=` / `!=` | `src.process.name = 'powershell.exe'` |
| `contains` | `tgt.file.path contains '\\Temp\\'` |
| `contains:anycase` | `src.process.cmdline contains:anycase 'downloadstring'` |
| `contains (a, b)` | `src.process.cmdline contains:anycase ('-enc', '-encodedcommand')` — any of |
| `in` / `in:anycase` | `src.process.name in ('powershell.exe', 'pwsh.exe')` |
| `matches` | `src.process.cmdline matches '(?i)\\s-e[a-z]*\\s'` — regex |
| `and`, `or`, `not` / `!( )` | boolean logic |

## Core fields

| Area | Fields |
| --- | --- |
| Event | `event.type`, `event.time`, `event.category` |
| Endpoint | `endpoint.name`, `endpoint.os`, `site.name` |
| Acting process | `src.process.name`, `src.process.cmdline`, `src.process.image.path`, `src.process.image.sha256`, `src.process.user`, `src.process.storyline.id` |
| Parent | `src.process.parent.name`, `src.process.parent.cmdline` |
| Target process (created) | `tgt.process.name`, `tgt.process.cmdline` |
| File | `tgt.file.path`, `tgt.file.sha256`, `tgt.file.extension` |
| Network | `src.ip.address`, `dst.ip.address`, `dst.port.number`, `event.network.direction` |
| DNS | `event.dns.request`, `event.dns.response` |
| Registry | `registry.keyPath`, `registry.value` |
| Scheduled task | `task.name`, `task.path` |
| Login | `event.login.userName`, `event.login.loginIsSuccessful`, `event.login.type` |

In **Process Creation** events, `src.process` is the parent that created the process and `tgt.process` is the new process.

## Common event types

`Process Creation`, `IP Connect`, `IP Listen`, `DNS Resolved`, `File Creation`, `File Modification`, `Registry Value Modified`, `Task Register`, `Login`.

## PowerQuery pipe commands

```text
| group count = count() by endpoint.name, src.process.name
| columns endpoint.name, src.process.name, src.process.cmdline
| filter count > 10
| sort -count
| limit 100
| let short_cmd = substr(src.process.cmdline, 0, 200)
```

## Example: count PowerShell executions per endpoint

```text
event.type = 'Process Creation' and tgt.process.name in:anycase ('powershell.exe', 'pwsh.exe')
| group executions = count() by endpoint.name
| sort -executions
| limit 50
```

## Storyline pivot

`src.process.storyline.id` links every event in an attack chain. When you find one suspicious event, filter on its storyline ID to see everything related:

```text
src.process.storyline.id = 'STORYLINE_ID'
| columns event.time, event.type, src.process.name, src.process.cmdline, tgt.file.path, dst.ip.address
| sort event.time
```

## Related

- [S1QL hunting queries](hunting.md)
- [KQL fundamentals](../kql/fundamentals.md)

## Sources

- SentinelOne console: *Help → Query Language* and the in-console field autocomplete (authoritative for your version)
- [SentinelOne: PowerQuery brings new data analytics capabilities](https://www.sentinelone.com/blog/powerquery-brings-new-data-analytics-capabilities-to-singularity-xdr/)

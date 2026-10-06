---
title: S1QL Hunting Queries
platforms: [SentinelOne, Windows, Linux]
languages: [S1QL]
tasks: [Threat Hunting, Incident Response, Investigation]
category: Hunting
tags: [s1ql, sentinelone, powershell, persistence, network, dns, lolbins, failed logins]
aliases: [sentinelone query powershell, sentinelone hunt, s1 network query, s1 scheduled task, deep visibility hunting]
difficulty: intermediate
verified: false
---

# S1QL Hunting Queries

!!! danger "VERIFY BEFORE PRODUCTION USE"
    S1QL 2.0 / PowerQuery syntax. Field names and event types vary by console version and agent OS — validate each query in your console before relying on it, then set `verified: true` on this page. See [S1QL fundamentals](fundamentals.md).

## Process investigation

### Encoded or download-cradle PowerShell

```text
event.type = 'Process Creation'
and tgt.process.name in:anycase ('powershell.exe', 'pwsh.exe')
and tgt.process.cmdline contains:anycase ('-enc', '-encodedcommand', 'frombase64string', 'downloadstring', 'invoke-expression', 'iex')
| columns event.time, endpoint.name, src.process.name, tgt.process.cmdline, src.process.user
| sort -event.time
```

`'-enc'` also matches `-encodedcommand`; it does not match the `-e`/`-ec` abbreviations — add a `matches` clause if you need them.

### Office or browser spawning a shell

```text
event.type = 'Process Creation'
and src.process.name in:anycase ('winword.exe', 'excel.exe', 'outlook.exe', 'chrome.exe', 'msedge.exe', 'firefox.exe')
and tgt.process.name in:anycase ('powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe')
| columns event.time, endpoint.name, src.process.name, tgt.process.name, tgt.process.cmdline
```

### Rare processes across the fleet

```text
event.type = 'Process Creation'
| group endpoints = estimate_distinct(endpoint.name), executions = count() by tgt.process.name
| filter endpoints <= 2
| sort executions
| limit 200
```

## Network investigation

### Connections to an indicator

```text
event.type = 'IP Connect' and dst.ip.address in ('<TARGET_IP>', '<SECONDARY_IP>')
| group connections = count() by endpoint.name, src.process.name, dst.ip.address, dst.port.number
| sort -connections
```

### Scripting engines with outbound connections

```text
event.type = 'IP Connect' and event.network.direction = 'OUTGOING'
and src.process.name in:anycase ('powershell.exe', 'pwsh.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'wscript.exe')
| columns event.time, endpoint.name, src.process.name, src.process.cmdline, dst.ip.address, dst.port.number
```

### DNS lookups for a domain

```text
event.type = 'DNS Resolved' and event.dns.request contains:anycase 'example.com'
| group lookups = count() by endpoint.name, src.process.name, event.dns.request
```

## Persistence

### Run key writes

```text
event.type = 'Registry Value Modified'
and registry.keyPath contains:anycase '\\CurrentVersion\\Run'
| columns event.time, endpoint.name, src.process.name, registry.keyPath, registry.value
```

### Scheduled task registration

```text
event.type = 'Task Register'
| columns event.time, endpoint.name, src.process.name, src.process.cmdline, task.name, task.path
```

### Linux cron and systemd file changes

```text
event.type in ('File Creation', 'File Modification')
and endpoint.os = 'linux'
and (tgt.file.path contains '/etc/cron' or tgt.file.path contains '/var/spool/cron' or tgt.file.path contains '/etc/systemd/system/')
| columns event.time, endpoint.name, src.process.name, src.process.cmdline, tgt.file.path
```

## Authentication

### Failed logins per user and endpoint

```text
event.type = 'Login' and event.login.loginIsSuccessful = false
| group failures = count() by endpoint.name, event.login.userName
| filter failures > 10
| sort -failures
```

## Related

- [KQL process events](../kql/process-events.md)
- [SPL PowerShell](../spl/powershell.md)
- [Suspicious PowerShell workflow](../../tasks/incident-response/suspicious-powershell.md)

## Sources

- SentinelOne console *Help → Query Language* (authoritative for your version)
- [secure-cake/sentinelone-powerquery (community examples)](https://github.com/secure-cake/sentinelone-powerquery)

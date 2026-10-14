---
title: S1QL Hunting Queries
platforms: [SentinelOne, Windows, Linux]
languages: [S1QL]
tasks: [Threat Hunting, Incident Response, Investigation]
category: Hunting
tags: [s1ql, sentinelone, powershell, persistence, network, dns, lolbins, failed logins]
aliases: [sentinelone query powershell, sentinelone hunt, s1 network query, s1 scheduled task, deep visibility hunting]
difficulty: intermediate
verified: true
last_verified: 2026-10-13
---

# S1QL Hunting Queries

!!! warning "Before you deploy"
    S1QL 2.0 / PowerQuery syntax, checked (2026-10-13) against SentinelOne's published PowerQuery reference and
    Deep Visibility field names; not run in a live console. Field availability still varies by agent OS and license. See [S1QL fundamentals](fundamentals.md).

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
| columns event.time, endpoint.name, src.process.name, registry.keyPath, registry.valueName, registry.value
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

## Test it

| Query | Atomic Red Team test |
| --- | --- |
| Encoded or download-cradle PowerShell | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) *ATHPowerShellCommandLineParameter -EncodedCommand parameter variations* |
| Office or browser spawning a shell | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) *Word spawned a command shell and used an IP address in the command line* |
| Rare processes | [T1036.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.003/T1036.003.md) *Masquerading - windows exe running as different windows exe* |
| Connections to an indicator, scripting engines outbound | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) *Windows - PowerShell Download* |
| DNS lookups for a domain | [T1071.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.004/T1071.004.md) *DNS Long Domain Query* |
| Run key writes | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) *Reg Key Run* |
| Scheduled task registration | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) *Scheduled task Local* |
| Linux cron and systemd | [T1053.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.003/T1053.003.md) *Cron - Add script to /etc/cron.d folder*; [T1543.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.002/T1543.002.md) *Create Systemd Service* |
| Failed logins | [T1110.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.001/T1110.001.md) *Brute Force Credentials of single Active Directory domain users via SMB* |

## Related

- [KQL process events](../kql/process-events.md)
- [SPL PowerShell](../spl/powershell.md)
- [Suspicious PowerShell workflow](../../tasks/incident-response/suspicious-powershell.md)

## Sources

- SentinelOne console *Help → Query Language* (authoritative for your version)
- [SentinelOne — PowerQuery syntax and operators (Sentinel-One/ai-siem)](https://github.com/Sentinel-One/ai-siem/blob/main/plugins/s1-secops-skills/skills/powerquery/references/syntax-and-operators.md)
- [secure-cake/sentinelone-powerquery (community examples)](https://github.com/secure-cake/sentinelone-powerquery)

---
title: KQL Fundamentals
platforms: [Microsoft Defender, Microsoft 365]
languages: [KQL]
tasks: [Threat Hunting, Detection Engineering, Investigation]
category: Query Language
tags: [kql, advanced hunting, sentinel, summarize, join, parse, dynamic, time filtering]
aliases: [kusto, kql cheat sheet, summarize count by, kql join, parse_json, has vs contains, arg_max]
difficulty: basic
verified: true
last_verified: 2026-10-05
search:
  boost: 2
---

# KQL Fundamentals

Kusto Query Language is used by **Microsoft Defender XDR advanced hunting** and **Microsoft Sentinel / Log Analytics**.

!!! info "Timestamp vs TimeGenerated"
    Defender XDR advanced hunting tables use **`Timestamp`**. Sentinel / Log Analytics tables use **`TimeGenerated`** (Defender tables streamed into Sentinel have both). Examples on this site use `Timestamp` for Defender tables and `TimeGenerated` for Entra/Sentinel tables.

## Query shape

Filter first, on time, then on the most selective columns; project only what you need.

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "DownloadString"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
| take 100
```

## String operators

| Operator | Meaning | Notes |
| --- | --- | --- |
| `==` / `=~` | equals (case-sensitive / insensitive) | |
| `has` | whole term match | Fast — uses the term index. Prefer it. |
| `has_any`, `has_all` | any/all of a list of terms | |
| `contains` | substring | Slower; use when the value is not a whole term |
| `startswith`, `endswith` | prefix / suffix | |
| `in`, `in~` | value in a list (case-sensitive / insensitive) | |
| `matches regex` | RE2 regex | Slowest; filter with `has` first |

Negate with `!`: `!has`, `!contains`, `!in~`, `!=`.

Kusto splits text into terms on non-alphanumeric characters, so `C:\Windows\powershell.exe` contains the terms `windows`, `powershell` and `exe`. `has "powershell"` matches it; `has "power"` does not (partial term) — use `contains` for partial strings.

## Time filtering

```kql
| where Timestamp > ago(7d)
| where Timestamp between (datetime(2026-10-01 00:00) .. datetime(2026-10-02 00:00))
| summarize count() by bin(Timestamp, 1h)
```

Advanced hunting keeps 30 days of data.

## summarize

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| summarize Connections = count(),
            Devices = dcount(DeviceName),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            Processes = make_set(InitiatingProcessFileName, 20)
          by RemoteIP
| order by Devices desc
```

Latest record per key:

```kql
DeviceInfo
| summarize arg_max(Timestamp, *) by DeviceId
```

## let and lists

```kql
let suspiciousParents = dynamic(["winword.exe", "excel.exe", "outlook.exe"]);
let lookback = 7d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName in~ (suspiciousParents)
```

## join

```kql
let procs = DeviceProcessEvents
    | where Timestamp > ago(1d)
    | where FileName =~ "powershell.exe"
    | where ProcessCommandLine has_any ("DownloadString", "IEX", "Invoke-Expression", "FromBase64String")
    | project DeviceId, ProcessId, ProcTime = Timestamp, ProcessCommandLine;
procs
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(1d)
    | where InitiatingProcessFileName =~ "powershell.exe"
    | project DeviceId, InitiatingProcessId, NetTime = Timestamp, RemoteIP, RemotePort, RemoteUrl
  ) on $left.DeviceId == $right.DeviceId, $left.ProcessId == $right.InitiatingProcessId
| where NetTime between (ProcTime .. (ProcTime + 1h))
| project ProcTime, NetTime, DeviceId, ProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
```

The time-window condition guards against PID reuse.

| kind | Returns |
| --- | --- |
| `inner` | rows that match on both sides |
| `leftouter` | all left rows, matched right columns or empty |
| `leftanti` | left rows with **no** match — "never seen before" logic |
| `innerunique` | **default** — deduplicates the left side first, which can silently drop rows |

Always specify `kind=` explicitly. Put the smaller table on the left.

## Parsing

```kql
| extend Domain = extract(@"https?://([^/:]+)", 1, RemoteUrl)
| parse ProcessCommandLine with * "-ExecutionPolicy " Policy " " *
```

## Dynamic (JSON) columns

`AdditionalFields` and similar columns hold JSON:

```kql
DeviceEvents
| where ActionType == "ScheduledTaskCreated"
| extend Fields = parse_json(AdditionalFields)
| extend TaskName = tostring(Fields.TaskName)
| project Timestamp, DeviceName, TaskName, AdditionalFields
```

Expand arrays into rows with `mv-expand`:

```kql
SigninLogs
| mv-expand Policy = ConditionalAccessPolicies
| extend PolicyName = tostring(Policy.displayName), Result = tostring(Policy.result)
```

## Explore an unfamiliar table

```kql
DeviceEvents
| where Timestamp > ago(1d)
| summarize count() by ActionType
| order by count_ desc
```

`getschema` lists columns and types: `DeviceProcessEvents | getschema`.

## Related

- [Process events](process-events.md)
- [SPL fundamentals](../spl/fundamentals.md)
- [Cross-platform equivalents](../../references/equivalents.md)

## Sources

- [KQL overview](https://learn.microsoft.com/kusto/query/)
- [String operators and the term index](https://learn.microsoft.com/kusto/query/datatypes-string-operators)
- [join operator](https://learn.microsoft.com/kusto/query/join-operator)
- [Advanced hunting schema](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables)

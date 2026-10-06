---
title: SPL Fundamentals and Search Optimization
platforms: [Splunk]
languages: [SPL]
tasks: [Threat Hunting, Detection Engineering, Investigation]
category: Query Language
tags: [spl, splunk, stats, tstats, eval, rex, optimization, cim]
aliases: [splunk cheat sheet, stats count by, tstats, splunk regex rex, faster splunk searches, first seen splunk]
difficulty: basic
verified: true
last_verified: 2026-10-05
search:
  boost: 2
---

# SPL Fundamentals and Search Optimization

## Search shape

```spl
index=wineventlog sourcetype=XmlWinEventLog EventCode=4625 earliest=-24h
| stats count AS failures, dc(host) AS hosts BY TargetUserName, IpAddress
| where failures > 10
| sort - failures
```

Everything before the first `|` is the **base search** — it runs on the indexers and is where most of the speed comes from.

## Make searches fast

1. **Always specify `index=`** (and `sourcetype=` when you know it). Searching `index=*` scans everything.
2. **Narrow the time range** with the picker or `earliest=` / `latest=`.
3. **Filter in the base search**, not with `| search` or `| where` later.
4. **Drop fields early** with `| fields` when events are wide.
5. **Use `stats`** instead of `transaction` and `join` wherever possible.
6. **Use `tstats`** on accelerated data models for counts across large time ranges.

## Common commands

| Command | Use |
| --- | --- |
| `stats` | aggregate: `count`, `dc()`, `values()`, `min()`, `max()`, `earliest()`, `latest()` |
| `eval` | compute fields: `eval mb = bytes/1024/1024` |
| `where` | filter with expressions: `where failures > 10 AND like(user, "adm%")` |
| `table` | choose output columns |
| `rex` | extract with regex |
| `timechart` | stats over time: `timechart span=1h count BY host` |
| `eventstats` / `streamstats` | add aggregates to each event / running aggregates |
| `dedup` | keep first event per value |
| `lookup` / `inputlookup` | enrich from / read a lookup table |
| `rename`, `fillnull`, `sort`, `head`, `rare`, `top` | shaping |

## Extract a field with rex

```spl
index=proxy sourcetype=squid
| rex field=url "^https?://(?<domain>[^/:]+)"
| stats count BY domain
| sort - count
```

## First and last seen

```spl
index=wineventlog EventCode=4688 earliest=-30d
| stats earliest(_time) AS first_seen, latest(_time) AS last_seen, count, dc(host) AS hosts BY New_Process_Name
| where first_seen > relative_time(now(), "-1d")
| convert ctime(first_seen) ctime(last_seen)
```

"Executables first seen in the last day, in 30 days of data" — a classic new-behaviour hunt. Field names depend on your Windows add-on (`New_Process_Name` classic vs `NewProcessName` XML).

## tstats on CIM data models

```spl
| tstats count FROM datamodel=Authentication WHERE Authentication.action=failure BY Authentication.src, Authentication.user
| rename Authentication.* AS *
| sort - count
```

Requires the data to be CIM-mapped and the data model accelerated. `tstats` reads summaries, not raw events — orders of magnitude faster.

## Time handling

```spl
| eval time = strftime(_time, "%Y-%m-%d %H:%M:%S")
| bin _time span=5m
```

## Build test data

```spl
| makeresults count=3
| streamstats count AS n
| eval user = "user" . n
```

## Related

- [KQL fundamentals](../kql/fundamentals.md)
- [Windows security events in SPL](windows-events.md)

## Sources

- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)
- [Write better searches](https://docs.splunk.com/Documentation/Splunk/latest/Search/Writebettersearches)
- [tstats](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Tstats)

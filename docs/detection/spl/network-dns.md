---
title: SPL Network and DNS Hunting
platforms: [Splunk]
languages: [SPL]
tasks: [Threat Hunting, Investigation, Detection Engineering]
category: Network
tags: [spl, network traffic, dns, sysmon 22, cim, firewall, rare domains]
aliases: [network connections splunk, dns splunk, long dns queries, rare domains splunk, outbound traffic splunk]
difficulty: intermediate
verified: false
---

# SPL Network and DNS Hunting

!!! danger "VERIFY BEFORE PRODUCTION USE"
    CIM examples (`datamodel=Network_Traffic`, `datamodel=Network_Resolution`) require CIM-compliant data and accelerated data models. Sysmon examples assume `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`. Confirm names in your environment.

## Connections to an indicator (CIM)

```spl
| tstats count, min(_time) AS first, max(_time) AS last FROM datamodel=Network_Traffic
    WHERE All_Traffic.dest IN ("203.0.113.10", "198.51.100.7")
    BY All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port
| rename All_Traffic.* AS *
| convert ctime(first) ctime(last)
```

## Rare outbound destinations

```spl
| tstats count, dc(All_Traffic.src) AS sources FROM datamodel=Network_Traffic
    WHERE All_Traffic.action=allowed All_Traffic.direction=outbound earliest=-7d
    BY All_Traffic.dest
| where sources == 1
| sort - count
```

`direction` is populated only when your firewall add-on maps it.

## RDP / SMB between workstations

```spl
| tstats count FROM datamodel=Network_Traffic
    WHERE All_Traffic.dest_port IN (3389, 445) earliest=-24h
    BY All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port
| rename All_Traffic.* AS *
```

Filter `src`/`dest` against your workstation subnets — workstation-to-workstation RDP/SMB is a lateral-movement signal.

## DNS queries from endpoints (Sysmon event 22)

```spl
index=wineventlog source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22
| stats count, dc(host) AS hosts, values(Image) AS processes BY QueryName
| where hosts <= 2
| sort - count
```

## Long or high-entropy DNS names (possible tunnelling)

```spl
| tstats count FROM datamodel=Network_Resolution BY DNS.query
| rename DNS.query AS query
| eval len = len(query)
| where len > 60
| sort - len
```

## Beaconing by interval regularity

```spl
index=proxy earliest=-24h
| bin _time span=1m
| stats count BY _time, src, dest
| streamstats current=f last(_time) AS prev BY src, dest
| eval gap = _time - prev
| stats count, avg(gap) AS avg_gap, stdev(gap) AS stdev_gap BY src, dest
| where count > 50 AND stdev_gap < 5
| sort stdev_gap
```

Low standard deviation of the gap between connections = regular, machine-like timing.

## Related

- [KQL network events](../kql/network-events.md)
- [Network Investigation workflow](../../tasks/investigation/network-investigation.md)

## Sources

- [CIM Network Traffic data model](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- [CIM Network Resolution (DNS)](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolutionDNS)
- [Sysmon event 22](https://learn.microsoft.com/sysinternals/downloads/sysmon)
